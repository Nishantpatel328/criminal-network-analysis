"""Community and hierarchy detection.

This module is the reason the pseudonymity boundary exists. It runs in Z4 on
surrogates and weights only. It cannot name anyone, and that is what makes it
safe to give it CPU, memory and a scheduler.

WHAT IT PRODUCES AND WHAT THAT MEANS
Every output here is a statement about *graph structure*, not about people. The
distinction is not pedantic — it determines what the API is allowed to say. A
community is a set of vertices more densely connected to each other than to the
rest of the projection, given the edges we happened to collect and the confidence
weights we assigned them. It is not "a gang". A CONNECTOR_HUB role is a
description of a degree distribution, not an allegation of seniority.

Under LED Art. 11 / GDPR Art. 22 these are automated characterisations of
identifiable people once re-associated at the API tier, so four things are
mandatory rather than nice:

  1. Nothing is emitted without a derivation envelope (derivation.py) recording
     algorithm, version, backend, seed, resolution and parameters. A result an
     analyst cannot reproduce is a result they cannot be cross-examined on.
  2. Every assignment carries a stability score, and the API refuses to disclose
     assignments below MIN_DISCLOSABLE_STABILITY. An unstable assignment is an
     artefact of the random seed, and presenting it as a finding is presenting
     noise as intelligence.
  3. Hierarchy comes from a resolution sweep with explicit nesting checks. We
     report when the hierarchy is not actually nested rather than drawing a
     dendrogram that implies containment we did not verify.
  4. Multi-affiliation is first class. Forcing every person into exactly one
     community is the single most misleading thing a partition can do to an
     investigation, because the people on the boundary between two groups are
     usually the interesting ones and a hard partition hides them.

WHAT THIS DELIBERATELY DOES NOT DO
No key-player or disruption scoring, no "who should we arrest" ranking, no
temporal prediction of future association. Those were out of scope for this
build, and the omission is load-bearing: several of the guardrails here (no
individual risk scores, hypothesis framing on every output) would need to be
redesigned before such features could be added lawfully.
"""

from __future__ import annotations

import logging
import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .backends import ClusteringBackend, Edge, Partition, modularity, select_backend
from .pseudonymize import PseudonymEdge

logger = logging.getLogger(__name__)

ALGORITHM_VERSION = "cna-community-1.0.0"

# Coarse to fine. The low end matters: a sweep that starts at 1.0 cannot see
# structure above the scale modularity's resolution limit imposes, so a large
# loose federation of cells looks like nothing at all. Chosen to bracket the range
# where CDR and financial graphs of this kind produce interpretable structure; a
# deployment should re-derive it from its own data rather than inherit ours.
DEFAULT_RESOLUTIONS: Tuple[float, ...] = (
    0.1, 0.2, 0.3, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0,
)

# Below this, we report the vertex as unclustered rather than as a member of a
# community. A "community" of two people is a pair of people; dressing it in the
# language of organised crime adds an implication the data does not support.
MIN_COMMUNITY_SIZE = 3

# Bootstrap runs. 20 gives a usable stability estimate; the national tier moves
# this to a separate job with more runs because it is embarrassingly parallel.
DEFAULT_BOOTSTRAP_RUNS = 20

# Co-membership counting is O(|c|^2) per community. Above this size we sample
# pairs instead, which turns a quadratic blow-up into a bounded approximation.
# Documented as an approximation in the derivation envelope, not hidden.
PAIR_EXACT_THRESHOLD = 2_000
PAIR_SAMPLE_MULTIPLIER = 20

# Secondary affiliation thresholds. A single edge into another community is not
# an affiliation — it is an edge. Requiring both a share of edge mass and
# multiple distinct contacts stops one phone call from creating a second
# "membership" that an analyst then has to disprove.
MIN_SECONDARY_SHARE = 0.25
MIN_SECONDARY_CONTACTS = 2
MAX_SECONDARY_COMMUNITIES = 3

# Guimera-Amaral cut-points, as published. These are conventions calibrated on
# metabolic and air-transport networks, not constants of nature. We keep them for
# comparability with the literature and always emit z and P numerically next to
# the label so a reviewer can disagree with the boundary.
Z_HUB = 2.5
P_PROVINCIAL = 0.30
P_CONNECTOR = 0.75
P_PERIPHERAL = 0.62
P_ULTRA_PERIPHERAL = 0.05

UNCLUSTERED = "UNCLUSTERED"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NodeAssignment:
    """One vertex's structural position. Surrogate-keyed: no identity here."""
    surrogate: str
    community_id: str
    level: int
    stability: float
    role: str
    within_z: float
    participation: float
    internal_weight: float
    external_weight: float
    secondary_communities: Tuple[Tuple[str, float], ...] = ()

    @property
    def is_multi_affiliated(self) -> bool:
        return bool(self.secondary_communities)


@dataclass(frozen=True)
class Community:
    community_id: str
    level: int
    resolution: float
    size: int
    members: Tuple[str, ...]
    internal_weight: float
    external_weight: float
    stability: float
    parent_id: Optional[str] = None
    parent_purity: Optional[float] = None

    @property
    def conductance(self) -> float:
        """Fraction of the community's edge mass that leaves it. Low means a
        tightly bounded group; high means we have drawn a boundary through the
        middle of something."""
        total = 2.0 * self.internal_weight + self.external_weight
        return (self.external_weight / total) if total > 0 else 0.0


@dataclass(frozen=True)
class Level:
    level: int
    resolution: float
    community_count: int
    modularity: float
    clustered_vertices: int
    unclustered_vertices: int
    nested_in_parent: Optional[bool] = None
    mean_parent_purity: Optional[float] = None


@dataclass
class CommunityResult:
    snapshot_id: str
    algorithm_version: str
    backend: str
    seed: int
    bootstrap_runs: int
    vertex_count: int
    edge_count: int
    levels: List[Level] = field(default_factory=list)
    communities: Dict[str, Community] = field(default_factory=dict)
    assignments: Dict[str, NodeAssignment] = field(default_factory=dict)
    primary_level: int = 0
    approximations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def at_level(self, level: int) -> List[Community]:
        return sorted(
            (c for c in self.communities.values() if c.level == level),
            key=lambda c: (-c.size, c.community_id),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def to_edges(pseudonym_edges: Iterable[PseudonymEdge]) -> List[Edge]:
    """Collapse multi-edges between the same surrogate pair.

    Two people who both call each other and share a bank account are one
    relationship for clustering purposes, not two. Summing keeps the strength;
    treating them as parallel edges would double-count the same underlying tie.
    """
    merged: Dict[Tuple[str, str], float] = defaultdict(float)
    for e in pseudonym_edges:
        key = (e.src, e.dst) if e.src <= e.dst else (e.dst, e.src)
        merged[key] += e.weight
    return [(s, d, w) for (s, d), w in sorted(merged.items())]


def _ci_lookup(pseudonym_edges: Iterable[PseudonymEdge]) -> Dict[Tuple[str, str], float]:
    """Worst-case (largest) uncertainty per collapsed pair.

    If a pair is supported by one billing record and one piece of hearsay, the
    conservative choice is to let the hearsay's uncertainty drive perturbation.
    Averaging would let strong evidence launder weak evidence.
    """
    out: Dict[Tuple[str, str], float] = {}
    for e in pseudonym_edges:
        key = (e.src, e.dst) if e.src <= e.dst else (e.dst, e.src)
        out[key] = max(out.get(key, 0.0), e.weight_ci)
    return out


def _group(partition: Partition) -> Dict[int, List[str]]:
    out: Dict[int, List[str]] = defaultdict(list)
    for v, c in partition.items():
        out[c].append(v)
    return {c: sorted(m) for c, m in out.items()}


def _adjacency(edges: Sequence[Edge]) -> Dict[str, Dict[str, float]]:
    adj: Dict[str, Dict[str, float]] = defaultdict(dict)
    for s, d, w in edges:
        if s == d:
            continue
        adj[s][d] = adj[s].get(d, 0.0) + w
        adj[d][s] = adj[d].get(s, 0.0) + w
    return adj


def adjusted_rand_index(a: Partition, b: Partition) -> float:
    """ARI between two partitions over their shared vertices.

    Used for plateau detection in the resolution sweep. ARI rather than raw
    agreement because it is corrected for chance: two random partitions of the
    same graph agree on a surprising number of pairs, and an uncorrected metric
    would report spurious plateaux.
    """
    shared = sorted(set(a) & set(b))
    n = len(shared)
    if n < 2:
        return 1.0

    contingency: Dict[Tuple[int, int], int] = defaultdict(int)
    rows: Dict[int, int] = defaultdict(int)
    cols: Dict[int, int] = defaultdict(int)
    for v in shared:
        contingency[(a[v], b[v])] += 1
        rows[a[v]] += 1
        cols[b[v]] += 1

    def c2(x: int) -> float:
        return x * (x - 1) / 2.0

    sum_ij = sum(c2(v) for v in contingency.values())
    sum_a = sum(c2(v) for v in rows.values())
    sum_b = sum(c2(v) for v in cols.values())
    total = c2(n)
    expected = (sum_a * sum_b) / total if total else 0.0
    maximum = 0.5 * (sum_a + sum_b)
    if abs(maximum - expected) < 1e-12:
        return 1.0
    return (sum_ij - expected) / (maximum - expected)


# ---------------------------------------------------------------------------
# Resolution sweep
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SweepPoint:
    resolution: float
    partition: Partition
    modularity: float
    community_count: int


def sweep(edges: Sequence[Edge], resolutions: Sequence[float], seed: int,
          backend: ClusteringBackend) -> List[SweepPoint]:
    """Partition at each resolution. Coarse resolutions yield few large groups,
    fine resolutions many small ones.

    We sweep rather than pick one resolution because there is no correct
    resolution. Modularity has a known resolution limit — it cannot see
    communities below a size that depends on total graph size — so any single
    value silently imposes a scale. Sweeping makes the scale choice visible and
    lets the analyst ask "at what granularity does this group hold together?",
    which is the question they actually have.
    """
    points: List[SweepPoint] = []
    for gamma in sorted(resolutions):
        part = backend.partition(edges, gamma, seed)
        points.append(SweepPoint(
            resolution=gamma,
            partition=part,
            modularity=modularity(edges, part, resolution=1.0),
            community_count=len(set(part.values())),
        ))
    return points


def find_plateaux(points: Sequence[SweepPoint],
                  min_ari: float = 0.90) -> List[List[int]]:
    """Group consecutive sweep points whose partitions substantially agree.

    A plateau — a range of resolutions producing essentially the same partition —
    is evidence of genuine structure at that scale. A partition that appears at
    exactly one resolution value and vanishes on either side is a fitting
    artefact. Reporting one hierarchy level per resolution value would present
    those artefacts as findings, so we collapse each plateau to a single level
    and report the resolution range it survived.
    """
    if not points:
        return []
    plateaux: List[List[int]] = [[0]]
    for i in range(1, len(points)):
        ari = adjusted_rand_index(points[i - 1].partition, points[i].partition)
        if ari >= min_ari:
            plateaux[-1].append(i)
        else:
            plateaux.append([i])
    return plateaux


# ---------------------------------------------------------------------------
# Stability bootstrapping
# ---------------------------------------------------------------------------

def _perturb(edges: Sequence[Edge], ci: Dict[Tuple[str, str], float],
             rng: random.Random) -> List[Edge]:
    """Resample edge weights within each edge's own confidence interval.

    Per-edge intervals rather than uniform noise: instability should appear where
    the evidence is weak, not spread evenly across strong and weak ties alike.
    Weak edges also drop out entirely when their jittered weight falls below the
    floor, which perturbs topology as well as weight — the two failure modes an
    analyst needs protection against are "this group only exists because of one
    dubious edge" and "this group only exists at one random seed".
    """
    from .weighting import CONFIDENCE_FLOOR

    out: List[Edge] = []
    for s, d, w in edges:
        key = (s, d) if s <= d else (d, s)
        interval = ci.get(key, 0.2)
        factor = 1.0 + rng.uniform(-interval, interval)
        jittered = w * factor
        if jittered >= CONFIDENCE_FLOOR:
            out.append((s, d, jittered))
    return out


def _count_co_membership(partition: Partition, counts: Dict[Tuple[str, str], int],
                         rng: random.Random, approximated: Set[str]) -> None:
    for cid, members in _group(partition).items():
        n = len(members)
        if n < 2:
            continue
        if n <= PAIR_EXACT_THRESHOLD:
            for i in range(n):
                for j in range(i + 1, n):
                    counts[(members[i], members[j])] += 1
        else:
            # Bounded sampling. Recorded so the derivation envelope can say the
            # stability figure for this community is an estimate.
            budget = PAIR_EXACT_THRESHOLD * PAIR_SAMPLE_MULTIPLIER
            for _ in range(budget):
                u, v = rng.sample(members, 2)
                key = (u, v) if u <= v else (v, u)
                counts[key] += 1
            approximated.add(str(cid))


def bootstrap_stability(
    edges: Sequence[Edge],
    reference: Partition,
    resolution: float,
    seed: int,
    backend: ClusteringBackend,
    ci: Dict[Tuple[str, str], float],
    runs: int = DEFAULT_BOOTSTRAP_RUNS,
) -> Tuple[Dict[str, float], List[str]]:
    """Per-vertex stability = mean co-membership frequency with the vertex's
    reference-community peers across perturbed runs.

    Chosen over pairwise-Jaccard-between-runs because it is O(runs) rather than
    O(runs^2) and, more importantly, because it states something an analyst and a
    court can follow: "the people we placed in this person's group were placed
    with them, on average, 87% of the time when we varied the evidence within its
    own margin of error." A number that requires explaining what a Jaccard index
    is will not survive cross-examination.
    """
    counts: Dict[Tuple[str, str], int] = defaultdict(int)
    approximated: Set[str] = set()

    for b in range(runs):
        run_seed = seed + 7919 * (b + 1)
        rng = random.Random(run_seed)
        perturbed = _perturb(edges, ci, rng)
        if not perturbed:
            continue
        part = backend.partition(perturbed, resolution, run_seed)
        _count_co_membership(part, counts, rng, approximated)

    stability: Dict[str, float] = {}
    for _cid, members in _group(reference).items():
        if len(members) < 2:
            # A vertex we could not place with anyone has no group membership to
            # be stable about. Zero, not one: it will be reported as unclustered,
            # and claiming high confidence in a non-assignment would be odd.
            for v in members:
                stability[v] = 0.0
            continue
        member_set = set(members)
        for v in members:
            total = 0.0
            for u in member_set:
                if u == v:
                    continue
                key = (v, u) if v <= u else (u, v)
                total += counts.get(key, 0) / float(runs)
            stability[v] = min(1.0, total / (len(members) - 1))

    notes: List[str] = []
    if approximated:
        notes.append(
            f"co-membership sampled rather than enumerated for "
            f"{len(approximated)} community(ies) exceeding "
            f"{PAIR_EXACT_THRESHOLD} members; their stability figures are "
            f"estimates with wider error than the exact ones"
        )
    return stability, notes


# ---------------------------------------------------------------------------
# Roles: Guimera-Amaral z-P
# ---------------------------------------------------------------------------

def _role_label(z: float, p: float) -> str:
    """Plain-language role names.

    The published taxonomy's names ("kinless hub", "ultra-peripheral node") are
    fine in a physics paper and actively harmful in a disclosure bundle, where
    every term will be read as a claim about a person's function in a criminal
    enterprise. These names are chosen to describe the measurement.
    """
    if z >= Z_HUB:
        if p <= P_PROVINCIAL:
            return "CORE_WITHIN_GROUP"
        if p <= P_CONNECTOR:
            return "CONNECTOR_HUB"
        return "DISPERSED_HUB"
    if p <= P_ULTRA_PERIPHERAL:
        return "ISOLATED_WITHIN_GROUP"
    if p <= P_PERIPHERAL:
        return "PERIPHERAL"
    return "BRIDGING"


def compute_roles(
    edges: Sequence[Edge], partition: Partition
) -> Dict[str, Tuple[float, float, str, float, float]]:
    """Within-module degree z-score and participation coefficient per vertex.

    Returns surrogate -> (z, P, role, internal_weight, external_weight).

    Note the guardrail this does NOT need: victims and witnesses are absent from
    the projection entirely (they are non-clusterable per docs/data-model.md and
    excluded at export), so no role label can ever attach to them. That is
    enforced upstream by a Neo4j constraint rather than by a check here, because
    a check here would be one refactor away from being removed.
    """
    adj = _adjacency(edges)
    internal: Dict[str, float] = defaultdict(float)
    external: Dict[str, float] = defaultdict(float)
    per_community: Dict[str, Dict[int, float]] = defaultdict(lambda: defaultdict(float))

    for v, nbrs in adj.items():
        cv = partition.get(v)
        for u, w in nbrs.items():
            cu = partition.get(u)
            per_community[v][cu] += w
            if cu == cv:
                internal[v] += w
            else:
                external[v] += w

    # Mean and population sd of internal degree, within each community.
    by_comm = _group(partition)
    stats: Dict[int, Tuple[float, float]] = {}
    for cid, members in by_comm.items():
        vals = [internal.get(v, 0.0) for v in members]
        mean = sum(vals) / len(vals)
        var = sum((x - mean) ** 2 for x in vals) / len(vals)
        stats[cid] = (mean, math.sqrt(var))

    out: Dict[str, Tuple[float, float, str, float, float]] = {}
    for v in partition:
        cv = partition[v]
        mean, sd = stats.get(cv, (0.0, 0.0))
        k_in = internal.get(v, 0.0)
        # sd == 0 means every member has identical internal degree, so nobody is
        # unusual. Reporting z = 0 is correct; dividing by a fudged epsilon would
        # manufacture large z-scores for uniform communities, which is exactly
        # how a small cluster of equals acquires a spurious "leader".
        z = 0.0 if sd < 1e-12 else (k_in - mean) / sd

        k_total = k_in + external.get(v, 0.0)
        if k_total <= 0:
            p = 0.0
        else:
            p = 1.0 - sum((w / k_total) ** 2 for w in per_community[v].values())
            p = max(0.0, min(1.0, p))

        role = _role_label(z, p)
        out[v] = (z, p, role, k_in, external.get(v, 0.0))
    return out


# ---------------------------------------------------------------------------
# Overlapping membership
# ---------------------------------------------------------------------------

def detect_secondary_affiliations(
    edges: Sequence[Edge], partition: Partition, community_ids: Dict[int, str]
) -> Dict[str, Tuple[Tuple[str, float], ...]]:
    """Communities a vertex has substantial ties to besides its assigned one.

    This is a deliberately simple, explainable overlap detector: share of edge
    mass plus a minimum number of distinct contacts. It is not clique percolation
    or a link-community decomposition, and it will miss overlaps that only show
    up in higher-order structure.

    That trade is intentional for this build. An analyst has to be able to see
    *why* a person was flagged as connected to two groups — "62% of their contact
    is with group A, 31% with group B, across 4 and 3 distinct contacts" is
    inspectable and challengeable. A k-clique percolation result is not, and an
    overlap claim an analyst cannot interrogate is worse than no overlap claim.
    Upgrade path is in docs/analytics.md.
    """
    adj = _adjacency(edges)
    out: Dict[str, Tuple[Tuple[str, float], ...]] = {}

    for v, nbrs in adj.items():
        own = partition.get(v)
        mass: Dict[int, float] = defaultdict(float)
        contacts: Dict[int, int] = defaultdict(int)
        for u, w in nbrs.items():
            cu = partition.get(u)
            if cu is None:
                continue
            mass[cu] += w
            contacts[cu] += 1

        total = sum(mass.values())
        if total <= 0:
            continue

        candidates: List[Tuple[str, float]] = []
        for cid, w in mass.items():
            if cid == own:
                continue
            share = w / total
            if share >= MIN_SECONDARY_SHARE and contacts[cid] >= MIN_SECONDARY_CONTACTS:
                label = community_ids.get(cid)
                if label:
                    candidates.append((label, round(share, 4)))

        if candidates:
            candidates.sort(key=lambda t: (-t[1], t[0]))
            out[v] = tuple(candidates[:MAX_SECONDARY_COMMUNITIES])
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def analyse(
    pseudonym_edges: Sequence[PseudonymEdge],
    snapshot_id: str,
    seed: int = 20260908,
    resolutions: Sequence[float] = DEFAULT_RESOLUTIONS,
    bootstrap_runs: int = DEFAULT_BOOTSTRAP_RUNS,
    backend: Optional[ClusteringBackend] = None,
) -> CommunityResult:
    """Full pipeline: sweep, plateau detection, hierarchy, stability, roles,
    overlap. Deterministic for a given (edges, seed) pair.

    Determinism is a requirement, not a convenience. If a defence expert reruns
    this on disclosed inputs and gets different communities, the analysis is
    worthless as evidence and the disclosure was misleading. Every source of
    randomness here is seeded from `seed`.
    """
    backend = backend or select_backend()
    edges = to_edges(pseudonym_edges)
    ci = _ci_lookup(pseudonym_edges)
    vertices = sorted({v for s, d, _ in edges for v in (s, d)})

    result = CommunityResult(
        snapshot_id=snapshot_id,
        algorithm_version=ALGORITHM_VERSION,
        backend=backend.name,
        seed=seed,
        bootstrap_runs=bootstrap_runs,
        vertex_count=len(vertices),
        edge_count=len(edges),
    )

    if not edges:
        result.warnings.append("empty projection: nothing to analyse")
        return result

    points = sweep(edges, resolutions, seed, backend)
    plateaux = find_plateaux(points)

    # One reported level per plateau, using the plateau's median resolution.
    chosen: List[SweepPoint] = []
    for group_idx in plateaux:
        mid = group_idx[len(group_idx) // 2]
        chosen.append(points[mid])
        if len(group_idx) == 1:
            result.warnings.append(
                f"resolution {points[mid].resolution} produced a partition that "
                f"did not persist to adjacent resolutions; treat its communities "
                f"as weakly supported"
            )

    # Level 0 = coarsest.
    level_partitions: Dict[int, Partition] = {}
    level_ids: Dict[int, Dict[int, str]] = {}

    for level, point in enumerate(chosen):
        groups = _group(point.partition)
        # Deterministic ids: descending size, then lexicographic first member.
        ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[1][0]))
        ids = {cid: f"L{level}-C{i:04d}" for i, (cid, _m) in enumerate(ordered)}
        level_partitions[level] = point.partition
        level_ids[level] = ids

    # Stability is computed once, at the primary level, because the bootstrap is
    # the expensive part of this pipeline and a per-level bootstrap multiplies
    # cost by the number of levels for information analysts rarely use. The
    # primary level is the widest plateau: the scale the data supports best.
    widest = max(range(len(plateaux)), key=lambda i: (len(plateaux[i]), -i))
    result.primary_level = widest
    primary_point = chosen[widest]
    primary_partition = level_partitions[widest]

    stability, notes = bootstrap_stability(
        edges, primary_partition, primary_point.resolution, seed,
        backend, ci, runs=bootstrap_runs,
    )
    result.approximations.extend(notes)

    roles = compute_roles(edges, primary_partition)
    secondary = detect_secondary_affiliations(
        edges, primary_partition, level_ids[widest]
    )

    # -- build communities per level ---------------------------------------
    for level, point in enumerate(chosen):
        groups = _group(point.partition)
        ids = level_ids[level]
        adj = _adjacency(edges)

        clustered = unclustered = 0
        for cid, members in groups.items():
            member_set = set(members)
            internal_w = external_w = 0.0
            for v in members:
                for u, w in adj.get(v, {}).items():
                    if u in member_set:
                        internal_w += w / 2.0
                    else:
                        external_w += w

            if len(members) >= MIN_COMMUNITY_SIZE:
                clustered += len(members)
            else:
                unclustered += len(members)

            member_stability = [stability.get(v, 0.0) for v in members] \
                if level == widest else []
            comm_stability = (sum(member_stability) / len(member_stability)
                              if member_stability else 0.0)

            result.communities[ids[cid]] = Community(
                community_id=ids[cid],
                level=level,
                resolution=point.resolution,
                size=len(members),
                members=tuple(members),
                internal_weight=round(internal_w, 6),
                external_weight=round(external_w, 6),
                stability=round(comm_stability, 4),
            )

        plateau_res = [points[i].resolution for i in plateaux[level]]
        result.levels.append(Level(
            level=level,
            resolution=point.resolution,
            community_count=len(groups),
            modularity=round(point.modularity, 6),
            clustered_vertices=clustered,
            unclustered_vertices=unclustered,
        ))
        logger.debug("level %d resolution range %s", level, plateau_res)

    _link_hierarchy(result, level_partitions, level_ids)

    # -- assignments at the primary level ----------------------------------
    for v in vertices:
        cid = primary_partition.get(v)
        if cid is None:
            continue
        label = level_ids[widest][cid]
        community = result.communities[label]
        z, p, role, k_in, k_out = roles.get(v, (0.0, 0.0, "PERIPHERAL", 0.0, 0.0))

        if community.size < MIN_COMMUNITY_SIZE:
            # Honest downgrade: too small to describe as a group, so it gets no
            # group label and no role. A role label on a 2-vertex "community" is
            # a statement about nothing.
            label, role = UNCLUSTERED, "UNCLASSIFIED"

        result.assignments[v] = NodeAssignment(
            surrogate=v,
            community_id=label,
            level=widest,
            stability=round(stability.get(v, 0.0), 4),
            role=role,
            within_z=round(z, 4),
            participation=round(p, 4),
            internal_weight=round(k_in, 6),
            external_weight=round(k_out, 6),
            secondary_communities=secondary.get(v, ()) if label != UNCLUSTERED else (),
        )

    _add_quality_warnings(result, primary_point)
    return result


def _link_hierarchy(result: CommunityResult,
                    level_partitions: Dict[int, Partition],
                    level_ids: Dict[int, Dict[int, str]]) -> None:
    """Attach each finer community to its coarser parent, and check nesting.

    A resolution sweep does NOT guarantee a nested hierarchy: a fine community
    can straddle two coarse ones. Drawing a dendrogram regardless would assert
    containment we have not verified, so we record the plurality parent together
    with a purity figure, and flag the level when purity is poor. An analyst
    seeing "purity 0.55" knows the tree is a summary, not a fact.
    """
    for level in range(1, len(result.levels)):
        fine, coarse = level_partitions[level], level_partitions[level - 1]
        purities: List[float] = []

        for cid, members in _group(fine).items():
            counts: Dict[int, int] = defaultdict(int)
            for v in members:
                parent = coarse.get(v)
                if parent is not None:
                    counts[parent] += 1
            if not counts:
                continue
            best_parent, best_count = max(counts.items(), key=lambda kv: (kv[1], -kv[0]))
            purity = best_count / len(members)
            purities.append(purity)

            label = level_ids[level][cid]
            existing = result.communities[label]
            result.communities[label] = Community(
                **{**existing.__dict__,
                   "parent_id": level_ids[level - 1].get(best_parent),
                   "parent_purity": round(purity, 4)}
            )

        mean_purity = sum(purities) / len(purities) if purities else 1.0
        nested = mean_purity > 0.99
        lv = result.levels[level]
        result.levels[level] = Level(
            **{**lv.__dict__,
               "nested_in_parent": nested,
               "mean_parent_purity": round(mean_purity, 4)}
        )
        if not nested:
            result.warnings.append(
                f"level {level} is not strictly nested within level {level - 1} "
                f"(mean parent purity {mean_purity:.2f}); the hierarchy is a "
                f"summary of overlapping partitions, not a containment tree"
            )


def _add_quality_warnings(result: CommunityResult, primary: SweepPoint) -> None:
    """Say plainly when the output is not worth much.

    The failure mode this guards against is a system that always returns
    confident-looking communities. On a sparse or near-random graph, modularity
    maximisation still returns a partition — it just means nothing. An analyst
    who is not told that will act on it.
    """
    if primary.modularity < 0.15:
        result.warnings.append(
            f"modularity {primary.modularity:.3f} is low: this projection has "
            f"little community structure. The partition below is close to an "
            f"arbitrary division and should not be relied on."
        )
    if result.assignments:
        low = sum(1 for a in result.assignments.values() if a.stability < 0.6)
        if low > len(result.assignments) * 0.4:
            result.warnings.append(
                f"{low} of {len(result.assignments)} vertices have stability "
                f"below 0.6; most assignments in this snapshot are not robust to "
                f"variation within the evidence's own margin of error"
            )
    if result.edge_count < 3 * max(result.vertex_count, 1) // 2:
        result.warnings.append(
            "projection is very sparse (mean degree below 3); community "
            "detection on graphs this sparse is unreliable regardless of "
            "algorithm"
        )
