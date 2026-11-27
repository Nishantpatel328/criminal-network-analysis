"""Community detection tests.

Two kinds of test here, and the second kind matters more.

The first kind checks the maths: does the sweep recover a planted partition, does
ARI behave, are roles computed correctly. Standard algorithm testing.

The second kind checks the guardrails — that low-stability results are withheld,
that tiny groups are not dressed up as organisations, that no output can escape
without a derivation envelope, that nothing identifying reaches this tier, and
that the same inputs always give the same answer. Those are the tests that would
fail if someone "simplified" the pipeline later, and each one corresponds to a
way this system could produce a false conclusion about a real person.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "analytics"))
sys.path.insert(0, str(ROOT / "services" / "api"))

from worker.backends import (  # noqa: E402
    ReferenceBackend, modularity, select_backend,
)
from worker.community import (  # noqa: E402
    DEFAULT_RESOLUTIONS, MIN_COMMUNITY_SIZE, UNCLUSTERED,
    adjusted_rand_index, analyse, bootstrap_stability, compute_roles,
    detect_secondary_affiliations, find_plateaux, sweep, to_edges,
)
from worker.derivation import (  # noqa: E402
    MIN_DISCLOSABLE_STABILITY, NOT_ESTABLISHED, envelope_for_assignment,
    envelope_for_community, summarise_for_review,
)
from worker.pseudonymize import (  # noqa: E402
    LocalKeyProvider, PseudonymEdge, Pseudonymizer, SurrogateMap, surrogate_for,
)
from worker.weighting import (  # noqa: E402
    CONFIDENCE_FLOOR, confidence_interval, confidence_weight,
)

BACKEND = ReferenceBackend()
SEED = 20260908


# ---------------------------------------------------------------------------
# Fixtures: synthetic graphs with known structure
# ---------------------------------------------------------------------------

def planted(groups: int = 3, size: int = 8, w_in: float = 5.0,
            w_out: float = 0.15):
    """Cliques joined by single weak edges. Ground truth is known."""
    edges = []
    for g in range(groups):
        members = [f"G{g}N{i}" for i in range(size)]
        for i in range(size):
            for j in range(i + 1, size):
                edges.append((members[i], members[j], w_in))
    for g in range(groups):
        edges.append((f"G{g}N0", f"G{(g + 1) % groups}N1", w_out))
    return edges


def as_pseudonym(edges, ci: float = 0.05):
    return [PseudonymEdge(s, d, w, "COMMUNICATED_WITH", ci) for s, d, w in edges]


def truth(groups: int = 3, size: int = 8):
    return {f"G{g}N{i}": g for g in range(groups) for i in range(size)}


def swing(w_a: float = 1.0, w_b: float = 0.95, w_core: float = 5.0):
    """Two solid triangles plus one node ("x") whose membership hinges on two
    near-equal edges.

    This is the shape that matters operationally. Most of a real network is
    well-evidenced and its community structure is not in doubt; the doubt lives
    at the boundary, in the handful of people whose recorded affiliation rests on
    one or two pieces of intelligence. A test on a uniformly strong or uniformly
    weak graph would never exercise it.
    """
    edges = []
    for g in ("a", "b"):
        for i in range(3):
            for j in range(i + 1, 3):
                edges.append((f"{g}{i}", f"{g}{j}", w_core))
    edges.append(("x", "a0", w_a))
    edges.append(("x", "b0", w_b))
    return edges


def _pairs(edges):
    """Canonical undirected keys, matching the analytics tier's convention."""
    return {(s, d) if s <= d else (d, s) for s, d, _w in edges}


def nested(supers: int = 3, subs: int = 3, size: int = 4, w_sub: float = 8.0,
           w_super: float = 2.5, links: int = 3, w_out: float = 0.05):
    """Genuinely two-scale structure: 9 tight cells that group into 3 federations.

    This is the shape the resolution sweep exists for, and it is the shape real
    organised crime networks tend to have — small operational cells with dense
    internal contact, joined at a few points into a looser wider structure. A
    single-resolution partition has to pick one of the two scales and throw the
    other away; which one it picks depends on a parameter nobody chose
    deliberately.
    """
    edges = []
    cells = {(S, s): [f"S{S}s{s}n{i}" for i in range(size)]
             for S in range(supers) for s in range(subs)}

    for S in range(supers):
        for s in range(subs):
            m = cells[(S, s)]
            for i in range(len(m)):
                for j in range(i + 1, len(m)):
                    edges.append((m[i], m[j], w_sub))
        for s in range(subs):
            for t in range(s + 1, subs):
                for i in range(links):
                    edges.append((cells[(S, s)][i], cells[(S, t)][i], w_super))

    for S in range(supers):
        edges.append((cells[(S, 0)][0], cells[((S + 1) % supers, 0)][1], w_out))
    return edges


def nested_truth(supers: int = 3, subs: int = 3, size: int = 4):
    """(coarse, fine) ground truth for the nested fixture."""
    coarse = {f"S{S}s{s}n{i}": S
              for S in range(supers) for s in range(subs) for i in range(size)}
    fine = {f"S{S}s{s}n{i}": S * subs + s
            for S in range(supers) for s in range(subs) for i in range(size)}
    return coarse, fine


# ---------------------------------------------------------------------------
# Weighting
# ---------------------------------------------------------------------------

class TestWeighting:
    def test_reliable_source_outweighs_hearsay(self):
        strong = confidence_weight(50, source_eval=1, intel_assessment=1)
        weak = confidence_weight(50, source_eval=4, intel_assessment=4)
        assert strong > weak * 4

    def test_suspected_false_is_excluded_entirely(self):
        """5x5x5 assessment 5 means the reporting officer believes the
        information is false. It must not shape communities at all."""
        assert confidence_weight(10_000, source_eval=1, intel_assessment=5) == 0.0

    def test_volume_is_log_damped(self):
        """Linear volume lets one dispatcher or delivery driver dominate the
        partition and drag unrelated people into a single cluster."""
        a = confidence_weight(10, 1, 1)
        b = confidence_weight(1_000, 1, 1)
        assert b < a * 3          # 100x the volume, under 3x the weight

    def test_floor_zeroes_negligible_edges(self):
        w = confidence_weight(0.01, source_eval=5, intel_assessment=4)
        assert w == 0.0
        assert CONFIDENCE_FLOOR > 0.0, "a zero floor would admit noise edges"

    def test_invalid_grades_rejected(self):
        for bad in (0, 6, -1):
            with pytest.raises(ValueError):
                confidence_weight(10, bad, 1)
            with pytest.raises(ValueError):
                confidence_weight(10, 1, bad)

    def test_uncertainty_tracks_evidence_quality(self):
        assert confidence_interval(1, 1) < confidence_interval(4, 4)
        assert 0.0 < confidence_interval(1, 1) < 1.0


# ---------------------------------------------------------------------------
# Pseudonymity boundary
# ---------------------------------------------------------------------------

class TestPseudonymityBoundary:
    def test_same_entity_same_snapshot_is_stable(self):
        kp = LocalKeyProvider(b"m" * 32)
        p = Pseudonymizer(kp, "snap-1")
        a = p._surrogate("3f2504e0-4f89-41d3-9a0c-0305e82c3301")
        b = p._surrogate("3f2504e0-4f89-41d3-9a0c-0305e82c3301")
        assert a == b

    def test_same_entity_different_snapshot_differs(self):
        """The whole point of per-snapshot keys: two leaked snapshots must not be
        joinable to track someone over time."""
        kp = LocalKeyProvider(b"m" * 32)
        uuid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
        a = Pseudonymizer(kp, "snap-1")._surrogate(uuid)
        b = Pseudonymizer(kp, "snap-2")._surrogate(uuid)
        assert a != b

    def test_surrogate_is_not_invertible_without_key(self):
        k1, k2 = b"a" * 32, b"b" * 32
        uuid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
        assert surrogate_for(uuid, k1) != surrogate_for(uuid, k2)

    def test_collision_raises_rather_than_merging_two_people(self):
        m = SurrogateMap("snap-1")
        m.add("uuid-a", "SAMESURROGATE")
        with pytest.raises(RuntimeError, match="collision"):
            m.add("uuid-b", "SAMESURROGATE")

    def test_map_repr_does_not_leak_the_mapping(self):
        m = SurrogateMap("snap-1")
        m.add("3f2504e0-4f89-41d3-9a0c-0305e82c3301", "ABCDEF")
        text = repr(m)
        assert "3f2504e0" not in text and "ABCDEF" not in text

    def test_raw_uuid_in_projection_is_detected(self):
        """The bug this catches: a code path that bypasses _surrogate and sends
        real UUIDs into the analytics tier, silently destroying the boundary."""
        kp = LocalKeyProvider(b"m" * 32)
        p = Pseudonymizer(kp, "snap-1")
        leaked = [PseudonymEdge("3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                                "b" * 26, 1.0, "COMMUNICATED_WITH")]
        with pytest.raises(RuntimeError, match="pseudonymity boundary"):
            p.assert_no_identities(leaked)

    def test_clean_projection_passes_the_guard(self):
        kp = LocalKeyProvider(b"m" * 32)
        p = Pseudonymizer(kp, "snap-1")
        rows = [{"src": f"uuid-{i}", "dst": f"uuid-{i + 1}", "rel_type":
                 "COMMUNICATED_WITH", "weight": 20, "source_eval": 1,
                 "intel_assessment": 1} for i in range(5)]
        edges = list(p.transform(rows))
        p.assert_no_identities(edges)
        assert len(edges) == 5

    def test_transform_carries_uncertainty_forward(self):
        kp = LocalKeyProvider(b"m" * 32)
        p = Pseudonymizer(kp, "snap-1")
        rows = [
            {"src": "a", "dst": "b", "rel_type": "COMMUNICATED_WITH",
             "weight": 20, "source_eval": 1, "intel_assessment": 1},
            {"src": "c", "dst": "d", "rel_type": "ASSOCIATE_OF",
             "weight": 20, "source_eval": 4, "intel_assessment": 4},
        ]
        strong, weak = list(p.transform(rows))
        assert weak.weight_ci > strong.weight_ci

    def test_self_loops_and_zero_weight_edges_dropped(self):
        kp = LocalKeyProvider(b"m" * 32)
        p = Pseudonymizer(kp, "snap-1")
        rows = [
            {"src": "a", "dst": "a", "rel_type": "COMMUNICATED_WITH",
             "weight": 99, "source_eval": 1, "intel_assessment": 1},
            {"src": "a", "dst": "b", "rel_type": "COMMUNICATED_WITH",
             "weight": 99, "source_eval": 1, "intel_assessment": 5},
        ]
        assert list(p.transform(rows)) == []


# ---------------------------------------------------------------------------
# Backend correctness
# ---------------------------------------------------------------------------

class TestBackend:
    def test_planted_partition_is_recovered(self):
        edges = planted()
        part = BACKEND.partition(edges, resolution=1.0, seed=SEED)
        assert adjusted_rand_index(part, truth()) > 0.95

    def test_communities_are_internally_connected(self):
        """The Louvain defect. A community that is two unconnected fragments
        reads to an analyst as one organisation when it is two."""
        edges = planted(groups=4, size=6)
        part = BACKEND.partition(edges, resolution=1.0, seed=SEED)
        adj = {}
        for s, d, _w in edges:
            adj.setdefault(s, set()).add(d)
            adj.setdefault(d, set()).add(s)

        members = {}
        for v, c in part.items():
            members.setdefault(c, set()).add(v)

        for c, group in members.items():
            start = next(iter(sorted(group)))
            seen, stack = set(), [start]
            while stack:
                v = stack.pop()
                if v in seen:
                    continue
                seen.add(v)
                stack.extend(u for u in adj.get(v, ()) if u in group and u not in seen)
            assert seen == group, f"community {c} is internally disconnected"

    def test_disconnected_community_is_split(self):
        backend = ReferenceBackend()
        edges = [("a", "b", 1.0), ("c", "d", 1.0)]
        adj = {"a": {"b": 1.0}, "b": {"a": 1.0}, "c": {"d": 1.0}, "d": {"c": 1.0}}
        forced = {"a": 0, "b": 0, "c": 0, "d": 0}     # deliberately wrong
        out = backend._split_disconnected(forced, adj)
        assert out["a"] == out["b"]
        assert out["c"] == out["d"]
        assert out["a"] != out["c"]

    def test_modularity_prefers_true_partition_over_scrambled(self):
        edges = planted()
        good = modularity(edges, truth())
        scrambled = {v: i % 3 for i, v in enumerate(sorted(truth()))}
        assert good > modularity(edges, scrambled)

    def test_empty_graph_returns_empty_partition(self):
        assert BACKEND.partition([], 1.0, SEED) == {}

    def test_partition_is_deterministic_for_a_seed(self):
        edges = planted()
        a = BACKEND.partition(edges, 1.0, SEED)
        b = BACKEND.partition(edges, 1.0, SEED)
        assert a == b

    def test_select_backend_returns_something_usable(self):
        b = select_backend()
        assert hasattr(b, "partition") and isinstance(b.name, str)


# ---------------------------------------------------------------------------
# Sweep, plateaux, hierarchy
# ---------------------------------------------------------------------------

class TestSweep:
    def test_higher_resolution_does_not_produce_fewer_communities(self):
        edges = planted(groups=4, size=10)
        points = sweep(edges, (0.5, 1.0, 2.0, 4.0), SEED, BACKEND)
        counts = [p.community_count for p in points]
        assert counts[-1] >= counts[0]

    def test_stable_structure_forms_a_plateau(self):
        """A partition that survives a range of resolutions is structure. One
        that appears at a single value is a fitting artefact."""
        edges = planted()
        points = sweep(edges, (0.5, 0.75, 1.0, 1.5), SEED, BACKEND)
        plateaux = find_plateaux(points)
        assert max(len(p) for p in plateaux) >= 2

    def test_plateaux_partition_the_sweep_exactly_once(self):
        edges = planted()
        points = sweep(edges, DEFAULT_RESOLUTIONS, SEED, BACKEND)
        flat = [i for group in find_plateaux(points) for i in group]
        assert flat == list(range(len(points)))

    def test_empty_sweep_yields_no_plateaux(self):
        assert find_plateaux([]) == []


class TestARI:
    def test_identical_partitions_score_one(self):
        p = truth()
        assert adjusted_rand_index(p, p) == pytest.approx(1.0)

    def test_relabelling_does_not_change_score(self):
        """ARI must be label-invariant: community 0 in one run and community 7 in
        another can be the same group."""
        a = truth()
        b = {v: c + 100 for v, c in a.items()}
        assert adjusted_rand_index(a, b) == pytest.approx(1.0)

    def test_unrelated_partitions_score_near_zero(self):
        a = truth(groups=4, size=10)
        b = {v: i % 4 for i, v in enumerate(sorted(a))}
        assert abs(adjusted_rand_index(a, b)) < 0.2

    def test_trivial_input_is_handled(self):
        assert adjusted_rand_index({}, {}) == 1.0
        assert adjusted_rand_index({"a": 0}, {"a": 1}) == 1.0


class TestHierarchy:
    def _nested_result(self):
        return analyse(as_pseudonym(nested()), "snap-1", seed=SEED,
                       bootstrap_runs=6, backend=BACKEND)

    def test_both_scales_are_found(self):
        """The core claim of the sweep: a two-scale network yields two levels,
        rather than one arbitrary partition that discards the other scale."""
        result = self._nested_result()
        assert len(result.levels) >= 2
        counts = [l.community_count for l in result.levels]
        assert counts[0] == 3, f"coarse level should find 3 federations, got {counts}"
        assert counts[-1] == 9, f"fine level should find 9 cells, got {counts}"

    def test_levels_are_ordered_coarse_to_fine(self):
        result = self._nested_result()
        resolutions = [l.resolution for l in result.levels]
        assert resolutions == sorted(resolutions)
        counts = [l.community_count for l in result.levels]
        assert counts == sorted(counts)

    def test_recovered_levels_match_ground_truth(self):
        result = self._nested_result()
        coarse_truth, fine_truth = nested_truth()
        points = sweep(nested(), DEFAULT_RESOLUTIONS, SEED, BACKEND)
        plateaux = find_plateaux(points)
        coarse = points[plateaux[0][len(plateaux[0]) // 2]].partition
        fine = points[plateaux[-1][len(plateaux[-1]) // 2]].partition
        assert adjusted_rand_index(coarse, coarse_truth) > 0.95
        assert adjusted_rand_index(fine, fine_truth) > 0.95

    def test_finer_levels_record_a_parent_and_a_purity(self):
        result = self._nested_result()
        finer = [c for c in result.communities.values() if c.level > 0]
        assert finer, "expected at least one non-root level"
        for c in finer:
            assert c.parent_id is not None
            assert 0.0 < (c.parent_purity or 0.0) <= 1.0

    def test_truly_nested_structure_reports_full_purity(self):
        """The positive path. These 9 cells sit entirely inside 3 federations, so
        purity must be 1.0 and the level must be marked nested — otherwise the
        nesting check is not actually measuring anything."""
        result = self._nested_result()
        for lv in result.levels[1:]:
            assert lv.mean_parent_purity == pytest.approx(1.0)
            assert lv.nested_in_parent is True
        assert not any("not strictly nested" in w for w in result.warnings)

    def test_non_nested_hierarchy_is_flagged_not_hidden(self):
        """A resolution sweep does not guarantee containment. Where it fails, the
        purity figure must say so rather than a dendrogram implying a
        relationship we did not verify."""
        result = analyse(as_pseudonym(planted(groups=4, size=10)), "snap-1",
                         seed=SEED, bootstrap_runs=5, backend=BACKEND)
        for lv in result.levels[1:]:
            if lv.nested_in_parent is False:
                assert any("not strictly nested" in w for w in result.warnings)
                assert (lv.mean_parent_purity or 1.0) <= 0.99

    def test_parent_ids_reference_real_communities(self):
        result = self._nested_result()
        for c in result.communities.values():
            if c.parent_id is not None:
                assert c.parent_id in result.communities
                assert result.communities[c.parent_id].level == c.level - 1


# ---------------------------------------------------------------------------
# Stability
# ---------------------------------------------------------------------------

class TestStability:
    def test_clear_structure_is_stable(self):
        edges = planted(w_in=5.0, w_out=0.1)
        ref = BACKEND.partition(edges, 1.0, SEED)
        ci = {(s, d) if s <= d else (d, s): 0.05 for s, d, _ in edges}
        stab, _ = bootstrap_stability(edges, ref, 1.0, SEED, BACKEND, ci, runs=10)
        core = [v for v in stab if v.endswith(("N3", "N4", "N5"))]
        assert sum(stab[v] for v in core) / len(core) > 0.8

    def test_weak_evidence_destabilises_the_assignment_it_supports(self):
        """The failure mode this guards against.

        `swing` is one node whose group membership rests on two near-equal edges
        — the situation where a single piece of intelligence decides which
        organisation a person is recorded as belonging to. When that evidence is
        graded reliable the assignment holds; when it is graded unreliable, the
        assignment must fall below the disclosure threshold rather than being
        presented as a finding.

        Note that a graph-wide mean would hide this: the rest of the graph is
        well-evidenced, so averaging drowns the one assignment that is actually
        in doubt. Stability is per-vertex for exactly this reason.
        """
        edges = swing()
        ref = BACKEND.partition(edges, 1.0, SEED)
        strong = {k: 0.02 for k in _pairs(edges)}
        weak = {k: 0.85 for k in _pairs(edges)}

        s_strong, _ = bootstrap_stability(edges, ref, 1.0, SEED, BACKEND,
                                          strong, runs=24)
        s_weak, _ = bootstrap_stability(edges, ref, 1.0, SEED, BACKEND,
                                        weak, runs=24)

        assert s_strong["x"] > 0.9
        assert s_weak["x"] < s_strong["x"] - 0.3
        assert s_weak["x"] < MIN_DISCLOSABLE_STABILITY

    def test_instability_concentrates_on_the_weak_evidence(self):
        """Per-edge intervals rather than uniform noise: the well-evidenced core
        must stay confident while the doubtful assignment degrades. Uniform noise
        would blur the two and make every assignment look equally shaky, which is
        just as misleading as making them all look solid."""
        edges = swing()
        ref = BACKEND.partition(edges, 1.0, SEED)
        ci = {k: 0.85 for k in _pairs(edges)}
        stab, _ = bootstrap_stability(edges, ref, 1.0, SEED, BACKEND, ci, runs=24)

        core = [v for v in stab if v != "x"]
        core_mean = sum(stab[v] for v in core) / len(core)
        assert core_mean > 0.8
        assert stab["x"] < core_mean - 0.25

    def test_singleton_gets_zero_not_one(self):
        edges = [("a", "b", 5.0), ("b", "c", 5.0), ("a", "c", 5.0),
                 ("z", "y", 5.0)]
        ref = {"a": 0, "b": 0, "c": 0, "z": 1, "y": 2}
        ci = {k: 0.05 for k in [("a", "b"), ("b", "c"), ("a", "c"), ("y", "z")]}
        stab, _ = bootstrap_stability(edges, ref, 1.0, SEED, BACKEND, ci, runs=5)
        assert stab["z"] == 0.0
        assert stab["y"] == 0.0

    def test_stability_is_bounded(self):
        edges = planted()
        ref = BACKEND.partition(edges, 1.0, SEED)
        ci = {(s, d) if s <= d else (d, s): 0.1 for s, d, _ in edges}
        stab, _ = bootstrap_stability(edges, ref, 1.0, SEED, BACKEND, ci, runs=8)
        assert all(0.0 <= v <= 1.0 for v in stab.values())

    def test_bootstrap_is_reproducible(self):
        edges = planted()
        ref = BACKEND.partition(edges, 1.0, SEED)
        ci = {(s, d) if s <= d else (d, s): 0.3 for s, d, _ in edges}
        a, _ = bootstrap_stability(edges, ref, 1.0, SEED, BACKEND, ci, runs=6)
        b, _ = bootstrap_stability(edges, ref, 1.0, SEED, BACKEND, ci, runs=6)
        assert a == b


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

class TestRoles:
    def test_high_internal_degree_scores_as_core(self):
        edges = [("hub", f"n{i}", 5.0) for i in range(10)]
        edges += [(f"n{i}", f"n{i + 1}", 0.5) for i in range(9)]
        part = {"hub": 0, **{f"n{i}": 0 for i in range(10)}}
        roles = compute_roles(edges, part)
        z, p, role, _k_in, _k_out = roles["hub"]
        assert z > 2.5
        assert role in {"CORE_WITHIN_GROUP", "CONNECTOR_HUB"}

    def test_node_spanning_two_groups_has_high_participation(self):
        edges = ([("bridge", f"a{i}", 1.0) for i in range(4)]
                 + [("bridge", f"b{i}", 1.0) for i in range(4)])
        edges += [(f"a{i}", f"a{j}", 3.0) for i in range(4) for j in range(i + 1, 4)]
        edges += [(f"b{i}", f"b{j}", 3.0) for i in range(4) for j in range(i + 1, 4)]
        part = {"bridge": 0, **{f"a{i}": 0 for i in range(4)},
                **{f"b{i}": 1 for i in range(4)}}
        _z, p, _role, _ki, _ko = compute_roles(edges, part)["bridge"]
        assert p > 0.4

    def test_uniform_community_yields_no_spurious_leader(self):
        """Every member identical means nobody is unusual. Dividing by an epsilon
        instead of returning z = 0 is how a group of equals acquires a fake
        hierarchy."""
        edges = [(f"n{i}", f"n{j}", 1.0) for i in range(4) for j in range(i + 1, 4)]
        part = {f"n{i}": 0 for i in range(4)}
        for v, (z, _p, _r, _ki, _ko) in compute_roles(edges, part).items():
            assert z == 0.0

    def test_participation_is_in_range(self):
        edges = planted()
        part = BACKEND.partition(edges, 1.0, SEED)
        for _v, (_z, p, _r, _ki, _ko) in compute_roles(edges, part).items():
            assert 0.0 <= p <= 1.0

    def test_role_names_avoid_operational_implications(self):
        """Role labels appear in disclosure bundles. "Lieutenant" or "boss" would
        be a claim about a person; these describe the measurement."""
        edges = planted()
        part = BACKEND.partition(edges, 1.0, SEED)
        forbidden = {"BOSS", "LEADER", "LIEUTENANT", "KINGPIN", "SUSPECT",
                     "ORGANISER", "PRINCIPAL"}
        for _v, (_z, _p, role, _ki, _ko) in compute_roles(edges, part).items():
            assert role not in forbidden


# ---------------------------------------------------------------------------
# Overlap
# ---------------------------------------------------------------------------

class TestOverlap:
    def test_multi_affiliated_node_is_flagged(self):
        edges = [(f"a{i}", f"a{j}", 3.0) for i in range(4) for j in range(i + 1, 4)]
        edges += [(f"b{i}", f"b{j}", 3.0) for i in range(4) for j in range(i + 1, 4)]
        edges += [("a0", "b0", 3.0), ("a0", "b1", 3.0), ("a0", "b2", 3.0)]
        part = {**{f"a{i}": 0 for i in range(4)}, **{f"b{i}": 1 for i in range(4)}}
        ids = {0: "L0-C0000", 1: "L0-C0001"}
        out = detect_secondary_affiliations(edges, part, ids)
        assert "L0-C0001" in dict(out.get("a0", ()))

    def test_single_edge_does_not_create_an_affiliation(self):
        """One phone call must not produce a second "membership" that an analyst
        then has to disprove."""
        edges = [(f"a{i}", f"a{j}", 1.0) for i in range(4) for j in range(i + 1, 4)]
        edges += [(f"b{i}", f"b{j}", 1.0) for i in range(4) for j in range(i + 1, 4)]
        edges += [("a0", "b0", 50.0)]
        part = {**{f"a{i}": 0 for i in range(4)}, **{f"b{i}": 1 for i in range(4)}}
        out = detect_secondary_affiliations(edges, part, {0: "L0-C0000", 1: "L0-C0001"})
        assert "a0" not in out

    def test_secondary_list_is_capped_and_ordered(self):
        edges = []
        for g in range(5):
            for i in range(3):
                for j in range(i + 1, 3):
                    edges.append((f"g{g}n{i}", f"g{g}n{j}", 2.0))
        for g in range(1, 5):
            for i in range(3):
                edges.append(("g0n0", f"g{g}n{i}", 1.0 * g))
        part = {f"g{g}n{i}": g for g in range(5) for i in range(3)}
        ids = {g: f"L0-C{g:04d}" for g in range(5)}
        out = detect_secondary_affiliations(edges, part, ids)
        shares = [s for _c, s in out.get("g0n0", ())]
        assert len(shares) <= 3
        assert shares == sorted(shares, reverse=True)


# ---------------------------------------------------------------------------
# End-to-end guardrails
# ---------------------------------------------------------------------------

class TestPipelineGuardrails:
    def test_analysis_is_reproducible(self):
        """A defence expert rerunning this on disclosed inputs must get the same
        communities, or the analysis cannot be relied on in proceedings."""
        edges = as_pseudonym(planted(groups=4, size=8))
        a = analyse(edges, "snap-1", seed=SEED, bootstrap_runs=6, backend=BACKEND)
        b = analyse(edges, "snap-1", seed=SEED, bootstrap_runs=6, backend=BACKEND)
        assert a.assignments == b.assignments
        assert {k: v.members for k, v in a.communities.items()} == \
               {k: v.members for k, v in b.communities.items()}

    def test_tiny_groups_are_not_reported_as_communities(self):
        edges = as_pseudonym([("a", "b", 5.0), ("c", "d", 5.0), ("e", "f", 5.0)])
        result = analyse(edges, "snap-1", seed=SEED, bootstrap_runs=4,
                         backend=BACKEND)
        assert MIN_COMMUNITY_SIZE > 2, "pairs must not qualify as communities"
        for a in result.assignments.values():
            assert a.community_id == UNCLUSTERED
            assert a.role == "UNCLASSIFIED"

    def test_structureless_graph_is_reported_as_such(self):
        """Modularity maximisation always returns a partition. On a graph with no
        community structure that partition is arbitrary, and an analyst who is
        not told so will act on it."""
        edges = [(f"n{i}", f"n{(i + 1) % 30}", 1.0) for i in range(30)]
        result = analyse(as_pseudonym(edges), "snap-1", seed=SEED,
                         bootstrap_runs=4, backend=BACKEND)
        assert result.warnings, "no warning emitted for a structureless graph"

    def test_empty_projection_warns_and_returns_nothing(self):
        result = analyse([], "snap-1", seed=SEED, backend=BACKEND)
        assert result.assignments == {}
        assert any("empty projection" in w for w in result.warnings)

    def test_result_records_everything_needed_to_reproduce_it(self):
        result = analyse(as_pseudonym(planted()), "snap-1", seed=SEED,
                         bootstrap_runs=4, backend=BACKEND)
        assert result.seed == SEED
        assert result.algorithm_version
        assert result.backend
        assert result.bootstrap_runs == 4

    def test_multi_edges_between_a_pair_are_collapsed(self):
        edges = [PseudonymEdge("a", "b", 1.0, "COMMUNICATED_WITH", 0.1),
                 PseudonymEdge("b", "a", 2.0, "TRANSACTED_WITH", 0.1)]
        collapsed = to_edges(edges)
        assert len(collapsed) == 1
        assert collapsed[0][2] == pytest.approx(3.0)

    def test_no_field_resembling_a_risk_score_on_assignments(self):
        """Individual risk/threat scoring was out of scope and several guardrails
        here assume its absence. This fails the build if one is added."""
        from worker.community import NodeAssignment
        fields = set(NodeAssignment.__dataclass_fields__)
        forbidden = {"risk", "risk_score", "threat", "threat_level", "priority",
                     "harm_score", "danger", "rank", "target_score"}
        assert not (fields & forbidden), f"risk-scoring field added: {fields & forbidden}"

    def test_assignments_are_keyed_only_by_surrogate(self):
        edges = as_pseudonym(planted())
        result = analyse(edges, "snap-1", seed=SEED, bootstrap_runs=4,
                         backend=BACKEND)
        inputs = {v for s, d, _w in planted() for v in (s, d)}
        assert set(result.assignments) <= inputs


# ---------------------------------------------------------------------------
# Derivation envelopes
# ---------------------------------------------------------------------------

class TestDerivation:
    def _result(self, **kw):
        return analyse(as_pseudonym(planted(groups=4, size=8)), "snap-1",
                       seed=SEED, bootstrap_runs=6, backend=BACKEND, **kw)

    def test_threshold_matches_the_api_side_constant(self):
        """Z4 must not import from the API package, so the threshold is
        duplicated. Drift would silently widen what gets disclosed."""
        from app.security.rules_common import MIN_DISCLOSABLE_STABILITY as api_min
        assert MIN_DISCLOSABLE_STABILITY == api_min

    def test_envelope_carries_reproduction_parameters(self):
        result = self._result()
        community = next(iter(result.at_level(result.primary_level)))
        env = envelope_for_community(result, community)
        assert env.seed == SEED
        assert env.backend == BACKEND.name
        assert env.algorithm_version == result.algorithm_version
        assert env.resolution > 0

    def test_envelope_always_states_what_is_not_established(self):
        result = self._result()
        community = next(iter(result.at_level(result.primary_level)))
        env = envelope_for_community(result, community)
        assert env.not_established == NOT_ESTABLISHED
        assert any("not evidence" in s for s in env.not_established)
        assert env.method_limits

    def test_low_stability_result_is_not_disclosable(self):
        from worker.community import Community
        result = self._result()
        shaky = Community(
            community_id="L0-C9999", level=result.primary_level,
            resolution=1.0, size=10, members=tuple(f"n{i}" for i in range(10)),
            internal_weight=5.0, external_weight=5.0, stability=0.2,
        )
        env = envelope_for_community(result, shaky)
        assert not env.disclosable
        assert "stability" in (env.non_disclosure_reason or "")
        with pytest.raises(ValueError, match="not disclosable"):
            env.require_disclosable()

    def test_disclosable_envelope_does_not_raise(self):
        from worker.community import Community
        result = self._result()
        solid = Community(
            community_id="L0-C0000", level=result.primary_level,
            resolution=1.0, size=10, members=tuple(f"n{i}" for i in range(10)),
            internal_weight=50.0, external_weight=1.0, stability=0.95,
        )
        env = envelope_for_community(result, solid)
        if env.disclosable:
            env.require_disclosable()

    def test_bridging_role_carries_the_shared_infrastructure_caveat(self):
        """Taxi firms, delivery drivers and solicitors sit between unconnected
        groups. Without this caveat a bridging position reads as significance."""
        from worker.community import NodeAssignment
        result = self._result()
        assignment = NodeAssignment(
            surrogate="X", community_id=next(iter(result.communities)),
            level=result.primary_level, stability=0.9, role="CONNECTOR_HUB",
            within_z=3.0, participation=0.5, internal_weight=5.0,
            external_weight=5.0,
        )
        env = envelope_for_assignment(result, assignment)
        assert any("solicitor" in s or "delivery" in s for s in env.method_limits)

    def test_multi_affiliation_caveat_is_added(self):
        from worker.community import NodeAssignment
        result = self._result()
        assignment = NodeAssignment(
            surrogate="X", community_id=next(iter(result.communities)),
            level=result.primary_level, stability=0.9, role="PERIPHERAL",
            within_z=0.0, participation=0.5, internal_weight=5.0,
            external_weight=5.0,
            secondary_communities=(("L0-C0001", 0.4),),
        )
        env = envelope_for_assignment(result, assignment)
        assert any("more than one community" in s for s in env.method_limits)

    def test_review_summary_leads_with_limitations(self):
        """A review screen that leads with findings gets approved on the
        findings. This one leads with why review is required."""
        result = self._result()
        summary = summarise_for_review(result)
        keys = list(summary)
        assert keys[0] == "review_required_because"
        assert summary["reviewer_must_confirm"]
        assert "hypotheses, not findings" in " ".join(summary["reviewer_must_confirm"])
        assert summary["reproducible_with_seed"] == SEED

    def test_review_summary_counts_withheld_assignments(self):
        result = self._result()
        summary = summarise_for_review(result)
        counts = summary["counts"]
        assert "assignments_below_disclosure_threshold" in counts
        assert counts["vertices"] == result.vertex_count
