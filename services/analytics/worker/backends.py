"""Clustering backends.

PRODUCTION uses `leidenalg` on `igraph` (pilot/regional) or distributed Leiden
(national). See ARCHITECTURE.md §6 for the tiering.

WHY LEIDEN AND NOT LOUVAIN
Louvain can return internally disconnected communities — a well-documented
defect, not a tuning problem. In this domain that failure is not cosmetic: a
"community" that is actually two mutually unconnected fragments will be read by
an analyst as one organisation. The system would then be generating a false
investigative conclusion out of a library artefact. Leiden guarantees connected,
locally optimal communities, which makes it a correctness requirement here rather
than a performance preference.

THE REFERENCE BACKEND
`ReferenceBackend` is a pure-stdlib multi-level modularity optimiser with an
explicit connected-component split pass, which recovers Leiden's connectivity
guarantee. It exists so this repo's analytics logic is verifiable in an
air-gapped enclave where installing igraph is not possible — a normal situation
for a police network. It is NOT the production path: it is slower, it does not
implement Leiden's refinement phase, and its partition quality is measurably
worse on large graphs. `select_backend()` prefers igraph and warns loudly when
it falls back.

Everything interesting in this package — the resolution sweep, hierarchy
extraction, stability bootstrapping, role inference, overlap detection — lives in
community.py and is backend-independent, so it is tested identically against
either backend.
"""

from __future__ import annotations

import logging
import random
from collections import defaultdict
from typing import Dict, List, Protocol, Sequence, Tuple

logger = logging.getLogger(__name__)

Partition = Dict[str, int]          # vertex -> community index
Edge = Tuple[str, str, float]       # src, dst, weight


class ClusteringBackend(Protocol):
    name: str

    def partition(self, edges: Sequence[Edge], resolution: float,
                  seed: int) -> Partition: ...


# ---------------------------------------------------------------------------
# Production backend
# ---------------------------------------------------------------------------

class IgraphLeidenBackend:
    """Leiden via leidenalg. The production path."""

    name = "leidenalg/igraph"

    def __init__(self) -> None:
        import igraph          # noqa: F401  (import-time availability check)
        import leidenalg       # noqa: F401
        self._igraph = igraph
        self._leidenalg = leidenalg

    def partition(self, edges: Sequence[Edge], resolution: float,
                  seed: int) -> Partition:
        vertices = sorted({v for s, d, _ in edges for v in (s, d)})
        index = {v: i for i, v in enumerate(vertices)}
        g = self._igraph.Graph(
            n=len(vertices),
            edges=[(index[s], index[d]) for s, d, _ in edges],
            directed=False,
        )
        g.es["weight"] = [w for _, _, w in edges]

        part = self._leidenalg.find_partition(
            g,
            self._leidenalg.RBConfigurationVertexPartition,
            weights="weight",
            resolution_parameter=resolution,
            seed=seed,
            n_iterations=-1,       # iterate to convergence
        )
        return {vertices[i]: part.membership[i] for i in range(len(vertices))}


# ---------------------------------------------------------------------------
# Reference backend — stdlib only
# ---------------------------------------------------------------------------

class ReferenceBackend:
    """Multi-level modularity optimisation with a connectivity split pass.

    Not production. See module docstring.
    """

    name = "reference (stdlib)"

    def partition(self, edges: Sequence[Edge], resolution: float,
                  seed: int) -> Partition:
        if not edges:
            return {}

        adj: Dict[str, Dict[str, float]] = defaultdict(dict)
        for s, d, w in edges:
            if s == d:
                continue
            adj[s][d] = adj[s].get(d, 0.0) + w
            adj[d][s] = adj[d].get(s, 0.0) + w

        vertices = sorted(adj)
        # Track how aggregated super-nodes map back to original vertices across
        # levels, so the final partition is expressed in original vertex names.
        membership: Dict[str, str] = {v: v for v in vertices}
        current_adj = {v: dict(adj[v]) for v in vertices}
        # Aggregated internal weight, carried as self-loops. Dropping it would
        # make each super-node look lower-degree than it is, and the next level
        # would then merge almost everything: the resolution parameter would stop
        # meaning anything after level 0.
        current_loops = {v: 0.0 for v in vertices}

        for _level in range(10):
            local = self._local_moving(current_adj, current_loops, resolution, seed)
            groups = len(set(local.values()))
            if groups == len(current_adj):
                break                      # no further aggregation possible
            membership = {v: str(local[membership[v]]) for v in vertices}
            current_adj, current_loops = self._aggregate(
                current_adj, current_loops, local
            )
            if groups == 1:
                break

        labels = {name: i for i, name in enumerate(sorted(set(membership.values())))}
        partition = {v: labels[membership[v]] for v in vertices}
        return self._split_disconnected(partition, adj)

    # -- local moving ------------------------------------------------------

    def _local_moving(self, adj: Dict[str, Dict[str, float]],
                      loops: Dict[str, float],
                      resolution: float, seed: int) -> Dict[str, int]:
        rng = random.Random(seed)
        two_m = (sum(sum(nbrs.values()) for nbrs in adj.values())
                 + 2.0 * sum(loops.values()))
        if two_m == 0:
            return {v: i for i, v in enumerate(sorted(adj))}

        community = {v: i for i, v in enumerate(sorted(adj))}
        degree = {v: sum(nbrs.values()) + 2.0 * loops.get(v, 0.0)
                  for v, nbrs in adj.items()}
        comm_degree = {community[v]: degree[v] for v in adj}

        order = sorted(adj)
        rng.shuffle(order)
        improved = True
        rounds = 0

        while improved and rounds < 50:
            improved = False
            rounds += 1
            for v in order:
                own = community[v]
                k_v = degree[v]
                comm_degree[own] -= k_v

                # Edge weight from v into each neighbouring community. The
                # self-loop is omitted deliberately: it follows v into whichever
                # community v joins, so it is constant across the candidates and
                # cannot change the argmax.
                links: Dict[int, float] = defaultdict(float)
                for nbr, w in adj[v].items():
                    links[community[nbr]] += w

                best, best_gain = own, 0.0
                base = links.get(own, 0.0) - resolution * k_v * comm_degree.get(own, 0.0) / two_m
                for c, w_into in links.items():
                    if c == own:
                        continue
                    gain = w_into - resolution * k_v * comm_degree.get(c, 0.0) / two_m
                    if gain - base > best_gain + 1e-12:
                        best, best_gain = c, gain - base

                community[v] = best
                comm_degree[best] = comm_degree.get(best, 0.0) + k_v
                if best != own:
                    improved = True

        remap = {c: i for i, c in enumerate(sorted(set(community.values())))}
        return {v: remap[c] for v, c in community.items()}

    def _aggregate(self, adj: Dict[str, Dict[str, float]],
                   loops: Dict[str, float], local: Dict[str, int]
                   ) -> Tuple[Dict[str, Dict[str, float]], Dict[str, float]]:
        out: Dict[str, Dict[str, float]] = {}
        new_loops: Dict[str, float] = defaultdict(float)
        for v, nbrs in adj.items():
            cv = str(local[v])
            out.setdefault(cv, {})
            new_loops[cv] += loops.get(v, 0.0)
            for nbr, w in nbrs.items():
                cn = str(local[nbr])
                if cv == cn:
                    # Counted once from each endpoint, hence the halving.
                    new_loops[cv] += w / 2.0
                else:
                    out[cv][cn] = out[cv].get(cn, 0.0) + w
        return out, dict(new_loops)

    # -- connectivity guarantee -------------------------------------------

    def _split_disconnected(self, partition: Partition,
                            adj: Dict[str, Dict[str, float]]) -> Partition:
        """Split any community that is not internally connected.

        This is the property Louvain fails to guarantee and Leiden provides. We
        recover it explicitly rather than hoping it does not arise, because a
        disconnected "community" presented to an analyst as one group is a false
        statement about the world.
        """
        by_comm: Dict[int, List[str]] = defaultdict(list)
        for v, c in partition.items():
            by_comm[c].append(v)

        out: Partition = {}
        next_label = 0
        for _c, members in sorted(by_comm.items()):
            member_set = set(members)
            unvisited = set(members)
            while unvisited:
                start = next(iter(sorted(unvisited)))
                stack, component = [start], set()
                while stack:
                    v = stack.pop()
                    if v in component:
                        continue
                    component.add(v)
                    for nbr in adj.get(v, {}):
                        if nbr in member_set and nbr not in component:
                            stack.append(nbr)
                for v in component:
                    out[v] = next_label
                next_label += 1
                unvisited -= component
        return out


# ---------------------------------------------------------------------------
# Quality metric
# ---------------------------------------------------------------------------

def modularity(edges: Sequence[Edge], partition: Partition,
               resolution: float = 1.0) -> float:
    """Newman-Girvan modularity with a resolution parameter.

    Used to score partitions across the resolution sweep. Reported alongside
    every result: a partition with modularity near zero has found no structure,
    and saying so plainly is more useful than presenting arbitrary clusters.
    """
    if not edges:
        return 0.0
    two_m = 2.0 * sum(w for _, _, w in edges)
    if two_m == 0:
        return 0.0

    degree: Dict[str, float] = defaultdict(float)
    internal: Dict[int, float] = defaultdict(float)
    comm_degree: Dict[int, float] = defaultdict(float)

    for s, d, w in edges:
        degree[s] += w
        degree[d] += w
        if partition.get(s) == partition.get(d):
            internal[partition[s]] += w

    for v, k in degree.items():
        c = partition.get(v)
        if c is not None:
            comm_degree[c] += k

    q = 0.0
    for c, w_in in internal.items():
        q += (2.0 * w_in) / two_m
    for c, k_c in comm_degree.items():
        q -= resolution * (k_c / two_m) ** 2
    return q


def select_backend(prefer_production: bool = True) -> ClusteringBackend:
    """Prefer leidenalg; fall back to the reference implementation with a loud
    warning. Silent degradation to a weaker algorithm would mean partition
    quality quietly depending on which container the job landed in."""
    if prefer_production:
        try:
            backend = IgraphLeidenBackend()
            logger.info("clustering backend: %s", backend.name)
            return backend
        except ImportError:
            logger.warning(
                "leidenalg/igraph unavailable — falling back to the reference "
                "backend. This is acceptable for tests and air-gapped smoke "
                "runs ONLY; it lacks Leiden's refinement phase and produces "
                "measurably worse partitions at scale. Do not use for "
                "operational analysis."
            )
    return ReferenceBackend()
