# Community & Hierarchy Detection

This document specifies the only analytical capability this system ships:
identifying groups in a criminal network and the nesting relationships between
them. It covers what the algorithms do, what they demonstrably do not do, and
the controls that keep a statistical grouping from being read as a finding of
fact.

Implementation lives in `services/analytics/worker/`. Tests are
`tests/test_analytics.py` (68 cases).

Deliberately out of scope, and absent from the codebase: key-player or
disruption modelling, temporal link prediction, and entity resolution across
sources. Each is a defensible capability and each was excluded from this
iteration. That matters more than it sounds — see §9.

---

## 1. The pseudonymity boundary

Everything in this tier operates on opaque surrogate keys. The compute plane
(zone Z4) never receives a name, a phone number, an address, a date of birth, or
the internal entity UUID. It receives triples of the form
`(surrogate_src, surrogate_dst, weight)` plus a per-edge confidence interval, and
it returns groupings over those same surrogates.

This is the load-bearing privacy decision in the whole design. Analytics is the
tier with the largest attack surface: it runs third-party numerical libraries, it
is the tier most likely to be scaled onto commodity or burst capacity, it holds
whole-graph state in memory, and it is operated by data engineers rather than
warranted officers. Making it identity-free converts the blast radius of a
compromise there from "national intelligence leak" to "structural metadata
leak" — still serious, no longer catastrophic.

Re-identification happens exactly once, at the API tier (Z2), inside an
authorization check, against an encrypted crosswalk that never leaves Z2.

### Surrogate construction

Surrogates are per-snapshot. For snapshot `S`, a key is derived by HKDF-SHA256
from a root key held in the HSM with `info = b"cna-surrogate-v1"` and salt
derived from the snapshot id; the surrogate for entity `e` is the first 128 bits
of `HMAC-SHA256(k_S, uuid(e))`, rendered unpadded base32.

Per-snapshot derivation is the point. A stable pseudonym across snapshots is
merely a slower identifier: anyone holding two snapshots can correlate them, and
over a year of weekly snapshots the longitudinal record of an individual is fully
reconstructible from "anonymous" data. Rotating the derivation per snapshot
means correlation requires the crosswalk, which requires Z2, which requires an
authorization decision and an audit record.

The cost is real and accepted: you cannot diff two snapshots inside Z4. Trend
analysis across snapshots must be done in Z2 after re-identification, under
policy. We would rather pay that than ship a system whose anonymisation degrades
with every snapshot taken.

`Pseudonymizer.assert_no_identities()` is a runtime guard over the outbound
projection: it fails the export if any field outside the permitted structural set
appears. It is a cheap check against the most likely future regression, which is
someone adding `display_name` to the projection query "just for debugging".

### Who is eligible for clustering

Only entities in `CLUSTERABLE_CATEGORIES` — `SUSPECT` and `CONVICTED` — enter the
projection. Victims, witnesses, and incidental contacts are excluded at the
Cypher level in `Q_EXPORT_PROJECTION`, not filtered afterwards.

Assigning an innocent person membership of a "criminal community" is the central
algorithmic harm this system can cause, and a caveat in the UI is not an adequate
answer to it. A victim who appears in the graph because they were burgled should
not acquire a community id, a role label, and a stability score that some future
analyst reads as an intelligence product. The exclusion is structural.

The consequence is that clusters are computed over a subgraph, and the excluded
nodes may well have been structurally important. That is stated in every
derivation envelope (§7) as an input exclusion, because an analyst reading a
sparse-looking group needs to know the sparseness may be an artefact of the
filter rather than a fact about the network.

---

## 2. Edge weighting from 5×5×5

Raw edge counts are the wrong input. Two hundred cell-site co-locations from a
technical deployment under warrant and two hundred inferred associations from a
single uncorroborated informant are not the same evidence, and a modularity
optimiser handed both as "weight 200" will treat them identically.

`worker/weighting.py` maps UK National Intelligence Model 5×5×5 grading onto a
multiplicative confidence factor:

| Source evaluation | Factor | | Intelligence assessment | Factor |
|---|---|---|---|---|
| 1 Always reliable | 1.00 | | 1 Known true | 1.00 |
| 2 Mostly reliable | 0.85 | | 2 Known personally to source | 0.80 |
| 3 Sometimes reliable | 0.60 | | 3 Not known personally, corroborated | 0.55 |
| 4 Unreliable | 0.30 | | 4 Cannot be judged | 0.25 |
| 5 Untested source | 0.25 | | 5 Suspected false | 0.00 |

Relationship type contributes a third factor (`COMMUNICATED_WITH` and
`TRANSACTED_WITH` at 1.00 down to `ASSOCIATE_OF` at 0.60), because a recorded
transaction is a harder fact than an officer's note that two people are
associates.

Assessment grade 5 maps to 0.00, which drops the edge entirely. Intelligence
assessed as suspected false should not contribute to a structural conclusion at
any weight; keeping it at 0.05 "for completeness" would mean a sufficiently large
volume of suspected-false reporting could still create a community.

Volume is damped with `log1p` rather than entering linearly. A thousand
messages between two people is stronger evidence of a relationship than ten, but
it is not a hundred times stronger, and undamped volume lets a single chatty pair
dominate the modularity landscape.

`CONFIDENCE_FLOOR = 0.05` sets the weight below which an edge is not worth
carrying.

### The confidence interval

`confidence_interval(source_eval, intel_assessment) = 0.05 + 0.75 × (1 − reliability)`

This is the one derived number that crosses into Z4 alongside the weight. It is
deliberately a single scalar rather than the three 5×5×5 grades: the grades are
rendered for the analyst by the UI from Z3 data, so Z4 has no need for them, and
one number is the minimum that supports the perturbation model in §5.

It is a *usable proxy for evidential doubt*, not a statistical confidence
interval in the frequentist sense. The doc says so, the docstring says so, and
the derivation envelope says so, because the phrase invites exactly the wrong
inference.

---

## 3. Leiden, not Louvain

`worker/backends.py` defines a `ClusteringBackend` protocol with two
implementations: `IgraphLeidenBackend` (production, `leidenalg` with
`RBConfigurationVertexPartition` and `n_iterations=-1` to iterate to
convergence) and `ReferenceBackend` (pure stdlib, no dependencies).

Leiden over Louvain for one reason that is not about speed. Louvain can and does
emit communities that are internally disconnected: a set of nodes labelled as one
community where no path exists between two of its members using only intra-
community edges. In a citation network that is a curiosity. Here, an analyst
reading a single labelled group is reading "these people form one organisation",
and if the group is actually two disconnected halves the system has manufactured
a link between two organisations that has no basis in the data. Leiden guarantees
connected communities. That guarantee is the feature.

`ReferenceBackend` exists so the suite runs, and the system degrades, in an
air-gapped enclave where installing `leidenalg` is not possible — which for a
police network is the normal case. It implements Louvain-style local moving with
aggregation, then recovers the connectivity guarantee explicitly in
`_split_disconnected()`, which BFS-splits every community into its connected
components. Slower and less refined than Leiden; never silently wrong in the way
that matters.

One implementation detail worth flagging because it was a real bug caught in
development: aggregation must carry each super-node's internal weight forward as
a self-loop. Dropping it makes every super-node look lower-degree than it is, so
the next level over-merges, and the resolution parameter stops meaning anything
past level 0 — the sweep in §4 would then produce a smooth-looking curve that was
pure artefact. `_aggregate()` accumulates `w / 2.0` per intra-community edge
(counted once from each endpoint) and both `two_m` and `degree` include
`2 × loops`.

`select_backend(prefer_production=True)` picks Leiden when available and falls
back with a recorded warning, never silently. The backend name and
`ALGORITHM_VERSION` are stamped on every result, so a conclusion reached under
the reference backend is identifiable as such a year later.

---

## 4. Hierarchy by resolution sweep and plateau detection

Criminal networks are not flat. A county-lines operation has a nesting structure
— a controlling group, regional distributors, local dealers — and a single
partition at a single resolution cannot express it.

The naive approach is to run the algorithm at increasing resolution and call each
result a level of the hierarchy. That produces as many "levels" as you had
parameter values, most of them noise, and it invites the analyst to interpret an
arbitrary parameter choice as a fact about the organisation.

Instead, `sweep()` runs the backend across `DEFAULT_RESOLUTIONS` — currently ten
values from 0.1 to 4.0 — and `find_plateaux()` groups adjacent resolutions whose
partitions agree, using adjusted Rand index with a threshold of 0.90. A plateau
is a range of the parameter over which the answer is stable, and stability across
a parameter you had no principled way to choose is the closest thing to evidence
that a level is real rather than an artefact of the setting.

Each plateau becomes one level. `analyse()` selects the *widest* plateau as
`primary_level` — the structure that survives the most parameter variation.

### Nesting is checked, not assumed

A resolution sweep does not guarantee that finer partitions nest inside coarser
ones. Modularity optimisation at a higher resolution can and does cut across the
coarser boundaries.

So `_link_hierarchy()` does not draw a dendrogram. For each community it records
the plurality parent from the level above and a `parent_purity` — the fraction of
its members that came from that single parent. Where purity is 1.0, containment
is genuine and `nested_in_parent` is true. Where it is not, the result says so and
a warning is attached, rather than rendering a tree that asserts a containment
relationship nobody verified.

Communities below `MIN_COMMUNITY_SIZE = 3` are labelled `UNCLUSTERED` rather than
reported as tiny groups. A "community" of two is a relationship, and the
machinery of community detection adds nothing to it beyond false authority.

---

## 5. Per-vertex stability

Every reported assignment carries a stability score in [0, 1]. It is computed by
bootstrap: `DEFAULT_BOOTSTRAP_RUNS = 20` re-runs of the primary level, each
perturbing every edge weight independently and uniformly within that edge's own
confidence interval from §2, dropping edges that fall below `CONFIDENCE_FLOOR`.
A vertex's stability is its mean co-membership frequency with its primary-level
peers across runs.

Three decisions inside that sentence are worth defending.

**Per-vertex, not graph-wide.** A single number for the whole partition is nearly
useless operationally, because real networks are mostly well-evidenced with doubt
concentrated at the boundaries. The graph mean averages away precisely the
assignments that are in question. This was confirmed empirically during
development: on a planted-partition graph, weight perturbation cannot dislodge
topologically dense cliques at all, and the graph mean sat at 1.000 for every
noise level tested. The behaviour only becomes visible per-vertex, on a node
whose membership genuinely hinges on two near-equal edges — where stability moves
from 1.000 at ci=0.02 to 0.500 at ci=0.85 while its core neighbours stay above
0.90. That is the signal an analyst needs: *this* person's placement is
uncertain, not *this partition* is 94% good.

**Mean co-membership, not pairwise Jaccard.** Cost is O(runs) rather than
O(runs × pairs), and more importantly the resulting number states something a
court can follow: "across twenty re-runs with the evidence weights varied within
their assessed reliability, this person was grouped with the same people 61% of
the time."

**Singletons score 0.0, not 1.0.** A vertex alone in its community is trivially
co-resident with all of its zero peers. Scoring that as perfect stability would
report maximum confidence in the assignment we know least about.

Above `PAIR_EXACT_THRESHOLD = 2_000` vertices, co-membership counting switches
from exact to sampled (`PAIR_SAMPLE_MULTIPLIER = 20`). The switch is recorded in
`CommunityResult.approximations` and propagates into the derivation envelope, so
a sampled number is never presented as an exact one.

---

## 6. Roles, and the words used for them

`compute_roles()` implements the Guimerà–Amaral cartographic classification:
within-module degree z-score against participation coefficient P, thresholds
`Z_HUB = 2.5`, `P_PROVINCIAL = 0.30`, `P_CONNECTOR = 0.75`, `P_PERIPHERAL = 0.62`,
`P_ULTRA_PERIPHERAL = 0.05`.

The labels are deliberately plain and deliberately structural:

| Label | Structural meaning |
|---|---|
| `CORE_WITHIN_GROUP` | High degree, almost all of it inside one group |
| `CONNECTOR_HUB` | High degree spread across several groups |
| `DISPERSED_HUB` | High degree with no group concentration |
| `ISOLATED_WITHIN_GROUP` | Ordinary degree, contained in one group |
| `PERIPHERAL` | Ordinary degree, mostly one group |
| `BRIDGING` | Ordinary degree spanning groups |

Not "kingpin", not "lieutenant", not "leader". The published literature calls
these things hubs and connectors; investigators reading a screen will translate
whatever word appears into a hypothesis about seniority. `CORE_WITHIN_GROUP`
makes the analyst do the translation consciously. A label like "kingpin" does it
for them, invisibly, on the basis of a degree calculation.

This is also why the analytics selection for this iteration stops here. Role
inference describes position in a structure. It does not identify who matters, who
to arrest, or what happens if you remove them — those are the key-player and
disruption questions, and they are not implemented (§9).

When the within-module degree standard deviation is below 1e-12, `z` is set to
0.0 rather than computed. In a group where everyone has identical degree there is
no leader to find, and dividing by a near-zero standard deviation would
manufacture one from floating-point noise.

### Multiple affiliations

`detect_secondary_affiliations()` reports additional groups a vertex is
substantially connected to: at least `MIN_SECONDARY_SHARE = 0.25` of its external
weight and at least `MIN_SECONDARY_CONTACTS = 2` distinct contacts, capped at
`MAX_SECONDARY_COMMUNITIES = 3`.

Hard partitioning is a poor fit for how people actually work. Someone brokering
between two groups is a real and investigatively interesting pattern, and a
single-label partition erases it — the broker is assigned to whichever side has
marginally more weight and the brokering disappears. The `is_multi_affiliated`
flag surfaces it, and triggers an extra caveat in the derivation envelope,
because multi-affiliation is also the signature of the most common false
positive in this whole system: shared infrastructure. A taxi firm, a delivery
driver, a solicitor, a corner shop.

---

## 7. Derivation envelopes

Nothing leaves this tier without one. `worker/derivation.py` builds a
`DerivationEnvelope` for every community and every assignment, carrying the
algorithm version, backend, seed, resolution, plateau width, bootstrap run count,
stability, any approximations used, the input exclusions, the method limits, and
four fixed statements about what the result is not. Among them, verbatim:

> These results are an investigative hypothesis to be tested against evidence.
> They are not evidence.

`require_disclosable()` raises rather than returning a flag when stability is
below `MIN_DISCLOSABLE_STABILITY = 0.6`. An unstable assignment is not shown with
a warning; it is withheld, and `Redactor.community()` in the API tier refuses to
serialise any community record that arrives without a `derivation` key at all.
Two independent layers, both fail-closed, because "the caveat didn't render" is
the exact failure mode that puts an unstable statistical grouping in front of a
court as a finding.

`MIN_DISCLOSABLE_STABILITY` is intentionally duplicated in Z4 rather than
imported from the API package. The pseudonymity boundary is also a dependency
boundary — if Z4 can import Z2 code, the import graph will eventually carry
something identifying across it. A test asserts the two constants agree, so the
duplication cannot drift.

`summarise_for_review()` returns a dict whose first key is
`review_required_because`. Key order in a serialised review payload determines
what a human sees first, and what they should see first is why they are being
asked.

---

## 8. Automated decision-making

LED Art. 11 and GDPR Art. 22 prohibit decisions producing adverse legal effects
based solely on automated processing. Community membership feeding into an arrest
decision, a stop, or a disclosure is squarely within scope.

Three controls, in layers. The output is framed as a hypothesis in the data model
itself, not in presentation — `Redactor.community()` sets
`presentation="HYPOTHESIS"` and attaches a disclaimer, so a client that ignores
the field is dropping a documented obligation rather than merely styling
something differently. Derivation envelopes travel with the data, so the caveats
cannot be separated from the finding by a copy-paste into a case file. And export
of derived data requires `Resource.human_reviewed`, which is set only when a
named person has recorded a review — the `EXPORT` action on a `COMMUNITY` resource
is denied without it.

The honest limit: none of this prevents an analyst from reading a group label and
acting on it. What it does is ensure that the record shows they were told it was a
hypothesis, that a named human reviewed it, and that the review is in the audit
chain. Technical controls can make the caveat unavoidable and the review
recorded. They cannot make someone read.

---

## 9. What is not here

This iteration implements community and hierarchy detection only. The following
were considered and excluded, and the exclusion is documented rather than left as
an apparent oversight, because an unimplemented capability that looks like an
oversight tends to get added by someone who has not thought about why it was left
out.

**Key-player and disruption modelling.** Ranking individuals by centrality or
simulating removal effects. Excluded because it converts a structural description
into an operational recommendation about specific named people, and the gap
between "high betweenness" and "worth arresting" is filled entirely by
assumptions the model does not contain. Adding it requires its own DPIA section
and its own human-review gate.

**Temporal analysis and link prediction.** Evolution over time, and inferring
edges that are not in the data. Excluded because predicted edges are
indistinguishable from observed ones once they are in a graph store, and a system
that cannot tell an analyst which links were observed and which were guessed
should not contain guessed links. Also blocked by the per-snapshot surrogate
design in §1, which is a trade we made knowingly.

**Entity resolution and data fusion.** Merging records that may refer to the same
person across sources. Excluded because a false merge is the most damaging error
this system could make — it attributes one person's associations to another, and
it is very hard to detect downstream. It needs a confidence model, a reversible
merge representation, and an unmerge path with audit, none of which exist yet.

If any of these is picked up later, the pseudonymity boundary in §1 is the
constraint to design against first, not last.

---

## 10. Scale path

Pilot tier is what is built: a single worker, whole graph in memory,
`ReferenceBackend` or `leidenalg` in-process. Comfortable to roughly 10⁵ vertices
and 10⁶ edges, which covers a force-area intelligence graph.

| Trigger | Replacement |
|---|---|
| Sweep wall-clock > 30 min | Neo4j GDS Leiden, projection in the database, sweep parallel across resolutions |
| Vertices > 10⁶ or memory > 32 GB | GDS with Arrow projection, or graph partitioning with boundary reconciliation |
| Bootstrap > 1 h | Parallelise runs across workers; sampled co-membership already active above 2·10³ |
| Multi-tenant contention | Per-tenant worker pools with separate surrogate root keys — never a shared key across tenants |

The migration constraint that does not change at any tier: the compute plane
stays identity-free. GDS runs inside Neo4j, which means at that point the
projection must be built in a *separate pseudonymized database instance* fed by
`Q_EXPORT_PROJECTION`, not as a projection over the evidential store. Running GDS
directly over identifying data would be a simpler deployment and would delete the
central privacy property of this design. It is the one shortcut to refuse.

---

## References

Traag, Waltman & van Eck (2019), *From Louvain to Leiden: guaranteeing
well-connected communities*, Scientific Reports 9:5233 — the connectivity
argument in §3.

Guimerà & Amaral (2005), *Functional cartography of complex metabolic networks*,
Nature 433:895 — the z–P role framework in §6.

Reichardt & Bornholdt (2006), *Statistical mechanics of community detection*,
Phys. Rev. E 74:016110 — the resolution parameter used in the sweep in §4.

Fortunato & Barthélemy (2007), *Resolution limit in community detection*, PNAS
104:36 — why a single resolution is not sufficient, cited in the method limits.

UK Home Office, *National Intelligence Model* 5×5×5 information evaluation —
the grading scheme in §2.
