# Data Model

## Entity types

The model is deliberately narrow. Every additional entity type is an additional
disclosure surface and an additional retention clock to get right, so new types
require a documented investigative need rather than "the source system has it".

| Label | Represents | Key sensitive properties |
|---|---|---|
| `:Person` | A natural person | `subject_category`, `dob_exact`, `address_plain`, `ni_number` |
| `:Organisation` | Company, association, or named group | `registration_no` |
| `:Phone` | A subscriber number or handset | `msisdn_hash` + `msisdn_plain` (encrypted) |
| `:Account` | Bank or payment account | `iban_hash` + `iban_plain` (encrypted) |
| `:Vehicle` | A vehicle | `vrm_hash` + `vrm_plain` (encrypted) |
| `:Location` | A premises or geographic point | `address_plain`, `geo` |
| `:Event` | A bounded occurrence (meeting, seizure, stop) | `occurred_at` |
| `:Case` | An investigation | `authorised_bases` |
| `:LegalBasis` | A warrant, production order, or statutory power | `instrument_type`, `expires_at` |
| `:Provenance` | An ingestion batch manifest | `source_system`, `file_sha256` |
| `:Snapshot` | A point-in-time projection for analytics | `snapshot_id`, `taken_at` |
| `:ProtectedSubject` | Marker co-label on victims and witnesses | — |

### The `subject_category` property

LED Article 6 requires that controllers distinguish between categories of data
subject. This is not a bookkeeping requirement — it is the hook that everything
else hangs from. `subject_category` drives the retention clock, the access rule,
whether the entity is eligible for clustering at all, and whether the
`:ProtectedSubject` co-label is applied.

| Category | Retention default | Clusterable | Access |
|---|---|---|---|
| `SUSPECT` | 6 years from last activity | Yes | Case members |
| `CONVICTED` | Per statutory schedule | Yes | Case members |
| `VICTIM` | 3 years, review earlier | **No** | Elevated + justification |
| `WITNESS` | 3 years, review earlier | **No** | Elevated + justification |
| `CONTACT` | 1 year from last activity | Degree-1 only | Case members |
| `OTHER` | 1 year | No | Case members |

`CONTACT` deserves comment. These are people who appear in the data only because
they communicated with a suspect — the suspect's dentist, their child's school,
a taxi dispatcher. They are overwhelmingly the largest category by volume in any
real CDR-derived graph, and they are entirely innocent. Including them in
community detection produces two bad outcomes: it inflates cluster sizes with
noise, and it assigns innocent people membership in a "criminal community",
which is the exact harm the system must not cause. So contacts participate in
the graph as degree-1 attachment points for structural completeness but are
excluded from the partition. If a contact turns out to be operationally
significant, an analyst re-categorises them as a suspect through an audited,
justified action — which is a human decision on the record, where it belongs.

## Relationship types

| Type | From → To | Cardinality note |
|---|---|---|
| `:COMMUNICATED_WITH` | Phone → Phone | Aggregated per (pair, period), not per call |
| `:USES_PHONE` | Person → Phone | Time-bounded; handsets change hands |
| `:ASSOCIATE_OF` | Person → Person | Human-asserted; always carries 5×5×5 |
| `:TRANSACTED_WITH` | Account → Account | Aggregated per (pair, period) |
| `:HOLDS_ACCOUNT` | Person/Org → Account | Time-bounded |
| `:REGISTERED_TO` | Vehicle → Person/Org | Time-bounded |
| `:PRESENT_AT` | Person/Vehicle → Location/Event | Time-stamped |
| `:APPEARS_IN` | any entity → Case | Carries `case_id` for indexed filtering |
| `:AUTHORISED_BY` | Case → LegalBasis | |
| `:DERIVED_FROM` | any → Provenance | |

`:COMMUNICATED_WITH` is aggregated rather than one edge per call, deliberately.
A year of CDRs for a thousand handsets is tens of millions of individual call
events; as distinct edges that is unusable for community detection and it forces
the analytics tier to hold a volume of behavioural detail it has no need for.
Aggregating to (pair, month) with `call_count`, `total_duration`, `distinct_days`
preserves everything modularity optimisation actually uses and discards the rest.
Individual call detail stays in Z3 for the one case where an analyst legitimately
needs to see it, retrieved per-request under audit.

## 5×5×5 intelligence evaluation

Every substantive relationship carries three integers (UK National Intelligence
Model; the NATO/Admiralty letter-number code maps onto it directly).

`source_eval` 1–5: 1 always reliable, 2 mostly reliable, 3 sometimes reliable,
4 unreliable, 5 untested source.

`intel_assessment` 1–5: 1 known directly true, 2 known to source but not
directly, 3 not known personally but corroborated, 4 not known personally and
uncorroborated, 5 suspected to be false.

`handling_code` 1–5: dissemination permissions, from "may be disseminated to
other law enforcement" through to "recipient-imposed conditions apply".

Two things depend on this and both matter.

**Edge weighting.** Community detection weights each edge by a confidence factor
derived from the evaluation, so uncorroborated intelligence contributes less to
cluster formation than direct observation. Without this, a single piece of
malicious or mistaken hearsay can create an apparent community. The mapping is
in `services/analytics/worker/weighting.py` and is deliberately conservative:
`intel_assessment >= 4` edges are down-weighted to 0.25, and `= 5` edges are
excluded from clustering entirely while remaining visible in the UI.

**Visual honesty.** The frontend renders stroke style from the evaluation
(§ARCHITECTURE.md 7.4). An analyst looking at a cluster must be able to tell at
a glance whether it is held together by billing records or by one informant's
say-so. Rendering both as identical grey lines is a design decision that
manufactures false confidence.

## Provenance without reification

Neo4j relationships cannot themselves have relationships, so linking an edge to
its provenance record requires either reifying every edge into a node — roughly
tripling node count and adding two hops to every traversal — or storing a
`provenance_id` property and resolving it by index.

We store the property. The tradeoff: we lose the ability to traverse from a
provenance node to all edges it sourced in a single pattern, so
"show me everything that came from batch B" becomes an indexed lookup plus a
relationship-property scan rather than a one-hop expansion. That query is a
back-office operation run by data stewards a few times a month, and paying two
extra hops on every analyst traversal to optimise it would be the wrong trade at
any scale. Revisit if provenance-first access becomes a hot path.

## Encryption of identifiers

Directly-actionable identifiers are stored twice: `*_hash` (HMAC with a
key-manager key, for equality lookup and joins) and `*_plain` (envelope-encrypted
with a per-case data key, for display). The base application role is denied read
on every `*_plain` property (`graph/02-rbac.cypher` §2b), so decryption requires
the elevated pool and a PDP permit.

Deterministic hashing is what makes lookup and entity resolution work, and it
does leak equality — an attacker with the store can tell that two records share
a phone number without knowing the number. That is an accepted residual risk,
recorded in the threat model as **R-07**, because equality-preserving lookup is
functionally indispensable here. The compensating control is that the HMAC key
lives in the HSM and is not present in the database, so the hashes cannot be
brute-forced offline against the ~10¹⁰ candidate MSISDN space — which they
trivially could be if we had used a plain SHA-256.
