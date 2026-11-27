# Criminal Network Analysis System — Architecture

**Status:** Design baseline v1.0
**Owner:** Security Engineering
**Classification of this document:** Internal / Unrestricted (contains no operational data)
**Target regimes:** US CJIS Security Policy 5.9.x *and* EU GDPR + Law Enforcement Directive 2016/680, selectable per tenant
**Sizing baseline:** Pilot tier (~1M entities), with documented migration triggers to Regional (~10M) and National (~500M)

---

## 1. What this system is, and what it deliberately is not

The system ingests lawfully-held investigative data, resolves it into a graph of entities and
relationships, and applies community-detection algorithms to help analysts understand the
*structure* of an organised criminal group: who clusters with whom, which clusters are distinct,
which actors bridge clusters, and how that structure has changed over time.

It produces **investigative hypotheses**. It does not produce findings of fact, evidence, risk
scores about individuals, or any output that by itself justifies an adverse action against a person.
This is not a disclaimer bolted on at the end; it is an architectural constraint that shows up in
five concrete places:

Community assignments are written to a *derived* store that is physically separate from the
evidential record, and are never written back onto entity nodes as if they were observed facts.
Every algorithmic output carries a `derivation` envelope naming the algorithm, version, parameters,
input snapshot, and a stability score, and the API refuses to serve an output whose envelope is
incomplete. The UI is contractually forbidden from rendering a community label without its
stability score and hypothesis framing (§7.4). No API endpoint returns a per-person score of
criminality, propensity, or threat — the analytics vocabulary is restricted to structural
descriptors (modularity, bridging, within-cluster degree). And the audit record distinguishes
*observed* reads from *derived* reads, so an oversight body can ask "what did this analyst rely on"
and get a truthful answer.

This matters legally as well as ethically. LED Article 11 and GDPR Article 22 both restrict
decisions based solely on automated processing that adversely affect a person. A system that emits
"subject X is a member of gang Y, confidence 0.87" and lets that flow into a custody decision has
built an automated-decision engine whether or not anyone intended to. The controls above are what
keep this on the right side of that line.

### Non-goals

Predictive policing — forecasting who will offend or where crime will occur — is out of scope, and
the data model has no place to put such an output. Bulk or untargeted acquisition is out of scope:
the ingestion tier accepts only data with an attached lawful-basis reference (§4.2). Covert
collection tooling is out of scope; this system is a *sink* for data collected under separate
authority, not a collector. Facial recognition, biometric matching, and voice identification are
out of scope. Direct integration with any live interception system is out of scope; interception
product enters only as a batch export reviewed by a human disclosure officer.

---

## 2. Trust zones and the pseudonymity boundary

The central security decision in this architecture: **the analytics compute plane never holds
identities.**

Community detection needs an adjacency structure and edge weights. It does not need names, dates of
birth, phone numbers, addresses, or photographs. So the analytics plane receives a graph whose
vertices are opaque surrogate keys and whose edges carry only a weight and a coarse type. It
returns cluster assignments keyed by those same surrogates. Re-identification happens exactly once,
at the API tier, inside an authorization check, on a per-request basis, for the specific subgraph
the analyst is entitled to see.

The payoff is that the tier doing the heaviest compute — the tier most likely to be scaled onto
additional hardware, run at elevated privilege, have a Spark cluster bolted onto it at national
tier, and be debugged at 3am with verbose logging on — is also the tier where a total compromise
yields a bag of meaningless UUIDs and an adjacency matrix. It converts the blast radius of the
most operationally exposed component from "national intelligence leak" into "structural metadata
leak," which is real but categorically smaller.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Z0  UNTRUSTED — Analyst browser                                              │
│     React SPA. Holds only the current viewport's subgraph. No bulk export.    │
│     No PII in localStorage/IndexedDB. Per-session canvas watermark.           │
└───────────────────────────────┬──────────────────────────────────────────────┘
                    mTLS + OIDC │ (short-lived, purpose-bound access token)
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ Z1  EDGE — Reverse proxy / WAF                                               │
│     TLS 1.3 term (FIPS 140-3 module in CJIS mode). Rate limit, request-size  │
│     cap, CSP injection, request-ID minting. No business logic. No data.      │
└───────────────────────────────┬──────────────────────────────────────────────┘
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ Z2  IDENTIFYING — API service (FastAPI)                                      │
│     ★ The ONLY tier that may join surrogate keys back to identities.         │
│     Policy Decision Point (dual-regime ABAC). Purpose-of-processing binding.  │
│     Query Registry — no caller-supplied Cypher ever reaches the driver.       │
│     Field-level redaction. Emits hash-chained audit events.                   │
└──────┬───────────────────────────────┬────────────────────────┬──────────────┘
       │                               │                        │
┌──────▼──────────────────┐ ┌──────────▼─────────────┐ ┌────────▼─────────────┐
│ Z3 EVIDENTIAL           │ │ Z4 ANALYTICS (pseudo.) │ │ Z5 AUDIT (WORM)      │
│ Neo4j Enterprise        │ │ NO IDENTITIES PRESENT  │ │ Append-only.          │
│ Entities, relationships,│ │ Surrogate keys + edge  │ │ Hash-chained, HMAC'd.│
│ 5x5x5 provenance,       │ │ weights only.          │ │ Merkle root anchored │
│ case partitions,        │ │ Leiden / role inference│ │ hourly to external   │
│ retention clocks.       │ │ Derived store (Postgres│ │ notary.              │
│ Encrypted at rest.      │ │ + object store).       │ │ Separate credentials │
│ Analyst creds CANNOT    │ │ Cannot reach Z3.       │ │ — API can append but │
│ reach this tier direct. │ │ Egress: derived only.  │ │ never read or amend. │
└─────────────────────────┘ └────────────────────────┘ └──────────────────────┘
```

Three zone invariants are enforced by network policy, not by code, and are asserted by a CI test
that fails the build if the policy drifts:

**I1.** Z4 has no network route to Z3. The projection is *pushed* to Z4 by a dedicated exporter
identity in Z2; Z4 cannot pull. A compromised analytics worker cannot reach identities because
there is no path, not because it lacks a password.

**I2.** Z5 accepts `append` from Z2's audit identity and nothing else. No component, including the
API and including a database administrator, holds credentials that can update or delete an audit
row. Audit reads go through a separate oversight service with its own authentication and its own
audit trail — reading the audit log is itself an audited event.

**I3.** The Z3→Z4 exporter is the sole holder of the pseudonymization key, which lives in an HSM/KMS
and is never materialised in Z4. Even with the full derived store, Z4 cannot invert the mapping.

### Pseudonymization scheme

Surrogates are per-*snapshot* HMAC values, not global ones:

```
surrogate = base32( HMAC-SHA256( key = K_snapshot, msg = entity_uuid )[0:16] )
K_snapshot = HKDF( master_key_in_HSM, salt = snapshot_id )
```

Deriving the key per snapshot means surrogates are not stable across snapshots, which defeats
longitudinal correlation by anyone who obtains two snapshots. It costs us the ability to trivially
diff cluster membership between snapshots — so the exporter additionally emits an encrypted
`crosswalk` blob, retained in Z2 only, that lets the API (and only the API) align consecutive
snapshots when an analyst legitimately asks "did this cluster change?" Truncating the HMAC to 128
bits keeps payloads small; collision probability at national tier (5×10⁸ vertices) is ~4×10⁻²²,
which is comfortably negligible.

---

## 3. Service topology

| Service | Zone | Responsibility | Scale unit |
|---|---|---|---|
| `edge-proxy` | Z1 | TLS, WAF, rate limit, CSP, request ID | Stateless, N replicas |
| `api` | Z2 | ABAC PDP, purpose binding, query registry, redaction, audit emit | Stateless, N replicas |
| `resolver` | Z2 | Entity resolution, candidate blocking, human-adjudicated merges | Queue workers |
| `exporter` | Z2 | Builds pseudonymized projection, holds crosswalk, pushes to Z4 | Scheduled job |
| `analytics` | Z4 | Leiden, resolution sweep, overlap, role inference, stability | Job-per-snapshot |
| `retention` | Z2 | Retention clock evaluation, tombstoning, derived invalidation | Nightly cron |
| `oversight` | Z5 | Audit search for DPO / CJIS auditor. Separate auth. | Low volume |
| `neo4j` | Z3 | Evidential graph | See §6 |
| `postgres` | Z4 | Derived community assignments, versioned | Primary + replica |
| `audit-store` | Z5 | WORM append-only log | Object-lock bucket |

The `api` service is deliberately the only thing analysts talk to. There is no direct Neo4j Browser
or Bloom access for analysts in any environment holding real data. This is unpopular with analysts
and I would expect to defend it in review, so the reasoning: Neo4j Browser gives the user arbitrary
Cypher, which means the application-tier controls — purpose binding, field redaction, per-subject
category rules, query cost limits, semantic audit — are all bypassed in one step. An analyst with
Browser access and a legitimate login can run `MATCH (n:Person) RETURN n` and walk out with the
national dataset, and the audit log will record one unremarkable query. The mitigation is not
"train them not to"; it is to not issue the credential. Break-glass DBA access exists, requires two-person
authorization, and mints a session that is screen-recorded and time-boxed (§7.6).

---

## 4. Data flow

### 4.1 Ingestion

Sources arrive as batch exports: custody and case-management records, CDR/toll records under a
production order, financial disclosures, ANPR hits, and structured intelligence submissions. Each
batch must present a manifest naming the source system, the legal instrument authorising the
transfer (warrant, production order, MLAT reference, or statutory power), the authorising officer,
the collection date range, and a SHA-256 of each file. A batch without a complete manifest is
quarantined, not ingested — there is no "ingest now, paperwork later" path, because in practice
that path becomes the only path.

Ingestion is staged: land → validate → resolve → commit. The validate stage enforces schema, rejects
out-of-authority records (e.g. a CDR range wider than the production order permits — a real and
common defect in practice, and one worth failing loudly on), and normalises identifiers. The resolve
stage proposes entity merges but does not apply them. The commit stage writes to Z3 inside a single
transaction per batch with the manifest attached as a `:Provenance` node.

### 4.2 Lawful-basis propagation

Every relationship in Z3 carries `legal_basis_ref` pointing at the instrument that authorised the
underlying collection. This is what makes purpose limitation enforceable at query time rather than
at policy-document time: when an analyst queries within case `C-2026-0412`, the API restricts
traversal to edges whose `legal_basis_ref` is in the set of instruments valid for that case. Data
lawfully held for case A is not silently available to case B. Cross-case access is a distinct,
separately-authorized action (`purpose=CROSS_CASE_LINK`) that requires supervisor approval and
generates a high-salience audit event.

This is the single highest-value privacy control in the system, and it is also the one most likely
to be eroded by delivery pressure, because it makes some analyst workflows slower. Recommendation:
treat any change to the cross-case path as requiring DPO sign-off, and add a CI test asserting the
supervisor-approval requirement so that removing it cannot pass silently.

### 4.3 Query path

```
Browser ──► edge-proxy ──► api
                            │ 1. Verify OIDC token, mTLS client cert
                            │ 2. Extract (subject, purpose, case_id, legal_basis)
                            │ 3. PDP decision  ── deny ──► 403 + audit
                            │ 4. Resolve named query from Query Registry
                            │ 5. Bind params (typed, validated, never interpolated)
                            │ 6. Cost pre-check (est. rows, hop budget)
                            ├──► Neo4j (Z3): observed subgraph
                            ├──► Postgres (Z4): community assignment for those surrogates
                            │ 7. Re-identify via crosswalk (in-memory, request-scoped)
                            │ 8. Field-level redaction per subject category + clearance
                            │ 9. Attach derivation envelopes + stability scores
                            └──► audit append (hash-chained) ──► response
```

Step 6 exists because graph queries have pathological cost profiles: a three-hop traversal from a
high-degree node (a shared prepaid handset, a bank branch, a taxi firm) can touch millions of
nodes. Unbounded, this is both a self-inflicted DoS and an accidental bulk-disclosure channel. The
registry declares a hop budget and estimated-cardinality ceiling per query; exceeding it returns a
structured "refine your query" response rather than a timeout.

---

## 5. Community and hierarchy detection

Full detail in [`docs/analytics.md`](docs/analytics.md). The design in brief:

**Leiden, not Louvain.** Louvain can produce internally disconnected communities — a known and
under-appreciated defect. In this domain that failure mode is not cosmetic: a "community" that is
actually two unconnected fragments will be read by an analyst as a single organisation, which is a
false investigative conclusion generated by a library bug. Leiden guarantees connected, locally
optimal communities. This is a correctness requirement, not a performance preference.

**Hierarchy by resolution sweep, not by single partition.** Organised groups are nested: crews
inside cells inside networks. Running Leiden across a geometric ladder of resolution parameters and
recording which partitions persist across the sweep produces a dendrogram whose stable levels
correspond to real structural strata. Levels that appear at only one resolution are artefacts and
are suppressed.

**Overlap is mandatory, not optional.** Actors with multiple affiliations — the money launderer
serving three groups, the broker between a supplier and two distributors — are exactly the actors
investigators care most about, and a hard partition assigns each to precisely one community,
erasing the signal. We run a hard partition for the structural backbone and a separate overlapping
pass (link-community / clique-percolation) whose sole job is to surface multi-affiliation actors.

**Stability scoring gates disclosure.** Every partition is bootstrapped: perturb edge weights
within their confidence intervals, re-run, and measure assignment agreement across runs. An actor
whose community assignment flips under perturbation gets a low stability score, and the UI renders
that as explicitly unreliable. Without this, algorithmic noise is indistinguishable from finding,
and the noise is systematically worse for peripheral actors — the people least involved and most
harmed by a wrong inference. This is the fairness control that matters most in this system.

**Roles from within/between-module degree.** Guimerà–Amaral z-P classification yields
core / peripheral / broker / connector-hub descriptors. These are *structural* descriptors of graph
position, never rendered as organisational rank. "High betweenness" and "is the boss" are different
claims and the vocabulary must not conflate them; a courier who happens to be the only observed
link between two clusters will have high betweenness and no seniority whatsoever.

---

## 6. Tiered scaling with explicit migration triggers

Every component is sized for Pilot and documents its replacement plus the measurable trigger that
should initiate migration. The intent is that no one has to relitigate the architecture to scale
it — they read the trigger table and execute.

| Concern | Pilot (~1M nodes / 6M edges) | Regional (~10M / 100M) | National (~500M / 5B) |
|---|---|---|---|
| Neo4j topology | Single Enterprise instance, 32 GB heap, 64 GB page cache | 3-core autonomous cluster + 2 read replicas; analytics pinned to a replica | Composite databases sharded by jurisdiction; per-shard clusters |
| Projection for analytics | GDS in-memory on same instance | GDS on dedicated read replica | Offline: Parquet export → Spark/GraphFrames, or cuGraph on GPU |
| Leiden implementation | `leidenalg` + `igraph`, single node | `graph-tool` (OpenMP), 64-core box | Distributed Leiden on Spark; GPU Leiden via cuGraph |
| Derived store | Single Postgres | Primary + read replica, partitioned by snapshot | Citus / sharded by jurisdiction |
| Snapshot cadence | Nightly full | Nightly full + 4h incremental | Continuous incremental, weekly full rebuild |
| Expected Leiden wall time | < 90 s | 5–20 min | 1–4 h distributed |

**Migration triggers.** Move Pilot → Regional when any of: GDS projection resident set exceeds 60%
of heap; p95 two-hop query latency exceeds 800 ms for three consecutive days; nightly Leiden
exceeds 20 minutes; or write throughput sustains above 2k tx/s. Move Regional → National when any
of: single-shard vertex count exceeds 150M; `graph-tool` Leiden exceeds 2 h; the derived store
exceeds 2 TB; or a second jurisdiction with independent legal-basis rules onboards — that last one
is a *legal* trigger for a technical migration, because per-jurisdiction sharding is what keeps
legal-basis enforcement tractable, and it will arrive before the volume triggers do.

The honest caveat on the National column: distributed Leiden is materially harder than the table
makes it look. Modularity optimisation is inherently global, partitioning the graph for distributed
compute changes the answer, and the current literature is not settled on how much. If national
scale becomes real, budget for a research spike rather than an implementation sprint, and expect to
run hierarchical local Leiden per shard with a coarse global pass over shard-contracted supernodes.
I would not commit to a delivery date for that on the strength of this document.

---

## 7. Security controls

### 7.1 Dual-regime policy engine

CJIS and LED ask overlapping questions in different vocabularies. CJIS asks "is this user
authorized, advanced-authenticated, and does this access serve an authorized criminal justice
purpose?" LED asks "is there a lawful basis, is the purpose compatible with collection, is the
data-subject category respected, and is retention still valid?" Rather than two codebases, the PDP
evaluates a common request envelope against a regime-specific rule set, so shared plumbing —
envelope construction, decision logging, fail-closed default, obligation handling — is written once
and audited once. `services/api/app/security/policy.py` holds the engine; regime packs are data.

The engine is deny-by-default and returns *obligations* alongside permit decisions (redact these
fields, watermark this export, expire this session in 15 minutes). An obligation the enforcement
point does not recognise converts the permit into a deny — an unknown obligation means the PEP is
older than the policy, and in that situation guessing is the wrong move.

### 7.2 Cypher injection

Treated as an unfixable-by-discipline problem and removed structurally. The Neo4j driver
parameterizes values but *not* labels, relationship types, or property keys, so a naive
`f"MATCH (n:{label})"` is injectable and this is a genuinely easy mistake to make. Countermeasures:
all queries live in a registry as named, pre-written templates; label and relationship-type slots
accept only values from a closed enum validated against the live schema; a CI check greps the graph
package for f-strings and `%`/`.format()` on anything reaching `session.run`; and the application's
Neo4j role has no schema or admin privileges, so even a successful injection cannot create labels or
call `dbms.*` procedures.

### 7.3 Tamper-evident audit

Each record contains the hash of its predecessor, HMAC'd with a key held in the HSM, and the current
head hash is anchored hourly to an external notary. This gives detection of tampering, not
prevention — worth being precise about, since "immutable audit log" is usually overclaimed. An
attacker with the HSM key and write access to the bucket can forge a consistent chain; what they
cannot do is alter history *already anchored* externally without the anchors disagreeing. Combined
with object-lock retention (5 years for CJIS) and the Z2-can-append-but-not-read invariant, this
raises tampering from "delete a row" to "compromise three separately-credentialed systems and defeat
an external anchor."

Audit records carry the *semantic* action, not just the HTTP verb: `VIEWED_SUBGRAPH` with the
entity count and case, `REIDENTIFIED_SURROGATE` with the surrogate and justification,
`CROSS_CASE_LINK_APPROVED` with the approving supervisor. An oversight body asking "who looked at
this person and why" needs to be able to answer it from the log alone, and a log of `GET /api/v2/graph`
lines cannot answer that question.

### 7.4 Frontend controls

The SPA never receives the full graph. Viewport queries are server-paginated with a hard cap on
returned elements, which serves both performance and anti-bulk-exfiltration. Edge rendering is
confidence-aware: 5×5×5 evaluation drives stroke style, so uncorroborated intelligence cannot be
mistaken for established fact — a visual-design decision doing genuine security work, since the
failure mode it prevents is an analyst treating a rumour as a proven link. Community labels render
only alongside stability scores and hypothesis framing. Every canvas carries a low-contrast
watermark of user ID, timestamp, and case, so a photographed screen is attributable. CSP is
nonce-based with no `unsafe-inline` and no `unsafe-eval`; PII never touches `localStorage`,
`sessionStorage`, or IndexedDB, and the service worker is configured with a deny-list for API routes
so responses are never cached to disk.

### 7.5 Insider misuse

The realistic threat here is not an external attacker; it is an authorized user looking up their
ex-partner, their neighbour, or a celebrity. Every one of the significant real-world abuse cases in
comparable systems has this shape. Controls: purpose binding makes every access state a reason;
self-lookup and lookup of colleagues, addresses matching the user's own, and flagged VIP records
trigger immediate supervisor notification; behavioural analytics flag volume anomalies and
out-of-case-pattern access; and quarterly access recertification expires case memberships by
default rather than on request. Detection is the primary control, because prevention is not
achievable against a user with a legitimate credential and a legitimate-looking case.

### 7.6 Break-glass

DBA access to Z3 requires two-person authorization, mints a 60-minute credential, records the
session, and files a mandatory post-hoc justification reviewed by the DPO. Unused break-glass
credentials are rotated weekly. The break-glass path is itself exercised quarterly, because an
emergency procedure that has never been run is not a procedure.

---

## 8. Repository map

```
ARCHITECTURE.md              This document
docs/
  data-model.md              Entity/relationship reference, 5x5x5, subject categories
  analytics.md               Community & hierarchy detection in depth
  privacy-compliance.md      CJIS ↔ LED control matrix, retention, DPIA skeleton
  threat-model.md            STRIDE + insider abuse + algorithmic-harm cases
  scaling.md                 Sizing math, trigger runbooks
  adr/                       Architecture decision records
graph/
  01-constraints.cypher      Constraints and indexes
  02-schema.cypher           Schema documentation and validation queries
  seed_synthetic.py          Synthetic network generator (no real data, ever)
services/api/                FastAPI: PDP, query registry, redaction, audit
  app/security/              Policy engine, regime rule packs, audit chain, redaction
  app/graph/                 Query registry (the only source of Cypher)
services/analytics/          Pseudonymized Leiden / hierarchy / role inference
  worker/pseudonymize.py     Z3 → Z4 boundary: per-snapshot surrogates
  worker/weighting.py        5x5x5 → confidence-weighted edges
  worker/backends.py         Leiden adapter + stdlib reference implementation
  worker/community.py        Sweep, plateaux, hierarchy, stability, roles, overlap
  worker/derivation.py       Derivation envelopes; nothing ships without one
web/                         React intelligence visualization
deploy/                      docker-compose, network policy, CI security gates
tests/                       Policy, audit-chain, injection, invariant tests
```

The analytics package is `worker`, not `app`, so that a test process can import both services at
once without a package-name collision. Minor, but the alternative is import gymnastics in every
cross-service test, and cross-service tests are exactly the ones that catch boundary violations.

## 9. Open questions for review

Cross-jurisdictional transfer under LED Chapter V needs a legal decision before the exporter can be
built for multi-tenant deployment; the current design assumes single-jurisdiction. The retention
interaction with derived data is designed (§ `docs/privacy-compliance.md`) but the case where a
subject's erasure materially changes a *previously disclosed* community assignment has a policy
question inside it: does the disclosure need to be retracted? Engineering can support either answer;
someone has to choose. And the stability threshold below which a community assignment is withheld
entirely rather than shown-with-warning is currently 0.6 on the basis of judgement, not evidence —
it should be calibrated against analyst outcomes in pilot.
