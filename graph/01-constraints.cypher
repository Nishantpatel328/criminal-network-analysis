// ============================================================================
// Criminal Network Analysis System — Constraints, Indexes, Schema Guards
// Neo4j 5.x Enterprise
//
// Run order: 01-constraints.cypher (this file) -> 02-rbac.cypher -> seed
//
// DESIGN NOTE ON KEYS
// Every entity carries a UUID `eid` as its stable external identifier. We never
// expose Neo4j's internal element IDs across a trust boundary: they are not
// stable across store copies, they leak insertion order (a real inference
// channel — adjacent IDs imply co-ingestion, which implies a shared source),
// and they cannot be pseudonymized meaningfully.
// ============================================================================

// ---------------------------------------------------------------------------
// 1. Entity identity constraints
// ---------------------------------------------------------------------------
CREATE CONSTRAINT person_eid IF NOT EXISTS
  FOR (p:Person) REQUIRE p.eid IS UNIQUE;
CREATE CONSTRAINT org_eid IF NOT EXISTS
  FOR (o:Organisation) REQUIRE o.eid IS UNIQUE;
CREATE CONSTRAINT phone_eid IF NOT EXISTS
  FOR (t:Phone) REQUIRE t.eid IS UNIQUE;
CREATE CONSTRAINT account_eid IF NOT EXISTS
  FOR (a:Account) REQUIRE a.eid IS UNIQUE;
CREATE CONSTRAINT vehicle_eid IF NOT EXISTS
  FOR (v:Vehicle) REQUIRE v.eid IS UNIQUE;
CREATE CONSTRAINT location_eid IF NOT EXISTS
  FOR (l:Location) REQUIRE l.eid IS UNIQUE;
CREATE CONSTRAINT case_id IF NOT EXISTS
  FOR (c:Case) REQUIRE c.case_id IS UNIQUE;
CREATE CONSTRAINT legalbasis_id IF NOT EXISTS
  FOR (lb:LegalBasis) REQUIRE lb.basis_id IS UNIQUE;
CREATE CONSTRAINT provenance_id IF NOT EXISTS
  FOR (pv:Provenance) REQUIRE pv.provenance_id IS UNIQUE;
CREATE CONSTRAINT snapshot_id IF NOT EXISTS
  FOR (s:Snapshot) REQUIRE s.snapshot_id IS UNIQUE;

// ---------------------------------------------------------------------------
// 2. Mandatory-property constraints  (Neo4j Enterprise: existence constraints)
//
// These are the teeth behind the privacy design. A Person without a
// data-subject category cannot have LED Art. 6 rules applied to it, and a
// relationship without a legal_basis_ref cannot have purpose limitation
// enforced. Rather than hope the ingestion code always sets them, we make it
// impossible to commit a record that would be unpoliceable.
// ---------------------------------------------------------------------------
CREATE CONSTRAINT person_category_exists IF NOT EXISTS
  FOR (p:Person) REQUIRE p.subject_category IS NOT NULL;
CREATE CONSTRAINT person_retention_exists IF NOT EXISTS
  FOR (p:Person) REQUIRE p.retention_review_at IS NOT NULL;
CREATE CONSTRAINT person_provenance_exists IF NOT EXISTS
  FOR (p:Person) REQUIRE p.provenance_id IS NOT NULL;

// LED Art. 6 data-subject categories. Drives access rules AND retention clocks.
// VICTIM and WITNESS are the categories that most need protecting from
// analyst browsing, and they are also the ones most likely to be miscoded on
// ingest, which is why 02-rbac.cypher denies them by default rather than
// relying on the code being right.
CREATE CONSTRAINT person_category_valid IF NOT EXISTS
  FOR (p:Person) REQUIRE p.subject_category IN
    ['SUSPECT','CONVICTED','VICTIM','WITNESS','CONTACT','OTHER'];

CREATE CONSTRAINT case_legal_basis_exists IF NOT EXISTS
  FOR (c:Case) REQUIRE c.authorised_bases IS NOT NULL;

// ---------------------------------------------------------------------------
// 3. Relationship property constraints — 5x5x5 intelligence evaluation
//
// Every substantive relationship carries a source evaluation, an intelligence
// assessment, and a handling code (UK National Intelligence Model 5x5x5).
// An edge without an evaluation is an assertion of unknown worth, and the UI
// cannot render it honestly, so we refuse to store it.
// ---------------------------------------------------------------------------
CREATE CONSTRAINT rel_comm_eval IF NOT EXISTS
  FOR ()-[r:COMMUNICATED_WITH]-() REQUIRE r.source_eval IS NOT NULL;
CREATE CONSTRAINT rel_comm_assess IF NOT EXISTS
  FOR ()-[r:COMMUNICATED_WITH]-() REQUIRE r.intel_assessment IS NOT NULL;
CREATE CONSTRAINT rel_comm_basis IF NOT EXISTS
  FOR ()-[r:COMMUNICATED_WITH]-() REQUIRE r.legal_basis_ref IS NOT NULL;

CREATE CONSTRAINT rel_assoc_eval IF NOT EXISTS
  FOR ()-[r:ASSOCIATE_OF]-() REQUIRE r.source_eval IS NOT NULL;
CREATE CONSTRAINT rel_assoc_assess IF NOT EXISTS
  FOR ()-[r:ASSOCIATE_OF]-() REQUIRE r.intel_assessment IS NOT NULL;
CREATE CONSTRAINT rel_assoc_basis IF NOT EXISTS
  FOR ()-[r:ASSOCIATE_OF]-() REQUIRE r.legal_basis_ref IS NOT NULL;

CREATE CONSTRAINT rel_txn_basis IF NOT EXISTS
  FOR ()-[r:TRANSACTED_WITH]-() REQUIRE r.legal_basis_ref IS NOT NULL;
CREATE CONSTRAINT rel_txn_eval IF NOT EXISTS
  FOR ()-[r:TRANSACTED_WITH]-() REQUIRE r.source_eval IS NOT NULL;

// ---------------------------------------------------------------------------
// 4. Indexes for the hot query paths
// ---------------------------------------------------------------------------

// Case-scoped traversal is the dominant access pattern: almost every analyst
// query is "within case C, starting from entity E, N hops".
CREATE INDEX person_case_lookup IF NOT EXISTS
  FOR (p:Person) ON (p.primary_case);
CREATE INDEX appears_in_case IF NOT EXISTS
  FOR ()-[r:APPEARS_IN]-() ON (r.case_id);

// Retention sweep runs nightly across the whole store; without this it is a
// full scan and at regional tier that is a multi-hour job competing with
// analyst queries for page cache.
CREATE INDEX person_retention_sweep IF NOT EXISTS
  FOR (p:Person) ON (p.retention_review_at);
CREATE INDEX org_retention_sweep IF NOT EXISTS
  FOR (o:Organisation) ON (o.retention_review_at);

// Tombstone filter is applied to EVERY read query, so it must be cheap.
CREATE INDEX person_tombstone IF NOT EXISTS
  FOR (p:Person) ON (p.tombstoned);

// Legal-basis filtering on traversal (purpose limitation enforcement).
CREATE INDEX comm_basis IF NOT EXISTS
  FOR ()-[r:COMMUNICATED_WITH]-() ON (r.legal_basis_ref);
CREATE INDEX assoc_basis IF NOT EXISTS
  FOR ()-[r:ASSOCIATE_OF]-() ON (r.legal_basis_ref);

// Temporal slicing for "how did this structure change" queries.
CREATE INDEX comm_valid_from IF NOT EXISTS
  FOR ()-[r:COMMUNICATED_WITH]-() ON (r.valid_from);

// Entity resolution blocking keys. Full-text, because resolution candidate
// generation needs fuzzy name matching. NOTE: this index is a disclosure
// surface — it permits name search across the whole store — so the
// application role granted access to it is separate from the general read
// role and its use is audited as SEARCHED_BY_NAME.
CREATE FULLTEXT INDEX person_name_ft IF NOT EXISTS
  FOR (p:Person) ON EACH [p.surname_normalised, p.forenames_normalised];

CREATE INDEX phone_msisdn IF NOT EXISTS
  FOR (t:Phone) ON (t.msisdn_hash);
CREATE INDEX account_iban IF NOT EXISTS
  FOR (a:Account) ON (a.iban_hash);

// Identifiers that are themselves sensitive (MSISDN, IBAN, VRM) are stored as
// keyed hashes for lookup plus an envelope-encrypted ciphertext for display.
// Lookup by hash needs no plaintext in the index, so a store-level compromise
// yields no directly-dialable numbers or usable account details.

// ---------------------------------------------------------------------------
// 5. Schema validation queries — run in CI against a seeded instance.
//    Each MUST return zero rows. These catch drift that constraints cannot,
//    because Neo4j has no CHECK constraints across properties.
// ---------------------------------------------------------------------------

// V1: no relationship may reference a legal basis that does not exist
//   MATCH ()-[r]->() WHERE r.legal_basis_ref IS NOT NULL
//   AND NOT EXISTS { MATCH (lb:LegalBasis {basis_id: r.legal_basis_ref}) }
//   RETURN r LIMIT 10;

// V2: 5x5x5 values must be in range 1..5
//   MATCH ()-[r]->() WHERE r.source_eval IS NOT NULL
//   AND (r.source_eval < 1 OR r.source_eval > 5
//        OR r.intel_assessment < 1 OR r.intel_assessment > 5)
//   RETURN r LIMIT 10;

// V3: no entity may be past its retention review date without a tombstone
//   MATCH (p:Person) WHERE p.retention_review_at < date()
//   AND coalesce(p.tombstoned, false) = false
//   RETURN p LIMIT 10;

// V4: victims and witnesses must not carry a threat/risk property of any kind
//   (guards against a future contributor adding scoring to protected categories)
//   MATCH (p:Person) WHERE p.subject_category IN ['VICTIM','WITNESS']
//   AND any(k IN keys(p) WHERE k CONTAINS 'risk' OR k CONTAINS 'threat'
//                            OR k CONTAINS 'score')
//   RETURN p LIMIT 10;

// V5: no node may carry a community assignment — derived data belongs in Z4
//   MATCH (n) WHERE any(k IN keys(n) WHERE k STARTS WITH 'community'
//                                       OR k STARTS WITH 'cluster')
//   RETURN n LIMIT 10;
