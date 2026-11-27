// ============================================================================
// Neo4j Enterprise fine-grained RBAC — defence in depth beneath the app-tier PDP
//
// WHY THIS FILE EXISTS
// The application-tier policy engine (services/api/app/security/policy.py) is
// the primary access control. This file is the backstop for the case where the
// application tier is compromised or contains a logic bug. The two layers are
// deliberately written against different models — app tier is attribute-based,
// this is label/property-based — because two implementations of the same model
// tend to share the same blind spot.
//
// The invariant worth stating plainly: if an attacker achieves RCE in the API
// container and steals the Neo4j credential, that credential still cannot read
// victim or witness records, cannot read plaintext contact identifiers, cannot
// modify anything, and cannot call procedures. That is the whole point.
// ============================================================================

// ---------------------------------------------------------------------------
// 1. Protected-category marker label
//
// VICTIM and WITNESS records get an additional :ProtectedSubject label at
// ingest. Label-based denial is enforced by the storage engine on every
// traversal, so it holds even against arbitrary Cypher — which is what makes
// it a genuine backstop rather than another layer of the same control.
// ---------------------------------------------------------------------------
// Applied by the ingestion pipeline; asserted in CI:
//   MATCH (p:Person) WHERE p.subject_category IN ['VICTIM','WITNESS']
//   AND NOT p:ProtectedSubject RETURN count(p);   // must be 0

// ---------------------------------------------------------------------------
// 2. Role: cna_app_read — the credential the API service normally holds
// ---------------------------------------------------------------------------
CREATE ROLE cna_app_read IF NOT EXISTS;
GRANT ACCESS ON DATABASE neo4j TO cna_app_read;

GRANT TRAVERSE ON GRAPH neo4j NODES
  Person, Organisation, Phone, Account, Vehicle, Location, Event,
  Case, LegalBasis, Provenance, Snapshot TO cna_app_read;
GRANT TRAVERSE ON GRAPH neo4j RELATIONSHIPS
  COMMUNICATED_WITH, ASSOCIATE_OF, TRANSACTED_WITH, USES_PHONE,
  HOLDS_ACCOUNT, REGISTERED_TO, PRESENT_AT, APPEARS_IN,
  AUTHORISED_BY, DERIVED_FROM TO cna_app_read;
GRANT READ {*} ON GRAPH neo4j TO cna_app_read;

// -- Denials override grants in Neo4j, unconditionally. --

// 2a. Protected categories are invisible to the base role.
DENY TRAVERSE ON GRAPH neo4j NODES ProtectedSubject TO cna_app_read;

// 2b. Plaintext contact identifiers are never readable. The application works
//     from the hashed lookup columns; display values are decrypted from the
//     ciphertext column only after an authorization decision, by a separate
//     role, so a stolen base credential yields no dialable numbers.
DENY READ {msisdn_plain, imei_plain} ON GRAPH neo4j NODES Phone TO cna_app_read;
DENY READ {iban_plain, pan_plain}    ON GRAPH neo4j NODES Account TO cna_app_read;
DENY READ {vrm_plain}                ON GRAPH neo4j NODES Vehicle TO cna_app_read;
DENY READ {address_plain, dob_exact, ni_number, ssn}
  ON GRAPH neo4j NODES Person TO cna_app_read;

// 2c. Special-category data under GDPR Art. 9 / LED Art. 10. Present in the
//     model only because source systems sometimes carry it and silently
//     dropping it on ingest would corrupt the provenance chain. No analytical
//     path is permitted to read it, and no algorithm may consume it — this
//     denial is what stops a future contributor from quietly building an
//     ethnicity-correlated cluster feature.
DENY READ {ethnicity, religion, health_notes, political_affiliation,
           trade_union, sexual_orientation, biometric_template}
  ON GRAPH neo4j NODES Person TO cna_app_read;

// 2d. No writes, no schema changes, no procedures.
DENY WRITE ON GRAPH neo4j TO cna_app_read;
DENY ALL ON DBMS TO cna_app_read;

// ---------------------------------------------------------------------------
// 3. Role: cna_app_protected — elevated read for authorized protected access
//
// Held by a SEPARATE connection pool that the API opens only after the PDP
// returns a permit carrying the `protected_subject_access` obligation. Keeping
// it in a distinct pool means the ordinary query path physically cannot use
// it, rather than merely being expected not to.
// ---------------------------------------------------------------------------
CREATE ROLE cna_app_protected IF NOT EXISTS;
GRANT ACCESS ON DATABASE neo4j TO cna_app_protected;
GRANT TRAVERSE ON GRAPH neo4j NODES ProtectedSubject, Person TO cna_app_protected;
GRANT READ {*} ON GRAPH neo4j NODES ProtectedSubject, Person TO cna_app_protected;
DENY READ {ethnicity, religion, health_notes, political_affiliation,
           trade_union, sexual_orientation, biometric_template}
  ON GRAPH neo4j NODES Person TO cna_app_protected;
DENY WRITE ON GRAPH neo4j TO cna_app_protected;
DENY ALL ON DBMS TO cna_app_protected;

// ---------------------------------------------------------------------------
// 4. Role: cna_ingest — write path only
// ---------------------------------------------------------------------------
CREATE ROLE cna_ingest IF NOT EXISTS;
GRANT ACCESS ON DATABASE neo4j TO cna_ingest;
GRANT CREATE ON GRAPH neo4j NODES * TO cna_ingest;
GRANT SET PROPERTY {*} ON GRAPH neo4j NODES * TO cna_ingest;
GRANT CREATE ON GRAPH neo4j RELATIONSHIPS * TO cna_ingest;
GRANT SET PROPERTY {*} ON GRAPH neo4j RELATIONSHIPS * TO cna_ingest;
GRANT SET LABEL ProtectedSubject ON GRAPH neo4j TO cna_ingest;
GRANT MATCH {*} ON GRAPH neo4j TO cna_ingest;
// Ingest may create and amend but never destroy. Deletion is the retention
// service's exclusive privilege, so a compromised ingestion pipeline cannot
// be used to destroy evidence — a real scenario when the adversary is an
// organised group with an insider.
DENY DELETE ON GRAPH neo4j NODES * TO cna_ingest;
DENY DELETE ON GRAPH neo4j RELATIONSHIPS * TO cna_ingest;
DENY ALL ON DBMS TO cna_ingest;

// ---------------------------------------------------------------------------
// 5. Role: cna_retention — the only role that may delete
// ---------------------------------------------------------------------------
CREATE ROLE cna_retention IF NOT EXISTS;
GRANT ACCESS ON DATABASE neo4j TO cna_retention;
GRANT MATCH {*} ON GRAPH neo4j TO cna_retention;
GRANT SET PROPERTY {tombstoned, tombstoned_at, retention_review_at,
                    retention_decision} ON GRAPH neo4j NODES * TO cna_retention;
GRANT DELETE ON GRAPH neo4j NODES * TO cna_retention;
GRANT DELETE ON GRAPH neo4j RELATIONSHIPS * TO cna_retention;
DENY ALL ON DBMS TO cna_retention;

// ---------------------------------------------------------------------------
// 6. Role: cna_exporter — builds the pseudonymized Z4 projection
//
// Reads ONLY structure: entity id, coarse type, edge type, weight, validity
// window. Denied every descriptive property. This is the enforcement of the
// pseudonymity boundary at the storage layer: even if the exporter is
// compromised and rewritten to exfiltrate identities, the credential cannot
// read them.
// ---------------------------------------------------------------------------
CREATE ROLE cna_exporter IF NOT EXISTS;
GRANT ACCESS ON DATABASE neo4j TO cna_exporter;
GRANT TRAVERSE ON GRAPH neo4j NODES
  Person, Organisation, Phone, Account, Vehicle, Location TO cna_exporter;
GRANT TRAVERSE ON GRAPH neo4j RELATIONSHIPS
  COMMUNICATED_WITH, ASSOCIATE_OF, TRANSACTED_WITH, USES_PHONE,
  HOLDS_ACCOUNT, REGISTERED_TO, PRESENT_AT TO cna_exporter;

// Whitelist, not blacklist: grant the four structural properties and nothing
// else. A blacklist here would silently leak any property added later, and
// properties get added all the time.
GRANT READ {eid, entity_type, tombstoned, subject_category}
  ON GRAPH neo4j NODES * TO cna_exporter;
GRANT READ {weight, source_eval, intel_assessment, valid_from, valid_to,
            legal_basis_ref, rel_type}
  ON GRAPH neo4j RELATIONSHIPS * TO cna_exporter;
DENY TRAVERSE ON GRAPH neo4j NODES ProtectedSubject TO cna_exporter;
DENY WRITE ON GRAPH neo4j TO cna_exporter;
DENY ALL ON DBMS TO cna_exporter;

// NOTE: `subject_category` is granted to the exporter deliberately. The
// analytics tier needs it to EXCLUDE victims and witnesses from clustering —
// clustering a victim into an offender community is precisely the harm we are
// trying to design out. The category is a six-value enum with no identifying
// power on its own, so exporting it does not weaken pseudonymity.

// ---------------------------------------------------------------------------
// 7. Role: cna_break_glass — two-person-authorized DBA access
// ---------------------------------------------------------------------------
CREATE ROLE cna_break_glass IF NOT EXISTS;
GRANT ALL ON DATABASE neo4j TO cna_break_glass;
GRANT MATCH {*} ON GRAPH neo4j TO cna_break_glass;
// Assigned to a user only by the break-glass workflow, which mints a 60-minute
// credential after two-person authorization and screen-records the session.
// Standing membership must be zero; asserted by a nightly compliance check:
//   SHOW USERS WITH ROLE cna_break_glass;   // must be empty

// ---------------------------------------------------------------------------
// 8. Users (passwords injected from the secret manager, never literals here)
// ---------------------------------------------------------------------------
// CREATE USER svc_api            SET PASSWORD $pw CHANGE NOT REQUIRED;
// CREATE USER svc_api_protected  SET PASSWORD $pw CHANGE NOT REQUIRED;
// CREATE USER svc_ingest         SET PASSWORD $pw CHANGE NOT REQUIRED;
// CREATE USER svc_retention      SET PASSWORD $pw CHANGE NOT REQUIRED;
// CREATE USER svc_exporter       SET PASSWORD $pw CHANGE NOT REQUIRED;
// GRANT ROLE cna_app_read      TO svc_api;
// GRANT ROLE cna_app_protected TO svc_api_protected;
// GRANT ROLE cna_ingest        TO svc_ingest;
// GRANT ROLE cna_retention     TO svc_retention;
// GRANT ROLE cna_exporter      TO svc_exporter;

// No human user is ever granted cna_app_read. Analysts have no database
// credential at all; they authenticate to the API. See ARCHITECTURE.md §3 for
// why Neo4j Browser access is withheld even from senior analysts.
