/**
 * The wire contract, as the API actually emits it.
 *
 * Every field here corresponds to an entry in a projection whitelist in
 * services/api/app/security/redaction.py, or to a field of DerivationEnvelope in
 * services/analytics/worker/derivation.py. Those are the sources of truth: if a
 * field is not whitelisted there, no response will ever contain it, and
 * declaring it here would be a lie the type checker would then help propagate.
 *
 * Note what is absent. There is no `risk_score`, no `centrality`, no
 * `is_leader`, no `predicted_link`. Several of those were considered upstream and
 * deliberately not built. A frontend type that optimistically includes a field
 * "for later" invites a component to render `?? "—"` and ship a UI affordance for
 * a capability that does not exist, which is how a scaffold acquires features
 * nobody designed.
 */

/* --- Vocabulary, closed on both sides ---------------------------------
   Every string union here mirrors a Python enum. Widening one of these without
   widening its counterpart produces a 400 at runtime rather than a type error,
   so they are kept adjacent in review: models.py and this file change together
   or not at all. */

export const PURPOSES = [
  "INVESTIGATION",
  "CROSS_CASE_LINK",
  "INTELLIGENCE_DEVELOPMENT",
  "DISCLOSURE_PREP",
  "DATA_SUBJECT_REQUEST",
  "AUDIT_OVERSIGHT",
] as const;
export type Purpose = (typeof PURPOSES)[number];
/* SYSTEM_MAINTENANCE is a real Purpose and is not offered here. It exists for
   platform operations and authorises no record disclosure; putting it in an
   analyst's dropdown would be an invitation to select it and a support ticket
   when it denies. */

/** Human-readable purpose labels. Written from the analyst's side of the screen:
 *  what they are doing, not what the enum is called. */
export const PURPOSE_LABELS: Record<Purpose, string> = {
  INVESTIGATION: "Investigating this case",
  CROSS_CASE_LINK: "Checking a link to another case",
  INTELLIGENCE_DEVELOPMENT: "Developing intelligence",
  DISCLOSURE_PREP: "Preparing a disclosure bundle",
  DATA_SUBJECT_REQUEST: "Answering a subject access request",
  AUDIT_OVERSIGHT: "Audit or oversight review",
};

export const REL_TYPES = [
  "COMMUNICATED_WITH",
  "ASSOCIATE_OF",
  "TRANSACTED_WITH",
  "USES_PHONE",
  "HOLDS_ACCOUNT",
  "REGISTERED_TO",
  "PRESENT_AT",
] as const;
export type RelType = (typeof REL_TYPES)[number];
/* APPEARS_IN exists in the graph and is deliberately absent. It is the
   case-membership edge; traversing it walks out of the current case into every
   other case an entity appears in. The API refuses it with a 403 and the client
   does not offer it — a control a user can see but not use reads as a
   permissions fault rather than a design decision. */

export const REL_LABELS: Record<RelType, string> = {
  COMMUNICATED_WITH: "Communicated with",
  ASSOCIATE_OF: "Associate of",
  TRANSACTED_WITH: "Transacted with",
  USES_PHONE: "Uses phone",
  HOLDS_ACCOUNT: "Holds account",
  REGISTERED_TO: "Registered to",
  PRESENT_AT: "Present at",
};

export type NodeLabel =
  | "Person" | "Organisation" | "Phone" | "Account"
  | "Vehicle" | "Location" | "Event" | "Case";

/** LED Art. 6 categories. Drives retention, access, and clusterability. */
export type SubjectCategory =
  | "SUSPECT" | "CONVICTED" | "VICTIM" | "WITNESS" | "CONTACT" | "OTHER";

/** VICTIM and WITNESS are PROTECTED_CATEGORIES server-side and are never
 *  clusterable. The client marks them so a protected subject is visually
 *  distinct before the analyst clicks anything. */
export const PROTECTED_CATEGORIES: ReadonlySet<SubjectCategory> = new Set<SubjectCategory>([
  "VICTIM", "WITNESS",
]);

export type Obligation =
  | "REDACT_SPECIAL_CATEGORY"
  | "REDACT_PLAIN_IDENTIFIERS"
  | "REDACT_PRECISE_DOB"
  | "PROTECTED_SUBJECT_POOL"
  | "SUPERVISOR_NOTIFY"
  | "HIGH_SALIENCE_AUDIT"
  | "WATERMARK_OUTPUT"
  | "HYPOTHESIS_FRAMING"
  | "WITHHOLD_LOW_STABILITY"
  | "MINIMISE_TO_DEGREE_1"
  | "SESSION_REAUTH_15M"
  | "RATE_LIMIT_STRICT";

/** 5x5x5 grade. 1 = always reliable / known true, 5 = untested / suspected
 *  false. Grade 5 on the assessment axis drops the edge entirely upstream, so an
 *  intel_assessment of 5 never reaches this client. */
export type Grade = 1 | 2 | 3 | 4 | 5;

/** Guimera-Amaral z-P roles, in the plain-language vocabulary from
 *  community.py::_role_label. "Kingpin", "lieutenant" and "foot soldier" are
 *  absent by design: those words assert a criminal hierarchy that a role
 *  assignment does not evidence. */
export type Role =
  | "CORE_WITHIN_GROUP"
  | "CONNECTOR_HUB"
  | "DISPERSED_HUB"
  | "ISOLATED_WITHIN_GROUP"
  | "PERIPHERAL"
  | "BRIDGING"
  | "UNCLASSIFIED";

/** What each role means, phrased as the measurement rather than as a claim about
 *  the person. Rendered next to the role every time it is shown, not behind a
 *  tooltip — a label an analyst has to hover to understand is a label they will
 *  interpret from its name instead. */
export const ROLE_MEANING: Record<Role, string> = {
  CORE_WITHIN_GROUP:
    "Most of this record's connections are inside its own group, and there are " +
    "more of them than is typical for the group.",
  CONNECTOR_HUB:
    "Heavily connected, with a substantial share of those connections reaching " +
    "one or two other groups.",
  DISPERSED_HUB:
    "Heavily connected, with connections spread across several groups rather " +
    "than concentrated in any one.",
  ISOLATED_WITHIN_GROUP:
    "Connections sit almost entirely within one group, and there are few of them.",
  PERIPHERAL:
    "Few connections, mostly within one group.",
  BRIDGING:
    "Few connections overall, but they reach across several groups.",
  UNCLASSIFIED:
    "Not enough connections in this snapshot to describe a position. No role " +
    "was assigned.",
};

/* --- Records ---------------------------------------------------------- */

/** Mirrors ENTITY_VIEW. `display_name` may arrive masked. */
export interface EntityRecord {
  eid: string;
  labels?: NodeLabel[];
  subject_category?: SubjectCategory;
  display_name?: string;
  /** Year only. The precise date is never emitted; see REDACT_PRECISE_DOB. */
  dob_year?: number | null;
  provenance_id?: string;
  primary_case?: string;
}

/** Mirrors RELATIONSHIP_VIEW, plus the endpoints the expansion query returns.
 *  `source_eval` and `intel_assessment` are non-optional: the redactor raises
 *  rather than emit an ungraded edge, so an edge without a grading cannot reach
 *  this type — which is what lets the renderer treat them as always present. */
export interface RelationshipRecord {
  type: RelType;
  source_eval: Grade;
  intel_assessment: Grade;
  handling_code: Grade;
  weight: number;
  basis?: string;
  valid_from?: string;
  valid_to?: string | null;
  src: string;
  dst: string;
}

/** Mirrors COMMUNITY_VIEW. */
export interface CommunityRecord {
  community_id: string;
  level: number;
  /** Mean co-membership frequency across bootstrap runs, 0..1. Absent when
   *  WITHHOLD_LOW_STABILITY applied — absence is meaningful and must be
   *  rendered as "withheld", not as zero. */
  stability?: number;
  role?: Role;
  participation_coefficient?: number;
  within_module_degree?: number;
  /** The derivation envelope. The redactor refuses to emit a derived record
   *  without one, so in practice this is always present on a released record;
   *  typed optional so a malformed response fails visibly in the renderer. */
  derivation?: Derivation;
  size?: number;
  member_surrogates?: string[];
}

/** Mirrors DerivationEnvelope in services/analytics/worker/derivation.py. */
export interface Derivation {
  algorithm: string;
  algorithm_version: string;
  backend: string;
  seed: number;
  resolution: number;
  snapshot_id: string;
  computed_at: string;
  vertex_count: number;
  edge_count: number;
  weighting_scheme: string;
  excluded_from_input: string[];
  stability: number | null;
  stability_method: string;
  bootstrap_runs: number;
  modularity: number;
  disclosable: boolean;
  non_disclosure_reason: string | null;
  /** Rendered verbatim as body text. Not collapsible, not truncated, not
   *  summarised. derivation.py's own comment says so, and the two must agree. */
  not_established: string[];
  method_limits: string[];
  approximations: string[];
  warnings: string[];
  thresholds: Record<string, string | number>;
}

/* --- Envelope --------------------------------------------------------- */

/**
 * Counts, not field names — and the client must not try to reconstruct names.
 *
 * The API returns `fields_redacted: 4` rather than a list, because "health_notes
 * was redacted" discloses that the subject has health notes. A UI that diffed
 * the received record against a known schema to show "Health notes: hidden"
 * would rebuild exactly the leak the API design removed. See RedactionReport in
 * services/api/app/security/redaction.py.
 */
export interface Disclosure {
  fields_redacted: number;
  fields_withheld: number;
  notes: string[];
  obligations_applied: Obligation[];
  truncated: boolean;
}

export interface Watermark {
  actor: string;
  case: string;
  at: string;
  text: string;
}

export interface Envelope<T> {
  records: T[];
  disclosure: Disclosure;
  watermark: Watermark | null;
  /** Sequence number of the audit record for this disclosure. Shown to the
   *  analyst. Knowing your reads are numbered and attributable is a deterrent a
   *  policy document alone does not achieve. */
  audit_seq: number;
  regime: "cjis" | "gdpr_led";
}

/* --- Requests --------------------------------------------------------- */

export interface ExpandRequest {
  eid: string;
  case_id: string;
  purpose: Purpose;
  justification?: string;
  rel_types?: RelType[];
}

export interface ReidentifyRequest {
  snapshot_id: string;
  surrogates: string[];
  case_id: string;
  purpose: Purpose;
  justification: string;
}

export interface ReviewRequest {
  snapshot_id: string;
  community_id: string;
  case_id: string;
  assessment: string;
  concurs: boolean;
}
