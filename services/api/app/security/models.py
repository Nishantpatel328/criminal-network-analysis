"""Core types for the access-control decision pipeline.

These types are the common vocabulary that both regime packs (CJIS, GDPR/LED)
evaluate against. The point of factoring it this way is that the *envelope* is
regime-neutral and the *rules* are regime-specific, so we write the plumbing
(envelope construction, decision combination, obligation handling, fail-closed
default, audit emission) exactly once and review it exactly once.

Everything here is frozen/immutable. An access request that can be mutated
between the decision and the enforcement is a TOCTOU bug waiting to happen, and
in this system that bug reads out someone's victim record.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import FrozenSet, Optional, Tuple


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Regime(enum.Enum):
    """Which statutory rule pack applies to this tenant."""
    CJIS = "cjis"
    GDPR_LED = "gdpr_led"


class SubjectCategory(enum.Enum):
    """LED Art. 6 categories of data subject. See docs/data-model.md."""
    SUSPECT = "SUSPECT"
    CONVICTED = "CONVICTED"
    VICTIM = "VICTIM"
    WITNESS = "WITNESS"
    CONTACT = "CONTACT"
    OTHER = "OTHER"


PROTECTED_CATEGORIES: FrozenSet[SubjectCategory] = frozenset(
    {SubjectCategory.VICTIM, SubjectCategory.WITNESS}
)

# Categories eligible to participate in community detection. Victims, witnesses
# and incidental contacts are excluded: assigning an innocent person membership
# of a "criminal community" is the central algorithmic harm this system must
# design out, not merely caveat. See docs/analytics.md §2.
CLUSTERABLE_CATEGORIES: FrozenSet[SubjectCategory] = frozenset(
    {SubjectCategory.SUSPECT, SubjectCategory.CONVICTED}
)


class Clearance(enum.IntEnum):
    """Ordered so comparisons are meaningful. Do not reorder."""
    NONE = 0
    BASIC = 10
    ENHANCED = 20
    SPECIAL = 30


class Purpose(enum.Enum):
    """Purpose of processing. Mandatory on every request.

    This is the single field that makes purpose limitation enforceable at query
    time rather than at policy-document time. GDPR Art. 5(1)(b) and LED Art. 4
    both require it; CJIS expresses the same idea as "authorized criminal
    justice purpose". One field, two regimes.
    """
    INVESTIGATION = "INVESTIGATION"
    CROSS_CASE_LINK = "CROSS_CASE_LINK"
    INTELLIGENCE_DEVELOPMENT = "INTELLIGENCE_DEVELOPMENT"
    DISCLOSURE_PREP = "DISCLOSURE_PREP"
    DATA_SUBJECT_REQUEST = "DATA_SUBJECT_REQUEST"
    AUDIT_OVERSIGHT = "AUDIT_OVERSIGHT"
    SYSTEM_MAINTENANCE = "SYSTEM_MAINTENANCE"


class Action(enum.Enum):
    VIEW_ENTITY = "VIEW_ENTITY"
    EXPAND_SUBGRAPH = "EXPAND_SUBGRAPH"
    SEARCH_BY_NAME = "SEARCH_BY_NAME"
    VIEW_COMMUNITY = "VIEW_COMMUNITY"
    REIDENTIFY = "REIDENTIFY"
    EXPORT = "EXPORT"
    RECATEGORISE_SUBJECT = "RECATEGORISE_SUBJECT"
    READ_AUDIT = "READ_AUDIT"


class ResourceKind(enum.Enum):
    ENTITY = "ENTITY"
    SUBGRAPH = "SUBGRAPH"
    COMMUNITY = "COMMUNITY"
    AUDIT_LOG = "AUDIT_LOG"


class Obligation(enum.Enum):
    """Conditions a permit is contingent upon.

    An obligation the enforcement point does not recognise converts the permit
    into a deny (see policy.enforce). An unknown obligation means the PEP build
    is older than the policy build, and in that situation proceeding is a guess
    about what a rule intended — so we refuse. This has bitten every XACML-ish
    system that treated obligations as advisory.
    """
    REDACT_SPECIAL_CATEGORY = "REDACT_SPECIAL_CATEGORY"
    REDACT_PLAIN_IDENTIFIERS = "REDACT_PLAIN_IDENTIFIERS"
    REDACT_PRECISE_DOB = "REDACT_PRECISE_DOB"
    PROTECTED_SUBJECT_POOL = "PROTECTED_SUBJECT_POOL"
    SUPERVISOR_NOTIFY = "SUPERVISOR_NOTIFY"
    HIGH_SALIENCE_AUDIT = "HIGH_SALIENCE_AUDIT"
    WATERMARK_OUTPUT = "WATERMARK_OUTPUT"
    HYPOTHESIS_FRAMING = "HYPOTHESIS_FRAMING"
    WITHHOLD_LOW_STABILITY = "WITHHOLD_LOW_STABILITY"
    MINIMISE_TO_DEGREE_1 = "MINIMISE_TO_DEGREE_1"
    SESSION_REAUTH_15M = "SESSION_REAUTH_15M"
    RATE_LIMIT_STRICT = "RATE_LIMIT_STRICT"


class Effect(enum.Enum):
    """Three effects, not two.

    OBLIGE exists to separate "I authorize this" from "if this is authorized,
    these conditions attach". Without the distinction, a rule whose only job is
    to add a redaction obligation would also count as an authorization, and a
    request that no rule actually meant to permit could be permitted by the
    accident of a redaction rule matching it. That is a subtle and very bad
    failure mode, so the type system separates the two concerns.
    """
    PERMIT = "PERMIT"   # authorizes the request, may carry obligations
    OBLIGE = "OBLIGE"   # authorizes nothing; contributes obligations only
    DENY = "DENY"       # refuses; never outvoted


# ---------------------------------------------------------------------------
# Request envelope
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    """The authenticated requester.

    `mfa_satisfied` and `mfa_method` exist because CJIS requires advanced
    authentication for access to CJI from a non-physically-secure location, and
    because not all second factors are equal — SMS OTP is not acceptable for
    the SPECIAL clearance paths.
    """
    user_id: str
    agency: str
    clearance: Clearance
    roles: FrozenSet[str] = frozenset()
    case_memberships: FrozenSet[str] = frozenset()
    mfa_satisfied: bool = False
    mfa_method: Optional[str] = None
    from_secure_location: bool = False
    training_current_until: Optional[date] = None
    supervisor_id: Optional[str] = None
    # Set by the resolver at authentication time from HR/identity data. Used to
    # detect self-lookup and relative/colleague lookup, the most common real
    # insider-misuse pattern by a wide margin.
    linked_entity_ids: FrozenSet[str] = frozenset()

    def training_valid_on(self, when: date) -> bool:
        if self.training_current_until is None:
            return False

        target_date = when.date() if isinstance(when, datetime) else when
        current_limit = (
            self.training_current_until.date()
            if isinstance(self.training_current_until, datetime)
            else self.training_current_until
        )

        return current_limit >= target_date

@dataclass(frozen=True)
class Resource:
    """What is being accessed.

    Note that `subject_categories` is a set: a subgraph request touches many
    entities of mixed category, and the policy must reason about the whole
    envelope. Evaluating per-entity after the fact is how systems end up
    disclosing a victim record inside an otherwise-permitted subgraph.
    """
    kind: ResourceKind
    resource_id: str
    case_id: Optional[str] = None
    subject_categories: FrozenSet[SubjectCategory] = frozenset()
    legal_basis_refs: FrozenSet[str] = frozenset()
    entity_ids: FrozenSet[str] = frozenset()
    # Lifecycle / content flags, populated by the PEP from the store. These are
    # facts about the data, not client-supplied hints — never populate them from
    # a request body.
    past_retention_review: bool = False
    tombstoned_present: bool = False
    special_category_present: bool = False
    origin_jurisdiction: Optional[str] = None
    # Derived-data attributes. Populated only for ResourceKind.COMMUNITY.
    is_derived: bool = False
    derivation_complete: bool = False
    stability: Optional[float] = None
    estimated_element_count: int = 0
    # Set true only when a named human has reviewed an algorithmic output and
    # recorded that review. Gates export of derived data under LED Art. 11.
    human_reviewed: bool = False


@dataclass(frozen=True)
class CaseContext:
    """Case metadata the PDP needs. Fetched by the PEP, not trusted from client."""
    case_id: str
    authorised_bases: FrozenSet[str]
    is_open: bool
    supervisor_ids: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class AccessRequest:
    principal: Principal
    action: Action
    resource: Resource
    purpose: Purpose
    request_id: str
    at: datetime = field(default_factory=lambda: datetime.now())
    justification: Optional[str] = None
    case_context: Optional[CaseContext] = None
    # Present when a second person has authorized an elevated action.
    approval_by: Optional[str] = None


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleOutcome:
    """What a single rule returned. `None` from a rule means 'no opinion'."""
    effect: Effect
    rule_id: str
    reason: str
    obligations: FrozenSet[Obligation] = frozenset()


@dataclass(frozen=True)
class Decision:
    effect: Effect
    obligations: FrozenSet[Obligation]
    reasons: Tuple[str, ...]
    rule_trace: Tuple[str, ...]
    regime: Regime
    request_id: str

    @property
    def permitted(self) -> bool:
        return self.effect is Effect.PERMIT


class PolicyDenied(Exception):
    """Raised by enforce() on deny. Carries the decision for audit, but the
    message given to the caller is deliberately generic — a detailed denial
    reason is an information leak that lets a user probe for what exists."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__("Access denied by policy")


class UnsupportedObligation(Exception):
    """The policy required something this build cannot enforce. Fail closed."""

    def __init__(self, missing: FrozenSet[Obligation]):
        self.missing = missing
        super().__init__(f"Enforcement point cannot honour obligations: "
                         f"{sorted(o.value for o in missing)}")
