"""Regime-neutral rules.

These encode controls that both CJIS and LED require, plus the anti-abuse
controls that neither statute mandates in these words but that any responsible
build of this system needs. They are evaluated for every tenant regardless of
regime.

Ordering within the list is irrelevant to the outcome — the combination algebra
is order-independent by construction — so rules are grouped for readability.
"""

from __future__ import annotations

from datetime import date
from typing import FrozenSet, Optional

from .models import (
    Action,
    AccessRequest,
    Clearance,
    Effect,
    Obligation,
    PROTECTED_CATEGORIES,
    Purpose,
    ResourceKind,
    RuleOutcome,
    SubjectCategory,
)
from .policy import rule

# Actions that read entity or relationship data.
READ_ACTIONS: FrozenSet[Action] = frozenset({
    Action.VIEW_ENTITY,
    Action.EXPAND_SUBGRAPH,
    Action.SEARCH_BY_NAME,
    Action.VIEW_COMMUNITY,
})

# Actions requiring a free-text justification recorded in the audit log.
JUSTIFICATION_REQUIRED: FrozenSet[Action] = frozenset({
    Action.SEARCH_BY_NAME,
    Action.REIDENTIFY,
    Action.EXPORT,
    Action.RECATEGORISE_SUBJECT,
})

# Hard ceiling on elements returned by a single request. Both a performance
# guard and an anti-bulk-exfiltration control: a legitimate analyst workflow
# never needs 5,000 nodes at once, but an exfiltration script does.
MAX_ELEMENTS_PER_REQUEST = 5_000

# Community assignments below this stability score are withheld rather than
# shown with a warning. 0.6 is a judgement call pending pilot calibration —
# flagged as an open question in ARCHITECTURE.md §9.
MIN_DISCLOSABLE_STABILITY = 0.6

MIN_JUSTIFICATION_CHARS = 20


# ---------------------------------------------------------------------------
# Baseline authorization
# ---------------------------------------------------------------------------

@rule("C-PERMIT-CASE-MEMBER")
def permit_case_member_read(req: AccessRequest) -> Optional[RuleOutcome]:
    """The ordinary path: a case member reading data within their own case."""
    if req.action not in READ_ACTIONS:
        return None
    if req.purpose is not Purpose.INVESTIGATION:
        return None
    if req.resource.case_id is None:
        return None
    if req.resource.case_id not in req.principal.case_memberships:
        return None
    return RuleOutcome(
        Effect.PERMIT,
        "C-PERMIT-CASE-MEMBER",
        f"case member of {req.resource.case_id} reading for investigation",
        obligations=frozenset({
            Obligation.REDACT_SPECIAL_CATEGORY,
            Obligation.REDACT_PLAIN_IDENTIFIERS,
            Obligation.WATERMARK_OUTPUT,
        }),
    )


@rule("C-PERMIT-CROSS-CASE")
def permit_cross_case_link(req: AccessRequest) -> Optional[RuleOutcome]:
    """Cross-case linkage: separately authorized, two-person, high salience.

    This is the control that stops "data lawfully held for case A" from
    becoming "data available for anything". It is deliberately inconvenient.
    """
    if req.purpose is not Purpose.CROSS_CASE_LINK:
        return None
    if req.approval_by is None:
        return RuleOutcome(
            Effect.DENY, "C-PERMIT-CROSS-CASE",
            "cross-case linkage requires supervisor approval",
        )
    if req.approval_by == req.principal.user_id:
        # Self-approval defeats the entire point of two-person authorization,
        # and is the first thing anyone tries.
        return RuleOutcome(
            Effect.DENY, "C-PERMIT-CROSS-CASE",
            "cross-case approval may not be granted by the requester",
        )
    if req.principal.clearance < Clearance.ENHANCED:
        return RuleOutcome(
            Effect.DENY, "C-PERMIT-CROSS-CASE",
            "cross-case linkage requires ENHANCED clearance",
        )
    return RuleOutcome(
        Effect.PERMIT, "C-PERMIT-CROSS-CASE",
        f"cross-case linkage approved by {req.approval_by}",
        obligations=frozenset({
            Obligation.REDACT_SPECIAL_CATEGORY,
            Obligation.REDACT_PLAIN_IDENTIFIERS,
            Obligation.WATERMARK_OUTPUT,
            Obligation.HIGH_SALIENCE_AUDIT,
            Obligation.SUPERVISOR_NOTIFY,
            Obligation.RATE_LIMIT_STRICT,
        }),
    )


@rule("C-PERMIT-AUDIT-OVERSIGHT")
def permit_audit_read(req: AccessRequest) -> Optional[RuleOutcome]:
    """Oversight bodies read the audit log. Reading it is itself audited."""
    if req.action is not Action.READ_AUDIT:
        return None
    if req.purpose is not Purpose.AUDIT_OVERSIGHT:
        return RuleOutcome(
            Effect.DENY, "C-PERMIT-AUDIT-OVERSIGHT",
            "audit log may only be read for oversight purposes",
        )
    if not ({"dpo", "cjis_auditor", "oversight"} & set(req.principal.roles)):
        return RuleOutcome(
            Effect.DENY, "C-PERMIT-AUDIT-OVERSIGHT",
            "audit read requires an oversight role",
        )
    return RuleOutcome(
        Effect.PERMIT, "C-PERMIT-AUDIT-OVERSIGHT",
        "oversight role reading audit log",
        obligations=frozenset({Obligation.HIGH_SALIENCE_AUDIT}),
    )


# ---------------------------------------------------------------------------
# Insider-misuse controls
#
# The realistic threat model here is not an external attacker. It is an
# authorized user with a legitimate credential looking up someone they have a
# personal interest in. Every significant real-world abuse case in comparable
# law-enforcement systems has had this shape.
# ---------------------------------------------------------------------------

@rule("C-DENY-SELF-OR-ASSOCIATE-LOOKUP")
def deny_self_lookup(req: AccessRequest) -> Optional[RuleOutcome]:
    """No user may access records linked to themselves or their known associates.

    `linked_entity_ids` is populated at authentication from HR data: the user's
    own record plus declared relatives and cohabitants. This is a hard deny with
    no override path in the application. A genuine need — an officer who is
    themselves a witness — is handled off-system by a different team, because
    the alternative is an override button that becomes the abuse vector.
    """
    overlap = req.resource.entity_ids & req.principal.linked_entity_ids
    if overlap:
        return RuleOutcome(
            Effect.DENY, "C-DENY-SELF-OR-ASSOCIATE-LOOKUP",
            "request touches records linked to the requesting user",
        )
    return None


@rule("C-DENY-NO-CASE-MEMBERSHIP")
def deny_non_member(req: AccessRequest) -> Optional[RuleOutcome]:
    """Reading case data without membership is refused even at high clearance.

    Clearance answers "how sensitive may this person see"; membership answers
    "is this person working on this". Conflating them produces the classic
    over-cleared-browsing problem, where a senior officer can read every case in
    the force because their clearance is high.
    """
    if req.action not in READ_ACTIONS:
        return None
    if req.purpose in (Purpose.CROSS_CASE_LINK, Purpose.AUDIT_OVERSIGHT,
                       Purpose.DATA_SUBJECT_REQUEST):
        return None
    case_id = req.resource.case_id
    if case_id is None:
        return RuleOutcome(
            Effect.DENY, "C-DENY-NO-CASE-MEMBERSHIP",
            "read request without a case scope",
        )
    if case_id not in req.principal.case_memberships:
        return RuleOutcome(
            Effect.DENY, "C-DENY-NO-CASE-MEMBERSHIP",
            "requester is not a member of the target case",
        )
    return None


@rule("C-DENY-JUSTIFICATION-MISSING")
def deny_missing_justification(req: AccessRequest) -> Optional[RuleOutcome]:
    if req.action not in JUSTIFICATION_REQUIRED:
        return None
    j = (req.justification or "").strip()
    if len(j) < MIN_JUSTIFICATION_CHARS:
        return RuleOutcome(
            Effect.DENY, "C-DENY-JUSTIFICATION-MISSING",
            f"{req.action.value} requires a justification of at least "
            f"{MIN_JUSTIFICATION_CHARS} characters",
        )
    return None


@rule("C-DENY-TRAINING-LAPSED")
def deny_training_lapsed(req: AccessRequest) -> Optional[RuleOutcome]:
    """Both regimes require current data-handling training. CJIS mandates
    biennial security awareness training; LED requires demonstrable staff
    competence. Enforcing it at the request rather than at the annual review
    means a lapsed user loses access on the day, not at the next audit."""
    if req.action is Action.READ_AUDIT:
        return None
    if not req.principal.training_valid_on(date.today()):
        return RuleOutcome(
            Effect.DENY, "C-DENY-TRAINING-LAPSED",
            "mandatory data-handling training is not current",
        )
    return None


# ---------------------------------------------------------------------------
# Protected data-subject categories
# ---------------------------------------------------------------------------

@rule("C-GATE-PROTECTED-SUBJECT")
def gate_protected_subject(req: AccessRequest) -> Optional[RuleOutcome]:
    """Victim and witness records need elevated clearance and a justification.

    Note this returns PERMIT rather than OBLIGE when satisfied: it is a genuine
    additional authorization for data the baseline rule cannot reach, since the
    base Neo4j role literally cannot traverse :ProtectedSubject.
    """
    touched = req.resource.subject_categories & PROTECTED_CATEGORIES
    if not touched:
        return None

    if req.principal.clearance < Clearance.ENHANCED:
        return RuleOutcome(
            Effect.DENY, "C-GATE-PROTECTED-SUBJECT",
            "victim/witness records require ENHANCED clearance",
        )
    if not (req.justification or "").strip():
        return RuleOutcome(
            Effect.DENY, "C-GATE-PROTECTED-SUBJECT",
            "victim/witness access requires a recorded justification",
        )
    return RuleOutcome(
        Effect.PERMIT, "C-GATE-PROTECTED-SUBJECT",
        "elevated access to protected subject category",
        obligations=frozenset({
            Obligation.PROTECTED_SUBJECT_POOL,
            Obligation.SUPERVISOR_NOTIFY,
            Obligation.HIGH_SALIENCE_AUDIT,
            Obligation.REDACT_SPECIAL_CATEGORY,
            Obligation.REDACT_PLAIN_IDENTIFIERS,
            Obligation.REDACT_PRECISE_DOB,
            Obligation.WATERMARK_OUTPUT,
        }),
    )


@rule("C-OBL-CONTACT-MINIMISATION")
def oblige_contact_minimisation(req: AccessRequest) -> Optional[RuleOutcome]:
    """Incidental contacts are visible only as degree-1 attachments.

    These are people in the data solely because a suspect phoned them — the
    dentist, the school, the taxi office. They are overwhelmingly the largest
    category by volume in CDR-derived graphs and overwhelmingly innocent.
    Permitting traversal *through* them turns a targeted investigation into a
    fishing expedition across their entire social graph, which is neither
    necessary nor proportionate under either regime.
    """
    if SubjectCategory.CONTACT not in req.resource.subject_categories:
        return None
    return RuleOutcome(
        Effect.OBLIGE, "C-OBL-CONTACT-MINIMISATION",
        "incidental contacts limited to degree-1 visibility",
        obligations=frozenset({Obligation.MINIMISE_TO_DEGREE_1}),
    )


# ---------------------------------------------------------------------------
# Derived-data integrity — the anti-automated-decision controls
# ---------------------------------------------------------------------------

@rule("C-DENY-INCOMPLETE-DERIVATION")
def deny_incomplete_derivation(req: AccessRequest) -> Optional[RuleOutcome]:
    """Refuse to serve an algorithmic output that cannot explain itself.

    If we cannot state which algorithm, which version, which parameters and
    which input snapshot produced a cluster assignment, then an analyst cannot
    evaluate it and a court cannot test it. Serving it anyway produces an
    unfalsifiable claim about a person, which is precisely what the automated-
    decision provisions of LED Art. 11 / GDPR Art. 22 exist to prevent.
    """
    if not req.resource.is_derived:
        return None
    if not req.resource.derivation_complete:
        return RuleOutcome(
            Effect.DENY, "C-DENY-INCOMPLETE-DERIVATION",
            "derived output lacks a complete derivation envelope",
        )
    return None


@rule("C-OBL-HYPOTHESIS-FRAMING")
def oblige_hypothesis_framing(req: AccessRequest) -> Optional[RuleOutcome]:
    """Community output must be presented as hypothesis, and withheld if unstable."""
    if req.resource.kind is not ResourceKind.COMMUNITY:
        return None

    obligations = {Obligation.HYPOTHESIS_FRAMING}
    stability = req.resource.stability
    if stability is None:
        return RuleOutcome(
            Effect.DENY, "C-OBL-HYPOTHESIS-FRAMING",
            "community assignment has no stability score",
        )
    if stability < MIN_DISCLOSABLE_STABILITY:
        obligations.add(Obligation.WITHHOLD_LOW_STABILITY)
    return RuleOutcome(
        Effect.OBLIGE, "C-OBL-HYPOTHESIS-FRAMING",
        f"community output framed as hypothesis (stability={stability:.2f})",
        obligations=frozenset(obligations),
    )


# ---------------------------------------------------------------------------
# Scope, cost, and lifecycle
# ---------------------------------------------------------------------------

@rule("C-DENY-BASIS-OUT-OF-SCOPE")
def deny_basis_out_of_scope(req: AccessRequest) -> Optional[RuleOutcome]:
    """Purpose limitation, enforced on the traversal.

    Every relationship carries the legal instrument that authorised its
    collection. A case may only traverse edges whose basis it is authorised for.
    """
    if req.action not in READ_ACTIONS:
        return None
    if req.purpose is Purpose.CROSS_CASE_LINK:
        return None  # handled by C-PERMIT-CROSS-CASE
    ctx = req.case_context
    if ctx is None:
        return None
    unauthorised = req.resource.legal_basis_refs - ctx.authorised_bases
    if unauthorised:
        return RuleOutcome(
            Effect.DENY, "C-DENY-BASIS-OUT-OF-SCOPE",
            f"{len(unauthorised)} relationship(s) rest on legal bases not "
            f"authorised for this case",
        )
    return None


@rule("C-DENY-CASE-CLOSED")
def deny_closed_case(req: AccessRequest) -> Optional[RuleOutcome]:
    if req.case_context is None or req.case_context.is_open:
        return None
    # Disclosure preparation and subject-access work legitimately continue after
    # a case closes; ordinary investigative browsing does not.
    if req.purpose in (Purpose.DISCLOSURE_PREP, Purpose.DATA_SUBJECT_REQUEST,
                       Purpose.AUDIT_OVERSIGHT):
        return None
    return RuleOutcome(
        Effect.DENY, "C-DENY-CASE-CLOSED",
        "case is closed; investigative access no longer permitted",
    )


@rule("C-DENY-EXCESSIVE-SCOPE")
def deny_excessive_scope(req: AccessRequest) -> Optional[RuleOutcome]:
    if req.resource.estimated_element_count > MAX_ELEMENTS_PER_REQUEST:
        return RuleOutcome(
            Effect.DENY, "C-DENY-EXCESSIVE-SCOPE",
            f"request would return ~{req.resource.estimated_element_count} "
            f"elements, above the {MAX_ELEMENTS_PER_REQUEST} ceiling; refine scope",
        )
    return None


@rule("C-DENY-MAINTENANCE-TOUCHING-DATA")
def deny_maintenance_purpose_on_data(req: AccessRequest) -> Optional[RuleOutcome]:
    """SYSTEM_MAINTENANCE must never be usable to read subject data.

    Otherwise it becomes the universal purpose that launders every access,
    which is exactly what happens to a catch-all purpose value under delivery
    pressure.
    """
    if req.purpose is not Purpose.SYSTEM_MAINTENANCE:
        return None
    if req.resource.kind in (ResourceKind.ENTITY, ResourceKind.SUBGRAPH,
                             ResourceKind.COMMUNITY):
        return RuleOutcome(
            Effect.DENY, "C-DENY-MAINTENANCE-TOUCHING-DATA",
            "maintenance purpose cannot be used to access subject data",
        )
    return None


COMMON_RULES = (
    permit_case_member_read,
    permit_cross_case_link,
    permit_audit_read,
    deny_self_lookup,
    deny_non_member,
    deny_missing_justification,
    deny_training_lapsed,
    gate_protected_subject,
    oblige_contact_minimisation,
    deny_incomplete_derivation,
    oblige_hypothesis_framing,
    deny_basis_out_of_scope,
    deny_closed_case,
    deny_excessive_scope,
    deny_maintenance_purpose_on_data,
)
