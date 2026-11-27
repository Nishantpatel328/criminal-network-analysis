"""GDPR + Law Enforcement Directive (EU) 2016/680 rule pack.

The LED is the instrument that actually governs police processing in the EU;
GDPR applies to the parts of the deployment that are not law-enforcement
processing (staff administration, for instance) and supplies the definitions the
LED leans on. Article references are to the LED unless marked GDPR.

The structural difference from CJIS worth noting: CJIS is fundamentally about
*who* may access *what*, and its questions are answerable from identity and
clearance. LED is about *why*, *for how long*, and *about whom* — purpose
compatibility, retention validity, and data-subject category. That is why the
common envelope carries `purpose`, `subject_categories` and the retention flags:
those fields exist because LED needs them, and CJIS turns out to benefit from
them too.
"""

from __future__ import annotations

from typing import Optional

from ..models import (
    Action,
    AccessRequest,
    Clearance,
    Effect,
    Obligation,
    PROTECTED_CATEGORIES,
    Purpose,
    ResourceKind,
    RuleOutcome,
)
from ..policy import rule


@rule("LED-DENY-RETENTION-EXPIRED")
def deny_retention_expired(req: AccessRequest) -> Optional[RuleOutcome]:
    """Art. 5 — time limits for storage and review.

    Data past its review date is not merely due for tidying; continuing to
    process it is unlawful. Refusing access is the enforcement, because a
    retention policy that only runs as a nightly batch has a window in which
    expired data is still being served. Deny at read, delete at batch.
    """
    if req.resource.past_retention_review:
        return RuleOutcome(
            Effect.DENY, "LED-DENY-RETENTION-EXPIRED",
            "data is past its retention review date and pending disposal",
        )
    if req.resource.tombstoned_present:
        return RuleOutcome(
            Effect.DENY, "LED-DENY-RETENTION-EXPIRED",
            "request touches tombstoned records awaiting erasure",
        )
    return None


@rule("LED-GATE-PURPOSE-COMPATIBILITY")
def gate_purpose_compatibility(req: AccessRequest) -> Optional[RuleOutcome]:
    """Art. 4(2) — further processing for another LED purpose is permitted only
    where authorised by law and where the processing is necessary and
    proportionate for that other purpose.

    `INTELLIGENCE_DEVELOPMENT` is exactly this case: data collected to
    investigate offence A being used to develop intelligence about network B.
    Legitimate, and specifically constrained.
    """
    if req.purpose is not Purpose.INTELLIGENCE_DEVELOPMENT:
        return None
    if req.principal.clearance < Clearance.ENHANCED:
        return RuleOutcome(
            Effect.DENY, "LED-GATE-PURPOSE-COMPATIBILITY",
            "intelligence development requires ENHANCED clearance",
        )
    if not (req.justification or "").strip():
        return RuleOutcome(
            Effect.DENY, "LED-GATE-PURPOSE-COMPATIBILITY",
            "further processing under Art. 4(2) requires a recorded "
            "necessity and proportionality justification",
        )
    if req.resource.subject_categories & PROTECTED_CATEGORIES:
        # Victim and witness data may not be repurposed into intelligence
        # development. They gave their information to be helped or to assist a
        # prosecution, not to become the raw material of network analysis, and
        # repurposing it is both unlawful and corrosive of the willingness of
        # future victims to come forward.
        return RuleOutcome(
            Effect.DENY, "LED-GATE-PURPOSE-COMPATIBILITY",
            "victim/witness data may not be repurposed for intelligence "
            "development",
        )
    return RuleOutcome(
        Effect.PERMIT, "LED-GATE-PURPOSE-COMPATIBILITY",
        "compatible further processing under Art. 4(2)",
        obligations=frozenset({
            Obligation.REDACT_SPECIAL_CATEGORY,
            Obligation.REDACT_PLAIN_IDENTIFIERS,
            Obligation.REDACT_PRECISE_DOB,
            Obligation.HIGH_SALIENCE_AUDIT,
            Obligation.WATERMARK_OUTPUT,
            Obligation.HYPOTHESIS_FRAMING,
        }),
    )


@rule("LED-OBL-ART10-SPECIAL-CATEGORY")
def oblige_special_category(req: AccessRequest) -> Optional[RuleOutcome]:
    """Art. 10 — special categories are permitted only where strictly necessary.

    We do not attempt to adjudicate "strictly necessary" in code; we make the
    data unreadable on every analytical path and require a separate, manual,
    documented process for the rare legitimate need. Unconditional redaction is
    a defensible interpretation and a testable one.
    """
    if not req.resource.special_category_present:
        return None
    return RuleOutcome(
        Effect.OBLIGE, "LED-OBL-ART10-SPECIAL-CATEGORY",
        "Art. 10 special-category data redacted unconditionally",
        obligations=frozenset({
            Obligation.REDACT_SPECIAL_CATEGORY,
            Obligation.HIGH_SALIENCE_AUDIT,
        }),
    )


@rule("LED-DENY-ART11-AUTOMATED-DECISION")
def deny_automated_decision(req: AccessRequest) -> Optional[RuleOutcome]:
    """Art. 11 — no decision based solely on automated processing that produces
    an adverse legal effect, without human intervention.

    Concretely: derived community assignments may not be exported into
    downstream systems until a named human has reviewed them and that review is
    recorded. Export is where an algorithmic hypothesis stops being a working
    note and starts being a fact that other systems act on, so that is the right
    place for the gate.
    """
    if req.action is not Action.EXPORT:
        return None
    if not req.resource.is_derived:
        return None
    if not req.resource.human_reviewed:
        return RuleOutcome(
            Effect.DENY, "LED-DENY-ART11-AUTOMATED-DECISION",
            "derived output may not be exported without recorded human review "
            "(Art. 11)",
        )
    return RuleOutcome(
        Effect.OBLIGE, "LED-DENY-ART11-AUTOMATED-DECISION",
        "human-reviewed derived output; hypothesis framing retained on export",
        obligations=frozenset({
            Obligation.HYPOTHESIS_FRAMING,
            Obligation.HIGH_SALIENCE_AUDIT,
            Obligation.WATERMARK_OUTPUT,
        }),
    )


@rule("LED-PERMIT-DATA-SUBJECT-REQUEST")
def permit_data_subject_request(req: AccessRequest) -> Optional[RuleOutcome]:
    """Arts. 12-16 — subject access, rectification and erasure.

    Handled by the DPO function, not by investigators, and deliberately routed
    through a distinct purpose so that subject-access work is separable in the
    audit log from investigative access to the same records.
    """
    if req.purpose is not Purpose.DATA_SUBJECT_REQUEST:
        return None
    if "dpo" not in req.principal.roles:
        return RuleOutcome(
            Effect.DENY, "LED-PERMIT-DATA-SUBJECT-REQUEST",
            "data-subject requests are handled by the DPO function only",
        )
    return RuleOutcome(
        Effect.PERMIT, "LED-PERMIT-DATA-SUBJECT-REQUEST",
        "DPO processing a data-subject request",
        obligations=frozenset({
            Obligation.HIGH_SALIENCE_AUDIT,
            Obligation.WATERMARK_OUTPUT,
        }),
    )


@rule("LED-DENY-THIRD-COUNTRY-TRANSFER")
def deny_third_country_transfer(req: AccessRequest) -> Optional[RuleOutcome]:
    """Chapter V — transfers to third countries need an adequacy decision or
    appropriate safeguards.

    The pilot deployment is single-jurisdiction, so any request whose data
    originates outside the tenant's jurisdiction is refused rather than
    silently permitted. Flagged as an open question in ARCHITECTURE.md §9: the
    multi-tenant design needs a legal decision before this rule can be relaxed,
    and relaxing it by default would be the easy wrong move.
    """
    origin = req.resource.origin_jurisdiction
    if origin is None:
        return None
    tenant_jurisdiction = req.principal.agency.split(":")[0]
    if origin != tenant_jurisdiction:
        if f"transfer_basis:{origin}" not in req.principal.roles:
            return RuleOutcome(
                Effect.DENY, "LED-DENY-THIRD-COUNTRY-TRANSFER",
                f"no Chapter V transfer basis recorded for data originating "
                f"in {origin}",
            )
        return RuleOutcome(
            Effect.OBLIGE, "LED-DENY-THIRD-COUNTRY-TRANSFER",
            f"third-country access under recorded transfer basis ({origin})",
            obligations=frozenset({Obligation.HIGH_SALIENCE_AUDIT}),
        )
    return None


@rule("LED-OBL-MINIMISATION")
def oblige_minimisation(req: AccessRequest) -> Optional[RuleOutcome]:
    """Art. 4(1)(c) — adequate, relevant and not excessive.

    Applied as a default redaction floor on every read: precise date of birth
    and plaintext identifiers are not needed to understand network structure, so
    they are withheld unless a rule specifically grants them.
    """
    if req.resource.kind not in (ResourceKind.ENTITY, ResourceKind.SUBGRAPH,
                                 ResourceKind.COMMUNITY):
        return None
    return RuleOutcome(
        Effect.OBLIGE, "LED-OBL-MINIMISATION",
        "default minimisation floor applied",
        obligations=frozenset({
            Obligation.REDACT_PRECISE_DOB,
            Obligation.REDACT_PLAIN_IDENTIFIERS,
            Obligation.REDACT_SPECIAL_CATEGORY,
        }),
    )


LED_RULES = (
    deny_retention_expired,
    gate_purpose_compatibility,
    oblige_special_category,
    deny_automated_decision,
    permit_data_subject_request,
    deny_third_country_transfer,
    oblige_minimisation,
)
