"""CJIS Security Policy rule pack.

Implements the access-control-relevant provisions of the CJIS Security Policy
(5.9.x) that belong in an application-tier PDP. Controls that are properly
infrastructure concerns — FIPS 140-3 validated cryptographic modules, physical
security of the facility, personnel screening, boundary protection — are
enforced in `deploy/` and asserted by CI checks rather than evaluated per
request. Putting them here would be theatre: a policy rule cannot verify that
the TLS module is FIPS-validated.

Section references are to the CJIS Security Policy and are given for
traceability in the control matrix (docs/privacy-compliance.md).
"""

from __future__ import annotations

from typing import Optional

from ..models import (
    Action,
    AccessRequest,
    Clearance,
    Effect,
    Obligation,
    Purpose,
    ResourceKind,
    RuleOutcome,
)
from ..policy import rule

# CJIS 5.6.2.2 — advanced authentication is required for access to CJI from a
# location that is not physically secure. SMS-delivered OTP is excluded: it is
# vulnerable to SIM-swap and SS7 interception, and against an adversary who is
# an organised criminal group with resources, that is a live threat rather than
# a theoretical one.
STRONG_MFA_METHODS = frozenset({"fido2", "piv", "cac", "totp_hardware", "push_verified"})
WEAK_MFA_METHODS = frozenset({"sms", "voice", "email"})


@rule("CJIS-DENY-NO-ADVANCED-AUTH")
def deny_without_advanced_auth(req: AccessRequest) -> Optional[RuleOutcome]:
    """CJIS 5.6.2.2 — advanced authentication outside a secure location."""
    if req.principal.from_secure_location:
        return None
    if not req.principal.mfa_satisfied:
        return RuleOutcome(
            Effect.DENY, "CJIS-DENY-NO-ADVANCED-AUTH",
            "advanced authentication required for CJI access from a "
            "location that is not physically secure",
        )
    if req.principal.mfa_method in WEAK_MFA_METHODS:
        return RuleOutcome(
            Effect.DENY, "CJIS-DENY-NO-ADVANCED-AUTH",
            f"authenticator '{req.principal.mfa_method}' does not satisfy "
            f"advanced authentication requirements",
        )
    if req.principal.mfa_method not in STRONG_MFA_METHODS:
        # Unknown method — fail closed rather than assume it is acceptable.
        return RuleOutcome(
            Effect.DENY, "CJIS-DENY-NO-ADVANCED-AUTH",
            f"unrecognised authenticator '{req.principal.mfa_method}'",
        )
    return None


@rule("CJIS-DENY-WEAK-AUTH-FOR-SPECIAL")
def deny_weak_auth_for_special_clearance(req: AccessRequest) -> Optional[RuleOutcome]:
    """Hardware-bound authenticators only for SPECIAL clearance paths.

    Phishing-resistant means origin-bound: FIDO2 or a PIV/CAC card. A software
    TOTP is replayable by a proxy phishing site, so it does not qualify here
    even though it satisfies the general advanced-authentication requirement.
    """
    if req.principal.clearance < Clearance.SPECIAL:
        return None
    if req.principal.mfa_method not in {"fido2", "piv", "cac"}:
        return RuleOutcome(
            Effect.DENY, "CJIS-DENY-WEAK-AUTH-FOR-SPECIAL",
            "SPECIAL clearance requires a phishing-resistant, hardware-bound "
            "authenticator (FIDO2 or PIV/CAC)",
        )
    return None


@rule("CJIS-OBL-SESSION-REAUTH")
def oblige_session_reauth(req: AccessRequest) -> Optional[RuleOutcome]:
    """Short re-authentication window for remote sessions.

    CJIS 5.5.5 requires session lock after inactivity; we tighten it for remote
    access because an unattended remote session is the disclosure risk the
    control is aimed at, and the facility protections that make a longer window
    acceptable are absent by definition.
    """
    if req.principal.from_secure_location:
        return None
    return RuleOutcome(
        Effect.OBLIGE, "CJIS-OBL-SESSION-REAUTH",
        "remote session: 15-minute re-authentication window",
        obligations=frozenset({Obligation.SESSION_REAUTH_15M}),
    )


@rule("CJIS-DENY-CROSS-AGENCY-WITHOUT-MCA")
def deny_cross_agency_without_agreement(req: AccessRequest) -> Optional[RuleOutcome]:
    """CJIS 5.1.1.4 — inter-agency CJI sharing needs a management control
    agreement. Modelled as a role granted only when the agreement is on file, so
    the paperwork state is represented in the authorization data rather than in
    a filing cabinet nobody checks.
    """
    ctx = req.case_context
    if ctx is None:
        return None
    owning_agency = ctx.case_id.split("-")[0] if "-" in ctx.case_id else None
    if owning_agency is None or owning_agency == req.principal.agency:
        return None
    if f"mca:{owning_agency}" not in req.principal.roles:
        return RuleOutcome(
            Effect.DENY, "CJIS-DENY-CROSS-AGENCY-WITHOUT-MCA",
            f"no management control agreement on file for agency "
            f"{owning_agency}",
        )
    return RuleOutcome(
        Effect.OBLIGE, "CJIS-DENY-CROSS-AGENCY-WITHOUT-MCA",
        "cross-agency access under management control agreement",
        obligations=frozenset({Obligation.HIGH_SALIENCE_AUDIT}),
    )


@rule("CJIS-OBL-EXPORT-CONTROLS")
def oblige_export_controls(req: AccessRequest) -> Optional[RuleOutcome]:
    """Dissemination of CJI is watermarked, rate-limited and audited (5.4, 5.13)."""
    if req.action is not Action.EXPORT:
        return None
    return RuleOutcome(
        Effect.OBLIGE, "CJIS-OBL-EXPORT-CONTROLS",
        "CJI dissemination controls applied to export",
        obligations=frozenset({
            Obligation.WATERMARK_OUTPUT,
            Obligation.HIGH_SALIENCE_AUDIT,
            Obligation.RATE_LIMIT_STRICT,
            Obligation.REDACT_SPECIAL_CATEGORY,
        }),
    )


@rule("CJIS-PERMIT-DISCLOSURE-PREP")
def permit_disclosure_prep(req: AccessRequest) -> Optional[RuleOutcome]:
    """Disclosure officers prepare case material after a case closes."""
    if req.purpose is not Purpose.DISCLOSURE_PREP:
        return None
    if "disclosure_officer" not in req.principal.roles:
        return RuleOutcome(
            Effect.DENY, "CJIS-PERMIT-DISCLOSURE-PREP",
            "disclosure preparation requires the disclosure_officer role",
        )
    if req.resource.kind is ResourceKind.COMMUNITY and not req.resource.human_reviewed:
        # Algorithmic output must not enter a disclosure bundle unreviewed; it
        # would arrive in court as though it were an observed fact.
        return RuleOutcome(
            Effect.DENY, "CJIS-PERMIT-DISCLOSURE-PREP",
            "algorithmic output requires recorded human review before disclosure",
        )
    return RuleOutcome(
        Effect.PERMIT, "CJIS-PERMIT-DISCLOSURE-PREP",
        "disclosure officer preparing case material",
        obligations=frozenset({
            Obligation.WATERMARK_OUTPUT,
            Obligation.HIGH_SALIENCE_AUDIT,
            Obligation.REDACT_SPECIAL_CATEGORY,
        }),
    )


CJIS_RULES = (
    deny_without_advanced_auth,
    deny_weak_auth_for_special_clearance,
    oblige_session_reauth,
    deny_cross_agency_without_agreement,
    oblige_export_controls,
    permit_disclosure_prep,
)
