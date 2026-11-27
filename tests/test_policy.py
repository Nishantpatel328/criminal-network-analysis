"""Security tests for the policy engine.

These are the tests that matter most in this codebase. A bug here is not a
crash — it is a silent, invisible disclosure of a victim's record. So the suite
is written adversarially: each test names the attack or mistake it prevents.
"""

from __future__ import annotations

import logging
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "api"))

from app.security.models import (  # noqa: E402
    AccessRequest, Action, CaseContext, Clearance, Effect, Obligation,
    PolicyDenied, Principal, Purpose, Regime, Resource, ResourceKind,
    RuleOutcome, SubjectCategory, UnsupportedObligation,
)
from app.security.policy import PolicyEngine, build_engine, enforce, rule  # noqa: E402
from app.security.redaction import Redactor  # noqa: E402

CASE = "NCA-2026-0412"
FUTURE = date.today() + timedelta(days=365)
PAST = date.today() - timedelta(days=1)


def principal(**kw) -> Principal:
    base = dict(
        user_id="analyst-1",
        agency="NCA",
        clearance=Clearance.BASIC,
        roles=frozenset(),
        case_memberships=frozenset({CASE}),
        mfa_satisfied=True,
        mfa_method="fido2",
        from_secure_location=True,
        training_current_until=FUTURE,
    )
    base.update(kw)
    return Principal(**base)


def resource(**kw) -> Resource:
    base = dict(
        kind=ResourceKind.SUBGRAPH,
        resource_id="sg-1",
        case_id=CASE,
        subject_categories=frozenset({SubjectCategory.SUSPECT}),
        legal_basis_refs=frozenset({"W-1"}),
        estimated_element_count=50,
    )
    base.update(kw)
    return Resource(**base)


def request(**kw) -> AccessRequest:
    base = dict(
        principal=principal(),
        action=Action.EXPAND_SUBGRAPH,
        resource=resource(),
        purpose=Purpose.INVESTIGATION,
        request_id="req-1",
        case_context=CaseContext(CASE, frozenset({"W-1"}), True),
    )
    base.update(kw)
    return AccessRequest(**base)


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------

class TestFailClosed:
    def test_unrecognised_request_is_denied(self):
        """A request no rule speaks to must be refused, not allowed.

        Prevents: adding a new Action without a corresponding rule and silently
        opening an unauthenticated hole. This is the single most important test
        in the file.
        """
        eng = build_engine(Regime.GDPR_LED)
        req = request(action=Action.RECATEGORISE_SUBJECT,
                      justification="x" * 40)
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert "no applicable rule" in d.reasons[0]

    def test_rule_raising_exception_denies(self):
        """A rule that throws must deny, not be skipped.

        Prevents: a NoneType error in one rule quietly removing that rule's
        protection while the system continues to serve requests.
        """
        @rule("BOOM")
        def exploding(req):
            raise RuntimeError("kaboom")

        @rule("ALWAYS-PERMIT")
        def permissive(req):
            return RuleOutcome(Effect.PERMIT, "ALWAYS-PERMIT", "yes")

        eng = PolicyEngine(Regime.CJIS, (permissive, exploding))
        # The engine logs the exception by design; silence it so the expected
        # traceback is not mistaken for a test failure in the output.
        logging.disable(logging.CRITICAL)
        try:
            d = eng.decide(request())
        finally:
            logging.disable(logging.NOTSET)
        assert d.effect is Effect.DENY
        assert any("evaluation error" in r for r in d.reasons)

    def test_deny_is_never_outvoted(self):
        @rule("P")
        def p(req):
            return RuleOutcome(Effect.PERMIT, "P", "permit")

        @rule("D")
        def d_(req):
            return RuleOutcome(Effect.DENY, "D", "deny")

        eng = PolicyEngine(Regime.CJIS, (p, p, p, d_))
        assert eng.decide(request()).effect is Effect.DENY

    def test_oblige_alone_does_not_authorize(self):
        """OBLIGE contributes obligations but authorizes nothing.

        Prevents the subtle failure the Effect.OBLIGE split exists for: a
        redaction rule accidentally becoming an authorization because it
        happened to match the request.
        """
        @rule("O")
        def o(req):
            return RuleOutcome(Effect.OBLIGE, "O", "redact",
                               frozenset({Obligation.WATERMARK_OUTPUT}))

        eng = PolicyEngine(Regime.CJIS, (o,))
        assert eng.decide(request()).effect is Effect.DENY

    def test_empty_rule_set_refuses_to_construct(self):
        with pytest.raises(ValueError):
            PolicyEngine(Regime.CJIS, ())


# ---------------------------------------------------------------------------
# Obligation enforcement
# ---------------------------------------------------------------------------

class TestObligations:
    def test_unenforceable_obligation_converts_permit_to_error(self):
        """Prevents: a permit whose redaction obligation is silently ignored.

        This is a real and quiet failure mode — the audit log shows PERMIT, the
        policy reads correctly, and the redaction never happened.
        """
        eng = build_engine(Regime.GDPR_LED)
        d = eng.decide(request())
        assert d.permitted
        with pytest.raises(UnsupportedObligation):
            enforce(d, {Obligation.WATERMARK_OUTPUT})  # missing the redactions

    def test_redactor_declares_support_for_everything_policy_can_emit(self):
        """Guards against a policy pack emitting an obligation no PEP can honour.

        Without this, adding an obligation to a rule would break requests at
        runtime rather than at test time.
        """
        emitted = set()
        for regime in (Regime.CJIS, Regime.GDPR_LED):
            for r in build_engine(regime)._rules:
                # Static scan is not possible; exercise the known obligation set.
                pass
        emitted = set(Obligation)
        # PROTECTED_SUBJECT_POOL etc. are handled by the Redactor's properties.
        assert emitted - Redactor.SUPPORTED == set(), (
            f"obligations no enforcement point honours: "
            f"{sorted(o.value for o in emitted - Redactor.SUPPORTED)}"
        )

    def test_obligations_union_not_intersect(self):
        """Two regimes' obligations must both apply, not cancel out."""
        eng = build_engine(Regime.GDPR_LED)
        d = eng.decide(request())
        assert Obligation.WATERMARK_OUTPUT in d.obligations      # from common
        assert Obligation.REDACT_PRECISE_DOB in d.obligations    # from LED


# ---------------------------------------------------------------------------
# Insider misuse
# ---------------------------------------------------------------------------

class TestInsiderMisuse:
    def test_self_lookup_denied(self):
        """The archetypal real-world abuse: looking yourself up."""
        me = "11111111-1111-4111-8111-111111111111"
        eng = build_engine(Regime.CJIS)
        req = request(
            principal=principal(linked_entity_ids=frozenset({me})),
            resource=resource(entity_ids=frozenset({me, "other"})),
        )
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("linked to the requesting user" in r for r in d.reasons)

    def test_self_lookup_denied_even_at_special_clearance(self):
        """No clearance level overrides this. Prevents a 'senior officers are
        trusted' carve-out, which is how this control usually dies."""
        me = "11111111-1111-4111-8111-111111111111"
        eng = build_engine(Regime.CJIS)
        req = request(
            principal=principal(clearance=Clearance.SPECIAL, mfa_method="piv",
                                linked_entity_ids=frozenset({me})),
            resource=resource(entity_ids=frozenset({me})),
        )
        assert eng.decide(req).effect is Effect.DENY

    def test_high_clearance_without_case_membership_denied(self):
        """Clearance is not membership. Prevents over-cleared browsing of every
        case in the force."""
        eng = build_engine(Regime.CJIS)
        req = request(principal=principal(clearance=Clearance.SPECIAL,
                                          mfa_method="piv",
                                          case_memberships=frozenset()))
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("not a member" in r for r in d.reasons)

    def test_lapsed_training_denies(self):
        eng = build_engine(Regime.CJIS)
        req = request(principal=principal(training_current_until=PAST))
        assert eng.decide(req).effect is Effect.DENY

    def test_cross_case_requires_two_person_approval(self):
        eng = build_engine(Regime.CJIS)
        base = dict(purpose=Purpose.CROSS_CASE_LINK,
                    principal=principal(clearance=Clearance.ENHANCED))

        assert eng.decide(request(**base)).effect is Effect.DENY

        self_approved = eng.decide(request(approval_by="analyst-1", **base))
        assert self_approved.effect is Effect.DENY
        assert any("may not be granted by the requester" in r
                   for r in self_approved.reasons)

        ok = eng.decide(request(approval_by="supervisor-9", **base))
        assert ok.permitted
        assert Obligation.HIGH_SALIENCE_AUDIT in ok.obligations


# ---------------------------------------------------------------------------
# Protected subject categories
# ---------------------------------------------------------------------------

class TestProtectedSubjects:
    def test_victim_record_denied_at_basic_clearance(self):
        eng = build_engine(Regime.CJIS)
        req = request(resource=resource(
            subject_categories=frozenset({SubjectCategory.SUSPECT,
                                          SubjectCategory.VICTIM})))
        d = eng.decide(req)
        assert d.effect is Effect.DENY

    def test_victim_record_needs_justification_even_when_cleared(self):
        eng = build_engine(Regime.CJIS)
        req = request(
            principal=principal(clearance=Clearance.ENHANCED),
            resource=resource(subject_categories=frozenset({SubjectCategory.VICTIM})),
        )
        assert eng.decide(req).effect is Effect.DENY

    def test_victim_access_permitted_with_clearance_and_justification(self):
        eng = build_engine(Regime.CJIS)
        req = request(
            principal=principal(clearance=Clearance.ENHANCED),
            resource=resource(subject_categories=frozenset({SubjectCategory.VICTIM})),
            justification="Victim statement corroborates the timeline in "
                          "exhibit KB-14; reviewing linked handset.",
        )
        d = eng.decide(req)
        assert d.permitted
        assert Obligation.PROTECTED_SUBJECT_POOL in d.obligations
        assert Obligation.SUPERVISOR_NOTIFY in d.obligations
        assert Obligation.HIGH_SALIENCE_AUDIT in d.obligations

    def test_victim_data_cannot_be_repurposed_for_intelligence(self):
        """LED Art. 4(2) boundary. Prevents victim statements becoming raw
        material for network analysis."""
        eng = build_engine(Regime.GDPR_LED)
        req = request(
            principal=principal(clearance=Clearance.ENHANCED),
            purpose=Purpose.INTELLIGENCE_DEVELOPMENT,
            resource=resource(subject_categories=frozenset({SubjectCategory.WITNESS})),
            justification="Developing intelligence picture on the wider network.",
        )
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("may not be repurposed" in r for r in d.reasons)

    def test_contacts_are_minimised_to_degree_one(self):
        eng = build_engine(Regime.CJIS)
        req = request(resource=resource(
            subject_categories=frozenset({SubjectCategory.SUSPECT,
                                          SubjectCategory.CONTACT})))
        d = eng.decide(req)
        assert d.permitted
        assert Obligation.MINIMISE_TO_DEGREE_1 in d.obligations


# ---------------------------------------------------------------------------
# Purpose limitation
# ---------------------------------------------------------------------------

class TestPurposeLimitation:
    def test_out_of_scope_legal_basis_denied(self):
        """Data collected under warrant W-2 is not available to a case
        authorised only for W-1."""
        eng = build_engine(Regime.CJIS)
        req = request(
            resource=resource(legal_basis_refs=frozenset({"W-1", "W-2"})),
            case_context=CaseContext(CASE, frozenset({"W-1"}), True),
        )
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("not authorised for this case" in r for r in d.reasons)

    def test_maintenance_purpose_cannot_read_subject_data(self):
        """Prevents SYSTEM_MAINTENANCE becoming the universal laundering purpose."""
        eng = build_engine(Regime.CJIS)
        req = request(purpose=Purpose.SYSTEM_MAINTENANCE)
        assert eng.decide(req).effect is Effect.DENY

    def test_closed_case_blocks_investigation_but_not_disclosure(self):
        eng = build_engine(Regime.CJIS)
        closed = CaseContext(CASE, frozenset({"W-1"}), False)
        assert eng.decide(request(case_context=closed)).effect is Effect.DENY

        d = eng.decide(request(
            case_context=closed,
            purpose=Purpose.DISCLOSURE_PREP,
            principal=principal(roles=frozenset({"disclosure_officer"})),
        ))
        assert d.permitted

    def test_excessive_scope_denied(self):
        eng = build_engine(Regime.CJIS)
        req = request(resource=resource(estimated_element_count=50_000))
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("refine scope" in r for r in d.reasons)


# ---------------------------------------------------------------------------
# Derived data / automated decision controls
# ---------------------------------------------------------------------------

class TestDerivedData:
    def community(self, **kw):
        base = dict(kind=ResourceKind.COMMUNITY, is_derived=True,
                    derivation_complete=True, stability=0.9)
        base.update(kw)
        return resource(**base)

    def test_incomplete_derivation_envelope_denied(self):
        eng = build_engine(Regime.CJIS)
        req = request(action=Action.VIEW_COMMUNITY,
                      resource=self.community(derivation_complete=False))
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("derivation envelope" in r for r in d.reasons)

    def test_missing_stability_score_denied(self):
        eng = build_engine(Regime.CJIS)
        req = request(action=Action.VIEW_COMMUNITY,
                      resource=self.community(stability=None))
        assert eng.decide(req).effect is Effect.DENY

    def test_community_always_carries_hypothesis_framing(self):
        eng = build_engine(Regime.CJIS)
        d = eng.decide(request(action=Action.VIEW_COMMUNITY,
                               resource=self.community()))
        assert d.permitted
        assert Obligation.HYPOTHESIS_FRAMING in d.obligations

    def test_low_stability_is_withheld(self):
        eng = build_engine(Regime.CJIS)
        d = eng.decide(request(action=Action.VIEW_COMMUNITY,
                               resource=self.community(stability=0.4)))
        assert d.permitted
        assert Obligation.WITHHOLD_LOW_STABILITY in d.obligations

    def test_derived_export_blocked_without_human_review(self):
        """LED Art. 11. Prevents an algorithmic cluster flowing into a
        downstream system as though it were an observed fact."""
        eng = build_engine(Regime.GDPR_LED)
        req = request(
            action=Action.EXPORT,
            resource=self.community(human_reviewed=False),
            justification="Exporting network structure for the case file.",
            principal=principal(clearance=Clearance.ENHANCED),
        )
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("human review" in r for r in d.reasons)


# ---------------------------------------------------------------------------
# CJIS-specific
# ---------------------------------------------------------------------------

class TestCJIS:
    def test_remote_access_requires_advanced_auth(self):
        eng = build_engine(Regime.CJIS)
        req = request(principal=principal(from_secure_location=False,
                                          mfa_satisfied=False))
        assert eng.decide(req).effect is Effect.DENY

    def test_sms_otp_rejected_as_advanced_auth(self):
        """SIM-swap and SS7 interception are live threats when the adversary is
        a resourced organised group, not theoretical ones."""
        eng = build_engine(Regime.CJIS)
        req = request(principal=principal(from_secure_location=False,
                                          mfa_method="sms"))
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("does not satisfy advanced authentication" in r
                   for r in d.reasons)

    def test_unknown_authenticator_fails_closed(self):
        eng = build_engine(Regime.CJIS)
        req = request(principal=principal(from_secure_location=False,
                                          mfa_method="magic-beans"))
        assert eng.decide(req).effect is Effect.DENY

    def test_special_clearance_requires_hardware_bound_authenticator(self):
        eng = build_engine(Regime.CJIS)
        req = request(principal=principal(clearance=Clearance.SPECIAL,
                                          mfa_method="totp_hardware"))
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("phishing-resistant" in r for r in d.reasons)

    def test_remote_session_gets_short_reauth_window(self):
        eng = build_engine(Regime.CJIS)
        d = eng.decide(request(principal=principal(from_secure_location=False)))
        assert d.permitted
        assert Obligation.SESSION_REAUTH_15M in d.obligations


# ---------------------------------------------------------------------------
# LED-specific
# ---------------------------------------------------------------------------

class TestLED:
    def test_expired_retention_denies_read(self):
        """Deny at read, delete at batch. Closes the window in which expired
        data is still being served because the nightly job has not run yet."""
        eng = build_engine(Regime.GDPR_LED)
        req = request(resource=resource(past_retention_review=True))
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("retention review date" in r for r in d.reasons)

    def test_tombstoned_records_denied(self):
        eng = build_engine(Regime.GDPR_LED)
        req = request(resource=resource(tombstoned_present=True))
        assert eng.decide(req).effect is Effect.DENY

    def test_special_category_forces_redaction(self):
        eng = build_engine(Regime.GDPR_LED)
        d = eng.decide(request(resource=resource(special_category_present=True)))
        assert d.permitted
        assert Obligation.REDACT_SPECIAL_CATEGORY in d.obligations
        assert Obligation.HIGH_SALIENCE_AUDIT in d.obligations

    def test_subject_access_restricted_to_dpo(self):
        eng = build_engine(Regime.GDPR_LED)
        req = request(purpose=Purpose.DATA_SUBJECT_REQUEST)
        assert eng.decide(req).effect is Effect.DENY

        d = eng.decide(request(purpose=Purpose.DATA_SUBJECT_REQUEST,
                               principal=principal(roles=frozenset({"dpo"}))))
        assert d.permitted

    def test_third_country_data_denied_without_transfer_basis(self):
        eng = build_engine(Regime.GDPR_LED)
        req = request(
            principal=principal(agency="EU:NL"),
            resource=resource(origin_jurisdiction="US"),
        )
        d = eng.decide(req)
        assert d.effect is Effect.DENY
        assert any("Chapter V" in r for r in d.reasons)

    def test_minimisation_floor_always_applies(self):
        eng = build_engine(Regime.GDPR_LED)
        d = eng.decide(request())
        for o in (Obligation.REDACT_PRECISE_DOB,
                  Obligation.REDACT_PLAIN_IDENTIFIERS,
                  Obligation.REDACT_SPECIAL_CATEGORY):
            assert o in d.obligations


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_rule_order_does_not_change_outcome(self):
        """The combination algebra must be order-independent, otherwise a
        refactor that reorders the rule tuple changes security behaviour."""
        from app.security.rules_common import COMMON_RULES
        from app.security.regimes.led import LED_RULES

        req = request(resource=resource(
            subject_categories=frozenset({SubjectCategory.CONTACT})))
        forward = PolicyEngine(Regime.GDPR_LED,
                              tuple(COMMON_RULES) + tuple(LED_RULES))
        reverse = PolicyEngine(Regime.GDPR_LED,
                              tuple(reversed(LED_RULES)) + tuple(reversed(COMMON_RULES)))
        a, b = forward.decide(req), reverse.decide(req)
        assert a.effect is b.effect
        assert a.obligations == b.obligations

    def test_decision_is_pure(self):
        eng = build_engine(Regime.CJIS)
        req = request()
        first = eng.decide(req)
        for _ in range(5):
            again = eng.decide(req)
            assert again.effect is first.effect
            assert again.obligations == first.obligations
