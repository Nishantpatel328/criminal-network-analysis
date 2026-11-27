"""Tests for the enforcement pipeline.

The PDP tests in test_policy.py prove the *decisions* are right. These prove the
decisions are actually applied, in the right order, and that both outcomes reach
the audit log. A correct PDP wired into a PEP that audits only successes is a
system with no insider-misuse detection.
"""

from __future__ import annotations

import os
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence

import pytest

os.environ.setdefault("CNA_ENV", "test")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "api"))

from app.core.config import Environment, Settings  # noqa: E402
from app.core.pep import (  # noqa: E402
    DEFAULT_EXPANSION_TYPES, PEP, TooExpensive,
)
from app.graph import registry as reg  # noqa: E402
from app.security.audit import (  # noqa: E402
    AuditChain, InMemorySink, InProcessSigner, Salience, verify_chain,
)
from app.security.models import (  # noqa: E402
    Action, CaseContext, Clearance, Obligation, PolicyDenied, Principal,
    Purpose, Regime, Resource, ResourceKind, SubjectCategory,
    UnsupportedObligation,
)
from app.security.policy import PolicyEngine, build_engine, rule  # noqa: E402
from app.security.models import Effect, RuleOutcome  # noqa: E402

CASE = "NCA-2026-0412"
EID = "11111111-2222-3333-4444-555555555555"
FUTURE = date.today() + timedelta(days=365)
NOW = datetime(2026, 9, 8, 10, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Doubles. Honest ones: the store returns rows in the shape the registered
# queries declare, so a projection mismatch shows up here rather than in prod.
# ---------------------------------------------------------------------------

class FakeStore:
    def __init__(self, **responses: List[dict]) -> None:
        self._responses = responses
        self.calls: List[str] = []

    def run(self, spec: reg.QuerySpec, params: Mapping[str, Any], *,
            rel_types: Optional[Sequence[reg.RelType]] = None) -> List[dict]:
        # Bind through the real spec so a test that passes a bad parameter fails
        # here for the same reason production would.
        spec.bind(params)
        if spec.slots:
            reg.render(spec, rel_types=rel_types)
        self.calls.append(spec.name)
        return list(self._responses.get(spec.name, []))


def settings(**over) -> Settings:
    base = dict(
        environment=Environment.TEST,
        regime=Regime.GDPR_LED,
        tenant_id="pilot-force-a",
        neo4j_uri="neo4j://localhost:7687",
        neo4j_database="cna",
    )
    base.update(over)
    return Settings(**base)


def principal(**kw) -> Principal:
    base = dict(
        user_id="analyst-1", agency="NCA", clearance=Clearance.BASIC,
        roles=frozenset(), case_memberships=frozenset({CASE}),
        mfa_satisfied=True, mfa_method="fido2", from_secure_location=True,
        training_current_until=FUTURE,
    )
    base.update(kw)
    return Principal(**base)


def resource(**kw) -> Resource:
    base = dict(
        kind=ResourceKind.SUBGRAPH, resource_id="sg-1", case_id=CASE,
        subject_categories=frozenset({SubjectCategory.SUSPECT}),
        legal_basis_refs=frozenset({"W-1"}), estimated_element_count=50,
    )
    base.update(kw)
    return Resource(**base)


def build(store: Optional[FakeStore] = None, *, engine=None,
          cfg: Optional[Settings] = None):
    sink = InMemorySink()
    chain = AuditChain(sink, InProcessSigner(b"k" * 32))
    cfg = cfg or settings()
    pep = PEP(
        settings=cfg,
        engine=engine or build_engine(cfg.regime),
        store=store or FakeStore(),
        audit=chain,
    )
    return pep, sink, chain


def granted(pep, **over):
    kw = dict(
        principal=principal(), action=Action.EXPAND_SUBGRAPH,
        purpose=Purpose.INVESTIGATION, resource=resource(),
        request_id="req-1", at=NOW,
        case_context=CaseContext(CASE, frozenset({"W-1"}), True),
    )
    kw.update(over)
    return pep.access(**kw)


# ---------------------------------------------------------------------------

class TestRegimeCoherence:

    def test_engine_and_settings_must_agree(self):
        """A CJIS rule pack serving a GDPR/LED tenant enforces the wrong statute
        and stamps the wrong regime on every audit record. Refuse to start."""
        with pytest.raises(ValueError, match="regime mismatch"):
            PEP(
                settings=settings(regime=Regime.GDPR_LED),
                engine=build_engine(Regime.CJIS),
                store=FakeStore(),
                audit=AuditChain(InMemorySink(), InProcessSigner(b"k" * 32)),
            )

    def test_matching_regimes_construct(self):
        pep, _, _ = build(cfg=settings(regime=Regime.CJIS),
                          engine=build_engine(Regime.CJIS))
        assert pep is not None


class TestCostCeiling:

    def test_oversized_request_is_refused_before_the_pdp(self):
        pep, sink, _ = build()
        with pytest.raises(TooExpensive):
            granted(pep, resource=resource(estimated_element_count=100_000))
        # Refused, and recorded. A cost refusal that leaves no trace is a
        # scanning channel: an attacker learns hub degrees for free.
        events = list(sink.read_all())
        assert len(events) == 1
        assert events[0].decision == "DENY"
        assert any("cost ceiling" in t for t in events[0].rule_trace)

    def test_ceiling_is_inclusive_of_the_configured_limit(self):
        pep, _, _ = build()
        d = granted(pep, resource=resource(estimated_element_count=500))
        assert d.permitted

    def test_message_tells_the_analyst_how_to_narrow_it(self):
        pep, _, _ = build()
        try:
            granted(pep, resource=resource(estimated_element_count=99_999))
        except TooExpensive as exc:
            assert "narrow the request" in str(exc)
        else:
            pytest.fail("no refusal")


class TestDenyPathIsAudited:

    def test_denial_is_written_to_the_chain(self):
        pep, sink, _ = build()
        outsider = principal(case_memberships=frozenset({"OTHER-2026-0001"}))
        with pytest.raises(PolicyDenied):
            granted(pep, principal=outsider)
        events = list(sink.read_all())
        assert len(events) == 1
        assert events[0].decision == "DENY"
        assert events[0].actor_id == "analyst-1"
        assert events[0].entity_ids == ()

    def test_self_lookup_denial_is_critical(self):
        """A user probing their own record is the signal oversight most needs,
        and it produces no disclosure — so if only permits were logged it would
        be invisible."""
        pep, sink, _ = build()
        me = principal(linked_entity_ids=frozenset({EID}))
        with pytest.raises(PolicyDenied):
            granted(pep, principal=me,
                    resource=resource(entity_ids=frozenset({EID})))
        assert list(sink.read_all())[0].salience == Salience.CRITICAL.value

    def test_unenforceable_obligation_denies_and_logs_critical(self):
        """A permit carrying an obligation this build cannot apply is not a
        permit. The PEP being older than the policy is an operational
        emergency, not a warning."""

        @rule("TEST-PERMIT-WITH-FUTURE-OBLIGATION")
        def permit_with_unknown(req):
            return RuleOutcome(
                Effect.PERMIT, "TEST-PERMIT-WITH-FUTURE-OBLIGATION", "test",
                obligations=frozenset({Obligation.PROTECTED_SUBJECT_POOL,
                                       Obligation.REDACT_PRECISE_DOB}),
            )

        # Redactor.SUPPORTED covers all current obligations, so simulate a
        # policy/PEP skew by shrinking what the engine is checked against.
        class NarrowPEP(PEP):
            pass

        import app.core.pep as pep_mod
        from app.security.redaction import Redactor
        original = Redactor.SUPPORTED
        try:
            Redactor.SUPPORTED = frozenset({Obligation.REDACT_PRECISE_DOB})
            pep, sink, _ = build(engine=PolicyEngine(Regime.GDPR_LED,
                                                     (permit_with_unknown,)))
            with pytest.raises(UnsupportedObligation):
                granted(pep)
            ev = list(sink.read_all())[0]
            assert ev.decision == "DENY"
            assert ev.salience == Salience.CRITICAL.value
        finally:
            Redactor.SUPPORTED = original

    def test_chain_stays_verifiable_across_mixed_outcomes(self):
        pep, sink, _ = build(FakeStore())
        outsider = principal(case_memberships=frozenset({"OTHER-2026-0001"}))
        for _ in range(2):
            with pytest.raises(PolicyDenied):
                granted(pep, principal=outsider)
        d = granted(pep)
        pep.complete(
            decision=d, principal=principal(), action=Action.EXPAND_SUBGRAPH,
            purpose=Purpose.INVESTIGATION, resource=resource(),
            records=[{"eid": EID, "labels": ["Person"],
                      "subject_category": "SUSPECT", "display_name": "A B"}],
            kind="entity", at=NOW,
        )
        result = verify_chain(list(sink.read_all()), InProcessSigner(b"k" * 32))
        assert result.ok, result.failures
        assert result.checked == 3


class TestDisclosureAudit:

    def _complete(self, pep, records, kind="entity", **over):
        d = granted(pep)
        kw = dict(
            decision=d, principal=principal(), action=Action.EXPAND_SUBGRAPH,
            purpose=Purpose.INVESTIGATION, resource=resource(),
            records=records, kind=kind, at=NOW,
        )
        kw.update(over)
        return pep.complete(**kw)

    def test_audits_what_was_released_not_what_was_asked_for(self):
        pep, sink, _ = build()
        res = self._complete(pep, [
            {"eid": EID, "labels": ["Person"], "subject_category": "SUSPECT",
             "display_name": "A B"},
        ])
        ev = [e for e in sink.read_all() if e.decision == "PERMIT"][-1]
        assert ev.entity_ids == (EID,)
        assert ev.entity_count == 1
        assert res.audit_seq == ev.seq

    def test_obligations_are_recorded_on_the_disclosure(self):
        pep, sink, _ = build()
        self._complete(pep, [{"eid": EID, "labels": ["Person"],
                              "subject_category": "SUSPECT"}])
        ev = [e for e in sink.read_all() if e.decision == "PERMIT"][-1]
        assert "WATERMARK_OUTPUT" in ev.obligations
        assert "REDACT_PLAIN_IDENTIFIERS" in ev.obligations

    def test_plain_identifiers_never_reach_the_payload(self):
        pep, _, _ = build()
        res = self._complete(pep, [{
            "eid": EID, "labels": ["Person"], "subject_category": "SUSPECT",
            "display_name": "A B",
            # Fields a careless query widening would introduce.
            "msisdn_plain": "+447700900000",
            "ni_number": "QQ123456C",
            "ethnicity": "REDACTED-CATEGORY",
            "surrogate_key": "ABCDEFGH",
        }])
        blob = repr(res.records)
        for leak in ("447700900000", "QQ123456C", "REDACTED-CATEGORY",
                     "ABCDEFGH"):
            assert leak not in blob, f"{leak} escaped the projection"

    def test_watermark_names_the_actor_and_the_case(self):
        pep, _, _ = build()
        res = self._complete(pep, [{"eid": EID, "labels": ["Person"],
                                    "subject_category": "SUSPECT"}])
        assert res.watermark is not None
        assert res.watermark["actor"] == "analyst-1"
        assert res.watermark["case"] == CASE

    def test_payload_tells_the_client_something_was_redacted(self):
        """Silent redaction teaches analysts the graph is complete. An analyst
        who knows a field is withheld can seek authority for it."""
        pep, _, _ = build()
        res = self._complete(pep, [{
            "eid": EID, "labels": ["Person"], "subject_category": "SUSPECT",
            "msisdn_plain": "+447700900000",
        }])
        payload = res.to_payload()
        assert payload["disclosure"]["fields_redacted"] >= 1
        assert payload["regime"] == "gdpr_led"

    def test_disclosure_block_reports_counts_not_field_names(self):
        """A field name is itself a disclosure: 'health_notes redacted' says the
        subject has health notes."""
        pep, _, _ = build()
        res = self._complete(pep, [{
            "eid": EID, "labels": ["Person"], "subject_category": "SUSPECT",
            "health_notes": "x", "msisdn_plain": "+447700900000",
        }])
        block = repr(res.to_payload()["disclosure"])
        assert "health_notes" not in block
        assert "msisdn" not in block

    def test_unknown_projection_kind_raises(self):
        pep, _, _ = build()
        with pytest.raises(ValueError, match="unknown projection kind"):
            self._complete(pep, [{"eid": EID}], kind="everything")

    def test_unevaluated_edge_is_refused(self):
        """The redactor refuses to emit a relationship with no 5x5x5 grading.
        An ungraded edge rendered at full strength is the analyst reading
        uncorroborated hearsay as fact."""
        pep, _, _ = build()
        with pytest.raises(ValueError):
            self._complete(pep, [{"type": "ASSOCIATE_OF", "weight": 1.0}],
                           kind="relationship")

    def test_graded_edge_passes(self):
        pep, _, _ = build()
        res = self._complete(pep, [{
            "type": "ASSOCIATE_OF", "weight": 1.0,
            "source_eval": 2, "intel_assessment": 2, "handling_code": 1,
        }], kind="relationship")
        assert res.records[0]["source_eval"] == 2

    def test_neighbourhood_rels_are_projected_as_edges(self):
        """Q_NEIGHBOURHOOD returns nested `rels`. Dropping them at the entity
        whitelist would leave the workstation with a bag of nodes and no
        drawable connections."""
        pep, _, _ = build()
        other = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        res = self._complete(pep, [{
            "eid": other, "labels": ["Person"], "subject_category": "SUSPECT",
            "rels": [{
                "type": "ASSOCIATE_OF",
                "source_eval": 1, "intel_assessment": 2, "handling_code": 1,
                "weight": 3.0, "basis": "W-1",
                "src": EID, "dst": other,
                "msisdn_plain": "+447700900000",
            }],
        }])
        rec = res.records[0]
        assert "rels" not in rec
        assert rec["edges"][0]["src"] == EID
        assert rec["edges"][0]["dst"] == other
        assert "msisdn_plain" not in rec["edges"][0]


class TestFactGathering:

    def test_case_context_comes_from_the_store(self):
        pep, _, _ = build(FakeStore(case_context=[{
            "case_id": CASE, "is_open": True,
            "authorised_bases": ["W-1", "W-2"],
            "supervisor_ids": ["dsu-9"],
        }]))
        ctx = pep.case_context(CASE)
        assert ctx is not None
        assert ctx.authorised_bases == frozenset({"W-1", "W-2"})
        assert ctx.supervisor_ids == frozenset({"dsu-9"})

    def test_missing_case_returns_none_rather_than_a_permissive_default(self):
        pep, _, _ = build(FakeStore())
        assert pep.case_context(CASE) is None

    def test_survey_runs_before_the_expansion(self):
        pep, _, _ = build(FakeStore(subject_categories_in_scope=[{
            "categories": ["SUSPECT", "VICTIM"], "element_count": 42,
        }]))
        count, cats = pep.survey_expansion(EID, ["W-1"], DEFAULT_EXPANSION_TYPES)
        assert count == 42
        assert SubjectCategory.VICTIM in cats

    def test_unknown_category_is_treated_as_the_most_protected(self):
        """A schema addition must fail closed. Defaulting an unrecognised
        category to 'fair game' is how a new protected category gets disclosed
        for the length of one deploy cycle."""
        pep, _, _ = build(FakeStore(subject_categories_in_scope=[{
            "categories": ["SUSPECT", "INFORMANT"], "element_count": 3,
        }]))
        _, cats = pep.survey_expansion(EID, ["W-1"], DEFAULT_EXPANSION_TYPES)
        assert SubjectCategory.VICTIM in cats

    def test_appears_in_is_not_traversable_by_analysts(self):
        """APPEARS_IN is the case-membership edge. Traversing it would let an
        analyst hop from an entity into every other case that entity is in —
        exactly what case scoping exists to prevent."""
        assert reg.RelType.APPEARS_IN not in DEFAULT_EXPANSION_TYPES

    def test_survey_binds_through_the_real_query_spec(self):
        store = FakeStore(subject_categories_in_scope=[])
        pep, _, _ = build(store)
        pep.survey_expansion(EID, ["W-1"], DEFAULT_EXPANSION_TYPES)
        assert store.calls == ["subject_categories_in_scope"]

    def test_survey_rejects_a_malformed_eid(self):
        pep, _, _ = build(FakeStore())
        with pytest.raises(ValueError):
            pep.survey_expansion("not-a-uuid", ["W-1"], DEFAULT_EXPANSION_TYPES)
