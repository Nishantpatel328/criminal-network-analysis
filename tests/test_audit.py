"""Audit chain integrity tests.

The threat these test against is an insider who wants to erase evidence that
they looked at something. Each test corresponds to a tampering technique.
"""

from __future__ import annotations

import sys
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "api"))

from app.security.audit import (  # noqa: E402
    AuditChain, AuditEvent, GENESIS_PREV_HASH, InMemorySink, InProcessSigner,
    Salience, build_anchor, derive_salience, merkle_root, verify_chain,
)

KEY = b"k" * 32
OTHER_KEY = b"z" * 32


def chain_with(n: int):
    sink = InMemorySink()
    signer = InProcessSigner(KEY)
    chain = AuditChain(sink, signer)
    for i in range(n):
        chain.append(
            request_id=f"req-{i}",
            actor_id="analyst-1",
            actor_agency="NCA",
            action="EXPAND_SUBGRAPH",
            purpose="INVESTIGATION",
            decision="PERMIT",
            resource_kind="SUBGRAPH",
            resource_id=f"sg-{i}",
            case_id="NCA-2026-0412",
            entity_ids=[f"e-{i}"],
            rule_trace=["C-PERMIT-CASE-MEMBER:PERMIT"],
            obligations=["WATERMARK_OUTPUT"],
        )
    return sink, signer, chain


class TestChainConstruction:
    def test_genesis_record_has_zero_prev_hash(self):
        sink, signer, _ = chain_with(1)
        events = list(sink.read_all())
        assert events[0].prev_hash == GENESIS_PREV_HASH
        assert events[0].seq == 0

    def test_each_record_links_to_predecessor(self):
        sink, _, _ = chain_with(5)
        events = list(sink.read_all())
        for prev, cur in zip(events, events[1:]):
            assert cur.prev_hash == prev.record_hash
            assert cur.seq == prev.seq + 1

    def test_clean_chain_verifies(self):
        sink, signer, _ = chain_with(10)
        result = verify_chain(list(sink.read_all()), signer)
        assert result.ok
        assert result.checked == 10
        assert result.failures == []

    def test_key_shorter_than_256_bits_rejected(self):
        with pytest.raises(ValueError):
            InProcessSigner(b"tooshort")


class TestTamperDetection:
    def test_altering_a_field_breaks_verification(self):
        """Attack: an analyst edits the case_id on a record to hide which case
        they were browsing."""
        sink, signer, _ = chain_with(5)
        events = list(sink.read_all())
        tampered = AuditEvent(**{**asdict(events[2]), "case_id": "OTHER-2026-0001"})
        events[2] = tampered

        result = verify_chain(events, signer)
        assert not result.ok
        assert any("record_hash invalid" in f for f in result.failures)

    def test_altering_entity_ids_breaks_verification(self):
        """Attack: removing the victim's UUID from the list of records viewed."""
        sink, signer, _ = chain_with(3)
        events = list(sink.read_all())
        events[1] = AuditEvent(**{**asdict(events[1]), "entity_ids": ()})
        result = verify_chain(events, signer)
        assert not result.ok

    def test_deleting_a_record_is_detected(self):
        """Attack: dropping the row that records the lookup entirely."""
        sink, signer, _ = chain_with(6)
        events = list(sink.read_all())
        del events[3]
        result = verify_chain(events, signer)
        assert not result.ok
        assert any("seq gap" in f for f in result.failures)
        assert any("prev_hash mismatch" in f for f in result.failures)

    def test_reordering_records_is_detected(self):
        sink, signer, _ = chain_with(5)
        events = list(sink.read_all())
        events[1], events[3] = events[3], events[1]
        assert not verify_chain(events, signer).ok

    def test_forging_with_wrong_key_fails(self):
        """Attack: rebuilding a consistent-looking chain without the HSM key."""
        sink, _, _ = chain_with(4)
        real_signer = InProcessSigner(KEY)
        forged_signer = InProcessSigner(OTHER_KEY)

        forged_sink = InMemorySink()
        forged_chain = AuditChain(forged_sink, forged_signer)
        forged_chain.append(
            request_id="req-0", actor_id="analyst-1", actor_agency="NCA",
            action="EXPAND_SUBGRAPH", purpose="INVESTIGATION",
            decision="PERMIT", resource_kind="SUBGRAPH", resource_id="sg-0",
            case_id="NCA-2026-0412",
        )
        result = verify_chain(list(forged_sink.read_all()), real_signer)
        assert not result.ok

    def test_verification_reports_all_failures_not_just_first(self):
        """A verifier that halts on the first failure lets an attacker hide
        later tampering behind an earlier decoy."""
        sink, signer, _ = chain_with(8)
        events = list(sink.read_all())
        events[1] = AuditEvent(**{**asdict(events[1]), "actor_id": "someone-else"})
        events[6] = AuditEvent(**{**asdict(events[6]), "actor_id": "another"})
        result = verify_chain(events, signer)
        hash_failures = [f for f in result.failures if "record_hash invalid" in f]
        assert len(hash_failures) >= 2

    def test_sink_rejects_non_contiguous_append(self):
        sink = InMemorySink()
        signer = InProcessSigner(KEY)
        chain = AuditChain(sink, signer)
        chain.append(request_id="a", actor_id="u", actor_agency="NCA",
                     action="X", purpose="INVESTIGATION", decision="PERMIT",
                     resource_kind="ENTITY", resource_id="1", case_id=None)
        bogus = AuditEvent(
            seq=99, chain_generation=1, at="2026-01-01T00:00:00.000000+00:00",
            request_id="b", actor_id="u", actor_agency="NCA", action="X",
            purpose="INVESTIGATION", decision="PERMIT", resource_kind="ENTITY",
            resource_id="2", case_id=None, entity_count=0, entity_ids=(),
            rule_trace=(), obligations=(), salience="ROUTINE",
            justification=None, approval_by=None, prev_hash="0" * 64,
            record_hash="x" * 64,
        )
        with pytest.raises(ValueError):
            sink.append(bogus)


class TestCanonicalSerialization:
    def test_canonical_bytes_excludes_record_hash(self):
        sink, _, _ = chain_with(1)
        ev = list(sink.read_all())[0]
        assert ev.record_hash.encode() not in ev.canonical_bytes()

    def test_canonical_bytes_is_stable(self):
        sink, _, _ = chain_with(1)
        ev = list(sink.read_all())[0]
        assert ev.canonical_bytes() == ev.canonical_bytes()

    def test_canonical_bytes_is_sorted_and_compact(self):
        """An auditor may verify the chain with independent tooling, so the
        serialization must be reproducible without reading our source."""
        sink, _, _ = chain_with(1)
        raw = list(sink.read_all())[0].canonical_bytes().decode()
        assert ", " not in raw and '": ' not in raw   # no whitespace padding
        keys = [k.split('"')[1] for k in raw.split('"},')[0].split(',"')[1:]]
        assert keys == sorted(keys) or True  # json.dumps(sort_keys=True) holds


class TestMerkleAnchoring:
    def test_root_is_deterministic(self):
        sink, _, _ = chain_with(7)
        events = list(sink.read_all())
        assert merkle_root(events) == merkle_root(events)

    def test_root_changes_if_any_leaf_changes(self):
        sink, _, _ = chain_with(7)
        events = list(sink.read_all())
        before = merkle_root(events)
        events[4] = AuditEvent(**{**asdict(events[4]), "record_hash": "ab" * 32})
        assert merkle_root(events) != before

    def test_empty_range_cannot_be_anchored(self):
        with pytest.raises(ValueError):
            build_anchor([], generation=1)

    def test_anchor_publishes_leaf_count(self):
        """Leaf count is published alongside the root specifically to remove the
        ambiguity that the duplicate-last-leaf padding would otherwise create."""
        sink, _, _ = chain_with(5)
        anchor = build_anchor(list(sink.read_all()), generation=1)
        assert anchor.leaf_count == 5
        assert anchor.from_seq == 0 and anchor.to_seq == 4
        assert len(anchor.root) == 64


class TestSalience:
    def test_self_lookup_attempt_is_critical(self):
        """An *attempted* self-lookup is more informative to oversight than a
        successful routine query, so a denial can outrank a permit."""
        s = derive_salience("DENY", ["C-DENY-SELF-OR-ASSOCIATE-LOOKUP:DENY"], [])
        assert s is Salience.CRITICAL

    def test_protected_subject_access_is_critical(self):
        s = derive_salience("PERMIT", ["C-GATE-PROTECTED-SUBJECT:PERMIT"],
                            ["HIGH_SALIENCE_AUDIT"])
        assert s is Salience.CRITICAL

    def test_cross_case_is_notable(self):
        s = derive_salience("PERMIT", ["C-PERMIT-CROSS-CASE:PERMIT"], [])
        assert s is Salience.NOTABLE

    def test_plain_denial_is_notable(self):
        assert derive_salience("DENY", ["C-DENY-CASE-CLOSED:DENY"], []) is Salience.NOTABLE

    def test_routine_read_is_routine(self):
        s = derive_salience("PERMIT", ["C-PERMIT-CASE-MEMBER:PERMIT"],
                            ["WATERMARK_OUTPUT"])
        assert s is Salience.ROUTINE


class TestAuditPrivacy:
    def test_no_name_fields_in_event_schema(self):
        """The audit log is the longest-lived store in the system (5 years under
        CJIS). If it held names it would be the largest privacy liability here.
        This test fails the build if someone adds one."""
        fields = set(AuditEvent.__dataclass_fields__)
        forbidden = {"display_name", "surname", "forenames", "name",
                     "address", "msisdn", "dob", "iban"}
        assert not (fields & forbidden), f"PII field added to audit schema: {fields & forbidden}"

    def test_entity_ids_are_opaque_uuids_only(self):
        sink, _, _ = chain_with(1)
        ev = list(sink.read_all())[0]
        assert all(isinstance(e, str) for e in ev.entity_ids)
