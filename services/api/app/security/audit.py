"""Tamper-evident audit log.

WHAT THIS GUARANTEES, PRECISELY
Hash chaining plus HMAC plus external anchoring gives *detection* of tampering.
It does not give prevention. "Immutable audit log" is routinely overclaimed and
the distinction matters when someone asks what the log is worth in court.

An adversary holding the HMAC key AND write access to the store can rewrite
history into a self-consistent chain. What they cannot do is make the rewritten
history agree with root hashes already published to an external anchor. So the
honest statement is:

  - Modifying any record already covered by a published anchor is DETECTABLE by
    anyone holding the anchor, without trusting this system.
  - Modifying records since the last anchor requires the HMAC key (in the HSM).
  - Deleting records is detectable by sequence gap and by chain break.
  - Appending false records going forward requires the HMAC key.

Combined with object-lock retention on the bucket and the Z2-can-append-but-not-
read invariant, tampering requires compromising three separately-credentialed
systems and defeating an external anchor. That is a defensible position. Claiming
immutability would not be.

PRIVACY OF THE LOG ITSELF
The audit log is retained for five years under CJIS, which makes it the
longest-lived store in the system. If it contained names it would be the single
largest privacy liability here. So it records internal entity UUIDs and counts,
never names, addresses or contact identifiers. Reconstructing "who did the
analyst look at" requires joining the log against the graph, which is an audited
operation in its own right.

The one genuine leak is `justification`: free text typed by a human, who may well
type a name into it. Accepted, recorded as R-11 in the threat model, mitigated by
(a) UI guidance not to include personal data, (b) the justification field being
readable only by oversight roles, and (c) it inheriting the graph's retention
clock rather than the log's where the two differ.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

GENESIS_PREV_HASH = "0" * 64


class Salience(enum.Enum):
    """How loudly this event should be surfaced to oversight.

    ROUTINE events are searchable. NOTABLE events appear on the supervisor's
    daily digest. CRITICAL events page the DPO. The distinction exists because
    an audit log where everything is equally important is an audit log nobody
    reads, which is the normal outcome.
    """
    ROUTINE = "ROUTINE"
    NOTABLE = "NOTABLE"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class AuditEvent:
    """One append-only record.

    Field order is part of the canonical serialization contract. Reordering,
    adding or removing a field changes every subsequent hash, so schema changes
    require a chain generation bump (see `chain_generation`) rather than an
    in-place migration. This is deliberate: a log whose format can be silently
    changed is a log whose history can be silently rewritten.
    """
    seq: int
    chain_generation: int
    at: str                      # RFC3339, UTC, microsecond precision
    request_id: str
    actor_id: str
    actor_agency: str
    action: str
    purpose: str
    decision: str                # PERMIT | DENY
    resource_kind: str
    resource_id: str
    case_id: Optional[str]
    entity_count: int
    entity_ids: Tuple[str, ...]  # internal UUIDs only, never names
    rule_trace: Tuple[str, ...]
    obligations: Tuple[str, ...]
    salience: str
    justification: Optional[str]
    approval_by: Optional[str]
    prev_hash: str
    record_hash: str = ""        # filled by the chain on append

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization for hashing.

        `record_hash` is excluded — it is the output. Sorted keys and separators
        with no whitespace make this stable across Python versions and across
        any reimplementation, which matters because an auditor may well verify
        the chain with their own tooling.
        """
        d = asdict(self)
        d.pop("record_hash", None)
        d["entity_ids"] = list(self.entity_ids)
        d["rule_trace"] = list(self.rule_trace)
        d["obligations"] = list(self.obligations)
        return json.dumps(
            d, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


class Signer(Protocol):
    """Abstracts the HSM/KMS. Production uses PKCS#11 or a cloud KMS; the key
    never enters this process. The in-process implementation below exists for
    tests only and says so loudly."""

    def mac(self, data: bytes) -> str: ...


class InProcessSigner:
    """TEST ONLY. Holds the key in memory, which defeats the purpose.

    Production must use HsmSigner. `assert_production_safe()` in
    services/api/app/core/config.py is called from the constructor below and
    fails instantiation outside a development or test environment — a check worth
    having, because a test double that reaches production is a classic and quiet
    failure. It is quiet specifically because everything works: the chain
    verifies against its own in-memory key, and the problem is invisible until
    someone with process memory access rewrites history self-consistently.
    """

    def __init__(self, key: bytes,
                 env: Optional[Mapping[str, str]] = None) -> None:
        from ..core.config import assert_production_safe
        assert_production_safe("InProcessSigner", env)
        if len(key) < 32:
            raise ValueError("audit MAC key must be at least 256 bits")
        self._key = key

    def mac(self, data: bytes) -> str:
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()


class AuditSink(Protocol):
    """Append-only destination. Production: object-lock bucket + WORM stream."""

    def append(self, event: AuditEvent) -> None: ...
    def read_all(self) -> Iterable[AuditEvent]: ...
    def head(self) -> Optional[AuditEvent]: ...


class InMemorySink:
    """Test sink. Enforces append-only semantics so tests exercise the real
    contract rather than a permissive stand-in."""

    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        if self._events and event.seq != self._events[-1].seq + 1:
            raise ValueError(
                f"non-contiguous append: expected seq "
                f"{self._events[-1].seq + 1}, got {event.seq}"
            )
        self._events.append(event)

    def read_all(self) -> Iterable[AuditEvent]:
        return tuple(self._events)

    def head(self) -> Optional[AuditEvent]:
        return self._events[-1] if self._events else None


class AuditChain:
    """Appends events, maintaining the hash chain."""

    def __init__(self, sink: AuditSink, signer: Signer,
                 chain_generation: int = 1) -> None:
        self._sink = sink
        self._signer = signer
        self._generation = chain_generation

    def append(
        self,
        *,
        request_id: str,
        actor_id: str,
        actor_agency: str,
        action: str,
        purpose: str,
        decision: str,
        resource_kind: str,
        resource_id: str,
        case_id: Optional[str],
        entity_ids: Sequence[str] = (),
        rule_trace: Sequence[str] = (),
        obligations: Sequence[str] = (),
        salience: Salience = Salience.ROUTINE,
        justification: Optional[str] = None,
        approval_by: Optional[str] = None,
        at: Optional[datetime] = None,
    ) -> AuditEvent:
        head = self._sink.head()
        seq = (head.seq + 1) if head else 0
        prev_hash = head.record_hash if head else GENESIS_PREV_HASH
        when = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)

        draft = AuditEvent(
            seq=seq,
            chain_generation=self._generation,
            at=when.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
            request_id=request_id,
            actor_id=actor_id,
            actor_agency=actor_agency,
            action=action,
            purpose=purpose,
            decision=decision,
            resource_kind=resource_kind,
            resource_id=resource_id,
            case_id=case_id,
            entity_count=len(entity_ids),
            entity_ids=tuple(entity_ids),
            rule_trace=tuple(rule_trace),
            obligations=tuple(sorted(obligations)),
            salience=salience.value,
            justification=justification,
            approval_by=approval_by,
            prev_hash=prev_hash,
        )
        record_hash = self._signer.mac(draft.canonical_bytes())
        sealed = AuditEvent(**{**asdict(draft),
                               "entity_ids": draft.entity_ids,
                               "rule_trace": draft.rule_trace,
                               "obligations": draft.obligations,
                               "record_hash": record_hash})
        self._sink.append(sealed)
        return sealed


@dataclass
class VerificationResult:
    ok: bool
    checked: int
    failures: List[str] = field(default_factory=list)


def verify_chain(events: Sequence[AuditEvent], signer: Signer) -> VerificationResult:
    """Recompute the whole chain. Reports every failure, not just the first.

    Stopping at the first failure would let an attacker who breaks record 5 hide
    what they did to record 900, since a verifier that halts early never looks.
    """
    failures: List[str] = []
    expected_prev = GENESIS_PREV_HASH

    for i, ev in enumerate(events):
        if ev.seq != i:
            failures.append(f"seq gap at index {i}: record claims seq {ev.seq}")
        if ev.prev_hash != expected_prev:
            failures.append(
                f"seq {ev.seq}: prev_hash mismatch "
                f"(expected {expected_prev[:12]}…, got {ev.prev_hash[:12]}…)"
            )
        recomputed = signer.mac(ev.canonical_bytes())
        if not hmac.compare_digest(recomputed, ev.record_hash):
            failures.append(f"seq {ev.seq}: record_hash invalid — record altered")
        expected_prev = ev.record_hash

    return VerificationResult(ok=not failures, checked=len(events), failures=failures)


def merkle_root(events: Sequence[AuditEvent]) -> str:
    """Root over record hashes, for hourly external anchoring.

    Duplicates the last leaf on odd levels. That is the standard approach and it
    carries the known second-preimage caveat for unbalanced trees; it is
    acceptable here because leaf count is published alongside the root, which
    removes the ambiguity an attacker would need to exploit.
    """
    if not events:
        return GENESIS_PREV_HASH
    level = [bytes.fromhex(e.record_hash) for e in events]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


@dataclass(frozen=True)
class Anchor:
    """Published hourly to an external notary (RFC 3161 TSA, or a transparency
    log). The anchor is what makes tampering detectable by someone who does not
    trust this system, which is the only kind of detection worth much."""
    generation: int
    from_seq: int
    to_seq: int
    leaf_count: int
    root: str
    anchored_at: str


def build_anchor(events: Sequence[AuditEvent], generation: int) -> Anchor:
    if not events:
        raise ValueError("cannot anchor an empty range")
    return Anchor(
        generation=generation,
        from_seq=events[0].seq,
        to_seq=events[-1].seq,
        leaf_count=len(events),
        root=merkle_root(events),
        anchored_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
    )


# ---------------------------------------------------------------------------
# Salience derivation
# ---------------------------------------------------------------------------

_CRITICAL_RULES = frozenset({
    "C-DENY-SELF-OR-ASSOCIATE-LOOKUP",
    "C-GATE-PROTECTED-SUBJECT",
    "LED-DENY-THIRD-COUNTRY-TRANSFER",
    "CJIS-DENY-WEAK-AUTH-FOR-SPECIAL",
})

_NOTABLE_RULES = frozenset({
    "C-PERMIT-CROSS-CASE",
    "LED-GATE-PURPOSE-COMPATIBILITY",
    "LED-PERMIT-DATA-SUBJECT-REQUEST",
    "CJIS-DENY-CROSS-AGENCY-WITHOUT-MCA",
    "C-PERMIT-AUDIT-OVERSIGHT",
})


def derive_salience(decision_effect: str, rule_trace: Sequence[str],
                    obligations: Sequence[str]) -> Salience:
    """Map a decision onto an oversight urgency.

    Any denial involving self-lookup is CRITICAL regardless of outcome: a user
    *attempting* to look up their own family is exactly the signal an oversight
    function needs, and it is more informative than a successful routine query.
    """
    fired = {t.split(":")[0] for t in rule_trace}
    if fired & _CRITICAL_RULES:
        return Salience.CRITICAL
    if "HIGH_SALIENCE_AUDIT" in obligations or (fired & _NOTABLE_RULES):
        return Salience.NOTABLE
    if decision_effect == "DENY":
        return Salience.NOTABLE
    return Salience.ROUTINE
