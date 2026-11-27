"""Policy Enforcement Point — the fixed order of operations.

WHY THIS IS ONE FILE AND NOT SPREAD ACROSS HANDLERS
Every access in this system must do the same seven things in the same order:

    1. Gather facts about the resource from the store (NOT from the request body)
    2. Cost the query and refuse if it exceeds the ceiling
    3. Decide (PDP)
    4. Enforce: permit, and every obligation actually enforceable here
    5. Execute the registered query
    6. Redact according to the obligations
    7. Audit — on the permit path AND the deny path

Get the order wrong and the controls stop working while still appearing to be
present. Decide before gathering facts and the PDP reasons about client-supplied
attributes. Audit before executing and the log records intent rather than
disclosure. Redact after audit and the log understates what was released. Cost
after deciding and a permitted request can still take the cluster down.

So the order lives in exactly one function, `PEP.access()`, and route handlers
cannot express any other order. A handler that wants to skip a step has to edit
this file, which is a reviewable act. A handler that could simply forget a step
is a handler that eventually will.

WHAT IS NOT HERE
No framework imports. This module is pure Python over protocols, which is what
makes the deny paths exhaustively testable without standing up a web server or a
database. The FastAPI layer in app/routers/ is a thin adapter over it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any, Dict, FrozenSet, List, Mapping, Optional, Protocol, Sequence, Tuple,
)

from ..graph import registry as reg
from ..security.audit import AuditChain, Salience, derive_salience
from ..security.models import (
    AccessRequest,
    Action,
    CaseContext,
    Clearance,
    Decision,
    Obligation,
    PolicyDenied,
    Principal,
    Purpose,
    Regime,
    Resource,
    ResourceKind,
    SubjectCategory,
    UnsupportedObligation,
)
from ..security.policy import PolicyEngine, enforce
from ..security.redaction import RedactionReport, Redactor
from .config import Settings

logger = logging.getLogger(__name__)


class TooExpensive(Exception):
    """The request would touch more of the graph than the ceiling allows.

    Both a DoS guard and an anti-bulk-disclosure control. The two are the same
    control viewed from different directions: "this query would read a million
    nodes" is a resource problem and a proportionality problem at once, and
    Art. 5(1)(c) data minimisation is not satisfied by a query that returns the
    whole network because the analyst clicked a hub.
    """

    def __init__(self, estimated: int, ceiling: int):
        self.estimated, self.ceiling = estimated, ceiling
        super().__init__(
            f"query would touch ~{estimated} elements, ceiling is {ceiling}; "
            f"narrow the request (add a relationship-type filter, reduce depth, "
            f"or start from a less connected entity)"
        )


class GraphStore(Protocol):
    """Everything the PEP needs from Neo4j, as a protocol.

    Deliberately narrow. A protocol this small is a protocol a test double can
    implement honestly, and the deny paths are the paths that most need testing
    against an honest double rather than a mock that returns whatever the test
    wants.
    """

    def run(self, spec: reg.QuerySpec, params: Mapping[str, Any], *,
            rel_types: Optional[Sequence[reg.RelType]] = None) -> List[dict]: ...


class Crosswalk(Protocol):
    """The surrogate → entity mapping. Z2 only, envelope-encrypted at rest.

    Returns None for an unknown surrogate rather than raising, because the caller
    must not be able to distinguish "not in this snapshot" from "error" — that
    distinction, queried repeatedly, is a read of the crosswalk's key set.
    """

    def to_entity(self, snapshot_id: str, surrogate: str) -> Optional[str]: ...


@dataclass(frozen=True)
class AccessResult:
    """What a permitted access produced."""
    records: Tuple[dict, ...]
    obligations: FrozenSet[Obligation]
    decision: Decision
    report: RedactionReport
    watermark: Optional[Dict[str, str]] = None
    audit_seq: int = -1
    truncated: bool = False

    def to_payload(self) -> Dict[str, Any]:
        """Response body. Obligation metadata is included on purpose.

        The client is told what was redacted and why. A UI that silently shows a
        partial graph teaches analysts that the graph is complete, and that
        mislearning is worse than the redaction itself — an analyst who knows a
        node is withheld can seek authority for it; one who does not know reaches
        a conclusion from data they believe to be whole.
        """
        return {
            "records": list(self.records),
            "disclosure": {
                # Counts, not field names. Telling the client that
                # `health_notes` was redacted discloses that the subject has
                # health notes, which is the thing the redaction was for. See
                # RedactionReport's docstring.
                "fields_redacted": self.report.fields_redacted,
                "fields_withheld": self.report.fields_withheld,
                "notes": list(self.report.notes),
                "obligations_applied": sorted(o.value for o in self.obligations),
                "truncated": self.truncated,
            },
            "watermark": self.watermark,
            "audit_seq": self.audit_seq,
            "regime": self.decision.regime.value,
        }


# Relationship types permitted in an analyst-facing expansion. APPEARS_IN is
# excluded: it is the case-membership edge, and traversing it would let an analyst
# hop from an entity into every other case that entity appears in — a lateral
# move across case boundaries that the case-scope predicate is there to prevent.
DEFAULT_EXPANSION_TYPES: Tuple[reg.RelType, ...] = (
    reg.RelType.COMMUNICATED_WITH,
    reg.RelType.ASSOCIATE_OF,
    reg.RelType.TRANSACTED_WITH,
    reg.RelType.USES_PHONE,
    reg.RelType.HOLDS_ACCOUNT,
    reg.RelType.REGISTERED_TO,
    reg.RelType.PRESENT_AT,
)


class PEP:
    """Wires the PDP, the query registry, the redactor and the audit chain."""

    def __init__(self, *, settings: Settings, engine: PolicyEngine,
                 store: GraphStore, audit: AuditChain,
                 crosswalk: Optional["Crosswalk"] = None,
                 community_store: Any = None) -> None:
        if engine.regime is not settings.regime:
            # A PDP loaded with the CJIS pack while the tenant is configured as
            # GDPR/LED would enforce the wrong statute and log the wrong regime.
            # Refuse to start rather than serve one request under the wrong law.
            raise ValueError(
                f"regime mismatch: settings say {settings.regime.value}, "
                f"policy engine was built for {engine.regime.value}"
            )
        self._settings = settings
        self._engine = engine
        self._store = store
        self._audit = audit
        self._crosswalk = crosswalk
        self.community_store = community_store

    # -- step 1 -------------------------------------------------------------

    def case_context(self, case_id: str) -> Optional[CaseContext]:
        """Fetch case metadata. Never accepted from the client.

        A client-supplied `authorised_bases` would let a caller assert the legal
        basis that authorises their own access, which is the entire control
        inverted.
        """
        rows = self._store.run(reg.Q_CASE_CONTEXT, {"case_id": case_id})
        if not rows:
            return None
        row = rows[0]
        return CaseContext(
            case_id=row["case_id"],
            authorised_bases=frozenset(row.get("authorised_bases") or ()),
            is_open=bool(row.get("is_open")),
            supervisor_ids=frozenset(row.get("supervisor_ids") or ()),
        )

    def survey_expansion(self, eid: str, bases: Sequence[str],
                         rel_types: Sequence[reg.RelType]) -> Tuple[int, FrozenSet[SubjectCategory]]:
        """Which categories an expansion would touch, and how big it would be.

        Run BEFORE the expansion so the PDP reasons about the whole envelope.
        Checking per-record as results stream back means discovering a victim
        record after it has already been read out of the database and, in a
        streaming response, possibly after it has been sent.
        """
        rows = self._store.run(
            reg.Q_SUBJECT_CATEGORIES_IN_SCOPE,
            {"eid": eid, "bases": list(bases)},
            rel_types=rel_types,
        )
        if not rows:
            return 0, frozenset()
        row = rows[0]
        cats = set()
        for raw in (row.get("categories") or ()):
            try:
                cats.add(SubjectCategory(raw))
            except ValueError:
                # An unrecognised category is not a reason to proceed. Treat it as
                # the most protected value we have, so a schema addition fails
                # closed instead of defaulting an unknown category to "fair game".
                logger.warning("unknown subject_category %r; treating as VICTIM", raw)
                cats.add(SubjectCategory.VICTIM)
        return int(row.get("element_count") or 0), frozenset(cats)

    # -- step 5 -------------------------------------------------------------

    def peek_entity(self, eid: str, case_id: str) -> List[dict]:
        """Read one entity's attributes so the PDP can reason about it.

        This is a pre-decision read, which needs justifying. It is bounded to a
        single node already inside case scope, it returns nothing to the caller,
        and its only consumer is the Resource envelope handed to the PDP. The
        alternative — asking the client for the subject category — would let a
        caller declare a victim record to be a suspect record and have the policy
        agree.

        It is a named method rather than a raw store call so that this reasoning
        sits next to the one place it applies, instead of every handler being free
        to read whatever it likes before deciding.
        """
        return self._store.run(reg.Q_ENTITY_BY_EID,
                               {"eid": eid, "case_id": case_id})

    def query(self, decision: Decision, spec: reg.QuerySpec,
              params: Mapping[str, Any], *,
              rel_types: Optional[Sequence[reg.RelType]] = None) -> List[dict]:
        """Execute a registered query, but only against a permitting decision.

        Taking the Decision as a parameter is the point. A handler cannot reach
        the store without one in hand, so "query first, check later" is not
        expressible — and the store stays private rather than being poked at
        through `pep._store`, which is the access pattern that quietly turns into
        an unchecked read six months from now.
        """
        if not decision.permitted:
            raise PolicyDenied(decision)
        return self._store.run(spec, params, rel_types=rel_types)

    # -- the pipeline -------------------------------------------------------

    def access(
        self,
        *,
        principal: Principal,
        action: Action,
        purpose: Purpose,
        resource: Resource,
        request_id: str,
        justification: Optional[str] = None,
        approval_by: Optional[str] = None,
        case_context: Optional[CaseContext] = None,
        at: Optional[datetime] = None,
    ) -> Decision:
        """Steps 2-4 and the deny-path audit. Returns the permitting decision.

        Callers get the decision back and then execute + redact + audit through
        `complete()`. Splitting it this way is what lets the expensive query sit
        between the permit and the disclosure audit record without either being
        skippable.
        """
        when = at or datetime.now(timezone.utc)
        request = AccessRequest(
            principal=principal,
            action=action,
            resource=resource,
            purpose=purpose,
            request_id=request_id,
            at=when,
            justification=justification,
            case_context=case_context,
            approval_by=approval_by,
        )

        # step 2: cost ceiling, before the PDP. A permitted request that reads a
        # million nodes is still an outage and still a bulk disclosure.
        if resource.estimated_element_count > self._settings.max_expansion_elements:
            self._audit_denial(
                request,
                reason=f"cost ceiling: ~{resource.estimated_element_count} elements",
            )
            raise TooExpensive(resource.estimated_element_count,
                               self._settings.max_expansion_elements)

        # step 3: decide
        decision = self._engine.decide(request)

        # step 4: enforce, including obligation enforceability
        try:
            enforce(decision, Redactor.SUPPORTED)
        except PolicyDenied:
            self._audit_denial(request, decision=decision)
            raise
        except UnsupportedObligation as exc:
            # A permit whose obligations this build cannot honour is not a permit.
            # Logged as a denial because that is what happened to the request, and
            # as CRITICAL because it means the PEP is older than the policy.
            logger.error("PEP cannot honour obligations %s; failing closed",
                         sorted(o.value for o in exc.missing))
            self._audit_denial(
                request, decision=decision,
                reason="enforcement point cannot honour required obligations",
                salience=Salience.CRITICAL,
            )
            raise

        return decision

    def complete(
        self,
        *,
        decision: Decision,
        principal: Principal,
        action: Action,
        purpose: Purpose,
        resource: Resource,
        records: Sequence[dict],
        kind: str,
        justification: Optional[str] = None,
        approval_by: Optional[str] = None,
        at: Optional[datetime] = None,
    ) -> AccessResult:
        """Steps 6-7: redact, then audit what was actually disclosed.

        `kind` selects the redactor projection: "entity", "relationship" or
        "community". It is not derived from the record shape — guessing the
        projection from the keys present would mean a record missing a field gets
        a different, possibly wider, whitelist applied to it.
        """
        when = at or datetime.now(timezone.utc)
        redactor = Redactor(decision.obligations)

        out: List[dict] = []
        redacted = 0
        withheld = 0
        notes: List[str] = []

        # MINIMISE_TO_DEGREE_1 is applied here rather than in the query because
        # it is an obligation the PDP may or may not attach; baking it into the
        # Cypher would apply it unconditionally and silently narrow every result.
        limit = len(records)
        truncated = False
        if Obligation.MINIMISE_TO_DEGREE_1 in decision.obligations:
            limit = min(limit, self._settings.max_expansion_elements)

        for record in records[:limit]:
            if kind == "entity":
                projected, report = redactor.entity(record)
            elif kind == "community":
                projected, report = redactor.community(record)
            elif kind == "relationship":
                projected, report = redactor.relationship(record), None
            else:
                raise ValueError(f"unknown projection kind {kind!r}")
            out.append(projected)
            if report is not None:
                redacted += report.fields_redacted
                withheld += report.fields_withheld
                for n in report.notes:
                    if n not in notes:
                        notes.append(n)
        truncated = limit < len(records)

        watermark = redactor.watermark(
            principal.user_id,
            resource.case_id or "NO-CASE",
            when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

        # step 7: audit the disclosure, with the entity ids actually released.
        # Recording the requested set rather than the released set would overstate
        # disclosure; recording nothing would understate it. Neither is auditable.
        released = tuple(
            str(r.get("eid") or r.get("community_id") or "")
            for r in out if (r.get("eid") or r.get("community_id"))
        )
        event = self._audit.append(
            request_id=decision.request_id,
            actor_id=principal.user_id,
            actor_agency=principal.agency,
            action=action.value,
            purpose=purpose.value,
            decision="PERMIT",
            resource_kind=resource.kind.value,
            resource_id=resource.resource_id,
            case_id=resource.case_id,
            entity_ids=released,
            rule_trace=decision.rule_trace,
            obligations=tuple(o.value for o in decision.obligations),
            salience=derive_salience(
                "PERMIT", decision.rule_trace,
                tuple(o.value for o in decision.obligations),
            ),
            justification=justification,
            approval_by=approval_by,
            at=when,
        )

        if redactor.notify_supervisor:
            # Fire-and-forget in the scaffold. In production this is an outbox
            # row written in the same transaction as the audit append, because a
            # notification that can be lost is a notification that will be, and
            # "the supervisor was told" is a claim the system has to be able to
            # substantiate.
            logger.info("SUPERVISOR_NOTIFY queued for audit seq %s", event.seq)

        return AccessResult(
            records=tuple(out),
            obligations=decision.obligations,
            decision=decision,
            report=RedactionReport(
                fields_redacted=redacted,
                fields_withheld=withheld,
                notes=tuple(notes),
            ),
            watermark=watermark,
            audit_seq=event.seq,
            truncated=truncated,
        )

    # -- derived data -------------------------------------------------------

    def reidentify(self, decision: Decision, snapshot_id: str,
                   surrogates: Sequence[str]) -> List[dict]:
        """Cross the pseudonymity boundary. Requires a permitting decision.

        This is the one operation that undoes the design's central privacy
        property, so it is the one operation with the most conditions on it: a
        REIDENTIFY permit, a written justification, a capped batch, and its own
        audit record distinct from the community read that preceded it.

        Unresolved surrogates are dropped silently from the result and reported
        only as a count by the caller. Naming them would tell a caller which
        surrogates are absent from this snapshot's crosswalk, and enough such
        queries enumerate the crosswalk's key set.
        """
        if not decision.permitted:
            raise PolicyDenied(decision)
        if self._crosswalk is None:
            raise RuntimeError("no crosswalk configured; re-identification "
                               "is unavailable in this deployment")
        if len(surrogates) > 100:
            # Also enforced by the request schema. Duplicated here because the
            # schema protects the HTTP path and this protects every path.
            raise ValueError("re-identification batch exceeds 100 surrogates")

        out: List[dict] = []
        for s in surrogates:
            eid = self._crosswalk.to_entity(snapshot_id, s)
            if eid is None:
                continue
            # Only the identifier. Attribute fetch is deliberately NOT done here:
            # this operation answers "which entity is this surrogate", and
            # nothing more. The caller reads attributes through the entity
            # endpoint, under a VIEW_ENTITY decision that reasons about that
            # entity's subject category. Bundling attributes in would disclose
            # them under a decision that never considered them — and would mean a
            # victim's details could arrive via a community read.
            out.append({"eid": eid})
        return out

    def record_review(self, decision: Decision, *, principal: Principal,
                     snapshot_id: str, community_id: str,
                     assessment: str, concurs: bool) -> int:
        """Persist a human review of an algorithmic output. Returns the audit seq.

        The review is written to the audit chain rather than only to a mutable
        review table, because the claim it supports — "a named human reviewed
        this before it was exported" — is a claim that has to survive someone
        later editing the review table.
        """
        if not decision.permitted:
            raise PolicyDenied(decision)
        event = self._audit.append(
            request_id=decision.request_id,
            actor_id=principal.user_id,
            actor_agency=principal.agency,
            action="RECORD_HUMAN_REVIEW",
            purpose=Purpose.INTELLIGENCE_DEVELOPMENT.value,
            decision="PERMIT",
            resource_kind=ResourceKind.COMMUNITY.value,
            resource_id=f"{snapshot_id}/{community_id}",
            case_id=None,
            entity_ids=(),
            rule_trace=decision.rule_trace + (
                f"REVIEW:{'CONCUR' if concurs else 'DISSENT'}",
            ),
            obligations=tuple(o.value for o in decision.obligations),
            # A dissent is always notable. An oversight function reviewing this
            # system needs to be able to find the cases where the algorithm was
            # overruled, and those are the informative ones.
            salience=Salience.ROUTINE if concurs else Salience.NOTABLE,
            justification=assessment,
        )
        return event.seq

    # -- deny path ----------------------------------------------------------

    def _audit_denial(self, request: AccessRequest, *,
                      decision: Optional[Decision] = None,
                      reason: Optional[str] = None,
                      salience: Optional[Salience] = None) -> None:
        """Denials are audited as carefully as permits.

        Arguably more carefully. A pattern of denied lookups is the strongest
        insider-misuse signal this system produces — a user probing for records
        they cannot see generates no disclosure and, in a system that only logs
        successes, no trace at all.
        """
        trace = decision.rule_trace if decision else ()
        obligations = (tuple(o.value for o in decision.obligations)
                       if decision else ())
        self._audit.append(
            request_id=request.request_id,
            actor_id=request.principal.user_id,
            actor_agency=request.principal.agency,
            action=request.action.value,
            purpose=request.purpose.value,
            decision="DENY",
            resource_kind=request.resource.kind.value,
            resource_id=request.resource.resource_id,
            case_id=request.resource.case_id,
            entity_ids=(),
            rule_trace=trace + ((f"PEP:{reason}",) if reason else ()),
            obligations=obligations,
            salience=salience or derive_salience("DENY", trace, obligations),
            justification=request.justification,
            approval_by=request.approval_by,
            at=request.at,
        )
