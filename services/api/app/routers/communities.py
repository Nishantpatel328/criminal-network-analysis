"""Community endpoints — algorithmic output, and the controls that gate it.

This is the endpoint with the most legal exposure in the system. Everything else
discloses recorded fact; this discloses a statistical inference about people, and
LED Art. 11 / GDPR Art. 22 constrain what may be done with it.

Three things are enforced here that are not enforced elsewhere:

  - Re-identification is a separate, separately-audited action. Reading a
    community's shape and learning who is in it are different disclosures with
    different thresholds, so they are different requests.
  - A derivation envelope must be present or the response is refused. Not
    warned about — refused, by the redactor, before serialization.
  - Export requires a recorded human review. The `human_reviewed` flag is set by
    a review endpoint, never by the caller asking for the export.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..core.pep import PEP
from ..deps import current_principal, get_pep, parse_purpose, request_id
from ..security.models import (
    Action, PolicyDenied, Principal, Purpose, Resource, ResourceKind,
    UnsupportedObligation,
)

router = APIRouter(prefix="/v1/communities", tags=["communities"])


class CommunityStore:
    """Reads the analytics results store (Z4 output, held in Z2).

    Community records live separately from the evidential graph, keyed by
    surrogate. Joining them back to identities is the `REIDENTIFY` action below,
    which is why this store returns surrogates and nothing else — a store that
    returned names would make the separate action pointless.
    """

    def __init__(self, backend) -> None:
        self._backend = backend

    def community(self, snapshot_id: str, community_id: str) -> Optional[dict]:
        return self._backend.get_community(snapshot_id, community_id)

    def members(self, snapshot_id: str, community_id: str) -> List[dict]:
        return self._backend.get_members(snapshot_id, community_id)


class ReidentifyRequest(BaseModel):
    snapshot_id: str = Field(..., max_length=64)
    surrogates: List[str] = Field(..., max_length=100)
    case_id: str = Field(..., max_length=32)
    purpose: str
    # Long minimum enforced by the PDP (C-DENY-JUSTIFICATION-MISSING). Naming a
    # person behind a statistical grouping is the step that turns an abstract
    # cluster into an investigative interest in an individual, so it is the step
    # that has to be explained in writing.
    justification: str = Field(..., min_length=20, max_length=2000)


@router.get("/{snapshot_id}/{community_id}")
async def get_community(
    snapshot_id: str,
    community_id: str,
    case_id: str = Query(..., max_length=32),
    purpose: str = Query(default=Purpose.INTELLIGENCE_DEVELOPMENT.value),
    principal: Principal = Depends(current_principal),
    pep: PEP = Depends(get_pep),
    rid: str = Depends(request_id),
):
    """The community's shape and quality metrics. No identities."""
    store: CommunityStore = pep.community_store
    record = store.community(snapshot_id, community_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    case_ctx = pep.case_context(case_id)
    if case_ctx is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    resource = Resource(
        kind=ResourceKind.COMMUNITY,
        resource_id=f"{snapshot_id}/{community_id}",
        case_id=case_id,
        legal_basis_refs=case_ctx.authorised_bases,
        estimated_element_count=int(record.get("size") or 0),
        is_derived=True,
        # Both read from the record, never from the request. A caller asserting
        # `derivation_complete=true` would bypass C-DENY-INCOMPLETE-DERIVATION.
        derivation_complete=bool(record.get("derivation")),
        stability=record.get("stability"),
    )

    try:
        decision = pep.access(
            principal=principal, action=Action.VIEW_COMMUNITY,
            purpose=parse_purpose(purpose), resource=resource, request_id=rid,
            case_context=case_ctx,
        )
    except PolicyDenied:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "access denied by policy")
    except UnsupportedObligation:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "policy cannot be enforced by this service version")

    try:
        result = pep.complete(
            decision=decision, principal=principal,
            action=Action.VIEW_COMMUNITY, purpose=parse_purpose(purpose),
            resource=resource, records=[record], kind="community",
        )
    except ValueError as exc:
        # The redactor refused. Almost certainly a missing derivation envelope,
        # which means the analytics tier emitted a result without one — a bug
        # upstream, not a client error, and not something to paper over with a
        # partial response.
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "derived record failed disclosure checks and was not emitted",
        ) from exc

    return result.to_payload()


@router.post("/reidentify")
async def reidentify(
    body: ReidentifyRequest,
    principal: Principal = Depends(current_principal),
    pep: PEP = Depends(get_pep),
    rid: str = Depends(request_id),
):
    """Resolve surrogates to entity ids. Separate action, separate audit.

    Batched and capped at 100. An uncapped endpoint here would let a caller walk
    the entire crosswalk in one request, which would make the pseudonymity
    boundary decorative.
    """
    case_ctx = pep.case_context(body.case_id)
    if case_ctx is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    resource = Resource(
        kind=ResourceKind.COMMUNITY,
        resource_id=f"reidentify:{body.snapshot_id}",
        case_id=body.case_id,
        legal_basis_refs=case_ctx.authorised_bases,
        estimated_element_count=len(body.surrogates),
        is_derived=True,
        derivation_complete=True,
    )

    try:
        decision = pep.access(
            principal=principal, action=Action.REIDENTIFY,
            purpose=parse_purpose(body.purpose), resource=resource,
            request_id=rid, justification=body.justification,
            case_context=case_ctx,
        )
    except PolicyDenied:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "access denied by policy")

    resolved = pep.reidentify(decision, body.snapshot_id, body.surrogates)

    # Surrogates that did not resolve are reported as a count, not a list. Naming
    # which ones failed tells the caller which surrogates are absent from this
    # snapshot's crosswalk, which is a slow read of the crosswalk's contents.
    result = pep.complete(
        decision=decision, principal=principal, action=Action.REIDENTIFY,
        purpose=parse_purpose(body.purpose), resource=resource,
        records=resolved, kind="entity", justification=body.justification,
    )
    payload = result.to_payload()
    payload["unresolved_count"] = len(body.surrogates) - len(resolved)
    return payload


class ReviewRequest(BaseModel):
    snapshot_id: str = Field(..., max_length=64)
    community_id: str = Field(..., max_length=64)
    case_id: str = Field(..., max_length=32)
    # The reviewer's own assessment, in their words. Not a checkbox.
    assessment: str = Field(..., min_length=40, max_length=4000)
    concurs: bool


@router.post("/review")
async def record_review(
    body: ReviewRequest,
    principal: Principal = Depends(current_principal),
    pep: PEP = Depends(get_pep),
    rid: str = Depends(request_id),
):
    """Record a named human's review of an algorithmic output.

    This is what satisfies the Art. 11 / Art. 22 requirement for meaningful human
    involvement before derived data can be exported. Two design choices make it
    meaningful rather than ceremonial: the assessment is free text with a real
    minimum length, and `concurs=false` is a valid, recorded outcome. A review
    that can only ever agree is not a review, and a system that only stores
    approvals cannot show an oversight body that disagreement was possible.

    Setting `human_reviewed` is a side effect of THIS endpoint. The export
    endpoint reads it; it cannot set it.
    """
    case_ctx = pep.case_context(body.case_id)
    if case_ctx is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    if "reviewer" not in principal.roles:
        # Self-review would satisfy the letter of Art. 11 and none of its point.
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "the reviewer role is required to record a review")

    resource = Resource(
        kind=ResourceKind.COMMUNITY,
        resource_id=f"{body.snapshot_id}/{body.community_id}",
        case_id=body.case_id,
        legal_basis_refs=case_ctx.authorised_bases,
        is_derived=True, derivation_complete=True,
        estimated_element_count=1,
    )

    decision = pep.access(
        principal=principal, action=Action.VIEW_COMMUNITY,
        purpose=Purpose.INTELLIGENCE_DEVELOPMENT, resource=resource,
        request_id=rid, justification=body.assessment, case_context=case_ctx,
    )
    seq = pep.record_review(
        decision, principal=principal,
        snapshot_id=body.snapshot_id, community_id=body.community_id,
        assessment=body.assessment, concurs=body.concurs,
    )
    return {"recorded": True, "audit_seq": seq, "concurs": body.concurs}
