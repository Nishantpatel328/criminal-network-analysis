"""Entity and subgraph endpoints.

Thin by design. Every handler does the same thing: build a Resource from facts
the store gave us, hand it to PEP.access(), run the registered query, hand the
rows to PEP.complete(). The ordering guarantees live in core/pep.py; a handler
cannot express a different order without editing that file.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from ..core.pep import DEFAULT_EXPANSION_TYPES, PEP, TooExpensive
from ..deps import current_principal, get_pep, parse_purpose, request_id
from ..graph import registry as reg
from ..security.models import (
    Action, PolicyDenied, Principal, Resource, ResourceKind,
    UnsupportedObligation,
)

router = APIRouter(prefix="/v1", tags=["entities"])


class ExpandRequest(BaseModel):
    """Note what this schema does NOT contain: clearance, case memberships,
    legal bases, subject categories. Those are facts about the requester and the
    data, and a request body is not a source of truth for either."""

    eid: str = Field(..., max_length=36)
    case_id: str = Field(..., max_length=32)
    purpose: str
    justification: Optional[str] = Field(default=None, max_length=2000)
    rel_types: Optional[List[str]] = None

    @field_validator("eid")
    @classmethod
    def _uuid(cls, v: str) -> str:
        if not reg.is_uuid(v):
            raise ValueError("eid must be a lowercase UUID")
        return v

    @field_validator("case_id")
    @classmethod
    def _case(cls, v: str) -> str:
        if not reg.is_case_id(v):
            raise ValueError("case_id must match FORCE-YYYY-NNNN")
        return v

    def resolved_rel_types(self):
        """Map names onto the closed enum. Unknown names are rejected, not ignored.

        Ignoring an unrecognised type would silently widen the traversal to the
        default set, so a typo would return more data than asked for — the wrong
        direction for a minimisation control to fail in.
        """
        if not self.rel_types:
            return DEFAULT_EXPANSION_TYPES
        out = []
        for name in self.rel_types:
            try:
                t = reg.RelType[name]
            except KeyError:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    f"unknown relationship type; permitted values are "
                    f"{[t.name for t in DEFAULT_EXPANSION_TYPES]}",
                )
            if t not in DEFAULT_EXPANSION_TYPES:
                # APPEARS_IN lands here: it is a real enum member but not
                # analyst-traversable, because it crosses case boundaries.
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    f"{name} is not traversable from an analyst context",
                )
            out.append(t)
        return tuple(out)


@router.post("/subgraph/expand")
async def expand(
    body: ExpandRequest,
    principal: Principal = Depends(current_principal),
    pep: PEP = Depends(get_pep),
    rid: str = Depends(request_id),
):
    purpose = parse_purpose(body.purpose)
    rel_types = body.resolved_rel_types()

    # Step 1: facts from the store. Both calls happen before any decision.
    case_ctx = pep.case_context(body.case_id)
    if case_ctx is None:
        # Same 404 whether the case does not exist or the caller cannot see it.
        # Distinguishing them turns the endpoint into a case-existence oracle.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    count, categories = pep.survey_expansion(
        body.eid, sorted(case_ctx.authorised_bases), rel_types
    )

    resource = Resource(
        kind=ResourceKind.SUBGRAPH,
        resource_id=f"sg:{body.eid}",
        case_id=body.case_id,
        subject_categories=categories,
        legal_basis_refs=case_ctx.authorised_bases,
        entity_ids=frozenset({body.eid}),
        estimated_element_count=count,
    )

    try:
        decision = pep.access(
            principal=principal, action=Action.EXPAND_SUBGRAPH, purpose=purpose,
            resource=resource, request_id=rid, justification=body.justification,
            case_context=case_ctx,
        )
    except TooExpensive as exc:
        # 413 rather than 500: this is a statement about the request, and the
        # message tells the analyst how to narrow it.
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc))
    except PolicyDenied:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "access denied by policy")
    except UnsupportedObligation:
        # The policy required something this build cannot apply. Not the client's
        # fault and not something to work around.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "policy cannot be enforced by this service version")

    rows = pep.query(
        decision, reg.Q_NEIGHBOURHOOD,
        {"eid": body.eid, "case_id": body.case_id,
         "bases": sorted(case_ctx.authorised_bases),
         "limit": min(count or 1, 500)},
        rel_types=rel_types,
    )

    nodes = pep.complete(
        decision=decision, principal=principal,
        action=Action.EXPAND_SUBGRAPH, purpose=purpose, resource=resource,
        records=rows, kind="entity", justification=body.justification,
    )
    return nodes.to_payload()


@router.get("/entity/{eid}")
async def get_entity(
    eid: str,
    case_id: str = Query(..., max_length=32),
    purpose: str = Query(...),
    justification: Optional[str] = Query(default=None, max_length=2000),
    principal: Principal = Depends(current_principal),
    pep: PEP = Depends(get_pep),
    rid: str = Depends(request_id),
):
    if not reg.is_uuid(eid) or not reg.is_case_id(case_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "malformed identifier")

    case_ctx = pep.case_context(case_id)
    if case_ctx is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    # The category lookup precedes the decision, so it runs through the store
    # directly rather than through pep.query() — there is no decision yet to
    # authorise it with. It reads one property of one node inside case scope and
    # discloses nothing to the caller; the disclosure decision is below.
    rows = pep.peek_entity(eid, case_id)
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    from ..security.models import SubjectCategory
    try:
        category = SubjectCategory(rows[0].get("subject_category"))
    except ValueError:
        category = SubjectCategory.VICTIM      # fail closed on an unknown value

    resource = Resource(
        kind=ResourceKind.ENTITY, resource_id=eid, case_id=case_id,
        subject_categories=frozenset({category}),
        legal_basis_refs=case_ctx.authorised_bases,
        entity_ids=frozenset({eid}),
        estimated_element_count=1,
    )

    try:
        decision = pep.access(
            principal=principal, action=Action.VIEW_ENTITY,
            purpose=parse_purpose(purpose), resource=resource, request_id=rid,
            justification=justification, case_context=case_ctx,
        )
    except PolicyDenied:
        # 403, not 404. Hiding the distinction here would be the honest choice
        # for existence-probing, but the record was already confirmed to exist
        # inside case scope, so a 404 would be a lie to the analyst about their
        # own case. The denial is audited either way.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "access denied by policy")

    result = pep.complete(
        decision=decision, principal=principal, action=Action.VIEW_ENTITY,
        purpose=parse_purpose(purpose), resource=resource, records=rows,
        kind="entity", justification=justification,
    )
    return result.to_payload()
