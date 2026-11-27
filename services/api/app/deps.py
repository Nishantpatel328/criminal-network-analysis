"""Request-scoped dependencies: identity, tenancy, and the wired PEP.

The rule this module exists to enforce: nothing security-relevant is read from
the request body. The principal comes from a verified token, the case context and
subject categories come from the store, the regime comes from process
configuration. A client can name a resource and state a purpose; it cannot assert
its own clearance, its case memberships, or the legal basis authorising it.

That sounds obvious written down. It is also the single most common way
attribute-based access control is subverted in practice — someone adds
`clearance` to a request schema for a test harness, and it stays.
"""

from __future__ import annotations

import logging
import uuid
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status

from .core.config import Settings
from .core.pep import PEP
from .security.models import Clearance, Principal, Purpose

logger = logging.getLogger(__name__)


class PrincipalResolver:
    """Turns a verified access token into a Principal.

    In production this validates a signed assertion from the force's IdP
    (SAML/OIDC), and the claims it reads are the ones the IdP is authoritative
    for: clearance level, current training date, case memberships, linked entity
    ids, and whether the second factor was phishing-resistant.

    `linked_entity_ids` is the interesting one. It comes from an HR join, not from
    the graph, and it is what makes self-lookup and relative-lookup detectable.
    Nearly all real insider misuse in police systems is someone checking on
    themselves, an ex-partner, a neighbour or a colleague — so the attribute that
    detects it has to be present on every request, not computed lazily.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def resolve(self, token: str, *, from_secure_location: bool) -> Principal:
        claims = self._verify(token)
        return Principal(
            user_id=claims["sub"],
            agency=claims["agency"],
            clearance=Clearance[claims.get("clearance", "NONE")],
            roles=frozenset(claims.get("roles", ())),
            case_memberships=frozenset(claims.get("cases", ())),
            mfa_satisfied=bool(claims.get("amr")),
            mfa_method=(claims.get("amr") or [None])[0],
            from_secure_location=from_secure_location,
            training_current_until=(
                date.fromisoformat(claims["training_until"])
                if claims.get("training_until") else None
            ),
            supervisor_id=claims.get("supervisor"),
            linked_entity_ids=frozenset(claims.get("linked_entities", ())),
        )

    def _verify(self, token: str) -> dict:  # pragma: no cover - scaffold
        """Signature and audience verification against the IdP JWKS.

        Not implemented in the scaffold, and deliberately raising rather than
        returning a permissive stub. A stub here that returns a plausible
        principal is a complete authentication bypass that passes every test.
        """
        raise NotImplementedError(
            "wire PrincipalResolver._verify to the force IdP before deployment; "
            "there is intentionally no default implementation"
        )


async def request_id(x_request_id: Optional[str] = Header(default=None)) -> str:
    """Correlation id. Generated if absent, never trusted for length.

    Echoed into the audit record, so an unbounded client-supplied string would be
    an injection vector into the log. Truncated and constrained.
    """
    if x_request_id and x_request_id.isascii() and len(x_request_id) <= 64:
        return x_request_id
    return f"req-{uuid.uuid4()}"


async def current_principal(
    request: Request,
    authorization: str = Header(...),
) -> Principal:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required")
    resolver: PrincipalResolver = request.app.state.principal_resolver
    # Network location is asserted by the edge proxy (Z1) via mTLS client cert
    # attributes, not by a header the client controls. CJIS advanced-auth rules
    # turn on this value, so a spoofable source would defeat them.
    secure = bool(getattr(request.state, "from_secure_location", False))
    try:
        return resolver.resolve(authorization[7:], from_secure_location=secure)
    except NotImplementedError:
        raise
    except Exception:
        # No detail to the client. A verbose auth error is a probing oracle.
        logger.warning("principal resolution failed", exc_info=True)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication failed")


async def get_pep(request: Request) -> PEP:
    return request.app.state.pep


def parse_purpose(raw: str) -> Purpose:
    """Purpose is mandatory and closed-vocabulary.

    A free-text purpose field would be unenforceable — purpose limitation only
    works if the value is comparable against the legal basis, and 'investigating'
    is not comparable to anything.
    """
    try:
        return Purpose(raw)
    except ValueError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"purpose must be one of {[p.value for p in Purpose]}",
        )
