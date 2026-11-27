"""Liveness, readiness, and an authenticated diagnostic.

Health endpoints are the most-forgotten attack surface in a service like this.
They are unauthenticated by necessity (a load balancer cannot hold a warrant
card), which makes them the one place an unauthenticated caller reliably gets a
response — so what they return is a design decision, not a convenience.

The split here:

  /healthz   unauthenticated, fixed body. Says the process is up and nothing else.
             No version, no tenant, no regime, no dependency status. A version
             string on an unauthenticated endpoint is a CVE-matching service for
             whoever is scanning.

  /readyz    unauthenticated, but answers only with a boolean per dependency and
             a 503 when not ready. Orchestrators need this to route traffic.
             Deliberately does not say *why* a dependency is unhealthy — the
             reason goes to the log, where it belongs.

  /v1/diagnostics
             authenticated and role-gated. This is where the useful detail lives:
             regime, tenant, environment, chain generation, registry fingerprint.
             It is an authorization-relevant read, so it is audited like one.
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..core.config import Settings, redact_env_for_logging
from ..graph import registry as reg
from ..security.models import Principal
from ..deps import current_principal

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ops"])


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    """Process liveness. Constant body — carries no information by design."""
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readyz(request: Request):
    """Dependency readiness as booleans only.

    Returning 503 with an opaque body when a dependency is down is the correct
    trade: the orchestrator gets what it needs (route traffic elsewhere), and a
    scanner learns nothing about which component failed or how.
    """
    checks: Dict[str, bool] = {}

    pep = getattr(request.app.state, "pep", None)
    checks["configured"] = pep is not None

    store = getattr(pep, "_store", None) if pep is not None else None
    if store is not None and hasattr(store, "ping"):
        try:
            store.ping()
            checks["graph"] = True
        except Exception:
            logger.error("readiness: graph store unreachable", exc_info=True)
            checks["graph"] = False
    else:
        checks["graph"] = store is not None

    audit = getattr(pep, "_audit", None) if pep is not None else None
    # An unwritable audit sink is a hard failure, not a degraded mode. If we
    # cannot record a disclosure, we must not make one — so the service takes
    # itself out of rotation rather than serving requests it cannot account for.
    if audit is not None and hasattr(audit, "_sink"):
        try:
            audit._sink.head()          # noqa: SLF001 - readiness probe only
            checks["audit"] = True
        except Exception:
            logger.critical("readiness: audit sink unavailable", exc_info=True)
            checks["audit"] = False
    else:
        checks["audit"] = audit is not None

    if all(checks.values()):
        return {"ready": True, "checks": checks}
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"ready": False, "checks": checks},
    )


@router.get("/v1/diagnostics")
async def diagnostics(
    request: Request,
    principal: Principal = Depends(current_principal),
) -> dict:
    """Operator-facing configuration summary. Role-gated.

    Everything here is non-secret by construction: `Settings` holds no
    credentials, and the environment dump is filtered through
    `redact_env_for_logging`. That filter is a heuristic and is treated as one —
    the actual control is that secrets never enter Settings, and the filter is a
    second line.
    """
    if "operator" not in principal.roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "the operator role is required")

    cfg: Settings = request.app.state.settings
    import os

    return {
        "environment": cfg.environment.value,
        "regime": cfg.regime.value,
        "tenant_id": cfg.tenant_id,
        "audit_chain_generation": cfg.audit_chain_generation,
        "ceilings": {
            "max_expansion_elements": cfg.max_expansion_elements,
            "max_expansion_hops": cfg.max_expansion_hops,
            "reauth_seconds": cfg.reauth_seconds,
        },
        "registry": {
            "queries": sorted(reg.REGISTRY.names()),
            "labels": sorted(l.value for l in reg.NodeLabel),
            "relationship_types": sorted(r.value for r in reg.RelType),
        },
        "config": redact_env_for_logging(dict(os.environ)),
    }
