"""Application factory and startup assertions.

The startup sequence is as much a security control as anything in security/. Four
things are asserted before the app accepts a request, and each one corresponds to
a failure that is silent if not checked:

  1. Configuration resolves, including the regime. Absent regime = refuse.
  2. Query-registry enums match the live schema. A renamed relationship type
     otherwise makes queries return empty, which an analyst reads as "no
     connections found" — a false negative that becomes an investigative
     conclusion.
  3. The audit chain verifies from its head. Starting up on a broken chain and
     appending to it destroys the evidence of whatever broke it.
  4. No development-grade credential holder is in use. Enforced by the
     constructors themselves (core/config.assert_production_safe).

A system that starts successfully in a broken state is worse than one that
refuses to start, because the first is discovered by an auditor and the second by
a deployment pipeline.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from .core.config import Settings, load_settings, redact_env_for_logging
from .core.pep import PEP, TooExpensive
from .deps import PrincipalResolver
from .graph import registry as reg
from .security.audit import AuditChain, verify_chain
from .security.models import PolicyDenied, UnsupportedObligation
from .security.policy import build_engine

logger = logging.getLogger(__name__)

# Content-Security-Policy for the SPA. No 'unsafe-inline', no 'unsafe-eval'.
# The graph renderer uses canvas, not injected SVG or dynamic style, precisely so
# this header can stay strict — a visualisation library that requires
# unsafe-inline would be a reason to choose a different library, not a reason to
# weaken the header.
CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Cache-Control": "no-store",
    # Intelligence data must not be written to disk by the browser. no-store on
    # every response is blunt and correct; a cached subgraph in a shared
    # workstation's browser cache is a disclosure nobody audited.
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


def create_app(settings: Optional[Settings] = None, *,
               store=None, audit: Optional[AuditChain] = None,
               crosswalk=None, community_store=None) -> FastAPI:
    cfg = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("starting: %s", redact_env_for_logging(dict(os.environ)))

        # Assertion 2: registry enums against the live schema.
        if store is not None and hasattr(store, "live_schema"):
            labels, rel_types = store.live_schema()
            reg.verify_against_schema(labels, rel_types)
        else:
            logger.warning(
                "schema verification skipped: no store with live_schema(). "
                "This must not be the case in a real deployment."
            )

        # Assertion 3: the audit chain verifies before we append to it.
        if audit is not None and hasattr(audit, "_sink"):
            events = list(audit._sink.read_all())   # noqa: SLF001
            if events:
                result = verify_chain(events, audit._signer)  # noqa: SLF001
                if not result.ok:
                    raise RuntimeError(
                        f"audit chain failed verification at startup "
                        f"({len(result.failures)} problems); refusing to append "
                        f"to a chain whose integrity is already in question"
                    )
                logger.info("audit chain verified: %d records", result.checked)

        app.state.settings = cfg
        app.state.principal_resolver = PrincipalResolver(cfg)
        app.state.pep = PEP(
            settings=cfg,
            engine=build_engine(cfg.regime),
            store=store,
            audit=audit,
            crosswalk=crosswalk,
            community_store=community_store,
        )
        yield

    app = FastAPI(
        title="Criminal Network Analysis API",
        version="0.1.0",
        lifespan=lifespan,
        # No interactive docs in production. The schema enumerates every
        # endpoint, parameter and enum value, which is a free reconnaissance
        # document for anyone who reaches the service.
        docs_url=None if cfg.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if cfg.is_production else "/openapi.json",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers[key] = value
        return response

    @app.exception_handler(PolicyDenied)
    async def _denied(request: Request, exc: PolicyDenied):
        """Generic body. The decision's reasons are audited, never returned.

        A detailed denial reason lets a user probe for what exists: "denied
        because this is a victim record" tells them it is a victim record.
        """
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "access denied by policy",
                     "request_id": exc.decision.request_id},
        )

    @app.exception_handler(UnsupportedObligation)
    async def _unsupported(request: Request, exc: UnsupportedObligation):
        logger.error("obligation gap: %s", sorted(o.value for o in exc.missing))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "policy cannot be enforced by this version"},
        )

    @app.exception_handler(TooExpensive)
    async def _too_big(request: Request, exc: TooExpensive):
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": str(exc)},
        )

    from .routers import communities, entities, health
    app.include_router(health.router)
    app.include_router(entities.router)
    app.include_router(communities.router)
    return app
