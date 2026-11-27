"""Runtime configuration and the startup safety gate.

WHY THIS FILE EXISTS
Two modules document a guarantee that has to live somewhere:

  - `worker.pseudonymize.LocalKeyProvider` holds the surrogate root key in the
    process, which defeats the point of an HSM.
  - `security.audit.InProcessSigner` holds the audit MAC key in the process,
    which defeats the point of a tamper-evident log.

Both are legitimate and necessary for tests. Both are catastrophic in production,
and both fail *silently* there — the system works perfectly, the log verifies
against its own key, and nobody discovers the problem until an adversary with
process memory access rewrites history into a self-consistent chain.

A comment saying "test only" does not stop this. A capitalised docstring does not
stop this. What stops it is the class refusing to instantiate. `assert_production_safe()`
is called from the constructor of every development-grade credential holder in
this codebase, and it raises unless the environment has explicitly declared
itself non-production.

FAIL-CLOSED DEFAULT
Absent or unrecognised `CNA_ENV` is treated as PRODUCTION. This is the direction
that matters: a misconfigured deployment should refuse to hold keys in memory,
not quietly permit it. The cost is that a developer who forgets to set the
variable gets an exception with an actionable message, which is a good trade.
"""

from __future__ import annotations

import enum
import os
import re
from dataclasses import dataclass
from typing import Mapping, Optional

from ..security.models import Regime

ENV_VAR = "CNA_ENV"


class Environment(enum.Enum):
    """Deployment environment.

    Only DEVELOPMENT and TEST may hold key material in process memory. STAGING
    is deliberately grouped with PRODUCTION: staging environments in this domain
    routinely carry real or realistically-derived data, and a control that is
    disabled in staging is a control that has never been exercised before it
    matters.
    """
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def permits_in_process_keys(self) -> bool:
        return self in (Environment.DEVELOPMENT, Environment.TEST)


class UnsafeConfiguration(RuntimeError):
    """A development-grade component was reached in a protected environment.

    Deliberately a RuntimeError rather than a custom hierarchy: this must not be
    caught by a broad `except Exception` in a startup path and downgraded to a
    warning. If it is raised, the correct behaviour is for the process to die.
    """


def current_environment(env: Optional[Mapping[str, str]] = None) -> Environment:
    """Read the environment, defaulting to PRODUCTION on anything unclear."""
    raw = (env if env is not None else os.environ).get(ENV_VAR, "")
    try:
        return Environment(raw.strip().lower())
    except ValueError:
        # Includes the empty string. An unset marker means we do not know where
        # we are running, and "we do not know" must be treated as "production".
        return Environment.PRODUCTION


def assert_production_safe(component: str,
                           env: Optional[Mapping[str, str]] = None) -> None:
    """Refuse to construct a development-grade credential holder outside dev/test.

    Called from the constructor, not from a factory. A factory can be bypassed by
    anyone who imports the class directly, and the person most likely to do that
    is someone debugging a production incident at 3am.
    """
    environment = current_environment(env)
    if environment.permits_in_process_keys:
        return
    raise UnsafeConfiguration(
        f"{component} holds key material in process memory and cannot be used "
        f"in environment '{environment.value}'. Configure an HSM-backed "
        f"implementation (HsmSigner / HsmKeyProvider), or set {ENV_VAR}="
        f"development if this really is a development machine."
    )


# ---------------------------------------------------------------------------
# Application settings
# ---------------------------------------------------------------------------

_SECRET_HINTS = re.compile(
    r"(pass|secret|token|key|cred|dsn)", re.IGNORECASE
)


@dataclass(frozen=True)
class Settings:
    """Resolved configuration.

    Frozen, and constructed once at startup. Configuration that can change
    underneath a running request handler means the policy regime a decision was
    made under is not knowable from the audit record, which would undermine the
    entire point of recording the regime on every Decision.

    Note what is NOT here: no secrets. Passwords, MAC keys and the surrogate root
    key are fetched from the secret manager at the point of use by the components
    that need them, so they never sit in a long-lived object that something might
    log or serialise. `__repr__` is overridden anyway, on the principle that the
    second line of defence is the one that gets used.
    """
    environment: Environment
    regime: Regime
    tenant_id: str
    neo4j_uri: str
    neo4j_database: str
    audit_chain_generation: int = 1
    # Cost ceilings. Enforced by the PEP before a query runs, not after.
    max_expansion_elements: int = 500
    max_expansion_hops: int = 2
    # Session lifetime for the SESSION_REAUTH_15M obligation. CJIS requires
    # re-authentication for CJI access from a non-secure location; 900s is the
    # value the Redactor exposes and the two must not drift apart.
    reauth_seconds: int = 900
    # Snapshot cadence for the analytics tier. Also the surrogate rotation
    # period, since surrogates are derived per snapshot.
    snapshot_interval_hours: int = 24

    def __repr__(self) -> str:
        return (f"Settings(environment={self.environment.value}, "
                f"regime={self.regime.value}, tenant_id={self.tenant_id!r}, "
                f"database={self.neo4j_database!r})")

    @property
    def is_production(self) -> bool:
        return not self.environment.permits_in_process_keys


def load_settings(env: Optional[Mapping[str, str]] = None) -> Settings:
    """Build Settings from the environment. Raises on anything missing.

    No defaults for `CNA_REGIME` or `CNA_TENANT_ID`. Defaulting the regime would
    mean a tenant could be silently processed under the wrong statutory rule
    pack, which is the single worst configuration error available in this system —
    it would look like it was working.
    """
    source = env if env is not None else os.environ
    environment = current_environment(source)

    raw_regime = source.get("CNA_REGIME", "").strip().lower()
    if not raw_regime:
        raise UnsafeConfiguration(
            "CNA_REGIME is not set. Set it to 'cjis' or 'gdpr_led'; there is "
            "deliberately no default, because guessing which statute applies to "
            "a tenant's data is not a recoverable error."
        )
    try:
        regime = Regime(raw_regime)
    except ValueError:
        raise UnsafeConfiguration(
            f"CNA_REGIME={raw_regime!r} is not a known regime "
            f"({[r.value for r in Regime]})"
        ) from None

    tenant_id = source.get("CNA_TENANT_ID", "").strip()
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$", tenant_id):
        raise UnsafeConfiguration(
            "CNA_TENANT_ID must be a lowercase kebab-case identifier. It names "
            "the surrogate key derivation domain, so a typo silently produces a "
            "different pseudonym space rather than an error."
        )

    return Settings(
        environment=environment,
        regime=regime,
        tenant_id=tenant_id,
        neo4j_uri=source.get("CNA_NEO4J_URI", "neo4j://127.0.0.1:7687"),
        neo4j_database=source.get("CNA_NEO4J_DATABASE", "cna"),
        audit_chain_generation=int(source.get("CNA_AUDIT_CHAIN_GENERATION", "1")),
    )


def redact_env_for_logging(env: Mapping[str, str]) -> dict:
    """Environment dump with anything secret-looking masked.

    Used by the startup banner and the /healthz diagnostic. Pattern-matching key
    names is a heuristic and will miss a badly-named secret, so this is a
    convenience, not a control — the control is that secrets are not in Settings
    in the first place.
    """
    out = {}
    for k, v in sorted(env.items()):
        if not k.startswith("CNA_"):
            continue
        out[k] = "[MASKED]" if _SECRET_HINTS.search(k) else v
    return out
