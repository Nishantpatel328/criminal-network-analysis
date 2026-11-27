"""Environment guard for the analytics tier — deliberately duplicated.

This is a near-copy of `assert_production_safe` from
`services/api/app/core/config.py`. The duplication is intentional and is the
same decision made for `MIN_DISCLOSABLE_STABILITY` in derivation.py.

WHY NOT IMPORT IT
The pseudonymity boundary is also a dependency boundary. If the analytics package
can import from the API package, then over time it will, and the thing that
eventually crosses will not be a nine-line environment check — it will be a model
class that carries a `display_name`, or a helper that reaches for the crosswalk.
Keeping the import graph one-directional is a structural control; a code-review
convention is not.

The cost is two copies of a small function that must not drift.
`tests/test_analytics.py` asserts they agree on every Environment value, so drift
fails the build rather than quietly disabling a guard on one side of the boundary.
"""

from __future__ import annotations

import os
from typing import Mapping, Optional

ENV_VAR = "CNA_ENV"

# Mirrors Environment.permits_in_process_keys on the API side. STAGING is absent
# on purpose: staging in this domain carries realistic data, and a control that is
# off in staging has never been exercised before it matters.
_PERMITTED = frozenset({"development", "test"})


class UnsafeConfiguration(RuntimeError):
    """A development-grade credential holder was reached outside dev/test."""


def assert_production_safe(component: str,
                           env: Optional[Mapping[str, str]] = None) -> None:
    """Raise unless the environment has explicitly declared itself dev or test.

    Absent or unrecognised `CNA_ENV` is treated as production. Not knowing where
    we are running has to mean "assume the worst", otherwise the guard is absent
    in precisely the deployments that were configured carelessly.
    """
    raw = (env if env is not None else os.environ).get(ENV_VAR, "").strip().lower()
    if raw in _PERMITTED:
        return
    raise UnsafeConfiguration(
        f"{component} holds key material in process memory and cannot be used "
        f"in environment '{raw or '<unset>'}'. Use an HSM-backed KeyProvider, "
        f"or set {ENV_VAR}=development if this really is a development machine."
    )
