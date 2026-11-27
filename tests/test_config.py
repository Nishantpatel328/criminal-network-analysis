"""Tests for the startup safety gate.

These are the highest-value tests in the suite per line of code. The guard they
cover is the difference between "the audit log is tamper-evident" and "the audit
log appears tamper-evident because nobody noticed the test double shipped".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "analytics"))
sys.path.insert(0, str(ROOT / "services" / "api"))

from app.core.config import (  # noqa: E402
    ENV_VAR,
    Environment,
    Settings,
    UnsafeConfiguration,
    assert_production_safe,
    current_environment,
    load_settings,
    redact_env_for_logging,
)
from app.security.audit import InProcessSigner  # noqa: E402
from app.security.models import Regime  # noqa: E402
from worker.env_guard import (  # noqa: E402
    assert_production_safe as worker_assert,
)
from worker.pseudonymize import LocalKeyProvider  # noqa: E402

DEV = {ENV_VAR: "development"}
TEST = {ENV_VAR: "test"}
PROD = {ENV_VAR: "production"}
STAGING = {ENV_VAR: "staging"}


class TestEnvironmentResolution:

    def test_known_values_parse(self):
        assert current_environment(DEV) is Environment.DEVELOPMENT
        assert current_environment(TEST) is Environment.TEST
        assert current_environment(STAGING) is Environment.STAGING
        assert current_environment(PROD) is Environment.PRODUCTION

    def test_unset_defaults_to_production(self):
        # The whole design rests on this. An unset marker must not mean "dev".
        assert current_environment({}) is Environment.PRODUCTION

    def test_garbage_defaults_to_production(self):
        assert current_environment({ENV_VAR: "prd"}) is Environment.PRODUCTION
        assert current_environment({ENV_VAR: ""}) is Environment.PRODUCTION
        assert current_environment({ENV_VAR: "DEVELOPMENT "}) is Environment.DEVELOPMENT

    def test_staging_is_not_permitted_to_hold_keys(self):
        # Staging carries realistic data. A control disabled in staging has never
        # been exercised before it matters.
        assert not Environment.STAGING.permits_in_process_keys
        assert not Environment.PRODUCTION.permits_in_process_keys
        assert Environment.DEVELOPMENT.permits_in_process_keys
        assert Environment.TEST.permits_in_process_keys


class TestGuard:

    def test_permits_dev_and_test(self):
        assert_production_safe("X", DEV)
        assert_production_safe("X", TEST)

    def test_refuses_production_and_staging(self):
        for env in (PROD, STAGING, {}):
            with pytest.raises(UnsafeConfiguration):
                assert_production_safe("X", env)

    def test_message_names_the_component_and_the_remedy(self):
        try:
            assert_production_safe("InProcessSigner", PROD)
        except UnsafeConfiguration as exc:
            msg = str(exc)
            assert "InProcessSigner" in msg
            assert "HsmSigner" in msg or "HSM" in msg
            assert ENV_VAR in msg
        else:
            pytest.fail("guard did not fire")

    def test_is_a_runtime_error_not_a_value_error(self):
        # Must not be swallowed by a startup path catching ValueError while
        # parsing config. If this fires, the process should die.
        assert issubclass(UnsafeConfiguration, RuntimeError)


class TestBoundaryDuplicationDoesNotDrift:
    """The analytics copy of the guard must agree with the API copy.

    The duplication is deliberate (see worker/env_guard.py) because the
    pseudonymity boundary is also a dependency boundary. These tests are the
    price of that decision.
    """

    def test_same_verdict_on_every_environment_value(self):
        for member in Environment:
            env = {ENV_VAR: member.value}
            api_ok = _fires(assert_production_safe, env) is False
            worker_ok = _fires(worker_assert, env) is False
            assert api_ok == worker_ok, (
                f"guards disagree on {member.value}: "
                f"api permits={api_ok}, worker permits={worker_ok}"
            )

    def test_same_verdict_on_unset_and_garbage(self):
        for env in ({}, {ENV_VAR: ""}, {ENV_VAR: "prod"}, {ENV_VAR: "Dev"}):
            assert _fires(assert_production_safe, env) == _fires(worker_assert, env)

    def test_worker_does_not_import_the_api_package(self):
        src = (ROOT / "services" / "analytics" / "worker" / "env_guard.py").read_text()
        assert "from app" not in src
        assert "import app" not in src


def _fires(fn, env) -> bool:
    try:
        fn("probe", env)
        return False
    except RuntimeError:
        return True


class TestCredentialHoldersRefuseProduction:

    def test_in_process_signer_refuses_production(self):
        with pytest.raises(UnsafeConfiguration):
            InProcessSigner(b"\x01" * 32, env=PROD)

    def test_in_process_signer_works_in_test(self):
        signer = InProcessSigner(b"\x01" * 32, env=TEST)
        assert len(signer.mac(b"hello")) == 64

    def test_guard_runs_before_key_length_validation(self):
        # A short key in production must report the environment problem, not the
        # key length. Otherwise a developer fixes the key and ships the double.
        with pytest.raises(UnsafeConfiguration):
            InProcessSigner(b"short", env=PROD)

    def test_local_key_provider_refuses_production(self):
        with pytest.raises(RuntimeError):
            LocalKeyProvider(b"\x02" * 32, env=PROD)

    def test_local_key_provider_works_in_dev(self):
        kp = LocalKeyProvider(b"\x02" * 32, env=DEV)
        assert len(kp.snapshot_key("2026-09-08T00:00:00Z")) == 32


class TestSettings:

    def _env(self, **over):
        base = {ENV_VAR: "test", "CNA_REGIME": "gdpr_led",
                "CNA_TENANT_ID": "pilot-force-a"}
        base.update(over)
        return base

    def test_loads_a_valid_environment(self):
        s = load_settings(self._env())
        assert s.regime is Regime.GDPR_LED
        assert s.tenant_id == "pilot-force-a"
        assert s.environment is Environment.TEST
        assert s.is_production is False

    def test_regime_has_no_default(self):
        # Guessing which statute applies is the worst available config error,
        # because the system would look like it was working.
        with pytest.raises(UnsafeConfiguration, match="CNA_REGIME"):
            load_settings(self._env(CNA_REGIME=""))

    def test_unknown_regime_is_rejected(self):
        with pytest.raises(UnsafeConfiguration):
            load_settings(self._env(CNA_REGIME="cjis_lite"))

    def test_tenant_id_shape_is_enforced(self):
        # The tenant id is part of the surrogate derivation domain, so a typo
        # silently produces a different pseudonym space rather than an error.
        for bad in ("", "Pilot", "a", "with_underscore", "-leading", "trailing-"):
            with pytest.raises(UnsafeConfiguration, match="CNA_TENANT_ID"):
                load_settings(self._env(CNA_TENANT_ID=bad))

    def test_settings_are_frozen(self):
        s = load_settings(self._env())
        with pytest.raises(Exception):
            s.regime = Regime.CJIS      # type: ignore[misc]

    def test_reauth_matches_the_redactor(self):
        from app.security.redaction import Redactor
        from app.security.models import Obligation
        r = Redactor(frozenset({Obligation.SESSION_REAUTH_15M}))
        assert load_settings(self._env()).reauth_seconds == r.session_reauth_seconds

    def test_repr_does_not_dump_the_environment(self):
        s = load_settings(self._env())
        text = repr(s)
        assert "pilot-force-a" in text          # useful identifiers stay
        assert "neo4j_uri" not in text          # connection strings do not


class TestEnvRedaction:

    def test_masks_secret_looking_keys(self):
        out = redact_env_for_logging({
            "CNA_ENV": "test",
            "CNA_NEO4J_PASSWORD": "hunter2",
            "CNA_AUDIT_MAC_KEY": "abc",
            "CNA_SURROGATE_SECRET": "xyz",
            "CNA_NEO4J_DSN": "bolt://u:p@h",
            "CNA_TENANT_ID": "pilot-force-a",
            "PATH": "/usr/bin",
        })
        assert out["CNA_ENV"] == "test"
        assert out["CNA_TENANT_ID"] == "pilot-force-a"
        for k in ("CNA_NEO4J_PASSWORD", "CNA_AUDIT_MAC_KEY",
                  "CNA_SURROGATE_SECRET", "CNA_NEO4J_DSN"):
            assert out[k] == "[MASKED]"
        assert "PATH" not in out               # non-CNA vars are not echoed at all
