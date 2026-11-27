#!/usr/bin/env python3
"""Test runner that works with or without pytest installed.

    python3 tests/run_tests.py              # all suites
    python3 tests/run_tests.py test_policy  # one module

Prefers the real pytest. Falls back to the stdlib shim in tests/_shim so the
security suite remains runnable inside an air-gapped enclave. See
tests/_shim/pytest.py for why that matters.
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# Declare the environment before importing anything. InProcessSigner and
# LocalKeyProvider refuse to instantiate unless this is set (see
# services/api/app/core/config.py), which is the point — the suite exercises the
# same guard production relies on, rather than a bypass for tests.
os.environ.setdefault("CNA_ENV", "test")

MODULES = ["test_policy", "test_audit", "test_registry", "test_analytics",
           "test_pep",
           "test_config"]


def _prepare_path() -> str:
    sys.path.insert(0, str(ROOT / "services" / "api"))
    sys.path.insert(0, str(ROOT / "services" / "analytics"))
    sys.path.insert(0, str(HERE))
    try:
        import pytest  # noqa: F401
        return "real"
    except ImportError:
        sys.path.insert(0, str(HERE / "_shim"))
        return "shim"


def run_module(name: str) -> tuple:
    mod = importlib.import_module(name)
    passed = failed = skipped = 0
    failures = []

    targets = []
    for attr, obj in sorted(vars(mod).items()):
        if attr.startswith("Test") and inspect.isclass(obj):
            for mname, meth in sorted(vars(obj).items()):
                if mname.startswith("test_") and callable(meth):
                    targets.append((f"{attr}::{mname}", obj, meth))
        elif attr.startswith("test_") and inspect.isfunction(obj):
            targets.append((attr, None, obj))

    for label, cls, meth in targets:
        if getattr(meth, "__skip__", None):
            skipped += 1
            print(f"  s {label}")
            continue
        try:
            meth(cls()) if cls is not None else meth()
            passed += 1
            print(f"  . {label}")
        except BaseException as exc:      # noqa: BLE001
            # Matched by type name so this works with both real pytest's
            # _pytest.outcomes.Skipped and the shim's. Both are BaseException
            # subclasses, so a bare `except Exception` would let a skip escape
            # and abort the whole run.
            if type(exc).__name__ == "Skipped":
                skipped += 1
                print(f"  s {label} ({exc})")
                continue
            if isinstance(exc, KeyboardInterrupt):
                raise
            failed += 1
            failures.append((f"{name}::{label}", traceback.format_exc()))
            print(f"  F {label}")

    return passed, failed, skipped, failures


def main() -> int:
    mode = _prepare_path()
    print(f"pytest: {mode}\n")

    wanted = sys.argv[1:] or MODULES
    total_p = total_f = total_s = 0
    all_failures = []

    for name in wanted:
        path = HERE / f"{name}.py"
        if not path.exists():
            print(f"{name}: NOT FOUND, skipping")
            continue
        print(f"{name}:")
        p, f, s, fails = run_module(name)
        total_p += p
        total_f += f
        total_s += s
        all_failures.extend(fails)
        print()

    if all_failures:
        print("=" * 70)
        for label, tb in all_failures:
            print(f"\nFAILED {label}\n{tb}")

    print("=" * 70)
    print(f"{total_p} passed, {total_f} failed, {total_s} skipped")
    return 1 if total_f else 0


if __name__ == "__main__":
    sys.exit(main())
