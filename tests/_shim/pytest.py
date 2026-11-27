"""Minimal pytest-API shim — stdlib only.

WHY THIS EXISTS
CI runs the real pytest (see deploy/ci/). This shim exists so the security test
suite can also be executed in a restricted or air-gapped environment where
installing packages is not possible — which, for a system destined for a CJIS
enclave or a police network, is the normal case rather than the exception. An
air-gapped reviewer being unable to run the tests that prove the access-control
kernel works would be a bad property for this repo to have.

It is loaded ONLY when the real pytest is absent (see run_tests.py), so it never
shadows the real thing.

Implements exactly the surface the suite uses: `raises`, `fail`, `approx`,
`skip`, and `mark.skip`. Nothing else. If a future test needs more, prefer
installing pytest over growing this file.
"""

from __future__ import annotations

import math
from typing import Any, Optional, Type


class Skipped(BaseException):
    """Deliberately not an Exception subclass, matching real pytest.

    A skip must not be swallowed by a test body's own `except Exception`, which
    would silently convert "we could not run this check" into "this check
    passed" — the worst possible outcome for a security suite.
    """


class _RaisesContext:
    def __init__(self, expected: Type[BaseException], match: Optional[str]) -> None:
        self.expected = expected
        self.match = match
        self.value: Optional[BaseException] = None

    def __enter__(self) -> "_RaisesContext":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None:
            raise AssertionError(
                f"DID NOT RAISE {self.expected.__name__}"
            )
        if not issubclass(exc_type, self.expected):
            return False  # propagate: wrong exception type is a real failure
        if self.match is not None:
            import re
            if not re.search(self.match, str(exc)):
                raise AssertionError(
                    f"exception message {str(exc)!r} does not match "
                    f"{self.match!r}"
                )
        self.value = exc
        return True


def raises(expected: Type[BaseException], match: Optional[str] = None):
    return _RaisesContext(expected, match)


def fail(msg: str = "") -> None:
    raise AssertionError(msg)


def skip(reason: str = "") -> None:
    raise Skipped(reason or "skipped")


class _Approx:
    def __init__(self, value: float, rel: float = 1e-6, abs_: float = 1e-12) -> None:
        self.value, self.rel, self.abs = value, rel, abs_

    def __eq__(self, other: Any) -> bool:
        return math.isclose(float(other), self.value,
                            rel_tol=self.rel, abs_tol=self.abs)

    def __repr__(self) -> str:
        return f"approx({self.value})"


def approx(value: float, rel: float = 1e-6, abs: float = 1e-12) -> _Approx:
    return _Approx(value, rel, abs)


class _Mark:
    @staticmethod
    def skip(reason: str = ""):
        def deco(fn):
            setattr(fn, "__skip__", reason or "skipped")
            return fn
        return deco

    @staticmethod
    def parametrize(*_a, **_k):
        raise NotImplementedError(
            "parametrize is not supported by the shim; install pytest"
        )


mark = _Mark()
