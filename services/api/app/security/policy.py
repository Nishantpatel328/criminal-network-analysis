"""Policy Decision Point — dual-regime attribute-based access control.

Combination algebra
-------------------
Deny-overrides, with an implicit deny when no rule permits:

  1. Every rule in (common ++ regime pack) is evaluated. A rule returns a
     RuleOutcome or None ("no opinion").
  2. If ANY rule denies, the decision is DENY. Denials are never outvoted.
  3. If no rule denies AND at least one rule permits, the decision is PERMIT
     with the union of all obligations from all permitting rules.
  4. Otherwise DENY ("no applicable rule").

Rule 4 is the important one. A great many access-control bugs are really
"the request fell through every branch and the default was allow". Here, a
request nobody explicitly recognised is refused, so adding a new action or
resource kind without a corresponding rule fails safely and loudly instead of
silently opening a hole.

Obligations union rather than intersect: if the LED pack says redact DOB and the
CJIS pack says watermark, we do both. Obligations are restrictions, so taking
the union is the conservative direction.

Rules must be pure functions of the request. No I/O, no clock reads (the clock
is on the request), no database lookups. The PEP gathers everything the PDP
needs first. This makes the whole engine deterministic and exhaustively
testable, which for an access-control kernel is worth the inconvenience.
"""

from __future__ import annotations

import logging
from typing import Callable, Iterable, List, Optional, Sequence, Set

from .models import (
    AccessRequest,
    Decision,
    Effect,
    Obligation,
    PolicyDenied,
    Regime,
    RuleOutcome,
    UnsupportedObligation,
)

logger = logging.getLogger(__name__)

Rule = Callable[[AccessRequest], Optional[RuleOutcome]]


class PolicyEngine:
    """Evaluates a request against the common rules plus one regime pack."""

    def __init__(self, regime: Regime, rules: Sequence[Rule]) -> None:
        self._regime = regime
        self._rules = tuple(rules)
        if not self._rules:
            # An engine with no rules would deny everything, which is safe but
            # is certainly a misconfiguration, so refuse to start rather than
            # present a mysteriously broken system.
            raise ValueError("PolicyEngine constructed with no rules")

    @property
    def regime(self) -> Regime:
        return self._regime

    def decide(self, request: AccessRequest) -> Decision:
        denials: List[RuleOutcome] = []
        permits: List[RuleOutcome] = []
        obliges: List[RuleOutcome] = []
        trace: List[str] = []

        for rule in self._rules:
            try:
                outcome = rule(request)
            except Exception:
                # A rule that throws is a rule whose intent we do not know.
                # Treat it as a denial: an engine that silently skips a broken
                # rule is an engine whose security properties depend on none of
                # its rules ever having a bug.
                rule_id = getattr(rule, "rule_id", getattr(rule, "__name__", "unknown"))
                logger.exception("policy rule %s raised; failing closed", rule_id)
                denials.append(
                    RuleOutcome(Effect.DENY, rule_id, "rule evaluation error")
                )
                trace.append(f"{rule_id}:ERROR")
                continue

            if outcome is None:
                continue
            trace.append(f"{outcome.rule_id}:{outcome.effect.value}")
            if outcome.effect is Effect.DENY:
                denials.append(outcome)
            elif outcome.effect is Effect.OBLIGE:
                obliges.append(outcome)
            else:
                permits.append(outcome)

        if denials:
            return Decision(
                effect=Effect.DENY,
                obligations=frozenset(),
                reasons=tuple(d.reason for d in denials),
                rule_trace=tuple(trace),
                regime=self._regime,
                request_id=request.request_id,
            )

        if not permits:
            return Decision(
                effect=Effect.DENY,
                obligations=frozenset(),
                reasons=("no applicable rule permitted this request",),
                rule_trace=tuple(trace),
                regime=self._regime,
                request_id=request.request_id,
            )

        # Obligations union across both permitting and obliging rules.
        # Obligations are restrictions, so union is the conservative direction:
        # if LED says redact DOB and CJIS says watermark, we do both.
        obligations: Set[Obligation] = set()
        for p in permits + obliges:
            obligations |= set(p.obligations)

        return Decision(
            effect=Effect.PERMIT,
            obligations=frozenset(obligations),
            reasons=tuple(p.reason for p in permits),
            rule_trace=tuple(trace),
            regime=self._regime,
            request_id=request.request_id,
        )


# ---------------------------------------------------------------------------
# Policy Enforcement Point helper
# ---------------------------------------------------------------------------

def enforce(
    decision: Decision,
    supported_obligations: Iterable[Obligation],
) -> frozenset:
    """Raise unless the decision permits AND every obligation is enforceable.

    Returns the obligation set for the caller to apply.

    The second check is the part people skip. A permit whose obligations are
    ignored is functionally an unconditional permit, and the failure is silent:
    the audit log shows PERMIT, the policy looks correct in review, and the
    redaction never happened. Requiring the PEP to declare what it can enforce
    turns that silent failure into a startup-time or request-time exception.
    """
    if not decision.permitted:
        raise PolicyDenied(decision)

    supported = set(supported_obligations)
    missing = decision.obligations - supported
    if missing:
        raise UnsupportedObligation(frozenset(missing))
    return decision.obligations


def build_engine(regime: Regime) -> PolicyEngine:
    """Factory: common rules plus the regime-specific pack."""
    from .rules_common import COMMON_RULES

    if regime is Regime.CJIS:
        from .regimes.cjis import CJIS_RULES
        pack = CJIS_RULES
    elif regime is Regime.GDPR_LED:
        from .regimes.led import LED_RULES
        pack = LED_RULES
    else:  # pragma: no cover - enum exhausted
        raise ValueError(f"unknown regime {regime}")

    return PolicyEngine(regime, tuple(COMMON_RULES) + tuple(pack))


def rule(rule_id: str):
    """Decorator attaching a stable ID to a rule for the audit trace.

    Stable IDs matter more than they look: the audit log records which rules
    fired, and an oversight body reviewing a denial six months later needs the
    ID to still mean the same thing. Renaming a function must not silently
    change the audit vocabulary, so the ID is declared explicitly.
    """
    def wrap(fn: Rule) -> Rule:
        setattr(fn, "rule_id", rule_id)
        return fn
    return wrap
