"""Edge weighting from 5x5x5 intelligence evaluation.

WHY THIS MATTERS MORE THAN IT LOOKS
Community detection is weight-sensitive. A single uncorroborated assertion —
one informant saying "X knows Y", possibly mistaken, possibly malicious — can,
if weighted equally with a year of billing records, create an apparent community
that does not exist. People then get investigated on the strength of it.

So the weighting is deliberately conservative and asymmetric: high-confidence
edges are trusted at face value, low-confidence edges are heavily discounted,
and the lowest tier is excluded from clustering altogether while remaining
visible in the UI. Being wrong in the direction of "we did not see a community
that was there" is recoverable by an analyst; being wrong in the direction of
"we invented a community that was not there" produces a false conclusion about
real people that is very hard to unwind.

Source evaluation (1 best .. 5 untested) and intelligence assessment
(1 known true .. 5 suspected false) are multiplied into a single factor.
"""

from __future__ import annotations

from typing import Dict

# Source reliability multiplier. 1 = always reliable (e.g. a telco's own billing
# record), 5 = untested source (a first-time informant).
SOURCE_FACTOR: Dict[int, float] = {
    1: 1.00,
    2: 0.85,
    3: 0.60,
    4: 0.30,
    5: 0.25,
}

# Intelligence assessment multiplier. 4 (uncorroborated hearsay) drops sharply
# because this is where fabrication and honest error live. 5 (suspected false) is
# zero: it is excluded from clustering entirely.
ASSESSMENT_FACTOR: Dict[int, float] = {
    1: 1.00,
    2: 0.80,
    3: 0.55,
    4: 0.25,
    5: 0.00,
}

# Relationship-type prior. Observed, machine-generated records outrank
# human-asserted association, which is the type most vulnerable to assumption
# and to the "known associate" label that accretes without re-examination.
REL_TYPE_FACTOR: Dict[str, float] = {
    "COMMUNICATED_WITH": 1.00,
    "TRANSACTED_WITH": 1.00,
    "HOLDS_ACCOUNT": 0.95,
    "USES_PHONE": 0.95,
    "REGISTERED_TO": 0.90,
    "PRESENT_AT": 0.70,
    "ASSOCIATE_OF": 0.60,
}

# Edges below this contribute nothing to cluster formation.
CONFIDENCE_FLOOR = 0.05


def confidence_weight(base_weight: float, source_eval: int,
                      intel_assessment: int,
                      rel_type: str = "COMMUNICATED_WITH") -> float:
    """Combine observed strength with evaluated confidence.

    `base_weight` is the observed intensity (call count, transaction volume,
    number of distinct days). It is log-damped: the difference between 2 calls
    and 20 is investigatively meaningful, the difference between 2,000 and
    20,000 mostly is not, and leaving it linear lets a single high-volume pair
    (a dispatcher, a delivery service) dominate the partition and pull unrelated
    actors into one cluster.
    """
    import math

    if source_eval not in SOURCE_FACTOR:
        raise ValueError(f"source_eval must be 1-5, got {source_eval}")
    if intel_assessment not in ASSESSMENT_FACTOR:
        raise ValueError(f"intel_assessment must be 1-5, got {intel_assessment}")
    if base_weight < 0:
        raise ValueError("base_weight must be non-negative")

    damped = math.log1p(max(base_weight, 0.0))
    confidence = (SOURCE_FACTOR[source_eval]
                  * ASSESSMENT_FACTOR[intel_assessment]
                  * REL_TYPE_FACTOR.get(rel_type, 0.5))
    weight = damped * confidence
    return weight if weight >= CONFIDENCE_FLOOR else 0.0


def confidence_interval(source_eval: int, intel_assessment: int) -> float:
    """Relative uncertainty on the weight, used by the stability bootstrap.

    A weight derived from a telco billing record is close to certain; one derived
    from untested hearsay could be badly wrong. The bootstrap perturbs each edge
    within its own interval rather than applying uniform noise, so instability
    concentrates exactly where the evidence is weakest — which is the honest
    behaviour and also the useful one.
    """
    reliability = SOURCE_FACTOR[source_eval] * ASSESSMENT_FACTOR[intel_assessment]
    # Perfect evidence -> +/-5%; worthless evidence -> +/-80%.
    return 0.05 + 0.75 * (1.0 - reliability)


def describe(source_eval: int, intel_assessment: int) -> str:
    """Human-readable evaluation for the UI tooltip. The frontend renders stroke
    style from the numbers; this is the text an analyst sees on hover."""
    src = {1: "always reliable", 2: "mostly reliable", 3: "sometimes reliable",
           4: "unreliable", 5: "untested source"}[source_eval]
    assess = {1: "known directly true", 2: "known to source",
              3: "corroborated", 4: "uncorroborated",
              5: "suspected false"}[intel_assessment]
    return f"source {source_eval}/5 ({src}); intelligence {intel_assessment}/5 ({assess})"
