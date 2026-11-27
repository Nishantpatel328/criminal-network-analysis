"""Derivation envelopes — the record that makes a derived result disclosable.

WHY THIS FILE EXISTS
`redaction.py` refuses to emit a community to any client unless the payload
carries one of these. That refusal is the enforcement point for a legal
requirement, not a code-quality preference.

Under LED Art. 11 and GDPR Art. 22, a decision affecting someone cannot rest
solely on automated processing. In practice a police system almost never makes
the decision automatically — an officer does — but the officer's decision is only
meaningfully human if they can see what the machine did and disagree with it.
An unexplained community assignment produces rubber-stamping, which is automated
decision-making wearing a human's signature.

So the envelope has to answer, without the analyst reading source code:

  - What algorithm, which version, which backend, which seed, which resolution?
    (reproducibility — a defence expert must get the same answer from the same
    inputs, or the analysis cannot be relied on in proceedings)
  - How confident are we, and how was that confidence measured?
  - What was approximated, and where does the method break down?
  - What does this output NOT mean?

The last one is doing the most work. `NOT_ESTABLISHED` below is emitted verbatim
to the UI on every community panel. Without it, "community" reads as
"organisation" and "CONNECTOR_HUB" reads as "lieutenant", and the system starts
laundering graph topology into allegations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .community import (
    ALGORITHM_VERSION, Community, CommunityResult, MIN_COMMUNITY_SIZE,
    NodeAssignment, P_CONNECTOR, P_PERIPHERAL, Z_HUB,
)

# Mirrors MIN_DISCLOSABLE_STABILITY in the API's rules_common.py. Duplicated
# rather than imported because Z4 must not depend on the API package — the
# pseudonymity boundary is also a dependency boundary. tests/test_analytics.py
# asserts the two constants agree, so drift fails the build instead of silently
# widening what gets disclosed.
MIN_DISCLOSABLE_STABILITY = 0.6

# Emitted verbatim, every time. Not a disclaimer to be collapsed behind a
# tooltip: the frontend renders it as body text on the community panel.
NOT_ESTABLISHED: Tuple[str, ...] = (
    "A community is a set of records more densely connected to each other than "
    "to the rest of this dataset. It is not a finding that an organisation "
    "exists, nor that its members know each other.",
    "Membership is derived from the data held in this snapshot only. Absence "
    "from a community means the data does not connect that person here — not "
    "that no connection exists.",
    "Role descriptors (for example CONNECTOR_HUB) describe a pattern of "
    "connections in this dataset. They are not statements about a person's "
    "seniority, intent, or knowledge.",
    "These results are an investigative hypothesis to be tested against "
    "evidence. They are not evidence.",
)

METHOD_LIMITS: Tuple[str, ...] = (
    "Modularity-based detection has a resolution limit: it cannot reliably "
    "identify communities smaller than a threshold that grows with the size of "
    "the graph. Small groups inside a large dataset may be absorbed into larger "
    "ones.",
    "Communities are computed on evidence-weighted edges. Where evidence is "
    "graded unreliable (5x5x5 source 4-5 or assessment 4), its influence is "
    "reduced and it may be excluded entirely, so a real association supported "
    "only by weak intelligence may not appear.",
    "Secondary affiliations are detected from share of connection volume, not "
    "from higher-order structure. Overlaps visible only in denser local patterns "
    "will be missed.",
    "The analysis sees only what was lawfully collected and loaded into this "
    "snapshot. Collection bias in the source data becomes structural bias here: "
    "a group under active surveillance will appear denser than an equivalent "
    "group that is not, purely because more of its contact was recorded.",
)


@dataclass(frozen=True)
class DerivationEnvelope:
    """Accompanies every derived result crossing the API boundary."""

    # Reproducibility
    algorithm: str
    algorithm_version: str
    backend: str
    seed: int
    resolution: float
    snapshot_id: str
    computed_at: str

    # Inputs
    vertex_count: int
    edge_count: int
    weighting_scheme: str
    excluded_from_input: Tuple[str, ...]

    # Confidence
    stability: Optional[float]
    stability_method: str
    bootstrap_runs: int
    modularity: float
    disclosable: bool
    non_disclosure_reason: Optional[str]

    # Honesty
    not_established: Tuple[str, ...] = NOT_ESTABLISHED
    method_limits: Tuple[str, ...] = METHOD_LIMITS
    approximations: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()
    thresholds: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def require_disclosable(self) -> None:
        """Raise unless this result may be shown.

        Called by the API before serialization. The check lives here, next to the
        reason it exists, rather than in a route handler where the next route
        would forget it.
        """
        if not self.disclosable:
            raise ValueError(
                f"derived result is not disclosable: {self.non_disclosure_reason}"
            )


_INPUT_EXCLUSIONS: Tuple[str, ...] = (
    "victim and witness records (non-clusterable by data model)",
    "contact-only records beyond degree 1 of a subject",
    "records past their retention review date",
    "tombstoned (erased) records",
    "relationships graded 5x5x5 assessment 5 (suspected false)",
    "relationships whose confidence weight falls below the floor",
)

_STABILITY_METHOD = (
    "mean co-membership frequency with the same community's members across "
    "{runs} runs in which each relationship's weight was resampled within its "
    "own 5x5x5-derived confidence interval, and relationships falling below the "
    "confidence floor were dropped"
)


def _thresholds() -> Dict[str, Any]:
    return {
        "min_disclosable_stability": MIN_DISCLOSABLE_STABILITY,
        "min_community_size": MIN_COMMUNITY_SIZE,
        "hub_z_score": Z_HUB,
        "connector_participation": P_CONNECTOR,
        "peripheral_participation": P_PERIPHERAL,
        "note": (
            "These cut-points are conventions adopted for comparability with "
            "published method, not measured properties of criminal networks. "
            "z and P are reported numerically so a reviewer may apply their own."
        ),
    }


def _non_disclosure_reason(result: CommunityResult,
                           stability: Optional[float],
                           size: Optional[int]) -> Optional[str]:
    if stability is not None and stability < MIN_DISCLOSABLE_STABILITY:
        return (
            f"stability {stability:.2f} is below the disclosure threshold "
            f"{MIN_DISCLOSABLE_STABILITY:.2f}: this grouping changed when the "
            f"underlying evidence was varied within its own margin of error, so "
            f"it reflects the random seed as much as the data"
        )
    if size is not None and size < MIN_COMMUNITY_SIZE:
        return (
            f"group of {size} is below the minimum reportable size "
            f"{MIN_COMMUNITY_SIZE}"
        )
    primary = next((l for l in result.levels if l.level == result.primary_level), None)
    if primary is not None and primary.modularity < 0.15:
        return (
            f"projection modularity {primary.modularity:.3f} indicates no "
            f"meaningful community structure; any partition of it would be "
            f"close to arbitrary"
        )
    return None


def envelope_for_community(result: CommunityResult,
                           community: Community) -> DerivationEnvelope:
    """Envelope for one community panel."""
    primary = next((l for l in result.levels if l.level == community.level), None)
    reason = _non_disclosure_reason(result, community.stability, community.size)
    return DerivationEnvelope(
        algorithm="Leiden (RBConfiguration) with resolution sweep",
        algorithm_version=result.algorithm_version,
        backend=result.backend,
        seed=result.seed,
        resolution=community.resolution,
        snapshot_id=result.snapshot_id,
        computed_at=datetime.now(timezone.utc).isoformat(),
        vertex_count=result.vertex_count,
        edge_count=result.edge_count,
        weighting_scheme="5x5x5 confidence-weighted, log-damped volume",
        excluded_from_input=_INPUT_EXCLUSIONS,
        stability=community.stability,
        stability_method=_STABILITY_METHOD.format(runs=result.bootstrap_runs),
        bootstrap_runs=result.bootstrap_runs,
        modularity=primary.modularity if primary else 0.0,
        disclosable=reason is None,
        non_disclosure_reason=reason,
        approximations=tuple(result.approximations),
        warnings=tuple(result.warnings),
        thresholds=_thresholds(),
    )


def envelope_for_assignment(result: CommunityResult,
                            assignment: NodeAssignment) -> DerivationEnvelope:
    """Envelope for one person's structural position.

    Separate from the community envelope because the disclosability test is
    different: a community can be solid overall while one member's placement in
    it is a coin flip. Reporting that member's assignment on the strength of the
    community's aggregate stability would hide exactly the case where an
    individual is about to be wrongly associated with a group.
    """
    community = result.communities.get(assignment.community_id)
    reason = _non_disclosure_reason(
        result, assignment.stability, community.size if community else None
    )
    resolution = community.resolution if community else 0.0

    limits = list(METHOD_LIMITS)
    if assignment.is_multi_affiliated:
        limits.append(
            "This record has substantial connection volume to more than one "
            "community. Its primary assignment is the strongest of several and "
            "should not be read as exclusive."
        )
    if assignment.role in {"CONNECTOR_HUB", "BRIDGING", "DISPERSED_HUB"}:
        limits.append(
            "Bridging and hub descriptors are frequently produced by shared "
            "infrastructure and services — a taxi firm, a delivery driver, a "
            "solicitor, a corner shop — appearing between otherwise unconnected "
            "groups. Verify the nature of the connections before treating this "
            "position as significant."
        )

    return DerivationEnvelope(
        algorithm="Leiden (RBConfiguration) with resolution sweep; "
                  "Guimera-Amaral z-P role classification",
        algorithm_version=result.algorithm_version,
        backend=result.backend,
        seed=result.seed,
        resolution=resolution,
        snapshot_id=result.snapshot_id,
        computed_at=datetime.now(timezone.utc).isoformat(),
        vertex_count=result.vertex_count,
        edge_count=result.edge_count,
        weighting_scheme="5x5x5 confidence-weighted, log-damped volume",
        excluded_from_input=_INPUT_EXCLUSIONS,
        stability=assignment.stability,
        stability_method=_STABILITY_METHOD.format(runs=result.bootstrap_runs),
        bootstrap_runs=result.bootstrap_runs,
        modularity=next((l.modularity for l in result.levels
                         if l.level == assignment.level), 0.0),
        disclosable=reason is None,
        non_disclosure_reason=reason,
        approximations=tuple(result.approximations),
        warnings=tuple(result.warnings),
        method_limits=tuple(limits),
        thresholds=_thresholds(),
    )


def summarise_for_review(result: CommunityResult) -> Dict[str, Any]:
    """The payload a supervisor sees on the human-review gate before export.

    LED-DENY-ART11-AUTOMATED-DECISION blocks export of derived data until a human
    review is recorded. This is what that human reads. It leads with what is
    wrong with the result, because a review screen that leads with the findings
    gets approved on the findings.
    """
    assignments = list(result.assignments.values())
    unstable = [a for a in assignments if a.stability < MIN_DISCLOSABLE_STABILITY]
    multi = [a for a in assignments if a.is_multi_affiliated]
    reportable = [c for c in result.communities.values()
                  if c.level == result.primary_level
                  and c.size >= MIN_COMMUNITY_SIZE]

    return {
        "review_required_because": (
            "This export contains automated characterisations of identifiable "
            "people. It may not leave the system until a named reviewer records "
            "that they have considered the limitations below."
        ),
        "snapshot_id": result.snapshot_id,
        "algorithm_version": result.algorithm_version,
        "backend": result.backend,
        "reproducible_with_seed": result.seed,
        "warnings": list(result.warnings),
        "approximations": list(result.approximations),
        "counts": {
            "vertices": result.vertex_count,
            "edges": result.edge_count,
            "reportable_communities": len(reportable),
            "assignments_below_disclosure_threshold": len(unstable),
            "multi_affiliated_records": len(multi),
            "unclustered_records": sum(
                1 for a in assignments if a.community_id == "UNCLUSTERED"
            ),
        },
        "reviewer_must_confirm": [
            "I have read the stated limitations of this analysis.",
            "I understand these communities are hypotheses, not findings.",
            f"I accept that {len(unstable)} record(s) fall below the stability "
            f"threshold and are withheld from the export.",
            "Any investigative action taken will rest on my own assessment of "
            "the underlying evidence, not on this output alone.",
        ],
        "not_established": list(NOT_ESTABLISHED),
        "method_limits": list(METHOD_LIMITS),
    }
