"""Field-level redaction — the enforcement side of the PDP's obligations.

The design rule here is deny-by-default on fields, not allow-by-default. A
projection whitelist means that adding a new property to the graph does not
automatically expose it through the API; someone has to add it to a view
explicitly. The alternative — blacklisting sensitive fields — leaks every field
anyone forgets to blacklist, and in a schema that grows over years, that is a
certainty rather than a risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional

from .models import Obligation

# Properties that must never leave the API tier under any obligation set. These
# are not "redact unless permitted" — there is no code path that emits them.
NEVER_EMIT: FrozenSet[str] = frozenset({
    "ethnicity", "religion", "health_notes", "political_affiliation",
    "trade_union", "sexual_orientation", "biometric_template",
    "ni_number", "ssn", "pan_plain",
    # Internal machinery that would leak infrastructure detail or defeat
    # pseudonymity if echoed back to a client.
    "surrogate_key", "crosswalk_token", "_neo4j_element_id",
})

# Whitelisted output fields per entity view.
ENTITY_VIEW: FrozenSet[str] = frozenset({
    "eid", "labels", "subject_category", "display_name", "dob_year",
    "provenance_id", "primary_case",
})

RELATIONSHIP_VIEW: FrozenSet[str] = frozenset({
    "type", "source_eval", "intel_assessment", "handling_code",
    "weight", "basis", "valid_from", "valid_to",
    # Endpoints are required by the canvas; without them an expansion is a
    # bag of nodes with no drawable connections.
    "src", "dst",
})

COMMUNITY_VIEW: FrozenSet[str] = frozenset({
    "community_id", "level", "stability", "role", "participation_coefficient",
    "within_module_degree", "derivation",
    "size", "member_surrogates",
})

REDACTED = "[REDACTED]"
WITHHELD = "[WITHHELD — INSUFFICIENT STABILITY]"


@dataclass(frozen=True)
class RedactionReport:
    """What was removed, for the response envelope.

    Telling the analyst that four fields were redacted — without saying what
    they contained — is deliberate. Silent redaction produces analysts who
    believe they are seeing the whole record, and an analyst who does not know
    something was withheld cannot ask for it through the proper channel. It also
    keeps us honest: an unexpected redaction count is a visible signal that the
    policy is doing something surprising.
    """
    fields_redacted: int
    fields_withheld: int
    notes: tuple


class Redactor:
    """Applies an obligation set to outbound records."""

    # Obligations this enforcement point understands. Passed to policy.enforce,
    # which converts a permit carrying anything else into a deny.
    SUPPORTED: FrozenSet[Obligation] = frozenset({
        Obligation.REDACT_SPECIAL_CATEGORY,
        Obligation.REDACT_PLAIN_IDENTIFIERS,
        Obligation.REDACT_PRECISE_DOB,
        Obligation.WITHHOLD_LOW_STABILITY,
        Obligation.HYPOTHESIS_FRAMING,
        Obligation.MINIMISE_TO_DEGREE_1,
        Obligation.WATERMARK_OUTPUT,
        Obligation.PROTECTED_SUBJECT_POOL,
        Obligation.SUPERVISOR_NOTIFY,
        Obligation.HIGH_SALIENCE_AUDIT,
        Obligation.SESSION_REAUTH_15M,
        Obligation.RATE_LIMIT_STRICT,
    })

    def __init__(self, obligations: Iterable[Obligation]) -> None:
        self._obl = frozenset(obligations)
        unsupported = self._obl - self.SUPPORTED
        if unsupported:
            raise ValueError(
                f"Redactor cannot honour: {sorted(o.value for o in unsupported)}"
            )

    def _project(self, record: Mapping[str, Any],
                 view: FrozenSet[str]) -> tuple:
        """Whitelist projection. Returns the record and how many keys it dropped.

        The count matters. The whitelist runs first, so a field like
        `msisdn_plain` is dropped here and never reaches the explicit masking
        loop below — which means without counting drops, a record that genuinely
        had an identifier stripped would be reported as "0 fields redacted".
        That is exactly the silent redaction this class exists to avoid: the
        analyst is told the record is whole when it is not.

        Dropping rather than masking is the right mechanism (a masked key still
        tells you the field exists), so the fix is to count, not to reorder.
        """
        out = {k: v for k, v in record.items()
               if k in view and k not in NEVER_EMIT}
        return out, len(record) - len(out)

    def entity(self, record: Mapping[str, Any]) -> tuple:
        # Nested relationships travel with neighbourhood rows (Q_NEIGHBOURHOOD
        # aliases them `rels`). They are not in ENTITY_VIEW — putting them there
        # would let an unprojected map leak — so they are projected separately
        # through relationship() and reattached as `edges`, which is the name
        # the workstation contract uses.
        nested = record.get("rels")
        if nested is None:
            nested = record.get("edges")
        out, redacted = self._project(record, ENTITY_VIEW)
        notes: List[str] = []

        if Obligation.REDACT_PRECISE_DOB in self._obl:
            # dob_year only ever leaves the store as a year, but an explicit
            # coarsening step here means the control survives someone widening
            # ENTITY_VIEW to include a precise date later.
            if "dob_exact" in out:
                out.pop("dob_exact")
                redacted += 1
            if isinstance(out.get("dob_year"), int):
                out["dob_year"] = (out["dob_year"] // 5) * 5
                notes.append("date of birth coarsened to 5-year band")

        if Obligation.REDACT_PLAIN_IDENTIFIERS in self._obl:
            for key in ("msisdn_plain", "iban_plain", "vrm_plain",
                        "imei_plain", "address_plain"):
                if key in out:
                    out[key] = REDACTED
                    redacted += 1

        # Unconditional, regardless of obligations.
        for key in list(out):
            if key in NEVER_EMIT:
                out.pop(key)
                redacted += 1

        if isinstance(nested, list):
            edges = []
            for rel in nested:
                if isinstance(rel, Mapping):
                    edges.append(self.relationship(rel))
            out["edges"] = edges

        return out, RedactionReport(redacted, 0, tuple(notes))

    def relationship(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        out, _dropped = self._project(record, RELATIONSHIP_VIEW)
        # Confidence metadata is never redacted. An edge without its 5x5x5
        # evaluation renders as though it were established fact, which is a
        # worse outcome than not showing the edge at all.
        for required in ("source_eval", "intel_assessment"):
            if required not in out:
                raise ValueError(
                    f"relationship record missing {required}; refusing to emit "
                    f"an unevaluated edge"
                )
        return out

    def community(self, record: Mapping[str, Any]) -> tuple:
        out, redacted = self._project(record, COMMUNITY_VIEW)
        notes: List[str] = []
        withheld = 0

        # Analytics emits `members`; the workstation contract is
        # `member_surrogates`. Accept either so a store that forwards the worker
        # result unchanged still names the field the UI expects.
        if "member_surrogates" not in out and "members" in record:
            members = record["members"]
            if isinstance(members, (list, tuple)):
                out["member_surrogates"] = list(members)
        if "size" not in out and "members" in record:
            members = record["members"]
            if isinstance(members, (list, tuple)):
                out["size"] = len(members)

        if Obligation.HYPOTHESIS_FRAMING in self._obl:
            out["presentation"] = "HYPOTHESIS"
            out["disclaimer"] = (
                "Algorithmically derived structural grouping. Not a finding of "
                "fact, not evidence of association, and not a basis for action "
                "against any individual without independent corroboration."
            )
            notes.append("hypothesis framing applied")

        if Obligation.WITHHOLD_LOW_STABILITY in self._obl:
            # Withhold the assignment but keep the stability score visible, so
            # the analyst can see that a computation happened and was judged
            # unreliable. Hiding the score too would look like missing data.
            for key in ("community_id", "level", "role",
                        "participation_coefficient", "within_module_degree"):
                if key in out:
                    out[key] = WITHHELD
                    withheld += 1
            out["withheld_reason"] = (
                "Community assignment is unstable under edge-weight "
                "perturbation and is not sufficiently reliable to disclose."
            )
            notes.append("low-stability assignment withheld")

        if "derivation" not in out:
            raise ValueError(
                "community record lacks a derivation envelope; refusing to emit"
            )
        return out, RedactionReport(redacted, withheld, tuple(notes))

    def watermark(self, actor_id: str, case_id: Optional[str],
                  at_iso: str) -> Optional[Dict[str, str]]:
        """Watermark descriptor for the client to render onto the canvas.

        Rendering happens client-side because the payload is JSON, not an image.
        That means a determined user can strip it, and this control is therefore
        about attribution of casual leaks — the photographed screen, the pasted
        screenshot — not about stopping a motivated exfiltrator. Recorded as a
        known limitation (R-09) rather than presented as prevention.
        """
        if Obligation.WATERMARK_OUTPUT not in self._obl:
            return None
        return {
            "actor": actor_id,
            "case": case_id or "-",
            "at": at_iso,
            "text": f"{actor_id} · {case_id or '-'} · {at_iso}",
        }

    @property
    def session_reauth_seconds(self) -> Optional[int]:
        return 900 if Obligation.SESSION_REAUTH_15M in self._obl else None

    @property
    def requires_protected_pool(self) -> bool:
        return Obligation.PROTECTED_SUBJECT_POOL in self._obl

    @property
    def notify_supervisor(self) -> bool:
        return Obligation.SUPERVISOR_NOTIFY in self._obl

    @property
    def max_degree(self) -> Optional[int]:
        return 1 if Obligation.MINIMISE_TO_DEGREE_1 in self._obl else None
