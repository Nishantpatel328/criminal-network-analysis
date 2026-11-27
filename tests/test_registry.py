"""Query registry / Cypher injection tests.

Each test in TestInjection corresponds to a real injection technique against
Neo4j. The driver parameterizes values but not structural tokens, so these are
the cases that a naive f-string implementation would fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "api"))

from app.graph.registry import (  # noqa: E402
    NodeLabel, ParamSpec, QueryRegistry, QuerySpec, REGISTRY, RelType,
    Q_NEIGHBOURHOOD, is_basis_list, is_case_id, is_uuid, is_uuid_list,
    render, render_label, render_rel_types, verify_against_schema,
)

GOOD_UUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
GOOD_CASE = "NCA-2026-0412"


class TestInjection:
    def test_raw_string_rejected_as_relationship_type(self):
        """The core attack. A string in a structural slot must not be accepted
        even if it looks harmless."""
        with pytest.raises(TypeError):
            render_rel_types(["COMMUNICATED_WITH"])

    def test_injection_payload_in_rel_type_slot_rejected(self):
        with pytest.raises(TypeError):
            render_rel_types(["COMMUNICATED_WITH]->() DETACH DELETE (n"])

    def test_raw_string_rejected_as_label(self):
        with pytest.raises(TypeError):
            render_label("Person")

    def test_label_injection_payload_rejected(self):
        with pytest.raises(TypeError):
            render_label("Person) DETACH DELETE (n) //")

    def test_enum_members_render_to_safe_identifiers(self):
        out = render_rel_types([RelType.COMMUNICATED_WITH, RelType.ASSOCIATE_OF])
        assert out == "COMMUNICATED_WITH|ASSOCIATE_OF"
        for ch in "(){}[]-> ;/\\'\"":
            assert ch not in out

    def test_empty_rel_type_list_rejected(self):
        with pytest.raises(ValueError):
            render_rel_types([])

    def test_duplicate_rel_types_deduplicated(self):
        out = render_rel_types([RelType.ASSOCIATE_OF, RelType.ASSOCIATE_OF])
        assert out == "ASSOCIATE_OF"

    def test_unfilled_slot_raises_before_reaching_driver(self):
        with pytest.raises(ValueError, match="requires rel_types"):
            render(Q_NEIGHBOURHOOD)

    def test_rendered_query_has_no_remaining_slots(self):
        cypher = render(Q_NEIGHBOURHOOD, rel_types=[RelType.COMMUNICATED_WITH])
        assert "{rel_types}" not in cypher
        # Cypher map literals must survive the leftover-slot check.
        assert "{eid: $eid}" in cypher


class TestParameterValidation:
    def test_unknown_parameter_rejected(self):
        """Silently dropping an unknown parameter hides caller bugs and could
        mask an attempt to smuggle a value into a differently-named slot."""
        with pytest.raises(ValueError, match="unknown parameters"):
            Q_NEIGHBOURHOOD.bind({
                "eid": GOOD_UUID, "case_id": GOOD_CASE,
                "bases": ["W-1"], "limit": 10, "evil": "payload",
            })

    def test_missing_required_parameter_rejected(self):
        with pytest.raises(ValueError, match="required"):
            Q_NEIGHBOURHOOD.bind({"eid": GOOD_UUID})

    def test_wrong_type_rejected(self):
        with pytest.raises(TypeError):
            Q_NEIGHBOURHOOD.bind({
                "eid": GOOD_UUID, "case_id": GOOD_CASE,
                "bases": ["W-1"], "limit": "10",
            })

    def test_malformed_uuid_rejected(self):
        with pytest.raises(ValueError):
            Q_NEIGHBOURHOOD.bind({
                "eid": "not-a-uuid", "case_id": GOOD_CASE,
                "bases": ["W-1"], "limit": 10,
            })

    def test_limit_out_of_range_rejected(self):
        for bad in (0, -1, 100_000):
            with pytest.raises(ValueError):
                Q_NEIGHBOURHOOD.bind({
                    "eid": GOOD_UUID, "case_id": GOOD_CASE,
                    "bases": ["W-1"], "limit": bad,
                })

    def test_valid_bind_succeeds(self):
        bound = Q_NEIGHBOURHOOD.bind({
            "eid": GOOD_UUID, "case_id": GOOD_CASE,
            "bases": ["W-1", "PO-77"], "limit": 200,
        })
        assert bound["limit"] == 200
        assert bound["bases"] == ["W-1", "PO-77"]

    def test_oversized_basis_list_rejected(self):
        with pytest.raises(ValueError):
            Q_NEIGHBOURHOOD.bind({
                "eid": GOOD_UUID, "case_id": GOOD_CASE,
                "bases": [f"W-{i}" for i in range(500)], "limit": 10,
            })

    def test_basis_with_injection_characters_rejected(self):
        assert not is_basis_list(["W-1' OR 1=1 //"])
        assert not is_basis_list(["W-1 UNION MATCH (n) RETURN n"])
        assert is_basis_list(["W-1", "PO:2026:44", "MLAT_9"])


class TestValidators:
    def test_uuid_validator(self):
        assert is_uuid(GOOD_UUID)
        assert not is_uuid("3f2504e0-4f89-41d3-9a0c")
        assert not is_uuid(GOOD_UUID.upper())   # canonical lowercase only
        assert not is_uuid(None)

    def test_case_id_validator(self):
        assert is_case_id("NCA-2026-0412")
        assert not is_case_id("nca-2026-0412")
        assert not is_case_id("NCA-2026-0412; MATCH (n) DETACH DELETE n")

    def test_uuid_list_bounded(self):
        assert is_uuid_list([GOOD_UUID] * 10)
        assert not is_uuid_list([GOOD_UUID] * 501)
        assert not is_uuid_list([GOOD_UUID, "nope"])


class TestRegistryDiscipline:
    def test_unknown_query_name_does_not_echo_input(self):
        """Error messages that reflect caller input are a probing channel."""
        try:
            REGISTRY.get("please_give_me_everything")
        except KeyError as exc:
            assert "please_give_me_everything" not in str(exc)
        else:
            pytest.fail("expected KeyError")

    def test_duplicate_registration_rejected(self):
        reg = QueryRegistry()
        spec = QuerySpec(name="dup", cypher="MATCH (n) RETURN n",
                         params=(), hop_budget=1, max_elements=1)
        reg.register(spec)
        with pytest.raises(ValueError, match="duplicate"):
            reg.register(spec)

    def test_read_only_query_containing_write_clause_rejected(self):
        reg = QueryRegistry()
        with pytest.raises(ValueError, match="read-only"):
            reg.register(QuerySpec(
                name="sneaky",
                cypher="MATCH (n:Person) DETACH DELETE n RETURN 1",
                params=(), hop_budget=1, max_elements=1, read_only=True,
            ))

    def test_read_only_query_calling_dbms_procedure_rejected(self):
        reg = QueryRegistry()
        with pytest.raises(ValueError, match="read-only"):
            reg.register(QuerySpec(
                name="proc",
                cypher="CALL dbms.showCurrentUser() YIELD username RETURN username",
                params=(), hop_budget=1, max_elements=1, read_only=True,
            ))

    def test_every_registered_query_declares_budgets(self):
        for name in REGISTRY.names():
            spec = REGISTRY.get(name)
            assert spec.hop_budget >= 1, f"{name} has no hop budget"
            assert spec.max_elements >= 1, f"{name} has no element ceiling"

    def test_every_read_query_filters_tombstones_or_is_exempt(self):
        """Retention enforcement must be in the query text, not caller-side.

        Exemptions are explicit and few: metadata queries that touch no subject
        data, and the counting queries whose whole purpose is cost estimation
        before any data is returned.
        """
        exempt = {"case_context", "count_neighbourhood",
                  "subject_categories_in_scope"}
        for name in REGISTRY.names():
            if name in exempt:
                continue
            cypher = REGISTRY.get(name).cypher
            assert "tombstoned" in cypher, f"{name} does not filter tombstones"


class TestSchemaDrift:
    def test_missing_relationship_type_detected(self):
        """A migration that renames a relationship type would otherwise make
        queries silently return nothing — which an analyst reads as 'no
        connections found'. A false negative here is a wrong investigative
        conclusion, not a cosmetic bug."""
        live_labels = frozenset(l.value for l in NodeLabel)
        live_rels = frozenset(r.value for r in RelType) - {"ASSOCIATE_OF"}
        with pytest.raises(RuntimeError, match="relationship types absent"):
            verify_against_schema(live_labels, live_rels)

    def test_missing_label_detected(self):
        live_labels = frozenset(l.value for l in NodeLabel) - {"Vehicle"}
        live_rels = frozenset(r.value for r in RelType)
        with pytest.raises(RuntimeError, match="labels absent"):
            verify_against_schema(live_labels, live_rels)

    def test_matching_schema_passes(self):
        verify_against_schema(
            frozenset(l.value for l in NodeLabel),
            frozenset(r.value for r in RelType),
        )
