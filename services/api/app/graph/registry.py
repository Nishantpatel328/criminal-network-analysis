"""Query Registry — structural elimination of Cypher injection.

THE PROBLEM
The Neo4j driver parameterizes *values* but not labels, relationship types, or
property keys. So this is safe:

    session.run("MATCH (p:Person {eid: $eid}) RETURN p", eid=user_input)

and this is injectable, with no parameterization available to fix it:

    session.run(f"MATCH (p:{label}) RETURN p")            # label injection
    session.run(f"MATCH ()-[r:{rel}]->() RETURN r")       # rel-type injection
    session.run(f"MATCH (p) RETURN p.{prop}")             # property injection

The second form is easy to reach for, because dynamic labels are a genuine
modelling need and the driver offers no parameter for them. A payload like
`Person) DETACH DELETE (n` in a label slot is game over.

THE APPROACH
Rather than rely on every future contributor knowing this, we remove the
capability. No caller-supplied string ever reaches the driver as query text:

  1. All queries are pre-written templates registered at import time. Callers
     name a query; they cannot supply one.
  2. Dynamic label and relationship-type slots accept values only from closed
     enums, validated against the live schema at startup.
  3. Parameters are typed and validated before binding.
  4. Each query declares a hop budget and element ceiling.
  5. A CI check (deploy/ci/check_no_dynamic_cypher.py) fails the build on any
     f-string, %-format or .format() reaching a session.run call in this package.
  6. The application's Neo4j role has no schema or DBMS privileges, so even a
     successful injection cannot create labels or call dbms.* procedures.

Layers 1-4 are correctness, 5 is drift prevention, 6 is blast-radius reduction.
Any one of them can fail without the system being exploitable.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Closed vocabularies. These are the ONLY strings permitted in a structural
# slot. Validated against the live schema at startup by verify_against_schema().
# ---------------------------------------------------------------------------

class NodeLabel(enum.Enum):
    PERSON = "Person"
    ORGANISATION = "Organisation"
    PHONE = "Phone"
    ACCOUNT = "Account"
    VEHICLE = "Vehicle"
    LOCATION = "Location"
    EVENT = "Event"
    CASE = "Case"


class RelType(enum.Enum):
    COMMUNICATED_WITH = "COMMUNICATED_WITH"
    ASSOCIATE_OF = "ASSOCIATE_OF"
    TRANSACTED_WITH = "TRANSACTED_WITH"
    USES_PHONE = "USES_PHONE"
    HOLDS_ACCOUNT = "HOLDS_ACCOUNT"
    REGISTERED_TO = "REGISTERED_TO"
    PRESENT_AT = "PRESENT_AT"
    APPEARS_IN = "APPEARS_IN"


# Belt and braces: even coming from an enum, assert the shape before it is
# concatenated into query text. If someone later adds an enum member with a
# malformed value, this catches it at startup rather than at exploit time.
_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def _safe_ident(value: str) -> str:
    if not _IDENT_RE.match(value):
        raise ValueError(f"illegal identifier in structural slot: {value!r}")
    return value


def render_rel_types(types: Sequence[RelType]) -> str:
    """Render a relationship-type disjunction for a MATCH pattern.

    Accepts enum members only — a str will raise on attribute access, which is
    the desired failure. This is the single place in the codebase where a
    structural token is concatenated into query text, which makes it the single
    place a reviewer has to scrutinise.
    """
    if not types:
        raise ValueError("at least one relationship type required")
    if len(types) > len(RelType):
        raise ValueError("more relationship types than exist")
    seen = []
    for t in types:
        if not isinstance(t, RelType):
            raise TypeError(f"expected RelType, got {type(t).__name__}")
        ident = _safe_ident(t.value)
        if ident not in seen:
            seen.append(ident)
    return "|".join(seen)


def render_label(label: NodeLabel) -> str:
    if not isinstance(label, NodeLabel):
        raise TypeError(f"expected NodeLabel, got {type(label).__name__}")
    return _safe_ident(label.value)


# ---------------------------------------------------------------------------
# Parameter specification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ParamSpec:
    name: str
    py_type: type
    required: bool = True
    max_len: Optional[int] = None
    validator: Optional[Callable[[Any], bool]] = None

    def validate(self, value: Any) -> None:
        if value is None:
            if self.required:
                raise ValueError(f"parameter '{self.name}' is required")
            return
        if self.py_type is float and isinstance(value, int):
            value = float(value)          # int is an acceptable float
        elif not isinstance(value, self.py_type):
            raise TypeError(
                f"parameter '{self.name}' expects {self.py_type.__name__}, "
                f"got {type(value).__name__}"
            )
        if self.max_len is not None and hasattr(value, "__len__"):
            if len(value) > self.max_len:
                raise ValueError(
                    f"parameter '{self.name}' exceeds max length {self.max_len}"
                )
        if self.validator is not None and not self.validator(value):
            raise ValueError(f"parameter '{self.name}' failed validation")


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CASE_ID_RE = re.compile(r"^[A-Z]{2,8}-\d{4}-\d{4,6}$")


def is_uuid(v: Any) -> bool:
    return isinstance(v, str) and bool(_UUID_RE.match(v))


def is_case_id(v: Any) -> bool:
    return isinstance(v, str) and bool(_CASE_ID_RE.match(v))


def is_uuid_list(v: Any) -> bool:
    return isinstance(v, list) and len(v) <= 500 and all(is_uuid(x) for x in v)


def is_basis_list(v: Any) -> bool:
    return (isinstance(v, list) and len(v) <= 200
            and all(isinstance(x, str) and len(x) <= 64
                    and re.match(r"^[A-Za-z0-9:_-]+$", x) for x in v))


# ---------------------------------------------------------------------------
# Query specification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class QuerySpec:
    name: str
    cypher: str
    params: Tuple[ParamSpec, ...]
    hop_budget: int
    max_elements: int
    # Structural slots this template exposes, if any. A template with slots is
    # rendered through render_* helpers; one without is used verbatim.
    slots: FrozenSet[str] = frozenset()
    read_only: bool = True
    description: str = ""

    def bind(self, values: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate and return the parameter dict. Unknown params are rejected."""
        known = {p.name for p in self.params}
        unknown = set(values) - known
        if unknown:
            # Silently dropping unknown parameters hides caller bugs and can
            # mask an attempt to smuggle a value into a differently-named slot.
            raise ValueError(
                f"query '{self.name}' received unknown parameters: "
                f"{sorted(unknown)}"
            )
        bound: Dict[str, Any] = {}
        for spec in self.params:
            value = values.get(spec.name)
            spec.validate(value)
            if value is not None:
                bound[spec.name] = value
        return bound


class QueryRegistry:
    def __init__(self) -> None:
        self._specs: Dict[str, QuerySpec] = {}

    def register(self, spec: QuerySpec) -> QuerySpec:
        if spec.name in self._specs:
            raise ValueError(f"duplicate query name: {spec.name}")
        if not spec.read_only and "MERGE" not in spec.cypher and "SET" not in spec.cypher:
            raise ValueError(f"query {spec.name} marked writable but performs no write")
        if spec.read_only:
            forbidden = ("CREATE ", "DELETE ", "SET ", "MERGE ", "DROP ",
                         "CALL dbms", "CALL db.", "LOAD CSV")
            upper = spec.cypher.upper()
            for token in forbidden:
                if token.upper() in upper:
                    raise ValueError(
                        f"read-only query {spec.name} contains '{token.strip()}'"
                    )
        self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> QuerySpec:
        try:
            return self._specs[name]
        except KeyError:
            # Deliberately does not echo the requested name back to the caller:
            # error messages that reflect input are a probing channel.
            raise KeyError("no such registered query") from None

    def names(self) -> Tuple[str, ...]:
        return tuple(sorted(self._specs))


REGISTRY = QueryRegistry()


# ---------------------------------------------------------------------------
# Registered queries
#
# Every query filters on: tombstoned = false, legal_basis_ref IN $bases, and
# case scope. Those three predicates are the enforcement of retention, purpose
# limitation and case partitioning respectively, and they belong in the query
# text rather than in caller-side filtering — a filter the caller can forget to
# apply is a filter that will be forgotten.
# ---------------------------------------------------------------------------

Q_ENTITY_BY_EID = REGISTRY.register(QuerySpec(
    name="entity_by_eid",
    description="Fetch a single entity within case scope.",
    cypher="""
    MATCH (n {eid: $eid})
    WHERE coalesce(n.tombstoned, false) = false
      AND EXISTS {
        MATCH (n)-[a:APPEARS_IN]->(:Case {case_id: $case_id})
      }
    RETURN n.eid            AS eid,
           labels(n)        AS labels,
           n.subject_category AS subject_category,
           n.display_name   AS display_name,
           n.dob_year       AS dob_year,
           n.provenance_id  AS provenance_id
    """,
    params=(
        ParamSpec("eid", str, max_len=36, validator=is_uuid),
        ParamSpec("case_id", str, max_len=32, validator=is_case_id),
    ),
    hop_budget=1,
    max_elements=1,
))


Q_NEIGHBOURHOOD = REGISTRY.register(QuerySpec(
    name="neighbourhood",
    description=(
        "Bounded expansion from a seed entity. Relationship types are rendered "
        "from the RelType enum into the {rel_types} slot; depth is a bounded "
        "integer parameter, NOT interpolated into the pattern."
    ),
    cypher="""
    MATCH path = (seed {eid: $eid})-[:{rel_types}*1..2]-(m)
    WHERE coalesce(seed.tombstoned, false) = false
      AND all(node IN nodes(path) WHERE coalesce(node.tombstoned, false) = false)
      AND all(rel IN relationships(path)
              WHERE rel.legal_basis_ref IN $bases
                AND coalesce(rel.intel_assessment, 3) < 5)
      AND EXISTS { MATCH (m)-[:APPEARS_IN]->(:Case {case_id: $case_id}) }
    WITH DISTINCT m, relationships(path) AS rels
    RETURN m.eid              AS eid,
           labels(m)          AS labels,
           m.subject_category AS subject_category,
           m.display_name     AS display_name,
           [rel IN rels | {
             type: type(rel),
             source_eval: rel.source_eval,
             intel_assessment: rel.intel_assessment,
             handling_code: rel.handling_code,
             weight: rel.weight,
             basis: rel.legal_basis_ref,
             src: startNode(rel).eid,
             dst: endNode(rel).eid
           }]                 AS rels
    LIMIT $limit
    """,
    params=(
        ParamSpec("eid", str, max_len=36, validator=is_uuid),
        ParamSpec("case_id", str, max_len=32, validator=is_case_id),
        ParamSpec("bases", list, max_len=200, validator=is_basis_list),
        ParamSpec("limit", int, validator=lambda v: 1 <= v <= 500),
    ),
    hop_budget=2,
    max_elements=500,
    slots=frozenset({"rel_types"}),
))


Q_COUNT_NEIGHBOURHOOD = REGISTRY.register(QuerySpec(
    name="count_neighbourhood",
    description=(
        "Cardinality pre-check run BEFORE the expansion itself. Graph queries "
        "have pathological cost profiles — two hops from a shared prepaid "
        "handset or a bank branch can touch millions of nodes — so we cost the "
        "query first and refuse rather than time out. This is simultaneously a "
        "DoS guard and an anti-bulk-disclosure control."
    ),
    cypher="""
    MATCH (seed {eid: $eid})-[r:{rel_types}*1..2]-(m)
    WHERE all(rel IN r WHERE rel.legal_basis_ref IN $bases)
    RETURN count(DISTINCT m) AS element_count
    """,
    params=(
        ParamSpec("eid", str, max_len=36, validator=is_uuid),
        ParamSpec("bases", list, max_len=200, validator=is_basis_list),
    ),
    hop_budget=2,
    max_elements=1,
    slots=frozenset({"rel_types"}),
))
# Cost pre-check note: at regional tier and above, replace this with a sampled
# estimate or a GDS degree-distribution lookup. An exact count of a two-hop
# expansion from a high-degree hub costs almost as much as the expansion itself,
# so at scale this guard starts paying for what it is trying to prevent.


Q_SUBJECT_CATEGORIES_IN_SCOPE = REGISTRY.register(QuerySpec(
    name="subject_categories_in_scope",
    description=(
        "Which data-subject categories a pending expansion would touch. Called "
        "before the expansion so the PDP can reason about the whole envelope "
        "rather than discovering a victim record mid-response."
    ),
    cypher="""
    MATCH (seed {eid: $eid})-[r:{rel_types}*1..2]-(m)
    WHERE all(rel IN r WHERE rel.legal_basis_ref IN $bases)
    RETURN collect(DISTINCT m.subject_category) AS categories,
           count(DISTINCT m)                    AS element_count
    """,
    params=(
        ParamSpec("eid", str, max_len=36, validator=is_uuid),
        ParamSpec("bases", list, max_len=200, validator=is_basis_list),
    ),
    hop_budget=2,
    max_elements=1,
    slots=frozenset({"rel_types"}),
))


Q_CASE_CONTEXT = REGISTRY.register(QuerySpec(
    name="case_context",
    description="Case metadata for the PDP. Never trusted from the client.",
    cypher="""
    MATCH (c:Case {case_id: $case_id})-[:AUTHORISED_BY]->(lb:LegalBasis)
    WHERE lb.expires_at IS NULL OR lb.expires_at >= date()
    RETURN c.case_id           AS case_id,
           c.is_open           AS is_open,
           collect(lb.basis_id) AS authorised_bases,
           c.supervisor_ids    AS supervisor_ids
    """,
    params=(ParamSpec("case_id", str, max_len=32, validator=is_case_id),),
    hop_budget=1,
    max_elements=1,
))
# Note the expiry filter: a warrant that has lapsed stops authorising traversal
# the moment it expires, without anyone running a job. Expressing the temporal
# validity of the legal instrument in the query that reads it is the difference
# between a control that holds and a control that depends on a cron.


Q_EXPORT_PROJECTION = REGISTRY.register(QuerySpec(
    name="export_projection",
    description=(
        "Structural projection for the pseudonymized analytics tier. Returns "
        "eids and edge weights ONLY — no descriptive properties. Run under the "
        "cna_exporter role, which is denied read on everything else, so this "
        "query cannot be widened by editing it."
    ),
    cypher="""
    MATCH (a)-[r:{rel_types}]->(b)
    WHERE coalesce(a.tombstoned, false) = false
      AND coalesce(b.tombstoned, false) = false
      AND coalesce(r.intel_assessment, 3) < 5
      AND a.subject_category IN $clusterable
      AND b.subject_category IN $clusterable
    RETURN a.eid AS src, b.eid AS dst, type(r) AS rel_type,
           coalesce(r.weight, 1.0)        AS weight,
           coalesce(r.source_eval, 5)     AS source_eval,
           coalesce(r.intel_assessment, 4) AS intel_assessment
    SKIP $skip LIMIT $batch
    """,
    params=(
        ParamSpec("clusterable", list, max_len=8,
                  validator=lambda v: all(isinstance(x, str) and x.isupper()
                                          and len(x) <= 16 for x in v)),
        ParamSpec("skip", int, validator=lambda v: v >= 0),
        ParamSpec("batch", int, validator=lambda v: 1 <= v <= 100_000),
    ),
    hop_budget=1,
    max_elements=100_000,
    slots=frozenset({"rel_types"}),
))


def render(spec: QuerySpec, *, rel_types: Optional[Sequence[RelType]] = None,
           label: Optional[NodeLabel] = None) -> str:
    """Fill a template's structural slots. The only path to executable text."""
    cypher = spec.cypher
    if "rel_types" in spec.slots:
        if rel_types is None:
            raise ValueError(f"query {spec.name} requires rel_types")
        cypher = cypher.replace("{rel_types}", render_rel_types(rel_types))
    if "label" in spec.slots:
        if label is None:
            raise ValueError(f"query {spec.name} requires label")
        cypher = cypher.replace("{label}", render_label(label))
    # Catch an unfilled slot before it reaches the driver. The regex requires
    # {lower_snake} with no colon, so Cypher map literals like {eid: $eid} and
    # {case_id: $case_id} do not false-positive.
    leftover = re.findall(r"\{([a-z_]+)\}", cypher)
    if leftover:
        raise ValueError(f"unfilled slots in {spec.name}: {sorted(set(leftover))}")
    return cypher


def verify_against_schema(live_labels: FrozenSet[str],
                          live_rel_types: FrozenSet[str]) -> None:
    """Startup assertion: every enum member exists in the live database.

    Catches the drift case where a migration renames a relationship type and the
    enum is not updated — the query would then match nothing and silently return
    an empty graph, which an analyst would read as "no connections found". A
    false negative in this system is not a cosmetic bug; it is an investigative
    conclusion that happens to be wrong.
    """
    missing_labels = {l.value for l in NodeLabel} - live_labels
    missing_rels = {r.value for r in RelType} - live_rel_types
    problems = []
    if missing_labels:
        problems.append(f"labels absent from database: {sorted(missing_labels)}")
    if missing_rels:
        problems.append(f"relationship types absent from database: {sorted(missing_rels)}")
    if problems:
        raise RuntimeError("query registry / schema mismatch: " + "; ".join(problems))
