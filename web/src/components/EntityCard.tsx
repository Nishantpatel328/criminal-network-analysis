/**
 * The selection card: one record, and an honest account of what is missing.
 *
 * The redaction-aware part is the whole point. The API returns counts, not field
 * names, and this component must not try to reverse that. It renders the fields
 * that arrived, then states how many were held back — without guessing what they
 * were.
 *
 * The temptation is to diff the received record against the known schema and
 * render "Health notes: hidden". That would be more informative and it would
 * rebuild the exact leak the API design removed: the presence of a health-notes
 * field is itself the sensitive fact. See RedactionReport in
 * services/api/app/security/redaction.py.
 */

import type { Disclosure, EntityRecord, RelationshipRecord } from "../api/types";
import { PROTECTED_CATEGORIES } from "../api/types";
import {
  assessmentLabel, HANDLING_LABELS, sourceLabel, stampCode,
} from "../graph/evaluation";

export interface EntityCardProps {
  record: EntityRecord;
  /** Edges from this record that are currently disclosed. */
  edges: readonly RelationshipRecord[];
  disclosure: Disclosure;
  onExpand: () => void;
  expanding: boolean;
}

const CATEGORY_LABELS: Record<string, string> = {
  SUSPECT: "Suspect",
  CONVICTED: "Convicted",
  VICTIM: "Victim",
  WITNESS: "Witness",
  CONTACT: "Contact",
  OTHER: "Other",
};

export function EntityCard(props: EntityCardProps) {
  const r = props.record;
  const category = r.subject_category;
  const isProtected = category !== undefined && PROTECTED_CATEGORIES.has(category);
  const held = props.disclosure.fields_redacted + props.disclosure.fields_withheld;

  return (
    <section className="card" aria-labelledby="sel-h">
      <h2 className="card__title" id="sel-h">
        {r.display_name ?? "Name not released"}
      </h2>
      <p className="card__sub">
        {r.labels?.join(" · ") ?? "Record"}
        {category ? ` · ${CATEGORY_LABELS[category] ?? category}` : ""}
      </p>

      {isProtected && (
        <p className="notice">
          This record is a {category === "VICTIM" ? "victim" : "witness"} record.
          It is excluded from grouping analysis, and onward use is restricted.
          Check the handling code on any material you take from it.
        </p>
      )}

      <dl className="dl">
        <Row k="Reference" v={r.eid} data />
        {r.dob_year != null && (
          <Row
            k="Year of birth"
            v={String(r.dob_year)}
            hint="Year only. The full date is not released to this view."
          />
        )}
        {r.primary_case && <Row k="Primary case" v={r.primary_case} data />}
        {r.provenance_id && <Row k="Provenance" v={r.provenance_id} data />}
      </dl>

      {/*
        The redaction statement. Counts only, and phrased so the analyst knows
        there is a route to the rest — an analyst who believes they are seeing a
        whole record reaches conclusions from a partial one, which is worse than
        the redaction itself.
      */}
      {held > 0 && (
        <p className="notice">
          {held} field{held === 1 ? "" : "s"} held back from this view
          {props.disclosure.fields_withheld > 0 &&
            ` (${props.disclosure.fields_withheld} withheld, ` +
            `${props.disclosure.fields_redacted} masked)`}.
          The contents are not named here, on purpose. If you need them, ask your
          supervisor to authorise a fuller view and quote the reference above.
        </p>
      )}

      {props.disclosure.notes.length > 0 && (
        <ul className="prose prose--quiet">
          {props.disclosure.notes.map((note) => <li key={note}>{note}</li>)}
        </ul>
      )}

      <button
        type="button"
        className="btn btn--primary"
        onClick={props.onExpand}
        disabled={props.expanding}
      >
        {props.expanding ? "Expanding…" : "Expand connections"}
      </button>

      {props.edges.length > 0 && (
        <>
          <hr className="hr" />
          <h3 className="eyebrow">
            <span>Connections</span>
            <span>{props.edges.length}</span>
          </h3>
          <ul className="dl" style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {props.edges.map((e) => (
              <EdgeRow key={`${e.src}-${e.dst}-${e.type}`} edge={e} />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function Row(props: { k: string; v: string; data?: boolean; hint?: string }) {
  return (
    <div className="dl__row">
      <dt className="dl__k">{props.k}</dt>
      <dd className={props.data ? "dl__v dl__v--data" : "dl__v"}>
        {props.v}
        {props.hint && <span className="field__hint">{props.hint}</span>}
      </dd>
    </div>
  );
}

/**
 * One connection, with its grading spelled out.
 *
 * The 5x5x5 code is shown as the three-part stamp an officer already knows from
 * paper intelligence reports, and each part is also written out in words. Both,
 * not one: the code is what gets quoted in a case file, and the words are what
 * stop the code being treated as a score. An analyst who reads "2/3/4" as
 * "roughly seven out of fifteen" has lost the distinction between an unreliable
 * source and an uncorroborated report, which are different problems with
 * different remedies.
 */
function EdgeRow(props: { edge: RelationshipRecord }) {
  const e = props.edge;
  return (
    <li style={{ padding: "var(--s-2) 0", borderBottom: "1px solid var(--rule)" }}>
      <div style={{ display: "flex", justifyContent: "space-between",
                    alignItems: "baseline", gap: "var(--s-2)" }}>
        <span style={{ fontFamily: "var(--face-ui)", fontSize: "var(--t-body)" }}>
          {e.type.replace(/_/g, " ").toLowerCase()}
        </span>
        <span className="stamp" title="Source / assessment / handling">
          <span className="stamp__cell">{e.source_eval}</span>
          <span className="stamp__cell">{e.intel_assessment}</span>
          <span className="stamp__cell stamp__cell--last">{e.handling_code}</span>
        </span>
      </div>
      <p className="stamp__legend">
        {sourceLabel(e.source_eval)} · {assessmentLabel(e.intel_assessment)}
      </p>
      <p className="stamp__legend">{HANDLING_LABELS[e.handling_code]}</p>
      <p className="stamp__legend">
        <span className="sr-only">Grading code </span>
        {stampCode(e.source_eval, e.intel_assessment, e.handling_code)}
        {e.basis ? ` · basis ${e.basis}` : ""}
      </p>
    </li>
  );
}

/** Shown when nothing is selected. An empty panel is a wasted opportunity to say
 *  what the tool does and what the scope of the view is. */
export function EmptySelection() {
  return (
    <section className="card">
      <h2 className="card__title">No record selected</h2>
      <p className="prose prose--quiet">
        Click a record on the graph to see what has been released about it.
        Double-click, or press Enter, to expand its connections.
      </p>
      <p className="prose prose--quiet">
        Every record you open is a recorded disclosure attributed to you. The
        sequence number of the last one is in the strip at the bottom of the
        screen.
      </p>
    </section>
  );
}
