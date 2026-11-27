/**
 * The evaluation key: legend and filter in one control.
 *
 * This is the element the interface is built around. The graph encodes source
 * reliability as ink density and the intelligence assessment as a dash pattern,
 * which means the graph is only readable next to a key that says so. So the key
 * is permanent chrome — no collapse, no dismiss, no "hide legend" preference.
 *
 * That is not tidiness. A legend that can be hidden is a legend that is hidden in
 * the screenshot someone pastes into a case file, and at that point a network of
 * uncorroborated informant reports and a network of warranted intercept data look
 * identical to whoever opens the file next.
 *
 * Making it a filter as well is what stops it being wallpaper. Hovering a level
 * dims every edge not at that level, so the key becomes the way an analyst asks
 * "what does this network look like if I only count the material I would put in
 * front of a court?" — a question worth asking often, answered without a new
 * request and therefore without a new disclosure.
 */

import {
  ASSESSMENT_LEVELS, SOURCE_LEVELS,
} from "../graph/evaluation";
import type { Grade } from "../api/types";

export interface EvaluationKeyProps {
  focus: Grade | null;
  onFocus: (grade: Grade | null) => void;
  /** Edge counts per source grade in the current view, so the analyst can see
   *  the evidential composition of what they are looking at without clicking
   *  anything. A network that is 80% grade-5 material should look like one. */
  counts: Readonly<Record<Grade, number>>;
}

export function EvaluationKey(props: EvaluationKeyProps) {
  const total = SOURCE_LEVELS.reduce(
    (sum, level) => sum + (props.counts[level.grade] ?? 0), 0,
  );

  return (
    <section className="block" aria-labelledby="evalkey-h">
      <h2 className="eyebrow" id="evalkey-h">
        <span>Evaluation key</span>
        <span>{total} edges</span>
      </h2>

      <div className="key" role="group" aria-label="Filter by source reliability">
        {SOURCE_LEVELS.map((level) => {
          const n = props.counts[level.grade] ?? 0;
          const isFocus = props.focus === level.grade;
          const muted = props.focus !== null && !isFocus;
          return (
            <button
              key={level.grade}
              type="button"
              className={`key__stop${muted ? " key__stop--muted" : ""}`}
              aria-pressed={isFocus}
              // Hover previews, click latches. Preview-on-hover means the common
              // case costs nothing to undo; latching means an analyst can hold a
              // filtered view while reading the selection card, which a
              // hover-only control makes impossible.
              onPointerEnter={() => { if (props.focus === null) props.onFocus(level.grade); }}
              onPointerLeave={() => { if (!isFocus) props.onFocus(null); }}
              onClick={() => props.onFocus(isFocus ? null : level.grade)}
            >
              <span className="key__code">{level.grade} · {n}</span>
              <span
                className="key__swatch"
                // Written through the style prop, which sets the value via CSSOM
                // rather than an inline style attribute — so it does not need
                // style-src 'unsafe-inline'. Six static classes would also work
                // and would drift from the alpha ramp in evaluation.ts.
                style={{ opacity: level.alpha }}
              />
              <span className="key__label">{level.label}</span>
            </button>
          );
        })}
      </div>

      <p className="key__note">
        Line darkness shows how reliable the source is. Hover a level to see only
        that material; click to hold it.
      </p>

      <h3 className="eyebrow" style={{ marginTop: "var(--s-4)" }}>
        <span>Line pattern</span>
      </h3>
      <dl className="dl">
        {ASSESSMENT_LEVELS.map((level) => (
          <div className="dl__row" key={level.grade}>
            <dt className="dl__k">{level.grade}</dt>
            <dd className="dl__v" style={{ fontSize: "var(--t-cap)" }}>
              {level.label}
            </dd>
          </div>
        ))}
      </dl>
      <p className="key__note">
        Solid means the source knew it directly. More broken means more indirect.
        Grade 5 material is excluded from grouping upstream and will not appear
        here.
      </p>
    </section>
  );
}

/** Tally edges by source grade. Exported so the shell can compute it once per
 *  disclosed edge set rather than on every render of the key. */
export function tallyBySource(
  edges: readonly { sourceEval: Grade }[],
): Record<Grade, number> {
  const counts: Record<Grade, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  for (const e of edges) counts[e.sourceEval] += 1;
  return counts;
}
