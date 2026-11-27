/**
 * The community panel: algorithmic output, framed as what it is.
 *
 * This component carries more legal weight than the rest of the interface put
 * together. Everything else on screen shows something a person recorded. This
 * shows a statistical inference about people, and LED Art. 11 / GDPR Art. 22
 * constrain what may be done with it.
 *
 * Four things are structural rather than cosmetic:
 *
 * 1. The caveats come first and are rendered verbatim. `derivation.not_established`
 *    is emitted by the analytics tier as body text and is displayed as body text —
 *    not in a tooltip, not behind "show details", not summarised to one line. A
 *    caveat the analyst has to click to read is a caveat that exists for the
 *    auditor rather than for the analyst.
 *
 * 2. Nothing here is called a gang, a network, an organisation or a crew. The
 *    word is "grouping", every time. The panel describes a measurement.
 *
 * 3. Export is gated on a recorded human review, and the gate is a server-side
 *    fact this component only reflects. `human_reviewed` is set by the review
 *    endpoint; the export request cannot set it. A disabled button here is a
 *    courtesy — the refusal happens at the API whether or not this file exists.
 *
 * 4. Disagreement is a first-class outcome. "This grouping does not hold up" is
 *    offered as prominently as agreement, and is recorded in the audit chain. A
 *    review that can only ever approve is not oversight, and a system that only
 *    stores approvals cannot show an oversight body that dissent was possible.
 */

import { useState } from "react";

import type { CommunityRecord, Disclosure, Role } from "../api/types";
import { ROLE_MEANING } from "../api/types";

export interface CommunityPanelProps {
  record: CommunityRecord;
  disclosure: Disclosure;
  /** True when the signed-in principal holds the reviewer role. Reflects the
   *  IdP claim; the API checks it again. */
  canReview: boolean;
  /** Set once a review has been recorded in this session. */
  reviewSeq: number | null;
  onReview: (assessment: string, concurs: boolean) => Promise<void>;
  onReidentify: (justification: string) => Promise<void>;
  reidentifying: boolean;
}

const MIN_ASSESSMENT = 40;
const MIN_JUSTIFICATION = 20;

export function CommunityPanel(props: CommunityPanelProps) {
  const c = props.record;
  const d = c.derivation;

  // A derived record without a derivation envelope should be impossible: the
  // redactor refuses to emit one. If it happens, say so plainly and render
  // nothing else — a community shown without its caveats is the single worst
  // output this interface could produce.
  if (!d) {
    return (
      <section className="card card--infer">
        <h2 className="card__title">Grouping cannot be shown</h2>
        <p className="notice notice--refuse">
          This result arrived without its derivation record, so there is no
          account of how it was produced. It has not been displayed. Report the
          reference below to the platform team.
        </p>
        <p className="dl__v dl__v--data">{c.community_id}</p>
      </section>
    );
  }

  return (
    <section className="card card--infer" aria-labelledby="comm-h">
      <p className="card__sub">Derived — not a record</p>
      <h2 className="card__title" id="comm-h">
        Grouping {c.community_id.slice(0, 8)}
      </h2>

      {/* The verbatim caveat block, at the top, as body text. */}
      <div className="notice notice--infer">
        {d.not_established.map((line) => (
          <p className="prose" key={line} style={{ margin: "0 0 var(--s-2)" }}>
            {line}
          </p>
        ))}
      </div>

      <dl className="dl">
        <div className="dl__row">
          <dt className="dl__k">Stability</dt>
          <dd className="dl__v">
            {/*
              Absent stability is rendered as "withheld", never as 0 or "—". The
              field is dropped by WITHHOLD_LOW_STABILITY, and a dash reads as
              "not applicable" when the truth is "measured, and too low to
              release".
            */}
            {c.stability == null ? (
              <span style={{ color: "var(--withheld)" }}>
                Withheld — below the disclosure threshold
              </span>
            ) : (
              <>
                {c.stability.toFixed(2)}
                <span className="field__hint">
                  Share of {d.bootstrap_runs} re-runs in which these records
                  stayed grouped together, with the evidence weightings varied
                  within their own uncertainty. Below 0.60 is not released.
                </span>
              </>
            )}
          </dd>
        </div>

        <div className="dl__row">
          <dt className="dl__k">Members</dt>
          <dd className="dl__v">
            {c.size ?? c.member_surrogates?.length ?? "—"}
            <span className="field__hint">
              Identities are not included in this view. Use “Name these records”
              below if you need them; that is a separate, separately recorded
              disclosure.
            </span>
          </dd>
        </div>

        <div className="dl__row">
          <dt className="dl__k">Level</dt>
          <dd className="dl__v">
            {c.level}
            <span className="field__hint">
              Nesting level from the resolution sweep. Level 0 is the coarsest
              division of the graph.
            </span>
          </dd>
        </div>

        <div className="dl__row">
          <dt className="dl__k">Modularity</dt>
          <dd className="dl__v dl__v--data">{d.modularity.toFixed(3)}</dd>
        </div>
      </dl>

      {c.role && <RoleBlock role={c.role} />}

      <hr className="hr" />
      <h3 className="eyebrow"><span>How this was produced</span></h3>
      <dl className="dl">
        <div className="dl__row">
          <dt className="dl__k">Method</dt>
          <dd className="dl__v">
            {d.algorithm} {d.algorithm_version}
            <span className="field__hint">
              {d.backend} backend, resolution {d.resolution}, seed {d.seed}
            </span>
          </dd>
        </div>
        <div className="dl__row">
          <dt className="dl__k">Input</dt>
          <dd className="dl__v">
            {d.vertex_count} records, {d.edge_count} connections
            <span className="field__hint">
              Snapshot {d.snapshot_id}, computed {d.computed_at}. Weighting:{" "}
              {d.weighting_scheme}.
            </span>
          </dd>
        </div>
        {d.excluded_from_input.length > 0 && (
          <div className="dl__row">
            <dt className="dl__k">Excluded</dt>
            <dd className="dl__v">
              {d.excluded_from_input.join(", ")}
              <span className="field__hint">
                These categories are never grouped. Their absence from this
                grouping means nothing about them.
              </span>
            </dd>
          </div>
        )}
      </dl>

      <h3 className="eyebrow"><span>What this method cannot do</span></h3>
      <ul className="prose prose--quiet">
        {d.method_limits.map((line) => <li key={line}>{line}</li>)}
      </ul>

      {d.warnings.length > 0 && (
        <div className="notice">
          {d.warnings.map((w) => (
            <p className="prose" key={w} style={{ margin: "0 0 var(--s-1)" }}>{w}</p>
          ))}
        </div>
      )}

      {d.approximations.length > 0 && (
        <>
          <h3 className="eyebrow"><span>Approximations applied</span></h3>
          <ul className="prose prose--quiet">
            {d.approximations.map((a) => <li key={a}>{a}</li>)}
          </ul>
        </>
      )}

      <hr className="hr" />
      <Reidentify
        onSubmit={props.onReidentify}
        busy={props.reidentifying}
        count={c.size ?? c.member_surrogates?.length ?? 0}
      />

      <hr className="hr" />
      <ReviewForm
        canReview={props.canReview}
        reviewSeq={props.reviewSeq}
        onSubmit={props.onReview}
      />

      {props.disclosure.fields_withheld > 0 && (
        <p className="notice">
          {props.disclosure.fields_withheld} field
          {props.disclosure.fields_withheld === 1 ? "" : "s"} withheld from this
          grouping.
        </p>
      )}
    </section>
  );
}

/**
 * The role, with its meaning next to it rather than behind it.
 *
 * The role vocabulary was chosen upstream to describe the measurement rather than
 * assert a function — CONNECTOR_HUB, not "lieutenant". That choice only survives
 * to the analyst if the explanation travels with the label. A role name alone will
 * be interpreted from its name, and CONNECTOR_HUB read cold sounds a lot like a
 * finding about someone's importance.
 */
function RoleBlock(props: { role: Role }) {
  return (
    <>
      <hr className="hr" />
      <h3 className="eyebrow"><span>Position in the grouping</span></h3>
      <p className="dl__v" style={{ fontFamily: "var(--face-data)",
                                    fontSize: "var(--t-cap)" }}>
        {props.role}
      </p>
      <p className="prose prose--quiet">{ROLE_MEANING[props.role]}</p>
      <p className="prose prose--quiet">
        This describes a pattern of connections in one snapshot of one dataset. It
        is not a statement about seniority, intent, or what this person knew.
      </p>
    </>
  );
}

/* --- Re-identification -------------------------------------------------- */

function Reidentify(props: {
  onSubmit: (justification: string) => Promise<void>;
  busy: boolean;
  count: number;
}) {
  const [justification, setJustification] = useState("");
  const short = justification.trim().length < MIN_JUSTIFICATION;

  return (
    <>
      <h3 className="eyebrow"><span>Name these records</span></h3>
      <p className="prose prose--quiet">
        Resolving a grouping to named individuals is the step that turns a
        statistical cluster into an investigative interest in specific people. It
        is authorised separately and recorded separately from viewing the shape.
      </p>
      <label className="field">
        <span className="field__label">Why do you need the names?</span>
        <textarea
          className="field__area"
          value={justification}
          onChange={(ev) => setJustification(ev.target.value)}
          placeholder="What decision will these names inform?"
          minLength={MIN_JUSTIFICATION}
          maxLength={2000}
        />
        <span className="field__hint">
          Recorded with your identifier and shown to anyone auditing this case.
          At least {MIN_JUSTIFICATION} characters.
        </span>
      </label>
      <button
        type="button"
        className="btn"
        disabled={short || props.busy || props.count === 0}
        onClick={() => void props.onSubmit(justification.trim())}
      >
        {props.busy ? "Requesting…" : `Name ${props.count} records`}
      </button>
      {short && (
        <p className="btn__why">
          Add a reason first. This is not a formality — it is the record of why
          these people became of interest.
        </p>
      )}
    </>
  );
}

/* --- Human review ------------------------------------------------------- */

function ReviewForm(props: {
  canReview: boolean;
  reviewSeq: number | null;
  onSubmit: (assessment: string, concurs: boolean) => Promise<void>;
}) {
  const [assessment, setAssessment] = useState("");
  const [concurs, setConcurs] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  if (props.reviewSeq !== null) {
    return (
      <>
        <h3 className="eyebrow"><span>Review</span></h3>
        <p className="prose prose--quiet">
          Recorded as audit entry{" "}
          <span className="disclose__seq">#{props.reviewSeq}</span>. Export of
          material derived from this grouping is now permitted.
        </p>
      </>
    );
  }

  if (!props.canReview) {
    return (
      <>
        <h3 className="eyebrow"><span>Review</span></h3>
        <p className="prose prose--quiet">
          Before anything derived from this grouping can be exported, a reviewer
          has to read it and record their own assessment. You do not hold the
          reviewer role, so ask a colleague who does.
        </p>
        <p className="btn__why">
          Reviewing your own analysis would satisfy the letter of the requirement
          and none of its purpose, so the system does not allow it.
        </p>
      </>
    );
  }

  const short = assessment.trim().length < MIN_ASSESSMENT;
  const ready = !short && concurs !== null && !busy;

  return (
    <>
      <h3 className="eyebrow"><span>Record your review</span></h3>
      <p className="prose prose--quiet">
        Write what you make of this grouping in your own words. This is the record
        that a human considered the result before it was used.
      </p>

      <label className="field">
        <span className="field__label">Your assessment</span>
        <textarea
          className="field__area"
          value={assessment}
          onChange={(ev) => setAssessment(ev.target.value)}
          placeholder="What does this grouping appear to show, and what would you want to see before relying on it?"
          minLength={MIN_ASSESSMENT}
          maxLength={4000}
        />
        <span className="field__hint">
          At least {MIN_ASSESSMENT} characters. Free text, not a checkbox — a
          tick cannot show anyone that the result was actually read.
        </span>
      </label>

      {/*
        Both outcomes, same weight, neither preselected. A default of "agree" is
        the outcome most reviews would then have, and the recorded fact would be
        the default rather than the judgement.
      */}
      <fieldset style={{ border: 0, padding: 0, margin: "0 0 var(--s-3)" }}>
        <legend className="field__label">Your conclusion</legend>
        <div className="radio-row">
          <label>
            <input
              type="radio"
              name="concurs"
              checked={concurs === true}
              onChange={() => setConcurs(true)}
            />{" "}
            This grouping is sound
          </label>
          <label>
            <input
              type="radio"
              name="concurs"
              checked={concurs === false}
              onChange={() => setConcurs(false)}
            />{" "}
            This grouping does not hold up
          </label>
        </div>
      </fieldset>

      <button
        type="button"
        className="btn btn--primary"
        disabled={!ready}
        onClick={() => {
          if (concurs === null) return;
          setBusy(true);
          void props.onSubmit(assessment.trim(), concurs).finally(() => setBusy(false));
        }}
      >
        {busy ? "Recording…" : "Record review"}
      </button>

      {!ready && !busy && (
        <p className="btn__why">
          {short
            ? `Write at least ${MIN_ASSESSMENT} characters of assessment.`
            : "Choose a conclusion. Disagreeing is a valid, recorded outcome."}
        </p>
      )}
    </>
  );
}
