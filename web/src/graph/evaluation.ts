/**
 * 5x5x5 intelligence grading, rendered.
 *
 * This module is the visual half of a control that the backend can only get
 * halfway. `worker/weighting.py` reduces the grading to a single weight so the
 * analytics tier can use it; that reduction is correct there and lossy here. An
 * analyst looking at an edge needs to know *why* it is weak — an untested source
 * and an uncorroborated hearsay report are both "weak" and call for different
 * next steps.
 *
 * So the grading is carried to the screen intact and encoded in two independent
 * visual channels:
 *
 *   source evaluation   -> ink density   (how much do we trust the source)
 *   intel assessment    -> dash pattern  (how directly is this known)
 *
 * Two channels rather than one combined score, because they answer different
 * questions and because a single "confidence" number invites an analyst to
 * threshold on it. Someone who filters at "confidence > 0.6" has silently
 * discarded every well-corroborated report from an untested source, which is
 * most of what a new informant produces.
 *
 * The handling code is not encoded visually at all. It governs onward
 * dissemination, not evidential strength, and drawing it would put a third
 * unrelated meaning into the same mark. It is shown as text on the stamp.
 */

import type { Grade } from "../api/types";

/* --- Source evaluation ------------------------------------------------- */

export interface SourceLevel {
  grade: Grade;
  /** The NIM wording, near enough that an officer recognises it. */
  label: string;
  /** Alpha applied to --attest when stroking the edge. Mirrors the --conf-N ramp
   *  in styles/tokens.css. The two are checked against each other by
   *  deploy/ci/check_alpha_ramp.py, because a silent divergence would mean the
   *  legend swatches and the edges they explain no longer match. */
  alpha: number;
}

export const SOURCE_LEVELS: readonly SourceLevel[] = [
  { grade: 1, label: "Always reliable",    alpha: 1.00 },
  { grade: 2, label: "Mostly reliable",    alpha: 0.78 },
  { grade: 3, label: "Sometimes reliable", alpha: 0.55 },
  { grade: 4, label: "Unreliable",         alpha: 0.36 },
  { grade: 5, label: "Untested source",    alpha: 0.24 },
];

/** Never returns below this. An edge drawn at 4% alpha is invisible on a
 *  police-issue monitor at office brightness, and invisibility is a stronger
 *  claim than faintness: it says the relationship is not there. Nothing in this
 *  interface is permitted to say that by accident. */
export const ALPHA_FLOOR = 0.16;

export function sourceAlpha(grade: Grade): number {
  const level = SOURCE_LEVELS[grade - 1];
  return Math.max(ALPHA_FLOOR, level?.alpha ?? ALPHA_FLOOR);
}

export function sourceLabel(grade: Grade): string {
  return SOURCE_LEVELS[grade - 1]?.label ?? "Ungraded";
}

/* --- Intelligence assessment ------------------------------------------- */

export interface AssessmentLevel {
  grade: Grade;
  label: string;
  /** Canvas dash pattern. Longer, more broken dashes as the knowledge becomes
   *  more indirect. Solid means the source knew it directly. */
  dash: readonly number[];
}

export const ASSESSMENT_LEVELS: readonly AssessmentLevel[] = [
  { grade: 1, label: "Known to be true",                     dash: [] },
  { grade: 2, label: "Known personally to source",           dash: [] },
  { grade: 3, label: "Not known personally, corroborated",   dash: [6, 3] },
  { grade: 4, label: "Cannot be judged",                     dash: [2, 4] },
  { grade: 5, label: "Suspected to be false",                dash: [1, 5] },
];

export function assessmentDash(grade: Grade): number[] {
  return [...(ASSESSMENT_LEVELS[grade - 1]?.dash ?? [2, 4])];
}

export function assessmentLabel(grade: Grade): string {
  return ASSESSMENT_LEVELS[grade - 1]?.label ?? "Ungraded";
}

/* --- Handling code ----------------------------------------------------- */

export const HANDLING_LABELS: Record<Grade, string> = {
  1: "May be disseminated to other agencies",
  2: "May be disseminated within the police service",
  3: "May be disseminated to non-prosecuting parties",
  4: "Dissemination only with the originator's authority",
  5: "Dissemination subject to specific conditions",
};

/* --- Composite --------------------------------------------------------- */

/** The three-part code as an analyst writes it on a paper report. */
export function stampCode(
  sourceEval: Grade, intelAssessment: Grade, handlingCode: Grade,
): string {
  return `${sourceEval}/${intelAssessment}/${handlingCode}`;
}

/**
 * Line width from evidential volume.
 *
 * Log-scaled, matching the `log1p` damping in weighting.py. If the width were
 * linear in weight, one chatty pair with ten thousand messages would render as a
 * bar across the canvas and everything else as hairlines — which is not a
 * proportionate picture of the network, it is a picture of one phone bill.
 *
 * Capped at 4px. Beyond that the stroke starts to read as a region rather than a
 * connection and begins to obscure the nodes it joins.
 */
export function edgeWidth(weight: number): number {
  const w = Math.max(0, weight);
  return Math.min(4, 0.8 + Math.log1p(w) * 0.55);
}

/**
 * Whether this edge should be drawn at all.
 *
 * Nothing is dropped here. The server already excluded assessment grade 5
 * (suspected false) from the analytics input, but an edge the analyst is entitled
 * to see is drawn even at the alpha floor. Hiding weak intelligence in the
 * display while the server considered it in the weighting would mean the picture
 * on screen and the picture the algorithm clustered are different graphs, and the
 * analyst would have no way to know which one produced the community.
 */
export function isDrawable(_weight: number): boolean {
  return true;
}
