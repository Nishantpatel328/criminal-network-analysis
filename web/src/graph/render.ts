/**
 * The canvas painter.
 *
 * Everything about how this draws is a disclosure decision rendered in pixels.
 * The three that matter most:
 *
 * 1. COMMUNITY BOUNDARIES ARE OPEN ARCS, NOT CLOSED HULLS.
 *    A closed polygon around a group of people is a claim: this is the extent of
 *    the organisation, these are its members, that person outside the line is
 *    not one. A modularity optimiser does not support any of that. Three arc
 *    segments with gaps between them say what the algorithm actually found —
 *    these records are more densely connected to each other than to the rest of
 *    this dataset — and leave the boundary visibly unfinished. It is the same
 *    information with an honest edge condition.
 *
 * 2. THE WATERMARK IS PAINTED INTO THE BITMAP.
 *    A CSS overlay watermark is removed by one line in devtools, and a DOM
 *    watermark does not appear in a screenshot taken by an OS-level tool at all.
 *    Drawn into the canvas, the analyst's identifier travels with any copy of the
 *    image. It does not prevent exfiltration; it makes an exfiltrated screenshot
 *    attributable, which is the achievable goal.
 *
 * 3. INFERENCE IS VIOLET, RECORD IS TEAL, AND THEY NEVER MIX.
 *    An analyst must be able to tell at a glance whether a mark came from the
 *    evidential graph or from an algorithm. Two hue families, no shared middle
 *    ground, and no decorative use of either.
 */

import {
  assessmentDash, edgeWidth, sourceAlpha,
} from "./evaluation";
import type { Layout, Node } from "./layout";
import type { EntityRecord, Grade, NodeLabel, SubjectCategory } from "../api/types";
import { PROTECTED_CATEGORIES } from "../api/types";

/* Read from the token layer rather than hardcoded, so the taxonomy has exactly
   one definition. If a colour is changed in tokens.css it changes here too. */
function token(name: string, fallback: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name);
  return v.trim() || fallback;
}

export interface EdgeDraw {
  src: string;
  dst: string;
  sourceEval: Grade;
  intelAssessment: Grade;
  weight: number;
}

export interface CommunityDraw {
  communityId: string;
  /** Entity ids currently on screen that belong to this community. */
  members: readonly string[];
  /** 0..1, or null when WITHHOLD_LOW_STABILITY suppressed it. Null is drawn
   *  differently from low — an unknown boundary and a shaky boundary are not the
   *  same thing to an analyst deciding whether to act on it. */
  stability: number | null;
}

export interface Scene {
  entities: ReadonlyMap<string, EntityRecord>;
  edges: readonly EdgeDraw[];
  communities: readonly CommunityDraw[];
  selectedId: string | null;
  hoverId: string | null;
  /** When set, edges whose source evaluation differs are drawn at a fraction of
   *  their alpha. Driven by the evaluation key acting as a filter. */
  reliabilityFocus: Grade | null;
  /** Painted diagonally across the bitmap. Null only when the policy did not
   *  attach WATERMARK_OUTPUT, which for a graph view it always does. */
  watermark: string | null;
  /** Set when the server truncated or refused part of the neighbourhood. */
  truncated: boolean;
}

interface Palette {
  ink: string; ink2: string; ink3: string;
  paper: string; panel: string; rule: string;
  attest: string; infer: string; withheld: string;
}

function palette(): Palette {
  return {
    ink:      token("--ink", "#1b1f23"),
    ink2:     token("--ink-2", "#4a5158"),
    ink3:     token("--ink-3", "#767d85"),
    paper:    token("--paper", "#edeef0"),
    panel:    token("--panel", "#f6f7f8"),
    rule:     token("--rule", "#c7cbd1"),
    attest:   token("--attest", "#275a6b"),
    infer:    token("--infer", "#6d4482"),
    withheld: token("--withheld", "#8a5a00"),
  };
}

function rgba(hex: string, alpha: number): string {
  const h = hex.replace("#", "");
  const full = h.length === 3
    ? h.split("").map((c) => c + c).join("")
    : h;
  const r = parseInt(full.slice(0, 2), 16);
  const g = parseInt(full.slice(2, 4), 16);
  const b = parseInt(full.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

/** Node radius by entity kind. Person is largest because a person is the subject
 *  of the legal framework; a phone is an attribute of one. */
const RADIUS: Record<NodeLabel, number> = {
  Person: 8, Organisation: 8, Phone: 5.5, Account: 5.5,
  Vehicle: 6, Location: 6, Event: 6, Case: 7,
};

function primaryLabel(rec: EntityRecord | undefined): NodeLabel {
  return rec?.labels?.[0] ?? "Person";
}

/**
 * Label shown under a node.
 *
 * Falls back to a truncated eid, never to "Unknown". `display_name` is absent
 * when it was redacted, and "Unknown" would tell the analyst the record has no
 * name — which is false, and is the kind of small lie that becomes a line in a
 * statement. The eid is what they can quote in a request for fuller access.
 */
function nodeLabel(rec: EntityRecord | undefined, id: string): string {
  const name = rec?.display_name;
  if (name && name.length > 0) {
    return name.length > 24 ? name.slice(0, 23) + "…" : name;
  }
  return id.slice(0, 8);
}

export function draw(
  ctx: CanvasRenderingContext2D,
  layout: Layout,
  scene: Scene,
  width: number,
  height: number,
  dpr: number,
): void {
  const p = palette();

  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = p.paper;
  ctx.fillRect(0, 0, width, height);

  if (scene.watermark) paintWatermark(ctx, scene.watermark, width, height, p);
  paintCommunities(ctx, layout, scene, p);
  paintEdges(ctx, layout, scene, p);
  paintNodes(ctx, layout, scene, p);
  if (scene.truncated) paintTruncation(ctx, width, height, p);

  ctx.restore();
}

/* --- Watermark --------------------------------------------------------- */

function paintWatermark(
  ctx: CanvasRenderingContext2D, text: string,
  width: number, height: number, p: Palette,
): void {
  ctx.save();
  // 0.055 alpha: legible in a screenshot when someone is looking for it,
  // effectively invisible while reading the graph. Tiled rather than drawn once,
  // so a crop of any region still carries the attribution — a single diagonal
  // banner is defeated by cropping to the interesting cluster.
  ctx.fillStyle = rgba(p.ink, 0.055);
  ctx.font = `500 12px "Cascadia Mono", Consolas, monospace`;
  ctx.textBaseline = "middle";
  ctx.translate(width / 2, height / 2);
  ctx.rotate(-Math.PI / 9);
  ctx.translate(-width / 2, -height / 2);

  const metrics = ctx.measureText(text);
  const stepX = metrics.width + 90;
  const stepY = 74;
  for (let y = -height; y < height * 2; y += stepY) {
    // Offset alternate rows so the tiling does not form vertical corridors that
    // read as part of the graph.
    const offset = (Math.round(y / stepY) % 2) * (stepX / 2);
    for (let x = -width; x < width * 2; x += stepX) {
      ctx.fillText(text, x + offset, y);
    }
  }
  ctx.restore();
}

/* --- Communities: open arcs -------------------------------------------- */

function paintCommunities(
  ctx: CanvasRenderingContext2D, layout: Layout, scene: Scene, p: Palette,
): void {
  for (const c of scene.communities) {
    const pts: Node[] = [];
    for (const id of c.members) {
      const n = layout.nodes.get(id);
      if (n) pts.push(n);
    }
    // Fewer than three on-screen members is not a shape. Drawing a boundary
    // around two nodes asserts a group of two, which is below
    // MIN_COMMUNITY_SIZE server-side anyway.
    if (pts.length < 3) continue;

    let cx = 0;
    let cy = 0;
    for (const n of pts) { cx += n.x; cy += n.y; }
    cx /= pts.length;
    cy /= pts.length;

    let r = 0;
    for (const n of pts) r = Math.max(r, Math.hypot(n.x - cx, n.y - cy));
    r += 26;

    // Stability drives how much of the circle is drawn. A well-supported grouping
    // is nearly closed; a marginal one is three short strokes. The boundary is
    // never fully closed, at any stability — see the module docstring.
    const stability = c.stability;
    const solidity = stability === null
      ? 0.3
      : Math.min(0.82, Math.max(0.3, stability));
    const arcSpan = (Math.PI * 2 / 3) * solidity;

    ctx.save();
    ctx.strokeStyle = rgba(p.infer, stability === null ? 0.3 : 0.5);
    ctx.lineWidth = 1.5;
    // Dashed when stability is unknown: a boundary we cannot vouch for is drawn
    // the way this interface draws all uncertain things.
    ctx.setLineDash(stability === null ? [3, 4] : []);
    ctx.lineCap = "round";
    for (let i = 0; i < 3; i += 1) {
      const start = (Math.PI * 2 / 3) * i - Math.PI / 2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, start, start + arcSpan);
      ctx.stroke();
    }
    ctx.setLineDash([]);

    ctx.fillStyle = rgba(p.infer, 0.7);
    ctx.font = `600 10px "Arial Narrow", "Segoe UI", sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "bottom";
    // The word "grouping", never "gang", "network" or "organisation". The label
    // on the arc is the shortest piece of text in the interface and the one most
    // likely to be read aloud in a briefing.
    const caption = stability === null
      ? `grouping ${c.communityId.slice(0, 6)} · stability withheld`
      : `grouping ${c.communityId.slice(0, 6)} · stability ${stability.toFixed(2)}`;
    ctx.fillText(caption, cx, cy - r - 6);
    ctx.restore();
  }
}

/* --- Edges ------------------------------------------------------------- */

function paintEdges(
  ctx: CanvasRenderingContext2D, layout: Layout, scene: Scene, p: Palette,
): void {
  ctx.save();
  ctx.lineCap = "round";
  for (const e of scene.edges) {
    const a = layout.nodes.get(e.src);
    const b = layout.nodes.get(e.dst);
    if (!a || !b) continue;

    let alpha = sourceAlpha(e.sourceEval);
    if (scene.reliabilityFocus !== null && e.sourceEval !== scene.reliabilityFocus) {
      // Dimmed, not hidden. The filter answers "what does this look like if I
      // only believe grade 2 material" — removing the rest would answer a
      // different question, namely "what if the rest does not exist".
      alpha *= 0.15;
    }
    const touchesSelection =
      scene.selectedId !== null &&
      (e.src === scene.selectedId || e.dst === scene.selectedId);
    if (touchesSelection) alpha = Math.min(1, alpha * 1.35);

    ctx.strokeStyle = rgba(p.attest, alpha);
    ctx.lineWidth = edgeWidth(e.weight);
    ctx.setLineDash(assessmentDash(e.intelAssessment));
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  ctx.setLineDash([]);
  ctx.restore();
}

/* --- Nodes ------------------------------------------------------------- */

function paintNodes(
  ctx: CanvasRenderingContext2D, layout: Layout, scene: Scene, p: Palette,
): void {
  ctx.save();
  ctx.textAlign = "center";

  for (const node of layout.nodes.values()) {
    const rec = scene.entities.get(node.id);
    const kind = primaryLabel(rec);
    const r = RADIUS[kind];
    const isSelected = node.id === scene.selectedId;
    const isHover = node.id === scene.hoverId;
    const category: SubjectCategory | undefined = rec?.subject_category;
    const protectedSubject =
      category !== undefined && PROTECTED_CATEGORIES.has(category);

    // Fade-in for newly disclosed nodes. Position is already stable by the time
    // this matters; the fade is about drawing the eye to what changed.
    const appear = Math.min(1, node.age / 12);

    ctx.beginPath();
    if (kind === "Organisation" || kind === "Case") {
      // Square for a legal person, circle for a natural one. Shape, not colour:
      // colour is spoken for by the provenance taxonomy.
      ctx.rect(node.x - r, node.y - r, r * 2, r * 2);
    } else {
      ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
    }
    ctx.fillStyle = rgba(p.attest, 0.9 * appear);
    ctx.fill();

    if (protectedSubject) {
      // A ring, not a different fill. Victims and witnesses are rendered as
      // ordinary records with an added mark, because they are ordinary records
      // that carry extra handling duties — recolouring them would make them the
      // most visually salient thing on a screen about suspects.
      ctx.beginPath();
      ctx.arc(node.x, node.y, r + 3.5, 0, Math.PI * 2);
      ctx.strokeStyle = rgba(p.withheld, 0.85 * appear);
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    if (node.pinned) {
      // Small tick above a node the analyst has placed by hand.
      ctx.beginPath();
      ctx.moveTo(node.x, node.y - r - 5);
      ctx.lineTo(node.x, node.y - r - 9);
      ctx.strokeStyle = rgba(p.ink2, 0.8);
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    if (isSelected || isHover) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, r + (isSelected ? 6 : 4.5), 0, Math.PI * 2);
      ctx.strokeStyle = rgba(p.ink, isSelected ? 0.9 : 0.4);
      ctx.lineWidth = isSelected ? 1.75 : 1;
      ctx.stroke();
    }

    // Labels only for nodes that matter right now. Painting 500 labels produces
    // an unreadable mat of text, and the labels that get lost in it are the ones
    // for the small peripheral nodes an analyst is most likely to be hunting.
    const labelled =
      isSelected || isHover || layout.nodes.size <= 60 || kind === "Organisation";
    if (labelled) {
      const text = nodeLabel(rec, node.id);
      ctx.font = `${isSelected ? 600 : 400} 11px "Arial Narrow", "Segoe UI", sans-serif`;
      // Halo behind the text so labels stay readable over edges without a solid
      // box, which would occlude the connections the label is describing.
      ctx.lineWidth = 3;
      ctx.strokeStyle = rgba(p.paper, 0.9);
      ctx.textBaseline = "top";
      ctx.strokeText(text, node.x, node.y + r + 3);
      ctx.fillStyle = rgba(p.ink, 0.92 * appear);
      ctx.fillText(text, node.x, node.y + r + 3);

      if (rec?.display_name === undefined) {
        // Says the name was not released, rather than implying there isn't one.
        ctx.font = `400 9px "Arial Narrow", "Segoe UI", sans-serif`;
        ctx.fillStyle = rgba(p.withheld, 0.9);
        ctx.fillText("name withheld", node.x, node.y + r + 15);
      }
    }
  }
  ctx.restore();
}

/* --- Truncation notice ------------------------------------------------- */

function paintTruncation(
  ctx: CanvasRenderingContext2D, width: number, _height: number, p: Palette,
): void {
  // On the canvas, not only in the status strip. This one is about what is NOT
  // drawn, and a notice about missing marks belongs in the same visual field as
  // the marks — an analyst reading the graph is not looking at the footer.
  const text = "Part of this neighbourhood was not released. The graph is incomplete.";
  ctx.save();
  ctx.font = `500 11px "Arial Narrow", "Segoe UI", sans-serif`;
  ctx.textAlign = "center";
  ctx.textBaseline = "top";
  const w = ctx.measureText(text).width + 20;
  ctx.fillStyle = rgba(p.withheld, 0.12);
  ctx.fillRect((width - w) / 2, 10, w, 22);
  ctx.strokeStyle = rgba(p.withheld, 0.6);
  ctx.lineWidth = 1;
  ctx.strokeRect((width - w) / 2, 10, w, 22);
  ctx.fillStyle = rgba(p.withheld, 1);
  ctx.fillText(text, width / 2, 16);
  ctx.restore();
}
