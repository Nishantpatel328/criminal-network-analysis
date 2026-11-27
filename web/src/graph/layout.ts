/**
 * Force layout, with position stability as the first requirement.
 *
 * WHY NOT d3-force
 * d3-force is a better simulation than this one. It is also a simulation that
 * restarts with `alpha = 1` when nodes are added, which repositions the entire
 * graph on every expansion. That behaviour is fine for a data visualisation and
 * wrong for an investigative tool: the analyst's spatial memory of the network —
 * "the haulage cluster is bottom-left, the two phones I care about are the pair
 * at the top" — is their working memory. Destroying it on every expansion means
 * they re-read the whole graph each time and lose the thread they were following.
 *
 * So: existing nodes are pinned to where they already are and only relax
 * gently. New nodes are seeded next to whichever known node pulled them in and
 * get the full force treatment. The graph grows outward from what the analyst was
 * already looking at.
 *
 * SCALE
 * O(n^2) repulsion, deliberately. The API refuses any expansion over 500 elements
 * (Settings.max_expansion_elements), so n is bounded at 500 and 250k pair
 * computations at 30fps is comfortable. If that ceiling is ever raised, this is
 * the file that needs a Barnes-Hut quadtree, and the trigger is documented in
 * docs/scaling.md rather than left for someone to discover as jank.
 */

export interface Node {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  /** Fixed by the analyst dragging it. Pinned nodes are never moved by the
   *  simulation: an analyst who has arranged a subgraph to mirror a whiteboard
   *  has encoded knowledge the layout does not have. */
  pinned: boolean;
  /** Frames since this node appeared, for the fade-in. */
  age: number;
}

export interface Edge {
  src: string;
  dst: string;
  /** Rest length scales with evidential weight: better-evidenced pairs sit
   *  closer. Physical proximity reads as relatedness whether or not we intend
   *  it, so it may as well encode something true. */
  rest: number;
}

const REPULSION = 5200;
const SPRING = 0.014;
const DAMPING = 0.86;
const CENTRE_PULL = 0.0016;

/** How much an already-placed node may still be moved, per frame. Low enough
 *  that the existing picture visibly holds while new material settles around
 *  it. */
const SETTLED_MOBILITY = 0.12;

/** Frames before a new node is considered settled. About a second at 60fps. */
const SETTLE_FRAMES = 60;

export class Layout {
  readonly nodes = new Map<string, Node>();
  private edges: Edge[] = [];
  private width = 1;
  private height = 1;

  resize(width: number, height: number): void {
    this.width = Math.max(1, width);
    this.height = Math.max(1, height);
  }

  /**
   * Merge a returned expansion into the layout.
   *
   * `anchor` is the entity the analyst expanded. New nodes are seeded on a small
   * ring around it rather than at random or at the centre: seeding at the centre
   * makes every expansion appear to explode out of the middle of an unrelated
   * part of the graph, and random seeding puts a node's first frame somewhere it
   * has no relationship to, which the eye tracks as motion and remembers as a
   * position.
   */
  merge(ids: readonly string[], edges: readonly Edge[], anchor: string | null): string[] {
    const anchorNode = anchor !== null ? this.nodes.get(anchor) : undefined;
    const cx = anchorNode?.x ?? this.width / 2;
    const cy = anchorNode?.y ?? this.height / 2;

    const added: string[] = [];
    let seeded = 0;
    for (const id of ids) {
      if (this.nodes.has(id)) continue;
      // Golden-angle ring so successive additions do not stack on one another.
      const theta = seeded * 2.399963;
      const r = 44 + 13 * Math.sqrt(seeded);
      this.nodes.set(id, {
        id,
        x: cx + Math.cos(theta) * r,
        y: cy + Math.sin(theta) * r,
        vx: 0, vy: 0,
        pinned: false,
        age: 0,
      });
      added.push(id);
      seeded += 1;
    }

    // Edge list is replaced, not appended: the server returns the authoritative
    // edge set for the disclosed subgraph, and keeping stale edges from a
    // previous decision would draw relationships the current decision did not
    // release.
    this.edges = edges.filter(
      (e) => this.nodes.has(e.src) && this.nodes.has(e.dst),
    );
    return added;
  }

  /** Drop everything. Called on idle wipe and session loss. */
  clear(): void {
    this.nodes.clear();
    this.edges = [];
  }

  remove(ids: Iterable<string>): void {
    for (const id of ids) this.nodes.delete(id);
    this.edges = this.edges.filter(
      (e) => this.nodes.has(e.src) && this.nodes.has(e.dst),
    );
  }

  pin(id: string, x: number, y: number): void {
    const n = this.nodes.get(id);
    if (!n) return;
    n.x = x; n.y = y; n.vx = 0; n.vy = 0; n.pinned = true;
  }

  unpin(id: string): void {
    const n = this.nodes.get(id);
    if (n) n.pinned = false;
  }

  /** One integration step. Returns true while anything is still moving enough to
   *  be worth another frame — the render loop stops when this goes false, so an
   *  idle graph costs no CPU and no battery on a mobile data terminal. */
  step(): boolean {
    const list = [...this.nodes.values()];
    const n = list.length;
    if (n === 0) return false;

    for (const a of list) {
      if (a.pinned) continue;
      let fx = 0;
      let fy = 0;

      for (const b of list) {
        if (a === b) continue;
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) {
          // Coincident nodes. Nudge deterministically rather than with
          // Math.random(): a random jitter makes the layout unreproducible, and
          // an analyst who describes "the node above the phone" in a case note
          // should find it there when they reopen the same expansion.
          dx = ((a.id.charCodeAt(0) % 7) - 3) || 1;
          dy = ((a.id.charCodeAt(1) % 7) - 3) || 1;
          d2 = dx * dx + dy * dy;
        }
        const inv = REPULSION / d2;
        const d = Math.sqrt(d2);
        fx += (dx / d) * inv;
        fy += (dy / d) * inv;
      }

      fx += (this.width / 2 - a.x) * CENTRE_PULL * n;
      fy += (this.height / 2 - a.y) * CENTRE_PULL * n;

      a.vx = (a.vx + fx * 0.001) * DAMPING;
      a.vy = (a.vy + fy * 0.001) * DAMPING;
    }

    for (const e of this.edges) {
      const a = this.nodes.get(e.src);
      const b = this.nodes.get(e.dst);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.hypot(dx, dy) || 1;
      const f = (d - e.rest) * SPRING;
      const ux = (dx / d) * f;
      const uy = (dy / d) * f;
      if (!a.pinned) { a.vx += ux; a.vy += uy; }
      if (!b.pinned) { b.vx -= ux; b.vy -= uy; }
    }

    let moving = 0;
    for (const a of list) {
      a.age += 1;
      if (a.pinned) continue;
      // The stability guarantee. A node that has been on screen long enough for
      // the analyst to have noticed where it is moves at a fraction of the speed
      // of a node that just arrived.
      const mobility = a.age > SETTLE_FRAMES ? SETTLED_MOBILITY : 1;
      a.x += a.vx * mobility;
      a.y += a.vy * mobility;
      // Keep everything on the canvas. Clamping rather than wrapping: a node that
      // reappears on the opposite edge has moved without meaning to move.
      a.x = Math.min(this.width - 24, Math.max(24, a.x));
      a.y = Math.min(this.height - 24, Math.max(24, a.y));
      if (Math.abs(a.vx) + Math.abs(a.vy) > 0.05) moving += 1;
    }
    return moving > 0;
  }

  /** Nearest node within `radius` px of a point, or null. Used for hit testing;
   *  linear scan is fine at n <= 500 and avoids a spatial index that would need
   *  invalidating on every frame. */
  hit(x: number, y: number, radius = 14): Node | null {
    let best: Node | null = null;
    let bestD = radius * radius;
    for (const node of this.nodes.values()) {
      const dx = node.x - x;
      const dy = node.y - y;
      const d2 = dx * dx + dy * dy;
      if (d2 <= bestD) { bestD = d2; best = node; }
    }
    return best;
  }

  edgeList(): readonly Edge[] {
    return this.edges;
  }
}
