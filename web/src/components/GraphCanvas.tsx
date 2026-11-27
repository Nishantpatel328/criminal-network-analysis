/**
 * The canvas host.
 *
 * React owns the DOM element and the event wiring; it does not own a single pixel
 * inside the canvas. Node positions live in a `Layout` instance held in a ref and
 * are mutated in place at 60fps. Putting them in state would mean 500 objects
 * reconciled per frame to produce one imperative `drawImage`-equivalent call,
 * which is all cost and no benefit.
 *
 * The frame loop stops when the layout stops moving. An idle graph costs nothing,
 * which matters on the mobile data terminals this runs on in vehicles.
 */

import { useCallback, useEffect, useRef } from "react";

import { Layout } from "../graph/layout";
import type { Edge } from "../graph/layout";
import { draw } from "../graph/render";
import type { Scene } from "../graph/render";

export interface GraphCanvasProps {
  scene: Scene;
  /** Edges in layout terms (rest lengths), recomputed by the caller whenever the
   *  disclosed edge set changes. */
  layoutEdges: readonly Edge[];
  nodeIds: readonly string[];
  /** The entity the analyst expanded from, so new nodes seed beside it. */
  anchorId: string | null;
  onSelect: (eid: string | null) => void;
  onHover: (eid: string | null) => void;
  onExpand: (eid: string) => void;
  /** Bumped by the caller to force a wipe (idle timeout, session loss). */
  wipeToken: number;
}

export function GraphCanvas(props: GraphCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const layoutRef = useRef<Layout>(new Layout());
  const sceneRef = useRef<Scene>(props.scene);
  const frameRef = useRef<number | null>(null);
  const dragRef = useRef<{ id: string; moved: boolean } | null>(null);

  // The scene is read by the frame loop, which is outside React's render cycle.
  // Keeping it in a ref that is refreshed every render is the honest way to
  // bridge the two; reading `props.scene` from inside the loop would capture a
  // stale value from whichever render created the loop.
  sceneRef.current = props.scene;

  const paint = useCallback(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d", { alpha: false });
    if (!canvas || !ctx) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    draw(ctx, layoutRef.current, sceneRef.current, w, h, dpr);
  }, []);

  const tick = useCallback(() => {
    const moving = layoutRef.current.step();
    paint();
    frameRef.current = moving ? requestAnimationFrame(tick) : null;
  }, [paint]);

  const kick = useCallback(() => {
    if (frameRef.current === null) frameRef.current = requestAnimationFrame(tick);
  }, [tick]);

  /* --- Sizing --------------------------------------------------------- */

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      // Backing store in device pixels, CSS box in layout pixels. Without this
      // the graph is soft on every retina and hidpi display, and a soft 11px
      // label is a misread phone number.
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      layoutRef.current.resize(w, h);
      kick();
    };

    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    return () => observer.disconnect();
  }, [kick]);

  /* --- Data merge ----------------------------------------------------- */

  useEffect(() => {
    const layout = layoutRef.current;
    // Drop nodes the server no longer discloses. A node that was released under a
    // previous decision and is absent from the current one must leave the screen:
    // keeping it would show intelligence under an authorisation that has lapsed.
    const incoming = new Set(props.nodeIds);
    const stale = [...layout.nodes.keys()].filter((id) => !incoming.has(id));
    if (stale.length > 0) layout.remove(stale);

    layout.merge(props.nodeIds, props.layoutEdges, props.anchorId);
    kick();
  }, [props.nodeIds, props.layoutEdges, props.anchorId, kick]);

  useEffect(() => {
    layoutRef.current.clear();
    paint();
  }, [props.wipeToken, paint]);

  useEffect(() => {
    paint();
  }, [props.scene, paint]);

  useEffect(() => () => {
    if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
  }, []);

  /* --- Pointer -------------------------------------------------------- */

  const toLocal = (ev: React.PointerEvent<HTMLCanvasElement>) => {
    const rect = ev.currentTarget.getBoundingClientRect();
    return { x: ev.clientX - rect.left, y: ev.clientY - rect.top };
  };

  const onPointerDown = (ev: React.PointerEvent<HTMLCanvasElement>) => {
    const { x, y } = toLocal(ev);
    const hit = layoutRef.current.hit(x, y);
    if (hit) {
      dragRef.current = { id: hit.id, moved: false };
      ev.currentTarget.setPointerCapture(ev.pointerId);
    } else {
      props.onSelect(null);
    }
  };

  const onPointerMove = (ev: React.PointerEvent<HTMLCanvasElement>) => {
    const { x, y } = toLocal(ev);
    const drag = dragRef.current;
    if (drag) {
      dragRef.current = { id: drag.id, moved: true };
      layoutRef.current.pin(drag.id, x, y);
      kick();
      return;
    }
    const hit = layoutRef.current.hit(x, y);
    props.onHover(hit ? hit.id : null);
  };

  const onPointerUp = (ev: React.PointerEvent<HTMLCanvasElement>) => {
    const drag = dragRef.current;
    dragRef.current = null;
    if (!drag) return;
    ev.currentTarget.releasePointerCapture(ev.pointerId);
    // A drag places the node; a click selects it. Distinguished by whether the
    // pointer moved, so an analyst arranging the graph does not fire a
    // disclosure request for every node they tidy up — each selection is an
    // audited read, and accidental reads are audit noise that hides real ones.
    if (!drag.moved) props.onSelect(drag.id);
  };

  const onDoubleClick = (ev: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = ev.currentTarget.getBoundingClientRect();
    const hit = layoutRef.current.hit(ev.clientX - rect.left, ev.clientY - rect.top);
    if (hit) props.onExpand(hit.id);
  };

  /* --- Keyboard -------------------------------------------------------
     A canvas is opaque to a screen reader and to keyboard navigation. The graph
     is not the only route to any record — the selection card and the community
     panel are ordinary focusable DOM — but the canvas still takes focus and
     supports arrow-key traversal between adjacent nodes, because an analyst using
     a keyboard should not be locked out of the primary view. The accessible name
     announces the counts, which is the part a sighted user gets from the shape. */

  const onKeyDown = (ev: React.KeyboardEvent<HTMLCanvasElement>) => {
    const ids = [...layoutRef.current.nodes.keys()];
    if (ids.length === 0) return;
    const current = props.scene.selectedId;
    const at = current === null ? -1 : ids.indexOf(current);

    if (ev.key === "ArrowRight" || ev.key === "ArrowDown") {
      ev.preventDefault();
      props.onSelect(ids[(at + 1) % ids.length] ?? null);
    } else if (ev.key === "ArrowLeft" || ev.key === "ArrowUp") {
      ev.preventDefault();
      props.onSelect(ids[(at - 1 + ids.length) % ids.length] ?? null);
    } else if (ev.key === "Enter" && current !== null) {
      ev.preventDefault();
      props.onExpand(current);
    } else if (ev.key === "Escape") {
      props.onSelect(null);
    }
  };

  const count = props.nodeIds.length;
  const edgeCount = props.layoutEdges.length;

  return (
    <>
      <canvas
        ref={canvasRef}
        className="stage__canvas"
        tabIndex={0}
        role="application"
        aria-label={
          `Network graph. ${count} record${count === 1 ? "" : "s"}, ` +
          `${edgeCount} connection${edgeCount === 1 ? "" : "s"}. ` +
          `Arrow keys move between records, Enter expands the selected record.`
        }
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={() => props.onHover(null)}
        onDoubleClick={onDoubleClick}
        onKeyDown={onKeyDown}
      />
      {count > 0 && (
        <p className="stage__count">
          {count} shown · {edgeCount} connections
          {props.scene.truncated ? " · incomplete" : ""}
        </p>
      )}
    </>
  );
}
