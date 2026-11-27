import { useMemo, useRef, useState, useCallback } from 'react';
import type { Entity, NetworkView, RelationshipType } from '../types/models';
import { TypeBadge, RiskMeter, fmtDate } from './ui';

const NODE_COLOR: Record<string, string> = {
  PERSON: '#7ba7d1', PHONE: '#8fb99a', VEHICLE: '#c2a05a', LOCATION: '#b58cc0',
  ORGANIZATION: '#c98f7d', ACCOUNT: '#7dc9c2', EVENT: '#a9b3c2',
};
const EDGE_COLOR: Record<string, string> = {
  COMMUNICATION: '#4f7fae', FINANCIAL: '#7dc9c2', OWNERSHIP: '#8a97ac',
  EMPLOYMENT: '#5f9e78', ASSOCIATION: '#c2a05a', CO_RESIDENCE: '#b58cc0',
  SIGHTING: '#c2574e', TRAVEL: '#c98f7d', FAMILY: '#a9b3c2',
};

const hash = (s: string) => { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return Math.abs(h); };

interface Pos { x: number; y: number }

/** Deterministic force-directed layout (fixed iterations, no animation churn). */
function layout(nodes: Entity[], edges: NetworkView['edges'], centerId: string): Map<string, Pos> {
  const pos = new Map<string, Pos & { vx: number; vy: number }>();
  nodes.forEach((n, i) => {
    const a = ((hash(n.id) % 628) / 100) + i * 0.35;
    pos.set(n.id, { x: Math.cos(a) * 180, y: Math.sin(a) * 180, vx: 0, vy: 0 });
  });
  const links = edges.filter((e) => pos.has(e.sourceId) && pos.has(e.targetId));
  for (let it = 0; it < 320; it++) {
    const ids = nodes.map((n) => n.id);
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = pos.get(ids[i])!, b = pos.get(ids[j])!;
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy || 1;
        if (d2 < 400) d2 = 400;
        const f = 5200 / d2;
        const d = Math.sqrt(d2);
        dx /= d; dy /= d;
        a.vx -= dx * f; a.vy -= dy * f;
        b.vx += dx * f; b.vy += dy * f;
      }
    }
    for (const e of links) {
      const a = pos.get(e.sourceId)!, b = pos.get(e.targetId)!;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = (d - 130) * 0.012 * (e.strength / 10 + 0.4);
      a.vx += (dx / d) * f; a.vy += (dy / d) * f;
      b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    }
    for (const n of nodes) {
      const p = pos.get(n.id)!;
      p.vx += -p.x * 0.008; p.vy += -p.y * 0.008;
      if (n.id === centerId) { p.vx += -p.x * 0.05; p.vy += -p.y * 0.05; }
      p.vx *= 0.82; p.vy *= 0.82;
      p.x += Math.max(-12, Math.min(12, p.vx));
      p.y += Math.max(-12, Math.min(12, p.vy));
    }
  }
  const out = new Map<string, Pos>();
  pos.forEach((p, id) => out.set(id, { x: p.x, y: p.y }));
  return out;
}

export const REL_TYPES = Object.keys(EDGE_COLOR) as RelationshipType[];

interface Props {
  view: NetworkView;
  entityMap: Map<string, Entity>;
  height?: number;
  onSelect?: (id: string) => void;
  selectedId?: string | null;
}
export function NetworkGraph({ view, entityMap, height = 460, onSelect, selectedId }: Props) {
  const [filter, setFilter] = useState<Set<RelationshipType>>(new Set(REL_TYPES));
  const [viewBox, setViewBox] = useState({ x: -420, y: -300, w: 840, h: 600 });
  const [hover, setHover] = useState<{ id: string; sx: number; sy: number } | null>(null);
  const drag = useRef<{ mode: 'pan' | null; sx: number; sy: number; vb: typeof viewBox } | null>(null);

  const edges = useMemo(() => view.edges.filter((e) => filter.has(e.type)), [view.edges, filter]);
  const pos = useMemo(() => layout(view.nodes, edges, view.centerId), [view.nodes, edges, view.centerId]);

  const toggle = (t: RelationshipType) =>
    setFilter((s) => { const n = new Set(s); n.has(t) ? n.delete(t) : n.add(t); return n; });

  const svgRef = useRef<SVGSVGElement>(null);
  const toSvg = useCallback((cx: number, cy: number) => {
    const r = svgRef.current!.getBoundingClientRect();
    return { x: viewBox.x + ((cx - r.left) / r.width) * viewBox.w, y: viewBox.y + ((cy - r.top) / r.height) * viewBox.h };
  }, [viewBox]);

  const onWheel = (e: React.WheelEvent) => {
    const factor = e.deltaY > 0 ? 1.12 : 0.89;
    const c = toSvg(e.clientX, e.clientY);
    setViewBox((vb) => {
      const w = Math.min(2400, Math.max(300, vb.w * factor));
      const h = vb.h * (w / vb.w);
      return { x: c.x - ((c.x - vb.x) / vb.w) * w, y: c.y - ((c.y - vb.y) / vb.h) * h, w, h };
    });
  };

  const degree = useMemo(() => {
    const m = new Map<string, number>();
    edges.forEach((e) => { m.set(e.sourceId, (m.get(e.sourceId) ?? 0) + 1); m.set(e.targetId, (m.get(e.targetId) ?? 0) + 1); });
    return m;
  }, [edges]);

  const hoverEnt = hover ? entityMap.get(hover.id) : null;

  return (
    <div>
      <div className="graph-wrap" style={{ height }}>
        <svg
          ref={svgRef}
          viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
          onWheel={onWheel}
          onPointerDown={(e) => { drag.current = { mode: 'pan', sx: e.clientX, sy: e.clientY, vb: viewBox }; (e.target as Element).setPointerCapture?.(e.pointerId); }}
          onPointerMove={(e) => {
            if (drag.current?.mode === 'pan') {
              const r = svgRef.current!.getBoundingClientRect();
              const dx = ((e.clientX - drag.current.sx) / r.width) * viewBox.w;
              const dy = ((e.clientY - drag.current.sy) / r.height) * viewBox.h;
              setViewBox({ ...drag.current.vb, x: drag.current.vb.x - dx, y: drag.current.vb.y - dy });
            }
          }}
          onPointerUp={() => { drag.current = null; }}
        >
          <g>
            {edges.map((e) => {
              const a = pos.get(e.sourceId), b = pos.get(e.targetId);
              if (!a || !b) return null;
              return <line key={e.id} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={EDGE_COLOR[e.type]} strokeWidth={0.5 + e.strength * 0.28} strokeOpacity={0.55} />;
            })}
            {view.nodes.map((n) => {
              const p = pos.get(n.id);
              if (!p) return null;
              const r = 6 + (degree.get(n.id) ?? 0) * 1.3 + n.riskScore / 28;
              const isSel = selectedId === n.id || view.centerId === n.id;
              return (
                <g key={n.id} transform={`translate(${p.x},${p.y})`}
                  onPointerEnter={(e) => setHover({ id: n.id, sx: e.clientX, sy: e.clientY })}
                  onPointerLeave={() => setHover(null)}
                  onClick={(e) => { e.stopPropagation(); onSelect?.(n.id); }}
                  style={{ cursor: 'pointer' }}>
                  {isSel && <circle r={r + 5} fill="none" stroke="#6d9bc8" strokeWidth={1.5} strokeDasharray="3 2" />}
                  <circle r={r} fill={NODE_COLOR[n.type]} fillOpacity={0.9} stroke="#0a0f18" strokeWidth={1.5} />
                  {(n.riskScore >= 75 || isSel) && (
                    <text y={-r - 5} textAnchor="middle" fontSize={12} fill="#d7deea" fontFamily="Segoe UI, sans-serif">
                      {n.label.length > 26 ? n.label.slice(0, 26) + '…' : n.label}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
        {hoverEnt && (
          <div className="graph-tooltip" style={{ left: 12, top: 12 }}>
            <div style={{ fontWeight: 600, color: 'var(--text-strong)' }}>{hoverEnt.label}</div>
            <div className="muted small">{hoverEnt.id} · {hoverEnt.subtype ?? hoverEnt.type}</div>
            <div className="mt"><RiskMeter score={hoverEnt.riskScore} /></div>
          </div>
        )}
      </div>
      <div className="graph-legend">
        {REL_TYPES.map((t) => (
          <button key={t} className="btn ghost sm" onClick={() => toggle(t)} style={{ opacity: filter.has(t) ? 1 : 0.35 }}>
            <span className="swatch" style={{ background: EDGE_COLOR[t], borderRadius: 0 }} /> {t}
          </button>
        ))}
      </div>
    </div>
  );
}

export function NodeDetail({ entity, edges, entityMap, onOpen }: {
  entity: Entity; edges: NetworkView['edges']; entityMap: Map<string, Entity>; onOpen: (id: string) => void;
}) {
  const linked = edges
    .filter((e) => e.sourceId === entity.id || e.targetId === entity.id)
    .map((e) => ({ rel: e, other: entityMap.get(e.sourceId === entity.id ? e.targetId : e.sourceId) }))
    .filter((x) => x.other)
    .sort((a, b) => b.rel.strength - a.rel.strength);
  return (
    <div className="section-gap">
      <div>
        <div className="flex wrap"><TypeBadge t={entity.type} /><span className="mono muted">{entity.id}</span></div>
        <h2 className="mt">{entity.label}</h2>
        {entity.subtype && <div className="muted small">{entity.subtype}</div>}
        <div className="mt"><RiskMeter score={entity.riskScore} /></div>
        {entity.aliases.length > 0 && <div className="small muted mt">Aliases: {entity.aliases.join(', ')}</div>}
      </div>
      <div>
        <h3>Connected entities ({linked.length})</h3>
        <div className="table-wrap mt">
          <table className="tbl">
            <thead><tr><th>Entity</th><th>Relationship</th><th>Str.</th></tr></thead>
            <tbody>
              {linked.slice(0, 14).map(({ rel, other }) => (
                <tr key={rel.id} className="clickable" onClick={() => onOpen(other!.id)}>
                  <td>
                    <div>{other!.label}</div>
                    <div className="muted small mono">{other!.id} · {rel.type}</div>
                  </td>
                  <td className="small">{rel.label ?? rel.type}<div className="muted">{fmtDate(rel.lastSeen)}</div></td>
                  <td className="mono">{rel.strength}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}