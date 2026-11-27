import type { ReactNode } from 'react';
import type { Entity, EntityType, Severity } from '../types/models';

/* ---------- formatting helpers ---------- */
export const fmtDate = (iso?: string) => (iso ? iso.slice(0, 10) : '—');
export const fmtDateTime = (iso?: string) =>
  iso ? iso.slice(0, 10) + ' ' + iso.slice(11, 16) : '—';
export const fmtMoney = (n: number, c = 'USD') =>
  `${c} ${n.toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
export const fmtDur = (s: number) =>
  s === 0 ? 'SMS' : s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m` : `${Math.round(s / 60)}m ${s % 60}s`;

/* ---------- states ---------- */
export const Spinner = () => <div className="spinner" aria-label="Loading" />;
export function StateBox({ title, children, error }: { title: string; children?: ReactNode; error?: boolean }) {
  return (
    <div className={`state-box${error ? ' error' : ''}`}>
      <div className="state-title">{title}</div>
      <div>{children}</div>
    </div>
  );
}
export const EmptyState = ({ msg = 'No records match the current filters.' }: { msg?: string }) => (
  <StateBox title="Nothing to display">{msg}</StateBox>
);
export const ErrorState = ({ msg, onRetry }: { msg: string; onRetry?: () => void }) => (
  <StateBox title="Request failed" error>
    <div className="mb">{msg}</div>
    {onRetry && <button className="btn sm" onClick={onRetry}>Retry</button>}
  </StateBox>
);

/* ---------- badges ---------- */
const SEV_TONE: Record<string, string> = { INFO: 'grey', LOW: 'grey', MEDIUM: 'warning', HIGH: 'danger', CRITICAL: 'critical' };
export const SevBadge = ({ sev }: { sev: Severity | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' }) => (
  <span className={`badge ${SEV_TONE[sev] ?? 'grey'}`}>{sev}</span>
);
export const StatusBadge = ({ s }: { s: string }) => {
  const tone = ['ACTIVE', 'CONNECTED', 'RESOLVED', 'HIGH'].includes(s) ? 'success'
    : ['OPEN', 'NEW', 'MEDIUM', 'ACKNOWLEDGED'].includes(s) ? 'info'
    : ['WATCHLIST', 'SUSPENDED', 'DEGRADED', 'INVESTIGATING', 'INACTIVE', 'MEDIUM'].includes(s) ? 'warning'
    : ['CRITICAL', 'DETAINED', 'FLAGGED', 'OFFLINE'].includes(s) ? 'danger' : 'grey';
  return <span className={`badge ${tone}`}>{s}</span>;
};
export const TypeBadge = ({ t }: { t: EntityType }) => <span className={`badge entity-${t}`}>{t}</span>;

/* ---------- risk meter ---------- */
export function RiskMeter({ score }: { score: number }) {
  const color = score >= 75 ? 'var(--danger)' : score >= 50 ? 'var(--warning)' : 'var(--success)';
  return (
    <span className="risk-meter" style={{ minWidth: 120 }}>
      <span className="bar"><span className="fill" style={{ width: `${score}%`, background: color }} /></span>
      <span className="mono small">{score}</span>
    </span>
  );
}

/* ---------- panel ---------- */
export function Panel({ title, hint, actions, children, flush }: {
  title: string; hint?: string; actions?: ReactNode; children: ReactNode; flush?: boolean;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{title}</h2>
        {hint && <span className="hint">{hint}</span>}
        {actions}
      </div>
      <div className={`panel-body${flush ? ' flush' : ''}`}>{children}</div>
    </section>
  );
}

/* ---------- data table ---------- */
export interface Col<T> {
  key: string;
  title: string;
  render?: (row: T) => ReactNode;
  className?: string;
}
interface TableProps<T> {
  cols: Col<T>[];
  rows?: T[];
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  rowKey: (row: T) => string;
  onRow?: (row: T) => void;
  empty?: string;
  pager?: { page: number; total: number; pageSize: number; onPage: (p: number) => void };
}
export function DataTable<T>({ cols, rows, loading, error, onRetry, rowKey, onRow, empty, pager }: TableProps<T>) {
  if (loading) return <><Spinner /><StateBox title="Loading records">Fetching from data service…</StateBox></>;
  if (error) return <ErrorState msg={error} onRetry={onRetry} />;
  if (!rows?.length) return <EmptyState msg={empty} />;
  const pages = pager ? Math.max(1, Math.ceil(pager.total / pager.pageSize)) : 1;
  return (
    <>
      <div className="table-wrap">
        <table className="tbl">
          <thead><tr>{cols.map((c) => <th key={c.key} className={c.className}>{c.title}</th>)}</tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={rowKey(r)} className={onRow ? 'clickable' : ''} onClick={() => onRow?.(r)}>
                {cols.map((c) => <td key={c.key} className={c.className}>{c.render ? c.render(r) : String((r as Record<string, unknown>)[c.key] ?? '—')}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pager && pages > 1 && (
        <div className="pager">
          <span>{pager.total} records — page {pager.page} of {pages}</span>
          <span className="pager-btns">
            <button className="btn sm" disabled={pager.page <= 1} onClick={() => pager.onPage(pager.page - 1)}>Prev</button>
            <button className="btn sm" disabled={pager.page >= pages} onClick={() => pager.onPage(pager.page + 1)}>Next</button>
          </span>
        </div>
      )}
    </>
  );
}

/* ---------- misc ---------- */
export const Stat = ({ label, value, foot, tone }: { label: string; value: ReactNode; foot?: string; tone?: string }) => (
  <div className={`stat ${tone ?? ''}`}>
    <div className="label">{label}</div>
    <div className="value">{value}</div>
    {foot && <div className="foot">{foot}</div>}
  </div>
);
export const Field = ({ label, children }: { label: string; children: ReactNode }) => (
  <label className="field"><span>{label}</span>{children}</label>
);
export function EntityLink({ id, entities, onClick }: { id: string; entities: Map<string, Entity>; onClick: (id: string) => void }) {
  const e = entities.get(id);
  if (!e) return <span className="mono muted">{id}</span>;
  return <a href={`/entity/${id}`} onClick={(ev) => { ev.preventDefault(); onClick(id); }}>{e.label}</a>;
}