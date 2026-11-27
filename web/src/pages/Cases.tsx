import { useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { useAsync } from '../hooks/useAsync';
import { api } from '../services/apiService';
import { DataTable, Field, Panel, StatusBadge, TypeBadge, RiskMeter, SevBadge, fmtDate, fmtDateTime } from '../components/ui';
import type { CaseStatus, Priority } from '../types/models';

export function CasesPage() {
  const nav = useNavigate();
  const [status, setStatus] = useState<CaseStatus | ''>('');
  const [priority, setPriority] = useState<Priority | ''>('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);
  const res = useAsync(() => api.listCases({ status: status || undefined, priority: priority || undefined, q, page, pageSize: 15 }), [status, priority, q, page]);

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Case Management</h1></div>
      <div className="filter-bar">
        <Field label="Filter"><input className="input grow" placeholder="Search title, code, summary…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} /></Field>
        <Field label="Status">
          <select className="input" value={status} onChange={(e) => { setStatus(e.target.value as CaseStatus | ''); setPage(1); }}>
            <option value="">All</option>{['OPEN', 'ACTIVE', 'SUSPENDED', 'CLOSED'].map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Priority">
          <select className="input" value={priority} onChange={(e) => { setPriority(e.target.value as Priority | ''); setPage(1); }}>
            <option value="">All</option>{['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
      </div>
      <Panel title="Cases" flush>
        <DataTable loading={res.loading} error={res.error} onRetry={res.reload} rowKey={(c) => c.id}
          onRow={(c) => nav(`/cases/${c.id}`)}
          pager={res.data ? { page, total: res.data.total, pageSize: 15, onPage: setPage } : undefined}
          cols={[
            { key: 'code', title: 'Code', render: (c) => <span className="mono nowrap">{c.code}</span> },
            { key: 'title', title: 'Title', render: (c) => <div>{c.title}<div className="muted small">{c.tags.join(' · ')}</div></div> },
            { key: 'status', title: 'Status', render: (c) => <StatusBadge s={c.status} /> },
            { key: 'priority', title: 'Priority', render: (c) => <StatusBadge s={c.priority} /> },
            { key: 'entities', title: 'Entities', render: (c) => <span className="mono">{c.entityIds.length}</span> },
            { key: 'openedAt', title: 'Opened', className: 'nowrap', render: (c) => fmtDate(c.openedAt) },
            { key: 'updatedAt', title: 'Updated', className: 'nowrap', render: (c) => fmtDate(c.updatedAt) },
          ]}
          rows={res.data?.data}
        />
      </Panel>
    </div>
  );
}

export function CaseDetailPage() {
  const { id } = useParams<{ id: string }>();
  const nav = useNavigate();
  const c = useAsync(() => api.getCase(id!), [id]);
  const events = useAsync(() => api.listEvents({ caseId: id!, pageSize: 100 }), [id]);
  const entities = useAsync(() => Promise.all((c.data?.entityIds ?? []).slice(0, 40).map((e) => api.getEntity(e).catch(() => null))), [c.data?.id]);

  if (c.loading) return <div className="state-box">Loading case…</div>;
  if (!c.data) return <div className="state-box error">Case not found.</div>;
  const cs = c.data;

  return (
    <div className="section-gap">
      <div className="page-header">
        <h1>{cs.code}</h1>
        <span className="muted">{cs.title}</span>
        <span className="actions"><StatusBadge s={cs.status} /><StatusBadge s={cs.priority} /></span>
      </div>
      <div className="grid main">
        <div className="section-gap">
          <Panel title="Summary">
            <p style={{ margin: 0 }}>{cs.summary}</p>
            <div className="flex wrap mt">
              <span className="small muted">Opened {fmtDate(cs.openedAt)} · Updated {fmtDateTime(cs.updatedAt)}</span>
              <span style={{ flex: 1 }} />
              <Link className="btn primary" to={`/reports?case=${cs.id}`}>Generate report</Link>
              <Link className="btn" to={`/network?center=${cs.entityIds[0] ?? ''}`}>Open network</Link>
            </div>
          </Panel>
          <Panel title={`Timeline (${events.data?.total ?? 0})`} flush>
            {events.data?.data.length ? (
              <div className="panel-body"><div className="timeline">
                {events.data.data.map((ev) => (
                  <div key={ev.id} className={`tl-item sev-${ev.severity}`}>
                    <div className="tl-time">{fmtDateTime(ev.occurredAt)} · {ev.source}</div>
                    <div><SevBadge sev={ev.severity} /> <strong style={{ color: 'var(--text-strong)' }}> {ev.title}</strong></div>
                    <div className="small muted">{ev.description}</div>
                  </div>
                ))}
              </div></div>
            ) : <div className="state-box">No events recorded for this case.</div>}
          </Panel>
        </div>
        <Panel title={`Linked entities (${cs.entityIds.length})`} flush>
          <div className="table-wrap"><table className="tbl"><tbody>
            {(entities.data ?? []).filter(Boolean).map((e) => (
              <tr key={e!.id} className="clickable" onClick={() => nav(`/entity/${e!.id}`)}>
                <td><TypeBadge t={e!.type} /></td>
                <td>{e!.label}<div className="muted small mono">{e!.id}</div></td>
                <td><RiskMeter score={e!.riskScore} /></td>
              </tr>
            ))}
          </tbody></table></div>
        </Panel>
      </div>
    </div>
  );
}