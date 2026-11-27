import { useSearchParams, useNavigate } from 'react-router-dom';
import { useState } from 'react';
import { useAsync } from '../hooks/useAsync';
import { api } from '../services/apiService';
import { DataTable, Field, Panel, TypeBadge, StatusBadge, RiskMeter, fmtDateTime } from '../components/ui';
import type { EntityType } from '../types/models';

export default function SearchPage() {
  const nav = useNavigate();
  const [sp, setSp] = useSearchParams();
  const q = sp.get('q') ?? '';
  const [input, setInput] = useState(q);
  const [type, setType] = useState<EntityType | ''>('');
  const [riskMin, setRiskMin] = useState('');
  const [page, setPage] = useState(1);

  const res = useAsync(
    () => api.listEntities({ q, type: type || undefined, riskMin: riskMin ? Number(riskMin) : undefined, page, pageSize: 15 }),
    [q, type, riskMin, page],
  );

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Entity Search</h1></div>
      <form className="filter-bar" onSubmit={(e) => { e.preventDefault(); setPage(1); setSp({ q: input }); }}>
        <Field label="Query"><input className="input grow" style={{ minWidth: 280 }} placeholder="Name, number, plate, alias, identifier…" value={input} onChange={(e) => setInput(e.target.value)} /></Field>
        <Field label="Entity type">
          <select className="input" value={type} onChange={(e) => { setType(e.target.value as EntityType | ''); setPage(1); }}>
            <option value="">All types</option>
            {['PERSON', 'PHONE', 'VEHICLE', 'ORGANIZATION', 'ACCOUNT', 'LOCATION', 'EVENT'].map((t) => <option key={t}>{t}</option>)}
          </select>
        </Field>
        <Field label="Min. risk">
          <select className="input" value={riskMin} onChange={(e) => { setRiskMin(e.target.value); setPage(1); }}>
            <option value="">Any</option><option value="50">50+</option><option value="70">70+</option><option value="85">85+</option>
          </select>
        </Field>
        <button className="btn primary" type="submit">Search</button>
      </form>

      <Panel title={q ? `Results for "${q}"` : 'All entities'} hint={res.data ? `${res.data.total} matches` : undefined} flush>
        <DataTable
          loading={res.loading} error={res.error} onRetry={res.reload}
          rowKey={(e) => e.id}
          onRow={(e) => nav(`/entity/${e.id}`)}
          pager={res.data ? { page, total: res.data.total, pageSize: 15, onPage: setPage } : undefined}
          cols={[
            { key: 'id', title: 'ID', render: (e) => <span className="mono muted">{e.id}</span> },
            { key: 'label', title: 'Entity', render: (e) => <div>{e.label}<div className="muted small">{e.subtype}</div></div> },
            { key: 'type', title: 'Type', render: (e) => <TypeBadge t={e.type} /> },
            { key: 'status', title: 'Status', render: (e) => <StatusBadge s={e.status} /> },
            { key: 'risk', title: 'Risk', render: (e) => <RiskMeter score={e.riskScore} /> },
            { key: 'updatedAt', title: 'Updated', className: 'nowrap', render: (e) => fmtDateTime(e.updatedAt) },
          ]}
          rows={res.data?.data}
        />
      </Panel>
    </div>
  );
}