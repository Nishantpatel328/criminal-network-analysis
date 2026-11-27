import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAsync } from '../hooks/useAsync';
import { api, isMockMode } from '../services/apiService';
import { useAuth } from '../store/AuthContext';
import { DataTable, Field, Panel, SevBadge, StatusBadge, fmtDateTime } from '../components/ui';
import type { AlertSeverity, AlertStatus, InvestigationReport } from '../types/models';

export function AlertsPage() {
  const [severity, setSeverity] = useState<AlertSeverity | ''>('');
  const [status, setStatus] = useState<AlertStatus | ''>('');
  const [tick, setTick] = useState(0);
  const res = useAsync(() => api.listAlerts({ severity: severity || undefined, status: status || undefined, pageSize: 100 }), [severity, status, tick]);

  const ack = async (id: string) => { await api.acknowledgeAlert(id); setTick((t) => t + 1); };

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Alerts &amp; Suspicious Patterns</h1></div>
      <div className="filter-bar">
        <Field label="Severity">
          <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value as AlertSeverity | '')}>
            <option value="">All</option>{['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Status">
          <select className="input" value={status} onChange={(e) => setStatus(e.target.value as AlertStatus | '')}>
            <option value="">All</option>{['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED'].map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
      </div>
      <Panel title={`Alerts (${res.data?.total ?? 0})`} hint="rule-based detections from the analytics engine" flush>
        <DataTable loading={res.loading} error={res.error} onRetry={res.reload} rowKey={(a) => a.id}
          cols={[
            { key: 'severity', title: 'Severity', render: (a) => <SevBadge sev={a.severity} /> },
            { key: 'title', title: 'Alert', render: (a) => <div>{a.title}<div className="muted small">{a.description}</div></div> },
            { key: 'rule', title: 'Rule', render: (a) => <span className="mono small">{a.rule}</span> },
            { key: 'entities', title: 'Entities', render: (a) => <span className="mono small">{a.entityIds.join(', ')}</span> },
            { key: 'caseId', title: 'Case', render: (a) => <span className="mono small">{a.caseId ?? '—'}</span> },
            { key: 'createdAt', title: 'Raised', className: 'nowrap', render: (a) => fmtDateTime(a.createdAt) },
            { key: 'status', title: 'Status', render: (a) => <StatusBadge s={a.status} /> },
            { key: 'act', title: '', render: (a) => a.status === 'NEW' ? <button className="btn sm" onClick={() => ack(a.id)}>Acknowledge</button> : null },
          ]}
          rows={res.data?.data}
        />
      </Panel>
    </div>
  );
}

export function ReportsPage() {
  const [sp] = useSearchParams();
  const [caseId, setCaseId] = useState(sp.get('case') ?? 'C-2026-014');
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const cases = useAsync(() => api.listCases({ pageSize: 100 }), []);

  const generate = async () => {
    setBusy(true); setErr(null);
    try { setReport(await api.generateReport(caseId)); }
    catch (e) { setErr(e instanceof Error ? e.message : 'Failed'); }
    finally { setBusy(false); }
  };

  const download = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${report!.caseId}-intelligence-summary.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="section-gap">
      <div className="page-header">
        <h1>Intelligence Reports</h1>
        <span className="actions">
          <select className="input" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
            {(cases.data?.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.code} — {c.title}</option>)}
          </select>
          <button className="btn primary" onClick={generate} disabled={busy}>{busy ? 'Generating…' : 'Generate'}</button>
          {report && <button className="btn" onClick={download}>Export JSON</button>}
        </span>
      </div>
      {err && <div className="badge danger">{err}</div>}
      {!report && !busy && <div className="state-box">Select a case and generate an intelligence summary. The report composes entities, timeline, financial exposure and recommended actions.</div>}
      {report && (
        <div className="report-doc">
          <h2 style={{ borderBottom: 'none', marginBottom: 2 }}>{report.title}</h2>
          <div className="report-meta">Case {report.caseId} · Generated {fmtDateTime(report.generatedAt)} · CIRIS analytic workspace</div>
          {report.sections.map((s) => (
            <section key={s.heading}>
              <h2>{s.heading}</h2>
              <p>{s.body}</p>
              {s.bullets && <ul className="clean">{s.bullets.map((b, i) => <li key={i}>{b}</li>)}</ul>}
              {s.table && (
                <table className="tbl mt">
                  <thead><tr>{s.table.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
                  <tbody>{s.table.rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{c}</td>)}</tr>)}</tbody>
                </table>
              )}
            </section>
          ))}
        </div>
      )}
    </div>
  );
}

export function SourcesPage() {
  const [tick, setTick] = useState(0);
  const res = useAsync(() => api.listDataSources(), [tick]);
  const [form, setForm] = useState({ sourceId: 'DS-4', records: 100, note: '' });
  const [msg, setMsg] = useState<string | null>(null);

  const runImport = async () => {
    if (api.importData) {
      await api.importData(form.sourceId, { records: form.records, note: form.note });
      setMsg(`Imported ${form.records} records into ${form.sourceId} (mock).`);
      setTick((t) => t + 1);
    }
  };

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Data Sources &amp; Import</h1></div>
      <Panel title="Connected sources" hint="ingestion pipelines feeding the analytic workspace" flush>
        <DataTable loading={res.loading} error={res.error} onRetry={res.reload} rowKey={(s) => s.id}
          cols={[
            { key: 'name', title: 'Source', render: (s) => <div>{s.name}<div className="muted small">{s.owner}</div></div> },
            { key: 'kind', title: 'Kind', render: (s) => <span className="badge grey">{s.kind}</span> },
            { key: 'status', title: 'Status', render: (s) => <StatusBadge s={s.status} /> },
            { key: 'lastSync', title: 'Last sync', className: 'nowrap', render: (s) => fmtDateTime(s.lastSync) },
            { key: 'recordsIngested', title: 'Records', className: 'right nowrap', render: (s) => s.recordsIngested.toLocaleString() },
          ]}
          rows={res.data ?? []}
        />
      </Panel>
      {isMockMode && (
        <Panel title="Import records (demo)">
          <div className="filter-bar" style={{ marginBottom: 0 }}>
            <Field label="Target source">
              <select className="input" value={form.sourceId} onChange={(e) => setForm({ ...form, sourceId: e.target.value })}>
                {(res.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </Field>
            <Field label="Records"><input className="input" type="number" style={{ width: 110 }} value={form.records} onChange={(e) => setForm({ ...form, records: Number(e.target.value) })} /></Field>
            <Field label="Note"><input className="input grow" value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} /></Field>
            <button className="btn primary" onClick={runImport}>Import</button>
          </div>
          {msg && <div className="small muted mt">{msg}</div>}
        </Panel>
      )}
    </div>
  );
}

export function SettingsPage() {
  const { session } = useAuth();
  const p = session!.profile;
  const [name, setName] = useState(p.name);
  const [phone, setPhone] = useState(p.phone);
  const [saved, setSaved] = useState(false);

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Profile &amp; Settings</h1></div>
      <div className="grid cols-2">
        <Panel title="Investigator profile">
          <dl className="kv">
            <dt>Badge</dt><dd className="mono">{p.badge}</dd>
            <dt>Unit</dt><dd>{p.unit}</dd>
            <dt>Role</dt><dd>{p.role}</dd>
            <dt>Email</dt><dd className="mono">{p.email}</dd>
          </dl>
          <div className="filter-bar mt" style={{ marginBottom: 0 }}>
            <Field label="Display name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
            <Field label="Phone"><input className="input mono" value={phone} onChange={(e) => setPhone(e.target.value)} /></Field>
            <button className="btn primary" onClick={() => setSaved(true)}>Save</button>
          </div>
          {saved && <div className="small muted mt">Saved locally (backend persistence pending).</div>}
        </Panel>
        <Panel title="Workspace">
          <dl className="kv">
            <dt>Data mode</dt><dd>{isMockMode ? <span className="badge warning">Mock adapter — demo data</span> : <span className="badge success">Live API</span>}</dd>
            <dt>API base URL</dt><dd className="mono">{import.meta.env.VITE_API_BASE_URL || '(not set)'}</dd>
          </dl>
          <p className="muted small mt">
            To connect the production backend, set <span className="mono">VITE_API_BASE_URL</span> and
            <span className="mono"> VITE_USE_MOCK=false</span> in <span className="mono">.env</span>, then implement the
            endpoints documented in <span className="mono">src/services/api/endpoints.ts</span>. No UI changes required.
          </p>
        </Panel>
      </div>
    </div>
  );
}