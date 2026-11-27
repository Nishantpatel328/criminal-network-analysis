import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { useAsync } from '../hooks/useAsync';
import { api } from '../services/apiService';
import { DataTable, Field, Panel, SevBadge, fmtDateTime, fmtMoney, fmtDur } from '../components/ui';
import type { EventType, Severity, CDRRecord, Transaction } from '../types/models';

export function TimelinePage() {
  const [sp] = useSearchParams();
  const [type, setType] = useState<EventType | ''>('');
  const [sev, setSev] = useState<Severity | ''>('');
  const [caseId, setCaseId] = useState(sp.get('case') ?? '');
  const [from, setFrom] = useState(''); const [to, setTo] = useState('');
  const res = useAsync(() => api.listEvents({ type: type || undefined, severity: sev || undefined, caseId: caseId || undefined, from: from || undefined, to: to || undefined, pageSize: 200 }), [type, sev, caseId, from, to]);

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Event Timeline</h1></div>
      <div className="filter-bar">
        <Field label="Case"><input className="input mono" style={{ width: 160 }} value={caseId} onChange={(e) => setCaseId(e.target.value.toUpperCase())} /></Field>
        <Field label="Type">
          <select className="input" value={type} onChange={(e) => setType(e.target.value as EventType | '')}>
            <option value="">All</option>
            {['SIGHTING', 'MEETING', 'ARREST', 'CALL', 'TRANSFER', 'TRAVEL', 'TIP', 'SEIZURE', 'BREACH'].map((t) => <option key={t}>{t}</option>)}
          </select>
        </Field>
        <Field label="Severity">
          <select className="input" value={sev} onChange={(e) => setSev(e.target.value as Severity | '')}>
            <option value="">All</option>{['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="From"><input className="input" type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
        <Field label="To"><input className="input" type="date" value={to} onChange={(e) => setTo(e.target.value)} /></Field>
      </div>
      <Panel title={`Events (${res.data?.total ?? 0})`}>
        {res.loading ? <div className="state-box">Loading…</div> : res.error ? <div className="state-box error">{res.error}</div> :
          !res.data?.data.length ? <div className="state-box">No events match the filters.</div> : (
            <div className="timeline">
              {res.data.data.map((ev) => (
                <div key={ev.id} className={`tl-item sev-${ev.severity}`}>
                  <div className="tl-time">{fmtDateTime(ev.occurredAt)} · {ev.source}{ev.caseId ? ` · ${ev.caseId}` : ''}</div>
                  <div><SevBadge sev={ev.severity} /> <span className="badge grey">{ev.type}</span> <strong style={{ color: 'var(--text-strong)' }}> {ev.title}</strong></div>
                  <div className="small muted">{ev.description}</div>
                </div>
              ))}
            </div>
          )}
      </Panel>
    </div>
  );
}

export function CDRPage() {
  const [number, setNumber] = useState('');
  const [kind, setKind] = useState<CDRRecord['kind'] | ''>('');
  const [page, setPage] = useState(1);
  const res = useAsync(() => api.listCDR({ number: number || undefined, kind: kind || undefined, page, pageSize: 25 }), [number, kind, page]);

  const chart = useAsync(() => api.listCDR({ pageSize: 500 }), []);
  const perDay = Object.values((chart.data?.data ?? []).reduce<Record<string, { day: string; calls: number; sms: number }>>((acc, r) => {
    const day = r.startedAt.slice(5, 10);
    acc[day] ??= { day, calls: 0, sms: 0 };
    r.kind === 'SMS' ? acc[day].sms++ : acc[day].calls++;
    return acc;
  }, {})).sort((a, b) => a.day.localeCompare(b.day));

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Communication Records (CDR)</h1></div>
      <div className="filter-bar">
        <Field label="Number"><input className="input mono grow" placeholder="+250…" value={number} onChange={(e) => { setNumber(e.target.value); setPage(1); }} /></Field>
        <Field label="Type">
          <select className="input" value={kind} onChange={(e) => { setKind(e.target.value as CDRRecord['kind'] | ''); setPage(1); }}>
            <option value="">All</option><option>VOICE</option><option>SMS</option><option>DATA</option>
          </select>
        </Field>
      </div>
      <div className="grid cols-2">
        <Panel title="Records" flush>
          <DataTable loading={res.loading} error={res.error} onRetry={res.reload} rowKey={(c) => c.id}
            pager={res.data ? { page, total: res.data.total, pageSize: 25, onPage: setPage } : undefined}
            cols={[
              { key: 'startedAt', title: 'Time', className: 'nowrap', render: (c) => fmtDateTime(c.startedAt) },
              { key: 'callerNumber', title: 'Caller', render: (c) => <span className="mono">{c.callerNumber}</span> },
              { key: 'calleeNumber', title: 'Callee', render: (c) => <span className="mono">{c.calleeNumber}</span> },
              { key: 'kind', title: 'Type', render: (c) => <span className="badge grey">{c.kind}</span> },
              { key: 'durationSec', title: 'Duration', render: (c) => fmtDur(c.durationSec) },
              { key: 'cellSiteName', title: 'Cell site', render: (c) => <span className="small muted">{c.cellSiteName ?? '—'}</span> },
            ]}
            rows={res.data?.data}
          />
        </Panel>
        <Panel title="Volume by day" hint="voice vs SMS">
          <div style={{ height: 280 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={perDay}>
                <CartesianGrid stroke="#223047" vertical={false} />
                <XAxis dataKey="day" tick={{ fill: '#8a97ac', fontSize: 11 }} />
                <YAxis tick={{ fill: '#8a97ac', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#0b1322', border: '1px solid #2e405c', fontSize: 12 }} />
                <Bar dataKey="calls" stackId="a" fill="#4f7fae" name="Voice" />
                <Bar dataKey="sms" stackId="a" fill="#5f9e78" name="SMS" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>
    </div>
  );
}

export function FinancialPage() {
  const [accountId, setAccountId] = useState('');
  const [channel, setChannel] = useState<Transaction['channel'] | ''>('');
  const [direction, setDirection] = useState<'IN' | 'OUT' | ''>('');
  const [minAmount, setMinAmount] = useState('');
  const res = useAsync(() => api.listTransactions({ accountId: accountId || undefined, channel: channel || undefined, direction: direction || undefined, minAmount: minAmount ? Number(minAmount) : undefined, pageSize: 200 }), [accountId, channel, direction, minAmount]);

  const flags = (res.data?.data ?? []).filter((t) => t.riskFlags.length > 0);
  const byFlag = flags.flatMap((t) => t.riskFlags).reduce<Record<string, number>>((a, f) => ((a[f] = (a[f] ?? 0) + 1), a), {});

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Financial Transaction Analysis</h1></div>
      <div className="filter-bar">
        <Field label="Account"><input className="input mono" style={{ width: 150 }} placeholder="AC-5002" value={accountId} onChange={(e) => setAccountId(e.target.value.toUpperCase())} /></Field>
        <Field label="Channel">
          <select className="input" value={channel} onChange={(e) => setChannel(e.target.value as Transaction['channel'] | '')}>
            <option value="">All</option>{['WIRE', 'CASH', 'CARD', 'MOBILE', 'CHECK'].map((c) => <option key={c}>{c}</option>)}
          </select>
        </Field>
        <Field label="Direction">
          <select className="input" value={direction} onChange={(e) => setDirection(e.target.value as 'IN' | 'OUT' | '')}>
            <option value="">All</option><option value="IN">IN</option><option value="OUT">OUT</option>
          </select>
        </Field>
        <Field label="Min amount"><input className="input" type="number" style={{ width: 120 }} value={minAmount} onChange={(e) => setMinAmount(e.target.value)} /></Field>
      </div>
      <div className="grid stats">
        <div className="stat"><div className="label">Movements</div><div className="value">{res.data?.total ?? 0}</div></div>
        <div className="stat warning"><div className="label">Flagged</div><div className="value">{flags.length}</div></div>
        <div className="stat danger"><div className="label">Flagged value</div><div className="value" style={{ fontSize: 18 }}>{fmtMoney(flags.reduce((s, t) => s + t.amount, 0), flags[0]?.currency ?? 'USD')}</div></div>
        <div className="stat"><div className="label">Distinct patterns</div><div className="value">{Object.keys(byFlag).length}</div></div>
      </div>
      <div className="grid cols-2">
        <Panel title="Pattern frequency" hint="risk flags across filtered set">
          <div className="flex wrap" style={{ alignItems: 'flex-start' }}>
            {Object.entries(byFlag).sort((a, b) => b[1] - a[1]).map(([f, n]) => (
              <span key={f} className="badge warning">{f} × {n}</span>
            ))}
            {!flags.length && <span className="muted small">No flagged transactions in this view.</span>}
          </div>
        </Panel>
        <Panel title="Reading the pattern" hint="analyst note">
          <p className="muted small" style={{ margin: 0 }}>
            Sub-threshold cash deposits split across branches within 48h indicate deliberate
            structuring. Escrow round-amount releases against generic consulting invoices are
            consistent with layering. Correlate timing with CDR bursts and ANPR sightings
            before escalation.
          </p>
        </Panel>
      </div>
      <Panel title="Transactions" flush>
        <DataTable loading={res.loading} error={res.error} onRetry={res.reload} rowKey={(t) => t.id}
          cols={[
            { key: 'occurredAt', title: 'Date', className: 'nowrap', render: (t) => fmtDateTime(t.occurredAt) },
            { key: 'accountId', title: 'Account', render: (t) => <span className="mono">{t.accountId}</span> },
            { key: 'narrative', title: 'Narrative', render: (t) => <div className="small">{t.narrative}<div className="muted">{t.counterpartyLabel ?? '—'}</div></div> },
            { key: 'channel', title: 'Channel', render: (t) => <span className="badge grey">{t.channel}</span> },
            { key: 'direction', title: 'Dir', render: (t) => <span className={`badge ${t.direction === 'IN' ? 'success' : 'danger'}`}>{t.direction}</span> },
            { key: 'amount', title: 'Amount', className: 'right nowrap', render: (t) => <span className="mono">{fmtMoney(t.amount, t.currency)}</span> },
            { key: 'riskFlags', title: 'Flags', render: (t) => <div className="flex wrap">{t.riskFlags.map((f) => <span key={f} className="badge warning">{f}</span>)}</div> },
          ]}
          rows={res.data?.data}
        />
      </Panel>
    </div>
  );
}

export function LocationsPage() {
  const [type, setType] = useState('');
  const [q, setQ] = useState('');
  const res = useAsync(() => api.listLocations({ type: type || undefined, q: q || undefined, pageSize: 100 }), [type, q]);
  const locs = res.data?.data ?? [];
  const lats = locs.map((l) => l.lat), lngs = locs.map((l) => l.lng);
  const minLat = Math.min(...lats, 0), maxLat = Math.max(...lats, 1);
  const minLng = Math.min(...lngs, 0), maxLng = Math.max(...lngs, 1);

  return (
    <div className="section-gap">
      <div className="page-header"><h1>Locations</h1></div>
      <div className="filter-bar">
        <Field label="Filter"><input className="input grow" placeholder="Name or address…" value={q} onChange={(e) => setQ(e.target.value)} /></Field>
        <Field label="Type">
          <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">All</option>{['ADDRESS', 'BUSINESS', 'CELL_SITE', 'BORDER', 'SAFEHOUSE'].map((t) => <option key={t}>{t}</option>)}
          </select>
        </Field>
      </div>
      <div className="grid cols-2">
        <Panel title="Geographic distribution" hint="relative plot — tile provider can be integrated later">
          <svg viewBox="0 0 600 360" style={{ width: '100%', background: '#0b1322', border: '1px solid var(--border)' }}>
            {Array.from({ length: 11 }, (_, i) => <line key={`v${i}`} x1={i * 60} y1={0} x2={i * 60} y2={360} stroke="#162032" />)}
            {Array.from({ length: 7 }, (_, i) => <line key={`h${i}`} x1={0} y1={i * 60} x2={600} y2={i * 60} stroke="#162032" />)}
            {locs.map((l) => {
              const x = 20 + ((l.lng - minLng) / Math.max(1e-6, maxLng - minLng)) * 560;
              const y = 340 - ((l.lat - minLat) / Math.max(1e-6, maxLat - minLat)) * 320;
              return (
                <g key={l.id}>
                  <circle cx={x} cy={y} r={7} fill={l.type === 'SAFEHOUSE' ? '#c2574e' : l.type === 'BORDER' ? '#c2a05a' : '#4f7fae'} fillOpacity={0.85}>
                    <title>{`${l.name}\n${l.address}`}</title>
                  </circle>
                  <text x={x + 10} y={y + 4} fontSize={10} fill="#8a97ac">{l.name}</text>
                </g>
              );
            })}
          </svg>
        </Panel>
        <Panel title="Location register" flush>
          <DataTable loading={res.loading} error={res.error} onRetry={res.reload} rowKey={(l) => l.id}
            cols={[
              { key: 'name', title: 'Name', render: (l) => <div>{l.name}<div className="muted small">{l.address}</div></div> },
              { key: 'type', title: 'Type', render: (l) => <span className="badge grey">{l.type}</span> },
              { key: 'coords', title: 'Lat / Lng', className: 'nowrap', render: (l) => <span className="mono small">{l.lat.toFixed(4)}, {l.lng.toFixed(4)}</span> },
              { key: 'notes', title: 'Notes', render: (l) => <span className="small muted">{l.notes ?? '—'}</span> },
            ]}
            rows={locs}
          />
        </Panel>
      </div>
    </div>
  );
}