import { useParams, useNavigate } from 'react-router-dom';
import { useState } from 'react';
import { useAsync } from '../hooks/useAsync';
import { api } from '../services/apiService';
import { Panel, TypeBadge, StatusBadge, RiskMeter, DataTable, SevBadge, fmtDateTime, fmtMoney, fmtDur } from '../components/ui';
import { NetworkGraph } from '../components/NetworkGraph';

const TABS = ['Overview', 'Connections', 'Network', 'Timeline', 'Financial', 'Communications'] as const;

export default function EntityProfilePage() {
  const { id } = useParams<{ id: string }>();
  const nav = useNavigate();
  const [tab, setTab] = useState<(typeof TABS)[number]>('Overview');

  const ent = useAsync(() => api.getEntity(id!), [id]);
  const rels = useAsync(() => api.listRelationships({ entityId: id!, pageSize: 50 }), [id]);
  const net = useAsync(() => api.getNetwork(id!, { depth: 1 }), [id]);
  const events = useAsync(() => api.listEvents({ entityId: id!, pageSize: 50 }), [id]);
  const txs = useAsync(() => api.listTransactions({ pageSize: 100 }), []);
  const cdr = useAsync(() => api.listCDR({ pageSize: 100 }), []);

  const e = ent.data;
  const entityMap = new Map((net.data?.nodes ?? []).map((n) => [n.id, n]));
  const accountIds = new Set(
    (rels.data?.data ?? []).filter((r) => r.type === 'OWNERSHIP')
      .map((r) => (r.sourceId === id ? r.targetId : r.sourceId)).filter((x) => x.startsWith('AC-')),
  );
  const phoneNumbers = new Set(
    (rels.data?.data ?? []).filter((r) => r.type === 'OWNERSHIP')
      .map((r) => (r.sourceId === id ? r.targetId : r.sourceId)).filter((x) => x.startsWith('PH-'))
      .map((x) => entityMap.get(x)?.label ?? ''),
  );
  const myTx = (txs.data?.data ?? []).filter((t) => accountIds.has(t.accountId));
  const myCdr = (cdr.data?.data ?? []).filter((c) => phoneNumbers.has(c.callerNumber) || phoneNumbers.has(c.calleeNumber) || c.callerNumber === e?.label);

  if (ent.loading) return <div className="state-box">Loading entity profile…</div>;
  if (ent.error || !e) return <div className="state-box error">Entity could not be loaded: {ent.error}</div>;

  return (
    <div className="section-gap">
      <div className="page-header">
        <TypeBadge t={e.type} />
        <h1>{e.label}</h1>
        <span className="mono muted">{e.id}</span>
        <span className="actions"><StatusBadge s={e.status} /><RiskMeter score={e.riskScore} /></span>
      </div>

      <div className="tabs">
        {TABS.map((t) => <button key={t} className={`tab${tab === t ? ' active' : ''}`} onClick={() => setTab(t)}>{t}</button>)}
      </div>

      {tab === 'Overview' && (
        <div className="grid cols-2">
          <Panel title="Identity & attributes">
            <dl className="kv">
              <dt>Subtype</dt><dd>{e.subtype ?? '—'}</dd>
              <dt>Status</dt><dd><StatusBadge s={e.status} /></dd>
              <dt>Risk score</dt><dd><RiskMeter score={e.riskScore} /></dd>
              <dt>Aliases</dt><dd>{e.aliases.length ? e.aliases.join(', ') : 'None recorded'}</dd>
              {Object.entries(e.attributes).map(([k, v]) => (
                <span key={k} style={{ display: 'contents' }}>
                  <dt className="mono">{k}</dt>
                  <dd>{/^P-\d|^ORG-\d|^L-\d/.test(v) ? <a href={`/entity/${v}`} onClick={(ev) => { ev.preventDefault(); nav(`/entity/${v}`); }}>{entityMap.get(v)?.label ?? v}</a> : v}</dd>
                </span>
              ))}
              <dt>First seen</dt><dd>{fmtDateTime(e.createdAt)}</dd>
              <dt>Last updated</dt><dd>{fmtDateTime(e.updatedAt)}</dd>
            </dl>
          </Panel>
          <Panel title="Assessment" hint="analytic workspace note">
            <p className="muted" style={{ marginTop: 0 }}>
              Composite risk of <strong style={{ color: 'var(--text-strong)' }}>{e.riskScore}/100</strong> derived from
              link density, source diversity and behavioural indicators. {e.riskScore >= 75
                ? 'Treat as a priority subject; coordinate any action through the case lead.'
                : e.riskScore >= 50 ? 'Maintain periodic review; relevance may increase as the network evolves.' : 'Low observed exposure within current scope.'}
            </p>
            <div className="flex wrap">
              <button className="btn" onClick={() => setTab('Network')}>Open in network view</button>
              <button className="btn" onClick={() => nav('/timeline')}>Full timeline</button>
            </div>
          </Panel>
        </div>
      )}

      {tab === 'Connections' && (
        <Panel title={`Relationships (${rels.data?.total ?? 0})`} hint="filter via Network Explorer for graph context" flush>
          <DataTable loading={rels.loading} error={rels.error} onRetry={rels.reload} rowKey={(r) => r.id}
            cols={[
              { key: 'other', title: 'Connected entity', render: (r) => {
                const oid = r.sourceId === id ? r.targetId : r.sourceId;
                return <a href={`/entity/${oid}`} onClick={(ev) => { ev.preventDefault(); nav(`/entity/${oid}`); }}>{entityMap.get(oid)?.label ?? oid}</a>;
              }},
              { key: 'type', title: 'Type', render: (r) => <span className="badge grey">{r.type}</span> },
              { key: 'label', title: 'Detail', render: (r) => <span className="small">{r.label ?? '—'}</span> },
              { key: 'strength', title: 'Strength', render: (r) => <span className="mono">{r.strength}/10</span> },
              { key: 'confidence', title: 'Confidence', render: (r) => <span className="badge info">{r.confidence}</span> },
              { key: 'source', title: 'Source', render: (r) => <span className="small muted">{r.source}</span> },
              { key: 'lastSeen', title: 'Last seen', className: 'nowrap', render: (r) => r.lastSeen },
            ]}
            rows={rels.data?.data}
          />
        </Panel>
      )}

      {tab === 'Network' && (
        <Panel title="1-hop relationship network" hint="click a node to re-center" flush>
          {net.data && <NetworkGraph view={net.data} entityMap={entityMap} height={540}
            selectedId={id!} onSelect={(nid) => nid !== id && nav(`/entity/${nid}`)} />}
        </Panel>
      )}

      {tab === 'Timeline' && (
        <Panel title="Linked events" flush>
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
          ) : <div className="state-box">No events linked to this entity.</div>}
        </Panel>
      )}

      {tab === 'Financial' && (
        <Panel title={accountIds.size ? 'Transactions on linked accounts' : 'No linked financial accounts'} flush>
          <DataTable rowKey={(t) => t.id} rows={myTx}
            cols={[
              { key: 'when', title: 'Date', className: 'nowrap', render: (t) => fmtDateTime(t.occurredAt) },
              { key: 'account', title: 'Account', render: (t) => <span className="mono">{t.accountId}</span> },
              { key: 'narrative', title: 'Narrative', render: (t) => <div className="small">{t.narrative}<div className="muted">{t.counterpartyLabel ?? '—'}</div></div> },
              { key: 'dir', title: 'Dir', render: (t) => <span className={`badge ${t.direction === 'IN' ? 'success' : 'danger'}`}>{t.direction}</span> },
              { key: 'amount', title: 'Amount', className: 'right nowrap', render: (t) => <span className="mono">{fmtMoney(t.amount, t.currency)}</span> },
              { key: 'flags', title: 'Flags', render: (t) => <div className="flex wrap">{t.riskFlags.map((f) => <span key={f} className="badge warning">{f}</span>)}</div> },
            ]}
          />
        </Panel>
      )}

      {tab === 'Communications' && (
        <Panel title={myCdr.length ? 'Call detail records on linked numbers' : 'No linked phone numbers'} flush>
          <DataTable rowKey={(c) => c.id} rows={myCdr.slice(0, 40)}
            cols={[
              { key: 'startedAt', title: 'Time', className: 'nowrap', render: (c) => fmtDateTime(c.startedAt) },
              { key: 'caller', title: 'Caller', render: (c) => <span className="mono">{c.callerNumber}</span> },
              { key: 'callee', title: 'Callee', render: (c) => <span className="mono">{c.calleeNumber}</span> },
              { key: 'kind', title: 'Type', render: (c) => <span className="badge grey">{c.kind}</span> },
              { key: 'dur', title: 'Duration', render: (c) => fmtDur(c.durationSec) },
              { key: 'site', title: 'Cell site', render: (c) => <span className="small muted">{c.cellSiteName ?? '—'}</span> },
            ]}
          />
        </Panel>
      )}
    </div>
  );
}