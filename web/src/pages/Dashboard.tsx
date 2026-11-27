import { useNavigate } from 'react-router-dom';
import { useAsync } from '../hooks/useAsync';
import { api } from '../services/apiService';
import { Panel, Stat, SevBadge, StatusBadge, fmtDateTime, fmtDate } from '../components/ui';
import { NetworkGraph } from '../components/NetworkGraph';

export default function DashboardPage() {
  const nav = useNavigate();
  const dash = useAsync(() => api.dashboard(), []);
  const net = useAsync(() => api.getNetwork('P-1001', { depth: 1 }), []);
  const entityMap = new Map((net.data?.nodes ?? []).map((n) => [n.id, n]));

  return (
    <div className="section-gap">
      <div className="page-header">
        <h1>Investigation Dashboard</h1>
        <span className="muted small">All figures reflect the active analytic workspace</span>
      </div>

      {dash.loading && <div className="grid stats">{[...Array(4)].map((_, i) => <div key={i} className="stat"><div className="label">Loading</div><div className="value">—</div></div>)}</div>}
      {dash.data && (
        <div className="grid stats">
          <Stat label="Active cases" value={dash.data.activeCases} foot="across all units" tone="accent" />
          <Stat label="Entities analyzed" value={dash.data.entitiesAnalyzed} foot="persons, devices, accounts, orgs" />
          <Stat label="High-risk connections" value={dash.data.highRiskConnections} foot="link strength ≥ 8" tone="warning" />
          <Stat label="Suspicious patterns" value={dash.data.suspiciousPatterns} foot="open / under investigation" tone="danger" />
        </div>
      )}

      <div className="grid main">
        <Panel title="Case network — OP NIGHTHARBOR (center: Viktor Sarek)" hint="scroll to zoom · drag to pan · click a node"
          flush>
          {net.loading && <div className="state-box">Rendering network…</div>}
          {net.data && (
            <NetworkGraph view={net.data} entityMap={entityMap} height={520}
              onSelect={(id) => nav(`/entity/${id}`)} selectedId="P-1001" />
          )}
        </Panel>

        <div className="section-gap">
          <Panel title="Open alerts" flush>
            {dash.data?.openAlerts.length ? (
              <div className="table-wrap"><table className="tbl"><tbody>
                {dash.data.openAlerts.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => nav('/alerts')}>
                    <td><SevBadge sev={a.severity} /><div className="small mt">{a.title}</div>
                      <div className="muted small mono">{a.rule} · {fmtDateTime(a.createdAt)}</div></td>
                  </tr>
                ))}
              </tbody></table></div>
            ) : <div className="state-box">No unacknowledged alerts.</div>}
          </Panel>

          <Panel title="Recent intelligence" flush>
            <div className="table-wrap"><table className="tbl"><tbody>
              {dash.data?.recentEvents.map((e) => (
                <tr key={e.id} className="clickable" onClick={() => nav('/timeline')}>
                  <td><SevBadge sev={e.severity} /><div className="small mt">{e.title}</div>
                    <div className="muted small">{fmtDateTime(e.occurredAt)} · {e.source}</div></td>
                </tr>
              ))}
            </tbody></table></div>
          </Panel>
        </div>
      </div>

      <Panel title="Recent investigations" flush>
        <div className="table-wrap"><table className="tbl">
          <thead><tr><th>Code</th><th>Title</th><th>Status</th><th>Priority</th><th>Updated</th></tr></thead>
          <tbody>
            {dash.data?.recentCases.map((c) => (
              <tr key={c.id} className="clickable" onClick={() => nav(`/cases/${c.id}`)}>
                <td className="mono nowrap">{c.code}</td>
                <td>{c.title}<div className="muted small">{c.tags.join(' · ')}</div></td>
                <td><StatusBadge s={c.status} /></td>
                <td><StatusBadge s={c.priority} /></td>
                <td className="nowrap">{fmtDate(c.updatedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </Panel>
    </div>
  );
}