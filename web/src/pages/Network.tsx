import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAsync } from '../hooks/useAsync';
import { api } from '../services/apiService';
import { Panel, Field } from '../components/ui';
import { NetworkGraph, NodeDetail, REL_TYPES } from '../components/NetworkGraph';
import type { RelationshipType } from '../types/models';

export default function NetworkPage() {
  const nav = useNavigate();
  const [sp] = useSearchParams();
  const [center, setCenter] = useState(sp.get('center') ?? 'P-1001');
  const [depth, setDepth] = useState<1 | 2>(1);
  const [relType, setRelType] = useState<RelationshipType | ''>('');

  const net = useAsync(() => api.getNetwork(center, { depth, types: relType ? [relType] : undefined }), [center, depth, relType]);
  const entityMap = new Map((net.data?.nodes ?? []).map((n) => [n.id, n]));
  const centerEnt = entityMap.get(center);

  return (
    <div className="section-gap">
      <div className="page-header">
        <h1>Network Explorer</h1>
      </div>
      <form className="filter-bar" onSubmit={(e) => e.preventDefault()}>
        <Field label="Center entity"><input className="input mono" style={{ width: 220 }} value={center} onChange={(e) => setCenter(e.target.value.toUpperCase())} /></Field>
        <Field label="Depth">
          <select className="input" value={depth} onChange={(e) => setDepth(Number(e.target.value) as 1 | 2)}>
            <option value={1}>1 hop</option><option value={2}>2 hops</option>
          </select>
        </Field>
        <Field label="Relationship type">
          <select className="input" value={relType} onChange={(e) => setRelType(e.target.value as RelationshipType | '')}>
            <option value="">All</option>
            {REL_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </Field>
      </form>

      <div className="grid main">
        <Panel title={centerEnt ? `Network — ${centerEnt.label}` : 'Network'} hint="click node to inspect · use detail panel to re-center" flush>
          {net.loading && <div className="state-box">Computing layout…</div>}
          {net.data && (
            <NetworkGraph view={net.data} entityMap={entityMap} height={600} selectedId={center}
              onSelect={(nid) => nav(`/entity/${nid}`)} />
          )}
        </Panel>
        <Panel title="Node detail">
          {centerEnt ? (
            <NodeDetail entity={centerEnt} edges={net.data?.edges ?? []} entityMap={entityMap}
              onOpen={setCenter} />
          ) : <div className="state-box">Unknown center entity.</div>}
        </Panel>
      </div>
    </div>
  );
}