import type { ApiAdapter, LoginCredentials } from '../api/endpoints';
import { ApiError } from '../../types/api';
import * as d from './mockData';
import type { Page } from '../../types/api-shim';
import type {
  AlertQuery, CaseQuery, CDRQuery, EntityQuery, EventQuery, LocationQuery,
  RelationshipQuery, TransactionQuery,
} from '../../types/api';

const delay = (ms = 150) => new Promise<void>((r) => setTimeout(r, ms));

function page<T>(arr: T[], p = 1, ps = 25): Page<T> {
  const start = (p - 1) * ps;
  return { data: arr.slice(start, start + ps), total: arr.length, page: p, pageSize: ps };
}

const inRange = (v: string, from?: string, to?: string) =>
  (!from || v >= from) && (!to || v <= to + 'T23:59:59');

const entMatch = (e: { label: string; aliases: string[]; id: string }, q?: string) => {
  if (!q) return true;
  const s = q.toLowerCase();
  return e.label.toLowerCase().includes(s) || e.id.toLowerCase().includes(s) || e.aliases.some((a) => a.toLowerCase().includes(s));
};

export const mockAdapter: ApiAdapter = {
  async login({ email, password }: LoginCredentials) {
    await delay();
    const inv = d.investigators.find((i) => i.email === email);
    if (!inv || password !== 'demo1234') throw new ApiError(401, 'Invalid credentials.');
    return { token: `mock.${inv.id}.${Date.now()}`, profile: inv };
  },

  async profile() {
    await delay();
    return d.investigators[0];
  },

  async dashboard() {
    await delay();
    return {
      activeCases: d.cases.filter((c) => c.status === 'ACTIVE').length,
      entitiesAnalyzed: d.entities.length,
      highRiskConnections: d.relationships.filter((r) => r.strength >= 8).length,
      suspiciousPatterns: d.alerts.filter((a) => a.status === 'NEW' || a.status === 'INVESTIGATING').length,
      recentEvents: [...d.events].sort((a, b) => b.occurredAt.localeCompare(a.occurredAt)).slice(0, 6),
      recentCases: [...d.cases].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 5),
      openAlerts: d.alerts.filter((a) => a.status === 'NEW').slice(0, 6),
    };
  },

  async listCases(q: CaseQuery = {}) {
    await delay();
    let rows = [...d.cases];
    if (q.status) rows = rows.filter((c) => c.status === q.status);
    if (q.priority) rows = rows.filter((c) => c.priority === q.priority);
    if (q.q) rows = rows.filter((c) => (c.title + c.code + c.summary).toLowerCase().includes(q.q!.toLowerCase()));
    rows.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return page(rows, q.page, q.pageSize);
  },

  async getCase(id: string) {
    await delay();
    const c = d.cases.find((x) => x.id === id);
    if (!c) throw new ApiError(404, 'Case not found.');
    return c;
  },

  async listEntities(q: EntityQuery = {}) {
    await delay();
    let rows = [...d.entities];
    if (q.type) rows = rows.filter((e) => e.type === q.type);
    if (q.status) rows = rows.filter((e) => e.status === q.status);
    if (q.riskMin !== undefined) rows = rows.filter((e) => e.riskScore >= q.riskMin!);
    if (q.q) rows = rows.filter((e) => entMatch(e, q.q));
    if (q.sort === 'label') rows.sort((a, b) => a.label.localeCompare(b.label));
    else if (q.sort === 'updatedAt') rows.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    else rows.sort((a, b) => b.riskScore - a.riskScore);
    return page(rows, q.page, q.pageSize);
  },

  async getEntity(id: string) {
    await delay();
    const e = d.entityById.get(id);
    if (!e) throw new ApiError(404, 'Entity not found.');
    return e;
  },

  async search(q: string) {
    await delay();
    const s = q.toLowerCase();
    return {
      entities: d.entities.filter((e) => entMatch(e, q)).slice(0, 20),
      cases: d.cases.filter((c) => (c.title + c.code + c.tags.join(' ')).toLowerCase().includes(s)).slice(0, 10),
      events: d.events.filter((e) => (e.title + e.description).toLowerCase().includes(s)).slice(0, 10),
    };
  },

  async getNetwork(id: string, opts: { depth?: 1 | 2; types?: string[] } = {}) {
    await delay();
    const depth = opts.depth ?? 1;
    const seen = new Set<string>([id]);
    let frontier = [id];
    for (let dpt = 0; dpt < depth; dpt++) {
      const next: string[] = [];
      for (const fid of frontier) {
        for (const r of d.relationships) {
          const other = r.sourceId === fid ? r.targetId : r.targetId === fid ? r.sourceId : null;
          if (other && !seen.has(other)) { seen.add(other); next.push(other); }
        }
      }
      frontier = next;
    }
    const nodes = [...seen].map((eid) => d.entityById.get(eid)).filter((e): e is NonNullable<typeof e> => Boolean(e));
    const edges = d.relationships.filter((r) => seen.has(r.sourceId) && seen.has(r.targetId))
      .filter((r) => !opts.types?.length || opts.types.includes(r.type));
    return { centerId: id, nodes, edges };
  },

  async listRelationships(q: RelationshipQuery = {}) {
    await delay();
    let rows = [...d.relationships];
    if (q.entityId) rows = rows.filter((r) => r.sourceId === q.entityId || r.targetId === q.entityId);
    if (q.type) rows = rows.filter((r) => r.type === q.type);
    if (q.source) rows = rows.filter((r) => r.source.toLowerCase().includes(q.source!.toLowerCase()));
    rows = rows.filter((r) => inRange(r.lastSeen, q.from, q.to));
    rows.sort((a, b) => b.strength - a.strength);
    return page(rows, q.page, q.pageSize);
  },

  async listEvents(q: EventQuery = {}) {
    await delay();
    let rows = [...d.events];
    if (q.caseId) rows = rows.filter((e) => e.caseId === q.caseId);
    if (q.entityId) rows = rows.filter((e) => e.entityIds.includes(q.entityId!));
    if (q.type) rows = rows.filter((e) => e.type === q.type);
    if (q.severity) rows = rows.filter((e) => e.severity === q.severity);
    rows = rows.filter((e) => inRange(e.occurredAt, q.from, q.to));
    rows.sort((a, b) => b.occurredAt.localeCompare(a.occurredAt));
    return page(rows, q.page, q.pageSize ?? 50);
  },

  async listLocations(q: LocationQuery = {}) {
    await delay();
    let rows = [...d.locations];
    if (q.type) rows = rows.filter((l) => l.type === q.type);
    if (q.q) rows = rows.filter((l) => (l.name + l.address).toLowerCase().includes(q.q!.toLowerCase()));
    return page(rows, q.page, q.pageSize);
  },

  async listTransactions(q: TransactionQuery = {}) {
    await delay();
    let rows = [...d.transactions];
    if (q.accountId) rows = rows.filter((t) => t.accountId === q.accountId);
    if (q.direction) rows = rows.filter((t) => t.direction === q.direction);
    if (q.channel) rows = rows.filter((t) => t.channel === q.channel);
    if (q.minAmount !== undefined) rows = rows.filter((t) => t.amount >= q.minAmount!);
    rows = rows.filter((t) => inRange(t.occurredAt, q.from, q.to));
    rows.sort((a, b) => b.occurredAt.localeCompare(a.occurredAt));
    return page(rows, q.page, q.pageSize ?? 50);
  },

  async listCDR(q: CDRQuery = {}) {
    await delay();
    let rows = [...d.cdrRecords];
    if (q.number) rows = rows.filter((c) => c.callerNumber.includes(q.number!) || c.calleeNumber.includes(q.number!));
    if (q.kind) rows = rows.filter((c) => c.kind === q.kind);
    rows = rows.filter((c) => inRange(c.startedAt, q.from, q.to));
    rows.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
    return page(rows, q.page, q.pageSize ?? 50);
  },

  async listAlerts(q: AlertQuery = {}) {
    await delay();
    let rows = [...d.alerts];
    if (q.severity) rows = rows.filter((a) => a.severity === q.severity);
    if (q.status) rows = rows.filter((a) => a.status === q.status);
    rows.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return page(rows, q.page, q.pageSize);
  },

  async acknowledgeAlert(id: string) {
    await delay();
    const a = d.alerts.find((x) => x.id === id);
    if (!a) throw new ApiError(404, 'Alert not found.');
    a.status = a.status === 'NEW' ? 'ACKNOWLEDGED' : a.status;
    return a;
  },

  async generateReport(caseId: string) {
    await delay(400);
    const c = d.cases.find((x) => x.id === caseId);
    if (!c) throw new ApiError(404, 'Case not found.');
    const ents = c.entityIds.map((e) => d.entityById.get(e)).filter((e): e is NonNullable<typeof e> => Boolean(e));
    const evs = d.events.filter((e) => e.caseId === caseId).sort((a, b) => a.occurredAt.localeCompare(b.occurredAt));
    const accts = ents.filter((e) => e.type === 'ACCOUNT').map((e) => e.id);
    const txs = d.transactions.filter((t) => accts.includes(t.accountId));
    const als = d.alerts.filter((a) => a.caseId === caseId);
    const flagged = txs.filter((t) => t.riskFlags.length > 0);
    return {
      caseId,
      title: `${c.code} — Intelligence Summary`,
      generatedAt: new Date().toISOString(),
      sections: [
        {
          heading: '1. Case Overview',
          body: c.summary,
          bullets: [
            `Status: ${c.status} — Priority: ${c.priority}`,
            `Opened ${c.openedAt}; last activity ${c.updatedAt}.`,
            `${ents.length} linked entities; ${evs.length} events on timeline.`,
          ],
        },
        {
          heading: '2. Principal Subjects',
          body: 'Highest-risk linked entities by composite risk score.',
          table: {
            columns: ['Entity', 'Type', 'Risk', 'Status'],
            rows: [...ents].sort((a, b) => b.riskScore - a.riskScore).slice(0, 10)
              .map((e) => [e.label, e.type, String(e.riskScore), e.status]),
          },
        },
        {
          heading: '3. Key Findings',
          bullets: [
            `${als.filter((a) => a.severity === 'CRITICAL').length} critical, ${als.filter((a) => a.severity === 'HIGH').length} high-severity alerts associated with this case.`,
            `${flagged.length} flagged transactions totalling ${flagged.reduce((s, t) => s + t.amount, 0).toLocaleString()} across ${new Set(flagged.flatMap((t) => t.riskFlags)).size} distinct risk patterns.`,
            evs.length ? `Most recent event: "${evs[evs.length - 1].title}" (${evs[evs.length - 1].occurredAt.slice(0, 10)}).` : 'No events recorded.',
          ],
        },
        {
          heading: '4. Financial Exposure',
          body: 'Aggregate movement across linked accounts in the reporting window.',
          table: {
            columns: ['Account', 'Movements', 'Flagged'],
            rows: accts.map((id) => {
              const rows = txs.filter((t) => t.accountId === id);
              return [id, String(rows.length), String(rows.filter((t) => t.riskFlags.length).length)];
            }),
          },
        },
        {
          heading: '5. Recommended Actions',
          bullets: [
            'Prioritise interception of high-centrality communication nodes (see alert NET-CENT-003).',
            'Escalate structured-deposit pattern to FIU for suspicious activity referral.',
            'Maintain surveillance on controlled-delivery target; avoid premature engagement.',
          ],
        },
      ],
    };
  },

  async listDataSources() {
    await delay();
    return d.dataSources;
  },

  async importData(sourceId: string, payload: { records: number }) {
    await delay(300);
    const s = d.dataSources.find((x) => x.id === sourceId);
    if (s) { s.recordsIngested += payload.records; s.lastSync = new Date().toISOString(); }
    return { ok: true };
  },
};