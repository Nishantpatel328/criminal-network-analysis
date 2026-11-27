import { NavLink, Outlet, useNavigate, useLocation, Navigate } from 'react-router-dom';
import { useState } from 'react';
import { useAuth } from '../store/AuthContext';
import { isMockMode } from '../services/apiService';

const I = ({ d }: { d: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
);

const NAV: Array<{ group: string; items: Array<{ to: string; label: string; icon: string }> }> = [
  { group: 'Overview', items: [
    { to: '/', label: 'Dashboard', icon: 'M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z' },
    { to: '/alerts', label: 'Alerts', icon: 'M12 3 2 20h20L12 3Zm0 6v5m0 3v.5' },
  ]},
  { group: 'Investigation', items: [
    { to: '/search', label: 'Entity Search', icon: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm10 17-5-5' },
    { to: '/cases', label: 'Cases', icon: 'M4 7h16v14H4V7Zm4-4h8l2 4H6l2-4Z' },
    { to: '/network', label: 'Network Explorer', icon: 'M12 3v6m0 0-5 8m5-8 5 8M7 5l5 4 5-4M5 17l2-4m12 4-2-4' },
    { to: '/timeline', label: 'Timeline', icon: 'M3 12h4l3-8 4 16 3-8h4' },
  ]},
  { group: 'Intelligence', items: [
    { to: '/cdr', label: 'Communications (CDR)', icon: 'M5 4h4l2 5-3 2a12 12 0 0 0 5 5l2-3 5 2v4a2 2 0 0 1-2 2A17 17 0 0 1 3 6a2 2 0 0 1 2-2Z' },
    { to: '/financial', label: 'Financial Analysis', icon: 'M3 20h18M6 16v-5m4 5V8m4 8v-3m4 3V5' },
    { to: '/locations', label: 'Locations', icon: 'M12 21s-7-6-7-11a7 7 0 1 1 14 0c0 5-7 11-7 11Zm0-8.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z' },
    { to: '/reports', label: 'Reports', icon: 'M6 3h9l4 4v14H6V3Zm8 0v5h5M9 13h6m-6 4h6' },
  ]},
  { group: 'System', items: [
    { to: '/sources', label: 'Data Sources', icon: 'M12 3c4 0 8 1.5 8 4s-4 4-8 4-8-1.5-8-4 4-4 8-4Zm-8 4v10c0 2.5 4 4 8 4s8-1.5 8-4V7' },
    { to: '/settings', label: 'Profile & Settings', icon: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-8 8c0-4 4-6 8-6s8 2 8 6' },
  ]},
];

const TITLES: Record<string, string> = {
  '/': 'Investigation Dashboard', '/search': 'Entity Search', '/cases': 'Case Management',
  '/network': 'Network Explorer', '/timeline': 'Event Timeline', '/cdr': 'Communication Records (CDR)',
  '/financial': 'Financial Transaction Analysis', '/locations': 'Locations', '/alerts': 'Alerts & Suspicious Patterns',
  '/reports': 'Intelligence Reports', '/sources': 'Data Sources & Import', '/settings': 'Profile & Settings',
};

export function AppLayout() {
  const { session, logout } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const [q, setQ] = useState('');
  const base = '/' + loc.pathname.split('/')[1];
  const title = TITLES[loc.pathname] ?? TITLES[base] ?? 'CIRIS';

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="mark">CI</div>
          <div>
            <div className="title">CIRIS</div>
            <div className="sub">Criminal Intel</div>
          </div>
        </div>
        <nav className="sidebar-nav">
          {NAV.map((g) => (
            <div className="nav-group" key={g.group}>
              <div className="nav-group-label">{g.group}</div>
              {g.items.map((it) => (
                <NavLink key={it.to} to={it.to} end={it.to === '/'} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
                  <I d={it.icon} /> {it.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div><span className="dot">●</span> {session?.profile.name}</div>
          <div className="small">{session?.profile.unit}</div>
        </div>
      </aside>
      <div className="main-col">
        <header className="topbar">
          <span className="crumb">{title}</span>
          <span className={`env-chip${isMockMode ? ' mock' : ''}`}>{isMockMode ? 'Demo Data' : 'Live API'}</span>
          <div className="topbar-spacer" />
          <form className="topbar-search" onSubmit={(e) => { e.preventDefault(); nav(`/search?q=${encodeURIComponent(q)}`); }}>
            <I d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm10 17-5-5" />
            <input className="input" placeholder="Search person, phone, vehicle, organization…" value={q} onChange={(e) => setQ(e.target.value)} />
          </form>
          <button className="btn ghost sm" onClick={logout}>Sign out</button>
        </header>
        <main className="page"><Outlet /></main>
      </div>
    </div>
  );
}

export function RequireAuth({ children }: { children: JSX.Element }) {
  const { session } = useAuth();
  if (!session) return <Navigate to="/login" replace />;
  return children;
}