import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './store/AuthContext';
import { AppLayout, RequireAuth } from './components/layout';
import LoginPage from './pages/Login';
import DashboardPage from './pages/Dashboard';
import SearchPage from './pages/Search';
import EntityProfilePage from './pages/EntityProfile';
import NetworkPage from './pages/Network';
import { CasesPage, CaseDetailPage } from './pages/Cases';
import { TimelinePage, CDRPage, FinancialPage, LocationsPage } from './pages/Ops';
import { AlertsPage, ReportsPage, SourcesPage, SettingsPage } from './pages/System';

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<RequireAuth><AppLayout /></RequireAuth>}>
          <Route index element={<DashboardPage />} />
          <Route path="search" element={<SearchPage />} />
          <Route path="entity/:id" element={<EntityProfilePage />} />
          <Route path="network" element={<NetworkPage />} />
          <Route path="cases" element={<CasesPage />} />
          <Route path="cases/:id" element={<CaseDetailPage />} />
          <Route path="timeline" element={<TimelinePage />} />
          <Route path="cdr" element={<CDRPage />} />
          <Route path="financial" element={<FinancialPage />} />
          <Route path="locations" element={<LocationsPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="sources" element={<SourcesPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
