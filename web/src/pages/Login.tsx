import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../store/AuthContext';

export default function LoginPage() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState('a.rahman@intel.demo');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try { await login(email, password); nav('/'); }
    catch (ex) { setErr(ex instanceof Error ? ex.message : 'Sign-in failed'); }
    finally { setBusy(false); }
  };

  return (
    <div className="login-screen">
      <div className="login-brand">
        <div>
          <span className="classification">RESTRICTED — LAW ENFORCEMENT USE ONLY</span>
          <h1 className="mt">Criminal Intelligence &amp; Relationship Investigation System</h1>
          <p className="muted mt">Entity resolution, link analysis and pattern detection across
            communications, financial, vehicle and location data. Authorized personnel only.
            All activity is logged and auditable.</p>
        </div>
        <div className="small muted">
          CIRIS v0.1 · National Joint Intelligence Program · Fictional demonstration environment
        </div>
      </div>
      <div className="login-form-col">
        <div className="login-box">
          <h2>Secure sign-in</h2>
          <p className="muted small mt">Authenticate with your issued investigative account.</p>
          <form onSubmit={submit}>
            <label className="field"><span>Email</span>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </label>
            <label className="field"><span>Password</span>
              <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </label>
            {err && <div className="badge danger">{err}</div>}
            <button className="btn primary" disabled={busy}>{busy ? 'Authenticating…' : 'Sign in'}</button>
          </form>
          <div className="login-note">
            <strong>Demo access</strong> — password <span className="mono">demo1234</span> for
            a.rahman@ / d.mensah@ / s.okafor@intel.demo
          </div>
        </div>
      </div>
    </div>
  );
}