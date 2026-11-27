import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';
import { api } from '../services/apiService';
import type { AuthSession } from '../types/models';

interface AuthState {
  session: AuthSession | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const Ctx = createContext<AuthState>(null as unknown as AuthState);
const KEY = 'ciris.session';

function load(): AuthSession | null {
  try { return JSON.parse(localStorage.getItem(KEY) ?? 'null'); } catch { return null; }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(load);

  const login = useCallback(async (email: string, password: string) => {
    const s = await api.login({ email, password });
    localStorage.setItem(KEY, JSON.stringify(s));
    localStorage.setItem('ciris.token', s.token);
    setSession(s);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(KEY);
    localStorage.removeItem('ciris.token');
    setSession(null);
  }, []);

  return <Ctx.Provider value={{ session, login, logout }}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);