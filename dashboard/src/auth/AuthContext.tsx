import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { ApiError, api, setUnauthorizedHandler } from '../api/client';
import type { AdminSummary, LoginResponse } from '../api/types';

type AuthStatus = 'checking' | 'authenticated' | 'anonymous';

interface AuthContextValue {
  status: AuthStatus;
  admin: AdminSummary | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('checking');
  const [admin, setAdmin] = useState<AdminSummary | null>(null);

  const markAnonymous = useCallback(() => {
    setAdmin(null);
    setStatus('anonymous');
  }, []);

  // Wire the API client's global 401 handler to drop us back to the login screen from anywhere.
  useEffect(() => {
    setUnauthorizedHandler(markAnonymous);
    return () => setUnauthorizedHandler(null);
  }, [markAnonymous]);

  // There is no /admin/auth/me endpoint yet, so on load we probe with a cheap, harmless GET the
  // dashboard needs anyway. A 401 (via the global handler) flips us to anonymous; success means
  // the session cookie from a previous visit is still good.
  useEffect(() => {
    let cancelled = false;
    api
      .get('/admin/products')
      .then(() => {
        if (!cancelled) setStatus('authenticated');
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) {
          markAnonymous();
        } else {
          // Non-auth failure (e.g. network) — don't strand the user on a spinner; let them try to log in.
          markAnonymous();
        }
      });
    return () => {
      cancelled = true;
    };
  }, [markAnonymous]);

  const login = useCallback(async (username: string, password: string) => {
    const result = await api.post<LoginResponse>('/admin/auth/login', { username, password });
    setAdmin(result.admin);
    setStatus('authenticated');
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post('/admin/auth/logout');
    } finally {
      markAnonymous();
    }
  }, [markAnonymous]);

  const value = useMemo(() => ({ status, admin, login, logout }), [status, admin, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
