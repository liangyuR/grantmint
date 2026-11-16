import { useState } from 'react';
import type { FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { ApiError } from '../api/client';
import Alert from '../components/Alert';
import FormField, { buttonClasses, inputClasses } from '../components/FormField';

export default function LoginPage() {
  const { status, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (status === 'checking') return <p className="p-6 text-gray-400">正在检查登录状态…</p>;

  if (status === 'authenticated') {
    const redirectTo = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname ?? '/products';
    return <Navigate to={redirectTo} replace />;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
      navigate('/products', { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '登录失败，请重试。');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 px-4 text-gray-100">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-bold text-white">Grantmint</h1>
          <p className="text-sm text-gray-400">登录管理控制台</p>
        </div>
        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-6">
          <FormField id="username" label="用户名">
            <input
              id="username"
              name="username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={inputClasses}
            />
          </FormField>
          <FormField id="password" label="密码">
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={inputClasses}
            />
          </FormField>
          {error && <Alert kind="error">{error}</Alert>}
          <button type="submit" disabled={submitting} className={`${buttonClasses} w-full`}>
            {submitting ? '登录中…' : '登录'}
          </button>
        </form>
      </div>
    </div>
  );
}
