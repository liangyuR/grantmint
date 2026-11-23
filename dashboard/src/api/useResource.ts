import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from './client';

export function useResource<T>(path: string | null) {
  const [request, setRequest] = useState(0);
  const [result, setResult] = useState<{ path: string; request: number; data: T | null; error: string | null } | null>(null);
  const reload = useCallback(() => setRequest((value) => value + 1), []);

  useEffect(() => {
    if (!path) return;
    let cancelled = false;
    api.get<T>(path).then(
      (data) => { if (!cancelled) setResult({ path, request, data, error: null }); },
      (err: unknown) => {
        if (!cancelled) setResult({ path, request, data: null, error: err instanceof ApiError ? err.message : 'Failed to load data.' });
      },
    );
    return () => { cancelled = true; };
  }, [path, request]);

  const current = result?.path === path && result.request === request ? result : null;
  return { data: current?.data ?? null, error: current?.error ?? null, loading: !!path && !current, reload };
}
