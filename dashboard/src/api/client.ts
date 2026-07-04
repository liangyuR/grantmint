/**
 * Small typed fetch wrapper for the Grantmint admin API.
 *
 * - Every request sends `credentials: 'include'` so the HttpOnly admin session cookie rides along.
 * - Every state-changing request (POST/PUT/PATCH/DELETE) echoes the `XSRF-TOKEN` cookie back as the
 *   `X-XSRF-TOKEN` header (double-submit CSRF; see GrantmintSecurityConfig's admin chain).
 * - A 401 from anywhere calls the registered "unauthorized" handler (wired to a redirect-to-login
 *   in AuthContext) before the error propagates.
 * - Errors are normalized to `ApiError`, unwrapping the server's `{error, message}` envelope.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(status: number, code: string | undefined, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

type UnauthorizedHandler = () => void;

let unauthorizedHandler: UnauthorizedHandler | null = null;

/** Registered once by AuthContext so any client call can trigger a redirect-to-login. */
export function setUnauthorizedHandler(fn: UnauthorizedHandler | null): void {
  unauthorizedHandler = fn;
}

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function readCookie(name: string): string | null {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return null;
}

interface ErrorEnvelope {
  error?: string;
  message?: string;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);

  if (init.body !== undefined && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }
  headers.set('Accept', 'application/json');

  if (WRITE_METHODS.has(method)) {
    const xsrf = readCookie('XSRF-TOKEN');
    if (xsrf) {
      headers.set('X-XSRF-TOKEN', xsrf);
    }
  }

  const response = await fetch(path, { ...init, method, headers, credentials: 'include' });

  if (response.status === 401) {
    unauthorizedHandler?.();
    throw new ApiError(401, 'unauthorized', 'Your session has expired. Please log in again.');
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  const data = text.length > 0 ? (JSON.parse(text) as unknown) : undefined;

  if (!response.ok) {
    const envelope = (data as ErrorEnvelope | undefined) ?? {};
    throw new ApiError(
      response.status,
      envelope.error,
      envelope.message ?? `Request failed with status ${response.status}`,
    );
  }

  return data as T;
}

function toBody(body: unknown): string | undefined {
  return body === undefined ? undefined : JSON.stringify(body);
}

export const api = {
  get: <T>(path: string): Promise<T> => request<T>(path),
  post: <T>(path: string, body?: unknown): Promise<T> =>
    request<T>(path, { method: 'POST', body: toBody(body) }),
  put: <T>(path: string, body?: unknown): Promise<T> =>
    request<T>(path, { method: 'PUT', body: toBody(body) }),
  delete: <T>(path: string, body?: unknown): Promise<T> =>
    request<T>(path, { method: 'DELETE', body: toBody(body) }),
};
