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

export function localizedError(status: number, code?: string): string {
  const messages: Record<string, string> = {
    product_has_licenses: '此应用已有授权，不能删除。',
    invalid_credentials: '用户名或密码错误。',
    bad_credentials: '用户名或密码错误。',
    invalid_argument: '请求参数无效，请检查填写内容。',
    not_found: '记录不存在，请刷新后重试。',
    forbidden: '没有执行此操作的权限。',
    access_denied: '没有执行此操作的权限。',
    license_revoked: '此授权已撤销。',
    license_expired: '此授权已到期。',
    license_suspended: '此授权已暂停。',
    device_already_bound: '此授权已绑定其他设备。',
    invalid_state_transition: '当前授权状态不允许此操作。',
    seat_limit_exceeded: '已达到设备数量上限。',
    offline_mode_required: '此授权需使用设备绑定激活流程。',
    offline_mode_unsupported: '离线设备授权不支持此操作。',
    signing_key_error: '签名密钥不可用，请联系部署管理员。',
  };
  if (code && messages[code]) return messages[code];
  if (status === 400) return '请求参数无效，请检查填写内容。';
  if (status === 403) return '操作被拒绝，请刷新页面并确认登录权限。';
  if (status === 404) return '记录不存在，请刷新后重试。';
  if (status === 409) return '记录状态发生冲突，请刷新后重试。';
  if (status === 429) return '请求过于频繁，请稍后再试。';
  return `请求失败（HTTP ${status}${code ? `，${code}` : ''}），请稍后重试或联系管理员。`;
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

  let response: Response;
  try {
    response = await fetch(path, { ...init, method, headers, credentials: 'include' });
  } catch {
    throw new ApiError(0, 'network_error', '无法连接服务器，请检查网络后重试。');
  }

  if (response.status === 401) {
    unauthorizedHandler?.();
    throw new ApiError(401, 'unauthorized', path === '/admin/auth/login' ? '用户名或密码错误。' : '登录已过期，请重新登录。');
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  let data: unknown;
  try {
    data = text.length > 0 ? JSON.parse(text) : undefined;
  } catch {
    throw new ApiError(response.status, 'invalid_response', '服务器响应格式异常，请联系部署管理员。');
  }

  if (!response.ok) {
    const envelope = (data as ErrorEnvelope | undefined) ?? {};
    throw new ApiError(
      response.status,
      envelope.error,
      localizedError(response.status, envelope.error),
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
