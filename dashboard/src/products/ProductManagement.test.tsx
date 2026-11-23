// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { Link, MemoryRouter } from 'react-router-dom';
import App from '../App';
import { api, setCsrfToken } from '../api/client';
import type { LicenseDetail, Product } from '../api/types';
const products: Product[] = ['alpha', 'beta'].map((id) => ({ id, slug: id, name: `应用${id}`, description: '', signingKeyId: `key-${id}`, archivedAt: null, createdAt: '' }));
const detail: LicenseDetail = { id: 'license-alpha', keyId: 'KEY-ALPHA', applicationId: 'alpha', applicationName: '应用alpha', customer: { name: '甲客户', email: 'a@example.invalid' }, expiresAt: '2099-11-30T16:00:00Z', status: 'active', revision: 2, bindingVersion: 1, signedToken: 'certificate', devicePublicKey: 'public-key', fingerprintHash: 'hash', fingerprintVersion: 1, entitlements: {}, renewals: [], deliveryStatus: 'pending', createdAt: '', revokedAt: null };
function mockReads(getDetail = () => detail, includeList = false) {
  vi.spyOn(api, 'get').mockImplementation(async <T,>(path: string): Promise<T> => {
    if (path === '/admin/auth/me') return { username: 'admin', csrfToken: 'csrf' } as T;
    if (path === '/admin/v2/applications') return products as T;
    if (path === '/admin/v2/licenses/license-alpha') return getDetail() as T;
    if (path.startsWith('/admin/v2/licenses?')) return { content: includeList ? [getDetail()] : [], totalElements: includeList ? 1 : 0, totalPages: includeList ? 1 : 0, number: 0, size: 50 } as T;
    throw new Error(`Unexpected read: ${path}`);
  });
}
function open() {
  render(<MemoryRouter initialEntries={['/licenses']}><Link to="/licenses/license-alpha">打开已有授权</Link><App /></MemoryRouter>);
  return userEvent.setup();
}
async function ready() { await waitFor(() => expect((screen.getByLabelText('当前应用') as HTMLSelectElement).disabled).toBe(false)); }
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); setCsrfToken(null); });
it('切换应用 → 清除未提交表单且其他应用详情不暴露', async () => {
  mockReads(); const user = open(); await ready();
  await user.click(screen.getByRole('button', { name: '创建授权' }));
  await user.type(screen.getByLabelText('客户名称'), '未提交甲客户');
  await user.selectOptions(screen.getByLabelText('当前应用'), 'beta');
  expect(screen.queryByDisplayValue('未提交甲客户')).toBeNull();
  await user.click(screen.getByRole('link', { name: '打开已有授权' }));
  await screen.findByText(/不属于当前应用/);
  expect(screen.queryByText('甲客户')).toBeNull();
  expect(screen.queryByRole('button', { name: '续期' })).toBeNull();
});
it('创建授权 → 直接提交当前应用合同与权益，秘密仅本次展示', async () => {
  mockReads(); const post = vi.spyOn(api, 'post').mockResolvedValue({ ...detail, licenseId: detail.id, activationSecret: 'one-time-secret' });
  const user = open(); await ready(); await user.selectOptions(screen.getByLabelText('当前应用'), 'beta');
  await user.click(screen.getByRole('button', { name: '创建授权' }));
  await user.type(screen.getByLabelText('客户名称'), '乙客户'); await user.type(screen.getByLabelText('客户邮箱'), 'b@example.invalid');
  fireEvent.submit(screen.getByLabelText('客户名称').closest('form')!); expect(post).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('停用日期（北京时间）'), { target: { value: '2099-12-01' } });
  fireEvent.change(screen.getByLabelText('权益（JSON）'), { target: { value: '{"inspect":true,"limit":4}' } });
  await user.click(screen.getByRole('button', { name: '确认创建' })); await screen.findByDisplayValue('one-time-secret');
  expect(post).toHaveBeenCalledWith('/admin/v2/licenses', { applicationId: 'beta', customer: { name: '乙客户', email: 'b@example.invalid' }, expiresAt: '2099-11-30T16:00:00.000Z', entitlements: { inspect: true, limit: 4 } });
  expect(JSON.stringify(localStorage)).not.toContain('one-time-secret');
  await user.click(screen.getByRole('button', { name: '关闭创建' })); await user.click(screen.getByRole('button', { name: '创建授权' })); expect(screen.queryByDisplayValue('one-time-secret')).toBeNull();
});
it('续期响应丢失 → 同内容重试复用幂等键和修订，不提前确认设备', async () => {
  let current = detail; mockReads(() => current);
  const post = vi.spyOn(api, 'post').mockRejectedValueOnce(new Error('network')).mockImplementationOnce(async () => { current = { ...detail, revision: 3, expiresAt: '2100-11-30T16:00:00Z' }; return current; });
  const user = open(); await ready(); await user.click(screen.getByRole('link', { name: '打开已有授权' }));
  await user.click(await screen.findByRole('button', { name: '续期' }));
  fireEvent.change(screen.getByLabelText('新的停用日期（北京时间）'), { target: { value: '2099-11-01' } });
  await user.type(screen.getByLabelText('续期原因'), '合同续约');
  await user.click(screen.getByRole('button', { name: '确认续期' })); expect(post).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('新的停用日期（北京时间）'), { target: { value: '2100-12-01' } });
  await user.click(screen.getByRole('button', { name: '确认续期' })); await screen.findByText(/同一内容重试/);
  await user.click(screen.getByRole('button', { name: '确认续期' }));
  await waitFor(() => expect(screen.queryByRole('form', { name: '续期授权' })).toBeNull());
  expect(post.mock.calls[0]).toEqual(post.mock.calls[1]);
  expect(post.mock.calls[0]![1]).toEqual({ expectedRevision: 2, newExpiresAt: '2100-11-30T16:00:00.000Z', reason: '合同续约', idempotencyKey: expect.any(String) });
  expect(await screen.findByText('待领取 / 尚未确认')).toBeTruthy(); expect(screen.queryByText('设备已确认')).toBeNull();
});
it('会话恢复 → 写请求使用me的CSRF且退出使页面失去授权', async () => {
  const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
    if (path === '/admin/auth/me') return new Response(JSON.stringify({ username: '管理员', csrfToken: 'actual-csrf' }));
    if (path === '/admin/v2/applications') return new Response(JSON.stringify(products));
    if (path.startsWith('/admin/v2/licenses?')) return new Response(JSON.stringify({ content: [], totalElements: 0, totalPages: 0, number: 0, size: 50 }));
    if (path === '/admin/auth/logout') return new Response(null, { status: 204 });
    throw new Error(path);
  });
  vi.stubGlobal('fetch', fetchMock); const user = open(); await ready();
  await user.click(screen.getByRole('button', { name: '退出登录' })); await screen.findByRole('button', { name: '登录' });
  const logout = fetchMock.mock.calls.find(([path]) => path === '/admin/auth/logout')?.[1];
  expect(new Headers(logout?.headers).get('X-XSRF-TOKEN')).toBe('actual-csrf');
  expect(logout?.credentials).toBe('include');
  expect(screen.queryByLabelText('当前应用')).toBeNull();
});

it('会话检查未完成 → 登录表单不可提交，避免迟到401覆盖新会话', async () => {
  let finish!: (response: Response) => void;
  vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((resolve) => { finish = resolve; })));
  render(<MemoryRouter initialEntries={['/login']}><App /></MemoryRouter>);
  expect(screen.queryByLabelText('密码')).toBeNull();
  finish(new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 }));
  expect(await screen.findByLabelText('密码')).toBeTruthy();
});

it.each(['续期', '撤销'] as const)('详情%s成功 → 关闭详情后列表同步修订和交付状态', async (operation) => {
  let current: LicenseDetail = { ...detail, deliveryStatus: 'confirmed' };
  mockReads(() => current, true);
  vi.spyOn(api, 'post').mockImplementation(async () => {
    current = operation === '续期'
      ? { ...current, revision: 3, expiresAt: '2100-11-30T16:00:00Z', deliveryStatus: 'pending' }
      : { ...current, status: 'revoked', revokedAt: '2026-01-01T00:00:00Z' };
    return current;
  });
  const user = open(); await ready();
  const table = within(screen.getByRole('table'));
  expect(await table.findByText('设备已确认')).toBeTruthy();
  await user.click(table.getByRole('link', { name: 'KEY-ALPHA' }));
  await user.click(await screen.findByRole('button', { name: operation === '续期' ? '续期' : '撤销授权' }));
  if (operation === '续期') {
    fireEvent.change(screen.getByLabelText('新的停用日期（北京时间）'), { target: { value: '2100-12-01' } });
    await user.type(screen.getByLabelText('续期原因'), '合同续约');
    await user.click(screen.getByRole('button', { name: '确认续期' }));
    await waitFor(() => expect(screen.queryByRole('form', { name: '续期授权' })).toBeNull());
  } else {
    await user.type(screen.getByLabelText('撤销原因'), '合同终止');
    await user.click(screen.getByRole('button', { name: '确认撤销' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: '确认撤销' })).toBeNull());
  }
  await user.click(screen.getByRole('button', { name: '关闭详情' }));
  if (operation === '续期') {
    expect(await table.findByText('第 3 版')).toBeTruthy();
    expect(table.getByText('待领取 / 尚未确认')).toBeTruthy();
    expect(table.queryByText('设备已确认')).toBeNull();
  } else {
    expect(await table.findByText('已撤销')).toBeTruthy();
    expect(table.queryByText('有效')).toBeNull();
  }
});
