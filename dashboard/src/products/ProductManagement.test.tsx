// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Link, MemoryRouter } from 'react-router-dom';
import App from '../App';
import { api } from '../api/client';
import type { LicenseDetail, Policy, Product } from '../api/types';

const products: Product[] = ['alpha', 'beta'].map((id) => ({
  id, slug: id, name: `Product ${id}`, description: null, createdAt: '', updatedAt: '',
}));
const policy = (productId: string): Policy => ({
  id: `${productId}-policy`, productId, code: `${productId}-annual`, name: `${productId} annual`,
  activationType: 'node_locked', maxSeats: 1, durationDays: 30, gracePeriodDays: 0,
  trial: false, heartbeatIntervalSeconds: 86400, constraints: {}, entitlements: {}, createdAt: '', updatedAt: '',
});

function mockReads(overrides: (path: string) => unknown = () => undefined) {
  vi.spyOn(api, 'get').mockImplementation(async <T,>(path: string): Promise<T> => {
    const override = overrides(path);
    if (override !== undefined) return await override as T;
    if (path === '/admin/products') return products as T;
    if (path.startsWith('/admin/licenses?')) return { items: [], page: 0, size: 20, total: 0 } as T;
    for (const product of products) {
      if (path === `/admin/products/${product.id}/policies`) return [policy(product.id)] as T;
    }
    throw new Error(`Unexpected read: ${path}`);
  });
}

function open(path: string) {
  render(<MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
    <Link to="/licenses/ALPHA-LICENSE">Open saved license link</Link>
    <App />
  </MemoryRouter>);
  return userEvent.setup();
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Product management boundaries', () => {
  it('switching products clears an unfinished policy form and ignores the previous product response', async () => {
    let finishAlpha!: (policies: Policy[]) => void;
    const alphaResponse = new Promise<Policy[]>((resolve) => { finishAlpha = resolve; });
    mockReads((path) => path === '/admin/products/alpha/policies' ? alphaResponse : undefined);
    const user = open('/policies');
    await waitFor(() => expect((screen.getByLabelText('当前应用') as HTMLSelectElement).disabled).toBe(false));
    await user.click(await screen.findByRole('button', { name: '新建策略' }));
    await user.type(screen.getByLabelText('名称'), 'Unfinished alpha policy');

    await user.selectOptions(screen.getByLabelText('当前应用'), 'beta');
    await screen.findByText('beta annual');
    await act(async () => { finishAlpha([policy('alpha')]); });

    expect(screen.queryByDisplayValue('Unfinished alpha policy')).toBeNull();
    expect(screen.queryByRole('button', { name: '创建策略' })).toBeNull();
    expect(screen.queryByText('alpha annual')).toBeNull();
    expect(screen.getByText('beta annual')).toBeTruthy();
  });

  it('a saved license link for another product does not expose its details or mutation controls', async () => {
    const otherLicense = {
      id: 'license-a', keyId: 'ALPHA-LICENSE', productId: 'alpha', holderName: 'Alpha customer',
      status: 'active', activations: [], entitlements: {}, constraints: {}, signedToken: 'secret-token',
    } as unknown as LicenseDetail;
    mockReads((path) => path === '/admin/licenses/ALPHA-LICENSE' ? otherLicense : undefined);
    const user = open('/licenses');
    await waitFor(() => expect((screen.getByLabelText('当前应用') as HTMLSelectElement).disabled).toBe(false));
    await user.selectOptions(screen.getByLabelText('当前应用'), 'beta');
    await user.click(screen.getByRole('link', { name: 'Open saved license link' }));

    await screen.findByText(/不属于当前应用/);
    expect(screen.queryByText('Alpha customer')).toBeNull();
    expect(screen.queryByDisplayValue('secret-token')).toBeNull();
    expect(screen.queryByRole('button', { name: /暂停|恢复|撤销/ })).toBeNull();
  });

  it('issuing uses the selected product policy and converts its stop date from Beijing midnight', async () => {
    mockReads();
    const post = vi.spyOn(api, 'post').mockResolvedValue({ keyId: 'BETA-LICENSE', token: 'signed', status: 'active', expiresAt: '2026-11-30T16:00:00Z' });
    const user = open('/licenses');
    await waitFor(() => expect((screen.getByLabelText('当前应用') as HTMLSelectElement).disabled).toBe(false));
    await user.selectOptions(screen.getByLabelText('当前应用'), 'beta');
    await user.click(screen.getByRole('button', { name: '创建授权' }));
    await screen.findByRole('option', { name: 'beta annual（1 台设备）' });
    await user.selectOptions(screen.getByLabelText('授权模式'), 'legacy');
    expect(screen.queryByRole('option', { name: 'alpha annual（1 台设备）' })).toBeNull();
    await user.type(screen.getByLabelText('客户名称'), 'Beta customer');
    const issueForm = within(screen.getByLabelText('客户名称').closest('form')!);
    await user.type(issueForm.getByLabelText('客户邮箱'), 'beta@example.invalid');
    fireEvent.change(screen.getByLabelText('停用日期（北京时间）'), { target: { value: '2026-12-01' } });
    await user.click(screen.getByRole('button', { name: '创建授权' }));

    await screen.findByDisplayValue('BETA-LICENSE');
    expect(post).toHaveBeenCalledWith('/admin/licenses', {
      productId: 'beta', policyId: 'beta-policy', holder: { name: 'Beta customer', email: 'beta@example.invalid' },
      expiresAt: '2026-11-30T16:00:00.000Z',
    });
  });
  it('默认离线授权要求未来停用日，创建后只展示本次激活秘密且关闭后清除', async () => {
    mockReads();
    const post = vi.spyOn(api, 'post').mockResolvedValue({
      licenseId: 'license-v2', keyId: 'OFFLINE-KEY', activationSecret: 'one-time-sensitive-secret',
      mode: 'offline_device_v2', status: 'created', expiresAt: '2099-11-30T16:00:00Z',
    });
    const user = open('/licenses');
    await waitFor(() => expect((screen.getByLabelText('当前应用') as HTMLSelectElement).disabled).toBe(false));
    await user.click(screen.getByRole('button', { name: '创建授权' }));
    await screen.findByRole('option', { name: 'alpha annual（1 台设备）' });
    await user.type(screen.getByLabelText('客户名称'), '离线客户');
    const form = screen.getByLabelText('客户名称').closest('form')!;
    await user.type(within(form).getByLabelText('客户邮箱'), 'offline@example.invalid');
    fireEvent.submit(form);
    expect(post).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('停用日期（北京时间）'), { target: { value: '2099-12-01' } });
    await user.click(screen.getByRole('button', { name: '创建授权' }));
    await screen.findByDisplayValue('one-time-sensitive-secret');
    expect(post).toHaveBeenCalledWith('/admin/v2/licenses', {
      productId: 'alpha', policyId: 'alpha-policy', holder: { name: '离线客户', email: 'offline@example.invalid' },
      expiresAt: '2099-11-30T16:00:00.000Z',
    });
    expect(screen.queryByLabelText('签名证书')).toBeNull();
    expect(JSON.stringify(localStorage)).not.toContain('one-time-sensitive-secret');
    await user.click(screen.getByRole('button', { name: '关闭' }));
    await user.click(screen.getByRole('button', { name: '创建授权' }));
    expect(screen.queryByDisplayValue('one-time-sensitive-secret')).toBeNull();
    expect(screen.queryByLabelText('一次性激活秘密')).toBeNull();
  });

  it.each([false, true])('v2 详情在绑定状态 %s 下隐藏旧解绑入口，仅激活后展示证书', async (bound) => {
    const license = {
      id: 'license-v2', keyId: 'ALPHA-LICENSE', productId: 'alpha', holderName: '离线客户',
      status: bound ? 'active' : 'created', mode: 'offline_device_v2', revision: 1, bindingVersion: bound ? 1 : 0,
      issuedAt: '2026-01-01T00:00:00Z', expiresAt: '2099-12-01T00:00:00Z',
      devicePublicKey: bound ? 'device-public-key' : null, fingerprintHash: bound ? 'fingerprint-hash' : null,
      fingerprintVersion: bound ? 1 : null, signedToken: bound ? 'signed-device-certificate' : null,
      activations: [{ id: 'activation-1', status: 'active', fingerprint: 'legacy-device' }],
    } as unknown as LicenseDetail;
    mockReads((path) => path === '/admin/licenses/ALPHA-LICENSE' ? license : undefined);
    const user = open('/licenses');
    await waitFor(() => expect((screen.getByLabelText('当前应用') as HTMLSelectElement).disabled).toBe(false));
    await user.click(screen.getByRole('link', { name: 'Open saved license link' }));
    await screen.findByText('离线客户', { exact: false });
    expect(screen.queryByRole('button', { name: /强制解绑/ })).toBeNull();
    expect(screen.queryByLabelText('一次性激活秘密')).toBeNull();
    if (bound) {
      expect(screen.getByDisplayValue('signed-device-certificate')).toBeTruthy();
      expect(screen.getByText('device-public-key')).toBeTruthy();
    } else {
      expect(within(screen.getByRole('dialog')).queryByRole('textbox')).toBeNull();
      expect(screen.getByText(/尚未签发设备证书/)).toBeTruthy();
    }
  });

});
