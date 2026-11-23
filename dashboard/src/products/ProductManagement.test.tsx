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
    await waitFor(() => expect((screen.getByLabelText('Current product') as HTMLSelectElement).disabled).toBe(false));
    await user.click(await screen.findByRole('button', { name: 'New policy' }));
    await user.type(screen.getByLabelText('Name'), 'Unfinished alpha policy');

    await user.selectOptions(screen.getByLabelText('Current product'), 'beta');
    await screen.findByText('beta annual');
    await act(async () => { finishAlpha([policy('alpha')]); });

    expect(screen.queryByDisplayValue('Unfinished alpha policy')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Create policy' })).toBeNull();
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
    await waitFor(() => expect((screen.getByLabelText('Current product') as HTMLSelectElement).disabled).toBe(false));
    await user.selectOptions(screen.getByLabelText('Current product'), 'beta');
    await user.click(screen.getByRole('link', { name: 'Open saved license link' }));

    await screen.findByText(/does not belong to the current product/);
    expect(screen.queryByText('Alpha customer')).toBeNull();
    expect(screen.queryByDisplayValue('secret-token')).toBeNull();
    expect(screen.queryByRole('button', { name: /Suspend|Reinstate|Revoke/ })).toBeNull();
  });

  it('issuing uses the selected product policy and converts its stop date from Beijing midnight', async () => {
    mockReads();
    const post = vi.spyOn(api, 'post').mockResolvedValue({ keyId: 'BETA-LICENSE', token: 'signed', status: 'active', expiresAt: '2026-11-30T16:00:00Z' });
    const user = open('/licenses');
    await waitFor(() => expect((screen.getByLabelText('Current product') as HTMLSelectElement).disabled).toBe(false));
    await user.selectOptions(screen.getByLabelText('Current product'), 'beta');
    await user.click(screen.getByRole('button', { name: 'Issue license' }));
    await screen.findByRole('option', { name: 'beta annual (1 seats)' });
    expect(screen.queryByRole('option', { name: 'alpha annual (1 seats)' })).toBeNull();
    await user.type(screen.getByLabelText('Holder name'), 'Beta customer');
    const issueForm = within(screen.getByLabelText('Holder name').closest('form')!);
    await user.type(issueForm.getByLabelText('Holder email'), 'beta@example.invalid');
    fireEvent.change(screen.getByLabelText('Stop date (Beijing time)'), { target: { value: '2026-12-01' } });
    await user.click(screen.getByRole('button', { name: 'Issue license' }));

    await screen.findByDisplayValue('BETA-LICENSE');
    expect(post).toHaveBeenCalledWith('/admin/licenses', {
      productId: 'beta', policyId: 'beta-policy', holder: { name: 'Beta customer', email: 'beta@example.invalid' },
      expiresAt: '2026-11-30T16:00:00.000Z',
    });
  });
});
