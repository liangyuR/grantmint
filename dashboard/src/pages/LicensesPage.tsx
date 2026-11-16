import { useState } from 'react';
import { useProducts } from '../products/ProductContext';
import { useResource } from '../api/useResource';
import type { FormEvent } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { IssueLicenseResponse, LicensePage, Policy } from '../api/types';
import Alert from '../components/Alert';
import StatusBadge from '../components/StatusBadge';
import FormField, { buttonClasses, inputClasses, secondaryButtonClasses } from '../components/FormField';

const PAGE_SIZE = 20;
const STATUS_OPTIONS = ['', 'created', 'active', 'suspended', 'expired', 'revoked'];

export default function LicensesPage() {
  const navigate = useNavigate();
  const { product } = useProducts();
  const productId = product?.id ?? '';
  const [status, setStatus] = useState('');
  const [holderEmail, setHolderEmail] = useState('');
  const [keyId, setKeyId] = useState('');
  const [page, setPage] = useState(0);

  const [showIssueForm, setShowIssueForm] = useState(false);

  const params = new URLSearchParams({ productId, page: String(page), size: String(PAGE_SIZE) });
  if (status) params.set('status', status);
  if (holderEmail) params.set('holderEmail', holderEmail);
  if (keyId) params.set('keyId', keyId);
  const { data: result, error, reload } = useResource<LicensePage>(productId ? `/admin/licenses?${params}` : null);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPage(0);
    reload();
  }

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.size)) : 1;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-white">Licenses</h1>
        <button type="button" className={buttonClasses} disabled={!productId} onClick={() => setShowIssueForm((v) => !v)}>
          {showIssueForm ? 'Close' : 'Issue license'}
        </button>
      </div>

      {error && <Alert kind="error">{error}</Alert>}

      {/* Keep the form mounted after issuance — it swaps to the shown-once token panel. */}
      {showIssueForm && <IssueLicenseForm onIssued={reload} />}

      <form onSubmit={applyFilters} className="flex flex-wrap items-end gap-3 rounded-lg border border-gray-800 bg-gray-900 p-4">
        <FormField id="filter-status" label="Status">
          <select id="filter-status" className={inputClasses} value={status} onChange={(e) => { setStatus(e.target.value); setPage(0); }}>
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt || 'any'} value={opt}>
                {opt || 'Any'}
              </option>
            ))}
          </select>
        </FormField>
        <FormField id="filter-holder-email" label="Holder email">
          <input
            id="filter-holder-email"
            className={inputClasses}
            value={holderEmail}
            onChange={(e) => { setHolderEmail(e.target.value); setPage(0); }}
            placeholder="jane@example.com"
          />
        </FormField>
        <FormField id="filter-key-id" label="Key ID">
          <input
            id="filter-key-id"
            className={inputClasses}
            value={keyId}
            onChange={(e) => { setKeyId(e.target.value); setPage(0); }}
            placeholder="K7P2-9QXM-4T1Y"
          />
        </FormField>
        <button type="submit" className={secondaryButtonClasses}>
          Apply filters
        </button>
      </form>

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-gray-900 text-xs uppercase tracking-wider text-gray-400">
            <tr>
              <th scope="col" className="px-4 py-2">Key ID</th>
              <th scope="col" className="px-4 py-2">Status</th>
              <th scope="col" className="px-4 py-2">Holder</th>
              <th scope="col" className="px-4 py-2">Seats</th>
              <th scope="col" className="px-4 py-2">Issued</th>
              <th scope="col" className="px-4 py-2">Stops (Beijing)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {!error && result === null && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  {productId ? 'Loading…' : 'Select or create a product first.'}
                </td>
              </tr>
            )}
            {result !== null && result.items.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  No licenses match these filters.
                </td>
              </tr>
            )}
            {result?.items.map((license) => (
              <tr
                key={license.id}
                tabIndex={0}
                role="button"
                aria-label={`View license ${license.keyId}`}
                onClick={() => navigate(`/licenses/${license.keyId}`)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') navigate(`/licenses/${license.keyId}`);
                }}
                className="cursor-pointer hover:bg-gray-900/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-indigo-500"
              >
                <td className="px-4 py-2 font-mono text-gray-300">{license.keyId}</td>
                <td className="px-4 py-2">
                  <StatusBadge status={license.status} />
                </td>
                <td className="px-4 py-2 text-gray-100">
                  {license.holderName}
                  <div className="text-xs text-gray-500">{license.holderEmail}</div>
                </td>
                <td className="px-4 py-2 text-gray-400">
                  {license.activeSeats}/{license.maxSeats}
                </td>
                <td className="px-4 py-2 text-gray-400">{new Date(license.issuedAt).toLocaleDateString()}</td>
                <td className="px-4 py-2 text-gray-400">
                  {license.expiresAt ? new Date(license.expiresAt).toLocaleString('en-GB', { timeZone: 'Asia/Shanghai', hourCycle: 'h23' }) : 'Perpetual'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {result && result.total > 0 && (
        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>
            Page {result.page + 1} of {totalPages} ({result.total} total)
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              className={secondaryButtonClasses}
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              Previous
            </button>
            <button
              type="button"
              className={secondaryButtonClasses}
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}

      <Outlet />
    </div>
  );
}

interface IssueFormState {
  policyId: string;
  holderName: string;
  holderEmail: string;
  expiresAt: string;
  externalRef: string;
}

function IssueLicenseForm({ onIssued }: { onIssued: () => void }) {
  const { product } = useProducts();
  const productId = product?.id ?? '';
  const { data: policies, error: policyError } = useResource<Policy[]>(productId ? `/admin/products/${productId}/policies` : null);
  const [form, setForm] = useState<IssueFormState>({
    policyId: '',
    holderName: '',
    holderEmail: '',
    expiresAt: '',
    externalRef: '',
  });
  const [issuing, setIssuing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssueLicenseResponse | null>(null);

  const policyId = form.policyId || policies?.[0]?.id || '';

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!productId || !policies?.some((policy) => policy.id === policyId)) return;
    setIssuing(true);
    setError(null);
    try {
      const response = await api.post<IssueLicenseResponse>('/admin/licenses', {
        productId,
        policyId,
        holder: { name: form.holderName, email: form.holderEmail },
        ...(form.expiresAt ? { expiresAt: new Date(`${form.expiresAt}T00:00:00+08:00`).toISOString() } : {}),
        ...(form.externalRef.trim() ? { externalRef: form.externalRef.trim() } : {}),
      });
      setIssued(response);
      onIssued();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to issue license.');
    } finally {
      setIssuing(false);
    }
  }

  if (issued) {
    return (
      <div className="space-y-3 rounded-lg border border-emerald-800 bg-emerald-950/40 p-4">
        <Alert kind="success">License issued. This token is shown once — copy it now.</Alert>
        <FormField id="issued-key-id" label="Key ID">
          <div className="flex gap-2">
            <input id="issued-key-id" readOnly className={`${inputClasses} font-mono`} value={issued.keyId} />
            <button type="button" className={secondaryButtonClasses} onClick={() => void navigator.clipboard.writeText(issued.keyId)}>
              Copy
            </button>
          </div>
        </FormField>
        <FormField id="issued-token" label="Signed token">
          <div className="flex gap-2">
            <textarea id="issued-token" readOnly className={`${inputClasses} font-mono`} rows={3} value={issued.token} />
            <button
              type="button"
              className={secondaryButtonClasses}
              onClick={() => void navigator.clipboard.writeText(issued.token)}
            >
              Copy
            </button>
          </div>
        </FormField>
        <button type="button" className={secondaryButtonClasses} onClick={() => setIssued(null)}>
          Issue another
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={(e) => void handleSubmit(e)} className="grid gap-4 rounded-lg border border-gray-800 bg-gray-900 p-4 sm:grid-cols-3">
      {error && (
        <div className="sm:col-span-3">
          <Alert kind="error">{error}</Alert>
        </div>
      )}
      <div className="sm:col-span-3 text-sm text-gray-400">
        Issuing for <strong className="text-gray-100">{product?.name}</strong>. This uses the current v1 license format; device-bound offline certificates are not available yet.
      </div>
      {policyError && <div className="sm:col-span-3"><Alert kind="error">{policyError}</Alert></div>}
      <FormField id="issue-policy" label="Policy">
        <select
          id="issue-policy"
          className={inputClasses}
          required
          value={policyId}
          onChange={(e) => setForm({ ...form, policyId: e.target.value })}
        >
          {!policies?.length && <option value="">{policies ? 'No policies for this product' : 'Loading policies…'}</option>}
          {policies?.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.maxSeats} seats)
            </option>
          ))}
        </select>
      </FormField>
      <FormField id="issue-expires" label="Stop date (Beijing time)" hint="Stops at 00:00 Asia/Shanghai. Blank = policy duration. Existing policy grace still applies to v1 tokens.">
        <input
          id="issue-expires"
          type="date"
          className={inputClasses}
          value={form.expiresAt}
          onChange={(e) => setForm({ ...form, expiresAt: e.target.value })}
        />
      </FormField>
      <FormField id="issue-holder-name" label="Holder name">
        <input
          id="issue-holder-name"
          className={inputClasses}
          required
          value={form.holderName}
          onChange={(e) => setForm({ ...form, holderName: e.target.value })}
        />
      </FormField>
      <FormField id="issue-holder-email" label="Holder email">
        <input
          id="issue-holder-email"
          type="email"
          className={inputClasses}
          required
          value={form.holderEmail}
          onChange={(e) => setForm({ ...form, holderEmail: e.target.value })}
        />
      </FormField>
      <FormField id="issue-external-ref" label="External ref" hint="Optional — e.g. billing subscription id">
        <input
          id="issue-external-ref"
          className={inputClasses}
          value={form.externalRef}
          onChange={(e) => setForm({ ...form, externalRef: e.target.value })}
        />
      </FormField>
      <div className="flex items-end">
        <button type="submit" disabled={issuing || !policyId || !!policyError} className={buttonClasses}>
          {issuing ? 'Issuing…' : 'Issue license'}
        </button>
      </div>
    </form>
  );
}
