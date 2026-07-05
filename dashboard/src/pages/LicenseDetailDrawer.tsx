import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { LicenseDetail } from '../api/types';
import Alert from '../components/Alert';
import ConfirmDialog from '../components/ConfirmDialog';
import StatusBadge from '../components/StatusBadge';
import { inputClasses, secondaryButtonClasses } from '../components/FormField';

export default function LicenseDetailDrawer() {
  const { keyId } = useParams<{ keyId: string }>();
  const navigate = useNavigate();

  const [license, setLicense] = useState<LicenseDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmingRevoke, setConfirmingRevoke] = useState(false);

  async function load() {
    if (!keyId) return;
    setError(null);
    try {
      const data = await api.get<LicenseDetail>(`/admin/licenses/${keyId}`);
      setLicense(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load license.');
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keyId]);

  function close() {
    navigate('/licenses');
  }

  async function handleSuspend() {
    if (!keyId) return;
    setBusy(true);
    setError(null);
    try {
      const reason = window.prompt('Reason for suspension (optional):') ?? undefined;
      await api.post(`/admin/licenses/${keyId}/suspend`, reason ? { reason } : {});
      setMessage('License suspended.');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to suspend license.');
    } finally {
      setBusy(false);
    }
  }

  async function handleReinstate() {
    if (!keyId) return;
    setBusy(true);
    setError(null);
    try {
      await api.post(`/admin/licenses/${keyId}/reinstate`);
      setMessage('License reinstated.');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to reinstate license.');
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke() {
    if (!keyId) return;
    setBusy(true);
    setError(null);
    try {
      await api.delete(`/admin/licenses/${keyId}`, { reason: 'Revoked from operator console' });
      setMessage('License revoked. This is terminal.');
      setConfirmingRevoke(false);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke license.');
    } finally {
      setBusy(false);
    }
  }

  async function handleForceDeactivate(activationId: string) {
    if (!keyId) return;
    if (!window.confirm('Force-deactivate this device? Its seat will be released immediately.')) return;
    setBusy(true);
    setError(null);
    try {
      await api.delete(`/admin/licenses/${keyId}/activations/${activationId}`);
      setMessage('Activation deactivated.');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to deactivate.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`License ${keyId ?? ''} details`}
        className="h-full w-full max-w-xl overflow-y-auto border-l border-gray-800 bg-gray-950 p-6 shadow-2xl"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">License {keyId}</h2>
          <button
            type="button"
            onClick={close}
            className={secondaryButtonClasses}
            aria-label="Close license details"
          >
            Close
          </button>
        </div>

        <div className="mt-4 space-y-4">
          {error && <Alert kind="error">{error}</Alert>}
          {message && <Alert kind="success">{message}</Alert>}

          {!license && !error && <p className="text-sm text-gray-500">Loading…</p>}

          {license && (
            <>
              <div className="grid grid-cols-2 gap-3 rounded-lg border border-gray-800 bg-gray-900 p-4 text-sm">
                <div>
                  <dt className="text-xs uppercase text-gray-500">Status</dt>
                  <dd>
                    <StatusBadge status={license.status} />
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-gray-500">Seats</dt>
                  <dd className="text-gray-100">
                    {license.activations.filter((a) => a.status === 'active').length}/{license.maxSeats}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-gray-500">Holder</dt>
                  <dd className="text-gray-100">
                    {license.holderName} &lt;{license.holderEmail}&gt;
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-gray-500">Issued</dt>
                  <dd className="text-gray-100">{new Date(license.issuedAt).toLocaleString()}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-gray-500">Expires</dt>
                  <dd className="text-gray-100">
                    {license.expiresAt ? new Date(license.expiresAt).toLocaleString() : 'Perpetual'}
                  </dd>
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <button type="button" className={secondaryButtonClasses} disabled={busy} onClick={() => void handleSuspend()}>
                  Suspend
                </button>
                <button type="button" className={secondaryButtonClasses} disabled={busy} onClick={() => void handleReinstate()}>
                  Reinstate
                </button>
                <button
                  type="button"
                  className="rounded-md border border-red-900 px-3 py-1.5 text-sm font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-60"
                  disabled={busy}
                  onClick={() => setConfirmingRevoke(true)}
                >
                  Revoke
                </button>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-gray-200">Signed token</h3>
                <div className="mt-1 flex gap-2">
                  <textarea readOnly rows={4} className={`${inputClasses} font-mono`} value={license.signedToken} />
                  <button
                    type="button"
                    className={secondaryButtonClasses}
                    onClick={() => void navigator.clipboard.writeText(license.signedToken)}
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-gray-200">Activations</h3>
                <div className="mt-2 overflow-x-auto rounded-lg border border-gray-800">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-gray-900 text-xs uppercase tracking-wider text-gray-400">
                      <tr>
                        <th scope="col" className="px-3 py-2">Fingerprint</th>
                        <th scope="col" className="px-3 py-2">Machine</th>
                        <th scope="col" className="px-3 py-2">Platform</th>
                        <th scope="col" className="px-3 py-2">Status</th>
                        <th scope="col" className="px-3 py-2">Last heartbeat</th>
                        <th scope="col" className="px-3 py-2">Deactivated</th>
                        <th scope="col" className="px-3 py-2">
                          <span className="sr-only">Actions</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {license.activations.length === 0 && (
                        <tr>
                          <td colSpan={7} className="px-3 py-4 text-center text-gray-500">
                            No activations yet.
                          </td>
                        </tr>
                      )}
                      {license.activations.map((activation) => (
                        <tr key={activation.id}>
                          <td className="px-3 py-2 font-mono text-gray-300">{activation.fingerprint}</td>
                          <td className="px-3 py-2 text-gray-400">{activation.machineName ?? '—'}</td>
                          <td className="px-3 py-2 text-gray-400">{activation.platform ?? '—'}</td>
                          <td className="px-3 py-2">
                            <StatusBadge status={activation.status} />
                          </td>
                          <td className="px-3 py-2 text-gray-400">
                            {activation.lastHeartbeatAt ? new Date(activation.lastHeartbeatAt).toLocaleString() : 'Never'}
                          </td>
                          <td className="px-3 py-2 text-gray-400">
                            {activation.deactivatedAt ? new Date(activation.deactivatedAt).toLocaleString() : '—'}
                          </td>
                          <td className="px-3 py-2 text-right">
                            <button
                              type="button"
                              className="rounded-md border border-red-900 px-2.5 py-1 text-xs font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-60"
                              disabled={busy}
                              onClick={() => void handleForceDeactivate(activation.id)}
                              aria-label={`Force deactivate ${activation.fingerprint}`}
                            >
                              Force deactivate
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {confirmingRevoke && (
        <ConfirmDialog
          title="Revoke this license?"
          description="Revocation is terminal and cannot be undone. Online validation will start rejecting it immediately; offline copies remain verifiable until they expire."
          confirmLabel="Revoke"
          danger
          busy={busy}
          onCancel={() => setConfirmingRevoke(false)}
          onConfirm={() => void handleRevoke()}
        />
      )}
    </div>
  );
}
