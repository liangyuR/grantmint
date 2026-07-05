import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { api, ApiError } from '../api/client';
import type { CreatePolicyRequest, Policy, Product, UpdatePolicyRequest } from '../api/types';
import Alert from '../components/Alert';
import EntitlementsEditor from '../components/EntitlementsEditor';
import FormField, { buttonClasses, inputClasses, secondaryButtonClasses } from '../components/FormField';

interface PolicyFormState {
  code: string;
  name: string;
  activationType: string;
  maxSeats: string;
  durationDays: string;
  gracePeriodDays: string;
  heartbeatIntervalSeconds: string;
  trial: boolean;
  constraintsText: string;
}

function toFormState(policy?: Policy): PolicyFormState {
  return {
    code: policy?.code ?? '',
    name: policy?.name ?? '',
    activationType: policy?.activationType ?? 'node_locked',
    maxSeats: String(policy?.maxSeats ?? 1),
    durationDays: policy?.durationDays != null ? String(policy.durationDays) : '',
    gracePeriodDays: String(policy?.gracePeriodDays ?? 0),
    heartbeatIntervalSeconds: String(policy?.heartbeatIntervalSeconds ?? 86400),
    trial: policy?.trial ?? false,
    constraintsText: policy ? JSON.stringify(policy.constraints ?? {}, null, 2) : '{}',
  };
}

export default function PoliciesPage() {
  const [products, setProducts] = useState<Product[]>([]);
  const [productId, setProductId] = useState<string>('');
  const [policies, setPolicies] = useState<Policy[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [form, setForm] = useState<PolicyFormState>(toFormState());
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api
      .get<Product[]>('/admin/products')
      .then((data) => {
        setProducts(data);
        const first = data[0];
        if (first) setProductId(first.id);
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : 'Failed to load products.'));
  }, []);

  async function loadPolicies(id: string) {
    if (!id) return;
    setError(null);
    try {
      const data = await api.get<Policy[]>(`/admin/products/${id}/policies`);
      setPolicies(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load policies.');
    }
  }

  useEffect(() => {
    setSelectedPolicyId(null);
    setShowCreateForm(false);
    void loadPolicies(productId);
  }, [productId]);

  const selectedPolicy = policies?.find((p) => p.id === selectedPolicyId) ?? null;

  function startCreate() {
    setSelectedPolicyId(null);
    setForm(toFormState());
    setShowCreateForm(true);
  }

  function startEdit(policy: Policy) {
    setShowCreateForm(false);
    setSelectedPolicyId(policy.id);
    setForm(toFormState(policy));
  }

  function parseConstraints(): Record<string, unknown> {
    try {
      const parsed = JSON.parse(form.constraintsText || '{}');
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('Constraints must be a JSON object.');
      }
      return parsed as Record<string, unknown>;
    } catch {
      throw new Error('Constraints must be valid JSON (an object).');
    }
  }

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const constraints = parseConstraints();
      const body: CreatePolicyRequest = {
        code: form.code,
        name: form.name,
        activationType: form.activationType,
        maxSeats: Number(form.maxSeats),
        durationDays: form.durationDays === '' ? null : Number(form.durationDays),
        gracePeriodDays: Number(form.gracePeriodDays),
        trial: form.trial,
        heartbeatIntervalSeconds: Number(form.heartbeatIntervalSeconds),
        constraints,
      };
      const created = await api.post<Policy>(`/admin/products/${productId}/policies`, body);
      setMessage(`Created policy "${created.name}". Add entitlements below.`);
      setShowCreateForm(false);
      await loadPolicies(productId);
      setSelectedPolicyId(created.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create policy.');
    } finally {
      setSaving(false);
    }
  }

  async function handleUpdate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedPolicy) return;
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const constraints = parseConstraints();
      const body: UpdatePolicyRequest = {
        name: form.name,
        activationType: form.activationType,
        maxSeats: Number(form.maxSeats),
        durationDays: form.durationDays === '' ? null : Number(form.durationDays),
        gracePeriodDays: Number(form.gracePeriodDays),
        trial: form.trial,
        heartbeatIntervalSeconds: Number(form.heartbeatIntervalSeconds),
        constraints,
      };
      await api.put(`/admin/policies/${selectedPolicy.id}`, body);
      setMessage(`Updated policy "${form.name}".`);
      await loadPolicies(productId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update policy.');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(policy: Policy) {
    if (!window.confirm(`Delete policy "${policy.name}"? This cannot be undone.`)) return;
    setError(null);
    try {
      await api.delete(`/admin/policies/${policy.id}`);
      setMessage(`Deleted policy "${policy.name}".`);
      if (selectedPolicyId === policy.id) setSelectedPolicyId(null);
      await loadPolicies(productId);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete policy.');
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-white">Policies</h1>
        <div className="flex items-center gap-2">
          <label htmlFor="product-select" className="text-sm text-gray-400">
            Product
          </label>
          <select
            id="product-select"
            className={inputClasses}
            value={productId}
            onChange={(e) => setProductId(e.target.value)}
          >
            {products.length === 0 && <option value="">No products</option>}
            {products.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <button type="button" className={buttonClasses} disabled={!productId} onClick={startCreate}>
            New policy
          </button>
        </div>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {message && <Alert kind="success">{message}</Alert>}

      {showCreateForm && (
        <PolicyForm
          form={form}
          setForm={setForm}
          onSubmit={handleCreate}
          onCancel={() => setShowCreateForm(false)}
          submitLabel="Create policy"
          saving={saving}
          codeEditable
        />
      )}

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-gray-900 text-xs uppercase tracking-wider text-gray-400">
            <tr>
              <th scope="col" className="px-4 py-2">Code</th>
              <th scope="col" className="px-4 py-2">Name</th>
              <th scope="col" className="px-4 py-2">Seats</th>
              <th scope="col" className="px-4 py-2">Duration</th>
              <th scope="col" className="px-4 py-2">Trial</th>
              <th scope="col" className="px-4 py-2">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {policies === null && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  Loading…
                </td>
              </tr>
            )}
            {policies !== null && policies.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  No policies for this product yet.
                </td>
              </tr>
            )}
            {policies?.map((policy) => (
              <tr key={policy.id} className="hover:bg-gray-900/60">
                <td className="px-4 py-2 font-mono text-gray-300">{policy.code}</td>
                <td className="px-4 py-2 text-gray-100">{policy.name}</td>
                <td className="px-4 py-2 text-gray-400">{policy.maxSeats}</td>
                <td className="px-4 py-2 text-gray-400">
                  {policy.durationDays != null ? `${policy.durationDays}d` : 'Perpetual'}
                </td>
                <td className="px-4 py-2 text-gray-400">{policy.trial ? 'Yes' : 'No'}</td>
                <td className="px-4 py-2 text-right">
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      className={secondaryButtonClasses}
                      onClick={() => startEdit(policy)}
                      aria-label={`Edit ${policy.name}`}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      className="rounded-md border border-red-900 px-3 py-1.5 text-sm font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                      onClick={() => void handleDelete(policy)}
                      aria-label={`Delete ${policy.name}`}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedPolicy && (
        <div className="space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-4">
          <h2 className="text-sm font-semibold text-gray-200">Edit policy: {selectedPolicy.name}</h2>
          <PolicyForm
            form={form}
            setForm={setForm}
            onSubmit={handleUpdate}
            onCancel={() => setSelectedPolicyId(null)}
            submitLabel="Save changes"
            saving={saving}
            codeEditable={false}
          />
          <EntitlementsEditor policyId={selectedPolicy.id} onChanged={() => void loadPolicies(productId)} />
        </div>
      )}
    </div>
  );
}

interface PolicyFormProps {
  form: PolicyFormState;
  setForm: (form: PolicyFormState) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onCancel: () => void;
  submitLabel: string;
  saving: boolean;
  codeEditable: boolean;
}

function PolicyForm({ form, setForm, onSubmit, onCancel, submitLabel, saving, codeEditable }: PolicyFormProps) {
  return (
    <form onSubmit={onSubmit} className="grid gap-4 rounded-lg border border-gray-800 bg-gray-900 p-4 sm:grid-cols-3">
      <FormField id="policy-code" label="Code">
        <input
          id="policy-code"
          className={inputClasses}
          required
          disabled={!codeEditable}
          value={form.code}
          onChange={(e) => setForm({ ...form, code: e.target.value })}
          placeholder="pro-annual"
        />
      </FormField>
      <FormField id="policy-name" label="Name">
        <input
          id="policy-name"
          className={inputClasses}
          required
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          placeholder="Pro Annual"
        />
      </FormField>
      <FormField id="policy-activation-type" label="Activation type">
        <select
          id="policy-activation-type"
          className={inputClasses}
          value={form.activationType}
          onChange={(e) => setForm({ ...form, activationType: e.target.value })}
        >
          <option value="node_locked">node_locked</option>
          <option value="floating">floating</option>
        </select>
      </FormField>
      <FormField id="policy-max-seats" label="Max seats">
        <input
          id="policy-max-seats"
          type="number"
          min={1}
          className={inputClasses}
          required
          value={form.maxSeats}
          onChange={(e) => setForm({ ...form, maxSeats: e.target.value })}
        />
      </FormField>
      <FormField id="policy-duration" label="Duration (days)" hint="Blank = perpetual">
        <input
          id="policy-duration"
          type="number"
          min={0}
          className={inputClasses}
          value={form.durationDays}
          onChange={(e) => setForm({ ...form, durationDays: e.target.value })}
        />
      </FormField>
      <FormField id="policy-grace" label="Grace period (days)">
        <input
          id="policy-grace"
          type="number"
          min={0}
          className={inputClasses}
          required
          value={form.gracePeriodDays}
          onChange={(e) => setForm({ ...form, gracePeriodDays: e.target.value })}
        />
      </FormField>
      <FormField id="policy-heartbeat" label="Heartbeat interval (seconds)">
        <input
          id="policy-heartbeat"
          type="number"
          min={1}
          className={inputClasses}
          required
          value={form.heartbeatIntervalSeconds}
          onChange={(e) => setForm({ ...form, heartbeatIntervalSeconds: e.target.value })}
        />
      </FormField>
      <FormField id="policy-trial" label="Trial">
        <select
          id="policy-trial"
          className={inputClasses}
          value={form.trial ? 'true' : 'false'}
          onChange={(e) => setForm({ ...form, trial: e.target.value === 'true' })}
        >
          <option value="false">No</option>
          <option value="true">Yes</option>
        </select>
      </FormField>
      <FormField id="policy-constraints" label="Constraints (JSON)" hint='e.g. {"seats":2,"nodeLocked":true}'>
        <textarea
          id="policy-constraints"
          className={`${inputClasses} font-mono`}
          rows={3}
          value={form.constraintsText}
          onChange={(e) => setForm({ ...form, constraintsText: e.target.value })}
        />
      </FormField>
      <div className="sm:col-span-3 flex gap-2">
        <button type="submit" disabled={saving} className={buttonClasses}>
          {saving ? 'Saving…' : submitLabel}
        </button>
        <button type="button" className={secondaryButtonClasses} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
