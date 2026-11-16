import { useState } from 'react';
import { useProducts } from '../products/ProductContext';
import { useResource } from '../api/useResource';
import type { FormEvent } from 'react';
import { api, ApiError } from '../api/client';
import type { CreatePolicyRequest, Policy, UpdatePolicyRequest } from '../api/types';
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
  const { product } = useProducts();
  const productId = product?.id ?? '';
  const { data: policies, error: loadError, reload } = useResource<Policy[]>(productId ? `/admin/products/${productId}/policies` : null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [form, setForm] = useState<PolicyFormState>(toFormState());
  const [saving, setSaving] = useState(false);

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
        throw new Error('约束必须是 JSON 对象。');
      }
      return parsed as Record<string, unknown>;
    } catch {
      throw new Error('请输入有效的 JSON 对象。');
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
      setMessage(`已创建策略“${created.name}”，可在下方添加权益。`);
      setShowCreateForm(false);
      reload();
      setSelectedPolicyId(created.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : '创建策略失败。');
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
      setMessage(`已更新策略“${form.name}”。`);
      reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : '更新策略失败。');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(policy: Policy) {
    if (!window.confirm(`删除策略“${policy.name}”？此操作不可撤销。`)) return;
    setError(null);
    try {
      await api.delete(`/admin/policies/${policy.id}`);
      setMessage(`已删除策略“${policy.name}”。`);
      if (selectedPolicyId === policy.id) setSelectedPolicyId(null);
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '删除策略失败。');
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-white">策略管理</h1>
        <div className="flex items-center gap-2">
          <button type="button" className={buttonClasses} disabled={!productId} onClick={startCreate}>
            新建策略
          </button>
        </div>
      </div>

      {(error || loadError) && <Alert kind="error">{error || loadError}</Alert>}
      {message && <Alert kind="success">{message}</Alert>}

      {showCreateForm && (
        <PolicyForm
          form={form}
          setForm={setForm}
          onSubmit={handleCreate}
          onCancel={() => setShowCreateForm(false)}
          submitLabel="创建策略"
          saving={saving}
          codeEditable
        />
      )}

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-gray-900 text-xs uppercase tracking-wider text-gray-400">
            <tr>
              <th scope="col" className="px-4 py-2">代码</th>
              <th scope="col" className="px-4 py-2">名称</th>
              <th scope="col" className="px-4 py-2">设备数</th>
              <th scope="col" className="px-4 py-2">有效期</th>
              <th scope="col" className="px-4 py-2">试用</th>
              <th scope="col" className="px-4 py-2">
                <span className="sr-only">操作</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {!loadError && policies === null && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  {productId ? '正在加载…' : '请先选择或创建应用。'}
                </td>
              </tr>
            )}
            {policies !== null && policies.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  此应用尚无策略。
                </td>
              </tr>
            )}
            {policies?.map((policy) => (
              <tr key={policy.id} className="hover:bg-gray-900/60">
                <td className="px-4 py-2 font-mono text-gray-300">{policy.code}</td>
                <td className="px-4 py-2 text-gray-100">{policy.name}</td>
                <td className="px-4 py-2 text-gray-400">{policy.maxSeats}</td>
                <td className="px-4 py-2 text-gray-400">
                  {policy.durationDays != null ? `${policy.durationDays} 天` : '永久'}
                </td>
                <td className="px-4 py-2 text-gray-400">{policy.trial ? '是' : '否'}</td>
                <td className="px-4 py-2 text-right">
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      className={secondaryButtonClasses}
                      onClick={() => startEdit(policy)}
                      aria-label={`编辑 ${policy.name}`}
                    >
                      编辑
                    </button>
                    <button
                      type="button"
                      className="rounded-md border border-red-900 px-3 py-1.5 text-sm font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                      onClick={() => void handleDelete(policy)}
                      aria-label={`删除 ${policy.name}`}
                    >
                      删除
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
            submitLabel="保存修改"
            saving={saving}
            codeEditable={false}
          />
          <EntitlementsEditor policyId={selectedPolicy.id} onChanged={reload} />
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
      <FormField id="policy-code" label="代码">
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
      <FormField id="policy-name" label="名称">
        <input
          id="policy-name"
          className={inputClasses}
          required
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          placeholder="专业版年度授权"
        />
      </FormField>
      <FormField id="policy-activation-type" label="激活类型">
        <select
          id="policy-activation-type"
          className={inputClasses}
          value={form.activationType}
          onChange={(e) => setForm({ ...form, activationType: e.target.value })}
        >
          <option value="node_locked">绑定设备（v1）</option>
          <option value="floating">浮动授权（v1）</option>
        </select>
      </FormField>
      <FormField id="policy-max-seats" label="最大设备数">
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
      <FormField id="policy-duration" label="有效天数" hint="留空表示永久">
        <input
          id="policy-duration"
          type="number"
          min={0}
          className={inputClasses}
          value={form.durationDays}
          onChange={(e) => setForm({ ...form, durationDays: e.target.value })}
        />
      </FormField>
      <FormField id="policy-grace" label="宽限期（天）">
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
      <FormField id="policy-heartbeat" label="心跳间隔（秒）">
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
      <FormField id="policy-trial" label="试用">
        <select
          id="policy-trial"
          className={inputClasses}
          value={form.trial ? 'true' : 'false'}
          onChange={(e) => setForm({ ...form, trial: e.target.value === 'true' })}
        >
          <option value="false">否</option>
          <option value="true">是</option>
        </select>
      </FormField>
      <FormField id="policy-constraints" label="约束（JSON）" hint='例如 {"seats":2,"nodeLocked":true}'>
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
          {saving ? '保存中…' : submitLabel}
        </button>
        <button type="button" className={secondaryButtonClasses} onClick={onCancel}>
          取消
        </button>
      </div>
    </form>
  );
}
