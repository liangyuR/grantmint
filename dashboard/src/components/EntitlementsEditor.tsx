import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { api, ApiError } from '../api/client';
import type {
  Entitlement,
  EntitlementValueType,
  EncodedEntitlementValue,
} from '../api/types';
import Alert from './Alert';
import FormField, { buttonClasses, inputClasses, secondaryButtonClasses } from './FormField';

function decodeValue(value: EncodedEntitlementValue): string {
  if ('bool' in value) return String(value.bool);
  if ('int' in value) return String(value.int);
  return value.string;
}

interface NewEntitlementForm {
  code: string;
  valueType: EntitlementValueType;
  value: string;
}

const EMPTY_NEW: NewEntitlementForm = { code: '', valueType: 'flag', value: 'true' };

/**
 * Key -> boolean/number/string entitlement editor for a policy, backed by
 * EntitlementAdminController. Each mutation rebuilds the policy's denormalized entitlements
 * snapshot server-side; `onChanged` lets the parent refetch the policy to reflect that.
 */
export default function EntitlementsEditor({
  policyId,
  onChanged,
}: {
  policyId: string;
  onChanged?: () => void;
}) {
  const [entitlements, setEntitlements] = useState<Entitlement[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [newForm, setNewForm] = useState<NewEntitlementForm>(EMPTY_NEW);
  const [editing, setEditing] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  async function load() {
    setError(null);
    try {
      const data = await api.get<Entitlement[]>(`/admin/policies/${policyId}/entitlements`);
      setEntitlements(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '加载权益失败。');
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policyId]);

  function parseRawValue(valueType: EntitlementValueType, raw: string): boolean | number | string {
    if (valueType === 'flag') return raw === 'true';
    if (valueType === 'limit') {
      const n = Number(raw);
      if (Number.isNaN(n)) throw new Error('限额必须是数字。');
      return n;
    }
    return raw;
  }

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const value = parseRawValue(newForm.valueType, newForm.value);
      await api.post(`/admin/policies/${policyId}/entitlements`, {
        code: newForm.code,
        valueType: newForm.valueType,
        value,
      });
      setNewForm(EMPTY_NEW);
      await load();
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : '添加权益失败。');
    } finally {
      setSaving(false);
    }
  }

  async function handleUpdate(entitlement: Entitlement) {
    const raw = editing[entitlement.id];
    if (raw === undefined) return;
    setSaving(true);
    setError(null);
    try {
      const value = parseRawValue(entitlement.valueType, raw);
      await api.put(`/admin/policies/${policyId}/entitlements/${entitlement.id}`, {
        valueType: entitlement.valueType,
        value,
      });
      await load();
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : '更新权益失败。');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(entitlement: Entitlement) {
    setSaving(true);
    setError(null);
    try {
      await api.delete(`/admin/policies/${policyId}/entitlements/${entitlement.id}`);
      await load();
      onChanged?.();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '删除权益失败。');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-gray-200">功能权益</h3>
      {error && <Alert kind="error">{error}</Alert>}

      {entitlements === null && <p className="text-sm text-gray-500">正在加载…</p>}
      {entitlements !== null && entitlements.length === 0 && (
        <p className="text-sm text-gray-500">尚未定义功能权益。</p>
      )}

      {entitlements !== null && entitlements.length > 0 && (
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase tracking-wider text-gray-500">
            <tr>
              <th scope="col" className="py-1 pr-2">代码</th>
              <th scope="col" className="py-1 pr-2">类型</th>
              <th scope="col" className="py-1 pr-2">值</th>
              <th scope="col" className="py-1 pr-2">
                <span className="sr-only">操作</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {entitlements.map((entitlement) => {
              const currentRaw = editing[entitlement.id] ?? decodeValue(entitlement.value);
              return (
                <tr key={entitlement.id}>
                  <td className="py-1.5 pr-2 font-mono text-gray-300">{entitlement.code}</td>
                  <td className="py-1.5 pr-2 text-gray-400">{{ flag: '开关', limit: '数值限额', string: '文本' }[entitlement.valueType]}</td>
                  <td className="py-1.5 pr-2">
                    {entitlement.valueType === 'flag' ? (
                      <select
                        aria-label={`${entitlement.code} 的值`}
                        className={inputClasses}
                        value={currentRaw}
                        onChange={(e) => setEditing({ ...editing, [entitlement.id]: e.target.value })}
                      >
                        <option value="true">启用</option>
                        <option value="false">关闭</option>
                      </select>
                    ) : (
                      <input
                        aria-label={`${entitlement.code} 的值`}
                        className={inputClasses}
                        type={entitlement.valueType === 'limit' ? 'number' : 'text'}
                        value={currentRaw}
                        onChange={(e) => setEditing({ ...editing, [entitlement.id]: e.target.value })}
                      />
                    )}
                  </td>
                  <td className="py-1.5 pr-2">
                    <div className="flex gap-2">
                      <button
                        type="button"
                        className={secondaryButtonClasses}
                        disabled={saving}
                        onClick={() => void handleUpdate(entitlement)}
                      >
                        保存
                      </button>
                      <button
                        type="button"
                        className="rounded-md border border-red-900 px-3 py-1.5 text-sm font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                        disabled={saving}
                        onClick={() => void handleDelete(entitlement)}
                        aria-label={`删除权益 ${entitlement.code}`}
                      >
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <form onSubmit={(e) => void handleCreate(e)} className="grid gap-3 rounded-md border border-gray-800 p-3 sm:grid-cols-4">
        <FormField id="new-ent-code" label="代码">
          <input
            id="new-ent-code"
            className={inputClasses}
            required
            pattern="^[a-z][a-z0-9_]{0,62}$"
            title="以小写字母开头，仅使用小写字母、数字或下划线"
            value={newForm.code}
            onChange={(e) => setNewForm({ ...newForm, code: e.target.value })}
            placeholder="max_devices"
          />
        </FormField>
        <FormField id="new-ent-type" label="类型">
          <select
            id="new-ent-type"
            className={inputClasses}
            value={newForm.valueType}
            onChange={(e) =>
              setNewForm({
                ...newForm,
                valueType: e.target.value as EntitlementValueType,
                value: e.target.value === 'flag' ? 'true' : '',
              })
            }
          >
            <option value="flag">开关</option>
            <option value="limit">数值限额</option>
            <option value="string">文本</option>
          </select>
        </FormField>
        <FormField id="new-ent-value" label="值">
          {newForm.valueType === 'flag' ? (
            <select
              id="new-ent-value"
              className={inputClasses}
              value={newForm.value}
              onChange={(e) => setNewForm({ ...newForm, value: e.target.value })}
            >
              <option value="true">启用</option>
              <option value="false">关闭</option>
            </select>
          ) : (
            <input
              id="new-ent-value"
              className={inputClasses}
              type={newForm.valueType === 'limit' ? 'number' : 'text'}
              required
              value={newForm.value}
              onChange={(e) => setNewForm({ ...newForm, value: e.target.value })}
            />
          )}
        </FormField>
        <div className="flex items-end">
          <button type="submit" disabled={saving} className={buttonClasses}>
            添加权益
          </button>
        </div>
      </form>
    </div>
  );
}
