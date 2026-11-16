import { useState } from 'react';
import { useProducts } from '../products/ProductContext';
import { useResource } from '../api/useResource';
import type { FormEvent } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { CreateOfflineLicenseResponse, IssueLicenseResponse, LicensePage, Policy } from '../api/types';
import Alert from '../components/Alert';
import StatusBadge, { STATUS_LABELS } from '../components/StatusBadge';
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
        <h1 className="text-xl font-semibold text-white">授权管理</h1>
        <button type="button" className={buttonClasses} disabled={!productId} onClick={() => setShowIssueForm((v) => !v)}>
          {showIssueForm ? '关闭' : '创建授权'}
        </button>
      </div>

      {error && <Alert kind="error">{error}</Alert>}

      {/* Keep the form mounted after issuance — it swaps to the shown-once token panel. */}
      {showIssueForm && <IssueLicenseForm onIssued={reload} />}

      <form onSubmit={applyFilters} className="flex flex-wrap items-end gap-3 rounded-lg border border-gray-800 bg-gray-900 p-4">
        <FormField id="filter-status" label="状态">
          <select id="filter-status" className={inputClasses} value={status} onChange={(e) => { setStatus(e.target.value); setPage(0); }}>
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt || 'any'} value={opt}>
                {STATUS_LABELS[opt] || '全部'}
              </option>
            ))}
          </select>
        </FormField>
        <FormField id="filter-holder-email" label="客户邮箱">
          <input
            id="filter-holder-email"
            className={inputClasses}
            value={holderEmail}
            onChange={(e) => { setHolderEmail(e.target.value); setPage(0); }}
            placeholder="jane@example.com"
          />
        </FormField>
        <FormField id="filter-key-id" label="授权编号">
          <input
            id="filter-key-id"
            className={inputClasses}
            value={keyId}
            onChange={(e) => { setKeyId(e.target.value); setPage(0); }}
            placeholder="K7P2-9QXM-4T1Y"
          />
        </FormField>
        <button type="submit" className={secondaryButtonClasses}>
          应用筛选
        </button>
      </form>

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-gray-900 text-xs uppercase tracking-wider text-gray-400">
            <tr>
              <th scope="col" className="px-4 py-2">授权编号</th>
              <th scope="col" className="px-4 py-2">状态</th>
              <th scope="col" className="px-4 py-2">客户</th>
              <th scope="col" className="px-4 py-2">设备数</th>
              <th scope="col" className="px-4 py-2">创建时间</th>
              <th scope="col" className="px-4 py-2">停用时间（北京时间）</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {!error && result === null && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  {productId ? '正在加载…' : '请先选择或创建应用。'}
                </td>
              </tr>
            )}
            {result !== null && result.items.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  没有符合筛选条件的授权。
                </td>
              </tr>
            )}
            {result?.items.map((license) => (
              <tr
                key={license.id}
                tabIndex={0}
                role="button"
                aria-label={`查看授权 ${license.keyId}`}
                onClick={() => navigate(`/licenses/${license.keyId}`)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') navigate(`/licenses/${license.keyId}`);
                }}
                className="cursor-pointer hover:bg-gray-900/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-indigo-500"
              >
                <td className="px-4 py-2 font-mono text-gray-300">{license.keyId}</td>
                <td className="px-4 py-2">
                  <StatusBadge status={license.status} />
                  <div className="mt-1 text-xs text-gray-400">{license.mode === 'offline_device_v2' ? '单设备离线 v2' : '兼容授权 v1'}</div>
                </td>
                <td className="px-4 py-2 text-gray-100">
                  {license.holderName}
                  <div className="text-xs text-gray-500">{license.holderEmail}</div>
                </td>
                <td className="px-4 py-2 text-gray-400">
                  {license.activeSeats}/{license.maxSeats}
                </td>
                <td className="px-4 py-2 text-gray-400">{new Date(license.issuedAt).toLocaleDateString('zh-CN', { timeZone: 'Asia/Shanghai' })}</td>
                <td className="px-4 py-2 text-gray-400">
                  {license.expiresAt ? new Date(license.expiresAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hourCycle: 'h23' }) : '永久'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {result && result.total > 0 && (
        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>
            第 {result.page + 1} / {totalPages} 页，共 {result.total} 条
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              className={secondaryButtonClasses}
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              上一页
            </button>
            <button
              type="button"
              className={secondaryButtonClasses}
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              下一页
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
  const [mode, setMode] = useState<'offline_device_v2' | 'legacy'>('offline_device_v2');
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssueLicenseResponse | CreateOfflineLicenseResponse | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopyError(null);
    } catch {
      setCopyError('复制失败，请手动选择并复制文本。');
    }
  }

  const policyId = form.policyId || policies?.[0]?.id || '';

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!productId || !policies?.some((policy) => policy.id === policyId)) return;
    if (mode === 'offline_device_v2' && (!form.expiresAt || new Date(`${form.expiresAt}T00:00:00+08:00`).getTime() <= Date.now())) {
      setError('单设备离线授权必须填写未来的停用日期。');
      return;
    }
    setIssuing(true);
    setError(null);
    try {
      const response = await api.post<IssueLicenseResponse | CreateOfflineLicenseResponse>(mode === 'offline_device_v2' ? '/admin/v2/licenses' : '/admin/licenses', {
        productId,
        policyId,
        holder: { name: form.holderName, email: form.holderEmail },
        ...(form.expiresAt ? { expiresAt: new Date(`${form.expiresAt}T00:00:00+08:00`).toISOString() } : {}),
        ...(mode === 'legacy' && form.externalRef.trim() ? { externalRef: form.externalRef.trim() } : {}),
      });
      setIssued(response);
      onIssued();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '创建授权失败。');
    } finally {
      setIssuing(false);
    }
  }

  if (issued) {
    const offline = 'activationSecret' in issued;
    return (
      <div className="space-y-3 rounded-lg border border-emerald-800 bg-emerald-950/40 p-4">
        <Alert kind="success">{offline ? '授权记录已创建，等待客户设备首次联网激活。激活成功后才会签发绑定设备的离线证书。' : '已签发 v1 兼容授权证书。'}</Alert>
        {offline && <Alert kind="info">激活秘密仅显示本次，请立即安全保存并通过可信渠道交付客户。关闭页面后无法再次查看；不要把它放入日志、公开链接或代码。激活秘密不是可运行的离线证书。</Alert>}
        {copyError && <Alert kind="error">{copyError}</Alert>}
        {offline && <div className="text-sm text-gray-300">授权 ID：<span className="font-mono">{issued.licenseId}</span></div>}
        {offline && <div className="text-sm text-gray-300">应用 ID：<span className="font-mono">{productId}</span></div>}
        <FormField id="issued-key-id" label="授权编号">
          <div className="flex gap-2">
            <input id="issued-key-id" readOnly className={`${inputClasses} font-mono`} value={issued.keyId} />
            <button type="button" className={secondaryButtonClasses} onClick={() => void copy(issued.keyId)}>
              复制
            </button>
          </div>
        </FormField>
        <FormField id="issued-token" label={offline ? '一次性激活秘密' : '签名证书'}>
          <div className="flex gap-2">
            <textarea id="issued-token" readOnly className={`${inputClasses} font-mono`} rows={3} value={offline ? issued.activationSecret : issued.token} />
            <button
              type="button"
              className={secondaryButtonClasses}
              onClick={() => void copy(offline ? issued.activationSecret : issued.token)}
            >
              复制
            </button>
          </div>
        </FormField>
        <button type="button" className={secondaryButtonClasses} onClick={() => { setIssued(null); setCopyError(null); }}>
          继续创建
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
        当前应用：<strong className="text-gray-100">{product?.name}</strong>。
      </div>
      <FormField id="issue-mode" label="授权模式">
        <select id="issue-mode" className={inputClasses} value={mode} onChange={(event) => setMode(event.target.value as typeof mode)}>
          <option value="offline_device_v2">单设备离线授权（v2，推荐）</option>
          <option value="legacy">旧版兼容授权（v1）</option>
        </select>
      </FormField>
      <div className="sm:col-span-3 text-sm text-gray-400">
        {mode === 'offline_device_v2' ? '固定绑定一台设备，无宽限期、无强制心跳。客户使用 Rust 客户端首次联网激活，之后可离线使用到合同到期。所选策略仅提供权益；后台暂停或撤销不能立即使已下载的离线证书失效。' : 'v1 不提供离线设备绑定，沿用策略的设备数、宽限期和心跳规则。'}
      </div>
      {policyError && <div className="sm:col-span-3"><Alert kind="error">{policyError}</Alert></div>}
      <FormField id="issue-policy" label="权益策略">
        <select
          id="issue-policy"
          className={inputClasses}
          required
          value={policyId}
          onChange={(e) => setForm({ ...form, policyId: e.target.value })}
        >
          {!policies?.length && <option value="">{policies ? '当前应用没有策略' : '正在加载策略…'}</option>}
          {policies?.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}（{p.maxSeats} 台设备）
            </option>
          ))}
        </select>
      </FormField>
      <FormField id="issue-expires" label="停用日期（北京时间）" hint={mode === 'offline_device_v2' ? '必填未来日期；所选日期北京时间 00:00 停用，不附加宽限期。' : '所选日期北京时间 00:00 停用。留空沿用策略期限，且仍适用策略宽限期。'}>
        <input
          id="issue-expires"
          type="date"
          required={mode === 'offline_device_v2'}
          className={inputClasses}
          value={form.expiresAt}
          onChange={(e) => setForm({ ...form, expiresAt: e.target.value })}
        />
      </FormField>
      <FormField id="issue-holder-name" label="客户名称">
        <input
          id="issue-holder-name"
          className={inputClasses}
          required
          value={form.holderName}
          onChange={(e) => setForm({ ...form, holderName: e.target.value })}
        />
      </FormField>
      <FormField id="issue-holder-email" label="客户邮箱">
        <input
          id="issue-holder-email"
          type="email"
          className={inputClasses}
          required
          value={form.holderEmail}
          onChange={(e) => setForm({ ...form, holderEmail: e.target.value })}
        />
      </FormField>
      {mode === 'legacy' && <FormField id="issue-external-ref" label="外部关联号" hint="可选，例如合同或订单编号">
        <input
          id="issue-external-ref"
          className={inputClasses}
          value={form.externalRef}
          onChange={(e) => setForm({ ...form, externalRef: e.target.value })}
        />
      </FormField>}
      <div className="flex items-end">
        <button type="submit" disabled={issuing || !policyId || !!policyError} className={buttonClasses}>
          {issuing ? '创建中…' : '创建授权'}
        </button>
      </div>
    </form>
  );
}
