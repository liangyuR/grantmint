import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link, Outlet } from 'react-router-dom';
import { useProducts } from '../products/ProductContext';
import { useResource } from '../api/useResource';
import { api } from '../api/client';
import type { CreateOfflineLicenseResponse, Entitlements, LicenseDetail, Page } from '../api/types';
import Alert from '../components/Alert';
import StatusBadge from '../components/StatusBadge';
import FormField, { buttonClasses, inputClasses, secondaryButtonClasses } from '../components/FormField';
import { beijingTime, deliveryLabels, stopDate, warningTime } from '../lib/format';

export interface LicenseOutletContext { refreshLicenses: () => void }

export default function LicensesPage() {
  const { product } = useProducts();
  const [page, setPage] = useState(0);
  const [showCreate, setShowCreate] = useState(false);
  const { data, error, reload } = useResource<Page<LicenseDetail>>(product ? `/admin/v2/licenses?applicationId=${product.id}&page=${page}&size=50` : null);
  return <div className="space-y-6">
    <div className="flex items-center justify-between"><h1 className="text-xl font-semibold">授权管理</h1>
      <button className={buttonClasses} disabled={!product || !!product.archivedAt} onClick={() => setShowCreate(!showCreate)}>{showCreate ? '关闭创建' : '创建授权'}</button></div>
    {product?.archivedAt && <Alert kind="info">应用已归档，不能创建新授权。</Alert>}
    {error && <Alert kind="error">{error}</Alert>}
    {showCreate && product && <CreateLicense applicationId={product.id} onCreated={reload} />}
    <p className="text-sm text-gray-400">固定单设备，首次激活后可离线使用至合同到期。后台撤销不能即时停止已有离线证书。</p>
    <div className="overflow-auto rounded-lg border border-gray-800"><table className="w-full text-left text-sm">
      <thead className="bg-gray-900 text-gray-400"><tr>{['授权编号', '客户', '状态', '修订 / 交付', '停用时间（北京时间）'].map((name) => <th className="p-3" key={name}>{name}</th>)}</tr></thead>
      <tbody className="divide-y divide-gray-800">{data?.content.map((license) => <tr key={license.id}>
        <td className="p-3"><Link className="font-mono text-indigo-300 underline" to={`/licenses/${license.id}`}>{license.keyId}</Link></td>
        <td className="p-3">{license.customer.name}<div className="text-gray-400">{license.customer.email}</div></td>
        <td className="p-3"><StatusBadge status={license.status} /></td>
        <td className="p-3">第 {license.revision} 版<div>{deliveryLabels[license.deliveryStatus]}</div></td>
        <td className="p-3">{beijingTime(license.expiresAt)}</td>
      </tr>)}</tbody></table>
      {!data && !error && <p className="p-4 text-gray-400">{product ? '正在加载…' : '请先选择或创建应用。'}</p>}
      {data?.content.length === 0 && <p className="p-4 text-gray-400">此应用尚无授权。</p>}
    </div>
    {data && data.totalElements > 0 && <div className="flex items-center gap-3 text-sm"><button className={secondaryButtonClasses} disabled={page === 0} onClick={() => setPage(page - 1)}>上一页</button><span>第 {page + 1} / {Math.max(data.totalPages, 1)} 页，共 {data.totalElements} 条</span><button className={secondaryButtonClasses} disabled={page + 1 >= data.totalPages} onClick={() => setPage(page + 1)}>下一页</button></div>}
    <Outlet context={{ refreshLicenses: reload } satisfies LicenseOutletContext} />
  </div>;
}

function CreateLicense({ applicationId, onCreated }: { applicationId: string; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [date, setDate] = useState('');
  const [entitlements, setEntitlements] = useState('{}');
  const [issued, setIssued] = useState<CreateOfflineLicenseResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault(); setError(null);
    try {
      if (!date || new Date(stopDate(date)).getTime() <= Date.now()) throw new Error('必须填写未来的停用日期。');
      let rights: Entitlements;
      try { rights = JSON.parse(entitlements); } catch { throw new Error('权益必须是有效的 JSON 对象。'); }
      if (!rights || Array.isArray(rights) || typeof rights !== 'object' || Object.values(rights).some((v) => !['boolean', 'string', 'number'].includes(typeof v) || (typeof v === 'number' && !Number.isSafeInteger(v)))) throw new Error('权益仅允许布尔、文本或安全范围整数。');
      setBusy(true);
      const result = await api.post<CreateOfflineLicenseResponse>('/admin/v2/licenses', { applicationId, customer: { name, email }, expiresAt: stopDate(date), entitlements: rights });
      setIssued(result); onCreated();
    } catch (err) { setError(err instanceof Error ? err.message : '创建失败。'); } finally { setBusy(false); }
  }
  async function copy(value: string) {
    try { await navigator.clipboard.writeText(value); } catch { setError('复制失败，请手动选择文本复制。'); }
  }
  if (issued) return <section className="space-y-3 rounded-lg border border-emerald-800 bg-emerald-950/30 p-4">
    <Alert kind="success">授权已创建，等待客户设备首次联网激活。</Alert>
    <Alert kind="info">激活秘密仅本次显示，关闭后无法找回。请安全保存并通过可信渠道交付客户；它不是运行证书，不能写入日志或公开链接。</Alert>
    <p>应用 ID：{applicationId}</p><p>授权 ID：{issued.licenseId || issued.id}</p><p>授权编号：{issued.keyId}</p>
    <FormField id="activation-secret" label="一次性激活秘密"><textarea id="activation-secret" className={`${inputClasses} font-mono`} readOnly value={issued.activationSecret} /></FormField>
    <button className={secondaryButtonClasses} onClick={() => void copy(issued.activationSecret)}>复制激活秘密</button>
    {error && <Alert kind="error">{error}</Alert>}
  </section>;
  return <form onSubmit={(event) => void submit(event)} className="grid gap-4 rounded-lg border border-gray-800 bg-gray-900 p-4 sm:grid-cols-2">
    {error && <div className="sm:col-span-2"><Alert kind="error">{error}</Alert></div>}
    <FormField id="customer-name" label="客户名称"><input id="customer-name" className={inputClasses} required value={name} onChange={(e) => setName(e.target.value)} /></FormField>
    <FormField id="customer-email" label="客户邮箱"><input id="customer-email" type="email" className={inputClasses} required value={email} onChange={(e) => setEmail(e.target.value)} /></FormField>
    <FormField id="stop-date" label="停用日期（北京时间）" hint="所选日期 00:00 停用，无宽限期。若约定12月底前可用，请选择次年1月1日。"><input id="stop-date" type="date" className={inputClasses} required value={date} onChange={(e) => setDate(e.target.value)} /></FormField>
    <FormField id="rights" label="权益（JSON）" hint="可留空对象；仅布尔、文本和安全范围整数。"><textarea id="rights" className={inputClasses} value={entitlements} onChange={(e) => setEntitlements(e.target.value)} /></FormField>
    {date && <p className="sm:col-span-2 text-sm text-gray-400">停用：{beijingTime(stopDate(date))}；提前七天提醒：{warningTime(stopDate(date))}（客户软件运行时显示）。</p>}
    <button className={buttonClasses} disabled={busy}>{busy ? '创建中…' : '确认创建'}</button>
  </form>;
}
