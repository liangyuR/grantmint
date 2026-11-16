import { useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate, useParams, useOutletContext } from 'react-router-dom';
import { useProducts } from '../products/ProductContext';
import { useResource } from '../api/useResource';
import { api, ApiError } from '../api/client';
import type { LicenseDetail } from '../api/types';
import type { LicenseOutletContext } from './LicensesPage';
import Alert from '../components/Alert';
import StatusBadge from '../components/StatusBadge';
import FormField, { inputClasses, buttonClasses, secondaryButtonClasses } from '../components/FormField';
import { beijingTime, deliveryLabels, stopDate, warningTime } from '../lib/format';

export default function LicenseDetailDrawer() {
  const { licenseId } = useParams();
  const { refreshLicenses } = useOutletContext<LicenseOutletContext>();
  const { product } = useProducts();
  const navigate = useNavigate();
  const { data, error: loadError, reload } = useResource<LicenseDetail>(licenseId ? `/admin/v2/licenses/${licenseId}` : null);
  const [error, setError] = useState<string | null>(null);
  const [renewing, setRenewing] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const wrongProduct = !!data && data.applicationId !== product?.id;
  const license = wrongProduct ? null : data;
  function refreshAfterWrite() { reload(); refreshLicenses(); }
  async function revoke(event: FormEvent) {
    event.preventDefault(); if (!license) return;
    setBusy(true); setError(null);
    try { await api.post(`/admin/v2/licenses/${license.id}/revoke`, { reason }); setRevoking(false); refreshAfterWrite(); }
    catch (err) { setError(err instanceof ApiError ? err.message : '撤销失败，请重试。'); }
    finally { setBusy(false); }
  }
  return <div className="fixed inset-0 z-40 flex justify-end bg-black/60" onMouseDown={(event) => { if (event.currentTarget === event.target) navigate('/licenses'); }}>
    <section role="dialog" aria-modal="true" aria-label="授权详情" className="h-full w-full max-w-2xl overflow-y-auto border-l border-gray-800 bg-gray-950 p-6">
      <div className="flex items-center justify-between"><h2 className="text-xl font-semibold">授权详情</h2><button className={secondaryButtonClasses} onClick={() => navigate('/licenses')}>关闭详情</button></div>
      <div className="mt-4 space-y-4">
        {(error || loadError || wrongProduct) && <Alert kind="error">{error || loadError || '此授权不属于当前应用，请切换到正确应用。'}</Alert>}
        {!license && !wrongProduct && !loadError && <p>正在加载…</p>}
        {license && <>
          <Alert kind="info">首次激活后长期离线使用，无强制心跳。撤销仅禁止后续联网激活或同步，已下载证书仍可运行至其原到期时间。</Alert>
          <dl className="grid grid-cols-2 gap-4 rounded-lg border border-gray-800 p-4 text-sm">
            <div><dt className="text-gray-400">授权编号</dt><dd>{license.keyId}</dd></div>
            <div><dt className="text-gray-400">状态</dt><dd><StatusBadge status={license.status} /></dd></div>
            <div><dt className="text-gray-400">客户</dt><dd>{license.customer.name}<br />{license.customer.email}</dd></div>
            <div><dt className="text-gray-400">修订 / 绑定版本</dt><dd>{license.revision} / {license.bindingVersion}</dd></div>
            <div><dt className="text-gray-400">停用时间（北京时间）</dt><dd>{beijingTime(license.expiresAt)}</dd></div>
            <div><dt className="text-gray-400">提前七天提醒</dt><dd>{warningTime(license.expiresAt)}</dd></div>
            <div><dt className="text-gray-400">设备交付状态</dt><dd>{deliveryLabels[license.deliveryStatus]}</dd></div>
          </dl>
          <p className="text-sm text-gray-400">待领取 / 尚未确认表示客户端尚未确认新证书已验证保存；未领取时继续按旧证书到期时间停用。</p>
          {license.status !== 'revoked' && <div className="flex gap-3"><button className={buttonClasses} disabled={!!product?.archivedAt} onClick={() => { setRenewing(true); setRevoking(false); }}>续期</button><button className={secondaryButtonClasses} onClick={() => { setRevoking(true); setRenewing(false); }}>撤销授权</button></div>}
          {renewing && <RenewalForm key={license.revision} license={license} onCancel={() => setRenewing(false)} onSaved={() => { setRenewing(false); refreshAfterWrite(); }} />}
          {revoking && <form onSubmit={(event) => void revoke(event)} className="space-y-3 rounded-lg border border-red-900 p-4"><Alert kind="info">撤销不可恢复，不会即时使已有离线证书失效。</Alert><FormField id="revoke-reason" label="撤销原因"><input id="revoke-reason" required className={inputClasses} value={reason} onChange={(e) => setReason(e.target.value)} /></FormField><button className={buttonClasses} disabled={busy}>确认撤销</button><button type="button" className={secondaryButtonClasses} onClick={() => setRevoking(false)}>取消</button></form>}
          <section className="space-y-2 rounded-lg border border-gray-800 p-4 text-sm"><h3 className="font-semibold">绑定设备</h3>{license.devicePublicKey ? <><p className="break-all">设备公钥：{license.devicePublicKey}</p><p className="break-all">指纹摘要：{license.fingerprintHash}</p><p>指纹版本：{license.fingerprintVersion}</p></> : <p>尚未激活。激活秘密不会再次显示。</p>}</section>
          <section><h3 className="font-semibold">权益快照</h3><pre className="overflow-auto text-sm text-gray-400">{JSON.stringify(license.entitlements, null, 2)}</pre></section>
          <section className="space-y-2"><h3 className="font-semibold">续期记录</h3>{license.renewals?.length ? license.renewals.map((renewal) => <div className="rounded border border-gray-800 p-3 text-sm" key={renewal.id}><p>第 {renewal.revision} 版 · {renewal.confirmedAt ? `设备已确认：${beijingTime(renewal.confirmedAt)}` : '待领取 / 尚未确认'}</p><p>{beijingTime(renewal.oldExpiresAt)} → {beijingTime(renewal.newExpiresAt)}</p><p>{renewal.reason}</p></div>) : <p className="text-sm text-gray-400">暂无续期。</p>}</section>
        </>}
      </div>
    </section>
  </div>;
}
function RenewalForm({ license, onCancel, onSaved }: { license: LicenseDetail; onCancel: () => void; onSaved: () => void }) {
  const [date, setDate] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const request = useRef<{ signature: string; id: string } | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault(); setError(null);
    if (!date || new Date(stopDate(date)).getTime() <= Math.max(Date.now(), new Date(license.expiresAt).getTime())) { setError('新停用日期必须晚于当前期限和当前时间。'); return; }
    const body = { expectedRevision: license.revision, newExpiresAt: stopDate(date), reason };
    const signature = JSON.stringify(body);
    if (request.current?.signature !== signature) request.current = { signature, id: crypto.randomUUID() };
    setBusy(true);
    try { await api.post(`/admin/v2/licenses/${license.id}/renewals`, { ...body, idempotencyKey: request.current.id }); onSaved(); }
    catch (err) { setError(err instanceof ApiError ? err.message : '续期失败。同一内容重试会复用请求编号，避免重复续期。'); }
    finally { setBusy(false); }
  }
  return <form aria-label="续期授权" onSubmit={(event) => void submit(event)} className="space-y-3 rounded-lg border border-indigo-800 p-4">
    <h3 className="font-semibold">确认合同续期</h3><p className="text-sm text-gray-400">当前第 {license.revision} 版；续期后需客户联网领取并保存新证书。服务端成功不等于客户端生效。</p>
    {error && <Alert kind="error">{error}</Alert>}
    <FormField id="renew-date" label="新的停用日期（北京时间）"><input id="renew-date" type="date" required className={inputClasses} value={date} onChange={(e) => setDate(e.target.value)} /></FormField>
    <FormField id="renew-reason" label="续期原因"><input id="renew-reason" required className={inputClasses} value={reason} onChange={(e) => setReason(e.target.value)} /></FormField>
    {date && <p className="text-sm text-gray-400">停用：{beijingTime(stopDate(date))}；提醒：{warningTime(stopDate(date))}</p>}
    <div className="flex gap-3"><button className={buttonClasses} disabled={busy}>{busy ? '提交中…' : '确认续期'}</button><button type="button" className={secondaryButtonClasses} disabled={busy} onClick={onCancel}>取消</button></div>
  </form>;
}
