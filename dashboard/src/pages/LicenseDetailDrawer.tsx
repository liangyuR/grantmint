import { useState } from 'react';
import { useProducts } from '../products/ProductContext';
import { useResource } from '../api/useResource';
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

  const { product } = useProducts();
  const { data, error: loadError, reload } = useResource<LicenseDetail>(keyId ? `/admin/licenses/${keyId}` : null);
  const wrongProduct = !!data && data.productId !== product?.id;
  const license = wrongProduct ? null : data;
  const offline = license?.mode === 'offline_device_v2';
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmingRevoke, setConfirmingRevoke] = useState(false);

  function close() {
    navigate('/licenses');
  }

  async function handleSuspend() {
    if (!keyId || !license) return;
    setBusy(true);
    setError(null);
    try {
      const reason = window.prompt('暂停原因（可选）：');
      if (reason === null) return;
      await api.post(`/admin/licenses/${keyId}/suspend`, reason ? { reason } : {});
      setMessage('授权已暂停。');
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '暂停授权失败。');
    } finally {
      setBusy(false);
    }
  }

  async function handleReinstate() {
    if (!keyId || !license) return;
    setBusy(true);
    setError(null);
    try {
      await api.post(`/admin/licenses/${keyId}/reinstate`);
      setMessage('授权已恢复。');
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '恢复授权失败。');
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke() {
    if (!keyId || !license) return;
    setBusy(true);
    setError(null);
    try {
      await api.delete(`/admin/licenses/${keyId}`, { reason: '通过管理控制台撤销' });
      setMessage('授权已撤销，无法恢复。');
      setConfirmingRevoke(false);
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '撤销授权失败。');
    } finally {
      setBusy(false);
    }
  }

  async function handleForceDeactivate(activationId: string) {
    if (!keyId || !license) return;
    if (!window.confirm('强制解绑此设备？此操作会释放设备名额。')) return;
    setBusy(true);
    setError(null);
    try {
      await api.delete(`/admin/licenses/${keyId}/activations/${activationId}`);
      setMessage('设备已解绑。');
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '解绑失败。');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`授权 ${keyId ?? ''} 详情`}
        className="h-full w-full max-w-xl overflow-y-auto border-l border-gray-800 bg-gray-950 p-6 shadow-2xl"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">授权 {keyId}</h2>
          <button
            type="button"
            onClick={close}
            className={secondaryButtonClasses}
            aria-label="关闭授权详情"
          >
            关闭
          </button>
        </div>

        <div className="mt-4 space-y-4">
          {(error || loadError || wrongProduct) && <Alert kind="error">{error || loadError || '此授权不属于当前应用。请关闭详情并选择正确应用。'}</Alert>}
          {message && <Alert kind="success">{message}</Alert>}

          {!license && !error && !loadError && !wrongProduct && <p className="text-sm text-gray-500">正在加载…</p>}

          {license && (
            <>
              {offline && <Alert kind="info">单设备离线授权：激活后无需周期联网或心跳。暂停或撤销仅阻止后续在线操作，已下载的证书仍可使用到原到期时间；本阶段不支持换机或续期重签。</Alert>}
              <div className="grid grid-cols-2 gap-3 rounded-lg border border-gray-800 bg-gray-900 p-4 text-sm">
                <div><dt className="text-xs uppercase text-gray-500">授权模式</dt><dd>{offline ? '单设备离线 v2' : '旧版兼容 v1'}</dd></div>
                {offline && <div><dt className="text-xs uppercase text-gray-500">修订 / 绑定版本</dt><dd>{license.revision} / {license.bindingVersion}</dd></div>}
                <div>
                  <dt className="text-xs uppercase text-gray-500">状态</dt>
                  <dd>
                    <StatusBadge status={license.status} />
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-gray-500">设备数</dt>
                  <dd className="text-gray-100">
                    {offline ? (license.devicePublicKey ? '已绑定一台设备' : '待首次联网激活') : `${license.activations.filter((a) => a.status === 'active').length}/${license.maxSeats}`}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-gray-500">客户</dt>
                  <dd className="text-gray-100">
                    {license.holderName} &lt;{license.holderEmail}&gt;
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-gray-500">创建时间</dt>
                  <dd className="text-gray-100">{new Date(license.issuedAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hourCycle: 'h23' })}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-gray-500">停用时间（北京时间）</dt>
                  <dd className="text-gray-100">
                    {license.expiresAt ? new Date(license.expiresAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hourCycle: 'h23' }) : '永久'}
                  </dd>
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <button type="button" className={secondaryButtonClasses} disabled={busy} onClick={() => void handleSuspend()}>
                  暂停授权
                </button>
                <button type="button" className={secondaryButtonClasses} disabled={busy} onClick={() => void handleReinstate()}>
                  恢复授权
                </button>
                <button
                  type="button"
                  className="rounded-md border border-red-900 px-3 py-1.5 text-sm font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-60"
                  disabled={busy}
                  onClick={() => setConfirmingRevoke(true)}
                >
                  撤销授权
                </button>
              </div>

              {license.signedToken ? <div>
                <h3 className="text-sm font-semibold text-gray-200">签名证书</h3>
                <div className="mt-1 flex gap-2">
                  <textarea readOnly rows={4} className={`${inputClasses} font-mono`} value={license.signedToken} />
                  <button
                    type="button"
                    className={secondaryButtonClasses}
                    onClick={() => void navigator.clipboard.writeText(license.signedToken!).catch(() => setError('复制失败，请手动复制证书。'))}
                  >
                    复制
                  </button>
                </div>
              </div> : <Alert kind="info">尚未签发设备证书。客户完成首次联网激活后，才可离线使用。激活秘密不会在详情中再次显示。</Alert>}

              {offline ? <div className="space-y-2 rounded-lg border border-gray-800 p-4 text-sm">
                <h3 className="font-semibold">绑定设备</h3>
                {license.devicePublicKey ? <>
                  <p className="break-all">设备公钥：<span className="font-mono">{license.devicePublicKey}</span></p>
                  <p className="break-all">指纹摘要：<span className="font-mono">{license.fingerprintHash}</span></p>
                  <p>指纹版本：{license.fingerprintVersion}</p>
                  <p>绑定不因心跳超时释放，不能通过旧版解绑接口更换设备。</p>
                </> : <p>尚未绑定设备。</p>}
              </div> : <div>
                <h3 className="text-sm font-semibold text-gray-200">激活设备</h3>
                <div className="mt-2 overflow-x-auto rounded-lg border border-gray-800">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-gray-900 text-xs uppercase tracking-wider text-gray-400">
                      <tr>
                        <th scope="col" className="px-3 py-2">设备指纹</th>
                        <th scope="col" className="px-3 py-2">设备名称</th>
                        <th scope="col" className="px-3 py-2">系统平台</th>
                        <th scope="col" className="px-3 py-2">状态</th>
                        <th scope="col" className="px-3 py-2">最近心跳</th>
                        <th scope="col" className="px-3 py-2">停用时间</th>
                        <th scope="col" className="px-3 py-2">
                          <span className="sr-only">操作</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {license.activations.length === 0 && (
                        <tr>
                          <td colSpan={7} className="px-3 py-4 text-center text-gray-500">
                            尚无激活设备。
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
                            {activation.lastHeartbeatAt ? new Date(activation.lastHeartbeatAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hourCycle: 'h23' }) : '无'}
                          </td>
                          <td className="px-3 py-2 text-gray-400">
                            {activation.deactivatedAt ? new Date(activation.deactivatedAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hourCycle: 'h23' }) : '—'}
                          </td>
                          <td className="px-3 py-2 text-right">
                            <button
                              type="button"
                              className="rounded-md border border-red-900 px-2.5 py-1 text-xs font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-60"
                              disabled={busy}
                              onClick={() => void handleForceDeactivate(activation.id)}
                              aria-label={`强制解绑 ${activation.fingerprint}`}
                            >
                              强制解绑
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>}
            </>
          )}
        </div>
      </div>

      {confirmingRevoke && (
        <ConfirmDialog
          title="撤销此授权？"
          description="撤销后无法恢复。在线校验将拒绝此授权，但已下载的离线证书仍可使用到原到期时间。"
          confirmLabel="撤销授权"
          danger
          busy={busy}
          onCancel={() => setConfirmingRevoke(false)}
          onConfirm={() => void handleRevoke()}
        />
      )}
    </div>
  );
}
