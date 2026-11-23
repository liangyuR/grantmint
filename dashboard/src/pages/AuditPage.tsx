import { useState } from 'react';
import { useProducts } from '../products/ProductContext';
import { useResource } from '../api/useResource';
import type { AuditEvent, Page } from '../api/types';
import Alert from '../components/Alert';
import { secondaryButtonClasses } from '../components/FormField';
import { beijingTime } from '../lib/format';
const actions: Record<string, string> = { 'application.created': '创建应用', 'application.updated': '更新应用', 'application.archived': '归档应用', 'license.created': '创建授权', 'license.activated': '激活设备', 'license.renewed': '合同续期', 'license.revoked': '撤销授权', 'license.acknowledged': '设备确认', 'signing_key.changed': '切换签名密钥' };
export default function AuditPage() {
  const { product } = useProducts();
  const [page, setPage] = useState(0);
  const { data, error } = useResource<Page<AuditEvent>>(product ? `/admin/v2/audit?applicationId=${product.id}&page=${page}&size=50` : null);
  return <div className="space-y-4"><h1 className="text-xl font-semibold">操作审计</h1><p className="text-sm text-gray-400">查看当前应用的授权和密钥变更；审计不包含激活秘密或私钥。</p>
    {error && <Alert kind="error">{error}</Alert>}
    {!data && !error && <p>{product ? '正在加载…' : '请先选择应用。'}</p>}
    {data?.content.length === 0 && <p className="text-gray-400">暂无审计记录。</p>}
    {data?.content.map((event) => <article key={event.id} className="space-y-2 rounded-lg border border-gray-800 p-4 text-sm"><div className="flex flex-wrap justify-between gap-2"><strong>{actions[event.action] || event.action}</strong><span>{beijingTime(event.createdAt)}</span></div><p>操作者：{event.actor === 'device' ? '客户设备' : event.actor}</p>{event.licenseId && <p>授权 ID：{event.licenseId}</p>}<pre className="overflow-auto text-gray-400">{JSON.stringify(event.detail, null, 2)}</pre></article>)}
    {data && data.totalElements > 0 && <div className="flex items-center gap-3"><button className={secondaryButtonClasses} disabled={page === 0} onClick={() => setPage(page - 1)}>上一页</button><span>第 {page + 1} / {Math.max(data.totalPages, 1)} 页</span><button className={secondaryButtonClasses} disabled={page + 1 >= data.totalPages} onClick={() => setPage(page + 1)}>下一页</button></div>}
  </div>;
}
