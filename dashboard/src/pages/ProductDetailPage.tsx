import { useEffect } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useProducts } from '../products/ProductContext';
import { useResource } from '../api/useResource';
import type { SigningKey } from '../api/types';
import Alert from '../components/Alert';
import { secondaryButtonClasses } from '../components/FormField';

export default function ProductDetailPage() {
  const { productId } = useParams<{ productId: string }>();
  const { products, loading, selectProduct } = useProducts();
  const product = products.find((item) => item.id === productId);
  const { data: keys, error, reload } = useResource<SigningKey[]>(product ? `/admin/v2/applications/${product.id}/keys` : null);

  useEffect(() => {
    if (product) selectProduct(product.id);
  }, [product, selectProduct]);

  if (!product) return <p className="text-gray-400">{loading ? '正在加载应用…' : '应用不存在，请返回应用管理选择有效应用。'}</p>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">{product.name}</h1>
        <div className="flex gap-2">
          <Link className={secondaryButtonClasses} to="/licenses">管理授权</Link>
        </div>
      </div>
      <dl className="grid gap-4 rounded-lg border border-gray-800 bg-gray-900 p-4 text-sm sm:grid-cols-2">
        <div><dt className="text-gray-400">应用 ID</dt><dd className="break-all font-mono">{product.id}</dd></div>
        <div><dt className="text-gray-400">应用标识</dt><dd className="font-mono">{product.slug}</dd></div>
        <div className="sm:col-span-2"><dt className="text-gray-400">说明</dt><dd>{product.description || '暂无说明'}</dd></div>
      </dl>
      <section className="space-y-3" aria-labelledby="signing-keys-heading">
        <h2 id="signing-keys-heading" className="font-semibold">签名公钥</h2>
        <p className="text-sm text-gray-400">下方为部署配置的公钥；轮换前须先让客户端信任新公钥。私钥只由部署人员配置，不通过页面上传。</p>
        {error && <Alert kind="error">{error} <button className="underline" type="button" onClick={reload}>重试</button></Alert>}
        {!keys && !error && <p className="text-gray-400">正在加载签名公钥…</p>}
        {keys?.length === 0 && <Alert kind="info">尚未注册签名密钥。签发该应用的授权前，请先配置签名密钥。</Alert>}
        {keys?.map((key) => (
          <div key={key.keyId} className="space-y-2 rounded-lg border border-gray-800 bg-gray-900 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono">{key.keyId}</span><span className="text-sm text-gray-300">Ed25519 · {key.active ? '当前签发密钥' : '保留公钥'}</span></div>
            <p className="break-all font-mono text-xs text-gray-300">{key.publicKey}</p>
          </div>
        ))}
      </section>
    </div>
  );
}
