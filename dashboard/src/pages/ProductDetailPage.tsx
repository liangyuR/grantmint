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
  const { data: keys, error, reload } = useResource<SigningKey[]>(product ? `/admin/products/${product.id}/signing-keys` : null);

  useEffect(() => {
    if (product) selectProduct(product.id);
  }, [product, selectProduct]);

  if (!product) return <p className="text-gray-400">{loading ? 'Loading product…' : 'Product not found. Return to Products to choose an available product.'}</p>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">{product.name}</h1>
        <div className="flex gap-2">
          <Link className={secondaryButtonClasses} to="/policies">Manage policies</Link>
          <Link className={secondaryButtonClasses} to="/licenses">Manage licenses</Link>
        </div>
      </div>
      <dl className="grid gap-4 rounded-lg border border-gray-800 bg-gray-900 p-4 text-sm sm:grid-cols-2">
        <div><dt className="text-gray-400">Product ID</dt><dd className="break-all font-mono">{product.id}</dd></div>
        <div><dt className="text-gray-400">Slug</dt><dd className="font-mono">{product.slug}</dd></div>
        <div className="sm:col-span-2"><dt className="text-gray-400">Description</dt><dd>{product.description || 'No description'}</dd></div>
      </dl>
      <section className="space-y-3" aria-labelledby="signing-keys-heading">
        <h2 id="signing-keys-heading" className="font-semibold">Signing public keys</h2>
        <p className="text-sm text-gray-400">Registered key status is shown below. Active status does not identify the key currently used for issuance. Private keys are provisioned by the deployment operator.</p>
        {error && <Alert kind="error">{error} <button className="underline" type="button" onClick={reload}>Retry</button></Alert>}
        {!keys && !error && <p className="text-gray-400">Loading signing keys…</p>}
        {keys?.length === 0 && <Alert kind="info">No signing keys registered. Configure a signing key before issuing licenses for this product.</Alert>}
        {keys?.map((key) => (
          <div key={key.keyId} className="space-y-2 rounded-lg border border-gray-800 bg-gray-900 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono">{key.keyId}</span><span className="text-sm text-gray-300">{key.algorithm} · {key.status}</span></div>
            <p className="break-all font-mono text-xs text-gray-300">{key.publicKey}</p>
            <p className="text-xs text-gray-400">Registered: {new Date(key.createdAt).toLocaleString()}</p>
          </div>
        ))}
      </section>
    </div>
  );
}
