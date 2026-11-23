import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { ProductProvider, useProducts } from '../products/ProductContext';
import Alert from './Alert';
import { inputClasses, secondaryButtonClasses } from './FormField';
import { useAuth } from '../auth/AuthContext';

const NAV_ITEMS = [
  { to: '/products', label: 'Products' },
  { to: '/policies', label: 'Policies' },
  { to: '/licenses', label: 'Licenses' },
  { to: '/demo', label: 'Demo' },
];

function navLinkClasses({ isActive }: { isActive: boolean }): string {
  return [
    'block rounded-md px-3 py-2 text-sm font-medium transition-colors',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-900',
    isActive ? 'bg-indigo-600 text-white' : 'text-gray-300 hover:bg-gray-800 hover:text-white',
  ].join(' ');
}

export default function Shell() {
  return <ProductProvider><ProductShell /></ProductProvider>;
}

function ProductShell() {
  const { admin, logout } = useAuth();
  const { products, product, loading, error, selectProduct, refreshProducts } = useProducts();
  const navigate = useNavigate();
  const location = useLocation();

  function changeProduct(id: string) {
    selectProduct(id);
    if (location.pathname.startsWith('/licenses/')) navigate('/licenses');
    if (location.pathname.startsWith('/products/')) navigate(`/products/${id}`);
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col sm:flex-row">
      <nav
        aria-label="Primary"
        className="sm:w-56 shrink-0 border-r border-gray-800 bg-gray-900 flex flex-col"
      >
        <div className="px-4 py-4 border-b border-gray-800">
          <span className="text-lg font-semibold tracking-tight text-white">Grantmint</span>
          <div className="text-xs font-medium text-indigo-300 uppercase tracking-wider">
            Operator Console
          </div>
        </div>
        <ul className="flex-1 space-y-1 p-3">
          {NAV_ITEMS.map((item) => (
            <li key={item.to}>
              <NavLink to={item.to} className={navLinkClasses}>
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="p-3 border-t border-gray-800 space-y-2">
          {admin && <p className="truncate px-1 text-xs text-gray-400">Signed in as {admin.username}</p>}
          <button
            type="button"
            onClick={() => void logout()}
            className="w-full rounded-md border border-gray-700 px-3 py-2 text-sm font-medium text-gray-200 hover:bg-gray-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
          >
            Log out
          </button>
        </div>
      </nav>
      <main className="flex-1 min-w-0 p-6">
        <div className="mb-6 space-y-3 border-b border-gray-800 pb-4">
          <div className="flex flex-wrap items-center gap-3">
            <label htmlFor="current-product" className="text-sm font-medium">Current product</label>
            <select id="current-product" className={`${inputClasses} max-w-sm`} value={product?.id ?? ''}
              disabled={loading || products.length === 0} onChange={(event) => changeProduct(event.target.value)}>
              {products.length === 0 && <option value="">{loading ? 'Loading products…' : 'No products'}</option>}
              {products.map((item) => <option key={item.id} value={item.id}>{item.name} ({item.slug})</option>)}
            </select>
            {product && <NavLink className={secondaryButtonClasses} to={`/products/${product.id}`}>Product details</NavLink>}
          </div>
          {product && <p className="break-all text-xs text-gray-400">Product ID: <span className="font-mono">{product.id}</span></p>}
          {error && <Alert kind="error">{error} <button type="button" className="underline" onClick={() => void refreshProducts()}>Retry</button></Alert>}
          {!loading && !error && products.length === 0 && <p className="text-sm text-gray-400">Create a product to manage its policies and licenses.</p>}
        </div>
        <div key={product?.id ?? 'no-product'}><Outlet /></div>
      </main>
    </div>
  );
}
