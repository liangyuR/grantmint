import { NavLink, Outlet } from 'react-router-dom';
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
  const { admin, logout } = useAuth();

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex">
      <nav
        aria-label="Primary"
        className="w-56 shrink-0 border-r border-gray-800 bg-gray-900 flex flex-col"
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
        <Outlet />
      </main>
    </div>
  );
}
