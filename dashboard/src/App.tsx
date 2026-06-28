export default function App() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col">
      <header className="border-b border-gray-800 bg-gray-900 px-6 py-4 flex items-center gap-3">
        <span className="text-lg font-semibold tracking-tight text-white">
          Grantmint
        </span>
        <span className="text-xs font-medium px-2 py-0.5 rounded bg-indigo-600 text-indigo-100 uppercase tracking-wider">
          Operator Console
        </span>
      </header>
      <main className="flex-1 flex items-center justify-center px-6">
        <div className="text-center space-y-3">
          <h1 className="text-3xl font-bold text-white">
            Grantmint
          </h1>
          <p className="text-gray-400 text-sm max-w-sm">
            Self-hostable license &amp; entitlement server &mdash; operator console
          </p>
        </div>
      </main>
    </div>
  )
}
