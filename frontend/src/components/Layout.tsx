import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import { clearToken } from '../api/client'

const nav = [
  { to: '/', label: 'Repositories' },
  { to: '/audit', label: 'Audit Log' },
]

export function Layout() {
  const navigate = useNavigate()

  function logout() {
    clearToken()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-guard-950">
      <header className="border-b border-guard-800 bg-guard-900/90">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4">
          <Link to="/" className="flex items-center gap-2 font-semibold text-guard-accent">
            <span className="text-xl">🛡️</span>
            GuardPR AI
          </Link>
          <nav className="flex items-center gap-6 text-sm text-slate-300">
            {nav.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => (isActive ? 'text-guard-accent' : 'hover:text-white')}
              >
                {item.label}
              </NavLink>
            ))}
            <button onClick={logout} className="rounded-lg border border-guard-700 px-3 py-1 hover:bg-guard-800">
              Logout
            </button>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-8">
        <Outlet />
      </main>
    </div>
  )
}
