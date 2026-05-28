import { FormEvent, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, setToken } from '../api/client'

export function LoginPage() {
  const [email, setEmail] = useState('admin@guardpr.local')
  const [password, setPassword] = useState('admin123')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const { access_token } = await api.login(email, password)
      setToken(access_token)
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-guard-950 px-4">
      <div className="card w-full max-w-md p-8">
        <h1 className="mb-2 text-2xl font-bold text-white">GuardPR AI</h1>
        <p className="mb-6 text-sm text-slate-400">AI Security Code Review Bot — Dashboard</p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm text-slate-400">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-lg border border-guard-700 bg-guard-950 px-3 py-2 text-white outline-none focus:border-guard-accent"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-sm text-slate-400">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-guard-700 bg-guard-950 px-3 py-2 text-white outline-none focus:border-guard-accent"
              required
            />
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-guard-accent py-2.5 font-medium text-guard-950 hover:opacity-90 disabled:opacity-50"
          >
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <p className="mt-4 text-xs text-slate-500">Demo: admin@guardpr.local / admin123 (after seed)</p>
      </div>
    </div>
  )
}
