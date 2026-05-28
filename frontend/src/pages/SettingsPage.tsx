import { FormEvent, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'

export function SettingsPage() {
  const { repoId } = useParams()
  const [settings, setSettings] = useState<Record<string, unknown>>({})
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (!repoId) return
    api.repoSettings(repoId).then((data) => {
      const payload = data as { settings?: Record<string, unknown> }
      setSettings(payload.settings || {})
    })
  }, [repoId])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!repoId) return
    await api.updateSettings(repoId, settings)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div>
      <Link to="/" className="text-sm text-guard-accent hover:underline">← Repositories</Link>
      <h1 className="mt-4 text-2xl font-bold">Repository settings</h1>
      <form onSubmit={handleSubmit} className="card mt-6 max-w-xl space-y-4 p-6">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={Boolean(settings.block_on_critical)}
            onChange={(e) => setSettings({ ...settings, block_on_critical: e.target.checked })}
          />
          Block merge on Critical findings
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={Boolean(settings.block_on_high)}
            onChange={(e) => setSettings({ ...settings, block_on_high: e.target.checked })}
          />
          Block merge on High findings
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={Boolean(settings.inline_comments_enabled)}
            onChange={(e) => setSettings({ ...settings, inline_comments_enabled: e.target.checked })}
          />
          Enable inline PR comments
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={settings.ai_triage_enabled !== false}
            onChange={(e) => setSettings({ ...settings, ai_triage_enabled: e.target.checked })}
          />
          AI triage enabled
        </label>
        <button type="submit" className="rounded-lg bg-guard-accent px-4 py-2 text-sm font-medium text-guard-950">
          Save settings
        </button>
        {saved && <span className="text-sm text-emerald-400">Saved</span>}
      </form>
    </div>
  )
}
