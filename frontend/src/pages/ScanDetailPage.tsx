import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, ScanDetail } from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

export function ScanDetailPage() {
  const { scanId } = useParams()
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [error, setError] = useState('')
  const [exportError, setExportError] = useState('')

  useEffect(() => {
    if (!scanId) return
    api.scan(scanId).then(setScan).catch((e) => setError(e.message))
  }, [scanId])

  async function handleExport(format: 'json' | 'sarif') {
    if (!scanId) return
    setExportError('')
    try {
      await api.downloadReport(scanId, format)
    } catch (e) {
      setExportError(e instanceof Error ? e.message : 'Export failed')
    }
  }

  if (error) return <p className="text-red-400">{error}</p>
  if (!scan) return <p className="text-slate-400">Loading scan…</p>

  const counts = scan.findings_count || {}

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <Link to="/" className="text-sm text-guard-accent hover:underline">← Repositories</Link>
          <h1 className="mt-2 text-2xl font-bold text-white">
            PR #{scan.pull_request?.pr_number} — Security Scan
          </h1>
          <p className="text-slate-400">{scan.pull_request?.title}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => scanId && api.rerunScan(scanId)} className="rounded-lg border border-guard-700 px-4 py-2 text-sm hover:bg-guard-800">
            Re-run scan
          </button>
          <button onClick={() => handleExport('json')} className="rounded-lg bg-guard-accent px-4 py-2 text-sm font-medium text-guard-950">
            Export JSON
          </button>
          <button onClick={() => handleExport('sarif')} className="rounded-lg border border-guard-accent px-4 py-2 text-sm text-guard-accent">
            Export SARIF
          </button>
        </div>
      </div>
      {exportError && <p className="mb-4 text-sm text-red-400">{exportError}</p>}

      <div className="mb-8 grid gap-4 sm:grid-cols-4">
        <div className="card p-4">
          <div className="text-xs text-slate-400">Overall risk</div>
          <div className="mt-1"><SeverityBadge severity={scan.overall_risk || 'None'} /></div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-slate-400">Risk score</div>
          <div className="mt-1 text-2xl font-bold">{scan.overall_risk_score ?? '—'}</div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-slate-400">Status</div>
          <div className="mt-1 capitalize">{scan.status}</div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-slate-400">Findings</div>
          <div className="mt-1 text-sm">
            H:{counts.high || 0} M:{counts.medium || 0} L:{counts.low || 0}
          </div>
        </div>
      </div>

      <h2 className="mb-4 text-lg font-semibold">Findings</h2>
      <div className="space-y-3">
        {scan.findings.map((f) => (
          <Link key={f.id} to={`/findings/${f.id}`} className="card block p-4 hover:border-guard-accent">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="font-medium text-white">{f.title}</div>
                <div className="mt-1 font-mono text-xs text-slate-400">
                  {f.file_path}:{f.line_start}
                </div>
                <div className="mt-1 text-xs text-slate-500">{f.scanner_name} · {f.owasp_category}</div>
              </div>
              <SeverityBadge severity={f.severity} />
            </div>
          </Link>
        ))}
        {scan.findings.length === 0 && <div className="card p-6 text-slate-400">No findings in this scan.</div>}
      </div>
    </div>
  )
}
