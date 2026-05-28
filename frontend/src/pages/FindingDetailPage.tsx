import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, FindingDetail } from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

export function FindingDetailPage() {
  const { findingId } = useParams()
  const [finding, setFinding] = useState<FindingDetail | null>(null)

  useEffect(() => {
    if (!findingId) return
    api.finding(findingId).then(setFinding)
  }, [findingId])

  if (!finding) return <p className="text-slate-400">Loading…</p>

  const ai = finding.ai_triage || {}

  return (
    <div>
      <Link to={`/scans/${finding.scan_id}`} className="text-sm text-guard-accent hover:underline">← Back to scan</Link>
      <div className="mt-4 flex items-start justify-between gap-4">
        <h1 className="text-2xl font-bold text-white">{finding.title}</h1>
        <SeverityBadge severity={finding.severity} />
      </div>
      <p className="mt-2 font-mono text-sm text-slate-400">{finding.file_path}:{finding.line_start}</p>

      <div className="mt-8 grid gap-6 lg:grid-cols-2">
        <div className="card p-6">
          <h2 className="mb-3 font-semibold text-guard-accent">Technical explanation</h2>
          <p className="text-sm leading-relaxed text-slate-300">{finding.description}</p>
          <dl className="mt-4 grid grid-cols-2 gap-2 text-sm">
            <dt className="text-slate-500">OWASP</dt>
            <dd>{finding.owasp_category}</dd>
            <dt className="text-slate-500">Exploitability</dt>
            <dd>{finding.exploitability_score}/10</dd>
            <dt className="text-slate-500">Scanner</dt>
            <dd>{finding.scanner_name}</dd>
            <dt className="text-slate-500">Status</dt>
            <dd className="capitalize">{finding.status}</dd>
          </dl>
        </div>

        <div className="card p-6">
          <h2 className="mb-3 font-semibold text-guard-accent">Remediation</h2>
          <p className="text-sm text-slate-300">{finding.remediation}</p>
          {finding.secure_code_example && (
            <pre className="mt-4 overflow-x-auto rounded-lg bg-guard-950 p-4 font-mono text-xs text-emerald-300">
              {finding.secure_code_example}
            </pre>
          )}
        </div>
      </div>

      {ai && (
        <div className="card mt-6 p-6">
          <h2 className="mb-3 font-semibold">AI triage</h2>
          <p className="text-sm text-slate-300">{String(ai.business_impact || '')}</p>
          <p className="mt-2 text-sm text-slate-400">{String(ai.developer_comment || '')}</p>
        </div>
      )}

      <div className="mt-6 flex gap-3">
        <button
          onClick={() => findingId && api.markFalsePositive(findingId, 'Manual review')}
          className="rounded-lg border border-guard-700 px-4 py-2 text-sm hover:bg-guard-800"
        >
          Mark false positive
        </button>
        <button
          onClick={() => findingId && api.acceptRisk(findingId, 'Accepted by reviewer')}
          className="rounded-lg border border-amber-600/50 px-4 py-2 text-sm text-amber-300 hover:bg-amber-950/30"
        >
          Accept risk
        </button>
      </div>
    </div>
  )
}
