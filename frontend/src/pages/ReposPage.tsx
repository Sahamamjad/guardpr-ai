import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, PullRequestRow, Repository } from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

export function ReposPage() {
  const [repos, setRepos] = useState<Repository[]>([])
  const [selected, setSelected] = useState<Repository | null>(null)
  const [prs, setPrs] = useState<PullRequestRow[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    api.repos().then(setRepos).catch((e) => setError(e.message))
  }, [])

  useEffect(() => {
    if (!selected) return
    api.pullRequests(selected.id).then(setPrs).catch((e) => setError(e.message))
  }, [selected])

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Connected Repositories</h1>
        <p className="text-slate-400">GitHub App installations and PR scan history</p>
      </div>

      {error && <p className="mb-4 text-red-400">{error}</p>}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-3 lg:col-span-1">
          {repos.length === 0 && (
            <div className="card p-6 text-sm text-slate-400">
              No repositories yet. Install the GitHub App on a repo to begin scanning.
            </div>
          )}
          {repos.map((repo) => (
            <button
              key={repo.id}
              onClick={() => setSelected(repo)}
              className={`card w-full p-4 text-left transition ${selected?.id === repo.id ? 'border-guard-accent' : 'hover:border-slate-500'}`}
            >
              <div className="font-medium text-white">{repo.full_name}</div>
              <div className="mt-1 text-xs text-slate-400">
                Score: {repo.security_score ?? '—'} · Branch: {repo.default_branch}
              </div>
            </button>
          ))}
        </div>

        <div className="lg:col-span-2">
          {selected ? (
            <>
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-semibold">{selected.full_name} — Pull Requests</h2>
                <Link to={`/repos/${selected.id}/settings`} className="text-sm text-guard-accent hover:underline">
                  Settings
                </Link>
              </div>
              <div className="space-y-3">
                {prs.map((pr) => (
                  <div key={pr.id} className="card p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="font-medium text-white">
                          #{pr.pr_number} {pr.title}
                        </div>
                        <div className="text-xs text-slate-400">@{pr.author_login}</div>
                      </div>
                      {pr.latest_scan && (
                        <div className="text-right">
                          <SeverityBadge severity={pr.latest_scan.overall_risk || 'None'} />
                          <Link to={`/scans/${pr.latest_scan.id}`} className="mt-2 block text-sm text-guard-accent hover:underline">
                            View scan
                          </Link>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="card flex h-64 items-center justify-center text-slate-500">Select a repository</div>
          )}
        </div>
      </div>
    </div>
  )
}
