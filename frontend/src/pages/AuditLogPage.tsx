import { useEffect, useState } from 'react'
import { api, AuditLog } from '../api/client'

export function AuditLogPage() {
  const [logs, setLogs] = useState<AuditLog[]>([])

  useEffect(() => {
    api.auditLogs().then(setLogs)
  }, [])

  return (
    <div>
      <h1 className="mb-6 text-2xl font-bold text-white">Audit Log</h1>
      <div className="card overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-guard-700 bg-guard-900/50 text-slate-400">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Resource</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id} className="border-b border-guard-800/50">
                <td className="px-4 py-3 text-slate-400">{new Date(log.created_at).toLocaleString()}</td>
                <td className="px-4 py-3 font-mono text-xs">{log.action}</td>
                <td className="px-4 py-3">{log.actor_type}</td>
                <td className="px-4 py-3 text-slate-400">{log.resource_type}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {logs.length === 0 && <p className="p-6 text-slate-500">No audit events yet.</p>}
      </div>
    </div>
  )
}
