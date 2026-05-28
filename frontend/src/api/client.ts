const API_BASE = import.meta.env.VITE_API_URL || ''

function getToken(): string | null {
  return localStorage.getItem('guardpr_token')
}

export function setToken(token: string) {
  localStorage.setItem('guardpr_token', token)
}

export function clearToken() {
  localStorage.removeItem('guardpr_token')
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers })
  if (res.status === 401) {
    clearToken()
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.message || `Request failed: ${res.status}`)
  }
  if (res.headers.get('content-type')?.includes('application/json')) {
    return res.json()
  }
  return res as unknown as T
}

export const api = {
  login: (email: string, password: string) =>
    request<{ access_token: string }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
  register: (email: string, password: string) =>
    request('/api/v1/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) }),
  repos: () => request<Repository[]>('/api/v1/repos'),
  pullRequests: (repoId: string) => request<PullRequestRow[]>(`/api/v1/repos/${repoId}/pull-requests`),
  scan: (scanId: string) => request<ScanDetail>(`/api/v1/scans/${scanId}`),
  finding: (findingId: string) => request<FindingDetail>(`/api/v1/findings/${findingId}`),
  rerunScan: (scanId: string) => request(`/api/v1/scans/${scanId}/rerun`, { method: 'POST' }),
  auditLogs: () => request<AuditLog[]>('/api/v1/audit-logs'),
  repoSettings: (repoId: string) => request(`/api/v1/repos/${repoId}/settings`),
  updateSettings: (repoId: string, body: object) =>
    request(`/api/v1/repos/${repoId}/settings`, { method: 'POST', body: JSON.stringify(body) }),
  markFalsePositive: (findingId: string, reason?: string) =>
    request(`/api/v1/findings/${findingId}/false-positive`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  acceptRisk: (findingId: string, reason?: string) =>
    request(`/api/v1/findings/${findingId}/accept-risk`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  downloadReport: (scanId: string, format: 'json' | 'sarif' | 'pdf') =>
    downloadFile(
      format === 'sarif'
        ? `/api/v1/scans/${scanId}/sarif`
        : `/api/v1/scans/${scanId}/report?format=${format}`,
      `guardpr-${scanId}.${format === 'sarif' ? 'sarif.json' : format}`,
    ),
}

async function downloadFile(path: string, filename: string) {
  const token = getToken()
  if (!token) {
    window.location.href = '/login'
    return
  }
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.message || `Download failed: ${res.status}`)
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export interface Repository {
  id: string
  full_name: string
  default_branch: string
  security_score: number | null
  last_scan_at: string | null
}

export interface PullRequestRow {
  id: string
  pr_number: number
  title: string
  author_login: string
  state: string
  github_url: string
  latest_scan: {
    id: string
    status: string
    overall_risk: string
    findings_count: Record<string, number>
    created_at: string
  } | null
}

export interface FindingDetail {
  id: string
  scan_id: string
  scanner_name: string
  severity: string
  title: string
  file_path: string
  line_start: number
  owasp_category: string
  description: string
  remediation: string
  secure_code_example: string
  status: string
  exploitability_score: number
  ai_triage: Record<string, unknown> | null
}

export interface ScanDetail {
  id: string
  status: string
  overall_risk: string
  overall_risk_score: number
  findings_count: Record<string, number>
  findings: FindingDetail[]
  pull_request: { pr_number: number; title: string; github_url: string }
}

export interface AuditLog {
  id: string
  action: string
  actor_type: string
  resource_type: string
  metadata: Record<string, unknown>
  created_at: string
}
