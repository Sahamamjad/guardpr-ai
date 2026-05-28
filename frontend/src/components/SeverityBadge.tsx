interface Props {
  severity: string
  className?: string
}

const map: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-low',
}

export function SeverityBadge({ severity, className = '' }: Props) {
  const key = severity?.toLowerCase() || 'medium'
  return <span className={`${map[key] || 'badge-medium'} ${className}`}>{severity}</span>
}
