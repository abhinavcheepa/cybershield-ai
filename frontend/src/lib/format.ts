import type { EventStatus, Severity } from './types'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#facc15',
  low: '#38bdf8',
  info: '#64748b',
}

/** Tailwind classes for a severity chip: text, border and background together. */
export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'text-severity-critical border-severity-critical/40 bg-severity-critical/10',
  high: 'text-severity-high border-severity-high/40 bg-severity-high/10',
  medium: 'text-severity-medium border-severity-medium/40 bg-severity-medium/10',
  low: 'text-severity-low border-severity-low/40 bg-severity-low/10',
  info: 'text-severity-info border-severity-info/40 bg-severity-info/10',
}

export const STATUS_CLASS: Record<EventStatus, string> = {
  active: 'text-severity-critical border-severity-critical/40 bg-severity-critical/10',
  investigating: 'text-severity-medium border-severity-medium/40 bg-severity-medium/10',
  mitigated: 'text-severity-low border-severity-low/40 bg-severity-low/10',
  resolved: 'text-emerald-400 border-emerald-400/40 bg-emerald-400/10',
  false_positive: 'text-slate-400 border-slate-500/40 bg-slate-500/10',
}

export const STATUS_LABEL: Record<EventStatus, string> = {
  active: 'Active',
  investigating: 'Investigating',
  mitigated: 'Mitigated',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

export function timeAgo(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 10) return 'just now'
  if (seconds < 60) return `${Math.floor(seconds)}s ago`
  const minutes = seconds / 60
  if (minutes < 60) return `${Math.floor(minutes)}m ago`
  const hours = minutes / 60
  if (hours < 24) return `${Math.floor(hours)}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export function clockTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function fullTimestamp(iso: string): string {
  return new Date(iso).toLocaleString([], {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function compactNumber(value: number): string {
  if (value < 1000) return String(value)
  if (value < 1_000_000) return `${(value / 1000).toFixed(value < 10_000 ? 1 : 0)}K`
  return `${(value / 1_000_000).toFixed(1)}M`
}

export function formatBytes(bytes: number): string {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const exponent = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)))
  return `${(bytes / 1024 ** exponent).toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`
}

/** ISO-2 country code to its regional-indicator flag emoji. */
export function countryFlag(code: string): string {
  if (!code || code.length !== 2) return '🏴'
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)))
}

export function scoreTone(score: number): string {
  if (score >= 85) return 'text-severity-critical'
  if (score >= 65) return 'text-severity-high'
  if (score >= 40) return 'text-severity-medium'
  return 'text-severity-low'
}
