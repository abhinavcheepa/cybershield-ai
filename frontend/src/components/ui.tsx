import { motion } from 'framer-motion'
import { AlertTriangle, Loader2 } from 'lucide-react'
import type { ReactNode } from 'react'

import { SEVERITY_CLASS, STATUS_CLASS, STATUS_LABEL } from '../lib/format'
import type { EventStatus, Severity } from '../lib/types'

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}

/** Glass panel with an optional header row. */
export function Panel({
  title,
  subtitle,
  action,
  children,
  className,
  bodyClassName,
}: {
  title?: string
  subtitle?: string
  action?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={cx('glass flex flex-col overflow-hidden', className)}>
      {title && (
        <header className="flex items-start justify-between gap-3 border-b border-hairline px-4 py-3">
          <div className="min-w-0">
            <h2 className="panel-title">{title}</h2>
            {subtitle && <p className="mt-0.5 truncate text-xs text-slate-500">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={cx('flex-1', bodyClassName ?? 'p-4')}>{children}</div>
    </section>
  )
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return <span className={cx('chip', SEVERITY_CLASS[severity], className)}>{severity}</span>
}

export function StatusBadge({ status }: { status: EventStatus }) {
  return <span className={cx('chip', STATUS_CLASS[status])}>{STATUS_LABEL[status]}</span>
}

/** Live/offline indicator with a pulsing ring while connected. */
export function ConnectionDot({ connected }: { connected: boolean }) {
  return (
    <span className="relative flex h-2 w-2" aria-hidden>
      {connected && (
        <span className="absolute inline-flex h-full w-full animate-pulse-ring rounded-full bg-emerald-400" />
      )}
      <span
        className={cx(
          'relative inline-flex h-2 w-2 rounded-full',
          connected ? 'bg-emerald-400' : 'bg-slate-600',
        )}
      />
    </span>
  )
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-slate-500">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
      <span>{label}…</span>
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-col items-center gap-3 rounded-md border border-severity-critical/30 bg-severity-critical/5 px-4 py-8 text-center"
    >
      <AlertTriangle className="h-5 w-5 text-severity-critical" aria-hidden />
      <p className="text-sm text-slate-300">{message}</p>
      {onRetry && (
        <button type="button" className="btn" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  )
}

export function EmptyState({ message }: { message: string }) {
  return <p className="py-10 text-center text-sm text-slate-500">{message}</p>
}

/** Headline metric tile. `trend` is a signed percentage. */
export function StatCard({
  label,
  value,
  icon,
  trend,
  hint,
  tone = 'text-white',
  delay = 0,
}: {
  label: string
  value: string | number
  icon: ReactNode
  trend?: number
  hint?: string
  tone?: string
  delay?: number
}) {
  const rising = (trend ?? 0) >= 0
  return (
    <motion.article
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay, ease: 'easeOut' }}
      className="glass group relative overflow-hidden p-4"
    >
      {/* Slow highlight sweep — signals "live" without animating the number. */}
      <div className="pointer-events-none absolute inset-y-0 -left-1/3 w-1/3 bg-gradient-to-r from-transparent via-white/[0.045] to-transparent opacity-0 transition-opacity duration-300 group-hover:animate-sweep group-hover:opacity-100" />
      <div className="flex items-start justify-between">
        <p className="panel-title">{label}</p>
        <span className="text-slate-500 transition-colors group-hover:text-accent">{icon}</span>
      </div>
      <p className={cx('metric mt-3', tone)}>{value}</p>
      <div className="mt-1.5 flex items-center gap-2 text-xs">
        {trend !== undefined && (
          <span className={rising ? 'text-severity-critical' : 'text-emerald-400'}>
            {rising ? '▲' : '▼'} {Math.abs(trend).toFixed(0)}%
          </span>
        )}
        {hint && <span className="truncate text-slate-500">{hint}</span>}
      </div>
    </motion.article>
  )
}

/** Horizontal ranking bar used by the "top N" widgets. */
export function RankBar({
  name,
  count,
  max,
  extra,
  href,
  color = '#22d3ee',
}: {
  name: string
  count: number
  max: number
  extra?: string
  href?: string
  color?: string
}) {
  const pct = max > 0 ? Math.max(4, (count / max) * 100) : 0
  const body = (
    <>
      <div className="flex items-baseline justify-between gap-3">
        <span className="truncate text-[13px] text-slate-200">{name}</span>
        <span className="data shrink-0 text-slate-400">{count}</span>
      </div>
      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-white/5">
        <div
          className="h-full rounded-full transition-[width] duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      {extra && <p className="mt-1 truncate text-[11px] text-slate-500">{extra}</p>}
    </>
  )

  return href ? (
    <a href={href} className="block rounded px-1 py-1.5 row-hover">
      {body}
    </a>
  ) : (
    <div className="px-1 py-1.5">{body}</div>
  )
}
