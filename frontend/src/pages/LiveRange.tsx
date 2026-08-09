import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Crosshair, Loader2, Play, Radio, Skull, Square, Target } from 'lucide-react'
import { useEffect, useState } from 'react'

import { EmptyState, Panel, Spinner, cx } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { useLive } from '../lib/ws'

const RATES = [
  { label: 'Gentle', value: 30 },
  { label: 'Steady', value: 90 },
  { label: 'Heavy', value: 240 },
]

export default function LiveRange() {
  const { atLeast } = useAuth()
  const canAttack = atLeast('analyst')
  const queryClient = useQueryClient()
  useLive() // keep the shared socket alive for dashboard cross-updates

  const catalog = useQuery({ queryKey: ['live-catalog'], queryFn: api.liveCatalog, refetchInterval: 5000 })
  const state = useQuery({ queryKey: ['live-state'], queryFn: api.liveState, refetchInterval: 3000 })

  const [attacks, setAttacks] = useState<string[]>([])
  const [target, setTarget] = useState('all')
  const [rate, setRate] = useState(90)

  // Default to all attack types once the catalog loads.
  useEffect(() => {
    if (catalog.data && attacks.length === 0) setAttacks(catalog.data.attacks.map((a) => a.key))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalog.data])

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['live-state'] })
    queryClient.invalidateQueries({ queryKey: ['live-catalog'] })
  }
  const start = useMutation({
    mutationFn: () =>
      api.liveStart({ attacks, target_username: target, attacks_per_minute: rate, repeat: true }),
    onSuccess: refresh,
  })
  const stop = useMutation({ mutationFn: api.liveStop, onSuccess: refresh })
  const busy = start.isPending || stop.isPending
  const running = state.data?.status === 'running'

  const toggle = (key: string) =>
    setAttacks((current) => (current.includes(key) ? current.filter((k) => k !== key) : [...current, key]))

  if (catalog.isLoading) return <Spinner label="Loading attack range" />

  const targets = catalog.data?.targets ?? []

  return (
    <div className="space-y-5">
      <p className="flex items-start gap-2.5 rounded-md border border-severity-critical/30 bg-severity-critical/5 px-4 py-3 text-xs leading-relaxed text-slate-300">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-severity-critical" aria-hidden />
        <span>
          <strong className="text-severity-critical">Real attacks.</strong> These fire genuine SQL injection,
          XSS, brute-force and traversal at the student practice site — students see their own pages get
          defaced and breached. The target is locked to{' '}
          <code className="rounded bg-black/40 px-1 py-0.5 font-mono text-[11px] text-accent">
            {catalog.data?.target_base_url}
          </code>{' '}
          and cannot be pointed anywhere else.
        </span>
      </p>

      <div className="grid gap-5 xl:grid-cols-[1.3fr_1fr]">
        <div className="space-y-5">
          <Panel
            title="Control"
            subtitle={
              running
                ? `Running · ${state.data?.requests_sent ?? 0} real requests sent`
                : 'Stopped'
            }
            action={
              <span className="flex items-center gap-2 text-[11px]">
                <Radio className={cx('h-3.5 w-3.5', running ? 'animate-pulse text-severity-critical' : 'text-slate-500')} aria-hidden />
                <span className={cx('uppercase tracking-wider', running ? 'text-severity-critical' : 'text-slate-500')}>
                  {state.data?.status ?? 'stopped'}
                </span>
              </span>
            }
          >
            {!canAttack ? (
              <EmptyState message="Launching attacks requires the analyst role." />
            ) : (
              <>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => start.mutate()}
                    disabled={busy || attacks.length === 0}
                  >
                    {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Play className="h-4 w-4" aria-hidden />}
                    {running ? 'Apply / restart' : 'Launch attacks'}
                  </button>
                  <button type="button" className="btn" onClick={() => stop.mutate()} disabled={busy || !running}>
                    <Square className="h-4 w-4" aria-hidden /> Stop
                  </button>
                </div>

                {/* Target */}
                <div className="mt-5">
                  <p className="panel-title mb-2 flex items-center gap-1.5">
                    <Target className="h-3.5 w-3.5" aria-hidden /> Target
                  </p>
                  <select
                    className="field"
                    value={target}
                    onChange={(changeEvent) => setTarget(changeEvent.target.value)}
                    aria-label="Attack target"
                  >
                    <option value="all">Everyone (rotate across the whole class)</option>
                    {targets.map((student) => (
                      <option key={student.username} value={student.username}>
                        {student.display_name} (@{student.username})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Attacks */}
                <div className="mt-5">
                  <p className="panel-title mb-2 flex items-center gap-1.5">
                    <Crosshair className="h-3.5 w-3.5" aria-hidden /> Attacks
                  </p>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {catalog.data?.attacks.map((attack) => {
                      const on = attacks.includes(attack.key)
                      return (
                        <button
                          key={attack.key}
                          type="button"
                          onClick={() => toggle(attack.key)}
                          className={cx(
                            'rounded-md border px-3 py-2 text-left text-[13px] transition-colors',
                            on ? 'border-severity-critical/50 bg-severity-critical/10 text-slate-100' : 'border-hairline text-slate-400 hover:text-slate-100',
                          )}
                          aria-pressed={on}
                        >
                          {attack.label}
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* Rate */}
                <div className="mt-5">
                  <p className="panel-title mb-2">Intensity</p>
                  <div className="flex flex-wrap gap-2">
                    {RATES.map((option) => (
                      <button
                        key={option.value}
                        type="button"
                        onClick={() => setRate(option.value)}
                        className={cx(
                          'rounded-md border px-3 py-1.5 text-xs transition-colors',
                          rate === option.value ? 'border-accent/50 bg-accent-soft text-accent' : 'border-hairline text-slate-400 hover:text-slate-100',
                        )}
                      >
                        {option.label} <span className="data opacity-70">{option.value}/min</span>
                      </button>
                    ))}
                  </div>
                </div>

                {(start.error || stop.error) && (
                  <p className="mt-3 text-xs text-severity-critical">
                    {((start.error || stop.error) as Error).message}
                  </p>
                )}
              </>
            )}
          </Panel>
        </div>

        {/* Class board */}
        <Panel
          title="The class"
          subtitle={`${targets.length} student site${targets.length === 1 ? '' : 's'} registered`}
          bodyClassName="max-h-[34rem] overflow-y-auto p-0"
        >
          {targets.length === 0 ? (
            <EmptyState message="No students yet. Share the /join link so they register their sites." />
          ) : (
            <ul className="divide-y divide-hairline">
              {targets.map((student) => (
                <li key={student.username} className="flex items-center gap-3 px-4 py-2.5">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[13px] text-slate-200">{student.display_name}</p>
                    <p className="data text-[11px] text-slate-500">@{student.username}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {student.failed_logins > 0 && (
                      <span className="data text-[11px] text-severity-high" title="Failed logins">
                        {student.failed_logins} hits
                      </span>
                    )}
                    {student.is_defaced && <Skull className="h-4 w-4 text-severity-critical" aria-label="defaced" />}
                    {student.is_breached && (
                      <span className="chip border-severity-critical/40 bg-severity-critical/10 text-severity-critical">
                        breached
                      </span>
                    )}
                    {!student.is_defaced && !student.is_breached && student.failed_logins === 0 && (
                      <span className="chip border-emerald-500/30 bg-emerald-500/5 text-emerald-400">safe</span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}
