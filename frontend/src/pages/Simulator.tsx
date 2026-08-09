import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Loader2, Pause, Play, Repeat, Shuffle, Square } from 'lucide-react'
import { useEffect, useState } from 'react'

import LiveFeed from '../components/LiveFeed'
import { ConnectionDot, EmptyState, Panel, Spinner, cx } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { countryFlag, timeAgo } from '../lib/format'
import { useLive } from '../lib/ws'

const RATES = [
  { label: 'Trickle', value: 12, hint: '12 / min' },
  { label: 'Steady', value: 60, hint: '60 / min' },
  { label: 'Busy', value: 240, hint: '240 / min' },
  { label: 'Storm', value: 900, hint: '900 / min' },
]

export default function Simulator() {
  const { atLeast } = useAuth()
  const canAnalyze = atLeast('analyst')
  const queryClient = useQueryClient()
  const { recentEvents, connected, simulation: liveState } = useLive()

  const scenarios = useQuery({ queryKey: ['scenarios'], queryFn: api.scenarios })
  const catalog = useQuery({ queryKey: ['country-catalog'], queryFn: api.countryCatalog })
  const state = useQuery({
    queryKey: ['simulation', 'state'],
    queryFn: api.simulationState,
    refetchInterval: 10_000,
  })

  const current = liveState ?? state.data
  const status = current?.status ?? 'stopped'

  const [selected, setSelected] = useState<string[]>([])
  const [countries, setCountries] = useState<string[]>([])
  const [rate, setRate] = useState(60)
  const [randomizeIps, setRandomizeIps] = useState(true)
  const [repeat, setRepeat] = useState(true)

  // Adopt the running configuration so the controls reflect reality after a
  // page reload mid-run.
  useEffect(() => {
    if (!current || status === 'stopped') return
    setSelected(current.config.scenarios)
    setCountries(current.config.source_countries)
    setRate(current.config.events_per_minute)
    setRandomizeIps(current.config.randomize_ips)
    setRepeat(current.config.repeat)
  }, [current, status])

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['simulation'] })
  const control = {
    start: useMutation({
      mutationFn: () =>
        api.startSimulation({
          scenarios: selected,
          source_countries: countries,
          events_per_minute: rate,
          randomize_ips: randomizeIps,
          repeat,
        }),
      onSuccess: refresh,
    }),
    pause: useMutation({ mutationFn: api.pauseSimulation, onSuccess: refresh }),
    resume: useMutation({ mutationFn: api.resumeSimulation, onSuccess: refresh }),
    stop: useMutation({ mutationFn: api.stopSimulation, onSuccess: refresh }),
  }
  const busy = Object.values(control).some((mutation) => mutation.isPending)
  const error = Object.values(control).find((mutation) => mutation.error)?.error as Error | undefined

  const toggle = (list: string[], setList: (next: string[]) => void, value: string) =>
    setList(list.includes(value) ? list.filter((item) => item !== value) : [...list, value])

  return (
    <div className="space-y-5">
      <p className="flex items-start gap-2.5 rounded-md border border-severity-medium/30 bg-severity-medium/5 px-4 py-3 text-xs leading-relaxed text-slate-400">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-severity-medium" aria-hidden />
        <span>
          <strong className="text-severity-medium">Synthetic traffic only.</strong> The simulator builds log
          records in memory and feeds them straight to the detection engine. No packet leaves this machine and no
          host is contacted — there is no target field to point anywhere.
        </span>
      </p>

      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <div className="space-y-5">
          {/* Transport controls */}
          <Panel
            title="Simulation control"
            subtitle={
              status === 'running'
                ? `Running · ${current?.events_generated ?? 0} observations, ${current?.detections ?? 0} detections`
                : status === 'paused'
                  ? 'Paused — generation halted, configuration retained'
                  : 'Stopped'
            }
            action={
              <span className="flex items-center gap-2 text-[11px]">
                <ConnectionDot connected={status === 'running'} />
                <span
                  className={cx(
                    'uppercase tracking-wider',
                    status === 'running' ? 'text-emerald-400' : status === 'paused' ? 'text-severity-medium' : 'text-slate-500',
                  )}
                >
                  {status}
                </span>
              </span>
            }
          >
            {!canAnalyze ? (
              <EmptyState message="Running the simulator requires the analyst role." />
            ) : (
              <>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => (status === 'paused' ? control.resume.mutate() : control.start.mutate())}
                    disabled={busy || status === 'running'}
                  >
                    {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Play className="h-4 w-4" aria-hidden />}
                    {status === 'paused' ? 'Resume' : 'Start'}
                  </button>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => control.pause.mutate()}
                    disabled={busy || status !== 'running'}
                  >
                    <Pause className="h-4 w-4" aria-hidden /> Pause
                  </button>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => control.stop.mutate()}
                    disabled={busy || status === 'stopped'}
                  >
                    <Square className="h-4 w-4" aria-hidden /> Stop
                  </button>
                  {status === 'running' && (
                    <button
                      type="button"
                      className="btn"
                      onClick={() => control.start.mutate()}
                      disabled={busy}
                      title="Apply the current configuration to the running simulation"
                    >
                      Apply changes
                    </button>
                  )}
                </div>

                {error && (
                  <p role="alert" className="mt-3 text-xs text-severity-critical">
                    {error.message}
                  </p>
                )}

                {/* Frequency */}
                <div className="mt-5">
                  <p className="panel-title mb-2">Attack frequency</p>
                  <div className="flex flex-wrap gap-2">
                    {RATES.map((option) => (
                      <button
                        key={option.value}
                        type="button"
                        onClick={() => setRate(option.value)}
                        className={cx(
                          'rounded-md border px-3 py-2 text-left transition-colors',
                          rate === option.value
                            ? 'border-accent/50 bg-accent-soft text-accent'
                            : 'border-hairline text-slate-400 hover:border-accent/40 hover:text-slate-100',
                        )}
                      >
                        <span className="block text-xs font-medium">{option.label}</span>
                        <span className="data block text-[10px] opacity-70">{option.hint}</span>
                      </button>
                    ))}
                    <label className="flex items-center gap-2 rounded-md border border-hairline px-3 py-2">
                      <span className="text-xs text-slate-400">Custom</span>
                      <input
                        type="number"
                        min={1}
                        max={3000}
                        value={rate}
                        onChange={(changeEvent) => setRate(Number(changeEvent.target.value))}
                        className="field w-20 !py-1 text-center"
                        aria-label="Events per minute"
                      />
                    </label>
                  </div>
                </div>

                {/* Toggles */}
                <div className="mt-5 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => setRandomizeIps(!randomizeIps)}
                    className={cx(
                      'flex items-center gap-2 rounded-md border px-3 py-2 text-xs transition-colors',
                      randomizeIps
                        ? 'border-accent/50 bg-accent-soft text-accent'
                        : 'border-hairline text-slate-400 hover:text-slate-100',
                    )}
                    aria-pressed={randomizeIps}
                  >
                    <Shuffle className="h-3.5 w-3.5" aria-hidden /> Randomise attacker IPs
                  </button>
                  <button
                    type="button"
                    onClick={() => setRepeat(!repeat)}
                    className={cx(
                      'flex items-center gap-2 rounded-md border px-3 py-2 text-xs transition-colors',
                      repeat
                        ? 'border-accent/50 bg-accent-soft text-accent'
                        : 'border-hairline text-slate-400 hover:text-slate-100',
                    )}
                    aria-pressed={repeat}
                  >
                    <Repeat className="h-3.5 w-3.5" aria-hidden /> Repeat continuously
                  </button>
                </div>
              </>
            )}
          </Panel>

          {/* Scenarios */}
          <Panel
            title="Attack scenarios"
            subtitle={selected.length === 0 ? 'None selected — all scenarios will run' : `${selected.length} selected`}
            action={
              selected.length > 0 && (
                <button type="button" className="text-[11px] text-accent hover:underline" onClick={() => setSelected([])}>
                  Reset to all
                </button>
              )
            }
          >
            {scenarios.isLoading ? (
              <Spinner />
            ) : (
              <div className="grid gap-2 sm:grid-cols-2">
                {scenarios.data?.map((scenario) => {
                  const active = selected.includes(scenario.key)
                  return (
                    <button
                      key={scenario.key}
                      type="button"
                      onClick={() => toggle(selected, setSelected, scenario.key)}
                      disabled={!canAnalyze}
                      className={cx(
                        'rounded-md border p-3 text-left transition-colors disabled:opacity-60',
                        active
                          ? 'border-accent/50 bg-accent-soft'
                          : 'border-hairline bg-white/[0.02] hover:border-accent/40',
                      )}
                      aria-pressed={active}
                    >
                      <span className={cx('block text-[13px] font-medium', active ? 'text-accent' : 'text-slate-200')}>
                        {scenario.name}
                      </span>
                      <span className="mt-1 block text-[11px] leading-relaxed text-slate-500">
                        {scenario.description}
                      </span>
                      <span className="chip mt-2 border-hairline text-slate-400">
                        → {scenario.expected_detection}
                      </span>
                    </button>
                  )
                })}
              </div>
            )}
          </Panel>

          {/* Source countries */}
          <Panel
            title="Source countries"
            subtitle={
              countries.length === 0
                ? 'None selected — a weighted global mix will be used'
                : `${countries.length} selected`
            }
            action={
              countries.length > 0 && (
                <button type="button" className="text-[11px] text-accent hover:underline" onClick={() => setCountries([])}>
                  Reset to global mix
                </button>
              )
            }
          >
            <div className="flex flex-wrap gap-1.5">
              {catalog.data?.map((country) => {
                const active = countries.includes(country.code)
                return (
                  <button
                    key={country.code}
                    type="button"
                    onClick={() => toggle(countries, setCountries, country.code)}
                    disabled={!canAnalyze}
                    className={cx(
                      'chip transition-colors disabled:opacity-60',
                      active
                        ? 'border-accent/50 bg-accent-soft text-accent'
                        : 'border-hairline text-slate-400 hover:border-accent/40 hover:text-slate-100',
                    )}
                    aria-pressed={active}
                    title={country.name}
                  >
                    <span className="mr-1" aria-hidden>
                      {countryFlag(country.code)}
                    </span>
                    {country.code}
                  </button>
                )
              })}
            </div>
          </Panel>
        </div>

        {/* Live output */}
        <div className="space-y-5">
          <Panel
            title="Generated events"
            subtitle={connected ? 'Streaming over WebSocket' : 'Socket offline'}
            bodyClassName="max-h-[38rem] overflow-y-auto p-0"
          >
            <LiveFeed
              events={recentEvents.slice(0, 30)}
              emptyHint={
                status === 'running'
                  ? 'Running — the first detections will appear here shortly.'
                  : 'Start the simulator to generate attack traffic.'
              }
            />
          </Panel>

          {current?.started_at && (
            <Panel title="Current run">
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">Started</dt>
                  <dd className="text-slate-300">{timeAgo(current.started_at)}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">Started by</dt>
                  <dd className="data truncate text-slate-300">{current.started_by}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">Observations</dt>
                  <dd className="data text-slate-300">{current.events_generated.toLocaleString()}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">Detections</dt>
                  <dd className="data text-accent">{current.detections.toLocaleString()}</dd>
                </div>
              </dl>
            </Panel>
          )}
        </div>
      </div>
    </div>
  )
}
