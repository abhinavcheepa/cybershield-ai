import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import {
  ArrowLeft,
  Brain,
  Crosshair,
  FileTerminal,
  Loader2,
  ShieldBan,
  Sparkles,
  Target,
} from 'lucide-react'
import { Link, useParams } from 'react-router-dom'

import { ErrorState, Panel, SeverityBadge, Spinner, StatusBadge, cx } from '../components/ui'
import { api } from '../lib/api'
import {
  SEVERITY_HEX,
  countryFlag,
  formatBytes,
  fullTimestamp,
  scoreTone,
  timeAgo,
} from '../lib/format'
import { useAuth } from '../lib/auth'
import type { EventStatus } from '../lib/types'

const TRIAGE: EventStatus[] = ['active', 'investigating', 'mitigated', 'resolved', 'false_positive']

function Field({ label, children, mono = false }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className={cx('mt-0.5 truncate text-sm text-slate-200', mono && 'data')}>{children}</dd>
    </div>
  )
}

export default function EventDetail() {
  const { uid = '' } = useParams()
  const { atLeast } = useAuth()
  const canAnalyze = atLeast('analyst')
  const queryClient = useQueryClient()

  const event = useQuery({ queryKey: ['event', uid], queryFn: () => api.event(uid), enabled: Boolean(uid) })
  const aiStatus = useQuery({ queryKey: ['ai-status'], queryFn: api.aiStatus })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['event', uid] })
    queryClient.invalidateQueries({ queryKey: ['events'] })
    queryClient.invalidateQueries({ queryKey: ['timeline'] })
    queryClient.invalidateQueries({ queryKey: ['stats'] })
  }

  const setStatus = useMutation({
    mutationFn: (status: EventStatus) => api.setEventStatus(uid, status),
    onSuccess: invalidate,
  })
  const reanalyze = useMutation({
    mutationFn: () => api.analyze(uid),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['event', uid] }),
  })

  if (event.isLoading) return <Spinner label="Loading attack detail" />
  if (event.isError || !event.data) {
    return <ErrorState message={(event.error as Error)?.message ?? 'Event not found'} onRetry={event.refetch} />
  }

  const data = event.data
  const explanation = data.explanation

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: 'easeOut' }}
      className="space-y-5"
    >
      <Link to="/timeline" className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-accent">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back to timeline
      </Link>

      {/* Headline */}
      <section
        className="glass relative overflow-hidden p-5"
        style={{ borderLeft: `3px solid ${SEVERITY_HEX[data.severity]}` }}
      >
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-lg font-semibold text-white">{data.name}</h1>
              <SeverityBadge severity={data.severity} />
              <StatusBadge status={data.status} />
              {data.blocked && (
                <span className="chip border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
                  <ShieldBan className="mr-1 inline h-3 w-3" aria-hidden />
                  blocked
                </span>
              )}
              {data.simulated && (
                <span className="chip border-slate-600 bg-white/5 text-slate-400">simulated</span>
              )}
            </div>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-400">{data.description}</p>
            <p className="mt-2 text-xs text-slate-500">
              Detected {fullTimestamp(data.detected_at)} · {timeAgo(data.detected_at)}
            </p>
          </div>

          <div className="text-right">
            <p className="panel-title">Risk score</p>
            <p className={cx('metric', scoreTone(data.threat_score))}>{data.threat_score.toFixed(0)}</p>
            <p className="mt-1 text-xs text-slate-500">
              Confidence {(data.confidence * 100).toFixed(0)}%
            </p>
          </div>
        </div>

        {canAnalyze && (
          <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-hairline pt-4">
            <span className="text-[11px] uppercase tracking-wider text-slate-500">Set status</span>
            {TRIAGE.map((status) => (
              <button
                key={status}
                type="button"
                disabled={setStatus.isPending || data.status === status}
                onClick={() => setStatus.mutate(status)}
                className={cx(
                  'chip transition-colors disabled:opacity-100',
                  data.status === status
                    ? 'border-accent/50 bg-accent-soft text-accent'
                    : 'border-hairline text-slate-400 hover:border-accent/40 hover:text-slate-100',
                )}
              >
                {status.replace('_', ' ')}
              </button>
            ))}
            {setStatus.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" aria-hidden />}
            {setStatus.isError && (
              <span className="text-xs text-severity-critical">{(setStatus.error as Error).message}</span>
            )}
          </div>
        )}
      </section>

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="space-y-5 xl:col-span-2">
          {/* Connection */}
          <Panel title="Connection" subtitle="Source, destination and transport">
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Field label="Source IP" mono>
                {data.source_ip}:{data.source_port}
              </Field>
              <Field label="Source country">
                <span className="mr-1.5" aria-hidden>
                  {countryFlag(data.source_country)}
                </span>
                {data.source_country_name}
              </Field>
              <Field label="Destination IP" mono>
                {data.destination_ip}:{data.destination_port}
              </Field>
              <Field label="Destination country">
                <span className="mr-1.5" aria-hidden>
                  {countryFlag(data.destination_country)}
                </span>
                {data.destination_country_name}
              </Field>
              <Field label="Protocol" mono>
                {data.protocol}
              </Field>
              <Field label="Attack type">{data.attack_type}</Field>
              <Field label="Packet count" mono>
                {data.packet_count.toLocaleString()}
              </Field>
              <Field label="Bytes transferred" mono>
                {formatBytes(data.bytes_transferred)}
              </Field>
              <Field label="Response time" mono>
                {data.response_time_ms} ms
              </Field>
              {data.asset && (
                <>
                  <Field label="Targeted asset">{data.asset.name}</Field>
                  <Field label="Hostname" mono>
                    {data.asset.hostname}
                  </Field>
                  <Field label="Service">
                    {data.asset.service} · owner {data.asset.owner}
                  </Field>
                </>
              )}
            </div>
          </Panel>

          {/* Why this fired */}
          <Panel
            title="Detection indicators"
            subtitle="What the rule actually matched"
            action={<Crosshair className="h-4 w-4 text-slate-500" aria-hidden />}
          >
            <ul className="space-y-1.5">
              {data.indicators.map((indicator, index) => (
                <li key={index} className="flex gap-2 text-sm text-slate-300">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent" aria-hidden />
                  <span className="data text-[13px]">{indicator}</span>
                </li>
              ))}
              {data.indicators.length === 0 && <li className="text-sm text-slate-500">No indicators recorded.</li>}
            </ul>
          </Panel>

          {/* AI assistant */}
          <Panel
            title="AI security assistant"
            subtitle={
              explanation
                ? `${explanation.generated_by} · confidence ${(explanation.confidence * 100).toFixed(0)}%`
                : 'No analysis stored'
            }
            action={
              canAnalyze && (
                <button
                  type="button"
                  className="btn !py-1.5 !text-xs"
                  onClick={() => reanalyze.mutate()}
                  disabled={reanalyze.isPending}
                  title={
                    aiStatus.data?.live_model_available
                      ? `Re-run analysis with ${aiStatus.data.model}`
                      : 'Re-run the built-in analyst templates (set ANTHROPIC_API_KEY for live model analysis)'
                  }
                >
                  {reanalyze.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                  ) : (
                    <Sparkles className="h-3.5 w-3.5" aria-hidden />
                  )}
                  Re-analyse
                </button>
              )
            }
          >
            {explanation ? (
              <div className="space-y-4">
                {[
                  { title: 'Why this was detected', body: explanation.why_detected, icon: Brain },
                  { title: 'Potential impact', body: explanation.potential_impact, icon: Target },
                  { title: 'MITRE ATT&CK mapping', body: explanation.mitre_mapping, icon: Crosshair },
                  { title: 'Recommended mitigation', body: explanation.recommended_mitigation, icon: ShieldBan },
                ].map((block) => (
                  <div key={block.title}>
                    <h3 className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-accent">
                      <block.icon className="h-3.5 w-3.5" aria-hidden />
                      {block.title}
                    </h3>
                    <p className="mt-1.5 text-sm leading-relaxed text-slate-300">{block.body}</p>
                  </div>
                ))}

                <div>
                  <h3 className="text-[11px] uppercase tracking-wider text-accent">Future prevention</h3>
                  <ul className="mt-1.5 space-y-1">
                    {explanation.future_prevention.map((item, index) => (
                      <li key={index} className="flex gap-2 text-sm text-slate-300">
                        <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-slate-600" aria-hidden />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <p className="py-6 text-center text-sm text-slate-500">
                No AI explanation stored for this event.
              </p>
            )}
            {reanalyze.isError && (
              <p className="mt-3 text-xs text-severity-critical">{(reanalyze.error as Error).message}</p>
            )}
          </Panel>
        </div>

        <div className="space-y-5">
          <Panel title="MITRE ATT&CK">
            <dl className="space-y-3">
              <Field label="Tactic">{data.mitre_tactic}</Field>
              <Field label="Technique">{data.mitre_technique}</Field>
            </dl>
            <a
              href={`https://attack.mitre.org/techniques/${data.mitre_technique.split(' ')[0].replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-3 inline-block text-xs text-accent hover:underline"
            >
              View on attack.mitre.org →
            </a>
          </Panel>

          <Panel title="Recommended fix" subtitle="From the detection rule">
            <p className="text-sm leading-relaxed text-slate-300">{data.recommended_action}</p>
          </Panel>

          <Panel
            title="Raw log"
            subtitle="Record as received by the engine"
            action={<FileTerminal className="h-4 w-4 text-slate-500" aria-hidden />}
            bodyClassName="p-0"
          >
            <pre className="max-h-96 overflow-auto px-4 py-3 font-mono text-[11px] leading-relaxed text-slate-400">
              {JSON.stringify(data.raw_log, null, 2)}
            </pre>
          </Panel>
        </div>
      </div>
    </motion.div>
  )
}
