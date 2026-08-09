import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, Lock } from 'lucide-react'

import { ErrorState, Panel, SeverityBadge, Spinner, cx } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { SEVERITY_ORDER } from '../lib/format'
import type { DetectionRule } from '../lib/types'

function RuleCard({ rule, canEdit }: { rule: DetectionRule; canEdit: boolean }) {
  const queryClient = useQueryClient()
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.updateRule(rule.key, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rules'] }),
  })

  return (
    <article
      className={cx(
        'glass p-4 transition-opacity',
        !rule.enabled && 'opacity-55',
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold text-slate-100">{rule.name}</h3>
            <SeverityBadge severity={rule.severity} />
          </div>
          <p className="data mt-0.5 text-[11px] text-slate-500">{rule.key}</p>
        </div>

        <label className="flex shrink-0 cursor-pointer items-center gap-2" title={canEdit ? undefined : 'Admin role required'}>
          <span className="sr-only">Enable {rule.name}</span>
          <input
            type="checkbox"
            className="peer sr-only"
            checked={rule.enabled}
            disabled={!canEdit || toggle.isPending}
            onChange={(changeEvent) => toggle.mutate(changeEvent.target.checked)}
          />
          <span
            className={cx(
              'relative h-5 w-9 rounded-full border transition-colors',
              rule.enabled ? 'border-accent/50 bg-accent/30' : 'border-hairline bg-white/5',
              !canEdit && 'cursor-not-allowed',
            )}
          >
            <span
              className={cx(
                'absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all',
                rule.enabled ? 'left-[1.15rem] bg-accent' : 'left-0.5 bg-slate-500',
              )}
            />
          </span>
          {toggle.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" aria-hidden />}
        </label>
      </div>

      <p className="mt-3 text-[13px] leading-relaxed text-slate-400">{rule.description}</p>

      <dl className="mt-3 grid grid-cols-3 gap-2 border-t border-hairline pt-3 text-center">
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-slate-500">Confidence</dt>
          <dd className="data mt-0.5 text-sm text-slate-200">{(rule.confidence * 100).toFixed(0)}%</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-slate-500">Base score</dt>
          <dd className="data mt-0.5 text-sm text-slate-200">{rule.base_score.toFixed(0)}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-slate-500">Hits</dt>
          <dd className="data mt-0.5 text-sm text-accent">{rule.hit_count.toLocaleString()}</dd>
        </div>
      </dl>

      <div className="mt-3 space-y-2 text-[11px]">
        <p className="text-slate-500">
          <span className="uppercase tracking-wider">MITRE</span>{' '}
          <span className="text-slate-300">
            {rule.mitre_tactic} · {rule.mitre_technique}
          </span>
        </p>
        <p className="leading-relaxed text-slate-500">
          <span className="uppercase tracking-wider">Action</span>{' '}
          <span className="text-slate-400">{rule.recommended_action}</span>
        </p>
      </div>

      {toggle.isError && (
        <p className="mt-2 text-xs text-severity-critical">{(toggle.error as Error).message}</p>
      )}
    </article>
  )
}

export default function Rules() {
  const { atLeast } = useAuth()
  const isAdmin = atLeast('admin')
  const rules = useQuery({ queryKey: ['rules'], queryFn: api.rules })

  if (rules.isLoading) return <Spinner label="Loading detection rules" />
  if (rules.isError || !rules.data) {
    return <ErrorState message={(rules.error as Error)?.message ?? 'Could not load rules'} onRetry={rules.refetch} />
  }

  const enabled = rules.data.filter((rule) => rule.enabled).length
  const sorted = [...rules.data].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.name.localeCompare(b.name),
  )

  return (
    <div className="space-y-5">
      <Panel
        title="Detection engine"
        subtitle={`${enabled} of ${rules.data.length} rules active · ${rules.data
          .reduce((sum, rule) => sum + rule.hit_count, 0)
          .toLocaleString()} total hits`}
        action={
          !isAdmin && (
            <span className="flex items-center gap-1.5 text-[11px] text-slate-500">
              <Lock className="h-3.5 w-3.5" aria-hidden /> Admin role required to tune
            </span>
          )
        }
      >
        <p className="text-sm leading-relaxed text-slate-400">
          Every rule scores an observation independently. When several fire on the same record the
          highest-scoring one owns the resulting event and the rest are attached as correlated signals, so a
          request that is both directory traversal and command injection surfaces once with both named.
        </p>
      </Panel>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {sorted.map((rule) => (
          <RuleCard key={rule.key} rule={rule} canEdit={isAdmin} />
        ))}
      </div>
    </div>
  )
}
