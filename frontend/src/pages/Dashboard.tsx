import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  Crosshair,
  Gauge,
  Globe2,
  ServerCrash,
  ShieldAlert,
  ShieldBan,
  Users,
} from 'lucide-react'
import { useMemo } from 'react'
import { Link } from 'react-router-dom'

import AttackMap from '../components/AttackMap'
import {
  AttackVolumeChart,
  CountryBarChart,
  ResponseTimeChart,
  SeverityDonut,
  ThreatTrendChart,
} from '../components/Charts'
import LiveFeed from '../components/LiveFeed'
import { EmptyState, ErrorState, Panel, RankBar, Spinner, StatCard, cx } from '../components/ui'
import { api } from '../lib/api'
import { SEVERITY_HEX, compactNumber, scoreTone } from '../lib/format'
import { useLive } from '../lib/ws'

export default function Dashboard() {
  const { recentEvents, connected } = useLive()

  const stats = useQuery({ queryKey: ['stats', 24], queryFn: () => api.stats(24), refetchInterval: 60_000 })
  const series = useQuery({
    queryKey: ['timeseries', 60, 30],
    queryFn: () => api.timeseries(60, 30),
    refetchInterval: 60_000,
  })
  const countries = useQuery({ queryKey: ['countries', 24], queryFn: () => api.countries(24) })
  const timeline = useQuery({ queryKey: ['timeline', 12], queryFn: () => api.timeline(12) })

  // Live socket events lead; the fetched timeline backfills so the feed is
  // populated before the first broadcast arrives.
  const feed = useMemo(() => {
    const seen = new Set<string>()
    return [...recentEvents, ...(timeline.data ?? [])]
      .filter((event) => !seen.has(event.uid) && seen.add(event.uid))
      .slice(0, 12)
  }, [recentEvents, timeline.data])

  if (stats.isLoading) return <Spinner label="Loading operations overview" />
  if (stats.isError || !stats.data) {
    return <ErrorState message={(stats.error as Error)?.message ?? 'Could not load stats'} onRetry={stats.refetch} />
  }

  const data = stats.data
  const maxType = Math.max(1, ...data.top_attack_types.map((t) => t.count))
  const maxAsset = Math.max(1, ...data.top_targeted_assets.map((t) => t.count))
  const maxAttacker = Math.max(1, ...data.top_attackers.map((t) => t.count))
  const maxService = Math.max(1, ...data.top_targeted_services.map((t) => t.count))

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard
          label="Total attacks (24h)"
          value={compactNumber(data.total_attacks)}
          icon={<Crosshair className="h-4 w-4" aria-hidden />}
          trend={data.trend_pct}
          hint={`${data.attacks_last_hour} in the last hour`}
          delay={0}
        />
        <StatCard
          label="Active"
          value={compactNumber(data.active_attacks)}
          icon={<Activity className="h-4 w-4" aria-hidden />}
          hint="Awaiting triage"
          tone="text-severity-high"
          delay={0.05}
        />
        <StatCard
          label="Critical"
          value={compactNumber(data.critical_attacks)}
          icon={<ShieldAlert className="h-4 w-4" aria-hidden />}
          hint={`${data.blocked_attacks} auto-blocked`}
          tone="text-severity-critical"
          delay={0.1}
        />
        <StatCard
          label="Threat score"
          value={data.threat_score.toFixed(0)}
          icon={<Gauge className="h-4 w-4" aria-hidden />}
          hint="Posture, 0–100"
          tone={scoreTone(data.threat_score)}
          delay={0.15}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Panel
          title="Attack volume"
          subtitle="Detections per bucket, last 60 minutes"
          className="xl:col-span-2"
          bodyClassName="h-64 p-4"
        >
          {series.isLoading ? <Spinner /> : <AttackVolumeChart series={series.data ?? []} />}
        </Panel>

        <Panel title="Severity distribution" subtitle="Last 24 hours" bodyClassName="p-4">
          <SeverityDonut data={data.by_severity} />
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Panel
          title="Live attack map"
          subtitle="Animated arcs draw as events arrive"
          className="xl:col-span-2"
          bodyClassName="p-0"
          action={
            <Link to="/map" className="text-[11px] text-accent hover:underline">
              Expand
            </Link>
          }
        >
          <AttackMap countries={countries.data ?? []} arcs={recentEvents} className="h-[22rem] !rounded-none !border-0" />
        </Panel>

        <Panel
          title="Live activity feed"
          subtitle={connected ? 'Streaming over WebSocket' : 'Reconnecting…'}
          bodyClassName="max-h-[22rem] overflow-y-auto p-0"
        >
          <LiveFeed
            events={feed}
            emptyHint="No events yet. Start the attack simulator to generate traffic."
          />
        </Panel>
      </div>

      <div className="grid gap-5 lg:grid-cols-2 xl:grid-cols-4">
        <Panel title="Top attack types" subtitle="Last 24 hours">
          {data.top_attack_types.length === 0 ? (
            <EmptyState message="No attacks recorded." />
          ) : (
            <div className="space-y-1">
              {data.top_attack_types.map((row) => (
                <RankBar
                  key={row.name}
                  name={row.name}
                  count={row.count}
                  max={maxType}
                  href={`/timeline?attack_type=${encodeURIComponent(row.name)}`}
                />
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Top attacked assets" subtitle="By event volume">
          {data.top_targeted_assets.length === 0 ? (
            <EmptyState message="No assets targeted." />
          ) : (
            <div className="space-y-1">
              {data.top_targeted_assets.map((row) => (
                <RankBar
                  key={row.name}
                  name={row.name}
                  count={row.count}
                  max={maxAsset}
                  extra={row.extra}
                  color={SEVERITY_HEX.high}
                />
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Top attackers" subtitle="Source addresses by volume">
          {data.top_attackers.length === 0 ? (
            <EmptyState message="No attackers seen." />
          ) : (
            <div className="space-y-1">
              {data.top_attackers.map((row) => (
                <RankBar
                  key={row.name}
                  name={row.name}
                  count={row.count}
                  max={maxAttacker}
                  extra={row.extra}
                  color={SEVERITY_HEX.critical}
                  href={`/timeline?search=${encodeURIComponent(row.name)}`}
                />
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Most targeted services" subtitle="By exposed service">
          {data.top_targeted_services.length === 0 ? (
            <EmptyState message="No services targeted." />
          ) : (
            <div className="space-y-1">
              {data.top_targeted_services.map((row) => (
                <RankBar key={row.name} name={row.name} count={row.count} max={maxService} color={SEVERITY_HEX.low} />
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Panel title="Threat score trend" subtitle="Mean score per bucket, 0–100" bodyClassName="h-56 p-4">
          {series.isLoading ? <Spinner /> : <ThreatTrendChart series={series.data ?? []} />}
        </Panel>

        <Panel title="Response time" subtitle="Mean observed latency per bucket" bodyClassName="h-56 p-4">
          {series.isLoading ? <Spinner /> : <ResponseTimeChart series={series.data ?? []} />}
        </Panel>

        <Panel title="Attacks by country" subtitle="Top 8 sources, last 24 hours" bodyClassName="h-56 p-4">
          {countries.isLoading ? <Spinner /> : <CountryBarChart countries={countries.data ?? []} />}
        </Panel>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          {
            label: 'Unique attackers',
            value: compactNumber(data.unique_attackers),
            icon: <Users className="h-4 w-4" aria-hidden />,
          },
          {
            label: 'Countries involved',
            value: String(data.countries_involved),
            icon: <Globe2 className="h-4 w-4" aria-hidden />,
          },
          {
            label: 'Auto-blocked',
            value: compactNumber(data.blocked_attacks),
            icon: <ShieldBan className="h-4 w-4" aria-hidden />,
          },
          {
            label: 'Avg response',
            value: `${compactNumber(data.avg_response_time_ms)} ms`,
            icon: <ServerCrash className="h-4 w-4" aria-hidden />,
          },
        ].map((tile) => (
          <div key={tile.label} className="glass flex items-center gap-3 p-4">
            <span className="rounded-md bg-accent-soft p-2 text-accent">{tile.icon}</span>
            <div className="min-w-0">
              <p className="panel-title truncate">{tile.label}</p>
              <p className={cx('data mt-0.5 text-lg font-semibold text-white')}>{tile.value}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
