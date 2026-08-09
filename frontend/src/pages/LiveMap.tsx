import { useQuery } from '@tanstack/react-query'
import { useMemo } from 'react'

import AttackMap from '../components/AttackMap'
import LiveFeed from '../components/LiveFeed'
import { ConnectionDot, Panel, Spinner } from '../components/ui'
import { api } from '../lib/api'
import { compactNumber, countryFlag } from '../lib/format'
import { useLive } from '../lib/ws'

export default function LiveMap() {
  const { recentEvents, connected } = useLive()

  const countries = useQuery({ queryKey: ['countries', 24], queryFn: () => api.countries(24) })
  const timeline = useQuery({ queryKey: ['timeline', 30], queryFn: () => api.timeline(30) })

  const arcs = useMemo(() => {
    const seen = new Set<string>()
    return [...recentEvents, ...(timeline.data ?? [])].filter(
      (event) => !seen.has(event.uid) && seen.add(event.uid),
    )
  }, [recentEvents, timeline.data])

  const rows = countries.data ?? []
  const total = rows.reduce((sum, row) => sum + row.count, 0)

  return (
    <div className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-[2.2fr_1fr]">
        <Panel
          title="Global attack origins"
          subtitle={`${compactNumber(total)} attacks from ${rows.length} countries in the last 24 hours`}
          bodyClassName="p-0"
          action={
            <span className="flex items-center gap-2 text-[11px]">
              <ConnectionDot connected={connected} />
              <span className={connected ? 'text-emerald-400' : 'text-slate-500'}>
                {connected ? 'Live' : 'Offline'}
              </span>
            </span>
          }
        >
          {countries.isLoading ? (
            <Spinner label="Loading map" />
          ) : (
            <AttackMap countries={rows} arcs={arcs} className="h-[34rem] !rounded-none !border-0" />
          )}
        </Panel>

        <Panel title="Live activity" subtitle="Newest first" bodyClassName="max-h-[34rem] overflow-y-auto p-0">
          <LiveFeed events={arcs.slice(0, 25)} emptyHint="No events yet. Start the simulator." />
        </Panel>
      </div>

      <Panel title="Country breakdown" subtitle="Ranked by attack volume" bodyClassName="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[34rem] text-left text-sm">
            <thead className="border-b border-hairline text-[11px] uppercase tracking-wider text-slate-500">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Country
                </th>
                <th scope="col" className="px-4 py-2.5 text-right font-medium">
                  Attacks
                </th>
                <th scope="col" className="px-4 py-2.5 text-right font-medium">
                  Critical
                </th>
                <th scope="col" className="px-4 py-2.5 text-right font-medium">
                  Share
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {rows.map((row) => (
                <tr key={row.country_code} className="row-hover">
                  <td className="px-4 py-2.5">
                    <span className="mr-2" aria-hidden>
                      {countryFlag(row.country_code)}
                    </span>
                    <span className="text-slate-200">{row.country_name}</span>
                    <span className="data ml-2 text-[11px] text-slate-500">{row.country_code}</span>
                  </td>
                  <td className="data px-4 py-2.5 text-right text-slate-300">{row.count}</td>
                  <td className="data px-4 py-2.5 text-right">
                    <span className={row.critical_count ? 'text-severity-critical' : 'text-slate-600'}>
                      {row.critical_count}
                    </span>
                  </td>
                  <td className="data px-4 py-2.5 text-right text-slate-400">
                    {total ? ((row.count / total) * 100).toFixed(1) : '0.0'}%
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-10 text-center text-sm text-slate-500">
                    No attacks recorded in this window.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
