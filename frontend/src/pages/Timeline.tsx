import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, Search, ShieldBan, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { EmptyState, ErrorState, Panel, SeverityBadge, Spinner, StatusBadge, cx } from '../components/ui'
import { api } from '../lib/api'
import { clockTime, countryFlag, fullTimestamp, scoreTone, timeAgo } from '../lib/format'
import type { EventStatus, Severity } from '../lib/types'

const PAGE_SIZE = 25
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES: EventStatus[] = ['active', 'investigating', 'mitigated', 'resolved', 'false_positive']
const WINDOWS = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
]

export default function Timeline() {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const [searchDraft, setSearchDraft] = useState(params.get('search') ?? '')

  const severity = params.get('severity') ?? ''
  const status = params.get('status') ?? ''
  const attackType = params.get('attack_type') ?? ''
  const search = params.get('search') ?? ''
  const hours = Number(params.get('hours') ?? 24)

  // Debounce the search box so typing doesn't fire a request per keystroke.
  useEffect(() => {
    const timer = setTimeout(() => {
      setParams((previous) => {
        const next = new URLSearchParams(previous)
        if (searchDraft) next.set('search', searchDraft)
        else next.delete('search')
        return next
      })
      setPage(1)
    }, 350)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchDraft])

  const { data: attackTypes = [] } = useQuery({ queryKey: ['attack-types'], queryFn: api.attackTypes })
  const events = useQuery({
    queryKey: ['events', { page, severity, status, attackType, search, hours }],
    queryFn: () =>
      api.events({
        page,
        page_size: PAGE_SIZE,
        severity: severity || undefined,
        status: status || undefined,
        attack_type: attackType || undefined,
        search: search || undefined,
        hours,
      }),
  })

  const setFilter = (key: string, value: string) => {
    setParams((previous) => {
      const next = new URLSearchParams(previous)
      if (value) next.set(key, value)
      else next.delete(key)
      return next
    })
    setPage(1)
  }

  const clearAll = () => {
    setParams(new URLSearchParams())
    setSearchDraft('')
    setPage(1)
  }

  const total = events.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const activeFilters = [severity, status, attackType, search].filter(Boolean).length

  return (
    <div className="space-y-4">
      {/* Filters live in one row above the table. */}
      <div className="glass flex flex-wrap items-center gap-2 p-3">
        <div className="relative min-w-[13rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" aria-hidden />
          <input
            type="search"
            className="field pl-8"
            placeholder="Search IP, attack type or country…"
            value={searchDraft}
            onChange={(changeEvent) => setSearchDraft(changeEvent.target.value)}
            aria-label="Search attack events"
          />
        </div>

        <select
          className="field w-auto"
          value={severity}
          onChange={(changeEvent) => setFilter('severity', changeEvent.target.value)}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <select
          className="field w-auto"
          value={status}
          onChange={(changeEvent) => setFilter('status', changeEvent.target.value)}
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {value.replace('_', ' ')}
            </option>
          ))}
        </select>

        <select
          className="field w-auto"
          value={attackType}
          onChange={(changeEvent) => setFilter('attack_type', changeEvent.target.value)}
          aria-label="Filter by attack type"
        >
          <option value="">All attack types</option>
          {attackTypes.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <div className="flex rounded-md border border-hairline p-0.5" role="group" aria-label="Time window">
          {WINDOWS.map((window) => (
            <button
              key={window.hours}
              type="button"
              onClick={() => setFilter('hours', String(window.hours))}
              className={cx(
                'rounded px-2.5 py-1 text-xs font-medium transition-colors',
                hours === window.hours ? 'bg-accent-soft text-accent' : 'text-slate-400 hover:text-slate-100',
              )}
            >
              {window.label}
            </button>
          ))}
        </div>

        {activeFilters > 0 && (
          <button type="button" onClick={clearAll} className="btn !py-1.5 !text-xs">
            <X className="h-3.5 w-3.5" aria-hidden /> Clear ({activeFilters})
          </button>
        )}
      </div>

      <Panel
        title="Attack timeline"
        subtitle={`${total.toLocaleString()} event${total === 1 ? '' : 's'} · newest first`}
        bodyClassName="p-0"
      >
        {events.isLoading ? (
          <Spinner label="Loading events" />
        ) : events.isError ? (
          <ErrorState message={(events.error as Error).message} onRetry={events.refetch} />
        ) : events.data && events.data.items.length === 0 ? (
          <EmptyState message="No events match these filters." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[60rem] text-left text-sm">
              <thead className="sticky top-0 border-b border-hairline bg-surface/90 text-[11px] uppercase tracking-wider text-slate-500 backdrop-blur">
                <tr>
                  <th scope="col" className="px-4 py-2.5 font-medium">Time</th>
                  <th scope="col" className="px-4 py-2.5 font-medium">Attack</th>
                  <th scope="col" className="px-4 py-2.5 font-medium">Severity</th>
                  <th scope="col" className="px-4 py-2.5 font-medium">Source</th>
                  <th scope="col" className="px-4 py-2.5 font-medium">Country</th>
                  <th scope="col" className="px-4 py-2.5 font-medium">Target</th>
                  <th scope="col" className="px-4 py-2.5 text-right font-medium">Score</th>
                  <th scope="col" className="px-4 py-2.5 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {events.data?.items.map((event) => (
                  <tr key={event.uid} className="row-hover">
                    <td className="whitespace-nowrap px-4 py-2.5">
                      <Link to={`/events/${event.uid}`} className="block" title={fullTimestamp(event.detected_at)}>
                        <span className="data text-slate-300">{clockTime(event.detected_at)}</span>
                        <span className="ml-2 text-[11px] text-slate-600">{timeAgo(event.detected_at)}</span>
                      </Link>
                    </td>
                    <td className="px-4 py-2.5">
                      <Link to={`/events/${event.uid}`} className="flex items-center gap-2 hover:text-accent">
                        <span className="truncate text-slate-100">{event.attack_type}</span>
                        {event.blocked && (
                          <span title="Auto-blocked">
                            <ShieldBan className="h-3.5 w-3.5 shrink-0 text-emerald-400" aria-label="Blocked" />
                          </span>
                        )}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={event.severity} />
                    </td>
                    <td className="data px-4 py-2.5 text-slate-300">
                      {event.source_ip}
                      <span className="text-slate-600">:{event.source_port}</span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-slate-400">
                      <span className="mr-1.5" aria-hidden>{countryFlag(event.source_country)}</span>
                      {event.source_country_name}
                    </td>
                    <td className="data px-4 py-2.5 text-slate-400">
                      {event.asset?.name ?? event.destination_ip}
                      <span className="text-slate-600">:{event.destination_port}</span>
                    </td>
                    <td className={cx('data px-4 py-2.5 text-right font-semibold', scoreTone(event.threat_score))}>
                      {event.threat_score.toFixed(0)}
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge status={event.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {pages > 1 && (
          <div className="flex items-center justify-between border-t border-hairline px-4 py-2.5">
            <p className="text-xs text-slate-500">
              Page {page} of {pages}
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                className="btn !py-1.5 !text-xs"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
              >
                <ChevronLeft className="h-3.5 w-3.5" aria-hidden /> Previous
              </button>
              <button
                type="button"
                className="btn !py-1.5 !text-xs"
                onClick={() => setPage((p) => Math.min(pages, p + 1))}
                disabled={page >= pages}
              >
                Next <ChevronRight className="h-3.5 w-3.5" aria-hidden />
              </button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  )
}
