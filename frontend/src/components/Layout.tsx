import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AnimatePresence, motion } from 'framer-motion'
import {
  Activity,
  Bell,
  CheckCheck,
  ChevronDown,
  Crosshair,
  Globe2,
  LayoutDashboard,
  ListOrdered,
  LogOut,
  Menu,
  Radio,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'

import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { SEVERITY_CLASS, timeAgo } from '../lib/format'
import { useLive } from '../lib/ws'
import { ConnectionDot, cx } from './ui'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/map', label: 'Live Attack Map', icon: Globe2, end: false },
  { to: '/timeline', label: 'Attack Timeline', icon: ListOrdered, end: false },
  { to: '/rules', label: 'Detection Rules', icon: SlidersHorizontal, end: false },
  { to: '/simulator', label: 'Attack Simulator', icon: Radio, end: false },
  { to: '/live-range', label: 'Live Attack Range', icon: Crosshair, end: false },
]

const TITLES: Record<string, string> = {
  '/': 'Security Operations Overview',
  '/map': 'Live Attack Map',
  '/timeline': 'Attack Timeline',
  '/rules': 'Detection Rules',
  '/simulator': 'Attack Simulator',
  '/live-range': 'Live Attack Range',
}

function NotificationCentre() {
  const [open, setOpen] = useState(false)
  const panelRef = useRef<HTMLDivElement>(null)
  const queryClient = useQueryClient()

  const { data: unread } = useQuery({
    queryKey: ['notifications', 'unread'],
    queryFn: api.unreadCount,
    refetchInterval: 30_000,
  })
  const { data: items = [] } = useQuery({
    queryKey: ['notifications', 'recent'],
    queryFn: () => api.notifications({ limit: 12 }),
    enabled: open,
  })

  const markAll = useMutation({
    mutationFn: api.markAllRead,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['notifications'] }),
  })

  // Close on outside click and on Escape — a dropdown that traps focus in a
  // SOC console is worse than one that closes too eagerly.
  useEffect(() => {
    if (!open) return
    const onClick = (event: MouseEvent) => {
      if (!panelRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const count = unread?.unread ?? 0

  return (
    <div className="relative" ref={panelRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="btn relative !px-2.5"
        aria-label={`Notifications${count ? `, ${count} unread` : ''}`}
        aria-expanded={open}
      >
        <Bell className="h-4 w-4" aria-hidden />
        {count > 0 && (
          <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-severity-critical px-1 text-[10px] font-bold text-white">
            {count > 99 ? '99+' : count}
          </span>
        )}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: 0.15 }}
            className="glass absolute right-0 z-50 mt-2 max-h-[26rem] w-[22rem] overflow-hidden"
          >
            <div className="flex items-center justify-between border-b border-hairline px-3 py-2">
              <span className="panel-title">Notification Centre</span>
              <button
                type="button"
                className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-accent disabled:opacity-40"
                onClick={() => markAll.mutate()}
                disabled={markAll.isPending || count === 0}
              >
                <CheckCheck className="h-3 w-3" aria-hidden /> Mark all read
              </button>
            </div>
            <ul className="max-h-[22rem] divide-y divide-hairline overflow-y-auto">
              {items.length === 0 && <li className="px-3 py-8 text-center text-xs text-slate-500">Nothing yet.</li>}
              {items.map((item) => (
                <li
                  key={item.id}
                  className={cx('px-3 py-2.5 row-hover', !item.is_read && 'bg-accent/[0.045]')}
                >
                  <div className="flex items-start gap-2">
                    <span
                      className={cx('mt-1 h-1.5 w-1.5 shrink-0 rounded-full', SEVERITY_CLASS[item.severity])}
                      aria-hidden
                    />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[13px] font-medium text-slate-200">{item.title}</p>
                      <p className="mt-0.5 break-all font-mono text-[11px] text-slate-400">{item.message}</p>
                      <p className="mt-1 text-[10px] uppercase tracking-wide text-slate-600">
                        {timeAgo(item.created_at)}
                      </p>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function Layout() {
  const { user, logout } = useAuth()
  const { connected, simulation } = useLive()
  const location = useLocation()
  const [navOpen, setNavOpen] = useState(false)

  useEffect(() => setNavOpen(false), [location.pathname])

  const sidebar = (
    <>
      <div className="flex items-center gap-2.5 px-5 py-5">
        <ShieldCheck className="h-6 w-6 text-accent" aria-hidden />
        <div className="leading-tight">
          <p className="text-sm font-bold tracking-tight text-white">
            Cyber<span className="text-accent">Shield</span> AI
          </p>
          <p className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Threat Operations</p>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 px-3" aria-label="Main">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cx(
                'group flex items-center gap-3 rounded-md px-3 py-2.5 text-sm transition-colors',
                isActive
                  ? 'bg-accent-soft text-white shadow-[inset_2px_0_0_0_theme(colors.accent.DEFAULT)]'
                  : 'text-slate-400 hover:bg-white/5 hover:text-slate-100',
              )
            }
          >
            {({ isActive }) => (
              <>
                <Icon className={cx('h-4 w-4 shrink-0', isActive && 'text-accent')} aria-hidden />
                <span className="truncate">{label}</span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-hairline p-3">
        <div className="rounded-md bg-white/[0.03] p-3">
          <div className="flex items-center justify-between text-[11px]">
            <span className="uppercase tracking-wider text-slate-500">Simulator</span>
            <span
              className={cx(
                'font-semibold uppercase',
                simulation?.status === 'running'
                  ? 'text-emerald-400'
                  : simulation?.status === 'paused'
                    ? 'text-severity-medium'
                    : 'text-slate-500',
              )}
            >
              {simulation?.status ?? 'stopped'}
            </span>
          </div>
          {simulation && simulation.status !== 'stopped' && (
            <p className="data mt-1.5 text-[11px] text-slate-400">
              {simulation.detections} detections · {simulation.events_generated} records
            </p>
          )}
        </div>
      </div>
    </>
  )

  return (
    <div className="flex min-h-screen">
      {/* Desktop sidebar */}
      <aside className="hidden w-64 shrink-0 flex-col border-r border-hairline bg-surface/70 backdrop-blur-xl lg:flex">
        {sidebar}
      </aside>

      {/* Mobile drawer */}
      <AnimatePresence>
        {navOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-40 bg-black/70 lg:hidden"
              onClick={() => setNavOpen(false)}
            />
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: 'tween', duration: 0.2 }}
              className="fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-hairline bg-surface lg:hidden"
            >
              <button
                type="button"
                className="absolute right-3 top-4 text-slate-400 hover:text-white"
                onClick={() => setNavOpen(false)}
                aria-label="Close navigation"
              >
                <X className="h-5 w-5" aria-hidden />
              </button>
              {sidebar}
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-hairline bg-void/85 px-4 py-3 backdrop-blur-xl sm:px-6">
          <button
            type="button"
            className="btn !px-2.5 lg:hidden"
            onClick={() => setNavOpen(true)}
            aria-label="Open navigation"
          >
            <Menu className="h-4 w-4" aria-hidden />
          </button>

          <div className="min-w-0 flex-1">
            <h1 className="truncate text-base font-semibold text-white">
              {TITLES[location.pathname] ?? 'Attack Detail'}
            </h1>
            <p className="hidden text-[11px] text-slate-500 sm:block">
              Educational lab environment · all attack traffic is synthetic
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span
              className="hidden items-center gap-2 rounded-md border border-hairline bg-white/[0.03] px-2.5 py-1.5 text-[11px] font-medium sm:flex"
              title={connected ? 'Realtime feed connected' : 'Realtime feed disconnected — retrying'}
            >
              <ConnectionDot connected={connected} />
              <span className={connected ? 'text-emerald-400' : 'text-slate-500'}>
                {connected ? 'LIVE' : 'OFFLINE'}
              </span>
            </span>

            <NotificationCentre />

            <details className="group relative">
              <summary className="btn cursor-pointer list-none !px-2.5 marker:content-none">
                <Activity className="h-4 w-4 text-accent" aria-hidden />
                <span className="hidden max-w-[9rem] truncate text-xs sm:inline">{user?.full_name}</span>
                <ChevronDown className="hidden h-3 w-3 sm:inline" aria-hidden />
              </summary>
              <div className="glass absolute right-0 z-50 mt-2 w-56 p-3">
                <p className="truncate text-sm font-medium text-white">{user?.full_name}</p>
                <p className="truncate text-xs text-slate-500">{user?.email}</p>
                <p className="mt-2 inline-block rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-accent">
                  {user?.role}
                </p>
                <button type="button" onClick={logout} className="btn mt-3 w-full !justify-start">
                  <LogOut className="h-4 w-4" aria-hidden /> Sign out
                </button>
              </div>
            </details>
          </div>
        </header>

        <main className="min-w-0 flex-1 p-4 sm:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
