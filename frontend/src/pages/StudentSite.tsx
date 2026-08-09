import { AnimatePresence, motion } from 'framer-motion'
import { Activity, BellOff, BellRing, Loader2, LogOut, ShieldAlert, Siren, Skull, Unlock } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { timeAgo } from '../lib/format'
import { getSiteToken, setSiteToken, siteApi, type SiteView, type UnderAttack } from '../lib/siteApi'

interface FeedItem extends UnderAttack {
  id: number
  at: number
}

// How long after the last attack event the big red banner stays up.
const BANNER_WINDOW_MS = 9000

// A desktop notification per attack event would mean dozens per minute, so at
// most one gets through per window. The tag makes Chrome replace the previous
// one instead of stacking a tower of toasts.
const NOTIFY_THROTTLE_MS = 15_000
const NOTIFY_TAG = 'cybershield-attack'

/** Browsers only expose Notification in a secure context (https, or localhost). */
const canNotify = () => typeof window !== 'undefined' && 'Notification' in window

export default function StudentSite() {
  const navigate = useNavigate()
  const [site, setSite] = useState<SiteView | null>(null)
  const [feed, setFeed] = useState<FeedItem[]>([])
  const [lastAttackAt, setLastAttackAt] = useState(0)
  const [, forceTick] = useState(0)

  const lastRefresh = useRef(0)
  const feedId = useRef(0)
  const lastNotifyAt = useRef(0)

  // 'unsupported' | 'default' | 'granted' | 'denied'
  const [notifyState, setNotifyState] = useState<string>(() =>
    canNotify() ? Notification.permission : 'unsupported',
  )

  // Chrome only shows the permission prompt from a user gesture, so this is a
  // button rather than something that fires on load.
  const enableNotifications = async () => {
    if (!canNotify()) return
    setNotifyState(await Notification.requestPermission())
  }

  const notify = useCallback((attack: UnderAttack) => {
    if (!canNotify() || Notification.permission !== 'granted') return
    if (Date.now() - lastNotifyAt.current < NOTIFY_THROTTLE_MS) return
    lastNotifyAt.current = Date.now()
    try {
      new Notification('🔴 Your site is under attack', {
        body: `${attack.message}\n${attack.attack_type} from ${attack.source_country}`,
        tag: NOTIFY_TAG,
      })
    } catch {
      // Some mobile browsers only allow notifications through a service worker
      // and throw on the constructor. The on-page banner still fires.
    }
  }, [])

  const refresh = useCallback(async () => {
    try {
      setSite(await siteApi.me())
    } catch (caught) {
      // Token invalid/expired -> back to join.
      if (caught instanceof Error && /sign|session|401/i.test(caught.message)) {
        setSiteToken(null)
        navigate('/join', { replace: true })
      }
    }
  }, [navigate])

  // Initial load + redirect if not signed in.
  useEffect(() => {
    if (!getSiteToken()) {
      navigate('/join', { replace: true })
      return
    }
    refresh()
  }, [navigate, refresh])

  // Live channel: real attacks against THIS student are pushed here.
  useEffect(() => {
    const token = getSiteToken()
    if (!token) return
    let socket: WebSocket | null = null
    let retry: number | undefined
    let closed = false

    const connect = () => {
      if (closed) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      socket = new WebSocket(`${proto}://${window.location.host}/site/ws?token=${encodeURIComponent(token)}`)
      socket.onmessage = (message) => {
        const parsed = JSON.parse(message.data) as { type: string; data: UnderAttack }
        if (parsed.type !== 'under_attack') return
        const item: FeedItem = { ...parsed.data, id: (feedId.current += 1), at: Date.now() }
        setFeed((previous) => [item, ...previous].slice(0, 40))
        setLastAttackAt(Date.now())
        notify(parsed.data)
        // Refresh my site (defaced/breached/guestbook), but not on every packet.
        if (Date.now() - lastRefresh.current > 1500) {
          lastRefresh.current = Date.now()
          refresh()
        }
      }
      socket.onclose = () => {
        if (!closed) retry = window.setTimeout(connect, 2000)
      }
      socket.onerror = () => socket?.close()
    }
    connect()
    return () => {
      closed = true
      window.clearTimeout(retry)
      socket?.close()
    }
  }, [refresh, notify])

  // Drives the banner countdown so it fades on its own.
  useEffect(() => {
    const timer = window.setInterval(() => forceTick((n) => n + 1), 1000)
    return () => window.clearInterval(timer)
  }, [])

  const logout = () => {
    setSiteToken(null)
    navigate('/join', { replace: true })
  }

  if (!site) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-void">
        <Loader2 className="h-6 w-6 animate-spin text-accent" aria-label="Loading" />
      </div>
    )
  }

  const underAttack = Date.now() - lastAttackAt < BANNER_WINDOW_MS
  const recentCount = feed.filter((f) => Date.now() - f.at < BANNER_WINDOW_MS).length

  return (
    <div className="min-h-screen bg-void">
      {/* Attack klaxon */}
      <AnimatePresence>
        {underAttack && (
          <motion.div
            initial={{ opacity: 0, y: -40 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -40 }}
            className="sticky top-0 z-50 border-b-2 border-severity-critical bg-severity-critical/20 backdrop-blur"
          >
            <div className="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3">
              <Siren className="h-6 w-6 animate-pulse text-severity-critical" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-bold text-severity-critical">
                  🔴 YOUR SITE IS UNDER ATTACK — {recentCount} live event{recentCount === 1 ? '' : 's'}
                </p>
                <p className="truncate text-xs text-slate-300">{feed[0]?.message}</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="mx-auto max-w-6xl p-4 sm:p-6">
        {/* Header */}
        <header className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold text-white">
              {site.display_name}
              <span className="text-slate-500">'s site</span>
            </h1>
            <p className="data text-xs text-slate-500">
              @{site.username} · {site.asset_ip}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {notifyState === 'default' && (
              <button type="button" onClick={enableNotifications} className="btn !py-1.5 !text-xs">
                <BellRing className="h-3.5 w-3.5" aria-hidden /> Alert me
              </button>
            )}
            {notifyState === 'granted' && (
              <span
                className="btn !py-1.5 !text-xs !cursor-default !border-accent/40 !text-accent"
                title="Your browser will pop up an alert when this site is attacked, even if this tab is in the background."
              >
                <BellRing className="h-3.5 w-3.5" aria-hidden /> Alerts on
              </span>
            )}
            {notifyState === 'denied' && (
              <span
                className="btn !py-1.5 !text-xs !cursor-default !text-slate-500"
                title="You blocked notifications for this site. Re-allow them from the padlock icon in the address bar."
              >
                <BellOff className="h-3.5 w-3.5" aria-hidden /> Alerts blocked
              </span>
            )}
            <button type="button" onClick={logout} className="btn !py-1.5 !text-xs">
              <LogOut className="h-3.5 w-3.5" aria-hidden /> Sign out
            </button>
          </div>
        </header>

        {/* Status strip */}
        <div className="mb-5 grid grid-cols-3 gap-3">
          <StatusTile
            label="Failed logins"
            value={String(site.failed_logins)}
            danger={site.failed_logins > 0}
            icon={<Unlock className="h-4 w-4" aria-hidden />}
          />
          <StatusTile
            label="Page status"
            value={site.is_defaced ? 'DEFACED' : 'Normal'}
            danger={site.is_defaced}
            icon={<Skull className="h-4 w-4" aria-hidden />}
          />
          <StatusTile
            label="Data status"
            value={site.is_breached ? 'BREACHED' : 'Safe'}
            danger={site.is_breached}
            icon={<ShieldAlert className="h-4 w-4" aria-hidden />}
          />
        </div>

        <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
          {/* The actual site */}
          <div className="space-y-5">
            {site.is_breached && (
              <motion.div
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                className="glass border-severity-critical/50 p-5"
              >
                <h2 className="flex items-center gap-2 text-sm font-bold text-severity-critical">
                  <ShieldAlert className="h-4 w-4" aria-hidden /> YOU'VE BEEN BREACHED
                </h2>
                <p className="mt-2 text-sm text-slate-300">
                  An attacker stole your data. This was supposed to be private — now it's in their hands:
                </p>
                <div className="mt-3 rounded-md border border-severity-critical/30 bg-black/40 p-3 font-mono text-xs">
                  <p className="text-slate-500">// leaked from the database</p>
                  <p className="text-severity-critical">username: {site.username}</p>
                  <p className="text-severity-critical">private note: {site.secret_note}</p>
                </div>
                <p className="mt-2 text-[11px] text-slate-500">
                  This is why real breaches matter — your data doesn't come back once it's out.
                </p>
              </motion.div>
            )}

            <section
              className={`glass overflow-hidden p-5 transition-colors ${
                site.is_defaced ? 'border-severity-critical/50 bg-severity-critical/5' : ''
              }`}
            >
              <div className="flex items-center justify-between">
                <h2 className="panel-title">Guestbook</h2>
                {site.is_defaced && (
                  <span className="chip border-severity-critical/40 bg-severity-critical/10 text-severity-critical">
                    defaced
                  </span>
                )}
              </div>
              <p className="mt-1 text-xs text-slate-500">Messages people leave on your site.</p>

              <ul className="mt-4 space-y-2">
                {site.guestbook.map((entry) => (
                  <li
                    key={entry.id}
                    className={`rounded-md border p-3 text-sm ${
                      entry.is_attack
                        ? 'border-severity-critical/40 bg-severity-critical/5'
                        : 'border-hairline bg-white/[0.02]'
                    }`}
                  >
                    <p className="mb-1 text-[11px] font-medium text-slate-500">
                      {entry.author} · {timeAgo(entry.created_at)}
                    </p>
                    {/*
                      VULN (deliberate): the message is rendered as raw HTML. A
                      payload like <img src=x onerror=...> actually executes —
                      this is the stored-XSS the class is meant to witness.
                    */}
                    <div className="text-slate-200" dangerouslySetInnerHTML={{ __html: entry.message }} />
                  </li>
                ))}
                {site.guestbook.length === 0 && (
                  <li className="py-6 text-center text-sm text-slate-500">No messages yet.</li>
                )}
              </ul>
            </section>
          </div>

          {/* Live attack feed */}
          <section className="glass flex max-h-[36rem] flex-col overflow-hidden">
            <header className="flex items-center gap-2 border-b border-hairline px-4 py-3">
              <Activity className={`h-4 w-4 ${underAttack ? 'animate-pulse text-severity-critical' : 'text-slate-500'}`} aria-hidden />
              <h2 className="panel-title">Live attack feed</h2>
            </header>
            <ul className="flex-1 divide-y divide-hairline overflow-y-auto">
              <AnimatePresence initial={false}>
                {feed.map((item) => (
                  <motion.li
                    key={item.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="px-4 py-2.5"
                  >
                    <p className="text-[13px] font-medium text-slate-200">{item.message}</p>
                    <p className="data mt-0.5 text-[11px] text-slate-500">
                      {item.attack_type} · from {item.source_country} · {item.source_ip}
                    </p>
                  </motion.li>
                ))}
              </AnimatePresence>
              {feed.length === 0 && (
                <li className="px-4 py-10 text-center text-sm text-slate-500">
                  All quiet. When your site is attacked, you'll see it here in real time.
                </li>
              )}
            </ul>
          </section>
        </div>
      </div>
    </div>
  )
}

function StatusTile({
  label,
  value,
  danger,
  icon,
}: {
  label: string
  value: string
  danger: boolean
  icon: React.ReactNode
}) {
  return (
    <div className={`glass p-3 ${danger ? 'border-severity-critical/40 bg-severity-critical/5' : ''}`}>
      <div className="flex items-center gap-2">
        <span className={danger ? 'text-severity-critical' : 'text-slate-500'}>{icon}</span>
        <p className="panel-title">{label}</p>
      </div>
      <p className={`data mt-1 text-lg font-bold ${danger ? 'text-severity-critical' : 'text-white'}`}>{value}</p>
    </div>
  )
}
