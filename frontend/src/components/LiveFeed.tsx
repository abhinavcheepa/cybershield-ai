import { AnimatePresence, motion } from 'framer-motion'
import { ShieldBan } from 'lucide-react'
import { Link } from 'react-router-dom'

import { SEVERITY_HEX, clockTime, countryFlag } from '../lib/format'
import type { AttackEvent } from '../lib/types'
import { SeverityBadge } from './ui'

export default function LiveFeed({ events, emptyHint }: { events: AttackEvent[]; emptyHint: string }) {
  if (events.length === 0) {
    return <p className="py-10 text-center text-sm text-slate-500">{emptyHint}</p>
  }

  return (
    <ul className="divide-y divide-hairline">
      <AnimatePresence initial={false}>
        {events.map((event) => (
          <motion.li
            key={event.uid}
            layout
            initial={{ opacity: 0, x: -12 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
          >
            <Link to={`/events/${event.uid}`} className="flex items-center gap-3 px-4 py-2.5 row-hover">
              <span
                className="h-8 w-0.5 shrink-0 rounded-full"
                style={{ backgroundColor: SEVERITY_HEX[event.severity] }}
                aria-hidden
              />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <p className="truncate text-[13px] font-medium text-slate-100">{event.attack_type}</p>
                  {event.blocked && (
                    <span title="Auto-blocked at the perimeter">
                      <ShieldBan className="h-3.5 w-3.5 shrink-0 text-emerald-400" aria-label="Blocked" />
                    </span>
                  )}
                </div>
                <p className="data truncate text-[11px] text-slate-500">
                  {countryFlag(event.source_country)} {event.source_ip} → {event.destination_ip}:
                  {event.destination_port}
                </p>
              </div>
              <div className="shrink-0 text-right">
                <SeverityBadge severity={event.severity} />
                <p className="data mt-1 text-[10px] text-slate-500">{clockTime(event.detected_at)}</p>
              </div>
            </Link>
          </motion.li>
        ))}
      </AnimatePresence>
    </ul>
  )
}
