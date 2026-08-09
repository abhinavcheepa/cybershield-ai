import { useQueryClient } from '@tanstack/react-query'
import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import { getToken } from './api'
import { useAuth } from './auth'
import type { AttackEvent, Notification, SimulationState } from './types'

interface WsValue {
  connected: boolean
  /** Rolling buffer of the newest events, newest first. Feeds the map and live feed. */
  recentEvents: AttackEvent[]
  /** Increments on every event — a cheap dependency for "something arrived". */
  eventTick: number
  simulation: SimulationState | null
}

const BUFFER_SIZE = 80

/** How often live traffic is allowed to trigger a React Query refetch. */
const REFETCH_THROTTLE_MS = 2500

const WsContext = createContext<WsValue>({
  connected: false,
  recentEvents: [],
  eventTick: 0,
  simulation: null,
})

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()

  const [connected, setConnected] = useState(false)
  const [recentEvents, setRecentEvents] = useState<AttackEvent[]>([])
  const [eventTick, setEventTick] = useState(0)
  const [simulation, setSimulation] = useState<SimulationState | null>(null)

  const lastRefetch = useRef(0)
  const pendingRefetch = useRef<number | null>(null)

  useEffect(() => {
    if (!user) {
      setConnected(false)
      return
    }

    let socket: WebSocket | null = null
    let reconnectTimer: number | undefined
    let heartbeat: number | undefined
    let attempt = 0
    let closed = false

    // A burst of events shouldn't mean a burst of refetches; coalesce them.
    const scheduleRefetch = () => {
      const invalidate = () => {
        lastRefetch.current = Date.now()
        pendingRefetch.current = null
        for (const key of ['stats', 'timeseries', 'countries', 'timeline', 'events', 'notifications', 'actors']) {
          queryClient.invalidateQueries({ queryKey: [key] })
        }
      }
      const elapsed = Date.now() - lastRefetch.current
      if (elapsed >= REFETCH_THROTTLE_MS) invalidate()
      else if (pendingRefetch.current === null) {
        pendingRefetch.current = window.setTimeout(invalidate, REFETCH_THROTTLE_MS - elapsed)
      }
    }

    const connect = () => {
      if (closed) return
      const token = getToken()
      if (!token) return

      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      socket = new WebSocket(`${protocol}://${window.location.host}/ws?token=${encodeURIComponent(token)}`)

      socket.onopen = () => {
        attempt = 0
        setConnected(true)
        // The server only reads to notice disconnects; this keeps the socket
        // and any intermediate proxy from idling out.
        heartbeat = window.setInterval(() => socket?.readyState === WebSocket.OPEN && socket.send('ping'), 25_000)
      }

      socket.onmessage = (message) => {
        const { type, data } = JSON.parse(message.data) as { type: string; data: unknown }
        switch (type) {
          case 'attack_event': {
            const event = data as AttackEvent
            setRecentEvents((previous) => [event, ...previous].slice(0, BUFFER_SIZE))
            setEventTick((tick) => tick + 1)
            scheduleRefetch()
            break
          }
          case 'notification':
            queryClient.invalidateQueries({ queryKey: ['notifications'] })
            queryClient.setQueryData<Notification[]>(['notifications', 'recent'], (old) =>
              old ? [data as Notification, ...old].slice(0, 50) : old,
            )
            break
          case 'event_updated':
            scheduleRefetch()
            break
          case 'simulation':
            setSimulation(data as SimulationState)
            queryClient.setQueryData(['simulation', 'state'], data)
            break
        }
      }

      socket.onclose = () => {
        setConnected(false)
        window.clearInterval(heartbeat)
        if (closed) return
        // Exponential backoff, capped — a backend restart shouldn't spin the tab.
        attempt += 1
        reconnectTimer = window.setTimeout(connect, Math.min(1000 * 2 ** attempt, 15_000))
      }

      socket.onerror = () => socket?.close()
    }

    connect()

    return () => {
      closed = true
      window.clearInterval(heartbeat)
      window.clearTimeout(reconnectTimer)
      if (pendingRefetch.current !== null) window.clearTimeout(pendingRefetch.current)
      socket?.close()
    }
  }, [user, queryClient])

  const value = useMemo(
    () => ({ connected, recentEvents, eventTick, simulation }),
    [connected, recentEvents, eventTick, simulation],
  )

  return <WsContext.Provider value={value}>{children}</WsContext.Provider>
}

export function useLive(): WsValue {
  return useContext(WsContext)
}
