import type {
  AiStatus,
  LiveCatalog,
  LiveStartConfig,
  LiveState,
  AttackEvent,
  AttackEventDetail,
  CountryOption,
  CountryStat,
  DashboardStats,
  DetectionRule,
  EventPage,
  EventStatus,
  Notification,
  ScenarioInfo,
  SimulationConfig,
  SimulationState,
  ThreatActor,
  TimeBucket,
  TokenResponse,
  User,
} from './types'

const TOKEN_KEY = 'cybershield.token'
const LOGIN_PATH = '/api/auth/login'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

/** Fired when the API rejects our token so the app can bounce to /login. */
export const UNAUTHORIZED_EVENT = 'cybershield:unauthorized'

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken()
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  })

  // A 401 from the login endpoint means "those credentials are wrong", not
  // "your session died" — let the server's own message through. Treating it
  // as an expired session showed "Session expired. Please sign in again." to
  // someone who had simply mistyped a password, and fired the logout event
  // while they were already sitting on the login screen.
  if (response.status === 401 && path !== LOGIN_PATH) {
    setToken(null)
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT))
    throw new ApiError(401, 'Session expired. Please sign in again.')
  }

  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const body = await response.json()
      // FastAPI validation errors arrive as a list of {loc, msg}.
      if (Array.isArray(body?.detail)) {
        detail = body.detail.map((d: { msg: string }) => d.msg).join('; ')
      } else if (typeof body?.detail === 'string') {
        detail = body.detail
      }
    } catch {
      /* non-JSON error body — keep the status-based message */
    }
    throw new ApiError(response.status, detail)
  }

  return response.status === 204 ? (undefined as T) : ((await response.json()) as T)
}

const qs = (params: Record<string, string | number | boolean | undefined | null>) => {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value))
  }
  const out = search.toString()
  return out ? `?${out}` : ''
}

export const api = {
  login: (email: string, password: string) =>
    request<TokenResponse>(LOGIN_PATH, {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
  me: () => request<User>('/api/auth/me'),

  events: (params: {
    page?: number
    page_size?: number
    severity?: string
    status?: string
    attack_type?: string
    country?: string
    search?: string
    hours?: number
  }) => request<EventPage>(`/api/events${qs(params)}`),
  event: (uid: string) => request<AttackEventDetail>(`/api/events/${uid}`),
  timeline: (limit = 50) => request<AttackEvent[]>(`/api/timeline${qs({ limit })}`),
  attackTypes: () => request<string[]>('/api/attack-types'),
  setEventStatus: (uid: string, status: EventStatus, note = '') =>
    request<AttackEventDetail>(`/api/events/${uid}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, note }),
    }),

  stats: (hours = 24) => request<DashboardStats>(`/api/dashboard/stats${qs({ hours })}`),
  timeseries: (minutes = 60, buckets = 30) =>
    request<TimeBucket[]>(`/api/dashboard/timeseries${qs({ minutes, buckets })}`),
  countries: (hours = 24) => request<CountryStat[]>(`/api/countries${qs({ hours })}`),
  countryCatalog: () => request<CountryOption[]>('/api/countries/catalog'),
  actors: (limit = 25) => request<ThreatActor[]>(`/api/threat-intel/actors${qs({ limit })}`),

  rules: () => request<DetectionRule[]>('/api/rules'),
  updateRule: (key: string, patch: Partial<Pick<DetectionRule, 'enabled' | 'confidence' | 'base_score'>>) =>
    request<DetectionRule>(`/api/rules/${key}`, { method: 'PATCH', body: JSON.stringify(patch) }),

  scenarios: () => request<ScenarioInfo[]>('/api/simulation/scenarios'),
  simulationState: () => request<SimulationState>('/api/simulation/state'),
  startSimulation: (config: Partial<SimulationConfig>) =>
    request<SimulationState>('/api/simulation/start', {
      method: 'POST',
      body: JSON.stringify(config),
    }),
  pauseSimulation: () => request<SimulationState>('/api/simulation/pause', { method: 'POST' }),
  resumeSimulation: () => request<SimulationState>('/api/simulation/resume', { method: 'POST' }),
  stopSimulation: () => request<SimulationState>('/api/simulation/stop', { method: 'POST' }),

  notifications: (params: { unread_only?: boolean; limit?: number } = {}) =>
    request<Notification[]>(`/api/notifications${qs(params)}`),
  unreadCount: () => request<{ unread: number }>('/api/notifications/unread-count'),
  markRead: (id: number) => request<Notification>(`/api/notifications/${id}/read`, { method: 'POST' }),
  markAllRead: () => request<{ marked: number }>('/api/notifications/read-all', { method: 'POST' }),

  liveCatalog: () => request<LiveCatalog>('/api/live/catalog'),
  liveState: () => request<LiveState>('/api/live/state'),
  liveStart: (config: LiveStartConfig) =>
    request<LiveState>('/api/live/start', { method: 'POST', body: JSON.stringify(config) }),
  livePause: () => request<LiveState>('/api/live/pause', { method: 'POST' }),
  liveResume: () => request<LiveState>('/api/live/resume', { method: 'POST' }),
  liveStop: () => request<LiveState>('/api/live/stop', { method: 'POST' }),

  aiStatus: () => request<AiStatus>('/api/ai/status'),
  analyze: (uid: string) => request<AttackEventDetail['explanation']>(`/api/ai/analyze/${uid}`, { method: 'POST' }),
}
