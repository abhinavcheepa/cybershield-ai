/**
 * Client for the vulnerable target site (`/site/*`).
 *
 * This is the STUDENT surface, completely separate from the SOC dashboard's
 * auth — different token, different key. A student is not a CyberShield user.
 */

const TOKEN_KEY = 'cybershield.site.token'

export function getSiteToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}
export function setSiteToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

export interface GuestbookEntry {
  id: number
  author: string
  message: string
  is_attack: boolean
  created_at: string
}
export interface SiteView {
  username: string
  display_name: string
  secret_note: string
  asset_ip: string
  is_defaced: boolean
  is_breached: boolean
  failed_logins: number
  guestbook: GuestbookEntry[]
}
async function call<T>(path: string, init: RequestInit = {}, auth = false): Promise<T> {
  const token = getSiteToken()
  const res = await fetch(path, {
    ...init,
    headers: {
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...(auth && token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  })
  if (!res.ok) {
    let detail = `Request failed (${res.status})`
    try {
      const body = await res.json()
      if (typeof body?.detail === 'string') detail = body.detail
      else if (Array.isArray(body?.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join('; ')
    } catch {
      /* keep status message */
    }
    throw new Error(detail)
  }
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T)
}

export const siteApi = {
  register: (body: { username: string; password: string; display_name: string; secret_note?: string }) =>
    call<{ access_token: string; site: SiteView }>('/site/register', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  login: (username: string, password: string) =>
    call<{ access_token: string; site: SiteView }>('/site/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  // A student only ever sees their own site. There is deliberately no way from
  // here to list the class or open someone else's page — the `/site/u/...`
  // endpoints still exist because they are what the attack runner breaks.
  me: () => call<SiteView>('/site/me', {}, true),
}

export interface UnderAttack {
  kind: string
  message: string
  attack_type: string
  severity: string
  threat_score: number
  source_ip: string
  source_country: string
}
