# API Reference

Base URL `http://localhost:8010`. Live OpenAPI at `/api/docs`.

Authenticate once, then send `Authorization: Bearer <token>` on every request.
The WebSocket takes the same token as `?token=`.

**Roles** — `viewer` < `analyst` < `admin`. Each endpoint below notes its minimum.

---

## Authentication

### `POST /api/auth/login`

```json
{ "email": "analyst@cybershield.io", "password": "CyberShield#2026" }
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 43200,
  "user": { "id": 2, "email": "analyst@cybershield.io", "full_name": "Daniel Okafor", "role": "analyst", "is_active": true, "last_login_at": "2026-08-02T10:14:02Z" }
}
```

Wrong password and unknown email both return `401 {"detail": "Invalid email or password"}` — the
API does not confirm which addresses exist.

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/auth/me` | viewer | Current user; used to validate a restored session |
| `GET /api/auth/users` | admin | All users |
| `GET /api/auth/audit` | admin | Audit log, newest first |

---

## Attack events

### `GET /api/events`

| Query | Default | Notes |
|---|---|---|
| `page` / `page_size` | 1 / 25 | `page_size` max 200 |
| `severity` | — | `critical` `high` `medium` `low` `info` |
| `status` | — | `active` `investigating` `mitigated` `resolved` `false_positive` |
| `attack_type` | — | Exact match; see `/api/attack-types` |
| `country` | — | ISO-3166 alpha-2 source country |
| `search` | — | Substring over IP, attack type, country. Bound parameter — payloads are literal text |
| `hours` | 24 | Lookback window |

```json
{ "items": [ { "uid": "f9652f9d-…", "detected_at": "2026-08-02T10:00:27Z", "attack_type": "ICMP Flood", "severity": "medium", "status": "active", "threat_score": 66.0, "source_ip": "175.45.134.42", "source_country": "KP", "destination_ip": "10.0.0.53", "blocked": false, "asset": { "name": "dns-resolver-01" } } ], "total": 285, "page": 1, "page_size": 25 }
```

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/timeline?limit=50` | viewer | Flat chronological list, no pagination envelope |
| `GET /api/events/{uid}` | viewer | Adds `raw_log`, `indicators`, `explanation` |
| `PATCH /api/events/{uid}/status` | analyst | `{"status": "investigating", "note": "…"}` |
| `GET /api/attack-types` | viewer | Names for the filter dropdown |

---

## Dashboard

### `GET /api/dashboard/stats?hours=24`

Returns headline counters (`total_attacks`, `active_attacks`, `critical_attacks`,
`blocked_attacks`, `threat_score`, `trend_pct`, `unique_attackers`, `countries_involved`,
`avg_response_time_ms`), a `by_severity` breakdown, and four ranked widgets:
`top_attack_types`, `top_targeted_assets`, `top_attackers`, `top_targeted_services`.

### `GET /api/dashboard/timeseries?minutes=60&buckets=30`

Continuous buckets — quiet periods still emit a row, so the chart never invents a gap.

```json
[{ "timestamp": "2026-08-02T09:30:00Z", "count": 14, "critical": 6, "high": 4, "blocked": 9, "threat_score": 71.2, "avg_response_ms": 210 }]
```

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/countries?hours=24` | viewer | Per-country totals **with lat/lon** for the map |
| `GET /api/countries/catalog` | viewer | Every selectable country |
| `GET /api/threat-intel/actors?limit=25` | viewer | Source IPs ranked by threat score |
| `GET /api/incidents` | viewer | Correlated incidents |

---

## Detection rules

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/rules` | viewer | Full catalog with hit counts |
| `PATCH /api/rules/{key}` | **admin** | `{"enabled": false}`, `confidence` 0–1, `base_score` 0–100 |

Toggling a rule updates the running engine immediately — no restart. Out-of-range values return
`422`. Every change is written to the audit log.

---

## Attack simulation

All synthetic. There is no target parameter by design.

### `POST /api/simulation/start` — analyst

```json
{
  "scenarios": ["sql_injection", "port_scan"],
  "source_countries": ["RU", "CN"],
  "events_per_minute": 60,
  "randomize_ips": true,
  "repeat": true
}
```

Every field is optional: `[]` for `scenarios` runs all of them, `[]` for `source_countries` uses a
weighted global mix. Unknown scenario keys or country codes return `422` naming the bad value.
Calling `start` while running applies the new configuration in place.

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/simulation/scenarios` | viewer | The 8 scenarios and what each should trigger |
| `GET /api/simulation/state` | viewer | Status, config, counters |
| `POST /api/simulation/pause` / `resume` / `stop` | analyst | Transport controls |
| `GET /api/simulation/runs` | viewer | Run history |

---

## Notifications

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/notifications?unread_only=&limit=` | viewer | Newest first; raised for high/critical only |
| `GET /api/notifications/unread-count` | viewer | Badge count |
| `POST /api/notifications/{id}/read` | viewer | Mark one read |
| `POST /api/notifications/read-all` | viewer | Returns `{"marked": n}` |

---

## AI analysis

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/ai/status` | viewer | Whether a live model is configured |
| `GET /api/ai/explanation/{uid}` | viewer | Stored explanation |
| `POST /api/ai/analyze/{uid}` | analyst | Regenerate and store |

Every explanation carries `why_detected`, `potential_impact`, `mitre_mapping`,
`recommended_mitigation`, `future_prevention[]`, `confidence` and `generated_by`.

Without `ANTHROPIC_API_KEY` the built-in analyst templates are used. `analyze` **never** 500s on a
missing key or a failed upstream call — it falls back to templates and reports that in `generated_by`.

---

## WebSocket

```
ws://localhost:8010/ws?token=<jwt>
```

Rejects a missing or invalid token with close code **4401**. Send any text as a keepalive.

| `type` | `data` | Meaning |
|---|---|---|
| `connected` | `{client_count}` | Handshake accepted |
| `attack_event` | full event | New detection — drives feed, map, counters |
| `notification` | notification | High/critical alert raised |
| `event_updated` | `{uid, status}` | Someone triaged an event |
| `simulation` | simulation state | Simulator started/paused/stopped |

---

## Errors

Standard codes: `401` unauthenticated, `403` role too low (detail names the required role), `404`
not found, `422` validation failure, `429` rate limited (`Retry-After: 60`).

Rate limit: 300 requests/minute per IP, configurable via `RATE_LIMIT_PER_MINUTE`. `/ws` and
`/api/health` are exempt.
