# Security

## Scope

CyberShield AI is a defensive, educational lab tool. The attack simulator constructs log records in
memory and hands them to the detection engine. It takes no target, opens no sockets, and
`test_simulator_never_opens_a_socket` enforces that by making `socket.connect`, `connect_ex`,
`sendto` and `create_connection` raise while every scenario runs.

Nothing here is an attack tool. There is no exploit delivery, no scanner, no credential-testing
client — only detection logic and synthetic inputs to exercise it.

---

## Controls implemented

| Control | How |
|---|---|
| Password hashing | bcrypt with a per-password salt. Plaintext is never stored or logged |
| JWT auth | HS256, 12-hour default expiry, `sub`/`email`/`role`/`iat`/`exp` |
| RBAC | `viewer < analyst < admin`, enforced by a dependency on the route — not in the UI |
| Audit logging | Actor, action, resource, detail and client IP for every state change |
| Input validation | Pydantic schemas on every request body and query parameter |
| SQL injection | SQLAlchemy bound parameters throughout; no string-built SQL anywhere |
| XSS | React escapes by default. No `dangerouslySetInnerHTML` in the codebase |
| Rate limiting | 300 req/min per IP, `429` + `Retry-After`, memory-bounded |
| Secure headers | `nosniff`, `DENY`, `no-referrer`, CSP, Permissions-Policy, COOP, HSTS on HTTPS |
| CORS | Explicit origin allowlist, never `*` |
| Container hardening | Backend runs as UID 10001, not root |
| Enumeration resistance | Bad password and unknown email return an identical `401` |

### Verified by test, not by assertion

- `test_event_search_is_injection_safe` — sends `' OR 1=1 --` through the search box, requires it to
  match zero rows and leave the table intact.
- `test_viewer_cannot_run_the_simulator`, `test_analyst_cannot_tune_rules_or_read_audit` — RBAC is
  checked server-side, so a crafted request cannot bypass a hidden button.
- `test_websocket_rejects_missing_and_bad_tokens` — both cases close with 4401.
- `test_bad_credentials_are_indistinguishable` — no user enumeration.

---

## Deliberately out of scope

**CSRF.** The API takes its credential from the `Authorization` header, never a cookie. A
cross-origin form post cannot attach that header, so there is no CSRF surface to defend. Adding
tokens would be ceremony against an attack this design already excludes. If you move the token into
a cookie, you must add CSRF protection at the same time.

**Refresh tokens.** A 12-hour access token, then sign in again. Rotation matters when tokens are
short-lived and sessions are long; neither holds in a lab console.

**Per-user notification state.** `is_read` is global. Adding a join table would matter with real
multi-tenant analysts, not with three seeded accounts.

---

## Before you expose this beyond localhost

1. **Change `JWT_SECRET`.** The default is `change-me-in-production` and it is in the repo.
2. **Change the seeded passwords, or delete the seeded users.** They are documented publicly.
3. **Set `CORS_ORIGINS`** to your real frontend origin.
4. **Terminate TLS** in front of the API. HSTS is emitted only over HTTPS.
5. **Keep `?token=` out of proxy access logs.** The WebSocket carries its JWT as a query parameter
   because browsers cannot set headers on a WS handshake. Default nginx log formats record the query
   string — strip it or log without it.
6. **Use PostgreSQL,** not the default SQLite file.
7. **Set `SEED_DEMO_EVENTS=0`** so a real deployment doesn't start with fabricated attack data.

---

## Reporting

This is a teaching project. If you find a flaw in the detection logic or the auth path, open an issue
describing the observation that should have fired and the one that did.
