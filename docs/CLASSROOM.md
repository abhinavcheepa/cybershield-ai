# Running the Live Class

How to run the real-attack exercise where each student owns a website and feels
it get attacked. No LAN required — students join from their own laptops over the
internet.

> **This is a lab.** The attacks only ever hit the practice "student site" that
> runs on your machine. The attack runner's target is fixed in server config and
> cannot be pointed at any real website. Tell students to use a throwaway
> password they don't use anywhere else.

---

## The picture

```
 Students' laptops                    Your laptop
 ─────────────────                    ───────────
  browser  ──►  https://xxx.trycloudflare.com  (Cloudflare tunnel)
                        │
                        ▼
                   Backend :8010
                     built frontend  (/join  /mysite  dashboard)
                     /site/*         (vulnerable site)
                     /api/*          (SOC + control)
                        ▲
             You: CyberShield dashboard ──► "Live Attack Range" ──► REAL attacks
```

- Students see **/join** and **/mysite** — their own site.
- You see the full **CyberShield dashboard** and drive attacks from **Live Attack Range**.

One port, and it serves the *built* frontend rather than the Vite dev server. The
dev server sends every source file separately and unminified, so through a single
tunnel the join page used to take a long time to appear on a phone or a slow
connection. The build is one small page plus a handful of cached assets.

> **Running this class more than once?** Deploy instead of tunnelling — a stable
> URL, no laptop to keep open, and it survives you closing the lid. See
> [DEPLOY.md](DEPLOY.md); the classroom steps below are otherwise identical.

---

## Step by step

### 1. Build the frontend (once)

```bash
cd frontend && npm install && npm run build
```

Re-run this only when you change the frontend. `share-with-class.ps1` does it for
you the first time if you skip it.

### 2. Start the backend (terminal 1)

```bash
cd backend && .venv/Scripts/python -m uvicorn app.main:app --port 8010
```

It serves the API, the vulnerable student site *and* the build from step 1.

### 3. Open the tunnel (terminal 2)

```bash
powershell -ExecutionPolicy Bypass -File share-with-class.ps1
```

It prints a line like:

```
https://brave-lions-share.trycloudflare.com
```

That is your class URL. (The first run downloads `cloudflared`, an official
Cloudflare tool, ~50 MB.)

### 4. Give students the join link

Share **`https://<your-tunnel>.trycloudflare.com/join`**.

Each student:
1. Opens the link on their laptop.
2. Picks a username, a **fake** password, and a display name.
3. Lands on **their own site** at `/mysite` — a guestbook, a private note, and a
   live "under attack" feed that is quiet for now.

### 5. Watch who's registered

On your machine open the CyberShield dashboard (`http://localhost:8010`), sign in
as **analyst@cybershield.io / CyberShield#2026**, go to **Live Attack Range**. The
right-hand "class" panel lists every student site as it appears.

### 6. Launch real attacks

On **Live Attack Range**:
- **Target**: "Everyone" to rotate across the class, or pick one student.
- **Attacks**: brute-force, SQL-injection (login bypass + password dump), stored
  XSS (defacement), path traversal (file leak).
- **Intensity**: Gentle / Steady / Heavy.
- Press **Launch attacks**.

### 7. What the students feel (instantly, on their own screen)

- A red **🔴 YOUR SITE IS UNDER ATTACK** banner.
- **Failed logins** counter climbing as their login is brute-forced.
- **Page status → DEFACED**: their guestbook fills with attacker messages and
  injected content actually runs.
- **Data status → BREACHED**: a panel shows *their own* private note leaked back
  to them — "this was supposed to be private."
- A live feed of each attack with the attacker's country and IP.

Meanwhile your dashboard's map, timeline, charts and notification centre light up
with the same events in real time — because they are the same real events.

### 8. Stop

Press **Stop** on Live Attack Range. Close the tunnel with Ctrl+C in terminal 3.

---

## Good demo flow (10 minutes)

1. Everyone registers (2 min) — let them personalise their site and their private
   note. Tell them to tap **Alert me** so their browser pops up an alert when the
   attacks start.
2. Start with **one** attack type at **Gentle** on **Everyone** — let them notice
   the banner. Ask "what's happening to your site?"
3. Turn on **SQL-injection dump** — every password in the class leaks. Show it on
   the projector via `/site/search`.
4. Turn on **XSS** — pages deface. Now it's personal.
5. Open a student's event on your dashboard → show the **AI explanation** and the
   **MITRE** mapping. Bridge from "it hurt" to "here's the technique and the fix."

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "Blocked request. This host is not allowed" | You are tunnelling the Vite dev server instead of the backend. Tunnel 8010 — `share-with-class.ps1` does. (If you deliberately tunnel `npm run dev`, `vite.config.ts` `allowedHosts` covers the tunnel domains.) |
| The tunnel URL shows JSON, not the app | The backend started before `frontend/dist` existed, so it has no build to serve. Build, then restart it. |
| Students see the join page but register fails | Backend not up on 8010, or the tunnel points at the wrong port (must be 8010). |
| The link takes ages to open on a phone | You are on the dev server, not the build — see the row above. On the build a student downloads ~110 KB. |
| Tunnel URL changes every run | Quick tunnels are ephemeral. Re-share the new link, or [deploy](DEPLOY.md) for a URL that never changes. |
| Live feed not updating on a student's page | Their WebSocket dropped; it reconnects automatically. A refresh forces it. |
| Attacks do nothing | No students registered yet, or every attack type is deselected on Live Attack Range. |

---

## Safety recap

- The target is **hard-locked** to the lab site (`TARGET_BASE_URL`); no button can
  point it elsewhere.
- Everything is synthetic accounts on a throwaway database. Delete
  `backend/cybershield.db` to wipe the class and start fresh.
- Do not leave the tunnel open after class — anyone with the link can register.
