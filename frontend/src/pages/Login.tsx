import { motion } from 'framer-motion'
import { AlertCircle, Loader2, LogIn, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Navigate } from 'react-router-dom'

import { useAuth } from '../lib/auth'

const DEMO_ACCOUNTS = [
  { email: 'admin@cybershield.io', role: 'Admin', can: 'Tune detection rules, read the audit log' },
  { email: 'analyst@cybershield.io', role: 'Analyst', can: 'Triage events, run the simulator, request AI analysis' },
  { email: 'viewer@cybershield.io', role: 'Viewer', can: 'Read-only access to every dashboard' },
]
const DEMO_PASSWORD = 'CyberShield#2026'

export default function Login() {
  const { user, login, loading } = useAuth()
  const [email, setEmail] = useState(DEMO_ACCOUNTS[1].email)
  const [password, setPassword] = useState(DEMO_PASSWORD)
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-accent" aria-label="Loading" />
      </div>
    )
  }
  if (user) return <Navigate to="/" replace />

  const submit = async (fieldEvent: React.FormEvent) => {
    fieldEvent.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(email, password)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Sign-in failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
        className="grid w-full max-w-4xl gap-5 lg:grid-cols-[1.05fr_1fr]"
      >
        <section className="glass p-7">
          <div className="flex items-center gap-3">
            <ShieldCheck className="h-8 w-8 text-accent" aria-hidden />
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">
                Cyber<span className="text-accent">Shield</span> AI
              </h1>
              <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Security Operations Centre</p>
            </div>
          </div>

          <p className="mt-6 text-sm leading-relaxed text-slate-400">
            Real-time attack detection, analysis and visualisation. Sign in to reach the live dashboard, the
            global attack map and the detection engine.
          </p>

          <form onSubmit={submit} className="mt-6 space-y-4">
            <div>
              <label htmlFor="email" className="mb-1.5 block text-xs font-medium text-slate-400">
                Email
              </label>
              <input
                id="email"
                type="email"
                autoComplete="username"
                required
                className="field"
                value={email}
                onChange={(changeEvent) => setEmail(changeEvent.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password" className="mb-1.5 block text-xs font-medium text-slate-400">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                className="field"
                value={password}
                onChange={(changeEvent) => setPassword(changeEvent.target.value)}
              />
            </div>

            {error && (
              <p
                role="alert"
                className="flex items-center gap-2 rounded-md border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical"
              >
                <AlertCircle className="h-4 w-4 shrink-0" aria-hidden />
                {error}
              </p>
            )}

            <button type="submit" className="btn btn-primary w-full" disabled={submitting}>
              {submitting ? (
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              ) : (
                <LogIn className="h-4 w-4" aria-hidden />
              )}
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </section>

        <section className="glass p-7">
          <h2 className="panel-title">Lab accounts</h2>
          <p className="mt-2 text-xs text-slate-500">
            Seeded on first run. Every account uses the password{' '}
            <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono text-[11px] text-accent">
              {DEMO_PASSWORD}
            </code>
          </p>

          <ul className="mt-4 space-y-2">
            {DEMO_ACCOUNTS.map((account) => (
              <li key={account.email}>
                <button
                  type="button"
                  onClick={() => {
                    setEmail(account.email)
                    setPassword(DEMO_PASSWORD)
                  }}
                  className="w-full rounded-md border border-hairline bg-white/[0.02] p-3 text-left transition-colors hover:border-accent/40 hover:bg-white/[0.06]"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[12px] text-slate-200">{account.email}</span>
                    <span className="chip border-accent/40 bg-accent/10 text-accent">{account.role}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500">{account.can}</p>
                </button>
              </li>
            ))}
          </ul>

          <p className="mt-5 rounded-md border border-severity-medium/30 bg-severity-medium/5 px-3 py-2.5 text-[11px] leading-relaxed text-slate-400">
            <strong className="text-severity-medium">Educational lab.</strong> Every attack shown here is
            synthetically generated inside the backend process. Nothing is transmitted to any host. Change these
            credentials before exposing this beyond localhost.
          </p>
        </section>
      </motion.div>
    </div>
  )
}
