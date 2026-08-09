import { motion } from 'framer-motion'
import { AlertCircle, Loader2, LogIn, ShieldAlert, UserPlus } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { setSiteToken, siteApi } from '../lib/siteApi'

type Mode = 'register' | 'login'

export default function StudentJoin() {
  const navigate = useNavigate()
  const [mode, setMode] = useState<Mode>('register')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [secret, setSecret] = useState('My secret: I still sleep with a night lamp.')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (formEvent: React.FormEvent) => {
    formEvent.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const result =
        mode === 'register'
          ? await siteApi.register({ username, password, display_name: displayName || username, secret_note: secret })
          : await siteApi.login(username, password)
      setSiteToken(result.access_token)
      navigate('/mysite', { replace: true })
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Something went wrong')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-void p-4">
      <motion.div
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
        className="w-full max-w-md"
      >
        <div className="mb-5 text-center">
          <h1 className="text-2xl font-bold tracking-tight text-white">
            My<span className="text-accent">Site</span>
          </h1>
          <p className="mt-1 text-sm text-slate-400">Build your own little website in seconds.</p>
        </div>

        <div className="glass p-6">
          <div className="mb-5 grid grid-cols-2 gap-1 rounded-lg border border-hairline p-1">
            {(['register', 'login'] as Mode[]).map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => {
                  setMode(option)
                  setError(null)
                }}
                className={`rounded-md py-2 text-sm font-medium capitalize transition-colors ${
                  mode === option ? 'bg-accent-soft text-accent' : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                {option === 'register' ? 'Create my site' : 'Sign in'}
              </button>
            ))}
          </div>

          <form onSubmit={submit} className="space-y-3">
            <div>
              <label htmlFor="u" className="mb-1 block text-xs font-medium text-slate-400">
                Username
              </label>
              <input
                id="u"
                className="field"
                required
                autoComplete="username"
                value={username}
                onChange={(changeEvent) => setUsername(changeEvent.target.value)}
                placeholder="e.g. riya"
              />
            </div>

            {mode === 'register' && (
              <div>
                <label htmlFor="d" className="mb-1 block text-xs font-medium text-slate-400">
                  Display name
                </label>
                <input
                  id="d"
                  className="field"
                  value={displayName}
                  onChange={(changeEvent) => setDisplayName(changeEvent.target.value)}
                  placeholder="Your name"
                />
              </div>
            )}

            <div>
              <label htmlFor="p" className="mb-1 block text-xs font-medium text-slate-400">
                Password
              </label>
              <input
                id="p"
                type="password"
                className="field"
                required
                autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                value={password}
                onChange={(changeEvent) => setPassword(changeEvent.target.value)}
              />
            </div>

            {mode === 'register' && (
              <div>
                <label htmlFor="s" className="mb-1 block text-xs font-medium text-slate-400">
                  A private note (only you should ever see this)
                </label>
                <input
                  id="s"
                  className="field"
                  value={secret}
                  onChange={(changeEvent) => setSecret(changeEvent.target.value)}
                />
              </div>
            )}

            {error && (
              <p role="alert" className="flex items-center gap-2 rounded-md border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
                <AlertCircle className="h-4 w-4 shrink-0" aria-hidden />
                {error}
              </p>
            )}

            <button type="submit" className="btn btn-primary w-full" disabled={busy}>
              {busy ? (
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              ) : mode === 'register' ? (
                <UserPlus className="h-4 w-4" aria-hidden />
              ) : (
                <LogIn className="h-4 w-4" aria-hidden />
              )}
              {mode === 'register' ? 'Create my site' : 'Sign in'}
            </button>
          </form>
        </div>

        <p className="mt-4 flex items-start gap-2 rounded-md border border-severity-medium/30 bg-severity-medium/5 px-3 py-2.5 text-[11px] leading-relaxed text-slate-400">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-severity-medium" aria-hidden />
          <span>
            This is a security-class exercise. Your site here is deliberately weak so you can watch what a
            real attack feels like. Use a <strong>fake</strong> password you don't use anywhere else.
          </span>
        </p>
      </motion.div>
    </div>
  )
}
