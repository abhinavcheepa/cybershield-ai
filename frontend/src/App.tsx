import { Suspense, lazy, useEffect } from 'react'
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom'

import { Spinner } from './components/ui'
import { UNAUTHORIZED_EVENT } from './lib/api'
import { useAuth } from './lib/auth'
import { WebSocketProvider } from './lib/ws'

// Every screen is its own chunk. Statically importing them put the whole SOC
// console — Leaflet, Recharts, all seven dashboard pages — into one 1 MB bundle
// that a student had to download in full before /join could paint. Now the
// browser fetches the one screen it is showing, and nothing else.
const Layout = lazy(() => import('./components/Layout'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const EventDetail = lazy(() => import('./pages/EventDetail'))
const LiveMap = lazy(() => import('./pages/LiveMap'))
const LiveRange = lazy(() => import('./pages/LiveRange'))
const Login = lazy(() => import('./pages/Login'))
const Rules = lazy(() => import('./pages/Rules'))
const Simulator = lazy(() => import('./pages/Simulator'))
const StudentJoin = lazy(() => import('./pages/StudentJoin'))
const StudentSite = lazy(() => import('./pages/StudentSite'))
const Timeline = lazy(() => import('./pages/Timeline'))

function FullPage({ label }: { label: string }) {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Spinner label={label} />
    </div>
  )
}

/** Gate for the authenticated shell. */
function Protected() {
  const { user, loading } = useAuth()

  if (loading) return <FullPage label="Restoring session" />
  if (!user) return <Navigate to="/login" replace />

  return (
    <WebSocketProvider>
      <Layout />
    </WebSocketProvider>
  )
}

export default function App() {
  const navigate = useNavigate()
  const { logout } = useAuth()

  // A 401 from any request means the token died mid-session; drop it and
  // bounce to the login screen rather than leaving broken panels on screen.
  useEffect(() => {
    const onUnauthorized = () => {
      logout()
      navigate('/login', { replace: true })
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [logout, navigate])

  return (
    <Suspense fallback={<FullPage label="Loading" />}>
      <Routes>
        <Route path="/login" element={<Login />} />

        {/* Student surface — the vulnerable target site. Public, outside the SOC
            auth guard: a student is not a CyberShield operator. */}
        <Route path="/join" element={<StudentJoin />} />
        <Route path="/mysite" element={<StudentSite />} />

        <Route element={<Protected />}>
          <Route index element={<Dashboard />} />
          <Route path="map" element={<LiveMap />} />
          <Route path="timeline" element={<Timeline />} />
          <Route path="events/:uid" element={<EventDetail />} />
          <Route path="rules" element={<Rules />} />
          <Route path="simulator" element={<Simulator />} />
          <Route path="live-range" element={<LiveRange />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  )
}
