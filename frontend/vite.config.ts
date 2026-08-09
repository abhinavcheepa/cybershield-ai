import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The dev server proxies the API and WebSocket to the backend so the browser
// only ever talks to one origin — no CORS preflight, and `?token=` on the
// WebSocket stays same-origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    // Bind every interface, not just ::1. Without this Vite listens on IPv6
    // loopback only, so anything reaching it over IPv4 — VS Code port
    // forwarding, ngrok, another device on the LAN — is refused.
    host: true,
    // Vite blocks requests whose Host header isn't a known local host, which
    // would reject a Cloudflare/ngrok tunnel with "Blocked request". Allow the
    // tunnel domains so students can reach the lab over the internet.
    allowedHosts: ['localhost', '127.0.0.1', '.trycloudflare.com', '.ngrok-free.app', '.ngrok.io'],
    proxy: {
      // 8010 keeps CyberShield clear of the voice-flow-ai stack on this
      // machine, which owns 8000 (API), 8001 (voice engine) and 8080 (UI).
      '/api': { target: 'http://127.0.0.1:8010', changeOrigin: true },
      // The vulnerable target site + its student WebSocket.
      '/site': { target: 'http://127.0.0.1:8010', changeOrigin: true, ws: true },
      '/ws': { target: 'ws://127.0.0.1:8010', ws: true },
    },
  },
  build: { outDir: 'dist', sourcemap: false },
})
