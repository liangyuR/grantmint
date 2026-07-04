import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Proxy the server's real surfaces in dev so cookies stay same-origin (the admin session +
// XSRF-TOKEN cookies are not sent cross-origin without this). /api is left in place in case
// something else still relies on it, but the dashboard talks to /admin, /v1, /issuance, /webhooks.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/admin': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/v1': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/issuance': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/webhooks': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
