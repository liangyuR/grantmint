import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    target: ['es2020', 'edge88', 'firefox78', 'chrome87', 'safari14'],
  },
  server: {
    port: 5173,
    proxy: {
      '/admin': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
})
