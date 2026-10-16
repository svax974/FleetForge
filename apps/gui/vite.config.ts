import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    // En développement web, le frontal est servi par Vite et l'API par
    // `fleetforge-web`. Le mandataire les remet sur la même origine : sans lui il
    // faudrait ouvrir CORS côté serveur, donc écrire pour le développement une
    // permission qui finirait en production.
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${process.env.FLEETFORGE_WEB_PORT ?? 9750}`,
        changeOrigin: false,
      }
    },
    watch: {
      ignored: ['**/src-tauri/**']
    }
  }
})
