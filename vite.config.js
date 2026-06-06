import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

const packageJson = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
const buildId = (
  process.env.VITE_APP_VERSION ||
  process.env.GITHUB_SHA ||
  process.env.VERCEL_GIT_COMMIT_SHA ||
  process.env.COMMIT_SHA ||
  new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 12)
).slice(0, 12);
const appVersion = `v${packageJson.version}-${buildId}`;
const apiProxyTarget = process.env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8080';

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(appVersion)
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    allowedHosts: ['frontend', 'localhost', '127.0.0.1'],
    proxy: {
      '/api': {
        target: apiProxyTarget,
        changeOrigin: true
      },
      '/healthz': {
        target: apiProxyTarget,
        changeOrigin: true
      }
    }
  },
  plugins: [
    VitePWA({
      injectRegister: false,
      registerType: 'autoUpdate',
      includeAssets: ['favicon.svg', 'apple-touch-icon.png'],
      workbox: {
        clientsClaim: true,
        skipWaiting: true,
        navigateFallback: 'index.html'
      },
      manifest: {
        id: '/',
        name: 'WeDo',
        short_name: 'WeDo',
        description: 'A mobile-first shared shopping and todo app that works offline.',
        theme_color: '#0b57d0',
        background_color: '#f6f8fb',
        display: 'standalone',
        scope: '/',
        start_url: '/',
        icons: [
          {
            src: 'pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: 'pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png'
          },
          {
            src: 'maskable-icon-512x512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'maskable'
          }
        ]
      }
    })
  ]
});
