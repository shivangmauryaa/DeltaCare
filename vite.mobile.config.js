import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: 'mobile',
  plugins: [react()],
  base: '/',
  server: {
    host: '0.0.0.0',
    port: 8080,
    proxy: { '/api': 'http://localhost:3001' },
  },
  build: {
    outDir: 'dist-mobile',
    emptyOutDir: true,
  },
});