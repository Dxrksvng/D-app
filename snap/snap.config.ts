import type { SnapConfig } from '@metamask/snaps-cli';

const config: SnapConfig = {
  input: './src/index.tsx',
  server: { port: 8081 },
  polyfills: { buffer: false },
  // Backend URL baked into the bundle. Local Flask testing: default. Production: API_BASE=https://api.example npm run build
  environment: { API_BASE: process.env.API_BASE ?? 'http://localhost:8080' },
};

export default config;
