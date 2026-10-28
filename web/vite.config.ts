import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'safari18',
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
} as Parameters<typeof defineConfig>[0]);
