import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'rate-limit': 'src/middleware/rate-limit/index.ts',
    auth: 'src/middleware/auth/index.ts',
    csrf: 'src/middleware/csrf/index.ts',
    headers: 'src/middleware/headers/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  minify: false,
  external: ['next', 'zod', '@upstash/redis', 'ioredis'],
  esbuildOptions(options) {
    options.platform = 'neutral' // Edge Runtime compatible
  },
})
