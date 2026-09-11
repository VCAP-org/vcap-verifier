import { defineConfig } from 'vitest/config'

// Only the unit tests: `test/*.spec.ts` are Playwright's and run under
// `test:e2e` against a built `dist`, which vitest must not try to execute.
export default defineConfig({
  test: { include: ['test/**/*.test.ts'] },
  resolve: { alias: { 'vcap-verify-core': new URL('../core/src/index.ts', import.meta.url).pathname } }
})
