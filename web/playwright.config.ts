import { defineConfig } from '@playwright/test'

// End-to-end tests run against `dist/` as built (`npm run build` first): what
// is tested is the artifact that ships, not a dev server's view of the source.
export default defineConfig({
  testDir: 'test',
  // `*.spec.ts` here, `*.test.ts` under vitest: the unit tests next door run
  // in a different runner and importing them into this one only breaks it.
  testMatch: '**/*.spec.ts',
  // Every test starts its own static server on a free port: offline behaviour
  // is proved by taking that server down, so the tests cannot share one.
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  use: { browserName: 'chromium' }
})
