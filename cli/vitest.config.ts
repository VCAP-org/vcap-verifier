import { defineConfig } from 'vitest/config'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  resolve: {
    alias: {
      // The tests run against the core's **source**, not its build output.
      //
      // `vcap-verify-core` publishes `dist`, because a consumer compiling with
      // `tsc` cannot import raw TypeScript — that is the whole reason the
      // package has a build. But inside this repository a build step between
      // "change the core" and "see the test fail" is a step somebody will skip,
      // and then the CLI's tests would pass against a stale `dist`, which is a
      // worse failure than a slow one. CI builds and imports the real package
      // separately, so both paths are covered.
      'vcap-verify-core': fileURLToPath(new URL('../core/src/index.ts', import.meta.url))
    }
  }
})
