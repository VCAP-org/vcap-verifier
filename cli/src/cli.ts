#!/usr/bin/env -S npx tsx
import { run } from './main.js'

// The shim, so that `main.ts` is importable without running anything: a module
// that sets `process.exitCode` on import cannot be tested in-process.
process.exitCode = await run(process.argv.slice(2))
