#!/usr/bin/env -S npx tsx
import { run } from './main.js'

// The shim, so that `main.ts` is importable without running anything: a module
// that sets `process.exitCode` on import cannot be tested in-process.
// `run` answers every file it can; anything that still escapes is a bug of
// this tool, and it exits 70 (sysexits' EX_SOFTWARE) with the message rather
// than 1, which would read as a verdict about the file.
try {
  process.exitCode = await run(process.argv.slice(2))
} catch (error) {
  process.stderr.write(`vcap-verify: internal error: ${error instanceof Error ? error.message : String(error)}\n`)
  process.exitCode = 70
}
