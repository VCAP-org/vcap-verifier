import { cpSync, existsSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

// The conformance vectors live in vcap-spec, a private repository until D4.
// A snapshot is committed here so CI needs no cross-repository token; the
// submodule is the source of truth and this script keeps the snapshot equal to
// it. `--check` fails when they differ, which is how CI notices a stale copy
// whenever the submodule is available.
const source = join(import.meta.dirname, '..', 'spec', 'vectors')
const snapshot = join(import.meta.dirname, 'vectors')
const check = process.argv.includes('--check')

// `edge-cases/` is not part of the versioned corpus: vcap-spec regenerates it
// on demand from a sweep, it is not in MANIFEST.json, and nothing here reads
// it. Copying it would put a few hundred generated files into a public
// repository that has no runner for them.
const EXCLUDED = new Set(['edge-cases'])

const listing = (dir) => {
  const out = []
  const walk = (d, prefix) => {
    for (const name of readdirSync(d).sort()) {
      if (!prefix && EXCLUDED.has(name)) continue
      const p = join(d, name); const rel = prefix ? `${prefix}/${name}` : name
      if (statSync(p).isDirectory()) walk(p, rel)
      else if (name !== '.DS_Store') out.push([rel, readFileSync(p)])
    }
  }
  walk(dir, '')
  return out
}

if (!existsSync(source) || readdirSync(source).length === 0) {
  // In --check the missing submodule is the failure: CI checks it out, so its
  // absence means the snapshot was compared against nothing and the gate would
  // pass without having read a single vector. Outside --check a working copy
  // without the submodule is normal and the snapshot is left alone.
  if (check) { console.error('[vcap] spec submodule not checked out: nothing to check the snapshot against (git submodule update --init)'); process.exit(1) }
  console.log('[vcap] spec submodule not checked out; snapshot left as is')
  process.exit(0)
}
const equal = existsSync(snapshot) && (() => {
  const a = listing(source); const b = listing(snapshot)
  return a.length === b.length && a.every(([rel, bytes], i) => b[i][0] === rel && bytes.equals(b[i][1]))
})()
if (check) {
  if (!equal) { console.error('[vcap] core/vectors differs from spec/vectors: run `npm run vectors:sync` in core/'); process.exit(1) }
  console.log('[vcap] snapshot equals the submodule')
} else {
  rmSync(snapshot, { recursive: true, force: true })
  cpSync(source, snapshot, { recursive: true, filter: (p) => !p.endsWith('.DS_Store') && !EXCLUDED.has(relative(source, p)) })
  const version = existsSync(join(snapshot, 'VERSION')) ? readFileSync(join(snapshot, 'VERSION'), 'utf8').trim() : 'unversioned'
  console.log(`[vcap] snapshot refreshed from spec/vectors (corpus ${version}, ${listing(snapshot).length} files)`)
}
