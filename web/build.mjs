import { build, context } from 'esbuild'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'

// One bundle, one HTML file, no external requests: the page must be archivable
// and its hash publishable, so an expert can say which verifier produced a
// verdict. The build is reproducible — two clean checkouts of the same commit
// with the pinned toolchain yield byte-identical `dist/` — and it writes
// `hashes.json` listing the SHA-256 of every shipped file, the commit and the
// tool versions. Nothing here reads the clock or the machine's paths into the
// output; CI builds twice and fails if the two differ.
const serve = process.argv.includes('--serve')
const esbuildVersion = createRequire(import.meta.url)('esbuild/package.json').version

// Provenance: the commit the page was built from, and whether the working tree
// had uncommitted changes in the sources that end up in the bundle. `unknown`
// when git is not available (a tarball): a build that cannot name its commit
// is still a build, it just cannot be compared with anything.
const git = (...args) => {
  try { return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() } catch { return '' }
}
const commit = git('rev-parse', 'HEAD') || 'unknown'
const dirty = git('status', '--porcelain', '--', '.', '../core/src') !== ''

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

const options = {
  entryPoints: ['src/main.ts'],
  // The page bundles the core's **source**, not its `dist`. The published
  // build exists for consumers who compile with `tsc`; here esbuild reads the
  // TypeScript directly, so the bundle whose hash gets published is made from
  // the sources somebody auditing it can read — with no build step in between
  // that could go stale.
  alias: { 'vcap-verify-core': '../core/src/index.ts' },
  bundle: true,
  format: 'esm',
  target: ['es2022'],
  minify: !serve,
  sourcemap: serve,
  metafile: true,
  outfile: 'dist/verifier.js',
  legalComments: 'none'
}

// The HTML carries its own provenance so a reader can compare the page in
// front of them with the repository's CI output without opening devtools.
const html = (fields) => Object.entries(fields).reduce(
  (page, [key, value]) => page.replaceAll(`{{${key}}}`, value),
  readFileSync('src/index.html', 'utf8')
)

rmSync('dist', { recursive: true, force: true })
mkdirSync('dist')

if (serve) {
  const ctx = await context(options)
  await ctx.watch()
  writeFileSync('dist/index.html', html({ bundle_sha256: 'dev build', commit, commit_short: commit.slice(0, 7), esbuild: esbuildVersion }))
  const { host, port } = await ctx.serve({ servedir: 'dist' })
  console.log(`[vcap] verifier at http://${host}:${port}`)
} else {
  const { metafile } = await build(options)
  // The metafile names every input that went into the bundle. An absolute path
  // in it would mean the builder's filesystem leaked into a shipped file, and
  // the same commit would hash differently on another machine.
  const absolute = Object.keys(metafile.inputs).filter((p) => p.startsWith('/'))
  if (absolute.length) throw new Error(`[vcap] absolute paths in the bundle metafile: ${absolute.join(', ')}`)
  writeFileSync('dist/metafile.json', JSON.stringify(metafile, null, 1) + '\n')

  const bundle = readFileSync('dist/verifier.js')
  const bundleHash = sha256(bundle)
  writeFileSync('dist/verifier.js.sha256', `${bundleHash}  verifier.js\n`)
  writeFileSync('dist/index.html', html({ bundle_sha256: bundleHash, commit, commit_short: commit.slice(0, 7), esbuild: esbuildVersion }))

  // Every shipped file, hashed. `hashes.json` cannot list itself; HASHES.md is
  // the same record for a reader. Unsigned: no signing key exists yet (D1),
  // so the way to trust these is to reproduce the build (README).
  const shipped = ['index.html', 'metafile.json', 'verifier.js', 'verifier.js.sha256']
  const files = Object.fromEntries(shipped.map((name) => [name, sha256(readFileSync(`dist/${name}`))]))
  const record = {
    commit,
    dirty,
    toolchain: { esbuild: esbuildVersion, node: process.version },
    files,
    signature: 'none: no signing key exists yet; reproduce the build to trust these hashes'
  }
  writeFileSync('dist/hashes.json', JSON.stringify(record, null, 2) + '\n')
  writeFileSync('dist/HASHES.md', [
    '# vcap verifier — build hashes',
    '',
    `Built from commit \`${commit}\`${dirty ? ' (working tree dirty)' : ''} with esbuild ${esbuildVersion} on Node ${process.version}.`,
    'Not signed: no signing key exists yet. To trust these hashes, rebuild the same commit with the pinned toolchain (see the README) and compare.',
    '',
    '| file | sha256 |',
    '|---|---|',
    ...Object.entries(files).map(([name, hash]) => `| \`${name}\` | \`${hash}\` |`),
    ''
  ].join('\n'))
  console.log(`[vcap] commit ${commit}${dirty ? ' (dirty)' : ''}, esbuild ${esbuildVersion}`)
  for (const [name, hash] of Object.entries(files)) console.log(`[vcap] ${hash}  ${name}`)
}
