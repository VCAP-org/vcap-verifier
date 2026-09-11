import { build, context } from 'esbuild'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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

/**
 * The detector is a second artifact, not part of the bundle. It is reached
 * from a dynamic `import()` of a URL the bundler cannot resolve, so the
 * browser fetches it only when the user asks for a detector — and it is left
 * out of the service worker's precache below, together with the ~34 MB model
 * it would pull. Both are deliberate: the page must be whole without either.
 */
const detectorOptions = {
  entryPoints: ['src/detector.ts'],
  bundle: true,
  format: 'esm',
  target: ['es2022'],
  minify: !serve,
  sourcemap: serve,
  outfile: 'dist/detector.js',
  legalComments: 'none'
}

// Shipped as they are: the web app manifest, its icon, and the detector
// manifest — which today says that no detector build is published, and is read
// only when somebody clicks.
const STATIC = ['manifest.webmanifest', 'icon.svg', 'detector.json']

rmSync('dist', { recursive: true, force: true })
mkdirSync('dist')
for (const name of STATIC) copyFileSync(`src/${name}`, `dist/${name}`)

if (serve) {
  const ctx = await context(options)
  await ctx.watch()
  await build(detectorOptions)
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

  await build(detectorOptions)

  const bundle = readFileSync('dist/verifier.js')
  const bundleHash = sha256(bundle)
  writeFileSync('dist/verifier.js.sha256', `${bundleHash}  verifier.js\n`)
  writeFileSync('dist/index.html', html({ bundle_sha256: bundleHash, commit, commit_short: commit.slice(0, 7), esbuild: esbuildVersion }))

  // The service worker precaches every shipped file. Its cache is named after
  // a build id derived from their hashes, so a new build is a new cache and
  // the old one goes; the worker itself is not in its own list (the browser
  // fetches it), nor is what is written after it — but the hash records are,
  // as URLs, so they are readable offline too.
  const shipped = ['index.html', 'metafile.json', 'verifier.js', 'verifier.js.sha256', 'detector.js', ...STATIC]
  // Everything shipped is cached except the detector module: it is an explicit
  // choice of the user's, it pulls a model far larger than this page, and an
  // offline page that silently held a stale detector would be worse than one
  // that says it has none. `detector.json` stays cached — it is a few hundred
  // bytes and it is what tells the reader why there is no detector.
  const deferred = new Set(['detector.js'])
  const hashOf = (name) => sha256(readFileSync(`dist/${name}`))
  const buildId = sha256(shipped.map((name) => `${name}:${hashOf(name)}`).join('\n')).slice(0, 16)
  await build({
    entryPoints: ['src/sw.ts'],
    bundle: true,
    format: 'iife',
    target: ['es2022'],
    minify: true,
    outfile: 'dist/sw.js',
    legalComments: 'none',
    define: {
      __VCAP_BUILD__: JSON.stringify(buildId),
      __VCAP_PRECACHE__: JSON.stringify([...shipped.filter((name) => !deferred.has(name)), 'hashes.json', 'HASHES.md'])
    }
  })

  // Every shipped file, hashed. `hashes.json` cannot list itself; HASHES.md is
  // the same record for a reader. Unsigned: no signing key exists yet (D1),
  // so the way to trust these is to reproduce the build (README).
  const files = Object.fromEntries([...shipped, 'sw.js'].sort().map((name) => [name, hashOf(name)]))
  const record = {
    commit,
    dirty,
    build_id: buildId,
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
