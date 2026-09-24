import { build, context } from 'esbuild'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'

// One bundle, one HTML file, no external requests but the chain read an anchor
// needs (`chains.json`, only for a proof that carries one): the page must be archivable
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
const dirty = git('status', '--porcelain', '--', '.', '../core/src', '../trust') !== ''

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

/**
 * The registry the page links a photo's mark to: the reference deployment's,
 * unless `VCAP_TRACE_URL` names another at build time. A build for another
 * deployment points at its own registry without a code change; the published
 * build is made with the default, so its hashes reproduce from a plain clone.
 */
const TRACE_URL = process.env.VCAP_TRACE_URL || 'https://console.vcap.gregoriogalante.com/t'

/**
 * The Content-Security-Policy of the page, from the files it describes: the
 * RPC origins of `trust/chains.json` (the one place a verdict may ask
 * anything), and the SHA-256 of the one inline `<style>`, so no other style
 * can be injected. `wasm-unsafe-eval` is what onnxruntime needs to compile the
 * detector's engine; `blob:` workers are its threads. Everything else is the
 * page's own origin.
 */
const csp = (template) => {
  const style = /<style>([\s\S]*?)<\/style>/.exec(template)
  if (!style) throw new Error('[vcap] index.html has no inline <style> to hash')
  const styleHash = createHash('sha256').update(style[1]).digest('base64')
  const chains = JSON.parse(readFileSync('../trust/chains.json', 'utf8')).chains
  const rpc = [...new Set(Object.values(chains).flatMap((c) => c.rpc.map((url) => new URL(url).origin)))]
  return [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    `style-src 'self' 'sha256-${styleHash}'`,
    "img-src 'self' blob: data:",
    "font-src 'self'",
    `connect-src 'self' ${rpc.join(' ')}`,
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'"
  ].join('; ')
}

const options = {
  entryPoints: ['src/main.ts'],
  // The page bundles the core's **source**, not its `dist`. The published
  // build exists for consumers who compile with `tsc`; here esbuild reads the
  // TypeScript directly, so the bundle whose hash gets published is made from
  // the sources somebody auditing it can read — with no build step in between
  // that could go stale.
  alias: { 'vcap-verify-core': '../core/src/index.ts' },
  define: { __VCAP_TRACE_URL__: JSON.stringify(TRACE_URL) },
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
const html = (fields) => {
  const template = readFileSync('src/index.html', 'utf8')
  return Object.entries({ ...fields, csp: csp(template) }).reduce(
    (page, [key, value]) => page.replaceAll(`{{${key}}}`, value),
    template
  )
}

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

/**
 * A third artifact, behind the second: `detector.js` is the manifest and the
 * digest check, and only once the downloaded bytes hash to what the manifest
 * pins does it import this one, which carries onnxruntime-web. The split is
 * not cosmetic — an engine is code, and code that runs before the model has
 * been checked is code the manifest does not cover.
 */
const runtimeOptions = {
  entryPoints: ['src/detector-runtime.ts'],
  bundle: true,
  format: 'esm',
  target: ['es2022'],
  minify: !serve,
  sourcemap: serve,
  outfile: 'dist/detector-runtime.js',
  legalComments: 'none'
}

// onnxruntime-web loads its WebAssembly binary at run time, by name, from
// wherever the runtime module tells it to — here, next to the page. Copied
// rather than fetched from a CDN: the page must be archivable, and a verifier
// that pulls an engine from someone else's host is a verifier with a third
// party in it. The `.jsep` binary is the one that carries both execution
// providers, WASM SIMD and WebGPU.
// The glue module is loaded by `import()` at run time and it in turn fetches
// the binary, so both names have to sit next to the page.
const ORT_ASSETS = ['ort-wasm-simd-threaded.jsep.mjs', 'ort-wasm-simd-threaded.jsep.wasm']
const ortDist = dirname(createRequire(import.meta.url).resolve('onnxruntime-web'))

// Shipped as they are: the web app manifest, its icon, and the detector
// manifest — which today says that no detector build is published, and is read
// only when somebody clicks.
const STATIC = ['manifest.webmanifest', 'icon.svg', 'detector.json']

// The typefaces, served next to the page like everything else it uses: a font
// from somebody else's host is a third party in the page, and a request the
// offline cache would have to trust. Flat in dist/ so `sha256sum dist/*`
// still reads every shipped file. The licence travels with the fonts (OFL).
const FONTS = ['Geist-Variable.woff2', 'GeistMono-Variable.woff2', 'Geist-OFL.txt']

rmSync('dist', { recursive: true, force: true })
mkdirSync('dist')
for (const name of STATIC) copyFileSync(`src/${name}`, `dist/${name}`)
for (const name of FONTS) copyFileSync(`src/fonts/${name}`, `dist/${name}`)
// The trust set, published verbatim beside the page. It is the same bytes the
// bundle pinned, so a reader can fetch it, recompute each log_id from its key
// and see exactly whom this build believes — and it is covered by hashes.json
// like every other shipped file.
copyFileSync('../trust/logs.json', 'dist/logs.json')
// The timestamping authorities, likewise, and as a separate document: a reader
// who refuses the log we run and keeps a third party's clock has taken a
// position the page has to be able to represent.
copyFileSync('../trust/tsa.json', 'dist/tsa.json')
// The chains an anchor is read from and the RPC asked, likewise: the one
// request a verdict can make is to an endpoint named in a published file.
copyFileSync('../trust/chains.json', 'dist/chains.json')
for (const name of ORT_ASSETS) copyFileSync(join(ortDist, name), `dist/${name}`)

if (serve) {
  const ctx = await context(options)
  await ctx.watch()
  await build(detectorOptions)
  await build(runtimeOptions)
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
  await build(runtimeOptions)

  const bundle = readFileSync('dist/verifier.js')
  const bundleHash = sha256(bundle)
  writeFileSync('dist/verifier.js.sha256', `${bundleHash}  verifier.js\n`)
  writeFileSync('dist/index.html', html({ bundle_sha256: bundleHash, commit, commit_short: commit.slice(0, 7), esbuild: esbuildVersion }))

  // The service worker precaches every shipped file. Its cache is named after
  // a build id derived from their hashes, so a new build is a new cache and
  // the old one goes; the worker itself is not in its own list (the browser
  // fetches it), nor is what is written after it — but the hash records are,
  // as URLs, so they are readable offline too.
  const shipped = ['index.html', 'metafile.json', 'verifier.js', 'verifier.js.sha256', 'detector.js', 'detector-runtime.js', 'logs.json', 'tsa.json', 'chains.json', ...ORT_ASSETS, ...STATIC, ...FONTS]
  // Everything shipped is cached except the detector module: it is an explicit
  // choice of the user's, it pulls a model far larger than this page, and an
  // offline page that silently held a stale detector would be worse than one
  // that says it has none. `detector.json` stays cached — it is a few hundred
  // bytes and it is what tells the reader why there is no detector.
  const deferred = new Set(['detector.js', 'detector-runtime.js', ...ORT_ASSETS])
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
  // the same record for a reader. The signature over this manifest is
  // **detached** and produced afterwards by the key holder (`bin/sign-build`):
  // it is published as `hashes.json.sig` next to the page and recorded in
  // `signing/manifests.jsonl`, and it is never a file of `dist/` — a signature
  // inside the tree would change the tree it certifies and the build would
  // stop reproducing the moment it was signed.
  const files = Object.fromEntries([...shipped, 'sw.js'].sort().map((name) => [name, hashOf(name)]))
  const record = {
    commit,
    dirty,
    build_id: buildId,
    toolchain: { esbuild: esbuildVersion, node: process.version },
    files,
    signature: {
      detached: 'hashes.json.sig',
      algorithm: 'ed25519',
      message: 'vcap/1.0/verifier-build\\n<sha256 of this file>\\n<commit>\\n',
      key: 'signing/public-key.pem in the vcap-verifier repository',
      proves: 'continuity: the same key signed the earlier manifests in signing/manifests.jsonl',
      does_not_prove: 'identity: no legal entity, no certificate, no eIDAS signature of any kind. Reproduce the build (README) — that, not this signature, is what makes the hashes worth something.'
    }
  }
  writeFileSync('dist/hashes.json', JSON.stringify(record, null, 2) + '\n')
  writeFileSync('dist/HASHES.md', [
    '# vcap verifier — build hashes',
    '',
    `Built from commit \`${commit}\`${dirty ? ' (working tree dirty)' : ''} with esbuild ${esbuildVersion} on Node ${process.version}.`,
    'A detached Ed25519 signature over this manifest is published as `hashes.json.sig`, next to it. It proves **continuity** — the same key signed the earlier manifests — and **not identity**: there is no legal entity behind that key and no certificate. What makes these hashes worth something is that anyone can rebuild the same commit with the pinned toolchain and get them (see the README, and `signing/README.md` for the by-hand checks).',
    '',
    '| file | sha256 |',
    '|---|---|',
    ...Object.entries(files).map(([name, hash]) => `| \`${name}\` | \`${hash}\` |`),
    ''
  ].join('\n'))
  console.log(`[vcap] commit ${commit}${dirty ? ' (dirty)' : ''}, esbuild ${esbuildVersion}`)
  for (const [name, hash] of Object.entries(files)) console.log(`[vcap] ${hash}  ${name}`)
}
