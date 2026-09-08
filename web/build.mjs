import { build, context } from 'esbuild'
import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'

// One bundle, one HTML file, no external requests: the page must be archivable
// and its hash publishable, so an expert can say which verifier produced a
// verdict. The build prints the SHA-256 of the bundle and writes it next to it.
const serve = process.argv.includes('--serve')
mkdirSync('dist', { recursive: true })
const options = {
  entryPoints: ['src/main.ts'],
  bundle: true,
  format: 'esm',
  target: ['es2022'],
  minify: !serve,
  sourcemap: serve,
  outfile: 'dist/verifier.js',
  legalComments: 'none'
}
if (serve) {
  const ctx = await context(options)
  await ctx.watch()
  copyFileSync('src/index.html', 'dist/index.html')
  const { host, port } = await ctx.serve({ servedir: 'dist' })
  console.log(`[vcap] verifier at http://${host}:${port}`)
} else {
  await build(options)
  copyFileSync('src/index.html', 'dist/index.html')
  const hash = createHash('sha256').update(readFileSync('dist/verifier.js')).digest('hex')
  writeFileSync('dist/verifier.js.sha256', `${hash}  verifier.js\n`)
  console.log(`[vcap] dist/verifier.js sha256 ${hash}`)
}
