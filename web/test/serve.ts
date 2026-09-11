import { readFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { extname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const dist = fileURLToPath(new URL('../dist/', import.meta.url))
export const vectors = fileURLToPath(new URL('../../core/vectors/', import.meta.url))
export const fixtures = fileURLToPath(new URL('fixtures/', import.meta.url))

// Served at the root, as the page is on its own host. Every URL the page and
// the worker build is relative, so the whole build is path-agnostic — which is
// what lets anybody serve these exact files from anywhere, sub-path included.
// `VCAP_TEST_BASE=/somewhere/` runs the same suite under a sub-path and is the
// cheapest proof that the claim still holds.
export const BASE = process.env.VCAP_TEST_BASE ?? '/'
const TYPES: Record<string, string> = {
  '.html': 'text/html', '.js': 'text/javascript',
  // `.mjs` is not decoration either: a module served as octet-stream is
  // refused by the browser, and the engine's glue is imported as a module.
  '.mjs': 'text/javascript', '.json': 'application/json', '.md': 'text/markdown',
  '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.sha256': 'text/plain',
  // The engine's binary and the model. `application/wasm` is not decoration:
  // without it the browser cannot compile the module while it streams.
  '.wasm': 'application/wasm', '.onnx': 'application/octet-stream'
}

// Cross-origin isolation. Everything the page loads is same-origin, so
// require-corp costs nothing and buys `SharedArrayBuffer`.
export const HEADERS: Record<string, string> = {
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-origin',
  'x-content-type-options': 'nosniff'
}

// A static server over dist/ that a test can take down mid-way: the proof of
// offline use is a page that keeps working when nothing can answer.
export const serve = (options: { corrupt?: RegExp, absent?: RegExp } = {}): Promise<{ server: Server, url: string }> => new Promise((resolve) => {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname
    if (!path.startsWith(BASE)) { res.writeHead(404); res.end(); return }
    const name = path.slice(BASE.length) || 'index.html'
    // `absent` is a host that does not have the file: the page has to stay
    // whole when the one thing it fetches is not there.
    if (options.absent?.test(name)) { res.writeHead(404); res.end(); return }
    try {
      const body = await readFile(join(dist, name))
      // A host that serves the right bytes is not what makes a model safe to
      // run; the digest is. `corrupt` flips one byte on the way out, which is
      // the whole threat in one line.
      if (options.corrupt?.test(name)) body[body.length - 1] = (body.at(-1) ?? 0) ^ 0x01
      res.writeHead(200, {
        'content-type': TYPES[extname(name)] ?? 'application/octet-stream',
        'cache-control': 'no-store',
        // The headers the real host sends (vcap-platform, infra/verifier/nginx.conf).
        // They are what gives the page `SharedArrayBuffer`, and therefore
        // multi-threaded WASM in the detector: a suite that ran without them
        // would be measuring and testing a different page from the live one.
        ...HEADERS
      })
      res.end(body)
    } catch {
      res.writeHead(404); res.end()
    }
  })
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address() as AddressInfo
    resolve({ server, url: `http://127.0.0.1:${port}${BASE}` })
  })
})

export const stop = (server: Server): Promise<void> => new Promise((resolve) => {
  server.closeAllConnections()
  server.close(() => resolve())
})
