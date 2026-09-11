import { readFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { extname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const dist = fileURLToPath(new URL('../dist/', import.meta.url))
export const vectors = fileURLToPath(new URL('../../core/vectors/', import.meta.url))
export const fixtures = fileURLToPath(new URL('fixtures/', import.meta.url))

// Served under the same sub-path as GitHub Pages, so a scope or base-URL
// mistake fails here and not on the live page.
export const BASE = '/vcap-verifier/'
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
      if (options.corrupt?.test(name)) body[body.length - 1] = body[body.length - 1] ^ 0x01
      res.writeHead(200, { 'content-type': TYPES[extname(name)] ?? 'application/octet-stream', 'cache-control': 'no-store' })
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
