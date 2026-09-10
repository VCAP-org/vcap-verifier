import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { extname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const vectors = fileURLToPath(new URL('../../core/vectors/', import.meta.url))

// Served under the same sub-path as GitHub Pages, so a scope or base-URL
// mistake fails here and not on the live page.
const BASE = '/vcap-verifier/'
const TYPES: Record<string, string> = {
  '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json', '.md': 'text/markdown',
  '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.sha256': 'text/plain'
}

// A static server over dist/ that the test can take down mid-way: the proof
// of offline use is a page that keeps working when nothing can answer.
const serve = (): Promise<{ server: Server, url: string }> => new Promise((resolve) => {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname
    if (!path.startsWith(BASE)) { res.writeHead(404); res.end(); return }
    const name = path.slice(BASE.length) || 'index.html'
    try {
      const body = await readFile(join(dist, name))
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

const stop = (server: Server): Promise<void> => new Promise((resolve) => {
  server.closeAllConnections()
  server.close(() => resolve())
})

test('verifies vectors with the server gone and the browser offline', async ({ page, context }) => {
  const { server, url } = await serve()
  const origin = new URL(url).origin
  const requested: string[] = []
  page.on('request', (request) => requested.push(request.url()))

  await page.goto(url)
  // The footer flips once the worker is active, which comes after install has
  // stored every shipped file.
  await expect(page.locator('#offline')).toHaveText('available offline')

  // Nothing left that can answer but the cache: no server, no network.
  await stop(server)
  await context.setOffline(true)
  await page.reload()
  await expect(page.locator('h1')).toHaveText('vcap verifier')

  await page.setInputFiles('#file', join(vectors, '01-jpeg-sealed/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await page.setInputFiles('#file', join(vectors, '11-jpeg-pixels-edited/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Tampered')
  await page.setInputFiles('#file', join(vectors, '05-jpeg-no-trailer/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('No proof found')

  // Every request the page made stayed on its own origin.
  expect(requested.filter((u) => !u.startsWith(origin))).toEqual([])
})

test('the page names the bundle and commit that hashes.json records', async ({ page }) => {
  const { server, url } = await serve()
  const hashes = JSON.parse(await readFile(join(dist, 'hashes.json'), 'utf8'))
  await page.goto(url)
  await expect(page.locator('#bundle-hash')).toHaveText(hashes.files['verifier.js'])
  await expect(page.locator('#commit')).toHaveText(hashes.commit.slice(0, 7))
  await stop(server)
})
