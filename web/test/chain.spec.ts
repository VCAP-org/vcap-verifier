import { expect, test, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { RPC_ORIGINS, serve, stop, vectors } from './serve.js'

/**
 * The anchor read online: the page asks the chain's public RPC, and nothing
 * else, which root the contract stored. The endpoint is answered here by a
 * recorded-shape reply, so the suite never reaches the real chain — and the
 * service worker is kept out of the way, because a request it forwards is one
 * Playwright's routing cannot see.
 */
test.use({ serviceWorkers: 'block' })

const input = join(vectors, '57-jpeg-anchor-on-chain/input.jpg')
const anchor = (JSON.parse(readFileSync(join(vectors, '57-jpeg-anchor-on-chain/proof.json'), 'utf8')) as { anchor: { root: string, tree_size: number, block: number } }).anchor
const word = (n: number): string => n.toString(16).padStart(64, '0')
const rootHex = Buffer.from(anchor.root, 'base64url').toString('hex')
const chip = (page: Page, text: string) => page.locator('.verdict .chips > li', { hasText: new RegExp(`^${text}$`) })

/** Answer every RPC origin as Base Sepolia holding the proof's own root; record every cross-origin request. */
const fakeChain = async (page: Page, origin: string): Promise<string[]> => {
  const outside: string[] = []
  page.on('request', (request) => { if (!request.url().startsWith(origin)) outside.push(request.url()) })
  for (const rpc of RPC_ORIGINS) {
    await page.route(`${rpc}/**`, async (route) => {
      const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type' }
      if (route.request().method() === 'OPTIONS') { await route.fulfill({ status: 204, headers: cors }); return }
      const { method } = JSON.parse(route.request().postData() ?? '{}') as { method: string }
      const result = method === 'eth_chainId' ? '0x14a34' : '0x' + rootHex + word(anchor.tree_size) + word(anchor.block) + word(1757332890)
      await route.fulfill({ status: 200, headers: { ...cors, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, result }) })
    })
  }
  return outside
}

test('reads the anchor from the chain, and contacts only the RPC chains.json lists', async ({ page }) => {
  const { server, url } = await serve()
  const outside = await fakeChain(page, new URL(url).origin)
  await page.goto(url)

  await expect(page.locator('#chain-list > li')).toHaveCount(1)
  await expect(page.locator('#chain-list')).toContainText('trusted to answer honestly')

  await page.setInputFiles('#file', input)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict')).toContainText(`anchored on base-sepolia, block ${anchor.block}`)
  await expect(chip(page, 'anchoring not verified')).toHaveCount(0)

  expect(outside.length).toBeGreaterThan(0)
  expect(outside.filter((u) => !RPC_ORIGINS.includes(new URL(u).origin))).toEqual([])
  await stop(server)
})

test('a chain switched off is not read, and the anchor is not consulted', async ({ page }) => {
  const { server, url } = await serve()
  const outside = await fakeChain(page, new URL(url).origin)
  await page.goto(url)

  await page.locator('details#advanced summary').click()
  await page.locator('#chain-list input[type=checkbox]').uncheck()
  await page.setInputFiles('#file', input)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict')).toContainText('chain not consulted')
  await expect(chip(page, 'anchoring not verified')).toHaveCount(1)
  expect(outside).toEqual([])
  await stop(server)
})
