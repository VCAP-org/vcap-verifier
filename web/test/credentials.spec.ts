import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { serve, stop, vectors } from './serve.js'
import { jpegWithStore, manifest, store } from '../../core/test/c2pa-fixtures.js'
import { parseTrailer } from '../../core/src/trailer.js'

/**
 * A proof carried in Content Credentials, in a real browser against `dist/`:
 * the verdict comes from the proof, the lane sits beside the card in none of
 * its colours, a `.c2pa` handed over through the Advanced input is read, and
 * nothing is requested beyond the page's own origin — reading a store takes
 * no wasm, no worker and no network, so the CSP needed no new directive.
 */
const sealed = new Uint8Array(readFileSync(join(vectors, '01-jpeg-sealed/input.jpg')))
const trailer = parseTrailer(sealed)
if (trailer.kind !== 'ok') throw new Error('vector 01 is not sealed')
const proof = trailer.payload

test('Content Credentials carry the proof: the verdict, a lane beside it, and no request beyond the page', async ({ page }) => {
  const { server, url } = await serve()
  const requested: string[] = []
  page.on('request', (request) => requested.push(request.url()))
  await page.addInitScript(() => {
    const seen: string[] = []
    ;(window as unknown as { violations: string[] }).violations = seen
    document.addEventListener('securitypolicyviolation', (e) => seen.push(`${e.violatedDirective} ${e.blockedURI}`))
  })
  await page.goto(url)

  const credentialed = jpegWithStore(trailer.media, store(manifest({ label: 'urn:c2pa:e2e', proof, generator: 'Acme Cam' })))
  await page.setInputFiles('#file', { name: 'credentialed.jpg', mimeType: 'image/jpeg', buffer: Buffer.from(credentialed) })
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  const lane = page.locator('.panel.cc')
  await expect(lane).toHaveCount(1)
  await expect(lane).toContainText('urn:c2pa:e2e')
  await expect(lane).toContainText('not checked by this page')
  await expect(lane).not.toHaveClass(/green|amber|red|grey/)
  await expect(page.locator('.verdict .panel.cc')).toHaveCount(0)

  // A stripped copy, then the store kept beside it, through the Advanced input.
  await page.setInputFiles('#file', join(vectors, '05-jpeg-no-trailer/input.jpg'))
  await expect(page.locator('.verdict h2')).toHaveText('No proof found')
  await expect(page.locator('.panel.cc')).toHaveCount(0)
  await page.setInputFiles('#store', { name: 'input.c2pa', mimeType: 'application/c2pa', buffer: Buffer.from(store(manifest({ label: 'urn:c2pa:beside', proof }))) })
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.panel.cc')).toContainText('the .c2pa file you supplied')

  const origin = new URL(url).origin
  expect(requested.filter((r) => r.startsWith('http') && new URL(r).origin !== origin)).toEqual([])
  expect(await page.evaluate(() => (window as unknown as { violations: string[] }).violations)).toEqual([])
  await stop(server)
})
