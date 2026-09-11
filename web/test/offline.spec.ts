import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { dist, serve, stop, vectors } from './serve.js'

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
  // §3.1: the file alone has no trailer; the sidecar handed over through its
  // own input restores the full verdict, with no label for where the proof sat.
  await page.setInputFiles('#file', join(vectors, '17-jpeg-sidecar-only/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('No proof found')
  await page.setInputFiles('#sidecar', join(vectors, '17-jpeg-sidecar-only/input.jpg.vcap'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict li', { hasText: 'sidecar' })).toHaveCount(0)
  // §7.1: the position level is named whenever a position is declared, and a
  // corroboration this page holds no registry key for is evidence it cannot
  // read — never "verified", never "guaranteed".
  await page.setInputFiles('#file', join(vectors, '75-jpeg-location-corroborated/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.position')).toContainText('Position declared only')
  await expect(page.locator('.position')).toContainText('45.464664, 9.188540')
  await expect(page.locator('.verdict li', { hasText: 'location corroboration not evaluated' })).toHaveCount(1)
  await expect(page.locator('.verdict')).not.toContainText(/guaranteed|verified by the operator/)

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
