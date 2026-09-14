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
  // corroboration no key of this page's trust set signed is *not verified* —
  // never "verified", never "guaranteed". It reads that way rather than *not
  // evaluated* because the page now holds a registry key: §6.2 keys are one
  // set, so pinning a transparency log also gives this check something to try,
  // and "we hold keys and none of them signed this" is a different, and
  // stronger, statement than "we hold none".
  await page.setInputFiles('#file', join(vectors, '75-jpeg-location-corroborated/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.position')).toContainText('Position declared only')
  await expect(page.locator('.position')).toContainText('45.464664, 9.188540')
  await expect(page.locator('.verdict li', { hasText: 'location corroboration not verified' })).toHaveCount(1)
  await expect(page.locator('.verdict')).not.toContainText(/guaranteed|verified by the operator/)

  // Every request the page made stayed on its own origin.
  expect(requested.filter((u) => !u.startsWith(origin))).toEqual([])
})

// The mirror's shape: a host that sends no COOP/COEP, under a sub-path. Both
// are env-driven (`VCAP_TEST_ISOLATION=off`, `VCAP_TEST_BASE=/x/`) and CI runs
// the whole suite above a second time that way, so the degradation is measured
// against the same verdicts rather than assumed. This test only checks that the
// harness really varies: a suite that quietly stayed isolated would prove the
// opposite of what it claims.
test('the page is cross-origin isolated only when the host says so', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  expect(await page.evaluate(() => window.crossOriginIsolated)).toBe(process.env.VCAP_TEST_ISOLATION !== 'off')
  await stop(server)
})

test('the page names the bundle and commit that hashes.json records', async ({ page }) => {
  const { server, url } = await serve()
  const hashes = JSON.parse(await readFile(join(dist, 'hashes.json'), 'utf8'))
  await page.goto(url)
  await expect(page.locator('#bundle-hash')).toHaveText(hashes.files['verifier.js'])
  await expect(page.locator('#commit')).toHaveText(hashes.commit.slice(0, 7))
  await stop(server)
})
