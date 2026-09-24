import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { RPC_ORIGINS, dist, serve, stop, vectors } from './serve.js'

test('verifies vectors with the server gone and the browser offline', async ({ page, context }) => {
  const { server, url } = await serve()
  const origin = new URL(url).origin
  const requested: string[] = []
  const answered: string[] = []
  page.on('request', (request) => requested.push(request.url()))
  page.on('response', (response) => answered.push(response.url()))

  await page.goto(url)
  // The footer flips once the worker is active, which comes after install has
  // stored every shipped file.
  await expect(page.locator('#offline')).toHaveText('available offline')

  // Nothing left that can answer but the cache: no server, no network.
  await stop(server)
  await context.setOffline(true)
  await page.reload()
  // The page identifies itself in the masthead; the `h1` is the question it
  // answers, which is what a reader arriving with a photo is looking for.
  await expect(page.locator('header .brand')).toHaveText('VCAP Verifier')
  await expect(page.locator('h1')).toHaveText('Is this photo or video real?')
  // The typefaces ship with the page and come out of the same cache: a font
  // that only loaded online would be a request the page cannot do without.
  expect(await page.evaluate(async () => {
    await document.fonts.ready
    return [...document.fonts].filter((font) => font.status === 'loaded').map((font) => font.family).sort()
  })).toEqual(['Geist', 'Geist Mono'])

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

  // An anchored proof, offline: the chain cannot be read, and that is *not
  // consulted* with the reason — never *not found*, never a failed verdict.
  await page.setInputFiles('#file', join(vectors, '57-jpeg-anchor-on-chain/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict .chips > li', { hasText: /^anchoring not verified$/ })).toHaveCount(1)
  // Chains are read only on request, so offline the page did not even try.
  await expect(page.locator('.verdict')).toContainText('chain not consulted')
  await expect(page.locator('.verdict')).not.toContainText('anchor evidence invalid')

  // The only thing the page may try beyond its own origin is the chain an
  // anchor names, at an endpoint `chains.json` publishes — and offline nothing
  // out there answered.
  expect(requested.filter((u) => !u.startsWith(origin) && !RPC_ORIGINS.includes(new URL(u).origin))).toEqual([])
  expect(answered.filter((u) => !u.startsWith(origin))).toEqual([])
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
