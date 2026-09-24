import { expect, test } from '@playwright/test'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { serve, stop, vectors } from './serve.js'

/**
 * The load's progress, phase by phase, with no real model: `detector.json` is
 * answered with a manifest pinning a small file of known digest and a runtime
 * that is not there. So the download, the digest check and the engine start
 * all happen for real, and the load then fails the way a missing engine does —
 * which also proves the verdict arrives anyway. The service worker is kept out
 * of the way, because a request it answers is one routing cannot see.
 */
test.use({ serviceWorkers: 'block' })

test('says how far the download got, then the digest check, then the engine, and still gives a verdict', async ({ page }) => {
  const { server, url } = await serve()
  const model = Buffer.alloc(3_000_000, 7)
  await page.route('**/detector.json', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ build: { url: 'fake-model.bin', sha256: createHash('sha256').update(model).digest('hex'), bytes: model.length, model_version: 'fake', runtime: 'no-such-runtime.js' } })
  }))
  await page.route('**/fake-model.bin', (route) => route.fulfill({ contentType: 'application/octet-stream', body: model }))
  // Every state the bar passes through, recorded as it changes: the phases
  // follow each other in milliseconds here, too fast to catch by polling.
  await page.addInitScript(() => {
    const seen: string[] = []
    ;(window as unknown as { seen: string[] }).seen = seen
    document.addEventListener('DOMContentLoaded', () => {
      const state = document.getElementById('detector-state') as HTMLElement
      new MutationObserver(() => seen.push(state.textContent ?? '')).observe(state, { childList: true, characterData: true, subtree: true })
    })
  })
  await page.goto(url)

  await page.setInputFiles('#file', join(vectors, '01-jpeg-sealed/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict .chips > li', { hasText: /^watermark not evaluated$/ })).toHaveCount(1)

  const seen = await page.evaluate(() => (window as unknown as { seen: string[] }).seen)
  const at = (pattern: RegExp): number => seen.findIndex((text) => pattern.test(text))
  expect(at(/^3\.0 of 3\.0 MB/)).toBeGreaterThanOrEqual(0)
  expect(at(/Checking the model against the digest/)).toBeGreaterThan(at(/of 3\.0 MB/))
  expect(at(/WebAssembly engine/)).toBeGreaterThan(at(/Checking the model/))
  expect(at(/The detector did not load/)).toBeGreaterThan(at(/WebAssembly engine/))
  await stop(server)
})
