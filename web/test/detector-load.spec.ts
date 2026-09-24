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
      const state = document.getElementById('status') as HTMLElement
      new MutationObserver(() => seen.push(state.textContent ?? '')).observe(state, { childList: true, characterData: true, subtree: true })
    })
  })
  await page.goto(url)

  await page.setInputFiles('#file', join(vectors, '01-jpeg-sealed/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict .chips > li', { hasText: /^watermark not evaluated$/ })).toHaveCount(1)

  const seen = await page.evaluate(() => (window as unknown as { seen: string[] }).seen)
  const at = (pattern: RegExp): number => seen.findIndex((text) => pattern.test(text))
  expect(at(/3\.0 of 3\.0 MB/)).toBeGreaterThanOrEqual(0)
  expect(at(/Checking the model against the digest/)).toBeGreaterThan(at(/of 3\.0 MB/))
  expect(at(/WebAssembly engine/)).toBeGreaterThan(at(/Checking the model/))
  expect(at(/The detector did not load/)).toBeGreaterThan(at(/WebAssembly engine/))
  await stop(server)
})

/**
 * A model of the reader's own, chosen under Advanced: no pin to check it
 * against, so it is not refused for its digest — and it is named by its own
 * digest everywhere it speaks, so a verdict never passes it off as the pinned
 * build. The runtime is a stub that records what it was handed; the pinned
 * model is absent from the host, so a request for it would fail the test.
 */
test('a custom model is used instead of the pinned one, named custom, and not digest-refused', async ({ page }) => {
  const { server, url } = await serve({ absent: /\.onnx$/ })
  const model = Buffer.alloc(1_000, 3)
  const version = `custom-${createHash('sha256').update(model).digest('hex').slice(0, 12)}`
  await page.route('**/detector-runtime.js', (route) => route.fulfill({
    contentType: 'text/javascript',
    body: `export const createDetector = async (model, modelVersion) => {
      window.handed = model.length
      return { model_version: modelVersion, backend: 'stub', detect: async (media, claim) => ({ layout: claim.layout, decoded: null, frames_sampled: 1, model_version: modelVersion }) }
    }`
  }))
  const requested: string[] = []
  page.on('request', (request) => requested.push(new URL(request.url()).pathname))
  await page.goto(url)

  await page.locator('details#advanced summary').click()
  await page.setInputFiles('#model', { name: 'mine.onnx', mimeType: 'application/octet-stream', buffer: model })
  await expect(page.locator('#detector-model')).toContainText(createHash('sha256').update(model).digest('hex'))
  await expect(page.locator('#detector-model')).toContainText(version)
  await expect(page.locator('#using')).toContainText('(custom)')
  await expect(page.locator('#using')).toContainText('custom detector')

  await page.setInputFiles('#file', join(vectors, '01-jpeg-sealed/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  // It ran: the stub was handed the reader's bytes, and the verdict names it.
  expect(await page.evaluate(() => (window as unknown as { handed: number }).handed)).toBe(model.length)
  await expect(page.locator('.verdict')).toContainText(version)
  await expect(page.locator('.verdict')).not.toContainText('videoseal-y256b-1')
  await expect(page.locator('.verdict')).not.toContainText('the manifest pins')
  await expect(page.locator('#status')).toHaveText(`Custom model ${version}, running on stub — not the pinned build.`)
  // Neither the pinned model nor its manifest was asked for.
  expect(requested.filter((p) => p.endsWith('.onnx') || p.endsWith('/detector.json'))).toEqual([])

  // And back: the pinned build is one click away again.
  await page.click('#model-reset')
  await expect(page.locator('#using')).toContainText('pinned detector')
  await stop(server)
})
