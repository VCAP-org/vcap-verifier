import { expect, test } from '@playwright/test'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { dist, fixtures, serve, stop } from './serve.js'

/**
 * The detector, end to end, against a real model and real marked pixels.
 *
 * Everything this needs is deliberately not in the repository: the model
 * (34 MB) is published next to the primary page and pinned by digest in
 * `detector.json`, and the marked media is produced by our embedder, which is
 * not public, so the suite **skips** rather than pretends when they are
 * absent. `README.md` says how to put the model in place.
 *
 * What is checked here is what cannot be checked by reading the source: that
 * the pinned digest refuses a model that is not the pinned one, that the page
 * without a detector is the page it always was, and that a mark read out of an
 * unsigned copy lands as an identifier beside the verdict and never as one.
 */
const model = join(dist, 'models/detector-videoseal-y256b-1-int8.onnx')
const photo = join(fixtures, 'marked-photo.jpg')
const clip = join(fixtures, 'marked-clip.mp4')

/** Wall clock, reported: a page nobody timed is a page nobody can size. */
const took = (from: number): string => `${((Date.now() - from) / 1000).toFixed(1)} s`

test.describe('with the published detector build', () => {
  test.skip(!existsSync(model) || !existsSync(photo), 'no detector build or marked fixture in place')
  // A 34 MB model and a few hundred milliseconds a frame: the default timeout
  // is a statement about a fast page, and this is not that page.
  test.setTimeout(180_000)

  test('reads the mark out of an unsigned copy and prints it as an identifier, not a verdict', async ({ page }) => {
    const { server, url } = await serve()
    await page.goto(url)

    // Nothing is fetched before the click: the model is 34 MB and the page is
    // whole without it.
    const asked: string[] = []
    page.on('request', (request) => asked.push(request.url()))
    await page.setInputFiles('#file', photo)
    await expect(page.locator('.verdict h2')).toHaveText('No proof found')
    expect(asked.filter((u) => u.includes('.onnx'))).toHaveLength(0)
    await expect(page.locator('#detector-state')).not.toContainText('running on')

    const clicked = Date.now()
    await page.click('#load-detector')
    await expect(page.locator('#detector-state')).toContainText('running on', { timeout: 120_000 })
    const loaded = Date.now()
    console.log(`[timing] photo — 34.2 MB downloaded, hashed and a session opened in ${took(clicked)}`)
    await expect(page.locator('#detector-state')).toContainText('videoseal-y256b-1')

    const mark = page.locator('.panel.mark')
    await expect(mark.locator('h3')).toHaveText('An invisible mark is still in these pixels', { timeout: 120_000 })
    console.log(`[timing] photo — one frame detected and the verdict redrawn in ${took(loaded)}`)
    await expect(mark).toContainText('This is not a verdict of authenticity')
    await expect(mark.locator('a', { hasText: 'Look this identifier up' })).toHaveCount(1)
    // The signature layer decides the colour, and it said nothing: a mark is
    // never why a file verifies.
    await expect(page.locator('.verdict')).toHaveClass(/grey/)
    await expect(page.locator('.verdict h2')).toHaveText('No proof found')

    await stop(server)
  })

  test('refuses a model whose bytes do not hash to the manifest', async ({ page }) => {
    // One byte of the model flipped on the way out of the server: the size is
    // right, the name is right, and it must still not run.
    const { server, url } = await serve({ corrupt: /\.onnx$/ })
    await page.goto(url)
    await page.setInputFiles('#file', photo)
    await page.click('#load-detector')

    await expect(page.locator('#detector-state')).toContainText('The detector did not load', { timeout: 120_000 })
    await expect(page.locator('#detector-state')).toContainText('the manifest pins')
    // Refused, and the page is exactly as useful as it was: the watermark is
    // not evaluated, which is a weaker verdict and not a failure.
    await expect(page.locator('.panel.mark a')).toHaveCount(0)
    await expect(page.locator('.verdict h2')).toHaveText('No proof found')
    await expect(page.locator('#load-detector')).toBeEnabled()

    await stop(server)
  })

  test('samples a clip frame by frame and says so while it does', async ({ page }) => {
    test.skip(!existsSync(clip), 'no marked clip in place')
    const { server, url } = await serve()
    await page.goto(url)
    await page.setInputFiles('#file', clip)

    const clicked = Date.now()
    await page.click('#load-detector')
    // Progressive: the eight frames are reported as they land, because six
    // seconds of silence reads as a hang and the reader has no other signal.
    // They arrive before the ready line, which the page prints once the clip
    // is done — so the frames are awaited first.
    await expect(page.locator('#detector-state')).toContainText(/frame \d of 8/, { timeout: 120_000 })
    const loaded = Date.now()
    await expect(page.locator('#detector-state')).toContainText('running on', { timeout: 120_000 })
    // The clip carries no proof, so what comes back is the mark on its own:
    // an identifier, or the page saying why it names none.
    await expect(page.locator('.panel.mark')).toBeVisible({ timeout: 180_000 })
    console.log(`[timing] clip — 8 frames decoded, detected and reported in ${took(loaded)} (load ${took(clicked)})`)
    await expect(page.locator('.verdict h2')).toHaveText('No proof found')
    await stop(server)
  })
})
