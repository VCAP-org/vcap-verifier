import { expect, test } from '@playwright/test'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { dist, fixtures, serve, stop, vectors } from './serve.js'

/**
 * The detector, end to end, against a real model and real marked pixels.
 *
 * Everything this needs is deliberately not in the repository: the model is a
 * release asset of `vcap-ml` (34 MB, P11) and the marked media is produced by
 * the embedder there, so the suite **skips** rather than pretends when they
 * are absent. `README.md` says how to put them in place:
 *
 *   vcap-ml: python -m vcap_ml quantize && python -m vcap_ml browser-build
 *   mkdir -p web/dist/models && cp ../vcap-ml/models/detector_int8.onnx \
 *     web/dist/models/detector-videoseal-y256b-1-int8.onnx
 *
 * What is checked here is what cannot be checked by reading the source: that
 * the pinned digest refuses a model that is not the pinned one, that the page
 * without a detector is the page it always was, and that a mark read out of an
 * unsigned copy lands as *origin traced* and never as a verdict.
 */
const model = join(dist, 'models/detector-videoseal-y256b-1-int8.onnx')
const photo = join(fixtures, 'marked-photo.jpg')
const clip = join(fixtures, 'marked-clip.mp4')
const original = join(vectors, '01-jpeg-sealed/input.jpg')
const videoOriginal = join(vectors, '33-mp4-video-sealed/input.mp4')

/** Wall clock, reported: a page nobody timed is a page nobody can size. */
const took = (from: number): string => `${((Date.now() - from) / 1000).toFixed(1)} s`

test.describe('with the published detector build', () => {
  test.skip(!existsSync(model) || !existsSync(photo), 'no detector build or marked fixture in place')
  // A 34 MB model and a few hundred milliseconds a frame: the default timeout
  // is a statement about a fast page, and this is not that page.
  test.setTimeout(180_000)

  test('reads the mark out of an unsigned copy and calls it origin traced', async ({ page }) => {
    const { server, url } = await serve()
    await page.goto(url)

    // Nothing is fetched before the click: the model is 34 MB and the page is
    // whole without it.
    const asked: string[] = []
    page.on('request', (request) => asked.push(request.url()))
    await page.setInputFiles('#file', photo)
    await page.setInputFiles('#original', original)
    await expect(page.locator('.pair .verdict h2').first()).toHaveText('No proof found')
    expect(asked.filter((u) => u.includes('.onnx'))).toHaveLength(0)
    await expect(page.locator('#detector-state')).not.toContainText('runs in this page')

    const clicked = Date.now()
    await page.click('#load-detector')
    await expect(page.locator('#detector-state')).toContainText('runs in this page', { timeout: 120_000 })
    const loaded = Date.now()
    console.log(`[timing] photo — 34.2 MB downloaded, hashed and a session opened in ${took(clicked)}`)
    await expect(page.locator('#detector-state')).toContainText('videoseal-y256b-1')

    const traced = page.locator('.verdict.traced')
    await expect(traced.locator('h2')).toContainText('Origin traced', { timeout: 120_000 })
    console.log(`[timing] photo — one frame detected and the verdict redrawn in ${took(loaded)}`)
    await expect(traced).toContainText('the payload carries the declared capture id')
    await expect(traced).toContainText('This is not a verdict of authenticity')
    // The signature layer decides the colour, and it said nothing: a mark is
    // never why a file verifies.
    await expect(page.locator('.pair .verdict').first()).toHaveClass(/grey/)
    await expect(page.locator('.pair .verdict h2').first()).toHaveText('No proof found')

    await stop(server)
  })

  test('refuses a model whose bytes do not hash to the manifest', async ({ page }) => {
    // One byte of the model flipped on the way out of the server: the size is
    // right, the name is right, and it must still not run.
    const { server, url } = await serve({ corrupt: /\.onnx$/ })
    await page.goto(url)
    await page.setInputFiles('#file', photo)
    await page.setInputFiles('#original', original)
    await page.click('#load-detector')

    await expect(page.locator('#detector-state')).toContainText('no detector:', { timeout: 120_000 })
    await expect(page.locator('#detector-state')).toContainText('the manifest pins')
    // Refused, and the page is exactly as useful as it was: the watermark is
    // not evaluated, which is a weaker verdict and not a failure.
    await expect(page.locator('.verdict.traced')).toHaveCount(0)
    await expect(page.locator('.pair .verdict h2').first()).toHaveText('No proof found')
    await expect(page.locator('#load-detector')).toBeEnabled()

    await stop(server)
  })

  test('samples a clip frame by frame and says so while it does', async ({ page }) => {
    test.skip(!existsSync(clip), 'no marked clip in place')
    const { server, url } = await serve()
    await page.goto(url)
    await page.setInputFiles('#file', clip)
    await page.setInputFiles('#original', videoOriginal)

    const clicked = Date.now()
    await page.click('#load-detector')
    await expect(page.locator('#detector-state')).toContainText('runs in this page', { timeout: 120_000 })
    const loaded = Date.now()

    // Progressive: the eight frames are reported as they land, because six
    // seconds of silence reads as a hang and the reader has no other signal.
    await expect(page.locator('#detector-state')).toContainText(/frame \d of 8/, { timeout: 120_000 })
    // Not the *traced* block: nothing was traced. A proof that declares a
    // layout and binds no id has nothing to compare a payload against.
    const traced = page.locator('.verdict h2', { hasText: 'Watermark not evaluated' })
    await expect(traced).toBeVisible({ timeout: 180_000 })
    console.log(`[timing] clip — 8 frames decoded, detected and reported in ${took(loaded)} (load ${took(clicked)})`)
    // Vector 33 declares `video-rep-v1` and binds no `mark_id`, so there is
    // nothing to compare a payload against: the label is *not evaluated*, and
    // it is a weaker answer rather than an error.
    await expect(traced.locator('..')).toContainText('no mark id')
    await stop(server)
  })
})
