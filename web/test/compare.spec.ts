import { expect, test } from '@playwright/test'
import { join } from 'node:path'
import { fixtures, serve, stop, vectors } from './serve.js'

/**
 * The side-by-side, and the two things it must never do: let a watermark read
 * as a verdict, and make a missing detector look like a breakage.
 *
 * Every case here runs against `dist/` as built. The copy is vector 05 — the
 * sealed photo with its trailer gone, which is what a messaging app returns —
 * and the original is vector 01, the same capture with its proof intact.
 */
const copy = join(vectors, '05-jpeg-no-trailer/input.jpg')
const original = join(vectors, '01-jpeg-sealed/input.jpg')

test('puts the copy next to the original and names what the copy lost', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)

  await page.setInputFiles('#file', copy)
  await expect(page.locator('.verdict h2')).toHaveText('No proof found')
  // Alone, the copy gets no comparison table — there is nothing to compare it
  // with — but it is no longer met with silence: this is the file people
  // actually arrive with, and the page says the pixels may still carry a mark.
  await expect(page.locator('.compare')).toHaveCount(0)
  await expect(page.locator('.panel.mark h3')).toHaveText('This file carries no proof — but it may still carry an invisible mark')

  await page.setInputFiles('#original', original)
  await expect(page.locator('.pair .verdict h2').first()).toHaveText('No proof found')
  await expect(page.locator('.pair .verdict h2').last()).toContainText('Authentic')

  const row = (name: string) => page.locator('.compare tbody tr', { has: page.locator('th', { hasText: name }) })
  await expect(row('proof identity')).toHaveClass(/lost/)
  await expect(row('proof identity').locator('.absent')).toHaveText('absent')
  await expect(row('signature').locator('td').first()).toContainText('nothing to check')
  await expect(row('signature').locator('td').nth(1)).toContainText('verifies over the signed core')
  await expect(row('verdict').locator('td').first()).toHaveText('no_proof_found')
  await expect(row('declared capture time')).toHaveClass(/lost/)
  // Evidence only: a row that neither file carries is not printed, so *no
  // trusted time* on both sides cannot read as something the copy lost.
  await expect(row('trusted time')).toHaveCount(0)
  await expect(row('watermark (§8)').locator('td').nth(1)).toContainText('not evaluated — no detection was available')
  await expect(page.locator('.pair .verdict li', { hasText: 'watermark not evaluated' })).toHaveCount(1)

  await stop(server)
})

/**
 * The owner's own photos, straight out of the app and through a chat, landed
 * here: the trailer stripped, the mark intact, and a page that said "No proof
 * found" and nothing else — with the detector downloaded. The mark was there
 * all along (decoded clean, 0 corrected bits, from a copy re-encoded *and*
 * resized), and the page never looked, because the core evaluates a watermark
 * only for a proof that declares one and a stripped copy declares nothing.
 *
 * The invariant is right and stays: a watermark is never the reason a verdict
 * is positive. What was wrong was the silence around it.
 */
test('a stripped copy is told its pixels may still carry a mark, and how to read it', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)

  await page.setInputFiles('#file', copy)
  await expect(page.locator('.verdict h2')).toHaveText('No proof found')
  const panel = page.locator('.panel.mark')
  await expect(panel).toHaveCount(1)
  await expect(panel).toContainText('Load the detector above and this page will look.')
  // Not dressed as a verdict: no verdict colour, and outside the verdict card.
  await expect(panel).not.toHaveClass(/green|amber|red|grey/)
  await expect(page.locator('.verdict .panel.mark')).toHaveCount(0)

  // A file that does carry its proof gets no such panel: the signature layer
  // answered, and the invitation would be noise.
  await page.setInputFiles('#file', original)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.panel.mark')).toHaveCount(0)
  await stop(server)
})

test('a mark found in an unsigned copy is origin traced and never authentic', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  await page.setInputFiles('#file', copy)
  await page.setInputFiles('#original', original)
  await page.setInputFiles('#evidence', join(fixtures, 'detection-matched.json'))

  const traced = page.locator('.verdict.traced')
  await expect(traced.locator('h2')).toContainText('Origin traced')
  await expect(traced).toContainText('This is not a verdict of authenticity')
  await expect(traced).toContainText('the payload carries the declared capture id')
  await expect(traced).toContainText('videoseal-y256b-1-detector_int8')
  // The verdict on the copy did not move: a watermark is never the reason a
  // file verifies, and the card stays the colour the signature layer gave it.
  await expect(page.locator('.pair .verdict').first()).toHaveClass(/grey/)
  await expect(page.locator('.pair .verdict h2').first()).toHaveText('No proof found')
  await expect(page.locator('.verdict.green')).toHaveCount(1)
  await expect(traced).not.toHaveClass(/green/)
  // The table must not call the mark lost while the block below calls it found.
  const watermarkRow = page.locator('.compare tbody tr', { has: page.locator('th', { hasText: 'watermark (§8)' }) })
  await expect(watermarkRow).not.toHaveClass(/lost/)
  await expect(watermarkRow.locator('.change')).toHaveText('read against the original')
  await expect(watermarkRow.locator('td').first()).toContainText('matched')
  await stop(server)
})

test('a mark that decodes to another id is not a trace, and one that does not decode is not an accusation', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  await page.setInputFiles('#file', copy)
  await page.setInputFiles('#original', original)

  // Wrapped in a `/v1/verify` response shape, which is the other file a user
  // is likely to be holding.
  await page.setInputFiles('#evidence', join(fixtures, 'detection-other-id.json'))
  await expect(page.locator('.verdict.red h2')).toContainText('A different id')
  await expect(page.locator('.verdict.red')).toContainText('and the proof declares 00112233445566778899aabbccddeeff')

  // Heavy re-compression is the normal case and must never read as forgery.
  await page.setInputFiles('#evidence', join(fixtures, 'detection-not-recovered.json'))
  await expect(page.locator('.verdict.grey h2').last()).toContainText('Nothing recovered')
  await expect(page.locator('.verdict.red')).toHaveCount(0)
  await stop(server)
})

test('a detection about a proof that declares a watermark lands in the verdict itself', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  await page.setInputFiles('#file', original)
  await page.setInputFiles('#evidence', join(fixtures, 'detection-matched.json'))

  // The core compared it, so the label is §8's and the trace block stays away:
  // the copy's own signature already answered.
  await expect(page.locator('.verdict li', { hasText: 'watermark matched' })).toHaveCount(1)
  await expect(page.locator('.verdict.traced')).toHaveCount(0)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await stop(server)
})

test('an unreadable detection changes nothing and says so', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  await page.setInputFiles('#file', original)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await page.setInputFiles('#evidence', join(fixtures, 'detection-unreadable.json'))
  await expect(page.locator('#detector-state')).toContainText('is not a readable detection')
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict li', { hasText: 'watermark not evaluated' })).toHaveCount(1)
  await stop(server)
})

test('the detector is fetched on a click and never on load, and its absence is an answer', async ({ page }) => {
  // A host with no model on it: the one file this page ever fetches is the one
  // that is missing, and the page has to keep working and say why.
  const { server, url } = await serve({ absent: /\.onnx$/ })
  const requested: string[] = []
  page.on('request', (request) => requested.push(new URL(request.url()).pathname))
  await page.goto(url)
  await page.setInputFiles('#file', original)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')

  // The page is complete and nothing about the detector has been asked for.
  expect(requested.some((p) => p.endsWith('/detector.js'))).toBe(false)
  expect(requested.some((p) => p.endsWith('/detector.json'))).toBe(false)
  // The absence is stated where the reader is about to need it: the bar's
  // title, next to the file, and not a line of grey text at the foot.
  await expect(page.locator('#detector-title')).toHaveText('Invisible watermark: not checked')
  await expect(page.locator('#detector-bar')).not.toHaveClass(/ready/)

  await page.click('#load-detector')
  // The reader gets the reason, and the verdict on screen is untouched: a
  // detector that cannot be had is *watermark not evaluated*, not a failure.
  await expect(page.locator('#detector-state')).toContainText('The detector did not load: the model could not be fetched: 404')
  await expect(page.locator('#detector-title')).toHaveText('Invisible watermark: not checked')
  expect(requested.some((p) => p.endsWith('/detector.js'))).toBe(true)
  expect(requested.some((p) => p.endsWith('/detector.json'))).toBe(true)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('#load-detector')).toBeEnabled()
  await stop(server)
})

test('a copy carrying the same proof lost nothing, whatever its verdict stopped short of', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  // Same signed claim, edited pixels: *tampered* returns before the fields
  // below the signature are read, and none of them was lost with the bytes.
  await page.setInputFiles('#file', join(vectors, '11-jpeg-pixels-edited/input.jpg'))
  await page.setInputFiles('#original', original)
  const row = (name: string) => page.locator('.compare tbody tr', { has: page.locator('th', { hasText: name }) })
  await expect(row('proof identity').locator('.change')).toHaveText('unchanged')
  await expect(row('declared capture time').locator('.change')).toHaveText('not reported')
  await expect(row('declared capture time')).not.toHaveClass(/lost/)
  await expect(row('declared capture time').locator('.absent')).toHaveText('not evaluated')
  await expect(page.locator('.compare tbody tr.lost')).toHaveCount(0)
  await stop(server)
})

test('two identical files lose nothing, and the table says so on every row', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  await page.setInputFiles('#file', original)
  await page.setInputFiles('#original', original)
  await expect(page.locator('.compare tbody tr')).not.toHaveCount(0)
  await expect(page.locator('.compare tbody tr.lost')).toHaveCount(0)
  await expect(page.locator('.compare tbody tr.differs')).toHaveCount(0)
  await stop(server)
})

/**
 * The count, on the page, for a clip whose proof binds a `mark_id`.
 *
 * Both detections below report the same id at the same agreement, and before
 * the count the page rendered them identically — which is the splice: one
 * genuine frame in foreign footage reports the real id at the agreement of a
 * clean recovery, because an unmarked frame abstains rather than dissenting.
 * The sentence sits outside the technical disclosure, because a qualifier a
 * reader has to open a section to find is a qualifier they will not read.
 */
test('a clip says how many of its sampled frames carried the mark', async ({ page }) => {
  const clip = join(vectors, '85-mp4-container-ios-sealed/input.mp4')
  const { server, url } = await serve()
  await page.goto(url)
  await page.setInputFiles('#file', clip)

  await page.setInputFiles('#evidence', join(fixtures, 'detection-clip-spliced.json'))
  await expect(page.locator('.verdict li', { hasText: 'watermark matched' })).toHaveCount(1)
  await expect(page.locator('.verdict .carried')).toContainText('1 of the 8 frames sampled across the clip')
  await expect(page.locator('.verdict .carried')).toContainText('cut into it')

  await page.setInputFiles('#evidence', join(fixtures, 'detection-clip-whole.json'))
  await expect(page.locator('.verdict .carried')).toContainText('All 8 frames sampled across the clip')
  await expect(page.locator('.verdict .carried')).not.toContainText('cut into it')
  await stop(server)
})
