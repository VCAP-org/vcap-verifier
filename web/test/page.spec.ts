import { expect, test } from '@playwright/test'
import { join } from 'node:path'
import { fixtures, serve, stop, vectors } from './serve.js'

/**
 * One file in, one verdict out, and the two things the page must never do: let
 * a watermark read as a verdict, and make a missing detector look like a
 * breakage.
 *
 * Every case here runs against `dist/` as built. The stripped copy is vector
 * 05 — the sealed photo with its trailer gone, which is what a messaging app
 * returns — and the sealed file is vector 01, the same capture with its proof
 * intact.
 */
const copy = join(vectors, '05-jpeg-no-trailer/input.jpg')
const sealed = join(vectors, '01-jpeg-sealed/input.jpg')

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

  const requested: string[] = []
  page.on('request', (request) => requested.push(new URL(request.url()).pathname))
  await page.setInputFiles('#file', copy)
  await expect(page.locator('.verdict h2')).toHaveText('No proof found')
  const panel = page.locator('.panel.mark')
  await expect(panel).toHaveCount(1)
  // Asked first, with the size, and nothing fetched until the reader agrees.
  await expect(panel).toContainText('about 62 MB')
  expect(requested.some((p) => p.endsWith('/detector.js'))).toBe(false)
  await panel.locator('#read-mark').click()
  // No model on this host: the page tried, and says it could not look.
  await expect(page.locator('.panel.mark')).toContainText('The detector could not be loaded (the reason is above), so this page could not look.')
  // Not dressed as a verdict: no verdict colour, and outside the verdict card.
  await expect(panel).not.toHaveClass(/green|amber|red|grey/)
  await expect(page.locator('.verdict .panel.mark')).toHaveCount(0)

  // A file that does carry its proof gets no such panel: the signature layer
  // answered, and the invitation would be noise.
  await page.setInputFiles('#file', sealed)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.panel.mark')).toHaveCount(0)
  await stop(server)
})

test('a detection about a proof that declares a watermark lands in the verdict itself', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  await page.setInputFiles('#file', sealed)
  await page.setInputFiles('#evidence', join(fixtures, 'detection-matched.json'))

  // The core compared it against the signed claim, so the label is §8's and
  // the no-proof panel stays away: the file's own signature already answered.
  await expect(page.locator('.verdict li', { hasText: 'watermark matched' })).toHaveCount(1)
  // Evidence that held, so it is listed as checked and not as a limit.
  await expect(page.locator('.verdict .limits.checked li', { hasText: 'watermark matched' })).toHaveCount(1)
  await expect(page.locator('.verdict .limits:not(.checked) li', { hasText: 'watermark matched' })).toHaveCount(0)
  await expect(page.locator('.panel.mark')).toHaveCount(0)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await stop(server)
})

test('an unreadable detection changes nothing and says so', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  await page.setInputFiles('#file', sealed)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  // Let the watermark pass finish (no model here) before the detection lands.
  await expect(page.locator('.verdict')).toContainText('no detection was available')
  await page.setInputFiles('#evidence', join(fixtures, 'detection-unreadable.json'))
  await expect(page.locator('#status')).toContainText('is not a readable detection')
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict li', { hasText: 'watermark not evaluated' })).toHaveCount(1)
  await stop(server)
})

test('the detector is fetched when a file needs it and never on load, and its absence is an answer', async ({ page }) => {
  // A host with no model on it: the one file this page fetches for a
  // watermark is the one that is missing, and the verdict has to arrive
  // anyway, with the reason on it.
  const { server, url } = await serve({ absent: /\.onnx$/ })
  const requested: string[] = []
  page.on('request', (request) => requested.push(new URL(request.url()).pathname))
  await page.goto(url)
  await expect(page.locator('#status')).toHaveText('No file chosen yet.')
  // The model is named before anything is fetched: the pin is in the bundle.
  await expect(page.locator('#detector-model')).toContainText('the pinned build videoseal-y256b-1')

  // Loaded and idle: nothing about the detector has been asked for.
  expect(requested.some((p) => p.endsWith('/detector.js'))).toBe(false)
  expect(requested.some((p) => p.endsWith('.onnx'))).toBe(false)

  // Vector 01 declares a watermark, so the page fetches the detector for it,
  // waits, and gives the verdict it can: *watermark not evaluated*, and why.
  await page.setInputFiles('#file', sealed)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict .chips > li', { hasText: /^watermark not evaluated$/ })).toHaveCount(1)
  await expect(page.locator('.verdict')).toContainText('no detection was available: the model could not be fetched: 404')
  await expect(page.locator('#status')).toContainText('The detector did not load: the model could not be fetched: 404')
  expect(requested.some((p) => p.endsWith('/detector.js'))).toBe(true)
  expect(requested.some((p) => p.endsWith('.onnx'))).toBe(true)
  await stop(server)
})

test('the signature verdict is on the page before the detector answers', async ({ page }) => {
  // The model is held back until the verdict is visible: had the page waited
  // for the detector, nothing would be on screen while the model is pending.
  const { server, url } = await serve({ absent: /\.onnx$/ })
  let release: () => void = () => {}
  const held = new Promise<void>((resolve) => { release = resolve })
  await page.route('**/*.onnx', async (route) => { await held; await route.fulfill({ status: 404, body: '' }) })
  await page.goto(url)
  await page.setInputFiles('#file', sealed)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('.verdict')).toContainText('being read')
  release()
  await expect(page.locator('.verdict')).toContainText('no detection was available: the model could not be fetched: 404')
  await expect(page.locator('.verdict')).not.toContainText('being read')
  await stop(server)
})

test('a file the page cannot read at all is an error card that says what to do', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)
  // A File whose bytes cannot be read: the one failure the core never sees.
  await page.evaluate(() => {
    Object.defineProperty(File.prototype, 'arrayBuffer', { value: () => Promise.reject(new Error('NotReadableError: the file could not be read')) })
  })
  await page.setInputFiles('#file', sealed)
  await expect(page.locator('.panel.error')).toContainText('could not finish checking')
  await expect(page.locator('.panel.error')).toContainText('NotReadableError')
  await expect(page.locator('#status')).toHaveAttribute('data-state', 'idle')
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

/**
 * The card's light is §7's ceiling, not the outcome. Vector 01 is *authentic*
 * with a session key the log never saw — "amber, never green" — and it used to
 * be painted green with its limits as grey chips underneath. The spec's title
 * stays; the plain line and the colour stop contradicting the ceiling.
 */
test('an authentic file under an amber ceiling is an amber card that says why', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)

  await page.setInputFiles('#file', sealed)
  const verdict = page.locator('.verdict')
  await expect(verdict.locator('h2')).toHaveText('Authentic — signed at capture, file complete')
  await expect(verdict).toHaveClass(/\bamber\b/)
  await expect(verdict).not.toHaveClass(/\bgreen\b/)
  await expect(verdict.locator('.ceiling')).toHaveText('amber origin not hardware-attested · key not in transparency log · no trusted time')
  await expect(verdict.locator('.lede')).toContainText('Intact, not fully proven')
  await expect(verdict.locator('.lede')).not.toContainText('Yes')
  // The chips and the detail list are still there.
  await expect(verdict.locator('.chips > li', { hasText: /^no trusted time$/ })).toHaveCount(1)
  await expect(verdict.locator('details.tech')).toHaveCount(1)

  // A tampered file stays red, and has no ceiling line: it never reached §7.
  await page.setInputFiles('#file', join(vectors, '11-jpeg-pixels-edited/input.jpg'))
  await expect(verdict).toHaveClass(/\bred\b/)
  await expect(verdict.locator('h2')).toContainText('Tampered')
  await expect(verdict.locator('.ceiling')).toHaveCount(0)
  await stop(server)
})

/**
 * The first view is the console's: a question, one drop, one status line. The
 * rest — the detector, the sidecar, the three trust sets — is one native
 * disclosure below it, closed, and its summary says what is in use so that a
 * folded panel never hides a changed setup.
 */
test('the first view is one drop and one line, and Advanced says what is in use', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)

  const advanced = page.locator('details#advanced')
  await expect(advanced).not.toHaveAttribute('open')
  await expect(page.locator('#using')).toHaveText('Using: 1 log · 1 timestamp authority · chains read on request · pinned detector')
  // Folded, not gone: every trust point is in the page and one click away.
  await expect(page.locator('#trust-logs li')).toHaveCount(1)
  await expect(page.locator('#trust-logs')).toBeHidden()
  await advanced.locator('summary').click()
  await expect(page.locator('#trust-logs')).toBeVisible()

  // Dropping a file needs nothing from Advanced.
  await page.setInputFiles('#file', sealed)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(page.locator('#status')).not.toBeEmpty()

  // Any change reads "custom" on the summary line.
  await page.uncheck('#tsa-roots input[type=checkbox]')
  await expect(page.locator('#using')).toHaveText('Using (custom): 1 log · 0 timestamp authorities · chains read on request · pinned detector')
  await stop(server)
})

test('the page fits a phone: no horizontal scroll at 390 px, Advanced open or not', async ({ page }) => {
  const { server, url } = await serve()
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(url)
  const overflow = async (): Promise<number> => await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(await overflow()).toBeLessThanOrEqual(0)
  await page.locator('details#advanced summary').click()
  await page.setInputFiles('#file', sealed)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await page.locator('.verdict details.tech summary').click()
  expect(await overflow()).toBeLessThanOrEqual(0)
  await stop(server)
})

/**
 * The page runs under its own Content-Security-Policy with nothing refused:
 * a policy that blocked the page's own style or bundle would be found here
 * and not by a reader. Every violation the browser reports is collected.
 */
test('runs under its Content-Security-Policy with no violation', async ({ page }) => {
  const { server, url } = await serve({ absent: /\.onnx$/ })
  await page.addInitScript(() => {
    const seen: string[] = []
    ;(window as unknown as { violations: string[] }).violations = seen
    document.addEventListener('securitypolicyviolation', (e) => seen.push(`${e.violatedDirective} ${e.blockedURI}`))
  })
  await page.goto(url)
  expect(await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content')).toContain("connect-src 'self' https://sepolia.base.org")
  await page.setInputFiles('#file', sealed)
  await expect(page.locator('.verdict')).toContainText('no detection was available')
  await page.setInputFiles('#file', copy)
  await page.locator('#read-mark').click()
  await expect(page.locator('.panel.mark')).toContainText('could not be loaded')
  // The font, the styles, the bundle and the detector module all loaded.
  expect(await page.evaluate(() => getComputedStyle(document.body).fontFamily)).toContain('Geist')
  expect(await page.evaluate(() => (window as unknown as { violations: string[] }).violations)).toEqual([])
  await stop(server)
})
