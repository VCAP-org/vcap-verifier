import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { serve, stop, vectors } from './serve.js'

/**
 * The trust panel, which is the page's one trust decision put where a reader
 * can see it and undo it.
 *
 * Three things have to hold, and they are the reasons the panel exists rather
 * than a constant in the bundle: the shipped set is named on the page and says
 * whose it is; the same bytes are published beside the page as `logs.json`;
 * and a reader can both drop ours and add their own, with the verdict changing
 * accordingly. A page that pinned a log the reader cannot inspect or refuse
 * would be asking for exactly the trust this project claims not to need.
 */
const registry = join(vectors, '49-jpeg-registry-verified/input.jpg')
const corpusLog = (): string => {
  const { logs } = JSON.parse(readFileSync(join(vectors, '_trust/logs.json'), 'utf8')) as { logs: { log_id: string, spki: string }[] }
  return `${logs[0]?.log_id}:${logs[0]?.spki}`
}
// The ceilings, not the details block: `log not trusted` appears in both, and
// a count that caught the second would pass for the wrong reason. They are
// chips now and still the same list — the words are the specification's
// either way, which is the part that must not move.
const label = (page: import('@playwright/test').Page, text: string) => page.locator('.verdict .chips > li', { hasText: new RegExp(`^${text}$`) })

test('names the log it ships with, and does not let it pass for a third party', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)

  const row = page.locator('#trust-logs li')
  await expect(row).toHaveCount(1)
  await expect(row).toContainText('1Iw8uAnl63-NzdTys4KmO8d0GphTBiNC4AqxJyaaRFQ')
  await expect(row).toContainText('Run by the same people who publish this page')
  await expect(row).toContainText('not independent corroboration')

  // The same set, fetchable beside the page by anybody, with no account.
  const published = await page.request.get(new URL('logs.json', url).href)
  expect(published.ok()).toBe(true)
  const document = await published.json() as { logs: { log_id: string, independent?: boolean }[] }
  expect(document.logs[0]?.log_id).toBe('1Iw8uAnl63-NzdTys4KmO8d0GphTBiNC4AqxJyaaRFQ')
  expect(document.logs[0]?.independent).toBe(false)

  await stop(server)
})

test('a reader can add a log and take one away, and the verdict follows', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)

  // The corpus's log is not the one this page ships, so the attachment reads
  // as absent evidence — and the verdict is otherwise whole.
  await page.setInputFiles('#file', registry)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(label(page, 'log not trusted')).toHaveCount(1)

  await page.fill('#trust-line', corpusLog())
  await page.click('#trust-add')
  await expect(page.locator('#trust-logs li')).toHaveCount(2)
  await expect(label(page, 'log not trusted')).toHaveCount(0)
  // What the file alone still cannot answer: a revocation is a later leaf.
  await expect(label(page, 'revocation not checked')).toHaveCount(1)
  // And it is what holds the card at amber, named beside the title (§7).
  await expect(page.locator('.verdict')).toHaveClass(/\bamber\b/)
  await expect(page.locator('.verdict .ceiling')).toContainText('revocation not checked')

  // And off again: refusing every log is a supported way to read this page.
  await page.uncheck('#trust-logs input[data-trust="1"]')
  await expect(label(page, 'log not trusted')).toHaveCount(1)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')

  await stop(server)
})

/**
 * The second panel, on the same terms as the first and for the opposite
 * reason. A transparency log we run has to be kept from reading as a third
 * party; a timestamping authority really is one, so the risk runs the other
 * way — a reader could take a token for a statement about the file. The panel
 * has to say both halves, publish the same bytes beside the page, and let the
 * whole set be switched off without the verdict becoming an error.
 */
test('names the authority it ships with, says what a token does not prove, and publishes the same bytes', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)

  const row = page.locator('#tsa-roots > li')
  await expect(row).toHaveCount(1)
  await expect(row).toContainText('a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc')
  await expect(row).toContainText('Run by somebody else')
  await expect(row).toContainText('never who made the file')
  // The caveat that keeps a free service from reading as a guarantee.
  await expect(row).toContainText('no contractual liability')

  const published = await page.request.get(new URL('tsa.json', url).href)
  expect(published.ok()).toBe(true)
  const document = await published.json() as { authorities: { fingerprint_sha256: string, independent?: boolean }[] }
  expect(document.authorities[0]?.fingerprint_sha256).toBe('a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc')
  expect(document.authorities[0]?.independent).toBe(true)

  await stop(server)
})

test('switching every authority off leaves a whole verdict, not an error', async ({ page }) => {
  const { server, url } = await serve()
  await page.goto(url)

  await page.setInputFiles('#file', join(vectors, '59-jpeg-timestamped/input.jpg'))
  await expect(page.locator('.verdict h2')).toContainText('Authentic')

  await page.uncheck('#tsa-roots input[type=checkbox]')
  await expect(page.locator('.verdict h2')).toContainText('Authentic')
  await expect(label(page, 'trusted time not evaluated')).toHaveCount(1)

  await stop(server)
})
