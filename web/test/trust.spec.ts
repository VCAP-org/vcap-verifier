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
// The label list, not the details block: `log not trusted` appears in both,
// and a count that caught the second would pass for the wrong reason.
const label = (page: import('@playwright/test').Page, text: string) => page.locator('.verdict > ul > li', { hasText: new RegExp(`^${text}$`) })

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

  // And off again: refusing every log is a supported way to read this page.
  await page.uncheck('#trust-logs input[data-trust="1"]')
  await expect(label(page, 'log not trusted')).toHaveCount(1)
  await expect(page.locator('.verdict h2')).toContainText('Authentic')

  await stop(server)
})
