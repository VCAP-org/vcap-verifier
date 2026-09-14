import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { parseTrustDocument, parseTrustedLog, TrustDocumentError } from '../src/trust.js'
import { logIdOf } from '../src/registry.js'
import { toBase64url } from '../src/bytes.js'

/**
 * A trust document is a list of people somebody decided to believe, so the one
 * thing that must never pass quietly is an entry whose name and key disagree:
 * `log_id` is *defined* as the SHA-256 of the SPKI, and a document that pins a
 * key under some other id pins a key no proof will ever cite while looking, to
 * a reader, exactly like a set that works.
 */
const spkiOf = async (): Promise<{ spki: string, logId: string }> => {
  const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const der = new Uint8Array(await crypto.subtle.exportKey('spki', key.publicKey))
  return { spki: btoa(String.fromCharCode(...der)), logId: await logIdOf(der) }
}

describe('parseTrustDocument', () => {
  it('reads a log and decodes its key', async () => {
    const { spki, logId } = await spkiOf()
    const parsed = await parseTrustDocument({ logs: [{ log_id: logId, spki, name: 'a log' }] })
    expect(parsed.logs).toHaveLength(1)
    expect(parsed.logs[0]?.logId).toBe(logId)
    expect(await logIdOf(parsed.logs[0]?.spki as Uint8Array)).toBe(logId)
    expect(parsed.entries[0]?.name).toBe('a log')
  })

  it('refuses an id that is not the hash of the key it names', async () => {
    const { spki } = await spkiOf()
    const other = await spkiOf()
    await expect(parseTrustDocument({ logs: [{ log_id: other.logId, spki }] })).rejects.toBeInstanceOf(TrustDocumentError)
  })

  it('refuses a document that is not one', async () => {
    await expect(parseTrustDocument({ logs: [{ log_id: 'x' }] })).rejects.toBeInstanceOf(TrustDocumentError)
    await expect(parseTrustDocument([])).rejects.toBeInstanceOf(TrustDocumentError)
  })

  it('reads and refuses a single `<log_id>:<spki>` line', async () => {
    const { spki, logId } = await spkiOf()
    expect((await parseTrustedLog(`${logId}:${spki}`)).logId).toBe(logId)
    await expect(parseTrustedLog(`${toBase64url(new Uint8Array(32))}:${spki}`)).rejects.toBeInstanceOf(TrustDocumentError)
    await expect(parseTrustedLog(spki)).rejects.toBeInstanceOf(TrustDocumentError)
  })
})

/**
 * The set this repository ships. It is the one trust decision made on the
 * reader's behalf, so it is checked here: that it parses, that each id is its
 * own key's hash, and that every log run by the project says so in the entry —
 * the page and the CLI print that flag, and a log that forgot it would be
 * presented as a second opinion.
 */
describe('trust/logs.json', () => {
  const document = JSON.parse(readFileSync(join(import.meta.dirname, '../../trust/logs.json'), 'utf8')) as {
    logs: { log_id: string, operator?: string, independent?: boolean, environment?: string }[]
  }

  it('parses, and every id is the hash of its own key', async () => {
    const parsed = await parseTrustDocument(document)
    expect(parsed.logs.length).toBeGreaterThan(0)
    for (const log of parsed.logs) expect(await logIdOf(log.spki)).toBe(log.logId)
  })

  it('says who runs every log, and never leaves ours looking independent', () => {
    for (const entry of document.logs) {
      expect(entry.operator).toBeTruthy()
      expect(entry.environment).toBeTruthy()
      expect(typeof entry.independent).toBe('boolean')
    }
  })
})
