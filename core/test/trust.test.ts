import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { fingerprintOf, parseTrustDocument, parseTrustedLog, parseTsaDocument, parseTsaRoot, TrustDocumentError } from '../src/trust.js'
import { logIdOf } from '../src/registry.js'
import { fromBase64, toBase64url } from '../src/bytes.js'

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

/**
 * The same rule, for the other half of a trust set. A TSA root is pinned by
 * the fingerprint a reader can reproduce with `openssl x509 -noout
 * -fingerprint -sha256`, and the reason to publish that fingerprint at all is
 * that they can compare it — so a document whose two fields disagree must be
 * refused rather than pinning a certificate under a name that describes
 * something else.
 */
describe('parseTsaDocument', () => {
  const root = (): string => {
    const { authorities } = JSON.parse(readFileSync(join(import.meta.dirname, '../../trust/tsa.json'), 'utf8')) as { authorities: { certificate: string }[] }
    return authorities[0]?.certificate as string
  }

  it('reads an authority and decodes its certificate', async () => {
    const parsed = await parseTsaDocument({ authorities: [{ fingerprint_sha256: await fingerprintOf(fromBase64(root())), certificate: root() }] })
    expect(parsed.roots).toHaveLength(1)
  })

  it('refuses a fingerprint that is not its own certificate’s', async () => {
    await expect(parseTsaDocument({ authorities: [{ fingerprint_sha256: '00'.repeat(32), certificate: root() }] })).rejects.toBeInstanceOf(TrustDocumentError)
  })

  it('refuses a document that is not one', async () => {
    await expect(parseTsaDocument({ authorities: [{ fingerprint_sha256: 'x' }] })).rejects.toBeInstanceOf(TrustDocumentError)
    await expect(parseTsaDocument({ logs: [] })).rejects.toBeInstanceOf(TrustDocumentError)
  })

  it('reads and refuses a single `<fingerprint>:<certificate>` line', async () => {
    const der = fromBase64(root())
    const fingerprint = await fingerprintOf(der)
    expect((await parseTsaRoot(`${fingerprint}:${root()}`)).fingerprint).toBe(fingerprint)
    await expect(parseTsaRoot(`${'00'.repeat(32)}:${root()}`)).rejects.toBeInstanceOf(TrustDocumentError)
    await expect(parseTsaRoot(root())).rejects.toBeInstanceOf(TrustDocumentError)
  })
})

/**
 * The authorities this repository ships. Unlike the log above, a TSA is a real
 * third party — so this entry is allowed to claim more, and the test pins how
 * much more. It must say who runs it, that somebody else does, and it must
 * still carry its caveats: a free service with no SLA and no liability is
 * exactly as useful as it is, and a document that printed the independence and
 * swallowed the caveats would be selling it.
 */
describe('trust/tsa.json', () => {
  const document = JSON.parse(readFileSync(join(import.meta.dirname, '../../trust/tsa.json'), 'utf8')) as {
    authorities: { fingerprint_sha256: string, certificate: string, operator?: string, independent?: boolean, environment?: string, proves?: string, does_not_prove?: string, caveats?: string[] }[]
  }

  it('parses, and every fingerprint is the hash of its own certificate', async () => {
    const parsed = await parseTsaDocument(document)
    expect(parsed.roots.length).toBeGreaterThan(0)
    for (let at = 0; at < parsed.roots.length; at++) {
      expect(await fingerprintOf(parsed.roots[at] as Uint8Array)).toBe(document.authorities[at]?.fingerprint_sha256)
    }
  })

  it('says who runs every authority, what it proves, and what it does not', () => {
    for (const entry of document.authorities) {
      expect(entry.operator).toBeTruthy()
      expect(entry.environment).toBeTruthy()
      expect(typeof entry.independent).toBe('boolean')
      expect(entry.proves).toBeTruthy()
      expect(entry.does_not_prove).toBeTruthy()
      expect(entry.caveats?.length).toBeGreaterThan(0)
    }
  })
})
