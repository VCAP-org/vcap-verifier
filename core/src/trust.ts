import { type Bytes, fromBase64 } from './bytes.js'
import { logIdOf, type TrustedLog } from './registry.js'

/**
 * Reading a trust set that somebody wrote down.
 *
 * A trust document is the list of transparency logs a verifier will check a
 * `registry` attachment against (§6.2). It is *data*: this file parses it and
 * nothing here decides whose logs belong in it. The core ships no default set
 * on purpose — a library that trusted somebody by importing it would put that
 * decision out of the caller's sight, and the whole claim of this verifier is
 * that the reader chooses who they believe.
 *
 * The document that the page, the CLI and the app happen to load lives in
 * `trust/logs.json` at the root of this repository.
 */
export interface TrustDocumentEntry {
  log_id: string
  /** DER SubjectPublicKeyInfo, base64. */
  spki: string
  name?: string
  environment?: string
  operator?: string
  /** Whether the log is run by somebody other than whoever ships the verifier. */
  independent?: boolean
}

export interface TrustDocument {
  logs: TrustDocumentEntry[]
}

export class TrustDocumentError extends Error {}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

/**
 * The parsed entries, with their keys decoded, exactly as written.
 *
 * `log_id` is not taken on trust: it is `base64url(SHA-256(spki))` by
 * definition, so a document whose two fields disagree is rejected rather than
 * silently pinning a key under a name no proof will ever cite. That check is
 * the reason this is a function and not a JSON import.
 */
export const parseTrustDocument = async (document: unknown): Promise<{ logs: TrustedLog[], entries: TrustDocumentEntry[] }> => {
  if (!isObj(document) || !Array.isArray(document.logs)) throw new TrustDocumentError('a trust document is an object with a `logs` array')
  const entries: TrustDocumentEntry[] = []
  const logs: TrustedLog[] = []
  for (const entry of document.logs as unknown[]) {
    if (!isObj(entry) || typeof entry.log_id !== 'string' || typeof entry.spki !== 'string') {
      throw new TrustDocumentError('every log needs a `log_id` and a base64 `spki`')
    }
    let spki: Bytes
    try { spki = fromBase64(entry.spki) } catch { throw new TrustDocumentError(`the spki of ${entry.log_id} is not base64`) }
    const derived = await logIdOf(spki)
    if (derived !== entry.log_id) throw new TrustDocumentError(`log_id ${entry.log_id} is not the SHA-256 of its own spki (that key is ${derived})`)
    entries.push(entry as unknown as TrustDocumentEntry)
    logs.push({ logId: entry.log_id, spki })
  }
  return { logs, entries }
}

/** `<log_id>:<base64 spki>`, the one-line form a reader can type or paste. */
export const parseTrustedLog = async (text: string): Promise<TrustedLog> => {
  // The id is base64url, so it never contains a colon: the split is on the
  // first one and the SPKI keeps its padding.
  const colon = text.indexOf(':')
  if (colon <= 0) throw new TrustDocumentError(`expected <log_id>:<base64 spki>, got ${text}`)
  const logId = text.slice(0, colon)
  let spki: Bytes
  try { spki = fromBase64(text.slice(colon + 1)) } catch { throw new TrustDocumentError(`the spki of ${logId} is not base64`) }
  const derived = await logIdOf(spki)
  if (derived !== logId) throw new TrustDocumentError(`log_id ${logId} is not the SHA-256 of that key (it is ${derived})`)
  return { logId, spki }
}
