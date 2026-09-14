import { type Bytes, fromBase64, toHex } from './bytes.js'
import { logIdOf, type TrustedLog } from './registry.js'
import { sha256 } from './sha.js'

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

/**
 * The other half of a trust set: which timestamping authorities a verifier
 * will check a `timestamp` attachment against (§7).
 *
 * It is a **separate document** from the logs above, and deliberately so. The
 * two answer different questions with different key material — a log is pinned
 * by the SPKI of its signing key, a TSA by an X.509 root certificate — and,
 * more importantly, they carry different claims. A log we run is us; a TSA is
 * somebody else. A reader who drops our log and keeps a public TSA has done
 * something perfectly coherent, and one document with two arrays would have
 * made that the awkward case instead of the obvious one.
 *
 * What a pinned root buys is narrow and worth stating exactly: a token that
 * chains to it proves *this hash existed before that instant, and that
 * authority said so*. It says nothing about who made the file, and nothing
 * about whether the authority is solvent, audited or liable.
 */
export interface TsaAuthorityEntry {
  /** Lowercase hex SHA-256 of the DER certificate — the fingerprint every tool prints. */
  fingerprint_sha256: string
  /** The root itself: X.509, DER, base64. */
  certificate: string
  name?: string
  subject?: string
  operator?: string
  environment?: string
  /** Whether the authority is run by somebody other than whoever ships the verifier. */
  independent?: boolean
  /** What the entry admits about itself. Printed wherever the entry is, never summarised away. */
  caveats?: string[]
}

/**
 * The parsed roots, with the same self-check the log document gets.
 *
 * `fingerprint_sha256` is recomputed from the certificate rather than taken on
 * trust. A document whose two fields disagree is rejected: a root pinned under
 * a fingerprint that does not describe it is a root nobody can compare against
 * what their own `openssl x509 -fingerprint -sha256` prints, and the whole
 * point of publishing the fingerprint is that they can.
 */
export const parseTsaDocument = async (document: unknown): Promise<{ roots: Bytes[], entries: TsaAuthorityEntry[] }> => {
  if (!isObj(document) || !Array.isArray(document.authorities)) throw new TrustDocumentError('a TSA trust document is an object with an `authorities` array')
  const entries: TsaAuthorityEntry[] = []
  const roots: Bytes[] = []
  for (const entry of document.authorities as unknown[]) {
    if (!isObj(entry) || typeof entry.fingerprint_sha256 !== 'string' || typeof entry.certificate !== 'string') {
      throw new TrustDocumentError('every authority needs a `fingerprint_sha256` and a base64 DER `certificate`')
    }
    let der: Bytes
    try { der = fromBase64(entry.certificate) } catch { throw new TrustDocumentError(`the certificate of ${entry.fingerprint_sha256} is not base64`) }
    const derived = await fingerprintOf(der)
    if (derived !== entry.fingerprint_sha256.toLowerCase()) throw new TrustDocumentError(`fingerprint ${entry.fingerprint_sha256} is not the SHA-256 of its own certificate (that certificate is ${derived})`)
    entries.push(entry as unknown as TsaAuthorityEntry)
    roots.push(der)
  }
  return { roots, entries }
}

/** `<sha256 fingerprint>:<base64 DER certificate>`, the one-line form a reader can paste. */
export const parseTsaRoot = async (text: string): Promise<{ fingerprint: string, der: Bytes }> => {
  const colon = text.indexOf(':')
  if (colon <= 0) throw new TrustDocumentError(`expected <sha256 fingerprint>:<base64 certificate>, got ${text}`)
  const fingerprint = text.slice(0, colon).toLowerCase()
  let der: Bytes
  try { der = fromBase64(text.slice(colon + 1)) } catch { throw new TrustDocumentError(`the certificate of ${fingerprint} is not base64`) }
  const derived = await fingerprintOf(der)
  if (derived !== fingerprint) throw new TrustDocumentError(`fingerprint ${fingerprint} is not the SHA-256 of that certificate (it is ${derived})`)
  return { fingerprint, der }
}

/** The fingerprint `openssl x509 -noout -fingerprint -sha256` prints, lowercase and without colons. */
export const fingerprintOf = async (der: Bytes): Promise<string> => toHex(await sha256(der))
