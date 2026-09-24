import { type Bytes, concat, fromBase64, isInstant } from './bytes.js'
import { jcs, type Json } from './jcs.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import type { TrustedLog } from './registry.js'

/**
 * Spec §6.2, `attestation_status`: what Google's attestation status list said
 * about the certificates of the chain, at an instant when it still said
 * anything about them, countersigned by the registry.
 *
 * The attachment exists because the question §7 poses expires. A proof is
 * validated at the proven instant of its capture, so what matters is whether
 * the chain was revoked *then* — and once a certificate expires its status
 * stops being published, so the answer must have been frozen while the chain
 * was current. Google's list carries no signature of its own, which is why the
 * registry's countersignature is the transportable form.
 *
 * It is evidence, not a verdict: this code checks the signature and reads the
 * entries, and the conclusion is drawn here, from the entries and the instant.
 */
export interface StatusEntry { serial: string, status: string, reason?: string, revoked_at?: number }

export interface StatusAttachment {
  source: string
  fetched_at: number
  entries: StatusEntry[]
  sig: string
}

export type StatusOutcome =
  // The entries as signed. What they mean for the chain — covered, revoked,
  // when — depends on the chain and on the proven instant, and is decided by
  // `chainStatus` below, not here.
  | { ok: true, fetchedAt: number, entries: StatusEntry[] }
  | { ok: false, reason: string }

/** Serials compare in lowercase hex with leading zeros stripped (§6.2). */
export const serialKey = (serial: string): string => serial.toLowerCase().replace(/^0+(?=.)/, '')

/**
 * §6.2 *Coverage* and *Revoked*, for the certificates of a chain other than
 * the pinned root: a `revoked` entry is the answer whatever else is there; a
 * certificate without an entry, or with `unknown`, leaves the chain unchecked;
 * `valid` for every one of them is a checked chain.
 */
export const chainStatus = (entries: StatusEntry[], serials: string[]): { state: 'revoked', entry: StatusEntry } | { state: 'unchecked' | 'clear' } => {
  const bySerial = new Map(entries.map((e) => [serialKey(e.serial), e]))
  const found = serials.map((s) => bySerial.get(serialKey(s)))
  const revoked = found.find((e) => e?.status === 'revoked')
  if (revoked) return { state: 'revoked', entry: revoked }
  return found.every((e) => e?.status === 'valid') ? { state: 'clear' } : { state: 'unchecked' }
}

// §9 declares `source` extensible; a verifier that does not know the source
// ignores the attachment rather than guessing what the values mean.
const KNOWN_SOURCES = new Set(['googleStatusList'])

/** §6.2: `core_hash ‖ JCS(entries) ‖ uint64 BE fetched_at`. */
export const statusMessage = (coreHash: Bytes, a: StatusAttachment): Bytes => {
  const at = new Uint8Array(8)
  new DataView(at.buffer).setBigUint64(0, BigInt(a.fetched_at))
  return concat(coreHash, jcs(a.entries as unknown as Json), at)
}

/**
 * The signing key is the one that signs tree heads, and the attachment does not
 * name it: the proof's `registry.log_id` names it when a registry attachment is
 * present, and otherwise every trusted log key is tried, since a signature that
 * verifies identifies the key that made it.
 */
export const verifyStatus = async (a: StatusAttachment, coreHash: Bytes, trusted: TrustedLog[], preferredLogId?: string): Promise<StatusOutcome> => {
  if (!KNOWN_SOURCES.has(a.source)) return { ok: false, reason: `unknown status source ${a.source}` }
  if (trusted.length === 0) return { ok: false, reason: 'no trusted log key to check the countersignature with' }
  if (!isInstant(a.fetched_at)) return { ok: false, reason: 'fetched_at is not an instant' }
  if (!Array.isArray(a.entries) || !a.entries.every((e) => typeof e === 'object' && e !== null && typeof e.serial === 'string' && typeof e.status === 'string' && (e.revoked_at === undefined || isInstant(e.revoked_at)))) return { ok: false, reason: 'entries malformed' }
  let sig: Bytes
  try { sig = fromBase64(a.sig) } catch { return { ok: false, reason: 'signature malformed' } }
  if (sig.length !== 64) return { ok: false, reason: 'signature is not 64 bytes' }

  let message: Bytes
  try { message = statusMessage(coreHash, a) } catch { return { ok: false, reason: 'entries malformed' } }
  const order = [...trusted].sort((x, y) => Number(y.logId === preferredLogId) - Number(x.logId === preferredLogId))
  for (const log of order) {
    const key = await importP256Spki(log.spki)
    if (key && await verifyEs256(key, message, sig)) return { ok: true, fetchedAt: a.fetched_at, entries: a.entries }
  }
  return { ok: false, reason: 'countersignature does not verify under any trusted log key' }
}
