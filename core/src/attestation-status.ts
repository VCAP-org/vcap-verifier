import { type Bytes, concat, fromBase64 } from './bytes.js'
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
export interface StatusAttachment {
  source: string
  fetched_at: number
  entries: { serial: string, status: string, reason?: string }[]
  sig: string
}

export type StatusOutcome =
  // `revoked` names the first certificate the list had an entry for; null means
  // the list had nothing against any of them, which is a checked revocation
  // rather than an unchecked one.
  | { ok: true, fetchedAt: number, revoked: { serial: string, reason?: string } | null }
  | { ok: false, reason: string }

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
  if (!Number.isInteger(a.fetched_at) || a.fetched_at < 0) return { ok: false, reason: 'fetched_at is not an instant' }
  let sig: Bytes
  try { sig = fromBase64(a.sig) } catch { return { ok: false, reason: 'signature malformed' } }
  if (sig.length !== 64) return { ok: false, reason: 'signature is not 64 bytes' }

  const message = statusMessage(coreHash, a)
  const order = [...trusted].sort((x, y) => Number(y.logId === preferredLogId) - Number(x.logId === preferredLogId))
  for (const log of order) {
    const key = await importP256Spki(log.spki)
    if (key && await verifyEs256(key, message, sig)) {
      const revoked = a.entries.find((e) => e.status !== 'valid')
      return { ok: true, fetchedAt: a.fetched_at, revoked: revoked ? { serial: revoked.serial, reason: revoked.reason } : null }
    }
  }
  return { ok: false, reason: 'countersignature does not verify under any trusted log key' }
}
