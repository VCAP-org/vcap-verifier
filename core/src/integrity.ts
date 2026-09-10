import { type Bytes, concat, fromBase64 } from './bytes.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import type { TrustedLog } from './registry.js'

/**
 * Spec §6.2, `integrity`: what Google Play Integrity or Apple App Attest said
 * about the device's state, relayed by the registry.
 *
 * It cannot live in the core, because an integrity verdict arrives as a token
 * only the developer's server can decrypt — so the device could only ever
 * *declare* its own health, and a self-declaration is worthless against the
 * compromised device the check exists to flag. Signed by the registry key a
 * verifier already holds for tree heads, the verdict is Google's or Apple's,
 * relayed.
 *
 * The verdict is inside the signed message, which is the whole point of signing
 * a string this short: `failed` cannot be relabelled `hardware` in transit, and
 * the other direction is nobody's interest.
 */
export interface IntegrityAttachment {
  source: string
  verdict: string
  evaluated_at: number
  sig: string
}

export type IntegrityOutcome =
  | { ok: true, source: string, verdict: string, evaluatedAt: number }
  // `trusted` is the difference between a lie and a stranger: false means no
  // key this verifier follows made the signature, which is absent evidence and
  // not failed evidence. §8's label rule turns on exactly this.
  | { ok: false, reason: string, trusted: boolean }

// §9 keeps these extensible, so an unknown value is a later version's, not a
// broken proof — but it is also not something to relay as if understood.
const SOURCES = new Set(['playIntegrity', 'appAttest', 'none'])
const VERDICTS = new Set(['hardware', 'basic', 'unevaluated', 'failed'])

/** §6.2: `core_hash ‖ UTF-8(verdict)`. */
export const integrityMessage = (coreHash: Bytes, verdict: string): Bytes =>
  concat(coreHash, new TextEncoder().encode(verdict))

/**
 * The attachment does not name its key, so every trusted log key is tried: a
 * signature that verifies identifies the key that made it.
 */
export const verifyIntegrity = async (a: IntegrityAttachment, coreHash: Bytes, trusted: TrustedLog[]): Promise<IntegrityOutcome> => {
  if (!SOURCES.has(a.source)) return { ok: false, reason: `unknown integrity source ${a.source}`, trusted: true }
  if (!VERDICTS.has(a.verdict)) return { ok: false, reason: `unknown integrity verdict ${a.verdict}`, trusted: true }
  if (!Number.isInteger(a.evaluated_at) || a.evaluated_at < 0) return { ok: false, reason: 'evaluated_at is not an instant', trusted: true }
  let sig: Bytes
  try { sig = fromBase64(a.sig) } catch { return { ok: false, reason: 'signature malformed', trusted: true } }
  if (sig.length !== 64) return { ok: false, reason: 'signature is not 64 bytes', trusted: true }

  const message = integrityMessage(coreHash, a.verdict)
  for (const log of trusted) {
    const key = await importP256Spki(log.spki)
    if (key && await verifyEs256(key, message, sig)) {
      return { ok: true, source: a.source, verdict: a.verdict, evaluatedAt: a.evaluated_at }
    }
  }
  // A relabelled verdict lands here, and so does an honest verdict from a
  // registry this verifier does not follow. They are indistinguishable from
  // here, so the report is the weaker of the two.
  return { ok: false, reason: 'no trusted registry key signed this verdict', trusted: false }
}
