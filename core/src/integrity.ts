import { type Bytes, concat, fromBase64, isInstant, utf8 } from './bytes.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import { jcs, type Json } from './jcs.js'
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
 * The whole attachment but `sig` is inside the signed message —
 * `"vcap/1.0/integrity" ‖ core_hash ‖ JCS(A)`, the construction of
 * `location_corroboration` — so `failed` cannot be relabelled `hardware`, and
 * neither `source` nor `evaluated_at` can be swapped under the signature.
 */
export interface IntegrityAttachment {
  source: string
  verdict: string
  evaluated_at: number
  sig: string
}

export type IntegrityOutcome =
  | { ok: true, source: string, verdict: string, evaluatedAt: number }
  // §6.2: `source` is extensible, and one this verifier does not know is read
  // as an absent attachment — *integrity unevaluated*, nothing else.
  | { ok: false, reason: string, trusted: boolean, unknownSource: true }
  // `trusted` is the difference between a lie and a stranger: false means no
  // key this verifier follows made the signature, which is absent evidence and
  // not failed evidence. §8's label rule turns on exactly this.
  | { ok: false, reason: string, trusted: boolean }

// §9 keeps these extensible, so an unknown value is a later version's, not a
// broken proof — but it is also not something to relay as if understood.
const SOURCES = new Set(['playIntegrity', 'appAttest', 'none'])
const VERDICTS = new Set(['hardware', 'basic', 'unevaluated', 'failed'])

const SEPARATOR = utf8('vcap/1.0/integrity')

/** §6.2: `"vcap/1.0/integrity" ‖ core_hash ‖ JCS(attachment without sig)`. */
export const integrityMessage = (coreHash: Bytes, attachment: { [key: string]: Json }): Bytes => {
  const { sig: _sig, ...body } = attachment
  return concat(SEPARATOR, coreHash, jcs(body))
}

/**
 * The attachment does not name its key, so every trusted log key is tried: a
 * signature that verifies identifies the key that made it.
 */
export const verifyIntegrity = async (a: IntegrityAttachment, coreHash: Bytes, trusted: TrustedLog[]): Promise<IntegrityOutcome> => {
  if (!SOURCES.has(a.source)) return { ok: false, reason: `unknown integrity source ${String(a.source)}`, trusted: false, unknownSource: true }
  if (!VERDICTS.has(a.verdict)) return { ok: false, reason: `unknown integrity verdict ${a.verdict}`, trusted: true }
  if (!isInstant(a.evaluated_at)) return { ok: false, reason: 'evaluated_at is not an instant', trusted: true }
  let sig: Bytes
  try { sig = fromBase64(a.sig) } catch { return { ok: false, reason: 'signature malformed', trusted: true } }
  if (sig.length !== 64) return { ok: false, reason: 'signature is not 64 bytes', trusted: true }

  let message: Bytes
  try { message = integrityMessage(coreHash, a as unknown as { [key: string]: Json }) } catch { return { ok: false, reason: 'attachment malformed', trusted: true } }
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
