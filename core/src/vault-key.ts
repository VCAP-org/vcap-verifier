import { type Bytes, concat, fromBase64, u32be, u64be, utf8 } from './bytes.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import type { TrustedLog } from './registry.js'

/**
 * The log's statement about an organization's **vault key**: the public key a
 * fleet of phones encrypts stored originals under (`vcap-vault-1.md`).
 *
 * Not part of a proof and never part of a verdict — nothing here changes what
 * §7 says about a file. It is checked by the device that is about to encrypt
 * under that key, and by anybody auditing what an organization published.
 *
 * ## What a valid signature proves, exactly
 *
 * That **this log recorded this key at this index**. Not that the key belongs
 * to the organization a phone was told it belongs to: between an organization
 * and a phone stands the platform that serves both, and no signature of that
 * platform's log can rule out a substitution by that platform. What it buys is
 * what a transparency log always buys — a swap is a second leaf, public, dated
 * and impossible to withdraw. `vcap-spec`'s threat model says so in the same
 * words, and a caller that renders this as "the key is genuine" has
 * misunderstood it.
 *
 * ## Why a device checks it at all
 *
 * Because the alternative is a person comparing a fingerprint on two screens.
 * A phone that can check the statement refuses a key whose evidence does not
 * hold up *before* it encrypts anything — and reports "not published" and "log
 * not trusted" as the different things they are.
 *
 *   "vcap/1.0/vault-key" (18) || key_id (32) || uint32 BE epoch || uint64 BE index
 */
export interface VaultKeyStatement {
  /** Which log signed it: a statement nobody can attribute is evidence of nothing. */
  log_id: string
  /** SHA-256 of the key's SPKI, 64 lowercase hex. */
  key_id: string
  epoch: number
  /** Where the leaf landed. */
  log_index: number
  /** ES256, P1363, by the log's tree-head key. */
  signature: string
}

export type VaultKeyOutcome =
  | { ok: true, logId: string, epoch: number, logIndex: number }
  | { ok: false, reason: string }

const VAULT_KEY = utf8('vcap/1.0/vault-key')

export const vaultKeyMessage = (keyId: Bytes, epoch: number, index: number): Bytes =>
  concat(VAULT_KEY, keyId, u32be(epoch), u64be(index))

export const verifyVaultKey = async (s: VaultKeyStatement, trusted: TrustedLog[]): Promise<VaultKeyOutcome> => {
  if (!/^[0-9a-f]{64}$/.test(s.key_id)) return { ok: false, reason: 'key_id is not a 32-byte hash' }
  if (!Number.isSafeInteger(s.epoch) || s.epoch < 1) return { ok: false, reason: 'epoch is not a positive integer' }
  if (!Number.isSafeInteger(s.log_index) || s.log_index < 0) return { ok: false, reason: 'log_index is not an index' }
  // A log outside the trust set is absent evidence, not failed evidence — the
  // same rule `registry` follows, and the difference matters to a caller that
  // must not treat "I cannot check this" as "this is wrong".
  const log = trusted.find((t) => t.logId === s.log_id)
  if (!log) return { ok: false, reason: 'log not trusted' }
  const key = await importP256Spki(log.spki)
  if (!key) return { ok: false, reason: 'log key unusable' }
  const keyId = Uint8Array.from((s.key_id.match(/../g) ?? []).map((b) => parseInt(b, 16)))
  let sig: Bytes
  try { sig = fromBase64(s.signature) } catch { return { ok: false, reason: 'statement signature malformed' } }
  if (!await verifyEs256(key, vaultKeyMessage(keyId, s.epoch, s.log_index), sig)) {
    return { ok: false, reason: 'statement signature invalid' }
  }
  return { ok: true, logId: s.log_id, epoch: s.epoch, logIndex: s.log_index }
}
