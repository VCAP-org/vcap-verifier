import { type Bytes, concat, fromBase64, u64be, utf8 } from './bytes.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import { type TrustedLog, treeHeadMessage } from './registry.js'

/**
 * Spec §6.2 `registry` → "Revocation, online": the device key's standing in the
 * transparency log **at the instant the capture is validated at**.
 *
 * The `registry` attachment proves the key was in the log when a tree head was
 * signed; it cannot prove the key was not revoked later, because a revocation
 * is a *later* leaf and nothing in a Merkle tree proves a leaf's absence. So
 * the answer is a statement signed by the log key over a fixed-length message,
 * and it answers the question for one instant only — the log applies the
 * temporal rule (`effective_from`, `retroactive`) before it signs.
 *
 * A verifier with no network gets no statement, and §7 requires it to say so:
 * *revocation not checked*, amber. That is the one check green cannot be
 * reached without, and it is deliberate — the whole point of the level table
 * is that green never means less than it says.
 */
export type KeyStatusCode = 0 | 1 | 2  // 0x00 unknown, 0x01 valid, 0x02 revoked

export interface KeyStatusStatement {
  log_id: string
  /** ms, the instant the status is asserted for: the verifier's question, echoed. */
  at: number
  tree_size: number
  status: number
  /** ES256, P1363, by the log's tree-head key. */
  signature: string
  /** The head of `tree_size`, when the log returned it: checked under the same key. */
  tree_head?: { tree_size: number, timestamp: number, root_hash: string, signature: string }
}

/**
 * Supplied by the caller, never by this module: the core contacts nothing. It
 * is handed the key id (hex, as the log spells it) and the instant to ask
 * about, and returns what the log signed, or null when it could not ask.
 */
export type KeyStatusLookup = (keyIdHex: string, at: Date) => Promise<KeyStatusStatement | null>

export type KeyStatusOutcome =
  | { ok: true, status: KeyStatusCode, at: number, treeSize: number }
  | { ok: false, reason: string }

const STATUS = utf8('vcap/1.0/status')

export const keyStatusMessage = (keyId: Bytes, at: number, treeSize: number, status: KeyStatusCode): Bytes =>
  concat(STATUS, keyId, u64be(at), u64be(treeSize), Uint8Array.of(status))

export const verifyKeyStatus = async (
  s: KeyStatusStatement,
  keyId: Bytes,
  asked: Date,
  trusted: TrustedLog[]
): Promise<KeyStatusOutcome> => {
  if (keyId.length !== 32) return { ok: false, reason: 'device.key_id is not a 32-byte hash' }
  const log = trusted.find((t) => t.logId === s.log_id)
  if (!log) return { ok: false, reason: 'status signed by a log that is not trusted' }
  const key = await importP256Spki(log.spki)
  if (!key) return { ok: false, reason: 'log key unusable' }
  if (s.status !== 0 && s.status !== 1 && s.status !== 2) return { ok: false, reason: `unknown status code ${s.status}` }
  // The instant is part of the signed message, so a log cannot be quoted out of
  // context: an answer about a different moment answers a different question,
  // and "valid today" says nothing about a capture two years ago.
  if (s.at !== asked.getTime()) return { ok: false, reason: 'status asserted for a different instant than the capture' }
  let sig: Bytes
  try { sig = fromBase64(s.signature) } catch { return { ok: false, reason: 'status signature malformed' } }
  if (!await verifyEs256(key, keyStatusMessage(keyId, s.at, s.tree_size, s.status), sig)) {
    return { ok: false, reason: 'status signature invalid' }
  }
  if (s.tree_head) {
    if (s.tree_head.tree_size !== s.tree_size) return { ok: false, reason: 'tree head is for a different tree size' }
    let root: Bytes, headSig: Bytes
    try { root = fromBase64(s.tree_head.root_hash); headSig = fromBase64(s.tree_head.signature) } catch { return { ok: false, reason: 'tree head malformed' } }
    if (root.length !== 32 || !await verifyEs256(key, treeHeadMessage(s.tree_head.tree_size, s.tree_head.timestamp, root), headSig)) {
      return { ok: false, reason: 'tree head signature invalid' }
    }
  }
  return { ok: true, status: s.status, at: s.at, treeSize: s.tree_size }
}
