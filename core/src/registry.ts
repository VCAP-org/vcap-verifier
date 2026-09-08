import { type Bytes, concat, fromBase64, u64be, utf8, equal, toBase64url } from './bytes.js'
import { sha256 } from './sha.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import { jcs, type Json } from './jcs.js'
import { leafHash, verifyInclusion } from './merkle.js'

/**
 * Spec §6.2 `registry`: the leaf, its inclusion path and the signed tree head,
 * carried inline; verified against the public key of a trusted log, keyed by
 * log_id = base64url(SHA-256(SPKI)). No server of ours is involved.
 */
export interface TrustedLog { logId: string, spki: Bytes }

export interface RegistryAttachment {
  log_id: string
  leaf_index: number
  leaf: { type: 'key', key_id: string, public_key: string, secure_hw: string, attestation_digest: string, registered_at: number }
  inclusion_path: string[]
  tree_head: { tree_size: number, timestamp: number, root_hash: string, signature: string }
}

export type RegistryOutcome =
  | { ok: true, secureHw: string, registeredAt: number, treeHeadTimestamp: number }
  | { ok: false, reason: string }

const STH = utf8('vcap/1.0/sth')

export const treeHeadMessage = (size: number, timestamp: number, root: Bytes): Bytes => concat(STH, u64be(size), u64be(timestamp), root)

export const verifyRegistry = async (r: RegistryAttachment, expected: { keyIdHex: string, sigPub: Bytes }, trusted: TrustedLog[]): Promise<RegistryOutcome> => {
  const log = trusted.find((t) => t.logId === r.log_id)
  if (!log) return { ok: false, reason: 'log not trusted' }
  const key = await importP256Spki(log.spki)
  if (!key) return { ok: false, reason: 'log key unusable' }
  let root: Bytes, sig: Bytes
  try { root = fromBase64(r.tree_head.root_hash); sig = fromBase64(r.tree_head.signature) } catch { return { ok: false, reason: 'tree head malformed' } }
  if (root.length !== 32 || !await verifyEs256(key, treeHeadMessage(r.tree_head.tree_size, r.tree_head.timestamp, root), sig)) return { ok: false, reason: 'tree head signature invalid' }

  const leaf = await leafHash(jcs(r.leaf as unknown as Json))
  let path: Bytes[]
  try { path = r.inclusion_path.map(fromBase64) } catch { return { ok: false, reason: 'inclusion path malformed' } }
  if (!await verifyInclusion(leaf, r.leaf_index, r.tree_head.tree_size, path, root)) return { ok: false, reason: 'inclusion proof invalid' }

  if (r.leaf.key_id !== expected.keyIdHex) return { ok: false, reason: 'leaf key_id differs from device.key_id' }
  let leafPub: Bytes
  try { leafPub = fromBase64(r.leaf.public_key) } catch { return { ok: false, reason: 'leaf public key malformed' } }
  if (!equal(leafPub, expected.sigPub)) return { ok: false, reason: 'leaf public key differs from sig.pub' }
  return { ok: true, secureHw: r.leaf.secure_hw, registeredAt: r.leaf.registered_at, treeHeadTimestamp: r.tree_head.timestamp }
}

export const logIdOf = async (spki: Bytes): Promise<string> => toBase64url(await sha256(spki))
