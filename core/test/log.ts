import { toBase64url, toHex, utf8 } from '../src/bytes.js'
import { jcs } from '../src/jcs.js'
import { leafHash, nodeHash } from '../src/merkle.js'
import { sha256, subtle } from '../src/sha.js'
import { logIdOf, treeHeadMessage, type RegistryAttachment } from '../src/registry.js'
import { keyStatusMessage, type KeyStatusStatement } from '../src/key-status.js'

// A test transparency log: one key, and trees built by hand with the same RFC
// 6962 functions the verifier uses. The attachments that need a log are not in
// the spec vectors yet — they need the log and the chain — so this is where
// they are exercised from.

const keyPair = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
export const logSpki = new Uint8Array(await subtle().exportKey('spki', keyPair.publicKey))
export const logId = await logIdOf(logSpki)
export const trusted = [{ logId, spki: logSpki }]
export const sign = async (message: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, Uint8Array.from(message)))

/** Root and audit path over a list of leaf hashes (RFC 6962 §2.1.1), test-side only. */
export const root = async (h: Uint8Array[]): Promise<Uint8Array> => {
  if (h.length === 1) return h[0] as Uint8Array
  let k = 1; while (k * 2 < h.length) k *= 2
  return nodeHash(await root(h.slice(0, k)), await root(h.slice(k)))
}
export const path = async (h: Uint8Array[], m: number): Promise<Uint8Array[]> => {
  if (h.length === 1) return []
  let k = 1; while (k * 2 < h.length) k *= 2
  return m < k ? [...await path(h.slice(0, k), m), await root(h.slice(k))] : [...await path(h.slice(k), m - k), await root(h.slice(0, k))]
}

export const deviceSpki = new Uint8Array(await subtle().exportKey('spki', (await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey))
export const deviceKeyIdHex = toHex(await sha256(deviceSpki))

/** A `registry` attachment placing one key in a four-leaf tree. */
export const registryFor = async (o: {
  keyIdHex?: string, publicKey?: string, pub?: Uint8Array, secureHw?: string, timestamp?: number, forgeSize?: boolean
} = {}): Promise<RegistryAttachment> => {
  const leaf = {
    type: 'key' as const,
    key_id: o.keyIdHex ?? deviceKeyIdHex,
    public_key: o.publicKey ?? toBase64url(o.pub ?? deviceSpki).replace(/-/g, '+').replace(/_/g, '/'),
    secure_hw: o.secureHw ?? 'tee',
    attestation_digest: 'a'.repeat(64),
    registered_at: 1757332800000
  }
  const others = await Promise.all([1, 2, 3].map((n) => leafHash(utf8(`other leaf ${n}`))))
  const hashes = [others[0] as Uint8Array, await leafHash(jcs(leaf)), others[1] as Uint8Array, others[2] as Uint8Array]
  const r = await root(hashes)
  const timestamp = o.timestamp ?? 1757332900000
  return {
    log_id: logId, leaf_index: 1, leaf,
    inclusion_path: (await path(hashes, 1)).map(toBase64url),
    tree_head: { tree_size: o.forgeSize ? 5 : 4, timestamp, root_hash: toBase64url(r), signature: toBase64url(await sign(treeHeadMessage(4, timestamp, r))) }
  }
}

/** The log's signed answer about a key at an instant (§6.2, "Revocation, online"). */
export const keyStatusFor = async (keyId: Uint8Array, at: number, status: 0 | 1 | 2, o: { treeSize?: number, logId?: string } = {}): Promise<KeyStatusStatement> => {
  const tree_size = o.treeSize ?? 4
  return {
    log_id: o.logId ?? logId, at, tree_size, status,
    signature: toBase64url(await sign(keyStatusMessage(keyId, at, tree_size, status)))
  }
}
