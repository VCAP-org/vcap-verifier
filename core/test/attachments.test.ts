import { describe, expect, it } from 'vitest'
import { fromBase64, toBase64url, toHex, utf8 } from '../src/bytes.js'
import { jcs } from '../src/jcs.js'
import { leafHash, nodeHash } from '../src/merkle.js'
import { sha256, subtle } from '../src/sha.js'
import { logIdOf, treeHeadMessage, verifyRegistry, type RegistryAttachment } from '../src/registry.js'
import { verifyAnchor } from '../src/anchor.js'

// Attachments are not in the spec vectors yet (they need the log and the
// chain), so they are exercised here with a test log key and trees built by
// hand with the same RFC 6962 functions.

const keyPair = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
const logSpki = new Uint8Array(await subtle().exportKey('spki', keyPair.publicKey))
const sign = async (message: Uint8Array): Promise<Uint8Array> => new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, Uint8Array.from(message)))

// Root and audit path over a list of leaf hashes (RFC 6962 §2.1.1), test-side only.
const root = async (h: Uint8Array[]): Promise<Uint8Array> => {
  if (h.length === 1) return h[0] as Uint8Array
  let k = 1; while (k * 2 < h.length) k *= 2
  return nodeHash(await root(h.slice(0, k)), await root(h.slice(k)))
}
const path = async (h: Uint8Array[], m: number): Promise<Uint8Array[]> => {
  if (h.length === 1) return []
  let k = 1; while (k * 2 < h.length) k *= 2
  return m < k ? [...await path(h.slice(0, k), m), await root(h.slice(k))] : [...await path(h.slice(k), m - k), await root(h.slice(0, k))]
}

const deviceSpki = new Uint8Array(await subtle().exportKey('spki', (await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey))
const keyIdHex = toHex(await sha256(deviceSpki))

const registryFor = async (o: { keyIdHex?: string, pub?: Uint8Array, timestamp?: number, forgeSize?: boolean } = {}): Promise<RegistryAttachment> => {
  const leaf = { type: 'key' as const, key_id: o.keyIdHex ?? keyIdHex, public_key: toBase64url(o.pub ?? deviceSpki).replace(/-/g, '+').replace(/_/g, '/'), secure_hw: 'tee', attestation_digest: 'a'.repeat(64), registered_at: 1757332800000 }
  const others = await Promise.all([1, 2, 3].map((n) => leafHash(utf8(`other leaf ${n}`))))
  const hashes = [others[0] as Uint8Array, await leafHash(jcs(leaf)), others[1] as Uint8Array, others[2] as Uint8Array]
  const r = await root(hashes)
  const size = o.forgeSize ? 5 : 4
  const timestamp = o.timestamp ?? 1757332900000
  return {
    log_id: await logIdOf(logSpki), leaf_index: 1, leaf,
    inclusion_path: (await path(hashes, 1)).map(toBase64url),
    tree_head: { tree_size: size, timestamp, root_hash: toBase64url(r), signature: toBase64url(await sign(treeHeadMessage(4, timestamp, r))) }
  }
}
const trusted = [{ logId: await logIdOf(logSpki), spki: logSpki }]

describe('registry attachment', () => {
  it('verifies a leaf for the signing key under a trusted log head', async () => {
    const r = await verifyRegistry(await registryFor(), { keyIdHex, sigPub: deviceSpki }, trusted)
    expect(r).toMatchObject({ ok: true, secureHw: 'tee' })
  })

  it('refuses an untrusted log, a forged head, a foreign leaf and a key mismatch', async () => {
    expect(await verifyRegistry(await registryFor(), { keyIdHex, sigPub: deviceSpki }, [])).toMatchObject({ ok: false, reason: 'log not trusted' })
    expect(await verifyRegistry(await registryFor({ forgeSize: true }), { keyIdHex, sigPub: deviceSpki }, trusted)).toMatchObject({ ok: false, reason: 'tree head signature invalid' })
    expect(await verifyRegistry(await registryFor({ keyIdHex: 'b'.repeat(64) }), { keyIdHex, sigPub: deviceSpki }, trusted)).toMatchObject({ ok: false, reason: 'leaf key_id differs from device.key_id' })
    expect(await verifyRegistry(await registryFor(), { keyIdHex, sigPub: logSpki }, trusted)).toMatchObject({ ok: false, reason: 'leaf public key differs from sig.pub' })
    const broken = await registryFor(); broken.inclusion_path = broken.inclusion_path.slice(1)
    expect(await verifyRegistry(broken, { keyIdHex, sigPub: deviceSpki }, trusted)).toMatchObject({ ok: false, reason: 'inclusion proof invalid' })
  })
})

describe('anchor attachment', () => {
  it('recomputes the batch root from core_hash and the path, and compares with the chain when a reader is given', async () => {
    const coreHash = await sha256(utf8('a core'))
    const hashes = [await leafHash(utf8('x')), await leafHash(coreHash), await leafHash(utf8('z'))]
    const r = await root(hashes)
    const attachment = { chain: 'base-sepolia', tx: '0x' + '1'.repeat(64), block: 42, anchor_id: 7, index: 1, tree_size: 3, root: toBase64url(r), merkle_path: (await path(hashes, 1)).map(toBase64url) }

    expect(await verifyAnchor(attachment, coreHash)).toMatchObject({ ok: true, onChain: false })
    expect(await verifyAnchor(attachment, coreHash, async () => ({ root: r, treeSize: 3 }))).toMatchObject({ ok: true, onChain: true, block: 42 })
    expect(await verifyAnchor(attachment, coreHash, async () => ({ root: r, treeSize: 4 }))).toMatchObject({ ok: false, reason: 'anchored root differs from the chain' })
    expect(await verifyAnchor(attachment, coreHash, async () => null)).toMatchObject({ ok: false, reason: 'anchor not found on chain' })
    expect(await verifyAnchor({ ...attachment, index: 0 }, coreHash)).toMatchObject({ ok: false })
    expect(await verifyAnchor(attachment, await sha256(utf8('another core')))).toMatchObject({ ok: false })
  })
})

describe('bytes', () => {
  it('round-trips base64url and hex without Buffer', () => {
    const b = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255])
    expect(fromBase64(toBase64url(b))).toEqual(b)
    expect(toHex(b)).toBe('000102fafbfcfdfeff')
  })
})
