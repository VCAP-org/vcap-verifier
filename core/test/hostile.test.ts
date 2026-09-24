import 'reflect-metadata'
import * as x509 from '@peculiar/x509'
import * as asn1js from 'asn1js'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { readU32BE, toBase64url, u64be, utf8 } from '../src/bytes.js'
import { duplicateKey, jcs, type Json } from '../src/jcs.js'
import { sha256, subtle } from '../src/sha.js'
import { buildTrailer, parseTrailer } from '../src/trailer.js'
import { canonicalBytes } from '../src/canonical.js'
import { extractCore, verify } from '../src/verify.js'
import { recomputeSegments } from '../src/container.js'
import { verifyAnchor } from '../src/anchor.js'
import { verifyKeyStatus } from '../src/key-status.js'
import { validateAndroidAttestation } from '../src/attestation/android.js'
import { validateTimestamp } from '../src/rfc3161.js'
import { decodeGetAnchor } from '../src/chain.js'
import { parseCertificate } from '../src/x509.js'
import { androidChain, genKey, issue, keyDescription, tsaSigner } from './fixtures.js'

/**
 * Inputs that used to throw out of `verify` — each one reproduced from the
 * review that found it. The property under test is the same every time: a
 * file somebody hands over is an answer, never an exception. A page that
 * called `verify` on any of these spun forever, and the CLI reported a crash
 * as "does not verify".
 */
const read = (vector: string, file: string) => {
  const bytes = new Uint8Array(readFileSync(new URL(`../vectors/${vector}/${file}`, import.meta.url)))
  const trailer = parseTrailer(bytes)
  if (trailer.kind !== 'ok') throw new Error(`${vector}: no trailer`)
  return { file: bytes, media: trailer.media, proof: JSON.parse(new TextDecoder().decode(trailer.payload)) as Record<string, Json> }
}
const photo = read('01-jpeg-sealed', 'input.jpg')
const clip = read('33-mp4-video-sealed', 'input.mp4')
const payload = (proof: object): Uint8Array => utf8(JSON.stringify(proof))

/** Vector 01's proof re-signed around a changed core, so the signature holds and the change is reached. */
const resign = async (change: (core: Record<string, Json>) => void): Promise<Uint8Array> => {
  const keys = await genKey()
  const spki = new Uint8Array(await subtle().exportKey('spki', keys.publicKey))
  const proof = structuredClone(photo.proof) as Record<string, any>
  proof.device.key_id = toBase64url(await sha256(spki))
  change(proof)
  const core = jcs(extractCore(proof))
  const value = new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, Uint8Array.from(core)))
  proof.sig = { alg: 'ES256', value: toBase64url(value), pub: toBase64url(spki) }
  return payload(proof)
}

describe('verify never throws on a hostile proof', () => {
  it('a core nested ten thousand levels deep', async () => {
    // Written as text: JSON.stringify would overflow building it, which is the
    // point. The recursive float check used to overflow reading it.
    const text = JSON.stringify({ ...photo.proof, policy: 'X' }).replace('"policy":"X"', `"policy":{"a":${'['.repeat(10_000)}${']'.repeat(10_000)}}`)
    const v = await verify(photo.media, { sidecar: utf8(text) })
    expect(v).toMatchObject({ outcome: 'no_proof_found', reason: 'core nested too deep' })
  })

  it('an attachment nested ten thousand levels deep', async () => {
    const text = JSON.stringify({ ...photo.proof, registry: 'X' }).replace('"registry":"X"', `"registry":{"log_id":"x","leaf_index":0,"leaf":${'{"a":'.repeat(10_000)}1${'}'.repeat(10_000)}}`)
    const v = await verify(photo.media, { sidecar: utf8(text) })
    expect(v.outcome).toBe('authentic')
    expect(v.registry).toEqual({ ok: false, detail: 'leaf malformed' })
  })

  it('a device clock of 1e20, which `Date` cannot hold', async () => {
    const v = await verify(photo.media, { sidecar: await resign((p) => { (p.time as Record<string, Json>).device_clock = 1e20 }) })
    expect(v.outcome).toBe('authentic')
    expect(v.device_clock).toBeUndefined()
    expect(v.validated_at?.source).toBe('verifier_clock')
  })

  it('a JPEG whose markers cannot be walked', async () => {
    const broken = Uint8Array.from(photo.media)
    broken[2] = 0x00  // the marker after SOI
    const v = await verify(broken, { sidecar: payload(photo.proof) })
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toBe('the canonical bytes cannot be computed: JPEG: marker expected')
    expect(() => canonicalBytes(Uint8Array.of(0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff))).toThrow('JPEG: segment length out of range')
  })

  it('a registry attachment without a tree head', async () => {
    const v = await verify(photo.media, { sidecar: payload({ ...photo.proof, registry: { log_id: 'x', leaf_index: 0, leaf: {}, inclusion_path: [] } }) })
    expect(v.registry).toEqual({ ok: false, detail: 'leaf malformed' })
    expect(v.labels).toEqual(expect.arrayContaining(['registry evidence invalid', 'key not in transparency log']))
    const headless = { log_id: 'x', leaf_index: 0, leaf: { key_id: '', public_key: '', secure_hw: 'tee' }, inclusion_path: [] }
    expect((await verify(photo.media, { sidecar: payload({ ...photo.proof, registry: headless }) })).registry).toEqual({ ok: false, detail: 'tree head malformed' })
  })

  it('a `segments` array holding null, or one index twice', async () => {
    const v = await verify(clip.file, { sidecar: payload({ ...clip.proof, segments: [null] }), recomputeSegments: false })
    // The trailer wins over a differing sidecar (§3.1), so the sidecar is
    // passed over the bare media instead.
    const bare = await verify(clip.media, { sidecar: payload({ ...clip.proof, segments: [null] }), recomputeSegments: false })
    expect(v.outcome).toBe('authentic')
    expect(bare).toMatchObject({ outcome: 'tampered', reason: 'segments malformed' })
    const twice = clip.proof.segments as Json[]
    const dup = await verify(clip.media, { sidecar: payload({ ...clip.proof, segments: [twice[0], twice[0], twice[1], twice[2]] }), recomputeSegments: false })
    expect(dup).toMatchObject({ outcome: 'tampered', reason: 'a segment index appears twice in the proof' })
  })

  it('an anchor whose path is not a list, and a chain reader that answers nonsense', async () => {
    const v = await verify(photo.media, { sidecar: payload({ ...photo.proof, anchor: { chain: 'c', block: 1, anchor_id: 1, index: 0, tree_size: 1, root: 'AA', merkle_path: 'AA' } }) })
    expect(v.anchor).toEqual({ ok: false, detail: 'anchor malformed' })
    const coreHash = new Uint8Array(32)
    const leaf = await sha256(Uint8Array.of(0), coreHash)
    const attachment = { chain: 'c', tx: '', block: 1, anchor_id: 1, index: 0, tree_size: 1, root: toBase64url(leaf), merkle_path: [] }
    const odd = await verifyAnchor(attachment, coreHash, async () => ({ root: 'not bytes', treeSize: 1 } as never))
    expect(odd).toMatchObject({ ok: true, onChain: false, unread: 'the chain reader returned an unreadable answer' })
  })

  it('an RPC answer whose words do not fit a number or a date', () => {
    const word = (hex: string) => hex.padStart(64, '0')
    expect(() => decodeGetAnchor(`0x${word('1')}${'f'.repeat(64)}${word('1')}${word('1')}`)).toThrow('out of range')
    expect(() => decodeGetAnchor(`0x${word('1')}${word('1')}${word('1')}${word('ffffffffffff')}`)).toThrow('timestamp is out of range')
  })

  it('a key-status statement with a fractional tree size', async () => {
    const r = await verifyKeyStatus({ log_id: 'x', at: 1, tree_size: 1.5, status: 1, signature: '' }, new Uint8Array(32), new Date(1), [{ logId: 'x', spki: new Uint8Array() }])
    expect(r).toEqual({ ok: false, reason: 'status statement malformed' })
  })

  it('an attestation revocation lookup that throws is *not checked*, never *clear*', async () => {
    const { root, chain, spki } = await androidChain()
    const r = await validateAndroidAttestation(chain, spki, { roots: [parseCertificate(root.der)], revocation: async () => { throw new Error('offline') } })
    expect(r.revocation).toBe('not_checked')
    expect(r.proven).toBe('tee')
  })

  it('a timestamp whose SignerInfo is one INTEGER', async () => {
    const seq = (...value: asn1js.AsnType[]) => new asn1js.Sequence({ value })
    const oid = (value: string) => new asn1js.ObjectIdentifier({ value })
    const ctx = (value: asn1js.AsnType[]) => new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value })
    const tst = seq(new asn1js.Integer({ value: 1 }), oid('1.2.3'), seq(seq(oid('2.16.840.1.101.3.4.2.1')), new asn1js.OctetString({ valueHex: new ArrayBuffer(32) })), new asn1js.Integer({ value: 1 }), new asn1js.GeneralizedTime({ valueDate: new Date(0) }))
    const signedData = seq(new asn1js.Integer({ value: 3 }), new asn1js.Set({ value: [] }), seq(oid('1.2.840.113549.1.9.16.1.4'), ctx([new asn1js.OctetString({ valueHex: tst.toBER() })])), new asn1js.Set({ value: [seq(new asn1js.Integer({ value: 1 }))] }))
    const token = new Uint8Array(seq(oid('1.2.840.113549.1.7.2'), ctx([signedData])).toBER())
    const { root } = await tsaSigner()
    const t = await validateTimestamp(token, new Uint8Array(32), [parseCertificate(root.der)])
    expect(t.ok).toBe(false)
    expect(t.checks.find((c) => c.id === 'signature')?.detail).toMatch(/^SignerInfo unreadable/)
  })

  it('a chain reader whose answer throws when read is still an answer, from the net under verify', async () => {
    const boom = (): never => { throw new Error('boom') }
    // Not thenable, so `await` hands it over; every field then throws.
    const hostile = new Proxy({}, { get: (_t, key) => key === 'then' ? undefined : boom() })
    const coreHash = await sha256(jcs(extractCore(photo.proof)))
    const leaf = await sha256(Uint8Array.of(0), coreHash)
    const anchor = { chain: 'c', tx: '', block: 1, anchor_id: 1, index: 0, tree_size: 1, root: toBase64url(leaf), merkle_path: [] }
    const v = await verify(photo.media, { sidecar: payload({ ...photo.proof, anchor }), readChain: async () => hostile as never })
    expect(v).toMatchObject({ outcome: 'corrupted_proof', reason: 'the proof could not be read to the end: boom' })
  })
})

describe('the container reader under hostile tables', () => {
  const { media } = read('36-mp4-container-verified', 'input.mp4')
  const find = (b: Uint8Array, name: string): number => {
    for (let i = 4; i + 4 <= b.length; i++) if (b[i] === name.charCodeAt(0) && b[i + 1] === name.charCodeAt(1) && b[i + 2] === name.charCodeAt(2) && b[i + 3] === name.charCodeAt(3)) return i - 4
    throw new Error(`no ${name}`)
  }
  const set32 = (b: Uint8Array, at: number, v: number) => { b[at] = v >>> 24; b[at + 1] = (v >>> 16) & 0xff; b[at + 2] = (v >>> 8) & 0xff; b[at + 3] = v & 0xff }

  it('an stsz count of 2^32 − 1 is refused at once, not iterated', async () => {
    const b = Uint8Array.from(media)
    set32(b, find(b, 'stsz') + 16, 0xffffffff)
    const started = performance.now()
    expect(await recomputeSegments(b)).toEqual({ kind: 'unsupported', reason: 'table count exceeds its box' })
    expect(performance.now() - started).toBeLessThan(1000)
  })

  it('an stts run of 2^32 − 1 costs only the samples the file has', async () => {
    const b = Uint8Array.from(media)
    set32(b, find(b, 'stts') + 16, 0xffffffff)
    const started = performance.now()
    const r = await recomputeSegments(b)
    expect(r.kind).toBe('hashes')
    expect(performance.now() - started).toBeLessThan(2000)
  })

  it('a file cut inside its moov', async () => {
    const r = await recomputeSegments(media.subarray(0, find(media, 'stsz') + 10))
    expect(r.kind).toBe('unsupported')
  })

  it('reads past the end throw rather than turn into NaN', () => {
    expect(() => readU32BE(new Uint8Array(3), 0)).toThrow(RangeError)
    expect(() => u64be(1.5)).toThrow(RangeError)
    expect(() => u64be(Number.NaN)).toThrow(RangeError)
  })

  it('a trailer-only file with a stolen proof and no media never throws', async () => {
    const trailer = buildTrailer(payload(clip.proof), 2, 0)
    expect((await verify(trailer)).outcome).toBe('frames_not_compared')
  })
})

describe('RFC 8785 as it is written', () => {
  it('sorts integer-like keys by code unit, as strings', () => {
    expect(new TextDecoder().decode(jcs({ b: 1, 10: 2, 9: 3 }))).toBe('{"10":2,"9":3,"b":1}')
  })

  it('keeps a `__proto__` key', () => {
    const parsed = JSON.parse('{"__proto__":1,"a":2}') as Json
    expect(new TextDecoder().decode(jcs(parsed))).toBe('{"__proto__":1,"a":2}')
  })

  it('finds a duplicate key at any depth, decoded, and ignores equal values', () => {
    expect(duplicateKey('{"a":1,"b":{"c":1,"c":2}}')).toBe('c')
    expect(duplicateKey('{"a":1,"\\u0061":2}')).toBe('a')
    expect(duplicateKey('{"a":"a","b":["a","a"],"c":{"a":1}}')).toBeNull()
    expect(duplicateKey('[{"a":1},{"a":1}]')).toBeNull()
  })

  it('refuses a proof that repeats a key', async () => {
    const text = JSON.stringify(photo.proof).replace('"v":', '"v":"vcap/1.0","v":')
    const v = await verify(photo.media, { sidecar: utf8(text) })
    expect(v).toMatchObject({ outcome: 'no_proof_found', reason: 'payload repeats the key "v"' })
  })
})

describe('a certificate that may not issue', () => {
  it('breaks an attestation chain at the intermediate that is not a CA', async () => {
    x509.cryptoProvider.set(globalThis.crypto)
    const root = await issue({ subject: 'CN=Root', ca: true })
    const inter = await issue({ subject: 'CN=Not a CA', issuer: root, ca: false })
    const leafKeys = await genKey()
    const leaf = await issue({ subject: 'CN=Leaf', issuer: inter, keys: leafKeys, extensions: [keyDescription({ attestation: 1, keyMint: 1 })] })
    const spki = new Uint8Array(await subtle().exportKey('spki', leafKeys.publicKey))
    const r = await validateAndroidAttestation([leaf.der, inter.der, root.der], spki, { roots: [parseCertificate(root.der)] })
    expect(r.proven).toBe('none')
    expect(r.checks.find((c) => c.id === 'chain_signatures')).toMatchObject({ outcome: 'fail', detail: 'certificate 0 is not issued by certificate 1' })
  })
})
