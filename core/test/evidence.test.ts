import { describe, expect, it } from 'vitest'
import { parseCertificate } from '../src/x509.js'
import { validateTimestamp } from '../src/rfc3161.js'
import { validateAndroidAttestation } from '../src/attestation/android.js'
import { sha256, subtle } from '../src/sha.js'
import { androidChain, genKey, issue, timestampToken, tsaSigner } from './fixtures.js'

const coreHash = await sha256(new Uint8Array([1, 2, 3]))
const failed = (v: { checks: { id: string, outcome: string }[] }) => v.checks.filter((c) => c.outcome === 'fail').map((c) => c.id)

describe('RFC 3161 token', async () => {
  const { root, signer } = await tsaSigner()
  const roots = [parseCertificate(root.der)]

  it('accepts a token over the core hash from a pinned TSA', async () => {
    const v = await validateTimestamp(await timestampToken(signer, coreHash), coreHash, roots)
    expect(v.ok).toBe(true)
    expect(v.genTime).toBeDefined()
  })
  it('rejects an imprint over other bytes', async () => {
    const v = await validateTimestamp(await timestampToken(signer, await sha256(new Uint8Array([9]))), coreHash, roots)
    expect(failed(v)).toEqual(['imprint'])
  })
  it('rejects a messageDigest that does not hash the TSTInfo', async () => {
    expect(failed(await validateTimestamp(await timestampToken(signer, coreHash, { wrongDigest: true }), coreHash, roots))).toEqual(['message_digest'])
  })
  it('rejects a signature by another key', async () => {
    expect(failed(await validateTimestamp(await timestampToken(signer, coreHash, { wrongSigner: (await genKey()).privateKey }), coreHash, roots))).toEqual(['signature'])
  })
  it('rejects a signer outside the pinned roots', async () => {
    const other = await tsaSigner()
    expect(failed(await validateTimestamp(await timestampToken(other.signer, coreHash), coreHash, roots))).toEqual(['signer_chain'])
  })
  it('rejects a signer without the timeStamping usage', async () => {
    const plain = await issue({ subject: 'CN=Not a TSA', issuer: root })
    expect(failed(await validateTimestamp(await timestampToken(plain, coreHash), coreHash, roots))).toEqual(['signer_usage'])
  })
  it('rejects a genTime in the future', async () => {
    expect(failed(await validateTimestamp(await timestampToken(signer, coreHash, { genTime: new Date(Date.now() + 3_600_000) }), coreHash, roots))).toEqual(['gen_time'])
  })
  it('fails closed on garbage', async () => {
    const v = await validateTimestamp(new Uint8Array([0x30, 0x03, 1, 2]), coreHash, roots)
    expect(v.ok).toBe(false)
    expect(failed(v)).toEqual(['token_parsed'])
  })
})

describe('Android key attestation', () => {
  it('proves tee for a valid chain on a locked, verified device', async () => {
    const a = await androidChain()
    const r = await validateAndroidAttestation(a.chain, a.spki, { roots: [parseCertificate(a.root.der)] })
    expect(r.proven).toBe('tee')
    expect(r.revocation).toBe('not_checked')
    expect(r.bootState).toEqual({ locked: true, state: 'verified' })
  })
  it('proves the weaker of the two levels', async () => {
    const a = await androidChain({ attestation: 2, keyMint: 1 })
    expect((await validateAndroidAttestation(a.chain, a.spki, { roots: [parseCertificate(a.root.der)] })).proven).toBe('tee')
    const b = await androidChain({ attestation: 2, keyMint: 2 })
    expect((await validateAndroidAttestation(b.chain, b.spki, { roots: [parseCertificate(b.root.der)] })).proven).toBe('strongbox')
  })
  it('proves none for software, an unlocked device or a foreign root', async () => {
    const sw = await androidChain({ attestation: 0, keyMint: 0 })
    expect((await validateAndroidAttestation(sw.chain, sw.spki, { roots: [parseCertificate(sw.root.der)] })).proven).toBe('none')
    const unlocked = await androidChain({ locked: false })
    expect((await validateAndroidAttestation(unlocked.chain, unlocked.spki, { roots: [parseCertificate(unlocked.root.der)] })).proven).toBe('none')
    const foreign = await androidChain()
    const r = await validateAndroidAttestation(foreign.chain, foreign.spki, { roots: [parseCertificate((await androidChain()).root.der)] })
    expect(r.proven).toBe('none')
    expect(failed(r)).toEqual(['chain_root'])
  })
  it('proves none when the leaf key is not the signing key', async () => {
    const a = await androidChain()
    const other = new Uint8Array(await subtle().exportKey('spki', (await genKey()).publicKey))
    const r = await validateAndroidAttestation(a.chain, other, { roots: [parseCertificate(a.root.der)] })
    expect(failed(r)).toEqual(['key_binding'])
    expect(r.proven).toBe('none')
  })
  it('uses the status list when given', async () => {
    const a = await androidChain()
    const revoked = parseCertificate(a.chain[1]!).serialHex
    const r = await validateAndroidAttestation(a.chain, a.spki, { roots: [parseCertificate(a.root.der)], revocation: async (s) => s === revoked ? { status: 'REVOKED' } : null })
    expect(r.revocation).toBe('revoked')
    expect(r.proven).toBe('none')
    const clear = await validateAndroidAttestation(a.chain, a.spki, { roots: [parseCertificate(a.root.der)], revocation: async () => null })
    expect(clear.revocation).toBe('clear')
    expect(clear.proven).toBe('tee')
  })
  it('falls back to none without the attestation extension', async () => {
    const root = await issue({ subject: 'CN=R', ca: true })
    const leaf = await issue({ subject: 'CN=L', issuer: root })
    const spki = new Uint8Array(await subtle().exportKey('spki', leaf.keys.publicKey))
    const r = await validateAndroidAttestation([leaf.der, root.der], spki, { roots: [parseCertificate(root.der)] })
    expect(failed(r)).toEqual(['extension'])
  })
})

describe('verdict with evidence attachments', async () => {
  // Vector 01 as media + sidecar, so the token can be attached outside the signed core.
  const { readFileSync } = await import('node:fs')
  const { parseTrailer, verify, toBase64url, coreHashOf } = await import('../src/index.js')
  const trailer = parseTrailer(new Uint8Array(readFileSync(new URL('../vectors/01-jpeg-sealed/input.jpg', import.meta.url))))
  if (trailer.kind !== 'ok') throw new Error('vector 01 has no trailer')
  const proof = JSON.parse(new TextDecoder().decode(trailer.payload))
  const hash = await coreHashOf(proof)
  const { root, signer } = await tsaSigner()
  const withProof = (extra: object) => new TextEncoder().encode(JSON.stringify({ ...proof, ...extra }))

  it('leaves the token unevaluated without TSA roots', async () => {
    const v = await verify(trailer.media, { sidecar: withProof({ timestamp: { tsr: toBase64url(await timestampToken(signer, hash)) } }) })
    expect(v.labels).toContain('trusted time not evaluated')
    expect(v.timestamp).toBeUndefined()
  })
  it('reports trusted time from a valid token', async () => {
    const v = await verify(trailer.media, { sidecar: withProof({ timestamp: { tsr: toBase64url(await timestampToken(signer, hash)) } }), tsaRoots: [root.der] })
    expect(v.timestamp?.ok).toBe(true)
    expect(v.labels).not.toContain('no trusted time')
    expect(v.labels).not.toContain('trusted time not evaluated')
    expect(v.level).toEqual({ claimed: 'tee', proven: 'none', ceiling: 'amber' })
  })
  it('flags a token over other bytes', async () => {
    const v = await verify(trailer.media, { sidecar: withProof({ timestamp: { tsr: toBase64url(await timestampToken(signer, await sha256(new Uint8Array([0])))) } }), tsaRoots: [root.der] })
    expect(v.timestamp?.ok).toBe(false)
    expect(v.labels).toContain('timestamp evidence invalid')
  })
  it('flags an attestation chain whose key is not the signer, and the claim above it', async () => {
    const a = await androidChain()
    const v = await verify(trailer.media, { sidecar: withProof({ attestation: a.chain.map(toBase64url) }), googleRoots: [parseCertificate(a.root.der)] })
    expect(v.attestation?.proven).toBe('none')
    expect(v.labels).toContain('inconsistent claim')
    expect(v.labels).toContain('revocation not checked')
    expect(v.level?.ceiling).toBe('amber')
  })
})
