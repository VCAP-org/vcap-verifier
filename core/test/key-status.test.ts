import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fromBase64, toBase64url } from '../src/bytes.js'
import { subtle } from '../src/sha.js'
import { coreHashOf, parseTrailer, verify } from '../src/index.js'
import { parseCertificate } from '../src/x509.js'
import { statusMessage } from '../src/attestation-status.js'
import { androidChain, genKey, timestampToken, tsaSigner } from './fixtures.js'
import { keyStatusFor, logId, registryFor, sign, trusted } from './log.js'

/**
 * §6.2 "Revocation, online" and the §7 row that goes with it. Two things are
 * under test, and both were places where a verdict said more than it knew.
 *
 * The device key's standing in the log is the one question a file cannot
 * answer: the `registry` attachment proves the key was in the log when a tree
 * head was signed, and a revocation is a later leaf. So green requires asking,
 * and an offline verifier says *revocation not checked* and stops at amber.
 *
 * The chain's revocation is temporal, and the two sources that report it are
 * read under one rule: a frozen snapshot can speak for an instant before the
 * capture, an online status list only ever for now.
 */
describe('the device key against the log', async () => {
  const trailer = parseTrailer(new Uint8Array(readFileSync(new URL('../vectors/01-jpeg-sealed/input.jpg', import.meta.url))))
  if (trailer.kind !== 'ok') throw new Error('vector 01 has no trailer')
  const proof = JSON.parse(new TextDecoder().decode(trailer.payload))
  const hash = await coreHashOf(proof)
  const clock = new Date(1757332800000)               // vector 01's device_clock
  const keyId = fromBase64(proof.device.key_id as string)

  // The attestation chain has to carry the proof's own signing key, or the
  // level is `none` and nothing downstream is exercised. Only the public half
  // is needed: the leaf is signed by the intermediate, not by itself.
  const signingKey = await subtle().importKey('spki', Uint8Array.from(fromBase64(proof.sig.pub as string)), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
  const leafKeys = { publicKey: signingKey, privateKey: (await genKey()).privateKey } as CryptoKeyPair
  const attested = await androidChain({ leafKeys, validity: { notBefore: new Date(clock.getTime() - 86_400_000), notAfter: new Date(clock.getTime() + 86_400_000) } })
  const registry = await registryFor({
    keyIdHex: Array.from(keyId, (b) => b.toString(16).padStart(2, '0')).join(''),
    publicKey: proof.sig.pub as string,
    timestamp: clock.getTime() - 1000
  })

  // A chain revocation observation covering every certificate but the pinned
  // root, so *chain revocation not checked* is not what keeps these verdicts
  // off green.
  const cleared = async () => {
    const entries = attested.chain.slice(0, -1).map((der) => ({ serial: parseCertificate(der).serialHex, status: 'valid' }))
    const a = { source: 'googleStatusList', fetched_at: clock.getTime() - 1000, entries, sig: '' }
    a.sig = toBase64url(await sign(Uint8Array.from(statusMessage(hash, a))))
    return a
  }
  // §7: green needs a trusted instant, so these proofs carry a timestamp token
  // at the device's own clock; the key status is asked at that instant.
  const tsa = await tsaSigner({ notBefore: new Date(clock.getTime() - 86_400_000), notAfter: new Date(clock.getTime() + 86_400_000) })
  const timestamp = { tsr: toBase64url(await timestampToken(tsa.signer, hash, { genTime: clock })) }
  const run = (extra: object, o: object = {}) => verify(trailer.media, {
    sidecar: new TextEncoder().encode(JSON.stringify({ ...proof, attestation: attested.chain.map(toBase64url), registry, timestamp, ...extra })),
    googleRoots: [parseCertificate(attested.root.der)], trustedLogs: trusted, tsaRoots: [tsa.root.der], now: clock, ...o
  })

  it('says *revocation not checked* when it cannot ask, and stops at amber', async () => {
    const v = await run({ attestation_status: await cleared() })

    expect(v.labels).not.toContain('key not in transparency log')
    expect(v.labels).not.toContain('chain revocation not checked')
    expect(v.labels).toContain('revocation not checked')
    expect(v.key_status).toEqual({ ok: false, detail: 'no log lookup available' })
    // Everything else is in place: the level is proven, the key is in the log,
    // the chain's revocation was checked. This label is the only thing between
    // this verdict and green, and that is the point of it.
    expect(v.level).toEqual({ claimed: 'tee', proven: 'tee', ceiling: 'amber' })
  })

  it('reaches green when the log places the key as valid at the capture', async () => {
    const v = await run({ attestation_status: await cleared() }, { keyStatus: async (_id: string, at: Date) => keyStatusFor(keyId, at.getTime(), 1) })

    expect(v.labels).not.toContain('revocation not checked')
    expect(v.key_status?.ok).toBe(true)
    expect(v.level).toEqual({ claimed: 'tee', proven: 'tee', ceiling: 'green' })
  })

  it('is red when the log places the key as revoked at the capture', async () => {
    const v = await run({ attestation_status: await cleared() }, { keyStatus: async (_id: string, at: Date) => keyStatusFor(keyId, at.getTime(), 2) })

    expect(v.labels).toContain('key revoked')
    expect(v.level?.ceiling).toBe('red')
  })

  it('treats an `unknown` answer as no answer', async () => {
    const v = await run({ attestation_status: await cleared() }, { keyStatus: async (_id: string, at: Date) => keyStatusFor(keyId, at.getTime(), 0) })

    expect(v.labels).toContain('revocation not checked')
    expect(v.key_status).toEqual({ ok: false, detail: 'the log answered `unknown`' })
  })

  it('refuses an answer about a different instant', async () => {
    // "Valid today" says nothing about a capture two years ago, so the instant
    // is inside the signed message and an answer for another one is not an
    // answer. Without this a log could be quoted out of context.
    const v = await run({ attestation_status: await cleared() }, { keyStatus: async () => keyStatusFor(keyId, clock.getTime() + 86_400_000, 1) })

    expect(v.key_status).toEqual({ ok: false, detail: 'status asserted for a different instant than the capture' })
    expect(v.labels).toContain('revocation not checked')
    expect(v.level?.ceiling).toBe('amber')
  })

  it('refuses an answer signed for a log it does not trust', async () => {
    const v = await run({ attestation_status: await cleared() }, { keyStatus: async (_id: string, at: Date) => keyStatusFor(keyId, at.getTime(), 1, { logId: 'not-a-trusted-log' }) })

    expect(v.key_status).toEqual({ ok: false, detail: 'status signed by a log that is not trusted' })
    expect(v.labels).toContain('revocation not checked')
  })

  it('refuses an answer whose signature covers a different status', async () => {
    const forged = await keyStatusFor(keyId, clock.getTime(), 1)
    forged.status = 2                                  // signed as valid, presented as revoked
    const v = await run({ attestation_status: await cleared() }, { keyStatus: async () => forged })

    expect(v.key_status).toEqual({ ok: false, detail: 'status signature invalid' })
    expect(v.labels).toContain('revocation not checked')
    expect(v.labels).not.toContain('key revoked')
  })

  it('does not ask about a key the log was never shown', async () => {
    // No `registry` attachment: the key is not in the log as far as anyone
    // knows, and *key not in transparency log* already says so. Asking whether
    // an unlogged key was revoked, and saying the answer is missing, would
    // report one gap as two.
    const v = await verify(trailer.media, {
      sidecar: new TextEncoder().encode(JSON.stringify({ ...proof, attestation: attested.chain.map(toBase64url) })),
      googleRoots: [parseCertificate(attested.root.der)], trustedLogs: trusted, now: clock
    })

    expect(v.labels).toContain('key not in transparency log')
    expect(v.labels).not.toContain('revocation not checked')
    expect(v.key_status).toBeUndefined()
  })

  it('survives a lookup that throws', async () => {
    const v = await run({}, { keyStatus: async () => { throw new Error('network down') } })

    expect(v.key_status).toEqual({ ok: false, detail: 'the log could not be asked' })
    expect(v.labels).toContain('revocation not checked')
  })
})

describe('the chain revocation, from either source, under one rule', async () => {
  const trailer = parseTrailer(new Uint8Array(readFileSync(new URL('../vectors/01-jpeg-sealed/input.jpg', import.meta.url))))
  if (trailer.kind !== 'ok') throw new Error('vector 01 has no trailer')
  const proof = JSON.parse(new TextDecoder().decode(trailer.payload))
  const clock = new Date(1757332800000)
  const monthLater = new Date(clock.getTime() + 30 * 86_400_000)
  // Same trick as above: the chain must carry the proof's signing key, or the
  // level is `none` before revocation says anything about it.
  const signingKey = await subtle().importKey('spki', Uint8Array.from(fromBase64(proof.sig.pub as string)), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
  const leafKeys = { publicKey: signingKey, privateKey: (await genKey()).privateKey } as CryptoKeyPair
  const attested = await androidChain({ leafKeys, validity: { notBefore: new Date(clock.getTime() - 86_400_000), notAfter: new Date(clock.getTime() + 365 * 86_400_000) } })
  const revokedSerial = parseCertificate(attested.chain[1]!).serialHex

  const run = (o: object, extra: object = {}) => verify(trailer.media, {
    sidecar: new TextEncoder().encode(JSON.stringify({ ...proof, attestation: attested.chain.map(toBase64url), ...extra })),
    googleRoots: [parseCertificate(attested.root.der)], trustedLogs: trusted, now: monthLater, ...o
  })

  it('counts an online lookup as the revocation check', async () => {
    const v = await run({ revocation: async () => null })

    expect(v.labels).not.toContain('chain revocation not checked')
    expect(v.labels).not.toContain('attestation key revoked')
  })

  it('reads an online revocation with no date as revoked: a current-status list cannot place it after the capture', async () => {
    // Google's status list carries no revocation date, and §6.2 never dates a
    // revocation by when it was read, so nothing shows the capture came first.
    const v = await run({ revocation: async (s: string) => s === revokedSerial ? { status: 'REVOKED' } : null })

    expect(v.labels).toContain('attestation key revoked')
    expect(v.labels).not.toContain('key revoked')
    expect(v.level).toMatchObject({ proven: 'none', ceiling: 'red' })
  })

  it('keeps the level when a token places the capture before the date the source gives, for a reason that is not a compromise', async () => {
    const hash = await coreHashOf(proof)
    const tsa = await tsaSigner({ notBefore: new Date(clock.getTime() - 86_400_000), notAfter: new Date(clock.getTime() + 86_400_000) })
    const timestamp = { tsr: toBase64url(await timestampToken(tsa.signer, hash, { genTime: clock })) }
    const later = clock.getTime() + 7 * 86_400_000
    const revoked = (reason: string) => async (s: string) => s === revokedSerial ? { status: 'REVOKED', reason, revoked_at: later } : null
    const superseded = await run({ revocation: revoked('SUPERSEDED'), tsaRoots: [tsa.root.der] }, { timestamp })
    expect(superseded.labels).toContain('attestation key revoked after the capture')
    expect(superseded.level?.proven).toBe('tee')
    // A compromised key vouches for nothing it ever signed, whatever the date.
    const compromised = await run({ revocation: revoked('KEY_COMPROMISE'), tsaRoots: [tsa.root.der] }, { timestamp })
    expect(compromised.labels).toContain('attestation key revoked')
    expect(compromised.level?.ceiling).toBe('red')
    // And the device's own clock is not a trusted instant: whoever holds a
    // leaked key sets it (vector 96).
    const clockOnly = await run({ revocation: revoked('SUPERSEDED') })
    expect(clockOnly.labels).toContain('attestation key revoked')
  })

  it('withdraws the level when a snapshot dates the revocation before the capture', async () => {
    const entries = [{ serial: revokedSerial, status: 'revoked', reason: 'KEY_COMPROMISE', revoked_at: clock.getTime() - 1000 }]
    const a = { source: 'googleStatusList', fetched_at: clock.getTime() - 1000, entries, sig: '' }
    a.sig = toBase64url(await sign(Uint8Array.from(statusMessage(await coreHashOf(proof), a))))
    // The online list agrees that it is revoked; only the snapshot knows when.
    const v = await run({ revocation: async (s: string) => s === revokedSerial ? { status: 'REVOKED' } : null }, { attestation_status: a })

    expect(v.labels).toContain('attestation key revoked')
    expect(v.level).toMatchObject({ proven: 'none', ceiling: 'red' })
  })
})
