import { describe, expect, it } from 'vitest'
import { parseCertificate } from '../src/x509.js'
import { validateTimestamp } from '../src/rfc3161.js'
import { validateAndroidAttestation } from '../src/attestation/android.js'
import { sha256, subtle } from '../src/sha.js'
import { type Issued, androidChain, genKey, issue, timestampToken, tsaSigner } from './fixtures.js'

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
  // §7: what instant the certificate paths are validated at, and what proved it.
  const clock = new Date(1757332800000)               // vector 01's device_clock
  const dayBefore = new Date(clock.getTime() - 86_400_000)
  const dayAfter = new Date(clock.getTime() + 86_400_000)
  const monthLater = new Date(clock.getTime() + 30 * 86_400_000)
  // Two TSA identities: one still current when the verifier runs, one that
  // covered the capture and has expired since.
  const current = await tsaSigner({ notBefore: dayBefore, notAfter: new Date(clock.getTime() + 365 * 86_400_000) })
  const lapsed = await tsaSigner({ notBefore: dayBefore, notAfter: dayAfter })
  const tokenAt = async (t: { root: Issued, signer: Issued }) => toBase64url(await timestampToken(t.signer, hash, { genTime: clock }))

  it('names the device clock as the instant when nothing better exists', async () => {
    const v = await verify(trailer.media, { sidecar: withProof({}) })
    expect(v.validated_at).toEqual({ instant: clock.toISOString(), source: 'device_clock' })
  })
  it('names the token as the instant when one is valid', async () => {
    const v = await verify(trailer.media, { sidecar: withProof({ timestamp: { tsr: await tokenAt(current) } }), tsaRoots: [current.root.der], now: monthLater })
    expect(v.validated_at).toEqual({ instant: clock.toISOString(), source: 'timestamp' })
  })
  it('keeps a chain that was valid at the capture and expired since, and says the capture time is only claimed', async () => {
    // The measured case: an RKP intermediate lives about twelve days, so a
    // month after the capture the chain is expired at the verifier's clock and
    // valid at the instant the proof declares.
    const a = await androidChain({ validity: { notBefore: dayBefore, notAfter: dayAfter } })
    const v = await verify(trailer.media, { sidecar: withProof({ attestation: a.chain.map(toBase64url) }), googleRoots: [parseCertificate(a.root.der)], now: monthLater })
    expect(v.attestation?.detail).not.toContain('outside its validity')
    expect(v.labels).toContain('attestation chain expired, capture time not proven')
    expect(v.level?.ceiling).toBe('amber')
  })
  it('says nothing about the expiry when the instant is proven by a token', async () => {
    const a = await androidChain({ validity: { notBefore: dayBefore, notAfter: dayAfter } })
    const v = await verify(trailer.media, {
      sidecar: withProof({ attestation: a.chain.map(toBase64url), timestamp: { tsr: await tokenAt(current) } }),
      googleRoots: [parseCertificate(a.root.der)], tsaRoots: [current.root.der], now: monthLater
    })
    expect(v.validated_at?.source).toBe('timestamp')
    expect(v.labels).not.toContain('attestation chain expired, capture time not proven')
  })
  it('validates the TSA chain at genTime, so a token outlives its TSA certificate', async () => {
    // Without this, long-term validation is impossible: the token proves the
    // bytes existed in 2026 and becomes unverifiable the day the TSA
    // certificate expires, which is the opposite of what it is for.
    const v = await verify(trailer.media, { sidecar: withProof({ timestamp: { tsr: await tokenAt(lapsed) } }), tsaRoots: [lapsed.root.der], now: monthLater })
    expect(v.timestamp?.ok).toBe(true)
    expect(v.labels).not.toContain('timestamp evidence invalid')
  })

  // §6.2 read at the level: the same entries mean different things before and
  // after the instant the proof is validated at.
  describe('the frozen chain revocation snapshot', async () => {
    const { statusMessage } = await import('../src/attestation-status.js')
    const { logIdOf } = await import('../src/registry.js')
    const { subtle } = await import('../src/sha.js')
    const logKeys = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const logSpki = new Uint8Array(await subtle().exportKey('spki', logKeys.publicKey))
    const trustedLogs = [{ logId: await logIdOf(logSpki), spki: logSpki }]

    const frozen = async (o: { revoked?: boolean, fetchedAt?: number } = {}) => {
      const entries = o.revoked ? [{ serial: 'bb', status: 'revoked', reason: 'KEY_COMPROMISE' }] : [{ serial: 'aa', status: 'valid' }]
      const a = { source: 'googleStatusList', fetched_at: o.fetchedAt ?? clock.getTime(), entries, sig: '' }
      a.sig = toBase64url(new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, logKeys.privateKey, Uint8Array.from(statusMessage(await coreHashOf(proof), a)))))
      return a
    }
    const withChain = async (extra: object) => {
      const a = await androidChain()
      return verify(trailer.media, { sidecar: withProof({ attestation: a.chain.map(toBase64url), ...extra }), googleRoots: [parseCertificate(a.root.der)], trustedLogs, now: monthLater })
    }

    it('is the revocation check when it clears the chain: offline is no longer *not checked*', async () => {
      const v = await withChain({ attestation_status: await frozen() })

      expect(v.attestation_status?.ok).toBe(true)
      expect(v.labels).not.toContain('chain revocation not checked')
    })
    it('is red for the level when a certificate was revoked at or before the capture', async () => {
      const v = await withChain({ attestation_status: await frozen({ revoked: true, fetchedAt: clock.getTime() - 1000 }) })

      expect(v.labels).toContain('attestation key revoked')
      expect(v.level).toMatchObject({ proven: 'none', ceiling: 'red' })
    })
    it('leaves the level standing when the revocation came after the capture', async () => {
      const v = await withChain({ attestation_status: await frozen({ revoked: true, fetchedAt: clock.getTime() + 86_400_000 }) })

      expect(v.labels).toContain('attestation key revoked after the capture')
      expect(v.labels).not.toContain('attestation key revoked')
      expect(v.level?.ceiling).not.toBe('red')
    })
    it('adds nothing and takes nothing away when the countersignature does not check out', async () => {
      const forged = await frozen()
      forged.entries = [{ serial: 'aa', status: 'valid', reason: 'edited after signing' }]
      const v = await withChain({ attestation_status: forged })

      expect(v.attestation_status?.ok).toBe(false)
      expect(v.labels).toContain('chain revocation not checked')
      expect(v.labels).not.toContain('attestation key revoked')
    })
  })

  it('flags an attestation chain whose key is not the signer, and the claim above it', async () => {
    const a = await androidChain()
    const v = await verify(trailer.media, { sidecar: withProof({ attestation: a.chain.map(toBase64url) }), googleRoots: [parseCertificate(a.root.der)] })
    expect(v.attestation?.proven).toBe('none')
    expect(v.labels).toContain('inconsistent claim')
    expect(v.labels).toContain('chain revocation not checked')
    expect(v.level?.ceiling).toBe('amber')
  })
})
