import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fromBase64, toBase64url, toHex } from '../src/bytes.js'
import { sha256, subtle } from '../src/sha.js'
import { coreHashOf, extractCore, jcs, parseTrailer, verify } from '../src/index.js'
import { parseCertificate } from '../src/x509.js'
import { deriveMarkId } from '../src/verify.js'
import { androidChain, genKey, timestampToken, tsaSigner } from './fixtures.js'
import { registryFor, trusted } from './log.js'

/**
 * §6.2's cross-checks between evidence that each holds on its own: the
 * registry leaf against the attestation chain and against an iOS claim, and
 * the tree head against a timestamp token. Each one is a place where two
 * valid attachments told different stories and the verdict used to believe
 * the kinder one.
 */
const trailer = parseTrailer(new Uint8Array(readFileSync(new URL('../vectors/01-jpeg-sealed/input.jpg', import.meta.url))))
if (trailer.kind !== 'ok') throw new Error('vector 01 has no trailer')
const proof = JSON.parse(new TextDecoder().decode(trailer.payload))
const clock = new Date(1757332800000)  // vector 01's device_clock
const keyIdHex = toHex(fromBase64(proof.device.key_id as string))

describe('the registry leaf against an Android chain', async () => {
  const signingKey = await subtle().importKey('spki', Uint8Array.from(fromBase64(proof.sig.pub as string)), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
  const leafKeys = { publicKey: signingKey, privateKey: (await genKey()).privateKey } as CryptoKeyPair
  const attested = await androidChain({ leafKeys, validity: { notBefore: new Date(clock.getTime() - 86_400_000), notAfter: new Date(clock.getTime() + 86_400_000) } })
  const run = async (secureHw: string) => verify(trailer.media, {
    sidecar: new TextEncoder().encode(JSON.stringify({
      ...proof,
      attestation: attested.chain.map(toBase64url),
      registry: await registryFor({ keyIdHex, publicKey: proof.sig.pub as string, secureHw, timestamp: clock.getTime() - 1000 })
    })),
    googleRoots: [parseCertificate(attested.root.der)], trustedLogs: trusted, now: clock
  })

  it('agrees when the log recorded what the chain proves', async () => {
    const v = await run('tee')
    expect(v.level?.proven).toBe('tee')
    expect(v.labels).not.toContain('inconsistent claim')
  })

  it('is an inconsistent claim when the log recorded more than the chain proves', async () => {
    const v = await run('strongbox')
    expect(v.labels).toContain('inconsistent claim')
    expect(v.level?.ceiling).toBe('amber')
  })
})

describe('the tree head against a timestamp token', async () => {
  const hash = await coreHashOf(proof)
  const tsa = await tsaSigner({ notBefore: new Date(clock.getTime() - 86_400_000), notAfter: new Date(clock.getTime() + 86_400_000) })
  const run = async (treeHead: number, genTime: number) => verify(trailer.media, {
    sidecar: new TextEncoder().encode(JSON.stringify({
      ...proof,
      timestamp: { tsr: toBase64url(await timestampToken(tsa.signer, hash, { genTime: new Date(genTime) })) },
      registry: await registryFor({ keyIdHex, publicKey: proof.sig.pub as string, timestamp: treeHead })
    })),
    tsaRoots: [tsa.root.der], trustedLogs: trusted, now: new Date(clock.getTime() + 60_000)
  })

  it('stays quiet when the key was logged before the token', async () => {
    const v = await run(clock.getTime() - 10_000, clock.getTime() - 5_000)
    expect(v.timestamp?.ok).toBe(true)
    expect(v.labels).not.toContain('registered after the declared capture')
  })

  it('flags a key logged after the token, even when the device clock says otherwise', async () => {
    // The tree head (clock − 1 s) precedes the device's own clock, so only the
    // token — a third party's instant, five seconds earlier — shows the key
    // entered the log after the capture was stamped.
    const v = await run(clock.getTime() - 1_000, clock.getTime() - 5_000)
    expect(v.timestamp?.ok).toBe(true)
    expect(v.labels).toContain('registered after the trusted time')
    expect(v.labels).not.toContain('registered after the declared capture')
  })
})

describe('an iOS claim against the registry leaf', async () => {
  // iOS carries no chain: the leaf is where App Attest put the level, so the
  // claim is measured against it. The core changes, so it is signed again.
  const sealed = async (leafLevel: string) => {
    const keys = await genKey()
    const spki = new Uint8Array(await subtle().exportKey('spki', keys.publicKey))
    const keyId = await sha256(spki)
    const ios = { ...proof, device: { platform: 'ios', secure_hw: 'secureEnclave', key_id: toBase64url(keyId) } }
    const value = new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, Uint8Array.from(jcs(extractCore(ios)))))
    ios.sig = { alg: 'ES256', value: toBase64url(value), pub: toBase64url(spki) }
    ios.registry = await registryFor({ keyIdHex: toHex(keyId), pub: spki, secureHw: leafLevel, timestamp: clock.getTime() - 1000 })
    return verify(trailer.media, { sidecar: new TextEncoder().encode(JSON.stringify(ios)), trustedLogs: trusted, now: clock })
  }

  it('proves the Secure Enclave when the leaf records it', async () => {
    const v = await sealed('secureEnclave')
    expect(v.level?.proven).toBe('secureEnclave')
    expect(v.labels).not.toContain('inconsistent claim')
  })

  it('is an inconsistent claim when the leaf records less', async () => {
    const v = await sealed('none')
    expect(v.level?.proven).toBe('none')
    expect(v.labels).toContain('inconsistent claim')
  })
})

describe('mark_id derivation', () => {
  it('matches every derivation vector of the layouts document', async () => {
    const layouts = JSON.parse(readFileSync(new URL('../vectors/_watermark/layouts.json', import.meta.url), 'utf8'))
    const cases = layouts['video-rep-v1'].derivation.cases as Array<{ capture_id: string, mark_id: number }>
    expect(cases.length).toBeGreaterThan(0)
    for (const c of cases) {
      const id = /^[0-9a-f]{32}$/.test(c.capture_id) ? Uint8Array.from(c.capture_id.match(/../g)!.map((h) => parseInt(h, 16))) : fromBase64(c.capture_id)
      expect(await deriveMarkId(id), c.capture_id).toBe(c.mark_id)
    }
  })
})
