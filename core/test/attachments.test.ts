import { describe, expect, it } from 'vitest'
import { fromBase64, toBase64url, toHex, utf8 } from '../src/bytes.js'
import { leafHash } from '../src/merkle.js'
import { sha256, subtle } from '../src/sha.js'
import { verifyRegistry } from '../src/registry.js'
import { verifyAnchor } from '../src/anchor.js'
import { type StatusAttachment, statusMessage, verifyStatus } from '../src/attestation-status.js'
import { type IntegrityAttachment, integrityMessage, verifyIntegrity } from '../src/integrity.js'
import { deviceKeyIdHex as keyIdHex, deviceSpki, logSpki, path, registryFor, root, sign, trusted } from './log.js'

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

describe('integrity attachment', () => {
  const attachmentFor = async (verdict: string, source = 'playIntegrity'): Promise<IntegrityAttachment> => {
    const coreHash = await sha256(utf8('a core'))
    return { source, verdict, evaluated_at: 1757331000, sig: toBase64url(await sign(integrityMessage(coreHash, verdict))) }
  }

  it('relays a verdict signed by a trusted registry key', async () => {
    const coreHash = await sha256(utf8('a core'))
    for (const verdict of ['hardware', 'basic', 'unevaluated', 'failed']) {
      expect(await verifyIntegrity(await attachmentFor(verdict), coreHash, trusted))
        .toMatchObject({ ok: true, verdict, source: 'playIntegrity' })
    }
  })

  it('will not let a verdict be relabelled, because the verdict is inside the signature', async () => {
    const coreHash = await sha256(utf8('a core'))
    const failed = await attachmentFor('failed')
    // The one attack this attachment exists to stop: a relay that says
    // `hardware` where the platform said `failed`.
    expect(await verifyIntegrity({ ...failed, verdict: 'hardware' }, coreHash, trusted))
      .toMatchObject({ ok: false, trusted: false })
  })

  it('is bound to the core it was issued for', async () => {
    expect(await verifyIntegrity(await attachmentFor('hardware'), await sha256(utf8('another core')), trusted))
      .toMatchObject({ ok: false, trusted: false })
  })

  it('separates a verdict it cannot read from one that failed', async () => {
    const coreHash = await sha256(utf8('a core'))
    // Unknown values are the attachment's own fault: §9 makes them a later
    // version's, but relaying one as if understood is worse than saying so.
    // `trusted: true` is what §8 turns into *integrity evidence invalid*.
    expect(await verifyIntegrity(await attachmentFor('rooted'), coreHash, trusted))
      .toMatchObject({ ok: false, trusted: true })
    expect(await verifyIntegrity(await attachmentFor('hardware', 'knoxAttest'), coreHash, trusted))
      .toMatchObject({ ok: false, trusted: true })
    const short = await attachmentFor('hardware')
    expect(await verifyIntegrity({ ...short, sig: toBase64url(new Uint8Array(63)) }, coreHash, trusted))
      .toMatchObject({ ok: false, trusted: true })
    expect(await verifyIntegrity({ ...short, evaluated_at: -1 }, coreHash, trusted))
      .toMatchObject({ ok: false, trusted: true })
    // And a registry this verifier does not follow is absence, not failure:
    // indistinguishable from a forgery here, so reported as the weaker one.
    expect(await verifyIntegrity(short, coreHash, []))
      .toMatchObject({ ok: false, trusted: false })
  })
})

describe('bytes', () => {
  it('round-trips base64url and hex without Buffer', () => {
    const b = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255])
    expect(fromBase64(toBase64url(b))).toEqual(b)
    expect(toHex(b)).toBe('000102fafbfcfdfeff')
  })
})

// §6.2, `attestation_status`: the chain's revocation status frozen while the
// chain was still current, countersigned by the log key the verifier already
// holds for tree heads.
describe('chain revocation snapshot', () => {
  const coreHash = new Uint8Array(32).fill(9)
  const entries = [{ serial: 'aa', status: 'valid' }]
  const snapshot = async (o: { entries?: StatusAttachment['entries'], fetchedAt?: number, source?: string, signer?: (m: Uint8Array) => Promise<Uint8Array> } = {}): Promise<StatusAttachment> => {
    const a: StatusAttachment = { source: o.source ?? 'googleStatusList', fetched_at: o.fetchedAt ?? 1757332800000, entries: o.entries ?? entries, sig: '' }
    a.sig = toBase64url(await (o.signer ?? sign)(statusMessage(coreHash, a)))
    return a
  }

  it('reads a countersigned snapshot that clears the chain', async () => {
    expect(await verifyStatus(await snapshot(), coreHash, trusted)).toEqual({ ok: true, fetchedAt: 1757332800000, revoked: null })
  })

  it('names the revoked certificate and the instant the list was read', async () => {
    const a = await snapshot({ entries: [{ serial: 'aa', status: 'valid' }, { serial: 'bb', status: 'revoked', reason: 'KEY_COMPROMISE' }] })

    expect(await verifyStatus(a, coreHash, trusted)).toEqual({ ok: true, fetchedAt: 1757332800000, revoked: { serial: 'bb', reason: 'KEY_COMPROMISE' } })
  })

  it('refuses a snapshot signed by a key the verifier does not trust for tree heads', async () => {
    const other = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const a = await snapshot({ signer: async (m) => new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, other.privateKey, Uint8Array.from(m))) })

    expect(await verifyStatus(a, coreHash, trusted)).toEqual({ ok: false, reason: 'countersignature does not verify under any trusted log key' })
  })

  it('refuses a snapshot whose entries were edited after signing', async () => {
    const a = await snapshot()
    a.entries = [{ serial: 'aa', status: 'revoked' }]

    expect((await verifyStatus(a, coreHash, trusted)).ok).toBe(false)
  })

  it('refuses a snapshot moved to another instant, because fetched_at is signed', async () => {
    const a = await snapshot()
    a.fetched_at += 1000

    expect((await verifyStatus(a, coreHash, trusted)).ok).toBe(false)
  })

  it('ignores a source it does not know (§9), rather than guessing what the values mean', async () => {
    expect(await verifyStatus(await snapshot({ source: 'someOtherList' }), coreHash, trusted)).toEqual({ ok: false, reason: 'unknown status source someOtherList' })
  })

  it('says so when it holds no log key to check the countersignature with', async () => {
    expect((await verifyStatus(await snapshot(), coreHash, [])).ok).toBe(false)
  })
})
