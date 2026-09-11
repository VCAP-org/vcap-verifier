import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { canonicalBytes, coreHashOf, evaluateWatermark, extractCore, jcs, parseTrailer, toBase64url, toHex, verify } from '../src/index.js'
import type { WatermarkClaim, WatermarkEvidence } from '../src/watermark.js'
import { sha256, subtle } from '../src/sha.js'
import { genKey } from './fixtures.js'

/**
 * Spec §8, "A declared watermark that does not come back": the three non-red
 * outcomes of a declared `watermark` and the red one underneath them.
 *
 * Before this, the core emitted *watermark not evaluated* unconditionally,
 * because nothing could ever hand it a detection. These tests cover both
 * halves of that change: that the unconditional answer is exactly what a
 * caller with no lookup still gets, and that each of §8's rows is reachable
 * with one.
 */

const vector = (name: string) => {
  const file = new Uint8Array(readFileSync(new URL(`../vectors/${name}/input.${name.includes('mp4') ? 'mp4' : 'jpg'}`, import.meta.url)))
  const trailer = parseTrailer(file)
  if (trailer.kind !== 'ok') throw new Error(`${name} has no trailer`)
  return { file, media: trailer.media, proof: JSON.parse(new TextDecoder().decode(trailer.payload)) as Record<string, unknown> }
}

const photo = vector('01-jpeg-sealed')
/** Vector 01's capture id, hex: the payload `photo-bch-v3` carries verbatim. */
const CAPTURE_ID = toHex(Uint8Array.from(Buffer.from(photo.proof.capture_id as string, 'base64url')))

/** A detection the caller reports; only `decoded` decides an outcome. */
const seen = (decoded: string | null, extra: Partial<WatermarkEvidence> = {}): WatermarkEvidence =>
  ({ layout: 'photo-bch-v3', decoded, model_version: 'videoseal-y256b-3', frames_sampled: 1, ...extra })

const run = (evidence: WatermarkEvidence | null, o: object = {}) =>
  verify(photo.file, { watermark: async () => evidence, now: new Date(1757332800000), ...o })

/**
 * A proof re-signed around a watermark block of our choosing. The corpus
 * declares `photo-bch-v3` on the stills and `video-rep-v1` with no `mark_id`
 * on the clips, so the layout rows of §8 need a proof that does not exist in
 * it — and `watermark` is inside the signed core, so editing it means signing
 * it again.
 */
const sealed = async (watermark: unknown, over: Record<string, unknown> = {}): Promise<{ media: Uint8Array, sidecar: Uint8Array }> => {
  const keys = await genKey()
  const spki = new Uint8Array(await subtle().exportKey('spki', keys.publicKey))
  const proof: Record<string, unknown> = {
    ...photo.proof,
    ...over,
    watermark,
    media: { ...(photo.proof.media as object), hash: toBase64url(await sha256(canonicalBytes(photo.media))) },
    device: { ...(photo.proof.device as object), key_id: toBase64url(await sha256(spki)) }
  }
  const core = jcs(extractCore(proof as never))
  const value = new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, Uint8Array.from(core)))
  proof.sig = { alg: 'ES256', value: toBase64url(value), pub: toBase64url(spki) }
  return { media: photo.media, sidecar: new TextEncoder().encode(JSON.stringify(proof)) }
}

describe('§8 — a declared watermark with no lookup', () => {
  it('reproduces today\'s verdict exactly: *watermark not evaluated*, and nothing else moves', async () => {
    const before = await verify(photo.file, { now: new Date(1757332800000) })
    // The same call with the option left out is the same object, member for
    // member. This is the property the 84 conformance vectors rest on.
    const after = await verify(photo.file, { now: new Date(1757332800000), watermark: undefined })

    expect(after).toEqual(before)
    expect(before.labels).toContain('watermark not evaluated')
    expect(before.watermark).toBeUndefined()
  })

  it('says *no watermark* when the core declares none, lookup or not', async () => {
    const { media, sidecar } = await sealed(undefined)
    const v = await verify(media, { sidecar, watermark: async () => seen(CAPTURE_ID) })

    // §8's absent row. Nothing was declared, so nothing is looked for, and a
    // detection offered for it is never consulted.
    expect(v.labels).toContain('no watermark')
    expect(v.labels).not.toContain('watermark matched')
    expect(v.watermark).toBeUndefined()
  })
})

describe('§8 — the three non-red outcomes', () => {
  it('*watermark matched*: the payload decodes and matches the proof', async () => {
    const v = await run(seen(CAPTURE_ID, { corrected_bits: 3 }))

    expect(v.outcome).toBe('authentic')
    expect(v.labels).toContain('watermark matched')
    expect(v.labels).not.toContain('watermark not evaluated')
    expect(v.watermark).toMatchObject({ result: 'matched', layout: 'photo-bch-v3', declared: CAPTURE_ID, decoded: CAPTURE_ID, corrected_bits: 3, model_version: 'videoseal-y256b-3' })
  })

  it('*watermark matched* is a label and never a green verdict — the §7 ceiling does not move', async () => {
    const without = await run(null)
    const withMark = await run(seen(CAPTURE_ID))

    // Vector 01 carries no attestation and no registry: amber is the honest
    // ceiling, and a mark in the pixels cannot buy any of the three things
    // §7 requires for green. "A watermark alone is never a green verdict."
    expect(without.level?.ceiling).toBe('amber')
    expect(withMark.level).toEqual(without.level)
  })

  it('*watermark not recovered*: the layout is known, the payload does not decode', async () => {
    const v = await run(seen(null, { agreement: 0.61 }))

    // The normal outcome of heavy re-compression. It weakens nothing: a
    // watermark is not part of what `sig` covers.
    expect(v.outcome).toBe('authentic')
    expect(v.labels).toContain('watermark not recovered')
    expect(v.watermark).toMatchObject({ result: 'not_recovered', declared: CAPTURE_ID, agreement: 0.61 })
    expect(v.watermark?.decoded).toBeUndefined()
  })

  it('*watermark not evaluated*: the layout is not one this verifier implements', async () => {
    const { media, sidecar } = await sealed({ algo: 'videoseal', layout: 'photo-bch-v9', payload_bits: 128, ecc: 'bch-255-131', strength: 8 })
    const v = await verify(media, { sidecar, watermark: async () => seen(CAPTURE_ID, { layout: 'photo-bch-v9' }) })

    expect(v.outcome).toBe('authentic')
    expect(v.labels).toContain('watermark not evaluated')
    expect(v.watermark).toEqual({ result: 'not_evaluated', detail: 'layout "photo-bch-v9" is not one this verifier implements' })
  })

  it('*watermark not evaluated*: the lookup could not answer', async () => {
    const v = await run(null)

    expect(v.labels).toContain('watermark not evaluated')
    expect(v.watermark).toEqual({ result: 'not_evaluated', detail: 'no detection was available' })
  })

  it('*watermark not evaluated*: a lookup that throws is an absent answer, not a failure', async () => {
    const v = await verify(photo.file, { watermark: async () => { throw new Error('the detector is down') } })

    // §8: an absent field is a weaker verdict, never an error. A caller whose
    // detector fell over gets the same answer as one that has none.
    expect(v.outcome).toBe('authentic')
    expect(v.labels).toContain('watermark not evaluated')
  })

  it('*watermark not evaluated*: `video-rep-v1` with no `mark_id` binds the payload to nothing', async () => {
    const clip = vector('33-mp4-video-sealed')
    const v = await verify(clip.file, { watermark: async () => ({ layout: 'video-rep-v1', decoded: '11074285' }) })

    // 24 bits collide by design, so a mark the proof does not bind is a lookup
    // hint and never an identification (`watermark-layouts-1.0.md`).
    expect(v.labels).toContain('watermark not evaluated')
    expect(v.watermark).toMatchObject({ result: 'not_evaluated', detail: 'the proof declares no mark id to compare against' })
  })
})

describe('§8 — "Invalidating — red": a payload that decodes to another id', () => {
  it('is red, with its reason and no labels', async () => {
    const other = '0f1e2d3c4b5a69788796a5b4c3d2e1f0'
    const v = await run(seen(other))

    expect(v.outcome).toBe('tampered')
    expect(v.reason).toContain(other)
    // §8: "a red verdict carries its reason and nothing else".
    expect(v.labels).toEqual([])
    expect(v.watermark).toMatchObject({ result: 'contradicted', declared: CAPTURE_ID, decoded: other })
  })

  it('a `video-rep-v1` mark id the proof binds to a different value is the same row', async () => {
    const { media, sidecar } = await sealed({ algo: 'videoseal', layout: 'video-rep-v1', payload_bits: 24, ecc: 'rep-8-crc8', strength: 20, mark_id: 11074285 })
    const matched = await verify(media, { sidecar, watermark: async () => ({ layout: 'video-rep-v1', decoded: '11074285', agreement: 0.98 }) })
    const v = await verify(media, { sidecar, watermark: async () => ({ layout: 'video-rep-v1', decoded: '4290898', agreement: 0.93 }) })

    // The id the comparison uses is named per layout (§8): `capture_id` for
    // `photo-bch-v3`, `watermark.mark_id` for `video-rep-v1`.
    expect(matched.labels).toContain('watermark matched')
    expect(v.outcome).toBe('tampered')
    expect(v.watermark).toMatchObject({ result: 'contradicted', declared: '11074285', decoded: '4290898' })
  })

  it('a payload that fails to decode is *not recovered* and never this', async () => {
    // The narrowing that matters: a clip a messaging app re-compressed comes
    // back with nothing decodable, and calling that forged is the worst
    // mistake this format can make.
    expect((await run(seen(null))).outcome).toBe('authentic')
  })
})

describe('the evidence is data from an untrusted caller', () => {
  const claim: WatermarkClaim = { layout: 'photo-bch-v3', captureId: CAPTURE_ID, mime: 'image/jpeg', coreHash: 'ff' }

  it('never takes the caller\'s word for the comparison — only for what came out of the pixels', async () => {
    // The platform's evidence block carries its own `outcome`. It is not read:
    // the comparison is made here, against the id the device signed.
    const v = await run({ ...seen(CAPTURE_ID), outcome: 'mismatched' } as WatermarkEvidence)

    expect(v.outcome).toBe('authentic')
    expect(v.watermark?.result).toBe('matched')
  })

  it('reads a malformed payload as *not evaluated*, never as a contradiction', () => {
    // The failure that matters: garbage sliding into the red row. An id that
    // is not a `photo-bch-v3` payload is not evidence of anything.
    for (const decoded of ['', 'not-hex', CAPTURE_ID + 'ff', '../../etc/passwd', '0'.repeat(31)]) {
      expect(evaluateWatermark({ decoded }, claim).result).toBe('not_evaluated')
    }
    expect(evaluateWatermark({ decoded: 42 }, claim).result).toBe('not_evaluated')
    expect(evaluateWatermark('a string', claim).result).toBe('not_evaluated')
    expect(evaluateWatermark(null, claim).result).toBe('not_evaluated')
  })

  it('refuses a mark id outside the 24 bits the layout carries', () => {
    const video: WatermarkClaim = { layout: 'video-rep-v1', captureId: CAPTURE_ID, markId: 1, mime: 'video/mp4', coreHash: 'ff' }
    expect(evaluateWatermark({ decoded: '16777216' }, video).result).toBe('not_evaluated')
    expect(evaluateWatermark({ decoded: '16777215' }, video).result).toBe('contradicted')
    expect(evaluateWatermark({ decoded: '1' }, video).result).toBe('matched')
  })

  it('does not answer a question it was not asked: a detection of another layout', () => {
    const v = evaluateWatermark({ layout: 'video-rep-v1', decoded: '1' }, claim)
    expect(v.result).toBe('not_evaluated')
    expect(v.detail).toContain('the proof declares "photo-bch-v3"')
  })

  it('drops figures outside their range rather than showing them', () => {
    const v = evaluateWatermark({ decoded: null, agreement: 7, corrected_bits: -1, frames_sampled: Number.NaN, model_version: '', sampling: { frames: 24 } }, claim)
    expect(v).toEqual({ result: 'not_recovered', detail: 'the payload did not decode', layout: 'photo-bch-v3', declared: CAPTURE_ID })
  })

  it('hands the lookup the core hash, so a caller relaying a cached detection can bind it', async () => {
    const seenClaim: WatermarkClaim[] = []
    const v = await verify(photo.file, { watermark: async (c) => { seenClaim.push(c); return null } })

    expect(seenClaim).toHaveLength(1)
    expect(seenClaim[0]).toEqual({ layout: 'photo-bch-v3', captureId: CAPTURE_ID, mime: 'image/jpeg', coreHash: v.core_hash })
    expect(v.core_hash).toBe(toHex(await coreHashOf(photo.proof as never)))
  })
})
