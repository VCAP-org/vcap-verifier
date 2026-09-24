import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { VIDEO_AGREEMENT_FLOOR, canonicalBytes, coreHashOf, evaluateWatermark, extractCore, jcs, parseTrailer, toBase64url, toHex, verify } from '../src/index.js'
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
    // member. This is the property the conformance vectors rest on.
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
    expect(v.watermark).toEqual({ result: 'not_evaluated', detail: 'no detection was available: the detector is down' })
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

/**
 * `watermark-layouts-1.0.md` *The agreement floor*, and the §8 outcome it maps
 * onto. The figures are the ones that produced the rule: a campaign of 38
 * recordings on one phone where two clips resolved an id their pixels had
 * never been given, at 0.738 and 0.789, while correct ids came back as low as
 * 0.727. The floor refuses all four.
 */
describe('§8 — a `video-rep-v1` id below the agreement floor', () => {
  const video: WatermarkClaim = { layout: 'video-rep-v1', captureId: CAPTURE_ID, markId: 11074285, mime: 'video/mp4', coreHash: 'ff' }
  const decode = (decoded: string, agreement: number) => evaluateWatermark({ layout: 'video-rep-v1', decoded, agreement }, video)

  it('pins the floor the layout states', () => {
    expect(VIDEO_AGREEMENT_FLOOR).toBe(0.85)
  })

  it('does not report the wrong id the campaign resolved at 0.738 and 0.789', () => {
    for (const agreement of [0.738, 0.789]) {
      const v = decode('4290898', agreement)
      expect(v.result).toBe('not_recovered')
      expect(v.id_refused).toBe(true)
      // Not *contradicted*: a decode nobody may report is not evidence
      // against the file that carried it. Before the floor this was red.
      expect(v.detail).toContain('a mark may be present and its id is not resolvable')
      expect(v.detail).not.toContain('4290898')
      expect(v.agreement).toBe(agreement)
    }
  })

  it('costs the correct ids under the floor too, and says so in the same words', () => {
    // 0.727 is the campaign's worst *correct* recovery, below a wrong one at
    // 0.738. The populations overlap, so this is what the rule buys honesty
    // with: a true answer refused, printed exactly like a false one.
    const v = decode('11074285', 0.727)
    expect(v.result).toBe('not_recovered')
    expect(v.id_refused).toBe(true)
  })

  it('is inclusive at the floor and resolves above it', () => {
    expect(decode('11074285', 0.85).result).toBe('matched')
    expect(decode('11074285', 0.8499).result).toBe('not_recovered')
    // The worst synthetic chain measured to recover: the floor may never
    // refuse it, which is what fixes it below 0.87.
    expect(decode('11074285', 0.87).result).toBe('matched')
  })

  it('reports no id at all when the detection carries no agreement figure', () => {
    // The layout's only discriminator, absent: evidence this verifier cannot
    // read, never a match on a checksum that passes one word in 256.
    const v = evaluateWatermark({ layout: 'video-rep-v1', decoded: '11074285' }, video)
    expect(v.result).toBe('not_evaluated')
    expect(v.detail).toContain('no agreement figure')
  })

  it('takes a detector\'s own refusal as the sentence, never as an outcome', () => {
    // The page's decoder applies the floor itself, so no unbelievable id ever
    // reaches a progress line: it reports no id and says why.
    const v = evaluateWatermark({ layout: 'video-rep-v1', decoded: null, agreement: 0.74, id_refused: true }, video)
    expect(v.result).toBe('not_recovered')
    expect(v.id_refused).toBe(true)
    // And with the hint absent the outcome is identical — it moves nothing.
    expect(evaluateWatermark({ layout: 'video-rep-v1', decoded: null, agreement: 0.74 }, video).result).toBe('not_recovered')
  })

  it('leaves `photo-bch-v3` alone: its block code has nothing for a floor to catch', async () => {
    const v = await run(seen(CAPTURE_ID))
    expect(v.labels).toContain('watermark matched')
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
    // Every one carries an agreement above the floor: without it no
    // `video-rep-v1` id is reportable at all, which is the test below.
    expect(evaluateWatermark({ decoded: '16777216', agreement: 0.98 }, video).result).toBe('not_evaluated')
    expect(evaluateWatermark({ decoded: '16777215', agreement: 0.98 }, video).result).toBe('contradicted')
    expect(evaluateWatermark({ decoded: '1', agreement: 0.98 }, video).result).toBe('matched')
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
  /**
   * The splice: one genuine marked frame in foreign footage reports the real
   * id at the agreement of a clean recovery, because an unmarked frame
   * abstains rather than dissents. `agreement` cannot tell the two apart —
   * the count can, and the sentence carries it so nobody has to go looking.
   */
  describe('how much of a clip carried the id', () => {
    const clip = { layout: 'video-rep-v1' as const, captureId: 'a'.repeat(32), markId: 5902388, mime: 'video/mp4', coreHash: 'b'.repeat(64) }
    const evidence = (framesWithId: number) => ({
      layout: 'video-rep-v1',
      decoded: '5902388',
      agreement: 0.996,
      frames_sampled: 8,
      frames_with_id: framesWithId,
      model_version: 'videoseal-y256b-3'
    })

    it('says how many frames carried it, in the sentence and not only in a field', () => {
      const spliced = evaluateWatermark(evidence(1), clip)
      const whole = evaluateWatermark(evidence(8), clip)

      expect(spliced.result).toBe('matched')
      expect(spliced.frames_with_id).toBe(1)
      expect(spliced.detail).toContain('1 of 8 sampled frames carry it')
      expect(whole.detail).toContain('8 of 8 sampled frames carry it')
      // The field this must never be mistaken for: identical in both.
      expect(spliced.agreement).toBe(whole.agreement)
    })

    it('says nothing about frames when the detector did not count them', () => {
      // The agreement stays: a count may be missing, the layout's own figure
      // may not, or there is no reportable id at all.
      const outcome = evaluateWatermark({ layout: 'video-rep-v1', decoded: '5902388', frames_sampled: 8, agreement: 0.99 }, clip)

      expect(outcome.result).toBe('matched')
      expect(outcome.frames_with_id).toBeUndefined()
      expect(outcome.detail).toBe('the payload carries the declared mark id')
    })

    /** "n of m" is one claim: a count larger than the frames it came from, or with no m beside it, is unreadable rather than weak. */
    it('drops a count with no denominator, or one larger than it', () => {
      const tooMany = evaluateWatermark({ ...evidence(9), frames_sampled: 8 }, clip)
      const { frames_sampled: _dropped, ...noDenominator } = evidence(1)
      const orphan = evaluateWatermark(noDenominator, clip)

      expect(tooMany.frames_with_id).toBeUndefined()
      expect(tooMany.detail).toBe('the payload carries the declared mark id')
      expect(orphan.frames_with_id).toBeUndefined()
    })

    it('drops a count that is not a number, like every other reported figure', () => {
      const outcome = evaluateWatermark({ ...evidence(1), frames_with_id: Number.NaN }, clip)

      expect(outcome.frames_with_id).toBeUndefined()
      expect(outcome.detail).toBe('the payload carries the declared mark id')
    })
  })

})
