import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { VIDEO_AGREEMENT_FLOOR, crc8, decodeClip, decodePhoto, decodeVideo } from '../src/layouts.js'
import { VIDEO_AGREEMENT_FLOOR as CORE_FLOOR } from 'vcap-verify-core'

/**
 * The layout port against the vectors that pin it. `test/layouts.json` is the
 * mirror of `vcap-ml/vectors/layouts.json`, which the exporter writes from the
 * normative Python: a port that decodes these reads the same bits as the
 * encoder that made the marks, and one that does not is a detector reporting
 * ids nobody embedded.
 *
 * The soft bits a detector produces are logits, so a vector's packed message
 * is read here as ±4 — the same substitution `layouts.py`'s own selftest uses.
 */
const vectors = JSON.parse(readFileSync(new URL('./layouts.json', import.meta.url), 'utf8')) as {
  message_bits: number
  'photo-bch-v3': { cases: Array<{ capture_id: string, message: string }> }
  'video-rep-v1': { cases: Array<{ mark_id: number, crc8: number, message: string }> }
}

/** Packed hex of the 256 message bits, MSB first, as logits. */
const logits = (message: string): Float32Array => {
  const soft = new Float32Array(vectors.message_bits)
  for (let i = 0; i < soft.length; i++) {
    const byte = parseInt(message.slice((i >> 3) * 2, (i >> 3) * 2 + 2), 16)
    soft[i] = ((byte >> (7 - (i % 8))) & 1) === 1 ? 4 : -4
  }
  return soft
}

/** Deterministic bit flips: which bits break is a property of the code, not of luck. */
const flip = (soft: Float32Array, count: number, step: number): Float32Array => {
  const out = soft.slice()
  for (let i = 0, at = 0; i < count; i++, at = (at + step) % out.length) out[at] = -out[at]!
  return out
}

describe('photo-bch-v3', () => {
  it('decodes every vector', () => {
    for (const { capture_id: id, message } of vectors['photo-bch-v3'].cases) {
      expect(decodePhoto(logits(message))).toEqual({ captureId: id, correctedBits: 0 })
    }
  })

  it('corrects up to the code radius', () => {
    const { capture_id: id, message } = vectors['photo-bch-v3'].cases[1]!
    for (let errors = 1; errors <= 18; errors++) {
      const decoded = decodePhoto(flip(logits(message), errors, 13))
      expect(decoded, `${errors} flipped bits`).toEqual({ captureId: id, correctedBits: errors })
    }
  })

  it('refuses past the radius instead of guessing an id', () => {
    const { message } = vectors['photo-bch-v3'].cases[1]!
    // 19 errors is one past t: the decoder may not place them, and a wrong id
    // would be worse than none — a verifier reads null as *not recovered*.
    for (let errors = 19; errors <= 40; errors++) {
      const decoded = decodePhoto(flip(logits(message), errors, 13))
      expect(decoded?.captureId, `${errors} flipped bits`).not.toBe(vectors['photo-bch-v3'].cases[1]!.capture_id)
    }
  })

  it('reads noise as nothing recovered', () => {
    let recovered = 0
    for (let seed = 1; seed <= 50; seed++) {
      const soft = new Float32Array(256)
      // A cheap deterministic generator: the point is unstructured input, not randomness.
      let state = seed
      for (let i = 0; i < soft.length; i++) {
        state = (state * 1103515245 + 12345) & 0x7fffffff
        soft[i] = (state % 2000) / 1000 - 1
      }
      if (decodePhoto(soft) !== null) recovered++
    }
    expect(recovered).toBe(0)
  })

  it('reads an all-zero payload as nothing, not as the zero id', () => {
    expect(decodePhoto(new Float32Array(256).fill(-4))).toBeNull()
  })
})

describe('video-rep-v1', () => {
  it('decodes every vector, unanimously', () => {
    for (const { mark_id: id, message } of vectors['video-rep-v1'].cases) {
      expect(decodeVideo(logits(message))).toEqual({ markId: id, agreement: 1, refused: false })
    }
  })

  it('matches the pinned crc8', () => {
    for (const { mark_id: id, crc8: expected } of vectors['video-rep-v1'].cases) {
      expect(crc8(id)).toBe(expected)
    }
  })

  it('survives errors up to the floor and reports how unanimous it was', () => {
    const { mark_id: id, message } = vectors['video-rep-v1'].cases[1]!
    const decoded = decodeVideo(flip(logits(message), 38, 7))
    expect(decoded.markId).toBe(id)
    expect(decoded.agreement).toBeLessThan(1)
    expect(decoded.agreement).toBeGreaterThanOrEqual(VIDEO_AGREEMENT_FLOOR)
  })

  /**
   * `watermark-layouts-1.0.md` *The agreement floor*. The layout refuses an id
   * the checksum accepted, because eight bits of CRC pass by chance one word
   * in 256 and on real recordings that happened twice in 38, at 0.738 and
   * 0.789, handing back an id the pixels had never carried.
   */
  it('refuses a mark id the crc accepted below the floor, and keeps the figure', () => {
    const { message } = vectors['video-rep-v1'].cases[1]!
    // Three more flipped positions than the test above — the same correct id
    // underneath, and the decoder now declines to report it. That is the cost
    // of the rule, and it is deliberate: at this agreement a correct id and a
    // wrong one are not distinguishable.
    const decoded = decodeVideo(flip(logits(message), 39, 7))
    expect(decoded.markId).toBeNull()
    expect(decoded.refused).toBe(true)
    expect(decoded.agreement).toBeLessThan(VIDEO_AGREEMENT_FLOOR)
  })

  it('keeps the floor equal to the one the core enforces', () => {
    // Two files hold the constant — the detector artifact stays free of the
    // core — and a verdict follows the core's. They may never differ.
    expect(CORE_FLOOR).toBe(VIDEO_AGREEMENT_FLOOR)
  })

  it('reports not recovered, with the agreement, when the crc rejects the vote', () => {
    const soft = new Float32Array(256)
    let state = 7
    for (let i = 0; i < soft.length; i++) {
      state = (state * 1103515245 + 12345) & 0x7fffffff
      soft[i] = (state % 2000) / 1000 - 1
    }
    const decoded = decodeVideo(soft)
    expect(decoded.markId).toBeNull()
    expect(decoded.agreement).toBeGreaterThan(0)
  })
})

/**
 * A clip, and the question a single decode cannot answer: how much of it
 * carried the mark.
 *
 * The id still comes from the frames averaged together, because that is what
 * recovers a mark no single frame carries cleanly. The count comes from
 * decoding them one by one, because an unmarked frame **abstains** rather than
 * dissenting — measured at mean absolute logit 0.131 against 11.3 for a marked
 * one — so the average is set by any single marked frame and a spliced frame
 * reports the real id at the agreement of a clean recovery
 * (`vcap-spec/spec/watermark-robustness-1.0.md`).
 */
describe('video-rep-v1, over the frames of a clip', () => {
  const marked = (index = 1): Float32Array => logits(vectors['video-rep-v1'].cases[index]!.message)
  const markIdOf = (index = 1): number => vectors['video-rep-v1'].cases[index]!.mark_id

  /** An unmarked frame: the detector's near-zero logits, not noise with an opinion. */
  const abstaining = (seed: number): Float32Array => {
    const soft = new Float32Array(vectors.message_bits)
    let state = seed
    for (let i = 0; i < soft.length; i++) {
      state = (state * 1103515245 + 12345) & 0x7fffffff
      soft[i] = ((state % 2000) / 1000 - 1) * 0.131
    }
    return soft
  }

  /** `count` consecutive positions flipped from `start`, so each frame errs somewhere else. */
  const flipRun = (soft: Float32Array, start: number, count: number): Float32Array => {
    const out = soft.slice()
    for (let i = 0; i < count; i++) {
      const at = (start + i) % out.length
      out[at] = -out[at]!
    }
    return out
  }

  it('counts every frame of a wholly marked clip', () => {
    const clip = decodeClip(Array.from({ length: 8 }, () => marked()))
    expect(clip.markId).toBe(markIdOf())
    expect(clip.framesWithId).toBe(8)
  })

  /**
   * The defence this count exists for. Both clips below report the same id at
   * the same agreement, and before the count a verifier could not tell them
   * apart — which is exactly the splice `threat-model.md` §5.8 describes: one
   * genuine frame in foreign footage, no model needed.
   */
  it('tells one spliced frame from a wholly marked clip', () => {
    const spliced = decodeClip([marked(), ...Array.from({ length: 7 }, (_, i) => abstaining(i + 1))])
    const whole = decodeClip(Array.from({ length: 8 }, () => marked()))

    // Indistinguishable on everything a verifier had before this.
    expect(spliced.markId).toBe(whole.markId)
    expect(spliced.agreement).toBeGreaterThanOrEqual(VIDEO_AGREEMENT_FLOOR)
    expect(spliced.agreement).toBe(whole.agreement)
    // And distinguishable now.
    expect(spliced.framesWithId).toBe(1)
    expect(whole.framesWithId).toBe(8)
  })

  /**
   * Why the id is not taken frame by frame. On the int8 build the browser
   * ships, the hardest chain that survives at all reads 39 flipped bits from
   * one frame — agreement 0.848, under the floor — and 35 from eight
   * (`vcap-ml/reports/frames-to-recover.md`). A page that required a frame to
   * pass on its own would refuse that clip; averaging still recovers it, and
   * the count honestly says no frame resolved alone.
   */
  it('still recovers a clip no single frame could report, and says so with a zero', () => {
    const frames = Array.from({ length: 8 }, (_, i) => flipRun(marked(), i * 32, 39))
    for (const frame of frames) {
      const alone = decodeVideo(frame)
      expect(alone.markId).toBeNull()
      expect(alone.agreement).toBeLessThan(VIDEO_AGREEMENT_FLOOR)
    }
    const clip = decodeClip(frames)
    expect(clip.markId).toBe(markIdOf())
    expect(clip.agreement).toBeGreaterThanOrEqual(VIDEO_AGREEMENT_FLOOR)
    expect(clip.framesWithId).toBe(0)
  })

  /** No id to count against is not a count of zero: nothing was reported to carry. */
  it('reports no count at all when the clip yields no id', () => {
    const clip = decodeClip(Array.from({ length: 8 }, (_, i) => abstaining(i + 1)))
    expect(clip.markId).toBeNull()
    expect(clip.framesWithId).toBeNull()
  })

  /**
   * Per-frame decoding may never become a second answer. Frames are counted
   * against the id the aggregate was allowed to report, so a frame carrying a
   * different one is not counted and its id is never named.
   */
  it('counts only the id the clip itself reported', () => {
    const clip = decodeClip([marked(0), ...Array.from({ length: 7 }, () => marked(1))])
    expect(clip.markId).toBe(markIdOf(1))
    expect(clip.framesWithId).toBe(7)
  })
})
