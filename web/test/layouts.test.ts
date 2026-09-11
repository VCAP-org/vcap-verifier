import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { crc8, decodePhoto, decodeVideo } from '../src/layouts.js'

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
      expect(decodeVideo(logits(message))).toEqual({ markId: id, agreement: 1 })
    }
  })

  it('matches the pinned crc8', () => {
    for (const { mark_id: id, crc8: expected } of vectors['video-rep-v1'].cases) {
      expect(crc8(id)).toBe(expected)
    }
  })

  it('survives a fifth of the bits and reports how unanimous it was', () => {
    const { mark_id: id, message } = vectors['video-rep-v1'].cases[1]!
    const decoded = decodeVideo(flip(logits(message), 51, 7))
    expect(decoded.markId).toBe(id)
    expect(decoded.agreement).toBeLessThan(1)
    expect(decoded.agreement).toBeGreaterThan(0.7)
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
