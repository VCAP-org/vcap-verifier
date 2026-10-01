import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { recomputeSegments } from '../src/container.js'
import { parseTrailer } from '../src/trailer.js'
import { verify } from '../src/verify.js'
import { fromBase64, toBase64url } from '../src/bytes.js'
import { resealed } from './reseal.js'

/**
 * Three files sealed by real hardware (see fixtures/NOTES.md). The acceptance
 * test of §5 recomputation is not "the parser runs": it is that the hashes
 * read back from the container are the hashes a device signed — on a file with
 * an empty edit list and interleaved audio, on one without audio, and on one
 * whose slices carry the zero padding an encoder adds to a cheap scene, where
 * how far a NAL unit reaches stops being a question with one obvious answer.
 */
interface Sealed { capture_id: string, segment_count: number, segments: { gop: number, hash: string }[] }

// The device's container under a re-signed core that carries
// `media.presentation` (`reseal.ts`): the device proofs predate it, and
// without it `verify` stops at *no proof found* before reading a GOP.
const FIXTURES = Object.fromEntries(await Promise.all(['sealed', 'sealed-hevc', 'sealed-padded'].map(async (name) =>
  [name, await resealed(new Uint8Array(readFileSync(new URL(`./fixtures/${name}.mp4`, import.meta.url))))] as const)))

const load = (name: string) => {
  const { file, media } = FIXTURES[name]!
  const sealed: Sealed = JSON.parse(readFileSync(new URL(`./fixtures/${name}-segments.json`, import.meta.url), 'utf8'))
  return { file, media, sealed }
}

describe('§5 recomputation from the container', () => {
  for (const name of ['sealed', 'sealed-hevc', 'sealed-padded']) {
    it(`${name}: every segment hashes to what the device signed`, async () => {
      const { media, sealed } = load(name)
      const r = await recomputeSegments(media, fromBase64(sealed.capture_id))
      if (r.kind !== 'hashes') throw new Error(r.reason)
      expect(r.gops.map((g) => [g.index, toBase64url(g.hash)])).toEqual(sealed.segments.map((s) => [s.gop, s.hash]))
    })

    it(`${name}: verifies authentic with the container read back`, async () => {
      const { file } = load(name)
      const v = await verify(file)
      expect(v.outcome).toBe('authentic')
      expect(v.content).toEqual({ recomputed: true, detail: '3 GOPs read from the container' })
      expect(v.segments).toEqual({ verified: [0, 1, 2] })
    })
  }

  it('reports tampered on a flipped bit inside segment 1, and says which segments verify', async () => {
    const { file, media, sealed } = load('sealed')
    const r = await recomputeSegments(media, fromBase64(sealed.capture_id))
    if (r.kind !== 'hashes') throw new Error(r.reason)
    // Deep inside the mdat, past the first GOP: the middle of the file's video
    // payload lands in segment 1 on a three-second capture.
    const edited = Uint8Array.from(file)
    const at = Math.floor(media.length / 2)
    edited[at] = (edited[at] as number) ^ 1
    const v = await verify(edited)
    expect(v.outcome).toBe('tampered')
    expect(v.segments).toEqual({ verified: [0, 2], contradicted: [1] })
    expect(v.reason).toBe('segment 1: content differs from the container')
  })

  it('gives no segment credit when recomputation is switched off and the file is not the sealed bytes', async () => {
    const { file } = load('sealed')
    const edited = Uint8Array.from(file)
    const at = Math.floor(file.length / 2)
    edited[at] = (edited[at] as number) ^ 1
    // Same bytes, message-level only: the proof's own hashes still agree with
    // themselves, which is exactly the check that is not verification — so it
    // earns no segment and never reads *verified clip*.
    const v = await verify(edited, { recomputeSegments: false })
    expect(v.outcome).toBe('frames_not_compared')
    expect(v.content).toEqual({ recomputed: false, detail: 'recomputation not requested' })
    expect(v.segments).toEqual({ verified: [] })
    expect(v.labels).toContain('segment content not recomputed')
  })
})

/**
 * A caller that hashed the canonical bytes itself — a phone, natively — hands
 * over the digest and only the trailer. The answer must be the one the whole
 * file gives, and a wrong digest must not be believed.
 */
describe('§5 edit lists beyond a delay and one media edit', () => {
  // The video track of `sealed` carries MediaMuxer's edit list: one empty edit
  // (the delay), then one media edit. Each variant rewrites it in place, so
  // every sample, SEI and segment hash is untouched and only the timeline a
  // player presents changes.
  const { file, sealed } = load('sealed')
  const elst = (b: Uint8Array): number => {
    for (let i = 4; i + 4 <= b.length; i++) if (b[i] === 0x65 && b[i + 1] === 0x6c && b[i + 2] === 0x73 && b[i + 3] === 0x74) return i + 4
    throw new Error('no elst')
  }
  const variant = (edit: (view: DataView, first: number) => void): Uint8Array => {
    const out = Uint8Array.from(file)
    const body = elst(out)
    const view = new DataView(out.buffer)
    if (out[body] !== 0 || view.getUint32(body + 4) !== 2) throw new Error('fixture edit list changed shape')
    edit(view, body + 8)
    return out
  }
  const cases: [string, Uint8Array, string][] = [
    // Both edits present media: the second repeats the track from its start.
    ['a second media edit', variant((v, e) => v.setInt32(e + 4, 0)), 'edit list has more than one edit after the leading delay'],
    // The media edit first, then the gap: a pause after the media.
    ['an empty edit after the media edit', variant((v, e) => {
      const empty = [v.getUint32(e), v.getInt32(e + 4), v.getUint32(e + 8)]
      for (let i = 0; i < 3; i++) v.setUint32(e + 4 * i, v.getUint32(e + 12 + 4 * i))
      v.setUint32(e + 12, empty[0]!); v.setInt32(e + 16, empty[1]!); v.setUint32(e + 20, empty[2]!)
    }), 'edit list has more than one edit after the leading delay'],
    ['a media edit at rate 2', variant((v, e) => v.setInt16(e + 12 + 8, 2)), 'edit list changes rate']
  ]
  for (const [what, edited, reason] of cases) {
    it(`refuses ${what}, and credits no segment`, async () => {
      const media = parseTrailer(edited)
      if (media.kind !== 'ok') throw new Error('no trailer')
      expect(await recomputeSegments(media.media, fromBase64(sealed.capture_id))).toEqual({ kind: 'unsupported', reason })
      // The edit is inside the canonical bytes, so this is not the original,
      // and nothing located over it may read *verified clip*.
      const v = await verify(edited)
      expect(v.outcome).toBe('frames_not_compared')
      expect(v.content).toEqual({ recomputed: false, detail: reason })
      expect(v.segments).toEqual({ verified: [] })
      expect(v.labels).toContain('segment content not recomputed')
    })
  }
})

describe('a media hash computed by the caller', () => {
  it('gives the whole file’s verdict from the trailer alone', async () => {
    const { file, media } = load('sealed')
    const trailerOnly = file.subarray(media.length)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(media)))
    const whole = await verify(file, { recomputeSegments: false })
    const alone = await verify(trailerOnly, { recomputeSegments: false, mediaHash: digest })
    expect(alone.outcome).toBe(whole.outcome)
    expect(alone.core_hash).toBe(whole.core_hash)
    expect(alone.labels).toEqual(whole.labels)
  })

  it('is not believed when it is the wrong one', async () => {
    const { file, media } = load('sealed')
    const alone = await verify(file.subarray(media.length), { recomputeSegments: false, mediaHash: new Uint8Array(32) })
    // A wrong digest and no frames to compare: the signatures hold and
    // nothing ties any frame to them.
    expect(alone.outcome).toBe('frames_not_compared')
    expect(alone.segments).toEqual({ verified: [] })
  })
})
