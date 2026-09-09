import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { recomputeSegments } from '../src/container.js'
import { parseTrailer } from '../src/trailer.js'
import { verify } from '../src/verify.js'
import { fromBase64, toBase64url } from '../src/bytes.js'

/**
 * Two files sealed by real hardware (see fixtures/NOTES.md). The acceptance
 * test of §5 recomputation is not "the parser runs": it is that the hashes
 * read back from the container are the hashes a StrongBox device signed, on a
 * file with an empty edit list and interleaved audio and on one without audio.
 */
interface Sealed { capture_id: string, segment_count: number, segments: { gop: number, hash: string }[] }

const load = (name: string) => {
  const file = new Uint8Array(readFileSync(new URL(`./fixtures/${name}.mp4`, import.meta.url)))
  const trailer = parseTrailer(file)
  if (trailer.kind !== 'ok') throw new Error(`${name}: no trailer`)
  const sealed: Sealed = JSON.parse(readFileSync(new URL(`./fixtures/${name}-segments.json`, import.meta.url), 'utf8'))
  return { file, media: trailer.media, sealed }
}

describe('§5 recomputation from the container', () => {
  for (const name of ['sealed', 'sealed-hevc']) {
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

  it('verifies the signature layer alone when recomputation is switched off', async () => {
    const { file } = load('sealed')
    const edited = Uint8Array.from(file)
    const at = Math.floor(file.length / 2)
    edited[at] = (edited[at] as number) ^ 1
    // Same bytes, message-level only: the proof's own hashes still agree with
    // themselves, which is exactly the check that is not verification.
    const v = await verify(edited, { recomputeSegments: false })
    expect(v.outcome).toBe('verified_clip')
    expect(v.content).toEqual({ recomputed: false, detail: 'recomputation not requested' })
    expect(v.segments).toEqual({ verified: [0, 1, 2] })
  })
})
