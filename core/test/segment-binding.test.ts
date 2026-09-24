import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { concat, u32be, utf8 } from '../src/bytes.js'
import { parseTrailer } from '../src/trailer.js'
import { verify } from '../src/verify.js'

/**
 * §5's binding between the segments a proof signs and the GOPs a file holds.
 *
 * A signed segment `n` counts as verified only if the container yields
 * exactly one GOP whose vcap SEI carries `n` and this proof's `capture_id`,
 * and that GOP's bytes hash to the signed `content_hash`. The SEI is unsigned:
 * it locates and never proves — which is why every case below edits it, moves
 * GOPs around it, or takes it away, on files a real device sealed.
 */
const fixture = (name: string) => {
  const file = new Uint8Array(readFileSync(new URL(`./fixtures/${name}.mp4`, import.meta.url)))
  const trailer = parseTrailer(file)
  if (trailer.kind !== 'ok') throw new Error(`${name}: no trailer`)
  return { file, media: trailer.media, payload: trailer.payload }
}

const UUID = [0xca, 0xa6, 0x53, 0xd1, 0xed, 0x17, 0x63, 0xc7, 0xaf, 0x38, 0x8a, 0xea, 0x76, 0x52, 0x73, 0x36]

/** Where each vcap SEI's UUID starts, in file order (one per GOP on these files). */
const seiOffsets = (b: Uint8Array): number[] => {
  const out: number[] = []
  for (let i = 0; i + UUID.length <= b.length; i++) if (UUID.every((x, j) => b[i + j] === x)) out.push(i)
  return out
}

describe('the vcap SEI edited in place (sealed.mp4, H.264 + AAC)', () => {
  // The SEI NAL is `06 05 24 <uuid 16> <capture_id 16> 00 00 03 00 0n 80`: the
  // index is emulation-escaped, so its low byte sits 36 bytes after the UUID.
  const { file } = fixture('sealed')
  const at = seiOffsets(file)
  const edit = (change: (b: Uint8Array) => void): Uint8Array => { const b = Uint8Array.from(file); change(b); return b }

  it('finds one SEI per GOP, and the file verifies untouched', async () => {
    expect(at).toHaveLength(3)
    expect((await verify(file)).outcome).toBe('authentic')
  })

  it('an index outside the signed range is tampered', async () => {
    const v = await verify(edit((b) => { b[at[1]! + 36] = 5 }))
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toBe('the container contradicts the proof: a GOP names segment 5, outside the 3 the proof signs')
  })

  it('an index 257 written over segment 1 is tampered, not a clip', async () => {
    // The review's reproduction: this used to read *verified clip* {0, 1, 2}.
    const v = await verify(edit((b) => { b[at[1]! + 35] = 1 }))
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toBe('the container contradicts the proof: a GOP names segment 257, outside the 3 the proof signs')
  })

  it('two GOPs naming one index is tampered', async () => {
    const v = await verify(edit((b) => { b[at[1]! + 36] = 2 }))
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toBe('the container contradicts the proof: two GOPs carry segment index 2')
  })

  it('indices out of file order are tampered', async () => {
    const v = await verify(edit((b) => { b[at[2]! + 36] = 0 }))
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toBe('the container contradicts the proof: segment index 0 follows 1 in the file')
  })

  it('an SEI of another capture locates nothing, and its GOP earns no credit', async () => {
    const v = await verify(edit((b) => { b[at[1]! + 16] = b[at[1]! + 16]! ^ 1 }))
    expect(v.outcome).toBe('verified_clip')
    expect(v.segments).toEqual({ verified: [0, 2] })
    expect(v.content?.detail).toBe('2 GOPs read from the container; 1 not located by a vcap SEI and not compared')
  })

  it('a vcap SEI sized other than 36 is tampered', async () => {
    const v = await verify(edit((b) => { b[at[1]! - 1] = 0x25 }))
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toBe('the container contradicts the proof: vcap SEI malformed: payloadSize 37, not 36')
  })

  it('a NAL length that overruns its sample is tampered, not skipped', async () => {
    // The SEI's four-byte length prefix sits right before `06 05 24`.
    const v = await verify(edit((b) => { b[at[1]! - 7] = 0x7f }))
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toMatch(/^the container contradicts the proof: NAL length \d+ does not fit its sample$/)
  })
})

describe('a stolen proof', () => {
  const { payload } = fixture('sealed')

  it('beside another device recording is not a clip: its SEIs name another capture', async () => {
    const other = fixture('sealed-hevc').media
    const v = await verify(other, { sidecar: payload })
    expect(v.outcome).toBe('frames_not_compared')
    expect(v.segments).toEqual({ verified: [] })
    expect(v.content).toEqual({ recomputed: false, detail: 'no vcap SEI locates a segment' })
  })

  it('beside bytes that are not a container at all', async () => {
    const v = await verify(new Uint8Array(4096).fill(7), { sidecar: payload })
    expect(v.outcome).toBe('frames_not_compared')
    expect(v.content).toEqual({ recomputed: false, detail: 'not an ISO-BMFF container' })
  })
})

/**
 * GOPs cut, copied and reordered, which takes a new sample table: a small
 * muxer over the samples of `sealed-hevc.mp4` (HEVC, no audio, so a GOP's
 * content hash is its video NALs alone). The first case rebuilds the file
 * unchanged, which is what makes the others mean anything — the rebuilt
 * container reads back every segment the device signed.
 */
describe('GOPs moved in a rebuilt container (sealed-hevc.mp4)', () => {
  const { media, payload } = fixture('sealed-hevc')
  const read = (at: number): number => ((media[at]! << 24) >>> 0) + (media[at + 1]! << 16) + (media[at + 2]! << 8) + media[at + 3]!
  const type = (at: number): string => String.fromCharCode(...media.subarray(at + 4, at + 8))
  // Size 1 is a 64-bit largesize, which the recorder writes for `mdat`.
  const sizeAt = (at: number): number => read(at) === 1 ? read(at + 8) * 2 ** 32 + read(at + 12) : read(at)
  const kids = (from: number, to: number): Record<string, [number, number]> => {
    const out: Record<string, [number, number]> = {}
    for (let at = from; at + 8 <= to; at += sizeAt(at)) out[type(at)] ??= [at, at + sizeAt(at)]
    return out
  }
  const inside = (box: [number, number], ...path: string[]): [number, number] =>
    path.reduce((b, name) => kids(b[0] + 8, b[1])[name]!, box)
  const moov = kids(0, media.length).moov!
  const stbl = inside(moov, 'trak', 'mdia', 'minf', 'stbl')
  const table = kids(stbl[0] + 8, stbl[1])
  const mdhd = inside(moov, 'trak', 'mdia', 'mdhd')
  const timescale = read(mdhd[0] + 8 + 12)

  // One sample per chunk or not, the offsets are what stsc, stco and stsz say.
  const sizes = Array.from({ length: read(table.stsz![0] + 16) }, (_, i) => read(table.stsz![0] + 20 + i * 4))
  // The recorder writes 64-bit chunk offsets (co64) on this file; stco otherwise.
  const offsets = table.co64 ?? table.stco!
  const wide = table.co64 !== undefined
  const chunks = Array.from({ length: read(offsets[0] + 12) }, (_, i) => wide ? read(offsets[0] + 16 + i * 8) * 2 ** 32 + read(offsets[0] + 20 + i * 8) : read(offsets[0] + 16 + i * 4))
  const runs = Array.from({ length: read(table.stsc![0] + 12) }, (_, i) => ({ first: read(table.stsc![0] + 16 + i * 12), per: read(table.stsc![0] + 20 + i * 12) }))
  const samples: Uint8Array[] = []
  for (let chunk = 1, s = 0; chunk <= chunks.length; chunk++) {
    const per = runs.filter((r) => r.first <= chunk).at(-1)!.per
    let offset = chunks[chunk - 1]!
    for (let i = 0; i < per && s < sizes.length; i++, s++) { samples.push(media.subarray(offset, offset + sizes[s]!)); offset += sizes[s]! }
  }
  const nals = (sample: Uint8Array): Uint8Array[] => {
    const out: Uint8Array[] = []
    for (let at = 0; at < sample.length;) { const n = ((sample[at]! << 24) >>> 0) + (sample[at + 1]! << 16) + (sample[at + 2]! << 8) + sample[at + 3]!; out.push(sample.subarray(at + 4, at + 4 + n)); at += 4 + n }
    return out
  }
  const idr = (sample: Uint8Array): boolean => nals(sample).some((n) => [19, 20].includes((n[0]! >> 1) & 0x3f))
  const gops: Uint8Array[][] = []
  for (const sample of samples) { if (idr(sample)) gops.push([]); gops.at(-1)!.push(sample) }

  const box = (name: string, ...parts: Uint8Array[]): Uint8Array => concat(u32be(8 + parts.reduce((n, p) => n + p.length, 0)), utf8(name), ...parts)
  const full = (name: string, ...parts: Uint8Array[]): Uint8Array => box(name, new Uint8Array(4), ...parts)
  const mux = (frames: Uint8Array[]): Uint8Array => {
    const data = concat(...frames)
    const moovOf = (offset: number): Uint8Array => box('moov',
      full('mvhd', new Uint8Array(8), u32be(timescale), new Uint8Array(84)),
      box('trak', box('mdia',
        full('mdhd', new Uint8Array(8), u32be(timescale), new Uint8Array(8)),
        full('hdlr', new Uint8Array(4), utf8('vide'), new Uint8Array(13)),
        box('minf', box('stbl',
          media.subarray(table.stsd![0], table.stsd![1]),
          full('stts', u32be(1), u32be(frames.length), u32be(timescale / 30)),
          full('stsc', u32be(1), u32be(1), u32be(frames.length), u32be(1)),
          full('stsz', u32be(0), u32be(frames.length), ...frames.map((f) => u32be(f.length))),
          full('stco', u32be(1), u32be(offset))
        ))
      )))
    const ftyp = box('ftyp', utf8('isom'), u32be(512), utf8('isom'))
    const offset = ftyp.length + moovOf(0).length + 8
    return concat(ftyp, moovOf(offset), box('mdat', data))
  }
  const check = (order: Uint8Array[][]) => verify(mux(order.flat()), { sidecar: payload })
  const [g0, g1, g2] = gops as [Uint8Array[], Uint8Array[], Uint8Array[]]

  it('rebuilt unchanged, every segment reads back: a clip of the whole recording', async () => {
    expect(gops).toHaveLength(3)
    const v = await check([g0, g1, g2])
    // New container bytes, so media.hash differs; every GOP is the signed one.
    expect(v.outcome).toBe('verified_clip')
    expect(v.segments).toEqual({ verified: [0, 1, 2] })
  })

  it('a GOP removed from the middle leaves a clip of the other two', async () => {
    const v = await check([g0, g2])
    expect(v.outcome).toBe('verified_clip')
    expect(v.segments).toEqual({ verified: [0, 2] })
  })

  it('a GOP duplicated is tampered', async () => {
    const v = await check([g0, g1, g1, g2])
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toBe('the container contradicts the proof: two GOPs carry segment index 1')
  })

  it('GOPs reordered are tampered', async () => {
    const v = await check([g0, g2, g1])
    expect(v.outcome).toBe('tampered')
    expect(v.reason).toBe('the container contradicts the proof: segment index 1 follows 2 in the file')
  })

  it('a GOP whose SEI was stripped is never placed by its position', async () => {
    // HEVC: two header bytes, payloadType, payloadSize, then the UUID.
    const vcap = (n: Uint8Array): boolean => UUID.every((x, j) => n[j + 4] === x)
    const stripped = g1.map((sample) => concat(...nals(sample).filter((n) => !vcap(n)).map((n) => concat(u32be(n.length), n))))
    const v = await check([g0, stripped, g2])
    // Its bytes are the signed bytes (the SEI is outside content_hash), and
    // still it earns nothing: position is the index only in a file nobody cut.
    expect(v.outcome).toBe('verified_clip')
    expect(v.segments).toEqual({ verified: [0, 2] })
    expect(v.content?.detail).toBe('2 GOPs read from the container; 1 not located by a vcap SEI and not compared')
  })
})
