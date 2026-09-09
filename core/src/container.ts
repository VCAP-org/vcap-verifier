import { type Bytes, concat, equal, fromHex, readU32BE } from './bytes.js'
import { sha256 } from './sha.js'

/**
 * Spec §5, recomputation side: read the GOPs of an ISO-BMFF file and hash the
 * bytes they are made of, so a verdict rests on the frames in front of the
 * reader rather than on the hashes the proof carries about itself.
 *
 * Progressive files only: sample tables in `moov`/`stbl`. A fragmented file
 * (`moof`) or a rate-changing edit list is reported unsupported rather than
 * guessed at — a wrong hash and an unread file must not look alike.
 */

// SHA-256("vcap/1.0/sei")[0:16]. The exclusion is by payload UUID, never by NAL
// type: every other SEI is content, and dropping SEIs wholesale would leave
// unsigned bytes inside a "verified" segment.
const VCAP_SEI_UUID = fromHex('caa653d1ed1763c7af388aea76527336')

export interface GopHash { index: number, hash: Bytes }

export type Recomputation =
  | { kind: 'hashes', gops: GopHash[] }
  | { kind: 'unsupported', reason: string }

interface Box { type: string, body: number, end: number }

const TYPE = (b: Bytes, at: number): string => String.fromCharCode(b[at]!, b[at + 1]!, b[at + 2]!, b[at + 3]!)

const boxes = (b: Bytes, from: number, to: number): Box[] => {
  const out: Box[] = []
  let at = from
  while (at + 8 <= to) {
    let size = readU32BE(b, at)
    let body = at + 8
    if (size === 1) {
      // 64-bit largesize; a real box never exceeds 2^53 so Number is exact enough.
      const view = new DataView(b.buffer, b.byteOffset + at + 8, 8)
      size = Number(view.getBigUint64(0))
      body = at + 16
    } else if (size === 0) size = to - at
    if (size < body - at || at + size > to) throw new Error(`box ${TYPE(b, at + 4)}: size out of range`)
    out.push({ type: TYPE(b, at + 4), body, end: at + size })
    at += size
  }
  return out
}

const find = (list: Box[], type: string): Box | undefined => list.find((x) => x.type === type)

const child = (b: Bytes, box: Box, ...path: string[]): Box | undefined => {
  let current: Box | undefined = box
  for (const type of path) {
    if (!current) return undefined
    current = find(boxes(b, current.body, current.end), type)
  }
  return current
}

interface Sample { offset: number, size: number, dts: number }

interface Track {
  handler: string
  timescale: number
  samples: Sample[]
  sync: number[]
  codec: 'h264' | 'h265' | null
  nalLength: number
  // Presentation offset (§5): empty edits delay the track (movie ticks, hence
  // `movieTimescale`), and the first real edit says which media time the
  // track's samples start at.
  delay: number
  movieTimescale: number
  mediaStart: number
}

// Every table below is a FullBox: 1 byte version, 3 bytes flags before the payload.
const entries = (b: Bytes, box: Box, stride: number, read: (at: number) => void): void => {
  const count = readU32BE(b, box.body + 4)
  for (let i = 0; i < count; i++) {
    const at = box.body + 8 + i * stride
    if (at + stride > box.end) throw new Error('table truncated')
    read(at)
  }
}

const sampleTable = (b: Bytes, stbl: Box): { samples: Sample[], sync: number[] } => {
  const get = (type: string): Box => {
    const box = find(boxes(b, stbl.body, stbl.end), type)
    if (!box) throw new Error(`stbl without ${type}`)
    return box
  }

  const sizes: number[] = []
  const stsz = find(boxes(b, stbl.body, stbl.end), 'stsz')
  if (stsz) {
    const uniform = readU32BE(b, stsz.body + 4)
    const count = readU32BE(b, stsz.body + 8)
    for (let i = 0; i < count; i++) sizes.push(uniform !== 0 ? uniform : readU32BE(b, stsz.body + 12 + i * 4))
  } else {
    // stz2 packs sizes in 4, 8 or 16 bits; unseen on the writers we handle.
    throw new Error('stbl without stsz')
  }

  const deltas: number[] = []
  entries(b, get('stts'), 8, (at) => {
    const count = readU32BE(b, at)
    const delta = readU32BE(b, at + 4)
    for (let i = 0; i < count; i++) deltas.push(delta)
  })

  const chunkOffsets: number[] = []
  const stco = find(boxes(b, stbl.body, stbl.end), 'stco')
  const co64 = find(boxes(b, stbl.body, stbl.end), 'co64')
  if (stco) entries(b, stco, 4, (at) => chunkOffsets.push(readU32BE(b, at)))
  else if (co64) entries(b, co64, 8, (at) => chunkOffsets.push(Number(new DataView(b.buffer, b.byteOffset + at, 8).getBigUint64(0))))
  else throw new Error('stbl without stco or co64')

  // stsc is run-length over chunks: expand it to samples-per-chunk.
  const runs: { firstChunk: number, perChunk: number }[] = []
  entries(b, get('stsc'), 12, (at) => runs.push({ firstChunk: readU32BE(b, at), perChunk: readU32BE(b, at + 4) }))

  const samples: Sample[] = []
  let sample = 0
  let dts = 0
  for (let chunk = 1; chunk <= chunkOffsets.length && sample < sizes.length; chunk++) {
    const run = runs.filter((r) => r.firstChunk <= chunk).at(-1)
    if (!run) throw new Error('stsc does not cover chunk 1')
    let offset = chunkOffsets[chunk - 1]!
    for (let i = 0; i < run.perChunk && sample < sizes.length; i++, sample++) {
      const size = sizes[sample]!
      samples.push({ offset, size, dts })
      offset += size
      dts += deltas[sample] ?? deltas.at(-1) ?? 0
    }
  }
  if (samples.length !== sizes.length) throw new Error('chunk offsets do not cover every sample')

  const sync: number[] = []
  const stss = find(boxes(b, stbl.body, stbl.end), 'stss')
  // No stss means every sample is a sync sample (audio, or all-intra video).
  if (stss) entries(b, stss, 4, (at) => sync.push(readU32BE(b, at) - 1))
  else for (let i = 0; i < samples.length; i++) sync.push(i)

  return { samples, sync }
}

const editList = (b: Bytes, elst: Box): { delay: number, mediaStart: number } => {
  const version = b[elst.body]!
  const stride = version === 1 ? 20 : 12
  let delay = 0
  let mediaStart: number | null = null
  entries(b, elst, stride, (at) => {
    const view = new DataView(b.buffer, b.byteOffset + at, stride)
    const duration = version === 1 ? Number(view.getBigUint64(0)) : view.getUint32(0)
    const mediaTime = version === 1 ? Number(view.getBigInt64(8)) : view.getInt32(4)
    const rate = view.getInt16(stride - 4)
    if (mediaTime < 0) {
      // Empty edit: no media, only a delay. MediaMuxer writes one (~473 ms) on
      // the video track whenever the microphone opened before the camera, and
      // ignoring it drags pre-IDR audio into segment 0.
      delay += duration
      return
    }
    if (rate !== 1) throw new Error('edit list changes rate')
    if (mediaStart === null) mediaStart = mediaTime
  })
  return { delay, mediaStart: mediaStart ?? 0 }
}

const parseTrack = (b: Bytes, trak: Box, movieTimescale: number): Track => {
  const mdia = child(b, trak, 'mdia')
  if (!mdia) throw new Error('trak without mdia')
  const mdhd = child(b, mdia, 'mdhd')
  const hdlr = child(b, mdia, 'hdlr')
  const stbl = child(b, mdia, 'minf', 'stbl')
  if (!mdhd || !hdlr || !stbl) throw new Error('trak without mdhd, hdlr or stbl')
  const timescale = b[mdhd.body] === 1 ? readU32BE(b, mdhd.body + 20) : readU32BE(b, mdhd.body + 12)
  const handler = TYPE(b, hdlr.body + 8)
  const { samples, sync } = sampleTable(b, stbl)

  let codec: Track['codec'] = null
  let nalLength = 4
  const stsd = find(boxes(b, stbl.body, stbl.end), 'stsd')
  if (stsd) {
    // Sample entries start after version/flags and the entry count; a
    // VisualSampleEntry body is 78 bytes before its child boxes.
    for (const entry of boxes(b, stsd.body + 8, stsd.end)) {
      if (entry.type === 'avc1' || entry.type === 'avc3') codec = 'h264'
      else if (entry.type === 'hvc1' || entry.type === 'hev1') codec = 'h265'
      else continue
      const config = find(boxes(b, entry.body + 78, entry.end), codec === 'h264' ? 'avcC' : 'hvcC')
      // lengthSizeMinusOne: avcC byte 4, hvcC byte 21 — both in the low 2 bits.
      if (config) nalLength = (b[config.body + (codec === 'h264' ? 4 : 21)]! & 3) + 1
      break
    }
  }

  const elst = child(b, trak, 'edts', 'elst')
  const edit = elst ? editList(b, elst) : { delay: 0, mediaStart: 0 }
  return { handler, timescale, movieTimescale, samples, sync, codec, nalLength, ...edit }
}

// Presentation time as an exact fraction: two tracks rarely share a timescale,
// the delay is counted in a third one, and rounding at a segment boundary would
// move an audio frame from one segment to the next — a wrong hash for both.
interface Time { num: bigint, den: bigint }
const presentation = (t: Track, dts: number): Time => ({
  num: BigInt(t.delay) * BigInt(t.timescale) + BigInt(dts - t.mediaStart) * BigInt(t.movieTimescale),
  den: BigInt(t.timescale) * BigInt(t.movieTimescale)
})
const before = (a: Time, b: Time): boolean => a.num * b.den < b.num * a.den

// RBSP: 0x000003 escapes a zero run inside a NAL. Parsing an SEI needs the
// unescaped bytes, while the hash covers the NAL exactly as the sample holds it.
const unescape = (nal: Bytes): Bytes => {
  const out = new Uint8Array(nal.length)
  let n = 0
  for (let i = 0; i < nal.length; i++) {
    if (i >= 2 && nal[i] === 3 && nal[i - 1] === 0 && nal[i - 2] === 0) continue
    out[n++] = nal[i]!
  }
  return out.subarray(0, n)
}

/** The 20-byte vcap SEI payload (`capture_id || uint32 BE n`), or null. */
const vcapSeiPayload = (nal: Bytes, codec: Track['codec']): Bytes | null => {
  if (nal.length < 2) return null
  const isSei = codec === 'h265'
    ? [39, 40].includes((nal[0]! >> 1) & 0x3f)
    : (nal[0]! & 0x1f) === 6
  if (!isSei) return null
  const rbsp = unescape(nal)
  let at = codec === 'h265' ? 2 : 1
  // An SEI NAL carries a sequence of payloads, each with 0xff-extended type and
  // size; the vcap payload is user_data_unregistered (5) with our UUID.
  while (at < rbsp.length) {
    let type = 0
    while (rbsp[at] === 0xff) { type += 255; at++ }
    if (at >= rbsp.length) return null
    type += rbsp[at++]!
    let size = 0
    while (rbsp[at] === 0xff) { size += 255; at++ }
    if (at >= rbsp.length) return null
    size += rbsp[at++]!
    if (at + size > rbsp.length) return null
    // payloadSize covers the UUID too: 16 + the 20 bytes §5 names.
    if (type === 5 && size >= 36 && equal(rbsp.subarray(at, at + 16), VCAP_SEI_UUID)) return rbsp.subarray(at + 16, at + 36)
    at += size
    if (rbsp[at] === 0x80) break
  }
  return null
}

const nalsOf = (media: Bytes, sample: Sample, nalLength: number): Bytes[] => {
  const out: Bytes[] = []
  let at = sample.offset
  const end = sample.offset + sample.size
  while (at + nalLength <= end) {
    let size = 0
    for (let i = 0; i < nalLength; i++) size = size * 256 + media[at + i]!
    at += nalLength
    if (size === 0 || at + size > end) break
    out.push(media.subarray(at, at + size))
    at += size
  }
  return out
}

export const recomputeSegments = async (media: Bytes, captureId?: Bytes): Promise<Recomputation> => {
  let gops: { first: number, last: number, index: number | null }[]
  let video: Track
  let audio: Track | undefined
  try {
    const top = boxes(media, 0, media.length)
    if (find(top, 'moof')) return { kind: 'unsupported', reason: 'fragmented mp4' }
    const moov = find(top, 'moov')
    if (!moov) return { kind: 'unsupported', reason: 'no moov' }
    const mvhd = child(media, moov, 'mvhd')
    if (!mvhd) return { kind: 'unsupported', reason: 'no mvhd' }
    const movieTimescale = media[mvhd.body] === 1 ? readU32BE(media, mvhd.body + 20) : readU32BE(media, mvhd.body + 12)
    const tracks = boxes(media, moov.body, moov.end).filter((x) => x.type === 'trak').map((t) => parseTrack(media, t, movieTimescale))
    const found = tracks.find((t) => t.handler === 'vide')
    if (!found?.codec) return { kind: 'unsupported', reason: 'no H.264 or H.265 video track' }
    video = found
    audio = tracks.find((t) => t.handler === 'soun')

    // GOP boundaries come from the sync sample table; the index of each comes
    // from its vcap SEI where present (§5 lets the SEI locate segments, never
    // prove anything), because in a clip position in the file is not the index.
    gops = video.sync.map((first, i) => {
      const last = (video.sync[i + 1] ?? video.samples.length) - 1
      let index: number | null = null
      for (let s = first; s <= last && index === null; s++) {
        for (const nal of nalsOf(media, video.samples[s]!, video.nalLength)) {
          const payload = vcapSeiPayload(nal, video.codec)
          // A SEI from another capture locates nothing here.
          if (payload && (!captureId || equal(payload.subarray(0, 16), captureId))) { index = readU32BE(payload, 16); break }
        }
      }
      return { first, last, index }
    })
  } catch (e) {
    return { kind: 'unsupported', reason: e instanceof Error ? e.message : 'unreadable container' }
  }

  // Fill the GOPs whose SEI is absent by contiguity with one that has an index.
  // With no vcap SEI anywhere, nothing locates the segments: position in the
  // file is not the index (a clip starts wherever it was cut), and a guess here
  // would turn a legitimate clip red.
  const anchor = gops.findIndex((g) => g.index !== null)
  if (anchor === -1) return { kind: 'unsupported', reason: 'no vcap SEI locates a segment' }
  const indexed = gops.map((g, i) => g.index ?? gops[anchor]!.index! + (i - anchor))

  const out: GopHash[] = []
  for (let i = 0; i < gops.length; i++) {
    const gop = gops[i]!
    const parts: Bytes[] = []
    for (let s = gop.first; s <= gop.last; s++) {
      for (const nal of nalsOf(media, video.samples[s]!, video.nalLength)) {
        if (!vcapSeiPayload(nal, video.codec)) parts.push(nal)
      }
    }
    if (audio) {
      const from = presentation(video, video.samples[gop.first]!.dts)
      const next = video.sync[i + 1]
      const to = next === undefined ? null : presentation(video, video.samples[next]!.dts)
      for (const sample of audio.samples) {
        const at = presentation(audio, sample.dts)
        // Half-open [DTS(IDR n), DTS(IDR n+1)); the last segment runs to the end
        // of the track, and frames before the first IDR belong to no segment.
        if (!before(at, from) && (to === null || before(at, to))) parts.push(media.subarray(sample.offset, sample.offset + sample.size))
      }
    }
    out.push({ index: indexed[i]!, hash: await sha256(concat(...parts)) })
  }
  return { kind: 'hashes', gops: out }
}
