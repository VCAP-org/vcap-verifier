import { type Bytes, equal, fromHex, readU32BE } from './bytes.js'
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

/**
 * `hashes`: the container was read and a vcap SEI of this capture names at
 * least one GOP. `gops` are the GOPs that earn credit — exactly one well-formed
 * vcap SEI of this capture, an index the proof signs, carried by no other GOP
 * — each hashed. `problems` is every way the rest of the file fails to account
 * for itself, in decode order (§5 *Locating segments*); any one is *tampered*.
 * `unlocated`: the container was read and no GOP names this capture — no
 * segment credit, and nothing contradicts the proof either.
 * `unsupported`: the container is not one this reads.
 * `malformed`: NAL framing that does not tile its sample, or a sample outside
 * the file — bytes inside a segment that no hash would cover — *tampered*,
 * with no segment credited.
 */
export type Recomputation =
  | { kind: 'hashes', gops: GopHash[], problems: string[] }
  | { kind: 'unlocated', reason: string }
  | { kind: 'unsupported', reason: string }
  | { kind: 'malformed', reason: string }

/** Thrown where the bytes, not the reader, are at fault; `recomputeSegments` turns it into `malformed`. */
class Malformed extends Error {}

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
      if (at + 16 > to) throw new Error('box largesize truncated')
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
  codec: 'h264' | 'h265' | null
  nalLength: number
  // Presentation offset (§5): empty edits delay the track (movie ticks, hence
  // `movieTimescale`), and the first real edit says which media time the
  // track's samples start at.
  delay: number
  movieTimescale: number
  mediaStart: number
}

/**
 * The entry count of a FullBox table (1 byte version, 3 bytes flags, then the
 * count), refused when the box cannot hold that many entries. The count is a
 * u32 an attacker writes: trusted, 2^32 iterations freeze a browser tab before
 * the first out-of-range read is ever reached.
 */
const tableCount = (b: Bytes, box: Box, header: number, stride: number): number => {
  const count = readU32BE(b, box.body + header - 4)
  if (count > Math.floor((box.end - box.body - header) / stride)) throw new Error('table count exceeds its box')
  return count
}

const entries = (b: Bytes, box: Box, stride: number, read: (at: number) => void): void => {
  const count = tableCount(b, box, 8, stride)
  for (let i = 0; i < count; i++) read(box.body + 8 + i * stride)
}

const sampleTable = (b: Bytes, stbl: Box): Sample[] => {
  const children = boxes(b, stbl.body, stbl.end)
  const get = (type: string): Box => {
    const box = find(children, type)
    if (!box) throw new Error(`stbl without ${type}`)
    return box
  }

  const sizes: number[] = []
  const stsz = find(children, 'stsz')
  if (!stsz) {
    // stz2 packs sizes in 4, 8 or 16 bits; unseen on the writers we handle.
    throw new Error('stbl without stsz')
  }
  const uniform = readU32BE(b, stsz.body + 4)
  if (uniform === 0) {
    const count = tableCount(b, stsz, 12, 4)
    for (let i = 0; i < count; i++) sizes.push(readU32BE(b, stsz.body + 12 + i * 4))
  } else {
    // A uniform size has no table to bound the count by; the file does. Every
    // sample occupies `uniform` bytes of it, so more of them than fit is a lie.
    const count = readU32BE(b, stsz.body + 8)
    if (count * uniform > b.length) throw new Error('stsz declares more bytes than the file holds')
    for (let i = 0; i < count; i++) sizes.push(uniform)
  }

  // stts is run-length; expanded only as far as there are samples, so a run
  // of 2^32 costs what the file actually has.
  const deltas: number[] = []
  entries(b, get('stts'), 8, (at) => {
    const count = Math.min(readU32BE(b, at), sizes.length - deltas.length)
    const delta = readU32BE(b, at + 4)
    for (let i = 0; i < count; i++) deltas.push(delta)
  })

  const chunkOffsets: number[] = []
  const stco = find(children, 'stco')
  const co64 = find(children, 'co64')
  if (stco) entries(b, stco, 4, (at) => chunkOffsets.push(readU32BE(b, at)))
  else if (co64) entries(b, co64, 8, (at) => chunkOffsets.push(Number(new DataView(b.buffer, b.byteOffset + at, 8).getBigUint64(0))))
  else throw new Error('stbl without stco or co64')

  // stsc is run-length over chunks, sorted by first chunk: walked once.
  const runs: { firstChunk: number, perChunk: number }[] = []
  entries(b, get('stsc'), 12, (at) => runs.push({ firstChunk: readU32BE(b, at), perChunk: readU32BE(b, at + 4) }))

  const samples: Sample[] = []
  let sample = 0
  let dts = 0
  let run = -1
  for (let chunk = 1; chunk <= chunkOffsets.length && sample < sizes.length; chunk++) {
    while (run + 1 < runs.length && runs[run + 1]!.firstChunk <= chunk) run++
    if (run === -1) throw new Error('stsc does not cover chunk 1')
    let offset = chunkOffsets[chunk - 1]!
    for (let i = 0; i < runs[run]!.perChunk && sample < sizes.length; i++, sample++) {
      const size = sizes[sample]!
      samples.push({ offset, size, dts })
      offset += size
      dts += deltas[sample] ?? deltas.at(-1) ?? 0
    }
  }
  if (samples.length !== sizes.length) throw new Error('chunk offsets do not cover every sample')
  return samples
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

const timescaleOf = (b: Bytes, header: Box): number => {
  const timescale = b[header.body] === 1 ? readU32BE(b, header.body + 20) : readU32BE(b, header.body + 12)
  if (timescale === 0) throw new Error('timescale 0')
  return timescale
}

const parseTrack = (b: Bytes, trak: Box, movieTimescale: number): Track => {
  const mdia = child(b, trak, 'mdia')
  if (!mdia) throw new Error('trak without mdia')
  const mdhd = child(b, mdia, 'mdhd')
  const hdlr = child(b, mdia, 'hdlr')
  const stbl = child(b, mdia, 'minf', 'stbl')
  if (!mdhd || !hdlr || !stbl) throw new Error('trak without mdhd, hdlr or stbl')
  const timescale = timescaleOf(b, mdhd)
  if (hdlr.body + 12 > hdlr.end) throw new Error('hdlr truncated')
  const handler = TYPE(b, hdlr.body + 8)
  const samples = sampleTable(b, stbl)

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
      const at = config ? config.body + (codec === 'h264' ? 4 : 21) : -1
      if (config && at < config.end) nalLength = (b[at]! & 3) + 1
      break
    }
  }

  const elst = child(b, trak, 'edts', 'elst')
  const edit = elst ? editList(b, elst) : { delay: 0, mediaStart: 0 }
  return { handler, timescale, movieTimescale, samples, codec, nalLength, ...edit }
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

const nalType = (nal: Bytes, codec: Track['codec']): number => codec === 'h265' ? (nal[0]! >> 1) & 0x3f : nal[0]! & 0x1f

// §5: a segment runs from an IDR access unit to the next one. IDR is H.264
// type 5 and H.265 IDR_W_RADL/IDR_N_LP (19, 20); a CRA or BLA is a random
// access point and not an IDR, so it starts no segment whatever `stss` says.
const isIdr = (nal: Bytes, codec: Track['codec']): boolean => {
  if (nal.length < 1) return false
  const type = nalType(nal, codec)
  return codec === 'h265' ? type === 19 || type === 20 : type === 5
}

type Sei = { captureId: Bytes, index: number } | { malformed: string }

/**
 * The vcap SEI a NAL unit carries, if it carries one: `capture_id || n`.
 *
 * A NAL is a vcap SEI when one of its messages is `user_data_unregistered`
 * with the vcap UUID. Such a NAL must then be exactly what §5 describes — one
 * message, `payloadSize` 36, nothing after it but the RBSP trailing bits —
 * because it is the one NAL the hash excludes: a vcap SEI that also carried
 * another message would carry that message outside every signature, and one
 * sized 37 would carry a byte nobody signed. Anything else is `malformed`,
 * and the GOP holding it is *tampered* (vector 93).
 */
const vcapSei = (nal: Bytes, codec: Track['codec']): Sei | null => {
  if (nal.length < 2) return null
  const type = nalType(nal, codec)
  if (!(codec === 'h265' ? type === 39 || type === 40 : type === 6)) return null
  const rbsp = unescape(nal)
  let at = codec === 'h265' ? 2 : 1
  let messages = 0
  let ours: { size: number, payload: number } | null = null
  // An SEI NAL carries a sequence of messages, each with 0xff-extended type and
  // size; a sequence that cannot be read is content, not a vcap SEI.
  while (at < rbsp.length && rbsp[at] !== 0x80) {
    let payloadType = 0
    while (rbsp[at] === 0xff) { payloadType += 255; at++ }
    if (at >= rbsp.length) return ours === null ? null : { malformed: 'truncated' }
    payloadType += rbsp[at++]!
    let size = 0
    while (rbsp[at] === 0xff) { size += 255; at++ }
    if (at >= rbsp.length) return ours === null ? null : { malformed: 'truncated' }
    size += rbsp[at++]!
    if (at + size > rbsp.length) return ours === null ? null : { malformed: 'truncated' }
    messages++
    if (payloadType === 5 && size >= 16 && equal(rbsp.subarray(at, at + 16), VCAP_SEI_UUID)) ours = { size, payload: at }
    at += size
  }
  if (ours === null) return null
  if (messages !== 1) return { malformed: `${messages} messages in one NAL` }
  if (ours.size !== 36) return { malformed: `payloadSize ${ours.size}, not 36` }
  // rbsp_trailing_bits, then only the zero bytes framing leaves inside a unit.
  if (rbsp[at] !== 0x80 || rbsp.subarray(at + 1).some((x) => x !== 0)) return { malformed: 'bytes after the message' }
  return { captureId: rbsp.slice(ours.payload + 16, ours.payload + 32), index: readU32BE(rbsp, ours.payload + 32) }
}

/**
 * The NAL units of a sample, as the length prefixes frame them — and they must
 * frame all of it. A prefix of zero, one that reaches past the sample, or
 * leftover bytes too short for a prefix leave bytes inside a segment that no
 * NAL, and so no hash, covers; stopping there quietly is how they would go
 * unsigned. The sample itself must lie inside the file.
 */
const nalsOf = (media: Bytes, sample: Sample, nalLength: number): Bytes[] => {
  const end = sample.offset + sample.size
  if (end > media.length) throw new Malformed('a sample lies outside the file')
  const out: Bytes[] = []
  let at = sample.offset
  while (at < end) {
    if (at + nalLength > end) throw new Malformed('NAL length prefix truncated')
    let size = 0
    for (let i = 0; i < nalLength; i++) size = size * 256 + media[at + i]!
    at += nalLength
    if (size === 0 || at + size > end) throw new Malformed(`NAL length ${size} does not fit its sample`)
    out.push(media.subarray(at, at + size))
    at += size
  }
  return out
}

interface Gop { first: number, last: number, seis: Sei[] }

/**
 * The GOPs of the video track and every vcap SEI each one carries.
 * Boundaries come from the IDRs in the samples, never from `stss`, which in
 * H.265 lists CRA pictures too (vector 94) and is metadata anybody can write.
 * Samples before the first IDR belong to no segment (§5).
 */
const locate = (media: Bytes, video: Track): Gop[] => {
  const gops: Gop[] = []
  for (let s = 0; s < video.samples.length; s++) {
    const nals = nalsOf(media, video.samples[s]!, video.nalLength)
    if (nals.some((nal) => isIdr(nal, video.codec))) gops.push({ first: s, last: s, seis: [] })
    const gop = gops.at(-1)
    if (!gop) continue
    for (const nal of nals) {
      const sei = vcapSei(nal, video.codec)
      if (sei) gop.seis.push(sei)
    }
    gop.last = s
  }
  return gops
}

const isOurs = (sei: Sei, captureId: Bytes | undefined): sei is { captureId: Bytes, index: number } =>
  'index' in sei && (!captureId || equal(sei.captureId, captureId))

/**
 * §5 *Locating segments*, applied whole: once one GOP names this capture,
 * every GOP accounts for itself in decode order. Returns the index each GOP
 * earns credit for (or null), and every problem, in order.
 */
const account = (gops: Gop[], captureId: Bytes | undefined, signed: Set<number> | undefined): { credit: Array<number | null>, problems: string[] } => {
  const problems: string[] = []
  const named: Array<number | null> = gops.map((gop, k) => {
    const where = `GOP ${k} (sample ${gop.first})`
    const bad = gop.seis.find((x): x is { malformed: string } => 'malformed' in x)
    if (bad) { problems.push(`${where}: vcap SEI malformed: ${bad.malformed}`); return null }
    if (gop.seis.length === 0) { problems.push(`${where} carries no vcap SEI`); return null }
    if (gop.seis.length > 1) { problems.push(`${where} carries ${gop.seis.length} vcap SEIs`); return null }
    const sei = gop.seis[0]!
    if (!isOurs(sei, captureId)) { problems.push(`${where} names another capture`); return null }
    if (signed && !signed.has(sei.index)) { problems.push(`${where} names segment ${sei.index}, which the proof does not sign`); return null }
    return sei.index
  })
  // An index carried twice earns nothing for either GOP: which one is the
  // signed frames is exactly what cannot be told (vector 91).
  const seen = new Map<number, number>()
  for (const n of named) if (n !== null) seen.set(n, (seen.get(n) ?? 0) + 1)
  for (const [n, count] of seen) if (count > 1) problems.push(`segment index ${n} is carried by ${count} GOPs`)
  // File order is signed order: an index that does not increase is a GOP
  // moved, which the chain over messages cannot see because every message it
  // checks is genuine (vector 90). The GOPs keep their credit; the file is
  // still tampered.
  let last: number | null = null
  for (const n of named) {
    if (n === null) continue
    if (last !== null && n <= last && seen.get(n) === 1) problems.push(`segment index ${n} follows ${last} in decode order`)
    last = n
  }
  return { credit: named.map((n) => n !== null && seen.get(n) === 1 ? n : null), problems }
}

/** Hashes a GOP's video NALs, vcap SEIs excluded, then its audio frames: §5's `content_hash`. */
const hashGop = async (media: Bytes, video: Track, gop: Gop, audio: Bytes[]): Promise<Bytes> => {
  const parts: Bytes[] = []
  for (let s = gop.first; s <= gop.last; s++) {
    for (const nal of nalsOf(media, video.samples[s]!, video.nalLength)) {
      // Only a well-formed vcap SEI is outside `content_hash`; a GOP holding a
      // malformed one earns no credit and is never hashed.
      if (!vcapSei(nal, video.codec)) parts.push(nal)
    }
  }
  parts.push(...audio)
  // `sha256` joins the parts itself: concatenating here first would copy every
  // segment twice.
  return await sha256(...parts)
}

/**
 * `signed` is the set of segment indices the proof carries entries for, when
 * the caller has a proof: a GOP naming any other index names a segment this
 * proof does not sign (vector 38 drops segment 0 from the proof and leaves it
 * in the file), and that is *tampered*.
 */
export const recomputeSegments = async (media: Bytes, captureId?: Bytes, signed?: Set<number>): Promise<Recomputation> => {
  let video: Track
  let audio: Track | undefined
  try {
    const top = boxes(media, 0, media.length)
    if (find(top, 'moof')) return { kind: 'unsupported', reason: 'fragmented mp4' }
    const moov = find(top, 'moov')
    if (!moov) return { kind: 'unsupported', reason: 'no moov' }
    const mvhd = child(media, moov, 'mvhd')
    if (!mvhd) return { kind: 'unsupported', reason: 'no mvhd' }
    const movieTimescale = timescaleOf(media, mvhd)
    const tracks = boxes(media, moov.body, moov.end).filter((x) => x.type === 'trak').map((t) => parseTrack(media, t, movieTimescale))
    const found = tracks.find((t) => t.handler === 'vide')
    if (!found?.codec) return { kind: 'unsupported', reason: 'no H.264 or H.265 video track' }
    video = found
    audio = tracks.find((t) => t.handler === 'soun')
  } catch (e) {
    return { kind: 'unsupported', reason: e instanceof Error ? e.message : 'unreadable container' }
  }

  try {
    // §5: a GOP's index is never inferred from its position in the file, and
    // a GOP that cannot be placed is never skipped: once one GOP names this
    // capture, every GOP must.
    const gops = locate(media, video)
    if (!gops.some((g) => g.seis.some((x) => isOurs(x, captureId)))) return { kind: 'unlocated', reason: 'no vcap SEI names this capture' }
    const { credit, problems } = account(gops, captureId, signed)

    // Audio by two pointers: both tracks are in decode order, so each frame's
    // presentation time is computed once and compared against one boundary,
    // not against every GOP.
    const audioTimes = audio ? audio.samples.map((sample) => presentation(audio!, sample.dts)) : []
    let next = 0
    const out: GopHash[] = []
    for (let g = 0; g < gops.length; g++) {
      const gop = gops[g]!
      const from = presentation(video, video.samples[gop.first]!.dts)
      const following = gops[g + 1]
      const to = following === undefined ? null : presentation(video, video.samples[following.first]!.dts)
      // Half-open [DTS(IDR n), DTS(IDR n+1)); the last segment runs to the end
      // of the track, and frames before the first IDR belong to no segment.
      while (next < audioTimes.length && before(audioTimes[next]!, from)) next++
      const frames: Bytes[] = []
      while (next < audioTimes.length && (to === null || before(audioTimes[next]!, to))) {
        const sample = audio!.samples[next++]!
        if (sample.offset + sample.size > media.length) throw new Malformed('an audio sample lies outside the file')
        frames.push(media.subarray(sample.offset, sample.offset + sample.size))
      }
      const index = credit[g]
      if (index !== null && index !== undefined) out.push({ index, hash: await hashGop(media, video, gop, frames) })
    }
    return { kind: 'hashes', gops: out, problems }
  } catch (e) {
    if (e instanceof Malformed) return { kind: 'malformed', reason: e.message }
    return { kind: 'unsupported', reason: e instanceof Error ? e.message : 'unreadable container' }
  }
}
