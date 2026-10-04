import { type Bytes, concat } from './bytes.js'
import { sha256 } from './sha.js'

/**
 * §5 *Timing*: the timing record of one segment, `timing(n)`, and what a
 * verifier does with it — ported from vcap-spec's reference
 * (`tools/src/timing.ts`), rule for rule, over Uint8Array and WebCrypto.
 *
 * Why it exists: a segment's `content_hash` covers NAL units and audio frame
 * bytes and `media.presentation` how a player is told to show them; neither
 * covers *when*. A re-mux that kept every sample could freeze a frame
 * (`stts`), reorder frames inside a GOP (`ctts`), rescale a track (`mdhd`) or
 * trim a located segment (the media edit) and still read *verified clip*. The
 * sealer hashes this record per segment and signs the root of those hashes in
 * the core (`media.timing`).
 *
 * This module reads no container: `container.ts` walks the sample tables and
 * hands each GOP's values here, so the byte layout stays testable on its own.
 */

/**
 * The values of one segment's record, each an integer in its own track's
 * media timescale, measured from the segment's own first sample — so a clip
 * that cut the segments before it has the same record as the original.
 */
export interface TimingValues {
  /** dts_i − dts_0 for each video sample of the segment, in decode order (the first is 0). */
  videoDts: bigint[]
  /** cts_i, the sample's composition offset from `ctts`; 0 when the track has none. */
  videoCts: bigint[]
  /** end_n − dts_0: the last video sample's DTS plus its own `stts` duration. */
  videoEnd: bigint
  /** adts_j − adts_0 for each audio frame §5 assigns to the segment, in decode order. */
  audioDts: bigint[]
  /** adur_j, each audio frame's `stts` duration. */
  audioDur: bigint[]
}

/** The `mdhd` timescale of each track; `audio` null when there is no audio track. */
export interface Timescales { video: bigint, audio: bigint | null }

/** A segment's span on one track, in that track's media ticks: [start, end). */
export interface Extent { start: bigint, end: bigint }

/** The single media edit §5 models: where the track's media starts, and for how long it is shown. */
export interface MediaEdit {
  /** `media_time`, in the track's media ticks. */
  mediaTime: bigint
  /** `segment_duration`, in movie ticks. */
  duration: bigint
  movieTimescale: bigint
  mediaTimescale: bigint
}

const INT64_MIN = -(1n << 63n)
const INT64_MAX = (1n << 63n) - 1n
const UINT64_MAX = (1n << 64n) - 1n
const UINT32_MAX = (1n << 32n) - 1n

/** A value that does not fit its field: a record that cannot be built is a timing that differs. */
class TimingUnencodable extends Error {}

const field = (size: 4 | 8, min: bigint, max: bigint, write: (view: DataView, value: bigint) => void) => (value: bigint): Bytes => {
  if (value < min || value > max) throw new TimingUnencodable(`${value} does not fit its field`)
  const out = new Uint8Array(size)
  write(new DataView(out.buffer), value)
  return out
}
const int64 = field(8, INT64_MIN, INT64_MAX, (v, x) => v.setBigInt64(0, x))
const uint64 = field(8, 0n, UINT64_MAX, (v, x) => v.setBigUint64(0, x))
const uint32 = field(4, 0n, UINT32_MAX, (v, x) => v.setUint32(0, Number(x)))

/**
 * The record's bytes (§5), big-endian, every field fixed-length and each
 * count before its list, so nothing can shift between the two halves:
 *
 * ```
 * timing(n) = uint32 v ‖ (int64 dts_i − dts_0 ‖ int64 cts_i) × v ‖ uint64 end_n − dts_0
 *           ‖ uint32 a ‖ (int64 adts_j − adts_0 ‖ uint32 adur_j) × a
 * ```
 */
export const timingRecord = (t: TimingValues): Bytes => {
  if (t.videoDts.length !== t.videoCts.length) throw new Error('timing: one composition offset per video sample')
  if (t.audioDts.length !== t.audioDur.length) throw new Error('timing: one duration per audio frame')
  return concat(
    uint32(BigInt(t.videoDts.length)),
    ...t.videoDts.flatMap((dts, i) => [int64(dts), int64(t.videoCts[i]!)]),
    uint64(t.videoEnd),
    uint32(BigInt(t.audioDts.length)),
    ...t.audioDts.flatMap((dts, j) => [int64(dts), uint32(t.audioDur[j]!)])
  )
}

/** `segments[n].timing`: SHA-256 of the record, 32 bytes. */
export const timingHash = async (t: TimingValues): Promise<Bytes> => await sha256(timingRecord(t))

/**
 * `media.timing.root`: SHA-256 over the 32-byte timing hashes of segments 0
 * to `segment_count − 1`, in index order. A flat hash, not a tree: a clip's
 * proof carries every entry, and a flat hash is the one two implementations
 * cannot build differently.
 */
export const timingRoot = async (hashes: Bytes[]): Promise<Bytes> => {
  if (hashes.some((h) => h.length !== 32)) throw new Error('timing root: every hash is 32 bytes')
  return await sha256(...hashes)
}

/**
 * Received ticks in the signed timescale: `t × ts_signed / ts_received`,
 * which must be an integer for **every** value, else null (timing differs).
 * Exact on purpose: a hash admits no tolerance, and a tolerance would be the
 * thing to argue about. Audio values need both audio timescales.
 */
export const convertTiming = (t: TimingValues, received: Timescales, signed: Timescales): TimingValues | null => {
  const scale = (from: bigint | null, to: bigint | null) => (value: bigint): bigint | null => {
    if (from === null || to === null || from <= 0n || to <= 0n) return null
    const product = value * to
    return product % from === 0n ? product / from : null
  }
  const all = (values: bigint[], f: (v: bigint) => bigint | null): bigint[] | null => {
    const out: bigint[] = []
    for (const value of values) {
      const converted = f(value)
      if (converted === null) return null
      out.push(converted)
    }
    return out
  }
  const video = scale(received.video, signed.video)
  const audio = scale(received.audio, signed.audio)
  const videoDts = all(t.videoDts, video)
  const videoCts = all(t.videoCts, video)
  const videoEnd = video(t.videoEnd)
  const audioDts = all(t.audioDts, audio)
  const audioDur = all(t.audioDur, audio)
  if (videoDts === null || videoCts === null || videoEnd === null || audioDts === null || audioDur === null) return null
  return { videoDts, videoCts, videoEnd, audioDts, audioDur }
}

/**
 * The hash of a record read from a received file, in the signed timescales,
 * or null when its values cannot be expressed in them or encoded at all: both
 * mean the timing differs.
 */
export const receivedTimingHash = async (t: TimingValues, received: Timescales, signed: Timescales): Promise<Bytes | null> => {
  const converted = convertTiming(t, received, signed)
  if (converted === null) return null
  try {
    return await timingHash(converted)
  } catch (e) {
    if (e instanceof TimingUnencodable) return null
    throw e
  }
}

/**
 * Whether the single media edit trims inside a segment's extent on one track
 * (§5 *Timing*, clips only): the segment starts before `media_time`, or ends
 * one movie tick or more after the edit does. The tick of slack is the
 * rounding a muxer cannot avoid when the movie timescale is the coarser one:
 * `(d + 1) × T ≤ (e − m) × M`, in integers.
 */
export const editTrims = (edit: MediaEdit, extent: Extent): boolean => {
  if (edit.mediaTime > extent.start) return true
  return (edit.duration + 1n) * edit.mediaTimescale <= (extent.end - edit.mediaTime) * edit.movieTimescale
}

/** A segment's video span: earliest composition instant to the latest instant a sample ends. */
export const videoExtent = (t: TimingValues, dts0: bigint): Extent => {
  let start: bigint | null = null
  let end: bigint | null = null
  t.videoDts.forEach((dts, i) => {
    const next = t.videoDts[i + 1] ?? t.videoEnd
    const shown = dts + t.videoCts[i]!
    const until = shown + (next - dts)
    if (start === null || shown < start) start = shown
    if (end === null || until > end) end = until
  })
  return { start: dts0 + (start ?? 0n), end: dts0 + (end ?? t.videoEnd) }
}

/** A segment's audio span: first frame's DTS to the last frame's DTS plus duration; null without audio. */
export const audioExtent = (t: TimingValues, adts0: bigint): Extent | null => {
  const last = t.audioDts.length - 1
  if (last < 0) return null
  return { start: adts0, end: adts0 + t.audioDts[last]! + t.audioDur[last]! }
}
