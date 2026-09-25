import { type Bytes, concat, equal, readU16BE, readU32BE, toHex, utf8 } from './bytes.js'
import { fourcc, jumbfUuid } from './jumbf.js'

/** Spec §4.1: container normalization before hashing. */
export type Container = 'jpeg' | 'bmff' | 'unknown'

export const detectContainer = (b: Bytes): Container => {
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xd8) return 'jpeg'
  if (b.length >= 8 && equal(b.subarray(4, 8), utf8('ftyp'))) return 'bmff'
  return 'unknown'
}

/** A piece of a JPEG before its first SOS: a marker segment, a fill byte, or a marker with no length. */
export interface JpegSegment { marker: number, bytes: Bytes }

// JPEG: the pieces before SOS in file order, and where the walk stopped. Fill
// bytes (0xFF padding before a marker) and length-less markers (TEM, RSTn) are
// pieces of their own. Throws on a marker structure it cannot walk: there is
// then no canonical form to hash, and the caller decides what that means.
export const jpegSegments = (jpeg: Bytes): { segments: JpegSegment[], rest: number } => {
  const segments: JpegSegment[] = []
  let pos = 2
  while (pos + 4 <= jpeg.length) {
    if (jpeg[pos] !== 0xff) throw new Error('JPEG: marker expected')
    const marker = jpeg[pos + 1] as number
    if (marker === 0xff) { segments.push({ marker, bytes: jpeg.subarray(pos, pos + 1) }); pos += 1; continue }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { segments.push({ marker, bytes: jpeg.subarray(pos, pos + 2) }); pos += 2; continue }
    if (marker === 0xda) break
    const length = readU16BE(jpeg, pos + 2)
    if (length < 2 || pos + 2 + length > jpeg.length) throw new Error('JPEG: segment length out of range')
    segments.push({ marker, bytes: jpeg.subarray(pos, pos + 2 + length) })
    pos += 2 + length
  }
  return { segments, rest: pos }
}

/** An APP11 segment whose payload starts with "JP": a packet of some JUMBF box, C2PA's or another. */
export const isJumbfSegment = (s: JpegSegment): boolean => s.marker === 0xeb && s.bytes[4] === 0x4a && s.bytes[5] === 0x50

/** The description TYPE of a C2PA Manifest Store (C2PA 11.1.4.2). */
export const C2PA_STORE_TYPE = jumbfUuid('c2pa')

/** One JUMBF APP11 packet: the segment, its sequence number `Z` and its share of the box. */
export interface JumbfPacket { segment: JpegSegment, z: number, data: Bytes }
/** The packets of one JUMBF box in file order, and the TYPE its `Z` = 1 packet names — null when that cannot be read. */
export interface JumbfGroup { packets: JumbfPacket[], type: string | null }

// The TYPE a first packet names: `LBox`, `TBox` = `jumb` (`XLBox` when
// `LBox` = 1), then a `jumd` whose first 16 bytes are the type.
const packetType = (p: Bytes): string | null => {
  if (p.length < 8 || fourcc(p, 4) !== 'jumb') return null
  const head = readU32BE(p, 0) === 1 ? 16 : 8
  if (p.length < head + 24 || fourcc(p, head + 4) !== 'jumd') return null
  return toHex(p.subarray(head + 8, head + 24))
}

/**
 * The JUMBF APP11 segments grouped into boxes by `En` (ISO 19566-5 over C2PA
 * A.3.1: CI "JP", `En` u16, `Z` u32, then the packet). A segment too short to
 * carry `En` belongs to no box and is a group of its own, of no readable type.
 * §4.1 and §3.2 read the type the same way, so the bytes a verifier hashes and
 * the store it reads the proof from can never disagree about what a box is.
 */
export const jumbfGroups = (segments: JpegSegment[]): JumbfGroup[] => {
  const byInstance = new Map<number, JumbfPacket[]>()
  const groups: JumbfPacket[][] = []
  for (const segment of segments) {
    if (!isJumbfSegment(segment)) continue
    if (segment.bytes.length < 12) { groups.push([{ segment, z: 0, data: segment.bytes.subarray(12) }]); continue }
    const en = readU16BE(segment.bytes, 6)
    const packets = byInstance.get(en) ?? []
    if (packets.length === 0) { byInstance.set(en, packets); groups.push(packets) }
    packets.push({ segment, z: readU32BE(segment.bytes, 8), data: segment.bytes.subarray(12) })
  }
  return groups.map((packets) => {
    const first = packets.find((p) => p.z === 1)
    return { packets, type: first ? packetType(first.data) : null }
  })
}

// §4.1, JPEG: drop the APP11 segments of the C2PA store and of every JUMBF box
// whose type cannot be read (vectors 02, 68); a readable JUMBF box of any other
// type — JPEG 360, JPEG Privacy and Security — is content, as C2PA hashes it
// (15.12.1.2, vector 122). Everything else is kept verbatim, and entropy-coded
// data after SOS is untouched.
export const stripC2paFromJpeg = (jpeg: Bytes): Bytes => {
  const { segments, rest } = jpegSegments(jpeg)
  const dropped = new Set(jumbfGroups(segments)
    .filter((g) => g.type === null || g.type === C2PA_STORE_TYPE)
    .flatMap((g) => g.packets.map((p) => p.segment)))
  return concat(jpeg.subarray(0, 2), ...segments.filter((s) => !dropped.has(s)).map((s) => s.bytes), jpeg.subarray(rest))
}

export const canonicalBytes = (media: Bytes): Bytes => detectContainer(media) === 'jpeg' ? stripC2paFromJpeg(media) : media
