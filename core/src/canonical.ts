import { type Bytes, concat, readU16BE, utf8, equal } from './bytes.js'

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

/** §4.1: an APP11 segment whose payload starts with "JP" — C2PA's JUMBF, and every other JUMBF too. */
export const isJumbfSegment = (s: JpegSegment): boolean => s.marker === 0xeb && s.bytes[4] === 0x4a && s.bytes[5] === 0x50

// JPEG: drop the JUMBF APP11 segments, keep everything else verbatim;
// entropy-coded data after SOS is untouched.
export const stripC2paFromJpeg = (jpeg: Bytes): Bytes => {
  const { segments, rest } = jpegSegments(jpeg)
  return concat(jpeg.subarray(0, 2), ...segments.filter((s) => !isJumbfSegment(s)).map((s) => s.bytes), jpeg.subarray(rest))
}

export const canonicalBytes = (media: Bytes): Bytes => detectContainer(media) === 'jpeg' ? stripC2paFromJpeg(media) : media
