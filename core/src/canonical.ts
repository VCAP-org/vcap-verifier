import { type Bytes, concat, readU16BE, utf8, equal } from './bytes.js'

/** Spec §4.1: container normalization before hashing. */
export type Container = 'jpeg' | 'bmff' | 'unknown'

export const detectContainer = (b: Bytes): Container => {
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xd8) return 'jpeg'
  if (b.length >= 8 && equal(b.subarray(4, 8), utf8('ftyp'))) return 'bmff'
  return 'unknown'
}

// JPEG: drop APP11 segments whose payload starts with "JP" (C2PA's JUMBF), keep
// everything else verbatim; entropy-coded data after SOS is untouched.
export const stripC2paFromJpeg = (jpeg: Bytes): Bytes => {
  const kept: Bytes[] = [jpeg.subarray(0, 2)]
  let pos = 2
  while (pos + 4 <= jpeg.length) {
    if (jpeg[pos] !== 0xff) throw new Error('JPEG: marker expected')
    const marker = jpeg[pos + 1] as number
    // §4.1 keeps fill bytes (0xFF padding before a marker) and length-less
    // markers (TEM, RSTn) as they are: content, not a segment to judge.
    if (marker === 0xff) { kept.push(jpeg.subarray(pos, pos + 1)); pos += 1; continue }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { kept.push(jpeg.subarray(pos, pos + 2)); pos += 2; continue }
    if (marker === 0xda) break
    const length = readU16BE(jpeg, pos + 2)
    const segment = jpeg.subarray(pos, pos + 2 + length)
    const isJumbf = marker === 0xeb && segment[4] === 0x4a && segment[5] === 0x50
    if (!isJumbf) kept.push(segment)
    pos += 2 + length
  }
  kept.push(jpeg.subarray(pos))
  return concat(...kept)
}

export const canonicalBytes = (media: Bytes): Bytes => detectContainer(media) === 'jpeg' ? stripC2paFromJpeg(media) : media
