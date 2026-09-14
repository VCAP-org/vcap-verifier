import { type Bytes, readU16BE, readU32BE, utf8, equal } from './bytes.js'
import { crc32 } from './crc32.js'

/** Spec §3: the trailer is a `free` box followed by a 16-byte footer. */
const MAGIC = utf8('VCAP')
const FOOTER = 16
const BOX_HEADER = 8

export type Trailer =
  | { kind: 'none' }
  | { kind: 'corrupted' }
  | { kind: 'ok', payload: Bytes, flags: number, minor: number, media: Bytes }

export const parseTrailer = (file: Bytes): Trailer => {
  if (file.length < FOOTER + BOX_HEADER) return { kind: 'none' }
  const footer = file.subarray(file.length - FOOTER)
  if (!equal(footer.subarray(0, 4), MAGIC) || footer[4] !== 1) return { kind: 'none' }
  const payloadLen = readU32BE(footer, 8)
  const total = BOX_HEADER + payloadLen + FOOTER
  if (total > file.length) return { kind: 'none' }
  const boxStart = file.length - total
  if (readU32BE(file, boxStart) !== total) return { kind: 'none' }
  if (!equal(file.subarray(boxStart + 4, boxStart + 8), utf8('free'))) return { kind: 'none' }
  const payload = file.subarray(boxStart + BOX_HEADER, file.length - FOOTER)
  if (crc32(payload) !== readU32BE(footer, 12)) return { kind: 'corrupted' }
  return { kind: 'ok', payload, flags: readU16BE(footer, 6), minor: footer[5] as number, media: file.subarray(0, boxStart) }
}
