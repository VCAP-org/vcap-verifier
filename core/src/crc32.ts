import type { Bytes } from './bytes.js'

// CRC-32 (IEEE 802.3), the one every standard library has. No security role:
// it separates a corrupted trailer from an edited one (spec §3).
const TABLE = new Uint32Array(256).map((_, n) => {
  let c = n
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
  return c >>> 0
})

export const crc32 = (bytes: Bytes): number => {
  let c = 0xffffffff
  for (const b of bytes) c = TABLE[(c ^ b) & 0xff]! ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}
