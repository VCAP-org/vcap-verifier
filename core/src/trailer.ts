import { type Bytes, concat, readU16BE, readU32BE, u32be, utf8, equal } from './bytes.js'
import { crc32 } from './crc32.js'

/** Spec §3: the trailer is a `free` box followed by a 16-byte footer. */
const MAGIC = utf8('VCAP')
const FOOTER = 16
const BOX_HEADER = 8

export type Trailer =
  | { kind: 'none' }
  | { kind: 'corrupted' }
  // §3: `VCAP` with a major this reader does not implement. The rest of such a
  // footer is not interpreted, and *no proof found* would tell a reader the
  // proof was stripped when it is there in a version this reader cannot read.
  | { kind: 'unsupported', major: number }
  | { kind: 'ok', payload: Bytes, flags: number, minor: number, media: Bytes }

export const parseTrailer = (file: Bytes): Trailer => {
  if (file.length < FOOTER + BOX_HEADER) return { kind: 'none' }
  const footer = file.subarray(file.length - FOOTER)
  if (!equal(footer.subarray(0, 4), MAGIC)) return { kind: 'none' }
  if (footer[4] !== 1) return { kind: 'unsupported', major: footer[4] as number }
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

/** §3's box and footer around a payload, the exact bytes `parseTrailer` reads back. */
export const buildTrailer = (payload: Bytes, flags: number, minor: number): Bytes => concat(
  u32be(BOX_HEADER + payload.length + FOOTER), utf8('free'),
  payload,
  MAGIC, Uint8Array.of(1, minor & 0xff, (flags >>> 8) & 0xff, flags & 0xff),
  u32be(payload.length), u32be(crc32(payload))
)

export type Replacement =
  | { kind: 'ok', file: Bytes }
  | { kind: 'refused', reason: string }

/**
 * §3: the same media bytes carrying a different payload.
 *
 * This is the one edit the format allows on a sealed file, and it exists
 * because the §6.2 attachments are produced *after* the device seals: a
 * timestamp token is minted by a TSA and an anchor is mined, minutes later and
 * somewhere else. Without a way to put them back, evidence that was obtained
 * for a capture can never reach the file somebody hands to a verifier.
 *
 * What makes it safe is what it does **not** touch. The media prefix does not
 * move, so `media.hash` covers the same bytes; the caller's payload must carry
 * the same §6.1 core and the same `sig`, so the device's signature covers the
 * same core hash — the attachments are outside `CORE_KEYS` by construction
 * (§6), which is the whole reason they can be added by somebody who
 * cannot sign. **This function does not check that**: it works on bytes and
 * has no opinion about JSON, so the caller compares the cores before calling
 * it, and `verify` is the judge afterwards either way.
 *
 * Two refusals, both of them ways to produce a file that reads worse than the
 * one that went in:
 *
 * - **appending instead of replacing.** A second trailer over a sealed file is
 *   *nested proof* (§3), which is exactly the attack the rule exists to stop.
 *   The old trailer is therefore dropped, never wrapped, and a media prefix
 *   that already ends in a footer is refused rather than sealed over.
 * - **replacing a trailer that is not intact.** A corrupted trailer means
 *   somebody edited the file; rewriting it would replace the evidence of that
 *   with a clean proof. *corrupted proof* is the verdict the file has earned
 *   and it must survive.
 *
 * `flags` and `minor` are carried over from the trailer being replaced rather
 * than recomputed: they are the writer's, they are derived from a core that
 * has not changed, and §3 makes the JSON win over them anyway.
 */
export const replaceTrailer = (file: Bytes, payload: Bytes): Replacement => {
  const current = parseTrailer(file)
  if (current.kind === 'none') return { kind: 'refused', reason: 'the file carries no trailer to replace' }
  if (current.kind === 'corrupted') return { kind: 'refused', reason: 'the trailer is corrupted' }
  if (current.kind === 'unsupported') return { kind: 'refused', reason: `the trailer is of major version ${current.major}` }
  if (parseTrailer(current.media).kind !== 'none') return { kind: 'refused', reason: 'the canonical bytes end in another trailer' }
  if (payload.length > 0xffffffff - (BOX_HEADER + FOOTER)) return { kind: 'refused', reason: 'payload too large for a free box' }
  return { kind: 'ok', file: concat(current.media, buildTrailer(payload, current.flags, current.minor)) }
}
