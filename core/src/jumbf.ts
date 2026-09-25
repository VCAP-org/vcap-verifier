import { type Bytes, equal, fromHex, fromUtf8, readU32BE, toHex, utf8 } from './bytes.js'

/**
 * JUMBF (ISO/IEC 19566-5) as C2PA uses it: a superbox `jumb` whose first child
 * is a description box `jumd` — a 16-byte type UUID, one byte of toggles and
 * the optional fields they announce — followed by content boxes or further
 * superboxes. This reads the tree and interprets nothing: what a C2PA store,
 * manifest or assertion is lives in `carrier.ts`.
 *
 * Every length is checked against the bytes of the box that holds it, the
 * nesting against `MAX_JUMBF_DEPTH` and the box count against
 * `MAX_JUMBF_BOXES`, and any failure throws for the caller to catch: a store
 * that cannot be read is an answer about the store, never a crash.
 */
export interface Superbox { kind: 'superbox', type: string, label: string | null, toggles: number, salt?: Bytes, children: JumbfBox[] }
export interface ContentBox { kind: 'content', type: string, data: Bytes }
export type JumbfBox = Superbox | ContentBox

/** The ISO 19566-5 form of a four-character type as a UUID, lower-case hex. */
export const jumbfUuid = (fourcc: string): string => `${toHex(utf8(fourcc))}00110010800000aa00389b71`
export const JSON_BOX = jumbfUuid('json')
export const CBOR_BOX = jumbfUuid('cbor')
/** C2PA 2.4 §6.8: a redacted assertion keeps its box and holds one `uuid` content box with this ID and zeros. */
export const REDACTION_UUID = fromHex('caa98eee9d4df80e86ad4dffca263973')

export const MAX_JUMBF_DEPTH = 8
export const MAX_JUMBF_BOXES = 10_000

// Toggle bits of the description box, ISO 19566-5 §B.3: bit 0 (0x01) says the
// box is requestable and announces no field.
const LABEL = 0x02
const ID = 0x04
const SIGNATURE = 0x08
const PRIVATE = 0x10

const fourcc = (b: Bytes, at: number): string => String.fromCharCode(b[at]!, b[at + 1]!, b[at + 2]!, b[at + 3]!)

/** One box header inside [at, end): its type, where its body starts and where the next box starts. */
export const boxAt = (b: Bytes, at: number, end: number): { type: string, body: number, next: number } => {
  if (end - at < 8) throw new RangeError(`JUMBF: box header truncated at ${at}`)
  let size = readU32BE(b, at)
  let body = at + 8
  if (size === 1) {
    if (end - at < 16) throw new RangeError(`JUMBF: extended length truncated at ${at}`)
    size = readU32BE(b, at + 8) * 2 ** 32 + readU32BE(b, at + 12)
    body = at + 16
  } else if (size === 0) size = end - at
  if (!Number.isSafeInteger(size) || size < body - at || size > end - at) throw new RangeError(`JUMBF: box ${fourcc(b, at + 4)} at ${at} claims ${size} bytes of ${end - at}`)
  return { type: fourcc(b, at + 4), body, next: at + size }
}

/** The whole of `b` as one `jumb` superbox; bytes before or after it are refused. */
export const parseJumbf = (b: Bytes): Superbox => {
  const counter = { boxes: 0 }
  const top = boxAt(b, 0, b.length)
  if (top.type !== 'jumb') throw new Error(`JUMBF: a ${top.type} box where a superbox was expected`)
  if (top.next !== b.length) throw new Error('JUMBF: bytes after the superbox')
  return superbox(b, top.body, top.next, 0, counter)
}

const superbox = (b: Bytes, from: number, to: number, depth: number, counter: { boxes: number }): Superbox => {
  if (depth > MAX_JUMBF_DEPTH) throw new RangeError(`JUMBF nested deeper than ${MAX_JUMBF_DEPTH} levels`)
  const d = boxAt(b, from, to)
  if (d.type !== 'jumd') throw new Error('JUMBF: a superbox that does not open with its description box')
  if (d.next - d.body < 17) throw new RangeError('JUMBF: description box truncated')
  const toggles = b[d.body + 16] as number
  const out: Superbox = { kind: 'superbox', type: toHex(b.subarray(d.body, d.body + 16)), label: null, toggles, children: [] }
  let at = d.body + 17
  const skip = (n: number, what: string): void => {
    if (d.next - at < n) throw new RangeError(`JUMBF: description box too short for its ${what}`)
    at += n
  }
  if (toggles & LABEL) {
    const nul = b.subarray(at, d.next).indexOf(0)
    if (nul === -1) throw new Error('JUMBF: a label with no terminating NUL')
    out.label = fromUtf8(b.subarray(at, at + nul))
    at += nul + 1
  }
  if (toggles & ID) skip(4, 'ID')
  if (toggles & SIGNATURE) skip(32, 'signature')
  if (toggles & PRIVATE) {
    // C2PA's private field is the `c2sh` salt box (toggles 0x13); another
    // private box is skipped as the opaque field ISO 19566-5 makes it.
    const p = boxAt(b, at, d.next)
    if (p.type === 'c2sh') out.salt = b.subarray(p.body, p.next)
    at = p.next
  }
  if (at !== d.next) throw new Error('JUMBF: bytes after the fields the toggles announce')
  for (let pos = d.next; pos < to;) {
    if (++counter.boxes > MAX_JUMBF_BOXES) throw new RangeError(`JUMBF: more than ${MAX_JUMBF_BOXES} boxes`)
    const box = boxAt(b, pos, to)
    out.children.push(box.type === 'jumb'
      ? superbox(b, box.body, box.next, depth + 1, counter)
      : { kind: 'content', type: box.type, data: b.subarray(box.body, box.next) })
    pos = box.next
  }
  return out
}

export const superboxes = (box: Superbox): Superbox[] => box.children.filter((c): c is Superbox => c.kind === 'superbox')
export const contentOf = (box: Superbox, type: string): Bytes | undefined =>
  box.children.find((c): c is ContentBox => c.kind === 'content' && c.type === type)?.data

/** §6.8's second form of redaction: the label kept, the content replaced by the redaction UUID box. */
export const isRedacted = (box: Superbox): boolean => box.children.some((c) =>
  c.kind === 'content' && c.type === 'uuid' && c.data.length >= 16 && equal(c.data.subarray(0, 16), REDACTION_UUID))
