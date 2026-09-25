import { type Bytes, fromUtf8 } from './bytes.js'

/**
 * The CBOR (RFC 8949) a C2PA claim and an ingredient assertion are written in,
 * read exactly as far as following a manifest chain needs and no further:
 * definite-length unsigned and negative integers, byte and text strings,
 * arrays, maps with text keys, `false`, `true` and `null`.
 *
 * Everything else — indefinite lengths, tags, floats, other simple values, a
 * map key that is not text — is refused rather than skipped. The input is
 * whatever sits in a file somebody handed over, and a decoder that guesses at
 * an item it does not implement is a decoder two readers disagree with.
 *
 * Bounded three ways, so a hostile claim costs what its bytes cost: a count is
 * refused when the bytes left cannot hold that many items, nesting stops at
 * `MAX_CBOR_DEPTH`, and the whole item at `MAX_CBOR_ITEMS`.
 */
export type Cbor = number | string | boolean | null | Bytes | Cbor[] | CborMap
// A Map, not an object: a key `__proto__` assigned to a plain object changes
// its prototype instead of adding a member.
export type CborMap = Map<string, Cbor>

export const MAX_CBOR_DEPTH = 16
export const MAX_CBOR_ITEMS = 100_000

export const decodeCbor = (b: Bytes): Cbor => {
  let at = 0
  let items = 0
  const need = (n: number): void => {
    if (n > b.length - at) throw new RangeError(`CBOR: ${n} bytes needed at ${at}, ${b.length - at} left`)
  }
  // The argument of a head: the value itself below 24, else the 1, 2, 4 or 8
  // bytes after it. 31 is an indefinite length, 28–30 are reserved.
  const argument = (info: number): number => {
    if (info < 24) return info
    const size = ({ 24: 1, 25: 2, 26: 4, 27: 8 } as Record<number, number>)[info]
    if (size === undefined) throw new Error('CBOR: indefinite length or reserved additional information')
    need(size)
    let value = 0
    for (let i = 0; i < size; i++) value = value * 256 + (b[at + i] as number)
    at += size
    if (!Number.isSafeInteger(value)) throw new RangeError('CBOR: integer outside ±(2^53 − 1)')
    return value
  }
  const item = (depth: number): Cbor => {
    if (depth > MAX_CBOR_DEPTH) throw new RangeError(`CBOR nested deeper than ${MAX_CBOR_DEPTH} levels`)
    if (++items > MAX_CBOR_ITEMS) throw new RangeError(`CBOR: more than ${MAX_CBOR_ITEMS} items`)
    need(1)
    const head = b[at++] as number
    const major = head >> 5
    const info = head & 31
    switch (major) {
      case 0: return argument(info)
      case 1: {
        const value = -1 - argument(info)
        if (!Number.isSafeInteger(value)) throw new RangeError('CBOR: integer outside ±(2^53 − 1)')
        return value
      }
      case 2: case 3: {
        const n = argument(info)
        need(n)
        const bytes = b.subarray(at, at + n)
        at += n
        return major === 2 ? bytes : fromUtf8(bytes)
      }
      case 4: {
        const n = argument(info)
        need(n)
        const out: Cbor[] = []
        for (let i = 0; i < n; i++) out.push(item(depth + 1))
        return out
      }
      case 5: {
        const n = argument(info)
        need(2 * n)
        const out: CborMap = new Map()
        for (let i = 0; i < n; i++) {
          const key = item(depth + 1)
          if (typeof key !== 'string') throw new Error('CBOR: a map key that is not text')
          // One key twice is a map two readers read two ways (the §6.1 rule for JSON).
          if (out.has(key)) throw new Error(`CBOR: the map repeats the key ${JSON.stringify(key)}`)
          out.set(key, item(depth + 1))
        }
        return out
      }
      case 7:
        if (info === 20) return false
        if (info === 21) return true
        if (info === 22) return null
        throw new Error(`CBOR: simple value or float ${info} not read here`)
      default: throw new Error(`CBOR: major type ${major} not read here`)
    }
  }
  const value = item(0)
  if (at !== b.length) throw new Error('CBOR: bytes after the item')
  return value
}
