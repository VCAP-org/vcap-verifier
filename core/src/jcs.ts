import { type Bytes, utf8 } from './bytes.js'

/**
 * RFC 8785 canonical JSON: keys sorted by UTF-16 code units at every level,
 * primitives as ECMAScript serializes them. The core (spec §6.1) carries
 * integers and enum strings only, so this is byte-identical in every
 * implementation.
 *
 * Serialized by hand rather than by `JSON.stringify` over a re-keyed object,
 * because an object cannot hold the order RFC 8785 asks for: ECMAScript puts
 * integer-like keys first in numeric order (`{"b","10","9"}` came out as
 * `9, 10, b`, where code-unit order is `10, 9, b`), and a plain object drops
 * an own `__proto__` key on assignment. Both produce a core hash no other
 * implementation computes.
 */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

/**
 * Deeper than any proof this version defines by an order of magnitude, and far
 * short of the stack: a payload nested ten thousand levels deep is an attack on
 * the reader, and it gets an error the caller can catch instead of a crash.
 */
export const MAX_DEPTH = 64

const serialize = (v: Json, depth: number): string => {
  if (depth > MAX_DEPTH) throw new RangeError(`JSON nested deeper than ${MAX_DEPTH} levels`)
  if (Array.isArray(v)) return `[${v.map((x) => serialize(x, depth + 1)).join(',')}]`
  if (v !== null && typeof v === 'object') {
    // `sort()` with no comparator compares UTF-16 code units, which is RFC 8785 §3.2.3.
    // A member whose value is `undefined` is left out, as `JSON.stringify`
    // leaves it out: it cannot come from parsed JSON, only from a caller's
    // object, and that caller's JSON of the same object would not carry it.
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${serialize(v[k] as Json, depth + 1)}`).join(',')}}`
  }
  return JSON.stringify(v) ?? 'null'
}

export const jcs = (v: Json): Bytes => utf8(serialize(v, 0))

/**
 * Why `text` is not a proof this format can read, or null. `text` must
 * already be valid JSON; this is §6.1 *Reading the JSON*, the rules that leave
 * two parsers no room to disagree:
 *
 * - **no member name twice in one object**, at any depth. `JSON.parse` keeps
 *   the last and says nothing, so a payload could show one reader
 *   `"secure_hw": "strongbox"` and another `"none"`;
 * - **every number an integer literal** `-?(0|[1-9][0-9]*)` — no fraction, no
 *   exponent, not `4032.0` — **within ±(2^53 − 1)**, the range every JSON
 *   implementation reads exactly. `JSON.parse` turns `1e3` and `1000` into
 *   the same number and rounds 2^53 + 1, so the text is read, not the value.
 *
 * Iterative, so depth costs nothing.
 */
export const jsonProblem = (text: string): string | null => {
  // One entry per open container: the keys seen so far for an object, null for an array.
  const open: Array<Set<string> | null> = []
  let expectKey = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!
    if (c === '"') {
      let j = i + 1
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1
      const keys = open.at(-1)
      if (keys && expectKey) {
        // Decoded, so `"a"` and `"\u0061"` are the same key, as they are to a parser.
        const key = JSON.parse(text.slice(i, j + 1)) as string
        if (keys.has(key)) return `payload repeats the key ${JSON.stringify(key)}`
        keys.add(key)
        expectKey = false
      }
      i = j
    } else if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i + 1
      while (j < text.length && /[0-9eE.+-]/.test(text[j]!)) j++
      const literal = text.slice(i, j)
      if (!/^-?(0|[1-9][0-9]*)$/.test(literal)) return `payload number ${literal} is not an integer literal`
      if (!Number.isSafeInteger(Number(literal))) return `payload number ${literal} is outside ±(2^53 − 1)`
      i = j - 1
    } else if (c === '{') {
      open.push(new Set())
      expectKey = true
    } else if (c === '[') {
      open.push(null)
      expectKey = false
    } else if (c === '}' || c === ']') {
      open.pop()
    } else if (c === ',') {
      expectKey = open.at(-1) instanceof Set
    } else if (c === ':') {
      expectKey = false
    }
  }
  return null
}
