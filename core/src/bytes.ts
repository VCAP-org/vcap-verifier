/**
 * Byte helpers that work identically in a browser and in Node: no Buffer.
 * Everything the core hands out is a Uint8Array or a plain string.
 */
export type Bytes = Uint8Array

export const concat = (...parts: Bytes[]): Bytes => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) { out.set(p, offset); offset += p.length }
  return out
}

export const equal = (a: Bytes, b: Bytes): boolean => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}

export const utf8 = (s: string): Bytes => new TextEncoder().encode(s)
export const fromUtf8 = (b: Bytes): string => new TextDecoder('utf-8', { fatal: true }).decode(b)

export const toHex = (b: Bytes): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
export const fromHex = (hex: string): Bytes => {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('bad hex')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

// Base64 without atob/btoa: those choke on non-Latin-1 in some engines and are
// missing in others, and a verifier must not depend on the host's mood.
export const fromBase64 = (s: string): Bytes => {
  const text = s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '')
  if (!/^[A-Za-z0-9+/]*$/.test(text)) throw new Error('bad base64')
  const out = new Uint8Array(Math.floor(text.length * 3 / 4))
  let bits = 0; let acc = 0; let n = 0
  for (const ch of text) {
    acc = (acc << 6) | B64.indexOf(ch); bits += 6
    if (bits >= 8) { bits -= 8; out[n++] = (acc >> bits) & 0xff }
  }
  return out.subarray(0, n)
}

/**
 * Standard base64 with padding, for the callers that hand bytes to a platform
 * decoder rather than to another verifier: `atob`, Android's `Base64.decode`
 * and `NSData` all refuse the URL-safe alphabet. Everything *inside* a proof
 * is base64url (§6.1) and keeps using `toBase64url`.
 */
export const toBase64 = (b: Bytes): string => {
  const raw = toBase64url(b).replace(/-/g, '+').replace(/_/g, '/')
  return raw + '='.repeat((4 - raw.length % 4) % 4)
}

export const toBase64url = (b: Bytes): string => {
  let out = ''
  for (let i = 0; i < b.length; i += 3) {
    const [x, y, z] = [b[i] as number, b[i + 1], b[i + 2]]
    const triple = (x << 16) | ((y ?? 0) << 8) | (z ?? 0)
    out += B64[(triple >> 18) & 63]! + B64[(triple >> 12) & 63]!
    out += y === undefined ? '' : B64[(triple >> 6) & 63]!
    out += z === undefined ? '' : B64[triple & 63]!
  }
  return out.replace(/\+/g, '-').replace(/\//g, '_')
}

// A read past the end throws rather than returning NaN: every caller parses
// untrusted bytes, and a NaN that reaches `BigInt` or a loop bound is a crash
// or a hang somewhere far from the read that produced it.
const inside = (b: Bytes, at: number, n: number): void => {
  if (!Number.isInteger(at) || at < 0 || at + n > b.length) throw new RangeError(`read of ${n} bytes at ${at} past the end (${b.length})`)
}
export const readU32BE = (b: Bytes, at: number): number => { inside(b, at, 4); return ((b[at]! << 24) >>> 0) + (b[at + 1]! << 16) + (b[at + 2]! << 8) + b[at + 3]! }
export const readU16BE = (b: Bytes, at: number): number => { inside(b, at, 2); return (b[at]! << 8) + b[at + 1]! }
export const u32be = (n: number): Bytes => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
export const u64be = (n: number): Bytes => {
  // `BigInt(1.5)` and `BigInt(undefined)` throw, and a value past 2^53 is not
  // the number the signer meant: refuse both here, where the caller can catch.
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`${String(n)} is not a non-negative safe integer`)
  const out = new Uint8Array(8)
  const big = BigInt(n)
  for (let i = 7; i >= 0; i--) out[i] = Number((big >> BigInt((7 - i) * 8)) & 0xffn)
  return out
}

/**
 * An instant in milliseconds that `Date` can hold (±8.64e15 ms, ECMA-262
 * §21.4.1.1) and that is a safe integer. Outside it `new Date(n)` is an
 * Invalid Date and `toISOString()` throws, so every signed or relayed instant
 * is checked with this before it becomes a `Date`.
 */
export const isInstant = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0 && (n as number) <= 8.64e15
