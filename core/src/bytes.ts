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

export const readU32BE = (b: Bytes, at: number): number => ((b[at]! << 24) >>> 0) + (b[at + 1]! << 16) + (b[at + 2]! << 8) + b[at + 3]!
export const readU16BE = (b: Bytes, at: number): number => (b[at]! << 8) + b[at + 1]!
export const u32be = (n: number): Bytes => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
export const u64be = (n: number): Bytes => {
  const out = new Uint8Array(8)
  const big = BigInt(n)
  for (let i = 7; i >= 0; i--) out[i] = Number((big >> BigInt((7 - i) * 8)) & 0xffn)
  return out
}
