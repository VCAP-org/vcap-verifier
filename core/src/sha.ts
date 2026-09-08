import type { Bytes } from './bytes.js'

// WebCrypto is the only crypto the core uses: present in every browser and in Node 22.
export const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle
  if (!s) throw new Error('WebCrypto is not available in this environment')
  return s
}

// WebCrypto's typings want a Uint8Array over a plain ArrayBuffer; a copy is the
// simplest way to promise that whatever slice we were handed.
export const owned = (b: Bytes): Uint8Array<ArrayBuffer> => Uint8Array.from(b)

export const sha256 = async (...parts: Bytes[]): Promise<Bytes> => {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const joined = new Uint8Array(new ArrayBuffer(total))
  let offset = 0
  for (const p of parts) { joined.set(p, offset); offset += p.length }
  return new Uint8Array(await subtle().digest('SHA-256', joined))
}
