import type { Bytes } from './bytes.js'
import { owned, subtle } from './sha.js'

/** ES256 over raw bytes, P1363 signature (r ‖ s, 64 bytes): WebCrypto's native shape. */
export const importP256Spki = async (spki: Bytes): Promise<CryptoKey | null> => {
  try {
    return await subtle().importKey('spki', owned(spki), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
  } catch {
    return null
  }
}

export const verifyEs256 = async (key: CryptoKey, message: Bytes, signature: Bytes): Promise<boolean> => {
  if (signature.length !== 64) return false
  try {
    return await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, key, owned(signature), owned(message))
  } catch {
    return false
  }
}
