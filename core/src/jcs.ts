import { type Bytes, utf8 } from './bytes.js'

/**
 * RFC 8785 canonical JSON: JSON.stringify over an object with keys sorted by
 * UTF-16 code units at every level. The core (spec §6.1) carries integers and
 * enum strings only, so this is byte-identical in every implementation.
 */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

const canonical = (v: Json): Json => {
  if (Array.isArray(v)) return v.map(canonical)
  if (v !== null && typeof v === 'object') {
    const out: { [key: string]: Json } = {}
    for (const k of Object.keys(v).sort()) out[k] = canonical(v[k] as Json)
    return out
  }
  return v
}

export const jcs = (v: Json): Bytes => utf8(JSON.stringify(canonical(v)))
