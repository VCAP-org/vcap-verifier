import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { equal, fromBase64, fromUtf8, toBase64, utf8 } from '../src/bytes.js'
import { buildTrailer, parseTrailer, replaceTrailer } from '../src/trailer.js'
import { verify } from '../src/verify.js'
import { corpus } from './corpus.js'

/**
 * §3's one permitted edit: the payload replaced, the media bytes untouched.
 *
 * The vectors are the fixtures on purpose — a hand-built trailer would test
 * this module against itself, and what has to hold is that a real sealed file
 * goes through `replaceTrailer` and comes out reading the same to `verify`.
 */

const dir = corpus().dir
const vector = (name: string, file: string): Uint8Array => new Uint8Array(readFileSync(join(dir, name, file)))

const enriched = (payload: Uint8Array, attachment: object): Uint8Array => {
  const proof = JSON.parse(fromUtf8(payload)) as Record<string, unknown>
  return utf8(JSON.stringify({ ...proof, ...attachment }))
}

describe('replaceTrailer', () => {
  const sealed = vector('01-jpeg-sealed', 'input.jpg')
  const original = parseTrailer(sealed)
  if (original.kind !== 'ok') throw new Error('vector 01 is not sealed')

  it('keeps the media bytes, the flags and the minor', () => {
    const out = replaceTrailer(sealed, enriched(original.payload, { anchor: { chain: 'base-sepolia' } }))
    expect(out.kind).toBe('ok')
    if (out.kind !== 'ok') return
    const rewritten = parseTrailer(out.file)
    expect(rewritten.kind).toBe('ok')
    if (rewritten.kind !== 'ok') return
    expect(equal(rewritten.media, original.media)).toBe(true)
    expect(rewritten.flags).toBe(original.flags)
    expect(rewritten.minor).toBe(original.minor)
    expect(JSON.parse(fromUtf8(rewritten.payload))).toMatchObject({ anchor: { chain: 'base-sepolia' } })
  })

  it('leaves the verdict where it was: same outcome, same core hash, no `sidecar differs`', async () => {
    const before = await verify(sealed)
    const out = replaceTrailer(sealed, enriched(original.payload, { anchor: { chain: 'base-sepolia' } }))
    if (out.kind !== 'ok') throw new Error(out.reason)
    // The sidecar is the payload that was written: a file whose two copies of
    // the proof disagree is the thing this must never produce.
    const after = await verify(out.file, { sidecar: parseTrailer(out.file).kind === 'ok' ? (parseTrailer(out.file) as { payload: Uint8Array }).payload : undefined })
    expect(after.outcome).toBe(before.outcome)
    expect(after.core_hash).toBe(before.core_hash)
    expect(after.labels).not.toContain('sidecar differs')
    expect(after.outcome).not.toBe('nested_proof')
  })

  it('replaces rather than appends, so a second pass does not grow the file', () => {
    const once = replaceTrailer(sealed, enriched(original.payload, { anchor: {} }))
    if (once.kind !== 'ok') throw new Error(once.reason)
    const twice = replaceTrailer(once.file, enriched(original.payload, { anchor: {} }))
    if (twice.kind !== 'ok') throw new Error(twice.reason)
    expect(twice.file.length).toBe(once.file.length)
    expect(equal(twice.file, once.file)).toBe(true)
  })

  it('refuses a file with no trailer', () => {
    expect(replaceTrailer(vector('05-jpeg-no-trailer', 'input.jpg'), utf8('{}'))).toEqual({ kind: 'refused', reason: 'the file carries no trailer to replace' })
  })

  it('refuses a corrupted trailer, because *corrupted proof* is the verdict the file earned', () => {
    expect(replaceTrailer(vector('06-jpeg-footer-crc-mismatch', 'input.jpg'), utf8('{}'))).toEqual({ kind: 'refused', reason: 'the trailer is corrupted' })
  })

  it('refuses a double-sealed file instead of hiding the inner proof', () => {
    expect(replaceTrailer(vector('09-jpeg-double-sealed', 'input.jpg'), utf8('{}'))).toEqual({ kind: 'refused', reason: 'the canonical bytes end in another trailer' })
  })
})

describe('buildTrailer', () => {
  it('writes what parseTrailer reads', () => {
    const payload = utf8('{"v":"vcap/1.0"}')
    const file = new Uint8Array([...utf8('media'), ...buildTrailer(payload, 6, 0)])
    const read = parseTrailer(file)
    expect(read.kind).toBe('ok')
    if (read.kind !== 'ok') return
    expect(fromUtf8(read.payload)).toBe('{"v":"vcap/1.0"}')
    expect(read.flags).toBe(6)
    expect(fromUtf8(read.media)).toBe('media')
  })
})

describe('toBase64', () => {
  it('round-trips through fromBase64 in the standard alphabet, padded', () => {
    for (let n = 0; n < 8; n++) {
      const bytes = new Uint8Array(Array.from({ length: n }, (_, i) => (i * 61 + 251) & 0xff))
      const text = toBase64(bytes)
      expect(/^[A-Za-z0-9+/]*={0,2}$/.test(text)).toBe(true)
      expect(text.length % 4).toBe(0)
      expect(equal(fromBase64(text), bytes)).toBe(true)
    }
  })
})
