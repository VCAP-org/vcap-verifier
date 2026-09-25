import { describe, expect, it } from 'vitest'
import { concat, fromHex, u32be } from '../src/bytes.js'
import { MAX_CBOR_DEPTH, decodeCbor } from '../src/cbor.js'
import { cbor } from './c2pa-fixtures.js'

/**
 * The CBOR subset a claim and an ingredient are read with, and every way a
 * hostile one is refused: an error the carrier catches and reports as a
 * claim it cannot decode, never a hang and never a guess.
 */
describe('decodeCbor', () => {
  it('reads the subset: integers, strings, bytes, arrays, text-keyed maps, booleans and null', () => {
    const value = decodeCbor(cbor({ n: 1, big: 70_000, neg: -500, s: 'ü', b: Uint8Array.of(1, 2), a: [true, false, null], m: { k: 'v' } }))
    expect(value).toBeInstanceOf(Map)
    const m = value as Map<string, unknown>
    expect([m.get('n'), m.get('big'), m.get('neg'), m.get('s')]).toEqual([1, 70_000, -500, 'ü'])
    expect(m.get('b')).toEqual(Uint8Array.of(1, 2))
    expect(m.get('a')).toEqual([true, false, null])
    expect((m.get('m') as Map<string, unknown>).get('k')).toBe('v')
  })

  it('keeps a key named __proto__ as a key', () => {
    const m = decodeCbor(cbor(JSON.parse('{"__proto__":"x"}') as { [k: string]: string })) as Map<string, unknown>
    expect(m.get('__proto__')).toBe('x')
  })

  it.each([
    ['a truncated head', fromHex('19')],
    ['a string longer than the bytes left', fromHex('7a7fffffff')],
    ['an array claiming 2^32 − 1 items in five bytes', fromHex('9affffffff')],
    ['a map claiming more pairs than bytes', fromHex('b90100')],
    ['an indefinite-length array', fromHex('9f01ff')],
    ['a reserved additional-information value', fromHex('1c')],
    ['a tag', fromHex('c074323031332d30332d32315432303a30343a30305a')],
    ['a float', fromHex('fb3ff199999999999a')],
    ['undefined', fromHex('f7')],
    ['a map key that is not text', fromHex('a10102')],
    ['a map that repeats a key', concat(fromHex('a2'), cbor('k'), cbor(1), cbor('k'), cbor(2))],
    ['an integer past 2^53 − 1', fromHex('1b0020000000000000')],
    ['a negative integer past −2^53', fromHex('3b001fffffffffffff')],
    ['a text string that is not UTF-8', fromHex('62c328')],
    ['bytes after the item', fromHex('0101')],
    ['nothing at all', new Uint8Array()]
  ])('refuses %s', (_name, bytes) => {
    expect(() => decodeCbor(bytes)).toThrow()
  })

  it('stops at its depth cap instead of the stack', () => {
    const deep = concat(new Uint8Array(MAX_CBOR_DEPTH + 1).fill(0x81), Uint8Array.of(0))
    expect(() => decodeCbor(deep)).toThrow(/nested deeper/)
    const fine = concat(new Uint8Array(MAX_CBOR_DEPTH).fill(0x81), Uint8Array.of(0))
    expect(() => decodeCbor(fine)).not.toThrow()
  })

  it('counts items, so a flat array of a hundred thousand and one zeros is refused', () => {
    const many = concat(Uint8Array.of(0x9a), u32be(100_001), new Uint8Array(100_001))
    expect(() => decodeCbor(many)).toThrow(/items/)
  })
})
