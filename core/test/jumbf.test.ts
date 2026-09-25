import { describe, expect, it } from 'vitest'
import { concat, fromHex, toHex, u32be, utf8 } from '../src/bytes.js'
import { JSON_BOX, MAX_JUMBF_DEPTH, contentOf, isRedacted, jumbfUuid, parseJumbf, superboxes } from '../src/jumbf.js'
import { box, jsonAssertion, redactedAssertion, superbox } from './c2pa-fixtures.js'

/**
 * JUMBF as a tree, and every box a hostile store can hand over refused with
 * an error the carrier turns into *the manifest store cannot be read*.
 */
describe('parseJumbf', () => {
  it('reads a description box with toggles 0x03: type, label, content', () => {
    const tree = parseJumbf(jsonAssertion('a.label', utf8('{"a":1}')))
    expect(tree).toMatchObject({ type: JSON_BOX, label: 'a.label', toggles: 0x03 })
    expect(new TextDecoder().decode(contentOf(tree, 'json'))).toBe('{"a":1}')
    expect(tree.salt).toBeUndefined()
  })

  it('reads toggles 0x13 and keeps the `c2sh` salt out of the content', () => {
    const salt = fromHex('00112233445566778899aabbccddeeff')
    const tree = parseJumbf(jsonAssertion('a.label', utf8('{}'), salt))
    expect(tree.toggles).toBe(0x13)
    expect(toHex(tree.salt as Uint8Array)).toBe(toHex(salt))
    expect(tree.children).toHaveLength(1)
  })

  it('skips an ID and a signature when the toggles announce them', () => {
    const jumd = box('jumd', fromHex(jumbfUuid('json')), Uint8Array.of(0x0f), utf8('x'), Uint8Array.of(0), u32be(7), new Uint8Array(32))
    const tree = parseJumbf(box('jumb', jumd, box('json', utf8('{}'))))
    expect(tree.label).toBe('x')
    expect(contentOf(tree, 'json')).toEqual(utf8('{}'))
  })

  it('reads an extended length (LBox 1) and a box that runs to the end (LBox 0)', () => {
    const inner = jsonAssertion('x', utf8('{}'))
    const body = inner.subarray(8)
    const extended = concat(u32be(1), utf8('jumb'), u32be(0), u32be(16 + body.length), body)
    expect(parseJumbf(extended).label).toBe('x')
    const toEnd = concat(u32be(0), utf8('jumb'), body)
    expect(parseJumbf(toEnd).label).toBe('x')
  })

  it('nests superboxes', () => {
    const tree = parseJumbf(superbox('c2pa', 'c2pa', [superbox('c2ma', 'urn:c2pa:m', [jsonAssertion('x', utf8('{}'))])]))
    expect(superboxes(superboxes(tree)[0]!)[0]!.label).toBe('x')
  })

  it('tells the redaction box from content', () => {
    expect(isRedacted(parseJumbf(redactedAssertion('x')))).toBe(true)
    expect(isRedacted(parseJumbf(jsonAssertion('x', utf8('{}'))))).toBe(false)
  })

  const valid = jsonAssertion('label', utf8('{"a":1}'))
  it.each([
    ['nothing', new Uint8Array()],
    ['a truncated header', valid.subarray(0, 6)],
    ['a box cut short', valid.subarray(0, valid.length - 1)],
    ['bytes after the superbox', concat(valid, Uint8Array.of(0))],
    ['a length of 2^32 − 1', concat(u32be(0xffffffff), valid.subarray(4))],
    ['a length below its own header', concat(u32be(4), valid.subarray(4))],
    ['an extended length past 2^53', concat(u32be(1), utf8('jumb'), u32be(0x00200000), u32be(0), valid.subarray(8))],
    ['a content box where the superbox was expected', box('json', utf8('{}'))],
    ['a superbox that does not open with its description', box('jumb', box('json', utf8('{}')))],
    ['a description box too short for its UUID', box('jumb', box('jumd', new Uint8Array(10)))],
    ['a label with no NUL', box('jumb', box('jumd', fromHex(JSON_BOX), Uint8Array.of(0x03), utf8('label')))],
    ['a signature announced and missing', box('jumb', box('jumd', fromHex(JSON_BOX), Uint8Array.of(0x0b), utf8('l'), Uint8Array.of(0)))],
    ['bytes the toggles do not announce', box('jumb', box('jumd', fromHex(JSON_BOX), Uint8Array.of(0x03), utf8('l'), Uint8Array.of(0, 9)))],
    ['a child box longer than its parent', box('jumb', box('jumd', fromHex(JSON_BOX), Uint8Array.of(0)), concat(u32be(64), utf8('json'), utf8('{}')))]
  ])('refuses %s', (_name, bytes) => {
    expect(() => parseJumbf(bytes)).toThrow()
  })

  it(`stops nesting at ${MAX_JUMBF_DEPTH} levels`, () => {
    let deep = jsonAssertion('x', utf8('{}'))
    for (let i = 0; i <= MAX_JUMBF_DEPTH; i++) deep = superbox('c2pa', `level ${i}`, [deep])
    expect(() => parseJumbf(deep)).toThrow(/nested deeper/)
  })
})
