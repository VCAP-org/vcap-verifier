import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { concat, fromUtf8, toBase64url, toHex, utf8 } from '../src/bytes.js'
import { jcs, type Json } from '../src/jcs.js'
import { sha256, subtle } from '../src/sha.js'
import { buildTrailer, parseTrailer } from '../src/trailer.js'
import { PROOF_LABEL, extractProof } from '../src/carrier.js'
import { SOURCE_CAPTURE, coreHashOf, extractCore, verify } from '../src/verify.js'
import { bmffWithStore, box, c2paUuidBox, jpegWithStore, manifest, redactedAssertion, store, superbox } from './c2pa-fixtures.js'
import { corpus } from './corpus.js'
import { canonicalBytes, isJumbfSegment, jpegSegments } from '../src/canonical.js'

/**
 * The C2PA carrier: where a store is found, which copy of the proof wins, how
 * far up the `parentOf` chain a proof is looked for, and the verdict over a
 * proof that came out of a manifest. Every store is built here, byte by byte
 * (`c2pa-fixtures.ts`); every proof is a vector's, so the verdicts are the
 * core's over real signatures.
 */
const dir = corpus().dir
const read = (vector: string, file: string): Uint8Array => new Uint8Array(readFileSync(join(dir, vector, file)))
const sealed = (vector: string, file: string) => {
  const bytes = read(vector, file)
  const t = parseTrailer(bytes)
  if (t.kind !== 'ok') throw new Error(`${vector} is not sealed`)
  return { file: bytes, media: t.media, payload: t.payload, flags: t.flags, minor: t.minor }
}
const photo = sealed('01-jpeg-sealed', 'input.jpg')
const proof = photo.payload
/** The same proof re-serialized: other key order, other whitespace, the same JCS. */
const reserialized = (payload: Uint8Array): Uint8Array => {
  const value = JSON.parse(fromUtf8(payload)) as Record<string, Json>
  return utf8(JSON.stringify(Object.fromEntries(Object.entries(value).reverse()), null, 2))
}
/** The same proof with one attachment more: a different proof as JCS, the same core. */
const enriched = (payload: Uint8Array): Uint8Array => utf8(JSON.stringify({ ...JSON.parse(fromUtf8(payload)), anchor: { chain: 'x' } }))
/** Vector 01's media with one entropy-coded byte changed: what an edit leaves. */
const edited = (() => { const b = Uint8Array.from(photo.media); b[b.length - 20] = b[b.length - 20]! ^ 0xff; return b })()
const one = (m: Parameters<typeof manifest>[0]): Uint8Array => store(manifest(m))
const labels01 = ['integrity unevaluated', 'key not in transparency log', 'location declared only', 'no trusted time', 'not anchored', 'origin not hardware-attested', 'watermark not evaluated']

/** A chain `urn:c2pa:0` (active) → `urn:c2pa:1` → …, each naming the next as its `parentOf`. */
const chain = (length: number, proofAt: number, extra: Partial<Parameters<typeof manifest>[0]> = {}): Uint8Array =>
  store(...Array.from({ length }, (_, i) => length - 1 - i).map((depth) => manifest({
    label: `urn:c2pa:${depth}`,
    ...(depth === proofAt ? { proof } : {}),
    ...(depth < length - 1 ? { ingredients: [['parentOf', `urn:c2pa:${depth + 1}`] as [string, string]] } : {}),
    ...(depth === 0 ? extra : {})
  })))

describe('where the store is found', () => {
  it('JPEG: one APP11 packet, read at depth 0, with where the claim lists it and who generated it', () => {
    const x = extractProof(jpegWithStore(photo.media, one({ label: 'urn:c2pa:one', proof, generator: 'Acme Cam' })))
    expect(x).toMatchObject({ kind: 'proof', source: { kind: 'c2pa', manifest: 'urn:c2pa:one', depth: 0 }, labels: [] })
    expect(x.c2pa).toEqual({ store: 'embedded', manifests: 1, active: { label: 'urn:c2pa:one', generator: 'Acme Cam 1.0' }, proof: { manifest: 'urn:c2pa:one', depth: 0, listed_as: 'gathered_assertions' }, notes: [] })
  })

  it('JPEG: packets reassembled in file order, Z = 1, 2, 3 …; the same packets out of order are a store that cannot be read', () => {
    const s = one({ label: 'urn:c2pa:split', proof, listed: 'created_assertions' })
    const x = extractProof(jpegWithStore(photo.media, s, { packet: 100 }))
    expect(x.kind === 'proof' && fromUtf8(x.payload)).toBe(fromUtf8(proof))
    expect(x.c2pa?.proof?.listed_as).toBe('created_assertions')
    // §3.2 and C2PA A.3.1: a broken sequence is not re-sorted into a store.
    expect(extractProof(jpegWithStore(photo.media, s, { packet: 100, reorder: true }))).toMatchObject({ kind: 'refused', outcome: 'no_proof_found', c2pa: { unread: 'the manifest store cannot be read: its APP11 packets are not numbered 1 to n in file order' } })
  })

  it('JPEG: a missing packet, or one that does not repeat the box header, is a store that cannot be read', () => {
    const file = jpegWithStore(photo.media, one({ label: 'urn:c2pa:split', proof }), { packet: 100 })
    // Drop the second APP11 packet: Z then jumps from 1 to 3.
    const packet = jpegSegments(file).segments.filter(isJumbfSegment)[1]!.bytes
    const second = packet.byteOffset
    const gap = concat(file.subarray(0, second), file.subarray(second + packet.length))
    expect(extractProof(gap)).toMatchObject({ kind: 'refused', outcome: 'no_proof_found', c2pa: { unread: 'the manifest store cannot be read: its APP11 packets are not numbered 1 to n in file order' } })
    const bent = Uint8Array.from(file)
    bent[second + 15] = bent[second + 15]! ^ 1
    expect(extractProof(bent).c2pa?.unread).toBe('the manifest store cannot be read: an APP11 packet does not repeat the box header')
  })

  it('JPEG: two stores (two box instance numbers) are no carrier at all, and no external store either', () => {
    const two = jpegWithStore(jpegWithStore(photo.media, one({ label: 'urn:c2pa:a', proof }), { en: 1 }), one({ label: 'urn:c2pa:b', proof }), { en: 2 })
    const x = extractProof(two, undefined, one({ label: 'urn:c2pa:ext', proof }))
    expect(x).toMatchObject({ kind: 'refused', outcome: 'no_proof_found', reason: 'no trailer and no sidecar', c2pa: { store: 'embedded', unread: 'more than one C2PA manifest store is embedded' } })
  })

  it('§4.1: the canonical bytes lose the C2PA store and any JUMBF of no readable type, and keep every other JUMBF box', () => {
    const base = canonicalBytes(photo.media)
    const app11 = (payload: Uint8Array): Uint8Array => concat(Uint8Array.of(0xff, 0xeb, (payload.length + 2) >> 8, (payload.length + 2) & 0xff), payload)
    const inserted = (segment: Uint8Array): Uint8Array => concat(photo.media.subarray(0, 2), segment, photo.media.subarray(2))
    expect(canonicalBytes(jpegWithStore(photo.media, one({ label: 'urn:c2pa:m', proof }), { packet: 100 }))).toEqual(base)
    // No En, no Z = 1 packet, no jumb/jumd: JUMBF-shaped, of no type anyone can read (vectors 02, 68).
    for (const junk of [utf8('JP'), concat(utf8('JP'), Uint8Array.of(0, 1, 0, 0, 0, 2), utf8('jumbjumd')), concat(utf8('JP'), Uint8Array.of(0, 1, 0, 0, 0, 1), utf8('not a box'))]) {
      expect(canonicalBytes(inserted(app11(junk)))).toEqual(base)
    }
    // A JPEG 360 or privacy box is content, as C2PA hashes it (15.12.1.2, vector 122).
    const other = jpegWithStore(photo.media, superbox('json', 'jpeg360', [box('json', utf8('{}'))]))
    expect(canonicalBytes(other)).toEqual(other)
  })

  it('JPEG: a JUMBF that is not a C2PA store is not one, and the external store is read instead', () => {
    const other = superbox('json', 'jpeg360', [box('json', utf8('{}'))])
    const x = extractProof(jpegWithStore(photo.media, other), undefined, one({ label: 'urn:c2pa:ext', proof }))
    expect(x).toMatchObject({ kind: 'proof', source: { kind: 'c2pa', manifest: 'urn:c2pa:ext', depth: 0 }, c2pa: { store: 'external' } })
  })

  it('an embedded store outranks the external one', () => {
    const x = extractProof(jpegWithStore(photo.media, one({ label: 'urn:c2pa:in', proof })), undefined, one({ label: 'urn:c2pa:ext', proof }))
    expect(x).toMatchObject({ source: { manifest: 'urn:c2pa:in' }, c2pa: { store: 'embedded' } })
  })

  const heic = sealed('23-heic-sealed', 'input.heic')
  it('ISO-BMFF: the uuid box after ftyp, the merkle offset skipped, for the purposes manifest, original and update', () => {
    for (const purpose of ['manifest', 'original', 'update']) {
      const x = extractProof(bmffWithStore(heic.media, c2paUuidBox(one({ label: `urn:c2pa:${purpose}`, proof: heic.payload }), purpose)))
      expect(x).toMatchObject({ kind: 'proof', source: { kind: 'c2pa', manifest: `urn:c2pa:${purpose}`, depth: 0 } })
    }
  })

  it('ISO-BMFF: an auxiliary merkle box holds no store; two store boxes are no carrier', () => {
    const merkle = bmffWithStore(heic.media, c2paUuidBox(new Uint8Array(12), 'merkle'))
    expect(extractProof(merkle).c2pa).toBeUndefined()
    const s = c2paUuidBox(one({ label: 'urn:c2pa:m', proof: heic.payload }))
    expect(extractProof(bmffWithStore(bmffWithStore(heic.media, s), s)).c2pa?.unread).toBe('more than one C2PA manifest store is embedded')
  })

  it('an external store is used as the caller hands it over', () => {
    const x = extractProof(photo.media, undefined, one({ label: 'urn:c2pa:ext', proof }))
    expect(x).toMatchObject({ kind: 'proof', source: { kind: 'c2pa', manifest: 'urn:c2pa:ext', depth: 0 }, c2pa: { store: 'external' } })
  })

  it('a file with no store and no external store reports none', () => {
    expect(extractProof(photo.media)).toEqual({ kind: 'refused', outcome: 'no_proof_found', reason: 'no trailer and no sidecar' })
  })

  it.each([
    ['a store box claiming 2^32 − 1 bytes', (s: Uint8Array) => concat(Uint8Array.of(0xff, 0xff, 0xff, 0xff), s.subarray(4))],
    ['a truncated store', (s: Uint8Array) => s.subarray(0, s.length - 5)],
    ['a store that is not the C2PA type', () => superbox('json', 'c2pa', [])],
    ['a store holding no manifest', () => store()],
    ['a store that repeats a manifest label', () => store(manifest({ label: 'urn:c2pa:x', proof }), manifest({ label: 'urn:c2pa:x', proof }))]
  ])('%s cannot be read, and carries nothing', (_name, bend) => {
    const x = extractProof(photo.media, undefined, bend(one({ label: 'urn:c2pa:m', proof })))
    expect(x).toMatchObject({ kind: 'refused', outcome: 'no_proof_found' })
    expect(x.c2pa?.unread).toMatch(/^the manifest store cannot be read: /)
  })
})

describe('which copy is the proof', () => {
  it('an intact trailer wins; a manifest copy that is the same proof as JCS carries no label', () => {
    const x = extractProof(jpegWithStore(photo.file, one({ label: 'urn:c2pa:m', proof: reserialized(proof) })))
    expect(x).toMatchObject({ kind: 'proof', source: { kind: 'trailer' }, labels: [] })
    expect(x.c2pa?.proof).toEqual({ manifest: 'urn:c2pa:m', depth: 0, listed_as: 'gathered_assertions' })
  })

  it('a manifest copy that differs as JCS is *manifest copy differs*, and the trailer still decides', async () => {
    const file = jpegWithStore(photo.file, one({ label: 'urn:c2pa:m', proof: enriched(proof) }))
    expect(extractProof(file)).toMatchObject({ source: { kind: 'trailer' }, labels: ['manifest copy differs'] })
    const v = await verify(file)
    expect(v.outcome).toBe('authentic')
    expect(v.labels).toEqual([...labels01, 'manifest copy differs'].sort())
    expect(v.proof_source).toEqual({ kind: 'trailer' })
  })

  it('a manifest copy that is no proof at all differs', () => {
    expect(extractProof(jpegWithStore(photo.file, one({ label: 'urn:c2pa:m', proof: utf8('{"v":"vcap/1.0","v":"vcap/1.0"}') })))).toMatchObject({ labels: ['manifest copy differs'] })
  })

  it('the trailer and the sidecar keep the byte rule: a re-serialized sidecar is *sidecar differs*', () => {
    expect(extractProof(photo.file, reserialized(proof))).toMatchObject({ source: { kind: 'trailer' }, labels: ['sidecar differs'] })
  })

  it('a footer whose CRC fails is corrupted proof, whatever the store carries', async () => {
    const file = jpegWithStore(read('06-jpeg-footer-crc-mismatch', 'input.jpg'), one({ label: 'urn:c2pa:m', proof }))
    const v = await verify(file)
    expect(v).toMatchObject({ outcome: 'corrupted_proof', reason: 'footer valid, CRC mismatch', content_credentials: { store: 'embedded', manifests: 1 } })
    expect(v.proof_source).toBeUndefined()
  })

  it('a footer of another major is unsupported, whatever the store carries', async () => {
    const file = jpegWithStore(read('115-jpeg-footer-major-2', 'input.jpg'), one({ label: 'urn:c2pa:m', proof }))
    expect((await verify(file)).outcome).toBe('unsupported_format_version')
  })

  it('a nested trailer is still nested proof', async () => {
    expect((await verify(jpegWithStore(read('09-jpeg-double-sealed', 'input.jpg'), one({ label: 'urn:c2pa:m', proof })))).outcome).toBe('nested_proof')
  })

  it('no footer: the active manifest before the sidecar, which is compared as JCS', () => {
    const file = jpegWithStore(photo.media, one({ label: 'urn:c2pa:m', proof }))
    expect(extractProof(file, reserialized(proof))).toMatchObject({ source: { kind: 'c2pa', depth: 0 }, labels: [] })
    expect(extractProof(file, enriched(proof))).toMatchObject({ source: { kind: 'c2pa', depth: 0 }, labels: ['sidecar differs'] })
  })

  it('no footer and no proof at depth 0: the sidecar before the chain, which is then not searched', () => {
    const x = extractProof(jpegWithStore(photo.media, chain(2, 1)), proof)
    expect(x).toMatchObject({ source: { kind: 'sidecar' }, labels: [] })
    expect(x.c2pa?.proof).toBeUndefined()
  })
})

describe('the parentOf chain', () => {
  it('finds the nearest proof up the chain and says how deep', () => {
    for (const depth of [1, 3, 16]) {
      expect(extractProof(photo.media, undefined, chain(depth + 1, depth))).toMatchObject({ source: { kind: 'c2pa', manifest: `urn:c2pa:${depth}`, depth } })
    }
  })

  it('stops at depth 16', () => {
    expect(extractProof(photo.media, undefined, chain(18, 17))).toMatchObject({ kind: 'refused', reason: 'no trailer and no sidecar' })
  })

  it('never follows componentOf or inputTo', () => {
    for (const relationship of ['componentOf', 'inputTo']) {
      const s = store(manifest({ label: 'urn:c2pa:1', proof }), manifest({ label: 'urn:c2pa:0', ingredients: [[relationship, 'urn:c2pa:1']] }))
      expect(extractProof(photo.media, undefined, s).kind).toBe('refused')
    }
  })

  it('follows the parentOf beside a componentOf, and a v1 claim with a v1 ingredient', () => {
    const beside = store(manifest({ label: 'urn:c2pa:c', proof: enriched(proof) }), manifest({ label: 'urn:c2pa:1', proof }),
      manifest({ label: 'urn:c2pa:0', ingredients: [['componentOf', 'urn:c2pa:c'], ['parentOf', 'urn:c2pa:1']] }))
    expect(extractProof(photo.media, undefined, beside)).toMatchObject({ source: { manifest: 'urn:c2pa:1', depth: 1 } })
    const v1 = store(manifest({ label: 'urn:c2pa:1', proof, claimVersion: 1 }), manifest({ label: 'urn:c2pa:0', claimVersion: 1, ingredients: [['parentOf', 'urn:c2pa:1']], ingredientVersion: 1 }))
    const x = extractProof(photo.media, undefined, v1)
    expect(x).toMatchObject({ source: { manifest: 'urn:c2pa:1', depth: 1 }, c2pa: { proof: { listed_as: 'assertions' }, active: { generator: 'test-generator/1.0' } } })
  })

  it('stops at a cycle, at two parentOf ingredients, and at a parent that is not in the store', () => {
    const cycle = store(manifest({ label: 'urn:c2pa:1', ingredients: [['parentOf', 'urn:c2pa:0']] }), manifest({ label: 'urn:c2pa:0', ingredients: [['parentOf', 'urn:c2pa:1']] }))
    expect(extractProof(photo.media, undefined, cycle)).toMatchObject({ kind: 'refused', c2pa: { notes: ['the parentOf chain returns to urn:c2pa:0, and stops'] } })
    const two = store(manifest({ label: 'urn:c2pa:a', proof }), manifest({ label: 'urn:c2pa:b', proof }), manifest({ label: 'urn:c2pa:0', ingredients: [['parentOf', 'urn:c2pa:a'], ['parentOf', 'urn:c2pa:b']] }))
    expect(extractProof(photo.media, undefined, two)).toMatchObject({ kind: 'refused', c2pa: { notes: ['urn:c2pa:0 names more than one parentOf ingredient, so the chain stops there'] } })
    const missing = store(manifest({ label: 'urn:c2pa:0', ingredients: [['parentOf', 'urn:c2pa:gone']] }))
    expect(extractProof(photo.media, undefined, missing).c2pa?.notes).toEqual(['the parentOf ingredient of urn:c2pa:0 names no manifest in this store'])
  })

  it('does not decompress: a compressed active manifest is not evaluated', () => {
    const x = extractProof(photo.media, undefined, one({ label: 'urn:c2pa:z', proof, kind: 'c2cm' }))
    expect(x).toMatchObject({ kind: 'refused', c2pa: { active: { label: 'urn:c2pa:z' }, notes: ['urn:c2pa:z is a compressed manifest, not evaluated'] } })
  })

  it('reads an update manifest and a legacy one like a standard one', () => {
    for (const kind of ['c2um', 'c2md'] as const) {
      expect(extractProof(photo.media, undefined, one({ label: 'urn:c2pa:u', proof, kind })).kind).toBe('proof')
    }
  })
})

describe('what counts as the proof assertion', () => {
  it('reads a salted box (toggles 0x13)', () => {
    expect(extractProof(photo.media, undefined, one({ label: 'urn:c2pa:m', proof, salt: new Uint8Array(16).fill(7) })).kind).toBe('proof')
  })

  it('ignores `__n` instances', () => {
    const s = one({ label: 'urn:c2pa:m', extra: [[`${PROOF_LABEL}__1`, superbox('json', `${PROOF_LABEL}__1`, [box('json', proof)])]] })
    expect(extractProof(photo.media, undefined, s).kind).toBe('refused')
  })

  it('reads neither of two boxes under the exact label', () => {
    const s = one({ label: 'urn:c2pa:m', proof, extra: [[PROOF_LABEL, superbox('json', PROOF_LABEL, [box('json', enriched(proof))])]] })
    expect(extractProof(photo.media, undefined, s)).toMatchObject({ kind: 'refused', c2pa: { notes: [`urn:c2pa:m repeats the label ${PROOF_LABEL}, so neither copy is read`] } })
  })

  it('reads no assertion the claim does not list, and none from a manifest with no claim', () => {
    expect(extractProof(photo.media, undefined, one({ label: 'urn:c2pa:m', proof, listed: null })).c2pa?.notes).toEqual(['the proof assertion of urn:c2pa:m is not listed by its claim'])
    expect(extractProof(photo.media, undefined, one({ label: 'urn:c2pa:m', proof, noClaim: true })).c2pa?.notes).toEqual(['urn:c2pa:m has no claim this reader can decode'])
  })

  it('reads a CBOR box under the label as no proof', () => {
    const s = one({ label: 'urn:c2pa:m', extra: [[PROOF_LABEL, superbox('cbor', PROOF_LABEL, [box('cbor', Uint8Array.of(0xa0))])]] })
    expect(extractProof(photo.media, undefined, s).c2pa?.notes).toEqual([`the proof assertion of urn:c2pa:m is not a JSON box`])
  })

  it('counts a redaction as absence in both of §6.8\'s forms, and the chain goes on past it', () => {
    // Replaced by the redaction box, with a proof further up.
    const boxed = store(manifest({ label: 'urn:c2pa:2', proof }), manifest({ label: 'urn:c2pa:1', extra: [[PROOF_LABEL, redactedAssertion(PROOF_LABEL)]], ingredients: [['parentOf', 'urn:c2pa:2']] }),
      manifest({ label: 'urn:c2pa:0', ingredients: [['parentOf', 'urn:c2pa:1']] }))
    expect(extractProof(photo.media, undefined, boxed)).toMatchObject({ source: { depth: 2 }, c2pa: { notes: ['the proof assertion of urn:c2pa:1 is redacted'] } })
    // Named in a later claim's redacted_assertions.
    const listed = store(manifest({ label: 'urn:c2pa:1', proof }),
      manifest({ label: 'urn:c2pa:0', ingredients: [['parentOf', 'urn:c2pa:1']], redacts: [`self#jumbf=/c2pa/urn:c2pa:1/c2pa.assertions/${PROOF_LABEL}`] }))
    expect(extractProof(photo.media, undefined, listed)).toMatchObject({ kind: 'refused', c2pa: { notes: ['the proof assertion of urn:c2pa:1 is redacted'] } })
  })
})

describe('the verdict over a carried proof', () => {
  it('depth 0 reads like a sidecar: authentic, and no label for where the proof sat', async () => {
    const v = await verify(jpegWithStore(photo.media, one({ label: 'urn:c2pa:m', proof })))
    expect(v).toMatchObject({ outcome: 'authentic', labels: labels01, proof_source: { kind: 'c2pa', manifest: 'urn:c2pa:m', depth: 0 } })
  })

  it('depth 0 over bytes that are not the sealed ones is tampered', async () => {
    const v = await verify(jpegWithStore(edited, one({ label: 'urn:c2pa:m', proof })))
    expect(v).toMatchObject({ outcome: 'tampered', reason: 'media.hash does not match the canonical bytes' })
  })

  it('depth ≥ 1 over bytes that are not the sealed ones is no proof found, never tampered', async () => {
    const v = await verify(jpegWithStore(edited, chain(2, 1)))
    expect(v).toEqual({ outcome: 'no_proof_found', labels: [], not_evaluated: [], core_hash: toHex(await coreHashOf(JSON.parse(fromUtf8(proof)))), reason: SOURCE_CAPTURE, proof_source: { kind: 'c2pa', manifest: 'urn:c2pa:1', depth: 1 }, content_credentials: expect.objectContaining({ proof: { manifest: 'urn:c2pa:1', depth: 1, listed_as: 'gathered_assertions' } }) })
  })

  it('depth ≥ 1 over the sealed bytes is the verdict of those bytes', async () => {
    expect(await verify(jpegWithStore(photo.media, chain(3, 2)))).toMatchObject({ outcome: 'authentic', labels: labels01, proof_source: { depth: 2 } })
  })

  it('ISO-BMFF: a store sealed inside media.hash says so; one added after the seal is tampered', async () => {
    const heic = sealed('23-heic-sealed', 'input.heic')
    const media = bmffWithStore(heic.media, c2paUuidBox(one({ label: 'urn:c2pa:pre' })))
    const payload = await resealed(heic.payload, media)
    const v = await verify(concat(media, buildTrailer(payload, heic.flags, heic.minor)))
    expect(v).toMatchObject({ outcome: 'authentic', proof_source: { kind: 'trailer' }, content_credentials: { store: 'embedded', sealed_with_capture: true } })
    const after = await verify(bmffWithStore(heic.file, c2paUuidBox(one({ label: 'urn:c2pa:post' }))))
    expect(after.outcome).toBe('tampered')
    expect(after.content_credentials?.sealed_with_capture).toBeUndefined()
  })

  it('a JPEG store is outside media.hash, so it is never sealed with the capture', async () => {
    expect((await verify(jpegWithStore(photo.file, one({ label: 'urn:c2pa:m' })))).content_credentials?.sealed_with_capture).toBeUndefined()
  })

  it('a clip whose proof is its source\'s, and whose GOPs name that capture, is a verified clip', async () => {
    const cut = sealed('89-mp4-container-cut-clip', 'input.mp4')
    const v = await verify(bmffWithStore(cut.media, c2paUuidBox(chainOf(cut.payload)), 'end'))
    expect(v).toMatchObject({ outcome: 'verified_clip', segments: { verified: [1, 2] }, frames_name_capture: true, proof_source: { depth: 1 } })
  })

  it('a clip whose frames are another capture\'s is no proof found, and says the frames do not name it', async () => {
    const stolen = read('86-mp4-container-stolen-proof-sidecar', 'input.mp4.vcap')
    const file = bmffWithStore(read('86-mp4-container-stolen-proof-sidecar', 'input.mp4'), c2paUuidBox(chainOf(stolen)), 'end')
    expect(await verify(file)).toMatchObject({ outcome: 'no_proof_found', reason: SOURCE_CAPTURE, frames_name_capture: false, proof_source: { depth: 1 } })
    // At depth 0 the same proof reads as it does from a sidecar.
    const depth0 = bmffWithStore(read('86-mp4-container-stolen-proof-sidecar', 'input.mp4'), c2paUuidBox(one({ label: 'urn:c2pa:0', proof: stolen })), 'end')
    expect(await verify(depth0)).toMatchObject({ outcome: 'frames_not_compared', frames_name_capture: false, proof_source: { depth: 0 } })
  })

  it('never throws over a store with bytes flipped anywhere', async () => {
    const s = chain(3, 2)
    const file = jpegWithStore(photo.media, s)
    const start = file.length - photo.media.length + 2 - s.length
    for (let i = 0; i < 300; i++) {
      const bent = Uint8Array.from(file)
      const at = start + ((i * 7919) % s.length)
      bent[at] = (bent[at]! + 1 + i) & 0xff
      const v = await verify(bent)
      // The net under `verify` names what escaped it; nothing may reach it.
      expect(v.reason ?? '').not.toMatch(/could not be read/)
    }
  })
})

/** A two-manifest store whose active manifest names the one carrying `payload` as its parent. */
const chainOf = (payload: Uint8Array): Uint8Array => store(manifest({ label: 'urn:c2pa:1', proof: payload }), manifest({ label: 'urn:c2pa:0', ingredients: [['parentOf', 'urn:c2pa:1']] }))

/** A vector's proof re-signed by a new key over `media`: what a device sealing that file would have written. */
const resealed = async (payload: Uint8Array, media: Uint8Array): Promise<Uint8Array> => {
  const keys = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const spki = new Uint8Array(await subtle().exportKey('spki', keys.publicKey))
  const p = JSON.parse(fromUtf8(payload)) as Record<string, Record<string, Json>>
  p.media!.hash = toBase64url(await sha256(media))
  p.device!.key_id = toBase64url(await sha256(spki))
  const signature = new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, Uint8Array.from(jcs(extractCore(p as Record<string, Json>)))))
  p.sig = { alg: 'ES256', value: toBase64url(signature), pub: toBase64url(spki) }
  return jcs(p as unknown as Json)
}
