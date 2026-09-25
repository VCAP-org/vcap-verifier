import { concat, fromHex, u32be, utf8 } from '../src/bytes.js'
import { jumbfUuid, REDACTION_UUID } from '../src/jumbf.js'
import { PROOF_LABEL } from '../src/carrier.js'

/**
 * Synthetic C2PA manifest stores, built byte by byte in the test: the JUMBF
 * boxes, a CBOR claim, ingredients, and the two places a store is embedded
 * (JPEG APP11 packets, an ISO-BMFF `uuid` box). No C2PA tool is involved and
 * nothing is signed — the reader under test checks no signature, and a
 * builder that needed one would test the tool instead of the reader.
 * Uint8Array only, so the page's end-to-end tests can import it too.
 */
type Bytes = Uint8Array

export const box = (type: string, ...parts: Bytes[]): Bytes => {
  const body = concat(...parts)
  return concat(u32be(8 + body.length), utf8(type), body)
}

/** A `jumb` superbox: description box (toggles 0x03, or 0x13 with a `c2sh` salt), then children. */
export const superbox = (fourcc: string, label: string, children: Bytes[], salt?: Bytes): Bytes => box('jumb',
  box('jumd', fromHex(jumbfUuid(fourcc)), Uint8Array.of(salt ? 0x13 : 0x03), utf8(label), Uint8Array.of(0), ...(salt ? [box('c2sh', salt)] : [])),
  ...children)

type CborIn = number | string | boolean | null | Bytes | CborIn[] | { [k: string]: CborIn }
const head = (major: number, n: number): Bytes => n < 24 ? Uint8Array.of((major << 5) | n)
  : n < 256 ? Uint8Array.of((major << 5) | 24, n)
    : n < 65536 ? Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff)
      : concat(Uint8Array.of((major << 5) | 26), u32be(n))
/** Definite-length CBOR of the subset the reader decodes. */
export const cbor = (v: CborIn): Bytes => {
  if (v === null) return Uint8Array.of(0xf6)
  if (v === true || v === false) return Uint8Array.of(v ? 0xf5 : 0xf4)
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v)
  if (typeof v === 'string') { const b = utf8(v); return concat(head(3, b.length), b) }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v)
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(cbor))
  const keys = Object.keys(v)
  return concat(head(5, keys.length), ...keys.flatMap((k) => [cbor(k), cbor(v[k] as CborIn)]))
}

const hashed = (url: string): CborIn => ({ url, alg: 'sha256', hash: new Uint8Array(32) })
export const assertionUrl = (label: string): string => `self#jumbf=c2pa.assertions/${label}`
export const manifestUrl = (manifest: string): string => `self#jumbf=/c2pa/${manifest}`

export const jsonAssertion = (label: string, json: Bytes, salt?: Bytes): Bytes => superbox('json', label, [box('json', json)], salt)
export const cborAssertion = (label: string, value: CborIn): Bytes => superbox('cbor', label, [box('cbor', cbor(value))])
/** C2PA 2.4 §6.8, second form: the labelled box kept, its content one `uuid` box with the redaction ID and zeros. */
export const redactedAssertion = (label: string): Bytes => superbox('json', label, [box('uuid', REDACTION_UUID, new Uint8Array(32))])
export const ingredient = (relationship: string, manifest: string, version: 1 | 2 | 3 = 3): CborIn => version === 3
  ? { 'dc:title': 'source', relationship, activeManifest: hashed(manifestUrl(manifest)) }
  : { 'dc:title': 'source', relationship, c2pa_manifest: hashed(manifestUrl(manifest)) }

export interface ManifestSpec {
  label: string
  /** The proof JSON, carried as `io.github.vcap-org.vcap.proof`. */
  proof?: Bytes
  /** Where the claim lists the proof; `null` leaves it unlisted. v1 claims have one list. */
  listed?: 'created_assertions' | 'gathered_assertions' | null
  claimVersion?: 1 | 2
  salt?: Bytes
  /** Ingredients: `[relationship, manifest label]`, in `c2pa.ingredient.v3` unless `ingredientVersion` says otherwise. */
  ingredients?: Array<[string, string]>
  ingredientVersion?: 1 | 2 | 3
  /** Assertions of other manifests this claim redacts (§6.8, first form), as absolute URIs. */
  redacts?: string[]
  /** Boxes to put in the assertion store as they are, listed by the claim under their label. */
  extra?: Array<[string, Bytes]>
  kind?: 'c2ma' | 'c2um' | 'c2md' | 'c2cm'
  generator?: string
  /** Skip the claim box. */
  noClaim?: boolean
}

export const manifest = (m: ManifestSpec): Bytes => {
  const assertions: Array<[string, Bytes]> = []
  if (m.proof) assertions.push([PROOF_LABEL, jsonAssertion(PROOF_LABEL, m.proof, m.salt)])
  for (const [i, [relationship, target]] of (m.ingredients ?? []).entries()) {
    const label = `c2pa.ingredient${m.ingredientVersion === 1 ? '' : `.v${m.ingredientVersion ?? 3}`}${i === 0 ? '' : `__${i}`}`
    assertions.push([label, cborAssertion(label, ingredient(relationship, target, m.ingredientVersion ?? 3))])
  }
  assertions.push(...(m.extra ?? []))
  const version = m.claimVersion ?? 2
  const listedAs = (label: string): string | null => label === PROOF_LABEL ? (m.listed === undefined ? 'gathered_assertions' : m.listed) : 'created_assertions'
  const refs = (field: string): CborIn[] => assertions.filter(([label]) => listedAs(label) !== null && (version === 1 || listedAs(label) === field)).map(([label]) => hashed(assertionUrl(label)))
  const body: Record<string, CborIn> = version === 2
    ? { instanceID: `xmp:iid:${m.label}`, claim_generator_info: { name: m.generator ?? 'test-generator', version: '1.0' }, signature: `self#jumbf=/c2pa/${m.label}/c2pa.signature`, created_assertions: refs('created_assertions'), gathered_assertions: refs('gathered_assertions'), alg: 'sha256' }
    : { claim_generator: m.generator ?? 'test-generator/1.0', signature: `self#jumbf=/c2pa/${m.label}/c2pa.signature`, assertions: refs('assertions'), 'dc:format': 'image/jpeg', instanceID: `xmp:iid:${m.label}` }
  if (m.redacts) body.redacted_assertions = m.redacts
  return superbox(m.kind ?? 'c2ma', m.label, [
    superbox('c2as', 'c2pa.assertions', assertions.map(([, b]) => b)),
    ...(m.noClaim ? [] : [superbox('c2cl', version === 2 ? 'c2pa.claim.v2' : 'c2pa.claim', [box('cbor', cbor(body))])]),
    superbox('c2cs', 'c2pa.signature', [box('cbor', cbor(null))])
  ])
}

/** A manifest store; the last manifest is the active one. */
export const store = (...manifests: Bytes[]): Bytes => superbox('c2pa', 'c2pa', manifests)

/**
 * The store as APP11 packets right after SOI: CI 'JP', En, Z from 1, each
 * packet after the first repeating the box header (Annex A.3.1).
 */
export const jpegWithStore = (jpeg: Bytes, jumbf: Bytes, o: { en?: number, packet?: number, reorder?: boolean } = {}): Bytes => {
  const packet = o.packet ?? 60_000
  const header = jumbf.subarray(0, 8)
  const pieces: Bytes[] = []
  for (let at = 0, z = 1; at < jumbf.length || z === 1; z++) {
    const share = z === 1 ? jumbf.subarray(0, packet) : concat(header, jumbf.subarray(at, at + packet))
    at += z === 1 ? share.length : share.length - 8
    const payload = concat(utf8('JP'), Uint8Array.of((o.en ?? 1) >> 8, (o.en ?? 1) & 0xff), u32be(z), share)
    pieces.push(concat(Uint8Array.of(0xff, 0xeb, (payload.length + 2) >> 8, (payload.length + 2) & 0xff), payload))
  }
  if (o.reorder) pieces.reverse()
  return concat(jpeg.subarray(0, 2), ...pieces, jpeg.subarray(2))
}

const BMFF_UUID = fromHex('d8fec3d61b0e483c92975828877ec481')
/** The C2PA `uuid` box (Annex A.5): FullBox, purpose, 8-byte merkle offset, store. */
export const c2paUuidBox = (jumbf: Bytes, purpose = 'manifest'): Bytes =>
  box('uuid', BMFF_UUID, new Uint8Array(4), utf8(purpose), Uint8Array.of(0), ...(purpose === 'merkle' ? [] : [new Uint8Array(8)]), jumbf)

/** The box after `ftyp` (where C2PA puts it), or appended at the end, where it moves no sample offset. */
export const bmffWithStore = (file: Bytes, uuidBox: Bytes, where: 'after-ftyp' | 'end' = 'after-ftyp'): Bytes => {
  if (where === 'end') return concat(file, uuidBox)
  const ftyp = (file[0]! << 24 | file[1]! << 16 | file[2]! << 8 | file[3]!) >>> 0
  return concat(file.subarray(0, ftyp), uuidBox, file.subarray(ftyp))
}
