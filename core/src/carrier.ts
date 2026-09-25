import { type Bytes, concat, equal, fromHex, fromUtf8, readU16BE, readU32BE, toHex } from './bytes.js'
import { jcs, jsonProblem, type Json } from './jcs.js'
import { parseTrailer } from './trailer.js'
import { detectContainer, isJumbfSegment, jpegSegments } from './canonical.js'
import { boxes } from './container.js'
import { type CborMap, decodeCbor } from './cbor.js'
import { CBOR_BOX, JSON_BOX, type Superbox, contentOf, isRedacted, jumbfUuid, parseJumbf, superboxes } from './jumbf.js'

/**
 * Where the proof is, before anything about it is believed: the trailer (§3),
 * a C2PA manifest store that carries it as the assertion
 * `io.github.vcap-org.vcap.proof` (`c2pa-interop` §2.1), or the sidecar
 * (§3.1). No COSE, no X.509, no hashed URI is checked here or anywhere in the
 * core: the proof authenticates itself, and what the store adds is a place to
 * find it and a `parentOf` chain to follow. Nothing C2PA says about itself
 * reaches the outcome, a label or the ceiling.
 *
 * The store is found in the file — JPEG APP11 'JP' packets reassembled by En
 * and Z, or a top-level ISO-BMFF `uuid` box of the C2PA type — or, when the
 * file embeds none, in the `.c2pa` bytes the caller hands over. Never fetched:
 * the verification path resolves nothing over a network.
 */
export const PROOF_LABEL = 'io.github.vcap-org.vcap.proof'
/** How far up the `parentOf` chain the proof of a source capture is looked for. */
export const MAX_CHAIN_DEPTH = 16

/** Diagnostic, never a label: where a proof sits is not evidence (§3.1). */
export type ProofSource =
  | { kind: 'trailer' }
  | { kind: 'sidecar' }
  | { kind: 'c2pa', manifest: string, depth: number }

/** What the manifest store held, for a surface to show beside the verdict and never inside it. */
export interface ContentCredentials {
  store: 'embedded' | 'external'
  /** Why the store yields nothing this reader can use; absent when it was read. */
  unread?: string
  manifests?: number
  /** The active manifest (the store's last) and its claim generator, as the claim names itself. */
  active?: { label: string, generator?: string }
  /** The proof assertion the search reached, nearest the active manifest, and the claim list naming it. */
  proof?: { manifest: string, depth: number, listed_as: string }
  /** What the search stepped over, in words: a redaction, a compressed manifest, an ambiguous parent, a cycle. */
  notes: string[]
  /** ISO-BMFF only: the store box is inside the canonical bytes and `media.hash` matched them. Set by `verify`. */
  sealed_with_capture?: boolean
}

export type Extraction =
  | { kind: 'proof', payload: Bytes, media: Bytes, flags: number | null, source: ProofSource, labels: string[], c2pa?: ContentCredentials }
  | { kind: 'refused', outcome: 'no_proof_found' | 'corrupted_proof' | 'unsupported_format_version' | 'nested_proof', reason: string, c2pa?: ContentCredentials }

const STORE = jumbfUuid('c2pa')
const ASSERTIONS = jumbfUuid('c2as')
const CLAIM = jumbfUuid('c2cl')
// C2PA 2.4 §11.2.2: standard, update and the legacy `c2md` are read; a
// compressed manifest is not decompressed here and is *not evaluated*.
const KINDS: Record<string, 'standard' | 'update' | 'legacy' | 'compressed'> = {
  [jumbfUuid('c2ma')]: 'standard', [jumbfUuid('c2um')]: 'update', [jumbfUuid('c2md')]: 'legacy', [jumbfUuid('c2cm')]: 'compressed'
}
const BMFF_STORE = fromHex('d8fec3d61b0e483c92975828877ec481')
const BMFF_PURPOSES = new Set(['manifest', 'original', 'update'])
const INGREDIENT = /^c2pa\.ingredient(\.v[23])?(__\d+)?$/

interface Manifest { label: string, kind: string, box: Superbox }
interface Claim { listed: Map<string, string>, generator?: string, redacted: string[] }
type Found = { store: Bytes } | { error: string }

const isMap = (v: unknown): v is CborMap => v instanceof Map

/** Every C2PA store embedded in the file; a structure that cannot be walked embeds none. */
const embedded = (file: Bytes): Found[] => {
  try {
    const container = detectContainer(file)
    return container === 'jpeg' ? jpegStores(file) : container === 'bmff' ? bmffStores(file) : []
  } catch { return [] }
}

// Annex A.3.1 over ISO 19566-5: CI 'JP', En (u16), Z (u32), then the box.
// Every packet after the first repeats the box header before its share of
// the body. A JUMBF that is not a C2PA store (JPEG 360, privacy) is not ours.
const jpegStores = (file: Bytes): Found[] => {
  const byInstance = new Map<number, Array<{ z: number, data: Bytes }>>()
  for (const s of jpegSegments(file).segments) {
    if (!isJumbfSegment(s) || s.bytes.length < 12) continue
    const en = readU16BE(s.bytes, 6)
    const packets = byInstance.get(en) ?? []
    if (packets.length === 0) byInstance.set(en, packets)
    packets.push({ z: readU32BE(s.bytes, 8), data: s.bytes.subarray(12) })
  }
  const found: Found[] = []
  for (const packets of byInstance.values()) {
    packets.sort((a, b) => a.z - b.z)
    const first = packets[0]!.data
    const head = first.length >= 4 && readU32BE(first, 0) === 1 ? 16 : 8
    const isStore = first.length >= head + 24 && fourcc(first, 4) === 'jumb' && fourcc(first, head + 4) === 'jumd' && toHex(first.subarray(head + 8, head + 24)) === STORE
    if (!isStore) continue
    if (packets.some((p, i) => p.z !== i + 1)) { found.push({ error: 'its APP11 packets are not numbered 1 to n' }); continue }
    const rest = packets.slice(1).map((p) => p.data)
    if (rest.some((d) => d.length < head || !equal(d.subarray(0, head), first.subarray(0, head)))) { found.push({ error: 'an APP11 packet does not repeat the box header' }); continue }
    found.push({ store: concat(first, ...rest.map((d) => d.subarray(head))) })
  }
  return found
}

// Annex A.5: a top-level `uuid` box of the C2PA type is a FullBox, then a
// NUL-terminated purpose, then for a store the 8-byte merkle offset, then the
// store. Other purposes (`merkle`) are auxiliary and hold no store.
const bmffStores = (file: Bytes): Found[] => {
  const found: Found[] = []
  for (const box of boxes(file, 0, file.length)) {
    if (box.type !== 'uuid' || box.end - box.body < 20 || !equal(file.subarray(box.body, box.body + 16), BMFF_STORE)) continue
    const from = box.body + 20
    const nul = file.subarray(from, Math.min(box.end, from + 64)).indexOf(0)
    if (nul === -1) { found.push({ error: 'its box names no purpose' }); continue }
    if (!BMFF_PURPOSES.has(String.fromCharCode(...file.subarray(from, from + nul)))) continue
    const at = from + nul + 1 + 8
    found.push(at > box.end ? { error: 'its box ends inside the merkle offset' } : { store: file.subarray(at, box.end) })
  }
  return found
}

const fourcc = (b: Bytes, at: number): string => String.fromCharCode(b[at]!, b[at + 1]!, b[at + 2]!, b[at + 3]!)

const readStore = (bytes: Bytes): Manifest[] => {
  const root = parseJumbf(bytes)
  if (root.type !== STORE) throw new Error('the JUMBF box is not a C2PA manifest store')
  const manifests: Manifest[] = []
  for (const box of superboxes(root)) {
    const kind = KINDS[box.type]
    if (kind === undefined) continue
    if (box.label === null) throw new Error('a manifest has no label')
    // A reference by label that could land on either of two boxes is a store two readers read two ways.
    if (manifests.some((m) => m.label === box.label)) throw new Error(`the store repeats the manifest label ${box.label}`)
    manifests.push({ label: box.label, kind, box })
  }
  if (manifests.length === 0) throw new Error('the store holds no manifest')
  return manifests
}

/** A JUMBF URI (`self#jumbf=…`, §8.1) as the manifest it points into and the path below it. */
const resolve = (url: string, current: string): { manifest: string, path: string[] } | null => {
  if (!url.startsWith('self#jumbf=')) return null
  const parts = url.slice('self#jumbf='.length).split('/')
  if (parts[0] === '') parts.shift()
  if (parts[0] !== 'c2pa') return { manifest: current, path: parts.filter(Boolean) }
  return parts[1] ? { manifest: parts[1], path: parts.slice(2).filter(Boolean) } : null
}

const readClaim = (m: Manifest): Claim | null => {
  const box = superboxes(m.box).find((b) => b.type === CLAIM)
  const data = box && contentOf(box, 'cbor')
  if (!data) return null
  let claim
  try { claim = decodeCbor(data) } catch { return null }
  if (!isMap(claim)) return null
  // Which assertions the claim lists, and in which list: v2 separates what the
  // signer made (`created_assertions`) from what it carried (`gathered_assertions`, §10.2.2).
  const listed = new Map<string, string>()
  for (const field of ['created_assertions', 'gathered_assertions', 'assertions']) {
    const list = claim.get(field)
    for (const ref of Array.isArray(list) ? list : []) {
      const url = isMap(ref) ? ref.get('url') : undefined
      const to = typeof url === 'string' ? resolve(url, m.label) : null
      if (to?.manifest === m.label && to.path.length === 2 && to.path[0] === 'c2pa.assertions' && !listed.has(to.path[1]!)) listed.set(to.path[1]!, field)
    }
  }
  const info = claim.get('claim_generator_info')
  const named = isMap(info) ? info : Array.isArray(info) && isMap(info[0]) ? info[0] : null
  const name = named?.get('name')
  const version = named?.get('version')
  const legacy = claim.get('claim_generator')
  const generator = typeof name === 'string' ? `${name}${typeof version === 'string' ? ` ${version}` : ''}` : typeof legacy === 'string' ? legacy : undefined
  const redacted = claim.get('redacted_assertions')
  return { listed, ...(generator ? { generator } : {}), redacted: Array.isArray(redacted) ? redacted.filter((r): r is string => typeof r === 'string') : [] }
}

/** One read of one store: its manifests, their claims decoded once, what the search noted. */
const session = (manifests: Manifest[], cc: ContentCredentials) => {
  const claims = new Map<string, Claim | null>()
  const claimOf = (m: Manifest): Claim | null => {
    if (!claims.has(m.label)) claims.set(m.label, readClaim(m))
    return claims.get(m.label) ?? null
  }
  const note = (text: string): void => { if (!cc.notes.includes(text)) cc.notes.push(text) }
  // §6.8's first form: removed and named in a later claim's `redacted_assertions`.
  let redactions: Set<string> | null = null
  const isListedRedacted = (manifest: string, label: string): boolean => {
    redactions ??= new Set(manifests.flatMap((m) => (claimOf(m)?.redacted ?? []).map((url) => resolve(url, m.label))
      .filter((to) => to !== null && to.path.length === 2 && to.path[0] === 'c2pa.assertions').map((to) => `${to!.manifest}/${to!.path[1]}`)))
    return redactions.has(`${manifest}/${label}`)
  }
  const assertionsOf = (m: Manifest): Superbox[] => {
    const store = superboxes(m.box).find((b) => b.type === ASSERTIONS)
    return store ? superboxes(store) : []
  }

  /** The proof assertion of one manifest: exactly one box under the exact label (`__n` instances are ignored). */
  const proofIn = (m: Manifest, claim: Claim): { payload: Bytes, listed_as: string } | null => {
    const copies = assertionsOf(m).filter((b) => b.label === PROOF_LABEL)
    if (copies.length === 0) return null
    const box = copies[0]!
    if (copies.length > 1) note(`${m.label} repeats the label ${PROOF_LABEL}, so neither copy is read`)
    else if (isRedacted(box) || isListedRedacted(m.label, PROOF_LABEL)) note(`the proof assertion of ${m.label} is redacted`)
    else if (!claim.listed.has(PROOF_LABEL)) note(`the proof assertion of ${m.label} is not listed by its claim`)
    else if (box.type !== JSON_BOX || !contentOf(box, 'json')) note(`the proof assertion of ${m.label} is not a JSON box`)
    else return { payload: contentOf(box, 'json') as Bytes, listed_as: claim.listed.get(PROOF_LABEL) as string }
    return null
  }

  /** The one `parentOf` ingredient's manifest. `componentOf` and `inputTo` are never followed. */
  const parentOf = (m: Manifest, claim: Claim): Manifest | null => {
    const targets: Array<ReturnType<typeof resolve>> = []
    for (const box of assertionsOf(m)) {
      if (box.label === null || !INGREDIENT.test(box.label) || !claim.listed.has(box.label) || box.type !== CBOR_BOX || isRedacted(box)) continue
      let ingredient
      try { ingredient = decodeCbor(contentOf(box, 'cbor') ?? new Uint8Array()) } catch { note(`an ingredient of ${m.label} cannot be read`); continue }
      if (!isMap(ingredient) || ingredient.get('relationship') !== 'parentOf') continue
      const ref = ingredient.get('activeManifest') ?? ingredient.get('c2pa_manifest')
      const url = isMap(ref) ? ref.get('url') : undefined
      targets.push(typeof url === 'string' ? resolve(url, m.label) : null)
    }
    if (targets.length === 0) return null
    if (targets.length > 1) { note(`${m.label} names more than one parentOf ingredient, so the chain stops there`); return null }
    const to = targets[0]
    const parent = to && to.path.length === 0 ? manifests.find((x) => x.label === to.manifest) : undefined
    if (!parent) note(`the parentOf ingredient of ${m.label} names no manifest in this store`)
    return parent ?? null
  }

  /** The nearest proof between depths `from` and `to` of the chain that starts at the active manifest. */
  const search = (from: number, to: number): { payload: Bytes, manifest: string, depth: number } | null => {
    let m = manifests.at(-1) as Manifest
    const visited = new Set([m.label])
    for (let depth = 0; ; depth++) {
      if (m.kind === 'compressed') { note(`${m.label} is a compressed manifest, not evaluated`); return null }
      const claim = claimOf(m)
      if (!claim) { note(`${m.label} has no claim this reader can decode`); return null }
      const found = depth >= from ? proofIn(m, claim) : null
      if (found) {
        cc.proof = { manifest: m.label, depth, listed_as: found.listed_as }
        return { payload: found.payload, manifest: m.label, depth }
      }
      const parent = depth < to ? parentOf(m, claim) : null
      if (!parent) return null
      if (visited.has(parent.label)) { note(`the parentOf chain returns to ${parent.label}, and stops`); return null }
      visited.add(parent.label)
      m = parent
    }
  }
  return { search, claimOf }
}

/** The store this file is read with, and what it held; null when there is none at all. */
const credentials = (file: Bytes, external?: Bytes): { cc: ContentCredentials, search?: ReturnType<typeof session>['search'] } | null => {
  const found = embedded(file)
  const store = found.length > 0 ? 'embedded' : external !== undefined ? 'external' : null
  if (store === null) return null
  const cc: ContentCredentials = { store, notes: [] }
  // C2PA §15.5.2.1: more than one embedded store is no store at all.
  if (found.length > 1) return { cc: { ...cc, unread: 'more than one C2PA manifest store is embedded' } }
  const one = found[0] ?? { store: external as Bytes }
  if ('error' in one) return { cc: { ...cc, unread: `the manifest store cannot be read: ${one.error}` } }
  let manifests: Manifest[]
  try { manifests = readStore(one.store) } catch (error) {
    return { cc: { ...cc, unread: `the manifest store cannot be read: ${error instanceof Error ? error.message : String(error)}` } }
  }
  const s = session(manifests, cc)
  const active = manifests.at(-1) as Manifest
  const generator = active.kind === 'compressed' ? undefined : s.claimOf(active)?.generator
  cc.manifests = manifests.length
  cc.active = { label: active.label, ...(generator ? { generator } : {}) }
  return { cc, search: s.search }
}

/**
 * Two copies of one proof are the same proof when `JCS(parse(a)) == JCS(parse(b))`:
 * a C2PA writer re-serializes the JSON it is given, so bytes are the wrong
 * test between a manifest copy and anything else. A copy that is not a proof
 * this format reads (§6.1) is not the same proof.
 */
const sameProof = (a: Bytes, b: Bytes): boolean => {
  try {
    const [x, y] = [a, b].map((p) => {
      if (p[0] === 0xef && p[1] === 0xbb && p[2] === 0xbf) throw new Error('byte-order mark')
      const text = fromUtf8(p)
      const value = JSON.parse(text) as Json
      if (jsonProblem(text) !== null) throw new Error('not one reading')
      return jcs(value)
    })
    return equal(x as Bytes, y as Bytes)
  } catch { return false }
}

/**
 * vcap-proof §3.1's precedence, with the manifest store in it:
 *
 * 1. a valid footer whose CRC matches — the trailer is the proof. A sidecar
 *    that differs byte for byte is *sidecar differs*; a copy in the active
 *    manifest that differs as JCS is *manifest copy differs*;
 * 2. a valid footer whose CRC fails — *corrupted proof*, whatever the store holds;
 * 3. `VCAP` with another major — *unsupported format version*;
 * 4. no footer — the active manifest's proof (depth 0, compared as JCS with a
 *    sidecar), then the sidecar, then the nearest proof up the `parentOf`
 *    chain (depth 1–16, no manifest twice).
 */
export const extractProof = (file: Bytes, sidecar?: Bytes, externalStore?: Bytes): Extraction => {
  const trailer = parseTrailer(file)
  const store = credentials(file, externalStore)
  const c2pa = store ? { c2pa: store.cc } : {}
  const refused = (outcome: Extract<Extraction, { kind: 'refused' }>['outcome'], reason: string): Extraction => ({ kind: 'refused', outcome, reason, ...c2pa })
  if (trailer.kind === 'corrupted') return refused('corrupted_proof', 'footer valid, CRC mismatch')
  if (trailer.kind === 'unsupported') return refused('unsupported_format_version', `footer major ${trailer.major}`)
  const active = store?.search?.(0, 0) ?? null
  if (trailer.kind === 'ok') {
    if (parseTrailer(trailer.media).kind !== 'none') return refused('nested_proof', 'the canonical bytes end in another trailer')
    const labels = [
      ...(sidecar && !equal(sidecar, trailer.payload) ? ['sidecar differs'] : []),
      ...(active && !sameProof(active.payload, trailer.payload) ? ['manifest copy differs'] : [])
    ]
    return { kind: 'proof', payload: trailer.payload, media: trailer.media, flags: trailer.flags, source: { kind: 'trailer' }, labels, ...c2pa }
  }
  const carried = (found: { payload: Bytes, manifest: string, depth: number }, labels: string[]): Extraction =>
    ({ kind: 'proof', payload: found.payload, media: file, flags: null, source: { kind: 'c2pa', manifest: found.manifest, depth: found.depth }, labels, ...c2pa })
  if (active) return carried(active, sidecar && !sameProof(sidecar, active.payload) ? ['sidecar differs'] : [])
  if (sidecar) return { kind: 'proof', payload: sidecar, media: file, flags: null, source: { kind: 'sidecar' }, labels: [], ...c2pa }
  const ancestor = store?.search?.(1, MAX_CHAIN_DEPTH) ?? null
  if (ancestor) return carried(ancestor, [])
  return refused('no_proof_found', 'no trailer and no sidecar')
}
