import { type Bytes, equal, fromBase64, fromUtf8, toBase64url, toHex } from './bytes.js'
import { sha256 } from './sha.js'
import { jcs, type Json } from './jcs.js'
import { parseTrailer } from './trailer.js'
import { canonicalBytes, detectContainer } from './canonical.js'
import { recomputeSegments } from './container.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import { type SegmentEntry, verifyChain } from './segments.js'
import { type RegistryAttachment, type TrustedLog, verifyRegistry } from './registry.js'
import { type AnchorAttachment, type ChainReader, verifyAnchor } from './anchor.js'
import { validateTimestamp } from './rfc3161.js'
import { type Certificate, parseCertificate } from './x509.js'
import { type RevocationLookup, validateAndroidAttestation } from './attestation/android.js'

/**
 * The verdict of the signature layer of vcap/1.0, from bytes to words. This
 * is the implementation the browser page, the platform API and the libraries
 * share; the conformance vectors of vcap-spec are its acceptance test. It
 * never contacts a server of ours: what it cannot check offline it labels.
 *
 * Outcome vocabulary and labels are the spec's (§8), verbatim.
 */
export type Outcome = 'no_proof_found' | 'corrupted_proof' | 'nested_proof' | 'unsupported_format_version' | 'tampered' | 'verified_clip' | 'authentic'

export interface Verdict {
  outcome: Outcome
  labels: string[]
  not_evaluated: string[]
  core_hash?: string
  segments?: { verified: number[], contradicted?: number[] }
  // §5 recomputation: whether the segment hashes were read back from the
  // container, and why not when they were not.
  content?: { recomputed: boolean, detail: string }
  reason?: string
  // What the attachments proved, when present and evaluated.
  registry?: { ok: boolean, detail: string, secure_hw?: string }
  anchor?: { ok: boolean, detail: string, on_chain?: boolean }
  timestamp?: { ok: boolean, detail: string, gen_time?: string }
  attestation?: { proven: string, detail: string, boot_state?: { locked: boolean, state: string } }
  // §7: claimed by the device, proven by the evidence, and the ceiling the two allow.
  level?: { claimed: string, proven: string, ceiling: 'green' | 'amber' | 'red' }
  claimed_secure_hw?: string
  device_clock?: number
}

export interface VerifyOptions {
  sidecar?: Bytes
  trustedLogs?: TrustedLog[]
  readChain?: ChainReader
  // TSA roots (DER) the timestamp attachment may chain to; none → not evaluated.
  tsaRoots?: Bytes[]
  // §5 recomputation from the container, on by default: a verifier holding the
  // file and trusting the proof's own hashes has checked that somebody signed
  // some hashes, not that these are the frames. Off for a caller that has only
  // a sidecar, or no demuxable container.
  recomputeSegments?: boolean
  // Google's attestation roots are pinned; override for tests only.
  googleRoots?: Certificate[]
  // Google's status list, when online; absent → *revocation not checked*.
  revocation?: RevocationLookup
  now?: Date
}

const CORE_KEYS = ['v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy'] as const
const KNOWN = new Set([...CORE_KEYS, 'sig', 'segments', 'attestation', 'registry', 'timestamp', 'anchor', 'integrity'])
const ABSENT: [string, string][] = [
  ['timestamp', 'no trusted time'], ['anchor', 'not anchored'], ['registry', 'key not in transparency log'],
  ['attestation', 'origin not hardware-attested'], ['integrity', 'integrity unevaluated'], ['watermark', 'no watermark']
]
const PLATFORMS = new Set(['android', 'ios', 'web'])
const SECURE_HW = new Set(['strongbox', 'tee', 'secureEnclave', 'none'])

type Obj = { [key: string]: Json }
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)
const hasFloat = (v: Json): boolean => typeof v === 'number' ? !Number.isInteger(v) : Array.isArray(v) ? v.some(hasFloat) : isObj(v) ? Object.values(v).some(hasFloat) : false
const b64Len = (s: unknown, n: number): boolean => { try { return typeof s === 'string' && /^[A-Za-z0-9_-]+$/.test(s) && fromBase64(s).length === n } catch { return false } }

const fail = (outcome: Outcome, reason: string): Verdict => ({ outcome, labels: [], not_evaluated: [], reason })

export const extractCore = (proof: Obj): Obj => {
  const core: Obj = {}
  for (const k of CORE_KEYS) if (k in proof) core[k] = proof[k] as Json
  return core
}

export const coreHashOf = (proof: Obj): Promise<Bytes> => sha256(jcs(extractCore(proof)))

const shapeProblem = (proof: Obj): string | null => {
  if (!b64Len(proof.capture_id, 16)) return 'capture_id missing or not 16 bytes'
  if (!isObj(proof.media) || typeof proof.media.hash !== 'string' || typeof proof.media.mime !== 'string') return 'media.hash or media.mime missing'
  // Shape only: any string passes here. §9 makes the format additive, so a
  // platform or secure_hw v1.0 does not define is a later version's value, not
  // a broken proof — refusing it would turn a valid signature over readable
  // bytes into *no proof found*. Unknown values are read as `none` below.
  if (!isObj(proof.device) || typeof proof.device.platform !== 'string' || typeof proof.device.secure_hw !== 'string' || typeof proof.device.key_id !== 'string') return 'device incomplete'
  if (!isObj(proof.sig) || typeof proof.sig.value !== 'string' || typeof proof.sig.pub !== 'string' || typeof proof.sig.alg !== 'string') return 'sig incomplete'
  if ('segments' in proof && (!Array.isArray(proof.segments) || !Number.isInteger((proof.media as Obj).segment_count))) return 'segments without media.segment_count'
  // §8: media.mime alone decides that a proof is a video proof, and a video
  // proof needs its segments — the container and duration_ms decide nothing.
  if ((proof.media.mime as string).startsWith('video/') && !('segments' in proof && Number.isInteger((proof.media as Obj).segment_count))) return 'video proof without segments'
  if (hasFloat(extractCore(proof))) return 'floating-point number in the core'
  return null
}

export const verify = async (file: Bytes, o: VerifyOptions = {}): Promise<Verdict> => {
  // 1. Trailer, sidecar, nesting (§3).
  const trailer = parseTrailer(file)
  if (trailer.kind === 'corrupted') return fail('corrupted_proof', 'footer valid, CRC mismatch')
  const labels: string[] = []
  let payload: Bytes, media: Bytes, flags: number | null = null
  if (trailer.kind === 'ok') {
    payload = trailer.payload; media = trailer.media; flags = trailer.flags
    if (parseTrailer(media).kind !== 'none') return fail('nested_proof', 'the canonical bytes end in another trailer')
    if (o.sidecar && !equal(o.sidecar, payload)) labels.push('sidecar differs')
  } else if (o.sidecar) {
    payload = o.sidecar; media = file
  } else {
    return fail('no_proof_found', 'no trailer and no sidecar')
  }

  // 2. JSON and version (§9).
  let proof: Obj
  try {
    const parsed: unknown = JSON.parse(fromUtf8(payload))
    if (!isObj(parsed)) throw new Error('not an object')
    proof = parsed
  } catch { return fail('no_proof_found', 'payload is not a JSON object') }
  const version = typeof proof.v === 'string' ? /^vcap\/(\d+)\.(\d+)$/.exec(proof.v) : null
  if (!version) return fail('no_proof_found', 'v missing or malformed')
  if (version[1] !== '1') return fail('unsupported_format_version', `major ${version[1]}`)
  const notEvaluated = Object.keys(proof).filter((k) => !KNOWN.has(k)).sort()

  // 3. Shape (§6.1, §8).
  const problem = shapeProblem(proof)
  if (problem) return fail('no_proof_found', problem)

  // 4. Core signature and key binding (§4.2, §6.1).
  const sig = proof.sig as { alg: string, value: string, pub: string }
  const core = jcs(extractCore(proof))
  const coreHash = await sha256(core)
  const hash = toHex(coreHash)
  const tampered = (reason: string): Verdict => ({ outcome: 'tampered', labels: [], not_evaluated: notEvaluated, core_hash: hash, reason })
  if (sig.alg !== 'ES256') return tampered('sig.alg is not ES256')
  let spki: Bytes, signature: Bytes
  try { spki = fromBase64(sig.pub); signature = fromBase64(sig.value) } catch { return tampered('sig fields are not base64url') }
  const key = await importP256Spki(spki)
  if (!key) return tampered('sig.pub is not an EC P-256 SubjectPublicKeyInfo')
  if (signature.length !== 64) return tampered('sig.value is not a 64-byte P1363 signature')
  if (!await verifyEs256(key, core, signature)) return tampered('core signature invalid')
  const device = proof.device as Obj
  if (device.key_id !== toBase64url(await sha256(spki))) return tampered('device.key_id is not SHA-256 of sig.pub')

  // 5. Media (§4.1), segments (§5), labels (§8).
  const mediaObj = proof.media as { hash: string, segment_count?: number }
  const mediaMatches = toBase64url(await sha256(canonicalBytes(media))) === mediaObj.hash
  for (const [k, label] of ABSENT) if (!(k in proof)) labels.push(label)
  // §7: a declared watermark is the writer saying a mark was embedded, not a
  // promise a reader finds it. This core carries no detector, so the honest
  // outcome is *watermark not evaluated* — silence would read as a match.
  if ('watermark' in proof) labels.push('watermark not evaluated')
  if (flags !== null) {
    const expected = ('segments' in proof ? 2 : 0) | ((isObj(proof.policy) && proof.policy.pseudonymous === true) ? 4 : 0)
    if ((flags & 6) !== expected) labels.push('flags disagree')
  }
  const verdict: Verdict = { outcome: 'authentic', labels, not_evaluated: notEvaluated, core_hash: hash, claimed_secure_hw: device.secure_hw as string }  // as written by the device, unknown values included
  if (isObj(proof.time) && typeof proof.time.device_clock === 'number') verdict.device_clock = proof.time.device_clock

  if ('segments' in proof) {
    const captureId = fromBase64(proof.capture_id as string)
    let recomputed: Map<number, Bytes> | undefined
    if (o.recomputeSegments !== false && detectContainer(media) === 'bmff') {
      const content = await recomputeSegments(media, captureId)
      if (content.kind === 'hashes') recomputed = new Map(content.gops.map((g) => [g.index, g.hash]))
      verdict.content = content.kind === 'hashes' ? { recomputed: true, detail: `${content.gops.length} GOPs read from the container` } : { recomputed: false, detail: content.reason }
    } else {
      verdict.content = { recomputed: false, detail: o.recomputeSegments === false ? 'recomputation not requested' : 'not an ISO-BMFF container' }
    }
    const chain = await verifyChain(captureId, mediaObj.segment_count as number, proof.segments as unknown as SegmentEntry[], key, recomputed)
    verdict.segments = { verified: chain.verified, ...(chain.contradicted ? { contradicted: chain.contradicted } : {}) }
    if (chain.status === 'tampered') return { ...tampered(chain.reason ?? 'segment chain'), segments: verdict.segments, content: verdict.content }
    if (!mediaMatches || chain.status === 'clip') { verdict.outcome = 'verified_clip'; verdict.reason = mediaMatches ? 'segments missing' : 'media.hash does not match the received file' }
  } else if (!mediaMatches) {
    return tampered('media.hash does not match the canonical bytes')
  }

  // 6. Attachments that can be checked offline (§6.2).
  if (isObj(proof.registry)) {
    const r = await verifyRegistry(proof.registry as unknown as RegistryAttachment, { keyIdHex: hexKeyId(device.key_id as string), sigPub: spki }, o.trustedLogs ?? [])
    verdict.registry = r.ok ? { ok: true, detail: 'key in the transparency log before tree head', secure_hw: r.secureHw } : { ok: false, detail: r.reason }
    if (!r.ok) labels.push(r.reason === 'log not trusted' ? 'log not trusted' : 'registry evidence invalid')
    else if (verdict.device_clock !== undefined && r.treeHeadTimestamp > verdict.device_clock) labels.push('registered after the declared capture')
  }
  if (isObj(proof.anchor)) {
    const a = await verifyAnchor(proof.anchor as unknown as AnchorAttachment, coreHash, o.readChain)
    verdict.anchor = a.ok ? { ok: true, detail: a.onChain ? `anchored on ${a.chain}, block ${a.block}` : 'merkle path reaches the anchored root; chain not consulted', on_chain: a.onChain } : { ok: false, detail: a.reason }
    if (!a.ok) labels.push('anchor evidence invalid')
    else if (!a.onChain) labels.push('anchoring not verified')
  }
  if (isObj(proof.timestamp) && typeof proof.timestamp.tsr === 'string') {
    if (!o.tsaRoots?.length) labels.push('trusted time not evaluated')
    else {
      let token: Bytes | null = null
      try { token = fromBase64(proof.timestamp.tsr) } catch { token = null }
      const t = token ? await validateTimestamp(token, coreHash, o.tsaRoots.map(parseCertificate), o.now) : null
      verdict.timestamp = t?.ok ? { ok: true, detail: `existed before ${t.genTime}`, gen_time: t.genTime } : { ok: false, detail: t ? t.checks.filter((c) => c.outcome === 'fail').map((c) => c.detail).join('; ') : 'token malformed' }
      if (!verdict.timestamp.ok) labels.push('timestamp evidence invalid')
    }
  }

  // 7. The proof level (§7): proven by the attestation (Android) or by the
  // registry leaf (iOS, App Attest goes to the registry), never by the claim.
  // §7: the claim reported in the level is one of the values this version
  // defines, or `none` — the same rule as the reference verifier's
  // claimedLevel(). The raw string stays in claimed_secure_hw, so a reader can
  // still see what the device wrote without the level ranking a name it cannot
  // interpret.
  const claimed = SECURE_HW.has(device.secure_hw as string) && PLATFORMS.has(device.platform as string) ? device.secure_hw as string : 'none'
  let proven: string = 'none'
  if (Array.isArray(proof.attestation) && device.platform === 'android') {
    let ders: Bytes[] | null = null
    try { ders = (proof.attestation as string[]).map(fromBase64) } catch { ders = null }
    const a = ders ? await validateAndroidAttestation(ders, spki, { roots: o.googleRoots, revocation: o.revocation, now: o.now }) : null
    proven = a?.proven ?? 'none'
    verdict.attestation = a
      ? { proven: a.proven, detail: a.checks.filter((c) => c.outcome === 'fail').map((c) => c.detail).join('; ') || 'chain to a pinned Google root', boot_state: a.bootState }
      : { proven: 'none', detail: 'attestation malformed' }
    if (a && a.revocation === 'not_checked') labels.push('revocation not checked')
    if (a && a.revocation === 'revoked') labels.push('key revoked')
  } else if (device.platform === 'ios' && verdict.registry?.ok && verdict.registry.secure_hw === 'secureEnclave') {
    proven = 'secureEnclave'
  }
  const rank: Record<string, number> = { none: 0, tee: 1, secureEnclave: 1, strongbox: 2 }
  // A claim above the evidence is flagged only when there is evidence: with no
  // attestation the §7 label is *origin not hardware-attested* alone.
  if (verdict.attestation && (rank[claimed] ?? 0) > (rank[proven] ?? 0)) labels.push('inconsistent claim')
  const inLog = verdict.registry?.ok === true && !labels.includes('registered after the declared capture')
  const ceiling: 'green' | 'amber' | 'red' = verdict.outcome === 'tampered' || labels.includes('key revoked') ? 'red'
    : proven !== 'none' && inLog && verdict.outcome === 'authentic' && !labels.includes('inconsistent claim') && !labels.includes('revocation not checked') && !labels.includes('key revoked') ? 'green'
    : 'amber'
  verdict.level = { claimed, proven, ceiling }

  verdict.labels = labels.sort()
  return verdict
}

// device.key_id is base64url of SHA-256(SPKI) in the proof; the log's leaf spells the same hash in hex.
const hexKeyId = (b64: string): string => { try { return toHex(fromBase64(b64)) } catch { return '' } }
