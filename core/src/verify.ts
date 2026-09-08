import { type Bytes, equal, fromBase64, fromUtf8, toBase64url, toHex } from './bytes.js'
import { sha256 } from './sha.js'
import { jcs, type Json } from './jcs.js'
import { parseTrailer } from './trailer.js'
import { canonicalBytes } from './canonical.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import { type SegmentEntry, verifyChain } from './segments.js'
import { type RegistryAttachment, type TrustedLog, verifyRegistry } from './registry.js'
import { type AnchorAttachment, type ChainReader, verifyAnchor } from './anchor.js'

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
  segments?: { verified: number[] }
  reason?: string
  // What the attachments proved, when present and evaluated.
  registry?: { ok: boolean, detail: string, secure_hw?: string }
  anchor?: { ok: boolean, detail: string, on_chain?: boolean }
  // Claimed by the device; the proven level needs the attestation chain (not evaluated here).
  claimed_secure_hw?: string
  device_clock?: number
}

export interface VerifyOptions {
  sidecar?: Bytes
  trustedLogs?: TrustedLog[]
  readChain?: ChainReader
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
  if (!isObj(proof.device) || !PLATFORMS.has(proof.device.platform as string) || !SECURE_HW.has(proof.device.secure_hw as string) || typeof proof.device.key_id !== 'string') return 'device incomplete'
  if (!isObj(proof.sig) || typeof proof.sig.value !== 'string' || typeof proof.sig.pub !== 'string' || typeof proof.sig.alg !== 'string') return 'sig incomplete'
  if ('segments' in proof && (!Array.isArray(proof.segments) || !Number.isInteger((proof.media as Obj).segment_count))) return 'segments without media.segment_count'
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
  if (flags !== null) {
    const expected = ('segments' in proof ? 2 : 0) | ((isObj(proof.policy) && proof.policy.pseudonymous === true) ? 4 : 0)
    if ((flags & 6) !== expected) labels.push('flags disagree')
  }
  const verdict: Verdict = { outcome: 'authentic', labels, not_evaluated: notEvaluated, core_hash: hash, claimed_secure_hw: device.secure_hw as string }
  if (isObj(proof.time) && typeof proof.time.device_clock === 'number') verdict.device_clock = proof.time.device_clock

  if ('segments' in proof) {
    const chain = await verifyChain(fromBase64(proof.capture_id as string), mediaObj.segment_count as number, proof.segments as unknown as SegmentEntry[], key)
    verdict.segments = { verified: chain.verified }
    if (chain.status === 'tampered') return { ...tampered(chain.reason ?? 'segment chain'), segments: verdict.segments }
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
  if ('timestamp' in proof) labels.push('trusted time not evaluated')

  verdict.labels = labels.sort()
  return verdict
}

// device.key_id is base64url of SHA-256(SPKI) in the proof; the log's leaf spells the same hash in hex.
const hexKeyId = (b64: string): string => { try { return toHex(fromBase64(b64)) } catch { return '' } }
