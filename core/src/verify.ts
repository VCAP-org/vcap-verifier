import { type Bytes, equal, fromBase64, fromUtf8, isInstant, toBase64url, toHex } from './bytes.js'
import { sha256 } from './sha.js'
import { MAX_DEPTH, jcs, jsonProblem, type Json } from './jcs.js'
import { parseTrailer } from './trailer.js'
import { canonicalBytes, detectContainer } from './canonical.js'
import { recomputeSegments } from './container.js'
import { type StatusAttachment, type StatusEntry, chainStatus, verifyStatus } from './attestation-status.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import { type SegmentEntry, verifyChain } from './segments.js'
import { type IntegrityAttachment, verifyIntegrity } from './integrity.js'
import { type RegistryAttachment, type TrustedLog, verifyRegistry } from './registry.js'
import { type AnchorAttachment, type ChainReader, verifyAnchor } from './anchor.js'
import { validateTimestamp } from './rfc3161.js'
import { type Certificate, parseCertificate } from './x509.js'
import { type RevocationLookup, validateAndroidAttestation } from './attestation/android.js'
import { type KeyStatusLookup, verifyKeyStatus } from './key-status.js'
import { type WatermarkClaim, type WatermarkLookup, type WatermarkOutcome, captureIdHex, evaluateWatermark } from './watermark.js'
import { type CorroborationOutcome, type DeclaredPosition, type PositionLevel, positionLevel } from './location.js'

/**
 * The verdict of the signature layer of vcap/1.0, from bytes to words. This
 * is the implementation the browser page, the platform API and the libraries
 * share; the conformance vectors of vcap-spec are its acceptance test. It
 * never contacts a server of ours: what it cannot check offline it labels.
 *
 * Outcome vocabulary and labels are the spec's (§8), verbatim — with one
 * addition the §5 binding rule needs and the spec is adopting alongside it:
 * `frames_not_compared`, a video whose file is not the sealed bytes and in
 * which no GOP could be tied to a signed segment. Its signatures hold; nothing
 * ties the frames in front of the reader to them, so it is neither a clip
 * (which needs frames that are the signed frames) nor tampered (nothing was
 * shown to contradict the proof). A stolen proof beside unrelated bytes reads
 * this, where it used to read *verified clip*.
 */
export type Outcome = 'no_proof_found' | 'corrupted_proof' | 'nested_proof' | 'unsupported_format_version' | 'tampered' | 'verified_clip' | 'frames_not_compared' | 'authentic'

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
  anchor?: { ok: boolean, detail: string, on_chain?: boolean, block_time?: string }
  timestamp?: { ok: boolean, detail: string, gen_time?: string }
  attestation?: { proven: string, detail: string, boot_state?: { locked: boolean, state: string } }
  // §6.2: the chain's revocation status as frozen while the chain was current.
  attestation_status?: { ok: boolean, detail: string }
  // §6.2 integrity: what the platform said about the device's state, relayed by
  // the registry. Shown, and never a ceiling — §7 takes the proven level from
  // `attestation`, and the rooted device that fails an integrity check also
  // fails to chain to a hardware root, so counting it would count it twice.
  integrity?: { ok: boolean, detail: string, verdict?: string, evaluated_at?: number }
  // §6.2 registry → "Revocation, online": the device key's own standing in the
  // log at the proven instant. The one check that needs network, and the one
  // green cannot be reached without.
  key_status?: { ok: boolean, detail: string }
  // §8 "A declared watermark that does not come back": what a detector the
  // caller ran reported about the pixels, compared here against the ids the
  // device signed. Present only when a `watermark` lookup was supplied — the
  // core runs no model.
  watermark?: WatermarkOutcome
  // §7: claimed by the device, proven by the evidence, and the ceiling the two allow.
  level?: { claimed: string, proven: string, ceiling: 'green' | 'amber' | 'red' }
  // §7.1: the position level, on its own axis — what the core claims, what the
  // evidence reaches, and the coordinates the device signed. Never a ceiling.
  location?: { claimed: PositionLevel, level: PositionLevel, declared?: DeclaredPosition }
  // §6.2 location_corroboration: the registry's word about an operator's
  // answer, when the attachment is present and could be read.
  location_corroboration?: { ok: boolean, detail: string, method?: string, result?: string, radius_m?: number, at?: number }
  // §7: the instant every certificate path was validated at, and what proved
  // it. A verifier must be able to say this: the same file reads differently
  // depending on whether the capture time came from a token or from the
  // device's own word.
  validated_at?: { instant: string, source: 'timestamp' | 'anchor' | 'device_clock' | 'verifier_clock' }
  claimed_secure_hw?: string
  device_clock?: number
  // `watermark.mark_id` of a `video-rep-v1` proof, and whether it is the value
  // `watermark-layouts-1.0.md` derives from the capture id. A SHOULD for the
  // writer, so a mismatch weakens nothing — but a registry lookup by mark id
  // finds a capture only when the writer followed it, and a reader is owed
  // the difference.
  mark_id?: { value: number, derived: boolean }
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
  // Google's status list, when online; absent → *chain revocation not checked*.
  revocation?: RevocationLookup
  // The transparency log's signed answer about the device key at an instant;
  // absent → *revocation not checked*, amber (§7). The core contacts nothing:
  // the caller owns the network.
  keyStatus?: KeyStatusLookup
  // What a detector saw in the pixels, for a proof that declares a `watermark`;
  // absent → *watermark not evaluated*, which is what every verdict said before
  // any implementation could supply this. The core runs no model and never
  // will: this is the same bargain as `keyStatus`, with one difference stated
  // in watermark.ts — nothing signs a detection, so the evidence is trusted
  // exactly as far as the caller that also hands over the media bytes.
  watermark?: WatermarkLookup
  // The SHA-256 of the canonical bytes (§4.1), when the caller already has it:
  // a phone that hashed a 100 MB recording natively should not hash it again
  // in JavaScript to learn the same 32 bytes. Trusted exactly as far as the
  // caller that computed it; a caller that passes it may pass a file that is
  // only the trailer, with `recomputeSegments: false`.
  mediaHash?: Bytes
  now?: Date
}

const CORE_KEYS = ['v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy'] as const
const KNOWN = new Set([...CORE_KEYS, 'sig', 'segments', 'attestation', 'attestation_status', 'registry', 'timestamp', 'anchor', 'integrity', 'location_corroboration'])
const ABSENT: [string, string][] = [
  ['timestamp', 'no trusted time'], ['anchor', 'not anchored'], ['registry', 'key not in transparency log'],
  ['integrity', 'integrity unevaluated'], ['watermark', 'no watermark']
]
const PLATFORMS = new Set(['android', 'ios', 'web'])
// §7's labels that keep an otherwise proven, logged, trusted-instant verdict
// off green.
const HOLDS_AMBER = new Set([
  'inconsistent claim', 'chain revocation not checked', 'revocation not checked', 'attestation chain expired, capture time not proven',
  'registered after the declared capture', 'registered after the trusted time', 'capture time not declared',
  'attestation app not admitted', 'attestation app not checked', 'integrity failed'
])
const SECURE_HW = new Set(['strongbox', 'tee', 'secureEnclave', 'none'])

type Obj = { [key: string]: Json }
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)
/**
 * What makes a core unhashable here: a non-integer number (§6.1: the core
 * carries integers only) or nesting past `MAX_DEPTH`. Iterative, because the
 * recursive walk it replaces overflowed the stack on a payload nested a few
 * thousand levels deep, and that exception escaped `verify`.
 */
const coreTrouble = (root: Json): 'floating-point number in the core' | 'core nested too deep' | null => {
  const stack: Array<[Json, number]> = [[root, 0]]
  while (stack.length > 0) {
    const [v, depth] = stack.pop()!
    if (depth > MAX_DEPTH) return 'core nested too deep'
    if (typeof v === 'number' && !Number.isInteger(v)) return 'floating-point number in the core'
    if (Array.isArray(v)) for (const x of v) stack.push([x, depth + 1])
    else if (isObj(v)) for (const x of Object.values(v)) stack.push([x as Json, depth + 1])
  }
  return null
}
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
  // §8: the pixel dimensions are required. Not evidence — nothing is proven by
  // them — but a reader that cannot say how large the frame is cannot place a
  // watermark payload or a segment in it. Missing is malformed, and the check
  // sits here so the signature is never examined: reporting *tampered* would be
  // reporting a check this verifier had not run (vector 46).
  if (!Number.isInteger(proof.media.w) || !Number.isInteger(proof.media.h) || (proof.media.w as number) < 1 || (proof.media.h as number) < 1) return 'media.w or media.h missing'
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
  return coreTrouble(extractCore(proof))
}

/**
 * `verify` never throws on what it is handed. Everything below is written to
 * turn a bad input into a labelled answer, and this is the net under it: an
 * exception that still escapes is a bug of this verifier, and the reader gets
 * the weakest honest verdict with the reason — *no proof found* when no proof
 * object was read, *corrupted proof* once one was — never a page that spins
 * or a CLI that reports "does not verify" because it crashed.
 */
export const verify = async (file: Bytes, o: VerifyOptions = {}): Promise<Verdict> => {
  const progress = { proof: false }
  try {
    return await verifyFile(file, o, progress)
  } catch (error) {
    const why = error instanceof Error ? error.message : String(error)
    return progress.proof
      ? fail('corrupted_proof', `the proof could not be read to the end: ${why}`)
      : fail('no_proof_found', `the file could not be read: ${why}`)
  }
}

const verifyFile = async (file: Bytes, o: VerifyOptions, progress: { proof: boolean }): Promise<Verdict> => {
  // 1. Trailer, sidecar, nesting (§3).
  const trailer = parseTrailer(file)
  if (trailer.kind === 'corrupted') return fail('corrupted_proof', 'footer valid, CRC mismatch')
  if (trailer.kind === 'unsupported') return fail('unsupported_format_version', `footer major ${trailer.major}`)
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
  let text: string
  // §6.1: UTF-8 with no byte-order mark. `TextDecoder` would strip one
  // silently, and a second reader that does not would see other bytes.
  if (payload[0] === 0xef && payload[1] === 0xbb && payload[2] === 0xbf) return fail('no_proof_found', 'payload begins with a byte-order mark')
  try {
    text = fromUtf8(payload)
    const parsed: unknown = JSON.parse(text)
    if (!isObj(parsed)) throw new Error('not an object')
    proof = parsed
  } catch { return fail('no_proof_found', 'payload is not a JSON object') }
  // §6.1 *Reading the JSON*: a key twice in one object, or a number that is
  // not an integer literal in the exact range, is a payload two parsers read
  // two ways — not well formed, *no proof found*.
  const problem = jsonProblem(text)
  if (problem !== null) return fail('no_proof_found', problem)
  progress.proof = true
  const version = typeof proof.v === 'string' ? /^vcap\/(\d+)\.(\d+)$/.exec(proof.v) : null
  if (!version) return fail('no_proof_found', 'v missing or malformed')
  if (version[1] !== '1') return fail('unsupported_format_version', `major ${version[1]}`)
  const notEvaluated = Object.keys(proof).filter((k) => !KNOWN.has(k)).sort()

  // 3. Shape (§6.1, §8).
  const shape = shapeProblem(proof)
  if (shape) return fail('no_proof_found', shape)

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
  let canonical: Bytes | null = null
  if (!o.mediaHash) {
    // §4.1: a JPEG whose markers cannot be walked has no canonical bytes, and
    // the verdict is *no proof found* — never an exception (vector 116).
    try { canonical = canonicalBytes(media) } catch (error) {
      return fail('no_proof_found', `the canonical bytes cannot be computed: ${error instanceof Error ? error.message : 'unreadable container'}`)
    }
  }
  const mediaMatches = toBase64url(o.mediaHash ?? await sha256(canonical!)) === mediaObj.hash
  for (const [k, label] of ABSENT) if (!(k in proof)) labels.push(label)
  if (flags !== null) {
    const expected = ('segments' in proof ? 2 : 0) | ((isObj(proof.policy) && proof.policy.pseudonymous === true) ? 4 : 0)
    if ((flags & 6) !== expected) labels.push('flags disagree')
  }
  const verdict: Verdict = { outcome: 'authentic', labels, not_evaluated: notEvaluated, core_hash: hash, claimed_secure_hw: device.secure_hw as string }  // as written by the device, unknown values included
  // An instant `Date` cannot hold (1e20) is not a clock reading: it would become
  // an Invalid Date that throws on `toISOString()`. Read as no declared time.
  if (isObj(proof.time) && isInstant(proof.time.device_clock)) verdict.device_clock = proof.time.device_clock
  if (isObj(proof.watermark) && proof.watermark.layout === 'video-rep-v1' && Number.isSafeInteger(proof.watermark.mark_id)) {
    const value = proof.watermark.mark_id as number
    verdict.mark_id = { value, derived: value === await deriveMarkId(fromBase64(proof.capture_id as string)) }
  }

  if ('segments' in proof) {
    const outcome = await segmentsOutcome(proof, media, key, mediaMatches, o)
    verdict.content = outcome.content
    if (!outcome.content.recomputed) labels.push('segment content not recomputed')
    verdict.segments = outcome.segments
    if (outcome.tampered !== undefined) return { ...tampered(outcome.tampered), segments: verdict.segments, content: verdict.content }
    if (outcome.outcome !== 'authentic') { verdict.outcome = outcome.outcome; verdict.reason = outcome.reason }
  } else if (!mediaMatches) {
    return tampered('media.hash does not match the canonical bytes')
  }

  // 5b. The declared watermark (§8, "A declared watermark that does not come
  // back"). A declared `watermark` is the writer saying a mark was embedded,
  // not a promise a reader finds it — and a reader that does not find one
  // never guesses, so silence is not an option: it would read as a match.
  //
  // With no lookup this core has no detector, and the only §8 outcome
  // available is *watermark not evaluated* — which is what it has always said,
  // unconditionally. With one, the caller reports what came out of the pixels
  // and the comparison is made here, against the ids the device signed.
  //
  // It sits **after** the signature: a watermark can never be the reason a
  // verdict is positive, because a proof whose `sig` does not verify has
  // already returned *tampered* and this code was never reached. That is the
  // invariant "a watermark alone is never a green verdict" enforced by
  // construction rather than by a rule — and *watermark matched* is a label,
  // never an input to the §7 ceiling below.
  if ('watermark' in proof) {
    if (!o.watermark) labels.push('watermark not evaluated')
    else {
      const w = isObj(proof.watermark) ? proof.watermark : {}
      const claim: WatermarkClaim = {
        layout: typeof w.layout === 'string' ? w.layout : '',
        captureId: captureIdHex(proof.capture_id as string),
        ...(Number.isInteger(w.mark_id) ? { markId: w.mark_id as number } : {}),
        mime: (proof.media as Obj).mime as string,
        coreHash: hash
      }
      // A lookup that throws is an absent answer, and its reason is kept: a
      // detector that could not be fetched should say why in the verdict.
      let evidence = null
      let unavailable = 'no detection was available'
      try { evidence = await o.watermark(claim) } catch (error) { unavailable += `: ${error instanceof Error ? error.message : String(error)}` }
      const result = evidence === null
        ? { result: 'not_evaluated' as const, detail: unavailable }
        : evaluateWatermark(evidence, claim)
      verdict.watermark = result
      // §8's red row. It is returned as *tampered* with a reason and no
      // labels, the same shape as a segment whose content hash contradicts the
      // signature: both are the received bytes disagreeing with what the
      // device signed over them.
      if (result.result === 'contradicted') {
        return { ...tampered(`watermark payload contradicts the proof: ${result.detail}`), segments: verdict.segments, content: verdict.content, watermark: result }
      }
      labels.push(result.result === 'matched' ? 'watermark matched' : result.result === 'not_recovered' ? 'watermark not recovered' : 'watermark not evaluated')
    }
  }

  // 6. Attachments that can be checked offline (§6.2).
  let treeHeadAt: number | null = null
  if (isObj(proof.registry)) {
    const r = await verifyRegistry(proof.registry as unknown as RegistryAttachment, { keyIdHex: hexKeyId(device.key_id as string), sigPub: spki }, o.trustedLogs ?? [])
    verdict.registry = r.ok ? { ok: true, detail: 'key in the transparency log before tree head', secure_hw: r.secureHw } : { ok: false, detail: r.reason }
    // §6.2: evidence that does not hold up emits **both** labels — the second
    // is what a reader is shown (nobody can confirm this key was registered)
    // and the first is what an operator can act on (somebody presented a proof
    // that does not hold up). A log this verifier holds no key for is neither:
    // it is absent evidence, not a lie, and gets *log not trusted* alone.
    if (!r.ok) {
      if (r.reason === 'log not trusted') labels.push('log not trusted')
      else labels.push('registry evidence invalid', 'key not in transparency log')
    }
    else {
      treeHeadAt = r.treeHeadTimestamp
      if (verdict.device_clock !== undefined && r.treeHeadTimestamp > verdict.device_clock) labels.push('registered after the declared capture')
    }
  }
  if (isObj(proof.anchor)) {
    const a = await verifyAnchor(proof.anchor as unknown as AnchorAttachment, coreHash, o.readChain)
    const offChain = a.ok && a.unread !== undefined ? `merkle path reaches the anchored root; the chain could not be read (${a.unread})` : 'merkle path reaches the anchored root; chain not consulted'
    verdict.anchor = a.ok ? { ok: true, detail: a.onChain ? `anchored on ${a.chain}, block ${a.block}` : offChain, on_chain: a.onChain, block_time: a.blockTime } : { ok: false, detail: a.reason }
    // §8's rule for every attachment: present and not holding up carries the
    // absent label too. *not anchored* is what a reader is shown, *anchor
    // evidence invalid* is what an operator can act on.
    if (!a.ok) labels.push('anchor evidence invalid', 'not anchored')
    else if (!a.onChain) labels.push('anchoring not verified')
  }
  if (isObj(proof.integrity)) {
    const i = await verifyIntegrity(proof.integrity as unknown as IntegrityAttachment, coreHash, o.trustedLogs ?? [])
    verdict.integrity = i.ok
      ? { ok: true, detail: `${i.source} reported ${i.verdict}`, verdict: i.verdict, evaluated_at: i.evaluatedAt }
      : { ok: false, detail: i.reason }
    // §8's uniform rule, with the same split as `registry`: evidence that does
    // not hold up carries the absent label *and* the operator's one, while
    // evidence signed by a key this verifier does not follow is absence alone —
    // a relabelled verdict and an honest verdict from an unfollowed registry
    // are indistinguishable from here, and the honest report is the weaker one.
    if (!i.ok) {
      if (i.trusted) labels.push('integrity evidence invalid')
      labels.push('integrity unevaluated')
    } else labels.push(`integrity ${i.verdict}`)
  }
  // §7.1: the position level, computed here with the attachments because the
  // corroboration is one, and kept out of §7's ceiling below by construction —
  // nothing it produces is read again.
  const position = await positionLevel(proof.location, proof.location_corroboration, coreHash, o.trustedLogs ?? [])
  labels.push(...position.labels)
  verdict.location = { claimed: position.claimed, level: position.level, ...(position.declared ? { declared: position.declared } : {}) }
  if (position.corroboration) verdict.location_corroboration = corroborationDetail(position.corroboration)
  // §6.2 check 6: a token must agree with a verified anchor, so the block time
  // is known before the token is read.
  const blockTime = verdict.anchor?.ok === true && verdict.anchor.on_chain === true && verdict.anchor.block_time ? new Date(verdict.anchor.block_time) : undefined
  if (isObj(proof.timestamp) && typeof proof.timestamp.tsr === 'string') {
    if (!o.tsaRoots?.length) labels.push('trusted time not evaluated')
    else {
      let token: Bytes | null = null
      try { token = fromBase64(proof.timestamp.tsr) } catch { token = null }
      const t = token ? await validateTimestamp(token, coreHash, o.tsaRoots.map(parseCertificate), o.now, blockTime) : null
      verdict.timestamp = t?.ok ? { ok: true, detail: `existed before ${t.genTime}`, gen_time: t.genTime } : { ok: false, detail: t ? t.checks.filter((c) => c.outcome === 'fail').map((c) => c.detail).join('; ') : 'token malformed' }
      if (!verdict.timestamp.ok) labels.push('timestamp evidence invalid', 'no trusted time')
    }
  }
  // §6.2 *Before the capture*: the tree head must not postdate a valid token
  // either. The device clock is the device's word; the token is a third
  // party's, and a key logged after it was not in the log when the capture
  // was stamped.
  const genTime = verdict.timestamp?.ok === true && verdict.timestamp.gen_time ? Date.parse(verdict.timestamp.gen_time) : null
  if (treeHeadAt !== null && genTime !== null && treeHeadAt > genTime) labels.push('registered after the trusted time')
  // §7: with no `time.device_clock` nothing in the core dates the capture, so
  // the registration cannot be placed before it — an absent field is a weaker
  // verdict, never a stronger one.
  if (verdict.device_clock === undefined) labels.push('capture time not declared')

  // 7. The instant every certificate path is validated at (§7), in order: a
  // valid timestamp token (which already agreed with any anchor), a verified
  // anchor's block, the device's own clock, and — with none of them — the
  // verifier's clock, which proves nothing about the capture and is only there
  // so validation has an instant at all. Green needs one of the first two.
  const clock = o.now ?? new Date()
  const instant: { at: Date, source: NonNullable<Verdict['validated_at']>['source'] } =
    genTime !== null ? { at: new Date(genTime), source: 'timestamp' }
      : blockTime ? { at: blockTime, source: 'anchor' }
        : verdict.device_clock !== undefined ? { at: new Date(verdict.device_clock), source: 'device_clock' }
          : { at: clock, source: 'verifier_clock' }
  // Every source above is checked where it is read; this is the last guard
  // between an instant and `toISOString()`, which throws on an Invalid Date.
  if (Number.isNaN(instant.at.getTime())) { instant.at = clock; instant.source = 'verifier_clock' }
  verdict.validated_at = { instant: instant.at.toISOString(), source: instant.source }
  const trustedInstant = instant.source === 'timestamp' || instant.source === 'anchor'

  // 8. The proof level (§7): proven by the attestation (Android) or by the
  // registry leaf (iOS, App Attest goes to the registry), never by the claim.
  // §7: the claim reported in the level is one of the values this version
  // defines, or `none`. The raw string stays in claimed_secure_hw, so a reader
  // can still see what the device wrote without the level ranking a name it
  // cannot interpret.
  const claimed = SECURE_HW.has(device.secure_hw as string) && PLATFORMS.has(device.platform as string) ? device.secure_hw as string : 'none'
  let proven: string = 'none'
  // The level the evidence establishes, before revocation withdraws it.
  // *inconsistent claim* is measured against this and not against the final
  // level: a revoked chain does not contradict the claim, it retracts it.
  let attested: string = 'none'
  // Whether an attestation chain holds as evidence at all (§7 rules 1–3). A
  // chain that does not is no evidence to contradict a claim with.
  let chainHolds = false
  if (Array.isArray(proof.attestation) && device.platform === 'android') {
    let ders: Bytes[] | null = null
    try { ders = (proof.attestation as string[]).map(fromBase64) } catch { ders = null }
    const a = ders ? await validateAndroidAttestation(ders, spki, { roots: o.googleRoots, revocation: o.revocation, now: instant.at, clock: o.now }) : null
    // §6.2, §7 rule 5: a chain about another key beside this signature is a
    // signature swap, not weak evidence (vector 108).
    if (a?.keyMismatch) return tampered('attestation leaf key differs from sig.pub')
    const failed = a ? a.checks.filter((c) => c.outcome === 'fail').map((c) => c.detail).join('; ') : ''
    if (!a || a.invalid) {
      // §7: rules 1–3 broken, or unreadable — evidence that does not hold up.
      labels.push('attestation evidence invalid')
      verdict.attestation = { proven: 'none', detail: a ? failed : 'attestation malformed' }
    } else {
      chainHolds = true
      proven = a.proven
      attested = proven
      verdict.attestation = { proven: a.proven, detail: failed || 'chain to a pinned Google root', boot_state: a.bootState }
      const revocation = await chainRevocation(proof, a, coreHash, o)
      if (revocation.detail) verdict.attestation_status = revocation.detail
      if (revocation.state === 'revoked') {
        // §6.2 *Revoked*: red, unless a trusted instant — never the device's
        // clock, which whoever holds a leaked key sets — predates the date the
        // source gives, and the reason is not a compromise, which reaches
        // back to the key's first use whatever the date says.
        const e = revocation.entry
        const survives = trustedInstant && e.revoked_at !== undefined && instant.at.getTime() < e.revoked_at &&
          e.reason !== 'KEY_COMPROMISE' && e.reason !== 'CA_COMPROMISE'
        if (survives) labels.push('attestation key revoked after the capture')
        else { proven = 'none'; labels.push('attestation key revoked') }
      } else if (revocation.state === 'unchecked') labels.push('chain revocation not checked')
      // §7: a chain valid at the proven instant and expired since is not an
      // error — the verifier is late, the capture is not forged. It is only
      // worth saying when the instant is the device's own claim.
      if (a.expiredSince && !trustedInstant) labels.push('attestation chain expired, capture time not proven')
      // §7 *The app that made the key*, against the digests the log that
      // admitted the key declares. Amber either way: the hardware claim stands.
      if (verdict.registry?.ok === true) {
        const declared = (o.trustedLogs ?? []).find((l) => l.logId === (proof.registry as Obj).log_id)?.appSigningDigests
        if (!declared || !a.appDigests) labels.push('attestation app not checked')
        else if (!a.appDigests.some((d) => declared.includes(d))) labels.push('attestation app not admitted')
      }
    }
  } else if (device.platform === 'ios' && verdict.registry?.ok && verdict.registry.secure_hw === 'secureEnclave') {
    // §7 *The Secure Enclave level*: reachable only through the registry, and
    // said to be our records — nothing in the file shows it.
    proven = 'secureEnclave'
    attested = proven
    labels.push('level from registry records')
  }
  if (attested === 'none') labels.push('origin not hardware-attested')
  // §6.2 registry → "Revocation, online", and §7's *revocation not checked*.
  // The registry attachment proves the key was in the log when a tree head was
  // signed; a revocation is a *later* leaf, and nothing in a Merkle tree proves
  // a leaf's absence, so this is the one question that cannot be answered from
  // the file. Until it is answered, green would say "sealed in the TEE, key in
  // the log, revocation checked" with the last third unverified — so an offline
  // verifier says *revocation not checked* and stops at amber, by design.
  if (verdict.registry?.ok === true) {
    const keyIdHex = hexKeyId(device.key_id as string)
    let statement = null
    try { statement = o.keyStatus ? await o.keyStatus(keyIdHex, instant.at) : null } catch { statement = null }
    // The statement is the network's answer, relayed by the caller: one that
    // cannot be checked is an unasked question, not a crash.
    let st: Awaited<ReturnType<typeof verifyKeyStatus>> | null = null
    try { st = statement ? await verifyKeyStatus(statement, fromBase64(device.key_id as string), instant.at, o.trustedLogs ?? []) : null } catch { st = { ok: false, reason: 'status statement malformed' } }
    if (st?.ok === true && st.status !== 0) {
      verdict.key_status = { ok: true, detail: st.status === 1 ? `the log placed the key as valid at ${instant.at.toISOString()}` : `the log placed the key as revoked at ${instant.at.toISOString()}` }
      if (st.status === 2) labels.push('key revoked')
    } else {
      // An unknown status and an unreachable log are the same amount of
      // knowledge, and a statement that does not check out is less than none:
      // it says so, rather than passing for one.
      verdict.key_status = { ok: false, detail: st ? (st.ok ? 'the log answered `unknown`' : st.reason) : o.keyStatus ? 'the log could not be asked' : 'no log lookup available' }
      labels.push('revocation not checked')
    }
  }
  const rank: Record<string, number> = { none: 0, tee: 1, secureEnclave: 1, strongbox: 2 }
  // A claim above the evidence is flagged only when there is evidence: with no
  // chain that holds, the §7 label is *origin not hardware-attested* alone.
  const logged = verdict.registry?.ok === true ? verdict.registry.secure_hw ?? 'none' : null
  const above = (x: string, y: string): boolean => (rank[x] ?? 0) > (rank[y] ?? 0)
  const inconsistent =
    (chainHolds && above(claimed, attested)) ||
    // §6.2: `leaf.secure_hw` is what the log saw proven at registration and
    // MUST NOT exceed what the attestation proves when both are present.
    (chainHolds && logged !== null && above(logged, attested)) ||
    // iOS has no chain in the proof: the registry leaf is the evidence, so the
    // claim is measured against it.
    (device.platform === 'ios' && logged !== null && above(claimed, logged))
  if (inconsistent) labels.push('inconsistent claim')
  // §7: green needs a proven level, the key in a trusted log, a trusted
  // instant (a token or a verified anchor — never the device's clock), and
  // none of the labels that hold a ceiling at amber.
  const ceiling: 'green' | 'amber' | 'red' = verdict.outcome === 'tampered' || labels.includes('key revoked') || labels.includes('attestation key revoked') ? 'red'
    : proven !== 'none' && verdict.registry?.ok === true && verdict.outcome === 'authentic' && trustedInstant && !labels.some((l) => HOLDS_AMBER.has(l)) ? 'green'
    : 'amber'
  verdict.level = { claimed, proven, ceiling }

  verdict.labels = labels.sort()
  return verdict
}

/**
 * §6.2's wording rule: what travels is the registry's countersignature of
 * what the registry saw, so the detail says *the registry attests* and never
 * "verified by the operator". The radius is shown because a `match` means the
 * same area — kilometres — and never the same point.
 */
const corroborationDetail = (c: CorroborationOutcome): NonNullable<Verdict['location_corroboration']> => {
  if (!c.ok) return { ok: false, detail: c.reason }
  const zone = c.radiusM !== undefined ? `, radius ${c.radiusM} m` : ''
  const said = c.result === 'match' ? `the registry attests that the operator confirmed the zone${zone}`
    : c.result === 'no-match' ? `the registry attests that the operator placed the line outside the zone${zone}`
      : `the registry attests that the operator could not say${zone}`
  return { ok: true, detail: `${said} (${c.method})`, method: c.method, result: c.result, at: c.at, ...(c.radiusM !== undefined ? { radius_m: c.radiusM } : {}) }
}

/**
 * §6.2 chain revocation from both sources a verifier may hold: the frozen
 * `attestation_status` snapshot and the caller's online status list. Either
 * source that covers the chain is the check; a `revoked` from either is the
 * answer, dated only by what the source itself says (`revoked_at`) and never
 * by when it was read.
 */
const chainRevocation = async (proof: Obj, a: Awaited<ReturnType<typeof validateAndroidAttestation>>, coreHash: Bytes, o: VerifyOptions): Promise<{ state: 'revoked', entry: StatusEntry, detail?: { ok: boolean, detail: string } } | { state: 'clear' | 'unchecked', detail?: { ok: boolean, detail: string } }> => {
  let detail: { ok: boolean, detail: string } | undefined
  let frozen: ReturnType<typeof chainStatus> | null = null
  if (isObj(proof.attestation_status)) {
    const status = await verifyStatus(proof.attestation_status as unknown as StatusAttachment, coreHash, o.trustedLogs ?? [], (proof.registry as Obj | undefined)?.log_id as string | undefined)
    if (!status.ok) {
      // A snapshot that does not check out adds nothing and takes nothing away.
      detail = { ok: false, detail: status.reason }
    } else {
      frozen = chainStatus(status.entries, a.serials)
      const as = new Date(status.fetchedAt).toISOString()
      detail = frozen.state === 'revoked'
        ? { ok: true, detail: `certificate ${frozen.entry.serial} revoked${frozen.entry.revoked_at !== undefined ? ` on ${new Date(frozen.entry.revoked_at).toISOString()}` : ', with no date from the source'}${frozen.entry.reason ? ` (${frozen.entry.reason})` : ''}` }
        : frozen.state === 'clear'
          ? { ok: true, detail: `every certificate of the chain was valid as of ${as}` }
          : { ok: true, detail: `as of ${as} the snapshot does not show every certificate of the chain valid (an entry missing or unknown)` }
    }
  }
  const online: ReturnType<typeof chainStatus> | null = a.revocation === 'not_checked' ? null
    : a.revoked ? { state: 'revoked', entry: { serial: a.revoked.serial, status: 'revoked', ...(a.revoked.reason ? { reason: a.revoked.reason } : {}), ...(a.revoked.revokedAt !== undefined ? { revoked_at: a.revoked.revokedAt } : {}) } }
      : { state: 'clear' }
  const revoked = [frozen, online].find((x) => x?.state === 'revoked')
  if (revoked?.state === 'revoked') return { state: 'revoked', entry: revoked.entry, detail }
  if (frozen?.state === 'clear' || online?.state === 'clear') return { state: 'clear', detail }
  return { state: 'unchecked', detail }
}

/**
 * `watermark-layouts-1.0.md`, *Deriving a mark_id*: the first three bytes of
 * SHA-256(capture_id) as a big-endian uint24, and 1 where that is 0 (0 is the
 * decoder's "no id").
 */
export const deriveMarkId = async (captureId: Bytes): Promise<number> => {
  const digest = await sha256(captureId)
  const value = (digest[0]! << 16) | (digest[1]! << 8) | digest[2]!
  return value === 0 ? 1 : value
}

interface SegmentsOutcome {
  content: NonNullable<Verdict['content']>
  segments: NonNullable<Verdict['segments']>
  outcome: Outcome
  reason?: string
  tampered?: string
}

/**
 * §5 for a video proof: the chain over the signed messages, the content of
 * every GOP the container locates, and — the binding rule — which segments
 * that earns credit for.
 *
 * A signed segment `n` is `verified` only if the container yields exactly one
 * GOP whose vcap SEI carries index `n` and this proof's `capture_id`, and that
 * GOP's recomputed `content_hash` matches. The SEI is unsigned, so it locates
 * and never proves; what it may not do is point a signed index at bytes the
 * device never hashed. A GOP naming an index the proof does not sign, an index
 * named twice, or indices out of file order are *tampered* (`container.ts`).
 *
 * With nothing located there is no content credit at all. Where `media.hash`
 * matches that costs nothing — the whole file is the sealed bytes, every
 * segment included, which is why a sidecar over the original still reads
 * *authentic* with *segment content not recomputed* (vector 33). Where it does
 * not, the signatures hold over frames nobody compared: *frames not compared*,
 * never *verified clip*, which is what a proof lifted onto unrelated bytes
 * used to read.
 */
const segmentsOutcome = async (proof: Obj, media: Bytes, key: CryptoKey, mediaMatches: boolean, o: VerifyOptions): Promise<SegmentsOutcome> => {
  const captureId = fromBase64(proof.capture_id as string)
  const signed = proof.segments as unknown as SegmentEntry[]
  let located: Map<number, Bytes> | undefined
  let content: SegmentsOutcome['content']
  let problems: string[] = []
  if (o.recomputeSegments !== false && detectContainer(media) === 'bmff') {
    const indices = new Set(Array.isArray(signed) ? signed.map((x) => (x as { gop?: unknown } | null)?.gop).filter((g): g is number => typeof g === 'number') : [])
    const r = await recomputeSegments(media, captureId, indices)
    if (r.kind === 'malformed') {
      return { content: { recomputed: false, detail: r.reason }, segments: { verified: [] }, outcome: 'tampered', tampered: `the container contradicts the proof: ${r.reason}` }
    }
    if (r.kind === 'hashes') {
      located = new Map(r.gops.map((g) => [g.index, g.hash]))
      problems = r.problems
      content = { recomputed: true, detail: `${r.gops.length} GOPs read from the container` }
    } else {
      // Read and unplaced is still a recomputation that ran: what it found is
      // that nothing in the file names this capture (vectors 86, 87).
      content = { recomputed: r.kind === 'unlocated', detail: r.reason }
    }
  } else {
    content = { recomputed: false, detail: o.recomputeSegments === false ? 'recomputation not requested' : 'not an ISO-BMFF container' }
  }

  const chain = await verifyChain(captureId, (proof.media as Obj).segment_count as number, signed, key, located)
  // Credit is the located GOPs whose message verified and whose bytes match:
  // with nothing located there is none, whatever the chain says (§5).
  const credited = (list: number[]): number[] => located ? list.filter((n) => located.has(n)) : []
  if (chain.status === 'tampered') {
    return { content, segments: { verified: credited(chain.verified), ...(chain.contradicted ? { contradicted: chain.contradicted } : {}) }, outcome: 'tampered', tampered: chain.reason ?? 'segment chain' }
  }
  const verified = credited(chain.verified)
  if (problems.length > 0) return { content, segments: { verified }, outcome: 'tampered', tampered: `the container contradicts the proof: ${problems[0]}` }
  if (mediaMatches) {
    return { content, segments: { verified }, outcome: chain.status === 'clip' ? 'verified_clip' : 'authentic', ...(chain.status === 'clip' ? { reason: 'segments missing' } : {}) }
  }
  if (verified.length === 0) {
    return { content, segments: { verified }, outcome: 'frames_not_compared', reason: `media.hash does not match the received file and no GOP in it is tied to a signed segment (${content.detail}): the signatures hold, the frames were not compared` }
  }
  return { content, segments: { verified }, outcome: 'verified_clip', reason: 'media.hash does not match the received file' }
}

// device.key_id is base64url of SHA-256(SPKI) in the proof; the log's leaf spells the same hash in hex.
const hexKeyId = (b64: string): string => { try { return toHex(fromBase64(b64)) } catch { return '' } }
