import { type Bytes, equal, fromBase64, fromUtf8, toBase64url, toHex } from './bytes.js'
import { sha256 } from './sha.js'
import { jcs, type Json } from './jcs.js'
import { parseTrailer } from './trailer.js'
import { canonicalBytes, detectContainer } from './canonical.js'
import { recomputeSegments } from './container.js'
import { type StatusAttachment, type StatusOutcome, verifyStatus } from './attestation-status.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import { type SegmentEntry, verifyChain } from './segments.js'
import { type IntegrityAttachment, verifyIntegrity } from './integrity.js'
import { type RegistryAttachment, type TrustedLog, verifyRegistry } from './registry.js'
import { type AnchorAttachment, type ChainReader, verifyAnchor } from './anchor.js'
import { validateTimestamp } from './rfc3161.js'
import { type Certificate, parseCertificate } from './x509.js'
import { type RevocationLookup, validateAndroidAttestation } from './attestation/android.js'
import { type KeyStatusLookup, verifyKeyStatus } from './key-status.js'
import { type CorroborationOutcome, type DeclaredPosition, type PositionLevel, positionLevel } from './location.js'

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
  now?: Date
}

const CORE_KEYS = ['v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy'] as const
const KNOWN = new Set([...CORE_KEYS, 'sig', 'segments', 'attestation', 'attestation_status', 'registry', 'timestamp', 'anchor', 'integrity', 'location_corroboration'])
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
    // §5/§7: skipping the recomputation stays conformant, staying quiet about it
    // does not. The two answers differ — on vector 39 the same file reads
    // *verified_clip* without it and *tampered* with it — so a reader who is not
    // told which one ran cannot know what the verdict means. Keyed off the
    // result and not the option, because a demux that failed is also a check
    // that did not run.
    if (!verdict.content.recomputed) labels.push('segment content not recomputed')
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
    // §6.2: evidence that does not hold up emits **both** labels — the second
    // is what a reader is shown (nobody can confirm this key was registered)
    // and the first is what an operator can act on (somebody presented a proof
    // that does not hold up). A log this verifier holds no key for is neither:
    // it is absent evidence, not a lie, and gets *log not trusted* alone.
    if (!r.ok) {
      if (r.reason === 'log not trusted') labels.push('log not trusted')
      else labels.push('registry evidence invalid', 'key not in transparency log')
    }
    else if (verdict.device_clock !== undefined && r.treeHeadTimestamp > verdict.device_clock) labels.push('registered after the declared capture')
  }
  if (isObj(proof.anchor)) {
    const a = await verifyAnchor(proof.anchor as unknown as AnchorAttachment, coreHash, o.readChain)
    verdict.anchor = a.ok ? { ok: true, detail: a.onChain ? `anchored on ${a.chain}, block ${a.block}` : 'merkle path reaches the anchored root; chain not consulted', on_chain: a.onChain, block_time: a.blockTime } : { ok: false, detail: a.reason }
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
  if (isObj(proof.timestamp) && typeof proof.timestamp.tsr === 'string') {
    if (!o.tsaRoots?.length) labels.push('trusted time not evaluated')
    else {
      let token: Bytes | null = null
      try { token = fromBase64(proof.timestamp.tsr) } catch { token = null }
      const t = token ? await validateTimestamp(token, coreHash, o.tsaRoots.map(parseCertificate), o.now) : null
      verdict.timestamp = t?.ok ? { ok: true, detail: `existed before ${t.genTime}`, gen_time: t.genTime } : { ok: false, detail: t ? t.checks.filter((c) => c.outcome === 'fail').map((c) => c.detail).join('; ') : 'token malformed' }
      if (!verdict.timestamp.ok) labels.push('timestamp evidence invalid', 'no trusted time')
    }
  }

  // 7. The instant every certificate path is validated at (§7). In order: a
  // valid timestamp token, a verified anchor's block, the device's own clock,
  // and — with none of the three — the verifier's clock, which proves nothing
  // about the capture and is only there so validation has an instant at all.
  // The verifier's own clock: it proves nothing about the capture, and is used
  // only where "when did we look" is the question — an expiry noticed since, an
  // online status list that can only speak for now.
  const clock = o.now ?? new Date()
  const instant: { at: Date, source: NonNullable<Verdict['validated_at']>['source'] } =
    verdict.timestamp?.ok === true && verdict.timestamp.gen_time ? { at: new Date(verdict.timestamp.gen_time), source: 'timestamp' }
      : verdict.anchor?.ok === true && verdict.anchor.block_time ? { at: new Date(verdict.anchor.block_time), source: 'anchor' }
        : verdict.device_clock !== undefined ? { at: new Date(verdict.device_clock), source: 'device_clock' }
          : { at: clock, source: 'verifier_clock' }
  verdict.validated_at = { instant: instant.at.toISOString(), source: instant.source }
  const trustedInstant = instant.source === 'timestamp' || instant.source === 'anchor'

  // 8. The proof level (§7): proven by the attestation (Android) or by the
  // registry leaf (iOS, App Attest goes to the registry), never by the claim.
  // §7: the claim reported in the level is one of the values this version
  // defines, or `none` — the same rule as the reference verifier's
  // claimedLevel(). The raw string stays in claimed_secure_hw, so a reader can
  // still see what the device wrote without the level ranking a name it cannot
  // interpret.
  const claimed = SECURE_HW.has(device.secure_hw as string) && PLATFORMS.has(device.platform as string) ? device.secure_hw as string : 'none'
  let proven: string = 'none'
  // The level the chain itself establishes, before revocation withdraws it.
  // *inconsistent claim* is measured against this and not against the final
  // level: a revoked chain does not contradict the claim, it retracts it, and
  // saying both would report one fact as two independent faults.
  let attested: string = 'none'
  if (Array.isArray(proof.attestation) && device.platform === 'android') {
    let ders: Bytes[] | null = null
    try { ders = (proof.attestation as string[]).map(fromBase64) } catch { ders = null }
    const a = ders ? await validateAndroidAttestation(ders, spki, { roots: o.googleRoots, revocation: o.revocation, now: instant.at, clock: o.now }) : null
    proven = a?.proven ?? 'none'
    attested = proven
    verdict.attestation = a
      ? { proven: a.proven, detail: a.checks.filter((c) => c.outcome === 'fail').map((c) => c.detail).join('; ') || 'chain to a pinned Google root', boot_state: a.bootState }
      : { proven: 'none', detail: 'attestation malformed' }
    // §6.2: the frozen snapshot answers, offline, the question the online
    // status list can no longer answer once the chain has expired. It is read
    // *after* the instant is known, because the same entries mean different
    // things before and after the capture.
    let frozen: StatusOutcome | null = null
    if (isObj(proof.attestation_status)) {
      frozen = await verifyStatus(proof.attestation_status as unknown as StatusAttachment, coreHash, o.trustedLogs ?? [], (proof.registry as Obj | undefined)?.log_id as string | undefined)
      if (!frozen.ok) {
        verdict.attestation_status = { ok: false, detail: frozen.reason }
        // An attachment that does not check out adds nothing and takes nothing
        // away: the chain's revocation is simply not established (§9's fallback
        // for an unknown source is the same outcome).
        frozen = null
      } else if (frozen.revoked === null) {
        verdict.attestation_status = { ok: true, detail: `no certificate of the chain was revoked as of ${new Date(frozen.fetchedAt).toISOString()}` }
      } else {
        const when = frozen.fetchedAt <= instant.at.getTime() ? 'at or before the capture' : 'after the capture'
        verdict.attestation_status = { ok: true, detail: `certificate ${frozen.revoked.serial} revoked ${when}${frozen.revoked.reason ? ` (${frozen.revoked.reason})` : ''}` }
      }
    }
    // Revocation is temporal, as for the device key: a certificate revoked at
    // or before the proven instant means the chain was already worthless when
    // the capture was claimed; revoked afterwards leaves the level at that
    // instant standing, because a batch key withdrawn later does not un-attest
    // what it attested.
    //
    // Both sources answer the same question and are read under the same rule.
    // The frozen snapshot carries the instant it was taken and can predate the
    // capture; Google's status list is a *current*-status list with no
    // revocation date on it, so the only instant an online answer speaks for is
    // the moment it was fetched — which is always after the capture. Reading
    // the online one as if it were dated at the capture is how the two paths
    // came to disagree: the same chain read red with network and amber without,
    // and a verdict that depends on which evidence the caller happened to hold
    // is not a verdict.
    const seen: { at: number, revoked: { serial: string, reason?: string } | null }[] = []
    if (frozen?.ok === true) seen.push({ at: frozen.fetchedAt, revoked: frozen.revoked })
    if (a && a.revocation !== 'not_checked') seen.push({ at: clock.getTime(), revoked: a.revoked ? { serial: a.revoked.serial, reason: a.revoked.status } : null })
    const atCapture = seen.find((x) => x.revoked !== null && x.at <= instant.at.getTime())
    const everRevoked = seen.find((x) => x.revoked !== null)
    if (atCapture) { proven = 'none'; labels.push('attestation key revoked') }
    else if (everRevoked) labels.push('attestation key revoked after the capture')
    // Either source *is* the revocation check, whatever it found: without one an
    // offline verifier can never reach green, which is the whole reason the
    // attachment exists. A snapshot that found a revocation checked just as
    // hard as one that cleared the chain — reporting *chain revocation not
    // checked* next to *attestation key revoked* would deny the very evidence
    // that produced the second label.
    if (seen.length === 0) labels.push('chain revocation not checked')
    // §7: a chain valid at the proven instant and expired since is not an
    // error — the verifier is late, the capture is not forged. It is only worth
    // saying when the instant is the device's own claim, because then nothing
    // independent places the capture inside the chain's validity.
    if (a?.expiredSince && !trustedInstant) labels.push('attestation chain expired, capture time not proven')
  } else if (device.platform === 'ios' && verdict.registry?.ok && verdict.registry.secure_hw === 'secureEnclave') {
    proven = 'secureEnclave'
  }
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
    const st = statement ? await verifyKeyStatus(statement, fromBase64(device.key_id as string), instant.at, o.trustedLogs ?? []) : null
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
  // attestation the §7 label is *origin not hardware-attested* alone.
  if (verdict.attestation && (rank[claimed] ?? 0) > (rank[attested] ?? 0)) labels.push('inconsistent claim')
  const inLog = verdict.registry?.ok === true && !labels.includes('registered after the declared capture')
  const ceiling: 'green' | 'amber' | 'red' = verdict.outcome === 'tampered' || labels.includes('key revoked') || labels.includes('attestation key revoked') ? 'red'
    : proven !== 'none' && inLog && verdict.outcome === 'authentic' && !labels.includes('inconsistent claim') && !labels.includes('chain revocation not checked') && !labels.includes('revocation not checked') && !labels.includes('key revoked') && !labels.includes('attestation chain expired, capture time not proven') ? 'green'
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

// device.key_id is base64url of SHA-256(SPKI) in the proof; the log's leaf spells the same hash in hex.
const hexKeyId = (b64: string): string => { try { return toHex(fromBase64(b64)) } catch { return '' } }
