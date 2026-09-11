import { type Bytes, concat, fromBase64, utf8 } from './bytes.js'
import { importP256Spki, verifyEs256 } from './es256.js'
import { jcs, type Json } from './jcs.js'
import type { TrustedLog } from './registry.js'

/**
 * Spec §7.1, the position level — a second level on a second axis. §7 says
 * how strong the *origin* claim is; this says how much the *coordinates* in
 * the core are worth, and the two never mix: nothing here moves a ceiling or
 * turns a verdict green or red.
 *
 * - `none`: the core declares no position. A position is two coordinates, so
 *   a `location` without both declares nothing, whatever its `level` says.
 * - `declared`: the device signed `lat_udeg` and `lon_udeg`. The device says
 *   so, and the OS is the only thing between the app and any coordinates it
 *   likes (`threat-model.md` §5.7) — which is why this is not called verified.
 * - `corroborated`: a `location_corroboration` attachment (§6.2), signed by a
 *   registry key this verifier trusts over this core hash, relays an
 *   operator-side check that agreed with the declared position. The
 *   registry's word about the operator's answer, and shown in those terms.
 * - `authenticated`: reserved. No evidence kind reaches it in this version,
 *   so this module never returns it; a core claiming it is *claimed above
 *   evidence*.
 *
 * The claim in the core never raises the level: `location.level` is what the
 * device says, exactly as `device.secure_hw` is.
 */
export type PositionLevel = 'none' | 'declared' | 'corroborated' | 'authenticated'

const LEVELS: PositionLevel[] = ['none', 'declared', 'corroborated', 'authenticated']
const rank = (level: PositionLevel): number => LEVELS.indexOf(level)

export interface LocationCorroboration {
  method: string
  result: string
  radius_m?: number
  at: number
  operator_ref?: string
  sig: string
}

/** §6.2's methods, each a CAMARA API the registry may have called. Extensible (§9). */
const METHODS = new Set(['camara-location-verification', 'camara-number-verification', 'camara-sim-swap'])
/** Not extensible: `result` decides the level, so a value outside this set under a valid signature is evidence that does not parse. */
const RESULTS = new Set(['match', 'no-match', 'unknown'])

const SEPARATOR = utf8('vcap/1.0/location')

/**
 * §6.2: `"vcap/1.0/location" ‖ core_hash ‖ JCS(A \ sig)`. JCS of the body,
 * not a fixed layout, so a later minor can add a member and this verifier —
 * which canonicalizes every member it sees — still verifies. The result sits
 * inside the message: `no-match` cannot become `match` in transit.
 */
export const corroborationMessage = (coreHash: Bytes, attachment: { [key: string]: Json }): Bytes => {
  const { sig: _sig, ...body } = attachment
  return concat(SEPARATOR, coreHash, jcs(body))
}

export type CorroborationOutcome =
  | { ok: true, method: string, result: 'match' | 'no-match' | 'unknown', radiusM?: number, at: number }
  /**
   * Three failures §8 keeps apart. `evaluated: false` is evidence this
   * verifier cannot read — no registry key held, a method it does not know —
   * and reads *not evaluated*. `trusted: false` is a signature no trusted key
   * made — *not verified*, covering both a signer nobody follows and a
   * genuine statement about another proof, the same bytes from here.
   * `trusted: true` is a verified signature over content outside §6.2 —
   * *evidence invalid*.
   */
  | { ok: false, reason: string, evaluated: boolean, trusted: boolean }

/**
 * The attachment does not name its key, so every trusted log key is tried, as
 * for `integrity`: the signature that verifies identifies the key.
 */
export const verifyLocationCorroboration = async (a: LocationCorroboration, coreHash: Bytes, trusted: TrustedLog[]): Promise<CorroborationOutcome> => {
  if (trusted.length === 0) return { ok: false, reason: 'no trusted registry key held', evaluated: false, trusted: false }
  if (typeof a.method !== 'string' || !METHODS.has(a.method)) return { ok: false, reason: `unknown corroboration method ${String(a.method)}`, evaluated: false, trusted: false }
  let sig: Bytes
  try { sig = fromBase64(a.sig) } catch { return { ok: false, reason: 'signature malformed', evaluated: true, trusted: false } }
  const message = corroborationMessage(coreHash, a as unknown as { [key: string]: Json })
  let signed = false
  for (const log of trusted) {
    const key = await importP256Spki(log.spki)
    if (key && await verifyEs256(key, message, sig)) { signed = true; break }
  }
  if (!signed) return { ok: false, reason: 'no trusted registry key signed this corroboration over this proof', evaluated: true, trusted: false }

  // From here the registry really said this; the question is whether it parses.
  if (typeof a.result !== 'string' || !RESULTS.has(a.result)) return { ok: false, reason: `result ${String(a.result)} is outside match, no-match, unknown`, evaluated: true, trusted: true }
  if (!Number.isInteger(a.at) || a.at < 0) return { ok: false, reason: 'at is not an instant', evaluated: true, trusted: true }
  const radius = a.radius_m
  const hasRadius = Number.isInteger(radius) && (radius as number) >= 1
  // A zone check without its zone corroborates nothing anyone can read.
  if (a.method === 'camara-location-verification' && !hasRadius) return { ok: false, reason: 'camara-location-verification without radius_m', evaluated: true, trusted: true }
  return { ok: true, method: a.method, result: a.result as 'match' | 'no-match' | 'unknown', at: a.at, ...(hasRadius ? { radiusM: radius as number } : {}) }
}

/** The §6.1 claim as the device wrote it; every member optional but `level`. */
export interface DeclaredPosition {
  lat_udeg: number
  lon_udeg: number
  alt_cm?: number
  acc_cm?: number
  source?: string
  at?: number
}

export interface PositionOutcome {
  claimed: PositionLevel
  level: PositionLevel
  declared?: DeclaredPosition
  corroboration?: CorroborationOutcome
  labels: string[]
}

const isObj = (v: unknown): v is { [key: string]: Json } => typeof v === 'object' && v !== null && !Array.isArray(v)

/**
 * §7.1 in one place: the level the core claims, the level the evidence
 * reaches, and the §8 labels that say why they differ. Labels come back
 * unsorted; the verdict sorts them with the rest.
 */
export const positionLevel = async (location: unknown, corroboration: unknown, coreHash: Bytes, trusted: TrustedLog[]): Promise<PositionOutcome> => {
  const claim = isObj(location) ? location : null
  const attachment = isObj(corroboration) ? corroboration : null
  // Two coordinates or nothing: without both there is no position on any map,
  // and an attachment about it has nothing to corroborate (vector 84).
  if (!claim || !Number.isInteger(claim.lat_udeg) || !Number.isInteger(claim.lon_udeg)) {
    return { claimed: 'none', level: 'none', labels: attachment ? ['location corroboration not evaluated'] : [] }
  }
  const labels: string[] = []
  const declared: DeclaredPosition = { lat_udeg: claim.lat_udeg as number, lon_udeg: claim.lon_udeg as number }
  if (Number.isInteger(claim.alt_cm)) declared.alt_cm = claim.alt_cm as number
  if (Number.isInteger(claim.acc_cm)) declared.acc_cm = claim.acc_cm as number
  if (typeof claim.source === 'string') declared.source = claim.source
  if (Number.isInteger(claim.at)) declared.at = claim.at as number

  // `level` is not extensible (§9): a word this version does not know is read
  // as `declared`, the level any signed position reaches on its own — treated,
  // not refused, as §7 does with an unknown `secure_hw` (vector 83).
  const claimed: PositionLevel = typeof claim.level === 'string' && LEVELS.includes(claim.level as PositionLevel) && claim.level !== 'none' ? claim.level as PositionLevel : 'declared'
  let level: PositionLevel = 'declared'
  let outcome: CorroborationOutcome | undefined
  if (attachment) {
    outcome = await verifyLocationCorroboration(attachment as unknown as LocationCorroboration, coreHash, trusted)
    if (!outcome.ok) {
      labels.push(!outcome.evaluated ? 'location corroboration not evaluated' : outcome.trusted ? 'location corroboration evidence invalid' : 'location corroboration not verified')
    } else if (outcome.result === 'match') {
      level = 'corroborated'
    } else if (outcome.result === 'no-match') {
      // The operator's check disagreed. Shown, never a ceiling: the file is as
      // authentic as before, what is less believable is where it says it was
      // taken (vector 79). `unknown` is silence.
      labels.push('location contradicted')
    }
  }
  // Device-side evidence kinds arrive with a later minor; this version weighs
  // none, so a non-empty array is listed rather than read (vector 81).
  if (Array.isArray(claim.evidence) && claim.evidence.length > 0) labels.push('location evidence not evaluated')
  labels.push(level === 'corroborated' ? 'location corroborated' : 'location declared only')
  if (rank(claimed) > rank(level)) labels.push('location claimed above evidence')
  return { claimed, level, declared, labels, ...(outcome ? { corroboration: outcome } : {}) }
}
