import { ceilingLabels } from 'vcap-verify-core'
import type { ContentCredentials, ProofSource, Verdict } from 'vcap-verify-core'

/**
 * The verdict as a person reads it.
 *
 * Two rules, both learned from the label table in §8. Say the outcome first
 * and in one word, because that is what somebody came for. Then say what is
 * *missing* rather than only what passed: a proof is a set of claims with
 * evidence attached, and a reader who is not told which evidence is absent
 * will assume it was all there.
 */
// The ceiling's words when no §7 label names it — an amber *verified clip*,
// capped by its outcome. Otherwise the line names the labels that set it
// (`ceilingLabels`), because "amber" over a list of eight labels, most of
// which move nothing, left the reader to guess which ones did.
const CEILING: Record<string, string> = {
  green: 'every question §7 asks has an answer',
  amber: 'verified, with evidence missing (below)'
}

/** What a label means for somebody who has not read the spec. */
const MEANING: Record<string, string> = {
  'no trusted time': 'only the device\'s own clock says when this was taken',
  'trusted time not evaluated': 'a timestamp is attached and no authority this run trusts issued it (--show-trust lists the ones it does; --tsa-root adds)',
  'timestamp evidence invalid': 'the attached timestamp does not hold up',
  'not anchored': 'nothing places this before a block on a public chain',
  'anchoring not verified': 'the anchor\'s path is consistent; the chain was not read (--offline, or no endpoint answered)',
  'anchor evidence invalid': 'the attached anchor does not hold up',
  'key not in transparency log': 'nobody can confirm this signing key was registered',
  'log not trusted': 'the proof names a transparency log this verifier does not follow (--show-trust lists the ones it does; --trust and --log add)',
  'registry evidence invalid': 'the attached registration does not hold up',
  'revocation not checked': 'the key was registered; whether it still is was not asked',
  'chain revocation not checked': 'the attestation certificates\' revocation was not established',
  'origin not hardware-attested': 'nothing proves the key lives in secure hardware',
  'integrity unevaluated': 'no statement about the state of the device',
  'integrity evidence invalid': 'the attached device-integrity statement does not hold up',
  // The four §6.2 verdicts, relayed. `failed` is the reason to show any of
  // them: the file is authentic *and* the platform said the device was
  // compromised, and a reader shown nothing takes no news for good news.
  'integrity hardware': 'the platform reported the device as hardware-backed and intact',
  'integrity basic': 'the platform reported a device that passes only basic checks',
  'integrity failed': 'the platform reported this device as failing its integrity checks',
  'no watermark': 'no watermark was looked for',
  'watermark not evaluated': 'a watermark is declared and no detection of it could be read (--watermark)',
  // §8's three non-red outcomes for a declared watermark. *Matched* is a
  // label and never a verdict: the verdict still comes from `sig`, and a mark
  // with no valid signature is *origin traced*, never authentic.
  'watermark matched': 'a detector read the declared id out of the pixels; the verdict still comes from the signature',
  // One label, two ways to get there: nothing decoded, or something decoded
  // below the agreement `video-rep-v1` requires before an id may be believed.
  // Neither licenses a claim about an id, and neither weakens the signature.
  'watermark not recovered': 'the payload did not decode, or its id was refused as unresolvable — the normal outcome of heavy re-compression, and it weakens nothing',
  'segment content not recomputed': 'the segment hashes were taken from the proof, not recomputed from the file',
  'inconsistent claim': 'the device claims a stronger level than its evidence proves',
  'registered after the declared capture': 'the key was registered after the time this capture claims',
  'attestation chain expired, capture time not proven': 'the attestation has expired and only the device places the capture inside its validity',
  'attestation key revoked': 'a certificate in the attestation chain was revoked at or before the capture',
  'attestation key revoked after the capture': 'a certificate was revoked later, which does not un-attest this capture',
  'key revoked': 'the log says this key was revoked at the capture time',
  'sidecar differs': 'the sidecar carries a different proof from the one this verdict read',
  'manifest copy differs': 'the Content Credentials carry a different proof from the trailer; the trailer decides',
  'capture time not declared': 'nothing in the core dates the capture, so the registration cannot be placed before it',
  'registered after the trusted time': 'the key was logged after the instant a timestamp authority placed the capture at',
  'attestation evidence invalid': 'the attached attestation chain breaks a rule it must satisfy (roots, CA issuers, the extension in the leaf only)',
  'attestation app not admitted': 'the key was made by an app build the log does not declare',
  'attestation app not checked': 'the log declares no app builds, or the attestation names no app, so the app that made the key is unknown',
  'level from registry records': 'the Secure Enclave level is the registry\'s word — our records — and nothing in the file shows it',
  // §7.1: the position level is on its own axis and never "guaranteed". The
  // words keep the spec's distinction between the device's word (declared),
  // the registry's word about an operator's cell-level answer (corroborated),
  // and evidence this version cannot read.
  'location declared only': 'the device signed the coordinates and nothing else vouches for them',
  'location corroborated': 'a registry this verifier trusts attests that an operator\'s check agreed with the declared position — the SIM\'s area, not the camera\'s',
  'location contradicted': 'the operator\'s check disagreed with the declared position; the file is as authentic as before, where it says it was taken is less believable',
  'location corroboration not verified': 'no trusted registry key signed the attached corroboration over this proof (--log): a signer this verifier does not follow, or a statement about another proof',
  'location corroboration not evaluated': 'the attached corroboration could not be read: no registry key given (--log), a method this verifier does not know, or no position to corroborate',
  'location corroboration evidence invalid': 'the attached corroboration is signed by a trusted registry and does not parse',
  'location evidence not evaluated': 'the core carries device-side position evidence of a kind this verifier does not weigh',
  'location claimed above evidence': 'the device claims a stronger position level than its evidence reaches'
}

export const render = (path: string, verdict: Verdict): string => {
  const lines: string[] = []
  lines.push(`${path}`)
  lines.push(`  outcome   ${verdict.outcome}${verdict.reason ? ` — ${verdict.reason}` : ''}`)
  if (verdict.level) {
    lines.push(`  level     claimed ${verdict.level.claimed}, proven ${verdict.level.proven}`)
    const why = ceilingLabels(verdict)
    const words = why.length > 0 ? why.join(', ') : CEILING[verdict.level.ceiling]
    lines.push(`  ceiling   ${verdict.level.ceiling}${words ? ` — ${words}` : ''}`)
  }
  if (verdict.validated_at) {
    lines.push(`  taken     before ${verdict.validated_at.instant} (from ${source(verdict.validated_at.source)})`)
  }
  if (verdict.location && verdict.location.level !== 'none') lines.push(`  position  ${position(verdict)}`)
  if (verdict.core_hash) lines.push(`  core      ${verdict.core_hash}`)
  // Where the proof sat is not evidence (§3.1), so this is a line and never a
  // label — and the trailer, the ordinary case, goes without saying.
  if (verdict.proof_source && verdict.proof_source.kind !== 'trailer') lines.push(`  proof     read from ${proofSource(verdict.proof_source)}`)
  if (verdict.content_credentials) lines.push(...credentials(verdict.content_credentials))
  // The registry line exists because the label it replaces used to be the only
  // trace of this check. A reader who watched *log not trusted* disappear is
  // owed the sentence that took its place — and the reminder of whose log it
  // was, which `--show-trust` answers and this line must not pretend to.
  if (verdict.registry) {
    lines.push(`  log       ${verdict.registry.ok ? `${verdict.registry.detail} — in a log this verifier trusts (--show-trust says which, and who runs it)` : verdict.registry.detail}`)
  }
  // The anchor's own sentence: on chain, not read and why, or not holding up.
  if (verdict.anchor) lines.push(`  anchor    ${verdict.anchor.detail}`)
  if (verdict.segments) {
    const verified = verdict.segments.verified
    const recomputed = verdict.content?.recomputed === true
    lines.push(`  segments  ${verified.length} verified${recomputed ? ', hashes recomputed from the file' : ''}`)
  }
  if (verdict.watermark) lines.push(`  watermark ${verdict.watermark.result.replace('_', ' ')} — ${verdict.watermark.detail}${figures(verdict)}`)
  if (verdict.labels.length > 0) {
    lines.push('  missing or worth knowing')
    for (const label of verdict.labels) {
      lines.push(`    · ${label}${MEANING[label] ? `: ${MEANING[label]}` : ''}`)
    }
  }
  if (verdict.not_evaluated.length > 0) {
    lines.push(`  ignored   ${verdict.not_evaluated.join(', ')} (fields this verifier does not know)`)
  }
  return lines.join('\n')
}

/** Where a proof was read, in words. */
export const proofSource = (s: ProofSource): string => {
  if (s.kind === 'trailer') return 'the trailer'
  if (s.kind === 'sidecar') return 'the sidecar'
  return s.depth === 0
    ? `the active manifest of the Content Credentials (${s.manifest})`
    : `the Content Credentials, ${s.depth} step${s.depth === 1 ? '' : 's'} up the parentOf chain (${s.manifest}) — the proof of a source capture`
}

/**
 * The manifest store in a line of its own, beside the verdict and never part
 * of it: nothing C2PA says reaches the outcome, and no C2PA signature was
 * checked, which the line says every time.
 */
const credentials = (cc: ContentCredentials): string[] => {
  const where = cc.store === 'embedded' ? 'in the file' : 'from --c2pa'
  if (cc.unread) return [`  c2pa      Content Credentials ${where}, not read: ${cc.unread}`]
  const generator = cc.active?.generator ? `, claim generator ${cc.active.generator} (its own word)` : ''
  const sealed = cc.sealed_with_capture ? '; sealed with the capture' : ''
  return [
    `  c2pa      Content Credentials ${where}: ${cc.manifests} manifest${cc.manifests === 1 ? '' : 's'}, active ${cc.active?.label}${generator}${sealed} — C2PA signature not checked`,
    ...cc.notes.map((note) => `    · ${note}`)
  ]
}

/**
 * What the layout defines to show next to a decode: the agreement between the
 * eight copies for `video-rep-v1`, the bits the block code corrected for
 * `photo-bch-v3`, and always the model that looked — a detection from an
 * unnamed build is not reproducible.
 */
const figures = (verdict: Verdict): string => {
  const w = verdict.watermark as NonNullable<Verdict['watermark']>
  const parts = [
    w.agreement !== undefined ? `agreement ${(w.agreement * 100).toFixed(0)}%` : null,
    w.corrected_bits !== undefined ? `${w.corrected_bits} bits corrected` : null,
    w.frames_sampled !== undefined ? `${w.frames_sampled} frame${w.frames_sampled === 1 ? '' : 's'}${w.sampling ? ` (${w.sampling.strategy})` : ''}` : null,
    w.model_version ?? null
  ].filter((p) => p !== null)
  return parts.length > 0 ? ` [${parts.join(', ')}]` : ''
}

/**
 * §7.1 in one line: the level reached, the coordinates the device signed, and
 * — when a corroboration was read — the registry's word about the operator's
 * answer, in the spec's terms: *the registry attests*, never "verified by the
 * operator", and always with the radius, because a match means the same
 * area and never the same point.
 */
const position = (verdict: Verdict): string => {
  const { level, declared } = verdict.location as NonNullable<Verdict['location']>
  const where = declared
    ? `${(declared.lat_udeg / 1e6).toFixed(6)}, ${(declared.lon_udeg / 1e6).toFixed(6)}${declared.acc_cm !== undefined ? ` ±${(declared.acc_cm / 100).toFixed(1)} m` : ''}${declared.source ? ` (${declared.source})` : ''}`
    : 'no coordinates'
  const corroboration = verdict.location_corroboration
  if (level === 'corroborated' && corroboration?.ok) return `corroborated — ${corroboration.detail}; the device signed ${where}`
  return `${level} — the device signed ${where}${corroboration?.ok ? `; ${corroboration.detail}` : ''}`
}

/** Where the instant came from, in words, because it is the difference between a claim and a fact. */
const source = (from: string): string => ({
  timestamp: 'an RFC 3161 timestamp — independent',
  anchor: 'a block on a public chain — independent',
  device_clock: 'the device\'s own clock — a claim',
  verifier_clock: 'this verifier\'s clock, the proof declares no time'
}[from] ?? from)
