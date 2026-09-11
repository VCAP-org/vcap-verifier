import type { Verdict } from 'vcap-verify-core'

/**
 * The verdict as a person reads it.
 *
 * Two rules, both learned from the label table in §8. Say the outcome first
 * and in one word, because that is what somebody came for. Then say what is
 * *missing* rather than only what passed: a proof is a set of claims with
 * evidence attached, and a reader who is not told which evidence is absent
 * will assume it was all there.
 */
const CEILING: Record<string, string> = {
  green: 'green — every question §7 asks has an answer',
  amber: 'amber — verified, with evidence missing (below)',
  red: 'red'
}

/** What a label means for somebody who has not read the spec. */
const MEANING: Record<string, string> = {
  'no trusted time': 'only the device\'s own clock says when this was taken',
  'trusted time not evaluated': 'a timestamp is attached and no TSA root was pinned to check it (--tsa-root)',
  'timestamp evidence invalid': 'the attached timestamp does not hold up',
  'not anchored': 'nothing places this before a block on a public chain',
  'anchoring not verified': 'the anchor\'s path is consistent; the chain was not consulted',
  'anchor evidence invalid': 'the attached anchor does not hold up',
  'key not in transparency log': 'nobody can confirm this signing key was registered',
  'log not trusted': 'the proof names a transparency log this verifier does not follow (--log)',
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
  'watermark not evaluated': 'a watermark is declared and this verifier ships no detector',
  'segment content not recomputed': 'the segment hashes were taken from the proof, not recomputed from the file',
  'inconsistent claim': 'the device claims a stronger level than its evidence proves',
  'registered after the declared capture': 'the key was registered after the time this capture claims',
  'attestation chain expired, capture time not proven': 'the attestation has expired and only the device places the capture inside its validity',
  'attestation key revoked': 'a certificate in the attestation chain was revoked at or before the capture',
  'attestation key revoked after the capture': 'a certificate was revoked later, which does not un-attest this capture',
  'key revoked': 'the log says this key was revoked at the capture time',
  'sidecar differs': 'the sidecar and the trailer carry different proofs',
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
    lines.push(`  ceiling   ${CEILING[verdict.level.ceiling] ?? verdict.level.ceiling}`)
  }
  if (verdict.validated_at) {
    lines.push(`  taken     before ${verdict.validated_at.instant} (from ${source(verdict.validated_at.source)})`)
  }
  if (verdict.location && verdict.location.level !== 'none') lines.push(`  position  ${position(verdict)}`)
  if (verdict.core_hash) lines.push(`  core      ${verdict.core_hash}`)
  if (verdict.segments) {
    const verified = verdict.segments.verified
    const recomputed = verdict.content?.recomputed === true
    lines.push(`  segments  ${verified.length} verified${recomputed ? ', hashes recomputed from the file' : ''}`)
  }
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
