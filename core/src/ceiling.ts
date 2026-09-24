import type { Verdict } from './verify.js'

/**
 * §7's "label shown" column: the words that name the verdict's light.
 *
 * `verify` computes `level.ceiling` and emits every label it found, but a
 * reader of a surface needs the ones that **set** the ceiling beside it —
 * "amber" alone says nothing, and the chips under a verdict mix the ceiling's
 * reasons with labels that move nothing (*no trusted time*, *not anchored*).
 * This reads them back out of `labels`, in the core's own words; it decides
 * nothing, so it cannot disagree with the ceiling it explains.
 */

/** The labels that make a ceiling red (§7: a key or a chain revoked at the capture). */
const RED = ['key revoked', 'attestation key revoked']

/**
 * The labels that hold a ceiling at amber. *log not trusted* is here because
 * it is the one registry failure that emits no *key not in transparency log*
 * beside it, and it still keeps the key out of the log §7 asks for.
 */
const AMBER = [
  'origin not hardware-attested',
  'key not in transparency log',
  'log not trusted',
  'capture time not declared',
  'registered after the declared capture',
  'registered after the trusted time',
  'revocation not checked',
  'chain revocation not checked',
  'attestation chain expired, capture time not proven',
  'attestation app not admitted',
  'attestation app not checked',
  'inconsistent claim',
  'integrity failed'
]

/** A green ceiling has no fault to name, so §7 names what was proven. */
const SEALED: Record<string, string> = {
  strongbox: 'sealed in secure hardware',
  tee: 'sealed in the TEE',
  secureEnclave: 'sealed in the Secure Enclave (app-attested)'
}

/**
 * The §7 labels that set `verdict.level.ceiling`, in §7's order. Empty when
 * the verdict has no level (a proof that never reached the signature layer's
 * end) or when nothing in `labels` explains it — an amber *verified clip* is
 * capped by its outcome, which the surface already prints.
 */
export const ceilingLabels = (verdict: Verdict): string[] => {
  const level = verdict.level
  if (!level) return []
  if (level.ceiling === 'green') return SEALED[level.proven] ? [SEALED[level.proven] as string] : []
  if (level.ceiling === 'red') return RED.filter((label) => verdict.labels.includes(label))
  const named = AMBER.filter((label) => verdict.labels.includes(label))
  // §7: green needs a token or a verified anchor for the instant. *no trusted
  // time* names the ceiling only when nothing else trusted dated the capture —
  // beside a verified anchor it is a missing token and caps nothing.
  const untrusted = verdict.validated_at?.source === 'device_clock' || verdict.validated_at?.source === 'verifier_clock'
  return untrusted && verdict.labels.includes('no trusted time') ? [...named, 'no trusted time'] : named
}
