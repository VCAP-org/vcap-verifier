import type { Verdict, WatermarkOutcome } from 'vcap-verify-core'

/**
 * Everything the page prints. The rule for every string here: the outcome and
 * the labels are the specification's words, copied and not paraphrased — a
 * relabelled verdict is a different verdict — and the sentences around them
 * exist only to say what a word means to a reader who has not read §8.
 */

export const escape = (s: string): string =>
  s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string))

export const COLOR: Record<Verdict['outcome'], string> = {
  authentic: 'green', verified_clip: 'amber', tampered: 'red', nested_proof: 'amber',
  corrupted_proof: 'red', no_proof_found: 'grey', unsupported_format_version: 'grey'
}
export const TITLE: Record<Verdict['outcome'], string> = {
  authentic: 'Authentic — signed at capture, file complete',
  verified_clip: 'Verified clip — signed frames of a longer original',
  tampered: 'Tampered — the file or its proof was altered after sealing',
  nested_proof: 'Nested proof — a sealed file was sealed again; the outer proof is not authoritative',
  corrupted_proof: 'Corrupted proof — the trailer is damaged',
  no_proof_found: 'No proof found',
  unsupported_format_version: 'Unsupported format version'
}

const SOURCE: Record<string, string> = {
  timestamp: 'proven by the timestamp token',
  anchor: 'proven by the anchored block',
  device_clock: 'the device\'s own clock, not proven',
  verifier_clock: 'this browser\'s clock; the proof declares no time'
}

/**
 * §7.1 in one sentence, on its own line because it is on its own axis: the
 * position level never colours the verdict. The words are the spec's — the
 * device's word is *declared*, the registry's word about an operator's
 * cell-level answer is *corroborated*, shown as *the registry attests* and
 * never as "verified by the operator", always with the radius. "Guaranteed"
 * is not a level and does not appear.
 */
const POSITION: Record<string, string> = {
  declared: 'Position declared only',
  corroborated: 'Position corroborated',
  authenticated: 'Position authenticated'
}
const coordinates = (v: Verdict): string => {
  const declared = v.location?.declared
  return declared
    ? `${(declared.lat_udeg / 1e6).toFixed(6)}, ${(declared.lon_udeg / 1e6).toFixed(6)}${declared.acc_cm !== undefined ? ` ±${(declared.acc_cm / 100).toFixed(1)} m` : ''}${declared.source ? ` (${escape(declared.source)})` : ''}`
    : 'no coordinates'
}
const position = (v: Verdict): string => {
  if (!v.location || v.location.level === 'none') return ''
  const said = v.location_corroboration?.ok ? `${escape(v.location_corroboration.detail)}; ` : ''
  // Only the device's word, and no registry statement read: say so, because a
  // reader shown coordinates on a green verdict assumes somebody checked them.
  const alone = v.location.level === 'declared' && !v.location_corroboration?.ok ? '; nothing else vouches for it' : ''
  return `<p class="position"><strong>${POSITION[v.location.level] ?? escape(v.location.level)}</strong> — ${said}the device signed ${coordinates(v)}${alone}.</p>`
}

/** The §8 outcome in the spec's own spelling, with the sentence the core wrote for it. */
const watermarkLine = (w: WatermarkOutcome): string =>
  `${w.result.replace(/_/g, ' ')} — ${w.detail}${figures(w)}`

/**
 * What the layout defines to show next to a decode: the agreement between the
 * eight copies for `video-rep-v1`, the bits the block code corrected for
 * `photo-bch-v3`, and always the model that looked — a detection from an
 * unnamed build is not reproducible.
 */
const figures = (w: WatermarkOutcome): string => {
  const parts = [
    w.agreement !== undefined ? `agreement ${(w.agreement * 100).toFixed(0)}%` : null,
    w.corrected_bits !== undefined ? `${w.corrected_bits} bits corrected` : null,
    w.frames_sampled !== undefined ? `${w.frames_sampled} frame${w.frames_sampled === 1 ? '' : 's'}${w.sampling ? ` (${w.sampling.strategy})` : ''}` : null,
    w.model_version ?? null
  ].filter((p) => p !== null)
  return parts.length > 0 ? ` [${parts.join(', ')}]` : ''
}

export const card = (name: string, v: Verdict): string => {
  const lines = [
    ...v.labels.map((l) => `<li>${escape(l)}</li>`),
    ...v.not_evaluated.map((k) => `<li>not evaluated: <code>${escape(k)}</code></li>`)
  ]
  const details = [
    v.claimed_secure_hw ? `<li>claimed level: <code>${escape(v.claimed_secure_hw)}</code> (attestation not evaluated by this page)</li>` : '',
    v.device_clock ? `<li>declared capture time: ${new Date(v.device_clock).toISOString()} (device clock, not trusted time)</li>` : '',
    // §7: which clock the certificate paths were validated at. A reader who is
    // not told cannot tell a capture time proven by a token from one the device
    // asserted about itself.
    v.validated_at ? `<li>validated at: ${escape(v.validated_at.instant)} (${escape(SOURCE[v.validated_at.source] ?? v.validated_at.source)})</li>` : '',
    v.segments ? `<li>segments verified: ${v.segments.verified.length ? v.segments.verified.join(', ') : 'none'}</li>` : '',
    v.segments?.contradicted?.length ? `<li>segments whose frames are not the signed frames: ${v.segments.contradicted.join(', ')}</li>` : '',
    // §5 recomputation either happened or did not, and the page says which:
    // "every segment verifies" means much less when nothing read the frames.
    v.content ? `<li>segment content: ${v.content.recomputed ? 'recomputed from the container' : 'not recomputed'} (${escape(v.content.detail)})</li>` : '',
    v.watermark ? `<li>watermark: ${escape(watermarkLine(v.watermark))}</li>` : '',
    v.registry ? `<li>transparency log: ${escape(v.registry.detail)}</li>` : '',
    v.attestation_status ? `<li>chain revocation: ${escape(v.attestation_status.detail)}</li>` : '',
    // The device key's own standing, which is the one thing this page cannot
    // establish from the file: it ships with no log to ask, so it says so
    // rather than leaving the reader to assume it was checked.
    v.key_status ? `<li>key revocation: ${escape(v.key_status.detail)}</li>` : '',
    v.anchor ? `<li>anchor: ${escape(v.anchor.detail)}</li>` : '',
    v.core_hash ? `<li>proof identity: <code>${v.core_hash}</code></li>` : '',
    v.reason ? `<li>${escape(v.reason)}</li>` : ''
  ].filter(Boolean)
  return `<div class="verdict ${COLOR[v.outcome]}">
    <h2>${escape(TITLE[v.outcome])}</h2>
    <div class="muted">${escape(name)}</div>
    ${position(v)}
    ${lines.length ? `<ul>${lines.join('')}</ul>` : ''}
    ${details.length ? `<details><summary>details</summary><ul>${details.join('')}</ul></details>` : ''}
  </div>`
}

/**
 * The side-by-side table: one row per piece of evidence, read out of each
 * verdict. A row exists when at least one of the two files has something to
 * say about it, so what is missing from the copy is visible next to what the
 * original carried — which is the whole point of putting them side by side.
 */
const SIGNATURE: Record<Verdict['outcome'], string> = {
  authentic: 'verifies over the signed core',
  verified_clip: 'verifies over the signed core',
  tampered: 'does not verify: these are not the signed bytes',
  nested_proof: 'verifies, for an outer proof that is not authoritative',
  corrupted_proof: 'not reached: the trailer is damaged',
  no_proof_found: 'nothing to check: no proof in the file',
  unsupported_format_version: 'not reached: this verifier does not implement the format version'
}

/** Named, because the side-by-side treats this one row differently. */
const WATERMARK_FIELD = 'watermark (§8)'

interface Field {
  name: string
  read: (v: Verdict) => string | null
}

const FIELDS: Field[] = [
  { name: 'verdict', read: (v) => v.outcome },
  { name: 'signature', read: (v) => SIGNATURE[v.outcome] },
  // The identity of the proof: two files carrying the same core hash carry the
  // same signed claim, and a copy that carries none carries no claim at all.
  { name: 'proof identity', read: (v) => v.core_hash ?? null },
  { name: 'declared capture time', read: (v) => v.device_clock ? new Date(v.device_clock).toISOString() : null },
  // Evidence only, never the label that says a field is absent. *No trusted
  // time* on both sides would otherwise print as something the copy lost,
  // when neither file ever had it; what each file is missing is on its own
  // card, where it belongs.
  { name: 'trusted time', read: (v) => v.timestamp?.detail ?? null },
  { name: 'transparency log', read: (v) => v.registry?.detail ?? null },
  { name: 'hardware attestation', read: (v) => v.attestation?.detail ?? null },
  { name: WATERMARK_FIELD, read: (v) => v.watermark ? watermarkLine(v.watermark) : null },
  { name: 'position level', read: (v) => v.location && v.location.level !== 'none' ? `${v.location.level} — ${coordinates(v)}` : null },
  { name: 'proof level (§7)', read: (v) => v.level ? `claimed ${v.level.claimed}, proven ${v.level.proven}, ceiling ${v.level.ceiling}` : null }
]

/**
 * What happened to a piece of evidence between the original and the copy.
 *
 * `sameProof` is the distinction that keeps this honest: when both files carry
 * the same `core_hash` they carry the same signed claim, and a field missing
 * from the copy's verdict was not lost by the file — the verdict stopped
 * before reaching it, which is what *tampered* does. Calling that "lost" would
 * report a second failure where there is one.
 */
const change = (copy: string | null, original: string | null, sameProof: boolean): { word: string, css: string } => {
  if (copy !== null && original !== null) return copy === original ? { word: 'unchanged', css: 'kept' } : { word: 'differs', css: 'differs' }
  if (original !== null) return sameProof ? { word: 'not reported', css: '' } : { word: 'lost', css: 'lost' }
  return { word: 'only in the copy', css: 'differs' }
}

export const comparison = (copy: { name: string, verdict: Verdict }, original: { name: string, verdict: Verdict }, traced: WatermarkOutcome | null = null): string => {
  // The same signed claim on both sides: what the copy's verdict does not
  // report was not lost with the bytes.
  const sameProof = copy.verdict.core_hash !== undefined && copy.verdict.core_hash === original.verdict.core_hash
  const rows = FIELDS.map((field) => {
    // A copy with no proof of its own declares no watermark, so §8 never runs
    // inside its verdict. What was read out of its pixels was read against the
    // *original's* ids, and the row says which — otherwise the table would
    // report a mark as lost while the block below it reports the same mark as
    // found.
    const against = traced !== null && field.name === WATERMARK_FIELD
    const mine = against ? watermarkLine(traced) : field.read(copy.verdict)
    const theirs = field.read(original.verdict)
    if (mine === null && theirs === null) return ''
    const { word, css } = against
      ? { word: 'read against the original', css: traced.result === 'matched' ? 'kept' : 'differs' }
      : change(mine, theirs, sameProof)
    return `<tr class="${css}">
      <th scope="row">${escape(field.name)}</th>
      <td>${mine === null ? `<span class="absent">${sameProof ? 'not evaluated' : 'absent'}</span>` : `<code>${escape(mine)}</code>`}</td>
      <td>${theirs === null ? '<span class="absent">absent</span>' : `<code>${escape(theirs)}</code>`}</td>
      <td class="change">${word}</td>
    </tr>`
  }).filter(Boolean)
  return `<table class="compare">
    <caption>What the copy still carries, next to what the original carries</caption>
    <thead><tr><th scope="col">evidence</th><th scope="col">${escape(copy.name)}</th><th scope="col">${escape(original.name)}</th><th scope="col">change</th></tr></thead>
    <tbody>${rows.join('')}</tbody>
  </table>`
}

/**
 * The watermark read against the **original's** signed ids, for a copy whose
 * own signature no longer says anything. This is the piece that holds when the
 * signature does not — a re-compressed file loses the trailer and keeps the
 * pixels — and it is also the piece most easily read backwards, so the wording
 * is fixed: a mark without a valid signature is **origin traced**, never
 * authentic. The verdict card above it stays exactly what the signature layer
 * said, and this block never changes its colour.
 *
 * The comparison itself is the core's (`evaluateWatermark` against the claim
 * the original's signed core produced), so the ids come from bytes a device
 * signed and not from anything the detection chose to call itself.
 */
export const trace = (outcome: WatermarkOutcome): string => {
  const headline: Record<WatermarkOutcome['result'], string> = {
    matched: 'Origin traced — the copy\'s pixels carry the id the original declares',
    contradicted: 'A different id — the pixels carry a mark, and it is not the original\'s',
    not_recovered: 'Nothing recovered — the watermark did not survive either',
    not_evaluated: 'Watermark not evaluated against the original'
  }
  const css: Record<WatermarkOutcome['result'], string> = {
    matched: 'traced', contradicted: 'red', not_recovered: 'grey', not_evaluated: 'grey'
  }
  const caveat = outcome.result === 'matched'
    ? '<p><strong>This is not a verdict of authenticity.</strong> No valid signature covers these bytes, so nothing here says the pixels are unedited or that the file is the one that was sealed — only that a mark the original declares came back out of them.</p>'
    : ''
  return `<div class="verdict ${css[outcome.result]}">
    <h2>${escape(headline[outcome.result])}</h2>
    <p>${escape(`${outcome.result.replace(/_/g, ' ')} — ${outcome.detail}${figures(outcome)}`)}</p>
    ${caveat}
  </div>`
}
