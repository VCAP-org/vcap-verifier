import type { Verdict, WatermarkEvidence, WatermarkOutcome } from 'vcap-verify-core'

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
/**
 * The answer to the question the reader arrived with, in the words they would
 * use. It sits **above** the specification's title and never instead of it:
 * `TITLE` below is copied from §8 and a relabelled verdict is a different
 * verdict, so both are printed — the plain line for somebody who wants to know
 * whether to believe a photo, the spec line for somebody who has to quote it.
 *
 * "Yes" and "No" answer authenticity and nothing else. The levels a proof
 * reaches — position, trusted time, watermark — stay on their own axes below,
 * because collapsing them into the headline is how a verifier starts implying
 * things it has not checked.
 */
export const PLAIN: Record<Verdict['outcome'], string> = {
  authentic: 'Yes — this file is what it says it is.',
  verified_clip: 'In part — these are signed frames of a longer recording.',
  tampered: 'No — this file changed after it was sealed.',
  nested_proof: 'Careful — a sealed file was sealed a second time.',
  corrupted_proof: 'The proof is damaged and cannot be read.',
  no_proof_found: 'This file carries no proof.',
  unsupported_format_version: 'This page cannot read a proof of this version.'
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
    // One decimal, because whole percent lands on the wrong side of the floor
    // exactly where the floor decides: the hardest surviving chain on the
    // shipped build reads 0.848 from a single frame, which rounds to "85%" and
    // sits next to a sentence saying it is below 0.85. A figure that appears
    // to contradict the reason given for refusing it reads as a broken page.
    w.agreement !== undefined ? `agreement ${(w.agreement * 100).toFixed(1)}%` : null,
    w.corrected_bits !== undefined ? `${w.corrected_bits} bits corrected` : null,
    w.frames_sampled !== undefined ? `${w.frames_sampled} frame${w.frames_sampled === 1 ? '' : 's'}${w.sampling ? ` (${w.sampling.strategy})` : ''}` : null,
    w.model_version ?? null
  ].filter((p) => p !== null)
  return parts.length > 0 ? ` [${parts.join(', ')}]` : ''
}

export const card = (name: string, v: Verdict): string => {
  // The ceilings, and they keep the specification's words: these are what the
  // verdict does **not** reach, and a paraphrase would be a different claim
  // (D20). What changes is only how they are set — as chips under a line that
  // names them, rather than a bullet list of seven grey phrases inside a green
  // card, which read as a list of faults and is the opposite of a ceiling.
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
    <p class="lede">${escape(PLAIN[v.outcome])}</p>
    <h2>${escape(TITLE[v.outcome])}</h2>
    <div class="file-line">${escape(name)}</div>
    ${position(v)}
    ${lines.length
      ? `<div class="limits"><p class="limits-head">What this verdict does not cover</p><ul class="chips">${lines.join('')}</ul></div>`
      : ''}
    ${details.length ? `<details class="tech"><summary><span class="chev" aria-hidden="true">›</span> Technical detail</summary><ul>${details.join('')}</ul></details>` : ''}
  </div>`
}

/**
 * A mark read out of a file that carries no proof.
 *
 * This is the case a person actually arrives with: a photo that came back from
 * a chat app or a social network, re-encoded, its trailer stripped. The
 * signature layer answers *no proof found* — correctly — and stops, because a
 * watermark may never be the reason a verdict is positive and the core
 * enforces that by construction: the watermark is evaluated after the
 * signature, and a file with no proof never reaches it.
 *
 * So the page used to say nothing at all about the pixels, even with the
 * detector loaded, and a mark that survived the re-encode went unmentioned.
 * The product has an answer for this file — the payload is the capture id, and
 * a registry can turn that id into the proof — and the two halves simply never
 * met on screen.
 *
 * What is printed here is deliberately not a verdict: no colour of the verdict
 * palette, the word "not" in the first sentence, and the id as a fact about
 * the pixels rather than a claim about the file.
 */
export const bareMark = (evidence: WatermarkEvidence, traceUrl: string): string => {
  const decoded = evidence.decoded ?? null
  const layout = evidence.layout
  if (decoded === null) {
    // Two different things, and the reader is owed the difference. "Nothing
    // came back" and "something came back and may not be named" both produce
    // no id, but only the second one is a clip whose mark is probably there —
    // and only the second one can be changed by reading more of it.
    if (evidence.id_refused === true) {
      return `<div class="panel mark">
        <h3>A mark may be in these pixels, and its identifier could not be read</h3>
        <p>Something came back out of them, and the copies of it disagreed too much to name an identifier. The page says nothing rather than risk pointing you at somebody else's recording — a name it is not sure of would be worse than no name.${frameNote(evidence)}</p>
        <p class="muted">This is not proof of anything either way: a file that never carried a mark can look like this too.</p>
      </div>`
    }
    return `<div class="panel mark">
      <h3>No invisible mark came back from these pixels</h3>
      <p class="muted">Which is not proof of anything either: heavy re-compression, a crop or a screenshot can take the mark out, and a file that never carried one looks the same from here.</p>
    </div>`
  }
  return `<div class="panel mark">
    <h3>An invisible mark is still in these pixels</h3>
    <p><strong>This is not a verdict of authenticity.</strong> No signature covers these bytes, so nothing here says the picture is unedited or that it is the file that was sealed. What the pixels carry is an identifier, and that is all.</p>
    <p>It reads <code>${escape(decoded)}</code>${layout ? ` in <code>${escape(layout)}</code>` : ''}.</p>
    <p class="muted">Two things can be done with it. Drop the <strong>original</strong> above, and this page will compare the two itself, here, with nothing leaving your browser. Or look the identifier up in the registry that issued it, which is a request to somebody's server and the only one this page will ever suggest.</p>
    <p><a class="btn secondary" href="${escape(traceUrl)}/${escape(decoded)}" rel="noreferrer">Look this identifier up in the registry</a></p>
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

/** Frames past which the measured margin stops improving (`watermark-robustness-1.0.md`). */
const SETTLED_FRAMES = 8

/**
 * Whether reading more of the clip would change a refusal — the question a
 * reader of *not recovered* actually has, and one only the frame count can
 * answer. The floor is applied per decode, so a thin detection can be refused
 * on a clip a deeper one resolves: on the shipped int8 build the hardest chain
 * that survives reads 0.848 from one frame and 0.867 from eight. Eight is also
 * where the measured gain stops, so a detection that already has them is told
 * that more would not help rather than left to hope
 * (`vcap-spec/spec/watermark-robustness-1.0.md`).
 *
 * A detection handed to the page in a file may have sampled anything, or not
 * said — hence three answers and not one.
 */
const frameNote = (w: { frames_sampled?: number | null }): string => {
  const frames = w.frames_sampled
  if (frames === null || frames === undefined || frames < 1) return ''
  return frames >= SETTLED_FRAMES
    ? ` Reading more of the clip would not change this: ${frames} frames were averaged, and past ${SETTLED_FRAMES} the measurements show no further gain.`
    : ` Reading more of the clip could change this: only ${frames === 1 ? 'one frame was' : `${frames} frames were`} averaged, and this model needs about four before the hardest clip that survives at all clears the floor.`
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
    // Both are *not recovered* to the specification, and they are two different
    // things to a reader: nothing came back, against something came back that
    // may not be believed. Neither says anything about an id.
    not_recovered: outcome.id_refused === true
      ? 'A mark may be present — its id could not be resolved'
      : 'Nothing recovered — the watermark did not survive either',
    not_evaluated: 'Watermark not evaluated against the original'
  }
  const css: Record<WatermarkOutcome['result'], string> = {
    matched: 'traced', contradicted: 'red', not_recovered: 'grey', not_evaluated: 'grey'
  }
  const caveat = outcome.result === 'matched'
    ? '<p><strong>This is not a verdict of authenticity.</strong> No valid signature covers these bytes, so nothing here says the pixels are unedited or that the file is the one that was sealed — only that a mark the original declares came back out of them.</p>'
    : outcome.id_refused === true
      ? `<p><strong>This is not a wrong id — it is no id.</strong> Something came back out of the pixels and the copies of it disagreed too much to name one, so the page says nothing rather than risk pointing you at somebody else's recording.${frameNote(outcome)}</p>`
      : ''
  return `<div class="verdict ${css[outcome.result]}">
    <h2>${escape(headline[outcome.result])}</h2>
    <p>${escape(`${outcome.result.replace(/_/g, ' ')} — ${outcome.detail}${figures(outcome)}`)}</p>
    ${caveat}
  </div>`
}
