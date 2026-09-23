import type { Verdict, WatermarkEvidence, WatermarkOutcome } from 'vcap-verify-core'
// The sampling policy, not a second copy of it: the page explains a refusal by
// the same count `detector-runtime.ts` samples at, and importing the runtime
// here would pull the engine into the bundle.
import { VIDEO_FRAMES } from './sampling.js'

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

/**
 * A heading whose first clause is the status word, set as a badge. The text is
 * the same string, character for character — only the clause before the first
 * dash is wrapped, so the colour that marks the status always sits on a word
 * and a reader copying the heading copies exactly what was written.
 */
const statusHeading = (text: string): string => {
  const cut = text.indexOf(' — ')
  return cut === -1
    ? `<span class="badge">${escape(text)}</span>`
    : `<span class="badge">${escape(text.slice(0, cut))}</span><span class="rest">${escape(text.slice(cut))}</span>`
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

/**
 * How much of a clip carried the mark, in the words of somebody who has not
 * read §8 — and the reason this page prints a count at all.
 *
 * "The payload carries the declared mark id" is true of a clip that is the
 * capture and equally true of foreign footage with one genuine frame cut into
 * it: an unmarked frame abstains rather than dissenting, so the averaged
 * decode is set by any single marked frame and reports the real id at the
 * agreement of a clean recovery (0.996, measured). The agreement figure cannot
 * separate the two and must never be shown as if it could. The count can, and
 * a reader who is shown "8 of 8" and a reader who is shown "1 of 8" are
 * looking at two different situations.
 *
 * The count says **where** the mark is, never **whether** it is: whether is
 * the clip's own decode, which already answered. Hence three sentences and not
 * two, because zero is not a small number here but a different statement.
 * A frame counts when its own decode yields the clip's id; the 0.85 floor
 * gates the id and not the count (§8, *Which sampled frames count*). Zero is
 * still reachable and still not an accusation: a clip can resolve on the
 * average while no single frame's checksum holds, which is what heavy
 * re-compression does. Reading zero as evidence of a splice would convict
 * exactly those clips, and for the same reason the count is never a floor of
 * its own: requiring one frame to resolve on its own would refuse the clips
 * averaging exists for.
 */
const carriedNote = (w: { frames_with_id?: number | null, frames_sampled?: number | null }): string => {
  const carried = w.frames_with_id
  const sampled = w.frames_sampled
  if (carried === null || carried === undefined || sampled === null || sampled === undefined || sampled < 1) return ''
  if (carried === 0) {
    return `The mark is there — the ${sampled} sampled frames read together resolve it — but no single frame carried it clearly enough on its own, which is what heavy re-compression does to a clip. So this page can say the mark is in the file and not how much of the file carries it.`
  }
  if (carried >= sampled) {
    return `All ${sampled} frames sampled across the clip carry the mark on their own, so the mark runs through the clip rather than sitting in one frame of it.`
  }
  return `${carried} of the ${sampled} frames sampled across the clip carry the mark on their own; the other ${sampled - carried} do not. That can be a genuine recording the codec hit hardest in places — or footage with a piece of that capture cut into it, which is the case no single confidence figure can tell apart.`
}

/** The count on its own line, above the fold: a qualifier inside a collapsed section is a qualifier nobody reads. */
const carriedParagraph = (w: { frames_with_id?: number | null, frames_sampled?: number | null }, css = ''): string => {
  const note = carriedNote(w)
  return note === '' ? '' : `<p${css === '' ? '' : ` class="${css}"`}>${escape(note)}</p>`
}

/** Only next to a reported id: a count of frames carrying nothing is not a fact about the clip. */
const carriedLine = (w: WatermarkOutcome | undefined): string =>
  w !== undefined && w.result === 'matched' ? carriedParagraph(w, 'carried') : ''

export const card = (name: string, v: Verdict): string => {
  // The ceilings, and they keep the specification's words: these are what the
  // verdict does **not** reach, and a paraphrase would be a different claim.
  // What changes is only how they are set — as chips under a line that
  // names them, rather than a bullet list of seven grey phrases inside a green
  // card, which read as a list of faults and is the opposite of a ceiling.
  const lines = [
    ...v.labels.map((l) => `<li>${escape(l)}</li>`),
    ...v.not_evaluated.map((k) => `<li>not evaluated: <code>${escape(k)}</code></li>`)
  ]
  // What the verdict rests on, as a description list: the name of each piece of
  // evidence on one side, what the core said about it on the other.
  const rows: Array<[string, string] | null> = [
    v.claimed_secure_hw ? ['claimed level', `<code>${escape(v.claimed_secure_hw)}</code> (attestation not evaluated by this page)`] : null,
    v.device_clock ? ['declared capture time', `${new Date(v.device_clock).toISOString()} (device clock, not trusted time)`] : null,
    // §7: which clock the certificate paths were validated at. A reader who is
    // not told cannot tell a capture time proven by a token from one the device
    // asserted about itself.
    v.validated_at ? ['validated at', `${escape(v.validated_at.instant)} (${escape(SOURCE[v.validated_at.source] ?? v.validated_at.source)})`] : null,
    v.segments ? ['segments verified', v.segments.verified.length ? v.segments.verified.join(', ') : 'none'] : null,
    v.segments?.contradicted?.length ? ['segments whose frames are not the signed frames', v.segments.contradicted.join(', ')] : null,
    // §5 recomputation either happened or did not, and the page says which:
    // "every segment verifies" means much less when nothing read the frames.
    v.content ? ['segment content', `${v.content.recomputed ? 'recomputed from the container' : 'not recomputed'} (${escape(v.content.detail)})`] : null,
    v.watermark ? ['watermark', escape(watermarkLine(v.watermark))] : null,
    v.registry ? ['transparency log', escape(v.registry.detail)] : null,
    v.attestation_status ? ['chain revocation', escape(v.attestation_status.detail)] : null,
    // The device key's own standing, which is the one thing this page cannot
    // establish from the file: it ships with no log to ask, so it says so
    // rather than leaving the reader to assume it was checked.
    v.key_status ? ['key revocation', escape(v.key_status.detail)] : null,
    v.anchor ? ['anchor', escape(v.anchor.detail)] : null,
    v.core_hash ? ['proof identity', `<code>${v.core_hash}</code>`] : null
  ]
  const details = rows.filter((row): row is [string, string] => row !== null)
  // The core's own sentence for why the verdict stopped where it did: it names
  // no field, so it is a line above the list rather than a row of it.
  const reason = v.reason ? `<p class="reason">${escape(v.reason)}</p>` : ''
  return `<div class="verdict ${COLOR[v.outcome]}">
    <p class="lede">${escape(PLAIN[v.outcome])}</p>
    <h2>${statusHeading(TITLE[v.outcome])}</h2>
    <div class="file-line">${escape(name)}</div>
    ${position(v)}
    ${carriedLine(v.watermark)}
    ${lines.length
      ? `<div class="limits"><p class="limits-head">What this verdict does not cover</p><ul class="chips">${lines.join('')}</ul></div>`
      : ''}
    ${details.length || reason
      ? `<details class="tech"><summary><span class="chev" aria-hidden="true">›</span> Technical detail</summary>${reason}${details.length ? `<dl class="kv">${details.map(([key, value]) => `<dt>${escape(key)}</dt><dd>${value}</dd>`).join('')}</dl>` : ''}</details>`
      : ''}
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
    ${carriedParagraph(evidence)}
    <p class="muted">The registry that issued it can turn it back into the proof. Looking it up is a request to somebody's server, and the only one this page will ever suggest.</p>
    <p><a class="btn" href="${escape(traceUrl)}/${escape(decoded)}" rel="noreferrer">Look this identifier up in the registry</a></p>
  </div>`
}

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
  return frames >= VIDEO_FRAMES
    ? ` Reading more of the clip would not change this: ${frames} frames were averaged, and past ${VIDEO_FRAMES} the measurements show no further gain.`
    : ` Reading more of the clip could change this: only ${frames === 1 ? 'one frame was' : `${frames} frames were`} averaged, and this model needs about four before the hardest clip that survives at all clears the floor.`
}
