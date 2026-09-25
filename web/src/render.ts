import { ceilingLabels } from 'vcap-verify-core'
import type { ContentCredentials, ProofSource, Verdict, WatermarkEvidence, WatermarkOutcome } from 'vcap-verify-core'
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

/**
 * The colour each outcome allows at most. It is a cap and not the answer:
 * §7 gives the verdict its light as `level.ceiling`, and an *authentic* file
 * whose key is a session key is amber there, never green.
 */
export const COLOR: Record<Verdict['outcome'], string> = {
  // §8's outcome table: a nested proof is red, and *frames not compared* is
  // amber — the signatures hold and nothing ties these frames to them.
  authentic: 'green', verified_clip: 'amber', tampered: 'red', nested_proof: 'red',
  corrupted_proof: 'red', no_proof_found: 'grey', unsupported_format_version: 'grey',
  frames_not_compared: 'amber'
}
const STRICTNESS: Record<string, number> = { green: 0, amber: 1, red: 2 }

/**
 * The card's colour: the stricter of the outcome's cap and the §7 ceiling, so
 * the page never paints greener than the core allows. Grey outcomes carry no
 * level — the core stops before §7 — and stay grey; so does every outcome the
 * core returns before §7 (tampered, corrupted, nested), with its own colour.
 */
export const colour = (v: Verdict): string => {
  const cap = COLOR[v.outcome]
  const ceiling = v.level?.ceiling
  if (ceiling === undefined || STRICTNESS[cap] === undefined) return cap
  return (STRICTNESS[ceiling] as number) > (STRICTNESS[cap] as number) ? ceiling : cap
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
  unsupported_format_version: 'This page cannot read a proof of this version.',
  frames_not_compared: 'Cannot tell — the proof is genuine, but nothing shows these frames are the ones it signed.'
}
/**
 * *Verified clip* is "these are signed frames" only when the frames were read
 * back from the container and matched (§5). Without that, somebody signed
 * some segments and this page did not look at the frames, and the headline
 * must not say more.
 */
const CLIP_NOT_READ = 'In part — some segments of this recording are signed, and their frames were not compared with this file.'
/**
 * The plain line when the card is not the outcome's own colour, so the largest
 * words on the card never contradict its light. "Yes" belongs to green only:
 * an authentic file under an amber ceiling is intact and something behind the
 * seal is unproven, and one under a red ceiling was sealed by a revoked key.
 * `TITLE` stays the spec's words beside it either way.
 */
const PLAIN_BELOW: Record<string, string> = {
  amber: 'Intact, not fully proven — unchanged since it was sealed, but not everything behind the seal is proven.',
  red: 'Do not rely on it — the file has not changed since it was sealed, but a key behind the seal was revoked.'
}
// "Has not changed since it was sealed" is a fact about an *authentic* file
// only: a clip under a red ceiling is part of a recording, not the whole one.
const RED_CLIP = 'Do not rely on it — a key behind the seal was revoked.'
// *No proof found* also answers a proof that is there and cannot be read
// (§8: a payload that is not a proof is no proof). "Carries no proof" would
// then be false about the file in the reader's hand.
const UNREADABLE_PROOF = 'This file carries no proof this page can read.'
// A proof read from an ancestor manifest that does not fit the file: the file
// was made from that capture, which is not an accusation and not an absence.
const SOURCE_CAPTURE_PROOF = 'This file carries no proof of its own — its Content Credentials carry the proof of the capture it was made from.'
const fromAncestor = (v: Verdict): boolean => v.proof_source?.kind === 'c2pa' && v.proof_source.depth > 0
const plain = (v: Verdict): string => {
  const shown = colour(v)
  if (shown === 'red' && v.outcome !== 'authentic' && shown !== COLOR[v.outcome]) return RED_CLIP
  if (shown !== COLOR[v.outcome]) return PLAIN_BELOW[shown] ?? PLAIN[v.outcome]
  if (v.outcome === 'no_proof_found' && fromAncestor(v)) return SOURCE_CAPTURE_PROOF
  if (v.outcome === 'no_proof_found' && v.reason !== undefined && v.reason !== 'no trailer and no sidecar') return UNREADABLE_PROOF
  return v.outcome === 'verified_clip' && v.content?.recomputed !== true ? CLIP_NOT_READ : PLAIN[v.outcome]
}

/**
 * The ceiling in words, beside the title: the colour, then the §7 labels that
 * set it, as the core wrote them. Only for a verdict that reached §7 — a
 * tampered file's reason is its title already.
 */
const ceilingLine = (v: Verdict): string => {
  if (!v.level) return ''
  const why = ceilingLabels(v)
  return `<p class="ceiling"><span class="badge">${escape(colour(v))}</span>${why.length ? `<span class="rest"> ${why.map(escape).join(' · ')}</span>` : ''}</p>`
}

export const TITLE: Record<Verdict['outcome'], string> = {
  authentic: 'Authentic — signed at capture, file complete',
  verified_clip: 'Verified clip — signed frames of a longer original',
  tampered: 'Tampered — the file or its proof was altered after sealing',
  nested_proof: 'Nested proof — a sealed file was sealed again; the outer proof is not authoritative',
  corrupted_proof: 'Corrupted proof — the trailer is damaged',
  no_proof_found: 'No proof found',
  unsupported_format_version: 'Unsupported format version',
  frames_not_compared: 'Frames not compared — the core and segment signatures hold, and nothing ties them to these frames'
}

const SOURCE: Record<string, string> = {
  timestamp: 'proven by the timestamp token',
  anchor: 'proven by the anchored block',
  device_clock: 'the device\'s own clock, not proven',
  verifier_clock: 'this browser\'s clock; the proof declares no time'
}

/**
 * Where each piece of evidence comes from, in plain words beside it. The
 * difference is the whole claim of this page: what the file proves on its own
 * anybody can check here offline; what rests on the transparency log rests on
 * a key of a log we run — our records, never independent corroboration; a
 * timestamp authority and a public chain are other people's; and the one
 * question only a live lookup answers is one this page does not ask.
 */
export const FROM = {
  file: 'from the file alone',
  log: 'VCAP transparency log key',
  tsa: 'third-party timestamp authority',
  chain: 'public chain via RPC',
  lookup: 'VCAP online lookup',
  browser: 'this browser\'s clock',
  supplied: 'a detection you supplied',
  // Read out of a C2PA manifest store whose signature this page does not check.
  cc: 'Content Credentials, signature not checked'
} as const
const INSTANT_FROM: Record<string, string> = { timestamp: FROM.tsa, anchor: FROM.chain, device_clock: FROM.file, verifier_clock: FROM.browser }
const SOURCES_LEGEND = `<p class="legend">Where each line comes from: <em>${FROM.file}</em> is checked here, offline, by anyone; <em>${FROM.log}</em> rests on a key of the log we run — our own records, not independent; a <em>${FROM.tsa}</em> and a <em>${FROM.chain}</em> are other people's; a <em>${FROM.lookup}</em> is a question this page does not ask. No source is a verdict of authenticity on its own.</p>`

/** The proven level and what proved it: the chain in the file (Android), the registry leaf (iOS), or nothing. */
const levelRow = (v: Verdict): [string, string, string] | null => {
  if (!v.level) return null
  const by = v.attestation ? FROM.file : v.level.proven !== 'none' && v.registry?.ok ? FROM.log : FROM.file
  return ['proven level', `<code>${escape(v.level.proven)}</code>, claimed <code>${escape(v.level.claimed)}</code>`, by]
}

const attestationRow = (v: Verdict): [string, string, string] | null => {
  const a = v.attestation
  if (!a) return null
  const boot = a.boot_state ? `; boot ${escape(a.boot_state.state)}, device ${a.boot_state.locked ? 'locked' : 'unlocked'}` : ''
  return ['attestation', `proves <code>${escape(a.proven)}</code> — ${escape(a.detail)}${boot}`, FROM.file]
}

/** `watermark.mark_id` and whether it is derived from the capture id (a SHOULD): a lookup by mark id finds the capture only if it is. */
const markIdRow = (v: Verdict): [string, string, string] | null => {
  const m = v.mark_id
  if (!m) return null
  return ['mark id', `<code>${m.value}</code> — ${m.derived ? 'derived from the capture id' : 'not the value derived from the capture id, so a lookup by mark id will not find this capture'}`, FROM.file]
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

/**
 * The labels that report evidence that held, not a gap. §8 and §7 emit them
 * in the same list as the ceilings, so the list alone cannot say which is
 * which; under "What this verdict does not cover", *watermark matched* read as
 * a limit. They keep the specification's words and move to their own line.
 */
const CHECKED = new Set(['watermark matched', 'location corroborated', 'integrity hardware'])

export interface CardOptions {
  /**
   * The signature layer has answered and the detector is still working: the
   * verdict is shown now and the watermark row says it is being read, instead
   * of the page withholding a finished answer for a 60 MB download.
   */
  watermarkPending?: boolean
  /** The detection came from a file the reader dropped, not from this page's detector. */
  detectionSupplied?: boolean
}

export const card = (name: string, v: Verdict, o: CardOptions = {}): string => {
  const checked = v.labels.filter((l) => CHECKED.has(l))
  // While the detector runs, *watermark not evaluated* is not yet an answer:
  // the row below says the mark is being read, and the label comes back if the
  // detector cannot be had.
  const shownLabels = o.watermarkPending === true ? v.labels.filter((l) => l !== 'watermark not evaluated') : v.labels
  // The ceilings, and they keep the specification's words: these are what the
  // verdict does **not** reach, and a paraphrase would be a different claim.
  // What changes is only how they are set — as chips under a line that
  // names them, rather than a bullet list of seven grey phrases inside a green
  // card, which read as a list of faults and is the opposite of a ceiling.
  const lines = [
    ...shownLabels.filter((l) => !CHECKED.has(l)).map((l) => `<li>${escape(l)}</li>`),
    ...v.not_evaluated.map((k) => `<li>not evaluated: <code>${escape(k)}</code></li>`)
  ]
  // What the verdict rests on, as a description list: the name of each piece of
  // evidence, what the core said about it, and where that evidence comes from.
  const watermarkFrom = o.detectionSupplied === true ? FROM.supplied : FROM.file
  const rows: Array<[string, string, string] | null> = [
    v.claimed_secure_hw ? ['claimed level', `<code>${escape(v.claimed_secure_hw)}</code> (the device's own claim)`, FROM.file] : null,
    levelRow(v),
    attestationRow(v),
    v.attestation_status ? ['chain revocation', escape(v.attestation_status.detail), FROM.log] : null,
    v.device_clock ? ['declared capture time', `${new Date(v.device_clock).toISOString()} (device clock, not trusted time)`, FROM.file] : null,
    v.timestamp ? ['trusted time', escape(v.timestamp.detail), FROM.tsa] : null,
    // §7: which clock the certificate paths were validated at. A reader who is
    // not told cannot tell a capture time proven by a token from one the device
    // asserted about itself.
    v.validated_at ? ['validated at', `${escape(v.validated_at.instant)} (${escape(SOURCE[v.validated_at.source] ?? v.validated_at.source)})`, INSTANT_FROM[v.validated_at.source] ?? FROM.file] : null,
    v.segments ? ['segments verified', v.segments.verified.length ? v.segments.verified.join(', ') : 'none', FROM.file] : null,
    v.segments?.contradicted?.length ? ['segments whose frames are not the signed frames', v.segments.contradicted.join(', '), FROM.file] : null,
    // §5 recomputation either happened or did not, and the page says which:
    // "every segment verifies" means much less when nothing read the frames.
    v.content ? ['segment content', `${v.content.recomputed ? 'recomputed from the container' : 'not recomputed'} (${escape(v.content.detail)})`, FROM.file] : null,
    o.watermarkPending === true
      ? ['watermark', 'being read — the verdict above is the signature\'s, and this line fills in when the detector finishes', FROM.file]
      : v.watermark ? ['watermark', escape(watermarkLine(v.watermark)), watermarkFrom] : null,
    markIdRow(v),
    v.registry ? ['transparency log', escape(v.registry.detail), FROM.log] : null,
    v.integrity ? ['device integrity', escape(v.integrity.detail), FROM.log] : null,
    v.location_corroboration ? ['position corroboration', escape(v.location_corroboration.detail), FROM.log] : null,
    // The device key's own standing, which is the one thing this page cannot
    // establish from the file: it ships with no log to ask, so it says so
    // rather than leaving the reader to assume it was checked.
    v.key_status ? ['key revocation', escape(v.key_status.detail), FROM.lookup] : null,
    v.anchor ? ['anchor', escape(v.anchor.detail), v.anchor.on_chain === true ? FROM.chain : FROM.file] : null,
    v.core_hash ? ['proof identity', `<code>${v.core_hash}</code>`, FROM.file] : null,
    // Where the proof sat is not evidence (§3.1), so it is a row and never a
    // label — and only where it is not the trailer or a sidecar the reader chose.
    v.proof_source?.kind === 'c2pa' ? ['proof read from', escape(proofSource(v.proof_source)), FROM.cc] : null
  ]
  const details = rows.filter((row): row is [string, string, string] => row !== null)
  // The core's own sentence for why the verdict stopped where it did: it names
  // no field, so it is a line above the list rather than a row of it.
  const reason = v.reason ? `<p class="reason">${escape(v.reason)}</p>` : ''
  return `<div class="verdict ${colour(v)}">
    <p class="lede">${escape(plain(v))}</p>
    <h2>${statusHeading(TITLE[v.outcome])}</h2>
    ${ceilingLine(v)}
    <div class="file-line">${escape(name)}</div>
    ${position(v)}
    ${carriedLine(v.watermark)}
    ${checked.length
      ? `<div class="limits checked"><p class="limits-head">Also checked</p><ul class="chips">${checked.map((l) => `<li>${escape(l)}</li>`).join('')}</ul></div>`
      : ''}
    ${lines.length
      ? `<div class="limits"><p class="limits-head">What this verdict does not cover</p><ul class="chips">${lines.join('')}</ul></div>`
      : ''}
    ${details.length || reason
      ? `<details class="tech"><summary><span class="chev" aria-hidden="true">›</span> Technical detail</summary>${reason}${details.length ? `<dl class="kv">${details.map(([key, value, from]) => `<dt>${escape(key)}</dt><dd>${value}<span class="source">${escape(from)}</span></dd>`).join('')}</dl>${SOURCES_LEGEND}` : ''}</details>`
      : ''}
  </div>`
}

/** Where a proof was read, in words. */
export const proofSource = (s: ProofSource): string => {
  if (s.kind === 'trailer') return 'the file\'s trailer'
  if (s.kind === 'sidecar') return 'the sidecar you supplied'
  return s.depth === 0
    ? `the active manifest of the Content Credentials (${s.manifest})`
    : `the Content Credentials, ${s.depth} step${s.depth === 1 ? '' : 's'} up the parentOf chain (${s.manifest}) — the proof of the capture this file was made from`
}

/**
 * The Content Credentials lane: what the file's C2PA manifest store holds, in
 * its own panel and never inside the verdict card, and never in a verdict
 * colour — nothing C2PA says reaches the outcome, the labels or the ceiling.
 * This page checks no C2PA signature, certificate or hashed URI, so the lane
 * names no signer, shows no mark of validity, and every row says it rests on
 * a signature nobody here checked. The mechanical facts it can state are the
 * ones about vcap's own bytes: where the proof was read, whether a copy
 * differs, and whether the store was inside the bytes the device sealed.
 */
export const contentCredentials = (v: Verdict): string => {
  const cc = v.content_credentials
  if (!cc) return ''
  const where = cc.store === 'embedded' ? 'embedded in the file' : 'the .c2pa file you supplied'
  const rows: Array<[string, string]> = cc.unread
    ? [['manifest store', `${where}, not read: ${escape(cc.unread)}`]]
    : [
        ['manifest store', `${where}, ${cc.manifests === 1 ? 'one manifest' : `${cc.manifests} manifests`}`],
        ['active manifest', `<code>${escape(cc.active?.label ?? '')}</code>`],
        ...(cc.active?.generator ? [['claim generator', `${escape(cc.active.generator)} — the generator's own name for itself`] as [string, string]] : []),
        ['vcap proof', escape(proofRow(v, cc))],
        ...(cc.sealed_with_capture ? [['sealed with the capture', 'Content Credentials sealed with the capture: the store sits inside the bytes the device hashed, and they match'] as [string, string]] : []),
        ...cc.notes.map((note): [string, string] => ['stepped over', escape(note)])
      ]
  rows.push(['C2PA signature', 'not checked by this page: who signed these Content Credentials, and whether their own bindings hold, is a question for a C2PA validator'])
  return `<div class="panel cc">
    <h3>Content Credentials</h3>
    <p class="muted">This file comes with a C2PA manifest store. This page reads it only to find a vcap proof; nothing in it changes the verdict above.</p>
    <dl class="kv">${rows.map(([key, value]) => `<dt>${escape(key)}</dt><dd>${value}<span class="source">${escape(FROM.cc)}</span></dd>`).join('')}</dl>
  </div>`
}

const proofRow = (v: Verdict, cc: ContentCredentials): string => {
  const source = v.proof_source
  if (source?.kind === 'c2pa') return `the verdict above was read from ${proofSource(source)}${cc.proof ? `, listed in its claim's ${cc.proof.listed_as}` : ''}`
  if (source?.kind === 'trailer' && cc.proof) {
    return v.labels.includes('manifest copy differs')
      ? `the active manifest carries a different copy of the proof (manifest copy differs); the trailer decides`
      : 'the active manifest carries a copy of the proof, the same as the trailer\'s; the trailer decides'
  }
  if (source?.kind === 'sidecar') return 'none in the active manifest; the verdict above is the sidecar\'s'
  return 'none in the manifests this page follows'
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
    ${customModelNote(evidence)}
    ${lookup(layout, decoded, traceUrl)}
  </div>`
}

/**
 * The registry lookup, for the one layout whose payload names a capture.
 * `photo-bch-v3` carries the whole 128-bit capture id; `video-rep-v1` carries
 * a 24-bit mark id that thousands of captures share by design, so a link on it
 * would point a reader at a stranger's recording as readily as at this one.
 */
const lookup = (layout: string | null | undefined, decoded: string, traceUrl: string): string => layout === 'video-rep-v1'
  ? '<p class="muted">A clip\'s mark is a short identifier that many captures share, so it cannot be looked up on its own: finding the capture takes its capture id, which only the proof carries.</p>'
  : `<p class="muted">The registry that issued it can turn it back into the proof. Looking it up is a request to somebody's server, and the only one this page will ever suggest.</p>
    <p><a class="btn" href="${escape(traceUrl)}/${escape(decoded)}" rel="noreferrer">Look this identifier up in the registry</a></p>`

/**
 * A file with no proof whose pixels may carry a mark, before anything is
 * downloaded: reading it needs the detector, and the reader is told what that
 * costs and asked. The verdict above is already whole.
 */
export const markOffer = (megabytes: number): string => `<div class="panel mark" id="mark-offer">
    <h3>This file carries no proof — but it may still carry an invisible mark</h3>
    <p class="muted">A copy that came back from a chat app or a social network has usually lost its proof and kept the mark. Reading it needs the watermark detector: about ${Math.round(megabytes)} MB, downloaded once from where this page is served and checked against the digest it pins. Nothing about your file is sent.</p>
    <p><button type="button" class="btn" id="read-mark">Read the mark (about ${Math.round(megabytes)} MB)</button></p>
  </div>`

/**
 * The chain read, offered rather than made: what is sent (the anchor id, and
 * the reader's address, as with any request) and to whom, before anything is.
 */
export const anchorOffer = (title: string, hosts: string[], anchorId: number): string => `<div class="panel anchor" id="anchor-offer">
    <h3>This proof is anchored on ${escape(title)}, and the chain was not read</h3>
    <p class="muted">Checking it asks ${hosts.map((h) => `<code>${escape(h)}</code>`).join(' or ')} — a public endpoint that is not ours — for anchor ${anchorId}. That number and your address are all it learns; the file and the proof stay here.</p>
    <p><button type="button" class="btn" id="read-anchor">Read the anchor from the chain</button></p>
  </div>`

/**
 * What the page shows when checking a file failed outright — never a spinner
 * that never stops. The core does not throw on a file; this is a page that
 * could not read the file at all, or a bug of ours, and the reader is told
 * what to do about either.
 */
export const errorCard = (name: string, message: string): string => `<div class="panel error" role="alert">
    <h3>This page could not finish checking ${escape(name)}</h3>
    <p>Nothing was uploaded, and no verdict was reached. Try the file again; if the browser ran out of memory on a large video, close other tabs first. If it fails again, the file may be damaged — the command-line verifier, <code>vcap-verify</code>, reads the same file with the same core and prints the error in full.</p>
    <p class="muted">What went wrong: <code>${escape(message)}</code></p>
  </div>`

/**
 * A mark read by a model the reader supplied is named as such, so an
 * identifier from an unpinned build never reads as one from the pinned build.
 */
const customModelNote = (w: WatermarkEvidence): string =>
  w.model_version?.startsWith('custom-') === true
    ? `<p class="muted">Read by <code>${escape(w.model_version)}</code>, a model you supplied — not the build this page pins.</p>`
    : ''

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
