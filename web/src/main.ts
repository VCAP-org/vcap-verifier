import { evaluateWatermark, verify, type Verdict, type WatermarkClaim, type WatermarkEvidence, type WatermarkOutcome } from 'vcap-verify-core'
import { card, comparison, trace } from './render.js'
import { readEvidence } from './evidence.js'
import { mountTrust, mountTsa, trustedLogs, trustedTsaRoots } from './trust.js'
import type { Detector, DetectProgress } from './detector.js'

/**
 * The page: read the file in question (and, when the user has them, the
 * original it is supposed to be a copy of, a sidecar, a detection), run the
 * shared core over each, and say what it found in the specification's words.
 * No network is in the verification path, and nothing is uploaded.
 *
 * The side-by-side exists because a verdict on a copy is not self-explanatory.
 * A file that came back from a messaging app has lost its trailer and with it
 * its signature, and *no proof found* on its own does not tell a reader
 * whether the picture is a forgery or simply a re-compressed copy of something
 * that was sealed. Put the two files next to each other and the answer is
 * readable: the table names each piece of evidence, what the original carries,
 * what the copy still carries, and which of the two it lost.
 *
 * The watermark is the piece that can survive that trip, and it is the piece
 * the interface must not let anyone read backwards. It is never a verdict
 * here: the card keeps whatever the signature layer said, and a mark found in
 * an unsigned copy is *origin traced* — see `render.ts`.
 *
 * The detector that reads a mark out of pixels is a separate, explicit
 * download (`detector.ts`), never fetched on load and never precached. Without
 * it every verdict is the verdict this page gave before one existed, with
 * *watermark not evaluated* on it: a weaker answer, not a failure.
 *
 * The transparency logs it checks a `registry` attachment against are the
 * reader's to see and to change (`trust.ts`). The page ships trusting one, and
 * says on its face whose it is.
 */
const zones = {
  copy: document.getElementById('drop') as HTMLDivElement,
  original: document.getElementById('original-drop') as HTMLDivElement,
  sidecar: document.getElementById('sidecar-drop') as HTMLDivElement
}
const inputs = {
  copy: document.getElementById('file') as HTMLInputElement,
  original: document.getElementById('original') as HTMLInputElement,
  sidecar: document.getElementById('sidecar') as HTMLInputElement,
  evidence: document.getElementById('evidence') as HTMLInputElement
}
const out = document.getElementById('out') as HTMLDivElement
const chosen = document.createElement('p')
chosen.className = 'chosen'
;(document.getElementById('drop') as HTMLDivElement).append(chosen)
const detectorState = document.getElementById('detector-state') as HTMLParagraphElement
const loadButton = document.getElementById('load-detector') as HTMLButtonElement
const detectorBar = document.getElementById('detector-bar') as HTMLDivElement
const detectorTitle = document.getElementById('detector-title') as HTMLHeadingElement
const detectorMark = detectorBar.querySelector('.mark') as HTMLSpanElement

// What the user has handed over so far. Each arrives on its own and the
// verdict is recomputed whenever any of them changes, so the order does not
// matter. `detection` is a detector's report about the file in question.
const held: { copy?: File, original?: File, sidecar?: File, detection?: WatermarkEvidence } = {}
let detector: Detector | null = null

/**
 * One lookup per file. It records the claim the signed core produced — which
 * layout, which id, which proof — because the comparison against the
 * **original's** claim is how an unsigned copy gets traced, and that claim is
 * only available from here. What it returns is what a detector said about
 * *that* file: the user's detection for the copy, and a fresh detection for
 * the original only when a detector is loaded (a detection file is about one
 * file, and the file it is about is the one in question).
 */
const lookup = (bytes: Uint8Array, own: WatermarkEvidence | undefined, seen: { claim?: WatermarkClaim }, label: string) =>
  async (claim: WatermarkClaim): Promise<WatermarkEvidence | null> => {
    seen.claim = claim
    if (own) return own
    if (!detector) return null
    return await detector.detect(bytes, claim, progress(label))
  }

/**
 * Progressive, because it has to be: a clip is eight model runs of a few
 * hundred milliseconds each, and a page that says nothing for six seconds is a
 * page the reader believes has hung. Every frame reports, and what the payload
 * decodes to so far is shown as soon as it decodes.
 */
const progress = (label: string) => ({ done, total, partial, frameMs }: DetectProgress): void => {
  const rate = frameMs === undefined ? '' : ` · ${(frameMs / 1000).toFixed(1)} s per frame`
  const found = partial ? ` · payload ${partial}` : ''
  say(total > 1 ? `reading ${label}: frame ${done} of ${total}${found}${rate}` : `reading ${label}${rate}`)
}

const verdictOf = async (file: File, seen: { claim?: WatermarkClaim }, extra: { sidecar?: Uint8Array, detection?: WatermarkEvidence }): Promise<Verdict> => {
  const bytes = new Uint8Array(await file.arrayBuffer())
  const verdict = await verify(bytes, {
    sidecar: extra.sidecar,
    // Read at every verdict, not captured once: switching a log off in the
    // panel has to change the next verdict, or the control is decoration.
    trustedLogs: trustedLogs(),
    // Same rule as the logs: read at every verdict, so switching an authority
    // off in the panel changes the next one.
    tsaRoots: trustedTsaRoots(),
    watermark: lookup(bytes, extra.detection, seen, file.name)
  })
  if (detector) say(`Model ${detector.model_version}, running on ${detector.backend}.`, 'ready', 'Invisible watermark: checked in this page')
  return verdict
}

/** A signature that stands: the verdicts where the file speaks for itself. */
const signed = (v: Verdict): boolean => v.outcome === 'authentic' || v.outcome === 'verified_clip'

const check = async (): Promise<void> => {
  const { copy, original, sidecar, detection } = held
  // Nothing rather than a card telling the reader to drop a file: the dropzone
  // directly above already says that, and the same sentence twice reads as an
  // answer the page has already given.
  document.body.classList.toggle('has-file', copy !== undefined)
  chosen.textContent = copy ? copy.name : ''
  if (!copy) { out.innerHTML = ''; return }

  // Verifying a large video takes seconds of hashing. Without this the page
  // looks like it ignored the file.
  out.innerHTML = '<div class="verdict grey"><p class="lede">Reading the file…</p></div>'

  const sidecarBytes = sidecar ? new Uint8Array(await sidecar.arrayBuffer()) : undefined
  const copySeen: { claim?: WatermarkClaim } = {}
  const copyName = sidecar ? `${copy.name} + ${sidecar.name}` : copy.name
  const copyVerdict = await verdictOf(copy, copySeen, { sidecar: sidecarBytes, detection })

  if (!original) {
    out.innerHTML = card(copyName, copyVerdict)
    return
  }

  const originalSeen: { claim?: WatermarkClaim } = {}
  const originalVerdict = await verdictOf(original, originalSeen, {})

  // The trace: a detection about the copy, compared by the core against the
  // ids the **original's** signed core declares. Only worth showing when the
  // copy's own signature says nothing — when it does, §8 already ran inside
  // its verdict and saying it twice would invite reading the second as more.
  //
  // The detection comes from the user's file when they brought one, and
  // otherwise from the detector this page loaded — which is the only way a
  // copy with no proof of its own ever gets read: nothing in its own verdict
  // asks a question about a watermark, because it declares none. The claim
  // asked is the original's, so the detector is never told what to find.
  let traced: WatermarkOutcome | null = null
  if (originalSeen.claim && !signed(copyVerdict)) {
    const evidence = detection ?? (detector
      ? await detector.detect(new Uint8Array(await copy.arrayBuffer()), originalSeen.claim, progress(copy.name))
      : null)
    if (evidence) traced = evaluateWatermark(evidence, originalSeen.claim)
    if (detector) say(`Model ${detector.model_version}, running on ${detector.backend}.`, 'ready', 'Invisible watermark: checked in this page')
  }

  out.innerHTML = [
    `<div class="pair">${card(copyName, copyVerdict)}${card(original.name, originalVerdict)}</div>`,
    comparison({ name: 'the file in question', verdict: copyVerdict }, { name: 'the original', verdict: originalVerdict }, traced),
    traced ? trace(traced) : ''
  ].join('')
}

const isSidecar = (f: File): boolean => f.name.endsWith('.vcap')
const isDetection = (f: File): boolean => f.name.endsWith('.json')

/**
 * Any zone takes any kind: the extension decides what a file is, and the zone
 * only decides which of the two media slots an ordinary file lands in. So
 * dropping a file and its sidecar together works, and a detection dropped on
 * the wrong box is not lost.
 */
const take = async (files: FileList | File[], zone: 'copy' | 'original'): Promise<void> => {
  const list = Array.from(files)
  const media = list.find((f) => !isSidecar(f) && !isDetection(f))
  const sidecar = list.find(isSidecar)
  const detection = list.find(isDetection)
  if (media) held[zone] = media
  if (sidecar) held.sidecar = sidecar
  if (detection) {
    try {
      held.detection = readEvidence(await detection.text())
      say(`A detection from ${detection.name} is in use. No detector ran in this page.`, 'ready', 'Invisible watermark: read from a detection you supplied')
    } catch {
      // A file that is not a detection changes nothing: the page keeps the
      // verdict it had and says why, rather than failing over a side input.
      say(`${detection.name} is not a readable detection; nothing was loaded`)
    }
  }
  if (media || sidecar || detection) void check()
}

/**
 * The detector bar's state, in one place.
 *
 * It used to be a line of grey text under a button at the foot of the page,
 * which is why a verdict saying "watermark not evaluated" read as a broken
 * page: the sentence naming the absence and the control that fills it were
 * three screens apart. The bar says what the page can check, next to the file
 * it is checking, and the three states are visible without reading.
 */
type Capability = 'off' | 'working' | 'ready'
const say = (text: string, state: Capability = 'off', title?: string): void => {
  detectorState.textContent = text
  if (title !== undefined) detectorTitle.textContent = title
  detectorBar.classList.toggle('working', state === 'working')
  detectorBar.classList.toggle('ready', state === 'ready')
  detectorMark.textContent = state === 'ready' ? '✓' : state === 'working' ? '◍' : '○'
}

for (const zone of ['copy', 'original'] as const) {
  inputs[zone].addEventListener('change', () => { if (inputs[zone].files) void take(inputs[zone].files as FileList, zone) })
  zones[zone].addEventListener('dragover', (e) => { e.preventDefault(); zones[zone].classList.add('over') })
  zones[zone].addEventListener('dragleave', () => zones[zone].classList.remove('over'))
  zones[zone].addEventListener('drop', (e) => { e.preventDefault(); zones[zone].classList.remove('over'); if (e.dataTransfer?.files) void take(e.dataTransfer.files, zone) })
}
inputs.sidecar.addEventListener('change', () => { if (inputs.sidecar.files) void take(inputs.sidecar.files, 'copy') })
inputs.evidence.addEventListener('change', () => { if (inputs.evidence.files) void take(inputs.evidence.files, 'copy') })
zones.sidecar.addEventListener('dragover', (e) => { e.preventDefault(); zones.sidecar.classList.add('over') })
zones.sidecar.addEventListener('dragleave', () => zones.sidecar.classList.remove('over'))
zones.sidecar.addEventListener('drop', (e) => { e.preventDefault(); zones.sidecar.classList.remove('over'); if (e.dataTransfer?.files) void take(e.dataTransfer.files, 'copy') })

/**
 * The detector, on a click and never before it. The module is reached through
 * a URL the bundler cannot resolve, so `detector.js` is a request this page
 * makes only here — and a failure leaves the page exactly as useful as it was,
 * with the reason printed.
 */
loadButton.addEventListener('click', () => {
  loadButton.disabled = true
  say('Fetching the model…', 'working', 'Invisible watermark: loading')
  const url = new URL('detector.js', location.href).href
  const started = performance.now()
  void import(url)
    .then((module: { loadDetector: typeof import('./detector.js').loadDetector }) => module.loadDetector(
      (loaded, total) => {
        const seconds = (performance.now() - started) / 1000
        const speed = seconds > 0 ? ` · ${(loaded / 1e6 / seconds).toFixed(1)} MB/s` : ''
        say(`${(loaded / 1e6).toFixed(1)} of ${(total / 1e6).toFixed(1)} MB${speed}`, 'working', 'Invisible watermark: downloading')
      }
    ))
    .then((loaded) => {
      detector = loaded
      // The backend is part of the answer: the same build is 2.3-2.6x slower
      // on one thread, which is what a page served without cross-origin
      // isolation gets, and a timing nobody can place is not a measurement.
      say(`Model ${loaded.model_version} on ${loaded.backend}, downloaded and verified in ${((performance.now() - started) / 1000).toFixed(1)} s.`, 'ready', 'Invisible watermark: checked in this page')
      void check()
    })
    .catch((error: Error) => {
      loadButton.disabled = false
      say(`The detector did not load: ${error.message}. Watermarks stay unevaluated, which is a weaker verdict and not a failure.`, 'off', 'Invisible watermark: not checked')
    })
})

// The trust panel, before anything can be dropped: a verdict computed against
// a set the reader has not been shown is the thing this page must not produce.
void mountTrust(() => { void check() })
void mountTsa(() => { void check() })

// Offline: the worker precaches this exact build (`sw.js` is generated by the
// build with the list of shipped files). `ready` resolves once the worker is
// active, which comes after install has stored every file — so the footer says
// "available offline" only when it is true. A failed registration (file://,
// a dev build without sw.js) leaves the page working online and is reported,
// not thrown.
const offline = document.getElementById('offline') as HTMLSpanElement
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js')
    .then(() => navigator.serviceWorker.ready)
    .then(() => { offline.textContent = 'available offline' })
    .catch(() => { offline.textContent = 'not cached for offline use' })
}
