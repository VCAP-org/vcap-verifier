import { evaluateWatermark, verify, type Verdict, type WatermarkClaim, type WatermarkEvidence, type WatermarkOutcome } from 'vcap-verify-core'
import { card, comparison, trace } from './render.js'
import { readEvidence } from './evidence.js'
import type { Detector } from './detector.js'

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
const detectorState = document.getElementById('detector-state') as HTMLParagraphElement
const loadButton = document.getElementById('load-detector') as HTMLButtonElement

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
const lookup = (bytes: Uint8Array, own: WatermarkEvidence | undefined, seen: { claim?: WatermarkClaim }) =>
  async (claim: WatermarkClaim): Promise<WatermarkEvidence | null> => {
    seen.claim = claim
    if (own) return own
    return detector ? await detector.detect(bytes, claim) : null
  }

const verdictOf = async (file: File, seen: { claim?: WatermarkClaim }, extra: { sidecar?: Uint8Array, detection?: WatermarkEvidence }): Promise<Verdict> => {
  const bytes = new Uint8Array(await file.arrayBuffer())
  return await verify(bytes, {
    sidecar: extra.sidecar,
    watermark: lookup(bytes, extra.detection, seen)
  })
}

/** A signature that stands: the verdicts where the file speaks for itself. */
const signed = (v: Verdict): boolean => v.outcome === 'authentic' || v.outcome === 'verified_clip'

const check = async (): Promise<void> => {
  const { copy, original, sidecar, detection } = held
  if (!copy) { out.innerHTML = '<div class="verdict grey"><h2>Drop the file in question</h2></div>'; return }

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

  // The trace: the detection about the copy, compared by the core against the
  // ids the **original's** signed core declares. Only worth showing when the
  // copy's own signature says nothing — when it does, §8 already ran inside
  // its verdict and saying it twice would invite reading the second as more.
  let traced: WatermarkOutcome | null = null
  if (detection && originalSeen.claim && !signed(copyVerdict)) {
    traced = evaluateWatermark(detection, originalSeen.claim)
  }

  out.innerHTML = [
    `<div class="pair">${card(copyName, copyVerdict)}${card(original.name, originalVerdict)}</div>`,
    comparison({ name: 'the file in question', verdict: copyVerdict }, { name: 'the original', verdict: originalVerdict }),
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
      say(`a detection from ${detection.name} is loaded; no detector ran in this page`)
    } catch {
      // A file that is not a detection changes nothing: the page keeps the
      // verdict it had and says why, rather than failing over a side input.
      say(`${detection.name} is not a readable detection; nothing was loaded`)
    }
  }
  if (media || sidecar || detection) void check()
}

const say = (text: string): void => { detectorState.textContent = text }

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
  say('loading the detector…')
  const url = new URL('detector.js', location.href).href
  void import(url)
    .then((module: { loadDetector: typeof import('./detector.js').loadDetector }) => module.loadDetector(
      (loaded, total) => say(`downloading the detector: ${(loaded / 1e6).toFixed(1)} of ${(total / 1e6).toFixed(1)} MB`)
    ))
    .then((loaded) => {
      detector = loaded
      say(`detector ${loaded.model_version} is loaded and runs in this page`)
      void check()
    })
    .catch((error: Error) => {
      loadButton.disabled = false
      say(`no detector: ${error.message}`)
    })
})

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
