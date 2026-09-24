import { verify, type Verdict, type WatermarkClaim, type WatermarkEvidence } from 'vcap-verify-core'
import { bareMark, card } from './render.js'
import { readEvidence } from './evidence.js'
import { chainReader, mountChains, mountTrust, mountTsa, trustedLogs, trustedTsaRoots } from './trust.js'
import type { Detector, DetectProgress } from './detector.js'

/**
 * The page: one file in (with its sidecar or a detection, when the user has
 * them), the shared core over it, one verdict out in the specification's
 * words. Nothing is uploaded. The one request a verdict may make is to the
 * public chain an `anchor` names (`chains.json`), and it carries the anchor id
 * only; offline, the verdict is whole and says *anchoring not verified*.
 *
 * The watermark is the piece that survives a trip through a messaging app,
 * and it is the piece the interface must not let anyone read backwards. It is
 * never a verdict here: the card keeps whatever the signature layer said, and
 * a mark read out of a file with no proof is an identifier, not an answer —
 * see `render.ts`.
 *
 * The detector that reads a mark out of pixels is a separate download
 * (`detector.ts`), never fetched on load and never precached: it is fetched
 * the first time a file needs it — a proof that declares a watermark, or a
 * file with no proof whose pixels may still carry one — checked against the
 * digest it pins, and the verdict waits for it. When it cannot be had the
 * verdict is the one this page gave before a detector existed, with
 * *watermark not evaluated* and the reason on it: weaker, never a failure.
 *
 * The transparency logs it checks a `registry` attachment against are the
 * reader's to see and to change (`trust.ts`). The page ships trusting one, and
 * says on its face whose it is.
 */
const zones = {
  file: document.getElementById('drop') as HTMLDivElement,
  sidecar: document.getElementById('sidecar-drop') as HTMLDivElement
}
const inputs = {
  file: document.getElementById('file') as HTMLInputElement,
  sidecar: document.getElementById('sidecar') as HTMLInputElement,
  evidence: document.getElementById('evidence') as HTMLInputElement
}
/**
 * The registry a capture id can be looked up in, as a path the id is appended
 * to. The only server this page ever names: verification itself needs none,
 * and this is offered to a reader holding a stripped copy as a thing they may
 * choose to do, never as a step.
 *
 * It links straight at the identifier rather than at the form. This page
 * prints the mark as hex, because that is what a 128-bit payload looks like
 * coming out of a model, while a proof spells the same sixteen bytes in
 * base64url — and for a while the conversion between our own two surfaces was
 * the reader's job: paste what this page printed, and the registry answered
 * "not found" about a capture it had.
 */
const TRACE_URL = 'https://console.vcap.gregoriogalante.com/t'

const out = document.getElementById('out') as HTMLDivElement
const chosen = document.createElement('p')
chosen.className = 'chosen'
zones.file.append(chosen)

// Every other file control prints what was chosen beside its button. The
// native control said this for us and looked like somebody else's form; having
// taken it away, the page owes the reader the same fact.
for (const span of document.querySelectorAll<HTMLSpanElement>('[data-name-for]')) {
  const input = document.getElementById(span.dataset.nameFor as string) as HTMLInputElement
  input.addEventListener('change', () => { span.textContent = input.files?.[0]?.name ?? '' })
}
const detectorState = document.getElementById('detector-state') as HTMLParagraphElement
const detectorBar = document.getElementById('detector-bar') as HTMLDivElement
const detectorTitle = document.getElementById('detector-title') as HTMLHeadingElement
const detectorMark = detectorBar.querySelector('.mark') as HTMLSpanElement

// What the user has handed over so far. Each arrives on its own and the
// verdict is recomputed whenever any of them changes, so the order does not
// matter. `detection` is a detector's report about the file.
const held: { file?: File, sidecar?: File, detection?: WatermarkEvidence } = {}
let detector: Detector | null = null
// The load in flight, shared by every file that needs it meanwhile; cleared on
// failure so the next file tries again rather than inheriting a dead promise.
let loading: Promise<Detector> | null = null
// Bumped by every check: a verdict that waited on a 34 MB download must not
// overwrite the verdict of a file dropped after it.
let generation = 0

/**
 * The detector, loaded the first time a file needs it, with every phase said
 * out loud: the download (MB loaded of total), the digest check, the engine.
 * Rejects with the reason, which the bar prints and the verdict carries.
 */
const ensureDetector = async (): Promise<Detector> => {
  if (detector) return detector
  loading ??= fetchDetector().then(
    (loaded) => { detector = loaded; return loaded },
    (error: Error) => {
      loading = null
      say(`The detector did not load: ${error.message}. Watermarks stay unevaluated, which is a weaker verdict and not a failure.`, 'off', 'Invisible watermark: not checked')
      throw error
    }
  )
  return await loading
}

const fetchDetector = async (): Promise<Detector> => {
  say('Fetching the model…', 'working', 'Invisible watermark: loading')
  const url = new URL('detector.js', location.href).href
  const started = performance.now()
  const module = await import(url) as { loadDetector: typeof import('./detector.js').loadDetector }
  const loaded = await module.loadDetector(
    (done, total) => {
      const seconds = (performance.now() - started) / 1000
      const speed = seconds > 0 ? ` · ${(done / 1e6 / seconds).toFixed(1)} MB/s` : ''
      say(`${(done / 1e6).toFixed(1)} of ${(total / 1e6).toFixed(1)} MB${speed}`, 'working', 'Invisible watermark: downloading the model')
    },
    // The two phases after the bytes arrive, which together take longer than
    // the download on a slow link and used to happen in silence.
    (phase) => {
      if (phase === 'checking') say('Checking the model against the digest this page pins.', 'working', 'Invisible watermark: checking the model')
      else say('Fetching the WebAssembly engine — about 28 MB more, once.', 'working', 'Invisible watermark: starting the engine')
    }
  )
  // The backend is part of the answer: the same build is 2.3-2.6x slower on
  // one thread, which is what a page served without cross-origin isolation
  // gets, and a timing nobody can place is not a measurement.
  say(`Model ${loaded.model_version} on ${loaded.backend}, downloaded and verified in ${((performance.now() - started) / 1000).toFixed(1)} s.`, 'ready', 'Invisible watermark: checked in this page')
  return loaded
}

/**
 * The core's watermark lookup: the user's detection when they brought one,
 * otherwise the detector, fetched now if it has not been. A detector that
 * cannot be had throws, and the core reads that as *watermark not evaluated*
 * with the reason. The core compares what comes back against the signed claim.
 */
const lookup = (bytes: Uint8Array, own: WatermarkEvidence | undefined, label: string) =>
  async (claim: WatermarkClaim): Promise<WatermarkEvidence | null> => {
    if (own) return own
    return await (await ensureDetector()).detect(bytes, claim, progress(label))
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

const verdictOf = async (file: File, extra: { sidecar?: Uint8Array, detection?: WatermarkEvidence }): Promise<Verdict> => {
  const bytes = new Uint8Array(await file.arrayBuffer())
  const verdict = await verify(bytes, {
    sidecar: extra.sidecar,
    // Read at every verdict, not captured once: switching a log off in the
    // panel has to change the next verdict, or the control is decoration.
    trustedLogs: trustedLogs(),
    // Same rule as the logs: read at every verdict, so switching an authority
    // off in the panel changes the next one.
    tsaRoots: trustedTsaRoots(),
    // Same rule again: a chain switched off in the panel is not read.
    readChain: chainReader(),
    watermark: lookup(bytes, extra.detection, file.name)
  })
  if (detector) say(`Model ${detector.model_version}, running on ${detector.backend}.`, 'ready', 'Invisible watermark: checked in this page')
  return verdict
}

/**
 * Read the mark out of a file that carries no proof, on its own terms.
 *
 * The claim handed to the detector names a layout and nothing else: there is
 * no signed id to compare against, which is exactly why what comes back is
 * printed as an identifier and never as a verdict. Choosing the layout from
 * the mime is the same rule §8 uses to tell a video proof from a photo one.
 */
const markAlone = async (file: File): Promise<string> => {
  let loaded: Detector
  try { loaded = await ensureDetector() } catch {
    return `<div class="panel mark">
      <h3>This file carries no proof — but it may still carry an invisible mark</h3>
      <p class="muted">A copy that came back from a chat app or a social network has usually lost its proof and kept the mark. The detector could not be loaded (the reason is above), so this page could not look.</p>
    </div>`
  }
  const video = file.type.startsWith('video/')
  const claim: WatermarkClaim = {
    layout: video ? 'video-rep-v1' : 'photo-bch-v3',
    captureId: '',
    mime: file.type,
    coreHash: ''
  }
  try {
    const evidence = await loaded.detect(new Uint8Array(await file.arrayBuffer()), claim, progress(file.name))
    say(`Model ${loaded.model_version}, running on ${loaded.backend}.`, 'ready', 'Invisible watermark: checked in this page')
    return bareMark(evidence, TRACE_URL)
  } catch {
    return ''
  }
}

const check = async (): Promise<void> => {
  const { file, sidecar, detection } = held
  // Nothing rather than a card telling the reader to drop a file: the dropzone
  // directly above already says that, and the same sentence twice reads as an
  // answer the page has already given.
  document.body.classList.toggle('has-file', file !== undefined)
  chosen.textContent = file ? file.name : ''
  const run = ++generation
  if (!file) { out.innerHTML = ''; return }

  // Verifying a large video takes seconds of hashing, and the first file that
  // needs the detector waits for its download. Without this the page looks
  // like it ignored the file; `say` writes the detector's progress here too.
  out.innerHTML = '<div class="verdict grey"><p class="lede" id="pending">Reading the file…</p></div>'

  const sidecarBytes = sidecar ? new Uint8Array(await sidecar.arrayBuffer()) : undefined
  const name = sidecar ? `${file.name} + ${sidecar.name}` : file.name
  const verdict = await verdictOf(file, { sidecar: sidecarBytes, detection })
  // A file the signature layer could not speak for may still carry a mark:
  // the watermark is only evaluated for a proof that declares one, which a
  // stripped copy does not have. This is the file people actually arrive with,
  // and its verdict waits for the mark like a sealed file's does.
  const mark = verdict.outcome === 'no_proof_found' ? await markAlone(file) : ''
  if (run !== generation) return
  out.innerHTML = card(name, verdict) + mark
}

const isSidecar = (f: File): boolean => f.name.endsWith('.vcap')
const isDetection = (f: File): boolean => f.name.endsWith('.json')

/**
 * Any zone takes any kind: the extension decides what a file is. So dropping
 * a file and its sidecar together works, and a detection dropped on the wrong
 * box is not lost.
 */
const take = async (files: FileList | File[]): Promise<void> => {
  const list = Array.from(files)
  const media = list.find((f) => !isSidecar(f) && !isDetection(f))
  const sidecar = list.find(isSidecar)
  const detection = list.find(isDetection)
  if (media) held.file = media
  if (sidecar) held.sidecar = sidecar
  let detectionRead = false
  if (detection) {
    try {
      held.detection = readEvidence(await detection.text())
      detectionRead = true
      say(`A detection from ${detection.name} is in use. No detector ran in this page.`, 'ready', 'Invisible watermark: read from a detection you supplied')
    } catch {
      // A file that is not a detection changes nothing: the page keeps the
      // verdict it had and says why, rather than failing over a side input.
      say(`${detection.name} is not a readable detection; nothing was loaded`)
    }
  }
  // An unreadable detection changes nothing, so it re-verifies nothing: a
  // second pass would only try the detector again and bury the reason above.
  if (media || sidecar || detectionRead) void check()
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
  const pending = document.getElementById('pending')
  if (pending && state === 'working') pending.textContent = `${detectorTitle.textContent ?? ''} — ${text}`
  if (title !== undefined) detectorTitle.textContent = title
  detectorBar.classList.toggle('working', state === 'working')
  detectorBar.classList.toggle('ready', state === 'ready')
  detectorMark.textContent = state === 'ready' ? '✓' : state === 'working' ? '◍' : '○'
}

for (const input of Object.values(inputs)) {
  input.addEventListener('change', () => { if (input.files) void take(input.files) })
}
for (const zone of Object.values(zones)) {
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over') })
  zone.addEventListener('dragleave', () => zone.classList.remove('over'))
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('over'); if (e.dataTransfer?.files) void take(e.dataTransfer.files) })
}

// The trust panel, before anything can be dropped: a verdict computed against
// a set the reader has not been shown is the thing this page must not produce.
void mountTrust(() => { void check() })
void mountTsa(() => { void check() })
mountChains(() => { void check() })

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
