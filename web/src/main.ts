import { verify, type Verdict, type WatermarkClaim, type WatermarkEvidence } from 'vcap-verify-core'
import { anchorOffer, bareMark, card, errorCard, escape, markOffer } from './render.js'
import { readEvidence } from './evidence.js'
import { chainOffer, chainReader, enableChain, mountChains, mountTrust, mountTsa, trustInUse, trustedLogs, trustedTsaRoots } from './trust.js'
import type { Detector, DetectorManifest, DetectProgress } from './detector.js'
// The pin, bundled so the page can name the model before anything is fetched.
// `detector.ts` still fetches and checks against the published copy.
import pinned from './detector.json'

/**
 * The page: one file in (with its sidecar or a detection, when the user has
 * them), the shared core over it, one verdict out in the specification's
 * words. Nothing is uploaded. The one request a verdict may make is to the
 * public chain an `anchor` names (`chains.json`), it carries the anchor id
 * only, and it is made only once the reader asks for it: until then, and
 * offline, the verdict is whole and says *anchoring not verified*.
 *
 * The watermark is the piece that survives a trip through a messaging app,
 * and it is the piece the interface must not let anyone read backwards. It is
 * never a verdict here: the card keeps whatever the signature layer said, and
 * a mark read out of a file with no proof is an identifier, not an answer —
 * see `render.ts`.
 *
 * The detector that reads a mark out of pixels is a separate download
 * (`detector.ts`), never fetched on load and never precached. For a proof
 * that declares a watermark it is fetched at once, and the signature's verdict
 * is on the page before it arrives, its watermark line filling in when the
 * detector finishes. For a file with no proof it is fetched only when the
 * reader asks, told the size first: a 60 MB download is not something to
 * start on somebody's phone because they dropped a file. When it cannot be had
 * the verdict is the one this page gave before a detector existed, with
 * *watermark not evaluated* and the reason on it: weaker, never a failure.
 *
 * A reader may run a model of their own instead (Advanced, *Use a different
 * model*). It has no pin, so it is hashed here and named by its own digest:
 * every detection it makes says `custom-<sha256 prefix>`, never the pinned
 * build's version.
 *
 * The transparency logs it checks a `registry` attachment against are the
 * reader's to see and to change (`trust.ts`). The page ships trusting one, and
 * says on its face whose it is. The first view shows none of this — the
 * defaults work on their own — and the Advanced summary names what is in use,
 * and says "custom" once any of it was changed.
 */
const zones = {
  file: document.getElementById('drop') as HTMLDivElement,
  sidecar: document.getElementById('sidecar-drop') as HTMLDivElement
}
const inputs = {
  file: document.getElementById('file') as HTMLInputElement,
  sidecar: document.getElementById('sidecar') as HTMLInputElement,
  evidence: document.getElementById('evidence') as HTMLInputElement,
  model: document.getElementById('model') as HTMLInputElement
}
/**
 * The registry a capture id can be looked up in, as a path the id is appended
 * to. The only server this page ever names: verification itself needs none,
 * and this is offered to a reader holding a stripped copy as a thing they may
 * choose to do, never as a step.
 *
 * A build-time constant (`VCAP_TRACE_URL`, see `build.mjs`), defaulting to the
 * reference deployment's registry, so a build for another deployment points at
 * its own registry without a code change — and the published build, built
 * with the default, reproduces its published hashes.
 *
 * It links straight at the identifier rather than at the form. This page
 * prints the mark as hex, because that is what a 128-bit payload looks like
 * coming out of a model, while a proof spells the same sixteen bytes in
 * base64url — and for a while the conversion between our own two surfaces was
 * the reader's job: paste what this page printed, and the registry answered
 * "not found" about a capture it had.
 */
declare const __VCAP_TRACE_URL__: string
const TRACE_URL = __VCAP_TRACE_URL__

const out = document.getElementById('out') as HTMLDivElement
const status = document.getElementById('status') as HTMLParagraphElement
const using = document.getElementById('using') as HTMLSpanElement
const modelLine = document.getElementById('detector-model') as HTMLParagraphElement
const modelReset = document.getElementById('model-reset') as HTMLButtonElement
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

// What the user has handed over so far. Each arrives on its own and the
// verdict is recomputed whenever any of them changes, so the order does not
// matter. `detection` is a detector's report about the file.
const held: { file?: File, sidecar?: File, detection?: WatermarkEvidence, detectionName?: string } = {}
/**
 * A model the reader chose instead of the pinned build. It has no digest to be
 * checked against, so it is named by its own: every detection it makes carries
 * `custom-<first 12 hex of its SHA-256>`, and a verdict can never pass it off
 * as the build `detector.json` pins.
 */
let custom: { name: string, bytes: Uint8Array, sha256: string } | null = null
const customVersion = (sha256: string): string => `custom-${sha256.slice(0, 12)}`
let detector: Detector | null = null
// The load in flight, shared by every file that needs it meanwhile; cleared on
// failure so the next file tries again rather than inheriting a dead promise.
let loading: Promise<Detector> | null = null
// Bumped whenever the model changes: a pinned load still in flight when the
// reader picks their own must not come back and replace it.
let source = 0
// Bumped by every check: a verdict that waited on a 34 MB download must not
// overwrite the verdict of a file dropped after it.
let generation = 0
// What the status line keeps saying once the verdict is in: how the watermark
// was read, or why it was not. Reset by every check.
let note: string | null = null

type State = 'idle' | 'working'
/** The status line under the drop: the one place the page speaks while it works. */
const say = (text: string, state: State = 'idle'): void => {
  status.textContent = text
  status.dataset.state = state
}

const toHex = (digest: ArrayBuffer): string =>
  Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`

/**
 * The Advanced summary: what is in use, in one line, visible while the panels
 * are folded. Any departure from what ships reads "custom", so a changed setup
 * is never hidden behind a closed disclosure.
 */
const drawUsing = (): void => {
  const trust = trustInUse()
  const changed = trust.changed || custom !== null || held.detection !== undefined
  const reader = held.detection ? 'your detection' : custom ? 'custom detector' : 'pinned detector'
  using.textContent = `Using${changed ? ' (custom)' : ''}: ${plural(trust.logs, 'log', 'logs')} · ${plural(trust.tsa, 'timestamp authority', 'timestamp authorities')} · ${trust.chains === 0 ? 'chains read on request' : plural(trust.chains, 'chain', 'chains')} · ${reader}`
  using.classList.toggle('custom', changed)
}

/**
 * Which model reads the pixels, said before anything is fetched. The pin is
 * the bundled copy of `detector.json`, the same bytes the detector module
 * fetches and checks against at load, so showing it costs no request.
 */
const drawModel = (): void => {
  modelReset.hidden = custom === null
  if (custom) {
    modelLine.innerHTML = `In use: <strong>a model you supplied</strong>, <code>${escape(custom.name)}</code>, SHA-256 <code>${custom.sha256}</code>. Not pinned: it runs as it is, and every verdict names it <code>${customVersion(custom.sha256)}</code>.`
    return
  }
  const build = (pinned as DetectorManifest).build
  modelLine.innerHTML = build
    ? `In use: the pinned build <code>${escape(build.model_version)}</code>, ${(build.bytes / 1e6).toFixed(1)} MB, SHA-256 <code>${escape(build.sha256)}</code>.`
    : `No detector build is published with this page${(pinned as DetectorManifest).reason ? `: ${escape((pinned as DetectorManifest).reason ?? '')}` : ''}.`
}

const resetDetector = (): void => {
  detector = null
  loading = null
  source++
}

/**
 * The detector, loaded the first time a file needs it, with every phase said
 * out loud on the status line: the download (MB loaded of total), the digest
 * check, the engine. Rejects with the reason, which the status line keeps and
 * the verdict carries.
 */
const ensureDetector = async (): Promise<Detector> => {
  if (detector) return detector
  const mine = source
  loading ??= fetchDetector().then(
    (loaded) => { if (mine === source) detector = loaded; return loaded },
    (error: Error) => {
      if (mine === source) loading = null
      note = `The detector did not load: ${error.message}. Watermarks stay unevaluated, which is a weaker verdict and not a failure.`
      say(note)
      throw error
    }
  )
  return await loading
}

const fetchDetector = async (): Promise<Detector> => {
  say('Fetching the watermark detector…', 'working')
  const url = new URL('detector.js', location.href).href
  const started = performance.now()
  const module = await import(url) as typeof import('./detector.js')
  if (custom) {
    const version = customVersion(custom.sha256)
    return await module.loadCustomDetector(custom.bytes, version, () => {
      say(`Starting the WebAssembly engine for your model (${version}) — about 28 MB, once.`, 'working')
    })
  }
  return await module.loadDetector(
    (done, total) => {
      const seconds = (performance.now() - started) / 1000
      const speed = seconds > 0 ? ` · ${(done / 1e6 / seconds).toFixed(1)} MB/s` : ''
      say(`Downloading the watermark model: ${(done / 1e6).toFixed(1)} of ${(total / 1e6).toFixed(1)} MB${speed}`, 'working')
    },
    // The two phases after the bytes arrive, which together take longer than
    // the download on a slow link and used to happen in silence.
    (phase) => {
      if (phase === 'checking') say('Checking the model against the digest this page pins.', 'working')
      else say('Fetching the WebAssembly engine — about 28 MB more, once.', 'working')
    }
  )
}

/**
 * The backend is part of the answer: the same build is 2.3-2.6x slower on one
 * thread, which is what a page served without cross-origin isolation gets,
 * and a timing nobody can place is not a measurement. A custom model says so
 * every time it is named.
 */
const ran = (loaded: Detector): void => {
  note = loaded.model_version.startsWith('custom-')
    ? `Custom model ${loaded.model_version}, running on ${loaded.backend} — not the pinned build.`
    : `Model ${loaded.model_version}, running on ${loaded.backend}.`
}

/**
 * The core's watermark lookup over this page's detector, fetched now if it has
 * not been. A detector that cannot be had throws, and the core reads that as
 * *watermark not evaluated* with the reason. The core compares what comes
 * back against the signed claim.
 */
const lookup = (file: File) =>
  async (claim: WatermarkClaim): Promise<WatermarkEvidence | null> => {
    const loaded = await ensureDetector()
    // The File itself, not the bytes already read for the core: the browser
    // decodes it from where it lies, where wrapping the bytes in a new Blob
    // would hold a third copy of a large video.
    const evidence = await loaded.detect(file, claim, progress(file.name))
    ran(loaded)
    return evidence
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
  say(total > 1 ? `Reading the watermark of ${label}: frame ${done} of ${total}${found}${rate}` : `Reading the watermark of ${label}${rate}`, 'working')
}

/**
 * What the detector costs, said before it is fetched: the pinned model plus the
 * WebAssembly engine and its loader (27.8 MB of `.wasm` and 0.4 MB of
 * runtime in this build). A model of the reader's own is already in memory, so
 * only the engine is left to download.
 */
const ENGINE_BYTES = 28.2e6
const detectorDownload = (): number => (custom ? 0 : (pinned as DetectorManifest).build?.bytes ?? 0) + ENGINE_BYTES

const verdictOf = (bytes: Uint8Array, sidecar: Uint8Array | undefined, watermark: (claim: WatermarkClaim) => Promise<WatermarkEvidence | null>): Promise<Verdict> =>
  verify(bytes, {
    sidecar,
    // Read at every verdict, not captured once: switching a log off in the
    // panel has to change the next verdict, or the control is decoration.
    trustedLogs: trustedLogs(),
    // Same rule as the logs: read at every verdict, so switching an authority
    // off in the panel changes the next one.
    tsaRoots: trustedTsaRoots(),
    // Same rule again: a chain switched off in the panel is not read.
    readChain: chainReader(),
    watermark
  })

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
    // The File, decoded where it lies: not a second read into memory, and not
    // a Blob wrapped around the bytes the verdict already holds.
    const evidence = await loaded.detect(file, claim, progress(file.name))
    ran(loaded)
    return bareMark(evidence, TRACE_URL)
  } catch {
    return ''
  }
}

const done = 'Checked in this browser. Nothing was uploaded.'

/**
 * An anchor this page has not read, because its chain is off: say what reading
 * it would send, and to whom, and read it only if the reader says so. The
 * answer replaces the verdict, which is computed again with the chain on.
 */
const offerAnchor = (verdict: Verdict, run: number): void => {
  const a = verdict.anchor
  if (!a?.ok || a.on_chain === true || a.chain === undefined || a.anchor_id === undefined) return
  const offer = chainOffer(a.chain)
  if (!offer) return
  out.insertAdjacentHTML('beforeend', anchorOffer(offer.title, offer.hosts, a.anchor_id))
  const button = document.getElementById('read-anchor') as HTMLButtonElement
  button.addEventListener('click', () => {
    if (run !== generation) return
    enableChain(a.chain as string)
    void check()
  })
}

/**
 * The verdict, in the order the reader needs it: the signature layer first,
 * because it needs no download, then the watermark when the detector has read
 * it. A proof that declares no watermark, or a detection the reader supplied,
 * is one pass. Any failure lands as a card that says what to do — a page
 * that stays on "Reading…" forever is the one answer this page may not give.
 */
const check = async (): Promise<void> => {
  drawUsing()
  const { file, sidecar, detection, detectionName } = held
  // Nothing rather than a card telling the reader to drop a file: the dropzone
  // directly above already says that, and the same sentence twice reads as an
  // answer the page has already given.
  document.body.classList.toggle('has-file', file !== undefined)
  chosen.textContent = file ? file.name : ''
  const run = ++generation
  if (!file) { out.innerHTML = ''; return }

  // Verifying a large video takes seconds of hashing. The status line says so,
  // and the previous verdict goes: it answered a different question.
  out.innerHTML = ''
  note = detection ? `Watermark read from ${detectionName ?? 'the detection you supplied'}. No detector ran in this page.` : null
  say(`Reading ${file.name}…`, 'working')
  const name = sidecar ? `${file.name} + ${sidecar.name}` : file.name

  try {
    const bytes = new Uint8Array(await file.arrayBuffer())
    const sidecarBytes = sidecar ? new Uint8Array(await sidecar.arrayBuffer()) : undefined
    if (detection) {
      const verdict = await verdictOf(bytes, sidecarBytes, async () => detection)
      if (run !== generation) return
      out.innerHTML = card(name, verdict, { detectionSupplied: true })
      offerAnchor(verdict, run)
      say(note ?? done)
      return
    }

    // Pass one: the signature layer, with a lookup that only notes it was
    // asked. The core asks only for a proof that declares a watermark and got
    // as far as the watermark check, which is exactly when a detector is due.
    let wanted = false
    const verdict = await verdictOf(bytes, sidecarBytes, async () => { wanted = true; return null })
    if (run !== generation) return

    if (wanted) {
      out.innerHTML = card(name, verdict, { watermarkPending: true })
      say('The signature is checked. Reading the watermark…', 'working')
      // Pass two, with the detector: it can change the verdict — a payload
      // that contradicts the proof is red (§8) — so the whole card is redrawn
      // from the core's second answer rather than patched.
      const full = await verdictOf(bytes, sidecarBytes, lookup(file))
      if (run !== generation) return
      out.innerHTML = card(name, full)
      offerAnchor(full, run)
      say(note ?? done)
      return
    }

    out.innerHTML = card(name, verdict)
    offerAnchor(verdict, run)
    // A file the signature layer could not speak for may still carry a mark:
    // the watermark is only evaluated for a proof that declares one, which a
    // stripped copy does not have. This is the file people actually arrive
    // with — and reading its pixels costs a download the reader agrees to.
    if (verdict.outcome === 'no_proof_found') {
      if (detector) {
        out.insertAdjacentHTML('beforeend', await markAlone(file))
        if (run !== generation) return
      } else {
        out.insertAdjacentHTML('beforeend', markOffer(detectorDownload() / 1e6))
        const button = document.getElementById('read-mark') as HTMLButtonElement
        button.addEventListener('click', () => {
          button.disabled = true
          void markAlone(file).then((html) => {
            if (run !== generation) return
            document.getElementById('mark-offer')?.remove()
            out.insertAdjacentHTML('beforeend', html)
            say(note ?? done)
          })
        })
      }
    }
    say(note ?? done)
  } catch (error) {
    if (run !== generation) return
    out.innerHTML = errorCard(file.name, error instanceof Error ? error.message : String(error))
    say(`${file.name} could not be checked. Nothing was uploaded.`)
  }
}

/**
 * The reader's own model: hashed here, shown with its digest, and used for
 * every file from now on instead of the pinned build — which is not fetched
 * while it is in place.
 */
const useModel = async (model: File): Promise<void> => {
  say(`Hashing ${model.name}…`, 'working')
  const bytes = new Uint8Array(await model.arrayBuffer())
  custom = { name: model.name, bytes, sha256: toHex(await crypto.subtle.digest('SHA-256', bytes as BufferSource)) }
  resetDetector()
  drawModel()
  say(`${model.name} will read watermarks in this page, named ${customVersion(custom.sha256)}.`)
  if (held.file) void check()
  else drawUsing()
}

modelReset.addEventListener('click', () => {
  custom = null
  inputs.model.value = ''
  resetDetector()
  drawModel()
  say('The pinned model will read watermarks again.')
  if (held.file) void check()
  else drawUsing()
})

const isSidecar = (f: File): boolean => f.name.endsWith('.vcap')
const isDetection = (f: File): boolean => f.name.endsWith('.json')
const isModel = (f: File): boolean => f.name.endsWith('.onnx')

/**
 * Any zone takes any kind: the extension decides what a file is. So dropping
 * a file and its sidecar together works, and a detection or a model dropped on
 * the wrong box is not lost.
 */
const take = async (files: FileList | File[]): Promise<void> => {
  const list = Array.from(files)
  const media = list.find((f) => !isSidecar(f) && !isDetection(f) && !isModel(f))
  const sidecar = list.find(isSidecar)
  const detection = list.find(isDetection)
  const model = list.find(isModel)
  if (media) held.file = media
  if (sidecar) held.sidecar = sidecar
  let detectionRead = false
  if (detection) {
    try {
      held.detection = readEvidence(await detection.text())
      held.detectionName = detection.name
      detectionRead = true
      say(`A detection from ${detection.name} is in use. No detector ran in this page.`)
    } catch {
      // A file that is not a detection changes nothing: the page keeps the
      // verdict it had and says why, rather than failing over a side input.
      say(`${detection.name} is not a readable detection; nothing was loaded`)
    }
  }
  if (model) { await useModel(model); return }
  // An unreadable detection changes nothing, so it re-verifies nothing: a
  // second pass would only try the detector again and bury the reason above.
  if (media || sidecar || detectionRead) void check()
}

for (const input of Object.values(inputs)) {
  input.addEventListener('change', () => { if (input.files) void take(input.files) })
}
for (const zone of Object.values(zones)) {
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over') })
  zone.addEventListener('dragleave', () => zone.classList.remove('over'))
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('over'); if (e.dataTransfer?.files) void take(e.dataTransfer.files) })
}

// The trust panels, before anything can be dropped: a verdict computed against
// a set the reader has not been shown is the thing this page must not produce.
// `check` redraws the Advanced summary too, file or no file.
drawModel()
mountChains(() => { void check() })
void Promise.all([mountTrust(() => { void check() }), mountTsa(() => { void check() })]).then(drawUsing)

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
