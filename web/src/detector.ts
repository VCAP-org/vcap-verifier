/**
 * The watermark detector, and the reason it is a file of its own.
 *
 * Reading a mark out of pixels needs a model. The one that ships is the full
 * int8 build — around 34 MB (decision D17: distillation under 10 MB was
 * dropped, so there is no small build to precache) — which is more than the
 * rest of this page by three orders of magnitude. Three consequences, all
 * visible here:
 *
 * - **Nothing is fetched when the page opens.** This module is not imported by
 *   the bundle; `main.ts` reaches it through a dynamic `import()` of a URL the
 *   bundler cannot resolve, so `detector.js` is a separate artifact that the
 *   browser asks for only after the user clicks.
 * - **It is not in the offline precache.** `sw.js` stores every other shipped
 *   file; this one and the model it pulls are excluded on purpose, so an
 *   offline page is the page minus the detector and not a failed install.
 * - **The page is whole without it.** Every verdict this page renders without a
 *   detector is the verdict it rendered before one existed: *watermark not
 *   evaluated* is a label on a weaker verdict, never an error.
 *
 * What arrives over the network is checked before it runs: `detector.json`
 * pins the model's SHA-256 and its size, and bytes that hash to anything else
 * are refused. That is the same bargain the page's own `hashes.json` offers —
 * unsigned, reproducible — applied to a file too big to ship inside it.
 */
import type { WatermarkClaim, WatermarkEvidence } from 'vcap-verify-core'

/** The published build, when there is one. `runtime` is the module that runs it. */
export interface DetectorBuild {
  /** Where the model sits. Not a server of ours is required: any host serving these exact bytes will do. */
  url: string
  /** SHA-256 of the model, hex. Checked before the bytes reach a runtime. */
  sha256: string
  /** Expected size, so the page can say what the download costs before starting it. */
  bytes: number
  /** The build that looked, carried into the evidence: a detection from an unnamed model is not reproducible. */
  model_version: string
  /** ES module exporting `createDetector`; fetched only after the model verifies. */
  runtime: string
}

export interface DetectorManifest {
  build: DetectorBuild | null
  /** Why there is no build, in words a reader can act on. Shown verbatim. */
  reason?: string
}

/**
 * What a runtime hands back. `detect` reports **what came out of the pixels**
 * and nothing else: the comparison against the ids the device signed belongs
 * to the core, which does it against the signed bytes rather than against
 * anything a detector chose to say (see `core/src/watermark.ts`).
 */
export interface Detector {
  model_version: string
  detect (media: Uint8Array, claim: WatermarkClaim): Promise<WatermarkEvidence>
}

interface Runtime {
  createDetector (model: Uint8Array, modelVersion: string): Promise<Detector>
}

const toHex = (digest: ArrayBuffer): string =>
  Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')

/** Streamed so the page can show what it is costing; `total` is the manifest's figure. */
const download = async (url: string, total: number, onProgress: (loaded: number, total: number) => void): Promise<Uint8Array> => {
  const response = await fetch(url)
  if (!response.ok || !response.body) throw new Error(`the model could not be fetched: ${response.status}`)
  const chunks: Uint8Array[] = []
  let loaded = 0
  const reader = response.body.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
    loaded += value.length
    onProgress(loaded, total)
  }
  const model = new Uint8Array(loaded)
  let at = 0
  for (const chunk of chunks) { model.set(chunk, at); at += chunk.length }
  return model
}

/**
 * Called only from a click. Throws with a sentence the page prints as it is:
 * every failure here leaves the page working and the watermark *not
 * evaluated*, so the message has to say which of the two it is.
 */
export const loadDetector = async (onProgress: (loaded: number, total: number) => void): Promise<Detector> => {
  const response = await fetch('detector.json')
  if (!response.ok) throw new Error(`detector.json could not be read: ${response.status}`)
  const manifest = await response.json() as DetectorManifest
  if (!manifest.build) throw new Error(manifest.reason ?? 'no detector build is published with this page')

  const { url, sha256, bytes, model_version: modelVersion, runtime } = manifest.build
  const model = await download(url, bytes, onProgress)
  const digest = toHex(await crypto.subtle.digest('SHA-256', model as BufferSource))
  // A model that hashes to something else is not the model this page vouches
  // for, whatever it would have decoded.
  if (digest !== sha256) throw new Error(`the downloaded model hashes ${digest} and the manifest pins ${sha256}`)

  const module = await import(new URL(runtime, location.href).href) as Runtime
  return await module.createDetector(model, modelVersion)
}
