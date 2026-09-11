/**
 * The detector runtime: pixels in, a payload out.
 *
 * This module is the only place in the repository that runs a model, and it is
 * reached only from `detector.ts`, after the downloaded bytes have hashed to
 * what `detector.json` pins. It is bundled into `detector.js` with
 * onnxruntime-web, which is why that file is not in the page's precache and
 * not in its bundle: the engine alone is larger than everything else shipped.
 *
 * ## What it reports, and what it does not
 *
 * `detect` says what came out of the pixels — the layout it read, the id the
 * payload decoded to, how unanimous the copies were, how many frames it looked
 * at — and stops there. The comparison against the ids the device signed is
 * the core's (`evaluateWatermark`), against the signed bytes rather than
 * against anything this module chose to say. So a mark found here is never a
 * verdict, and a payload that does not decode is `decoded: null`, which the
 * core reads as *watermark not recovered*: the normal outcome of a
 * re-compressed copy, and never an error.
 *
 * ## Backends
 *
 * Two execution providers exist in this build, WebGPU and WASM SIMD, and which
 * one is tried first is the **manifest's** call, not this file's: a build's
 * fastest backend is a property of the build. `detector.json` carries
 * `execution_providers`; each is tried in order and the first session that
 * initialises wins, so a browser with no WebGPU falls back without the page
 * noticing. The int8 build published today asks for WASM only, because
 * `vcap-ml/reports/detector-in-the-browser.md` measured int8 on WebGPU at
 * 1016 ms per frame against 211–456 ms on WASM — this graph's quantized nodes
 * have no GPU kernels and round-trip to the CPU inside the session. Routing it
 * to WebGPU would be a regression sold as an acceleration.
 *
 * ## Threads
 *
 * Multi-threaded WASM needs `SharedArrayBuffer`, which needs the page to be
 * cross-origin isolated (COOP/COEP). GitHub Pages does not send those headers,
 * so the shipped page runs the single-thread numbers; `backend` says which it
 * got, because a timing is not comparable without it.
 */
import * as ort from 'onnxruntime-web'
import type { WatermarkClaim, WatermarkEvidence } from 'vcap-verify-core'
import { decodePhoto, decodeVideo } from './layouts.js'

/** Detection is slow enough that silence would read as a hang. */
export interface DetectProgress {
  /** Frames whose logits are in. */
  done: number
  /** Frames that will be looked at in total. */
  total: number
  /** What the payload decodes to from the frames seen so far, when it decodes. */
  partial?: string | null
  /** Milliseconds the last frame cost, so the page can say what the rest will. */
  frameMs?: number
}

export interface Detector {
  model_version: string
  /** The execution provider that initialised, and its thread count. */
  backend: string
  detect (media: Uint8Array, claim: WatermarkClaim, onProgress?: (p: DetectProgress) => void): Promise<WatermarkEvidence>
}

/**
 * Frames a clip is sampled at. `vcap-ml/reports/frames-to-recover.md` measured
 * the payload coming back from the **first** frame on all seven sharing
 * chains — the eight copies inside the message already do the work aggregation
 * was expected to do — so eight uniform frames is margin, not necessity, and
 * the corpus it was measured on is one clip (the report says so). It is
 * reported in the evidence because it is settable: two answers taken under
 * different policies are not comparable.
 */
const VIDEO_FRAMES = 8
const SAMPLING_STRATEGY = 'uniform'

/**
 * The longest side a frame is scaled to before it reaches the graph. The graph
 * resizes to a constant 256 internally (`pins.json`, `export.proc_size`), so
 * this costs no recovery — it bounds the tensor a phone has to allocate, and
 * it matches the 1280 the robustness corpus is measured at.
 */
const MAX_SIDE = 1280

const MESSAGE_BITS = 256

/** The engine's own binaries sit next to the page; nothing is fetched from a CDN. */
ort.env.wasm.wasmPaths = new URL('./', location.href).href
ort.env.logLevel = 'error'

const scaled = (width: number, height: number): { width: number, height: number } => {
  const side = Math.max(width, height)
  if (side <= MAX_SIDE) return { width, height }
  const factor = MAX_SIDE / side
  return { width: Math.max(1, Math.round(width * factor)), height: Math.max(1, Math.round(height * factor)) }
}

/** RGB planes in 0…1, the layout the exported graph takes (`pipeline.to_nchw`). */
const toTensor = (image: ImageData): ort.Tensor => {
  const { width, height, data } = image
  const plane = width * height
  const values = new Float32Array(3 * plane)
  for (let i = 0; i < plane; i++) {
    values[i] = data[i * 4]! / 255
    values[plane + i] = data[i * 4 + 1]! / 255
    values[2 * plane + i] = data[i * 4 + 2]! / 255
  }
  return new ort.Tensor('float32', values, [1, 3, height, width])
}

const canvasOf = (width: number, height: number): { canvas: OffscreenCanvas, context: OffscreenCanvasRenderingContext2D } => {
  const canvas = new OffscreenCanvas(width, height)
  const context = canvas.getContext('2d', { willReadFrequently: true })
  if (!context) throw new Error('this browser gives no 2d canvas to read frames with')
  return { canvas, context }
}

const drawn = (source: CanvasImageSource, width: number, height: number): ImageData => {
  const { context } = canvasOf(width, height)
  context.drawImage(source, 0, 0, width, height)
  return context.getImageData(0, 0, width, height)
}

const stillFrame = async (media: Uint8Array, mime: string): Promise<ImageData> => {
  const bitmap = await createImageBitmap(new Blob([media as BufferSource], { type: mime || 'image/jpeg' }))
  const { width, height } = scaled(bitmap.width, bitmap.height)
  const frame = drawn(bitmap, width, height)
  bitmap.close()
  return frame
}

const settled = async (video: HTMLVideoElement, event: string): Promise<void> =>
  await new Promise((resolve, reject) => {
    const ok = (): void => { cleanup(); resolve() }
    const bad = (): void => { cleanup(); reject(new Error('the clip could not be decoded by this browser')) }
    const cleanup = (): void => {
      video.removeEventListener(event, ok)
      video.removeEventListener('error', bad)
    }
    video.addEventListener(event, ok, { once: true })
    video.addEventListener('error', bad, { once: true })
  })

/**
 * Uniformly spaced frames of a clip, decoded by the browser's own demuxer —
 * the page carries no container parser for this, and a codec the browser
 * cannot open is a detection that did not happen, not a wrong one.
 */
const videoFrames = async function * (media: Uint8Array, mime: string): AsyncGenerator<ImageData> {
  const url = URL.createObjectURL(new Blob([media as BufferSource], { type: mime || 'video/mp4' }))
  const video = document.createElement('video')
  video.muted = true
  video.preload = 'auto'
  video.src = url
  try {
    await settled(video, 'loadedmetadata')
    const { width, height } = scaled(video.videoWidth, video.videoHeight)
    const duration = Number.isFinite(video.duration) && video.duration > 0 ? video.duration : 0
    for (let i = 0; i < VIDEO_FRAMES; i++) {
      // Mid-interval rather than at the edges: the last frame of a clip is
      // often the one an editor faded, and the first is the one a thumbnail
      // generator re-encoded hardest.
      video.currentTime = (duration * (i + 0.5)) / VIDEO_FRAMES
      await settled(video, 'seeked')
      yield drawn(video, width, height)
    }
  } finally {
    video.src = ''
    URL.revokeObjectURL(url)
  }
}

/** The 256 message logits of one frame; column 0 of the graph's output is the detection bit. */
const messageLogits = async (session: ort.InferenceSession, frame: ImageData): Promise<Float32Array> => {
  const feeds = { [session.inputNames[0]!]: toTensor(frame) }
  const output = await session.run(feeds)
  const values = output[session.outputNames[0]!]!.data as Float32Array
  if (values.length < MESSAGE_BITS + 1) throw new Error(`the model returned ${values.length} values, not ${MESSAGE_BITS + 1}`)
  return values.subarray(1, MESSAGE_BITS + 1)
}

const evidenceOf = (layout: string, decoded: string | null, extra: Partial<WatermarkEvidence>): WatermarkEvidence => ({
  layout,
  decoded,
  frames_sampled: 1,
  ...extra
})

/**
 * A session on the first provider that initialises. WebGPU can be present and
 * still fail to give a device; the fallback is silent for the user and named
 * in `backend`.
 */
const openSession = async (model: Uint8Array, providers: string[]): Promise<{ session: ort.InferenceSession, backend: string }> => {
  const failures: string[] = []
  for (const provider of providers) {
    if (provider === 'webgpu' && !('gpu' in navigator)) {
      failures.push('webgpu: this browser exposes no GPU')
      continue
    }
    try {
      const session = await ort.InferenceSession.create(model, {
        executionProviders: [provider as 'wasm' | 'webgpu'],
        graphOptimizationLevel: 'all'
      })
      const threads = provider === 'wasm' ? ` (${ort.env.wasm.numThreads ?? 1} thread${ort.env.wasm.numThreads === 1 ? '' : 's'})` : ''
      return { session, backend: `${provider}${threads}` }
    } catch (error) {
      failures.push(`${provider}: ${(error as Error).message}`)
    }
  }
  throw new Error(`no execution provider started — ${failures.join('; ')}`)
}

export const createDetector = async (model: Uint8Array, modelVersion: string, providers: string[] = ['wasm']): Promise<Detector> => {
  // Threads are capped at what the browser admits: without cross-origin
  // isolation `SharedArrayBuffer` is absent and onnxruntime-web silently uses
  // one, so asking for more would misreport the backend rather than speed it up.
  ort.env.wasm.numThreads = typeof SharedArrayBuffer === 'undefined' ? 1 : Math.min(navigator.hardwareConcurrency || 1, 10)
  const { session, backend } = await openSession(model, providers)

  const detect = async (media: Uint8Array, claim: WatermarkClaim, onProgress?: (p: DetectProgress) => void): Promise<WatermarkEvidence> => {
    const report = (p: DetectProgress): void => onProgress?.(p)

    if (claim.layout === 'video-rep-v1') {
      const summed = new Float32Array(MESSAGE_BITS)
      let frames = 0
      for await (const frame of videoFrames(media, claim.mime)) {
        const started = performance.now()
        const logits = await messageLogits(session, frame)
        for (let i = 0; i < MESSAGE_BITS; i++) summed[i] = summed[i]! + logits[i]!
        frames++
        // The aggregate so far, decoded: a clip that recovers on frame two
        // should show it on frame two rather than after the last seek.
        const soFar = decodeVideo(summed.map((v) => v / frames))
        report({ done: frames, total: VIDEO_FRAMES, partial: soFar.markId === null ? null : String(soFar.markId), frameMs: performance.now() - started })
      }
      if (frames === 0) throw new Error('no frame could be decoded out of this clip')
      // Every frame carries the same message, so the logits are averaged and
      // the repetition layout is decoded once, on the aggregate — the same
      // thing `robustness.py` does on the server side.
      const { markId, agreement } = decodeVideo(summed.map((v) => v / frames))
      return evidenceOf('video-rep-v1', markId === null ? null : String(markId), {
        agreement,
        frames_sampled: frames,
        sampling: { frames: VIDEO_FRAMES, strategy: SAMPLING_STRATEGY },
        model_version: modelVersion
      })
    }

    const started = performance.now()
    const logits = await messageLogits(session, await stillFrame(media, claim.mime))
    const payload = decodePhoto(logits)
    report({ done: 1, total: 1, partial: payload?.captureId ?? null, frameMs: performance.now() - started })
    return evidenceOf('photo-bch-v3', payload?.captureId ?? null, {
      ...(payload ? { corrected_bits: payload.correctedBits } : {}),
      sampling: { frames: 1, strategy: 'still' },
      model_version: modelVersion
    })
  }

  return { model_version: modelVersion, backend, detect }
}
