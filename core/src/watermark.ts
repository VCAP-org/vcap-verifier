/**
 * Spec §8 "A declared watermark that does not come back": the three non-red
 * outcomes of a declared `watermark`, and the red one underneath them.
 *
 * `watermark` in the core is the **writer** saying a mark was embedded. It is
 * not a promise that a reader will find one, and a reader that does not find
 * one never guesses. Reading the pixels needs a detector — a model, frames, a
 * demux — which this core does not carry and never will: it is the piece that
 * cannot run in a browser tab the way ES256 can. So the detection arrives the
 * way every other answer this core cannot reach offline arrives, from the
 * **caller**, and its absence is a labelled answer rather than a failure
 * (§8: an absent field is a weaker verdict, never an error).
 *
 * ## What the core does NOT verify
 *
 * It cannot re-run a detector, so it does not check that the evidence came
 * from one. What it refuses to take from the caller is the **comparison**: the
 * caller says only what came out of the pixels, and this module compares that
 * against the ids in the signed core — `capture_id` for `photo-bch-v3`,
 * `watermark.mark_id` for `video-rep-v1` (§8) — so the outcome is derived from
 * bytes the device signed and an id the caller reported, never from a verdict
 * word the caller chose. A detection carrying its own `outcome` field is not
 * read.
 *
 * That is deliberately weaker than `keyStatus`, and the difference is worth
 * stating. A key-status statement is trusted because it is **signed** by a log
 * the caller pinned, over a message binding the key id, the instant and the
 * status: the core checks that signature and the answer is the log's, not the
 * caller's. Nothing signs a detector's output — there is no key for it in
 * v1.0, and inventing one would put a server of ours on the path to a verdict,
 * which is the one thing the product forbids. So the evidence is trusted
 * exactly as far as the caller is, which is exactly as far as it already had
 * to be: the same caller hands over the media bytes, so it can reach any
 * verdict it likes by editing those instead. Binding the evidence to the core
 * hash would therefore buy nothing against the caller — but the lookup is
 * handed `coreHash` anyway, so a caller **relaying** a detection made
 * elsewhere (a job queue, a cache) can check that it is about this proof
 * before passing it on. Relaying evidence about another file is how a
 * detection becomes a lie, and it is the relayer that can catch it.
 */
import { type Bytes, fromBase64, toHex } from './bytes.js'

/** The layouts §8 names an id for. An unknown one is *watermark not evaluated*. */
export const WATERMARK_LAYOUTS = ['photo-bch-v3', 'video-rep-v1'] as const
export type WatermarkLayout = (typeof WATERMARK_LAYOUTS)[number]

/**
 * The question, built from the signed core and handed to the caller's lookup:
 * which layout to read, which id to expect, and which proof this is about.
 */
export interface WatermarkClaim {
  /** `watermark.layout` as the writer wrote it; `''` when the field is malformed. */
  layout: string
  /** Hex of the 16-byte `capture_id`: the payload of `photo-bch-v3`. */
  captureId: string
  /** `watermark.mark_id`, the 24-bit id `video-rep-v1` carries, when the core binds one. */
  markId?: number
  /** `media.mime`, the signal §8 uses to tell a video proof from a photo one. */
  mime: string
  /** Hex `core_hash`: the identity of the proof this question is about. */
  coreHash: string
}

/**
 * What a detector reports, in the terms the layouts define. A structural
 * subset of the platform's `DetectionEvidence`, so that block goes in as it
 * comes out; extra members (its own `outcome`, timings) are ignored.
 */
export interface WatermarkEvidence {
  /** The layout the detector read, when it says. A different one is not an answer to this question. */
  layout?: string | null
  /**
   * The id that came out of the payload — hex for `photo-bch-v3`, decimal for
   * `video-rep-v1` — or null when nothing decoded. Null is the normal outcome
   * of heavy re-compression, not a failure.
   */
  decoded?: string | null
  /** `video-rep-v1`: how unanimous the eight copies were, 0…1. Shown next to *not recovered*. */
  agreement?: number | null
  /** `photo-bch-v3`: bits the block code corrected. */
  corrected_bits?: number | null
  /** Frames the decode was averaged over; 1 for a still. */
  frames_sampled?: number | null
  /** Which frames were chosen and how — reported, because it is settable. */
  sampling?: { frames?: number | null, strategy?: string | null } | null
  /** The detector build that looked. A verdict from an unnamed model is not reproducible. */
  model_version?: string | null
}

/**
 * Supplied by the caller, never by this module: the core contacts nothing and
 * runs no model. Null is a legitimate answer — no detector, an unreachable
 * one — and reads as *watermark not evaluated*.
 */
export type WatermarkLookup = (claim: WatermarkClaim) => Promise<WatermarkEvidence | null>

/** §8's three outcomes, plus the contradiction the same section makes red. */
export type WatermarkResult = 'matched' | 'not_recovered' | 'not_evaluated' | 'contradicted'

export interface WatermarkOutcome {
  result: WatermarkResult
  detail: string
  layout?: string
  /** The id the signed core declares, in the layout's own spelling. */
  declared?: string
  /** The id that came back, when one did. */
  decoded?: string
  agreement?: number
  corrected_bits?: number
  frames_sampled?: number
  /** The policy those frames were chosen under: two answers under different policies are not comparable. */
  sampling?: { frames: number, strategy: string }
  model_version?: string
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const isLayout = (v: string): v is WatermarkLayout => (WATERMARK_LAYOUTS as readonly string[]).includes(v)
/** A number a caller sent: finite, in range, or dropped. Never rounded into shape. */
const num = (v: unknown, min: number, max: number): number | undefined =>
  typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max ? v : undefined
const text = (v: unknown, max: number): string | undefined =>
  typeof v === 'string' && v.length > 0 && v.length <= max ? v : undefined

const MARK_ID_MAX = (1 << 24) - 1

/** Both halves or neither: a frame count with no strategy says nothing about comparability. */
const sampling = (v: unknown): { sampling?: { frames: number, strategy: string } } => {
  if (!isObj(v)) return {}
  const frames = num(v.frames, 0, 1e6)
  const strategy = text(v.strategy, 64)
  return frames !== undefined && strategy !== undefined ? { sampling: { frames, strategy } } : {}
}

/** `capture_id` as `photo-bch-v3` spells it: 32 lowercase hex characters. */
export const captureIdHex = (captureIdB64: string): string => {
  try {
    const bytes: Bytes = fromBase64(captureIdB64)
    return bytes.length === 16 ? toHex(bytes) : ''
  } catch { return '' }
}

/**
 * §8's table, applied. Everything here is defensive on purpose: the evidence is
 * data from an untrusted caller, and the failure that matters is a malformed
 * `decoded` sliding into the red row — so a payload this cannot read as an id
 * of the declared layout is *not evaluated* and never a contradiction.
 */
export const evaluateWatermark = (evidence: unknown, claim: WatermarkClaim): WatermarkOutcome => {
  const notEvaluated = (detail: string, extra: Partial<WatermarkOutcome> = {}): WatermarkOutcome =>
    ({ result: 'not_evaluated', detail, ...extra })

  if (!isObj(evidence)) return notEvaluated('the detection evidence is not an object')
  // "The layout is not one this verifier implements" (§8). The claim decides,
  // not the evidence: this is a verifier saying what it can read.
  if (!isLayout(claim.layout)) {
    return notEvaluated(claim.layout === ''
      ? 'the proof declares no readable watermark layout'
      : `layout ${JSON.stringify(claim.layout)} is not one this verifier implements`)
  }
  const layout = claim.layout
  // A detection of another layout answers another question. Silence about the
  // layout is taken as the declared one — the platform reports it, a thinner
  // caller need not.
  const said = text(evidence.layout, 64)
  if (said !== undefined && said !== layout) {
    return notEvaluated(`the detection is about ${JSON.stringify(said)} and the proof declares ${JSON.stringify(layout)}`, { layout })
  }

  const shown: Partial<WatermarkOutcome> = {
    layout,
    ...(num(evidence.agreement, 0, 1) !== undefined ? { agreement: num(evidence.agreement, 0, 1) } : {}),
    ...(num(evidence.corrected_bits, 0, 4096) !== undefined ? { corrected_bits: num(evidence.corrected_bits, 0, 4096) } : {}),
    ...(num(evidence.frames_sampled, 0, 1e6) !== undefined ? { frames_sampled: num(evidence.frames_sampled, 0, 1e6) } : {}),
    ...(text(evidence.model_version, 128) !== undefined ? { model_version: text(evidence.model_version, 128) } : {}),
    ...sampling(evidence.sampling)
  }

  // The id the signed core declares, in the layout's own spelling (§8). A
  // `video-rep-v1` proof with no `mark_id` binds the payload to nothing, and
  // 24 bits collide by design: that is a lookup hint, never an identification.
  const declared = layout === 'photo-bch-v3' ? claim.captureId : claim.markId === undefined ? '' : String(claim.markId)
  if (declared === '') {
    return notEvaluated(layout === 'photo-bch-v3'
      ? 'the proof carries no readable capture id to compare against'
      : 'the proof declares no mark id to compare against', shown)
  }
  const withIds = { ...shown, declared }

  const decoded = evidence.decoded
  // "The layout is known, the payload does not decode" (§8): the normal
  // outcome of heavy re-compression, and it weakens nothing — a watermark is
  // not part of what `sig` covers.
  if (decoded === null || decoded === undefined) {
    return { result: 'not_recovered', detail: 'the payload did not decode', ...withIds }
  }
  const readable = typeof decoded === 'string' && (layout === 'photo-bch-v3'
    ? /^[0-9a-fA-F]{32}$/.test(decoded)
    : /^\d{1,8}$/.test(decoded) && Number(decoded) >= 0 && Number(decoded) <= MARK_ID_MAX)
  if (!readable) {
    return notEvaluated(`the reported payload is not a ${layout} id`, withIds)
  }
  const normalized = layout === 'photo-bch-v3' ? decoded.toLowerCase() : String(Number(decoded))
  if (normalized === declared) {
    return {
      result: 'matched',
      detail: layout === 'photo-bch-v3' ? 'the payload carries the declared capture id' : 'the payload carries the declared mark id',
      ...withIds,
      decoded: normalized
    }
  }
  // §8, "Invalidating — red": a payload that **decodes** to an id other than
  // the one the proof declares. A payload that fails to decode is *not
  // recovered* above and not this — the narrowing matters, because a clip that
  // a messaging app re-compressed is the common case and calling it forged
  // would be the worst mistake this format can make.
  return {
    result: 'contradicted',
    detail: `the payload decodes to ${normalized} and the proof declares ${declared}`,
    ...withIds,
    decoded: normalized
  }
}
