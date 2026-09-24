/**
 * The two payload layouts, decoded from what the model says.
 *
 * A detector produces 256 soft bits; a layout is what turns them into an id,
 * or into nothing. The proof format declares which layout was used and
 * deliberately does not define its internals; the bit layout is specified in
 * `vcap-spec/spec/watermark-layouts-1.0.md`. This file is the JavaScript port
 * that has to stay bit-identical to the reference encoder in our model
 * pipeline (not public), pinned by the vectors that pipeline exports
 * (`vcap-spec/vectors/_watermark/layouts.json`, run by `test/layouts.test.ts`).
 *
 * The two differ because the channels differ. A photo survives compression
 * with most bits intact, so it carries the whole 128-bit capture id under a
 * block code. A video re-encoded by a messaging app comes back with bit errors
 * in the tens, past any block code of this size, so it carries a short id
 * repeated eight times and the proof binds that id to the capture id.
 *
 * Two numbers exist for that repetition code and only the smaller one is a
 * promise. The code recovers an id through roughly 51 random flips of 256
 * (≈ 0.80 agreement) — but `VIDEO_AGREEMENT_FLOOR` below lets one be
 * **reported** only through 38 of 256, a 14.8 % bit error rate: agreement is
 * `1 − flips/256` while every position's majority holds, so 38 flips is 0.8516
 * and reportable and 39 is 0.8477 and refused. The 51 is what the code can
 * repair; the 38 is all `decodeVideo` may say out loud, and the five points of
 * bit error rate between them are not margin this file has.
 *
 * Inside that ceiling recovery is probable and not certain: a position whose
 * eight copies split 4–4 ties and loses the CRC, so about three patterns in
 * four resolve the id at 38 flips. Every failure there is a **refusal and
 * never a wrong id** — a 20 000-pattern sweep per flip count returned none at
 * any count — which is the asymmetry the floor exists for
 * (`vcap-spec/spec/watermark-robustness-1.0.md`, *What may be reported*).
 *
 * Failure is a result here, never an exception: a payload that does not decode
 * is *not recovered*, which is the normal outcome of heavy re-compression and
 * the one thing this must never dress up as a wrong id (§8).
 */

/** A decoded photo payload, or `null` when the block code gave up. */
export interface PhotoPayload {
  /** The 16 capture-id bytes, hex. */
  captureId: string
  /** Bits the block code had to correct — the margin that was left. */
  correctedBits: number
}

/**
 * A decoded video payload. `markId` is null when the CRC rejected the vote —
 * or when the copies agreed too little for the vote to be believed.
 */
export interface VideoPayload {
  markId: number | null
  /** How unanimous the eight copies were, 0…1. Meaningful even when the CRC fails. */
  agreement: number
  /**
   * A block passed the CRC and the floor refused it — as against nothing
   * decoding at all. Both are *no id*; they are not the same thing to tell a
   * reader, and this is the only place that still knows which happened.
   */
  refused: boolean
}

// --- GF(2^8), the field BCH(255,131) is built over -------------------------
// Primitive polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1), the same one bchlib
// uses for m=8 in the exporter.
const EXP = new Uint8Array(512)
const LOG = new Uint8Array(256)
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x
  LOG[x] = i
  x = x << 1
  if (x & 0x100) x ^= 0x11d
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!

const mul = (a: number, b: number): number => (a === 0 || b === 0 ? 0 : EXP[LOG[a]! + LOG[b]!]!)
const div = (a: number, b: number): number => (a === 0 ? 0 : EXP[LOG[a]! + 255 - LOG[b]!]!)
const pow = (a: number, n: number): number => (a === 0 ? 0 : EXP[(LOG[a]! * n) % 255]!)

// --- photo-bch-v3 ----------------------------------------------------------
const DATA_BITS = 128
const ECC_BITS = 124
/** The shortened codeword: BCH(255,131) with three unused data bits. */
const CODE_BITS = DATA_BITS + ECC_BITS
const T = 18

/**
 * Berlekamp-Massey over GF(2^8): the error locator polynomial of the
 * syndromes, and `L`, the number of errors it accounts for. Written for 2t = 36
 * syndromes, which is all this layout ever has.
 *
 * `L` is tracked on its own and never read off the polynomial. The length
 * update is the textbook one — when `2L <= n`, the new length is `n + 1 - L`
 * and the old polynomial becomes the one to shift — and it is a statement about
 * the linear recurrence, not about the array: a coefficient that cancels to
 * zero, or an update that lands past the current end, makes the array's length
 * a wrong `L`. An earlier port tested `sigma.length - 1` there and refused
 * about 3 % of correctable words (0.3 % at four errors, 2.8 % at eighteen)
 * while the reference decoder recovered them.
 */
const errorLocator = (syndromes: number[]): { sigma: number[], errors: number } => {
  let sigma = [1]
  let previous = [1]
  let errors = 0
  let shift = 1
  let lastDiscrepancy = 1
  for (let n = 0; n < syndromes.length; n++) {
    let discrepancy = syndromes[n]!
    for (let i = 1; i <= errors; i++) discrepancy ^= mul(sigma[i] ?? 0, syndromes[n - i]!)
    if (discrepancy === 0) {
      shift++
      continue
    }
    // σ(x) − (d / b) · x^shift · B(x), over a copy wide enough for both terms.
    const scale = div(discrepancy, lastDiscrepancy)
    const updated = new Array<number>(Math.max(sigma.length, previous.length + shift)).fill(0)
    sigma.forEach((c, i) => { updated[i] = c })
    previous.forEach((c, i) => { updated[i + shift] = updated[i + shift]! ^ mul(scale, c) })
    if (2 * errors <= n) {
      errors = n + 1 - errors
      previous = sigma
      lastDiscrepancy = discrepancy
      shift = 1
    } else {
      shift++
    }
    sigma = updated
  }
  return { sigma, errors }
}

/**
 * Chien search: the codeword positions the locator points at, or null if they
 * are not exactly `errors` positions inside the shortened word.
 */
const errorPositions = ({ sigma, errors }: { sigma: number[], errors: number }): number[] | null => {
  // A locator whose degree is not the length Berlekamp-Massey settled on
  // describes no error pattern of that weight: past the correction radius.
  let degree = sigma.length - 1
  while (degree > 0 && sigma[degree] === 0) degree--
  if (degree !== errors) return null
  const found: number[] = []
  // Root α^-i of σ means an error at the coefficient of x^i; the codeword is
  // shortened by three bits, so only exponents inside CODE_BITS are real.
  for (let exponent = 0; exponent < 255; exponent++) {
    let sum = 0
    for (let i = 0; i <= degree; i++) sum ^= mul(sigma[i]!, pow(EXP[exponent]!, i))
    if (sum !== 0) continue
    const position = (255 - exponent) % 255
    if (position >= CODE_BITS) return null
    found.push(position)
  }
  // A locator whose roots do not all exist is a received word past the
  // correction radius: no answer, never a guessed one.
  return found.length === degree ? found : null
}

/**
 * `photo-bch-v3`: 128 capture-id bits, 124 parity bits of BCH(255,131,t=18),
 * zero-padded to the model's 256. `soft` is the detector's logits, positive
 * meaning a one.
 */
export const decodePhoto = (soft: Float32Array | number[]): PhotoPayload | null => {
  const bits = new Uint8Array(CODE_BITS)
  for (let i = 0; i < CODE_BITS; i++) bits[i] = soft[i]! > 0 ? 1 : 0

  // Syndromes S_j = c(α^j). Bit i of the shortened word is the coefficient of
  // x^(CODE_BITS-1-i) in the full length-255 codeword.
  const syndromes: number[] = []
  let failed = false
  for (let j = 1; j <= 2 * T; j++) {
    let s = 0
    for (let i = 0; i < CODE_BITS; i++) {
      if (bits[i]) s ^= EXP[(j * (CODE_BITS - 1 - i)) % 255]!
    }
    syndromes.push(s)
    if (s !== 0) failed = true
  }

  let corrected = 0
  if (failed) {
    const positions = errorPositions(errorLocator(syndromes))
    if (positions === null || positions.length > T) return null
    for (const position of positions) bits[CODE_BITS - 1 - position] = bits[CODE_BITS - 1 - position]! ^ 1
    corrected = positions.length
    // The corrected word must satisfy every syndrome, or the locator found a
    // consistent lie: a miscorrection is worse than a refusal.
    for (let j = 1; j <= 2 * T; j++) {
      let s = 0
      for (let i = 0; i < CODE_BITS; i++) {
        if (bits[i]) s ^= EXP[(j * (CODE_BITS - 1 - i)) % 255]!
      }
      if (s !== 0) return null
    }
  }

  let captureId = ''
  let any = 0
  for (let i = 0; i < DATA_BITS; i += 8) {
    let byte = 0
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i + b]!
    any |= byte
    captureId += byte.toString(16).padStart(2, '0')
  }
  // An all-zero id is what an empty frame decodes to; the exporter refuses to
  // embed it, so reading it back means nothing was there.
  return any === 0 ? null : { captureId, correctedBits: corrected }
}

// --- video-rep-v1 ----------------------------------------------------------
const BLOCK_BITS = 32
const REPS = 8
/**
 * The agreement floor of `watermark-layouts-1.0.md`.
 *
 * Spelled out here rather than imported: this file is the detector's own
 * artifact, kept free of the core so the bundle the browser fetches only when a file needs it
 * stays the layout port and nothing else. `test/layouts.test.ts` pins it equal
 * to the core's `VIDEO_AGREEMENT_FLOOR`, which is the value that decides a
 * verdict — a detection from anywhere else reaches the same gate there.
 */
export const VIDEO_AGREEMENT_FLOOR = 0.85

/** CRC-8/ATM (poly 0x07, init 0x00) over the three id bytes, MSB first. */
export const crc8 = (value: number): number => {
  let crc = 0
  for (const shift of [16, 8, 0]) {
    crc ^= (value >>> shift) & 0xff
    for (let i = 0; i < 8; i++) crc = crc & 0x80 ? ((crc << 1) ^ 0x07) & 0xff : (crc << 1) & 0xff
  }
  return crc
}

/**
 * `video-rep-v1` without the floor: (24-bit mark id ‖ crc8) repeated eight
 * times, the copies summed as soft votes rather than majority-counted, so a
 * bit the model was sure about outweighs seven it was not. The CRC is the only
 * gate here, and `markId` is what the block says — not yet what a reader may
 * be told.
 *
 * It is separate from `decodeVideo` because §8 asks two different questions of
 * the same arithmetic. Naming an id to a reader needs the floor; *agreeing*
 * with an id the aggregate already resolved does not, and a frame is only ever
 * asked the second question (`decodeClip`).
 */
const decodeBlock = (soft: ArrayLike<number>): VideoPayload => {
  const combined = new Float64Array(BLOCK_BITS)
  for (let rep = 0; rep < REPS; rep++) {
    for (let i = 0; i < BLOCK_BITS; i++) combined[i]! += soft[rep * BLOCK_BITS + i]!
  }
  let agreed = 0
  for (let rep = 0; rep < REPS; rep++) {
    for (let i = 0; i < BLOCK_BITS; i++) {
      if ((soft[rep * BLOCK_BITS + i]! > 0) === (combined[i]! > 0)) agreed++
    }
  }
  const agreement = agreed / (REPS * BLOCK_BITS)

  let block = 0
  for (let i = 0; i < BLOCK_BITS; i++) block = block * 2 + (combined[i]! > 0 ? 1 : 0)
  const markId = Math.floor(block / 256)
  const crc = block % 256
  if (markId === 0 || crc8(markId) !== crc) return { markId: null, agreement, refused: false }
  return { markId, agreement, refused: false }
}

/**
 * The floor applied to a block decode, in the one place that applies it: the
 * gate between a block that decoded and an id a reader may be told.
 */
const floored = (block: VideoPayload): VideoPayload =>
  block.markId !== null && block.agreement < VIDEO_AGREEMENT_FLOOR
    ? { markId: null, agreement: block.agreement, refused: true }
    : block

/**
 * A `video-rep-v1` decode a verifier may report an id from.
 *
 * Two gates, not one: the CRC, and `VIDEO_AGREEMENT_FLOOR`. Eight bits of
 * checksum admit one word in 256 by chance and every word they admit is a
 * legal id, so on real recordings the CRC alone handed back ids the pixels had
 * never carried. Below the floor this returns no id and keeps the figure — the
 * core reads that as *watermark not recovered*, which is what a reader can
 * honestly be told: a mark may be there and its id did not resolve.
 */
export const decodeVideo = (soft: ArrayLike<number>): VideoPayload => floored(decodeBlock(soft))

/**
 * What a clip's sampled frames say. `markId`, `agreement` and `refused` are
 * the aggregated decode — the clip's one answer — and `framesWithId` is how
 * many of the sampled frames decoded to that id on their own.
 */
export interface ClipPayload extends VideoPayload {
  /**
   * Null when there is no id to count against: a count of frames carrying
   * nothing is not a number, and reporting 0 there would read as a clip whose
   * frames disagreed rather than as a clip that gave no id at all.
   */
  framesWithId: number | null
}

/**
 * A clip, decoded the two ways §8 needs, because neither one answers the
 * other's question.
 *
 * **The id comes from the aggregate**, the logits of every sampled frame
 * averaged and decoded once. That is not a shortcut: averaging is what lets a
 * mark survive on a chain where no single frame carries it cleanly, and the
 * measurements say the difference is real on the only build browsers get. On
 * `detector_int8`, crf 36 at 640 px reads 39 flipped bits from one frame
 * (agreement 0.848, under the floor) and 35 from eight (0.863, reportable) —
 * so a page that decoded frames individually and reported an id only when a
 * frame passed on its own would refuse a clip it recovers today (an internal
 * measurement).
 *
 * **The count comes from decoding each frame separately**, and it is the only
 * thing that separates a marked recording from one genuine frame spliced into
 * foreign footage. An unmarked frame does not vote against the mark, it
 * abstains — mean absolute message logit 11.3 marked against 0.131 unmarked —
 * so the average is set by any single marked frame, and a splice reports the
 * real id at the agreement of a clean recovery, measured at 0.996. Agreement
 * cannot see that and must never be shown as if it could
 * (`vcap-spec/spec/watermark-robustness-1.0.md`, *The severe result needs no
 * model at all*).
 *
 * **The floor gates the id and not the count** (§8, *Which sampled frames
 * count*). The aggregate is held to it, so the id exists at all; a frame is
 * then only asked whether its own block decodes to that same id, and its own
 * agreement is never compared to 0.85. A chance CRC pass is not a free count —
 * it must also land on the one value in 2²⁴ the clip already resolved — so
 * equality against an already-floored id supplies exactly what the floor
 * supplied. Applying the floor twice cost real counts for nothing: on the int8
 * build this page ships, a clip marked throughout reads 39 flipped bits from
 * one frame (0.848, under the floor) and 35 from eight (0.863, reportable), so
 * it reported *0 of 8* while one spliced frame reported *1 of 8* — the count
 * ranked the genuine recording below the forgery, which is the one comparison
 * it exists to make (an internal measurement).
 *
 * Per-frame decoding still never becomes a second answer: frames are counted
 * only against the id the aggregate reported, so a frame that resolves some
 * other id carries nothing here and is never named, and a clip whose own
 * decode the floor refused reports no id and no count.
 *
 * It costs no model runs. The frames were already inferred one at a time —
 * averaging happened after the detector, not inside it — so this is one extra
 * block decode per frame: a vote and a CRC over 256 numbers.
 */
export const decodeClip = (frames: ReadonlyArray<ArrayLike<number>>): ClipPayload => {
  const averaged = new Float64Array(BLOCK_BITS * REPS)
  for (const frame of frames) {
    for (let i = 0; i < averaged.length; i++) averaged[i]! += frame[i]! / frames.length
  }
  return readClip(decodeBlock(averaged), frames.map(decodeBlock))
}

/**
 * §8's reading rule for a clip, over decodes that have already happened.
 *
 * Split out from `decodeClip` because it is what `vcap-spec`'s
 * `vectors/_watermark/clip-reading.json` pins: those cases are readings — an
 * id, an agreement, a CRC verdict per frame — and not pixels, so the gate can
 * only reach the rule if the rule is reachable without a detector.
 *
 * `aggregate` and `frames` are block decodes, neither of them floored. The
 * floor is applied here and to the aggregate alone, which is also what makes
 * the aggregate own the reported `agreement`: the figure beside an id is the
 * one produced by the decode that produced the id, never a mean over the
 * frames that carried it (§8, *Which agreement is reported*).
 */
export const readClip = (aggregate: VideoPayload, frames: ReadonlyArray<VideoPayload>): ClipPayload => {
  const clip = floored(aggregate)
  if (clip.markId === null) return { ...clip, framesWithId: null }
  return { ...clip, framesWithId: frames.filter((frame) => frame.markId === clip.markId).length }
}
