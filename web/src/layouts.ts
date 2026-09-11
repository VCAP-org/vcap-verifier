/**
 * The two payload layouts, decoded from what the model says.
 *
 * A detector produces 256 soft bits; a layout is what turns them into an id,
 * or into nothing. The proof format declares which layout was used and
 * deliberately does not define its internals, so the normative description is
 * `vcap-ml/src/vcap_ml/layouts.py` and `vcap-ml/docs/layouts.md`; this file is
 * the JavaScript port that has to stay bit-identical to it, pinned by the
 * vectors in `vcap-ml/vectors/layouts.json` (mirrored in `test/layouts.json`
 * and run by `test/layouts.test.ts`).
 *
 * The two differ because the channels differ. A photo survives compression
 * with most bits intact, so it carries the whole 128-bit capture id under a
 * block code. A video re-encoded by a messaging app flips a fifth of the bits,
 * past any block code, so it carries a short id repeated eight times and the
 * proof binds that id to the capture id.
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

/** A decoded video payload. `markId` is null when the CRC rejected the vote. */
export interface VideoPayload {
  markId: number | null
  /** How unanimous the eight copies were, 0…1. Meaningful even when the CRC fails. */
  agreement: number
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
 * syndromes, or the sequence that says there are more errors than the code can
 * place. Written for 2t = 36 syndromes, which is all this layout ever has.
 */
const errorLocator = (syndromes: number[]): number[] => {
  let sigma = [1]
  let previous = [1]
  let shift = 1
  let lastDiscrepancy = 1
  for (let n = 0; n < syndromes.length; n++) {
    let discrepancy = syndromes[n]!
    for (let i = 1; i < sigma.length; i++) discrepancy ^= mul(sigma[i]!, syndromes[n - i]!)
    if (discrepancy === 0) {
      shift++
      continue
    }
    const scale = div(discrepancy, lastDiscrepancy)
    const updated = sigma.slice()
    for (let i = 0; i < previous.length; i++) {
      const at = i + shift
      updated[at] = (updated[at] ?? 0) ^ mul(scale, previous[i]!)
    }
    if (sigma.length - 1 <= n - (shift - 1)) {
      previous = sigma
      lastDiscrepancy = discrepancy
      shift = 1
    } else {
      shift++
    }
    sigma = updated
  }
  return sigma
}

/** Chien search: the codeword positions the locator points at, or null if it points outside. */
const errorPositions = (sigma: number[]): number[] | null => {
  const degree = sigma.length - 1
  const found: number[] = []
  // Root α^-i of σ means an error at the coefficient of x^i; the codeword is
  // shortened by three bits, so only exponents inside CODE_BITS are real.
  for (let exponent = 0; exponent < 255; exponent++) {
    let sum = 0
    for (let i = 0; i < sigma.length; i++) sum ^= mul(sigma[i]!, pow(EXP[exponent]!, i))
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
 * `video-rep-v1`: (24-bit mark id ‖ crc8) repeated eight times. The copies are
 * summed as soft votes rather than majority-counted, so a bit the model was
 * sure about outweighs seven it was not.
 */
export const decodeVideo = (soft: Float32Array | number[]): VideoPayload => {
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
  if (markId === 0 || crc8(markId) !== crc) return { markId: null, agreement }
  return { markId, agreement }
}
