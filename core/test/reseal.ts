import { type Json, jcs } from '../src/jcs.js'
import { type Bytes, concat, fromBase64, fromUtf8, toBase64url } from '../src/bytes.js'
import { recomputeSegments } from '../src/container.js'
import { segmentMessage } from '../src/segments.js'
import { timingHash, timingRoot } from '../src/timing.js'
import { sha256, subtle } from '../src/sha.js'
import { buildTrailer, parseTrailer } from '../src/trailer.js'
import { extractCore } from '../src/verify.js'

/**
 * A device-sealed fixture under a core that carries `media.presentation` and
 * `media.timing`.
 *
 * The device proofs of `fixtures/` predate both fields, which §6.1 now requires
 * of every proof carrying `segments`, so `verify` reads them *no proof found*
 * before any GOP is located. The container code these tests exist for is
 * reached only under a core that has it: the same capture id and content
 * hashes, the chain and the core re-signed by a fresh key, the presentation
 * and timing read back from the device's own container as a writer would. Every byte of
 * the media stays the device's. `attestation` is dropped: its leaf is the
 * device key, and a chain about another key is a signature swap (§6.2).
 */
export const resealed = async (file: Bytes): Promise<{ file: Bytes, media: Bytes, payload: Bytes }> => {
  const trailer = parseTrailer(file)
  if (trailer.kind !== 'ok') throw new Error('fixture has no trailer')
  const { attestation: _attestation, ...proof } = JSON.parse(fromUtf8(trailer.payload)) as Record<string, any>
  const captureId = fromBase64(proof.capture_id)
  const read = await recomputeSegments(trailer.media, captureId)
  if (read.kind !== 'hashes' || read.presentation === null) throw new Error('fixture container has no readable presentation')
  const keys = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const sign = async (message: Bytes): Promise<string> =>
    toBase64url(new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, Uint8Array.from(message))))
  const spki = new Uint8Array(await subtle().exportKey('spki', keys.publicKey))

  // §5: prev_link(0) is 32 zero bytes, prev_link(n) the hash of message(n−1).
  let prev: Bytes = new Uint8Array(32)
  const segments = []
  const timings: Bytes[] = []
  for (const entry of proof.segments as { gop: number, hash: string }[]) {
    const message = segmentMessage(captureId, entry.gop, fromBase64(entry.hash), prev)
    const gop = read.gops.find((g) => g.index === entry.gop)
    if (!gop) throw new Error(`fixture container does not locate segment ${entry.gop}`)
    const timing = await timingHash(gop.timing)
    timings.push(timing)
    segments.push({ gop: entry.gop, hash: entry.hash, prev: toBase64url(prev), sig: await sign(message), timing: toBase64url(timing) })
    prev = await sha256(message)
  }
  proof.segments = segments
  const { video, audio } = read.timing.timescales
  proof.media.timing = { video_timescale: Number(video), ...(audio === null ? {} : { audio_timescale: Number(audio) }), root: toBase64url(await timingRoot(timings)) }
  proof.media.presentation = { config: toBase64url(read.presentation.config), matrix: read.presentation.matrix, display: read.presentation.display }
  proof.device.key_id = toBase64url(await sha256(spki))
  proof.sig = { alg: 'ES256', value: await sign(jcs(extractCore(proof as Record<string, Json>))), pub: toBase64url(spki) }
  const payload = jcs(proof as Json)
  return { file: concat(trailer.media, buildTrailer(payload, trailer.flags, trailer.minor)), media: trailer.media, payload }
}
