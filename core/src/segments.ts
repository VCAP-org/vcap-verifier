import { type Bytes, concat, fromBase64, u32be, utf8, equal } from './bytes.js'
import { sha256 } from './sha.js'
import { verifyEs256 } from './es256.js'

/** Spec §5: per-segment messages and the chain over messages. */
const SEPARATOR = utf8('vcap/1.0/seg')
const ZERO = new Uint8Array(32)

export interface SegmentEntry { gop: number, hash: string, prev: string, sig: string }

export const segmentMessage = (captureId: Bytes, index: number, contentHash: Bytes, prev: Bytes): Bytes => {
  if (captureId.length !== 16 || contentHash.length !== 32 || prev.length !== 32) throw new Error('segment message: bad field length')
  return concat(SEPARATOR, captureId, u32be(index), contentHash, prev)
}

export type ChainStatus = 'complete' | 'clip' | 'tampered'

/**
 * `recomputed` carries the content hashes read back from the container (§5),
 * keyed by segment index; a segment absent from it was not recomputed and is
 * verified at message level, which is all a verifier without a demuxer can do.
 */
export const verifyChain = async (captureId: Bytes, segmentCount: number, segments: SegmentEntry[], key: CryptoKey, recomputed?: Map<number, Bytes>): Promise<{ status: ChainStatus, verified: number[], contradicted?: number[], reason?: string }> => {
  const byIndex = new Map(segments.map((s) => [s.gop, s]))
  const messages = new Map<number, Bytes>()
  const verified: number[] = []
  const contradicted: number[] = []
  for (const index of [...byIndex.keys()].sort((a, b) => a - b)) {
    const entry = byIndex.get(index) as SegmentEntry
    let hash: Bytes, storedPrev: Bytes, sig: Bytes
    try { hash = fromBase64(entry.hash); storedPrev = fromBase64(entry.prev); sig = fromBase64(entry.sig) } catch { return { status: 'tampered', verified, reason: `segment ${index}: malformed` } }
    const previous = messages.get(index - 1)
    const expectedPrev = index === 0 ? ZERO : previous ? await sha256(previous) : storedPrev
    if (!equal(storedPrev, expectedPrev)) return { status: 'tampered', verified, reason: `segment ${index}: chain broken` }
    let message: Bytes
    try { message = segmentMessage(captureId, index, hash, storedPrev) } catch { return { status: 'tampered', verified, reason: `segment ${index}: malformed` } }
    if (!await verifyEs256(key, message, sig)) return { status: 'tampered', verified, reason: `segment ${index}: signature invalid` }
    messages.set(index, message)
    // §5: the frames of a present segment are not the signed frames —
    // substitution inside a signed range, red, never a clip. The chain runs
    // over the signed messages, so the walk continues and reports which
    // segments do verify.
    const content = recomputed?.get(index)
    if (content && !equal(content, hash)) contradicted.push(index)
    else verified.push(index)
  }
  if (contradicted.length > 0) return { status: 'tampered', verified, contradicted, reason: `segment ${contradicted.join(', ')}: content differs from the container` }
  const complete = verified.length === segmentCount && verified.every((v, i) => v === i)
  return { status: complete ? 'complete' : 'clip', verified }
}
