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

export const verifyChain = async (captureId: Bytes, segmentCount: number, segments: SegmentEntry[], key: CryptoKey): Promise<{ status: ChainStatus, verified: number[], reason?: string }> => {
  const byIndex = new Map(segments.map((s) => [s.gop, s]))
  const messages = new Map<number, Bytes>()
  const verified: number[] = []
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
    verified.push(index)
  }
  const complete = verified.length === segmentCount && verified.every((v, i) => v === i)
  return { status: complete ? 'complete' : 'clip', verified }
}
