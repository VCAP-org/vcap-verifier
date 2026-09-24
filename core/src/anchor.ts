import { type Bytes, equal, fromBase64 } from './bytes.js'
import { leafHash, verifyInclusion } from './merkle.js'

/**
 * Spec §6.2 `anchor`: recompute the batch root from core_hash, index, size and
 * path. Comparing it with what the contract recorded needs a chain reader;
 * without one the verdict says *anchoring not verified* and stays amber.
 */
export interface AnchorAttachment {
  chain: string, tx: string, block: number, anchor_id: number, index: number, tree_size: number, root: string, merkle_path: string[]
}

// A reader may also return the block's time: §7 makes it the proven instant of
// the capture when no timestamp token is present. Optional, because a light
// client that only reads the contract's storage does not have it.
export type ChainReader = (chain: string, anchorId: number) => Promise<{ root: Bytes, treeSize: number, blockTime?: Date } | null>

export type AnchorOutcome =
  | { ok: true, onChain: boolean, chain: string, block: number, blockTime?: string, unread?: string }
  | { ok: false, reason: string }

const isCount = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0

export const verifyAnchor = async (a: AnchorAttachment, coreHash: Bytes, readChain?: ChainReader): Promise<AnchorOutcome> => {
  // The integers index a tree and name a contract slot; the strings are decoded
  // below. Anything else is written by whoever handed over the file.
  if (typeof a.chain !== 'string' || !isCount(a.block) || !isCount(a.anchor_id) || !isCount(a.index) || !isCount(a.tree_size) ||
    !Array.isArray(a.merkle_path) || !a.merkle_path.every((p) => typeof p === 'string')) return { ok: false, reason: 'anchor malformed' }
  let root: Bytes, path: Bytes[]
  try { root = fromBase64(a.root); path = a.merkle_path.map(fromBase64) } catch { return { ok: false, reason: 'anchor malformed' } }
  if (!await verifyInclusion(await leafHash(coreHash), a.index, a.tree_size, path, root)) return { ok: false, reason: 'merkle path does not reach the anchored root' }
  if (!readChain) return { ok: true, onChain: false, chain: a.chain, block: a.block }
  // A reader that throws could not ask (no network, unknown chain, an RPC
  // error): that is *not consulted*, with the reason, and never *not found* —
  // a verifier offline must not report a genuine anchor as missing.
  let recorded: Awaited<ReturnType<ChainReader>>
  try { recorded = await readChain(a.chain, a.anchor_id) } catch (error) {
    return { ok: true, onChain: false, chain: a.chain, block: a.block, unread: error instanceof Error ? error.message : String(error) }
  }
  if (!recorded) return { ok: false, reason: 'anchor not found on chain' }
  // The reader is the caller's, and a reader that answers nonsense is one that
  // could not be read, never a verdict about the anchor.
  if (!(recorded.root instanceof Uint8Array) || !Number.isSafeInteger(recorded.treeSize) || (recorded.blockTime !== undefined && !(recorded.blockTime instanceof Date && !Number.isNaN(recorded.blockTime.getTime())))) {
    return { ok: true, onChain: false, chain: a.chain, block: a.block, unread: 'the chain reader returned an unreadable answer' }
  }
  const same = recorded.treeSize === a.tree_size && equal(recorded.root, root)
  return same ? { ok: true, onChain: true, chain: a.chain, block: a.block, blockTime: recorded.blockTime?.toISOString() } : { ok: false, reason: 'anchored root differs from the chain' }
}
