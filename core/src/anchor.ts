import { type Bytes, fromBase64 } from './bytes.js'
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
  | { ok: true, onChain: boolean, chain: string, block: number, blockTime?: string }
  | { ok: false, reason: string }

export const verifyAnchor = async (a: AnchorAttachment, coreHash: Bytes, readChain?: ChainReader): Promise<AnchorOutcome> => {
  let root: Bytes, path: Bytes[]
  try { root = fromBase64(a.root); path = a.merkle_path.map(fromBase64) } catch { return { ok: false, reason: 'anchor malformed' } }
  if (!await verifyInclusion(await leafHash(coreHash), a.index, a.tree_size, path, root)) return { ok: false, reason: 'merkle path does not reach the anchored root' }
  if (!readChain) return { ok: true, onChain: false, chain: a.chain, block: a.block }
  const recorded = await readChain(a.chain, a.anchor_id)
  if (!recorded) return { ok: false, reason: 'anchor not found on chain' }
  const same = recorded.treeSize === a.tree_size && recorded.root.length === root.length && recorded.root.every((b, i) => b === root[i])
  return same ? { ok: true, onChain: true, chain: a.chain, block: a.block, blockTime: recorded.blockTime?.toISOString() } : { ok: false, reason: 'anchored root differs from the chain' }
}
