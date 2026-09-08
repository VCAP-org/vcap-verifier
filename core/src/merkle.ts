import { type Bytes, concat, equal } from './bytes.js'
import { sha256 } from './sha.js'

/** RFC 6962, the tree of both the transparency log and the anchoring batches. */
export const leafHash = (leaf: Bytes): Promise<Bytes> => sha256(new Uint8Array([0]), leaf)
export const nodeHash = (l: Bytes, r: Bytes): Promise<Bytes> => sha256(new Uint8Array([1]), l, r)

export const verifyInclusion = async (leaf: Bytes, index: number, size: number, path: Bytes[], root: Bytes): Promise<boolean> => {
  if (index < 0 || index >= size) return false
  let fn = index; let sn = size - 1; let r = leaf
  for (const p of path) {
    if (sn === 0) return false
    if ((fn & 1) === 1 || fn === sn) {
      r = await nodeHash(p, r)
      while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1 }
    } else {
      r = await nodeHash(r, p)
    }
    fn >>= 1; sn >>= 1
  }
  return sn === 0 && equal(r, root)
}

export { concat }
