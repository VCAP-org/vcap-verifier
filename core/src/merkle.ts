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

/**
 * RFC 6962 §2.1.4.2: does `secondRoot` extend `firstRoot`?
 *
 * The check a client makes to catch a **split view** — a log showing one head
 * to one reader and a different one to another. An inclusion proof says a leaf
 * is in a tree; only consistency says the tree it is in is the same tree that
 * grew, and a log that rewrote history fails here and nowhere else.
 *
 * Written here rather than left to the platform because it is a *reader's*
 * check: the party that would benefit from a split view is the log, so the
 * verification cannot live only in the log's own code.
 */
export const verifyConsistency = async (
  first: number, second: number, firstRoot: Bytes, secondRoot: Bytes, path: Bytes[]
): Promise<boolean> => {
  if (first < 0 || first > second) return false
  // Equal sizes need no proof, and an empty first tree is consistent with
  // anything — both are cases where a path would be evidence of confusion.
  if (first === second) return path.length === 0 && equal(firstRoot, secondRoot)
  if (first === 0) return path.length === 0
  if (path.length === 0) return false

  let fn = first - 1
  let sn = second - 1
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1 }

  const nodes = [...path]
  // When `first` is a power of two the first tree is a complete subtree, so
  // its root is not in the path: it is the seed. Otherwise the path carries it.
  const seed = (first & (first - 1)) === 0 ? firstRoot : nodes.shift() as Bytes
  let fr = seed
  let sr = seed
  for (const node of nodes) {
    if (sn === 0) return false
    if ((fn & 1) === 1 || fn === sn) {
      fr = await nodeHash(node, fr)
      sr = await nodeHash(node, sr)
      while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1 }
    } else {
      sr = await nodeHash(sr, node)
    }
    fn >>= 1
    sn >>= 1
  }
  return sn === 0 && equal(fr, firstRoot) && equal(sr, secondRoot)
}

export { concat }
