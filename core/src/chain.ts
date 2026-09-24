import { type Bytes, fromHex } from './bytes.js'
import type { ChainReader } from './anchor.js'
import type { ChainEntry } from './trust.js'

/**
 * A `ChainReader` over plain JSON-RPC, for the anchoring contract of §6.2.
 *
 * The core still contacts nothing: `post` is the caller's transport — it sends
 * `body` to `url` and resolves with the response text, or rejects. The page
 * hands in `fetch`, the CLI Node's `fetch`, a test a recorded answer.
 *
 * What is asked is one view call, `getAnchor(uint256 id)`, which returns the
 * root, tree size, block number and timestamp the contract stored. The
 * endpoint is trusted to answer honestly: it is not a light client, and a
 * lying RPC could hand back whatever root the proof carries. The one thing
 * checked about the endpoint is that it serves the chain the document names
 * (`eth_chainId`), so a misconfigured URL cannot read another chain's slot.
 *
 * Three answers, kept apart on purpose:
 *  - a record → the caller compares it with the proof;
 *  - `null` → the contract holds nothing under that id (zero root, or a
 *    revert): *anchor not found on chain*;
 *  - a throw → the chain could not be asked (unknown chain, no network, an RPC
 *    error, a wrong chain id). That is *not consulted*, never *not found*.
 */
export type Post = (url: string, body: string) => Promise<string>

// keccak256("getAnchor(uint256)")[0..4]
const GET_ANCHOR = '0x4c7df18f'

class RpcError extends Error {
  constructor (message: string, readonly code?: number) { super(message) }
}

const call = async (post: Post, url: string, method: string, params: unknown[]): Promise<unknown> => {
  const text = await post(url, JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }))
  let answer: { result?: unknown, error?: { code?: number, message?: string } }
  try { answer = JSON.parse(text) } catch { throw new RpcError(`${method}: the endpoint did not answer JSON`) }
  if (answer.error) throw new RpcError(`${method}: ${answer.error.message ?? 'rpc error'}`, answer.error.code)
  return answer.result
}

/** `getAnchor(id)` calldata: selector, then the id as one 32-byte big-endian word. */
export const encodeGetAnchor = (anchorId: number): string => {
  if (!Number.isSafeInteger(anchorId) || anchorId < 0) throw new Error(`anchor_id ${anchorId} is not a non-negative integer`)
  return GET_ANCHOR + anchorId.toString(16).padStart(64, '0')
}

/** The four static words `getAnchor` returns: root, treeSize, blockNumber, timestamp. Zero root → null. */
export const decodeGetAnchor = (result: unknown): { root: Bytes, treeSize: number, blockNumber: number, blockTime: Date } | null => {
  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{256}$/.test(result)) throw new Error('getAnchor: the answer is not four 32-byte words')
  const word = (i: number): string => result.slice(2 + i * 64, 2 + (i + 1) * 64)
  if (/^0+$/.test(word(0))) return null
  const uint = (i: number): number => Number(BigInt('0x' + word(i)))
  return { root: fromHex(word(0)), treeSize: uint(1), blockNumber: uint(2), blockTime: new Date(uint(3) * 1000) }
}

// A revert is the contract saying "no such id"; any other RPC error is the
// endpoint failing, and must not be read as an answer about the anchor.
const isRevert = (error: unknown): boolean =>
  error instanceof RpcError && (error.code === 3 || /revert/i.test(error.message))

const readFrom = async (post: Post, url: string, entry: ChainEntry, anchorId: number): ReturnType<ChainReader> => {
  const id = await call(post, url, 'eth_chainId', [])
  if (typeof id !== 'string' || Number.parseInt(id, 16) !== entry.chain_id) throw new Error(`${url} serves chain ${String(id)}, not ${entry.chain_id}`)
  let result: unknown
  try {
    result = await call(post, url, 'eth_call', [{ to: entry.contract, data: encodeGetAnchor(anchorId) }, 'latest'])
  } catch (error) {
    if (isRevert(error)) return null
    throw error
  }
  const anchor = decodeGetAnchor(result)
  return anchor && { root: anchor.root, treeSize: anchor.treeSize, blockTime: anchor.blockTime }
}

/** Ask each endpoint of the named chain in order; the first that answers decides. */
export const rpcChainReader = (chains: Record<string, ChainEntry>, post: Post): ChainReader => async (chain, anchorId) => {
  const entry = Object.hasOwn(chains, chain) ? chains[chain] : undefined
  if (!entry) throw new Error(`no RPC is configured for chain ${chain}`)
  const failures: string[] = []
  for (const url of entry.rpc) {
    try {
      return await readFrom(post, url, entry, anchorId)
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error))
    }
  }
  throw new Error(failures.join('; '))
}
