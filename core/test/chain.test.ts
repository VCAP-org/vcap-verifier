import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { fromBase64, toHex } from '../src/bytes.js'
import { decodeGetAnchor, encodeGetAnchor, rpcChainReader, type Post } from '../src/chain.js'
import { parseChainsDocument, TrustDocumentError } from '../src/trust.js'
import { verify } from '../src/verify.js'
import { corpus } from './corpus.js'

/**
 * The JSON-RPC chain reader, against answers recorded from the public Base
 * Sepolia endpoint (24 Sep 2026). No test here touches the network: `post` is
 * a table from request to recorded response text.
 */
const chains = parseChainsDocument(JSON.parse(readFileSync(join(import.meta.dirname, '../../trust/chains.json'), 'utf8')))
const RPC = 'https://sepolia.base.org'

// eth_call getAnchor(62), as recorded.
const ANCHOR_62 = '0x4d0c66cf533e3e678de31d12b06b7b295377906a6988b8afaf9ad03388e2492d' +
  '0000000000000000000000000000000000000000000000000000000000000001' +
  '0000000000000000000000000000000000000000000000000000000002d0e879' +
  '000000000000000000000000000000000000000000000000000000006ab52fd2'
const REVERT = { code: 3, message: 'execution reverted: panic: array out-of-bounds access (0x32)' }

const word = (n: number | bigint): string => n.toString(16).padStart(64, '0')
const anchorWords = (rootHex: string, treeSize: number, block: number, seconds: number): string => '0x' + rootHex + word(treeSize) + word(block) + word(seconds)

/** A transport that answers from a table; `calls` records every URL and method asked. */
const recorded = (answers: { chainId?: string, call?: string | { code: number, message: string } }, calls: string[] = []): Post => async (url, body) => {
  const { method, params } = JSON.parse(body) as { method: string, params: unknown[] }
  calls.push(`${url} ${method}`)
  const answer = method === 'eth_chainId' ? answers.chainId ?? '0x14a34' : answers.call
  if (method === 'eth_call') expect(params[0]).toMatchObject({ to: chains['base-sepolia']?.contract })
  return JSON.stringify(typeof answer === 'object' ? { jsonrpc: '2.0', id: 1, error: answer } : { jsonrpc: '2.0', id: 1, result: answer })
}

describe('getAnchor encoding', () => {
  it('encodes the selector and the id as one 32-byte word', () => {
    expect(encodeGetAnchor(62)).toBe('0x4c7df18f' + word(62))
    expect(() => encodeGetAnchor(-1)).toThrow()
    expect(() => encodeGetAnchor(1.5)).toThrow()
  })

  it('decodes the recorded answer for id 62', () => {
    const decoded = decodeGetAnchor(ANCHOR_62)
    expect(toHex(decoded?.root as Uint8Array)).toBe('4d0c66cf533e3e678de31d12b06b7b295377906a6988b8afaf9ad03388e2492d')
    expect(decoded).toMatchObject({ treeSize: 1, blockNumber: 47245433 })
    expect(decoded?.blockTime.getTime()).toBe(0x6ab52fd2 * 1000)
  })

  it('reads a zero root as nothing stored, and refuses a short answer', () => {
    expect(decodeGetAnchor('0x' + '0'.repeat(256))).toBeNull()
    expect(() => decodeGetAnchor('0x')).toThrow()
  })
})

describe('rpcChainReader', () => {
  it('reads id 62 after checking the chain id', async () => {
    const calls: string[] = []
    const read = rpcChainReader(chains, recorded({ call: ANCHOR_62 }, calls))
    const anchor = await read('base-sepolia', 62)
    expect(anchor?.treeSize).toBe(1)
    expect(toHex(anchor?.root as Uint8Array)).toMatch(/^4d0c66cf/)
    expect(calls).toEqual([`${RPC} eth_chainId`, `${RPC} eth_call`])
  })

  it('answers null for an id the contract never wrote: zero root or revert', async () => {
    expect(await rpcChainReader(chains, recorded({ call: '0x' + '0'.repeat(256) }))('base-sepolia', 1_000_000)).toBeNull()
    expect(await rpcChainReader(chains, recorded({ call: REVERT }))('base-sepolia', 1_000_000)).toBeNull()
  })

  it('throws, never null, when it could not ask', async () => {
    // An endpoint serving another chain: its storage says nothing about this one.
    await expect(rpcChainReader(chains, recorded({ chainId: '0x1', call: ANCHOR_62 }))('base-sepolia', 62)).rejects.toThrow(/serves chain 0x1, not 84532/)
    await expect(rpcChainReader(chains, recorded({ call: ANCHOR_62 }))('ethereum', 62)).rejects.toThrow(/no RPC is configured for chain ethereum/)
    await expect(rpcChainReader(chains, async () => { throw new TypeError('fetch failed') })('base-sepolia', 62)).rejects.toThrow(/fetch failed/)
    await expect(rpcChainReader(chains, recorded({ call: { code: -32005, message: 'rate limited' } }))('base-sepolia', 62)).rejects.toThrow(/rate limited/)
  })

  it('tries the next endpoint when one fails', async () => {
    const two = { 'base-sepolia': { ...chains['base-sepolia']!, rpc: ['https://down.example', RPC] } }
    const answer = recorded({ call: ANCHOR_62 })
    const post: Post = async (url, body) => { if (url !== RPC) throw new Error('down'); return await answer(url, body) }
    expect((await rpcChainReader(two, post)('base-sepolia', 62))?.treeSize).toBe(1)
  })
})

describe('parseChainsDocument', () => {
  it('refuses an entry it could not use safely', () => {
    const ok = { chain_id: 84532, contract: '0x' + 'a'.repeat(40), rpc: ['https://rpc.example'] }
    expect(Object.keys(parseChainsDocument({ chains: { x: ok } }))).toEqual(['x'])
    expect(() => parseChainsDocument({ chains: { x: { ...ok, rpc: ['http://rpc.example'] } } })).toThrow(TrustDocumentError)
    expect(() => parseChainsDocument({ chains: { x: { ...ok, contract: '0x12' } } })).toThrow(TrustDocumentError)
    expect(() => parseChainsDocument({ chains: { x: { ...ok, chain_id: '84532' } } })).toThrow(TrustDocumentError)
    expect(() => parseChainsDocument({ logs: [] })).toThrow(TrustDocumentError)
  })
})

/**
 * The reader inside `verify`, on the corpus's anchored file (vector 57): the
 * chain answers what the proof says, something else, or nothing at all.
 */
describe('verify with an RPC chain reader', () => {
  const dir = join(corpus().dir, '57-jpeg-anchor-on-chain')
  const file = new Uint8Array(readFileSync(join(dir, 'input.jpg')))
  const { anchor } = JSON.parse(readFileSync(join(dir, 'proof.json'), 'utf8')) as { anchor: { root: string, tree_size: number, block: number } }
  const now = new Date(1757419200000)
  const run = async (post: Post) => await verify(file, { recomputeSegments: false, now, readChain: rpcChainReader(chains, post) })

  it('matching root: anchored, with the block', async () => {
    const v = await run(recorded({ call: anchorWords(toHex(fromBase64(anchor.root)), anchor.tree_size, anchor.block, 1757332890) }))
    expect(v.anchor).toMatchObject({ ok: true, on_chain: true, detail: `anchored on base-sepolia, block ${anchor.block}` })
    expect(v.labels).not.toContain('anchoring not verified')
    expect(v.validated_at).toEqual({ instant: '2025-09-08T12:01:30.000Z', source: 'anchor' })
  })

  it('differing root: the anchor does not hold up', async () => {
    const v = await run(recorded({ call: anchorWords('11'.repeat(32), anchor.tree_size, anchor.block, 1757332890) }))
    expect(v.anchor).toMatchObject({ ok: false, detail: 'anchored root differs from the chain' })
    expect(v.labels).toEqual(expect.arrayContaining(['anchor evidence invalid', 'not anchored']))
  })

  it('a reader that throws: not consulted, with why, and never a failure', async () => {
    const v = await run(async () => { throw new TypeError('fetch failed') })
    expect(v.outcome).toBe('authentic')
    expect(v.anchor).toMatchObject({ ok: true, on_chain: false })
    expect(v.anchor?.detail).toBe('merkle path reaches the anchored root; the chain could not be read (fetch failed)')
    expect(v.labels).toContain('anchoring not verified')
    expect(v.labels).not.toContain('anchor evidence invalid')
  })
})
