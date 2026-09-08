import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { verify, verifyChain, jcs, toHex, extractCore, fromBase64 } from '../src/index.js'
import { importP256Spki } from '../src/es256.js'
import { sha256 } from '../src/sha.js'
import type { Json } from '../src/jcs.js'

/**
 * The conformance vectors of vcap-spec. Source of truth: the `spec` submodule;
 * fallback: the snapshot in core/vectors, kept equal by vectors-sync.mjs so CI
 * needs no token for the private spec repository. This core was written from
 * the spec, not from the reference verifier; the vectors are where the two
 * must agree byte for byte.
 */
const SUBMODULE = join(import.meta.dirname, '..', '..', 'spec', 'vectors')
const SNAPSHOT = join(import.meta.dirname, '..', 'vectors')
const VECTORS = existsSync(SUBMODULE) && readdirSync(SUBMODULE).length > 0 ? SUBMODULE : SNAPSHOT
const dirs = existsSync(VECTORS) ? readdirSync(VECTORS).filter((d) => /^\d\d-/.test(d)).sort() : []

const pick = (actual: object, expected: Record<string, unknown>) =>
  Object.fromEntries(Object.keys(expected).map((k) => [k, (actual as Record<string, unknown>)[k]]))

describe('vcap-spec conformance vectors', () => {
  it('are present (git submodule update --init)', () => { expect(dirs.length).toBeGreaterThanOrEqual(30) })

  for (const dir of dirs) {
    it(dir, async () => {
      const path = join(VECTORS, dir)
      const { kind, debug: _d, schema_valid: _s, ...want } = JSON.parse(readFileSync(join(path, 'expected.json'), 'utf8'))
      if (kind === 'file') {
        const input = readdirSync(path).find((f) => f.startsWith('input.') && !f.endsWith('.vcap')) as string
        const sidecarPath = join(path, `${input}.vcap`)
        const verdict = await verify(new Uint8Array(readFileSync(join(path, input))), { sidecar: existsSync(sidecarPath) ? new Uint8Array(readFileSync(sidecarPath)) : undefined })
        expect(pick(verdict, want)).toEqual(want)
      } else if (kind === 'segments') {
        const input = JSON.parse(readFileSync(join(path, 'segments.json'), 'utf8'))
        const key = await importP256Spki(fromBase64(input.pub))
        const chain = await verifyChain(fromBase64(input.capture_id), input.segment_count, input.segments, key as CryptoKey)
        const outcome = chain.status === 'complete' ? 'authentic' : chain.status === 'clip' ? 'verified_clip' : 'tampered'
        expect(pick({ outcome, labels: [], not_evaluated: [], segments: { verified: chain.verified } }, want)).toEqual(want)
      } else if (kind === 'jcs') {
        const core = extractCore(JSON.parse(readFileSync(join(path, 'core.json'), 'utf8')) as { [k: string]: Json })
        const bytes = jcs(core)
        expect(toHex(bytes)).toBe(want.core_bytes_hex)
        expect(toHex(await sha256(bytes))).toBe(want.core_hash)
      }
    })
  }
})
