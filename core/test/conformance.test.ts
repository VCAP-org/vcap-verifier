import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { verify, verifyChain, jcs, toHex, extractCore, fromBase64, parseCertificate, pemToDer } from '../src/index.js'
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

// `_trust/` holds the anchors the corpus assumes a verifier already has: the
// root its attestation chains end in — a test root standing in for a pinned
// Google root — and the public key of the log it pretends to trust. They ship
// as loadable files rather than compiled into a verifier precisely so a second
// implementation can reproduce the verdicts; loading them here is what makes
// this core that second implementation. Absent, the §7 vectors fail loudly with
// `proven: none`, which is the honest answer for a verifier holding no anchor.
const TRUST = join(VECTORS, '_trust')
const pemCerts = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((b) => parseCertificate(pemToDer(b)))
// The TSA roots the corpus ships. Without them a timestamped vector reads as
// *trusted time not evaluated* — evidence this verifier cannot read — which is
// a different verdict from the one the vector states, so leaving them out
// would look like a bug in the timestamp validator.
const tsaRoots = existsSync(join(TRUST, 'tsa-roots.pem'))
  ? (readFileSync(join(TRUST, 'tsa-roots.pem'), 'utf8').match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map(pemToDer)
  : []

const googleRoots = existsSync(join(TRUST, 'attestation-roots.pem'))
  ? pemCerts(readFileSync(join(TRUST, 'attestation-roots.pem'), 'utf8'))
  : undefined
const trustedLogs = existsSync(join(TRUST, 'logs.json'))
  ? (JSON.parse(readFileSync(join(TRUST, 'logs.json'), 'utf8')).logs as { log_id: string, spki: string }[])
      .map((l) => ({ logId: l.log_id, spki: fromBase64(l.spki) }))
  : undefined

// Compare only what the vector asks about, at every depth: a verdict may carry
// more than the corpus pins (this core names the contradicted segments, the
// reference verifier does not) and extra diagnostics must not read as a
// conformance failure.
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const pick = (actual: unknown, expected: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(expected).map(([k, want]) => {
    const got = isPlain(actual) ? actual[k] : undefined
    return [k, isPlain(want) && isPlain(got) ? pick(got, want) : got]
  }))

describe('vcap-spec conformance vectors', () => {
  // A floor, not a count: it catches a missing submodule and an accidental
  // downgrade. It cannot catch a submodule left behind a newer spec — raising
  // it is the deliberate act of adopting new vectors, and that is the point.
  it('are present (git submodule update --init)', () => { expect(dirs.length).toBeGreaterThanOrEqual(84) })

  for (const dir of dirs) {
    it(dir, async () => {
      const path = join(VECTORS, dir)
      // `verifier_clock` is an input, not an expectation: a §7 verdict depends on
      // when the verifier runs, so the corpus fixes that instant instead of
      // letting the wall clock decide. Vectors 43 and 45 say the same chain twice
      // and differ only by it. Comparing it as an output is how it read as a
      // failure while the logic underneath was right.
      const { kind, debug: _d, schema_valid: _s, verifier_clock: clock, key_status: keyStatus, chain_read: chainRead, ...want } = JSON.parse(readFileSync(join(path, 'expected.json'), 'utf8'))
      const now = typeof clock === 'number' ? new Date(clock) : undefined
      if (kind === 'file' || kind === 'container') {
        // A container vector is a file vector with one more question asked of
        // the same bytes: recompute every segment's content_hash from the GOPs
        // (§5) instead of trusting the hashes the proof carries about itself.
        const input = readdirSync(path).find((f) => f.startsWith('input.') && !f.endsWith('.vcap')) as string
        const sidecarPath = join(path, `${input}.vcap`)
        const verdict = await verify(new Uint8Array(readFileSync(join(path, input))), {
          sidecar: existsSync(sidecarPath) ? new Uint8Array(readFileSync(sidecarPath)) : undefined,
          recomputeSegments: kind === 'container',
          googleRoots,
          trustedLogs,
          tsaRoots,
          // Also an input: §6.2 makes revocation an online question, so the
          // corpus declares what the verifier is assumed to have fetched. A
          // vector without it is one where the log could not be asked, which
          // is *revocation not checked* and never green.
          keyStatus: keyStatus ? async () => keyStatus : undefined,
          // What the corpus says a caller read from the anchoring contract.
          readChain: chainRead
            ? async () => ({ root: fromBase64(chainRead.root), treeSize: chainRead.tree_size, blockTime: chainRead.block_time ? new Date(chainRead.block_time) : undefined })
            : undefined,
          now
        })
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
      } else {
        // A kind this core does not know is a vector that never ran: the gate
        // must say so, because silently skipping one is indistinguishable from
        // passing it. This is how the container vectors sat unchecked.
        throw new Error(`unknown vector kind: ${kind}`)
      }
    })
  }
})
