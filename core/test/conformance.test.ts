import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { verify, verifyChain, jcs, toHex, extractCore, fromBase64, parseCertificate, pemToDer, evaluateWatermark, VIDEO_AGREEMENT_FLOOR } from '../src/index.js'
import { importP256Spki } from '../src/es256.js'
import { sha256 } from '../src/sha.js'
import type { Json } from '../src/jcs.js'
import { corpus } from './corpus.js'

/**
 * The conformance vectors of vcap-spec. Source of truth: the `spec` submodule;
 * fallback: the snapshot in core/vectors, kept equal by vectors-sync.mjs so a
 * checkout without the submodule still runs every vector. This core was written from
 * the spec, not from the reference verifier; the vectors are where the two
 * must agree byte for byte.
 */
const CORPUS = corpus()
const VECTORS = CORPUS.dir
const dirs = CORPUS.names

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
  ? (JSON.parse(readFileSync(join(TRUST, 'logs.json'), 'utf8')).logs as { log_id: string, spki: string, app_signing_digests?: string[] }[])
      .map((l) => ({ logId: l.log_id, spki: fromBase64(l.spki), ...(l.app_signing_digests ? { appSigningDigests: l.app_signing_digests } : {}) }))
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

describe(`vcap-spec conformance vectors (corpus ${CORPUS.version}, manifest ${CORPUS.manifestSha256.slice(0, 12)})`, () => {
  // A count, not a floor. The floor this replaces (`>= 84`) passed while the
  // corpus shrank under it, and `corpus()` above already refuses to hand back
  // an empty list — the two together are what stop this suite from going green
  // on nothing. Pinning to MANIFEST.json also fails when the submodule is left
  // behind a newer spec, which is the useful half: adopting new vectors becomes
  // a deliberate submodule bump rather than a silent omission.
  it(`run the ${CORPUS.declaredCount} vectors of corpus ${CORPUS.version}`, () => {
    expect(dirs.length).toBe(CORPUS.declaredCount)
  })

  // A count can match while the set does not: a vector renamed on one side
  // and not the other, or one directory swapped for another, passes an
  // equality of lengths. The names are the claim the manifest makes.
  it('run exactly the vectors the manifest names, each of the kind it declares', () => {
    expect(dirs).toEqual(Object.keys(CORPUS.kinds).sort())
    for (const dir of dirs) {
      const { kind } = JSON.parse(readFileSync(join(VECTORS, dir, 'expected.json'), 'utf8')) as { kind: string }
      expect(kind, dir).toBe(CORPUS.kinds[dir])
    }
  })

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

/**
 * `_watermark/agreement-floor.json`: the `video-rep-v1` floor as cases — an
 * agreement, whether the CRC passed, whether an id may be reported. The core
 * applies the floor to any detection it is handed (`evaluateWatermark`), so
 * this is where the corpus's cases reach it; the page's own decoder is held to
 * the same file in `web/test/layouts.test.ts`.
 */
describe(`vcap-spec agreement floor (corpus ${CORPUS.version})`, () => {
  const floor = JSON.parse(readFileSync(join(VECTORS, '_watermark', 'agreement-floor.json'), 'utf8')) as { floor: number, cases: Array<{ agreement: number, crc_passes: boolean, resolves: boolean }> }
  it('pins the same floor as the core', () => {
    expect(floor.floor).toBe(VIDEO_AGREEMENT_FLOOR)
    expect(floor.cases.length).toBeGreaterThan(0)
  })
  for (const c of floor.cases) {
    it(`agreement ${c.agreement}, CRC ${c.crc_passes ? 'passes' : 'fails'}: ${c.resolves ? 'resolves' : 'no id'}`, () => {
      const claim = { layout: 'video-rep-v1', captureId: '00'.repeat(16), markId: 4242, mime: 'video/mp4', coreHash: '' }
      // A CRC that fails is a detector reporting no id; one that passes reports the id it read.
      const w = evaluateWatermark({ layout: 'video-rep-v1', decoded: c.crc_passes ? '4242' : null, agreement: c.agreement, model_version: 'm' }, claim)
      expect(w.result).toBe(c.resolves ? 'matched' : 'not_recovered')
    })
  }
})
