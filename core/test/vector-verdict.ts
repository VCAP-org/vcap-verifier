import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { verify, fromBase64, parseCertificate, pemToDer } from '../src/index.js'
import type { Verdict } from '../src/index.js'
import { corpus } from './corpus.js'

/**
 * A file or container vector verified the one way the conformance runner and
 * the surfaces' tests all do: the corpus's own trust set (`_trust/`), the
 * inputs `expected.json` declares a verifier fetched (`verifier_clock`,
 * `key_status`, `chain_read`), the §3.1 sidecar `input.<ext>.vcap`, and a C2PA
 * manifest store kept beside the file (`*.c2pa`), which the caller hands over
 * exactly as a reader would.
 */
const CORPUS = corpus()
// `_trust/` holds the anchors the corpus assumes a verifier already has: the
// root its attestation chains end in — a test root standing in for a pinned
// Google root — the TSA roots, and the public key of the log it pretends to
// trust. They ship as loadable files rather than compiled into a verifier so a
// second implementation can reproduce the verdicts; loading them here is what
// makes this core that second implementation. Absent, the §7 vectors fail
// loudly with `proven: none`, the honest answer for a verifier holding no anchor.
const TRUST = join(CORPUS.dir, '_trust')
const pems = (file: string): string[] =>
  existsSync(join(TRUST, file)) ? readFileSync(join(TRUST, file), 'utf8').match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [] : []

const tsaRoots = pems('tsa-roots.pem').map(pemToDer)
const googleRoots = existsSync(join(TRUST, 'attestation-roots.pem')) ? pems('attestation-roots.pem').map((b) => parseCertificate(pemToDer(b))) : undefined
const trustedLogs = existsSync(join(TRUST, 'logs.json'))
  ? (JSON.parse(readFileSync(join(TRUST, 'logs.json'), 'utf8')).logs as { log_id: string, spki: string, app_signing_digests?: string[] }[])
      .map((l) => ({ logId: l.log_id, spki: fromBase64(l.spki), ...(l.app_signing_digests ? { appSigningDigests: l.app_signing_digests } : {}) }))
  : undefined

/** The media file of a vector: `input.<ext>`, never its sidecar or its manifest store. */
export const vectorInput = (path: string): string =>
  readdirSync(path).find((f) => f.startsWith('input.') && !f.endsWith('.vcap') && !f.endsWith('.c2pa')) as string

/** A C2PA manifest store the vector keeps beside its file, if any. */
export const vectorStore = (path: string): string | undefined => readdirSync(path).find((f) => f.endsWith('.c2pa'))

export const vectorVerdict = async (name: string): Promise<Verdict> => {
  const path = join(CORPUS.dir, name)
  const { kind, verifier_clock: clock, key_status: keyStatus, chain_read: chainRead } = JSON.parse(readFileSync(join(path, 'expected.json'), 'utf8'))
  if (kind !== 'file' && kind !== 'container') throw new Error(`${name} is a ${kind} vector, not a file`)
  const input = vectorInput(path)
  const sidecarPath = join(path, `${input}.vcap`)
  const store = vectorStore(path)
  return await verify(new Uint8Array(readFileSync(join(path, input))), {
    sidecar: existsSync(sidecarPath) ? new Uint8Array(readFileSync(sidecarPath)) : undefined,
    c2paStore: store ? new Uint8Array(readFileSync(join(path, store))) : undefined,
    recomputeSegments: kind === 'container',
    googleRoots,
    trustedLogs,
    tsaRoots,
    keyStatus: keyStatus ? async () => keyStatus : undefined,
    readChain: chainRead
      ? async () => ({ root: fromBase64(chainRead.root), treeSize: chainRead.tree_size, blockTime: chainRead.block_time ? new Date(chainRead.block_time) : undefined })
      : undefined,
    now: typeof clock === 'number' ? new Date(clock) : undefined
  })
}
