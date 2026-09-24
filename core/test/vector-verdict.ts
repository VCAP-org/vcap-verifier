import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { verify, fromBase64, parseCertificate, pemToDer } from '../src/index.js'
import type { Verdict } from '../src/index.js'
import { corpus } from './corpus.js'

/**
 * A file or container vector verified exactly as the conformance runner does:
 * the corpus's own trust set (`_trust/`), and the inputs `expected.json`
 * declares a verifier fetched (`verifier_clock`, `key_status`, `chain_read`).
 * Shared so the surfaces' tests render the verdict the corpus pins, not one
 * assembled by hand.
 */
const CORPUS = corpus()
const TRUST = join(CORPUS.dir, '_trust')
const pems = (file: string): string[] =>
  existsSync(join(TRUST, file)) ? readFileSync(join(TRUST, file), 'utf8').match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [] : []

const tsaRoots = pems('tsa-roots.pem').map(pemToDer)
const googleRoots = existsSync(join(TRUST, 'attestation-roots.pem')) ? pems('attestation-roots.pem').map((b) => parseCertificate(pemToDer(b))) : undefined
const trustedLogs = existsSync(join(TRUST, 'logs.json'))
  ? (JSON.parse(readFileSync(join(TRUST, 'logs.json'), 'utf8')).logs as { log_id: string, spki: string, app_signing_digests?: string[] }[])
      .map((l) => ({ logId: l.log_id, spki: fromBase64(l.spki), ...(l.app_signing_digests ? { appSigningDigests: l.app_signing_digests } : {}) }))
  : undefined

export const vectorVerdict = async (name: string): Promise<Verdict> => {
  const path = join(CORPUS.dir, name)
  const { kind, verifier_clock: clock, key_status: keyStatus, chain_read: chainRead } = JSON.parse(readFileSync(join(path, 'expected.json'), 'utf8'))
  if (kind !== 'file' && kind !== 'container') throw new Error(`${name} is a ${kind} vector, not a file`)
  const input = readdirSync(path).find((f) => f.startsWith('input.') && !f.endsWith('.vcap')) as string
  const sidecarPath = join(path, `${input}.vcap`)
  return await verify(new Uint8Array(readFileSync(join(path, input))), {
    sidecar: existsSync(sidecarPath) ? new Uint8Array(readFileSync(sidecarPath)) : undefined,
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
