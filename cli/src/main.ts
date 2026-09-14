#!/usr/bin/env -S npx tsx
import { readFile } from 'node:fs/promises'
import { verify, pemToDer, parseTrustedLog, TrustDocumentError, type TrustedLog, type Verdict, type WatermarkEvidence } from 'vcap-verify-core'
import { type Options, USAGE, UsageError, parse } from './options.js'
import { render } from './render.js'
import { DEFAULT_TRUST_FILE, describeTrust, readTrustFile, type TrustSet } from './trust.js'

/**
 * `vcap-verify`: a verdict from a shell.
 *
 * It contacts nothing. Every check this makes is one a file carries the
 * evidence for, which is the whole promise of the format — so *revocation not
 * checked* and *anchoring not verified* are the normal answers here, and they
 * are answers rather than failures. A caller who wants those closed reads the
 * log and the chain themselves and uses the library.
 *
 * The one thing it does read from disk beyond the files named is its trust set
 * (`trust.ts`): which transparency logs it will check a `registry` attachment
 * against. It ships trusting one, ours, and `--show-trust` prints it,
 * `--no-default-logs` drops it. That is a decision the reader is entitled to
 * see and to undo, not a configuration detail.
 */
const EXIT = { ok: 0, doesNotVerify: 1, notGreen: 2, usage: 64 }

const VERIFIES = new Set(['authentic', 'verified_clip'])

export interface Streams {
  out: (text: string) => void
  err: (text: string) => void
}

const streams: Streams = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text)
}

/**
 * The whole tool, with its output injected.
 *
 * Injected so the tests can run it in-process: spawning `tsx` once per vector
 * costs half a second of startup each, which turns a conformance run into a
 * minute of waiting and, worse, into something nobody runs locally.
 */
export const run = async (argv: string[], io: Streams = streams): Promise<number> => {
  let options
  try {
    options = parse(argv)
  } catch (error) {
    if (!(error instanceof UsageError)) throw error
    io.err(`vcap-verify: ${error.message}\n\n${USAGE}`)
    return EXIT.usage
  }
  if (options.help) {
    io.out(USAGE)
    return EXIT.ok
  }

  let trust: TrustSet
  try {
    trust = await trustSet(options)
  } catch (error) {
    io.err(`vcap-verify: ${error instanceof Error ? error.message : String(error)}\n`)
    return EXIT.usage
  }
  if (options.showTrust) {
    io.out(describeTrust(trust))
    return EXIT.ok
  }

  const tsaRoots: Uint8Array[] = []
  for (const path of options.tsaRoots) {
    const pem = await readFile(path, 'utf8')
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g)
    if (!blocks) {
      io.err(`vcap-verify: ${path} holds no certificate\n`)
      return EXIT.usage
    }
    for (const block of blocks) tsaRoots.push(pemToDer(block))
  }
  // §8's watermark detection. This tool runs no detector and contacts nothing,
  // so the evidence is a file the caller produced — the `watermark` block of a
  // `/v1/verify` response, or any other detector's output in that shape. What
  // it says is *what came out of the pixels*; the comparison against the ids
  // the device signed is the core's, and a payload it cannot read is
  // *watermark not evaluated* rather than an accusation.
  let watermark: WatermarkEvidence | undefined
  if (options.watermark !== undefined) {
    try {
      watermark = JSON.parse(await readFile(options.watermark, 'utf8')) as WatermarkEvidence
    } catch {
      io.err(`vcap-verify: ${options.watermark} is not readable JSON\n`)
      return EXIT.usage
    }
  }

  const verdicts: { path: string, verdict: Verdict }[] = []
  for (const path of options.files) {
    const file = new Uint8Array(await readFile(path))
    const sidecar = await readSidecar(path, options)
    verdicts.push({
      path,
      verdict: await verify(file, {
        sidecar,
        recomputeSegments: options.recompute,
        trustedLogs: trust.logs,
        tsaRoots,
        ...(watermark ? { watermark: async () => watermark } : {}),
        now: options.now
      })
    })
  }

  if (options.json) {
    // One object per line, so a shell can pipe a directory through `jq`
    // without the tool holding every verdict in memory first.
    for (const { path, verdict } of verdicts) {
      io.out(JSON.stringify({ file: path, ...verdict }) + '\n')
    }
  } else {
    io.out(verdicts.map(({ path, verdict }) => render(path, verdict)).join('\n\n') + '\n')
  }

  // The worst answer across the files decides, so a script checking a
  // directory cannot pass because the last file happened to be fine.
  if (verdicts.some(({ verdict }) => !VERIFIES.has(verdict.outcome))) return EXIT.doesNotVerify
  if (options.requireGreen && verdicts.some(({ verdict }) => verdict.level?.ceiling !== 'green')) return EXIT.notGreen
  return EXIT.ok
}

/**
 * The trust set for this run: what the tool ships with, unless refused, plus
 * every document and every key the caller named, in the order they gave them.
 * A document that does not parse stops the run — a verifier that silently
 * ignored half a trust set would produce *log not trusted* for a log the
 * caller believes they pinned, and that is the one failure mode this whole
 * feature exists to avoid.
 */
const trustSet = async (options: Options): Promise<TrustSet> => {
  const set: TrustSet = { logs: [], entries: [] }
  const add = (from: TrustSet): void => { set.logs.push(...from.logs); set.entries.push(...from.entries) }
  if (!options.noDefaultLogs) add(await readTrustFile(DEFAULT_TRUST_FILE))
  for (const path of options.trustFiles) add(await readTrustFile(path))
  for (const text of options.logs) {
    let log: TrustedLog
    try { log = await parseTrustedLog(text) } catch (error) {
      throw error instanceof TrustDocumentError ? new Error(`--log: ${error.message}`) : error
    }
    set.logs.push(log)
    set.entries.push({ log_id: log.logId, spki: text.slice(text.indexOf(':') + 1), name: 'given on the command line' })
  }
  return set
}

/**
 * §3.1 discovery: the sidecar of `F` is `<full filename of F>.vcap` in the
 * same directory, or the one the caller names — and nothing else. No other
 * name, no parent folder, no URL from inside the proof: a proof that had to
 * be looked for is a proof whose absence could not be reported with
 * confidence. A missing file is the normal case, not an error.
 */
const readSidecar = async (path: string, options: Options): Promise<Uint8Array | undefined> => {
  if (options.sidecar === false) return undefined
  const sidecarPath = options.sidecar ?? `${path}.vcap`
  try {
    return new Uint8Array(await readFile(sidecarPath))
  } catch (error) {
    // Only a file that is not there may be skipped, and only when nobody
    // asked for it by name: a named sidecar that cannot be read is an error
    // the caller wants to hear about.
    if (options.sidecar === undefined && (error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
}
