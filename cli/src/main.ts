#!/usr/bin/env -S npx tsx
import { readFile } from 'node:fs/promises'
import { verify, rpcChainReader, pemToDer, parseTrustedLog, fingerprintOf, TrustDocumentError, type TrustedLog, type ChainReader, type Verdict, type WatermarkEvidence } from 'vcap-verify-core'
import { type Options, USAGE, UsageError, parse } from './options.js'
import { render } from './render.js'
import { DEFAULT_CHAINS_FILE, DEFAULT_TRUST_FILE, DEFAULT_TSA_FILE, describeChains, describeTrust, describeTsa, readChainsFile, readTrustFile, readTsaFile, type TrustSet, type TsaSet } from './trust.js'

/**
 * `vcap-verify`: a verdict from a shell.
 *
 * It contacts one thing: the public chain an `anchor` attachment names, through
 * the JSON-RPC endpoint `trust/chains.json` lists, to read the root the
 * contract stored — so that anchoring is checkable without us. Only the anchor
 * id is sent, never the file; `--offline` sends nothing, and a chain that
 * cannot be read gives *anchoring not verified*, an answer and not a failure.
 * Every other check is one the file carries the evidence for, so *revocation
 * not checked* stays the normal answer here.
 *
 * The only thing it reads from disk beyond the files named is its trust
 * (`trust.ts`): which transparency logs it checks a `registry` attachment
 * against, and which timestamping authorities it checks a `timestamp` against.
 * It ships trusting one of each — our development log, and FreeTSA — and
 * `--show-trust` prints both, `--no-default-logs` and `--no-default-tsa` drop
 * them one at a time. Two switches because they are two decisions: our log is
 * us, a TSA is somebody else. Those are decisions the reader is entitled to
 * see and to undo, not configuration details.
 */
// 66 is sysexits' EX_NOINPUT: a file that could not be read was never judged,
// and a script must be able to tell that apart from a file that was judged
// and failed.
const EXIT = { ok: 0, doesNotVerify: 1, notGreen: 2, usage: 64, unreadable: 66 }

/**
 * Whether a verdict answers "yes, these bytes are what was signed". A clip
 * does only when its frames were read back from the container (§5): a clip
 * whose segment hashes came out of the proof alone proves somebody signed
 * some hashes, not that these frames are the signed ones.
 */
const verifies = (v: Verdict): boolean =>
  v.outcome === 'authentic' || (v.outcome === 'verified_clip' && v.content?.recomputed === true)

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
  let tsa: TsaSet
  try {
    tsa = await tsaSet(options)
  } catch (error) {
    io.err(`vcap-verify: ${error instanceof Error ? error.message : String(error)}\n`)
    return EXIT.usage
  }
  // A PEM that holds no certificate is the caller's mistake and stops the run,
  // for the same reason a broken trust document does: a root the caller
  // believes they pinned, silently absent, produces *trusted time not
  // evaluated* and looks exactly like a file with no timestamp.
  for (const path of options.tsaRoots) {
    const pem = await readFile(path, 'utf8')
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g)
    if (!blocks) {
      io.err(`vcap-verify: ${path} holds no certificate\n`)
      return EXIT.usage
    }
    for (const block of blocks) {
      tsa.roots.push(pemToDer(block))
      tsa.entries.push({ fingerprint_sha256: await fingerprintOf(pemToDer(block)), certificate: '', name: `given on the command line (${path})`, independent: undefined })
    }
  }
  let chains
  try {
    chains = options.offline ? null : await readChainsFile(options.chainsFile ?? DEFAULT_CHAINS_FILE)
  } catch (error) {
    io.err(`vcap-verify: ${error instanceof Error ? error.message : String(error)}\n`)
    return EXIT.usage
  }
  if (options.showTrust) {
    io.out('transparency logs\n' + describeTrust(trust))
    io.out('\ntimestamping authorities\n' + await describeTsa(tsa))
    io.out('\nchains read for anchors\n' + describeChains(chains))
    return EXIT.ok
  }
  const readChain: ChainReader | undefined = chains === null ? undefined : rpcChainReader(chains, post)
  const tsaRoots = tsa.roots
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

  // One file that cannot be read (missing, a directory, a named sidecar that
  // is not there) is reported and the others are still judged: a directory
  // run must not lose every verdict to its first bad path.
  const results: Array<{ path: string, verdict: Verdict } | { path: string, error: string }> = []
  for (const path of options.files) {
    try {
      const file = new Uint8Array(await readFile(path))
      const sidecar = await readSidecar(path, options)
      results.push({
        path,
        verdict: await verify(file, {
          sidecar,
          recomputeSegments: options.recompute,
          trustedLogs: trust.logs,
          tsaRoots,
          readChain,
          ...(watermark ? { watermark: async () => watermark } : {}),
          now: options.now
        })
      })
    } catch (error) {
      results.push({ path, error: error instanceof Error ? error.message : String(error) })
    }
  }

  if (options.json) {
    // One object per line, so a shell can pipe a directory through `jq`
    // without the tool holding every verdict in memory first. A file that
    // could not be read is a line too, with `error` and no `outcome`.
    for (const r of results) {
      io.out(JSON.stringify('error' in r ? { file: r.path, error: r.error } : { file: r.path, ...r.verdict }) + '\n')
    }
  } else {
    io.out(results.map((r) => 'error' in r ? `${r.path}\n  error     ${r.error}` : render(r.path, r.verdict)).join('\n\n') + '\n')
  }

  // The worst answer across the files decides, so a script checking a
  // directory cannot pass because the last file happened to be fine — and a
  // file that was never judged outranks one that was judged and failed.
  const verdicts = results.flatMap((r) => 'error' in r ? [] : [r.verdict])
  if (verdicts.length < results.length) return EXIT.unreadable
  if (verdicts.some((verdict) => !verifies(verdict))) return EXIT.doesNotVerify
  if (options.requireGreen && verdicts.some((verdict) => verdict.level?.ceiling !== 'green')) return EXIT.notGreen
  return EXIT.ok
}

/**
 * The chain reader's transport: one JSON-RPC POST with Node's `fetch`. Bounded
 * in time, because an endpoint that never answers must end as *anchoring not
 * verified*, not as a hung shell.
 */
const post = async (url: string, body: string): Promise<string> => {
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body, signal: AbortSignal.timeout(10_000) })
  if (!response.ok) throw new Error(`${new URL(url).host} answered HTTP ${response.status}`)
  return await response.text()
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
 * The timestamping authorities for this run: what the tool ships with, unless
 * refused, plus every PEM the caller named. A separate function from
 * `trustSet` and a separate switch, because they are separate decisions —
 * `--no-default-logs` must never quietly also drop a third party's clock.
 */
const tsaSet = async (options: Options): Promise<TsaSet> => {
  const set: TsaSet = { roots: [], entries: [] }
  if (!options.noDefaultTsa) {
    const shipped = await readTsaFile(DEFAULT_TSA_FILE)
    set.roots.push(...shipped.roots)
    set.entries.push(...shipped.entries)
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
