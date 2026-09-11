#!/usr/bin/env -S npx tsx
import { readFile } from 'node:fs/promises'
import { verify, pemToDer, type Verdict } from 'vcap-verify-core'
import { type Options, USAGE, UsageError, parse } from './options.js'
import { render } from './render.js'

/**
 * `vcap-verify`: a verdict from a shell.
 *
 * It contacts nothing. Every check this makes is one a file carries the
 * evidence for, which is the whole promise of the format — so *revocation not
 * checked* and *anchoring not verified* are the normal answers here, and they
 * are answers rather than failures. A caller who wants those closed reads the
 * log and the chain themselves and uses the library.
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
  const trustedLogs = options.logs.map(({ logId, spki }) => ({ logId, spki: base64(spki) }))

  const verdicts: { path: string, verdict: Verdict }[] = []
  for (const path of options.files) {
    const file = new Uint8Array(await readFile(path))
    const sidecar = await readSidecar(path, options)
    verdicts.push({
      path,
      verdict: await verify(file, {
        sidecar,
        recomputeSegments: options.recompute,
        trustedLogs,
        tsaRoots,
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

const base64 = (text: string): Uint8Array => Uint8Array.from(Buffer.from(text, 'base64'))

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
