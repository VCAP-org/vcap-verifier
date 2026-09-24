/**
 * The command line, parsed by hand.
 *
 * No argument-parsing dependency: this tool exists so that somebody can check
 * a file without trusting us, and every package in its tree is something they
 * would have to trust. Nineteen flags of hand-rolled parsing is a smaller ask
 * than a transitive graph.
 */
export interface Options {
  files: string[]
  json: boolean
  /**
   * The §3.1 sidecar: a path names one, `false` refuses to look, undefined
   * means `<file>.vcap` next to the file if it exists.
   */
  sidecar?: string | false
  /** §5 recomputation from the container. On by default; `--no-recompute` for a caller that has only a sidecar. */
  recompute: boolean
  /**
   * §8's watermark detection, as a file: this tool contacts nothing and runs
   * no model, so the only honest source of a detection is the caller. Absent,
   * a declared watermark reads *watermark not evaluated*.
   */
  watermark?: string
  /** Transparency-log public keys, `--log <log_id>:<base64 spki>`. */
  logs: string[]
  /** Trust documents to add, `--trust <path.json>`; the same shape as `trust/logs.json`. */
  trustFiles: string[]
  /** Drop the logs this tool ships with, leaving only what `--trust` and `--log` added. */
  noDefaultLogs: boolean
  /** Print the effective trust set and stop. */
  showTrust: boolean
  /** TSA roots to pin, PEM files, on top of the ones this tool ships with. */
  tsaRoots: string[]
  /** Drop the timestamping authorities this tool ships with, leaving only what `--tsa-root` added. */
  noDefaultTsa: boolean
  /** Read no chain: an anchor reads *anchoring not verified*. The only switch that keeps the tool off the network. */
  offline: boolean
  /** The chains document to read anchors with, instead of `trust/chains.json`. */
  chainsFile?: string
  /** Exit non-zero unless the verdict's ceiling is green. */
  requireGreen: boolean
  /** The verifier's clock, for reproducing a verdict at a stated instant. */
  now?: Date
  help: boolean
}

export class UsageError extends Error {}

export const USAGE = `vcap-verify — check a vcap proof

  vcap-verify [options] <file>...

Options
  --json                    machine-readable verdict on stdout, one object per file
  --sidecar <path>          read the proof from this .vcap sidecar (single file only);
                            by default <file>.vcap next to the file is read when present (§3.1)
  --no-sidecar              ignore any sidecar, verify the file alone
  --no-recompute            do not recompute segment hashes from the container (§5)
  --watermark <path.json>   a detection of the declared watermark, as JSON (single file only):
                            layout, decoded, agreement, corrected_bits, frames_sampled,
                            frames_with_id, sampling {frames, strategy}, model_version (§8).
                            For a clip, frames_with_id is how many of the sampled frames
                            decoded to that id on their own — the figure that separates a
                            marked recording from one marked frame spliced into other
                            footage, which agreement cannot. This tool runs no
                            detector: "decoded" is what somebody else's read out of the pixels
  --log <id>:<spki>         a transparency log to trust: log_id and its base64 DER SPKI
  --trust <path.json>       a trust document to add, in the shape of trust/logs.json; repeatable
  --no-default-logs         do not trust the logs this tool ships with
  --show-trust              print the logs and the timestamping authorities this run
                            would trust, and stop
  --tsa-root <path.pem>     a timestamping authority root to pin, on top of the shipped
                            ones; repeatable
  --no-default-tsa          do not trust the timestamping authorities this tool ships with
  --chains <path.json>      the chains document to read anchors with, in the shape of
                            trust/chains.json, instead of the shipped one
  --offline                 read no chain: an anchor reads *anchoring not verified*
  --require-green           exit 2 unless the ceiling is green
  --at <iso8601>            the instant to verify at, instead of now
  -h, --help                this

Trust
  Two sets, two documents, two switches, because they are two decisions.

  Transparency logs (trust/logs.json). This tool ships trusting one, the vcap
  development log, and it is run by the same people who publish this tool — it
  is not independent corroboration of anything. Read it, edit it, or drop it
  with --no-default-logs and bring your own --trust / --log. A proof naming a
  log you do not follow reads *log not trusted*: absent evidence, not a failure.

  Timestamping authorities (trust/tsa.json). This tool ships trusting FreeTSA,
  which is a genuine third party — a token from it is evidence we did not make.
  What it proves is narrow: this hash existed before that instant, and that
  authority said so. Never who made the file. FreeTSA is a free community
  service with no SLA and no contractual liability. Drop it with
  --no-default-tsa and bring your own --tsa-root. Without any authority a
  timestamp reads *trusted time not evaluated* and §7 validates against the
  device's own clock, which caps the ceiling at amber.

  Chains (trust/chains.json). An anchor is checked by asking the chain's
  contract, through the public JSON-RPC endpoint listed there, which root it
  stored. That endpoint is a trust point: a lying RPC could return the root a
  forged proof carries. It learns the anchor id and your address, never the
  file. List your own node with --chains, or read nothing with --offline;
  a chain that cannot be read gives *anchoring not verified*, never a failure.

  Verifying against sets that contain none of ours is a supported way to run
  this tool, not a degraded one.

Exit codes
  0   authentic, or a verified clip
  1   the file does not verify — tampered, no proof, or an unreadable one
  2   the verdict is not green and --require-green was given
  64  usage error

The exit code answers "should I trust this file", not "did the tool run": a
tampered file is a successful run of the tool and a failure of the file.
`

export const parse = (argv: string[]): Options => {
  const o: Options = { files: [], json: false, recompute: true, logs: [], trustFiles: [], noDefaultLogs: false, showTrust: false, tsaRoots: [], noDefaultTsa: false, offline: false, requireGreen: false, help: false }
  const next = (flag: string, at: number): string => {
    const value = argv[at + 1]
    if (value === undefined || value.startsWith('--')) throw new UsageError(`${flag} needs a value`)
    return value
  }

  for (let at = 0; at < argv.length; at++) {
    const arg = argv[at] as string
    switch (arg) {
      case '--json': o.json = true; break
      case '--no-recompute': o.recompute = false; break
      case '--require-green': o.requireGreen = true; break
      case '-h': case '--help': o.help = true; break
      case '--sidecar': o.sidecar = next(arg, at); at++; break
      case '--watermark': o.watermark = next(arg, at); at++; break
      case '--no-sidecar': o.sidecar = false; break
      case '--no-default-logs': o.noDefaultLogs = true; break
      case '--no-default-tsa': o.noDefaultTsa = true; break
      case '--show-trust': o.showTrust = true; break
      case '--offline': o.offline = true; break
      case '--chains': o.chainsFile = next(arg, at); at++; break
      case '--trust': o.trustFiles.push(next(arg, at)); at++; break
      case '--tsa-root': o.tsaRoots.push(next(arg, at)); at++; break
      case '--at': {
        const value = next(arg, at); at++
        const parsed = new Date(value)
        if (Number.isNaN(parsed.getTime())) throw new UsageError(`--at is not a date: ${value}`)
        o.now = parsed
        break
      }
      case '--log': {
        const value = next(arg, at); at++
        // Kept as written and decoded in `trust.ts`, which is also where the
        // id is checked against the key it names.
        if (value.indexOf(':') <= 0) throw new UsageError(`--log wants <log_id>:<base64 spki>, got ${value}`)
        o.logs.push(value)
        break
      }
      default:
        if (arg.startsWith('-')) throw new UsageError(`unknown option ${arg}`)
        o.files.push(arg)
    }
  }

  if (!o.help && !o.showTrust) {
    if (o.files.length === 0) throw new UsageError('no file given')
    if (o.sidecar && o.files.length > 1) throw new UsageError('--sidecar takes a single file')
    // One detection is about one file's pixels. Spreading it over a directory
    // would report a mark that was never looked for in the other files.
    if (o.watermark && o.files.length > 1) throw new UsageError('--watermark takes a single file')
  }
  return o
}
