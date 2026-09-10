/**
 * The command line, parsed by hand.
 *
 * No argument-parsing dependency: this tool exists so that somebody can check
 * a file without trusting us, and every package in its tree is something they
 * would have to trust. Fourteen flags of hand-rolled parsing is a smaller ask
 * than a transitive graph.
 */
export interface Options {
  files: string[]
  json: boolean
  sidecar?: string
  /** §5 recomputation from the container. On by default; `--no-recompute` for a caller that has only a sidecar. */
  recompute: boolean
  /** Transparency-log public keys, `--log <log_id>:<base64 spki>`. */
  logs: { logId: string, spki: string }[]
  /** TSA roots to pin, PEM files. Without one a timestamp is *trusted time not evaluated*. */
  tsaRoots: string[]
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
  --sidecar <path>          read the proof from a .vcap sidecar (single file only)
  --no-recompute            do not recompute segment hashes from the container (§5)
  --log <id>:<spki>         a transparency log to trust: log_id and its base64 DER SPKI
  --tsa-root <path.pem>     a TSA root to pin; repeatable
  --require-green           exit 1 unless the ceiling is green
  --at <iso8601>            the instant to verify at, instead of now
  -h, --help                this

Exit codes
  0   authentic, or a verified clip
  1   the file does not verify — tampered, no proof, or an unreadable one
  2   the verdict is not green and --require-green was given
  64  usage error

The exit code answers "should I trust this file", not "did the tool run": a
tampered file is a successful run of the tool and a failure of the file.
`

export const parse = (argv: string[]): Options => {
  const o: Options = { files: [], json: false, recompute: true, logs: [], tsaRoots: [], requireGreen: false, help: false }
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
        // `log_id:spki`, and the id is base64url so it never contains a colon
        // — the split is on the first one, and the SPKI keeps its padding.
        const colon = value.indexOf(':')
        if (colon <= 0) throw new UsageError(`--log wants <log_id>:<base64 spki>, got ${value}`)
        o.logs.push({ logId: value.slice(0, colon), spki: value.slice(colon + 1) })
        break
      }
      default:
        if (arg.startsWith('-')) throw new UsageError(`unknown option ${arg}`)
        o.files.push(arg)
    }
  }

  if (!o.help) {
    if (o.files.length === 0) throw new UsageError('no file given')
    if (o.sidecar && o.files.length > 1) throw new UsageError('--sidecar takes a single file')
  }
  return o
}
