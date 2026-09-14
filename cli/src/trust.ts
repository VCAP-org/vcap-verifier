import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { fingerprintOf, parseTrustDocument, parseTsaDocument, type TrustDocumentEntry, type TrustedLog, type TsaAuthorityEntry } from 'vcap-verify-core'

/**
 * The logs this tool follows unless told otherwise.
 *
 * The set is a file — `trust/logs.json` at the root of this repository — and
 * not a constant in the source, because pinning a log is a trust decision and
 * a trust decision the user cannot read is worth nothing. The file says who
 * runs each log and what its evidence does and does not prove; `--show-trust`
 * prints it, `--no-default-logs` drops it, `--trust` and `--log` add to it.
 *
 * Trusting nobody is a first-class way to run this tool: the only thing that
 * changes is that a `registry` attachment reads *log not trusted*, which §8
 * treats as absent evidence and never as a failure.
 */
export const DEFAULT_TRUST_FILE = fileURLToPath(new URL('../../trust/logs.json', import.meta.url))

export interface TrustSet {
  logs: TrustedLog[]
  /** What the documents said about each log, for printing. `--log` entries have no description beyond their id. */
  entries: TrustDocumentEntry[]
}

export const readTrustFile = async (path: string): Promise<TrustSet> =>
  await parseTrustDocument(JSON.parse(await readFile(path, 'utf8')) as unknown)

/** One line per log, in the words of the document that pinned it. */
export const describeTrust = (set: TrustSet): string => {
  if (set.logs.length === 0) return 'no transparency log is trusted: every `registry` attachment will read *log not trusted*\n'
  return set.logs.map((log, at) => {
    const entry = set.entries[at]
    const lines = [`  ${entry?.name ?? 'log'}${entry?.environment ? ` (${entry.environment})` : ''}`]
    lines.push(`    log_id    ${log.logId}`)
    if (entry?.operator) lines.push(`    operator  ${entry.operator}`)
    // The one thing a reader must not have to infer. A log run by whoever
    // ships the verifier corroborates nothing on its own, and a list that
    // prints operators without saying so invites reading it as a third party.
    if (entry?.independent === false) lines.push('    warning   run by the same party that publishes this tool — not independent corroboration')
    return lines.join('\n')
  }).join('\n') + '\n'
}

/**
 * The timestamping authorities this tool follows unless told otherwise.
 *
 * A separate file — `trust/tsa.json` — and a separate switch from the logs
 * above, because the two are separate decisions. Our log is us; a TSA is a
 * third party. Dropping ours and keeping a public clock is a coherent
 * position, and `--no-default-logs` must not quietly do it for the reader.
 *
 * Trusting no authority is a first-class way to run this tool: a `timestamp`
 * attachment reads *trusted time not evaluated*, §7 falls back to the device's
 * own clock for the validated instant, and nothing else in the verdict moves.
 */
export const DEFAULT_TSA_FILE = fileURLToPath(new URL('../../trust/tsa.json', import.meta.url))

export interface TsaSet {
  roots: Uint8Array[]
  /** What the documents said about each authority, for printing. `--tsa-root` PEMs have no description beyond their fingerprint. */
  entries: TsaAuthorityEntry[]
}

export const readTsaFile = async (path: string): Promise<TsaSet> =>
  await parseTsaDocument(JSON.parse(await readFile(path, 'utf8')) as unknown)

/** One line per authority, in the words of the document that pinned it. */
export const describeTsa = async (set: TsaSet): Promise<string> => {
  if (set.roots.length === 0) return 'no timestamping authority is trusted: every `timestamp` attachment will read *trusted time not evaluated*\n'
  const lines: string[] = []
  for (let at = 0; at < set.roots.length; at++) {
    const entry = set.entries[at]
    const fingerprint = entry?.fingerprint_sha256 ?? await fingerprintOf(set.roots[at] as Uint8Array)
    lines.push(`  ${entry?.name ?? 'a timestamping authority'}${entry?.environment ? ` (${entry.environment})` : ''}`)
    lines.push(`    sha256    ${fingerprint}`)
    if (entry?.subject) lines.push(`    subject   ${entry.subject}`)
    if (entry?.operator) lines.push(`    operator  ${entry.operator}`)
    // The two halves a reader must not have to infer. An authority somebody
    // else runs really is a third party — that is the whole reason a token is
    // worth more than our word — and saying so would be dishonest without the
    // other half: what the token proves stops at a hash and an instant.
    if (entry?.independent === true) lines.push('    third     run by somebody else, so a token from it is evidence we did not make — but it proves\n              only that this hash existed before that instant, never who made the file')
    if (entry?.independent === false) lines.push('    warning   run by the same party that publishes this tool — not independent corroboration')
    for (const caveat of entry?.caveats ?? []) lines.push(`    caveat    ${caveat}`)
  }
  return lines.join('\n') + '\n'
}
