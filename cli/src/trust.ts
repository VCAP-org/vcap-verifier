import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { parseTrustDocument, type TrustDocumentEntry, type TrustedLog } from 'vcap-verify-core'

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
