import { parseTrustDocument, parseTrustedLog, type TrustDocumentEntry, type TrustedLog } from 'vcap-verify-core'
import { escape } from './render.js'
import defaultDocument from '../../trust/logs.json'

/**
 * Which transparency logs this page believes, and the reader's hand on that.
 *
 * Pinning a log is the one trust decision this page makes on the reader's
 * behalf, and it is made in public: the set is the repository's
 * `trust/logs.json`, bundled here and published unchanged as `logs.json` next
 * to the page, so the identity of every pinned log can be fetched and its
 * `log_id` recomputed from its own key by anyone, with no account.
 *
 * Every entry can be switched off, and a reader can add their own — by file or
 * by a pasted `<log_id>:<base64 spki>` line. Running with none of ours, or
 * with none at all, is a supported way to use this page and not a broken one:
 * a proof that names a log the set does not hold reads *log not trusted*,
 * which §8 counts as absent evidence, and the rest of the verdict is
 * unchanged. That has to stay true, because "you do not have to trust us" is
 * the only thing this verifier is for.
 *
 * The set is bundled rather than fetched: a page that asked a server which
 * logs to trust would have put a server of ours back into the verification
 * path, which is the invariant this whole repository exists to keep.
 */
interface Entry {
  log: TrustedLog
  described: TrustDocumentEntry
  /** Where it came from, for the reader: the shipped document, a file, a pasted line. */
  source: string
  /** Shipped with the page rather than added by the reader. */
  shipped: boolean
  on: boolean
}

const entries: Entry[] = []
let onChange: () => void = () => {}

const panel = (): HTMLDivElement => document.getElementById('trust') as HTMLDivElement

/** What the page will actually check a `registry` attachment against. */
export const trustedLogs = (): TrustedLog[] => entries.filter((e) => e.on).map((e) => e.log)

const add = (parsed: { logs: TrustedLog[], entries: TrustDocumentEntry[] }, source: string, shipped: boolean): void => {
  parsed.logs.forEach((log, at) => {
    const described = parsed.entries[at] as TrustDocumentEntry
    // The same key twice is one decision, not two: a reader who loaded a file
    // that repeats a pinned log should see one row they can switch off.
    if (entries.some((e) => e.log.logId === log.logId)) return
    entries.push({ log, described, source, shipped, on: true })
  })
}

const say = (text: string): void => {
  const state = document.getElementById('trust-state') as HTMLParagraphElement
  state.textContent = text
}

const row = (entry: Entry, at: number): string => {
  const d = entry.described
  const name = escape(d.name ?? 'a transparency log')
  const environment = d.environment ? ` <span class="muted">(${escape(d.environment)})</span>` : ''
  // The sentence a list of operators cannot be read without. A log run by
  // whoever publishes the verifier corroborates nothing on its own, and a row
  // that printed the operator's name and stopped there would let a reader take
  // it for a second opinion.
  const ours = d.independent === false
    ? '<br><strong>Run by the same people who publish this page.</strong> It proves the key was in our log before the capture. It is not independent corroboration, and it does not prove we are honest.'
    : ''
  return `<li>
    <label><input type="checkbox" data-trust="${at}"${entry.on ? ' checked' : ''}> ${name}${environment}</label>
    <div class="muted"><code>${escape(entry.log.logId)}</code></div>
    <div class="muted">${d.operator ? `Operated by ${escape(d.operator)}.` : 'No operator is named for this log.'}${ours} <span class="absent">${escape(entry.source)}</span></div>
  </li>`
}

const draw = (): void => {
  const list = document.getElementById('trust-logs') as HTMLUListElement
  list.innerHTML = entries.length === 0
    ? '<li class="absent">No log is trusted. Every proof that names one will read <em>log not trusted</em> — absent evidence, not a failure.</li>'
    : entries.map(row).join('')
  for (const box of list.querySelectorAll('input[type=checkbox]')) {
    box.addEventListener('change', () => {
      const at = Number((box as HTMLInputElement).dataset.trust)
      const entry = entries[at]
      if (entry) entry.on = (box as HTMLInputElement).checked
      onChange()
    })
  }
}

/**
 * Reads the shipped set, draws the panel, and wires the two ways a reader adds
 * their own. Anything that does not parse changes nothing and is reported: a
 * trust set that half-loaded would be worse than one that refused.
 */
export const mountTrust = async (changed: () => void): Promise<void> => {
  onChange = changed
  try {
    add(await parseTrustDocument(defaultDocument), 'shipped with this page', true)
  } catch (error) {
    say(`the shipped trust set did not load: ${error instanceof Error ? error.message : String(error)}`)
  }
  draw()

  const file = document.getElementById('trust-file') as HTMLInputElement
  file.addEventListener('change', () => {
    const chosen = file.files?.[0]
    if (!chosen) return
    void chosen.text()
      .then(async (text) => {
        const parsed = await parseTrustDocument(JSON.parse(text) as unknown)
        add(parsed, `from ${chosen.name}`, false)
        draw(); onChange()
        say(`${parsed.logs.length} log${parsed.logs.length === 1 ? '' : 's'} added from ${chosen.name}`)
      })
      .catch((error: Error) => { say(`${chosen.name} is not a trust document: ${error.message}`) })
  })

  const line = document.getElementById('trust-line') as HTMLInputElement
  const addLine = document.getElementById('trust-add') as HTMLButtonElement
  addLine.addEventListener('click', () => {
    const text = line.value.trim()
    if (text === '') return
    void parseTrustedLog(text)
      .then((log) => {
        add({ logs: [log], entries: [{ log_id: log.logId, spki: text.slice(text.indexOf(':') + 1), name: 'a log you pinned' }] }, 'pasted here', false)
        line.value = ''
        draw(); onChange()
        say(`${log.logId} is now trusted in this page`)
      })
      .catch((error: Error) => { say(error.message) })
  })
}
