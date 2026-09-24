import { parseChainsDocument, parseTrustDocument, parseTrustedLog, parseTsaDocument, parseTsaRoot, rpcChainReader, type ChainEntry, type ChainReader, type TrustDocumentEntry, type TrustedLog, type TsaAuthorityEntry } from 'vcap-verify-core'
import { escape } from './render.js'
import defaultDocument from '../../trust/logs.json'
import defaultTsaDocument from '../../trust/tsa.json'
import defaultChainsDocument from '../../trust/chains.json'

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

/**
 * Which timestamping authorities this page believes, on the same terms.
 *
 * A second panel and a second document rather than a second array in the
 * first, because the two decisions are not the same decision. The log this
 * page ships is ours; FreeTSA is not. A reader who switches our log off and
 * leaves a third party's clock on has taken a coherent position, and the page
 * has to make that the obvious move rather than a clever one.
 *
 * What a pinned root buys, said here exactly as the document says it: a token
 * that chains to it proves this hash existed before that instant and that
 * authority said so. Not who made the file. Switching them all off is
 * supported: the attachment reads *trusted time not evaluated*, §7 validates
 * against the device's own clock, and the rest of the verdict is unchanged.
 */
interface TsaEntry {
  der: Uint8Array
  described: TsaAuthorityEntry
  source: string
  on: boolean
}

const authorities: TsaEntry[] = []

/** What the page will actually check a `timestamp` attachment against. */
export const trustedTsaRoots = (): Uint8Array[] => authorities.filter((e) => e.on).map((e) => e.der)

const addTsa = (parsed: { roots: Uint8Array[], entries: TsaAuthorityEntry[] }, source: string): void => {
  parsed.roots.forEach((der, at) => {
    const described = parsed.entries[at] as TsaAuthorityEntry
    if (authorities.some((e) => e.described.fingerprint_sha256 === described.fingerprint_sha256)) return
    authorities.push({ der, described, source, on: true })
  })
}

const sayTsa = (text: string): void => {
  const state = document.getElementById('tsa-state') as HTMLParagraphElement
  state.textContent = text
}

const tsaRow = (entry: TsaEntry, at: number): string => {
  const d = entry.described
  const name = escape(d.name ?? 'a timestamping authority')
  const environment = d.environment ? ` <span class="muted">(${escape(d.environment)})</span>` : ''
  // The sentence that keeps a third party from being read as more than it is.
  // An authority somebody else runs is genuinely independent of us — that is
  // why a token is worth more than our word — and stating that without its
  // limit would let a reader take a timestamp for a statement about the file.
  const third = d.independent === true
    ? '<br><strong>Run by somebody else.</strong> A token from it is evidence we did not make. It proves this hash existed before that instant and that this authority said so — never who made the file, or what it shows.'
    : d.independent === false
      ? '<br><strong>Run by the same people who publish this page.</strong> It is not independent corroboration of anything.'
      : ''
  const caveats = (d.caveats ?? []).map((c) => `<li>${escape(c)}</li>`).join('')
  return `<li>
    <label><input type="checkbox" data-tsa="${at}"${entry.on ? ' checked' : ''}> ${name}${environment}</label>
    <div class="muted"><code>${escape(d.fingerprint_sha256)}</code></div>
    <div class="muted">${d.subject ? `${escape(d.subject)}. ` : ''}${d.operator ? `Operated by ${escape(d.operator)}.` : 'No operator is named.'}${third} <span class="absent">${escape(entry.source)}</span></div>
    ${caveats === '' ? '' : `<ul class="muted">${caveats}</ul>`}
  </li>`
}

const drawTsa = (): void => {
  const list = document.getElementById('tsa-roots') as HTMLUListElement
  list.innerHTML = authorities.length === 0
    ? '<li class="absent">No timestamping authority is trusted. Every proof carrying a timestamp will read <em>trusted time not evaluated</em> — absent evidence, not a failure — and the instant certificates are validated at falls back to the device\'s own clock.</li>'
    : authorities.map(tsaRow).join('')
  for (const box of list.querySelectorAll('input[type=checkbox]')) {
    box.addEventListener('change', () => {
      const at = Number((box as HTMLInputElement).dataset.tsa)
      const entry = authorities[at]
      if (entry) entry.on = (box as HTMLInputElement).checked
      onChange()
    })
  }
}

/** The same three ways in as the log panel: what ships, a document, a pasted line. */
export const mountTsa = async (changed: () => void): Promise<void> => {
  onChange = changed
  try {
    addTsa(await parseTsaDocument(defaultTsaDocument), 'shipped with this page')
  } catch (error) {
    sayTsa(`the shipped timestamping authorities did not load: ${error instanceof Error ? error.message : String(error)}`)
  }
  drawTsa()

  const file = document.getElementById('tsa-file') as HTMLInputElement
  file.addEventListener('change', () => {
    const chosen = file.files?.[0]
    if (!chosen) return
    void chosen.text()
      .then(async (text) => {
        const parsed = await parseTsaDocument(JSON.parse(text) as unknown)
        addTsa(parsed, `from ${chosen.name}`)
        drawTsa(); onChange()
        sayTsa(`${parsed.roots.length} ${parsed.roots.length === 1 ? 'authority' : 'authorities'} added from ${chosen.name}`)
      })
      .catch((error: Error) => { sayTsa(`${chosen.name} is not a TSA trust document: ${error.message}`) })
  })

  const line = document.getElementById('tsa-line') as HTMLInputElement
  const addLine = document.getElementById('tsa-add') as HTMLButtonElement
  addLine.addEventListener('click', () => {
    const text = line.value.trim()
    if (text === '') return
    void parseTsaRoot(text)
      .then(({ fingerprint, der }) => {
        addTsa({ roots: [der], entries: [{ fingerprint_sha256: fingerprint, certificate: text.slice(text.indexOf(':') + 1), name: 'an authority you pinned' }] }, 'pasted here')
        line.value = ''
        drawTsa(); onChange()
        sayTsa(`${fingerprint} is now trusted in this page`)
      })
      .catch((error: Error) => { sayTsa(error.message) })
  })
}

/**
 * Which public chains this page reads an anchor from, and the RPC it asks.
 *
 * The one request a verdict can make, and only for a proof that carries an
 * `anchor`: a read-only `eth_call` to the endpoint `chains.json` lists. It
 * sends the anchor id, never the file or the proof. The endpoint is trusted to
 * answer honestly — a lying RPC could return a forged root — and the panel
 * says so. Switched off, or offline, the anchor reads *anchoring not
 * verified* and the rest of the verdict is unchanged.
 */
const chains: { name: string, entry: ChainEntry, on: boolean }[] = []

// A plain JSON POST with no credentials and no referrer: the endpoint learns
// the anchor id and the reader's address, and nothing about this page. Bounded,
// because a verdict must not wait forever on somebody else's server.
const post = async (url: string, body: string): Promise<string> => {
  const response = await window.fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
    signal: AbortSignal.timeout(10_000)
  })
  if (!response.ok) throw new Error(`${new URL(url).host} answered HTTP ${response.status}`)
  return await response.text()
}

/** The reader over the chains switched on; none on → undefined, which is *chain not consulted*. */
export const chainReader = (): ChainReader | undefined => {
  const on = chains.filter((c) => c.on)
  return on.length === 0 ? undefined : rpcChainReader(Object.fromEntries(on.map((c) => [c.name, c.entry])), post)
}

const drawChains = (): void => {
  const list = document.getElementById('chain-list') as HTMLUListElement
  list.innerHTML = chains.map(({ name, entry, on }, at) => `<li>
    <label><input type="checkbox" data-chain="${at}"${on ? ' checked' : ''}> ${escape(entry.name ?? name)}</label>
    <div class="muted">Contract <code>${escape(entry.contract)}</code>, read through ${entry.rpc.map((url) => `<code>${escape(url)}</code>`).join(', ')}.
    <br><strong>The endpoint is trusted to answer honestly.</strong> This page checks it serves chain ${entry.chain_id} and then believes the root it returns.</div>
    ${(entry.caveats ?? []).length === 0 ? '' : `<ul class="muted">${(entry.caveats ?? []).map((c) => `<li>${escape(c)}</li>`).join('')}</ul>`}
  </li>`).join('')
  for (const box of list.querySelectorAll('input[type=checkbox]')) {
    box.addEventListener('change', () => {
      const chain = chains[Number((box as HTMLInputElement).dataset.chain)]
      if (chain) chain.on = (box as HTMLInputElement).checked
      onChainChange()
    })
  }
}

let onChainChange: () => void = () => {}

export const mountChains = (changed: () => void): void => {
  onChainChange = changed
  try {
    for (const [name, entry] of Object.entries(parseChainsDocument(defaultChainsDocument))) chains.push({ name, entry, on: true })
  } catch (error) {
    (document.getElementById('chain-state') as HTMLParagraphElement).textContent = `the shipped chains did not load: ${error instanceof Error ? error.message : String(error)}`
  }
  drawChains()
}
