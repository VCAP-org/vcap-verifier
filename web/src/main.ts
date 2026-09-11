import { verify, type Verdict } from 'vcap-verify-core'

/**
 * The page: read the dropped file (and a sidecar if one is dropped with it or
 * into its own zone), run the shared core, say what it found in the spec's
 * words. No network. Trusted transparency logs would be listed in a
 * `logs.json` next to the page; none are, yet — so `registry` attachments
 * read "log not trusted" for now.
 *
 * The sidecar (§3.1) comes from the user's hands only: a second file input
 * or a `.vcap` dropped anywhere on the page. Nothing is looked for and
 * nothing is fetched — a page has no directory to read `<filename>.vcap` from,
 * so the caller-provided form is the only one it can offer. What the core
 * does with it is the spec's precedence: the trailer wins and a differing
 * sidecar is a label; a broken trailer stays corrupted; a sidecar alone is the
 * full verdict over the whole file, and where the proof sat is never a label.
 */
const drop = document.getElementById('drop') as HTMLDivElement
const input = document.getElementById('file') as HTMLInputElement
const sidecarDrop = document.getElementById('sidecar-drop') as HTMLDivElement
const sidecarInput = document.getElementById('sidecar') as HTMLInputElement
const out = document.getElementById('out') as HTMLDivElement

const COLOR: Record<Verdict['outcome'], string> = {
  authentic: 'green', verified_clip: 'amber', tampered: 'red', nested_proof: 'amber',
  corrupted_proof: 'red', no_proof_found: 'grey', unsupported_format_version: 'grey'
}
const TITLE: Record<Verdict['outcome'], string> = {
  authentic: 'Authentic — signed at capture, file complete',
  verified_clip: 'Verified clip — signed frames of a longer original',
  tampered: 'Tampered — the file or its proof was altered after sealing',
  nested_proof: 'Nested proof — a sealed file was sealed again; the outer proof is not authoritative',
  corrupted_proof: 'Corrupted proof — the trailer is damaged',
  no_proof_found: 'No proof found',
  unsupported_format_version: 'Unsupported format version'
}

const SOURCE: Record<string, string> = {
  timestamp: 'proven by the timestamp token',
  anchor: 'proven by the anchored block',
  device_clock: 'the device\'s own clock, not proven',
  verifier_clock: 'this browser\'s clock; the proof declares no time'
}

const escape = (s: string): string => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string))

const render = (name: string, v: Verdict): void => {
  const lines = [
    ...v.labels.map((l) => `<li>${escape(l)}</li>`),
    ...v.not_evaluated.map((k) => `<li>not evaluated: <code>${escape(k)}</code></li>`)
  ]
  const details = [
    v.claimed_secure_hw ? `<li>claimed level: <code>${escape(v.claimed_secure_hw)}</code> (attestation not evaluated by this page)</li>` : '',
    v.device_clock ? `<li>declared capture time: ${new Date(v.device_clock).toISOString()} (device clock, not trusted time)</li>` : '',
    // §7: which clock the certificate paths were validated at. A reader who is
    // not told cannot tell a capture time proven by a token from one the device
    // asserted about itself.
    v.validated_at ? `<li>validated at: ${escape(v.validated_at.instant)} (${escape(SOURCE[v.validated_at.source] ?? v.validated_at.source)})</li>` : '',
    v.segments ? `<li>segments verified: ${v.segments.verified.length ? v.segments.verified.join(', ') : 'none'}</li>` : '',
    v.segments?.contradicted?.length ? `<li>segments whose frames are not the signed frames: ${v.segments.contradicted.join(', ')}</li>` : '',
    // §5 recomputation either happened or did not, and the page says which:
    // "every segment verifies" means much less when nothing read the frames.
    v.content ? `<li>segment content: ${v.content.recomputed ? 'recomputed from the container' : 'not recomputed'} (${escape(v.content.detail)})</li>` : '',
    v.registry ? `<li>transparency log: ${escape(v.registry.detail)}</li>` : '',
    v.attestation_status ? `<li>chain revocation: ${escape(v.attestation_status.detail)}</li>` : '',
    // The device key's own standing, which is the one thing this page cannot
    // establish from the file: it ships with no log to ask, so it says so
    // rather than leaving the reader to assume it was checked.
    v.key_status ? `<li>key revocation: ${escape(v.key_status.detail)}</li>` : '',
    v.anchor ? `<li>anchor: ${escape(v.anchor.detail)}</li>` : '',
    v.core_hash ? `<li>proof identity: <code>${v.core_hash}</code></li>` : '',
    v.reason ? `<li>${escape(v.reason)}</li>` : ''
  ].filter(Boolean)
  out.innerHTML = `<div class="verdict ${COLOR[v.outcome]}">
    <h2>${escape(TITLE[v.outcome])}</h2>
    <div class="muted">${escape(name)}</div>
    ${lines.length ? `<ul>${lines.join('')}</ul>` : ''}
    ${details.length ? `<details><summary>details</summary><ul>${details.join('')}</ul></details>` : ''}
  </div>`
}

// What the user has handed over so far. The two arrive separately or
// together, and the verdict is recomputed whenever either changes, so the
// order they are dropped in does not matter.
const held: { media?: File, sidecar?: File } = {}

const isSidecar = (f: File): boolean => f.name.endsWith('.vcap')

const check = async (): Promise<void> => {
  const { media, sidecar } = held
  if (!media) { out.innerHTML = '<div class="verdict grey"><h2>Drop the media file</h2></div>'; return }
  const verdict = await verify(new Uint8Array(await media.arrayBuffer()), {
    sidecar: sidecar ? new Uint8Array(await sidecar.arrayBuffer()) : undefined
  })
  render(sidecar ? `${media.name} + ${sidecar.name}` : media.name, verdict)
}

// Either zone takes either kind: a `.vcap` is the sidecar, anything else the
// media, whichever box it landed in — so two files dropped together in the
// first zone still work, and a sidecar dropped into the wrong box is not lost.
const take = (files: FileList | File[]): void => {
  const list = Array.from(files)
  const media = list.find((f) => !isSidecar(f))
  const sidecar = list.find(isSidecar)
  if (media) held.media = media
  if (sidecar) held.sidecar = sidecar
  if (media || sidecar) void check()
}

input.addEventListener('change', () => { if (input.files) take(input.files) })
sidecarInput.addEventListener('change', () => { if (sidecarInput.files) take(sidecarInput.files) })
for (const zone of [drop, sidecarDrop]) {
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over') })
  zone.addEventListener('dragleave', () => zone.classList.remove('over'))
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('over'); if (e.dataTransfer?.files) take(e.dataTransfer.files) })
}

// Offline: the worker precaches this exact build (`sw.js` is generated by the
// build with the list of shipped files). `ready` resolves once the worker is
// active, which comes after install has stored every file — so the footer says
// "available offline" only when it is true. A failed registration (file://,
// a dev build without sw.js) leaves the page working online and is reported,
// not thrown.
const offline = document.getElementById('offline') as HTMLSpanElement
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js')
    .then(() => navigator.serviceWorker.ready)
    .then(() => { offline.textContent = 'available offline' })
    .catch(() => { offline.textContent = 'not cached for offline use' })
}
