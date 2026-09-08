import { verify, type Verdict } from 'vcap-verify-core'

/**
 * The page: read the dropped file (and a sidecar if one is dropped with it),
 * run the shared core, say what it found in the spec's words. No network.
 * Trusted transparency logs would be listed in a `logs.json` next to the page;
 * none are, yet — so `registry` attachments read "log not trusted" for now.
 */
const drop = document.getElementById('drop') as HTMLDivElement
const input = document.getElementById('file') as HTMLInputElement
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

const escape = (s: string): string => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string))

const render = (name: string, v: Verdict): void => {
  const lines = [
    ...v.labels.map((l) => `<li>${escape(l)}</li>`),
    ...v.not_evaluated.map((k) => `<li>not evaluated: <code>${escape(k)}</code></li>`)
  ]
  const details = [
    v.claimed_secure_hw ? `<li>claimed level: <code>${escape(v.claimed_secure_hw)}</code> (attestation not evaluated by this page)</li>` : '',
    v.device_clock ? `<li>declared capture time: ${new Date(v.device_clock).toISOString()} (device clock, not trusted time)</li>` : '',
    v.segments ? `<li>segments verified: ${v.segments.verified.length ? v.segments.verified.join(', ') : 'none'}</li>` : '',
    v.registry ? `<li>transparency log: ${escape(v.registry.detail)}</li>` : '',
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

const handle = async (files: FileList | File[]): Promise<void> => {
  const list = Array.from(files)
  const media = list.find((f) => !f.name.endsWith('.vcap'))
  const sidecar = list.find((f) => f.name.endsWith('.vcap'))
  if (!media) { out.innerHTML = '<div class="verdict grey"><h2>Drop the media file</h2></div>'; return }
  const verdict = await verify(new Uint8Array(await media.arrayBuffer()), {
    sidecar: sidecar ? new Uint8Array(await sidecar.arrayBuffer()) : undefined
  })
  render(media.name, verdict)
}

input.addEventListener('change', () => { if (input.files) void handle(input.files) })
drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over') })
drop.addEventListener('dragleave', () => drop.classList.remove('over'))
drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer?.files) void handle(e.dataTransfer.files) })
