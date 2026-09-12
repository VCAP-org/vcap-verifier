#!/usr/bin/env node
//
// Checks a built (or downloaded) page against its own manifest and, when a
// detached signature is there, against the published key.
//
//   node bin/verify-build.mjs [web/dist]   one build: hashes, signature, log
//   node bin/verify-build.mjs --log        every signature ever published
//
// Nothing here needs the private key or our host. Running this script is a
// convenience: signing/README.md has the same checks as shell commands, so a
// third party can do them by hand instead of running code of ours — which is
// the point, since code of ours is exactly what is under examination.
import { createPublicKey, verify } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { keyFingerprint, sha256, signedMessage } from './manifest-signature.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const arg = (name, fallback) => {
  const i = process.argv.indexOf(name)
  return i === -1 ? fallback : process.argv[i + 1]
}
// Same overrides as `sign-build`, for the same reason: CI exercises the real
// scripts against a throwaway key. A reader checking a published build passes
// neither and gets the key and the log this repository publishes.
const publicKeyPath = resolve(arg('--public-key', join(root, 'signing/public-key.pem')))
const logPath = resolve(arg('--log-file', join(root, 'signing/manifests.jsonl')))

const die = (message) => { console.error(`[vcap] ${message}`); process.exit(1) }
const ok = (message) => console.log(`[vcap] ok — ${message}`)

const publicKey = createPublicKey(readFileSync(publicKeyPath))
const fingerprint = keyFingerprint(publicKey)
const entries = existsSync(logPath)
  ? readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line))
  : []

const verifyEntry = (entry) => verify(
  null,
  Buffer.from(`vcap/1.0/verifier-build\n${entry.manifest_sha256}\n${entry.commit}\n`, 'utf8'),
  publicKey,
  Buffer.from(entry.sig, 'base64')
)

if (process.argv.includes('--log')) {
  // The continuity claim, checked: every manifest ever published was signed by
  // the key published here. One bad line and the claim is gone — which is
  // what makes it worth stating at all.
  // An empty log is a true statement, not a failure: no manifest has been
  // published yet. It becomes a real gate the day the first line lands.
  if (!entries.length) {
    ok('no manifest has been signed yet — the log is empty, which is what it says')
    process.exit(0)
  }
  for (const entry of entries) {
    if (entry.key_sha256 !== fingerprint) die(`${entry.commit}: signed by key ${entry.key_sha256}, published key is ${fingerprint} (a rotation must be documented in signing/README.md)`)
    if (!verifyEntry(entry)) die(`${entry.commit}: signature does not verify against signing/public-key.pem`)
  }
  ok(`${entries.length} signed manifest(s), one key (${fingerprint.slice(0, 16)}…), unbroken`)
  console.log('[vcap] this says the same key signed all of them. It does not say whose key it is.')
  process.exit(0)
}

const positional = process.argv.slice(2).filter((value, i, all) => !value.startsWith('--') && !all[i - 1]?.startsWith('--'))
const dist = resolve(root, positional[0] || 'web/dist')
if (!existsSync(`${dist}/hashes.json`)) die(`${dist}/hashes.json missing`)

const manifestBytes = readFileSync(`${dist}/hashes.json`)
const manifest = JSON.parse(manifestBytes)
const manifestHash = sha256(manifestBytes)

// The manifest first. A signature over a manifest whose files have changed is
// a signature over a story about files that are not there.
for (const [name, hash] of Object.entries(manifest.files)) {
  if (!existsSync(join(dist, name))) die(`${name} is listed in hashes.json and missing from ${dist}`)
  const actual = sha256(readFileSync(join(dist, name)))
  if (actual !== hash) die(`${name}: ${actual} on disk, ${hash} in hashes.json`)
}
ok(`${Object.keys(manifest.files).length} files match hashes.json (commit ${manifest.commit.slice(0, 7)}${manifest.dirty ? ', dirty' : ''})`)

const sigPath = `${dist}/hashes.json.sig`
if (!existsSync(sigPath)) {
  console.log('[vcap] no hashes.json.sig next to the manifest: this build is unsigned.')
  console.log('[vcap] unsigned is not invalid — rebuild the commit and compare (README).')
} else {
  if (!verify(null, signedMessage(manifestBytes, manifest.commit), publicKey, readFileSync(sigPath))) {
    die(`hashes.json.sig does not verify against ${publicKeyPath}`)
  }
  ok(`hashes.json.sig verifies against the published key (${fingerprint.slice(0, 16)}…)`)
}

const entry = entries.find((e) => e.manifest_sha256 === manifestHash)
if (entry) {
  if (!verifyEntry(entry)) die(`the log entry for ${entry.commit} does not verify`)
  ok(`this manifest is in signing/manifests.jsonl, after ${entries.indexOf(entry)} earlier one(s) by the same key`)
} else {
  console.log('[vcap] this manifest is not in signing/manifests.jsonl — it was never published, or the log is behind.')
}

console.log('')
console.log('[vcap] What this proves: these bytes are the ones the manifest names, and the')
console.log('[vcap] manifest was signed by the same key that signed the earlier ones.')
console.log('[vcap] What it does not prove: who holds that key. There is no certificate and no')
console.log('[vcap] legal entity behind it. Continuity, not identity — signing/README.md.')
