#!/usr/bin/env node
//
// Restores `hashes.json.sig` next to a built page from the signature the key
// holder already published in `signing/manifests.jsonl`.
//
//   node bin/mirror-signature.mjs [--dist web/dist]
//
// This exists so a **mirror** can serve the same signed manifest as the
// primary host without the private key ever reaching the machine that
// publishes it (the key is held offline, on one machine, and has no
// business on a CI runner). Nothing here signs anything: it decodes 64 bytes
// that are already public, and refuses when the manifest in front of it is not
// one of the manifests that were signed by hand.
//
// That refusal is the whole point. A mirror may only republish a build the key
// holder published: if the commit being mirrored is not in the log, there is
// no signature for it, and serving an unsigned copy of a page whose primary is
// signed would quietly weaken the thing a reader compares the two hosts on.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256 } from './manifest-signature.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const arg = (name, fallback) => {
  const i = process.argv.indexOf(name)
  return i === -1 ? fallback : process.argv[i + 1]
}
const dist = resolve(root, arg('--dist', 'web/dist'))
const logPath = resolve(arg('--log-file', join(root, 'signing/manifests.jsonl')))

const die = (message) => { console.error(`[vcap] ${message}`); process.exit(1) }

if (!existsSync(`${dist}/hashes.json`)) die(`${dist}/hashes.json missing — build the page first`)
const manifestBytes = readFileSync(`${dist}/hashes.json`)
const manifest = JSON.parse(manifestBytes)
const manifestHash = sha256(manifestBytes)

// A dirty manifest cannot be reproduced by anyone, so it was never signed and
// must never be mirrored. Checked here too rather than left to the lookup: the
// error a publisher reads should name the cause, not the symptom.
if (manifest.dirty) die('this manifest records dirty: true — it was built from a working tree nobody can rebuild')

const entries = existsSync(logPath)
  ? readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line))
  : []
const entry = entries.find((e) => e.manifest_sha256 === manifestHash)
if (!entry) {
  die([
    `no signature for this manifest (sha256 ${manifestHash.slice(0, 16)}…, commit ${manifest.commit.slice(0, 7)}) in ${logPath}.`,
    'A mirror serves what the key holder published: sign and publish this build on the primary first',
    '(signing/README.md), commit the new line in signing/manifests.jsonl, then mirror it.'
  ].join('\n[vcap] '))
}
// The log records the commit alongside the digest and both go into the signed
// message, so a digest that matched under another commit would verify against
// neither. Caught here with a readable message instead of as a bad signature.
if (entry.commit !== manifest.commit) die(`the log entry for this manifest names commit ${entry.commit}, the manifest names ${manifest.commit}`)

writeFileSync(`${dist}/hashes.json.sig`, Buffer.from(entry.sig, 'base64'))
console.log(`[vcap] hashes.json.sig restored from the published log (commit ${entry.commit.slice(0, 7)}, key ${entry.key_sha256.slice(0, 16)}…)`)
console.log(`[vcap] Nothing was signed here. Check it: node bin/verify-build.mjs ${dist}`)
