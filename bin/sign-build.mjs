#!/usr/bin/env node
//
// Signs the manifest of a built page: `web/dist/hashes.json`.
//
//   node bin/sign-build.mjs [--dist web/dist] [--key <private key.pem>]
//
// What this does NOT do is sign the page. The signature is detached, it is
// written *next to* `dist/` and never inside it, and nothing in the signed
// bytes depends on it — otherwise signing would change the tree it certifies
// and the reproducible build would invalidate itself on the first publish.
//
// What the signature is worth is written in signing/README.md and repeated by
// `bin/verify-build.mjs`: there is no legal entity (R4) and no certificate
// (D2) behind this key, so it proves **continuity, not identity**.
//
// The private key lives in `Ops/verifier-signing/ed25519-private.pem`, outside
// every repository (workspace AGENT.md rule 6). It is never read from the
// repository and never written to it.
import { execFileSync } from 'node:child_process'
import { createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { keyFingerprint, logLine, sha256, signedMessage } from './manifest-signature.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const arg = (name, fallback) => {
  const i = process.argv.indexOf(name)
  return i === -1 ? fallback : process.argv[i + 1]
}

const dist = resolve(root, arg('--dist', 'web/dist'))
const keyPath = resolve(arg('--key', process.env.VCAP_SIGNING_KEY || join(root, '..', 'Ops/verifier-signing/ed25519-private.pem')))
const publicKeyPath = join(root, 'signing/public-key.pem')
const logPath = join(root, 'signing/manifests.jsonl')

const die = (message) => { console.error(`[vcap] ${message}`); process.exit(1) }

if (!existsSync(`${dist}/hashes.json`)) die(`${dist}/hashes.json missing — build the page first`)
if (!existsSync(keyPath)) die(`no signing key at ${keyPath}. It lives in Ops/, outside every repo; pass --key or set VCAP_SIGNING_KEY`)

const manifestBytes = readFileSync(`${dist}/hashes.json`)
const manifest = JSON.parse(manifestBytes)

// A dirty build matches no commit, so its manifest names a tree nobody can
// rebuild. Signing it would be a signature over something unverifiable, which
// is the one thing this signature must never be.
if (manifest.dirty) die('this build records dirty: true — sign only a build from a clean checkout')
if (manifest.commit === 'unknown') die('this build could not name its commit — sign only a build from a git checkout')

// The signed manifest must describe the files that are actually there. A
// signature produced over a manifest whose tree has drifted is worse than none.
for (const [name, hash] of Object.entries(manifest.files)) {
  const actual = sha256(readFileSync(join(dist, name)))
  if (actual !== hash) die(`${name} hashes ${actual}, manifest says ${hash} — refusing to sign a manifest that does not match its own tree`)
}

const privateKey = createPrivateKey(readFileSync(keyPath))
const publicKey = createPublicKey(privateKey)
if (privateKey.asymmetricKeyType !== 'ed25519') die(`the key at ${keyPath} is ${privateKey.asymmetricKeyType}, not ed25519`)

// The published public key is the anchor of the whole continuity claim: a
// silent swap would turn "the same key as last time" into a sentence that
// means nothing. A rotation is allowed, but it is a deliberate commit.
const published = existsSync(publicKeyPath) ? createPublicKey(readFileSync(publicKeyPath)) : null
if (published && keyFingerprint(published) !== keyFingerprint(publicKey)) {
  die(`this key does not match signing/public-key.pem. Rotating is allowed, but it breaks continuity: publish the new key in its own commit and say so in signing/README.md`)
}
if (!published) writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }))

const message = signedMessage(manifestBytes, manifest.commit)
const signature = sign(null, message, privateKey)
writeFileSync(`${dist}/hashes.json.sig`, signature)

const entry = {
  commit: manifest.commit,
  build_id: manifest.build_id,
  manifest_sha256: sha256(manifestBytes),
  key_sha256: keyFingerprint(publicKey),
  sig: signature.toString('base64')
}
const line = logLine(entry)
const existing = existsSync(logPath) ? readFileSync(logPath, 'utf8').split('\n').filter(Boolean) : []

// Re-signing the identical manifest is a no-op, not a second line: the log is
// a record of what was published, and Ed25519 is deterministic, so the same
// manifest always yields the same signature.
if (!existing.includes(line)) {
  const clash = existing.map((l) => JSON.parse(l)).find((e) => e.commit === entry.commit && e.manifest_sha256 !== entry.manifest_sha256)
  if (clash) die(`commit ${entry.commit} is already in the log with manifest ${clash.manifest_sha256}. Two different manifests for one commit means the build is not reproducible — fix that, do not sign both`)
  appendFileSync(logPath, `${line}\n`)
}

const head = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
console.log(`[vcap] signed the manifest of commit ${manifest.commit} (build ${manifest.build_id})`)
console.log(`[vcap] ${dist}/hashes.json.sig — publish it next to hashes.json`)
console.log(`[vcap] signing/manifests.jsonl updated; commit it (repo is at ${head.slice(0, 7)})`)
console.log('[vcap] this proves continuity of the signing key, not who we are. See signing/README.md.')
