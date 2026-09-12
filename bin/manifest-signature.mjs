// The one definition of what gets signed, shared by `sign-build` and
// `verify-build` so the two can never drift. It is three lines of text, and it
// is written out here rather than hidden in a library because a third party
// must be able to rebuild the same bytes with `printf` and check the signature
// with `openssl` — see signing/README.md.
//
//   vcap/1.0/verifier-build\n<sha256 of hashes.json>\n<commit>\n
//
// Domain-separated like every other signature in this system (the webhook
// messages, the registry's signed answers): a signature over a bare digest
// could be replayed as a signature over something else that hashes the same
// way in another protocol.
import { createHash, createPublicKey } from 'node:crypto'

export const DOMAIN = 'vcap/1.0/verifier-build'

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

/**
 * The signed message for a manifest.
 * @param {Buffer|Uint8Array} manifestBytes the exact bytes of `hashes.json`
 * @param {string} commit the commit `hashes.json` records
 */
export const signedMessage = (manifestBytes, commit) =>
  Buffer.from(`${DOMAIN}\n${sha256(manifestBytes)}\n${commit}\n`, 'utf8')

// Which key signed, recorded in every log line so a rotation is visible rather
// than silent: the digest of the public key's SPKI DER, the same bytes the
// PEM in signing/public-key.pem carries.
export const keyFingerprint = (publicKey) =>
  sha256(createPublicKey(publicKey).export({ type: 'spki', format: 'der' }))

// One line of the continuity log, with a fixed key order so the file stays a
// stable, append-only text record.
export const logLine = (entry) => JSON.stringify({
  commit: entry.commit,
  build_id: entry.build_id,
  manifest_sha256: entry.manifest_sha256,
  key_sha256: entry.key_sha256,
  sig: entry.sig
})
