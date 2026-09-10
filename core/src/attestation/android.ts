import { type Bytes, equal, fromUtf8, toHex } from '../bytes.js'
import { Asn1Error, type Node, boolean, contextTag, enumerated, explicitContent, integer, octets, parseDer, sequence, set } from '../asn1.js'
import { type Certificate, chainToRoot, issuedBy, parseCertificate, pemToDer, withinValidity } from '../x509.js'
import { GOOGLE_ROOT_PEMS } from './google-roots.js'

/**
 * Android key attestation as a verifier reads it from a proof (§7): the chain
 * must end in a pinned Google root, the extension on the leaf gives the proven
 * level and the boot state, the leaf key must be the signing key. Revocation
 * needs Google's status list, i.e. network: injected when available, labelled
 * when not. Challenge, proof of possession and application identity are the
 * registry's business at enrolment, not the verifier's.
 */
export const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17'
export type SecureLevel = 'software' | 'tee' | 'strongbox'
const LEVELS: SecureLevel[] = ['software', 'tee', 'strongbox']
const BOOT = ['verified', 'selfSigned', 'unverified', 'failed']

export interface AndroidResult {
  proven: 'strongbox' | 'tee' | 'none'
  checks: { id: string, outcome: 'pass' | 'fail' | 'skip', detail: string }[]
  bootState?: { locked: boolean, state: string }
  revocation: 'clear' | 'revoked' | 'not_checked'
  // Which certificate the status list had an entry for, when it had one. The
  // *when* is missing on purpose: Google's list is a current-status list and
  // carries no revocation date, so the only instant an online answer can speak
  // for is the moment it was fetched. §6.2's temporal rule therefore applies to
  // it exactly as to the frozen snapshot, with the fetch time as `fetched_at` —
  // which is why this result reports the finding and draws no conclusion from
  // it. Zeroing the proven level here would say a batch key withdrawn in 2028
  // un-attests a capture from 2026.
  revoked?: { serial: string, status: string }
  // Set when the chain was valid at the instant it was validated at but has
  // expired since: the earliest notAfter in the chain. The caller decides what
  // to say about it, because that depends on how the instant was proven (§7).
  expiredSince?: string
}

export type RevocationLookup = (serialHex: string) => Promise<{ status: string } | null>

let cachedRoots: Certificate[] | null = null
export const googleRoots = (): Certificate[] => (cachedRoots ??= GOOGLE_ROOT_PEMS.map((p) => parseCertificate(pemToDer(p))))

interface Description { attestationLevel: SecureLevel, keyMintLevel: SecureLevel, rootOfTrust?: { locked: boolean, state: string } }

const parseDescription = (value: Bytes): Description => {
  const f = sequence(parseDer(value), 'KeyDescription')
  if (f.length < 8) throw new Asn1Error('KeyDescription: expected 8 fields')
  const level = (n: Node, what: string): SecureLevel => { const l = LEVELS[enumerated(n, what)]; if (!l) throw new Asn1Error(`${what}: unknown level`); return l }
  const d: Description = { attestationLevel: level(f[1] as Node, 'attestationSecurityLevel'), keyMintLevel: level(f[3] as Node, 'keyMintSecurityLevel') }
  for (const entry of sequence(f[7] as Node, 'hardwareEnforced')) {
    if (contextTag(entry) !== 704) continue
    const rot = sequence(explicitContent(entry, 'rootOfTrust'), 'RootOfTrust')
    d.rootOfTrust = { locked: boolean(rot[1] as Node, 'deviceLocked'), state: BOOT[enumerated(rot[2] as Node, 'verifiedBootState')] ?? 'unknown' }
  }
  return d
}

export const validateAndroidAttestation = async (chainB64: Bytes[], sigPub: Bytes, o: { roots?: Certificate[], revocation?: RevocationLookup, now?: Date, clock?: Date } = {}): Promise<AndroidResult> => {
  const checks: AndroidResult['checks'] = []
  const pass = (id: string, detail: string) => checks.push({ id, outcome: 'pass', detail })
  const fail = (id: string, detail: string) => checks.push({ id, outcome: 'fail', detail })
  const result: AndroidResult = { proven: 'none', checks, revocation: 'not_checked' }
  // §7: `now` is the proven instant of the capture, which is what path
  // validation uses; `clock` is the verifier's own clock, used only to notice
  // that a chain valid then has expired since. An RKP intermediate lives about
  // twelve days, so with the two collapsed into one every attested capture
  // would read as unattested a fortnight later.
  const now = o.now ?? new Date()
  const clock = o.clock ?? new Date()

  let certs: Certificate[]
  try { certs = chainB64.map(parseCertificate); if (!certs.length) throw new Error('empty') } catch { fail('chain_parsed', 'chain is empty or not DER certificates'); return result }
  pass('chain_parsed', `${certs.length} certificates`)

  const leaf = certs[0] as Certificate
  if (!equal(leaf.spki, sigPub)) fail('key_binding', 'attestation leaf key differs from sig.pub')
  else pass('key_binding', 'attestation leaf key is the signing key')

  // Every link signed by the next; the last one issued by (or equal to) a pinned root.
  let linked = true
  for (let i = 0; i < certs.length - 1; i++) if (!await issuedBy(certs[i] as Certificate, certs[i + 1] as Certificate)) { fail('chain_signatures', `certificate ${i} is not issued by certificate ${i + 1}`); linked = false; break }
  if (linked) pass('chain_signatures', 'every certificate is signed by the next')
  const chain = await chainToRoot(certs[certs.length - 1] as Certificate, [], o.roots ?? googleRoots())
  if (chain) pass('chain_root', 'ends in a pinned Google attestation root'); else fail('chain_root', 'chain does not end in a pinned Google root')
  const outside = certs.findIndex((c) => !withinValidity(c, now))
  if (outside === -1) pass('chain_validity', `every certificate is within its validity period at ${now.toISOString()}`)
  else fail('chain_validity', `certificate ${outside} is outside its validity period at ${now.toISOString()}`)
  if (outside === -1) {
    const expired = certs.filter((c) => !withinValidity(c, clock)).map((c) => c.notAfter.getTime())
    if (expired.length > 0) result.expiredSince = new Date(Math.min(...expired)).toISOString()
  }

  if (o.revocation) {
    for (const c of certs) {
      const r = await o.revocation(c.serialHex)
      if (r) { result.revoked = { serial: c.serialHex, status: r.status }; break }
    }
    result.revocation = result.revoked ? 'revoked' : 'clear'
    if (result.revoked) fail('chain_revocation', `certificate ${result.revoked.serial} is ${result.revoked.status}`)
    else pass('chain_revocation', 'no certificate in the chain is revoked')
  } else {
    checks.push({ id: 'chain_revocation', outcome: 'skip', detail: 'revocation list not available offline' })
  }

  const ext = leaf.extensions.get(KEY_DESCRIPTION_OID)
  if (!ext) { fail('extension', 'leaf carries no key attestation extension'); return result }
  let d: Description
  try { d = parseDescription(ext); pass('extension', 'key attestation extension read') } catch (e) { fail('extension', `attestation extension unreadable: ${e instanceof Asn1Error ? e.message : 'malformed'}`); return result }

  const rank: Record<SecureLevel, number> = { software: 0, tee: 1, strongbox: 2 }
  const weakest = rank[d.attestationLevel] <= rank[d.keyMintLevel] ? d.attestationLevel : d.keyMintLevel
  if (d.rootOfTrust) {
    result.bootState = d.rootOfTrust
    if (d.rootOfTrust.locked && d.rootOfTrust.state === 'verified') pass('boot_state', 'verified boot on a locked device')
    else fail('boot_state', `boot state ${d.rootOfTrust.state}, device ${d.rootOfTrust.locked ? 'locked' : 'unlocked'}`)
  } else fail('boot_state', 'no hardware-enforced rootOfTrust')

  const structural = checks.filter((c) => ['key_binding', 'chain_signatures', 'chain_root', 'chain_validity', 'boot_state'].includes(c.id)).every((c) => c.outcome === 'pass')
  if (weakest === 'software') fail('security_level', 'attestation or key is software')
  else pass('security_level', `attestation ${d.attestationLevel}, key ${d.keyMintLevel}`)
  // Revocation does not enter here: it is temporal (§6.2) and this function
  // does not know the proven instant of the capture, only the instant it was
  // asked to validate the path at. The caller withdraws the level when the
  // revocation precedes the capture, and leaves it standing when it follows.
  result.proven = structural && weakest !== 'software' ? weakest : 'none'
  return result
}

export { toHex, fromUtf8, set, integer, octets }
