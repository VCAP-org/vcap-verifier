import { type Bytes, equal } from './bytes.js'
import { Asn1Error, type Node, children, contextTag, explicitContent, integerHex, octets, oid, parseDer, sequence, set, derOf } from './asn1.js'
import { sha256, subtle, owned } from './sha.js'
import { type Certificate, chainToRoot, hashOf, importForVerify, parseCertificate, verifyWith, withinValidity } from './x509.js'

/**
 * RFC 3161 token validation, offline, as a verifier meets it in a proof:
 * messageImprint equals core_hash; the signed attributes name TSTInfo and hash
 * it; the signer's signature over them verifies; the signer chains to a pinned
 * TSA root **at genTime** (§7: the proven instant, not the verifier's clock);
 * the signer certificate is for time-stamping; genTime is not in the future.
 * No nonce (the verifier never made the request). Same eight checks as the
 * platform, over WebCrypto.
 */
const OID = {
  sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3',
  tstInfo: '1.2.840.113549.1.9.16.1.4', signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3', messageDigest: '1.2.840.113549.1.9.4',
  rsaEncryption: '1.2.840.113549.1.1.1', extendedKeyUsage: '2.5.29.37', timeStamping: '1.3.6.1.5.5.7.3.8', ski: '2.5.29.14'
} as const
const DIGEST: Record<string, string> = { [OID.sha256]: 'SHA-256', [OID.sha384]: 'SHA-384', [OID.sha512]: 'SHA-512' }

export type TimestampCheckId = 'token_parsed' | 'imprint' | 'message_digest' | 'signature' | 'signer_chain' | 'signer_usage' | 'gen_time'
export interface TimestampVerdict {
  ok: boolean
  checks: { id: TimestampCheckId, outcome: 'pass' | 'fail' | 'skip', detail: string }[]
  genTime?: string
  tsa?: string
  /**
   * The TSA's own identifier for this token, hex, and the policy it issued
   * under.
   *
   * Not checks — nothing here verifies them — but the serial is what you cite
   * to a TSA when disputing a token, and a party that has to ask "which stamp
   * do you mean" without it has to send the whole token back. Read once here
   * because the parse is already done.
   */
  serialNumber?: string
  policy?: string
}

export const validateTimestamp = async (tokenDer: Bytes, coreHash: Bytes, roots: Certificate[], now = new Date()): Promise<TimestampVerdict> => {
  const checks: TimestampVerdict['checks'] = []
  const pass = (id: TimestampCheckId, detail: string) => checks.push({ id, outcome: 'pass', detail })
  const fail = (id: TimestampCheckId, detail: string) => checks.push({ id, outcome: 'fail', detail })
  const verdict: TimestampVerdict = { ok: false, checks }

  let tstInfoDer: Bytes, tst: Node[], certs: Certificate[], si: Node[]
  try {
    const contentInfo = sequence(parseDer(tokenDer), 'ContentInfo')
    if (oid(contentInfo[0] as Node, 'contentType') !== OID.signedData) throw new Asn1Error('not CMS SignedData')
    const sd = sequence(explicitContent(contentInfo[1] as Node, 'content'), 'SignedData')
    const encap = sequence(sd[2] as Node, 'encapContentInfo')
    if (oid(encap[0] as Node, 'eContentType') !== OID.tstInfo) throw new Asn1Error('content is not TSTInfo')
    tstInfoDer = octets(explicitContent(encap[1] as Node, 'eContent'), 'eContent')
    tst = sequence(parseDer(tstInfoDer), 'TSTInfo')
    certs = []
    for (const n of sd.slice(3)) if (contextTag(n) === 0) for (const c of children(n, 'certificates')) certs.push(parseCertificate(derOf(c)))
    const signerInfos = set(sd[sd.length - 1] as Node, 'signerInfos')
    if (signerInfos.length !== 1) throw new Asn1Error('expected one SignerInfo')
    si = sequence(signerInfos[0] as Node, 'SignerInfo')
    pass('token_parsed', `${certs.length} certificates`)
  } catch (error) {
    fail('token_parsed', `token unreadable: ${error instanceof Asn1Error ? error.message : 'malformed'}`)
    for (const id of ['imprint', 'message_digest', 'signature', 'signer_chain', 'signer_usage', 'gen_time'] as TimestampCheckId[]) checks.push({ id, outcome: 'skip', detail: 'token not parsed' })
    return verdict
  }

  // TSTInfo: version, policy, messageImprint, serialNumber, genTime, …
  try {
    const imprint = sequence(tst[2] as Node, 'messageImprint')
    const alg = oid(sequence(imprint[0] as Node, 'hashAlgorithm')[0] as Node, 'hashAlgorithm')
    if (alg === OID.sha256 && equal(octets(imprint[1] as Node, 'hashedMessage'), coreHash)) pass('imprint', 'messageImprint is SHA-256 of the core hash')
    else fail('imprint', alg === OID.sha256 ? 'messageImprint differs from the core hash' : 'messageImprint is not SHA-256')
    verdict.policy = oid(tst[1] as Node, 'policy')
    verdict.serialNumber = integerHex(tst[3] as Node, 'serialNumber')
    const genTime = (tst[4] as { toDate: () => Date }).toDate()
    verdict.genTime = genTime.toISOString()
    if (genTime.getTime() <= now.getTime() + 5 * 60_000) pass('gen_time', verdict.genTime)
    else fail('gen_time', 'genTime is in the future')
  } catch { fail('imprint', 'TSTInfo malformed'); fail('gen_time', 'TSTInfo malformed') }

  // SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
  const sidNode = si[1] as Node
  const attrsNode = si.find((n, i) => i > 1 && contextTag(n) === 0)
  const digestAlg = oid(sequence(si[2] as Node, 'digestAlgorithm')[0] as Node, 'digestAlgorithm')
  const sigAlgIndex = attrsNode ? si.indexOf(attrsNode) + 1 : -1
  if (!attrsNode || sigAlgIndex < 0) { fail('message_digest', 'no signed attributes'); fail('signature', 'no signed attributes'); fail('signer_chain', 'no signer'); fail('signer_usage', 'no signer'); return verdict }
  const signatureAlg = oid(sequence(si[sigAlgIndex] as Node, 'signatureAlgorithm')[0] as Node, 'signatureAlgorithm')
  const signature = octets(si[sigAlgIndex + 1] as Node, 'signature')
  const attrs = children(attrsNode, 'signedAttrs').map((a) => { const [t, v] = sequence(a, 'Attribute'); return { type: oid(t as Node, 'attrType'), values: set(v as Node, 'attrValues') } })
  const hashName = DIGEST[digestAlg]
  try {
    if (!hashName) throw new Error(`unsupported digest algorithm ${digestAlg}`)
    const ct = attrs.find((a) => a.type === OID.contentType)?.values[0]
    const md = attrs.find((a) => a.type === OID.messageDigest)?.values[0]
    if (!ct || oid(ct, 'contentType') !== OID.tstInfo) throw new Error('contentType attribute is not TSTInfo')
    const digest = new Uint8Array(await subtle().digest(hashName, owned(tstInfoDer)))
    if (!md || !equal(octets(md, 'messageDigest'), digest)) throw new Error('messageDigest does not hash the TSTInfo')
    pass('message_digest', 'signed attributes name TSTInfo and hash it')
  } catch (error) { fail('message_digest', (error as Error).message) }

  // The signer: by issuer+serial or by subjectKeyIdentifier.
  const signer = certs.find((c) => {
    if (contextTag(sidNode) === 0) {
      const ski = c.extensions.get(OID.ski)
      try { return ski !== undefined && equal(octets(parseDer(ski), 'SKI'), new Uint8Array((sidNode as { valueBlock: { valueHexView: Uint8Array } }).valueBlock.valueHexView)) } catch { return false }
    }
    try { const [, serial] = sequence(sidNode, 'IssuerAndSerialNumber'); return integerHex(serial as Node, 'serial') === c.serialHex } catch { return false }
  })
  if (!signer) { fail('signature', 'signer certificate not found in the token'); fail('signer_chain', 'no signer certificate'); fail('signer_usage', 'no signer certificate'); return verdict }

  // Signature over the signedAttrs re-tagged as SET OF (RFC 5652 §5.4).
  const attrsAsSet = derOf(attrsNode); attrsAsSet[0] = 0x31
  const sigHash = signatureAlg === OID.rsaEncryption ? hashName : hashOf(signatureAlg)
  const pub = sigHash ? await importForVerify(signer.spki, sigHash) : null
  const verified = pub !== null && sigHash !== null && (signatureAlg === OID.rsaEncryption
    ? await subtle().verify({ name: 'RSASSA-PKCS1-v1_5' }, pub.key, owned(signature), owned(attrsAsSet)).catch(() => false)
    : await verifyWith(pub, signatureAlg, attrsAsSet, signature))
  if (verified) pass('signature', 'signed by the TSA certificate')
  else fail('signature', sigHash ? 'signature does not verify with the signer certificate' : `unsupported signature algorithm ${signatureAlg}`)

  // §7: the TSA chain is validated at the instant the token proves, not at the
  // verifier's clock. genTime lives inside the signed TSTInfo, so it cannot be
  // moved without breaking the TSA signature — and validating at "now" would
  // make every token unverifiable the day its TSA certificate expires, which
  // destroys the long-term validation the token exists to provide. Falls back
  // to the verifier's clock only when genTime could not be read.
  const at = verdict.genTime ? new Date(verdict.genTime) : now
  const chain = await chainToRoot(signer, certs, roots)
  if (chain && chain.every((c) => withinValidity(c, at))) pass('signer_chain', `signer chains to a pinned TSA root, valid at ${at.toISOString()}`)
  else fail('signer_chain', chain ? `a certificate in the chain is outside its validity at ${at.toISOString()}` : 'signer does not chain to a pinned TSA root')

  const eku = signer.extensions.get(OID.extendedKeyUsage)
  let stamping = false
  try { stamping = eku !== undefined && sequence(parseDer(eku), 'EKU').some((n) => oid(n, 'eku') === OID.timeStamping) } catch { stamping = false }
  if (stamping) pass('signer_usage', 'signer certificate is for time-stamping')
  else fail('signer_usage', 'signer certificate lacks the timeStamping extended key usage')
  verdict.tsa = `serial ${signer.serialHex}`

  verdict.ok = checks.every((c) => c.outcome !== 'fail')
  return verdict
}

export const coreHashImprint = sha256
