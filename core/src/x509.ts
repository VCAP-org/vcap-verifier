import * as asn1js from 'asn1js'
import { type Bytes, concat, equal } from './bytes.js'
import { Asn1Error, type Node, bitStringBytes, contextTag, derOf, explicitContent, integerHex, octets, oid, parseDer, sequence, time } from './asn1.js'
import { owned, subtle } from './sha.js'

/**
 * A minimal X.509 reader for the verifier: enough to chain a certificate to a
 * pinned root and read an extension, in a browser. No hostname logic, no CRLs,
 * no policy: what a verifier needs to say "this leaf was issued under that
 * root" and nothing more. Signature algorithms: RSA PKCS#1 v1.5 and ECDSA with
 * SHA-256/384/512; RSA-PSS is refused, not guessed.
 */
export interface Certificate {
  der: Bytes
  tbs: Bytes
  serialHex: string
  issuer: Bytes
  subject: Bytes
  notBefore: Date
  notAfter: Date
  spki: Bytes
  signatureAlgorithm: string
  signature: Bytes
  extensions: Map<string, Bytes>
  // Basic constraints: cA flag when the extension is present.
  isCa: boolean | null
}

const OID = {
  sha256WithRSA: '1.2.840.113549.1.1.11', sha384WithRSA: '1.2.840.113549.1.1.12', sha512WithRSA: '1.2.840.113549.1.1.13',
  ecdsaSHA256: '1.2.840.10045.4.3.2', ecdsaSHA384: '1.2.840.10045.4.3.3', ecdsaSHA512: '1.2.840.10045.4.3.4',
  rsaEncryption: '1.2.840.113549.1.1.1', ecPublicKey: '1.2.840.10045.2.1',
  p256: '1.2.840.10045.3.1.7', p384: '1.3.132.0.34', p521: '1.3.132.0.35',
  basicConstraints: '2.5.29.19'
} as const

const HASH: Record<string, string> = {
  [OID.sha256WithRSA]: 'SHA-256', [OID.sha384WithRSA]: 'SHA-384', [OID.sha512WithRSA]: 'SHA-512',
  [OID.ecdsaSHA256]: 'SHA-256', [OID.ecdsaSHA384]: 'SHA-384', [OID.ecdsaSHA512]: 'SHA-512'
}
const CURVES: Record<string, { name: string, bytes: number }> = { [OID.p256]: { name: 'P-256', bytes: 32 }, [OID.p384]: { name: 'P-384', bytes: 48 }, [OID.p521]: { name: 'P-521', bytes: 66 } }

export const parseCertificate = (der: Bytes): Certificate => {
  const cert = sequence(parseDer(der), 'Certificate')
  if (cert.length !== 3) throw new Asn1Error('Certificate: expected 3 fields')
  const tbsNode = cert[0] as Node
  const tbs = sequence(tbsNode, 'tbsCertificate')
  // [0] version is optional; everything after shifts by one when present.
  const offset = contextTag(tbs[0] as Node) === 0 ? 1 : 0
  const validity = sequence(tbs[offset + 3] as Node, 'validity')
  const extensions = new Map<string, Bytes>()
  let isCa: boolean | null = null
  const extNode = tbs.slice(offset + 6).find((n) => contextTag(n) === 3)
  if (extNode) {
    for (const ext of sequence(explicitContent(extNode, 'extensions'), 'extensions')) {
      const f = sequence(ext, 'Extension')
      const id = oid(f[0] as Node, 'extnID')
      const value = octets(f[f.length - 1] as Node, 'extnValue')
      extensions.set(id, value)
      if (id === OID.basicConstraints) {
        const bc = sequence(parseDer(value), 'BasicConstraints')
        isCa = bc[0] instanceof asn1js.Boolean ? bc[0].valueBlock.value : false
      }
    }
  }
  return {
    der,
    tbs: derOf(tbsNode),
    serialHex: integerHex(tbs[offset] as Node, 'serialNumber'),
    issuer: derOf(tbs[offset + 2] as Node),
    subject: derOf(tbs[offset + 4] as Node),
    notBefore: time(validity[0] as Node, 'notBefore'),
    notAfter: time(validity[1] as Node, 'notAfter'),
    spki: derOf(tbs[offset + 5] as Node),
    signatureAlgorithm: oid(sequence(cert[1] as Node, 'signatureAlgorithm')[0] as Node, 'signatureAlgorithm'),
    signature: bitStringBytes(cert[2] as Node, 'signature'),
    extensions,
    isCa
  }
}

export interface PublicKey { key: CryptoKey, kind: 'rsa' | 'ec', curveBytes?: number }

/** Imports an SPKI for signature verification with the algorithm implied by the certificate that signed with it. */
export const importForVerify = async (spki: Bytes, hash: string): Promise<PublicKey | null> => {
  const algId = sequence(sequence(parseDer(spki), 'SPKI')[0] as Node, 'algorithm')
  const algo = oid(algId[0] as Node, 'algorithm')
  try {
    if (algo === OID.rsaEncryption) {
      return { key: await subtle().importKey('spki', owned(spki), { name: 'RSASSA-PKCS1-v1_5', hash }, true, ['verify']), kind: 'rsa' }
    }
    if (algo === OID.ecPublicKey) {
      const curve = CURVES[oid(algId[1] as Node, 'namedCurve')]
      if (!curve) return null
      return { key: await subtle().importKey('spki', owned(spki), { name: 'ECDSA', namedCurve: curve.name }, true, ['verify']), kind: 'ec', curveBytes: curve.bytes }
    }
  } catch { return null }
  return null
}

// DER ECDSA-Sig-Value → r ‖ s, each left-padded to the curve size.
export const derToP1363 = (der: Bytes, size: number): Bytes | null => {
  try {
    const [r, s] = sequence(parseDer(der), 'ECDSA-Sig-Value')
    const fix = (n: Node): Bytes => {
      const raw = new Uint8Array((n as asn1js.Integer).valueBlock.valueHexView)
      const stripped = raw.length > size ? raw.subarray(raw.length - size) : raw
      const out = new Uint8Array(size); out.set(stripped, size - stripped.length); return out
    }
    return concat(fix(r as Node), fix(s as Node))
  } catch { return null }
}

/** Verifies `signature` (as the algorithm OID says it is encoded) over `message` with a public key. */
export const verifyWith = async (pub: PublicKey, algorithmOid: string, message: Bytes, signature: Bytes): Promise<boolean> => {
  const hash = HASH[algorithmOid]
  if (!hash) return false
  try {
    if (pub.kind === 'rsa') return await subtle().verify({ name: 'RSASSA-PKCS1-v1_5' }, pub.key, owned(signature), owned(message))
    const p1363 = derToP1363(signature, pub.curveBytes as number)
    return p1363 !== null && await subtle().verify({ name: 'ECDSA', hash }, pub.key, owned(p1363), owned(message))
  } catch { return false }
}

export const hashOf = (algorithmOid: string): string | null => HASH[algorithmOid] ?? null

/** `subject` was issued by `issuer`: names match and the signature verifies. */
export const issuedBy = async (subject: Certificate, issuer: Certificate): Promise<boolean> => {
  if (!equal(subject.issuer, issuer.subject)) return false
  const hash = HASH[subject.signatureAlgorithm]
  if (!hash) return false
  const pub = await importForVerify(issuer.spki, hash)
  return pub !== null && await verifyWith(pub, subject.signatureAlgorithm, subject.tbs, subject.signature)
}

/**
 * Walks from `leaf` through `pool` to one of `roots`. Returns the chain (leaf
 * first, root last) or null. The root is pinned: it is never taken from the pool.
 */
export const chainToRoot = async (leaf: Certificate, pool: Certificate[], roots: Certificate[]): Promise<Certificate[] | null> => {
  const chain = [leaf]
  let current = leaf
  for (let hop = 0; hop < 8; hop++) {
    for (const root of roots) if (equal(current.der, root.der) || await issuedBy(current, root)) return equal(current.der, root.der) ? chain : [...chain, root]
    const next = await (async () => { for (const c of pool) if (!chain.includes(c) && await issuedBy(current, c)) return c; return null })()
    if (!next) return null
    chain.push(next); current = next
  }
  return null
}

export const withinValidity = (cert: Certificate, now: Date): boolean => cert.notBefore <= now && now <= cert.notAfter

export const pemToDer = (pem: string): Bytes => {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
  const bin = atob(b64)
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}
