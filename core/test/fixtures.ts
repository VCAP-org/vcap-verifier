import 'reflect-metadata'
import * as x509 from '@peculiar/x509'
import * as asn1js from 'asn1js'
import { subtle } from '../src/sha.js'

// Test-side certificate and CMS builders: a fake TSA and a synthetic Android
// attestation chain, so the verifier's chain, extension and CMS logic is
// exercised without a live TSA or a device. WebCrypto keys, DER via asn1js.

x509.cryptoProvider.set(globalThis.crypto)

const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const
export const genKey = () => subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])

export interface Issued { der: Uint8Array, keys: CryptoKeyPair, cert: x509.X509Certificate }

export const issue = async (o: { subject: string, issuer?: Issued, ca?: boolean, extensions?: x509.Extension[], keys?: CryptoKeyPair, notBefore?: Date, notAfter?: Date, serial?: string }): Promise<Issued> => {
  const keys = o.keys ?? await genKey()
  const base = { serialNumber: o.serial ?? Math.floor(Math.random() * 1e9).toString(16).padStart(2, '0'), notBefore: o.notBefore ?? new Date(Date.now() - 86_400_000), notAfter: o.notAfter ?? new Date(Date.now() + 365 * 86_400_000), signingAlgorithm: EC, extensions: [new x509.BasicConstraintsExtension(o.ca ?? false, undefined, true), ...(o.extensions ?? [])] }
  const cert = o.issuer
    ? await x509.X509CertificateGenerator.create({ ...base, subject: o.subject, issuer: o.issuer.cert.subject, publicKey: keys.publicKey, signingKey: o.issuer.keys.privateKey })
    : await x509.X509CertificateGenerator.createSelfSigned({ ...base, name: o.subject, keys })
  return { der: new Uint8Array(cert.rawData), keys, cert }
}

const oid = (v: string) => new asn1js.ObjectIdentifier({ value: v })
const seq = (...value: asn1js.AsnType[]) => new asn1js.Sequence({ value })
const octets = (b: Uint8Array) => new asn1js.OctetString({ valueHex: Uint8Array.from(b).buffer })
const der = (n: asn1js.AsnType) => new Uint8Array(n.toBER(false))
const ctx = (tag: number, ...value: asn1js.AsnType[]) => new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: tag }, value })
const spkiOf = async (k: CryptoKey) => new Uint8Array(await subtle().exportKey('spki', k))

export const tsaSigner = async (): Promise<{ root: Issued, signer: Issued }> => {
  const root = await issue({ subject: 'CN=Test TSA Root', ca: true })
  const signer = await issue({ subject: 'CN=Test TSA', issuer: root, extensions: [new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.8'], true)] })
  return { root, signer }
}

/** RFC 3161 TimeStampToken (CMS SignedData over TSTInfo) signed by `signer`, with optional tamper hooks. */
export const timestampToken = async (signer: Issued, imprint: Uint8Array, o: { genTime?: Date, extraCerts?: Issued[], wrongDigest?: boolean, wrongSigner?: CryptoKey } = {}): Promise<Uint8Array> => {
  const tstInfo = der(seq(
    new asn1js.Integer({ value: 1 }), oid('1.2.3.4.1'),
    seq(seq(oid('2.16.840.1.101.3.4.2.1')), octets(imprint)),
    new asn1js.Integer({ value: 42 }), new asn1js.GeneralizedTime({ valueDate: o.genTime ?? new Date() })
  ))
  const digest = new Uint8Array(await subtle().digest('SHA-256', tstInfo))
  if (o.wrongDigest) digest[0] = (digest[0] ?? 0) ^ 1
  const attrs = ctx(0,
    seq(oid('1.2.840.113549.1.9.3'), new asn1js.Set({ value: [oid('1.2.840.113549.1.9.16.1.4')] })),
    seq(oid('1.2.840.113549.1.9.4'), new asn1js.Set({ value: [octets(digest)] }))
  )
  const toSign = der(attrs); toSign[0] = 0x31
  const p1363 = new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, o.wrongSigner ?? signer.keys.privateKey, toSign))
  const int = (b: Uint8Array) => new asn1js.Integer({ valueHex: Uint8Array.from((b[0] ?? 0) & 0x80 ? [0, ...b] : b).buffer })
  const sigDer = der(seq(int(p1363.slice(0, 32)), int(p1363.slice(32))))
  const serial = new asn1js.Integer({ valueHex: Uint8Array.from((signer.cert.serialNumber.match(/../g) ?? []).map((h) => parseInt(h, 16))).buffer })
  const issuerName = asn1js.fromBER(new Uint8Array(new x509.Name(signer.cert.issuer).toArrayBuffer()).buffer).result
  const signerInfo = seq(
    new asn1js.Integer({ value: 1 }),
    seq(issuerName, serial),
    seq(oid('2.16.840.1.101.3.4.2.1')), attrs,
    seq(oid('1.2.840.10045.4.3.2')), octets(sigDer)
  )
  const certs = [signer, ...(o.extraCerts ?? [])].map((c) => asn1js.fromBER(Uint8Array.from(c.der).buffer).result)
  const signedData = seq(
    new asn1js.Integer({ value: 3 }), new asn1js.Set({ value: [seq(oid('2.16.840.1.101.3.4.2.1'))] }),
    seq(oid('1.2.840.113549.1.9.16.1.4'), ctx(0, octets(tstInfo))),
    ctx(0, ...certs), new asn1js.Set({ value: [signerInfo] })
  )
  return der(seq(oid('1.2.840.113549.1.7.2'), ctx(0, signedData)))
}

export type Level = 0 | 1 | 2
/** Android KeyDescription extension (schema v300, only the fields the verifier reads). */
export const keyDescription = (o: { attestation: Level, keyMint: Level, locked?: boolean, bootState?: number, withRot?: boolean }): x509.Extension => {
  const en = (v: number) => new asn1js.Enumerated({ value: v })
  const rot = o.withRot === false ? [] : [ctx(704, seq(octets(new Uint8Array(32)), new asn1js.Boolean({ value: o.locked ?? true }), en(o.bootState ?? 0), octets(new Uint8Array(32))))]
  const body = der(seq(
    new asn1js.Integer({ value: 300 }), en(o.attestation), new asn1js.Integer({ value: 300 }), en(o.keyMint),
    octets(new Uint8Array([1, 2, 3])), octets(new Uint8Array(0)), seq(), seq(...rot)
  ))
  return new x509.Extension('1.3.6.1.4.1.11129.2.1.17', false, body)
}

export const androidChain = async (o: { attestation?: Level, keyMint?: Level, locked?: boolean, bootState?: number, withRot?: boolean, leafKeys?: CryptoKeyPair } = {}): Promise<{ root: Issued, chain: Uint8Array[], spki: Uint8Array }> => {
  const root = await issue({ subject: 'CN=Test Android Root', ca: true })
  const inter = await issue({ subject: 'CN=Test Android Intermediate', issuer: root, ca: true })
  const leaf = await issue({ subject: 'CN=Android Keystore Key', issuer: inter, keys: o.leafKeys, extensions: [keyDescription({ attestation: o.attestation ?? 1, keyMint: o.keyMint ?? 1, locked: o.locked, bootState: o.bootState, withRot: o.withRot })] })
  return { root, chain: [leaf.der, inter.der, root.der], spki: await spkiOf(leaf.keys.publicKey) }
}
