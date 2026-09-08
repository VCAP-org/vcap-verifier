import * as asn1js from 'asn1js'
import type { Bytes } from './bytes.js'

/**
 * The few DER operations the verifier needs, over asn1js (browser and Node),
 * with the shape checks asn1js leaves to the caller. Every helper throws
 * `Asn1Error` on a structure that is not what the schema says; callers turn
 * that into a failed check, never into a crash.
 */
export class Asn1Error extends Error {}
export type Node = asn1js.AsnType

export const parseDer = (der: Bytes): Node => {
  const { offset, result } = asn1js.fromBER(Uint8Array.from(der).buffer)
  if (offset === -1) throw new Asn1Error('malformed DER')
  return result
}

const isConstructed = (n: Node): n is asn1js.Constructed | asn1js.Sequence | asn1js.Set =>
  n instanceof asn1js.Constructed || n instanceof asn1js.Sequence || n instanceof asn1js.Set

export const children = (n: Node, what: string): Node[] => {
  if (!isConstructed(n)) throw new Asn1Error(`${what}: expected a constructed value`)
  return n.valueBlock.value as Node[]
}
export const sequence = (n: Node, what: string): Node[] => {
  if (!(n instanceof asn1js.Sequence)) throw new Asn1Error(`${what}: expected SEQUENCE`)
  return n.valueBlock.value as Node[]
}
export const set = (n: Node, what: string): Node[] => {
  if (!(n instanceof asn1js.Set)) throw new Asn1Error(`${what}: expected SET`)
  return n.valueBlock.value as Node[]
}
export const integer = (n: Node, what: string): number => {
  if (!(n instanceof asn1js.Integer)) throw new Asn1Error(`${what}: expected INTEGER`)
  const v = n.toBigInt()
  if (v > BigInt(Number.MAX_SAFE_INTEGER) || v < BigInt(Number.MIN_SAFE_INTEGER)) throw new Asn1Error(`${what}: integer out of range`)
  return Number(v)
}
// Identifiers (serials) as unsigned bytes without leading zeros.
export const integerHex = (n: Node, what: string): string => {
  if (!(n instanceof asn1js.Integer)) throw new Asn1Error(`${what}: expected INTEGER`)
  return Array.from(new Uint8Array(n.valueBlock.valueHexView), (b) => b.toString(16).padStart(2, '0')).join('').replace(/^0+(?=.)/, '')
}
export const enumerated = (n: Node, what: string): number => {
  if (!(n instanceof asn1js.Enumerated)) throw new Asn1Error(`${what}: expected ENUMERATED`)
  return n.valueBlock.valueDec
}
export const boolean = (n: Node, what: string): boolean => {
  if (!(n instanceof asn1js.Boolean)) throw new Asn1Error(`${what}: expected BOOLEAN`)
  return n.valueBlock.value
}
export const octets = (n: Node, what: string): Bytes => {
  if (!(n instanceof asn1js.OctetString)) throw new Asn1Error(`${what}: expected OCTET STRING`)
  return new Uint8Array(n.valueBlock.valueHexView)
}
export const bitStringBytes = (n: Node, what: string): Bytes => {
  if (!(n instanceof asn1js.BitString)) throw new Asn1Error(`${what}: expected BIT STRING`)
  return new Uint8Array(n.valueBlock.valueHexView)
}
export const oid = (n: Node, what: string): string => {
  if (!(n instanceof asn1js.ObjectIdentifier)) throw new Asn1Error(`${what}: expected OBJECT IDENTIFIER`)
  return n.valueBlock.toString()
}
export const time = (n: Node, what: string): Date => {
  if (n instanceof asn1js.UTCTime || n instanceof asn1js.GeneralizedTime) return n.toDate()
  throw new Asn1Error(`${what}: expected a time`)
}
export const contextTag = (n: Node): number | null => (n.idBlock.tagClass === 3 ? n.idBlock.tagNumber : null)
export const explicitContent = (n: Node, what: string): Node => {
  const inner = children(n, what)
  if (inner.length !== 1 || !inner[0]) throw new Asn1Error(`${what}: EXPLICIT tag must wrap one value`)
  return inner[0]
}
export const derOf = (n: Node): Bytes => new Uint8Array(n.toBER())
