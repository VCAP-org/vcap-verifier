import { describe, expect, it } from 'vitest'
import { toBase64 } from '../src/bytes.js'
import { vaultKeyMessage, verifyVaultKey } from '../src/index.js'
import { logId, sign, trusted } from './log.js'

/**
 * The log's statement about an organization's vault key.
 *
 * Not part of a proof and never part of a verdict: what is under test is the
 * one thing it claims — **this log recorded this key at this index** — and the
 * three ways a caller could believe more than that.
 */
describe('a vault key statement', async () => {
  const keyIdHex = 'a1'.repeat(32)
  const keyId = Uint8Array.from((keyIdHex.match(/../g) ?? []).map((b) => parseInt(b, 16)))
  const statement = async (overrides: Record<string, unknown> = {}) => {
    const epoch = (overrides.epoch as number) ?? 1
    const index = (overrides.log_index as number) ?? 41207
    return {
      log_id: logId,
      key_id: keyIdHex,
      epoch,
      log_index: index,
      signature: toBase64(await sign(vaultKeyMessage(keyId, epoch, index))),
      ...overrides
    }
  }

  it('verifies what the log signed, and says what it verified', async () => {
    expect(await verifyVaultKey(await statement(), trusted)).toEqual({ ok: true, logId, epoch: 1, logIndex: 41207 })
  })

  // The message is fixed-length and binds all three: a statement about epoch 1
  // is not a statement about epoch 2, and neither is one about another index.
  it('does not carry over to another epoch, another index or another key', async () => {
    const signed = await statement()

    expect(await verifyVaultKey({ ...signed, epoch: 2 }, trusted)).toMatchObject({ ok: false, reason: 'statement signature invalid' })
    expect(await verifyVaultKey({ ...signed, log_index: 41208 }, trusted)).toMatchObject({ ok: false, reason: 'statement signature invalid' })
    expect(await verifyVaultKey({ ...signed, key_id: 'b2'.repeat(32) }, trusted)).toMatchObject({ ok: false, reason: 'statement signature invalid' })
  })

  // A log outside the trust set is **absent** evidence, not failed evidence.
  // A caller that treated "I cannot check this" as "this is wrong" would
  // refuse keys for the only reason that is not the key's fault.
  it('separates a log it does not trust from a signature that does not hold', async () => {
    const signed = await statement()

    expect(await verifyVaultKey({ ...signed, log_id: 'not-a-log-we-carry' }, trusted)).toMatchObject({ ok: false, reason: 'log not trusted' })
    expect(await verifyVaultKey({ ...signed, signature: toBase64(new Uint8Array(64)) }, trusted)).toMatchObject({ ok: false, reason: 'statement signature invalid' })
  })

  it('refuses a malformed key id, epoch or index before it asks the trust set', async () => {
    const signed = await statement()

    expect(await verifyVaultKey({ ...signed, key_id: 'short' }, [])).toMatchObject({ ok: false, reason: 'key_id is not a 32-byte hash' })
    expect(await verifyVaultKey({ ...signed, epoch: 0 }, [])).toMatchObject({ ok: false, reason: 'epoch is not a positive integer' })
    expect(await verifyVaultKey({ ...signed, log_index: -1 }, [])).toMatchObject({ ok: false, reason: 'log_index is not an index' })
  })
})
