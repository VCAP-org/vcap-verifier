import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { validateAndroidAttestation } from '../src/attestation/android.js'

// A chain minted by real hardware (SDK-Android/tools/attest-dump): moto g75 5G,
// Android 16, KeyMint 300, TEE, Remote Key Provisioning — five certificates
// down to the pinned 2025 Google root. The clock is pinned to capture time:
// the per-device RKP intermediate lives twelve days.
interface Fixture { captured_at: string, chain: string[], public_key: string }
const fixture: Fixture = JSON.parse(readFileSync(new URL('./fixtures/moto-g75-android16.json', import.meta.url), 'utf8'))
const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
const chain = fixture.chain.map(b64)
const spki = b64(fixture.public_key)
const capturedAt = new Date(fixture.captured_at)

describe('real device chain (moto g75 5G, Android 16, RKP, TEE)', () => {
  it('proves tee with verified boot against the pinned Google roots', async () => {
    const r = await validateAndroidAttestation(chain, spki, { now: capturedAt, revocation: async () => null })
    expect(r.checks.filter((c) => c.outcome !== 'pass')).toEqual([])
    expect(r.proven).toBe('tee')
    expect(r.bootState).toEqual({ locked: true, state: 'verified' })
    expect(r.revocation).toBe('clear')
  })

  it('still proves tee a month later, and reports since when the chain has been expired', async () => {
    // §7: the path is validated at the proven instant of the capture, and the
    // verifier's own clock only tells the caller that the chain has lapsed
    // since. This is the case that would otherwise rot on its own: the
    // intermediate in this fixture expires on 18 September 2026, so a suite
    // that validated at `new Date()` would start failing on the 19th without
    // anyone touching the code.
    const r = await validateAndroidAttestation(chain, spki, { now: capturedAt, clock: new Date(capturedAt.getTime() + 30 * 86_400_000), revocation: async () => null })
    expect(r.proven).toBe('tee')
    expect(r.expiredSince).toBe('2026-09-18T04:58:41.000Z')
  })

  it('proves nothing when the instant itself is after the intermediate expired', async () => {
    const r = await validateAndroidAttestation(chain, spki, { now: new Date(capturedAt.getTime() + 30 * 86_400_000) })
    expect(r.checks.find((c) => c.id === 'chain_validity')?.outcome).toBe('fail')
    expect(r.proven).toBe('none')
  })
})
