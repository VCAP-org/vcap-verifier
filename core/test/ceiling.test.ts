import { describe, expect, it } from 'vitest'
import { ceilingLabels } from '../src/index.js'
import { corpus } from './corpus.js'
import { vectorVerdict } from './vector-verdict.js'

/**
 * The labels that name the §7 light. `ceilingLabels` decides nothing, so what
 * is tested is that it explains the ceiling `verify` already set — on the
 * vectors, which pin that ceiling, and never on a verdict built by hand.
 */
describe('the labels that set the verdict ceiling', () => {
  it('names the hardware a green verdict was sealed in (vector 100)', async () => {
    const v = await vectorVerdict('100-jpeg-registry-green-timestamped')
    expect(v.level?.ceiling).toBe('green')
    expect(ceilingLabels(v)).toEqual(['sealed in the TEE'])
  })

  it('names the device clock and the unproven device as what keep vector 54 amber', async () => {
    const v = await vectorVerdict('54-jpeg-registry-green')
    expect(v.level?.ceiling).toBe('amber')
    expect(ceilingLabels(v)).toEqual(['integrity not proven', 'no trusted time'])
  })

  // Vector 100 without its integrity statement: stripping evidence must not
  // make a verdict greener, so the missing half is what keeps it amber.
  it('names the unproven device as the one thing keeping vector 148 amber', async () => {
    const v = await vectorVerdict('148-jpeg-registry-timestamped-integrity-absent')
    expect(v.level?.ceiling).toBe('amber')
    expect(ceilingLabels(v)).toEqual(['integrity not proven'])
  })

  it('names what green proved on vector 100', async () => {
    const v = await vectorVerdict('100-jpeg-registry-green-timestamped')
    expect(v.level?.ceiling).toBe('green')
    expect(ceilingLabels(v)).toEqual(['sealed in the TEE'])
  })

  it('names a session key and a key outside the log as amber (vector 01)', async () => {
    const v = await vectorVerdict('01-jpeg-sealed')
    expect(v.level?.ceiling).toBe('amber')
    expect(ceilingLabels(v)).toEqual(['origin not hardware-attested', 'key not in transparency log', 'no trusted time'])
  })

  it('names the unasked revocation as amber when the key is in the log (vector 49)', async () => {
    const v = await vectorVerdict('49-jpeg-registry-verified')
    expect(v.level?.ceiling).toBe('amber')
    expect(ceilingLabels(v)).toContain('revocation not checked')
    expect(ceilingLabels(v)).not.toContain('key not in transparency log')
  })

  it('names only the revocation on a red verdict (vector 44)', async () => {
    const v = await vectorVerdict('44-jpeg-attestation-revoked-before-capture')
    expect(v.level?.ceiling).toBe('red')
    // `key not in transparency log` is on the verdict too; it is not why it is red.
    expect(ceilingLabels(v)).toEqual(['attestation key revoked'])
  })

  it('has nothing to name for a verdict that never reached the level (vector 11)', async () => {
    const v = await vectorVerdict('11-jpeg-pixels-edited')
    expect(v.outcome).toBe('tampered')
    expect(ceilingLabels(v)).toEqual([])
  })

  // verify caps an authentic video whose presentation differs at amber, so the
  // label must be named beside the colour it set.
  it('names a differing presentation as amber (vector 163)', async () => {
    const v = await vectorVerdict('163-mp4-presentation-original-misdescribed')
    expect(v.outcome).toBe('authentic')
    expect(v.level?.ceiling).toBe('amber')
    expect(ceilingLabels(v)).toContain('presentation differs')
  })

  // The same for an original whose signed timing root its own segments do
  // not reproduce (§5 *Timing*).
  it('names a differing timing as amber (vector 185)', async () => {
    const v = await vectorVerdict('185-mp4-timing-original-misdescribed')
    expect(v.outcome).toBe('authentic')
    expect(v.level?.ceiling).toBe('amber')
    expect(ceilingLabels(v)).toContain('timing differs')
  })

  // The drift check: a label `verify` starts capping on and this list does not
  // know would leave an authentic amber or red verdict with no reason beside
  // its colour. Every such verdict in the corpus has to be explained.
  it('explains every authentic verdict below green in the corpus', async () => {
    const { names, kinds } = corpus()
    const files = names.filter((n) => kinds[n] === 'file' || kinds[n] === 'container')
    expect(files.length).toBeGreaterThan(0)
    for (const name of files) {
      const v = await vectorVerdict(name)
      if (v.outcome === 'authentic' && v.level) expect(ceilingLabels(v), name).not.toEqual([])
    }
  })
})
