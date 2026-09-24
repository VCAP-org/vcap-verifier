import { describe, expect, it } from 'vitest'
import type { Verdict, WatermarkOutcome } from 'vcap-verify-core'
import { bareMark, card, colour, errorCard, markOffer } from '../src/render.js'
import { vectorVerdict } from '../../core/test/vector-verdict.js'
import { VIDEO_FRAMES } from '../src/sampling.js'

/**
 * What the page says about how much of a clip carried the mark.
 *
 * The core writes the §8 sentence — "n of m sampled frames carry it" — and it
 * is correct and unreadable to the person this page exists for. These are the
 * lines beside it, and what they must never do: read "1 of 8" and "8 of 8" the
 * same way, or turn "0 of 8" into an accusation. Zero is what a genuine clip
 * the codec hit hard looks like on the build this page ships, where the
 * hardest surviving chain clears the floor over eight frames and not over one
 * (an internal measurement).
 */
const matched = (framesWithId?: number): WatermarkOutcome => ({
  result: 'matched',
  detail: 'the payload carries the declared mark id',
  layout: 'video-rep-v1',
  declared: '5902900',
  decoded: '5902900',
  agreement: 0.996,
  frames_sampled: 8,
  ...(framesWithId === undefined ? {} : { frames_with_id: framesWithId })
})

const clip = (watermark: WatermarkOutcome): Verdict =>
  ({ outcome: 'verified_clip', labels: [], not_evaluated: [], watermark })

describe('how much of the clip carried the mark', () => {
  it('reads one of eight as a piece of that capture inside other footage', () => {
    const html = card('clip.mp4', clip(matched(1)))
    expect(html).toContain('1 of the 8 frames sampled across the clip carry the mark on their own')
    expect(html).toContain('cut into it')
    // Above the technical disclosure, not inside it.
    expect(html.indexOf('class="carried"')).toBeLessThan(html.indexOf('<details'))
  })

  it('reads eight of eight as a mark that runs through the clip', () => {
    const html = card('clip.mp4', clip(matched(8)))
    expect(html).toContain('All 8 frames sampled across the clip carry the mark on their own')
    expect(html).not.toContain('cut into it')
  })

  /**
   * The count a page must not read as a splice: no frame resolved alone, the
   * clip did. Saying so is the difference between a limitation and an
   * accusation.
   */
  it('reads zero of eight as re-compression, never as a splice', () => {
    const html = card('clip.mp4', clip(matched(0)))
    expect(html).toContain('The mark is there')
    expect(html).toContain('8 sampled frames read together resolve it')
    expect(html).toContain('not how much of the file carries it')
    expect(html).not.toContain('cut into it')
  })

  it('says nothing about frames when the detector did not count them', () => {
    expect(card('clip.mp4', clip(matched()))).not.toContain('class="carried"')
  })

  /** A count belongs next to a reported id and nowhere else. */
  it('never prints a count beside an outcome that named no id', () => {
    const refused: WatermarkOutcome = {
      result: 'not_recovered',
      detail: 'a mark may be present and its id is not resolvable',
      layout: 'video-rep-v1',
      agreement: 0.7,
      frames_sampled: 8,
      frames_with_id: 0,
      id_refused: true
    }
    expect(card('clip.mp4', clip(refused))).not.toContain('class="carried"')
  })

  it('carries it into a mark read out of a file with no proof at all', () => {
    const html = bareMark({ layout: 'video-rep-v1', decoded: '5902900', frames_sampled: 8, frames_with_id: 1 }, 'https://example.test/trace')
    expect(html).toContain('1 of the 8 frames sampled across the clip')
  })
})

/**
 * The page explains a refusal by the count it actually samples at. Two
 * constants with one measurement behind them drift; this is the assertion that
 * keeps the sentence and the policy the same number, here and in the surfaces
 * that vendor these sources.
 */
describe('the sampling policy the page explains itself with', () => {
  it('is the one the detector samples at', () => {
    expect(VIDEO_FRAMES).toBe(8)
    const refused = bareMark({ layout: 'video-rep-v1', frames_sampled: VIDEO_FRAMES, id_refused: true }, 'https://example.test/trace')
    expect(refused).toContain(`past ${VIDEO_FRAMES} the measurements show no further gain`)
  })
})

/**
 * The card's light is §7's ceiling, not the outcome: an *authentic* file whose
 * key is a session key, or outside the log, is amber and never green (§7).
 * Every case is a corpus vector verified as the conformance runner does, so
 * the page is tested on the verdict the corpus pins.
 */
describe('the verdict colour follows the §7 ceiling', () => {
  const lede = (html: string): string => /<p class="lede">([^<]*)<\/p>/.exec(html)?.[1] ?? ''
  const ceiling = (html: string): string => (/<p class="ceiling">(.*?)<\/p>/.exec(html)?.[1] ?? '').replace(/<[^>]+>/g, '')

  it('is green only when the ceiling is green (vector 100: registered TEE key, timestamped)', async () => {
    const v = await vectorVerdict('100-jpeg-registry-green-timestamped')
    const html = card('photo.jpg', v)
    expect(colour(v)).toBe('green')
    expect(html).toContain('<div class="verdict green">')
    expect(lede(html)).toBe('Yes — this file is what it says it is.')
    expect(ceiling(html)).toBe('green sealed in the TEE')
  })

  it('is amber for a session key outside the log, and says so beside the title (vector 01)', async () => {
    const v = await vectorVerdict('01-jpeg-sealed')
    const html = card('photo.jpg', v)
    expect(v.outcome).toBe('authentic')
    expect(html).toContain('<div class="verdict amber">')
    // §8's title unchanged; the plain line no longer says "Yes".
    expect(html).toContain('Authentic</span><span class="rest"> — signed at capture, file complete')
    expect(lede(html)).toMatch(/^Intact, not fully proven — /)
    expect(ceiling(html)).toBe('amber origin not hardware-attested · key not in transparency log · no trusted time')
    // The chips stay: the ceiling line adds, it does not replace.
    expect(html).toContain('<li>no trusted time</li>')
  })

  it('is amber when the key is in the log and its revocation was not asked (vector 49)', async () => {
    const v = await vectorVerdict('49-jpeg-registry-verified')
    const html = card('photo.jpg', v)
    expect(html).toContain('<div class="verdict amber">')
    expect(ceiling(html)).toContain('revocation not checked')
  })

  it('is red for a revoked attestation key, on an authentic outcome (vector 44)', async () => {
    const v = await vectorVerdict('44-jpeg-attestation-revoked-before-capture')
    const html = card('photo.jpg', v)
    expect(v.outcome).toBe('authentic')
    expect(html).toContain('<div class="verdict red">')
    expect(lede(html)).toMatch(/^Do not rely on it — /)
    expect(ceiling(html)).toBe('red attestation key revoked')
  })

  it('keeps a tampered file red with no ceiling line (vector 11)', async () => {
    const v = await vectorVerdict('11-jpeg-pixels-edited')
    const html = card('photo.jpg', v)
    expect(html).toContain('<div class="verdict red">')
    expect(lede(html)).toBe('No — this file changed after it was sealed.')
    expect(html).not.toContain('class="ceiling"')
  })

  it('never paints a clip greener than its outcome, nor greener than the ceiling', () => {
    const base = { labels: [], not_evaluated: [] }
    expect(colour({ ...base, outcome: 'verified_clip', level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' } })).toBe('amber')
    expect(colour({ ...base, outcome: 'verified_clip', level: { claimed: 'tee', proven: 'none', ceiling: 'red' } })).toBe('red')
    expect(colour({ ...base, outcome: 'no_proof_found' })).toBe('grey')
    expect(colour({ ...base, outcome: 'corrupted_proof' })).toBe('red')
  })
})

describe('which labels are limits', () => {
  it('lists a matched watermark as checked, never under what the verdict does not cover', () => {
    const html = card('photo.jpg', { outcome: 'authentic', labels: ['watermark matched', 'revocation not checked'], not_evaluated: [] } as unknown as Verdict)
    const limits = html.slice(html.indexOf('What this verdict does not cover'))
    const checked = html.slice(html.indexOf('Also checked'), html.indexOf('What this verdict does not cover'))
    expect(checked).toContain('<li>watermark matched</li>')
    expect(limits).toContain('<li>revocation not checked</li>')
    expect(limits).not.toContain('watermark matched')
  })
})

describe('the headline of a clip says only what was compared', () => {
  const base: Verdict = { outcome: 'verified_clip', labels: [], not_evaluated: [], segments: { verified: [1, 2] } }

  it('says "signed frames" when the frames were read back from the file', () => {
    const html = card('clip.mp4', { ...base, content: { recomputed: true, detail: '2 GOPs read from the container' } })
    expect(html).toContain('In part — these are signed frames of a longer recording.')
  })

  it('does not, when the segment hashes came out of the proof alone', () => {
    const html = card('clip.mp4', { ...base, content: { recomputed: false, detail: 'recomputation not requested' } })
    expect(html).not.toContain('these are signed frames')
    expect(html).toContain('their frames were not compared with this file')
  })

  it('reads frames not compared as amber, never as a clip', () => {
    const v: Verdict = { outcome: 'frames_not_compared', labels: [], not_evaluated: [], segments: { verified: [] }, level: { claimed: 'tee', proven: 'none', ceiling: 'amber' } }
    expect(colour(v)).toBe('amber')
    expect(card('clip.mp4', v)).toContain('Frames not compared')
  })
})

describe('every line of evidence says where it comes from', () => {
  const v: Verdict = {
    outcome: 'authentic',
    labels: [],
    not_evaluated: [],
    core_hash: 'ab'.repeat(32),
    claimed_secure_hw: 'tee',
    level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
    attestation: { proven: 'tee', detail: 'chain to a pinned Google root', boot_state: { locked: true, state: 'verified' } },
    registry: { ok: true, detail: 'key in the transparency log before tree head', secure_hw: 'tee' },
    timestamp: { ok: true, detail: 'existed before 2026-09-08T12:00:00.000Z', gen_time: '2026-09-08T12:00:00.000Z' },
    integrity: { ok: true, detail: 'playIntegrity reported hardware', verdict: 'hardware' },
    key_status: { ok: false, detail: 'no log lookup available' },
    anchor: { ok: true, detail: 'anchored on base-sepolia, block 42', on_chain: true },
    validated_at: { instant: '2026-09-08T12:00:00.000Z', source: 'timestamp' },
    mark_id: { value: 5902900, derived: false }
  }
  const html = card('photo.jpg', v)
  const row = (key: string): string => {
    const at = html.indexOf(`<dt>${key}</dt>`)
    expect(at, key).toBeGreaterThan(-1)
    return html.slice(at, html.indexOf('</dd>', at))
  }

  it('renders the proven level, the attestation with its boot state, the timestamp and the integrity statement', () => {
    expect(row('proven level')).toContain('<code>tee</code>')
    expect(row('attestation')).toContain('boot verified, device locked')
    expect(row('trusted time')).toContain('existed before 2026-09-08')
    expect(row('device integrity')).toContain('playIntegrity reported hardware')
  })

  it('names the source of each in words', () => {
    expect(row('attestation')).toContain('from the file alone')
    expect(row('transparency log')).toContain('VCAP transparency log key')
    expect(row('device integrity')).toContain('VCAP transparency log key')
    expect(row('trusted time')).toContain('third-party timestamp authority')
    expect(row('validated at')).toContain('third-party timestamp authority')
    expect(row('anchor')).toContain('public chain via RPC')
    expect(row('key revocation')).toContain('VCAP online lookup')
    expect(html).toContain('our own records, not independent')
  })

  it('no longer says the attestation is not evaluated', () => {
    expect(html).not.toContain('attestation not evaluated by this page')
    expect(row('claimed level')).toContain('the device\'s own claim')
  })

  it('says when a mark id is not the one derived from the capture id', () => {
    expect(row('mark id')).toContain('will not find this capture')
  })

  it('shows the signature verdict while the watermark is still being read', () => {
    const pending = card('photo.jpg', { ...v, labels: ['watermark not evaluated'] }, { watermarkPending: true })
    expect(pending).toContain('being read')
    expect(pending).not.toContain('<li>watermark not evaluated</li>')
  })
})

describe('the words around a verdict that is not the plain one', () => {
  it('says a proof it cannot read is not the same as no proof', () => {
    expect(card('x.jpg', { outcome: 'no_proof_found', labels: [], not_evaluated: [], reason: 'payload is not a JSON object' })).toContain('carries no proof this page can read')
    expect(card('x.jpg', { outcome: 'no_proof_found', labels: [], not_evaluated: [], reason: 'no trailer and no sidecar' })).toContain('This file carries no proof.')
  })

  it('does not tell a clip under a red ceiling that the file is unchanged', () => {
    const html = card('clip.mp4', { outcome: 'verified_clip', labels: ['key revoked'], not_evaluated: [], content: { recomputed: true, detail: '' }, level: { claimed: 'tee', proven: 'tee', ceiling: 'red' } })
    expect(html).toContain('a key behind the seal was revoked')
    expect(html).not.toContain('has not changed since it was sealed')
  })
})

describe('a mark read with no proof', () => {
  it('links a photo payload — the whole capture id — to the registry', () => {
    expect(bareMark({ layout: 'photo-bch-v3', decoded: 'ab'.repeat(16) }, 'https://registry.example/t')).toContain('href="https://registry.example/t/' + 'ab'.repeat(16) + '"')
  })

  it('does not link a clip\'s mark id, which many captures share, and says why', () => {
    const html = bareMark({ layout: 'video-rep-v1', decoded: '5902900', agreement: 0.99 }, 'https://registry.example/t')
    expect(html).not.toContain('href=')
    expect(html).toContain('cannot be looked up on its own')
  })

  it('asks before downloading the detector, and says how much', () => {
    const html = markOffer(62.4)
    expect(html).toContain('about 62 MB')
    expect(html).toContain('id="read-mark"')
  })
})

describe('a check that failed outright', () => {
  it('is a card that says what to do, never a spinner', () => {
    const html = errorCard('big.mov', 'Array buffer allocation failed')
    expect(html).toContain('role="alert"')
    expect(html).toContain('Try the file again')
    expect(html).toContain('vcap-verify')
    expect(html).toContain('Array buffer allocation failed')
  })
})
