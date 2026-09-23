import { describe, expect, it } from 'vitest'
import type { Verdict, WatermarkOutcome } from 'vcap-verify-core'
import { bareMark, card, trace } from '../src/render.js'
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

  it('carries the count into the origin-traced block, where no signature holds', () => {
    const html = trace(matched(1))
    expect(html).toContain('This is not a verdict of authenticity')
    expect(html).toContain('1 of the 8 frames sampled across the clip')
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
    const refused: WatermarkOutcome = {
      result: 'not_recovered',
      detail: 'a mark may be present and its id is not resolvable',
      layout: 'video-rep-v1',
      agreement: 0.7,
      frames_sampled: VIDEO_FRAMES,
      id_refused: true
    }
    expect(trace(refused)).toContain(`past ${VIDEO_FRAMES} the measurements show no further gain`)
  })
})
