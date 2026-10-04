import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { toHex } from '../src/bytes.js'
import { recomputeSegments } from '../src/container.js'
import { sha256 } from '../src/sha.js'
import { convertTiming, editTrims, timingRecord, timingRoot } from '../src/timing.js'

// §5 *Timing*, pinned at the byte level, as vcap-spec's reference test pins
// it: the record layout, the exact timescale conversion, and the media-edit
// rule's slack. The last case reads vector 175's container back.
describe('timing(n)', () => {
  it('lays out counts, then fixed-width big-endian values', () => {
    const record = timingRecord({ videoDts: [0n, 3000n], videoCts: [0n, -1n], videoEnd: 6001n, audioDts: [0n], audioDur: [1024n] })
    expect(toHex(record)).toBe([
      '00000002', // v
      '0000000000000000', '0000000000000000', // dts_0 − dts_0, cts_0
      '0000000000000bb8', 'ffffffffffffffff', // dts_1 − dts_0, cts_1 (signed)
      '0000000000001771', // end_n − dts_0
      '00000001', // a
      '0000000000000000', '00000400' // adts_0 − adts_0, adur_0
    ].join(''))
  })

  it('refuses a value that does not fit its field', () => {
    expect(() => timingRecord({ videoDts: [0n], videoCts: [0n], videoEnd: -1n, audioDts: [], audioDur: [] })).toThrow()
    expect(() => timingRecord({ videoDts: [0n], videoCts: [0n], videoEnd: 1n, audioDts: [0n], audioDur: [1n << 32n] })).toThrow()
  })

  it('converts exactly or not at all', () => {
    const t = { videoDts: [0n, 3000n], videoCts: [0n, 0n], videoEnd: 6000n, audioDts: [], audioDur: [] }
    // A finer timescale with every value doubled maps back exactly.
    expect(convertTiming({ ...t, videoDts: [0n, 6000n], videoEnd: 12000n }, { video: 180000n, audio: null }, { video: 90000n, audio: null })).toEqual(t)
    // 3001 ticks at 180 kHz is 1500.5 at 90 kHz: not representable, so it differs.
    expect(convertTiming({ ...t, videoDts: [0n, 3001n] }, { video: 180000n, audio: null }, { video: 90000n, audio: null })).toBeNull()
    // Audio frames with no signed audio timescale cannot be converted.
    expect(convertTiming({ ...t, audioDts: [0n], audioDur: [1024n] }, { video: 90000n, audio: 48000n }, { video: 90000n, audio: null })).toBeNull()
  })

  it('gives a media edit one movie tick of slack at the end, none at the start', () => {
    const edit = { mediaTime: 0n, movieTimescale: 10000n, mediaTimescale: 90000n }
    // 218 178 media ticks are 24 242.0 movie ticks: rounded down, no trim.
    expect(editTrims({ ...edit, duration: 24242n }, { start: 0n, end: 218178n })).toBe(false)
    expect(editTrims({ ...edit, duration: 24241n }, { start: 0n, end: 218178n })).toBe(true)
    expect(editTrims({ ...edit, mediaTime: 1n, duration: 24242n }, { start: 0n, end: 218178n })).toBe(true)
  })

  it('reads back the records vector 175 publishes', async () => {
    const dir = new URL('../vectors/175-mp4-timing-original/', import.meta.url)
    const debug = (JSON.parse(readFileSync(new URL('expected.json', dir), 'utf8')) as { debug: { video_timescale: number, audio_timescale: number, timing_records_hex: string[], root_hex: string } }).debug
    const reading = await recomputeSegments(new Uint8Array(readFileSync(new URL('input.mp4', dir))))
    if (reading.kind !== 'hashes') throw new Error('vector 175 is not a readable video')
    expect(reading.timing.timescales).toEqual({ video: BigInt(debug.video_timescale), audio: BigInt(debug.audio_timescale) })
    const records = [0, 1, 2].map((n) => timingRecord(reading.gops.find((g) => g.index === n)!.timing))
    expect(records.map(toHex)).toEqual(debug.timing_records_hex)
    expect(toHex(await timingRoot(await Promise.all(records.map(async (r) => await sha256(r)))))).toBe(debug.root_hex)
  })
})
