import type { WatermarkEvidence } from 'vcap-verify-core'

/**
 * A detection someone else's detector already produced — the `watermark` block
 * of a `/v1/verify` response, or the file `vcap-verify --watermark` takes.
 * Today this is the only source of a detection a browser has, and it is in the
 * bundle rather than in `detector.ts` for one reason: it must work offline,
 * and the detector module deliberately is not cached.
 *
 * It is read as data and never as a verdict. A detection carrying its own
 * `outcome` is ignored by the core, which compares the reported payload
 * against the ids the device signed itself. Nothing signs a detection
 * (decision D18), so this is worth exactly what the hand that dropped it is
 * worth — which is what it was worth anyway, since the same hand dropped the
 * media bytes.
 */
export const readEvidence = (text: string): WatermarkEvidence => {
  const parsed: unknown = JSON.parse(text)
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('a detection is a JSON object')
  }
  // A `/v1/verify` response carries the block under `watermark`; a bare block
  // is accepted too, so either file works without the user being told which.
  const record = parsed as Record<string, unknown>
  const inner = record.watermark
  return (typeof inner === 'object' && inner !== null && !Array.isArray(inner) ? inner : record) as WatermarkEvidence
}
