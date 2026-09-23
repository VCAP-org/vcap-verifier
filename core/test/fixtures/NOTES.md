# Test fixtures

## moto-g75-android16.json

Android key attestation chain minted by real hardware (moto g75 5G, Android 16,
KeyMint 300, TEE, Remote Key Provisioning), dumped from the phone with a small key-attestation tool.

## sealed.mp4, sealed-hevc.mp4 (+ `*-segments.json`)

Sealed by real hardware, not generated: Samsung SM-S908B (Exynos 2200),
Android 16, StrongBox keys, 640x360, one-second GOPs, three segments each,
produced by SDK-Android's `VideoPipelineOnDeviceTest`.

- `sealed.mp4` — H.264 + AAC audio. Carries the empty edit list `MediaMuxer`
  writes when the microphone opens before the camera (473 ms on the video
  track) and 23 audio frames that precede the first IDR, so it is the file that
  fails if §5's presentation-timeline rule is ignored.
- `sealed-hevc.mp4` — HEVC, no audio track.

## sealed-padded.mp4 (+ `sealed-padded-segments.json`)

moto g75 5G, Android 16, TEE, 1280x720, three segments, H.264 + AAC, sealed by
SDK-Android's drop-in on 14 September 2026 — the file the other two are missing.
Neither of them, and not one NAL unit of the seven container vectors in
`vcap-spec`, ends in a zero byte: an H.264 encoder pads slices to the level's
minimum size only when a scene is too cheap to code, and a camera pointed at a
room never is. **73 of this file's 83 NAL units end in one to fifteen zeros**,
because it records a mostly static screen, so it is the file that fails if a
reader trims them instead of hashing the length prefix's whole extent (§5, *a
NAL unit is exactly the bytes the container stores for it*). The writer that
trimmed them sealed every recording as `tampered` against its own signature.

Its `-segments.json` is derived from the sidecar the drop-in wrote next to the
file rather than from a `VideoPipelineOnDeviceTest` run, so it carries no `pub`:
that proof's key lives in its attestation chain, and nothing here reads `pub`.

`*-segments.json` is the device's own record of what it signed (`capture_id`,
`pub`, `segment_count`, `segments[]`): the hashes in it are the acceptance
criterion for container recomputation, and they were never recomputed by this
repository's code.
