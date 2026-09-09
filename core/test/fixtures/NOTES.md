# Test fixtures

## moto-g75-android16.json

Android key attestation chain minted by real hardware (moto g75 5G, Android 16,
KeyMint 300, TEE, Remote Key Provisioning), dumped by `SDK-Android/tools/attest-dump`.

## sealed.mp4, sealed-hevc.mp4 (+ `*-segments.json`)

Sealed by real hardware, not generated: Samsung SM-S908B (Exynos 2200),
Android 16, StrongBox keys, 640x360, one-second GOPs, three segments each,
produced by SDK-Android's `VideoPipelineOnDeviceTest`.

- `sealed.mp4` — H.264 + AAC audio. Carries the empty edit list `MediaMuxer`
  writes when the microphone opens before the camera (473 ms on the video
  track) and 23 audio frames that precede the first IDR, so it is the file that
  fails if §5's presentation-timeline rule is ignored.
- `sealed-hevc.mp4` — HEVC, no audio track.

`*-segments.json` is the device's own record of what it signed (`capture_id`,
`pub`, `segment_count`, `segments[]`): the hashes in it are the acceptance
criterion for container recomputation, and they were never recomputed by this
repository's code.
