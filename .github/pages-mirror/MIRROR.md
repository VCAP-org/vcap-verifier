# This is a mirror

If you reached this file from `https://vcap-org.github.io/vcap-verifier/`, you
are on the **mirror**. It is published by
[`.github/workflows/pages-mirror.yml`](https://github.com/VCAP-org/vcap-verifier/blob/main/.github/workflows/pages-mirror.yml)
and it is not the primary.

- **Primary:** https://verify.vcap.gregoriogalante.com/
- **Mirror:** https://vcap-org.github.io/vcap-verifier/

Two hosts exist so that neither has to be believed. They serve the same bytes,
and because the build is reproducible and its manifest is signed, you can check
that yourself rather than take it from this file.

## Check that both hosts serve the same bytes

```sh
diff <(curl -s https://verify.vcap.gregoriogalante.com/hashes.json) \
     <(curl -s https://vcap-org.github.io/vcap-verifier/hashes.json)
```

An empty diff means one manifest, therefore one set of file hashes, on both
hosts. Then check that the files each host actually serves are the ones the
manifest names, and that the manifest was signed:

```sh
curl -sO https://vcap-org.github.io/vcap-verifier/verifier.js
sha256sum verifier.js     # compare with .files["verifier.js"] in hashes.json
```

`hashes.json.sig` is served here too — the **same** detached signature as on the
primary, not a second one. It is produced by hand from a key that never reaches
a CI runner; this mirror only republishes the 64 bytes already recorded in
[`signing/manifests.jsonl`](https://github.com/VCAP-org/vcap-verifier/blob/main/signing/manifests.jsonl),
and refuses to publish a build that has no entry there. The signature proves
**continuity, not identity** — the by-hand checks and both halves of that claim
are in
[`signing/README.md`](https://github.com/VCAP-org/vcap-verifier/blob/main/signing/README.md).

The check that does not involve either host is the one that matters most:
rebuild the commit named in `hashes.json` and compare (README, *Reproducing the
published build*).

## What this mirror does not have

Two things it cannot serve, said here rather than left to be discovered:

- **No watermark detector.** The 34.2 MB model is served next to the primary,
  outside git and outside the build manifest, and is not in this artifact. The
  engine that would run it *is* here, hashed like the rest; only the model is
  missing. The page stays whole without it —
  it says *watermark not evaluated* and every other verdict is unchanged — but
  a file that needs the detector here will find no model.
- **No cross-origin isolation.** GitHub Pages does not send COOP/COEP, so there
  is no `SharedArrayBuffer` and WASM runs on one thread. Nothing breaks; the
  detector, where one is available, is roughly 2.3–2.6× slower than on the
  primary.

Everything else is identical, signature included, and no verdict depends on
either of those: the verification path contains no server, here or anywhere.
