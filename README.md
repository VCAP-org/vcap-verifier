# vcap-verifier

The public verifier: a static page that validates a sealed file entirely in the
browser, and the **isomorphic verification core** shared with the platform's API
and the server-side libraries.

Free, client-side, no account. This is the guarantee that makes everything else
sellable: anyone — a judge, a journalist, a customer who fell out with us — can
check a file without trusting us.

## Status

Started early (phase 1, September 2026) because the core is what the platform
API and the libraries import: `core/` verifies the signature layer of vcap/1.0
and passes every conformance vector of `vcap-spec`, evaluates RFC 3161 tokens
against injected TSA roots and Android attestation chains against the pinned
Google roots (the §7 proven level and ceiling); `web/` is a first static page
over it, carrying both trust sets — `trust/logs.json` and `trust/tsa.json` are
bundled into the build and published unchanged beside the page.
Both revocation questions §7 asks are implemented as *injected* lookups, because
this core contacts nothing: the chain's status list and the log's signed answer
about the device key. Given neither, a verdict says *chain revocation not
checked* and *revocation not checked* and stops at amber — green is the one
verdict that cannot be reached from the file alone, by design. The §7.1
position level is computed on its own axis — `declared` from the signed
coordinates, `corroborated` from a `location_corroboration` under an injected
log key — and never moves the ceiling.

The page also puts a copy next to the original when the user has both, and
names what the copy still carries: see *Side by side* below.

Not yet: App Attest (the iOS proven level comes from the registry leaf, which is
where enrolment puts it), a page that actually reaches a log or a status list
(the static build ships no network).

## Design constraints

- **One verification core, four consumers** (this page, the platform API, the
  Node and Ruby libraries, the app's offline verdict). Same input, same verdict,
  same wording. The conformance suite from `vcap-spec` is a required CI gate in
  all of them.
- **No network in the verification path.** Registry proofs, anchors and QTSP
  chains are checked from data carried in the file or fetched from public
  endpoints; if there is no network the verdict degrades and says so.
- **The detector is an explicit download, and the page is whole without it.**
  Distillation under 10 MB was dropped (decision D17): what exists is the full
  model at 34.2 MB, so it is never fetched on load, never precached, and its
  absence is *watermark not evaluated* — a weaker verdict, not an error. The
  verifier states which model looked.
- **Reproducible build**, every shipped file hashed and published, so an expert
  can prove which verifier produced a given verdict — by rebuilding it. The
  manifest carries a detached signature that proves **continuity of the signing
  key, not identity** (`signing/README.md`); rebuilding, not the signature, is
  what the trust rests on.

## Layout

```
core/    isomorphic verification core (TypeScript, WebCrypto only — no Buffer, no Node API)
         built to dist/ with declarations for consumers that compile; see core/README.md
cli/     `vcap-verify`, a verdict from a shell (see cli/README.md)
trust/   what the page and the CLI trust by default, as data: the transparency
         logs (`logs.json`) and the timestamping authorities (`tsa.json`), both
         published unchanged beside the page — see trust/README.md
web/     the static verifier page (esbuild, one bundle with its SHA-256 published)
spec/    vcap-spec as a git submodule: the conformance vectors the core runs in CI
bin/     sign and verify a build manifest (the key itself lives outside every repo)
signing/ the published key, the log of signed manifests, and what the signature is worth
```

## Working on it

The vectors run from the `spec` submodule (public, MIT) when it is checked out
and from the committed snapshot `core/vectors` otherwise; `npm run vectors:sync
--workspace core` refreshes the snapshot, `vectors:check` fails when the two
differ, and CI runs both.

```
git submodule update --init      # the spec and its vectors
npm ci
npm run typecheck && npm test    # core: the spec vectors, attachments, evidence; web: the layout ports
npm run build --workspace web    # web/dist: index.html, verifier.js (+ .sha256), detector.js, detector-runtime.js, the engine's wasm, detector.json, logs.json, tsa.json, sw.js, hashes.json, HASHES.md, metafile.json, manifest, icon
npm run test:e2e --workspace web # Playwright against web/dist: offline use and the side-by-side (needs `npx playwright install chromium` once)
npm run dev --workspace web      # serves the page with a watcher (no service worker: dev builds are not cached)
```

## Public page

The page is served at **https://verify.vcap.gregoriogalante.com/**, from a host
of ours: stock nginx over a directory, configured in `vcap-platform`
(`infra/verifier/nginx.conf`, a Kamal accessory in `config/deploy.yml`) and
filled by `bin/push-verifier` with a `web/dist` built here. It was on GitHub
Pages until September 2026; three things moved it, none of them about trust —
and all three are still why Pages is the *mirror* below and not the primary:

- the **model is same-origin**, so its 34.2 MB download needs no CORS and no
  second host;
- the page is **cross-origin isolated** (COOP/COEP), which is what gives
  onnxruntime-web `SharedArrayBuffer` and therefore more than one WASM thread —
  measured at 2.3–2.6× on this machine (*What it costs* below);
- **media types are ours to get right**: a `.mjs` served as `octet-stream` makes
  the browser refuse the module with an error no user can read, and a `.wasm`
  without `application/wasm` cannot be compiled while it streams.

What did not change is the part that matters: the page is static, nothing is
fetched from our infrastructure to reach a verdict, and once the service worker
has installed there is no request at all. **Our host serves the page; it is not
in the verification path** — which is why the hashes below, and not the
hostname, are what the page asks to be trusted on. Anyone who would rather not
fetch it from us can serve the same `dist/` anywhere, sub-path included: every
URL the build produces is relative.

CI is unchanged and is still the gate: typecheck, the core against the spec
vectors, the double clean build with one set of hashes (`build-web.yml`), and
the offline suite against that same artifact, run twice — once shaped like the
primary and once like the mirror below. Neither host is published by a push to
`main`: `bin/push-verifier` from the platform checkout, and `pages-mirror.yml`
by hand, are both a deliberate hand on a public page.

### Mirror on GitHub Pages

The same bytes are also published at
**https://vcap-org.github.io/vcap-verifier/**, a **mirror**. The primary is the
address above; this one exists because the primary is a single CX23 in
Helsinki, and a page whose whole argument is *you do not need us to verify*
should not go down with us.

A second host does not ask for more trust — it asks for less. The two can be
diffed against each other, and both against a build the reader made themselves:

```sh
diff <(curl -s https://verify.vcap.gregoriogalante.com/hashes.json) \
     <(curl -s https://vcap-org.github.io/vcap-verifier/hashes.json)
```

One manifest means one set of file hashes on both hosts. It holds by
construction, and the construction is checkable: `.github/workflows/pages-mirror.yml`
publishes the `web-dist` artifact of `build-web.yml` — the tree two clean
checkouts reproduced, the same artifact that goes to the primary — and never
builds its own. The build is path-agnostic, so the sub-path costs nothing: no
URL it emits is absolute, and CI runs the whole end-to-end suite under
`/vcap-verifier/` with no COOP/COEP to keep that proved rather than asserted.

`hashes.json.sig` is served there too, and it is the **same** signature, not a
second one. The private key never reaches a runner (D59): `bin/mirror-signature.mjs`
restores the 64 bytes from [`signing/manifests.jsonl`](signing/manifests.jsonl),
where the key holder recorded them when they published by hand, and **refuses**
when this manifest has no entry — so the mirror can never run ahead of the
primary, and never serves an unsigned copy of a signed page.

Two things the mirror does not have, said rather than discovered — it serves
`MIRROR.md` next to the page saying the same:

- **no detector**: the 34.2 MB model lives next to the primary, outside git and
  outside the manifest (P11). The engine is mirrored, the model is not, so a
  click on the detector there finds nothing. The page stays whole — *watermark
  not evaluated*, every other verdict unchanged.
- **no cross-origin isolation**: GitHub Pages does not send COOP/COEP, so no
  `SharedArrayBuffer` and one WASM thread instead of several — the 2.3–2.6×
  measured below, in reverse. Slower, not wrong.

The page itself is byte-identical on both hosts and therefore says nothing
about which one it is on. That is deliberate: telling the reader would mean
either a build flag (two builds, two sets of hashes — the one thing this must
not cost) or a hostname compiled into the bundle, and a hostname in a public
repository is there for good. The host-specific claims live in host-specific
files instead: this section, and the `MIRROR.md` served beside the mirror.

### Offline use

The page is a static app that installs itself: `sw.js`, generated by the
build, precaches every shipped file under a cache named after a build id
derived from their hashes, so a new deploy replaces the old cache and an old
one never serves a new page's request. Once the footer says *available
offline*, the page verifies files with no network at all — which is the
product invariant made literal. It never fetches anything else: no
analytics, no roots, no logs fetched: the trusted logs and the TSA roots are
shipped **in** the build and hashed like the rest.

This is tested, not asserted: `web/test/offline.spec.ts` (Playwright, the
`offline` job in CI, run against the same `web-dist` artifact the
reproducibility job hashed) loads the page from a local static server that
sends the live host's headers, waits for the worker, **stops the server and takes the
browser offline**, reloads, and verifies four vectors — authentic, tampered,
no proof, and a sidecar-only proof handed over through the page's second
input — from the cache alone, checking that every request stayed on the
page's origin. It serves at the root with the live host's headers;
`VCAP_TEST_BASE=/somewhere/ VCAP_TEST_ISOLATION=off npm run test:e2e --workspace web`
runs the same suite under a sub-path with no COOP/COEP — the mirror's shape, and
anybody else's — which is the cheapest proof that the build stayed path-agnostic
and that a host whose headers are not ours costs threads and nothing else. CI
runs both shapes.

### Published hashes

Every publish puts, next to the page:

- `https://verify.vcap.gregoriogalante.com/hashes.json` — the SHA-256 of every
  shipped file, the commit it was built from, and the tool versions
  (`toolchain.esbuild`, `toolchain.node`);
- `https://verify.vcap.gregoriogalante.com/HASHES.md` — the same, for a reader;
- `https://verify.vcap.gregoriogalante.com/verifier.js.sha256` — the bundle
  hash alone, `sha256sum -c` format.

Serving the page ourselves makes these **more** load-bearing, not less: on a
third party's host the bytes were at least not ours to change quietly. The
answer is the same one it always was, and it is why the build is reproducible —
rebuild the commit in the footer and compare. A reader who wants no part of our
host can take `hashes.json`, rebuild, and serve the result themselves.

The page footer shows its own bundle hash and commit, so a user can compare
the page in front of them with `hashes.json` and with the CI run for that commit
(the `reproducible` job of `build-web.yml` prints `HASHES.md` in its log).

- `https://verify.vcap.gregoriogalante.com/hashes.json.sig` — a detached
  Ed25519 signature over that manifest.

**What the signature proves is continuity, not identity.** It says the manifest
was signed by the key in [`signing/public-key.pem`](signing/public-key.pem),
the same key that signed every earlier manifest in
[`signing/manifests.jsonl`](signing/manifests.jsonl). It does **not** say who
holds that key: there is no legal entity behind it (R4), no certificate (D2)
and no key-management service (D16), so it is not eIDAS, not an advanced
electronic signature, and not a claim about a person or a company. The key
lives on one machine, in the workspace's `Ops/` folder outside every
repository, and whoever has that disk can sign — which is exactly why the claim
is kept this small. [`signing/README.md`](signing/README.md) spells out both
halves, the by-hand checks with `openssl`, and what a rotation looks like.

The signature is **detached and outside the manifest it certifies** — not
outside `dist/`. `bin/sign-build.mjs` writes it to `web/dist/hashes.json.sig`,
so publishing a build copies one directory and not two; what keeps the build
reproducible is that `hashes.json` does not list it and the two clean builds CI
diffs never carry one. A signature inside the *manifest* would change the tree
it certifies.

What still makes the hashes worth something is not the signature — it is that
anyone can reproduce them:

### Reproducing the published build

The build is deterministic: no timestamps, no absolute paths (the bundle
metafile is checked for them), no environment in the output beyond what
`hashes.json` records. Same commit, same toolchain, same bytes.

```
git clone --recurse-submodules https://github.com/VCAP-org/vcap-verifier
cd vcap-verifier
git checkout <commit>          # the one in hashes.json / the page footer
nvm use                        # exact Node version from .nvmrc
npm ci                         # exact dependency tree from package-lock.json
npm run build --workspace web
sha256sum web/dist/*           # compare with the published hashes.json
node bin/verify-build.mjs web/dist   # or have the script do it, signature included
```

The script is a convenience, not the procedure: every check it runs is written
out as a shell command in [`signing/README.md`](signing/README.md), because
somebody auditing this page should not have to run code of ours to check it.

`verifier.js` and `index.html` depend only on the sources and on the pinned
esbuild version (`web/package.json`, exact), so they reproduce on any OS and
any Node 22. `hashes.json` and `HASHES.md` also record `process.version`, so
they reproduce byte for byte only with the Node in `.nvmrc`; a mismatch there
with matching bundle hashes means a different Node, not a different verifier.
A working tree with uncommitted changes under `web/` or `core/src` is recorded
as `dirty: true` and will not match a CI build.

## Side by side: a copy next to its original

A verdict on a copy is not self-explanatory. A file that came back from a
messaging app has lost its trailer and with it its signature, and *no proof
found* on its own does not say whether the picture is a forgery or a
re-compressed copy of something that was sealed. So the page takes the original
too, when the user has it, and prints one row per piece of evidence: what each
file carries, and which of the two the copy lost.

The watermark is the piece that survives that trip, and the piece an interface
can most easily let someone read backwards. Three rules hold it in place:

- **A mark is never a verdict.** The verdict card keeps whatever the signature
  layer said. A mark found in a copy with no valid signature is rendered in its
  own block as **origin traced**, with the sentence that says no signature
  covers those bytes — never *authentic*, never green.
- **The comparison is the core's.** The page calls `evaluateWatermark` with the
  claim the **original's** signed core produced, so the id compared against
  comes from bytes a device signed and never from anything a detection called
  itself. A payload that does not decode is *not recovered*, which is the
  normal outcome of heavy re-compression and not an accusation.
- **What is missing is labelled, not failed.** A row neither file carries is not
  printed; a copy carrying the same `core_hash` lost nothing, so what its
  verdict stopped short of reading is *not reported* rather than *lost*.

### The detector

Reading a mark out of pixels needs the model, and the model is 34.2 MB (D17).
It is therefore **three artifacts and not one**, none of them in the bundle and
none of them precached:

| file | what it is | when it is fetched |
|---|---|---|
| `detector.json` | the manifest: url, bytes, SHA-256, `model_version`, providers | with the page (a few hundred bytes, cached offline) |
| `detector.js` | the download and the digest check | on the click |
| `detector-runtime.js` + `ort-wasm-simd-threaded.jsep.*` | onnxruntime-web and the layout decoders | after the model's bytes hash to the manifest |

The order is the point: an engine is code, and code that runs before the model
has been checked is code the manifest does not cover. Bytes that hash to
anything else are refused with the two digests printed, and the page is left
exactly as useful as it was — a Playwright test flips one byte of the model in
flight and asserts both.

The model's url is **relative**, so it is served from wherever the page is —
today that is `models/` next to the page on our own host, which is what makes
the download same-origin and spares it CORS entirely. Nobody has to fetch it
from us all the same: the digest is what makes the file trustworthy, not the
host, and `vcap-ml`'s `browser-build` prints the same digest from the artifact
it produces. The verification path is unchanged either way — the download is an
explicit act of the user's, the page is whole without it, and no verdict
depends on it.

**Backends.** `execution_providers` in the manifest is tried in order and the
first session that initialises wins, so a browser with no WebGPU falls back to
WASM SIMD without the reader noticing. The published int8 build asks for
`wasm` alone, because it has no WebGPU kernels for this graph and round-trips
to the CPU inside the session: 1016 ms a frame there against 211–456 ms on
WASM (`vcap-ml/reports/detector-in-the-browser.md`). Which backend ran is
printed, **with its thread count**, because multi-threaded WASM needs
cross-origin isolation (COOP/COEP) and a timing nobody can place is not a
measurement. The page asks for threads only when the browser admits them —
without isolation `SharedArrayBuffer` is absent and onnxruntime-web silently
uses one, so asking for more would misreport the backend rather than speed it
up.

**What it costs, measured** (M4, Chromium, page and model on the same host).
Cross-origin isolation is the whole difference; the same build, the same
files, one server sending COOP/COEP and one not:

| | 1 thread | 10 threads |
|---|---|---|
| download 34.2 MB, hash it, open a session | 0.73 s | 0.75 s |
| photo, one frame, end to end | 1.76 s | 0.69 s |
| clip, eight frames, end to end | 14.2 s | 6.3 s |

So isolation is worth **2.3–2.6×** and costs nothing here: every file the page
loads is same-origin, and the whole e2e suite passes identically with the
headers on. The download is unaffected, as it should be.

Against the published host rather than a loopback, the same photo took **1.32 s**
and the load **296 s** — because the wire, not the page, is what a first
detector click pays for, and because that click fetches **more than the model**:
the engine (`ort-wasm-simd-threaded.jsep.wasm`, 27.8 MB) is deferred with it, so
the first use moves about **62 MB**, not 34.2. The 296 s is one observer's route
(88 ms to Helsinki, ~220 kB/s sustained from this machine, against 3.2 MB/s to a
nearby CDN from the same machine and 167 MB/s out of the server); it is a fact
about a link, not about the host, and it is why the page streams the download
with a progress figure instead of blocking on it. A second click costs nothing:
the engine revalidates to a 304 and the model is served `immutable`. That is
why detection is **progressive**: every frame reports as it lands and the
payload is shown as soon as it decodes — for `video-rep-v1` often on the first
frame, since the eight copies inside one message already do much of the work
aggregation was expected to do (`vcap-ml/reports/frames-to-recover.md`, one
clip with no motion).

**The page reads eight uniformly spaced frames, and on the hardest chain that
survives it needs them.** That count used to be described here as margin; it is
not. On the int8 build published for browsers, crf 36 at 640 px costs 39
flipped bits of 256 aggregated over a single frame — agreement 0.848, *under*
the 0.85 floor — so a one-frame page would answer *watermark not recovered* on
a clip whose id it had decoded correctly. Four frames clear the floor (0.859)
and eight settle it (0.867), which is also where the measurable gain stops: a
ninth frame changes no outcome and costs another model run. An id under the
agreement floor is never shown, partially or otherwise.

A detection can still come from a file the user already holds instead: the
`watermark` block of a `/v1/verify` response, or what `vcap-verify --watermark`
takes. Nothing signs a detection (D18), so it is worth exactly what the hand
that dropped it is worth — which is what it was worth anyway, since the same
hand dropped the media bytes.

#### Where the watermark stops working

A verifier that only publishes what its detector can read is advertising. The
measured curve of the published model — both break points, what quantization
costs, and the list of what was not measured — is public in
`vcap-spec/spec/watermark-robustness-1.0.md`. The three numbers a reader of
this page needs:

- **A photo reduced to a thumbnail carries no readable mark.** Recovery is
  total through a double re-encode at JPEG quality 40, and **zero** from a
  480 px / quality 30 thumbnail onward. There is no partial answer in between:
  BCH either corrects the block or it does not exist.
- **A clip past crf 36 / 640 px does not decode.** It holds to crf 36 with
  agreement 0.87–0.90; at crf 40 it is at 0.65–0.67 — past what the repetition
  code can correct, and far past what this page is allowed to report.
- **What may be reported off a clip is 38 flipped bits of 256, not 51.** Two
  numbers exist for this channel and only the smaller one is a promise. The
  code *recovers* an id through roughly 51 random flips of 256, about 0.80
  agreement; the floor below lets one be **reported** only through **38 of 256,
  a 14.8 % bit error rate** (0.8516 reportable, 0.8477 refused). The larger
  number is what the code can repair, the smaller is what a reader may rely on,
  and the five points of bit error rate between them are not margin this page
  has. On the int8 build it ships, the hardest surviving chain spends **34 of
  those 38 bits** — about four bits of headroom. Inside the ceiling recovery is
  probable and not certain: roughly three patterns in four at 38 flips, because
  a position whose eight copies split 4–4 ties and loses the checksum. And
  **every one of those failures is a refusal, never a wrong id** — across a
  20 000-pattern sweep per flip count, none returned an id that was not the one
  embedded. At the edge of this channel the page fails by saying less, not by
  naming somebody else's capture.

The first two were measured on three images and one synthetic clip, on
re-encode recipes named after sharing services but not produced by them. The
third is arithmetic on the floor plus a sweep of *uniformly random* flips,
which is a property of the code and not of a codec: a real encoder puts its
errors where its bitrate ran out, in bursts, which is what the layout's
32-position interleave is against and what the sweep does not measure.

**And a clip's `mark_id` is refused below 0.85 agreement, even when its
checksum passes.** `video-rep-v1` protects a 24-bit id with eight bits of CRC,
so a word with no structure left in it passes by chance about once in 256: on
unmarked content the measured rate is 15 passes in 4 329 trials — 0.35 %, on
top of CRC-8's own 1/256 — while `photo-bch-v3` produced no id at all
(`vcap-ml/reports/false-positives.md`). Two device recordings resolved an id
the pixels had never carried, at 0.738 and 0.789, so the verifier applies the
layout's floor (`VIDEO_AGREEMENT_FLOOR`, and
`vcap-spec/spec/watermark-layouts-1.0.md`): under 0.85 it reports **no id and
the agreement figure**, never the id it refused. It is a refusal band and not a
separator — correct ids have been observed at 0.727, below a wrong one at
0.738 — so true answers are refused along with false ones, and that cost is the
rule rather than a flaw in it. Above the floor, a recovered `mark_id` taken
**alone** still says little: 24 bits collide by design, and it is the
signature, not the mark, that identifies a capture.

None of which changes a verdict, because it cannot: a mark that is read is
*origin traced*, a mark that is not — including one the floor refused — is
*watermark not recovered*, and the verdict card keeps the colour the signature
layer gave it either way. The failure of a detector is a weaker answer, never an
error and never a red verdict.

#### Running the end-to-end detector tests

They skip unless the model and the marked media are in place, because neither
is in git — the model is a release asset (`vcap-ml`, P11) and the media is
generated by the embedder there:

```
# in vcap-ml
python -m vcap_ml quantize && python -m vcap_ml browser-build
# here
mkdir -p web/dist/models
cp ../vcap-ml/models/detector_int8.onnx web/dist/models/detector-videoseal-y256b-1-int8.onnx
npm run test:e2e --workspace web
```

A host serving these files must send `application/wasm` for the engine's binary
and a JavaScript type for its `.mjs` glue; the test server does, our own host
declares both rather than inheriting them (`vcap-platform`,
`infra/verifier/nginx.conf`), and a static host that does not will fail to
start a session with no error the user can read. Sending COOP/COEP as well is
optional and worth 2.3–2.6× (above).

## What the core verifies

Trailer and footer (structure first, CRC second), nested trailers, the §3.1
sidecar in the spec's precedence (an intact trailer wins and a sidecar that
differs byte for byte is *sidecar differs*; a broken trailer is *corrupted
proof* whatever sits beside it; a sidecar alone is the full verdict over the
whole file, with no label for where the proof came from — the core takes it
as `verify(file, { sidecar })`, the CLI reads `<file>.vcap` next to the file
and the page takes it from a second input, never from a search or a fetch),
canonical bytes (JPEG APP11 JUMBF stripped, BMFF untouched), the
signed core (`ES256` over `JCS(core)`, P1363, `key_id` derived), video segment
chains over messages, the version policy (unknown minor: *not evaluated*;
unknown major: unsupported), the §8 labels for absent attachments, and — when
present — the `registry` attachment against trusted log keys (signed tree head,
RFC 6962 inclusion, key binding, *registered after the declared capture*) and
the `anchor` attachment (root recomputed; compared with the chain only through
an injected reader, otherwise *anchoring not verified*), the `timestamp`
attachment (CMS over TSTInfo: imprint = core hash, signed attributes, signature,
chain to the given TSA roots, timeStamping usage, genTime) and the `attestation`
attachment on Android (chain to a pinned Google root, leaf key = `sig.pub`,
weaker of the two security levels, locked device with verified boot; revocation
through an injected status lookup, read under §6.2's temporal rule — a
current-status list can only speak for the moment it was read, so what it finds
is *attestation key revoked after the capture* and the level at the capture
stands; only a snapshot dated before the capture withdraws it). The device key's
own standing is a separate question with a separate label, answered by the log's
signed statement over `"vcap/1.0/status" ‖ key_id ‖ at ‖ tree_size ‖ status`,
whose `at` is checked against the proven instant so a log cannot be quoted out of
context. The `integrity` attachment relays what Play Integrity or App Attest
said about the device, signed by the registry over `core_hash ‖ verdict` — the
verdict sits inside the signed message, so it cannot be relabelled — and it is
**shown without changing any ceiling**: the same rooted device that fails an
integrity check also fails to chain to a hardware root, so counting it in §7
would count one fact twice. From those the verdict carries `level`:
claimed, proven and the §7 ceiling, with *inconsistent claim* when the claim
exceeds the evidence. X.509 and CMS are read with `asn1js` over WebCrypto (RSA
PKCS#1 v1.5 and ECDSA with SHA-256/384/512). Besides synthetic chains, the tests
run a chain minted by real hardware (`core/test/fixtures/`, from
`SDK-Android/tools/attest-dump`): five certificates under Remote Key Provisioning
down to the pinned 2025 Google root, clock pinned to capture time.

Verdict vocabulary is the spec's: `authentic`, `verified_clip`, `tampered`,
`nested_proof`, `corrupted_proof`, `no_proof_found`, `unsupported_format_version`.

## Conformance: which corpus, and how many vectors

This repository's verdicts are checked against the `vcap-spec` vector corpus,
and the claim is only worth what it names. Today that is **corpus 1.2.0, 85
vectors** (manifest `29fd346eda9206bb…`), the last of them an iOS video sealed
on a device, whose segment chain a Secure Enclave signed:

| Runner | Vectors | Corpus |
|---|---|---|
| `core/test/conformance.test.ts` | all of them, every `kind` | `vectors/VERSION` of the `spec` submodule, count pinned to `vectors/MANIFEST.json` |
| `cli/test/cli.test.ts` | the `file` and `container` vectors — the CLI takes a file, so `segments` and `jcs` have nothing to hand it | same corpus, count pinned to the manifest's count of those two kinds |
| `web/test/offline.spec.ts` | a hand-picked few, in a real browser with the network gone | the same snapshot |

Two rules, and they are the point of the table:

- **The count is pinned, not floored.** A floor (`>= 84`) passes while the
  corpus shrinks under it. Both suites compare against `MANIFEST.json` and fail
  on inequality, which also fails when the submodule is left behind a newer
  corpus — adopting new vectors is then a deliberate bump.
- **A run of zero vectors is a failure, never a pass.** `core/test/corpus.ts`
  throws on a missing or empty corpus instead of handing back an empty list, so
  no loop here can be green for having no body. `vcap-spec/vectors/CONFORMANCE.md`
  is the same rule written for implementations that are not ours.

The snapshot in `core/vectors` is kept byte-equal to the submodule by
`vectors-sync.mjs` (`npm run vectors:check`, run in CI), so a checkout without
the submodule still runs the vectors — but never *no* vectors.

## Project documentation

This repository is code only. The plan, the decision log and the product
context live in the project workspace, outside this repo and not public;
`AGENTS.md` here carries everything a contributor to *this* repository needs.

## Product invariants

These hold for every line of code in every repository:

- **The verification path never contains one of our servers.** If a component
  becomes necessary to produce a verdict, that is a design error.
- **Server registration is always optional**: capturing and verifying work with
  no account and no network.
- **A watermark alone is never a green verdict**: without a valid signature it is
  "origin traced", not "authentic".
- **A missing field yields a weaker verdict, not an error**: no timestamp means
  "no trusted time", and the verifier says so.
- Failures are published alongside successes.
- Location is never "guaranteed": the reached level is declared
  (declared, corroborated, authenticated).

Naming, the definition of done and the language rule are in `AGENTS.md`, once.

## License

MIT (`LICENSE`), like `vcap-spec`: a verifier anyone can audit, run and embed
is the promise. Copyright holder "the vcap authors" until decision D1 names the
legal entity.

