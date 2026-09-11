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
over it, still without TSA roots (so it labels *trusted time not evaluated*).
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
  can prove which verifier produced a given verdict — by rebuilding it.

## Layout

```
core/    isomorphic verification core (TypeScript, WebCrypto only — no Buffer, no Node API)
         built to dist/ with declarations for consumers that compile; see core/README.md
cli/     `vcap-verify`, a verdict from a shell (see cli/README.md)
web/     the static verifier page (esbuild, one bundle with its SHA-256 published)
spec/    vcap-spec as a git submodule: the conformance vectors the core runs in CI
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
npm run build --workspace web    # web/dist: index.html, verifier.js, detector.js, detector-runtime.js, the engine's wasm, detector.json, sw.js, hashes.json, HASHES.md, metafile.json, manifest, icon
npm run test:e2e --workspace web # Playwright against web/dist: offline use and the side-by-side (needs `npx playwright install chromium` once)
npm run dev --workspace web      # serves the page with a watcher (no service worker: dev builds are not cached)
```

## Public page

The page is served at **https://verify.vcap.gregoriogalante.com/**, from a host
of ours: stock nginx over a directory, configured in `vcap-platform`
(`infra/verifier/nginx.conf`, a Kamal accessory in `config/deploy.yml`) and
filled by `bin/push-verifier` with a `web/dist` built here. It was on GitHub
Pages until September 2026; three things moved it, none of them about trust:

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
the offline suite against that same artifact. There is no deploy workflow —
publishing is `bin/push-verifier` from the platform checkout, which is a
deliberate hand on a public page rather than a push to `main`.

### Offline use

The page is a static app that installs itself: `sw.js`, generated by the
build, precaches every shipped file under a cache named after a build id
derived from their hashes, so a new deploy replaces the old cache and an old
one never serves a new page's request. Once the footer says *available
offline*, the page verifies files with no network at all — which is the
product invariant made literal. It never fetches anything else: no
analytics, no roots, no logs (trusted logs and TSA roots, when the page gains
them, will be shipped in the build and hashed like the rest).

This is tested, not asserted: `web/test/offline.spec.ts` (Playwright, the
`offline` job in CI, run against the same `web-dist` artifact the
reproducibility job hashed) loads the page from a local static server that
sends the live host's headers, waits for the worker, **stops the server and takes the
browser offline**, reloads, and verifies four vectors — authentic, tampered,
no proof, and a sidecar-only proof handed over through the page's second
input — from the cache alone, checking that every request stayed on the
page's origin. It serves at the root, as the live host does;
`VCAP_TEST_BASE=/somewhere/ npm run test:e2e --workspace web` runs the same
suite under a sub-path, which is the cheapest proof that the build stayed
path-agnostic and that somebody else can host it wherever they like.

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

**These hashes are not signed.** No signing key exists yet — the legal entity
that would hold one is decision D1, still open — and an unsigned hash file next
to the file it hashes proves only that the two were published together. What
makes them worth something is that anyone can reproduce them:

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
```

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
headers on. The download is unaffected, as it should be. That is
why detection is **progressive**: every frame reports as it lands and the
payload is shown as soon as it decodes, which for `video-rep-v1` is usually the
first frame (`vcap-ml/reports/frames-to-recover.md`).

A detection can still come from a file the user already holds instead: the
`watermark` block of a `/v1/verify` response, or what `vcap-verify --watermark`
takes. Nothing signs a detection (D18), so it is worth exactly what the hand
that dropped it is worth — which is what it was worth anyway, since the same
hand dropped the media bytes.

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

## Project documentation

This repository is code only. Plan, specification, decisions and market context
live in the project workspace, outside this repo:

- `Doc/01-piattaforma-build-spec.md` — components, epics, estimates, sequence
- `Doc/05-decisioni.md` — decision log (read before proposing an architectural change)
- `Doc/06-fase1-avvio.md` — phase 1 work order
- `AGENT.md` — workspace rules, naming conventions, product invariants
- `CHECKLIST.md` — the single work list; tick your line in the same commit

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

## Naming

`vcap` (verified capture) is the internal codename and the only name allowed in
identifiers: package names, bundle ids, trailer magic, proof version string,
database schemas, log prefixes. The product brand is provisional and must never
appear in anything expensive to rename — it lives only in UI strings (single
localization file) and store metadata. Full table in the workspace `AGENT.md`.

## Definition of done

In main, tested, conformance vectors passing in CI, and documented where the next
person needs it. Not "works on my branch".

## Language

Code, comments, README and commit messages in English. Project documentation in
`Doc/` is in Italian.

## License

MIT (`LICENSE`), like `vcap-spec`: a verifier anyone can audit, run and embed
is the promise. Copyright holder "the vcap authors" until decision D1 names the
legal entity.

