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
Not yet: App Attest (the iOS proven level comes from the registry leaf), Google's
status list online (offline it labels *chain revocation not checked*), the watermark
detector.

The PoC verifier stays online for its own samples and is not a code source.

## Design constraints

- **One verification core, four consumers** (this page, the platform API, the
  Node and Ruby libraries, the app's offline verdict). Same input, same verdict,
  same wording. The conformance suite from `vcap-spec` is a required CI gate in
  all of them.
- **No network in the verification path.** Registry proofs, anchors and QTSP
  chains are checked from data carried in the file or fetched from public
  endpoints; if there is no network the verdict degrades and says so.
- **Detector under 10 MB** (WebGPU with a WASM SIMD fallback), distilled from the
  large model, with a documented robustness curve. The verifier states which
  model it used.
- **Reproducible build**, bundle hash published, so an expert can prove which
  verifier produced a given verdict.

## Layout

```
core/    isomorphic verification core (TypeScript, WebCrypto only — no Buffer, no Node API)
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
npm run typecheck && npm test    # core: 32 vectors + attachment and evidence tests
npm run build --workspace web    # web/dist/{index.html, verifier.js, verifier.js.sha256}
npm run dev --workspace web      # serves the page with a watcher
```

## Public page

The page is served from GitHub Pages at
**https://vcap-org.github.io/vcap-verifier/**. It deploys from `main` through
`.github/workflows/pages.yml`: checkout with the `spec` submodule, `npm ci`,
typecheck and the core tests as a gate (a red core never deploys), then the
`web` build and the `web/dist` artifact as published — nothing more. The page is
static and stays so: no server of ours is in the path, nothing is fetched from
our infrastructure.

The bundle hash lives next to the bundle,
`https://vcap-org.github.io/vcap-verifier/verifier.js.sha256`, and every
deploy prints it in the workflow log, so an expert can prove which verifier
produced a given verdict.

## What the core verifies

Trailer and footer (structure first, CRC second), nested trailers, sidecar
precedence, canonical bytes (JPEG APP11 JUMBF stripped, BMFF untouched), the
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
through an injected status lookup). From those the verdict carries `level`:
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

