# Agent instructions — vcap-verifier

## The rule that matters most

Everything user-visible here is a claim about evidence. Precision of wording is
part of correctness:

- A watermark match without a valid signature is **origin traced**, never
  authentic.
- A missing timestamp is **no trusted time**, not a failure.
- An unknown minor version means the unknown parts are **not evaluated**, and the
  verifier says which.
- The verifier must be able to say **no proof found** without embarrassment. One
  that cannot does not deserve trust.

## Working rules

- `core/` is published as a package and consumed by the platform and the
  libraries. Never fork it: a second implementation of the same verdict is the
  failure this project cannot afford. It uses WebCrypto and Uint8Array only —
  no `Buffer`, no `node:` imports — so the same file runs in a browser, in Node
  and in the platform.
- `core/src/container.ts` recomputes the §5 segment hashes from the ISO-BMFF
  container and is on by default in `verify`: a verdict that reads the hashes
  out of the proof has checked that somebody signed some hashes, not that these
  are the frames. It stays optional at the API level
  (`verify(file, { recomputeSegments: false })`) for callers that hold a sidecar
  and no demuxable container, and the verdict always says which of the two ran
  (`verdict.content`).
- `spec/` is the `vcap-spec` submodule; `core/test/conformance.test.ts` runs
  every vector in it. A vector that fails is a spec conversation, never a local
  expectation edit.
- No analytics, no telemetry, no uploads. Nothing leaves the browser, and that
  must stay auditable in a single read of the source.
- The **detector** is the one thing the page fetches, and only on a click:
  `web/src/detector.ts` is a separate artifact, excluded from the service
  worker's precache, and `detector.json` pins the build's SHA-256 so nothing
  unverified runs. Never import it from the bundle, and never make a verdict
  depend on it — a page without a detector says *watermark not evaluated* and
  is otherwise whole.
- In the side-by-side, a watermark is never a verdict: a mark found in a copy
  with no valid signature is **origin traced**, in its own block, and the
  verdict card keeps the colour the signature layer gave it. The comparison
  against the original's ids is the core's `evaluateWatermark`, never the
  page's own.
- Publish the failures too: the demo set includes the cases where verification
  cannot conclude.
- Keep the page usable offline and archivable.
- The page is published on a host of ours (`verify.vcap.gregoriogalante.com`,
  configured in `vcap-platform`), by hand, from a clean checkout. Nothing in
  this repository may come to depend on that: every URL the build produces is
  relative, the e2e suite runs at a root and under a sub-path, and a verdict
  still needs no request of any kind. The host serves bytes whose hashes are
  published — it is not in the verification path, and a change that would put
  it there is the change to refuse.
- The page build is reproducible and stays so: nothing in `web/dist` may depend
  on the clock, the machine or its paths — only on the commit and the pinned
  toolchain. CI builds twice from clean checkouts and fails if the trees differ.
  Every shipped file is listed in `hashes.json`; there is nothing to sign it
  with yet, so say so rather than pretend.

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
