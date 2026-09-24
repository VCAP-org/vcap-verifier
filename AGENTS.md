# Agent instructions — vcap-verifier

## The rule that matters most

Everything user-visible here is a claim about evidence. Precision of wording is
part of correctness:

- A watermark match without a valid signature is **origin traced**, never
  authentic.
- A missing timestamp is **no trusted time**, not a failure.
- An unknown minor version means the unknown parts are **not evaluated**, and the
  verifier says which.
- A `video-rep-v1` id decoded below **0.85** agreement is not reported at all:
  *watermark not recovered*, with the figure and never the id that was refused.
  Eight bits of CRC over a 24-bit id admit a wrong one about once in 256, and a
  wrong `mark_id` points a reader at somebody else's capture. The floor is
  `VIDEO_AGREEMENT_FLOOR` in the core, exported for the surfaces that apply it
  before they report — never re-derived, never printed alongside the refused id.
- A clip's *watermark matched* says **how much of the clip carried it**: the id
  comes from the sampled frames averaged and decoded once, the count comes from
  the same frames decoded individually, and the floor is held against the id
  alone: a frame counts when its own decode passes the CRC and yields the id
  the clip reported, whatever its own agreement was, because the count names no
  id and equality against an already-floored id is what the floor supplied. An
  unmarked frame abstains rather than dissents, so one genuine frame spliced
  into foreign footage reports the real id at the agreement of a clean
  recovery — the count is the only thing that sees it, and `agreement` is never
  shown as if it did — and the figure beside the id is the aggregate decode's
  own, never a mean over the frames that carried it. A count of zero is a
  limitation and not an accusation: a clip can resolve on the average while no
  single frame's checksum holds, which is what heavy re-compression does.
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
  (`verdict.content`). A segment is credited only when a GOP's vcap SEI of this
  capture locates it and the GOP's bytes match; once one GOP names the capture
  every GOP must (no SEI, a foreign one, an unsigned, repeated or decreasing
  index → tampered); nothing located over bytes that are not the sealed ones is
  `frames_not_compared`, never `verified_clip`. Never infer an index from
  position, never let the SEI prove anything.
- `verify` never throws on input. A new parser bounds every count by the bytes
  that hold it, checks `Number.isSafeInteger` before `BigInt`/`Date`, and keeps
  DER inside `try`; `core/test/hostile.test.ts` holds one case per crash found.
- `spec/` is the `vcap-spec` submodule; `core/test/conformance.test.ts` runs
  every vector in it. A vector that fails is a spec conversation, never a local
  expectation edit.
- **A run of zero vectors is a failure, never a pass.** Every conformance
  runner here pins its count against the corpus `MANIFEST.json` and names the
  corpus version; `core/test/corpus.ts` throws rather than hand back an empty
  list. A floor (`>= 84`) is not that assertion: it passes while the corpus
  shrinks under it, and it passes loudest when nothing ran at all.
- The **trust sets** are `trust/logs.json` and `trust/tsa.json` (plus
  `trust/chains.json`, below, for where anchors are read): two
  documents, because they are two decisions, with separate switches everywhere
  (`--no-default-logs` / `--no-default-tsa`, two panels, two Settings
  sections). Refusing the log we run must never also drop a third party's
  clock. A **TSA** is the one pinned party that really is independent, so its
  entry is allowed to claim more than `logs.json` does — and exactly that much:
  a token proves *this hash existed before that instant, and that authority
  said so*, never who made the file. FreeTSA is a free community service with
  no SLA and no contractual liability, and that stays in the caveats wherever
  the entry is printed. A root is never shipped on a URL's word: it is proven
  against a real token first, because a wrong certificate fails closed and
  looks like tampering.
- The **log trust set** — which transparency logs a `registry` attachment is
  checked against — is `trust/logs.json`, data and not a constant, and it is
  bundled into the page, read by the CLI and published unchanged beside the
  page. Two rules hold wherever it is used. It must be **visible and
  refusable**: every surface names the logs it trusts, says who runs each one,
  and lets the reader drop them and supply their own — a default that cannot be
  inspected or turned off is a requirement pretending to be a default, and it
  destroys the only claim this repository makes. And a log **this project runs
  is not a third party**: `registry` proves the sealing key was in *our* log
  before the capture and nothing else, so no wording anywhere may let it read
  as independent corroboration.
- No analytics, no telemetry, no uploads. The file and the proof never leave
  the browser, and that must stay auditable in a single read of the source.
- The **chain read** is the one request a verdict makes: for a proof with an
  `anchor`, the page and the CLI ask the public chain RPC listed in
  `trust/chains.json` (never a server of ours) for the root the contract
  stored, sending the anchor id only. The core stays transport-free
  (`rpcChainReader(chains, post)`, the caller's `post`). The RPC is a **trust
  point** — a lying endpoint could fake a root — and every surface says so and
  lets the reader refuse it (`--offline`, `--chains`, the page's switch). A
  reader that throws is *not consulted* (*anchoring not verified*), never
  *not found*; offline must still give a whole verdict.
- The **detector** is fetched only when a file needs it (a proof declaring a
  `watermark`, or a file with no proof), never on load, and the verdict waits
  for it with its progress shown:
  `web/src/detector.ts` is a separate artifact, excluded from the service
  worker's precache, and `detector.json` pins the build's SHA-256 so nothing
  unverified runs. Never import it from the bundle, and never make a verdict
  depend on it — a page without a detector says *watermark not evaluated* and
  is otherwise whole. A reader may run their own model instead (*Advanced →
  Use a different model*): unpinned, so it is hashed in the page and named
  `custom-<sha256 prefix>` in every detection — never the pinned build's
  `model_version`.
- The **first view** is one question, one dropzone and one status line; the
  detector, the sidecar and the three trust panels live in one closed
  *Advanced* `<details>`. That is still *visible and refusable*: the panels are
  one click away, and the summary line names what is in use and says *custom*
  whenever the setup differs from what ships. Never fold a trust point
  anywhere its summary does not reach.
- The verdict's **colour is §7's ceiling**, not the outcome: the page paints the
  stricter of `level.ceiling` and the outcome's own colour, never greener, and
  names the labels that set it with the core's `ceilingLabels` — never a list
  of its own. An *authentic* file under an amber ceiling is not a "yes".
- The page is one file in, one verdict out. A watermark is never a verdict: a
  mark read out of a file with no valid signature is an identifier in its own
  block, and the verdict card keeps the colour the signature layer gave it. A
  comparison against signed ids is the core's `evaluateWatermark`, never the
  page's own.
- Publish the failures too: the demo set includes the cases where verification
  cannot conclude.
- Keep the page usable offline and archivable.
- The page is published on a host of ours (`verify.vcap.gregoriogalante.com`,
  configured on the platform's host), by hand, from a clean checkout. Nothing in
  this repository may come to depend on that: every URL the build produces is
  relative, the e2e suite runs at a root and under a sub-path, and a verdict
  needs no request to our host. The host serves bytes whose hashes are
  published — it is not in the verification path, and a change that would put
  it there is the change to refuse.
- The page is also mirrored on GitHub Pages
  (`.github/workflows/pages-mirror.yml`, by hand, `workflow_dispatch` only).
  The mirror is **not** the primary and must never become one: it republishes
  the `web-dist` artifact `build-web.yml` reproduced — no build of its own — and
  restores the signature the key holder already recorded in
  `signing/manifests.jsonl` rather than making one, so the signing key never
  touches a runner. It refuses a manifest with no log line. What the mirror
  lacks (the detector model, COOP/COEP) is written in the README and in the
  `MIRROR.md` served beside it: a mirror that hides what it cannot do is worse
  than no mirror. Keep the page itself byte-identical on both hosts — a
  host-specific string in the bundle would cost a second set of hashes.
- The page build is reproducible and stays so: nothing in `web/dist` may depend
  on the clock, the machine or its paths — only on the commit and the pinned
  toolchain. CI builds twice from clean checkouts and fails if the trees differ.
  Every shipped file is listed in `hashes.json`, and that manifest is signed
  with a **detached** Ed25519 signature (`bin/sign-build.mjs`, key in `Ops/`,
  never in a repo). It lands at `dist/hashes.json.sig`, which is safe because
  the manifest does not list it and the builds CI diffs are unsigned: what must
  never happen is the signature entering the bytes it signs. It claims
  **continuity, not identity**: no legal
  entity, no certificate, no KMS. Write that limit wherever the signature is
  mentioned, the way the evidence report prints its own, and never let a
  verdict come to depend on it: this is the provenance of the page, not of a
  proof.

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
localization file) and store metadata.

## Public repository

This repository is public and the rest of the project is not. Never name a
private repository, a path inside one, a command that only runs there, the
internal project docs or an internal decision/task code (`D17`, `P11`, ...):
say what the thing is in words ("our model pipeline, which is not public", "the
platform's host", "an internal measurement"). `vcap-spec` is public and may be
named. The one exception is `core/vectors/`, a byte-for-byte mirror of the
published corpus, which is never edited here.

## Definition of done

In main, tested, conformance vectors passing in CI, and documented where the next
person needs it. Not "works on my branch".

## Language

Code, comments, README and commit messages in English.
