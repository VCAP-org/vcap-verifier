# vcap-verify-core

Verification of a vcap proof, isomorphic: the same verdict in a browser, in
Node, and inside the platform. **WebCrypto only** — no `Buffer`, no Node API,
and no network of its own: what needs one is injected by the caller.

```ts
import { verify } from 'vcap-verify-core'

const verdict = await verify(new Uint8Array(bytes))
verdict.outcome   // 'authentic' | 'verified_clip' | 'frames_not_compared' | 'tampered' | …
verdict.labels    // what is missing, sorted (§8)
verdict.level     // { claimed, proven, ceiling } (§7)
verdict.location  // { claimed, level, declared? } (§7.1): none | declared | corroborated | authenticated — never a ceiling
```

## It contacts nothing, and that is the design

Every check here is one the file carries the evidence for. The answers that
need a network the core will not go and get — the **caller** supplies them,
and their absence is a labelled answer rather than a failure:

```ts
await verify(bytes, {
  trustedLogs: [{ logId, spki }],   // else: log not trusted
  tsaRoots: [der],                  // else: trusted time not evaluated
  keyStatus: async (keyIdHex, at) => …,  // else: revocation not checked
  revocation: async (serialHex) => …,  // Google's status list; else: chain revocation not checked
  readChain: rpcChainReader(parseChainsDocument(chains), post), // else, or if it throws: anchoring not verified
  watermark: async (claim) => …,    // else: watermark not evaluated
  now: new Date(…)                  // a §7 verdict depends on when it is asked
})
```

`rpcChainReader(chains, post)` reads an anchor over JSON-RPC: `chains` is
`parseChainsDocument` of a document shaped like `trust/chains.json` (chain id,
contract, RPC URLs per chain name) and `post(url, body) => Promise<string>` is
**your** transport — the core never calls `fetch`. It checks `eth_chainId`,
calls `getAnchor(anchor_id)` and decodes root, tree size and block time. A zero
root or a revert is `null` (*anchor not found on chain*); an unknown chain, a
wrong chain id, or a transport or RPC error **throws**, and `verify` reads a
throw as *not consulted* — the detail says why, the label is *anchoring not
verified*, never a failure. The RPC endpoint is a trust point: this is not a
light client, and a lying endpoint could return a forged root.

`verify` never throws on what it is handed: a malformed proof, attachment,
container or lookup answer is a labelled verdict, and a top-level guard turns
anything that still escapes into *no proof found* or *corrupted proof* with a
`reason`. A payload that repeats a key is refused (*no proof found*), because
two parsers would read it two ways.

A clip is *verified* only for segments whose GOP the container locates by its
vcap SEI and whose bytes hash to the signed value; with nothing located and a
file that is not the sealed bytes, the outcome is `frames_not_compared`
(the signatures hold, no frame is tied to them) and never `verified_clip`.

One more option is not about the network but about where the hashing runs.
`mediaHash` is the SHA-256 of the canonical bytes (§4.1) when the caller
already has it — a phone that hashed a long recording natively. With it the
core needs only the trailer (pass `recomputeSegments: false`, since there is
no container to read), and the digest is trusted exactly as far as the caller
that computed it.

A verdict is only ever green **against a named set of anchors**. Google's
attestation roots are pinned in the library (`googleRoots`); logs and TSA roots
are yours to name, because the same bytes are green for a verifier that pins a
log and amber for one that does not, and both are right.

This library ships **no** default trust set, and that is deliberate: a log
imported by a dependency is a trust decision out of the caller's sight, and the
callers here are the page, the CLI, the app and the platform, each of which
has to be able to show its reader whom it believes. What it does ship is a
reader for a written one — `parseTrustDocument(json)`, which decodes each
`spki` and refuses any entry whose `log_id` is not that key's SHA-256 — and
`parseTrustedLog('<log_id>:<base64 spki>')` for a single pasted line. The set
the verifiers in this repository happen to load is `trust/logs.json`, one
directory up.

## The watermark, and what this core will not do with it

`watermark` in the core is the **writer** saying a mark was embedded in the
pixels (§6.1). Reading it back needs a model, a demux and frames, which this
library does not carry — so the detection arrives the way every other answer
it cannot reach offline arrives, from the caller:

```ts
await verify(bytes, {
  watermark: async ({ layout, captureId, markId, mime, coreHash }) => ({
    layout: 'photo-bch-v3',
    decoded: '00112233445566778899aabbccddeeff',  // null when nothing decoded
    corrected_bits: 4,                            // photo-bch-v3
    agreement: 0.94,                              // video-rep-v1, required
    frames_sampled: 8,
    frames_with_id: 8,                            // video-rep-v1
    sampling: { frames: 8, strategy: 'uniform' },
    model_version: 'videoseal-y256b-1'
  })
})
```

The lookup is handed the question, built from the **signed** core: the declared
layout, `capture_id` as hex, `watermark.mark_id` when the proof binds one,
`media.mime`, and the `core_hash` — so a caller relaying a detection made
elsewhere (a job queue, a cache) can check it is about this proof before
passing it on. It returns what came out of the pixels, or `null`; `null`, a
throw and an absent option are the same answer and none of them is an error.

The core then applies §8's table itself. The four rows, and `verdict.watermark`
carries the detail and the figures:

| Evidence | Label | Verdict |
|---|---|---|
| `decoded` is the id the core declares | *watermark matched* | unchanged |
| `decoded: null` | *watermark not recovered* | unchanged |
| unknown layout, unreadable payload, no lookup | *watermark not evaluated* | unchanged |
| `decoded` is a **different** id | — | **tampered**, with its reason and no labels |

Four things are deliberate and are the reason this is not a thin passthrough.

**`video-rep-v1` has a floor, and it comes before the comparison.** The layout
protects a 24-bit id with eight bits of CRC, which a structureless word passes
about once in 256 — measured at 0.35 % on unmarked content, and twice on real
recordings at agreement 0.738 and 0.789 with an id the pixels never carried. So
an id from that layout is read only when `agreement` is present and at least
`VIDEO_AGREEMENT_FLOOR` (0.85, `watermark-layouts-1.0.md`). Below it the
outcome is *not recovered* with `id_refused: true` and the figure, and the
refused id is never named; without an `agreement` figure at all the outcome is
*not evaluated*. Both come **before** the comparison on purpose: an id that may
not be reported as a match may not be held against the proof as a contradiction
either. `photo-bch-v3` has no such floor — BCH either corrects the block or it
does not.

**The comparison is never the caller's.** The evidence says only what came out
of the pixels; the id it is compared against is read from the signed core —
`capture_id` for `photo-bch-v3`, `watermark.mark_id` for `video-rep-v1` (§8).
A detection block carrying its own outcome word is not read.

**A malformed payload is *not evaluated*, never a contradiction.** The red row
requires a payload that **decodes**, to a well-formed id of the declared
layout. Everything else — a truncated hex string, a mark id past 24 bits, a
number where a string belongs — is evidence this core cannot read, which §8
makes a weaker verdict and never an accusation. The case this protects is the
common one: a clip a messaging app re-compressed comes back with nothing
decodable, and calling that forged is the worst mistake this format can make.

**A watermark alone is never green, by construction.** The evaluation sits
after the core signature, so a proof whose `sig` does not verify has already
returned *tampered* and never reaches it; *watermark matched* is a label and is
not read by the §7 ceiling. A mark with no valid signature is *origin traced*,
which is a thing a caller says about a file this core called red — not an
outcome it can reach.

**What it does not verify, stated plainly.** It cannot re-run a detector, so it
does not check that the evidence came from one. This is weaker than
`keyStatus`, and the difference is worth naming: a key-status statement is
trusted because it is *signed* by a log the caller pinned, over a message
binding the key id, the instant and the status. Nothing signs a detector's
output — there is no key for it in the format, and minting one would put a server of
ours on the path to a verdict, which the product forbids. So the evidence is
trusted exactly as far as the caller is, which is exactly as far as it already
had to be: the same caller hands over the media bytes and can reach any verdict
it likes by editing those instead. Binding the evidence to the core hash would
buy nothing against that caller, so it is not required — the `coreHash` in the
claim is there for the caller that *relays* somebody else's detection, which is
the only place the binding can be checked.

## The verdict

`outcome` answers "does this file verify". `labels` answers "what is missing",
and a caller **must** show them: a proof is a set of claims with evidence
attached, and a reader told only what passed will assume it was all there.
`level.ceiling` is green, amber or red, and is bounded by the weakest link —
green needs a proven hardware level, the key in the log before the capture, and
its revocation actually asked.
The ceiling is the verdict's light (§7), and a surface colours by it, not by
`outcome`: *authentic* under an amber ceiling is not green. `ceilingLabels(verdict)`
returns the §7 labels that set it, from `labels` in the core's words — the
revocation on red, the missing evidence on amber, the proven hardware on green
(*sealed in the TEE*) — so a surface can say why without a list of its own.

`validated_at` says which instant every certificate path was checked at and
**where that instant came from**: an RFC 3161 timestamp, a block on a public
chain, or the device's own clock — a claim. The same file reads differently
depending on which, so a verifier that could not say this would be hiding the
difference.

## Content Credentials

A C2PA manifest store is a **carrier** here, never a verdict. It can hold the
proof as the assertion `io.github.vcap-org.vcap.proof` (`vcap-spec`,
`c2pa-interop` §2.1), and `extractProof` finds it:

```ts
import { extractProof } from 'vcap-verify-core'

const found = extractProof(file, sidecar?, c2paStore?)
// { kind: 'proof', payload, media, flags, source, labels, c2pa? }
//   source: { kind: 'trailer' } | { kind: 'sidecar' } | { kind: 'c2pa', manifest, depth }
// { kind: 'refused', outcome, reason, c2pa? }   // no_proof_found, corrupted_proof, …
```

`verify(file, { sidecar, c2paStore })` runs the same function first, so its
verdict carries `proof_source` (where the proof was read — diagnostic, never a
label), `content_credentials` (what the store held, for a surface to show in a
lane of its own) and, for a video whose container was read,
`frames_name_capture` (whether any GOP's vcap SEI names the capture — a hint,
never evidence). The precedence is §3.1's with the store in it: an intact
trailer; a broken CRC is *corrupted proof* whatever the store holds; then the
active manifest (depth 0), the sidecar, and the nearest proof up the
`parentOf` chain (depth 1–16). A copy in a manifest is compared as
`JCS(parse(a)) == JCS(parse(b))` (*manifest copy differs*), because a C2PA
writer re-serializes the JSON; trailer and sidecar keep the byte rule. A proof
from depth ≥ 1 that does not fit the file is *no proof found* with the reason
`SOURCE_CAPTURE`, never *tampered*: the file was made from that capture and
says so. No COSE, X.509, hashed URI or hard binding is checked — the proof
authenticates itself, and no C2PA state reaches the outcome, the labels or the
ceiling. The repository README says exactly what is and is not read.

## What is exported

| | |
|---|---|
| `verify` | the whole thing: trailer, canonical bytes, signature, §5 chain, attachments, §7 level |
| `coreHashOf`, `extractCore`, `jcs` | the identity of a proof and the canonical bytes it is over |
| `parseTrailer`, `canonicalBytes`, `detectContainer` | §3 and §4.1 on their own |
| `extractProof`, `PROOF_LABEL`, `SOURCE_CAPTURE` | where the proof is — trailer, C2PA manifest store, sidecar, `parentOf` chain — before anything about it is believed |
| `verifyChain`, `segmentMessage`, `recomputeSegments` | §5 at message level and from a container |
| `verifyRegistry`, `verifyKeyStatus`, `verifyAnchor`, `validateTimestamp`, `verifyIntegrity` | the §6.2 attachments, individually |
| `evaluateWatermark`, `captureIdHex`, `VIDEO_AGREEMENT_FLOOR` | §8's watermark table on its own, for a caller holding a detection and no file — and the floor, so a detector can apply it before it reports |
| `leafHash`, `nodeHash`, `verifyInclusion`, `verifyConsistency` | RFC 6962, shared by the log and the anchor |
| `positionLevel`, `verifyLocationCorroboration` | §7.1's position level on its own |
| `verifyVaultKey` | the log's statement about an organization's vault key (`vcap-vault-1.md`) — never part of a verdict |
| `parseTrustDocument`, `parseTrustedLog`, `parseTsaDocument`, `parseTsaRoot` | readers for a written trust set |
| `validateAndroidAttestation`, `googleRoots`, `parseCertificate` | §7's proven level |

The pieces are exported as well as `verify` because a service usually has one
question, not all of them — the platform validates an attestation at enrolment
and never touches a file.

`verifyConsistency` is there for the same reason it is a reader's check at all:
it catches a **split view**, a log showing one head to one reader and another
to another, and the party that would benefit from one is the log. So the
verification cannot live only in the log's own code, and the platform's tests
now check its proofs with this implementation rather than with the one that
made them.

## Consuming it

Published output is `dist` with declarations, so a service that compiles with
`tsc` can import it. Inside this repository the CLI and the page alias to
`src` instead: a build step between changing the core and seeing a test fail is
a step somebody skips, and stale `dist` is a worse failure than a slow one. CI
builds the package and imports it from plain Node so both paths stay honest.

Without a registry account, the way to depend on it is the one `spec` already
uses in four repositories: a git submodule and a `file:` dependency.

## The corpus is the contract

`npm test` runs every vector in `vcap-spec` — the submodule, with the committed
mirror in `vectors/` checked against it so a stale copy fails in CI rather than
quietly proving an older contract. An implementation passes conformance when it
reproduces every vector's `outcome`, `labels`, `not_evaluated`, `core_hash` and
`segments.verified`.
