# vcap-verify-core

Verification of a vcap proof, isomorphic: the same verdict in a browser, in
Node, and inside the platform. **WebCrypto only** — no `Buffer`, no Node API,
no network.

```ts
import { verify } from 'vcap-verify-core'

const verdict = await verify(new Uint8Array(bytes))
verdict.outcome   // 'authentic' | 'verified_clip' | 'tampered' | …
verdict.labels    // what is missing, sorted (§8)
verdict.level     // { claimed, proven, ceiling } (§7)
verdict.location  // { claimed, level, declared? } (§7.1): none | declared | corroborated | authenticated — never a ceiling
```

## It contacts nothing, and that is the design

Every check here is one the file carries the evidence for. Two answers need a
network and the core will not go and get them — the **caller** supplies them,
and their absence is a labelled answer rather than a failure:

```ts
await verify(bytes, {
  trustedLogs: [{ logId, spki }],   // else: log not trusted
  tsaRoots: [der],                  // else: trusted time not evaluated
  keyStatus: async (keyIdHex, at) => …,  // else: revocation not checked
  readChain: async (chain, anchorId) => …, // else: anchoring not verified
  watermark: async (claim) => …,    // else: watermark not evaluated
  now: new Date(…)                  // a §7 verdict depends on when it is asked
})
```

A verdict is only ever green **against a named set of anchors**. Google's
attestation roots are pinned in the library (`googleRoots`); logs and TSA roots
are yours to name, because the same bytes are green for a verifier that pins a
log and amber for one that does not, and both are right.

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
    agreement: 0.94,                              // video-rep-v1
    frames_sampled: 24,
    sampling: { frames: 24, strategy: 'uniform' },
    model_version: 'videoseal-y256b-3'
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

Three things are deliberate and are the reason this is not a thin passthrough.

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
output — there is no key for it in v1.0, and minting one would put a server of
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

`validated_at` says which instant every certificate path was checked at and
**where that instant came from**: an RFC 3161 timestamp, a block on a public
chain, or the device's own clock — a claim. The same file reads differently
depending on which, so a verifier that could not say this would be hiding the
difference.

## What is exported

| | |
|---|---|
| `verify` | the whole thing: trailer, canonical bytes, signature, §5 chain, attachments, §7 level |
| `coreHashOf`, `extractCore`, `jcs` | the identity of a proof and the canonical bytes it is over |
| `parseTrailer`, `canonicalBytes`, `detectContainer` | §3 and §4.1 on their own |
| `verifyChain`, `segmentMessage`, `recomputeSegments` | §5 at message level and from a container |
| `verifyRegistry`, `verifyKeyStatus`, `verifyAnchor`, `validateTimestamp`, `verifyIntegrity` | the §6.2 attachments, individually |
| `evaluateWatermark`, `captureIdHex` | §8's watermark table on its own, for a caller holding a detection and no file |
| `leafHash`, `nodeHash`, `verifyInclusion`, `verifyConsistency` | RFC 6962, shared by the log and the anchor |
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
