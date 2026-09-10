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
  now: new Date(…)                  // a §7 verdict depends on when it is asked
})
```

A verdict is only ever green **against a named set of anchors**. Google's
attestation roots are pinned in the library (`googleRoots`); logs and TSA roots
are yours to name, because the same bytes are green for a verifier that pins a
log and amber for one that does not, and both are right.

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
| `verifyRegistry`, `verifyKeyStatus`, `verifyAnchor`, `validateTimestamp` | the §6.2 attachments, individually |
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
