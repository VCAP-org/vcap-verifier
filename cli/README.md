# vcap-verify

A verdict from a shell. Not published to npm: it runs from a clone of this
repository.

```
git clone --recurse-submodules https://github.com/VCAP-org/vcap-verifier
cd vcap-verifier && npm ci && npm run build -w core
npx vcap-verify photo.jpg
```

```
photo.jpg
  outcome   authentic
  level     claimed tee, proven none
  ceiling   amber — origin not hardware-attested, key not in transparency log
  taken     before 2026-09-08T12:00:00.000Z (from the device's own clock — a claim)
  core      dc59127e528a04d6e285de3abe748559e49c7f1ef66b238092a6b13afeeb5119
  missing or worth knowing
    · key not in transparency log: nobody can confirm this signing key was registered
    · no trusted time: only the device's own clock says when this was taken
    · origin not hardware-attested: nothing proves the key lives in secure hardware
```

## It contacts one thing: the chain an anchor names

For a proof with an `anchor`, the tool asks the public chain it names, through
the JSON-RPC endpoint `trust/chains.json` lists, which root the contract stored
(one read-only `eth_call`) — so anchoring is checkable without us. It sends the
anchor id, never the file. The endpoint is a **trust point**: the tool checks
its chain id and then believes the root, so a lying RPC could fake one. List
your own node with `--chains <file>`, or read nothing with `--offline`; a chain
that cannot be read gives *anchoring not verified*, an answer and not a
failure.

Every other check is one the file carries the evidence for, which is the whole
promise of the format. So *revocation not checked* is the normal answer here,
and it is an **answer**, not a failure: a verifier that cannot ask the log says
so rather than guessing. A caller who wants it closed reads the log and uses
`vcap-verify-core` directly.

The anchors are yours to supply, because a verdict is only ever green against a
named set of them:

```
--log <log_id>:<base64 spki>   a transparency log to trust
--trust <path.json>            a trust document, shaped like trust/logs.json
--no-default-logs              do not trust the logs this tool ships with
--show-trust                   print the logs and the authorities this run would trust
--tsa-root <path.pem>          a TSA root to pin
--no-default-tsa               do not trust the authorities this tool ships with
--chains <path.json>           the chains and RPC endpoints to read anchors with, shaped like trust/chains.json
--offline                      read no chain: anchors read *anchoring not verified*
```

Two sets, two switches, because they are two decisions: `trust/logs.json` is
ours and `trust/tsa.json` is somebody else's (`trust/README.md`). Refusing the
log we run must not also drop a third party's clock. Google's attestation roots
are pinned in the library.

## The one log it ships trusting

`trust/logs.json`, at the root of this repository, holds the **vcap development
log** — and that log is run by the same people who write this tool. It is a
pin, not a second opinion: a `registry` attachment that checks out against it
proves the sealing key was a leaf of *our* log before the capture, and proves
nothing about whether we are honest. `--show-trust` prints that in as many
words, along with each log's id and operator.

The set is a file you can read and edit, not a constant compiled in. Drop it
with `--no-default-logs` and bring your own with `--trust` or `--log`;
verifying against a set that contains none of ours is a supported way to run
this and costs exactly one check — a proof naming a log you do not follow reads
*log not trusted*, which §8 counts as absent evidence, never a failure.

`--log` also decides the §7.1 position level: a `location_corroboration` is
the registry's countersignature of an operator's answer, so without the log's
key it reads *location corroboration not evaluated* — or *not verified*, once
some log key is held and none of them signed it — and the position stays
*declared*. A position is never "guaranteed": the `position` line names the
level reached — `declared` or `corroborated` — and says what the registry
attests, never "verified by the operator".

## Exit codes

| | |
|---|---|
| `0` | authentic, or a verified clip whose frames were read back from the file |
| `1` | the file does not verify — tampered, no proof, an unreadable proof, or a clip whose frames could not be compared (`frames_not_compared`, or `--no-recompute`) |
| `2` | the verdict is not green and `--require-green` was given |
| `64` | usage error |
| `66` | a file could not be read — missing, a directory, a named sidecar absent; the others are still judged, and `--json` prints `{"file", "error"}` for it |
| `70` | an internal error of this tool |

`--require-green` cannot pass today: green needs the log's signed answer about
the key's revocation, and this tool asks no log, so every file that verifies
stays amber — at best *revocation not checked* — and exits `2` with it. It is a way to fail
closed, not a gate anything clears yet.

**The code answers "should I trust this file", not "did the tool run".** A
tampered file is a successful run of the tool and a failure of the file. And
`--require-green` is `2` rather than `1` on purpose: the file verifies, what is
missing is evidence, and a script may want to ask those separately.

Across several files the **worst** answer decides, so a check over a directory
cannot pass because the last file happened to be fine.

## JSON

`--json` writes one object per line — the verdict as `vcap-verify-core`
produces it, plus the file it is about — so a directory can be piped through
`jq` without the tool holding every verdict first.

```
vcap-verify --json shots/*.jpg | jq -r 'select(.level.ceiling != "green") | .file'
```

## The sidecar

A proof may sit beside the file instead of inside it (spec §3.1). The tool
reads `<file>.vcap` — the full filename plus `.vcap`, in the same directory —
when it exists, and looks nowhere else: no other name, no parent folder, no
URL from inside the proof. What it does with it is the spec's precedence, not
a preference: an intact trailer is the proof and a sidecar that differs from
it byte for byte is the label *sidecar differs*; a trailer found and broken is
*corrupted proof* whatever the sidecar says; no trailer and a sidecar is the
full verdict over the whole file, with no label for where the proof came from.

```
--sidecar <path>     name the sidecar yourself (single file only)
--no-sidecar         ignore any sidecar, verify the file alone
```

## The watermark

A proof may declare a `watermark` (§6.1): the writer saying a mark was embedded
in the pixels. Reading it back needs a detector — a model, a demux, frames —
and this tool has none and runs no model, so the detection comes from the
caller as a file:

```
--watermark <path.json>   a detection of the declared watermark (single file only)
```

The file is what a detector saw, not a verdict. The members it reads are the
ones the platform's `/v1/verify` already returns, so its `watermark` block goes
in unchanged:

```json
{
  "layout": "photo-bch-v3",
  "decoded": "00112233445566778899aabbccddeeff",
  "corrected_bits": 4,
  "frames_sampled": 1,
  "sampling": { "frames": 8, "strategy": "uniform" },
  "agreement": 0.94,
  "model_version": "videoseal-y256b-1"
}
```

`decoded` is the id that came out of the payload — hex for `photo-bch-v3`, the
decimal `mark_id` for `video-rep-v1` — or `null` when nothing decoded. The
**comparison is not the caller's**: the core makes it against the ids the
device signed, so §8's four rows are reached from the file's own bytes and a
detection that carries its own verdict word is not read.

| What the file says | What comes out |
|---|---|
| the declared id | *watermark matched* — a label, never a green verdict |
| `null` | *watermark not recovered*, with whatever figure the layout defines |
| an unreadable payload, an unknown layout, no file at all | *watermark not evaluated* |
| a different id, decoded | **red**: *tampered*, with the reason and no labels (§8) |

For `video-rep-v1` the table is reached only after the layout's agreement
floor: the id is read when `agreement` is present and at least **0.85**, and
below that the answer is *watermark not recovered* with the figure and no id —
never a match and never a contradiction. Eight bits of CRC over a 24-bit id
pass by chance about once in 256, and device recordings have resolved wrong ids
at 0.738 and 0.789, so an unbelievable id is refused rather than printed
(`core/README.md`). A detection with no `agreement` figure is *not evaluated*.

For a clip, add `frames_with_id`: how many of the `frames_sampled` frames
decoded to that id **on their own**, which a verifier reporting one answer for
several frames MUST report (§8). It is the only figure that separates a marked
recording from one genuine frame spliced into foreign footage — an unmarked
frame abstains rather than dissenting, so a decode taken over averaged frames
is set by any single marked one and a splice reports the real id at the
agreement of a clean recovery. `agreement` does not answer that question and is
never presented as if it did. A count with no `frames_sampled` beside it, or
larger than it, is dropped: "n of m" is one claim.

Without `--watermark` a declared watermark is *watermark not evaluated*, which
is what this tool has always said and is a weaker verdict, never an error.

## Other options

```
--no-recompute       do not recompute segment hashes from the container (§5)
--at <iso8601>       verify at a stated instant instead of now
```

`--at` exists because a §7 verdict depends on when it is asked: certificates
expire, and a proof read a year later is a different question from the same
proof read the next day. It is what makes a verdict reproducible in a bug
report.

`--no-recompute` is for a caller who has only a sidecar or a container this
tool cannot demux. Leaving recomputation **on** is the default because a
verifier that trusts the proof's own segment hashes has checked that somebody
signed some hashes, not that those are the frames in this file.

## Dependencies

`vcap-verify-core`, and nothing else. This tool exists so somebody can check a
file without trusting us, and every package in its tree is one more thing they
would have to trust — so the argument parsing is forty lines of `switch`.
