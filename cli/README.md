# vcap-verify

A verdict from a shell.

```
npx vcap-verify photo.jpg
```

```
photo.jpg
  outcome   authentic
  level     claimed tee, proven none
  ceiling   amber — verified, with evidence missing (below)
  taken     before 2026-09-08T12:00:00.000Z (from the device's own clock — a claim)
  core      dc59127e528a04d6e285de3abe748559e49c7f1ef66b238092a6b13afeeb5119
  missing or worth knowing
    · key not in transparency log: nobody can confirm this signing key was registered
    · no trusted time: only the device's own clock says when this was taken
    · origin not hardware-attested: nothing proves the key lives in secure hardware
```

## It contacts nothing

Every check this makes is one the file carries the evidence for, which is the
whole promise of the format. So *revocation not checked* and *anchoring not
verified* are the normal answers here, and they are **answers**, not failures:
a verifier that cannot ask the log says so rather than guessing. A caller who
wants those closed reads the log and the chain themselves and uses
`vcap-verify-core` directly.

The anchors are yours to supply, because a verdict is only ever green against a
named set of them:

```
--log <log_id>:<base64 spki>   a transparency log to trust
--tsa-root <path.pem>          a TSA root to pin
```

Google's attestation roots are pinned in the library.

`--log` also decides the §7.1 position level: a `location_corroboration` is
the registry's countersignature of an operator's answer, so without the log's
key it reads *location corroboration not evaluated* and the position stays
*declared*. A position is never "guaranteed": the `position` line names the
level reached — `declared` or `corroborated` — and says what the registry
attests, never "verified by the operator".

## Exit codes

| | |
|---|---|
| `0` | authentic, or a verified clip |
| `1` | the file does not verify — tampered, no proof, or an unreadable one |
| `2` | the verdict is not green and `--require-green` was given |
| `64` | usage error |

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
and this tool has none and contacts nothing, so the detection comes from the
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
  "sampling": { "frames": 24, "strategy": "uniform" },
  "agreement": 0.94,
  "model_version": "videoseal-y256b-3"
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
