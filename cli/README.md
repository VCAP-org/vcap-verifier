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

## Other options

```
--sidecar <path>     read the proof from a .vcap sidecar (single file only)
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
