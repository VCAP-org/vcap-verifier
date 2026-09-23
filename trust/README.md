# The default trust sets

Two documents, because they are two decisions. `logs.json` pins the
transparency logs a `registry` attachment is checked against (§6.2);
`tsa.json` pins the timestamping authorities a `timestamp` attachment is
checked against (§7). They are kept apart on purpose: the log in `logs.json`
is **ours**, and the authority in `tsa.json` is somebody else's. A reader who
refuses the first and keeps the second has taken a perfectly coherent
position, and one document with two arrays would have made that the awkward
case instead of the obvious one. The switches are separate everywhere —
`--no-default-logs` and `--no-default-tsa`, two panels on the page, two
sections in the app's Settings.

## Transparency logs

`logs.json` is the list of transparency logs the page and the CLI in this
repository check a `registry` attachment against unless the reader says
otherwise. It is **data**, not code: one JSON document, read by the CLI from
this directory, bundled into the page, and published unchanged as `logs.json`
next to the page so anyone can fetch it without an account and check it against
what the bundle actually pinned (`hashes.json` covers it like every other
shipped file).

## What pinning a log buys, and what it does not

A `registry` attachment is the proof that a device's sealing key was a leaf of
a named log under a tree head that log signed, before the capture. Verifying it
needs that log's public key. With it, *log not trusted* disappears and the
"key in log before capture" row of the level table applies. Without it, nothing
else changes: §8 treats a log outside the trust set as **absent evidence**, so
the verdict is a label weaker and never a failure.

## The log in here is ours

The one entry today is the **vcap development log**, and it is run by the same
people who write this verifier and publish the page. That is stated in the
document, printed by `vcap-verify --show-trust`, and shown on the page next to
the log. It matters because it is the one thing a list of operators invites a
reader to get wrong: this is a pin, not corroboration. It proves a key was in
*our* log. It does not prove we are honest. The log is readable without an
account — the signed tree head, the RFC 6962 proofs and the leaves in pages,
under `/api/v1/log/` — so anyone can download the leaves and rebuild the tree.
What is missing is a mirror somebody else keeps: reading a log from the party
that writes it catches a tree that contradicts itself, never one quietly
replaced for a single reader.

## Replacing it

Nothing here is compulsory, and that is the point — a default that quietly
became a requirement would destroy the claim the product rests on.

| where | how |
|---|---|
| CLI | `--show-trust` to read it, `--no-default-logs` to drop it, `--trust <file>` / `--log <id>:<spki>` to add |
| page | the *Transparency logs this page trusts* panel: a switch per log, a file input for your own document, and a box for a single `<log_id>:<base64 spki>` line |
| library | `vcap-verify-core` ships **no** default set; `verify(bytes, { trustedLogs })` is the whole interface, and `parseTrustDocument` reads a document like this one |

## The shape

```json
{
  "logs": [
    { "log_id": "base64url(SHA-256(spki))", "spki": "base64 DER SubjectPublicKeyInfo",
      "name": "…", "environment": "…", "operator": "…", "independent": false }
  ]
}
```

`log_id` is never taken on trust: `parseTrustDocument` recomputes it from
`spki` and refuses a document where the two disagree, because a key pinned
under an id no proof will ever cite looks exactly like a trust set that works.

## Timestamping authorities

`tsa.json` is the list of timestamping authorities the page and the CLI check a
`timestamp` attachment against. Same rules, same publication: read by the CLI
from this directory, bundled into the page, published unchanged as `tsa.json`
beside it and covered by `hashes.json`.

### What pinning a root buys, and what it does not

An RFC 3161 token binds the proof's **core hash** to an instant and is signed
by the authority. With a root it chains to, the verdict says *existed before
`<instant>`* and §7 validates every certificate path at that instant instead of
at the device's own clock. Without one, the attachment reads *trusted time not
evaluated*, the validated instant falls back to `device_clock`, and nothing
else changes — absent evidence, never a failure.

What a token proves is narrow, and the document says so in those words: **this
hash existed before that instant, and that authority said so.** It proves
nothing about who made the file or what it shows. A timestamp over a forged
file is a valid timestamp over a forged file.

### The authority in here is not ours

Unlike the log above, FreeTSA is a genuine third party — which is the whole
reason a token is worth more than our word, and the reason timestamping
sits at **level 1**: once the token is in the file, it is checkable
without us, forever. The caveats are in the document and printed everywhere it
is: a free community service with **no SLA and no contractual liability**, not
a qualified trust service under eIDAS, and no presumption of accuracy in court.

The root pinned here was not taken from a URL's word for it. It was fetched,
compared byte for byte against the root embedded in a real token this
platform's provider minted, and the token was verified against it — by
`openssl ts -verify` and by this repository's own core.

### Replacing it

| where | how |
|---|---|
| CLI | `--show-trust` to read it, `--no-default-tsa` to drop it, `--tsa-root <file.pem>` to add |
| page | the *Timestamping authorities this page trusts* panel: a switch per authority, a file input for your own document, and a box for a single `<sha256 fingerprint>:<base64 certificate>` line |
| library | `vcap-verify-core` ships **no** default set; `verify(bytes, { tsaRoots })` is the whole interface, and `parseTsaDocument` reads a document like this one |

### The shape

```json
{
  "authorities": [
    { "fingerprint_sha256": "lowercase hex SHA-256 of the DER certificate",
      "certificate": "base64 DER X.509 root",
      "name": "…", "environment": "…", "operator": "…", "independent": true,
      "proves": "…", "does_not_prove": "…", "caveats": ["…"] }
  ]
}
```

`fingerprint_sha256` is never taken on trust: `parseTsaDocument` recomputes it
from `certificate` and refuses a document where the two disagree. The
fingerprint is published so a reader can compare it with what their own
`openssl x509 -noout -fingerprint -sha256` prints, and that is worthless if the
file may name a certificate it does not hold.

Rotating a provider means a **new entry**, never an edit of an existing one:
tokens already minted keep chaining to the root that signed them.
