# The default trust set

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
*our* log. It does not prove we are honest, and until the log is publicly
readable and mirrored by somebody else, nobody outside the project can check
that it is append-only at all.

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
