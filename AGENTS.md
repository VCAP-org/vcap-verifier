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
  failure this project cannot afford.
- No analytics, no telemetry, no uploads. Nothing leaves the browser, and that
  must stay auditable in a single read of the source.
- Publish the failures too: the demo set includes the cases where verification
  cannot conclude.
- Keep the page usable offline and archivable.

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
