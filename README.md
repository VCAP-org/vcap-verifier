# vcap-verifier

The public verifier: a static page that validates a sealed file entirely in the
browser, and the **isomorphic verification core** shared with the platform's API
and the server-side libraries.

Free, client-side, no account. This is the guarantee that makes everything else
sellable: anyone — a judge, a journalist, a customer who fell out with us — can
check a file without trusting us.

## Status

Phase 3. New implementation: the PoC verifier stays online for its own samples
and is not a code source.

## Design constraints

- **One verification core, four consumers** (this page, the platform API, the
  Node and Ruby libraries, the app's offline verdict). Same input, same verdict,
  same wording. The conformance suite from `vcap-spec` is a required CI gate in
  all of them.
- **No network in the verification path.** Registry proofs, anchors and QTSP
  chains are checked from data carried in the file or fetched from public
  endpoints; if there is no network the verdict degrades and says so.
- **Detector under 10 MB** (WebGPU with a WASM SIMD fallback), distilled from the
  large model, with a documented robustness curve. The verifier states which
  model it used.
- **Reproducible build**, bundle hash published, so an expert can prove which
  verifier produced a given verdict.

## Layout

```
core/    isomorphic verification core (TypeScript)
web/     the static verifier page
```

## Project documentation

This repository is code only. Plan, specification, decisions and market context
live in the project workspace, outside this repo:

- `Doc/01-piattaforma-build-spec.md` — components, epics, estimates, sequence
- `Doc/05-decisioni.md` — decision log (read before proposing an architectural change)
- `Doc/06-fase1-avvio.md` — phase 1 work order
- `AGENT.md` — workspace rules, naming conventions, product invariants
- `CHECKLIST.md` — the single work list; tick your line in the same commit

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
