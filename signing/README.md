# Signed build manifests — what the signature proves, and what it does not

The page's build is reproducible: two clean checkouts of the same commit with
the pinned toolchain produce a byte-identical `web/dist`, and `hashes.json`
lists the SHA-256 of every shipped file. CI builds it twice and fails if the
two trees differ.

Reproducibility answers *are these the bytes that commit produces?* It does not
answer *who says so* — until now, the hashes were only as trustworthy as the
repository that carried them, and whoever controls the repository controls both
the hashes and the page.

This directory adds one detached Ed25519 signature over each published
manifest. It is deliberately a small claim.

## What it proves

- The manifest `hashes.json` you are holding was signed by the key whose public
  half is `public-key.pem`, and has not been edited since.
- That same key signed every earlier manifest in `manifests.jsonl`. A manifest
  signed by a different key, or an entry that does not verify, is visible
  immediately (`node bin/verify-build.mjs --log`).

That is **continuity**: today's publisher holds the key that published
yesterday. A takeover of the repository, of the host, or of a release does not
by itself get the key.

## What it does not prove

- **Not identity.** There is no legal entity behind this key (R4, still open),
  no certificate (D2), and no key-management service (D16). The signature says
  "the same key as last time" and cannot say "us", because there is no "us"
  that a third party could check against any register.
- **Not a qualified signature.** It is not eIDAS of any kind, not an advanced
  electronic signature, not a timestamped seal. Same discipline as the evidence
  report (D40): the limits are printed on the document rather than left to be
  discovered.
- **Not the first key.** Continuity starts at the first entry of
  `manifests.jsonl`. Anyone reading it for the first time is trusting a key they
  have no prior reason to trust; what the log gives them is the ability to
  notice a *change* later.
- **Nothing about the page's correctness.** A signed manifest of a backdoored
  build is a correctly signed manifest. The defence against that is the source
  being public and the build being reproducible — not this signature.
- **Nothing about a verified file.** This is the provenance of the *page*, never
  of a proof. A verdict on a file is computed from the file, and nothing in the
  verification path changes because a manifest is signed or unsigned.

## Where the key lives

The private key is `Ops/verifier-signing/ed25519-private.pem` in the project
workspace — a folder that is **not a repository** and never becomes one, and
that already holds the deploy SSH key and the environment secrets (workspace
`AGENT.md` rule 6, `Ops/README.md`). It is a bare Ed25519 key with no
passphrase, on one machine, backed up by hand with the rest of `Ops/`.

Stated plainly rather than dressed up: **whoever gets that machine's disk can
sign manifests.** There is no HSM and no KMS to say otherwise. That is why the
claim is limited to continuity — and why losing the key costs a documented
rotation and nothing more, since no file anyone holds depends on it.

Rotation, when it happens: sign with the new key, replace `public-key.pem` in
its own commit, and append a line to this file saying when and why. A rotation
is a break in continuity by definition; hiding it inside a routine commit would
be the only way to make it worse.

Key in use since 12 September 2026, fingerprint (SHA-256 of the SPKI DER):

```
51bc2b4da8376438dd529f0c3f9abfbdac8de0ebd7ce48a5f7065053b50614d4
```

(Recompute it: `openssl pkey -pubin -in public-key.pem -outform DER | sha256sum`.)

## What is signed, exactly

A three-line message, domain-separated, over the digest of the manifest — not
the manifest itself, so the whole signed message fits in one log line and can
be rebuilt by hand:

```
vcap/1.0/verifier-build\n<sha256 hex of hashes.json>\n<commit>\n
```

Ed25519, deterministic (like the evidence report's signature, D40), so the same
manifest always yields the same 64 bytes and a second signing run is a no-op
rather than a second record.

The signature lives in two places, both **outside** the reproducible tree:

- `hashes.json.sig` — 64 raw bytes, published next to `hashes.json` on the host;
- `manifests.jsonl` — one line per published manifest, append-only, in this
  repository: `{commit, build_id, manifest_sha256, key_sha256, sig}`.

It is outside `web/dist` on purpose. A signature inside the tree would change
the tree it certifies, so the build would stop reproducing the moment it was
signed — the signature would invalidate its own premise.

## Verifying by hand, without running anything of ours

Three independent checks. Nothing below needs our host, our scripts, or the
private key; steps 1 and 2 are worth doing even if you skip step 3 entirely.

**1. Rebuild the page and get the same hashes.**

```sh
git clone --recurse-submodules https://github.com/VCAP-org/vcap-verifier
cd vcap-verifier
git checkout <commit>            # the commit in hashes.json / the page footer
nvm use                          # exact Node from .nvmrc
npm ci                           # exact tree from package-lock.json
npm run build --workspace web
diff <(sort web/dist/hashes.json) <(curl -s https://verify.vcap.gregoriogalante.com/hashes.json | sort)
```

Identical means the published page is the page that commit produces. This step
alone is the substance; the signature only adds who published it.

**2. Check the served files against the manifest.**

```sh
curl -sO https://verify.vcap.gregoriogalante.com/verifier.js
sha256sum verifier.js            # compare with .files["verifier.js"] in hashes.json
```

**3. Check the signature on the manifest.**

```sh
curl -sO https://verify.vcap.gregoriogalante.com/hashes.json
curl -sO https://verify.vcap.gregoriogalante.com/hashes.json.sig
commit=$(sed -n 's/.*"commit": "\([0-9a-f]*\)".*/\1/p' hashes.json)
printf 'vcap/1.0/verifier-build\n%s\n%s\n' "$(sha256sum hashes.json | cut -d' ' -f1)" "$commit" > message
openssl pkeyutl -verify -rawin -in message -sigfile hashes.json.sig \
  -pubin -inkey public-key.pem
```

`Signature Verified Successfully` means the manifest carries the same key as
every earlier one. Get `public-key.pem` from this repository, at a commit older
than the build you are checking — a key fetched from the same host as the page
proves nothing at all.

**4. Check the whole history with one key.**

```sh
while read -r line; do
  commit=$(printf '%s' "$line" | sed -n 's/.*"commit":"\([0-9a-f]*\)".*/\1/p')
  digest=$(printf '%s' "$line" | sed -n 's/.*"manifest_sha256":"\([0-9a-f]*\)".*/\1/p')
  printf '%s' "$line" | sed -n 's/.*"sig":"\([^"]*\)".*/\1/p' | base64 -d > /tmp/sig
  printf 'vcap/1.0/verifier-build\n%s\n%s\n' "$digest" "$commit" > /tmp/msg
  openssl pkeyutl -verify -rawin -in /tmp/msg -sigfile /tmp/sig -pubin -inkey public-key.pem
done < manifests.jsonl
```

The equivalent one-liners, if you would rather run ours than write your own:

```sh
node bin/verify-build.mjs web/dist   # hashes, detached signature, log entry
node bin/verify-build.mjs --log      # every published manifest, one key
```

## Publishing (for whoever holds the key)

From a clean checkout, never from a working tree with changes — `sign-build`
refuses a manifest that records `dirty: true`, because a manifest nobody can
rebuild is the one thing this signature must not cover.

```sh
npm ci && npm run build --workspace web
node bin/sign-build.mjs                       # reads the key from Ops/
node bin/verify-build.mjs web/dist            # check before publishing
cd ../Platform && bin/push-verifier --dist ../Verifier/web/dist \
  --sig ../Verifier/web/dist/hashes.json.sig
```

Then commit the new line in `manifests.jsonl`. The log is the public half of
the record; a signature published on the host and never recorded here would be
a signature nobody can compare with the previous ones.
