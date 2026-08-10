# The registry bot

Two entry points, because there are two different questions.

| | `bot/ingest.mjs` | `bot/run-checks.mjs` |
|---|---|---|
| Input | a repository and a release tag | a hand-edited listing in a pull request |
| Trust boundary | **yes** | no — the reviewer is |
| Ownership | proved against GitHub | the reviewer |
| Attestation | verified, and pinned to an allowlisted workflow commit | not attempted |
| Listing | **written** by the bot, from the bundle | read, and checked against its artifacts |

`docs/BOT-CHECKS.md` is the reference: every code, what it means, what to do
about it, and — at least as important — the three checks that are heuristics and
what they do not catch. It is generated from `bot/lib/codes.mjs`, so it cannot
drift; `node bot/gen-checks-doc.mjs --check` fails when it has.

```bash
node bot/ingest.mjs --repo you/dice-roller --tag v0.2.0 --submitter you
# 0 listed · 1 refused · 3 held for a maintainer · 2 the bot itself failed
```

Today every run stops at `E_TRUST_UNPROVISIONED`, and that is correct:
`registry/v1/root.json` carries no root keys because the ceremony in
`SECURITY.md` has not been run, so there is no root-signed `trust.json` and no
reusable-workflow allowlist. The daemon compiles in an empty
`PRODUCTION_ROOT_KEYS` for the same reason. A trust chain whose anchor does not
exist must verify nothing, not everything.

## The language decision, and why it is not the one the plan wrote down

`PRODUCTION_PLAN` task 3.3 specifies **one Rust binary linking the shared
`astra-plugin-manifest` crate**. What landed is a **JavaScript pipeline plus a
small Rust helper that owns everything the shared crate decides**, and the
reasoning is worth writing down because the alternative looks tidier on paper.

The plan's real requirement is the *crate*, not the language: the registry must
not have its own idea of what a `plugin.toml` is. That requirement is met in
full — `bot/manifest-probe/` links `astra-plugin-manifest` and is the only thing
in this repository that parses a manifest.

Porting the *rest* of the bot to Rust would have meant reimplementing
`tools/validate.mjs`, and that file is the reason the pull-request path and CI
cannot disagree about what a valid listing is. There would then be two
definitions of a valid listing — one in Rust for releases, one in JavaScript for
pull requests — which is precisely the fork task 3.7 exists to delete, moved to a
different file. The same argument applies to `tools/lib/canonical.mjs` (RFC 8785,
byte-matched against the daemon's Rust implementation and against the RFC's own
vectors), to `tools/lib/zip.mjs`, and to `bot/lib/sign.mjs`.

So the split is by *what owns the definition*, not by language:

- **Rust, because the daemon owns the definition:** `plugin.toml` — the parse,
  the `plugin.id` charset, reserved device names, the capability vocabulary,
  `min_astra_version`, the platform-key mapping.
- **JavaScript, because this repository owns the definition and already has
  exactly one of it:** listing rules, canonical JSON, signatures, the ZIP
  reader, GitHub, orchestration.

What that costs, stated plainly: one subprocess per bundle, and a build step
that has to succeed before an ingest can run. `bot/lib/probe.mjs` treats a
missing probe as `E_PROBE_UNAVAILABLE` at **error** level rather than skipping
the manifest checks, because a bot that quietly stops validating manifests on a
runner where the build failed — and reports success — is a worse outcome than a
red run.

A JavaScript reimplementation of manifest parsing was never on the table.

### Getting the crate

There is **no copy of `astra-plugin-manifest` in this repository.** Astra is the
source of truth, AstraPlugins vendors it under a byte-equality check
(`tools/check-manifest-crate.sh` there), and a third copy here would be a third
place to drift silently.

```bash
bot/manifest-probe/link-deps.sh          # symlink a sibling AstraPlugins checkout
ASTRA_PLUGINS_DIR=/path/to/AstraPlugins bot/manifest-probe/link-deps.sh
bot/manifest-probe/link-deps.sh --clone  # CI, with ASTRA_PLUGINS_REF pinned to a SHA
cargo build --release --manifest-path bot/manifest-probe/Cargo.toml
```

`.github/workflows/ingest.yml` pins `ASTRA_PLUGINS_REF` to a commit SHA. Bumping
it is a reviewed commit, because it changes the rules a stranger's listing is
judged by.

## What runs, in order

1. **The allowlist**, out of a root-signed `trust.json`. First, not last: if
   there is no root, the bot has no basis for any conclusion and should not
   spend a stranger's bandwidth pretending otherwise.
2. **Ownership.** `GET /repos/{o}/{r}/collaborators/{u}/permission` requiring
   `admin` or `maintain`, then `.well-known/astra-plugin-owner` on the default
   branch, then the account that published the release. `docs/BOT-CHECKS.md`
   says what each one establishes and why a nonce challenge file is not the
   primary.
3. **The release**, its `.astraplugin` assets, and that every URL sits under
   `github.com/<repo>/releases/download/<tag>/` — the same check a user's daemon
   repeats locally against its TOFU pin.
4. **`HEAD`, then download under a cap, then hash.** The cap is enforced from
   the `HEAD`: a bot that has to download something to discover it is too big
   has no size cap.
5. **The attestation** — `gh attestation verify --repo --signer-workflow`, and
   then the resolved reusable-workflow commit against the allowlist from step 1.
   The second half is what makes the first mean anything: verifying an
   attestation without pinning which workflow produced it proves only that
   GitHub built something.
6. **The archive**, in memory. Nothing is ever extracted. The single moment a
   bundle touches a filesystem is a whole-file write into a `mkdtemp` directory,
   because `gh attestation verify` takes a path.
7. **`plugin.toml`**, through the Rust probe.
8. **Names, metadata, licence, versions, identity**, and the host-RPC scan.
9. **The listing is written** — and then run past `tools/validate.mjs`, the same
   code CI applies to every hand-written listing. The bot's output is held to the
   rules its input would have been.

## What it is allowed to do

Read the network, read this repository, write a report. `--out DIR` puts the
derived listing where a separate, minimal job can commit it. **The bot never has
write access to anything**, which is also why task 3.4's release ping can be an
unauthenticated payload carrying nothing but `owner/repo/tag`: an attacker who
forges one can at most cause a re-check of a listing that is already pinned to a
repository identity.

`.github/workflows/ingest.yml` enforces that split — `check` downloads a
stranger's archive with `contents: read` and no secrets; `comment` has
`issues: write` and runs no code from the submission at all, reading one markdown
file out of an artifact. Stranger-controlled text never reaches a `run:` block
through `${{ }}`.

## Signing the catalogue

`node bot/sign-index.mjs --in dist/index.json --out dist/index.json`

`registry/v1/index.json` is a `{ "signed": …, "signatures": [ … ] }` envelope.

```
sig = Ed25519(index_priv, SHA-256("astra.registry.index/1" ‖ 0x00 ‖ JCS(signed)))
```

`JCS` is RFC 8785 from `tools/lib/canonical.mjs` — the same canonicaliser
`trust.json` is signed with, and the one `astra-daemon`'s `plugins/trust.rs`
reimplements in Rust. `bot/fixtures/index/catalogue-signed.json` is signed here
and embedded byte-for-byte in a daemon unit test, so the two implementations
cannot drift apart in silence. Both suites also assert the SHA-256 of the
canonical form of RFC 8785 §3.2.3's own vector.

**Only `signed` is covered.** `$comment`, and the `key_id` on each signature, are
outside it. `key_id` is a hint for logs and key selection: the verifier tries
every trusted key against every offered signature, so a document that lies about
who signed it still verifies if a trusted key actually did, and never verifies
because it claimed the right name.

**The key never touches a command line.** `ASTRA_INDEX_SIGNING_KEY` (base64 of
the raw 32-byte seed) and `ASTRA_INDEX_SIGNING_KEY_ID` come from the `publish`
environment's secrets. A key on a command line is a key in the shell history, in
`ps` output for every other account on the runner, and in the Actions log the
first time somebody turns on command tracing. `--test-key` uses the throwaway
keys in `tools/testkeys/` and refuses to write into `registry/`.

**The generator stamps no time; the signer does.** `issued_at` and `expires_at`
are properties of the publication, not of the content. `--ttl-days` defaults to
30. What that expiry buys is bounded and the daemon is built around the bound: a
stale catalogue downgrades Browse to a banner and **records already pinned by
digest stay installable**, because a digest does not expire. The hard block lives
on `revocations.json` at seven days instead — the one document whose staleness
means "we may be about to install something already withdrawn".

## Tests

```bash
node bot/tests/ingest.test.mjs                                  # the bot
cargo test --manifest-path bot/manifest-probe/Cargo.toml        # the manifest rules
node tools/selftest.mjs                                         # the listing rules
node bot/gen-checks-doc.mjs --check                             # the docs
```

`bot/tests/ingest.test.mjs` runs the **whole pipeline** over every one of the 27
shared bundle vectors in `tests/vectors/` — vendored from
`AstraPlugins/testdata/bundles`, and consumed by the CLI's suite and the daemon's
too — and asserts the verdict recorded in that file's `expect.registry` column.
Three of those verdicts are recorded *divergences* (`duplicate-entry-case`,
`mode-mismatch`, `permissions-hash-mismatch`): the registry accepts them today.
This bot now reports all three, as **warnings**, because turning them into
rejections would make the shared corpus disagree with itself — closing them is a
change to `AstraPlugins/testdata/bundles/vectors.json` and to all three suites at
once, which is exactly the coordination that file exists to force.

Everything else is one test per failure class, each asserting the fixed code, and
the run ends by printing which declared codes no test provoked.
