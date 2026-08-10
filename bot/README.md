# The registry bot — Phase 2 half

`node bot/run-checks.mjs --plugin <id> [--version <semver>]`

Flags: `--registry-dir DIR`, `--bundle-dir DIR`, `--offline`, and the two
tolerances it passes straight through to `tools/validate.mjs` —
`--allow-staging` (a listing with no digest) and `--allow-direct` (an artifact
origin that is not a GitHub release). Both mean, and cost, exactly what they do
there.

It runs every submission check that needs no cryptography, prints the comment it
would post, and exits non-zero if anything blocking failed.

## What it checks today

| Code | Check |
|---|---|
| `E_LISTING` | The whole of `tools/validate.mjs`: schema, id safety as a path component, reserved names, confusable collisions, licence allowlist, size caps, and that every artifact URL sits under the declared release of the declared repository. |
| `E_ASSET_MISSING` | The GitHub Release exists and has an asset with the listed filename. On a `direct` release there is no release to ask, so this row is skipped by name and the listed URL is fetched instead — every check below still runs on the real bytes. |
| `E_ASSET_SIZE` | The asset's size is the size the listing claims. |
| `E_DIGEST_MISMATCH` | The downloaded bytes hash to the listed `sha256`. |
| `E_ARTIFACT_TOO_LARGE` | Under `policy/limits.json` `max_artifact_bytes`. |
| `E_BUNDLE_*` | Archive structure: entry and extraction caps, no duplicate names, no `..`, no absolute or Windows-style paths, no `:` (NTFS alternate data streams), no trailing dot or space, **no symlink entries**. |
| `E_MANIFEST_*` | `MANIFEST.json` is the first entry and stored; it is `astra.bundle/2`; its `plugin_id`, `version` and `platform` match the listing; `files` is sorted and **exhaustive in both directions**; every listed file's size and SHA-256 match the archive. |
| `E_MANIFEST_HEADER_DISAGREE` | The manifest reached through the central directory is byte-identical to the one at offset 0. A ZIP's central directory is appended last and nothing in the format forces it to describe the archive it is attached to, so a crafted bundle can file benign bytes under `MANIFEST.json` in the index while byte zero — which is what the daemon reads — holds another. Two readings, compared. |
| `E_MANIFEST_LOCAL_HEADER` | Byte zero is a stored local file header for `MANIFEST.json` at all. |
| `E_ENTRY_*` | `entry.command` is relative, does not escape the install directory, is not a shell, and is either a file in the bundle or a declared runtime. |

Two properties of that list are worth stating.

**The listing half is delegated, not reimplemented.** `run-checks.mjs` calls
`tools/validate.mjs` and filters the result. CI and the bot must not be able to
disagree about what a valid listing is, and the only way to guarantee that is
for there to be one implementation.

## Signing the catalogue

`node bot/sign-index.mjs --in dist/index.json --out dist/index.json`

`registry/v1/index.json` is a `{ "signed": …, "signatures": [ … ] }` envelope.
The signature is

```
sig = Ed25519(index_priv, SHA-256("astra.registry.index/1" ‖ 0x00 ‖ JCS(signed)))
```

where `JCS` is RFC 8785 from `tools/lib/canonical.mjs` — the same canonicaliser
`trust.json` is signed with, and the one `astra-daemon`'s `plugins/trust.rs`
reimplements in Rust. `bot/fixtures/index/catalogue-signed.json` is signed here
and embedded byte-for-byte in a daemon unit test, so the two implementations
cannot drift apart in silence. Both suites also assert the SHA-256 of the
canonical form of RFC 8785 §3.2.3's own vector.

Three properties are worth stating.

**Only `signed` is covered.** `$comment`, and the `key_id` on each signature,
are outside it. `key_id` is a hint for logs and key selection: the verifier
tries every trusted key against every offered signature, so a document that lies
about who signed it still verifies if a trusted key actually did, and never
verifies because it claimed the right name.

**The key never touches a command line.** `ASTRA_INDEX_SIGNING_KEY` (base64 of
the raw 32-byte seed) and `ASTRA_INDEX_SIGNING_KEY_ID` come from the `publish`
environment's secrets. A key on a command line is a key in the shell history, in
`ps` output for every other account on the runner, and in the Actions log the
first time somebody turns on command tracing. `--test-key` uses the throwaway
keys in `tools/testkeys/` and refuses to write into `registry/`.

**The generator stamps no time; the signer does.** `issued_at` and `expires_at`
are properties of the publication, not of the content. Stamping them in
`tools/build-index.mjs` would make a catalogue nobody edited for 31 days expire
itself, and would make the generator's output unreproducible — which
`--check`, CI's determinism diff, and any third party rebuilding the index from
the git tree all depend on. `--ttl-days` defaults to 30.

What that expiry buys is deliberately bounded, and the daemon is built around
the bound: a stale catalogue downgrades Browse to a banner and **records already
pinned by digest stay installable**, because a digest does not expire. The hard
block lives on `revocations.json` at seven days instead — the one document whose
staleness means "we may be about to install something already withdrawn".

`--verify FILE --trust FILE` checks a signed catalogue against the index keys a
root-signed `trust.json` delegates to. CI runs it after signing, against the
*published* `trust.json` rather than against the key it just signed with: the
first proves the crypto library works, the second proves the daemon will accept
the result.

**Nothing extracts anything.** Every archive check runs against bytes in memory,
through `tools/lib/zip.mjs`, which reads the ZIP central directory and hands
back an entry table. A hostile bundle never reaches a filesystem here — not the
runner's, and not by accident.

## What it does not check — the important half

The bot prints all of these as skipped rows on **every** run, from
`bot/lib/phase3.mjs`. That is deliberate: a checklist that shows only what
passed reads as a clean bill of health, and someone eventually cites "the bot
approved it" for a property the bot never looked at.

- **`E_ATTESTATION_MISSING` — build provenance.** Nothing here proves who
  produced an artifact. The digest proves the bytes match the listing; it says
  nothing about where the bytes came from. Phase 3.3 adds
  `gh attestation verify`, and until it lands *this bot is not a trust
  boundary* — it is a consistency checker.
- **`E_WORKFLOW_NOT_ALLOWED`** — the resolved reusable-workflow SHA against a
  root-signed allowlist. Phase 3.1 + 3.3.
- **`E_OWNERSHIP_UNPROVEN`** — that the submitter controls the repository.
  Phase 3.3; a maintainer's judgement today.
- **`E_IDENTITY_CHANGED`** — a listing that changes its source repository is a
  different author. Phase 3.5.
- **`E_PERMISSIONS_WIDENED`** — `[permissions]` does not exist in the manifest
  yet; consent is Phase 4.
- **`E_HOST_RPC_UNDECLARED`** — the declared-vs-called host RPC scan. Phase 3.3.
  `POLICY.md` says plainly that it catches accidents, not a determined attacker.
- **`E_REVOKED`** — there is no signed revocation list until Phase 3.9.
- **`E_INDEX_UNSIGNED`** — the index this repository publishes is unsigned in
  Phase 2.

## Why this is JavaScript, when the plan says Rust

`PRODUCTION_PLAN.md` task 3.3 specifies the full bot as **one Rust binary
linking the shared `astra-plugin-manifest` crate**, so it validates with the
daemon's own code. That is the right end state and this skeleton does not change
it.

It is JavaScript today for one reason: the crate does not exist yet (task 3.7),
so a Rust bot would have to grow its own second copy of manifest validation —
which is precisely the duplication task 3.7 exists to delete. Writing that copy
now would create the drift the plan is trying to prevent, and it would have to
be thrown away in the same phase that fixes it.

So the split is:

- **Now:** the crypto-free checks run, in the same language and the same process
  as `tools/validate.mjs`, sharing one implementation of every listing rule.
- **Phase 3.3:** the Rust binary lands, links `astra-plugin-manifest`, and takes
  over. The error-code vocabulary above is chosen to survive that move
  unchanged, so the issue comments and the policy documentation do not churn.

`tools/lib/zip.mjs` and `bot/lib/bundle.mjs` are the parts with real logic worth
porting; they are written to be read alongside the daemon's `bundle.rs`, and
`tools/selftest.mjs` covers them with the same adversarial cases task 3.11 wants
as cross-repo golden fixtures (extra file, missing file, duplicate name, symlink
entry, swapped payload, manifest naming another plugin).

## Local use

```bash
# against a real release, with network
node bot/run-checks.mjs --plugin dice-roller

# against bundles you already have, no network
node bot/run-checks.mjs --plugin my-plugin --bundle-dir ./dist

# judge a tree that is not this repository (what the tests do)
node bot/run-checks.mjs --registry-dir /tmp/fx/digest-ok --plugin fixture-plugin \
                        --bundle-dir /tmp/fx/artifacts
```

`GITHUB_TOKEN` is used for rate limit only. **The bot never needs write access
to anything** — it verifies everything it reads from scratch, which is also why
Phase 3.4's release notification can be an unauthenticated ping carrying nothing
but `owner/repo/tag`.
