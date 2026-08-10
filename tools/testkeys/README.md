# TEST KEY MATERIAL — NOT PRODUCTION ROOTS

> **Everything in this directory is a throwaway key whose private half is
> committed to a public git repository.** It exists so the daemon's trust tests,
> the registry's fixtures and a developer's staging catalogue can exercise the
> real signature path without inventing a ceremony. It is not a secret, it never
> was a secret, and nothing a user will ever install may be signed with it.

The production root ceremony is [`../keygen-root.sh`](../keygen-root.sh), it is
run once by the maintainer on an offline machine, and its output never lands in
this repository. See [`../../SECURITY.md`](../../SECURITY.md).

## Why the daemon cannot be tricked into trusting these

`astra-daemon/src/plugins/trust.rs` compiles the two public keys below into the
binary **only** under

```rust
#[cfg(any(test, all(feature = "insecure-test-trust-roots", debug_assertions)))]
```

Three things have to be true at once for a build to contain them: the
`insecure-test-trust-roots` feature must be named explicitly (it is not in
`default`), `debug_assertions` must be on (it is off in every release profile),
and if you ask for the feature *without* `debug_assertions` the crate fails to
compile with a `compile_error!` that says so. A shipped binary cannot contain
these bytes.

The production root list in that same file is currently **empty**, because the
ceremony has not been run. An empty root set means no `trust.json` verifies,
which is the correct fail-closed behaviour for a chain whose anchor does not
exist yet — not a hole to be plugged with a test key.

## The keys

Both are Ed25519. Both are **deterministic**: the 32-byte seed is
`SHA-256(seed_phrase)`, so anyone can rederive them from the phrase alone and
prove that the copy compiled into the daemon and the copy in this directory are
the same key. `astra-daemon`'s `test_roots_match_the_published_seed_phrases`
test does exactly that, which is why there is no file path shared between the
two repositories.

| Role | key_id | seed phrase |
|---|---|---|
| Active | `TEST-ONLY-DO-NOT-TRUST-root-a` | `astra-registry TEST-ONLY root key A - NOT FOR PRODUCTION` |
| Reserve | `TEST-ONLY-DO-NOT-TRUST-root-b` | `astra-registry TEST-ONLY root key B (reserve) - NOT FOR PRODUCTION` |

```
TEST-ONLY-DO-NOT-TRUST-root-a  sT0w2UuCzf9J8kp2n7PllC/fQZs4ZNiDnkMnCMUqkNo=
  fingerprint 27acc4e124e0087b28c46fc2f909d7540c1b0fc3e45f49a146c9f0b8a848910b
TEST-ONLY-DO-NOT-TRUST-root-b  kjNqlEvEZof8jpVdaZQnCXB8lAi1kYTfeN0MZtFa1mI=
  fingerprint eb1d9ea06166909dcb0f96ffcabb3accf3c57652ead9aca526a63e0caf13d1cc
```

The **reserve** key is the one the acceptance test signs with, on purpose: the
whole point of shipping two roots is that the second one works without a daemon
release, and a reserve that is never exercised is a reserve that does not work.

## Files

```
TEST-ONLY-DO-NOT-TRUST-root-a.pub.json           public key, safe anywhere
TEST-ONLY-DO-NOT-TRUST-root-a.SECRET-TEST-KEY.json   private seed — see the banner
TEST-ONLY-DO-NOT-TRUST-root-b.pub.json
TEST-ONLY-DO-NOT-TRUST-root-b.SECRET-TEST-KEY.json
regenerate.mjs                                   rederives all four from the phrases
sign-trust.mjs                                   signs a trust.json `signed` block
fixtures/                                        signed documents the daemon tests read
```

## Regenerating

```sh
node tools/testkeys/regenerate.mjs          # rewrites the four key files
node tools/testkeys/regenerate.mjs --check  # verifies them without writing
```

Because the derivation is deterministic, `--check` failing means somebody edited
a key file by hand.

## Producing a signed `trust.json`

```sh
node tools/testkeys/sign-trust.mjs \
  --key TEST-ONLY-DO-NOT-TRUST-root-b \
  --in  tools/testkeys/fixtures/trust-unsigned.json \
  --out tools/testkeys/fixtures/trust-reserve-signed.json
```

The signature is over `SHA-256(domain ‖ 0x00 ‖ JCS(signed))` with
`domain = "astra.registry.trust/1"`, using `tools/lib/canonical.mjs`'s `jcs()` —
the same canonicaliser the index will be signed with in 3.2. The daemon's
`trust.rs` reimplements JCS in Rust; `fixtures/trust-reserve-signed.json` is
embedded byte-for-byte in a daemon test so the two implementations cannot drift
apart in silence.
