# Runbook

Operational procedures for the person who holds the keys. `SECURITY.md` says
*why*; this file says *what to type*.

Everything here assumes one maintainer. Where a bigger team would use a second
pair of eyes, this document says what compensates instead.

---

## Contents

1. [Where each thing lives](#1-where-each-thing-lives)
2. [The root ceremony](#2-the-root-ceremony)
3. [Signing `trust.json`](#3-signing-trustjson)
4. [Rotating the index key](#4-rotating-the-index-key)
5. [Promoting the reserve root](#5-promoting-the-reserve-root)
6. [Emergency revocation](#6-emergency-revocation)
7. [Testing the chain without any real key](#7-testing-the-chain-without-any-real-key)
8. [Upgrades this runbook is written to accept](#8-upgrades-this-runbook-is-written-to-accept)

---

## 1. Where each thing lives

| Thing | Where |
|---|---|
| Root private keys | Offline: paper/steel + an encrypted attachment in the password manager. Never on a networked machine, never in a repository. |
| Root public keys | `registry/v1/root.json` here, **and** `PRODUCTION_ROOT_KEYS` in `astra-rs/astra-daemon/src/plugins/trust.rs`. Two copies of one fact, on purpose. |
| `trust.json` | Published next to the index; cached by each daemon under `<config>/registry/trust.json`. |
| Index private key | GitHub Environment secret `ASTRA_INDEX_SIGNING_KEY` on the `publish` environment, with the maintainer as required reviewer. |
| Index public key | Inside the current root-signed `trust.json`. Nowhere else — that is what makes it rotatable. |
| Test keys | `tools/testkeys/`. Public *and* private, committed on purpose, trusted by no shipped build. |

The daemon's copy of `trust.json` lives in `<config>/registry/`, a **sibling** of
`<config>/plugins/` and never a child of it. Plugins run with their own install
directory as the working directory; nothing on the trust path may live inside a
tree the subject can write.

---

## 2. The root ceremony

Once, ever, unless §5 happens. Full rationale in `SECURITY.md` §3–4.

```sh
# On a machine with no network, from removable media:
tools/keygen-root.sh --i-am-offline --out /run/media/$USER/ASTRA-ROOT/keys
```

Then, in this order — the order matters, step 5 is irreversible:

1. Back up **both** private keys to paper/steel **and** to the password manager.
2. Verify the paper copy by transcribing it back and diffing.
3. Copy `root.json` (public only) to the online machine; commit it as
   `registry/v1/root.json`.
4. Paste both public keys into `trust.rs`'s `PRODUCTION_ROOT_KEYS` and run
   `cargo test -p astra-daemon plugins::trust`. The tests prove the keys parse,
   are distinct, and are not the test roots.
5. Wipe the ceremony machine's copies.

Do not skip step 4 in the same sitting. A `root.json` in the repository that the
daemon does not have is a catalogue nobody can verify; the reverse is worse.

---

## 3. Signing `trust.json`

`trust.json` is the only document a root ever signs. It names the index signing
keys and their validity windows.

The `signed` block:

```json
{
  "schema": "astra.registry.trust/1",
  "serial": 8,
  "issued_at": "2026-08-10T00:00:00Z",
  "expires_at": "2027-08-10T00:00:00Z",
  "index_keys": [
    {
      "key_id": "astra-reg-2026a",
      "public_key": "<base64 raw 32-byte Ed25519 public key>",
      "not_before": "2026-08-01T00:00:00Z",
      "not_after": "2026-11-01T00:00:00Z"
    }
  ],
  "reusable_workflow_shas": ["<40-hex commit sha>"]
}
```

Rules the daemon enforces, so get them right before you publish:

- **`serial` must be strictly greater** than the one the daemon already has.
  Equal is rejected, not accepted-as-idempotent: equal serials with different
  contents is exactly what a rollback attempt looks like.
- The signature covers `SHA-256("astra.registry.trust/1" ‖ 0x00 ‖ JCS(signed))`.
  Changing one byte of `signed` after signing invalidates it.
- Unknown fields inside `signed` are preserved and signed, and older daemons
  ignore them. Add fields freely; never repurpose one.
- `reusable_workflow_shas` is the allowlist §5.5 of the plan refers to. Changing
  it is a root ceremony, by construction — that is the point.

### 3.1 First, an index key to delegate to

A `trust.json` that delegates to nothing verifies perfectly and grants nothing —
every catalogue still reads `UNSIGNED`. So the index key comes first.

```sh
sh tools/keygen-index.sh --id astra-index-2026a
```

It writes three files and prints **no secret**: the private key
(`.private.pem`), the same key as the base64 raw seed the GitHub secret takes
(`.seed.b64`, mode 0600), and the public half (`.pub.json`) for the next step.

Unlike the root, this key is *meant* to live in CI. It is delegated, so a leak
costs one re-signing rather than a daemon release — which is the whole reason
the indirection exists. Generate it wherever you will paste it from.

```sh
gh secret set ASTRA_INDEX_SIGNING_KEY --env publish \
  --repo mihailinl/astra-registry < astra-index-2026a.seed.b64
gh secret set ASTRA_INDEX_SIGNING_KEY_ID --env publish \
  --repo mihailinl/astra-registry --body astra-index-2026a
```

### 3.2 Then sign, offline, with the root key on removable media

```sh
node tools/sign-trust.mjs \
  --root-key /run/media/$USER/ASTRA-ROOT/keys/astra-root-2026a.private.pem \
  --index-key-file astra-index-2026a.pub.json \
  --workflow-sha <40-hex commit of AstraPlugins' plugin-release.yml> \
  --out registry/v1/trust.json
```

The tool does no network I/O, so it belongs on the offline machine; carry
`registry/v1/trust.json` — and only that — back.

It refuses, rather than writes, when:

- the key is **not one of the roots published in `root.json`**. This is the
  guard worth having: signing with the reserve key, or last year's, produces a
  document that looks perfect, verifies against itself, and is refused by every
  daemon. You would hear about it from a user, and fixing it means another trip.
- no index key was given — §3.1.
- a `--workflow-sha` is not 40 hex characters. A tag will not do: it can be
  repointed, and this workflow runs inside every plugin author's repository.
- the index key is one of the TEST keys whose private half is committed here.

It verifies what it just signed, with the same code the bot uses, before writing.

`--serial` defaults to one more than the published document's. The daemon
requires **strictly greater**; equal is rejected rather than treated as
idempotent, because equal serials with differing contents is what a rollback
looks like.

### 3.3 Verify before you publish

```sh
node tools/sign-trust.mjs --verify registry/v1/trust.json
```

It prints the signing root, the serial, the expiry, every delegated index key
and the workflow allowlist. Read them: a delegation to the wrong key is
invisible until an install fails.

Then the other side of the wire, a separate implementation of the same
construction:

```sh
cargo test -p astra-daemon plugins::trust
```

`the_production_signers_output_verifies_here` is the one that matters — it feeds
this tool's output to the daemon's verifier, so a canonicalisation or
field-shape drift is a red build instead of a wasted ceremony.

### 3.4 By hand, if you ever need to

The tool is a convenience over four steps. They stay written down so that losing
it is an inconvenience rather than a lockout.

```sh
# 1. Write the `signed` block to trust-signed-block.json.
# 2. Canonicalise and hash it. The digest is over the domain string, a NUL, and
#    the JCS form of `signed`; that NUL is what stops one domain that is a
#    prefix of another from colliding with it.
node -e '
  import("./tools/lib/canonical.mjs").then(({ jcs }) => {
    const fs = require("node:fs"), crypto = require("node:crypto");
    const signed = JSON.parse(fs.readFileSync("trust-signed-block.json", "utf8"));
    const d = crypto.createHash("sha256")
      .update(Buffer.from("astra.registry.trust/1", "utf8"))
      .update(Buffer.from([0]))
      .update(Buffer.from(jcs(signed), "utf8"))
      .digest();
    fs.writeFileSync("trust.digest", d);
  })'

# 3. Sign the digest with the ACTIVE root. -rawin because Ed25519 hashes
#    internally; the message we hand it is our own digest.
openssl pkeyutl -sign -inkey /run/media/$USER/ASTRA-ROOT/keys/astra-root-2026a.private.pem \
  -rawin -in trust.digest -out trust.sig

# 4. Assemble { "signed": …, "signatures": [ { "key_id": …, "sig": base64 } ] }
openssl base64 -A -in trust.sig
```

Then copy `trust.json` — and only `trust.json` — back to the online machine,
verify it as in §3.3, and publish it. Confirm the fingerprint the daemon logs on
acceptance matches the one `keygen-root.sh` printed.

---

## 4. Rotating the index key

Quarterly, and immediately on suspicion. The planned form has a **30-day
overlap** so no window exists in which nothing can sign.

1. Generate a new index keypair and store the private half as the
   `ASTRA_INDEX_SIGNING_KEY` secret on the `publish` environment.
2. Sign a new `trust.json` (serial +1) whose `index_keys` contains **both**:
   the outgoing key with `not_after` = today + 30 days, and the incoming key with
   `not_before` = today.
3. Publish it. Daemons now accept an index signed by either key.
4. Switch the CI signer to the new key.
5. After the overlap, publish a `trust.json` (serial +1) with the old key
   removed.

**On suspicion, skip the overlap.** Publish a `trust.json` naming only the new
key, with the old key's `not_after` in the past. Then follow `SECURITY.md` §5.1
— rotation alone does not undo anything already published.

---

## 5. Promoting the reserve root

When the active root is compromised, or lost, or simply being retired.

1. Sign the next `trust.json` with the **reserve** private key. Serial +1 as
   always. Nothing else changes — every shipped Astra already carries the reserve
   public key, so it verifies on the next refresh with no update and no flag day.
2. Ship an Astra release that removes the retired root from
   `PRODUCTION_ROOT_KEYS` and adds a **newly generated** reserve, restoring the
   two-key invariant. Until that release is broadly installed, you are operating
   with one root; note the date you started and the date you consider it done.
3. Update `registry/v1/root.json` to match, in the same release window.
4. If the retirement is a compromise, publish an advisory naming the retired
   key's fingerprint so users can compare it to what their daemon logs.

The reserve is only real if it works. Exercise the path on the test roots
(§7) before you ever need it in anger — the daemon's own acceptance test signs
with the reserve rather than the active key for exactly this reason.

---

## 6. Emergency revocation

> **Not yet buildable.** `registry/v1/revocations.json`, `revoke.yml` and the
> daemon's five enforcement points land in 3.9. This section is written now so
> the procedure is decided before the incident, not during one; check the files
> exist before relying on it.

Target: signed and reachable within five minutes.

1. Add the entry to `registry/v1/revocations.json` — `kind` is one of `digest`,
   `version_range`, `publisher_key`, `identity`; include a human-readable
   `reason` and an advisory URL.
2. Run the `revoke.yml` workflow. It regenerates and signs revocations plus the
   index only, bypassing the site build.
3. Confirm the published `serial` is higher than the previous one, and that the
   file's age is under the daemon's 7-day revocation-freshness limit — past that,
   daemons block **new installs** with "Astra can't check whether this plugin has
   been withdrawn", which is a different and much noisier failure.

Digest-keyed revocation reaches a bundle however it arrived: the store, a local
import, or a copy from a friend. A source directory sideload has no archive and
therefore no digest — for those, the `binary_sha256` entry is what applies.

A stale index never disables a working plugin. Revocation takes effect only from
a **fresh, signature-valid** list, and the last applied revocation serial is
persisted so an attacker cannot un-revoke by serving an older list.

---

## 7. Testing the chain without any real key

Never rehearse with the production root. `tools/testkeys/` exists so you do not
have to.

```sh
# Rederive the test keys and prove the committed files match their seed phrases
node tools/testkeys/regenerate.mjs --check

# Sign a trust.json with the TEST reserve root
node tools/testkeys/sign-trust.mjs \
  --key TEST-ONLY-DO-NOT-TRUST-root-b \
  --in  tools/testkeys/fixtures/trust-unsigned.json \
  --out /tmp/trust.json

# Run a daemon that trusts the test roots — debug profile only; asking for this
# feature in a release profile is a compile error, by design.
cargo run -p astra-daemon --features insecure-test-trust-roots
```

The fixtures in `tools/testkeys/fixtures/` are the negative cases too: a
document signed by a well-formed non-root key, a genuinely-signed older serial,
and one whose serial was edited after signing. `astra-daemon` embeds them
byte-for-byte, so a change to either repository's canonicaliser breaks the other
repository's tests.

---

## 8. Upgrades this runbook is written to accept

Written down so they are decisions rather than aspirations. None is required
today; each becomes worth its friction at a specific moment.

| Upgrade | Take it when |
|---|---|
| Root private keys in a KMS / HSM instead of paper | The signing frequency stops being "a few times a year", or an audit asks. |
| A hardware security key for the root | Same trigger. A YubiKey with Ed25519 signs `trust.json` fine and removes the paper-transcription step. |
| A second custodian and an m-of-n root | The team reaches two people who are not on the same continent. Before that it is theatre: one person holding two shares is one person. |
| A transparency log for the index | Third-party clients appear, or someone asks to verify history without trusting a `git log`. |
| Automated `root.json` ↔ `trust.rs` drift check in CI | The moment the ceremony runs. Until the roots exist there is nothing to compare. |
