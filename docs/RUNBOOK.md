# Runbook

What to type, as the person who runs this registry. `SECURITY.md` says *why*;
this file says *what*.

**§1 is the one you need most nights** — a listing request is open and somebody
is waiting. Everything from §2 onwards is key custody, and most of it happens
once a year or once ever.

Everything here assumes one maintainer. Where a bigger team would use a second
pair of eyes, this document says what compensates instead.

---

## Contents

1. [A listing request is open — what do I do?](#1-a-listing-request-is-open--what-do-i-do)
2. [Where each thing lives](#2-where-each-thing-lives)
3. [The root ceremony](#3-the-root-ceremony)
4. [Signing `trust.json`](#4-signing-trustjson)
5. [Rotating the index key](#5-rotating-the-index-key)
6. [Promoting the reserve root](#6-promoting-the-reserve-root)
7. [Emergency revocation](#7-emergency-revocation)
8. [Testing the chain without any real key](#8-testing-the-chain-without-any-real-key)
9. [Upgrades this runbook is written to accept](#9-upgrades-this-runbook-is-written-to-accept)

---

## 1. A listing request is open — what do I do?

The whole procedure is: **check the label, read the bot's comment, type one
command.** Everything below is that, with the failure cases named.

You need nothing installed. Every step is a click or a comment on the issue.

### Step 1 — Does it have the `listing` label?

Open the issue and look at the labels.

**It does.** Go to step 2; the bot is already working.

**It does not, and the bot has commented** saying it reads as a listing request.
Add the label. One click.

```
The Labels box, right-hand side → listing
```

Adding the label starts verification on **this** issue within one run. Nothing
needs reopening and nothing needs retyping. That is why the bot asks for a
label rather than applying one itself: in this repository the label is an
authority token, not a category. A labelled issue may drive an ingest of a
repository this registry has never seen. An unlabelled one may only ask for a
re-check of something already listed. A bot that minted that label from the
shape of a body would let anybody who can copy a form choose which repositories
this registry downloads archives from.

**It does not, and the bot has said nothing.** That is a bug. Check
`gh run list --workflow=Ingest --limit 5 --repo mihailinl/astra-registry` for a
run against that issue. If there is no run at all, the event never fired; if
there is a green run with everything skipped, `bot/triage.mjs` decided the issue
is not a listing request and `bot/tests/policy.test.mjs` wants a case for it.

### Step 2 — Read the bot's comment

The run compiles a Rust manifest probe before it checks anything, so allow
minutes rather than seconds. When it finishes the bot comments with two tables:
the checks, then a **Publication** section with the outcome in bold.

Four outcomes, and only one of them needs you:

| The comment says | What to do |
|---|---|
| **Published** | Nothing. It is live. |
| **Publishing itself at `<time>`** | Nothing. It goes live at that time on its own. |
| **Held for a maintainer** | Step 3. This is the one. |
| **Not published** | Nothing. A check failed; the author fixes it and comments `/recheck`. |

The comment also states an SLA of 48 h from the moment it was posted. That
number is declared in `bot/lib/policy.mjs` and is a commitment about the three
blocking events only.

### Step 3 — Decide, in one comment

Read the `R_…` rows in the Publication table. They say exactly what is being
asked of you. There are only four:

| Row | What you are actually deciding |
|---|---|
| `R_FIRST_LISTING` | Is this a real plugin, named honestly, doing what it says? Once per plugin, ever. |
| `R_NEW_HIGH_RISK` | The release asks for a permission that reaches outside its own surface. Is the stated reason one a user would accept? |
| `R_IDENTITY_CHANGED` | The repository moved. Every installed copy is pinned to the old one. Is this the same author, or a takeover? |
| `R_CHECK_HELD` | A name one edit from a listed plugin, or a display name that collides. Is it a coincidence? |

Then comment **one line**:

```
/approve
```

or

```
/reject the licence is not one this registry allows — POLICY.md §4
```

Expect a new comment within minutes. For `/approve` it is a full check table
again with a line naming you and the time. For `/reject` it is your reason
quoted back to the author with what they can do next, and then the issue closes.

**Approving does not skip anything.** The entire ingest runs again from
scratch — the assets are re-downloaded, the attestation re-verified, the
manifest re-read, the digests re-hashed. A tag can be moved and a release asset
can be replaced between the hold and your yes, so what publishes is what *this*
run verified, never what an earlier one did. This is also why there is no
"approve the version I already looked at" command: there would be no way to
prove the bytes were the same ones.

**A rejection is a sentence, not a close.** `/reject` with nothing after it does
nothing and tells you so. A silent close is the one thing this flow will not do.

### When the command does not work

| The bot replies | What it means, and the fix |
|---|---|
| "is refused" … "role is `read`" | GitHub does report a role for you on **this** repository, and it is not `admin` or `maintain`. Check which account you commented from. An answered role stands: `author_association` cannot override it, because it is not a permission — `COLLABORATOR` is true for a `triage` role that cannot push a byte, and `CONTRIBUTOR` never expires. |
| "is refused" … "would not say" | The permission call itself failed **and** you are not the account this repository belongs to. Re-run it. If it keeps happening from the owner's account, that is a bug: `author_association: OWNER` is meant to carry the command through exactly this case. From any other account the fallback is to publish the listing by hand through a pull request — `bot/run-checks.mjs` is that path. |
| "would not say … but the event payload marks the comment `author_association: OWNER`" | Not a failure. `GITHUB_TOKEN` could not read `GET /repos/{owner}/{repo}/collaborators/{login}/permission` — it holds `contents: read`, and that endpoint is documented as needing push access — so the command was honoured on GitHub's own assertion that you are the repository's owner instead. **Whether the API path works at all with a real Actions token has not been observed in a live run**; if every `/approve` comes through this line, that is the answer. |
| "has nothing to act on here" | The issue carries no readable form. Ask the author to open a fresh request with the listing template. |
| Nothing at all | The command was not the first line you wrote, or it was inside a quoted reply. Post it alone, on its own line. |

### Reproducing a decision locally

Only worth doing when you disagree with the bot. It needs a Rust toolchain and
network access, and it writes nothing into this repository.

```sh
bot/manifest-probe/link-deps.sh
cargo build --release --manifest-path bot/manifest-probe/Cargo.toml
ASTRA_MANIFEST_PROBE=bot/manifest-probe/target/release/astra-manifest-probe \
  node bot/decide.mjs --repo you/dice-roller --tag v0.2.0 --submitter you --out /tmp/ingest
```

It prints the same comment the bot posts and exits `0` published, `1` refused,
`3` held, `4` delayed, `2` the bot itself broke. `--approved-by you` reproduces
what your `/approve` would decide.

The trust chain is provisioned, so this really does run: `registry/v1/root.json`
carries `astra-root-2026a` and its reserve, and `registry/v1/trust.json` is
signed by the active root at serial 1, delegating to `astra-index-2026a` and
allowlisting one reusable-workflow commit. An attestation from any other
workflow is refused, which is the point of the allowlist.

---

## 2. Where each thing lives

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

## 3. The root ceremony

Once, ever, unless §6 happens. Full rationale in `SECURITY.md` §3–4.

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

## 4. Signing `trust.json`

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

### 4.1 First, an index key to delegate to

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

### 4.2 Then sign, offline, with the root key on removable media

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
- no index key was given — §4.1.
- a `--workflow-sha` is not 40 hex characters. A tag will not do: it can be
  repointed, and this workflow runs inside every plugin author's repository.
- the index key is one of the TEST keys whose private half is committed here.

It verifies what it just signed, with the same code the bot uses, before writing.

`--serial` defaults to one more than the published document's. The daemon
requires **strictly greater**; equal is rejected rather than treated as
idempotent, because equal serials with differing contents is what a rollback
looks like.

### 4.3 Verify before you publish

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

### 4.4 By hand, if you ever need to

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
verify it as in §4.3, and publish it. Confirm the fingerprint the daemon logs on
acceptance matches the one `keygen-root.sh` printed.

---

## 5. Rotating the index key

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

## 6. Promoting the reserve root

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
(§8) before you ever need it in anger — the daemon's own acceptance test signs
with the reserve rather than the active key for exactly this reason.

---

## 7. Emergency revocation

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

## 8. Testing the chain without any real key

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

## 9. Upgrades this runbook is written to accept

Written down so they are decisions rather than aspirations. None is required
today; each becomes worth its friction at a specific moment.

| Upgrade | Take it when |
|---|---|
| Root private keys in a KMS / HSM instead of paper | The signing frequency stops being "a few times a year", or an audit asks. |
| A hardware security key for the root | Same trigger. A YubiKey with Ed25519 signs `trust.json` fine and removes the paper-transcription step. |
| A second custodian and an m-of-n root | The team reaches two people who are not on the same continent. Before that it is theatre: one person holding two shares is one person. |
| A transparency log for the index | Third-party clients appear, or someone asks to verify history without trusting a `git log`. |
| Automated `root.json` ↔ `trust.rs` drift check in CI | The moment the ceremony runs. Until the roots exist there is nothing to compare. |
