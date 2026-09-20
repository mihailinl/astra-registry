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
7. [Withdrawing a plugin](#7-withdrawing-a-plugin)
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

### Step 2a — If the refusal is `E_OWNERSHIP_UNPROVEN`

The most common refusal, and the one most likely to be aimed at you in a
follow-up comment. **Do not work around it by publishing the listing by hand.**
The fix is one commit in the author's repository, and the bot's comment already
leads with it:

```
mkdir -p .well-known
echo THEIR-GITHUB-LOGIN > .well-known/astra-plugin-owner
```

Then they comment `/recheck` on the same issue. Nothing needs reopening.

| What the refusal says | What it means, and what you do |
|---|---|
| "there is no `.well-known/astra-plugin-owner` on that branch (HTTP 404)" | The ordinary case. The file has not been created, or it landed on a branch that is not the default one. Point at the two lines above. |
| "the file is there but does not name you: it lists `…`" | A typo, a second account, or an organisation listing its release bot. The refusal prints what the file *does* contain, so compare it with the issue's author by eye. Adding a line and `/recheck` is the whole fix. |
| "GitHub reports @x has `write` on …" | Not a visibility problem: GitHub answered directly, and the answer was that this account is not `admin` or `maintain`. The owner file does **not** override that, on purpose — it speaks where GitHub will not, it does not overrule GitHub where it will. Someone with `admin`/`maintain` opens the request, or grants the role. |
| "the file could not be read (HTTP 403)" | Not a private repository — GitHub hides those, so a private one comes back **404** and lands in row 1. A 403 here is the repository being blocked, or a token that may not read it. |
| "the bot ran out of GitHub API requests before it could read the file" | Rate limiting (403 with `x-ratelimit-remaining: 0`, or 429). Nothing was learnt about the file, so the refusal does **not** tell the author to commit one; it asks for a `/recheck`. If a run of submissions all say this, wait for the window to reset rather than answering them one by one. |
| Any mention of a **403 or 404 from the collaborator** endpoint | You should never see this in a comment. It means the bot's token cannot see that repository's collaborator list — true of every repository this registry does not itself own, and evidence of nothing. If it is being reported to an author as a finding, that is a bug in `bot/lib/ownership.mjs`: it belongs in the audit trail (`tried`), never in the comment. An **answered** collaborator call is a different fact and belongs in the comment — that is row 3. |

Two things worth knowing before you answer a question about it. The file proves
**write access to the default branch**, not legal ownership — so "prove you own
it" is not what is being asked, and saying so avoids an argument nobody here can
settle. And it is read live on every run that consults it: an author handing a
plugin over removes their login and adds the new one, and the next *listing
request or `/recheck`* follows the file. It does not follow a release ping or
the cron backstop — those prove the release against the account that published
it (`resolveSubmitter`, `bot/lib/notify.mjs`), so the outgoing maintainer's own
releases would still ingest. If someone asks you to cut a person off entirely,
that is a repository-side question, not a file-side one.

### Step 3 — Decide, in one comment

Read the `R_…` rows in the Publication table. They say exactly what is being
asked of you. There are only four:

| Row | What you are actually deciding |
|---|---|
| `R_FIRST_LISTING` | Is this a real plugin, named honestly, doing what it says? Once per plugin, ever. |
| `R_NEW_HIGH_RISK` | The release asks for a permission that reaches outside its own surface. Is the stated reason one a user would accept? |
| `R_IDENTITY_CHANGED` | The repository moved. Every installed copy is pinned to the old one. Is this the same author, or a takeover? |
| `R_CHECK_HELD` | A name one edit from a listed plugin, or a display name that collides. Is it a coincidence? |

Then comment **one line**. For a yes, that line is printed in the bot's own
comment, in a code block, ready to copy — **do not retype it from memory**:

```
/approve you/dice-roller@v0.2.0 4f1c9a02be773d15
```

or

```
/reject the licence is not one this registry allows — POLICY.md §4
```

Expect a new comment within minutes. For `/approve` it is a full check table
again with a line naming you, the time, and the submission you cleared. For
`/reject` it is your reason quoted back to the author with what they can do next,
and then the issue closes.

**Approving does not skip anything.** The entire ingest runs again from
scratch — the assets are re-downloaded, the attestation re-verified, the
manifest re-read, the digests re-hashed. A tag can be moved and a release asset
can be replaced between the hold and your yes, so what publishes is what *this*
run verified, never what an earlier one did.

**And it applies to nothing but what you read.** The last field of the line is a
fingerprint of that submission: the repository, the tag, the version, and the
digest of every asset that run hashed. The re-run works it out again from the
release in front of it and compares. So the answer to "what if it changed between
my reading it and my yes" is no longer only *the checks would run again* — it is
**the approval is refused, and you are told what moved**: `P_APPROVAL_STALE`, a
comment naming both fingerprints, and a fresh line to copy if you still want to
say yes. There is still no "publish the version I already looked at" command, and
there never will be; the bytes are re-fetched every time. The fingerprint buys
the other half — that the bytes being re-fetched are the ones you meant.

The case that made this necessary does not look like an attack while it is
happening: **the issue body belongs to its author.** They can edit the repository
and tag fields at any time, including after the bot posts the hold and before you
answer it. A bare `/approve` meant "approve whatever this issue says right now",
so two edits were enough to point your yes at a release you never saw. If you get
*"this issue no longer describes what you approved"*, read the issue's edit
history before you retype anything.

**A rejection is a sentence, not a close.** `/reject` with nothing after it does
nothing and tells you so. A silent close is the one thing this flow will not do.

### When the command does not work

| The bot replies | What it means, and the fix |
|---|---|
| "is refused" … "role is `read`" | GitHub does report a role for you on **this** repository, and it is not `admin` or `maintain`. Check which account you commented from. An answered role stands: `author_association` cannot override it, because it is not a permission — `COLLABORATOR` is true for a `triage` role that cannot push a byte, and `CONTRIBUTOR` never expires. |
| "is refused" … "would not say" | The permission call itself failed **and** you are not the account this repository belongs to. Re-run it. If it keeps happening from the owner's account, that is a bug: `author_association: OWNER` is meant to carry the command through exactly this case. From any other account the fallback is to publish the listing by hand through a pull request — `bot/run-checks.mjs` is that path. |
| "would not say … but the event payload marks the comment `author_association: OWNER`" | Not a failure. `GITHUB_TOKEN` could not read `GET /repos/{owner}/{repo}/collaborators/{login}/permission` — it holds `contents: read`, and that endpoint is documented as needing push access — so the command was honoured on GitHub's own assertion that you are the repository's owner instead. **Whether the API path works at all with a real Actions token has not been observed in a live run**; if every `/approve` comes through this line, that is the answer. |
| "has nothing to act on here" | The issue carries no readable form. Ask the author to open a fresh request with the listing template. |
| "`/approve` has to name what it is approving" | You typed the bare word, or the line lost a field on the way into the comment box. Copy the whole line out of the bot's **Held for a maintainer** comment: `/approve <owner/repo>@<tag> <fingerprint>`. |
| "this issue no longer describes what you approved" | The repository or tag in the issue is not the one your command named. **Look at the issue's edit history before doing anything else** — this is what an author swapping a submission under review looks like from here, and it is also what a stale browser tab looks like. If the issue as it stands is what you meant, comment `/recheck`, read the new comment, and copy the line out of *that* one. |
| `P_APPROVAL_STALE` in the new comment | Your command was well formed and named an earlier state of the release: the tag moved, or a release asset was replaced, after the comment you answered. Nothing published and the hold stands. Re-read the table as it now is; the same comment prints the current line. |
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
`3` held, `4` delayed, `2` the bot itself broke.

To reproduce what your `/approve` would decide, run it once as above, take the
fingerprint out of the `/approve` line it printed, and run it again with all
three flags:

```sh
… node bot/decide.mjs --repo you/dice-roller --tag v0.2.0 --submitter you \
    --approved-by you --approved-at 2026-08-14T09:00:00Z \
    --approved-for 4f1c9a02be773d15 --out /tmp/ingest
```

`--approved-by` on its own is refused exactly as a bare `/approve` is, and for
the same reason: it says yes without saying to what.

The trust chain is provisioned, so this really does run: `registry/v1/root.json`
carries `astra-root-2026a` and its reserve, and `registry/v1/trust.json` is
signed by the active root at serial 1, delegating to `astra-index-2026a` and
allowlisting one reusable-workflow commit. An attestation from any other
workflow is refused, which is the point of the allowlist.

### The one switch that is not flipped yet

**Private vulnerability reporting is off on this repository.** Check it, and
check it after you change it — the answer is one line either way:

```sh
gh api repos/mihailinl/astra-registry/private-vulnerability-reporting
```

```
{"enabled":false}          # as of 2026-08-15
```

While it says `false`, `https://github.com/mihailinl/astra-registry/security/advisories/new`
works **for you** and 404s for everybody else: GitHub shows the "Report a
vulnerability" form to outside reporters only when this is on. That is the
opposite of what a security contact link is for, and it is why the one in
`.github/ISSUE_TEMPLATE/config.yml` now points at `docs/POLICY.md` §11 — which
carries a fallback that works today — rather than at the form.

Turn it on:

```
Settings → Advanced Security → Private vulnerability reporting → Enable
```

Then, in one commit: delete step 2 of §11's "how to open one" in
`docs/POLICY.md`, and point the security contact link in
`.github/ISSUE_TEMPLATE/config.yml` back at `/security/advisories/new`. Leave the
sentence about who can read an advisory where it is — enabling the form does not
make it end-to-end encrypted.

**Two other places to fix, neither done here.** `site/build.mjs` still generates
"it is end-to-end between you and the maintainer" onto the published security
page (`bot/security-contact.json`, which feeds it, has been corrected).
`SECURITY.md`'s third paragraph says "open a private security advisory on this
repository, or email the address in the repository profile" — the first half is
the form that 404s while the switch is off, and the second names an address this
repository does not publish anywhere it can be checked.

---

## 2. Where each thing lives

| Thing | Where |
|---|---|
| Root private keys | Offline: paper/steel + an encrypted attachment in the password manager. Never on a networked machine, never in a repository. |
| Root public keys | `registry/v1/root.json` here, **and** `PRODUCTION_ROOT_KEYS` in `astra-rs/astra-daemon/src/plugins/trust.rs`. Two copies of one fact, on purpose. |
| `trust.json` | Published next to the index; cached by each daemon under `<config>/registry/trust.json`. |
| Index private key | GitHub Environment secret `ASTRA_INDEX_SIGNING_KEY` on the `publish` environment. No required reviewer is configured on it (LM-1). |
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

## 7. Withdrawing a plugin

The path a withdrawal actually takes, end to end, and the moderation acts
around it. **§7.1 is the one to follow with somebody on the phone**; everything
after it is the vocabulary that procedure uses and the acts that touch the same
files.

**What exists today, so you find out here and not mid-incident.**
`.github/workflows/sign.yml` is the one publisher of the catalogue and the
withdrawal list, and it is live. It replaces a withdrawal workflow that was
deleted at R0 having failed every scheduled run it ever made; if you remember
that one, the procedure below is not it. What is **not** here yet:
`.github/workflows/operator.yml`, so
§7.7's confirmations, cancellations, reverts and denies have no dispatch to run
and are performed as hand commits with the trailer in §7.3; `state/holds/**`
has its library (`bot/lib/holds.mjs`) and its schemas, and nothing yet writes
an entry; the takedown bound of §7.10 is stated in policy and is not yet
counted by code. Each of those says so in its own subsection. Nothing below
depends on them for the withdrawal itself.

### 7.1 The procedure

Target: committed, signed and reachable at the edge within **ten minutes**.

1. **Write the advisory.** One file, `tools/revocations/ASTRA-<year>-<nnnn>.json`.
   `tools/revocations/README.md` is the format and — more importantly — the
   `kind` table, which is where this goes wrong: a wrong `kind` or a mistyped
   digest matches nothing, silently, and the plugin stays installed.
   **Prefer `digest`, and never ship only a `digest`**: a sideloaded source
   directory has no archive and therefore no bundle digest, so add a `binary`,
   an `id_version` or a `version_range` entry beside it.

   ```sh
   node tools/build-revocations.mjs --check   # refuses anything the daemon would not read
   ```

2. **Commit it, with the trailer**, and push to `main`:

   ```
   revocations: ASTRA-2026-0007, clipboard exfiltration in example-plugin 1.2.0

   Moderation-Exempt: mihailin: hand advisory during an active report; the
   service decision follows
   ```

   §7.3 says what the trailer is for and when it may be left off.

3. **The signer runs.** A human push to `main` starts `Signer` at once; it
   plans against main's head, signs the list, commits it to `signed` and
   deploys Pages. If no run appears within a minute or two, dispatch it — the
   Actions tab, `Signer`, *Run workflow* (it takes no inputs; there is nothing
   to aim it at).

   ```sh
   gh workflow run sign.yml
   gh run watch "$(gh run list --workflow sign.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
   ```

   Read the `publish` job's log. It prints one line per document saying what it
   decided: `changed`, `resign`, `unchanged`, `carry` or `blocked`. **`carry` on
   the withdrawal list means the list did not publish** — the old bytes were
   re-committed and clients are being served yesterday's list. The line says
   why; fix that and run it again. `blocked` means the run committed nothing at
   all, and the reason is in the same log.

4. **Verify at each serving host.** Do not take the workflow's word for it:
   what matters is the bytes a daemon fetches.

   ```sh
   # `signed`'s head, read the way a client reads it
   sha=$(git ls-remote https://github.com/mihailinl/astra-registry refs/heads/signed | cut -f1)
   curl -fsS "https://raw.githubusercontent.com/mihailinl/astra-registry/$sha/registry/v1/revocations.json" > /tmp/r.json

   # Pages
   curl -fsS https://mihailinl.github.io/astra-registry/registry/v1/revocations.json > /tmp/p.json

   # the catalogue host, from R2, once its DNS record resolves
   curl -fsS https://registry.minice.ai/registry/v1/revocations.json > /tmp/h.json
   ```

   For each: the `serial` is higher than the one before, the advisory's entry
   is in it, and the signature verifies against the published `trust.json`:

   ```sh
   node tools/sign-revocations.mjs --verify /tmp/r.json --trust registry/v1/trust.json
   ```

   The freshness window is **7 days**. Past it, daemons block **new installs**
   with "Astra can't check whether this plugin has been withdrawn" — a
   different and much noisier failure than the one you are fixing.

**Two things that are true whatever went wrong.** A stale list never disables a
working plugin: withdrawal takes effect only from a fresh, signature-valid list,
and the last applied serial is persisted, so an attacker cannot un-withdraw by
serving an older one. And digest-keyed withdrawal reaches a bundle however it
arrived — the store, `ImportPluginFile`, or a copy from a friend.

### 7.2 Lifting one

Delete the advisory file and commit, **with the same trailer on the deleting
commit**. The list's serial is a commit count over `tools/revocations/`, so it
rises on a deletion exactly as it rose on the addition — which is why the
serial is not the number of advisories, and why an un-withdrawal cannot make it
go backwards.

Then §7.1 step 4 again. A lift is the case where verifying at the edge matters
most: the plugin is working for you the moment you delete the file, and it is
still blocked for everybody else until the list they hold expires or is
replaced.

### 7.3 The trailer, on both commits

```
Moderation-Exempt: <actor>: <reason>
```

`<actor>` is a person, `<reason>` is a sentence. It goes on the commit that
**adds** a hand advisory and on the commit that **deletes** it — both, because
the coverage canary (§7.11) walks both directions and a delete with no cover is
the same defect as an add with no cover.

It is not a bridge that disappears. It is the standing escape hatch for any
hand-committed `unlisted`, `yanked` or `tools/revocations/**` change: the
break-glass of §7.5, the withdrawal drills, and anything else a person does
without a service decision behind it. Leave it off **only** when a decision
record covers the commit — a log entry, or an author-action record — which is
the case for everything the bot commits.

A commit that should have carried it and did not is not rewritten. It is
cleared afterwards, from a later commit; see §7.11.

### 7.4 The flag, and the latch

Every shipped 0.2.x daemon reads the withdrawal list **from Pages**, and stays
`NotEnforced` while what it reads carries no valid signature. The moment Pages
serves a list that verifies, those clients arm themselves — and seven days
after each one's last accepted fetch, a stale or unsigned list **blocks
installs** on that machine.

So arming is one-way in the field, whatever git says, and it is one file:

```
policy/pages-withdrawal-list.json     {"schema": "astra.registry.pages-withdrawal-list/1", "armed_at": "…"}
```

* **Before that file exists**, Pages gets `main`'s unsigned list, exactly as it
  does today, and shipped clients stay `NotEnforced`.
* **From the first commit that ADDS it**, Pages gets `signed`'s list.

The latch is the commit, not the file. Reverting the commit changes nothing,
because the clients do not disarm — they block installs a week later while the
person who reverted watches a green build. The flag is therefore **never
changed and never deleted**, and a check fails on any commit that touches it.

**Adding that file needs the owner's approval** (ROLL-14), and the drill in
§7.6 is what the approval is given against. §7.5 is the exception.

### 7.5 Break-glass: withdrawing before the drill

A plugin may have to come down before the flag is armed. That is a real state,
not an oversight: from the day `sign.yml` landed until the day the owner arms
Pages, a withdrawal reaches `signed` and the catalogue host and does **not**
reach a shipped 0.2.x client.

What to do:

1. Do §7.1 anyway. The advisory is published, `signed` carries it, and every
   reader of `signed` and of the catalogue host is protected.
2. Say so, in the commit and in the report: **shipped 0.2.x clients are not
   covered by this withdrawal** until the flag is armed.
3. If the incident warrants it, ask the owner to arm the flag early
   (**owner approval**), accepting that the drill has not run. He is accepting
   one thing: every 0.2.x daemon in the field arms itself, and from then on an
   unsigned or stale list blocks installs on it after seven days. The signer
   is what keeps the list fresh, and §7.1 step 4 is how you know it is.

### 7.6 The drill

Before the flag is armed, once, end to end, on a bundle nobody depends on:

1. publish a test bundle from the test repository and install it on a machine
   running a released 0.2.x daemon pointed at this registry;
2. write and commit a `digest` advisory for that bundle, with the §7.3 trailer;
3. watch the signer run, and verify at every host as in §7.1 step 4;
4. record what the installed copy does, and when — the build tag, the digest the
   advisory matched, both serials, and the client's state;
5. lift it (§7.2), and record what the copy does after the lift.

A drill with no client is not this drill. The whole question is what an
installed copy does, and that is only observable on one.

### 7.7 Confirming, cancelling or reverting a service decision

**Not yet dispatchable.** `.github/workflows/operator.yml` and `bot/operator.mjs`
land with the moderation workflows. Until they do, each act below is a hand
commit carrying `Moderation-Exempt:` (§7.3) and the same files. This subsection
is written now so the procedure is decided before it is needed.

The operator workflow is dispatched with one `act` and one
`service_decision_id`, and that is the whole interface:

| `act` | What it writes |
|---|---|
| `confirm` | `state/holds/<id>.confirm.json`. Releases a held decision — see §7.8 |
| `cancel` | `state/holds/<id>.cancel.json`. Ends the hold without applying the decision |
| `revert` | Finds the log entry by `service_decision_id`; refuses unless it is a `delist`, `deprecate` or `revoke`; removes the `unlisted` flag or deletes the advisory; and writes a `relist` or `unrevoke` entry naming what it reverses |
| `deny` | `state/deny/<fingerprint>.json` — §7.9. This one takes a `fingerprint` as well |

Three things about it that are load-bearing:

* it runs in the `operator` environment, which admits **only `main`**. That is
  not tidiness. The authority check lives in the tree at the ref the dispatcher
  chooses, the dispatch API takes a ref, and the permission needed to dispatch
  is plain **write** — so without an environment pinned to `main`, anyone with
  write access could push a branch whose role check returns `admin` and confirm
  a hold from it. GitHub refuses the job before it starts; that refusal is the
  boundary, and the role check inside is defence in depth;
* it refuses anyone who is not an **admin or a maintainer**, and it checks both
  the actor and the triggering actor;
* a **revert is outside the takedown bound** (§7.10) — it is the one act the
  bound deliberately does not count, because a revert un-does a withdrawal.

### 7.8 Holds

A hold is a decision that has been made and **not applied**. It is a file under
`state/holds/`, and it ends in exactly one of three ways: a release, a cancel,
or a hand deletion that a later commit names.

What is held:

| Held | Kind | Ends |
|---|---|---|
| `M_RELIST`, `M_UNREVOKE` | `reversal` | **24 hours** after it was held, *and* a confirm record. Both |
| `M_REVOKE` with action `disable` | `disable_confirmation` | A confirm record, at once. No period |
| Any takedown over the bound (§7.10) | `bound` | A confirm record, at once |
| `A_REMOVAL_REQUEST` for a listing with no identity record | `unbound_removal` | An applied `author_request` delist, or a cancel |
| `A_YANK` for a listing with no identity record | `unbound_yank` | **Never applied.** A cancel record, or the entry's deletion |

The 24-hour period on a reversal is a reversal period, not a review queue: it
is there so that a relist issued in error can be caught before it reaches
installed copies. A `disable` is held for a **confirmation** and not for a
period, because a disable is the irreversible direction and the owner chose a
person over a clock. An `M_REVOKE` with `block_install` is held only if it is
over the bound.

`unbound_yank` is the one that surprises people: it is never applied, not on a
confirm, not after any period, not by an applied delist of the same plugin. An
author yank can only come from the bound account, so an unbound one means the
service got something wrong, and no confirmation makes it right.

**How a release reaches git.** One commit: it applies the held decision from the
entry, writes the log entry, deletes the hold entry **and** its confirm record,
and carries `Service-Decision:`. A cancel is one commit that deletes the entry
with a trailer. An entry that disappears with neither is a hand cancellation,
and the commit that removed it is what records that.

**A red coverage canary blocks a `reversal` and nothing else** (§7.11). It never
blocks a takedown: a withdrawal that waits for a transparency check is a
withdrawal a transparency check can stop.

### 7.9 Operator deny

`state/deny/<fingerprint>.json` withholds a release **permanently**, by the
submission's fingerprint. It is written by the operator workflow's `deny` act
and by nothing else, and there is no expiry and no undo but deleting the file.

The record is four members and no prose: `schema`, `fingerprint`, `run`, `at`.
Nothing about the person, nothing about the submission — that is PRIV-2, and
the scan in §7.11 reads this directory.

Use it when a release must not be published again however many times it is
re-submitted. Anything short of that is a decision with a reason, and belongs in
the log where a reader can find it.

### 7.10 The takedown bound

**Three in any trailing 24 hours, estate-wide.** Above it, a moderator's
takedown — `block_install` included — is held (`bound`) until an operator
confirms it.

What counts toward it: every listed plugin id that moved to `yanked` or
`unlisted`; every listed id newly matched by an entry added under
`tools/revocations/`, siblings included; a bound account's removal request; and
an author's yank. **Whatever trailer the commit carries** — the count is taken
from the tree, so the hand advisories of §7.1 and §7.5 count exactly as a
service decision does. Two exclusions and only two: a MOD-52 revert (§7.7), and
the staging listing, excluded by its reserved id.

The consequence to keep in mind on a bad day: **three hand advisories fill the
bound**, and the fourth withdrawal that day — a moderator's `disable`, say —
will be held for a confirmation you then have to give. That is the bound
working, not a fault. It caps the blast radius of a compromised panel or
service at three withdrawals a day, and the price is that the one day the
registry is withdrawing by hand is a day it has to confirm the fourth.

Author actions count. The service caps each account at one listed plugin id in
any trailing 24 hours, so filling the bound by author actions takes three
distinct accounts; the registry cannot see accounts and does not try to.

### 7.11 Clearing a red coverage canary

`Moderation coverage` runs every fifteen minutes and asks one question: did
whoever took a moderation action leave a record a reader can find? It has no
opinion about whether the action was right, and it **gates nothing** — the one
thing it holds back is the release of a held reversal (§7.8).

Three ways to clear a red one, in order of preference:

1. **Write the log entry that was owed.** The honest repair, and the only one
   that makes the transparency log true.
2. **On the commit itself**, if it has not been pushed yet:
   `Moderation-Exempt: <actor>: <reason>`.
3. **Afterwards, from a later commit**, naming the commit being cleared:
   `Moderation-Exempt: <sha>: <actor>: <reason>`.

History is not rewritten to clear a canary. The third form exists precisely so
that it never has to be.

The tool refuses edits to existing `bot/moderation/*.json` and to `log/**`
outright, and it will not accept a deleted advisory unless a log entry names it
as reversed or the deleting commit carries the trailer — which is why §7.2 puts
the trailer on the deletion.

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
