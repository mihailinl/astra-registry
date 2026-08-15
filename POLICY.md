# Listing policy

What gets into the Astra plugin registry, what does not, and what happens when
something that got in should not have.

This document is enforced by `tools/validate.mjs` and `bot/run-checks.mjs`
wherever a rule can be checked mechanically. Where it cannot, it is enforced by a
maintainer reading the submission. Every rule below says which of the two it is,
because a policy you cannot tell apart from a wish is not a policy.

---

## 0. The sentence this policy cannot get around

**A listed plugin runs as a native program with your full user account access.**
Astra checks that a plugin's bytes are the bytes its author released, and that
nobody swapped them in transit. That is all any registry can check. It is not a
safety review, it is not a code audit, and being listed here is not an
endorsement.

Nothing else in this document should be read as softening that.

---

## 1. What is listed

A plugin is listed when all of the following hold.

| Requirement | Enforced by |
|---|---|
| It is an Astra plugin: a valid `plugin.toml`, a working `.astraplugin` bundle, and at least one declared capability. | bot (bundle structure), maintainer |
| Its source is a public GitHub repository. | `validate.mjs` (schema: `source.kind: github`) |
| Every artifact is a GitHub Release asset **of that repository** (`release.kind: github_release`), pinned by SHA-256 and size. | `validate.mjs` (URL must sit under the declared release), bot (digest) |
| Its licence is on the SPDX allowlist. | `validate.mjs` against `policy/spdx-allowlist.json` |
| Its id is a safe path component, is not reserved, and is not confusable with a listed id. | `validate.mjs` against `policy/reserved-ids.json` |
| Each artifact is at most 256 MiB. | `validate.mjs` against `policy/limits.json` |
| It does something a user asked for, described honestly. | maintainer |

`release.kind: direct`, which names an artifact origin that is not a GitHub
release, is a shape the schemas can express and this catalogue does not list.
It exists because a self-hosted or staging catalogue serves its own bytes and
Astra's daemon supports that; it is refused here without an explicit
`--allow-direct`, which nothing in this repository passes. The reason is not
that a direct URL is untrustworthy — it is pinned by the same digest — but that
it names no build: nothing for the build attestation to be checked against, and
no release for the bot to read an asset list from. A listing here must be re-derivable by
a third party from the author's repository alone.

Two further requirements apply **on the release path**, and are checked there:
the artifact carries a GitHub build attestation, and the submitter is proved to
control the repository. Control is proved by
`.well-known/astra-plugin-owner` on the repository's default branch naming the
submitter's login, read live on every run. Asking GitHub who holds `admin` or
`maintain` is tried first and is an opportunistic shortcut only: GitHub answers
that endpoint solely for a caller that can already see the repository, so for
any repository this registry does not itself own it returns `403` — no answer,
never a denial, and never a substitute for the file. `bot/ingest.mjs` proves
ownership (`bot/lib/ownership.mjs`) and verifies the attestation against a
reusable-workflow allowlist read out of the root-signed `trust.json`
(`bot/lib/attestation.mjs`, which passes both `--repo` and `--signer-workflow`
to `gh attestation verify`, so "some workflow in that repository built it"
becomes "the workflow we allow built it").

On the **pull-request path** — a listing somebody hand-edited — neither is
checked, because there is no submitter to attribute an attestation to and the
maintainer reading the pull request is the control. `bot/run-checks.mjs` prints
every such unchecked row on every run rather than reporting a clean bill of
health; the list is `bot/lib/phase3.mjs`.

## 2. What is not listed

- **Anything whose artifact cannot be verified.** No digest, no listing. The one
  exception is a `staging` entry, which requires an explicit `--allow-staging`
  and is uninstallable by construction; every listing here is one today, and
  README.md §The staging entries says exactly what has to happen upstream before
  the first of them carries a digest.
- **Malware, or anything whose described purpose differs from its behaviour.**
  Including "the plugin does what it says plus one more thing".
- **Credential harvesters, undisclosed telemetry, or anything that exfiltrates
  conversation content without saying so on the store card.**
- **Impersonation.** A name, id, icon or author string that presents the plugin
  as first-party, or as someone else's work.
- **A wrapper whose only content is a remote code loader.** If the bytes we
  pinned fetch and run other bytes at startup, the digest guarantees nothing,
  and the whole chain this registry exists to build is decorative.
- **Plugins that exist to install other plugins**, for the same reason.
- **Unlicensed or licence-incompatible redistribution.**

## 3. Names

Ids are lowercase, 2–64 characters, `[a-z0-9-]`, no leading, trailing or doubled
hyphens. An id is a **path component** — the daemon joins it onto its plugins
directory — so it is checked far beyond that charset: no `..`, no separators, no
NUL, no control or bidirectional characters, no Windows device names, no
trailing dot or space.

Two ids that a person cannot tell apart cannot both exist. `validate.mjs` folds
each id (NFKC, lowercase, strip separators, fold digit/letter confusables such
as `0`→`o`, `rn`→`m`) and **rejects** an exact collision; ids within one edit of
each other are **flagged for a human**, not rejected.

**This is a heuristic that catches accidents and lazy impersonation. It does not
stop a determined attacker,** and no amount of Unicode folding will. Report a
name you believe is impersonation — that path works, and it is the one that
scales.

Reserved ids and prefixes are in `policy/reserved-ids.json`. Removing an entry
there is a security change, not a cleanup.

## 4. Licensing

`policy/spdx-allowlist.json` is an allowlist, not a denylist: a licence nobody
here has read is a licence this registry cannot promise anything about. To add
one, open a pull request against that file with a sentence on why. That pull
request is the review.

The declared licence must be the licence in the repository. A mismatch is a
removal.

**Open source only, for now.** Every entry on the allowlist is an OSI-approved
open-source licence, and that is the whole rule today: a plugin whose source
nobody can read does not get listed here.

This is a policy, not a legal limit, and the distinction matters. The SDKs are
MPL-2.0 — file-level copyleft that does not reach an author's own code — so
writing a proprietary plugin for Astra is *permitted by the licence*, and always
will be. Companies that cannot open their source are expected to integrate with
Astra eventually, and the licence was chosen so that stays possible.

What is unsettled is how such a plugin would be *listed*. Everything this
registry promises rests on being able to inspect what it lists: the bot reads the
manifest out of the bundle, scans for host RPCs the plugin never declared, and a
human can read the code behind a first listing. None of that survives a binary
nobody may decompile. A proprietary listing therefore needs something standing in
its place — a trust relationship, an agreement, an audit — and none of those
exist yet.

So proprietary plugins are a planned path for trusted publishers, gated on work
that has not been done. Until it is, this section is the answer, and loosening it
is a change to this file rather than to anybody's licence.

## 5. Data handling

If a plugin sends anything off the user's machine, the store card must say so,
in the summary or the description, in plain language: what leaves, and where it
goes. "Uses an AI provider" counts as saying so. Silence does not.

A plugin that reads conversation content, microphone audio, or the contents of
the Astra window, and transmits any of it, must say so explicitly.

**Reading** it is now a declared permission. `subscribe_events` carries an
event-type **allowlist that the daemon enforces**, rather than trusting the
filter the plugin sends — `speech_recognized`, which carries the user's
transcripts, is one of the types a grant can withhold
(`granted_event_allowlist`, `astra-daemon/src/plugins/host_service.rs`). The
permissions a plugin asks for are shown before it is installed
(`astra-ui/src/pages/Plugins/InstallConsentSheet.tsx`).

**Sending it on is gated by nothing, and cannot be.** A plugin is a native
process with the user's network access; a permission decides what the daemon
will do *for* a plugin, never what the plugin's own process may do. So on the
transmitting half this stays exactly what it was — a disclosure rule enforced by
a maintainer and by reports — and no reading of the paragraph above should
suggest otherwise.

## 6. Versions

- Versions are semver, and a new listing must be strictly greater than the last.
- A version file is **immutable once merged**. Fixing a published release means
  publishing a new version, never editing a digest in place: the digest is the
  whole promise, and a mutable one is not a promise.
- An author may **yank** a version (`"yanked": true`). It leaves the index and
  stays in git. Yanking is the author's tool for "do not use this one"; it is
  not a security control, it does not touch installs, and it is not revocation.
- Retiring a plugin entirely is `"unlisted": true` on `plugin.json`. The audit
  trail stays.

## 7. Removal

| Situation | What happens |
|---|---|
| Policy breach found before install matters | The listing is removed. `git log plugins/<id>/` keeps the record. |
| Author asks for removal | Removed, no argument, no delay. |
| Malicious plugin, already installed by users | Removal alone still does nothing to an installed copy — but a **signed revocation** does, and it exists. An advisory with `"action": "disable"` refuses new installs *and* stops the copy that is there and will not start it again; `"block_install"` refuses installs and updates and leaves a running copy alone. `docs/POLICY.md` §8 is the full table. |
| Licensing or trademark dispute | Listing removed pending resolution. Not a reason to break a working install, so it gets `"action": "warn"` at most, and usually no advisory at all. |

A revocation is signed, carries exactly one action and a severity, and reaches
installed copies at the next refresh of `revocations.json`. **The action is the
field with consequences; the severity is advisory and no enforcement decision
reads it** — deliberately, so that someone who reached the signing key could not
also downgrade a withdrawal to "low" and have it stop mattering. An action a
build does not recognise **disables**, which is the safe direction: a newer
registry inventing a spelling and an older daemon reading it as "do nothing"
would be a withdrawal that silently did not happen. The behaviour of each action
is `RevocationAction` in `astra-daemon/src/plugins/trust.rs` — `blocks_install()`
is true for everything except `warn`, `stops_installed()` only for `disable`.

## 8. Review, and how long it takes

**Exactly three events take blocking human review**, and the SLA on those three
is **48 hours**: a first listing, a newly requested high-risk permission
(`client`, `dom_access`, `send_chat_message`, `set_theme_contribution`), and an
identity or repository change.

Everything else publishes itself with nobody in the loop — immediately for a
routine release, and after a 24-hour delay (6 hours for an author with a clean
release history here) when the permission set grew or when the plugin holds any
high-risk permission at all.

That number is a commitment about three events precisely because it is three
events. **`docs/POLICY.md` is the whole publication policy**: every outcome the
bot can post, what each delay is for and what it honestly buys, how a release
notification reaches this registry without the author holding any credential for
it, and — stated there rather than left to be discovered — what happens when the
SLA slips, which is that auto-publication widens rather than the queue rotting.

**And here is what that apparatus buys, and exactly where it stops.** Every rule
above is keyed on what a plugin *declares*, and a declaration is now enforced at
run time. `require_permission` runs at the top of every host RPC that needs one;
`HOST_RPC_PERMISSIONS` in `astra-daemon/src/plugins/host_service.rs` is the
table, and it names all ten RPCs — six gated (`SubscribeEvents`,
`SendChatMessage`, `FireTrigger`, `SetVariable`, `SetThemeContribution`,
`PushToUi`) and four deliberately not (`Register`, `GetPluginSelfConfig`,
`PluginLog`, `GetDaemonInfo`, none of which acts on anything outside the
plugin). A test reads that table rather than the methods, so a new RPC with no
gate is a failing test instead of a silent omission. So a plugin that declares
nothing and calls `SetThemeContribution` or `SendChatMessage` anyway **is
refused on the user's machine**, and declaring honestly is no longer more
expensive than not declaring.

Two of the names in `[permissions]` gate no RPC: `dom_access` and `client` are
*surface* rather than calls, and are refused where the surface is handed out.

**Where it stops** is §0, unchanged by any of the above. A permission decides
what the daemon will do *for* a plugin. It decides nothing about what the
plugin's own process may do to the machine, because there is no sandbox — a
plugin is a native program with the user's full privileges. Read the whole of
this section as "what the daemon will permit", never as "what the plugin can
do".

## 9. Appeals and reports

Open an issue. A rejection names the check that failed and the file it failed
in — if it does not, that is a bug in the bot and worth reporting on its own.

To report a listed plugin, open an issue with the plugin id and what you
observed. Reports about behaviour beat every heuristic in this document, and
they are the mechanism this registry actually relies on.
