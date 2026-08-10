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
it names no build: nothing for Phase 3's attestation to check, and no release
for the bot to read an asset list from. A listing here must be re-derivable by
a third party from the author's repository alone.

From Phase 3, add: the artifact carries a GitHub build attestation, and the
submitter has admin or maintain permission on the repository. Neither is checked
today — `bot/lib/phase3.mjs` lists them on every run.

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

## 5. Data handling

If a plugin sends anything off the user's machine, the store card must say so,
in the summary or the description, in plain language: what leaves, and where it
goes. "Uses an AI provider" counts as saying so. Silence does not.

A plugin that reads conversation content, microphone audio, or the contents of
the Astra window, and transmits any of it, must say so explicitly. From Phase 4
this becomes a declared permission with a consent sheet; today it is a
disclosure rule enforced by a maintainer and by reports.

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
| Malicious plugin, already installed by users | Removal alone does nothing to an installed copy. That needs signed revocation — **Phase 3.9**. Until then, the honest answer is that the registry can stop offering it and cannot stop it running, and this document will not pretend otherwise. |
| Licensing or trademark dispute | Listing removed pending resolution. Not a reason to break a working install, so it will never carry a `malware` severity. |

From Phase 3.9 a revocation is signed, carries a severity, and reaches installed
copies at the next index refresh: `malware` stops the plugin without asking,
`vulnerability` notifies with an Update button, `policy` shows a passive notice.

## 8. Review, and how long it takes

**Exactly three events take blocking human review**, and the SLA on those three
is **48 hours**: a first listing, a newly requested high-risk permission
(`client`, `dom_access`, `send_chat_message`, `set_theme_contribution`), and an
identity or repository change.

Everything else publishes itself with nobody in the loop — immediately for a
routine release, and after a 24-hour delay (6 hours for an author with a clean
release history here) when the permission set grew or when the plugin holds any
high-risk permission at all.

**And here is what that apparatus does not yet buy.** Every rule above is keyed
on what a plugin *declares*. Nothing in Astra enforces a declaration at run time
today: the daemon issues a session token to every plugin it starts and the host
RPCs check who is calling, not what that plugin was granted — the
`require_permission` gate PRODUCTION_PLAN §5.6 specifies is Phase 4.1 and does
not exist yet. So a plugin that declares nothing and calls
`SetThemeContribution` or `SendChatMessage` anyway is **not blocked on the
user's machine**; it is caught, if at all, by the registry's string search over
the bundle's source (§Names' caveat applies here too — it is a heuristic).
Declaring honestly is currently more expensive than not declaring, which is the
wrong way round and is a thing this registry can only partly compensate for.
That sentence stays here until the runtime gate lands.

That number is a commitment about three events precisely because it is three
events. **`docs/POLICY.md` is the whole publication policy**: every outcome the
bot can post, what each delay is for and what it honestly buys, how a release
notification reaches this registry without the author holding any credential for
it, and — stated there rather than left to be discovered — what happens when the
SLA slips, which is that auto-publication widens rather than the queue rotting.

## 9. Appeals and reports

Open an issue. A rejection names the check that failed and the file it failed
in — if it does not, that is a bug in the bot and worth reporting on its own.

To report a listed plugin, open an issue with the plugin id and what you
observed. Reports about behaviour beat every heuristic in this document, and
they are the mechanism this registry actually relies on.
