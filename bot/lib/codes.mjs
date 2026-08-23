// Every verdict the bot can reach, as a fixed code with a fixed meaning.
//
// PRODUCTION_PLAN task 3.3's acceptance is "each failure class produces a fixed
// error code and an actionable comment", and both halves of that live here.
//
// **The code is the contract.** It appears in the issue comment a stranger
// reads, in docs/BOT-CHECKS.md, in this repository's tests, and in whatever the
// author greps when a release stops ingesting. Renaming one is a breaking
// change to a published interface; adding one is not. `remedy` is the sentence
// that tells someone what to *do* — a comment that says only "E_ENTRY_SHELL"
// has told them nothing.
//
// The levels, and what each costs the submitter:
//
//   error   the release is not listed. Nothing publishes until it is fixed.
//   review  the release is held for a human. Not a rejection — a decision the
//           bot is not entitled to make (POLICY.md and task 3.5 own the SLA).
//   warn    listed anyway, said out loud. A property worth knowing that is not
//           worth blocking on.
//   note    something the bot did NOT decide. Printed on every run, because a
//           checklist that shows only what passed reads as a clean bill of
//           health for properties nobody looked at.
//   pass    a check that ran and was satisfied.
//
// `skip` exists too, for a check that could not run in this mode (offline, no
// `gh`); it renders like `note` and is never counted as a pass.

/**
 * @typedef {"error"|"review"|"warn"|"note"|"pass"|"skip"} Level
 * @typedef {{level: Level, title: string, remedy: string, stage: string}} CodeDef
 */

/** @type {Record<string, CodeDef>} */
export const CODES = {
  // ── the two facts the submitter types ──────────────────────────────────────
  E_INPUT_REPO: {
    level: "error", stage: "submission",
    title: "The source repository is not `owner/name`",
    remedy: "Write it exactly as GitHub does: `you/dice-roller`. No URL, no trailing slash, no branch.",
  },
  E_INPUT_TAG: {
    level: "error", stage: "submission",
    title: "The release tag is not a tag",
    remedy: "Copy the tag from the release page — `v0.2.0`, not a commit SHA and not a branch name.",
  },

  // ── ownership ──────────────────────────────────────────────────────────────
  // The remedy leads with the one thing to create, because for months this
  // comment led with three failures and buried the fix in the fourth clause.
  // Two of those three cannot fire for an honest first submission at all — see
  // `bot/lib/ownership.mjs` — so a correct author was refused once by design.
  E_OWNERSHIP_UNPROVEN: {
    level: "error", stage: "ownership",
    title: "The repository has not vouched for the account asking",
    remedy:
      "Commit `.well-known/astra-plugin-owner` on the repository's default branch with your " +
      "GitHub login on a line of its own, then comment `/recheck`. One commit, no CI: " +
      "`mkdir -p .well-known && echo YOUR-LOGIN > .well-known/astra-plugin-owner`. " +
      "That file is the proof this registry asks for: it says somebody who can write to that " +
      "branch vouches for this login — a proof of write access, not of legal ownership — and it " +
      "is read live on every run, so deleting a line stops that login opening a new request " +
      "or passing a `/recheck`. The bot also tries a free " +
      "shortcut first (`GET /collaborators/{you}/permission`, which grants on `admin` or " +
      "`maintain`), but GitHub answers that only for a caller that can already see the " +
      "repository, so for any repository this registry does not itself own it is told nothing " +
      "at all — a limit of the bot's token, not a finding about you, and not something you " +
      "can install your way around.",
  },

  // ── the release and its assets ─────────────────────────────────────────────
  E_RELEASE_NOT_FOUND: {
    level: "error", stage: "release",
    title: "That repository has no release with that tag",
    remedy:
      "Publish the release (a draft is invisible to everyone but you) and check the tag spelling. " +
      "The bot reads it unauthenticated, so a private repository looks the same as a missing one.",
  },
  E_NO_BUNDLE_ASSETS: {
    level: "error", stage: "release",
    title: "The release carries no `.astraplugin` asset",
    remedy:
      "`astra-plugin build` produces one file per target; attach every one of them to the release. " +
      "The reusable release workflow does this for you.",
  },
  E_ASSET_URL_FOREIGN: {
    level: "error", stage: "release",
    title: "An asset URL does not belong to the repository being listed",
    remedy:
      "Every download URL must sit under `https://github.com/<owner>/<repo>/releases/download/<tag>/`. " +
      "This is the one check a user's daemon can make locally that ties the bytes to the repo, so a " +
      "listing that fails it here would fail there too.",
  },
  E_ASSET_FILENAME: {
    level: "error", stage: "release",
    title: "The asset is not named `<id>-<version>-<target>.astraplugin`",
    remedy:
      "`astra-plugin build` names bundles that way and the reusable release workflow asserts it. A " +
      "different name is usually one of two real mistakes: a stale bundle left over from the previous " +
      "version, or one build leg's file uploaded under another leg's name. Neither is caught by the " +
      "digest, because the digest is taken of whatever was uploaded.",
  },
  E_ASSET_HEAD_FAILED: {
    level: "error", stage: "release",
    title: "The asset could not be fetched",
    remedy: "Re-upload it and comment `/recheck`. If the release is private or the asset was deleted, nothing downstream can run.",
  },
  E_ASSET_SIZE: {
    level: "error", stage: "release",
    title: "The asset changed size between the listing and the download",
    remedy: "Do not overwrite a published release asset. Cut a new version instead — a digest that moves is a digest that pins nothing.",
  },
  E_ARTIFACT_TOO_LARGE: {
    level: "error", stage: "release",
    title: "The bundle is over the size cap",
    remedy: "See `policy/limits.json`. Ship models and datasets as a download the plugin fetches on first run, not inside the bundle.",
  },
  E_DIGEST_MISMATCH: {
    level: "error", stage: "release",
    title: "The bytes do not hash to what the attestation covers",
    remedy:
      "The file at the URL is not the file CI built. Re-run the release workflow; if it happens twice, " +
      "treat the repository as compromised before you treat it as a bug.",
  },

  // ── provenance ─────────────────────────────────────────────────────────────
  E_ATTESTATION_MISSING: {
    level: "error", stage: "attestation",
    title: "The bundle has no build attestation",
    remedy:
      "Build it in GitHub Actions with `actions/attest-build-provenance`, which the Astra reusable " +
      "release workflow already does. A hand-built bundle is refused however good it is: CI is the " +
      "only signer, so an author's compromised laptop cannot publish.",
  },
  E_ATTESTATION_INVALID: {
    level: "error", stage: "attestation",
    title: "The attestation does not verify",
    remedy: "Re-run the release workflow. Do not re-upload the asset by hand — the attestation covers the exact bytes, and hand-uploading is how they stop matching.",
  },
  E_ATTESTATION_UNCHECKED: {
    level: "error", stage: "attestation",
    title: "The attestation could not be checked — this is not about your release",
    remedy:
      "Nothing to fix and nothing to rebuild: the verifier could not start. `gh attestation verify` " +
      "fetches Sigstore's trust root before it can check anything, and when that fetch fails it " +
      "reports a failure that reads like a bad signature. Comment `/recheck` — the same bytes usually " +
      "verify on the next run. It still blocks, because an artifact nobody could verify must not be " +
      "listed; it blocks as \"we could not look\", not as \"we looked and it was wrong\".",
  },
  E_ATTESTATION_SUBJECT_MISMATCH: {
    level: "error", stage: "attestation",
    title: "The attestation is for different bytes",
    remedy: "The asset was replaced after CI attested it. Cut a new release; never overwrite an asset in place.",
  },
  E_RELEASE_COMMIT_MISMATCH: {
    level: "error", stage: "attestation",
    title: "The Release points at a different commit than the one that built it",
    remedy:
      "`release.target_commitish` and the commit named in the build attestation must be the same. " +
      "They are not, which means the Release was created against — or re-pointed at — a tree that " +
      "did not produce these bytes. This matters beyond tidiness: the listing records that commit " +
      "as the release's provenance, and every relative image in your README is pinned to it, so a " +
      "mismatch renders pictures from a tree nothing attested. Re-create the Release at the commit " +
      "the workflow built (`gh release create <tag> --target <sha>`), or re-run the release " +
      "workflow on the tag.",
  },
  E_ATTESTATION_REPO_MISMATCH: {
    level: "error", stage: "attestation",
    title: "The attestation was issued to another repository",
    remedy: "The bundle was built somewhere other than the repository being listed. That is exactly the case this check exists to catch.",
  },
  E_WORKFLOW_NOT_ALLOWED: {
    level: "error", stage: "attestation",
    title: "The build ran a release workflow this registry does not allow",
    remedy:
      "Call the Astra reusable release workflow and pin it by commit SHA " +
      "(`uses: mihailinl/AstraPlugins/.github/workflows/plugin-release.yml@<sha>`). Verifying an " +
      "attestation without pinning which workflow produced it proves only that GitHub built " +
      "something. The allowed SHAs live in the root-signed `trust.json`; adding one is a root-key " +
      "ceremony, not a pull request.",
  },
  E_TRUST_UNPROVISIONED: {
    level: "error", stage: "attestation",
    title: "This registry has no root-signed trust document yet",
    remedy:
      "Nothing a submitter can do — the root-key ceremony (SECURITY.md) has not been run, so there " +
      "is no allowlist to check a workflow against. The bot fails closed rather than accepting a " +
      "build it cannot place.",
  },

  // ── the archive ────────────────────────────────────────────────────────────
  E_BUNDLE_UNREADABLE: { level: "error", stage: "bundle", title: "The archive cannot be read", remedy: "Rebuild with `astra-plugin build`. A truncated upload is the usual cause." },
  E_BUNDLE_TOO_MANY_ENTRIES: { level: "error", stage: "bundle", title: "Too many files in the archive", remedy: "The daemon refuses to extract it, so listing it would publish something uninstallable. See `policy/limits.json`." },
  E_BUNDLE_TOO_LARGE_EXTRACTED: { level: "error", stage: "bundle", title: "The archive expands past the extraction cap", remedy: "Same cap the daemon enforces. Shrink the payload or fetch it at runtime." },
  E_BUNDLE_DUPLICATE_ENTRY: { level: "error", stage: "bundle", title: "Two archive entries share a name", remedy: "Rebuild. The second copy would overwrite a file that already matched the manifest, after it was verified." },
  E_BUNDLE_ABSOLUTE_PATH: { level: "error", stage: "bundle", title: "An entry is an absolute or Windows-style path", remedy: "Bundle paths are relative and use `/`. Rebuild with `astra-plugin build` rather than a hand-made zip." },
  E_BUNDLE_TRAVERSAL: { level: "error", stage: "bundle", title: "An entry contains `..`", remedy: "Rebuild. A `..` component is how an archive writes outside the directory it was extracted into." },
  E_BUNDLE_ADS: { level: "error", stage: "bundle", title: "An entry name contains `:`", remedy: "Rename the file. On Windows `:` opens an NTFS alternate data stream, so the bytes land somewhere nothing looks." },
  E_BUNDLE_TRAILING_DOT: { level: "error", stage: "bundle", title: "An entry name ends in a dot or space", remedy: "Rename it. Windows strips both silently, so the name in the manifest and the name on disk stop being the same string." },
  E_BUNDLE_SYMLINK: { level: "error", stage: "bundle", title: "The archive contains a symlink", remedy: "Ship the file itself. A symlink's target is not covered by any of the checks its path passes." },
  E_BUNDLE_CONTROL_CHARACTER: { level: "error", stage: "bundle", title: "An entry name contains a control or invisible character", remedy: "Rename the file to printable characters. An entry name is not only a path: it is printed in this report, in the run log and in the job summary, and a newline or a pipe in one forges rows in the table a maintainer reads before approving a listing." },
  W_BUNDLE_DUPLICATE_ENTRY_CASE: {
    level: "warn", stage: "bundle",
    title: "Two entries differ only in letter case",
    remedy:
      "Rename one. Linux keeps both; Windows and macOS keep one, and the daemon refuses the bundle " +
      "there — so this lists cleanly and then fails to install for most of your users.",
  },
  E_PLUGIN_TOML_MISSING: {
    level: "error", stage: "bundle",
    title: "The bundle has no `plugin.toml`",
    remedy: "Every plugin carries one; it is what the daemon reads to know what the plugin is. Rebuild with `astra-plugin build`.",
  },

  E_MANIFEST_MISSING: { level: "error", stage: "bundle", title: "No `MANIFEST.json` — this is not a v2 bundle", remedy: "Rebuild with a current `astra-plugin`." },
  E_MANIFEST_NOT_FIRST: { level: "error", stage: "bundle", title: "`MANIFEST.json` is not the first archive entry", remedy: "The daemon reads it from byte zero. Rebuild rather than repacking by hand." },
  E_MANIFEST_COMPRESSED: { level: "error", stage: "bundle", title: "`MANIFEST.json` is compressed", remedy: "It must be stored uncompressed so it can be read without inflating attacker-supplied bytes." },
  E_MANIFEST_INVALID: { level: "error", stage: "bundle", title: "`MANIFEST.json` is malformed", remedy: "Rebuild with `astra-plugin build`." },
  E_MANIFEST_ID_MISMATCH: { level: "error", stage: "bundle", title: "The manifest names a different plugin", remedy: "One release, one plugin. A bundle whose manifest names another id installs as that other id." },
  E_MANIFEST_VERSION_MISMATCH: { level: "error", stage: "bundle", title: "The manifest names a different version", remedy: "Retag and rebuild so the tag, the manifest and the filename agree." },
  E_MANIFEST_PLATFORM_UNKNOWN: { level: "error", stage: "bundle", title: "The manifest's platform has no registry key", remedy: "`os`/`arch` must be one of the pairs in `tools/lib/platform.mjs`." },
  E_MANIFEST_PLATFORM_MISMATCH: { level: "error", stage: "bundle", title: "Two artifacts of this release claim the same platform", remedy: "Each target gets its own file. Check the build matrix." },
  E_MANIFEST_UNSORTED: { level: "error", stage: "bundle", title: "`MANIFEST.files` is not sorted by path", remedy: "Rebuild. The order is part of the format so two builders produce the same bytes." },
  E_MANIFEST_EXTRA_FILE: { level: "error", stage: "bundle", title: "The archive holds a file the manifest does not list", remedy: "An unlisted file is a file nothing verifies — at install, and at every start afterwards. Rebuild." },
  E_MANIFEST_MISSING_FILE: { level: "error", stage: "bundle", title: "The manifest lists a file the archive does not hold", remedy: "Rebuild; the manifest and the archive were produced from different trees." },
  E_MANIFEST_SIZE_MISMATCH: { level: "error", stage: "bundle", title: "A file's size disagrees with the manifest", remedy: "Rebuild. The archive was edited after the manifest was written." },
  E_MANIFEST_HASH_MISMATCH: { level: "error", stage: "bundle", title: "A file's content disagrees with the manifest", remedy: "Rebuild. If the build is reproducible and this persists, the release asset was tampered with after CI." },
  E_MANIFEST_HEADER_DISAGREE: {
    level: "error", stage: "bundle",
    title: "The archive holds two different `MANIFEST.json`s",
    remedy:
      "The manifest the central directory points at is not the one at byte zero, and the daemon " +
      "reads byte zero. This is not something a build tool does by accident.",
  },
  E_MANIFEST_LOCAL_HEADER: { level: "error", stage: "bundle", title: "`MANIFEST.json` cannot be read from byte zero", remedy: "Rebuild with `astra-plugin build`." },
  W_MANIFEST_MODE_MISMATCH: {
    level: "warn", stage: "bundle",
    title: "A file's recorded mode differs from the archive's",
    remedy:
      "The daemon applies the manifest's mode and refuses the mismatch, so this lists and then does " +
      "not install. Rebuild.",
  },
  E_PERMISSIONS_HASH_MISMATCH: {
    level: "error", stage: "bundle",
    title: "`permissions_hash` does not cover the declared permissions",
    remedy:
      "Rebuild with `astra-plugin build`, which derives the hash from the permissions and cannot " +
      "emit a mismatch. Astra refuses to install this bundle (§5.3-D, block code " +
      "PERMISSIONS_HASH_MISMATCH), so listing it would advertise a version nobody can have. The " +
      "hash is what the consent sheet renders against and what the update gate compares: when it " +
      "does not cover the permission map, a user can approve one list while the daemon enforces " +
      "another.",
  },
  W_LEGACY_SIGNATURE_ENTRY: {
    level: "warn", stage: "bundle",
    title: "The bundle carries a legacy in-ZIP `SIGNATURE`/`PUBKEY`",
    remedy:
      "Harmless and ignored. It is never a trust signal here — trust comes from the attestation and " +
      "from this registry's countersignature. `astra-plugin build` stops writing it.",
  },

  E_ENTRY_MISSING: { level: "error", stage: "bundle", title: "`entry.command` is missing", remedy: "Declare the program the daemon should run." },
  E_ENTRY_ABSOLUTE: { level: "error", stage: "bundle", title: "`entry.command` is an absolute path", remedy: "It must be relative to the install directory, or the name of a declared runtime." },
  E_ENTRY_TRAVERSAL: { level: "error", stage: "bundle", title: "`entry.command` escapes the install directory", remedy: "Point it at a file inside the bundle." },
  E_ENTRY_SHELL: {
    level: "error", stage: "bundle",
    title: "`entry.command` is a shell",
    remedy:
      "Run your program directly. A shell as the entry point means the daemon executes whatever " +
      "`args` say, which is arbitrary code with none of the review the rest of this list applies.",
  },
  E_ENTRY_NOT_IN_BUNDLE: { level: "error", stage: "bundle", title: "`entry.command` is neither a bundled file nor a declared runtime", remedy: "Ship the binary in the bundle, or name `python` / `node` / `deno` / `bun`." },

  // ── the manifest, parsed by the daemon's own crate ─────────────────────────
  E_ID_CHARSET: { level: "error", stage: "manifest", title: "`plugin.id` is not a safe directory name", remedy: "Lowercase letters, digits and single hyphens. The id becomes `<plugins_dir>/<id>/` on every user's disk." },
  E_ID_RESERVED_DEVICE: { level: "error", stage: "manifest", title: "`plugin.id` is a reserved Windows device name", remedy: "Rename. `con`, `prn`, `aux`, `nul`, `com1`-`com9`, `lpt1`-`lpt9` are devices, not directories." },
  E_MIN_ASTRA_INVALID: { level: "error", stage: "manifest", title: "`min_astra_version` is not a semver version", remedy: "Write `\"0.9.0\"`. A value that does not parse is a requirement that requires nothing." },
  E_MIN_ASTRA_TOO_NEW: { level: "error", stage: "manifest", title: "The plugin needs a newer Astra than this registry publishes for", remedy: "Lower `min_astra_version`, or wait for that Astra to ship. A listing nobody can install is worse than no listing." },
  E_ENTRY_COMMAND_MISSING: { level: "error", stage: "manifest", title: "`[entry] command` is missing from `plugin.toml`", remedy: "Add it." },
  E_MANIFEST_FIELD_MISSING: { level: "error", stage: "manifest", title: "`plugin.toml` is missing a required field", remedy: "`id`, `name` and `version` are all required." },
  E_CAPABILITY_UNKNOWN: {
    level: "error", stage: "manifest",
    title: "`[capabilities]` names something the daemon has never had",
    remedy:
      "Use the exact name — `ui_contributions`, not `ui_panels`. An unknown key used to be dropped " +
      "silently, which is how three shipped examples declared nothing at all.",
  },
  E_TOML_MANIFEST_DISAGREE: { level: "error", stage: "manifest", title: "`plugin.toml` and `MANIFEST.json` describe different plugins", remedy: "Rebuild from one tree. The daemon installs under the manifest's id and runs what plugin.toml describes." },
  W_ENTRY_COMMAND_DISAGREE: { level: "warn", stage: "manifest", title: "The bundle runs a different command than `plugin.toml` declares", remedy: "The daemon executes the manifest's. Usually a stale `plugin.toml`." },
  E_PLATFORM_UNSUPPORTED: { level: "error", stage: "manifest", title: "Astra ships no daemon for that platform", remedy: "`linux-x64`, `windows-x64` and `noarch` are the hosts that exist. macOS and arm64 names are reserved and unusable." },
  E_PROBE_INPUT: { level: "error", stage: "manifest", title: "The manifest probe rejected the bot's own request", remedy: "A bug in this registry, not in your plugin. Please leave the issue open." },
  E_PROBE_UNAVAILABLE: { level: "error", stage: "manifest", title: "The manifest probe could not be run", remedy: "A bug in this registry, not in your plugin. `plugin.toml` was not validated by anything, so the run fails closed." },

  // ── names ──────────────────────────────────────────────────────────────────
  E_ID_RESERVED: { level: "error", stage: "names", title: "That id is reserved", remedy: "See `policy/reserved-ids.json`. Ids that read as first-party are an impersonation primitive." },
  E_ID_RESERVED_PREFIX: { level: "error", stage: "names", title: "That id uses a reserved prefix", remedy: "`astra-`, `official-` and `verified-` are first-party only." },
  E_TYPOSQUAT_COLLISION: {
    level: "error", stage: "names",
    title: "The id is indistinguishable from a listed plugin",
    remedy:
      "After NFKC normalisation, case folding, hyphen stripping and confusable folding it is the " +
      "same string as an existing listing. Two cards a user cannot tell apart cannot both exist. " +
      "Pick a different name.",
  },
  E_TRADEMARK: {
    level: "error", stage: "names",
    title: "The id or display name claims someone else's mark",
    remedy:
      "Name it for what it does, not for the service it talks to: `telegram-client` becomes " +
      "`tg-bridge`, `Spotify Controller` becomes `Music Controller for Spotify` only with the " +
      "rightsholder's say-so. See `bot/policy/trademarks.json`.",
  },
  R_TYPOSQUAT_NEAR: {
    level: "review", stage: "names",
    title: "The id is one edit away from a listed plugin",
    remedy:
      "Held for a human, not rejected — plenty of honest names are near-misses. If it is deliberate, " +
      "say so in the issue and it will be approved faster.",
  },
  R_DISPLAY_NAME_COLLISION: {
    level: "review", stage: "names",
    title: "The display name matches a listed plugin's, bar case, spacing or lookalike letters",
    remedy:
      "Held for a human. The store shows names, not ids, so two identical names are two identical cards. " +
      "A byte-identical name counts: it is the strongest form of the collision, not an exception to it.",
  },
  R_DISPLAY_NAME_MIXED_SCRIPT: {
    level: "review", stage: "names",
    title: "The display name mixes alphabets",
    remedy:
      "Held for a human. Write the name in one alphabet. A name that borrows a single Cyrillic or Greek " +
      "letter for its Latin shape renders as a name it does not contain, and the id charset cannot catch " +
      "it because the id is not the string on the card.",
  },

  // ── metadata, licence, size ────────────────────────────────────────────────
  E_METADATA_UNSAFE_TEXT: {
    level: "error", stage: "metadata",
    title: "Metadata contains invisible or direction-changing characters",
    remedy:
      "Remove the zero-width, bidi-override or control characters. They are what makes a card render " +
      "as a name it does not contain.",
  },
  E_METADATA_TOO_LONG: { level: "error", stage: "metadata", title: "A metadata field is over its length cap", remedy: "See `policy/limits.json`. The store's card has a fixed size; a longer string is truncated somewhere less pleasant." },
  E_METADATA_MISSING: {
    level: "error", stage: "metadata",
    title: "`plugin.toml` does not say what the plugin is",
    remedy:
      "Fill in `description` (and `author`). The store card is built entirely out of the bundle — " +
      "there is no form to type a summary into, by design — so a manifest with no description " +
      "produces a listing with nothing on it.",
  },
  E_LICENSE_MISSING: { level: "error", stage: "metadata", title: "`plugin.license` is empty", remedy: "Declare an SPDX identifier. A plugin with no licence is code nobody may legally run." },
  E_LICENSE_NOT_ALLOWED: {
    level: "error", stage: "metadata",
    title: "That licence is not on the allowlist",
    remedy:
      "See `policy/spdx-allowlist.json`. It is an allowlist, not a denylist: a licence nobody here " +
      "has read is one this registry cannot promise anything about. To add one, open a pull request " +
      "with a sentence on why.",
  },

  // ── the card, in more than one language ────────────────────────────────────
  //
  // Read out of `locales/<code>.json` in the bundle the bot already holds, under
  // the two reserved keys `listing.name` and `listing.description`. Nothing here
  // is typed by a submitter and nothing here is a second download.
  E_LISTING_NOT_ENGLISH: {
    level: "error", stage: "metadata",
    title: "The store card's summary is not in English",
    remedy:
      "Write `plugin.description` in English and put your own language in `locales/<code>.json` " +
      "under `listing.description`. The card, the search index, every client that predates " +
      "localization and every user whose language you have not translated all read the English " +
      "one. This is a SCRIPT check, not a language detector: it refuses a description whose " +
      "letters are under 60% Latin, and it cannot tell English from French.",
  },
  W_LISTING_NAME_NOT_LATIN: {
    level: "warn", stage: "metadata",
    title: "The plugin's name is mostly outside the Latin script",
    remedy:
      "Nothing to fix, necessarily — a product name is not prose and is legitimately anything. " +
      "The summary beside it is held to English, so check that the two read as one listing.",
  },
  E_LOCALE_NO_ENGLISH: {
    level: "error", stage: "metadata",
    title: "`locales/` has translations and no `en.json`",
    remedy:
      "`astra-plugin locale add en`. English is the base every other language falls back to, and " +
      "the released daemon falls back per FILE rather than per key — it selects one whole locale " +
      "map and then resolves — so without `en.json` there is nothing to fall back to and the key " +
      "itself reaches the screen.",
  },
  E_LOCALE_UNKNOWN_CODE: {
    level: "error", stage: "metadata",
    title: "A locale file is named for a language Astra cannot be set to",
    remedy:
      "The ten codes are in `AstraPlugins/spec/locales.yaml`. Matching is exact string equality and " +
      "there are no region tags anywhere in this system — Chinese is `zh`, never `zh-CN` — so a " +
      "file named anything else is packed, digested, signed, installed, and read by nothing.",
  },
  E_LOCALE_MALFORMED: {
    level: "error", stage: "metadata",
    title: "A locale file is not a flat map of string to string",
    remedy:
      "Flatten it. The daemon deserialises `HashMap<String,String>` and drops the WHOLE file on one " +
      "non-string value — silently, at install time — so a nested object costs every translation in " +
      "that file and says nothing. Plurals are key suffixes (`msg.done.one`), never nested objects.",
  },
  E_LOCALE_KEY_MISSING: {
    level: "error", stage: "metadata",
    title: "A locale file is missing keys `en.json` declares",
    remedy:
      "`astra-plugin locale add <code>` seeds the missing keys from English and leaves what is " +
      "already translated alone. Every language must carry every key while the daemon falls back " +
      "per file: a key missing here is not filled in from English, it is shown to the user as a key.",
  },
  E_LOCALE_KEY_EXTRA: {
    level: "error", stage: "metadata",
    title: "A locale file declares keys `en.json` does not",
    remedy:
      "Add them to `en.json` or delete them. `en.json` is the base, so a key that is not in it can " +
      "never be reached from any other language and is dead weight in every bundle.",
  },
  E_LISTING_TEXT_MISMATCH: {
    level: "error", stage: "metadata",
    title: "`en.json`'s `listing.*` disagrees with `plugin.toml`",
    remedy:
      "`astra-plugin locale sync` rewrites `en.json` from `plugin.toml`. They are the same fact in " +
      "two files because the manifest crate cannot hold a locale table, and the card is drawn from " +
      "one while every other language falls back to the other — so a disagreement is a listing that " +
      "says two things.",
  },
  E_LOCALE_CARD_TOO_LONG: {
    level: "error", stage: "metadata",
    title: "A localized card string is over its cap",
    remedy:
      "See `policy/limits.json`: 64 characters for a name, 4000 for a description. The block is " +
      "refused, so that language's card falls back to English with nothing explaining why.",
  },
  E_LOCALE_CARD_TOO_LARGE: {
    level: "error", stage: "metadata",
    title: "One listing's translations are over the per-listing budget",
    remedy:
      "See `max_listing_i18n_bytes` in `policy/limits.json`. The catalogue is one signed document " +
      "every install fetches whole every hour; this budget is what keeps one listing's translations " +
      "from being everybody's download.",
  },
  E_LOCALE_TOO_LARGE: {
    level: "error", stage: "metadata",
    title: "A locale file is too big to read",
    remedy:
      "See `max_locale_bytes` and `max_locale_keys` in `policy/limits.json`. The file is refused " +
      "unread — a locale file is loaded whole by the daemon, by the CLI and by this bot, and before " +
      "the parse is the only cheap place to stop a runaway one.",
  },
  E_LOCALE_BUNDLE_MISMATCH: {
    level: "error", stage: "bundle",
    title: "This release's bundles carry different translations",
    remedy:
      "Build every platform from the same tree. The store card is derived from one bundle and each " +
      "platform installs its own, so bundles whose `locales/` differ describe different plugins to " +
      "different halves of the users.",
  },
  W_LOCALE_STALE: {
    level: "warn", stage: "metadata",
    title: "A translation describes English that has since been rewritten",
    remedy:
      "`astra-plugin locale sync` before the next release. The affected strings fall back to English " +
      "on the card rather than being shown: a confidently wrong sentence in a language nobody here " +
      "can proof-read is worse than a correct one in the wrong language, and the release is not " +
      "refused over prose.",
  },
  W_LOCALE_NO_CARD_TEXT: {
    level: "warn", stage: "metadata",
    title: "`en.json` declares neither reserved listing key",
    remedy:
      "`astra-plugin locale sync` writes `listing.name` and `listing.description`. They are the only " +
      "two keys the registry reads out of `locales/`, so without them a plugin that translates its " +
      "whole interface still gets an English-only store card.",
  },
  N_LISTING_LANGUAGE_EXEMPT: {
    level: "note", stage: "metadata",
    title: "The English card rule was waived for this repository",
    remedy:
      "Nothing to do. The waiver is a reviewed entry in `policy/listing-language-exemptions.json`, " +
      "keyed on the repository rather than on the plugin id so that a rename cannot walk past it.",
  },

  // ── versions and identity ──────────────────────────────────────────────────
  E_VERSION_NOT_NEW: { level: "error", stage: "version", title: "That version is already listed, or is older than one that is", remedy: "Releases go forward. Bump the version and cut a new release — a version that is republished with different bytes is how a downgrade attack starts." },
  E_VERSION_INCONSISTENT: { level: "error", stage: "version", title: "The release's bundles do not agree on a version", remedy: "One release, one version, every target. Check the build matrix." },
  R_IDENTITY_CHANGED: {
    level: "review", stage: "version",
    title: "This plugin was listed from a different repository",
    remedy:
      "Held for a human, always. A repository change is an author change until somebody says " +
      "otherwise, and every installed copy carries a pin to the old one.",
  },
  R_FIRST_LISTING: {
    level: "review", stage: "version",
    title: "First listing for this plugin",
    remedy: "A human reads the first one, once, ever. Later releases from the same repository are zero-touch.",
  },

  // ── the host-RPC heuristic ─────────────────────────────────────────────────
  E_HOST_RPC_UNDECLARED: {
    level: "error", stage: "rpc-scan",
    title: "Source in the bundle calls a high-risk host RPC the manifest does not declare",
    remedy:
      "Declare the capability the call needs, or remove the call. The four that block are " +
      "`FireTrigger`, `SendChatMessage`, `SetVariable` and `SetThemeContribution` — each of them " +
      "acts on the user's session rather than inside your plugin.",
  },
  W_HOST_RPC_UNDECLARED: { level: "warn", stage: "rpc-scan", title: "Source in the bundle names a host RPC the manifest does not declare", remedy: "Not blocking. Declare the capability if the call is real; ignore this if the string is a comment or a log line." },
  W_HOST_RPC_IN_OPAQUE_FILE: {
    level: "warn", stage: "rpc-scan",
    title: "A compiled file contains a host RPC name",
    remedy:
      "Not blocking, and usually not a call: a linked SDK client contains the name of every method " +
      "on the service whether or not you invoke it. Named so it is on the record, not because it is " +
      "evidence.",
  },
  R_HOST_RPC_IN_VENDOR_DIR: {
    level: "review", stage: "rpc-scan",
    title: "One of the four acting-outside-the-plugin RPCs is named inside a `generated/` or `vendor/` directory",
    remedy:
      "Held for a human. Those two directory names are chosen by whoever built the bundle, not by a " +
      "toolchain, so the scan no longer skips them — but a real generated tree is a normal thing to " +
      "ship. Declare the capability or permission if the call is yours, or say in the issue what wrote " +
      "the file.",
  },
  W_HOST_RPC_IN_VENDOR_DIR: {
    level: "warn", stage: "rpc-scan",
    title: "A non-blocking host RPC is named inside a `generated/` or `vendor/` directory",
    remedy: "Recorded. Declare the capability if the call is yours.",
  },
  N_HOST_RPC_SCAN_SCOPE: {
    level: "note", stage: "rpc-scan",
    title: "The RPC scan read source files only",
    remedy:
      "Compiled binaries and vendored SDK code are not decidable by string matching. This check " +
      "catches accidents; it does not catch anyone who is trying.",
  },

  // ── the bot's own output ───────────────────────────────────────────────────
  E_DERIVED_LISTING_INVALID: {
    level: "error", stage: "derive",
    title: "The listing the bot derived does not pass this repository's own validator",
    remedy: "A bug in this registry, not in your plugin. Please leave the issue open.",
  },
};

/** @param {string} code */
export function codeDef(code) {
  const def = CODES[code];
  if (!def) {
    // Better a loud unknown than a comment that renders `undefined` at a
    // stranger. Every code the bot emits has to be declared above.
    return { level: "error", stage: "?", title: `undeclared code ${code}`, remedy: "This is a bug in the registry bot: the code is not in bot/lib/codes.mjs." };
  }
  return def;
}

/** Codes that stop a release being listed. */
export const BLOCKING_LEVELS = new Set(["error"]);
/** Codes that hand the decision to a person. */
export const REVIEW_LEVELS = new Set(["review"]);

export const LEVEL_GLYPH = { error: "❌", review: "🧑‍⚖️", warn: "⚠️", pass: "✅", skip: "⏭️", note: "ℹ️" };
