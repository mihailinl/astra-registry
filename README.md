# astra-registry

The catalogue Astra's plugin store reads.

**The author's GitHub Release is the origin of the bytes. This repository pins
*which* bytes, by digest.** Nothing is hosted here — no binaries, no archives,
no mirrors. A listing is a small JSON file saying: this plugin, this version,
this repository's release, this exact SHA-256. Astra downloads from the author's
release and refuses anything whose digest is not the one listed here.

That split is the whole design. Hosting the bytes would make this repository a
target worth attacking; pinning them makes it a target that is not worth much,
because tampering with a listing changes a digest, and a changed digest is a
one-line diff in a public git history.

```
plugins/<id>/plugin.json              what the plugin is        hand-written
plugins/<id>/versions/<semver>.json   one release               hand-written
registry/v1/index.json                what Astra fetches        GENERATED
schema/                               the shapes, as JSON Schema
policy/                               limits, SPDX allowlist, reserved ids
tools/                                generator, validator, self-test
bot/                                  submission checks (Phase 2 half)
```

---

## The URL Astra fetches

```
https://raw.githubusercontent.com/mihailinl/astra-registry/main/registry/v1/index.json
```

One file, unsigned in Phase 2, served over HTTPS. It carries a `sha256` and a
`size` for every artifact, so the *artifacts* are pinned even though the
*catalogue* is not yet signed. Phase 3.2 signs the index with the registry key
and the daemon starts verifying it offline against a root key compiled into the
binary; until then, HTTPS is the only thing standing behind this file, and
`bot/lib/phase3.mjs` prints that on every bot run so nobody forgets.

## Two files per listing, and why

`plugin.json` holds what does not change between releases — name, summary,
license, source repository. `versions/<semver>.json` holds one release: the tag,
the artifacts, their digests.

One file per plugin per version buys three things that a single big file, or a
single file per plugin, does not:

- **No merge conflicts.** Two authors publishing in the same minute touch two
  different paths. A shared catalogue file would have them queueing behind each
  other's rebases.
- **A review diff that is one whole file.** A reviewer sees a new file with
  everything in it, not five lines of context around a changed digest.
- **`git log plugins/<id>/` is the audit trail.** Every change to what a plugin
  is, and every release it ever shipped, in one command, with authorship and
  dates, for as long as the repository exists.

## The index is generated, and CI proves it

`registry/v1/index.json` is produced by `tools/build-index.mjs` and by nothing
else. It carries a DO-NOT-EDIT banner as its first key, and
`.github/workflows/build-index.yml` regenerates it and compares byte for byte on
every push and every pull request.

That check exists because of a specific attack: the highest-value edit anyone
with commit access could make to this repository is a hand-typed URL or digest
in the index, pointing at bytes that no listing describes. A generated file
whose generation is verified in CI turns that edit into a red build.

The generator is deterministic — object keys sorted by UTF-16 code unit, plugins
by id, releases by semver precedence, and **no clock read anywhere**. Same
sources plus same serial gives the same bytes, on any machine, on any rerun.
`published_at` is recorded data copied from the release, never "now"; a
generator that stamped the time would make its own output unreproducible, and
Phase 3 signs these bytes.

Two flat fields — `version` and `platform_downloads` — are a *projection* of
`releases[0]`, emitted for the daemon shipping today, which knows only those.
They are computed in the same pass from the same object, so they cannot drift.
An entry with no digest gets an **empty** `platform_downloads`: a client that
understands only the flat fields has no way to verify a download, so the only
safe thing to hand it is nothing.

## The serial

`serial` is monotonic and comes from **the commit count of `main`, path-limited
to `plugins/`**.

It is never read-and-incremented from a file. Two pull requests merging in the
same minute would both read *N* and both write *N+1*, and the second would
silently un-bump the first — in a field whose only job is to let the daemon
refuse a rolled-back catalogue. A commit count cannot do that: it is a property
of the history, not of a file, so concurrent merges get distinct values by
construction. It is path-limited so a commit that touches only docs does not
move the catalogue's version number.

`.github/workflows/build-index.yml` also declares a `concurrency:` group, so one
index build is ever in flight.

## The staging entries — read this before trusting the index

**Every listing here is marked `"staging": true`,** all eleven. None of the
releases they name exists, so none carries a `sha256` or a `size` — the only
honest thing they can carry, since a digest for bytes nobody has produced would
be a fabrication.

The reason is not in this repository, and it is smaller than it used to be.
`AstraPlugins/.github/workflows/plugin-release.yml` once asserted that the tag
equals `v<version>`, which eleven plugins in one repository could not each own;
it now takes a `tag-prefix` input, so `dice-roller-v0.1.1` is a tag it accepts.
What is left upstream is mechanical, and none of it has happened yet:

1. tag `plugin-release/v1` in AstraPlugins, so `astra-plugin init-ci` has
   something to pin the caller to other than a moving default branch;
2. `astra-plugin init-ci examples/<id>`, which writes that plugin's nine-line
   caller workflow;
3. push `<id>-v<version>`, and let the workflow build, attest and upload.

`GET /repos/mihailinl/AstraPlugins/releases` returns `[]` as this is written —
that is the whole of it. Every `staging_reason` in `plugins/*/versions/*.json`
says the same thing, per plugin, with its own tag named.

Everything about how those entries are treated follows from there:

- `tools/validate.mjs` **rejects** them. Accepting a listing whose artifact does
  not exist makes the whole registry worthless, so tolerating one takes an
  explicit `--allow-staging`. It is passed on one line of `build-index.yml` and
  one of `bot-checks.yml`, and nowhere else.
- The generated index marks each plugin `"staging": true` and leaves
  `download_url` and `platform_downloads` empty. A digest-blind client cannot
  reach any of them.
- `bot/run-checks.mjs` skips their artifact checks and says why, rather than
  reporting a 404 that means "the staging entry is still a staging entry".

`--allow-staging` is load-bearing today, and every listing added moves it further
from removal rather than closer. That is precisely why it is a flag a human types
and not a default: the day it can be deleted is the day this section can be too.

**To go live,** per plugin: publish the release, replace `staging`/`staging_reason`
with the real `sha256`, `size`, `published_at` and `release.commit`, and
regenerate. Drop `--allow-staging` from `build-index.yml` and `bot-checks.yml`
only once the **last** staging entry is gone.

## Where artifacts come from — and how to run your own catalogue

A version file's `release` says where its bytes live, and every artifact URL
must sit under the prefix that release implies. There are two kinds:

| `release.kind`   | anchor                                                | who uses it |
| ---------------- | ----------------------------------------------------- | ----------- |
| `github_release` | `https://github.com/<repo>/releases/download/<tag>/`   | this catalogue |
| `direct`         | `release.base_url`                                     | a self-hosted or staging catalogue |

The pinning rule is one rule with two anchors, checked in
`tools/validate.mjs`: a URL that does not start with its release's prefix is an
error, and so is a filename that is not `<id>-<version>-<target>.astraplugin`.
The artifact `url` pattern in the schemas is deliberately *not* the thing doing
that work. It used to be — it hardcoded `github.com/<owner>/<repo>/releases/
download/` — and the effect was that a self-hosted catalogue could not state a
legal listing at all, even though Astra's daemon supports one: its
`artifact_download_policy` adds the artifact URL's own host to the allow-list,
with the comment "a self-hosted or staging catalogue serves its artifacts from
its own origin". Half the system supported it and the other half forbade
expressing it. The pattern now says `https` and a host; the release object says
which host.

`direct` is expressible, and it is **not** accepted here without someone typing
`--allow-direct`, the same bargain as `--allow-staging`: a direct release names
no GitHub release, so there is no build for Phase 3 to attest and no assets
endpoint for the bot to read. It carries a digest and nothing else. Nothing in
this repository passes the flag; POLICY.md §1 is the rule.

To stand one up — a QA catalogue, an air-gapped mirror, a rehearsal of a
release before it is public:

```bash
# 1. a listing that names your origin
#    "release": { "kind": "direct", "base_url": "https://catalogue.internal:8443/astra/" }
#    "artifacts": { "linux-x64": { "url": "https://catalogue.internal:8443/astra/<id>-<v>-linux-x64.astraplugin", ... } }
# 2. check it against the bundles you actually built
node tools/validate.mjs --registry-dir ../my-catalogue --allow-direct --artifacts ./dist --no-index
# 3. generate its index, then serve that file and the bundles from your origin
node tools/build-index.mjs --registry-dir ../my-catalogue
```

Both tools take `--registry-dir`, and neither takes its **rules** from there:
schemas and `policy/` always come from this repository, so a downstream tree is
judged by the same file the public catalogue is judged by and cannot relax
anything by editing its own copy.

Serve it over **https**: the daemon's download policy is `https_only()` with no
loopback exemption, so a plaintext URL is refused on the user's machine after
the listing has already promised it. The schemas refuse to write one down for
the same reason.

## Listing a plugin

1. Run the checks locally, from a checkout of this repository:
   `node tools/validate.mjs` and `node bot/run-checks.mjs --plugin <id>`.
   In your plugin's own directory, `astra-plugin check --strict` catches the
   manifest problems before a listing exists at all.
2. Open a listing issue (`.github/ISSUE_TEMPLATE/plugin-listing.yml`). It asks
   for two facts: the repository and the release tag. Everything else is read
   out of the bundle, which is why there is no "your form disagrees with
   plugin.toml" rejection.
3. A maintainer adds `plugins/<id>/plugin.json` and the first version file,
   regenerates the index, and merges.

From Phase 3 that becomes zero-touch for subsequent releases: tag → CI →
attestation → the bot verifies → index regenerated. A human sees a plugin again
only on a first listing, a newly requested high-risk permission, an identity
change, or a report. See `POLICY.md`.

## Running the tools

No dependencies, no lockfile, no `npm install`. Node 20+ and nothing else.

```bash
node tools/selftest.mjs                 # 39 checks, offline, ~1s
node tools/validate.mjs                 # strict: refuses the staging entry
node tools/validate.mjs --allow-staging # what CI runs today
node tools/validate.mjs --allow-direct  # tolerate a non-GitHub artifact origin
node tools/build-index.mjs              # regenerate registry/v1/index.json
node tools/build-index.mjs --check      # fail if the committed file differs
node bot/run-checks.mjs --plugin dice-roller --allow-staging
```

Two flags exist for checking digests against real bytes:
`--artifacts DIR` hashes local files (what the bot uses after it downloads), and
`--online` fetches each artifact and hashes it. Everything else is offline by
design: this is the last gate before a listing reaches a stranger's machine, and
a gate that needs the network is a gate that gets skipped the first time GitHub
is slow, and then quietly forever.

The zero-dependency rule is not minimalism for its own sake. It is what makes
"offline" true and what keeps this repository's own supply chain to exactly one
thing: Node.

## What is not here

Named, so nobody assumes otherwise:

- **No signature on the index.** Phase 3.2.
- **No `trust.json`, no root key, no key rotation.** Phase 3.1.
- **No `revocations.json`.** There is no kill switch for a listed plugin yet.
  Phase 3.9.
- **No build-provenance verification.** Nothing here proves who produced an
  artifact — only that its bytes match what the listing says. Phase 3.3.
- **No ownership proof.** That the submitter controls the repository they listed
  is currently a maintainer's judgement. Phase 3.3.
- **No download counts, no stars, no telemetry.** The index emits `0` for both
  because the daemon's current reader requires the fields. This registry counts
  nothing about anyone; "popular" sorting will need a source that is not a
  privacy problem before it means anything.

## Related

- `PRODUCTION_PLAN.md` in AstraPlugins — §2 architecture, §3.5 the author's
  journey, §5.2 what is signed, §5.3 the install-time verification algorithm.
  Where this README and that document disagree, that document wins.
- `POLICY.md` — what gets listed, and what gets removed.
- `bot/README.md` — what the bot checks, and everything it does not.
