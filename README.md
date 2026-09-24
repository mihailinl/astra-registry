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
https://mihailinl.github.io/astra-registry/registry/v1/index.json
```

One file, served over HTTPS. It carries a `sha256` and a `size` for every
artifact, so the *artifacts* are pinned by digest regardless of what is believed
about the catalogue itself.

**Not the copy in this branch.** `raw.githubusercontent.com/…/main/registry/v1/index.json`
serves the committed file, which carries `"signatures": []` permanently and by
design — see below. The signed catalogue exists only on the `signed` branch and
in the deployment, so fetching `main`'s copy gets a catalogue the daemon will
classify `UNSIGNED` and refuse. That URL was the daemon's default until it was
measured against this one; `astra-daemon`'s `DEFAULT_REGISTRY_URL` now points
here.

Since Phase 3.2 the catalogue is a **signed envelope** —
`{ "signatures": [...], "signed": { "schema", "serial", "plugins" } }` — and only
the `signed` member is covered by a signature. The construction is
`Ed25519( SHA-256( "astra.registry.index/1" ‖ 0x00 ‖ JCS(signed) ) )` over RFC
8785 canonical JSON, made by an index key that a **root-signed `trust.json`**
delegates to. `bot/lib/sign.mjs` is the only place that is written on this side
and `astra-daemon/src/plugins/trust.rs` the only place on the other; both are
pinned to RFC 8785's own §3.2.3 vector by the same asserted digest, so the
signer and the verifier cannot drift apart in silence.

**The trust anchor is the root key, never this hostname.** The index is believed
because a root key vouched for the key that signed it, not because of where it
was fetched from. The catalogue can move to another host without a daemon
change, and an attacker serving their own file from this exact URL gains
nothing.

Where the signatures are, and where they are not:

- The **committed** `registry/v1/index.json` carries `signatures: []`, and so
  does the committed `registry/v1/revocations.json`. This repository holds no
  signing key; `sign.yml`'s `publish` job signs both inside the `publish`
  environment and commits the signed copies to the `signed` branch. An empty
  array says "unsigned" out loud, where an absent member could not be told from
  a stripped one.
- The **root ceremony was run** on 2026-08-11, offline.
  [`registry/v1/root.json`](registry/v1/root.json) publishes two Ed25519 public
  keys, `astra-root-2026a` (active) and `astra-root-2026a-reserve`, and
  `node bot/check-roots.mjs` holds them to the two `bot/lib/roots.mjs` compiles
  in. **`trust.json` is signed**: at serial 1 by `50c40c3` (2026-08-11), and
  again at serial 2 by `5283fa7` (2026-08-19). Measured at `62c0f8e`, it
  carries one signature, by the active root `astra-root-2026a`; it delegates
  one index key, `astra-index-2026a`, with `not_before` 2026-08-19T11:00:49Z
  and no `not_after`; it allows two reusable-workflow commits; and the document
  expires 2027-08-19T11:00:49Z. The catalogue and the withdrawal list at the
  head of `signed`, `430efba` at that measurement, each carry one signature, by
  `astra-index-2026a`, and both verify under it. None of that has to be taken
  from this page — these print it, serials and expiry included:

  ```bash
  node tools/sign-trust.mjs --verify registry/v1/trust.json   # against root.json's keys
  git fetch origin signed && d=$(mktemp -d)
  git show origin/signed:registry/v1/index.json > "$d/index.json"
  git show origin/signed:registry/v1/revocations.json > "$d/revocations.json"
  node bot/sign-index.mjs --verify "$d/index.json" --trust registry/v1/trust.json
  node tools/sign-revocations.mjs --verify "$d/revocations.json" --trust registry/v1/trust.json
  ```

  Pages serves `signed`'s catalogue, `trust.json` and `root.json`, and `main`'s
  **unsigned** withdrawal list, on purpose, until the commit that adds
  `policy/pages-withdrawal-list.json` (`tools/signer/pages.mjs` says why);
  `served-set.yml` compares what Pages serves with `signed` on a schedule.
  **What the daemon does with any of this is outside this repository.** Its
  verifier is in `Astra`, which nothing here reads, so no sentence on this page
  about how a daemon classifies a catalogue is checked by anything in it. The
  clearly-labelled test keys in `tools/testkeys/` are never a stand-in for these
  keys. See [`SECURITY.md`](SECURITY.md) and [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

`bot/lib/phase3.mjs` still lists every check that does not run yet, by its final
error code, so nobody forgets which of these is which.

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
these are the bytes that get signed.

That is also why `issued_at` and `expires_at` are stamped by `bot/sign-index.mjs`
at **signing** time rather than by the generator: a catalogue nobody edited for
31 days must not expire itself, and a generator that reads a clock is a
generator whose output cannot be reproduced. `build-index.mjs --check` therefore
compares the *content* projection — `signed` minus those two timestamps — so a
signed file can still be held to being the catalogue the sources describe.

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

**A version file marked `"staging": true` names a release that does not
exist,** so it carries no `sha256` and no `size` — the only honest thing it can
carry, since a digest for bytes nobody has produced would be a fabrication.
When this catalogue began, every listing was one. Which files still are, and
which releases AstraPlugins has actually published, both move, so this page
names neither and gives the commands that do:

```bash
git grep -l '"staging": true' -- plugins           # the staging entries
gh api repos/mihailinl/AstraPlugins/releases --paginate --jq '.[].tag_name'
```

What made every listing staging was upstream and is gone.
`AstraPlugins/.github/workflows/plugin-release.yml` once asserted that the tag
equals `v<version>`, which many plugins in one repository could not each own;
it now takes a `tag-prefix` input, `plugin-release/v1` is tagged for
`astra-plugin init-ci` to pin callers to, and AstraPlugins' plugins are released
under `<id>-v<version>` tags. What keeps an entry staging now is its own
release: until that tag is published and the record rewritten with its digests,
it stays one. Each record's `staging_reason` describes AstraPlugins' releases as
they stood when it was written; the second command is the current answer.

Everything about how those entries are treated follows from there:

- `tools/validate.mjs` **rejects** them. Accepting a listing whose artifact does
  not exist makes the whole registry worthless, so tolerating one takes an
  explicit `--allow-staging` — or `allowStaging: true`, its in-process form.
  Several workflows and tools pass it, and the set moves; this prints the lines
  that pass it literally (`bot/run-checks.mjs` forwards its own flag, so
  `bot-checks.yml`'s line is where that one is decided):

  ```bash
  git grep -n -E -e 'node [^#]*--allow-staging' -e '\[.*"--allow-staging"' \
    -e 'allowStaging: true' -- .github bot tools/signer ':!bot/tests' ':!bot/manifest-probe'
  ```
- The generated index marks a plugin `"staging": true`, and leaves its
  `download_url` and `platform_downloads` empty, when its latest version is a
  staging entry; an older staging version under a released one is marked in its
  own `releases` record, and no flat field points at it. A digest-blind client
  cannot reach any of them.
- `bot/run-checks.mjs` skips their artifact checks and says why, rather than
  reporting a 404 that means "the staging entry is still a staging entry".

`--allow-staging` is load-bearing for as long as one staging entry remains. That
is precisely why it is a flag a human types and not a default: the day it can be
deleted is the day this section can be too.

**To go live,** per entry: publish the release, replace `staging`/`staging_reason`
with the real `sha256`, `size`, `published_at` and `release.commit`, and
regenerate. Drop `--allow-staging` from every line the command above prints only
once the **last** staging entry is gone.

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

Three steps, and you write nothing into this repository. The bot writes the
listing, from your release bundle.

**First, you need a GitHub Release that already exists.** This registry reads
one; it does not build anything. Build and release your plugin in AstraPlugins
first — `plugin-release.yml` there produces the `.astraplugin` files and the
*attestation*, which is a signed statement from GitHub saying which workflow, in
which repository, built those exact bytes. Without one there is nothing here to
verify.

**Second, you need one commit on your side.** `.well-known/astra-plugin-owner`,
on your default branch, containing your GitHub login on a line of its own:

```bash
mkdir -p .well-known
echo YOUR-GITHUB-LOGIN > .well-known/astra-plugin-owner
git add .well-known/astra-plugin-owner && git commit -m "registry: owner" && git push
```

That is what proves the account opening the request controls the repository. For
a repository this registry does not itself own it is the **only** proof
available — GitHub answers the collaborator endpoint only for a caller that can
already see the repository, so it tells this bot nothing — and the form asks for
it as a required confirmation. One commit, no CI.

### 1. Check it locally first

In your plugin's own directory:

```bash
astra-plugin publish --dry-run
```

It takes seconds and prints the checks it ran plus the ones only the registry
can run. Fixing something here is minutes; fixing it after you have submitted is
a round trip.

### 2. Open a listing request

<https://github.com/mihailinl/astra-registry/issues/new?template=plugin-listing.yml>

It asks for **two facts** — the repository and the release tag — and three
required confirmations, the first being that you have committed
`.well-known/astra-plugin-owner` to your default branch with your login in it.
Everything else (id, version, capabilities, permissions, licence,
summary, platforms, digests) is read out of the bundle, which is covered by the
attestation. That is why there is no "your form disagrees with `plugin.toml`"
rejection: the form is not consulted about any of it.

Blank issues are off, so this link is the way in. If you land on a chooser page,
pick **Plugin listing request**.

### 3. Read the bot's comment

The bot downloads your release assets, verifies the attestation, reads the
manifest and comments on your issue with a table of every check and a digest.
Allow minutes, not seconds — the run compiles a manifest parser first.

You get one of four answers, always on the thread:

| | What it means |
|---|---|
| **Published** | Live. Nothing more to do. |
| **Publishing itself at `<time>`** | Everything passed; it waits out a publication delay and then goes live on its own. |
| **Held for a maintainer** | A first listing is one of exactly three things a person decides. Answer within 48 h, by `/approve` or `/reject <reason>`. |
| **Not published** | A check failed. The comment names it and the fix; comment `/recheck` when you have pushed a new release. |

**If you ever get silence, that is a bug in this registry.** Say so on the issue.

### After the first time

Listing happens **once, ever**. Every later release is zero-touch: tag it, let
CI build and attest it, and the registry picks it up — by a `/release v0.2.0`
comment on your listing issue within minutes, or by a daily backstop that polls
your release feed within a week.

A person sees your plugin again only on a newly requested high-risk permission,
a change of repository, or a report. `docs/POLICY.md` is the detail.

## Running the tools

No dependencies, no lockfile, no `npm install`. Node 20+ and nothing else.

```bash
node tools/selftest.mjs                 # the suite; its summary line counts the checks
node tools/validate.mjs                 # strict: refuses every staging entry
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

- **No production signing key, so no signed catalogue on `main`.** The
  committed `registry/v1/index.json` and `registry/v1/revocations.json` carry
  `"signatures": []`. The index signing key and its id are secrets of the
  `publish` environment, where `sign.yml` signs both documents and commits the
  signed copies to the `signed` branch. *Where the signatures are*, above, has
  the commands that verify them and `trust.json`.
- **Nothing intersects a candidate with `revocations.json`.** The document
  exists, the daemon enforces it at five points, and `tools/build-revocations.mjs`
  / `tools/sign-revocations.mjs` produce it — but neither bot path checks a
  *candidate* artifact's digest against it before listing, so this registry can
  publish a version it has itself withdrawn and the daemon is the only thing that
  stops it. `E_REVOKED` in `bot/lib/phase3.mjs`.
- **Build provenance and ownership are checked on ONE of the two paths.**
  `bot/ingest.mjs` verifies a GitHub build attestation against the
  reusable-workflow allowlist (`bot/lib/attestation.mjs`) and proves the
  submitter has admin or maintain permission on the repository
  (`bot/lib/ownership.mjs`) — on the **release** path. On the **pull-request**
  path neither runs, because there is no submitter to attribute an attestation
  to and the maintainer reading the diff is the control. `bot/run-checks.mjs`
  prints every such unchecked row on every run rather than reporting a clean
  bill of health.
- **No download counts and no stars in the catalogue.** The index emits `0` for
  both because the daemon's current reader requires the fields, and it will go on
  emitting `0`. **Amended YYYY-MM-DD (ROLL-47 B1):** this repository itself still
  receives nothing from an installed copy, but Minice's plugins service now counts
  installs and updates as aggregates, under its own privacy disclosure (ROLL-48);
  "popular" sorting, if it comes, comes from there and not from this catalogue.
- **Not the desktop update manifest.** Its signer, its test-key helpers and
  their tests moved into Astra as `tools/update-manifest-signer/`, and the
  records of each signed release as `release-records/`, at
  Astra@44e86d82495db4ffa383c9b4ebe6a593014007f2 (client plan C2.1; registry plan RC-R3-4). The
  manifest is Astra's; this registry shares only the root key's ceremony with
  it. One file here is still read from there: Astra's rehearsal loads the
  published TEST root through `tools/testkeys/regenerate.mjs`'s `loadTestRoot`,
  which `tools/selftest/desk-moved.mjs` holds to its shape.

## Related

- `PRODUCTION_PLAN.md` in AstraPlugins — §2 architecture, §3.5 the author's
  journey, §5.2 what is signed, §5.3 the install-time verification algorithm.
  Where this README and that document disagree, that document wins.
- `POLICY.md` — what gets listed, and what gets removed.
- `bot/README.md` — what the bot checks, and everything it does not.
