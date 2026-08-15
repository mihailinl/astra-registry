# The registry bot

Two entry points, because there are two different questions.

| | `bot/ingest.mjs` | `bot/run-checks.mjs` |
|---|---|---|
| Input | a repository and a release tag | a hand-edited listing in a pull request |
| Trust boundary | **yes** | no — the reviewer is |
| Ownership | proved against GitHub | the reviewer |
| Attestation | verified, and pinned to an allowlisted workflow commit | not attempted |
| Listing | **written** by the bot, from the bundle | read, and checked against its artifacts |

`docs/BOT-CHECKS.md` is the reference: every code, what it means, what to do
about it, and — at least as important — the three checks that are heuristics and
what they do not catch. It is generated from `bot/lib/codes.mjs`, so it cannot
drift; `node bot/gen-checks-doc.mjs --check` fails when it has.

```bash
node bot/ingest.mjs --repo you/dice-roller --tag v0.2.0 --submitter you
# 0 listed · 1 refused · 3 held for a maintainer · 2 the bot itself failed
```

The trust chain is provisioned, and runs no longer stop at
`E_TRUST_UNPROVISIONED`: the ceremony in `SECURITY.md` was run,
`registry/v1/root.json` carries `astra-root-2026a` and its reserve, and
`registry/v1/trust.json` is signed by the active root at serial 1 — delegating
`astra-index-2026a` and allowlisting one reusable-workflow commit. An
attestation from any other workflow is still refused, which is the whole point
of the allowlist.

What is still unsigned is one step further down: `registry/v1/index.json`
carries `"signatures": []`, so a daemon reads the catalogue as `UNSIGNED` and
the artifact digest is doing all the work. That is a publish run away, not code.

## The language decision, and why it is not the one the plan wrote down

`PRODUCTION_PLAN` task 3.3 specifies **one Rust binary linking the shared
`astra-plugin-manifest` crate**. What landed is a **JavaScript pipeline plus a
small Rust helper that owns everything the shared crate decides**, and the
reasoning is worth writing down because the alternative looks tidier on paper.

The plan's real requirement is the *crate*, not the language: the registry must
not have its own idea of what a `plugin.toml` is. That requirement is met in
full — `bot/manifest-probe/` links `astra-plugin-manifest` and is the only thing
in this repository that parses a manifest.

Porting the *rest* of the bot to Rust would have meant reimplementing
`tools/validate.mjs`, and that file is the reason the pull-request path and CI
cannot disagree about what a valid listing is. There would then be two
definitions of a valid listing — one in Rust for releases, one in JavaScript for
pull requests — which is precisely the fork task 3.7 exists to delete, moved to a
different file. The same argument applies to `tools/lib/canonical.mjs` (RFC 8785,
byte-matched against the daemon's Rust implementation and against the RFC's own
vectors), to `tools/lib/zip.mjs`, and to `bot/lib/sign.mjs`.

So the split is by *what owns the definition*, not by language:

- **Rust, because the daemon owns the definition:** `plugin.toml` — the parse,
  the `plugin.id` charset, reserved device names, the capability vocabulary,
  `min_astra_version`, the platform-key mapping.
- **JavaScript, because this repository owns the definition and already has
  exactly one of it:** listing rules, canonical JSON, signatures, the ZIP
  reader, GitHub, orchestration.

What that costs, stated plainly: one subprocess per bundle, and a build step
that has to succeed before an ingest can run. `bot/lib/probe.mjs` treats a
missing probe as `E_PROBE_UNAVAILABLE` at **error** level rather than skipping
the manifest checks, because a bot that quietly stops validating manifests on a
runner where the build failed — and reports success — is a worse outcome than a
red run.

A JavaScript reimplementation of manifest parsing was never on the table.

### Getting the crate

There is **no copy of `astra-plugin-manifest` in this repository.** Astra is the
source of truth, AstraPlugins vendors it under a byte-equality check
(`tools/check-manifest-crate.sh` there), and a third copy here would be a third
place to drift silently.

```bash
bot/manifest-probe/link-deps.sh          # symlink a sibling AstraPlugins checkout
ASTRA_PLUGINS_DIR=/path/to/AstraPlugins bot/manifest-probe/link-deps.sh
bot/manifest-probe/link-deps.sh --clone  # CI, with ASTRA_PLUGINS_REF pinned to a SHA
cargo build --release --manifest-path bot/manifest-probe/Cargo.toml
```

`.github/workflows/ingest.yml` pins `ASTRA_PLUGINS_REF` to a commit SHA. Bumping
it is a reviewed commit, because it changes the rules a stranger's listing is
judged by.

## What runs, in order

1. **The allowlist**, out of a root-signed `trust.json`. First, not last: if
   there is no root, the bot has no basis for any conclusion and should not
   spend a stranger's bandwidth pretending otherwise.
2. **Ownership.** `.well-known/astra-plugin-owner` on the default branch,
   naming the submitter, is the proof — it is what the listing form asks for
   before a run ever happens, and for a third-party repository it is the only
   arm that can answer. `GET /repos/{o}/{r}/collaborators/{u}/permission` is
   still tried first, as an opportunistic shortcut: GitHub answers it only for
   a caller that can already see the repository, so it returns `403` (no
   answer, never a denial) for everything this registry does not itself own.
   When it *does* answer, that answer is final in both directions and the file
   does not override it. The account that published the release is third and
   covers the already-listed paths,
   where `resolveSubmitter` makes it the submitter. `docs/BOT-CHECKS.md` says
   what each one establishes and why a nonce challenge file is not the
   primary.
3. **The release**, its `.astraplugin` assets, and that every URL sits under
   `github.com/<repo>/releases/download/<tag>/` — the same check a user's daemon
   repeats locally against its TOFU pin.
4. **`HEAD`, then download under a cap, then hash.** The cap is enforced from
   the `HEAD`: a bot that has to download something to discover it is too big
   has no size cap.
5. **The attestation** — `gh attestation verify --repo --signer-workflow`, and
   then the resolved reusable-workflow commit against the allowlist from step 1.
   The second half is what makes the first mean anything: verifying an
   attestation without pinning which workflow produced it proves only that
   GitHub built something.
6. **The archive**, in memory. Nothing is ever extracted. The single moment a
   bundle touches a filesystem is a whole-file write into a `mkdtemp` directory,
   because `gh attestation verify` takes a path.
7. **`plugin.toml`**, through the Rust probe.
8. **Names, metadata, licence, versions, identity**, and the host-RPC scan.
9. **The listing is written** — and then run past `tools/validate.mjs`, the same
   code CI applies to every hand-written listing. The bot's output is held to the
   rules its input would have been.

## Before any of that: who is answered, and who may decide

`bot/triage.mjs` runs first, on every issue and comment event. It downloads
nothing and decides nothing about a release. It answers one question — *does
this event ask for an ingest, and of what* — and it now has two more answers
than it used to, because both of its old silences were bugs somebody hit.

**`mode: reply` — the submission that was answered with nothing.** Two listing
requests arrived carrying the rendered form and **zero labels**: there was no
`.github/ISSUE_TEMPLATE/config.yml`, blank issues were on, and they bypassed the
template that applies the label. The bot only acts on a labelled issue, so it
answered `none`, `targets=[]`, every later job was skipped, and the run went
green. It had succeeded at deciding to do nothing, and neither author was told.

`bot/lib/intake.mjs` holds the recognisers and the replies. Two independent
signals identify a listing request — the `[listing]` title the template sets,
and the form's own field headings in the body — either of which is enough,
because the two ways a submission loses its label leave different remains.

**It replies rather than auto-labelling, and that is the load-bearing choice.**
In this repository the `listing` label is an *authority token*, not a category:
a labelled issue may drive an ingest of a repository this registry has never
seen, while an unlabelled `/release` may only ask for a re-check of a listing
that already exists. A bot that minted that label from the shape of a body would
hand that exemption to anybody who can copy a form — and the check that would
eventually refuse it (ownership) runs *after* the archive is fetched, so the
refusal is not the point; the spending is. The label stays a person's decision,
one click, which the reply names. What the bot must never do is go quiet.

**`mode: approve` / `mode: reject` — the hold that had no next move.**
`bot/lib/policy.mjs` returns `outcome: "review"` for three events, the ingest
exits 3, and until now nothing implemented what the maintainer does about it.

- `bot/lib/maintainer.mjs` proves the permission against
  `GET /repos/{owner}/{repo}/collaborators/{login}/permission` on **this**
  repository, requiring `admin` or `maintain` — the same bar
  `bot/lib/ownership.mjs` sets for a submitter, asked about the registry instead
  of about the plugin. `collaboratorRole` is shared between the two so they
  cannot come to different conclusions about what `maintain` means. The
  comment's `author_association` is deliberately not consulted: it is not a
  permission, `COLLABORATOR` is true for a `triage` role that cannot push a
  byte, and `CONTRIBUTOR` never expires.
- Unlike `proveOwnership`, it **fails closed**. There, a missing answer falls
  through to weaker proofs, because refusing every organisation that has not
  installed an app would make third-party publishing theoretical. Here there is
  one repository, this bot's own token, and the cost of being wrong is a
  published listing rather than a refused one.
- **An approval clears the hold and nothing else.** It is a name and a moment on
  a target; `bot/decide.mjs` runs the entire ingest again before the policy sees
  it. It cannot clear a failed check, and it does not waive the publication
  delay. `bot/lib/policy.mjs` carries the argument in full.

## What it is allowed to do

Read the network, read this repository, write a report. `--out DIR` puts the
derived listing where a separate, minimal job can commit it. **The bot never has
write access to anything**, which is also why task 3.4's release ping can be an
unauthenticated payload carrying nothing but `owner/repo/tag`: an attacker who
forges one can at most cause a re-check of a listing that is already pinned to a
repository identity.

`.github/workflows/ingest.yml` enforces that split — `check` downloads a
stranger's archive with `contents: read` and no secrets; `comment` has
`issues: write` and runs no code from the submission at all, reading one markdown
file out of an artifact. Stranger-controlled text never reaches a `run:` block
through `${{ }}`.

`respond` is the same split applied to the intake reply: `triage` composes the
markdown with no write access anywhere and writes it to a file; `respond` reads
that one file out of an artifact, posts it, and closes the issue when the mode
was `reject`. The instruction to close travels as a *job output*, never inside
the text — the job that can write to an issue parses no submission, and the job
that parses a submission can write nothing.

## Signing the catalogue

`node bot/sign-index.mjs --in dist/index.json --out dist/index.json`

`registry/v1/index.json` is a `{ "signed": …, "signatures": [ … ] }` envelope.

```
sig = Ed25519(index_priv, SHA-256("astra.registry.index/1" ‖ 0x00 ‖ JCS(signed)))
```

`JCS` is RFC 8785 from `tools/lib/canonical.mjs` — the same canonicaliser
`trust.json` is signed with, and the one `astra-daemon`'s `plugins/trust.rs`
reimplements in Rust. `bot/fixtures/index/catalogue-signed.json` is signed here
and embedded byte-for-byte in a daemon unit test, so the two implementations
cannot drift apart in silence. Both suites also assert the SHA-256 of the
canonical form of RFC 8785 §3.2.3's own vector.

**Only `signed` is covered.** `$comment`, and the `key_id` on each signature, are
outside it. `key_id` is a hint for logs and key selection: the verifier tries
every trusted key against every offered signature, so a document that lies about
who signed it still verifies if a trusted key actually did, and never verifies
because it claimed the right name.

**The key never touches a command line.** `ASTRA_INDEX_SIGNING_KEY` (base64 of
the raw 32-byte seed) and `ASTRA_INDEX_SIGNING_KEY_ID` come from the `publish`
environment's secrets. A key on a command line is a key in the shell history, in
`ps` output for every other account on the runner, and in the Actions log the
first time somebody turns on command tracing. `--test-key` uses the throwaway
keys in `tools/testkeys/` and refuses to write into `registry/`.

**The generator stamps no time; the signer does.** `issued_at` and `expires_at`
are properties of the publication, not of the content. `--ttl-days` defaults to
30. What that expiry buys is bounded and the daemon is built around the bound: a
stale catalogue downgrades Browse to a banner and **records already pinned by
digest stay installable**, because a digest does not expire. The hard block lives
on `revocations.json` at seven days instead — the one document whose staleness
means "we may be about to install something already withdrawn".

## After a listing: moderation, and the nightly asset check

Two programs that run when something has already been published.

`bot/moderation.mjs` builds the transparency log from
`bot/moderation/<date>-<plugin>-<action>.json`. Four escalating actions — yank,
delist, deprecate, revoke — ordered by what each costs somebody who **already
installed** the plugin; the first two are catalogue edits that reach nobody's
machine, the last two are signed statements that do. An entry claiming a
`deprecate` or a `revoke` must name an advisory that is actually in the signed
withdrawal list, with a matching action, or the build fails: a transparency log
that can claim an unsigned revocation is a tool for scaring people off a
competitor. `bot/moderation/README.md` is the field guide; `docs/POLICY.md` §8–11
is the policy, including the triage clock declared in `bot/lib/moderation.mjs`.

`bot/asset-check.mjs` asks nightly whether every artifact the catalogue pins
still hashes to what the signed index says — with **one conditional request per
artifact**. `Content-Length` is compared against the `size` the index records
(which needs no memory of a previous run at all: the index is the memory) and
`ETag` against what the last run saw (which is the only thing that catches a
replacement of exactly the same length). A body is downloaded only when a header
disagrees, at which point the download is the investigation rather than the cost.

```bash
node bot/asset-check.mjs --index registry/v1/index.json --cache "$RUNNER_TEMP/asset-cache.json"
node bot/asset-check.mjs --index registry/v1/index.json --full   # what the naive job would cost
```

The ETag memory is **not committed**: it has no security value — the worst a lost
or poisoned cache does is cost one extra `HEAD` — so it lives in the Actions
cache rather than putting a machine-written file into this repository's history
every night. A mismatch opens an issue and touches nothing; Astra already refuses
bytes that do not match the pinned digest, so a swapped asset is uninstallable
rather than dangerous, and which of the four actions follows is a person's call.

## Tests

```bash
node bot/tests/ingest.test.mjs                                  # the bot
node bot/tests/policy.test.mjs                                  # the publication policy
node bot/tests/asset-check.test.mjs                             # the nightly check, measured
cargo test --manifest-path bot/manifest-probe/Cargo.toml        # the manifest rules
node bot/moderation.mjs --check                                 # the moderation sources
node tools/selftest.mjs                                         # the listing rules
node site/selftest.mjs                                          # the website
node bot/gen-checks-doc.mjs --check                             # the docs
```

`bot/tests/asset-check.test.mjs` serves two artifacts totalling 15.9 MB from a
`node:http` server on loopback and measures the bytes the check actually moves,
because "kilobytes when nothing changed" is a number and a number should be
measured rather than asserted. It also proves both detection paths — a length
change and a same-length swap — and that an entry with no digest is skipped
rather than fetched.

`bot/tests/ingest.test.mjs` runs the **whole pipeline** over every one of the 27
shared bundle vectors in `tests/vectors/` — vendored from
`AstraPlugins/testdata/bundles`, and consumed by the CLI's suite and the daemon's
too — and asserts the verdict recorded in that file's `expect.registry` column.
Three of those verdicts are recorded *divergences* (`duplicate-entry-case`,
`mode-mismatch`, `permissions-hash-mismatch`): the registry accepts them today.
This bot now reports all three, as **warnings**, because turning them into
rejections would make the shared corpus disagree with itself — closing them is a
change to `AstraPlugins/testdata/bundles/vectors.json` and to all three suites at
once, which is exactly the coordination that file exists to force.

Everything else is one test per failure class, each asserting the fixed code, and
the run ends by printing which declared codes no test provoked.

`bot/tests/policy.test.mjs` carries three sections about the intake and the
maintainer's commands. Two of them are regression tests for things that
happened: an unlabelled listing request producing no reply, and `outcome:
"review"` having no next move. The first runs `mihailinl/astra-registry#14`'s
real body — embedded verbatim rather than fetched, because a suite that needs
GitHub to be up goes quiet on the day the network is the problem — through
triage with an empty label set, and asserts it no longer decides `none`. The
third proves the four properties an approval has to have: it publishes what
*this* run hashed, it cannot clear a failed check, it does not waive the
publication delay, and it does not survive a swap of the assets it was recorded
against.
