# `state/` — what the registry remembers between runs

There is no server behind this registry. Everything the bot has to remember from
one workflow run to the next lives here, in git, where it is auditable and where
a maintainer can change it with an editor.

| Path | What it is | Losing it costs |
|---|---|---|
| `queue/<id>@<version>.json` | A release waiting out the publication delay (PRODUCTION_PLAN §3.5, `docs/POLICY.md` §4). | The release never publishes itself. Delete a file to **cancel** a publication; edit `publish_after` to bring one forward. |
| `releases-seen.json` | The release backstop's memory: one `etag` and last-seen tag per listed repository (task 3.4, layer 2). | Nothing but bandwidth — one full poll of every listing, once. It is a cache. |
| `keepalive.json` | ROLL-62's keepalive (RC-R1-9(b)): the month of the last commit made so that this repository is never 60 days quiet. | Every `schedule:` in this repository, 60 days later, disabled by GitHub with nothing going red. `tools/coverage/keepalive-age.mjs` is red 35 days after the last change to it. |

**Nothing in here is trusted.** A queue entry records what a release was queued
for, and when the delay ends the *entire* ingest runs again from scratch against
the release as it is at that moment — the assets are re-downloaded, the
attestation re-verified, ownership re-proved. The entry's recorded digests exist
so that a swapped asset **restarts** the clock rather than inheriting the time
already served.

The queue and `releases-seen.json` are written by
`.github/workflows/ingest.yml`'s `publish` job, which runs no submitter code: it
copies JSON out of an artifact, checks every path against the shape it is
allowed to have, revalidates the tree with `tools/validate.mjs`, and commits.

## `keepalive.json`, and the one thing it must never become

`.github/workflows/keepalive.yml` rewrites it on the first of its seven runs
each month that finds a month other than the current one recorded, and commits
that file **alone** — a keepalive that carried a second path would start a
signing run and a served-set comparison for a commit whose only purpose is to be
a commit. The workflow asserts the staged set rather than trusting itself.

An operator or an agent may make the month's commit by hand instead; ROLL-62
counts it either way, and the workflow then finds the month recorded and does
nothing. The shape, which is the same shape the workflow writes:

- `at` is `date -Iseconds` **on the machine making the commit** — local time
  with its offset, deliberately not `date -u`. `keepalive-age` compares the
  file's month against `git log --format=%aI`, which git renders in the
  committer's own offset, so a commit made at 17:10 on the last day of a month
  in UTC-7 is in the next month by `date -u` and in this one by git;
- `month` is the first seven characters of `at`;
- `by` is `hand` for an account push and `workflow` for the workflow's
  `GITHUB_TOKEN` one, because whether the second counts as repository activity
  for GitHub's 60-day rule is still unmeasured (RC-R1-9(b), OPEN-OPS-18) and
  this field is what will answer it from the file's own history;
- `run` is the Actions run URL for a `workflow` commit and `null` for a hand
  one.

Then `node tools/coverage/keepalive-age.mjs` before the push: green, not
`pending` and not red. It is the only reader this file has.
