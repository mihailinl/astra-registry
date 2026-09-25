# `state/` — what the registry remembers between runs

There is no server behind this registry. Everything the bot has to remember from
one workflow run to the next lives here, in git, where it is auditable and where
a maintainer can change it with an editor.

| Path | What it is | Losing it costs |
|---|---|---|
| `queue/<id>@<version>.json` | A release waiting out the publication delay (PRODUCTION_PLAN §3.5, `docs/POLICY.md` §4). | The release never publishes itself. Delete a file to **cancel** a publication; edit `publish_after` to bring one forward. |
| `releases-seen.json` | The release backstop's memory: one `etag` and last-seen tag per listed repository (task 3.4, layer 2). | Bandwidth — one full poll of every listing, once — and one thing that is not a cache: a tag held as seen because its author withdrew its listing request is offered again. Today that is `voltur792/voice-text-input`'s `v1.0.0` (issue #69, superseded by `v1.0.1`). The backstop would ingest it in the first week the listing is quiet, and the poll would register it from B-T5.1 (BOT-74, MIG-23). `bot/tests/poll.test.mjs` lists each such tag and fails when one is no longer seen here. |
| `coverage-live-run.json` | M-T1.5's live run, once: the fixture repository, the commit its `Operator` workflow pushed with its GITHUB_TOKEN, the `Moderation coverage` run there that found it (never a `push` run, which that push does not start) and when, the `[DRILL]` alarm's delivery time, and the `Moderation-Exempt:` commit and run that cleared it. Written by hand after the walk; `bot/tests/moderation-coverage.test.mjs` refuses a record that does not say all of that. | The coverage canary prints the `live-once` owner act again on every run, as owed. It gates nothing. |
| `keepalive.json` | ROLL-62's keepalive (RC-R1-9(b)): the month of the last commit made so that this repository is never 60 days quiet. | Every `schedule:` in this repository, 60 days later, disabled by GitHub with nothing going red. `tools/coverage/keepalive-age.mjs` is red 35 days after the last change to it. |
| `moderation-settled.json` | The moderation results a commit in history decided — a hold ended by hand, or by a release or cancel commit — that the plugins service answered `accepted` or `duplicate`: BOT-82's key, the answer, its time and the run (ops entry 100). Written by `plugins-moderation.yml`'s `commit` job. | Nothing but noise: every such result is posted once more on each live run, and answered `duplicate`, until it is recorded again. Absent or invalid, it skips nothing. |
| `publishers-without-listing.json` | The publisher records that reach no listing, each with the reason none is expected (gap 6). Written by hand in a reviewed commit, and by `publisher-recheck.yml`, which drops a withdrawn record's declaration in the same commit as the withdrawal. | `tools/selftest/publishers.mjs` refuses every undeclared record that reaches no listing — today `publishers/KnlCE.json` — so `main`, and every bot commit the suite gates, is red until it is back. |

**Nothing in here is trusted**, with two exceptions, below, each trusted no
further than the records it names. A queue entry records what a release was
queued for, and when the delay ends the *entire* ingest runs again from scratch
against the release as it is at that moment — the assets are re-downloaded,
the attestation re-verified, ownership re-proved. The entry's recorded digests
exist so that a swapped asset **restarts** the clock rather than inheriting the
time already served.

The queue and `releases-seen.json` are written by
`.github/workflows/ingest.yml`'s `publish` job, which runs no submitter code: it
copies JSON out of an artifact, checks every path against the shape it is
allowed to have, revalidates the tree with `tools/validate.mjs`, and commits.

## `publishers-without-listing.json`, and why it is here

`tools/selftest/publishers.mjs` fails on a publisher record that reaches no
listing unless this file declares it, so unlike the rest of this directory it
is read as an excuse. The excuse reaches no further than the records it names,
and those are under `publishers/`, as editable as this file is: a writer who
can add a declaration can as easily delete the record it excuses or add the
listing it waits for.

It lived under `tools/selftest/` until 2026-09-22, inside contract TRUST-31's
hashed set — and the daily re-check, which runs unattended, drops a withdrawn
record's declaration in the same commit as the withdrawal, so after R3 that
commit would have put the bot into shadow and raised an alarm for a withdrawal
nobody did wrong. It is a record a run writes, not a rule a run judges by, and
this directory is where the records a run writes as it works live. It is not
under `publishers/` because every `*.json` there is loaded as a publisher
record. Its path is `bot/recheck-publishers.mjs`'s `NO_LISTING_FILE`, which
the suite imports, and only the workflow's commit step spells it again; its
shape is `tools/selftest/publishers.mjs`'s to judge, and that module is red if
the workflow ever commits a path inside the set.

## `moderation-settled.json`, and what a row buys

The second exception. A row stops the moderation run posting one result — one
`(service_decision_id, outcome, commit)`, BOT-82's key — that a commit in
history decided, because the plugins service has already answered it
`accepted` or `duplicate`. Only the service's answer writes a row, never the
post: the `list` job posts and hands on the settling answers, and the `commit`
job, which holds no bot token, re-checks each one against its own walk and
records it (`bot/lib/settled.mjs`). A row is trusted no further than that one
post. A forged row withholds a result the service never received: it changes
nothing in git, but the decision then stays `held` at the service, and nothing
in this repository notices. That is why each row carries the answer's time and
the run that saw it, and why a hand edit here is reviewed like any other.
Everything else degrades to posting again: a missing file, a file that is not
this schema, a row that is malformed.

It is outside contract TRUST-31's hashed set for the reason the rest of this
directory is: a record the run writes as it works. The rule that reads it is
`bot/lib/settled.mjs`, inside the set.

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
