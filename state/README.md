# `state/` — what the registry remembers between runs

There is no server behind this registry. Everything the bot has to remember from
one workflow run to the next lives here, in git, where it is auditable and where
a maintainer can change it with an editor.

| Path | What it is | Losing it costs |
|---|---|---|
| `queue/<id>@<version>.json` | A release waiting out the publication delay (PRODUCTION_PLAN §3.5, `docs/POLICY.md` §4). | The release never publishes itself. Delete a file to **cancel** a publication; edit `publish_after` to bring one forward. |
| `releases-seen.json` | The release backstop's memory: one `etag` and last-seen tag per listed repository (task 3.4, layer 2). | Nothing but bandwidth — one full poll of every listing, once. It is a cache. |

**Nothing in here is trusted.** A queue entry records what a release was queued
for, and when the delay ends the *entire* ingest runs again from scratch against
the release as it is at that moment — the assets are re-downloaded, the
attestation re-verified, ownership re-proved. The entry's recorded digests exist
so that a swapped asset **restarts** the clock rather than inheriting the time
already served.

Both files are written by `.github/workflows/ingest.yml`'s `publish` job, which
runs no submitter code: it copies JSON out of an artifact, checks every path
against the shape it is allowed to have, revalidates the tree with
`tools/validate.mjs`, and commits.
