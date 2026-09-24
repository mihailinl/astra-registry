# Telling the authors of existing listings

What the authors of listings published before the move to the plugins service
are told, how, and what the registry records when they have been (contract
MIG-13, MIG-14; registry plan M-T5.3). The texts are public and name no
person: the only things a round fills in are the binding deadline, the cutover
date, and the account's own public plugin ids.

## Who is told

Every account holding a listed plugin that has no identity record
(`plugins/<id>/identity.json`), except the accounts an `astra_team` publisher
record speaks for. `node tools/migration-notice.mjs recipients` lists them from
the tree: one entry per account, naming each of its listings and the
repository of its earliest one.

## How a round reaches an account

Twice, and both are required (MIG-13):

1. **A banner** on each listing's page, `https://astra.minice.ai/plugins/<id>`.
   The plugins service renders it from the round and the announced date in
   the markers below, and the deadline from `policy/binding-deadline.json`.
2. **One outbound issue** in the account's own repository — the repository of
   its earliest listing — opened at the account's first round and naming every
   one of its listings. Every later round, and every re-send, is a comment on
   that issue. The issue only notifies. It takes nothing in: nothing written on
   it reaches the registry, and it is not a submission channel (OD-2).

**Before each round goes out, the issue path is measured.** For each account's
target repository, `node tools/migration-notice.mjs issue-paths` reads
`has_issues`, `archived` and whether it is public. An account whose repository
takes no issues, is archived, is not public, or could not be read has **no
issue path**, and the round does not go out to it: it becomes an item for the
owner, naming the account and its listings, and he decides — direct contact, a
commit comment, or accepting the freeze. A banner alone is not a notification,
because an author with no Minice account yet has no reason to load the page.

## The markers, and which one a reader believes

Each round is recorded, once, as `log/migration-notice-<n>.json`, committed
with the round's sends and never before them. Its members are exactly
`schema`, `round`, `sent_at` (the moment the round went out) and, from round 2,
`cutover_planned_at` (the announced cutover date). No marker counts or names
anybody. Each send is also recorded per account, dated, with the issue and
comment URLs, in the operators' own notes.

**The authoritative marker is the one with the highest `round` present on
`main`** — not the most recently committed file, and not the one with the
latest `sent_at`. A re-send can re-commit a marker without changing which round
it is, so the file's history says nothing about which marker is current. The
listing banner, the deadline watch and the cutover preflight all read it this
way.

**Round 1's marker carries no date**, and is committed once. A round 1 sent
later, at a new account's first listing, writes no second marker. Where the
cutover date is already fixed, round 1's text states it anyway; the banner
shows none until round 2's marker.

**A re-send** (the deadline or the cutover date moved, MIG-29) follows from the
dates, and nobody chooses the branch:

- **The cutover date moved later.** Every dated marker is re-committed with the
  new date and **its own `sent_at`**. No `sent_at` moves, so the deadline
  watch's clocks do not start over.
- **The cutover date moved earlier.** That is not a re-send at all: it is a
  **new round 2**, with its own `sent_at`, sent before the earlier date comes.
  Every later round's marker already on `main` is re-committed with the new
  date and its own `sent_at`, so that no marker announces the abandoned date.
- **Nothing new is announced.** No marker is written.

`node tools/migration-notice.mjs resend --cutover <time> --at <time>` prints
which branch the dates give and the files it writes; `round` does the same for
a round.

A commit that re-commits a marker already on `main` ends with the
`Moderation-Exempt: migration-notice: …` trailer the command prints. The
moderation coverage canary treats every change under `log/` as an edit of an
append-only record (MOD-34) and is red without it; the trailer is that rule's
own clearing path, and it leaves the re-commit visible in history as a
declared act. A marker's first commit is an addition and needs none.

## When

- **Round 1** — when third-party bindings open (R4b), or at a new account's
  first listing after that.
- **Round 2** — with the cutover date, before cutover. Since contract 2.0.0 no
  interval is required between the two: the owner's own notice to the
  publishers, given in Telegram on about 2026-09-09, that the old path will be
  removed, is the advance notice the 30 days used to stand for.
- **Round 3** — at least 14 days before the deadline.

`node tools/migration-notice.mjs render --round <n>` fills a round's text from
the tree. It refuses while no deadline is committed, because every notice
states it.

## The texts

Round 1 opens the issue. Rounds 2 and 3 are comments on it. Each says
everything MIG-14 requires, so an author who reads only one of them has
everything.

<!-- notice:round-1 -->
**Your Astra plugin listing needs to be bound to a Minice account**

This is a notice from the Astra plugin registry about these listings:

{{listings}}

This issue only notifies you. Nothing written on it reaches the registry, and it is not a way to ask for anything.

**What is changing.** Publication is moving to the Astra plugins service. Your listing is `grandfathered` today: it stays listed and keeps taking new versions until the later of the binding deadline and the cutover.

- **Binding deadline: {{deadline_date}}** (`{{deadline}}`), the value in `policy/binding-deadline.json` in the registry.
- **Cutover to the plugins service:** {{cutover}}.

**What binding needs.**

1. A Minice account holding `astraUser`, which is an account that owns Astra. After a purchase the role can take up to 12 hours to reach the account.
2. A binding line in your repository: `astra-binding: <your token>` as the first line of `.well-known/astra-plugin-owner` at its root, with a token you mint in the panel. `astra-plugin init-ci --binding <your token>` writes the line.
3. A new tag, released as usual.
4. One `R_FIRST_BINDING` review: the first bound release of the listing waits for a moderator, once.

**Your token expires.** A minted token expires 30 days after its mint unless a live submission names it or its line is on the repository's default branch when the rule is applied. So an author who tags much later without the line on the default branch mints again, and one whose line is still on that branch when the rule is applied does not.

**What `frozen` means.** A listing not bound by the later of the deadline and the cutover becomes `frozen`: it stays listed and installed copies keep working, but it takes no new version until it is bound. A bound release unfreezes it, with no penalty.

**From the cutover**, a delayed or reviewed release of a listing that is not bound yet waits until the listing is bound.

**The panel is the only place to act:** https://astra.minice.ai/plugins. Binding, releases and questions all go through it, and nothing written on GitHub changes anything.
<!-- /notice:round-1 -->

<!-- notice:round-2 -->
**Second notice: the cutover date is fixed**

This is the second notice from the Astra plugin registry about these listings:

{{listings}}

- **Cutover to the plugins service: {{cutover}}.**
- **Binding deadline: {{deadline_date}}** (`{{deadline}}`), the value in `policy/binding-deadline.json` in the registry.

Your listing is `grandfathered` until the later of the two.

**What binding needs.**

1. A Minice account holding `astraUser`, which is an account that owns Astra. After a purchase the role can take up to 12 hours to reach the account.
2. A binding line in your repository: `astra-binding: <your token>` as the first line of `.well-known/astra-plugin-owner` at its root, with a token you mint in the panel. `astra-plugin init-ci --binding <your token>` writes the line.
3. A new tag, released as usual.
4. One `R_FIRST_BINDING` review: the first bound release of the listing waits for a moderator, once.

**Your token expires.** A minted token expires 30 days after its mint unless a live submission names it or its line is on the repository's default branch when the rule is applied. So an author who tags much later without the line on the default branch mints again, and one whose line is still on that branch when the rule is applied does not.

**What `frozen` means.** A listing not bound by the later of the deadline and the cutover becomes `frozen`: it stays listed and installed copies keep working, but it takes no new version until it is bound. A bound release unfreezes it, with no penalty.

**From the cutover**, a delayed or reviewed release of a listing that is not bound yet waits until the listing is bound.

**The panel is the only place to act:** https://astra.minice.ai/plugins. Binding, releases and questions all go through it, and nothing written on GitHub changes anything.
<!-- /notice:round-2 -->

<!-- notice:round-3 -->
**Last notice before the binding deadline**

This is the last notice from the Astra plugin registry, at least 14 days before the binding deadline, about these listings:

{{listings}}

- **Binding deadline: {{deadline_date}}** (`{{deadline}}`), the value in `policy/binding-deadline.json` in the registry.
- **Cutover to the plugins service:** {{cutover}}.

**What binding needs.**

1. A Minice account holding `astraUser`, which is an account that owns Astra. After a purchase the role can take up to 12 hours to reach the account.
2. A binding line in your repository: `astra-binding: <your token>` as the first line of `.well-known/astra-plugin-owner` at its root, with a token you mint in the panel. `astra-plugin init-ci --binding <your token>` writes the line.
3. A new tag, released as usual.
4. One `R_FIRST_BINDING` review: the first bound release of the listing waits for a moderator, once.

**Your token expires.** A minted token expires 30 days after its mint unless a live submission names it or its line is on the repository's default branch when the rule is applied. So an author who tags much later without the line on the default branch mints again, and one whose line is still on that branch when the rule is applied does not.

**What `frozen` means.** A listing not bound by the later of the deadline and the cutover becomes `frozen`: it stays listed and installed copies keep working, but it takes no new version until it is bound. A bound release unfreezes it, with no penalty.

**From the cutover**, a delayed or reviewed release of a listing that is not bound yet waits until the listing is bound.

**The panel is the only place to act:** https://astra.minice.ai/plugins. Binding, releases and questions all go through it, and nothing written on GitHub changes anything.
<!-- /notice:round-3 -->
