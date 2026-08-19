# Publication policy

What happens to a release **after** every check has passed: whether it goes live
by itself, waits, or waits for a person — and how long each of those takes.

`POLICY.md` at the root of this repository says what may be listed at all.
`docs/BOT-CHECKS.md` says what the bot checks and what each failure code means.
This document says what the registry *does* with a submission that got nothing
wrong, which is a different question and the one every author actually has.

It is implemented in `bot/lib/policy.mjs`. Every number below is declared there
and asserted against this file by `bot/tests/policy.test.mjs`, so a published
promise cannot drift from the code that keeps it. A published SLA that has
quietly stopped being true is worse than no SLA, because it teaches people the
document is decoration.

---

## 0. You always get an answer

Open a listing request and the bot comments on it. Every time.

That is worth stating because it was not true. Two submissions — `#13` and
`#14` — arrived without the `listing` label, because blank issues were on and
they bypassed the form that applies it. The bot only acts on a labelled issue,
so it decided there was nothing to do, every later job was skipped, and the
Actions run went green. Neither author was told anything at all. Not refused;
nothing.

Three things changed, and together they close it:

1. **Blank issues are off.** Every way into this repository is a form now, and
   the listing form applies the label itself.
2. **An unlabelled listing request gets a comment** naming the label, the
   one-click fix, and why the bot will not apply the label for you.
3. **A held submission has a next move.** `/approve` and `/reject` are §3.1.

If you ever get silence from this registry, that is a bug in it. Say so on the
issue.

### The one thing to do before you open the request

**Commit `.well-known/astra-plugin-owner` to your default branch, containing
your GitHub login on a line of its own.**

```
mkdir -p .well-known
echo YOUR-GITHUB-LOGIN > .well-known/astra-plugin-owner
```

One commit, no CI. The listing form asks for it as a required confirmation,
because the alternative — finding out from a refusal — is what used to happen to
every honest first submission, and it happened for structural reasons rather
than by accident. `astra-registry#13` and `#14` are the record: every
cryptographic check passed, and the run refused them on ownership alone.

The registry has to know that the account asking for the listing controls the
repository, or a stranger could list your plugin and become the account through
which its updates reach Astra users. The file is how you say so, and it is read
**live from the default branch on every run** — so removing a line stops that
login opening a new listing request or passing a `/recheck`, and a person
removed from an organisation stops being able to submit as soon as the file is
updated. What it does **not** do is reach a plugin that is already listed; that
is the second bullet below.

Be clear about what it proves: **that somebody who can write to that branch
vouches for that login.** It is a proof of write access, not of legal ownership,
not of authorship, and not of identity. That is the right size for what this
check defends against, and `docs/BOT-CHECKS.md` states its residual risk rather
than hiding it.

**Nothing spares you the commit on a first listing.** Two things are worth
knowing about the checks either side of it, and neither is a shortcut you can
take:

- The bot does ask GitHub who has `admin` or `maintain`, first and for free.
  GitHub answers that endpoint only for a caller that can already see the
  repository, and the bot's token belongs to this registry — so for a repository
  this registry does not itself own the answer is `403`, meaning "I will not
  tell you" rather than "no". **That silence is never held against you**, it is
  never printed as a failed check, and it is never an answer either. There is
  nothing you can install that changes this.
- Once a plugin is listed, later releases prove ownership against the account
  that published the release rather than against whoever pinged (§5). That is a
  different question with a different answer: it is why routine releases need no
  file update and no form, and also why editing the file does not revoke
  anybody's ability to ship a release of a plugin that is already listed.

## 1. The four outcomes

| Outcome | What it means | Who is involved |
|---|---|---|
| **Published** | The listing is committed and reaches the catalogue on the next index build. | Nobody. |
| **Delayed** | Everything passed. It publishes itself at a stated time. | Nobody, unless the author objects. |
| **Held** | A decision this registry is not entitled to make automatically. | A maintainer, within **48 h**. |
| **Refused** | A check failed. The policy never got a say. | The author, who fixes it and comments `/recheck`. |

The bot posts the outcome on the listing issue with the reason and, when there
is one, the exact time it will publish.

## 2. When a release publishes itself

All five of these, and it goes live with no human:

- the repository it comes from is the one already listed for that plugin;
- every check in `docs/BOT-CHECKS.md` is green;
- the version is strictly greater than the newest listed version;
- it asks for no **high-risk** permission it did not already have;
- it asks for no permission or capability at all that the previous release did
  not have.

Drop the last condition and it still publishes itself — after a delay.

## 3. The three events that need a person

Exactly three, and this list does not grow without a change to this document:

| Event | Code | Why a person |
|---|---|---|
| First listing of a plugin | `R_FIRST_LISTING` | Once, ever. Nothing is pinned yet, so nothing later can be checked against it. Every later release from the same repository is zero-touch. |
| A newly requested high-risk permission | `R_NEW_HIGH_RISK` | The user will be asked to consent to it; somebody should have read what it is for before they are. |
| The repository or identity changed | `R_IDENTITY_CHANGED` | Every installed copy carries a pin to the old repository. A repository change is an author change until somebody says otherwise. |

A check may separately hand a decision to a person — a name one edit away from a
listed plugin, a display name that collides with one. That arrives as
`R_CHECK_HELD`, is not one of the three, and carries the same SLA.

**The high-risk set is four names:** `client`, `dom_access`,
`send_chat_message`, `set_theme_contribution`. Each of them reaches outside the
plugin's own surface — into the chat session, the theme, or the Astra window —
and each is refused outright to an unverified local import (PRODUCTION_PLAN
§5.5). They are matched in `[capabilities]` and in `[permissions]` alike: the
section a manifest declares them in is not the point, the authority requested is.

`push_to_ui` is high-risk on the *consent sheet* (§5.6) and is deliberately not
in the set above. A consent checkbox costs a user one read; blocking review costs
an author days. `push_to_ui` draws inside a panel the plugin already owns, so a
first request for it is a widening — see below — not a review.

**What a declaration is worth now that Phase 4 has landed.** A declaration is
enforced at run time. `require_permission` runs at the top of every host RPC
that needs one: `HOST_RPC_PERMISSIONS` in
`astra-daemon/src/plugins/host_service.rs` is the table, and it names all ten
RPCs — six gated (`SubscribeEvents`, `SendChatMessage`, `FireTrigger`,
`SetVariable`, `SetThemeContribution`, `PushToUi`) and four deliberately not
(`Register`, `GetPluginSelfConfig`, `PluginLog`, `GetDaemonInfo`, none of which
acts on anything outside the plugin). A canary reads that table rather than the
methods, so a new RPC with no gate is a failing test instead of a silent
omission. `dom_access` and `client` gate no RPC because they are not calls: they
are *surface*, refused where the surface is handed out — the tier ceiling on
`PluginStatusMsg` and on the UI-contribution and theme responses.

So an undeclared call is now refused on the user's machine, with
`permission_denied` and a message naming the permission and where the plugin's
granted set came from. What that changes here: the string search over a bundle's
source is no longer the only lever, and declaring honestly is no longer more
expensive than not declaring — an undeclared authority simply does not work.

**What it still does not buy.** A permission decides what the daemon will do
*for* a plugin. It decides nothing about what the plugin's own process may do to
the machine, because there is no sandbox: a plugin is a native process with the
user's full privileges, and Phase 7 is where that changes. Read the table above
as "what the daemon will permit", and root `POLICY.md` §0 for the part no
permission model reaches.

### 3.1 What happens to a held submission

A maintainer answers on the issue with one of two commands. You will see it.

**`/approve <owner/repo>@<tag> <fingerprint>`** — the hold is cleared and the
release goes back through the pipeline. The bot comments again with a full table
of checks and a line saying who cleared the hold, when, and which submission they
cleared it for.

The bot prints that whole line, ready to copy, in the **Held for a maintainer**
comment. It is not decoration and it is not optional:

> ```
> /approve you/dice-roller@v0.2.0 4f1c9a02be773d15
> ```

The fingerprint is a short hash of the repository, the tag, the plugin id, the
version and the digest of every release asset **that run downloaded and hashed**.
When the approval is processed the registry works the fingerprint out again from
the release as it is at that moment, and honours the approval only if the two
match. If they do not — the tag moved, an asset was replaced, the issue's fields
were edited — the answer is `P_APPROVAL_STALE`: nothing publishes, the hold
stands, and the comment names both the submission that was approved and the one
that is there now.

**Why the command carries arguments at all.** A submission is described by the
issue body, and the issue body belongs to its author, who can edit it at any
time — including between the bot posting the hold and the maintainer answering
it. A bare `/approve` meant *approve whatever this issue says right now*, so two
edited fields were enough to make a maintainer's yes land on a release nobody had
looked at. Naming the submission is how the yes and the thing read stay the same
thing. It is the same rule as "the digest that reaches the catalogue is the
digest this run hashed", applied one layer up, to the form that names the bytes
rather than to the bytes.

**`/reject <reason>`** — the reason is posted on the issue and the issue is
closed. A rejection is about *this* submission and is not permanent: fix what
the reason names and open a fresh request. Nothing counts against a later one.
It takes no fingerprint: it publishes nothing, so there is nothing for one to
protect.

Four things an approval is deliberately **not**:

- **It is not a skip.** Every check runs again, from scratch, against the
  release as it is at that moment. Nothing verified in the earlier run is
  reused. A tag can be moved and a release asset can be replaced between the
  hold and the yes, so the digest that reaches the catalogue is the digest of
  the bytes this run downloaded and hashed.
- **It cannot clear a failed check.** A refusal outranks it. A bad signature, an
  unproved ownership or a licence this registry does not allow are facts about
  the bytes, and the answer to one is a new release.
- **It does not waive the publication delay.** If your release also widens its
  permissions, it still waits out §4's window and then publishes itself. The
  hold and the delay answer different questions: *may this be listed at all*,
  and *has the author had a chance to notice*.
- **It is not a review of your code.** §7.

Who may run them: only an account GitHub reports as `admin` or `maintain` on
**this** repository. It is asked of the GitHub API at the moment the command is
typed, not read off the comment. If you run one and are not a maintainer, the
bot says so and nothing changes — the command is not secret and trying it is not
a fault.

Every approval leaves three records that cannot disagree: `P_APPROVED` in the
comment on your issue, `approved_by` / `approved_at` / `fingerprint` in the run's
`decision.json`, and the commit the publication makes. An approval that was
*refused* is recorded too — `approval_refused` in the same file, and
`P_APPROVAL_STALE` in the same comment — because "a maintainer typed the command
and the registry did not honour it" is a thing the thread has to be able to say.

### The SLA, and what happens when it slips

**48 h** for all four review codes, measured from the moment the bot posts the
comment. There is one maintainer, and that number is a commitment about *those
three events only* — which is the reason the list is three items long and not
thirty.

When the queue starts running past it, the answer is **to make fewer things need
review — not to review harder.** Concretely: if listings sit past 96 h, the
maintainer must either publish them or move the triggering event out of the
blocking set in `bot/lib/policy.mjs`, in a reviewed commit that also edits this
paragraph. Letting the queue rot is not an available option, and the reason is
not politeness: an author who cannot ship routes around the registry, and a
release that auto-published after 24 h is safer for everybody than one that
shipped through a side channel, because at least the registry saw it.

The cron job prints the queue's age on every run (`node bot/watch.mjs --sla`) so
a breach is loud rather than something a maintainer has to go and look for.

## 4. The publication delay

Some releases publish themselves, but not immediately.

| Situation | Code | Delay |
|---|---|---|
| The plugin holds **any** high-risk permission, whether or not this release changed anything | `P_DELAY_HIGH_RISK` | 24 h |
| The release asks for a permission or capability the previous one did not, inside the non-high-risk set | `P_DELAY_WIDENED` | 24 h |
| Either of the above, from an author with **5 clean** releases in this registry | `P_TRUSTED_AUTHOR` | 6 h |

A maintainer of this registry can waive part of the window by editing
`publish_after` in the queue entry, which reports `P_DELAY_BROUGHT_FORWARD`. It
moves the date **earlier only** — the delay is a maximum that may be waived, not
a dial — and it takes a commit here, so who shortened it and when is in the
history. Every check still runs again from scratch first. This grants nobody new
authority: anyone able to edit that file could publish a listing by hand, and
that path skips the checks entirely.

While a release waits, `P_DELAY_WAITING` states the exact publication time; when
the clock runs out, the **entire ingest runs again from scratch** against the
bytes as they are at that moment, and `P_DELAY_ELAPSED` says so. Nothing is
resumed and nothing queued is trusted.

**You are told, either way.** The bot comments on your listing issue. If the
release reached the registry by a ping or by the backstop and there is no issue
behind it, the bot opens one — titled `[notice]`, saying what will happen and
when. A routine publication gets no issue (the commit and the index serial are
the record, and an issue per patch release teaches everybody to ignore the ones
that matter), but every release that waits gets one, and every release of a
plugin holding a high-risk permission waits.

**Why a delay at all, and what it honestly buys.** PRODUCTION_PLAN §5.5 is blunt
about the one threat this whole chain cannot touch: *an author's GitHub account
compromised — nothing cryptographic; provenance will be perfect and will attest a
malicious build.* The signature chain is exactly as strong as the author's GitHub
account. The delay plus the notification is the only defence there is, and it
buys one thing: a window in which the author, who did not publish that release,
can see that it happened and say so. It buys nothing at all from an attacker
nobody is watching, and this registry does not claim otherwise.

That is also why the high-risk delay fires on *every* release of a plugin holding
one of those permissions rather than only on changes. §5.5's realistic takeover
case is a malicious version shipping with **identical** permissions, and a delay
that only fired on a change would never fire on the case it exists for.

**The clock is pinned to the bytes.** The queue entry records the sha256 of every
artifact it is waiting on. Replace an asset mid-window and `P_DELAY_BYTES_CHANGED`
restarts the clock — otherwise the window is a schedule an attacker can publish
against.

**Why a track record shortens it.** Not because an established author is more
trustworthy; a compromised account is a compromised account. Because the delay's
value decays: it is a window for somebody to notice, and an author with a release
history has watchers, subscribers, and four earlier notifications from this bot.
The first release from an account nobody has ever seen is where 24 hours buys the
most. A revocation against any of an author's plugins resets the counter; a yank
does not (yanking is the author's own "do not use this one", not a fault signal),
and a `staging` listing never counted, because nobody could verify its artifact.

### The queue is a directory

A waiting release is `state/queue/<id>@<version>.json`, committed like everything
else here. It survives a runner, `git log state/queue/` is the record of every
release that ever waited and why, and a maintainer with no tooling can bring one
forward by editing `publish_after` or cancel it by deleting the file. A queued
release whose re-check now fails, or now needs a person, stops waiting rather
than being retried for ever.

## 5. How this registry hears that you released

Three ways in, all of which end in the same verification. None of them requires
you to hold a credential for this repository — the bot verifies everything from
scratch every time, so a notification is a *request to re-check*, never a claim.

1. **Comment `/release v0.2.0` on your listing issue.** One line, on its own,
   first line of the comment. This is the fast path and it is the one to use.
   Anyone may say it — the bot re-verifies everything from scratch anyway.
2. **Open "A release of a plugin that is already listed"** from the issue
   template chooser, if you cannot find your listing issue. It is honoured only
   for a repository that is **already listed**, so the worst a stranger achieves
   is causing a re-check of a listing already pinned to a repository identity. A
   first listing still goes through the listing form.
3. **The backstop.** A daily cron polls listings whose newest known release is
   more than 7 days old, using each repository's `releases.atom` with
   `If-None-Match`. An unchanged repository costs one 304 and no API quota. It is
   a safety net for a missed notification, not the fast path: use 1 or 2 and your
   release is in the catalogue in minutes.

**One thing does not work today.** `astra-plugin publish --notify` prints a
prefilled `issues/new?title=…&body=…` link. Blank issues are now off, so that
link lands on the template chooser and the prefilled text is dropped. Pick "A
release of a plugin that is already listed" and paste the `/release` line, or
use option 1 instead. Fixing the CLI to link the template directly is a change
in AstraPlugins and has not been made.

For 2 and 3, the ownership that gets proved is the **release author's** — the
account that published the bytes, which required push access to the pinned
repository — not whoever typed the notification. Whoever pinged is not part of
the decision. In practice that account is `github-actions[bot]`, because
`plugin-release.yml` is what creates the Release, and so this arm is
deliberately **circular**: the release's author is checked against the release's
author. Saying that out loud is the point. What actually protects these two
paths is not the check but the pin — a ping may only name a repository that is
**already listed**, so the worst it can do is re-verify a listing that is
already tied to that repository's identity, and the two events that could change
that identity (a first listing, a repository change) always block on a human.
It is capped at 90 days, so "they published something once" cannot stand in for
"they have access now".

None of this applies to a first listing, where the release author is a bot and
cannot be you. That is why the owner file above is what the form asks for, and
why a first-listing refusal never mentions who published the release: it is not
a fact you can act on.

The planned upgrade to 2 is a **GitHub App** subscribed to `release` on the
author's repository, posting the same line automatically. It needs the
maintainer's account to create and install it, which is why the comment path
exists first; nothing downstream changes when it arrives.

## 6. Every code this policy can post

| Code | Meaning |
|---|---|
| `P_PUBLISHED` | Live, nobody in the loop. What a routine release looks like. |
| `P_REFUSED` | A check failed; the policy never ran. The reason is above it in the same comment. |
| `R_FIRST_LISTING` | First listing — a person reads it, once, ever. |
| `R_NEW_HIGH_RISK` | A high-risk permission this plugin did not have before. |
| `R_IDENTITY_CHANGED` | The repository this plugin is listed from changed. |
| `R_CHECK_HELD` | A check handed the decision to a person; not one of the three, same SLA. |
| `P_DELAY_HIGH_RISK` | Waiting, because the plugin holds a high-risk permission. |
| `P_DELAY_WIDENED` | Waiting, because the permission set grew. |
| `P_TRUSTED_AUTHOR` | Shorter delay: a clean release history in this registry. |
| `P_DELAY_WAITING` | The publication time, stated. |
| `P_DELAY_ELAPSED` | The delay is over and every check has just been re-run. |
| `P_DELAY_BROUGHT_FORWARD` | A maintainer waived part of the window, on the record. |
| `P_DELAY_BYTES_CHANGED` | The assets changed mid-window, so the clock restarted. |
| `P_APPROVED` | A maintainer cleared the hold. Every check above it ran again from scratch in that same run. |
| `P_APPROVAL_STALE` | An `/approve` named a different submission from this one — the release changed after the comment it answered. Nothing published; the hold stands. |
| `P_UNKNOWN_PERMISSION` | A permission name this registry cannot describe. Reported, never blocking — the daemon default-denies, so it grants nothing. |
| `P_SLA` | What happens next, and by when. |

## 7. The publisher badge

A badge belongs to the **account**, never to the plugin, and never to the
`author` string. That string is read out of the plugin's own manifest, inside
the bundle, and it is whatever the author typed — a badge keyed on it would be
forged by a one-line edit. The only identity this registry proves is the GitHub
owner of `source.repo`, because that is what the ownership check binds to, so
that is what carries a tier.

Records live in `publishers/<owner>.json`, hand-written and hand-reviewed like a
listing. They are joined into `signed.publishers` at generation time and are
inside the signature a client already verifies; a claim outside it is one
whoever serves the bytes could invent.

| tier | what it says | evidence | how it is withdrawn |
|---|---|---|---|
| `official` | published by the Astra project | membership of this repository — the claim IS the reviewed file | deleting the file |
| `verified` | the registry has confirmed who this account is | a URL on a domain the publisher controls, serving their owner login | the re-check stops finding it, or `expires_at` passes |
| *(no record)* | **no claim at all** | — | — |

Each record also carries **one line saying who the publisher is to Astra** —
"Astra's creator and main developer", not "verified". The tier says what kind
of claim the registry is making; that line says what the publisher actually
is, which is the thing a person wanted to know when they looked. It is free
text rendered beside a trust mark, which is exactly where an impersonation
would want to live, so it is reviewed like everything else here and signed
with the rest of the catalogue. A client renders nothing when it is absent
rather than inventing a default.

**`verified` is stored as live evidence and the date it last held, not as a
verdict.** A tier granted once and never revisited becomes a claim about who
somebody *used to be*, and this registry is the only place that can notice. So
the evidence must be re-fetchable, it is re-fetched on a schedule, and
`expires_at` is the backstop for a re-check that has been failing quietly: a
record nobody has confirmed inside its window is reported by the build rather
than shipped on the strength of having once been true.

**`official` and `verified` are not degrees of one thing**, and the difference is
what each rests on rather than how much we like the publisher. `official` says
the account belongs to this project, and its evidence is a reviewed commit in
this repository — it cannot rot, because the claim *is* the file. `verified`
says we confirmed who a stranger is, and its evidence lives outside: a document
on their own domain that we re-fetch, and take the badge away when it stops
saying what it said. One is an assertion about ourselves; the other is a fact
about somebody else that we keep re-checking.

**What the badge does not mean.** It is not a safety claim. "We know who
published this" is not "this code is safe" — §8 below is unchanged by it, and a
client that lets a badge stand in for the permission sheet has made the user
worse off, not better. For the same reason a client must render on explicit
membership — the tier being exactly `official` or exactly `verified` — and never
on a value merely being present, non-empty, or not-some-default. An
unrecognised tier is not a badge.

---

## 8. What none of this proves

Auto-publication is not a safety review, and neither is human review — a
maintainer reading a listing issue is checking a name, a repository and a
permission request, not auditing a compiled binary. Being in this catalogue means
the bytes are the bytes CI built from a repository somebody proved they control,
and that this document's rules were applied to the result. Root POLICY.md §0 says
the rest, and it is the sentence this policy cannot get around.

---

## 9. Taking something back

Four actions, and they escalate by **what they cost somebody who already
installed the plugin** — which is the only ordering a user cares about. None of
them is a new mechanism; each is a thing the code already does, and naming them
in one table is the whole point.

| Action | Expressed as | Signed | A copy already installed | Reversible by |
|---|---|---|---|---|
| **Yank** | `"yanked": true` on `plugins/<id>/versions/<semver>.json` | no | **Nothing.** The version leaves the catalogue and stops being offered. | deleting the field |
| **Delist** | `"unlisted": true` on `plugins/<id>/plugin.json` | no | **Nothing.** The whole plugin leaves the catalogue and stops being offered updates. | deleting the field |
| **Deprecate** | an advisory with `"action": "warn"` | yes | Badged, and the user is told. Nothing is blocked and nothing is stopped. | a higher serial without it |
| **Revoke** | an advisory with `"action": "block_install"` or `"disable"` | yes | `block_install` — new installs and updates refused, a running copy left alone. `disable` — also stopped, and it will not start again. | a higher serial without it |

The first two are catalogue edits and reach nobody's machine; the last two are
signed statements that do. The behaviour in the fourth column is
`RevocationAction` in `astra-daemon/src/plugins/trust.rs`: `blocks_install()` is
true for everything except `warn`, and `stops_installed()` is true only for
`disable`.

**Yanking is the author's tool**, not a moderation action — it means "do not use
this one". It appears in the log when the registry does it; when an author does
it, the commit is the record.

**A revocation is deliberately undoable.** The daemon replaces its set on a
strictly greater serial and may only *add* on an equal one, so a mistaken
advisory is withdrawn by publishing a higher serial without it. That has to be
possible, or the only way to correct a mistake would be to delete files and hope.

### How it reaches a machine, and how fast

`.github/workflows/revoke.yml` regenerates, signs and pushes
`registry/v1/revocations.json` — and it exists as a separate workflow precisely
so a withdrawal never queues behind a listing build. The target is **signed and
on the CDN within five minutes**; the job stamps its own elapsed time on every
run and warns past 300 s, so a miss is a fact in the log rather than a belief.

The document carries a **seven-day** expiry against the catalogue's thirty. Past
that window Astra blocks new installs outright — "Astra can't check whether this
plugin has been withdrawn" — which is the one hard block in the whole freshness
policy, and why the list is re-signed on a schedule even when no advisory has
changed.

### Advisories

One file per advisory, `tools/revocations/ASTRA-YYYY-NNNN.json`, and the id is
**stable for as long as the advisory exists**: the file name, the `id` field and
every entry in the signed document must agree, or the build fails. Each advisory
carries a severity, exactly one action, a reason a user can act on, and one or
more keys — a bundle digest, a binary digest, an id, an `id@version`, a version
range, an author identity, or a publisher key.

At least one key must be one that can match a **sideloaded source directory**
(`binary`, `id`, `id_version` or `version_range`). A digest-only advisory leaves
"copy the files into a folder and sideload it" open by default rather than by
exception, and `tools/lib/revocations.mjs` refuses one.

### The transparency log

Every action above is recorded in `bot/moderation/<date>-<plugin>-<action>.json`
and published, machine-readable, at `/transparency/moderation-log.json`. An entry
claiming a `deprecate` or a `revoke` must name an advisory that is **actually in
the signed withdrawal list**, with a matching action, or the build fails. A
transparency log that can claim an unsigned revocation is a tool for scaring
people off a competitor.

What the log does not contain, stated on the page itself: submissions refused
before they were ever listed (those are public issues), reports received and not
acted on (publishing those publishes an unsubstantiated accusation), and anything
about installed copies — this registry has no telemetry and cannot tell you how
many people are running a withdrawn version.

## 10. Triage: how long a report takes

A report is somebody telling this registry that a **listed** plugin is not what
it says it is. Reports about behaviour beat every heuristic in this repository,
and they are the mechanism it actually relies on, so the clock on them is
published.

| From | To | Target |
|---|---|---|
| A report arriving | a human has read it and said so on the thread | **72 h** |
| A report of active harm becoming credible | the first action taken | **24 h** |
| Acknowledgement | a decision, for everything that is not active harm | **7 days** |
| An appeal being filed | a reasoned answer | **7 days** |

"Active harm" means malware, credential harvesting, undisclosed exfiltration of
conversation content, or a plugin whose behaviour differs from its description in
a way that costs the user something. Everything else — a licence mismatch, a name
that looks like impersonation, a disclosure that should have been on the store
card — is the third row.

**The first action is allowed to be the reversible one.** Delisting inside the
24 h and deciding afterwards is not a failure of process, it is the process: a
delist costs an author a listing and is undone in a commit, while `disable` stops
software on somebody's machine. Speed comes from the reversible end of the table,
never from the other one.

**And when this slips.** The same answer as §3's review queue, for the same
reason: the fix is to make fewer things need a person, not to promise harder. One
maintainer cannot audit binaries and will not pretend to. If triage is
consistently late, what changes is this table, in a reviewed commit — because a
published clock nobody meets teaches people the document is decoration, and this
one is load-bearing.

These four numbers are declared in `bot/lib/moderation.mjs` and asserted against
this file by `bot/tests/policy.test.mjs`, exactly like §3's and §4's.

### The nightly asset check

Every night, every artifact the catalogue pins is checked against the signed
index with **one conditional request** — `Content-Length` compared to the `size`
the index records, and `ETag` compared to what the previous run saw. A body is
downloaded only when a header disagrees. Measured against a real server in
`bot/tests/asset-check.test.mjs`: two artifacts totalling 15.9 MB cost 326 bytes
of headers and no body on a cold run, against 15.9 MB per run for the
unconditional version of the same job.

A mismatch means the release this catalogue points at is no longer the release
that was reviewed. It does **not** mean anybody is in danger: Astra verifies the
digest before it unpacks anything, so a swapped asset is uninstallable rather
than dangerous. The job opens an issue and touches nothing; what happens next is
one of the four actions in §9, and that is a person's decision.

## 11. Appeals

Every action in §9 can be appealed, including one that has already taken effect,
and the answer arrives within **7 days**. Open an issue titled
`[appeal] <plugin-id>` and use this template:

```
Plugin id:
Action being appealed:      yank / delist / deprecate / revoke
Advisory id (if any):       ASTRA-YYYY-NNNN
Your relationship to it:    author / co-maintainer / user / other

What the registry said:
  (paste the reason from the log entry or the advisory)

What you say happened:

What has changed since, if anything:
  (a new release, a corrected manifest, a licence fix, a disclosure added to
  the store card)

What you are asking for:
  (relist / reduce the action to a warning / withdraw the advisory entirely)
```

What happens: the maintainer answers on the thread, in public, naming the rule
that was applied and whether it still applies. If the appeal succeeds, the
correction is a commit — a field deleted, or an advisory withdrawn by publishing
a higher serial without it — and the moderation log keeps both the original entry
and the reversal. Nothing is quietly deleted; a log that can be edited is not a
log.

If the action was taken in error by this registry rather than by a rule, say so
plainly in the appeal. That is a bug report about the bot or about this document,
and it is worth filing on its own.

## 12. Embargoed reports

For anything that would let somebody **ship code to a user** — a hole in the
verification chain, a way to get a listing past the checks, a compromised
publisher — do not open a public issue.

**Today, the channel is a private GitHub security advisory on this repository.**
It needs no key ceremony, and it is the path this registry can honestly offer
right now.

**Who can read it, exactly.** You, this repository's admins, and GitHub. It is
*private*; it is not end-to-end encrypted, and this document used to say it was.
That is a difference worth a sentence, because it is the difference between "not
public" and "unreadable by anyone but us", and which of those you believe decides
how much detail you paste into a first message. Until the PGP slot below is
filled, nothing this registry publishes can offer the second one.

**How to open one, including when the button is not there.**

1. Go to
   [Security → Advisories](https://github.com/mihailinl/astra-registry/security/advisories)
   and use **Report a vulnerability**.
2. **If there is no such button, that is expected right now.** GitHub shows it to
   outside reporters only when *private vulnerability reporting* is enabled for
   the repository, and on this one it is not yet
   (`gh api repos/mihailinl/astra-registry/private-vulnerability-reporting` →
   `{"enabled":false}`, checked 2026-08-15). Enabling it is one switch, it is on
   the maintainer's list in `docs/RUNBOOK.md` §1, and this paragraph goes away
   the day it is flipped.
3. Until then, ask for the channel in public and put nothing in it. Blank issues
   are off, so the door is the **Report a listed plugin** form; use `n/a` for the
   plugin id if the finding is about the registry itself, say that you have a
   security report and how to reach you, and **write not one word about the
   mechanism** — that form is public the moment you submit it. A maintainer opens
   an advisory and adds you to it, and the details go there. It costs one
   round-trip and it needs no setting to have been switched on first.

A report that arrives the wrong way is still a report. Nothing here is a reason
to sit on a finding: if the only way you can reach somebody is a public issue
with details in it, send it and say why, and the registry will deal with the
disclosure rather than blame the reporter.

**There is no PGP key yet, and no `security@` mailbox yet.** Both are slots in
`bot/security-contact.json`, and both are empty. The security page on the website
is generated from that file and says so in a box rather than printing a
fingerprint for a key nobody holds — the same shape as the two compiled-in root
key slots, which are also empty and which a default Astra build fails closed on.
A vulnerability report sent into a void is worse than one never sent, because the
reporter believes they told us.

Provisioning it, when it happens, is this checklist and not fewer steps:

1. Register `security@` on the domain the catalogue is served from, and prove
   delivery by sending to it from an unrelated account and receiving it.
2. Generate the key **offline**, on the same machine and with the same custody
   rules as the root key ceremony in `SECURITY.md` §3 — one person, two copies,
   one of them physical.
3. Publish the armored public key in this repository, and the 40-hex fingerprint
   in `bot/security-contact.json`, `SECURITY.md` and the repository profile, in
   **one commit**. A fingerprint published in one place and not another is a
   fingerprint an attacker gets to choose between.
4. Send yourself an encrypted test report and decrypt it before announcing the
   address anywhere.

Until step 4 has happened, this section stays as it is.

**What you get for reporting privately:** an acknowledgement inside the §10
window, a coordinated disclosure date agreed with you rather than announced at
you, credit in the advisory unless you ask otherwise, and — if the finding leads
to a withdrawal — a stable `ASTRA-YYYY-NNNN` id that points at what you found.
