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

**What a declaration is worth right now.** All of the above — the four names,
`R_NEW_HIGH_RISK`, `P_DELAY_HIGH_RISK`, the host-RPC scan — reads what the
manifest *declares*. **Nothing enforces that declaration at run time yet.** The
daemon issues a session token to every plugin it starts, and the host RPCs check
that a caller is a registered plugin, not that the plugin was granted the thing
it is calling; PRODUCTION_PLAN §5.6's `require_permission` is Phase 4.1 and has
not landed. So an undeclared call is **not blocked on the user's machine**. The
registry's only lever against a plugin that declares nothing and calls one of
the four anyway is the string search over its source, which
`docs/BOT-CHECKS.md` describes as a heuristic that catches accidents rather than
a determined author. Read the table above as "who told us what", not as "what
the daemon will permit", until that sentence is deleted.

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

1. **`astra-plugin publish --notify`** (AstraPlugins CLI). Prints, and offers to
   open, a prefilled URL. This is the escape hatch that always works.
2. **A comment on your listing issue:** `/release v0.2.0`. Anyone may say it. An
   unlabelled new issue may also say `/release you/your-plugin v0.2.0`, and is
   honoured only for a repository that is **already listed** — so the worst a
   stranger achieves is causing a re-check of a listing already pinned to a
   repository identity. A first listing still goes through the issue template.
3. **The backstop.** A daily cron polls listings whose newest known release is
   more than 7 days old, using each repository's `releases.atom` with
   `If-None-Match`. An unchanged repository costs one 304 and no API quota. It is
   a safety net for a missed notification, not the fast path: use 1 or 2 and your
   release is in the catalogue in minutes.

For 2 and 3, the ownership that gets proved is the **release author's** — the
account that published the bytes, which required push access to the pinned
repository — not whoever typed the notification. Whoever pinged is not part of
the decision. This is weaker than the admin/maintain answer a first listing gets,
and the weakening is bounded by the two events that always block on a human
anyway: a first listing, and a repository change.

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
| `P_DELAY_BYTES_CHANGED` | The assets changed mid-window, so the clock restarted. |
| `P_UNKNOWN_PERMISSION` | A permission name this registry cannot describe. Reported, never blocking — the daemon default-denies, so it grants nothing. |
| `P_SLA` | What happens next, and by when. |

## 7. What none of this proves

Auto-publication is not a safety review, and neither is human review — a
maintainer reading a listing issue is checking a name, a repository and a
permission request, not auditing a compiled binary. Being in this catalogue means
the bytes are the bytes CI built from a repository somebody proved they control,
and that this document's rules were applied to the result. Root POLICY.md §0 says
the rest, and it is the sentence this policy cannot get around.
