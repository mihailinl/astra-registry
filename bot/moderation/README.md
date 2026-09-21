# Moderation entries

One JSON file per action taken against a **listed** plugin. Read by
`bot/lib/moderation.mjs`, published as `/transparency/moderation-log.json` and
rendered at `/transparency/`.

A refusal is not in here. A submission that never got listed is a public issue
with the failing check named; mixing the two would make the count meaningless.

## The file

Named `<date>-<plugin>-<action>.json`, and a **second** entry for the same date,
plugin and action takes `-2`, then `-3` (MOD-47). The generator refuses a file
whose name does not match its contents, and refuses a `-3` with no `-2` beside
it — a gap means the next writer computes `-3` again from the count and
overwrites somebody's takedown record.

The first entry of a day keeps the plain name. Every entry taking a suffix
would have been tidier and would have meant renaming the six entries already on
`main`, and a moderation entry is the worst file here to rename: its path is
what a reader of a commit, an alarm or a transparency page was given.

```json
{
  "date": "2026-08-11",
  "action": "revoke",
  "plugin": "example-plugin",
  "versions": ["0.3.0", "0.3.1"],
  "reason": "Shipped a build that read the Astra config directory and posted it to a third-party host.",
  "category": "malicious",
  "advisory": "ASTRA-2026-0001",
  "service_decision_id": "3f2c1b8a-0d4e-4c7a-9b1f-2e5a6c8d0f13"
}
```

| Field | Rule |
|---|---|
| `date` | `YYYY-MM-DD`, the day the action took effect. |
| `action` | One of the seven below. |
| `plugin` | The listed plugin id. |
| `versions` | Optional. Semver strings, for an action that covers some versions and not others. |
| `reason` | 10–300 **code points**, shown verbatim. See below — it has its own corpus. |
| `advisory` | **Required** for `deprecate`, `revoke` and `unrevoke`; **refused** for the other four. `ASTRA-YYYY-NNNN`. |
| `appeal` | Optional https URL of the appeal thread. Only on an entry dated **before** `log/cutover.json`'s `cutover_at` — the public issue channel closes there, and a link to a thread nobody can open reads as the estate having hidden the appeal. |
| `category` | Optional. §7.2's table, per action; see below. Refused on an `appeal`. |
| `reverses` | Only on `relist` and `unrevoke`. The `service_decision_id` being undone — or, on an `unrevoke` of a hand advisory that had no service decision behind it, that advisory's own `ASTRA-YYYY-NNNN`. |
| `appeal_of` | **Required** on an `appeal`, refused elsewhere. The `service_decision_id` or `decision_id` appealed. |
| `outcome` | **Required** on an `appeal`, refused elsewhere. `stands` or `reversed`. |
| `service_decision_id` | Optional. §0.7's lowercase UUID, for an entry a service decision produced (BOT-81). |
| `declared_interest` | Optional, and a **flag**: `true` when a moderator declared a conflict (MOD-12). Never a name — this document carries no `moderator` member and `tools/priv-scan.mjs` permits no handle in any of its members. |

`$comment` is allowed, and five of the entries here carry one.

## The seven actions

Four take something away. They escalate by what they cost somebody who has
already installed the plugin, which is the only ordering a user cares about.
Each is a mechanism that already exists; none is behaviour invented for the log.

| Action | Expressed as | Signed? | A copy already installed |
|---|---|---|---|
| **yank** | `"yanked": true` on `plugins/<id>/versions/<semver>.json` | no | Untouched. The version leaves the catalogue (`tools/build-index.mjs` `listedReleases`). |
| **delist** | `"unlisted": true` on `plugins/<id>/plugin.json` | no | Untouched. The plugin leaves the catalogue and stops being offered updates. |
| **deprecate** | an advisory with `"action": "warn"` | yes | Badged, and the user is told. Nothing is blocked and nothing is stopped. |
| **revoke** | an advisory with `"action": "block_install"` or `"disable"` | yes | `block_install`: new installs and updates refused, a running copy left alone. `disable`: also stopped, and it will not start again. |

Three give it back, or record that somebody asked for it back (MOD-47). They
are in **this** log rather than a second one because a log that records only the
taking overstates the estate's severity for ever: a reader who finds the delist
and not the relist reads a listed plugin as withdrawn.

| Action | Expressed as | Carries |
|---|---|---|
| **relist** | `unlisted` removed — MOD-52's revert, or `M_RELIST` | `reverses` |
| **unrevoke** | the advisory file deleted, and the effect lifted at a higher serial | `advisory`, `reverses` |
| **appeal** | nothing in the catalogue. It records a decided appeal (`M_APPEAL`; MOD-33) | `appeal_of`, `outcome`, and **no category** |

An `appeal` entry never carries the appellant's text. PRIV-2 keeps report and
appeal text out of git entirely; what is published is the outcome and the
public reason.

### The backing rule, and what an unrevoke does to it

The last two of the four are the ones with teeth, and they are the ones the
maintainer cannot fake here: `buildModerationLog` is given the **signed**
`revocations.json` being deployed and refuses to emit an entry whose advisory is
not in it, or whose advisory carries a different action. A transparency log that
could claim an unsigned revocation could be used to scare people off a
competitor.

An `unrevoke` **deletes** that advisory, so from the next signing run the
withdrawal list stops carrying it — and the backing check would then throw about
an entry that is not wrong. It is **settled**: the entry is right, the advisory
is gone on purpose, and the published entry says `"backed": "settled"` instead
of a claim. Without that, the build would refuse to emit a log every time the
estate corrected itself, which is backwards — the reversal is the part of the
record a wrongly-withdrawn author most needs published.

An `unrevoke`'s own entry is never backing-checked, for the same reason: the
correct state of the signed list for one is *absent*.

### Categories (§7.2)

One per `M_*` decision, except `M_APPEAL`, which has none. `bot/lib/moderation.mjs`'s
`CATEGORIES` is the table, keyed by log action rather than by decision code:

| Action | May carry |
|---|---|
| `yank` | malicious, account_compromise, account_sanction, privacy, broken, security_defect, author_request |
| `delist` | malicious, account_compromise, account_sanction, privacy, impersonation, broken, licence, naming, legal, author_request |
| `deprecate` | privacy, broken, security_defect, licence, legal, path_test |
| `revoke` | malicious, account_compromise, account_sanction, privacy, impersonation, security_defect, legal |
| `relist`, `unrevoke` | error, appeal_reversed, path_test |
| `appeal` | — |

`author_request` on a `yank` is FLOW-79's: an author's own yank, taken in the
panel and compiled to a yank with an author-action decision record. Its reason
is the one fixed registry string `schema/contract-tokens-v1.json` lists for
`A_YANK` — never author text, because an author action has no moderator and
DEC-14 and MOD-41 forbid an author-typed reason.

## The reason, and the corpus behind it

**10 to 300 code points**, not UTF-16 code units. `[...s].length`, Postgres
`char_length`, Python `len`, Rust `chars().count()`. Not JavaScript
`String.length`.

That distinction is not pedantry: the plugins service refuses the same reason at
entry (MOD-48) counting code points, and if this side counted UTF-16 units a
299-code-point Russian reason with four emoji would be accepted there and
refused here — the decision settles as `refused` with nothing for the moderator
to act on, and **the takedown stalls**.

Also refused: a URI scheme, `www.`, `@`, an email, and a host-like token. Names
such as `plugin.toml`, `astra-chess.json`, `README.md` and `v1.2.3-rc.1` pass.
`evil.example` does not.

All of it is one function — `reasonProblems` in `bot/lib/moderation.mjs`, shared
with `checkAdvisory` in `tools/lib/revocations.mjs` — and the vectors are
[`tests/moderation-reasons.json`](../../tests/moderation-reasons.json), which
[`tests/README.md`](../../tests/README.md) documents. Add a vector there before
you change a rule here.

## Writing one

1. Do the thing first — edit `plugins/**` for a yank, a delist or a relist,
   write or delete `tools/revocations/ASTRA-YYYY-NNNN.json` for a deprecation,
   a revocation or an unrevoke.
2. Add the file here. If there is already one for that date, plugin and action,
   yours is `-2`.
3. `node bot/moderation.mjs --check` and, when an advisory is involved,
   `node bot/moderation.mjs --revocations registry/v1/revocations.json`.
4. Commit both together. A revocation deployed without its log entry is a
   withdrawal nobody can read the reason for; a log entry without its advisory
   fails the build.

`node --test bot/tests/moderation.test.mjs` is the suite that holds all of the
above, including the shared reason corpus and MOD-47's round trip.

## Timing

A revocation will be signed and put on the CDN by the withdrawal workflow built at R1.
There is no such workflow today. The one that held that name failed on every run it
ever made and was deleted at R0, because it was also the second place in this
repository that could sign (registry plan RC-R0-1, 2026-09-18); the withdrawal path
is built once, at R1, in `sign.yml`. What follows describes the path it will take, which
exists separately from the catalogue build precisely so it does not queue behind
it. Everything else here rides the ordinary index build.

The triage clock — how long from a report arriving to one of these actions —
is in `docs/POLICY.md`.
