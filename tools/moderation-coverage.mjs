#!/usr/bin/env node
// MOD-39's coverage canary: every moderation effect in this repository is
// accounted for, in the state it leaves behind and in the commit that made it.
//
//     node tools/moderation-coverage.mjs                       both modes
//     node tools/moderation-coverage.mjs --mode state          the tree as it is
//     node tools/moderation-coverage.mjs --mode commits        the walk
//     node tools/moderation-coverage.mjs --repo <dir> …        a fixture clone
//     node tools/moderation-coverage.mjs --report findings.jsonl
//
// ── THE TWO MODES, AND WHY NEITHER IS THE OTHER ─────────────────────────────
//
// **State** asks what is true now: is every delisted plugin delisted in the
// log, is every yanked version yanked in the log. It catches the effect that
// has no record, whenever it happened and however it got here — including the
// five delists that reached `main` in August 2026 with nothing in
// `bot/moderation/` at all (OPEN-OWNER-21; M-T1.4 writes them).
//
// **Commit** asks who did it: it walks every commit after the one that added
// this file and looks for the act rather than the residue. It catches the
// thing state mode cannot see — an effect applied and reverted between two
// runs, an advisory added and deleted, a log entry edited after the fact.
// State mode looks at both of those and sees nothing wrong, because by then
// there is nothing left to see.
//
// A moderation record whose only witness is the tree is a record that can be
// edited into agreement with the tree. That is what MOD-34 is about and why
// both modes exist.
//
// **"Every commit" includes a merge's own resolution** (gap 93). The walk
// takes merges out of the commit list, because a merge's first-parent diff is
// the whole branch again, and until 2026-09-22 that was the end of it: a
// delist typed while resolving a conflict, or a log entry dropped while
// merging `main` into a branch, was in no walked commit and gave nothing.
// The second of those is invisible to state mode too — nothing is left
// unlisted, a record is simply gone. `mergeView` is the merge half.
//
// ── IT GATES NOTHING (MOD-46) ───────────────────────────────────────────────
//
// This file runs in `.github/workflows/moderation-coverage.yml` and nowhere
// else. It is in no signing job, no publishing job and no ingest path, and it
// may never become one: a takedown that waits for a transparency check is a
// takedown that a transparency check can stop. A red canary alarms, and it
// blocks only the release of a held `M_RELIST` or `M_UNREVOKE` (MOD-9) — which
// costs time and nothing else — until an operator's commit clears it with a
// retro log entry, a `Moderation-Exempt:` trailer or a fix.
//
// ── HOW A RED ONE IS CLEARED ────────────────────────────────────────────────
//
// Three ways, and `docs/RUNBOOK.md` §7 "Clearing a red coverage canary"
// (M-T1.8) is the operator's copy:
//
//   1. write the log entry that was owed — the honest repair, and the only one
//      that makes the transparency log true;
//   2. on the commit itself: `Moderation-Exempt: <actor>: <reason>`;
//   3. afterwards, from a later commit: `Moderation-Exempt: <sha>: <actor>:
//      <reason>`, naming the commit being cleared. History is not rewritten to
//      clear a canary.
//
// ── WHAT THIS DOES NOT DO ───────────────────────────────────────────────────
//
// It does not judge whether a moderation action was RIGHT, and it cannot. It
// asks only whether the person who took it left a record a reader can find. A
// delist with a log entry saying "Removed" passes here and is worth nothing to
// a reader; `tests/moderation-reasons.json` (M-T1.6) is the check that has an
// opinion about the reason, and `bot/moderation.mjs --check` is the one with
// an opinion about the schema.
//
// It also does not re-judge history before its own introducing commit in
// commit mode. That is deliberate and it is the reason state mode exists: the
// walk starts empty on the day it lands, so a canary that had only the walk
// would be green on a repository with five unlogged delists in it.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ACTIONS, reasonProblems } from "../bot/lib/moderation.mjs";
import { stagingListingId as reservedStagingListingId } from "./lib/reserved.mjs";
import { ADVISORY_FILE } from "./lib/revocations.mjs";
import { report } from "./coverage/rules.mjs";
import {
  blobAt, changedPaths, commitMeta, commitsAfter, firstParent, git, historyCount,
  introducingCommit, isShallow, jsonAt, mergeOwnChanges, mergesAfter, trailerValues,
} from "./coverage/git.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..");

/** This file, as git knows it. The walk's start is derived from it, not pinned. */
export const SELF_PATH = "tools/moderation-coverage.mjs";

export const RULE = "moderation-coverage";

// ── the two floors ──────────────────────────────────────────────────────────
//
// **Unlisted listings.** Six on 2026-09-19: astra-chess, echo-stt, knice-chess,
// mock-stt, tone-tts, web-chat. Five from M-T6.3 step 3, which relisted
// astra-chess under MINICE-AI. Every state-mode rule below is a loop over a
// set, and a loop over an empty set is green about nothing. The number is a
// floor rather than an equality because relisting a plugin is a legitimate act
// and this line is not the inventory; it goes red when the WALK has stopped
// finding listings, which is the failure that would otherwise read as a clean
// bill of health.
export const UNLISTED_FLOOR = 5;

// **History.** 228 commits reachable from HEAD on 2026-09-19. This is not a
// statement that history is interesting; it is the check that the checkout is
// not shallow. `fetch-depth: 0` is one line in one workflow, it is the line a
// person deletes while making a job faster, and without it `rev-list` returns
// one commit, the walk judges nothing, and the canary is green — green because
// it looked at nothing, which is the exact shape of failure this whole file
// exists to make impossible somewhere else. History here only grows, so a tight
// floor costs nothing and a force-push that rewrote 228 commits is a thing
// somebody should be told about anyway.
export const HISTORY_FLOOR = 228;

// `tools/lib/revocations.mjs`'s ADVISORY_FILE, not a pattern of this file's own
// (gap 72): the directory is `SOURCE_DIR`'s, so had advisories moved a literal
// here would have stopped seeing every one of them; and the id is
// `tools/lib/ids.mjs`'s grammar, four serial digits OR MORE. The tail this file
// typed for itself took exactly four, so from `ASTRA-YYYY-10000` on — which
// `nextAdvisoryId` writes — this canary would have gone green about advisories
// it could not see.
const ADVISORY_RE = ADVISORY_FILE;
const LOG_ENTRY_RE = /^bot\/moderation\/[^/]+\.json$/;
const LOG_TREE_RE = /^log\//;

// The one record under `log/` that is re-committed on purpose (contract 2.3.0,
// MOD-34's Check: "CI refuses edits to existing `bot/moderation/*.json` and
// `log/**`, except `log/migration-notice-<n>.json`, which contract MIG-13's
// re-send re-commits"). A re-send that announces a later cutover date writes
// the new date into every marker from round 2 on, each keeping its own
// `sent_at`, so ROLL-32's and ROLL-63's clocks do not move. Only a CHANGE is
// excepted: no MIG-13 procedure deletes a marker, and a deleted one erases the
// round the banner and the deadline watch read. The name is B.4's, `<n>` a
// positive integer, so a look-alike (`…-2.json.bak`, `…-x.json`) stays under
// the rule. Until 2.3.0 each re-send cleared itself with `Moderation-Exempt:`,
// which clears every trigger in its commit; the exception is the narrower
// instrument.
const NOTICE_MARKER_RE = /^log\/migration-notice-[1-9][0-9]*\.json$/;

// **Deliberately looser than `tools/lib/ids.mjs`'s `ID_PATTERN`.**
//
// The first spelling of these two copied that pattern, which is a rule this
// repository already has a name for (B-T0.5: no second copy of the plugin-id
// predicate). Deriving them from it instead was the obvious repair and it is
// the wrong one, which a fixture whose plugin was called `a` showed: a
// one-character directory is not a valid plugin id, so a walk filtered by the
// predicate does not see `plugins/a/plugin.json` at all, and a delist there is
// invisible. State mode, which reads the directory, sees it.
//
// A path the id predicate REJECTS is exactly the path somebody would use to
// put a listing where a rule does not look. `tools/validate.mjs` is what
// refuses an invalid id; this walk's job is to notice the commit, whatever the
// id turns out to be. So it matches any single path component, and the
// predicate is not in this file in either direction.
const PLUGIN_JSON_RE = /^plugins\/([^/]+)\/plugin\.json$/;
const PUBLISHER_JSON_RE = /^publishers\/([^/]+)\.json$/;
const VERSION_JSON_RE = /^plugins\/([^/]+)\/versions\/([^/]+)\.json$/;

/** MOD-47: `<date>-<plugin>-<action>.json`, and `-2`, `-3` for a second the same day. */
export const ENTRY_NAME_RE = /^(\d{4}-\d{2}-\d{2})-([a-z0-9][a-z0-9-]*)-([a-z]+)(?:-(\d+))?\.json$/;

// ── trailers ────────────────────────────────────────────────────────────────

const SHA_RE = /^[0-9a-f]{7,40}$/;

/**
 * Parse one `Moderation-Exempt:` value into what it exempts.
 *
 * Two grammars share one key, and the first field tells them apart:
 *
 *   `Moderation-Exempt: <actor>: <reason>`          this commit
 *   `Moderation-Exempt: <sha>: <actor>: <reason>`   that one, from here
 *
 * An actor that looks like a short SHA would be read as the second form. That
 * is a seven-character all-hex actor name — `deadbee` — and the cost of the
 * ambiguity is an exemption that clears nothing and is reported as clearing a
 * commit that does not exist, which is a red canary with a legible cause.
 *
 * @returns {{sha: string|null, actor: string, reason: string}|null}
 */
export function parseExempt(value) {
  const parts = value.split(":").map((s) => s.trim());
  if (parts.length >= 3 && SHA_RE.test(parts[0])) {
    const [sha, actor, ...rest] = parts;
    const reason = rest.join(":").trim();
    return actor && reason ? { sha, actor, reason } : null;
  }
  if (parts.length >= 2) {
    const [actor, ...rest] = parts;
    const reason = rest.join(":").trim();
    return actor && reason && !SHA_RE.test(actor) ? { sha: null, actor, reason } : null;
  }
  return null;
}

/** Every `Moderation-Exempt:` on a message, parsed. Unparseable ones are dropped. */
const exemptions = (message) => trailerValues(message, "Moderation-Exempt").map(parseExempt).filter(Boolean);

// ── M-T5.8: a badge withdrawn says why (MOD-44, MOD-42) ─────────────────────
//
// Contract MOD-44: a badge withdrawn for cause is a public commit to
// `publishers/` whose `Badge-Withdrawn:` trailer carries a MOD-41 reason, and
// that trailer is what the plugins service reads to send `notice.moderated`
// to every listing the record covered — "for such a commit, and no other".
// So a commit that removes or narrows a publisher record with no trailer is a
// withdrawal nobody is told about, and one whose trailer carries a reason
// MOD-41 refuses is a notice the service either refuses or sends with text
// that must never reach a reader. Publisher records are hand commits the bot
// never validates (MOD-42), which is why the check is here, in the walk that
// reads hand commits, and not in a publish path.
//
// **A lapse is not a withdrawal for cause.** `publisher-recheck.yml` deletes a
// `verified` record whose confirmations ran out, and that is no moderation
// act: it sends no notice and carries no `Badge-Withdrawn:`. Its commit
// carries `Moderation-Exempt: publisher-recheck: …` instead, which this walk
// already honours for every trigger in a commit. A hand narrowing that copies
// the same exemption is green too, and that is accepted: `publishers/**` is a
// reviewed hand path, and a registry writer already has the power it grants.
//
// **Narrowing** is anything that leaves the badge saying less than it did:
// the record deleted or made unreadable; a login it spoke for (its `owner`, or
// one in `covers`) no longer among those it speaks for; `astra_team` becoming
// `verified`; or an `expires_at` added where there was none, or moved earlier.
// A renewal moves `expires_at` LATER, so the re-check's everyday commit is not
// a narrowing and needs no trailer at all.
//
// **It applies to commits after the one that introduced it** (the plan), so
// history is not re-judged. The start is the oldest commit in which this file
// carries `BADGE_RULE_TOKEN` — derived, like the walk's own start, rather than
// pinned to a SHA nobody can write before the commit exists.

/** The string whose first appearance in this file starts M-T5.8's rule. */
export const BADGE_RULE_TOKEN = "m-t5.8/badge-withdrawn-trailer";

const TIER_RANK = { astra_team: 2, verified: 1 };

/** Every login a publisher record speaks for: its owner, and each of `covers`. */
const speaksFor = (doc) => new Set([doc?.owner, ...(Array.isArray(doc?.covers) ? doc.covers : [])]
  .filter((l) => typeof l === "string").map((l) => l.toLowerCase()));

/**
 * How `now` says less than `before`, or null when it does not. Both are the
 * parsed record; `now === null` is a deletion or an unreadable file.
 *
 * @returns {string|null} a phrase for the run log
 */
export function badgeNarrowing(before, now) {
  if (!before || typeof before !== "object") return null; // a new record widens
  if (!now || typeof now !== "object") return "removed the record, or left it unreadable";
  const lost = [...speaksFor(before)].filter((l) => !speaksFor(now).has(l));
  if (lost.length) return `stopped speaking for ${lost.join(", ")}`;
  const rb = TIER_RANK[before.tier] ?? 0;
  const rn = TIER_RANK[now.tier] ?? 0;
  if (rn < rb) return `lowered the tier from ${before.tier} to ${now.tier ?? "none"}`;
  if (typeof now.expires_at === "string") {
    if (typeof before.expires_at !== "string") return `added an expiry, ${now.expires_at}`;
    if (now.expires_at < before.expires_at) return `moved the expiry earlier, to ${now.expires_at}`;
  }
  return null;
}

/**
 * Whether a commit's own message covers a badge narrowing: a
 * `Badge-Withdrawn:` whose reason MOD-41's rules accept. Every value is
 * judged, so one good trailer beside a refused one still reports the refused
 * one — a notice the service would send with the bad text is not covered by
 * the good one next to it.
 *
 * @returns {{covered: boolean, refused: string[]}}
 */
export function badgeWithdrawnCover(message) {
  const values = trailerValues(message, "Badge-Withdrawn");
  const refused = [];
  for (const v of values) {
    const problems = reasonProblems(v);
    if (problems.length) refused.push(problems.map((p) => p.class).join("+"));
  }
  return { covered: values.length > 0 && refused.length === 0, refused };
}

/**
 * The commit that introduced M-T5.8's rule: the oldest one in which this file
 * carries `BADGE_RULE_TOKEN`. Null when git knows none (an uncommitted working
 * copy, or a fixture repository), which the walk reports rather than treats
 * as "judge nothing".
 */
export function badgeRuleStart(repo) {
  const out = git(["log", "--format=%H", `-S${BADGE_RULE_TOKEN}`, "--", SELF_PATH], { cwd: repo, allowFailure: true });
  const shas = out.split("\n").map((x) => x.trim()).filter(Boolean);
  return shas.length ? shas[shas.length - 1] : null;
}

// ── state mode ──────────────────────────────────────────────────────────────

function readJsonFile(file) {
  try {
    return { value: JSON.parse(fs.readFileSync(file, "utf8")), bad: null };
  } catch (e) {
    return { value: null, bad: String(e.message) };
  }
}

/**
 * A file name split into the part that orders it and the part that numbers it.
 *
 * MOD-47's second entry of a day is `<date>-<plugin>-<action>-2.json`, and
 * `-` sorts BEFORE `.`, so a plain name sort puts `…-delist-2.json` ahead of
 * `…-delist.json`: the second write ahead of the first, and `…-delist-10`
 * ahead of `…-delist-2`. Every rule that reads "the last one" then reads a
 * same-day run of one action backwards.
 *
 * **What this does NOT fix**, said here so nobody reads the sort as more than
 * it is: within one date, a `delist` and a `relist` cannot be ordered at all —
 * the log carries a date and no time, so `delistCovered` below takes the
 * alphabetically later of the two and `relist` happens to win. A plugin
 * delisted, relisted and delisted again inside one day reads as relisted. The
 * fix for that is a time on the entry, which is a schema change and a contract
 * question, not a comparator.
 *
 * Read off the NAME rather than rebuilt from the entry's members, unlike
 * `bot/lib/moderation.mjs`'s `suffixOf`, because this file must stay readable
 * over a malformed entry: a file whose `action` is misspelled still has to
 * sort somewhere, and the alternative is a canary that throws on the one file
 * it is there to complain about.
 */
function nameParts(name) {
  const m = /^(.*?)(?:-(\d+))?\.json$/.exec(name);
  return m ? { base: m[1], n: m[2] ? Number(m[2]) : 1 } : { base: name, n: 1 };
}

/** Every `bot/moderation/*.json`, parsed, sorted by date, then name, then MOD-47's `-<n>`. */
export function loadLog(repo) {
  const dir = path.join(repo, "bot", "moderation");
  if (!fs.existsSync(dir)) return { entries: [], bad: [] };
  const bad = [];
  const entries = [];
  for (const name of fs.readdirSync(dir).filter((n) => n.endsWith(".json")).sort()) {
    const { value, bad: why } = readJsonFile(path.join(dir, name));
    if (why) { bad.push(`bot/moderation/${name} is not readable JSON: ${why}`); continue; }
    entries.push({ name, ...value });
  }
  entries.sort((a, b) => {
    const byDate = (a.date ?? "").localeCompare(b.date ?? "");
    if (byDate) return byDate;
    const pa = nameParts(a.name);
    const pb = nameParts(b.name);
    return pa.base.localeCompare(pb.base) || pa.n - pb.n;
  });
  return { entries, bad };
}

/**
 * The staging listing id M-T2.1 reserves, or null.
 *
 * The file read stays here — this rule takes a repository root and may be
 * pointed at a fixture tree — and the JUDGEMENT of what the member means moved
 * to `tools/lib/reserved.mjs` when M-T2.1 landed the value, because
 * `tools/validate.mjs` and `bot/lib/derive.mjs` now ask the same question of a
 * policy object they already hold. Three copies of "a non-empty string is an
 * id and anything else is null" is three chances to disagree about `""`, and
 * the walk below EXCLUDES whatever this returns: a copy that read `""` as an
 * id would silently stop reporting every listing with a malformed id.
 */
export function stagingListingId(repo) {
  const file = path.join(repo, "policy", "reserved-ids.json");
  if (!fs.existsSync(file)) return null;
  const { value } = readJsonFile(file);
  return reservedStagingListingId(value ?? {});
}

/** Author-action records (DEC-7), which cover a yank instead of a log entry. */
export function loadAuthorActions(repo) {
  const root = path.join(repo, "log", "decisions");
  const out = [];
  if (!fs.existsSync(root)) return out;
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!e.name.endsWith(".json")) continue;
      const { value } = readJsonFile(full);
      if (isAuthorAction(value)) out.push(value);
    }
  };
  walk(root);
  return out;
}

/** FLOW-79's `A_YANK`, compiled. `actor: author`, `state: yanked`, no submission. */
export function isAuthorAction(v) {
  return !!v && typeof v === "object"
    && v.actor === "author" && v.state === "yanked"
    && Array.isArray(v.reasons) && v.reasons.includes("A_YANK")
    && typeof v.plugin_id === "string";
}

/**
 * Is this plugin's delist recorded, and not later undone?
 *
 * `relist` is still read here as DATA — off the parsed file — rather than
 * through `bot/lib/moderation.mjs`'s validator, and that is deliberate now
 * rather than provisional: this canary has to keep judging a log whose entries
 * do not pass their own schema, because an unreadable entry is one of the
 * things it reports. The cost is that a typo'd action name reads as "no
 * relist", which is the safe direction — it leaves the canary red.
 *
 * What changed with M-T1.6 is that `ACTIONS` now carries `relist`, so the two
 * spellings can be COMPARED instead of merely coexisting. `actionVocabulary`
 * below is that comparison, and it is why this comment no longer says "which
 * does not carry it yet" — a sentence that was true when it was written and
 * would have gone on reading as true for as long as nobody checked.
 */
/**
 * The action names this file spells out, against the ones the log's validator
 * will accept.
 *
 * Three literals in this file decide what it can see — `delist`, `relist` and
 * `yank` — and none of them is checked against anything today. Rename one in
 * `bot/lib/moderation.mjs` and the rules here stop matching: every delisted
 * plugin reads as unlogged, which is loud, or every relist reads as absent,
 * which is quiet and leaves the canary red about plugins that are fine. The
 * second is the one worth a check, because a canary that is red for a reason
 * nobody can find is a canary somebody switches off.
 *
 * @returns {string[]} the names this file uses that `ACTIONS` does not have
 */
export function actionVocabulary(actions = ACTIONS) {
  return ["delist", "relist", "yank"].filter((a) => !actions.includes(a));
}

function delistCovered(entries, pluginId) {
  const mine = entries.filter((e) => e.plugin === pluginId && (e.action === "delist" || e.action === "relist"));
  const last = mine[mine.length - 1];
  return last?.action === "delist";
}

function yankCovered(entries, authorActions, pluginId, version) {
  const logged = entries.some((e) =>
    e.plugin === pluginId && e.action === "yank"
    && (!Array.isArray(e.versions) || e.versions.length === 0 || e.versions.includes(version)));
  const byAuthor = authorActions.some((a) => a.plugin_id === pluginId && (a.version === undefined || a.version === version));
  return logged || byAuthor;
}

/** @returns {{codes: string[], ids: string[], detail: string[]}} */
export function stateMode(repo, { unlistedFloor = UNLISTED_FLOOR } = {}) {
  const codes = [];
  const ids = [];
  const detail = [];
  const { entries, bad } = loadLog(repo);
  for (const why of bad) { codes.push("MOD_ENTRY_UNREADABLE"); detail.push(why); }

  const strangers = actionVocabulary();
  if (strangers.length) {
    codes.push("MOD_ACTION_VOCABULARY");
    detail.push(
      `this file matches on the action name(s) ${strangers.join(", ")}, and bot/lib/moderation.mjs's ACTIONS no ` +
      "longer has them. Every rule below matches on a literal, so a renamed action makes them match nothing — " +
      "which reads as coverage rather than as a broken rule",
    );
  }

  const authorActions = loadAuthorActions(repo);
  const staging = stagingListingId(repo);
  const pluginsDir = path.join(repo, "plugins");
  const listings = fs.existsSync(pluginsDir)
    ? fs.readdirSync(pluginsDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort()
    : [];

  const unlisted = [];
  const yanked = [];
  for (const id of listings) {
    const { value: plugin } = readJsonFile(path.join(pluginsDir, id, "plugin.json"));
    if (plugin?.unlisted === true) unlisted.push(id);
    const versionsDir = path.join(pluginsDir, id, "versions");
    if (!fs.existsSync(versionsDir)) continue;
    for (const name of fs.readdirSync(versionsDir).filter((n) => n.endsWith(".json")).sort()) {
      const { value } = readJsonFile(path.join(versionsDir, name));
      if (value?.yanked === true) yanked.push({ id, version: name.replace(/\.json$/, "") });
    }
  }

  // The floor, before the loops it guards. A `plugins/` that has moved, a
  // readdir that throws into an empty array, a filter whose predicate stopped
  // matching: every rule below is then green over nothing.
  if (unlisted.length < unlistedFloor) {
    codes.push("MOD_FLOOR_UNLISTED");
    detail.push(
      `the walk of plugins/*/plugin.json found ${unlisted.length} unlisted listing(s) and there were ` +
      `${unlistedFloor} on 2026-09-19; this is a broken walk, not a smaller catalogue, and every rule ` +
      `below it would have passed`,
    );
  }

  for (const id of unlisted) {
    if (staging && id === staging) {
      detail.push(`${id} is policy/reserved-ids.json's staging_listing_id, which is created unlisted (MOD-16)`);
      continue;
    }
    if (delistCovered(entries, id)) continue;
    codes.push("MOD_UNLISTED_UNLOGGED");
    ids.push(id);
    detail.push(
      `plugins/${id}/plugin.json is unlisted and bot/moderation/ holds no delist entry for it that a later ` +
      `relist has not undone`,
    );
  }

  for (const { id, version } of yanked) {
    if (yankCovered(entries, authorActions, id, version)) continue;
    codes.push("MOD_YANKED_UNLOGGED");
    ids.push(id);
    detail.push(
      `plugins/${id}/versions/${version}.json is yanked and neither a yank entry nor an author-action ` +
      `record (FLOW-79) covers it`,
    );
  }

  detail.push(
    `state: ${listings.length} listings, ${unlisted.length} unlisted, ${yanked.length} yanked version(s), ` +
    `${entries.length} log entr${entries.length === 1 ? "y" : "ies"}, ${authorActions.length} author-action record(s)`,
  );
  return { codes, ids, detail };
}

// ── commit mode ─────────────────────────────────────────────────────────────

/**
 * How `triggersOf` compares a commit: which paths it changed, what each held
 * before, and — for the two advisory triggers — whether the write or the
 * deletion is this commit's own. The default is the first parent, which is
 * what every caller but the merge walk asks for; `bot/lib/takedown-bound.mjs`
 * walks the first-parent line and MEANS a merge's first-parent diff there
 * (when did the catalogue lose a plugin), so that default is not the merge
 * rule and must not become it.
 */
export function firstParentView(sha, repo) {
  const parent = firstParent(sha, repo);
  return {
    changes: changedPaths(sha, repo),
    before: (p) => (parent ? jsonAt(parent, p, repo) : { present: false, value: null }),
    ownWrite: () => true,
    ownDeletion: () => true,
  };
}

/**
 * The same questions asked of what a merge's resolution did itself (gap 93).
 *
 * `changes` is `mergeOwnChanges`: the tree the merge recorded against the one
 * git would have written for its two parents. Where git wrote that file
 * cleanly, "before" is git's version, so a resolution that quietly undoes one
 * side — re-delisting what `main` relisted, deleting a log entry `main` added
 * — is judged against what it undid. Where git could not (a conflict), the
 * remerged file is conflict markers and has no "before" to read, so the
 * parents answer instead, and a flag or a byte-for-byte copy some parent
 * already had is that side's act, judged on that side's commit, not the
 * merge's a second time.
 *
 * The log's append-only refusals take no such allowance: a conflicted record
 * the resolution changed is a record that was edited, whichever side's bytes
 * it ended up with, because both sides' versions existed.
 */
export function mergeView(sha, repo, own = mergeOwnChanges(sha, repo)) {
  const { tree, parents, conflicted, changes } = own;
  return {
    changes,
    before(p, flag) {
      if (!conflicted.has(p)) return jsonAt(tree, p, repo);
      const seen = parents.map((q) => jsonAt(q, p, repo)).filter((x) => x.present);
      if (!seen.length) return { present: false, value: null };
      return seen.find((x) => x.value?.[flag] === true) ?? seen[0];
    },
    ownWrite(p) {
      if (!conflicted.has(p)) return true;
      const now = blobAt(sha, p, repo);
      return !parents.some((q) => blobAt(q, p, repo) === now);
    },
    ownDeletion(p) {
      if (!conflicted.has(p)) return true;
      return parents.every((q) => blobAt(q, p, repo) !== null);
    },
  };
}

/**
 * What one commit did that owes a record.
 *
 * "Turns `unlisted` on for an EXISTING listing" is the plan's wording and it
 * matters: a listing created unlisted is not a delist, it is a listing that was
 * never listed, which is what MOD-16's staging id is and what an operator does
 * when they land a plugin they are not ready to serve. Reading the parent's
 * copy of the file is the only way to tell those apart, and a rule that could
 * not would have made every new unlisted listing look like an unlogged
 * takedown.
 */
export function triggersOf(sha, repo, view = firstParentView(sha, repo)) {
  const triggers = [];
  const refusals = [];
  for (const { status, path: p } of view.changes) {
    if (LOG_ENTRY_RE.test(p) && (status === "M" || status === "D")) {
      refusals.push({ kind: "log-entry-edited", path: p, status });
      continue;
    }
    if (NOTICE_MARKER_RE.test(p) && status === "M") continue;
    if (LOG_TREE_RE.test(p) && (status === "M" || status === "D")) {
      refusals.push({ kind: "log-tree-edited", path: p, status });
      continue;
    }
    if (ADVISORY_RE.test(p)) {
      const advisory = path.basename(p, ".json");
      if (!(status === "D" ? view.ownDeletion(p) : view.ownWrite(p))) continue;
      triggers.push({ kind: status === "D" ? "advisory-deleted" : "advisory-written", advisory, path: p });
      continue;
    }
    const mPlugin = PLUGIN_JSON_RE.exec(p);
    if (mPlugin && status !== "D") {
      const id = mPlugin[1];
      const now = jsonAt(sha, p, repo).value;
      if (now?.unlisted !== true) continue;
      const before = view.before(p, "unlisted");
      if (!before.present) continue;            // created unlisted: never listed, never delisted
      if (before.value?.unlisted === true) continue; // already unlisted: this commit changed something else
      triggers.push({ kind: "delist", id, path: p });
      continue;
    }
    const mVersion = VERSION_JSON_RE.exec(p);
    if (mVersion && status !== "D") {
      const [, id, version] = mVersion;
      const now = jsonAt(sha, p, repo).value;
      if (now?.yanked !== true) continue;
      const before = view.before(p, "yanked");
      if (before.present && before.value?.yanked === true) continue;
      triggers.push({ kind: "yank", id, version, path: p });
      continue;
    }
    // M-T5.8 (MOD-44): a publisher record removed or narrowed. See
    // `badgeNarrowing` above for what counts, and `badgeWithdrawnCover` for
    // what covers it.
    const mPublisher = PUBLISHER_JSON_RE.exec(p);
    if (mPublisher) {
      if (status === "D" && !view.ownDeletion(p)) continue;
      if (status !== "D" && !view.ownWrite(p)) continue;
      const before = view.before(p, "tier");
      if (!before.present) continue; // a record created: a badge granted, not withdrawn
      const now = status === "D" ? null : jsonAt(sha, p, repo).value;
      const how = badgeNarrowing(before.value, now);
      if (how) triggers.push({ kind: "badge-narrowed", login: mPublisher[1], how, path: p });
    }
  }
  return { triggers, refusals };
}

/** The records a commit itself carries, which may cover its own triggers. */
function coversInCommit(sha, repo, changes = changedPaths(sha, repo)) {
  const added = { entries: [], authorActions: [] };
  for (const { status, path: p } of changes) {
    if (status !== "A") continue;
    if (LOG_ENTRY_RE.test(p)) {
      const { value } = jsonAt(sha, p, repo);
      if (value) added.entries.push(value);
    } else if (LOG_TREE_RE.test(p)) {
      const { value } = jsonAt(sha, p, repo);
      if (isAuthorAction(value)) added.authorActions.push(value);
    }
  }
  return added;
}

function triggerCovered(trigger, added) {
  const { entries, authorActions } = added;
  switch (trigger.kind) {
    case "delist":
      return entries.some((e) => e.action === "delist" && e.plugin === trigger.id);
    case "yank":
      return entries.some((e) => e.action === "yank" && e.plugin === trigger.id
          && (!Array.isArray(e.versions) || e.versions.length === 0 || e.versions.includes(trigger.version)))
        || authorActions.some((a) => a.plugin_id === trigger.id
          && (a.version === undefined || a.version === trigger.version));
    case "advisory-written":
      return entries.some((e) => e.advisory === trigger.advisory);
    case "advisory-deleted":
      // The one trigger with a narrower cover than the others. A deletion
      // removes a signed statement from the withdrawal list, and "somebody
      // added a log entry in the same commit" is not the record that makes
      // that legible — `reverses` naming the advisory is (M-T1.6's field).
      return entries.some((e) => e.reverses === trigger.advisory);
    default:
      return false;
  }
}

const describe = (t) => ({
  "badge-narrowed": () => `${t.how} in ${t.path} (a badge withdrawn)`,
  delist: () => `delisted ${t.id}`,
  yank: () => `yanked ${t.id}@${t.version}`,
  "advisory-written": () => `wrote advisory ${t.advisory}`,
  "advisory-deleted": () => `deleted advisory ${t.advisory}`,
}[t.kind] ?? (() => t.kind))();

/**
 * Does a later retro log entry match this trigger?
 *
 * MOD-46's second clearing path: the operator writes the entry that was owed,
 * dated whenever it actually happened, and the canary goes green because the
 * transparency log is now true — which is a better outcome than an exemption
 * and is why it is a path at all.
 */
function retroCovers(trigger, entries, authorActions) {
  switch (trigger.kind) {
    case "delist": return entries.some((e) => e.action === "delist" && e.plugin === trigger.id);
    case "yank":
      return entries.some((e) => e.action === "yank" && e.plugin === trigger.id)
        || authorActions.some((a) => a.plugin_id === trigger.id);
    case "advisory-written": return entries.some((e) => e.advisory === trigger.advisory);
    case "advisory-deleted": return entries.some((e) => e.reverses === trigger.advisory);
    default: return false;
  }
}

export function commitMode(repo, { historyFloor = HISTORY_FLOOR, from, badgeFrom } = {}) {
  const codes = [];
  const ids = [];
  const hexes = [];
  const detail = [];

  if (isShallow(repo)) {
    codes.push("MOD_SHALLOW_CHECKOUT");
    detail.push(
      "this checkout is shallow, so the walk can see only the commits that were fetched; the job that runs " +
      "this rule needs `fetch-depth: 0` and a rule that walked a shallow history would be green about the " +
      "commits it never saw",
    );
    return { codes, ids, hexes, detail };
  }
  const reachable = historyCount(repo);
  if (reachable < historyFloor) {
    codes.push("MOD_HISTORY_FLOOR");
    detail.push(
      `git rev-list --count HEAD is ${reachable} and there were ${historyFloor} on 2026-09-19; history here ` +
      "only grows, so this is a truncated checkout or a rewritten history and not a smaller repository",
    );
    return { codes, ids, hexes, detail };
  }

  const start = from ?? introducingCommit(SELF_PATH, repo);
  if (!start) {
    codes.push("MOD_NO_INTRODUCING_COMMIT");
    detail.push(
      `git knows no commit that added ${SELF_PATH}, so the walk has no start and judged nothing; this is ` +
      "what an uncommitted working copy looks like, and what a path renamed without this constant looks like",
    );
    return { codes, ids, hexes, detail };
  }

  const shas = commitsAfter(start, repo);
  const merges = mergesAfter(start, repo);

  // M-T5.8's own start, which is later than the walk's: its commits are the
  // ones after the commit that introduced the rule, merges included.
  const badgeStart = badgeFrom ?? badgeRuleStart(repo);
  const badgeJudged = new Set(badgeStart ? [...commitsAfter(badgeStart, repo), ...mergesAfter(badgeStart, repo)] : []);
  if (!badgeStart) {
    codes.push("MOD_BADGE_RULE_NO_START");
    detail.push(
      `git knows no commit in which ${SELF_PATH} carries ${JSON.stringify(BADGE_RULE_TOKEN)}, so M-T5.8's ` +
      "badge-withdrawal rule has no start and judged nothing; an uncommitted working copy looks like this, and so " +
      "does a token renamed without its history",
    );
  }
  const uncovered = [];
  const cleared = new Set();
  const refusalsFound = [];
  let mergesWithOwnChanges = 0;

  const judge = (sha, view) => {
    const meta = commitMeta(sha, repo);
    const exempts = exemptions(meta.message);
    const selfExempt = exempts.some((e) => e.sha === null);
    for (const e of exempts) if (e.sha) cleared.add(e.sha);
    if (view === null) {
      if (!selfExempt) refusalsFound.push({ sha, kind: "merge-not-judged", path: null, status: null });
      return;
    }

    const { triggers, refusals } = triggersOf(sha, repo, view);
    const added = coversInCommit(sha, repo, view.changes);

    for (const r of refusals) {
      if (selfExempt) continue;
      refusalsFound.push({ sha, ...r });
    }
    for (const t of triggers) {
      if (selfExempt) continue;
      if (t.kind === "badge-narrowed") {
        if (!badgeJudged.has(sha)) continue;
        const cover = badgeWithdrawnCover(meta.message);
        if (cover.covered) continue;
        uncovered.push({ sha, subject: meta.message.split("\n")[0], trigger: { ...t, refused: cover.refused } });
        continue;
      }
      if (triggerCovered(t, added)) continue;
      uncovered.push({ sha, subject: meta.message.split("\n")[0], trigger: t });
    }
  };

  for (const sha of shas) judge(sha, firstParentView(sha, repo));

  // Gap 93. `commitsAfter` leaves merges out, which is right for "who wrote
  // this change" and made a merge's own resolution invisible: a delist typed
  // while resolving a conflict was 0 triggers across the walk. This mode asks
  // who did it, and a merge's committer did that — so a merge is judged on
  // what its resolution changed (`mergeView`), with its own message read for
  // `Moderation-Exempt:` like any commit's, and never on its first-parent
  // diff, which would judge every branch commit twice.
  for (const sha of merges) {
    const own = mergeOwnChanges(sha, repo);
    if (own.judged && own.changes.length) mergesWithOwnChanges++;
    judge(sha, own.judged ? mergeView(sha, repo, own) : null);
  }

  // Clearing, after the walk rather than during it: a `Moderation-Exempt:
  // <sha>:` may name a commit the walk has not reached yet only in the sense
  // that it is LATER in history, which cannot happen — but it may also be
  // written by a commit the walk reached after the uncovered one, which is the
  // ordinary case and the reason this is a second pass and not an `if` inside
  // the first.
  const { entries } = loadLog(repo);
  const authorActions = loadAuthorActions(repo);
  const clearedBy = (sha) => [...cleared].some((prefix) => sha.startsWith(prefix));

  for (const u of uncovered) {
    if (clearedBy(u.sha)) continue;
    if (u.trigger.kind === "badge-narrowed") {
      // No retro cover: the notice MOD-44 sends is keyed on THIS commit's
      // trailer, so an entry written later informs nobody. Cleared only by a
      // `Moderation-Exempt: <sha>: …` naming it, like every other trigger.
      codes.push(u.trigger.refused.length ? "MOD_BADGE_REASON_REFUSED" : "MOD_BADGE_UNCOVERED");
      hexes.push(u.sha);
      detail.push(
        `${u.sha.slice(0, 12)} ${describe(u.trigger)} and ` +
        (u.trigger.refused.length
          ? `its \`Badge-Withdrawn:\` reason is refused by MOD-41 (${u.trigger.refused.join(", ")}), so the ` +
            "notice the plugins service sends from it would carry text that must never reach a reader"
          : "carries no `Badge-Withdrawn: <reason>` and no `Moderation-Exempt:`; MOD-44's notice to the covered " +
            "listings' bound accounts is keyed on that trailer, so nobody is told") +
        ". A lapse carries `Moderation-Exempt: publisher-recheck: …` instead",
      );
      continue;
    }
    if (retroCovers(u.trigger, entries, authorActions)) continue;
    codes.push("MOD_COMMIT_UNCOVERED");
    hexes.push(u.sha);
    if (u.trigger.id) ids.push(u.trigger.id);
    detail.push(
      `${u.sha.slice(0, 12)} ${describe(u.trigger)} and carries no log entry, no author-action record and ` +
      "no `Moderation-Exempt:` trailer",
    );
  }
  for (const r of refusalsFound) {
    if (clearedBy(r.sha)) continue;
    if (r.kind === "merge-not-judged") {
      codes.push("MOD_MERGE_NOT_JUDGED");
      hexes.push(r.sha);
      detail.push(
        `${r.sha.slice(0, 12)} is a merge of more than two parents, which has no two-sided remerge, so what its ` +
        "own resolution changed was not judged; a merge this walk could not read is not a clean one",
      );
      continue;
    }
    codes.push(r.kind === "log-entry-edited" ? "MOD_LOG_ENTRY_EDITED" : "MOD_LOG_APPEND_ONLY");
    hexes.push(r.sha);
    detail.push(
      `${r.sha.slice(0, 12)} ${r.status === "D" ? "deleted" : "changed"} ${r.path}, which MOD-34 makes ` +
      "append-only; a record that can be edited into agreement with the tree is not a record",
    );
  }

  detail.push(
    `walk: ${shas.length} commit(s) after ${start.slice(0, 12)} (the commit that added ${SELF_PATH}), ` +
    `${reachable} reachable, ${cleared.size} exemption(s) naming a SHA`,
  );
  detail.push(
    `merges: ${merges.length} merge(s) in range, ${mergesWithOwnChanges} whose own resolution changed a path`,
  );
  if (badgeStart) {
    detail.push(`badges (M-T5.8): ${badgeJudged.size} commit(s) after ${badgeStart.slice(0, 12)}, the rule's own start`);
  }
  return { codes, ids, hexes, detail };
}

// ── the verdict ─────────────────────────────────────────────────────────────

export function run(repo, { mode = "both", historyFloor, unlistedFloor, from, badgeFrom } = {}) {
  const codes = [];
  const ids = [];
  const hexes = [];
  const detail = [];
  if (mode === "state" || mode === "both") {
    const r = stateMode(repo, { unlistedFloor });
    codes.push(...r.codes); ids.push(...r.ids); detail.push(...r.detail);
  }
  if (mode === "commits" || mode === "both") {
    const r = commitMode(repo, { historyFloor, from, badgeFrom });
    codes.push(...r.codes); ids.push(...r.ids); hexes.push(...r.hexes); detail.push(...r.detail);
  }
  // The five delists OPEN-OWNER-21 closed with retro entries are M-T1.4's, and
  // this canary is M-T1.4's own Check: "red without these files and green with
  // them". Saying so in the finding is the difference between the next reader
  // writing five JSON files and the next reader deciding the rule is too
  // strict.
  if (codes.includes("MOD_UNLISTED_UNLOGGED")) {
    detail.push(
      "if these are the August 2026 delists — echo-stt, mock-stt, tone-tts, web-chat, knice-chess — the " +
      "repair is M-T1.4's five retro entries in bot/moderation/, whose reason texts the owner confirms; " +
      "it is not a change to this rule",
    );
  }
  return { status: codes.length ? "red" : "green", codes, ids, hexes, detail };
}

function parseArgs(argv) {
  const args = { repo: DEFAULT_REPO, mode: "both", report: process.env.ASTRA_COVERAGE_FINDINGS };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--repo") args.repo = path.resolve(argv[++i]);
    else if (a === "--mode") args.mode = argv[++i];
    else if (a === "--report") args.report = argv[++i];
    else if (a === "--from") args.from = argv[++i];
    else if (a === "--history-floor") args.historyFloor = Number(argv[++i]);
    else if (a === "--unlisted-floor") args.unlistedFloor = Number(argv[++i]);
    else { console.error(`FAIL  unknown argument ${JSON.stringify(a)}`); return null; }
  }
  if (!["state", "commits", "both"].includes(args.mode)) {
    console.error(`FAIL  --mode must be state, commits or both, not ${JSON.stringify(args.mode)}`);
    return null;
  }
  return args;
}

function main(argv) {
  const args = parseArgs(argv);
  if (!args) return 2;
  const finding = run(args.repo, args);
  report(RULE, finding, args.report);
  // Exit 0 on a red finding. The line in the findings file is the signal, and
  // `tools/coverage-verdict.mjs` is the one thing that decides what a red rule
  // does to the job — because a rule that failed its own step and a rule that
  // never ran are indistinguishable from outside, and telling those two apart
  // is the whole reason the findings file exists.
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
