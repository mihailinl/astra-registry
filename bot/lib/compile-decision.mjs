// The decision compiler: one service decision in, the artefacts it becomes out.
//
// Registry plan M-T3.1 (BOT-31, BOT-34, FLOW-79, MOD-3, MOD-4, MOD-10, MOD-19,
// MOD-32, MOD-33, MOD-34, MOD-41, MIG-27, MIG-30, TRUST-26, DEC-13, DEC-14,
// PRIV-2). At R2 exit this is DARK: nothing imports it. `bot/moderation-run.mjs`
// (M-T3.4) is the first caller, and its `commit` job is what turns the return
// value into one commit.
//
// ── IT IS A PURE FUNCTION, AND WHAT THAT BUYS ───────────────────────────────
//
// In: one entry already checked against M-T3.4's schema, and the `main` tree.
// Out: edits, log entries, advisories and decision records — or one of §0.8's
// seven service-decision refusal codes, or a MOD-9 hold kind. It writes
// nothing, commits nothing, posts nothing and reaches no network.
//
// That is not tidiness. A takedown is the one act in this estate that cannot be
// rehearsed in production: the first real `M_REVOKE` with `disable` stops
// software on somebody's machine, and there is no staging catalogue that
// installed copies poll. So the compile has to be exercisable against fixture
// trees, hundreds of times, before it is exercised once for real — and a
// function that committed as it went could only be tested by letting it commit.
//
// ── WHAT IT READS, AND WHAT IT REFUSES TO READ ──────────────────────────────
//
// Reads: `plugins/<id>/plugin.json` and `plugins/<id>/versions/*.json` (MOD-4's
// digests, the listed set, the containment check), `plugins/<id>/identity.json`
// (whether the listing is BOUND, and the three repository members DEC-7's
// author-action record carries), `tools/revocations/**` through git history
// (MOD-13's next advisory id) and through the tree (MOD-10's
// `relist_under_advisory`), `bot/moderation/` (MOD-47's `-<n>` suffix),
// `log/cutover.json` (the appeal-link deadline) and
// `schema/contract-tokens-v1.json` (SCOPE-7's fixed `A_*` reason strings).
//
// Does not read: the decision's payload, for anything but `severity`, `action`
// and the moderator's public reason. MOD-4 states that as a rule and the reason
// is DEC-11: the payload is the service's word about the registry's own tree,
// and a digest taken from it is a digest nobody in this repository can check.
// The mechanism is `ENTRY_ALLOWLIST` below — the entry is copied member by
// member into a decision object, so a member the schema ignored on the read
// side (SCOPE-3: readers ignore unknown members) cannot ride into git on the
// write side. That split is M-T3.4's attack M-1, and this is its write half.
//
// ── SEVEN REFUSALS, AND WHY THE ORDER IS PART OF THE ANSWER ─────────────────
//
// A refusal is FINAL: BOT-81 makes `refused` one of the three final results, so
// a decision refused here is settled, leaves BOT-80's list, pages nobody
// (BOT-84 pages only for a decision with NO settled result), and reaches a
// moderator as "the takedown did not land" with no further stage. That is the
// failure M-T3.4's attack M-1 walks in full, and it is why nothing below
// refuses for a condition that is merely unknown: an unreadable tree, an
// unpublished fixed reason or a code this file has not been taught THROWS, and
// a thrown error fails the run loudly, which is the direction a compiler that
// does not know must take.
//
// Refusals are checked BEFORE the MOD-9 hold, and that order is load-bearing.
// A `M_RELIST` under a signed advisory is refused rather than held: holding it
// would put an entry in `state/holds/` waiting for an operator to confirm
// something that can never be applied, and M-T3.3's release commit applies a
// held decision FROM THE ENTRY without re-asking this file.
//
// ── THE TWO YANKS ARE NOT SYMMETRIC, AND THAT IS DELIBERATE ─────────────────
//
// `A_YANK`: any named version that is not listed, or is already yanked, makes
// the whole decision `target_changed`. FLOW-79 makes that case the SERVICE's
// own `plugin_not_listed` refusal at the served `Source-Commit`, so one
// reaching the bot means the tree moved under the service between its read and
// this run — and a partial apply would yank versions the author asked about
// under a decision the service believes was about others.
//
// `M_YANK`: the versions that can move, move; `target_changed` only when none
// can. §0.8 gives the service no pre-filter for a moderator's yank, so a
// moderator naming a set where one version was already yanked is ordinary, and
// refusing the lot would stall a takedown — the one class of failure contract
// §7 calls unsafe, because only a withdrawal reaches a machine that already has
// the plugin on it.
//
// ── WHAT THIS FILE DOES NOT COMPILE, WRITTEN DOWN RATHER THAN DISCOVERED ────
//
//   * `M_RELIST` and `M_UNREVOKE` have no compile branch. MOD-9 holds both
//     unconditionally, and M-T3.3's release commit "applies the held decision
//     from the hold entry" — so the plan puts the apply there and M-T3.1's own
//     "Compiles" list names neither. What IS here is their three refusals,
//     which must run before the hold.
//   * MOD-33's decision record for an appealed refusal. The log entry is
//     composed; the record is not, and it CANNOT be today: BOT-35 has four key
//     domains and none of them is an appeal. `submission:<submission_id>` — the
//     only one an appeal of a submission refusal could use — derives the id the
//     REFUSAL's own record already has, so the write would collide with it and
//     BOT-36's dedupe would drop it. `appealRecordOwed` below reports that as a
//     named gap instead of inventing a fifth domain, which `bot/lib/decisions.mjs`
//     says in its own words is a contract amendment and not an argument.

import fs from "node:fs";
import path from "node:path";

import { composeAuthorActions } from "./decisions.mjs";
import { holdKindFor } from "./holds.mjs";
import {
  CATEGORIES,
  checkEntry,
  cutoverAt,
  fileNameFor,
  loadEntries,
  reasonProblems,
  SOURCE_DIR as MODERATION_DIR,
  suffixOf,
} from "./moderation.mjs";
import { git } from "../../tools/coverage/git.mjs";
import { isTimeWithFraction } from "../../tools/lib/time.mjs";
import { ID_PATTERN } from "../../tools/lib/ids.mjs";
import {
  ACTIONS as ADVISORY_ACTIONS,
  ADVISORY_FILE,
  ADVISORY_URL_BASE,
  SEVERITIES,
  SOURCE_DIR as REVOCATIONS_DIR,
  checkAdvisory,
  loadAdvisories,
} from "../../tools/lib/revocations.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { compareSemver, parseSemver } from "../../tools/lib/semver.mjs";

const ID_RE = new RegExp(ID_PATTERN);

/** SCOPE-7's token file, the one artifact carrying the fixed `A_*` reasons. */
export const TOKEN_FILE = "schema/contract-tokens-v1.json";

/**
 * §0.8's service-decision refusal codes. Seven, and there is no eighth.
 *
 * BOT-82 makes the service accept a well-formed code it does not know, record
 * it verbatim and alarm — which is the SERVICE's safety net against a registry
 * that ships a new code before the service's pinned token file has it. It is
 * not a licence to invent one here: a code outside this list reaches a
 * moderator as "unrecognised" and tells them nothing about what to do.
 */
export const REFUSALS = Object.freeze([
  "target_not_in_registry",
  "kind_refused",
  "relist_under_advisory",
  "relist_unbound",
  "relist_contained",
  "reason_refused",
  "target_changed",
]);

/**
 * The advisory kinds this compiler emits, and the two halves of why.
 *
 * TRUST-26 permits the bot to compile a service decision "into advisories with
 * action `warn`, `block_install` or `disable` and kind `digest`, `id`,
 * `id_version` or `version_range` … or `github:` `identity` entries (registry
 * plan: MOD-19)". So the set is FOUR withdrawal kinds plus `identity`, and
 * `identity` only under MOD-19's account-level rule, only with a `github:`
 * value, and never with `origin:` — which this registry could not resolve to a
 * listing anyway (`bot/lib/takedown-bound.mjs` measured that: no listing
 * records an origin host).
 *
 * `publisher_key` and `binary` are the two `tools/lib/revocations.mjs` accepts
 * and this file never emits. Both are keyed on something that lives on a user's
 * machine — a signer key id, the sha256 of a resolved `entry.command` — so the
 * registry cannot derive either from git, and MOD-4's whole rule is that an
 * advisory entry is derived from git and never from a decision's payload.
 *
 * RC-R1-6's "Advisory kinds" couplings row is what keeps this set and the
 * daemon's `RevocationKind` in step (AV-7): a kind the daemon cannot parse is a
 * withdrawal that does not happen.
 */
export const ADVISORY_KINDS = Object.freeze(["digest", "id", "id_version", "version_range"]);

/** The one kind MOD-19 adds, for an account-level decision, and its one prefix. */
export const IDENTITY_KIND = "identity";
export const IDENTITY_PREFIX = "github:";

/**
 * MOD-13's advisory page base, compiled onto every advisory this file writes.
 *
 * Declared here AND published in the token file as `page:MOD-13-advisory-base`,
 * and `bot/tests/compile-decision.test.mjs` compares them. Two copies with a
 * comparison between them is a different thing from two copies: the daemon
 * prints this URL in a signed notice, so a base that drifts from the page the
 * service serves is a signed link to a 404 on the one document a user reads
 * when something has already gone wrong.
 */
// Imported from `tools/lib/revocations.mjs`, whose `checkAdvisory` refuses any
// other value since M-T3.9, and re-exported so its readers here keep one name.
// A second literal would be a second base, and the gate that runs before the
// commit job's push would refuse every advisory compiled from it.
export { ADVISORY_URL_BASE };

/**
 * §7.2's two account-level categories, which are the only ones MOD-19's
 * `github:` identity entries may ride on (DEC-13: account-level moderation
 * compiles only into per-listing artefacts, never naming an account).
 *
 * `account_sanction` is in PRIV-2's permitted list by name — "each decision's
 * public category, `account_sanction` included, which ties a sanction to a
 * listing's public GitHub owner and never to a Minice account". An identity
 * entry under any other category would be reaching sibling listings for a
 * reason that was not about the account.
 */
export const ACCOUNT_LEVEL_CATEGORIES = Object.freeze(["account_compromise", "account_sanction"]);

/**
 * MIG-30's contained owner, case-folded.
 *
 * `KNICE-TECH` is a login the organisation freed when it renamed itself
 * MINICE-AI, which means anybody may register it. `policy/reserved-ids.json`
 * carries the one repository under it that still has to validate
 * (`KNICE-TECH/astra-chess`, frozen and unlisted) and says in its own note why
 * the OWNER is deliberately not in `first_party_owners`. The literal is here
 * rather than read out of that file because the two say different things: that
 * file says which repository names may list under a reserved prefix, and this
 * says which owner no relist may put back into the catalogue.
 */
export const CONTAINED_OWNERS = Object.freeze(["knice-tech"]);

/**
 * MIG-25's one exception to MIG-27, by id.
 *
 * MIG-27 refuses `relist_unbound` for a plugin with no bound release "except
 * astra-chess under MIG-25 before cutover". The exception is not a way to
 * relist astra-chess: it is what lets the decision fall through to
 * `relist_contained`, which is the refusal that actually describes why it
 * cannot come back. Without it the moderator is told "no bound release", fixes
 * that, and is refused again for the reason nobody mentioned.
 */
export const MIG25_UNBOUND_EXCEPTION = "astra-chess";

/**
 * BOT-80's members, per kind, as an ALLOWLIST.
 *
 * SCOPE-3 binds the read side — "within `/n` only optional members are added
 * and readers ignore unknown ones" — so M-T3.4's schema validates what it names
 * and ignores the rest. DEC-7 binds the write side, and this is it: the entry
 * is copied through here before anything is composed from it, so an optional
 * member minice-be adds in a MINOR reaches this compiler, is ignored, and
 * reaches no committed file.
 *
 * `moderator` and `declared_interest` are on the `M_*` list and off the `A_*`
 * one, which is n4: no moderator decided an author action, and 0.12.0's wording
 * would have let a moderator handle ride onto an author's yank and into the
 * public log (DEC-14; PRIV-2).
 */
export const ENTRY_ALLOWLIST = Object.freeze({
  moderator: Object.freeze([
    "service_decision_id", "code", "category", "plugin_id", "versions", "decided_at",
    "reason", "reverses", "appeal_of", "outcome", "severity", "action",
    "moderator", "declared_interest",
  ]),
  author: Object.freeze([
    "service_decision_id", "code", "category", "plugin_id", "versions", "decided_at", "reason",
  ]),
});

/**
 * BOT-80's THIRD kind, which is not a service decision and does not come
 * through `compileDecision` at all.
 *
 * A stop or an `M_REJECT` arrives in the answer's `submissions[]`, removes the
 * queue entry and gets the terminal record (BOT-30), so M-T3.4's `commit` job
 * composes it directly rather than through the switch below. That is exactly
 * why the allowlist belongs HERE and not in the run: the rule M-1 states is
 * "`bot/lib/compile-decision.mjs` **and the record composers** take their
 * inputs from an allowlist", and a third entry kind whose composer took the
 * service's object whole would be the same hole in a place nobody was looking,
 * because the two lists above would still read as complete.
 *
 * The `M_REJECT` row is the longer one: `category`, `moderator`, `decided_at`
 * and `declared_interest` are a moderator's, and a STOP has none of them — a
 * stop is the author's own act through the panel, so a stop entry that arrived
 * carrying a moderator handle would put one into a terminal record under an
 * act no moderator made. That is the same failure n4 names for `A_*`, one
 * record shape over.
 */
export const SUBMISSION_ALLOWLIST = Object.freeze({
  stop: Object.freeze([
    "submission_id", "repo", "tag", "trigger", "service_repository_id",
    "stop_status", "fingerprints", "code",
  ]),
  reject: Object.freeze([
    "submission_id", "repo", "tag", "trigger", "service_repository_id",
    "stop_status", "fingerprints", "code",
    "category", "moderator", "decided_at", "declared_interest",
  ]),
});

/** The one submission code that is a moderator's decision rather than a stop. */
export const REJECT_CODE = "M_REJECT";

/** The author-action codes. Neither carries a moderator (BOT-80; n4). */
export const AUTHOR_CODES = Object.freeze(["A_REMOVAL_REQUEST", "A_YANK"]);

/**
 * Every code this file has an answer for, and what that answer is.
 *
 * A code outside this table THROWS rather than refusing `kind_refused`. The
 * distinction is the one the header draws: `kind_refused` says "the registry
 * read this decision and will not compile it", which is a final result a
 * moderator can act on; a code nobody taught this file is a registry that does
 * not know what it was asked, and settling that as a refusal is how a takedown
 * disappears quietly.
 */
const KNOWN_CODES = Object.freeze({
  M_YANK: "yank",
  M_DELIST: "delist",
  M_DEPRECATE: "advisory",
  M_REVOKE: "advisory",
  M_APPEAL: "appeal",
  M_RELIST: "reversal",
  M_UNREVOKE: "reversal",
  M_BINDING_REVOKE: "nothing",
  A_YANK: "yank",
  A_REMOVAL_REQUEST: "delist",
});

/**
 * §7.2's left column, keyed by code: which moderation-log action each becomes.
 *
 * `M_BINDING_REVOKE` is absent because it produces no log entry at all — §7.2's
 * "Git artefact" cell for it is "none" — so there is no action to check its
 * category against, and `CATEGORIES` has no row that would be the right one.
 * `M_APPEAL` maps to `appeal`, whose allowed-category list is deliberately
 * EMPTY: §7.2 gives one category per `M_*` decision except that one.
 */
const LOG_ACTION = Object.freeze({
  M_YANK: "yank",
  A_YANK: "yank",
  M_DELIST: "delist",
  A_REMOVAL_REQUEST: "delist",
  M_DEPRECATE: "deprecate",
  M_REVOKE: "revoke",
  M_RELIST: "relist",
  M_UNREVOKE: "unrevoke",
  M_APPEAL: "appeal",
});

// ── reading the tree ────────────────────────────────────────────────────────

const readJson = (file) => {
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return undefined; // present and unreadable: told apart from absent below
  }
};

const pluginDir = (root, id) => path.join(root, "plugins", id);

/**
 * One listing, as this compiler needs it. `null` when there is no directory,
 * which is TRUST-26's `target_not_in_registry`.
 */
function readListing(root, id) {
  const dir = pluginDir(root, id);
  if (!fs.existsSync(dir)) return null;

  const plugin = readJson(path.join(dir, "plugin.json"));
  if (plugin === undefined || plugin === null) {
    throw new Error(
      `plugins/${id}/plugin.json is missing or unreadable, so this run cannot say what the listing is. That is ` +
      "not a refusal: a decision refused here is settled for ever (BOT-81), and a tree this run could not read " +
      "is a fact about the run",
    );
  }
  const identity = readJson(path.join(dir, "identity.json"));
  if (identity === undefined) {
    throw new Error(`plugins/${id}/identity.json is present and unreadable, so "is this listing bound" has no answer`);
  }

  const versionsDir = path.join(dir, "versions");
  const versions = [];
  if (fs.existsSync(versionsDir)) {
    for (const name of fs.readdirSync(versionsDir).sort()) {
      if (!name.endsWith(".json")) continue;
      const version = name.slice(0, -".json".length);
      const doc = readJson(path.join(versionsDir, name));
      if (doc === undefined) throw new Error(`plugins/${id}/versions/${name} is unreadable`);
      versions.push({ version, doc });
    }
  }
  versions.sort((a, b) => compareSemver(a.version, b.version));

  return {
    id,
    plugin,
    identity,
    versions,
    listed: plugin.unlisted !== true,
    bound: identity !== null,
  };
}

/** Every `release.repo` in the listing's version records, and every historic `source.repo`. */
function historicRepos(root, listing) {
  const repos = new Set();
  const add = (v) => { if (typeof v === "string" && v.includes("/")) repos.add(v); };

  add(listing.plugin?.source?.repo);
  for (const { doc } of listing.versions) add(doc?.release?.repo);

  // MOD-19: "every distinct `source.repo` in the HISTORY of
  // `plugins/<id>/plugin.json`". The identity record holds only the last name,
  // and a pin keeps the install-time one — so a rename that this tree no longer
  // shows is still the name an installed copy was published under.
  const file = `plugins/${listing.id}/plugin.json`;
  const shas = git(["log", "--format=%H", "--", file], { cwd: root, allowFailure: true })
    .split("\n").map((s) => s.trim()).filter(Boolean);
  for (const sha of shas) {
    const blob = git(["show", `${sha}:${file}`], { cwd: root, allowFailure: true });
    if (!blob) continue;
    try { add(JSON.parse(blob)?.source?.repo); } catch { /* an unparsable ancestor names no repo */ }
  }
  return [...repos].sort();
}

/**
 * MOD-13's next advisory id: one more than the highest ever ADDED.
 *
 * `--diff-filter=A` and not the tree, and the canary is the reason: add
 * `ASTRA-2026-0001`, delete it, and a tree reading hands the next advisory the
 * same id. Two advisories with one id is a signed document in which the second
 * silently replaces the first in every reader that keys on it.
 *
 * The serial does not reset with the year. "One more than the highest ever
 * added" is what the plan says and what the canary asserts, and a per-year
 * reset would make `ASTRA-2027-0001` a second use of a number this registry has
 * already published under a different year — legible to a person, and not to a
 * reader that parses the four digits.
 */
export function nextAdvisoryId({ root = REPO_ROOT, year } = {}) {
  const out = git(
    ["log", "--diff-filter=A", "--name-only", "--format=", "--", `${REVOCATIONS_DIR}/`],
    { cwd: root, allowFailure: true },
  );
  let highest = 0;
  for (const line of out.split("\n")) {
    // `ADVISORY_FILE` is built from `REVOCATIONS_DIR`, the constant this log's
    // pathspec is built from, so the two cannot name different directories
    // (gap 72); its group 1 is the id, whose serial is everything after the
    // second hyphen — four digits or more, which is what this writes.
    const m = ADVISORY_FILE.exec(line.trim());
    if (!m) continue;
    const serial = Number(m[1].slice(m[1].lastIndexOf("-") + 1));
    if (Number.isSafeInteger(serial) && serial > highest) highest = serial;
  }
  const next = highest + 1;
  return `ASTRA-${year}-${String(next).padStart(4, "0")}`;
}

/**
 * SCOPE-7's fixed registry reason for an `A_*` code, out of the token file.
 *
 * `null` when the file carries `fixed_reasons: null`, which is where `main`
 * stands today: the token file's own `pending` record says the two strings land
 * with contract version ops.15, and §1.3 row 8.5 makes minice-be's half due at
 * R4a "before the first author yank".
 *
 * The caller must not turn that null into `reason_refused`. See
 * `compileDecision`: an unpublished string is a registry that does not yet know
 * what an author yank says, and settling every author yank as refused until
 * ops.15 lands would be indistinguishable, from the panel, from the service
 * having sent something wrong.
 */
export function fixedReason(code, { root = REPO_ROOT } = {}) {
  const file = path.join(root, TOKEN_FILE);
  const doc = readJson(file);
  if (doc === null) throw new Error(`${TOKEN_FILE} is not on this tree, and SCOPE-7 requires it on \`main\` before R2`);
  if (doc === undefined) throw new Error(`${TOKEN_FILE} is unreadable`);
  const fixed = doc.fixed_reasons;
  if (fixed === null || fixed === undefined) return null;
  const value = fixed[code];
  return typeof value === "string" && value.length ? value : null;
}

/** The token file's own statement of MOD-13's base, for the canary to compare. */
export function tokenAdvisoryBase({ root = REPO_ROOT } = {}) {
  const doc = readJson(path.join(root, TOKEN_FILE));
  if (!doc) return null;
  const entry = (doc.entries ?? []).find((e) => e?.id === "page:MOD-13-advisory-base");
  return typeof entry?.url === "string" ? entry.url : null;
}

// ── composing ───────────────────────────────────────────────────────────────

/**
 * §0.7's RFC 3339 UTC with whole seconds, from a `decided_at` that may carry a
 * fraction.
 *
 * TRUNCATED, never rounded. A record's PATH is derived from its `decided_at`
 * (`log/decisions/<YYYY>/<MM>/`), so a `…T23:59:59.7Z` rounded forward on the
 * last second of December files the record under the next year, where the
 * year's walk does not look for it and BOT-36's dedupe does not find it.
 */
export function wholeSeconds(at) {
  const text = String(at ?? "");
  // The grammar and the real-instant test are §0.7's, from tools/lib/time.mjs:
  // until contract 0.34.0 this admitted second 60, hour 24 and `2026-02-30`,
  // and filed the record under whatever month the string's digits said.
  if (!isTimeWithFraction(text)) throw new Error(`\`decided_at\` ${JSON.stringify(at)} is not §0.7's RFC 3339 UTC`);
  return `${text.slice(0, 19)}Z`;
}

/**
 * One object, copied member by member out of a named list.
 *
 * A COPY and not a filtered view, and the difference is the whole mechanism:
 * a `delete` over the service's own object leaves the caller holding that
 * object, and the next composer that takes it whole undoes the work. Nothing
 * downstream of this ever sees the wire object again.
 */
function copyThrough(source, members) {
  const out = {};
  for (const member of members) {
    if (Object.hasOwn(source ?? {}, member) && source[member] !== undefined) out[member] = source[member];
  }
  return out;
}

/** The entry, copied through BOT-80's allowlist for its kind. */
export function allowlisted(entry) {
  const code = entry?.code;
  const members = AUTHOR_CODES.includes(code) ? ENTRY_ALLOWLIST.author : ENTRY_ALLOWLIST.moderator;
  return copyThrough(entry, members);
}

/**
 * A `submissions[]` entry, copied through BOT-80's allowlist for a stop or an
 * `M_REJECT` (BOT-30).
 *
 * The discriminant is `code === "M_REJECT"` and not "does it carry a
 * moderator", which is the reading that would make the entry choose its own
 * allowlist: an entry arriving with a moderator handle would be read as a
 * rejection, widen its own list, and commit the handle. The code names the
 * kind; the kind names the members.
 */
export function allowlistedSubmission(entry) {
  const members = entry?.code === REJECT_CODE ? SUBMISSION_ALLOWLIST.reject : SUBMISSION_ALLOWLIST.stop;
  return copyThrough(entry, members);
}

/**
 * The name a new log entry takes, with MOD-47's `-<n>` for a second the same
 * day (M-T1.6).
 *
 * Counted over the entries already on the tree rather than over a number the
 * caller passes, because the caller would have to read the same directory to
 * produce one and two readings of a directory a moment apart is how two entries
 * claim `-2`.
 */
function logEntryFile(root, doc) {
  const { entries, files } = loadEntries({ root });
  // The suffixes actually TAKEN, read off the names, rather than a count of
  // matching entries. They are the same number while the directory is
  // contiguous and they are not the same fact: a hand-deleted `-2` leaves a
  // `-3` behind, and a count would hand the next entry `-2` and overwrite
  // nothing while two files claim one place in the log's ordering.
  const taken = new Set();
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.date !== doc.date || e.plugin !== doc.plugin || e.action !== doc.action) continue;
    const n = suffixOf(files[i], e);
    if (n !== null) taken.add(n);
  }
  let n = 1;
  while (taken.has(n)) n += 1;
  return `${MODERATION_DIR}/${fileNameFor(doc, n)}`;
}

/** A composed log entry, refused here if the directory would refuse it. */
function logEntry(root, doc) {
  const problems = checkEntry(doc, "<compiled>", { cutoverAt: cutoverAt(root) });
  if (problems.length) {
    throw new Error(
      `refusing to compile a moderation log entry the log would refuse: ${problems.join("; ")}. MOD-3 commits the ` +
      "artefact and its log entry together, so an entry that cannot be written is an artefact that must not be",
    );
  }
  return { file: logEntryFile(root, doc), doc };
}

/** `plugins/<id>/versions/<v>.json` gains `"yanked": true`. */
const yankEdit = (id, version) => ({
  op: "set", file: `plugins/${id}/versions/${version}.json`, member: "yanked", value: true,
});

/** `plugins/<id>/plugin.json` gains `"unlisted": true`. */
const unlistEdit = (id) => ({
  op: "set", file: `plugins/${id}/plugin.json`, member: "unlisted", value: true,
});

/**
 * MOD-4's advisory entries, derived from git and from nothing else.
 *
 * `digest`: `artifacts.<platform>.sha256`, `artifacts` being an OBJECT keyed by
 * platform (m11 corrected the plan's `artifacts[].sha256`), so a version built
 * for two platforms yields two digests. A version record with no `sha256` at
 * all yields none, which is why there is always a non-digest entry beside them.
 *
 * The non-digest entry, and the one reading this file has to choose:
 *
 *   * no versions named → `id`, the whole listing.
 *   * the named versions are exactly a contiguous run of this listing's version
 *     records with a record above them → one `version_range` `[introduced,
 *     fixed)`, which expresses that set and no more.
 *   * otherwise → one `id_version` per named version.
 *
 * The rule the fallback exists for is *never withdraw a version the decision
 * did not name*. A `version_range` with an open `fixed` covers everything above
 * `introduced`, including versions published after the advisory was signed, and
 * a moderator who named three versions did not ask for that. So the range is
 * used only when it is exact, and the exact-but-verbose form is used otherwise.
 * The plan says "an `id_version` or `version_range` entry" and does not say
 * which when; this is the reading, written down so the next reader meets it.
 */
function advisoryEntries(listing, versions) {
  const entries = [];
  const named = versions ?? [];

  for (const version of named) {
    const record = listing.versions.find((v) => v.version === version);
    for (const artifact of Object.values(record?.doc?.artifacts ?? {})) {
      if (typeof artifact?.sha256 === "string" && /^[0-9a-f]{64}$/.test(artifact.sha256)) {
        entries.push({ kind: "digest", value: artifact.sha256 });
      }
    }
  }

  if (named.length === 0) {
    entries.push({ kind: "id", value: listing.id });
    return entries;
  }

  const all = listing.versions.map((v) => v.version);
  const sorted = [...named].sort(compareSemver);
  const first = all.indexOf(sorted[0]);
  const contiguous = first >= 0
    && sorted.every((v, i) => all[first + i] === v)
    && all.length > first + sorted.length;

  if (contiguous) {
    entries.push({
      kind: "version_range",
      value: listing.id,
      versions: { introduced: sorted[0], fixed: all[first + sorted.length] },
    });
  } else {
    for (const version of sorted) entries.push({ kind: "id_version", value: `${listing.id}@${version}` });
  }
  return entries;
}

/** MOD-19's `github:` identity entries, for an account-level decision only. */
function identityEntries(root, listing) {
  return historicRepos(root, listing).map((repo) => ({
    kind: IDENTITY_KIND,
    value: `${IDENTITY_PREFIX}${repo}`,
  }));
}

// ── the compile ─────────────────────────────────────────────────────────────

const refuse = (d, code, why) => ({
  outcome: "refused",
  code: d.code,
  service_decision_id: d.service_decision_id,
  refusal: code,
  why,
  edits: [], log: [], advisories: [], records: [], alerts: [],
});

const held = (d, held_for, why) => ({
  outcome: "held",
  code: d.code,
  service_decision_id: d.service_decision_id,
  held_for,
  why,
  decision: d,
  edits: [], log: [], advisories: [], records: [],
  // MOD-8: every hold entered is alerted before the push.
  alerts: [{ kind: "hold", held_for, service_decision_id: d.service_decision_id, why }],
});

/**
 * Compile one service decision.
 *
 * @param {object} entry   one BOT-80 service-decision entry, already checked
 *                         against M-T3.4's schema.
 * @param {object} ctx
 * @param {string}  ctx.root        the `main` tree to read.
 * @param {boolean} ctx.overBound   TRUST-26's count is at or above the bound
 *                                  (M-T3.2 counts; this file only believes it).
 * @returns {{outcome: "compiled"|"refused"|"held", ...}}
 */
export function compileDecision(entry, { root = REPO_ROOT, overBound = false } = {}) {
  const d = allowlisted(entry);
  const code = d.code;

  // ── the three things that are a fault of the run, not of the decision ────
  if (typeof code !== "string" || !Object.hasOwn(KNOWN_CODES, code)) {
    throw new Error(
      `\`${code}\` is not a service-decision code this compiler has an answer for ` +
      `(${Object.keys(KNOWN_CODES).join(", ")}). Settling it as \`kind_refused\` would take it off BOT-80's list ` +
      "with a final result, and a moderator re-deciding would be refused again",
    );
  }
  if (typeof d.plugin_id !== "string" || !ID_RE.test(d.plugin_id)) {
    throw new Error(`\`plugin_id\` ${JSON.stringify(d.plugin_id)} is not a plugin id`);
  }
  const decidedAt = wholeSeconds(d.decided_at);
  const date = decidedAt.slice(0, 10);

  // ── kind_refused: what BOT-80's payload must carry, by code ──────────────
  if (AUTHOR_CODES.includes(code)) {
    for (const member of ["moderator", "declared_interest"]) {
      if (Object.hasOwn(entry ?? {}, member)) {
        return refuse(d, "kind_refused",
          `an \`${code}\` entry carries no \`${member}\`: no moderator decided an author action, and DEC-14 and ` +
          "MOD-41 forbid an author-typed reason reaching git (BOT-80; n4)");
      }
    }
  }
  if (code === "M_DEPRECATE" || code === "M_REVOKE") {
    if (!SEVERITIES.includes(d.severity)) {
      return refuse(d, "kind_refused",
        `an ${code} carries \`severity\` (${SEVERITIES.join(", ")}) and this one carries ` +
        `${JSON.stringify(d.severity)}; git holds no source for it, so an advisory cannot be derived (MOD-4; MOD-10)`);
    }
  }
  if (code === "M_REVOKE" && !["block_install", "disable"].includes(d.action)) {
    return refuse(d, "kind_refused",
      `an M_REVOKE carries \`action\` (block_install, disable) and this one carries ${JSON.stringify(d.action)} ` +
      "(MOD-10); tools/lib/revocations.mjs requires it and git holds no source for it");
  }

  // §7.2's category table, refused here rather than at the log. It is the same
  // rule `checkEntry` enforces, and the difference is what a moderator is told:
  // this returns `kind_refused`, which M-T3.4's `list` job already maps a bad
  // category to and which BOT-81 posts back as a final result they can act on.
  // Letting it reach `logEntry` instead would throw and fail the whole run for
  // one decision's category, taking every other decision in the batch with it.
  const logAction = LOG_ACTION[code];
  if (logAction && d.category !== undefined) {
    const allowed = CATEGORIES[logAction] ?? [];
    if (!allowed.includes(d.category)) {
      return refuse(d, "kind_refused",
        `category ${JSON.stringify(d.category)} is not one §7.2 allows with ${code}` +
        (allowed.length ? `: ${allowed.join(", ")}` : ", which carries none"));
    }
  }

  // ── reason_refused ───────────────────────────────────────────────────────
  //
  // Two rules, and the `A_*` one is a VALUE comparison. SCOPE-8 and SCOPE-9
  // compare member names and vocabularies, so without this the token file's
  // copy of the string and the one a log entry carries could diverge invisibly
  // (attack M-7). MOD-41's pattern set governs the moderator's own reason.
  let reason = d.reason;
  if (AUTHOR_CODES.includes(code)) {
    const fixed = fixedReason(code, { root });
    if (fixed === null) {
      throw new Error(
        `${TOKEN_FILE} carries no fixed reason for \`${code}\`: \`fixed_reasons\` is null, and the file's own ` +
        "`pending` record says the two strings land with contract version ops.15 (§1.3 row 8.5 makes minice-be's " +
        "half due at R4a, before the first author yank). Refusing the decision would settle every author action " +
        "as `reason_refused` until then, which reads from the panel exactly like a service that sent something " +
        "wrong; substituting a string of our own is the invention SCOPE-7 exists to prevent",
      );
    }
    if (reason !== fixed) {
      return refuse(d, "reason_refused",
        `an \`${code}\` entry's reason is the one fixed registry string SCOPE-7's file lists for that code, and ` +
        `this entry carries ${JSON.stringify(reason)}. An author never types it and a moderator never sees it ` +
        "(BOT-80; DEC-14; MOD-41)");
    }
  } else if (code !== "M_BINDING_REVOKE") {
    const problems = reasonProblems(reason);
    if (problems.length) {
      return refuse(d, "reason_refused", problems.map((p) => p.why).join("; "));
    }
  }

  // ── M_APPEAL is about a DECISION, not about a listing ────────────────────
  //
  // Checked before `target_not_in_registry`, and the case is not an edge. An
  // appeal of an `M_REJECT` is an appeal of a REFUSAL: the submission never
  // became a listing, so `plugins/<id>/` does not exist and cannot, and
  // refusing it here would mean an appeal of a rejection could never be logged
  // at all — while MOD-33 requires the log entry for every decided appeal and
  // FLOW-18 turns a reversed one into the estate's only Recheck. Nothing in
  // this branch reads the tree for the listing, so there is nothing to derive.
  if (code === "M_APPEAL") return compileAppeal(root, d, { decidedAt, date, reason });

  // ── target_not_in_registry ───────────────────────────────────────────────
  const listing = readListing(root, d.plugin_id);
  if (listing === null) {
    return refuse(d, "target_not_in_registry",
      `\`${d.plugin_id}\` has no \`plugins/\` directory on \`main\` (TRUST-26). The bot compiles a decision only ` +
      "into artefacts derived from git, and there is nothing here to derive one from");
  }

  // ── M_BINDING_REVOKE compiles to nothing (§7.2) ──────────────────────────
  if (code === "M_BINDING_REVOKE") {
    return {
      outcome: "compiled", code, service_decision_id: d.service_decision_id,
      edits: [], log: [], advisories: [], records: [],
      alerts: [],
      note: "§7.2: none; the next release gets `B_BINDING_UNUSABLE`. The revocation itself is the service's record.",
    };
  }

  // ── the three relist refusals, before any hold ───────────────────────────
  if (code === "M_RELIST") {
    const covered = advisoryCovering(root, listing);
    if (covered) {
      return refuse(d, "relist_under_advisory",
        `${listing.id}'s latest listed version is covered by ${covered} (MOD-10). Relisting under a signed ` +
        "advisory would put a plugin back in the catalogue that installed copies are already refusing");
    }
    if (!listing.bound && listing.id !== MIG25_UNBOUND_EXCEPTION) {
      return refuse(d, "relist_unbound",
        `${listing.id} has no identity record on \`main\`, so it has no bound release, and a release cannot lift ` +
        "`unlisted` by itself (MIG-27)");
    }
    const contained = containedRepo(listing);
    if (contained) {
      return refuse(d, "relist_contained",
        `${listing.id} is published from ${contained}, whose owner login was freed by the rename to MINICE-AI ` +
        "and is claimable by anybody (MIG-30). Neither a moderator nor the bot may relist such a plugin");
    }
  }

  // ── MOD-9's holds, after the refusals and before any artefact ────────────
  const kind = holdKindFor(d, { overBound, listingBound: listing.bound });
  if (kind) {
    return held(d, kind, holdWhy(kind, d, listing));
  }

  // ── what is left compiles ────────────────────────────────────────────────
  switch (KNOWN_CODES[code]) {
    case "yank": return compileYank(root, d, listing, { decidedAt, date, reason });
    case "delist": return compileDelist(root, d, listing, { decidedAt, date, reason });
    case "advisory": return compileAdvisory(root, d, listing, { decidedAt, date, reason });
    default:
      // `reversal` with no hold cannot happen: `holdKindFor` returns "reversal"
      // for both reversal codes unconditionally. Said out loud rather than
      // fallen through, because a silent fall-through here would compile a
      // relist that MOD-9 requires an operator for.
      throw new Error(
        `\`${code}\` reached the compile with no hold kind. MOD-9 holds every M_RELIST and M_UNREVOKE, so this ` +
        "is `holdKindFor` and this table disagreeing about the reversal codes",
      );
  }
}

/** Which advisory, if any, covers the listing's latest non-yanked version. */
function advisoryCovering(root, listing) {
  const live = listing.versions.filter((v) => v.doc?.yanked !== true);
  if (live.length === 0) return null;
  const latest = live[live.length - 1];

  const { advisories } = loadAdvisories({ root });
  const digests = new Set(
    Object.values(latest.doc?.artifacts ?? {})
      .map((a) => (typeof a?.sha256 === "string" ? a.sha256.toLowerCase() : null))
      .filter(Boolean),
  );

  for (const advisory of advisories) {
    for (const e of advisory.entries) {
      const value = String(e?.value ?? "");
      if (e.kind === "id" && value === listing.id) return advisory.id;
      if (e.kind === "id_version" && value === `${listing.id}@${latest.version}`) return advisory.id;
      if (e.kind === "digest" && digests.has(value.toLowerCase())) return advisory.id;
      if (e.kind === "version_range" && value === listing.id) {
        const introduced = e.versions?.introduced;
        const fixed = e.versions?.fixed;
        const above = !introduced || compareSemver(latest.version, introduced) >= 0;
        const below = !fixed || compareSemver(latest.version, fixed) < 0;
        if (above && below) return advisory.id;
      }
      if (e.kind === IDENTITY_KIND && value.startsWith(IDENTITY_PREFIX)) {
        const slug = value.slice(IDENTITY_PREFIX.length).toLowerCase();
        if (String(listing.plugin?.source?.repo ?? "").toLowerCase() === slug) return advisory.id;
      }
    }
  }
  return null;
}

/** MIG-30's containment: the listing's own source, or any non-yanked release repo. */
function containedRepo(listing) {
  const owner = (repo) => String(repo ?? "").split("/")[0].toLowerCase();
  const source = listing.plugin?.source?.repo;
  if (CONTAINED_OWNERS.includes(owner(source))) return source;
  for (const { doc } of listing.versions) {
    if (doc?.yanked === true) continue;
    if (CONTAINED_OWNERS.includes(owner(doc?.release?.repo))) return doc.release.repo;
  }
  return null;
}

function holdWhy(kind, d, listing) {
  switch (kind) {
    case "unbound_yank":
      return `${listing.id} has no identity record on \`main\`. FLOW-79 forbids an unbound listing a yank outright ` +
        "— its author asks a moderator (`M_YANK`, category `author_request`) — so one reaching the bot means the " +
        "service erred, and no confirmation makes it right (M-T3.3)";
    case "unbound_removal":
      return `${listing.id} has no bound account, so FLOW-28 sends its removal request to a moderator after ` +
        "TRUST-27's period rather than to the catalogue (MOD-9)";
    case "reversal":
      return `${d.code} gives something back, and MOD-9 releases it only on a MOD-52 confirmation after the 24-hour ` +
        "hold period (OPEN-OWNER-4)";
    case "disable_confirmation":
      return "an M_REVOKE with action `disable` stops software already running on somebody's machine, so it waits " +
        "for a second person whatever the bound says (OPEN-OWNER-14)";
    case "bound":
      return "TRUST-26's count is at or above the takedown bound, so this takedown waits for an operator's MOD-52 " +
        "confirmation (MOD-9; OPEN-OWNER-45)";
    default:
      return kind;
  }
}

/** `M_YANK` and a bound `A_YANK` (§7.2; FLOW-79). */
function compileYank(root, d, listing, { decidedAt, date, reason }) {
  const author = d.code === "A_YANK";
  const named = Array.isArray(d.versions) ? d.versions : [];
  if (named.length === 0) {
    return refuse(d, "target_changed",
      "a yank names at least one version, and this decision names none. BOT-34's CI count compares records " +
      "against the versions a commit yanks, and zero of zero passes");
  }

  const movable = [];
  const stuck = [];
  for (const version of named) {
    const record = listing.versions.find((v) => v.version === version);
    if (!record || record.doc?.yanked === true || !listing.listed) stuck.push(version);
    else movable.push(version);
  }

  // The asymmetry the header explains: FLOW-79 makes the service pre-filter an
  // `A_YANK`, so one arriving stuck is a tree that moved; nothing pre-filters a
  // moderator's yank, so it takes what it can.
  if (author ? stuck.length > 0 : movable.length === 0) {
    return refuse(d, "target_changed",
      `${stuck.join(", ")} of ${listing.id} ${stuck.length === 1 ? "is" : "are"} not listed, or already yanked, on ` +
      "this tree. FLOW-79 makes that the service's own `plugin_not_listed` refusal at the served `Source-Commit`, " +
      "so a decision reaching the bot with one means the target moved between the service's read and this run");
  }

  const entry = {
    date,
    action: "yank",
    plugin: listing.id,
    versions: movable,
    reason,
    category: d.category ?? (author ? "author_request" : undefined),
    service_decision_id: d.service_decision_id,
    ...(d.declared_interest !== undefined ? { declared_interest: d.declared_interest } : {}),
  };
  if (entry.category === undefined) delete entry.category;

  const records = author
    ? composeAuthorActions({
      service_decision_id: d.service_decision_id,
      plugin_id: listing.id,
      versions: movable,
      repo: listing.identity.repo,
      repository_id: listing.identity.repository_id,
      repository_owner_id: listing.identity.repository_owner_id,
      decided_at: decidedAt,
    })
    : [];

  return {
    outcome: "compiled",
    code: d.code,
    service_decision_id: d.service_decision_id,
    edits: movable.map((v) => yankEdit(listing.id, v)),
    log: [logEntry(root, entry)],
    advisories: [],
    records,
    alerts: [],
    // BOT-37: detector B row 2 matches an author-action record — which carries
    // no `submission_id` — by its commit's `Service-Decision:` trailer, so a
    // yank committed without one reads to the service as a record with no
    // service outcome.
    trailers: { "Service-Decision": d.service_decision_id, "Decided-At": decidedAt },
  };
}

/** `M_DELIST` and a bound `A_REMOVAL_REQUEST` (§7.2; FLOW-28). */
function compileDelist(root, d, listing, { decidedAt, date, reason }) {
  if (!listing.listed) {
    return refuse(d, "target_changed",
      `${listing.id} is already unlisted on this tree, so there is nothing left for this decision to take away`);
  }
  const author = d.code === "A_REMOVAL_REQUEST";
  const entry = {
    date,
    action: "delist",
    plugin: listing.id,
    reason,
    category: d.category ?? (author ? "author_request" : undefined),
    service_decision_id: d.service_decision_id,
    ...(d.declared_interest !== undefined ? { declared_interest: d.declared_interest } : {}),
  };
  if (entry.category === undefined) delete entry.category;

  return {
    outcome: "compiled",
    code: d.code,
    service_decision_id: d.service_decision_id,
    edits: [unlistEdit(listing.id)],
    log: [logEntry(root, entry)],
    advisories: [],
    records: [],
    alerts: [],
    trailers: { "Service-Decision": d.service_decision_id, "Decided-At": decidedAt },
  };
}

/** `M_DEPRECATE` and `M_REVOKE` (§7.2; MOD-4; MOD-13; MOD-19). */
function compileAdvisory(root, d, listing, { decidedAt, date, reason }) {
  // §7.2: a deprecate IS an advisory with action `warn`. The payload carries an
  // `action` only for `M_REVOKE` (MOD-10), so taking one from a deprecate would
  // be taking a field the contract says is not there.
  const action = d.code === "M_DEPRECATE" ? "warn" : d.action;
  if (!ADVISORY_ACTIONS.includes(action)) {
    return refuse(d, "kind_refused", `action ${JSON.stringify(action)} is not one a withdrawal list may carry`);
  }

  const id = nextAdvisoryId({ root, year: date.slice(0, 4) });
  const entries = advisoryEntries(listing, Array.isArray(d.versions) ? d.versions : []);

  if (ACCOUNT_LEVEL_CATEGORIES.includes(d.category)) {
    entries.push(...identityEntries(root, listing));
  }

  const advisory = {
    id,
    published: date,
    severity: d.severity,
    action,
    reason,
    advisory_url: `${ADVISORY_URL_BASE}${id}`,
    entries,
  };
  const problems = checkAdvisory(advisory, `${REVOCATIONS_DIR}/${id}.json`);
  if (problems.length) {
    throw new Error(
      `refusing to compile an advisory the withdrawal list would refuse: ${problems.join("; ")}. MOD-3 will not ` +
      "push when the backing check fails, so this is the same refusal one step earlier and with the reason intact",
    );
  }

  const entry = {
    date,
    action: d.code === "M_DEPRECATE" ? "deprecate" : "revoke",
    plugin: listing.id,
    ...(Array.isArray(d.versions) && d.versions.length ? { versions: d.versions } : {}),
    reason,
    advisory: id,
    ...(d.category !== undefined ? { category: d.category } : {}),
    service_decision_id: d.service_decision_id,
    ...(d.declared_interest !== undefined ? { declared_interest: d.declared_interest } : {}),
  };

  return {
    outcome: "compiled",
    code: d.code,
    service_decision_id: d.service_decision_id,
    edits: [{ op: "add", file: `${REVOCATIONS_DIR}/${id}.json`, doc: advisory }],
    log: [logEntry(root, entry)],
    advisories: [advisory],
    records: [],
    // MOD-8: every advisory is alerted before the push, `warn` included. A
    // signed `warn` reaches every installed copy.
    alerts: [{ kind: "advisory", advisory: id, action, severity: d.severity }],
    trailers: { "Service-Decision": d.service_decision_id, "Decided-At": decidedAt },
  };
}

/**
 * `M_APPEAL` → log `appeal` (MOD-33), and what else follows from the outcome.
 *
 * `appeal` is the one action §7.2 gives no category, and `checkEntry` refuses
 * one — so a compile that copied `category` through would be refused by the log
 * it was written for.
 */
function compileAppeal(root, d, { decidedAt, date, reason }) {
  const entry = {
    date,
    action: "appeal",
    plugin: d.plugin_id,
    reason,
    appeal_of: d.appeal_of,
    outcome: d.outcome,
    service_decision_id: d.service_decision_id,
    ...(d.declared_interest !== undefined ? { declared_interest: d.declared_interest } : {}),
  };

  const reversed = d.outcome === "reversed";
  return {
    outcome: "compiled",
    code: d.code,
    service_decision_id: d.service_decision_id,
    edits: [],
    log: [logEntry(root, entry)],
    advisories: [],
    records: [],
    alerts: [],
    // FLOW-18's one Recheck, for a reversed `M_REJECT`. The Recheck itself is
    // the service's to open; what this says is that the appeal compiled to it
    // rather than to an artefact, which is MOD-34's "a `reversed` appeal is a
    // NEW artefact and the originals are left alone".
    recheck: reversed ? { plugin_id: d.plugin_id, appeal_of: d.appeal_of } : null,
    record_owed: reversed ? appealRecordOwed(d) : null,
    trailers: { "Service-Decision": d.service_decision_id, "Decided-At": decidedAt },
  };
}

/**
 * MOD-33's decision record for an appealed refusal, reported as owed rather
 * than composed. The header says why in full; the short version is that BOT-35
 * has four key domains and an appeal has none of them, and the only one it
 * could borrow derives the id the refusal's own record already holds.
 */
function appealRecordOwed(d) {
  return {
    what: "a decision record with `trigger: appeal`, `appeal_of` and `outcome` (MOD-33; DEC-7)",
    blocked_by:
      "BOT-35 gives an appeal record no key domain. `submission:<submission_id>` derives the id the appealed " +
      "refusal's own record already carries, so the write collides with it and BOT-36's dedupe drops it. A fifth " +
      "domain is a contract amendment (registry plan §1.3 row 6), not a choice this file makes",
    appeal_of: d.appeal_of,
    outcome: d.outcome,
  };
}

/** Every §7.2 category the log will accept for an action, for a caller's check. */
export const categoriesFor = (action) => CATEGORIES[action] ?? [];
