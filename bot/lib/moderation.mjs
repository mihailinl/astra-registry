// The moderation log: the seven actions, their source files, and the one place
// their rules are checked.
//
// PRODUCTION_PLAN task 6.6. Rendered at `/transparency/` and published as
// `/transparency/moderation-log.json`.
//
// ── WHAT THIS DOCUMENT IS, AND WHAT IT IS NOT ───────────────────────────────
//
// It is NOT signed, and it must never be presented as if it were. Two of the
// four actions it records — `deprecate` and `revoke` — are *effects*, and the
// signed statement that produces those effects is `registry/v1/revocations.json`,
// which a daemon fetches, verifies and acts on. This log is the human-readable
// record beside it: it also covers the two actions that produce no signed
// document at all (`yank` and `delist` are catalogue edits), and it carries the
// reason and the appeal link, which the signed document deliberately keeps
// short.
//
// So the rule is: a log entry claiming a signed effect must be BACKED BY the
// signed document. `buildModerationLog` refuses to emit an entry whose action is
// `deprecate` or `revoke` unless the advisory it names is actually in the
// withdrawal list it was handed, with a matching action. A transparency log that
// can claim a revocation nobody signed is a transparency log that can be used to
// scare people off a competitor.
//
// ── THE ACTIONS ─────────────────────────────────────────────────────────────
//
// Four of them take something away, and they escalate by what they take from
// somebody who has already installed the plugin, which is the only ordering
// that matters to a user:
//
//   yank       a version leaves the catalogue. `tools/build-index.mjs:103`
//              (`listedReleases` filters `yanked !== true`). Installed copies:
//              untouched.
//   delist     the plugin leaves the catalogue. `tools/build-index.mjs:179`
//              (`unlisted === true` is skipped). Installed copies: untouched.
//   deprecate  an advisory with `action: "warn"`. Installed copies are badged
//              and the user is told; installs are still allowed
//              (`RevocationAction::blocks_install()` in
//              astra-daemon/src/plugins/trust.rs is false only for `warn`).
//   revoke     an advisory with `action: "block_install"` or `"disable"`.
//              `block_install` refuses new installs and updates and leaves a
//              running copy alone; `disable` also stops what is already there
//              (`RevocationAction::stops_installed()` is true only for it).
//
// Three of them give something back, or record that somebody asked for it
// back. They are MOD-47's addition, and the reason they are in the SAME log
// rather than in a second one is that a log which records only the taking is a
// log that overstates the estate's severity for ever: a reader who finds the
// delist and not the relist reads a plugin as withdrawn when it is listed.
//
//   relist     `unlisted` removed (MOD-52's revert, or `M_RELIST`). Carries
//              `reverses`: the service decision it undoes.
//   unrevoke   the advisory file deleted, and the effect lifted at a higher
//              serial (`M_UNREVOKE`, or MOD-52's revert of a deprecate or a
//              revoke). Carries `reverses` — a `service_decision_id`, or, for
//              a hand advisory committed under `Moderation-Exempt:` with no
//              service decision behind it, the `ASTRA-YYYY-NNNN` itself.
//   appeal     a decided appeal (`M_APPEAL`; MOD-33). Never its text: the
//              appellant's words are the one thing PRIV-2 keeps out of git.
//              It carries `appeal_of`, `outcome` and the public reason, and it
//              carries NO category — §7.2's "one category per `M_*` decision
//              except `M_APPEAL`".
//
// ── WHY THE SOURCES LIVE UNDER bot/ ─────────────────────────────────────────
//
// The same reason the advisories live under `tools/`: a moderation entry is not
// a listing. It is not submitted by an author, not generated from a release, and
// written by the maintainer at the moment of a decision. Keeping it beside the
// generator that consumes it leaves `plugins/**` meaning exactly one thing —
// "things people asked us to list".

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { ADVISORY_ID_PATTERN, ID_PATTERN, unsafeDisplayText } from "../../tools/lib/ids.mjs";
import { parseSemver } from "../../tools/lib/semver.mjs";

export const SCHEMA = "astra.registry.moderation-log/1";

/** Where a maintainer writes one file per action taken. */
export const SOURCE_DIR = "bot/moderation";

/**
 * Escalating, each followed by what undoes it, and the appeal record last.
 *
 * The order of the four that take something away is the order of what a user
 * already running it loses. The three that give it back sit beside the action
 * they reverse rather than in a block of their own, because the pair is the
 * unit a reader of `/transparency/` is looking for.
 */
export const ACTIONS = ["yank", "delist", "relist", "deprecate", "revoke", "unrevoke", "appeal"];

/**
 * The four whose cost `docs/POLICY.md` §9 tabulates.
 *
 * Named as a set of its own because a check with `ACTIONS` as its subject and
 * "what does this cost an installed copy" as its question is a check applied
 * to something that is not its subject: a relist costs nothing, an appeal is
 * not a mechanism, and neither belongs in an escalation table.
 */
export const ESCALATING_ACTIONS = ["yank", "delist", "deprecate", "revoke"];

/**
 * §7.2's category table, keyed by the LOG action rather than by the decision
 * code, because the log is what this file checks.
 *
 * Transcribed from contract §7.2 ("Category | Allowed with"), with the two
 * translations that table's own column needs:
 *
 *   - REJECT, APPROVE and BINDING_REVOKE produce no log entry at all, so the
 *     categories that exist only for them (`review_passed`) appear nowhere
 *     below;
 *   - "revert" is MOD-52's, and a revert is logged as `relist` or `unrevoke`,
 *     so `error`, `appeal_reversed` and `path_test` reach those two actions.
 *
 * `appeal` is deliberately absent: §7.2 says "one category per `M_*` decision
 * except `M_APPEAL`", and §4.2 says "`category` (none for `M_APPEAL`)". An
 * appeal that carried one would be publishing a reason for the underlying
 * action a second time, under the appeal's date.
 */
export const CATEGORIES = {
  yank: ["malicious", "account_compromise", "account_sanction", "privacy", "broken", "security_defect", "author_request"],
  delist: ["malicious", "account_compromise", "account_sanction", "privacy", "impersonation", "broken", "licence", "naming", "legal", "author_request"],
  relist: ["error", "appeal_reversed", "path_test"],
  deprecate: ["privacy", "broken", "security_defect", "licence", "legal", "path_test"],
  revoke: ["malicious", "account_compromise", "account_sanction", "privacy", "impersonation", "security_defect", "legal"],
  unrevoke: ["error", "appeal_reversed", "path_test"],
  appeal: [],
};

/** MOD-33's two outcomes. There is no third, and "pending" is not an outcome. */
export const OUTCOMES = ["stands", "reversed"];

// ── the triage clock docs/POLICY.md publishes ───────────────────────────────
//
// Declared here and nowhere else, and asserted against the document by
// `bot/tests/policy.test.mjs`, for the same reason every number in
// `bot/lib/policy.mjs` is: a published SLA that has quietly stopped being true
// is worse than no SLA, because it teaches people the document is decoration.
//
// These are a commitment ONE PERSON can keep. They are deliberately not
// ambitious. The escape hatch, stated in the document rather than discovered,
// is that when triage runs late the answer is to reach for the REVERSIBLE
// action sooner — delisting a plugin costs an author a listing and can be undone
// in a commit, while `disable` stops software on somebody's machine and should
// never be the fast reflex.

/** From a report arriving to a human having read it and said so. */
export const TRIAGE_ACK_HOURS = 72;

/** From a report of active harm being credible to the first action taken. */
export const TRIAGE_HARM_HOURS = 24;

/** From acknowledgement to a decision, for everything that is not active harm. */
export const TRIAGE_DECISION_DAYS = 7;

/** From an appeal being filed to a reasoned answer. */
export const APPEAL_RESPONSE_DAYS = 7;

// ── TRUST-26's takedown bound ───────────────────────────────────────────────
//
// How many listed plugin ids the estate may withdraw in any trailing 24 hours
// before the next takedown — `block_install` included — waits for an
// operator's MOD-52 confirmation (MOD-9). It caps the blast radius of a
// compromised panel or service; `bot/lib/takedown-bound.mjs` is what counts
// the window, out of git, and `bot/lib/holds.mjs` is what holds above it.
//
// **IT IS 1 BECAUSE NO POLICY DOCUMENT PUBLISHES A NUMBER YET, AND THAT IS THE
// WHOLE OF THE REASON.** The owner closed OPEN-OWNER-3 at 3 — three in the
// trailing 24 h, a bound account's removal request and an author's yank
// counting — and `reg.61a` lands that 3 here and the sentence that carries it
// in POLICY.md §7, in one commit, before TRUST-10's acknowledgement (M-T3.2,
// B-T3.3b). Until then the bot enforces the strictest bound it can that is
// still a bound: 1 lets the first withdrawal of a day through and holds every
// one after it for a person, where 0 would hold the first as well and be a
// stop rather than a bound. A bot enforcing 3 against a policy that promises
// nothing would be making the estate's most consequential promise out of a
// literal nobody can read.
//
// `bot/tests/policy.test.mjs` holds the pair together in both directions: with
// no bound published this must be 1, and with one published it must be that
// number and the document must also say that a takedown above it waits for an
// operator. So reg.61a cannot land half of itself.
export const TAKEDOWN_BOUND = 1;

/** Which advisory actions a log entry of each kind is allowed to be backed by. */
export const BACKING = {
  deprecate: ["warn"],
  revoke: ["block_install", "disable"],
};

// ── MOD-41's public-reason rules, and the unit they are counted in ──────────
//
// **The unit is CODE POINTS.** MOD-41 says "outside 10 to 300 characters" and
// names no unit, and two implementations read that differently by default:
// the service's entry check (MOD-48) counts Postgres `char_length`, which is
// code points, and JavaScript's `String.length` counts UTF-16 code units. A
// 299-code-point Russian reason carrying four emoji is 303 units.
//
// The direction that disagreement fails in is the unsafe one. The service
// accepts the decision and records it; this side refuses the reason; the bot
// routes the decision to `refused` with `reason_refused`; `report` posts that
// back; and the decision settles as refused with nothing for the moderator to
// act on. **A takedown stalls**, and a takedown that stalls is the one class
// of failure §7 calls unsafe, because only a withdrawal reaches a machine that
// already has the plugin on it.
//
// So both of this repository's validators count `[...s].length` — here and in
// `tools/lib/revocations.mjs`, through this one function — and
// `tests/moderation-reasons.json` carries a vector on each side of 300 whose
// UTF-16 length differs from its code-point length, so that a validator which
// quietly went back to `String.length` is red rather than merely stricter.
// The unit goes to the contract as a PATCH to MOD-41 and MOD-48; the corpus is
// written with it stated either way, because a corpus that waits for a PATCH
// is a corpus nobody can vendor.
//
// **Counted over the TRIMMED reason**, which is the string `buildModerationLog`
// publishes and the one a reader sees. Counting the untrimmed value would make
// this side stricter than a service that stores a trimmed one, which is the
// stall again, one character at a time.

/** MOD-41's floor, in code points. */
export const REASON_MIN_CODE_POINTS = 10;

/** MOD-41's ceiling, in code points. */
export const REASON_MAX_CODE_POINTS = 300;

/** Code points, not UTF-16 code units. The whole of M-11 is this line. */
export const codePointLength = (s) => [...s].length;

/**
 * Dotted tokens whose last label is one of these are file names, not hosts.
 *
 * This list is the one judgement call in the host-like rule and it is pinned
 * by example in `tests/moderation-reasons.json` rather than by a second regex
 * somebody has to keep in step. MOD-41 requires that names such as
 * `plugin.toml` pass, and a reason about a malicious build genuinely does have
 * to be able to say `README.md` or `Cargo.lock`.
 *
 * Each entry is a hole, because several of these are also real top-level
 * domains — `.md` is Moldova, `.js` is Jersey — and `evil.md` therefore
 * passes. The list is kept short for that reason and three plausible suffixes
 * are deliberately NOT on it: `.so`, `.sh` and `.py` are Somalia, Saint Helena
 * and Paraguay, and a reason can say "a shared library", "a shell script" or
 * "a Python file" instead. What the rule is for is keeping a CLICKABLE host
 * out of a sentence a stranger wrote; `payload.exe` is not one.
 */
export const REASON_FILE_SUFFIXES = [
  "astraplugin", "dll", "dylib", "exe", "js", "json", "lock", "md", "mjs", "rs", "toml", "txt", "yaml", "yml",
];

/** The refusal classes `reasonProblems` can report. The corpus indexes on these. */
export const REASON_CLASSES = [
  "not_a_string", "too_short", "too_long", "unsafe_text", "uri_scheme", "www", "at_sign", "host_like",
];

// `scheme://`, and the schemes that carry a payload without one. A bare
// `mailto:` is a link a reader can click in exactly the same way.
const URI_SCHEME_RE = /[A-Za-z][A-Za-z0-9+.-]*:\/\//;
const BARE_SCHEME_RE = /\b(?:mailto|data|javascript|tel|sms|ftp|file):/i;
const WWW_RE = /(?:^|[^A-Za-z0-9-])www\./i;
const DOTTED_RE = /[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+/g;

/**
 * MOD-41's rules over one public reason. **The one implementation this
 * repository has**, shared by the moderation log and by `checkAdvisory` in
 * `tools/lib/revocations.mjs`.
 *
 * Every clause that matches is reported, not just the first. The first error
 * found is a stopping condition, and a reason refused for its length that also
 * carries a host would come back green the moment somebody shortened it.
 *
 * @param {unknown} reason
 * @returns {{class: string, why: string}[]}
 */
export function reasonProblems(reason) {
  if (typeof reason !== "string") {
    return [{ class: "not_a_string", why: `reason ${JSON.stringify(reason)} must be a string` }];
  }
  const out = [];
  const text = reason.trim();
  const n = codePointLength(text);
  if (n < REASON_MIN_CODE_POINTS) {
    out.push({
      class: "too_short",
      why: `reason must be a sentence a reader can act on (at least ${REASON_MIN_CODE_POINTS} code points; this one is ${n})`,
    });
  }
  if (n > REASON_MAX_CODE_POINTS) {
    out.push({
      class: "too_long",
      why: `reason is ${n} code points; keep it under ${REASON_MAX_CODE_POINTS + 1}`,
    });
  }
  const unsafe = unsafeDisplayText(text);
  if (unsafe) {
    out.push({ class: "unsafe_text", why: `reason ${unsafe}, which must never reach a reader's screen` });
  }
  if (URI_SCHEME_RE.test(text) || BARE_SCHEME_RE.test(text)) {
    out.push({ class: "uri_scheme", why: "reason carries a URI scheme; a public reason is a sentence, never a link (MOD-41)" });
  }
  if (WWW_RE.test(text)) {
    out.push({ class: "www", why: "reason carries `www.`; a public reason is a sentence, never a link (MOD-41)" });
  }
  if (text.includes("@")) {
    out.push({ class: "at_sign", why: "reason carries `@`, which is an address or an `id@version`; name the version in words (MOD-41)" });
  }
  for (const m of text.matchAll(DOTTED_RE)) {
    const labels = m[0].split(".");
    const last = labels[labels.length - 1].toLowerCase();
    if (!/^[a-z]{2,}$/.test(last)) continue;
    if (REASON_FILE_SUFFIXES.includes(last)) continue;
    out.push({
      class: "host_like",
      why: `reason carries the host-like token \`${m[0]}\`; if it is a file name its suffix belongs in REASON_FILE_SUFFIXES (MOD-41)`,
    });
    break;
  }
  return out;
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;
// `tools/lib/ids.mjs`'s grammar, the one `tools/lib/revocations.mjs` validates
// an advisory's own id with. Not imported from there: that module imports this
// one, and the other direction would be an import cycle (ids.mjs says so).
const ADVISORY_ID = new RegExp(ADVISORY_ID_PATTERN);
const ID_RE = new RegExp(ID_PATTERN);
// §0.7: `service_decision_id` is a lowercase canonical UUID v4 or v7 (RFC 9562).
const SERVICE_DECISION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
// §0.7: `decision_id` is 32 lowercase hex, deterministic (bot).
const DECISION_ID = /^[0-9a-f]{32}$/;

/**
 * Check one moderation entry and return its problems.
 *
 * As strict as `checkAdvisory` about display text, and for the same reason: a
 * reason string reaches a reader's screen verbatim, and a bidi override in that
 * position is the spoofing primitive every other check in this repository
 * refuses.
 *
 * @param {unknown} doc
 * @param {string} where
 * @param {{cutoverAt?: string|null}} opts
 *        `cutoverAt` is `log/cutover.json`'s `cutover_at`, or null when the
 *        marker is not on `main`. Null means cutover has not happened
 *        (ROLL-33), which is the same reading `bot/lib/listing-state.mjs`
 *        takes of the same file.
 * @returns {string[]}
 */
export function checkEntry(doc, where = "<entry>", { cutoverAt = null } = {}) {
  const errs = [];
  const bad = (m) => errs.push(`${where}: ${m}`);

  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    bad("is not a JSON object");
    return errs;
  }

  if (typeof doc.date !== "string" || !DATE.test(doc.date)) {
    bad(`date ${JSON.stringify(doc.date)} must be YYYY-MM-DD`);
  }
  if (!ACTIONS.includes(doc.action)) {
    bad(`action ${JSON.stringify(doc.action)} must be one of ${ACTIONS.join(", ")}`);
  }
  if (typeof doc.plugin !== "string" || !ID_RE.test(doc.plugin)) {
    bad(`plugin ${JSON.stringify(doc.plugin)} is not a plugin id`);
  }
  for (const p of reasonProblems(doc.reason)) bad(p.why);

  if (doc.versions !== undefined) {
    if (!Array.isArray(doc.versions) || doc.versions.length === 0) {
      bad("versions, when present, must be a non-empty array of semver strings");
    } else {
      for (const v of doc.versions) {
        if (typeof v !== "string" || !parseSemver(v)) bad(`versions entry ${JSON.stringify(v)} is not semver`);
      }
    }
  }

  // An advisory id is what makes an effect checkable. Required for the three
  // actions that name one, refused for the four that cannot — a `yank`
  // pointing at an advisory would be an entry claiming a signed effect it does
  // not produce. `unrevoke` names the advisory it DELETED, which is why it is
  // in this set and out of `BACKING`: by the time the entry is readable the
  // thing it names is gone from the signed list on purpose.
  const needsAdvisory = doc.action === "deprecate" || doc.action === "revoke" || doc.action === "unrevoke";
  if (needsAdvisory) {
    if (typeof doc.advisory !== "string" || !ADVISORY_ID.test(doc.advisory)) {
      bad(`a ${doc.action} must name the advisory that carries it, as ASTRA-YYYY-NNNN`);
    }
  } else if (doc.advisory !== undefined) {
    bad(`${doc.action} is a catalogue edit and produces no signed document, so it may not name an advisory`);
  }

  // ── the appeal URL, and why it has a deadline ────────────────────────────
  //
  // It is a link to a public issue thread, and the public issue channel closes
  // at cutover (ROLL-33; OD-2 ends public refusal issues, DEC-12 removes the
  // channel). An entry dated after `cutover_at` that carried one would be
  // publishing a link to a thread nobody can open — worse than no link, since
  // a reader who cannot reach it reads it as the estate having hidden the
  // appeal rather than as the channel having moved into the panel.
  if (doc.appeal !== undefined) {
    if (typeof doc.appeal !== "string" || !doc.appeal.startsWith("https://")) {
      bad(`appeal ${JSON.stringify(doc.appeal)} must be an https URL`);
    } else if (cutoverAt && typeof doc.date === "string" && doc.date >= cutoverAt.slice(0, 10)) {
      bad(
        `appeal links to the public issue channel, which closed at cutover (${cutoverAt}); an entry dated ` +
          `${doc.date} may not carry one`,
      );
    }
  }

  // ── §7.2's category table ────────────────────────────────────────────────
  if (doc.category !== undefined) {
    const allowed = CATEGORIES[doc.action];
    if (!allowed) {
      // The action is already refused above; saying it twice helps nobody.
    } else if (allowed.length === 0) {
      bad(`an ${doc.action} carries no category (§7.2: one category per M_* decision except M_APPEAL)`);
    } else if (typeof doc.category !== "string" || !allowed.includes(doc.category)) {
      bad(`category ${JSON.stringify(doc.category)} is not one a ${doc.action} may carry: ${allowed.join(", ")}`);
    }
  }

  // ── what a reversal names, and what an appeal names ──────────────────────
  if (doc.reverses !== undefined) {
    const reversing = doc.action === "relist" || doc.action === "unrevoke";
    if (!reversing) {
      bad(`${doc.action} reverses nothing, so it may not carry reverses`);
    } else if (typeof doc.reverses !== "string") {
      bad("reverses must be a string");
    } else if (SERVICE_DECISION_ID.test(doc.reverses)) {
      // A service decision. The ordinary case (MOD-52's revert, M_RELIST,
      // M_UNREVOKE).
    } else if (ADVISORY_ID.test(doc.reverses) && doc.action === "unrevoke") {
      // A hand advisory, committed under `Moderation-Exempt:` with no service
      // decision behind it (D9's break-glass). It is the only thing there is
      // to name, and only an unrevoke can meet one.
    } else {
      bad(
        `reverses ${JSON.stringify(doc.reverses)} must be a service_decision_id (§0.7's UUID)` +
          (doc.action === "unrevoke" ? ", or the ASTRA-YYYY-NNNN of a hand advisory" : ""),
      );
    }
  }

  const isAppeal = doc.action === "appeal";
  if (isAppeal) {
    if (doc.appeal_of === undefined) bad("an appeal must name what was appealed, as appeal_of (MOD-33)");
    if (doc.outcome === undefined) bad(`an appeal must carry its outcome, one of ${OUTCOMES.join(", ")} (MOD-33)`);
  }
  if (doc.appeal_of !== undefined) {
    if (!isAppeal) {
      bad(`${doc.action} is not an appeal, so it may not carry appeal_of`);
    } else if (typeof doc.appeal_of !== "string"
      || !(SERVICE_DECISION_ID.test(doc.appeal_of) || DECISION_ID.test(doc.appeal_of))) {
      // §0.7 gives two ids an appeal can be OF: a service decision (a
      // withdrawal, appealed to the moderators) and a bot decision record (an
      // `M_REJECT`, whose appeal FLOW-18 turns into one Recheck). The contract
      // does not say which minter appears here, so both shapes are accepted
      // and anything that is neither is refused.
      bad(`appeal_of ${JSON.stringify(doc.appeal_of)} must be a service_decision_id or a decision_id (§0.7)`);
    }
  }
  if (doc.outcome !== undefined) {
    if (!isAppeal) bad(`${doc.action} is not an appeal, so it may not carry outcome`);
    else if (!OUTCOMES.includes(doc.outcome)) {
      bad(`outcome ${JSON.stringify(doc.outcome)} must be one of ${OUTCOMES.join(", ")} (MOD-33)`);
    }
  }

  if (doc.service_decision_id !== undefined
    && (typeof doc.service_decision_id !== "string" || !SERVICE_DECISION_ID.test(doc.service_decision_id))) {
    bad(`service_decision_id ${JSON.stringify(doc.service_decision_id)} must be §0.7's lowercase UUID v4 or v7`);
  }

  // MOD-12's conflict flag, and it is a FLAG. The moderation log carries no
  // `moderator` member — `tools/priv-scan.mjs` declares none for this document
  // and permits no handle in any of its members — so a string here is where a
  // moderator's name would land in git without anybody having decided that it
  // should. The conflict itself is shown to the owner and the moderators by the
  // service; what reaches the public log is that there was one.
  if (doc.declared_interest !== undefined && typeof doc.declared_interest !== "boolean") {
    bad("declared_interest is a flag (MOD-12): true when a moderator declared a conflict, and never a name");
  }

  for (const key of Object.keys(doc)) {
    if (!ENTRY_MEMBERS.includes(key)) {
      bad(`unknown field ${JSON.stringify(key)}`);
    }
  }

  return errs;
}

/**
 * Every member a moderation entry may carry.
 *
 * **Declared here AND in `tools/priv-scan.mjs`'s `DOCUMENT_MEMBERS`, on
 * purpose.** They are two different questions about the same list: this one
 * asks what the schema permits, and that one asks what PRIV-2 has decided is
 * safe to walk — an undeclared member there is skipped by the value scan
 * entirely, so the two lists agreeing is what makes "every member is checked"
 * true. `bot/tests/moderation.test.mjs` compares them.
 */
export const ENTRY_MEMBERS = [
  "$comment", "date", "action", "plugin", "versions", "reason", "advisory", "appeal",
  "category", "reverses", "appeal_of", "outcome", "service_decision_id", "declared_interest",
];

/**
 * The file name an entry must have, so that a directory listing reads as a log.
 *
 * MOD-47: names are unique per date, plugin and action. The first entry of a
 * day keeps the name it has always had and a second one takes `-2`, then `-3`
 * — rather than every entry taking a suffix — because the six entries already
 * on `main` would otherwise all have to be renamed, and a moderation entry is
 * the worst file in this repository to rename: its path is what a reader of a
 * commit, an alarm or a transparency page was given.
 *
 * @param {{date: string, plugin: string, action: string}} doc
 * @param {number} n 1 for the first entry of its day, 2 upward after that
 */
export function fileNameFor(doc, n = 1) {
  const suffix = n > 1 ? `-${n}` : "";
  return `${doc.date}-${doc.plugin}-${doc.action}${suffix}.json`;
}

/**
 * Read a file name back: its (date, plugin, action) key and its `n`.
 *
 * The candidate `n` is read off the name, and then the name is REBUILT from it
 * with `fileNameFor` and compared. A regex that only parsed would be a second
 * spelling of the naming rule, which is the thing this file has exactly one
 * of; rebuilding means the parser cannot drift from the writer.
 *
 * `-0` and `-01` are not names: the first would be a zeroth entry and the
 * second is a second spelling of `n`, and a directory where both `-2` and
 * `-02` can exist is a directory where a write can miss the file it meant to
 * find.
 *
 * @param {string} file
 * @param {{date: string, plugin: string, action: string}} doc
 * @returns {number|null}
 */
export function suffixOf(file, doc) {
  if (file === fileNameFor(doc, 1)) return 1;
  const m = /-(\d+)\.json$/.exec(file);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isInteger(n) || n < 2) return null;
  return file === fileNameFor(doc, n) ? n : null;
}

/** `log/cutover.json`'s `cutover_at`, or null when the marker is not there. */
export function cutoverAt(root = REPO_ROOT) {
  const file = path.join(root, "log", "cutover.json");
  if (!fs.existsSync(file)) return null;
  try {
    const at = JSON.parse(fs.readFileSync(file, "utf8"))?.cutover_at;
    return typeof at === "string" && at ? at : null;
  } catch {
    // Unreadable is not "after cutover". What refuses a malformed marker is
    // `tools/validate.mjs`'s `checkMigrationMarkers`, which reports it as an
    // error, and `build-index.yml` runs that validator on every pull request
    // and every push to `main`. `bot/lib/listing-state.mjs`'s `readMarkers`
    // throws on one too, but nothing the bot runs calls it yet. Guessing here
    // would make an appeal link vanish from the log because a comma was
    // misplaced in an unrelated file.
    return null;
  }
}

/**
 * Read every entry under `bot/moderation/`.
 *
 * `files[i]` is the name `entries[i]` was read from, so that a caller can name
 * a second same-day entry by its real path. It is returned beside the entries
 * rather than written onto them, because an entry object goes on to be checked
 * against `ENTRY_MEMBERS` and a member this function added would be refused by
 * the check this function just ran.
 *
 * @param {{root?: string}} opts
 * @returns {{entries: object[], errors: string[], files: string[]}}
 */
export function loadEntries({ root = REPO_ROOT } = {}) {
  const dir = path.join(root, SOURCE_DIR);
  const errors = [];
  const entries = [];
  const files = [];
  if (!fs.existsSync(dir)) return { entries, errors, files };

  const names = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  const cutover = cutoverAt(root);
  // MOD-47's uniqueness, counted per (date, plugin, action). A `-2` with no
  // `-1` beside it, and two files claiming the same `n`, are both a second
  // write that did not know about the first.
  const seen = new Map();

  for (const file of names) {
    const where = `${SOURCE_DIR}/${file}`;
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
    } catch (e) {
      errors.push(`${where}: not readable JSON (${e.message})`);
      continue;
    }
    const problems = checkEntry(doc, where, { cutoverAt: cutover });
    if (problems.length) {
      errors.push(...problems);
      continue;
    }
    const n = suffixOf(file, doc);
    if (n === null) {
      errors.push(`${where}: the file name must be ${fileNameFor(doc)}, or ${fileNameFor(doc, 2)} for a second one the same day`);
      continue;
    }
    const key = `${doc.date}\u0000${doc.plugin}\u0000${doc.action}`;
    const group = seen.get(key) ?? new Set();
    if (group.has(n)) {
      errors.push(`${where}: a second file already claims ${fileNameFor(doc, n)}`);
      continue;
    }
    group.add(n);
    seen.set(key, group);
    entries.push(doc);
    files.push(file);
  }

  // The suffixes of one (date, plugin, action) must be 1..k. A gap is the
  // shape a hand-written `-3` takes when `-2` was renamed or deleted, and the
  // cost of tolerating it is that the next writer computes `-3` again from the
  // count and silently overwrites somebody's entry.
  for (const [key, group] of seen) {
    const [date, plugin, action] = key.split("\u0000");
    const missing = [];
    for (let n = 1; n <= group.size; n++) if (!group.has(n)) missing.push(fileNameFor({ date, plugin, action }, n));
    if (missing.length) {
      errors.push(
        `${SOURCE_DIR}/: ${group.size} entr${group.size === 1 ? "y" : "ies"} for ${date} ${plugin} ${action}, and ` +
          `${missing.join(", ")} ${missing.length === 1 ? "is" : "are"} not among them. MOD-47 numbers them from 1 with no gaps`,
      );
    }
  }

  return { entries, errors, files };
}

/**
 * The published log.
 *
 * @param {{root?: string, revocations?: object[], revocationsSerial?: number}} opts
 *        `revocations` is the `signed.revocations` array out of the deployed,
 *        signed withdrawal list. Pass it: without it, the backing check cannot
 *        run and the log is emitted with `backed: null` rather than a claim.
 */
export function buildModerationLog({ root = REPO_ROOT, revocations = null, revocationsSerial } = {}) {
  const { entries, errors, files } = loadEntries({ root });
  if (errors.length) {
    throw new Error(`refusing to build a moderation log from invalid sources:\n  ${errors.join("\n  ")}`);
  }

  const byAdvisory = new Map();
  for (const r of revocations ?? []) {
    if (!byAdvisory.has(r.id)) byAdvisory.set(r.id, r);
  }

  // ── what a later unrevoke does to the backing check (MOD-47) ─────────────
  //
  // A `deprecate` or a `revoke` is BACKED BY the signed advisory it names, and
  // the check that enforces it is this file's whole reason for existing. An
  // `unrevoke` deletes that advisory, so from the next signing run onward the
  // withdrawal list does not carry it and the backing check would throw about
  // an entry that is not wrong — it is SETTLED. The build would then refuse to
  // emit a log every time the estate corrected itself, which is precisely
  // backwards: the reversal is the part of the record a wrongly-withdrawn
  // author most needs published.
  //
  // Settled is keyed on the log itself and not on the withdrawal list, because
  // the withdrawal list is exactly what no longer says anything about it.
  const settled = new Set();
  for (const e of entries) {
    if (e.action !== "unrevoke") continue;
    if (e.advisory) settled.add(e.advisory);
    // A hand advisory has no service decision, so `reverses` names it directly.
    if (e.reverses && ADVISORY_ID.test(e.reverses)) settled.add(e.reverses);
  }

  const out = [];
  for (const [i, e] of entries.entries()) {
    const at = `${SOURCE_DIR}/${files[i] ?? fileNameFor(e)}`;
    // `unrevoke` names the advisory it removed, so it is never backing-checked:
    // the correct state of the signed list for one is "absent".
    const checkable = e.advisory && revocations && e.action !== "unrevoke";
    let backed = e.advisory ? (revocations ? true : null) : false;
    if (checkable) {
      const signed = byAdvisory.get(e.advisory);
      if (!signed && settled.has(e.advisory)) {
        backed = "settled";
      } else if (!signed) {
        throw new Error(
          `${at} records a ${e.action} carried by ${e.advisory}, and ` +
            "the signed withdrawal list does not contain that advisory. Either the advisory was " +
            "never deployed or this entry is wrong; a transparency log may not claim a signed " +
            "effect that nobody signed.",
        );
      } else if (!BACKING[e.action].includes(signed.action)) {
        throw new Error(
          `${at} calls ${e.advisory} a ${e.action}, but the signed entry ` +
            `carries action "${signed.action}". A ${e.action} is ${BACKING[e.action].join(" or ")}.`,
        );
      }
    } else if (e.action === "unrevoke") {
      // It records the lifting of an effect; there is no effect of its own to
      // be in force, so it is never "in effect" and never "pending".
      backed = false;
    }
    out.push({
      date: e.date,
      action: e.action,
      plugin: e.plugin,
      ...(e.versions ? { versions: [...e.versions] } : {}),
      reason: e.reason.trim(),
      ...(e.advisory ? { advisory: e.advisory } : {}),
      ...(e.appeal ? { appeal: e.appeal } : {}),
      ...(e.category ? { category: e.category } : {}),
      ...(e.reverses ? { reverses: e.reverses } : {}),
      ...(e.appeal_of ? { appeal_of: e.appeal_of } : {}),
      ...(e.outcome ? { outcome: e.outcome } : {}),
      ...(e.service_decision_id ? { service_decision_id: e.service_decision_id } : {}),
      ...(e.declared_interest === undefined ? {} : { declared_interest: e.declared_interest }),
      backed,
    });
  }

  // Newest first, then by plugin, so the order is stable and the top of the
  // page is the thing that just happened.
  out.sort((a, b) => (a.date === b.date ? (a.plugin < b.plugin ? -1 : 1) : a.date < b.date ? 1 : -1));

  return {
    $comment:
      "GENERATED FILE — DO NOT EDIT. Source of truth: bot/moderation/<date>-<plugin>-<action>[-<n>].json. " +
      "THIS DOCUMENT IS NOT SIGNED. The signed statement that produces the deprecate/revoke effects " +
      "is registry/v1/revocations.json; this is the human record beside it, and it also covers yank, " +
      "delist and relist, which are catalogue edits and produce no signed document at all, and appeal, " +
      "which records a decision about one.",
    schema: SCHEMA,
    ...(revocationsSerial !== undefined ? { revocations_serial: revocationsSerial } : {}),
    entries: out,
  };
}
