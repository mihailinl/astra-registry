// The moderation log: the four escalating actions, their source files, and the
// one place their rules are checked.
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
// ── THE FOUR ACTIONS ────────────────────────────────────────────────────────
//
// Escalating by what they take away from somebody who has already installed the
// plugin, which is the only ordering that matters to a user:
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
import { ID_PATTERN, unsafeDisplayText } from "../../tools/lib/ids.mjs";
import { parseSemver } from "../../tools/lib/semver.mjs";

export const SCHEMA = "astra.registry.moderation-log/1";

/** Where a maintainer writes one file per action taken. */
export const SOURCE_DIR = "bot/moderation";

/** Escalating. The order is the order of what a user already running it loses. */
export const ACTIONS = ["yank", "delist", "deprecate", "revoke"];

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

/** Which advisory actions a log entry of each kind is allowed to be backed by. */
export const BACKING = {
  deprecate: ["warn"],
  revoke: ["block_install", "disable"],
};

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const ADVISORY_ID = /^ASTRA-\d{4}-\d{4,}$/;
const ID_RE = new RegExp(ID_PATTERN);

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
 * @returns {string[]}
 */
export function checkEntry(doc, where = "<entry>") {
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
  if (typeof doc.reason !== "string" || doc.reason.trim().length < 10) {
    bad("reason must be a sentence a reader can act on (at least 10 characters)");
  } else if (doc.reason.length > 300) {
    bad(`reason is ${doc.reason.length} characters; keep it under 300`);
  } else if (unsafeDisplayText(doc.reason)) {
    bad(`reason contains ${unsafeDisplayText(doc.reason)}, which must never reach a reader's screen`);
  }

  if (doc.versions !== undefined) {
    if (!Array.isArray(doc.versions) || doc.versions.length === 0) {
      bad("versions, when present, must be a non-empty array of semver strings");
    } else {
      for (const v of doc.versions) {
        if (typeof v !== "string" || !parseSemver(v)) bad(`versions entry ${JSON.stringify(v)} is not semver`);
      }
    }
  }

  // An advisory id is what makes an effect checkable. Required for the two
  // actions that claim one, refused for the two that cannot have one — a `yank`
  // pointing at an advisory would be an entry claiming a signed effect it does
  // not produce.
  const needsAdvisory = doc.action === "deprecate" || doc.action === "revoke";
  if (needsAdvisory) {
    if (typeof doc.advisory !== "string" || !ADVISORY_ID.test(doc.advisory)) {
      bad(`a ${doc.action} must name the advisory that carries it, as ASTRA-YYYY-NNNN`);
    }
  } else if (doc.advisory !== undefined) {
    bad(`${doc.action} is a catalogue edit and produces no signed document, so it may not name an advisory`);
  }

  if (doc.appeal !== undefined && (typeof doc.appeal !== "string" || !doc.appeal.startsWith("https://"))) {
    bad(`appeal ${JSON.stringify(doc.appeal)} must be an https URL`);
  }

  for (const key of Object.keys(doc)) {
    if (!["$comment", "date", "action", "plugin", "versions", "reason", "advisory", "appeal"].includes(key)) {
      bad(`unknown field ${JSON.stringify(key)}`);
    }
  }

  return errs;
}

/** The file name an entry must have, so that a directory listing reads as a log. */
export function fileNameFor(doc) {
  return `${doc.date}-${doc.plugin}-${doc.action}.json`;
}

/**
 * Read every entry under `bot/moderation/`.
 *
 * @param {{root?: string}} opts
 * @returns {{entries: object[], errors: string[]}}
 */
export function loadEntries({ root = REPO_ROOT } = {}) {
  const dir = path.join(root, SOURCE_DIR);
  const errors = [];
  const entries = [];
  if (!fs.existsSync(dir)) return { entries, errors };

  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    const where = `${SOURCE_DIR}/${file}`;
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
    } catch (e) {
      errors.push(`${where}: not readable JSON (${e.message})`);
      continue;
    }
    const problems = checkEntry(doc, where);
    if (problems.length) {
      errors.push(...problems);
      continue;
    }
    if (file !== fileNameFor(doc)) {
      errors.push(`${where}: the file name must be ${fileNameFor(doc)}`);
      continue;
    }
    entries.push(doc);
  }
  return { entries, errors };
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
  const { entries, errors } = loadEntries({ root });
  if (errors.length) {
    throw new Error(`refusing to build a moderation log from invalid sources:\n  ${errors.join("\n  ")}`);
  }

  const byAdvisory = new Map();
  for (const r of revocations ?? []) {
    if (!byAdvisory.has(r.id)) byAdvisory.set(r.id, r);
  }

  const out = [];
  for (const e of entries) {
    if (e.advisory && revocations) {
      const signed = byAdvisory.get(e.advisory);
      if (!signed) {
        throw new Error(
          `${SOURCE_DIR}/${fileNameFor(e)} records a ${e.action} carried by ${e.advisory}, and ` +
            "the signed withdrawal list does not contain that advisory. Either the advisory was " +
            "never deployed or this entry is wrong; a transparency log may not claim a signed " +
            "effect that nobody signed.",
        );
      }
      if (!BACKING[e.action].includes(signed.action)) {
        throw new Error(
          `${SOURCE_DIR}/${fileNameFor(e)} calls ${e.advisory} a ${e.action}, but the signed entry ` +
            `carries action "${signed.action}". A ${e.action} is ${BACKING[e.action].join(" or ")}.`,
        );
      }
    }
    out.push({
      date: e.date,
      action: e.action,
      plugin: e.plugin,
      ...(e.versions ? { versions: [...e.versions] } : {}),
      reason: e.reason.trim(),
      ...(e.advisory ? { advisory: e.advisory } : {}),
      ...(e.appeal ? { appeal: e.appeal } : {}),
      backed: e.advisory ? (revocations ? true : null) : false,
    });
  }

  // Newest first, then by plugin, so the order is stable and the top of the
  // page is the thing that just happened.
  out.sort((a, b) => (a.date === b.date ? (a.plugin < b.plugin ? -1 : 1) : a.date < b.date ? 1 : -1));

  return {
    $comment:
      "GENERATED FILE — DO NOT EDIT. Source of truth: bot/moderation/<date>-<plugin>-<action>.json. " +
      "THIS DOCUMENT IS NOT SIGNED. The signed statement that produces the deprecate/revoke effects " +
      "is registry/v1/revocations.json; this is the human record beside it, and it also covers yank " +
      "and delist, which are catalogue edits and produce no signed document at all.",
    schema: SCHEMA,
    ...(revocationsSerial !== undefined ? { revocations_serial: revocationsSerial } : {}),
    entries: out,
  };
}
