#!/usr/bin/env node
//
// The moderation run: what `.github/workflows/plugins-moderation.yml` executes
// in each of its four jobs (registry plan M-T3.4).
//
//   node bot/moderation-run.mjs --job list      GET bot/moderation-work, check it
//   node bot/moderation-run.mjs --job commit    compile, walk the holds, write
//   node bot/moderation-run.mjs --job report    POST the results
//   node bot/moderation-run.mjs --job settled   every listed id got a result
//
// `--job` and not `--step`, and the reason is not taste: `bot/tests/workflows.test.mjs`
// reads `--step commit` as the signature of a job that pushes to `signed`, and
// would then refuse this job the `tools/selftest.mjs` gate the plan requires of
// it. A flag name that collides with another file's heuristic is a flag name
// that makes a correct file fail a rule about a different file.
//
// ── THE RULE THIS FILE IS MOSTLY ABOUT, AND WHY IT IS SPLIT IN TWO ──────────
//
// SCOPE-3 binds the READ side: within `/n` only optional members are added and
// readers ignore unknown ones. DEC-7 binds the WRITE side. So:
//
//   * `schema/moderation-work-v1.json` validates the members BOT-80 names and
//     ignores the rest, with one named denylist — `moderator` and
//     `declared_interest` on an `A_*` entry;
//   * every composer takes its inputs from an allowlist of the members BOT-80
//     names for the kind (`bot/lib/compile-decision.mjs`: `allowlisted`,
//     `allowlistedSubmission`), so a member this file ignored on read can
//     never reach git.
//
// **The failure the strict reading produces is silent by construction, and it
// is the reason this file carries the argument rather than a comment saying
// "be careful".** Suppose minice-be publishes a MINOR adding one optional
// member — an item-level `unavailable` is the shape they have already added
// once, a `withheld_since` is the obvious next. Under a strict schema every
// entry in `service_decisions[]` fails at the next run; `list` routes them all
// to `refused`; `report` posts `kind_refused` for each; BOT-81 makes `refused`
// one of the three FINAL results, so each is settled. BOT-84 pages only for a
// decision with NO settled result. MOD-15 alarms on a stage past its bound,
// and a refused decision has no further stage. BOT-82's alarm fires only for a
// refusal code the service does not know, and `kind_refused` is known. So
// `M_YANK`, `M_DELIST` and `M_REVOKE` stop reaching `main` entirely, with a
// GREEN run and a `settled` job that sees a result for every listed id. The
// first person to notice is a moderator wondering why the takedown did not
// land, and re-deciding refuses again.
//
// ── SHADOW IS THE DEFAULT, INCLUDING WHEN NOBODY SAID SO ────────────────────
//
// `shadow === false` and never `!shadow`. `undefined`, `null` and the string
// `"false"` are each an answer this run did not understand, and the silent
// direction has to be the one a missing member produces (BOT-92; ID-71). An
// answer with no `shadow` member is read as shadow AND alerts, so that "we are
// in shadow because we were told to be" and "we are in shadow because we could
// not tell" are never the same log line.
//
// A confirmed hold is the one thing a `shadow: true` answer does not govern.
// It is not work that answer names — a settled `held` result took it off
// BOT-80's list — and its release is driven by the MOD-52 record in git
// (BOT-81). So `commit` still releases it, in shadow and with `list` down. Its
// `applied` or `cancelled` result, though, SETTLES a decision, which BOT-92
// calls state-setting, so `report` posts it only in a run whose list answer is
// `shadow: false` — the next such run, not this one (`resultsToPost`).
//
// ── WHAT THIS FILE DOES NOT DO ─────────────────────────────────────────────
//
//   * It does not count TRUST-26's bound. `bot/lib/takedown-bound.mjs` does,
//     and it imports `stagingListingId` and `triggersOf` from
//     `tools/moderation-coverage.mjs` — a DESK TOOL, outside TRUST-31's hashed
//     set. Importing it here would pull that file into the closure of a bot
//     run, which contract 0.23.0 states is a thirteenth hashed path and a
//     contract MINOR of its own, owed BEFORE that commit lands. So `overBound`
//     arrives as an input, and `compileAll` REFUSES TO GUESS it: with a
//     takedown in the batch and no answer, it throws. Reading an absent input
//     as `false` would apply a takedown the bound should have held, which is
//     the one direction MOD-9 exists to prevent.
//   * It does not push. The workflow's `commit` job runs the gates — both
//     regenerated documents, `tools/selftest.mjs`, `tools/validate.mjs` over
//     the staged tree, MOD-3's backing check — and then commits. This file
//     writes the files and composes the message, so the gates run over a tree
//     and not over a promise.

import fs from "node:fs";
import path from "node:path";

import {
  AUTHOR_CODES,
  REFUSALS,
  REJECT_CODE,
  allowlistedSubmission,
  compileDecision,
} from "./lib/compile-decision.mjs";
import { CODES } from "./lib/codes.mjs";
import {
  decisionCommitMessage,
  recordsOnMain,
  submissionKey,
  trailerLine,
  writeDecisionRecord,
} from "./lib/decisions.mjs";
import {
  readHolds,
  resolveHold,
  resultKey,
  resultsToPost,
} from "./lib/holds.mjs";
import { VERDICT_SCHEMA, runUrl, verdictProblems } from "./lib/alert-verdict.mjs";
import { SOURCE_DIR as MODERATION_DIR } from "./lib/moderation.mjs";
import { POLICY_CODES } from "./lib/policy/constants.mjs";
import { createClient } from "./lib/service.mjs";
import { validate } from "../tools/lib/jsonschema.mjs";
import { REPO_ROOT } from "../tools/lib/sources.mjs";
import { SOURCE_DIR as REVOCATIONS_DIR } from "../tools/lib/revocations.mjs";

/** The registry's check of the service's answer, read by literal path. */
export const SCHEMA_FILE = "schema/moderation-work-v1.json";

/** The body §4.2 names, and the three members BOT-80 gives it. */
export const WORK_SCHEMA = "astra.plugins.bot-moderation-work/1";
export const TOP_MEMBERS = Object.freeze(["shadow", "submissions", "service_decisions"]);

/** The two members an `A_*` entry may not carry, refused BY NAME (n4). */
export const AUTHOR_DENIED_MEMBERS = Object.freeze(["moderator", "declared_interest"]);

/**
 * The one `submissions[]` code that is a moderator's decision, re-exported
 * from where the allowlist that keys on it lives. One definition: a second
 * literal here and a third in the schema would be three answers to "which
 * entries carry a moderator", and the one that drifts is the one the composer
 * reads.
 */
export { REJECT_CODE };

/** BOT-83's interval, and it is the token file's. The cron is derived from it. */
export const MODERATION_INTERVAL_SECONDS = 600;

/** The `list` job fails loudly rather than truncating (registry plan M-T3.4). */
export const MAX_OUTPUT_BYTES = 900 * 1024;

/**
 * Which of §0.8's seven refusals a bad member routes to.
 *
 * The routing is the plan's, and the two rows that are not obvious are the
 * ones worth stating. `plugin_id` → `target_not_in_registry`: a plugin id that
 * is not an id names no listing on any tree, which is the same answer as a
 * listing that is not here. `versions` → `target_changed`: the member names a
 * TARGET, and a target this tree cannot resolve is what that code is for.
 *
 * Anything not in this table — a malformed `decided_at`, a missing required
 * member, the `not` that carries the `A_*` denylist — is `kind_refused`, which
 * is the plan's own catch-all ("severity, action, code, category or kind").
 */
export const REFUSAL_BY_MEMBER = Object.freeze({
  reason: "reason_refused",
  severity: "kind_refused",
  action: "kind_refused",
  code: "kind_refused",
  category: "kind_refused",
  moderator: "kind_refused",
  declared_interest: "kind_refused",
  plugin_id: "target_not_in_registry",
  versions: "target_changed",
});

/**
 * BOT-33's moderation allowlist: every path a moderation commit may touch.
 *
 * A separate list from `bot/publish-apply.mjs`'s, because it is a separate
 * question — that one asks what an INGEST run may write to a stranger's
 * listing, this one asks what a takedown may write. They overlap on
 * `plugins/<id>/` and nowhere else, and merging them would give an ingest run
 * the right to write an advisory.
 */
export const MODERATION_ALLOWLIST = Object.freeze([
  "plugins/",
  `${MODERATION_DIR}/`,
  `${REVOCATIONS_DIR}/`,
  "log/decisions/",
  "state/holds/",
  "registry/v1/",
]);

/** Is this repository-relative path one a moderation commit may write? */
export function allowedPath(rel) {
  const p = String(rel ?? "");
  if (p === "" || p.startsWith("/") || p.split("/").some((s) => s === "" || s === "." || s === "..")) return false;
  return MODERATION_ALLOWLIST.some((prefix) => p.startsWith(prefix));
}

const readJson = (file) => {
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return undefined;
  }
};

/** `schema/moderation-work-v1.json`, read from disk so the file is the statement. */
export function workSchema(root = REPO_ROOT) {
  const doc = readJson(path.join(root, ...SCHEMA_FILE.split("/")));
  if (doc === null) {
    throw new Error(
      `${SCHEMA_FILE} is not on this tree. It is the registry's only check of the service's answer, and a run ` +
      "that could not read it would accept whatever arrived — which is the substitution TRUST-31's hashed set " +
      "puts this file inside to refuse",
    );
  }
  if (doc === undefined) throw new Error(`${SCHEMA_FILE} is present and unreadable`);
  return doc;
}

/** The entry's own member list, out of the schema, for a canary to compare. */
export function schemaMembers(def, root = REPO_ROOT) {
  const doc = workSchema(root);
  const node = def === null ? doc : doc.$defs?.[def];
  if (!node) throw new Error(`${SCHEMA_FILE} carries no $defs.${def}`);
  return Object.keys(node.properties ?? {}).filter((m) => m !== "$comment" && m !== "schema").sort();
}

// ── the list job ────────────────────────────────────────────────────────────

/**
 * BOT-92's mode, and whether the answer actually said it.
 *
 * Three states and not two: told shadow, told live, and could not tell. The
 * third is shadow with an alarm, because a run that cannot tell which mode it
 * is in must not be able to look, in a log or in a result, like a run that was
 * told `false`.
 */
export function readShadow(body) {
  const value = body?.shadow;
  if (value === true) return { shadow: true, stated: true, alert: null };
  if (value === false) return { shadow: false, stated: true, alert: null };
  return {
    shadow: true,
    stated: false,
    alert:
      `the list answer carries \`shadow: ${JSON.stringify(value)}\`, which is not a boolean. It is read as ` +
      "shadow, so this run commits nothing for the work it names and posts nothing for it, and it alerts: " +
      "`shadow === false` is the only thing that means live (BOT-92; ID-71)",
  };
}

/** The member a validator error is about, or null for a whole-entry problem. */
export function memberOfProblem(problem) {
  const m = /^\$(?:\.([A-Za-z_][A-Za-z0-9_]*))/.exec(String(problem?.path ?? ""));
  return m ? m[1] : null;
}

/**
 * One §0.8 refusal for a list of validator errors, and the reason it is one
 * rather than a list.
 *
 * BOT-81 gives a decision exactly one final result, so a decision with four
 * bad members still gets one code. The FIRST problem decides, in the
 * validator's own order, so two runs over the same entry pick the same code —
 * a refusal that varied with map iteration order would make BOT-82's
 * idempotency key, which carries the outcome, disagree with itself.
 */
export function refusalForProblems(problems) {
  const first = problems[0];
  const member = memberOfProblem(first);
  const code = (member && REFUSAL_BY_MEMBER[member]) || "kind_refused";
  const why = problems
    .map((p) => `${p.path} ${p.message}`)
    .join("; ");
  return { code, why, member };
}

/** Every FLOW-13 code the bot's own tables define, which is the one answer. */
export function knownCodes() {
  return new Set([...Object.keys(CODES), ...Object.keys(POLICY_CODES)]);
}

/**
 * Check one entry, and say what it is.
 *
 * The `A_*` denylist runs BEFORE the schema, and only so that the refusal can
 * NAME the member. The schema states the same rule with `not`, which cannot
 * say which member tripped it; running both means the file is a correct
 * statement on its own and the moderator is told something they can act on.
 */
export function checkServiceDecision(entry, { root = REPO_ROOT, schema = null } = {}) {
  const doc = schema ?? workSchema(root);
  const def = doc.$defs?.serviceDecision;
  const bound = { ...def, $defs: doc.$defs };

  if (AUTHOR_CODES.includes(entry?.code)) {
    for (const member of AUTHOR_DENIED_MEMBERS) {
      if (Object.hasOwn(entry ?? {}, member)) {
        return {
          ok: false,
          code: "kind_refused",
          why:
            `an \`${entry.code}\` entry carries \`${member}\`, and an author action has no moderator. DEC-14 and ` +
            "MOD-41 forbid one reaching the public log, and 0.12.0's wording would have committed a moderator's " +
            "handle under an author's yank (BOT-80; n4)",
        };
      }
    }
  }

  const problems = validate(bound, entry, "$");
  if (problems.length) return { ok: false, ...refusalForProblems(problems) };
  return { ok: true };
}

/** The same, for a `submissions[]` entry. */
export function checkSubmission(entry, { root = REPO_ROOT, schema = null } = {}) {
  const doc = schema ?? workSchema(root);
  const bound = { ...doc.$defs?.submission, $defs: doc.$defs };
  const problems = validate(bound, entry, "$");
  if (problems.length) return { ok: false, ...refusalForProblems(problems) };

  const known = knownCodes();
  if (entry.code !== REJECT_CODE && !known.has(entry.code)) {
    return {
      ok: false,
      code: "kind_refused",
      why:
        `\`${entry.code}\` is neither ${REJECT_CODE} nor a FLOW-13 reason code this bot's own tables define. ` +
        "The vocabulary is `bot/lib/codes.mjs` and `POLICY_CODES`, which is also what the token file's " +
        "`flow13_table` is generated from, so a code outside it is one no author would ever be shown",
    };
  }
  return { ok: true };
}

/**
 * The whole answer: what survives, what is refused, and what fails the run.
 *
 * An entry with no valid id is NOT a refusal. A refusal is posted against an
 * id, so an entry whose id is unreadable has nothing to post against and no
 * way to leave BOT-80's list — it would be re-listed, re-refused and
 * re-unpostable every ten minutes, for ever, in silence. It alerts and fails
 * the run instead.
 */
export function checkWorkAnswer(body, { root = REPO_ROOT } = {}) {
  const doc = workSchema(root);
  const out = {
    shadow: true,
    stated: false,
    alerts: [],
    entries: [],
    submissions: [],
    refused: [],
    fatal: [],
  };

  const mode = readShadow(body);
  out.shadow = mode.shadow;
  out.stated = mode.stated;
  if (mode.alert) out.alerts.push({ cause: "shadow", detail: mode.alert });

  const topProblems = validate(
    { type: doc.type, required: doc.required, properties: doc.properties, additionalProperties: true, $defs: doc.$defs },
    body,
    "$",
  ).filter((p) => p.path === "$" || /^\$\.(shadow|submissions|service_decisions)$/.test(p.path));
  if (topProblems.length) {
    out.fatal.push(
      `the list answer is not \`${WORK_SCHEMA}\`: ${topProblems.map((p) => `${p.path} ${p.message}`).join("; ")}. ` +
      "This is the body itself and not one entry of it, so there is no id to refuse against",
    );
    return out;
  }

  const seen = new Set();
  for (const entry of body.service_decisions) {
    const id = entry?.service_decision_id;
    if (typeof id !== "string" || !id) {
      out.fatal.push("a `service_decisions[]` entry carries no `service_decision_id`, so no result can name it");
      continue;
    }
    if (seen.has(id)) {
      // A duplicate list. Not a refusal: the second copy is the same decision,
      // and refusing it would settle the decision the first copy is about.
      out.alerts.push({ cause: "duplicate", detail: `${id} appears twice in one list answer; the second is dropped` });
      continue;
    }
    seen.add(id);
    const verdict = checkServiceDecision(entry, { root, schema: doc });
    if (verdict.ok) out.entries.push(entry);
    else out.refused.push({ service_decision_id: id, code: verdict.code, why: verdict.why });
  }

  const seenSubmissions = new Set();
  for (const entry of body.submissions) {
    const id = entry?.submission_id;
    if (typeof id !== "string" || !id) {
      out.fatal.push("a `submissions[]` entry carries no `submission_id`, so no result can name it");
      continue;
    }
    if (seenSubmissions.has(id)) {
      out.alerts.push({ cause: "duplicate", detail: `${id} appears twice in one list answer; the second is dropped` });
      continue;
    }
    seenSubmissions.add(id);
    const verdict = checkSubmission(entry, { root, schema: doc });
    if (verdict.ok) out.submissions.push(entry);
    else out.refused.push({ submission_id: id, code: verdict.code, why: verdict.why });
  }

  for (const code of out.refused) {
    if (!REFUSALS.includes(code.code)) {
      out.fatal.push(`${code.code} is not one of §0.8's seven service-decision refusals`);
    }
  }
  return out;
}

/** What the `list` job prints: ids and codes, and nothing else (PRIV-2). */
export function listSummary(checked) {
  const lines = [];
  lines.push(`shadow ${checked.shadow}${checked.stated ? "" : " (not stated; read as shadow)"}`);
  for (const e of checked.entries) lines.push(`work   ${e.service_decision_id} ${e.code}`);
  for (const s of checked.submissions) lines.push(`work   ${s.submission_id} ${s.code}`);
  for (const r of checked.refused) {
    lines.push(`refuse ${r.service_decision_id ?? r.submission_id} ${r.code}`);
  }
  const text = `${lines.join("\n")}\n`;
  if (Buffer.byteLength(text, "utf8") > MAX_OUTPUT_BYTES) {
    throw new Error(
      `the list summary is ${Buffer.byteLength(text, "utf8")} bytes and the bound is ${MAX_OUTPUT_BYTES}. A run ` +
      "that truncated it would report a shorter list than it acted on, and `settled` compares the two",
    );
  }
  return text;
}

// ── the commit job ──────────────────────────────────────────────────────────

/** Does this batch hold anything TRUST-26's bound could hold? */
export function hasTakedown(entries) {
  return entries.some((e) => ["M_YANK", "M_DELIST", "M_DEPRECATE", "M_REVOKE", "A_YANK", "A_REMOVAL_REQUEST"].includes(e?.code));
}

/**
 * Compile every surviving entry.
 *
 * `overBound` is `null` when nobody measured it, and that is not the same as
 * `false`. See the header: the count lives in `bot/lib/takedown-bound.mjs`,
 * which reaches a desk tool outside TRUST-31's set, so wiring it in here is a
 * contract MINOR of its own. Until then a batch with a takedown in it and no
 * measured bound FAILS THE RUN.
 */
export function compileAll(entries, { root = REPO_ROOT, overBound = null } = {}) {
  if (overBound === null && hasTakedown(entries)) {
    throw new Error(
      "this batch holds a takedown and TRUST-26's bound was not measured for this run. `overBound` is not " +
      "defaulted to false, because false is the direction that APPLIES a takedown MOD-9 should have held: over " +
      "the bound every takedown waits for an operator's MOD-52 confirmation, and a run that guessed would take " +
      "software off machines that the bound exists to protect. The count is `bot/lib/takedown-bound.mjs`'s and " +
      "importing it here pulls `tools/moderation-coverage.mjs` — a desk tool — into a bot run's import closure, " +
      "which contract 0.23.0 prices as a thirteenth TRUST-31 path and a MINOR before that commit lands",
    );
  }
  const compiled = [];
  const refused = [];
  const held = [];
  for (const entry of entries) {
    const result = compileDecision(entry, { root, overBound: overBound === true });
    if (result.outcome === "refused") refused.push(result);
    else if (result.outcome === "held") held.push(result);
    else compiled.push(result);
  }
  return { compiled, refused, held };
}

/**
 * Turn compiled edits, log entries and records into files on the tree.
 *
 * Every path goes through `allowedPath` before it is opened, and a `set` edit
 * refuses a file that is not there. Both are the same rule from two sides: the
 * compiler derives its edits from git, so an edit naming a file this tree does
 * not have is a compiler that read a different tree than the one being
 * written — which is `target_changed`'s whole case, arriving too late to be
 * one.
 */
export function applyCompiled(compiled, { root = REPO_ROOT } = {}) {
  const touched = [];
  const write = (rel, doc) => {
    if (!allowedPath(rel)) {
      throw new Error(`a compiled artefact names ${rel}, which BOT-33's moderation allowlist does not carry`);
    }
    const full = path.join(root, ...rel.split("/"));
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, `${JSON.stringify(doc, null, 2)}\n`);
    touched.push(rel);
  };

  for (const result of compiled) {
    for (const edit of result.edits ?? []) {
      if (edit.op === "add") { write(edit.file, edit.doc); continue; }
      if (edit.op !== "set") throw new Error(`unknown edit op ${JSON.stringify(edit.op)}`);
      const full = path.join(root, ...edit.file.split("/"));
      const doc = readJson(full);
      if (doc === null) {
        throw new Error(
          `${edit.file} is not on this tree and a \`set\` edit was compiled for it. The compiler derives its ` +
          "edits from git, so this means the tree moved between the compile and the write",
        );
      }
      if (doc === undefined) throw new Error(`${edit.file} is unreadable`);
      write(edit.file, { ...doc, [edit.member]: edit.value });
    }
    for (const entry of result.log ?? []) write(entry.file, entry.doc);
    for (const record of result.records ?? []) {
      const placed = writeDecisionRecord({
        key: record.key,
        record: record.record ?? record,
        root,
      });
      if (placed.written) touched.push(placed.path);
    }
  }
  return touched;
}

/**
 * BOT-30's terminal record for a stop or an `M_REJECT`.
 *
 * The entry goes through `allowlistedSubmission` FIRST. That is the write half
 * of M-1 for the third entry kind: a stop is the author's own act through the
 * panel and carries no moderator, so a stop entry arriving with a moderator
 * handle must not be able to put one into a terminal record — the same failure
 * n4 names for `A_*`, one record shape over.
 */
export function terminalSubmissionRecord(entry, { root = REPO_ROOT, existing = null, now = new Date() } = {}) {
  const e = allowlistedSubmission(entry);
  // **A stop carries no `decided_at` and DEC-7 requires one**, which is not an
  // omission in BOT-80: an `M_REJECT` is a moderator's decision and has a time
  // the panel recorded, and a stop is the author pressing stop — the moment
  // that matters for the record is the moment the registry acted on it, which
  // is this run. Taking the run's clock for an `M_REJECT` would be worse than
  // pointless: the record's PATH is derived from `decided_at`, so it would
  // file a moderator's decision under the month the bot happened to notice.
  const decidedAt = e.code === REJECT_CODE
    ? e.decided_at
    : `${now.toISOString().slice(0, 19)}Z`;
  const record = {
    decided_at: decidedAt,
    actor: e.code === REJECT_CODE ? "moderator" : "author",
    trigger: e.code === REJECT_CODE ? "moderation" : "stop",
    submission_id: e.submission_id,
    repo: e.repo,
    repository_id: e.service_repository_id,
    tag: e.tag,
    state: e.code === REJECT_CODE ? "refused" : "stopped",
    reasons: [e.code],
    ...(e.category !== undefined ? { category: e.category } : {}),
    ...(e.moderator !== undefined ? { moderator: e.moderator } : {}),
    ...(e.declared_interest !== undefined ? { declared_interest: e.declared_interest } : {}),
    ...(Array.isArray(e.fingerprints) && e.fingerprints.length ? { fingerprint: e.fingerprints[0] } : {}),
  };
  for (const [member, value] of Object.entries(record)) {
    if (value === undefined) {
      throw new Error(
        `a terminal record for ${e.submission_id} has no \`${member}\`. BOT-30 writes the record that ends the ` +
        "submission, and a record short of a member the schema requires is one `tools/validate.mjs` refuses " +
        "after the push rather than before it",
      );
    }
  }
  return writeDecisionRecord({
    key: submissionKey({ submission_id: e.submission_id }),
    record,
    root,
    existing: existing ?? recordsOnMain(root),
  });
}

/**
 * The commit's trailer block.
 *
 * **`Decided-At:` is BOT-37's fifth trailer**, and the grammar that holds it to
 * §0.7's timestamp is `bot/lib/decisions.mjs`'s, reached through `trailerLine`.
 * That import is the point of this paragraph. Until the trailer was declared,
 * this file carried a `TIMESTAMP_RE` of its own and rendered `Decided-At:`
 * AFTER `decisionCommitMessage` had composed and scanned the four it knew — so
 * the one trailer added after the privacy scanner was written was the one
 * trailer the privacy scanner never saw, and the check that should have said so
 * (`privacyFindings`'s `E_PRIV_UNDECLARED_TRAILER`) was never handed the name.
 * A second copy of a grammar is only ever as good as the day it was copied, and
 * this one was the sole thing standing between a free-text trailer and a value
 * PRIV-2 refuses.
 *
 * `renderTrailers` still cannot do this job: it renders one of each trailer, and
 * BOT-73's single commit carries a `Decision:`, a `Service-Decision:` and a
 * `Decided-At:` per decision. What moved is the grammar, not the loop.
 */
export function composeTrailers({ run, decisions = [] }) {
  const lines = [];
  if (!run) throw new Error("BOT-37: every bot commit carries a `Run:` trailer");
  lines.push(trailerLine("Run", run));
  for (const d of decisions) {
    if (d.decision_id) lines.push(trailerLine("Decision", d.decision_id));
    lines.push(trailerLine("Service-Decision", d.service_decision_id));
    if (d.decided_at !== undefined) lines.push(trailerLine("Decided-At", d.decided_at));
  }
  return lines;
}

/**
 * One commit for the whole run (BOT-73), or none at all.
 *
 * `edits` are applied by the caller — this composes the message and reports
 * what would be touched, so the workflow's gates run over a real tree. Every
 * path is checked against BOT-33's moderation allowlist here rather than after
 * the push: a path outside it is a bug in a compiler, and the place to stop it
 * is before `git add`.
 */
export function composeCommit({ compiled, held = [], submissions = [], run, subject = null }) {
  const paths = new Set();
  const decisions = [];
  for (const r of compiled) {
    for (const e of r.edits ?? []) paths.add(e.file);
    for (const l of r.log ?? []) paths.add(l.file);
    decisions.push({
      service_decision_id: r.service_decision_id,
      decided_at: r.trailers?.["Decided-At"],
    });
  }
  for (const h of held) {
    paths.add(`state/holds/${h.service_decision_id}.json`);
  }
  for (const s of submissions) if (s.path) paths.add(s.path);

  const bad = [...paths].filter((p) => !allowedPath(p));
  if (bad.length) {
    throw new Error(
      `a moderation commit would touch ${bad.join(", ")}, which BOT-33's moderation allowlist does not carry ` +
      `(${MODERATION_ALLOWLIST.join(", ")}). A takedown writes listings, log entries, advisories, decision ` +
      "records and holds, and a path outside that set is a compiler writing somewhere nobody reviewed",
    );
  }

  if (paths.size === 0) return { message: null, paths: [], decisions };

  const what = [
    compiled.length ? `${compiled.length} decision(s)` : null,
    held.length ? `${held.length} hold(s)` : null,
    submissions.length ? `${submissions.length} terminal record(s)` : null,
  ].filter(Boolean).join(", ");

  const message = decisionCommitMessage({
    subject: subject ?? `registry: moderation (${what})`,
    body: [...paths].sort().map((p) => `- ${p}`).join("\n"),
    run,
  });
  // `decisionCommitMessage` renders one of each of BOT-37's five; the
  // per-decision triples are appended here, after its PRIV-2 scan of the
  // subject and body, and through the same `trailerLine` grammar.
  const extra = composeTrailers({ run, decisions }).slice(1);
  return {
    message: extra.length ? `${message.trimEnd()}\n${extra.join("\n")}\n` : message,
    paths: [...paths].sort(),
    decisions,
  };
}

// ── holds, which run whether or not `list` answered ──────────────────────────

/**
 * Walk every hold under M-T3.3, even when `list` failed.
 *
 * A confirmed hold is not work the list answer names: a settled `held` result
 * took it off BOT-80's list, and its release is driven by the MOD-52 record in
 * git. So this runs on `if: always() && !cancelled()`, with the list answer's
 * `shadow` used only to decide whether a RESULT may be posted.
 */
export function walkHolds({ root = REPO_ROOT, now = new Date(), shadow = true, delistedPlugins = [], coverageRed = false } = {}) {
  const out = { released: [], cancelled: [], waiting: [], pending: [] };
  for (const hold of readHolds(root)) {
    const verdict = resolveHold(hold, { now, shadow, delistedPlugins, coverageRed });
    const id = hold.entry?.service_decision_id ?? null;
    if (verdict.act === "wait" || !id) {
      out.waiting.push({ service_decision_id: id, reason: verdict.reason });
      continue;
    }
    const row = { service_decision_id: id, act: verdict.act, outcome: verdict.result, reason: verdict.reason };
    (verdict.act === "cancel" ? out.cancelled : out.released).push(row);
    out.pending.push({ service_decision_id: id, outcome: verdict.result, commit: null });
  }
  return out;
}

// ── the report job ──────────────────────────────────────────────────────────

/**
 * BOT-81: at most one `held` and exactly one final result per decision.
 *
 * Both halves are asserted rather than assumed. A decision that got a `held`
 * AND a final result in one run would settle at the service under whichever
 * arrived last, and the two say opposite things about whether a moderator
 * should expect anything more.
 */
export function resultsFor({ compiled = [], refused = [], held = [], holds = { pending: [] }, commit = null, shadow = true }) {
  const results = [];
  for (const r of compiled) {
    results.push({ service_decision_id: r.service_decision_id, outcome: "applied", commit, refusal_code: null });
  }
  for (const r of refused) {
    results.push({ service_decision_id: r.service_decision_id, outcome: "refused", commit: null, refusal_code: r.refusal });
  }
  for (const h of held) {
    results.push({ service_decision_id: h.service_decision_id, outcome: "held", commit: null, refusal_code: null });
  }
  for (const p of holds.pending ?? []) {
    results.push({ service_decision_id: p.service_decision_id, outcome: p.outcome, commit: commit ?? p.commit, refusal_code: null });
  }

  // BOT-82's key first, and BOT-81's count second, in that order. A run that
  // saw one release twice — a retry after a crash between the commit and the
  // post is exactly that shape — has ONE result to send, and counting before
  // deduplicating would turn the retry this estate is built to survive into a
  // failed run.
  const deduped = [];
  const keys = new Set();
  for (const r of results) {
    const k = resultKey(r);
    if (keys.has(k)) continue;
    keys.add(k);
    deduped.push(r);
  }
  results.length = 0;
  results.push(...deduped);

  const byId = new Map();
  for (const r of results) {
    const list = byId.get(r.service_decision_id) ?? [];
    list.push(r);
    byId.set(r.service_decision_id, list);
  }
  for (const [id, list] of byId) {
    const finals = list.filter((r) => r.outcome !== "held");
    if (finals.length > 1) {
      throw new Error(
        `${id} would get ${finals.length} final results in one run (${finals.map((r) => r.outcome).join(", ")}). ` +
        "BOT-81 gives a decision exactly one, and two settle at the service under whichever arrives last",
      );
    }
    if (list.filter((r) => r.outcome === "held").length > 1) {
      throw new Error(`${id} would get two \`held\` results in one run; BOT-81 allows at most one`);
    }
  }

  // BOT-92. A `held` result is not state-setting — it says the registry has
  // not decided — so it is posted in shadow; `applied`, `cancelled` and
  // `refused` are, and `resultsToPost` withholds them until a `shadow: false`
  // answer.
  //
  // `withheld` is computed from the LIVE call and not from the shadow one, and
  // that is the difference between a report that says what it is holding back
  // and one that is simply empty. A shadow run whose `withheld` list was also
  // empty would be indistinguishable, in a log, from a run with nothing to
  // post — which is the state this whole mode has to stay visible during.
  const holdResults = results.filter((r) => r.outcome === "held");
  const settling = results.filter((r) => r.outcome !== "held");
  const sendable = resultsToPost(settling, { shadow: false });
  return shadow === false
    ? { post: [...holdResults, ...sendable], withheld: [] }
    : { post: holdResults, withheld: sendable };
}

// ── the settled job ─────────────────────────────────────────────────────────

/** Every listed id that got no result at all, which fails the run and alerts. */
export function unsettled({ listed = [], results = [], listFailed = false }) {
  if (listFailed) {
    return {
      ok: false,
      why: "the `list` job failed, so this run cannot say that every decision the service named got a result",
      ids: [],
    };
  }
  const answered = new Set(results.map((r) => r.service_decision_id));
  const missing = listed.filter((id) => !answered.has(id));
  return {
    ok: missing.length === 0,
    why: missing.length
      ? `${missing.length} listed decision(s) got no result: ${missing.join(", ")}. BOT-84 pages only for a ` +
        "decision with no settled result, and this is the run that can see one"
      : null,
    ids: missing,
  };
}

// ── the two alert jobs ──────────────────────────────────────────────────────

/**
 * MOD-8's alarms, derived from the LIST entry and not from the compile.
 *
 * That is what lets the alert precede the push as a property of the GRAPH
 * rather than of a script's control flow. TRUST-14 requires the alarm to go
 * out in the run that first reads the event and BEFORE any commit that
 * publishes, and a GitHub environment is a job-level property — there is no
 * way to put one step of `commit` in `alerts`. So `alert` is its own job,
 * `needs: [list]`, and `commit` needs it; the same shape `plugins-ingest.yml`
 * uses for exactly this reason.
 *
 * It is derivable: MOD-8 alerts on every advisory entered and every hold
 * entered, and both are decided by the entry's `code`, `action` and `severity`
 * plus the tree — never by the advisory's own text. An alarm that named the
 * advisory id would have to wait for the compile, which is after the push.
 */
export function alarmsFor(entries) {
  const out = [];
  for (const e of entries) {
    if (e.code === "M_DEPRECATE" || e.code === "M_REVOKE") {
      out.push({ code: `MOD_8_ADVISORY_${String(e.action ?? "warn").toUpperCase()}`, id: e.plugin_id });
    }
    if (e.code === "M_REVOKE" && e.action === "disable") {
      out.push({ code: "MOD_9_DISABLE_CONFIRMATION", id: e.plugin_id });
    }
    if (e.code === "M_RELIST" || e.code === "M_UNREVOKE") {
      out.push({ code: "MOD_9_REVERSAL_HOLD", id: e.plugin_id });
    }
  }
  return out;
}

/** An `astra.registry.alert-verdict/1`, refused here rather than at the channel. */
export function composeVerdict({ check, status, codes = [], ids = [], run = null }) {
  const verdict = {
    schema: VERDICT_SCHEMA,
    check,
    status,
    ...(codes.length ? { codes: [...new Set(codes)].sort() } : {}),
    ...(ids.length ? { ids: [...new Set(ids)].sort() } : {}),
    ...(run ? { run } : {}),
  };
  const problems = verdictProblems(verdict);
  if (problems.length) {
    throw new Error(
      `this verdict may not be sent: ${problems.join("; ")}. An alarm composed here and refused at the channel ` +
      "is an alarm nobody receives, and the run that needed it is the run that finds out",
    );
  }
  return verdict;
}

// ── the CLI ─────────────────────────────────────────────────────────────────

const arg = (argv, name) => {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
};

export async function main(argv = [], { env = process.env, log = console, fetchImpl = fetch } = {}) {
  const job = arg(argv, "--job");
  const root = arg(argv, "--registry-dir") ?? REPO_ROOT;

  if (job === "list") {
    const client = createClient({ workflow: "moderation", env, log, fetchImpl });
    const answer = await client.call("moderationWork");
    if (!answer.ok) {
      log.error("::error::the moderation work list could not be read; this run compiles nothing new");
      return 1;
    }
    const checked = checkWorkAnswer(answer.body, { root });
    process.stdout.write(listSummary(checked));
    for (const a of checked.alerts) log.error(`::warning::${a.cause}: ${a.detail}`);
    for (const f of checked.fatal) log.error(`::error::${f}`);
    return checked.fatal.length ? 1 : 0;
  }

  if (job === "commit") {
    // **No network, by construction.** This job holds `contents: write` and
    // therefore no bot token (BOT-2); it reads `needs.list.outputs`, re-checked
    // here against the same schema, plus `main`. Nothing below reaches `fetch`,
    // and `bot/tests/moderation-run.test.mjs` runs it with `fetch` replaced by
    // a throwing stub rather than trusting this sentence.
    const out = arg(argv, "--out") ?? "moderation";
    const entries = JSON.parse(env.ASTRA_ENTRIES || "[]");
    const submissions = JSON.parse(env.ASTRA_SUBMISSIONS || "[]");
    const shadow = env.ASTRA_SHADOW === "false" ? false : true;
    const overBound = env.ASTRA_OVER_BOUND === undefined || env.ASTRA_OVER_BOUND === ""
      ? null
      : env.ASTRA_OVER_BOUND === "true";

    // Re-checked, never trusted: `list` is a different job and its outputs
    // travel through the run's metadata. Re-reading them through the same
    // schema costs a millisecond and closes the door between the two jobs.
    const recheck = checkWorkAnswer(
      { shadow, submissions, service_decisions: entries },
      { root },
    );
    if (recheck.fatal.length) {
      for (const f of recheck.fatal) log.error(`::error::${f}`);
      return 1;
    }

    const compiledAll = compileAll(recheck.entries, { root, overBound });
    const written = applyCompiled(compiledAll.compiled, { root });
    const terminal = [];
    const existing = recordsOnMain(root);
    for (const s of recheck.submissions) terminal.push(terminalSubmissionRecord(s, { root, existing }));

    const holds = walkHolds({ root, shadow });
    const commit = composeCommit({
      compiled: compiledAll.compiled,
      held: compiledAll.held,
      submissions: terminal,
      run: env.GITHUB_RUN_ID ?? "0",
    });

    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, "results.json"), `${JSON.stringify({
      shadow,
      compiled: compiledAll.compiled.map((r) => r.service_decision_id),
      refused: compiledAll.refused.map((r) => ({ service_decision_id: r.service_decision_id, refusal: r.refusal })),
      held: compiledAll.held.map((r) => ({ service_decision_id: r.service_decision_id, held_for: r.held_for })),
      holds,
      written,
      terminal,
    }, null, 2)}\n`);
    if (commit.message) fs.writeFileSync(path.join(out, "commit-message.txt"), commit.message);
    fs.writeFileSync(path.join(out, "paths.txt"), `${commit.paths.join("\n")}\n`);
    log.log(`ok    ${compiledAll.compiled.length} compiled, ${compiledAll.refused.length} refused, ` +
      `${compiledAll.held.length} held, ${holds.released.length} released, ${holds.cancelled.length} cancelled`);
    if (shadow) {
      log.log("note  shadow: nothing new is committed for the work this answer names, and nothing is posted for it");
    }
    return 0;
  }

  if (job === "report") {
    const state = JSON.parse(fs.readFileSync(arg(argv, "--results") ?? "moderation/results.json", "utf8"));
    const { post, withheld } = resultsFor({
      compiled: state.compiled.map((id) => ({ service_decision_id: id })),
      refused: state.refused,
      held: state.held,
      holds: state.holds,
      commit: env.ASTRA_MAIN_COMMIT ?? null,
      shadow: state.shadow !== false,
    });
    for (const w of withheld) {
      log.log(`hold  ${w.service_decision_id} ${w.outcome} is not posted under a shadow answer (BOT-92); the next ` +
        "run answered shadow: false posts it once, and BOT-82's key settles a repeat as duplicate");
    }
    if (state.shadow !== false) {
      log.log(`note  shadow: ${post.length} held result(s) posted, ${withheld.length} settling result(s) withheld`);
    }
    const client = createClient({ workflow: "moderation", env, log, fetchImpl });
    for (const r of post) {
      await client.call("serviceDecisionResult", {
        service_decision_id: r.service_decision_id,
        outcome: r.outcome,
        commit: r.commit,
        refusal_code: r.refusal_code,
      });
    }
    return 0;
  }

  if (job === "alarms") {
    // MOD-8's alarms for the work `list` named, composed into a verdict. An
    // EMPTY list here is a green verdict and not a skipped step: an alert job
    // that sent nothing when there was nothing to send is indistinguishable
    // from one that sent nothing because it was broken.
    const entries = JSON.parse(arg(argv, "--entries") || "[]");
    const alarms = alarmsFor(entries);
    const verdict = composeVerdict({
      check: arg(argv, "--check") ?? "moderation-run",
      status: alarms.length ? "red" : "green",
      codes: alarms.map((a) => a.code),
      ids: alarms.map((a) => a.id).filter(Boolean),
      run: runUrl(env),
    });
    fs.writeFileSync(arg(argv, "--out") ?? "verdict.json", `${JSON.stringify(verdict, null, 2)}\n`);
    log.log(`ok    ${alarms.length} MOD-8 alarm(s) for ${entries.length} entr(ies)`);
    return 0;
  }

  if (job === "verdict") {
    // Both `alerts` jobs compose their verdict here rather than in a shell
    // heredoc. `verdictProblems` then refuses at composition what the channel
    // would refuse at send time — the difference being that this refusal is
    // red in a job somebody is reading, and that one is an alarm nobody got.
    const out = arg(argv, "--out") ?? "verdict.json";
    const check = arg(argv, "--check") ?? "moderation-run";
    const codes = JSON.parse(env.ASTRA_VERDICT_CODES || "[]");
    const ids = JSON.parse(env.ASTRA_VERDICT_IDS || "[]");
    const verdict = composeVerdict({
      check,
      status: codes.length ? "red" : "green",
      codes,
      ids,
      run: runUrl(env),
    });
    fs.writeFileSync(out, `${JSON.stringify(verdict, null, 2)}\n`);
    log.log(`ok    ${out}: ${verdict.status}, ${codes.length} code(s)`);
    return 0;
  }

  if (job === "settled") {
    const listed = JSON.parse(env.ASTRA_LISTED_IDS || "[]");
    const results = JSON.parse(env.ASTRA_RESULTS || "[]");
    const verdict = unsettled({ listed, results, listFailed: env.ASTRA_LIST_FAILED === "true" });
    if (!verdict.ok) {
      log.error(`::error::${verdict.why}`);
      return 1;
    }
    log.log(`ok    every one of ${listed.length} listed decision(s) has a result`);
    return 0;
  }

  throw new Error(`\`--job ${JSON.stringify(job)}\` is not one of list, commit, report, settled`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`FAIL  ${e.message}`);
      process.exit(2);
    },
  );
}
