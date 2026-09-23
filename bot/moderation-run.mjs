#!/usr/bin/env node
//
// The moderation run: what `.github/workflows/plugins-moderation.yml` executes
// in each of its four jobs (registry plan M-T3.4).
//
//   node bot/moderation-run.mjs --job list      GET bot/moderation-work, check it
//   node bot/moderation-run.mjs --job history   (in `list`) POST the results history
//                                               decided; hand on what the service settled
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
// **Under `shadow: true` the work that answer names leaves NO trace in git and
// NO result at the service** (BOT-92: "commit nothing for the work that answer
// names … and post no state-setting result"; its Check: "a run with no commit
// for that work and no posted result"). That is four things, and until
// 2026-09-22 this file withheld only the last of them:
//
//   * no compiled artefact — listing edit, log entry, advisory, decision
//     record. The job wrote and listed all of them in shadow and then printed
//     "nothing new is committed", and the workflow's own `git add`/`git commit`
//     lines committed the takedown (measured on a fixture M_DELIST);
//   * no hold entry. Entering one is a commit for the decision the answer
//     names, and BOT-81 has the `held` result name that commit, so there is
//     no hold in shadow that is not a commit in shadow;
//   * no terminal record for a stop or an `M_REJECT` (BOT-30);
//   * no result of any kind, `held` included. A `held` result takes the
//     decision off BOT-80's list (BOT-81's Why), which is a state move; the
//     plan's M-T3.4 says `report` posts "nothing at all" for listed work in
//     shadow, and B-T3.5 watches its own suite by posting a `held` under a
//     shadow lease. So the decision stays listed — ID-71 has the service change
//     no state in shadow anyway — and the first live run holds it for real,
//     with `held_at` from that run and not from a shadow run days earlier.
//
// The entries are still COMPILED, for timing (OPEN-OPS-13), and what the run
// would have done goes to `results.json` as `shadow_withheld`: ids and kinds,
// never a result `report` could post.
//
// A confirmed hold is the one thing a `shadow: true` answer does not govern.
// It is not work that answer names — a settled `held` result took it off
// BOT-80's list — and its release is driven by the MOD-52 record in git
// (BOT-81). So `commit` walks the holds in shadow and with `list` down, and
// M-T3.3's release, once built, is committed there too. Its `applied` or
// `cancelled` result, though, SETTLES a decision, which BOT-92 calls
// state-setting, so `report` posts it only in a run whose list answer is
// `shadow: false` — the next such run, not this one (`resultsToPost`).
//
// **And once, not for ever** (ops entry 100). A hold ended by a commit in
// history — a hand deletion, a release or cancel commit — was re-derived from
// that commit and re-posted on every live run, because nothing here recorded
// that the service had accepted it. Now the `list` job posts those results
// before `commit` (`--job history`: each names a commit already on `main`, so
// none waits for this run's push), hands on the ones the service ANSWERED
// `accepted` or `duplicate`, and `commit` records them in
// `state/moderation-settled.json`; the walk skips a recorded one. Anything
// else — a 5xx, a timeout, a shadow answer, a missing or unreadable record —
// leaves it to be posted again. `bot/lib/settled.mjs` carries the argument
// and what a forged row costs.
//
// **The release commit itself is not built** (M-T3.3: "a release commit
// applies the held decision from the hold entry, writes the log entry, deletes
// the entry and its confirm record"). Nothing here applies a held decision or
// deletes an entry, so a hold that is DUE is refused by name (`walkHolds`'s
// `due`, alert `hold_end_not_built`) rather than reported `applied` or
// `cancelled` against a commit that did neither — and it is not released, in
// shadow or out of it (ops entry 99).
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
//     documents held to their generators' `--check`, `tools/validate.mjs`
//     over the staged tree, `tools/selftest.mjs`, MOD-3's backing check — and
//     then commits. This file writes the files, REGENERATES the two documents
//     (`regenerateDocuments`) and composes the message, so the gates run over a
//     tree and not over a promise, and what `paths.txt` lists is what this
//     file wrote (ops entries 79 and 102).
//   * It does not compose a result in the `commit` job. BOT-81 has an
//     `applied`, and a `held` for a hold this run entered, name the commit the
//     workflow's `apply` step pushes after this file has exited; `report`
//     composes them, from this job's `results.json` and that commit, both of
//     which the step hands on as job outputs.

import { execFileSync } from "node:child_process";
import { cleanEnv } from "../tools/lib/git-env.mjs";
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
  HOLDS_DIR,
  classifyHoldCommit,
  holdEntry,
  readHolds,
  resolveHold,
  resultKey,
  resultsToPost,
} from "./lib/holds.mjs";
import { VERDICT_SCHEMA, runUrl, verdictProblems } from "./lib/alert-verdict.mjs";
import { SOURCE_DIR as MODERATION_DIR } from "./lib/moderation.mjs";
import {
  SETTLED_FILE,
  acceptRows,
  composeSettled,
  readSettled,
  settledKey,
  settledRow,
  writeSettled,
} from "./lib/settled.mjs";
import { POLICY_CODES } from "./lib/policy/constants.mjs";
import { createClient } from "./lib/service.mjs";
import { buildIndex } from "../tools/build-index.mjs";
import { stableStringify } from "../tools/lib/canonical.mjs";
import { validate } from "../tools/lib/jsonschema.mjs";
import { REPO_ROOT } from "../tools/lib/sources.mjs";
import {
  OUTPUT_FILE as REVOCATIONS_FILE,
  SERIAL_PATHSPEC as LIST_SERIAL_PATHSPEC,
  SOURCE_DIR as REVOCATIONS_DIR,
  buildRevocations,
  resolveSerial as listSerialAtHead,
} from "../tools/lib/revocations.mjs";

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
  // One file, not a directory: the results the service answered as settled
  // (`bot/lib/settled.mjs`; ops entry 100).
  SETTLED_FILE,
]);

/**
 * Is this repository-relative path one a moderation commit may write? An entry
 * ending in `/` admits everything beneath it; any other entry admits exactly
 * that file, so `state/moderation-settled.json` does not also admit a sibling
 * whose name merely begins the same way.
 */
export function allowedPath(rel) {
  const p = String(rel ?? "");
  if (p === "" || p.startsWith("/") || p.split("/").some((s) => s === "" || s === "." || s === "..")) return false;
  return MODERATION_ALLOWLIST.some((entry) => (entry.endsWith("/") ? p.startsWith(entry) : p === entry));
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
 *
 * `documents` are the generated documents `regenerateDocuments` rewrote for
 * this commit. They are listed only beside something else — a document is
 * what a change produces, never a change of its own — and only when they
 * changed.
 *
 * `settled` are the rows this run added to `state/moderation-settled.json`
 * (ops entry 100). They are a change of their own: a run whose only news is
 * that the service accepted a result derived from history commits the record
 * alone, once, and the next run skips that result rather than posting it again.
 * No `Service-Decision:` trailer is written for them — a trailer says a commit
 * applies, holds or cancels a decision (BOT-81), and this one does none of that.
 */
export function composeCommit({ compiled, held = [], submissions = [], documents = [], settled = [], run, subject = null }) {
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
    paths.add(holdEntryPath(h.service_decision_id));
  }
  for (const s of submissions) if (s.path) paths.add(s.path);
  if (settled.length) paths.add(SETTLED_FILE);
  if (paths.size) for (const d of documents) paths.add(d);

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
    settled.length ? `${settled.length} settled result(s) recorded` : null,
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

// ── the two generated documents ─────────────────────────────────────────────

/**
 * The documents a moderation commit regenerates, where each generator writes
 * it. The index path is `tools/build-index.mjs`'s CLI default, stated there as
 * a literal; the suite holds this one to it by running that CLI's `--check`
 * over a tree this file wrote.
 */
export const INDEX_FILE = "registry/v1/index.json";

/** Does a commit of these paths change what the withdrawal list's serial counts? */
export const movesListSerial = (paths) =>
  paths.some((p) => p === LIST_SERIAL_PATHSPEC || p.startsWith(`${LIST_SERIAL_PATHSPEC}/`));

/**
 * Regenerate `registry/v1/index.json` and `registry/v1/revocations.json` for
 * the commit whose paths are `paths`, and return the ones whose bytes changed.
 *
 * **Why here and not in the workflow.** The workflow used to run both
 * generators in a step of its own, AFTER this job had written `paths.txt` — so
 * neither document was ever listed, the push carried a delist beside an index
 * that still listed the plugin (`build-index.yml`'s `--check` red on `main`),
 * and an advisory beside a withdrawal list that did not carry it (ops entry
 * 102). A path list written by one step for a file written by another is entry
 * 79's defect in a new place; the writer and the lister are now one function.
 *
 * **The serials are the ones the signer assigns the commit that lands them.**
 * Both generators count a pending change as the commit about to be made — the
 * index's since `a85c198`, the list's since ops entry 69 — by reading `git
 * status`, which is a guess at the commit. This job does not guess: it knows
 * exactly which commit it is composing, so for the list it asks
 * `resolveSerial` for `HEAD`'s count alone (`pending: false`) and adds that
 * commit when — and only when — its paths touch the list's pathspec. Letting
 * both count it would write the list one past the signer's serial, because
 * the advisory this job wrote is pending when it asks. The landing commit is a single-parent commit
 * on `HEAD`, which every way of counting the pathspec counts. The formula
 * itself stays `tools/lib/revocations.mjs`'s.
 *
 * Nothing is regenerated for an empty commit: a document is what a change
 * produces, and a run that commits nothing leaves the tree as it found it
 * (BOT-92's shadow run included, which the suite checks by `git status`).
 */
export function regenerateDocuments({ root = REPO_ROOT, paths = [] } = {}) {
  if (!paths.length) return { changed: [], serials: null };
  const index = buildIndex({ root });
  const list = buildRevocations({ root, serial: listSerialAtHead({ root, pending: false }) + (movesListSerial(paths) ? 1 : 0) });
  const changed = [];
  for (const [rel, doc] of [[INDEX_FILE, index], [REVOCATIONS_FILE, list]]) {
    if (!allowedPath(rel)) {
      throw new Error(`${rel} is a generated document BOT-33's moderation allowlist does not carry`);
    }
    const full = path.join(root, ...rel.split("/"));
    const text = stableStringify(doc);
    if (fs.existsSync(full) && fs.readFileSync(full, "utf8") === text) continue;
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, text);
    changed.push(rel);
  }
  return { changed, serials: { index: index.signed.serial, revocations: list.signed.serial } };
}

// ── holds: entering one ─────────────────────────────────────────────────────

/** `state/holds`, repository-relative with `/`, whatever the platform joins with. */
export const HOLDS_PREFIX = HOLDS_DIR.split(path.sep).join("/");

/**
 * The one statement of where a held decision's entry lives. `composeCommit`
 * puts this path into `paths.txt` and `writeHoldEntries` writes to it, and
 * the two used to be two spellings — one of which nothing wrote.
 */
export const holdEntryPath = (id) => `${HOLDS_PREFIX}/${id}.json`;

/**
 * Write `state/holds/<id>.json` for every decision this run held.
 *
 * **Until this existed, nothing wrote the file.** `compileDecision`'s `held()`
 * returns no edits, `applyCompiled` writes compiled edits only, and
 * `composeCommit` put the entry's path into `paths.txt` anyway — so the
 * workflow's `git add --pathspec-from-file` met a path that did not exist,
 * exited 128, and the first held decision failed the commit. Had it not, the
 * `held` result would have been posted for a hold no file recorded: the
 * decision leaves BOT-80's list on that result, and a hold that is not in git
 * is one no confirmation can ever release.
 *
 * The entry is `holdEntry`'s, so the decision is copied through the schema's
 * allowlist and checked before it is written, and the path goes through BOT-33's
 * moderation allowlist before it is opened. The schema it is checked against is
 * this repository's (`schemaRoot`), for `readHolds`'s reason: the tree being
 * written may be a fixture, and the rule is what THIS checkout says.
 *
 * **Never called in a shadow run.** Until 2026-09-22 it was, on the reading
 * that a `held` result is not state-setting and is posted under `shadow: true`,
 * so the entry had to exist to make that post true. The consequence was right
 * — committing nothing while posting `held` would lose the decision — and the
 * premise was not: a `held` result takes the decision off BOT-80's list, BOT-81
 * has it name the entry's commit, and BOT-92's Check is "no commit for that
 * work and no posted result". So shadow does neither, together, and the pair
 * stays consistent: no entry and no `held`, the decision still listed, held by
 * the first live run.
 *
 * **An entry already on the tree is left as it is**, byte for byte, and is not
 * listed for the commit. That is the decision being listed again because an
 * earlier run's `held` result never reached the service; rewriting it would
 * move `held_at` and `release_after`, which a reversal waits for as well as
 * for 24 hours from its commit, and so restart the period every time; and
 * listing an unchanged file would compose a commit with nothing in it.
 *
 * **And its `held` result names the commit that entered it** (`results`'s
 * `commit`), read here because this is where the entry is found to be there
 * already. BOT-81 has a `held` name the hold entry's commit; this run makes
 * none for it, and BOT-82 keys the result on the commit, so any other commit
 * would be a second, different result for the post that was lost. A kept
 * entry git cannot place — on disk and never committed, which a checkout of
 * `main` cannot hold — gets `commit: null`, which `resultsFor` refuses to post.
 *
 * @returns {{written: string[], entered: {service_decision_id: string, file: string}[], kept: string[],
 *   results: {service_decision_id: string, held_for: string, commit?: string|null}[]}}
 */
export function writeHoldEntries(held, { root = REPO_ROOT, schemaRoot = REPO_ROOT, heldAt, run = null } = {}) {
  const out = { written: [], entered: [], kept: [], results: [] };
  for (const h of held) {
    const rel = holdEntryPath(h.service_decision_id);
    if (!allowedPath(rel)) {
      throw new Error(`a held decision names ${rel}, which BOT-33's moderation allowlist does not carry`);
    }
    const full = path.join(root, ...rel.split("/"));
    if (fs.existsSync(full)) {
      out.kept.push(rel);
      out.results.push({ service_decision_id: h.service_decision_id, held_for: h.held_for, commit: entryCommit(root, rel) });
      continue;
    }
    // No `commit` member: this entry's commit is the one the workflow's `apply`
    // step is about to push, and `report` names it from that step's output.
    out.results.push({ service_decision_id: h.service_decision_id, held_for: h.held_for });
    const entry = holdEntry(h.decision, { held_for: h.held_for, held_at: heldAt, ...(run ? { run } : {}), root: schemaRoot });
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, `${JSON.stringify(entry, null, 2)}\n`);
    out.written.push(rel);
    out.entered.push({ service_decision_id: h.service_decision_id, file: rel });
  }
  return out;
}

/**
 * Where a hold entry landed on `main`: the commit that added it, and when. The
 * one reader of that commit — BOT-81's `held` result names it
 * (`entryCommit`), and MOD-9's 24 hours run from it (`reversalDue` in
 * `bot/lib/holds.mjs`, ops entry 101) — so the two can never name different
 * commits.
 *
 * **The commit on HEAD's first-parent line that brought the file, read against
 * its first parent, at its committer time** — how TRUST-26's window dates a
 * withdrawal and SERVE-85's readers date a change (ops entries 92 and 93). The
 * commit job pushes its own commit as a fast-forward, so for every hold it
 * enters this is that commit. A hold that reached `main` through a merge is
 * dated at the merge: without `--first-parent` git follows the side the file
 * came from and names the branch commit, which may be days older than the
 * moment `main` held the entry — the early direction. The commit that ADDED
 * it, not the last that touched it: an edit to the entry is not a new hold.
 *
 * Three shapes, and `reversalDue` reads each:
 *
 *   - `{sha, at}` — landed;
 *   - `{sha: null, at: null, uncommitted: true, why}` — the file is in no
 *     commit on HEAD: the entry this run has just written. Its period has not
 *     started. Asked of HEAD's tree and not of the log, because a path that
 *     was added, deleted and written again would otherwise be dated at its
 *     first life;
 *   - `{sha: null, at: null, why}` — the history cannot be read. **A shallow
 *     checkout is this, whatever the log says:** its boundary commit has no
 *     parent here, so git reports it as adding every file in the tree, and the
 *     newest commit would be named as the hold's. The commit job checks out
 *     with `fetch-depth: 0`, so this is not the live path there.
 */
export function entryLanding(root, rel) {
  const git = (args) => execFileSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...cleanEnv(), GIT_PAGER: "cat", GIT_OPTIONAL_LOCKS: "0" },
  });
  const unknown = (why) => ({ sha: null, at: null, why });
  try {
    if (git(["rev-parse", "--is-shallow-repository"]).trim() !== "false") {
      return unknown(`${root} is a shallow clone, whose boundary commit git reports as adding every file, so the commit that added ${rel} cannot be told from it`);
    }
    if (git(["ls-tree", "--name-only", "HEAD", "--", rel]).trim() !== rel) {
      return { sha: null, at: null, uncommitted: true, why: `${rel} is in no commit on HEAD` };
    }
    const line = git(["log", "-1", "--first-parent", "--diff-filter=A", "--format=%H %ct", "HEAD", "--", rel]).trim();
    const m = /^([0-9a-f]{40}) (\d+)$/.exec(line);
    if (!m) return unknown(`${rel} is on HEAD and git names no commit on its first-parent line that added it`);
    return { sha: m[1], at: new Date(Number(m[2]) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z") };
  } catch (err) {
    return unknown(`git could not read the history of ${rel} here: ${String(err.message).split("\n")[0]}`);
  }
}

/** The commit that brought this hold entry onto `main` (`entryLanding`), or null. */
export const entryCommit = (root, rel) => entryLanding(root, rel).sha;

// ── holds: the ones that have left the tree ─────────────────────────────────

/**
 * Every hold entry that has LEFT the tree, read off the commit that removed it,
 * in the shape `classifyHoldCommit` reads.
 *
 * `readHolds` sees only entries still on disk, so without this the documented
 * way for a person with no tooling to end a hold — deleting the file (BOT-70,
 * RUNBOOK §7.8) — was never classified and never reported: the decision stayed
 * `held` at the service for ever. The record of what happened is the commit,
 * so this reads commits.
 *
 * Here, in `bot/`, and not through `tools/coverage/git.mjs`: that is a desk
 * tool outside TRUST-31's hashed set, and importing it would pull it into a bot
 * run's closure. Every call is `execFileSync` with an argument array.
 *
 * Per entry, the LATEST commit that deleted it, and none for an id whose entry
 * is on the tree again. Both facts `classifyHoldCommit` weighs are read FOR
 * THIS ID, because BOT-73 puts a whole run in one commit:
 *
 *   - `trailers["Service-Decision"]` is set only if one of the commit's
 *     `Service-Decision:` trailers names this id. A commit that cancelled one
 *     hold and compiled another carries the other's trailer, and reading "has a
 *     trailer" would call a hand deletion beside it a trailered cancel;
 *   - `writesLogEntry` is true if the commit added or changed a moderation log
 *     entry that names this id, OR one that names no decision at all or cannot
 *     be read. The second half is the conservative one: a hand log entry beside
 *     a hand deletion is a person applying the decision by hand, and reading it
 *     as no log entry would post `cancelled` for something the public log says
 *     was applied. `classifyHoldCommit` calls that `unclear` and posts nothing.
 *
 * A shallow clone would hide every deletion before its graft and return fewer
 * rows with nothing said, so it throws instead.
 */
export function holdDeletions(root = REPO_ROOT, { present = new Set() } = {}) {
  const git = (args) => execFileSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...cleanEnv(), GIT_PAGER: "cat", GIT_OPTIONAL_LOCKS: "0" },
  });
  if (git(["rev-parse", "--is-shallow-repository"]).trim() !== "false") {
    throw new Error(
      `${root} is a shallow clone, so the commits that deleted a hold entry before its graft cannot be read. ` +
      "A hold a person cancelled by deleting its file would then go unreported with nothing said; the commit " +
      "job checks out with fetch-depth: 0 for this and for MOD-13's history",
    );
  }
  const prefix = `${HOLDS_PREFIX}/`;
  const logDir = `${MODERATION_DIR}/`;
  const out = [];
  const seen = new Set(present);
  // Newest first, so the first deletion met for an id is its latest.
  const shas = git(["log", "--format=%H", "--diff-filter=D", "--", prefix]).split("\n").filter(Boolean);
  for (const sha of shas) {
    const fields = git(["diff-tree", "--root", "--no-commit-id", "-r", "-z", "--name-status", sha]).split("\0");
    const changes = [];
    for (let i = 0; i + 1 < fields.length; i += 2) changes.push({ status: fields[i], file: fields[i + 1] });
    const ids = [];
    for (const { status, file } of changes) {
      if (status !== "D" || !file.startsWith(prefix)) continue;
      const name = file.slice(prefix.length);
      if (name.includes("/") || !name.endsWith(".json")) continue;
      const id = name.slice(0, -".json".length);
      if (id.endsWith(".confirm") || id.endsWith(".cancel") || seen.has(id)) continue;
      seen.add(id);
      ids.push(id);
    }
    if (!ids.length) continue;
    const named = git(["log", "-1", "--format=%(trailers:key=Service-Decision,valueonly,separator=%x00)", sha])
      .split("\0").map((v) => v.trim()).filter(Boolean);
    const logIds = [];
    for (const { status, file } of changes) {
      if (!(status === "A" || status === "M") || !file.startsWith(logDir) || !file.endsWith(".json")) continue;
      let doc = null;
      try {
        doc = JSON.parse(git(["show", `${sha}:${file}`]));
      } catch {
        doc = null;
      }
      logIds.push(typeof doc?.service_decision_id === "string" ? doc.service_decision_id : null);
    }
    for (const id of ids) {
      out.push({
        id,
        sha,
        deletesEntry: true,
        writesLogEntry: logIds.some((l) => l === null || l === id),
        trailers: named.includes(id) ? { "Service-Decision": id } : {},
      });
    }
  }
  return out;
}

// ── holds, which run whether or not `list` answered ──────────────────────────

/**
 * Walk every hold under M-T3.3, even when `list` failed.
 *
 * A confirmed hold is not work the list answer names: a settled `held` result
 * took it off BOT-80's list, and its release is driven by the MOD-52 record in
 * git. So this runs on `if: always() && !cancelled()`, with the list answer's
 * `shadow` used only to decide whether a RESULT may be posted.
 *
 * Two sources: the entries still on the tree (`readHolds`, `resolveHold`), and
 * the entries that have left it (`holdDeletions`, `classifyHoldCommit`). A
 * row from the second names the commit that removed the entry, because BOT-70
 * says that commit IS the record, and BOT-82's key carries it. `unclear` —
 * the entry deleted and a log entry written under no trailer — is reported and
 * alerted and posts nothing; a hand cancellation posts `cancelled` and alerts
 * as well, since nobody announced it.
 *
 * **Each entry on the tree is dated by the commit that brought it onto
 * `main`** (`entryLanding`), and a reversal's 24 hours run from that commit,
 * as MOD-9 says, and not from its `held_at` (ops entry 101). An entry this
 * run has just written is in no commit yet, so its period has not started.
 *
 * **A hold still on the tree whose release or cancel is DUE goes to `due`,
 * not to `released` or `cancelled`, and gets no result.** M-T3.3's release
 * commit — apply the held decision from the entry, write its log entry,
 * delete the entry and its record, under `Service-Decision:` — and its cancel
 * commit are not built: nothing in this job applies a held decision or deletes
 * an entry. Until 2026-09-22 such a hold was reported `applied` (or
 * `cancelled`) with `commit: null`, which `resultsFor` filled with the run's
 * own commit — so the service would have been told a relist landed in a
 * commit that left `unlisted: true` and the entry where they were. BOT-81 has
 * `applied` name the commit that applies and `cancelled` the commit that
 * removes the entry, and there is no such commit. So it is refused by name: an
 * `::error::` (`hold_end_not_built`) every run, the entry left for the run
 * that can build the commit, and nothing posted.
 *
 * **A result from history the service has already settled is skipped** — not
 * posted, not alerted — when `settled` holds its BOT-82 key (ops entry 100).
 * `settled` is `readSettled`'s `keys`: the results the service ANSWERED
 * `accepted` or `duplicate`, never the ones merely posted. It defaults to the
 * empty set, and an absent or unreadable record is the empty set too, so every
 * fault here is a result posted again and never one withheld. A skipped row
 * goes to `settled`, so a run still says how many it passed over. An
 * `unclear` deletion has no result, so nothing can settle it and it alerts on.
 */
export function walkHolds({
  root = REPO_ROOT,
  now = new Date(),
  shadow = true,
  delistedPlugins = [],
  coverageRed = false,
  settled = new Set(),
} = {}) {
  const out = { released: [], cancelled: [], waiting: [], due: [], unclear: [], alerts: [], pending: [], settled: [] };
  const onTree = readHolds(root);
  for (const hold of onTree) {
    // Where the entry landed: a reversal's 24 hours run from that commit, not
    // from `held_at` (MOD-9; ops entry 101).
    const landed = entryLanding(root, holdEntryPath(hold.id));
    const verdict = resolveHold(hold, { now, shadow, delistedPlugins, coverageRed, landed });
    const id = hold.entry?.service_decision_id ?? null;
    if (verdict.act === "wait" || !id) {
      out.waiting.push({ service_decision_id: id, reason: verdict.reason });
      continue;
    }
    if (verdict.act !== "release" && verdict.act !== "cancel") {
      throw new Error(`resolveHold answered ${verdict.act} for the hold entry of ${id}`);
    }
    out.due.push({ service_decision_id: id, act: verdict.act, would_post: verdict.result, reason: verdict.reason });
    out.alerts.push({
      kind: "hold_end_not_built",
      service_decision_id: id,
      commit: null,
      why:
        `the hold is due to ${verdict.act} (${verdict.reason}), and this job does not build the ${verdict.act} ` +
        `commit M-T3.3 describes: ${verdict.act === "release"
          ? "nothing here applies the held decision, writes its log entry, or deletes the entry and its confirm record"
          : "nothing here deletes the entry and its cancel record under a Service-Decision: trailer"}. ` +
        `So \`${verdict.result}\` is NOT reported — BOT-81 has it name the commit that ` +
        `${verdict.act === "release" ? "applies the decision" : "removes the hold entry"}, and no commit does. The entry ` +
        "stays on the tree for the run that can build that commit",
    });
  }

  for (const gone of holdDeletions(root, { present: new Set(onTree.map((h) => h.id)) })) {
    const c = classifyHoldCommit(gone);
    const row = { service_decision_id: gone.id, act: c.act, outcome: c.result, commit: gone.sha, hand: c.hand, reason: c.reason };
    if (c.act === "unclear") {
      out.unclear.push(row);
      out.alerts.push({ kind: "hold_unclear", service_decision_id: gone.id, commit: gone.sha, why: c.reason });
      continue;
    }
    if (c.act !== "release" && c.act !== "cancel") {
      throw new Error(`${gone.sha} deleted the hold entry for ${gone.id} and classifyHoldCommit answered ${c.act}`);
    }
    if (settled.has(settledKey({ service_decision_id: gone.id, outcome: c.result, commit: gone.sha }))) {
      out.settled.push(row);
      continue;
    }
    if (c.hand) out.alerts.push({ kind: "hold_hand_cancelled", service_decision_id: gone.id, commit: gone.sha, why: c.reason });
    (c.act === "cancel" ? out.cancelled : out.released).push(row);
    out.pending.push({ service_decision_id: gone.id, outcome: c.result, commit: gone.sha });
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
 *
 * `commit` is the commit the workflow's `apply` step pushed, or null (or the
 * empty string the step hands on) when it pushed nothing. **It is the only
 * commit an `applied`, or a `held` for a hold this run ENTERED, can name**
 * (BOT-81: "at most one `held` result, naming the hold entry's commit"), and
 * it does not exist until after the commit job has exited — which is why this
 * runs in `report` and never in `commit`. Until 2026-09-22 every `held` was
 * composed with `commit: null` (ops entry 102). A hold kept from an earlier
 * run names its own commit (`writeHoldEntries`), as a hold ended in history
 * does (`holdDeletions`).
 *
 * A live result that must name a commit and names none is REFUSED here, with
 * the reason, rather than posted: the service settles a result against `main`
 * (BOT-82), and one with no commit is a result it can only reject — or, worse,
 * record.
 */
export function resultsFor({ compiled = [], refused = [], held = [], holds = { pending: [] }, commit = null, shadow = true }) {
  const pushed = typeof commit === "string" && commit !== "" ? commit : null;
  const results = [];
  for (const r of compiled) {
    results.push({ service_decision_id: r.service_decision_id, outcome: "applied", commit: pushed, refusal_code: null });
  }
  for (const r of refused) {
    results.push({ service_decision_id: r.service_decision_id, outcome: "refused", commit: null, refusal_code: r.refusal });
  }
  for (const h of held) {
    // A row carrying `commit` — even null — is a kept entry and names its own;
    // a row without it is one this run entered, and names what was pushed.
    const named = Object.hasOwn(h, "commit") ? (h.commit ?? null) : pushed;
    results.push({ service_decision_id: h.service_decision_id, outcome: "held", commit: named, refusal_code: null });
  }
  // A row that names its own commit keeps it: a hold ended by a commit in
  // history (`holdDeletions`) is reported against THAT commit, and BOT-82's
  // key carries it, so overwriting it with this run's commit would make every
  // re-post a new result rather than a `duplicate` of the last one.
  for (const p of holds.pending ?? []) {
    results.push({ service_decision_id: p.service_decision_id, outcome: p.outcome, commit: p.commit ?? pushed, refusal_code: null });
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

  // BOT-92. Under anything but `shadow === false`, NOTHING is posted — a
  // `held` result included. This used to post `held` in shadow on the reading
  // that it "says the registry has not decided" and so is not state-setting.
  // It is: a settled `held` takes the decision off BOT-80's list (BOT-81's
  // Why), BOT-81 has it name the hold entry's commit — and a shadow run commits
  // no entry — and the plan's M-T3.4 says `report` posts "nothing at all" for
  // listed work in shadow, as B-T3.5 says for a `wait`. `applied`, `cancelled`
  // and `refused` settle outright, and `resultsToPost` withholds them until a
  // `shadow: false` answer.
  //
  // `withheld` is computed from the LIVE call and not from the shadow one, and
  // that is the difference between a report that says what it is holding back
  // and one that is simply empty. A shadow run whose `withheld` list was also
  // empty would be indistinguishable, in a log, from a run with nothing to
  // post — which is the state this whole mode has to stay visible during.
  const holdResults = results.filter((r) => r.outcome === "held");
  const settling = results.filter((r) => r.outcome !== "held");
  const sendable = resultsToPost(settling, { shadow: false });
  if (shadow !== false) return { post: [], withheld: [...holdResults, ...sendable] };

  const post = [...holdResults, ...sendable];
  const unnamed = post.filter((r) => COMMITTED_OUTCOMES.includes(r.outcome) && !FULL_SHA.test(String(r.commit ?? "")));
  if (unnamed.length) {
    throw new Error(
      `${unnamed.map((r) => `${r.service_decision_id} ${r.outcome}`).join(", ")} would be posted naming no commit ` +
      `(${unnamed.map((r) => JSON.stringify(r.commit)).join(", ")}). BOT-81 has \`applied\` name the main commit, ` +
      "`held` the hold entry's commit and `cancelled` the commit that removes the entry, and BOT-82 settles each " +
      "against main; so this run posts none of them and fails, rather than tell the service something landed " +
      "nowhere (ops entry 102)",
    );
  }
  return { post, withheld: [] };
}

/** The outcomes BOT-81 gives a commit, which the token file's `commit` condition names too. */
export const COMMITTED_OUTCOMES = Object.freeze(["applied", "held", "cancelled"]);
const FULL_SHA = /^[0-9a-f]{40}$/;

/** `resultsFor` over a commit job's `results.json`, which is what its `results` output hands on. */
export function resultsFromState(state, { commit = null } = {}) {
  if (!state || typeof state !== "object" || !Array.isArray(state.compiled) || !Array.isArray(state.held)) {
    throw new Error(
      "the commit job's `results` output is not a results.json. It is the only way `report` and `settled` learn " +
      "what that job did, and a run that read an absent one as \"nothing happened\" would post nothing and page for " +
      "nothing",
    );
  }
  return resultsFor({
    compiled: state.compiled.map((id) => ({ service_decision_id: id })),
    refused: state.refused ?? [],
    held: state.held,
    holds: state.holds ?? { pending: [] },
    commit,
    shadow: state.shadow === false ? false : true,
  });
}

/** The one body BOT-81's result is posted as: `commit` for a committed outcome, `refusal_code` for `refused`, never both. */
export function resultBody(r) {
  return {
    service_decision_id: r.service_decision_id,
    outcome: r.outcome,
    ...(COMMITTED_OUTCOMES.includes(r.outcome) ? { commit: r.commit } : { refusal_code: r.refusal_code }),
  };
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

/**
 * The decisions a commit job's `results.json` answered, for `unsettled`: every
 * result `report` posted from it, and every one a shadow answer withheld.
 *
 * Withheld counts as answered, and that is BOT-84's own split, not leniency:
 * "for work withheld only by shadow, TRUST-45 pages instead". A `settled` that
 * paged too would page every ten minutes for as long as shadow lasts, for runs
 * that did exactly what BOT-92 asks — and an alarm that fires on the correct
 * state is an alarm nobody reads by the time it fires on a wrong one.
 */
export function answeredBy(state, { commit = null } = {}) {
  const { post, withheld } = resultsFromState(state, { commit });
  const rows = [...post, ...withheld];
  const shadowed = state.shadow_withheld ?? {};
  for (const id of shadowed.compiled ?? []) rows.push({ service_decision_id: id, outcome: "shadow_withheld" });
  for (const r of [...(shadowed.refused ?? []), ...(shadowed.held ?? [])]) {
    rows.push({ service_decision_id: r.service_decision_id, outcome: "shadow_withheld" });
  }
  return rows;
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

/** The commit job's `results` output, or null when nothing was handed on. A value that is not JSON throws. */
const parseResults = (text) => (typeof text === "string" && text.trim() !== "" ? JSON.parse(text) : null);

/**
 * `list`'s `settled` output (ops entry 100), or no rows. Empty — `list` failed,
 * or its step is not built — is no rows. So is a value that is not a JSON
 * array, said aloud: a row not recorded is a result posted again, and failing
 * the commit job over it would hold back every takedown in the batch for the
 * sake of a record.
 */
function parseSettled(text, log) {
  if (typeof text !== "string" || text.trim() === "") return [];
  try {
    const rows = JSON.parse(text);
    if (Array.isArray(rows)) return rows;
  } catch {
    // fall through to the warning
  }
  log.error("::warning::settled_row_refused: `list`'s `settled` output is not a JSON array, so no row is recorded " +
    "and every result it named is posted again");
  return [];
}

export async function main(argv = [], { env = process.env, log = console, fetchImpl = fetch, now = new Date() } = {}) {
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

  if (job === "history") {
    // Ops entry 100, in the `list` job, after the list call and BEFORE
    // `commit`: post the results a commit already on `main` decided — a hold a
    // person deleted, a release or cancel commit — and write the ones the
    // service ANSWERED `accepted` or `duplicate` to `settled.json`, which the
    // step hands to `commit` as the job's `settled` output. `commit` records
    // them, and the next run skips them. This job may post them because each
    // names a commit already on `main`: it is not a promise waiting for this
    // run's push (BOT-6), and BOT-82 settles it against `main` as it would
    // from `report`. What the service does not settle here, `report` posts
    // again after the commit, as it always has.
    //
    // It is not the list call, and it is not in `--job list`, so that a run
    // with the list answer in hand can tell "the work list could not be read"
    // from "a result from history was not settled": the second is not a
    // failed list, and fails nothing — the result is simply posted again.
    const out = arg(argv, "--out") ?? "moderation";
    fs.mkdirSync(out, { recursive: true });
    const file = path.join(out, "settled.json");
    const shadow = env.ASTRA_SHADOW === "false" ? false : true;
    if (shadow !== false) {
      // BOT-92: an `applied` or `cancelled` result settles a decision, so under
      // anything but `shadow: false` none is posted, and so none is settled.
      fs.writeFileSync(file, "[]\n");
      log.log("note  shadow: no result derived from history is posted, so none is recorded as settled (BOT-92)");
      return 0;
    }
    const record = readSettled(root);
    for (const p of record.problems) log.error(`::warning::settled_record_unreadable: ${p}`);
    const holds = walkHolds({ root, now, shadow: false, settled: record.keys });
    const pending = resultsToPost(holds.pending, { shadow: false });
    const client = pending.length ? createClient({ workflow: "moderation", env, log, fetchImpl }) : null;
    const rows = [];
    const run = runUrl(env);
    for (const p of pending) {
      const answer = await client.call("serviceDecisionResult", resultBody(p));
      const { row, why } = settledRow(p, answer, { now, run });
      if (row) {
        rows.push(row);
        log.log(`settle ${p.service_decision_id} ${p.outcome} ${row.answer}`);
      } else {
        log.log(`post   ${p.service_decision_id} ${p.outcome} is not recorded as settled: ${why}. \`report\` posts ` +
          "it again after the commit, and the next live run again after that");
      }
    }
    fs.writeFileSync(file, `${JSON.stringify(rows)}\n`);
    log.log(`ok    ${pending.length} result(s) derived from history posted, ${rows.length} settled, ` +
      `${holds.settled.length} skipped as already settled`);
    return 0;
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

    // Compiled in both modes: in shadow for timing (OPEN-OPS-13), and so that a
    // compile that throws is red in shadow too rather than first at R3's exit.
    const compiledAll = compileAll(recheck.entries, { root, overBound });

    // BOT-92: from here to `composeCommit`, the work the list answer names is
    // written ONLY under `shadow === false` — and "written" is every one of
    // the three writers, because each is a commit for that work. `live` is the
    // one switch; a writer outside it is a shadow commit.
    const live = shadow === false;
    const written = live ? applyCompiled(compiledAll.compiled, { root }) : [];
    // Between the compile and the compose, so that every path `composeCommit`
    // lists for a hold is a file on this tree when `git add` reads it.
    const holdsEntered = live
      ? writeHoldEntries(compiledAll.held, {
        root,
        heldAt: `${now.toISOString().slice(0, 19)}Z`,
        run: runUrl(env),
      })
      : { written: [], entered: [], kept: [], results: [] };
    written.push(...holdsEntered.written);
    const terminal = [];
    if (live) {
      const existing = recordsOnMain(root);
      for (const s of recheck.submissions) terminal.push(terminalSubmissionRecord(s, { root, existing }));
    }

    // Ops entry 100. The results from history that the service has already
    // settled are skipped by the walk: the ones in the record on this tree,
    // and — live only — the ones `list` posted before this job and the service
    // answered `accepted` or `duplicate`, which this job records now. A record
    // that is absent or unreadable skips nothing, and says so when unreadable.
    const record = readSettled(root);
    for (const p of record.problems) log.error(`::warning::settled_record_unreadable: ${p}`);
    const holds = walkHolds({ root, now, shadow, settled: record.keys });
    const handed = parseSettled(env.ASTRA_SETTLED, log);
    let recorded = [];
    const refusedRows = [];
    if (live) {
      // Re-checked, as `entries` is: each row must be sound AND name a result
      // this walk derived and has not recorded. The answer itself this job
      // cannot see; that trust, and what a forged row costs, is
      // `bot/lib/settled.mjs`'s header.
      const accepted = acceptRows(handed, { derived: new Set(holds.pending.map(settledKey)) });
      refusedRows.push(...accepted.problems);
      recorded = accepted.rows;
      if (recorded.length) {
        const nowSettled = new Set(recorded.map(settledKey));
        holds.pending = holds.pending.filter((p) => !nowSettled.has(settledKey(p)));
        writeSettled(root, composeSettled(record.rows, recorded));
      }
    } else if (handed.length) {
      refusedRows.push(
        `${handed.length} settled row(s) were handed on under a list answer that is not \`shadow: false\`; a shadow ` +
        "run posts nothing, so nothing it was handed can have been settled, and none is recorded (BOT-92)",
      );
    }
    for (const p of refusedRows) log.error(`::warning::settled_row_refused: ${p}`);
    const composed = {
      compiled: live ? compiledAll.compiled : [],
      held: holdsEntered.entered,
      submissions: terminal,
      settled: recorded,
      run: env.GITHUB_RUN_ID ?? "0",
    };
    let commit = composeCommit(composed);
    // The two documents, for exactly the commit just composed, and listed with
    // it. Last among the writers, because each generator reads the tree the
    // others left: the index reads the listing edits, and the list's serial
    // reads which paths this commit carries.
    const documents = regenerateDocuments({ root, paths: commit.paths });
    if (documents.changed.length) {
      written.push(...documents.changed);
      commit = composeCommit({ ...composed, documents: documents.changed });
    }

    // In shadow, what the run WOULD have done is recorded apart, as ids and
    // kinds, and the members `report` reads are empty: a result `report`
    // could post for work this run did not do is exactly what BOT-92 forbids,
    // and keeping it out of those members is what makes that structural.
    const shadowWithheld = live ? null : {
      compiled: compiledAll.compiled.map((r) => r.service_decision_id),
      refused: compiledAll.refused.map((r) => ({ service_decision_id: r.service_decision_id, refusal: r.refusal })),
      held: compiledAll.held.map((r) => ({ service_decision_id: r.service_decision_id, held_for: r.held_for })),
      submissions: recheck.submissions.map((s) => s.submission_id),
    };

    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, "results.json"), `${JSON.stringify({
      shadow,
      compiled: live ? compiledAll.compiled.map((r) => r.service_decision_id) : [],
      refused: live ? compiledAll.refused.map((r) => ({ service_decision_id: r.service_decision_id, refusal: r.refusal })) : [],
      // A kept entry's row carries the commit that entered it; an entered one's
      // carries none, and `report` names the commit the `apply` step pushed.
      held: live ? holdsEntered.results : [],
      holds_kept: holdsEntered.kept,
      holds,
      // Ops entry 100: what the record on this tree was, and the rows this
      // run added to it. `holds.settled` is what the walk passed over.
      settled: { record: record.state, recorded, problems: [...record.problems, ...refusedRows] },
      written,
      documents: documents.changed,
      serials: documents.serials,
      terminal,
      ...(shadowWithheld ? { shadow_withheld: shadowWithheld } : {}),
    }, null, 2)}\n`);
    // **The handoff to the workflow's `apply` step, and its one rule: a
    // zero-byte `paths.txt`, and no `commit-message.txt`, means "nothing to
    // commit".** Until 2026-09-22 a run with nothing to commit wrote
    // `paths.txt` as a single newline and no message. `git add
    // --pathspec-from-file` exits 128 on that line ("empty string is not a
    // valid pathspec") and `git commit --file=` exits 128 on the missing file,
    // so the quietest run there is — no work, no due hold — failed the commit
    // step, and every ten minutes once the schedule is on.
    //
    // `paths.txt` is written EVERY run, empty or not, because its absence is
    // the other thing the step has to tell apart: a job that never got this
    // far must fail the step, not read as a run with nothing to say. And a
    // stale message from an earlier run in the same directory is removed, so
    // the pair is always this run's.
    const messageFile = path.join(out, "commit-message.txt");
    fs.rmSync(messageFile, { force: true });
    if (commit.message) fs.writeFileSync(messageFile, commit.message);
    fs.writeFileSync(path.join(out, "paths.txt"), commit.paths.length ? `${commit.paths.join("\n")}\n` : "");
    // An unclear deletion is an error: nobody can say what happened, and no
    // result will be posted until a person does. A hand cancellation is the
    // documented way to end a hold, so it is a warning — but it is said,
    // because nothing else announced it. An unclear deletion repeats on every
    // run for as long as its commit is in history, because it has no result
    // and nothing can settle it. A hand cancellation repeats until the service
    // has answered its `cancelled` `accepted` or `duplicate` and the record on
    // `main` says so (ops entry 100) — so it is said at least in the run that
    // records it, and then no more.
    for (const a of holds.alerts) {
      const level = a.kind === "hold_hand_cancelled" ? "warning" : "error";
      log.error(`::${level}::${a.kind} ${a.service_decision_id}${a.commit ? ` in ${a.commit}` : ""}: ${a.why}`);
    }
    log.log(`ok    ${compiledAll.compiled.length} compiled, ${compiledAll.refused.length} refused, ` +
      `${compiledAll.held.length} held (${holdsEntered.written.length} entered, ${holdsEntered.kept.length} already on the tree), ` +
      `${holds.released.length} released, ${holds.cancelled.length} cancelled, ${holds.due.length} due and not built, ` +
      `${holds.unclear.length} unclear, ${holds.settled.length} already settled, ${recorded.length} recorded as settled`);
    if (!live) {
      // The sentence is now true because the code above makes it true, and the
      // suite checks the pair: this line, and a `paths.txt` naming none of it.
      log.log(`note  shadow: ${compiledAll.compiled.length} compiled, ${compiledAll.held.length} held, ` +
        `${compiledAll.refused.length} refused and ${recheck.submissions.length} terminal record(s) are withheld — none ` +
        "is written, listed for the commit, or posted (BOT-92)");
    }
    return 0;
  }

  if (job === "report") {
    // **Read from the `commit` job's outputs, never from a file.** A job starts
    // from a fresh checkout, so `moderation/results.json` — which this read
    // until 2026-09-22 — exists only in the job that wrote it; and
    // `ASTRA_MAIN_COMMIT` is the commit that job's `apply` step pushed, which
    // every `applied` and every newly entered `held` names (BOT-81).
    const state = parseResults(env.ASTRA_RESULTS);
    if (!state) {
      log.error("::error::report was handed no `results` from the commit job, so it has nothing to post and says so");
      return 1;
    }
    const { post, withheld } = resultsFromState(state, { commit: env.ASTRA_MAIN_COMMIT ?? null });
    for (const w of withheld) {
      log.log(`hold  ${w.service_decision_id} ${w.outcome} is not posted under a shadow answer (BOT-92); the next ` +
        "run answered shadow: false posts it once, and BOT-82's key settles a repeat as duplicate");
    }
    if (state.shadow !== false) {
      log.log(`note  shadow: ${post.length} result(s) posted, ${withheld.length} withheld (BOT-92)`);
    }
    const client = createClient({ workflow: "moderation", env, log, fetchImpl });
    // The body carries `commit` or `refusal_code` and never a null of either:
    // the token file makes each member conditional on the outcome, both ways,
    // and a null is a member carried. Until 2026-09-22 every row passed both,
    // and `composeBody` refused all three shapes this job posts.
    const unaccepted = [];
    for (const r of post) {
      const answer = await client.call("serviceDecisionResult", resultBody(r));
      if (!answer.ok) unaccepted.push(`${r.service_decision_id} ${r.outcome}`);
    }
    if (unaccepted.length) {
      // `settled` counts this run's results only when this job succeeded, so a
      // result that did not arrive is a decision it pages for.
      log.error(`::error::${unaccepted.length} result(s) were not accepted: ${unaccepted.join(", ")}`);
      return 1;
    }
    log.log(`ok    ${post.length} result(s) posted`);
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
    // The commit job's `results`, handed on only when `report` succeeded (the
    // workflow's expression), and read as nothing answered when absent — the
    // direction that pages.
    const state = parseResults(env.ASTRA_RESULTS);
    const results = state ? answeredBy(state, { commit: env.ASTRA_MAIN_COMMIT ?? null }) : [];
    const verdict = unsettled({ listed, results, listFailed: env.ASTRA_LIST_FAILED === "true" });
    if (!verdict.ok) {
      log.error(`::error::${verdict.why}`);
      return 1;
    }
    log.log(`ok    every one of ${listed.length} listed decision(s) has a result`);
    return 0;
  }

  throw new Error(`\`--job ${JSON.stringify(job)}\` is not one of list, history, commit, report, settled, alarms, verdict`);
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
