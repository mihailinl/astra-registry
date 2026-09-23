// The results the plugins service has already answered as settled, for the one
// kind of result the moderation run derives from history (ops dev/couplings.md
// entry 100).
//
// ── THE DEFECT ──────────────────────────────────────────────────────────────
//
// A hold that has left the tree is ended by a commit, and `holdDeletions` in
// `bot/moderation-run.mjs` reads every such commit in the whole of `main`'s
// history, every run: a hand deletion is a `cancelled`, a release commit an
// `applied`. Nothing on this side recorded that the service had accepted one,
// so every live run posted every one of them again, and warned again about
// every hand cancellation. BOT-82 answers each repeat `duplicate`, so nothing
// was wrong at the service; the posts and the warnings simply grew with history
// for ever, and a warning that repeats every ten minutes is one nobody reads by
// the time it matters. Measured before this file existed: two consecutive live
// runs over one hand-deleted hold each posted the same `cancelled`, and each
// warned.
//
// ── THE RULE, IN ONE LINE ───────────────────────────────────────────────────
//
// **A result is recorded as settled when the service ANSWERED `accepted` or
// `duplicate` for it — never because it was posted.** A 5xx, a timeout, a
// refusal, a body this bot cannot read, an answer carrying `shadow: true`, or
// an acknowledgement word outside the token file's `result_acknowledgements`
// each leave it unrecorded, and an unrecorded result is posted again. The
// acceptor (minice-e4) chose this over a service-side "settled?" read and
// refused a walk bounded by BOT-84's window: a bound loses a result whenever
// the service is down, or in shadow, for longer than the window.
//
// ── WHERE THE ANSWER COMES FROM, AND WHY IT IS `list` ───────────────────────
//
// The job that sees an answer holds a bot token and may not write `main`; the
// job that writes `main` holds no token (BOT-2). In `plugins-moderation.yml`
// `report` posts AFTER `commit`, so an answer `report` saw could reach the
// writer only in the NEXT run — through an artifact, which a token job may not
// upload (BOT-55) and which `commit` could fetch from another run only with
// `actions: read`, a permission it does not hold; or through the Actions cache,
// which neither job may touch (BOT-56). Each of those was measured against
// `bot/tests/workflows.test.mjs`.
//
// A result derived from history names a commit that is already on `main`, so
// it is not a promise that waits for this run's push (BOT-6's reason does not
// reach it). So the `list` job, which already holds the token, posts those
// results BEFORE `commit` runs, and hands the rows this file composes on as a
// job output — the one channel `commit` already reads (`needs.list.outputs`,
// re-checked). `commit` records them in the commit it already makes. No job
// gains a permission, an environment or a secret, and the job that writes
// still holds no token.
//
// ── WHAT A ROW IS TRUSTED FOR, AND WHAT A BAD ONE COSTS ─────────────────────
//
// `commit` cannot check an answer it never saw. It trusts `list`'s output
// exactly as far as it trusts `list`'s `entries` — re-checked for shape, and
// here also for naming a result this run's own walk derived — and the record
// on `main` is outside TRUST-31's hashed set, like every record under `state/`.
// So a forged or corrupted row that is well formed makes the walk skip a
// result the service never recorded. What that can do is bounded: it changes
// nothing in git — no listing, no advisory, no withdrawal — and only keeps the
// service's record of a hold's END from arriving, so the decision stays `held`
// there. Whether the service then alarms is the service's: the acceptor states
// that its detector B sees a decision with no final result. This side has not
// verified that, and read in the contract it is not obvious — FLOW-31's 48-hour
// `held` bound is a submission's, BOT-84 fires only for a decision with no
// settled result and a `held` result is settled, and detector B's row 2 matches
// a commit by its `Service-Decision:` trailer, which a hand deletion lacks. So
// a skip is traced by a person, which is why every row keeps the time of the
// answer and the run that received it, and why the file is in git, where every
// row has a commit.
//
// Every other fault degrades to re-posting, never to silence: a missing file
// skips nothing; a file that is not JSON, or not this schema, skips nothing
// and says so; a row that is malformed is ignored and said.

import fs from "node:fs";
import path from "node:path";

import { RUN_URL_PATTERN } from "./alert-verdict.mjs";
import { resultKey } from "./holds.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { validate } from "../../tools/lib/jsonschema.mjs";
import { TIME_PATTERN, isTime } from "../../tools/lib/time.mjs";

/**
 * Where the record lives: `state/`, outside TRUST-31's hashed set, because it
 * is a record a run writes as it works and not a rule a run judges by — the
 * rule is this file, which is in the set under `bot/lib/`. Declared in
 * `bot/tests/code-paths.test.mjs`'s `DATA_OUTSIDE` with that reason.
 */
export const SETTLED_FILE = "state/moderation-settled.json";

/** Registry-only: no other party reads it, so it is in no contract and not in the token file. */
export const SETTLED_SCHEMA = "astra.registry.moderation-settled/1";

/**
 * The two acknowledgement words that settle a result: the token file's
 * `list:result_acknowledgements`, which `bot/tests/moderation-run.test.mjs`
 * compares with this in both directions. A word the service adds later is not
 * read as settled until this list learns it — the re-posting direction.
 */
export const SETTLING_ANSWERS = Object.freeze(["accepted", "duplicate"]);

/** The results a hold ended in history can be (`classifyHoldCommit`); `unclear` gets none. */
export const HISTORY_OUTCOMES = Object.freeze(["applied", "cancelled"]);

/** BOT-82's key, the one definition (`bot/lib/holds.mjs`). A row skips exactly this triple. */
export const settledKey = (r) => resultKey(r);

/** One row: BOT-82's triple, the answer that settled it, when, and in which run. */
export const ROW_SCHEMA = Object.freeze({
  type: "object",
  required: ["service_decision_id", "outcome", "commit", "answer", "answered_at", "run"],
  additionalProperties: false,
  properties: {
    // `schema/hold-v1.json`'s own bound on the id: a hold's id is its file name.
    service_decision_id: { type: "string", minLength: 1, maxLength: 200 },
    outcome: { enum: [...HISTORY_OUTCOMES] },
    commit: { type: "string", pattern: "^[0-9a-f]{40}$" },
    answer: { enum: [...SETTLING_ANSWERS] },
    // §0.7's time, whole seconds: the one grammar, from `tools/lib/time.mjs`.
    answered_at: { type: "string", pattern: TIME_PATTERN },
    run: { type: "string", pattern: RUN_URL_PATTERN },
  },
});

/** What is wrong with one row, as sentences; empty when it may be trusted. */
export function rowProblems(row) {
  const problems = validate(ROW_SCHEMA, row, "$").map((p) => `${p.path} ${p.message}`);
  // The pattern cannot know a month's length; `isTime` refuses `2026-02-30`.
  if (!problems.length && !isTime(row.answered_at)) problems.push("$.answered_at is not a real instant");
  return problems;
}

const second = (now) => `${now.toISOString().slice(0, 19)}Z`;

/**
 * The row an answer earns, or `null` and why. **Keyed on the answer**: `ok`
 * alone is what a shadow answer and an unreadable one also carry (the client
 * returns both as `ok: true`), so each is asked by name.
 *
 * @param {{service_decision_id: string, outcome: string, commit: string}} pair
 * @param {object} answer what `createClient().call` returned for the post.
 */
export function settledRow(pair, answer, { now = new Date(), run = null } = {}) {
  const no = (why) => ({ row: null, why });
  if (answer?.ok !== true) {
    return no(answer?.refused
      ? `the service refused it (\`${answer.refused}\`)`
      : `no answer settled it (${answer?.cause ?? answer?.wait ?? "the call did not succeed"})`);
  }
  if (answer.unreadable === true) return no("the answer failed its schema, and an answer nobody can read settles nothing");
  if (answer.shadow !== false || answer.body?.shadow !== false) {
    return no("the answer carries `shadow: true`, and a shadow answer records nothing (ID-71)");
  }
  const word = answer.body?.outcome;
  if (!SETTLING_ANSWERS.includes(word)) {
    return no(`the service answered ${JSON.stringify(word)}, which is not one of ${SETTLING_ANSWERS.join(", ")}`);
  }
  const row = {
    service_decision_id: pair.service_decision_id,
    outcome: pair.outcome,
    commit: pair.commit,
    answer: word,
    answered_at: second(now),
    run,
  };
  const problems = rowProblems(row);
  if (problems.length) return no(`the row it would record is not sound: ${problems.join("; ")}`);
  return { row, why: null };
}

/**
 * The record on this tree, and what it may skip.
 *
 * `state` is `absent`, `read` or `unreadable`, and only `read` skips anything.
 * A file that is not JSON, or not this schema, is `unreadable`: nothing is
 * skipped and `problems` says why. A malformed row in a sound file is dropped
 * and named, and the rows beside it still count.
 */
export function readSettled(root = REPO_ROOT) {
  const full = path.join(root, ...SETTLED_FILE.split("/"));
  const none = (state, problems = []) => ({ state, rows: [], keys: new Set(), problems });
  if (!fs.existsSync(full)) return none("absent");
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(full, "utf8"));
  } catch (err) {
    return none("unreadable", [
      `${SETTLED_FILE} is not JSON (${String(err.message).split("\n")[0]}), so no result is skipped and every one ` +
      "derived from history is posted again until the file is rewritten",
    ]);
  }
  const shapeOk = doc && typeof doc === "object" && !Array.isArray(doc) &&
    doc.schema === SETTLED_SCHEMA && Array.isArray(doc.settled) &&
    Object.keys(doc).every((k) => k === "schema" || k === "settled");
  if (!shapeOk) {
    return none("unreadable", [
      `${SETTLED_FILE} is not \`${SETTLED_SCHEMA}\` (a \`schema\` and a \`settled\` array, and nothing else), so no ` +
      "result is skipped and every one derived from history is posted again until the file is rewritten",
    ]);
  }
  const rows = [];
  const problems = [];
  doc.settled.forEach((row, i) => {
    const wrong = rowProblems(row);
    if (wrong.length) {
      problems.push(`${SETTLED_FILE} settled[${i}] is ignored, so the result it names is posted again: ${wrong.join("; ")}`);
      return;
    }
    rows.push(row);
  });
  return { state: "read", rows, keys: new Set(rows.map(settledKey)), problems };
}

/**
 * The commit job's re-check of what `list` handed on: each row must be sound
 * AND name a result this run's own walk derived and has not already recorded.
 * A row naming anything else is dropped and named — it cannot skip a result
 * that exists, and it would only grow the record.
 */
export function acceptRows(handed, { derived = new Set() } = {}) {
  const rows = [];
  const problems = [];
  if (!Array.isArray(handed)) {
    return { rows, problems: ["the `settled` rows handed on by `list` are not an array, so none is recorded"] };
  }
  const seen = new Set();
  handed.forEach((row, i) => {
    const wrong = rowProblems(row);
    if (wrong.length) { problems.push(`settled[${i}] is not recorded: ${wrong.join("; ")}`); return; }
    const k = settledKey(row);
    if (!derived.has(k)) {
      problems.push(`settled[${i}] names ${k}, which this run's walk did not derive as a result still to post, so it is not recorded`);
      return;
    }
    if (seen.has(k)) return;
    seen.add(k);
    rows.push(row);
  });
  return { rows, problems };
}

/** The record with `added` merged in: sorted by BOT-82's key, the first answer kept for a key seen twice. */
export function composeSettled(existing = [], added = []) {
  const byKey = new Map();
  for (const row of [...existing, ...added]) if (!byKey.has(settledKey(row))) byKey.set(settledKey(row), row);
  const settled = [...byKey.values()].sort((a, b) => (settledKey(a) < settledKey(b) ? -1 : settledKey(a) > settledKey(b) ? 1 : 0));
  return { schema: SETTLED_SCHEMA, settled };
}

/** Write the record and return its path, for `composeCommit`. */
export function writeSettled(root, doc) {
  for (const row of doc.settled) {
    const wrong = rowProblems(row);
    if (wrong.length) throw new Error(`a row about to be written to ${SETTLED_FILE} is not sound: ${wrong.join("; ")}`);
  }
  const full = path.join(root, ...SETTLED_FILE.split("/"));
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, `${JSON.stringify(doc, null, 2)}\n`);
  return SETTLED_FILE;
}
