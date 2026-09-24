// The binding deadline, planned: the one value MIG-2 has the owner commit, the
// POLICY.md line MIG-3 holds it to, and the floors that decide whether a date
// may be committed at all (registry plan M-T5.2).
//
// ── WHAT WAS MISSING, AND WHY IT IS A LIBRARY ──────────────────────────────
//
// Everything that READS the deadline was on `main` before this file:
// `schema/deadline-v1.json` types it, `tools/validate.mjs` judges it,
// `bot/lib/listing-state.mjs` reads it for MIG-1, `tools/cutover-preflight.mjs`
// holds ROLL-32 to it, and `bot/tests/policy.test.mjs`'s MIG-3 test fails when
// POLICY.md and the file disagree. Nothing WROTE it. The plan puts the file
// and its POLICY.md line "in one commit", computed from the owner's estimate
// of cutover plus 60 days and at least 60 days after his estimate of round 2
// (contract MIG-2), never earlier than a committed one (MIG-29) — and every
// one of those clauses was going to be done by a person with a calculator on
// the day, under the one deadline this estate has that stops strangers'
// releases.
//
// So the arithmetic and the refusals live here, pure, and `tools/binding-
// deadline.mjs` is the thin command that reads the tree and writes the two
// files. It sits under `tools/lib/` — inside TRUST-31's set — for one reason:
// `tools/selftest/deadline.mjs` tests it, the publish path runs the selftest
// as its fifth gate, and a module that gate loads from outside the set is a
// red in `tools/selftest/loads.mjs` (contract 0.38.0). The command itself
// stays outside, because nothing a bot run or a gate reaches imports it.
//
// ── WHAT IT DOES NOT DECIDE ────────────────────────────────────────────────
//
// The estimate. MIG-2's date is "60 days after the owner's estimate of
// cutover", and the estimate is the owner's (OPEN-OWNER-8, closed on the rule
// and deferred on the date, 2026-09-23). This takes it as an argument and
// never defaults one.

import { isTime } from "./time.mjs";
import { DEADLINE_SCHEMA } from "../../bot/lib/listing-state.mjs";

const DAY_MS = 86_400_000;

/** MIG-2: the deadline is the owner's estimate of cutover plus exactly this. */
export const DEADLINE_AFTER_CUTOVER_DAYS = 60;

/** MIG-2's second floor: at least this long after the estimate of MIG-13's round 2. */
export const ROUND2_FLOOR_DAYS = 60;

/**
 * The line in root `POLICY.md` that states the deadline, found by this prefix.
 * Exactly one line may start with it: two would be two statements of one date,
 * which is MIG-3's failure written into the policy itself.
 */
export const POLICY_LINE_PREFIX = "**Binding deadline:**";

/** The line while no deadline is committed. It carries no date, so MIG-3's scan finds no claim in it. */
export const POLICY_LINE_ABSENT =
  `${POLICY_LINE_PREFIX} not fixed yet. It is committed as \`policy/binding-deadline.json\` before ` +
  "third-party bindings open, and this line then states it.";

/**
 * The line once a deadline is committed. It carries the §0.7 time and its
 * `YYYY-MM-DD` form, because MIG-3's test compares the prose on the ISO form.
 */
export function policyLine(deadline) {
  if (deadline === null) return POLICY_LINE_ABSENT;
  if (!isTime(deadline)) throw new Error(`the deadline ${JSON.stringify(deadline)} is not a §0.7 time`);
  return `${POLICY_LINE_PREFIX} ${deadline.slice(0, 10)} (\`${deadline}\`), the value committed in ` +
    "`policy/binding-deadline.json`, which is the one place the bot and the plugins service read it (contract " +
    "MIG-2, MIG-3). It is never moved earlier (MIG-29).";
}

/**
 * `text` with its one deadline line replaced by `policyLine(deadline)`.
 * Throws unless exactly one line starts with `POLICY_LINE_PREFIX` — a missing
 * anchor is a POLICY.md that nobody can hold to the file, and two anchors is
 * a policy that states the date twice.
 */
export function withPolicyLine(text, deadline) {
  const lines = text.split("\n");
  const at = lines.flatMap((l, i) => (l.startsWith(POLICY_LINE_PREFIX) ? [i] : []));
  if (at.length !== 1) {
    throw new Error(
      `POLICY.md has ${at.length} line(s) starting with ${JSON.stringify(POLICY_LINE_PREFIX)}, and there must be ` +
      "exactly one: it is the sentence MIG-3 holds to policy/binding-deadline.json",
    );
  }
  lines[at[0]] = policyLine(deadline);
  return lines.join("\n");
}

/** The record B.4 fixes: exactly `schema` and `deadline`, as the file is written. */
export function deadlineText(deadline) {
  if (!isTime(deadline)) throw new Error(`the deadline ${JSON.stringify(deadline)} is not a §0.7 time`);
  return `${JSON.stringify({ schema: DEADLINE_SCHEMA, deadline }, null, 2)}\n`;
}

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

/**
 * The deadline MIG-2 gives for these estimates, or the reasons it may not be
 * committed.
 *
 *   * `cutoverEstimate` — the owner's estimate of cutover, a §0.7 time.
 *     Required: MIG-2 computes from it and from nothing else.
 *   * `round2Estimate` — his estimate of MIG-13's round 2, a §0.7 time, or
 *     null. MIG-2's floor is at least 60 days after it; with no estimate the
 *     floor is not asked, and the plan says so in `notes`.
 *   * `committed` — the deadline already on the tree, or null. MIG-29: never
 *     earlier. The same date is not a change and writes nothing.
 *
 * @returns {{deadline: string|null, change: "new"|"later"|"same"|null, problems: string[], notes: string[]}}
 */
export function planDeadline({ cutoverEstimate, round2Estimate = null, committed = null }) {
  const problems = [];
  const notes = [];
  if (!isTime(cutoverEstimate)) {
    problems.push(`the cutover estimate ${JSON.stringify(cutoverEstimate)} is not a §0.7 time (RFC 3339 UTC, whole ` +
      "seconds, ending in Z, a real instant); MIG-2 computes the deadline from it and from nothing else");
  }
  if (round2Estimate !== null && !isTime(round2Estimate)) {
    problems.push(`the round-2 estimate ${JSON.stringify(round2Estimate)} is not a §0.7 time`);
  }
  if (committed !== null && !isTime(committed)) {
    problems.push(`the committed deadline ${JSON.stringify(committed)} is not a §0.7 time, so MIG-29 cannot be asked`);
  }
  if (problems.length) return { deadline: null, change: null, problems, notes };

  const deadlineMs = Date.parse(cutoverEstimate) + DEADLINE_AFTER_CUTOVER_DAYS * DAY_MS;
  const deadline = iso(deadlineMs);
  notes.push(`deadline = the cutover estimate ${cutoverEstimate} + ${DEADLINE_AFTER_CUTOVER_DAYS} days = ${deadline} (MIG-2)`);

  if (round2Estimate === null) {
    notes.push("no round-2 estimate was given, so MIG-2's second floor (60 days after round 2) was NOT ASKED");
  } else {
    const gap = (deadlineMs - Date.parse(round2Estimate)) / DAY_MS;
    if (gap < ROUND2_FLOOR_DAYS) {
      problems.push(`${deadline} is ${gap.toFixed(1)} day(s) after the round-2 estimate ${round2Estimate}, and MIG-2 ` +
        `keeps it at least ${ROUND2_FLOOR_DAYS}: an author told at round 2 must have that long to buy Astra, wait ` +
        "for `astraUser` and clear `R_FIRST_BINDING`. Move the estimates, not the rule");
    } else {
      notes.push(`${deadline} is ${gap.toFixed(1)} day(s) after the round-2 estimate ${round2Estimate} (MIG-2: at least ${ROUND2_FLOOR_DAYS})`);
    }
  }

  let change = "new";
  if (committed !== null) {
    const was = Date.parse(committed);
    if (deadlineMs < was) {
      problems.push(`${deadline} is earlier than the committed deadline ${committed}, and MIG-29 never moves it ` +
        "earlier: the authors were told the committed date");
      change = null;
    } else if (deadlineMs === was) {
      change = "same";
      notes.push(`${deadline} is the committed deadline already; nothing to write`);
    } else {
      change = "later";
      notes.push(`${deadline} moves the committed ${committed} later, which MIG-29 permits: it lands with POLICY.md ` +
        "in one commit and is re-sent to every MIG-13 recipient (a re-send, recorded per account)");
    }
  }
  return { deadline: problems.length ? null : deadline, change: problems.length ? null : change, problems, notes };
}
