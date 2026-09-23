// What a served-set check reports, and the one grammar it is allowed to report
// it in.
//
// Two jobs of `served-set.yml` compare things, and one `alert` job turns what
// they found into the single message a person reads (registry plan RC-R1-4,
// RC-R1-5: "Same `alert` job"). Between them is a GitHub job output, which is a
// string — so this module is where a finding stops being a sentence and becomes
// a fixed code the alarm channel will carry.
//
// **The codes are validated HERE, against the channel's own pattern.** A code
// the channel refuses is not a cosmetic problem: `bot/lib/alert-verdict.mjs`
// refuses the whole verdict, `bot/alert.mjs` exits non-zero, and the alarm that
// was about a real drift is never sent — the run goes red in a tab nobody has
// open, and the receiver hears the heartbeat's absence a day later at best
// (`boundMinutes`'s floor for a poster GitHub schedules). So `CODE_PATTERN`
// is imported from the channel rather than re-typed, and a code that does not
// match makes THIS job red, in CI, where its author is standing.
//
// **Nothing from a plugin's tree reaches the verdict.** The channel's grammar
// would take plugin ids and 64-hex digests, and the first draft of this file
// put the drifting ids in so the operator could see them. It is out, on
// purpose: those strings come from `tools/revocations/**` and from `signed`,
// and if one of them ever failed the channel's grammar the failure would land
// at exactly the moment an alarm was owed. Codes and 40-hex commit SHAs are
// generated here and nowhere else, so the verdict cannot be made unsendable by
// the content it is about. The run URL carries the operator to the transcript,
// which has every detail in it.

import fs from "node:fs";

import { CODE_PATTERN } from "../../bot/lib/alert-verdict.mjs";

const CODE_RE = new RegExp(CODE_PATTERN);
const SHA_RE = /^[0-9a-f]{40}$/;

/**
 * SERVE-39's and SERVE-85's shared window: a difference is only a failure more
 * than this long after the commit it is measured from.
 *
 * Both requirements say 30 minutes and they say it about different clocks —
 * SERVE-85 about the `main` commit, SERVE-39 about the `signed` one — so the
 * number is one constant and the CHOICE of clock is each checker's own, named
 * where it is made.
 */
export const GRACE_MINUTES = 30;

/**
 * One thing a check found.
 *
 * @param {string} code a fixed code the alarm channel will carry
 * @param {string} message the sentence a reader gets in the run's transcript
 */
export function finding(code, message) {
  if (!CODE_RE.test(code)) {
    throw new Error(
      `${JSON.stringify(code)} is not a code the alarm channel will carry (${CODE_PATTERN}). A verdict carrying ` +
      `it is refused by bot/lib/alert-verdict.mjs, which means no alarm is sent about whatever this finding was.`,
    );
  }
  return { code, message };
}

/**
 * A check's whole answer.
 *
 * `status` is what the alarm reads. `waiting` is the third state and it is not
 * a status: a comparison whose other side does not exist yet is green, says so
 * out loud in the transcript, and still posts its heartbeat — so the dead-man
 * path is live from the first run while the comparison is honest about having
 * nothing to compare. RC-R1-0 creates every receiver check whose poster does
 * not run yet disarmed for the same reason (`bot/lib/alert-checks.mjs`), and
 * TRUST-45 prices the alternative: "an always-firing alarm is ignored".
 *
 * @param {{findings?: object[], waiting?: string[], hexes?: string[], notes?: string[]}} parts
 */
export function verdict({ findings = [], waiting = [], hexes = [], notes = [] } = {}) {
  for (const hex of hexes) {
    if (!SHA_RE.test(hex)) throw new Error(`${JSON.stringify(hex)} is not a 40-hex commit SHA`);
  }
  return {
    status: findings.length ? "red" : "green",
    findings,
    waiting,
    hexes: [...new Set(hexes)],
    notes,
  };
}

/**
 * Print the transcript and write the job's outputs.
 *
 * The outputs are three: `status`, `codes` (space-separated) and `hexes`. They
 * are what the `alert` job composes its verdict from, and they are deliberately
 * the whole interface — a job output is a string on a wire between two jobs,
 * and anything richer would be a second document shape for one message.
 *
 * `codes` is capped, and the cap is not tidiness: the channel refuses a verdict
 * with more than 40 elements in a list, so a check that found sixty things
 * would render a verdict that cannot be sent. Above the cap the codes are
 * de-duplicated and the count goes into the transcript.
 *
 * @param {object} v from `verdict`
 * @param {{out?: string|null, log?: Console}} opts `out` is $GITHUB_OUTPUT
 */
export function emit(v, { out = process.env.GITHUB_OUTPUT ?? null, log = console } = {}) {
  for (const line of v.notes) log.log(`      ${line}`);
  for (const line of v.waiting) log.log(`wait  ${line}`);
  for (const f of v.findings) log.log(`FAIL  ${f.code}: ${f.message}`);
  if (v.status === "green") log.log(`ok    nothing differs${v.waiting.length ? ", and the waits above are stated" : ""}`);

  const codes = [...new Set(v.findings.map((f) => f.code))].slice(0, 40);
  if (out) {
    fs.appendFileSync(out, `status=${v.status}\ncodes=${codes.join(" ")}\nhexes=${v.hexes.join(" ")}\n`);
  }
  return { status: v.status, codes, hexes: v.hexes };
}

/**
 * Minutes between two RFC 3339 instants, or `null` when either is unreadable.
 *
 * `null` rather than 0 or Infinity, because both of those are a decision: 0
 * excuses every difference for ever, Infinity fails one that may be seconds
 * old. A caller that gets `null` has to say what it does about a clock it
 * cannot read, and both callers here treat it as "no excuse" — an unreadable
 * commit time is itself a fault.
 */
export function minutesSince(from, now) {
  const a = Date.parse(from);
  const b = Date.parse(now);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return (b - a) / 60000;
}

/**
 * Is a difference measured from `from` still inside the window at `now`?
 *
 * Both edges. A `from` dated more than the window's own width AFTER `now` is
 * a clock that cannot be read, and an unreadable clock excuses nothing (above):
 * a negative wait is not a short one. Skew inside the width — a runner and a
 * committer disagreeing by minutes — is inside the window, and must not page.
 *
 * The bound used to be the callers'. SERVE-85 and A7 each added it by hand
 * (`waited >= -grace`, 2026-09-22) and SERVE-39 did not, so a `signed` commit
 * dated 132 days ahead excused Pages drifting from it — both the documents and,
 * after the latch, the withdrawal list — until that date (measured on a
 * fixture). One edge here, and none at the callers, is what makes a caller
 * that forgets it impossible and each caller's test a test of this line.
 */
export function withinGrace(from, now, graceMinutes = GRACE_MINUTES) {
  const mins = minutesSince(from, now);
  return mins !== null && mins <= graceMinutes && mins >= -graceMinutes;
}
