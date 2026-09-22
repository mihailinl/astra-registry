// §0.7's time, in one place (contract 0.34.0).
//
// **What §0.7 says, from 0.34.0:** times are RFC 3339 UTC, whole seconds,
// ending in `Z`, and *every time names a real UTC instant, and a seconds field
// of 60 is not admissible* — a day its month does not have (`2026-02-30`) and
// an hour of `24` are already not RFC 3339 date-times, and second `60`, which
// RFC 3339 permits in a leap-second month, is refused everywhere on the wire.
// 0.31.0 said it of the migration-notice marker's two times alone.
//
// **Why this module exists.** Until 0.34.0 this repository judged a time at
// twelve code sites and in seventeen schema patterns, and spelled the grammar
// five ways. The strictest — the marker's schema, `parseTime`, the cutover
// preflight — refused second 60; ten code sites in six modules and fifteen
// patterns in nine schemas admitted it, and admitted hour 24, minute 60 and
// day 32 with it. So a `policy/binding-deadline.json` carrying
// `…:60Z` was refused by `tools/validate.mjs` and accepted by the plugins
// service's reader of the same file, while a decision record's `Decided-At:`
// trailer, a baseline marker's `written_at` and every signed document's
// `issued_at` were admitted by this repository's own readers and refused by its
// own `parseTime`. One committed record, read two ways, is the shape SCOPE-8
// exists to find (ops `dev/server-registry-contract-pending.md` item 10).
//
// Every reader imports from here, and `tools/selftest/times.mjs` holds each of
// them to it: every date-time pattern under `schema/` is one of the two below,
// byte for byte; every reader refuses second 60, hour 24 and minute 60 and
// admits a real time; and no module in TRUST-31's set spells a time's
// grammar for itself.

/**
 * The grammar, as a JSON Schema `pattern` and a regular expression.
 *
 * Month 01–12, day 01–31, hour 00–23, minute and second 00–59. A pattern
 * cannot know how many days a month has, so `2026-02-30` passes it; `isTime`
 * is the half that refuses it, and a schema that carries this pattern is
 * followed by `isTime` wherever the reader is code.
 */
export const TIME_PATTERN =
  "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$";

/**
 * The same, admitting a fraction of a second — for the three schemas that
 * read a time the plugins service may send with one (`hold`, `hold-record`,
 * `moderation-work`), which the compiler truncates and never rounds. The
 * seconds field is bounded exactly as above: `…:60.5Z` is second 60.
 */
export const TIME_FRACTION_PATTERN =
  "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\\.[0-9]+)?Z$";

export const TIME_RE = new RegExp(TIME_PATTERN);
export const TIME_FRACTION_RE = new RegExp(TIME_FRACTION_PATTERN);

/** The whole-second part names a day the calendar has: not `2026-02-30`. */
function realInstant(wholeSeconds) {
  const ms = Date.parse(wholeSeconds);
  return Number.isFinite(ms) && new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z") === wholeSeconds;
}

/** A §0.7 time: the grammar, and a real UTC instant. */
export function isTime(value) {
  return typeof value === "string" && TIME_RE.test(value) && realInstant(value);
}

/** A §0.7 time that may carry a fraction of a second, which is not judged. */
export function isTimeWithFraction(value) {
  if (typeof value !== "string" || !TIME_FRACTION_RE.test(value)) return false;
  return realInstant(`${value.slice(0, 19)}Z`);
}

/**
 * `isTime` in the shape a grammar table holds: an object with `test`, which
 * is what `bot/lib/decisions.mjs`' trailer grammar and member tables call. A
 * regular expression there could not refuse `2026-02-30`.
 */
export const TIME = Object.freeze({ test: (value) => isTime(value), source: TIME_PATTERN });
