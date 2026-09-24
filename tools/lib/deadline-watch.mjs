// ROLL-63's deadline watch, as a pure judgement over dates (registry plan
// M-T5.4). `tools/deadline-watch.mjs` gathers the inputs — the tree, the
// markers' history, the clock, the banner — and this decides.
//
// ── WHAT IT ALARMS ON ──────────────────────────────────────────────────────
//
//   (a) round 2 cannot give MIG-2's 60 days any more: the deadline is under
//       60 days away and no round-2 marker is on `main`, or the round-2
//       marker's `sent_at` is under 60 days before the deadline.
//   (b) the deadline is under 30 days away and `log/cutover.json` is not on
//       `main` — MIG-29 keeps it at least 30 days after cutover.
//   (c) the deadline is under 14 days away and no round-3 marker is on
//       `main`, or round 3's `sent_at` is under 14 days before it (MIG-13).
//   guard n22: a marker's `cutover_planned_at` moved EARLIER while its
//       `sent_at` stayed the same. An earlier date is a new round 2 with a new
//       `sent_at`; the same `sent_at` means the procedure was done wrong, and
//       every clock that counts from it counts from a date the authors were
//       never given notice of.
//   guard n28: a marker on `main` announces a cutover date the authoritative
//       one (the highest `round` present) does not.
//   banner: the listing banner MIG-13 names serves a date the authoritative
//       marker does not carry. minice-be's banner takes its date from an
//       owner-set knob and not from the marker, so a re-send can move the
//       marker and leave the banner behind, silently on both sides.
//
// **It reads `sent_at`, never a commit's date.** A re-send that re-commits
// round 2's marker with a later cutover keeps its `sent_at`, and (a) keyed on
// the commit would count 60 days from the re-commit and fire about a round
// the authors already had.
//
// **No deadline is a state, not a finding** (BOT-72): there is nothing to
// count down to, and the watch says so. The two guards still run, because a
// marker announcing a superseded date is wrong whether or not a deadline has
// been committed.
//
// **It never waits.** It compares the clock it is handed with dates; a
// fixture clock is a `now` argument.

import { isTime } from "./time.mjs";
import { authoritative } from "./migration-notice.mjs";

const DAY_MS = 86_400_000;

export const ROUND2_DAYS = 60;
export const CUTOVER_DAYS = 30;
export const ROUND3_DAYS = 14;

/** The check this watch reports as, in `bot/lib/alert-checks.mjs`. */
export const CHECK = "deadline-watch";

/** The fixed codes a verdict may carry (bot/lib/alert-verdict.mjs: no sentences). */
export const CODES = Object.freeze({
  round2: "DEADLINE_ROUND2_UNFIT",
  cutover: "DEADLINE_NO_CUTOVER",
  round3: "DEADLINE_ROUND3_UNFIT",
  earlier: "MARKER_EARLIER_SAME_SENT_AT",
  superseded: "MARKER_DATE_SUPERSEDED",
  unreadable: "MARKER_UNREADABLE",
  bannerDiffers: "BANNER_DATE_DIFFERS",
  bannerUnreachable: "BANNER_UNREACHABLE",
});

const days = (ms) => (ms / DAY_MS).toFixed(1);

/**
 * Guard n22 over one marker file's history, oldest first.
 *
 * Among the versions that share the CURRENT version's `sent_at` — the ones
 * that record this send — the announced date may only have stayed or moved
 * later. The current date being earlier than any of them is n22's wrong turn.
 * A version with a different `sent_at` is a different send (a new round 2),
 * and is not compared: that is the procedure done right.
 *
 * @param history {{sent_at?: string, cutover_planned_at?: string}[]}
 * @returns {string|null} the finding, or null
 */
export function earlierWithSameSentAt(file, history) {
  const readable = history.filter((v) => v && isTime(v.sent_at));
  if (!readable.length) return null;
  const now = readable[readable.length - 1];
  if (!isTime(now.cutover_planned_at)) return null;
  const same = readable.filter((v) => v.sent_at === now.sent_at && isTime(v.cutover_planned_at));
  const latest = same.reduce((a, v) => (Date.parse(v.cutover_planned_at) > Date.parse(a.cutover_planned_at) ? v : a), same[0]);
  if (Date.parse(now.cutover_planned_at) < Date.parse(latest.cutover_planned_at)) {
    return `${file} announced ${latest.cutover_planned_at} and now announces the EARLIER ${now.cutover_planned_at} ` +
      `under the same sent_at ${now.sent_at}. An earlier cutover is a new round 2 with its own sent_at (MIG-13, n22); ` +
      "kept, it leaves every clock counting from a notice of a date that is not the one arriving";
  }
  return null;
}

/**
 * The date a banner page carries, if it carries the one it should.
 *
 * The page is minice-be's HTML, and nothing publishes how it spells a date.
 * So this does not parse it for "the" date: it asks whether the page carries
 * the authoritative date, as the §0.7 time or as its `YYYY-MM-DD`, and a page
 * that carries neither differs. A page that spells the date some other way is
 * red too, loudly — the fix then is a published banner form (the contract ask
 * in the lane report), not a looser check.
 */
export function bannerCarries(body, expected) {
  if (typeof body !== "string") return false;
  return body.includes(expected) || body.includes(expected.slice(0, 10));
}

/**
 * @param {{
 *   deadline: string|null,        policy/binding-deadline.json's value, or null
 *   cutoverOnMain: boolean,       log/cutover.json is on the tree
 *   markers: object[],            tools/lib/migration-notice.mjs readMarkers()
 *   histories: Record<string, object[]>,  each marker file's versions, oldest first
 *   now: string,                  the clock, a §0.7 time
 *   banner: {id: string, url: string, status: number|null, body: string|null}|null,
 * }} input
 * @returns {{status: "red"|"green", codes: string[], ids: string[], detail: string[]}}
 */
export function judge({ deadline, cutoverOnMain, markers, histories = {}, now, banner = null }) {
  const codes = [];
  const ids = [];
  const detail = [];
  const add = (code, line) => { codes.push(code); detail.push(`${code}: ${line}`); };
  if (!isTime(now)) throw new Error(`the clock ${JSON.stringify(now)} is not a §0.7 time`);
  const nowMs = Date.parse(now);

  const { marker: top, problems } = authoritative(markers);
  for (const p of problems) add(CODES.unreadable, p);
  const readable = problems.length ? [] : markers;
  const round = (n) => readable.find((m) => m.doc.round === n) ?? null;

  // The guards first: they are about the markers, deadline or not.
  for (const m of readable) {
    const finding = earlierWithSameSentAt(m.file, histories[m.file] ?? [m.doc]);
    if (finding) add(CODES.earlier, finding);
  }
  const announced = top && top.doc.round >= 2 ? top.doc.cutover_planned_at : null;
  if (announced) {
    detail.push(`authoritative marker: ${top.file} (round ${top.doc.round}), announcing ${announced}`);
    for (const m of readable.filter((x) => x.doc.round >= 2 && x.doc.cutover_planned_at !== announced)) {
      add(CODES.superseded, `${m.file} announces ${m.doc.cutover_planned_at} and the authoritative round ` +
        `${top.doc.round} announces ${announced}; re-commit it (MIG-13, n28)`);
    }
  } else {
    detail.push(top ? `authoritative marker: ${top.file} (round ${top.doc.round}), which carries no date` : "no migration-notice marker on this tree");
  }

  if (deadline === null) {
    detail.push("no binding deadline is committed, so (a), (b) and (c) have nothing to count down to (BOT-72)");
  } else {
    if (!isTime(deadline)) throw new Error(`the deadline ${JSON.stringify(deadline)} is not a §0.7 time`);
    const dl = Date.parse(deadline);
    const away = dl - nowMs;
    detail.push(`deadline ${deadline}, ${days(away)} day(s) away at ${now}`);

    const two = round(2);
    if (!two && away < ROUND2_DAYS * DAY_MS) {
      add(CODES.round2, `the deadline is ${days(away)} day(s) away and no round-2 marker is on main; MIG-2 keeps it at ` +
        `least ${ROUND2_DAYS} days after round 2`);
    } else if (two && dl - Date.parse(two.doc.sent_at) < ROUND2_DAYS * DAY_MS) {
      add(CODES.round2, `round 2 was sent at ${two.doc.sent_at}, ${days(dl - Date.parse(two.doc.sent_at))} day(s) before ` +
        `the deadline, and MIG-2 keeps it at least ${ROUND2_DAYS}`);
    }
    if (!cutoverOnMain && away < CUTOVER_DAYS * DAY_MS) {
      add(CODES.cutover, `the deadline is ${days(away)} day(s) away and log/cutover.json is not on main; MIG-29 keeps ` +
        `it at least ${CUTOVER_DAYS} days after cutover — the owner moves it later (never earlier)`);
    }
    const three = round(3);
    if (!three && away < ROUND3_DAYS * DAY_MS) {
      add(CODES.round3, `the deadline is ${days(away)} day(s) away and no round-3 marker is on main; MIG-13 sends round ` +
        `3 at least ${ROUND3_DAYS} days before it`);
    } else if (three && dl - Date.parse(three.doc.sent_at) < ROUND3_DAYS * DAY_MS) {
      add(CODES.round3, `round 3 was sent at ${three.doc.sent_at}, ${days(dl - Date.parse(three.doc.sent_at))} day(s) ` +
        `before the deadline, and MIG-13 sends it at least ${ROUND3_DAYS} before`);
    }
  }

  // The banner, only once there is a date for it to show: before round 2's
  // marker MIG-13's banner shows none, and there is nothing to compare.
  if (announced && banner) {
    if (banner.status !== 200) {
      add(CODES.bannerUnreachable, `${banner.url} answered ${banner.status ?? "nothing"}; MIG-13's banner is one of the ` +
        "two ways a round reaches an author, and a page that does not load tells nobody");
      ids.push(banner.id);
    } else if (!bannerCarries(banner.body, announced)) {
      add(CODES.bannerDiffers, `${banner.url} does not carry the announced cutover date ${announced} (as the time or ` +
        "as its YYYY-MM-DD); the banner is showing some other date, or none");
      ids.push(banner.id);
    } else {
      detail.push(`${banner.url} carries the announced date ${announced}`);
    }
  } else if (announced) {
    detail.push("the banner was not read this run");
  }

  return { status: codes.length ? "red" : "green", codes, ids, detail };
}
