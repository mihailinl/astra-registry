#!/usr/bin/env node
// `ingest.yml`'s schedule, and whether it is still firing.
//
//     node tools/coverage/drain-age.mjs [--repo <dir>] [--report <file>]
//
// **The registry's hourly drain publishes every delayed release, and nothing
// could tell it running quietly from its having stopped.** `ingest.yml`'s
// `17 * * * *` cron is the only thing that empties `state/queue/`; an author
// whose release was held was told, on their own thread, "publishes itself at
// 14:00". If that schedule stops — GitHub disables a scheduled workflow in a
// repository with 60 days of no activity, an owner can disable Actions in two
// clicks, and a `schedule:` block edited wrongly fails no test — every queued
// release simply never publishes. The symptom is *no releases were published*,
// which is what a quiet week looks like, so the person best placed to notice
// has been given a reason not to.
//
// The cost is why this is a rule and not a note: it repeats per queued release
// for the whole outage, and each one is a promise this registry made in
// writing.
//
// ── WHAT IS ACTUALLY MEASURABLE FROM COMMITTED STATE ────────────────────────
//
// The near miss is the useful part: the heartbeat already exists and nobody
// reads it. `ingest.yml` carries TWO crons in ONE `schedule:` block —
// `17 * * * *` drains the queue and `41 5 * * *` polls the quiet listings —
// and the second one commits `state/releases-seen.json` on EVERY run, because
// `runWatch` rewrites `updated_at` whether or not a single repository had
// anything new. A schedule that has been disabled loses both crons together,
// so that file's age is a liveness signal for the drain even though the drain
// writes nothing itself. It has been in the tree all along and no check has
// ever compared it with the clock.
//
// That proxy has a hole, and the hole is the whole reason for leg 1: delete or
// retime the `17 * * * *` line alone and the daily poll keeps committing, so
// `updated_at` stays fresh while the drain is dead. Worse, the schedule's
// router is a shell `case` on the cron STRING — `case "$SCHEDULE" in
// '17 * * * *')` — so moving the cron without moving the label does not stop
// the run, it silently turns the hourly drain into a second backstop poll.
//
// ── THE FOUR LEGS, AND WHICH FAILURE EACH ONE IS FOR ────────────────────────
//
//   1. ROUTING.  `ingest.yml` carries a live (uncommented) `- cron: '<x>'` and
//      the decide step's `case` routes that same literal `<x>` to
//      `bot/watch.mjs --drain`. Catches a removed, commented-out or retimed
//      drain cron the moment it lands — no waiting, no clock.
//   2. LIVENESS. `state/releases-seen.json`'s `updated_at` is under
//      MAX_SEEN_AGE_HOURS old. Catches the whole schedule having stopped: the
//      forge disabling it, Actions switched off, the `schedule:` block broken.
//      This is the leg that fires during a genuinely quiet week, which is
//      exactly the week nothing else would say anything.
//   3. RIPENESS. No queue entry is more than MAX_RIPE_AGE_HOURS past its own
//      `publish_after`. **This is the different failure**: a drain that RUNS
//      and commits nothing. The schedule fires, `updated_at` is fresh, leg 1
//      and leg 2 are green, and a release sits in `state/queue/` past the
//      minute it was promised because the publish job failed, lost its push,
//      or refused the entry. Nothing about that is visible from outside.
//   4. VISIBILITY (the floor for leg 3). Every `state/queue/*.json` on disk is
//      one `readQueue` returns. An entry missing `repo`, `tag` or
//      `publish_after` is skipped silently by the drain's own reader — so the
//      drain will never empty it AND leg 3 would never see it. A rule whose
//      set can be emptied by the same defect it watches for is a rule that
//      reports green about nothing.
//
// The queue is read through `readQueue` from `bot/lib/policy/queue.mjs` — the
// function `runDrain` itself calls — and not through a second reader of the
// same directory. `tools/cutover-preflight.mjs` needs a different one because
// it reads a git ref rather than the tree, and pays for it with a regex that
// checks the drain's filter has not moved out from under it. Importing costs
// nothing here and cannot drift.
//
// ── THE NUMBERS, WHICH ARE MEASURED AND NOT CHOSEN ──────────────────────────
//
// Over the 41 commits `state/releases-seen.json` has (2026-08-12 to
// 2026-09-21): median gap 24.00 h, largest gap ever 34.72 h — one missed daily
// run, on 2026-08-26. And the schedule is LATE, reliably: the delay from the
// 05:41 cron minute to the commit is 0.32 h at best, 4.25 h at the median and
// 12.03 h at the worst. Any bound that ignores that second measurement cries
// wolf at an operator for GitHub's queueing.
//
//   MAX_SEEN_AGE_HOURS = 72   three consecutive missed daily runs; 2.07x the
//                             largest gap this repository has ever had.
//   MAX_RIPE_AGE_HOURS = 24   twenty-four missed hourly drains, and 2x the
//                             worst cron-to-commit latency measured above.
//
// ── THE HALF THIS CANNOT DO ─────────────────────────────────────────────────
//
// **This rule goes red in the Actions tab; it does not page.** It runs inside
// `moderation-coverage.yml`, which is itself a schedule in this repository, so
// the one case it cannot report is Actions being disabled — both schedules
// stop together, and a liveness check that dies with what it watches has the
// ambiguity it was built to remove. The outer guard is BOT-85's receiver,
// which pages on the canary's silence from off this box, and provisioning it
// is an owner act. `PENDING_OWNER_ACTS`'s `ingest-schedule-receiver` in
// `tools/coverage/rules.mjs` prints that act on every run. The inner guard
// does not wait for it: red in the Actions tab is most of the value and is
// available today.
//
// ── ABSENCE ─────────────────────────────────────────────────────────────────
//
// Absence of `state/releases-seen.json` is `pending`, not red, and only until
// the file has existed once — the same rule `keepalive-age.mjs` applies, for
// the same reason. A fixture repository that has never run a backstop is not
// an estate whose backstop died. But once the file has been committed even
// once, its absence is a deletion, and a deletion is red: otherwise the honest
// "not yet" and the dangerous "not any more" are the same colour.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { report } from "./rules.mjs";
import { git } from "./git.mjs";
import { readQueue } from "../../bot/lib/policy/queue.mjs";
import { invalidId } from "../lib/ids.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..", "..");

export const RULE = "drain-age";
export const SEEN = "state/releases-seen.json";
export const QUEUE_DIR = "state/queue";
export const INGEST = ".github/workflows/ingest.yml";

/** Three consecutive missed daily backstops. Largest gap ever seen: 34.72 h. */
export const MAX_SEEN_AGE_HOURS = 72;
/** Twenty-four missed hourly drains, and 2x the worst measured run latency. */
export const MAX_RIPE_AGE_HOURS = 24;
/**
 * The floor for leg 2. `updated_at` advances on every backstop run, so an
 * empty `repos` map still looks alive — and a poll of nothing is what an
 * emptied `sources` list produces. One listed repository is not much of a
 * floor; it is the difference between a timestamp with a poll behind it and a
 * timestamp with nothing behind it.
 */
export const MIN_WATCHED_REPOS = 1;

const HOUR_MS = 60 * 60 * 1000;

/**
 * Every `- cron: '…'` in a workflow that is NOT commented out, with its line.
 *
 * Live ones only, and deliberately: `bot/tests/workflows.test.mjs` reads the
 * commented ones too because `plugins-ingest.yml` lands dark and is uncommented
 * at R3-open. This file asks the opposite question — is the drain firing TODAY
 * — and a commented cron is a drain that is not.
 */
export function liveCrons(src) {
  const out = [];
  src.split("\n").forEach((line, i) => {
    if (/^\s*#/.test(line)) return;
    const m = /^\s*-\s*cron:\s*['"]([^'"]+)['"]/.exec(line);
    if (m) out.push({ expr: m[1], line: i + 1 });
  });
  return out;
}

/**
 * The cron literals the decide step routes to `bot/watch.mjs --drain`.
 *
 * The router is a shell `case` over `$SCHEDULE`, whose labels are the cron
 * strings themselves. A label and a cron are therefore one decision written in
 * two places eleven lines apart, and the way they come apart is silent: the
 * `*)` arm runs the BACKSTOP, so a retimed cron whose label did not move keeps
 * the workflow green, keeps `updated_at` fresh, and stops draining the queue.
 */
export function drainRoutedCrons(src) {
  const routed = [];
  // `case "$SCHEDULE" in` … each arm is `'<expr>')` … until the next `;;`.
  const block = /case\s+"\$SCHEDULE"\s+in([\s\S]*?)\besac\b/.exec(src);
  if (!block) return { routed, why: `${INGEST} has no \`case "$SCHEDULE" in\` block; the schedule router has been reshaped` };
  for (const arm of block[1].split(";;")) {
    const label = /^\s*'([^']+)'\s*\)/m.exec(arm);
    if (!label) continue;
    if (/bot\/watch\.mjs\s+--drain/.test(arm)) routed.push(label[1]);
  }
  return { routed, why: null };
}

/** @returns {{status: string, codes: string[], ids: string[], hexes: string[], detail: string[]}} */
export function run(repo, { now = new Date() } = {}) {
  const codes = [];
  const ids = [];
  const detail = [];

  // ── leg 1: is there a drain cron at all, and does the router still aim at it?
  const ingestPath = path.join(repo, ...INGEST.split("/"));
  if (!fs.existsSync(ingestPath)) {
    codes.push("DRAIN_WORKFLOW_ABSENT");
    detail.push(`${INGEST} is not in the tree; the queue drain has no workflow to run in`);
  } else {
    const src = fs.readFileSync(ingestPath, "utf8");
    const live = liveCrons(src).map((c) => c.expr);
    const { routed, why } = drainRoutedCrons(src);
    if (why) {
      codes.push("DRAIN_ROUTER_RESHAPED");
      detail.push(why);
    }
    const firing = routed.filter((r) => live.includes(r));
    if (firing.length === 0) {
      codes.push("DRAIN_CRON_UNROUTED");
      detail.push(
        `no live cron in ${INGEST} is routed to \`bot/watch.mjs --drain\`. Live: ` +
        `${live.length ? live.map((c) => JSON.stringify(c)).join(", ") : "none"}; routed to --drain: ` +
        `${routed.length ? routed.map((c) => JSON.stringify(c)).join(", ") : "none"}. The router's \`*)\` arm ` +
        "runs the BACKSTOP, so a cron the case no longer names does not fail — it polls, commits, and leaves " +
        "state/queue/ untouched for ever",
      );
    } else {
      detail.push(`${INGEST} fires ${firing.map((c) => JSON.stringify(c)).join(", ")} into \`bot/watch.mjs --drain\``);
    }
  }

  // ── leg 2: has the schedule committed anything recently?
  const seenPath = path.join(repo, ...SEEN.split("/"));
  const everAdded = git(["log", "--format=%H", "--diff-filter=A", "--", SEEN], { cwd: repo, allowFailure: true })
    .split("\n").map((s) => s.trim()).filter(Boolean);

  // `pending`, not red, and only while the file has never existed. It is its
  // own flag rather than an early return: legs 1, 3 and 4 need no backstop
  // history to be true, and a rule that returned here would stop asserting
  // them the moment somebody handed it a fresh checkout.
  let neverRan = false;

  if (!fs.existsSync(seenPath)) {
    if (everAdded.length === 0) {
      neverRan = true;
      detail.push(
        `${SEEN} has never existed in this repository, so there is no run of ingest.yml's backstop to date and ` +
        "no clock to compare. Legs 1, 3 and 4 above still hold; leg 2 starts the day the first backstop commits",
      );
    } else {
      codes.push("DRAIN_MARKER_DELETED");
      detail.push(
        `${SEEN} was added in ${everAdded[everAdded.length - 1].slice(0, 12)} and is not in the tree now; the ` +
        "one committed trace that ingest.yml's schedule ran at all is gone",
      );
    }
  } else {
    let seen = null;
    try {
      seen = JSON.parse(fs.readFileSync(seenPath, "utf8"));
    } catch (e) {
      codes.push("DRAIN_MARKER_UNREADABLE");
      detail.push(`${SEEN} is not readable JSON: ${e.message}`);
    }
    if (seen) {
      const updated = seen.updated_at;
      const at = updated ? new Date(updated) : null;
      if (!at || Number.isNaN(at.getTime())) {
        codes.push("DRAIN_MARKER_UNDATED");
        detail.push(
          `${SEEN} carries no readable \`updated_at\` (${JSON.stringify(updated ?? null)}). bot/watch.mjs writes ` +
          "it on every backstop run, so a file without one is a file something other than the backstop wrote",
        );
      } else {
        const ageHours = (now.getTime() - at.getTime()) / HOUR_MS;
        detail.push(`${SEEN} says updated_at ${updated} (${ageHours.toFixed(1)} h ago)`);
        if (ageHours > MAX_SEEN_AGE_HOURS) {
          codes.push("DRAIN_SCHEDULE_STALE");
          detail.push(
            `that is over the ${MAX_SEEN_AGE_HOURS}-hour bound — three consecutive missed daily runs, against a ` +
            "largest-ever observed gap of 34.7 h. Both of ingest.yml's crons are in one `schedule:` block, so a " +
            "backstop that has stopped committing is an HOURLY DRAIN THAT HAS STOPPED TOO, and every delayed " +
            "release in state/queue/ is waiting on a schedule that is not firing",
          );
        }
      }
      const watched = Object.keys(seen.repos ?? {}).length;
      if (watched < MIN_WATCHED_REPOS) {
        codes.push("DRAIN_WATCH_SET_EMPTY");
        detail.push(
          `${SEEN} records ${watched} polled repositor${watched === 1 ? "y" : "ies"}, below the floor of ` +
          `${MIN_WATCHED_REPOS}. updated_at advances on every run whether or not anything was polled, so below ` +
          "this floor the age above is a timestamp with nothing behind it",
        );
      }
    }
  }

  // ── legs 3 and 4: the queue the drain is supposed to be emptying
  const queueRoot = path.join(repo, ...QUEUE_DIR.split("/"));
  let onDisk = [];
  try {
    onDisk = fs.readdirSync(queueRoot).filter((n) => n.endsWith(".json"));
  } catch {
    onDisk = [];
  }
  const visible = readQueue(repo);
  const visibleNames = new Set(visible.map((e) => path.basename(e.file)));
  const invisible = onDisk.filter((n) => !visibleNames.has(n));
  if (invisible.length) {
    codes.push("DRAIN_QUEUE_INVISIBLE");
    detail.push(
      `${invisible.length} file(s) in ${QUEUE_DIR}/ are invisible to readQueue — ` +
      `${invisible.map((n) => JSON.stringify(n)).join(", ")}. It keeps only entries carrying \`repo\`, \`tag\` ` +
      "and `publish_after` and skips the rest without a word, so the drain will never empty these and the " +
      "ripeness check below cannot see them either",
    );
  }

  detail.push(
    `${QUEUE_DIR}/ holds ${onDisk.length} file(s), ${visible.length} of them visible to the drain's own reader`,
  );
  for (const entry of visible) {
    const at = new Date(entry.publish_after);
    if (Number.isNaN(at.getTime())) {
      codes.push("DRAIN_QUEUE_UNDATED");
      detail.push(`${entry.file} has an unreadable publish_after ${JSON.stringify(entry.publish_after)}`);
      continue;
    }
    const lateHours = (now.getTime() - at.getTime()) / HOUR_MS;
    if (lateHours > MAX_RIPE_AGE_HOURS) {
      codes.push("DRAIN_QUEUE_OVERDUE");
      // The id reaches the alarm only if it is one the channel will carry; an
      // alarm that arrives as E_VERDICT_UNSENDABLE is the alarm complaining
      // about itself. The file name is in `detail` either way.
      if (entry.id && !invalidId(String(entry.id))) ids.push(String(entry.id));
      detail.push(
        `${entry.file} was due at ${entry.publish_after} and is ${lateHours.toFixed(1)} h past it, over the ` +
        `${MAX_RIPE_AGE_HOURS}-hour bound. The hourly drain either is not running or is running and publishing ` +
        "nothing; those are different faults and only the first one has any other symptom",
      );
    }
  }

  const status = codes.length ? "red" : neverRan ? "pending" : "green";
  return { status, codes, ids, hexes: [], detail };
}

function main(argv) {
  const args = { repo: DEFAULT_REPO, report: process.env.ASTRA_COVERAGE_FINDINGS };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--repo") args.repo = path.resolve(argv[++i]);
    else if (argv[i] === "--report") args.report = argv[++i];
    else { console.error(`FAIL  unknown argument ${JSON.stringify(argv[i])}`); return 2; }
  }
  report(RULE, run(args.repo), args.report);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
