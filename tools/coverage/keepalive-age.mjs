#!/usr/bin/env node
// ROLL-62's keepalive, and whether it is still happening.
//
//     node tools/coverage/keepalive-age.mjs [--repo <dir>] [--report <file>]
//
// GitHub disables a scheduled workflow in a repository that has seen no
// activity for 60 days. Every schedule this plan builds is in that sentence:
// the signer, the ingest claims (BOT-51), the moderation run (BOT-83), the
// coverage canary this rule runs inside, and every check BOT-85 lists. So
// RC-R1-9(b) commits `state/keepalive.json` — one file, one month, outside
// `plugins/` and outside `log/**` — once a month, and that commit is what
// keeps all of them alive.
//
// **The keepalive is a single point of failure for every alarm in this
// repository, and nothing else watches it.** If it stops, nothing goes red:
// the schedules simply stop firing, sixty days later, one at a time, and an
// estate whose alarms have all been switched off by the forge looks exactly
// like an estate with nothing to report. BOT-85's heartbeats are the outer
// guard — the receiver pages on silence — and this rule is the inner one,
// which says the month before the silence rather than a day after it.
//
// 35 days, not 30: a month is 31 days and a keepalive committed on the 1st and
// then on the 31st of the next month is 61 days apart at worst. 35 gives the
// monthly commit a four-day window to be late in before anybody is woken, and
// still leaves 25 days of margin before the 60-day mark.
//
// **Absence is `pending`, not red, and only until the file has existed once.**
// RC-R1-9(b) has not landed, and a rule that is red from the day it lands
// until the day another task lands is a rule somebody deletes in between
// (TRUST-45). But once `state/keepalive.json` has been committed even once,
// its absence is a deletion, and a deletion is red — otherwise the honest
// "not yet" and the dangerous "not any more" are the same colour.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { report } from "./rules.mjs";
import { git } from "./git.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..", "..");

export const RULE = "keepalive-age";
export const KEEPALIVE = "state/keepalive.json";
export const MAX_AGE_DAYS = 35;

const DAY_MS = 24 * 60 * 60 * 1000;

export function run(repo, { now = new Date() } = {}) {
  const file = path.join(repo, KEEPALIVE);
  const everAdded = git(["log", "--format=%H", "--diff-filter=A", "--", KEEPALIVE], { cwd: repo, allowFailure: true })
    .split("\n").map((s) => s.trim()).filter(Boolean);

  if (!fs.existsSync(file)) {
    if (everAdded.length === 0) {
      return {
        status: "pending",
        codes: [], ids: [], hexes: [],
        detail: [
          `${KEEPALIVE} has never existed in this repository. RC-R1-9(b) (ROLL-62) commits it monthly, and ` +
          "until it does, every schedule here — this workflow's included — is 60 days of quiet away from " +
          "being disabled by GitHub with no signal at all",
        ],
      };
    }
    return {
      status: "red",
      codes: ["ROLL_62_KEEPALIVE_DELETED"], ids: [], hexes: [],
      detail: [
        `${KEEPALIVE} was added in ${everAdded[everAdded.length - 1].slice(0, 12)} and is not in the tree now; ` +
        "a keepalive that has been deleted is a keepalive nobody is committing",
      ],
    };
  }

  // Two clocks, because the rule asks two questions, and they come apart on
  // exactly the history this estate makes: a keepalive written on a branch
  // and merged with a merge commit (every lane's pull request is merged that
  // way), or one rebased onto main, which keeps its author date.
  //
  // HOW LONG SINCE MAIN LAST ACQUIRED ONE is a question about `main`, and
  // GitHub's 60-day rule counts activity on the repository, not the time a
  // branch commit was written. So it is the newest FIRST-PARENT commit that
  // changed the file, at its COMMITTER time: a merge is dated at the merge
  // (gap 68's repair, astra-registry #197). `git log -1 -- <path>` simplifies
  // through a merge that is TREESAME to its branch parent and dates the branch
  // commit instead, and `%aI` dates a rebased commit when it was first
  // written. Measured 2026-09-22 on fixtures, with `now` 2026-09-28: a
  // keepalive written 2026-08-20 on a branch and merged 2026-09-20 read as
  // 38.6 days old and ROLL_62_KEEPALIVE_STALE, where main had acquired it 7.5
  // days before — the same through a branch that had merged main in, and for
  // a single-parent commit authored 08-20 and committed 09-20. A false red,
  // not a silent one, but a false red on the one rule that watches every
  // schedule here is how that rule gets switched off.
  //
  // WHETHER THE FILE SAYS THE MONTH IT WAS WRITTEN IN is a question about the
  // commit that WROTE it, in its writer's own clock — which is what the
  // workflow and `state/README.md` ask the writer to put in the file. That is
  // the commit `git log -1 -- <path>` finds, at its author time, and it stays
  // so: dated at a merge in a later month, a correct keepalive would read as
  // MONTH_STALE.
  const landedISO = git(["log", "-1", "--first-parent", "--format=%cI", "--", KEEPALIVE], { cwd: repo, allowFailure: true }).trim();
  const writtenISO = git(["log", "-1", "--format=%aI", "--", KEEPALIVE], { cwd: repo, allowFailure: true }).trim();
  if (!landedISO || !writtenISO) {
    return {
      status: "red",
      codes: ["ROLL_62_KEEPALIVE_UNDATED"], ids: [], hexes: [],
      detail: [`${KEEPALIVE} is in the tree and no commit in this checkout touches it; the walk cannot date it`],
    };
  }
  const ageDays = (now.getTime() - new Date(landedISO).getTime()) / DAY_MS;

  // The content and the commit must agree. A keepalive commit that rewrote
  // nothing — the same month committed again, or an empty commit — is a
  // commit git records as activity and a reader records as a month that was
  // kept. The two only come apart when somebody has automated the commit and
  // not the file, which is the version of this that survives longest.
  const detail = [
    `${KEEPALIVE} last changed ${landedISO} (${ageDays.toFixed(1)} day(s) ago)` +
    (writtenISO === landedISO ? "" : `, in a commit written ${writtenISO}`),
  ];
  const codes = [];
  let month = null;
  try {
    month = JSON.parse(fs.readFileSync(file, "utf8")).month;
  } catch (e) {
    codes.push("ROLL_62_KEEPALIVE_UNREADABLE");
    detail.push(`${KEEPALIVE} is not readable JSON: ${e.message}`);
  }
  if (month !== null && month !== undefined) {
    const commitMonth = writtenISO.slice(0, 7);
    if (month !== commitMonth) {
      codes.push("ROLL_62_KEEPALIVE_MONTH_STALE");
      detail.push(
        `${KEEPALIVE} says ${JSON.stringify(month)} and the commit that last wrote it is in ${commitMonth}; the commit ` +
        "counts as activity and the file does not say the month it was made, so one of the two is automated " +
        "and the other is not",
      );
    }
  }
  if (ageDays > MAX_AGE_DAYS) {
    codes.push("ROLL_62_KEEPALIVE_STALE");
    detail.push(
      `that is over the ${MAX_AGE_DAYS}-day bound; GitHub disables a scheduled workflow after 60 days of ` +
      "repository inactivity, and every schedule here goes with it — silently",
    );
  }
  return { status: codes.length ? "red" : "green", codes, ids: [], hexes: [], detail };
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
