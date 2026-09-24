#!/usr/bin/env node
// ROLL-47's promise greps: a promise this registry has retired is not said
// again anywhere in it (registry plan M-T4.2, and the seam M-T4.3 and M-T6.2
// add their rows to).
//
//     node tools/coverage/roll47-promises.mjs [--repo <dir>] [--report <file>]
//
// ── WHY A GREP, AND WHY OVER THE WHOLE TREE ─────────────────────────────────
//
// Contract ROLL-47: "Each promise below MUST be amended explicitly, dated, in
// the change that first makes it false, each with a grep canary". Rows A1 and
// A2 are the registry's two account promises, and the step that makes them
// false is R4a's first mint — the first time a Minice account, holding
// `astraUser`, is bound to a repository whose listing lives here. From then on
// "there are no registry accounts, so there is nothing else a publisher could
// be" tells an author that nothing else is involved, and "the only identity
// this registry proves is the GitHub owner" tells a reader the same thing in
// the policy's words.
//
// The plan named ONE place for each (`site/README.md`, `docs/POLICY.md:455`).
// Measured on 2026-09-24 the tree said them in SIX: the two it named, the
// publisher page every visitor of the Pages site is served
// (`site/templates/pages.mjs`, "There are no registry accounts, no passwords
// and nothing to sign in to"), the comment in `site/build.mjs` that the page's
// text was written from, and the descriptions of `schema/index-v1.json`'s
// `publisher` member and of `schema/publisher-v1.json`. A canary scoped to the
// two named files would have been green over the one a reader actually sees.
// So the scan is every tracked file, less the few that are someone else's
// words or this rule's own (`SKIP`).
//
// ── ARMED FROM THE DAY IT LANDS, NOT FROM R3'S EXIT ─────────────────────────
//
// The plan arms this "from `log/rollout/R3-exit.json`". That was a start date
// for a rule that would otherwise go red before its amendment existed. The
// amendment lands in the same commit as this rule, so there is no interval in
// which it is red for a true promise, and a start marker would only have
// opened one in which the literal could come back unwatched. Stricter, and
// recorded as a disagreement with the plan in the commit that lands it.
//
// ── WHAT THIS DOES NOT DO ───────────────────────────────────────────────────
//
// It cannot tell whether the AMENDMENT is true. It knows the retired words,
// and that is all a grep can know: a sentence that makes the same promise in
// new words passes. That is why each row carries `why` — the sentence the next
// reviewer compares a rewording against — and why the rows name the contract
// row they come from, where the promise is written in full.
//
// ── ADDING A ROW (M-T4.3, M-T6.2, and ROLL-47's later rows) ─────────────────
//
// One entry in `PROMISES`, in the commit that amends the promise. The literal
// is matched case-insensitively over text whose runs of whitespace — line
// breaks included, because Markdown wraps — are collapsed to one space. Write
// it as a reader would quote it, and no longer than it needs to be to mean
// the promise and nothing else.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { cleanEnv } from "../lib/git-env.mjs";
import { report } from "./rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..", "..");

export const RULE = "roll47-promises";

/** This file, which has to spell every literal it looks for. */
export const SELF_PATH = "tools/coverage/roll47-promises.mjs";

/**
 * The retired promises. `amended` is the date the amendment landed, which is
 * the date the amended text carries (ROLL-47: "amended explicitly, dated").
 */
export const PROMISES = [
  {
    row: "A1",
    task: "M-T4.2",
    literal: "no registry accounts",
    amended: "2026-09-24",
    why:
      "R4a's first mint binds a repository to a Minice account holding `astraUser`. The registry still has no " +
      "accounts of its own, and saying that is fine; saying there are none, so there is nothing else a publisher " +
      "could be, tells an author the binding does not exist",
  },
  {
    row: "A2",
    task: "M-T4.2",
    literal: "the only identity this registry proves",
    amended: "2026-09-24",
    why:
      "from R4a a binding names the Minice account that is told about each release and can stop one; the GitHub " +
      "owner is still what the ownership check proves and what a badge is keyed on, but it is not the only " +
      "identity a listing's releases now depend on",
  },
  {
    row: "sandbox",
    task: "M-T4.2 (ROLL-47's rewrite clause)",
    literal: "Phase 7",
    amended: "2026-09-24",
    why:
      "ROLL-47: a rewrite of docs/POLICY.md MUST NOT carry its \"Phase 7\" sandbox prose. Plugins are not " +
      "sandboxed and will not be (settled); a sentence promising the phase in which that changes is a promise " +
      "the estate has refused to keep",
  },
  // M-T6.2 commit B, the cutover commit: FLOW-64 moves these three out of
  // commit C and into the commit that makes them false, and ROLL-47 rows C1
  // and C4 are where they are listed. `amended` is "cutover" because the text
  // is dated by the cutover it names (log/cutover.json carries the moment).
  {
    row: "C1-report",
    task: "M-T6.2 commit B (FLOW-64)",
    literal: "open an issue with the plugin id",
    amended: "cutover",
    why:
      "from the cutover no issue on this repository reaches anybody (DEC-12); a report is made from the plugin's " +
      "page in Minice's panel, by an Astra owner (MOD-21, MOD-54)",
  },
  {
    row: "C1-appeal",
    task: "M-T6.2 commit B (FLOW-64)",
    literal: "open an issue. a rejection names the check",
    amended: "cutover",
    why:
      "from the cutover an appeal is made in the panel, from the account the notice reached (MOD-31), and never " +
      "on an issue",
  },
  {
    row: "C4-readme",
    task: "M-T6.2 commit B (FLOW-64)",
    literal: "comment on your listing issue within minutes",
    amended: "cutover",
    why:
      "from the cutover a later release is found by the poll every 30 minutes (BOT-41) and taken up within 10 " +
      "(BOT-51); there is no listing issue and no comment. docs/RUNBOOK.md's operator copy is commit C's",
  },
  {
    row: "C1-docs-appeal",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "open an issue titled",
    amended: "cutover",
    why: "from the cutover an appeal is made in the panel (MOD-31), never on an issue; the template in docs/POLICY.md \u00a711 went with the form",
  },
  {
    row: "C2-security",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "open a private security advisory on this repository",
    amended: "cutover",
    why: "from R6 no registry page offers the issue form or GitHub private reporting for a vulnerability; the channel is security@minice.ai, read by the owner, unencrypted (MOD-45)",
  },
  {
    row: "C2-notification",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "out-of-band notification to the author on every publish",
    amended: "cutover",
    why: "the author is told by `notice.published` to the listing's bound account (OD-17), and a listing not yet bound has nobody to tell; the old sentence promised a notice for every listing",
  },
  {
    row: "C4-runbook",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "expect a new comment within minutes",
    amended: "cutover",
    why: "the operator's copy of C4: from the cutover a moderator decides in the panel, and no comment is posted anywhere",
  },
  {
    row: "C5-policy",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "an author may **yank**",
    amended: "cutover",
    why: "C5: an author yanks from the panel (A_YANK, FLOW-79), compiled to a yank with an author-action decision record, never undone; the old sentence described a hand edit",
  },
  {
    row: "C5-docs",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "yanking is the author's tool",
    amended: "cutover",
    why: "the docs/POLICY.md copy of C5, amended with the same panel path and record",
  },
  {
    row: "MOD-40-docs",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "those are public issues",
    amended: "cutover",
    why: "MOD-40: refusals are public in the decision log, never as issues",
  },
  {
    row: "MOD-40-site",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "in the issue tracker, publicly",
    amended: "cutover",
    why: "the copy of MOD-40 on the site's transparency page",
  },
  {
    row: "MOD-40-log",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "never got listed is a public issue",
    amended: "cutover",
    why: "the copy of MOD-40 in bot/moderation/README.md",
  },
  {
    row: "MOD-45-fallback",
    task: "M-T6.2 commit C (ROLL-47; MOD-40; MOD-45)",
    literal: "ask for the channel in public",
    amended: "cutover",
    why: "MOD-45: from R6 no public-issue fallback for a vulnerability; the form route in docs/POLICY.md \u00a712 went with the forms",
  },
];

/**
 * What the scan does not read, each for a reason.
 *
 * `plugins/` and `registry/v1/` are authors' words: READMEs, summaries and
 * descriptions a stranger wrote, and the generated catalogue that carries
 * them. A plugin that says "no registry accounts" in its own README is not the
 * registry promising anything, and a canary one author's README can turn red
 * is a canary somebody exempts wholesale. `schema/contract-tokens-v1.json` is
 * generated from the contract, which quotes these promises in order to retire
 * them. The last two are this rule and its tests.
 */
export const SKIP = [
  { prefix: "plugins/", why: "authors' own words, published verbatim" },
  { prefix: "registry/v1/", why: "the generated catalogue, which carries authors' words" },
  { prefix: "schema/contract-tokens-v1.json", why: "generated from the contract, which quotes the retired promises" },
  { prefix: SELF_PATH, why: "this rule, which has to spell every literal" },
  { prefix: "bot/tests/moderation-coverage.test.mjs", why: "this rule's tests, which restore each literal to watch it" },
];

/**
 * The two documents the plan names for rows A1 and A2. They must be IN the
 * scan: a rule whose subject has moved out from under it passes about nothing.
 */
export const NAMED = ["site/README.md", "docs/POLICY.md"];

/**
 * Text files the scan read on 2026-09-24 at `d44f0cf`: 384, of 536 tracked
 * (the rest are `SKIP`'s or binary). A floor, not an equality — the tree
 * grows — and it is what goes red when `git ls-files` has stopped answering
 * (a missing checkout, a changed cwd) and the scan is green about nothing.
 */
export const SCANNED_FLOOR = 300;

const normalise = (s) => s.replace(/\s+/g, " ").toLowerCase();

function tracked(repo) {
  try {
    const out = execFileSync("git", ["-C", repo, "ls-files", "-z"], {
      encoding: "utf8", env: cleanEnv(), maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
    });
    return out.split("\0").filter(Boolean);
  } catch (e) {
    return { error: String(e.message ?? e).split("\n")[0] };
  }
}

/**
 * @param {string} repo repository root
 * @param {{promises?: typeof PROMISES, scannedFloor?: number}} [opts]
 * @returns {{status: "green"|"red", codes: string[], ids: string[], hexes: string[], detail: string[]}}
 */
export function run(repo, { promises = PROMISES, scannedFloor = SCANNED_FLOOR } = {}) {
  const codes = [];
  const detail = [];
  const files = tracked(repo);
  if (!Array.isArray(files)) {
    return {
      status: "red", codes: ["ROLL47_SCAN_FAILED"], ids: [], hexes: [],
      detail: [`git ls-files failed in ${repo}: ${files.error}; the scan read nothing and cannot say the tree is clean`],
    };
  }

  const inScope = files.filter((f) => !SKIP.some((s) => f === s.prefix || f.startsWith(s.prefix)));
  for (const named of NAMED) {
    if (!inScope.includes(named)) {
      codes.push("ROLL47_SUBJECT_ABSENT");
      detail.push(
        `${named} is not a tracked file in the scan. It is where the plan says rows A1 and A2 are amended, and a ` +
        "scan that no longer reads it is green about the one document the promise was made in",
      );
    }
  }

  let scanned = 0;
  const wanted = promises.map((p) => ({ ...p, needle: normalise(p.literal) }));
  for (const rel of inScope) {
    let buf;
    try {
      buf = fs.readFileSync(path.join(repo, rel));
    } catch {
      continue; // tracked but not checked out (sparse, or deleted in the working copy)
    }
    if (buf.includes(0)) continue; // binary: an image, an archive, a key fixture
    scanned++;
    const text = buf.toString("utf8");
    const flat = normalise(text);
    for (const p of wanted) {
      let at = flat.indexOf(p.needle);
      while (at !== -1) {
        codes.push("ROLL47_PROMISE_RESTATED");
        detail.push(
          `${rel} says "${p.literal}" (ROLL-47 row ${p.row}, amended ${p.amended} by ${p.task}): ${p.why}. Amend ` +
          "the sentence, dated, rather than this row",
        );
        at = flat.indexOf(p.needle, at + p.needle.length);
      }
    }
  }

  if (scanned < scannedFloor) {
    codes.push("ROLL47_SCAN_FLOOR");
    detail.push(
      `the scan read ${scanned} text file(s) and there were more than ${scannedFloor} on 2026-09-24; this is a ` +
      "broken read, not a smaller repository, and a grep over nothing finds nothing",
    );
  }

  if (codes.length === 0) {
    detail.push(
      `${scanned} tracked text file(s) read; none restates a retired promise (${promises.map((p) => p.row).join(", ")})`,
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
