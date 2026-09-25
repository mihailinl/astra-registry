#!/usr/bin/env node
// DEC-12's "no GitHub issues channel", held from the cutover commit on
// (registry plan M-T6.2; contract ROLL-33, DEC-12).
//
//     node tools/coverage/no-issue-channel.mjs [--repo <dir>] [--report <file>]
//
// ── WHAT CUTOVER PROMISES, AND WHAT WOULD QUIETLY UNDO IT ───────────────────
//
// ROLL-33: cutover is the registry commit that drops the `issues`,
// `issue_comment` and `repository_dispatch` triggers and adds
// `log/cutover.json`; from it the plugins service is the only channel. Every
// document the cutover commit amends then tells authors and reporters that a
// GitHub issue reaches nobody. The way that stops being true is one line: a
// trigger restored in a workflow — by a revert, by a merge that resolved a
// conflict the wrong way, by a new workflow copied from an old one — and the
// registry is answering issues again in a bot's voice while every policy
// document says it does not. Nothing else in the repository would notice,
// because a trigger that fires is a workflow that works.
//
// ── ARMED BY THE MARKER, NOT BY A DATE ──────────────────────────────────────
//
// Before `log/cutover.json` exists the issue channel is the live path
// (`ingest.yml` carries all three triggers), so the rule is green and says
// where the triggers are. From the commit that adds the marker it is red on
// any live trigger of the three in any workflow under `.github/workflows/`,
// named by file and line. Arming on the marker means the rule needs no edit on
// cutover day, and the cutover commit is the first commit it judges.
//
// ── WHAT IT READS ───────────────────────────────────────────────────────────
//
// The `on:` of every workflow, in the three spellings YAML allows: a block
// (`on:` then two-space keys), a flow list (`on: [push, issues]`) and a
// scalar (`on: issues`). Comments are not triggers. It reads files, not
// GitHub: a workflow disabled in the settings but present in the tree is
// still a trigger a person can re-enable with one click.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { execFileSync } from "node:child_process";

import { cleanEnv } from "../lib/git-env.mjs";
import { report } from "./rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..", "..");

export const RULE = "no-issue-channel";

/** The cutover marker (contract B.4; ROLL-33). */
export const CUTOVER = "log/cutover.json";

/** ROLL-33's three triggers. */
export const ISSUE_TRIGGERS = ["issues", "issue_comment", "repository_dispatch"];

/**
 * Sixteen workflows on 2026-09-24. A floor, because every rule below is a loop
 * over them and a moved `.github/workflows/` is a rule that is green about
 * nothing.
 */
export const WORKFLOW_FLOOR = 10;

// `ingest.yml` was exempt from the `issues: write` leg by name, from commit C
// until commit E deleted it (registry plan M-T6.2, B-T5.2). The exemption went
// with the file: a workflow named ingest.yml after E is a new file, and it is
// held to the rule like any other.

const unquote = (s) => s.trim().replace(/^['"]|['"]$/g, "");

/**
 * The triggers one workflow's `on:` names, with their lines.
 *
 * @param {string} src the workflow's text
 * @returns {{trigger: string, line: number}[]}
 */
export function triggersOf(src) {
  const lines = src.split("\n");
  const out = [];
  const at = lines.findIndex((l) => /^["']?on["']?\s*:/.test(l));
  if (at < 0) return out;
  const head = lines[at].replace(/#.*$/, "");
  const rest = head.replace(/^["']?on["']?\s*:/, "").trim();
  if (rest.startsWith("[")) {
    // A flow list on the `on:` line.
    const inner = /^\[([^\]]*)\]/.exec(rest)?.[1] ?? "";
    for (const t of inner.split(",").map(unquote).filter(Boolean)) out.push({ trigger: t, line: at + 1 });
    return out;
  }
  if (rest !== "") {
    out.push({ trigger: unquote(rest), line: at + 1 });
    return out;
  }
  for (let i = at + 1; i < lines.length; i++) {
    const l = lines[i];
    if (/^\S/.test(l)) break;
    if (/^\s*#/.test(l) || l.trim() === "") continue;
    const m = /^ {2}["']?([A-Za-z_]+)["']?\s*:/.exec(l);
    if (m) out.push({ trigger: m[1], line: i + 1 });
  }
  return out;
}

/**
 * How far `cutover_at` may sit from the moment `main` acquired the marker.
 * ROLL-33 and M-T6.2: `cutover_at` is the commit time. The cutover commit is
 * prepared as a pull request days ahead and merged on the owner's approval, so
 * the value is stamped just before the merge; a day covers the stamp-to-merge
 * gap and still catches a stamp left from the day the branch was written.
 */
export const STAMP_TOLERANCE_HOURS = 24;

/**
 * The marker's `cutover_at` against the committer time of the first-parent
 * commit on `main` that brought it — the moment the channel actually closed.
 * MIG-1 and the appeal-URL rule read `cutover_at`; a stale stamp moves every
 * listing's frozen date and every entry's appeal cut-off to a day nothing
 * happened on.
 *
 * @returns {{code: string|null, detail: string}}
 */
export function cutoverStamp(repo, { toleranceHours = STAMP_TOLERANCE_HOURS } = {}) {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(path.join(repo, CUTOVER), "utf8"));
  } catch (e) {
    return { code: "CUTOVER_MARKER_UNREADABLE", detail: `${CUTOVER} is not readable JSON: ${e.message}` };
  }
  const at = Date.parse(doc?.cutover_at);
  if (!Number.isFinite(at)) {
    return { code: "CUTOVER_MARKER_UNREADABLE", detail: `${CUTOVER}'s cutover_at is ${JSON.stringify(doc?.cutover_at)}, not a time` };
  }
  const out = gitOut(repo, ["log", "--first-parent", "--diff-filter=A", "--format=%H %cI", "--", CUTOVER]);
  const line = out.split("\n").map((l) => l.trim()).filter(Boolean).at(-1);
  if (!line) {
    return { code: null, detail: `${CUTOVER} is on the tree and not in git's history, so the stamp is not compared (an uncommitted tree)` };
  }
  const [sha, when] = line.split(" ");
  const hours = Math.abs(at - Date.parse(when)) / 3_600_000;
  if (hours > toleranceHours) {
    return {
      code: "CUTOVER_STAMP_STALE",
      detail: `${CUTOVER} says cutover_at ${doc.cutover_at}, and main acquired it in ${sha.slice(0, 12)} at ${when}, ` +
        `${hours.toFixed(1)} h apart. ROLL-33 makes cutover_at the commit time; restamp it in a commit that says why`,
    };
  }
  return { code: null, detail: `${CUTOVER}'s cutover_at is ${hours.toFixed(1)} h from ${sha.slice(0, 12)}, the commit that brought it` };
}

function gitOut(repo, args) {
  try {
    return execFileSync("git", args, { cwd: repo, encoding: "utf8", env: cleanEnv(), stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    return "";
  }
}

/** @returns {{status: string, codes: string[], ids: string[], hexes: string[], detail: string[]}} */
export function run(repo, { workflowFloor = WORKFLOW_FLOOR } = {}) {
  const codes = [];
  const detail = [];
  const dir = path.join(repo, ".github", "workflows");
  const files = fs.existsSync(dir)
    ? fs.readdirSync(dir).filter((n) => /\.ya?ml$/.test(n)).sort()
    : [];
  if (files.length < workflowFloor) {
    codes.push("ISSUE_CHANNEL_FLOOR");
    detail.push(
      `read ${files.length} workflow file(s) under .github/workflows/ and there were 16 on 2026-09-24; a walk ` +
      "that stopped finding workflows is green about nothing",
    );
  }
  const hits = [];
  const writers = [];
  for (const name of files) {
    const src = fs.readFileSync(path.join(dir, name), "utf8");
    for (const { trigger, line } of triggersOf(src)) {
      if (ISSUE_TRIGGERS.includes(trigger)) hits.push(`.github/workflows/${name}:${line} ${trigger}`);
    }
    src.split("\n").forEach((l, i) => {
      if (/^\s*#/.test(l)) return;
      if (/^\s+issues:\s*write\s*(#.*)?$/.test(l)) writers.push({ name, line: i + 1 });
    });
  }
  const armed = fs.existsSync(path.join(repo, CUTOVER));
  if (armed) {
    const stamp = cutoverStamp(repo);
    if (stamp.code) {
      codes.push(stamp.code);
    }
    detail.push(stamp.detail);
  }
  if (!armed) {
    detail.push(
      `not armed: ${CUTOVER} is not on this tree, so the issue channel is still the live path; ` +
      `${hits.length} trigger(s) of ${ISSUE_TRIGGERS.join(", ")} today${hits.length ? `: ${hits.join(", ")}` : ""}`,
    );
  } else if (writers.length) {
    // Commit C's leg (M-T6.2, BOT-53): nothing writes an issue after cutover.
    // Since commit E deleted ingest.yml, no workflow is exempt.
    codes.push("ISSUE_CHANNEL_WRITE");
    for (const w of writers) {
      detail.push(
        `.github/workflows/${w.name}:${w.line} grants \`issues: write\` after cutover: nothing may write an issue ` +
        "on this repository any more (DEC-12, BOT-53); alert through environment `alerts` instead",
      );
    }
  }
  if (armed && hits.length) {
    codes.push("ISSUE_CHANNEL_TRIGGER");
    for (const h of hits) {
      detail.push(
        `${h}: ${CUTOVER} is on this tree, so the plugins service is the only channel (ROLL-33, DEC-12), and ` +
        "this workflow still starts on a GitHub issue event. Every policy document the cutover commit amended " +
        "tells authors an issue reaches nobody",
      );
    }
  } else if (armed) {
    detail.push(`${CUTOVER} is on this tree and no workflow of ${files.length} starts on ${ISSUE_TRIGGERS.join(", ")}`);
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
