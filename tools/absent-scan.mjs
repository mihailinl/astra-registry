#!/usr/bin/env node
// Gap 28's marker, given a reader that can disagree with it.
//
//     node tools/absent-scan.mjs                   this checkout
//     node tools/absent-scan.mjs --repo <dir>      a fixture clone
//
// ── the failure ─────────────────────────────────────────────────────────────
//
// A header, a docblock or a workflow step name that says some path DOES NOT
// EXIST is believed by every later reader, and nothing re-asks it. Nothing
// executes a comment, so there is no run in which a stale absence goes red;
// the commits that edit the file around it do not re-read it; and what a
// reader takes from it is worse than nothing — they conclude the module they
// were looking for is unwritten, and go and write a second one.
//
// Four instances landed in this repository in one day (2026-09-20), which is
// what makes it a class rather than four mistakes: `bot/baseline.mjs` said
// three gates were absent when two had landed a commit earlier; `bot/lib/
// identity.mjs` said four when one had landed in the merge below it;
// `bot/publish-apply.mjs` said TWO when it was one; and a step name in
// `.github/workflows/plugins-ingest.yml` asserted a task was unbuilt
// **forty-six minutes after that task merged**. FOUR MORE were live on
// 2026-09-22 and are the reason this file exists — `bot/baseline.mjs` again,
// `plugins-ingest.yml`'s B-T3.4 step and its header (about
// `bot/lib/service.mjs`, landed `68f9dde` 4 h 48 m after that file's last
// commit), and `bot/export-issues.mjs`'s `resolveWriter` docblock. All four
// named a module that was on `main`; three of the four named the same one.
//
// ── why this scan reads a MARKER and not the prose ──────────────────────────
//
// The obvious check — an absence phrase within a few comment lines of a
// backticked path — was prototyped on 2026-09-20 and deliberately not shipped.
// The failure is not tuning: **the phrase and the path are both present and
// the phrase is not about the path**, and no amount of tightening resolves a
// referent out of English.
//
// The prototype was never committed, so its measurement ("7, of which the path
// EXISTS: 3") is a citation of an act nobody can repeat. Re-derived here on
// astra-registry `212d7c6`, 2026-09-22, BEFORE the commit that adds this file
// — the prose below shifts the count, which is itself the point — with the
// entry's own four phrases (`is not in this checkout`, ``not on `main` ``,
// `does not exist yet`, `MEASURED ABSENT`), tracked `.mjs` only (171 of 514),
// a backticked path within three comment lines whose first segment is a real
// tracked top-level directory, one claim per (phrase occurrence, path) pair:
//
//     11 pairs over 9 phrase occurrences   of which the path EXISTS: 11
//
// **All eleven**, not three of seven. Widening the phrase list to thirteen
// gives 25 of 25; reading each comment BLOCK as one joined paragraph instead
// of line by line gives 7 of 7. Three closings of the entry's "…" and the
// ratio is 100% in every one: the population moves, the uselessness does not.
//
// The block-joined variant is not a curiosity. The prototype was line
// oriented, and prose wraps: `bot/export-issues.mjs` said a module "is not" /
// "on `main` yet" across a line break, and was invisible to the very
// instrument whose numbers were being quoted — while being one of the four
// live instances above.
//
// Every one of the eleven is a false positive — sentences of the form "this
// said X until 2026-09-22", "the key was not on `main` until M-T2.1 landed
// it". A check that fires on eleven authors who did nothing wrong is switched
// off on its second run, and the requirement is then enforced by nothing at
// all, with a green tick over it.
//
// A check cannot infer a referent. An author can state one. So the claim is
// written as a marker and the marker is verified exactly:
//
//     `@absent <path> (<task>)`
//
// on a comment line of its own — `path` is repo-relative, `task` is whoever
// lands it. The scan fails when `path` is TRACKED. There is no guessing left
// in it, and its cost is honest: it covers only absences somebody chose to
// mark. A retrofit over the four instances above would be forty guesses about
// what forty sentences meant, made by the person least able to check, and is
// not attempted here.
//
// **The backticks on the line above are load-bearing, and CI is what said so.**
// This scan reads TRACKED files, so while it was a new untracked file it never
// read itself, and every local run was green. Its first run on the tracked
// tree — `35719026264`, the first push of this branch — went red on line 68 of
// this header, which illustrated the convention without them and parsed as a
// marker claiming a path called `<path>`. A guard whose first red is its own
// documentation is one nobody keeps, and the only reason it was caught at all
// is that the end-to-end run happened before the merge rather than after.
//
// ── WHAT THIS SCAN CANNOT REACH, stated here rather than only in a report ───
//
//   * **Another repository.** `AstraPlugins`, `Astra` and `astra-plugins-ops`
//     are not in this checkout, so "not on `main` in AstraPlugins" is not a
//     question `git ls-files` here can answer. A marker naming one is REFUSED
//     as malformed rather than silently passing — a marker that can never go
//     red is the defect wearing the fix's clothes.
//   * **A symbol rather than a path.** "`fixed_reasons` is not on `main`",
//     "`refusesDroppedKey` has no production caller", "B-T3.4's allow-list is
//     not widened" — the file exists in each case and the claim is about a
//     field, a caller or a behaviour inside it. Those need a test, not a
//     scan, and `bot/tests/code-paths.test.mjs` is where that kind lives.
//   * **Prose.** All four of the 2026-09-20 instances were written as
//     sentences. This scan is blind to every one of them, by construction.
//
// ── the floors ──────────────────────────────────────────────────────────────
//
// A scan over nothing passes every assertion in it. Two ways in: a walk that
// returns no files, and a tree that carries no markers. Both have a floor
// below, and the marker floor is the one that is allowed to be argued with —
// when the last absence in this repository is filled the honest act is to
// delete that floor in the commit that fills it, not to leave a guard that
// asserts nothing.

import { execFileSync } from "node:child_process";
import { cleanEnv } from "./lib/git-env.mjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_REPO = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/** Measured 2026-09-22 with this file tracked: 515 tracked, 43 NUL-bearing (all images). */
export const CORPUS_FLOOR = 450;

/** Measured 2026-09-22: 1. See "the floors" above before lowering this. */
export const MARKER_FLOOR = 1;

/** Repositories of this estate that are not this checkout. */
export const FOREIGN_REPOS = ["AstraPlugins", "Astra", "astra-registry", "astra-plugins-ops", "astra-api"];

/**
 * The marker, anchored: a comment line that is the marker and nothing else.
 *
 * Anchored deliberately. `bot/publish-apply.mjs` names the convention in a
 * sentence — "Gap 28's `@absent <path> (<task>)` marker is the answer" — and a
 * loose match would read that as a marker claiming the literal path `<path>`.
 * A reference inside backticks is prose ABOUT the convention and is counted
 * separately; a `@absent` outside backticks that does not match this form is
 * malformed and fails, because a typo'd marker is a claim nothing checks,
 * which is the whole defect one level up.
 */
const MARKER = /^\s*(?:\/\/+|\/\*+|\*+|#+|--)\s*@absent\s+(\S+)\s+\(([^)]+)\)\s*$/;

/**
 * A comment line — the only place a marker, or a malformed one, is looked for.
 *
 * Found by the scan finding itself: the first draft read every line, and the
 * check wired into `bot/tests/workflows.test.mjs` failed on two lines of that
 * check's own source — a template literal containing `` \`@absent\` `` and an
 * assertion message containing the word — because a JS string is not a comment
 * and its backticks are escaped. A guard whose first red is its own author's
 * quotation marks is a guard that gets switched off. So: a claim about the
 * tree is made in a COMMENT, and `@absent` anywhere else is code.
 *
 * The cost, said out loud: a malformed marker written inside a string literal
 * is invisible here, and a marker in a file with no comment syntax — a `.md`,
 * a `.json` — cannot be written at all.
 */
const COMMENT_LINE = /^\s*(?:\/\/|\/\*|\*|#|--|<!--)/;

/** A repo-relative path: no root, no escape, no glob, no backslash. */
const REPO_RELATIVE = /^[A-Za-z0-9_.@-]+(?:\/[A-Za-z0-9_.@-]+)*$/;

/** Every tracked path, read through git rather than a readdir. */
function trackedPaths(repo) {
  return execFileSync("git", ["-C", repo, "ls-files", "-z"], { encoding: "utf8", maxBuffer: 64 << 20, env: cleanEnv() })
    .split("\0")
    .filter(Boolean);
}

/**
 * The scan.
 *
 * Reads every tracked file with `fs.readFileSync` rather than through the
 * `grep` wrapper, which is `ugrep -I`: a NUL-bearing file is invisible to it
 * and it exits 1 cleanly while saying so to nobody. 43 of this repository's
 * 515 tracked files carry a NUL (every one an icon or a binary fixture), and a
 * marker scan that silently skipped 8% of the tree would be an instrument with
 * the same disease as its subject. They are skipped here too — a NUL-bearing
 * file has no comment lines — but the number is REPORTED, so the skip is a
 * fact in the output rather than a property of the tool.
 */
export function scanAbsent(repo = DEFAULT_REPO) {
  const tracked = trackedPaths(repo);
  const files = new Set(tracked);
  const dirs = new Set();
  for (const p of tracked) {
    const parts = p.split("/");
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join("/"));
  }

  const markers = [];
  const references = [];
  const malformed = [];
  let read = 0;
  let binary = 0;
  let code = 0;

  for (const rel of tracked) {
    let buf;
    try {
      buf = fs.readFileSync(path.join(repo, rel));
    } catch {
      continue;
    }
    if (buf.includes(0)) { binary++; continue; }
    read++;
    const text = buf.toString("utf8");
    if (!text.includes("@absent")) continue;
    text.split("\n").forEach((line, i) => {
      if (!line.includes("@absent")) return;
      if (!COMMENT_LINE.test(line)) { code++; return; }
      const where = `${rel}:${i + 1}`;
      // Prose about the convention lives inside backticks. Strip every
      // backticked span; if nothing is left, this line claims nothing.
      if (!line.replace(/`[^`]*`/g, "").includes("@absent")) {
        references.push({ file: rel, line: i + 1, text: line.trim() });
        return;
      }
      const m = MARKER.exec(line);
      if (!m) {
        malformed.push(
          `${where} carries @absent outside backticks and is not \`@absent <path> (<task>)\` on a comment ` +
          `line of its own: ${JSON.stringify(line.trim().slice(0, 120))}. A marker nothing can parse is a ` +
          `claim nothing checks`,
        );
        return;
      }
      const [, claimed, task] = m;
      const first = claimed.split("/")[0];
      if (FOREIGN_REPOS.includes(first)) {
        malformed.push(
          `${where} claims ${claimed} is absent, and ${first} is not this checkout. A cross-repository ` +
          `absence is out of this scan's reach and a marker for one can never go red — say it in prose, or ` +
          `write the check in the repository that can answer it`,
        );
        return;
      }
      if (!REPO_RELATIVE.test(claimed)) {
        malformed.push(
          `${where} claims ${JSON.stringify(claimed)} is absent, which is not a repo-relative path (no ` +
          `leading /, no .., no glob, no backslash). This scan asks git about a path and can ask about ` +
          `nothing else`,
        );
        return;
      }
      if (/^<.*>$/.test(task) || task.trim() === "") {
        malformed.push(`${where} names no task: \`(${task})\` is the convention's placeholder, not a task`);
        return;
      }
      markers.push({ file: rel, line: i + 1, path: claimed, task: task.trim(), exists: files.has(claimed) || dirs.has(claimed) });
    });
  }

  return { repo, tracked: tracked.length, read, binary, code, markers, references, malformed };
}

/**
 * Every problem this tree has, floors included, as sentences a reader can act
 * on. Empty means green.
 */
export function absentProblems(scan) {
  const problems = [];

  for (const m of scan.markers) {
    if (!m.exists) continue;
    problems.push(
      `${m.file}:${m.line} says \`${m.path}\` is absent (${m.task}) and git tracks it. Whoever lands a path ` +
      `does not re-read the comments that were waiting for it, so this sentence has been read as true by ` +
      `everyone who has opened this file since — correct the claim, and delete the marker with it`,
    );
  }
  problems.push(...scan.malformed);

  if (scan.read < CORPUS_FLOOR) {
    problems.push(
      `only ${scan.read} tracked file(s) were read and there were 472 readable of 515 tracked on ` +
      `2026-09-22. A walk that loses the tree finds no markers and reports green about every claim in it`,
    );
  }
  if (scan.markers.length < MARKER_FLOOR) {
    problems.push(
      `${scan.markers.length} \`@absent\` marker(s) found and the floor is ${MARKER_FLOOR}. Either the last ` +
      `marked absence in this repository has been filled — in which case lower this floor in the commit ` +
      `that fills it, and say so — or the marker was renamed and this scan has stopped applying to ` +
      `anything while still passing`,
    );
  }
  return problems;
}

function main(argv) {
  let repo = DEFAULT_REPO;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--repo") repo = path.resolve(argv[++i]);
    else { console.error(`FAIL  unknown argument ${JSON.stringify(argv[i])}`); return 2; }
  }
  const scan = scanAbsent(repo);
  const problems = absentProblems(scan);
  for (const m of scan.markers) {
    console.log(`${m.exists ? "TRACKED " : "absent  "} ${m.file}:${m.line}  ${m.path}  (${m.task})`);
  }
  console.log(
    `scan: ${scan.read} file(s) read, ${scan.binary} NUL-bearing skipped, ${scan.markers.length} marker(s), ` +
    `${scan.references.length} prose reference(s) and ${scan.code} code mention(s) of the convention`,
  );
  if (problems.length === 0) {
    console.log("absent-scan: green");
    return 0;
  }
  for (const p of problems) console.error(`FAIL  ${p}`);
  console.error(`absent-scan: ${problems.length} problem(s)`);
  return 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
