// The suite's harness: the counters, the assertions, the one temp directory,
// and the two repository walkers the R0 self-scan is built on.
//
// `passed` and `failures` are deliberately NOT exported as bare bindings. A
// reader that copied `passed` into a local would hold a stale zero for the rest
// of the run, so the runner asks for them through `results()` at the end.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runValidation } from "../validate.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";

export const LIMITS = JSON.parse(fs.readFileSync(new URL("../../policy/limits.json", import.meta.url), "utf8"));

let passed = 0;
const failures = [];
let running = 0;

export async function test(name, fn) {
  running++;
  try {
    try {
      await fn();
      console.log(`  ok    ${name}`);
      passed++;
    } catch (e) {
      console.log(`  FAIL  ${name}`);
      console.log(`        ${e.message.split("\n").join("\n        ")}`);
      failures.push(name);
    }
  } finally {
    running--;
  }
}

/** What the runner prints on the last line. Read once, after the last module. */
export function results() {
  return { passed, failures };
}

/**
 * How many `test()` calls have not finished. Zero everywhere the runner looks,
 * because it only looks between modules and a module that awaits each of its
 * tests has none outstanding when `run()` resolves.
 *
 * A non-zero reading is a forgotten `await` on a `test(...)`, which is the one
 * mistake in this suite that makes a broken check ship GREEN: the promise nobody
 * holds settles after the summary has printed and after the exit code has been
 * decided, so the FAIL appears below the PASS and CI never sees it. Pre-existing
 * — the shape was always available — but the split turned one file into fifteen
 * `run()` bodies for ten tasks to write into, which is fifteen times the surface.
 *
 * A function rather than a bare binding, for the reason given at the top of this
 * file: a reader that copied the number would hold a stale zero.
 */
export function inFlight() {
  return running;
}

/**
 * Two values, and the difference printed when they are not one value. `assert`
 * alone reports "expected true" for a mismatch nobody can then see.
 */
export function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}\n  expected: ${JSON.stringify(expected)}\n  actual:   ${JSON.stringify(actual)}`);
  }
}

export function assert(cond, message) {
  if (!cond) throw new Error(message);
}

/** Run the validator in-process against a tree and return its report. */
export function validateTree(dir, opts = {}) {
  return runValidation({
    root: dir, allowStaging: false, allowDirect: false, online: false, artifactsDir: null, index: false, ...opts,
  });
}

export function errorsMatching(report, needle) {
  return report.errors.filter((e) => `${e.where} ${e.message}`.includes(needle));
}

// Created at import, before any module's import-time fixture writes, and removed
// by the runner after the last run() resolves.
export const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-registry-selftest-"));

export function cleanupTmp() {
  fs.rmSync(tmp, { recursive: true, force: true });
}

// ─────────────────────────────────────────────────────────────────────────────
// The repository walkers the R0 self-scan is built on.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Every file in the tree, minus the places a checkout does not own.
 *
 * `reports/` and `watch-state/` are the two that are not about tidiness. In the
 * `publish` job this file runs inside a WORKSPACE, not a clean checkout, and
 * that workspace holds the downloaded ingest artifacts — bytes lifted verbatim
 * out of a stranger's release bundle, including their README. Every `grepRepo`
 * rule below therefore scanned submitter-controlled text, so a plugin whose
 * README happened to mention `revoke.yml` failed the publication and the author
 * was told the bot had broken. Measured, not theorised: one such README under
 * `reports/` turned a green `node tools/selftest.mjs` red.
 *
 * Neither name can appear in a real checkout of this repository — nothing is
 * tracked at either path — so excluding them costs no coverage.
 */
export function walkRepo(dir = REPO_ROOT, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === ".git" || e.name === "node_modules" || e.name === "dist") continue;
    if (dir === REPO_ROOT && (e.name === "reports" || e.name === "watch-state")) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walkRepo(full, out);
    else out.push(full);
  }
  return out;
}

// Derived from this module's own location rather than written down, so moving
// the directory renames the exclusion with it instead of silently emptying it.
// `tools/selftest.mjs` is the runner beside this directory; everything under
// `tools/selftest/` is the suite it runs.
const SUITE_DIR = path.relative(REPO_ROOT, path.dirname(fileURLToPath(import.meta.url)));
const SUITE_RUNNER = `${SUITE_DIR}.mjs`;

/**
 * The file that states a rule is not an instance of it: the suite has to contain
 * the needles in order to look for them, so it is excluded — and since 2026-09-19
 * it is a DIRECTORY rather than one file, so the exclusion is a predicate rather
 * than a name. Any other file that matches is a real claim.
 *
 * What it must not become is `tools/`. That would blind `grepRepo` to
 * `tools/validate.mjs`, `tools/build-index.mjs`, `tools/sign-trust.mjs` and every
 * `tools/lib/*`, and it would make the id and tag scans vacuous outright, since
 * the owners they are about live under `tools/` too. A prefix one keystroke from
 * matching everything needs a canary a name did not, so two of the tests that use
 * this carry one: `only the runbook still names the deleted withdrawal workflow`
 * asserts `grepRepo` still finds the runbook, and `nothing claims the publish
 * environment has a required reviewer` asserts this predicate's scope in both
 * directions.
 */
export function isSuiteFile(rel) {
  return rel === SUITE_RUNNER || rel.startsWith(`${SUITE_DIR}${path.sep}`);
}

export function grepRepo(needle) {
  const hits = [];
  for (const file of walkRepo()) {
    const rel = path.relative(REPO_ROOT, file);
    if (isSuiteFile(rel)) continue;
    // A listing's README is a stranger's document that this repository stores.
    // These rules are about what the registry says about ITSELF — "nothing
    // claims a required reviewer", "only the runbook names the deleted
    // workflow" — and a plugin author writing `revoke.yml` in their own
    // Releasing section is not the registry making a claim. Without this, one
    // published README turns `main` red for everybody, for ever, and the only
    // fix is editing somebody else's document. Watched: the same README with
    // the exclusion removed fails "a file other than the runbook still points
    // at revoke.yml".
    if (/^plugins[\\/][^\\/]+[\\/]README\.md$/.test(rel)) continue;
    let text;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    text.split("\n").forEach((line, i) => {
      if (line.includes(needle)) hits.push(`${path.relative(REPO_ROOT, file)}:${i + 1}`);
    });
  }
  return hits;
}
