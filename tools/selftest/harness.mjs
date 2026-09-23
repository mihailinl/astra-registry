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
import { execFileSync } from "node:child_process";
import { cleanEnv } from "../lib/git-env.mjs";

import { runValidation } from "../validate.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";

export const LIMITS = JSON.parse(fs.readFileSync(new URL("../../policy/limits.json", import.meta.url), "utf8"));

let passed = 0;
const failures = [];

/**
 * Every test this run has started, in the order it started, and the promise
 * that settles when it is done. **The runner holds these handles, not the
 * caller.**
 *
 * That sentence is the whole design and it replaces two earlier attempts that
 * were the same attempt. The failure both were for: a `test(...)` called
 * without `await` returns a promise nobody holds, `run()` resolves, the runner
 * moves on, and the test's pass or fail lands after the summary has printed and
 * after the exit code has been decided. CI reads the exit code, so a broken
 * check ships green.
 *
 * Attempt one counted tests that had STARTED and read the counter when `run()`
 * resolved. Attempt two read the same counter one turn of the event loop later.
 * Both sample — *is the started-but-unfinished set empty at moment T* — so every
 * escape is "T was too early" and every fix moves T. A helper that awaits a file
 * read before it calls `test()` has not started one yet at either moment, and
 * that is not an oversight in the choice of T; it is what choosing a T means.
 * **A longer prefix match is still a prefix match.**
 *
 * So: `test()` registers synchronously, BEFORE it returns, and the run ends when
 * everything registered has settled. There is no moment to pick, so there is no
 * moment to pick wrong, and a caller that forgets `await` changes nothing —
 * the runner never depended on the caller's discipline. What is left is not a
 * timer either: work that registers DURING the drain is caught by comparing two
 * measurements across it, which is what `drain()` returns.
 *
 * The shape is minice-be's, sent 2026-09-19 after it read the second attempt
 * here and named what both had in common.
 */
const registered = [];

/**
 * The third word, and the reason there has to be one.
 *
 * Two checks in this suite reach a state where the thing they examine is not
 * there to be examined, and until now both printed `ok` and were counted in the
 * number on the last line. `(b) the committed tree's staging listing` returns
 * early because no staging listing is published yet; the sibling half of
 * ``a `NOT verified` note never decides anything`` is inside an
 * `if (!existsSync(../AstraPlugins))`, so it runs in CI and never on a
 * developer's machine. Both were honest in the transcript — each printed a
 * parenthetical saying it had not run — and both were absorbed into
 * `300 passed`, which is the number people quote.
 *
 * **A skipped check and a passing check are the same colour in every summary.**
 * That was true of this suite until this commit, and it is the same class as
 * C19 and Gap 17: a sentence that is true about today's tree standing in for a
 * measurement nobody took.
 *
 * The shape is `tools/cutover-preflight.mjs`'s, settled at R12: three words that
 * are never merged, and **no way to convert NOT ASKED into a pass**. There is no
 * `--attested` flag there and there is no equivalent here — `neverAsk` throws, so
 * it reads like a `return` and nothing after it can be counted. An operator who
 * knows the answer records it beside the run, not in it.
 *
 * What is deliberately NOT copied is that tool's exit code 2. This suite is a
 * step in lanes that run without anybody asking — the runner prints how many on
 * its last line and `node tools/selftest.mjs --lanes` names them — so exiting
 * non-zero on a tree where these states are legitimate would turn `main` red
 * today and teach everybody to ignore the word. So the exit code still reflects
 * failures only, and the honesty is carried by the headline word and by the
 * count being taken OUT of `passed`. Flipping it to 2 is the one-line change
 * marked in the runner, and it is the operator's call, not this file's.
 *
 * Gap 106 made one kind of NOT ASKED a failure, and it is not this word's
 * kind: a NOT ASKED that no live lane can be shown to ask and nothing
 * declares. The runner proves the rest are asked in some other lane or
 * declared with the event that arms them, and exits 1, naming the check, on
 * any that is neither. That is why exit 0 on INCOMPLETE is an answer rather
 * than a count: see the note at `EXIT-2` in the runner.
 *
 * This paragraph used to name `build-index.yml`, `ingest.yml` and
 * `baseline.yml`. Measured on 2026-09-22: `baseline.yml` runs this suite only
 * on `workflow_dispatch`, so a third of the reason given for not flipping the
 * exit code was a lane that a flip could not have reddened. The runner derives
 * the list now rather than any file restating it.
 */
export class NeverAsked extends Error {
  constructor(message) {
    super(message);
    // WHERE it was said, read off the stack at the moment it was said: the
    // first frame outside this file, as a repository path, a line and a column.
    // Gap 106. The runner holds every NOT ASKED to a `neverAsk(` call it has
    // READ in tools/selftest/ and classified by the condition that gates it
    // (`neverAskSites` in tools/selftest.mjs), because a lane table can only
    // account for a NOT ASKED whose cause it can see without running the other
    // lanes. A site it did not read — an alias, a helper outside the suite, a
    // bare `throw new NeverAsked` — is a NOT ASKED no lane table accounts for,
    // and the site is how the runner tells. `null` when no frame outside this
    // file is found, which the runner treats as a site it did not read.
    this.site = callerSite(this.stack);
  }
}

const HARNESS_FILE = fileURLToPath(import.meta.url);

/** `{ file, line, column }` of the first stack frame outside this file, or null. */
function callerSite(stack) {
  for (const frame of String(stack || "").split("\n").slice(1)) {
    const m = /\(?(file:\/\/[^\s()]+?|\/[^\s()]+?):(\d+):(\d+)\)?\s*$/.exec(frame);
    if (!m) continue;
    let file;
    try { file = m[1].startsWith("file://") ? fileURLToPath(m[1]) : m[1]; } catch { continue; }
    if (file === HARNESS_FILE) continue;
    return { file: path.relative(REPO_ROOT, file).split(path.sep).join("/"), line: Number(m[2]), column: Number(m[3]) };
  }
  return null;
}

const notAsked = [];

/**
 * Every check's verdict, in the order it settled: `{ name, verdict, site }`,
 * where `verdict` is `ok`, `fail` or `notAsked`, and `site` is where a NOT
 * ASKED was said. The runner reads it per module, to hold each NOT ASKED to
 * the `neverAsk(` it was read from, and each environment-gated check to
 * having said NOT ASKED wherever its environment really holds (gap 106).
 */
const outcomes = [];

/**
 * Say that this check could not be asked, and say who can answer it.
 *
 * Throws rather than returns, for the reason `cutover-preflight.mjs` has no
 * `--attested`: a helper that returned would let the rest of the test body run
 * and be counted, which is the behaviour being removed.
 *
 * @param {string} why what was not there, in the present tense
 * @param {string} [whoCanAnswer] what would have to change for this to be asked
 */
export function neverAsk(why, whoCanAnswer) {
  throw new NeverAsked(whoCanAnswer ? `${why} — ${whoCanAnswer}` : why);
}

export function test(name, fn) {
  const done = (async () => {
    try {
      await fn();
      console.log(`  ok    ${name}`);
      passed++;
      outcomes.push({ name, verdict: "ok", site: null });
    } catch (e) {
      if (e instanceof NeverAsked) {
        // A marker a reader cannot mistake for `ok`, and the reason on the line
        // under it, because "which check did not run" is the question somebody
        // reading a green log is trying to answer.
        console.log(`  ----  ${name}`);
        console.log(`        NOT ASKED: ${e.message.split("\n").join("\n        ")}`);
        notAsked.push(`${name} — ${e.message}`);
        outcomes.push({ name, verdict: "notAsked", site: e.site });
        return;
      }
      console.log(`  FAIL  ${name}`);
      console.log(`        ${e.message.split("\n").join("\n        ")}`);
      failures.push(name);
      outcomes.push({ name, verdict: "fail", site: null });
    }
  })();
  registered.push({ name, done });
  return done;
}

/** What the runner prints on the last line. Read once, after the last module. */
export function results() {
  return { passed, failures, notAsked, outcomes };
}

/**
 * Settle everything registered, and return the names of any test that
 * registered WHILE that was happening.
 *
 * A name in the returned list is a test whose `test(...)` call the module did
 * not await: its work reached the harness only after the module had already
 * been accounted for. The late ones are settled too, so their pass or fail is
 * still counted and still printed — the point is to report the accounting
 * error, not to lose the result.
 *
 * This is a comparison of two measurements rather than a reading taken at a
 * chosen instant, which is why "how long to wait" never enters. It terminates
 * because each pass drains a set that was already registered when the pass
 * began.
 */
export async function drain() {
  const before = registered.length;
  for (let mark = before; ; mark = registered.length) {
    await Promise.allSettled(registered.map((r) => r.done));
    if (registered.length === mark) break;
  }
  return registered.slice(before).map((r) => r.name);
}

/** How many tests have been registered so far. A floor's denominator. */
export function registeredCount() {
  return registered.length;
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

// And at exit, whatever the exit was. The runner calls `cleanupTmp()` on every
// path it chooses, and only on those: a script that imports this file or a case
// without the runner, or a rejection nobody awaited, left this directory in
// `/tmp`, a tmpfs every session on the machine shares (58 were counted there on
// 2026-09-23, causes unrecorded). `exit` fires on both, and on process.exit().
//
// It does not fire for a signal, and that is left alone on purpose. A JS
// listener for SIGTERM or SIGINT only runs when the event loop turns, and this
// suite runs synchronously from its first module to its last: measured, a
// SIGTERM sent four seconds into a run with such a listener installed was held
// until the run had finished, and the process exited 0. A suite that cannot be
// stopped is worse than a directory left behind by one that was.
//
// A fixture a case makes UNDER `tmp` goes with it, which is why they are made
// there and not beside it (repo-rules.mjs holds them to that).
process.on("exit", cleanupTmp);

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
 *
 * It asks git what this repository CONTAINS rather than reading the disk and
 * subtracting, and the difference is not tidiness.
 *
 * It was a `readdirSync` recursion skipping `.git`, `node_modules` and `dist`.
 * On this machine that walk returned 633 files; in CI, and in any fresh
 * checkout, 335. The 298 are `bot/manifest-probe/_deps/` and
 * `bot/manifest-probe/target/` — git-ignored Rust build output that the skip
 * list had never heard of. **So every rule built on this walk had a different
 * subject depending on whose machine it ran on**, and nothing said so. A grep
 * for a forbidden phrase could hit a vendored dependency's source locally and
 * not in CI; a floor measured here would be measured against build artifacts.
 * The second is not hypothetical — the floor in repo-rules.mjs was written at
 * 150 for `bot/` from the 356 files on this machine, and CI, which sees 61,
 * went red on the commit that added it.
 *
 * `git ls-files` is the same answer everywhere: the tracked set, on this
 * machine, in CI, and in the `publish` workspace — where it also happens to
 * answer the older finding that the self-scan must not read a stranger's
 * downloaded bundle, because nothing downloaded is tracked.
 *
 * What is left of the exclusion list is the two paths that ARE tracked and are
 * deliberately not the subject. Every other name in it was compensating for
 * reading the disk.
 */
export function walkRepo() {
  let listed;
  try {
    listed = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z"], {
      encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
      env: cleanEnv(),
    });
  } catch (e) {
    // Loud rather than empty: an empty walk makes every rule built on it pass.
    throw new Error(
      `the repository walk asked \`git ls-files\` in ${REPO_ROOT} and it failed, so every rule that scans this ` +
      `repository would have found nothing and passed: ${String(e.stderr || e.message).trim()}`,
    );
  }
  return listed
    .split("\0")
    .filter(Boolean)
    .filter((rel) => !rel.startsWith("reports/") && !rel.startsWith("watch-state/"))
    .map((rel) => path.join(REPO_ROOT, rel));
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
