#!/usr/bin/env node
// The registry's own test suite. `node tools/selftest.mjs`, no arguments, no
// network, no dependencies.
//
// Half of these tests assert that something is ACCEPTED. The other half assert
// that something is REJECTED, and those are the ones that matter: a validator
// nobody has watched say no is a validator nobody knows works. Each negative
// case is a file a reviewer can open — tests/fixtures/ — or two bytes away from
// one, and each names the real defect it stands for.
//
// This file is the runner. The tests live in `tools/selftest/`, one module per
// subject, and each exports `run()` rather than testing at import: two sibling
// modules that both used top-level `await test(...)` would INTERLEAVE — the spec
// starts the second module's evaluation while the first is suspended at its
// first await — and the printed order is itself under test, so the names would
// come out round-robin across fifteen files. The runner awaits them one at a
// time, in the order below, which is the order they print in.
//
// Sequential is also a correctness requirement, not just a cosmetic one:
// `$ASTRA_PLUGINS_DIR` is set and restored around individual checks, and one
// test mutates `CORPUS_NO_RULE_ID` and puts it back. Both are process-global.
// Do not "speed this up" with Promise.all.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { cleanupTmp, inFlight, results } from "./selftest/harness.mjs";

// The order is load-bearing: it is the order the 165 names print in, and two of
// the boundaries are not where the section headers are. The serial test opens
// catalogue.mjs and prints under primitives' "zip reader/writer" header; the
// staging tests open validation.mjs and print under catalogue's "the real
// registry".
//
// Filenames, and nothing but filenames. This list used to pair each name with a
// separately-imported binding — `["origins.mjs", origins]` — and nothing
// compared the two halves, because `checkModuleSet` reads the strings and the
// loop runs the bindings. Changing one binding to a sibling's, which is what a
// copy-paste in a fifteen-line list does, ran that sibling twice and origins not
// at all: `PASS  202 passed, 0 failed`, exit 0, every guard green, and the
// number a reader checks went UP. The mismatch is not caught now, it cannot be
// written: the string IS the module, loaded by it below.
const MODULES = [
  "primitives.mjs",
  "catalogue.mjs",
  "publishers.mjs",
  "validation.mjs",
  "couplings.mjs",
  "listings.mjs",
  "origins.mjs",
  "bundles.mjs",
  "index-signature.mjs",
  "revocations.mjs",
  "cli.mjs",
  "root-delegation.mjs",
  "update-signing.mjs",
  "update-notes.mjs",
  "repo-rules.mjs",
];

const SUITE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "selftest");

const load = (name) => import(`./selftest/${name}`);

// tmp exists from the moment harness.mjs is imported and the fixture modules
// write PEMs into it at their own import, so every exit path from here on has to
// go through this rather than through a bare `process.exit`.
function fail(headline, problems) {
  cleanupTmp();
  console.log(`\nFAIL  ${headline}`);
  for (const p of problems) console.log(`      - ${p}`);
  process.exit(1);
}

// A module nobody runs is a silent loss of tests, and one file made that
// impossible. Neither the count on the last line nor a green PASS can see it: a
// suite that runs fourteen of fifteen modules says PASS and says it about less.
//
// So the directory and the list above are compared as SETS, and the check fails
// in both directions — a module added and not listed, and a module listed twice,
// which would print its names again. Watched failing both ways before it was
// committed, the way bot/lib/policy.mjs's 26 exports were.
//
// What makes a file a test module is DERIVED, not declared: a file under
// tools/selftest/ is a test module if and only if it exports `run`. There used
// to be a hand-written `FIXTURE_MODULES` list asserting that three files carry
// no tests, and it was an assertion nothing checked — an `export async function
// run()` added to fixtures.mjs, with a deliberately failing test in it, printed
// `PASS  166 passed, 0 failed`: in the imported set so the sets agreed, and the
// total unmoved so the floor agreed, and the test neither run nor reported. It
// also made adding an honest new fixture module go red with a message that was
// false — "never imported", about a file that is imported. Asking each file what
// it exports answers both, and the question has one answer rather than two lists
// that can drift.
//
// Importing every file in the directory to ask is not new exposure: all eighteen
// are imported today anyway, the three fixture ones through the test modules
// that use them. What is new is that a nineteenth file is imported here before
// it is listed anywhere, which is what lets this say `exports run()` about it.
//
// Not a test(): this commit's proof is that the 165 names came back identical,
// and a sixteenth name would spend that proof.
async function checkModuleSet() {
  const onDisk = fs.readdirSync(SUITE_DIR).filter((n) => n.endsWith(".mjs")).sort();
  const problems = [];
  // A floor on the WALK, because everything below it compares two lists and two
  // empty lists agree. If the readdir stops finding anything — the directory
  // renamed, the `.mjs` filter outlived the extension, this file executed from
  // somewhere its own dirname does not resolve from — `missing` is empty and the
  // check reads as a clean bill of health. `phantom` happens to catch the empty
  // walk today, but only because the module list is not empty, and that is a
  // property of the other side of the comparison rather than of this one.
  //
  // 18 on 2026-09-19 — fifteen test modules and three fixture ones — and the
  // floor is 10, not 18, deliberately. Retiring a module is a legitimate act and
  // this line is not the inventory: TEST_FLOOR below is, and it counts the thing
  // that actually matters. Set at 18 this would go red on an honest deletion,
  // get read as noise, and be the first number somebody lowers to zero. Ten is
  // the number below which the walk has stopped working rather than the suite
  // having stopped having modules.
  if (onDisk.length < 10) {
    problems.push(
      `the walk of tools/selftest/ found ${onDisk.length} .mjs files and there were 18 on 2026-09-19; ` +
      `this is a broken walk, not a smaller suite, and every comparison below it would have passed`,
    );
  }
  const duplicated = MODULES.filter((n, i) => MODULES.indexOf(n) !== i);
  const phantom = MODULES.filter((n) => !onDisk.includes(n));
  if (duplicated.length) problems.push(`listed twice, so its names print twice: ${duplicated.join(", ")}`);
  if (phantom.length) problems.push(`listed by the runner and not in tools/selftest/: ${phantom.join(", ")}`);
  // Only ask the files that are actually there; a phantom's import would throw
  // before the list above could be printed, and a missing file is the more
  // useful message.
  const carriesTests = [];
  for (const name of onDisk) {
    const mod = await load(name);
    if (typeof mod.run === "function") carriesTests.push(name);
  }
  const unrun = carriesTests.filter((n) => !MODULES.includes(n));
  const testless = MODULES.filter((n) => onDisk.includes(n) && !carriesTests.includes(n));
  if (unrun.length) {
    problems.push(`exports run() and is not in the runner's list, so its tests do not run: ${unrun.join(", ")}`);
  }
  if (testless.length) {
    problems.push(`listed by the runner and exports no run(), so nothing in it runs: ${testless.join(", ")}`);
  }
  if (problems.length) fail("the suite does not run what tools/selftest/ holds", problems);
}

// Two ways the suite gets smaller that checkModuleSet cannot see, because in
// both of them the directory and the module list still agree with each other:
//
//   - a module that is listed, and runs, and tests nothing — a rewrite that
//     lost the body of `run()`, an early `return`, a `for` over an empty list;
//   - a module deleted from tools/selftest/ AND from the list above in one
//     commit, which is two consistent lists and fewer checks.
//
// The first is caught per module and reported BY NAME, which is the one thing
// the split bought here: before it there was one file and no boundary to stand
// on, so an emptied section was only ever a number that had drifted.
//
// The second is caught by the total, and the total is a FLOOR rather than an
// equality on purpose. Ten wave-1 tasks write into this suite and all of them
// add tests; an exact count would send every one of them to edit this line,
// which is the queue the split existed to remove. A floor never fires on growth,
// so it costs the ten nothing and still goes red the day a check is lost.
//
// That sentence was false when it was written, and the falsehood was not here.
// This number is ratcheted from below by a test in repo-rules.mjs, so that
// somebody clearing a red build cannot just set it to zero — and that ratchet
// compared this number against the live count of `await test(` sites on disk,
// 133 of them against a floor of 166. Thirty-three tests of slack, after which
// the interlock fired on GROWTH: a strictly larger, wholly green suite went red,
// telling its author the floor was too low, and the edit it asked for was this
// line — the one shared line in the runner that the split existed to take out of
// ten tasks' path. The ratchet is a pinned literal now, measured on the same day
// as this one and checked into repo-rules.mjs beside the date. Nothing that
// grows with the suite is compared against this number by anything.
//
// 166 on 2026-09-19: the 165 this split was proved against, plus the interlock
// test added with these guards. Measured, not estimated —
// `node tools/selftest.mjs | grep -c '^  ok'`.
const TEST_FLOOR = 166;

function shrinkage(silentModules, total) {
  const out = [];
  if (silentModules.length) {
    out.push(
      `${silentModules.join(", ")} reported no test at all — listed and run, so the module set is intact, and empty`,
    );
  }
  if (total < TEST_FLOOR) {
    out.push(
      `${total} tests reported, and there were ${TEST_FLOOR} on 2026-09-19; ` +
      `a floor only moves down when checks stop running`,
    );
  }
  return out;
}

await checkModuleSet();

const reported = () => {
  const r = results();
  return r.passed + r.failures.length;
};

const silent = [];
for (const name of MODULES) {
  const before = reported();
  const mod = await load(name);
  try {
    await mod.run();
  } catch (e) {
    // A throw out of run() and not out of a test() — a fixture that could not be
    // built, a bad import inside the body. Without this it is an unhandled
    // rejection: no summary line, and the temp directory left behind.
    fail(`${name} threw outside a test(), so the rest of the suite did not run`, [
      String(e && e.stack ? e.stack : e),
    ]);
  }
  if (reported() === before) silent.push(name);
  // A `test(...)` written without its `await` returns a promise nobody holds.
  // The module's run() finishes, the runner moves on, and if the test's body has
  // any real await in it — a dynamic import, a file read — its result lands
  // after the summary has already been printed and the exit code already
  // decided. Watched: one non-awaited test asserting false printed
  // `PASS  166 passed, 0 failed`, exit 0, with its FAIL line below the summary.
  // CI reads the exit code. So the harness counts tests in flight and the
  // boundary between two modules is where a test still running is a test whose
  // result nothing is waiting for.
  const running = inFlight();
  if (running) {
    fail(`${name}'s run() returned with ${running} test(s) still running`, [
      "a test() was called without `await`, so its pass or fail lands after this module — and can land after the " +
      "summary line, where the exit code has already been decided",
    ]);
  }
}

cleanupTmp();

const { passed, failures } = results();
const shortfalls = shrinkage(silent, passed + failures.length);
console.log(`\n${failures.length === 0 && shortfalls.length === 0 ? "PASS" : "FAIL"}  ${passed} passed, ${failures.length} failed`);
for (const f of failures) console.log(`      - ${f}`);
for (const s of shortfalls) console.log(`      - the suite is smaller than it was: ${s}`);
if (failures.length || shortfalls.length) process.exit(1);
