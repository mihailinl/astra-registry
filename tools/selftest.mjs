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
  // this line is not the inventory: the pinned list in repo-rules.mjs is, and it
  // names the modules rather than counting files. Set at 18 this would go red on
  // an honest deletion, get read as noise, and be the first number somebody
  // lowers to zero. Ten is the number below which the walk has stopped working
  // rather than the suite having stopped having modules.
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
  //
  // The try/catch is what makes the sentence above `fail()` true. A file that
  // throws at its top level — a bad import, a fixture that cannot be built at
  // module scope — threw straight out of here, past every catch in this file:
  // Node printed a bare stack, there was no FAIL headline, no summary line, and
  // the temp directory stayed behind. Repro: `printf 'throw new Error("boom");'
  // > tools/selftest/x.mjs`. It is the one import in the runner that touches a
  // file nothing has vouched for yet, so it is the one that has to assume the
  // file is broken.
  const carriesTests = [];
  const undeclared = [];
  for (const name of onDisk) {
    let mod;
    try {
      mod = await load(name);
    } catch (e) {
      fail(`${name} threw while it was being imported, so the suite never started`, [
        String(e && e.stack ? e.stack : e),
      ]);
    }
    if (typeof mod.run !== "function") continue;
    carriesTests.push(name);
    // The count a test module owns. See TESTS below; here it is only checked to
    // exist, because a module that joins the suite without one would be a module
    // whose only size check is that it is not zero.
    if (!Number.isInteger(mod.TESTS) || mod.TESTS < 1) {
      undeclared.push(`${name} (TESTS is ${JSON.stringify(mod.TESTS)})`);
    }
  }
  const unrun = carriesTests.filter((n) => !MODULES.includes(n));
  const testless = MODULES.filter((n) => onDisk.includes(n) && !carriesTests.includes(n));
  if (unrun.length) {
    problems.push(`exports run() and is not in the runner's list, so its tests do not run: ${unrun.join(", ")}`);
  }
  if (testless.length) {
    problems.push(`listed by the runner and exports no run(), so nothing in it runs: ${testless.join(", ")}`);
  }
  if (undeclared.length) {
    problems.push(
      `exports run() and does not declare how many tests it reports; add \`export const TESTS = <n>;\` ` +
      `beside its run(): ${undeclared.join(", ")}`,
    );
  }
  if (problems.length) fail("the suite does not run what tools/selftest/ holds", problems);
}

// The way the suite gets smaller that checkModuleSet cannot see: the directory
// and the list above still agree with each other, and there is simply less in
// the modules than there was. An emptied `run()`, an early `return`, a `for`
// over a list that is now empty, half a file deleted in a bad merge.
//
// This was a GLOBAL count in the runner, twice, and a global count cannot be
// what it has to be here. Both attempts are worth reading, because the shape
// below is the thing they rule out rather than a third guess:
//
//   - as a floor derived from the suite (the live count of `await test(` sites),
//     it fired on GROWTH: append 34 passing tests and a strictly larger, wholly
//     green suite went red, telling its author to raise the number. The number
//     lives in the runner. Ten wave-1 tasks write into this suite and all of
//     them add tests, so that is ten tasks queueing on one line — which is the
//     queue the split existed to remove, put back by the guard that was supposed
//     to protect the split;
//   - as a pinned literal it stopped firing on growth and stopped firing at all.
//     Nothing re-armed it. Grow the suite by 30 and you can then delete a whole
//     module from disk and from the list above: `PASS  196 passed`, then
//     `PASS  191 passed`, exit 0, five checks gone and the guard green through
//     both.
//
// So the count is not global any more. EACH MODULE DECLARES ITS OWN — `export
// const TESTS = 12;` beside its `run()` — and the runner asserts each module
// reported exactly that many. That answers both failures at once: growth is an
// edit to the file the task is already editing, in the same commit as the test
// it added, so no line is shared and nothing serialises; and the number cannot
// go stale in the direction that matters, because there is no slack anywhere for
// a loss to hide in.
//
// EQUALITY, not a per-module floor. A floor would still miss the commonest real
// shrinkage — a module that loses four tests of eighteen and keeps fourteen —
// and equality costs exactly one line, in a file the author has open, in a
// commit that is already changing that file's test count. That is the cheapest
// guard in this repository and the only one that reads a deletion as a deletion.
//
// It also deletes the two guards that existed only to protect the old global
// number: the ratchet in repo-rules.mjs that pinned TEST_FLOOR from below, and
// the interlock that counted textual occurrences of the guards' names in this
// file. See the note on `no module has left the runner's list` in
// repo-rules.mjs for what took their place and what did not.
const reported = () => {
  const r = results();
  return r.passed + r.failures.length;
};

// Let everything already scheduled finish before reading a counter.
//
// `inFlight()` counts tests that have STARTED, and a helper that awaits
// something before it calls `test()` — the commonest shape in this suite — has
// not started one yet at the moment `run()` resolves. So the un-awaited
// `test(...)` that this check exists to catch read as zero in flight whenever it
// was one await away from beginning: `PASS  166 passed, 0 failed`, exit 0, and
// the FAIL printed below the summary line where CI does not look. One turn of
// the event loop is enough for the pending continuations to reach their
// `test()` call and make themselves countable.
const settle = () => new Promise((r) => setImmediate(r));

await checkModuleSet();

// Nothing may have run yet.
//
// Every accounting below is per module, and a test that runs outside a module's
// `run()` belongs to no module: it prints above the first section header, it is
// counted in the total on the last line, and no `TESTS` anywhere is asked about
// it. The way to write one is not exotic — a file under tools/selftest/ with
// top-level `await test(...)` and no `run()` export is not a test module by the
// only definition this runner has, so it is treated as a fixture, imported by
// checkModuleSet to ask what it exports, and its tests execute inside the guard.
// Watched: two such tests came out as transcript lines 1 and 2 of
// `PASS  168 passed, 0 failed`, exit 0.
//
// Asserting the counters are still zero here is one line and does not care how
// the file was classified, what it is called, or which of the eighteen imports
// pulled it in. Anything that has run by this point ran somewhere nothing is
// accountable for it.
await settle();
{
  const early = reported();
  const starting = inFlight();
  if (early || starting) {
    fail(`${early + starting} test(s) ran before the first module`, [
      "a file under tools/selftest/ calls test() at import time instead of from inside run(); its names print " +
      "above the first section header, no module's TESTS accounts for them, and nothing reports them",
    ]);
  }
}

const shortfalls = [];
let declared = 0;
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
  await settle();
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
  declared += mod.TESTS;
  const ran = reported() - before;
  if (ran !== mod.TESTS) {
    shortfalls.push(
      ran < mod.TESTS
        ? `${name} reported ${ran} tests and declares TESTS = ${mod.TESTS}: ${mod.TESTS - ran} check(s) that used ` +
          `to run do not run any more`
        : `${name} reported ${ran} tests and declares TESTS = ${mod.TESTS}: it grew, so raise TESTS to ${ran} in ` +
          `tools/selftest/${name} — that line and no other file`,
    );
  }
}

cleanupTmp();

const { passed, failures } = results();
// The sum is derived and printed, and nothing compares it to a number written
// down anywhere: it is fifteen module-owned numbers added up, and it is on the
// last line so a reader still has one figure to look at. A reader who wants to
// know whether the suite shrank reads the shortfalls, not this.
console.log(
  `\n${failures.length === 0 && shortfalls.length === 0 ? "PASS" : "FAIL"}  ${passed} passed, ${failures.length} failed ` +
  `(${MODULES.length} modules declaring ${declared})`,
);
for (const f of failures) console.log(`      - ${f}`);
for (const s of shortfalls) console.log(`      - the suite is not the size its modules say: ${s}`);
if (failures.length || shortfalls.length) process.exit(1);
