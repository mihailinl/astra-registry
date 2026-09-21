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
// come out round-robin across every module in the list. The runner awaits them
// one at a time, in the order below, which is the order they print in.
//
// Sequential is also a correctness requirement, not just a cosmetic one:
// `$ASTRA_PLUGINS_DIR` is set and restored around individual checks, and one
// test mutates `CORPUS_NO_RULE_ID` and puts it back. Both are process-global.
// Do not "speed this up" with Promise.all.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { cleanupTmp, drain, registeredCount, results } from "./selftest/harness.mjs";

// The order is load-bearing: it is the order every name prints in, and two of
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
  // Beside index-signature.mjs because it is the same subject one step on —
  // that module asks whether a signature is good, this one asks which key was
  // allowed to make it and which document it was allowed to make it over. It
  // prints its own three section headers, and so does revocations.mjs below
  // it, so inserting here moves no existing name under a header it does not
  // belong to. The two places in this list where a module's names print under
  // the PREVIOUS module's header are primitives→catalogue and
  // catalogue→validation; nothing may be inserted between either pair.
  "signer.mjs",
  // Immediately after signer.mjs, because it is that module's other half:
  // signer.mjs asks what the signer DECIDES, and this one asks what it DOES —
  // the four documents it writes, the commit it makes, the push it retries,
  // and SERVE-95's refusal, which is the one rule that can only be asked once
  // all four documents exist. It prints its own section header, so inserting
  // here moves no existing name under a header it does not belong to.
  "signer-run.mjs",
  // Beside signer.mjs for the reason signer.mjs is beside index-signature.mjs:
  // it is the same subject one step on. That module asks what the signer
  // decides to publish; this one asks whether what is published is what `main`
  // says, whether what a stranger is served is what was published (RC-R1-4,
  // RC-R1-5), and how long the trust document under all of it has left
  // (ROLL-45, RC-R1-6). It prints its own six section headers, so inserting
  // here moves no existing name under a header it does not belong to.
  "served-set.mjs",
  "revocations.mjs",
  "cli.mjs",
  "root-delegation.mjs",
  // After root-delegation.mjs because it is the same subject from the other
  // end — that module asks whether the offline ceremony's command refuses a
  // key that is not a published root; this one asks whether the published
  // roots are still the keys the bot compiles in (B-T1.5). It prints its own
  // section header, and so does update-signing.mjs below it, so inserting
  // here moves no existing name under a header it does not belong to.
  "roots.mjs",
  "update-signing.mjs",
  "update-notes.mjs",
  "repo-rules.mjs",
  // After `repo-rules.mjs` rather than before it, and with a section header
  // of its own. `repo-rules.mjs` has no header, so its names print under
  // `update-notes.mjs`'s — inserting ABOVE it would move them under this
  // module's header instead. Inserting below moves nothing, and `baseline.mjs`
  // stays last.
  "claims.mjs",
  // RC-R2-2 — the token file's own version discipline, and the register of
  // which half of the cron-versus-file comparison runs here and which runs in
  // `bot/tests/workflows.test.mjs`. It prints its own section header, so
  // appending here moves no existing name under a header it does not belong
  // to; the boundary to protect is still `update-notes.mjs` → `repo-rules.mjs`,
  // and nothing is inserted between that pair.
  "contract-tokens.mjs",
  // RC-R2-4 — `tools/regenerate-signed.mjs`, run as a carrier runs it. It
  // prints its own section header, so it could sit anywhere after a module
  // that prints one; here, after `contract-tokens.mjs` and before
  // `baseline.mjs`, because that is the slot where nothing at all moves.
  //
  // **This line and the file beneath it are ONE change and cannot be split
  // across two commits.** The reason is `checkModuleSet` below: the list and
  // the directory are compared as SETS and it fails in BOTH directions. A
  // commit that adds the module without this line fails with "exports run()
  // and is not in the runner's list"; a commit that adds this line without
  // the module fails with "listed by the runner and not in tools/selftest/".
  // Either half alone is a red `node tools/selftest.mjs`, which is a step in
  // `build-index.yml`, `ingest.yml`, `plugins-moderation.yml` and
  // `baseline.yml` — so splitting the change does not stage it, it schedules
  // an outage and only chooses which side of the merge gets it. The two-way
  // check is right and is not the thing to relax; what it means is that
  // whoever owns this list and whoever writes a module have to arrive in the
  // same commit. Written here because the instruction to leave the line to
  // its owner assumed it was separable, and for this file it is not.
  "regenerate.mjs",
  // Last, and with a section header of its own. The boundary to protect is
  // `update-notes.mjs` → `repo-rules.mjs`: `repo-rules.mjs` prints no header,
  // so its names come out under `update-notes.mjs`'s, and anything inserted
  // between that pair would take them. Appending after a module that prints
  // its own header moves nothing at all.
  "baseline.mjs",
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
// Importing every file in the directory to ask is not new exposure: every file
// under tools/selftest/ is imported anyway, the three fixture ones through the
// test modules that use them. What is new is that a file is imported here
// before it is listed anywhere, which is what lets this say `exports run()`
// about it.
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
  // 19 on 2026-09-19 — sixteen test modules and three fixture ones — and the
  // floor is 10, not 19, deliberately. Retiring a module is a legitimate act and
  // this line is not the inventory: the pinned list in repo-rules.mjs is, and it
  // names the modules rather than counting files. Set at 19 this would go red on
  // an honest deletion, get read as noise, and be the first number somebody
  // lowers to zero. Ten is the number below which the walk has stopped working
  // rather than the suite having stopped having modules.
  if (onDisk.length < 10) {
    problems.push(
      `the walk of tools/selftest/ found ${onDisk.length} .mjs files and there were 19 on 2026-09-19; ` +
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
  const sharedRun = [];
  const runOwners = new Map();
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
    // Two names, one module. A module copied from a sibling whose
    // `export { run } from "./…"` was never changed, or a file replaced by a
    // symlink to one, loads ONE module under two names: the shadowed module's
    // tests stop running and the printed total RISES, because the other
    // module's names come out twice. Watched on this tree: a re-export gave
    // `PASS  189 passed, 0 failed`, exit 0, with eighteen checks gone and
    // forty-one names printed twice. Every check above compares text, and no
    // text distinguishes that from a legitimate file — only the identity of the
    // function does.
    const twin = runOwners.get(mod.run);
    if (twin) sharedRun.push(`${twin} and ${name}`);
    else runOwners.set(mod.run, name);
  }
  const unrun = carriesTests.filter((n) => !MODULES.includes(n));
  const testless = MODULES.filter((n) => onDisk.includes(n) && !carriesTests.includes(n));
  if (unrun.length) {
    problems.push(`exports run() and is not in the runner's list, so its tests do not run: ${unrun.join(", ")}`);
  }
  if (testless.length) {
    problems.push(`listed by the runner and exports no run(), so nothing in it runs: ${testless.join(", ")}`);
  }
  if (sharedRun.length) {
    problems.push(
      `two names load one module, so one of each pair never runs and the other's names print twice: ` +
      `${sharedRun.join(", ")}`,
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
// A third attempt gave each module its own number — `export const TESTS = 12;`
// beside its `run()`, asserted for EQUALITY — on the argument that growth is
// then an edit to the file the author already has open, so no line is shared.
// It is gone too, and the reason is worth more than the guard was, because it
// is arithmetic rather than taste.
//
// **Equality fires exactly when a module's test count changes without that
// module's text changing.** Every other shrinkage — a deleted test, an emptied
// loop, a bad merge — is an edit to the module, and the author editing it
// updates the number three lines away in the same diff. So ask what actually
// changes a module's count from outside it, and in this repository there is one
// answer: `bundles.mjs` declares 41 and owns 8. The other 33 come from
// `registerSharedVectorTests` over the VENDORED `tests/vectors/`, one test per
// vector, refreshed from AstraPlugins. The ordinary re-vendor therefore went red
// — `bundles.mjs reported 42 and declares 41: raise TESTS to 42 in
// tools/selftest/bundles.mjs — that line and no other file` — naming a file the
// author never opened, about a number owned by another repository. That is the
// guard's entire true-positive set, and it is a false alarm.
//
// And the loss it was meant to catch there is already caught, better, by the
// side that owns it: `tests/shared-vectors.mjs` asserts `checked >= 20` and
// `n >= 20` twice, in the module whose vectors they are, with a message about
// vectors.
//
// The cost was not only the false red. Two tasks adding a test to one module
// make the IDENTICAL `18` → `19` edit; git auto-merges it as one change and the
// merged tree is red on a line neither author could have written correctly.
// With ten tasks over fifteen modules that collision is near certain. The queue
// was not removed by sharding it fifteen ways — it was hidden, in the one place
// a merge does not warn.
//
// What is left is a FLOOR OF ONE per module, and the honest statement of what
// it does not catch is below it. It reads a module that reported nothing —
// emptied `run()`, early `return`, a `for` over a list that is now empty, half a
// file lost in a merge — and it says nothing about a module that kept fourteen
// tests of eighteen. Nothing here catches that, and no count can: the author who
// deletes four tests is the author who would update the number.
//
// Deleted with the global count: the ratchet in repo-rules.mjs that pinned
// TEST_FLOOR from below, and the interlock that counted textual occurrences of
// the guards' names in this file. See the note on `no module has left the
// runner's list` in repo-rules.mjs for what took their place and what did not.
const reported = () => {
  const r = results();
  return r.passed + r.failures.length;
};

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
// Asserting nothing has registered here is one line and does not care how the
// file was classified, what it is called, or which of the eighteen imports
// pulled it in. Anything registered by this point ran somewhere nothing is
// accountable for it.
{
  const early = await drain();
  if (early.length || registeredCount()) {
    fail(`${registeredCount()} test(s) registered before the first module`, [
      "a file under tools/selftest/ calls test() at import time instead of from inside run(); its names print " +
      "above the first section header and belong to no module: " + [...new Set(early)].join(", "),
    ]);
  }
}

const shortfalls = [];
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
  // A `test(...)` written without its `await` no longer loses its result: the
  // harness registered the promise synchronously, so `drain()` settles it and
  // its pass or fail is counted here, in this module, where it belongs. What
  // `drain()` returns is the accounting error that is left — a test that
  // reached the harness only AFTER this module had been drained, which means
  // the module returned while work of its own was still on the way.
  //
  // This replaced two readings of a counter, both of which asked "is the
  // started-but-unfinished set empty now" and both of which were beaten by a
  // helper that awaits a file read before it calls `test()`. Moving the moment
  // is not a fix for having chosen a moment.
  const late = await drain();
  if (late.length) {
    fail(`${name}'s run() returned before ${late.length} of its own test(s) had even registered`, [
      "a test() was called without `await` behind something else that was awaited, so the call reached the " +
      "harness after this module was accounted for: " + [...new Set(late)].join(", "),
    ]);
  }
  const ran = reported() - before;
  if (ran < 1) {
    shortfalls.push(
      `${name} is in the list, was imported and its run() returned, and it reported no test at all — an emptied ` +
      `run(), an early return, or a loop over a list that is now empty`,
    );
  }
}

// One more, after the last module: a test registered by something slower than
// any module boundary — a timer, a watcher — belongs to nobody and would
// otherwise settle after the summary. Reported rather than silently counted,
// because a result that arrives with no module to attribute it to is an
// accounting hole even when it passes.
const stragglers = await drain();
if (stragglers.length) {
  fail(`${stragglers.length} test(s) registered after the last module`, [
    "nothing was waiting for these and no module is accountable for them: " + [...new Set(stragglers)].join(", "),
  ]);
}

cleanupTmp();

const { passed, failures } = results();
// Both figures are counted, not compared to anything written down. The module
// count is here because a module count going down by one is the one shrinkage
// a reader can see at a glance, and the pinned list in repo-rules.mjs is what
// actually asserts it.
console.log(
  `\n${failures.length === 0 && shortfalls.length === 0 ? "PASS" : "FAIL"}  ${passed} passed, ${failures.length} failed ` +
  `(${MODULES.length} modules)`,
);
for (const f of failures) console.log(`      - ${f}`);
for (const s of shortfalls) console.log(`      - a module ran and reported nothing: ${s}`);
if (failures.length || shortfalls.length) process.exit(1);
