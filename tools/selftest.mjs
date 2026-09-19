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

import { cleanupTmp, results } from "./selftest/harness.mjs";

import * as primitives from "./selftest/primitives.mjs";
import * as catalogue from "./selftest/catalogue.mjs";
import * as publishers from "./selftest/publishers.mjs";
import * as validation from "./selftest/validation.mjs";
import * as couplings from "./selftest/couplings.mjs";
import * as listings from "./selftest/listings.mjs";
import * as origins from "./selftest/origins.mjs";
import * as bundles from "./selftest/bundles.mjs";
import * as indexSignature from "./selftest/index-signature.mjs";
import * as revocations from "./selftest/revocations.mjs";
import * as cli from "./selftest/cli.mjs";
import * as rootDelegation from "./selftest/root-delegation.mjs";
import * as updateSigning from "./selftest/update-signing.mjs";
import * as updateNotes from "./selftest/update-notes.mjs";
import * as repoRules from "./selftest/repo-rules.mjs";

// The order is load-bearing: it is the order the 165 names print in, and two of
// the boundaries are not where the section headers are. The serial test opens
// catalogue.mjs and prints under primitives' "zip reader/writer" header; the
// staging tests open validation.mjs and print under catalogue's "the real
// registry".
const MODULES = [
  ["primitives.mjs", primitives],
  ["catalogue.mjs", catalogue],
  ["publishers.mjs", publishers],
  ["validation.mjs", validation],
  ["couplings.mjs", couplings],
  ["listings.mjs", listings],
  ["origins.mjs", origins],
  ["bundles.mjs", bundles],
  ["index-signature.mjs", indexSignature],
  ["revocations.mjs", revocations],
  ["cli.mjs", cli],
  ["root-delegation.mjs", rootDelegation],
  ["update-signing.mjs", updateSigning],
  ["update-notes.mjs", updateNotes],
  ["repo-rules.mjs", repoRules],
];

// The modules that carry no tests, and are imported by the ones that do.
const FIXTURE_MODULES = ["harness.mjs", "fixtures.mjs", "update-fixtures.mjs"];

// A module nobody imports is a silent loss of tests, and one file made that
// impossible. Neither the count on the last line nor a green PASS can see it: a
// suite that runs fourteen of fifteen modules says PASS and says it about less.
//
// So the directory and the import list are compared as SETS, and the check fails
// in both directions — a module added and not imported, and a module imported
// twice, which would print its names again. Watched failing both ways before it
// was committed, the way bot/lib/policy.mjs's 26 exports were.
//
// Not a test(): this commit's proof is that the 165 names came back identical,
// and a sixteenth name would spend that proof.
function checkModuleSet() {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "selftest");
  const onDisk = fs.readdirSync(dir).filter((n) => n.endsWith(".mjs")).sort();
  const names = MODULES.map(([n]) => n);
  const duplicated = names.filter((n, i) => names.indexOf(n) !== i);
  const imported = [...new Set([...names, ...FIXTURE_MODULES])].sort();
  const missing = onDisk.filter((n) => !imported.includes(n));
  const phantom = imported.filter((n) => !onDisk.includes(n));
  const problems = [];
  // A floor on the WALK, because everything below it compares two lists and two
  // empty lists agree. If the readdir stops finding anything — the directory
  // renamed, the `.mjs` filter outlived the extension, this file executed from
  // somewhere its own dirname does not resolve from — `missing` is empty and the
  // check reads as a clean bill of health. `phantom` happens to catch the empty
  // walk today, but only because the import list is not empty, and that is a
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
  if (duplicated.length) problems.push(`imported twice, so its names print twice: ${duplicated.join(", ")}`);
  if (missing.length) problems.push(`in tools/selftest/ and never imported, so its tests do not run: ${missing.join(", ")}`);
  if (phantom.length) problems.push(`imported and not in tools/selftest/: ${phantom.join(", ")}`);
  if (problems.length) {
    console.log(`\nFAIL  the suite does not run what tools/selftest/ holds`);
    for (const p of problems) console.log(`      - ${p}`);
    process.exit(1);
  }
}

// Two ways the suite gets smaller that checkModuleSet cannot see, because in
// both of them the directory and the import list still agree with each other:
//
//   - a module that is imported, and runs, and tests nothing — a rewrite that
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
// 166 on 2026-09-19: the 165 this split was proved against, plus the interlock
// test added with these guards. Measured, not estimated —
// `node tools/selftest.mjs | grep -c '^  ok'`.
const TEST_FLOOR = 166;

function shrinkage(silentModules, total) {
  const out = [];
  if (silentModules.length) {
    out.push(
      `${silentModules.join(", ")} reported no test at all — imported, so the module set is intact, and empty`,
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

checkModuleSet();

const reported = () => {
  const r = results();
  return r.passed + r.failures.length;
};

const silent = [];
for (const [name, mod] of MODULES) {
  const before = reported();
  await mod.run();
  if (reported() === before) silent.push(name);
}

cleanupTmp();

const { passed, failures } = results();
const shortfalls = shrinkage(silent, passed + failures.length);
console.log(`\n${failures.length === 0 && shortfalls.length === 0 ? "PASS" : "FAIL"}  ${passed} passed, ${failures.length} failed`);
for (const f of failures) console.log(`      - ${f}`);
for (const s of shortfalls) console.log(`      - the suite is smaller than it was: ${s}`);
if (failures.length || shortfalls.length) process.exit(1);
