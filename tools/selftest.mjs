#!/usr/bin/env node
// The registry's own test suite. `node tools/selftest.mjs`, no network, no
// dependencies.
//
// Two flags, neither of which changes what is asserted:
//   --lanes    print the derived table of every place that runs this suite
//   --census   print the per-module floors below, ready to paste
//
// And one that changes what can be ASKED, and nothing a check decides:
//   --loads    relaunch this runner under tools/selftest/loads/hook.mjs, which
//              records every module each node process of the run loads, so the
//              last module, tools/selftest/loads.mjs, can hold the ones outside
//              TRUST-31's set to its declared residual (ops couplings entry
//              116). Without it those checks say NOT ASKED. The bot's gates run
//              this file without it; `--lanes` shows which lanes ask them.
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

import { REPO_ROOT } from "./lib/sources.mjs";
import { isShallow } from "./coverage/git.mjs";
import { cleanupTmp, drain, registeredCount, results, walkRepo } from "./selftest/harness.mjs";
import { NODE_FLOOR, RELAUNCHED, loadsState, loadsUnrecorded, relaunchUnderHook } from "./selftest/loads/record.mjs";

const ARGS = process.argv.slice(2);
const WANT_LANES = ARGS.includes("--lanes");
const WANT_CENSUS = ARGS.includes("--census");
{
  const unknown = ARGS.filter((a) => a !== "--lanes" && a !== "--census" && a !== "--loads");
  if (unknown.length) {
    // Exit 1, not 2. Two is reserved for the `EXIT-2` flip at the bottom of this
    // file — the day NOT ASKED becomes fatal — and a typo'd flag must not be
    // able to spell that.
    cleanupTmp();
    console.error(`tools/selftest.mjs: unknown argument(s): ${unknown.join(", ")}`);
    console.error("usage: node tools/selftest.mjs [--lanes] [--census] [--loads]");
    process.exit(1);
  }
}

// `--loads`: the whole run again, in a child preloaded with the recorder, with
// this process's exit status. Here, before anything is asked, because a module
// loaded before the recorder is a module the record cannot hold — which is
// also why the relaunch and not this process is the run. Once: the child
// carries the recorder's state (or RELAUNCHED, if the recorder never ran in
// it), and a child that cannot record says NOT ASKED rather than relaunching.
if (ARGS.includes("--loads") && !loadsState() && !process.env[RELAUNCHED]) {
  cleanupTmp();
  process.exit(relaunchUnderHook(fileURLToPath(import.meta.url), ARGS));
}

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
  // RC-R2-5, and third in the same line of thought: signer.mjs asks what the
  // signer DECIDES, signer-run.mjs what it DOES, and this one asks whether the
  // documents it produced for ROLL-60's rehearsal — the ones a staging service
  // and a debug daemon will accept or refuse a key rotation on the strength of
  // — still verify the way that service will judge them. It prints its own
  // section header, and served-set.mjs below prints its own six, so inserting
  // here moves no existing name under a header it does not belong to.
  //
  // **This line and tools/selftest/rehearsal-r2.mjs are one change.**
  // `checkModuleSet` below compares the list and the directory as SETS and
  // fails in both directions, so the file without the line, or the line without
  // the file, turns the whole suite red — and bot/publish-apply.mjs runs this
  // suite as the last of five checks before it commits.
  "rehearsal-r2.mjs",
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
  // Gap 48, and the third module in the same line of thought. root-delegation
  // asks whether the ceremony refuses a key that is not a published root;
  // roots.mjs asks whether the published roots are still the compiled set;
  // this one asks the question neither of them does — whether the DOCUMENT
  // those keys exist to sign still verifies under them. Nothing in the suite
  // asked it: a bit flipped in the root signature of registry/v1/trust.json
  // left this file printing `300 passed, 0 failed`, exit 0, with a transcript
  // byte-identical to the sound tree's.
  //
  // It prints its own section header, and update-signing.mjs below it prints
  // its own, so inserting here moves no existing name under a header it does
  // not belong to.
  //
  // **This line and tools/selftest/trust-anchor.mjs are ONE change and cannot
  // be split across two commits**, for the reason written out at
  // rehearsal-r2.mjs above: `checkModuleSet` compares this list and the
  // directory as SETS and fails in both directions, and FLOORS below is
  // compared with this list the same way. Any one of the three alone is a red
  // `node tools/selftest.mjs` in every lane `laneSites()` reports as LIVE.
  "trust-anchor.mjs",
  "update-signing.mjs",
  "update-notes.mjs",
  "repo-rules.mjs",
  // After `repo-rules.mjs` rather than before it, and with a section header
  // of its own. `repo-rules.mjs` has no header, so its names print under
  // `update-notes.mjs`'s — inserting ABOVE it would move them under this
  // module's header instead. Inserting below moves nothing, and `baseline.mjs`
  // stays after it.
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
  // every lane `laneSites()` below reports as LIVE — so splitting the change
  // does not stage it, it schedules an outage and only chooses which side of
  // the merge gets it. (This sentence used to name four workflows. Three of
  // them could not run the suite on the day it was written, and nothing
  // re-asked; `node tools/selftest.mjs --lanes` is the list now.) The two-way
  // check is right and is not the thing to relax; what it means is that
  // whoever owns this list and whoever writes a module have to arrive in the
  // same commit. Written here because the instruction to leave the line to
  // its owner assumed it was separable, and for this file it is not.
  "regenerate.mjs",
  // Contract 0.31.0 — MIG-13's marker and the schema B.4's types let this
  // repository write for it, held to the token file's condition. It prints its
  // own section header, so inserting it after `regenerate.mjs`, which prints
  // one too, moves no existing name under a header it does not belong to, and
  // `baseline.mjs` stays after it. **This line, its FLOORS entry and the file are
  // one change**, for the reason written out at `regenerate.mjs` above.
  "migration-notice.mjs",
  // Contract 0.34.0 — §0.7's time, one statement in every reader: the grammar
  // in tools/lib/time.mjs, every schema pattern held to it byte for byte, every
  // code reader driven with second 60, and no private spelling. It prints its
  // own section header and sits between two modules that print theirs, so it
  // moves no existing name under a header it does not belong to, and
  // `baseline.mjs` stays after it. **This line, its FLOORS entry and the file are
  // one change**, for the reason written out at `regenerate.mjs` above.
  "times.mjs",
  // Ops gap 22 — the repository settings held to `policy/settings-expected.json`
  // and to the workflows, with fixtures: the comparison the coverage canary runs
  // against GitHub every fifteen minutes, watched red here clause by clause with
  // no network. It prints its own section header and sits between two modules
  // that print theirs, so it moves no existing name under a header it does not
  // belong to, and `baseline.mjs` stays after it. **This line, its FLOORS entry and
  // the file are one change**, for the reason written out at `regenerate.mjs`.
  "settings.mjs",
  // Last until `loads.mjs` below, and with a section header of its own. The
  // boundary to protect is `update-notes.mjs` → `repo-rules.mjs`:
  // `repo-rules.mjs` prints no header, so its names come out under
  // `update-notes.mjs`'s, and anything inserted between that pair would take
  // them. Appending after a module that prints its own header moves nothing at
  // all.
  "baseline.mjs",
  // Ops couplings entry 116 — the modules this run loaded, held to TRUST-31's
  // set and to the residual declared beside the checks. LAST, and it has to
  // be: it reads what the whole run loaded, children included, so every module
  // before it has run and none after it could be seen. It prints its own
  // section header after `baseline.mjs`, which prints one, so it moves no
  // existing name. **This line, its FLOORS entry and the file are one
  // change**, for the reason written out at `regenerate.mjs` above.
  "loads.mjs",
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

// ─────────────────────────────────────────────────────────────────────────────
// WHICH LANES REACH THIS SUITE. Derived, because the sentence was wrong.
//
// This block replaces four words. The comment above used to name
// *build-index.yml, ingest.yml, plugins-moderation.yml and baseline.yml* as the
// lanes that run this file, and on 2026-09-22 that was true of the YAML and
// false of the runner: two of the four sat behind steps that exit 1 before the
// suite is reached, one runs only on `workflow_dispatch`, and the line number
// quoted for the fourth had already moved. It was gap 28's shape one level up —
// a claim in a comment that nothing re-asks — so correcting the sentence would
// only have bought until the next workflow edit.
//
// Nothing is written down here now. `laneSites()` reads `.github/workflows/`
// through the same tracked-file walk every other repository rule uses, and
// reports every place that runs this suite and what gates it.
// `node tools/selftest.mjs --lanes` prints the table; every ordinary run prints
// the one-line count beside the totals, so the claim is a measurement taken at
// the moment somebody reads it.
//
// WHAT IS DERIVED, AND WHAT IS DELIBERATELY NOT.
//
//   SITES are exact: a step whose `run:` invokes this file, plus a step that
//     invokes a script that invokes this file. The indirection is VERIFIED by
//     reading that script rather than assumed, so `bot/publish-apply.mjs`'s two
//     lanes stop being counted on the day it stops running the suite — which is
//     the whole difference between this and a list.
//   DEAD is exact and syntactic: an earlier step in the same job whose script
//     always exits non-zero, with the later step either ungated (GitHub skips
//     it) or gated on that step having succeeded (GitHub runs it and the
//     condition is false). Both stubbed lanes in this repository are that shape.
//   DISPATCH-ONLY is exact: a workflow with no trigger but a dispatch, or a job
//     pinned to `github.event_name == 'workflow_dispatch'`.
//
//   The word "unconditional" is NOT derived, and that is the honest part. A
//     job's `if:` is a GitHub expression over an event this scan does not have,
//     so the gates are PRINTED rather than collapsed into a word somebody chose.
//     A reader who needs to know whether a lane fires on a given event reads the
//     condition, which is the thing that decides.
//
// THE ASSERTION is the one that needs no expression evaluated: at least one site
// is neither dead nor dispatch-only. Zero is the outage this file cannot see
// from the inside — the suite goes on passing and stops being run — and it is
// exactly the direction the four-name sentence was drifting in, one lane at a
// time. Plus a floor on the walk, for the reason `checkModuleSet` has one: a
// scan that finds no workflows agrees with every claim made about them.
const SUITE_REL = path.relative(REPO_ROOT, fileURLToPath(import.meta.url)).split(path.sep).join("/");

/** Tracked path, forward slashes, for a file the walk returned. */
const relOf = (abs) => path.relative(REPO_ROOT, abs).split(path.sep).join("/");

/**
 * The value of a `key:` line, including a block scalar's continuation.
 *
 * Not a YAML parser and not pretending to be one: it reads the subset GitHub
 * workflow files are written in — two-space indentation, `key: value`, `key: |`
 * and `key: >-`. Anything it cannot read comes out as an empty string, which
 * makes a gate INVISIBLE rather than false, so the failure direction is a lane
 * reported as live when it is gated — loud — rather than a gated lane reported
 * as absent.
 */
const indentOf = (line) => line.length - line.replace(/^ */, "").length;
const isKeyLine = (line) => /^\s*[\w-]+:/.test(line) && !line.trim().startsWith("#");

function scalarAt(lines, i, indent) {
  const m = /^\s*[\w-]+:\s*(.*)$/.exec(lines[i]);
  if (!m) return "";
  const head = m[1].trim();
  if (head && head !== "|" && head !== ">" && head !== ">-" && head !== "|-") return head;
  const out = [];
  for (let j = i + 1; j < lines.length; j++) {
    const line = lines[j];
    if (!line.trim()) { out.push(""); continue; }
    if (indentOf(line) <= indent) break;
    out.push(line.slice(indent + 2));
  }
  return out.join("\n").trim();
}

/**
 * A `with:` block's inputs, one level down: `key: value`, the trailing comment
 * and the quotes taken off. A value this cannot read comes out as whatever text
 * is there, so `fetch-depth: ${{ inputs.depth }}` is not `0` — the direction
 * gap 75's reader needs, where anything unproven reads as shallow.
 */
function mappingAt(lines, i, indent) {
  const out = {};
  for (let j = i + 1; j < lines.length; j++) {
    const line = lines[j];
    if (!line.trim() || /^\s*#/.test(line)) continue;
    if (indentOf(line) <= indent) break;
    if (indentOf(line) !== indent + 2 || !isKeyLine(line)) continue;
    const m = /^\s*([\w-]+):\s*(.*)$/.exec(line);
    out[m[1]] = unquote(m[2].replace(/\s+#.*$/, "").trim());
  }
  return out;
}

/** `{ triggers, jobs: [{ name, if, steps: [{ name, id, if, run, uses, with, line }] }] }` */
function parseWorkflow(text) {
  const lines = text.split("\n");
  const triggers = [];
  const jobs = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (indentOf(line) !== 0 || !isKeyLine(line)) continue;
    const key = /^([\w-]+):/.exec(line.trim())?.[1];
    if (key === "on") {
      const inline = /^on:\s*\[(.*)\]\s*$/.exec(line.trim());
      if (inline) { triggers.push(...inline[1].split(",").map((s) => s.trim()).filter(Boolean)); continue; }
      for (let j = i + 1; j < lines.length && (indentOf(lines[j]) > 0 || !lines[j].trim()); j++) {
        if (indentOf(lines[j]) === 2 && isKeyLine(lines[j])) triggers.push(/^([\w-]+):/.exec(lines[j].trim())[1]);
      }
    } else if (key === "jobs") {
      for (let j = i + 1; j < lines.length && (indentOf(lines[j]) > 0 || !lines[j].trim()); j++) {
        if (indentOf(lines[j]) !== 2 || !isKeyLine(lines[j])) continue;
        jobs.push({ name: /^([\w-]+):/.exec(lines[j].trim())[1], start: j, if: "", steps: [] });
      }
    }
  }
  for (let k = 0; k < jobs.length; k++) {
    const job = jobs[k];
    const end = k + 1 < jobs.length ? jobs[k + 1].start : lines.length;
    for (let j = job.start + 1; j < end; j++) {
      const line = lines[j];
      if (indentOf(line) !== 4 || !isKeyLine(line)) continue;
      const key = /^([\w-]+):/.exec(line.trim())[1];
      if (key === "if") job.if = scalarAt(lines, j, 4).replace(/\s+/g, " ");
      if (key !== "steps") continue;
      // Step items, at whatever indent this file writes a `- ` at.
      let itemIndent = -1;
      for (let s = j + 1; s < end; s++) {
        const sl = lines[s];
        if (!sl.trim()) continue;
        if (itemIndent < 0 && /^\s*- /.test(sl)) itemIndent = indentOf(sl);
        if (itemIndent < 0) continue;
        if (indentOf(sl) < itemIndent && sl.trim()) break;
        if (indentOf(sl) !== itemIndent || !/^\s*- /.test(sl)) continue;
        job.steps.push({ start: s, name: "", id: "", if: "", run: "", uses: "", with: {}, line: s + 1 });
      }
      const keyIndent = itemIndent + 2;
      for (let t = 0; t < job.steps.length; t++) {
        const step = job.steps[t];
        const stepEnd = t + 1 < job.steps.length ? job.steps[t + 1].start : end;
        // The first key rides on the `- ` line; normalise it into place.
        const body = [lines[step.start].replace(/^(\s*)- /, "$1  "), ...lines.slice(step.start + 1, stepEnd)];
        for (let b = 0; b < body.length; b++) {
          if (indentOf(body[b]) !== keyIndent || !isKeyLine(body[b])) continue;
          const key2 = /^([\w-]+):/.exec(body[b].trim())[1];
          if (key2 === "name" || key2 === "id" || key2 === "if" || key2 === "run") {
            step[key2] = scalarAt(body, b, keyIndent);
            if (key2 === "if") step.if = step.if.replace(/\s+/g, " ");
          }
          // Gap 75 reads a checkout's `fetch-depth`, so the action and its inputs.
          if (key2 === "uses") step.uses = unquote(scalarAt(body, b, keyIndent).replace(/\s+#.*$/, ""));
          if (key2 === "with") step.with = mappingAt(body, b, keyIndent);
        }
      }
    }
  }
  return { triggers, jobs };
}

/**
 * A script that cannot succeed. `set -euo pipefail`, an `::error::` line and
 * `exit 1` is how this repository writes a step that is not built yet, and it is
 * the shape that made two of the four named lanes unable to reach this suite.
 *
 * Conservative in the direction that matters: any branching keyword at all
 * (`fi`, `else`, `esac`, `done`) and the answer is no, because then the exit is
 * reachable-but-not-certain and calling the lane dead would understate it.
 */
function alwaysFails(run) {
  const body = run.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (!body.length) return false;
  if (body.some((l) => /^(fi|else|elif\b|esac|done)/.test(l))) return false;
  return /^exit\s+[1-9]\d*$/.test(body[body.length - 1]);
}

const DISPATCH_TRIGGERS = new Set(["workflow_dispatch", "repository_dispatch"]);

/**
 * A shell script that actually runs this path, rather than a script that names
 * it. `node <path>`, with flags allowed between.
 *
 * Written because the first version of this scan matched a substring and found
 * `plugins-ingest.yml`'s stub step, whose `::error::` text explains that
 * `bot/publish-apply.mjs` will apply the commit — a sentence, reported as a
 * lane.
 */
const invokes = (script, run) =>
  new RegExp(`(?:^|[\\n;&|(]\\s*|\\s)node\\s+(?:--[\\w=-]+\\s+)*${script.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=$|[\\s\\\\;&|)])`)
    .test(shellCode(run));

/**
 * A step's script with its prose taken out: shell comments, and the inside of
 * every quoted string.
 *
 * This repository writes `echo "::error::…"` in the steps that are not built
 * yet, and those sentences quote the commands the step will one day run.
 * Watched, on this tree: a step whose whole body was `echo "::error::not built:
 * one day this runs node tools/selftest.mjs before it commits"` and `exit 1`
 * was reported as a fourth LIVE lane. A phantom lane is the dangerous
 * direction — it is a lane the assertion below counts, so it would hold the
 * count above zero on the day the real ones died.
 *
 * Nothing real is lost: a command this repository actually runs is never inside
 * quotes.
 */
const shellCode = (run) => run
  .split("\n")
  .map((l) => l.replace(/\s#.*$/, ""))
  .join("\n")
  .replace(/'[^']*'/g, "''")
  .replace(/"[^"]*"/g, '""');

/**
 * A module's code with its comments taken out, well enough for a path literal.
 *
 * The same finding `bot/tests/code-paths.test.mjs` records about its own scan,
 * arrived at the same way: without this, `bot/tests/code-paths.test.mjs` was
 * itself reported as a script that runs this suite, on the strength of a
 * COMMENT quoting the call `bot/publish-apply.mjs` makes. It ran nothing, and it
 * put a phantom LIVE lane into the table the assertion below counts.
 */
const stripComments = (text) => text
  .split("\n")
  .filter((l) => !/^\s*(\/\/|\/\*|\*)/.test(l))
  .map((l) => l.replace(/\s\/\/.*$/, ""))
  .join("\n");

/** YAML's quotes are not part of the name a reader sees in the run log. */
const unquote = (s) => s.replace(/^"(.*)"$/s, "$1").replace(/^'(.*)'$/s, "$1");

// ─────────────────────────────────────────────────────────────────────────────
// GAP 41. A LANE HAS AN ENVIRONMENT, AND FOR ONE CHECK THE ENVIRONMENT IS THE
// CHECK.
//
// `tools/selftest/signer.mjs`'s ``with no sibling checkout the catalogue gate
// RECORDS the checks it could not run`` can only be asked where
// `../AstraPlugins` does not exist. It is not a check that could be written
// hermetically and was not: `validateForSigning` DELETES `$ASTRA_PLUGINS_DIR`
// on purpose — the signer must read the real environment, because a signer that
// can be pointed at a checkout is a signer that can be pointed at the wrong one
// — so the only way the gate sees a `NOT verified` note is for there to be no
// checkout. With a sibling present the check's premise is environmentally
// false, and it says `NOT ASKED` rather than `ok`.
//
// It is asked today only because every LIVE lane happens to run before any
// AstraPlugins checkout exists. **Nothing said so, and it is one step-reorder
// away from being true nowhere.** Move `build-index.yml`'s sibling fetch above
// its selftest step — a reasonable thing to want, and for a year the obvious
// way to give C19's absent case teeth in CI — and that half goes `NOT ASKED` in
// every environment that runs without a human, with the suite still green and
// the count still printed. That is the same shape as gap 42: a property of the
// lanes that only a sentence held.
//
// WHAT IS DERIVED. Whether anything in a job, BEFORE the step that runs this
// suite, so much as names an AstraPlugins checkout. Not whether it creates one:
// that would be a claim about shell semantics this scan cannot evaluate, and
// the word `unconditional` is left underived above for exactly that reason.
//
// THE DIRECTION OF THE UNCERTAINTY IS THE DESIGN. A mention that turns out to
// be harmless makes a lane UNPROVEN and can turn this red — loud, and fixed by
// moving one step. A creation this scan failed to recognise would make a lane
// look sibling-free when it is not, which is silent, and is the failure the
// whole entry is about. So the needle is the widest one that separates them:
// the directory name, and the override. Quoted strings are NOT stripped here,
// unlike `shellCode()` above — there the risk was a phantom lane and prose had
// to go; here the risk is a missed checkout, and `ln -s "$X" "$Y/../AstraPlugins"`
// is a real step written entirely inside quotes.
//
// Comment lines and `name:` values are the two places this repository puts
// prose systematically, and they are the two things taken out.
//
// WHAT IT DOES NOT READ, said rather than left to be discovered: the SCRIPTS an
// earlier step runs. `laneSites()` above follows one indirection because it had
// to — `bot/publish-apply.mjs` is where two of the six sites live — and this
// deliberately does not follow any. Measured before choosing: following them
// turns `ingest.yml`'s `selftest` lane UNPROVEN today (it was line 745 when this was
// measured), because `bot/manifest-probe/link-deps.sh`
// names AstraPlugins on eight lines. It does not create a sibling — it clones
// into `bot/manifest-probe/_deps/AstraPlugins`, inside the checkout, and its one
// mention of `$here/../../../AstraPlugins` READS a developer's existing one — so
// that red would be false, on a correct tree, in the lane that runs on every
// submission. A guard that is red on a correct tree is a guard somebody deletes.
//
// So the uncovered case is a step that runs a script that creates
// `../AstraPlugins`. Nothing in this repository does, and if something ever
// should, it would be written in the workflow, because putting a checkout
// beside the workspace is a `path:` or an `ln -s` and this estate writes those
// in the YAML. That is a judgement about how the failure arrives rather than a
// proof that it cannot, and it is here so that the next reader can disagree with
// it in one place.
const SIBLING_MENTION = /AstraPlugins|ASTRA_PLUGINS_DIR/;

function siblingMentionBefore(lines, from, to) {
  for (let i = from; i < to; i++) {
    const line = lines[i];
    if (/^\s*#/.test(line)) continue;
    const bare = line.replace(/\s#.*$/, "");
    if (/^\s*(- )?name:/.test(bare)) continue;
    if (SIBLING_MENTION.test(bare)) return { line: i + 1, text: line.trim().slice(0, 90) };
  }
  return null;
}

/**
 * The checks in this suite whose askability is gated on the sibling's ABSENCE,
 * found by reading them.
 *
 * Derived, because the failure below has to name which half goes unasked and a
 * name written down here is the kind of claim gap 42 was recorded for.
 *
 * **Read by the gate's CONDITION since gap 106, not by proximity.** This used
 * to count any `neverAsk(` within twenty lines of the string `../AstraPlugins`,
 * and measured on 2026-09-22 that counted signer.mjs's check with its
 * `neverAsk(` moved into the `else` — where it says NOT ASKED in every lane
 * that has NO sibling, which is every lane there is — and the suite printed
 * `INCOMPLETE … 2 not asked` and exited 0, with a NOT ASKED reason claiming a
 * sibling that did not exist. A check qualifies now when its `neverAsk(` opens
 * the block of an `if` whose whole condition asks whether the sibling exists
 * (`asksSibling` below), which is `historyGatedChecks`' rule one environment
 * over.
 */
function siblingGatedChecks(sites) {
  return sites.filter((s) => s.env === "sibling").map(siteLabel);
}

// ─────────────────────────────────────────────────────────────────────────────
// GAP 75. THE SAME SHAPE AS GAP 41, ONE ENVIRONMENT OVER: A CHECK WHOSE PASSING
// CONDITION IS AN ABSENCE IN THE HISTORY HAS A CHECKOUT, AND A SHALLOW CHECKOUT
// HOLDS NO HISTORY TO BE ABSENT FROM.
//
// Measured on 2026-09-22: `tools/selftest/revocations.mjs` asks
// `flagPermanenceProblems` whether the arming flag was ever changed after it
// was added, and in a depth-1 clone of a history that adds it and then edits it
// the suite printed `ok` and exited 0, while a full clone of the same history
// failed naming the edit. `actions/checkout` fetches depth 1 unless told
// otherwise, and `ingest.yml`'s `selftest` job does not tell it — so one of the
// three live lanes was answering "clean" about history it did not hold, and
// the lane table said nothing about checkouts at all.
//
// The guard now reports `notAsked` in a shallow checkout and its check says
// NOT ASKED there — as `update-notes.mjs`'s record-history check already did —
// and what that leaves is gap 41's second sentence again: "a lane with the
// whole history asks it" is a claim about lanes. So it is derived. For every
// site, the last `actions/checkout` of THIS repository before the step (no
// `repository:`, no `path:`) is read for `fetch-depth`, and only a literal
// `0` reads as the whole history.
//
// THE DIRECTION OF THE UNCERTAINTY is the one gap 41 chose. Anything this does
// not recognise — a `fetch-depth` written as an expression, a later `git fetch
// --unshallow`, a checkout inside a composite action — reads as SHALLOW, which
// can only make the count below smaller and the failure louder. A lane read as
// WHOLE when it is shallow is the silent direction, and the only way to get it
// is a literal `fetch-depth: 0` on a checkout of this repository that some
// later step undoes — which is a thing somebody would have to write on purpose.
/**
 * What history a step's checkout holds: the whole of it, or not.
 *
 * @returns {{full: boolean, why: string}}
 */
function historyBefore(job, step) {
  let checkout = null;
  for (const st of job.steps) {
    if (st === step) break;
    if (/^actions\/checkout@/.test(st.uses) && !st.with.repository && !st.with.path) checkout = st;
  }
  if (!checkout) return { full: false, why: "no checkout of this repository before it in this job" };
  const depth = checkout.with["fetch-depth"];
  if (depth === "0") return { full: true, why: `the checkout at line ${checkout.line} sets fetch-depth: 0` };
  return {
    full: false,
    why: depth === undefined
      ? `the checkout at line ${checkout.line} sets no fetch-depth, and actions/checkout fetches 1 commit by default`
      : `the checkout at line ${checkout.line} sets fetch-depth: ${depth}`,
  };
}

/**
 * The checks in this suite that say NOT ASKED in a shallow checkout, found by
 * reading them — `siblingGatedChecks`'s reason, and a tighter read than its.
 * The title is the `test(...)` it sits inside, and the title line is not read
 * for anything else, so a check whose NAME mentions a shallow clone is not
 * counted for that alone.
 *
 * **A gate is counted by its CONDITION, not its shape.** A `neverAsk(` counts
 * when it OPENS the block of an `if` (braced or not) whose condition is, whole,
 * the shallowness question:
 *
 *   - `isShallow(…)` — the helper `tools/coverage/git.mjs` exports;
 *   - `<fn>("rev-parse", "--is-shallow-repository") === "true"` — the question
 *     itself, asked inline;
 *   - `<name>.shallow`, where the same body bound `const <name> = <call>(…)`
 *     before the `if` — the `shallow` a helper returned having asked it, as
 *     `flagPermanenceProblems` does. This one trusts the helper's field to
 *     mean what it is called;
 *   - `<name>`, where the same body bound `const <name> = <either of the two
 *     above, or the third>;` before the `if` — one gate written over two lines.
 *
 * Whole means whole: `!isShallow(…)`, `isShallow(…) && false` and a call in the
 * `else` are not gates on shallowness, and first means first, so nothing is
 * asked about what a block's other statements do. Anything this does not
 * recognise is not counted, which can only lower the count and turn the floor
 * red — the loud direction. And since gap 106 it is not dropped either: a
 * `neverAsk(` this does not read as an environment has to be declared in
 * ASKED_NOWHERE, or the suite is red naming the check.
 *
 * Measured 2026-09-22, gap 81's open item: the census this replaced counted a
 * body in which code named `shallow` anywhere above a `neverAsk(`, so
 * `const shallow = isShallow(REPO_ROOT);` over `if (false) {` left every one of
 * the five gates counted and the floor green — and so did the condition
 * negated, `&& false` added, and the call moved into the `else`. It caught only
 * a one-line `if (false)` and the block deleted. `checkGateCensus` below
 * makes all five edits to every gate this finds, on every run.
 */
function historyGatedChecks(sites) {
  return sites.filter((s) => s.env === "history").map(siteLabel);
}

/** `title — tools/selftest/<module>:<line>`, the form every list of checks here prints. */
function siteLabel(s) {
  return `${s.title || "(no test() encloses it)"} — tools/selftest/${s.module}:${s.line}`;
}

/** The two spellings of the question that need no binding to be read. */
const SHALLOW_QUESTION = [
  /^isShallow\([^()]*\)$/,
  /^[\w$]+\(\s*(["'])rev-parse\1\s*,\s*(["'])--is-shallow-repository\2\s*\)\s*===\s*(["'])true\3$/,
];

/** What the last `const <name> = …;` in `before` binds, as text, or undefined. */
function boundIn(before, name) {
  const re = new RegExp(`\\bconst\\s+${name.replace(/\$/g, "\\$")}\\s*=\\s*([^;]*);`, "g");
  return [...before.matchAll(re)].pop()?.[1]?.trim();
}

/**
 * Is `cond` — an `if`'s whole condition — the shallowness question? `before`
 * is the body's code above the `if`, where a name it reads must be bound.
 */
function asksShallow(cond, before, bindings = 0) {
  const c = cond.trim();
  if (SHALLOW_QUESTION.some((re) => re.test(c))) return true;
  const member = /^([\w$]+)\.shallow$/.exec(c);
  if (member) return /^[\w$.]+\(/.test(boundIn(before, member[1]) ?? "");
  const bare = /^[\w$]+$/.exec(c);
  if (bare && bindings === 0) {
    const bound = boundIn(before, c);
    return bound !== undefined && asksShallow(bound, before, 1);
  }
  return false;
}

/**
 * Is `cond` — an `if`'s whole condition — the sibling question, `does
 * ../AstraPlugins exist`? Gap 106, and `asksShallow`'s rule one environment
 * over: `existsSync(<the path>)` or `fs.existsSync(<the path>)`, where the
 * path is written `path.resolve(REPO_ROOT, "../AstraPlugins")` or is a name
 * the same body bound to exactly that; or a name bound to one of those. The
 * path is the one `ENVIRONMENTS.sibling.here` asks of this run, character for
 * character, so what the scan reads and what the run measures are one question.
 */
const SIBLING_PATH = /^path\.resolve\(\s*REPO_ROOT\s*,\s*(["'])\.\.\/AstraPlugins\1\s*\)$/;

function asksSibling(cond, before, bindings = 0) {
  const c = cond.trim();
  const call = /^(?:fs\.)?existsSync\(\s*([\s\S]*?)\s*\)$/.exec(c);
  if (call) {
    if (SIBLING_PATH.test(call[1])) return true;
    return /^[\w$]+$/.test(call[1]) && SIBLING_PATH.test(boundIn(before, call[1]) ?? "");
  }
  const bare = /^[\w$]+$/.exec(c);
  if (bare && bindings === 0) {
    const bound = boundIn(before, c);
    return bound !== undefined && asksSibling(bound, before, 1);
  }
  return false;
}

/**
 * Is `cond` — an `if`'s whole condition — the load question, `is this run NOT
 * recording the modules it loads`? Ops couplings entry 116, and `asksShallow`'s
 * rule a third time: `loadsUnrecorded()` (tools/selftest/loads/record.mjs),
 * or a name the same body bound to exactly that. The function is the one
 * `ENVIRONMENTS.loads.here` asks of this run.
 */
function asksLoads(cond, before, bindings = 0) {
  const c = cond.trim();
  if (/^loadsUnrecorded\(\s*\)$/.test(c)) return true;
  const bare = /^[\w$]+$/.exec(c);
  if (bare && bindings === 0) {
    const bound = boundIn(before, c);
    return bound !== undefined && asksLoads(bound, before, 1);
  }
  return false;
}

/**
 * Whether a lane's run of this suite records its loads, read the way
 * `historyBefore` reads a checkout: `--loads` on the step's own command line,
 * and a Node that has `module.registerHooks` — the last `actions/setup-node`
 * before the step, its `node-version` read by `nodeHasHooks`. A suite reached
 * through a script reads as not recording: this reads flags only where a step
 * writes them. Anything it cannot read reads as NOT recording, which can only
 * make a lane stop asking and the per-check requirement go red — the loud
 * direction, gap 41's choice.
 *
 * @returns {{recorded: boolean, why: string}}
 */
function loadsBefore(job, step, how) {
  if (how !== "direct") {
    return {
      recorded: false,
      why: `the suite is reached ${how}, and this scan reads \`--loads\` only on a step's own command line`,
    };
  }
  const flagged = new RegExp(
    `(?:^|[\\n;&|(]\\s*|\\s)node\\s+(?:--[\\w=-]+\\s+)*${SUITE_REL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}` +
    "(?:[ \\t]+[^\\s;&|]+)*?[ \\t]+--loads(?=$|[\\s\\\\;&|)])",
  );
  if (!flagged.test(shellCode(step.run))) return { recorded: false, why: "the step runs the suite without `--loads`" };
  let setup = null;
  for (const st of job.steps) {
    if (st === step) break;
    if (/^actions\/setup-node@/.test(st.uses)) setup = st;
  }
  if (!setup) {
    return { recorded: false, why: "`--loads`, and no actions/setup-node before it in its job, so a Node whose version this scan cannot read" };
  }
  const v = setup.with["node-version"];
  if (!nodeHasHooks(v)) {
    return {
      recorded: false,
      why: `\`--loads\`, on the node-version ${JSON.stringify(v ?? null)} the setup-node at line ${setup.line} pins, ` +
        `and module.registerHooks needs ${NODE_FLOOR}`,
    };
  }
  return { recorded: true, why: `\`--loads\`, on the node-version ${v} the setup-node at line ${setup.line} pins` };
}

/**
 * Does a `node-version` input name a Node with `module.registerHooks`? A bare
 * major is the newest release of that line, which `actions/setup-node`
 * resolves it to (`'22'` ran as v22.23.2 in `Registry index` run 35797299924),
 * and every 22 from 22.15.0 has it. Anything this cannot read — `lts/*`, an
 * expression, a file — is no.
 */
function nodeHasHooks(spec) {
  const m = /^v?(\d+)(?:\.(\d+|x))?(?:\.(\d+|x))?$/.exec(String(spec ?? "").trim());
  if (!m) return false;
  const major = Number(m[1]);
  const minor = m[2] === undefined || m[2] === "x" ? Infinity : Number(m[2]);
  if (major >= 24) return true;
  if (major === 23) return minor >= 5;
  if (major === 22) return minor >= 15;
  return false;
}

/**
 * GAP 106. The environments a lane is read for, as one table: for each, the
 * condition a gate asks (`recognise`), whether a lane is one where that
 * condition HOLDS — so the gated checks are NOT ASKED there (`heldIn`), what
 * the lane table read to say so (`read`), and the same condition asked of this
 * run (`here`), which is what lets a run check its own NOT ASKEDs against the
 * scan. A new environment is a new entry here, and nothing else in this file
 * names one.
 */
const ENVIRONMENTS = {
  history: {
    recognise: asksShallow,
    condition: "the checkout is shallow",
    heldIn: (lane) => !lane.history.full,
    read: (lane) => lane.history.why,
    here: () => isShallow(REPO_ROOT),
    remedy:
      "Where it can be asked: a live lane whose checkout of this repository sets `fetch-depth: 0`. Setting it " +
      "on any one of the lanes above is the whole fix. This reads only that checkout's `fetch-depth`, on " +
      "purpose — history that arrives some other way reads as SHALLOW, which is the loud direction — so say it " +
      "in the checkout.",
  },
  sibling: {
    recognise: asksSibling,
    condition: "an AstraPlugins checkout is beside this one",
    heldIn: (lane) => Boolean(lane.sibling),
    read: (lane) => (lane.sibling
      ? `line ${lane.sibling.line} names a checkout: ${lane.sibling.text}`
      : "nothing before it in its job names an AstraPlugins checkout"),
    here: () => fs.existsSync(path.resolve(REPO_ROOT, "../AstraPlugins")),
    remedy:
      "Where it can be asked: a live lane that runs `node tools/selftest.mjs` BEFORE it fetches AstraPlugins. " +
      "Moving the suite above the fetch in any one of the lanes above is the whole fix. If the mention is prose " +
      "rather than a checkout, this scan cannot tell them apart on purpose — the direction it is wrong in is the " +
      "loud one — so move the step or the sentence.",
  },
  // Ops couplings entry 116: the checks that read what a run LOADED, which
  // only a run started with `--loads`, on a Node with `module.registerHooks`,
  // has a record of. The bot's gates run the suite without the flag on
  // purpose: pending item 19 was decided (a) — the modules went into the set,
  // contract 0.38.0 — and running a GATE under the recorder is a separate
  // choice nobody has made, so the lane that asks them is one that is not a gate.
  loads: {
    recognise: asksLoads,
    condition: "the run does not record the modules it loads",
    heldIn: (lane) => !lane.loads.recorded,
    read: (lane) => lane.loads.why,
    here: () => loadsUnrecorded(),
    remedy:
      "Where it can be asked: a live lane that is not one of the bot's gates, whose step runs " +
      "`node tools/selftest.mjs --loads` on a setup-node `node-version` of " + NODE_FLOOR + " or newer — " +
      "build-index.yml's `check` job is the one that did. Putting `--loads` on a gate's run is a decision " +
      "nobody has taken — pending item 19 chose the set, not the gate — and not this file's.",
  },
};

/**
 * The `if` whose block a call at `at` opens, read backwards over `code` no
 * further than `from`: `{ cond, ifAt, condAt, condEnd }` as offsets, or null.
 */
function gateAbove(code, from, at) {
  const head = code.slice(from, at).trimEnd().replace(/\{$/, "").trimEnd();
  if (!head.endsWith(")")) return null;
  let depth = 0;
  let open = head.length - 1;
  for (; open >= 0; open--) {
    if (head[open] === ")") depth++;
    else if (head[open] === "(" && --depth === 0) break;
  }
  if (open < 0) return null;
  const kw = /(^|[^\w$.])if\s*$/.exec(head.slice(0, open));
  if (!kw) return null;
  return {
    cond: head.slice(open + 1, head.length - 1),
    ifAt: from + kw.index + kw[1].length,
    condAt: from + open + 1,
    condEnd: from + head.length - 1,
  };
}

/** The file that defines `neverAsk` and `NeverAsked`, and so the one file whose mentions are not calls. */
const HARNESS = "harness.mjs";

/**
 * A `test(` call's title, as a literal: the quote, the text, the same quote,
 * a comma. Over the whole text rather than a line, so a title whose string
 * starts on the line after `test(` is still read, and with escapes taken in
 * the string's own grammar, so an apostrophe inside a title does not end it.
 */
const TEST_OPENING = /\btest\(\s*(["'`])((?:\\[\s\S]|(?!\1)[^\\])*)\1\s*,/g;

/** Comments blanked to spaces, so offsets and line numbers are the text's own. */
function blankComments(text) {
  return text.split("\n").map((l) => {
    if (/^\s*(\/\/|\/?\*)/.test(l)) return " ".repeat(l.length);
    const c = l.search(/\s\/\/.*$/);
    return c < 0 ? l : l.slice(0, c) + " ".repeat(l.length - c);
  }).join("\n");
}

/**
 * Every `neverAsk(` call in one module's text, and every other mention of it.
 *
 * Gap 106: `{ sites, problems }`. A site is `{ module, line, column, title,
 * cond, when, env, ifAt, condAt, condEnd }`: `title` is the `test(` it sits
 * under; `cond` is the whole condition of the `if` whose block the call OPENS,
 * or null when it opens none; `env` is the entry of ENVIRONMENTS that condition
 * is, or null. `line` and `column` are where V8 reports the call, which is
 * what `NeverAsked` records at run time, so the runner can hold every NOT
 * ASKED it sees to exactly one site read here.
 *
 * A problem is a mention of `neverAsk` that is not a call — an alias, a rename
 * on import, a value passed along — or any mention of `NeverAsked`: each is a
 * way to say NOT ASKED from somewhere this scan does not read, and a NOT ASKED
 * the scan cannot read is one no lane table can account for.
 *
 * Whole condition, first in the block, as `historyGatedChecks` says above:
 * anything this does not recognise gets `env: null`, and a site with no
 * environment must be declared in ASKED_NOWHERE or the suite is red naming it.
 */
function neverAskSitesIn(module, text) {
  const code = blankComments(text);
  const openings = [...code.matchAll(TEST_OPENING)]
    .map((m) => ({ end: m.index + m[0].length, title: m[2].replace(/\\([\s\S])/g, "$1") }));
  const position = (at) => ({
    line: code.slice(0, at).split("\n").length,
    column: at - code.lastIndexOf("\n", at - 1),
  });
  const imports = [...code.matchAll(/\bimport\s*\{([^}]*)\}\s*from\s*(["'])\.\/harness\.mjs\2/g)]
    .map((m) => ({ start: m.index, end: m.index + m[0].length, names: m[1] }));
  const sites = [];
  const problems = [];
  for (const imp of imports) {
    for (const spec of imp.names.split(",").map((s) => s.trim()).filter(Boolean)) {
      if (/^neverAsk\s+as\b/.test(spec)) {
        problems.push(
          `tools/selftest/${module}:${position(imp.start).line} imports \`${spec}\`: a NOT ASKED said under another ` +
          "name is one this scan cannot read, so import `neverAsk` as itself",
        );
      }
    }
  }
  for (const m of code.matchAll(/\b(neverAsk|NeverAsked)\b/g)) {
    const at = m.index;
    const { line, column } = position(at);
    const inImport = imports.some((s) => at >= s.start && at < s.end);
    if (m[1] === "NeverAsked") {
      problems.push(
        `tools/selftest/${module}:${line} names \`NeverAsked\`${inImport ? " in an import" : ""}: only ` +
        "`neverAsk(` may say NOT ASKED, because a call is what this scan reads and classifies",
      );
      continue;
    }
    if (inImport) continue;
    if (!/^neverAsk\s*\(/.test(code.slice(at, at + 40))) {
      problems.push(
        `tools/selftest/${module}:${line} mentions \`neverAsk\` other than by calling it — an alias or a value ` +
        "passed along says NOT ASKED from a place this scan does not read",
      );
      continue;
    }
    const opening = openings.filter((o) => o.end <= at).pop();
    const from = opening ? opening.end : 0;
    const gate = gateAbove(code, from, at);
    const before = gate ? code.slice(from, gate.ifAt) : "";
    const env = gate
      ? Object.keys(ENVIRONMENTS).find((k) => ENVIRONMENTS[k].recognise(gate.cond, before)) ?? null
      : null;
    sites.push({
      module, line, column,
      title: opening ? opening.title : "",
      cond: gate ? gate.cond : null,
      when: gate ? gate.cond.replace(/\s+/g, " ").trim() : null,
      env,
      ...(gate ?? {}),
    });
  }
  return { sites, problems };
}

/** Every `neverAsk(` under tools/selftest/, classified, and every mention that is not a call. */
function neverAskSites() {
  const sites = [];
  const problems = [];
  for (const name of fs.readdirSync(SUITE_DIR).filter((n) => n.endsWith(".mjs") && n !== HARNESS).sort()) {
    let text;
    try { text = fs.readFileSync(path.join(SUITE_DIR, name), "utf8"); } catch { continue; }
    const read = neverAskSitesIn(name, text);
    sites.push(...read.sites);
    problems.push(...read.problems);
  }
  return { sites, problems };
}

/**
 * The census, asked of itself on every run with material from the tree: for
 * each gate it reads as an ENVIRONMENT, four edits that keep the gate's SHAPE
 * and lose its CONDITION must each lose that gate, and the same condition moved
 * onto a line of its own must keep it. Without the second half a census that
 * counted nothing would pass the first.
 *
 * Every environment, since gap 106, not only history: the sibling question is
 * read by `asksSibling` now, and a reader nobody has watched refuse the four
 * edits is the reader the history census was written to replace.
 */
function checkGateCensus() {
  const problems = [];
  for (const name of fs.readdirSync(SUITE_DIR).filter((n) => n.endsWith(".mjs") && n !== HARNESS).sort()) {
    let text;
    try { text = fs.readFileSync(path.join(SUITE_DIR, name), "utf8"); } catch { continue; }
    const all = neverAskSitesIn(name, text).sites;
    for (const g of all.filter((s) => s.env)) {
      const counted = (t) => neverAskSitesIn(name, t).sites.filter((s) => s.env === g.env).length;
      const n = all.filter((s) => s.env === g.env).length;
      const indent = /[ \t]*$/.exec(text.slice(0, g.ifAt))[0];
      const withCond = (c, line = "") =>
        text.slice(0, g.ifAt) + line + text.slice(g.ifAt, g.condAt) + c + text.slice(g.condEnd);
      const lost = {
        "`if (false)`": withCond("false"),
        "`const shallow = <the condition>;` over `if (false)`": withCond("false", `const shallow = ${g.cond};\n${indent}`),
        "the condition negated": withCond(`!(${g.cond})`),
        "`&& false` added to the condition": withCond(`${g.cond} && false`),
        "the call moved into the `else`": text.slice(0, g.condEnd + 1) + " {} else" + text.slice(g.condEnd + 1),
      };
      for (const [edit, mutated] of Object.entries(lost)) {
        if (mutated === text) throw new Error(`the census's edit ${edit} changed nothing in ${name}`);
        if (counted(mutated) !== n - 1) {
          problems.push(`tools/selftest/${name}:${g.line} (${g.title}) is still read as a ${g.env} gate with ${edit}`);
        }
      }
      // A gate already written over two lines is its own proof of this half,
      // and binding it again would ask for a second binding, which is one
      // more than the census follows.
      if (/^[\w$]+$/.test(g.cond.trim())) continue;
      const kept = withCond("askedHere", `const askedHere = ${g.cond};\n${indent}`);
      if (counted(kept) !== n) {
        problems.push(`tools/selftest/${name}:${g.line} (${g.title}) is not read as a ${g.env} gate with its condition bound on the line above`);
      }
    }
  }
  if (problems.length) {
    fail("the gate census does not judge a gate by its condition", [
      ...problems,
      "`neverAskSites` in tools/selftest.mjs is what broke: a gate it reads as an environment must be an `if` " +
      "whose whole condition is that environment's question (`asksShallow`, `asksSibling`), with the `neverAsk(` " +
      "first in its block. Gap 81 measured the census counting all five history gates under " +
      "`const shallow = isShallow(REPO_ROOT);` over `if (false) {`, and the floor green",
    ]);
  }
}

/** Every place in this repository that runs this suite, and what gates it. */
function laneSites() {
  const files = walkRepo().filter((f) => /^\.github\/workflows\/.+\.ya?ml$/.test(relOf(f))).sort();
  // The scripts that run this suite as a subprocess, found by reading them. A
  // name written down here would be the same kind of claim this block exists to
  // delete.
  const needle = new RegExp(`\\[\\s*"${SUITE_REL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`);
  const indirect = [];
  for (const abs of walkRepo()) {
    const rel = relOf(abs);
    if (!rel.endsWith(".mjs") || rel === SUITE_REL || rel.startsWith("tools/selftest/")) continue;
    let text;
    try { text = stripComments(fs.readFileSync(abs, "utf8")); } catch { continue; }
    if (/execFileSync\(\s*process\.execPath/.test(text) && needle.test(text)) indirect.push(rel);
  }
  const sites = [];
  for (const abs of files) {
    const rel = relOf(abs);
    let parsed;
    let lines;
    try {
      const text = fs.readFileSync(abs, "utf8");
      lines = text.split("\n");
      parsed = parseWorkflow(text);
    } catch { continue; }
    const dispatchOnlyWorkflow = parsed.triggers.length > 0
      && parsed.triggers.every((t) => DISPATCH_TRIGGERS.has(t));
    // The workflow's own `env:`, which every job below it inherits.
    let topEnv = null;
    for (let i = 0; i < lines.length && !topEnv; i++) {
      if (indentOf(lines[i]) !== 0 || !isKeyLine(lines[i]) || !/^env:/.test(lines[i].trim())) continue;
      let j = i + 1;
      while (j < lines.length && (!lines[j].trim() || indentOf(lines[j]) > 0)) j++;
      topEnv = siblingMentionBefore(lines, i, j);
    }
    for (const job of parsed.jobs) {
      const stubsBefore = [];
      for (const step of job.steps) {
        const how = invokes(SUITE_REL, step.run) ? "direct"
          : indirect.find((s) => invokes(s, step.run));
        if (how) {
          // Dead if a stub already failed and this step either has no `if:` —
          // GitHub skips it — or has one that asks whether the stub succeeded.
          const dead = stubsBefore.find((stub) => !step.if
            || (stub.id && new RegExp(`steps\\.${stub.id}\\.(conclusion|outcome)\\s*==\\s*'success'`).test(step.if)));
          sites.push({
            workflow: rel,
            job: job.name,
            step: unquote(step.name) || step.run.split("\n")[0].slice(0, 40),
            line: step.line,
            how: how === "direct" ? "direct" : `via ${how}`,
            jobIf: job.if,
            stepIf: step.if,
            dead: dead ? (unquote(dead.name) || `the step at line ${dead.line}`) : "",
            dispatchOnly: dispatchOnlyWorkflow
              || /event_name\s*==\s*'workflow_dispatch'/.test(job.if)
              || /event_name\s*==\s*'workflow_dispatch'/.test(step.if),
            // Gap 41. This job up to this step, plus the workflow's top-level
            // `env:` — a variable set there is in scope for every step under
            // it. Not the whole file from line 0: `ingest.yml` runs this suite
            // in two jobs, and one job's pin step is not in the other job's
            // environment.
            sibling: siblingMentionBefore(lines, job.start, step.start) || topEnv,
            // Gap 75: the history the suite can see at this step.
            history: historyBefore(job, step),
            // Entry 116: whether this step's run records the modules it loads.
            loads: loadsBefore(job, step, how === "direct" ? "direct" : `via ${how}`),
            triggers: parsed.triggers,
          });
        }
        if (alwaysFails(step.run)) stubsBefore.push(step);
      }
    }
  }
  return { files: files.length, indirect, sites };
}

function laneReport(lanes, sites = []) {
  const out = [];
  out.push(`${lanes.sites.length} site(s) run this suite, in ${lanes.files} workflow file(s).`);
  if (lanes.indirect.length) out.push(`  reached indirectly through: ${lanes.indirect.join(", ")}`);
  for (const s of lanes.sites) {
    const state = s.dead ? `DEAD — "${s.dead}" above it always exits non-zero`
      : s.dispatchOnly ? "DISPATCH-ONLY"
      : "LIVE";
    out.push(`  ${state}  ${s.workflow}:${s.line}  job \`${s.job}\`  (${s.how})`);
    out.push(`        step: ${s.step}`);
    out.push(`        on: ${s.triggers.join(", ") || "(none parsed)"}`);
    out.push(`        job if: ${s.jobIf || "—"}`);
    out.push(`        step if: ${s.stepIf || "—"}`);
    out.push(`        sibling: ${s.sibling
      ? `UNPROVEN — line ${s.sibling.line} names one: ${s.sibling.text}`
      : "nothing before this step in this job names an AstraPlugins checkout"}`);
    out.push(`        history: ${s.history.full ? "WHOLE" : "SHALLOW"} — ${s.history.why}`);
    out.push(`        loads: ${s.loads.recorded ? "RECORDED" : "NOT RECORDED"} — ${s.loads.why}`);
    // Per lane, what that costs: the checks that are NOT ASKED here, and why —
    // every environment gate whose environment holds in this lane, and every
    // check declared asked nowhere (gap 106).
    for (const g of sites) {
      if (g.env && ENVIRONMENTS[g.env].heldIn(s)) out.push(`          NOT ASKED here (${g.env}): ${siteLabel(g)}`);
      else if (!g.env && g.declared?.length) out.push(`          NOT ASKED here (declared in ASKED_NOWHERE): ${siteLabel(g)}`);
    }
  }
  // GAP 106: the same, the other way round — per check, which live lanes ask
  // it. Every check not listed has no `neverAsk(` and is asked wherever this
  // suite runs.
  const live = lanes.sites.filter((l) => !l.dead && !l.dispatchOnly);
  const at = (ls) => ls.map((l) => `${l.workflow.replace(".github/workflows/", "")}:${l.line}`).join(", ");
  out.push("");
  out.push(`checks that can say NOT ASKED, and the live lanes that ask each (${sites.length} of them; every other check ` +
    `has no \`neverAsk(\` and is asked in all ${live.length} live lane(s)):`);
  for (const g of sites) {
    const how = g.env ? g.env : g.declared?.length ? "declared" : "UNACCOUNTED";
    out.push(`  [${how}]  ${siteLabel(g)}`);
    out.push(`        gate: ${g.cond === null ? "no `if` opens with this call" : `if (${g.when})`}`);
    if (g.env) {
      const asking = live.filter((l) => !ENVIRONMENTS[g.env].heldIn(l));
      const not = live.filter((l) => ENVIRONMENTS[g.env].heldIn(l));
      out.push(`        asked in ${asking.length} of ${live.length}: ${at(asking) || "none"}` +
        `${not.length ? `; NOT ASKED in: ${at(not)}` : ""}`);
    } else if (g.declared?.length) {
      out.push(`        asked in none of ${live.length}, declared: ${ASKED_NOWHERE[g.declared[0]].arms}`);
    } else {
      out.push(`        asked in none that this file can prove, and not declared — red`);
    }
  }
  return out;
}

// Not a test(), for `checkModuleSet`'s reason: this runs before the first
// module, and a name here would print above the first section header and belong
// to no module.
function checkLanes(lanes) {
  const problems = [];
  // The floor on the walk. 15 workflow files on 2026-09-22 and the floor is 5,
  // for the reason the module walk's floor is 10 rather than 19: deleting a
  // workflow is legitimate, a walk that has stopped working is not, and a number
  // that reddens on an honest deletion is the first number somebody zeroes.
  if (lanes.files < 5) {
    problems.push(
      `the walk of .github/workflows/ found ${lanes.files} file(s) and there were 15 on 2026-09-22; this is a ` +
      `broken walk, not a smaller estate, and every claim below it would have been made about nothing`,
    );
  }
  const live = lanes.sites.filter((s) => !s.dead && !s.dispatchOnly);
  if (!live.length) {
    const stubbed = lanes.sites.filter((s) => s.dead).length;
    const manual = lanes.sites.filter((s) => s.dispatchOnly && !s.dead).length;
    problems.push(
      `no workflow runs this suite any more without a human: of ${lanes.sites.length} site(s) that invoke it, ` +
      `${stubbed} ${stubbed === 1 ? "sits" : "sit"} behind a step that always exits non-zero and ` +
      `${manual} ${manual === 1 ? "runs" : "run"} only on a dispatch. A suite nothing runs goes on passing — ` +
      `run \`node tools/selftest.mjs --lanes\` for the table this was derived from`,
    );
  }
  if (problems.length) fail("nothing reaches this suite on its own any more", problems);
  return live;
}

/**
 * GAP 41's half of the lane question: not *is this suite run*, but *is it run
 * anywhere it can ask the checks whose passing condition is an absence*.
 *
 * `checkLanes` above asserts that at least one site is neither dead nor
 * dispatch-only. That is the outage where the suite goes on passing and stops
 * being run. This is the quieter one a level in: every live lane keeps running
 * it, and one of its checks silently stops being asked anywhere, because the
 * environment it needed went away.
 *
 * Only the ABSENT direction is asserted, and the asymmetry is the point rather
 * than an omission. Its opposite — the half that needed a sibling to be
 * observable at all — was C19's absent case, and it no longer needs one: gap
 * 41's other repair asks `astraPluginsCandidates()` for the LENGTH of its list
 * instead of inferring it from what a fake checkout resolves to, and a length
 * is the same number on both machines. So there is nothing left to assert about
 * a sibling-BEARING lane, and asserting one would mean adding a lane whose only
 * job is a question that no longer has an environment.
 *
 * What is left genuinely does. `validateForSigning` deletes
 * `$ASTRA_PLUGINS_DIR` by design, so the signer reads the real environment and
 * the gate sees a `NOT verified` note only where there is really no checkout.
 * One run cannot be two environments. What one run CAN do is say whether the
 * estate still contains the environment the other half is asked in.
 */
function checkAbsenceEnvironment(live, gated) {
  // The floor on the walk, before the comparison, for the reason
  // `checkModuleSet` and `checkLanes` both have one: a scan that finds nothing
  // agrees with every claim made about it. If nothing under tools/selftest/ is
  // gated on the sibling's absence, then either the pair was retired — and this
  // check is asserting a property of the lanes for nobody — or the scan broke
  // and the sentence below would be being made about an empty set.
  //
  // It is asserted UNCONDITIONALLY and not only on the failure path, which is
  // the difference between a floor and a footnote. Retiring the pair is a
  // legitimate act; what this makes impossible is retiring it and leaving this
  // check behind, green, describing something that is not there.
  if (!gated.length) {
    fail("this check is about a pair that is no longer in tools/selftest/", [
      "nothing under tools/selftest/ says NOT ASKED because `../AstraPlugins` exists, so there is no check " +
      "left whose askability depends on there being no sibling — and `checkAbsenceEnvironment` in " +
      "tools/selftest.mjs exists only to keep a lane in the environment that asks one",
      "If gap 41's pair was retired deliberately, delete that function and the line that calls it, in the SAME " +
      "commit. If it was not, this SCAN is what broke: it reads a `neverAsk(` that opens the block of an `if` " +
      "whose whole condition is `existsSync(path.resolve(REPO_ROOT, \"../AstraPlugins\"))`, or a `const` bound " +
      "to it (`asksSibling`), so a rename of the path, of the call or of `neverAsk` is invisible to it",
    ]);
  }
  // The lanes that ask them. Zero is not a failure HERE any more: since gap
  // 106, `checkAskedSomewhere` fails per check, naming each one and what each
  // lane read, and lets a check declared in ASKED_NOWHERE through — which one
  // failure for the whole set could not do.
  return live.filter((s) => !ENVIRONMENTS.sibling.heldIn(s));
}

// A CENSUS FLOOR on the checks `checkHistoryEnvironment` below is about, where
// `checkAbsenceEnvironment` has only "not empty" — and the difference is
// measured rather than preferred. That set holds one check, so
// "not empty" is the census. This one holds two, from two lanes of work —
// revocations.mjs's flag check and update-notes.mjs's release-record check —
// and deleting the `if (…shallow…) neverAsk(…)` from EITHER put gap 75 back
// for it (`ok` in every shallow lane, about history it cannot see) while
// "not empty" stayed true on the other one, and every FLOORS entry stayed
// met, because a check that stops saying NOT ASKED still reports once.
// A floor and not an equality, for FLOORS' reason: adding one needs no edit
// here; retiring one on purpose needs this number lowered in the same diff.
//
// 5 since gap 81 (2026-09-22), which found three more by diffing a full clone's
// transcript against a depth-1 clone's: catalogue.mjs's equal-serial check,
// contract-tokens.mjs's version check, and the serial half of regenerate.mjs's
// head-catalogue check, which is now a check of its own. Each printed `ok` at
// depth 1 about history it had not asked. Each gate is an `if` whose whole
// condition is the shallowness question, with its `neverAsk(` first in the
// block; `historyGatedChecks` says what counts, and `checkGateCensus` makes
// five edits to every gate that lose its condition and keep its shape, and
// fails unless each one loses the gate. Deleting a gate's block turns this red.
const HISTORY_GATED_FLOOR = 5;
const HISTORY_GATED_DAY = "2026-09-22";

/**
 * GAP 75's half of the lane question, in `checkAbsenceEnvironment`'s shape: not
 * *is this suite run*, but *is it run anywhere that holds the history its
 * history checks are about*. The census floor above is this function's version
 * of that one's floor on the scan; zero lanes fails per check, by name, in
 * `checkAskedSomewhere` (gap 106).
 */
function checkHistoryEnvironment(live, gated) {
  if (gated.length < HISTORY_GATED_FLOOR) {
    fail(
      `${gated.length} check(s) under tools/selftest/ say NOT ASKED in a shallow checkout, and there were ` +
      `${HISTORY_GATED_FLOOR} on ${HISTORY_GATED_DAY}`,
      [
        `found: ${gated.join("; ") || "none"}`,
        "A check that stopped testing for a shallow checkout prints `ok` there again, about history it cannot " +
        "see — gap 75, back — and nothing else in this suite notices, because it still reports once. If one " +
        "was retired deliberately, lower HISTORY_GATED_FLOOR in tools/selftest.mjs in the SAME commit; if every " +
        "one was, delete `checkHistoryEnvironment` and the line that calls it too. If not, this SCAN is what " +
        "broke: it counts a `neverAsk(` that opens the block of an `if` whose whole condition is `isShallow(…)`, " +
        "the `--is-shallow-repository` question, or a `const` bound to one of those in the same body, so a rename " +
        "of the helper or of `neverAsk` is invisible to it",
      ],
    );
  }
  // The lanes that ask them. Zero fails in `checkAskedSomewhere`, per check,
  // for `checkAbsenceEnvironment`'s reason.
  return live.filter((s) => !ENVIRONMENTS.history.heldIn(s));
}

// ─────────────────────────────────────────────────────────────────────────────
// GAP 106. EVERY CHECK IS ASKED IN AT LEAST ONE LIVE LANE, OR SAYS WHY NOT.
//
// Measured 2026-09-22: `node tools/selftest.mjs` prints `INCOMPLETE … N not
// asked` and exits 0, and a check whose `neverAsk(` was moved into an `else`
// gave exit 0 with one more not-asked. The two functions above caught that
// shape for their own two classes — and for signer.mjs's sibling check the
// scan above them read the `neverAsk(` by its distance from a path, so even
// that one stayed green (measured: `INCOMPLETE 357 passed, 0 failed, 2 not
// asked`, exit 0). For any other reason a check was NOT ASKED in every lane,
// nothing was red anywhere, and the only trace was a count nobody reads.
//
// One run cannot see another lane's results, so the requirement is computed
// from what this file already derives without running anything:
//
//   * every `neverAsk(` under tools/selftest/ is READ (`neverAskSites`), and
//     classified by the condition of the `if` whose block it opens: an
//     ENVIRONMENT (the checkout is shallow; AstraPlugins is beside it), or
//     nothing this file can evaluate;
//   * the lane table says, per live lane, whether each environment holds there;
//   * so a check gated on an environment is asked in exactly the live lanes
//     where it does not hold, and **zero such lanes is red, naming the check**;
//   * a check gated on anything else is asked in no lane this file can prove,
//     so it must be DECLARED in ASKED_NOWHERE below — its module, its name,
//     the gate's condition as written, why nothing asks it, and the event that
//     arms it — and **an undeclared one is red, naming the check**.
//
// That covers every check, not only the gated ones, for one reason: a check
// with no `neverAsk(` in it cannot say NOT ASKED, because `checkNotAskedAccounting`
// below holds every NOT ASKED a run actually says to a site read here — an
// alias, a helper outside the suite or a bare `throw new NeverAsked` is red.
//
// WHAT IT DOES NOT SEE, said here so it is not found later. A check that skips
// its assertion WITHOUT `neverAsk` — `if (…) return;` and `ok` — is not NOT
// ASKED, it is VACUOUS, and it prints `ok`; nothing in this file can tell that
// from a pass. And a declared gate is pinned by its condition's TEXT, not by
// what its operands mean: `const here = undefined;` above `if (!here)` keeps
// the declaration matched and the check unasked. The first is a different
// class, and the second is the price of a declaration being data.

/**
 * Checks that no live lane asks, each with the reason and the event that ends
 * it. A declaration is itself checked, the way SCHEMA_ABSENCES and the privacy
 * scan's exemptions are: an unknown key, a `why` or `arms` that is not a
 * sentence, a declaration that matches no `neverAsk(`, and one that covers a
 * check some live lane already asks are all red.
 *
 * `when` is the whole condition of the `if` whose block the `neverAsk(` opens,
 * as written (whitespace aside). It is what makes a declaration a declaration
 * of THIS gate rather than of the check's name: move the call into the `else`,
 * or add `|| true`, and the declaration stops matching — so the site is red as
 * undeclared AND the declaration is red as matching nothing, both by name.
 *
 * A declared check that IS asked in a run is a note under the totals and not a
 * red, and that is decided rather than defaulted. The one entry below arms
 * itself on M-T2.2's publish commit, and `bot/publish-apply.mjs` runs this
 * suite over that commit's tree before it pushes — so a red for "declared and
 * asked" would refuse the very publication that arms the check, in the lane
 * where a red costs a publication, and the check would never arm. The note
 * says which entry to delete; its gate stays pinned by `when` meanwhile.
 */
const ASKED_NOWHERE = [
  {
    module: "validation.mjs",
    check: "(b) the committed tree's staging listing, if it has one, is unlisted",
    when: "!here",
    why:
      "its subject is the committed staging listing, and no committed tree holds one yet: " +
      "policy/reserved-ids.json reserves `staging_listing_id` and nothing has published it. The rule itself " +
      "is asked in every lane by `(b) a committed staging listing that is not unlisted is refused, and an " +
      "unlisted one is not`, over fixtures",
    arms:
      "M-T2.2 — the bot's first-listing publish commit that adds the staging listing with `unlisted: true`. " +
      "bot/publish-apply.mjs runs this suite over that tree before it pushes, so the check is asked there first " +
      "and in every lane after it, with no edit to the check; then delete this entry",
  },
];

const DECLARATION_KEYS = ["module", "check", "when", "why", "arms"];

/** Words in a string; a floor on a sentence, not a judge of one, as SCHEMA_ABSENCES uses it. */
const words = (s) => (typeof s === "string" ? s.trim().split(/\s+/).filter(Boolean).length : 0);

/**
 * Each site's declarations in ASKED_NOWHERE, as `site.declared` (an array of
 * indexes), and the problems with the declarations themselves.
 */
function matchDeclarations(sites) {
  const problems = [];
  for (const s of sites) s.declared = [];
  ASKED_NOWHERE.forEach((d, i) => {
    const label = `ASKED_NOWHERE[${i}]${typeof d?.check === "string" ? ` (${d.check})` : ""}`;
    if (!d || typeof d !== "object" || Array.isArray(d)) {
      problems.push(`${label} is not a declaration: it must be { ${DECLARATION_KEYS.join(", ")} }`);
      return;
    }
    const unknown = Object.keys(d).filter((k) => !DECLARATION_KEYS.includes(k));
    if (unknown.length) problems.push(`${label} has key(s) no declaration has: ${unknown.join(", ")}`);
    for (const k of ["module", "check", "when"]) {
      if (typeof d[k] !== "string" || !d[k].trim()) problems.push(`${label} names no \`${k}\`, so it cannot be matched to a gate`);
    }
    for (const k of ["why", "arms"]) {
      if (words(d[k]) < 8) {
        problems.push(
          `${label}'s \`${k}\` is ${JSON.stringify(d[k] ?? null)}, and a declaration needs a sentence there — ` +
          `${k === "why" ? "why no lane asks it" : "the event that arms it"}. Below eight words it is a label, and ` +
          "a label is a skip that reads like a reason",
        );
      }
    }
    const when = typeof d.when === "string" ? d.when.replace(/\s+/g, " ").trim() : null;
    const hits = sites.filter((s) => s.module === d.module && s.title === d.check && s.when === when);
    if (!hits.length) {
      const near = sites.filter((s) => s.module === d.module && s.title === d.check);
      problems.push(
        `${label} matches no \`neverAsk(\` under tools/selftest/ — a declaration about nothing. It names ` +
        `tools/selftest/${d.module}, the check ${JSON.stringify(d.check)} and the gate \`if (${d.when})\`` +
        (near.length
          ? `; that check's \`neverAsk(\` is at ${near.map((s) => `line ${s.line}, under ${s.cond === null ? "no `if`" : `\`if (${s.when})\``}`).join(" and ")}. ` +
            "A gate that moved is a gate that changed: if the move is right, the declaration has to be re-read and re-written, not re-pointed"
          : ". If the check was retired or armed, delete the declaration in the same commit"),
      );
    }
    for (const s of hits) s.declared.push(i);
  });
  return problems;
}

/**
 * The requirement: every check that can say NOT ASKED is asked in at least one
 * live lane, or is declared. Fails once, listing every check that is neither,
 * by name, with what each lane read.
 */
function checkAskedSomewhere(live, sites, scanProblems, declarationProblems) {
  const problems = [...scanProblems, ...declarationProblems];
  const lanesAt = (ls) => ls.map((l) => `${l.workflow.replace(".github/workflows/", "")}:${l.line}`).join(", ");
  for (const s of sites) {
    if (!s.title) {
      problems.push(
        `tools/selftest/${s.module}:${s.line} calls \`neverAsk(\` with no \`test(\` above it, so the scan cannot ` +
        "say which check it would leave unasked; call it inside the check it belongs to",
      );
      continue;
    }
    if (s.declared.length > 1) {
      problems.push(`${siteLabel(s)} is declared ${s.declared.length} times in ASKED_NOWHERE (entries ${s.declared.join(", ")})`);
    }
    if (s.env) {
      const env = ENVIRONMENTS[s.env];
      const asking = live.filter((l) => !env.heldIn(l));
      if (asking.length && s.declared.length) {
        problems.push(
          `${siteLabel(s)} is declared in ASKED_NOWHERE and ${asking.length} live lane(s) ask it: ${lanesAt(asking)}. ` +
          "A declaration that outlived its reason is the shelter the next check inherits — delete it in this commit",
        );
      }
      if (!asking.length && !s.declared.length) {
        problems.push([
          `${siteLabel(s)} is NOT ASKED in every live lane: it says NOT ASKED where ${env.condition}, and that ` +
          "holds in each of them —",
          ...live.map((l) => `    ${l.workflow}:${l.line} — ${env.read(l)}`),
          `  ${env.remedy} Or declare it in ASKED_NOWHERE with why and the event that arms it.`,
        ].join("\n      "));
      }
      continue;
    }
    if (s.declared.length) continue;
    problems.push(
      `${siteLabel(s)} says NOT ASKED ` +
      `${s.cond === null ? "with its `neverAsk(` opening no `if`'s block (it opens an `else`, or something comes before it)" : `under \`if (${s.when})\``}, which is no ` +
      `environment a lane is read for (${Object.keys(ENVIRONMENTS).join(", ")}) and is not declared in ASKED_NOWHERE ` +
      "— so no live lane can be shown to ask it, and a check NOT ASKED everywhere is green everywhere. Gate it on " +
      "the environment's own question, first in the block — `if (isShallow(REPO_ROOT))`, " +
      "`if (fs.existsSync(path.resolve(REPO_ROOT, \"../AstraPlugins\")))` — or declare it in ASKED_NOWHERE in " +
      "tools/selftest.mjs with that condition, why no lane asks it, and the event that arms it",
    );
  }
  if (problems.length) {
    fail("a check can be NOT ASKED in every lane that runs this suite, and nothing accounts for it", [
      ...problems,
      "Gap 106. `node tools/selftest.mjs --lanes` prints the check × lane table this was derived from.",
    ]);
  }
}

/**
 * The run's half: every NOT ASKED this run actually said is held to a site the
 * scan read, and every gate whose environment holds in this run is held to
 * having said so. Returns `{ problems, notes }`; a problem is a failure.
 *
 *   - a NOT ASKED from a place the scan did not read — an alias, a helper
 *     outside tools/selftest/, a bare `throw new NeverAsked` — is one no lane
 *     table accounts for;
 *   - every site's check must have reported in this run under the name the
 *     scan read for it, or the table names a check that does not exist — a
 *     `neverAsk(` in a helper below some other test, or a title the scan
 *     cannot read literally;
 *   - an environment gate that said NOT ASKED where its environment does NOT
 *     hold is a gate asking something other than what the scan reads it as
 *     asking (a helper's `shallow` field that lies, say) — and one that said
 *     `ok` where it DOES hold said clean about what it cannot see, gap 75;
 *   - a declared check that was asked is a note: see ASKED_NOWHERE.
 */
function checkNotAskedAccounting(sites, byModule) {
  const problems = [];
  const notes = [];
  const here = new Map(Object.entries(ENVIRONMENTS).map(([k, e]) => [k, e.here()]));
  const siteAt = new Map(sites.map((s) => [`tools/selftest/${s.module}:${s.line}:${s.column}`, s]));
  for (const [module, outs] of byModule) {
    for (const o of outs.filter((x) => x.verdict === "notAsked")) {
      const at = o.site ? `${o.site.file}:${o.site.line}:${o.site.column}` : null;
      const s = at ? siteAt.get(at) : undefined;
      if (!s) {
        problems.push(
          `${o.name} (${module}) said NOT ASKED from ${at ?? "a place its stack does not show"}, which is not a ` +
          "`neverAsk(` call the runner read under tools/selftest/ — so no lane table accounts for it, and it could " +
          "be NOT ASKED in every lane with nothing red. Call `neverAsk(` itself, in the check's own body",
        );
        continue;
      }
      if (s.module !== module || s.title !== o.name) {
        problems.push(
          `${o.name} (${module}) said NOT ASKED from ${at}, which the scan reads as belonging to ` +
          `${JSON.stringify(s.title)} in ${s.module}, so the lane table names the wrong check for it`,
        );
        continue;
      }
      if (s.env && !here.get(s.env)) {
        problems.push(
          `${siteLabel(s)} said NOT ASKED, and its gate is read as \`${ENVIRONMENTS[s.env].condition}\` — which does ` +
          "not hold in this run. The gate is asking something other than that, so the lanes where the table says it " +
          "is asked may not ask it",
        );
      }
    }
  }
  for (const s of sites) {
    const outs = (byModule.get(`${s.module}`) ?? []).filter((o) => o.name === s.title);
    if (!outs.length) {
      problems.push(
        `the scan reads the \`neverAsk(\` at tools/selftest/${s.module}:${s.line} as belonging to ` +
        `${JSON.stringify(s.title)}, and no check by that name reported from ${s.module} in this run — so the ` +
        "check × lane table names a check that is not there. Call `neverAsk(` in the body of the check it belongs " +
        "to, whose name is a plain string literal",
      );
      continue;
    }
    if (s.env && here.get(s.env) && outs.some((o) => o.verdict === "ok")) {
      problems.push(
        `${siteLabel(s)} printed \`ok\` in a run where ${ENVIRONMENTS[s.env].condition}, which its gate says it ` +
        "cannot answer — so it said clean about what this checkout cannot show it (gap 75's shape)",
      );
    }
    // Only a gate on something no lane is read for. A declared ENVIRONMENT
    // gate asked here says only that this machine is not the lanes, and
    // whether a lane asks it is `checkAskedSomewhere`'s question, answered
    // from the workflows before anything ran.
    if (!s.env && s.declared.length && outs.some((o) => o.verdict !== "notAsked")) {
      notes.push(
        `${siteLabel(s)} is declared in ASKED_NOWHERE and was ASKED in this run — the event it waits for ` +
        `(${ASKED_NOWHERE[s.declared[0]].arms.split(" — ")[0]}) has happened here. Delete its entry once it is ` +
        "on main; until then its gate stays pinned by `when`",
      );
    }
  }
  return { problems, notes };
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
//
// NOT ASKED counts as REPORTED here, and only here. The floor below asks
// "did this module say anything at all", and a module whose every check was
// honestly unaskable has said something — it has said so. Leaving it out would
// make the third word trip the emptied-run() guard, which is a different
// failure with a different fix, and the first thing anybody would do about it
// is delete the third word.
const reported = () => {
  const r = results();
  return r.passed + r.failures.length + r.notAsked.length;
};

// ─────────────────────────────────────────────────────────────────────────────
// THE FLOOR OF ONE IS NOT A FLOOR. It is a liveness check wearing a floor's
// clothes, and everything above admits it: "it says nothing about a module that
// kept fourteen tests of eighteen". Measured 2026-09-22 on this tree: delete one
// `await test(...)` from any module and the suite prints `PASS`, one lower, and
// exits 0. The number on the last line is an OUTPUT. Nothing compares it to
// anything, and the direction it moves in is the silent one — nobody opens an
// investigation because a suite reported fewer failures.
//
// So: a pinned floor PER MODULE, at census, asserted as `reported >= floor`.
//
// WHY NOT ONE NUMBER FOR THE SUITE, which is the cheaper repair and the one the
// register recommends. Three reasons, in the order they bite:
//
//   * a suite-wide total is a single number in a single file, so the commit that
//     deletes the check is the commit that edits it down — one line, one diff
//     hunk, no module named. A reviewer sees `301` become `300` beside a diff
//     that removed a test and reads it as bookkeeping, because that is what it
//     looks like. Per module, the same edit says `catalogue.mjs: 31 → 30` and
//     the reviewer is told WHICH subject lost a check, which is the only form of
//     the question anybody can answer;
//   * one number for twenty-four modules is a number every task touches. The
//     comment above records what that cost the last time: two tasks making the
//     IDENTICAL `18` → `19` edit, git auto-merging it as one change, and a
//     merged tree red on a line neither author could have written correctly.
//     That failure is specific to EQUALITY, which forces an edit on growth;
//     a floor forces none. Per module it also gives two deletions in two
//     modules two different lines, so they do not merge into each other at all;
//   * a suite-wide floor cannot survive the one thing this suite does
//     constantly, which is grow. It would have to be re-pinned, by hand, on a
//     shared line, by whoever happened to be last — and the comment above is the
//     record of what happened when it was.
//
// WHY A FLOOR AND NOT AN EQUALITY, since the third attempt above was equality
// per module and it is gone. Equality fires on GROWTH, and growth is the common
// case: ten tasks write into this suite and all of them add. A guard that
// reddens every legitimate addition is deleted within a week, and it would be
// right to delete it. A floor fires only downward. Adding a check needs no edit
// here at all; removing one needs exactly one, in the same diff, naming the
// module.
//
// WHAT THIS BUYS AND WHAT IT DOES NOT. It does not stop anybody deleting a check
// — nothing can, and the register is right that the real control is a reviewer
// seeing the diff. What it does is make the deletion IMPOSSIBLE TO MAKE
// SILENTLY: the number is no longer only an output, so the same commit has to
// say so, in a file whose diff a reviewer is already reading, about a named
// module. And it decays honestly: a floor left at last month's census still
// catches a module losing half its checks, it just stops catching the loss of
// one. `node tools/selftest.mjs --census` prints the block to re-pin it.
//
// NOT ASKED counts as REPORTED here, for the reason it does in the floor of one
// — and it is what makes these numbers the same on a developer's machine and in
// CI. `signer.mjs`'s sibling-checkout check `neverAsk`s where AstraPlugins is
// beside this repository and runs where it is not; either way it reports once.
// A floor on `passed` alone would be 300 here and 299 there, red on one of them,
// and the first fix anybody reached for would be deleting the third word.
const CENSUS_DAY = "2026-09-22";
const FLOORS = new Map(Object.entries({
  // `node tools/selftest.mjs --census` prints this block. MODULES order, so the
  // diff of a re-census is readable and a module's line sits where its entry in
  // the list above does.
  "primitives.mjs": 16,
  "catalogue.mjs": 9,
  "publishers.mjs": 17,
  "validation.mjs": 17,
  "couplings.mjs": 18,
  "listings.mjs": 5,
  "origins.mjs": 5,
  // 8, NOT the 41 this module reports, and it is the one number here that is
  // not its census. 33 of the 41 come from `registerSharedVectorTests` over the
  // VENDORED `tests/vectors/`, one test per vector, refreshed from AstraPlugins
  // by a script in THAT repository. Pinned at 41 the ordinary re-vendor would go
  // red here — naming a file the author never opened, about a number another
  // repository owns — which is precisely the false alarm that killed the
  // per-module EQUALITY guard, reintroduced by the back door. Eight is what this
  // repository writes and can lose. The vendored half is floored where it is
  // owned: `tests/shared-vectors.mjs` asserts `>= 20` three times, in the module
  // whose vectors they are, with a message about vectors.
  "bundles.mjs": 14,
  "index-signature.mjs": 21,
  "signer.mjs": 25,
  "signer-run.mjs": 7,
  "rehearsal-r2.mjs": 14,
  "served-set.mjs": 35,
  "revocations.mjs": 24,
  "cli.mjs": 12,
  "root-delegation.mjs": 6,
  "roots.mjs": 3,
  "trust-anchor.mjs": 4,
  "update-signing.mjs": 12,
  "update-notes.mjs": 9,
  "repo-rules.mjs": 20,
  "claims.mjs": 10,
  "contract-tokens.mjs": 28,
  "regenerate.mjs": 15,
  "migration-notice.mjs": 6,
  "times.mjs": 4,
  "settings.mjs": 13,
  "baseline.mjs": 9,
  "loads.mjs": 2,
}));

// A floor computed from nothing passes every assertion below it — the finding
// `checkModuleSet`'s walk floor is built on, one level down. An empty or partial
// FLOORS would silently restore the floor of one for every module it forgot, so
// there is no `?? 1` anywhere above: the map is compared with MODULES as SETS,
// in both directions, before any of it is used.
function checkFloors() {
  const problems = [];
  const listed = [...FLOORS.keys()];
  const missing = MODULES.filter((n) => !FLOORS.has(n));
  const phantom = listed.filter((n) => !MODULES.includes(n));
  if (missing.length) {
    problems.push(
      `in the runner's MODULES and carries no floor, so nothing stands under its count: ${missing.join(", ")} ` +
      `— run \`node tools/selftest.mjs --census\` and paste the block`,
    );
  }
  if (phantom.length) {
    problems.push(`carries a floor and is not a module the runner runs: ${phantom.join(", ")}`);
  }
  const unusable = listed.filter((n) => !Number.isInteger(FLOORS.get(n)) || FLOORS.get(n) < 1);
  if (unusable.length) {
    problems.push(
      `has a floor that asserts nothing — it must be a whole number of checks, at least one: ` +
      `${unusable.map((n) => `${n} = ${JSON.stringify(FLOORS.get(n))}`).join(", ")}`,
    );
  }
  if (problems.length) fail("the per-module floors do not describe this suite", problems);
}

await checkModuleSet();

const LANES = laneSites();
// Gap 106: every `neverAsk(` in the suite, read and classified before anything
// runs, so the table below and the requirement after it are about the same set.
const { sites: SITES, problems: SCAN_PROBLEMS } = neverAskSites();
const DECLARATION_PROBLEMS = matchDeclarations(SITES);
const HISTORY_GATED = historyGatedChecks(SITES);
if (WANT_LANES) {
  console.log("\nlanes that reach this suite (derived from .github/workflows/ at this commit)");
  for (const line of laneReport(LANES, SITES)) console.log(line);
  console.log("");
}
const LIVE_LANES = checkLanes(LANES);
// The census first: it proves the reader judges a gate by its condition, and
// everything after it believes the reader's answers.
checkGateCensus();
// Then per check, by name — before the floors below, so a gate that moved is
// named as the check it was rather than counted as one fewer.
checkAskedSomewhere(LIVE_LANES, SITES, SCAN_PROBLEMS, DECLARATION_PROBLEMS);
const ABSENCE_LANES = checkAbsenceEnvironment(LIVE_LANES, siblingGatedChecks(SITES));
const HISTORY_LANES = checkHistoryEnvironment(LIVE_LANES, HISTORY_GATED);

// `--census` is the one run that is allowed past this, because it is the run
// that produces the block. It asserts no floor and prints no PASS.
if (!WANT_CENSUS) checkFloors();

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
const census = new Map();
// Gap 106: each module's verdicts, for `checkNotAskedAccounting` after the last.
const OUTCOMES = new Map();
for (const name of MODULES) {
  const before = reported();
  const outcomesFrom = results().outcomes.length;
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
  census.set(name, ran);
  OUTCOMES.set(name, results().outcomes.slice(outcomesFrom));
  if (ran < 1) {
    shortfalls.push(
      `a module ran and reported nothing: ${name} is in the list, was imported and its run() returned, and it ` +
      `reported no test at all — an emptied run(), an early return, or a loop over a list that is now empty`,
    );
    continue;
  }
  // The floor, below. `checkFloors()` has already refused a missing one, so
  // there is deliberately no default to fall back to.
  const floor = WANT_CENSUS ? 1 : FLOORS.get(name);
  if (ran < floor) {
    shortfalls.push(
      `a module lost ${floor - ran} check(s): ` +
      `${name} reported ${ran} and its floor is ${floor} — ${floor - ran} fewer than the census of ` +
      `${CENSUS_DAY}. A check was deleted, an early \`return\` was added, or a loop over it is now shorter. ` +
      `If the removal is deliberate, lower ${name}'s number in FLOORS in tools/selftest.mjs to ${ran} in the ` +
      `SAME commit; \`node tools/selftest.mjs --census\` prints the block`,
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

if (WANT_CENSUS) {
  console.log("\nper-module floors, as measured by this run. Paste into FLOORS in tools/selftest.mjs,");
  console.log(`and move CENSUS_DAY to today. Was pinned on ${CENSUS_DAY}.\n`);
  for (const name of MODULES) console.log(`  ${JSON.stringify(name)}: ${census.get(name)},`);
  console.log("");
}

const { passed, failures, notAsked } = results();
// Gap 106, the run's half: every NOT ASKED said here held to a site the scan
// read, and every gate whose environment holds here held to having said it.
const ACCOUNTING = checkNotAskedAccounting(SITES, OUTCOMES);
// Three figures, all counted, and two of them now compared to something: every
// module's share is held to the floor pinned above, and the module count is held
// to the pinned list in repo-rules.mjs.
//
// THE HEADLINE WORD IS THE POINT. `passed` no longer absorbs the checks that
// could not be asked, so the number a reader quotes is the number of checks
// that actually measured something. A run with anything unasked cannot print
// `PASS`, because `PASS` is what everybody had been quoting about a suite that
// contained two checks nobody had run.
//
// EXIT CODES. 1 on a failure, a shortfall, or a NOT ASKED nothing accounts
// for; 0 otherwise — including when something was not asked.
// `tools/cutover-preflight.mjs` exits 2 in that case and is right to: it is
// read by an operator before a cutover. This suite is a step in every lane the
// line below reports as LIVE — which is the reason the flip is not free, and
// the count is printed rather than described so that the reason is re-measured
// whenever somebody reads it.
//
// SINCE GAP 106, INCOMPLETE WITH EXIT 0 MEANS ONE THING, and that is the
// argument for keeping it. A NOT ASKED reaches this line only if the run
// before the modules proved some live lane asks that check — its gate is an
// environment the lane table reads, and a live lane lacks it — or ASKED_NOWHERE
// declares it with its gate, why, and the event that arms it; and only if the
// run after them held it to that very gate (`checkNotAskedAccounting`). A NOT
// ASKED that is neither is already exit 1, by name. So exit 0 with a NOT ASKED
// is "not asked HERE, and asked there" or "asked nowhere, on the record" —
// never the count nobody reads. Exit 2 would add nothing a reader can act on
// and would take two things away: `ingest.yml`'s `selftest` job is shallow on
// purpose (gap 75's decision) and would be red on every submission, and every
// lane would be red on a correct tree until M-T2.2 arms the declared check. A
// red that is expected makes every red look expected (gap 73). **To make NOT
// ASKED fatal anyway, change the line marked `EXIT-2` below**; that is the
// operator's decision, not this file's.
const headline = failures.length || shortfalls.length || ACCOUNTING.problems.length ? "FAIL"
  : notAsked.length ? "INCOMPLETE"
  : "PASS";
console.log(
  `\n${headline}  ${passed} passed, ${failures.length} failed, ${notAsked.length} not asked ` +
  `(${MODULES.length} modules)`,
);
// Derived on every run, printed where the numbers are read. The sentence this
// replaced named four workflows and three of them could not run this suite.
console.log(
  `      ${LIVE_LANES.length} of ${LANES.sites.length} lane(s) that run this suite reach it without a human: ` +
  `${LIVE_LANES.map((l) => `${l.workflow.replace(".github/workflows/", "")}:${l.line}`).join(", ") || "none"} ` +
  `— \`node tools/selftest.mjs --lanes\` for the table`,
);
// Gap 41, and printed for the reason the line above is: a NOT ASKED that reads
// "CI asks it" is a claim about lanes, and a claim about lanes is what gap 42
// was recorded for. This is the measurement behind that sentence, taken where
// somebody reads the count.
console.log(
  `      ${ABSENCE_LANES.length} of those reach it with nothing before it naming an AstraPlugins checkout, ` +
  `which is where the checks whose passing condition is an ABSENCE are asked: ` +
  `${ABSENCE_LANES.map((l) => `${l.workflow.replace(".github/workflows/", "")}:${l.line}`).join(", ") || "none"}`,
);
// Gap 75, printed for gap 41's reason: "a checkout with the whole history asks
// it" is a claim about lanes, measured here where the count is read. The
// shallow ones are named too, because they are where those checks said NOT
// ASKED, and a reader of that lane's log is the one asking why.
{
  const shallowLive = LIVE_LANES.filter((l) => !l.history.full);
  const at = (ls) => ls.map((l) => `${l.workflow.replace(".github/workflows/", "")}:${l.line}`).join(", ");
  console.log(
    `      ${HISTORY_LANES.length} of the ${LIVE_LANES.length} live lane(s) reach it with the whole history, which is where the ` +
    `${HISTORY_GATED.length} check(s) about HISTORY are asked: ${at(HISTORY_LANES) || "none"}` +
    `${shallowLive.length ? `; through a shallow checkout, so NOT ASKED there: ${at(shallowLive)}` : ""}`,
  );
}
// Entry 116, printed for gap 41's reason: "build-index.yml asks the load
// checks" is a claim about lanes, measured here where the count is read. The
// lanes that do not are named, because a gate is among them on purpose.
{
  const recording = LIVE_LANES.filter((l) => l.loads.recorded);
  const unrecorded = LIVE_LANES.filter((l) => !l.loads.recorded);
  const at = (ls) => ls.map((l) => `${l.workflow.replace(".github/workflows/", "")}:${l.line}`).join(", ");
  console.log(
    `      ${recording.length} of the ${LIVE_LANES.length} live lane(s) record the modules the suite loads ` +
    `(\`--loads\`), which is where the ${SITES.filter((s) => s.env === "loads").length} check(s) about LOADS are ` +
    `asked: ${at(recording) || "none"}${unrecorded.length ? `; without it, so NOT ASKED there: ${at(unrecorded)}` : ""}`,
  );
}
// Gap 106, printed for gap 41's reason: that every NOT ASKED above is asked in
// another lane or declared is a claim about lanes, measured where the count is
// read.
{
  const declared = SITES.filter((s) => s.declared.length).length;
  const gated = SITES.filter((s) => s.env && !s.declared.length).length;
  console.log(
    `      ${SITES.length} check(s) can say NOT ASKED: ${gated} gated on an environment some live lane does not ` +
    `have, and asked there; ${declared} declared in ASKED_NOWHERE with the event that arms it — ` +
    `${ACCOUNTING.problems.length
      ? `and ${ACCOUNTING.problems.length} thing(s) in this run's NOT ASKEDs that none of that accounts for, below`
      : "every NOT ASKED in this run is one of them, and every other check is asked in every live lane"}`,
  );
}
for (const f of failures) console.log(`      - ${f}`);
for (const p of ACCOUNTING.problems) console.log(`      - NOT ASKED, unaccounted: ${p}`);
for (const n of ACCOUNTING.notes) console.log(`      - note: ${n}`);
// The shortfall carries its own lead sentence: there are two of them now — a
// module that reported nothing, and a module that reported fewer than its floor
// — and one prefix for both was a line that said the wrong thing about the
// second. Watched: `cli.mjs reported 4 check(s)` printed under "a module ran and
// reported nothing".
for (const s of shortfalls) console.log(`      - ${s}`);
for (const n of notAsked) console.log(`      - not asked: ${n}`);
if (failures.length || shortfalls.length || ACCOUNTING.problems.length) process.exit(1);
// EXIT-2: `if (notAsked.length) process.exit(2);` — see the note above.
