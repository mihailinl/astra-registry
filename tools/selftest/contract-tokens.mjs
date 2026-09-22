// `schema/contract-tokens-v1.json`'s own discipline: the version it names, and
// the schedule intervals it is one end of (RC-R2-2; SCOPE-1; SCOPE-2; BOT-51;
// BOT-83).
//
// The file is written by `astra-plugins-ops`' generator out of the contract and
// committed here. That makes this repository the one that holds it and the one
// that can be asked, on every push and every pull request, three questions the
// generator cannot ask about itself:
//
//   1. **Did its tokens move without `contract_version` moving?** SCOPE-1 makes
//      every published change to the token file a new contract version. The
//      generator runs in the other repository, against the contract, and never
//      sees this file's parent commit; the ops-side pre-push hook
//      (`tools/check-contract.mjs` there) sees the parent of the CONTRACT. The
//      commit that lands a regenerated file here, with an unmoved version, is
//      visible to neither. It is visible here.
//
//   2. **Does a workflow's cron still say what the file says?** BOT-51 and
//      BOT-83 pin the ingest and moderation intervals, amendment A6 makes each
//      a MUST, and SCOPE-1 makes a change to one a contract MINOR published
//      BEFORE the cron edit. So a cron line is one end of a three-way agreement
//      between a workflow, this file and a published contract version.
//
//   3. **Is its staging listing id the one this repository reserves?** MOD-16's
//      id is spelled in `policy/reserved-ids.json`, which the registry's three
//      rules read, and will be spelled again here when the contract records
//      it. The generator never reads the policy file, so the comparison can
//      only be made here (ops `dev/couplings.md` entry 33).
//
// ── One comparison, one owner, and a canary over the seam ───────────────────
//
// The second question is ALREADY ANSWERED for the ingest schedule, in
// `bot/tests/workflows.test.mjs`, which has compared `plugins-ingest.yml`'s cron
// against this file since the file landed. That module says so in its own words:
// *"This is the workflow half. RC-R2-2 runs the same comparison from
// `tools/selftest/` once `schema/contract-tokens-v1.json` exists."* The file now
// exists, the note it printed while the file did not is no longer printed, and
// the comparison there is live — measured, on `main` at `8c94c24`: the test
// `the ingest cron is BOT-51's interval, and the token file agrees once it
// exists` passes, and it reaches the token file's `$.schedules[0]` to do it.
//
// So this module does **not** run that comparison again. Two implementations of
// one rule is a coupling with no enforcer — they agree until the day one is
// edited, and then the estate has two answers and no way to tell which is the
// stale one. What this module does instead is the half that was missing:
//
//   - it compares every schedule this file names whose comparison NOBODY owns
//     (today: `schedule:moderation`, whose workflow does not exist yet, so the
//     leg is written armed and reports itself dormant rather than passing); and
//   - it asserts that the workflow half is still there for the one it delegates.
//     Delete the comparison from `bot/tests/workflows.test.mjs` and this module
//     goes red naming it. That is the canary the delegation is worth; without it
//     "somebody else checks that" is a promise, and this estate has a rule about
//     preferring a canary to one.
//
// `OWNED_ELSEWHERE` below is the register of that seam, and it is a list of
// schedule ids rather than a count, so a NEW schedule in the file is picked up
// here automatically instead of silently belonging to nobody.

import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

import { isShallow } from "../coverage/git.mjs";
import { REPO_ROOT, loadPublishers, loadRecords, loadSources, publisherRecords } from "../lib/sources.mjs";
import { stagingListingId } from "../lib/reserved.mjs";
import { NOTICE_DIR, NOTICE_NAME } from "../validate.mjs";
import { CUTOVER_FILE, DEADLINE_FILE } from "../../bot/lib/listing-state.mjs";
import { test, assert, assertEqual, neverAsk, tmp } from "./harness.mjs";

const TOKEN_FILE = "schema/contract-tokens-v1.json";
const POLICY_FILE = "policy/reserved-ids.json";
const STAGING_MEMBER = "staging_listing_id";
const WORKFLOW_HALF = "bot/tests/workflows.test.mjs";
const BOT_TESTS_WORKFLOW = ".github/workflows/bot-tests.yml";

/**
 * The word that makes a schema's prose a claim about the token file's register.
 *
 * `pending` is the estate's own vocabulary: the token file carries a `pending[]`
 * array whose records name what is missing, who owes it, the version that lands
 * it and what the floor asserts until then, and the ops-side generator REFUSES
 * TO RUN once the contract records one of them and no extractor has been
 * written. That machinery watches the records. It has never watched a schema
 * saying, in prose, that it is waiting for one — which is how
 * `schema/queue-v1.json` went on saying `submission_id` "is silent here because
 * the fact is pending" for two days and ten releases after 0.20.0 landed the
 * fact (astra-registry `8e03da6`, 2026-09-20, `"required": false`), while the
 * register two files away had never carried a record for it at all.
 *
 * So the word is reserved here: a record schema may use it, and when it does it
 * must NAME the record that carries the fact, so that the claim dies with the
 * record instead of outliving it.
 */
const PENDING_WORD = /\bpending\b/i;

/**
 * The floor on the scan, and it is on what was READ rather than on what was
 * found. Zero claims is a legitimate and desirable state — it is the state this
 * tree is in after the queue note was repaired — so a floor on findings would
 * be red on a healthy tree. A floor on the corpus is the one that matters: a
 * walk that resolves no schemas, or schemas with no prose in them, passes every
 * assertion below it while comparing nothing, which is the shape this whole
 * module exists to refuse.
 *
 * 12 record schemas holding 845 strings on 2026-09-22, at `dabbfbd`. The floors
 * are set well under both: eight is TRUST-31's schema enumeration as 0.20.0
 * published it, before 0.21.0's three and 0.23.0's one, and below it the walk
 * has stopped seeing `schema/` rather than `schema/` having shrunk.
 */
const RECORD_SCHEMA_FLOOR = 8;
const SCANNED_STRING_FLOOR = 200;

/**
 * Schedule ids whose cron-versus-file comparison lives somewhere else, with the
 * file that owns each. Every entry here is also asserted to still exist; an id
 * that is NOT here is compared by this module.
 */
const OWNED_ELSEWHERE = new Map([
  ["schedule:ingest", WORKFLOW_HALF],
]);

/**
 * The name of the test in `WORKFLOW_HALF` that owns the delegated comparison.
 * The canary at the bottom of this module runs THIS test and no other, so that
 * it stays a statement about the token file rather than an alarm about that
 * module's overall health.
 */
const OWNED_TEST_PATTERN = "the ingest cron is BOT-51's interval";

/**
 * The floor on the walk. Two schedules on 2026-09-21 — `schedule:ingest` and
 * `schedule:moderation` — and the floor is 1, not 2, deliberately: a schedule
 * legitimately retired must not make this red and teach the next reader that
 * the number is noise. One is the number below which the file has stopped
 * carrying schedules at all, and below which every comparison under it would be
 * a loop over an empty list reporting a clean tree.
 */
const SCHEDULE_FLOOR = 1;

function git(args) {
  return execFileSync("git", ["-C", REPO_ROOT, ...args], {
    encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
  });
}

function showOrNull(rev, file) {
  try {
    return git(["show", `${rev}:${file}`]);
  } catch {
    return null;
  }
}

const tokenPath = path.join(REPO_ROOT, TOKEN_FILE);

/**
 * The tracked record schemas: everything under `schema/` except the register
 * itself.
 *
 * Tracked via `git ls-files` for the reason the fixture copy below gives, and
 * the token file is excluded BY CONSTRUCTION rather than by an exclusion list:
 * it is the file the claims are compared against, and it says `pending` six
 * more times as a `notice_status` VALUE (`$.entries[76]`, `$.entries[92]`) that
 * has nothing to do with the register. Including it turns a population of one
 * into a population of seven, six of which are right.
 */
function recordSchemas() {
  return git(["ls-files", "--", "schema/"]).split("\n")
    .filter((rel) => rel.endsWith(".json") && rel !== TOKEN_FILE);
}

/** Every string value in a parsed document, with its JSON path. */
function* stringsOf(node, at = "$") {
  if (typeof node === "string") yield [at, node];
  else if (Array.isArray(node)) for (const [i, v] of node.entries()) yield* stringsOf(v, `${at}[${i}]`);
  else if (node && typeof node === "object") for (const [k, v] of Object.entries(node)) yield* stringsOf(v, `${at}.${k}`);
}

const namesWord = (text, word) => new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(text);

/**
 * Every `- cron: '…'` in a workflow, live or commented out, with its line.
 *
 * Commented crons count. `plugins-ingest.yml` lands dark at R2 exit with its
 * schedule commented and the R3-open commit uncomments it (§2.5), so a reader
 * that only saw a live `schedule:` block would assert nothing for the whole of
 * R2 and then start asserting, unwatched, inside a commit about something else.
 * `plugins-moderation.yml` will land the same way.
 */
function crons(text) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    const m = /^\s*#?\s*-\s*cron:\s*['"]?([^'"#]+?)['"]?\s*(?:#.*)?$/.exec(line);
    if (m) out.push({ expr: m[1].trim(), line: i + 1 });
  });
  return out;
}

/** Seconds between fires of a cron whose gaps are even, or an `error`. */
function cronIntervalSeconds(expr) {
  const fields = expr.trim().split(/\s+/);
  if (fields.length !== 5) return { error: `${JSON.stringify(expr)} is not five fields` };
  const [minute, hour, dom, month, dow] = fields;
  if ([hour, dom, month, dow].some((f) => f !== "*")) {
    return { error: `${JSON.stringify(expr)} is not an every-hour schedule, so it has no single interval` };
  }
  const fires = [];
  for (let m = 0; m < 60; m++) {
    const hit = minute.split(",").some((part) => {
      const step = /^(\*|\d+-\d+)\/(\d+)$/.exec(part);
      if (step) {
        const [lo, hi] = step[1] === "*" ? [0, 59] : step[1].split("-").map(Number);
        return m >= lo && m <= hi && (m - lo) % Number(step[2]) === 0;
      }
      const range = /^(\d+)-(\d+)$/.exec(part);
      if (range) return m >= +range[1] && m <= +range[2];
      return part === "*" ? true : Number(part) === m;
    });
    if (hit) fires.push(m);
  }
  if (fires.length < 2) return { error: `${JSON.stringify(expr)} fires ${fires.length} time(s) an hour` };
  const gaps = fires.map((m, i) => (i === 0 ? fires[0] + 60 - fires[fires.length - 1] : m - fires[i - 1]));
  const distinct = [...new Set(gaps)];
  if (distinct.length !== 1) {
    return { error: `${JSON.stringify(expr)} fires at uneven gaps of ${distinct.join(", ")} minutes` };
  }
  return { seconds: distinct[0] * 60, minutes: fires };
}

export async function run() {
  console.log("\nthe contract token file's version discipline (RC-R2-2)");

  await test("the token file names a contract version, an ops commit and its schedules", () => {
    assert(fs.existsSync(tokenPath),
      `${TOKEN_FILE} is not in this checkout. SCOPE-7 makes this repository commit it to main before R2 opens ` +
      `(RC-R2-1, merged in #127); every check in this module reads it, and so do minice's SCOPE-8 test and the ` +
      `client's SCOPE-10 copy`);
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    assert(/^\d+\.\d+\.\d+$/.test(doc.contract_version || ""),
      `${TOKEN_FILE}'s contract_version is ${JSON.stringify(doc.contract_version)}. Every rule below compares ` +
      `that value with another one, and a missing version makes each of them vacuous`);
    assert(/^[0-9a-f]{40}$/.test(doc.source_commit || ""),
      `${TOKEN_FILE}'s source_commit is ${JSON.stringify(doc.source_commit)} and it has to be the astra-plugins-ops ` +
      `commit the generator read. Without it nobody can reproduce this file, and the ops-side check that asks ` +
      `whether the stamp names published history has nothing to ask about`);
    assert(Array.isArray(doc.schedules) && doc.schedules.length >= SCHEDULE_FLOOR,
      `${TOKEN_FILE} names ${(doc.schedules || []).length} schedule(s) and the floor is ${SCHEDULE_FLOOR} (2 on ` +
      `2026-09-21). SCOPE-7 says the file carries "the schedule interval of the ingest and moderation workflows ` +
      `(BOT-51; BOT-83)"; below this floor the cron comparisons are loops over an empty list`);
    for (const s of doc.schedules) {
      assert(typeof s.id === "string" && typeof s.workflow === "string" && Number.isFinite(s.interval_seconds),
        `a schedule entry has no id, workflow or interval_seconds: ${JSON.stringify(s)}. The workflow path is ` +
        `what says WHICH cron line this number is the other end of`);
    }
  });

  // ── the rule the generator cannot ask about itself ────────────────────────
  await test("the token file's tokens did not move without contract_version moving", () => {
    const here = showOrNull("HEAD", TOKEN_FILE);
    assert(here !== null,
      `${TOKEN_FILE} is not committed at HEAD. This rule reads git, not the working tree, because SCOPE-1 is ` +
      `about what was PUBLISHED`);

    // GAP 81. A shallow checkout has no parent, and that is a question this
    // rule could not ask rather than a rule it passed — which is what the
    // comment here said, while the code printed a note saying "COULD NOT BE
    // ASKED" and then returned, so the check printed `ok` and was counted in
    // `passed`. Measured at 97c0b0d in a depth-1 file:// clone: `ok`, and
    // `ingest.yml`'s `selftest` job (depth 1) counted it every run.
    //
    // It now says NOT ASKED, and it asks the CHECKOUT, not whether a parent
    // happened to resolve. Deeper than 1 a parent does resolve, and it is not
    // always the commit this rule needs: the merge base with origin/main is
    // fetched only when the branch is close enough to main, and when it is
    // not it reads as absent and the rule falls back to HEAD~1. That is the
    // comparison the paragraph below says masked a real red on 2026-09-21. So
    // no red comes before the gate either. On a branch, HEAD~1 can also show a
    // change that the whole branch's delta has already versioned. The runner
    // finds this check by reading it (a `neverAsk(` first in the block of an
    // `if` whose whole condition is the shallowness question), prints the live
    // lanes that ask it and fails when there are none. Keep the gate written
    // that way.
    if (isShallow(REPO_ROOT)) {
      neverAsk(
        "this checkout is shallow, so the commit the token file is compared against is not established: at depth " +
        "1 neither HEAD's parent nor the merge base with origin/main was fetched, and deeper a merge base " +
        "outside the fetched commits reads as absent and the rule falls back to HEAD~1, the comparison that " +
        "masked an unversioned change on 2026-09-21",
        "a checkout with its whole history asks it: the runner prints the live lanes that reach this suite with " +
        "it under the totals and goes red when there are none (`node tools/selftest.mjs --lanes`)",
      );
    }
    // WHAT THIS RULE IS ABOUT IS THE BRANCH'S DELTA, NOT THE LAST COMMIT'S, and
    // the two differ the moment a branch has more than one commit. Its first
    // version compared HEAD with HEAD~1, and on 2026-09-21 that was watched
    // masking a real red: B-T2.3 landed FLOW-13's table with the version
    // standing still (red at 5e34409, correctly), and then a coordinator commit
    // adding a bot-tests.yml step landed on top. That commit touches no token,
    // so `a.body === b.body` returned early and the rule went GREEN at the
    // branch head while the change was still unversioned.
    //
    // It was never silent on `main` — a merge commit's first parent is main's
    // tip, so it fires there — but a pull request is read at its head, and any
    // later commit masked it. A check whose subject is a published artifact has
    // to be asked about the whole change that will be published, and on a
    // branch that is the merge base.
    //
    // The fallbacks say which ref was measured against rather than quietly
    // choosing one.
    const { parent, against } = (() => {
      const verify = (rev) => {
        try { return git(["rev-parse", "--verify", rev]).trim(); } catch { return null; }
      };
      const head = verify("HEAD^{commit}");
      const base = (() => {
        try { return git(["merge-base", "HEAD", "origin/main"]).trim(); } catch { return null; }
      })();
      // On main itself the merge base IS HEAD, which would compare a commit with
      // itself and pass over everything. There, the previous commit is right.
      if (base && base !== head) return { parent: base, against: `the merge base with origin/main (${base.slice(0, 7)})` };
      const prev = verify("HEAD^{commit}~1");
      return { parent: prev, against: prev ? `HEAD~1 (${prev.slice(0, 7)})` : null };
    })();
    if (!parent) {
      // The checkout holds the whole history (the gate above), so this is the
      // first commit, and the token file in it is not a change from anything.
      console.log(`  note  HEAD has no parent: this is the first commit, so there is no previous version to have risen above.`);
      return;
    }

    console.log(`  note  comparing against ${against}.`);

    const before = showOrNull(parent, TOKEN_FILE);
    if (before === null) {
      console.log(`  note  ${TOKEN_FILE} is new in HEAD, so there is no previous version to have risen above.`);
      return;
    }

    // `source_commit` is excluded, and that is not a convenience. The generator
    // stamps whichever ops commit it read, so a regeneration that moves no token
    // at all still changes this file's bytes. Comparing bytes would make every
    // pin move a contract version — which contradicts the version schedule
    // outright: 0.15.0 to 0.18.0 "add no token, code, schema or member", and
    // the file "needs no regeneration for these releases". The ops-side checker
    // makes the same exclusion for the same measured reason, and that is the
    // one number the two sides have to agree about.
    const tokensOf = (text) => {
      const doc = JSON.parse(text);
      const version = doc.contract_version;
      delete doc.source_commit;
      return { version, body: JSON.stringify(doc) };
    };
    const a = tokensOf(before);
    const b = tokensOf(here);
    if (a.body === b.body) return;   // only the stamp moved, or nothing did

    const rose = (x, y) => {
      const p = (s) => String(s || "0.0.0").split(".").map(Number);
      const [am, ai, ap] = p(x);
      const [bm, bi, bp] = p(y);
      return (bm - am || bi - ai || bp - ap) > 0;
    };
    assert(rose(a.version, b.version),
      `${TOKEN_FILE}'s tokens changed between ${against} and HEAD and contract_version did not rise: ` +
      `it is ${JSON.stringify(a.version)} on both sides. SCOPE-1 makes every published change to this file a new ` +
      `contract version with a dated §0.6 row naming the IDs it touches — the row the plugins service and the ` +
      `client read to find out what they have to re-read. A regenerated file with an unmoved version is the one ` +
      `shape neither the generator nor the ops-side pre-push hook can see: the generator never reads this file's ` +
      `parent, and the hook reads the contract's parent in the other repository`);
  });

  // ── BOT-51 and BOT-83's intervals, and who compares which ─────────────────
  await test("every schedule the token file names has its cron compared by somebody", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const unowned = [];
    const dormant = [];
    const problems = [];

    for (const schedule of doc.schedules) {
      const owner = OWNED_ELSEWHERE.get(schedule.id);
      if (owner) continue;
      unowned.push(schedule.id);
      const at = path.join(REPO_ROOT, schedule.workflow);
      if (!fs.existsSync(at)) {
        // Not a skip and not a pass. The plan says this leg runs "once those
        // workflows exist"; saying which one does not exist is the difference
        // between a rule waiting and a rule that quietly stopped applying.
        dormant.push(`${schedule.id} (${schedule.workflow} is not in this repository yet)`);
        continue;
      }
      const found = crons(fs.readFileSync(at, "utf8"));
      if (found.length !== 1) {
        problems.push(
          `${schedule.workflow} carries ${found.length} cron expression(s) and ${schedule.requirement} is one ` +
          `schedule; this file records one number`);
        continue;
      }
      const interval = cronIntervalSeconds(found[0].expr);
      if (interval.error) {
        problems.push(`${schedule.workflow}:${found[0].line}: ${interval.error}`);
        continue;
      }
      if (interval.seconds !== schedule.interval_seconds) {
        problems.push(
          `${schedule.workflow}:${found[0].line} fires every ${interval.seconds} s and ${TOKEN_FILE} records ` +
          `${schedule.interval_seconds} s for ${schedule.id} (${schedule.requirement}; amendment A6). SCOPE-1 ` +
          `makes a change to that number a contract MINOR published BEFORE the cron edit, so a cron moved first ` +
          `is the wrong order — and it silently moves BOT-47's, BOT-76's and BOT-84's bounds, which are all ` +
          `"max(5400 s, 3 × this interval)"`);
      }
      if (interval.minutes.includes(0)) {
        problems.push(
          `${schedule.workflow}:${found[0].line} fires on the hour, and ${schedule.requirement} says "at minutes ` +
          `off the hour"`);
      }
    }

    // The floor on THIS walk, separate from the file's schedule floor: if every
    // schedule turned out to be owned elsewhere, this test would compare
    // nothing and report a clean tree. Today `schedule:moderation` is the one
    // it owns, and if that ever becomes zero the register below has to say so
    // deliberately rather than by arithmetic.
    assert(unowned.length >= 1,
      `every schedule in ${TOKEN_FILE} is marked as compared elsewhere, so this test compared nothing. If a ` +
      `comparison really did move, take the id out of the file's schedules or say here why this module is now ` +
      `empty; OWNED_ELSEWHERE is a register, not a way to make a check quiet`);

    if (dormant.length) {
      console.log(`  note  dormant, and armed: ${dormant.join("; ")}. The comparison runs on the commit that ` +
        `lands the workflow, live cron or commented out.`);
    }
    assertEqual(problems.join("\n        "), "");
  });

  // ── the seam: the half this module delegates must still be there ──────────
  await test("the half this module delegates to is on disk and CI runs it", () => {
    for (const [id, owner] of OWNED_ELSEWHERE) {
      assert(fs.existsSync(path.join(REPO_ROOT, owner)),
        `${TOKEN_FILE}'s ${id} is registered as compared by ${owner} and that file is gone. Either restore it or ` +
        `take the id out of OWNED_ELSEWHERE in this module, which puts the comparison back here — what must not ` +
        `happen is the id staying registered to a file that no longer exists, because then nobody compares it ` +
        `and both halves report a clean tree`);
    }
    // A test nothing invokes is a comparison that is not happening, and nothing
    // else here can tell the difference: a file under `bot/tests/` runs only
    // when `bot-tests.yml` names it.
    const wf = path.join(REPO_ROOT, BOT_TESTS_WORKFLOW);
    assert(fs.existsSync(wf), `${BOT_TESTS_WORKFLOW} is gone, so nothing in CI runs ${WORKFLOW_HALF}`);
    assert(fs.readFileSync(wf, "utf8").includes(WORKFLOW_HALF),
      `${BOT_TESTS_WORKFLOW} does not name ${WORKFLOW_HALF}, so the half this module delegates the ingest ` +
      `comparison to is not run by anything. A test file under bot/tests/ runs only when that workflow names it`);
  });

  // ── and the seam is WATCHED, not described ────────────────────────────────
  //
  // The first version of this check read `bot/tests/workflows.test.mjs` as text
  // and asserted it still mentioned the token file's path. It passed on a tree
  // where the code had been changed to read a file that does not exist, because
  // what it had matched was the PROSE: that module explains itself at length and
  // names the path in a comment and in two assertion messages. A text match over
  // another file's source cannot tell a live read from a described one — the
  // same reason `repo-rules.mjs` deleted its interlock rather than rewording it,
  // and the same shape as the three module headers found on 2026-09-19 claiming
  // absences that had stopped being true.
  //
  // So the delegation is watched by DOING it: a fixture copy of the tracked tree
  // with one number changed in the token file, the other half run against it in
  // a subprocess, and its own words required in the output. Clean first, because
  // "it failed" proves nothing if the fixture fails for its own reasons.
  await test("doctoring the token file's ingest interval makes the other half red", () => {
    const fixture = fixtureRepo(["bot", ".github", "schema", "policy", "tools"]);
    const under = path.join(fixture, WORKFLOW_HALF);
    assert(fs.existsSync(under), `the fixture copy has no ${WORKFLOW_HALF}; the copy is what is broken, not the seam`);

    // Only the test that owns the comparison, by name. Running the whole of
    // `workflows.test.mjs` made this canary an alarm about that module's
    // OVERALL health, which is not its subject: a tree that adds
    // `plugins-moderation.yml` trips a dozen rules there about dispatch inputs
    // and concurrency groups, and this check would then refuse to say anything
    // about the token file for a reason that has nothing to do with it.
    // Measured that way on a branch landing a stub moderation workflow.
    const clean = runNodeTest(under, OWNED_TEST_PATTERN);
    assert(clean.code === 0,
      `an untouched fixture copy of this tree already fails ${WORKFLOW_HALF}'s ` +
      `${JSON.stringify(OWNED_TEST_PATTERN)}, so the red below would prove nothing about the token ` +
      `file. Its output was:\n${tailOf(clean.out)}`);
    assert(/(^|\n)#\s*pass 1(\s|$)/m.test(clean.out) || /✔/.test(clean.out),
      `${WORKFLOW_HALF} ran no test matching ${JSON.stringify(OWNED_TEST_PATTERN)}, so the clean run above ` +
      `was green over nothing and the doctored run below would be too. The test this module delegates to has ` +
      `been renamed or removed; find it and move the pattern with it. Output:\n${tailOf(clean.out)}`);

    const at = path.join(fixture, TOKEN_FILE);
    const doc = JSON.parse(fs.readFileSync(at, "utf8"));
    const ingest = doc.schedules.find((s) => s.id === "schedule:ingest");
    assert(ingest, `${TOKEN_FILE} has no schedule:ingest, so there is no number to doctor`);
    const wrong = ingest.interval_seconds + 600;
    ingest.interval_seconds = wrong;
    fs.writeFileSync(at, `${JSON.stringify(doc, null, 2)}\n`);

    const doctored = runNodeTest(under, OWNED_TEST_PATTERN);
    assert(doctored.code !== 0,
      `${TOKEN_FILE}'s ingest interval was changed from ${ingest.interval_seconds - 600} s to ${wrong} s in a ` +
      `fixture copy and ${WORKFLOW_HALF} still passed. That comparison is the ingest half of RC-R2-2, this ` +
      `module delegates it rather than writing it a second time, and it is not happening. Either put it back ` +
      `there or take schedule:ingest out of OWNED_ELSEWHERE, which moves the comparison into this module`);
    assert(doctored.out.includes("the token file records") && doctored.out.includes(String(wrong)),
      `${WORKFLOW_HALF} went red on the doctored fixture for some OTHER reason — its output never mentions the ` +
      `token file's recorded interval or the ${wrong} s that was planted. A canary that accepts any red accepts ` +
      `the wrong one. Output:\n${tailOf(doctored.out)}`);
  });

  // ── a prose claim about the register, against the register ────────────────
  //
  // The token file's `pending[]` is machine-readable and watched at WRITE time:
  // the ops generator refuses a run where the contract records a pending fact
  // and no extractor was written. Nothing read the other end. A schema that
  // says in prose *the fact is pending* is making the same claim in the one
  // place where no record has to exist for it — and it goes on making it after
  // the record is discharged, which is exactly what happened to
  // `schema/queue-v1.json` between 0.20.0 and 0.29.0 (couplings 53).
  //
  // The join is the record's `id`, and it runs both ways:
  //
  //   - a claim naming no live record is a claim whose fact has landed, or one
  //     nobody ever registered — and neither is a thing a schema may assert;
  //   - a record that names a `schema/…json` path is a fact the register says
  //     that file is waiting on, so that file must still say so.
  //
  // Both halves are one test because a tree where one is vacuous usually makes
  // the other vacuous too, and a reader has to see the counts together.
  await test("a schema's `pending` prose names a record the token file still carries, and vice versa", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const records = Array.isArray(doc.pending) ? doc.pending : [];
    const ids = records.map((p) => p.id).filter((id) => typeof id === "string");

    const files = recordSchemas();
    let scanned = 0;
    const claims = [];
    for (const rel of files) {
      const parsed = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, rel), "utf8"));
      for (const [at, text] of stringsOf(parsed)) {
        scanned++;
        if (PENDING_WORD.test(text)) claims.push({ rel, at, text });
      }
    }

    assert(files.length >= RECORD_SCHEMA_FLOOR,
      `the walk of tracked \`schema/\` found ${files.length} record schema(s) besides ${TOKEN_FILE} and the floor ` +
      `is ${RECORD_SCHEMA_FLOOR} (12 on 2026-09-22). Below it this scan is not finding a clean tree, it is not ` +
      `reading the directory`);
    assert(scanned >= SCANNED_STRING_FLOOR,
      `the walk read ${scanned} string(s) out of ${files.length} record schema(s) and the floor is ` +
      `${SCANNED_STRING_FLOOR} (845 on 2026-09-22). A scan over no schema descriptions passes every assertion ` +
      `below it`);

    const stale = claims.filter((c) => !ids.some((id) => namesWord(c.text, id)));
    assertEqual(stale.map((c) =>
      `${c.rel} ${c.at} says \`pending\` and names none of ${TOKEN_FILE}'s ${ids.length} record(s) ` +
      `(${ids.join(", ") || "none"}). Either the fact LANDED and this prose outlived it — which is what the ` +
      `register is for and what it would have said — or the fact is owed and nobody registered it, in which ` +
      `case the generator that refuses a run over an unextracted pending fact has nothing to refuse. Name the ` +
      `record id in the sentence, or stop making the claim: ${JSON.stringify(c.text.slice(0, 160))}…`,
    ).join("\n        "), "", "a schema's `pending` prose has outlived the record it was waiting on");

    // The reverse. A record's own `what`/`why`/`floor` is where it says which
    // file is waiting on it, so the register is DERIVED from the record rather
    // than hand-kept here — a new record naming a schema is picked up on the
    // day it is generated, which is the same reason `OWNED_ELSEWHERE` above is
    // a list of ids and not a count.
    const tracked = new Set(files);
    const orphaned = [];
    let watched = 0;
    for (const record of records) {
      const body = JSON.stringify(record);
      for (const rel of new Set([...body.matchAll(/schema\/[A-Za-z0-9._-]+\.json/g)].map((m) => m[0]))) {
        if (!tracked.has(rel)) continue;
        watched++;
        const says = claims.some((c) => c.rel === rel && namesWord(c.text, record.id));
        if (!says) {
          orphaned.push(
            `${TOKEN_FILE}'s pending record \`${record.id}\` names ${rel} and that file says nothing about ` +
            `\`${record.id}\` being pending. The register says that file is waiting on a fact; the file does not. ` +
            `One of the two is wrong, and the silent one is the file`);
        }
      }
    }
    assertEqual(orphaned.join("\n        "), "", "a register record names a schema that has stopped saying it is waiting");

    console.log(
      `  note  ${claims.length} \`pending\` claim(s) in ${files.length} record schema(s) (${scanned} strings), ` +
      `against ${records.length} register record(s); ${watched} record-to-schema pointer(s) followed.`);
    if (records.length && !watched) {
      console.log(
        `  note  dormant, and armed: no pending record names a schema/ path, so the reverse leg compared nothing ` +
        `this run. It arms itself on the first record that does, with no edit here.`);
    }
  });

  // ── and the sentence this lane put in queue-v1.json's place ───────────────
  //
  // The repair above replaced a claim about a pending fact with a claim about
  // THIS TREE: that `submission_id` is absent from the schema and that
  // B-T3.10's registry half — the `properties` entry and the legacy conditional
  // in `tools/validate.mjs` — is still owed. That claim can go stale in the
  // other direction the moment somebody writes the entry, and a note saying a
  // member is missing, in a file the member is now in, is the same defect one
  // turn later. It is a biconditional over one file, hand-kept on purpose and
  // cheap: the general scan above cannot read "is owed", and inventing prose it
  // could read would be a convention nobody knows.
  await test("queue-v1.json's note about the member it lacks is a fact about this tree", () => {
    const rel = "schema/queue-v1.json";
    const at = path.join(REPO_ROOT, rel);
    assert(fs.existsSync(at), `${rel} is gone, and it is one of TRUST-31's twelve record schemas`);
    const queue = JSON.parse(fs.readFileSync(at, "utf8"));
    const present = Object.hasOwn(queue.properties || {}, "submission_id");
    const says = String(queue.description || "").includes(MISSING_MEMBER_SENTENCE);
    assertEqual(present ? "the member is in `properties`" : "the member is not in `properties`",
      says ? "the member is not in `properties`" : "the member is in `properties`",
      `${rel} and its own description disagree about \`submission_id\`. The description ` +
      `${says ? "carries" : "does not carry"} ${JSON.stringify(MISSING_MEMBER_SENTENCE)} and \`properties\` ` +
      `${present ? "has" : "does not have"} the member. If B-T3.10's registry half has been written — a \`properties\` ` +
      `entry with §0.7's UUID grammar, NOT required, and the legacy \`trigger\` conditional in ` +
      `tools/validate.mjs — then that paragraph is the stale one and goes; if it has not, the paragraph is the ` +
      `only record that it is owed and must stay`);
  });

  // ── MOD-16's staging listing id, spelled in two files ─────────────────────
  //
  // Found 2026-09-22 by the lane landing M-T2.1 (ops `dev/couplings.md` entry
  // 33). `policy/reserved-ids.json` has carried `staging_listing_id` since
  // `bf51592`, and the three rules that make the reservation mean something
  // read it there, through `tools/lib/reserved.mjs`. This file carries the same
  // member as `null` under a pending record owed by ops.15, and the day ops.15
  // lands, the generator writes the id a second time. The generator reads the
  // contract and never this repository's policy, so from that commit the
  // estate has two spellings of one id and nothing comparing them. MOD-10
  // refuses `path_test` on any id but this one, so a disagreement is the panel
  // offering a path test the registry will not honour.
  //
  // The pending record also said its floor, "until ops.15 lands the member is
  // null and this record is present", as if something asserted it. Nothing
  // did: this module never read the member, and the ops generator's own
  // selftest floors `fixed_reasons`, `templates`, the FLOW-13 table and the
  // outcome codes one by one and has no floor for this member. A record could
  // be dropped with the member still null and every suite stayed green.
  //
  // So the join is held in both states, by one predicate:
  //
  //   - `null`: the pending record is present, once, and names who owes the
  //     value and what it lands with;
  //   - an id: it equals the one the policy file reserves (read through
  //     `stagingListingId`, like every other reader, so `""` means the same
  //     thing here as there), and no pending record is left behind.
  //
  // The second state has never been on any tree. So the second test builds it
  // from the committed files and requires each red, so its clauses are shown
  // working on every run and not only on the day ops.15 lands.
  await test("the token file's staging_listing_id is null under its pending record, or policy/reserved-ids.json's id with none", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const policyAt = path.join(REPO_ROOT, POLICY_FILE);
    assert(fs.existsSync(policyAt),
      `${POLICY_FILE} is not in this checkout, and it is the file every registry rule reads MOD-16's staging ` +
      `listing id from`);
    const reserved = JSON.parse(fs.readFileSync(policyAt, "utf8"));
    const { state, problems } = stagingIdJoin(doc, reserved);
    assert(problems.length === 0,
      `${TOKEN_FILE} and ${POLICY_FILE} disagree about MOD-16's staging listing id (ops dev/couplings.md ` +
      `entry 33):\n` + problems.map((p) => `- ${p}`).join("\n"));
    console.log(state === "pending"
      ? `  note  ${TOKEN_FILE}'s ${STAGING_MEMBER} is null and its pending record is present; ${POLICY_FILE} ` +
        `reserves ${JSON.stringify(stagingListingId(reserved))}. The equality leg arms on the regeneration that ` +
        `records the id, with no edit here.`
      : `  note  ${TOKEN_FILE}'s ${STAGING_MEMBER} is recorded and equals ${POLICY_FILE}'s.`);
  });

  await test("the staging-id join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    const policyText = showOrNull("HEAD", POLICY_FILE);
    assert(tokenText !== null && policyText !== null,
      `${tokenText === null ? TOKEN_FILE : POLICY_FILE} is not committed at HEAD, so there is nothing to build ` +
      `the states from`);
    const committed = JSON.parse(tokenText);
    const reserved = JSON.parse(policyText);
    const policyId = stagingListingId(reserved);
    assert(policyId !== null,
      `${POLICY_FILE} at HEAD reserves no staging listing id, so the recorded state cannot be built. ` +
      `tools/selftest/validation.mjs is red for the same reason`);
    // Another listing's id, from the committed tree: the value a mistaken
    // regeneration would most plausibly write.
    const other = git(["ls-tree", "-d", "--name-only", "HEAD", "plugins/"]).split("\n")
      .map((l) => l.replace(/^plugins\//, "")).filter((id) => id && id !== policyId).sort()[0];
    assert(other, `no committed listing under plugins/ besides ${policyId}, so the mismatch leg has no id to use`);

    // The committed record if the file still carries one, otherwise one built
    // here, so this test survives the regeneration that discharges the record.
    const committedRecord = (committed.pending || []).find((p) => p && p.id === STAGING_MEMBER);
    const record = committedRecord ?? {
      id: STAGING_MEMBER, what: "the staging listing id", owed_by: "(built by this test)",
      lands_with: "(built by this test)", floor: "the member is null and this record is present.",
    };
    const variant = (value, records) => {
      const doc = structuredClone(committed);
      doc[STAGING_MEMBER] = value;
      doc.pending = [...(committed.pending || []).filter((p) => p && p.id !== STAGING_MEMBER), ...records];
      return doc;
    };
    const without = (key) => { const r = { ...record }; delete r[key]; return r; };

    const legs = [
      { name: "null under its pending record", doc: variant(null, [record]), red: [] },
      { name: "the policy's id and no record", doc: variant(policyId, []), red: [] },
      { name: "null with no record", doc: variant(null, []), red: [TOKEN_FILE, "no pending record"] },
      { name: "null under a record with no lands_with", doc: variant(null, [without("lands_with")]), red: [TOKEN_FILE, "lands_with"] },
      { name: "null under a record with no owed_by", doc: variant(null, [without("owed_by")]), red: [TOKEN_FILE, "owed_by"] },
      { name: "null under the record twice", doc: variant(null, [record, record]), red: [TOKEN_FILE, "2 pending records"] },
      { name: "another listing's id", doc: variant(other, []), red: [TOKEN_FILE, POLICY_FILE, other, policyId] },
      { name: "the policy's id with the record left behind", doc: variant(policyId, [record]), red: [TOKEN_FILE, POLICY_FILE, "still carries"] },
      { name: "an empty string", doc: variant("", []), red: [TOKEN_FILE, "neither null nor an id"] },
      { name: "no member at all", doc: (() => { const d = variant(null, [record]); delete d[STAGING_MEMBER]; return d; })(), red: [TOKEN_FILE, "no `staging_listing_id` member"] },
    ];
    const wrong = [];
    for (const leg of legs) {
      const { problems } = stagingIdJoin(leg.doc, reserved);
      const said = problems.join("\n");
      if (leg.red.length === 0) {
        if (problems.length) wrong.push(`${leg.name}: expected green, was red: ${said}`);
      } else if (!problems.length) {
        wrong.push(`${leg.name}: expected red, was green`);
      } else {
        const unnamed = leg.red.filter((s) => !said.includes(s));
        if (unnamed.length) wrong.push(`${leg.name}: red, but not naming ${unnamed.join(", ")}: ${said}`);
      }
    }
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s ${STAGING_MEMBER} and ${POLICY_FILE} does not hold on a copy of the ` +
      `committed files, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} and ${POLICY_FILE}` +
      `${committedRecord ? "" : " (the pending record built here, the file no longer carries one)"}; ` +
      `${legs.filter((l) => l.red.length).length} red as named, ${legs.filter((l) => !l.red.length).length} green.`);
  });

  // ── what the file calls required, against the records it describes ──────
  //
  // Found 2026-09-22 answering the plugins service's question about which of
  // its two readings of "listed" decides (ops `dev/couplings.md` entry 86).
  // Contract 0.31.0's file published `astra.registry.plugin/1` `unlisted`,
  // `astra.registry.version/1` `yanked` and `astra.registry.publisher/1`
  // `covers` as `required: true`, and this tree's records omitted them:
  // `unlisted` in 16 of 22 listing records, `yanked` in 52 of 52 version
  // records, `covers` in 1 of 2 publisher records. A reader that takes
  // requiredness from the file — which is what the file is for — would have
  // refused most of the catalogue. The generator had rendered B.4's "others
  // READ `source.repo` and `unlisted`" as "both are required", because B.4
  // named no member of those three records optional; contract 0.32.0 says
  // which are.
  //
  // Nothing compared the file's `required: true` with the records it describes.
  // SCOPE-8's two-way test compares the file with an IMPLEMENTATION, entry 38
  // and entry 50 were about CONDITIONAL members, and the record schemas here
  // make all three optional — so the file, the prose and the schemas each
  // agreed with somebody, and the records agreed with none of them.
  //
  // So: every member the file publishes `required: true` for a B.4 record
  // kind is present in every record of that kind this tree commits, found the
  // way `tools/lib/sources.mjs` loads them.
  await test("every B.4 member the token file calls required is in every committed record of its kind", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const kinds = (doc.entries || []).filter((e) => e.kind === "schema" && /^astra\.registry\./.test(e.name));
    assert(kinds.length >= REGISTRY_KIND_FLOOR,
      `${TOKEN_FILE} carries ${kinds.length} \`astra.registry.*\` schema entries and the floor is ` +
      `${REGISTRY_KIND_FLOOR} (14 on 2026-09-22). Below it this is a loop over a broken read`);

    // A kind the file makes something required of, with no way here to find
    // its records, is a kind this check silently stops asking about. And a
    // loader for a kind the file no longer carries is a map gone stale.
    const demanding = kinds.filter((e) => (e.members || []).some((m) => m.required === true));
    const unloaded = demanding.map((e) => e.name).filter((n) => !RECORD_LOADERS[n]);
    assert(unloaded.length === 0,
      `${TOKEN_FILE} publishes a \`required: true\` member for ${unloaded.join(", ")}, and this check has no ` +
      `loader for that kind's committed records. Add one to RECORD_LOADERS, found the way tools/lib/sources.mjs ` +
      `(or the kind's own reader) finds them — never an empty list, which would pass`);
    const stale = Object.keys(RECORD_LOADERS).filter((n) => !kinds.some((e) => e.name === n));
    assert(stale.length === 0,
      `RECORD_LOADERS names ${stale.join(", ")}, which ${TOKEN_FILE} does not carry as a schema entry`);

    const sources = loadSources(REPO_ROOT);
    assert(sources.errors.length === 0,
      `plugins/ does not load, so no record of it can be said to carry anything: ` +
      sources.errors.slice(0, 3).map((e) => `${e.file}: ${e.message}`).join("; "));

    const problems = [];
    const read = [];
    const exceptionsSeen = new Set();
    let membersAsked = 0;
    for (const entry of demanding) {
      const records = RECORD_LOADERS[entry.name](REPO_ROOT, sources);
      read.push(`${entry.name.replace(/^astra\.registry\./, "")} ${records.length}`);
      for (const member of entry.members.filter((m) => m.required === true)) {
        if (records.length === 0) continue;
        membersAsked += 1;
        const missing = records.filter((r) => !memberPresent(r.doc, member.name));
        const exception = KNOWN_FALSE.find((k) => k.schema === entry.name && k.member === member.name);
        if (exception) {
          exceptionsSeen.add(`${exception.schema} ${exception.member}`);
          const outside = missing.filter((r) => !exception.onlyWhere(r.doc));
          if (outside.length) {
            problems.push(
              `${entry.name} \`${member.name}\` is absent from ${outside.length} record(s) the recorded exception ` +
              `does not cover (${exception.where}), first ${outside[0].file}`);
          }
          if (missing.length === 0) {
            problems.push(
              `${entry.name} \`${member.name}\` is recorded here as published \`required: true\` and absent ` +
              `${exception.where}, and every committed record now carries it. The exception is stale: remove it ` +
              `from KNOWN_FALSE, and ops \`dev/server-registry-contract-pending.md\` ${exception.pending} with it`);
          }
          continue;
        }
        if (missing.length) {
          problems.push(
            `${entry.name} publishes \`${member.name}\` \`required: true\`, and ${missing.length} of ` +
            `${records.length} committed record(s) do not carry it — first ${missing[0].file}` +
            (missing.length > 1 ? `, then ${missing.slice(1, 3).map((r) => r.file).join(", ")}` : ""));
        }
      }
    }
    for (const k of KNOWN_FALSE) {
      if (!exceptionsSeen.has(`${k.schema} ${k.member}`)) {
        problems.push(
          `KNOWN_FALSE records ${k.schema} \`${k.member}\` as published \`required: true\`, and ${TOKEN_FILE} no ` +
          `longer publishes it so. The exception is stale: remove it, and ops ` +
          `\`dev/server-registry-contract-pending.md\` ${k.pending} with it`);
      }
    }

    // The floor is on what was READ, so a loader that quietly returns nothing
    // for the three kinds this tree does commit is a failure and not a pass.
    const counts = Object.fromEntries(
      Object.keys(RECORD_FLOORS).map((n) => [n, RECORD_LOADERS[n](REPO_ROOT, sources).length]));
    for (const [n, floor] of Object.entries(RECORD_FLOORS)) {
      if (counts[n] < floor) {
        problems.push(`read ${counts[n]} committed ${n} record(s) and the floor is ${floor}; a loader stopped finding them`);
      }
    }
    if (membersAsked < REQUIRED_MEMBER_FLOOR) {
      problems.push(`asked ${membersAsked} \`required: true\` member(s) and the floor is ${REQUIRED_MEMBER_FLOOR}`);
    }
    const empty = demanding.filter((e) => RECORD_LOADERS[e.name](REPO_ROOT, sources).length === 0).map((e) => e.name);
    console.log(
      `  note  ${membersAsked} \`required: true\` member(s) asked against a committed record, over ${demanding.length} ` +
      `record kind(s) that publish one; records read: ` +
      `${read.join(", ")}. No committed record, so nothing asked there: ${empty.length ? empty.join(", ") : "none"}.`);
    assert(problems.length === 0,
      `the token file calls a member required that a committed record omits. A reader taking requiredness ` +
      `from the file refuses that record (ops dev/couplings.md entry 86):\n` + problems.map((p) => `- ${p}`).join("\n"));
  });
}

/**
 * The fragment of `schema/queue-v1.json`'s description that asserts the member
 * is absent. Kept here rather than in that file's own prose-about-prose, so
 * that a reword of the paragraph is a deliberate act with a red test beside it.
 */
const MISSING_MEMBER_SENTENCE = "`submission_id` IS NOT IN THIS FILE";

/** 14 `astra.registry.*` schema entries on 2026-09-22 (contract 0.31.0). */
const REGISTRY_KIND_FLOOR = 10;
/**
 * `required: true` members asked against at least one committed record: 10 at
 * contract 0.31.0 (plugin 2, version 5, publisher 3), 7 at 0.32.0, 6 at 0.33.0
 * (plugin 1, version 3, publisher 2), which made `artifacts.<platform>.sha256`
 * optional.
 */
const REQUIRED_MEMBER_FLOOR = 5;
/** 22 listing, 52 version and 2 publisher records on 2026-09-22. */
const RECORD_FLOORS = { "astra.registry.plugin/1": 10, "astra.registry.version/1": 20, "astra.registry.publisher/1": 1 };

/**
 * Each B.4 record kind's committed records, as `{file, doc}`, found where the
 * registry's own readers find them — `tools/lib/sources.mjs` for the four it
 * loads, and for the three it does not, the constant the kind's reader uses.
 * A new kind the token file makes a member required of has to be added here,
 * or the test above is red naming it.
 */
const RECORD_LOADERS = {
  "astra.registry.plugin/1": (_root, sources) => sources.plugins.map((p) => ({ file: p.file, doc: p.doc })),
  "astra.registry.version/1": (_root, sources) => sources.plugins.flatMap((p) => p.versions),
  "astra.registry.publisher/1": (root) => {
    const { errors, publishers } = loadPublishers(root);
    if (errors.length) throw new Error(`publishers/ does not load: ${errors[0].file}: ${errors[0].message}`);
    return publisherRecords(publishers);
  },
  "astra.registry.identity/1": (root, sources) => recordsOf(root, sources).identities,
  "astra.registry.decision/1": (root, sources) => recordsOf(root, sources).decisions,
  "astra.registry.queue/1": (root, sources) => recordsOf(root, sources).queue,
  "astra.registry.deadline/1": (root) => oneFile(root, DEADLINE_FILE),
  "astra.registry.cutover/1": (root) => oneFile(root, CUTOVER_FILE),
  "astra.registry.migration-notice/1": (root) => {
    const dir = path.join(root, NOTICE_DIR);
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir).filter((f) => NOTICE_NAME.test(f)).sort()
      .map((f) => ({ file: `${NOTICE_DIR}/${f}`, doc: JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")) }));
  },
};

function recordsOf(root, sources) {
  const r = loadRecords(root, sources);
  if (r.errors.length) throw new Error(`a B.4 record does not load: ${r.errors[0].file}: ${r.errors[0].message}`);
  return r;
}

function oneFile(root, rel) {
  const at = path.join(root, rel);
  return fs.existsSync(at) ? [{ file: rel, doc: JSON.parse(fs.readFileSync(at, "utf8")) }] : [];
}

/**
 * Whether a record carries a member the token file names by path. `a.b` is a
 * member of a member; `<platform>` is every key of the object at that point
 * (`artifacts.<platform>.sha256`), and an object with no key carries none.
 */
function memberPresent(doc, name) {
  const walk = (node, parts) => {
    if (parts.length === 0) return true;
    if (node === null || typeof node !== "object" || Array.isArray(node)) return false;
    const [head, ...rest] = parts;
    if (/^<[a-z_]+>$/.test(head)) {
      const keys = Object.keys(node);
      return keys.length > 0 && keys.every((k) => walk(node[k], rest));
    }
    return Object.hasOwn(node, head) && walk(node[head], rest);
  };
  return walk(doc, name.split("."));
}

/**
 * Whether the token file's `staging_listing_id` and the policy file's agree,
 * as `{state, problems}`. `state` is "pending" while the member is null,
 * "recorded" once it holds anything else, and "absent" when the file has no
 * such member. An empty `problems` is agreement.
 *
 * @param {object} doc the parsed token file
 * @param {object} reserved the parsed policy/reserved-ids.json
 */
function stagingIdJoin(doc, reserved) {
  const problems = [];
  const records = (Array.isArray(doc.pending) ? doc.pending : []).filter((p) => p && p.id === STAGING_MEMBER);
  const policyId = stagingListingId(reserved);
  if (!Object.hasOwn(doc, STAGING_MEMBER)) {
    problems.push(
      `${TOKEN_FILE} has no \`${STAGING_MEMBER}\` member at all. SCOPE-7 makes the file carry it, null until ` +
      `ops.15 and ${POLICY_FILE}'s id after, and a reader cannot tell a dropped member from one nobody owes`);
    return { state: "absent", problems };
  }
  const value = doc[STAGING_MEMBER];
  if (value === null) {
    if (records.length === 0) {
      problems.push(
        `${TOKEN_FILE}'s \`${STAGING_MEMBER}\` is null and the file carries no pending record for it, so nothing ` +
        `says the id is owed, by whom, or when. The record's floor is "until ops.15 lands the member is null and ` +
        `this record is present"; a regeneration that drops the record has to record the id`);
    } else if (records.length > 1) {
      problems.push(
        `${TOKEN_FILE} carries ${records.length} pending records with id \`${STAGING_MEMBER}\`, and a reader ` +
        `finding the first one cannot know the others say something different`);
    }
    for (const r of records) {
      for (const key of ["owed_by", "lands_with"]) {
        if (!(typeof r[key] === "string" && r[key].trim() !== "")) {
          problems.push(
            `${TOKEN_FILE}'s pending record \`${STAGING_MEMBER}\` has no \`${key}\`, so it does not say ` +
            `${key === "owed_by" ? "who owes the id" : "which version lands it"}: a record that names nothing to ` +
            `wait on is a null nobody is waiting to fill`);
        }
      }
    }
    return { state: "pending", problems };
  }
  if (typeof value !== "string" || value === "") {
    problems.push(
      `${TOKEN_FILE}'s \`${STAGING_MEMBER}\` is ${JSON.stringify(value)}, which is neither null nor an id. ` +
      `${POLICY_FILE}'s readers take anything but a non-empty string as "none reserved" (tools/lib/reserved.mjs)`);
    return { state: "recorded", problems };
  }
  if (value !== policyId) {
    problems.push(
      `${TOKEN_FILE} records \`${STAGING_MEMBER}\` ${JSON.stringify(value)} and ${POLICY_FILE} reserves ` +
      `${policyId === null ? "no staging listing id" : JSON.stringify(policyId)}. The registry derives, validates ` +
      `and excludes by the policy file's id and the panel reads this file's, so MOD-10's path test would be ` +
      `offered on an id the registry does not treat as its staging listing. One of the two is wrong, and the ` +
      `policy file's is the one three rules enforce`);
  }
  if (records.length) {
    problems.push(
      `${TOKEN_FILE} records \`${STAGING_MEMBER}\` ${JSON.stringify(value)} and still carries its pending record ` +
      `saying the id is owed. Once the value is recorded, and held to ${POLICY_FILE}'s, the record has outlived ` +
      `its reason; the ops generator drops a pending record when it writes the value, and this one was not dropped`);
  }
  return { state: "recorded", problems };
}

/**
 * A `required: true` the file publishes that the records are KNOWN to
 * contradict, with where the absence is permitted and where it is owed. Each
 * one is held both ways: absent outside `onlyWhere` is red, and an exception
 * that no longer fails — every record carries the member, or the file stopped
 * publishing it required — is red too, so it cannot outlive its reason.
 *
 * EMPTY SINCE CONTRACT 0.33.0, and the machinery stays for the next one.
 *
 * The one entry it held was `artifacts.<platform>.sha256`, found by this
 * check's first run: ten of the 52 version records on 2026-09-22 are the
 * bootstrap entries `staging: true` exists for, and carry no digest, while
 * 0.32.0's file published the member required. The acceptor answered that its
 * version parser reads the digest as optional (ops
 * `dev/server-registry-contract-pending.md` item 14), so 0.33.0's B.4 says the
 * digest is optional and absent only from a `staging: true` record, and the
 * file publishes it `required: false`. The entry went red by itself on that
 * file — "the exception is stale" — which is the prompt it was written to give.
 *
 * What the entry also asserted — that no NON-staging record lacks a digest —
 * does not leave with it: `tools/validate.mjs` refuses a non-staging artifact
 * with no `sha256` or `size`, and a staging one that carries a digest, over
 * every committed record.
 */
const KNOWN_FALSE = [];

/**
 * A copy of the tracked files under `dirs`, in the suite's temp directory.
 *
 * Tracked, via `git ls-files`, for the reason `walkRepo` gives: reading the disk
 * picks up build output and downloaded bundles that differ between this machine
 * and CI, so a fixture built that way is a different fixture in each place.
 * Copied rather than symlinked, because `bot/tests/workflows.test.mjs` derives
 * its repository root from `import.meta.dirname` and a symlink resolves straight
 * back to the real tree — which would doctor nothing and pass.
 */
function fixtureRepo(dirs) {
  const dest = fs.mkdtempSync(path.join(tmp, "workflow-half-"));
  const listed = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z", "--", ...dirs], {
    encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
  }).split("\0").filter(Boolean);
  let copied = 0;
  for (const rel of listed) {
    const from = path.join(REPO_ROOT, rel);
    if (!fs.existsSync(from)) continue;
    const to = path.join(dest, rel);
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.copyFileSync(from, to);
    copied++;
  }
  // A floor on the copy, for the reason every walk here has one: an empty
  // fixture makes the clean run pass and the doctored run fail for the wrong
  // reason, and both legs above would read as a healthy seam.
  if (copied < 50) {
    throw new Error(
      `the fixture copy took ${copied} tracked file(s) from ${dirs.join(", ")} and there were 226 on ` +
      `2026-09-21. That is a broken copy, not a smaller tree`);
  }
  return dest;
}

function runNodeTest(file, pattern) {
  const args = ["--test"];
  if (pattern) args.push(`--test-name-pattern=${pattern}`);
  args.push(file);
  const r = spawnSync(process.execPath, args, { encoding: "utf8", cwd: path.dirname(file) });
  return { code: r.status, out: `${r.stdout || ""}\n${r.stderr || ""}` };
}

const tailOf = (out) => out.trim().split("\n").slice(-14).join("\n");
