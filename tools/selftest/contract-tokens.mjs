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
//   3. **Does each member it carries under a pending record hold the record's
//      floor, and, once recorded, agree with what this repository says?**
//      MOD-16's staging listing id is spelled in `policy/reserved-ids.json`,
//      the shared-vector paths name files in this tree, and MOD-54's report
//      page is the page `tools/cutover-preflight.mjs` asks an operator to walk.
//      The generator never reads any of the three, so the comparison can only
//      be made here (ops `dev/couplings.md` entries 33 and 123).
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
import { cleanEnv } from "../lib/git-env.mjs";

import { isShallow } from "../coverage/git.mjs";
import { REPO_ROOT, loadPublishers, loadRecords, loadSources, publisherRecords } from "../lib/sources.mjs";
import { stagingListingId } from "../lib/reserved.mjs";
import { AUTHOR_CODES } from "../../bot/lib/compile-decision.mjs";
import { NOTICE_DIR, NOTICE_NAME } from "../validate.mjs";
import { CUTOVER_FILE, DEADLINE_FILE } from "../../bot/lib/listing-state.mjs";
import { holdEntryPath } from "../../bot/moderation-run.mjs";
import { test, assert, assertEqual, neverAsk, tmp } from "./harness.mjs";

const TOKEN_FILE = "schema/contract-tokens-v1.json";
const POLICY_FILE = "policy/reserved-ids.json";
const STAGING_MEMBER = "staging_listing_id";
const VECTOR_MEMBER = "shared_vector_paths";
const REPORT_RECORD = "mod54_report_page";
// The four members only the ops generator floored until contract 0.36.0 (ops
// pending item 27), and what two of them are read from.
const FIXED_MEMBER = "fixed_reasons";
const TEMPLATES_MEMBER = "templates";
const FLOW13_MEMBER = "flow13_table";
const OUTCOME_RECORD = "report_outcome_codes";
const OUTCOME_LIST = "list:report_outcomes";
const REPORT_STATES = "list:states:report";
const CODES_FILE = "tools/codes-table.json";
/**
 * `asserted_by`'s grammar (contract 0.36.0, SCOPE-7), the same one the ops
 * generator refuses to emit outside of: this repository, a module directly
 * under `tools/selftest/`, and a check name with no newline and no space at
 * either end. This module is `SELF`; its own records name `ASSERTED_BY_THIS`.
 */
const ASSERTED_BY = /^astra-registry:(tools\/selftest\/[a-z0-9][a-z0-9.-]*\.mjs)#(\S(?:[^\n]*\S)?)$/;
const SELF = "tools/selftest/contract-tokens.mjs";
const ASSERTED_BY_THIS = `astra-registry:${SELF}#`;
/**
 * MOD-54's report page as this repository spells it: `REPORT_PAGE` in the
 * cutover preflight, the page its `mod-54-report-page` check asks an operator
 * to walk. READ AS BYTES and never imported, for the reason
 * `tools/selftest/times.mjs` gives: this directory is in TRUST-31's set and the
 * publish path runs it, so an import would make a desk tool an input to every
 * publication.
 */
const PREFLIGHT_FILE = "tools/cutover-preflight.mjs";
const REPORT_PAGE_LINE = /^const REPORT_PAGE = "([^"\\]+)";$/gm;
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
    env: cleanEnv(),
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
    const wrong = legsGoneWrong(legs, (doc) => stagingIdJoin(doc, reserved));
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s ${STAGING_MEMBER} and ${POLICY_FILE} does not hold on a copy of the ` +
      `committed files, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} and ${POLICY_FILE}` +
      `${committedRecord ? "" : " (the pending record built here, the file no longer carries one)"}; ` +
      `${legs.filter((l) => l.red.length).length} red as named, ${legs.filter((l) => !l.red.length).length} green.`);
  });

  // ── two more pending members, the same shape twice more ───────────────────
  //
  // Found 2026-09-22 by the lane that closed the staging id (ops
  // `dev/couplings.md` entry 123). The token file's records for
  // `shared_vector_paths` and `mod54_report_page` state floors — "until ops.15
  // lands the list is empty and this record is present", "until that version
  // lands the entry is absent and this record is present" — and nothing
  // asserted either. The ops generator's selftest never names them, and
  // nothing here read them. So both are held the way the staging id is, by the
  // same predicate (`pendingJoin`, one row per member in `PENDING_MEMBERS`),
  // and each recorded state — which no tree has held — is built from the
  // committed files and required to go red clause by clause.
  //
  // What each is held to once recorded, and it is not the same kind of thing:
  //
  //   - the shared-vector paths are corpora a party that is not this one reads
  //     out of THIS repository at a pinned commit (§1.3 row 8.3). No file here
  //     lists them, so there is no list to equal; the counterpart is the tree.
  //     A path naming a file must be one this repository commits, and a path
  //     naming a directory must not be a file. A directory not committed YET is
  //     not red, and is printed: `tests/results/` is created at R3 (B-T3.5)
  //     and ops.15, which records it, lands before R2.
  //   - MOD-54's page is spelled in `tools/cutover-preflight.mjs` as
  //     `REPORT_PAGE`, the page its `mod-54-report-page` check sends an operator
  //     to walk before R6. Compared as "the page and its query parameters" —
  //     path, parameter names and, when the file names one, origin — because
  //     the shape the file will record it in is not yet written: a member
  //     string, or a `page` entry like FLOW-77's `url` + `query`. Both are
  //     read; a third shape is red until somebody teaches this module it.
  await test("the token file's shared_vector_paths is empty under its pending record, or paths this repository commits with none", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const tracked = trackedTree(git(["ls-files", "-z"]).split("\0"));
    const { state, problems, notes } = pendingJoin(doc, PENDING_MEMBERS[VECTOR_MEMBER], { tracked });
    assert(problems.length === 0,
      `${TOKEN_FILE}'s ${VECTOR_MEMBER} does not hold its pending record's floor, or does not name what this ` +
      `repository commits (ops dev/couplings.md entry 123):\n` + problems.map((p) => `- ${p}`).join("\n"));
    console.log(state === "pending"
      ? `  note  ${TOKEN_FILE}'s ${VECTOR_MEMBER} is empty and its pending record is present. The tree leg arms ` +
        `on the regeneration that records the paths, with no edit here.`
      : `  note  ${TOKEN_FILE}'s ${VECTOR_MEMBER} is recorded and every file it names is committed` +
        `${notes.length ? `; ${notes.join("; ")}` : ""}.`);
  });

  await test("the shared-vector join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    assert(tokenText !== null, `${TOKEN_FILE} is not committed at HEAD, so there is nothing to build the states from`);
    const committed = JSON.parse(tokenText);
    const tracked = trackedTree(git(["ls-tree", "-r", "-z", "--name-only", "HEAD"]).split("\0"));
    const row = PENDING_MEMBERS[VECTOR_MEMBER];

    // The paths ops.15 will record, as the committed record names them, or the
    // recorded list once the record is discharged: the value this test holds
    // to the tree is the one the next regeneration writes.
    const committedRecord = (committed.pending || []).find((p) => p && p.id === VECTOR_MEMBER);
    const record = committedRecord ?? builtRecord(VECTOR_MEMBER, "the list is empty and this record is present.");
    const paths = committedRecord
      ? [...String(committedRecord.what).matchAll(/`([^`\s]+\/[^`\s]*)`/g)].map((m) => m[1])
      : committed[VECTOR_MEMBER];
    const file = (Array.isArray(paths) ? paths : []).find((p) => typeof p === "string" && tracked.files.has(p));
    assert(file,
      `none of ${JSON.stringify(paths)} is a file committed at HEAD, so the recorded state cannot be built from ` +
      `the tree. ${committedRecord ? "The pending record names them" : `${TOKEN_FILE} records them`}; if a corpus ` +
      `moved, the regeneration that records the paths will be red here too`);
    const dir = file.slice(0, file.lastIndexOf("/"));
    const unwritten = `${dir}/unwritten-${path.posix.basename(file)}`;
    assert(!tracked.files.has(unwritten), `${unwritten} is committed, so it cannot stand for a path that is not`);
    const notYet = `${dir}/not-yet-committed/`;
    const variant = (value, records) => {
      const doc = structuredClone(committed);
      if (value === ABSENT) delete doc[VECTOR_MEMBER];
      else doc[VECTOR_MEMBER] = value;
      doc.pending = [...(committed.pending || []).filter((p) => p && p.id !== VECTOR_MEMBER), ...records];
      return doc;
    };
    const without = (key) => { const r = { ...record }; delete r[key]; return r; };

    const legs = [
      { name: "an empty list under its pending record", doc: variant([], [record]), red: [], state: "pending" },
      { name: "the paths the record names, and no record", doc: variant(paths, []), red: [], state: "recorded" },
      { name: "a directory not committed yet", doc: variant([file, notYet], []), red: [], state: "recorded", noted: [notYet] },
      { name: "an empty list with no record", doc: variant([], []), red: [TOKEN_FILE, "no pending record"] },
      { name: "an empty list under a record with no lands_with", doc: variant([], [without("lands_with")]), red: [TOKEN_FILE, "lands_with"] },
      { name: "an empty list under a record with no owed_by", doc: variant([], [without("owed_by")]), red: [TOKEN_FILE, "owed_by"] },
      { name: "an empty list under the record twice", doc: variant([], [record, record]), red: [TOKEN_FILE, "2 pending records"] },
      { name: "the paths with the record left behind", doc: variant(paths, [record]), red: [TOKEN_FILE, "still carries"] },
      { name: "no member at all", doc: variant(ABSENT, [record]), red: [TOKEN_FILE, "no `shared_vector_paths` member"] },
      { name: "null", doc: variant(null, [record]), red: [TOKEN_FILE, "neither the empty list nor a list of paths"] },
      { name: "a path this repository does not commit", doc: variant([file, unwritten], []), red: [TOKEN_FILE, unwritten, "does not commit"] },
      { name: "a file named as a directory", doc: variant([`${file}/`], []), red: [TOKEN_FILE, `${file}/`, "commits a file at"] },
      { name: "a directory named as a file", doc: variant([dir], []), red: [TOKEN_FILE, dir, "commits a directory there"] },
      { name: "an absolute path", doc: variant([`/${file}`], []), red: [TOKEN_FILE, "not a repository-relative path", "absolute"] },
      { name: "a path that climbs out", doc: variant([`${dir}/../${file}`], []), red: [TOKEN_FILE, "not a repository-relative path", "`..`"] },
      { name: "a path that is not a string", doc: variant([file, 7], []), red: [TOKEN_FILE, "not a repository-relative path", "not a string"] },
      { name: "a path named twice", doc: variant([file, file], []), red: [TOKEN_FILE, file, "twice"] },
    ];
    const wrong = legsGoneWrong(legs, (doc) => pendingJoin(doc, row, { tracked }));
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s ${VECTOR_MEMBER}, its pending record and the committed tree does not ` +
      `hold on a copy of the committed files, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} and tree, the recorded one from ` +
      `${committedRecord ? "the paths its pending record names" : "the paths it records"} (${paths.join(", ")}); ` +
      `${legs.filter((l) => l.red.length).length} red as named, ${legs.filter((l) => !l.red.length).length} green.`);
  });

  await test("the token file's MOD-54 report page is absent under its pending record, or tools/cutover-preflight.mjs's page with none", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const preflightAt = path.join(REPO_ROOT, PREFLIGHT_FILE);
    assert(fs.existsSync(preflightAt),
      `${PREFLIGHT_FILE} is not in this checkout, and its REPORT_PAGE is the one spelling of MOD-54's page in ` +
      `this repository — the page its mod-54-report-page check asks an operator to walk`);
    // Read in every state, not only once the page is recorded: a constant
    // renamed today would otherwise leave the equality leg with nothing to
    // compare on the day it arms, and nobody would find out until then.
    const reportPage = reportPageOf(fs.readFileSync(preflightAt, "utf8"));
    assert(!reportPage.error, `${PREFLIGHT_FILE}: ${reportPage.error}`);
    const { state, problems } = pendingJoin(doc, PENDING_MEMBERS[REPORT_RECORD], { reportPage });
    assert(problems.length === 0,
      `${TOKEN_FILE} does not hold its MOD-54 report page's pending record to its floor, or disagrees with ` +
      `${PREFLIGHT_FILE} about the page (ops dev/couplings.md entry 123):\n` + problems.map((p) => `- ${p}`).join("\n"));
    console.log(state === "pending"
      ? `  note  ${TOKEN_FILE} records no MOD-54 report page and its pending record is present; ${PREFLIGHT_FILE} ` +
        `walks ${reportPage.url}. The equality leg arms on the version that records the page, with no edit here.`
      : `  note  ${TOKEN_FILE}'s MOD-54 report page is recorded and is ${PREFLIGHT_FILE}'s.`);
  });

  await test("the MOD-54 page join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    const preflightText = showOrNull("HEAD", PREFLIGHT_FILE);
    assert(tokenText !== null && preflightText !== null,
      `${tokenText === null ? TOKEN_FILE : PREFLIGHT_FILE} is not committed at HEAD, so there is nothing to build ` +
      `the states from`);
    const committed = JSON.parse(tokenText);
    const want = reportPageOf(preflightText);
    assert(!want.error, `${PREFLIGHT_FILE} at HEAD: ${want.error}`);
    const row = PENDING_MEMBERS[REPORT_RECORD];

    // The recorded state in each shape the file could take, built from the
    // committed page entry the contract already writes that way (FLOW-77's,
    // `url` without a query and `query` as names), and a page a mistaken
    // regeneration would most plausibly copy: that same entry.
    const model = (committed.entries || []).find((e) => e && e.kind === "page" && Array.isArray(e.query));
    assert(model, `${TOKEN_FILE} at HEAD carries no \`page\` entry with a \`query\`, so the entry shape has no model`);
    const entry = (over = {}) => ({
      ...structuredClone(model), id: "page:MOD-54", name: "MOD-54", source: "MOD-54",
      requirements: ["MOD-54", "SCOPE-7"], url: `${want.origin}${want.pathname}`, query: want.params, ...over,
    });
    const rootRelative = want.url.slice(want.origin.length);
    const committedRecord = (committed.pending || []).find((p) => p && p.id === REPORT_RECORD);
    const record = committedRecord ?? builtRecord(REPORT_RECORD, "the entry is absent and this record is present.");
    const variant = ({ member = ABSENT, pages = [] }, records) => {
      const doc = structuredClone(committed);
      delete doc[REPORT_RECORD];
      if (member !== ABSENT) doc[REPORT_RECORD] = member;
      doc.entries = [...(committed.entries || []).filter((e) => !(e && e.kind === "page" && namesMod54(e))), ...pages];
      doc.pending = [...(committed.pending || []).filter((p) => p && p.id !== REPORT_RECORD), ...records];
      return doc;
    };
    const without = (key) => { const r = { ...record }; delete r[key]; return r; };

    const legs = [
      { name: "absent under its pending record", doc: variant({}, [record]), red: [], state: "pending" },
      { name: "the preflight's page as a member, and no record", doc: variant({ member: want.url }, []), red: [], state: "recorded" },
      { name: "the preflight's page as a root-relative member, and no record", doc: variant({ member: rootRelative }, []), red: [], state: "recorded" },
      { name: "the preflight's page as a page entry, and no record", doc: variant({ pages: [entry()] }, []), red: [], state: "recorded" },
      { name: "absent with no record", doc: variant({}, []), red: [TOKEN_FILE, "no pending record"] },
      { name: "absent under a record with no lands_with", doc: variant({}, [without("lands_with")]), red: [TOKEN_FILE, "lands_with"] },
      { name: "absent under a record with no owed_by", doc: variant({}, [without("owed_by")]), red: [TOKEN_FILE, "owed_by"] },
      { name: "absent under the record twice", doc: variant({}, [record, record]), red: [TOKEN_FILE, "2 pending records"] },
      { name: "the page with the record left behind", doc: variant({ member: want.url }, [record]), red: [TOKEN_FILE, PREFLIGHT_FILE, "still carries"] },
      { name: "another committed page's entry", doc: variant({ pages: [entry({ url: model.url, query: model.query })] }, []), red: [TOKEN_FILE, PREFLIGHT_FILE, model.url, want.url, "the path is"] },
      { name: "the page under another parameter", doc: variant({ member: `${want.origin}${want.pathname}?id=<id>` }, []), red: [TOKEN_FILE, PREFLIGHT_FILE, "the parameters are"] },
      { name: "the page on another origin", doc: variant({ member: `https://elsewhere.invalid${rootRelative}` }, []), red: [TOKEN_FILE, PREFLIGHT_FILE, "the origin is"] },
      { name: "a page outside /plugins/_/", doc: variant({ member: "/report?plugin=<id>" }, []), red: [TOKEN_FILE, "not under `/plugins/_/`"] },
      { name: "a relative page", doc: variant({ member: rootRelative.slice(1) }, []), red: [TOKEN_FILE, "neither a URL nor a root-relative path"] },
      { name: "a null member", doc: variant({ member: null }, []), red: [TOKEN_FILE, "neither a page path nor a page URL"] },
      { name: "a page entry with no url", doc: variant({ pages: [entry({ url: undefined })] }, []), red: [TOKEN_FILE, "page:MOD-54", "no `url`"] },
      { name: "a page entry whose query is not a list", doc: variant({ pages: [entry({ query: want.params.join(",") })] }, []), red: [TOKEN_FILE, "page:MOD-54", "not a list of parameter names"] },
      { name: "a member and a page entry both", doc: variant({ member: want.url, pages: [entry()] }, []), red: [TOKEN_FILE, "twice"] },
      { name: "two page entries naming MOD-54", doc: variant({ pages: [entry(), entry({ id: "page:MOD-54-again" })] }, []), red: [TOKEN_FILE, "2 page entries"] },
    ];
    const wrong = legsGoneWrong(legs, (doc) => pendingJoin(doc, row, { reportPage: want }));
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s MOD-54 report page, its pending record and ${PREFLIGHT_FILE}'s REPORT_PAGE ` +
      `does not hold on a copy of the committed files, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} and ${PREFLIGHT_FILE} ` +
      `(${want.url}); ${legs.filter((l) => l.red.length).length} red as named, ` +
      `${legs.filter((l) => !l.red.length).length} green.`);
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

  // ── four more pending members, which only the ops generator floored ───────
  //
  // Ops `dev/server-registry-contract-pending.md` item 27, carried by contract
  // 0.36.0. `fixed_reasons`, `templates`, `flow13_table` and the report-outcome
  // list were floored by the ops generator's selftest and by nothing else — over
  // the generator's OWN OUTPUT, never over the file this repository commits. A
  // hand edit here, a regeneration from another ops commit, or a run whose
  // selftest nobody ran could publish a member that broke its record's floor,
  // and no check that reads what is published would say so. So each is a row in
  // PENDING_MEMBERS, held by `pendingJoin` like the three above, and the record
  // in the file names this module's check for it in `asserted_by` (below).
  //
  // What each is held to once recorded, and in this repository where it can be:
  //
  //   - `fixed_reasons` to `AUTHOR_CODES` in `bot/lib/compile-decision.mjs`,
  //     the codes `fixedReason` is asked for — the file's ONE reader here — and
  //     to the code entries that repeat the string, so it is spelled once;
  //   - `templates` to this file's own author-audience and author-notify
  //     entries: a template must name ones the file lists, and ID-73 forbids
  //     either being `retired` while a listed template compiles it — and while
  //     the list is empty, the record's floor says nothing may be `retired` on
  //     the strength of it;
  //   - `flow13_table` to `tools/codes-table.json`, which `tools/gen-codes-table.mjs`
  //     emits from the codes and the ops generator merges. The committed file
  //     never holds the pending state (the generator refuses to drop a group
  //     registry main publishes), so the record is proven on built states only;
  //   - the report-outcome list to nothing here: minice-be supplies it, so it is
  //     held to its shape, and while it is owed, to B.3's report states being in
  //     the file, which is the floor the record says the client writes alone.
  await test("the token file's fixed_reasons is null under its pending record, or a string for each A_* code with none", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const { state, problems } = pendingJoin(doc, PENDING_MEMBERS[FIXED_MEMBER], {});
    assert(problems.length === 0,
      `${TOKEN_FILE}'s ${FIXED_MEMBER} does not hold its pending record's floor, or disagrees with the codes ` +
      `bot/lib/compile-decision.mjs asks it for (ops pending item 27):\n` + problems.map((p) => `- ${p}`).join("\n"));
    console.log(state === "pending"
      ? `  note  ${TOKEN_FILE}'s ${FIXED_MEMBER} is null, its pending record is present, and no code entry carries a ` +
        `string. The recorded leg arms on the regeneration that records the strings, with no edit here.`
      : `  note  ${TOKEN_FILE}'s ${FIXED_MEMBER} is recorded for ${AUTHOR_CODES.join(" and ")}, spelled once.`);
  });

  await test("the fixed_reasons join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    assert(tokenText !== null, `${TOKEN_FILE} is not committed at HEAD, so there is nothing to build the states from`);
    const committed = JSON.parse(tokenText);
    const row = PENDING_MEMBERS[FIXED_MEMBER];
    const committedRecord = (committed.pending || []).find((p) => p && p.id === FIXED_MEMBER);
    const record = committedRecord ?? builtRecord(FIXED_MEMBER, "`fixed_reasons` is null and this record is present.");
    const carriers = (committed.entries || []).filter((e) => e && Object.hasOwn(e, "fixed_reason"));
    assert(carriers.length > 0, `${TOKEN_FILE} at HEAD has no entry carrying \`fixed_reason\`, so the entry legs have no model`);
    const strings = Object.fromEntries(AUTHOR_CODES.map((c) => [c, `the fixed reason for ${c} (built by this test)`]));
    // `value` is the member; `entries` says what the carriers hold: "null" as
    // the pending file writes them, "same" the member's strings, or a function.
    const variant = (value, records, entries = "null") => {
      const doc = structuredClone(committed);
      if (value === ABSENT) delete doc[FIXED_MEMBER];
      else doc[FIXED_MEMBER] = value;
      for (const e of doc.entries.filter((x) => x && Object.hasOwn(x, "fixed_reason"))) {
        if (entries === "null") { e.fixed_reason = null; e.fixed_reason_pending = FIXED_MEMBER; }
        else if (entries === "same") { e.fixed_reason = value?.[e.name] ?? null; delete e.fixed_reason_pending; }
        else entries(e);
      }
      doc.pending = [...(committed.pending || []).filter((p) => p && p.id !== FIXED_MEMBER), ...records];
      return doc;
    };
    const without = (key) => { const r = { ...record }; delete r[key]; return r; };
    const [first, second] = AUTHOR_CODES;
    const legs = [
      { name: "null under its pending record", doc: variant(null, [record]), red: [], state: "pending" },
      { name: "a string for each author code, spelled once, and no record", doc: variant(strings, [], "same"), red: [], state: "recorded" },
      { name: "a string for each author code, and entries that carry none", doc: variant(strings, [], (e) => { delete e.fixed_reason; delete e.fixed_reason_pending; }), red: [], state: "recorded" },
      { name: "null with no record", doc: variant(null, []), red: [TOKEN_FILE, "no pending record"] },
      { name: "null under a record with no lands_with", doc: variant(null, [without("lands_with")]), red: [TOKEN_FILE, "lands_with"] },
      { name: "null under a record with no owed_by", doc: variant(null, [without("owed_by")]), red: [TOKEN_FILE, "owed_by"] },
      { name: "null under the record twice", doc: variant(null, [record, record]), red: [TOKEN_FILE, "2 pending records"] },
      { name: "no member at all", doc: variant(ABSENT, [record]), red: [TOKEN_FILE, "no `fixed_reasons` member"] },
      { name: "null while an entry carries a string", doc: variant(null, [record], (e) => { e.fixed_reason = "invented"; e.fixed_reason_pending = FIXED_MEMBER; }), red: [TOKEN_FILE, carriers[0].id, "while `fixed_reasons` is null"] },
      { name: "null while an entry points at another record", doc: variant(null, [record], (e) => { e.fixed_reason = null; e.fixed_reason_pending = "templates"; }), red: [TOKEN_FILE, "fixed_reason_pending"] },
      { name: "the strings with the record left behind", doc: variant(strings, [record], "same"), red: [TOKEN_FILE, "still carries"] },
      { name: "one author code with no string", doc: variant({ [first]: strings[first] }, [], "same"), red: [TOKEN_FILE, second, "AUTHOR_CODES"] },
      { name: "a code the registry does not treat as an author's", doc: variant({ ...strings, M_YANK: "x" }, [], "same"), red: [TOKEN_FILE, "M_YANK", "AUTHOR_CODES"] },
      { name: "an empty string", doc: variant({ ...strings, [first]: " " }, [], "same"), red: [TOKEN_FILE, first, "not a non-empty string"] },
      { name: "a string instead of an object", doc: variant("a reason", [], "same"), red: [TOKEN_FILE, "neither null nor an object"] },
      { name: "an entry spelling another string", doc: variant(strings, [], (e) => { e.fixed_reason = `${strings[e.name]} (retyped)`; delete e.fixed_reason_pending; }), red: [TOKEN_FILE, "spelled twice"] },
      { name: "an entry still null once the member is recorded", doc: variant(strings, [], "null"), red: [TOKEN_FILE, "spelled twice"] },
    ];
    const wrong = legsGoneWrong(legs, (doc) => pendingJoin(doc, row, {}));
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s ${FIXED_MEMBER}, its pending record, its code entries and AUTHOR_CODES does ` +
      `not hold on a copy of the committed file, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} and AUTHOR_CODES (${AUTHOR_CODES.join(", ")}); ` +
      `${legs.filter((l) => l.red.length).length} red as named, ${legs.filter((l) => !l.red.length).length} green.`);
  });

  await test("the token file's templates list is empty under its pending record, or templates naming this file's entries with none", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const { state, problems } = pendingJoin(doc, PENDING_MEMBERS[TEMPLATES_MEMBER], {});
    assert(problems.length === 0,
      `${TOKEN_FILE}'s ${TEMPLATES_MEMBER} does not hold its pending record's floor, or names what the file does not ` +
      `list, or has an entry a listed template compiles marked retired (ID-73; ops pending item 27):\n` +
      problems.map((p) => `- ${p}`).join("\n"));
    const compiled = authorCompiled(doc);
    console.log(state === "pending"
      ? `  note  ${TOKEN_FILE}'s ${TEMPLATES_MEMBER} is empty, its pending record is present, and none of the ` +
        `${compiled.length} entries author CI compiles (${compiled.map((e) => e.id).join(", ")}) is retired. The ` +
        `recorded leg arms on the regeneration that records template 1, with no edit here.`
      : `  note  ${TOKEN_FILE}'s ${doc[TEMPLATES_MEMBER].length} template(s) each name an author audience and ` +
        `author-notify path the file lists, and neither is retired.`);
  });

  await test("the templates join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    assert(tokenText !== null, `${TOKEN_FILE} is not committed at HEAD, so there is nothing to build the states from`);
    const committed = JSON.parse(tokenText);
    const row = PENDING_MEMBERS[TEMPLATES_MEMBER];
    const audience = authorCompiled(committed).find((e) => e.kind === "audience");
    const notify = authorCompiled(committed).find((e) => e.kind === "operation");
    assert(audience && notify,
      `${TOKEN_FILE} at HEAD lists no author audience or no author-CI operation, so a template has nothing to name`);
    const committedRecord = (committed.pending || []).find((p) => p && p.id === TEMPLATES_MEMBER);
    const record = committedRecord ?? builtRecord(TEMPLATES_MEMBER, "`templates` is an empty array and this record is present.");
    const template = (over = {}) => ({ version: "1", audience: audience.value, notify_path: notify.path, state: "live", ...over });
    const variant = (value, records, retire = []) => {
      const doc = structuredClone(committed);
      if (value === ABSENT) delete doc[TEMPLATES_MEMBER];
      else doc[TEMPLATES_MEMBER] = value;
      for (const e of doc.entries) if (e && retire.includes(e.id)) e.state = "retired";
      doc.pending = [...(committed.pending || []).filter((p) => p && p.id !== TEMPLATES_MEMBER), ...records];
      return doc;
    };
    const without = (key) => { const r = { ...record }; delete r[key]; return r; };
    const legs = [
      { name: "an empty list under its pending record", doc: variant([], [record]), red: [], state: "pending" },
      { name: "template 1 naming the author audience and notify path, and no record", doc: variant([template()], []), red: [], state: "recorded" },
      { name: "template 1 naming the audience by name", doc: variant([template({ audience: audience.name })], []), red: [], state: "recorded" },
      // Template 1 as it is: AstraPlugins' `init-ci` caller compiles no author
      // audience and no notify path (its test
      // `the_generated_caller_calls_nothing_but_the_reusable_workflow`; AP-4's
      // C25). SCOPE-7 lists what a template compiles, and `null` is that it
      // compiles none. ID-73 then protects nothing on its behalf, which is true.
      { name: "template 1 compiling no audience and no notify path, as init-ci's caller does", doc: variant([template({ audience: null, notify_path: null })], []), red: [], state: "recorded" },
      { name: "a template compiling the audience and no notify path", doc: variant([template({ notify_path: null })], []), red: [], state: "recorded" },
      { name: "a template whose audience is the empty string", doc: variant([template({ audience: "" })], []), red: [TOKEN_FILE, "audience", "null"] },
      { name: "a template whose notify path is a number", doc: variant([template({ notify_path: 7 })], []), red: [TOKEN_FILE, "notify_path", "null"] },
      // Compiling nothing, it protects nothing: ID-73 is about what a listed
      // template compiles, and the reusable workflow's half is AstraPlugins' C33.
      { name: "a template compiling nothing, with the author audience retired", doc: variant([template({ audience: null, notify_path: null })], [], [audience.id]), red: [], state: "recorded" },
      { name: "an empty list with no record", doc: variant([], []), red: [TOKEN_FILE, "no pending record"] },
      { name: "an empty list under a record with no lands_with", doc: variant([], [without("lands_with")]), red: [TOKEN_FILE, "lands_with"] },
      { name: "an empty list under a record with no owed_by", doc: variant([], [without("owed_by")]), red: [TOKEN_FILE, "owed_by"] },
      { name: "an empty list under the record twice", doc: variant([], [record, record]), red: [TOKEN_FILE, "2 pending records"] },
      { name: "no member at all", doc: variant(ABSENT, [record]), red: [TOKEN_FILE, "no `templates` member"] },
      { name: "the author audience retired while the list is empty", doc: variant([], [record], [audience.id]), red: [TOKEN_FILE, audience.id, "retired", "ID-73"] },
      { name: "the notify operation retired while the list is empty", doc: variant([], [record], [notify.id]), red: [TOKEN_FILE, notify.id, "retired", "ID-73"] },
      { name: "the templates with the record left behind", doc: variant([template()], [record]), red: [TOKEN_FILE, "still carries"] },
      { name: "null", doc: variant(null, [record]), red: [TOKEN_FILE, "neither the empty list nor a list of templates"] },
      { name: "a template with no notify path", doc: variant([template({ notify_path: undefined })], []), red: [TOKEN_FILE, "notify_path"] },
      { name: "a template whose state is not one of SCOPE-7's", doc: variant([template({ state: "current" })], []), red: [TOKEN_FILE, "\"current\"", "state"] },
      { name: "a template naming an audience the file does not list", doc: variant([template({ audience: "https://elsewhere.invalid/author" })], []), red: [TOKEN_FILE, "elsewhere.invalid", "lists no author audience"] },
      { name: "a template naming a notify path the file does not list", doc: variant([template({ notify_path: "/elsewhere" })], []), red: [TOKEN_FILE, "/elsewhere", "lists no author-CI operation"] },
      { name: "a listed template whose audience is retired", doc: variant([template()], [], [audience.id]), red: [TOKEN_FILE, audience.id, "ID-73"] },
      { name: "a retired template whose notify path is retired, still listed", doc: variant([template({ state: "retired" })], [], [notify.id]), red: [TOKEN_FILE, notify.id, "ID-73"] },
      { name: "two templates with one version", doc: variant([template(), template()], []), red: [TOKEN_FILE, "version \"1\"", "twice"] },
    ];
    const wrong = legsGoneWrong(legs, (doc) => pendingJoin(doc, row, {}));
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s ${TEMPLATES_MEMBER}, its pending record and the entries author CI compiles ` +
      `does not hold on a copy of the committed file, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} (${audience.id}, ${notify.id}); ` +
      `${legs.filter((l) => l.red.length).length} red as named, ${legs.filter((l) => !l.red.length).length} green.`);
  });

  await test("the token file's flow13_table is null under its pending record, or tools/codes-table.json's table with none", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const codesAt = path.join(REPO_ROOT, CODES_FILE);
    assert(fs.existsSync(codesAt),
      `${CODES_FILE} is not in this checkout, and it is the table tools/gen-codes-table.mjs emits from the codes and ` +
      `the ops generator merges into ${TOKEN_FILE}`);
    const codesTable = JSON.parse(fs.readFileSync(codesAt, "utf8"));
    const { state, problems } = pendingJoin(doc, PENDING_MEMBERS[FLOW13_MEMBER], { codesTable });
    assert(problems.length === 0,
      `${TOKEN_FILE}'s ${FLOW13_MEMBER} does not hold its pending record's floor, or is not the table ${CODES_FILE} ` +
      `carries (ops pending item 27):\n` + problems.map((p) => `- ${p}`).join("\n"));
    console.log(state === "pending"
      ? `  note  ${TOKEN_FILE}'s ${FLOW13_MEMBER} is null and its pending record is present.`
      : `  note  ${TOKEN_FILE}'s ${FLOW13_MEMBER} is ${CODES_FILE}'s, ${doc[FLOW13_MEMBER].length} rows and their ` +
        `source, byte for byte as JSON.`);
  });

  await test("the flow13_table join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    const codesText = showOrNull("HEAD", CODES_FILE);
    assert(tokenText !== null && codesText !== null,
      `${tokenText === null ? TOKEN_FILE : CODES_FILE} is not committed at HEAD, so there is nothing to build the states from`);
    const committed = JSON.parse(tokenText);
    const codesTable = JSON.parse(codesText);
    const row = PENDING_MEMBERS[FLOW13_MEMBER];
    const table = codesTable.flow13_table;
    assert(Array.isArray(table) && table.length >= 2, `${CODES_FILE} at HEAD carries no table of two rows or more to build from`);
    const source = { codes_source: codesTable.codes_source, codes: codesTable.codes.length };
    const record = (committed.pending || []).find((p) => p && p.id === FLOW13_MEMBER)
      ?? builtRecord(FLOW13_MEMBER, "without --codes the table is null and this record is present.");
    const variant = (value, src, records) => {
      const doc = structuredClone(committed);
      if (value === ABSENT) delete doc[FLOW13_MEMBER];
      else doc[FLOW13_MEMBER] = value;
      doc.flow13_source = src;
      doc.pending = [...(committed.pending || []).filter((p) => p && p.id !== FLOW13_MEMBER), ...records];
      return doc;
    };
    const without = (key) => { const r = { ...record }; delete r[key]; return r; };
    const retold = structuredClone(table);
    retold[0].remedy = `${retold[0].remedy} (retold)`;
    const legs = [
      { name: "null under its pending record, with no source", doc: variant(null, null, [record]), red: [], state: "pending" },
      { name: "the codes table's rows and source, and no record", doc: variant(structuredClone(table), source, []), red: [], state: "recorded" },
      { name: "null with no record", doc: variant(null, null, []), red: [TOKEN_FILE, "no pending record"] },
      { name: "null under a record with no lands_with", doc: variant(null, null, [without("lands_with")]), red: [TOKEN_FILE, "lands_with"] },
      { name: "null under a record with no owed_by", doc: variant(null, null, [without("owed_by")]), red: [TOKEN_FILE, "owed_by"] },
      { name: "null under the record twice", doc: variant(null, null, [record, record]), red: [TOKEN_FILE, "2 pending records"] },
      { name: "null with a source left behind", doc: variant(null, source, [record]), red: [TOKEN_FILE, "flow13_source"] },
      { name: "no member at all", doc: variant(ABSENT, null, [record]), red: [TOKEN_FILE, "no `flow13_table` member"] },
      { name: "the table with the record left behind", doc: variant(structuredClone(table), source, [record]), red: [TOKEN_FILE, "still carries"] },
      { name: "a row dropped", doc: variant(table.slice(1), { ...source, codes: source.codes - 1 }, []), red: [TOKEN_FILE, CODES_FILE, table[0].code] },
      { name: "a row's remedy retold", doc: variant(retold, source, []), red: [TOKEN_FILE, CODES_FILE, table[0].code] },
      { name: "two rows swapped", doc: variant([table[1], table[0], ...table.slice(2)], source, []), red: [TOKEN_FILE, CODES_FILE, "order"] },
      { name: "the source's count off by one", doc: variant(structuredClone(table), { ...source, codes: source.codes + 1 }, []), red: [TOKEN_FILE, "flow13_source"] },
      { name: "a list where the table is not rows", doc: variant("the table", source, []), red: [TOKEN_FILE, "neither null nor a list of rows"] },
    ];
    const wrong = legsGoneWrong(legs, (doc) => pendingJoin(doc, row, { codesTable }));
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s ${FLOW13_MEMBER}, its pending record and ${CODES_FILE} does not hold on a ` +
      `copy of the committed files, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} and ${CODES_FILE} (${table.length} rows); ` +
      `${legs.filter((l) => l.red.length).length} red as named, ${legs.filter((l) => !l.red.length).length} green.`);
  });

  await test("the token file's report-outcome list is absent under its pending record, or a list of codes with none", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const { state, problems } = pendingJoin(doc, PENDING_MEMBERS[OUTCOME_RECORD], {});
    assert(problems.length === 0,
      `${TOKEN_FILE}'s report-outcome list does not hold its pending record's floor (ops pending item 27):\n` +
      problems.map((p) => `- ${p}`).join("\n"));
    console.log(state === "pending"
      ? `  note  ${TOKEN_FILE} lists no report-outcome codes, its pending record is present, and B.3's report ` +
        `states are listed. The recorded leg arms on the version that records minice-be's list, with no edit here.`
      : `  note  ${TOKEN_FILE}'s report-outcome list is recorded, ${doc.entries.find((e) => e.id === OUTCOME_LIST).values.length} code(s).`);
  });

  await test("the report-outcome join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    assert(tokenText !== null, `${TOKEN_FILE} is not committed at HEAD, so there is nothing to build the states from`);
    const committed = JSON.parse(tokenText);
    const row = PENDING_MEMBERS[OUTCOME_RECORD];
    const model = (committed.entries || []).find((e) => e && e.id === REPORT_STATES);
    assert(model && Array.isArray(model.values), `${TOKEN_FILE} at HEAD has no ${REPORT_STATES}, so the list shape has no model`);
    const record = (committed.pending || []).find((p) => p && p.id === OUTCOME_RECORD)
      ?? builtRecord(OUTCOME_RECORD, "the outcome list is not floored and this record says so.");
    const list = (values) => ({ ...structuredClone(model), id: OUTCOME_LIST, name: "report outcomes", values });
    const variant = (lists, records, states = true) => {
      const doc = structuredClone(committed);
      doc.entries = doc.entries.filter((e) => e && e.id !== OUTCOME_LIST && (states || e.id !== REPORT_STATES));
      doc.entries.push(...lists);
      doc.pending = [...(committed.pending || []).filter((p) => p && p.id !== OUTCOME_RECORD), ...records];
      return doc;
    };
    const without = (key) => { const r = { ...record }; delete r[key]; return r; };
    const legs = [
      { name: "absent under its pending record", doc: variant([], [record]), red: [], state: "pending" },
      { name: "a list of codes, and no record", doc: variant([list(["upheld", "not_upheld"])], []), red: [], state: "recorded" },
      { name: "absent with no record", doc: variant([], []), red: [TOKEN_FILE, "no pending record"] },
      { name: "absent under a record with no lands_with", doc: variant([], [without("lands_with")]), red: [TOKEN_FILE, "lands_with"] },
      { name: "absent under a record with no owed_by", doc: variant([], [without("owed_by")]), red: [TOKEN_FILE, "owed_by"] },
      { name: "absent under the record twice", doc: variant([], [record, record]), red: [TOKEN_FILE, "2 pending records"] },
      { name: "absent, and B.3's report states gone too", doc: variant([], [record], false), red: [TOKEN_FILE, REPORT_STATES] },
      { name: "the list with the record left behind", doc: variant([list(["upheld"])], [record]), red: [TOKEN_FILE, "still carries"] },
      { name: "an empty list", doc: variant([list([])], []), red: [TOKEN_FILE, "no code"] },
      { name: "a code listed twice", doc: variant([list(["upheld", "upheld"])], []), red: [TOKEN_FILE, "\"upheld\"", "twice"] },
      { name: "a code that is not a string", doc: variant([list(["upheld", 3])], []), red: [TOKEN_FILE, "not a non-empty string"] },
      { name: "two lists", doc: variant([list(["upheld"]), list(["upheld"])], []), red: [TOKEN_FILE, "2 entries"] },
    ];
    const wrong = legsGoneWrong(legs, (doc) => pendingJoin(doc, row, {}));
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s report-outcome list and its pending record does not hold on a copy of the ` +
      `committed file, so the live check above is not asking what its name says:\n` + wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE}, the list modelled on ${REPORT_STATES}; ` +
      `${legs.filter((l) => l.red.length).length} red as named, ${legs.filter((l) => !l.red.length).length} green.`);
  });

  // ── asserted_by: every record names the check that holds its floor ────────
  //
  // Contract 0.36.0, SCOPE-7 (ops pending item 27). The seven joins above are
  // what a record's floor is held by; `asserted_by` is the record SAYING so, in
  // the file every party reads, as `astra-registry:<path>#<check name>`. The ops
  // generator refuses to emit a record without a well-formed one. Whether the
  // named check EXISTS is this repository's question, because only this tree
  // has the check, so it is asked here, statically: the name must be, character
  // for character, the title of exactly one `test(` call in that committed
  // module, comments blanked. For a record whose member has a row above, the
  // name must also be THAT row's check — a record pointing at some other real
  // check would pass an existence test and assert nothing about its floor.
  //
  // So a new pending record with no floor anywhere is red here, naming it,
  // instead of waiting to be found by reading, which is how all three of entry
  // 123's were found.
  await test("the asserted_by rule goes red for a record with none, a malformed one, and a check that does not exist, built from the committed file", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    assert(tokenText !== null, `${TOKEN_FILE} is not committed at HEAD, so there is nothing to build the states from`);
    const committed = JSON.parse(tokenText);
    const committedModules = new Set(git(["ls-tree", "-r", "--name-only", "HEAD", "--", "tools/selftest/"]).split("\n").filter(Boolean));
    const textOf = (rel) => (committedModules.has(rel) ? showOrNull("HEAD", rel) : null);
    // The committed records, each given its row's check if the file does not
    // carry one yet: the state the regeneration that lands this rule writes.
    const records = (committed.pending || []).map((p) => ({ ...p, asserted_by: p.asserted_by ?? `${ASSERTED_BY_THIS}${PENDING_MEMBERS[p.id]?.check}` }));
    assert(records.length > 0 && records.every((p) => PENDING_MEMBERS[p.id]),
      `${TOKEN_FILE} at HEAD carries a pending record with no row in PENDING_MEMBERS (${records.filter((p) => !PENDING_MEMBERS[p.id]).map((p) => p.id).join(", ")}), so the legs below cannot be built for it`);
    const other = "settings.mjs";
    const otherTitle = testTitlesIn(textOf(`tools/selftest/${other}`) ?? "")[0];
    assert(otherTitle, `tools/selftest/${other} at HEAD has no check to point at`);
    const doc = (edit) => { const d = structuredClone(committed); d.pending = structuredClone(records); edit(d.pending, d); return d; };
    const at = (id) => (list) => list.find((p) => p.id === id);
    const [a, b] = records.map((p) => p.id);
    const legs = [
      { name: "every record naming its row's check", doc: doc(() => {}), red: [] },
      { name: "a record with no asserted_by", doc: doc((l) => { delete at(a)(l).asserted_by; }), red: [TOKEN_FILE, a, "no `asserted_by`"] },
      { name: "another repository's check", doc: doc((l) => { at(a)(l).asserted_by = "astra-plugins-ops:tools/contract-tokens.mjs#the template list is floored"; }), red: [TOKEN_FILE, a, "not `astra-registry:"] },
      { name: "a module outside tools/selftest/", doc: doc((l) => { at(a)(l).asserted_by = "astra-registry:bot/tests/workflows.test.mjs#x"; }), red: [TOKEN_FILE, a, "not `astra-registry:"] },
      { name: "no check name", doc: doc((l) => { at(a)(l).asserted_by = `${ASSERTED_BY_THIS}`; }), red: [TOKEN_FILE, a, "not `astra-registry:"] },
      { name: "a trailing space", doc: doc((l) => { at(a)(l).asserted_by += " "; }), red: [TOKEN_FILE, a, "not `astra-registry:"] },
      { name: "a module this repository does not commit", doc: doc((l) => { at(a)(l).asserted_by = `astra-registry:tools/selftest/unwritten.mjs#${PENDING_MEMBERS[a].check}`; }), red: [TOKEN_FILE, a, "tools/selftest/unwritten.mjs", "does not commit"] },
      { name: "a check name that matches nothing", doc: doc((l) => { at(a)(l).asserted_by += " (renamed)"; }), red: [TOKEN_FILE, a, "names no check"] },
      { name: "another record's check", doc: doc((l) => { at(a)(l).asserted_by = at(b)(l).asserted_by; }), red: [TOKEN_FILE, a, "is not the check"] },
      { name: "a real check in another module", doc: doc((l) => { at(a)(l).asserted_by = `astra-registry:tools/selftest/${other}#${otherTitle}`; }), red: [TOKEN_FILE, a, "is not the check"] },
      { name: "a record with no row, naming a real check", doc: doc((l) => { l.push({ ...at(a)(l), id: "synthetic_member", asserted_by: `astra-registry:tools/selftest/${other}#${otherTitle}` }); }), red: [] },
      { name: "a record with no row, naming nothing", doc: doc((l) => { l.push({ ...at(a)(l), id: "synthetic_member", asserted_by: `astra-registry:tools/selftest/${other}#no such check` }); }), red: [TOKEN_FILE, "synthetic_member", "names no check"] },
    ];
    // And a module in which the named title appears twice: the name then picks
    // no one check, which is a name that asserts nothing in particular.
    const doubled = (rel) => {
      const t = textOf(rel);
      return rel === SELF ? `${t}\n test(${JSON.stringify(PENDING_MEMBERS[a].check)}, () => {});\n` : t;
    };
    const wrong = [];
    for (const leg of legs) {
      const said = assertedByProblems(leg.doc, { textOf, committedModules }).join("\n");
      if (!leg.red.length && said) wrong.push(`${leg.name}: expected green, was red: ${said}`);
      if (leg.red.length && !said) wrong.push(`${leg.name}: expected red, was green`);
      const unnamed = leg.red.filter((s) => !said.includes(s));
      if (leg.red.length && said && unnamed.length) wrong.push(`${leg.name}: red, but not naming ${unnamed.join(", ")}: ${said}`);
    }
    const twice = assertedByProblems(doc(() => {}), { textOf: doubled, committedModules }).join("\n");
    if (!(twice.includes(a) && twice.includes("2 checks"))) wrong.push(`a title defined twice: expected red naming ${a} and "2 checks", was: ${twice || "green"}`);
    // Every row's check is a literal title in this module, once: the copy the
    // generator emits and the title the check runs under cannot drift apart.
    const selfTitles = testTitlesIn(textOf(SELF) ?? "");
    for (const row of Object.values(PENDING_MEMBERS)) {
      const n = selfTitles.filter((t) => t === row.check).length;
      if (n !== 1) wrong.push(`PENDING_MEMBERS.${row.id}.check is the title of ${n} check(s) in ${SELF} at HEAD, not 1: ${JSON.stringify(row.check)}`);
    }
    assert(wrong.length === 0,
      `the asserted_by rule does not hold on a copy of the committed file, so the live check is not asking what ` +
      `its name says:\n` + wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length + 1} states built from HEAD's ${TOKEN_FILE} and tools/selftest/; ` +
      `${legs.filter((l) => l.red.length).length + 1} red as named, ${legs.filter((l) => !l.red.length).length} green; ` +
      `${Object.keys(PENDING_MEMBERS).length} rows' checks each a title in ${SELF} once.`);
  });

  // The live half of the rule above: the committed file, as it stands. Every
  // record names, in `asserted_by`, a check this repository runs by exactly
  // that name — and for a member with a row, that row's check. Landed with the
  // token file regenerated from contract 0.36.0, because a file generated
  // before it carries no `asserted_by` and this is red on it by design.
  await test("every pending record names, in asserted_by, the check in this repository that asserts its floor", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const committedModules = new Set(git(["ls-files", "--", "tools/selftest/"]).split("\n").filter(Boolean));
    const textOf = (rel) => (committedModules.has(rel) ? fs.readFileSync(path.join(REPO_ROOT, rel), "utf8") : null);
    const records = Array.isArray(doc.pending) ? doc.pending : [];
    const problems = assertedByProblems(doc, { textOf, committedModules });
    assert(problems.length === 0,
      `${TOKEN_FILE}'s pending records do not each name the check that holds their floor (contract 0.36.0, SCOPE-7; ` +
      `ops pending item 27):\n` + problems.map((p) => `- ${p}`).join("\n"));
    const unrowed = records.filter((p) => !PENDING_MEMBERS[p.id]).map((p) => p.id);
    console.log(`  note  ${records.length} pending record(s), each naming one check by its exact title; ` +
      `${records.length - unrowed.length} of them this module's own row check` +
      `${unrowed.length ? `, and ${unrowed.join(", ")} a check elsewhere` : ""}.`);
  });

  // ── contract 0.37.0: two things the file now says about THIS tree ─────────
  //
  // Both are statements the ops generator cannot check, because it reads the
  // contract and nothing else: that a schema path the file points a reader at
  // is a schema this repository commits, for the kind it is named on (ops
  // pending item 11); and that the one registry-only path the file publishes
  // for another party to read — a hold entry, for its presence alone (item 29,
  // §4.8 row 10) — is the path the moderation run really writes. A pointer
  // that resolves to nothing, or a path the writer moved, is silent in the file
  // and wrong in every reader of it; so each is held here, over the committed
  // file and tree, with every state the tree has not held built from them.
  await test("every schema_path in the token file is a schema committed here for its kind, and every committed registry-kind schema is named", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const tracked = trackedTree(git(["ls-tree", "-r", "-z", "--name-only", "HEAD"]).split("\0"));
    const { problems, notes } = schemaPathJoin(doc, { tracked, titleOf: committedTitle });
    assert(problems.length === 0,
      `${TOKEN_FILE}'s \`schema_path\` pointers and the schemas committed under schema/ disagree (contract 0.37.0, ` +
      `B.4 and SCOPE-7; ops pending item 11):\n` + problems.map((p) => `- ${p}`).join("\n"));
    console.log(`  note  ${notes.join("; ")}.`);
  });

  await test("the schema_path join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    assert(tokenText !== null, `${TOKEN_FILE} is not committed at HEAD, so there is nothing to build the states from`);
    const committed = JSON.parse(tokenText);
    const tracked = trackedTree(git(["ls-tree", "-r", "-z", "--name-only", "HEAD"]).split("\0"));
    const entryOf = (doc, name) => doc.entries.find((e) => e && e.kind === "schema" && e.name === name);
    const typed = (committed.entries || []).filter((e) => e && typeof e.schema_path === "string");
    assert(typed.length >= SCHEMA_PATH_FLOOR,
      `HEAD's ${TOKEN_FILE} carries ${typed.length} \`schema_path\`(s), under the floor of ${SCHEMA_PATH_FLOOR}, so ` +
      `the states below would be built from a file that has none`);
    // One kind named on the file and one the file names none for, both read
    // from the committed file, so the legs survive a later version.
    const named = typed.find((e) => e.name === "astra.registry.queue/1") ?? typed[0];
    const other = typed.find((e) => e !== named);
    const untyped = (committed.entries || []).find((e) => e && e.kind === "schema" &&
      /^astra\.registry\./.test(e.name) && !("schema_path" in e));
    assert(untyped, `every \`astra.registry.*\` entry in HEAD's ${TOKEN_FILE} names a schema, so the leg for a ` +
      `committed schema the file does not name has no kind to use`);
    const leaf = untyped.name.replace(/^astra\.registry\./, "").replace(/\/(\d+)$/, "-v$1");
    const synthesized = `schema/${leaf}.json`;
    assert(!tracked.files.has(synthesized), `${synthesized} is committed, so it cannot stand for one that is not`);
    const unwritten = named.schema_path.replace(/-v(\d+)\.json$/, "-v9$1.json");
    assert(!tracked.files.has(unwritten), `${unwritten} is committed, so it cannot stand for a path that is not`);

    const variant = (edit) => { const d = structuredClone(committed); edit(d); return d; };
    const set = (name, value) => (d) => {
      const e = entryOf(d, name);
      if (value === ABSENT) delete e.schema_path; else e.schema_path = value;
    };
    const withSchema = (base, file, title) => ({
      tracked: { files: new Set([...base.files, file]), dirs: base.dirs },
      titleOf: (rel) => (rel === file ? title : committedTitle(rel)),
    });
    const legs = [
      { name: "as committed", doc: committed, red: [] },
      { name: "a path this repository does not commit", doc: variant(set(named.name, unwritten)), red: [unwritten, "not a file committed"] },
      { name: "a directory", doc: variant(set(named.name, "schema")), red: ["`schema`", "not a file committed"] },
      { name: "another kind's schema", doc: variant(set(named.name, other.schema_path)),
        red: [named.name, other.schema_path, `titled ${JSON.stringify(other.name)}`] },
      { name: "a committed file that is no schema", doc: variant(set(named.name, POLICY_FILE)), red: [POLICY_FILE, "titled null"] },
      { name: "an absolute path", doc: variant(set(named.name, `/${named.schema_path}`)), red: ["not a repository-relative path", "absolute"] },
      { name: "a path that climbs out", doc: variant(set(named.name, `schema/../${named.schema_path}`)), red: ["not a repository-relative path", "`..`"] },
      { name: "not a string", doc: variant(set(named.name, 7)), red: ["not a repository-relative path", "not a string"] },
      { name: "a kind's pointer dropped", doc: variant(set(named.name, ABSENT)), red: [named.schema_path, named.name, "names no `schema_path`"] },
      { name: "a pointer on an entry that is no registry record", doc: variant((d) => {
        d.entries.find((e) => e && e.id === "schema:astra.plugins.error/1").schema_path = named.schema_path; }),
        red: ["schema:astra.plugins.error/1", "not an `astra.registry.*` schema entry"] },
      { name: "every pointer dropped", doc: variant((d) => { for (const e of d.entries) delete e.schema_path; }),
        red: [`floor of ${SCHEMA_PATH_FLOOR}`] },
      { name: "a schema committed for a kind the file names none for", doc: committed,
        ctx: withSchema(tracked, synthesized, untyped.name), red: [synthesized, untyped.name, "names no `schema_path`"] },
    ];
    const wrong = [];
    for (const leg of legs) {
      const ctx = leg.ctx ?? { tracked, titleOf: committedTitle };
      wrong.push(...legsGoneWrong([leg], (doc) => schemaPathJoin(doc, ctx)));
    }
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s \`schema_path\` pointers and the committed schemas does not hold on a copy of ` +
      `the committed files, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} and tree, the missing schema synthesized as ` +
      `${synthesized} for ${untyped.name}; ${legs.filter((l) => l.red.length).length} red as named, ` +
      `${legs.filter((l) => !l.red.length).length} green.`);
  });

  await test("the token file's hold-entry presence path is the path the moderation run writes", () => {
    const doc = JSON.parse(fs.readFileSync(tokenPath, "utf8"));
    const { problems, notes } = presenceJoin(doc, PRESENCE_WRITERS);
    assert(problems.length === 0,
      `${TOKEN_FILE}'s \`presence_paths\` and the paths this repository writes disagree (contract 0.37.0, B.4 and ` +
      `§4.8 row 10; ops pending item 29):\n` + problems.map((p) => `- ${p}`).join("\n"));
    console.log(`  note  ${notes.join("; ")}.`);
  });

  await test("the presence join goes red in each state the tree has not held, built from its committed files", () => {
    const tokenText = showOrNull("HEAD", TOKEN_FILE);
    assert(tokenText !== null, `${TOKEN_FILE} is not committed at HEAD, so there is nothing to build the states from`);
    const committed = JSON.parse(tokenText);
    const record = (committed.presence_paths || []).find((r) => r && PRESENCE_WRITERS[r.name]);
    assert(record, `HEAD's ${TOKEN_FILE} carries no \`presence_paths\` record this module has a writer for, so the ` +
      `states below would be built from a file that has none`);
    const variant = (edit) => { const d = structuredClone(committed); edit(d); return d; };
    const rec = (d) => d.presence_paths.find((r) => r.name === record.name);
    const moved = (fn) => ({ [record.name]: fn });
    const legs = [
      { name: "as committed", doc: committed, red: [] },
      { name: "the path moved in the file", doc: variant((d) => { rec(d).path = record.path.replace("state/holds/", "state/hold/"); }),
        red: [record.name, "state/hold/", "writes"] },
      { name: "the placeholder renamed", doc: variant((d) => { rec(d).path = record.path.replace(/<[a-z_]+>/, "<id>"); }),
        red: [record.name, "<id>", "placeholder"] },
      { name: "the suffix changed", doc: variant((d) => { rec(d).path = record.path.replace(/\.json$/, ".hold.json"); }),
        red: [record.name, ".hold.json", "writes"] },
      { name: "the writer moved", doc: committed, writers: moved((id) => `state/holds/${id}/entry.json`),
        red: [record.name, "/entry.json", "writes"] },
      { name: "no group at all", doc: variant((d) => { delete d.presence_paths; }), red: ["no `presence_paths`"] },
      { name: "the record twice", doc: variant((d) => { d.presence_paths.push(structuredClone(rec(d))); }), red: [record.name, "2 records"] },
      { name: "a record this module has no writer for", doc: variant((d) => {
        d.presence_paths.push({ ...structuredClone(rec(d)), name: "some other record", path: "state/other/<service_decision_id>.json" }); }),
        red: ["some other record", "no writer"] },
      { name: "read for content", doc: variant((d) => { rec(d).reads = "content"; }), red: [record.name, "`content`"] },
      { name: "read by the registry", doc: variant((d) => { rec(d).acceptor = ["registry"]; }), red: [record.name, "read by"] },
      { name: "written by the service", doc: variant((d) => { rec(d).emitter = ["service"]; }), red: [record.name, "written by"] },
    ];
    const wrong = [];
    for (const leg of legs) {
      const writers = leg.writers ?? PRESENCE_WRITERS;
      wrong.push(...legsGoneWrong([leg], (doc) => presenceJoin(doc, writers)));
    }
    assert(wrong.length === 0,
      `the join between ${TOKEN_FILE}'s \`presence_paths\` and the moderation run's writer does not hold on a copy ` +
      `of the committed file, so the live check above is not asking what its name says:\n` +
      wrong.map((w) => `- ${w}`).join("\n"));
    console.log(`  note  ${legs.length} states built from HEAD's ${TOKEN_FILE} and bot/moderation-run.mjs's writer; ` +
      `${legs.filter((l) => l.red.length).length} red as named, ${legs.filter((l) => !l.red.length).length} green.`);
  });
}

// ── contract 0.37.0's joins ─────────────────────────────────────────────────

/** Ten `schema_path`s at contract 0.37.0; below this the file has stopped carrying them. */
const SCHEMA_PATH_FLOOR = 10;

/** A committed file's JSON Schema `title` at HEAD, or null when it is not a JSON object with one. */
function committedTitle(rel) {
  const text = showOrNull("HEAD", rel);
  if (text === null) return null;
  try {
    const doc = JSON.parse(text);
    return doc && typeof doc === "object" && typeof doc.title === "string" ? doc.title : null;
  } catch {
    return null;
  }
}

/**
 * `schema_path` against the tree. Four clauses, each with its own leg above:
 * a pointer sits only on an `astra.registry.*` schema entry; it is a
 * repository-relative file the tree commits; that file's `title` is the entry's
 * kind, which is how each of this repository's schemas names what it types;
 * and every committed `schema/*.json` titled with a kind the file carries is
 * that kind's pointer — so a schema committed for one of the kinds B.4 names as
 * having none is red here until a contract version names it.
 */
function schemaPathJoin(doc, { tracked, titleOf }) {
  const problems = [];
  const entries = Array.isArray(doc.entries) ? doc.entries : [];
  const registry = entries.filter((e) => e && e.kind === "schema" && /^astra\.registry\./.test(e.name));
  let pointers = 0;
  for (const e of entries) {
    if (!e || !("schema_path" in e)) continue;
    pointers += 1;
    if (!registry.includes(e)) {
      problems.push(`${e.id} carries a \`schema_path\` and is not an \`astra.registry.*\` schema entry; B.4 names ` +
        "schemas for registry records only");
      continue;
    }
    const why = repoPathProblem(e.schema_path);
    if (why) {
      problems.push(`${e.name}'s \`schema_path\` ${JSON.stringify(e.schema_path)} is not a repository-relative path: ${why}`);
      continue;
    }
    if (!tracked.files.has(e.schema_path)) {
      problems.push(`${e.name}'s \`schema_path\` \`${e.schema_path}\` is not a file committed in this tree, so a reader ` +
        "following it finds nothing");
      continue;
    }
    const title = titleOf(e.schema_path);
    if (title !== e.name) {
      problems.push(`${e.name}'s \`schema_path\` \`${e.schema_path}\` is a schema titled ${JSON.stringify(title)}, so ` +
        "it types some other record, or none");
    }
  }
  if (pointers < SCHEMA_PATH_FLOOR) {
    problems.push(`${TOKEN_FILE} carries ${pointers} \`schema_path\`(s), under the floor of ${SCHEMA_PATH_FLOOR} ` +
      "(contract 0.37.0 publishes ten)");
  }
  const byKind = new Map(registry.map((e) => [e.name, e]));
  const committedSchemas = [...tracked.files].filter((f) => /^schema\/[^/]+\.json$/.test(f) && f !== TOKEN_FILE).sort();
  let titled = 0;
  for (const file of committedSchemas) {
    const title = titleOf(file);
    const e = byKind.get(title);
    if (!e) continue;
    titled += 1;
    if (e.schema_path !== file) {
      problems.push(`\`${file}\` is committed here, titled ${title}, and ${TOKEN_FILE}'s entry for ${title} names no ` +
        `\`schema_path\`${"schema_path" in e ? ` for it (it names ${JSON.stringify(e.schema_path)})` : ""}. B.4 names ` +
        "every committed schema for a registry record; a new one is a contract version (SCOPE-1)");
    }
  }
  const notes = [
    `${pointers} \`schema_path\`(s) over ${registry.length} \`astra.registry.*\` entries`,
    `${committedSchemas.length} committed schema file(s) read, ${titled} of them titled with a kind the file carries`,
  ];
  return { state: "recorded", problems, notes };
}

/**
 * The writer of each registry-only path the token file publishes for a presence
 * read, by the record's `name`, as the function that composes the path from
 * the one identifier. A record this map does not name is red, so a path a later
 * contract version publishes cannot go unchecked here: add its writer.
 */
const PRESENCE_WRITERS = {
  "moderation hold entry": holdEntryPath,
};

/** A canonical lowercase UUID v4, the §0.7 shape of a `service_decision_id`, to instantiate a path with. */
const SAMPLE_SERVICE_DECISION_ID = "0192f1d4-7b3a-4c5e-9d2f-3a1b2c3d4e5f";

/**
 * `presence_paths` against the writers. Each record is read for presence by
 * the service and written by the registry, and its path — with its one
 * placeholder, `<service_decision_id>`, filled with a well-formed id — is the
 * path the writer composes for that id; and exactly one record names each
 * writer.
 */
function presenceJoin(doc, writers) {
  const problems = [];
  if (!Array.isArray(doc.presence_paths)) {
    return { state: "recorded", problems: [`${TOKEN_FILE} carries no \`presence_paths\` group (contract 0.37.0)`], notes: [] };
  }
  const seen = new Map();
  for (const r of doc.presence_paths) {
    const name = r && r.name;
    seen.set(name, (seen.get(name) ?? 0) + 1);
    const write = writers[name];
    if (!write) {
      problems.push(`${JSON.stringify(name)} is a \`presence_paths\` record and this module has no writer for it. ` +
        "Name the function that composes its path in PRESENCE_WRITERS");
      continue;
    }
    if (r.reads !== "presence") problems.push(`${name} is read for \`${r.reads}\`; B.4 publishes \`presence\` alone`);
    if (JSON.stringify(r.acceptor) !== '["service"]') problems.push(`${name} is read by ${JSON.stringify(r.acceptor)}, not the service`);
    if (JSON.stringify(r.emitter) !== '["registry"]') problems.push(`${name} is written by ${JSON.stringify(r.emitter)}, not the registry`);
    const holders = typeof r.path === "string" ? [...r.path.matchAll(/<([a-z_]+)>/g)].map((m) => m[1]) : [];
    if (holders.length !== 1 || holders[0] !== "service_decision_id") {
      problems.push(`${name}'s path ${JSON.stringify(r.path)} has placeholder(s) ${JSON.stringify(holders)}, not the one ` +
        "`<service_decision_id>` its writer takes");
      continue;
    }
    const want = write(SAMPLE_SERVICE_DECISION_ID);
    const got = r.path.replace("<service_decision_id>", SAMPLE_SERVICE_DECISION_ID);
    if (got !== want) {
      problems.push(`${name}: the file says a reader finds it at \`${r.path}\`, which for one id is \`${got}\`, and ` +
        `this repository writes \`${want}\``);
    }
  }
  for (const [name, n] of seen) {
    if (n > 1) problems.push(`${name} is in \`presence_paths\` as ${n} records`);
  }
  for (const name of Object.keys(writers)) {
    if (!seen.has(name)) problems.push(`${TOKEN_FILE}'s \`presence_paths\` has no record for ${name}, whose writer is here`);
  }
  return { state: "recorded", problems, notes: [`${doc.presence_paths.length} presence record(s), each the path its writer composes`] };
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
 * The token file's members that sit under a pending record, one row each, and
 * what this module holds each to (ops `dev/couplings.md` entries 33 and 123).
 *
 * The clauses every row shares are written once, in `pendingJoin`: in the
 * pending state exactly one record, naming who owes the value and what lands
 * it; once recorded, no record left behind. A row says only what differs —
 * where the member lives, which value is its pending state, what a recorded
 * value must look like, and what in THIS repository it must agree with. So a
 * fourth member gets the shared clauses by adding a row, rather than by
 * somebody re-typing them and forgetting one.
 *
 * Row members: `find(doc)` → `{absent}` | `{value, at}` | `{problems}`;
 * `absent` is the red when the member is missing, or `null` when absence IS
 * the pending state; `pending(value)` is whether a present value is the
 * pending one; `judge(value, ctx, found)` → `{malformed}` | `{problems, notes}`
 * for a recorded value. The rest are words for the messages.
 */
const PENDING_MEMBERS = {
  [STAGING_MEMBER]: {
    id: STAGING_MEMBER,
    check: "the token file's staging_listing_id is null under its pending record, or policy/reserved-ids.json's id with none",
    what: "the id",
    owes: "who owes the id",
    floor: "until ops.15 lands the member is null and this record is present",
    waiting: "a null nobody is waiting to fill",
    pendingSays: `\`${STAGING_MEMBER}\` is null`,
    heldTo: `${POLICY_FILE}'s`,
    find: (doc) => (Object.hasOwn(doc, STAGING_MEMBER) ? { value: doc[STAGING_MEMBER], at: `\`${STAGING_MEMBER}\`` } : { absent: true }),
    absent:
      `${TOKEN_FILE} has no \`${STAGING_MEMBER}\` member at all. SCOPE-7 makes the file carry it, null until ` +
      `ops.15 and ${POLICY_FILE}'s id after, and a reader cannot tell a dropped member from one nobody owes`,
    pending: (value) => value === null,
    judge: (value, { reserved }) => {
      if (typeof value !== "string" || value === "") {
        return { malformed: [
          `${TOKEN_FILE}'s \`${STAGING_MEMBER}\` is ${JSON.stringify(value)}, which is neither null nor an id. ` +
          `${POLICY_FILE}'s readers take anything but a non-empty string as "none reserved" (tools/lib/reserved.mjs)`,
        ] };
      }
      const policyId = stagingListingId(reserved);
      if (value !== policyId) {
        return { problems: [
          `${TOKEN_FILE} records \`${STAGING_MEMBER}\` ${JSON.stringify(value)} and ${POLICY_FILE} reserves ` +
          `${policyId === null ? "no staging listing id" : JSON.stringify(policyId)}. The registry derives, validates ` +
          `and excludes by the policy file's id and the panel reads this file's, so MOD-10's path test would be ` +
          `offered on an id the registry does not treat as its staging listing. One of the two is wrong, and the ` +
          `policy file's is the one three rules enforce`,
        ] };
      }
      return { problems: [] };
    },
  },
  [VECTOR_MEMBER]: {
    id: VECTOR_MEMBER,
    check: "the token file's shared_vector_paths is empty under its pending record, or paths this repository commits with none",
    what: "the list of paths",
    owes: "who owes the paths",
    floor: "until ops.15 lands the list is empty and this record is present",
    waiting: "an empty list nobody is waiting to fill",
    pendingSays: `\`${VECTOR_MEMBER}\` is empty`,
    heldTo: "what this repository commits",
    find: (doc) => (Object.hasOwn(doc, VECTOR_MEMBER) ? { value: doc[VECTOR_MEMBER], at: `\`${VECTOR_MEMBER}\`` } : { absent: true }),
    absent:
      `${TOKEN_FILE} has no \`${VECTOR_MEMBER}\` member at all. The generator writes it as an empty list until ` +
      `ops.15 records the paths, and a reader cannot tell a dropped member from one nobody owes`,
    pending: (value) => Array.isArray(value) && value.length === 0,
    judge: (value, { tracked }) => vectorPathsAgainstTree(value, tracked),
  },
  [REPORT_RECORD]: {
    id: REPORT_RECORD,
    check: "the token file's MOD-54 report page is absent under its pending record, or tools/cutover-preflight.mjs's page with none",
    what: "the page",
    owes: "who owes the page",
    floor: "until that version lands the entry is absent and this record is present",
    waiting: "an absence nobody is waiting to fill",
    pendingSays: "MOD-54 report page is absent",
    heldTo: `${PREFLIGHT_FILE}'s REPORT_PAGE`,
    find: findReportPage,
    absent: null,
    pending: () => false,
    judge: (value, { reportPage }, found) => reportPageAgainstPreflight(value, reportPage, found),
  },
  [FIXED_MEMBER]: {
    id: FIXED_MEMBER,
    check: "the token file's fixed_reasons is null under its pending record, or a string for each A_* code with none",
    what: "the fixed reason strings",
    owes: "who owes the strings",
    floor: "until ops.15 lands, `fixed_reasons` is null and this record is present",
    waiting: "a null nobody is waiting to fill",
    pendingSays: `\`${FIXED_MEMBER}\` is null`,
    heldTo: "bot/lib/compile-decision.mjs's AUTHOR_CODES",
    find: (doc) => (Object.hasOwn(doc, FIXED_MEMBER) ? { value: doc[FIXED_MEMBER], at: `\`${FIXED_MEMBER}\`` } : { absent: true }),
    absent:
      `${TOKEN_FILE} has no \`${FIXED_MEMBER}\` member at all. SCOPE-7 makes the file carry the one fixed registry ` +
      `string each A_* code carries, null until ops.15, and bot/lib/compile-decision.mjs's fixedReason reads it there`,
    pending: (value) => value === null,
    whilePending: (doc) => fixedCarriersWhilePending(doc),
    judge: (value, _ctx, found) => fixedReasonsAgainstCodes(value, found.doc),
  },
  [TEMPLATES_MEMBER]: {
    id: TEMPLATES_MEMBER,
    check: "the token file's templates list is empty under its pending record, or templates naming this file's entries with none",
    what: "the template list",
    owes: "who owes the list",
    floor: "until ops.15 lands, `templates` is an empty array, this record is present, and nothing may be marked `retired` on the strength of it",
    waiting: "an empty list nobody is waiting to fill",
    pendingSays: `\`${TEMPLATES_MEMBER}\` is empty`,
    heldTo: "the author audience and author-notify entries this file lists",
    find: (doc) => (Object.hasOwn(doc, TEMPLATES_MEMBER) ? { value: doc[TEMPLATES_MEMBER], at: `\`${TEMPLATES_MEMBER}\`` } : { absent: true }),
    absent:
      `${TOKEN_FILE} has no \`${TEMPLATES_MEMBER}\` member at all. SCOPE-7 makes the file carry every generated-workflow ` +
      `template version init-ci has emitted, and ID-73 reads it before anything author CI compiles may be retired`,
    pending: (value) => Array.isArray(value) && value.length === 0,
    whilePending: (doc) => {
      const compiled = authorCompiled(doc);
      if (compiled.length === 0) {
        return [`${TOKEN_FILE} lists no author audience and no author-CI operation, so the floor that nothing author CI ` +
          `compiles is retired while \`${TEMPLATES_MEMBER}\` is empty holds over nothing`];
      }
      return compiled.filter((e) => e.state === "retired").map((e) =>
        `${TOKEN_FILE} marks \`${e.id}\` retired while \`${TEMPLATES_MEMBER}\` is empty, and the record's floor says nothing ` +
        `may be marked retired on the strength of an empty list: authors' repositories may still compile it (ID-73)`);
    },
    judge: (value, _ctx, found) => templatesAgainstEntries(value, found.doc),
  },
  [FLOW13_MEMBER]: {
    id: FLOW13_MEMBER,
    check: "the token file's flow13_table is null under its pending record, or tools/codes-table.json's table with none",
    what: "the table",
    owes: "who emits the table",
    floor: "without --codes the table is null and this record is present",
    waiting: "a null nobody is waiting to fill",
    pendingSays: `\`${FLOW13_MEMBER}\` is null`,
    heldTo: CODES_FILE,
    find: (doc) => (Object.hasOwn(doc, FLOW13_MEMBER) ? { value: doc[FLOW13_MEMBER], at: `\`${FLOW13_MEMBER}\`` } : { absent: true }),
    absent:
      `${TOKEN_FILE} has no \`${FLOW13_MEMBER}\` member at all. SCOPE-7 makes the file carry FLOW-13's table, one entry ` +
      `per reason code, which the panel reads from the file (FLOW-13)`,
    pending: (value) => value === null,
    whilePending: (doc) => (doc.flow13_source === null || doc.flow13_source === undefined ? [] : [
      `${TOKEN_FILE} carries flow13_source ${JSON.stringify(doc.flow13_source)} and no \`${FLOW13_MEMBER}\`: a source for ` +
      `a table that is not there, which the generator writes only when it merged one`,
    ]),
    judge: (value, { codesTable }, found) => flow13AgainstCodes(value, codesTable, found.doc),
  },
  [OUTCOME_RECORD]: {
    id: OUTCOME_RECORD,
    check: "the token file's report-outcome list is absent under its pending record, or a list of codes with none",
    what: "the outcome list",
    owes: "who supplies the list",
    floor: "until that version lands the client-side floor is written for B.3's four report states alone and this record says the outcome list is not floored",
    waiting: "an absence nobody is waiting to fill",
    pendingSays: "report-outcome list is absent",
    heldTo: "its own shape, since minice-be supplies it and nothing in this repository lists it",
    find: (doc) => {
      const hits = (Array.isArray(doc.entries) ? doc.entries : []).filter((e) => e && e.id === OUTCOME_LIST);
      if (hits.length > 1) {
        return { problems: [`${TOKEN_FILE} carries ${hits.length} entries \`${OUTCOME_LIST}\`, and a reader of the first ` +
          `cannot know the others say something different`] };
      }
      return hits.length ? { value: hits[0], at: `the entry \`${OUTCOME_LIST}\`` } : { absent: true };
    },
    absent: null,
    pending: () => false,
    whilePending: (doc) => {
      const states = (Array.isArray(doc.entries) ? doc.entries : []).find((e) => e && e.id === REPORT_STATES);
      return states && Array.isArray(states.values) && states.values.length >= 4 ? [] : [
        `${TOKEN_FILE} lists no ${REPORT_STATES} with B.3's four report states, and the report-outcome record's floor ` +
        `says the client's floor is written for those states alone until the outcome list lands`,
      ];
    },
    judge: (entry) => outcomeListShape(entry),
  },
};

/**
 * Whether one pending member holds its record's floor and, once recorded,
 * agrees with this repository, as `{state, problems, notes}`. `state` is
 * "pending", "recorded", or "absent" when a member that must be present is
 * not. An empty `problems` is agreement; `notes` are said, not judged.
 *
 * @param {object} doc the parsed token file
 * @param {object} row one of PENDING_MEMBERS
 * @param {object} ctx what the row's `judge` compares with
 */
function pendingJoin(doc, row, ctx) {
  const problems = [];
  const records = (Array.isArray(doc.pending) ? doc.pending : []).filter((p) => p && p.id === row.id);
  const found = row.find(doc);
  if (found.problems) return { state: "recorded", problems: found.problems, notes: [] };
  if (found.absent && row.absent !== null) {
    problems.push(row.absent);
    return { state: "absent", problems, notes: [] };
  }
  if (found.absent || row.pending(found.value)) {
    if (records.length === 0) {
      problems.push(
        `${TOKEN_FILE}'s ${row.pendingSays} and the file carries no pending record for it, so nothing ` +
        `says ${row.what} is owed, by whom, or when. The record's floor is "${row.floor}"; a regeneration that ` +
        `drops the record has to record ${row.what}`);
    } else if (records.length > 1) {
      problems.push(
        `${TOKEN_FILE} carries ${records.length} pending records with id \`${row.id}\`, and a reader ` +
        `finding the first one cannot know the others say something different`);
    }
    for (const r of records) {
      for (const key of ["owed_by", "lands_with"]) {
        if (!(typeof r[key] === "string" && r[key].trim() !== "")) {
          problems.push(
            `${TOKEN_FILE}'s pending record \`${row.id}\` has no \`${key}\`, so it does not say ` +
            `${key === "owed_by" ? row.owes : "which version lands it"}: a record that names nothing to ` +
            `wait on is ${row.waiting}`);
        }
      }
    }
    // A row may hold something else while its member is pending, and it is
    // asked in the pending state only: `fixed_reasons`' code entries carry no
    // string, nothing author CI compiles is retired on the strength of an empty
    // template list (contract 0.36.0; ops pending item 27).
    if (row.whilePending) problems.push(...row.whilePending(doc, ctx));
    return { state: "pending", problems, notes: [] };
  }
  const judged = row.judge(found.value, ctx, { ...found, doc });
  if (judged.malformed?.length) return { state: "recorded", problems: judged.malformed, notes: [] };
  problems.push(...judged.problems);
  if (records.length) {
    problems.push(
      `${TOKEN_FILE} records ${found.at} ${JSON.stringify(found.value)} and still carries its pending record ` +
      `\`${row.id}\` saying ${row.what} is owed. Once the value is recorded, and held to ${row.heldTo}, the record ` +
      `has outlived its reason; the ops generator drops a pending record when it writes the value, and this one ` +
      `was not dropped`);
  }
  return { state: "recorded", problems, notes: judged.notes ?? [] };
}

/** AT's name for the staging row's join, which its two tests above call. */
const stagingIdJoin = (doc, reserved) => pendingJoin(doc, PENDING_MEMBERS[STAGING_MEMBER], { reserved });

/** A synthesised leg's "delete this member" value. */
const ABSENT = Symbol("absent");

/** A pending record for a test to use once the file no longer carries one. */
const builtRecord = (id, floor) => ({
  id, what: `the ${id} (built by this test)`, owed_by: "(built by this test)",
  lands_with: "(built by this test)", floor,
});

/**
 * The synthesised legs that did not come out as written, as sentences. A leg
 * is `{name, doc, red, state?, noted?}`: `red` empty means green, otherwise
 * every string in it must appear in the problems; `state` and `noted`, when
 * given, are held too, so a green leg cannot be green for the wrong reason.
 */
function legsGoneWrong(legs, join) {
  const wrong = [];
  for (const leg of legs) {
    const { state, problems, notes = [] } = join(leg.doc);
    const said = problems.join("\n");
    if (leg.red.length === 0) {
      if (problems.length) wrong.push(`${leg.name}: expected green, was red: ${said}`);
      else if (leg.state && state !== leg.state) wrong.push(`${leg.name}: green, but read as ${state}, not ${leg.state}`);
      const unsaid = (leg.noted || []).filter((s) => !notes.some((n) => n.includes(s)));
      if (unsaid.length) wrong.push(`${leg.name}: green, but its note does not name ${unsaid.join(", ")}: ${JSON.stringify(notes)}`);
    } else if (!problems.length) {
      wrong.push(`${leg.name}: expected red, was green`);
    } else {
      const unnamed = leg.red.filter((s) => !said.includes(s));
      if (unnamed.length) wrong.push(`${leg.name}: red, but not naming ${unnamed.join(", ")}: ${said}`);
    }
  }
  return wrong;
}

/** Every committed file, and every directory above one, from a NUL-split listing. */
function trackedTree(listing) {
  const files = new Set(listing.filter(Boolean));
  const dirs = new Set();
  for (const f of files) {
    for (let i = f.indexOf("/"); i !== -1; i = f.indexOf("/", i + 1)) dirs.add(f.slice(0, i));
  }
  return { files, dirs };
}

/** Why `p` is not a repository-relative path, or null when it is one. */
function repoPathProblem(p) {
  if (typeof p !== "string") return "it is not a string";
  if (p === "") return "it is empty";
  if (p.startsWith("/")) return "it is absolute";
  if (p.includes("\\")) return "it carries a backslash";
  const segments = (p.endsWith("/") ? p.slice(0, -1) : p).split("/");
  if (segments.some((s) => s === "" || s === "." || s === "..")) return "it has an empty, `.` or `..` segment";
  const odd = segments.find((s) => !/^[A-Za-z0-9._-]+$/.test(s));
  if (odd) return `its segment ${JSON.stringify(odd)} carries a character no committed corpus path uses`;
  return null;
}

/**
 * A recorded `shared_vector_paths`, against the tree. There is no list of the
 * shared corpora anywhere in this repository to equal, so the counterpart is
 * the tree itself: a file path must be committed, a directory path (trailing
 * `/`) must not name a file, and a directory not committed yet is said rather
 * than judged — `tests/results/` is created at R3 and recorded before R2.
 */
function vectorPathsAgainstTree(value, tracked) {
  if (!Array.isArray(value)) {
    return { malformed: [
      `${TOKEN_FILE}'s \`${VECTOR_MEMBER}\` is ${JSON.stringify(value)}, which is neither the empty list nor a list ` +
      `of paths. A party reading the shared corpora at a pinned registry commit takes each element as a path in ` +
      `this repository (§1.3 row 8.3)`,
    ] };
  }
  const malformed = [];
  const seen = new Set();
  value.forEach((p, i) => {
    const why = repoPathProblem(p);
    if (why) {
      malformed.push(`${TOKEN_FILE}'s \`${VECTOR_MEMBER}\`[${i}] is ${JSON.stringify(p)}, which is not a ` +
        `repository-relative path: ${why}`);
    } else if (seen.has(p)) {
      malformed.push(`${TOKEN_FILE}'s \`${VECTOR_MEMBER}\` names ${JSON.stringify(p)} twice, and a reader ` +
        `counting corpora counts one of them twice`);
    }
    seen.add(p);
  });
  if (malformed.length) return { malformed };
  const problems = [];
  const notes = [];
  for (const p of value) {
    if (p.endsWith("/")) {
      const dir = p.slice(0, -1);
      if (tracked.files.has(dir)) {
        problems.push(`${TOKEN_FILE}'s \`${VECTOR_MEMBER}\` names ${JSON.stringify(p)} as a directory and this ` +
          `repository commits a file at ${dir}`);
      } else if (!tracked.dirs.has(dir)) {
        notes.push(`${p} is not committed yet`);
      }
    } else if (!tracked.files.has(p)) {
      problems.push(tracked.dirs.has(p)
        ? `${TOKEN_FILE}'s \`${VECTOR_MEMBER}\` names ${JSON.stringify(p)} as a file, and this repository commits a ` +
          `directory there; a directory is written with its trailing \`/\``
        : `${TOKEN_FILE}'s \`${VECTOR_MEMBER}\` names ${JSON.stringify(p)} and this repository does not commit it. ` +
          `The corpora are read at a pinned registry commit by a party that is not this one (§1.3 row 8.3), so a ` +
          `path the file agrees and the tree lacks is a reader that fails there, or skips`);
    }
  }
  return { problems, notes };
}

/** Whether a token-file entry is MOD-54's: it says so in its id, name or source. */
function namesMod54(e) {
  return [e.id, e.name, e.source].some((s) => typeof s === "string" && /\bMOD-54\b/.test(s));
}

/**
 * MOD-54's report page in the token file, in either shape a version could
 * record it in: a `mod54_report_page` member, or a `page` entry naming MOD-54
 * (FLOW-77's is the model). Both at once, or two entries, is a page spelled
 * twice. Neither is the pending state — the record's floor says "absent".
 */
function findReportPage(doc) {
  const member = Object.hasOwn(doc, REPORT_RECORD);
  const pages = (Array.isArray(doc.entries) ? doc.entries : []).filter((e) => e && e.kind === "page" && namesMod54(e));
  if (member && pages.length) {
    return { problems: [
      `${TOKEN_FILE} spells MOD-54's report page twice, as a \`${REPORT_RECORD}\` member and as the page entry ` +
      `\`${pages[0].id}\`, and a reader of one cannot know the other says something different`,
    ] };
  }
  if (pages.length > 1) {
    return { problems: [
      `${TOKEN_FILE} carries ${pages.length} page entries naming MOD-54 (${pages.map((e) => `\`${e.id}\``).join(", ")}), ` +
      `and MOD-54 is one page`,
    ] };
  }
  if (member) return { value: doc[REPORT_RECORD], at: `\`${REPORT_RECORD}\`` };
  if (pages.length) return { value: pages[0], at: `the page entry \`${pages[0].id}\``, entry: true };
  return { absent: true };
}

/**
 * A page as "the page and its query parameters": `{origin, pathname, params}`,
 * `origin` null for a root-relative path, `params` the sorted names from its
 * own query string and from `query`. Null when it is neither a URL nor a path
 * from the root.
 */
function pageOf(text, query = []) {
  const absolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(text);
  if (!absolute && !text.startsWith("/")) return null;
  let u;
  try { u = new URL(text, "https://root-relative.invalid"); } catch { return null; }
  return { origin: absolute ? u.origin : null, pathname: u.pathname, params: [...new Set([...u.searchParams.keys(), ...query])].sort() };
}

/** `REPORT_PAGE` out of the preflight's bytes, or `{error}`. It must be defined exactly once, absolute. */
function reportPageOf(text) {
  const hits = [...text.matchAll(REPORT_PAGE_LINE)];
  if (hits.length !== 1) {
    return { error: `\`const REPORT_PAGE = "…";\` is defined ${hits.length} time(s), not once, so MOD-54's page as ` +
      `this repository spells it cannot be read and the token file's page has nothing to be held to` };
  }
  const page = pageOf(hits[0][1]);
  if (!page || page.origin === null) {
    return { error: `REPORT_PAGE is ${JSON.stringify(hits[0][1])}, which is not an absolute URL` };
  }
  return { url: hits[0][1], ...page };
}

/** A recorded MOD-54 page, against the preflight's `REPORT_PAGE`. */
function reportPageAgainstPreflight(value, want, found) {
  const isEntry = found.entry === true;
  let page;
  if (isEntry) {
    if (typeof value.url !== "string" || value.url === "") {
      return { malformed: [`${TOKEN_FILE}'s ${found.at} has no \`url\`, so it names no page`] };
    }
    if (value.query !== undefined && !(Array.isArray(value.query) && value.query.every((q) => typeof q === "string" && q))) {
      return { malformed: [`${TOKEN_FILE}'s ${found.at} has \`query\` ${JSON.stringify(value.query)}, which is not a ` +
        `list of parameter names`] };
    }
    page = pageOf(value.url, value.query ?? []);
  } else {
    if (typeof value !== "string" || value.trim() === "") {
      return { malformed: [`${TOKEN_FILE}'s ${found.at} is ${JSON.stringify(value)}, which is neither a page path ` +
        `nor a page URL`] };
    }
    page = pageOf(value);
  }
  const shown = JSON.stringify(isEntry ? { url: value.url, query: value.query } : value);
  if (!page) {
    return { malformed: [`${TOKEN_FILE}'s ${found.at} is ${shown}, which is neither a URL nor a root-relative path`] };
  }
  if (!page.pathname.startsWith("/plugins/_/")) {
    return { malformed: [`${TOKEN_FILE}'s ${found.at} is ${shown}, whose path ${page.pathname} is not under ` +
      "`/plugins/_/`, and MOD-54 says the report page is \"under `/plugins/_/`\""] };
  }
  const differs = [];
  if (page.pathname !== want.pathname) differs.push(`the path is ${page.pathname}, not ${want.pathname}`);
  if (page.params.join(",") !== want.params.join(",")) {
    differs.push(`the parameters are ${JSON.stringify(page.params)}, not ${JSON.stringify(want.params)}`);
  }
  if (page.origin !== null && page.origin !== want.origin) differs.push(`the origin is ${page.origin}, not ${want.origin}`);
  if (!differs.length) return { problems: [] };
  return { problems: [
    `${TOKEN_FILE} records MOD-54's report page as ${found.at} ${shown}, and ${PREFLIGHT_FILE}'s REPORT_PAGE is ` +
    `${JSON.stringify(want.url)}: ${differs.join("; ")}. The preflight's mod-54-report-page check sends an ` +
    `operator to walk its page before R6, and the panel serves the one this file names, so a disagreement is a ` +
    `walk of one page and a gate passed on another. One of the two is wrong`,
  ] };
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

/** The code entries that carry a `fixed_reason` beside the member. */
function fixedCarriers(doc) {
  return (Array.isArray(doc.entries) ? doc.entries : []).filter((e) => e && Object.hasOwn(e, "fixed_reason"));
}

/** While `fixed_reasons` is null, no code entry may carry a string, and each points at this record. */
function fixedCarriersWhilePending(doc) {
  const problems = [];
  for (const e of fixedCarriers(doc)) {
    if (e.fixed_reason !== null) {
      problems.push(
        `${TOKEN_FILE}'s entry \`${e.id}\` carries fixed_reason ${JSON.stringify(e.fixed_reason)} while ` +
        `\`${FIXED_MEMBER}\` is null: a string the file's own record says nobody has written, which fixedReason never ` +
        `reads and a reader of the entry takes as published`);
    }
    if (Object.hasOwn(e, "fixed_reason_pending") && e.fixed_reason_pending !== FIXED_MEMBER) {
      problems.push(
        `${TOKEN_FILE}'s entry \`${e.id}\` has fixed_reason_pending ${JSON.stringify(e.fixed_reason_pending)}, and the ` +
        `record that owes its string is \`${FIXED_MEMBER}\``);
    }
  }
  return problems;
}

/**
 * A recorded `fixed_reasons`, against the codes this repository asks it for:
 * `AUTHOR_CODES`, the codes `fixedReason` is called with, and nothing else —
 * and against the code entries, so the string is spelled once.
 */
function fixedReasonsAgainstCodes(value, doc) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { malformed: [
      `${TOKEN_FILE}'s \`${FIXED_MEMBER}\` is ${JSON.stringify(value)}, which is neither null nor an object of one ` +
      `string per author code`,
    ] };
  }
  const malformed = Object.entries(value)
    .filter(([, s]) => typeof s !== "string" || s.trim() === "")
    .map(([code, s]) => `${TOKEN_FILE}'s \`${FIXED_MEMBER}\`.${code} is ${JSON.stringify(s)}, not a non-empty string`);
  if (malformed.length) return { malformed };
  const problems = [];
  const have = Object.keys(value).sort();
  const want = [...AUTHOR_CODES].sort();
  const missing = want.filter((c) => !have.includes(c));
  const extra = have.filter((c) => !want.includes(c));
  if (missing.length || extra.length) {
    problems.push(
      `${TOKEN_FILE}'s \`${FIXED_MEMBER}\` records ${have.join(", ") || "no code"}, and bot/lib/compile-decision.mjs's ` +
      `AUTHOR_CODES, the codes fixedReason is asked for, are ${want.join(", ")}` +
      (missing.length ? `: no string for ${missing.join(", ")}, so a moderation compile throws on that author action` : "") +
      (extra.length ? `: ${extra.join(", ")} is a code the registry never asks a fixed reason for` : ""));
  }
  for (const e of fixedCarriers(doc)) {
    const pointing = Object.hasOwn(e, "fixed_reason_pending");
    if (e.fixed_reason !== value[e.name] || pointing) {
      problems.push(
        `${TOKEN_FILE}'s entry \`${e.id}\` carries fixed_reason ${JSON.stringify(e.fixed_reason)}` +
        `${pointing ? ` and still points at ${JSON.stringify(e.fixed_reason_pending)}` : ""}, and \`${FIXED_MEMBER}\` ` +
        `records ${JSON.stringify(value[e.name] ?? null)}: the string is spelled twice, and a reader of one cannot know ` +
        `the other says something different`);
    }
  }
  return { problems };
}

/** The entries author CI compiles: an audience it emits, and an operation it calls. */
function authorCompiled(doc) {
  return (Array.isArray(doc.entries) ? doc.entries : []).filter((e) => e &&
    (e.kind === "audience" || e.kind === "operation") && Array.isArray(e.emitter) && e.emitter.includes("author-ci"));
}

/** SCOPE-7's five states, `until <step>` as the generator writes it. */
const isTokenState = (s) => ["live", "reserved", "service-only", "retired"].includes(s) || /^until R[0-9]+[ab]?$/.test(s);

/**
 * A recorded template list, against this file's own entries: each template
 * names an author audience and an author-notify operation the file lists, and
 * ID-73 forbids marking either `retired` while a listed template compiles it.
 */
function templatesAgainstEntries(value, doc) {
  if (!Array.isArray(value)) {
    return { malformed: [
      `${TOKEN_FILE}'s \`${TEMPLATES_MEMBER}\` is ${JSON.stringify(value)}, which is neither the empty list nor a list ` +
      `of templates`,
    ] };
  }
  const malformed = [];
  const seen = new Set();
  value.forEach((t, i) => {
    for (const k of ["version", "state"]) {
      if (!(t && typeof t[k] === "string" && t[k].trim() !== "")) {
        malformed.push(`${TOKEN_FILE}'s \`${TEMPLATES_MEMBER}\`[${i}] has no \`${k}\`; SCOPE-7 lists each template with ` +
          `the author audience and author-notify path it compiles, and its state`);
      }
    }
    // What a template compiles is a value or `null`, and `null` is a statement:
    // it compiles none. Template 1, `init-ci`'s caller, compiles neither — its
    // AstraPlugins test `the_generated_caller_calls_nothing_but_the_reusable_workflow`
    // and C25 hold that — so a judge that took only strings could not accept the
    // one true entry the list has (registry plan AP-24: "both `null` for version
    // 1"). Absent is still refused: absence says nothing, and the reader of ID-73
    // has to be told.
    for (const k of ["audience", "notify_path"]) {
      if (!(t && Object.hasOwn(t, k) && (t[k] === null || (typeof t[k] === "string" && t[k].trim() !== "")))) {
        malformed.push(`${TOKEN_FILE}'s \`${TEMPLATES_MEMBER}\`[${i}] has no \`${k}\`; SCOPE-7 lists each template with ` +
          `the author audience and author-notify path it compiles, as a value or \`null\` when it compiles none`);
      }
    }
    if (t && typeof t.state === "string" && t.state.trim() !== "" && !isTokenState(t.state)) {
      malformed.push(`${TOKEN_FILE}'s \`${TEMPLATES_MEMBER}\`[${i}] has state ${JSON.stringify(t.state)}, which is not ` +
        `one of SCOPE-7's five`);
    }
    if (t && typeof t.version === "string") {
      if (seen.has(t.version)) malformed.push(`${TOKEN_FILE}'s \`${TEMPLATES_MEMBER}\` lists version ${JSON.stringify(t.version)} twice`);
      seen.add(t.version);
    }
  });
  if (malformed.length) return { malformed };
  const compiled = authorCompiled(doc);
  const problems = [];
  for (const t of value) {
    const aud = t.audience === null ? null
      : compiled.find((e) => e.kind === "audience" && (e.value === t.audience || e.name === t.audience));
    const op = t.notify_path === null ? null
      : compiled.find((e) => e.kind === "operation" && e.path === t.notify_path);
    if (t.audience !== null && !aud) {
      problems.push(`${TOKEN_FILE}'s template ${JSON.stringify(t.version)} compiles audience ${JSON.stringify(t.audience)}, ` +
        `and the file lists no author audience by that value or name`);
    }
    if (t.notify_path !== null && !op) {
      problems.push(`${TOKEN_FILE}'s template ${JSON.stringify(t.version)} calls notify path ${JSON.stringify(t.notify_path)}, ` +
        `and the file lists no author-CI operation at that path`);
    }
    for (const e of [aud, op].filter(Boolean)) {
      if (e.state === "retired") {
        problems.push(`${TOKEN_FILE} marks \`${e.id}\` retired while template ${JSON.stringify(t.version)} is listed as ` +
          `compiling it: ID-73 forbids marking an author audience or the author-notify path retired while any listed ` +
          `template compiles it`);
      }
    }
  }
  return { problems };
}

/** A recorded FLOW-13 table, against `tools/codes-table.json`'s, rows and source. */
function flow13AgainstCodes(value, codesTable, doc) {
  if (!Array.isArray(value)) {
    return { malformed: [
      `${TOKEN_FILE}'s \`${FLOW13_MEMBER}\` is ${JSON.stringify(value).slice(0, 80)}, which is neither null nor a list of rows`,
    ] };
  }
  const want = codesTable.flow13_table;
  const problems = [];
  if (JSON.stringify(value) !== JSON.stringify(want)) {
    const byCode = (rows) => new Map((Array.isArray(rows) ? rows : []).map((r) => [r?.code, JSON.stringify(r)]));
    const a = byCode(value);
    const b = byCode(want);
    const differ = [...new Set([...a.keys(), ...b.keys()])].filter((c) => a.get(c) !== b.get(c));
    problems.push(differ.length
      ? `${TOKEN_FILE}'s \`${FLOW13_MEMBER}\` and ${CODES_FILE}'s differ at ${differ.length} code(s), first ` +
        `${differ.slice(0, 5).join(", ")}. The ops generator merges ${CODES_FILE} as it stands, so the file was ` +
        `generated from another table, or edited after it was generated`
      : `${TOKEN_FILE}'s \`${FLOW13_MEMBER}\` carries ${CODES_FILE}'s rows in another order, and the ops generator ` +
        `merges them in the order the table gives, so the file was not generated from this table`);
  }
  const src = { codes_source: codesTable.codes_source, codes: Array.isArray(codesTable.codes) ? codesTable.codes.length : null };
  if (JSON.stringify(doc.flow13_source) !== JSON.stringify(src)) {
    problems.push(`${TOKEN_FILE}'s flow13_source is ${JSON.stringify(doc.flow13_source)}, and ${CODES_FILE} gives ` +
      `${JSON.stringify(src)}`);
  }
  return { problems };
}

/** A recorded report-outcome list: a list of codes, each a distinct non-empty string. */
function outcomeListShape(entry) {
  const values = entry?.values;
  if (!Array.isArray(values) || values.length === 0) {
    return { malformed: [`${TOKEN_FILE}'s entry \`${OUTCOME_LIST}\` lists no code, and an empty vocabulary is not the ` +
      `list minice-be supplies`] };
  }
  const malformed = [];
  const seen = new Set();
  values.forEach((v, i) => {
    if (typeof v !== "string" || v.trim() === "") {
      malformed.push(`${TOKEN_FILE}'s entry \`${OUTCOME_LIST}\` value ${i} is ${JSON.stringify(v)}, not a non-empty string`);
    } else if (seen.has(v)) {
      malformed.push(`${TOKEN_FILE}'s entry \`${OUTCOME_LIST}\` lists ${JSON.stringify(v)} twice`);
    }
    seen.add(v);
  });
  return malformed.length ? { malformed } : { problems: [] };
}

/**
 * `test(` titles in a module's text, as literals, comments blanked: the same
 * reading `tools/selftest.mjs` gives a module (its TEST_OPENING), so a name
 * this finds is a check that runner prints. A template-literal title with an
 * interpolation is not a name anything can equal, and is left out.
 */
const TEST_OPENING = /\btest\(\s*(["'`])((?:\\[\s\S]|(?!\1)[^\\])*)\1\s*,/g;
function testTitlesIn(text) {
  const code = text.split("\n").map((l) => {
    if (/^\s*(\/\/|\/?\*)/.test(l)) return " ".repeat(l.length);
    const c = l.search(/\s\/\/.*$/);
    return c < 0 ? l : l.slice(0, c) + " ".repeat(l.length - c);
  }).join("\n");
  return [...code.matchAll(TEST_OPENING)]
    .filter((m) => !(m[1] === "`" && m[2].includes("${")))
    .map((m) => m[2].replace(/\\([\s\S])/g, "$1"));
}

/**
 * Every problem with the file's `asserted_by` members (contract 0.36.0,
 * SCOPE-7). `textOf(rel)` gives a committed module's text or null;
 * `committedModules` is the set of paths committed under `tools/selftest/`.
 */
function assertedByProblems(doc, { textOf, committedModules }) {
  const problems = [];
  const titles = new Map();
  const titlesOf = (rel) => {
    if (!titles.has(rel)) {
      const t = textOf(rel);
      titles.set(rel, t === null ? [] : testTitlesIn(t));
    }
    return titles.get(rel);
  };
  for (const r of Array.isArray(doc.pending) ? doc.pending : []) {
    const id = r && typeof r.id === "string" ? r.id : JSON.stringify(r?.id);
    const v = r?.asserted_by;
    if (v === undefined || v === null || v === "") {
      problems.push(
        `${TOKEN_FILE}'s pending record \`${id}\` has no \`asserted_by\`, so nothing in the file says which check holds ` +
        `its floor (${JSON.stringify(r?.floor ?? null)}). SCOPE-7 requires one from contract 0.36.0 and the ops generator ` +
        `refuses to emit a record without it, so this file was not written by that generator from 0.36.0 on`);
      continue;
    }
    const m = typeof v === "string" ? ASSERTED_BY.exec(v) : null;
    if (!m) {
      problems.push(
        `${TOKEN_FILE}'s pending record \`${id}\` has \`asserted_by\` ${JSON.stringify(v)}, which is not ` +
        "`astra-registry:tools/selftest/<module>.mjs#<check name>` (SCOPE-7): the check that holds a floor over the " +
        "committed file is one this repository's suite runs, named character for character");
      continue;
    }
    const [, rel, name] = m;
    if (!committedModules.has(rel)) {
      problems.push(
        `${TOKEN_FILE}'s pending record \`${id}\` names ${rel}, and this repository does not commit that module, so ` +
        `no suite runs the check it names`);
    } else {
      const n = titlesOf(rel).filter((t) => t === name).length;
      if (n === 0) {
        problems.push(
          `${TOKEN_FILE}'s pending record \`${id}\` names no check that ${rel} runs: ${JSON.stringify(name)} is the title ` +
          `of none of its ${titlesOf(rel).length} check(s). A check renamed and a floor claimed for a check nobody wrote ` +
          `read the same from outside`);
      } else if (n > 1) {
        problems.push(
          `${TOKEN_FILE}'s pending record \`${id}\` names ${JSON.stringify(name)}, which is the title of ${n} checks in ` +
          `${rel}, so it names no one check`);
      }
    }
    const row = PENDING_MEMBERS[r?.id];
    if (row && v !== `${ASSERTED_BY_THIS}${row.check}`) {
      problems.push(
        `${TOKEN_FILE}'s pending record \`${id}\` names ${JSON.stringify(v)}, and that is not the check that holds its ` +
        `floor here, ${JSON.stringify(`${ASSERTED_BY_THIS}${row.check}`)}: a record pointing at some other check passes ` +
        `an existence test and asserts nothing about its own floor`);
    }
  }
  return problems;
}

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
    env: cleanEnv(),
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
