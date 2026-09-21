// `schema/contract-tokens-v1.json`'s own discipline: the version it names, and
// the schedule intervals it is one end of (RC-R2-2; SCOPE-1; SCOPE-2; BOT-51;
// BOT-83).
//
// The file is written by `astra-plugins-ops`' generator out of the contract and
// committed here. That makes this repository the one that holds it and the one
// that can be asked, on every push and every pull request, two questions the
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

import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

const TOKEN_FILE = "schema/contract-tokens-v1.json";
const WORKFLOW_HALF = "bot/tests/workflows.test.mjs";
const BOT_TESTS_WORKFLOW = ".github/workflows/bot-tests.yml";

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

    // A shallow checkout has no parent, and that is a question this rule could
    // not ask rather than a rule it passed. `build-index.yml` checks out with
    // `fetch-depth: 0` and is where this suite's answer counts; `baseline.yml`
    // takes the default depth of 1 and will land here.
    const parent = (() => {
      try { return git(["rev-parse", "--verify", "HEAD^{commit}~1"]).trim(); } catch { return null; }
    })();
    if (!parent) {
      console.log(
        `  note  HEAD has no reachable parent in this checkout (a shallow clone, or the first commit), so ` +
        `"did the tokens move without the version" COULD NOT BE ASKED this run. It is asked wherever the ` +
        `suite runs on a full history — build-index.yml checks out with fetch-depth: 0.`,
      );
      return;
    }

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
      `${TOKEN_FILE}'s tokens changed between ${parent.slice(0, 7)} and HEAD and contract_version did not rise: ` +
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
