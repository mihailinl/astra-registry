// TRUST-31's hashed code paths, and the one thing a path list cannot say about
// itself: whether the code the workflows actually reach is inside it.
//
// Contract 0.20.0 publishes the set (OPEN-OPS-5, bot half; registry plan
// B-T3.10). From R3 the plugins service diffs the tree at a bot token's
// `job_workflow_sha` against the last acknowledged one, restricted to these
// paths, and drops the bot into shadow on any difference. Two failures follow
// from a set that is wrong, and they point in opposite directions:
//
//   * a path INSIDE the set that the bot writes as it works — a decision
//     record, an advisory, a queue entry — re-shadows the bot for doing its
//     job, and every withdrawal it was carrying stops reaching installed
//     copies until an operator acknowledges a commit nobody meant to make;
//   * a path OUTSIDE the set that a bot run READS — a module, a policy file, a
//     composite action — is a change to what the registry decides that the
//     service cannot see, which is the whole substitution TRUST-31 exists to
//     refuse.
//
// The first is loud. The second is silent, and it is the one this file is
// mostly about: `(b)` walks out from the two workflow files to every module,
// composite action and spawned script a run can reach, and fails on a target
// the set does not name.
//
// **The set's definition lives here, in `bot/tests/`, which is OUTSIDE the
// set, and that is deliberate.** Editing the list must not itself be a hashed-
// path commit: changing what TRUST-31 covers is a contract MINOR under
// SCOPE-1, published before the tree moves, not a change the service discovers
// as a shadow transition. A definition that lived in `bot/lib/` would put
// every widening of the set into the thing being widened.
//
// The set hash this file prints is what a TRUST-42 acknowledgement names
// beside the `job_workflow_sha` (registry plan: ROLL-64, step 2). It is a
// value rather than a description of one, so two people can compare it.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
const git = (...args) =>
  execFileSync("git", args, { cwd: REPO, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });

// ── the set, exactly as contract 0.21.0's TRUST-31 publishes it ─────────────
//
// Order matters only for the one exception: `schema/contract-tokens-v1.json`
// is generated FROM the contract, so a contract version would otherwise be a
// shadow transition, and every party would re-acknowledge the registry for a
// document it had just agreed to.

const WORKFLOWS = [
  ".github/workflows/plugins-ingest.yml",
  ".github/workflows/plugins-moderation.yml",
];

// **Literal paths, and nothing else**, to a grammar rather than a blocklist:
// segments of `A-Za-z0-9._-` joined by `/`, at most one trailing `/` marking a
// directory, never absolute and never a `.` or `..` segment. The reason is not
// tidiness, and it is not that globs are ugly.
//
// The service resolves each entry with a literal tree lookup, and compares the
// entry's id at the acknowledged commit with its id at the presented one. An
// entry that resolves to NOTHING at both compares equal, which is right for a
// path that was deleted between the two — and for a path that can never exist
// it makes the entry check nothing, for ever, in the PERMISSIVE direction,
// while the published set reads as though it covered it. `tools/selftest/**`
// was the spelling first published here, and it would have reintroduced
// exactly the hole this file had just found: a selftest edited to exit 0,
// running as the publish path's fifth gate, with the bot staying live.
//
// Two careful rules composed into it. The service's own entry check refuses an
// absolute path, a `..`, an empty entry and whitespace — each correct, and a
// glob passes all four; the `None == None` comparison is correct for a real
// path. Neither rule is wrong. The class was already named in that function's
// own doc comment — "a list entry that silently checks nothing" — and the
// spelling was not.
//
// A directory entry compares that directory's TREE id, which is already a
// recursive hash, so `.github/actions/` covers every file beneath it for ever,
// including files added later. The glob was never buying anything.
//
// Two groups are enumerated file by file, because no directory spells them:
// `bot/` also holds records, fixtures and tests that must stay OUTSIDE, and
// `schema/` holds `contract-tokens-v1.json`, which is generated from the
// contract and would make every contract version a shadow transition. Adding a
// top-level bot entry point, or a schema to that group, is a contract MINOR
// published BEFORE the file lands — which is the right cost, and which the two
// tests below make loud rather than leaving to a reader. **The cost is stated
// without an ordinal on purpose**: this comment used to say "a nineteenth … or a
// twelfth", 0.23.0 published both, and the sentence went on naming the release
// before last as the next one.
export const ENTRIES = [
  ...WORKFLOWS,
  ".github/actions/",
  "bot/alert.mjs",
  "bot/asset-check.mjs",
  "bot/baseline.mjs",
  "bot/check-roots.mjs",
  "bot/decide.mjs",
  "bot/detectors.mjs",
  "bot/export-issues.mjs",
  "bot/gen-checks-doc.mjs",
  "bot/heartbeat.mjs",
  "bot/ingest.mjs",
  // Contract 0.23.0's, and the first entry to arrive through the cost the two
  // tests below state rather than before it: `bot/moderation-run.mjs` is the
  // nineteenth top-level entry point, and the moderation workflow's `list`,
  // `alert`, `commit`, `report` and `settled` jobs all run it.
  "bot/moderation-run.mjs",
  "bot/moderation.mjs",
  "bot/publish-apply.mjs",
  "bot/read-submission.mjs",
  "bot/recheck-publishers.mjs",
  "bot/run-checks.mjs",
  "bot/sign-index.mjs",
  "bot/triage.mjs",
  "bot/watch.mjs",
  "bot/lib/",
  "bot/policy/",
  "bot/manifest-probe/",
  "tools/lib/",
  "tools/validate.mjs",
  "tools/build-index.mjs",
  "tools/build-revocations.mjs",
  // `tools/selftest.mjs` and its cases. The plan's first draft of this set put
  // them under "tests and fixtures", outside — and `bot/publish-apply.mjs:480`
  // runs `execFileSync(process.execPath, ["tools/selftest.mjs"])` with
  // `stdio: "inherit"` as the last of five registry checks a publication must
  // pass. The cases are covered by the DIRECTORY and not through the import
  // walk, because `tools/selftest.mjs:107` loads them with
  // `import(\`./selftest/${name}\`)` — a dynamic specifier no static closure
  // can follow.
  "tools/selftest.mjs",
  "tools/selftest/",
  "policy/limits.json",
  // Contract 0.21.0. The same finding as `tools/selftest.mjs`, one gate
  // EARLIER: `tools/validate.mjs` — the first of the five checks
  // `bot/publish-apply.mjs` runs before it commits — imports
  // `bot/lib/decisions.mjs`, which takes `DOCUMENT_MEMBERS`, `roleAddresses`,
  // `scanDocument` and `shapeFindings` from `tools/priv-scan.mjs`. PRIV-2's
  // member table and shape rules, which decide what a decision record may
  // contain, were outside the set while the bot wrote records by them.
  // `tools/priv-scan.mjs` imports `tools/coverage/rules.mjs`, and
  // `tools/coverage/git.mjs` comes with it.
  //
  // `tools/coverage/` is ENUMERATED and not taken whole: `docs-advisory-url`,
  // `keepalive-age` and `reserved-id-mirror` are rule reporters only the desk
  // tools run, and `priv-scan-exempt.json` is read by `loadExemptions`, the
  // standalone history walk's entry point, which is not among the four symbols
  // the decision writer imports. A directory entry is right when everything
  // beneath it belongs; here four of six do not. What makes enumerating safe
  // is leg (b): a file under `tools/coverage/` that a bot run starts reaching
  // fails there, by name, the day it does.
  "tools/priv-scan.mjs",
  "tools/coverage/rules.mjs",
  "tools/coverage/git.mjs",
  "policy/reserved-ids.json",
  "policy/spdx-allowlist.json",
  "policy/listing-language-exemptions.json",
  "schema/cutover-v1.json",
  "schema/deadline-v1.json",
  // B-T2.1's three, added by contract 0.21.0. `tools/lib/sources.mjs`'s
  // `loadSchemas` loads all eleven by literal path and `tools/validate.mjs`
  // judges records against them — from THIS repository, never from the tree
  // under test, so that `--registry-dir` cannot supply the rules it is judged
  // by. That is what makes them gate inputs rather than documents.
  "schema/decision-v1.json",
  "schema/hold-record-v1.json",
  "schema/hold-v1.json",
  "schema/identity-v1.json",
  "schema/index-v1.json",
  // Contract 0.23.0's, and the one entry under `schema/` that is not a record
  // schema: it is the registry's check of the SERVICE's own
  // `astra.plugins.bot-moderation-work/1` answer, read by
  // `bot/moderation-run.mjs` by literal path. A writer who could edit it from
  // outside the set could widen what a moderation run accepts from the service
  // — and compile an advisory out of an entry nobody validated — without the
  // bot returning to shadow.
  "schema/moderation-work-v1.json",
  "schema/plugin-v1.json",
  "schema/publisher-v1.json",
  "schema/queue-v1.json",
  "schema/version-v1.json",
];

/** Is this repository-relative path inside TRUST-31's hashed set? */
export function inSet(p) {
  return ENTRIES.some((e) => (e.endsWith("/") ? p.startsWith(e) : p === e));
}

const tracked = () => git("ls-tree", "-r", "--name-only", "HEAD").split("\n").filter(Boolean);

// **A grammar, not a blocklist**, and the reason is the second instance in one
// night of the shape this file already records.
//
// The first version of this test refused `*`, `?` and `[`, an absolute path, a
// `..` and whitespace — and said it closed the class. It closed six spellings.
// A control character passes all six and makes the service's loader refuse the
// WHOLE list; so would a spelling nobody has thought of. That is the same
// error as the one that put `tools/selftest/**` into the set — *the author saw
// the class and did not see the spelling* — arriving one level up, at the
// check written to hold it. Both times the fix was to stop enumerating what is
// forbidden and state what is allowed.
//
// So: an entry is one or more segments joined by `/`, each segment one or more
// of `A-Za-z0-9._-`, with an optional single trailing `/` marking a directory.
// Never absolute, never a `.` or `..` segment, never an empty one. That is a
// statement about what an entry IS, so the service's validator and this fence
// agree by construction rather than by coincidence.
//
// The character class alone would not do it: `^[A-Za-z0-9._/-]+$` admits
// `/bot/lib/`, which their loader rejects outright as absolute, and `a//b`,
// whose empty segment resolves to nothing. The segment walk below covers both.
export const ENTRY_SEGMENT = /^[A-Za-z0-9._-]+$/;

/** Why this entry is not a well-formed path, or null. */
export function entryProblem(e) {
  if (typeof e !== "string" || e === "") return "empty";
  if (e.startsWith("/")) return "absolute; their loader rejects it and refuses the whole list";
  const segs = e.split("/");
  if (segs[segs.length - 1] === "") segs.pop(); // one trailing `/` marks a directory
  if (!segs.length) return "no segments";
  for (const s of segs) {
    if (s === "") return "carries an empty segment (`//`), which resolves to nothing";
    if (s === "." || s === "..") return `carries a \`${s}\` segment`;
    if (!ENTRY_SEGMENT.test(s)) {
      return `segment ${JSON.stringify(s)} is outside the grammar ${ENTRY_SEGMENT} — a glob character, ` +
        `a space, a backtick or a control character is all the same failure here`;
    }
  }
  return null;
}

test("every entry is a well-formed path, and one bad entry refuses the whole set", () => {
  // The mirror of the service's own `TrackedPaths::new`, which refuses the
  // WHOLE list rather than dropping the offending entry — a set that silently
  // lost a member is narrower than the one an operator acknowledged. This test
  // collects every bad entry and reports them together, for the same reason.
  const bad = [];
  for (const e of ENTRIES) {
    const why = entryProblem(e);
    if (why) bad.push(`${JSON.stringify(e)} — ${why}`);
  }
  assert.deepEqual(bad, [], "TRUST-31's set would be refused whole by a party that compiles it");
  assert.equal(new Set(ENTRIES).size, ENTRIES.length, "a duplicated entry");

  // The grammar is asserted to still refuse the spellings that have actually
  // arrived, so that widening it later is a deliberate act and not a typo in a
  // regex. A glob, a control character, an absolute path, a climb, a space.
  // The control character is written as an escape on purpose: a literal one
  // in a source file is invisible, which is the property that makes this
  // whole class hard to see in the first place.
  for (const e of ["tools/selftest/**", "bot/lib/\u0007x.mjs", "/bot/lib/", "bot/../etc",
                   "bot/ lib/", "bot//lib/", "bot/./lib/", "bot/lib/`x`.mjs"]) {
    assert.ok(entryProblem(e), `${JSON.stringify(e)} must not be a well-formed entry`);
  }
  assert.equal(entryProblem("bot/lib/"), null);
  assert.equal(entryProblem("bot/alert.mjs"), null);
});

// An entry may legitimately name a path that is not on the tree yet, and the
// distinction is the whole of the finding rather than an exception to it.
// `None == None` is SAFE for a path that WILL exist: the commit that creates
// it turns `None` into a tree id, which is a difference, which is a shadow
// transition — the entry starts working at exactly the right moment.
//
// It is unsafe for an entry that can NEVER resolve. A pattern is ONE MEMBER of
// that class and contract 0.20.0 wrote it as though it were the class; 0.21.0
// strikes that. **A misspelling is the same class and is not a pattern.**
// `bot/lib/idenity.mjs` passes every check above — not absolute, no `..`, not
// empty, no whitespace, no glob character — reads as deliberate and correctly
// spelled, and compares equal for ever while `bot/lib/identity.mjs` is covered
// by nothing.
//
// The row below is what makes "not yet" distinguishable from "never", and a
// row with only a task name is not enough: a false excuse is indistinguishable
// from a real pending file and INHERITS the shelter built for a real one. So
// each row carries, beside the owning task, a landing condition observable
// from the tree — the rollout step whose exit marker must not appear before
// the file does. It is the shape `tools/contract-tokens.mjs`'s pending records
// already use, where each names the contract version that lands it and a probe
// that fires when the reason closes.
//
// Three checks hang off it, and they close different halves:
//
//   * the row dies when the file arrives (a real excuse cannot outlive its
//     reason and shelter the next entry that names nothing);
//   * the row dies when its step exits without the file (an excuse with no
//     expiry is permanent shelter);
//   * an unresolved entry that is one or two edits from a path that DOES
//     exist is a FAILURE when nothing claims it is pending, and a WARNING
//     naming both the row and the near path when something does. That is the
//     leg that catches a typo today, without waiting for a marker — and the
//     split is why it needs no exception list, which would be a new shelter.
//
// **It is empty, and it is empty because the one row it ever held did what a
// row is for.** `.github/workflows/plugins-moderation.yml` was excused by
// M-T3.4 until R3; M-T3.4 landed it, and the third assertion below — *the row
// dies when the file arrives* — is what turns leaving the row behind into a
// failure rather than into shelter the next entry inherits. An empty map is
// therefore the correct state and not a deleted check: every assertion in the
// test still runs, the `empty` list above it is what does the work while
// nothing is pending, and the next entry that names a path not yet on the
// tree writes its row here with a task and a step.
const UNRESOLVED_BY = new Map([]);

/** Edit distance, with an early exit: anything over `max` is just "far". */
function editDistance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = [...Array(b.length + 1).keys()];
  for (let i = 1; i <= a.length; i += 1) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j += 1) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (cur[j] < best) best = cur[j];
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

/** Which rollout steps have exited, read off the tree and never declared. */
function exitedSteps(files) {
  const out = new Set();
  for (const f of files) {
    const m = /^log\/rollout\/([A-Za-z0-9]+)-exit\.json$/.exec(f);
    if (m) out.add(m[1]);
  }
  return out;
}

test("every entry resolves, or carries an excuse that expires", () => {
  // THE test that would have caught `tools/selftest/**` before it was
  // published. An entry naming nothing is not an entry that fails; it is an
  // entry that passes for ever, in the permissive direction, and a set full of
  // them looks exactly like a set that covers everything.
  const files = tracked();
  const resolves = (e) => (e.endsWith("/") ? files.some((f) => f.startsWith(e)) : files.includes(e));
  const empty = ENTRIES.filter((e) => !resolves(e) && !UNRESOLVED_BY.has(e));
  assert.deepEqual(
    empty,
    [],
    "an entry of TRUST-31's set resolves to nothing at HEAD and names nobody who will land it, so it " +
      "compares equal at every commit and checks nothing while the set reads as though it covered it",
  );

  const exited = exitedSteps(files);
  for (const [e, row] of UNRESOLVED_BY) {
    assert.ok(ENTRIES.includes(e), `${e} is excused as not-yet-landed and is not in the set at all`);
    assert.ok(row.by && row.why && row.due, `${e}'s excuse is missing a task, a reason or a due step`);
    assert.ok(
      !resolves(e),
      `${e} is on the tree now (${row.by}: ${row.why}); delete its UNRESOLVED_BY row, or the next entry ` +
        `that names nothing hides behind a row that stopped being true`,
    );
    assert.ok(
      !exited.has(row.due),
      `${e} is excused until ${row.due} and log/rollout/${row.due}-exit.json is on the tree, so that step ` +
        `exited without the file appearing. Either ${row.by} did not land what it owed, or this entry is a ` +
        `misspelling wearing a real task's name — which is the case this expiry exists to separate`,
    );
  }

  // The expiry has never fired, because no step has exited. That is a DERIVED
  // state, and it is asserted rather than assumed, or the loop above is
  // `if (true)` with a comment on it. Two instruments, because an absence is a
  // claim about the tool: `git ls-tree` over HEAD, and the working directory.
  if (exited.size === 0) {
    assert.equal(files.filter((f) => f.startsWith("log/rollout/")).length, 0);
    assert.equal(fs.existsSync(path.join(REPO, "log", "rollout")), false);
    console.log(
      `note  no rollout exit marker is on the tree, so ${UNRESOLVED_BY.size} excuse(s) have not expired: ` +
        `${[...UNRESOLVED_BY].map(([e, r]) => `${e} until ${r.due}`).join(", ")}.`,
    );
  }
});

test("an unresolved entry with no excuse is not a near-miss of a path that exists", () => {
  // The leg that catches a misspelling TODAY, without waiting for a rollout
  // marker. A pending file is normally nothing like an existing one; a typo is
  // one or two edits from it by construction.
  //
  // **It splits on whether the entry carries a row, and that split is part of
  // its correctness rather than a softening of it.** A legitimately pending
  // file can be one edit from an existing one BY CONSTRUCTION: sibling modules
  // are the normal case, and `bot/lib/decisions.mjs` exists while a pending
  // `bot/lib/decision.mjs` would be one edit away and entirely innocent. If
  // that were a failure, its only remedy would be an exception list — and an
  // exception list is a new shelter, which is the exact thing the expiry above
  // exists to prevent. A guard whose only remedy is an exemption has rebuilt
  // the hole it was closing.
  //
  // So: no row at all is a FAILURE — nothing claims the entry is pending, and
  // that is the `bot/lib/idenity.mjs` case. A valid row is a WARNING that
  // names BOTH the row and the near path, so a reader can see a typo wearing a
  // real task's name. The expiry stays the authority; this is the early
  // signal. No entry ever needs an exception to pass.
  const files = tracked();
  const resolves = (e) => (e.endsWith("/") ? files.some((f) => f.startsWith(e)) : files.includes(e));
  const fail = [];
  const warn = [];
  for (const e of ENTRIES) {
    if (resolves(e)) continue;
    let best = 3;
    const near = [];
    for (const f of files) {
      const d = editDistance(e, f, 2);
      if (d <= 2) {
        near.push(`${f} (${d})`);
        if (d < best) best = d;
      }
    }
    if (!near.length) continue;
    const row = UNRESOLVED_BY.get(e);
    if (row) {
      warn.push(
        `${e} — excused by ${row.by} until ${row.due}, and ${best} edit(s) from ${near.slice(0, 3).join(", ")}. ` +
          `If that row is wrong, this entry checks nothing until ${row.due} exits.`,
      );
    } else {
      fail.push(`${e} — names nothing, is ${best} edit(s) from ${near.slice(0, 3).join(", ")}, and nothing claims it is pending`);
    }
  }
  for (const w of warn) console.log(`warn  ${w}`);
  assert.deepEqual(
    fail,
    [],
    "an entry of TRUST-31's set names nothing, is one or two characters from a path that does exist, and " +
      "carries no row saying it is pending. That is a misspelling: it passes every structural check, reads " +
      "as deliberate, compares equal for ever, and leaves the file it meant to name covered by nothing",
  );
});

test("the two enumerated groups are exactly what is on the tree", () => {
  // `bot/*.mjs` and `schema/*.json` cannot be directory entries, so they are
  // written out. These two assertions are what stops the enumeration drifting
  // from the tree in silence: a new top-level bot entry point or a new record
  // schema goes RED here until a contract MINOR names it, which is the cost
  // the contract states rather than a surprise at a pin move.
  const files = tracked();
  const onTree = (re) => files.filter((f) => re.test(f)).sort();
  // THE COUNTS ARE COMPUTED, NOT SPELLED. Until 2026-09-21 these two messages
  // said "a nineteenth entry point" and "a twelfth schema" — the ordinals that
  // were next when 0.20.0 wrote them. 0.23.0 then published exactly those two,
  // so by the time anybody could trip these assertions the ordinals had been
  // wrong for a release, and the comment at the top of this file said one thing
  // while the comment beside `bot/moderation-run.mjs` said it WAS the
  // nineteenth. A canary that states the cost it enforces must not carry that
  // cost as a literal: the numbers below come off the tree and off the set, so
  // the failure text is right in every release without anyone maintaining it.
  const setBots = ENTRIES.filter((e) => /^bot\/[^/]+\.mjs$/.test(e)).sort();
  const treeBots = onTree(/^bot\/[^/]+\.mjs$/);
  assert.deepEqual(
    setBots, treeBots,
    `the bot's top-level entry points and TRUST-31's enumeration of them differ: the set enumerates ` +
      `${setBots.length}, the tree holds ${treeBots.length}. Every entry point beyond the published set is a ` +
      `contract MINOR published BEFORE the file lands (contract 0.20.0's TRUST-31)`,
  );
  const setSchemas = ENTRIES.filter((e) => /^schema\/[^/]+\.json$/.test(e)).sort();
  const treeSchemas = onTree(/^schema\/[^/]+\.json$/).filter((f) => f !== "schema/contract-tokens-v1.json");
  assert.deepEqual(
    setSchemas, treeSchemas,
    `the record schemas and TRUST-31's enumeration of them differ: the set enumerates ${setSchemas.length}, the ` +
      `tree holds ${treeSchemas.length} once \`schema/contract-tokens-v1.json\` — the one deliberate omission — is ` +
      `set aside. Every schema beyond the published set is a contract MINOR published BEFORE the file lands`,
  );
});

// ── (a) the commits that must leave the set alone ───────────────────────────
//
// Every one of these is a file a bot or operator run writes while doing the
// thing TRUST-31 protects. If any of them were in the set, the first
// publication after an acknowledgement would un-acknowledge the registry.
//
// The `exists` column is not decoration. A fixture list of paths nobody writes
// rots into a test that asserts something about nothing, so the paths that are
// on the tree today are asserted to be on it, and the ones that are not carry
// the task that creates them — checked below, so that a path arriving under a
// different name is a failure rather than a silently dead row.

const ROUTINE = [
  { p: "log/decisions/2026/09/abc.json", why: "a decision record (DEC-7)", exists: false, by: "B-T2.2, first written at R3" },
  { p: "log/baseline.json", why: "the migration baseline marker (MIG-20)", exists: false, by: "B-T3.7b's single dispatch" },
  { p: "tools/revocations/ASTRA-2026-0001.json", why: "an advisory", exists: false, by: "the first withdrawal; `tools/revocations/` holds only its README today" },
  { p: "bot/moderation/2026-08-19-echo-stt-delist.json", why: "a moderation log entry (MOD-47)", exists: true },
  { p: "state/queue/demo@1.0.0.json", why: "a queue entry (BOT-38)", exists: false, by: "written by an ingest run" },
  { p: "state/holds/0192.json", why: "a hold (MOD-9)", exists: false, by: "M-T3.3" },
  { p: "state/deny/abc123.json", why: "an operator deny record (TRUST-33)", exists: false, by: "operator.yml's `act: deny`, M-T3.5" },
  { p: "state/alerts/abc123.json", why: "an alert record (TRUST-32); its delivery report is what the operator window counts from", exists: false, by: "the ingest run's alert job" },
  { p: "policy/binding-deadline.json", why: "the binding deadline, which the OWNER commits by hand (MIG-2)", exists: false, by: "the owner, before R4b" },
  { p: "tools/sign-update-manifest.mjs", why: "a desk tool, deleted at R2 by RC-R3-4(b)", exists: true },
  { p: "tools/signer/plan.mjs", why: "a ceremony tool the bot never reaches", exists: true },
];

test("(a) the files a run writes as it works are outside the hashed set", () => {
  const wrong = ROUTINE.filter((r) => inSet(r.p));
  assert.deepEqual(
    wrong.map((r) => `${r.p} — ${r.why}`),
    [],
    "a path the bot writes is inside TRUST-31's set, so the first publication after an acknowledgement " +
      "puts the bot back into shadow and every withdrawal it was carrying stops reaching installed copies",
  );
});

test("(a) the fixture paths that exist are on the tree, and the rest name who writes them", () => {
  const files = new Set(tracked());
  for (const r of ROUTINE) {
    if (r.exists) {
      assert.ok(
        files.has(r.p),
        `${r.p} is listed above as a file on the tree and is not one. Either it moved — in which case this ` +
          `row must follow it, or the row is asserting nothing — or it was deleted and the row goes.`,
      );
    } else {
      assert.ok(
        r.by && !files.has(r.p),
        `${r.p} is listed as not-yet-written ("${r.by}") and is on the tree. Move the row to exists: true.`,
      );
    }
  }
});

test("`schema/contract-tokens-v1.json` is the one file under `schema/` outside the set", () => {
  const schemas = tracked().filter((p) => /^schema\/[^/]+\.json$/.test(p));
  assert.ok(schemas.length >= 8, `only ${schemas.length} schema files found; this is a broken read`);
  const outside = schemas.filter((p) => !inSet(p));
  assert.deepEqual(outside, ["schema/contract-tokens-v1.json"]);
});

test("the operator workflow is outside the set and the two bot workflows are named exactly", () => {
  assert.equal(inSet(".github/workflows/operator.yml"), false,
    "operator.yml holds no bot token and mints none; MOD-52 binds it through environment `operator`, " +
    "not through TRUST-31 (contract 0.20.0; registry plan M-T3.5)");
  // No glob. A `plugins-*.yml` rule would have quietly taken in any future
  // workflow whose name began that way, which is a widening of what the
  // service pins that no contract version published.
  assert.equal(inSet(".github/workflows/plugins-anything.yml"), false);
  for (const w of WORKFLOWS) assert.equal(inSet(w), true);
  // Every other workflow file on the tree is outside.
  const others = tracked().filter((p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p) && !WORKFLOWS.includes(p));
  assert.ok(others.length >= 10, `only ${others.length} other workflows found; this is a broken read`);
  assert.deepEqual(others.filter(inSet), []);
});

// ── (b) everything a run of the two workflows can reach ─────────────────────

const present = (p) => fs.existsSync(path.join(REPO, p));
const read = (p) => fs.readFileSync(path.join(REPO, p), "utf8");

/** `node [flags] <script.mjs>` anywhere in a YAML file's run blocks. */
function nodeEntryPoints(yaml) {
  const out = new Set();
  for (const m of yaml.matchAll(/\bnode\s+((?:--[\w-]+(?:=\S+)?\s+)*)([\w./-]+\.mjs)\b/g)) out.add(m[2]);
  return out;
}

/** `uses: ./<path>` — a local composite action. */
function localUses(yaml) {
  return new Set([...yaml.matchAll(/uses:\s*\.\/(\S+)/g)].map((m) => m[1]));
}

/** Relative static imports and re-exports, followed transitively. */
function importClosure(entries) {
  const seen = new Set();
  const missing = [];
  const walk = (rel) => {
    if (seen.has(rel)) return;
    seen.add(rel);
    if (!present(rel)) { missing.push(rel); return; }
    const src = read(rel);
    const re = /(?:^|[\s;{}])(?:import\s[^;]*?from\s*|import\s*|export\s[^;]*?from\s*)["'](\.[^"']+)["']/g;
    for (const m of src.matchAll(re)) {
      walk(path.posix.normalize(path.posix.join(path.posix.dirname(rel), m[1])));
    }
  };
  for (const e of entries) walk(e);
  return { modules: [...seen], missing };
}

/**
 * Node scripts a reachable module hands to child_process.
 *
 * It is deliberately over-inclusive: every `.mjs` path literal in a module
 * that imports `child_process` counts as a target. A precise call-site read
 * would find nothing, and that is not a hypothetical — the one real target on
 * this tree is `tools/selftest.mjs`, and the call is
 * `execFileSync(process.execPath, step)` where `step` is a loop variable over
 * an array declared twenty lines above (`bot/publish-apply.mjs:470-481`). A
 * scanner that read the call's arguments would have come back empty and gone
 * green over a gate the publish path actually runs.
 *
 * Backticked literals are skipped, and only those: this repository writes
 * paths in prose with markdown backticks, and three comments naming
 * `bot/tests/policy.test.mjs` were the first three findings this leg reported.
 * A module that runs node scripts and carries a quoted `.mjs` path it does not
 * execute should move that path into a comment, where it belongs.
 */
function spawnedScripts(modules) {
  const out = new Set();
  for (const rel of modules) {
    if (!present(rel)) continue;
    const src = read(rel);
    if (!/child_process/.test(src)) continue;
    for (const m of src.matchAll(/["']([\w./-]*\.mjs)["']/g)) {
      const raw = m[1];
      const cand = raw.startsWith(".")
        ? path.posix.normalize(path.posix.join(path.posix.dirname(rel), raw))
        : raw;
      if (present(cand) && cand !== rel) out.add(cand);
    }
  }
  return out;
}

/** The workflow files of the two that are on the tree, derived, never declared. */
function liveWorkflows() {
  return WORKFLOWS.filter(present);
}

/**
 * A step whose `run:` prints `::error::` and names the task that will build it
 * is a stub. The marker is already in the tree and machine-readable, which is
 * why the floor below is derived from it rather than from a boolean here.
 */
function stubTasks(yaml) {
  const out = new Set();
  for (const m of yaml.matchAll(/not built:\s*([A-Za-z0-9 ,.\-]+?)\)/g)) {
    for (const id of m[1].split(",")) {
      const t = id.trim();
      if (/^[A-Z]+-[A-Z]?T?[0-9][0-9a-z.]*$/.test(t)) out.add(t);
    }
  }
  return out;
}

test("(b) every reachable code path of the two bot workflows is inside the set", () => {
  const live = liveWorkflows();
  assert.ok(
    live.length >= 1,
    "neither bot workflow is on the tree. TRUST-31's set would then be asserted against nothing, " +
      "which is a green run about an empty walk, not a green run about a correct set",
  );

  const entries = new Set();
  const actions = new Set();
  for (const w of live) {
    const yaml = read(w);
    for (const e of nodeEntryPoints(yaml)) entries.add(e);
    for (const u of localUses(yaml)) actions.add(u);
  }

  // Every `uses: ./…` reference, and the whole directory each names. The alert
  // action is the reason `.github/actions/**` is in the set at all: it outputs
  // the `delivered_at` TRUST-32 gates publication on, so a registry writer who
  // could edit it from outside the set could change what a run reports as
  // delivered without the bot returning to shadow.
  assert.ok(actions.size >= 1, "the workflows reference no local composite action; this is a broken read");
  for (const dir of actions) {
    assert.ok(present(dir), `the workflows run \`uses: ./${dir}\` and that directory is not on the tree`);
    assert.ok(inSet(dir + "/action.yml"), `\`uses: ./${dir}\` is outside TRUST-31's set`);
    for (const f of tracked().filter((p) => p.startsWith(dir + "/"))) {
      assert.ok(inSet(f), `${f} lives under a composite action the workflows run and is outside the set`);
    }
    // The action's own `node` entry points are entry points of the run.
    const af = path.posix.join(dir, "action.yml");
    if (present(af)) for (const e of nodeEntryPoints(read(af))) entries.add(e);
  }

  assert.ok(entries.size >= 1, "the workflows name no node entry point; this is a broken read");
  for (const e of entries) {
    assert.ok(present(e), `the workflows run \`node ${e}\` and that file is not on the tree`);
    assert.ok(inSet(e), `\`node ${e}\` runs in a bot workflow and is outside TRUST-31's set`);
  }

  // The closure, taken to a fixpoint: a spawned script is an entry point of
  // the run, so its own imports are reachable too. Without the second pass the
  // five checks `bot/publish-apply.mjs` runs would be judged and their
  // libraries would not.
  let modules = [];
  const roots = new Set(entries);
  for (let pass = 0; pass < 8; pass += 1) {
    const { modules: m, missing } = importClosure([...roots]);
    assert.deepEqual(missing, [], "a module is imported and is not on the tree");
    modules = m;
    const before = roots.size;
    for (const s of spawnedScripts(m)) roots.add(s);
    if (roots.size === before) break;
  }

  const outside = modules.filter((m) => !inSet(m));
  assert.deepEqual(
    outside,
    [],
    "a module a bot run reaches is outside TRUST-31's set, so a change to what the registry decides " +
      "would not return the bot to shadow",
  );
  for (const s of roots) {
    assert.ok(inSet(s), `${s} runs, or is spawned, in a bot run and is outside the set`);
  }

  // The floor. 20 modules, from the plan, and it is met on today's tree at 23
  // — but only once `tools/selftest.mjs` and its cases are counted, which is
  // the correction this canary forced. Written as a floor rather than an
  // equality because the closure only grows as the stub jobs are built.
  assert.ok(
    modules.length >= 20,
    `the bot workflows reach ${modules.length} modules; the floor is 20. A closure this small is a ` +
      `broken walk, not a smaller bot.`,
  );
  assert.ok(
    modules.length > roots.size,
    `${modules.length} modules from ${roots.size} entry points: no import was followed, so the closure ` +
      `is the entry-point list wearing another name`,
  );

  // What is NOT yet walked, derived from the tree and never declared, so that
  // a green run here is not read as a statement about both workflows.
  const absent = WORKFLOWS.filter((w) => !present(w));
  const stubs = new Set();
  for (const w of live) for (const t of stubTasks(read(w))) stubs.add(t);
  for (const t of stubs) assert.ok(/^[A-Z]/.test(t), `stub marker ${JSON.stringify(t)} names no task`);
  if (absent.length || stubs.size) {
    assert.ok(
      absent.length < WORKFLOWS.length,
      "both bot workflows are absent; there is nothing to walk",
    );
    console.log(
      `note  ${modules.length} modules reached, floor 20. Not yet walked: ` +
        `${absent.join(", ") || "no absent workflow"}` +
        `${stubs.size ? `; stub steps still name ${[...stubs].sort().join(", ")}` : ""}.`,
    );
  }
});

// ── the value an acknowledgement names ──────────────────────────────────────

test("the set hash, which a TRUST-42 acknowledgement names", () => {
  const rows = git("ls-tree", "-r", "HEAD")
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      const [meta, p] = l.split("\t");
      const [, , blob] = meta.split(/\s+/);
      return { p, blob };
    })
    .filter((r) => inSet(r.p))
    .sort((a, b) => (a.p < b.p ? -1 : 1));

  assert.ok(rows.length >= 40, `only ${rows.length} files are in the set; this is a broken read`);
  const h = crypto.createHash("sha256");
  for (const r of rows) h.update(`${r.blob} ${r.p}\n`);
  const digest = h.digest("hex");
  assert.match(digest, /^[0-9a-f]{64}$/);
  console.log(`set   TRUST-31 hashed set: ${rows.length} files, sha256 ${digest}`);
  console.log(`set   at ${git("rev-parse", "HEAD").trim()}`);
});
