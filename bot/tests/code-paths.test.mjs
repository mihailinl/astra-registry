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
  // **That import is gone** (dev/couplings.md entry 104). The decision writer
  // takes the rules from `tools/lib/priv-rules.mjs`, under the `tools/lib/`
  // entry, because `tools/priv-scan.mjs` also held `roleAddresses`, which reads
  // `bot/security-contact.json` — outside this set — and exempted whatever
  // address that file held from the bot's own PRIV-2 refusal. So leg (b)'s
  // closure no longer reaches `tools/priv-scan.mjs` or `tools/coverage/rules.mjs`
  // (52 modules to 51).
  //
  // **Contract 0.34.0 takes `tools/priv-scan.mjs` out, and only that one.** It
  // is reached by no bot run through the closure below AND by none through the
  // selftest's cases, whose own static imports this walk cannot follow (the
  // runner loads them by a dynamic `import()`). `tools/coverage/rules.mjs` IS
  // reached that second way: `tools/selftest/couplings.mjs` imports
  // `tools/coverage/docs-advisory-url.mjs`, which imports it, and the publish
  // path runs the selftest as its fifth gate — so taking it out would be the
  // direction that opens a hole, and it stayed until that path was decided (ops
  // pending item 19). Contract 0.38.0 decided it by bringing
  // `docs-advisory-url.mjs` in beside it, below. `tools/coverage/git.mjs` is reached through
  // `bot/lib/compile-decision.mjs`, which `bot/moderation-run.mjs` and
  // `tools/validate.mjs` import.
  //
  // `tools/coverage/` is ENUMERATED and not taken whole: `drain-age`,
  // `examples-staging-id`, `keepalive-age` and `reserved-id-mirror` are rule
  // reporters the moderation-coverage workflow runs, and
  // `priv-scan-exempt.json` is read only by the canary's own history walk. A
  // directory entry is right when everything beneath it belongs; here five of
  // eight do not. (`docs-advisory-url` is the sixth reporter, and 0.38.0 put it
  // in, below, because a selftest case imports it.) What makes enumerating safe
  // is leg (b): a file under `tools/coverage/` that a bot run starts reaching
  // fails there, by name, the day it does.
  "tools/coverage/rules.mjs",
  "tools/coverage/git.mjs",
  // ── contract 0.38.0: what the fifth gate LOADS, not only what the bot imports ──
  //
  // Ops pending item 19 and couplings entry 116, decided (a) for the owner on
  // 2026-09-23. `bot/publish-apply.mjs` runs `tools/selftest.mjs` as the last of
  // its five checks and the moderation commit job runs it too, and the runner
  // loads its cases by a dynamic `import()` that leg (b) cannot follow. The
  // cases reach — by import, by a node child, by a temp copy run as a child —
  // the 31 modules below, measured at runtime by `node tools/selftest.mjs
  // --loads` (tools/selftest/loads.mjs), whose declared residual they were.
  // An edit to any of them changes what a bot commit is held to, so it is a
  // shadow transition and an acknowledgement from R3 (registry plan ROLL-64):
  // about three a week more, measured on the week before the decision, and 11
  // in the week to 2026-09-23 — 8 of them edits to `bot/tests/workflows.test.mjs`
  // alone, which is here only because a case runs a copy of it (below).
  //
  // A directory entry where every file beneath it is code the gate reaches —
  // `tools/served-set/` (all seven), `site/lib/` (one) and `site/templates/`
  // (all three) — and every other path enumerated, because the directory also
  // holds what the gate does not load: `tools/signer/verdict.mjs`; `site/`'s
  // assets, redirects and its own selftest; `tools/testkeys/`' keys, README and
  // fixtures; `tests/`' vectors; `bot/fixtures/`' catalogues; `bot/tests/`' other
  // suites. Enumerating is safe for the reason leg (b) makes it safe for
  // `tools/coverage/`: a new module the gate starts loading is red, by name, in
  // `loads.mjs`'s check, whose residual is now empty.
  //
  // `bot/tests/workflows.test.mjs` is the one test file in the set: the case
  // `tools/selftest/contract-tokens.mjs` copies it into a temp tree and runs
  // the copy, so its assertions are part of what the fifth gate decides.
  "bot/fixtures/index/regenerate.mjs",
  "bot/tests/workflows.test.mjs",
  "site/build.mjs",
  "site/lib/",
  "site/templates/",
  "tests/shared-vectors.mjs",
  "tools/coverage-verdict.mjs",
  "tools/coverage/docs-advisory-url.mjs",
  "tools/make-fixtures.mjs",
  "tools/moderation-coverage.mjs",
  "tools/regenerate-signed.mjs",
  "tools/served-set/",
  "tools/sign-revocations.mjs",
  "tools/sign-trust.mjs",
  "tools/sign-update-manifest.mjs",
  "tools/signer/git.mjs",
  "tools/signer/key-window.mjs",
  "tools/signer/pages.mjs",
  "tools/signer/plan.mjs",
  "tools/signer/run.mjs",
  "tools/testkeys/make-rehearsal-r2.mjs",
  // Ops couplings entry 126: `bot/sign-index.mjs`, a set entry, imports it —
  // the one import from inside the set to outside it that leg (d) below found
  // on the tree 0.34.0 left, besides the ones the gate's own cases make.
  "tools/testkeys/regenerate.mjs",
  "tools/testkeys/sign-trust.mjs",
  // Ops couplings entry 132: since contract 0.36.0 the fifth gate holds the
  // token file's `flow13_table` to this file, rows, order and source
  // (tools/selftest/contract-tokens.mjs). The registry's own table, written by
  // a desk tool from `bot/lib/codes.mjs` (in the set) and by no workflow, so
  // hashing it costs no acknowledgement a change to the codes does not already.
  "tools/codes-table.json",
  "policy/reserved-ids.json",
  "policy/spdx-allowlist.json",
  "policy/listing-language-exemptions.json",
  "schema/cutover-v1.json",
  "schema/deadline-v1.json",
  // B-T2.1's three, added by contract 0.21.0. `tools/lib/sources.mjs`'s
  // `loadSchemas` loads them by literal path and `tools/validate.mjs` judges
  // records against them — from THIS repository, never from the tree under
  // test, so that `--registry-dir` cannot supply the rules it is judged by.
  // That is what makes them gate inputs rather than documents. This comment
  // used to say `loadSchemas` loads "all eleven", the sentence contract 0.21.0
  // carried and later struck: it loads eight of the set's thirteen, and
  // `bot/lib/holds.mjs`, `bot/lib/listing-state.mjs` and
  // `bot/moderation-run.mjs` read the other five. Which loader opens each one
  // is asked now rather than written: tools/selftest/primitives.mjs runs every
  // loader, records what it opens, and holds this list to it.
  "schema/decision-v1.json",
  "schema/hold-record-v1.json",
  "schema/hold-v1.json",
  "schema/identity-v1.json",
  "schema/index-v1.json",
  // Contract 0.31.0's, published before the file landed, as
  // `schema/moderation-work-v1.json` was at 0.23.0. B.4 typed MIG-13's marker in that
  // version and this file asserts the types; `loadSchemas` takes it by literal
  // path and `tools/validate.mjs` — the first of the five checks the publish
  // path runs — judges every `log/migration-notice-<n>.json` against it. A
  // writer who could edit it from outside the set could make that check pass a
  // marker whose `round` the token file's condition cannot compare, without
  // the bot returning to shadow.
  "schema/migration-notice-v1.json",
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
// the file does. It is the shape the pending records already use in
// `astra-plugins-ops`'s `tools/contract-tokens.mjs` — THE OTHER ESTATE'S
// generator, not a file in this repository — where each names the contract
// version that lands it and a probe that fires when the reason closes.
//
// The estate is spelled because it was not, and the omission is the failure
// this very file exists to catch, one level out. `tools/contract-tokens.mjs`
// reads as a path here and there is no such path here; the nearest thing on
// this tree is `tools/selftest/contract-tokens.mjs`, which is a different
// program doing a different job. A reader looks, does not find it, and
// concludes the comment is stale — when it is exact, about somewhere else.
// A bare path beside no estate name is the same defect as a bare section
// number beside no document name, which cost both estates a day this month.
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
  { p: "state/moderation-settled.json", why: "the results history decided that the service settled (ops entry 100)", exists: false, by: "the first live moderation run whose list job settles one, from R3" },
  { p: "state/deny/abc123.json", why: "an operator deny record (TRUST-33)", exists: false, by: "operator.yml's `act: deny`, M-T3.5" },
  { p: "state/alerts/abc123.json", why: "an alert record (TRUST-32); its delivery report is what the operator window counts from", exists: false, by: "the ingest run's alert job" },
  { p: "policy/binding-deadline.json", why: "the binding deadline, which the OWNER commits by hand (MIG-2)", exists: false, by: "the owner, before R4b" },
  // Until contract 0.38.0 two rows here held `tools/sign-update-manifest.mjs`
  // and `tools/signer/plan.mjs` OUTSIDE, as desk and ceremony tools the bot
  // never reaches — true of the bot's closure and false of its fifth gate,
  // which loads both (ops pending item 19). They are in the set now, and the
  // row that stays is the one file under `tools/signer/` neither reaches.
  { p: "tools/signer/verdict.mjs", why: "the signer workflow's verdict step, which neither a bot run nor the fifth gate loads", exists: true },
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

/** The closure of `entries`, spawned scripts followed to a fixpoint. Leg (b)'s walk, and leg (c)'s. */
function closureOf(entries) {
  let modules = [];
  let missing = [];
  const roots = new Set(entries);
  for (let pass = 0; pass < 8; pass += 1) {
    ({ modules, missing } = importClosure([...roots]));
    const before = roots.size;
    for (const s of spawnedScripts(modules)) roots.add(s);
    if (roots.size === before) break;
  }
  return { modules, roots, missing };
}

/** Every `node` entry point the two workflows and their local actions run. */
function workflowEntries() {
  const entries = new Set();
  for (const w of liveWorkflows()) {
    const yaml = read(w);
    for (const e of nodeEntryPoints(yaml)) entries.add(e);
    for (const u of localUses(yaml)) {
      const af = path.posix.join(u, "action.yml");
      if (present(af)) for (const e of nodeEntryPoints(read(af))) entries.add(e);
    }
  }
  return entries;
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
  const { modules, roots, missing } = closureOf(entries);
  assert.deepEqual(missing, [], "a module is imported and is not on the tree");

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

// ── (c) the data files a reachable module names ─────────────────────────────
//
// Leg (b) follows imports and spawned scripts. A module also READS files that
// are not modules — a policy, a schema, an allow-list — and a data file that
// decides what a run does is as much a gate input as the code that reads it
// (registry plan ROLL-64: "a bot run's outcome depends on it" is the test).
// Before this leg, a new `policy/*.json` read by `tools/validate.mjs` sat
// outside the set with nothing red (dev/couplings.md entry 104).
//
// **Its first run found one, and it was not excused: it was moved.**
// `bot/security-contact.json`, read by `tools/priv-scan.mjs`'s
// `roleAddresses`, which the decision writer imported: every address in that
// file was exempt from the bot's own PRIV-2 refusal, so a registry writer could
// widen what a bot run writes into a public decision record without the bot
// going back to shadow. The rules moved to `tools/lib/priv-rules.mjs`, which
// reads no file; the read stays in the canary, which no bot run imports; and
// `bot/tests/decisions.test.mjs` asserts the property from the outside. The
// file is not in `DATA_OUTSIDE` below, and the test refuses a declaration of
// it — declaring it would have been the one-line way to make this leg green
// and leave the hole open.
//
// So every path a module in leg (b)'s closure NAMES — a whole string literal
// that is a repository path, the literal and constant arguments of a
// `path.join`/`path.resolve`, a `new URL("../x", import.meta.url)`, the static
// head of a template like `plugins/${id}` — must be inside the set or declared
// outside it below, with a reason. Code files are leg (b)'s subject and are
// skipped here.
//
// **What this scan cannot see, stated so a green run is not read as more:**
// a path built from a value no module spells (a CLI argument, a run artifact);
// a walk of the whole tree (`tools/selftest.mjs` and its harness read every
// tracked file — they are the check, and the tree is its subject); files in
// the AstraPlugins checkout (outside this repository, selected by
// `bot/manifest-probe/astra-plugins.pin`, which is in the set); the selftest
// cases under `tools/selftest/`, which the directory entry covers as code and
// no static closure reaches; a path under a top-level directory that is
// neither on the tree nor named by the set or a declaration; and a path whose
// segments are separate literals put together by anything other than
// `path.join`/`path.resolve` — `["bot", "x.json"].join("/")`, a `+` — which
// no single string spells. That last one was watched: a read of the contact
// file written that way is green here, and red only in
// `bot/tests/decisions.test.mjs`, which judges what the writer DOES rather
// than what it names.

/**
 * Declared outside the set. `path` is exact, or a directory with a trailing
 * `/` that covers everything beneath it — and a directory declaration may not
 * be a prefix of a set entry, because it would shelter a new file next to a
 * hashed one (`policy/` would have sheltered exactly the file this leg exists
 * to catch). Every declaration must match something the scan found.
 */
export const DATA_OUTSIDE = [
  // Records a run writes or reads as its subject — TRUST-31's own outside
  // paragraph: hashing them would put the bot into shadow for doing its job.
  { path: "plugins/", why: "the catalogue's sources, which every run judges and a publication writes" },
  { path: "publishers/", why: "publisher records, hand-reviewed and withdrawn by the daily re-check; TRUST-31 lists them outside" },
  { path: "log/", why: "decision records, the baseline marker, the cutover marker and migration notices: records, not rules" },
  // Named before `state/`, which would also cover it, because this record is
  // READ to decide something — whether a result from history is posted again —
  // and that trade is stated here rather than inherited (ops entry 100).
  {
    path: "state/moderation-settled.json",
    why: "the moderation run's record of results the service answered accepted or duplicate (ops entry 100). A record " +
      "the commit job writes as it works, so hashing it would put the bot into shadow for doing its job; the rule that " +
      "reads it is bot/lib/settled.mjs, inside the set. A forged well-formed row withholds one result a commit in " +
      "history decided — changing nothing in git, only keeping a hold's end from the service's record — and every " +
      "other fault in the file degrades to posting again",
  },
  { path: "state/", why: "queue, holds, alerts and watch state a run writes as it works" },
  { path: "bot/moderation/", why: "MOD-47 moderation log entries, the moderation run's subject" },
  { path: "tools/revocations/", why: "advisories, compiled into the served list" },
  { path: "registry/v1/", why: "the served index and revocation list (outputs), and root.json, which bot/check-roots.mjs holds to the roots compiled into the code — the file is the subject of that comparison, not its rule" },
  { path: "policy/binding-deadline.json", why: "committed by the owner by hand (MIG-2); TRUST-31 lists it outside" },
  // Deliberate, and each is TRUST-31's own words.
  { path: "schema/contract-tokens-v1.json", why: "generated from the contract, so hashing it would make every contract version a shadow transition (TRUST-31). It IS read at run time: fixedReason decides a moderation compile's reason_refused" },
  { path: ".github/workflows", why: "tools/selftest.mjs's lane census reads every workflow file; the two bot workflows are set entries and the rest are outside by TRUST-31. Exact, so a named new workflow is still judged" },
  // Not files at all: operation paths relative to the plugins service's API
  // base (contract §4.2), in bot/lib/service.mjs's OPERATIONS.
  ...["gates", "leases", "moderation-work", "notice-status", "results", "service-decision-results", "submissions", "verdicts"]
    .map((op) => ({ path: `bot/${op}`, why: "not a file: an operation path relative to the plugins service's API base (§4.2)" })),
];

const lex = (src) => {
  let code = ""; const strs = []; let i = 0; const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === "/" && d === "/") { while (i < n && src[i] !== "\n") i += 1; continue; }
    if (c === "/" && d === "*") { i += 2; while (i < n && !(src[i] === "*" && src[i + 1] === "/")) { if (src[i] === "\n") code += "\n"; i += 1; } i += 2; continue; }
    if (c === '"' || c === "'" || c === "`") {
      const at = code.length; let body = ""; let depth = 0; let interp = false; code += c; i += 1;
      while (i < n && !(src[i] === c && depth === 0)) {
        if (src[i] === "\\") { body += src[i] + src[i + 1]; code += src[i] + src[i + 1]; i += 2; continue; }
        if (c === "`" && src[i] === "$" && src[i + 1] === "{") { interp = true; depth += 1; } else if (c === "`" && depth && src[i] === "}") depth -= 1;
        body += src[i]; code += src[i]; i += 1;
      }
      code += c; i += 1; strs.push({ at, body, interp });
      if (interp) for (const m of body.matchAll(/\$\{/g)) {
        let j = m.index + 2; let dd = 1; for (; j < body.length && dd; j += 1) { if (body[j] === "{") dd += 1; else if (body[j] === "}") dd -= 1; }
        for (const s of lex(body.slice(m.index + 2, j - 1)).strs) strs.push({ ...s, at: at + m.index + 2 + s.at });
      }
      continue;
    }
    if (c === "/" && /[=(,:;!&|?{}[\n]\s*$/.test(code.slice(-3))) {
      code += c; i += 1; let cls = false;
      while (i < n && (src[i] !== "/" || cls) && src[i] !== "\n") { if (src[i] === "\\") { code += src[i] + src[i + 1]; i += 2; continue; } if (src[i] === "[") cls = true; if (src[i] === "]") cls = false; code += src[i]; i += 1; }
      code += "/"; i += 1; continue;
    }
    code += c; i += 1;
  }
  return { code, strs };
};

/** Every repository path the given modules name, as `path -> ["module:line", …]`. */
export function namedDataPaths(modules, roots) {
  const norm = (p) => { const r = path.posix.normalize(p).replace(/\/+$/, ""); return r === "." ? "" : r; };
  const isCode = (p) => /\.(?:m?js|cjs)$/.test(p);
  const pathLike = (s) => /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*\/?$/.test(s) && roots.has(s.split("/")[0]);
  const splitArgs = (s) => { const out = []; let depth = 0; let cur = ""; let q = null; for (const ch of s) { if (q) { cur += ch; if (ch === q) q = null; continue; } if (ch === '"' || ch === "'" || ch === "`") { q = ch; cur += ch; continue; } if ("([{".includes(ch)) depth += 1; if (")]}".includes(ch)) depth -= 1; if (ch === "," && depth === 0) { out.push(cur.trim()); cur = ""; continue; } cur += ch; } if (cur.trim()) out.push(cur.trim()); return out; };
  const lexed = new Map(modules.filter(present).map((m) => [m, lex(read(m))]));
  const consts = new Map();
  const evalExpr = (m, expr, local) => {
    expr = expr.trim();
    let mm = /^(["'])([^"'\\]*)\1$|^`([^`$\\]*)`$/.exec(expr); if (mm) return { kind: "str", p: mm[2] ?? mm[3] };
    mm = /^(?:path\.resolve\()?\s*fileURLToPath\(\s*new URL\(\s*["']([^"']+)["']\s*,\s*import\.meta\.url\s*\)\s*\)\s*\)?$/.exec(expr);
    if (mm) return { kind: "dir", p: norm(path.posix.join(path.posix.dirname(m), mm[1])) };
    if (/^path\.dirname\(\s*fileURLToPath\(\s*import\.meta\.url\s*\)\s*\)$|^import\.meta\.dirname$/.test(expr)) return { kind: "dir", p: path.posix.dirname(m) };
    mm = /^path(?:\.posix)?\.(?:join|resolve)\(([\s\S]*)\)$/.exec(expr);
    if (mm) { const a = splitArgs(mm[1]).map((x) => evalExpr(m, x, local)); if (a.length && a.every(Boolean) && a.slice(1).every((r) => r.kind === "str")) return { kind: a[0].kind, p: norm(a.map((r) => r.p).filter(Boolean).join("/")) }; return null; }
    if (/^[A-Za-z_$][\w$]*$/.test(expr)) return local.get(expr) ?? null;
    return null;
  };
  const exprAfter = (src, i) => { let depth = 0; let q = null; const st = i; for (; i < src.length; i += 1) { const ch = src[i]; if (q) { if (ch === "\\") { i += 1; continue; } if (ch === q) q = null; continue; } if (ch === '"' || ch === "'" || ch === "`") q = ch; else if ("([{".includes(ch)) depth += 1; else if (")]}".includes(ch)) { if (depth === 0) break; depth -= 1; } else if ((ch === ";" || ch === "\n" || ch === ",") && depth === 0) break; } return src.slice(st, i); };
  const rel = (m, spec) => norm(path.posix.join(path.posix.dirname(m), spec));
  for (let pass = 0; pass < 4; pass += 1) {
    for (const [m, { code }] of lexed) {
      const local = consts.get(m) ?? new Map();
      for (const x of code.matchAll(/(import|export)\s*\{([^}]*)\}\s*from\s*["'](\.[^"']+)["']/g)) {
        for (const spec of x[2].split(",")) { const s = spec.trim(); if (!s) continue; const [a, b] = s.split(/\s+as\s+/); const v = consts.get(rel(m, x[3]))?.get(a.trim()); if (v) local.set((b ?? a).trim(), v); }
      }
      for (const x of code.matchAll(/export\s*\*\s*from\s*["'](\.[^"']+)["']/g)) for (const [k, v] of consts.get(rel(m, x[1])) ?? []) if (!k.startsWith("param:")) local.set(k, v);
      for (const x of code.matchAll(/^(?:export\s+)?const\s+([A-Z_][A-Z0-9_]*)\s*=\s*/gm)) { const v = evalExpr(m, exprAfter(code, x.index + x[0].length), local); if (v) local.set(x[1], v); }
      for (const x of code.matchAll(/[(,]\s*([A-Za-z_$][\w$]*)\s*=\s*([A-Z_][A-Z0-9_]*)\s*[,)]/g)) { const v = local.get(x[2]); if (v?.kind === "dir") local.set(`param:${x[1]}`, v); }
      consts.set(m, local);
    }
  }
  const out = new Map();
  for (const [m, { code, strs }] of lexed) {
    const local = consts.get(m);
    const lineOf = (i) => code.slice(0, i).split("\n").length;
    const add = (p, i) => { p = norm(p); if (!p || isCode(p) || !roots.has(p.split("/")[0])) return; if (!out.has(p)) out.set(p, []); out.get(p).push(`${m}:${lineOf(i)}`); };
    for (const s of strs) {
      if (!s.interp) {
        if (s.body.includes("/") && pathLike(s.body)) add(s.body, s.at);
        if (/^\.{1,2}\//.test(s.body) && !isCode(s.body)) add(path.posix.join(path.posix.dirname(m), s.body), s.at);
      } else {
        const head = s.body.slice(0, s.body.indexOf("${"));
        if (head.endsWith("/") && pathLike(head)) add(head, s.at);
      }
    }
    for (const x of code.matchAll(/path(?:\.posix)?\.(?:join|resolve)\(/g)) {
      let i = x.index + x[0].length; let depth = 1; let q = null; const start = i;
      for (; i < code.length && depth; i += 1) { const ch = code[i]; if (q) { if (ch === "\\") { i += 1; continue; } if (ch === q) q = null; continue; } if (ch === '"' || ch === "'" || ch === "`") q = ch; else if (ch === "(") depth += 1; else if (ch === ")") depth -= 1; }
      const args = splitArgs(code.slice(start, i - 1));
      const vals = args.map((a) => evalExpr(m, a, local) ?? local.get(`param:${a}`) ?? null);
      let k = vals.length; while (k > 0 && vals[k - 1]?.kind === "str") k -= 1;
      const tail = vals.slice(k).map((v) => v.p).join("/");
      if (!tail) continue;
      const base = k === 0 ? { kind: "dir", p: "" } : vals[k - 1];
      if (base?.kind === "dir") add([base.p, tail].filter(Boolean).join("/"), x.index);
      else add(tail, x.index); // a root identifier, or a base this scan cannot resolve: judged as repository-relative
    }
  }
  return out;
}

/** Is `p` covered by the declaration `d`? */
const declares = (d, p) => (d.endsWith("/") ? (p + "/").startsWith(d) : p === d);

test("(c) every data file a reachable module names is in the set, or declared outside it with a reason", () => {
  const { modules } = closureOf(workflowEntries());
  const tracked_ = tracked();
  const roots = new Set([
    ...tracked_.map((f) => f.split("/")[0]),
    ...ENTRIES.map((e) => e.split("/")[0]),
    ...DATA_OUTSIDE.map((d) => d.path.split("/")[0]),
  ]);
  const named = namedDataPaths(modules, roots);

  // The declarations themselves: a grammar, a reason, no shelter over the set.
  const bad = [];
  for (const d of DATA_OUTSIDE) {
    const why = entryProblem(d.path);
    if (why) bad.push(`${d.path} — ${why}`);
    if (typeof d.why !== "string" || d.why.trim().length < 10) bad.push(`${d.path} — declared outside with no reason`);
    if (inSet(d.path) || inSet(d.path + "/")) bad.push(`${d.path} — is inside the set, so declaring it outside says two things`);
    if (d.path.endsWith("/") && ENTRIES.some((e) => e.startsWith(d.path))) {
      bad.push(`${d.path} — a directory declaration over a set entry would shelter a new file beside a hashed one`);
    }
  }
  assert.deepEqual(bad, [], "a declaration in DATA_OUTSIDE is itself malformed");
  assert.deepEqual(
    DATA_OUTSIDE.filter((d) => declares(d.path, "bot/security-contact.json")).map((d) => d.path), [],
    "bot/security-contact.json is declared outside the set. Entry 104 took it off the bot's path instead: a " +
    "decision record's PRIV-2 refusal must not depend on it. If a bot run reads it again, move the read, or put " +
    "the file in the set by a contract MINOR — do not excuse it here",
  );

  const outside = [];
  const matched = new Set();
  let inside = 0;
  for (const [p, at] of named) {
    if (inSet(p) || inSet(p + "/")) { inside += 1; continue; }
    const d = DATA_OUTSIDE.find((x) => declares(x.path, p));
    if (d) { matched.add(d.path); continue; }
    outside.push(`${p} — named by ${at.slice(0, 4).join(", ")}${at.length > 4 ? ` and ${at.length - 4} more` : ""}`);
  }
  assert.deepEqual(outside, [],
    "a module a bot run reaches names a data file that is neither in TRUST-31's set nor declared outside it. " +
    "If the run's outcome depends on it, adding it to the set is a contract MINOR (TRUST-31) published before " +
    "this lands; if it is a record, an output or not a file, declare it in DATA_OUTSIDE with the reason");
  const stale = DATA_OUTSIDE.filter((d) => !matched.has(d.path)).map((d) => d.path);
  assert.deepEqual(stale, [],
    "a DATA_OUTSIDE declaration matches nothing any reachable module names, so it excuses nothing today and " +
    "would shelter the next path that happens to match it");

  // The floor: the gate inputs this leg is for are found, so an empty scan is red.
  assert.ok(inside >= 15, `only ${inside} named data path(s) are inside the set; the scan has stopped finding the policy and schema reads`);
  console.log(`note  (c) ${named.size} data path(s) named by ${modules.length} modules: ${inside} inside the set, ` +
    `${named.size - inside} declared outside by ${DATA_OUTSIDE.length} declaration(s).`);
});

// ── (d) every module a set entry imports is in the set ──────────────────────
//
// Ops couplings entry 126. Leg (b) walks out from the two bot workflows, so it
// asks "is the set closed under import" only for the entries the bot's own
// closure reaches. An entry nothing in that closure reaches — `bot/sign-index.mjs`,
// which a signer process and the selftest's cases import — could import a
// module outside the set and no leg would look, and it did: it imported
// `tools/testkeys/regenerate.mjs`, outside until contract 0.38.0. An entry is
// what a reader takes to be closed, so the set now says it is, of every code
// file it covers, and this is what holds it.
//
// One level of static import from every code file the set covers is enough:
// every target must itself be in the set, so the closure follows by induction.
// It sees what leg (b)'s pattern sees — relative static imports and re-exports
// — and nothing a dynamic `import()` computes; that is what `--loads`
// (tools/selftest/loads.mjs) measures at runtime, for the selftest's cases.

test("(d) every module a set entry statically imports is in the set", () => {
  const code = tracked().filter((f) => /\.(?:m?js|cjs)$/.test(f) && inSet(f));
  const re = /(?:^|[\s;{}])(?:import\s[^;]*?from\s*|import\s*|export\s[^;]*?from\s*)["'](\.[^"']+)["']/g;
  const outside = [];
  const missing = [];
  let edges = 0;
  for (const f of code) {
    for (const m of read(f).matchAll(re)) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(f), m[1]));
      edges += 1;
      if (!present(target)) missing.push(`${target} — imported by ${f}`);
      else if (!inSet(target)) outside.push(`${target} — imported by ${f}`);
    }
  }
  // Floors: 147 code files and 532 static imports among them, measured on
  // 2026-09-23 at contract 0.38.0's set; half of each, so an honest deletion
  // is not red and an empty walk is.
  assert.ok(code.length >= 73, `only ${code.length} code file(s) in the set; this is a broken read`);
  assert.ok(edges >= 266, `only ${edges} import(s) among them; the pattern has stopped matching`);
  assert.deepEqual(missing, [], "a set entry imports a module that is not on the tree");
  assert.deepEqual(outside, [],
    "a module inside TRUST-31's set imports one outside it, so a change to the outside module changes what the " +
    "entry does without the bot returning to shadow (ops couplings entry 126). Put the module in the set by a " +
    "contract MINOR, or take the import out");
  console.log(`note  (d) ${code.length} code file(s) in the set, ${edges} static import(s) among them, all inside.`);
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
