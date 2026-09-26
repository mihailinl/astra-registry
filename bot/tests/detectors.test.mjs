// Detector A, against real git trees.
//
// Every one of these five detectors is a statement about HISTORY — what was
// added after a commit, what a commit added alongside what, how far one branch
// has fallen behind another — so none of them can be asserted against a
// directory. A fixture that is a JSON blob would be a fixture of this file's
// idea of git rather than of git, and the two defects most worth catching here
// are both in the seam: a `--diff-filter` that means something other than what
// the sentence says, and an ignore set taken from the wrong commit.
//
// So each test builds a real repository, commits into it in order, and runs the
// detector over it. They are small — three files and four commits — and they
// live under the system temp directory, which is a tmpfs here.
//
// **The fixture trees are also the dispatch input.** `detectors.yml`'s
// `workflow_dispatch` names a fixture tree so ROLL-23's live drill can fire
// each detector for real through the real alert channel; the builders below are
// what such a tree looks like, and the drill is the same shapes on a runner.
//
// Registry plan B-T3.8.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fixtureEnv } from "../../tools/lib/git-env.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { A7_BOUND_MINUTES, DETECTORS, detect, verdict } from "../detectors.mjs";
import { verdictProblems } from "../lib/alert-verdict.mjs";
import { GRACE_MINUTES } from "../../tools/served-set/report.mjs";
import {
  SOURCE_DIR as REVOCATIONS_SOURCE_DIR,
  SOURCE_PATHSPEC as REVOCATIONS_SOURCE_PATHSPEC,
} from "../../tools/lib/revocations.mjs";

// `when` is `AT(iso)`'s two dates, or nothing; the rest of the environment is a
// fixture's (tools/lib/git-env.mjs), so no inherited GIT_DIR can take the command.
const git = (cwd, args, when = {}) =>
  execFileSync("git", args, {
    cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...fixtureEnv(cwd),
      ...(when.GIT_AUTHOR_DATE ? { GIT_AUTHOR_DATE: when.GIT_AUTHOR_DATE, GIT_COMMITTER_DATE: when.GIT_COMMITTER_DATE } : {}),
    },
  }).trim();

const write = (root, rel, body) => {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), typeof body === "string" ? body : `${JSON.stringify(body, null, 2)}\n`);
};

const AT = (iso) => ({ GIT_AUTHOR_DATE: iso, GIT_COMMITTER_DATE: iso });

function commit(root, message, when) {
  git(root, ["add", "-A"]);
  git(root, ["commit", "--quiet", "-m", message], when ? AT(when) : {});
  return git(root, ["rev-parse", "HEAD"]);
}

const trash = [];
process.on("exit", () => {
  for (const d of trash) fs.rmSync(d, { recursive: true, force: true });
});

/** A registry with one listed plugin and one published version, and nothing else. */
function estate() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-detectors-"));
  trash.push(dir);
  git(dir, ["init", "--quiet", "--initial-branch=main"]);
  git(dir, ["config", "user.email", "test@example.invalid"]);
  git(dir, ["config", "user.name", "test"]);
  listing(dir, "alpha", "1.0.0");
  commit(dir, "seed", "2026-01-01T00:00:00Z");
  return dir;
}

function listing(dir, id, version, extra = {}) {
  write(dir, `plugins/${id}/plugin.json`, {
    schema: "astra.registry.plugin/1",
    id,
    name: id,
    source: { kind: "github", repo: `example/${id}` },
    ...extra.plugin,
  });
  if (version) version_(dir, id, version, extra);
}

function version_(dir, id, version, extra = {}) {
  write(dir, `plugins/${id}/versions/${version}.json`, {
    schema: "astra.registry.version/1",
    id,
    version,
    published_at: "2026-01-01T00:00:00Z",
    release: { kind: "github_release", repo: `example/${id}`, tag: `v${version}`, commit: "a".repeat(40) },
    artifacts: { noarch: { url: `https://example.invalid/${id}`, filename: `${id}.astraplugin`, sha256: "b".repeat(64), size: 1 } },
    ...extra.version,
  });
}

let recordSeq = 0;
function record(dir, doc) {
  const id = `${String(++recordSeq).padStart(4, "0")}`;
  write(dir, `log/decisions/2026/01/${id}.json`, { schema: "astra.registry.decision/1", decision_id: id, ...doc });
  return `log/decisions/2026/01/${id}.json`;
}

const migrationRecord = (dir, id, version) => record(dir, {
  decided_at: "2026-01-01T00:00:00Z",
  actor: "system",
  trigger: "migration",
  plugin_id: id,
  version,
  repo: `example/${id}`,
  tag: `v${version}`,
  state: "published",
  repository_id: "111",
  repository_owner_id: "222",
});

/**
 * The baseline commit: a `migration` record for every non-staging version in
 * the tree, and the marker naming the commit they were computed over.
 */
function baseline(dir, { versions = [["alpha", "1.0.0"]], marker = {} } = {}) {
  const sourceCommit = git(dir, ["rev-parse", "HEAD"]);
  for (const [id, version] of versions) migrationRecord(dir, id, version);
  write(dir, "log/baseline.json", {
    schema: "astra.registry.baseline/1",
    written_at: "2026-01-02T00:00:00Z",
    source_commit: sourceCommit,
    version_count: versions.length,
    record_count: versions.length,
    ...marker,
  });
  return { sourceCommit, commit: commit(dir, "registry: the migration baseline", "2026-01-02T00:00:00Z") };
}

const codes = (r) => r.findings.map((f) => f.code).sort();
// The detectors skipped WHOLE. A skip that names a `clause` is one clause of a
// detector that otherwise ran (A11's third, before contract 3.0.0's landing
// commit exists), and it is read by `clauseSkips`.
const skipped = (r) => r.skipped.filter((s) => s.clause === undefined).map((s) => s.detector).sort();
const clauseSkips = (r) => r.skipped.filter((s) => s.clause !== undefined).map((s) => `${s.detector}.${s.clause}`).sort();

// ── skipping, and that it is derived ────────────────────────────────────────

test("with no marker and no `signed`, every detector that needs one skips and nothing alarms", () => {
  // A11 needs neither. Its first two clauses read every commit that changed a
  // version record, whatever the marker says; its third needs contract 3.0.0's
  // landing commit, which this tree does not have, and says so by clause.
  const dir = estate();
  const r = detect({ root: dir });
  assert.deepEqual(skipped(r), DETECTORS.filter((d) => d !== "A11").sort(), "a detector ran with its input absent");
  assert.deepEqual(clauseSkips(r), ["A11.3"], "A11's third clause ran with no landing commit to count from");
  assert.deepEqual(codes(r), [], "a skipped detector produced a finding");
  assert.deepEqual(r.ran, ["A11"]);
});

test("the skip is derived from the marker, not written down: with one, four detectors run", () => {
  // The mutation this is for: `if (false)` in front of a skip, or a skip list
  // that is a literal. Both keep every test above green. Here the only thing
  // that changed between the two runs is that the marker exists.
  const dir = estate();
  baseline(dir);
  const r = detect({ root: dir });
  assert.deepEqual(skipped(r), ["A7"], "a detector still skipped with a baseline on the tree");
  assert.deepEqual(r.ran.sort(), ["A1", "A11", "A3", "A5", "A9"]);
});

test("a marker naming a source_commit that is not an ancestor of its own commit is a finding, not a skip", () => {
  const dir = estate();
  baseline(dir, { marker: { source_commit: "f".repeat(40) } });
  const r = detect({ root: dir });
  assert.ok(codes(r).includes("A1_BASELINE_UNREADABLE"),
    `a moved marker went unnoticed: ${JSON.stringify(codes(r))}`);
});

// ── A1 and MIG-20's tree check ──────────────────────────────────────────────

test("A1: a version published after the baseline with no record alarms; the historic one does not", () => {
  const dir = estate();
  baseline(dir);
  version_(dir, "alpha", "1.1.0");
  commit(dir, "registry: publish", "2026-01-03T00:00:00Z");

  const r = detect({ root: dir });
  assert.deepEqual(codes(r), ["A1_PUBLISHED_UNRECORDED"]);
  assert.equal(r.findings[0].plugin_id, "alpha");
  // The historic version is the one BOT-75 exists for: it has a `migration`
  // record and no `published` one, and a detector that did not ignore history
  // would report it too.
  assert.ok(!r.findings.some((f) => /1\.0\.0/.test(f.message)), "the pre-baseline version alarmed");
});

test("A1: the same version WITH its published record is silent", () => {
  const dir = estate();
  baseline(dir);
  version_(dir, "alpha", "1.1.0");
  record(dir, {
    decided_at: "2026-01-03T00:00:00Z", actor: "bot", trigger: "issue", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "published", repository_id: "111", repository_owner_id: "222",
  });
  commit(dir, "registry: publish", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), []);
});

test("MIG-20's tree check: a baselined version whose `migration` record is gone", () => {
  // The plan's named mutation, done to the tree instead of to the code:
  // "watched by deleting one record in a fixture tree".
  const dir = estate();
  const { commit: at } = baseline(dir);
  void at;
  const file = fs.readdirSync(path.join(dir, "log/decisions/2026/01"))[0];
  fs.rmSync(path.join(dir, "log/decisions/2026/01", file));
  commit(dir, "registry: a record disappears", "2026-01-04T00:00:00Z");
  // Two witnesses since the marker's count became a floor: the version with
  // no record, and a walk that reads fewer records than the baseline wrote.
  assert.deepEqual(codes(detect({ root: dir })), ["A1_RECORDS_BELOW_MARKER", "MIG20_NO_MIGRATION_RECORD"]);
});

test("MIG-20's tree check: a staging entry never carries a baseline record", () => {
  const dir = estate();
  version_(dir, "alpha", "0.9.0", { version: { staging: true, staging_reason: "no release yet" } });
  commit(dir, "registry: a staging entry", "2026-01-01T12:00:00Z");
  baseline(dir, { versions: [["alpha", "1.0.0"], ["alpha", "0.9.0"]] });
  assert.deepEqual(codes(detect({ root: dir })), ["MIG20_STAGING_BASELINED"]);
});

test("MIG-20's tree check: a post-baseline publication must carry both certificate ids", () => {
  const dir = estate();
  baseline(dir);
  version_(dir, "alpha", "1.1.0");
  record(dir, {
    decided_at: "2026-01-03T00:00:00Z", actor: "bot", trigger: "issue", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "published", repository_id: "111",
  });
  commit(dir, "registry: publish with half an identity", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), ["MIG20_IDS_MISSING"]);
});

test("A1's floor: a baseline over a tree the walk cannot see is a finding", () => {
  // The failure a floor is for. `nonStagingVersions` returning nothing — a
  // renamed directory, a walk that lost its root — makes every loop above run
  // over nothing and the whole of A1 green.
  const dir = estate();
  baseline(dir);
  fs.rmSync(path.join(dir, "plugins"), { recursive: true });
  commit(dir, "registry: the catalogue leaves", "2026-01-05T00:00:00Z");
  assert.ok(codes(detect({ root: dir })).includes("A1_SCANNED_NOTHING"));
});

// ── A3 ──────────────────────────────────────────────────────────────────────

test("A3: a `delayed` record whose queue entry is not on the tree", () => {
  const dir = estate();
  baseline(dir);
  record(dir, {
    decided_at: "2026-01-03T00:00:00Z", actor: "bot", trigger: "issue", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "delayed", publish_after: "2026-01-04T00:00:00Z",
  });
  commit(dir, "registry: a promise with no entry", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), ["A3_DELAYED_NO_ENTRY"]);
});

test("A3: the same record WITH its queue entry is silent", () => {
  const dir = estate();
  baseline(dir);
  record(dir, {
    decided_at: "2026-01-03T00:00:00Z", actor: "bot", trigger: "issue", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "delayed", publish_after: "2026-01-04T00:00:00Z",
  });
  write(dir, "state/queue/alpha@1.1.0.json", { repo: "example/alpha", tag: "v1.1.0", publish_after: "2026-01-04T00:00:00Z" });
  commit(dir, "registry: a promise and its entry", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), []);
});

test("A3: a queue entry removed in a commit that wrote no record", () => {
  const dir = estate();
  write(dir, "state/queue/alpha@1.1.0.json", { repo: "example/alpha", tag: "v1.1.0", publish_after: "2026-01-04T00:00:00Z" });
  commit(dir, "registry: queued", "2026-01-01T06:00:00Z");
  baseline(dir);
  fs.rmSync(path.join(dir, "state/queue/alpha@1.1.0.json"));
  commit(dir, "registry: unqueued, quietly", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), ["A3_QUEUE_REMOVED_NO_RECORD"]);
});

test("A3: a drain that removes the entry and writes the record in one commit is silent", () => {
  // BOT-73: one commit per run, holding all its records. The two halves are
  // asked of the same commit for exactly that reason, and this is the case
  // that fails if they are asked of the tree instead.
  const dir = estate();
  write(dir, "state/queue/alpha@1.1.0.json", { repo: "example/alpha", tag: "v1.1.0", publish_after: "2026-01-04T00:00:00Z" });
  commit(dir, "registry: queued", "2026-01-01T06:00:00Z");
  baseline(dir);
  fs.rmSync(path.join(dir, "state/queue/alpha@1.1.0.json"));
  version_(dir, "alpha", "1.1.0");
  record(dir, {
    decided_at: "2026-01-03T00:00:00Z", actor: "bot", trigger: "drain", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "published", repository_id: "111", repository_owner_id: "222",
  });
  commit(dir, "registry: publish (drain)", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), []);
});

// ── A5 ──────────────────────────────────────────────────────────────────────

test("A5: `published` beside `stopped` for one fingerprint", () => {
  const dir = estate();
  baseline(dir);
  for (const state of ["stopped", "published"]) {
    record(dir, {
      decided_at: "2026-01-03T00:00:00Z", actor: state === "stopped" ? "moderator" : "bot", trigger: "issue",
      plugin_id: "alpha", version: "1.1.0", repo: "example/alpha", tag: "v1.1.0", state,
      fingerprint: "0123456789abcdef", repository_id: "111", repository_owner_id: "222",
    });
  }
  version_(dir, "alpha", "1.1.0");
  commit(dir, "registry: a stop, bypassed", "2026-01-03T00:00:00Z");
  const r = detect({ root: dir });
  assert.ok(codes(r).includes("A5_PUBLISHED_BESIDE_STOP"), JSON.stringify(codes(r)));
  assert.ok(r.findings.some((f) => f.hex === "0123456789abcdef"));
});

test("A5: a stop on OTHER bytes of the same version is not a bypass", () => {
  // The reason row 5 is keyed on the fingerprint. A stop is about the exact
  // bytes a person looked at; a rebuilt release is a different fingerprint and
  // a different decision, and a version-keyed check would call it a bypass.
  const dir = estate();
  baseline(dir);
  record(dir, {
    decided_at: "2026-01-03T00:00:00Z", actor: "moderator", trigger: "moderation", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "stopped", fingerprint: "0123456789abcdef",
  });
  record(dir, {
    decided_at: "2026-01-04T00:00:00Z", actor: "bot", trigger: "issue", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "published", fingerprint: "fedcba9876543210",
    repository_id: "111", repository_owner_id: "222",
  });
  version_(dir, "alpha", "1.1.0");
  commit(dir, "registry: a rebuild, published", "2026-01-04T00:00:00Z");
  assert.ok(!codes(detect({ root: dir })).includes("A5_PUBLISHED_BESIDE_STOP"));
});

// ── A7 ──────────────────────────────────────────────────────────────────────

/**
 * The first commit on `signed`, with the trailers `tools/signer/run.mjs`
 * writes for a freshly generated catalogue: `Index-Source-Commit` is the run's
 * `Source-Commit` (B.4). `{ index: null }` leaves `Index-Source-Commit` out,
 * which no signer run writes and B.4 does not allow; `{ index: sha }` names
 * another commit.
 */
function signedAt(dir, sourceCommit, when, { index = sourceCommit } = {}) {
  const main = git(dir, ["rev-parse", "HEAD"]);
  git(dir, ["checkout", "--quiet", "--orphan", "signed"]);
  git(dir, ["rm", "-rq", "--cached", "."]);
  for (const e of fs.readdirSync(dir)) if (e !== ".git") fs.rmSync(path.join(dir, e), { recursive: true, force: true });
  write(dir, "registry/v1/index.json", { schema: "astra.registry.index/1" });
  git(dir, ["add", "-A"]);
  const trailers =
    `Source-Commit: ${sourceCommit}\nRun: https://example.invalid/runs/0\nSigner: sign.yml\n` +
    (index === null ? "" : `Index-Source-Commit: ${index}\n`);
  git(dir, ["commit", "--quiet", "-m", `registry: signed\n\n${trailers}`], AT(when));
  git(dir, ["checkout", "--quiet", "main"]);
  return main;
}

// Every A7 test names its `now`. A7 measures against the run's clock (gap 76),
// and these fixtures are dated 2026-01-01, so a test that left `now` to the
// wall clock would find every change months overdue: it would pass, and it
// would stop being able to see its own bound.
const NOW = (iso) => Date.parse(iso);

test("A7: `signed` three hours behind the newest plugins commit", () => {
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  version_(dir, "alpha", "1.1.0");
  commit(dir, "registry: publish", "2026-01-01T03:30:00Z");
  signedAt(dir, source, "2026-01-01T03:31:00Z");
  const r = detect({ root: dir, now: NOW("2026-01-01T06:30:00Z") });
  assert.ok(codes(r).includes("A7_SIGNED_BEHIND_PLUGINS"), JSON.stringify(codes(r)));
  assert.ok(!r.skipped.some((s) => s.detector === "A7"), "A7 skipped with `signed` present");
});

test("A7: inside the two-hour bound, nothing", () => {
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  version_(dir, "alpha", "1.1.0");
  commit(dir, "registry: publish", "2026-01-01T01:30:00Z");
  signedAt(dir, source, "2026-01-01T01:31:00Z");
  assert.ok(!codes(detect({ root: dir, now: NOW("2026-01-01T03:00:00Z") })).includes("A7_SIGNED_BEHIND_PLUGINS"));
  assert.equal(A7_BOUND_MINUTES.plugins, 120);
});

test("A7: the revocations bound is thirty minutes, not two hours", () => {
  // Watched failing by giving both paths the same bound: this advisory has
  // waited 40 minutes, which is inside the plugins bound and outside this one.
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  write(dir, "tools/revocations/one.json", { schema: "astra.registry.revocation/1" });
  commit(dir, "registry: a revocation", "2026-01-01T00:40:00Z");
  signedAt(dir, source, "2026-01-01T00:41:00Z");
  const found = codes(detect({ root: dir, now: NOW("2026-01-01T01:20:00Z") }));
  assert.ok(found.includes("A7_SIGNED_BEHIND_REVOCATIONS"), JSON.stringify(found));
  assert.ok(!found.includes("A7_SIGNED_BEHIND_PLUGINS"), "the plugins bound fired at 40 minutes");
  assert.equal(A7_BOUND_MINUTES.revocations, 30);
  assert.equal(A7_BOUND_MINUTES.revocations, GRACE_MINUTES,
    "A7's withdrawal-list bound and SERVE-85's window are one requirement and have parted");
});

test("A7: the withdrawal list's README is not the withdrawal list", () => {
  // The live failure, 2026-09-20 09:25. `a6a4c55` added ten lines to
  // `tools/revocations/README.md`; A7 read the directory, computed 223 minutes
  // against a thirty-minute bound and alarmed. Every number was right and the
  // subject was wrong: the list's entries had not changed, only its serial,
  // which counts the README too. `detectors.yml` went red; it had read
  // `signed` three seconds before the same push's signer run committed serial
  // 4, and its next run, seven minutes later, was green. `tools/lib/revocations.mjs`
  // carries the timeline.
  //
  // Three hours here rather than forty minutes, so this stays red for the
  // original defect however the bound is later tuned.
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  write(dir, "tools/revocations/README.md", "# advisories\n\nHow to write one.\n");
  commit(dir, "docs: how to write an advisory", "2026-01-01T03:00:00Z");
  signedAt(dir, source, "2026-01-01T03:01:00Z");
  const found = codes(detect({ root: dir, now: NOW("2026-01-01T06:00:00Z") }));
  assert.ok(
    !found.includes("A7_SIGNED_BEHIND_REVOCATIONS"),
    `a documentation commit alarmed the withdrawal-list detector: ${JSON.stringify(found)}`,
  );
});

test("A7: an advisory beside that README still alarms", () => {
  // The control, and it is the half that matters. A fix for the test above
  // that stopped A7 firing at all would pass it, and the alarm exists because
  // a stale signed withdrawal list is how a revoked plugin stays installable.
  // Same directory, same commit time, one `.json` instead of one `.md`.
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  write(dir, "tools/revocations/README.md", "# advisories\n");
  write(dir, "tools/revocations/ASTRA-2026-0001.json", { schema: "astra.registry.revocation/1" });
  commit(dir, "registry: an advisory, and a line about advisories", "2026-01-01T03:00:00Z");
  signedAt(dir, source, "2026-01-01T03:01:00Z");
  const found = codes(detect({ root: dir, now: NOW("2026-01-01T06:00:00Z") }));
  assert.ok(found.includes("A7_SIGNED_BEHIND_REVOCATIONS"), JSON.stringify(found));
});

/**
 * Gap 68's shape: a change committed on a branch at 01:00, main moving on at
 * 01:30 without it — the commit `signed` then signs — and the pull request
 * merged with a real merge commit at 04:00. The change became reachable from
 * main at 04:00, so `signed` is 150 minutes behind it: outside both bounds.
 *
 * A plain `git log -1 -- <pathspec>` simplifies history through the merge,
 * which is TREESAME to its branch parent for the path, and dates the branch
 * commit — 30 minutes BEFORE the Source-Commit, a negative drift, and A7 says
 * nothing. Measured 2026-09-22 before the repair: drift -30 on both halves,
 * no finding on either, against a true drift of 150.
 */
function mergedFromBranch(file, body) {
  const dir = estate();
  git(dir, ["checkout", "--quiet", "-b", "topic"]);
  write(dir, file, body);
  commit(dir, `a change to ${file}, on a branch`, "2026-01-01T01:00:00Z");
  git(dir, ["checkout", "--quiet", "main"]);
  write(dir, "docs/elsewhere.md", "main moves on while the pull request is open\n");
  const source = commit(dir, "docs: elsewhere", "2026-01-01T01:30:00Z");
  git(dir, ["merge", "--quiet", "--no-ff", "-m", "Merge pull request #1 from topic", "topic"], AT("2026-01-01T04:00:00Z"));
  const merge = git(dir, ["rev-parse", "HEAD"]);
  // The fixture guards. The merge is a merge, and the plain path-limited log
  // dates the branch commit here — otherwise this tree cannot tell the two
  // clocks apart and the assertions below are about nothing.
  assert.equal(git(dir, ["rev-list", "--parents", "-n", "1", merge]).split(" ").length, 3, "the fixture's merge is not a two-parent commit");
  assert.equal(git(dir, ["log", "-1", "--format=%cI", merge, "--", file]), "2026-01-01T01:00:00Z",
    "a plain path-limited log no longer dates the branch commit, so this fixture no longer separates the two clocks");
  signedAt(dir, source, "2026-01-01T04:01:00Z");
  return { dir, merge };
}

test("A7: an advisory merged from a long-lived branch is dated at the merge", () => {
  const { dir, merge } = mergedFromBranch(`${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  const r = detect({ root: dir, now: NOW("2026-01-01T06:30:00Z") });
  assert.equal(r.scanned.revocations_drift_minutes, 150,
    `A7 measured ${r.scanned.revocations_drift_minutes} minutes; the advisory became reachable from main at the merge, 150 minutes after the Source-Commit`);
  const found = r.findings.find((f) => f.code === "A7_SIGNED_BEHIND_REVOCATIONS");
  assert.ok(found, `a withdrawal merged 150 minutes after \`signed\`'s Source-Commit went unreported: ${JSON.stringify(codes(r))}`);
  assert.equal(found.hex, merge, "the finding names a commit other than the merge that brought the advisory onto main");
});

test("A7: a publication merged from a long-lived branch is dated at the merge", () => {
  const { dir, merge } = mergedFromBranch("plugins/alpha/versions/1.1.0.json", { schema: "astra.registry.version/1" });
  const r = detect({ root: dir, now: NOW("2026-01-01T06:30:00Z") });
  assert.equal(r.scanned.plugins_drift_minutes, 150,
    `A7 measured ${r.scanned.plugins_drift_minutes} minutes; the version became reachable from main at the merge, 150 minutes after the Source-Commit`);
  const found = r.findings.find((f) => f.code === "A7_SIGNED_BEHIND_PLUGINS");
  assert.ok(found, `a publication merged 150 minutes after \`signed\`'s Source-Commit went unreported: ${JSON.stringify(codes(r))}`);
  assert.equal(found.hex, merge, "the finding names a commit other than the merge that brought the version onto main");
});

// ── A7 and the run's clock (gap 76) ─────────────────────────────────────────
//
// `detectors.yml` and `sign.yml` start on the same push. The detector reads
// `signed` a few seconds in, the signer commits a few seconds later, and in
// every such pair measured on 2026-09-22 the detector read first. A7 used to
// subtract the Source-Commit's time from the newest change's and never read
// `now`, so a Source-Commit older than the bound made the push's own run alarm
// — run 35502265394, the only A7 red there has been, fetched `signed` at
// 09:25:28Z and the signer committed at 09:25:31Z — and a Source-Commit within
// the bound made A7 blind to a signer that never ran again.

/**
 * `signed` made at 00:01 from the seed (00:00), then one push at 03:00 that
 * moves both documents' inputs. The previous Source-Commit is 180 minutes
 * older than the push, past both bounds, which is the shape that raced.
 */
function pushAfterQuiet() {
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  signedAt(dir, source, "2026-01-01T00:01:00Z");
  version_(dir, "alpha", "1.1.0");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  const push = commit(dir, "Merge pull request #2: an advisory, and a publication", "2026-01-01T03:00:00Z");
  // The fixture guard, from git and not from A7: the drift the old arithmetic
  // read is past both bounds, so this tree is the race's shape and not a
  // quieter one that would pass either way.
  const quiet = (Date.parse(git(dir, ["log", "-1", "--format=%cI", push])) - Date.parse(git(dir, ["log", "-1", "--format=%cI", source]))) / 60000;
  assert.ok(quiet > A7_BOUND_MINUTES.plugins && quiet > A7_BOUND_MINUTES.revocations,
    `the fixture's previous Source-Commit is only ${quiet} minutes older than the push`);
  return { dir, push };
}

const a7Codes = (r) => r.findings.filter((f) => f.detector === "A7").map((f) => f.code).sort();

test("A7 does not alarm on a push its signer has not had time to sign", () => {
  const { dir } = pushAfterQuiet();
  const r = detect({ root: dir, now: NOW("2026-01-01T03:00:03Z") });
  assert.deepEqual(a7Codes(r), [],
    "A7 alarmed three seconds after the push, reading `signed` before the same push's signer could commit");
  // Not vacuous: `signed` IS behind on both halves, by one commit, for seconds.
  assert.equal(r.scanned.plugins_unsigned_commits, 1);
  assert.equal(r.scanned.revocations_unsigned_commits, 1);
  assert.equal(r.scanned.revocations_unsigned_minutes, 0);
});

test("A7 still alarms when the signer has not caught up after the grace", () => {
  const { dir, push } = pushAfterQuiet();
  const at = (iso) => a7Codes(detect({ root: dir, now: NOW(iso) }));
  // The list's grace is its bound, 30 minutes, inclusive as SERVE-85's is.
  assert.deepEqual(at("2026-01-01T03:30:00Z"), [], "the list alarmed with the signer still inside its 30 minutes");
  assert.deepEqual(at("2026-01-01T03:30:01Z"), ["A7_SIGNED_BEHIND_REVOCATIONS"],
    "no signer run in 30 minutes, and the withdrawal list's half said nothing");
  // The catalogue has two hours; the list is still overdue beside it.
  assert.deepEqual(at("2026-01-01T05:00:00Z"), ["A7_SIGNED_BEHIND_REVOCATIONS"]);
  assert.deepEqual(at("2026-01-01T05:00:01Z"), ["A7_SIGNED_BEHIND_PLUGINS", "A7_SIGNED_BEHIND_REVOCATIONS"],
    "no signer run in two hours, and the catalogue's half said nothing");
  const found = detect({ root: dir, now: NOW("2026-01-01T13:00:00Z") }).findings.filter((f) => f.detector === "A7");
  assert.deepEqual(found.map((f) => f.hex), [push, push], "the finding names a commit other than the unsigned push");
});

test("A7 alarms on a change the signer never signed, however soon after the last Source-Commit it landed", () => {
  // The other half of the same defect. Measured before the repair: an
  // advisory 20 minutes after the Source-Commit gave a drift of 20, inside
  // the bound, at every hour after — a signer that stopped was invisible.
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  signedAt(dir, source, "2026-01-01T00:01:00Z");
  version_(dir, "alpha", "1.1.0");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  commit(dir, "registry: an advisory and a publication, soon after the last signing", "2026-01-01T00:20:00Z");
  const r = detect({ root: dir, now: NOW("2026-01-01T10:20:00Z") });
  assert.deepEqual(a7Codes(r), ["A7_SIGNED_BEHIND_PLUGINS", "A7_SIGNED_BEHIND_REVOCATIONS"],
    "ten hours with no signer run, and A7 said nothing because the change came 20 minutes after the last one");
});

test("A7 is silent at any hour once `signed` carries the change", () => {
  // What keeps "compare with now" from becoming "alarm on anything old": the
  // question is what `signed` does NOT carry, and here it carries everything.
  const dir = estate();
  version_(dir, "alpha", "1.1.0");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  const push = commit(dir, "registry: an advisory and a publication", "2026-01-01T03:00:00Z");
  signedAt(dir, push, "2026-01-01T03:01:00Z");
  const r = detect({ root: dir, now: NOW("2026-01-11T03:00:00Z") });
  assert.deepEqual(a7Codes(r), [], "A7 alarmed ten days on about changes `signed` already carries");
  assert.equal(r.scanned.revocations_unsigned_commits, 0);
});

test("A7 measures from the oldest change `signed` does not carry, so a later one cannot reset it", () => {
  // A dead signer on a `main` that keeps taking advisories: dated at the
  // newest, the wait would restart with every one and never pass the bound.
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  signedAt(dir, source, "2026-01-01T00:01:00Z");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  const first = commit(dir, "registry: an advisory", "2026-01-01T00:10:00Z");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0002.json`, { schema: "astra.registry.revocation/1" });
  commit(dir, "registry: another", "2026-01-01T00:30:00Z");
  const r = detect({ root: dir, now: NOW("2026-01-01T00:41:00Z") });
  const found = r.findings.find((f) => f.code === "A7_SIGNED_BEHIND_REVOCATIONS");
  assert.ok(found, `the first advisory has waited 31 minutes and A7 dated the wait from the second: ${JSON.stringify(r.scanned)}`);
  assert.equal(found.hex, first);
  assert.equal(r.scanned.revocations_unsigned_minutes, 31);
});

test("A7: a change dated after the run's clock is overdue, not excused until its date", () => {
  // The one shape `now` could have hidden and the old arithmetic did not: a
  // committer date in the future makes the wait negative, and a negative wait
  // is inside any bound. Past the bound's own width it is a clock that cannot
  // be read, and SERVE-85's rule for those is that they excuse nothing.
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  signedAt(dir, source, "2026-01-01T00:01:00Z");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  commit(dir, "registry: an advisory from a committer whose clock is wrong", "2026-06-01T00:00:00Z");
  assert.deepEqual(a7Codes(detect({ root: dir, now: NOW("2026-01-01T03:00:00Z") })), ["A7_SIGNED_BEHIND_REVOCATIONS"]);
  // A few minutes of skew between the runner and whoever dated the merge is
  // not that, and must not page.
  assert.deepEqual(a7Codes(detect({ root: dir, now: NOW("2026-05-31T23:55:00Z") })), []);
});

test("A7: a README commit after a signed advisory is not a change `signed` has missed", () => {
  // The walk that decides reads the list's SOURCE_PATHSPEC as the dating
  // does. With an advisory already signed, only the question "what has not
  // been signed" can see this README, and it must not count it.
  const dir = estate();
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  const advisory = commit(dir, "registry: an advisory", "2026-01-01T01:00:00Z");
  signedAt(dir, advisory, "2026-01-01T01:01:00Z");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/README.md`, "# advisories\n\nHow to write one.\n");
  commit(dir, "docs: how to write an advisory", "2026-01-01T03:00:00Z");
  const r = detect({ root: dir, now: NOW("2026-01-01T06:00:00Z") });
  assert.deepEqual(a7Codes(r), [], `a documentation commit after the signed advisory alarmed: ${JSON.stringify(r.scanned)}`);
  assert.equal(r.scanned.revocations_unsigned_commits, 0);
});

test("A7: the signer's time on a merged change starts at the merge", () => {
  // Gap 68's shape, asked of the clock `now` is compared with: the advisory
  // was committed on a branch at 01:00 and reached main at 04:00. Ten minutes
  // after the merge the signer has had ten minutes, not 190.
  const { dir, merge } = mergedFromBranch(`${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  const early = detect({ root: dir, now: NOW("2026-01-01T04:10:00Z") });
  assert.equal(early.scanned.revocations_unsigned_minutes, 10,
    `A7 dated the advisory's wait from somewhere other than the merge: ${JSON.stringify(early.scanned)}`);
  assert.deepEqual(a7Codes(early), []);
  const late = detect({ root: dir, now: NOW("2026-01-01T04:31:00Z") });
  assert.deepEqual(late.findings.filter((f) => f.detector === "A7").map((f) => f.hex), [merge]);
});

/**
 * One more commit on `signed`, with D2's trailers as `tools/signer/run.mjs`
 * writes them: `Source-Commit` is the run's, `Index-Source-Commit` the tree
 * the catalogue was generated from. They differ when the catalogue was carried
 * and also when it was `unchanged` (run.mjs keeps the head's for both). On the
 * real `signed`, 2 of its 8 commits differ, `ae80bc7` and `f2afd04`, and both
 * were `unchanged`, not carried.
 */
function signedAgain(dir, sourceCommit, indexSourceCommit, when, subject = "signed: the list re-signed, the catalogue carried") {
  git(dir, ["checkout", "--quiet", "signed"]);
  write(dir, "registry/v1/revocations.json", { schema: "astra.registry.revocations/1", at: when });
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "--quiet", "-m",
    `${subject}\n\n` +
    `Source-Commit: ${sourceCommit}\nRun: https://example.invalid/runs/1\nSigner: sign.yml\n` +
    `Index-Source-Commit: ${indexSourceCommit}\n`], AT(when));
  git(dir, ["checkout", "--quiet", "main"]);
}

/** The first-parent commits in `from..to` under a pathspec, from git and not from A7. */
const firstParentTouching = (dir, from, to, pathspec) =>
  git(dir, ["log", "--first-parent", "--format=%H", `${from}..${to}`, "--", pathspec]).split("\n").filter(Boolean);

/**
 * A carried catalogue: `signed` made from the seed at 00:01, a publication at
 * 01:00, an advisory at 01:02, and a signer run at 01:05 that carried the
 * catalogue past a failed gate and committed anyway because the list changed.
 * So `Source-Commit` is the advisory — main's head — and `Index-Source-Commit`
 * is still the seed. The publication is in the first and not the second.
 */
function carriedCatalogue() {
  const dir = estate();
  const seed = git(dir, ["rev-parse", "HEAD"]);
  signedAt(dir, seed, "2026-01-01T00:01:00Z");
  version_(dir, "alpha", "1.1.0");
  const publish = commit(dir, "registry: publish", "2026-01-01T01:00:00Z");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  const advisory = commit(dir, "registry: an advisory", "2026-01-01T01:02:00Z");
  signedAgain(dir, advisory, seed, "2026-01-01T01:05:00Z");
  // The fixture guards, from git: the Source-Commit contains the publication,
  // so a catalogue half reading it sees nothing, and the Index-Source-Commit
  // does not, so one reading row 7's trailer sees exactly the publication.
  assert.deepEqual(firstParentTouching(dir, advisory, "main", "plugins"), [],
    "the fixture's Source-Commit does not contain the publication, so it cannot tell the two trailers apart");
  assert.deepEqual(firstParentTouching(dir, seed, "main", "plugins"), [publish],
    "the fixture's Index-Source-Commit is not exactly one publication behind");
  return { dir, seed, publish, advisory };
}

test("A7's catalogue half reads the served catalogue's Index-Source-Commit (row 7, 0.32.0)", () => {
  // Row 7 at 0.32.0: "the oldest commit on main's first-parent line that
  // brought a change under plugins/ and that the served catalogue's
  // Index-Source-Commit does not contain … has been on main more than 2 h …
  // counted to now". Until 0.32.0 A7 read Source-Commit here by decision
  // (astra-registry PR #219), and was silent on this tree at every hour:
  // measured 2026-09-22 at 03:00:01 and at 09:00, no finding.
  const { dir, seed, publish, advisory } = carriedCatalogue();
  const plugins = (iso) => detect({ root: dir, now: NOW(iso) }).findings.filter((f) => f.code === "A7_SIGNED_BEHIND_PLUGINS");
  const r = detect({ root: dir, now: NOW("2026-01-01T03:00:00Z") });
  assert.equal(r.scanned.signed_source_commit, advisory, "A7 took Source-Commit from somewhere other than its trailer");
  assert.equal(r.scanned.signed_index_source_commit, seed, "A7 took Index-Source-Commit from somewhere other than its trailer");
  assert.equal(r.scanned.plugins_unsigned_commits, 1,
    "A7's catalogue half does not see the publication the served catalogue was not generated from: it is reading Source-Commit");
  // The bound is the grace, inclusive as SERVE-85's is: 120 minutes after the
  // publication the signer is still inside it, and one second later it is not.
  assert.deepEqual(plugins("2026-01-01T03:00:00Z"), [], "the catalogue half alarmed with the signer still inside its two hours");
  const late = plugins("2026-01-01T03:00:01Z");
  assert.equal(late.length, 1,
    "a catalogue carried from before a publication, two hours and a second after it, and A7's catalogue half said nothing");
  assert.equal(late[0].hex, publish, "the finding names a commit other than the publication the served catalogue does not contain");
  assert.match(late[0].message, /Index-Source-Commit/, "the finding does not say which trailer it measured from");
  // Eight hours on, the hour astra-registry PR #219 measured silent.
  assert.equal(plugins("2026-01-01T09:00:00Z").length, 1, "eight hours after the publication, the carried catalogue is still unreported");
});

test("A7's list half stays on `Source-Commit`, narrower than row 7's serial: an advisory the served list carries is not behind, whatever the catalogue's trailer says", () => {
  // Row 7's list half reads the list's serial from contract 0.34.0; A7's reads
  // Source-Commit, which is narrower (bot/detectors.mjs says why, and since
  // 0.35.0 why it is never wider), and the list has no trailer of its own; a
  // carried list is SERVE-85's, by its serial. Here the list was signed
  // at the advisory while the catalogue was carried from before it, so a list
  // half that read Index-Source-Commit would report an advisory `signed` holds.
  const { dir, advisory } = carriedCatalogue();
  const r = detect({ root: dir, now: NOW("2026-01-01T09:00:00Z") });
  assert.ok(!codes(r).includes("A7_SIGNED_BEHIND_REVOCATIONS"),
    `A7's list half alarmed on an advisory the served list carries: it is reading Index-Source-Commit (${JSON.stringify(r.scanned)})`);
  assert.equal(r.scanned.revocations_unsigned_commits, 0);
  // The control: the list half is not switched off. An advisory after the
  // Source-Commit is behind, and at its own 30 minutes.
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0002.json`, { schema: "astra.registry.revocation/1" });
  const second = commit(dir, "registry: another advisory", "2026-01-01T02:00:00Z");
  assert.notEqual(second, advisory);
  const at = (iso) => detect({ root: dir, now: NOW(iso) }).findings.filter((f) => f.code === "A7_SIGNED_BEHIND_REVOCATIONS").map((f) => f.hex);
  assert.deepEqual(at("2026-01-01T02:30:00Z"), [], "the list half alarmed inside its 30 minutes");
  assert.deepEqual(at("2026-01-01T02:30:01Z"), [second], "an advisory the served list does not carry, 30 minutes on, and the list half said nothing");
});

test("A7: an unchanged catalogue whose two trailers differ is not a carry, and alarms on nothing (the shape of `ae80bc7` and `f2afd04`)", () => {
  // Ops register entry 96. The signer keeps the head's Index-Source-Commit
  // when the catalogue is `unchanged` as well as when it is carried, and the
  // two real `signed` commits whose trailers differ are both unchanged: main
  // moved, and nothing under `plugins/` did. A reader that took "the trailers
  // differ" for "carried" would report two carries that never happened.
  const dir = estate();
  const seed = git(dir, ["rev-parse", "HEAD"]);
  signedAt(dir, seed, "2026-01-01T00:01:00Z");
  write(dir, "docs/elsewhere.md", "main moves on outside plugins/\n");
  commit(dir, "docs: elsewhere", "2026-01-01T00:30:00Z");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  const advisory = commit(dir, "registry: an advisory", "2026-01-01T00:40:00Z");
  signedAgain(dir, advisory, seed, "2026-01-01T00:45:00Z", "signed: the list changed, the catalogue unchanged");
  // The fixture guards: the trailers differ, nothing under plugins/ lies
  // between them, and the advisory does — so this tree is the real shape and
  // also the one a list half reading the wrong trailer would alarm on.
  assert.deepEqual(firstParentTouching(dir, seed, advisory, "plugins"), [], "the fixture has a plugins/ commit between its trailers");
  assert.deepEqual(firstParentTouching(dir, seed, advisory, REVOCATIONS_SOURCE_PATHSPEC), [advisory]);
  const r = detect({ root: dir, now: NOW("2026-01-01T10:45:00Z") });
  assert.notEqual(r.scanned.signed_index_source_commit, r.scanned.signed_source_commit, "the fixture's two trailers agree");
  assert.deepEqual(a7Codes(r), [], `an unchanged catalogue with differing trailers alarmed, ten hours on: ${JSON.stringify(r.scanned)}`);
  assert.equal(r.scanned.plugins_unsigned_commits, 0);
  assert.equal(r.scanned.revocations_unsigned_commits, 0);
});

test("A7: `signed` with no Index-Source-Commit trailer is a finding, not a fallback to Source-Commit, and the list half still runs", () => {
  // B.4 has every `signed` commit name both trailers, and every signer run
  // writes both (all eight on the real branch do). A head without one did not
  // come from a signer run; reading Source-Commit in its place is the reading
  // that was blind to a carried catalogue, so the catalogue half says so and
  // stops, and the list half, which never needed the trailer, goes on.
  const dir = estate();
  const seed = git(dir, ["rev-parse", "HEAD"]);
  signedAt(dir, seed, "2026-01-01T00:01:00Z", { index: null });
  version_(dir, "alpha", "1.1.0");
  write(dir, `${REVOCATIONS_SOURCE_DIR}/ASTRA-2026-0001.json`, { schema: "astra.registry.revocation/1" });
  commit(dir, "registry: an advisory and a publication, never signed", "2026-01-01T01:00:00Z");
  assert.doesNotMatch(git(dir, ["log", "-1", "--format=%B", "signed"]), /Index-Source-Commit/, "the fixture's `signed` names the trailer");
  const r = detect({ root: dir, now: NOW("2026-01-01T11:00:00Z") });
  assert.deepEqual(a7Codes(r), ["A7_NO_INDEX_SOURCE_COMMIT", "A7_SIGNED_BEHIND_REVOCATIONS"],
    "a `signed` head with no Index-Source-Commit: the catalogue half must say so and not fall back to Source-Commit, " +
      "and the list half, which reads Source-Commit, must still report the advisory ten hours unsigned");
  assert.equal(r.scanned.plugins_unsigned_commits, undefined, "the catalogue half walked from some commit with no trailer naming it");
});

test("A7: an Index-Source-Commit this checkout does not hold is a finding", () => {
  const dir = estate();
  const seed = git(dir, ["rev-parse", "HEAD"]);
  const nowhere = "c".repeat(40);
  signedAt(dir, seed, "2026-01-01T00:01:00Z", { index: nowhere });
  const r = detect({ root: dir, now: NOW("2026-01-01T01:00:00Z") });
  assert.deepEqual(a7Codes(r), ["A7_INDEX_SOURCE_COMMIT_UNKNOWN"]);
  assert.equal(r.findings.find((f) => f.code === "A7_INDEX_SOURCE_COMMIT_UNKNOWN").hex, nowhere);
});

test("A7 asks the revocations module which files the list is built from", () => {
  // The pathspec is not typed in `detectors.mjs`, and this is what notices if
  // somebody types it back. A detector carrying its own copy of another
  // module's answer is the shape `tools/lib/ids.mjs` and `tools/lib/tags.mjs`
  // both exist to end.
  assert.equal(REVOCATIONS_SOURCE_PATHSPEC, `${REVOCATIONS_SOURCE_DIR}/*.json`);
  const text = fs.readFileSync(new URL("../detectors.mjs", import.meta.url), "utf8");
  const typed = text.split("\n").filter((l) => /["'`]tools\/revocations["'`]/.test(l));
  assert.deepEqual(typed, [], "bot/detectors.mjs names tools/revocations directly again; import it from tools/lib/revocations.mjs");
});

test("A7: `signed` with no Source-Commit trailer says so rather than passing", () => {
  const dir = estate();
  git(dir, ["checkout", "--quiet", "--orphan", "signed"]);
  git(dir, ["rm", "-rq", "--cached", "."]);
  for (const e of fs.readdirSync(dir)) if (e !== ".git") fs.rmSync(path.join(dir, e), { recursive: true, force: true });
  write(dir, "registry/v1/index.json", { schema: "astra.registry.index/1" });
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "--quiet", "-m", "registry: signed"], AT("2026-01-01T01:00:00Z"));
  git(dir, ["checkout", "--quiet", "main"]);
  assert.deepEqual(codes(detect({ root: dir })), ["A7_NO_SOURCE_COMMIT"]);
});

// ── A9 ──────────────────────────────────────────────────────────────────────

test("A9: an identity record written in a commit with no matching decision", () => {
  const dir = estate();
  baseline(dir);
  write(dir, "plugins/alpha/identity.json", {
    schema: "astra.registry.identity/1", plugin_id: "alpha", repository_id: "111",
    repository_owner_id: "222", repo: "example/alpha", token_hash: "c".repeat(64),
  });
  commit(dir, "registry: a hand-edited identity", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), ["A9_IDENTITY_CHANGED_NO_DECISION"]);
});

test("A9: the same commit with a `published` record whose repo and ids match is silent", () => {
  const dir = estate();
  baseline(dir);
  write(dir, "plugins/alpha/identity.json", {
    schema: "astra.registry.identity/1", plugin_id: "alpha", repository_id: "111",
    repository_owner_id: "222", repo: "example/alpha", token_hash: "c".repeat(64),
  });
  version_(dir, "alpha", "1.1.0");
  record(dir, {
    decided_at: "2026-01-03T00:00:00Z", actor: "bot", trigger: "issue", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "published", repository_id: "111", repository_owner_id: "222",
  });
  commit(dir, "registry: publish, first bound listing", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), []);
});

test("A9: a record naming OTHER ids does not excuse the change", () => {
  const dir = estate();
  baseline(dir);
  write(dir, "plugins/alpha/identity.json", {
    schema: "astra.registry.identity/1", plugin_id: "alpha", repository_id: "999",
    repository_owner_id: "222", repo: "example/alpha", token_hash: "c".repeat(64),
  });
  version_(dir, "alpha", "1.1.0");
  record(dir, {
    decided_at: "2026-01-03T00:00:00Z", actor: "bot", trigger: "issue", plugin_id: "alpha", version: "1.1.0",
    repo: "example/alpha", tag: "v1.1.0", state: "published", repository_id: "111", repository_owner_id: "222",
  });
  commit(dir, "registry: the ids do not match", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), ["A9_IDENTITY_CHANGED_NO_DECISION"]);
});

test("A9: a `source.repo` change with no decision, and a README change without one", () => {
  const dir = estate();
  baseline(dir);
  fs.writeFileSync(path.join(dir, "plugins/alpha/README.md"), "a listing\n");
  commit(dir, "registry: presentation only", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), [], "a change that is not `source` alarmed");

  const doc = JSON.parse(fs.readFileSync(path.join(dir, "plugins/alpha/plugin.json"), "utf8"));
  doc.source.repo = "somebody-else/alpha";
  write(dir, "plugins/alpha/plugin.json", doc);
  commit(dir, "registry: the source moves", "2026-01-04T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), ["A9_IDENTITY_CHANGED_NO_DECISION"]);
});

test("A9: a hand deletion of an identity record alarms, and one beside its identity-reset record does not", () => {
  const seed = (dir) => {
    baseline(dir);
    write(dir, "plugins/alpha/identity.json", {
      schema: "astra.registry.identity/1", plugin_id: "alpha", repository_id: "111",
      repository_owner_id: "222", repo: "example/alpha", token_hash: "c".repeat(64),
    });
    version_(dir, "alpha", "1.1.0");
    record(dir, {
      decided_at: "2026-01-03T00:00:00Z", actor: "bot", trigger: "issue", plugin_id: "alpha", version: "1.1.0",
      repo: "example/alpha", tag: "v1.1.0", state: "published", repository_id: "111", repository_owner_id: "222",
    });
    commit(dir, "registry: publish, first bound listing", "2026-01-03T00:00:00Z");
  };

  const hand = estate();
  seed(hand);
  fs.rmSync(path.join(hand, "plugins/alpha/identity.json"));
  commit(hand, "registry: tidy up", "2026-01-05T00:00:00Z");
  assert.deepEqual(codes(detect({ root: hand })), ["A9_IDENTITY_CHANGED_NO_DECISION"],
    "a hand deletion of identity.json raised nothing; A9 read additions and edits only");

  const reset = estate();
  seed(reset);
  fs.rmSync(path.join(reset, "plugins/alpha/identity.json"));
  record(reset, {
    decided_at: "2026-01-05T00:00:00Z", actor: "moderator", moderator: "mod-1", trigger: "moderation",
    plugin_id: "alpha", state: "identity_reset", reasons: ["M_IDENTITY_RESET"], category: "identity_reset",
  });
  commit(reset, "moderation: identity reset for alpha", "2026-01-05T00:00:00Z");
  assert.deepEqual(codes(detect({ root: reset })), [], "the reset's own release commit alarmed");

  const other = estate();
  seed(other);
  fs.rmSync(path.join(other, "plugins/alpha/identity.json"));
  record(other, {
    decided_at: "2026-01-05T00:00:00Z", actor: "moderator", moderator: "mod-1", trigger: "moderation",
    plugin_id: "beta", state: "identity_reset", reasons: ["M_IDENTITY_RESET"], category: "identity_reset",
  });
  commit(other, "moderation: a reset for a different id", "2026-01-05T00:00:00Z");
  assert.deepEqual(codes(detect({ root: other })), ["A9_IDENTITY_CHANGED_NO_DECISION"],
    "a reset of another id excused this deletion");
});

// ── the verdict ─────────────────────────────────────────────────────────────

test("what a finding becomes in the alarm channel passes the channel's own grammar", () => {
  const dir = estate();
  baseline(dir);
  version_(dir, "alpha", "1.1.0");
  commit(dir, "registry: publish", "2026-01-03T00:00:00Z");
  const doc = verdict(detect({ root: dir }), {});
  assert.deepEqual(verdictProblems(doc), [], "the detectors' verdict is one bot/alert.mjs would refuse");
  assert.equal(doc.status, "red");
  assert.equal(doc.check, "detectors");
  assert.deepEqual(doc.ids, ["alpha"]);
  // No message text anywhere in it: a detector reads a stranger's listing, and
  // the one thing that must not cross into the owner's Telegram is a sentence
  // that listing chose.
  assert.equal(JSON.stringify(doc).includes("was published after"), false);
});

test("a green run is a green verdict, and it still names the check", () => {
  const doc = verdict(detect({ root: estate() }), {});
  assert.deepEqual(verdictProblems(doc), []);
  assert.equal(doc.status, "green");
  assert.equal(doc.check, "detectors");
});

// ── B-T3.8: the detectors over records the real writers make ────────────────
//
// Every fixture above hand-writes its records. These seed the tree with the
// writers the registry actually runs — `bot/baseline.mjs`'s composer and
// `bot/lib/decisions.mjs`' writer, under BOT-35's own keys — because a
// detector armed by the marker is only as good as its agreement with the shape
// of what the marker lets through, and the marker and those writers landed
// together.

import { composeRecords, marker as baselineMarker } from "../baseline.mjs";
import { legacyKey, migrationKey as decisionsMigrationKey, writeDecisionRecord } from "../lib/decisions.mjs";

/** The baseline commit as `bot/baseline.mjs --write` makes it: its records, its marker, one commit. */
function realBaseline(dir, versions) {
  const sourceCommit = git(dir, ["rev-parse", "HEAD"]);
  const facts = versions.map(([id, version, over = {}]) => ({
    plugin_id: id, version, repo: `example/${id}`, tag: `v${version}`, commit: "c".repeat(40),
    fingerprint: `${id.length}${version.replace(/\./g, "")}`.padEnd(16, "0").slice(0, 16),
    outcome: "verified", repository_id: "111", repository_owner_id: "222", ...over,
  }));
  const at = new Map(facts.map((f) => [`${f.plugin_id}@${f.version}`, "2026-01-01T00:00:00Z"]));
  for (const { key, record } of composeRecords(facts, at)) {
    assert.equal(key, decisionsMigrationKey(record));
    writeDecisionRecord({ key, record, root: dir });
  }
  write(dir, "log/baseline.json", baselineMarker({
    writtenAt: "2026-01-02T00:00:00Z", sourceCommit, versionCount: facts.length, recordCount: facts.length,
  }));
  return commit(dir, "baseline: MIG-20's migration records and marker", "2026-01-02T00:00:00Z");
}

/** One legacy decision, as `bot/decide.mjs`'s writer files it. */
function legacyRecord(dir, { state, version = "1.1.0", decided_at, fingerprint = "a1b2c3d4e5f60718", extra = {} }) {
  const record = {
    decided_at, actor: "bot", trigger: state === "published" ? "legacy" : "issue", plugin_id: "alpha", version,
    repo: "example/alpha", repository_id: "111", repository_owner_id: "222", tag: `v${version}`, fingerprint, state,
    ...extra,
  };
  return writeDecisionRecord({ key: legacyKey({ repo: record.repo, tag: record.tag, fingerprint, state }), record, root: dir });
}

test("B-T3.8: over a baseline the real writer made, all four detectors run and a quiet tree is quiet", () => {
  const dir = estate();
  realBaseline(dir, [["alpha", "1.0.0"]]);
  const r = detect({ root: dir });
  assert.deepEqual(skipped(r), ["A7"], "a detector the marker arms still skipped");
  assert.deepEqual(codes(r), [], JSON.stringify(r.findings));
  assert.equal(r.scanned.records, 1);
  assert.equal(r.scanned.versions_baselined, 1);
});

test("A3: a delay that drained — the `delayed` record, then the entry removed with its `published` record — is silent", () => {
  // The sequence every delayed release takes, written by the writers that
  // write it: run one records `delayed` and queues; the drain removes the
  // entry and records `published`, in one commit. A3 read every `delayed`
  // record as a live promise, so the drained one alarmed for ever — on the
  // first delayed release after the baseline, and every hour after.
  const dir = estate();
  realBaseline(dir, [["alpha", "1.0.0"]]);
  legacyRecord(dir, { state: "delayed", decided_at: "2026-01-03T00:00:00Z", extra: { publish_after: "2026-01-04T00:00:00Z" } });
  write(dir, "state/queue/alpha@1.1.0.json", { repo: "example/alpha", tag: "v1.1.0", publish_after: "2026-01-04T00:00:00Z" });
  commit(dir, "registry: publish (issues) — delayed", "2026-01-03T00:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), [], "a delay and its entry alarmed");

  fs.rmSync(path.join(dir, "state/queue/alpha@1.1.0.json"));
  version_(dir, "alpha", "1.1.0");
  legacyRecord(dir, { state: "published", decided_at: "2026-01-04T01:00:00Z" });
  commit(dir, "registry: publish (schedule) — drained", "2026-01-04T01:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), [], "a drained delay alarmed as a promise never queued");
});

test("A3: a delay superseded by a record for OTHER bytes is still a promise, and still alarms without its entry", () => {
  // The supersession is keyed on the fingerprint the delay was for: a later
  // record about a re-cut release of the same version does not settle a
  // promise made about the first bytes.
  const dir = estate();
  realBaseline(dir, [["alpha", "1.0.0"]]);
  legacyRecord(dir, { state: "delayed", decided_at: "2026-01-03T00:00:00Z", extra: { publish_after: "2026-01-04T00:00:00Z" } });
  legacyRecord(dir, { state: "held", decided_at: "2026-01-03T02:00:00Z", fingerprint: "ffffffffffffffff" });
  commit(dir, "registry: a promise with no entry, and a hold about other bytes", "2026-01-03T02:00:00Z");
  assert.deepEqual(codes(detect({ root: dir })), ["A3_DELAYED_NO_ENTRY"]);
});

test("the records a baseline counted are a floor: fewer on the tree is a finding, not a quieter detector", () => {
  // Records are never deleted (DEC-7; git never forgets), and the marker says
  // how many the baseline wrote. A walk that sees fewer has lost its input —
  // a moved directory, a broken reader — and a detector that reads nothing
  // finds nothing.
  const dir = estate();
  listing(dir, "beta", "2.0.0");
  commit(dir, "beta", "2026-01-01T01:00:00Z");
  realBaseline(dir, [["alpha", "1.0.0"], ["beta", "2.0.0"]]);
  for (const f of fs.readdirSync(path.join(dir, "log/decisions/2026/01"))) {
    const doc = JSON.parse(fs.readFileSync(path.join(dir, "log/decisions/2026/01", f), "utf8"));
    if (doc.plugin_id === "beta") fs.rmSync(path.join(dir, "log/decisions/2026/01", f));
  }
  commit(dir, "a record goes missing", "2026-01-03T00:00:00Z");
  const found = codes(detect({ root: dir }));
  assert.ok(found.includes("A1_RECORDS_BELOW_MARKER"), `found ${found.join(", ")}`);
});

// ── A11 · review marked without a decision (contract 3.0.0; §4.8 row 11) ────
//
// Three clauses, and one fixture shape each:
//
//   1. a version record whose `review` BECAME `reviewed` in a commit that adds
//      no moderation-log `review` entry naming that version, or that carries no
//      `Service-Decision:` trailer;
//   2. any other change to a committed `review`;
//   3. a version record added at or after 3.0.0's landing commit — the first
//      commit on the first-parent line whose `schema/version-v1.json` declares
//      `review` (B.4) — whose `review` is absent or not `unreviewed`.
//
// Clauses 1 and 2 are judged per commit, on what that commit changed itself:
// a merge is judged on its own resolution only, so a review made on a branch is
// read on the branch commit that made it, and a merge carrying it in is not a
// second, trailer-less change. Clause 3 is judged where `main` acquired the
// record, which for a branch merged with a merge commit is the merge.

const SDI = "0192f3a4-5b6c-7d8e-9f01-234567890abc";
const REVIEW_REASON = "A moderator read this version's manifest, permissions and bundle and found nothing wrong.";
const TRAILER = `Service-Decision: ${SDI}`;
const a11 = (r) => r.findings.filter((f) => f.detector === "A11").map((f) => f.code).sort();

/** Contract 3.0.0's landing commit: the version schema starts declaring `review`. */
function landReview(dir, when = "2026-02-01T00:00:00Z") {
  write(dir, "schema/version-v1.json", { properties: { review: { enum: ["unreviewed", "reviewed"] } } });
  return commit(dir, "registry: the version schema declares `review` (contract 3.0.0)", when);
}

/** Set, change or (with `undefined`) remove a version record's mark, on the working tree. */
function mark(dir, id, version, review) {
  const file = path.join(dir, `plugins/${id}/versions/${version}.json`);
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  if (review === undefined) delete doc.review;
  else doc.review = review;
  write(dir, `plugins/${id}/versions/${version}.json`, doc);
}

/** MOD-47's entry for a review, as `compileReview` writes it. */
function reviewEntry(dir, id, versions, { n = "", over = {} } = {}) {
  write(dir, `bot/moderation/2026-02-02-${id}-review${n}.json`, {
    date: "2026-02-02", action: "review", plugin: id, versions, reason: REVIEW_REASON,
    category: "review_passed", service_decision_id: SDI, ...over,
  });
}

/** A landed tree with alpha 1.1.0 published `unreviewed` after the landing commit. */
function reviewable() {
  const dir = estate();
  landReview(dir);
  version_(dir, "alpha", "1.1.0", { version: { review: "unreviewed" } });
  commit(dir, "registry: publish alpha 1.1.0", "2026-02-01T01:00:00Z");
  return dir;
}

test("A11: a mark set with its log entry and its Service-Decision trailer is silent", () => {
  const dir = reviewable();
  mark(dir, "alpha", "1.1.0", "reviewed");
  reviewEntry(dir, "alpha", ["1.1.0"]);
  commit(dir, `registry: moderation (1 decision(s))\n\n${TRAILER}\nDecided-At: 2026-02-02T00:00:00Z`, "2026-02-02T00:00:00Z");
  const r = detect({ root: dir });
  assert.deepEqual(a11(r), [], JSON.stringify(r.findings));
  assert.ok(r.ran.includes("A11"));
  assert.ok(r.scanned.review_commits >= 2, `A11 examined ${r.scanned.review_commits} commit(s)`);
  assert.equal(r.scanned.review_records_added, 1, "clause 3 read the one record added after the landing commit");
});

test("A11 clause 1: a mark set without the entry naming that version, or without the trailer, alarms", () => {
  const cases = [
    ["no trailer", { trailer: false }],
    ["no log entry", { entry: false }],
    ["an entry naming another version", { entry: ["1.0.0"] }],
    ["an entry naming the version of another plugin", { entryOver: { plugin: "beta" } }],
    ["an entry that is not a review", { entryOver: { action: "yank", category: "broken" } }],
    ["an entry that names no versions", { entryOver: { versions: undefined } }],
    ["a trailer that names no decision", { trailerText: "Service-Decision: forged" }],
    ["a trailer only mentioned in a sentence", { trailerText: `this commit is not a ${TRAILER}` }],
  ];
  for (const [what, { trailer = true, entry = ["1.1.0"], entryOver = {}, trailerText = TRAILER }] of cases) {
    const dir = reviewable();
    mark(dir, "alpha", "1.1.0", "reviewed");
    if (entry) reviewEntry(dir, "alpha", entry, { over: entryOver });
    const sha = commit(dir, `registry: moderation${trailer ? `\n\n${trailerText}` : ""}`, "2026-02-02T00:00:00Z");
    const r = detect({ root: dir });
    assert.deepEqual(a11(r), ["A11_REVIEWED_NO_DECISION"], `${what}: ${JSON.stringify(r.findings)}`);
    const f = r.findings.find((x) => x.code === "A11_REVIEWED_NO_DECISION");
    assert.equal(f.hex, sha, `${what}: the finding does not name the commit that set the mark`);
    assert.equal(f.plugin_id, "alpha");
  }

  // The entry has to be the commit's own: one written a commit earlier is a
  // log that claims a review no commit of its own carried.
  const dir = reviewable();
  reviewEntry(dir, "alpha", ["1.1.0"]);
  commit(dir, "registry: a log entry alone", "2026-02-02T00:00:00Z");
  mark(dir, "alpha", "1.1.0", "reviewed");
  commit(dir, `registry: the mark alone\n\n${TRAILER}`, "2026-02-02T00:01:00Z");
  assert.deepEqual(a11(detect({ root: dir })), ["A11_REVIEWED_NO_DECISION"]);

  // And ADDED, not edited: the log is append-only (MOD-47), so an older review
  // entry widened to name one more version is not a review of it.
  const edited = reviewable();
  version_(edited, "alpha", "1.2.0", { version: { review: "unreviewed" } });
  commit(edited, "registry: publish alpha 1.2.0", "2026-02-01T02:00:00Z");
  mark(edited, "alpha", "1.1.0", "reviewed");
  reviewEntry(edited, "alpha", ["1.1.0"]);
  commit(edited, `registry: moderation\n\n${TRAILER}`, "2026-02-02T00:00:00Z");
  mark(edited, "alpha", "1.2.0", "reviewed");
  reviewEntry(edited, "alpha", ["1.1.0", "1.2.0"]);
  commit(edited, `a hand edit of an old entry\n\n${TRAILER}`, "2026-02-03T00:00:00Z");
  assert.deepEqual(a11(detect({ root: edited })), ["A11_REVIEWED_NO_DECISION"], "an edited entry was read as the commit's own");
});

test("A11 clause 2: every other change to a committed review alarms, and a change beside it does not", () => {
  const changed = [
    ["reviewed back to unreviewed", "reviewed", "unreviewed"],
    ["reviewed removed", "reviewed", undefined],
    ["unreviewed removed", "unreviewed", undefined],
    ["unreviewed to a value nobody wrote", "unreviewed", "pending"],
  ];
  for (const [what, from, to] of changed) {
    const dir = reviewable();
    if (from === "reviewed") {
      mark(dir, "alpha", "1.1.0", "reviewed");
      reviewEntry(dir, "alpha", ["1.1.0"]);
      commit(dir, `registry: moderation\n\n${TRAILER}`, "2026-02-02T00:00:00Z");
    }
    mark(dir, "alpha", "1.1.0", to);
    commit(dir, "a hand edit", "2026-02-03T00:00:00Z");
    assert.deepEqual(a11(detect({ root: dir })), ["A11_REVIEW_CHANGED"], what);
  }

  // A record published before the landing commit carries no mark (B.4), and
  // back-filling one is a change to it too: it puts a warning on a legacy
  // version the coordinator's D4 leaves unmarked.
  const legacy = reviewable();
  mark(legacy, "alpha", "1.0.0", "unreviewed");
  commit(legacy, "a back-fill", "2026-02-03T00:00:00Z");
  assert.deepEqual(a11(detect({ root: legacy })), ["A11_REVIEW_CHANGED"], "a back-filled mark on a legacy record");

  // A deleted record takes its mark with it.
  const gone = reviewable();
  fs.rmSync(path.join(gone, "plugins/alpha/versions/1.1.0.json"));
  commit(gone, "a record deleted", "2026-02-03T00:00:00Z");
  assert.deepEqual(a11(detect({ root: gone })), ["A11_REVIEW_CHANGED"], "a deleted record carrying a mark");

  // A yank of a reviewed version changes the record and not the mark.
  const yanked = reviewable();
  mark(yanked, "alpha", "1.1.0", "reviewed");
  reviewEntry(yanked, "alpha", ["1.1.0"]);
  commit(yanked, `registry: moderation\n\n${TRAILER}`, "2026-02-02T00:00:00Z");
  const doc = JSON.parse(fs.readFileSync(path.join(yanked, "plugins/alpha/versions/1.1.0.json"), "utf8"));
  fs.writeFileSync(path.join(yanked, "plugins/alpha/versions/1.1.0.json"), JSON.stringify({ ...doc, yanked: true }));
  commit(yanked, "registry: yank, reformatted", "2026-02-03T00:00:00Z");
  assert.deepEqual(a11(detect({ root: yanked })), [], "a yank of a reviewed version is not a change to its mark");
});

test("A11 clause 3: a record added at or after the landing commit carries `unreviewed`, and one added before needs none", () => {
  for (const [what, extra, want] of [
    ["no mark", {}, ["A11_ADDED_NOT_UNREVIEWED"]],
    ["born reviewed", { review: "reviewed" }, ["A11_ADDED_NOT_UNREVIEWED"]],
    ["a value nobody wrote", { review: "pending" }, ["A11_ADDED_NOT_UNREVIEWED"]],
    ["unreviewed", { review: "unreviewed" }, []],
  ]) {
    const dir = estate();
    landReview(dir);
    version_(dir, "alpha", "1.1.0", { version: extra });
    const sha = commit(dir, "registry: publish", "2026-02-01T01:00:00Z");
    const r = detect({ root: dir });
    assert.deepEqual(a11(r), want, `${what}: ${JSON.stringify(r.findings)}`);
    if (want.length) assert.equal(r.findings.find((f) => f.detector === "A11").hex, sha);
  }

  // At or after: the landing commit's own additions are judged.
  const same = estate();
  write(same, "schema/version-v1.json", { properties: { review: {} } });
  version_(same, "alpha", "1.1.0");
  const landing = commit(same, "the schema and a record in one commit", "2026-02-01T00:00:00Z");
  const r = detect({ root: same });
  assert.equal(r.scanned.review_landing_commit, landing);
  assert.deepEqual(a11(r), ["A11_ADDED_NOT_UNREVIEWED"]);

  // The landing commit is the first whose schema DECLARES the member: an
  // earlier edit of the schema that does not is not it, and records added
  // after that edit and before the landing need no mark.
  const early = estate();
  write(early, "schema/version-v1.json", { properties: { yanked: {} } });
  commit(early, "a schema edit that is not 3.0.0's", "2026-01-10T00:00:00Z");
  version_(early, "alpha", "1.1.0");
  commit(early, "published before 3.0.0", "2026-01-11T00:00:00Z");
  const land = landReview(early);
  const e = detect({ root: early });
  assert.equal(e.scanned.review_landing_commit, land);
  assert.deepEqual(a11(e), [], JSON.stringify(e.findings));
});

test("A11: with no landing commit, clause 3 skips loudly and by derivation, and clauses 1 and 2 still run", () => {
  const dir = estate();
  version_(dir, "alpha", "1.1.0");
  commit(dir, "published before 3.0.0", "2026-01-02T00:00:00Z");
  const before = detect({ root: dir });
  assert.deepEqual(clauseSkips(before), ["A11.3"]);
  const skip = before.skipped.find((s) => s.detector === "A11");
  assert.match(skip.why, /landing commit/);
  assert.ok(skip.lifted_by, "a skip names what lifts it");
  assert.deepEqual(a11(before), []);
  assert.ok(before.ran.includes("A11"), "A11's first two clauses need no landing commit");

  // Clause 1 reads a hand-set mark whatever the schema says.
  mark(dir, "alpha", "1.1.0", "reviewed");
  commit(dir, "a hand-set mark, before 3.0.0", "2026-01-03T00:00:00Z");
  assert.deepEqual(a11(detect({ root: dir })), ["A11_REVIEWED_NO_DECISION"]);

  // And the skip is the landing commit's absence, not a literal.
  landReview(dir);
  const after = detect({ root: dir });
  assert.deepEqual(clauseSkips(after), [], "clause 3 still skipped with a landing commit on the tree");
  assert.ok(after.scanned.review_landing_commit, "no landing commit was read");
});

test("A11 and merges: a branch's change is judged on its commit, a merge on its own resolution, clause 3 where main acquired it", () => {
  // (a) A hand-set mark on a branch, merged with a merge commit: one finding,
  //     naming the branch commit — not the merge, which only carried it.
  const a = reviewable();
  git(a, ["checkout", "--quiet", "-b", "side"]);
  mark(a, "alpha", "1.1.0", "reviewed");
  const hand = commit(a, "a hand-set mark on a branch", "2026-02-02T00:00:00Z");
  git(a, ["checkout", "--quiet", "main"]);
  git(a, ["merge", "--quiet", "--no-ff", "-m", "Merge branch side", "side"], AT("2026-02-02T01:00:00Z"));
  const ra = detect({ root: a });
  assert.deepEqual(a11(ra), ["A11_REVIEWED_NO_DECISION"], JSON.stringify(ra.findings));
  assert.equal(ra.findings.find((f) => f.detector === "A11").hex, hand);

  // (b) A review made with its entry and trailer on a branch, merged: silent.
  //     The merge's first-parent diff shows the mark move and its message has
  //     no trailer; read that way, every review a pull request carried alarms.
  const b = reviewable();
  git(b, ["checkout", "--quiet", "-b", "side"]);
  mark(b, "alpha", "1.1.0", "reviewed");
  reviewEntry(b, "alpha", ["1.1.0"]);
  commit(b, `registry: moderation\n\n${TRAILER}`, "2026-02-02T00:00:00Z");
  git(b, ["checkout", "--quiet", "main"]);
  git(b, ["merge", "--quiet", "--no-ff", "-m", "Merge branch side", "side"], AT("2026-02-02T01:00:00Z"));
  assert.deepEqual(a11(detect({ root: b })), [], "a merge that carried a decided review was read as the review");

  // (c) A merge whose own resolution sets the mark: its own change, and it has
  //     neither the entry nor the trailer.
  const c = reviewable();
  git(c, ["checkout", "--quiet", "-b", "side"]);
  write(c, "README.md", "side\n");
  commit(c, "an unrelated branch", "2026-02-02T00:00:00Z");
  git(c, ["checkout", "--quiet", "main"]);
  git(c, ["merge", "--quiet", "--no-ff", "--no-commit", "side"]);
  mark(c, "alpha", "1.1.0", "reviewed");
  git(c, ["add", "-A"]);
  git(c, ["commit", "--quiet", "-m", "Merge branch side"], AT("2026-02-02T01:00:00Z"));
  const evil = git(c, ["rev-parse", "HEAD"]);
  const rc = detect({ root: c });
  assert.deepEqual(a11(rc), ["A11_REVIEWED_NO_DECISION"], JSON.stringify(rc.findings));
  assert.equal(rc.findings.find((f) => f.detector === "A11").hex, evil);

  // (d) Clause 3 through a merge: a branch forked before 3.0.0 adds a record
  //     with no mark, and lands after the landing commit. `main` acquired the
  //     record at the merge, after 3.0.0, so the merge is the finding.
  const d = estate();
  git(d, ["checkout", "--quiet", "-b", "old"]);
  version_(d, "alpha", "1.1.0");
  commit(d, "a record with no mark, on a branch from before 3.0.0", "2026-01-15T00:00:00Z");
  git(d, ["checkout", "--quiet", "main"]);
  landReview(d);
  git(d, ["merge", "--quiet", "--no-ff", "-m", "Merge branch old", "old"], AT("2026-02-01T01:00:00Z"));
  const merge = git(d, ["rev-parse", "HEAD"]);
  const rd = detect({ root: d });
  assert.deepEqual(a11(rd), ["A11_ADDED_NOT_UNREVIEWED"], JSON.stringify(rd.findings));
  assert.equal(rd.findings.find((f) => f.detector === "A11").hex, merge);
});

test("A11: a shallow checkout is a finding, never a green walk", () => {
  const dir = reviewable();
  const shallow = fs.mkdtempSync(path.join(os.tmpdir(), "astra-detectors-shallow-"));
  trash.push(shallow);
  execFileSync("git", ["clone", "--quiet", "--depth", "1", `file://${dir}`, shallow], { env: fixtureEnv(shallow), stdio: "ignore" });
  const r = detect({ root: shallow });
  assert.deepEqual(a11(r), ["A11_HISTORY_SHALLOW"], JSON.stringify(r.findings));
  assert.deepEqual(verdictProblems(verdict(r, {})), [], "an A11 code the alarm channel would refuse");
});

test("A11: a mark set and taken back on a branch is still read, whatever the merge nets out to", () => {
  // `--full-history`: git's default simplification follows only the first
  // parent of a merge that is TREESAME to it, so a branch that set a mark by
  // hand and then undid it before merging would be walked by nobody. Both of
  // its commits are on `main`'s history, and both changed a committed mark.
  const dir = reviewable();
  git(dir, ["checkout", "--quiet", "-b", "side"]);
  mark(dir, "alpha", "1.1.0", "reviewed");
  commit(dir, "a hand-set mark", "2026-02-02T00:00:00Z");
  mark(dir, "alpha", "1.1.0", "unreviewed");
  commit(dir, "and back", "2026-02-02T00:01:00Z");
  git(dir, ["checkout", "--quiet", "main"]);
  git(dir, ["merge", "--quiet", "--no-ff", "-m", "Merge branch side", "side"], AT("2026-02-02T01:00:00Z"));
  assert.deepEqual(a11(detect({ root: dir })), ["A11_REVIEWED_NO_DECISION", "A11_REVIEW_CHANGED"]);
});
