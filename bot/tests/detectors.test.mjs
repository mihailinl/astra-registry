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
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { A7_BOUND_MINUTES, DETECTORS, detect, verdict } from "../detectors.mjs";
import { verdictProblems } from "../lib/alert-verdict.mjs";
import {
  SOURCE_DIR as REVOCATIONS_SOURCE_DIR,
  SOURCE_PATHSPEC as REVOCATIONS_SOURCE_PATHSPEC,
} from "../../tools/lib/revocations.mjs";

const git = (cwd, args, env = {}) =>
  execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } }).trim();

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
const skipped = (r) => r.skipped.map((s) => s.detector).sort();

// ── skipping, and that it is derived ────────────────────────────────────────

test("with no marker and no `signed`, every detector skips and nothing alarms", () => {
  const dir = estate();
  const r = detect({ root: dir });
  assert.deepEqual(skipped(r), [...DETECTORS].sort(), "a detector ran with its input absent");
  assert.deepEqual(codes(r), [], "a skipped detector produced a finding");
  assert.equal(r.ran.length, 0);
});

test("the skip is derived from the marker, not written down: with one, four detectors run", () => {
  // The mutation this is for: `if (false)` in front of a skip, or a skip list
  // that is a literal. Both keep every test above green. Here the only thing
  // that changed between the two runs is that the marker exists.
  const dir = estate();
  baseline(dir);
  const r = detect({ root: dir });
  assert.deepEqual(skipped(r), ["A7"], "a detector still skipped with a baseline on the tree");
  assert.deepEqual(r.ran.sort(), ["A1", "A3", "A5", "A9"]);
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
  assert.deepEqual(codes(detect({ root: dir })), ["MIG20_NO_MIGRATION_RECORD"]);
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

function signedAt(dir, sourceCommit, when) {
  const main = git(dir, ["rev-parse", "HEAD"]);
  git(dir, ["checkout", "--quiet", "--orphan", "signed"]);
  git(dir, ["rm", "-rq", "--cached", "."]);
  for (const e of fs.readdirSync(dir)) if (e !== ".git") fs.rmSync(path.join(dir, e), { recursive: true, force: true });
  write(dir, "registry/v1/index.json", { schema: "astra.registry.index/1" });
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "--quiet", "-m", `registry: signed\n\nSource-Commit: ${sourceCommit}\n`], AT(when));
  git(dir, ["checkout", "--quiet", "main"]);
  return main;
}

test("A7: `signed` three hours behind the newest plugins commit", () => {
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  version_(dir, "alpha", "1.1.0");
  commit(dir, "registry: publish", "2026-01-01T03:30:00Z");
  signedAt(dir, source, "2026-01-01T03:31:00Z");
  const r = detect({ root: dir });
  assert.ok(codes(r).includes("A7_SIGNED_BEHIND_PLUGINS"), JSON.stringify(codes(r)));
  assert.ok(!r.skipped.some((s) => s.detector === "A7"), "A7 skipped with `signed` present");
});

test("A7: inside the two-hour bound, nothing", () => {
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  version_(dir, "alpha", "1.1.0");
  commit(dir, "registry: publish", "2026-01-01T01:30:00Z");
  signedAt(dir, source, "2026-01-01T01:31:00Z");
  assert.ok(!codes(detect({ root: dir })).includes("A7_SIGNED_BEHIND_PLUGINS"));
  assert.equal(A7_BOUND_MINUTES.plugins, 120);
});

test("A7: the revocations bound is thirty minutes, not two hours", () => {
  // Watched failing by giving both paths the same bound: this tree is 40
  // minutes behind, which is inside the plugins bound and outside this one.
  const dir = estate();
  const source = git(dir, ["rev-parse", "HEAD"]);
  write(dir, "tools/revocations/one.json", { schema: "astra.registry.revocation/1" });
  commit(dir, "registry: a revocation", "2026-01-01T00:40:00Z");
  signedAt(dir, source, "2026-01-01T00:41:00Z");
  const found = codes(detect({ root: dir }));
  assert.ok(found.includes("A7_SIGNED_BEHIND_REVOCATIONS"), JSON.stringify(found));
  assert.ok(!found.includes("A7_SIGNED_BEHIND_PLUGINS"), "the plugins bound fired at 40 minutes");
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
  const found = codes(detect({ root: dir }));
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
  const found = codes(detect({ root: dir }));
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
  const r = detect({ root: dir });
  assert.equal(r.scanned.revocations_drift_minutes, 150,
    `A7 measured ${r.scanned.revocations_drift_minutes} minutes; the advisory became reachable from main at the merge, 150 minutes after the Source-Commit`);
  const found = r.findings.find((f) => f.code === "A7_SIGNED_BEHIND_REVOCATIONS");
  assert.ok(found, `a withdrawal merged 150 minutes after \`signed\`'s Source-Commit went unreported: ${JSON.stringify(codes(r))}`);
  assert.equal(found.hex, merge, "the finding names a commit other than the merge that brought the advisory onto main");
});

test("A7: a publication merged from a long-lived branch is dated at the merge", () => {
  const { dir, merge } = mergedFromBranch("plugins/alpha/versions/1.1.0.json", { schema: "astra.registry.version/1" });
  const r = detect({ root: dir });
  assert.equal(r.scanned.plugins_drift_minutes, 150,
    `A7 measured ${r.scanned.plugins_drift_minutes} minutes; the version became reachable from main at the merge, 150 minutes after the Source-Commit`);
  const found = r.findings.find((f) => f.code === "A7_SIGNED_BEHIND_PLUGINS");
  assert.ok(found, `a publication merged 150 minutes after \`signed\`'s Source-Commit went unreported: ${JSON.stringify(codes(r))}`);
  assert.equal(found.hex, merge, "the finding names a commit other than the merge that brought the version onto main");
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
