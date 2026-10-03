// Two clones and a bare remote, because that is what the failure needs.
//
// `bot/publish-apply.mjs` exists for one situation: two publications reaching
// `main` at the same time. Every property worth asserting about it is a property
// of a race, and a race cannot be asserted against a single working copy — the
// old shell fallback (`git pull --rebase --autostash && git push`) passed every
// test anybody wrote for it, because nobody wrote one with a second writer in it.
//
// So each test here builds a bare repository and two clones of it, lets one
// clone commit, and then makes the other one try. They are real pushes to a real
// remote on disk: no network, no fixtures of git's behaviour, and nothing
// mocked, because the thing under test IS git's behaviour under contention.
//
// `skipChecks` is passed throughout: these trees hold two-line JSON files and no
// catalogue, so `tools/validate.mjs` and `tools/selftest.mjs` have nothing to
// say about them. `bot/tests/workflows.test.mjs` asserts that no workflow ever
// passes that flag — an escape hatch CI can reach is not an escape hatch.
//
// Registry plan B-T0.3.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { fixtureEnv } from "../../tools/lib/git-env.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  classifyChanges,
  compareReportNames,
  idOfPath,
  newestVersionInTree,
  run,
} from "../publish-apply.mjs";
import { readTree, treeModeProblems } from "../../tools/lib/tree-modes.mjs";

const git = (cwd, ...args) =>
  execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: fixtureEnv(cwd) }).trim();

const write = (root, rel, body) => {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), body);
};

// Every estate is removed when the process exits. None ever was: each run of
// this file left eighteen of them (~10 MB) in `/tmp`, a tmpfs every session on
// the machine shares, and on 2026-09-23 1,566 of them held 883 MiB of it (ops
// `dev/couplings.md` entry 135). An `exit` handler rather than a `finally` in
// each test, because it also runs when an assertion fails or the process dies
// of an uncaught error, and it cannot be forgotten by the next test written.
// The last test in this file runs the file again and holds it to that.
const estates = [];
process.on("exit", () => {
  for (const d of estates) fs.rmSync(d, { recursive: true, force: true });
});

/** A bare remote with one commit, and two clones of it. */
function estate() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-publish-apply-"));
  estates.push(dir);
  const bare = path.join(dir, "remote.git");
  git(dir, "init", "--bare", "--initial-branch=main", bare);

  const seed = path.join(dir, "seed");
  git(dir, "clone", "--quiet", bare, seed);
  git(seed, "config", "user.email", "test@example.invalid");
  git(seed, "config", "user.name", "test");
  write(seed, "README.md", "a registry\n");
  git(seed, "add", "-A");
  git(seed, "commit", "-m", "seed");
  git(seed, "push", "origin", "HEAD:main");

  const clone = (name) => {
    const at = path.join(dir, name);
    git(dir, "clone", "--quiet", bare, at);
    git(at, "config", "user.email", `${name}@example.invalid`);
    git(at, "config", "user.name", name);
    return at;
  };
  return { dir, bare, one: clone("one"), two: clone("two") };
}

/** What `bot/decide.mjs` leaves behind, including the two files that must NOT be copied. */
function report(dir, name, { id, version, listing, queue, remove }) {
  const at = path.join(dir, "reports", name);
  fs.mkdirSync(at, { recursive: true });
  fs.writeFileSync(path.join(at, "comment.md"), "what the author reads\n");
  fs.writeFileSync(path.join(at, "decision.json"), '{"outcome":"publish"}\n');
  if (id) {
    write(at, `plugins/${id}/plugin.json`, listing ?? `{"id":"${id}"}\n`);
    if (version) write(at, `plugins/${id}/versions/${version}.json`, `{"version":"${version}"}\n`);
  }
  if (queue) write(at, `state/queue/${queue}`, "{}\n");
  if (remove) fs.writeFileSync(path.join(at, "remove.txt"), `${remove.join("\n")}\n`);
  return path.join(dir, "reports");
}

const quiet = () => {};

test("an id and its version land, and the bot's own paperwork does not", () => {
  const { dir, one, bare } = estate();
  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });

  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "committed");
  assert.equal(result.attempts, 1);

  const landed = git(bare, "ls-tree", "-r", "--name-only", "main").split("\n");
  assert.ok(landed.includes("plugins/alpha/plugin.json"), landed.join(" "));
  assert.ok(landed.includes("plugins/alpha/versions/0.1.0.json"), landed.join(" "));
  // The artifact carries `comment.md` and `decision.json` — the `comment` job
  // reads them out of the same artifact. A version of this file that copied
  // every file it found would have put both in the catalogue, and a version that
  // REFUSED every file it did not recognise would have refused every real
  // publication. Both mistakes are one line apart, so both are asserted.
  assert.ok(!landed.some((p) => p.endsWith("comment.md") || p.endsWith("decision.json")), landed.join(" "));
});

test("two ids on one base both land in one commit", () => {
  const { dir, one, bare } = estate();
  report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const reports = report(dir, "ingest-report-1", { id: "beta", version: "2.0.0" });

  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "committed");
  assert.deepEqual([...result.touchedIds].sort(), ["alpha", "beta"]);
  const landed = git(bare, "ls-tree", "-r", "--name-only", "main");
  assert.ok(landed.includes("plugins/alpha/plugin.json") && landed.includes("plugins/beta/plugin.json"));
});

test("the same id from two bases: the older release is refused and nothing of it lands", () => {
  const { dir, one, two, bare } = estate();

  // The other writer publishes a COMPLETE listing, which is what a publish run
  // actually writes: plugin.json and the version file beside it. The fixture
  // used to write plugin.json alone, which is a registry state no run produces,
  // and it mattered — with no version in the tree there is nothing for the
  // version rules to judge and the "conflict" was decided by path alone.
  write(two, "plugins/alpha/plugin.json", '{"id":"alpha","latest":"0.2.0"}\n');
  write(two, "plugins/alpha/versions/0.2.0.json", '{"version":"0.2.0"}\n');
  git(two, "add", "-A");
  git(two, "commit", "-m", "the other run published 0.2.0");
  git(two, "push", "origin", "HEAD:main");
  const theirs = git(two, "rev-parse", "HEAD");

  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });

  // Refused by the version rules on the second attempt, against the tree as it
  // then is — not by a path comparison on the first. The distinction is the
  // whole of what this file got wrong before: a path another commit touched is
  // not by itself a conflict.
  assert.equal(result.outcome, "refused");
  assert.match(result.refusals[0].message, /not newer than 0\.2\.0/);
  assert.equal(git(bare, "rev-parse", "main"), theirs);
  assert.equal(git(bare, "show", "main:plugins/alpha/plugin.json"), '{"id":"alpha","latest":"0.2.0"}');
  assert.equal(git(one, "status", "--porcelain"), "", "the working tree is left as it was found");
});

test("two runs publishing the SAME release: the loser commits nothing and says nothing false", () => {
  const { dir, one, two, bare } = estate();

  // Byte-identical to what this run is about to write — which is exactly what
  // two runs for one release look like. This used to end as `outcome: conflict`
  // with a comment telling the author somebody had changed their listing.
  write(two, "plugins/alpha/plugin.json", '{"id":"alpha"}\n');
  write(two, "plugins/alpha/versions/0.1.0.json", '{"version":"0.1.0"}\n');
  git(two, "add", "-A");
  git(two, "commit", "-m", "the other run published the same release");
  git(two, "push", "origin", "HEAD:main");
  const theirs = git(two, "rev-parse", "HEAD");

  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });

  assert.equal(result.outcome, "nothing");
  assert.deepEqual(result.refusals, []);
  assert.equal(git(bare, "rev-parse", "main"), theirs, "the winner's commit stands and no second one was made");
});

test("a different id landing in the meantime is re-applied, not refused", () => {
  const { dir, one, two, bare } = estate();

  write(two, "plugins/beta/plugin.json", '{"id":"beta"}\n');
  git(two, "add", "-A");
  git(two, "commit", "-m", "somebody else's plugin");
  git(two, "push", "origin", "HEAD:main");

  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });

  assert.equal(result.outcome, "committed");
  assert.equal(result.attempts, 2, "the first push is refused and the second, re-applied, succeeds");
  const landed = git(bare, "ls-tree", "-r", "--name-only", "main");
  assert.ok(landed.includes("plugins/alpha/plugin.json") && landed.includes("plugins/beta/plugin.json"));
});

test("0.2.0 after 0.3.0 is refused — INV-12's publish-time half", () => {
  const { dir, one } = estate();
  write(one, "plugins/alpha/versions/0.3.0.json", '{"version":"0.3.0"}\n');
  git(one, "add", "-A");
  git(one, "commit", "-m", "0.3.0 is listed");

  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.2.0" });
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "refused");
  assert.match(result.refusals[0].message, /not newer than 0\.3\.0/);
  // A queued release drains hours after it was decided. This is the whole of
  // what stops the drain from walking a listing backwards, so it must refuse
  // BEFORE anything is copied: the working tree is untouched.
  assert.equal(git(one, "status", "--porcelain"), "");
});

test("a published version re-cut with different bytes is refused; an identical one is a no-op", () => {
  const { dir, one } = estate();
  write(one, "plugins/alpha/versions/0.1.0.json", '{"version":"0.1.0"}\n');
  git(one, "add", "-A");
  git(one, "commit", "-m", "0.1.0 is listed");

  const rewritten = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  fs.writeFileSync(
    path.join(rewritten, "ingest-report-0", "plugins/alpha/versions/0.1.0.json"),
    '{"version":"0.1.0","and":"something else"}\n',
  );
  const refused = run({ root: one, reports: rewritten, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(refused.outcome, "refused");
  assert.match(refused.refusals[0].message, /already published with different bytes/);

  // The same bytes are allowed through, because re-publishing them changes
  // nothing on disk. A refusal here would make every retry of a partly-landed
  // run fail on its own previous success.
  fs.writeFileSync(
    path.join(rewritten, "ingest-report-0", "plugins/alpha/versions/0.1.0.json"),
    '{"version":"0.1.0"}\n',
  );
  const result = run({ root: one, reports: rewritten, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "committed");
});

test("only a queue entry may be deleted", () => {
  const { dir, one } = estate();
  write(one, "plugins/alpha/plugin.json", '{"id":"alpha"}\n');
  git(one, "add", "-A");
  git(one, "commit", "-m", "alpha is listed");

  const reports = report(dir, "ingest-report-0", { remove: ["plugins/alpha/plugin.json"] });
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "refused");
  assert.match(result.refusals[0].message, /refusing to delete plugins\/alpha\/plugin\.json/);
  assert.equal(git(one, "status", "--porcelain"), "");
});

test("a directory nobody designed is refused rather than ignored", () => {
  const { dir, one } = estate();
  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  fs.mkdirSync(path.join(reports, "ingest-report-0", "policy"), { recursive: true });
  fs.writeFileSync(path.join(reports, "ingest-report-0", "policy", "reserved-ids.json"), "{}\n");
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "refused");
  assert.match(result.refusals[0].message, /policy\/ is not something the publish job knows how to apply/);
});

test("a delayed release reports the queue entry that actually landed", () => {
  const { dir, one, two, bare } = estate();
  const reports = report(dir, "ingest-report-0", { queue: "alpha@0.1.0.json" });

  const landed = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(landed.outcome, "committed");
  assert.deepEqual(landed.queued, ["state/queue/alpha@0.1.0.json"]);
  assert.ok(git(bare, "ls-tree", "-r", "--name-only", "main").includes("state/queue/alpha@0.1.0.json"));

  // And when this run loses the race, the list still describes the repository
  // rather than the decision. The other run queued the same id@version with
  // different bytes; this one re-applies on top of it, its entry wins, and
  // `queued` names the file that is in the pushed commit. The version that
  // returned `outcome: conflict` here reported `queued: []` without looking at
  // the tree it had just reset onto — so the author of a release that WAS
  // queued was told, as a fact, that it was not.
  const other = estate();
  write(other.two, "state/queue/beta@2.0.0.json", '{"from":"the other run"}\n');
  git(other.two, "add", "-A");
  git(other.two, "commit", "-m", "the other run queued beta");
  git(other.two, "push", "origin", "HEAD:main");
  const clash = report(other.dir, "ingest-report-0", { queue: "beta@2.0.0.json" });
  const second = run({
    root: other.one, reports: clash, watchState: path.join(other.dir, "none"), skipChecks: true, log: quiet,
  });
  assert.equal(second.outcome, "committed");
  assert.equal(second.attempts, 2, "the first push loses and the second, re-applied, wins");
  assert.deepEqual(second.queued, ["state/queue/beta@2.0.0.json"]);
  assert.equal(
    git(other.bare, "show", "main:state/queue/beta@2.0.0.json"),
    "{}",
    "and the entry in the commit is this run's, which is the one `queued` names",
  );
});

test("a queue entry that names no plugin is refused", () => {
  const { dir, one } = estate();
  const reports = report(dir, "ingest-report-0", { queue: "evil.json" });
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "refused");
  assert.match(result.refusals[0].message, /state\/queue\/evil\.json: has no id/);
  assert.equal(git(one, "status", "--porcelain"), "");
});

test("the backstop's etag memory lands, and yields to a newer one", () => {
  const { dir, one, two, bare } = estate();
  const watchState = path.join(dir, "watch-state");
  write(watchState, "releases-seen.json", '{"etag":"ours"}\n');

  // Nobody else is writing: it lands.
  const first = run({
    root: one, reports: path.join(dir, "none"), watchState, skipChecks: true, log: quiet,
  });
  assert.equal(first.outcome, "committed");
  assert.equal(git(bare, "show", "main:state/releases-seen.json"), '{"etag":"ours"}');

  // Now somebody else writes a newer memory while this run is working. It is a
  // cache, so the newer one wins and this run drops its copy rather than
  // failing a publication over a poll optimisation.
  git(two, "pull", "--quiet", "origin", "main");
  write(two, "state/releases-seen.json", '{"etag":"theirs"}\n');
  write(two, "plugins/beta/plugin.json", '{"id":"beta"}\n');
  git(two, "add", "-A");
  git(two, "commit", "-m", "a newer poll");
  git(two, "push", "origin", "HEAD:main");

  write(watchState, "releases-seen.json", '{"etag":"stale"}\n');
  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const second = run({ root: one, reports, watchState, skipChecks: true, log: quiet });
  assert.equal(second.outcome, "committed");
  assert.equal(git(bare, "show", "main:state/releases-seen.json"), '{"etag":"theirs"}');
  assert.ok(git(bare, "ls-tree", "-r", "--name-only", "main").includes("plugins/alpha/plugin.json"));
});

test("a rejection that is not a race stops at once, carrying what git said", () => {
  const { dir, one } = estate();
  // A remote that is not there stands in for every rejection that will be the
  // same on the fifth attempt as on the first: a branch protection, a revoked
  // token, a declining hook. The old shape retried all of them and then told
  // the author another commit had changed their listing.
  git(one, "remote", "set-url", "origin", path.join(dir, "no-such-remote.git"));
  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const lines = [];
  assert.throws(
    () => run({
      root: one, reports, watchState: path.join(dir, "none"), skipChecks: true,
      log: (l) => lines.push(l),
    }),
    /will not change on a retry/,
  );
  assert.equal(
    lines.filter((l) => l.startsWith("attempt ")).length,
    1,
    `it should not have tried again: ${lines.join(" | ")}`,
  );
});

test("eleven reports apply in the order the bot decided them, not in string order", () => {
  const { dir, one, bare } = estate();
  // `ingest-report-<strategy.job-index>`, and the index reaches 19 on a busy
  // drain. A string sort gives 0, 1, 10, 11, …, 2, 3 — so the queue order that
  // `readQueue` sorted by publish_after was discarded exactly when the queue was
  // busiest. Here reports 2 and 11 are two ripe releases of ONE plugin, oldest
  // deadline first, which is the shape that made the old order fatal: applied
  // backwards, the older one is refused for being older and, before refusals
  // were isolated, took the other nine plugins in the batch down with it.
  for (let i = 0; i < 11; i++) report(dir, `ingest-report-${i}`, { id: `p${i}`, version: "1.0.0" });
  report(dir, "ingest-report-2", { id: "shared", version: "1.9.0", listing: '{"id":"shared","latest":"1.9.0"}\n' });
  const reports = report(dir, "ingest-report-11", {
    id: "shared", version: "1.10.0", listing: '{"id":"shared","latest":"1.10.0"}\n',
  });

  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "committed");
  assert.deepEqual(result.refusals, [], "nothing was refused; they arrived in the right order");

  const landed = git(bare, "ls-tree", "-r", "--name-only", "main").split("\n");
  assert.ok(landed.includes("plugins/shared/versions/1.9.0.json"), landed.join(" "));
  assert.ok(landed.includes("plugins/shared/versions/1.10.0.json"), landed.join(" "));
  // Both versions are listed and the NEWER one is what the listing points at,
  // which is only true if 1.9.0 was written first.
  assert.equal(git(bare, "show", "main:plugins/shared/plugin.json"), '{"id":"shared","latest":"1.10.0"}');
});

test("compareReportNames orders by the index, and falls back to text", () => {
  const names = ["ingest-report-0", "ingest-report-10", "ingest-report-2", "ingest-report-1"];
  assert.deepEqual(
    [...names].sort(compareReportNames),
    ["ingest-report-0", "ingest-report-1", "ingest-report-2", "ingest-report-10"],
  );
  // A name with no trailing number still has to order deterministically, and
  // two names with the same index fall back to the text rather than to
  // whichever the filesystem happened to list first.
  assert.deepEqual(["b", "a"].sort(compareReportNames), ["a", "b"]);
  assert.deepEqual(["x-1", "y-1"].sort(compareReportNames), ["x-1", "y-1"]);
});

test("one report's refusal is one release's refusal, and the rest of the run lands", () => {
  const { dir, one, bare } = estate();
  write(one, "plugins/alpha/versions/0.3.0.json", '{"version":"0.3.0"}\n');
  git(one, "add", "-A");
  git(one, "commit", "-m", "alpha 0.3.0 is listed");
  git(one, "push", "origin", "HEAD:main");

  report(dir, "ingest-report-0", { id: "alpha", version: "0.2.0" });   // refused: older
  report(dir, "ingest-report-1", { id: "beta", version: "1.0.0" });    // fine
  const reports = report(dir, "ingest-report-2", { id: "gamma", version: "1.0.0" }); // fine

  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });

  // This is the finding that mattered most: it used to abort the whole process,
  // so beta and gamma lost their publication because alpha's was stale — and
  // because the run never committed, the queue entries that caused it were
  // never removed, so the next drain re-dispatched the identical set and
  // refused again, hourly, for ever.
  assert.equal(result.outcome, "committed");
  assert.equal(result.refusals.length, 1);
  assert.match(result.refusals[0].message, /not newer than 0\.3\.0/);
  assert.equal(result.refusals[0].report, "ingest-report-0");
  const landed = git(bare, "ls-tree", "-r", "--name-only", "main");
  assert.ok(landed.includes("plugins/beta/plugin.json"), landed);
  assert.ok(landed.includes("plugins/gamma/plugin.json"), landed);
  assert.ok(!landed.includes("plugins/alpha/versions/0.2.0.json"), landed);
});

test("a failed registry check is a refusal of the listing, and leaves the tree as it was", () => {
  const { dir, one } = estate();
  // A TRACKED file the report will overwrite, and an untracked one it will
  // create. Both halves are needed to give the cleanup teeth: `git clean`
  // removes what was created and only `git reset --hard` restores what was
  // overwritten, so a test that creates files alone passes with half the
  // cleanup deleted — which is exactly what the first version of this test did.
  write(one, "plugins/alpha/plugin.json", '{"id":"alpha","from":"the tree"}\n');
  git(one, "add", "-A");
  git(one, "commit", "-m", "alpha is listed");
  const reports = report(dir, "ingest-report-0", {
    id: "alpha", version: "0.1.0", listing: '{"id":"alpha","from":"the report"}\n',
  });
  // `skipChecks: false` against a toy repository: `registryChecks` shells
  // `node tools/validate.mjs` with this tree as cwd and there is no such file,
  // which stands in for the real thing — a derived listing that this
  // repository's own validator refuses. What is being asserted is the SHAPE of
  // the failure, not the validator: it arrives as ChecksFailed rather than as
  // an anonymous Error, so the CLI can exit 1 "refused" instead of 2 "the bot
  // broke" while writing `outcome=refused` — three answers to one question,
  // which is what it did before.
  let err;
  try {
    run({ root: one, reports, watchState: path.join(dir, "none"), log: quiet });
  } catch (e) {
    err = e;
  }
  assert.ok(err, "a failing check must not be swallowed");
  assert.equal(err.name, "ChecksFailed");
  assert.equal(
    git(one, "status", "--porcelain"),
    "",
    "the created files are gone: this is the only path that could leave the tree dirty",
  );
  assert.equal(
    fs.readFileSync(path.join(one, "plugins/alpha/plugin.json"), "utf8"),
    '{"id":"alpha","from":"the tree"}\n',
    "and the overwritten file is the tree's again, not the report's",
  );
});

test("classifyChanges reads a path for what it is", () => {
  const touchedIds = new Set(["alpha"]);
  const of = (paths, removals = []) => classifyChanges(paths, { touchedIds, removals });

  assert.deepEqual(of(["plugins/alpha/plugin.json"]).conflicts, ["plugins/alpha/plugin.json"]);
  assert.deepEqual(of(["state/queue/alpha@0.1.0.json"]).conflicts, ["state/queue/alpha@0.1.0.json"]);
  assert.deepEqual(of(["plugins/beta/plugin.json"]).conflicts, []);
  assert.deepEqual(of(["docs/POLICY.md"]).conflicts, []);
  assert.equal(of(["state/releases-seen.json"]).seenChanged, true);
  assert.equal(of(["plugins/beta/plugin.json"]).seenChanged, false);
  // A path this run is deleting is a conflict whoever else touched it: the
  // deletion was decided against a tree that no longer exists.
  assert.deepEqual(
    of(["state/queue/beta@1.0.0.json"], ["state/queue/beta@1.0.0.json"]).conflicts,
    ["state/queue/beta@1.0.0.json"],
  );
});

test("idOfPath and newestVersionInTree", () => {
  assert.equal(idOfPath("plugins/dice-roller/versions/1.0.0.json"), "dice-roller");
  assert.equal(idOfPath("state/queue/dice-roller@1.0.0.json"), "dice-roller");
  assert.equal(idOfPath("docs/POLICY.md"), null);
  // The id is what precedes the FIRST `@`, because an id cannot contain one —
  // so a second `@` leaves the id readable and makes the version half
  // nonsense, which `tools/validate.mjs` is the one to say so about. Written
  // down because the first version of this test asserted null here, on the
  // assumption that an unparseable *version* makes the *id* unknowable. It does
  // not, and the conservative reading is the one that matters: this name still
  // conflicts with a run touching `a`.
  assert.equal(idOfPath("state/queue/a@b@c.json"), "a");
  // A queue entry with no `@` at all has no id, and applyReport refuses it
  // rather than guessing — see the test below.
  assert.equal(idOfPath("state/queue/evil.json"), null);

  const { one } = estate();
  assert.equal(newestVersionInTree(one, "alpha"), null);
  write(one, "plugins/alpha/versions/0.9.0.json", "{}\n");
  write(one, "plugins/alpha/versions/0.10.0.json", "{}\n");
  // Sorted as semver, not as text: 0.10.0 is newer than 0.9.0, and a string
  // sort says the opposite.
  assert.equal(newestVersionInTree(one, "alpha"), "0.10.0");
});

// ── B-T3.7 and BOT-34: the decision log rides in the publication's commit ───
//
// `log/decisions/<YYYY>/<MM>/<decision_id>.json` is the one path under `log/`
// a publish job may write, and once MIG-20's marker is on the tree a version
// or queue ADDITION without its record is refused (contract BOT-34's Check:
// "CI fails a `versions/` or `state/queue/` addition without its record").

const RECORD_ID = "0123456789abcdef0123456789abcdef";
const recordDoc = (over = {}) => ({
  schema: "astra.registry.decision/1",
  decision_id: RECORD_ID,
  decided_at: "2026-09-24T01:02:03Z",
  actor: "bot",
  trigger: "legacy",
  plugin_id: "alpha",
  version: "0.1.0",
  repo: "example/alpha",
  tag: "v0.1.0",
  fingerprint: "0123456789abcdef",
  state: "published",
  ...over,
});
const recordRel = (doc) => `log/decisions/${doc.decided_at.slice(0, 4)}/${doc.decided_at.slice(5, 7)}/${doc.decision_id}.json`;
const withRecord = (reports, name, doc) => {
  write(path.join(reports, name), recordRel(doc), `${JSON.stringify(doc)}\n`);
  return reports;
};
const withMarker = (clone) => {
  write(clone, "log/baseline.json", '{"schema":"astra.registry.baseline/1"}\n');
  git(clone, "add", "-A");
  git(clone, "commit", "-m", "MIG-20's marker");
};

test("a decision record lands in the same commit as the publication it records", () => {
  const { dir, one, bare } = estate();
  const reports = withRecord(report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" }), "ingest-report-0", recordDoc());
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(result.outcome, "committed", JSON.stringify(result.refusals));
  const files = git(bare, "show", "--name-only", "--format=", "main").split("\n");
  assert.ok(files.includes(recordRel(recordDoc())), `the record is not in the publication's commit: ${files.join(" ")}`);
  assert.ok(files.includes("plugins/alpha/versions/0.1.0.json"));
});

test("under log/, a decision record and nothing else, and only one that is what its path says", () => {
  const cases = [
    ["the marker", (at) => write(at, "log/baseline.json", "{}\n"), /log\/baseline\.json is not a listing file, a queue entry or a decision record/],
    ["a rollout marker", (at) => write(at, "log/rollout/R3-exit.json", "{}\n"), /log\/rollout\/R3-exit\.json is not/],
    ["a name that is not an id", (at) => write(at, "log/decisions/2026/09/not-an-id.json", "{}\n"), /is not/],
    ["month thirteen", (at) => write(at, `log/decisions/2026/13/${RECORD_ID}.json`, "{}\n"), /is not/],
    ["a record naming another id", (at) => write(at, recordRel(recordDoc()), `${JSON.stringify(recordDoc({ decision_id: "f".repeat(32) }))}\n`), /names decision_id f{32}/],
    ["a record filed under another month", (at) => write(at, `log/decisions/2026/08/${RECORD_ID}.json`, `${JSON.stringify(recordDoc())}\n`), /decided_at 2026-09-24T01:02:03Z files it under log\/decisions\/2026\/09/],
    ["a record that is not a decision", (at) => write(at, recordRel(recordDoc()), `${JSON.stringify(recordDoc({ schema: "astra.registry.queue/1" }))}\n`), /is not an astra\.registry\.decision\/1 record/],
    ["a record that is not JSON", (at) => write(at, recordRel(recordDoc()), "{nope\n"), /is not JSON/],
  ];
  for (const [what, plant, expected] of cases) {
    const { dir, one } = estate();
    const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
    plant(path.join(reports, "ingest-report-0"));
    const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
    assert.equal(result.outcome, "refused", `${what} was applied`);
    assert.match(result.refusals[0].message, expected, what);
    assert.equal(git(one, "status", "--porcelain"), "", `${what}: the refusal left the tree dirty`);
  }
});

test("a decision record already on main is never rewritten; the same bytes are a no-op", () => {
  const { dir, one, bare } = estate();
  write(one, recordRel(recordDoc()), `${JSON.stringify(recordDoc())}\n`);
  git(one, "add", "-A");
  git(one, "commit", "-m", "the record");
  git(one, "push", "origin", "HEAD:main");
  const changed = withRecord(report(dir, "ingest-report-0", {}), "ingest-report-0", recordDoc({ state: "held" }));
  const refused = run({ root: one, reports: changed, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(refused.outcome, "refused");
  assert.match(refused.refusals[0].message, /already on main with different bytes/);
  fs.rmSync(path.join(dir, "reports"), { recursive: true, force: true });
  const same = withRecord(report(dir, "ingest-report-0", {}), "ingest-report-0", recordDoc());
  const noop = run({ root: one, reports: same, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(noop.outcome, "nothing", JSON.stringify(noop));
  assert.equal(git(bare, "rev-list", "--count", "main"), "2");
});

test("once the marker is on main, a version or queue addition with no record is refused (BOT-34)", () => {
  // Before the marker nothing writes records (B-T3.7's gate), so the rule
  // cannot apply; the first test in this file is that case, and it lands.
  const bare1 = estate();
  withMarker(bare1.one);
  const noRecord = report(bare1.dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const refused = run({ root: bare1.one, reports: noRecord, watchState: path.join(bare1.dir, "none"), skipChecks: true, log: quiet });
  assert.equal(refused.outcome, "refused", "a publication with no decision record landed after the baseline");
  assert.match(refused.refusals[0].message, /plugins\/alpha\/versions\/0\.1\.0\.json is added with no `published` decision record for alpha 0\.1\.0/);

  const wrongRecord = estate();
  withMarker(wrongRecord.one);
  const other = withRecord(report(wrongRecord.dir, "ingest-report-0", { id: "alpha", version: "0.1.0" }), "ingest-report-0", recordDoc({ version: "0.0.9" }));
  const r2 = run({ root: wrongRecord.one, reports: other, watchState: path.join(wrongRecord.dir, "none"), skipChecks: true, log: quiet });
  assert.equal(r2.outcome, "refused", "a record for ANOTHER version excused this one");

  const queued = estate();
  withMarker(queued.one);
  const q = report(queued.dir, "ingest-report-0", { queue: "alpha@0.1.0.json" });
  const r3 = run({ root: queued.one, reports: q, watchState: path.join(queued.dir, "none"), skipChecks: true, log: quiet });
  assert.equal(r3.outcome, "refused", "a queue entry with no `delayed` record landed after the baseline");
  assert.match(r3.refusals[0].message, /state\/queue\/alpha@0\.1\.0\.json is added with no `delayed` decision record/);

  const good = estate();
  withMarker(good.one);
  const ok = withRecord(report(good.dir, "ingest-report-0", { id: "alpha", version: "0.1.0" }), "ingest-report-0", recordDoc());
  const r4 = run({ root: good.one, reports: ok, watchState: path.join(good.dir, "none"), skipChecks: true, log: quiet });
  assert.equal(r4.outcome, "committed", JSON.stringify(r4.refusals));
});


// ── the service path's two record kinds (B-T3.4) ────────────────────────────

const FP16 = "0123456789abcdef";
const alertDoc = (over = {}) => ({ schema: "astra.registry.alert/1", fingerprint: FP16, event: "approval", approval_decided_at: "2026-09-24T00:00:00Z", delivered_at: "2026-09-24T00:00:05Z", run: "1/1", ...over });
const identityDoc = (over = {}) => ({ schema: "astra.registry.identity/1", plugin_id: "alpha", repository_id: "12", repository_owner_id: "34", repo: "you/alpha", token_hash: FP16, ...over });

test("an alert record and an identity record land only through the service path", () => {
  for (const [what, plant] of [
    ["an alert record", (at) => write(at, `state/alerts/${FP16}.json`, `${JSON.stringify(alertDoc())}\n`)],
    ["an identity record", (at) => write(at, "plugins/alpha/identity.json", `${JSON.stringify(identityDoc())}\n`)],
  ]) {
    const legacy = estate();
    const reports = withRecord(report(legacy.dir, "ingest-report-0", { id: "alpha", version: "0.1.0" }), "ingest-report-0", recordDoc());
    plant(path.join(reports, "ingest-report-0"));
    const refused = run({ root: legacy.one, reports, watchState: path.join(legacy.dir, "none"), skipChecks: true, log: quiet });
    assert.equal(refused.outcome, "refused", `the legacy path applied ${what}`);
    assert.match(refused.refusals[0].message, /service-path record/);

    const svc = estate();
    const r2 = withRecord(report(svc.dir, "ingest-report-0", { id: "alpha", version: "0.1.0" }), "ingest-report-0", recordDoc());
    plant(path.join(r2, "ingest-report-0"));
    const ok = run({ root: svc.one, reports: r2, watchState: path.join(svc.dir, "none"), skipChecks: true, servicePath: true, log: quiet });
    assert.equal(ok.outcome, "committed", `${what}: ${JSON.stringify(ok.refusals)}`);
  }
});

test("an identity record needs a publication beside it, and each record is what its name says", () => {
  const lone = estate();
  const reports = report(lone.dir, "ingest-report-0", {});
  write(path.join(reports, "ingest-report-0"), "plugins/alpha/identity.json", `${JSON.stringify(identityDoc())}\n`);
  const r = run({ root: lone.one, reports, watchState: path.join(lone.dir, "none"), skipChecks: true, servicePath: true, log: quiet });
  assert.equal(r.outcome, "refused", "an identity record landed in a commit that publishes nothing (ID-40)");
  assert.match(r.refusals[0].message, /ID-40/);
  for (const [what, rel, doc, expected] of [
    ["an alert named for another fingerprint", `state/alerts/${"f".repeat(16)}.json`, alertDoc(), /name is its fingerprint/],
    ["an identity record with a seventh member", "plugins/alpha/identity.json", identityDoc({ note: "x" }), /exactly B\.4's six members/],
    ["an identity record for another id", "plugins/alpha/identity.json", identityDoc({ plugin_id: "beta" }), /names plugin_id beta/],
  ]) {
    const e = estate();
    const rep = withRecord(report(e.dir, "ingest-report-0", { id: "alpha", version: "0.1.0" }), "ingest-report-0", recordDoc());
    write(path.join(rep, "ingest-report-0"), rel, `${JSON.stringify(doc)}\n`);
    const out = run({ root: e.one, reports: rep, watchState: path.join(e.dir, "none"), skipChecks: true, servicePath: true, log: quiet });
    assert.equal(out.outcome, "refused", what);
    assert.match(out.refusals[0].message, expected, what);
  }
});

// ── contract 3.0.0's landing commit, under contention (B.4's review mark) ───
//
// B.4: every version record added on main from 3.0.0's landing commit — the
// first first-parent commit whose schema/version-v1.json declares `review` —
// carries `review: "unreviewed"`. A publication run that checked out main
// BEFORE that commit derived its record with code that knows no mark. If the
// landing commit reaches main while the run is between its checkout and its
// push, the run's push is refused (non-fast-forward), and `run()` fetches,
// resets to the new main and re-applies. The question is what stops the
// re-applied, unmarked record from landing after the landing commit.
//
// The answer this asserts: the re-applied attempt runs `registryChecks` from
// the tree it was RESET to, so it runs the landing commit's validator, not the
// one the run started with — and that validator refuses an added record with
// no mark. So the run ends ChecksFailed and nothing of it lands; its next run
// derives the record with the mark. No rebase, no retry from the stale tree.
//
// Real commits, a real bare remote and the real rule: the toy tree's
// `tools/validate.mjs` is a stub before the landing commit (exit 0, as a
// validator that knows no mark) and, from the landing commit, a shim that runs
// tools/lib/review-mark.mjs — the module `tools/validate.mjs` runs — over the
// checkout. The generator and the selftest are stubs throughout; this tree
// has no catalogue for them to judge.
//
// Watched: with the shim's rule call removed (the landing commit's validator
// knowing no mark), the unmarked record lands on the second attempt and the
// first assertion fails; the control shows a marked record from the same
// race lands, so the refusal is about the mark and not about the race.
const REVIEW_MARK_LIB = new URL("../../tools/lib/review-mark.mjs", import.meta.url).href;

function landingRace(dir, one, two, { mark }) {
  const stub = "process.exit(0);\n";
  write(two, "tools/build-index.mjs", stub);
  write(two, "tools/selftest.mjs", stub);
  write(two, "tools/validate.mjs", stub);
  write(two, "schema/version-v1.json", `${JSON.stringify({ properties: { version: {} } }, null, 2)}\n`);
  git(two, "add", "-A");
  git(two, "commit", "-m", "a registry before 3.0.0 lands");
  git(two, "push", "origin", "HEAD:main");
  // The publication run checks out main here, before the landing commit.
  git(one, "pull", "--quiet", "--ff-only", "origin", "main");
  const base = git(one, "rev-parse", "HEAD");

  // 3.0.0's landing commit reaches main while that run is working.
  write(two, "schema/version-v1.json", `${JSON.stringify({ properties: { version: {}, review: {} } }, null, 2)}\n`);
  write(two, "tools/validate.mjs",
    `import { reviewMarkFindings } from ${JSON.stringify(REVIEW_MARK_LIB)};\n` +
    "const { errors } = reviewMarkFindings(process.cwd());\n" +
    "for (const e of errors) console.error(`ERROR ${e.file}: ${e.message}`);\n" +
    "process.exit(errors.length ? 1 : 0);\n");
  git(two, "add", "-A");
  git(two, "commit", "-m", "3.0.0's landing commit");
  git(two, "push", "origin", "HEAD:main");
  const landing = git(two, "rev-parse", "HEAD");

  const reports = report(dir, "ingest-report-0", {
    id: "alpha", version: "0.1.0",
  });
  if (mark !== undefined) {
    write(path.join(reports, "ingest-report-0"), "plugins/alpha/versions/0.1.0.json",
      `${JSON.stringify({ version: "0.1.0", review: mark })}\n`);
  }
  return { base, landing, reports };
}

test("a run that checked out main before 3.0.0's landing commit cannot land an unmarked record after it (B.4)", () => {
  const { dir, one, two, bare } = estate();
  const { base, landing, reports } = landingRace(dir, one, two, { mark: undefined });

  let err = null;
  let result = null;
  try {
    result = run({ root: one, reports, watchState: path.join(dir, "none"), base, log: quiet });
  } catch (e) {
    err = e;
  }
  assert.ok(err && err.name === "ChecksFailed",
    `the re-applied, unmarked record was not refused by the landing commit's validator: ${err ? err.message : JSON.stringify(result)}`);
  assert.equal(git(bare, "rev-parse", "main"), landing, "main moved past the landing commit");
  assert.equal(git(bare, "ls-tree", "--name-only", "main", "plugins/alpha/versions/0.1.0.json"), "",
    "the unmarked record reached main after the landing commit");
});

test("control: the same race with a marked record lands on the second attempt", () => {
  const { dir, one, two, bare } = estate();
  const { base, landing, reports } = landingRace(dir, one, two, { mark: "unreviewed" });

  const result = run({ root: one, reports, watchState: path.join(dir, "none"), base, log: quiet });
  assert.equal(result.outcome, "committed");
  assert.equal(result.attempts, 2, "the first push is refused by the landing commit, and the re-applied one lands");
  assert.equal(git(bare, "rev-parse", "main^"), landing);
  assert.equal(git(bare, "show", "main:plugins/alpha/versions/0.1.0.json"), '{"version":"0.1.0","review":"unreviewed"}');
});

test("DRY_RUN commits on the runner, pushes nothing, and says `dry-run`", () => {
  const { dir, one, bare } = estate();
  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const lines = [];
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, dryRun: true, log: (l) => lines.push(l) });
  assert.equal(result.outcome, "dry-run");
  assert.equal(git(bare, "rev-list", "--count", "main"), "1", "nothing reached the remote");
  assert.ok(lines.some((l) => l.includes("would push  plugins/alpha/versions/0.1.0.json")), lines.join("\n"));
});

// ── the tree rule, on the commit this file makes (tools/lib/tree-modes.mjs) ──
//
// `git add -A plugins state log/decisions …` takes whatever stands under those
// paths, and the validator that ran before it read the commit the run started
// from. So a link left in the runner's checkout — by an earlier step, a cache
// restore, anything — is committed beside a genuine publication unless the
// commit itself is asked. `skipChecks` is passed, as everywhere in this file:
// the rule does not hide behind it.

test("a link in the checkout is swept into the bot's commit, and the tree rule refuses that commit before it is pushed", () => {
  const { dir, one, bare } = estate();
  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const base = git(one, "rev-parse", "HEAD");
  fs.mkdirSync(path.join(one, "plugins", "alpha"), { recursive: true });
  fs.symlinkSync("../../README.md", path.join(one, "plugins", "alpha", "identity.json"));

  let err = null;
  let result = null;
  try {
    result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  } catch (e) {
    err = e;
  }
  assert.ok(err && err.name === "ChecksFailed",
    `a commit carrying a link was not refused: ${err ? err.message : JSON.stringify(result)}`);
  assert.match(err.message, /plugins\/alpha\/identity\.json: a symbolic link, git mode 120000,/);
  assert.equal(git(bare, "rev-list", "--count", "main"), "1", "the commit carrying the link reached the remote");
  assert.equal(git(one, "rev-parse", "HEAD"), base, "the refused commit was left on the runner's branch");
  assert.ok(!fs.existsSync(path.join(one, "plugins")), "the attempt was not undone: plugins/ is still in the checkout");
});

// ── the tree rule, on the commit every OTHER writer makes (ops couplings 216) ──
//
// This file's own commit has been asked the rule since registry #392. Five
// writers commit and push from a workflow's shell instead: the moderation
// commit job, the operator job, baseline, keepalive and the publisher
// re-check. Each validated the commit it STARTED from, if it validated at all
// (keepalive and the re-check never did), so the commit it made met the rule
// only after the push, in Registry index and the Signer's gate — by which time
// it was `main`. So each now runs `node tools/lib/tree-modes.mjs HEAD` after
// its last `git commit` and before every `git push`, and a refusal ends the
// shell under `set -e` with nothing pushed.
//
// Each case below runs the writer's own steps, read out of its workflow, in a
// clone with a bare `origin`, over a commit that holds a link or an empty
// directory under a record root, and holds the remote to where it was. Then it
// runs the same steps with the rule's line deleted and holds the remote to
// having taken that commit: the fixture is a real bad commit, and the line is
// the only thing that stops it.
//
// **How each bad entry gets into a writer's commit.** A link: by `git add` of a
// path the writer stages, which takes a link as readily as a file. An empty
// directory: never by `git add`, which cannot stage one. It rides in a tree
// git carries over unchanged — a base that held one, checked out by a
// `reset --hard` (which primes the index's cache of trees from the commit), and
// a writer whose change is in another directory. That is the only way it
// reaches these writers, so it is the way the fixture makes it; a `checkout`
// rebuilds the cache from the index and drops it, which is why the estate
// resets rather than checks out.

const REPO = path.resolve(import.meta.dirname, "..", "..");
const WORKFLOWS = path.join(REPO, ".github", "workflows");

/** The line every writer runs, exactly: the rule, on HEAD, from the checkout. The census and the mutation both read it. */
const TREE_CHECK = /^\s*node\s+tools\/lib\/tree-modes\.mjs\s+HEAD\s*$/;

const gitInput = (cwd, input, ...args) =>
  execFileSync("git", args, { cwd, input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], env: fixtureEnv(cwd) }).trim();

/**
 * The `run: |` block of the step named `name` in `workflow`, verbatim and
 * dedented: what the runner hands bash. Throws unless the step is found
 * exactly once and has a block.
 */
function stepScript(workflow, name) {
  const lines = fs.readFileSync(path.join(WORKFLOWS, workflow), "utf8").split("\n");
  const at = lines.flatMap((l, i) => {
    const m = /^(\s*)- name:\s*(.+?)\s*$/.exec(l);
    return m && m[2].replace(/^(["'])(.*)\1$/, "$2") === name ? [i] : [];
  });
  assert.equal(at.length, 1, `${workflow} has ${at.length} step(s) named ${JSON.stringify(name)}; this reads exactly one`);
  const dash = lines[at[0]].indexOf("-");
  let run = -1;
  for (let j = at[0] + 1; j < lines.length; j++) {
    if (lines[j].trim() === "") continue;
    const n = lines[j].search(/\S/);
    if (n <= dash) break;
    if (n === dash + 2 && /^\s*run: \|\s*$/.test(lines[j])) { run = j; break; }
  }
  assert.ok(run > 0, `${workflow}'s step ${JSON.stringify(name)} has no \`run: |\` block`);
  const body = [];
  let indent = null;
  for (let j = run + 1; j < lines.length; j++) {
    const l = lines[j];
    if (l.trim() === "") { body.push(""); continue; }
    const n = l.search(/\S/);
    if (indent === null) indent = n;
    if (n < indent) break;
    body.push(l.slice(indent));
  }
  return `${body.join("\n").trimEnd()}\n`;
}

/** A commit on HEAD whose tree adds an empty directory at `rel`, made from trees because nothing else can make one. */
function withEmptyDirectory(work, rel) {
  const empty = gitInput(work, "", "mktree");
  const build = (tree, [name, ...rest]) => {
    const rows = tree ? git(work, "ls-tree", "-z", tree).split("\0").filter(Boolean) : [];
    const named = (r) => r.slice(r.indexOf("\t") + 1) === name;
    const had = rows.find(named);
    const child = rest.length === 0 ? empty : build(had ? had.split(/\s/)[2] : null, rest);
    return gitInput(work, [...rows.filter((r) => !named(r)), `040000 tree ${child}\t${name}`].map((r) => `${r}\0`).join(""),
      "mktree", "-z");
  };
  return git(work, "commit-tree", build(git(work, "rev-parse", "HEAD^{tree}"), rel.split("/")), "-p", "HEAD",
    "-m", `an empty directory at ${rel}`);
}

/**
 * A bare `origin` holding `w.base` (and, with `ghost`, an empty directory at
 * `w.ghost`), and the clone a workflow's checkout would be. The rule's module
 * is copied in beside the tree and excluded from it: the step runs it from the
 * checkout, as the runner does, and the fixture's commits stay what the case
 * says they are.
 */
function writerEstate(w, { ghost = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-writer-tree-"));
  estates.push(dir);
  const bare = path.join(dir, "remote.git");
  git(dir, "init", "--quiet", "--bare", "--initial-branch=main", bare);
  const work = path.join(dir, "work");
  git(dir, "clone", "--quiet", bare, work);
  git(work, "config", "user.email", "test@example.invalid");
  git(work, "config", "user.name", "test");
  git(work, "config", "commit.gpgsign", "false");
  write(work, "README.md", "a registry\n");
  for (const [rel, body] of Object.entries(w.base)) write(work, rel, body);
  git(work, "add", "-A");
  git(work, "commit", "--quiet", "-m", "seed");
  if (ghost) git(work, "reset", "--quiet", "--hard", withEmptyDirectory(work, w.ghost));
  git(work, "push", "--quiet", "-u", "origin", "HEAD:main");
  fs.cpSync(path.join(REPO, "tools", "lib"), path.join(work, "tools", "lib"), { recursive: true });
  fs.appendFileSync(path.join(work, ".git", "info", "exclude"), "/tools/lib/\n");
  const temp = path.join(dir, "runner-temp");
  fs.mkdirSync(temp);
  return { dir, bare, work, temp, base: git(work, "rev-parse", "HEAD") };
}

/** `w.steps`, in order, under `bash -e` as a runner starts a `run:` block; the first failure ends the job. */
function runWriter(w, e, { withoutCheck = false } = {}) {
  const output = path.join(e.dir, "github-output");
  fs.writeFileSync(output, "");
  let out = "";
  for (const name of w.steps) {
    let script = stepScript(w.workflow, name);
    if (withoutCheck) script = script.split("\n").filter((l) => !TREE_CHECK.test(l)).join("\n");
    const file = path.join(e.dir, "step.sh");
    fs.writeFileSync(file, script);
    const r = spawnSync("bash", ["-e", file], {
      cwd: e.work,
      encoding: "utf8",
      env: { ...fixtureEnv(e.work), ...(w.env?.(e) ?? {}), GITHUB_OUTPUT: output, RUNNER_TEMP: e.temp },
    });
    out += `${r.stdout}${r.stderr}`;
    if (r.status !== 0) return { status: r.status, out };
  }
  return { status: 0, out };
}

const link = (work, rel, target) => {
  fs.rmSync(path.join(work, rel), { force: true });
  fs.mkdirSync(path.dirname(path.join(work, rel)), { recursive: true });
  fs.symlinkSync(target, path.join(work, rel));
};
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

const KEEPALIVE_FILE = `${JSON.stringify({ $comment: "the keepalive", month: "2000-01", at: "2000-01-01T00:00:00+00:00", by: "hand", run: null }, null, 2)}\n`;

/**
 * The five, each with the steps that commit and push, a base, the path its
 * link case leaves a link at, the directory its empty case carries, and what
 * the job before the steps leaves on the runner.
 */
const WRITERS = {
  moderation: {
    name: "the moderation commit job",
    workflow: "plugins-moderation.yml",
    steps: ["Commit once, with a Service-Decision: trailer per decision, and push"],
    base: { "plugins/alpha/plugin.json": '{"id":"alpha"}\n', "publishers/pub.json": '{"login":"pub"}\n' },
    link: "plugins/alpha/identity.json",
    ghost: "publishers/ghost",
    prepare(e, { bad }) {
      const listed = bad ? this.link : "plugins/alpha/plugin.json";
      if (bad) link(e.work, this.link, "plugin.json");
      else write(e.work, listed, '{"id":"alpha","unlisted":true}\n');
      write(e.work, "moderation/paths.txt", `${listed}\n`);
      write(e.work, "moderation/commit-message.txt", "registry: moderation (1 decision(s))\n");
      write(e.work, "moderation/results.json", "{}\n");
    },
  },
  operator: {
    name: "the operator job",
    workflow: "operator.yml",
    steps: ["Commit once, and push"],
    base: { "plugins/alpha/plugin.json": '{"id":"alpha"}\n' },
    link: "state/holds/alpha.json",
    ghost: "plugins/ghost",
    prepare(e, { bad }) {
      if (bad) link(e.work, this.link, "../../README.md");
      else write(e.work, this.link, '{"hold":"alpha"}\n');
      write(e.work, "operator/paths.txt", `${this.link}\n`);
      write(e.work, "operator/commit-message.txt", "operator: confirm\n");
    },
  },
  baseline: {
    name: "baseline",
    workflow: "baseline.yml",
    steps: ["One commit holding every record and the marker, pushed, and read back"],
    base: { "plugins/alpha/plugin.json": '{"id":"alpha"}\n' },
    link: "log/decisions/alpha.json",
    ghost: "plugins/ghost",
    prepare(e, { bad }) {
      write(e.work, "log/baseline.json", '{"marker":true}\n');
      if (bad) link(e.work, this.link, "../baseline.json");
      else write(e.work, this.link, '{"kind":"migration"}\n');
      write(e.work, "baseline-commit.txt", "baseline: MIG-20\n");
    },
  },
  keepalive: {
    name: "keepalive",
    workflow: "keepalive.yml",
    steps: ["The month, committed, and nothing else with it", "The push, which starts no workflow run and is not meant to"],
    base: {
      "plugins/alpha/plugin.json": '{"id":"alpha"}\n',
      "state/keepalive.json": KEEPALIVE_FILE,
      "state/elsewhere.json": KEEPALIVE_FILE,
    },
    link: "state/keepalive.json",
    ghost: "plugins/ghost",
    prepare(e, { bad }) {
      if (bad) link(e.work, this.link, "elsewhere.json");
    },
    // The month step's outputs. TZ=UTC so git stamps the commit in the month
    // the clock gave, as the runner does.
    env() {
      const at = new Date().toISOString().replace(/\.\d+Z$/, "+00:00");
      return { TZ: "UTC", NEEDED: "true", AT: at, MONTH: at.slice(0, 7), RUN_URL: "https://example.invalid/run/1" };
    },
  },
  recheck: {
    name: "the publisher re-check",
    workflow: "publisher-recheck.yml",
    steps: ["Commit whatever moved"],
    base: {
      "plugins/alpha/plugin.json": '{"id":"alpha"}\n',
      "publishers/pub.json": '{"login":"pub"}\n',
      "state/publishers-without-listing.json": '{"declarations":[]}\n',
    },
    link: "publishers/pub.json",
    ghost: "plugins/ghost",
    prepare(e, { bad }) {
      if (bad) link(e.work, this.link, "../README.md");
      else write(e.work, this.link, '{"login":"pub","last_confirmed_at":"2026-10-03"}\n');
      fs.writeFileSync(path.join(e.temp, "recheck.log"), "ok    pub: confirmed\n");
    },
  },
};

/**
 * Both cases for one writer, each as written (refused) and with the rule's
 * line deleted (pushed). Both are run whatever the first one says, so a red
 * names every case that is red.
 */
function judgeWriter(w) {
  const failures = [];
  for (const ghost of [false, true]) {
    try {
      judgeCase(w, ghost);
    } catch (err) {
      failures.push(err.message);
    }
  }
  assert.equal(failures.length, 0, failures.join("\n\n"));
}

function judgeCase(w, ghost) {
  const what = ghost ? `an empty directory at ${w.ghost}` : `a link at ${w.link}`;
  const said = ghost
    ? new RegExp(`${escape(w.ghost)}: an empty directory, git mode 040000 with no file beneath it, in the tree at ([0-9a-f]{12})`)
    : new RegExp(`${escape(w.link)}: a symbolic link, git mode 120000, in the tree at ([0-9a-f]{12})`);

  const e = writerEstate(w, { ghost });
  w.prepare(e, { bad: !ghost });
  const r = runWriter(w, e);
  assert.notEqual(r.status, 0, `${w.name} pushed a commit holding ${what}:\n${r.out}`);
  assert.equal(git(e.bare, "rev-parse", "main"), e.base, `${w.name}: the commit holding ${what} reached the remote`);
  const head = git(e.work, "rev-parse", "HEAD");
  assert.notEqual(head, e.base, `${w.name} stopped before it committed, so the rule was never asked of its commit:\n${r.out}`);
  const named = said.exec(r.out);
  assert.ok(named, `${w.name} was refused, but not by the tree rule naming ${what}:\n${r.out}`);
  assert.equal(named[1], head.slice(0, 12), `the rule judged ${named[1]}, not the commit ${w.name} made`);

  const m = writerEstate(w, { ghost });
  w.prepare(m, { bad: !ghost });
  const mr = runWriter(w, m, { withoutCheck: true });
  assert.equal(mr.status, 0, `${w.name}, with the rule's line deleted, failed for another reason, so the case proves nothing:\n${mr.out}`);
  const landed = git(m.bare, "rev-parse", "main");
  assert.notEqual(landed, m.base, `${w.name}, with the rule's line deleted, pushed nothing`);
  const { rows } = readTree(m.bare, landed);
  assert.deepEqual(treeModeProblems(rows).map((p) => p.path), [ghost ? w.ghost : w.link],
    `${w.name}, with the rule's line deleted, pushed a commit that does not hold ${what} and nothing else`);
}

test("the moderation commit job's own commit, holding a link or an empty directory, is refused before the push", () => {
  judgeWriter(WRITERS.moderation);
});

test("the operator job's own commit, holding a link or an empty directory, is refused before the push", () => {
  judgeWriter(WRITERS.operator);
});

test("baseline's own commit, holding a link or an empty directory, is refused before the push", () => {
  judgeWriter(WRITERS.baseline);
});

test("keepalive's own commit, holding a link or an empty directory, is refused before the push", () => {
  judgeWriter(WRITERS.keepalive);
});

test("the publisher re-check's own commit, holding a link or an empty directory, is refused before the push", () => {
  judgeWriter(WRITERS.recheck);
});

// Keepalive retries a refused push by rebasing onto what `main` holds now, so
// the commit it pushes on the second attempt is not the one it made: it carries
// whatever `main` moved to. The rule is asked on every attempt, and this is the
// case that tells "every attempt" from "once, before the loop".
test("keepalive asks the rule again of the commit a rebase made, before the push after it", () => {
  const w = WRITERS.keepalive;
  const moveMain = (e) => {
    const other = path.join(e.dir, "other");
    git(e.dir, "clone", "--quiet", e.bare, other);
    git(other, "config", "user.email", "other@example.invalid");
    git(other, "config", "user.name", "other");
    git(other, "config", "commit.gpgsign", "false");
    link(other, "plugins/alpha/up", "../..");
    git(other, "add", "-A");
    git(other, "commit", "--quiet", "-m", "a writer that asks nothing lands a link");
    git(other, "push", "--quiet", "origin", "HEAD:main");
    return git(e.bare, "rev-parse", "main");
  };

  const e = writerEstate(w);
  const moved = moveMain(e);
  const r = runWriter(w, e);
  assert.notEqual(r.status, 0, `keepalive pushed its rebased commit over a main holding a link:\n${r.out}`);
  assert.match(r.out, /push refused on attempt 1/, `the first push was not the one refused, so the rebase never ran:\n${r.out}`);
  assert.match(r.out, /plugins\/alpha\/up: a symbolic link, git mode 120000/, r.out);
  assert.equal(git(e.bare, "rev-parse", "main"), moved, "keepalive's rebased commit reached the remote");

  const m = writerEstate(w);
  const movedToo = moveMain(m);
  const mr = runWriter(w, m, { withoutCheck: true });
  assert.equal(mr.status, 0, `with the rule's line deleted, keepalive failed for another reason:\n${mr.out}`);
  assert.match(mr.out, /pushed on attempt 2/, mr.out);
  assert.notEqual(git(m.bare, "rev-parse", "main"), movedToo);
});

// The census, so that a sixth writer cannot arrive without the line: every
// uncommented workflow line that runs `git push` has the rule on HEAD before
// it, in its job, after the last line that makes or moves a commit. It reads
// lines and not shells, so it is the floor under the cases above and not a
// substitute for them: it cannot see a loop, which the rebase case can.
test("every workflow line that pushes has the tree rule on HEAD before it, after the last line that makes a commit", () => {
  const moves = /\bgit\s+(commit|commit-tree|rebase|merge|cherry-pick|am|pull|reset|revert|update-ref|checkout|switch)\b/;
  const pushes = [];
  const problems = [];
  for (const file of fs.readdirSync(WORKFLOWS).filter((n) => /\.ya?ml$/.test(n)).sort()) {
    const lines = fs.readFileSync(path.join(WORKFLOWS, file), "utf8").split("\n");
    lines.forEach((line, i) => {
      if (/^\s*#/.test(line) || !/\bgit\s+push\b/.test(line)) return;
      pushes.push(`${file}:${i + 1}`);
      for (let k = i - 1; ; k--) {
        if (k < 0 || /^\S/.test(lines[k]) || /^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[k])) {
          problems.push(`${file}:${i + 1} pushes, and nothing in its job runs \`node tools/lib/tree-modes.mjs HEAD\` before it`);
          break;
        }
        if (/^\s*#/.test(lines[k])) continue;
        if (TREE_CHECK.test(lines[k])) break;
        const moved = moves.exec(lines[k]);
        if (moved) {
          problems.push(`${file}:${i + 1} pushes after \`git ${moved[1]}\` at line ${k + 1}, and runs no ` +
            "`node tools/lib/tree-modes.mjs HEAD` between them, so its own commit meets the tree rule only on main");
          break;
        }
      }
    });
  }
  // The floor, counted 2026-10-03: baseline, keepalive, operator,
  // plugins-moderation and publisher-recheck, one push line each.
  assert.ok(pushes.length >= 5, `found ${pushes.length} workflow line(s) that push, and there were 5 on 2026-10-03: ${pushes.join(", ")}`);
  assert.deepEqual(problems, [], "a workflow pushes a commit the tree rule has not been asked about");
});

// ── this file, from outside ──────────────────────────────────────────────────
//
// The `exit` handler above is invisible from inside the process it runs in:
// whether the estates are gone can only be seen after this process has ended.
// So this last test runs the whole file again as a child, whose TMPDIR is a
// directory made for that child alone, and looks in it once the child is gone.
//
// It does not count `astra-*` entries in the shared `/tmp`, because other
// sessions create and delete them there at the same moment and a count would
// be flaky. The private directory starts empty and nothing else on the machine
// knows its name, so "empty afterwards" is exact. `os.tmpdir()` reads TMPDIR on
// every POSIX system, and the canary below proves that the child built here
// honours it: one that did not would pass by writing where nobody looks.
//
// Whether the child's tests PASS is theirs to say, here in the parent; a
// failing one stays in, since a cleanup that ran only after every assertion
// held is exactly what this is for. What it cannot see: a directory made
// from a literal `/tmp/...` path, and a child killed by a signal (exit handlers
// do not run then, so that is reported as a kill and not as a leak).
const CHILD = "ASTRA_PUBLISH_APPLY_CHILD";

test("this file, run again as a child, leaves its temp directory empty", { skip: process.env[CHILD] === "1" }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-temp-check-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const env = { ...process.env, TMPDIR: dir, TMP: dir, TEMP: dir, [CHILD]: "1" };
  // Set by the runner in every child it starts; a nested `node --test` that
  // inherits it reports to a parent that is not listening.
  delete env.NODE_TEST_CONTEXT;
  const node = (args) => {
    const r = spawnSync(process.execPath, args, { env, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 5 * 60 * 1000 });
    assert.equal(r.error, undefined, `the child could not be run: ${r.error}`);
    assert.equal(r.signal, null, `the child was killed by ${r.signal}, so its exit handlers never ran`);
    return r;
  };
  const left = () => fs.readdirSync(dir).map((n) => n.replace(/[A-Za-z0-9]{6}$/, "*")).sort();

  node(["-e", 'require("node:fs").mkdtempSync(require("node:path").join(require("node:os").tmpdir(), "canary-"))']);
  const canary = left();
  assert.deepEqual(canary, ["canary-*"],
    `a child that made one directory under os.tmpdir() left ${JSON.stringify(canary)} where this test looks, ` +
    "so the check below would be looking in the wrong place");
  for (const n of fs.readdirSync(dir)) fs.rmSync(path.join(dir, n), { recursive: true, force: true });

  const r = node(["--test", "--test-reporter=tap", import.meta.filename]);
  // Every test this file declares ran in the child (this one as a skip), so
  // the estates it makes were made; derived, so a new test needs no edit here.
  const declared = (fs.readFileSync(import.meta.filename, "utf8").match(/^test\(/gm) ?? []).length;
  const ran = Number(/^# tests (\d+)$/m.exec(r.stdout)?.[1] ?? -1);
  assert.equal(ran, declared, `the child ran ${ran} test(s) of the ${declared} this file declares:\n${r.stdout.slice(-3000)}`);

  const after = left();
  assert.deepEqual(after, [],
    `the child left ${after.length} entr${after.length === 1 ? "y" : "ies"} in its temp directory after it exited ` +
    `(${[...new Set(after)].join(", ")}); every directory a test here makes has to go into \`estates\`, which the ` +
    "`exit` handler at the top of this file removes");
});
