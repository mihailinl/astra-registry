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

const git = (cwd, ...args) =>
  execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

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
