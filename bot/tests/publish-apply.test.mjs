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
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { classifyChanges, idOfPath, newestVersionInTree, run } from "../publish-apply.mjs";

const git = (cwd, ...args) =>
  execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

const write = (root, rel, body) => {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), body);
};

/** A bare remote with one commit, and two clones of it. */
function estate() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-publish-apply-"));
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

test("the same id from two bases: the second is refused, and commits nothing", () => {
  const { dir, one, two, bare } = estate();

  // The other writer publishes alpha first.
  write(two, "plugins/alpha/plugin.json", '{"id":"alpha","from":"the other run"}\n');
  git(two, "add", "-A");
  git(two, "commit", "-m", "the other run");
  git(two, "push", "origin", "HEAD:main");
  const theirs = git(two, "rev-parse", "HEAD");

  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  const result = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });

  assert.equal(result.outcome, "conflict");
  assert.deepEqual(result.conflicts, ["plugins/alpha/plugin.json"]);
  // Nothing of this run reached the remote, and the local branch is exactly
  // theirs — no commit of ours survives to be pushed by a later step.
  assert.equal(git(bare, "rev-parse", "main"), theirs);
  assert.equal(git(one, "rev-parse", "HEAD"), theirs);
  assert.equal(
    git(bare, "show", "main:plugins/alpha/plugin.json"),
    '{"id":"alpha","from":"the other run"}',
  );
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
  assert.throws(
    () => run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet }),
    /not newer than 0\.3\.0/,
  );
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
  assert.throws(
    () => run({ root: one, reports: rewritten, watchState: path.join(dir, "none"), skipChecks: true, log: quiet }),
    /already published with different bytes/,
  );

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
  assert.throws(
    () => run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet }),
    /refusing to delete plugins\/alpha\/plugin\.json/,
  );
  assert.equal(git(one, "status", "--porcelain"), "");
});

test("a directory nobody designed is refused rather than ignored", () => {
  const { dir, one } = estate();
  const reports = report(dir, "ingest-report-0", { id: "alpha", version: "0.1.0" });
  fs.mkdirSync(path.join(reports, "ingest-report-0", "policy"), { recursive: true });
  fs.writeFileSync(path.join(reports, "ingest-report-0", "policy", "reserved-ids.json"), "{}\n");
  assert.throws(
    () => run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet }),
    /policy\/ is not something the publish job knows how to apply/,
  );
});

test("a delayed release reports the queue entry that actually landed", () => {
  const { dir, one, two, bare } = estate();
  const reports = report(dir, "ingest-report-0", { queue: "alpha@0.1.0.json" });

  const landed = run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet });
  assert.equal(landed.outcome, "committed");
  assert.deepEqual(landed.queued, ["state/queue/alpha@0.1.0.json"]);
  assert.ok(git(bare, "ls-tree", "-r", "--name-only", "main").includes("state/queue/alpha@0.1.0.json"));

  // And when the entry does NOT reach the repository, the list is empty — which
  // is the whole point of reporting it. `comment` tells the author "publishes
  // itself at 14:00" off this list rather than off the decision, because the
  // decision is what the bot wanted and the list is what happened. A run
  // cancelled or conflicted here used to leave that promise standing with no
  // file behind it and nothing retrying.
  const other = estate();
  write(other.two, "state/queue/beta@2.0.0.json", '{"from":"the other run"}\n');
  git(other.two, "add", "-A");
  git(other.two, "commit", "-m", "the other run queued beta");
  git(other.two, "push", "origin", "HEAD:main");
  const clash = report(other.dir, "ingest-report-0", { queue: "beta@2.0.0.json" });
  const refused = run({
    root: other.one, reports: clash, watchState: path.join(other.dir, "none"), skipChecks: true, log: quiet,
  });
  assert.equal(refused.outcome, "conflict");
  assert.deepEqual(refused.queued ?? [], []);
});

test("a queue entry that names no plugin is refused", () => {
  const { dir, one } = estate();
  const reports = report(dir, "ingest-report-0", { queue: "evil.json" });
  assert.throws(
    () => run({ root: one, reports, watchState: path.join(dir, "none"), skipChecks: true, log: quiet }),
    /state\/queue\/evil\.json: has no id/,
  );
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
