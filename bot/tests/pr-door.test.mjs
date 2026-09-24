// BOT-54's door, asked of real git repositories (registry plan B-T5.4).
//
// Every case is a repository built in a temp directory with a base commit and a
// pull-request branch, because the door reads two commits' trees and a merge
// base, and none of that can be faked in process without testing the fake.
//
// The cases are the plan's canary, one each, plus the four shapes a door can
// leak through that the plan does not list: a rename out of `plugins/`, the
// cutover commit itself (which the door must NOT refuse), a branch that merged
// `main` into itself after the bot changed a listing there, and histories the
// door cannot relate (which must be an error, never a pass).
//
// This suite runs from `.github/workflows/bot-checks.yml`'s `door-tests` job,
// on the pull request's own checkout. The `door` job beside it runs the BASE's
// copy of the script, so a PR editing the door is tested here and judged by
// the old door until it is merged.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { after } from "node:test";

import { fixtureEnv } from "../../tools/lib/git-env.mjs";
import { CLOSED, CUTOVER_MARKER, doorVerdict, isClosed, run } from "../../tools/pr-door.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const SCRIPT = path.join(REPO, "tools", "pr-door.mjs");
const tmps = [];
after(() => { for (const d of tmps) fs.rmSync(d, { recursive: true, force: true }); });

function fixture(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `astra-door-${name}-`));
  tmps.push(dir);
  const g = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: fixtureEnv(dir), stdio: ["ignore", "pipe", "pipe"] });
  g("init", "-q", "-b", "main");
  g("config", "user.name", "Fixture");
  g("config", "user.email", "fixture@example.invalid");
  g("config", "commit.gpgsign", "false");
  const api = {
    dir,
    git: g,
    write(rel, content = "x\n") {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, typeof content === "string" ? content : `${JSON.stringify(content, null, 2)}\n`);
      return api;
    },
    remove(rel) { fs.rmSync(path.join(dir, rel)); return api; },
    move(from, to) { fs.mkdirSync(path.dirname(path.join(dir, to)), { recursive: true }); g("mv", from, to); return api; },
    commit(message) { g("add", "-A"); g("commit", "-q", "--allow-empty", "-m", message); return api; },
    branch(b) { g("checkout", "-q", "-b", b); return api; },
    checkout(ref) { g("checkout", "-q", ref); return api; },
    head: () => g("rev-parse", "HEAD").trim(),
  };
  return api;
}

const version = (id, v, extra = {}) => ({
  schema: "astra.registry.version/1", id, version: v, release: { repo: `someone/${id}`, tag: `v${v}` }, ...extra,
});

/**
 * A registry with one listing, optionally past cutover, and a PR branch off
 * it. `pr` makes the branch's change; the result is the door's verdict.
 */
function door({ cutover = true, pr, name = "case" }) {
  const f = fixture(name);
  f.write("plugins/x/plugin.json", { id: "x" })
    .write("plugins/x/README.md", "# x\n")
    .write("plugins/x/versions/1.0.0.json", version("x", "1.0.0"))
    .write("policy/limits.json", { limit: 1 })
    .write("bot/lib/thing.mjs", "export const a = 1;\n")
    .commit("a registry");
  if (cutover) f.write(CUTOVER_MARKER, { schema: "astra.registry.cutover/1", cutover_at: "2026-09-27T00:00:00Z" }).commit("cutover");
  const base = f.head();
  f.branch("pr");
  pr(f);
  return { f, base, head: f.head(), verdict: run({ repo: f.dir, base, head: f.head() }) };
}

const refusedPaths = (v) => v.refused.map((r) => `${r.status} ${r.path}`);

// ── the plan's canary ───────────────────────────────────────────────────────

test("a PR that only sets `yanked`, with its matching bot/moderation/ entry, is refused — there is no exception", () => {
  const { verdict } = door({
    name: "yank",
    pr: (f) => f.write("plugins/x/versions/1.0.0.json", version("x", "1.0.0", { yanked: true }))
      .write("bot/moderation/2026-09-28-x-yank.json", {
        date: "2026-09-28", action: "yank", plugin: "x", versions: ["1.0.0"],
        reason: "A reason long enough to be a reason and short enough to be read by a person.",
      })
      .commit("yank x 1.0.0 by hand"),
  });
  assert.equal(verdict.ok, false, "0.11.1's exception is back: a hand yank beside its log entry passed the door");
  assert.deepEqual(refusedPaths(verdict), ["M plugins/x/versions/1.0.0.json"],
    "the version file is the one refused, and the moderation entry is not what the door is about");
});

test("a PR that only changes policy/ passes, and so does one that only changes bot/lib/", () => {
  const policy = door({ name: "policy", pr: (f) => f.write("policy/limits.json", { limit: 2 }).commit("policy") });
  assert.equal(policy.verdict.ok, true, `a policy-only PR was refused: ${refusedPaths(policy.verdict)}`);
  assert.equal(policy.verdict.armed, true, "the base carries the cutover marker, so the door must be armed");
  const lib = door({ name: "lib", pr: (f) => f.write("bot/lib/thing.mjs", "export const a = 2;\n").commit("bot code") });
  assert.equal(lib.verdict.ok, true, `a bot/lib-only PR was refused: ${refusedPaths(lib.verdict)}`);
});

test("deleting plugins/x/README.md is refused, and so is adding log/decisions/…", () => {
  const readme = door({ name: "readme", pr: (f) => f.remove("plugins/x/README.md").commit("drop a README") });
  assert.deepEqual(refusedPaths(readme.verdict), ["D plugins/x/README.md"],
    "BOT-54 is every file under plugins/**, not just the records: a README deletion passed");
  const log = door({ name: "log", pr: (f) => f.write("log/decisions/2026/09/abc.json", { decision_id: "abc" }).commit("a record by hand") });
  assert.deepEqual(refusedPaths(log.verdict), ["A log/decisions/2026/09/abc.json"],
    "a hand-written decision record passed the door, and log/** is half of what BOT-54 closes");
});

test("a pre-cutover base fails nothing, whatever the PR touches", () => {
  const { verdict } = door({
    cutover: false, name: "pre",
    pr: (f) => f.remove("plugins/x/README.md").write("log/decisions/2026/09/abc.json", {}).commit("the old door, still open"),
  });
  assert.equal(verdict.armed, false, "a base with no log/cutover.json armed the door");
  assert.equal(verdict.ok, true, "before cutover a listing IS a pull request; the door must not refuse one");
});

// ── the shapes a door leaks through ─────────────────────────────────────────

test("a rename OUT of plugins/ is a deletion under plugins/, and refused", () => {
  const { verdict } = door({ name: "rename", pr: (f) => f.move("plugins/x/README.md", "docs/x.md").commit("move it out") });
  assert.deepEqual(refusedPaths(verdict), ["D plugins/x/README.md"],
    "a move out of plugins/ passed: git's rename detection folds it into one path outside the door");
});

test("the cutover commit itself — a PR adding log/cutover.json to a pre-cutover base — is not refused", () => {
  const { verdict } = door({
    cutover: false, name: "cutover-commit",
    pr: (f) => f.write(CUTOVER_MARKER, { schema: "astra.registry.cutover/1", cutover_at: "2026-09-27T00:00:00Z" }).commit("cutover"),
  });
  assert.equal(verdict.ok, true,
    "the door armed itself from the PR's head: the commit that opens R6 would be refused by the check it arms");
});

test("a branch that merged main after the bot changed a listing there is judged on its own change only", () => {
  const f = fixture("merge");
  f.write("plugins/x/plugin.json", { id: "x" }).write("policy/limits.json", { limit: 1 })
    .write(CUTOVER_MARKER, { schema: "astra.registry.cutover/1", cutover_at: "2026-09-27T00:00:00Z" }).commit("post-cutover");
  f.branch("pr").write("policy/limits.json", { limit: 2 }).commit("a policy change");
  f.checkout("main").write("plugins/x/versions/1.0.1.json", version("x", "1.0.1")).commit("the bot publishes 1.0.1");
  const base = f.head();
  f.checkout("pr");
  f.git("merge", "-q", "--no-ff", "-m", "merge main", "main");
  const verdict = run({ repo: f.dir, base, head: f.head() });
  assert.equal(verdict.ok, true,
    `the door charged the PR with main's own bot commit: ${refusedPaths(verdict)}. A two-dot diff reads a branch ` +
    "that is merely up to date as one that edits listings");
});

test("a branch cut before the bot's latest listing commit, and never updated, is judged on its own change only", () => {
  // The merge-base's own case. main moves on after the branch point and the
  // branch does NOT merge it: a two-dot diff against the base then reads the
  // bot's newer version file as a deletion by the pull request, and refuses a
  // policy-only change for a listing edit it never made. The merged-main case
  // above cannot tell the two diffs apart; this one can.
  const f = fixture("stale-branch");
  f.write("plugins/x/plugin.json", { id: "x" }).write("policy/limits.json", { limit: 1 })
    .write(CUTOVER_MARKER, { schema: "astra.registry.cutover/1", cutover_at: "2026-09-27T00:00:00Z" }).commit("post-cutover");
  f.branch("pr").write("policy/limits.json", { limit: 2 }).commit("a policy change");
  f.checkout("main").write("plugins/x/versions/1.0.1.json", version("x", "1.0.1")).commit("the bot publishes 1.0.1");
  const base = f.head();
  f.checkout("pr");
  const verdict = run({ repo: f.dir, base, head: f.head() });
  assert.equal(verdict.ok, true,
    `the door charged a stale branch with main's newer bot commit: ${refusedPaths(verdict)}`);
});

test("histories the door cannot relate are an error, never a pass", () => {
  const f = fixture("unrelated");
  f.write(CUTOVER_MARKER, {}).commit("base");
  const base = f.head();
  f.git("checkout", "-q", "--orphan", "other");
  f.git("rm", "-rq", "--cached", ".");
  fs.rmSync(path.join(f.dir, "log"), { recursive: true, force: true });
  f.write("plugins/y/plugin.json", { id: "y" }).commit("unrelated");
  assert.throws(() => run({ repo: f.dir, base, head: f.head() }), /no common commit/,
    "a door that cannot say what a PR changed reported that it changed nothing");
});

test("it takes full SHAs and commits it holds, and nothing else", () => {
  const f = fixture("args");
  f.commit("one");
  const sha = f.head();
  assert.throws(() => run({ repo: f.dir, base: "main", head: sha }), /full commit SHA/);
  assert.throws(() => run({ repo: f.dir, base: sha, head: "0".repeat(40) }), /not a commit/);
});

test("the pure rule: the two trees, by prefix, and nothing that merely resembles them", () => {
  assert.deepEqual([...CLOSED], ["plugins/", "log/"]);
  for (const p of ["plugins/x/plugin.json", "plugins/x/README.md", "log/cutover.json", "log/decisions/2026/09/a.json"]) {
    assert.equal(isClosed(p), true, p);
  }
  for (const p of ["policy/limits.json", "bot/lib/x.mjs", "tools/plugins/x", "docs/log/x.md", "pluginsX/y", "logs/x"]) {
    assert.equal(isClosed(p), false, p);
  }
  assert.deepEqual(doorVerdict({ armed: false, changes: [{ status: "A", path: "plugins/x" }] }), { ok: true, armed: false, refused: [] });
});

// ── the command line and the workflow ───────────────────────────────────────

test("the command exits 1 on a refusal, 0 on a pass, and 2 when it cannot judge", () => {
  const refused = door({ name: "cli", pr: (f) => f.remove("plugins/x/README.md").commit("drop") });
  const cli = (base, head, dir) => spawnSync(process.execPath, [SCRIPT, "--repo", dir, "--base", base, "--head", head], {
    encoding: "utf8", env: { ...fixtureEnv(dir), GITHUB_STEP_SUMMARY: "" },
  });
  const r1 = cli(refused.base, refused.head, refused.f.dir);
  assert.equal(r1.status, 1, r1.stdout + r1.stderr);
  assert.match(r1.stdout, /::error file=plugins\/x\/README\.md::/);
  assert.match(r1.stdout, /blocks no merge/, "the residual (ROLL-5) must be on the run page, not only in this file");
  const r0 = cli(refused.base, refused.base, refused.f.dir);
  assert.equal(r0.status, 0, r0.stdout + r0.stderr);
  const r2 = cli("nope", refused.head, refused.f.dir);
  assert.equal(r2.status, 2, r2.stdout + r2.stderr);
});

const WORKFLOW = path.join(REPO, ".github", "workflows", "bot-checks.yml");

/** One job's lines, from `  <name>:` to the next two-space key. */
function job(src, name) {
  const lines = src.split("\n");
  const at = lines.findIndex((l) => l === `  ${name}:`);
  assert.ok(at >= 0, `bot-checks.yml has no job \`${name}\``);
  let end = at + 1;
  while (end < lines.length && !/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[end])) end++;
  return lines.slice(at, end).filter((l) => !/^\s*#/.test(l)).join("\n");
}

test("bot-checks.yml judges every pull request with the BASE's door, holding nothing", () => {
  const src = fs.readFileSync(WORKFLOW, "utf8");
  // No `paths:` filter on pull_request. A filter is a door-shaped hole: GitHub
  // evaluates it over at most 300 changed files, and a rename's source is not
  // what a reader expects it to match.
  const on = src.slice(src.indexOf("\non:"), src.indexOf("\npermissions:")).split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  assert.match(on, /^\s{2}pull_request:\s*$/m, "bot-checks.yml no longer runs on pull requests");
  assert.doesNotMatch(on.split("workflow_dispatch:")[0], /paths:/,
    "a paths filter on pull_request lets a PR the filter does not match skip the door entirely");
  assert.doesNotMatch(src, /pull_request_target/, "the door needs no base-repository token; pull_request_target would hand it one");

  const d = job(src, "door");
  assert.match(d, /if: github\.event_name == 'pull_request'/);
  assert.match(d, /ref: \$\{\{ github\.event\.pull_request\.base\.sha \}\}/,
    "the door checks out the PR's merge ref, so a PR can edit the script that judges it");
  assert.match(d, /persist-credentials: false/);
  assert.match(d, /BASE_SHA: \$\{\{ github\.event\.pull_request\.base\.sha \}\}/);
  assert.match(d, /HEAD_SHA: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/);
  assert.match(d, /node tools\/pr-door\.mjs --base "\$BASE_SHA" --head "\$HEAD_SHA"/);
  // The PR that introduces the door has a base without it; a base that is past
  // cutover and has lost it is a deleted door and red.
  assert.match(d, /if \[ ! -f tools\/pr-door\.mjs \]; then\n\s+if \[ -f log\/cutover\.json \]; then/);
  assert.doesNotMatch(d, /secrets\.|github\.token|continue-on-error|:\s*write\b/,
    "the door holds a secret, a token, write access or a continue-on-error");
  // Expressions only in `if:`, the checkout's `ref:` and the env block — never
  // inside a `run:` body, where a value is shell text before anything checks it.
  const interpolated = d.split("\n").filter((l) => l.includes("${{") && !/^\s+(?:if|ref|BASE_SHA|HEAD_SHA|PR_NUMBER):/.test(l));
  assert.deepEqual(interpolated, [], "an expression is interpolated outside the env block");

  const t = job(src, "door-tests");
  assert.match(t, /node --test bot\/tests\/pr-door\.test\.mjs/);
  assert.doesNotMatch(t, /secrets\.|github\.token|:\s*write\b/);
  assert.match(src, /^permissions:\n\s+contents: read\s*$/m, "the workflow's default permission is read-only");
});
