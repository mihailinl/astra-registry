#!/usr/bin/env node
// `bot/lib/listing-state.mjs`: MIG-1, against real git trees.
//
//   node --test bot/tests/listing-state.test.mjs
//
// Registry plan M-T5.1. MIG-1's Check asks for "fixtures either side of the
// deadline and of `log/cutover.json`, one listing with a revoked binding, and
// one with no baseline"; all four are below, with two more the rule needs and
// the Check does not name: a listing whose `identity.json` a B-T4.2 reset
// deleted (ID-25's "ever"), and a checkout too shallow to answer that question.
//
// **Every fixture is a real repository**, built and committed here, for the
// reason `bot/tests/detectors.test.mjs` gives: ID-25's "ever had an identity
// record" is a statement about HISTORY, and a fixture that stubbed `git log`
// would be a fixture of this file's idea of git. The reset case is the one that
// matters — the record is gone from the tree, and the only thing that still
// knows it existed is the log.
//
// The last section is `tools/validate.mjs` over the two schemas, because a
// schema nothing validates against is a document rather than a check.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fixtureEnv } from "../../tools/lib/git-env.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CUTOVER_FILE,
  DEADLINE_ALERT,
  DEADLINE_FILE,
  LISTING_STATES,
  historyReader,
  listingState,
  listingStateAt,
  readListingTree,
  readMarkers,
} from "../lib/listing-state.mjs";
import { runValidation } from "../../tools/validate.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";

const git = (cwd, args) =>
  execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: fixtureEnv(cwd) }).trim();

const trash = [];
process.on("exit", () => {
  for (const d of trash) fs.rmSync(d, { recursive: true, force: true });
});

function tmp(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  trash.push(d);
  return d;
}

function write(root, rel, body) {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), typeof body === "string" ? body : `${JSON.stringify(body, null, 2)}\n`);
}

function commit(root, message) {
  git(root, ["add", "-A"]);
  git(root, ["commit", "--quiet", "--allow-empty", "-m", message]);
  return git(root, ["rev-parse", "HEAD"]);
}

/** The deadline, and a cutover four days after it. Arbitrary, and used everywhere. */
const DEADLINE = "2026-12-01T00:00:00Z";
const CUTOVER = "2026-12-05T00:00:00Z";
const TOKEN_HASH = "0123456789abcdef";

/**
 * A registry: one listing, optionally bound, optionally with each marker.
 *
 * `reset: true` commits the identity record and then deletes it in a second
 * commit, which is what B-T4.2's `M_IDENTITY_RESET` does to the tree.
 */
function estate({ id = "alpha", unlisted = false, identity = null, reset = false, deadline = null, cutover = null, baseline = false } = {}) {
  const dir = tmp("astra-listing-state-");
  git(dir, ["init", "--quiet", "--initial-branch=main"]);
  git(dir, ["config", "user.email", "test@example.invalid"]);
  git(dir, ["config", "user.name", "test"]);

  write(dir, `plugins/${id}/plugin.json`, { schema: "astra.registry.plugin/1", id, ...(unlisted ? { unlisted: true } : {}) });
  if (deadline) write(dir, DEADLINE_FILE, { schema: "astra.registry.deadline/1", deadline });
  if (cutover) write(dir, CUTOVER_FILE, { schema: "astra.registry.cutover/1", cutover_at: cutover });
  if (baseline) write(dir, "log/baseline.json", { schema: "astra.registry.baseline/1", version_count: 1, record_count: 1 });
  if (identity || reset) {
    const doc = identity === true || identity === null ? {
      schema: "astra.registry.identity/1", plugin_id: id, repository_id: 1, repository_owner_id: 2,
      repo: "someone/alpha", token_hash: TOKEN_HASH,
    } : identity;
    write(dir, `plugins/${id}/identity.json`, doc);
  }
  commit(dir, "listing");
  if (reset) {
    fs.rmSync(path.join(dir, "plugins", id, "identity.json"));
    commit(dir, "M_IDENTITY_RESET: the record is deleted, and the log remembers it");
  }
  return dir;
}

const at = (root, now, overlay, id = "alpha") => listingStateAt(root, id, { now, overlay, schemaRoot: REPO_ROOT });

/** Every state this suite actually produced, for the floor at the end. */
const produced = new Set();
function state(result) {
  produced.add(result.state);
  return result.state;
}

// ── MIG-1 from git alone ────────────────────────────────────────────────────

test("before the deadline, a listing with no identity record is grandfathered", () => {
  const root = estate({ deadline: DEADLINE, cutover: null });
  const r = at(root, "2026-11-01T00:00:00Z");
  assert.equal(state(r), "grandfathered");
  assert.equal(r.alert, null, "nothing alerts before the deadline");
  assert.equal(r.bound, false);
  assert.equal(r.ever_bound, false);
});

test("a past deadline with no cutover marker alerts and freezes NOTHING (BOT-72)", () => {
  const root = estate({ deadline: DEADLINE, cutover: null });
  const r = at(root, "2026-12-02T00:00:00Z");
  assert.equal(state(r), "grandfathered",
    "a deadline that passed before cutover freezes nothing — it would strand authors while the issue channel lives");
  assert.equal(r.alert?.kind, DEADLINE_ALERT);
  assert.match(r.alert.message, /log\/cutover\.json is not on main/);
});

test("past the LATER of the deadline and cutover, it is frozen", () => {
  const root = estate({ deadline: DEADLINE, cutover: CUTOVER });
  const r = at(root, "2026-12-06T00:00:00Z");
  assert.equal(state(r), "frozen");
  assert.equal(r.alert, null, "the freeze is the outcome, not an alert");
});

test("past the deadline but not past cutover, still grandfathered", () => {
  // The marker is on `main` and its moment has not arrived: MIG-1 takes the
  // later of the two, so the state is still `grandfathered`.
  const root = estate({ deadline: DEADLINE, cutover: "2026-12-10T00:00:00Z" });
  const r = at(root, "2026-12-06T00:00:00Z");
  assert.equal(state(r), "grandfathered");
  assert.match(r.why, /takes the later of the two/);
});

test("with no deadline file, every unbound listing is grandfathered and nothing alerts", () => {
  const root = estate({ deadline: null, cutover: CUTOVER });
  const r = at(root, "2030-01-01T00:00:00Z");
  assert.equal(state(r), "grandfathered");
  assert.equal(r.alert, null);
  assert.match(r.why, /no policy\/binding-deadline\.json/);
});

test("a listing with an identity record is listed, and the deadline does not touch it", () => {
  const root = estate({ deadline: DEADLINE, cutover: CUTOVER, identity: true });
  const r = at(root, "2026-12-06T00:00:00Z");
  assert.equal(state(r), "listed", "a bound listing is never grandfathered and never frozen by a date");
  assert.equal(r.bound, true);
});

test("a listing whose identity.json a reset deleted is frozen, never grandfathered again (ID-25)", () => {
  // No deadline and no cutover marker at all: under the date rules alone this
  // listing would be `grandfathered`. It is `frozen` because the log says it
  // was bound once, which is the whole of ID-25's "ever".
  const root = estate({ reset: true, deadline: null, cutover: null });
  const r = at(root, "2026-11-01T00:00:00Z");
  assert.equal(state(r), "frozen");
  assert.equal(r.bound, false, "the record is gone from the tree");
  assert.equal(r.ever_bound, true, "and the log remembers it");
  assert.match(r.why, /git log/);

  // The mutation this case exists for, run here rather than described: a reader
  // that consulted only the current tree.
  const treeOnly = readListingTree(root, "alpha", { now: "2026-11-01T00:00:00Z" });
  assert.equal(listingState({ ...treeOnly, ever_identity: false }).state, "grandfathered",
    "if this stops being `grandfathered`, the tree-only reading is no longer the defect this test guards");
});

test("unlisted is reported beside the state, not instead of it (MIG-7, MIG-30)", () => {
  const root = estate({ unlisted: true, deadline: DEADLINE, cutover: CUTOVER });
  const r = at(root, "2026-12-06T00:00:00Z");
  assert.equal(r.unlisted, true);
  assert.equal(state(r), "frozen",
    "ID-25 refuses `B_UNBOUND` to a frozen listing whether or not the catalogue shows it");
});

test("a listing with no MIG-20 baseline has the same states as one with a baseline", () => {
  const withBaseline = at(estate({ deadline: DEADLINE, cutover: CUTOVER, baseline: true }), "2026-12-06T00:00:00Z");
  const without = at(estate({ deadline: DEADLINE, cutover: CUTOVER, baseline: false }), "2026-12-06T00:00:00Z");
  assert.equal(withBaseline.state, without.state);
  assert.equal(state(without), "frozen",
    "MIG-1: a listing with no baseline has the same states; its releases stay held under MIG-28, which is not this module's business");
});

// ── the one non-git rule: MIG-1's revoked binding ───────────────────────────

test("a `revoked` verdict for the recorded token_hash freezes a bound listing", () => {
  const root = estate({ identity: true });
  const r = at(root, "2026-11-01T00:00:00Z", { shadow: false, token_states: { [TOKEN_HASH]: "revoked" } });
  assert.equal(state(r), "frozen");
  assert.equal(r.decided_by, "git+verdict", "and it says which half decided it");
});

test("with no verdict at all, the git answer stands and nothing is guessed", () => {
  const root = estate({ identity: true });
  assert.equal(state(at(root, "2026-11-01T00:00:00Z")), "listed");
  assert.equal(at(root, "2026-11-01T00:00:00Z", { shadow: false, token_states: {} }).state, "listed",
    "an answer that carries no state for this token is not an answer that the binding is live");
});

test("in shadow the overlay is not applied (ID-71)", () => {
  const root = estate({ identity: true });
  const r = at(root, "2026-11-01T00:00:00Z", { shadow: true, token_states: { [TOKEN_HASH]: "revoked" } });
  assert.equal(state(r), "listed", "in shadow every verdict is `unknown`, so a `revoked` here is not something the service may have said");
  assert.equal(r.decided_by, "git");
});

test("an overlay that does not SAY it is not shadow is read as shadow", () => {
  // The same direction `bot/decide.mjs` takes for BOT-92: a missing `shadow`
  // member is a fact about a parser, and reading it as not-shadow is the one
  // reading that commits state on an answer nobody made.
  const root = estate({ identity: true });
  const r = at(root, "2026-11-01T00:00:00Z", { token_states: { [TOKEN_HASH]: "revoked" } });
  assert.equal(state(r), "listed");
  assert.match(r.why, /shadow/);
});

test("a verdict for another token hash decides nothing", () => {
  const root = estate({ identity: true });
  const r = at(root, "2026-11-01T00:00:00Z", { shadow: false, token_states: { ["f".repeat(16)]: "revoked" } });
  assert.equal(state(r), "listed");
});

test("a stubbed service cannot call a bound listing grandfathered", () => {
  // The overlay's only power is MIG-1's revoked-binding clause. An answer that
  // asserts a STATE — which a compromised or merely wrong service would — has
  // nowhere to land: there is no member for it, and the members there are
  // cannot produce `grandfathered` for a listing with an identity record.
  const root = estate({ identity: true, deadline: DEADLINE, cutover: CUTOVER });
  const r = at(root, "2026-12-06T00:00:00Z", {
    shadow: false, state: "grandfathered", listing_state: "grandfathered",
    token_states: { [TOKEN_HASH]: "bound" },
  });
  assert.equal(state(r), "listed");
  assert.notEqual(r.state, "grandfathered", "DEC-11: a service answer is necessary and never sufficient");
});

test("an identity record with no token_hash is a refusal, not a guess", () => {
  const root = estate({ identity: { schema: "astra.registry.identity/1", plugin_id: "alpha", repo: "someone/alpha" } });
  assert.throws(
    () => at(root, "2026-11-01T00:00:00Z", { shadow: false, token_states: { [TOKEN_HASH]: "revoked" } }),
    /token_hash/,
  );
});

// ── what this reader refuses rather than answering ──────────────────────────

test("a shallow checkout cannot answer ID-25's `ever`, and says so", () => {
  const origin = estate({ reset: true });
  const shallow = tmp("astra-listing-state-shallow-");
  git(shallow, ["clone", "--quiet", "--depth", "1", `file://${origin}`, "clone"]);
  const root = path.join(shallow, "clone");

  assert.equal(historyReader(root).shallow(), true, "the fixture is not shallow, so this test proves nothing");
  assert.throws(() => at(root, "2026-11-01T00:00:00Z"), /fetch-depth: 0/);

  // And the reason it must refuse: the shallow log has lost the record's life.
  assert.equal(historyReader(root).touching("plugins/alpha/identity.json").length, 0);
  assert.equal(historyReader(origin).touching("plugins/alpha/identity.json").length, 2);
});

test("a marker that is present and malformed is an error, never an absent one", () => {
  const cases = [
    [{ schema: "astra.registry.deadline/1", deadline: "2026-12-01T00:00:00.000Z" }, /deadline/, "fractional seconds"],
    [{ schema: "astra.registry.deadline/1", deadline: "2026-12-01T00:00:00Z", note: "hi" }, /note/, "a member B.4 does not name"],
    [{ schema: "astra.registry.deadline/2", deadline: "2026-12-01T00:00:00Z" }, /schema/, "a schema string nobody reads"],
    [{ schema: "astra.registry.deadline/1" }, /deadline/, "no deadline at all"],
    [{ schema: "astra.registry.deadline/1", deadline: "2026-02-31T00:00:00Z" }, /not a real moment/, "a date that is not a date"],
  ];
  for (const [doc, pattern, why] of cases) {
    const root = estate({});
    write(root, DEADLINE_FILE, doc);
    assert.throws(() => readMarkers(root, { schemaRoot: REPO_ROOT }), pattern, why);
  }

  const unreadable = estate({});
  write(unreadable, DEADLINE_FILE, "{not json");
  assert.throws(() => readMarkers(unreadable, { schemaRoot: REPO_ROOT }), /not readable JSON/);

  const badCutover = estate({ deadline: DEADLINE });
  write(badCutover, CUTOVER_FILE, { schema: "astra.registry.cutover/1", cutover_at: "2026-12-05" });
  assert.throws(() => readMarkers(badCutover, { schemaRoot: REPO_ROOT }), /cutover_at/);
});

test("a tree missing a member is refused, because a missing one would read as its falsy value", () => {
  const root = estate({ deadline: DEADLINE, cutover: CUTOVER });
  const tree = readListingTree(root, "alpha", { now: "2026-12-06T00:00:00Z" });
  for (const member of Object.keys(tree)) {
    const { [member]: _dropped, ...without } = tree;
    assert.throws(() => listingState(without), new RegExp(`missing "${member}"|tree's ${member}`),
      `dropping ${member} was answered rather than refused`);
  }
  assert.throws(() => listingState({ ...tree, now: "yesterday" }), /now/);
  assert.throws(() => listingState({ ...tree, ever_identity: "no" }), /ever_identity/);
});

test("a listing that is not in the tree has no state, and an unreadable identity record is not an absent one", () => {
  const root = estate({});
  assert.throws(() => at(root, "2026-11-01T00:00:00Z", undefined, "nobody"), /no listing/);
  assert.throws(() => readListingTree(root, "../etc", { now: "2026-11-01T00:00:00Z" }), /not a plugin id/);
  write(root, "plugins/alpha/identity.json", "{oh dear");
  assert.throws(() => at(root, "2026-11-01T00:00:00Z"), /could not be read/);
});

// ── the two schemas, read by tools/validate.mjs ─────────────────────────────

const marked = (report, file) => report.items.filter((i) => i.where === file);

async function validateTree(root) {
  const { report } = await runValidation({
    root, allowStaging: true, allowDirect: false, online: false, artifactsDir: null, index: false,
  });
  return report;
}

test("validate.mjs says both markers are absent, rather than silently not checking", async () => {
  const root = estate({});
  const report = await validateTree(root);
  for (const file of [DEADLINE_FILE, CUTOVER_FILE]) {
    const items = marked(report, file);
    assert.equal(items.length, 1, `${file}: ${JSON.stringify(items)}`);
    assert.equal(items[0].level, "note");
  }
});

test("validate.mjs accepts both markers when they are well formed", async () => {
  const root = estate({ deadline: DEADLINE, cutover: "2026-10-01T00:00:00Z" });
  const report = await validateTree(root);
  const items = [...marked(report, DEADLINE_FILE), ...marked(report, CUTOVER_FILE)];
  assert.deepEqual(items, [], `a valid pair was refused: ${JSON.stringify(items)}`);
});

test("validate.mjs refuses a document B.4 would not recognise", async () => {
  const root = estate({ cutover: CUTOVER });
  write(root, DEADLINE_FILE, { schema: "astra.registry.deadline/1", deadline: DEADLINE, committed_by: "the owner" });
  write(root, CUTOVER_FILE, { schema: "astra.registry.cutover/1", cutover_at: "2026-12-05T00:00:00+00:00" });

  const report = await validateTree(root);
  const deadlineErrors = marked(report, DEADLINE_FILE).filter((i) => i.level === "error");
  const cutoverErrors = marked(report, CUTOVER_FILE).filter((i) => i.level === "error");
  assert.equal(deadlineErrors.length, 1, JSON.stringify(marked(report, DEADLINE_FILE)));
  assert.match(deadlineErrors[0].message, /committed_by/);
  assert.equal(cutoverErrors.length, 1, JSON.stringify(marked(report, CUTOVER_FILE)));
  assert.match(cutoverErrors[0].message, /cutover_at does not match/);
});

test("validate.mjs round-trips each date, because the pattern admits days that do not exist", async () => {
  const root = estate({});
  write(root, DEADLINE_FILE, { schema: "astra.registry.deadline/1", deadline: "2026-02-31T00:00:00Z" });
  const report = await validateTree(root);
  const errors = marked(report, DEADLINE_FILE).filter((i) => i.level === "error");
  assert.equal(errors.length, 1);
  assert.match(errors[0].message, /not a real moment/);
});

test("validate.mjs warns when the deadline is less than 30 days after cutover (MIG-2)", async () => {
  const root = estate({ deadline: "2026-12-11T00:00:00Z", cutover: "2026-12-05T00:00:00Z" });
  const report = await validateTree(root);
  const warnings = marked(report, DEADLINE_FILE).filter((i) => i.level === "warn");
  assert.equal(warnings.length, 1, JSON.stringify(marked(report, DEADLINE_FILE)));
  assert.match(warnings[0].message, /at least 30/);

  // And the floor of the same rule: 30 days exactly passes.
  const ok = estate({ deadline: "2027-01-04T00:00:00Z", cutover: "2026-12-05T00:00:00Z" });
  assert.deepEqual((await validateTree(ok)).items.filter((i) => i.where === DEADLINE_FILE), []);
});

// ── the floor ───────────────────────────────────────────────────────────────

test("every state MIG-1 has was produced above, by a fixture rather than by a claim", () => {
  assert.deepEqual([...produced].sort(), [...LISTING_STATES].sort(),
    "a state this module can return that no fixture here reaches is a state nothing checks");
  assert.equal(LISTING_STATES.length, 3, "the floor: MIG-1's three derived states (`unlisted` is answered before them)");
});

// ── the desk commands around the two records (M-T5.2, M-T5.3, M-T5.4) ───────
//
// `tools/selftest/deadline.mjs` holds the rules these commands apply, pure.
// These run the COMMANDS, as a person runs them, on real trees and real git
// history: the read of a marker's history is guard n22's whole input, and a
// command that wrote the deadline but not its POLICY.md line would pass every
// pure test above it.

const node = (script, args, cwd) => {
  try {
    return { status: 0, out: execFileSync(process.execPath, [path.join(REPO_ROOT, script), ...args], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (e) {
    return { status: e.status, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
};

test("M-T5.2: tools/binding-deadline.mjs writes the deadline and POLICY.md's line together, and refuses an earlier one", () => {
  const root = tmp("astra-binding-deadline-");
  fs.mkdirSync(path.join(root, "policy"));
  fs.copyFileSync(path.join(REPO_ROOT, "POLICY.md"), path.join(root, "POLICY.md"));
  const run = (...a) => node("tools/binding-deadline.mjs", [...a, "--root", root], root);

  const dry = run("--cutover-estimate", "2026-09-27T00:00:00Z");
  assert.equal(dry.status, 0, dry.out);
  assert.equal(fs.existsSync(path.join(root, DEADLINE_FILE)), false, "a run without --write wrote the deadline");

  const wrote = run("--cutover-estimate", "2026-09-27T00:00:00Z", "--round2-estimate", "2026-09-25T00:00:00Z", "--write");
  assert.equal(wrote.status, 0, wrote.out);
  assert.equal(readMarkers(root).deadline, "2026-11-26T00:00:00Z", "the bot's reader does not read the written deadline");
  const policy = fs.readFileSync(path.join(root, "POLICY.md"), "utf8");
  const line = policy.split("\n").filter((l) => l.startsWith("**Binding deadline:**"));
  assert.equal(line.length, 1);
  assert.match(line[0], /2026-11-26 \(`2026-11-26T00:00:00Z`\)/, "POLICY.md's line does not state the written deadline");

  const before = [DEADLINE_FILE, "POLICY.md"].map((f) => fs.readFileSync(path.join(root, f), "utf8"));
  const earlier = run("--cutover-estimate", "2026-09-20T00:00:00Z", "--write");
  assert.equal(earlier.status, 1, earlier.out);
  assert.match(earlier.out, /MIG-29/);
  assert.deepEqual([DEADLINE_FILE, "POLICY.md"].map((f) => fs.readFileSync(path.join(root, f), "utf8")), before,
    "a refused run changed a file");
  const floor = run("--cutover-estimate", "2026-10-01T00:00:00Z", "--round2-estimate", "2026-10-05T00:00:00Z");
  assert.equal(floor.status, 1, "a deadline under 60 days after the round-2 estimate was not refused");
});

/** A registry with two third-party accounts, as MIG-13's recipients see it. */
function noticeEstate() {
  const root = tmp("astra-notice-");
  write(root, "publishers/team.json", { owner: "team", tier: "astra_team" });
  write(root, "plugins/alpha/plugin.json", { id: "alpha", source: { repo: "stranger/alpha" }, added_at: "2026-08-01" });
  write(root, "plugins/gamma/plugin.json", { id: "gamma", source: { repo: "other/gamma" }, added_at: "2026-08-02" });
  write(root, "plugins/ours/plugin.json", { id: "ours", source: { repo: "team/ours" }, added_at: "2026-08-01" });
  git(root, ["init", "--quiet", "--initial-branch=main"]);
  git(root, ["config", "user.email", "test@example.invalid"]);
  git(root, ["config", "user.name", "test"]);
  commit(root, "an estate");
  return root;
}

test("M-T5.3: issue-paths stops the round for an account whose repository takes no issues, and names it for the owner", () => {
  const root = noticeEstate();
  const readings = path.join(root, "readings.json");
  write(root, "readings.json", {
    "stranger/alpha": { has_issues: true, archived: false, private: false },
    "other/gamma": { has_issues: false, archived: false, private: false },
  });
  const r = node("tools/migration-notice.mjs", ["issue-paths", "--root", root, "--readings", readings], root);
  assert.equal(r.status, 1, "a round with an unreachable account exited as if every account were reachable");
  assert.match(r.out, /OWNER ITEM {2}other has no issue path \(other\/gamma: has_issues is false\); listings gamma/);
  assert.match(r.out, /ok {4}stranger: an issue in stranger\/alpha reaches it/);
  write(root, "readings.json", {
    "stranger/alpha": { has_issues: true, archived: false, private: false },
    "other/gamma": { has_issues: true, archived: false, private: false },
  });
  assert.equal(node("tools/migration-notice.mjs", ["issue-paths", "--root", root, "--readings", readings], root).status, 0);
});

test("M-T5.3 + M-T5.4: a re-send the command writes is one the watch passes, and an earlier date under the same sent_at is red", async () => {
  const { verdictProblems } = await import("../lib/alert-verdict.mjs");
  const root = noticeEstate();
  const notice = (...a) => node("tools/migration-notice.mjs", [...a, "--root", root], root);
  const watch = (now) => {
    const out = path.join(root, "verdict.json");
    const r = node("tools/deadline-watch.mjs", ["--root", root, "--now", now, "--no-banner", "--out", out], root);
    assert.equal(r.status, 0, r.out);
    const v = JSON.parse(fs.readFileSync(out, "utf8"));
    fs.rmSync(out);
    assert.deepEqual(verdictProblems(v), [], "the watch composed a verdict the alarm channel refuses");
    return v;
  };
  fs.mkdirSync(path.join(root, "log"));
  assert.equal(notice("round", "--round", "1", "--sent-at", "2026-09-24T00:00:00Z", "--write").status, 0);
  commit(root, "round 1 sent");
  assert.equal(notice("round", "--round", "2", "--sent-at", "2026-09-25T00:00:00Z", "--cutover", "2026-10-30T00:00:00Z", "--write").status, 0);
  commit(root, "round 2 sent");
  assert.equal(watch("2026-09-26T00:00:00Z").status, "green");

  const later = notice("resend", "--cutover", "2026-11-15T00:00:00Z", "--at", "2026-09-28T00:00:00Z", "--write");
  assert.equal(later.status, 0, later.out);
  assert.match(later.out, /branch later/);
  assert.doesNotMatch(later.out, /Moderation-Exempt:/,
    "the re-send asked for a self-exemption, which clears every trigger in its commit; contract 2.3.0 excepts the markers instead");
  commit(root, "re-send: later");
  const two = JSON.parse(fs.readFileSync(path.join(root, "log/migration-notice-2.json"), "utf8"));
  assert.deepEqual([two.sent_at, two.cutover_planned_at], ["2026-09-25T00:00:00Z", "2026-11-15T00:00:00Z"]);
  assert.equal(watch("2026-09-29T00:00:00Z").status, "green", "the watch alarmed on the tree MIG-13's later branch leaves");

  // The wrong turn, by hand: the date moved EARLIER and sent_at kept.
  write(root, "log/migration-notice-2.json", { ...two, cutover_planned_at: "2026-10-20T00:00:00Z" });
  commit(root, "an earlier date, committed the wrong way");
  const v = watch("2026-09-30T00:00:00Z");
  assert.deepEqual([v.status, v.codes], ["red", ["MARKER_EARLIER_SAME_SENT_AT"]],
    "the watch did not read the marker's history, or did not refuse an earlier date under the same sent_at");
});
