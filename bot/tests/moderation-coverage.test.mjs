// The coverage canary's own canaries (registry plan M-T1.5).
//
// Every case here is a real git repository built in a temp directory, because
// both rules under test read HISTORY and nothing about history can be faked in
// process: the walk's start is the commit that added the tool, the trigger for
// a delist is the difference between a file's parent and its child, and the
// clearing trailer is on a later commit than the one it clears. A fixture that
// stubbed git would be a fixture that tested the stub.
//
// Two kinds of assertion, and the second kind is the point:
//
//   - that a clean repository is GREEN. Three of these, and they are the ones
//     that catch a rule which has become a rule about nothing: an author
//     README with an e-mail in it, a listing created unlisted, a commit that
//     carries its own exemption;
//   - that a dirty one is RED, with the code named. A rule nobody has watched
//     say no is a rule nobody knows works.
//
// The PRIV-2 block is the one to read if you are here to change
// `tools/priv-scan.mjs`. It holds the pair that is the whole argument for an
// allowlist: the SAME string, `usr_a1b2c3`, in a member nobody declared and in
// `plugin_id`. The first is red and the second is green, and no pattern over
// the value can tell them apart — which is why there is no pattern over the
// value.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { after } from "node:test";

import {
  HISTORY_FLOOR as MOD_HISTORY_FLOOR, UNLISTED_FLOOR, parseExempt,
  run as coverage,
} from "../../tools/moderation-coverage.mjs";
import {
  DOCUMENT_MEMBERS, HISTORY_FLOOR as PRIV_HISTORY_FLOOR, run as privScan, withoutAuthorship,
} from "../../tools/priv-scan.mjs";
import { ADVISORY_BASE, DOC as DOCS_DOC, run as docsRule } from "../../tools/coverage/docs-advisory-url.mjs";
import { KEEPALIVE, run as keepaliveRule } from "../../tools/coverage/keepalive-age.mjs";
import {
  AP7_LANDED, ASTRAPLUGINS_URL, astraPluginsRemote, loadPolicyReserved,
  parseReservedIdsYaml, repoSlug, run as mirrorRule,
} from "../../tools/coverage/reserved-id-mirror.mjs";
import {
  EXAMPLE_RE, pluginId, run as examplesRule,
} from "../../tools/coverage/examples-staging-id.mjs";
import { stagingListingId } from "../../tools/lib/reserved.mjs";
import { compareTree, expectationProblems, workflowJobs } from "../../tools/lib/settings.mjs";
import { githubGetter, localWorkflows, run as settingsRun } from "../../tools/coverage/settings.mjs";
import { mergeOwnChanges } from "../../tools/coverage/git.mjs";
import { RULES, outstandingActs, ruleNames } from "../../tools/coverage/rules.mjs";
import { compose } from "../../tools/coverage-verdict.mjs";
import { CHECKS } from "../lib/alert-checks.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const tmpRoots = [];

after(() => {
  for (const dir of tmpRoots) fs.rmSync(dir, { recursive: true, force: true });
});

// ── the fixture builder ─────────────────────────────────────────────────────

function fixture(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `astra-coverage-${name}-`));
  tmpRoots.push(dir);
  const g = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" });
  g("init", "-q", "-b", "main");
  g("config", "user.name", "Fixture");
  g("config", "user.email", "fixture@example.invalid");
  g("config", "commit.gpgsign", "false");
  const api = {
    dir,
    git: g,
    write(rel, content) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, typeof content === "string" ? content : `${JSON.stringify(content, null, 2)}\n`);
      return api;
    },
    remove(rel) { fs.rmSync(path.join(dir, rel), { force: true }); return api; },
    commit(message) { g("add", "-A"); g("commit", "-q", "--allow-empty", "-m", message); return api; },
    branch(name) { g("checkout", "-q", "-b", name); return api; },
    checkout(ref) { g("checkout", "-q", ref); return api; },
    /**
     * `git merge --no-ff --no-commit`, conflicts and all: the caller writes
     * the resolution and `commit()`s it, which is how a merge gets changes of
     * its own. Exit 1 is a conflict, which is the point; anything else throws.
     */
    startMerge(ref) {
      try {
        execFileSync("git", ["-C", dir, "merge", "--no-ff", "--no-commit", ref], { stdio: "pipe" });
      } catch (e) {
        if (e.status !== 1) throw e;
      }
      return api;
    },
    head: () => g("rev-parse", "HEAD").trim(),
    /** The commit that introduces both tools, so both walks have a start. */
    landTools() {
      api.write("tools/moderation-coverage.mjs", "// the real one lives in the repository\n");
      api.write("tools/priv-scan.mjs", "// the real one lives in the repository\n");
      api.commit("land the coverage tools");
      return api;
    },
  };
  return api;
}

const listing = (id, extra = {}) => ({
  schema: "astra.registry.plugin/1", id, name: id, summary: `${id} does a thing`,
  license: "MIT", source: { kind: "github", repo: `someone/${id}` }, added_at: "2026-09-01", ...extra,
});

const entry = (date, plugin, action, extra = {}) => ({
  date, action, plugin,
  reason: "A reason long enough to be a reason and short enough to be read by a person.",
  ...extra,
});

const mod = (repoDir, opts = {}) => coverage(repoDir, { historyFloor: 0, unlistedFloor: 0, ...opts });
const priv = (repoDir, opts = {}) => privScan(repoDir, { historyFloor: 0, ...opts });

const codesOf = (r) => r.codes.join(" ");

// ── the floors, first, because every case below is a loop over a set ────────

test("the floors are the numbers measured on the real repository, not zero", () => {
  // These two constants are what stops a truncated checkout and a moved
  // `plugins/` directory from reading as a clean bill of health, and they are
  // exactly the kind of number that gets lowered to make a red run go away.
  assert.ok(UNLISTED_FLOOR >= 6, `the unlisted floor is ${UNLISTED_FLOOR}; six listings were unlisted on 2026-09-19`);
  assert.ok(MOD_HISTORY_FLOOR >= 228, `the coverage history floor is ${MOD_HISTORY_FLOOR}; there were 228 commits on 2026-09-19`);
  assert.ok(PRIV_HISTORY_FLOOR >= 228, `the priv-scan history floor is ${PRIV_HISTORY_FLOOR}; there were 228 commits on 2026-09-19`);
});

test("the real repository still holds the six unlisted listings the floor counts", () => {
  const dir = path.join(REPO, "plugins");
  const unlisted = fs.readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .filter((e) => {
      const f = path.join(dir, e.name, "plugin.json");
      return fs.existsSync(f) && JSON.parse(fs.readFileSync(f, "utf8")).unlisted === true;
    });
  assert.ok(unlisted.length >= UNLISTED_FLOOR,
    `${unlisted.length} unlisted listing(s) in plugins/, and the floor is ${UNLISTED_FLOOR}`);
});

test("a shallow or truncated checkout is red, and never green about what it did not see", () => {
  const f = fixture("shallow").write("plugins/a/plugin.json", listing("a")).commit("one").landTools();
  const r = coverage(f.dir, { mode: "commits" });     // the real floor, 228, against a 2-commit fixture
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /MOD_HISTORY_FLOOR/);
});

// ── state mode ──────────────────────────────────────────────────────────────

test("an unlisted listing with no delist entry is red, and with one is green", () => {
  const f = fixture("state-delist")
    .write("plugins/a/plugin.json", listing("a", { unlisted: true }))
    .commit("delist a")
    .landTools();
  const red = mod(f.dir, { mode: "state" });
  assert.equal(red.status, "red");
  assert.match(codesOf(red), /MOD_UNLISTED_UNLOGGED/);
  assert.deepEqual(red.ids, ["a"]);

  f.write("bot/moderation/2026-09-01-a-delist.json", entry("2026-09-01", "a", "delist")).commit("log it");
  assert.equal(mod(f.dir, { mode: "state" }).status, "green");
});

test("a relist after the delist makes the listing's unlisted flag unaccounted for again", () => {
  // MOD-39's own wording: "a `delist` entry with no later `relist`". Without
  // the ordering, a plugin delisted, relisted and delisted again is covered by
  // the first entry for ever.
  const f = fixture("state-relist")
    .write("plugins/a/plugin.json", listing("a", { unlisted: true }))
    .write("bot/moderation/2026-09-01-a-delist.json", entry("2026-09-01", "a", "delist"))
    .commit("delist and log")
    .landTools();
  assert.equal(mod(f.dir, { mode: "state" }).status, "green");

  f.write("bot/moderation/2026-09-05-a-relist.json", entry("2026-09-05", "a", "relist")).commit("relist, on paper only");
  const r = mod(f.dir, { mode: "state" });
  assert.equal(r.status, "red", "the log says relisted and the listing is still unlisted");
  assert.match(codesOf(r), /MOD_UNLISTED_UNLOGGED/);
});

test("(f) the staging listing created unlisted is green", () => {
  // MOD-16's reserved id is created unlisted on purpose and is never a
  // takedown. Without the exemption, M-T2.1's own task turns this canary red
  // on the day it lands.
  const f = fixture("state-staging")
    .write("policy/reserved-ids.json", { staging_listing_id: "astra-path-test" })
    .write("plugins/astra-path-test/plugin.json", listing("astra-path-test", { unlisted: true }))
    .commit("the staging listing")
    .landTools();
  assert.equal(mod(f.dir, { mode: "state" }).status, "green");
});

test("a yanked version is covered by a yank entry or by an author-action record, and by nothing else", () => {
  const f = fixture("state-yank")
    .write("plugins/a/plugin.json", listing("a"))
    .write("plugins/a/versions/1.0.0.json", { version: "1.0.0", yanked: true })
    .commit("yank 1.0.0")
    .landTools();
  const red = mod(f.dir, { mode: "state" });
  assert.equal(red.status, "red");
  assert.match(codesOf(red), /MOD_YANKED_UNLOGGED/);

  // FLOW-79's `A_YANK`, compiled to an author-action record.
  f.write("log/decisions/2026/09/abc.json", {
    schema: "astra.registry.decision/1", decision_id: "abc", decided_at: "2026-09-02T00:00:00Z",
    actor: "author", trigger: "moderation", plugin_id: "a", version: "1.0.0",
    repo: "someone/a", state: "yanked", reasons: ["A_YANK"], category: "author_request",
  }).commit("the author yanked it from the panel");
  assert.equal(mod(f.dir, { mode: "state" }).status, "green");
});

// ── commit mode ─────────────────────────────────────────────────────────────

test("(b) an uncovered yanked commit is red, and a later Moderation-Exempt naming its SHA clears it", () => {
  const f = fixture("walk-yank")
    .write("plugins/a/plugin.json", listing("a"))
    .write("plugins/a/versions/1.0.0.json", { version: "1.0.0" })
    .commit("list a")
    .landTools();

  f.write("plugins/a/versions/1.0.0.json", { version: "1.0.0", yanked: true }).commit("yank it, quietly");
  const bad = f.head();
  const red = mod(f.dir, { mode: "commits" });
  assert.equal(red.status, "red");
  assert.match(codesOf(red), /MOD_COMMIT_UNCOVERED/);
  assert.ok(red.hexes.includes(bad), "the verdict names the commit, which is what an operator needs to clear it");

  f.commit(`unrelated work\n\nModeration-Exempt: ${bad}: operator: a release script error, reverted, no user was served it`);
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green");
});

test("(c) a commit that carries its own trailer is green", () => {
  const f = fixture("walk-selfexempt")
    .write("plugins/a/plugin.json", listing("a"))
    .commit("list a")
    .landTools();
  f.write("plugins/a/plugin.json", listing("a", { unlisted: true }))
    .commit("delist a\n\nModeration-Exempt: operator: taken down by hand during an incident, logged in the runbook");
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green");
});

test("a delist in the same commit as its log entry is green, and without it red", () => {
  const f = fixture("walk-delist")
    .write("plugins/a/plugin.json", listing("a"))
    .commit("list a")
    .landTools();
  f.write("plugins/a/plugin.json", listing("a", { unlisted: true })).commit("delist a");
  assert.match(codesOf(mod(f.dir, { mode: "commits" })), /MOD_COMMIT_UNCOVERED/);

  // The honest repair: write the entry that was owed. It clears the walk too,
  // because MOD-46's second path is a matching retro log entry.
  f.write("bot/moderation/2026-09-02-a-delist.json", entry("2026-09-02", "a", "delist")).commit("the entry that was owed");
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green");
});

test("a listing CREATED unlisted is not a delist", () => {
  // Reading only the child would make every new unlisted listing look like an
  // unlogged takedown, which is what an operator does when they land a plugin
  // they are not ready to serve.
  const f = fixture("walk-created-unlisted").write("plugins/a/plugin.json", listing("a")).commit("seed").landTools();
  f.write("plugins/b/plugin.json", listing("b", { unlisted: true })).commit("land b, not ready to serve it");
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green");
});

test("(d) an edited existing log entry is red, and (a) a deleted one is too", () => {
  const f = fixture("walk-log-edit")
    .write("bot/moderation/2026-09-01-a-delist.json", entry("2026-09-01", "a", "delist"))
    .commit("the entry")
    .landTools();

  f.write("bot/moderation/2026-09-01-a-delist.json", entry("2026-09-01", "a", "delist", { reason: "A different reason entirely, written afterwards." }))
    .commit("tidy the wording");
  const edited = mod(f.dir, { mode: "commits" });
  assert.equal(edited.status, "red");
  assert.match(codesOf(edited), /MOD_LOG_ENTRY_EDITED/);

  const g = fixture("walk-log-delete")
    .write("bot/moderation/2026-09-01-a-delist.json", entry("2026-09-01", "a", "delist"))
    .commit("the entry")
    .landTools();
  g.remove("bot/moderation/2026-09-01-a-delist.json").commit("remove the retro entry");
  const deleted = mod(g.dir, { mode: "commits" });
  assert.equal(deleted.status, "red");
  assert.match(codesOf(deleted), /MOD_LOG_ENTRY_EDITED/);
});

test("log/** is append-only too, so a decision record cannot be rewritten after the fact", () => {
  const f = fixture("walk-log-tree")
    .write("log/decisions/2026/09/abc.json", { schema: "astra.registry.decision/1", state: "refused" })
    .commit("a decision")
    .landTools();
  f.write("log/decisions/2026/09/abc.json", { schema: "astra.registry.decision/1", state: "approved" })
    .commit("change our mind, silently");
  const r = mod(f.dir, { mode: "commits" });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /MOD_LOG_APPEND_ONLY/);
});

test("(e) a hand advisory added and deleted under trailers is green; deleted with neither is red", () => {
  const f = fixture("walk-advisory").write("plugins/a/plugin.json", listing("a")).commit("seed").landTools();

  f.write("tools/revocations/ASTRA-2026-0009.json", { id: "ASTRA-2026-0009", action: "warn" })
    .commit("the RC-R1-10(e) advisory\n\nModeration-Exempt: operator: ROLL-14's withdrawal drill, approved by the owner");
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green");

  f.remove("tools/revocations/ASTRA-2026-0009.json")
    .commit("lift it\n\nModeration-Exempt: operator: ROLL-14's withdrawal drill, the lift half");
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green");

  const g = fixture("walk-advisory-bare").write("plugins/a/plugin.json", listing("a")).commit("seed").landTools();
  g.write("tools/revocations/ASTRA-2026-0009.json", { id: "ASTRA-2026-0009", action: "warn" })
    .commit("an advisory, with nothing recording it");
  const red = mod(g.dir, { mode: "commits" });
  assert.equal(red.status, "red");
  assert.match(codesOf(red), /MOD_COMMIT_UNCOVERED/);
});

test("an advisory is deleted only under a log entry whose `reverses` names it", () => {
  const f = fixture("walk-unrevoke").write("plugins/a/plugin.json", listing("a")).commit("seed").landTools();
  f.write("tools/revocations/ASTRA-2026-0010.json", { id: "ASTRA-2026-0010", action: "block_install" })
    .write("bot/moderation/2026-09-03-a-revoke.json", entry("2026-09-03", "a", "revoke", { advisory: "ASTRA-2026-0010" }))
    .commit("revoke a");
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green");

  // A log entry in the deleting commit is not enough: it has to say what it
  // reverses, or the transparency log records a revocation that is no longer
  // in force with nothing saying so.
  f.remove("tools/revocations/ASTRA-2026-0010.json")
    .write("bot/moderation/2026-09-04-a-delist.json", entry("2026-09-04", "a", "delist"))
    .commit("drop the advisory and log something else");
  assert.match(codesOf(mod(f.dir, { mode: "commits" })), /MOD_COMMIT_UNCOVERED/);

  const g = fixture("walk-unrevoke-ok").write("plugins/a/plugin.json", listing("a")).commit("seed").landTools();
  g.write("tools/revocations/ASTRA-2026-0010.json", { id: "ASTRA-2026-0010", action: "block_install" })
    .write("bot/moderation/2026-09-03-a-revoke.json", entry("2026-09-03", "a", "revoke", { advisory: "ASTRA-2026-0010" }))
    .commit("revoke a");
  g.remove("tools/revocations/ASTRA-2026-0010.json")
    .write("bot/moderation/2026-09-04-a-unrevoke.json", entry("2026-09-04", "a", "unrevoke", { reverses: "ASTRA-2026-0010" }))
    .commit("lift it, and say what is lifted");
  assert.equal(mod(g.dir, { mode: "commits" }).status, "green");
});

test("the walk starts at the commit that added the tool, and judges nothing before it", () => {
  const f = fixture("walk-start")
    .write("plugins/a/plugin.json", listing("a"))
    .commit("list a");
  f.write("plugins/a/plugin.json", listing("a", { unlisted: true })).commit("an unlogged delist, before the rule existed");
  f.landTools();
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green",
    "history before the introducing commit is not re-judged; that is what state mode is for");

  f.write("plugins/a/plugin.json", listing("a", { unlisted: true, deprecated: true })).commit("touch it again");
  assert.equal(mod(f.dir, { mode: "commits" }).status, "green",
    "an already-unlisted listing changed for another reason is not a second delist");
});

test("`Moderation-Exempt:` is read in two grammars and not in three", () => {
  assert.deepEqual(parseExempt("publisher-recheck: evidence lapsed past the confirmation window"),
    { sha: null, actor: "publisher-recheck", reason: "evidence lapsed past the confirmation window" });
  assert.deepEqual(parseExempt("deadbeef1234567: operator: cleared after review"),
    { sha: "deadbeef1234567", actor: "operator", reason: "cleared after review" });
  assert.equal(parseExempt("operator"), null, "an actor with no reason exempts nothing");
  assert.equal(parseExempt("operator: "), null, "an empty reason exempts nothing");
});

// ── PRIV-2 ──────────────────────────────────────────────────────────────────

const decision = (extra = {}) => ({
  schema: "astra.registry.decision/1", decision_id: "d1", decided_at: "2026-09-02T00:00:00Z",
  actor: "bot", trigger: "poll", plugin_id: "astra-chess", version: "1.0.0",
  repo: "MINICE-AI/astra-chess", state: "published", ...extra,
});

test("PRIV-2: an e-mail address in a composed decision record is red", () => {
  const f = fixture("priv-email").commit("seed").landTools();
  f.write("log/decisions/2026/09/d1.json", decision({ moderator: "someone.real@gmail.com" })).commit("a decision");
  const r = priv(f.dir);
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /E_PRIV_EMAIL/);
});

test("PRIV-2: an `@handle` in a commit body is red, and in DEC-7's `moderator` member is not", () => {
  const f = fixture("priv-handle").commit("seed").landTools();
  f.commit("approve it\n\nDecided with @astra-maintainer-7 on the call");
  const r = priv(f.dir);
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /E_PRIV_HANDLE/);

  const g = fixture("priv-handle-ok").commit("seed").landTools();
  g.write("log/decisions/2026/09/d1.json", decision({ actor: "moderator", moderator: "@knice" })).commit("a moderator decision");
  assert.equal(priv(g.dir).status, "green",
    "DEC-7 carries a moderator handle, and PRIV-2 permits it in that member and in no other");
});

test("PRIV-2: a Telegram chat id is red, and so is a member whose NAME says Telegram", () => {
  const f = fixture("priv-tg").commit("seed").landTools();
  f.commit("wire the alarm\n\nDelivered to -1001234567890 at 09:23");
  assert.match(codesOf(priv(f.dir)), /E_PRIV_TELEGRAM/);

  const g = fixture("priv-tg-member").commit("seed").landTools();
  g.write("state/alerts/abc.json", { schema: "x", fingerprint: "a", event: "e", chat_id: "1234567" }).commit("an alert record");
  const r = priv(g.dir);
  assert.equal(r.status, "red");
  // A bare integer has no shape that separates it from a run number, so the
  // rule that catches this one is the member's NAME and, before that, the fact
  // that `chat_id` is not a member TRUST-14 declares.
  assert.match(codesOf(r), /E_PRIV_UNDECLARED_MEMBER|E_PRIV_TELEGRAM/);
});

test("PRIV-2: a UUID is red outside `submission_id` and `service_decision_id`, and green inside", () => {
  const u = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
  const f = fixture("priv-uuid").commit("seed").landTools();
  f.write("log/decisions/2026/09/d1.json", decision({ fingerprint: u })).commit("a decision with a UUID in the wrong member");
  assert.match(codesOf(priv(f.dir)), /E_PRIV_UUID/);

  const g = fixture("priv-uuid-ok").commit("seed").landTools();
  g.write("log/decisions/2026/09/d1.json", decision({ submission_id: u })).commit("a decision with a UUID where DEC-7 puts one");
  assert.equal(priv(g.dir).status, "green");
});

test("PRIV-2: the subject-id shape is caught by POSITION, and the same string in a declared member is green", () => {
  // The pair that is the entire argument for an allowlist. `usr_a1b2c3`
  // matches `^[A-Za-z0-9_-]{1,64}$`, and so does `astra-chess`, and so does
  // 80% of the tokens in this repository's commit messages. No rule over the
  // VALUE can separate them. The rule over the POSITION can.
  const subject = "usr_a1b2c3";
  const f = fixture("priv-subject").commit("seed").landTools();
  f.write("log/decisions/2026/09/d1.json", decision({ subject })).commit("a decision naming an account");
  const r = priv(f.dir);
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /E_PRIV_UNDECLARED_MEMBER/);
  assert.match(r.detail.join("\n"), /`subject` is not a member decision may carry/);

  const g = fixture("priv-subject-ok").commit("seed").landTools();
  g.write("log/decisions/2026/09/d1.json", decision({ plugin_id: subject })).commit("a decision about a plugin");
  assert.equal(priv(g.dir).status, "green",
    "the same string in a member that may only hold a repository coordinate is a repository coordinate");
});

test("PRIV-2: an author README with a contact address in it is never scanned", () => {
  // MOD-46 v3. Author bundle content reaches `main` verbatim (BOT-33), PRIV-2
  // exempts it by name, and the version of this rule that scanned it would
  // have let any author's README stall the revoke of that author's plugin.
  const f = fixture("priv-author-readme").commit("seed").landTools();
  f.write("plugins/a/readme/README.md", "# a\n\nWrite to me at someone.real@gmail.com\n")
    .write("plugins/a/plugin.json", listing("a"))
    .commit("publish a, README and all");
  assert.equal(priv(f.dir).status, "green");
});

test("PRIV-2: a composed document nobody declared is red, naming what to do", () => {
  const f = fixture("priv-undeclared").commit("seed").landTools();
  f.write("log/rollout/R3-exit.json", { walked: true }).commit("record the R3 exit");
  const r = priv(f.dir);
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /E_PRIV_UNDECLARED_DOCUMENT/);
  assert.match(r.detail.join("\n"), /declare it there/);
});

test("PRIV-2: git's authorship trailers and reserved TLDs are exempt, and a real address is not", () => {
  const f = fixture("priv-trailers").commit("seed").landTools();
  f.commit([
    "a change",
    "",
    "It mentions 1@evil.example, a test vector, and security@minice.ai, a role address.",
    "",
    "Co-authored-by: Miha <mishasamil32@gmail.com>",
    "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>",
  ].join("\n"));
  assert.equal(priv(f.dir).status, "green");

  // The same message with the personal address moved OUT of the trailer.
  const g = fixture("priv-trailers-moved").commit("seed").landTools();
  g.commit("a change\n\nAsk mishasamil32@gmail.com about it.");
  assert.match(codesOf(priv(g.dir)), /E_PRIV_EMAIL/);
});

test("PRIV-2: the canary exempts the address the contact file publishes, and needs the file to", () => {
  // MOD-45's "read rather than typed", which this walk keeps and the decision
  // writer gave up (dev/couplings.md entry 104; `bot/tests/decisions.test.mjs`
  // holds the writer to it). No test here exercised it until then — every
  // role address in this file is a role LOCAL PART, which needs no file — so
  // the address below has a local part that is not one and a domain that is
  // not reserved: only the file can exempt it.
  const published = "disclosures@astra-registry-fixture.net";
  const f = fixture("priv-contact-file").commit("seed").landTools();
  f.write("bot/security-contact.json", { email: published }).commit("publish the contact");
  f.write("log/decisions/2026/09/d1.json", decision({ reasons: [`E_X, write to ${published}`] }))
    .commit("a decision naming the published contact");
  const green = priv(f.dir);
  assert.equal(green.status, "green", green.detail.join("\n"));
  assert.match(green.detail.join("\n"), /, 1 exempt role address\(es\),/);

  // The file is read from the working tree the walk runs in. Without it the
  // same history is red, which is what makes the green above the file's doing.
  f.remove("bot/security-contact.json");
  const red = priv(f.dir);
  assert.match(codesOf(red), /E_PRIV_EMAIL/);
  assert.match(red.detail.join("\n"), /, 0 exempt role address\(es\),/);
});

test("PRIV-2: this repository's own queue filenames are not addresses", () => {
  // The one finding the naive pattern produced over all 228 commits, and it
  // was `state/queue/dice-roller@0.1.2.json`.
  const f = fixture("priv-filename").commit("seed").landTools();
  f.commit("queue it\n\nWrote state/queue/dice-roller@0.1.2.json, publish_after 24h");
  assert.equal(priv(f.dir).status, "green");
});

test("PRIV-2: an exemption that matches nothing fails", () => {
  const f = fixture("priv-stale-exemption").commit("seed").landTools();
  f.write("tools/coverage/priv-scan-exempt.json", {
    exemptions: [{ commit: "0123456", where: "commit-message", code: "E_PRIV_EMAIL", reason: "it was fine" }],
  }).commit("an exemption for a finding that does not exist");
  const r = priv(f.dir);
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /PRIV_EXEMPTION_MATCHES_NOTHING/);
});

test("PRIV-2: an exemption that matches is honoured exactly once and for one place", () => {
  const f = fixture("priv-live-exemption").commit("seed").landTools();
  f.commit("a change\n\nAsk mishasamil32@gmail.com about it.");
  const bad = f.head();
  assert.match(codesOf(priv(f.dir)), /E_PRIV_EMAIL/);

  f.write("tools/coverage/priv-scan-exempt.json", {
    exemptions: [{ commit: bad, where: "commit-message", code: "E_PRIV_EMAIL", reason: "the owner's own address, quoted by him" }],
  }).commit("clear it");
  assert.equal(priv(f.dir).status, "green");
});

test("withoutAuthorship strips the block and nothing else", () => {
  const msg = "Subject\n\nBody mentioning Co-authored-by in a sentence.\n\nCo-authored-by: X <x@y.z>\n";
  const out = withoutAuthorship(msg);
  assert.match(out, /Body mentioning Co-authored-by in a sentence/);
  assert.doesNotMatch(out, /<x@y\.z>/);
});

test("every declared document kind lists members, a source and its exempt sets", () => {
  // The table is the position rule. A kind added with an empty member list
  // would accept everything and read as declared.
  const kinds = Object.entries(DOCUMENT_MEMBERS);
  assert.ok(kinds.length >= 7, `${kinds.length} document kinds declared; there were 7 on 2026-09-19`);
  for (const [name, t] of kinds) {
    assert.ok(Array.isArray(t.members) && t.members.length >= 2, `${name} declares ${t.members?.length} member(s)`);
    assert.ok(Array.isArray(t.uuidOk), `${name} has no uuidOk set`);
    assert.ok(Array.isArray(t.handleOk), `${name} has no handleOk set`);
    assert.ok(t.source && t.source.length > 10, `${name} names no requirement that fixes its members`);
  }
});

// ── gap 93: what a merge's own resolution wrote ────────────────────────────
//
// Both walks took `rev-list --no-merges`, which is right for "who wrote this
// change" and cannot see a change made inside a merge's resolution: before
// this block, every red case below was green. The pairs are the point — each
// "the merge's own change is judged" has a "and the branch's change is judged
// ONCE", because the obvious repair (walk the merges' first-parent diffs)
// reports every branch commit a second time under the merge's SHA, where the
// exemption or trailer that cleared the branch commit does not reach.

const FAKE_ADDRESS = "someone.real@gmail.com";
const count = (r, code) => r.codes.filter((c) => c === code).length;
const D1 = "log/decisions/2026/09/d1.json";

test("gap 93: an address a merge's resolution writes into a document neither side touched is red, at the merge", () => {
  const f = fixture("merge-evil-clean").write(D1, decision()).commit("seed").landTools();
  f.branch("side").write("README", "side\n").commit("side work");
  f.checkout("main").write("OTHER", "main\n").commit("main work");
  f.startMerge("side").write(D1, decision({ moderator: FAKE_ADDRESS })).commit("Merge branch 'side'");
  const merge = f.head();
  const r = priv(f.dir);
  assert.equal(r.status, "red");
  assert.equal(count(r, "E_PRIV_EMAIL"), 1);
  assert.deepEqual(r.hexes, [merge], "the finding is the merge's, because no side commit wrote it");
});

test("gap 93: an address typed while resolving a conflict, merging main into a branch, is red at that merge", () => {
  const f = fixture("merge-evil-conflict").write(D1, decision()).commit("seed").landTools();
  f.branch("side").write(D1, decision({ run: "side" })).commit("side edits d1");
  f.checkout("main").write(D1, decision({ run: "main" })).commit("main edits d1");
  f.checkout("side").startMerge("main").write(D1, decision({ run: "both", moderator: FAKE_ADDRESS }))
    .commit("Merge branch 'main' into side");
  const merge = f.head();
  // And the pull request's merge back into main, which carries the branch
  // tree as it is: no change of its own, so nothing a second time.
  f.checkout("main").startMerge("side").commit("Merge pull request #1 from someone/side");
  const r = priv(f.dir);
  assert.equal(r.status, "red");
  assert.equal(count(r, "E_PRIV_EMAIL"), 1);
  assert.deepEqual(r.hexes, [merge]);
});

test("gap 93: a merge's own message is scanned like any commit's", () => {
  const f = fixture("merge-message").commit("seed").landTools();
  f.branch("side").write("README", "side\n").commit("side work");
  f.checkout("main").write("OTHER", "main\n").commit("main work");
  f.startMerge("side").commit(`Merge branch 'side'\n\nAsk ${FAKE_ADDRESS} about the conflict.`);
  const r = priv(f.dir);
  assert.equal(r.status, "red");
  assert.deepEqual(r.hexes, [f.head()]);
  assert.match(r.detail.join("\n"), /commit-message/);
});

test("gap 93: a branch's address merged cleanly, or through a conflict kept whole, is one finding at the branch commit", () => {
  // Clean: the merge has no change of its own.
  const f = fixture("merge-dup-clean").write(D1, decision()).commit("seed").landTools();
  f.branch("side").write("log/decisions/2026/09/d2.json", decision({ decision_id: "d2", moderator: FAKE_ADDRESS }))
    .commit("side adds d2");
  const side = f.head();
  f.checkout("main").write("OTHER", "main\n").commit("main work");
  f.startMerge("side").commit("Merge branch 'side'");
  const clean = priv(f.dir);
  assert.equal(count(clean, "E_PRIV_EMAIL"), 1, "a clean merge adds no finding");
  assert.deepEqual(clean.hexes, [side]);

  // Conflicted, and resolved by keeping both sides: the document is among the
  // merge's own changes (it differs from the conflicted remerge), and the
  // address in it is the side's, so it is not reported again under the merge.
  const g = fixture("merge-dup-conflict").write(D1, decision()).commit("seed").landTools();
  g.branch("side").write(D1, decision({ run: "side", moderator: FAKE_ADDRESS })).commit("side edits d1");
  const side2 = g.head();
  g.checkout("main").write(D1, decision({ run: "main" })).commit("main edits d1");
  g.startMerge("side").write(D1, decision({ run: "main and side", moderator: FAKE_ADDRESS })).commit("Merge branch 'side'");
  const merge = g.head();
  assert.ok(mergeOwnChanges(merge, g.dir).changes.some((c) => c.path === D1),
    "the fixture has not built what it says: the resolution must be a change of the merge's own");
  const conflicted = priv(g.dir);
  assert.equal(count(conflicted, "E_PRIV_EMAIL"), 1);
  assert.deepEqual(conflicted.hexes, [side2]);

  // And the side's exemption still clears it: nothing new appeared at the
  // merge for the entry to fail to reach.
  g.write("tools/coverage/priv-scan-exempt.json", {
    exemptions: [{ commit: side2, where: D1, code: "E_PRIV_EMAIL", reason: "a fixture address" }],
  }).commit("clear it");
  assert.equal(priv(g.dir).status, "green");
});

test("gap 93: a merge's own changes are remerge-diff's, and a resolution that drops one side's file is one of them", () => {
  // The claim tools/coverage/git.mjs makes for merge-tree, held to git's own
  // remerge-diff on the shapes that tell the mechanisms apart. `--cc` gives
  // nothing for the last one: its whole content is a deletion.
  const nameStatus = (dir, sha) => {
    const f = execFileSync("git", ["-C", dir, "show", "--remerge-diff", "--format=", "--name-status", "-z", "--no-renames", sha],
      { encoding: "utf8" }).split("\0").filter(Boolean);
    const out = [];
    for (let i = 0; i < f.length; i += 2) out.push(`${f[i][0]} ${f[i + 1]}`);
    return out.sort();
  };
  const mine = (dir, sha) => mergeOwnChanges(sha, dir).changes.map((c) => `${c.status} ${c.path}`).sort();
  const lines = (sub = {}) => `${Array.from({ length: 20 }, (_, i) => sub[i] ?? `line ${i}`).join("\n")}\n`;
  const seen = {};

  const a = fixture("mech-auto").write("a", lines()).commit("seed");
  a.branch("s").write("a", lines({ 1: "S" })).commit("s");
  a.checkout("main").write("a", lines({ 15: "M" })).commit("m");
  a.startMerge("s").commit("merge");
  seen.auto = [mine(a.dir, a.head()), nameStatus(a.dir, a.head())];

  const b = fixture("mech-union").write("a", lines()).commit("seed");
  b.branch("s").write("a", lines({ 5: "S" })).commit("s");
  b.checkout("main").write("a", lines({ 5: "M" })).commit("m");
  b.startMerge("s").write("a", lines({ 5: "M\nS" })).commit("merge");
  seen.union = [mine(b.dir, b.head()), nameStatus(b.dir, b.head())];

  const c = fixture("mech-drop").write("a", lines()).commit("seed");
  c.branch("s").write("x", "s\n").commit("s");
  c.checkout("main").write("z", "added on main\n").commit("m");
  c.checkout("s").startMerge("main").remove("z").commit("merge main into s");
  seen.drop = [mine(c.dir, c.head()), nameStatus(c.dir, c.head())];

  for (const [shape, [ours, git]] of Object.entries(seen)) assert.deepEqual(ours, git, `${shape}: merge-tree and remerge-diff disagree`);
  assert.deepEqual(seen.auto[0], [], "a clean auto-merge of one file both sides edited is no change of the merge's own");
  assert.deepEqual(seen.union[0], ["M a"]);
  assert.deepEqual(seen.drop[0], ["D z"]);
});

test("gap 93: an octopus merge is reported as not judged by both walks, never passed", () => {
  const f = fixture("merge-octopus").commit("seed").landTools();
  for (const n of ["x", "y"]) f.checkout("main").branch(n).write(n, `${n}\n`).commit(n);
  f.checkout("main");
  f.git("merge", "-q", "--no-ff", "-m", "octopus", "x", "y");
  assert.match(codesOf(priv(f.dir)), /E_PRIV_MERGE_NOT_JUDGED/);
  assert.match(codesOf(mod(f.dir, { mode: "commits" })), /MOD_MERGE_NOT_JUDGED/);
});

test("gap 93: a delist a merge's resolution makes is uncovered at the merge, and its own trailer clears it", () => {
  const build = (name, message) => {
    const f = fixture(name).write("plugins/a/plugin.json", listing("a")).commit("list a").landTools();
    f.branch("side").write("README", "side\n").commit("side work");
    f.checkout("main").write("OTHER", "main\n").commit("main work");
    f.startMerge("side").write("plugins/a/plugin.json", listing("a", { unlisted: true })).commit(message);
    return f;
  };
  const f = build("merge-delist", "Merge branch 'side'");
  const r = mod(f.dir, { mode: "commits" });
  assert.equal(count(r, "MOD_COMMIT_UNCOVERED"), 1);
  assert.deepEqual(r.hexes, [f.head()]);

  const g = build("merge-delist-exempt",
    "Merge branch 'side'\n\nModeration-Exempt: operator: taken down by hand while resolving, logged in the runbook");
  assert.equal(mod(g.dir, { mode: "commits" }).status, "green");
});

test("gap 93: a resolution that undoes main's relist is a delist, judged against what git would have written", () => {
  // Neither parent's bytes answer this one: the branch still has the listing
  // unlisted from before the relist, so "some parent was unlisted" would call
  // it inherited. What git would have written is main's relist.
  const f = fixture("merge-undo-relist").write("plugins/a/plugin.json", listing("a", { unlisted: true }))
    .commit("seed").landTools();
  f.branch("side").write("README", "side\n").commit("side work");
  f.checkout("main").write("plugins/a/plugin.json", listing("a"))
    .write("bot/moderation/2026-09-03-a-relist.json", entry("2026-09-03", "a", "relist")).commit("relist a");
  f.checkout("side").startMerge("main").write("plugins/a/plugin.json", listing("a", { unlisted: true }))
    .commit("Merge branch 'main' into side");
  const r = mod(f.dir, { mode: "commits" });
  assert.equal(count(r, "MOD_COMMIT_UNCOVERED"), 1);
  assert.deepEqual(r.hexes, [f.head()]);
});

test("gap 93: a branch's delist merged cleanly, or through a conflict kept whole, is one finding at the branch commit", () => {
  const f = fixture("merge-delist-dup").write("plugins/a/plugin.json", listing("a")).commit("list a").landTools();
  f.branch("side").write("plugins/a/plugin.json", listing("a", { unlisted: true })).commit("side delists a");
  const side = f.head();
  f.checkout("main").write("OTHER", "main\n").commit("main work");
  f.startMerge("side").commit("Merge branch 'side'");
  const clean = mod(f.dir, { mode: "commits" });
  assert.equal(count(clean, "MOD_COMMIT_UNCOVERED"), 1);
  assert.deepEqual(clean.hexes, [side]);

  // Conflicted: main rewrote the summary on the same line region, and the
  // resolution keeps both. The remerged file is conflict markers, so the
  // parents answer, and the branch's flag is the branch's act.
  const g = fixture("merge-delist-dup-conflict").write("plugins/a/plugin.json", listing("a")).commit("list a").landTools();
  g.branch("side").write("plugins/a/plugin.json", listing("a", { summary: "side's summary", unlisted: true }))
    .commit("side delists a");
  const side2 = g.head();
  g.checkout("main").write("plugins/a/plugin.json", listing("a", { summary: "main's summary" })).commit("main edits a");
  g.startMerge("side").write("plugins/a/plugin.json", listing("a", { summary: "main's summary", unlisted: true }))
    .commit("Merge branch 'side'");
  assert.ok(mergeOwnChanges(g.head(), g.dir).conflicted.has("plugins/a/plugin.json"),
    "the fixture has not built a conflict, so it is not testing the parents' answer");
  const conflicted = mod(g.dir, { mode: "commits" });
  assert.equal(count(conflicted, "MOD_COMMIT_UNCOVERED"), 1);
  assert.deepEqual(conflicted.hexes, [side2]);
});

test("gap 93: merging main into a branch and dropping a log entry main added is an edited log, at that merge only", () => {
  // Invisible to state mode as well: nothing is unlisted without a record,
  // the record is simply gone from main once the pull request merges.
  const e = "bot/moderation/2026-09-02-b-delist.json";
  const f = fixture("merge-drop-entry").write("plugins/a/plugin.json", listing("a")).commit("seed").landTools();
  f.branch("side").write("README", "side\n").commit("side work");
  f.checkout("main").write(e, entry("2026-09-02", "b", "delist")).commit("log an entry");
  f.checkout("side").startMerge("main").remove(e).commit("Merge branch 'main' into side");
  const merge = f.head();
  f.checkout("main").startMerge("side").commit("Merge pull request #1 from someone/side");
  assert.equal(fs.existsSync(path.join(f.dir, e)), false, "the fixture has not built what it says");
  const r = mod(f.dir, { mode: "commits" });
  assert.equal(count(r, "MOD_LOG_ENTRY_EDITED"), 1);
  assert.deepEqual(r.hexes, [merge]);
});

// ── M-T1.3: the advisory URL the withdrawal docs teach ──────────────────────
//
// No git here. This rule reads one document in the working tree, so its
// fixtures are one document in a temp directory — and the case that matters is
// the last one: a github.com link that is NOT an advisory stays green, because
// a canary that goes red for an ordinary link is a canary somebody deletes.

function docsFixture(name, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `astra-docs-${name}-`));
  tmpRoots.push(dir);
  if (body !== null) {
    fs.mkdirSync(path.join(dir, path.dirname(DOCS_DOC)), { recursive: true });
    fs.writeFileSync(path.join(dir, DOCS_DOC), body);
  }
  return dir;
}

test("M-T1.3: this repository's withdrawal docs name no advisory URL it does not serve", () => {
  const r = docsRule(REPO);
  assert.equal(r.status, "green", r.detail.join("\n"));
});

test("M-T1.3: the example this task deleted is red the moment it comes back", () => {
  // Verbatim the line that was in `tools/revocations/README.md` until today,
  // which is the mutation this rule exists for.
  const r = docsRule(docsFixture("restored",
    '```json\n{\n  "id": "ASTRA-2026-0001",\n' +
    '  "advisory_url": "https://github.com/mihailinl/astra-registry/security/advisories/ASTRA-2026-0001",\n' +
    "}\n```\n"));
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /MOD_13_DOCS_ADVISORY_EXAMPLE/);
  assert.match(codesOf(r), /MOD_13_DOCS_GITHUB_ADVISORY/, "the host leg has to fire on it too, not only the base leg");
});

test("M-T1.3: an advisory_url under any other base is red, github or not", () => {
  const r = docsRule(docsFixture("other-host",
    '"advisory_url": "https://advisories.example.invalid/ASTRA-2026-0001"\n'));
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /MOD_13_DOCS_ADVISORY_EXAMPLE/);
  assert.doesNotMatch(codesOf(r), /GITHUB/, "example.invalid is not a github host and must not be reported as one");
});

test("M-T1.3: a github.io advisory page is the same mistake with a different host", () => {
  const r = docsRule(docsFixture("pages",
    "The advisory is at https://mihailinl.github.io/advisories/ASTRA-2026-0001.html today.\n" +
    "Leave advisory_url out.\n"));
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /MOD_13_DOCS_GITHUB_ADVISORY/);
});

test("M-T1.3: MOD-13's own base is green, so M-T3.9's README edit lands without touching this rule", () => {
  const r = docsRule(docsFixture("base",
    `The bot sets it:\n\n    "advisory_url": "${ADVISORY_BASE}ASTRA-2026-0001"\n`));
  assert.equal(r.status, "green", r.detail.join("\n"));
});

test("M-T1.3: an ordinary github.com link is not what this rule is about", () => {
  const r = docsRule(docsFixture("plain-link",
    "The policy is at https://github.com/mihailinl/astra-registry/blob/main/docs/POLICY.md.\n\n" +
    "A hand-written advisory omits advisory_url.\n"));
  assert.equal(r.status, "green",
    `a link to a repository is not an advisory URL, and a rule red for one is a rule somebody deletes: ${r.detail.join("\n")}`);
});

test("M-T1.3: a document that has stopped mentioning the field is red, not vacuously green", () => {
  const r = docsRule(docsFixture("silent", "# Withdrawals\n\nOne JSON file per advisory.\n"));
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /MOD_13_DOCS_SILENT/);
});

test("M-T1.3: a document that has moved is red, because the rule would otherwise pass about nothing", () => {
  const r = docsRule(docsFixture("gone", null));
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /MOD_13_DOCS_ABSENT/);
});

// ── M-T5.7: the reserved-id mirror ──────────────────────────────────────────
//
// No network in any of these. The rule takes its reader as an argument
// precisely so that the four answers a forge can give — the file, a 404, an
// unreachable host, a HEAD that does not resolve — are all four testable, and
// so that a test suite never depends on github.com being up.

const SPEC_URL = "https://raw.githubusercontent.com/mihailinl/AstraPlugins/master/spec/reserved-ids.yaml";

const specYaml = ({ reserved, prefixes, pattern = "^[a-z0-9][a-z0-9-]{0,62}$" }) =>
  "# Mirrored from astra-registry@0000000:policy/reserved-ids.json (AP-7).\n" +
  "# first_party_repos and first_party_owners are deliberately NOT mirrored.\n" +
  "reserved:\n" + reserved.map((r) => `  - ${r}\n`).join("") +
  "reserved_prefixes:\n" + prefixes.map((p) => `  - "${p}"\n`).join("") +
  `id_pattern: "${pattern}"\n`;

const serves = (text) => async () => ({ kind: "spec", url: SPEC_URL, branch: "master", text });

const ours = loadPolicyReserved(REPO);

test("M-T5.7: the mirror compares the list this repository actually holds", () => {
  // The plan predicted 30 reserved ids; M-T1.1 landed 22 and 3 prefixes on
  // 2026-09-19, having released eight panel names (about, docs, feed, help,
  // new, rss, search, sitemap) on purpose. The floor is what was measured, and
  // WHICH names are reserved is tools/selftest/validation.mjs's assertion, not
  // a second list here.
  assert.ok(ours.reserved.length >= 20, `${ours.reserved.length} reserved id(s); there were 22 on 2026-09-19`);
  assert.ok(ours.prefixes.length >= 3, `${ours.prefixes.length} prefix(es); there were 3 on 2026-09-19`);
});

test("M-T5.7: an equal mirror is green", async () => {
  const r = await mirrorRule(REPO, { readSpec: serves(specYaml({ reserved: ours.reserved, prefixes: ours.prefixes })) });
  assert.equal(r.status, "green", r.detail.join("\n"));
});

test("M-T5.7: a name we reserve and the spec does not says re-mirror", async () => {
  // `moderation`, not `rss`: the plan's canary named `rss`, which ID-66
  // RELEASED on 2026-09-19. Written against `rss` this case would pass for the
  // wrong reason — the two lists agree about rss, because neither holds it.
  assert.ok(ours.reserved.includes("moderation"), "policy/reserved-ids.json no longer reserves `moderation`");
  const r = await mirrorRule(REPO, {
    readSpec: serves(specYaml({ reserved: ours.reserved.filter((n) => n !== "moderation"), prefixes: ours.prefixes })),
  });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /RESERVED_MIRROR_NAME_MISSING/);
  assert.match(r.detail.join("\n"), /re-mirror/);
  assert.match(r.detail.join("\n"), /moderation/);
});

test("M-T5.7: a name the spec reserves and we do not says re-mirror too", async () => {
  const r = await mirrorRule(REPO, {
    readSpec: serves(specYaml({ reserved: [...ours.reserved, "sitemap"], prefixes: ours.prefixes })),
  });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /RESERVED_MIRROR_NAME_EXTRA/);
});

test("M-T5.7: a prefix that drifts in either direction is the same alarm", async () => {
  const dropped = await mirrorRule(REPO, {
    readSpec: serves(specYaml({ reserved: ours.reserved, prefixes: ours.prefixes.filter((p) => p !== "astra-") })),
  });
  assert.match(codesOf(dropped), /RESERVED_MIRROR_PREFIX_MISSING/);

  const added = await mirrorRule(REPO, {
    readSpec: serves(specYaml({ reserved: ours.reserved, prefixes: [...ours.prefixes, "minice-"] })),
  });
  assert.match(codesOf(added), /RESERVED_MIRROR_PREFIX_EXTRA/);
});

test("M-T5.7: no reserved name or prefix ever reaches the verdict's `ids`", async () => {
  // `astra-` is not a plugin id, and `bot/lib/alert-verdict.mjs` checks every
  // entry of `ids` against the id grammar before the channel will carry the
  // message. A drift alarm that put one there would arrive as
  // E_VERDICT_UNSENDABLE — the alarm complaining about itself.
  const r = await mirrorRule(REPO, {
    readSpec: serves(specYaml({ reserved: ours.reserved, prefixes: [...ours.prefixes, "minice-"] })),
  });
  assert.deepEqual(r.ids, []);
  const lines = ruleNames().map((n) => (n === "reserved-id-mirror"
    ? { rule: n, ...r }
    : { rule: n, status: "green", codes: [], ids: [], hexes: [], detail: [] }));
  const composed = compose({ lines, bad: [] });
  assert.match(composed.verdict.codes.join(" "), /RESERVED_MIRROR_PREFIX_EXTRA/);
  assert.notDeepEqual(composed.verdict.codes, ["E_VERDICT_UNSENDABLE"],
    "the drift alarm arrived as a complaint about the alarm");
});

test("M-T5.7: before AP-7, an absent file was pending and named AP-7", async () => {
  // `ap7Landed: false` is passed explicitly now, because the constant it
  // overrides was flipped on 2026-09-20. The branch is still in the code and
  // still worth pinning: it is the shape of every rule this estate writes
  // against another repository's unlanded task, and getting it wrong in the
  // other direction — red from the day it lands until the day the other task
  // does — is what TRUST-45 calls the rule somebody switches off in between.
  const r = await mirrorRule(REPO, {
    ap7Landed: false,
    readSpec: async () => ({ kind: "absent", url: SPEC_URL, branch: "master" }),
  });
  assert.equal(r.status, "pending", "a rule red from today until R3 is a rule somebody switches off");
  assert.deepEqual(r.codes, []);
  assert.match(r.detail.join("\n"), /AP-7/);
  assert.match(r.detail.join("\n"), /spec\/reserved-ids\.yaml/);
});

test("M-T5.7: once AP-7 has landed, the same 404 is a deletion and is red", async () => {
  const r = await mirrorRule(REPO, {
    ap7Landed: true,
    readSpec: async () => ({ kind: "absent", url: SPEC_URL, branch: "master" }),
  });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /RESERVED_MIRROR_SPEC_DELETED/);
});

test("M-T5.7: AP7_LANDED is flipped, so an absent mirror is a deletion and not a wait", async () => {
  // This test used to assert the constant was `false` and that the rule nagged
  // about it on every green run, with the message "AP-7 has landed; this
  // assertion and the nag below both retire". AP-7 landed as AstraPlugins
  // `1b8849c` on 2026-09-20 and both retired, so what it pins now is the other
  // side: the constant is true, and the rule no longer nags.
  //
  // The design worth keeping is that the nag is what found it. A constant that
  // records a fact living in another repository's history cannot verify
  // itself, so instead it was written to say, on every successful run, that it
  // had not been checked — the only thing a hand-maintained fact can do for
  // itself, and strictly better than a comment nobody executes.
  assert.equal(AP7_LANDED, true, "AP-7 landed 2026-09-20; a 404 is now a deletion");
  const r = await mirrorRule(REPO, { readSpec: serves(specYaml({ reserved: ours.reserved, prefixes: ours.prefixes })) });
  assert.doesNotMatch(r.detail.join("\n"), /AP7_LANDED/, "the rule still nags about a constant that has been flipped");
});

test("M-T5.7: an unresolvable default branch and an unreachable file both name the URL", async () => {
  const noBranch = await mirrorRule(REPO, {
    readSpec: async () => ({ kind: "no-branch", remote: ASTRAPLUGINS_URL, why: "no symbolic HEAD" }),
  });
  assert.equal(noBranch.status, "red");
  assert.match(codesOf(noBranch), /RESERVED_MIRROR_BRANCH_UNRESOLVED/);
  assert.match(noBranch.detail.join("\n"), /AstraPlugins/,
    "the plan asks for the URL by name: an operator clearing this has to know which remote failed");

  const down = await mirrorRule(REPO, {
    readSpec: async () => ({ kind: "unreachable", url: SPEC_URL, branch: "master", why: "HTTP 502" }),
  });
  assert.equal(down.status, "red");
  assert.match(codesOf(down), /RESERVED_MIRROR_UNREACHABLE/);
  assert.match(down.detail.join("\n"), new RegExp(SPEC_URL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("M-T5.7: a spec whose shape is not the one AP-7 defines is one code, not forty", async () => {
  const renamed = await mirrorRule(REPO, { readSpec: serves("reserved_ids:\n  - astra\nreserved_prefixes:\n  - astra-\n") });
  assert.equal(renamed.status, "red");
  assert.match(codesOf(renamed), /RESERVED_MIRROR_UNPARSEABLE/);
  assert.doesNotMatch(codesOf(renamed), /NAME_MISSING/,
    "a renamed member must not read as every name in this repository having been dropped");

  const nested = await mirrorRule(REPO, { readSpec: serves("reserved:\n  ids:\n    - astra\n") });
  assert.match(codesOf(nested), /RESERVED_MIRROR_UNPARSEABLE/);
});

test("M-T5.7: the parser reads comments, quotes and flow lists, and refuses what it does not know", () => {
  const doc = parseReservedIdsYaml(
    "# a header\nreserved:  # the names\n  - astra\n  - 'account'\n  - \"api\"\n" +
    'reserved_prefixes: [astra-, "official-"]\nid_pattern: "^[a-z0-9][a-z0-9-]{0,62}$"\n',
  );
  assert.deepEqual(doc.reserved, ["astra", "account", "api"]);
  assert.deepEqual(doc.reserved_prefixes, ["astra-", "official-"]);
  assert.equal(doc.id_pattern, "^[a-z0-9][a-z0-9-]{0,62}$");
  assert.throws(() => parseReservedIdsYaml("reserved:\n\t- astra\n"), /tab/);
  assert.throws(() => parseReservedIdsYaml("- astra\n"), /under no key/);
});

test("M-T5.7: the remote this rule reads is the one the repository declares", () => {
  // Two copies of a URL is two copies that can disagree, and the day B-T1.4
  // moves the declaration out of ingest.yml into astra-plugins.pin this rule
  // must follow it rather than go red.
  const declared = astraPluginsRemote(REPO);
  assert.equal(declared.url, ASTRAPLUGINS_URL,
    `${declared.source} names ${declared.url} and the rule's fallback names ${ASTRAPLUGINS_URL}`);
  assert.notEqual(declared.source, "tools/coverage/reserved-id-mirror.mjs",
    "no file in this repository declares AstraPlugins' URL any more; the rule is running on its fallback");
  assert.equal(repoSlug(declared.url), "mihailinl/AstraPlugins");
});

// ── M-T2.1: no AstraPlugins example takes the staging listing id ────────────
//
// No network in any of these either, and for the same reason: the rule takes
// its reader as an argument so that every answer a forge can give — the
// examples, an unresolvable HEAD, a clone that failed — is testable without
// github.com being up. The one thing these cannot prove is that the real
// partial clone works, which is why `tools/coverage/examples-staging-id.mjs`
// is a step in the scheduled job and not only a module with tests.

const STAGING_ID = stagingListingId(
  JSON.parse(fs.readFileSync(path.join(REPO, "policy", "reserved-ids.json"), "utf8")),
);

/** The remote the repository declares, so these cases read the same URL the job will. */
const AP_REMOTE = astraPluginsRemote(REPO);

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const toml = ({ id, extra = "" }) =>
  `# an example\n[plugin]\nid = "${id}"\nname = "Example"\nversion = "0.1.0"\n${extra}\n[entry]\ncommand = "./bin/plugin"\n`;

/** An AstraPlugins whose examples are exactly these `{dir: id}` pairs. */
const servesExamples = (pairs, branch = "master") => async (url) => ({
  kind: "examples", url, branch,
  files: Object.entries(pairs).map(([dir, id]) => ({ path: `examples/${dir}/plugin.toml`, text: toml({ id }) })),
});

const ELEVEN = {
  "bad-apple": "bad-apple", companion: "companion-cat", "dice-roller": "dice-roller", doom: "doom",
  "echo-stt": "echo-stt", "json-tools": "json-tools", "mock-stt": "mock-stt",
  "telegram-client": "telegram-client", "text-utils": "text-utils", "tone-tts": "tone-tts",
  "web-chat": "web-chat",
};

test("M-T2.1: the id this rule is about is the one the registry reserves", () => {
  // The floor under every case below. Written first because all of them pass
  // vacuously against `null`: a rule looking for nothing finds nothing.
  assert.ok(STAGING_ID, "policy/reserved-ids.json reserves no staging_listing_id (M-T2.1)");
  assert.ok(STAGING_ID.startsWith("astra-"),
    `${STAGING_ID} does not carry a reserved prefix, so the repository it is published from needs no ` +
    "first-party exception and half of what this rule protects is not what the plan describes");
});

test("M-T2.1: the eleven examples AstraPlugins ships today are green", async () => {
  const r = await examplesRule(REPO, { readExamples: servesExamples(ELEVEN), remote: AP_REMOTE });
  assert.equal(r.status, "green", r.detail.join("\n"));
  assert.match(r.detail.join("\n"), /11 examples/);
});

test("M-T2.1: an example that declares the id is red and names the file", async () => {
  const r = await examplesRule(REPO, {
    readExamples: servesExamples({ ...ELEVEN, "withdrawal-demo": STAGING_ID }), remote: AP_REMOTE,
  });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /EXAMPLES_STAGING_ID_TAKEN/);
  assert.match(r.detail.join("\n"), /examples\/withdrawal-demo\/plugin\.toml/);
});

test("M-T2.1: an example DIRECTORY named for the id is the same alarm", async () => {
  // One rename from being the first case, and it is the shape somebody
  // reaches for first: make the directory, then decide what to call the
  // plugin inside it.
  const r = await examplesRule(REPO, {
    readExamples: servesExamples({ ...ELEVEN, [STAGING_ID]: "withdrawal-demo" }), remote: AP_REMOTE,
  });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /EXAMPLES_STAGING_ID_TAKEN/);
  assert.match(r.detail.join("\n"), new RegExp(`examples/${STAGING_ID}/`));
});

test("M-T2.1: an unresolvable default branch names the URL, and so does a clone that failed", async () => {
  // Seam 16's fixture, both halves. An operator clearing this has to know
  // which remote failed before they can do anything about it.
  const noBranch = await examplesRule(REPO, {
    readExamples: async (url) => ({ kind: "no-branch", url, why: "no symbolic HEAD" }),
    remote: AP_REMOTE,
  });
  assert.equal(noBranch.status, "red");
  assert.match(codesOf(noBranch), /EXAMPLES_BRANCH_UNRESOLVED/);
  assert.match(noBranch.detail.join("\n"), new RegExp(escapeRe(AP_REMOTE.url)));

  const down = await examplesRule(REPO, {
    readExamples: async (url) => ({ kind: "unreachable", url, branch: "master", why: "fatal: unable to access" }),
    remote: AP_REMOTE,
  });
  assert.equal(down.status, "red");
  assert.match(codesOf(down), /EXAMPLES_UNREACHABLE/);
  assert.match(down.detail.join("\n"), new RegExp(escapeRe(AP_REMOTE.url)));
});

test("M-T2.1: a walk that found no example is red, not green about nothing", async () => {
  const r = await examplesRule(REPO, { readExamples: servesExamples({}), remote: AP_REMOTE });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /EXAMPLES_NONE_FOUND/);
  assert.doesNotMatch(codesOf(r), /STAGING_ID_TAKEN/,
    "an empty walk must not also report the thing it could not look for");
});

test("M-T2.1: a manifest whose `[plugin] id` cannot be read is reported, not passed over", async () => {
  const r = await examplesRule(REPO, {
    readExamples: async (url) => ({
      kind: "examples", url, branch: "master",
      files: [
        { path: "examples/ok/plugin.toml", text: toml({ id: "ok" }) },
        // `id` under another table is not this file's id, and a rule that read
        // it as one would be answering a question nobody asked.
        { path: "examples/odd/plugin.toml", text: "[entry]\nid = \"odd\"\ncommand = \"./bin/plugin\"\n" },
      ],
    }),
    remote: AP_REMOTE,
  });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /EXAMPLES_MANIFEST_UNREAD/);
  assert.match(r.detail.join("\n"), /examples\/odd\/plugin\.toml/);
});

test("M-T2.1: with the reservation taken back out, the rule says so rather than going quiet", async () => {
  const dir = fixture("no-staging-id").write("policy/reserved-ids.json", { reserved: [], reserved_prefixes: [] }).dir;
  const r = await examplesRule(dir, { readExamples: servesExamples(ELEVEN), remote: AP_REMOTE });
  assert.equal(r.status, "red");
  assert.match(codesOf(r), /EXAMPLES_STAGING_ID_UNRESERVED/);
});

test("M-T2.1: the reserved id never reaches the verdict's `ids`, and the rule declares its network", async () => {
  // `astra-withdrawal-canary` is a well-formed plugin id, so this would not
  // have been caught by the grammar the way `astra-` was in M-T5.7. The reason
  // is the other one: `ids` is the plugins a finding is ABOUT, and a reader
  // scanning an alarm for which of THEIR listings is in trouble must not find
  // our own canary's name in that column.
  const r = await examplesRule(REPO, {
    readExamples: servesExamples({ ...ELEVEN, "withdrawal-demo": STAGING_ID }), remote: AP_REMOTE,
  });
  assert.equal(r.status, "red");
  assert.deepEqual(r.ids, []);
  assert.match(r.detail.join("\n"), new RegExp(escapeRe(STAGING_ID)), "and it is in `detail`, where a human reads it");

  assert.equal(RULES.find((x) => x.name === "examples-staging-id")?.network, true,
    "the examples rule is registered without `network: true`, and it is the second rule here that leaves the runner");
});

test("M-T2.1: the path grammar and the id reader, at their edges", () => {
  assert.ok(EXAMPLE_RE.test("examples/doom/plugin.toml"));
  assert.ok(!EXAMPLE_RE.test("examples/doom/src/plugin.toml"), "a nested manifest is not an example's manifest");
  assert.ok(!EXAMPLE_RE.test("staging/doom/plugin.toml"), "AP-12's staging/ is not examples/");

  assert.equal(pluginId('[plugin]\nid = "doom"\n'), "doom");
  assert.equal(pluginId("[plugin]\nid = 'doom'  # quoted the other way\n"), "doom");
  assert.equal(pluginId('[entry]\nid = "doom"\n'), null, "another table's id is not the plugin's");
  assert.equal(pluginId('# id = "doom"\n[plugin]\nname = "Doom"\n'), null, "a commented-out id declares nothing");
  assert.equal(pluginId('[plugin]\nname = "Doom"\nid = "doom"\n'), "doom", "order inside the table is free");
});

// ── the register, and the rule that never ran ───────────────────────────────

const finding = (rule, status = "green", extra = {}) =>
  ({ rule, status, codes: [], ids: [], hexes: [], detail: [], ...extra });

test("a declared rule that wrote no finding is red, whatever its step's exit code said", () => {
  const all = ruleNames().map((n) => finding(n));
  assert.equal(compose({ lines: all, bad: [] }).status, "green");

  const missing = all.slice(1);
  const r = compose({ lines: missing, bad: [] });
  assert.equal(r.status, "red");
  assert.match(r.verdict.codes.join(" "), /E_RULE_DID_NOT_REPORT/);
  assert.match(r.summary.join("\n"), new RegExp(`MISSING\\s+${ruleNames()[0]}`));
});

test("a rule that reported and is not in the register is red", () => {
  const lines = [...ruleNames().map((n) => finding(n)), finding("a-rule-nobody-declared")];
  const r = compose({ lines, bad: [] });
  assert.equal(r.status, "red");
  assert.match(r.verdict.codes.join(" "), /E_RULE_UNDECLARED/);
});

test("one rule reporting twice is red, because one of the two came from somewhere", () => {
  const lines = [...ruleNames().map((n) => finding(n)), finding(ruleNames()[0])];
  const r = compose({ lines, bad: [] });
  assert.equal(r.status, "red");
  assert.match(r.verdict.codes.join(" "), /E_RULE_REPORTED_TWICE/);
});

test("a `pending` rule never turns the canary red, and its sentence is still on the run page", () => {
  const lines = ruleNames().map((n) => finding(n, n === "keepalive-age" ? "pending" : "green"));
  const r = compose({ lines, bad: [] });
  assert.equal(r.status, "green");
  assert.match(r.summary.join("\n"), /pending\s+keepalive-age/);
});

test("the verdict this job sends is one `bot/lib/alert-verdict.mjs` will carry", () => {
  const lines = ruleNames().map((n) => finding(n, "red", {
    codes: ["MOD_COMMIT_UNCOVERED"], ids: ["astra-chess"], hexes: ["a".repeat(40)],
  }));
  const r = compose({ lines, bad: [] });
  assert.equal(r.verdict.check, "coverage-canary");
  assert.deepEqual(r.verdict.codes, ["MOD_COMMIT_UNCOVERED"], "one code repeated is one thing wrong");
  assert.deepEqual(r.verdict.ids, ["astra-chess"]);
});

test("a verdict the channel would refuse becomes a red verdict saying so, never silence", () => {
  const lines = ruleNames().map((n) => finding(n, "red", { codes: ["not a fixed code"] }));
  const r = compose({ lines, bad: [] });
  assert.equal(r.status, "red");
  assert.deepEqual(r.verdict.codes, ["E_VERDICT_UNSENDABLE"]);
});

test("every register entry names a script that exists and a task that owns it", () => {
  assert.ok(RULES.length >= 5, `${RULES.length} rules registered; there were 5 on 2026-09-19`);
  for (const rule of RULES) {
    assert.ok(fs.existsSync(path.join(REPO, rule.script)), `${rule.name} names ${rule.script}, which is not in the tree`);
    assert.match(rule.owner, /T\d|RC-/, `${rule.name} names no owning task`);
    assert.ok(rule.what && rule.what.length > 20, `${rule.name} does not say what is true when it is green`);
    assert.equal(typeof rule.network, "boolean", `${rule.name} does not say whether it needs the network`);
  }
});

// ── the workflow ────────────────────────────────────────────────────────────
//
// These three live here rather than in `bot/tests/workflows.test.mjs`. That
// file is shared — RC-R1-0 landed in it an hour before this task, M-T3.5 adds
// a case to it at R3 — and its generic `alerts` tests already cover this
// workflow's alert job for free. Three assertions about one workflow do not
// need to be written into the one file every lane in the batch is editing.

const WORKFLOW = path.join(REPO, ".github", "workflows", "moderation-coverage.yml");
const workflowSrc = () => fs.readFileSync(WORKFLOW, "utf8");

test("the canary is scheduled, because a GITHUB_TOKEN push starts no run", () => {
  const src = workflowSrc();
  assert.match(src, /^\s+schedule:$/m, "no schedule: the commits this canary judges are made by the automatic token");
  const cron = /^\s+- cron: '(.+)'$/m.exec(src)?.[1];
  assert.equal(cron, "*/15 * * * *");

  // The cron and the receiver's bound are one decision in two files: the
  // bound is computed from `interval_seconds` (`boundMinutes`, a day for a
  // poster GitHub schedules), so an interval that is not this cron's is a
  // bound nobody chose.
  const check = CHECKS.find((c) => c.name === "coverage-canary");
  assert.ok(check, "bot/lib/alert-checks.mjs lists no `coverage-canary` check for this workflow to post to");
  assert.equal(check.interval_seconds, 900,
    "the receiver check's interval and this workflow's cron disagree; one of the two has to move");
  assert.match(check.source, /moderation-coverage\.yml/);
});

test("the canary does not cancel itself in progress", () => {
  const src = workflowSrc();
  const group = /concurrency:\n\s+group: moderation-coverage\n(?:\s+#.*\n)*\s+cancel-in-progress: (\w+)/.exec(src);
  assert.ok(group, "the concurrency block is not where this test reads it; it has been reshaped");
  assert.equal(group[1], "false",
    "cancel-in-progress would throw away the run that was about to report an uncovered commit, and a lost " +
    "finding looks exactly like a delayed one");
});

test("the check job fetches all of history, and every rule step is `if: always()`", () => {
  const src = workflowSrc();
  assert.match(src, /fetch-depth: 0/, "without it both walks see a shallow history and report green about what they missed");

  // Every `node tools/…` step in `check` runs unconditionally, so one red rule
  // does not hide the rules after it.
  const steps = [...src.matchAll(/- name: [^\n]*\n(\s+)(?:# [^\n]*\n\s+)*if: (always\(\)[^\n]*)\n\s+run: (node [^\n]+)/g)];
  const runners = [...src.matchAll(/run: node (tools\/[^\s]+\.mjs)/g)].map((m) => m[1]);
  for (const rule of RULES) {
    assert.ok(runners.includes(rule.script),
      `${rule.name} is in the register and no step in ${path.basename(WORKFLOW)} runs ${rule.script}`);
  }
  assert.ok(steps.length >= RULES.length,
    `${steps.length} step(s) carry \`if: always()\` and ${RULES.length} rules are registered`);
});

test("nothing in a signing or publishing workflow runs these rules (MOD-46)", () => {
  const dir = path.join(REPO, ".github", "workflows");
  const offenders = [];
  for (const name of fs.readdirSync(dir).filter((n) => n.endsWith(".yml"))) {
    if (name === "moderation-coverage.yml") continue;
    const src = fs.readFileSync(path.join(dir, name), "utf8");
    for (const rule of RULES) {
      if (src.includes(rule.script)) offenders.push(`${name} runs ${rule.script}`);
    }
  }
  assert.equal(offenders.join("\n"), "",
    "a moderation or privacy check inside a signing or publishing job is a check that can delay a takedown");
});

// ── keepalive-age: two questions, and a clock for each ─────────────────────
//
// Gap 68's shape under another spelling (ops register, entry 93). The rule
// dated the file with `git log -1 --format=%aI -- state/keepalive.json`, which
// simplifies through a merge TREESAME to its branch parent and dates the BRANCH
// commit, at the time it was first written. This estate merges every pull
// request with a merge commit, and `state/README.md` invites a hand keepalive.

const keepaliveDoc = (month, by = "hand") => ({ $comment: "fixture", month, at: `${month}-15T00:00:00Z`, by, run: null });

/** `git` with both clocks set: `when` is one instant, or [author, committer]. */
function dated(f, when, ...args) {
  const [author, committer] = Array.isArray(when) ? when : [when, when];
  execFileSync("git", ["-C", f.dir, ...args], {
    stdio: "pipe", env: { ...process.env, GIT_AUTHOR_DATE: author, GIT_COMMITTER_DATE: committer },
  });
  return f.head();
}
const keepaliveAt = (f, month, when, by) => {
  f.write(KEEPALIVE, keepaliveDoc(month, by)).git("add", "-A");
  return dated(f, when, "commit", "-q", "-m", `the keepalive for ${month}`);
};
const touchAt = (f, rel, when) => {
  f.write(rel, `${when}\n`).git("add", "-A");
  return dated(f, when, "commit", "-q", "-m", `${rel} at ${when}`);
};
const mergeAt = (f, ref, when) => dated(f, when, "merge", "-q", "--no-ff", "-m", `merge ${ref}`, ref);

test("keepalive-age: the age is main's, from the first-parent commit that brought the file, at its committer time", () => {
  // Measured before the repair, `now` 2026-09-28: each of the first two read
  // 38.6 days and ROLL_62_KEEPALIVE_STALE about a file main had acquired 7.5
  // days before. A false red, and on the one rule that watches every
  // schedule here that is how the rule gets switched off.
  const NOW = new Date("2026-09-28T00:00:00Z");

  // An agent's keepalive, written on a branch and merged with a merge commit.
  // Needs `--first-parent`: without it the walk dates the branch commit.
  const merged = fixture("keepalive-merged");
  keepaliveAt(merged, "2026-07", "2026-07-01T00:00:00Z");
  merged.branch("hand");
  keepaliveAt(merged, "2026-08", "2026-08-20T10:00:00Z");
  merged.checkout("main");
  touchAt(merged, "README.md", "2026-09-01T00:00:00Z");
  const merge = mergeAt(merged, "hand", "2026-09-20T12:00:00Z");
  const m = keepaliveRule(merged.dir, { now: NOW });
  assert.equal(m.status, "green", `a keepalive main acquired at ${merge.slice(0, 8)} 7.5 days ago read as stale: ${m.detail.join(" / ")}`);
  assert.match(m.detail[0], /last changed 2026-09-20T12:00:00Z \(7\.5 day/);

  // A keepalive rebased onto main: one parent, authored 08-20, committed 09-20.
  // Needs the COMMITTER time: the author time is when it was first written.
  const rebased = fixture("keepalive-rebased");
  keepaliveAt(rebased, "2026-07", "2026-07-01T00:00:00Z");
  keepaliveAt(rebased, "2026-08", ["2026-08-20T10:00:00Z", "2026-09-20T12:00:00Z"]);
  const r = keepaliveRule(rebased.dir, { now: NOW });
  assert.equal(r.status, "green", `a keepalive committed to main 7.5 days ago read by its author date: ${r.detail.join(" / ")}`);

  // And a first-parent walk is not "any recent merge": a keepalive main
  // acquired 58 days ago is stale however recently main merged something else.
  const stale = fixture("keepalive-stale");
  keepaliveAt(stale, "2026-08", "2026-08-01T00:00:00Z");
  stale.branch("other");
  touchAt(stale, "README.md", "2026-09-19T00:00:00Z");
  stale.checkout("main");
  touchAt(stale, "NOTES.md", "2026-09-19T06:00:00Z");
  mergeAt(stale, "other", "2026-09-20T12:00:00Z");
  assert.deepEqual(keepaliveRule(stale.dir, { now: NOW }).codes, ["ROLL_62_KEEPALIVE_STALE"],
    "a keepalive 58 days old was dated by an unrelated merge");
});

test("keepalive-age: the month is the writer's, read from the commit that wrote the file", () => {
  // The workflow and `state/README.md` ask whoever writes the file to put in
  // it the month of the commit they are making, in their own clock. Dated at
  // a merge in a later month, a correct keepalive would read as MONTH_STALE —
  // which says somebody automated the commit and not the file, and sends a
  // reader after the wrong thing.
  const writer = fixture("keepalive-writer");
  keepaliveAt(writer, "2026-08", "2026-08-02T00:00:00Z");
  writer.branch("hand");
  keepaliveAt(writer, "2026-09", "2026-09-01T10:00:00Z");
  writer.checkout("main");
  touchAt(writer, "README.md", "2026-09-05T00:00:00Z");
  mergeAt(writer, "hand", "2026-10-02T12:00:00Z");
  const w = keepaliveRule(writer.dir, { now: new Date("2026-10-05T00:00:00Z") });
  assert.deepEqual(w.codes, [], `a September keepalive merged on 2 October was judged by the merge's month: ${w.detail.join(" / ")}`);
  assert.match(w.detail[0], /in a commit written 2026-09-01T10:00:00Z/, "the transcript does not say when the file was written");

  // The check still fires on what it is for: a commit that did not rewrite the month.
  const unchanged = fixture("keepalive-month-unchanged");
  keepaliveAt(unchanged, "2026-08", "2026-08-02T00:00:00Z");
  keepaliveAt(unchanged, "2026-08", "2026-09-20T10:00:00Z", "workflow");
  assert.deepEqual(keepaliveRule(unchanged.dir, { now: new Date("2026-09-28T00:00:00Z") }).codes,
    ["ROLL_62_KEEPALIVE_MONTH_STALE"], "a September commit over a file still saying August was accepted");
});

// ── the owner's act ─────────────────────────────────────────────────────────

test("the live run is still owed, and cannot stop being printed without being done", () => {
  // The one part of M-T1.5 an agent may not perform: it needs an owner-approved
  // fixture repository. `outstandingActs` derives the notice from the ABSENCE
  // of the record, so the day the record lands the line retires itself — and
  // until then there is no way to stop printing it except by writing a record
  // that says it happened.
  const acts = outstandingActs(REPO);
  const live = acts.find((a) => a.id === "live-once");
  const recorded = fs.existsSync(path.join(REPO, "state", "coverage-live-run.json"));
  assert.equal(!!live, !recorded,
    recorded
      ? "state/coverage-live-run.json exists and the pending notice is still printed"
      : "the live run has not been recorded and nothing is printing that it is owed");
  if (live) {
    assert.match(live.act, /OWNER APPROVAL/);
    assert.match(live.act, /fixture repository/);
  }
});

// ── repo-settings: the settings GitHub serves, against the committed file ───
//
// Ops `dev/couplings.md` gap 22. The comparison's own clauses are watched red
// with fixtures in `tools/selftest/settings.mjs`; these hold the RULE — the
// committed expectation against this tree on every pull request, the network
// failures that must never read green, the token that is only for the rate
// limit — and they are here rather than in the selftest because they read
// `policy/settings-expected.json`, which no bot run reads and which therefore
// stays outside TRUST-31's set.

const SETTINGS_FILE = path.join(REPO, "policy", "settings-expected.json");
const settingsDoc = () => JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
const checkoutSlug = (doc) => Object.keys(doc.repositories).find((s) => doc.repositories[s].tree === "checkout");

/** This tree's workflows through the rule's own reader, concatenated as the rule concatenates them. */
function thisTree(files = localWorkflows(REPO)) {
  const tree = { jobs: [], problems: [] };
  for (const f of files) {
    const r = workflowJobs(f.text, f.path);
    tree.jobs.push(...r.jobs);
    tree.problems.push(...r.problems);
  }
  return tree;
}

/**
 * GitHub's answers, played back from an expectation: the inverse of the
 * rule's normaliser, so that a clean run against it is the file agreeing with
 * itself and every red below is one value somebody changed.
 */
function servesSettings(doc, { fail = () => null } = {}) {
  const dbp = (k) => (k === "all" ? null : k === "protected"
    ? { protected_branches: true, custom_branch_policies: false }
    : { protected_branches: false, custom_branch_policies: true });
  const routes = new Map();
  for (const [slug, r] of Object.entries(doc.repositories)) {
    routes.set(`repos/${slug}`, { default_branch: r.default_branch });
    const envs = Object.entries(r.environments);
    routes.set(`repos/${slug}/environments?per_page=100`, {
      total_count: envs.length,
      environments: envs.map(([name, e]) => ({
        name, deployment_branch_policy: dbp(e.deployment_branch_policy),
        protection_rules: e.protection_rules.map((type, i) => ({ id: i + 1, type })), can_admins_bypass: e.can_admins_bypass,
      })),
    });
    for (const [name, e] of envs) {
      routes.set(`repos/${slug}/environments/${encodeURIComponent(name)}/deployment-branch-policies?per_page=100`,
        { total_count: e.branch_policies.length, branch_policies: e.branch_policies.map((p, i) => ({ id: i + 1, ...p })) });
    }
    const sets = Object.entries(r.rulesets);
    routes.set(`repos/${slug}/rulesets?per_page=100`, sets.map(([name], i) => ({ id: 100 + i, name })));
    sets.forEach(([name, s], i) => routes.set(`repos/${slug}/rulesets/${100 + i}`, {
      id: 100 + i, name, target: s.target, enforcement: s.enforcement,
      conditions: { ref_name: { include: s.include, exclude: s.exclude } }, rules: s.rules.map((type) => ({ type })),
    }));
    routes.set(`repos/${slug}/rules/branches/${encodeURIComponent(r.default_branch)}?per_page=100`, r.rules_on_default_branch.map((type) => ({ type })));
  }
  return async (route) => {
    const why = fail(route);
    if (why) return { ok: false, why: `${route}: ${why}` };
    if (!routes.has(route)) return { ok: false, why: `${route}: HTTP 404 — Not Found` };
    return { ok: true, data: structuredClone(routes.get(route)), auth: "the fixture" };
  };
}

/** A remote tree that names each of a repository's expected environments from one job. */
const servesRemoteTree = (doc) => async () => {
  const [, r] = Object.entries(doc.repositories).find(([, x]) => x.tree === "remote");
  const jobs = Object.keys(r.environments).map((name, i) =>
    `  job${i}:\n    runs-on: ubuntu-24.04\n    environment: ${name}\n    steps:\n      - run: echo\n`).join("");
  return { kind: "files", branch: r.default_branch, files: [{ path: ".github/workflows/release.yml", text: `name: release\non: push\njobs:\n${jobs}` }] };
};

const settingsRule = (overrides = {}) => settingsRun(REPO, {
  get: servesSettings(settingsDoc()), readRemote: servesRemoteTree(settingsDoc()), env: {}, ...overrides,
});

test("repo-settings: the committed expectation is well formed, and every environment this tree names is in it", () => {
  const doc = settingsDoc();
  assert.deepEqual(expectationProblems(doc), [], "policy/settings-expected.json is malformed");
  const slug = checkoutSlug(doc);
  assert.equal(slug, "mihailinl/astra-registry", "the checkout this suite runs in is not the repository the file reads it as");
  const tree = thisTree();
  const named = tree.jobs.filter((j) => j.environment !== null);
  assert.ok(named.length >= 15, `${named.length} jobs name an environment and there were 20 on 2026-09-22; the reader stopped reading`);
  const { findings } = compareTree(slug, doc.repositories[slug], tree);
  assert.deepEqual(findings.map((f) => `${f.code} ${f.detail}`), [],
    "a workflow names an environment policy/settings-expected.json does not hold live and pinned, or pending and held — " +
    "or the file lists one no workflow names. Fix the workflow, or change the file in a commit that says why");
});

test("repo-settings: deleting a committed `if: false` before its environment exists is red, naming the job and the environment", () => {
  // Committed material, not a fixture: the jobs this tree holds today, each
  // with its hold deleted in memory. A guard that has never seen its case is
  // not proven by passing.
  const doc = settingsDoc();
  const slug = checkoutSlug(doc);
  const expected = doc.repositories[slug];
  const files = localWorkflows(REPO);
  const held = thisTree(files).jobs.filter((j) => j.held && j.environment in (expected.pending_environments ?? {}));
  if (held.length === 0) {
    assert.deepEqual(Object.keys(expected.pending_environments ?? {}), [],
      "no held job names a pending environment, and the file still lists one");
    return; // nothing is pending any more; tools/selftest/settings.mjs still holds the rule with its fixture
  }
  for (const j of held) {
    const copy = files.map((f) => {
      if (f.path !== j.file) return f;
      const lines = f.text.split("\n");
      const at = lines.findIndex((l, i) => i > j.line - 1 && /^\s+if:\s*false\s*$/.test(l));
      assert.ok(at > j.line - 1 && at < j.environmentLine, `${j.file}: the hold of job ${j.job} is not between its name and its environment`);
      const text = [...lines.slice(0, at), ...lines.slice(at + 1)].join("\n");
      assert.notEqual(text, f.text, "the edit changed nothing");
      return { path: f.path, text };
    });
    const codes = compareTree(slug, expected, thisTree(copy)).findings;
    const hit = codes.filter((f) => f.code === "SETTINGS_TREE_ENV_NOT_LIVE");
    assert.equal(hit.length, 1, `with ${j.file}'s job ${j.job} unheld: ${codes.map((f) => f.code).join(", ") || "nothing"}`);
    assert.match(hit[0].detail, new RegExp(`job \`${j.job}\``));
    assert.match(hit[0].detail, new RegExp(`\`${j.environment}\``));
  }
});

test("repo-settings: the file against GitHub answering exactly what it says is green, and names what it cannot ask", async () => {
  const r = await settingsRule();
  assert.equal(r.status, "green", r.detail.join("\n"));
  const text = r.detail.join("\n");
  assert.match(text, /NOT ASKED \(by design\): which secrets exist where/);
  assert.match(text, /NOT ASKED \(by design\): ruleset bypass actors/);
  assert.match(text, /`bot-state` pending creation \(B-T5\.0\)/);
  assert.deepEqual(r.ids, [], "an environment name is not a plugin id");
  assert.equal(RULES.find((x) => x.name === "repo-settings")?.network, true, "the settings rule leaves the runner and does not say so");
});

test("repo-settings: one wrong value in the file is red, naming it", async () => {
  const doc = settingsDoc();
  const slug = checkoutSlug(doc);
  const wrong = structuredClone(doc);
  wrong.repositories[slug].environments.publish.branch_policies = [{ name: "release", type: "branch" }];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-settings-"));
  tmpRoots.push(dir);
  const file = path.join(dir, "settings-expected.json");
  fs.writeFileSync(file, `${JSON.stringify(wrong, null, 2)}\n`);
  const r = await settingsRule({ expectation: file });
  assert.equal(r.status, "red");
  assert.deepEqual(r.codes, ["SETTINGS_ENV_DRIFT"]);
  assert.match(r.detail.join("\n"), /environment `publish` branch_policies/);
});

test("repo-settings: a read that fails is NOT ASKED by route and red, never green, and the rest is still compared", async () => {
  const doc = settingsDoc();
  const slug = checkoutSlug(doc);
  const r = await settingsRule({
    get: servesSettings(doc, { fail: (route) => (route.startsWith(`repos/${slug}/rulesets`) ? "HTTP 403, rate limit exhausted" : null) }),
  });
  assert.equal(r.status, "red");
  assert.deepEqual(r.codes, ["SETTINGS_NOT_ASKED"]);
  assert.match(r.detail.join("\n"), new RegExp(`NOT ASKED \\(this run\\): ${escapeRe(slug)}'s rulesets: repos/${escapeRe(slug)}/rulesets`));

  // One environment's branch policies unread: that is NOT ASKED, and it is not
  // an environment gone missing — the half-read member is not compared at all.
  const half = await settingsRule({
    get: servesSettings(doc, { fail: (route) => (route.includes("/environments/publish/") ? "HTTP 502" : null) }),
  });
  assert.deepEqual(half.codes, ["SETTINGS_NOT_ASKED"], half.detail.join("\n"));
  assert.match(half.detail.join("\n"), /environment `publish`'s branch policies: .*HTTP 502/);

  const down = await settingsRule({ readRemote: async () => ({ kind: "unreachable", why: "fatal: unable to access" }) });
  assert.equal(down.status, "red");
  assert.deepEqual(down.codes, ["SETTINGS_NOT_ASKED"]);
  assert.match(down.detail.join("\n"), /NOT ASKED \(this run\): mihailinl\/AstraPlugins's workflow tree: fatal/);

  const nothing = await settingsRule({ get: async (route) => ({ ok: false, why: `${route}: fetch failed` }) });
  assert.equal(nothing.status, "red", "a run in which GitHub answered nothing at all was green");
  assert.deepEqual(nothing.codes, ["SETTINGS_NOT_ASKED"]);
});

test("repo-settings: an unreadable or malformed file, and a checkout it does not describe, are red", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-settings-"));
  tmpRoots.push(dir);
  const missing = await settingsRule({ expectation: path.join(dir, "absent.json") });
  assert.deepEqual(missing.codes, ["SETTINGS_EXPECTATION_UNREADABLE"]);
  const bad = path.join(dir, "bad.json");
  fs.writeFileSync(bad, JSON.stringify({ schema: "astra.registry.settings-expected/1", repositories: {} }));
  assert.deepEqual((await settingsRule({ expectation: bad })).codes, ["SETTINGS_EXPECTATION_MALFORMED"]);
  const fork = await settingsRule({ env: { GITHUB_REPOSITORY: "someone/astra-registry" } });
  assert.ok(fork.codes.includes("SETTINGS_EXPECTATION_REPO"), fork.detail.join("\n"));
});

test("repo-settings: the token is sent, a token GitHub refuses is dropped for that read, and an exhausted limit is not retried", async () => {
  const seen = [];
  const reply = (status, body, remaining = "59") => ({
    status, headers: { get: (h) => (h === "x-ratelimit-remaining" ? remaining : null) }, text: async () => JSON.stringify(body),
  });
  const refused = githubGetter({
    token: "fixture-token", attempts: 1,
    fetchImpl: async (url, init) => {
      seen.push(init.headers.authorization ?? "none");
      return init.headers.authorization ? reply(403, { message: "Resource not accessible by integration" }) : reply(200, { ok: 1 });
    },
  });
  const a = await refused("repos/x/y/environments");
  assert.equal(a.ok, true);
  assert.equal(a.auth, "no credential (the workflow token was refused)");
  assert.deepEqual(seen, ["Bearer fixture-token", "none"]);

  let calls = 0;
  const exhausted = githubGetter({
    token: null, attempts: 3,
    fetchImpl: async () => { calls += 1; return reply(403, { message: "API rate limit exceeded" }, "0"); },
  });
  const b = await exhausted("repos/x/y/rulesets");
  assert.equal(b.ok, false);
  assert.match(b.why, /HTTP 403, rate limit exhausted/);
  assert.equal(calls, 1, "a rate limit at zero was asked again, which two seconds cannot refill");
});

// ── ROLL-7's R0 file, held to the same expectation (contract 0.36.0) ───────
//
// Ops `dev/server-registry-contract-pending.md` item 26. Contract 0.36.0 makes
// ROLL-7's file — the pins TRUST-10's acknowledgement records, and TRUST-44
// compares GitHub with hourly from outside this repository — carry each pinned
// environment's deployment-branch policy kind and names, as data. GitHub answers
// the names with no credential. TRUST-44 does not read them today, and ops
// pending item 28 proposes that it should. `policy/settings-expected.json`
// already records the same facts, reviewed, and the `repo-settings` canary
// holds it to GitHub every 15 minutes. Two copies of one fact with nothing
// comparing them is the shape this file exists to refuse, so the choice is
// one source and one check:
//
//   - the EXPECTATION is the source. It exists, it is compared with GitHub, and
//     it is read by no bot run, so it can change in a commit that says why.
//     ROLL-7's file is a dated record that the service's pins are acknowledged
//     from, and it does not exist yet: RC-R0-4 writes `log/rollout/R0-settings.json`
//     at R0's exit, its schema still G3's (`MBE-PENDING`), and a lane that was
//     asked to write it on 2026-09-20 correctly wrote nothing because the
//     baseline was already stale. A canary reading a dated record would be
//     comparing GitHub with a history;
//   - ROLL-7's rows are DERIVED from it: each environment's
//     `deployment_branch_policy` and `branch_policies` in the expectation's
//     own shape, copied from the checkout repository's entry at the commit the
//     file is written in — and this test fails, in both directions, when they
//     disagree: a row that differs from the expectation, a row for an
//     environment the expectation does not hold live, and a live environment
//     with no row, which is an environment ROLL-7 would not pin.
//
// The file is not on this tree, so the predicate is proven on a file BUILT
// from the committed expectation and broken one value at a time; the committed
// file, once RC-R0-4 lands it, is compared with no edit here.
const ROLL7_FILE = "log/rollout/R0-settings.json";

/** Every way ROLL-7's environment rows and the expectation's live environments disagree, as sentences. */
function roll7Disagreements(roll7, expected) {
  const out = [];
  const rows = roll7?.environments;
  if (!rows || typeof rows !== "object" || Array.isArray(rows)) {
    return [`${ROLL7_FILE} has no \`environments\` object, so it pins no environment at all`];
  }
  const policySet = (ps) => (Array.isArray(ps) ? ps.map((p) => `${p?.type}:${p?.name}`).sort() : null);
  for (const [name, row] of Object.entries(rows)) {
    const live = expected.environments?.[name];
    if (!live) {
      out.push(expected.pending_environments?.[name]
        ? `${ROLL7_FILE} pins \`${name}\`, which policy/settings-expected.json holds as pending creation, not live`
        : `${ROLL7_FILE} pins \`${name}\`, which policy/settings-expected.json does not hold at all`);
      continue;
    }
    if (row?.deployment_branch_policy !== live.deployment_branch_policy) {
      out.push(`${ROLL7_FILE} pins \`${name}\`'s policy kind as ${JSON.stringify(row?.deployment_branch_policy)} and ` +
        `policy/settings-expected.json as ${JSON.stringify(live.deployment_branch_policy)}`);
    }
    const a = policySet(row?.branch_policies);
    const b = policySet(live.branch_policies);
    if (a === null) {
      out.push(`${ROLL7_FILE} pins \`${name}\` with no \`branch_policies\` list, so it records no names for it`);
    } else if (JSON.stringify(a) !== JSON.stringify(b)) {
      out.push(`${ROLL7_FILE} pins \`${name}\`'s branch policies as ${JSON.stringify(a)} and ` +
        `policy/settings-expected.json as ${JSON.stringify(b)}`);
    }
  }
  for (const name of Object.keys(expected.environments ?? {})) {
    if (!Object.hasOwn(rows, name)) {
      out.push(`policy/settings-expected.json holds \`${name}\` live and ${ROLL7_FILE} pins no row for it, so ` +
        `the acknowledgement would not pin it and TRUST-44 would not read its flags`);
    }
  }
  return out;
}

test("repo-settings: ROLL-7's R0 file pins each environment's branch policies as the expectation does, built from it and broken, and committed when it is", () => {
  const doc = settingsDoc();
  const expected = doc.repositories[checkoutSlug(doc)];
  const live = Object.keys(expected.environments);
  assert.ok(live.length >= 4, `the expectation holds ${live.length} live environment(s) and held 5 on 2026-09-23; the read stopped reading`);
  const built = {
    environments: Object.fromEntries(Object.entries(expected.environments).map(([name, e]) => [name, {
      deployment_branch_policy: e.deployment_branch_policy,
      branch_policies: structuredClone(e.branch_policies),
      trust44_monitors: true,
    }])),
  };
  assert.deepEqual(roll7Disagreements(built, expected), [], "a file derived from the expectation disagrees with it");

  const [first, second] = live;
  const pending = Object.keys(expected.pending_environments ?? {})[0];
  const breaks = [
    ["a policy renamed", (f) => { f.environments[first].branch_policies[0].name += "-renamed"; }, [first, "branch policies"]],
    ["a policy's type changed", (f) => { const p = f.environments[first].branch_policies[0]; p.type = p.type === "tag" ? "branch" : "tag"; }, [first, "branch policies"]],
    ["a policy added", (f) => { f.environments[second].branch_policies.push({ name: "release/*", type: "branch" }); }, [second, "release/*"]],
    ["a policy dropped", (f) => { f.environments[second].branch_policies = []; }, [second, "branch policies"]],
    ["the list missing", (f) => { delete f.environments[second].branch_policies; }, [second, "no `branch_policies`"]],
    ["the kind changed", (f) => { f.environments[first].deployment_branch_policy = "all"; }, [first, "policy kind"]],
    ["a live environment with no row", (f) => { delete f.environments[second]; }, [second, "pins no row"]],
    ["a row for an environment nobody has", (f) => { f.environments["not-an-environment"] = structuredClone(f.environments[first]); }, ["not-an-environment", "does not hold at all"]],
    ...(pending ? [["a row for an environment still pending creation", (f) => { f.environments[pending] = structuredClone(f.environments[first]); }, [pending, "pending creation"]]] : []),
    ["no environments at all", (f) => { delete f.environments; }, ["no `environments` object"]],
  ];
  for (const [how, edit, words] of breaks) {
    const f = structuredClone(built);
    edit(f);
    assert.notDeepEqual(f, built, `the break "${how}" changed nothing`);
    const said = roll7Disagreements(f, expected).join("\n");
    assert.ok(said, `${how}: ${ROLL7_FILE} and the expectation disagree and the comparison was silent`);
    for (const w of words) assert.ok(said.includes(w), `${how}: red, but not naming ${JSON.stringify(w)}: ${said}`);
  }

  // The committed file, once RC-R0-4 lands it. Until then this says so, and
  // the predicate above is what is proven.
  const at = path.join(REPO, ROLL7_FILE);
  if (fs.existsSync(at)) {
    assert.deepEqual(roll7Disagreements(JSON.parse(fs.readFileSync(at, "utf8")), expected), [],
      `${ROLL7_FILE} and policy/settings-expected.json disagree about a pinned environment's branch policies. The ` +
      "expectation is the source (it is compared with GitHub every 15 minutes); re-derive the file's rows from it, " +
      "as a dated amendment, and the service's acknowledgement with them");
  } else {
    console.log(`# ${ROLL7_FILE} is not committed yet (RC-R0-4 writes it at R0's exit); the comparison was proven on a ` +
      `file built from policy/settings-expected.json and ${breaks.length} breaks of it, and arms on that commit`);
  }
});

// ── TRUST-44's reservation, against the read it makes (contract 0.36.0) ─────
//
// TRUST-44 reserves 6 of the plugins service's 60 unauthenticated requests an
// hour for its read of the settings ROLL-7 pins, and contract 0.36.0's Why
// gives that read as calls: `/rulesets`, one `/rulesets/{id}` per ruleset,
// `/rules/branches/main`, `/environments` and `/branches/main` — 4 + R, 5
// today. The 6 lives in the contract and the rulesets live in
// `policy/settings-expected.json`, and an owner who adds a ruleset changes the
// second without anyone opening the first. At 7 calls the service's hourly
// read would overrun its share, and its mint lookups would start answering
// `rate_limited` for a reason nothing records. So the two are compared here.
//
// The read that also takes each pinned environment's policy names would be
// 4 + R + E, 11 at R5. Ops pending item 28 proposes it, with a reservation of
// 12, as the contract's first MAJOR, for the owner. This test counts that read
// too, and prints it, but holds only the read TRUST-44 makes.
const TRUST44_RESERVATION = 6;
const trust44Calls = (expected) => 4 + Object.keys(expected.rulesets ?? {}).length;
const trust44CallsWithNames = (expected) => trust44Calls(expected) +
  Object.keys(expected.environments ?? {}).length + Object.keys(expected.pending_environments ?? {}).length;

/** Why TRUST-44's read of an expectation overruns its reservation, or null when it fits. */
function trust44Overrun(expected) {
  const calls = trust44Calls(expected);
  if (calls <= TRUST44_RESERVATION) return null;
  return `TRUST-44's read of astra-registry is 4 + R = ${calls} calls for the rulesets ` +
    `policy/settings-expected.json holds, and the contract reserves ${TRUST44_RESERVATION} for it (TRUST-44; ID-12). A ` +
    "ruleset past the reservation waits for a contract version that raises it, published before the ruleset is " +
    `created. (The read ops pending item 28 proposes, with each pinned environment's policy names, would be ` +
    `4 + R + E = ${trust44CallsWithNames(expected)} within 12.)`;
}

test("repo-settings: TRUST-44's read of what ROLL-7 pins fits the 6 calls the contract reserves for it", () => {
  const doc = settingsDoc();
  const expected = doc.repositories[checkoutSlug(doc)];
  const calls = trust44Calls(expected);
  assert.ok(calls >= 5, `TRUST-44's read counts ${calls} calls from the expectation and counted 5 on 2026-09-23; the count stopped reading`);
  assert.equal(trust44Overrun(expected), null);
  // Proven on the committed expectation grown by one ruleset, which still
  // fits, and by two, which do not: an owner's next settings acts.
  const grown = (n) => {
    const g = structuredClone(expected);
    const model = Object.values(g.rulesets)[0];
    for (let i = 0; i < n; i++) g.rulesets[`extra-${i}`] = structuredClone(model);
    return g;
  };
  assert.equal(trust44Overrun(grown(1)), null, "one ruleset more still fits the reservation, and was refused");
  const over = trust44Overrun(grown(2));
  assert.ok(over && over.includes("= 7 calls") && over.includes("reserves 6") && over.includes("pending item 28"),
    `two rulesets more count ${trust44Calls(grown(2))} calls and the check said ${JSON.stringify(over)}`);
  console.log(`# TRUST-44's read: 4 + ${Object.keys(expected.rulesets ?? {}).length} ruleset(s) = ${calls} of ` +
    `${TRUST44_RESERVATION}; with the policy names (ops pending item 28), 4 + R + ` +
    `${Object.keys(expected.environments).length} live and ${Object.keys(expected.pending_environments ?? {}).length} ` +
    `pending environment(s) = ${trust44CallsWithNames(expected)} of the 12 it proposes`);
});
