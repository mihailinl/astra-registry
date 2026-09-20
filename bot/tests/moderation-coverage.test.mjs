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
  assert.ok(RULES.length >= 3, `${RULES.length} rules registered; there were 3 on 2026-09-19`);
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

  // The cron and the receiver's bound are one decision in two files. The
  // receiver pages after 3 × the interval or 90 minutes, whichever is longer;
  // a cron slower than `interval_seconds` pages every night.
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
