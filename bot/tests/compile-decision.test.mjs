// The decision compiler, against trees it has to judge.
//
// Registry plan M-T3.1's canary, plus the one clause of it that is NOT about
// this compiler's return value: BOT-34's second Check clause, which counts
// author-action records against the versions a commit yanks and lives in
// `tools/validate.mjs`. The plan says in as many words why that one is here —
// "without this one, a short-counted yank is caught by nothing": B-T2.2's
// canary asserts what the WRITER emits, and B-T3.4's guards the publish job,
// which a yank does not pass through.
//
// ── REAL GIT REPOSITORIES, NOT A STUBBED TREE ───────────────────────────────
//
// Three of the rules under test are statements about HISTORY, not about a
// working tree: MOD-13's next advisory id is "one more than the highest ever
// ADDED" (`git log --diff-filter=A`), MOD-19's identity entries cover "every
// distinct `source.repo` in the HISTORY of `plugins/<id>/plugin.json`", and the
// add-then-delete case exists precisely because a tree reading gets the id
// wrong. A fixture that stubbed git would be a fixture of the stub, which is
// the reason `bot/tests/takedown-bound.test.mjs` and
// `bot/tests/listing-state.test.mjs` build repositories too.
//
// ── THE TOKEN FILE IN A FIXTURE CARRIES `fixed_reasons`, AND SO DOES `main` ─
//
// Contract 2.3.0 published the two strings (ops.15), and every fixture below
// writes a token file with its own. One test reads the real repository's, and
// asserts that a token file WITHOUT them still makes an `A_YANK` THROW rather
// than be refused `reason_refused`: a refusal is final (BOT-81), and settling
// every author yank as refused reads from the panel exactly like a service
// that sent something wrong.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fixtureEnv } from "../../tools/lib/git-env.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import * as compiler from "../lib/compile-decision.mjs";
import {
  ACCOUNT_LEVEL_CATEGORIES,
  ADVISORY_KINDS,
  ADVISORY_URL_BASE,
  ENTRY_ALLOWLIST,
  MIG25_UNBOUND_EXCEPTION,
  REFUSALS,
  compileDecision,
  compileIdentityReset,
  fixedReason,
  newBatch,
  nextAdvisoryId,
  recordInBatch,
  tokenAdvisoryBase,
} from "../lib/compile-decision.mjs";
import { decisionId, recordPath, RECORD_SCHEMA, writeDecisionRecord } from "../lib/decisions.mjs";
import { HOLD_KINDS, holdKindFor, isTakedown } from "../lib/holds.mjs";
import { checkEntry } from "../lib/moderation.mjs";
import { headListing, withdrawnBy } from "../lib/takedown-bound.mjs";
import { KINDS } from "../../tools/lib/revocations.mjs";
import { REPO_ROOT, loadRecords, loadSchemas, loadSources } from "../../tools/lib/sources.mjs";
import { checkAuthorActionRecords, checkRecords } from "../../tools/validate.mjs";

// ── fixtures ────────────────────────────────────────────────────────────────

const tmpRoots = [];
process.on("exit", () => {
  for (const dir of tmpRoots) fs.rmSync(dir, { recursive: true, force: true });
});

const sh = (args, cwd) => execFileSync("git", args, { cwd, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", env: fixtureEnv(cwd) });

function writeAll(root, files) {
  for (const [rel, body] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, typeof body === "string" ? body : `${JSON.stringify(body, null, 2)}\n`);
  }
}

/** A repository with one commit per entry of `commits`, in order. */
function repo(commits) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "compile-decision-"));
  tmpRoots.push(root);
  sh(["init", "-q", "-b", "main"], root);
  sh(["config", "user.email", "fixture@example.invalid"], root);
  sh(["config", "user.name", "fixture"], root);
  sh(["config", "commit.gpgsign", "false"], root);
  for (const [i, commit] of commits.entries()) {
    for (const rel of commit.delete ?? []) fs.rmSync(path.join(root, rel), { force: true });
    writeAll(root, commit.files ?? {});
    sh(["add", "-A"], root);
    sh(["commit", "-q", "-m", commit.message ?? `fixture ${i}`], root);
  }
  return root;
}

/** MOD-41-clean, 10 to 300 code points, no host, no `@`. Two of them. */
const FIXED_YANK = "The account bound to this listing asked the registry to yank the versions named here.";
const FIXED_REMOVAL = "The account bound to this listing asked the registry to remove it from the catalogue.";
const MODERATOR_REASON = "The published bundle shipped a build that crashes the host on start, so it is withdrawn.";

const tokenFile = ({ fixed = true } = {}) => ({
  contract_version: "0.20.0",
  entries: [{ id: "page:MOD-13-advisory-base", kind: "page", url: ADVISORY_URL_BASE }],
  fixed_reasons: fixed ? { A_YANK: FIXED_YANK, A_REMOVAL_REQUEST: FIXED_REMOVAL } : null,
});

const plugin = (id, { repo: src = "acme/widgets", unlisted } = {}) => ({
  schema: "astra.registry.plugin/1",
  id,
  name: id,
  summary: `the ${id} plugin`,
  license: "MIT",
  source: { kind: "github", repo: src },
  added_at: "2026-01-01T00:00:00Z",
  ...(unlisted ? { unlisted: true } : {}),
});

const version = (id, v, { repo: rel = "acme/widgets", yanked, artifacts } = {}) => ({
  schema: "astra.registry.version/1",
  id,
  version: v,
  published_at: "2026-01-01T00:00:00Z",
  release: { kind: "github_release", repo: rel, tag: `${id}-v${v}` },
  artifacts: artifacts ?? { noarch: { url: `https://example.invalid/${id}-${v}.astraplugin`, filename: `${id}-${v}.astraplugin` } },
  ...(yanked ? { yanked: true } : {}),
});

const identity = (id, { repo: r = "acme/widgets" } = {}) => ({
  schema: "astra.registry.identity/1",
  plugin_id: id,
  repository_id: "912345678",
  repository_owner_id: "4711",
  repo: r,
  token_hash: "a".repeat(64),
});

const SDI = "0192f3a4-5b6c-7d8e-9f01-234567890abc";
const SDI2 = "0192f3a4-5b6c-7d8e-9f01-234567890abd";

/** A listing with three versions, bound, listed, and a token file with the strings. */
function estate({ versions = ["1.0.0", "1.1.0", "1.2.0"], bound = true, extra = {}, id = "widgets" } = {}) {
  const files = {
    "schema/contract-tokens-v1.json": tokenFile(),
    [`plugins/${id}/plugin.json`]: plugin(id),
  };
  for (const v of versions) files[`plugins/${id}/versions/${v}.json`] = version(id, v);
  if (bound) files[`plugins/${id}/identity.json`] = identity(id);
  return repo([{ files: { ...files, ...extra } }]);
}

const entry = (over) => ({
  service_decision_id: SDI,
  plugin_id: "widgets",
  decided_at: "2026-09-20T12:00:00Z",
  reason: MODERATOR_REASON,
  ...over,
});

/** The three methods `checkAuthorActionRecords` uses, and a way to read them back. */
class Report {
  constructor() { this.items = []; }
  error(where, message, hint) { this.items.push({ level: "error", where, message, hint }); }
  warn(where, message, hint) { this.items.push({ level: "warn", where, message, hint }); }
  note(where, message, hint) { this.items.push({ level: "note", where, message, hint }); }
  get errors() { return this.items.filter((i) => i.level === "error"); }
  get notes() { return this.items.filter((i) => i.level === "note"); }
  text() { return this.items.map((i) => `${i.level} ${i.where}: ${i.message}`).join("\n"); }
}

// ── the vocabularies, compared rather than copied ───────────────────────────

test("REFUSALS is exactly §0.8's seven service-decision refusal codes", () => {
  assert.deepEqual([...REFUSALS], [
    "target_not_in_registry", "kind_refused", "relist_under_advisory",
    "relist_unbound", "relist_contained", "reason_refused", "target_changed",
  ], "§0.8 names seven and BOT-82's acceptance of an unknown well-formed code is the service's safety net, " +
     "not a licence to invent an eighth here");
});

test("ADVISORY_KINDS is a subset of the daemon's kinds, and excludes the two git cannot derive", () => {
  for (const kind of ADVISORY_KINDS) {
    assert.ok(Object.hasOwn(KINDS, kind), `${kind} is not a kind tools/lib/revocations.mjs accepts (AV-7)`);
  }
  assert.ok(!ADVISORY_KINDS.includes("publisher_key"), "a signer key id lives on a user's machine, not in git");
  assert.ok(!ADVISORY_KINDS.includes("binary"), "the sha256 of a resolved entry.command is not recorded here");
});

test("the compiled advisory base equals the token file's (MOD-13; M-T3.9)", () => {
  assert.equal(ADVISORY_URL_BASE, tokenAdvisoryBase({ root: REPO_ROOT }),
    "the daemon prints this URL in a signed notice; a base that drifts from the page the service serves is a " +
    "signed link to a 404 on the one document a user reads when something has already gone wrong");
});

test("BOT-80's allowlist gives an `A_*` entry no moderator and no declared interest (n4)", () => {
  for (const member of ["moderator", "declared_interest"]) {
    assert.ok(ENTRY_ALLOWLIST.moderator.includes(member), `an M_* entry carries ${member}`);
    assert.ok(!ENTRY_ALLOWLIST.author.includes(member),
      `an A_* entry carrying ${member} would put a moderator handle on an author's act and into the public log ` +
      "(DEC-14; PRIV-2)");
  }
});

test("an entry carrying a member BOT-80 does not name compiles normally, and the member reaches nothing", () => {
  // SCOPE-3's read side says a reader IGNORES an unknown member, and §0.6 makes
  // a new optional member a MINOR — so minice-be may add one at any time and
  // this side must do nothing. DEC-7's write side is this allowlist: the member
  // must reach no composed object, and a hold entry is the second way into git.
  const root = estate({ bound: false });
  const unknown = { ...entry({ code: "A_YANK", category: "author_request", versions: ["1.0.0"], reason: FIXED_YANK }), withheld_since: "2026-09-20T11:00:00Z" };

  const r = compileDecision(unknown, { root });
  assert.equal(r.outcome, "held", "the compile is unaffected by the member it does not know");
  assert.ok(!Object.hasOwn(r.decision, "withheld_since"),
    "the hold entry is written in one run and applied in another, so a member that rode into it would reach git " +
    "a run later than the one that ignored it");
  assert.equal(JSON.stringify(r).includes("withheld_since"), false);
});

// ── BOT-37's Decided-At, on every branch rather than on the one that had it ──

// Both plans say a `Decided-At:` sits beside each `Service-Decision:`. Until
// 2026-09-21 ONE of the four compile branches supplied it: `decidedAt` is
// computed once, before the dispatch, and the switch handed it to the yank and
// to nothing else. Three kinds of decision reached git with a
// `Service-Decision:` and no time beside it.
//
// Nothing was red. The suite had a fixture per code and asserted edits, log
// entries and records — never the trailers — so the defect and its repair were
// equally invisible, and adding the missing lines without this test would have
// left the next branch free to omit it again.
//
// THE CODE LIST IS DERIVED, NOT COPIED. The compiler's refusal prints every key
// `KNOWN_CODES` holds, and this reads the list out of that message, so a code
// added to the module is covered here without anybody editing this file. (The
// table itself is exported since contract 3.0.0, for the moderation run's
// canary that holds it equal to the work schema's code enum; reading it from
// the message here also keeps the message honest.) The floor is what stops
// the loop passing by reaching nothing.
test("every compiled decision carries a Decided-At beside its Service-Decision", () => {
  const root = estate();

  const listed = (() => {
    try {
      compileDecision(entry({ code: "M_NOT_A_CODE" }), { root });
    } catch (e) {
      const m = /\(([^)]*)\)/.exec(String(e.message));
      if (m) return m[1].split(",").map((s) => s.trim()).filter(Boolean);
    }
    return [];
  })();
  assert.ok(listed.length >= 4,
    `the module's refusal named ${listed.length} code(s) and it knows at least four; this test derives its ` +
    "subject from that message, so a refusal that stops printing the list would leave this loop with nothing " +
    "to iterate and it would pass by reaching nothing");

  const shapes = {
    M_YANK: { category: "broken", versions: ["1.1.0"], moderator: "knice" },
    M_DELIST: { category: "broken", moderator: "knice" },
    M_DEPRECATE: { category: "broken", moderator: "knice", advisory: { kind: "id" } },
    M_REVOKE: { category: "broken", moderator: "knice", advisory: { kind: "id" } },
    M_APPEAL: { category: "broken", moderator: "knice", outcome: "stands" },
    // Contract 3.0.0 (MOD-56): a review carries `review_passed` and nothing
    // else, so the default shape below would be refused and the branch never
    // reached.
    M_REVIEW: { category: "review_passed", versions: ["1.1.0"], moderator: "knice" },
  };

  const compiled = [];
  const missing = [];
  for (const code of listed) {
    let r;
    try {
      r = compileDecision(entry({ code, ...(shapes[code] ?? { category: "broken", moderator: "knice" }) }), { root });
    } catch {
      continue; // this code needs a shape this test does not build; the floor below covers the loss
    }
    if (!r || r.outcome !== "compiled" || !r.trailers) continue;
    compiled.push(code);
    if (r.trailers["Decided-At"] !== "2026-09-20T12:00:00Z") {
      missing.push(`${code}: ${JSON.stringify(r.trailers["Decided-At"])}`);
    }
  }

  assert.ok(compiled.length >= 2,
    `this test compiled ${compiled.length} of ${listed.length} known code(s) (${compiled.join(", ") || "none"}); ` +
    "a loop that reaches one branch asserts nothing about the others, which is the defect it exists to catch");
  assert.deepEqual(missing, [],
    "a compiled decision carries a `Service-Decision:` with no `Decided-At:` beside it. Both plans say every " +
    "one has both, and `decidedAt` is in scope for every branch — it is computed once before the dispatch, so " +
    "omitting it is a branch that did not pass an argument it already had");
});

// ── a fixture per code and outcome ──────────────────────────────────────────

test("M_YANK yanks the versions it names and writes one log entry", () => {
  const root = estate();
  const r = compileDecision(entry({ code: "M_YANK", category: "broken", versions: ["1.1.0"], moderator: "knice" }), { root });
  assert.equal(r.outcome, "compiled");
  assert.deepEqual(r.edits, [{ op: "set", file: "plugins/widgets/versions/1.1.0.json", member: "yanked", value: true }]);
  assert.equal(r.log.length, 1);
  assert.equal(r.log[0].doc.action, "yank");
  assert.equal(r.log[0].file, "bot/moderation/2026-09-20-widgets-yank.json");
  assert.equal(r.records.length, 0, "BOT-34 writes an author-action record for an `A_YANK` and for nothing else");
});

test("a bound A_YANK yanks, logs `author_request`, and writes one record per version", () => {
  const root = estate();
  const r = compileDecision(entry({
    code: "A_YANK", category: "author_request", versions: ["1.0.0", "1.2.0"], reason: FIXED_YANK,
  }), { root });

  assert.equal(r.outcome, "compiled");
  assert.equal(r.edits.length, 2);
  assert.equal(r.log[0].doc.category, "author_request");
  assert.equal(r.log[0].doc.reason, FIXED_YANK);
  assert.equal(r.records.length, 2, "DEC-7's `version` is a single member, so a yank of two versions is two records");
  assert.deepEqual(r.records.map((x) => x.record.version), ["1.0.0", "1.2.0"]);
  assert.equal(new Set(r.records.map((x) => decisionId(x.key))).size, 2, "BOT-35's tuple carries `version` so the ids differ");
  for (const { record } of r.records) {
    assert.equal(record.actor, "author");
    assert.equal(record.trigger, "moderation");
    assert.equal(record.state, "yanked");
    assert.deepEqual(record.reasons, ["A_YANK"]);
    assert.ok(!Object.hasOwn(record, "submission_id"), "detector B row 2 matches an author-action record BY its absence");
  }
  assert.equal(r.trailers["Service-Decision"], SDI,
    "a yank committed without it reads to the service as a record with no service outcome (BOT-37; n5)");
});

test("an unbound A_YANK is held `unbound_yank`, compiles nothing, and alerts", () => {
  const root = estate({ bound: false });
  const r = compileDecision(entry({
    code: "A_YANK", category: "author_request", versions: ["1.0.0"], reason: FIXED_YANK,
  }), { root });

  assert.equal(r.outcome, "held");
  assert.equal(r.held_for, "unbound_yank");
  assert.ok(HOLD_KINDS.includes(r.held_for), "the kind must be one schema/hold-v1.json can write");
  assert.deepEqual(r.edits, []);
  assert.deepEqual(r.records, []);
  assert.equal(r.alerts.length, 1, "MOD-8 alerts on every hold entered");
});

test("M_DELIST unlists, and a bound A_REMOVAL_REQUEST does the same with `author_request`", () => {
  const root = estate();
  const m = compileDecision(entry({ code: "M_DELIST", category: "naming", moderator: "knice" }), { root });
  assert.deepEqual(m.edits, [{ op: "set", file: "plugins/widgets/plugin.json", member: "unlisted", value: true }]);
  assert.equal(m.log[0].doc.action, "delist");

  const a = compileDecision(entry({
    code: "A_REMOVAL_REQUEST", category: "author_request", reason: FIXED_REMOVAL,
  }), { root });
  assert.equal(a.outcome, "compiled");
  assert.equal(a.log[0].doc.category, "author_request");
  assert.equal(a.records.length, 0, "a removal request is a delist; only a yank owes DEC-7's author-action record");
});

test("an unbound A_REMOVAL_REQUEST is held `unbound_removal` (FLOW-28; MOD-9)", () => {
  const root = estate({ bound: false });
  const r = compileDecision(entry({ code: "A_REMOVAL_REQUEST", category: "author_request", reason: FIXED_REMOVAL }), { root });
  assert.equal(r.held_for, "unbound_removal");
});

test("M_DEPRECATE compiles an advisory with action `warn` and its log entry in one return", () => {
  const root = estate();
  const r = compileDecision(entry({
    code: "M_DEPRECATE", category: "broken", severity: "moderate", versions: ["1.0.0"], moderator: "knice",
  }), { root });

  assert.equal(r.outcome, "compiled");
  assert.equal(r.advisories.length, 1);
  assert.equal(r.advisories[0].action, "warn", "§7.2: a deprecate IS an advisory with action `warn`");
  assert.equal(r.advisories[0].id, "ASTRA-2026-0001");
  assert.equal(r.advisories[0].advisory_url, `${ADVISORY_URL_BASE}ASTRA-2026-0001`);
  assert.equal(r.log[0].doc.action, "deprecate");
  assert.equal(r.log[0].doc.advisory, "ASTRA-2026-0001");
  assert.equal(r.alerts.length, 1, "MOD-8: a signed `warn` reaches every installed copy, so it is alerted too");
});

test("M_REVOKE with block_install applies under the bound and is held above it", () => {
  const root = estate();
  const e = entry({
    code: "M_REVOKE", category: "malicious", severity: "critical", action: "block_install",
    versions: ["1.2.0"], moderator: "knice",
  });
  const under = compileDecision(e, { root, overBound: false });
  assert.equal(under.outcome, "compiled");
  assert.equal(under.advisories[0].action, "block_install");

  const over = compileDecision(e, { root, overBound: true });
  assert.equal(over.outcome, "held");
  assert.equal(over.held_for, "bound",
    "OPEN-OWNER-45, kept on 2026-09-17: above the bound every takedown waits, `block_install` included");
});

test("M_REVOKE with disable is held for a second person whatever the bound says", () => {
  const root = estate();
  const r = compileDecision(entry({
    code: "M_REVOKE", category: "malicious", severity: "critical", action: "disable",
    versions: ["1.2.0"], moderator: "knice",
  }), { root, overBound: false });
  assert.equal(r.held_for, "disable_confirmation");
});

test("M_APPEAL logs an appeal; `reversed` adds FLOW-18's Recheck and names the record it cannot write", () => {
  const root = estate();
  const stands = compileDecision(entry({
    code: "M_APPEAL", appeal_of: SDI2, outcome: "stands", moderator: "knice",
  }), { root });
  assert.equal(stands.log[0].doc.action, "appeal");
  assert.ok(!Object.hasOwn(stands.log[0].doc, "category"),
    "§7.2: one category per M_* decision EXCEPT M_APPEAL, and checkEntry refuses one");
  assert.equal(stands.recheck, null);

  const reversed = compileDecision(entry({
    code: "M_APPEAL", appeal_of: SDI2, outcome: "reversed", moderator: "knice",
  }), { root });
  assert.equal(reversed.recheck?.appeal_of, SDI2);
  assert.ok(reversed.record_owed?.blocked_by.includes("BOT-35"),
    "MOD-33's decision record for an appealed refusal has no key domain, and inventing a fifth is a contract " +
    "amendment and not a choice this file makes");
});

test("an appeal of an M_REJECT is logged even though its listing does not exist", () => {
  // The submission was REFUSED, so `plugins/<id>/` never came into being. An
  // appeal is about a decision; refusing it `target_not_in_registry` would mean
  // an appeal of a rejection could never be logged, while MOD-33 requires the
  // entry for every decided appeal and FLOW-18 turns a reversed one into the
  // estate's only Recheck.
  const root = estate();
  const r = compileDecision(entry({
    code: "M_APPEAL", plugin_id: "never-listed", appeal_of: SDI2, outcome: "reversed", moderator: "knice",
  }), { root });
  assert.equal(r.outcome, "compiled", `an appeal of a rejection was refused ${r.refusal}`);
  assert.equal(r.log[0].doc.plugin, "never-listed");
  assert.equal(r.recheck?.plugin_id, "never-listed");
});

test("M_RELIST with nothing against it is held `reversal`, not compiled", () => {
  const root = estate({ extra: { "plugins/widgets/plugin.json": plugin("widgets", { unlisted: true }) } });
  const r = compileDecision(entry({ code: "M_RELIST", category: "error", moderator: "knice" }), { root });
  assert.equal(r.outcome, "held");
  assert.equal(r.held_for, "reversal");
});

test("M_BINDING_REVOKE compiles to nothing at all (§7.2)", () => {
  const root = estate();
  const r = compileDecision(entry({ code: "M_BINDING_REVOKE", category: "impersonation", moderator: "knice" }), { root });
  assert.equal(r.outcome, "compiled");
  assert.deepEqual([r.edits, r.log, r.advisories, r.records], [[], [], [], []]);
});

// ROLL-59 (e), the bot's half of the walk M-T5.5 owns (registry plan §2.7):
// `M_YANK`, then a `reversed` appeal, "as a new record". MOD-34 is the rule —
// a reversed appeal is a NEW artefact and the originals are left unchanged —
// and B.3 is why it has to be: a version's `yanked` is never undone, so what
// follows a reversed yank is a new version, never an un-yank. The walk runs in
// the order the live one will, with the yank's effects committed before the
// appeal is compiled, so "a path the appeal writes already exists" is asked of
// the tree the appeal actually meets. Watched failing: with `compileAppeal`
// made to answer a reversed appeal by setting the version's `yanked` back to
// false, the first assertion is red.
test("ROLL-59 (e): an M_YANK, then its appeal reversed, is two artefacts, and the yank stands (MOD-34)", () => {
  const root = estate();
  const yank = compileDecision(entry({ code: "M_YANK", category: "broken", versions: ["1.1.0"], moderator: "knice" }), { root });
  assert.equal(yank.outcome, "compiled");
  // The yank's commit, as M-T3.4's `commit` job would make it.
  writeAll(root, {
    "plugins/widgets/versions/1.1.0.json": version("widgets", "1.1.0", { yanked: true }),
    [yank.log[0].file]: yank.log[0].doc,
  });
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", `M_YANK widgets 1.1.0\n\nService-Decision: ${SDI}`], root);

  const appeal = compileDecision(entry({
    code: "M_APPEAL", service_decision_id: SDI2, appeal_of: SDI, outcome: "reversed", moderator: "knice",
  }), { root });
  assert.equal(appeal.outcome, "compiled", `a reversed appeal of a yank was refused ${appeal.refusal}`);
  assert.deepEqual(appeal.edits, [],
    "a reversed appeal edited the tree; B.3 never undoes `yanked`, and MOD-34 makes the reversal a new artefact");
  assert.equal(appeal.log.length, 1);
  assert.notEqual(appeal.log[0].file, yank.log[0].file, "the appeal's log entry is the yank's file, so the original is overwritten");
  assert.equal(appeal.log[0].doc.action, "appeal");
  assert.equal(appeal.log[0].doc.appeal_of, SDI, "the appeal does not name the decision it reverses");
  assert.equal(appeal.log[0].doc.outcome, "reversed");
  const writes = [...appeal.log, ...appeal.advisories, ...appeal.records].map((w) => w.file).filter(Boolean);
  for (const file of writes) {
    assert.ok(!fs.existsSync(path.join(root, file)),
      `${file} already exists on the tree the appeal meets, so the appeal rewrites an original (MOD-34)`);
  }
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, "plugins/widgets/versions/1.1.0.json"), "utf8")).yanked, true);
  assert.equal(appeal.trailers["Service-Decision"], SDI2, "the appeal's commit names its own decision, not the yank's");
});

// ── the seven refusals ──────────────────────────────────────────────────────

test("target_not_in_registry: an id with no `plugins/` directory (TRUST-26)", () => {
  const root = estate();
  const r = compileDecision(entry({ code: "M_DELIST", plugin_id: "nowhere", category: "naming", moderator: "knice" }), { root });
  assert.equal(r.refusal, "target_not_in_registry");
});

test("kind_refused: a deprecate with no severity, and a revoke with no action (MOD-4; MOD-10)", () => {
  const root = estate();
  const noSeverity = compileDecision(entry({ code: "M_DEPRECATE", category: "broken", versions: ["1.0.0"], moderator: "knice" }), { root });
  assert.equal(noSeverity.refusal, "kind_refused");

  const noAction = compileDecision(entry({
    code: "M_REVOKE", category: "malicious", severity: "high", versions: ["1.0.0"], moderator: "knice",
  }), { root });
  assert.equal(noAction.refusal, "kind_refused");
});

test("kind_refused: a category §7.2's table does not allow with the code", () => {
  const root = estate();
  const r = compileDecision(entry({
    code: "M_REVOKE", category: "broken", severity: "high", action: "block_install",
    versions: ["1.0.0"], moderator: "knice",
  }), { root });
  assert.equal(r.refusal, "kind_refused",
    "a refusal is a final result the moderator can act on; letting it reach the log's own check instead would " +
    "throw and take every other decision in the batch down with it");
});

test("kind_refused: an `A_*` entry carrying a moderator (n4)", () => {
  const root = estate();
  const r = compileDecision(entry({
    code: "A_YANK", category: "author_request", versions: ["1.0.0"], reason: FIXED_YANK, moderator: "knice",
  }), { root });
  assert.equal(r.refusal, "kind_refused");
});

test("reason_refused: an `A_YANK` carrying anything but the token file's fixed string (M-7)", () => {
  const root = estate();
  const good = compileDecision(entry({
    code: "A_YANK", category: "author_request", versions: ["1.0.0"], reason: FIXED_YANK,
  }), { root });
  assert.equal(good.outcome, "compiled");

  // The mutation: copy the entry's own reason through instead of comparing it
  // to the file. An author-typed reason then reaches the public log.
  const typed = compileDecision(entry({
    code: "A_YANK", category: "author_request", versions: ["1.0.0"],
    reason: "I am withdrawing these builds because they were published by mistake this morning.",
  }), { root });
  assert.equal(typed.refusal, "reason_refused");
});

test("reason_refused: a moderator's reason MOD-41 refuses", () => {
  const root = estate();
  const r = compileDecision(entry({
    code: "M_DELIST", category: "naming", moderator: "knice",
    reason: "Delisted; see https://example.invalid/why for the details of this decision.",
  }), { root });
  assert.equal(r.refusal, "reason_refused");
});

test("target_changed: an A_YANK naming an already-yanked version, and nothing changes", () => {
  const root = estate({ versions: ["1.0.0", "1.1.0"] });
  writeAll(root, { "plugins/widgets/versions/1.0.0.json": version("widgets", "1.0.0", { yanked: true }) });
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", "1.0.0 yanked"], root);

  const r = compileDecision(entry({
    code: "A_YANK", category: "author_request", versions: ["1.0.0", "1.1.0"], reason: FIXED_YANK,
  }), { root });
  assert.equal(r.refusal, "target_changed");
  assert.deepEqual(r.edits, [], "a partial apply would yank a version under a decision the service believes was about others");
  assert.deepEqual(r.records, []);
});

test("M_YANK takes the versions that can move, and refuses only when none can", () => {
  const root = estate({ versions: ["1.0.0", "1.1.0"] });
  writeAll(root, { "plugins/widgets/versions/1.0.0.json": version("widgets", "1.0.0", { yanked: true }) });
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", "1.0.0 yanked"], root);

  const partial = compileDecision(entry({
    code: "M_YANK", category: "broken", versions: ["1.0.0", "1.1.0"], moderator: "knice",
  }), { root });
  assert.equal(partial.outcome, "compiled",
    "§0.8 gives the service no pre-filter for a moderator's yank, so refusing the lot would stall a takedown");
  assert.deepEqual(partial.edits.map((e) => e.file), ["plugins/widgets/versions/1.1.0.json"]);

  const none = compileDecision(entry({
    code: "M_YANK", category: "broken", versions: ["1.0.0"], moderator: "knice",
  }), { root });
  assert.equal(none.refusal, "target_changed");
});

test("relist_under_advisory: the latest listed version is covered by a signed advisory (MOD-10)", () => {
  const root = estate({
    extra: {
      "plugins/widgets/plugin.json": plugin("widgets", { unlisted: true }),
      "tools/revocations/ASTRA-2026-0001.json": {
        id: "ASTRA-2026-0001",
        published: "2026-09-01",
        severity: "high",
        action: "block_install",
        reason: MODERATOR_REASON,
        entries: [{ kind: "id_version", value: "widgets@1.2.0" }],
      },
    },
  });
  const r = compileDecision(entry({ code: "M_RELIST", category: "error", moderator: "knice" }), { root });
  assert.equal(r.refusal, "relist_under_advisory");
});

test("relist_unbound: no identity record, and no release can lift `unlisted` (MIG-27)", () => {
  const root = estate({ bound: false, extra: { "plugins/widgets/plugin.json": plugin("widgets", { unlisted: true }) } });
  const r = compileDecision(entry({ code: "M_RELIST", category: "error", moderator: "knice" }), { root });
  assert.equal(r.refusal, "relist_unbound");
});

test("relist_contained refuses astra-chess at R′, and the post-M-T6.3 fixture passes it", () => {
  const id = MIG25_UNBOUND_EXCEPTION;
  const contained = repo([{
    files: {
      "schema/contract-tokens-v1.json": tokenFile(),
      [`plugins/${id}/plugin.json`]: { ...plugin(id, { repo: "KNICE-TECH/astra-chess" }), unlisted: true },
      [`plugins/${id}/versions/0.1.17.json`]: version(id, "0.1.17", { repo: "KNICE-TECH/astra-chess" }),
    },
  }]);
  const before = compileDecision(entry({ code: "M_RELIST", plugin_id: id, category: "error", moderator: "knice" }), { root: contained });
  assert.equal(before.refusal, "relist_contained",
    "MIG-25's exception exists so this falls through to the refusal that describes WHY it cannot come back, " +
    "rather than to `relist_unbound`, which a moderator would fix and then be refused again");

  const moved = repo([{
    files: {
      "schema/contract-tokens-v1.json": tokenFile(),
      [`plugins/${id}/plugin.json`]: { ...plugin(id, { repo: "MINICE-AI/astra-chess" }), unlisted: true },
      [`plugins/${id}/identity.json`]: identity(id, { repo: "MINICE-AI/astra-chess" }),
      [`plugins/${id}/versions/0.1.18.json`]: version(id, "0.1.18", { repo: "MINICE-AI/astra-chess" }),
    },
  }]);
  const after = compileDecision(entry({ code: "M_RELIST", plugin_id: id, category: "error", moderator: "knice" }), { root: moved });
  assert.equal(after.outcome, "held", "nothing contains it any more, so MOD-9's ordinary reversal hold is all that is left");
  assert.equal(after.held_for, "reversal");
});

// ── MOD-4, MOD-13, MOD-19 ───────────────────────────────────────────────────

test("a version record whose `artifacts` is an object keyed by two platforms yields both digests (m11)", () => {
  const root = estate({
    extra: {
      "plugins/widgets/versions/1.2.0.json": version("widgets", "1.2.0", {
        artifacts: {
          "linux-x86_64": { url: "https://example.invalid/a", filename: "a", sha256: "1".repeat(64) },
          "darwin-aarch64": { url: "https://example.invalid/b", filename: "b", sha256: "2".repeat(64) },
        },
      }),
    },
  });
  const r = compileDecision(entry({
    code: "M_REVOKE", category: "malicious", severity: "critical", action: "block_install",
    versions: ["1.2.0"], moderator: "knice",
  }), { root });
  const digests = r.advisories[0].entries.filter((e) => e.kind === "digest").map((e) => e.value).sort();
  assert.deepEqual(digests, ["1".repeat(64), "2".repeat(64)]);
});

test("a digest in the payload that differs from git is ignored (MOD-4; DEC-11)", () => {
  const root = estate({
    extra: {
      "plugins/widgets/versions/1.2.0.json": version("widgets", "1.2.0", {
        artifacts: { noarch: { url: "https://example.invalid/a", filename: "a", sha256: "3".repeat(64) } },
      }),
    },
  });
  const r = compileDecision({
    ...entry({
      code: "M_REVOKE", category: "malicious", severity: "critical", action: "block_install",
      versions: ["1.2.0"], moderator: "knice",
    }),
    // The mutation this asserts against: a composer handed the entry object
    // straight through would put the service's word about our own tree into a
    // signed document.
    artifact_digests: ["f".repeat(64)],
    entries: [{ kind: "digest", value: "f".repeat(64) }],
  }, { root });

  const values = r.advisories[0].entries.map((e) => e.value);
  assert.ok(values.includes("3".repeat(64)), "the digest git holds is the one that is signed");
  assert.ok(!values.includes("f".repeat(64)), "a mistyped digest matches nothing, and nobody here can check one");
});

test("after adding and then deleting ASTRA-2026-0001, the next id is 0002 (MOD-13)", () => {
  const advisory = {
    id: "ASTRA-2026-0001", published: "2026-09-01", severity: "low", action: "warn",
    reason: MODERATOR_REASON, entries: [{ kind: "id", value: "widgets" }],
  };
  const root = repo([
    { files: { "schema/contract-tokens-v1.json": tokenFile(), "plugins/widgets/plugin.json": plugin("widgets") } },
    { files: { "tools/revocations/ASTRA-2026-0001.json": advisory }, message: "advise" },
    { delete: ["tools/revocations/ASTRA-2026-0001.json"], message: "unrevoke" },
  ]);
  assert.equal(fs.existsSync(path.join(root, "tools/revocations/ASTRA-2026-0001.json")), false);
  assert.equal(nextAdvisoryId({ root, year: "2026" }), "ASTRA-2026-0002",
    "a tree reading hands the next advisory the id the deleted one had, and two advisories with one id is a " +
    "signed document in which the second silently replaces the first");
});

test("MOD-19's identity entries cover a historic source.repo and reach two siblings", () => {
  const root = repo([
    {
      files: {
        "schema/contract-tokens-v1.json": tokenFile(),
        "plugins/widgets/plugin.json": plugin("widgets", { repo: "acme/old-monorepo" }),
        "plugins/widgets/versions/1.0.0.json": version("widgets", "1.0.0", { repo: "acme/old-monorepo" }),
        "plugins/gadgets/plugin.json": plugin("gadgets", { repo: "acme/old-monorepo" }),
        "plugins/gadgets/versions/1.0.0.json": version("gadgets", "1.0.0", { repo: "acme/old-monorepo" }),
      },
    },
    {
      files: { "plugins/widgets/plugin.json": plugin("widgets", { repo: "acme/monorepo" }) },
      message: "renamed",
    },
  ]);

  const r = compileDecision(entry({
    code: "M_REVOKE", category: "account_compromise", severity: "critical", action: "disable",
    moderator: "knice",
  }), { root, overBound: false });
  // `disable` is held, so read the compile through a `block_install` instead:
  // the entries are the same and the hold is MOD-9's, not MOD-19's.
  assert.equal(r.held_for, "disable_confirmation");

  const applied = compileDecision(entry({
    code: "M_REVOKE", category: "account_compromise", severity: "critical", action: "block_install",
    moderator: "knice",
  }), { root });
  const identities = applied.advisories[0].entries.filter((e) => e.kind === "identity").map((e) => e.value).sort();
  assert.deepEqual(identities, ["github:acme/monorepo", "github:acme/old-monorepo"],
    "a pin keeps the install-time name (DEC-17), and the identity record holds only the last one, so the " +
    "history is where the earlier name is");
  assert.ok(identities.every((v) => v.startsWith("github:")), "`origin:` is never emitted; nothing here resolves it");
});

test("account-level entries appear only under the two categories (DEC-13)", () => {
  const root = estate();
  for (const category of ["privacy", "impersonation", "security_defect"]) {
    const r = compileDecision(entry({
      code: "M_REVOKE", category, severity: "high", action: "block_install", versions: ["1.0.0"], moderator: "knice",
    }), { root });
    assert.equal(r.advisories[0].entries.filter((e) => e.kind === "identity").length, 0,
      `an identity entry under \`${category}\` would reach sibling listings for a reason that was not about the account`);
  }
  for (const category of ACCOUNT_LEVEL_CATEGORIES) {
    const r = compileDecision(entry({
      code: "M_REVOKE", category, severity: "high", action: "block_install", versions: ["1.0.0"], moderator: "knice",
    }), { root });
    assert.ok(r.advisories[0].entries.some((e) => e.kind === "identity"), `${category} is account-level (MOD-19)`);
  }
});

test("a contiguous run with a version above it becomes one exact version_range; anything else becomes id_versions", () => {
  const root = estate({ versions: ["1.0.0", "1.1.0", "1.2.0"] });

  const range = compileDecision(entry({
    code: "M_DEPRECATE", category: "broken", severity: "low", versions: ["1.0.0", "1.1.0"], moderator: "knice",
  }), { root });
  const rangeEntry = range.advisories[0].entries.find((e) => e.kind === "version_range");
  assert.deepEqual(rangeEntry.versions, { introduced: "1.0.0", fixed: "1.2.0" },
    "half-open [introduced, fixed) expresses exactly the two versions named and no more");

  const tail = compileDecision(entry({
    code: "M_DEPRECATE", category: "broken", severity: "low", versions: ["1.0.0", "1.2.0"], moderator: "knice",
  }), { root });
  assert.equal(tail.advisories[0].entries.filter((e) => e.kind === "version_range").length, 0);
  assert.deepEqual(
    tail.advisories[0].entries.filter((e) => e.kind === "id_version").map((e) => e.value),
    ["widgets@1.0.0", "widgets@1.2.0"],
    "a range would swallow 1.1.0, which the moderator did not name",
  );

  const whole = compileDecision(entry({
    code: "M_DEPRECATE", category: "broken", severity: "low", moderator: "knice",
  }), { root });
  assert.deepEqual(whole.advisories[0].entries.filter((e) => e.kind === "id").map((e) => e.value), ["widgets"]);
});

// ── the floor: `fixed_reasons` is published on `main` since contract 2.3.0 ──

test("on the real tree `fixed_reasons` is published, and a token file without it makes an A_YANK throw", () => {
  // Contract 2.3.0 (ops.15). The two strings are §0.8's *Fixed registry
  // reasons*, byte for byte; this reads them through the one reader the bot
  // and tools/validate.mjs share.
  assert.equal(fixedReason("A_YANK", { root: REPO_ROOT }),
    "Yanked at its author's own request, made from the Astra plugins panel.");
  assert.equal(fixedReason("A_REMOVAL_REQUEST", { root: REPO_ROOT }),
    "Delisted at its author's own request, made from the Astra plugins panel. Installed copies are not removed.");

  const root = estate({ extra: { "schema/contract-tokens-v1.json": tokenFile({ fixed: false }) } });
  assert.throws(
    () => compileDecision(entry({ code: "A_YANK", category: "author_request", versions: ["1.0.0"], reason: FIXED_YANK }), { root }),
    /fixed_reasons/,
    "a refusal is FINAL (BOT-81): settling every author yank as `reason_refused` until ops.15 lands reads from " +
    "the panel exactly like a service that sent something wrong, and a run that fails loudly does not",
  );
});

// ── BOT-34's second Check clause, in tools/validate.mjs ─────────────────────
//
// The one clause of M-T3.1's canary that is a property of the COMMIT and not of
// this compiler's return value. Every file in the set can be individually valid
// while the set is wrong, which is exactly the failure it exists to catch.

/** A tree in which an `A_YANK` yanked `versions`, with `records` of them logged. */
function yankedTree({ versions, records, reason = FIXED_YANK, category = "author_request" }) {
  const id = "widgets";
  const files = {
    "schema/contract-tokens-v1.json": tokenFile(),
    [`plugins/${id}/plugin.json`]: plugin(id),
    [`plugins/${id}/identity.json`]: identity(id),
    [`bot/moderation/2026-09-20-${id}-yank.json`]: {
      date: "2026-09-20",
      action: "yank",
      plugin: id,
      versions,
      reason,
      category,
      service_decision_id: SDI,
    },
  };
  for (const v of versions) files[`plugins/${id}/versions/${v}.json`] = version(id, v, { yanked: true });

  for (const v of records) {
    const key = `service-decision:${SDI}:${id}:${v}:yanked`;
    const doc = {
      schema: RECORD_SCHEMA,
      decision_id: decisionId(key),
      decided_at: "2026-09-20T12:00:00Z",
      actor: "author",
      trigger: "moderation",
      plugin_id: id,
      version: v,
      repo: "acme/widgets",
      repository_id: "912345678",
      repository_owner_id: "4711",
      state: "yanked",
      reasons: ["A_YANK"],
      category: "author_request",
    };
    files[recordPath(doc)] = doc;
  }
  return repo([{ files }]);
}

function runCount(root, { authorYankReason }) {
  const report = new Report();
  const { plugins } = loadSources(root);
  const ctx = { report, root, authorYankReason };
  checkAuthorActionRecords(ctx, { plugins }, loadRecords(root, { plugins }));
  return report;
}

test("a commit that yanks three versions and carries two author-action records is refused (BOT-34)", () => {
  const root = yankedTree({ versions: ["1.0.0", "1.1.0", "1.2.0"], records: ["1.0.0", "1.1.0"] });
  const report = runCount(root, { authorYankReason: FIXED_YANK });
  assert.equal(report.errors.length, 1, report.text());
  assert.match(report.errors[0].message, /no record for 1\.2\.0/,
    "the refusal names the version, because a count that only said `3 != 2` tells nobody which record to write");
});

test("the same fixture with three records passes", () => {
  const root = yankedTree({ versions: ["1.0.0", "1.1.0", "1.2.0"], records: ["1.0.0", "1.1.0", "1.2.0"] });
  const report = runCount(root, { authorYankReason: FIXED_YANK });
  assert.equal(report.errors.length, 0, report.text());
});

test("with the fixed reason published, an M_YANK a moderator took for an unbound author owes no records", () => {
  // FLOW-79: "A listing with no bound account offers no yank: its author asks a
  // moderator (`M_YANK`, category `author_request`) until it is bound." That
  // entry is `action: yank`, `category: author_request` and writes NO
  // author-action record — so a check discriminating on action and category
  // alone refuses a legal tree for carrying zero of the records it does not owe.
  const root = yankedTree({ versions: ["1.0.0"], records: [], reason: MODERATOR_REASON });
  const published = runCount(root, { authorYankReason: FIXED_YANK });
  assert.equal(published.errors.length, 0, published.text());

  // Since contract 2.3.0 the string is published, so a token file without it
  // is broken: refused by name, and no record is counted against a set the
  // check cannot draw.
  const unpublished = runCount(root, { authorYankReason: null });
  assert.equal(unpublished.errors.length, 1, unpublished.text());
  assert.match(unpublished.errors[0].message, /no fixed `A_YANK` reason/,
    "a token file that lost the string is refused as that, not counted by action and category");
  assert.equal(unpublished.notes.length, 0, "the fallback note went with the fallback");
});

test("a yank naming no version is refused rather than passing a count of zero against zero", () => {
  const root = yankedTree({ versions: ["1.0.0"], records: ["1.0.0"] });
  writeAll(root, {
    "bot/moderation/2026-09-20-widgets-yank.json": {
      date: "2026-09-20", action: "yank", plugin: "widgets", reason: FIXED_YANK,
      category: "author_request", service_decision_id: SDI,
    },
  });
  const report = runCount(root, { authorYankReason: FIXED_YANK });
  assert.equal(report.errors.length, 1, report.text());
  assert.match(report.errors[0].message, /naming no version/);
});

// ── M_IDENTITY_RESET (contract 2.5.0; registry plan B-T4.2) ─────────────────
//
// OPEN-OWNER-15 made `B_REPOSITORY_RECYCLED` permanent "which a moderator may
// reset", and until contract 2.5.0 no code carried the reset, so ID-41's
// refusal stood for good. These are the compile's half: MOD-10's refusal
// (`target_changed` for an id with no newer `B_REPOSITORY_RECYCLED` record),
// MOD-9's hold (a reversal), and the release `compileIdentityReset` composes —
// DEC-7's voiding record, ID-40's one deletion of an identity record, and the
// log entry `reset`. The walk through the commit job to `main` is
// `bot/tests/moderation-run.test.mjs`'s.

const RESET_REASON = "The repository name was re-registered by its new owner after the old one deleted it.";
const reset = (over = {}) => entry({
  code: "M_IDENTITY_RESET", category: "identity_reset", moderator: "knice", declared_interest: false,
  reason: RESET_REASON, ...over,
});

/** A decision record on the tree, at the path its name and `decided_at` require. */
const onMain = (hex, doc) => ({
  [`log/decisions/${doc.decided_at.slice(0, 4)}/${doc.decided_at.slice(5, 7)}/${hex.repeat(32 / hex.length)}.json`]: {
    schema: "astra.registry.decision/1", decision_id: hex.repeat(32 / hex.length), ...doc,
  },
});
const recycledRefusal = (at, id = "widgets") => ({
  decided_at: at, actor: "bot", trigger: "panel", plugin_id: id, repo: "acme/widgets", tag: "widgets-v2.0.0",
  state: "refused", reasons: ["B_REPOSITORY_RECYCLED"],
});
const voiding = (at, id = "widgets") => ({
  decided_at: at, actor: "moderator", moderator: "knice", trigger: "moderation", plugin_id: id,
  state: "identity_reset", reasons: ["M_IDENTITY_RESET"], category: "identity_reset",
});

test("M_IDENTITY_RESET against a B_REPOSITORY_RECYCLED refusal is held `reversal`, and writes nothing yet (MOD-9)", () => {
  for (const bound of [true, false]) {
    const root = estate({ bound, extra: onMain("a", recycledRefusal("2026-09-19T10:00:00Z")) });
    const r = compileDecision(reset(), { root });
    assert.equal(r.outcome, "held", `bound ${bound}: ${r.outcome} ${r.refusal ?? ""} ${r.why ?? ""}`);
    assert.equal(r.held_for, "reversal", "MOD-9 names M_IDENTITY_RESET a reversal: 24 hours and a confirmation");
    assert.deepEqual([r.edits, r.log, r.advisories, r.records], [[], [], [], []],
      "a held reset wrote an artefact; the reset is its release commit and nothing before it");
    assert.ok(HOLD_KINDS.includes(r.held_for));
  }
});

test("MOD-10: a reset with no B_REPOSITORY_RECYCLED record newer than the newest voiding record is `target_changed`", () => {
  const cases = [
    ["no refusal at all", {}],
    ["a refusal for another id", onMain("b", recycledRefusal("2026-09-19T10:00:00Z", "gadgets"))],
    ["a refusal the last reset already answered",
      { ...onMain("c", recycledRefusal("2026-09-19T10:00:00Z")), ...onMain("d", voiding("2026-09-19T11:00:00Z")) }],
    ["a refusal in the same second as the voiding record",
      { ...onMain("e", recycledRefusal("2026-09-19T11:00:00Z")), ...onMain("f", voiding("2026-09-19T11:00:00Z")) }],
    ["another refusal code", onMain("1", { ...recycledRefusal("2026-09-19T10:00:00Z"), reasons: ["B_OWNER_CHANGED"] })],
  ];
  for (const [what, extra] of cases) {
    const r = compileDecision(reset(), { root: estate({ extra }) });
    assert.equal(r.outcome, "refused", `${what}: ${r.outcome}`);
    assert.equal(r.refusal, "target_changed", `${what}: ${r.refusal} — ${r.why}`);
    assert.match(r.why, /B_REPOSITORY_RECYCLED/);
  }
  // And the satisfiable direction beside each: a refusal NEWER than the last
  // reset is one the reset may lift.
  const again = compileDecision(reset(), {
    root: estate({ extra: { ...onMain("2", voiding("2026-09-19T11:00:00Z")), ...onMain("3", recycledRefusal("2026-09-19T12:00:00Z")) } }),
  });
  assert.equal(again.outcome, "held", `a refusal after the last reset was not resettable: ${again.why}`);
});

test("kind_refused: a reset under another category, or with no moderator for its record", () => {
  const root = estate({ extra: onMain("a", recycledRefusal("2026-09-19T10:00:00Z")) });
  for (const [what, over, pattern] of [
    ["category error", { category: "error" }, /identity_reset/],
    ["no category", { category: undefined }, /identity_reset/],
    ["no moderator", { moderator: undefined }, /moderator/],
  ]) {
    const r = compileDecision(reset(over), { root });
    assert.equal(r.refusal, "kind_refused", `${what}: ${r.outcome} ${r.refusal}`);
    assert.match(r.why, pattern, what);
  }
  // `identity_reset` is §7.2's for IDENTITY_RESET alone: a delist carrying it is refused too.
  const delist = compileDecision(entry({ code: "M_DELIST", category: "identity_reset", moderator: "knice" }), { root });
  assert.equal(delist.refusal, "kind_refused", `a delist under identity_reset was ${delist.outcome}`);
});

test("target_not_in_registry: a reset of an id with no listing", () => {
  const root = estate({ extra: onMain("a", recycledRefusal("2026-09-19T10:00:00Z", "gone")) });
  const r = compileDecision(reset({ plugin_id: "gone" }), { root });
  assert.equal(r.refusal, "target_not_in_registry");
});

test("the release, case (ii): the voiding record, the identity record deleted, the log entry `reset`, one trailer", () => {
  const root = estate({ extra: onMain("a", recycledRefusal("2026-09-19T10:00:00Z")) });
  const r = compileIdentityReset(reset(), { root });
  assert.equal(r.outcome, "compiled", `${r.outcome} ${r.refusal ?? ""} ${r.why ?? ""}`);
  assert.deepEqual(r.edits, [{ op: "delete", file: "plugins/widgets/identity.json" }],
    "ID-40: the reset's release commit is the one non-publishing commit that deletes an identity record");
  assert.equal(r.log.length, 1);
  assert.deepEqual(r.log[0].doc, {
    date: "2026-09-20", action: "reset", plugin: "widgets", reason: RESET_REASON, category: "identity_reset",
    service_decision_id: SDI, declared_interest: false,
  });
  assert.equal(r.log[0].file, "bot/moderation/2026-09-20-widgets-reset.json");
  assert.equal(r.records.length, 1, "DEC-7: one voiding record per applied M_IDENTITY_RESET");
  const [{ key, record }] = r.records;
  assert.equal(key, `service-decision:${SDI}:widgets::identity_reset`, "BOT-35's key for the voiding record");
  assert.deepEqual(record, {
    decided_at: "2026-09-20T12:00:00Z", actor: "moderator", moderator: "knice", trigger: "moderation",
    plugin_id: "widgets", state: "identity_reset", reasons: ["M_IDENTITY_RESET"], category: "identity_reset",
    declared_interest: false,
  });
  assert.deepEqual(r.trailers, { "Service-Decision": SDI, "Decided-At": "2026-09-20T12:00:00Z" });
  assert.deepEqual([r.advisories, r.alerts], [[], []]);
});

test("the release, case (i): no identity record, so the voiding record and the log entry alone", () => {
  const root = estate({ bound: false, extra: onMain("a", recycledRefusal("2026-09-19T10:00:00Z")) });
  const r = compileIdentityReset(reset(), { root });
  assert.equal(r.outcome, "compiled", `${r.outcome} ${r.refusal ?? ""} ${r.why ?? ""}`);
  assert.deepEqual(r.edits, [], "a listing with no identity record has none to delete, and the release names no other file");
  assert.equal(r.records.length, 1,
    "the voiding record is written in BOTH cases: it is what ends the baseline, and deleting identity.json alone ends none");
  assert.equal(r.log[0].doc.action, "reset");
});

test("a release the tree has moved under is not composed: another reset voided the id first", () => {
  // The hold waited 24 hours. A second reset of the same refusal, released in
  // between, voided the id: this one now lifts nothing, and the release asks
  // MOD-10 again rather than trusting what it was told a day earlier.
  const root = estate({
    extra: { ...onMain("a", recycledRefusal("2026-09-19T10:00:00Z")), ...onMain("b", voiding("2026-09-20T11:00:00Z")) },
  });
  const r = compileIdentityReset(reset(), { root });
  assert.equal(r.outcome, "refused");
  assert.equal(r.refusal, "target_changed");
  assert.deepEqual([r.edits, r.log, r.records], [[], [], []]);
  assert.throws(() => compileIdentityReset(entry({ code: "M_RELIST" }), { root }), /composes an M_IDENTITY_RESET/);
});

test("MIG-20's tree check accepts the voiding record the writer composes, and nothing else that carries its marks", () => {
  const root = estate({ extra: onMain("a", recycledRefusal("2026-09-19T10:00:00Z")) });
  const { key, record } = compileIdentityReset(reset(), { root }).records[0];
  writeDecisionRecord({ key, record, root });
  const check = (tree) => {
    const report = new Report();
    const { plugins } = loadSources(tree);
    checkRecords({ report, root: tree, schemas: loadSchemas(REPO_ROOT) }, { plugins }, loadRecords(tree, { plugins }));
    return report;
  };
  // Judged on `log/decisions/` alone: this file's `identity()` fixture carries
  // a 64-hex `token_hash` where B.4 says 16, which is the fixture's, not the
  // record's, and not this test's subject.
  const clean = check(root);
  const records = clean.errors.filter((e) => e.where.startsWith("log/decisions/"));
  assert.ok(clean.items.length >= 0 && fs.existsSync(path.join(root, recordPath({ decision_id: decisionId(key), decided_at: record.decided_at }))),
    "the voiding record was not written, so the check below would judge nothing");
  assert.equal(records.length, 0, `the composed voiding record is refused by tools/validate.mjs:\n${clean.text()}`);

  const lookalikes = [
    ["a version", { ...record, version: "1.0.0" }, /carries no `version`/],
    ["the old ids", { ...record, repository_id: "912345678", repository_owner_id: "4711" }, /carries no `repository_id`/],
    ["a bot's", { ...record, actor: "bot" }, /`actor`/],
    ["the category on a delist", { ...record, state: "delisted", reasons: ["M_DELIST"] }, /`state`/],
    ["the code under another category", { ...record, category: "error" }, /`category`/],
    ["the state alone", { decided_at: "2026-09-20T12:00:00Z", actor: "bot", trigger: "panel", plugin_id: "widgets", state: "identity_reset" }, /`actor`|missing/],
    ["no moderator", (() => { const { moderator: _m, ...rest } = record; return rest; })(), /missing moderator/],
  ];
  for (const [what, doc, pattern] of lookalikes) {
    const tree = estate({ extra: onMain("9", doc) });
    const report = check(tree);
    const mine = report.errors.filter((e) => e.where.startsWith("log/decisions/"));
    assert.equal(mine.length, 1, `${what}: ${report.text()}`);
    assert.match(mine[0].message, pattern, what);
  }
});

// ── M_REVIEW (contract 3.0.0; MOD-56) ───────────────────────────────────────
//
// The one service decision that ADDS trust. A release publishes at once,
// marked `review: "unreviewed"` in its version record (B.4; DEC-19), and a
// moderator's `M_REVIEW` is the only thing that moves a version to
// `reviewed`. MOD-56 is the whole rule, and every clause of it is a test here:
//
//   * it sets `review` to `reviewed` on each named version that is listed,
//     not yanked and not already `reviewed` on `main`;
//   * in one commit carrying `Service-Decision:`, with one moderation-log
//     entry `review` naming the versions it moved;
//   * `target_changed` when no named version can move;
//   * never held (MOD-9), never counted toward the takedown bound (TRUST-26).
//
// Its partial apply is `M_YANK`'s and not `A_YANK`'s, for the reason MOD-56
// states: a moderator naming a set in which one version was reviewed a minute
// earlier is ordinary, and nothing is lost by marking the rest. What is NOT
// ordinary is a decision that moves nothing, and that is refused rather than
// committed as an empty log entry, which detector A's row 11 would then read as
// a review naming no version.

const REVIEW_REASON = "A moderator read this version's manifest, permissions and bundle and found nothing wrong.";

/** A version record with a review mark, or with none (`undefined`: published before 3.0.0). */
const marked = (id, v, mark, opts = {}) => ({ ...version(id, v, opts), ...(mark === undefined ? {} : { review: mark }) });

const review = (over) => entry({
  code: "M_REVIEW", category: "review_passed", moderator: "knice", reason: REVIEW_REASON, ...over,
});

/** widgets: 1.0.0 reviewed, 1.1.0 unreviewed, 1.2.0 yanked, 1.3.0 published before 3.0.0 (no mark). */
function reviewEstate({ extra = {}, ...opts } = {}) {
  return estate({
    versions: [],
    ...opts,
    extra: {
      "plugins/widgets/versions/1.0.0.json": marked("widgets", "1.0.0", "reviewed"),
      "plugins/widgets/versions/1.1.0.json": marked("widgets", "1.1.0", "unreviewed"),
      "plugins/widgets/versions/1.2.0.json": marked("widgets", "1.2.0", "unreviewed", { yanked: true }),
      "plugins/widgets/versions/1.3.0.json": marked("widgets", "1.3.0", undefined),
      ...extra,
    },
  });
}

test("M_REVIEW is a code the compiler knows, and its log action is `review` (§7.2; MOD-47)", () => {
  assert.equal(compiler.KNOWN_CODES?.M_REVIEW, "review",
    "bot/lib/compile-decision.mjs has no answer for M_REVIEW, so a moderator's review THROWS the whole run");
  assert.equal(compiler.LOG_ACTION.M_REVIEW, "review", "§7.2: `M_REVIEW` → log `review`");
});

test("M_REVIEW marks the versions that can move, in one log entry naming them, under its two trailers (MOD-56)", () => {
  const root = reviewEstate();
  const r = compileDecision(review({ versions: ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "9.9.9"] }), { root });
  assert.equal(r.outcome, "compiled", JSON.stringify(r.why ?? r));
  // 1.0.0 is already reviewed, 1.2.0 is yanked, 9.9.9 is not on the tree; 1.3.0
  // carries no mark (published before 3.0.0), which is not `reviewed`, so it moves.
  assert.deepEqual(r.edits, [
    { op: "set", file: "plugins/widgets/versions/1.1.0.json", member: "review", value: "reviewed" },
    { op: "set", file: "plugins/widgets/versions/1.3.0.json", member: "review", value: "reviewed" },
  ]);
  assert.equal(r.log.length, 1, "MOD-56: ONE moderation-log entry per review");
  assert.equal(r.log[0].file, "bot/moderation/2026-09-20-widgets-review.json");
  assert.deepEqual(r.log[0].doc, {
    date: "2026-09-20",
    action: "review",
    plugin: "widgets",
    versions: ["1.1.0", "1.3.0"],
    reason: REVIEW_REASON,
    category: "review_passed",
    service_decision_id: SDI,
  }, "the entry names the versions it MOVED, and no other: detector A's row 11 reads a mark by this list");
  assert.deepEqual(checkEntry(r.log[0].doc), [], "the log refuses the entry the compiler wrote");
  assert.ok(!JSON.stringify(r).includes("knice"), "a moderator's handle reached a composed artefact (PRIV-2)");
  assert.deepEqual([r.advisories, r.records, r.alerts], [[], [], []],
    "a review withdraws nothing, writes no decision record and alerts nobody (MOD-56: no notice.moderated)");
  assert.deepEqual(r.trailers, { "Service-Decision": SDI, "Decided-At": "2026-09-20T12:00:00Z" });
});

test("M_REVIEW that can move nothing is `target_changed`, and composes nothing (MOD-56)", () => {
  const root = reviewEstate();
  const unlisted = reviewEstate({ extra: { "plugins/widgets/plugin.json": plugin("widgets", { unlisted: true }) } });
  for (const [what, over, tree] of [
    ["an already-reviewed version", { versions: ["1.0.0"] }, root],
    ["a yanked version", { versions: ["1.2.0"] }, root],
    ["a version not on this tree", { versions: ["9.9.9"] }, root],
    ["all three at once", { versions: ["1.0.0", "1.2.0", "9.9.9"] }, root],
    ["no version at all", { versions: [] }, root],
    ["no `versions` member", { versions: undefined }, root],
    ["an unmarked version of a listing that is not listed", { versions: ["1.1.0", "1.3.0"] }, unlisted],
  ]) {
    const r = compileDecision(review(over), { root: tree });
    assert.equal(r.outcome, "refused", `${what}: ${JSON.stringify(r)}`);
    assert.equal(r.refusal, "target_changed", what);
    assert.deepEqual([r.edits, r.log, r.records], [[], [], []], `${what} composed an artefact`);
  }
});

test("a version named twice moves once, and a mark this registry does not know is not `reviewed`", () => {
  const root = reviewEstate({ extra: { "plugins/widgets/versions/1.4.0.json": marked("widgets", "1.4.0", "pending") } });
  const r = compileDecision(review({ versions: ["1.1.0", "1.1.0", "1.4.0"] }), { root });
  assert.deepEqual(r.edits.map((e) => e.file),
    ["plugins/widgets/versions/1.1.0.json", "plugins/widgets/versions/1.4.0.json"]);
  assert.deepEqual(r.log[0].doc.versions, ["1.1.0", "1.4.0"]);
});

test("M_REVIEW carries `review_passed` and no other category, and `review_passed` rides on nothing else (§7.2)", () => {
  const root = reviewEstate();
  for (const category of ["broken", "error", "author_request", undefined]) {
    const r = compileDecision(review({ versions: ["1.1.0"], category }), { root });
    assert.equal(r.refusal, "kind_refused", `M_REVIEW under ${JSON.stringify(category)} was not refused`);
  }
  for (const code of ["M_YANK", "M_DELIST", "M_DEPRECATE", "M_REVOKE"]) {
    const r = compileDecision(entry({
      code, category: "review_passed", versions: ["1.1.0"], moderator: "knice", severity: "low", action: "block_install",
    }), { root, overBound: false });
    assert.equal(r.refusal, "kind_refused", `${code} under review_passed was not refused`);
  }
});

test("M_REVIEW's reason is a moderator's, held to MOD-41, and its target must be a listing (TRUST-26)", () => {
  const root = reviewEstate();
  const link = compileDecision(review({
    versions: ["1.1.0"], reason: "Reviewed; see https://example.invalid/notes for what was read.",
  }), { root });
  assert.equal(link.refusal, "reason_refused");
  const nowhere = compileDecision(review({ plugin_id: "nothing-here", versions: ["1.0.0"] }), { root });
  assert.equal(nowhere.refusal, "target_not_in_registry");
});

test("M_REVIEW is never held: not over the bound, not for an unbound listing (MOD-9)", () => {
  for (const bound of [true, false]) {
    for (const overBound of [false, true]) {
      const r = compileDecision(review({ versions: ["1.1.0"] }), { root: reviewEstate({ bound }), overBound });
      assert.equal(r.outcome, "compiled", `a review was ${r.outcome} (bound ${bound}, over the bound ${overBound})`);
    }
  }
  // The two predicates `compileDecision` asks, asked directly, so a later edit
  // that adds the code to either list is red here by name.
  assert.equal(holdKindFor({ code: "M_REVIEW" }, { overBound: true, listingBound: false }), null);
  assert.equal(isTakedown({ code: "M_REVIEW" }), false, "a review takes nothing away, so it is not a takedown");
});

test("M_REVIEW costs the takedown bound nothing, where a yank of the same version costs one (TRUST-26)", () => {
  const root = reviewEstate();
  const head = headListing(root);
  const r = compileDecision(review({ versions: ["1.1.0"] }), { root });
  assert.deepEqual(withdrawnBy(r, head), { ids: [], unresolved: [] }, "a review was counted as a withdrawal");
  const yank = compileDecision(entry({ code: "M_YANK", category: "broken", versions: ["1.1.0"], moderator: "knice" }), { root });
  assert.deepEqual(withdrawnBy(yank, head).ids, ["widgets"], "the counter is not counting anything, so the line above proves nothing");
});

test("within one run, a version an earlier decision reviewed, yanked or delisted does not move again", () => {
  const root = reviewEstate();

  const once = newBatch();
  const first = compileDecision(review({ versions: ["1.1.0"] }), { root, batch: once });
  recordInBatch(once, first);
  const again = compileDecision(review({ service_decision_id: SDI2, versions: ["1.1.0"] }), { root, batch: once });
  assert.equal(again.refusal, "target_changed",
    "a second review of the same version in one run compiled again: two log entries for one mark");
  const other = compileDecision(review({ service_decision_id: SDI2, versions: ["1.1.0", "1.3.0"] }), { root, batch: once });
  assert.deepEqual(other.edits.map((e) => e.file), ["plugins/widgets/versions/1.3.0.json"]);
  assert.equal(other.log[0].file, "bot/moderation/2026-09-20-widgets-review-2.json",
    "the second review of the day took the first one's log name (MOD-47)");

  const yanked = newBatch();
  recordInBatch(yanked, compileDecision(entry({
    code: "M_YANK", category: "broken", versions: ["1.1.0"], moderator: "knice",
  }), { root, batch: yanked }));
  assert.equal(compileDecision(review({ service_decision_id: SDI2, versions: ["1.1.0"] }), { root, batch: yanked }).refusal,
    "target_changed", "a version this run yanked was marked reviewed in the same commit");

  const delisted = newBatch();
  recordInBatch(delisted, compileDecision(entry({ code: "M_DELIST", category: "broken", moderator: "knice" }), { root, batch: delisted }));
  assert.equal(compileDecision(review({ service_decision_id: SDI2, versions: ["1.1.0"] }), { root, batch: delisted }).refusal,
    "target_changed", "a listing this run delisted had a version marked reviewed in the same commit");
});

test("a grandfathered or frozen listing's version is reviewable, and an `unlisted` listing's is not (MOD-56 at 3.0.0)", () => {
  // MOD-56 names the listing RECORD: "whose listing record is not `unlisted`
  // (`grandfathered` and `frozen` listings included)". B.3's listing state
  // `listed` is a different word — a listing with an identity record — and
  // reading it here would make every legacy plugin unreviewable, the sixteen
  // on `main` today among them.
  const grandfathered = reviewEstate({ bound: false });
  const r = compileDecision(review({ versions: ["1.1.0"] }), { root: grandfathered });
  assert.equal(r.outcome, "compiled", `a grandfathered listing's version was not reviewable: ${JSON.stringify(r)}`);
  assert.deepEqual(r.edits.map((e) => e.file), ["plugins/widgets/versions/1.1.0.json"]);

  // Frozen: it had an identity record once, and has none now (ID-25).
  const frozen = reviewEstate({ bound: true });
  fs.rmSync(path.join(frozen, "plugins/widgets/identity.json"));
  sh(["add", "-A"], frozen);
  sh(["commit", "-q", "-m", "an identity reset deleted the record"], frozen);
  const f = compileDecision(review({ versions: ["1.3.0"] }), { root: frozen });
  assert.equal(f.outcome, "compiled", `a frozen listing's version was not reviewable: ${JSON.stringify(f)}`);

  const unlisted = reviewEstate({ bound: false, extra: { "plugins/widgets/plugin.json": plugin("widgets", { unlisted: true }) } });
  const u = compileDecision(review({ versions: ["1.1.0"] }), { root: unlisted });
  assert.equal(u.refusal, "target_changed", "an `unlisted` listing's version was marked reviewed");
});
