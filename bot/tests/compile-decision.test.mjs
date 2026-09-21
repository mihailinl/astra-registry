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
// ── THE TOKEN FILE IN A FIXTURE CARRIES `fixed_reasons`; `main` DOES NOT ────
//
// `schema/contract-tokens-v1.json` on `main` carries `fixed_reasons: null`, and
// its own `pending` record says the two strings land with contract version
// ops.15. So every fixture below writes a token file with them, and one test
// asserts the OTHER direction against the real repository: with the strings
// unpublished, `fixedReason` is null and an `A_YANK` THROWS rather than being
// refused `reason_refused`. That asymmetry is the point — a refusal is final
// (BOT-81), and settling every author yank as refused until ops.15 lands reads
// from the panel exactly like a service that sent something wrong.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ACCOUNT_LEVEL_CATEGORIES,
  ADVISORY_KINDS,
  ADVISORY_URL_BASE,
  ENTRY_ALLOWLIST,
  MIG25_UNBOUND_EXCEPTION,
  REFUSALS,
  compileDecision,
  fixedReason,
  nextAdvisoryId,
  tokenAdvisoryBase,
} from "../lib/compile-decision.mjs";
import { decisionId, recordPath, RECORD_SCHEMA } from "../lib/decisions.mjs";
import { HOLD_KINDS } from "../lib/holds.mjs";
import { KINDS } from "../../tools/lib/revocations.mjs";
import { REPO_ROOT, loadRecords, loadSources } from "../../tools/lib/sources.mjs";
import { checkAuthorActionRecords } from "../../tools/validate.mjs";

// ── fixtures ────────────────────────────────────────────────────────────────

const tmpRoots = [];
process.on("exit", () => {
  for (const dir of tmpRoots) fs.rmSync(dir, { recursive: true, force: true });
});

const sh = (args, cwd) => execFileSync("git", args, { cwd, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });

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

// ── the floor: `fixed_reasons` is null on `main` today ──────────────────────

test("on the real tree `fixed_reasons` is unpublished, and an A_YANK throws rather than being refused", () => {
  assert.equal(fixedReason("A_YANK", { root: REPO_ROOT }), null,
    "if this ever returns a string, ops.15 has landed and the fallback in tools/validate.mjs is dead code");

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

  const unpublished = runCount(root, { authorYankReason: null });
  assert.equal(unpublished.errors.length, 1,
    "until ops.15 publishes the string the check is strict in the safe direction: it asks an M_YANK for records " +
    "it does not owe, which is a red a person resolves");
  assert.equal(unpublished.notes.length, 1, "and it says so, because a check that silently changed its subject is worse");
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
