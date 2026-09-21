// The moderation run, against the answers it has to judge.
//
// Registry plan M-T3.4's canary. Two of its clauses are not about this run's
// return values at all, and they are the two that matter most:
//
//   * **an entry carrying an unnamed member is accepted, compiles normally,
//     and that member appears in no committed file.** The read side and the
//     write side are two different files and each is green on its own while
//     the rule is broken, so the test mutates BOTH — it makes the schema
//     reject the entry (the read-side break) and it passes the entry object
//     straight to the composer instead of through the allowlist (the
//     write-side break). The floor is the number of members BOT-80 names for
//     the kind, written down before the mutation;
//   * **the token-file comparison is two-way on membership.** A member added
//     to `astra.plugins.bot-moderation-work/1` at a token-moving contract
//     version turns registry CI red at the moment it is added, rather than
//     turning every takedown into a silent refusal in production.
//
// ── WHY THE TREES ARE REAL GIT REPOSITORIES ────────────────────────────────
//
// For the reason `bot/tests/compile-decision.test.mjs` gives: MOD-13's next
// advisory id is "one more than the highest ever ADDED", which is a statement
// about history. A stubbed tree would be a fixture of the stub.
//
// ── AND WHY `fixed_reasons` IS IN THE FIXTURES AND NOT ON `main` ───────────
//
// `schema/contract-tokens-v1.json` carries `fixed_reasons: null` until contract
// version ops.15, so every fixture here writes the two strings and one test
// asserts the other direction against the real repository.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  AUTHOR_DENIED_MEMBERS,
  MODERATION_ALLOWLIST,
  MODERATION_INTERVAL_SECONDS,
  REFUSAL_BY_MEMBER,
  SCHEMA_FILE,
  TOP_MEMBERS,
  WORK_SCHEMA,
  alarmsFor,
  allowedPath,
  applyCompiled,
  checkServiceDecision,
  checkSubmission,
  checkWorkAnswer,
  compileAll,
  composeCommit,
  composeTrailers,
  composeVerdict,
  listSummary,
  readShadow,
  resultsFor,
  schemaMembers,
  terminalSubmissionRecord,
  unsettled,
  walkHolds,
  workSchema,
} from "../moderation-run.mjs";
import {
  ADVISORY_URL_BASE,
  ENTRY_ALLOWLIST,
  SUBMISSION_ALLOWLIST,
  allowlisted,
  allowlistedSubmission,
} from "../lib/compile-decision.mjs";
import { CATEGORIES } from "../lib/moderation.mjs";
import { BODIES } from "../lib/service.mjs";
import { ID_PATTERN } from "../../tools/lib/ids.mjs";
import { ACTIONS, SEVERITIES } from "../../tools/lib/revocations.mjs";
import { validate } from "../../tools/lib/jsonschema.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const read = (rel) => fs.readFileSync(path.join(REPO, rel), "utf8");

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

const FIXED_YANK = "The account bound to this listing asked the registry to yank the versions named here.";
const FIXED_REMOVAL = "The account bound to this listing asked the registry to remove it from the catalogue.";
const MODERATOR_REASON = "The published bundle shipped a build that crashes the host on start, so it is withdrawn.";

const SDI = "0192f3a4-5b6c-7d8e-9f01-234567890abc";
const SDI2 = "0192f3a4-5b6c-7d8e-9f01-234567890abd";
const SUB = "0192f3a4-5b6c-7d8e-9f01-2345678901ab";

const tokenFile = () => ({
  contract_version: "0.23.0",
  entries: [{ id: "page:MOD-13-advisory-base", kind: "page", url: ADVISORY_URL_BASE }],
  fixed_reasons: { A_YANK: FIXED_YANK, A_REMOVAL_REQUEST: FIXED_REMOVAL },
});

const plugin = (id, { unlisted } = {}) => ({
  schema: "astra.registry.plugin/1",
  id,
  name: id,
  summary: `the ${id} plugin`,
  license: "MIT",
  source: { kind: "github", repo: "acme/widgets" },
  added_at: "2026-01-01T00:00:00Z",
  ...(unlisted ? { unlisted: true } : {}),
});

const version = (id, v, { yanked } = {}) => ({
  schema: "astra.registry.version/1",
  id,
  version: v,
  published_at: "2026-01-01T00:00:00Z",
  release: { kind: "github_release", repo: "acme/widgets", tag: `${id}-v${v}` },
  artifacts: { noarch: { url: `https://example.invalid/${id}-${v}.astraplugin`, filename: `${id}-${v}.astraplugin` } },
  ...(yanked ? { yanked: true } : {}),
});

const identity = (id) => ({
  schema: "astra.registry.identity/1",
  plugin_id: id,
  repository_id: "912345678",
  repository_owner_id: "4711",
  repo: "acme/widgets",
  token_hash: "a".repeat(64),
});

/** A repository with one commit per entry, and the schema this run reads. */
function estate({ versions = ["1.0.0", "1.1.0", "1.2.0"], bound = true, id = "widgets", extra = {} } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-"));
  tmpRoots.push(root);
  const files = {
    "schema/contract-tokens-v1.json": tokenFile(),
    // The one file this run reads by literal path. Copied from the repository
    // under test rather than re-written here: a fixture schema would be a
    // fixture of the fixture, and the rule being tested is what THIS file says.
    [SCHEMA_FILE]: read(SCHEMA_FILE),
    [`plugins/${id}/plugin.json`]: plugin(id),
  };
  for (const v of versions) files[`plugins/${id}/versions/${v}.json`] = version(id, v);
  if (bound) files[`plugins/${id}/identity.json`] = identity(id);
  writeAll(root, { ...files, ...extra });
  sh(["init", "-q", "-b", "main"], root);
  sh(["config", "user.email", "fixture@example.invalid"], root);
  sh(["config", "user.name", "fixture"], root);
  sh(["config", "commit.gpgsign", "false"], root);
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", "fixture"], root);
  return root;
}

const decision = (over) => ({
  service_decision_id: SDI,
  plugin_id: "widgets",
  decided_at: "2026-09-20T12:00:00Z",
  reason: MODERATOR_REASON,
  ...over,
});

const answer = (over) => ({
  schema: WORK_SCHEMA,
  shadow: true,
  submissions: [],
  service_decisions: [],
  ...over,
});

// ── the two-way comparison with the token file ──────────────────────────────

test("the schema's members and the token file's are the same set, both ways", () => {
  // THE clause the plan calls out, and the direction that is easy to forget is
  // the second one: a member the CONTRACT adds and this file does not have.
  // Without it, minice-be publishes a MINOR, the token file gains a member,
  // this repository does nothing, and the next moderation run refuses every
  // entry — green, with `kind_refused` posted for each, which BOT-81 settles
  // as final and BOT-84 does not page for.
  const tokens = JSON.parse(read("schema/contract-tokens-v1.json"));
  const record = (tokens.entries ?? []).find((e) => e?.id === `schema:${WORK_SCHEMA}`);
  assert.ok(record, `the token file carries no \`schema:${WORK_SCHEMA}\` record, so this comparison has no subject`);
  assert.equal(record.members_recorded, true,
    "the token file records no member list for this schema, so a comparison with it would assert nothing");
  assert.equal(record.state, "live");

  const published = record.members.map((m) => m.name).sort();
  assert.deepEqual(published, [...TOP_MEMBERS].sort(),
    "this run's idea of the answer's members and the token file's differ");

  const schemaSide = schemaMembers(null, REPO);
  assert.deepEqual(schemaSide, published,
    `${SCHEMA_FILE}'s top-level members and the token file's differ. A member the contract adds at a ` +
    "token-moving version must turn THIS red at the moment it is added, and never turn every takedown into a " +
    "silent refusal in production");

  // And the third copy, which is the wire client's.
  assert.deepEqual(
    BODIES[WORK_SCHEMA].members.map(([name]) => name).sort(),
    published,
    "bot/lib/service.mjs's table for this body and the token file disagree",
  );
});

test("a member added to the token file, or removed from the schema, is caught", () => {
  // Watched both ways, as the plan asks, by mutating copies rather than the
  // files: a mutation of a real file would leave the repository broken if this
  // process died between the edit and the restore.
  const tokens = JSON.parse(read("schema/contract-tokens-v1.json"));
  const record = (tokens.entries ?? []).find((e) => e?.id === `schema:${WORK_SCHEMA}`);

  const widened = [...record.members.map((m) => m.name), "withheld_since"].sort();
  assert.notDeepEqual(widened, schemaMembers(null, REPO),
    "a token file with one more member than the schema compares EQUAL, so this comparison is not a comparison");

  const narrowed = schemaMembers(null, REPO).filter((m) => m !== "service_decisions");
  assert.notDeepEqual(narrowed, record.members.map((m) => m.name).sort(),
    "a schema with one member removed compares equal to the token file");
});

test("the vocabularies this schema copies are the ones their modules hold", () => {
  // A schema cannot import, so four of its enums are copies. Each is compared
  // with its single source here, because a copy nobody compares is a second
  // answer waiting to disagree.
  const doc = workSchema(REPO);
  const props = doc.$defs.serviceDecision.properties;
  assert.deepEqual([...props.severity.enum], [...SEVERITIES], "tools/lib/revocations.mjs's SEVERITIES");
  assert.deepEqual([...props.action.enum], [...ACTIONS], "tools/lib/revocations.mjs's ACTIONS");
  assert.equal(props.plugin_id.pattern, ID_PATTERN, "tools/lib/ids.mjs's ID_PATTERN");

  // §7.2's categories, against `schema/decision-v1.json`'s copy of the same
  // published list, and NOT against `bot/lib/moderation.mjs`'s `CATEGORIES`.
  // The two are different questions and the difference is one value:
  // `CATEGORIES` maps each moderation-log ACTION to the categories that action
  // allows, and `review_passed` belongs to no takedown action — it is a
  // decision category all the same. A wire schema that took the union of the
  // per-action lists would refuse a category §7.2 publishes, and BOT-81 would
  // settle the entry carrying it as `kind_refused`, finally.
  const decisionSchema = JSON.parse(read("schema/decision-v1.json"));
  assert.deepEqual([...props.category.enum], [...decisionSchema.properties.category.enum],
    "§7.2's categories, as schema/decision-v1.json publishes them");
  const perAction = [...new Set(Object.values(CATEGORIES).flat())];
  for (const c of perAction) {
    assert.ok(props.category.enum.includes(c), `${c} is a category the moderation log accepts and this schema refuses`);
  }
  assert.ok(perAction.length >= 10, `only ${perAction.length} per-action categories found; this is a broken read`);
});

// ── shadow, which is the default even when nobody said so ───────────────────

test("an answer missing `shadow` is read as shadow and alerts", () => {
  for (const value of [undefined, null, "false", 0, "true"]) {
    const mode = readShadow({ shadow: value });
    assert.equal(mode.shadow, true, `\`shadow: ${JSON.stringify(value)}\` must be read as shadow`);
    assert.equal(mode.stated, false);
    assert.ok(mode.alert, "a run that could not tell which mode it is in must say so");
  }
  assert.deepEqual(readShadow({ shadow: false }), { shadow: false, stated: true, alert: null });
  assert.deepEqual(readShadow({ shadow: true }), { shadow: true, stated: true, alert: null });

  const checked = checkWorkAnswer({ submissions: [], service_decisions: [] }, { root: REPO });
  assert.equal(checked.shadow, true);
  assert.ok(checked.alerts.some((a) => a.cause === "shadow"));
  assert.match(listSummary(checked), /shadow true \(not stated; read as shadow\)/);
});

// ── the read side: what is ignored, and what is refused ─────────────────────

test("an entry carrying an unnamed member is accepted, and the member reaches no file", () => {
  // M-1, both halves, with the floor written before either mutation.
  const named = ENTRY_ALLOWLIST.moderator;
  assert.equal(named.length, 14, `BOT-80 names 14 members for a moderator decision and this list has ${named.length}`);

  const root = estate();
  const entry = decision({
    code: "M_DELIST",
    category: "broken",
    moderator: "amoderator",
    withheld_since: "2026-09-20T11:00:00Z",
    x: { anything: [1, 2, 3] },
  });

  // Read side: accepted.
  assert.deepEqual(checkServiceDecision(entry, { root }), { ok: true },
    "SCOPE-3: within `/n` only optional members are added and readers ignore unknown ones. A schema that " +
    "refused this would settle EVERY entry as `kind_refused` at the next run minice-be publishes a MINOR");

  // Write side: the composer never sees them.
  const copied = allowlisted(entry);
  assert.ok(!Object.hasOwn(copied, "x"));
  assert.ok(!Object.hasOwn(copied, "withheld_since"));
  for (const member of ["service_decision_id", "code", "category", "plugin_id", "decided_at", "reason", "moderator"]) {
    assert.ok(Object.hasOwn(copied, member), `${member} is a member BOT-80 names and the allowlist dropped it`);
  }

  const { compiled } = compileAll([entry], { root, overBound: false });
  assert.equal(compiled.length, 1);
  const text = JSON.stringify(compiled[0]);
  assert.ok(!text.includes("withheld_since"), "an ignored member reached a compiled artefact");
  assert.ok(!text.includes("anything"), "an ignored member reached a compiled artefact");

  applyCompiled(compiled, { root });
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
    d.name === ".git" ? [] : d.isDirectory() ? walk(path.join(dir, d.name)) : [path.join(dir, d.name)]);
  for (const file of walk(root)) {
    const body = fs.readFileSync(file, "utf8");
    assert.ok(!body.includes("withheld_since"), `${file} carries a member the bot ignored on read`);
    assert.ok(!body.includes("anything"), `${file} carries a member the bot ignored on read`);
  }
});

test("the read-side break: a schema that refuses the unknown member", () => {
  // The mutation, run against a COPY of the schema. What it costs is stated as
  // a count rather than as a sentence: every entry in the batch is refused.
  const doc = workSchema(REPO);
  const strict = structuredClone(doc);
  strict.$defs.serviceDecision.additionalProperties = false;
  const entry = decision({ code: "M_DELIST", category: "broken", moderator: "amoderator", withheld_since: "x" });
  const bound = { ...strict.$defs.serviceDecision, $defs: strict.$defs };
  assert.ok(validate(bound, entry, "$").length > 0,
    "with `additionalProperties: false` the entry must fail — if it does not, this mutation proves nothing");
  assert.equal(validate({ ...doc.$defs.serviceDecision, $defs: doc.$defs }, entry, "$").length, 0,
    "and the shipped schema must accept it");
});

test("the write-side break: the entry object handed to a composer whole", () => {
  const entry = decision({ code: "M_DELIST", category: "broken", moderator: "amoderator", x: "leaked" });
  assert.ok(!JSON.stringify(allowlisted(entry)).includes("leaked"));
  assert.ok(JSON.stringify(entry).includes("leaked"),
    "the entry itself must still carry the member, or the allowlist is being asserted against nothing");
});

test("a held decision carries only BOT-80's members, so an ignored one cannot ride into a hold", () => {
  // The clause that makes the plan's own mutation — `const d = entry` in
  // `compileDecision`, instead of `const d = allowlisted(entry)` — go red.
  // Measured: without it that mutation is INERT, because every composer in
  // `bot/lib/compile-decision.mjs` also builds its object member by member, so
  // an ignored member reaches no log entry and no advisory even when the
  // allowlist is bypassed. The hold is the one artefact that carries the
  // decision OBJECT: `held()` puts it straight into `state/holds/<id>.json`,
  // where `schema/hold-v1.json`'s `additionalProperties: false` would refuse
  // it — on the NEXT run, reading back a file this one already committed,
  // which that schema's own description says is too late to be the defence.
  const root = estate();
  const held = compileAll(
    [decision({ code: "M_RELIST", category: "error", moderator: "amoderator", reverses: SDI2, x: "leaked" })],
    { root, overBound: false },
  ).held;
  assert.equal(held.length, 1, "MOD-9 holds every M_RELIST unconditionally");
  assert.equal(held[0].held_for, "reversal");
  assert.ok(!JSON.stringify(held[0].decision).includes("leaked"),
    "a member the schema ignored on read reached the held decision, and a hold entry is committed to git");
  assert.ok(Object.hasOwn(held[0].decision, "reverses"), "and a member BOT-80 DOES name was kept");
});

test("an `A_*` entry carrying a moderator or a declared_interest is `kind_refused`, by name", () => {
  const root = estate();
  for (const member of AUTHOR_DENIED_MEMBERS) {
    const entry = decision({ code: "A_YANK", versions: ["1.0.0"], reason: FIXED_YANK, [member]: member === "moderator" ? "amoderator" : true });
    const verdict = checkServiceDecision(entry, { root });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.code, "kind_refused");
    assert.match(verdict.why, new RegExp(member), "the refusal must NAME the member; `not` alone cannot");
  }
  // And the schema states the same rule on its own, so the file is correct
  // without the code beside it. Watched by accepting a moderator handle on an
  // `A_YANK`, which is n4's own mutation.
  const doc = workSchema(REPO);
  const bound = { ...doc.$defs.serviceDecision, $defs: doc.$defs };
  assert.ok(
    validate(bound, decision({ code: "A_YANK", versions: ["1.0.0"], reason: FIXED_YANK, moderator: "amoderator" }), "$").length > 0,
    "the schema alone must refuse a moderator on an author action (DEC-14; MOD-41; n4)",
  );
  assert.equal(
    validate(bound, decision({ code: "A_YANK", versions: ["1.0.0"], reason: FIXED_YANK }), "$").length, 0,
    "and it must accept the same entry without one",
  );
});

test("an `A_YANK` whose reason is not the token file's fixed string is `reason_refused`", () => {
  const root = estate();
  const { refused } = compileAll(
    [decision({ code: "A_YANK", versions: ["1.0.0"], reason: MODERATOR_REASON })],
    { root, overBound: false },
  );
  assert.equal(refused.length, 1);
  assert.equal(refused[0].refusal, "reason_refused");
  assert.match(refused[0].why, /fixed registry string/);
});

test("a malformed member routes to the §0.8 code the plan names for it", () => {
  const root = estate();
  const cases = [
    [{ code: "M_DELIST", category: "broken", reason: "short" }, "reason_refused"],
    [{ code: "M_REVOKE", category: "malicious", severity: "extreme", action: "disable" }, "kind_refused"],
    [{ code: "M_REVOKE", category: "malicious", severity: "high", action: "explode" }, "kind_refused"],
    [{ code: "M_SOMETHING", category: "broken" }, "kind_refused"],
    [{ code: "M_DELIST", category: "not_a_category" }, "kind_refused"],
    [{ code: "M_DELIST", category: "broken", plugin_id: "NOT AN ID" }, "target_not_in_registry"],
    [{ code: "M_YANK", category: "broken", versions: ["not-a-semver"] }, "target_changed"],
  ];
  for (const [over, expected] of cases) {
    const verdict = checkServiceDecision(decision(over), { root });
    assert.equal(verdict.ok, false, `${JSON.stringify(over)} must be refused`);
    assert.equal(verdict.code, expected, `${JSON.stringify(over)} routed to ${verdict.code}: ${verdict.why}`);
  }
  // And a well-formed one is not refused, which is the leg most often skipped:
  // a check nobody can pass is not a check.
  assert.deepEqual(
    checkServiceDecision(decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" }), { root }),
    { ok: true },
  );
});

test("the refusal routing table is every §0.8 code the plan assigns and no more", () => {
  assert.deepEqual(REFUSAL_BY_MEMBER.plugin_id, "target_not_in_registry");
  assert.deepEqual(REFUSAL_BY_MEMBER.versions, "target_changed");
  assert.deepEqual(REFUSAL_BY_MEMBER.reason, "reason_refused");
  for (const member of ["severity", "action", "code", "category"]) {
    assert.equal(REFUSAL_BY_MEMBER[member], "kind_refused");
  }
});

test("a submission entry's code is checked against the bot's own landed tables", () => {
  const root = estate();
  const stop = { submission_id: SUB, repo: "acme/widgets", tag: "widgets-v1.0.0", code: "R_FIRST_LISTING" };
  assert.deepEqual(checkSubmission(stop, { root }), { ok: true },
    "R_FIRST_LISTING moved stage hours ago and is still a code this bot emits; the vocabulary is the module, " +
    "never a copy of the published table");
  assert.deepEqual(checkSubmission({ ...stop, code: "R_IDENTITY_CHANGED" }, { root }), { ok: true });
  assert.deepEqual(checkSubmission({ ...stop, code: "M_REJECT", category: "malicious", moderator: "amoderator", decided_at: "2026-09-20T12:00:00Z" }, { root }), { ok: true });
  const bad = checkSubmission({ ...stop, code: "R_NOT_A_CODE" }, { root });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "kind_refused");
});

test("a duplicate list drops the second copy and alerts, and refuses neither", () => {
  const root = estate();
  const entry = decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" });
  const checked = checkWorkAnswer(answer({ service_decisions: [entry, { ...entry }] }), { root });
  assert.equal(checked.entries.length, 1, "two copies of one decision are one decision");
  assert.equal(checked.refused.length, 0,
    "refusing the second copy would settle the decision the first copy is about (BOT-81)");
  assert.ok(checked.alerts.some((a) => a.cause === "duplicate"));
});

test("an entry with no id fails the run rather than being refused", () => {
  const root = estate();
  const checked = checkWorkAnswer(
    answer({ service_decisions: [{ code: "M_DELIST", plugin_id: "widgets" }] }),
    { root },
  );
  assert.equal(checked.refused.length, 0,
    "a refusal is posted AGAINST an id; an entry with none would be re-listed and re-refused for ever, silently");
  assert.equal(checked.fatal.length, 1);
  assert.match(checked.fatal[0], /no result can name it/);
});

// ── the compile, with the network off ───────────────────────────────────────

test("every kind compiles from outputs alone, with the network disabled", () => {
  const root = estate();
  const saved = globalThis.fetch;
  globalThis.fetch = () => {
    throw new Error("the commit job reached the network; it holds contents: write and therefore no bot token (BOT-2)");
  };
  try {
    const kinds = [
      decision({ code: "M_YANK", category: "broken", versions: ["1.0.0"], moderator: "amoderator" }),
      decision({ service_decision_id: SDI2, code: "M_DELIST", category: "broken", moderator: "amoderator" }),
      decision({ service_decision_id: "0192f3a4-5b6c-7d8e-9f01-234567890abe", code: "M_DEPRECATE", category: "broken", severity: "low", moderator: "amoderator" }),
    ];
    const { compiled, refused, held } = compileAll(kinds, { root, overBound: false });
    assert.deepEqual(refused.map((r) => r.refusal), [], "a kind that should compile was refused");
    assert.equal(held.length, 0);
    assert.equal(compiled.length, 3);
  } finally {
    globalThis.fetch = saved;
  }
});

test("an unmeasured takedown bound fails the run and never reads as `under the bound`", () => {
  const root = estate();
  const takedown = decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" });
  assert.throws(
    () => compileAll([takedown], { root }),
    /TRUST-26's bound was not measured/,
    "reading an absent bound as false is the direction that APPLIES a takedown MOD-9 should have held",
  );
  // And the satisfiable direction: with the bound measured, it compiles.
  assert.equal(compileAll([takedown], { root, overBound: false }).compiled.length, 1);
  assert.equal(compileAll([takedown], { root, overBound: true }).held.length, 1);
});

test("an `A_YANK` compiles to one log entry, one record per version, and a trailer", () => {
  const root = estate();
  const { compiled } = compileAll(
    [decision({ code: "A_YANK", versions: ["1.0.0", "1.1.0"], reason: FIXED_YANK })],
    { root, overBound: false },
  );
  assert.equal(compiled.length, 1);
  const [result] = compiled;
  assert.equal(result.log.length, 1, "MOD-3 commits the artefact and its log entry together");
  assert.equal(result.records.length, 2, "BOT-34: n author-action records for n yanked versions");
  assert.equal(result.trailers["Service-Decision"], SDI);
  assert.equal(result.trailers["Decided-At"], "2026-09-20T12:00:00Z");

  const commit = composeCommit({ compiled, run: "35502265394" });
  assert.match(commit.message, /^Service-Decision: 0192f3a4-5b6c-7d8e-9f01-234567890abc$/m);
  assert.match(commit.message, /^Decided-At: 2026-09-20T12:00:00Z$/m);
  assert.match(commit.message, /^Run: 35502265394$/m);
});

test("the per-decision trailers are held to `bot/lib/decisions.mjs`'s grammar, not to a copy", () => {
  // `Decided-At:` is BOT-37's fifth trailer and `TRAILER_GRAMMAR` is where its
  // §0.7 timestamp lives. This file used to carry its own `TIMESTAMP_RE` — the
  // consequence of rendering a trailer the declared list did not have — and
  // that copy was the only thing between a free-text trailer and a value PRIV-2
  // refuses.
  //
  // Asserted on the MESSAGE and not merely on the throw, and that is what makes
  // this a canary rather than a restatement: "A trailer is correlation and
  // never authority (BOT-37)" is written once in this repository, in
  // `trailerLine`. Reinstate a local pattern here and the refusal still fires,
  // with a different sentence, and this goes red.
  const ok = composeTrailers({
    run: "35502265394/2",
    decisions: [{ service_decision_id: SDI, decision_id: "a".repeat(32), decided_at: "2026-09-20T12:00:00Z" }],
  });
  assert.deepEqual(ok, [
    "Run: 35502265394/2",
    `Decision: ${"a".repeat(32)}`,
    `Service-Decision: ${SDI}`,
    "Decided-At: 2026-09-20T12:00:00Z",
  ]);

  for (const bad of ["amoderator", "mod-7", "2026-09-20T12:00:00.700Z", "2026-09-20"]) {
    assert.throws(
      () => composeTrailers({ run: "35502265394", decisions: [{ service_decision_id: SDI, decided_at: bad }] }),
      /A trailer is correlation and never authority \(BOT-37\)/,
      `\`Decided-At: ${bad}\` was rendered, or refused by a second copy of the grammar`,
    );
  }
  assert.throws(
    () => composeTrailers({ run: "mihailinl", decisions: [] }),
    /A trailer is correlation and never authority \(BOT-37\)/,
    "`Run:` goes through the same one grammar",
  );
});

test("two same-day delists of one plugin take MOD-47's `-2`", () => {
  // The sequence that produces two in a day is delist → an operator's MOD-52
  // relist → delist, and it is written out rather than faked, because the
  // obvious fixture — compile the same delist twice — does not produce two log
  // entries at all: the second is `target_changed`, since the listing is
  // already unlisted. A test that stubbed past that would be asserting MOD-47
  // over a state the compiler refuses to be in.
  const root = estate();
  const first = compileAll([decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" })], { root, overBound: false });
  assert.equal(first.compiled.length, 1);
  assert.match(first.compiled[0].log[0].file, /-delist\.json$/);
  applyCompiled(first.compiled, { root });

  // The relist, by hand, as an operator's release commit would leave it.
  const pluginFile = path.join(root, "plugins", "widgets", "plugin.json");
  const doc = JSON.parse(fs.readFileSync(pluginFile, "utf8"));
  delete doc.unlisted;
  fs.writeFileSync(pluginFile, `${JSON.stringify(doc, null, 2)}\n`);

  const second = compileAll(
    [decision({ service_decision_id: SDI2, code: "M_DELIST", category: "broken", moderator: "amoderator" })],
    { root, overBound: false },
  );
  assert.equal(second.refused.length, 0, second.refused.map((r) => r.why).join("; "));
  assert.match(second.compiled[0].log[0].file, /-delist-2\.json$/,
    "a second entry for the same date, plugin and action takes MOD-47's `-<n>` (M-T1.6)");
});

test("BOT-33's moderation allowlist refuses a path no takedown writes", () => {
  for (const good of ["plugins/widgets/plugin.json", "bot/moderation/2026-09-20-widgets-delist.json",
    "tools/revocations/ASTRA-2026-0001.json", "log/decisions/2026/09/abc.json", "state/holds/x.json"]) {
    assert.equal(allowedPath(good), true, `${good} is a path a takedown writes`);
  }
  for (const bad of ["bot/lib/policy.mjs", ".github/workflows/plugins-moderation.yml", "../etc/passwd",
    "/plugins/widgets/plugin.json", "state/queue/widgets@1.0.0.json", "schema/moderation-work-v1.json"]) {
    assert.equal(allowedPath(bad), false, `${bad} is not`);
  }
  assert.ok(MODERATION_ALLOWLIST.length >= 5, "the allowlist lost a prefix and every loop above runs over less");
  assert.throws(
    () => composeCommit({ compiled: [{ service_decision_id: SDI, edits: [{ file: "bot/lib/policy.mjs" }], log: [] }], run: "1" }),
    /BOT-33's moderation allowlist/,
  );
});

// ── BOT-30's terminal record, through the third allowlist ───────────────────

test("a stop's terminal record carries no moderator, whatever the entry carried", () => {
  // n4, one record shape over. `SUBMISSION_ALLOWLIST.stop` is the mechanism
  // and the discriminant is the CODE, never "does it carry a moderator" —
  // which is the reading that lets an entry widen its own allowlist.
  assert.ok(!SUBMISSION_ALLOWLIST.stop.includes("moderator"));
  assert.ok(SUBMISSION_ALLOWLIST.reject.includes("moderator"));
  const copied = allowlistedSubmission({
    submission_id: SUB, repo: "acme/widgets", tag: "v1", code: "R_FIRST_LISTING",
    moderator: "amoderator", declared_interest: true, x: "leaked",
  });
  assert.ok(!Object.hasOwn(copied, "moderator"), "a stop is the author's own act and no moderator decided it");
  assert.ok(!Object.hasOwn(copied, "declared_interest"));
  assert.ok(!Object.hasOwn(copied, "x"));

  const root = estate();
  const placed = terminalSubmissionRecord({
    submission_id: SUB, repo: "acme/widgets", service_repository_id: "912345678",
    tag: "widgets-v1.0.0", code: "R_FIRST_LISTING", decided_at: "2026-09-20T12:00:00Z",
    moderator: "amoderator",
  }, { root });
  assert.equal(placed.written, true);
  const body = fs.readFileSync(path.join(root, placed.path), "utf8");
  assert.ok(!body.includes("amoderator"), "a moderator handle reached a stop's terminal record");
});

// ── holds, which run whether or not `list` answered ─────────────────────────

test("with `list` down a confirmed reversal still releases, and posts next run", () => {
  const held = {
    schema: "astra.registry.hold/1",
    held_for: "reversal",
    service_decision_id: SDI,
    held_at: "2026-09-18T12:00:00Z",
    release_after: "2026-09-19T12:00:00Z",
    decision: {
      service_decision_id: SDI, code: "M_RELIST", plugin_id: "widgets",
      decided_at: "2026-09-18T11:00:00Z", reason: MODERATOR_REASON,
      moderator: "amoderator", reverses: SDI2,
    },
  };
  const confirm = {
    schema: "astra.registry.hold-record/1", act: "confirm", service_decision_id: SDI,
    at: "2026-09-19T13:00:00Z", actor: "operator", run: "https://github.com/a/b/actions/runs/1",
  };
  const root = estate({
    extra: {
      [`state/holds/${SDI}.json`]: held,
      [`state/holds/${SDI}.confirm.json`]: confirm,
    },
  });

  // The run in which `list` never answered: shadow defaults to true, and the
  // hold is released anyway, because a settled `held` result took it off
  // BOT-80's list and its release is driven by the MOD-52 record in git.
  const shadowRun = walkHolds({ root, now: new Date("2026-09-20T00:00:00Z"), shadow: true });
  assert.equal(shadowRun.released.length, 1, "a confirmed reversal is released even with the service down");
  assert.equal(shadowRun.released[0].outcome, "applied");

  const shadowPost = resultsFor({ holds: shadowRun, shadow: true });
  assert.equal(shadowPost.post.length, 0, "an `applied` result settles a decision, which BOT-92 withholds in shadow");
  assert.equal(shadowPost.withheld.length, 1);

  // The next run whose answer is `shadow: false` posts it, once.
  const liveRun = walkHolds({ root, now: new Date("2026-09-20T00:10:00Z"), shadow: false });
  const livePost = resultsFor({ holds: liveRun, shadow: false, commit: "c".repeat(40) });
  assert.equal(livePost.post.length, 1);
  assert.equal(livePost.post[0].outcome, "applied");
  assert.equal(livePost.post[0].commit, "c".repeat(40));
});

test("under a shadow answer nothing at all is posted for the work the answer names", () => {
  const root = estate();
  const { compiled } = compileAll(
    [decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" })],
    { root, overBound: false },
  );
  const shadow = resultsFor({ compiled, shadow: true });
  assert.deepEqual(shadow.post, [], "BOT-92: a `shadow: true` run posts no result of any kind for the listed work");
  assert.equal(shadow.withheld.length, 1);

  const live = resultsFor({ compiled, shadow: false, commit: "d".repeat(40) });
  assert.equal(live.post.length, 1);
  assert.equal(live.post[0].outcome, "applied");
});

test("a `held` result is posted in shadow and a settling one is not", () => {
  // BOT-92 calls a state-setting result what settles a decision. `held` says
  // the registry has NOT decided, so withholding it would leave a moderator
  // with no signal at all during shadow.
  const held = [{ service_decision_id: SDI, held_for: "reversal" }];
  const shadow = resultsFor({ held, shadow: true });
  assert.equal(shadow.post.length, 1);
  assert.equal(shadow.post[0].outcome, "held");
});

test("BOT-81: at most one `held` and exactly one final result per decision", () => {
  assert.throws(
    () => resultsFor({
      compiled: [{ service_decision_id: SDI }],
      refused: [{ service_decision_id: SDI, refusal: "kind_refused" }],
      shadow: false,
    }),
    /exactly one/,
    "two final results settle at the service under whichever arrives last",
  );
});

test("a crash between the commit and the result posts nothing twice", () => {
  // The re-post after a lost acknowledgement is byte-identical, so BOT-82's
  // key — (service_decision_id, outcome, commit) — settles it as `duplicate`.
  // What this asserts is the half this side owns: the same run state produces
  // the same result, and a repeat inside one run is dropped.
  const holds = { pending: [
    { service_decision_id: SDI, outcome: "applied", commit: "e".repeat(40) },
    { service_decision_id: SDI, outcome: "applied", commit: "e".repeat(40) },
  ] };
  const first = resultsFor({ holds, shadow: false });
  assert.equal(first.post.length, 1, "one decision, one result, however many times the run saw it");
  const second = resultsFor({ holds, shadow: false });
  assert.deepEqual(second.post, first.post, "a re-post is byte-identical or BOT-82's key does not match it");
});

// ── the settled job ─────────────────────────────────────────────────────────

test("a listed id with no result fails the run, and a failed `list` does too", () => {
  const ok = unsettled({ listed: [SDI], results: [{ service_decision_id: SDI }] });
  assert.equal(ok.ok, true, "the satisfiable direction: every listed id answered");

  const missing = unsettled({ listed: [SDI, SDI2], results: [{ service_decision_id: SDI }] });
  assert.equal(missing.ok, false);
  assert.deepEqual(missing.ids, [SDI2]);
  assert.match(missing.why, /BOT-84 pages only for a decision with no settled result/);

  const down = unsettled({ listed: [], results: [], listFailed: true });
  assert.equal(down.ok, false, "a run that could not list cannot say every decision got a result");
});

// ── the alarms, and the verdict they are sent as ────────────────────────────

test("MOD-8's alarms are derivable from the list entry, before any compile", () => {
  const alarms = alarmsFor([
    { code: "M_REVOKE", action: "disable", plugin_id: "widgets" },
    { code: "M_RELIST", plugin_id: "widgets" },
    { code: "M_DELIST", plugin_id: "widgets" },
  ]);
  assert.ok(alarms.some((a) => a.code === "MOD_8_ADVISORY_DISABLE"));
  assert.ok(alarms.some((a) => a.code === "MOD_9_DISABLE_CONFIRMATION"));
  assert.ok(alarms.some((a) => a.code === "MOD_9_REVERSAL_HOLD"));
  // Three, not four: an `M_DELIST` enters no advisory and no hold, so MOD-8
  // owes no alarm for it. The count is here so that widening `alarmsFor` is a
  // deliberate edit — an alarm per decision would page an operator ten times
  // an hour and end as an alarm nobody reads.
  assert.equal(alarms.length, 3);
  // The composer refuses here what the channel would refuse at send time.
  const verdict = composeVerdict({ check: "moderation-run", status: "red", codes: alarms.map((a) => a.code), ids: ["widgets"] });
  assert.equal(verdict.status, "red");
  assert.throws(() => composeVerdict({ check: "moderation-run", status: "red", ids: ["NOT AN ID"] }), /may not be sent/);
});

// ── the cron, and the one number three files agree on ───────────────────────

test("the moderation cron's interval is the token file's, commented or not", () => {
  const yaml = read(".github/workflows/plugins-moderation.yml");
  const crons = [...yaml.matchAll(/^\s*#?\s*-\s*cron:\s*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  assert.equal(crons.length, 1, `the workflow carries ${crons.length} cron expression(s) and BOT-83 is one schedule`);

  // The interval is computed from the minutes it FIRES at and never read off
  // the `/n`: `3-40/10` fires at 3, 13, 23, 33 and then waits thirty minutes.
  const fields = crons[0].trim().split(/\s+/);
  assert.equal(fields.length, 5);
  assert.deepEqual(fields.slice(1), ["*", "*", "*", "*"], "a schedule that is not every hour has no single interval");
  const [range, step] = fields[0].split("/");
  const [from, to] = range.split("-").map(Number);
  const minutes = [];
  for (let m = from; m <= to; m += Number(step)) minutes.push(m);
  const gaps = new Set(minutes.map((m, i) => (i === 0 ? m + 60 - minutes[minutes.length - 1] : m - minutes[i - 1])));
  assert.equal(gaps.size, 1, `the cron fires at uneven gaps of ${[...gaps].join(", ")} minutes`);
  const seconds = [...gaps][0] * 60;

  assert.equal(seconds, MODERATION_INTERVAL_SECONDS,
    "BOT-83 pins 600 s and SCOPE-1 makes an edit to it a contract MINOR published BEFORE this line moves");

  const tokens = JSON.parse(read("schema/contract-tokens-v1.json"));
  const schedule = (tokens.schedules ?? []).find((s) => s.id === "schedule:moderation");
  assert.ok(schedule, "the token file records no moderation schedule, so SCOPE-1 has nothing between its two ends");
  assert.equal(schedule.workflow, ".github/workflows/plugins-moderation.yml");
  assert.equal(schedule.interval_seconds, seconds,
    "the service computes BOT-47's silence bound from the token file's number and this workflow runs on the other one");

  // BOT-83's other half: five minutes off the ingest run, so a run of each
  // never starts in the same minute.
  const ingest = [...read(".github/workflows/plugins-ingest.yml")
    .matchAll(/^\s*#?\s*-\s*cron:\s*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  assert.equal(ingest.length, 1);
  const ingestFrom = Number(ingest[0].split(/\s+/)[0].split("-")[0]);
  assert.equal(from - ingestFrom, 5, "BOT-83 puts the moderation run five minutes from the ingest run's minutes");
});
