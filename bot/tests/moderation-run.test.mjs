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
import { execFileSync, spawnSync } from "node:child_process";
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
  holdDeletions,
  holdEntryPath,
  listSummary,
  main,
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
  AUTHOR_CODES,
  ENTRY_ALLOWLIST,
  SUBMISSION_ALLOWLIST,
  allowlisted,
  allowlistedSubmission,
} from "../lib/compile-decision.mjs";
import { holdEntry, readHolds } from "../lib/holds.mjs";
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

// ── and one level down: the conditions, stated structurally here and with ───
//    `when` there
//
// The comparison above stops at the answer's three TOP-LEVEL members. One level
// below it, `$defs/serviceDecision` states part of BOT-80's conditions on a
// `service_decisions[]` entry STRUCTURALLY — `not/allOf[1]/anyOf[*]/required` —
// and `schema/contract-tokens-v1.json` states conditions on that same body with
// `when`, under `entries[].members[].of[]`. Two hand-kept statements of one
// rule, in two notations, and nothing between them: a reader that walks members
// and forgets `of[]` has the whole class of blind spot silently.
//
// ── WHAT "AGREE" MEANS BETWEEN A `not/allOf/anyOf/required` AND A `when` ────
//
// They are not the same language and cannot be compared by string, so both are
// reduced to one normal form and the reduction is PROVED rather than assumed:
//
//   * a `when` is already in that form. The token file's readme publishes a
//     predicate over ONE sibling's value, so `(member, code) -> required |
//     forbidden | optional` loses nothing;
//   * the structural side is MEASURED into it, by probing the real schema
//     through `tools/lib/jsonschema.mjs` — the validator the moderation run
//     itself uses, bound the way `checkServiceDecision` binds it — one member
//     at a time;
//   * and the reduction is REPLAYED against every body in an exhaustively
//     enumerated corpus. A `not` may in general say things no per-member table
//     can hold; today's does not, and the replay mispredicts nothing. The day
//     somebody writes a clause with a combination effect, that number moves and
//     this refuses to compare rather than comparing the wrong thing quietly.
//
// ── AGREEMENT IS NOT EQUIVALENCE, AND THAT IS THE JUDGEMENT ─────────────────
//
// The schema is DELIBERATELY the looser of the two and must stay that way. This
// file's own description says why: BOT-81 makes `refused` one of three FINAL
// results, so a schema stricter than the contract does not report a
// disagreement — it settles a LAWFUL entry as `kind_refused`, takes it off
// BOT-80's list, pages nobody (BOT-84 pages only for a decision with no settled
// result), and the first person to notice is a moderator wondering why the
// takedown did not land. So the rule is directional, in three clauses:
//
//   * the schema may NEVER be stricter than the contract, on any cell;
//   * where the schema says anything at all, it must say EXACTLY what the
//     contract says there;
//   * and the cells where it says anything must be exactly the rule production
//     enforces a step earlier — `AUTHOR_CODES` × `AUTHOR_DENIED_MEMBERS`, which
//     is the third statement of this one rule and the only one that runs.
//
// The third clause is what makes this two-sided. Without it, loosening the
// structure while the `when` stands is merely the schema getting looser, which
// the first two clauses permit; with it, a structure that drops a member the
// contract and the compiler both still name is red.
//
// NEITHER PUBLISHED FILE IS THE SOURCE AND NEITHER IS THE COPY. Where the two
// disagree this reports the disagreement; it does not pick a winner, and it
// derives nothing in one from the other.

/**
 * One schema-valid value per member of `$defs/serviceDecision` EXCEPT `code`,
 * which is the axis every condition on this body is decided by and therefore
 * takes each of the schema's published values in turn rather than one fixture.
 *
 * So that the probe below measures the CONDITIONS and never a malformed value:
 * a member whose value fails its own `pattern` reads as `forbidden` on every
 * code, and the comparison would then agree with a rule nobody wrote. Floored
 * against the schema in the first test of this section.
 */
const SD_VALUES = Object.freeze({
  service_decision_id: SDI,
  category: "malicious",
  plugin_id: "widgets",
  versions: ["1.0.0"],
  decided_at: "2026-01-01T00:00:00Z",
  reason: MODERATOR_REASON,
  reverses: "2026/0001-widgets-delist",
  appeal_of: SDI2,
  outcome: "stands",
  severity: "high",
  action: "block_install",
  moderator: "amoderator",
  declared_interest: false,
});

/** The token file's member table for `service_decisions[]`, which is `of[]`. */
function serviceDecisionOf(tokens = JSON.parse(read("schema/contract-tokens-v1.json"))) {
  const record = (tokens.entries ?? []).find((e) => e?.id === `schema:${WORK_SCHEMA}`);
  const member = (record?.members ?? []).find((m) => m?.name === "service_decisions");
  if (!Array.isArray(member?.of) || member.of.length === 0) {
    throw new Error(
      "the token file records no `of[]` for `service_decisions`, so every comparison below would run over an " +
      "empty member set — and a comparison over nothing passes every assertion under it",
    );
  }
  return member.of;
}

/** The readme publishes three requirednesses; a fourth is a file to refuse. */
function fourthValue(member) {
  return new Error(
    `\`${member.name}\` states requiredness ${JSON.stringify(member.required)}, and the token file's readme ` +
    "publishes `true`, `false` and `conditional` and no fourth",
  );
}

/**
 * A member's `when`, as `{kind, predicate}` — `if` or `iff`, never both and
 * never neither, which is the token file's readme verbatim.
 *
 * Throws rather than defaults, for the reason the readme gives: defaulting to
 * `if` drops the forbidding half and defaulting to `iff` forbids what the
 * contract permits, and either reading makes this comparison agree with a
 * statement nobody published.
 */
function readWhen(member) {
  const when = member.when;
  if (when === null || typeof when !== "object" || Array.isArray(when)) {
    throw new Error(`\`${member.name}\` is \`conditional\` and states no \`when\`, which makes the token file malformed`);
  }
  const kinds = ["if", "iff"].filter((k) => k in when);
  if (kinds.length !== 1) {
    throw new Error(`\`${member.name}\` states \`when\` ${JSON.stringify(when)}; a \`when\` is \`if\` or \`iff\``);
  }
  return { kind: kinds[0], predicate: when[kinds[0]] };
}

/**
 * The readme's three predicate shapes and no fourth: `{m: [values]}`,
 * `{m: {not: [values]}}` — which an ABSENT sibling does not satisfy, because
 * `not` is over the values the member may take and a member that is not carried
 * has none — and `{m: "absent"}`.
 */
function predicateHolds(predicate, body) {
  const unreadable = () => new Error(`a \`when\` predicate this test cannot evaluate: ${JSON.stringify(predicate ?? null)}`);
  if (predicate === null || typeof predicate !== "object" || Array.isArray(predicate)) throw unreadable();
  const names = Object.keys(predicate);
  if (names.length !== 1) throw unreadable();
  const [name] = names;
  const rule = predicate[name];
  const carried = Object.hasOwn(body, name);
  if (rule === "absent") return !carried;
  if (Array.isArray(rule)) return carried && rule.includes(body[name]);
  if (rule !== null && typeof rule === "object" && Array.isArray(rule.not) && Object.keys(rule).length === 1) {
    return carried && !rule.not.includes(body[name]);
  }
  throw unreadable();
}

/**
 * What the CONTRACT asks of this member of an entry whose `code` is `code`.
 *
 * A projection onto the `code` axis, and it is only sound because every
 * predicate on this body names `code` — which the test below asserts before it
 * reads a single cell, because a condition decided by a different sibling is
 * not a cell in this table at all.
 */
function tokenVerdict(member, code) {
  if (member.required === true) return "required";
  if (member.required === false) return "optional";
  if (member.required !== "conditional") throw fourthValue(member);
  const { kind, predicate } = readWhen(member);
  const holds = predicateHolds(predicate, code === null ? {} : { code });
  if (holds) return "required";
  return kind === "iff" ? "forbidden" : "optional";
}

/**
 * The member table with every `when` read once, because the corpus reads the
 * table ninety thousand times and a malformed one must be refused before the
 * first body rather than on whichever body happens to reach it.
 */
function compileMembers(entryMembers) {
  return entryMembers.map((member) => {
    if (member.required === true || member.required === false) return { name: member.name, required: member.required };
    if (member.required !== "conditional") throw fourthValue(member);
    return { name: member.name, required: "conditional", ...readWhen(member) };
  });
}

/**
 * Every problem the CONTRACT has with one whole `service_decisions[]` entry.
 *
 * Evaluated against the WHOLE body and not through the `code` projection above,
 * so the corpus sweep is a reading of the token file rather than a reading of
 * this test's idea of it: both halves of a biconditional, and only the
 * requiring half of an `if`, which is what the readme states.
 */
function tokenProblems(compiled, body) {
  const out = [];
  for (const member of compiled) {
    const carried = Object.hasOwn(body, member.name);
    if (member.required !== "conditional") {
      if (member.required && !carried) out.push(`missing ${member.name}`);
      continue;
    }
    const holds = predicateHolds(member.predicate, body);
    if (holds && !carried) out.push(`missing ${member.name}`);
    else if (!holds && carried && member.kind === "iff") out.push(`forbidden ${member.name}`);
  }
  return out;
}

/** `$defs/serviceDecision`, bound to its `$defs` exactly as the run binds it. */
function boundServiceDecision(doc) {
  return { ...doc.$defs.serviceDecision, $defs: doc.$defs };
}

/**
 * What the SCHEMA asks of each member on each code, measured by probing.
 *
 * One member at a time, against a base carrying the schema's own unconditional
 * `required` and nothing else. The result is a claim about a per-member table,
 * and `sweepServiceDecision` proves the claim by replaying it.
 */
function structTable(doc, members, codes) {
  const bound = boundServiceDecision(doc);
  const required = doc.$defs.serviceDecision.required ?? [];
  const table = new Map();
  for (const name of members.filter((m) => m !== "code")) {
    for (const code of codes) {
      const base = { code };
      for (const r of required) if (r !== "code" && r !== name) base[r] = SD_VALUES[r];
      const without = validate(bound, base, "$").length === 0;
      const present = validate(bound, { ...base, [name]: SD_VALUES[name] }, "$").length === 0;
      table.set(`${name}|${code}`,
        present && without ? "optional" : present ? "required" : without ? "forbidden" : "contradiction");
    }
  }
  return table;
}

/**
 * The cells the structural statement makes CONDITIONALLY — everything it says
 * that its own flat `required` array does not already say.
 *
 * Derived from the schema and not listed here, so that a member moving into or
 * out of `required` cannot quietly move a cell out of this set.
 */
function conditionalCells(table, doc) {
  const unconditional = new Set(doc.$defs.serviceDecision.required ?? []);
  return [...table]
    .filter(([cell, verdict]) => verdict !== "optional" && !unconditional.has(cell.split("|")[0]))
    .map(([cell]) => cell)
    .sort();
}

/**
 * Both statements, over every body in the enumerated corpus.
 *
 * ENUMERATED and not sampled: the value space is one code out of a published
 * list (or none) crossed with the presence of every other member, which is
 * small enough to walk whole. Values are held at one schema-valid value each,
 * because a `when` conditions PRESENCE and says nothing about formats, and a
 * second value per member would multiply the corpus to say the same thing.
 */
function sweepServiceDecision(doc, entryMembers, members, codes) {
  const bound = boundServiceDecision(doc);
  const required = doc.$defs.serviceDecision.required ?? [];
  const table = structTable(doc, members, codes);
  const compiled = compileMembers(entryMembers);
  const vary = members.filter((m) => m !== "code");
  const out = {
    corpus: 0, conforming: 0, schemaAccepts: 0, schemaRefuses: 0,
    strictCount: 0, stricter: [], mispredictCount: 0, mispredicts: [], table, vary,
  };
  for (const code of [...codes, null]) {
    for (let mask = 0; mask < 2 ** vary.length; mask++) {
      const body = {};
      if (code !== null) body.code = code;
      vary.forEach((m, i) => { if (mask & (1 << i)) body[m] = SD_VALUES[m]; });
      const errors = validate(bound, body, "$");
      const accepted = errors.length === 0;
      const conforms = tokenProblems(compiled, body).length === 0;
      // Is the per-member table a complete account of what the schema just did?
      const predicted =
        required.every((r) => Object.hasOwn(body, r)) &&
        Object.keys(body).every((m) => m === "code" || code === null || table.get(`${m}|${code}`) !== "forbidden");
      if (predicted !== accepted) {
        out.mispredictCount++;
        if (out.mispredicts.length < 4) out.mispredicts.push({ body, accepted, predicted });
      }
      // The fatal direction: a body the CONTRACT calls conforming and the
      // schema refuses is a lawful answer settled `kind_refused`, for ever.
      if (conforms && !accepted) {
        out.strictCount++;
        if (out.stricter.length < 4) out.stricter.push({ body, why: errors.map((e) => `${e.path} ${e.message}`).join("; ") });
      }
      out.corpus++;
      if (conforms) out.conforming++;
      if (accepted) out.schemaAccepts++; else out.schemaRefuses++;
    }
  }
  return out;
}

/**
 * The two statements, cell by cell.
 *
 * `compared` is the floor: a loop over an `of[]` that went empty compares
 * nothing, and reports every cell as agreeing.
 */
function compareCells(table, entryMembers, codes) {
  const out = { compared: 0, stated: [], disagreements: [], unmeasured: [] };
  for (const member of entryMembers) {
    if (member.name === "code") continue; // the axis, not a cell
    for (const code of codes) {
      const cell = `${member.name}|${code}`;
      const str = table.get(cell);
      const tok = tokenVerdict(member, code);
      out.compared++;
      if (str === "contradiction" || str === undefined) { out.unmeasured.push(cell); continue; }
      if (str === "optional") continue; // the schema states nothing here
      out.stated.push(cell);
      if (str !== tok) out.disagreements.push(`${cell}: the schema says \`${str}\` and the token file says \`${tok}\``);
    }
  }
  return out;
}

test("the entry's members are the same set in the schema and in the token file's `of[]`", () => {
  // The level the comparison above stops one short of, and the precondition for
  // everything below it: two statements about different member sets are not a
  // disagreement about a condition, they are a disagreement about a subject.
  const of = serviceDecisionOf();
  const published = of.map((m) => m.name).sort();
  const schemaSide = schemaMembers("serviceDecision", REPO);
  assert.ok(schemaSide.length >= 10, `only ${schemaSide.length} members read out of $defs/serviceDecision; this is a broken read`);
  assert.deepEqual(schemaSide, published,
    `${SCHEMA_FILE}'s \`$defs/serviceDecision\` members and the token file's \`service_decisions[].of[]\` differ. ` +
    "The comparison above is over the answer's three top-level members and would stay green through this");

  // And the floor under the probe: every member has a schema-valid value, so a
  // `forbidden` verdict below is a condition and never a bad fixture.
  const doc = workSchema(REPO);
  const bound = boundServiceDecision(doc);
  for (const name of schemaSide.filter((m) => m !== "code")) {
    assert.ok(Object.hasOwn(SD_VALUES, name),
      `SD_VALUES has no value for \`${name}\`, so the probe would read it as forbidden on every code`);
  }
  const maximal = Object.fromEntries(schemaSide.filter((m) => m !== "code").map((m) => [m, SD_VALUES[m]]));
  assert.deepEqual(validate(bound, { ...maximal, code: "M_REVOKE" }, "$"), [],
    "the body carrying every member at its fixture value does not validate, so the probe's verdicts are about the values");
  assert.deepEqual(
    validate(bound, { ...maximal, code: "A_YANK" }, "$").map((e) => e.message),
    ["matches a forbidden shape (not)"],
    "the same body on an author code fails for something other than the `not` clause this section is about",
  );
});

test("the structural clause and the token file's `when`s state one condition, and it is the same one", () => {
  const doc = workSchema(REPO);
  const of = serviceDecisionOf();
  const members = schemaMembers("serviceDecision", REPO);
  const codes = [...doc.$defs.serviceDecision.properties.code.enum];

  // ── floors, before anything is compared ──
  assert.ok(codes.length >= 5, `the schema publishes ${codes.length} codes; the corpus has no axis to walk`);
  const conditional = of.filter((m) => m.required === "conditional");
  assert.ok(conditional.length >= 1, "the token file conditions nothing on this body, so there is no second statement to compare");
  // Every predicate names `code`, or the per-code table is the wrong normal form.
  for (const m of conditional) {
    const { predicate } = readWhen(m);
    assert.deepEqual(Object.keys(predicate), ["code"],
      `\`${m.name}\`'s \`when\` is decided by a sibling other than \`code\`, and the table below is indexed by \`code\` alone`);
  }
  // Every code a `when` names must be one the schema publishes, or the schema
  // refuses every entry carrying it on the enum, before any condition is read.
  for (const m of conditional) {
    const rule = readWhen(m).predicate.code;
    for (const v of Array.isArray(rule) ? rule : rule.not ?? []) {
      assert.ok(codes.includes(v),
        `the token file conditions \`${m.name}\` on code \`${v}\`, which ${SCHEMA_FILE}'s enum does not publish — ` +
        "so the schema refuses every entry carrying it before any condition is read");
    }
  }

  const swept = sweepServiceDecision(doc, of, members, codes);
  assert.equal(swept.corpus, 2 ** swept.vary.length * (codes.length + 1));
  assert.ok(swept.corpus > 0, "the corpus is empty, and a comparison over nothing passes every assertion under it");
  assert.ok(swept.conforming > 0,
    "no body in the corpus conforms to the token file, so `conforming implies accepted` is vacuously true below");
  assert.ok(swept.schemaRefuses > 0, "the schema refuses no body in the corpus, so it is not constraining this entry at all");

  // 1 — the reduction is lossless, so the table is a complete account of the
  //     structural statement and the comparison is between two like things.
  assert.equal(swept.mispredictCount, 0,
    `${SCHEMA_FILE}'s structural statement is no longer expressible as a per-(member, code) table — some clause now ` +
    "depends on a COMBINATION of members. Comparing it with a `when`, which cannot say that, would compare the " +
    `wrong thing quietly; teach this reduction the new shape first. ${JSON.stringify(swept.mispredicts)}`);

  // 2 — the schema may never be stricter than the contract.
  assert.equal(swept.strictCount, 0,
    `${SCHEMA_FILE} refuses ${swept.strictCount} bodies the token file calls conforming. BOT-81 makes that refusal ` +
    "FINAL: the entry is settled `kind_refused`, leaves BOT-80's list, pages nobody, and the takedown never lands. " +
    `${JSON.stringify(swept.stricter)}`);

  // 3 — and where it says anything, it says exactly what the contract says,
  //     on exactly the cells production enforces a step earlier.
  //
  // `code` is the axis and is not a cell: it is what every condition on this
  // body is decided by, and both files must ask for it of every entry, or
  // nothing here is indexed by anything.
  assert.equal(tokenVerdict(of.find((m) => m.name === "code"), null), "required");
  assert.ok((doc.$defs.serviceDecision.required ?? []).includes("code"),
    `${SCHEMA_FILE} no longer requires \`code\`, and every condition compared here is decided by it`);

  const cells = compareCells(swept.table, of, codes);
  assert.deepEqual(cells.unmeasured, [], "the probe's base body was itself refused on these cells, so they were not measured");
  assert.equal(cells.compared, of.filter((m) => m.name !== "code").length * codes.length);
  assert.ok(cells.compared > 0, "no cell was compared, and a comparison over nothing agrees with everything");
  assert.deepEqual(cells.disagreements, [],
    "two published statements of one condition disagree. Which of them is right is not this test's call, and " +
    "neither file was edited to make this pass — the disagreement is the finding");

  const enforced = [...new Set(AUTHOR_DENIED_MEMBERS.flatMap((m) => AUTHOR_CODES.map((c) => `${m}|${c}`)))].sort();
  assert.ok(enforced.length > 0, "the compiler's author denylist is empty, so this clause has no cells and asserts nothing");
  assert.deepEqual(conditionalCells(swept.table, doc), enforced,
    "the cells the schema states CONDITIONALLY and the rule `bot/lib/compile-decision.mjs` enforces a step earlier " +
    "are no longer the same set. Either the structural clause lost a member the compiler still denies, or it gained " +
    "one the compiler does not");
  assert.ok(cells.stated.length > enforced.length,
    `only ${cells.stated.length} of ${cells.compared} cells are stated at all, and the schema's unconditional ` +
    "`required` should put more than the conditional ones there; this is a broken read of the table");
});

test("both statements of the condition are watched, in both directions, over a corpus that cannot go empty", () => {
  // Mutated copies, never the files: a mutation of a real file would leave the
  // repository broken if this process died between the edit and the restore.
  const doc = workSchema(REPO);
  const of = serviceDecisionOf();
  const members = schemaMembers("serviceDecision", REPO);
  const codes = [...doc.$defs.serviceDecision.properties.code.enum];
  const enforced = [...new Set(AUTHOR_DENIED_MEMBERS.flatMap((m) => AUTHOR_CODES.map((c) => `${m}|${c}`)))].sort();
  const table = structTable(doc, members, codes);

  // ── red 1: the structure loosened while the `when` stands ──
  //
  // One `{required: [...]}` out of the `not`'s `anyOf`. The schema now accepts
  // an author's own yank carrying a moderator's conflict declaration, which
  // DEC-14 and MOD-41 forbid reaching the public log — and nothing in the
  // clauses above is STRICTER, because the schema only got looser. This is the
  // direction a one-way soundness check cannot see, and why the cells the
  // schema states are tied to the rule the compiler enforces.
  const loosened = JSON.parse(JSON.stringify(doc));
  loosened.$defs.serviceDecision.not.allOf[1].anyOf =
    loosened.$defs.serviceDecision.not.allOf[1].anyOf.filter((a) => !a.required.includes("declared_interest"));
  const afterStruct = structTable(loosened, members, codes);
  assert.deepEqual(conditionalCells(table, doc), enforced, "the unmutated schema does not state the enforced cells");
  assert.notDeepEqual(conditionalCells(afterStruct, loosened), enforced,
    "the `not` clause dropped `declared_interest` and the cells it states still match the compiler's denylist, " +
    "so the section above would stay green while an author yank carrying a conflict declaration is accepted");
  for (const code of AUTHOR_CODES) {
    assert.equal(afterStruct.get(`declared_interest|${code}`), "optional");
    assert.equal(tokenVerdict(of.find((m) => m.name === "declared_interest"), code), "forbidden",
      "the token file stopped forbidding it too, so this mutation is no longer a disagreement between two files");
  }
  // And the corpus is blind to it, which is the whole reason for the third
  // clause: a looser schema refuses no conforming body.
  assert.equal(sweepServiceDecision(loosened, of, members, codes).strictCount, 0);

  // ── red 2: the `when` loosened while the structure stands ──
  //
  // `iff` to `if` drops the forbidding half, which is the looser reading the
  // vocabulary exists to close. The contract now permits a moderator on an
  // author yank; the schema still refuses one; and a lawful answer would be
  // settled `kind_refused`, finally, in production.
  const relaxed = JSON.parse(JSON.stringify(of));
  const moderator = relaxed.find((m) => m.name === "moderator");
  moderator.when = { if: moderator.when.iff };
  assert.equal(tokenVerdict(moderator, "A_YANK"), "optional");
  const afterWhen = sweepServiceDecision(doc, relaxed, members, codes);
  assert.ok(afterWhen.strictCount > 0,
    "`moderator`'s `iff` became an `if` and the corpus found no body on which the two statements now differ");
  assert.ok(compareCells(table, relaxed, codes).disagreements.some((d) => d.startsWith("moderator|A_YANK")),
    "the cell comparison agrees after the forbidding half was dropped");

  // The other way a `when` loosens: a code leaves the condition's `not` list,
  // so the contract REQUIRES on `A_YANK` what the schema forbids there.
  const narrowed = JSON.parse(JSON.stringify(of));
  const di = narrowed.find((m) => m.name === "declared_interest");
  di.when.iff.code.not = di.when.iff.code.not.filter((c) => c !== "A_YANK");
  assert.equal(tokenVerdict(di, "A_YANK"), "required");
  assert.ok(sweepServiceDecision(doc, narrowed, members, codes).strictCount > 0,
    "`A_YANK` left the condition's `not` list and no corpus body separates the two statements");
  assert.ok(compareCells(table, narrowed, codes).disagreements.some((d) => d.startsWith("declared_interest|A_YANK")));

  // ── the floor: a comparison over nothing agrees with everything ────────────
  //
  // Shown rather than argued, and one half of it is better than expected. An
  // `of[]` that went empty does NOT slip past the corpus sweep: with no members
  // the contract asks nothing, every body conforms, and the schema's own
  // refusals become counterexamples in their thousands.
  const empty = sweepServiceDecision(doc, [], members, codes);
  assert.equal(empty.conforming, empty.corpus, "with no members the contract asks nothing and every body conforms");
  assert.ok(empty.strictCount > 1000,
    "an empty member table is expected to make the corpus sweep loudly red, and it did not");

  // The cell comparison is the half that WOULD go quiet, so it counts.
  assert.equal(compareCells(table, [], codes).compared, 0,
    "an empty member table compares no cells, and every assertion over that list is true of nothing");
  assert.deepEqual(compareCells(table, [], codes).disagreements, [],
    "a comparison over no cells reports no disagreement, which is the point of the floor above it");

  // So the reader refuses an empty `of[]` outright rather than comparing over
  // it, and refuses a record that lost its `service_decisions` member too.
  const record = { id: `schema:${WORK_SCHEMA}`, members: [{ name: "service_decisions", of: [] }] };
  assert.throws(() => serviceDecisionOf({ entries: [record] }), /passes every assertion under it/,
    "an empty `of[]` is read as a member table rather than refused");
  assert.throws(() => serviceDecisionOf({ entries: [{ id: record.id, members: [{ name: "shadow" }] }] }),
    /passes every assertion under it/, "a record with no `service_decisions` member is read as one with no conditions");
  assert.throws(() => serviceDecisionOf({ entries: [] }), /passes every assertion under it/,
    "a token file with no record for this schema at all is read as one that conditions nothing");

  // And the corpus cannot shrink to nothing unnoticed: it is the product of the
  // members varied and the codes walked, and both are derived from the files.
  const axisOnly = sweepServiceDecision(doc, of, ["code"], codes);
  assert.equal(axisOnly.corpus, codes.length + 1);
  assert.equal(axisOnly.conforming, 0,
    "with every member but the axis gone no body conforms, so `conforming implies accepted` has nothing to check — " +
    "which is why the section above floors `conforming > 0` before trusting it");
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
  // decision OBJECT: `held()` returns it, and the commit job's
  // `writeHoldEntries` puts it into `state/holds/<id>.json` through
  // `holdEntry`, where `schema/hold-v1.json`'s `additionalProperties: false`
  // would refuse it — on the NEXT run, reading back a file this one already
  // committed, which that schema's own description says is too late to be the
  // defence.
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

// The commit job, end to end through `main`, on the path the workflow runs.
// Until this test, no test passed a held decision to `composeCommit`, and the
// one sentence about the file (above, at the held-decision allowlist test) said
// `held()` wrote it. Nothing did: `paths.txt` named `state/holds/<id>.json`,
// the tree had no such file, and `git add --pathspec-from-file` — the next
// command the workflow runs — exits 128 on a path that does not exist. Measured
// before the repair on this same shape: `main` returned 0, and the add died.
async function commitJob(root, { entries, shadow = false, now = new Date("2026-09-20T12:30:00Z") }) {
  const out = path.join(root, "moderation");
  const logs = [];
  const saved = globalThis.fetch;
  const offline = () => {
    throw new Error("the commit job reached the network; it holds contents: write and therefore no bot token (BOT-2)");
  };
  globalThis.fetch = offline;
  try {
    const code = await main(["--job", "commit", "--registry-dir", root, "--out", out], {
      env: {
        ASTRA_ENTRIES: JSON.stringify(entries),
        ASTRA_SUBMISSIONS: "[]",
        ASTRA_SHADOW: shadow ? "true" : "false",
        ASTRA_OVER_BOUND: "false",
        GITHUB_RUN_ID: "35502265394",
      },
      log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
      fetchImpl: offline,
      now,
    });
    const paths = fs.readFileSync(path.join(out, "paths.txt"), "utf8").split("\n").filter(Boolean);
    const results = JSON.parse(fs.readFileSync(path.join(out, "results.json"), "utf8"));
    return { code, logs, paths, results };
  } finally {
    globalThis.fetch = saved;
  }
}

test("a batch with one held decision leaves a tree in which every `paths.txt` entry exists", async () => {
  for (const shadow of [false, true]) {
    const root = estate();
    const relist = decision({ code: "M_RELIST", category: "error", moderator: "amoderator", reverses: SDI2, x: "leaked" });
    const delist = decision({ service_decision_id: SDI2, code: "M_DELIST", category: "broken", moderator: "amoderator" });
    const { code, logs, paths, results } = await commitJob(root, { entries: [relist, delist], shadow });
    assert.equal(code, 0, logs.join("\n"));
    assert.equal(results.held.length, 1, "MOD-9 holds every M_RELIST, so this batch holds one or it proves nothing");
    assert.ok(paths.includes(holdEntryPath(SDI)), `paths.txt does not list the hold entry: ${paths.join(", ")}`);

    for (const p of paths) {
      assert.ok(fs.existsSync(path.join(root, p)),
        `paths.txt names ${p} and the commit job left no such file (shadow: ${shadow}). The workflow's next command is ` +
        "git add --pathspec-from-file, which exits 128 on it — the run commits nothing, and the held result it posts " +
        "names a hold no file records");
    }
    // The workflow's own command, over the tree the job left.
    const add = spawnSync("git", ["add", "--pathspec-from-file=moderation/paths.txt"], { cwd: root, encoding: "utf8" });
    assert.equal(add.status, 0, `git add --pathspec-from-file exited ${add.status}: ${add.stderr}`);

    // The entry is one the next run can read, released on the rule MOD-9 states.
    const holds = readHolds(root);
    assert.equal(holds.length, 1);
    assert.deepEqual(holds[0].problems, [], holds[0].problems.join("; "));
    assert.equal(holds[0].entry.held_for, "reversal");
    assert.equal(holds[0].entry.held_at, "2026-09-20T12:30:00Z");
    assert.equal(holds[0].entry.release_after, "2026-09-21T12:30:00Z");
    assert.ok(!fs.readFileSync(path.join(root, holdEntryPath(SDI)), "utf8").includes("leaked"),
      "a member the schema ignored on read reached the committed hold entry");

    // Listed again because the `held` result never landed: the entry stays
    // byte for byte, so `held_at` does not move and the 24 hours do not restart,
    // and it is not listed for a commit that would then carry no change.
    const before = fs.readFileSync(path.join(root, holdEntryPath(SDI)));
    const again = await commitJob(root, { entries: [relist], shadow, now: new Date("2026-09-20T12:40:00Z") });
    assert.equal(again.code, 0, again.logs.join("\n"));
    assert.ok(before.equals(fs.readFileSync(path.join(root, holdEntryPath(SDI)))), "a re-listed hold rewrote its entry");
    assert.ok(!again.paths.includes(holdEntryPath(SDI)), "an unchanged hold entry was listed for the commit");
    assert.deepEqual(again.results.holds_kept, [holdEntryPath(SDI)]);
  }
});

// BOT-70: deleting the file is how a person with no tooling ends a hold, and
// the commit that deleted it is the record. `readHolds` sees only entries still
// on the tree, so until `holdDeletions` a deleted hold was never classified, the
// service kept it `held` for ever, and `classifyHoldCommit` — BOT-70's reading —
// was called by nothing but its own unit test. Every shape the classifier
// distinguishes is committed here, plus the two a BOT-73 batch commit makes
// possible: a trailer for ANOTHER decision, and an entry that came back.
test("a deleted hold is classified and reported, against the commit that deleted it", async () => {
  const id = (n) => `0192f3a4-5b6c-7d8e-9f01-23456789100${n}`;
  const [HAND, UNCLEAR, CANCEL, RELEASE, OTHER, BACK] = [1, 2, 3, 4, 5, 6].map(id);
  const entryFor = (sdi) => holdEntry({
    service_decision_id: sdi, code: "M_RELIST", category: "error", plugin_id: "widgets",
    decided_at: "2026-09-18T11:00:00Z", reason: MODERATOR_REASON, moderator: "amoderator", reverses: SDI2,
  }, { held_for: "reversal", held_at: "2026-09-18T12:00:00Z" });
  const extra = {};
  for (const sdi of [HAND, UNCLEAR, CANCEL, RELEASE, OTHER, BACK]) extra[holdEntryPath(sdi)] = entryFor(sdi);
  const root = estate({ extra });
  const logEntry = (sdi, n) => ({ [`bot/moderation/2026-09-21-widgets-relist${n ? `-${n}` : ""}.json`]:
    { date: "2026-09-21", action: "relist", plugin: "widgets", reason: MODERATOR_REASON, ...(sdi ? { service_decision_id: sdi } : {}) } });
  const commit = (message, { rm = [], add = {} } = {}) => {
    for (const r of rm) sh(["rm", "-q", r], root);
    writeAll(root, add);
    sh(["add", "-A"], root);
    sh(["commit", "-q", ...message.flatMap((m) => ["-m", m])], root);
    return sh(["rev-parse", "HEAD"], root).trim();
  };
  const sha = {};
  sha.hand = commit(["tidy the holds directory"], { rm: [holdEntryPath(HAND)] });
  sha.unclear = commit(["relist widgets by hand"], { rm: [holdEntryPath(UNCLEAR)], add: logEntry(null, 0) });
  sha.cancel = commit(["registry: cancel a hold", `Service-Decision: ${CANCEL}`], { rm: [holdEntryPath(CANCEL)] });
  sha.release = commit(["registry: release a hold", `Run: 1\nService-Decision: ${RELEASE}`], { rm: [holdEntryPath(RELEASE)], add: logEntry(RELEASE, 2) });
  sha.other = commit(["registry: moderation (2 decision(s))", `Run: 2\nService-Decision: ${SDI}`], { rm: [holdEntryPath(OTHER)], add: logEntry(SDI, 3) });
  commit(["tidy again"], { rm: [holdEntryPath(BACK)] });
  commit(["held again"], { add: { [holdEntryPath(BACK)]: entryFor(BACK) } });

  const gone = new Map(holdDeletions(root, { present: new Set([BACK]) }).map((g) => [g.id, g]));
  assert.deepEqual([...gone.keys()].sort(), [HAND, UNCLEAR, CANCEL, RELEASE, OTHER].sort(),
    "the reader must return every entry that left the tree and none that came back");
  assert.deepEqual(gone.get(OTHER).trailers, {}, "a trailer naming another decision was read as this one's");
  assert.equal(gone.get(OTHER).writesLogEntry, false, "a log entry naming another decision was read as this one's");
  assert.equal(gone.get(UNCLEAR).writesLogEntry, true, "a log entry naming no decision must count, or a hand application reads as a cancel");

  const holds = walkHolds({ root, now: new Date("2026-09-18T13:00:00Z"), shadow: false });
  const row = (list, sdi) => holds[list].find((r) => r.service_decision_id === sdi);
  assert.ok(row("cancelled", HAND)?.hand, `a hand deletion was not reported as a hand cancellation: ${JSON.stringify(holds)}`);
  assert.equal(row("cancelled", HAND).commit, sha.hand, "a hand cancellation must name the commit that made it (BOT-70)");
  assert.equal(row("cancelled", CANCEL)?.hand, false, "a trailered cancel commit was reported as a hand cancellation");
  assert.equal(row("released", RELEASE)?.outcome, "applied", "a release commit was not recognised");
  assert.ok(row("cancelled", OTHER)?.hand, "a deletion under another decision's trailer is a hand cancellation of this one");
  assert.ok(row("unclear", UNCLEAR), "a deletion with a log entry and no trailer was not reported as unclear");
  assert.ok(!holds.pending.some((p) => p.service_decision_id === UNCLEAR), "an unclear deletion was given a result to post");
  assert.ok(row("waiting", BACK), "an entry that is on the tree again is a live hold, not a cancelled one");
  assert.ok(!holds.cancelled.some((r) => r.service_decision_id === BACK), "an entry that came back was reported from its old deletion");
  assert.deepEqual(holds.alerts.map((a) => `${a.kind} ${a.service_decision_id}`).sort(),
    [`hold_hand_cancelled ${HAND}`, `hold_hand_cancelled ${OTHER}`, `hold_unclear ${UNCLEAR}`].sort(),
    "a hand cancellation and an unclear deletion each alert, and nothing else does");

  // Posted against the commit that ended it, in a live run, and only there.
  const live = resultsFor({ holds, shadow: false, commit: "f".repeat(40) });
  const posted = new Map(live.post.map((r) => [r.service_decision_id, r]));
  assert.deepEqual([...posted.keys()].sort(), [HAND, CANCEL, RELEASE, OTHER].sort());
  for (const [sdi, key] of [[HAND, "hand"], [CANCEL, "cancel"], [RELEASE, "release"], [OTHER, "other"]]) {
    assert.equal(posted.get(sdi).commit, sha[key],
      "a result for a hold ended in history must carry that commit, or every re-post is a new BOT-82 key");
  }
  const shadowRun = resultsFor({ holds, shadow: true });
  assert.deepEqual(shadowRun.post, [], "an applied or cancelled result settles a decision, which BOT-92 withholds in shadow");
  assert.equal(shadowRun.withheld.length, 4);

  // And the job reports it: results.json carries the rows, and the log says so.
  const job = await commitJob(root, { entries: [] });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.equal(job.results.holds.unclear.length, 1);
  assert.equal(job.results.holds.cancelled.length, 3);
  assert.ok(job.logs.some((l) => l.startsWith("::error::hold_unclear") && l.includes(sha.unclear)),
    `the commit job did not say that ${sha.unclear} left a hold unclear: ${job.logs.join(" | ")}`);

  // A depth-1 clone cannot see the deletions, and says so rather than seeing none.
  const shallow = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-shallow-"));
  tmpRoots.push(shallow);
  sh(["clone", "-q", "--depth", "1", `file://${root}`, shallow], os.tmpdir());
  assert.throws(() => holdDeletions(shallow), /shallow clone/);
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

// ── the commit step, run as the workflow runs it ────────────────────────────

/**
 * The `run:` block of `plugins-moderation.yml`'s step `id: apply`, verbatim —
 * the lines that `git add`, `git commit` and `git push` what the commit job
 * listed. Read from the file rather than restated here, so that the step this
 * suite runs is the step the workflow runs; it throws unless the anchor and
 * its `run: |` are each found exactly once.
 */
function applyStep() {
  const lines = read(".github/workflows/plugins-moderation.yml").split("\n");
  const at = lines.flatMap((l, i) => (/^\s+id: apply\s*$/.test(l) ? [i] : []));
  assert.equal(at.length, 1, `plugins-moderation.yml has ${at.length} steps with \`id: apply\`; this suite runs exactly one`);
  const indent = lines[at[0]].search(/\S/);
  const runs = [];
  for (let j = at[0] + 1; j < lines.length; j++) {
    if (lines[j].trim() === "") continue;
    if (lines[j].search(/\S/) < indent) break;
    if (lines[j].search(/\S/) === indent && /^\s+run: \|\s*$/.test(lines[j])) runs.push(j);
  }
  assert.equal(runs.length, 1, `the \`apply\` step has ${runs.length} \`run: |\` blocks`);
  const body = [];
  for (let j = runs[0] + 1; j < lines.length; j++) {
    if (lines[j].trim() !== "" && lines[j].search(/\S/) <= indent) break;
    body.push(lines[j].slice(indent + 2));
  }
  const script = `${body.join("\n").trimEnd()}\n`;
  assert.match(script, /^git push origin HEAD:main$/m, "the extracted step does not push; the anchor found something else");
  return script;
}

/** A bare `origin` the fixture pushes to, so the step's `git push` runs for real. */
function withRemote(root) {
  const bare = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-origin-"));
  tmpRoots.push(bare);
  sh(["init", "-q", "--bare", "-b", "main"], bare);
  sh(["remote", "add", "origin", bare], root);
  sh(["push", "-q", "origin", "main"], root);
  return bare;
}
const headOf = (repo) => sh(["rev-parse", "refs/heads/main"], repo).trim();

/** The step, under `bash -e` as a runner starts a `run:` block, in the checkout. */
function runApply(root) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-step-"));
  tmpRoots.push(dir);
  const file = path.join(dir, "apply.sh");
  fs.writeFileSync(file, applyStep());
  return spawnSync("bash", ["-e", file], { cwd: root, encoding: "utf8" });
}

// Until 2026-09-22 a run with nothing to commit — no work listed and no hold
// due, which is most runs — failed the commit step. The job wrote `paths.txt`
// as a single newline and no `commit-message.txt`; `git add
// --pathspec-from-file` exited 128 on the empty line ("empty string is not a
// valid pathspec") and `git commit --file=` exited 128 on the missing file.
// Nothing caught it because the step has never run and no test ran the
// workflow's lines over what the job leaves behind. This one does, with a real
// `origin` to push to, in both directions: nothing is a clean no-op, and
// something is still committed and pushed. It also covers the two states that
// must NOT read as nothing.
test("a run with nothing to commit leaves the commit step nothing to fail on", async () => {
  for (const shadow of [false, true]) {
    const root = estate();
    const origin = withRemote(root);
    const before = headOf(origin);
    const job = await commitJob(root, { entries: [], shadow });
    assert.equal(job.code, 0, job.logs.join("\n"));
    assert.equal(fs.readFileSync(path.join(root, "moderation", "paths.txt"), "utf8"), "",
      "with nothing to commit, paths.txt is the empty marker: zero bytes, no empty pathspec in it");
    assert.ok(!fs.existsSync(path.join(root, "moderation", "commit-message.txt")));
    const step = runApply(root);
    assert.equal(step.status, 0, `the commit step failed a run with nothing to commit (shadow: ${shadow}): ${step.stderr}`);
    assert.match(step.stdout, /^nothing to commit/m);
    assert.equal(headOf(origin), before, "a run with nothing to commit pushed");
    assert.equal(sh(["rev-parse", "HEAD"], root).trim(), before, "a run with nothing to commit made a commit");
  }

  // The satisfiable direction, by the same lines: a takedown is committed,
  // with exactly the listed paths and its trailer, and pushed.
  const root = estate();
  const origin = withRemote(root);
  const before = headOf(origin);
  const job = await commitJob(root, { entries: [decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" })] });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.ok(job.paths.length >= 2, `the takedown listed ${job.paths.length} path(s)`);
  const step = runApply(root);
  assert.equal(step.status, 0, `the commit step failed a run with a takedown to commit: ${step.stderr}`);
  const after = headOf(origin);
  assert.notEqual(after, before, "the commit step pushed nothing for a run with a takedown to commit");
  assert.deepEqual(sh(["diff-tree", "--no-commit-id", "--name-only", "-r", after], origin).trim().split("\n").sort(), job.paths);
  assert.match(sh(["log", "-1", "--format=%B", after], origin), new RegExp(`^Service-Decision: ${SDI}$`, "m"));

  // Then a quiet run in the SAME output directory: the last run's message
  // must not survive into it, and the step is a no-op again.
  const quiet = await commitJob(root, { entries: [] });
  assert.equal(quiet.code, 0, quiet.logs.join("\n"));
  assert.ok(!fs.existsSync(path.join(root, "moderation", "commit-message.txt")),
    "a stale commit-message.txt survived into a run with nothing to commit");
  const again = runApply(root);
  assert.equal(again.status, 0, `the commit step failed the quiet run after a commit: ${again.stderr}`);
  assert.equal(headOf(origin), after);

  // What "nothing" must not be mistaken for. A job that never wrote paths.txt
  // did not say it had nothing; and an empty list beside a message is a job
  // whose two outputs disagree. Both fail the step, and neither pushes.
  const lost = estate();
  const lostOrigin = withRemote(lost);
  const missing = runApply(lost);
  assert.notEqual(missing.status, 0, "a missing paths.txt was read as a run with nothing to commit");
  assert.match(missing.stdout, /^::error::the commit job left no moderation\/paths\.txt/m);
  fs.mkdirSync(path.join(lost, "moderation"));
  fs.writeFileSync(path.join(lost, "moderation", "paths.txt"), "");
  fs.writeFileSync(path.join(lost, "moderation", "commit-message.txt"), "registry: moderation (1 decision(s))\n");
  const odd = runApply(lost);
  assert.notEqual(odd.status, 0, "an empty path list beside a commit message was read as nothing to commit");
  assert.equal(headOf(lostOrigin), sh(["rev-parse", "HEAD"], lost).trim(), "a refused step pushed");
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
