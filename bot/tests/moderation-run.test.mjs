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
// `schema/contract-tokens-v1.json` carried `fixed_reasons: null` until contract
// 2.3.0 (ops.15). Every fixture here writes its own two strings, so no test
// here depends on `main`'s; `compile-decision.test.mjs` reads `main`'s.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { fixtureEnv } from "../../tools/lib/git-env.mjs";
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
  entryCommit,
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
import { holdEntry, readHolds, resolveHold } from "../lib/holds.mjs";
import { decisionId, recordPath } from "../lib/decisions.mjs";
import { compareWithBaseline, identityFromCertificate } from "../lib/identity.mjs";
import { baselineFor } from "../lib/service-decide.mjs";
import { listingStateAt } from "../lib/listing-state.mjs";
import { checkEntry } from "../lib/moderation.mjs";
import { detect } from "../detectors.mjs";
import { loadRecords } from "../../tools/lib/sources.mjs";
// What ops entry 101 added, off the namespaces, so that this suite run against
// modules without them is red test by test rather than at import.
import * as holdsModule from "../lib/holds.mjs";
import * as moderationRun from "../moderation-run.mjs";
// Ops entry 100's module, imported so that this suite, run against a tree
// without it, is red test by test rather than at import.
const settledLib = await import("../lib/settled.mjs").catch(() => null);
import { CATEGORIES, TAKEDOWN_BOUND } from "../lib/moderation.mjs";
import { BOT_AUDIENCE } from "../lib/oidc.mjs";
import { BODIES } from "../lib/service.mjs";
import { buildIndex } from "../../tools/build-index.mjs";
import { stableStringify } from "../../tools/lib/canonical.mjs";
import { ID_PATTERN } from "../../tools/lib/ids.mjs";
import {
  ACTIONS,
  OUTPUT_FILE as REVOCATIONS_FILE,
  SEVERITIES,
  SOURCE_DIR as REVOCATIONS_DIR,
  buildRevocations,
} from "../../tools/lib/revocations.mjs";
import { validate } from "../../tools/lib/jsonschema.mjs";
import { serialsAt } from "../../tools/signer/plan.mjs";

/** Where `tools/build-index.mjs` writes the catalogue; its CLI states it as this literal. */
const INDEX_FILE = "registry/v1/index.json";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const read = (rel) => fs.readFileSync(path.join(REPO, rel), "utf8");

const tmpRoots = [];
process.on("exit", () => {
  for (const dir of tmpRoots) fs.rmSync(dir, { recursive: true, force: true });
});

// `when` is `dated(iso)`'s two dates, or nothing; the rest of the environment is
// a fixture's (tools/lib/git-env.mjs), so no inherited GIT_DIR can take the command.
const sh = (args, cwd, when = null) => execFileSync("git", args, {
  cwd, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8",
  env: {
    ...fixtureEnv(cwd),
    ...(when ? { GIT_AUTHOR_DATE: when.GIT_AUTHOR_DATE, GIT_COMMITTER_DATE: when.GIT_COMMITTER_DATE } : {}),
  },
});
/** Both of a commit's clocks at one instant, for a fixture whose history says when. */
const dated = (iso) => ({ GIT_COMMITTER_DATE: iso, GIT_AUTHOR_DATE: iso });

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
function estate({ versions = ["1.0.0", "1.1.0", "1.2.0"], bound = true, id = "widgets", extra = {}, at = null } = {}) {
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
  sh(["commit", "-q", "-m", "fixture"], root, at ? dated(at) : null);
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

// Until 2026-09-22 this test was named "with `list` down a confirmed reversal
// still releases, and posts next run", and it passed by asserting a REPORT:
// `released` held one row with outcome `applied`, and a live `resultsFor`
// posted it against the run's commit. Nothing released anything — the job
// never applied the held decision nor deleted the entry, because M-T3.3's
// release commit is not built — so the service would have been told a relist
// landed in a commit that left `unlisted: true`. The plan's canary for M-T3.4
// ("with `list` down, a confirmed reversal releases and posts next run") is
// therefore NOT met today, and this test now asserts what is true instead: the
// hold is due, it is refused by name, and nothing is posted for it. The builder
// of the release commit turns this back into the plan's canary.
test("a confirmed, due hold that nothing applies is refused by name, never reported `applied`", async () => {
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
  const cancel = { ...confirm, act: "cancel" };
  const delisted = { [`plugins/widgets/plugin.json`]: plugin("widgets", { unlisted: true }) };

  // Both ends a hold can come to while its entry is still on the tree: a
  // reversal confirmed past its period (release), and a cancel record
  // (cancel). Neither commit is built, and each would have been reported.
  for (const [end, record, wouldPost] of [["release", confirm, "applied"], ["cancel", cancel, "cancelled"]]) {
    // Committed at `held_at`: a reversal's 24 hours run from the commit that
    // added its entry (MOD-9, ops entry 101), so a fixture committed at the
    // wall clock would be a hold entered in the future of `now` below.
    const root = estate({
      extra: {
        ...delisted,
        [`state/holds/${SDI}.json`]: held,
        [`state/holds/${SDI}.${record.act}.json`]: record,
      },
      at: held.held_at,
    });

    for (const shadow of [true, false]) {
      const walked = walkHolds({ root, now: new Date("2026-09-20T00:00:00Z"), shadow });
      // The satisfiable half first: the hold IS due, or this proves nothing.
      assert.deepEqual(walked.due.map((d) => `${d.act} ${d.would_post}`), [`${end} ${wouldPost}`],
        `the fixture's hold should be due to ${end} (shadow: ${shadow}): ${JSON.stringify(walked)}`);
      assert.deepEqual(walked.released, [], `a ${end} nothing performed was reported as released`);
      assert.deepEqual(walked.cancelled, [], `a ${end} nothing performed was reported as cancelled`);
      assert.deepEqual(walked.pending, [], `a ${end} nothing performed was given a result to post`);
      assert.deepEqual(walked.alerts.map((a) => `${a.kind} ${a.service_decision_id}`), [`hold_end_not_built ${SDI}`],
        "a due hold nothing ends must be said, every run, or it waits in silence");
      const posted = resultsFor({ holds: walked, shadow, commit: "c".repeat(40) });
      assert.deepEqual(posted.post, [], `\`${wouldPost}\` was posted for a ${end} no commit performed (BOT-81)`);
    }

    // Through the job, on the path the workflow runs: nothing listed, the
    // listing and the entry exactly as they were, and the refusal in the log.
    const job = await commitJob(root, { entries: [], now: new Date("2026-09-20T00:00:00Z") });
    assert.equal(job.code, 0, job.logs.join("\n"));
    assert.deepEqual(job.paths, []);
    assert.equal(JSON.parse(fs.readFileSync(path.join(root, "plugins/widgets/plugin.json"), "utf8")).unlisted, true);
    assert.ok(fs.existsSync(path.join(root, holdEntryPath(SDI))), "the hold entry left the tree");
    assert.ok(job.logs.some((l) => l.startsWith(`::error::hold_end_not_built ${SDI}:`)),
      `the commit job did not refuse the due ${end} by name: ${job.logs.join(" | ")}`);
    assert.deepEqual(resultsFor({ holds: job.results.holds, shadow: false, commit: "c".repeat(40) }).post, []);
  }
});

// The commit job, end to end through `main`, on the path the workflow runs.
// Until this test, no test passed a held decision to `composeCommit`, and the
// one sentence about the file (above, at the held-decision allowlist test) said
// `held()` wrote it. Nothing did: `paths.txt` named `state/holds/<id>.json`,
// the tree had no such file, and `git add --pathspec-from-file` — the next
// command the workflow runs — exits 128 on a path that does not exist. Measured
// before the repair on this same shape: `main` returned 0, and the add died.
async function commitJob(root, { entries, submissions = [], shadow = false, now = new Date("2026-09-20T12:30:00Z"), env = {} }) {
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
        ASTRA_SUBMISSIONS: JSON.stringify(submissions),
        ASTRA_SHADOW: shadow ? "true" : "false",
        ASTRA_OVER_BOUND: "false",
        GITHUB_RUN_ID: "35502265394",
        ...env,
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

// Live only. It ran in shadow too until 2026-09-22, and asserted there that
// the hold entry WAS written and listed — which BOT-92 forbids: entering a hold
// is a commit for the decision the answer names. The shadow half is now the
// next test's, which asserts the opposite.
test("a batch with one held decision leaves a tree in which every `paths.txt` entry exists", async () => {
  for (const shadow of [false]) {
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
    const add = spawnSync("git", ["add", "--pathspec-from-file=moderation/paths.txt"], {
      cwd: root, encoding: "utf8", env: fixtureEnv(root),
    });
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

// BOT-92: "the bot MUST commit nothing for the work that answer names (no
// publication, decision, identity or queue record for it) and post no
// state-setting result"; its Check, "a run with no commit for that work and no
// posted result". Until 2026-09-22 the commit job withheld only the posting:
// under `shadow: true` it wrote and listed a compiled M_DELIST's listing edit
// and log entry, a held decision's entry and a stop's terminal record, printed
// "nothing new is committed for the work this answer names", and the
// workflow's own `git add`/`git commit` lines then committed the takedown.
//
// So the property is stated against a LIVE run of the same batch, which is the
// only way to say "nothing": the live run's `paths.txt` is the list of what a
// shadow run must not commit, and the live run is required to reach every one
// of the three writers first — a batch that only exercised one would let the
// other two write in shadow with this test green.
test("a shadow run commits nothing a live run would", async () => {
  const batch = {
    entries: [
      // compiled: the listing edit and the log entry
      decision({ service_decision_id: SDI2, code: "M_DELIST", category: "broken", moderator: "amoderator" }),
      // held (MOD-9 holds every M_RELIST): the hold entry
      decision({ code: "M_RELIST", category: "error", moderator: "amoderator", reverses: SDI2 }),
    ],
    // a stop: BOT-30's terminal decision record
    submissions: [{
      submission_id: SUB, repo: "acme/widgets", tag: "widgets-v1.0.0", trigger: "panel",
      service_repository_id: "912345678", stop_status: "stopped", fingerprints: [], code: "R_FIRST_LISTING",
    }],
  };
  const dirty = (root) => sh(["status", "--porcelain", "--untracked-files=all"], root)
    .split("\n").filter(Boolean).filter((l) => !/^\?\? moderation\//.test(l));

  const liveRoot = estate();
  const live = await commitJob(liveRoot, { ...batch, shadow: false });
  assert.equal(live.code, 0, live.logs.join("\n"));
  // The floor: every writer reached, or "nothing" below is a smaller claim.
  for (const [what, test] of [
    ["the compiled listing edit", (p) => p === "plugins/widgets/plugin.json"],
    ["the compiled log entry", (p) => p.startsWith("bot/moderation/")],
    ["the hold entry", (p) => p === holdEntryPath(SDI)],
    ["the stop's terminal record", (p) => p.startsWith("log/decisions/")],
  ]) {
    assert.ok(live.paths.some(test), `the live run did not commit ${what}, so the shadow run is not tested on it: ${live.paths.join(", ")}`);
  }
  assert.ok(dirty(liveRoot).length >= 4, "the live run wrote nothing to its tree");

  const shadowRoot = estate();
  const shadow = await commitJob(shadowRoot, { ...batch, shadow: true });
  assert.equal(shadow.code, 0, shadow.logs.join("\n"));
  const leaked = shadow.paths.filter((p) => live.paths.includes(p));
  assert.deepEqual(leaked, [], `a shadow run listed for its commit what a live run commits (BOT-92): ${leaked.join(", ")}`);
  assert.deepEqual(shadow.paths, [], "a shadow run with no due hold has nothing to commit at all");
  assert.deepEqual(dirty(shadowRoot), [],
    "a shadow run wrote to the tree; the workflow's gates and `git add` run over that tree, so a write is one step from a commit");

  // And nothing `report` could post: the members it reads are empty, what the
  // run would have done is recorded apart, and a shadow `resultsFor` over the
  // job's own state posts nothing — no `applied`, and no `held` either.
  assert.deepEqual(
    { compiled: shadow.results.compiled, held: shadow.results.held, refused: shadow.results.refused,
      written: shadow.results.written, terminal: shadow.results.terminal },
    { compiled: [], held: [], refused: [], written: [], terminal: [] },
  );
  assert.deepEqual(shadow.results.shadow_withheld.compiled, [SDI2]);
  assert.deepEqual(shadow.results.shadow_withheld.held.map((h) => h.service_decision_id), [SDI]);
  assert.deepEqual(shadow.results.shadow_withheld.submissions, [SUB]);
  const state = shadow.results;
  const reported = resultsFor({
    compiled: state.compiled.map((id) => ({ service_decision_id: id })),
    refused: state.refused, held: state.held, holds: state.holds, shadow: state.shadow !== false,
  });
  assert.deepEqual(reported.post, [], "a shadow run posted a result for the work its answer named");
  assert.ok(shadow.logs.some((l) => l.startsWith("note  shadow:") && l.includes("none is written")),
    `the shadow note is missing: ${shadow.logs.join(" | ")}`);
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

// This test asserted the opposite until 2026-09-22 ("a `held` result is posted
// in shadow and a settling one is not"), on the reading that `held` says the
// registry has not decided. BOT-81's Why says what it DOES: "a settled `held`
// result takes the decision off BOT-80's list" — a state move — and it names
// the hold entry's commit, which a shadow run does not make. The plan's M-T3.4
// has `report` post "nothing at all" for listed work in shadow, and B-T3.5 is
// watched by "posting a `held` result under a shadow lease". So `held` is
// withheld with the rest, and still SAID: it is in `withheld`, not dropped.
test("under a shadow answer a `held` result is withheld too, and still reported as withheld", () => {
  const held = [{ service_decision_id: SDI, held_for: "reversal" }];
  const shadow = resultsFor({ held, shadow: true });
  assert.deepEqual(shadow.post, [], "a `held` result was posted under a shadow answer (BOT-92; BOT-81)");
  assert.deepEqual(shadow.withheld.map((r) => `${r.service_decision_id} ${r.outcome}`), [`${SDI} held`],
    "a withheld `held` must still be visible in the report, or shadow is indistinguishable from an empty run");
  for (const notFalse of [undefined, null, "false"]) {
    assert.deepEqual(resultsFor({ held, shadow: notFalse }).post, [], `shadow ${JSON.stringify(notFalse)} posted`);
  }
  // The satisfiable direction: live, it is posted — naming the commit that
  // entered the hold, which is the one thing a `held` result exists to say
  // (BOT-81). This line posted it with `commit: null` until 2026-09-22.
  assert.deepEqual(resultsFor({ held, shadow: false, commit: "b".repeat(40) }).post.map((r) => `${r.outcome} ${r.commit}`),
    [`held ${"b".repeat(40)}`]);
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
  assert.match(script, /^\s*git push origin HEAD:main$/m, "the extracted step does not push; the anchor found something else");
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

/**
 * `$GITHUB_OUTPUT` as the runner reads it back: `key=value` lines, and
 * `key<<DELIMITER` … `DELIMITER` blocks for a value that spans lines. A key
 * written twice keeps the last value, as the runner does.
 */
function readOutputs(file) {
  const out = {};
  const lines = fs.existsSync(file) ? fs.readFileSync(file, "utf8").split("\n") : [];
  for (let i = 0; i < lines.length; i++) {
    const heredoc = /^([A-Za-z0-9_-]+)<<(.+)$/.exec(lines[i]);
    if (heredoc) {
      const body = [];
      let j = i + 1;
      while (j < lines.length && lines[j] !== heredoc[2]) body.push(lines[j++]);
      assert.ok(j < lines.length, `$GITHUB_OUTPUT opens \`${heredoc[1]}<<${heredoc[2]}\` and never closes it`);
      out[heredoc[1]] = body.join("\n");
      i = j;
      continue;
    }
    const pair = /^([A-Za-z0-9_-]+)=(.*)$/.exec(lines[i]);
    if (pair) out[pair[1]] = pair[2];
  }
  return out;
}

/**
 * The step, under `bash -e` as a runner starts a `run:` block, in the checkout,
 * with a `$GITHUB_OUTPUT` of its own — which is what the job's `outputs:` block
 * reads, and so what `report` and `settled` are handed.
 */
function runApply(root, env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-step-"));
  tmpRoots.push(dir);
  const file = path.join(dir, "apply.sh");
  const output = path.join(dir, "github-output");
  fs.writeFileSync(file, applyStep());
  fs.writeFileSync(output, "");
  // The step runs `git add`, `git commit` and `git push` itself, so its shell
  // gets a fixture's environment: under a hook's GIT_DIR it committed into the
  // repository that names (measured 2026-09-23, ops couplings 143), and
  // tools/selftest/git-env.mjs reads `git` spawns, not the git a shell runs.
  const step = spawnSync("bash", ["-e", file], {
    cwd: root,
    encoding: "utf8",
    env: { ...fixtureEnv(root), ...env, GITHUB_OUTPUT: output },
  });
  return { ...step, outputs: readOutputs(output) };
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

// ── what the commit lands, and what it hands to `report` and `settled` ──────
//
// Ops register entry 102: four defects on this path, each of which the first
// live run would have hit, none of which any test reached, because every test
// above stops at the commit job's return value or at `git push`. The three
// below go one step further each time — the landed TREE, the RESULT a landed
// commit is reported with, and the OUTPUTS the next two jobs are handed — and
// each was red on the code before the repair (the commit that adds them says
// what each printed).

/**
 * The two generated documents `main` carries, as its own CI would leave them
 * for this tree, and committed. Without them a fixture is a registry that has
 * never been built, and "the regenerated document was not committed" cannot
 * be told from "there was no document".
 */
function withDocuments(root) {
  writeAll(root, {
    [INDEX_FILE]: stableStringify(buildIndex({ root })),
    [REVOCATIONS_FILE]: stableStringify(buildRevocations({ root })),
  });
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", "catalogue: the generated documents"], root);
  return root;
}

const SDI3 = "0192f3a4-5b6c-7d8e-9f01-234567890abe";
const delistOf = (id) => decision({ service_decision_id: id, code: "M_DELIST", category: "broken", moderator: "amoderator" });
const deprecateOf = (id) => decision({ service_decision_id: id, code: "M_DEPRECATE", category: "broken", severity: "low", moderator: "amoderator" });
const relistOf = (id) => decision({ service_decision_id: id, code: "M_RELIST", category: "error", moderator: "amoderator", reverses: SDI2 });

/** What `report` hands `resultsFor`, out of a `results.json` — the shape the job's own CLI reads. */
const stateArgs = (state) => ({
  compiled: state.compiled.map((id) => ({ service_decision_id: id })),
  refused: state.refused,
  held: state.held,
  holds: state.holds,
});

const FULL_SHA = /^[0-9a-f]{40}$/;

// 102 (2). `plugins-moderation.yml` regenerates `registry/v1/index.json` and
// `registry/v1/revocations.json` between the compile and the commit, and
// `composeCommit` never listed either — so a delist landed with the index that
// still lists the plugin, `build-index.yml`'s `--check` went red on the push,
// and an advisory landed with a withdrawal list that does not carry it.
//
// And entry 69 rides on the same line: once the list IS committed, it must be
// committed at the serial the signer assigns to the commit that lands it.
// Until entry 69 closed, `resolveSerial` counted history and never the
// pending change, so a regeneration run before the commit wrote the serial
// `signed` already serves. It counts a pending change now, and this job adds
// the commit it composes itself, so the first batch is also where counting
// both would show, one past the signer. Both batches are needed: the list's
// serial moves only when the commit touches `tools/revocations/`, and a repair
// that always added one would pass the first batch and fail the second.
test("a moderation commit carries the documents it regenerates, at the serials the signer gives the commit that lands them", async () => {
  for (const [label, entries, listMoves] of [
    ["a delist and a deprecate", [delistOf(SDI2), deprecateOf(SDI3)], true],
    ["a delist alone", [delistOf(SDI2)], false],
  ]) {
    const root = withDocuments(estate());
    const origin = withRemote(root);
    const job = await commitJob(root, { entries });
    assert.equal(job.code, 0, job.logs.join("\n"));
    // The floor: the batch reached each generator's input, or "the document was
    // listed" is a claim about a document nothing changed.
    assert.ok(job.paths.some((p) => p.startsWith("plugins/")), `${label}: no listing edit — ${job.paths.join(", ")}`);
    assert.equal(job.paths.some((p) => p.startsWith(`${REVOCATIONS_DIR}/`)), listMoves,
      `${label}: the batch ${listMoves ? "entered no" : "entered an"} advisory — ${job.paths.join(", ")}`);

    for (const doc of [INDEX_FILE, ...(listMoves ? [REVOCATIONS_FILE] : [])]) {
      assert.ok(job.paths.includes(doc),
        `${label}: paths.txt does not list ${doc}. The workflow regenerates it before the gates and commits only ` +
        `what paths.txt names, so the commit lands the change and leaves behind the document that describes it ` +
        `(ops entry 102): ${job.paths.join(", ")}`);
    }

    const step = runApply(root);
    assert.equal(step.status, 0, `${label}: the commit step failed: ${step.stderr}`);
    const landed = headOf(origin);
    const at = (rel) => JSON.parse(sh(["show", `${landed}:${rel}`], origin));
    const signer = serialsAt({ root, sha: landed });
    assert.equal(at(INDEX_FILE).signed.serial, signer.index,
      `${label}: the committed index carries serial ${at(INDEX_FILE).signed.serial} and the signer assigns ` +
      `${signer.index} to the commit that landed it`);
    assert.equal(at(REVOCATIONS_FILE).signed.serial, signer.revocations,
      `${label}: the committed withdrawal list carries serial ${at(REVOCATIONS_FILE).signed.serial} and the ` +
      `signer assigns ${signer.revocations} to the commit that landed it (ops entry 69)`);

    // And the landed documents are the generators' own output for the landed
    // tree, by the two checks `build-index.yml` and the gates run.
    const check = spawnSync(process.execPath, [path.join(REPO, "tools", "build-index.mjs"), "--check", "--registry-dir", root],
      { encoding: "utf8" });
    assert.equal(check.status, 0, `${label}: build-index --check over the landed tree: ${check.stdout}${check.stderr}`);
    const list = at(REVOCATIONS_FILE);
    assert.deepEqual(list.signed.revocations, buildRevocations({ root, serial: list.signed.serial }).signed.revocations,
      `${label}: the landed withdrawal list is not what its sources produce`);
    if (listMoves) assert.ok(list.signed.revocations.length > 0, `${label}: the advisory reached no entry of the list`);
  }
});

// 102 (3). BOT-81: "at most one `held` result, naming the hold entry's
// commit". `resultsFor` posted every `held` with `commit: null`, and the
// commit that would have to be named does not exist when the commit job writes
// `results.json` — the workflow's `apply` step makes it afterwards. So the
// repair is an ORDERING one and no contract change: `report` runs only after
// `commit` succeeded and composes the result then, naming the commit the step
// pushed. A decision listed again because its `held` never arrived has no new
// commit at all, and names the one that entered its entry, which is also the
// BOT-82 key of the post that was lost.
test("a live `held` result names the commit that entered the hold, and a re-listed one names the same commit", async () => {
  const root = withDocuments(estate());
  const origin = withRemote(root);
  const first = await commitJob(root, { entries: [relistOf(SDI)] });
  assert.equal(first.code, 0, first.logs.join("\n"));
  assert.ok(first.paths.includes(holdEntryPath(SDI)), "MOD-9 holds every M_RELIST, so this run enters one or proves nothing");
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  assert.equal(sh(["log", "-1", "--format=%H", "--diff-filter=A", "--", holdEntryPath(SDI)], origin).trim(), landed,
    "the fixture's landed commit is not the one that entered the hold, so what follows names the wrong thing");

  const live = resultsFor({ ...stateArgs(first.results), commit: landed, shadow: false });
  assert.deepEqual(live.post.filter((r) => r.outcome === "held").map((r) => r.commit), [landed],
    `BOT-81: the \`held\` result must name the hold entry's commit, ${landed}; it named ` +
    `${JSON.stringify(live.post.filter((r) => r.outcome === "held").map((r) => r.commit))}`);

  const again = await commitJob(root, { entries: [relistOf(SDI)], now: new Date("2026-09-20T12:40:00Z") });
  assert.equal(again.code, 0, again.logs.join("\n"));
  assert.deepEqual(again.paths, [], "a re-listed hold whose entry is on the tree commits nothing");
  const relisted = resultsFor({ ...stateArgs(again.results), commit: null, shadow: false });
  assert.deepEqual(relisted.post.filter((r) => r.outcome === "held").map((r) => r.commit), [landed],
    "a decision listed again because its `held` never arrived must be reported against the commit that entered " +
    "its entry — this run made none, and BOT-82 would read any other commit as a second, different result");

  // And the guard under both: a live `held`, `applied` or `cancelled` that
  // names no commit is refused here, not posted and not composed.
  for (const [what, args] of [
    ["held", { held: [{ service_decision_id: SDI, held_for: "reversal" }] }],
    ["applied", { compiled: [{ service_decision_id: SDI }] }],
    ["cancelled", { holds: { pending: [{ service_decision_id: SDI, outcome: "cancelled", commit: null }] } }],
  ]) {
    assert.throws(() => resultsFor({ ...args, commit: null, shadow: false }), /BOT-81/,
      `a live \`${what}\` with no commit was composed for posting`);
  }
});

// ── ops entry 101: the 24 hours run from the commit that landed the entry ──
//
// MOD-9: "A reversal is released only on a MOD-52 confirmation after a 24 h
// hold period (OPEN-OWNER-4) has run from that commit" — the commit that adds
// `state/holds/<service_decision_id>.json`. The commit job hands its own `now`
// to the entry as `held_at`, and the commit that lands the entry is made after
// the gates, in the `apply` step; the job's `timeout-minutes` is all that
// bounds the gap. Until entry 101 closed, the period ran from `held_at`, so a
// hold compiled at T and landed at T + 15 min was due at T + 24 h — fifteen
// minutes before MOD-9 lets it be. Nothing caught it because the fixtures
// committed every entry at the wall clock and asked about a `now` two days
// earlier, and no test ever landed a hold through the workflow's own step at a
// time of its own.

/** Commit everything in `root` at `iso`, and return the commit. */
const commitAt = (root, iso, message) => {
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", message], root, dated(iso));
  return sh(["rev-parse", "HEAD"], root).trim();
};
const confirmOf = (id, at) => ({
  schema: "astra.registry.hold-record/1", act: "confirm", service_decision_id: id,
  at, actor: "operator", run: "https://github.com/a/b/actions/runs/1",
});
const dueIds = (walked) => walked.due.map((d) => `${d.service_decision_id} ${d.act}`);
const waitingFor = (walked, id) => walked.waiting.find((w) => w.service_decision_id === id)?.reason ?? "";

test("a reversal compiled at T and landed at T + 15 min is not due at T + 24 h + 1 min, and is at T + 15 min + 24 h", async () => {
  const T = "2026-09-20T12:30:00Z";
  const root = withDocuments(estate({ at: "2026-09-20T12:00:00Z" }));
  const origin = withRemote(root);
  const job = await commitJob(root, { entries: [relistOf(SDI)], now: new Date(T) });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.ok(job.paths.includes(holdEntryPath(SDI)), "MOD-9 holds every M_RELIST, so this run enters one or proves nothing");

  // The workflow's own commit step, landing the entry fifteen minutes after
  // the compile: the gates, the self-test, the push.
  const step = runApply(root, dated("2026-09-20T12:45:00Z"));
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  assert.equal(sh(["log", "-1", "--format=%cI", landed], root).trim(), "2026-09-20T12:45:00Z",
    "the fixture's landing commit is not dated where this test needs it, so what follows asks the wrong question");
  const [entry] = readHolds(root).map((h) => h.entry);
  assert.equal(entry.held_at, T, "held_at is the compile's clock, and this test is about the gap between it and the commit");

  // An operator confirms an hour later, and somebody annotates the entry an
  // hour after that: neither is the commit that added it.
  writeAll(root, { [`state/holds/${SDI}.confirm.json`]: confirmOf(SDI, "2026-09-20T13:45:00Z") });
  commitAt(root, "2026-09-20T13:45:00Z", "operator: confirm");
  writeAll(root, { [holdEntryPath(SDI)]: { $comment: "the appeal was checked by hand", ...entry } });
  commitAt(root, "2026-09-20T14:45:00Z", "annotate the hold");

  const early = walkHolds({ root, now: new Date("2026-09-21T12:31:00Z"), shadow: false });
  assert.deepEqual(dueIds(early), [],
    "a confirmed reversal was due 24 h and 1 min after it was compiled and 14 minutes before 24 hours had run from " +
    `${landed}, the commit that added its entry — MOD-9 violated in the early direction: ${JSON.stringify(early)}`);
  assert.match(waitingFor(early, SDI), /2026-09-21T12:45:00Z/, "the wait does not name the end of the period counted from the commit");
  assert.ok(waitingFor(early, SDI).includes(landed), `the wait does not name the commit it counts from: ${waitingFor(early, SDI)}`);

  const due = walkHolds({ root, now: new Date("2026-09-21T12:45:00Z"), shadow: false });
  assert.deepEqual(dueIds(due), [`${SDI} release`],
    "24 hours after the commit that added the entry, confirmed, the reversal was not due — counted from a later " +
    `commit that touched the entry or its directory: ${JSON.stringify(due)}`);

  // The entry this run wrote was in no commit when the run walked the holds:
  // its period had not started, and the walk says so rather than dating it.
  assert.match(waitingFor(job.results.holds, SDI), /not started/,
    `a hold entry in no commit yet was given a period: ${waitingFor(job.results.holds, SDI)}`);
});

test("a hold merged from a branch runs its 24 hours from the merge that brought it onto main", async () => {
  const root = estate({ at: "2026-09-10T00:00:00Z" });
  const entry = holdEntry({
    service_decision_id: SDI, code: "M_RELIST", category: "error", plugin_id: "widgets",
    decided_at: "2026-09-17T08:00:00Z", reason: MODERATOR_REASON, moderator: "amoderator", reverses: SDI2,
  }, { held_for: "reversal", held_at: "2026-09-17T09:00:00Z" });
  sh(["checkout", "-q", "-b", "hand-hold"], root);
  writeAll(root, { [holdEntryPath(SDI)]: entry });
  const branch = commitAt(root, "2026-09-17T09:00:00Z", "a hold written on a branch");
  sh(["checkout", "-q", "main"], root);
  writeAll(root, { "README.md": "main moves on\n" });
  commitAt(root, "2026-09-18T00:00:00Z", "main moves on");
  sh(["merge", "-q", "--no-ff", "-m", "Merge the hold", "hand-hold"], root, dated("2026-09-20T12:00:00Z"));
  const merge = sh(["rev-parse", "HEAD"], root).trim();
  writeAll(root, { [`state/holds/${SDI}.confirm.json`]: confirmOf(SDI, "2026-09-20T12:10:00Z") });
  commitAt(root, "2026-09-20T12:10:00Z", "operator: confirm");

  // BOT-81's `held` names the commit the 24 hours run from, and it is main's.
  assert.equal(entryCommit(root, holdEntryPath(SDI)), merge,
    `the hold's commit was read as ${entryCommit(root, holdEntryPath(SDI))}; ${branch} is the branch commit, which ` +
    `main never held on its own, and ${merge} is the merge that brought the entry onto main`);

  const mid = walkHolds({ root, now: new Date("2026-09-20T13:00:00Z"), shadow: false });
  assert.deepEqual(dueIds(mid), [],
    "an hour after the merge that brought it onto main, a confirmed reversal was due — dated at its branch commit " +
    `or its held_at, three days before main held it: ${JSON.stringify(mid)}`);
  assert.match(waitingFor(mid, SDI), /2026-09-21T12:00:00Z/);
  const due = walkHolds({ root, now: new Date("2026-09-21T12:00:00Z"), shadow: false });
  assert.deepEqual(dueIds(due), [`${SDI} release`], `24 hours after the merge the reversal was not due: ${JSON.stringify(due)}`);
});

test("a checkout that cannot see the commit names none, and counts from held_at + 24 h + the commit job's timeout", async () => {
  const root = estate({ at: "2026-09-20T12:00:00Z" });
  const entry = holdEntry({
    service_decision_id: SDI, code: "M_RELIST", category: "error", plugin_id: "widgets",
    decided_at: "2026-09-20T12:00:00Z", reason: MODERATOR_REASON, moderator: "amoderator", reverses: SDI2,
  }, { held_for: "reversal", held_at: "2026-09-20T12:30:00Z" });
  writeAll(root, { [holdEntryPath(SDI)]: entry });
  commitAt(root, "2026-09-20T12:45:00Z", "registry: moderation (1 decision(s))");
  writeAll(root, { [`state/holds/${SDI}.confirm.json`]: confirmOf(SDI, "2026-09-20T13:45:00Z") });
  const head = commitAt(root, "2026-09-20T13:45:00Z", "operator: confirm");
  const shallow = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-shallow-clock-"));
  tmpRoots.push(shallow);
  sh(["clone", "-q", "--depth", "1", `file://${root}`, shallow], os.tmpdir());
  assert.equal(sh(["rev-parse", "--is-shallow-repository"], shallow).trim(), "true");

  // A depth-1 clone's only commit has no parent here, so git reports it as
  // adding every file: the confirm commit would be named as the hold's.
  assert.equal(entryCommit(shallow, holdEntryPath(SDI)), null,
    `a shallow checkout named ${entryCommit(shallow, holdEntryPath(SDI))} as the hold's commit; ${head} is its ` +
    "boundary, which git reports as adding every file in the tree");
  const landed = moderationRun.entryLanding(shallow, holdEntryPath(SDI));
  assert.match(landed.why ?? "", /shallow/, `the reader does not say why it named no commit: ${JSON.stringify(landed)}`);

  const [hold] = readHolds(shallow);
  const slack = holdsModule.HOLD_COMMIT_SLACK_MINUTES;
  const at = (iso) => resolveHold(hold, { now: new Date(iso), shadow: false, landed }).act;
  assert.equal(at("2026-09-21T12:31:00Z"), "wait",
    "counted from held_at alone, as before entry 101, the reversal was due while its commit's 24 hours had 14 minutes to run");
  assert.equal(at("2026-09-21T12:45:00Z"), "wait", "the fallback is not later than the commit could have landed");
  const end = new Date(Date.parse("2026-09-21T12:30:00Z") + slack * 60_000).toISOString();
  assert.equal(at(new Date(Date.parse(end) - 1000).toISOString()), "wait", `released a second before held_at + 24 h + ${slack} min`);
  assert.equal(at(end), "release", "the fallback never ends");

  // And the job itself never reaches it there: the walk refuses a shallow clone.
  assert.throws(() => walkHolds({ root: shallow, now: new Date(end), shadow: false }), /shallow clone/);
});

// The fallback is sound only while its slack outlasts the commit job: `held_at`
// is taken in that job's compile step and the commit is made in its `apply`
// step, and GitHub cancels the job at `timeout-minutes` with nothing pushed.
test("the fallback's slack outlasts the commit job's timeout, so a hold counted without its commit is never due early", () => {
  const lines = read(".github/workflows/plugins-moderation.yml").split("\n");
  const jobs = lines.flatMap((l, i) => (/^ {2}commit:\s*$/.test(l) ? [i] : []));
  assert.equal(jobs.length, 1, `plugins-moderation.yml has ${jobs.length} \`commit:\` jobs; this reads exactly one`);
  const timeouts = [];
  for (let j = jobs[0] + 1; j < lines.length && !/^ {2}\S/.test(lines[j]); j++) {
    const m = /^ {4}timeout-minutes:\s*(\d+)\s*$/.exec(lines[j]);
    if (m) timeouts.push(Number(m[1]));
  }
  assert.equal(timeouts.length, 1, `the commit job states ${timeouts.length} timeout-minutes; this reads exactly one`);
  const slack = holdsModule.HOLD_COMMIT_SLACK_MINUTES;
  assert.ok(Number.isInteger(slack) && slack > timeouts[0],
    `bot/lib/holds.mjs counts a hold whose commit cannot be read from held_at + 24 h + ${slack} min, and the commit ` +
    `job can land that commit up to ${timeouts[0]} min after held_at (plus the second both stamps are truncated to): ` +
    "raise HOLD_COMMIT_SLACK_MINUTES above the job's timeout-minutes");
});

/** A token shaped like the runner's, with the two claims `mintToken` pins. */
const fakeToken = () => [
  Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url"),
  Buffer.from(JSON.stringify({ aud: BOT_AUDIENCE, environment: "plugins-service", jti: `jti-${Math.random()}` })).toString("base64url"),
  "not-a-signature",
].join(".");

/** `--job report`, as the workflow runs it, against a stub service that records every body it is sent. */
async function reportJob(env, { answer = () => ({ status: 200, body: { schema: "astra.plugins.bot-ack/1", shadow: false, outcome: "recorded" } }) } = {}) {
  const bodies = [];
  const logs = [];
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url, init = {}) => {
    if (String(url).startsWith("https://token.invalid/")) return json(200, { value: fakeToken() });
    const body = JSON.parse(init.body);
    bodies.push(body);
    const a = answer(body);
    return json(a.status, a.body);
  };
  const code = await main(["--job", "report"], {
    env: {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.invalid/token?api-version=2.0",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "the-runner-secret",
      ...env,
    },
    log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
    fetchImpl,
  });
  return { code, bodies, logs };
}

/** `--job settled`, as the workflow runs it. */
async function settledJob(env) {
  const logs = [];
  const code = await main(["--job", "settled"], {
    env,
    log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
  });
  return { code, logs };
}

// 102 (4). The `commit` job's `outputs:` map `results` and `main_commit` from
// `steps.apply.outputs`, and nothing wrote either: `$GITHUB_OUTPUT` appeared
// nowhere in the workflow or in this file. So `settled` was handed an empty
// string, parsed it as no results, and would have failed and paged on every
// run that did its work; and `report` read `moderation/results.json`, a file
// that exists only in the commit job's workspace.
test("the commit step hands `report` and `settled` the commit it pushed and the results it recorded", async () => {
  const root = withDocuments(estate());
  const origin = withRemote(root);
  const job = await commitJob(root, { entries: [delistOf(SDI2), relistOf(SDI)] });
  assert.equal(job.code, 0, job.logs.join("\n"));
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  assert.equal(step.outputs.main_commit, landed,
    `the commit step's \`main_commit\` output is ${JSON.stringify(step.outputs.main_commit)} and it pushed ${landed}. ` +
    "The job's `outputs:` read it from `steps.apply.outputs`, and `report` names it in every result it posts");
  assert.ok(step.outputs.results, "the commit step wrote no `results` output, so `settled` is handed nothing and pages");
  assert.deepEqual(JSON.parse(step.outputs.results), job.results, "the results handed on are not the ones the job recorded");

  // `report`, over exactly what the job's outputs hand it.
  const posted = await reportJob({ ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit });
  assert.equal(posted.code, 0, posted.logs.join("\n"));
  assert.deepEqual(
    posted.bodies.map((b) => `${b.service_decision_id} ${b.outcome} ${b.commit ?? "-"} ${b.refusal_code ?? "-"}`).sort(),
    [`${SDI} held ${landed} -`, `${SDI2} applied ${landed} -`].sort(),
    "report posted something other than one `applied` and one `held`, each naming the commit that landed it",
  );
  for (const b of posted.bodies) assert.equal(b.schema, "astra.plugins.bot-service-decision-result/1");

  // `settled`, over the same outputs: every listed id has a result.
  const handed = { ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit };
  const ok = await settledJob({ ...handed, ASTRA_LISTED_IDS: JSON.stringify([SDI, SDI2]) });
  assert.equal(ok.code, 0, `settled failed a run whose every listed decision landed: ${ok.logs.join(" | ")}`);
  // The directions that must stay red: an id nobody answered, and nothing handed on.
  assert.equal((await settledJob({ ...handed, ASTRA_LISTED_IDS: JSON.stringify([SDI, SDI2, SDI3]) })).code, 1);
  assert.equal((await settledJob({ ASTRA_RESULTS: "", ASTRA_LISTED_IDS: JSON.stringify([SDI]) })).code, 1);

  // A post the service does not accept fails `report`, so `settled` — which
  // counts results only when `report` succeeded — sees the decision unsettled.
  const refused = await reportJob(handed, {
    answer: () => ({ status: 422, body: { schema: "astra.plugins.error/1", error: "invalid", message: "no" } }),
  });
  assert.equal(refused.code, 1, `report exited 0 though no result was accepted: ${refused.logs.join(" | ")}`);

  // A run with nothing to commit still hands both on: no commit, and results.
  const quiet = await commitJob(root, { entries: [] });
  assert.equal(quiet.code, 0, quiet.logs.join("\n"));
  const none = runApply(root);
  assert.equal(none.status, 0, none.stderr);
  assert.equal(none.outputs.main_commit, "", "a run that pushed nothing named a commit");
  assert.deepEqual(JSON.parse(none.outputs.results ?? "null"), quiet.results);
  assert.equal((await settledJob({ ASTRA_RESULTS: none.outputs.results, ASTRA_MAIN_COMMIT: "", ASTRA_LISTED_IDS: "[]" })).code, 0);

  // Shadow: the listed work is withheld, which TRUST-45 pages for and `settled`
  // must not — a run that did exactly what BOT-92 asks is not a lost decision.
  const shadowRoot = withDocuments(estate());
  withRemote(shadowRoot);
  const shadow = await commitJob(shadowRoot, { entries: [delistOf(SDI2), relistOf(SDI)], shadow: true });
  assert.equal(shadow.code, 0, shadow.logs.join("\n"));
  const shadowStep = runApply(shadowRoot);
  assert.equal(shadowStep.status, 0, shadowStep.stderr);
  const shadowHanded = { ASTRA_RESULTS: shadowStep.outputs.results ?? "", ASTRA_MAIN_COMMIT: shadowStep.outputs.main_commit ?? "" };
  const shadowSettled = await settledJob({ ...shadowHanded, ASTRA_LISTED_IDS: JSON.stringify([SDI, SDI2]) });
  assert.equal(shadowSettled.code, 0, `settled paged for work a shadow answer withheld: ${shadowSettled.logs.join(" | ")}`);
  const shadowPosted = await reportJob(shadowHanded);
  assert.equal(shadowPosted.code, 0, shadowPosted.logs.join("\n"));
  assert.deepEqual(shadowPosted.bodies, [], "report posted under a shadow answer (BOT-92)");
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

// ── ops entry 100: a result history decided is posted until SETTLED, then never ─
//
// A hold that left the tree is ended by a commit, and the walk re-read every
// such commit in the whole history every run: two consecutive live runs over
// one hand-deleted hold each posted the same `cancelled`, and each warned.
// Nothing on this side recorded that the service had accepted it. Now the
// `list` job posts those results before `commit` (`--job history`), hands on
// the rows the service ANSWERED `accepted` or `duplicate`, and `commit`
// records them in `state/moderation-settled.json`, which the walk skips.
//
// The rule these tests hold, and the three mutations they were written
// against: a result is recorded on the ANSWER — not because it was posted, and
// not on a 5xx — and a record that is absent or unreadable skips NOTHING.

const SETTLED_FILE_PATH = "state/moderation-settled.json";
const RUN_URL = "https://github.com/mihailinl/astra-registry/actions/runs/35502265394";
const hid = (n) => `0192f3a4-5b6c-7d8e-9f01-2345678920${String(n).padStart(2, "0")}`;

/** A tree with one hold entry per id, each then deleted BY HAND in its own commit (BOT-70): a `cancelled` each. */
function handCancelled(ids, { documents = false, remote = false } = {}) {
  const entryFor = (sdi) => holdEntry({
    service_decision_id: sdi, code: "M_RELIST", category: "error", plugin_id: "widgets",
    decided_at: "2026-09-18T11:00:00Z", reason: MODERATOR_REASON, moderator: "amoderator", reverses: SDI2,
  }, { held_for: "reversal", held_at: "2026-09-18T12:00:00Z" });
  const extra = {};
  for (const id of ids) extra[holdEntryPath(id)] = entryFor(id);
  const root = estate({ extra });
  if (documents) withDocuments(root);
  const sha = {};
  for (const id of ids) {
    sh(["rm", "-q", holdEntryPath(id)], root);
    sh(["commit", "-q", "-m", "tidy the holds directory"], root);
    sha[id] = sh(["rev-parse", "HEAD"], root).trim();
  }
  const origin = remote ? withRemote(root) : null;
  return { root, sha, origin };
}

/** A bot-ack answer, as the stub service sends it. */
const ack = (outcome, over = {}) => ({ status: 200, body: { schema: "astra.plugins.bot-ack/1", shadow: false, outcome, ...over } });

/** `--job history`, as the `list` job's step runs it, against a stub service that records every body. */
async function historyJob(root, { shadow = "false", answer = () => ack("accepted"), env = {}, now = new Date("2026-09-21T10:00:00Z") } = {}) {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-history-"));
  tmpRoots.push(out);
  const bodies = [];
  const logs = [];
  const json = (status, body) => new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status, headers: { "content-type": "application/json" },
  });
  const fetchImpl = async (url, init = {}) => {
    if (String(url).startsWith("https://token.invalid/")) return json(200, { value: fakeToken() });
    const body = JSON.parse(init.body);
    bodies.push(body);
    const a = answer(body);
    if (a instanceof Error) throw a;
    return json(a.status, a.body);
  };
  const code = await main(["--job", "history", "--registry-dir", root, "--out", out], {
    env: {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.invalid/token?api-version=2.0",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "the-runner-secret",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "mihailinl/astra-registry",
      GITHUB_RUN_ID: "35502265394",
      ASTRA_SHADOW: shadow,
      ...env,
    },
    log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
    fetchImpl,
    now,
  });
  const file = path.join(out, "settled.json");
  const text = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
  return { code, bodies, logs, text, settled: text === null ? null : JSON.parse(text) };
}

/** A sound row for one of `handCancelled`'s ids, as the record holds it. */
const rowFor = (id, commit, over = {}) => ({
  service_decision_id: id, outcome: "cancelled", commit, answer: "accepted",
  answered_at: "2026-09-21T09:00:00Z", run: RUN_URL, ...over,
});

const writeRecord = (root, doc) => writeAll(root, { [SETTLED_FILE_PATH]: typeof doc === "string" ? doc : doc });
const postedIds = (bodies) => [...new Set(bodies.map((b) => b.service_decision_id))].sort();
const pendingIds = (job) => job.results.holds.pending.map((p) => p.service_decision_id).sort();

test("the acknowledgement words that settle a result are the token file's `result_acknowledgements`, both ways", () => {
  assert.ok(settledLib, "bot/lib/settled.mjs is not on this tree (ops entry 100)");
  const tokens = JSON.parse(read("schema/contract-tokens-v1.json"));
  const list = (tokens.entries ?? []).find((e) => e.id === "list:result_acknowledgements");
  assert.ok(list, "the token file carries no `list:result_acknowledgements`, so there is nothing to hold the words to");
  assert.ok(list.acceptor.includes("bot"), "the list is not one the bot accepts, so this comparison is about someone else's list");
  assert.deepEqual([...settledLib.SETTLING_ANSWERS].sort(), [...list.values].sort(),
    "the words that record a result as settled are not exactly the words the service answers a result with. One " +
    "missing here re-posts for ever; one extra records a result the service never said it holds");
  assert.equal(settledLib.SETTLED_FILE, SETTLED_FILE_PATH);
});

test("a result from history is recorded as settled on `accepted` or `duplicate`, and on no other answer", async () => {
  assert.ok(settledLib, "bot/lib/settled.mjs is not on this tree (ops entry 100)");
  const ids = [1, 2, 3, 4, 5, 6, 7, 8].map(hid);
  const [ACCEPTED, DUPLICATE, UNAVAILABLE, TIMEOUT, SHADOW, UNKNOWN_WORD, REFUSED, UNREADABLE] = ids;
  const { root, sha } = handCancelled(ids, { documents: true });
  const answers = {
    [ACCEPTED]: () => ack("accepted"),
    [DUPLICATE]: () => ack("duplicate"),
    [UNAVAILABLE]: () => ({ status: 503, body: "service unavailable" }),
    [TIMEOUT]: () => new Error("The operation was aborted due to timeout"),
    [SHADOW]: () => ack("accepted", { shadow: true }),
    [UNKNOWN_WORD]: () => ack("recorded"),
    [REFUSED]: () => ({ status: 422, body: { schema: "astra.plugins.error/1", error: "invalid", message: "no" } }),
    [UNREADABLE]: () => ({ status: 200, body: { schema: "astra.plugins.bot-ack/1", outcome: "accepted" } }),
  };
  const job = await historyJob(root, { answer: (b) => answers[b.service_decision_id]() });
  assert.equal(job.code, 0, `a result the service did not settle failed the list job: ${job.logs.join(" | ")}`);
  assert.deepEqual(postedIds(job.bodies), [...ids].sort(), "every result history decided must be posted");
  for (const b of job.bodies) {
    assert.deepEqual(Object.keys(b).sort(), ["commit", "outcome", "schema", "service_decision_id"].sort());
    assert.equal(b.commit, sha[b.service_decision_id], "a result from history names the commit that ended the hold");
  }
  assert.deepEqual(job.settled.map((r) => r.service_decision_id).sort(), [ACCEPTED, DUPLICATE].sort(),
    "a result was recorded as settled on something other than the service answering `accepted` or `duplicate`: " +
    "a 5xx, a timeout, a shadow answer, a word outside the token file's list, a refusal and an answer that failed " +
    "its schema each settle nothing");
  for (const r of job.settled) {
    assert.deepEqual(r, {
      service_decision_id: r.service_decision_id, outcome: "cancelled", commit: sha[r.service_decision_id],
      answer: r.service_decision_id === ACCEPTED ? "accepted" : "duplicate",
      answered_at: "2026-09-21T10:00:00Z", run: RUN_URL,
    }, "a row must carry the answer, when it came and the run that received it, so a skip can be traced");
  }
  assert.deepEqual(settledLib.rowProblems(job.settled[0]), []);

  // The commit job records exactly those, and the rest stay results to post.
  const commit = await commitJob(root, { entries: [], env: { ASTRA_SETTLED: job.text } });
  assert.equal(commit.code, 0, commit.logs.join("\n"));
  assert.deepEqual(commit.results.settled.recorded.map((r) => r.service_decision_id).sort(), [ACCEPTED, DUPLICATE].sort());
  assert.deepEqual(commit.paths, [SETTLED_FILE_PATH], "a run whose only news is a settled result commits the record, and only it");
  const onDisk = JSON.parse(fs.readFileSync(path.join(root, SETTLED_FILE_PATH), "utf8"));
  assert.equal(onDisk.schema, "astra.registry.moderation-settled/1");
  assert.deepEqual(onDisk.settled.map((r) => r.service_decision_id).sort(), [ACCEPTED, DUPLICATE].sort());
  assert.deepEqual(pendingIds(commit), [UNAVAILABLE, TIMEOUT, SHADOW, UNKNOWN_WORD, REFUSED, UNREADABLE].sort(),
    "a result the service did not settle must stay a result `report` posts");
  const message = fs.readFileSync(path.join(root, "moderation", "commit-message.txt"), "utf8");
  assert.match(message, /2 settled result\(s\) recorded/);
  assert.doesNotMatch(message, /^Service-Decision:/m, "recording a result applies, holds and cancels nothing (BOT-81)");
});

test("a recorded result is not posted again, and an unrecorded one is, by both jobs that post", async () => {
  const [DONE, OPEN] = [11, 12].map(hid);
  const { root, sha } = handCancelled([DONE, OPEN]);
  writeRecord(root, { schema: "astra.registry.moderation-settled/1", settled: [rowFor(DONE, sha[DONE])] });

  const history = await historyJob(root);
  assert.deepEqual(postedIds(history.bodies), [OPEN],
    "the list job posted a result the record says the service already settled, or did not post one it does not");
  const commit = await commitJob(root, { entries: [] });
  assert.equal(commit.code, 0, commit.logs.join("\n"));
  assert.deepEqual(pendingIds(commit), [OPEN], "the commit job handed `report` a result the record says is settled");
  assert.deepEqual(commit.results.holds.settled.map((r) => r.service_decision_id), [DONE]);
  assert.ok(!commit.logs.some((l) => l.includes("hold_hand_cancelled") && l.includes(DONE)),
    `a hand cancellation the service has settled was warned about again: ${commit.logs.join(" | ")}`);
  assert.ok(commit.logs.some((l) => l.includes("hold_hand_cancelled") && l.includes(OPEN)),
    "a hand cancellation the service has not settled must still be said");
  const report = await reportJob({ ASTRA_RESULTS: JSON.stringify(commit.results), ASTRA_MAIN_COMMIT: "" });
  assert.equal(report.code, 0, report.logs.join("\n"));
  assert.deepEqual(postedIds(report.bodies), [OPEN], "report re-posted a settled result, or dropped an unsettled one");

  // The skip is BOT-82's whole key: the same decision and outcome under another commit is another result.
  writeRecord(root, { schema: "astra.registry.moderation-settled/1", settled: [rowFor(DONE, "e".repeat(40)), rowFor(OPEN, sha[OPEN], { outcome: "applied" })] });
  const other = await historyJob(root);
  assert.deepEqual(postedIds(other.bodies), [DONE, OPEN].sort(), "a row skipped a result whose commit or outcome it does not name");
});

test("two live runs over one hand-deleted hold post its `cancelled` once, and the second run is silent about it", async () => {
  const [ID] = [21].map(hid);
  const { root, sha, origin } = handCancelled([ID], { documents: true, remote: true });

  // Run 1: `list` posts and the service accepts; `commit` records; `apply` pushes; `report` has nothing left.
  const first = await historyJob(root);
  assert.deepEqual(postedIds(first.bodies), [ID]);
  const commit1 = await commitJob(root, { entries: [], env: { ASTRA_SETTLED: first.text } });
  assert.equal(commit1.code, 0, commit1.logs.join("\n"));
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  assert.equal(headOf(origin), step.outputs.main_commit, "the record was not pushed");
  assert.deepEqual(sh(["show", "--name-only", "--format=", "HEAD"], root).split("\n").filter(Boolean), [SETTLED_FILE_PATH],
    "the commit that records a settled result touches the record and nothing else");
  const report1 = await reportJob({ ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit });
  assert.equal(report1.code, 0, report1.logs.join("\n"));
  assert.deepEqual(report1.bodies, [], "report posted a result `list` had already settled in this run");

  // Run 2, on what run 1 pushed: nothing is posted for it, and nothing is said about it.
  const second = await historyJob(root);
  assert.deepEqual(second.bodies, [], `the second live run posted ${ID}'s \`cancelled\` again (ops entry 100)`);
  const commit2 = await commitJob(root, { entries: [], env: { ASTRA_SETTLED: second.text } });
  assert.equal(commit2.code, 0, commit2.logs.join("\n"));
  assert.deepEqual(commit2.paths, [], "a run with nothing new to record committed something");
  assert.deepEqual(pendingIds(commit2), []);
  assert.ok(!commit2.logs.some((l) => l.includes("hold_hand_cancelled")), `the second run warned again: ${commit2.logs.join(" | ")}`);
  assert.equal(commit2.results.holds.settled[0]?.commit, sha[ID]);
});

test("a result the service did not settle keeps being posted, run after run, until an answer settles it", async () => {
  const [ID] = [31].map(hid);
  const { root } = handCancelled([ID], { documents: true, remote: true });
  let calls = 0;
  const down = () => { calls++; return { status: 503, body: "down" }; };
  for (let run = 1; run <= 2; run++) {
    const history = await historyJob(root, { answer: down });
    assert.deepEqual(postedIds(history.bodies), [ID], `run ${run}: an unsettled result was not posted again`);
    assert.deepEqual(history.settled, [], `run ${run}: a 5xx recorded a result as settled`);
    const commit = await commitJob(root, { entries: [], env: { ASTRA_SETTLED: history.text } });
    assert.equal(commit.code, 0, commit.logs.join("\n"));
    assert.deepEqual(commit.paths, [], `run ${run}: the record was written with nothing settled`);
    assert.deepEqual(pendingIds(commit), [ID], `run ${run}: report was not handed the unsettled result`);
    assert.equal(fs.existsSync(path.join(root, SETTLED_FILE_PATH)), false);
  }
  assert.ok(calls >= 2);
  // Then the service answers `duplicate` (report's own post had got through), and it is recorded once.
  const third = await historyJob(root, { answer: () => ack("duplicate") });
  assert.deepEqual(third.settled.map((r) => r.answer), ["duplicate"]);
});

test("an absent, unreadable or malformed record skips nothing it cannot vouch for, and says so", async () => {
  const [A, B, C, D] = [41, 42, 43, 44].map(hid);
  const { root, sha } = handCancelled([A, B, C, D]);
  const all = [A, B, C, D].sort();
  const cases = [
    { name: "absent", doc: null, posted: all, state: "absent", warned: false },
    { name: "not JSON", doc: "{ this is not json", posted: all, state: "unreadable", warned: true },
    { name: "another schema", doc: { schema: "astra.registry.something-else/1", settled: [rowFor(A, sha[A])] }, posted: all, state: "unreadable", warned: true },
    { name: "an extra top-level member", doc: { schema: "astra.registry.moderation-settled/1", settled: [rowFor(A, sha[A])], note: "x" }, posted: all, state: "unreadable", warned: true },
    {
      name: "one sound row among malformed ones",
      doc: {
        schema: "astra.registry.moderation-settled/1",
        settled: [
          rowFor(A, sha[A]),
          rowFor(B, sha[B], { answer: "failed" }),
          rowFor(C, sha[C].slice(0, 12)),
          { ...rowFor(D, sha[D]), posted_by: "list" },
        ],
      },
      posted: [B, C, D].sort(), state: "read", warned: true,
    },
    { name: "a row with no run", doc: { schema: "astra.registry.moderation-settled/1", settled: [rowFor(A, sha[A], { run: null })] }, posted: all, state: "read", warned: true },
  ];
  for (const c of cases) {
    fs.rmSync(path.join(root, SETTLED_FILE_PATH), { force: true });
    if (c.doc !== null) writeRecord(root, c.doc);
    const history = await historyJob(root);
    assert.deepEqual(postedIds(history.bodies), c.posted, `${c.name}: the list job skipped a result the record cannot vouch for`);
    const commit = await commitJob(root, { entries: [] });
    assert.equal(commit.code, 0, commit.logs.join("\n"));
    assert.deepEqual(pendingIds(commit), c.posted, `${c.name}: the commit job skipped a result the record cannot vouch for`);
    assert.equal(commit.results.settled.record, c.state, `${c.name}: the record was read as ${commit.results.settled.record}`);
    const warned = commit.logs.some((l) => l.startsWith("::warning::settled_record_unreadable"));
    assert.equal(warned, c.warned, `${c.name}: ${c.warned ? "a record it could not read was not said" : "an absent record was warned about"}`);
  }
});

test("the commit job records only sound rows, for results its own walk derived, and only live", async () => {
  const [A, B] = [51, 52].map(hid);
  const { root, sha } = handCancelled([A, B]);
  const record = () => (fs.existsSync(path.join(root, SETTLED_FILE_PATH))
    ? JSON.parse(fs.readFileSync(path.join(root, SETTLED_FILE_PATH), "utf8")).settled.map((r) => r.service_decision_id).sort()
    : []);
  const run = async (rows, { shadow = false } = {}) => {
    fs.rmSync(path.join(root, SETTLED_FILE_PATH), { force: true });
    return commitJob(root, { entries: [], shadow, env: { ASTRA_SETTLED: typeof rows === "string" ? rows : JSON.stringify(rows) } });
  };

  const good = await run([rowFor(A, sha[A]), rowFor(A, sha[A])]);
  assert.deepEqual(record(), [A], "a sound row for a derived result was not recorded, or was recorded twice");
  assert.deepEqual(pendingIds(good), [B]);

  const stranger = await run([rowFor(hid(59), "d".repeat(40))]);
  assert.deepEqual(record(), [], "a row naming a result this walk never derived was recorded");
  assert.ok(stranger.logs.some((l) => l.startsWith("::warning::settled_row_refused")));

  await run([rowFor(A, sha[A], { answer: "posted" }), rowFor(B, sha[B], { commit: undefined })]);
  assert.deepEqual(record(), [], "a malformed row was recorded");

  const shadowed = await run([rowFor(A, sha[A])], { shadow: true });
  assert.deepEqual(record(), [], "a row was recorded under a shadow answer, when a shadow run posts nothing");
  assert.deepEqual(pendingIds(shadowed), [A, B].sort());

  const garbage = await run("not json");
  assert.equal(garbage.code, 0, "a malformed handoff failed the commit job, holding back every takedown for a record");
  assert.deepEqual(record(), []);
  assert.ok(garbage.logs.some((l) => l.startsWith("::warning::settled_row_refused")));
});

test("under a shadow answer, or none, the history step posts nothing and hands on nothing", async () => {
  const [ID] = [61].map(hid);
  const { root } = handCancelled([ID]);
  for (const shadow of ["true", "", "False"]) {
    const job = await historyJob(root, { shadow });
    assert.equal(job.code, 0);
    assert.deepEqual(job.bodies, [], `ASTRA_SHADOW=${JSON.stringify(shadow)}: a result was posted, and BOT-92 withholds every one`);
    assert.deepEqual(job.settled, [], `ASTRA_SHADOW=${JSON.stringify(shadow)}: settled rows were handed on under shadow`);
  }
});

test("a moderation commit may write the settled record, and exactly that one file of it", () => {
  assert.equal(allowedPath(SETTLED_FILE_PATH), true, "the settled record is not on BOT-33's moderation allowlist");
  for (const bad of [`${SETTLED_FILE_PATH}.bak`, `${SETTLED_FILE_PATH}x`, "state/moderation-settled/other.json", "state/releases-seen.json"]) {
    assert.equal(allowedPath(bad), false, `${bad} passes the allowlist because it begins like the record`);
  }
});

// ── TRUST-26's bound, measured by the commit job and spent entry by entry ────
//
// M-T3.4 × M-T3.2. Until this, the commit job read the bound from an input
// nothing supplied (`ASTRA_OVER_BOUND`) and asked it ONCE per run: one boolean
// for the whole batch. Two things were wrong with that, and a single-entry
// fixture could show neither:
//
//   * a batch is not one takedown. With nothing withdrawn today and a bound of
//     three, a list answer carrying four takedowns compiled all four against
//     `overBound: false`, and four listed plugins left the catalogue in one
//     commit — the day the bound exists for, arriving as a batch;
//   * an environment variable that says "under the bound" is a switch that
//     applies a takedown MOD-9 should have held, and a workflow step or a
//     dispatch that set it would have been the whole of the bypass.
//
// So the job counts the window out of git itself (`countWindow`, M-T3.2's
// counter) and each compiled takedown spends what it withdraws before the next
// one is asked. These fixtures are real repositories with real history,
// because the count is a comparison between commits.

const PEERS = ["gadgets", "gizmos", "doohickeys"];
const SDIS = ["…a1", "…a2", "…a3", "…a4", "…a5"].map((_, i) => `0192f3a4-5b6c-7d8e-9f01-2345678910${String(i + 10)}`);

/** An estate with `widgets` and three more listed, bound plugins. */
function crowd({ at = "2026-09-20T09:00:00Z" } = {}) {
  const extra = {};
  for (const id of PEERS) {
    extra[`plugins/${id}/plugin.json`] = plugin(id);
    extra[`plugins/${id}/versions/1.0.0.json`] = version(id, "1.0.0");
    extra[`plugins/${id}/identity.json`] = identity(id);
  }
  return estate({ extra, at });
}

/** Commit, dated, what a hand withdrawal would leave on `main`. */
function withdrawnInGit(root, ids, when) {
  for (const id of ids) {
    const file = path.join(root, "plugins", id, "plugin.json");
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, `${JSON.stringify({ ...doc, unlisted: true }, null, 2)}\n`);
  }
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", `hand delist of ${ids.join(", ")}\n\nModeration-Exempt: operator: fixture`], root, dated(when));
}

const takedownOf = (id, i) => decision({ service_decision_id: SDIS[i], plugin_id: id, code: "M_DELIST", category: "broken", moderator: "amoderator" });

/** The commit job as the workflow runs it: no bound handed in from outside. */
async function measuredJob(root, entries, { env = {}, now = new Date("2026-09-20T12:30:00Z") } = {}) {
  return commitJob(root, { entries, now, env: { ASTRA_OVER_BOUND: "", ...env } });
}

test("M-T3.4: a batch of four takedowns under a bound of three, with none spent today, applies three and holds the fourth", async () => {
  assert.equal(TAKEDOWN_BOUND, 3, "this fixture is written for the owner's bound of 3");
  const root = crowd();
  const entries = ["widgets", ...PEERS].map(takedownOf);
  const { code, logs, results } = await measuredJob(root, entries);
  assert.equal(code, 0, logs.join("\n"));
  assert.deepEqual(results.compiled, SDIS.slice(0, 3),
    "the first three takedowns of the batch are the ones the bound admits");
  assert.deepEqual(results.held.map((h) => [h.service_decision_id, h.held_for]), [[SDIS[3], "bound"]],
    "the fourth takedown in one batch went out unheld — four withdrawals in one commit under a bound of three");
});

test("M-T3.4: the bound counts what git already holds, and a full one is not lifted by the environment", async () => {
  const root = crowd();
  withdrawnInGit(root, ["gadgets", "gizmos"], "2026-09-20T11:30:00Z");
  const two = await measuredJob(root, [takedownOf("widgets", 0), takedownOf("doohickeys", 1)]);
  assert.equal(two.code, 0, two.logs.join("\n"));
  assert.deepEqual(two.results.compiled, [SDIS[0]], "two withdrawn an hour ago leave one; the first takedown spends it");
  assert.deepEqual(two.results.held.map((h) => h.held_for), ["bound"]);

  const full = crowd();
  withdrawnInGit(full, ["gadgets", "gizmos", "doohickeys"], "2026-09-20T11:30:00Z");
  const forced = await measuredJob(full, [takedownOf("widgets", 0)], { env: { ASTRA_OVER_BOUND: "false" } });
  assert.equal(forced.code, 0, forced.logs.join("\n"));
  assert.deepEqual(forced.results.held.map((h) => h.held_for), ["bound"],
    "ASTRA_OVER_BOUND=false applied a takedown past a full bound: an input that says `under` is the whole bypass");
  assert.deepEqual(forced.results.compiled, []);

  // And the window is a window: the same three, withdrawn 25 hours earlier, cost nothing now.
  const old = crowd({ at: "2026-09-19T09:00:00Z" });
  withdrawnInGit(old, ["gadgets", "gizmos", "doohickeys"], "2026-09-19T11:00:00Z");
  const later = await measuredJob(old, [takedownOf("widgets", 0)]);
  assert.deepEqual(later.results.compiled, [SDIS[0]], "a withdrawal older than 24 h still counted");
});

test("M-T3.4: a count the job cannot make holds every takedown, and says why", async () => {
  const root = crowd();
  // A `binary` advisory names a hash this registry records for no listing, so
  // the listed ids it withdraws are unknown (M-T3.2) — and unknown is over.
  writeAll(root, { "tools/revocations/ASTRA-2026-0001.json": {
    id: "ASTRA-2026-0001", published: "2026-09-20", severity: "high", action: "block_install",
    reason: "A test advisory whose binary entry no listing records.",
    entries: [{ kind: "binary", value: "b".repeat(64) }, { kind: "id", value: "gizmos" }],
  } });
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", "hand advisory\n\nModeration-Exempt: operator: fixture"], root, dated("2026-09-20T11:00:00Z"));
  const { code, logs, results } = await measuredJob(root, [takedownOf("widgets", 0)]);
  assert.equal(code, 0, logs.join("\n"));
  assert.deepEqual(results.held.map((h) => h.held_for), ["bound"], "an uncountable window applied a takedown");
  assert.ok(logs.some((l) => /bound/.test(l) && /cannot be counted/.test(l)),
    `the run did not say why it held: ${logs.join(" | ")}`);
});

test("M-T3.4: two revocations in one batch get two advisory ids, and neither overwrites the other", async () => {
  const root = crowd();
  const revoke = (id, i) => decision({
    service_decision_id: SDIS[i], plugin_id: id, code: "M_REVOKE", category: "security_defect",
    severity: "high", action: "block_install", moderator: "amoderator", versions: ["1.0.0"],
  });
  const { code, logs, results } = await measuredJob(root, [revoke("gadgets", 0), revoke("gizmos", 1)]);
  assert.equal(code, 0, logs.join("\n"));
  assert.deepEqual(results.compiled, [SDIS[0], SDIS[1]], logs.join("\n"));
  const files = results.written.filter((p) => p.startsWith("tools/revocations/")).sort();
  assert.deepEqual(files, ["tools/revocations/ASTRA-2026-0001.json", "tools/revocations/ASTRA-2026-0002.json"],
    "two advisories compiled in one run took one id, and the second file overwrote the first: the first plugin's " +
    "revocation was logged as done and never published");
  const byPlugin = {};
  for (const f of files) {
    const doc = JSON.parse(fs.readFileSync(path.join(root, f), "utf8"));
    byPlugin[doc.id] = doc.entries.filter((e) => e.kind === "id_version" || e.kind === "id" || e.kind === "version_range").map((e) => e.value)[0];
  }
  assert.deepEqual(Object.values(byPlugin).map((v) => String(v).split("@")[0]).sort(), ["gadgets", "gizmos"]);
  const logFiles = results.written.filter((p) => p.startsWith("bot/moderation/"));
  assert.equal(new Set(logFiles).size, 2, `two decisions, ${new Set(logFiles).size} log entr(y|ies)`);
});

test("M-T3.4: a second takedown of one plugin in the same batch is `target_changed`, and costs the bound nothing", async () => {
  const root = crowd();
  const { code, logs, results } = await measuredJob(root, [
    takedownOf("widgets", 0), takedownOf("widgets", 1), takedownOf("gadgets", 2), takedownOf("gizmos", 3),
  ]);
  assert.equal(code, 0, logs.join("\n"));
  assert.deepEqual(results.refused.map((r) => [r.service_decision_id, r.refusal]), [[SDIS[1], "target_changed"]],
    "a second delist of a plugin this run already delisted compiled a second time, onto the same file and log entry");
  assert.deepEqual(results.compiled, [SDIS[0], SDIS[2], SDIS[3]],
    "one plugin taken away twice is one plugin: the bound still had room for the other two");
  assert.deepEqual(results.held, []);
});

test("M-T3.4: a revocation spends the bound like a delist, and two of one plugin take two ids and two log names", async () => {
  const root = crowd();
  const revoke = (id, i) => decision({
    service_decision_id: SDIS[i], plugin_id: id, code: "M_REVOKE", category: "security_defect",
    severity: "high", action: "block_install", moderator: "amoderator", versions: ["1.0.0"],
  });
  const three = await measuredJob(root, [revoke("gadgets", 0), revoke("gizmos", 1), revoke("doohickeys", 2), takedownOf("widgets", 3)]);
  assert.equal(three.code, 0, three.logs.join("\n"));
  assert.deepEqual(three.results.held.map((h) => [h.service_decision_id, h.held_for]), [[SDIS[3], "bound"]],
    "three revocations spent nothing, and a fourth takedown went out unheld");

  const same = crowd();
  const twice = await measuredJob(same, [revoke("gadgets", 0), revoke("gadgets", 1)]);
  assert.equal(twice.code, 0, twice.logs.join("\n"));
  assert.deepEqual(twice.results.compiled, [SDIS[0], SDIS[1]]);
  const logs = twice.results.written.filter((p) => p.startsWith("bot/moderation/")).sort();
  assert.equal(logs.length, 2, `two revocations of one plugin wrote ${logs.length} log entr(y|ies): ${logs.join(", ")}`);
  assert.deepEqual(logs, ["bot/moderation/2026-09-20-gadgets-revoke-2.json", "bot/moderation/2026-09-20-gadgets-revoke.json"],
    "the second revocation of a plugin in one run took the first one's log name and overwrote its entry (MOD-47)");
});

test("M-T3.4: the staging listing costs the batch nothing, as it costs the window nothing (MOD-16)", async () => {
  const canary = "astra-withdrawal-canary";
  const extra = {
    "policy/reserved-ids.json": { staging_listing_id: canary },
    [`plugins/${canary}/plugin.json`]: plugin(canary),
    [`plugins/${canary}/versions/1.0.0.json`]: version(canary, "1.0.0"),
    [`plugins/${canary}/identity.json`]: identity(canary),
  };
  for (const id of PEERS) {
    extra[`plugins/${id}/plugin.json`] = plugin(id);
    extra[`plugins/${id}/versions/1.0.0.json`] = version(id, "1.0.0");
    extra[`plugins/${id}/identity.json`] = identity(id);
  }
  const root = estate({ extra, at: "2026-09-20T09:00:00Z" });
  const pathTest = decision({
    service_decision_id: SDIS[4], plugin_id: canary, code: "M_DEPRECATE", category: "path_test",
    severity: "low", moderator: "amoderator", versions: ["1.0.0"],
  });
  const { code, logs, results } = await measuredJob(root, [pathTest, takedownOf("widgets", 0), takedownOf("gadgets", 1), takedownOf("gizmos", 2)]);
  assert.equal(code, 0, logs.join("\n"));
  assert.deepEqual(results.held, [], "the staging listing's path test spent the bound and held a real takedown");
  assert.deepEqual(results.compiled, [SDIS[4], SDIS[0], SDIS[1], SDIS[2]]);
});

// ── M-T3.5: the operator's four acts (MOD-52, TRUST-33, BOT-70) ─────────────
//
// `tools/operator.mjs` and `bot/lib/operator-role.mjs`, run the way
// `.github/workflows/operator.yml` runs them. The workflow's own boundary —
// environment `operator`, which admits `main` alone — is a setting GitHub
// enforces before a job starts, and `bot/tests/workflows.test.mjs` holds the
// workflow to it; what is tested here is everything the tree decides.

const OP_RUN = "https://github.com/mihailinl/astra-registry/actions/runs/35999999999";
const OP_NOW = new Date("2026-09-24T08:00:00Z");

/** A stub of GitHub's collaborator-permission endpoint: login → role, or an HTTP status. */
function rolesApi(table) {
  return async (url) => {
    const login = decodeURIComponent(String(url).split("/collaborators/")[1].split("/")[0]);
    const v = table[login];
    if (typeof v === "number") return { ok: false, status: v, json: async () => ({}) };
    if (v === undefined) return { ok: true, status: 200, json: async () => ({ role_name: "read", permission: "read" }) };
    return { ok: true, status: 200, json: async () => ({ role_name: v, permission: v === "maintain" ? "write" : v }) };
  };
}

test("M-T3.5: only an admin or a maintainer may act, as actor AND triggering actor, on the first attempt only", async () => {
  const { operatorAuthority } = await import("../lib/operator-role.mjs");
  const ask = (over) => operatorAuthority({
    repo: "mihailinl/astra-registry", actor: "opadmin", triggeringActor: "opadmin", runAttempt: "1",
    fetchImpl: rolesApi({ opadmin: "admin", opmaint: "maintain", opwriter: "write", opgone: 404, opblind: 403 }), ...over,
  });
  assert.equal((await ask({})).ok, true, "an admin on attempt 1 was refused");
  assert.equal((await ask({ actor: "opmaint", triggeringActor: "opmaint" })).ok, true, "a maintainer was refused");
  for (const [what, over] of [
    ["a `write` collaborator", { actor: "opwriter", triggeringActor: "opwriter" }],
    ["an admin actor with a `write` triggering actor", { triggeringActor: "opwriter" }],
    ["a `write` actor re-run by an admin", { actor: "opwriter" }],
    ["an unanswered API (403)", { actor: "opblind", triggeringActor: "opblind" }],
    ["an unanswered API (404)", { actor: "opgone", triggeringActor: "opgone" }],
    ["a non-collaborator", { actor: "stranger", triggeringActor: "stranger" }],
    ["run_attempt 2", { runAttempt: "2" }],
    ["a login that is not one", { actor: "not a login" }],
  ]) {
    const got = await ask(over);
    assert.equal(got.ok, false, `${what} was allowed an operator act: ${got.why}`);
  }
});

/** An estate with one bound listing, and holds entered the way the commit job enters them. */
function heldEstate(decisions) {
  const root = crowd();
  const { held } = compileAll(decisions, { root, overBound: true });
  moderationRun.writeHoldEntries(held, { root, heldAt: "2026-09-24T07:00:00Z", run: OP_RUN });
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", "holds"], root, dated("2026-09-24T07:00:00Z"));
  return root;
}

async function operator(root, env, { authority = null } = {}) {
  const { main: operatorMain } = await import("../../tools/operator.mjs");
  const logs = [];
  const out = path.join(root, "operator");
  const code = await operatorMain(["--job", "act", "--registry-dir", root, "--out", out], {
    env: { GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "mihailinl/astra-registry", GITHUB_RUN_ID: "35999999999", ...env },
    log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
    now: OP_NOW,
    ...(authority ? { fetchImpl: authority } : {}),
  });
  const read = (f) => (fs.existsSync(path.join(out, f)) ? fs.readFileSync(path.join(out, f), "utf8") : null);
  return { code, logs, paths: (read("paths.txt") ?? "").split("\n").filter(Boolean), message: read("commit-message.txt") };
}

test("M-T3.5: confirm and cancel answer a hold on main once, and a confirm never reaches an unbound_yank", async () => {
  const root = heldEstate([takedownOf("widgets", 0), takedownOf("gadgets", 1)]);
  const ok = await operator(root, { ASTRA_ACT: "confirm", ASTRA_SERVICE_DECISION_ID: SDIS[0] });
  assert.equal(ok.code, 0, ok.logs.join("\n"));
  assert.deepEqual(ok.paths, [`state/holds/${SDIS[0]}.confirm.json`]);
  const record = JSON.parse(fs.readFileSync(path.join(root, ok.paths[0]), "utf8"));
  assert.deepEqual(Object.keys(record).sort(), ["act", "at", "plugin_id", "run", "schema", "service_decision_id"]);
  assert.equal(record.act, "confirm");
  assert.match(ok.message, /^Run: 35999999999$/m);
  const holds = readHolds(root);
  assert.ok(holds.find((h) => h.id === SDIS[0]).confirm, "readHolds does not see the record the operator wrote");
  assert.deepEqual(holds.find((h) => h.id === SDIS[0]).problems, []);

  const again = await operator(root, { ASTRA_ACT: "cancel", ASTRA_SERVICE_DECISION_ID: SDIS[0] });
  assert.equal(again.code, 1, "a hold already answered took a second answer");
  const none = await operator(root, { ASTRA_ACT: "confirm", ASTRA_SERVICE_DECISION_ID: SDIS[4] });
  assert.equal(none.code, 1, "a confirmation of a hold that is not on main was written");
  const cancel = await operator(root, { ASTRA_ACT: "cancel", ASTRA_SERVICE_DECISION_ID: SDIS[1] });
  assert.equal(cancel.code, 0, cancel.logs.join("\n"));
  assert.deepEqual(cancel.paths, [`state/holds/${SDIS[1]}.cancel.json`]);

  // An unbound listing's A_YANK is held `unbound_yank`, and only a cancel ends it.
  const unbound = estate({ bound: false, at: "2026-09-24T06:00:00Z" });
  const yank = decision({ code: "A_YANK", category: "author_request", reason: FIXED_YANK, versions: ["1.0.0"] });
  const { held } = compileAll([yank], { root: unbound, overBound: false });
  assert.equal(held[0]?.held_for, "unbound_yank", "the fixture did not produce an unbound_yank hold");
  moderationRun.writeHoldEntries(held, { root: unbound, heldAt: "2026-09-24T06:30:00Z", run: OP_RUN });
  const refused = await operator(unbound, { ASTRA_ACT: "confirm", ASTRA_SERVICE_DECISION_ID: SDI });
  assert.equal(refused.code, 1, "a confirmation was written for an unbound_yank, which no confirmation releases");
  assert.ok(refused.logs.some((l) => /unbound_yank/.test(l)), refused.logs.join("\n"));
});

test("M-T3.5: a revert undoes an applied delist or revoke, logs what it reverses, and refuses a yank", async () => {
  const root = crowd();
  const job = await measuredJob(root, [
    takedownOf("gadgets", 0),
    decision({ service_decision_id: SDIS[1], plugin_id: "gizmos", code: "M_REVOKE", category: "security_defect",
      severity: "high", action: "block_install", moderator: "amoderator", versions: ["1.0.0"] }),
    // widgets has three versions; yanking a listing's LAST listed version makes
    // the index generator refuse the whole tree, which is a finding of its own.
    decision({ service_decision_id: SDIS[2], plugin_id: "widgets", code: "M_YANK", category: "broken",
      moderator: "amoderator", versions: ["1.0.0"] }),
  ]);
  assert.equal(job.code, 0, job.logs.join("\n"));
  sh(["add", "-A", "--", ".", ":!moderation"], root);
  sh(["commit", "-q", "-m", "moderation"], root, dated("2026-09-24T07:00:00Z"));

  const relist = await operator(root, { ASTRA_ACT: "revert", ASTRA_SERVICE_DECISION_ID: SDIS[0] });
  assert.equal(relist.code, 0, relist.logs.join("\n"));
  assert.ok(!("unlisted" in JSON.parse(fs.readFileSync(path.join(root, "plugins/gadgets/plugin.json"), "utf8"))));
  const logFile = relist.paths.find((p) => p.startsWith("bot/moderation/"));
  assert.equal(logFile, "bot/moderation/2026-09-24-gadgets-relist.json");
  const entry = JSON.parse(fs.readFileSync(path.join(root, logFile), "utf8"));
  assert.equal(entry.action, "relist");
  assert.equal(entry.reverses, SDIS[0]);
  assert.equal(entry.category, "error");
  assert.ok(relist.paths.includes("registry/v1/index.json"), `the index was not regenerated: ${relist.paths.join(", ")}`);
  assert.match(relist.message, new RegExp(`^Service-Decision: ${SDIS[0]}$`, "m"), "MOD-52's revert carries Service-Decision:");

  const unrevoke = await operator(root, { ASTRA_ACT: "revert", ASTRA_SERVICE_DECISION_ID: SDIS[1] });
  assert.equal(unrevoke.code, 0, unrevoke.logs.join("\n"));
  const advisory = unrevoke.paths.find((p) => p.startsWith("tools/revocations/"));
  assert.ok(advisory && !fs.existsSync(path.join(root, advisory)), `the advisory was not deleted: ${unrevoke.paths.join(", ")}`);
  assert.ok(unrevoke.paths.includes("registry/v1/revocations.json"), "the withdrawal list was not regenerated");

  const yank = await operator(root, { ASTRA_ACT: "revert", ASTRA_SERVICE_DECISION_ID: SDIS[2] });
  assert.equal(yank.code, 1, "a yank was reverted; MOD-52 reverts a delist, a deprecate or a revoke only");
  assert.ok(yank.logs.some((l) => /not reversible/.test(l)),
    `a yank was refused, but not because a yank is not reversible: ${yank.logs.join(" | ")}`);
  sh(["add", "-A", "--", ".", ":!operator"], root);
  sh(["commit", "-q", "-m", "reverts"], root, dated("2026-09-24T08:00:00Z"));
  // The same listing delisted AGAIN by a later decision: the tree now looks
  // exactly like the first delist before its revert, so only the log can say
  // the first decision is already reverted.
  withdrawnInGit(root, ["gadgets"], "2026-09-24T08:30:00Z");
  const twice = await operator(root, { ASTRA_ACT: "revert", ASTRA_SERVICE_DECISION_ID: SDIS[0] });
  assert.equal(twice.code, 1, "a decision already reverted was reverted again, relisting a plugin a later decision delisted");
  assert.ok(twice.logs.some((l) => /already reverted/.test(l)), twice.logs.join(" | "));
});

test("M-T3.5: a deny is TRUST-33's four members, written once, and names a fingerprint and nothing else", async () => {
  const root = crowd();
  const fp = "4f1c9a02be773d15";
  const ok = await operator(root, { ASTRA_ACT: "deny", ASTRA_FINGERPRINT: fp });
  assert.equal(ok.code, 0, ok.logs.join("\n"));
  assert.deepEqual(ok.paths, [`state/deny/${fp}.json`]);
  const doc = JSON.parse(fs.readFileSync(path.join(root, ok.paths[0]), "utf8"));
  assert.deepEqual(Object.keys(doc).sort(), ["at", "fingerprint", "run", "schema"]);
  assert.equal(doc.schema, "astra.registry.deny/1");
  assert.equal((await operator(root, { ASTRA_ACT: "deny", ASTRA_FINGERPRINT: fp })).code, 1, "a deny was written twice");
  assert.equal((await operator(root, { ASTRA_ACT: "deny", ASTRA_FINGERPRINT: "not-a-fingerprint" })).code, 1);
  assert.equal((await operator(root, { ASTRA_ACT: "deny", ASTRA_FINGERPRINT: fp.replace("4", "5"), ASTRA_SERVICE_DECISION_ID: SDIS[0] })).code, 1,
    "a deny naming a service decision too was accepted");
  assert.equal((await operator(root, { ASTRA_ACT: "approve", ASTRA_SERVICE_DECISION_ID: SDIS[0] })).code, 1, "a fifth act ran");
});

test("M-T3.5: the operator's allowlist admits its records, its revert paths and the two documents, and nothing else", async () => {
  const { operatorPath } = await import("../../tools/operator.mjs");
  for (const good of [`state/holds/${SDIS[0]}.confirm.json`, `state/holds/${SDIS[0]}.cancel.json`, "state/deny/4f1c9a02be773d15.json",
    "plugins/widgets/plugin.json", "bot/moderation/2026-09-24-widgets-relist.json", "bot/moderation/2026-09-24-widgets-unrevoke-2.json",
    "tools/revocations/ASTRA-2026-0001.json", "registry/v1/index.json", "registry/v1/revocations.json"]) {
    assert.equal(operatorPath(good), true, `${good} is a path an operator act writes`);
  }
  for (const bad of [`state/holds/${SDIS[0]}.json`, "state/queue/x.json", "plugins/widgets/versions/1.0.0.json",
    "bot/moderation/2026-09-24-widgets-delist.json", "policy/reserved-ids.json", "state/deny/../../x.json",
    "bot/lib/operator-role.mjs", ".github/workflows/operator.yml", "tools/revocations/README.md"]) {
    assert.equal(operatorPath(bad), false, `${bad} passes the operator's allowlist`);
  }
});

// ── A yank of a listing's last listed version (the coordinator's decision, 2026-09-24) ──
//
// Measured before the repair: a batch carrying an `M_YANK` of a one-version
// listing made `regenerateDocuments` throw "every version is yanked or
// missing" from `tools/build-index.mjs`, so the commit job wrote nothing for
// ANY decision in the batch, and the list answer named the same decisions on
// the next run. The decision: such a yank is valid, and the catalogue omits a
// listing with no installable version; its records stay on `main`.

test("a batch that yanks a one-version listing, with another takedown: both apply, and the listing leaves the catalogue", async () => {
  const root = crowd();
  const entries = [
    decision({ service_decision_id: SDIS[0], plugin_id: "gizmos", code: "M_YANK", category: "broken",
      moderator: "amoderator", versions: ["1.0.0"] }),
    takedownOf("gadgets", 1),
  ];
  const { code, logs, results } = await measuredJob(root, entries);
  assert.equal(code, 0, logs.join("\n"));
  assert.deepEqual(results.compiled, [SDIS[0], SDIS[1]],
    "the batch lost a takedown: a yank of a listing's last version must not stop the others");
  assert.ok(results.written.includes("plugins/gizmos/versions/1.0.0.json"), `the yank was not written: ${results.written.join(", ")}`);
  const index = JSON.parse(fs.readFileSync(path.join(root, "registry", "v1", "index.json"), "utf8"));
  const ids = index.signed.plugins.map((p) => p.id).sort();
  assert.deepEqual(ids, ["doohickeys", "widgets"],
    "the regenerated catalogue still carries a listing with no installable version, or lost one that has one");
  assert.ok(fs.existsSync(path.join(root, "plugins", "gizmos", "plugin.json")), "the yanked listing's records left main");

  // A later release that is not yanked brings it back.
  writeAll(root, { "plugins/gizmos/versions/1.1.0.json": version("gizmos", "1.1.0") });
  const back = buildIndex({ root, serial: 1 }).signed.plugins.find((p) => p.id === "gizmos");
  assert.ok(back, "a new version did not bring the listing back");
  assert.equal(back.version, "1.1.0");
});

// ── the records a compiled result carries reach the commit ──────────────────
//
// `composeCommit` listed edits and log entries and never the decision records
// the same result carries, so `applyCompiled` wrote an `A_YANK`'s BOT-34
// records to the runner's tree and `git add --pathspec-from-file` never staged
// them: the yank landed, the records stayed behind, and `tools/validate.mjs`'s
// BOT-34 count went red on `main` after the push rather than before it.
// B-T4.2's release depends on the same line — detector A9 excuses the deletion
// of an identity record only beside the voiding record in the SAME commit.
test("a compiled result's decision records are listed for the commit, at the path the writer puts them", () => {
  const root = estate();
  const { compiled } = compileAll(
    [decision({ code: "A_YANK", versions: ["1.0.0", "1.1.0"], reason: FIXED_YANK })],
    { root, overBound: false },
  );
  const written = applyCompiled(compiled, { root });
  const records = written.filter((p) => p.startsWith("log/decisions/"));
  assert.equal(records.length, 2, `the fixture wrote ${records.length} author-action records; this proves nothing without two`);
  const commit = composeCommit({ compiled, run: "35502265394" });
  for (const rel of records) {
    assert.ok(commit.paths.includes(rel), `${rel} was written and is not in paths.txt, so it is never committed (BOT-34)`);
  }
});

// ── B-T4.2: M_IDENTITY_RESET, walked to the end ─────────────────────────────
//
// The plan's canary, both cases, through `--job commit` and the workflow's own
// `apply` step: a listing refused `B_REPOSITORY_RECYCLED` is reset; the reset
// is held (MOD-9, a reversal), lands, waits out 24 hours from that commit AND
// an operator's confirmation, and is released in ONE commit carrying
// `Service-Decision:` — DEC-7's voiding record, the log entry `reset`, the hold
// entry and its confirm record deleted, and in case (ii) the identity record
// deleted too (ID-40). The next live run reads that commit as `applied`;
// detector A9 is silent on it; the listing reads `frozen` (ID-25); and the new
// owner's certificate is held `R_IDENTITY_CHANGED` against a voided baseline,
// never refused `B_REPOSITORY_RECYCLED` again.

const RESET_REASON = "The repository name was re-registered by its new owner after the old one deleted it.";
const resetOf = (id = SDI) => decision({
  service_decision_id: id, code: "M_IDENTITY_RESET", category: "identity_reset",
  moderator: "amoderator", declared_interest: false, reason: RESET_REASON,
});
const OLD_IDS = { repository_id: "912345678", repository_owner_id: "4711" };
/** A certificate for `acme/widgets`, the name the baseline recorded (TRUST-23 compares both ids and the name). */
const CERT = {
  job_workflow_ref: `https://github.com/mihailinl/AstraPlugins/.github/workflows/plugin-release.yml@${"c".repeat(40)}`,
  job_workflow_sha: "c".repeat(40),
  runner_environment: "github-hosted",
  source_repository_uri: "https://github.com/acme/widgets",
  sha: "a".repeat(40),
  ref: "refs/tags/widgets-v2.0.0",
  event_name: "push",
  run: "https://github.com/acme/widgets/actions/runs/1/attempts/1",
};
const NEW_IDS = { repository_id: "2000000001", repository_owner_id: "2000000002" };

/**
 * A listing published by the old owner (its migration baseline and the
 * baseline marker, which arms detector A9), then refused
 * `B_REPOSITORY_RECYCLED` when the name's new owner released.
 */
function recycledEstate({ bound }) {
  const root = estate({ bound, at: "2026-09-10T00:00:00Z" });
  if (bound) {
    // B.4's identity record: the file's own `identity()` carries a 64-hex hash.
    writeAll(root, { "plugins/widgets/identity.json": { ...identity("widgets"), token_hash: "0123456789abcdef" } });
  }
  const source = sh(["rev-parse", "HEAD"], root).trim();
  writeAll(root, {
    "log/decisions/2026/09/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json": {
      schema: "astra.registry.decision/1", decision_id: "a".repeat(32), decided_at: "2026-09-11T00:00:00Z",
      actor: "system", trigger: "migration", plugin_id: "widgets", version: "1.2.0", repo: "acme/widgets",
      tag: "widgets-v1.2.0", state: "published", ...OLD_IDS,
    },
    "log/baseline.json": {
      schema: "astra.registry.baseline/1", written_at: "2026-09-11T00:00:00Z", source_commit: source,
      version_count: 1, record_count: 1,
    },
  });
  commitAt(root, "2026-09-11T00:00:00Z", "registry: the migration baseline");
  writeAll(root, {
    "log/decisions/2026/09/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json": {
      schema: "astra.registry.decision/1", decision_id: "b".repeat(32), decided_at: "2026-09-19T10:00:00Z",
      actor: "bot", trigger: "panel", plugin_id: "widgets", repo: "acme/widgets", tag: "widgets-v2.0.0",
      state: "refused", reasons: ["B_REPOSITORY_RECYCLED"], ...NEW_IDS,
    },
  });
  commitAt(root, "2026-09-19T10:00:00Z", "registry: refused, the repository was re-created by another owner");
  return withDocuments(root);
}

/** The reset entered and landed at 2026-09-20T12:45Z, as the workflow lands it. */
async function heldReset({ bound }) {
  const root = recycledEstate({ bound });
  const origin = withRemote(root);
  const job = await commitJob(root, { entries: [resetOf()], now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.held.map((h) => h.held_for), ["reversal"], "MOD-9 holds an M_IDENTITY_RESET as a reversal");
  assert.deepEqual(job.paths, [holdEntryPath(SDI)], `entering the hold wrote more than the hold: ${job.paths.join(" ")}`);
  const step = runApply(root, dated("2026-09-20T12:45:00Z"));
  assert.equal(step.status, 0, step.stderr);
  return { root, origin };
}

const landedFiles = (root) => sh(["show", "--name-status", "--format=", "HEAD"], root).trim().split("\n").sort();

test("B-T4.2 (ii): a bound listing's reset is held, released once in one commit, and never refused again", async () => {
  const { root, origin } = await heldReset({ bound: true });

  // Without a confirmation, however long it waits: nothing.
  const unconfirmed = await commitJob(root, { entries: [], now: new Date("2026-09-22T12:00:00Z") });
  assert.equal(unconfirmed.code, 0, unconfirmed.logs.join("\n"));
  assert.deepEqual(unconfirmed.paths, [], "an unconfirmed reset wrote something");
  assert.ok(fs.existsSync(path.join(root, "plugins/widgets/identity.json")));

  // Confirmed at 13:00, and asked at 12:44 the next day — a minute inside the
  // 24 hours that run from the commit that landed the entry: nothing.
  writeAll(root, { [`state/holds/${SDI}.confirm.json`]: confirmOf(SDI, "2026-09-20T13:00:00Z") });
  commitAt(root, "2026-09-20T13:00:00Z", "operator: confirm");
  const early = await commitJob(root, { entries: [], now: new Date("2026-09-21T12:44:00Z") });
  assert.deepEqual(early.paths, [], `a reset released before its 24 hours: ${early.paths.join(" ")}`);

  // Due: the release, and nothing else.
  const job = await commitJob(root, { entries: [], now: new Date("2026-09-21T12:46:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.released_holds, [SDI]);
  assert.ok(!job.logs.some((l) => l.includes("hold_end_not_built")), "the reset's release is built, and was refused as not built");
  const voidingKey = `service-decision:${SDI}:widgets::identity_reset`;
  const voidingPath = recordPath({ decision_id: decisionId(voidingKey), decided_at: "2026-09-20T12:00:00Z" });
  for (const rel of [
    "plugins/widgets/identity.json", "bot/moderation/2026-09-20-widgets-reset.json", voidingPath,
    holdEntryPath(SDI), `state/holds/${SDI}.confirm.json`,
  ]) {
    assert.ok(job.paths.includes(rel), `the release commit does not list ${rel}: ${job.paths.join(" ")}`);
  }
  const step = runApply(root, dated("2026-09-21T12:50:00Z"));
  assert.equal(step.status, 0, step.stderr);
  const released = headOf(origin);
  const files = landedFiles(root);
  for (const want of [
    "D\tplugins/widgets/identity.json", "A\tbot/moderation/2026-09-20-widgets-reset.json", `A\t${voidingPath}`,
    `D\t${holdEntryPath(SDI)}`, `D\tstate/holds/${SDI}.confirm.json`,
  ]) assert.ok(files.includes(want), `the landed release commit lacks ${want}: ${files.join(" | ")}`);
  assert.match(sh(["log", "-1", "--format=%B", released], root), new RegExp(`^Service-Decision: ${SDI}$`, "m"));

  // DEC-7's voiding record and MOD-47's entry, as `main` now holds them.
  const record = JSON.parse(fs.readFileSync(path.join(root, voidingPath), "utf8"));
  assert.deepEqual(
    [record.actor, record.trigger, record.state, record.category, record.reasons, record.plugin_id],
    ["moderator", "moderation", "identity_reset", "identity_reset", ["M_IDENTITY_RESET"], "widgets"],
  );
  const entry = JSON.parse(fs.readFileSync(path.join(root, "bot/moderation/2026-09-20-widgets-reset.json"), "utf8"));
  assert.deepEqual(checkEntry(entry), [], "the log refuses the entry the release wrote");

  // BOT-81 through history: the next live run reads the commit as `applied`.
  const after = walkHolds({ root, now: new Date("2026-09-21T13:00:00Z"), shadow: false });
  assert.deepEqual(after.pending, [{ service_decision_id: SDI, outcome: "applied", commit: released }]);
  assert.deepEqual(after.released.map((r) => r.hand), [false], "the release commit read as a hand deletion");
  const again = await commitJob(root, { entries: [], now: new Date("2026-09-22T13:00:00Z") });
  assert.deepEqual(again.paths, [], "a released reset was released a second time");

  // Detector A9 excuses the deletion because the voiding record is beside it.
  const detected = detect({ root });
  assert.ok(detected.ran.includes("A9") && detected.scanned.identity_commits >= 1,
    `A9 did not read the release commit (ran ${detected.ran.join(", ")}; skipped ` +
    `${JSON.stringify(detected.skipped)}), so its silence below would say nothing`);
  assert.deepEqual(detected.findings.filter((f) => f.detector === "A9"), [],
    "A9 alarmed on the reset's own release commit");

  // ID-25: a listing that ever had an identity record is `frozen`, never
  // `grandfathered` again, so a release with no binding line is `B_UNBOUND`.
  assert.equal(listingStateAt(root, "widgets", { now: "2026-09-22T00:00:00Z", schemaRoot: REPO }).state, "frozen");

  // TRUST-23 against what `main` now holds, through the service path's own
  // baseline reader (`baselineFor`, bot/lib/service-decide.mjs): no baseline,
  // so MIG-28 holds the new owner's release `R_IDENTITY_CHANGED` — and never
  // refuses it `B_REPOSITORY_RECYCLED` again. Without the voiding record (the
  // mutation the plan names), the old baseline stands and it is refused a
  // second time.
  const records = loadRecords(root).decisions.map((r) => r.doc);
  const certificate = identityFromCertificate({ ...CERT, ...NEW_IDS });
  const { baseline } = baselineFor({ records, pluginId: "widgets" });
  assert.equal(baseline, null, "the voiding record did not end the old baseline");
  assert.equal(compareWithBaseline({ identity: certificate, baseline }).code, "R_IDENTITY_CHANGED");
  const withoutVoiding = baselineFor({ records: records.filter((r) => r.category !== "identity_reset"), pluginId: "widgets" });
  assert.equal(compareWithBaseline({ identity: certificate, baseline: withoutVoiding.baseline }).code, "B_REPOSITORY_RECYCLED",
    "the counterfactual is not the defect the voiding record exists to prevent, so the line above proves nothing");
});

test("B-T4.2 (i): an unbound listing's reset writes the voiding record and the entry, and deletes no identity record", async () => {
  const { root, origin } = await heldReset({ bound: false });
  writeAll(root, { [`state/holds/${SDI}.confirm.json`]: confirmOf(SDI, "2026-09-20T13:00:00Z") });
  commitAt(root, "2026-09-20T13:00:00Z", "operator: confirm");
  const job = await commitJob(root, { entries: [], now: new Date("2026-09-21T12:46:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.released_holds, [SDI]);
  assert.ok(!job.paths.some((p) => p.endsWith("identity.json")), "a release with no identity record touched one");
  assert.equal(runApply(root, dated("2026-09-21T12:50:00Z")).status, 0);
  const records = loadRecords(root).decisions.map((r) => r.doc);
  assert.equal(records.filter((r) => r.category === "identity_reset").length, 1,
    "no voiding record: deleting nothing and writing nothing would leave the refusal where it was");
  const { baseline } = baselineFor({ records, pluginId: "widgets" });
  assert.equal(compareWithBaseline({ identity: identityFromCertificate({ ...CERT, ...NEW_IDS }), baseline }).code, "R_IDENTITY_CHANGED");
  assert.equal(walkHolds({ root, now: new Date("2026-09-21T13:00:00Z"), shadow: false }).pending[0]?.commit, headOf(origin));
});

test("B-T4.2: a due reset the tree moved under writes nothing and alerts by name, every run", async () => {
  const { root } = await heldReset({ bound: true });
  writeAll(root, { [`state/holds/${SDI}.confirm.json`]: confirmOf(SDI, "2026-09-20T13:00:00Z") });
  commitAt(root, "2026-09-20T13:00:00Z", "operator: confirm");
  // Another reset of the same refusal voided the id while this one waited.
  writeAll(root, {
    "log/decisions/2026/09/cccccccccccccccccccccccccccccccc.json": {
      schema: "astra.registry.decision/1", decision_id: "c".repeat(32), decided_at: "2026-09-21T09:00:00Z",
      actor: "moderator", moderator: "amoderator", trigger: "moderation", plugin_id: "widgets",
      state: "identity_reset", reasons: ["M_IDENTITY_RESET"], category: "identity_reset",
    },
  });
  commitAt(root, "2026-09-21T09:00:00Z", "moderation: an earlier reset of widgets");
  const job = await commitJob(root, { entries: [], now: new Date("2026-09-21T12:46:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.paths, [], `a reset MOD-10 now refuses was released: ${job.paths.join(" ")}`);
  assert.ok(job.logs.some((l) => l.startsWith(`::error::hold_release_refused ${SDI}:`) && l.includes("target_changed")),
    job.logs.join(" | "));
  assert.ok(fs.existsSync(path.join(root, "plugins/widgets/identity.json")));
  assert.ok(fs.existsSync(path.join(root, holdEntryPath(SDI))), "the entry left the tree without a commit that names it");
});
