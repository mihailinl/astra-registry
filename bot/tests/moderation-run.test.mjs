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
  LIST_OUTPUTS,
  MAX_OUTPUT_BYTES,
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
  listOutputs,
  listRefusals,
  listSummary,
  main,
  readShadow,
  resultsFor,
  resultsFromState,
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
import { buildModerationLog, categoryWords, checkEntry } from "../lib/moderation.mjs";
import { REVOCATIONS_SCHEMA, publicKeyFromBase64, verifyEnvelope } from "../lib/sign.mjs";
import { signRevocations } from "../../tools/sign-revocations.mjs";
import { loadTestRoot } from "../../tools/testkeys/regenerate.mjs";
import { detect } from "../detectors.mjs";
import { loadRecords } from "../../tools/lib/sources.mjs";
// What ops entry 101 added, off the namespaces, so that this suite run against
// modules without them is red test by test rather than at import.
import * as holdsModule from "../lib/holds.mjs";
import * as moderationRun from "../moderation-run.mjs";
import { operatorAct } from "../../tools/operator.mjs";
import { shapeFindings, withoutAuthorship, withoutUuidTrailers } from "../../tools/priv-scan.mjs";
// Contract 3.0.0's (MOD-56), off the namespaces for the same reason.
import * as compiler from "../lib/compile-decision.mjs";
import { countWindow } from "../lib/takedown-bound.mjs";
// Ops entry 100's module, imported so that this suite, run against a tree
// without it, is red test by test rather than at import.
const settledLib = await import("../lib/settled.mjs").catch(() => null);
import { CATEGORIES, TAKEDOWN_BOUND } from "../lib/moderation.mjs";
import { BOT_AUDIENCE } from "../lib/oidc.mjs";
import { BODIES, CALL_TIMEOUT_MS } from "../lib/service.mjs";
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

/**
 * A decision MOD-9 still holds whatever the bound says (contract 6.6.0): an
 * unbound listing's removal request (`unbound_removal`), which nothing ends by
 * itself. Use it with `estate({ bound: false })`.
 */
const removalOf = (id = SDI, over = {}) => decision({ service_decision_id: id, code: "A_REMOVAL_REQUEST", reason: FIXED_REMOVAL, ...over });

/** A hold entry for `removalOf`, as the commit job writes one, for a tree that should hold a hold that stays. */
const removalEntry = (sdi, held_at = "2026-09-18T12:00:00Z") => holdEntry(
  { service_decision_id: sdi, code: "A_REMOVAL_REQUEST", plugin_id: "widgets", decided_at: "2026-09-18T11:00:00Z", reason: FIXED_REMOVAL },
  { held_for: "unbound_removal", held_at },
);

/**
 * A hold entry of any kind. The kinds MOD-9 writes go through `holdEntry`; the
 * two the rule before contract 6.6.0 wrote — `reversal` and
 * `disable_confirmation` — are built by hand, member for member as the old
 * `holdEntry` wrote them (`release_after` on a reversal), because the bot now
 * refuses to write one and a run must still end one it meets on the tree.
 */
function holdFixture(decisionDoc, { held_for, held_at }) {
  if (held_for !== "reversal" && held_for !== "disable_confirmation") return holdEntry(decisionDoc, { held_for, held_at });
  const named = Object.keys(JSON.parse(read("schema/hold-v1.json")).properties.decision.properties);
  const copied = Object.fromEntries(Object.entries(decisionDoc).filter(([k, v]) => named.includes(k) && v !== undefined));
  const plus24 = new Date(Date.parse(held_at) + 24 * 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  return {
    schema: "astra.registry.hold/1", held_for, service_decision_id: decisionDoc.service_decision_id, held_at,
    ...(held_for === "reversal" ? { release_after: plus24 } : {}),
    decision: copied,
  };
}

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
  // 6.7.0 (MOD-57): the applied decision an M_CORRECT_CATEGORY corrects.
  corrects: "0192f3a4-5b6c-7d8e-9f01-2345678930cc",
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
  assert.equal(named.length, 15, `BOT-80 names 15 members for a moderator decision (\`corrects\` since 6.7.0) and this list has ${named.length}`);

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
    [decision({ code: "M_DELIST", category: "broken", moderator: "amoderator", x: "leaked" })],
    { root, overBound: true },
  ).held;
  assert.equal(held.length, 1, "MOD-9 holds every takedown over the bound");
  assert.equal(held[0].held_for, "bound");
  assert.ok(!JSON.stringify(held[0].decision).includes("leaked"),
    "a member the schema ignored on read reached the held decision, and a hold entry is committed to git");
  assert.ok(Object.hasOwn(held[0].decision, "moderator"), "and a member BOT-80 DOES name was kept");
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
// nothing released anything. From then until 2026-10-14 it asserted the truth
// of that day instead — the hold is due, refused by name (`hold_end_not_built`)
// and nothing is posted — and said the builder of the release commit would
// turn it back into the plan's canary. This is that canary (M-T3.4: "with
// `list` down, a confirmed reversal releases and posts next run"), for both
// ends a hold on the tree can come to: a confirmed reversal past its period
// (the release commit) and a cancel record (the cancel commit). Watched failing
// by handing the walk's `releasable` to nothing, and by writing a log entry in
// the cancel commit — which `classifyHoldCommit` then reads as an `applied`.
test("with `list` down, a reversal held before contract 6.6.0 is released in one commit, and the next live run posts what that commit did", async () => {
  const held = {
    schema: "astra.registry.hold/1",
    held_for: "reversal",
    service_decision_id: SDI,
    held_at: "2026-09-18T12:00:00Z",
    release_after: "2026-09-19T12:00:00Z",
    decision: {
      service_decision_id: SDI, code: "M_RELIST", category: "error", plugin_id: "widgets",
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

  for (const [end, record, outcome] of [["release", confirm, "applied"], ["cancel", cancel, "cancelled"]]) {
    // A leftover from before contract 6.6.0, when MOD-9 held every relist:
    // nothing will confirm it now, so a run ends it — released at once, or
    // cancelled by the cancel record beside it.
    const root = withDocuments(estate({
      extra: { ...delisted, [`state/holds/${SDI}.json`]: held, [`state/holds/${SDI}.${record.act}.json`]: record },
      at: held.held_at,
    }));
    const origin = withRemote(root);
    const now = new Date("2026-09-20T00:00:00Z");

    for (const shadow of [true, false]) {
      const walked = walkHolds({ root, now, shadow });
      // The satisfiable half first: the hold IS due, or this proves nothing.
      assert.deepEqual(dueIds(walked), [`${SDI} ${end}`], `the fixture's hold should be due to ${end} (shadow: ${shadow})`);
      assert.deepEqual(walked.due, [], `a due ${end} was refused as not built`);
      assert.deepEqual(walked.pending, [], `a ${end} no commit has performed yet was given a result to post`);
      assert.deepEqual(resultsFor({ holds: walked, shadow, commit: "c".repeat(40) }).post, [],
        `\`${outcome}\` was posted for a ${end} before the commit that performs it (BOT-81)`);
    }

    // `list` down: no entries, no shadow member. The hold ends anyway.
    const job = await commitJob(root, {
      entries: [], now, env: { ASTRA_SHADOW: "", ASTRA_ENTRIES: "", ASTRA_SUBMISSIONS: "" },
    });
    assert.equal(job.code, 0, job.logs.join("\n"));
    assert.deepEqual(end === "release" ? job.results.released_holds : job.results.cancelled_holds, [SDI]);
    assert.ok(!job.logs.some((l) => l.includes("hold_end_not_built")), `the ${end} was refused as not built`);
    const step = runApply(root);
    assert.equal(step.status, 0, step.stderr);
    const landed = headOf(origin);
    assert.equal(step.outputs.main_commit, landed);
    const at = (rel) => {
      try { return sh(["show", `${landed}:${rel}`], root); } catch { return null; }
    };
    assert.equal(at(holdEntryPath(SDI)), null, `the ${end} commit left the hold entry on main`);
    assert.equal(at(`state/holds/${SDI}.${record.act}.json`), null, `the ${end} commit left the ${record.act} record`);
    assert.match(sh(["log", "-1", "--format=%B", landed], root), new RegExp(`^Service-Decision: ${SDI}$`, "m"));
    const added = sh(["show", "--name-status", "--format=", landed], root);
    const unlisted = JSON.parse(at("plugins/widgets/plugin.json")).unlisted;
    if (end === "release") {
      assert.equal(unlisted, undefined, "the release commit did not relist the plugin");
      const logFile = added.split("\n").find((l) => /^A\s+bot\/moderation\/.*-widgets-relist\.json$/.test(l))?.split(/\s+/)[1];
      assert.ok(logFile, `the release commit wrote no relist log entry: ${added}`);
      const entry = JSON.parse(at(logFile));
      assert.deepEqual([entry.action, entry.reverses, entry.service_decision_id, entry.category], ["relist", SDI2, SDI, "error"]);
      assert.match(at(INDEX_FILE), /"widgets"/, "the index that landed beside the relist does not list the plugin");
    } else {
      assert.equal(unlisted, true, "a cancelled relist relisted the plugin");
      assert.ok(!/bot\/moderation\//.test(added), `the cancel commit wrote a log entry, which reads as an applied decision: ${added}`);
    }

    // The next live run reads that commit and posts exactly what it did.
    const next = await historyJob(root, { now: new Date("2026-09-20T00:20:00Z") });
    assert.equal(next.code, 0, next.logs.join("\n"));
    assert.deepEqual(next.bodies.map((b) => [b.service_decision_id, b.outcome, b.commit]), [[SDI, outcome, landed]],
      `the next live run did not post \`${outcome}\` naming the ${end} commit`);
  }
});

// The commit job, end to end through `main`, on the path the workflow runs.
// Until this test, no test passed a held decision to `composeCommit`, and the
// one sentence about the file (above, at the held-decision allowlist test) said
// `held()` wrote it. Nothing did: `paths.txt` named `state/holds/<id>.json`,
// the tree had no such file, and `git add --pathspec-from-file` — the next
// command the workflow runs — exits 128 on a path that does not exist. Measured
// before the repair on this same shape: `main` returned 0, and the add died.
async function commitJob(root, {
  entries, submissions = [], shadow = false, now = new Date("2026-09-20T12:30:00Z"), env = {},
  coverage = () => ({ status: "green", codes: [] }),
}) {
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
      // MOD-46's canary, green: a fixture has neither the history nor the
      // unlisted floor the real one is held to. The test that asks about it
      // hands in a red one.
      coverage,
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
    const root = estate({ bound: false });
    const removal = removalOf(SDI, { x: "leaked" });
    const delist = decision({ service_decision_id: SDI2, code: "M_DELIST", category: "broken", moderator: "amoderator" });
    const { code, logs, paths, results } = await commitJob(root, { entries: [removal, delist], shadow });
    assert.equal(code, 0, logs.join("\n"));
    assert.equal(results.held.length, 1, "MOD-9 holds an unbound listing's removal request, so this batch holds one or it proves nothing");
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
    assert.equal(holds[0].entry.held_for, "unbound_removal");
    assert.equal(holds[0].entry.held_at, "2026-09-20T12:30:00Z");
    assert.equal(holds[0].entry.release_after, undefined, "a hold entered since contract 6.6.0 waits on no clock");
    assert.ok(!fs.readFileSync(path.join(root, holdEntryPath(SDI)), "utf8").includes("leaked"),
      "a member the schema ignored on read reached the committed hold entry");

    // Listed again because the `held` result never landed: the entry stays
    // byte for byte, so `held_at` — the hold's place in the queue — does not
    // move, and it is not listed for a commit that would then carry no change.
    const before = fs.readFileSync(path.join(root, holdEntryPath(SDI)));
    const again = await commitJob(root, { entries: [removal], shadow, now: new Date("2026-09-20T12:40:00Z") });
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
      // held (MOD-9 holds an unbound listing's removal request): the hold entry
      removalOf(SDI),
    ],
    // a stop: BOT-30's terminal decision record
    submissions: [{
      submission_id: SUB, repo: "acme/widgets", tag: "widgets-v1.0.0", trigger: "panel",
      service_repository_id: "912345678", stop_status: "stopped", fingerprints: [], code: "R_FIRST_LISTING",
    }],
  };
  const dirty = (root) => sh(["status", "--porcelain", "--untracked-files=all"], root)
    .split("\n").filter(Boolean).filter((l) => !/^\?\? moderation\//.test(l));

  const liveRoot = estate({ bound: false });
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

  const shadowRoot = estate({ bound: false });
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
  const entryFor = (sdi) => removalEntry(sdi);
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
  const held = [{ service_decision_id: SDI, held_for: "bound" }];
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
  assert.match(script, /\bgit push origin HEAD:main\b/m, "the extracted step does not push; the anchor found something else");
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
 * The step runs `node tools/lib/tree-modes.mjs HEAD` from the checkout before
 * it pushes (ops couplings 216), so the fixture needs the module where a
 * checkout has it. Copied beside the tree and excluded from it, so that no
 * fixture commit carries it and every path list asserted here stays the one
 * the case wrote. `bot/tests/publish-apply.test.mjs` holds the rule's line to
 * refusing a bad commit; here it only has to pass a good one.
 */
function withTreeRule(root) {
  if (!fs.existsSync(path.join(root, "tools", "lib", "tree-modes.mjs"))) {
    fs.cpSync(path.join(REPO, "tools", "lib"), path.join(root, "tools", "lib"), { recursive: true });
    fs.appendFileSync(path.join(root, ".git", "info", "exclude"), "/tools/lib/\n");
  }
  // And the policy its bounds are read from, beside it (ops couplings 215).
  if (!fs.existsSync(path.join(root, "policy", "limits.json"))) {
    fs.cpSync(path.join(REPO, "policy", "limits.json"), path.join(root, "policy", "limits.json"));
    fs.appendFileSync(path.join(root, ".git", "info", "exclude"), "/policy/limits.json\n");
  }
}

/**
 * The step, under `bash -e` as a runner starts a `run:` block, in the checkout,
 * with a `$GITHUB_OUTPUT` of its own — which is what the job's `outputs:` block
 * reads, and so what `report` and `settled` are handed.
 */
function runApply(root, env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-step-"));
  tmpRoots.push(dir);
  withTreeRule(root);
  const file = path.join(dir, "apply.sh");
  const output = path.join(dir, "github-output");
  fs.writeFileSync(file, applyStep());
  fs.writeFileSync(output, "");
  // The step runs `git add`, `git commit` and `git push` itself, so its shell
  // gets a fixture's environment: under a hook's GIT_DIR it committed into the
  // repository that names (measured 2026-09-23, ops couplings 143), and
  // tools/selftest/git-env.mjs reads `git` spawns, not the git a shell runs.
  // `DRY_RUN` is the workflow's, and the live value is the default here so
  // that every case below pushes as the committed file does; a case that
  // passes `DRY_RUN: undefined` runs the step with it unset.
  // `ASTRA_BOT_DIR`: where the step finds this repository's bot when it is run
  // inside a fixture, for the retry's re-check (R6). Unset on a runner, where
  // the checkout is the bot.
  const stepEnv = { ...fixtureEnv(root), DRY_RUN: "false", ASTRA_BOT_DIR: REPO, ...env, GITHUB_OUTPUT: output };
  for (const [k, v] of Object.entries(stepEnv)) if (v === undefined) delete stepEnv[k];
  const step = spawnSync("bash", ["-e", file], { cwd: root, encoding: "utf8", env: stepEnv });
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
// R6 (2026-10-29): two writers race on `main`. Run 40274912876's push was
// rejected as a non-fast-forward and its decision waited a cycle. The step now
// fetches, rebases its one commit, re-checks it and pushes again; a conflict,
// or a rebased commit whose withdrawal list no longer carries the serial it
// lands at, pushes nothing.
function concurrentPush(origin, files, message, when) {
  const other = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-other-"));
  tmpRoots.push(other);
  sh(["clone", "-q", origin, other], os.tmpdir());
  sh(["config", "user.email", "fixture@example.invalid"], other);
  sh(["config", "user.name", "fixture"], other);
  writeAll(other, files);
  sh(["add", "-A"], other);
  sh(["commit", "-q", "-m", message], other, dated(when));
  sh(["push", "-q", "origin", "HEAD:main"], other);
  return headOf(origin);
}

/**
 * The redo's gates, in a fixture: the gate steps run `tools/…` and
 * `bot/moderation.mjs` out of the checkout, which a fixture does not have, so
 * each is a stub that records it ran and exits with `ASTRA_TEST_GATE_FAIL`'s
 * verdict for its name. Excluded from the tree like `withTreeRule`'s copies.
 * The real gates are held to refusing by their own suites; here the question
 * is only whether the redo runs every one, and stops on a red one.
 */
const GATE_STUBS = ["tools/build-index.mjs", "tools/build-revocations.mjs", "tools/validate.mjs", "tools/selftest.mjs", "bot/moderation.mjs"];
function withGateStubs(root) {
  const ran = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-gates-")), "ran.txt");
  tmpRoots.push(path.dirname(ran));
  for (const rel of GATE_STUBS) {
    fs.mkdirSync(path.join(root, path.dirname(rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), `import fs from "node:fs";
fs.appendFileSync(${JSON.stringify(ran)}, ${JSON.stringify(rel)} + " " + process.argv.slice(2).join(" ") + "\\n");
process.exit((process.env.ASTRA_TEST_GATE_FAIL ?? "") === ${JSON.stringify(rel)} ? 1 : 0);
`);
    fs.appendFileSync(path.join(root, ".git", "info", "exclude"), `/${rel}\n`);
  }
  return () => (fs.existsSync(ran) ? fs.readFileSync(ran, "utf8").split("\n").filter(Boolean) : []);
}

/** The compile step's inputs, as the `apply` step's `env:` hands them to a redo. */
const compileEnv = ({ entries = [], settled = "[]", shadow = false } = {}) => ({
  ASTRA_ENTRIES: JSON.stringify(entries),
  ASTRA_SUBMISSIONS: "[]",
  ASTRA_REFUSED: "[]",
  ASTRA_SHADOW: shadow ? "true" : "false",
  ASTRA_SETTLED: typeof settled === "string" ? settled : JSON.stringify(settled),
  ASTRA_DELIVERED_AT: "",
  GITHUB_RUN_ID: "35502265394",
});

test("R6: a push rejected because main moved is compiled again over the new main and pushed, never rebased; a conflict or a moved serial lands too", async () => {
  // Main moves on a file this commit does not touch: rebased and pushed.
  const root = withDocuments(estate());
  const origin = withRemote(root);
  withGateStubs(root);
  const job = await commitJob(root, { entries: [delistOf(SDI)] });
  assert.equal(job.code, 0, job.logs.join("\n"));
  const theirs = concurrentPush(origin, { "README.md": "an ingest landed first\n" }, "registry: publish (plugins ingest)", "2026-09-20T12:31:00Z");
  const step = runApply(root, compileEnv({ entries: [delistOf(SDI)] }));
  assert.equal(step.status, 0, `the redone retry did not push: ${step.stderr} ${step.stdout}`);
  assert.match(step.stdout + step.stderr, /the compile runs again against the new main/, "a rejected push was not compiled again");
  assert.doesNotMatch(step.stdout + step.stderr, /Rebasing|Successfully rebased/, "a rejected push was rebased (review of #480)");
  const landed = headOf(origin);
  assert.notEqual(landed, theirs, "the moderation commit never landed");
  assert.equal(step.outputs.main_commit, landed, "`main_commit` is not the rebased commit that landed");
  assert.equal(sh(["rev-parse", `${landed}^`], root).trim(), theirs, "the redone commit is not on top of the commit that beat it");
  assert.match(sh(["log", "-1", "--format=%B", landed], root), new RegExp(`^Service-Decision: ${SDI}$`, "m"));

  // Main moved on the same document: the rebase conflicts, the compile runs
  // again over the new main with every gate, and what it produces lands.
  const clash = withDocuments(estate());
  const clashOrigin = withRemote(clash);
  const clashGates = withGateStubs(clash);
  assert.equal((await commitJob(clash, { entries: [delistOf(SDI)] })).code, 0);
  const index = JSON.parse(fs.readFileSync(path.join(clash, INDEX_FILE), "utf8"));
  const moved = concurrentPush(clashOrigin, { [INDEX_FILE]: { ...index, $comment: "another writer" } }, "registry: publish", "2026-09-20T12:31:00Z");
  const redone = runApply(clash, compileEnv({ entries: [delistOf(SDI)] }));
  assert.equal(redone.status, 0, `a conflicting rebase was not compiled again: ${redone.stderr} ${redone.stdout}`);
  assert.match(redone.stdout + redone.stderr, /the compile runs again against the new main/);
  assert.equal(sh(["rev-parse", `${headOf(clashOrigin)}^`], clash).trim(), moved, "the redone commit is not on top of the commit that beat it");
  assert.equal(redone.outputs.main_commit, headOf(clashOrigin));
  assert.match(sh(["log", "-1", "--format=%B", headOf(clashOrigin)], clash), new RegExp(`^Service-Decision: ${SDI}$`, "m"));
  assert.deepEqual(clashGates().map((l) => l.split(" ")[0]), GATE_STUBS, "the redo did not run every gate, once, in order");

  // A redo whose gate is red pushes nothing and fails the step.
  const red = withDocuments(estate());
  const redOrigin = withRemote(red);
  withGateStubs(red);
  assert.equal((await commitJob(red, { entries: [delistOf(SDI)] })).code, 0);
  const redIndex = JSON.parse(fs.readFileSync(path.join(red, INDEX_FILE), "utf8"));
  const redMoved = concurrentPush(redOrigin, { [INDEX_FILE]: { ...redIndex, $comment: "another writer" } }, "registry: publish", "2026-09-20T12:31:00Z");
  const refused = runApply(red, { ...compileEnv({ entries: [delistOf(SDI)] }), ASTRA_TEST_GATE_FAIL: "tools/validate.mjs" });
  assert.notEqual(refused.status, 0, "a redo whose rules gate is red was pushed");
  assert.equal(headOf(redOrigin), redMoved, "something was pushed past a red gate");

  // Main moved under the withdrawal list's serial: rebased cleanly, the
  // re-check refuses the stale list, and the compile runs again at the serial
  // the landing commit gets.
  const serial = withDocuments(estate());
  const serialOrigin = withRemote(serial);
  withGateStubs(serial);
  const revoke = decision({ code: "M_REVOKE", category: "security_defect", severity: "high", action: "block_install", moderator: "amoderator", versions: ["1.0.0"] });
  assert.equal((await commitJob(serial, { entries: [revoke] })).code, 0);
  const advanced = concurrentPush(serialOrigin, { "tools/revocations/README.md": "a note beside the advisories\n" }, "docs", "2026-09-20T12:31:00Z");
  const restaled = runApply(serial, compileEnv({ entries: [revoke] }));
  assert.equal(restaled.status, 0, `a moved serial was not compiled again: ${restaled.stderr} ${restaled.stdout}`);
  assert.equal(sh(["rev-parse", `${headOf(serialOrigin)}^`], serial).trim(), advanced);
  const atHead = spawnSync(process.execPath, [path.join(REPO, "bot", "moderation-run.mjs"), "--job", "documents-at-head", "--registry-dir", serial],
    { cwd: serial, encoding: "utf8", env: fixtureEnv(serial) });
  assert.equal(atHead.status, 0, `the redone commit's list is not at the serial it landed at: ${atHead.stderr}`);
});

// Review of #480 (LOW, pre-existing): a clean rebase pushed a commit compiled
// against the old tree, and TRUST-26's bound was never counted again, so two
// runs that each admitted a takedown under a bound with one slot left landed
// both. Every rejected push is compiled again now, and the redo counts the
// window out of the new main. Watched red: with a clean rebase pushed as
// before, origin carries four withdrawals in the trailing 24 h.
test("two takedowns raced across a rejected push never make four withdrawals in 24 h", async () => {
  assert.equal(TAKEDOWN_BOUND, 3);
  const now = new Date();
  const iso = (ms) => `${new Date(now.getTime() - ms).toISOString().slice(0, 19)}Z`;
  const root = withDocuments(crowd({ at: iso(10 * 3600_000) }));
  withdrawnInGit(root, ["gadgets", "gizmos"], iso(3600_000));
  const origin = withRemote(root);
  const peer = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-peer-"));
  tmpRoots.push(peer);
  sh(["clone", "-q", origin, peer], os.tmpdir());
  for (const r of [root, peer]) withGateStubs(r);
  // A delist (the listing and the index) and a revoke (an advisory and the
  // withdrawal list) touch no file in common, so the second commit REBASES
  // CLEANLY onto the first: the case a clean rebase used to push.
  const a = [takedownOf("widgets", 0)];
  const b = [decision({ service_decision_id: SDIS[1], plugin_id: "doohickeys", code: "M_REVOKE", category: "security_defect",
    severity: "high", action: "block_install", moderator: "amoderator", versions: ["1.0.0"] })];
  const first = await measuredJob(root, a, { now });
  assert.deepEqual(first.results.compiled, [SDIS[0]], "the fixture: two withdrawn leave one slot, and A takes it");
  const second = await measuredJob(peer, b, { now, env: { GITHUB_RUN_ID: "35502265999" } });
  assert.deepEqual(second.results.compiled, [SDIS[1]], "the fixture: B, from the same tree, also sees one slot");
  assert.equal(runApply(root, compileEnv({ entries: a })).status, 0);
  const two = runApply(peer, { ...compileEnv({ entries: b }), GITHUB_RUN_ID: "35502265999" });
  assert.equal(two.status, 0, `${two.stderr} ${two.stdout}`);
  const listed = (id) => {
    try {
      return JSON.parse(sh(["show", `refs/heads/main:plugins/${id}/plugin.json`], origin)).unlisted !== true;
    } catch {
      return true;
    }
  };
  const advisories = sh(["ls-tree", "--name-only", "refs/heads/main", "tools/revocations/"], origin).split("\n").filter((f) => f.endsWith(".json"));
  const withdrawn = ["widgets", ...PEERS].filter((id) => !listed(id)).length + advisories.length;
  assert.ok(withdrawn <= TAKEDOWN_BOUND,
    `origin carries ${withdrawn} withdrawals in the trailing 24 h under a bound of ${TAKEDOWN_BOUND}: ${advisories.join(", ")}`);
  assert.equal(advisories.length, 0, "the second run's revoke went out over a full bound");
  const results = JSON.parse(two.outputs.results);
  assert.deepEqual(results.held.map((h) => [h.service_decision_id, h.held_for]), [[SDIS[1], "bound"]],
    "the second run's takedown was not held for the bound after the redo");
});

// Run 40833642707, 2026-10-29T07:15Z: two moderation runs were handed the
// same settled result. The first recorded it and landed; the second's commit
// recorded the same row, its rebase conflicted, the step failed "does not
// rebase cleanly onto the new main", and the run paged although nothing was
// wrong. The second run now compiles again over the new main, finds the row
// recorded, has nothing to commit, and is green.
test("two runs over the same settled result give one commit and a green second run", async () => {
  for (const identical of [false, true]) {
    const ID = hid(identical ? 31 : 30);
    const { root, sha, origin } = handCancelled([ID], { documents: true, remote: true });
    const base = headOf(origin);
    // The second run's checkout is the same commit: its run was queued on it.
    const peer = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-peer-"));
    tmpRoots.push(peer);
    sh(["clone", "-q", origin, peer], os.tmpdir());
    withGateStubs(root);
    withGateStubs(peer);
    const rowA = rowFor(ID, sha[ID]);
    // Identical rows make the second commit a patch main already has, which
    // the rebase drops: the work is no longer there. Different rows conflict.
    const rowB = identical ? rowA : rowFor(ID, sha[ID], {
      answered_at: "2026-09-21T09:10:00Z", run: "https://github.com/mihailinl/astra-registry/actions/runs/35502265999",
    });

    const first = await commitJob(root, { entries: [], env: { ASTRA_SETTLED: JSON.stringify([rowA]) } });
    assert.equal(first.code, 0, first.logs.join("\n"));
    assert.deepEqual(first.paths, [SETTLED_FILE_PATH]);
    const one = runApply(root, compileEnv({ settled: [rowA] }));
    assert.equal(one.status, 0, `${one.stderr} ${one.stdout}`);
    const landed = headOf(origin);
    assert.equal(sh(["rev-parse", `${landed}^`], root).trim(), base);

    // Another run, so another run id and another commit message: the two
    // commits differ though the change may not.
    const RUN_B = { GITHUB_RUN_ID: "35502265999" };
    const second = await commitJob(peer, { entries: [], env: { ASTRA_SETTLED: JSON.stringify([rowB]), ...RUN_B } });
    assert.equal(second.code, 0, second.logs.join("\n"));
    assert.deepEqual(second.paths, [SETTLED_FILE_PATH], "the second run did not record the row too, so it does not race");
    const two = runApply(peer, { ...compileEnv({ settled: [rowB] }), ...RUN_B });
    assert.equal(two.status, 0, `the second run over a settled result is red: ${two.stderr} ${two.stdout}`);
    assert.match(two.stdout + two.stderr, /the push was rejected \(try 1 of 3\); the compile runs again against the new main/);
    assert.match(two.stdout, /nothing left to commit/);
    assert.equal(headOf(origin), landed, "the second run pushed a commit over a result the first had already recorded");
    assert.equal(two.outputs.main_commit, "", "a run that pushed nothing names a commit");
    const results = JSON.parse(two.outputs.results);
    assert.deepEqual(results.settled.recorded, [], "the redo recorded the row a second time");
    const record = JSON.parse(sh(["show", `${landed}:${SETTLED_FILE_PATH}`], root));
    assert.deepEqual(record.settled.map((r) => r.service_decision_id), [ID], "the record on main holds the row once");
  }
});

// The redo is the compile step and the two gate steps again, inside `apply`.
// Two copies of one list drift; this holds them to one: every gate line the
// `documents` and `rules` steps run is in the redo, in order, and every input
// the compile step is handed is in the `apply` step's `env:` with the same
// expression — a redo missing `ASTRA_SETTLED` would record nothing, and one
// missing `ASTRA_ENTRIES` would compile an empty list and land nothing.
test("the redo inside `apply` runs every gate the gate steps run, over the compile step's own inputs", () => {
  const lines = read(".github/workflows/plugins-moderation.yml").split("\n");
  const stepBlock = (id) => {
    const at = lines.findIndex((l) => new RegExp(`^\\s+id: ${id}\\s*$`).test(l));
    assert.ok(at > 0, `no step \`${id}\``);
    const indent = lines[at].search(/\S/);
    let from = at;
    while (from > 0 && !/^\s+- /.test(lines[from])) from--;
    const block = [lines[from]];
    for (let j = from + 1; j < lines.length; j++) {
      if (lines[j].trim() !== "" && lines[j].search(/\S/) < indent) break;
      if (/^\s+- /.test(lines[j]) && lines[j].search(/\S/) === indent - 2) break;
      block.push(lines[j]);
    }
    return block;
  };
  const envOf = (block) => Object.fromEntries(block
    .map((l) => /^\s+(ASTRA_[A-Z_]+): (\$\{\{.*\}\})\s*$/.exec(l)).filter(Boolean).map((m) => [m[1], m[2]]));
  const gateLines = (block) => block.map((l) => l.trim()).filter((l) => /^node (tools|bot)\//.test(l));
  const want = [...gateLines(stepBlock("documents")), ...gateLines(stepBlock("rules"))];
  assert.ok(want.length >= 5, `the gate steps run ${want.length} lines; the reader lost them`);
  const apply = applyStep().split("\n");
  const from = apply.findIndex((l) => /^\s*redo\(\) \{/.test(l));
  assert.ok(from >= 0, "the `apply` step has no `redo` function");
  const to = apply.findIndex((l, i) => i > from && /^\s*\}\s*$/.test(l));
  const redo = apply.slice(from, to).map((l) => l.trim());
  assert.deepEqual(redo.filter((l) => /^node (tools|bot)\//.test(l)), want,
    "the redo's gates are not exactly the gate steps' lines, in order; a redone commit would skip a gate the first one passed");
  assert.ok(redo.some((l) => /bot\/moderation-run\.mjs" --job commit --registry-dir \. --out moderation$/.test(l)),
    "the redo does not run the commit job's compile");
  const compile = envOf(stepBlock("compile"));
  assert.ok(Object.keys(compile).length >= 5, "the compile step's inputs were not found");
  assert.deepEqual(envOf(stepBlock("apply")), compile,
    "the `apply` step is not handed exactly the compile step's inputs, so its redo compiles something else");
  assert.doesNotMatch(applyStep(), /git push[^\n]*(--force|\s-f\b|\+HEAD)/, "the push may be forced");
});

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
  const root = withDocuments(estate({ bound: false }));
  const origin = withRemote(root);
  const first = await commitJob(root, { entries: [removalOf(SDI)] });
  assert.equal(first.code, 0, first.logs.join("\n"));
  assert.ok(first.paths.includes(holdEntryPath(SDI)), "MOD-9 holds an unbound listing's removal request, so this run enters one or proves nothing");
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  assert.equal(sh(["log", "-1", "--format=%H", "--diff-filter=A", "--", holdEntryPath(SDI)], origin).trim(), landed,
    "the fixture's landed commit is not the one that entered the hold, so what follows names the wrong thing");

  const live = resultsFor({ ...stateArgs(first.results), commit: landed, shadow: false });
  assert.deepEqual(live.post.filter((r) => r.outcome === "held").map((r) => r.commit), [landed],
    `BOT-81: the \`held\` result must name the hold entry's commit, ${landed}; it named ` +
    `${JSON.stringify(live.post.filter((r) => r.outcome === "held").map((r) => r.commit))}`);

  const again = await commitJob(root, { entries: [removalOf(SDI)], now: new Date("2026-09-20T12:40:00Z") });
  assert.equal(again.code, 0, again.logs.join("\n"));
  assert.deepEqual(again.paths, [], "a re-listed hold whose entry is on the tree commits nothing");
  const relisted = resultsFor({ ...stateArgs(again.results), commit: null, shadow: false });
  assert.deepEqual(relisted.post.filter((r) => r.outcome === "held").map((r) => r.commit), [landed],
    "a decision listed again because its `held` never arrived must be reported against the commit that entered " +
    "its entry — this run made none, and BOT-82 would read any other commit as a second, different result");

  // And the guard under both: a live `held`, `applied` or `cancelled` that
  // names no commit is refused here, not posted and not composed.
  for (const [what, args] of [
    ["held", { held: [{ service_decision_id: SDI, held_for: "unbound_removal" }] }],
    ["applied", { compiled: [{ service_decision_id: SDI }] }],
    ["cancelled", { holds: { pending: [{ service_decision_id: SDI, outcome: "cancelled", commit: null }] } }],
  ]) {
    assert.throws(() => resultsFor({ ...args, commit: null, shadow: false }), /BOT-81/,
      `a live \`${what}\` with no commit was composed for posting`);
  }
});

// ── the commit that landed a hold entry ─────────────────────────────────────
//
// BOT-81's `held` names the commit that added `state/holds/<id>.json`
// (`entryCommit`). Until contract 6.6.0 a reversal's 24 hours also ran from it
// (ops entry 101), and these tests walked that clock; nothing is held for a
// period now, so what is left to prove is the commit itself.

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
/** Every hold the walk found due, whether this job builds its end (`releasable`, `cancellable`) or refuses it (`due`). */
const dueIds = (walked) => [
  ...walked.due.map((d) => `${d.service_decision_id} ${d.act}`),
  ...walked.releasable.map((d) => `${d.service_decision_id} release`),
  ...walked.cancellable.map((d) => `${d.service_decision_id} cancel`),
];
const waitingFor = (walked, id) => walked.waiting.find((w) => w.service_decision_id === id)?.reason ?? "";

test("a hold merged from a branch is named by the merge that brought it onto main", async () => {
  const root = estate({ at: "2026-09-10T00:00:00Z" });
  sh(["checkout", "-q", "-b", "hand-hold"], root);
  writeAll(root, { [holdEntryPath(SDI)]: removalEntry(SDI, "2026-09-17T09:00:00Z") });
  const branch = commitAt(root, "2026-09-17T09:00:00Z", "a hold written on a branch");
  sh(["checkout", "-q", "main"], root);
  writeAll(root, { "README.md": "main moves on\n" });
  commitAt(root, "2026-09-18T00:00:00Z", "main moves on");
  sh(["merge", "-q", "--no-ff", "-m", "Merge the hold", "hand-hold"], root, dated("2026-09-20T12:00:00Z"));
  const merge = sh(["rev-parse", "HEAD"], root).trim();
  writeAll(root, { [`state/holds/${SDI}.confirm.json`]: confirmOf(SDI, "2026-09-20T12:10:00Z") });
  commitAt(root, "2026-09-20T12:10:00Z", "operator: confirm");

  // BOT-81's `held` names main's commit, not the branch's and not the confirm's.
  assert.equal(entryCommit(root, holdEntryPath(SDI)), merge,
    `the hold's commit was read as ${entryCommit(root, holdEntryPath(SDI))}; ${branch} is the branch commit, which ` +
    `main never held on its own, and ${merge} is the merge that brought the entry onto main`);
});

test("a checkout that cannot see the commit names none, and the walk refuses it", async () => {
  const root = estate({ at: "2026-09-20T12:00:00Z" });
  writeAll(root, { [holdEntryPath(SDI)]: removalEntry(SDI, "2026-09-20T12:30:00Z") });
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

  // And the job itself never reaches it there: the walk refuses a shallow clone.
  assert.throws(() => walkHolds({ root: shallow, now: new Date("2026-09-21T13:00:00Z"), shadow: false }), /shallow clone/);
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
  const posts = [];
  const logs = [];
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url, init = {}) => {
    if (String(url).startsWith("https://token.invalid/")) return json(200, { value: fakeToken() });
    const body = JSON.parse(init.body);
    bodies.push(body);
    posts.push({ path: new URL(String(url)).pathname.replace(/^.*\/bot\//, "bot/"), bytes: init.body });
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
  return { code, bodies, posts, logs };
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
  const root = withDocuments(estate({ bound: false }));
  const origin = withRemote(root);
  const job = await commitJob(root, { entries: [delistOf(SDI2), removalOf(SDI)] });
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
  const shadowRoot = withDocuments(estate({ bound: false }));
  withRemote(shadowRoot);
  const shadow = await commitJob(shadowRoot, { entries: [delistOf(SDI2), removalOf(SDI)], shadow: true });
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

/**
 * The `run: |` block of the step with this `id:` in `plugins-moderation.yml`,
 * with its one `node bot/moderation-run.mjs …` line taken out and returned
 * apart. The job itself runs in-process here, against a stub service — a
 * bash subprocess cannot be handed one — and the step's remaining lines, the
 * ones that copy what the job wrote into $GITHUB_OUTPUT, run under `bash -e`
 * as the runner runs them, over exactly what the job left behind.
 */
function stepAround(id) {
  const lines = read(".github/workflows/plugins-moderation.yml").split("\n");
  const at = lines.flatMap((l, i) => (new RegExp(`^\\s+id: ${id}\\s*$`).test(l) ? [i] : []));
  assert.equal(at.length, 1, `plugins-moderation.yml has ${at.length} steps with \`id: ${id}\``);
  const indent = lines[at[0]].search(/\S/);
  let run = -1;
  for (let j = at[0] + 1; j < lines.length; j++) {
    if (lines[j].trim() === "") continue;
    if (lines[j].search(/\S/) < indent) break;
    if (lines[j].search(/\S/) === indent && /^\s+run: \|\s*$/.test(lines[j])) { run = j; break; }
  }
  assert.ok(run > 0, `the \`${id}\` step has no \`run: |\` block`);
  const body = [];
  for (let j = run + 1; j < lines.length; j++) {
    if (lines[j].trim() !== "" && lines[j].search(/\S/) <= indent) break;
    body.push(lines[j].slice(indent + 2));
  }
  const calls = body.filter((l) => /^\s*node bot\/moderation-run\.mjs /.test(l));
  assert.equal(calls.length, 1, `the \`${id}\` step runs ${calls.length} moderation-run lines; this reads exactly one`);
  return { call: calls[0].trim(), script: `${body.map((l) => (l === calls[0] ? ":" : l)).join("\n").trimEnd()}\n` };
}

/** A step's remaining lines, in `dir`, with a `$GITHUB_OUTPUT` of its own, read back as the runner reads it. */
function runAround(id, dir, env = {}) {
  const { script } = stepAround(id);
  const file = path.join(dir, `${id}.sh`);
  const output = path.join(dir, `${id}-output`);
  fs.writeFileSync(file, script);
  fs.writeFileSync(output, "");
  const step = spawnSync("bash", ["-e", file], { cwd: dir, encoding: "utf8", env: { PATH: process.env.PATH, ...env, GITHUB_OUTPUT: output } });
  return { ...step, outputs: readOutputs(output) };
}

// B-T5.1, 2026-10-14: the path the owner's delist of `e2e-test` never got
// down, because `list` and `report` were placeholders (run 38525175920). One
// M_DELIST from a stub service through every hand-off the workflow makes —
// the work step's five outputs, the history step's `settled`, the commit, the
// push to a real `origin`, the posted `applied`, and `settled`'s comparison —
// using the workflow's own step lines wherever a step has lines of its own.
test("M_DELIST end to end: listed, committed, pushed, reported, settled, through the workflow's own steps", async () => {
  const root = withDocuments(estate());
  const origin = withRemote(root);
  const before = headOf(origin);
  assert.match(sh(["show", `${before}:registry/v1/index.json`], root), /"widgets"/,
    "the fixture's index does not list the plugin, so its absence after the delist would prove nothing");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-e2e-"));
  tmpRoots.push(dir);
  const out = path.join(dir, "moderation");
  const json = (status, b) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
  const posted = [];
  const fetchImpl = async (url, init = {}) => {
    if (String(url).startsWith("https://token.invalid/")) return json(200, { value: fakeToken() });
    if ((init.method ?? "GET") === "GET") return json(200, answer({ shadow: false, service_decisions: [delistOf(SDI)] }));
    posted.push(JSON.parse(init.body));
    return json(ack("accepted").status, ack("accepted").body);
  };
  const tokenEnv = {
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.invalid/token?api-version=2.0",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "the-runner-secret",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_REPOSITORY: "mihailinl/astra-registry",
    GITHUB_RUN_ID: "35502265394",
  };
  const logs = [];
  const log = { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) };

  // `list`, work step: the job, then the step's own lines over its files.
  assert.equal(stepAround("work").call, "node bot/moderation-run.mjs --job list --out moderation");
  const saved = process.stdout.write;
  process.stdout.write = () => true;
  let listed;
  try {
    listed = await main(["--job", "list", "--registry-dir", root, "--out", out], { env: tokenEnv, log, fetchImpl });
  } finally {
    process.stdout.write = saved;
  }
  assert.equal(listed, 0, logs.join("\n"));
  const work = runAround("work", dir);
  assert.equal(work.status, 0, work.stderr + work.stdout);
  assert.equal(work.outputs.shadow, "false");
  assert.deepEqual(JSON.parse(work.outputs.listed), [SDI]);
  assert.deepEqual(JSON.parse(work.outputs.entries).map((e) => [e.service_decision_id, e.code]), [[SDI, "M_DELIST"]]);

  // `list`, history step, under the work step's shadow: nothing in history.
  assert.equal(stepAround("history").call, "node bot/moderation-run.mjs --job history --out moderation");
  const history = await main(["--job", "history", "--registry-dir", root, "--out", out], {
    env: { ...tokenEnv, ASTRA_SHADOW: work.outputs.shadow }, log, fetchImpl, now: new Date("2026-09-20T12:30:00Z"),
  });
  assert.equal(history, 0, logs.join("\n"));
  const settledStep = runAround("history", dir);
  assert.equal(settledStep.status, 0, settledStep.stderr + settledStep.stdout);
  assert.equal(settledStep.outputs.settled, "[]");
  assert.deepEqual(posted, [], "the history step posted for a tree with no hold in its history");

  // `alert`: a delist is no MOD-8 alarm, so the verdict is green.
  assert.deepEqual(alarmsFor(JSON.parse(work.outputs.entries)), []);

  // `commit`, over exactly `list`'s outputs, then the `apply` step's own lines.
  const job = await commitJob(root, {
    entries: [],
    env: {
      ASTRA_SHADOW: work.outputs.shadow,
      ASTRA_ENTRIES: work.outputs.entries,
      ASTRA_SUBMISSIONS: work.outputs.submissions,
      ASTRA_SETTLED: settledStep.outputs.settled,
    },
  });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.compiled, [SDI]);
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  assert.equal(step.outputs.main_commit, landed, "the delist did not reach `main`");
  const plugin = JSON.parse(sh(["show", `${landed}:plugins/widgets/plugin.json`], root));
  assert.equal(plugin.unlisted, true, "the commit that landed does not delist the plugin");
  const index = sh(["show", `${landed}:registry/v1/index.json`], root);
  assert.ok(!/"widgets"/.test(index), "the index that landed beside the delist still lists the plugin");
  assert.match(sh(["log", "-1", "--format=%B", landed], root), new RegExp(`^Service-Decision: ${SDI}$`, "m"));

  // `report`, over the commit job's outputs: one `applied`, naming the push.
  const report = await reportJob({ ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit });
  assert.equal(report.code, 0, report.logs.join("\n"));
  assert.deepEqual(report.bodies.map((b) => [b.service_decision_id, b.outcome, b.commit]), [[SDI, "applied", landed]]);

  // `settled`: the one listed decision has its result.
  const done = await settledJob({
    ASTRA_LISTED_IDS: work.outputs.listed,
    ASTRA_RESULTS: step.outputs.results,
    ASTRA_MAIN_COMMIT: step.outputs.main_commit,
    ASTRA_LIST_FAILED: "false",
  });
  assert.equal(done.code, 0, done.logs.join(" | "));
});

/** `list`'s work step over a stub answer: the job in-process, then the step's own lines. Its outputs, as the runner reads them. */
async function workOutputs(root, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-work-"));
  tmpRoots.push(dir);
  const job = await listJob(root, body);
  assert.equal(job.code, 0, job.logs.join("\n"));
  fs.mkdirSync(path.join(dir, "moderation"));
  for (const [name, text] of Object.entries(job.files)) fs.writeFileSync(path.join(dir, "moderation", `${name}.json`), text);
  const step = runAround("work", dir);
  assert.equal(step.status, 0, step.stderr + step.stdout);
  return step.outputs;
}

/** The commit job's environment, exactly as the workflow maps it from `list`'s outputs. */
const commitEnvFrom = (outputs) => ({
  ASTRA_SHADOW: outputs.shadow,
  ASTRA_ENTRIES: outputs.entries,
  ASTRA_SUBMISSIONS: outputs.submissions,
  ASTRA_REFUSED: outputs.refused,
  ASTRA_SETTLED: outputs.settled ?? "",
});

// B-T5.1. `list`'s `refused` output was declared and read by nothing, so a
// decision refused at the list — an `A_YANK` carrying a moderator is
// `kind_refused` there, by name — never got the FINAL `refused` result BOT-81
// gives it, stayed on BOT-80's list, and was refused again every run. Now
// `commit` hands it to `report` in `results`, beside the compile's own.
// Watched failing by dropping ASTRA_REFUSED from the commit job's read, and by
// putting the list's refusals in `refused` only in shadow.
test("a decision refused at the list is posted `refused` once, beside the compile's results, and `settled` counts it", async () => {
  const root = withDocuments(estate());
  const origin = withRemote(root);
  const refusedYank = decision({
    service_decision_id: SDI2, code: "A_YANK", versions: ["1.0.0"], reason: FIXED_YANK, moderator: "amoderator",
  });
  const outputs = await workOutputs(root, answer({ shadow: false, service_decisions: [delistOf(SDI), refusedYank] }));
  assert.deepEqual(JSON.parse(outputs.listed), [SDI, SDI2]);

  const job = await commitJob(root, { entries: [], env: commitEnvFrom(outputs) });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.refused, [{ service_decision_id: SDI2, refusal: "kind_refused" }]);
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);

  const report = await reportJob({ ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit });
  assert.equal(report.code, 0, report.logs.join("\n"));
  assert.deepEqual(
    report.bodies.map((b) => `${b.service_decision_id} ${b.outcome} ${b.commit ?? "-"} ${b.refusal_code ?? "-"}`).sort(),
    [`${SDI} applied ${landed} -`, `${SDI2} refused - kind_refused`].sort(),
  );
  const done = await settledJob({
    ASTRA_LISTED_IDS: outputs.listed, ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit,
  });
  assert.equal(done.code, 0, done.logs.join(" | "));

  // Shadow: the refusal is withheld like everything else the answer names,
  // posted by nobody, and counted as answered by `settled` (BOT-84's split).
  const shadowRoot = withDocuments(estate());
  withRemote(shadowRoot);
  const shadowOut = await workOutputs(shadowRoot, answer({ shadow: true, service_decisions: [delistOf(SDI), refusedYank] }));
  const shadowJob = await commitJob(shadowRoot, { entries: [], env: commitEnvFrom(shadowOut) });
  assert.equal(shadowJob.code, 0, shadowJob.logs.join("\n"));
  assert.deepEqual(shadowJob.results.refused, []);
  assert.deepEqual(shadowJob.results.shadow_withheld.refused, [{ service_decision_id: SDI2, refusal: "kind_refused" }]);
  const shadowStep = runApply(shadowRoot);
  assert.equal(shadowStep.status, 0, shadowStep.stderr);
  const shadowReport = await reportJob({ ASTRA_RESULTS: shadowStep.outputs.results, ASTRA_MAIN_COMMIT: shadowStep.outputs.main_commit });
  assert.deepEqual(shadowReport.bodies, [], "report posted a refusal under a shadow answer (BOT-92)");
  const shadowDone = await settledJob({
    ASTRA_LISTED_IDS: shadowOut.listed, ASTRA_RESULTS: shadowStep.outputs.results, ASTRA_MAIN_COMMIT: shadowStep.outputs.main_commit,
  });
  assert.equal(shadowDone.code, 0, shadowDone.logs.join(" | "));
});

test("the list's refusals are re-checked before they are handed on, and a malformed one fails the commit job", async () => {
  assert.deepEqual(listRefusals(""), { decisions: [], submissions: [], fatal: [] }, "a failed or empty list refuses nothing");
  const ok = listRefusals(JSON.stringify([{ service_decision_id: SDI2, code: "kind_refused" }, { submission_id: SUB, code: "kind_refused" }]));
  assert.deepEqual(ok.fatal, []);
  assert.equal(ok.decisions.length, 1);
  assert.equal(ok.submissions.length, 1);
  for (const [text, why] of [
    ["{}", "not an array"],
    [JSON.stringify([{ service_decision_id: SDI2, code: "not_a_refusal" }]), "a code outside §0.8"],
    [JSON.stringify([{ service_decision_id: SDI2, code: "kind_refused", why: "a member's value" }]), "a member beyond id and code"],
    [JSON.stringify([{ code: "kind_refused" }]), "no id"],
    [JSON.stringify([{ service_decision_id: SDI2, code: "kind_refused" }, { service_decision_id: SDI2, code: "kind_refused" }]), "twice"],
  ]) {
    assert.ok(listRefusals(text).fatal.length > 0, `a \`refused\` output with ${why} was accepted`);
  }
  assert.ok(
    listRefusals(JSON.stringify([{ service_decision_id: SDI, code: "kind_refused" }]), { entries: [delistOf(SDI)] }).fatal.length > 0,
    "a decision both compiled and refused was accepted; BOT-81 gives it one final result",
  );

  const root = estate();
  const logs = [];
  const code = await main(["--job", "commit", "--registry-dir", root, "--out", path.join(root, "moderation")], {
    env: {
      ASTRA_SHADOW: "false",
      ASTRA_ENTRIES: JSON.stringify([delistOf(SDI)]),
      ASTRA_SUBMISSIONS: "[]",
      ASTRA_REFUSED: JSON.stringify([{ service_decision_id: SDI, code: "kind_refused" }]),
    },
    log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
    fetchImpl: () => { throw new Error("the commit job reached the network"); },
    now: new Date("2026-09-20T12:30:00Z"),
  });
  assert.equal(code, 1, `the commit job accepted a decision both compiled and refused: ${logs.join(" | ")}`);
  assert.ok(!fs.existsSync(path.join(root, "moderation", "paths.txt")), "and it listed paths for the apply step anyway");
});

// B-T5.1 commits `DRY_RUN: "false"`. It was "true" through R3 and no step read
// it, so the `apply` step pushed whatever the committed value said. Now the
// step pushes only under exactly "false", and every other value — a typo, a
// case, an unset variable — commits on the runner and pushes nothing, which
// `report` then refuses to describe as landed. Watched failing by keying the
// guard on `== "true"` (the unset and "False" cases push) and by dropping it.
test("the apply step pushes only under DRY_RUN exactly \"false\", and a withheld push is red at `report`", async () => {
  for (const value of ["true", "", "False", "false ", "0", undefined]) {
    const root = withDocuments(estate());
    const origin = withRemote(root);
    const before = headOf(origin);
    const job = await commitJob(root, { entries: [delistOf(SDI)] });
    assert.equal(job.code, 0, job.logs.join("\n"));
    const step = runApply(root, { DRY_RUN: value });
    const label = `DRY_RUN ${JSON.stringify(value)}`;
    assert.equal(step.status, 0, `${label}: ${step.stderr}`);
    assert.equal(headOf(origin), before, `${label} pushed to main`);
    assert.equal(step.outputs.main_commit, "", `${label} named a commit nothing pushed`);
    assert.match(step.stdout, /would push [0-9a-f]{40}/, `${label}: the step did not say what it withheld`);
    assert.notEqual(sh(["rev-parse", "HEAD"], root).trim(), before, `${label}: the commit was not even made on the runner`);

    // `report` refuses an `applied` that names no commit, so the run is red
    // and `settled`, handed nothing by a failed `report`, pages for it.
    const report = await reportJob({ ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit })
      .catch((e) => ({ code: 2, bodies: [], logs: [e.message] }));
    assert.notEqual(report.code, 0, `${label}: report posted a takedown that did not land`);
    assert.deepEqual(report.bodies, [], `${label}: report posted`);
    assert.equal((await settledJob({ ASTRA_LISTED_IDS: JSON.stringify([SDI]), ASTRA_RESULTS: "" })).code, 1);
  }
  const root = withDocuments(estate());
  const origin = withRemote(root);
  const job = await commitJob(root, { entries: [delistOf(SDI)] });
  assert.equal(job.code, 0, job.logs.join("\n"));
  const live = runApply(root, { DRY_RUN: "false" });
  assert.equal(live.status, 0, live.stderr);
  assert.equal(live.outputs.main_commit, headOf(origin), "DRY_RUN \"false\" did not push");
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

/** `--job list`, as the `list` job's work step runs it, against a stub service that answers `body`. */
async function listJob(root, body) {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "moderation-run-list-"));
  tmpRoots.push(out);
  const calls = [];
  const logs = [];
  const json = (status, b) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url, init = {}) => {
    if (String(url).startsWith("https://token.invalid/")) return json(200, { value: fakeToken() });
    calls.push({ url: String(url), method: init.method ?? "GET" });
    return json(200, body);
  };
  const saved = process.stdout.write;
  let printed = "";
  process.stdout.write = (chunk) => { printed += String(chunk); return true; };
  let code;
  try {
    code = await main(["--job", "list", "--registry-dir", root, "--out", out], {
      env: {
        ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.invalid/token?api-version=2.0",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "the-runner-secret",
      },
      log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
      fetchImpl,
    });
  } finally {
    process.stdout.write = saved;
  }
  const files = {};
  for (const name of LIST_OUTPUTS) {
    const file = path.join(out, `${name}.json`);
    if (fs.existsSync(file)) files[name] = fs.readFileSync(file, "utf8");
  }
  return { code, calls, logs, printed, files };
}

// B-T5.1, 2026-10-14. Until this date `--job list` printed its summary and
// handed on nothing: the workflow step that would run it was a placeholder,
// and the five outputs `list` declares had no writer. Each now has a file the
// step copies into $GITHUB_OUTPUT by name. Watched failing by dropping a
// refused id from `listed` (a refusal nobody posts then leaves BOT-80's list
// unseen), by passing `why` through on a refusal, and by reading `shadow` as
// `!shadow`.
test("the list job hands on its five outputs, one line each, and `listed` names the refused decisions too", async () => {
  const root = estate();
  const delist = decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" });
  const refusedYank = decision({
    service_decision_id: SDI2, code: "A_YANK", versions: ["1.0.0"], reason: FIXED_YANK, moderator: "amoderator",
  });
  const stop = { submission_id: SUB, repo: "acme/widgets", tag: "widgets-v1.0.0", code: "R_FIRST_LISTING" };
  const job = await listJob(root, answer({ shadow: false, service_decisions: [delist, refusedYank], submissions: [stop] }));
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.calls.map((c) => [c.method, new URL(c.url).pathname.replace(/^.*\/bot\//, "bot/")]),
    [["GET", "bot/moderation-work"]], "one GET of the work list, and nothing else");
  assert.deepEqual(Object.keys(job.files).sort(), [...LIST_OUTPUTS].sort(), "a list output has no file to be copied from");
  for (const [name, text] of Object.entries(job.files)) {
    assert.match(text, /^[^\n\r]+\n$/, `${name}.json is not one line, so $GITHUB_OUTPUT's name=value would split it`);
  }
  const read = (name) => JSON.parse(job.files[name]);
  assert.equal(read("shadow"), false);
  assert.deepEqual(read("entries").map((e) => e.service_decision_id), [SDI]);
  assert.deepEqual(read("submissions").map((e) => e.submission_id), [SUB]);
  assert.deepEqual(read("refused"), [{ service_decision_id: SDI2, code: "kind_refused" }],
    "a refusal hands on its id and its §0.8 code and nothing else; the reason text can quote a member's value");
  assert.deepEqual(read("listed"), [SDI, SDI2],
    "`listed` is every decision the answer named, refused ones included: `settled` is the only job that would " +
    "notice a refusal that never reached the service");
  assert.ok(!/amoderator|withdrawn/.test(job.printed), "the summary printed a member's value (PRIV-2)");
  assert.match(job.printed, new RegExp(`refuse ${SDI2} kind_refused`));
});

// The 2026-10-17 review: a body that fails its schema is returned by the
// client as `shadow: true, unreadable: true`, while the body itself may say
// `shadow: false`. Read alone, the body made the run live.
test("a work answer the client withheld (its schema is not the one this bot reads) hands on shadow, whatever the body says", async () => {
  const root = estate();
  const delist = decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" });
  const body = answer({ shadow: false, service_decisions: [delist] });
  body.schema = "astra.plugins.bot-moderation-work/99";
  const job = await listJob(root, body);
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.equal(job.files.shadow, "true\n", "a withheld answer must never be handed on as live");
  assert.ok(job.logs.some((l) => /withheld by the client/.test(l)), job.logs.join("\n"));
  const live = await listJob(root, answer({ shadow: false, service_decisions: [delist] }));
  assert.equal(live.files.shadow, "false\n", "the positive control: a conforming live answer is still live");
});

test("a shadow answer hands on `true`, and a list with anything fatal in it hands on nothing", async () => {
  const root = estate();
  const delist = decision({ code: "M_DELIST", category: "broken", moderator: "amoderator" });
  const shadowed = await listJob(root, answer({ shadow: true, service_decisions: [delist] }));
  assert.equal(shadowed.code, 0, shadowed.logs.join("\n"));
  assert.equal(shadowed.files.shadow, "true\n", "a shadow answer is handed on as shadow (BOT-92)");
  assert.deepEqual(JSON.parse(shadowed.files.listed), [SDI], "and the work it names is still listed, for `settled`");

  // An answer missing `shadow`, or carrying one that is not a boolean, is not
  // the schema's body at all: the run fails, and nothing reads it as live.
  const unstated = answer({ service_decisions: [delist] });
  delete unstated.shadow;
  for (const body of [unstated, answer({ shadow: "false", service_decisions: [delist] })]) {
    const job = await listJob(root, body);
    assert.equal(job.code, 1, `shadow ${JSON.stringify(body.shadow)} was accepted`);
    assert.deepEqual(job.files, {}, `shadow ${JSON.stringify(body.shadow)} handed on outputs from a failed list`);
  }

  const fatal = await listJob(root, answer({ shadow: false, service_decisions: [{ code: "M_DELIST", plugin_id: "widgets" }] }));
  assert.equal(fatal.code, 1);
  assert.deepEqual(fatal.files, {},
    "a list that failed wrote outputs anyway; every later job must read a failed `list`, never an empty one");
});

test("the list outputs are bounded as the summary is, and a cut-short output is refused before it is handed on", () => {
  const big = { service_decision_id: SDI, code: "M_DELIST", plugin_id: "widgets", note: "x".repeat(MAX_OUTPUT_BYTES) };
  assert.throws(
    () => listOutputs({ shadow: false, entries: [big], submissions: [], refused: [] }),
    /bound is/,
  );
  const fine = listOutputs({ shadow: true, entries: [], submissions: [], refused: [] });
  assert.deepEqual(fine, { shadow: "true", entries: "[]", submissions: "[]", refused: "[]", listed: "[]" });
});

test("MOD-8's alarms are derivable from the list entry, before any compile", () => {
  const alarms = alarmsFor([
    { code: "M_REVOKE", action: "disable", plugin_id: "widgets" },
    { code: "M_RELIST", plugin_id: "widgets" },
    { code: "M_DELIST", plugin_id: "widgets" },
  ]);
  assert.ok(alarms.some((a) => a.code === "MOD_8_ADVISORY_DISABLE"));
  // Contract 6.6.0: a `disable` and a relist are held for nobody's
  // confirmation, so MOD-9 owes no alarm for either; the two codes that
  // announced one are gone, and the advisory's own MOD-8 alarm stays.
  assert.ok(!alarms.some((a) => a.code === "MOD_9_DISABLE_CONFIRMATION" || a.code === "MOD_9_REVERSAL_HOLD"),
    `an alarm still announces a hold MOD-9 no longer makes: ${alarms.map((a) => a.code).join(", ")}`);
  // One, not three: an `M_DELIST` enters no advisory and no hold, and neither
  // does a relist now, so MOD-8 owes no alarm for them. The count is here so
  // that widening `alarmsFor` is a deliberate edit — an alarm per decision
  // would page an operator ten times an hour and end as an alarm nobody reads.
  assert.equal(alarms.length, 1);
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
  const entryFor = (sdi) => removalEntry(sdi);
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
// ── MOD-9 since contract 6.6.0: one confirmation, and a bound that ends by itself
//
// The owner, 2026-10-29: he revoked a plugin with `disable`, confirmed it with
// the console's step-up, and the registry then held it for a second
// confirmation that only a dispatch of `operator.yml` on GitHub could give —
// and the site said nothing. So nothing is held for a person now. A reversal
// and a `disable` apply in the run that compiles them; TRUST-26's bound stays,
// and a takedown it holds releases BY ITSELF in the first run whose trailing
// 24 hours admit it, oldest held first, never more in one run than the bound
// admits. MOD-52's confirmation still releases one at once: break-glass.

const SPROCKETS = "sprockets";
/** `crowd()` plus a fifth listing, for two holds beside three withdrawals. */
function crowd5({ at = "2026-09-20T09:00:00Z" } = {}) {
  const root = crowd({ at });
  writeAll(root, {
    [`plugins/${SPROCKETS}/plugin.json`]: plugin(SPROCKETS),
    [`plugins/${SPROCKETS}/versions/1.0.0.json`]: version(SPROCKETS, "1.0.0"),
    [`plugins/${SPROCKETS}/identity.json`]: identity(SPROCKETS),
  });
  commitAt(root, at, "a fifth listing");
  return root;
}
/** A takedown held by the bound, as the commit job writes one, committed at `held_at`. */
function boundHold(root, id, sdi, held_at) {
  writeAll(root, { [holdEntryPath(sdi)]: holdEntry(takedownOf(id, SDIS.indexOf(sdi)), { held_for: "bound", held_at }) });
  return commitAt(root, held_at, `registry: moderation (1 hold(s)) for ${id}`);
}
const unlistedOn = (root, id) => JSON.parse(fs.readFileSync(path.join(root, "plugins", id, "plugin.json"), "utf8")).unlisted === true;

test("6.6.0: a `disable` applies in its first run — advisory and log entry, no state/holds file — and a relist and an unrevoke apply at once too", async () => {
  const root = withDocuments(crowd());
  const origin = withRemote(root);
  const disable = decision({
    service_decision_id: SDIS[0], code: "M_REVOKE", category: "malicious", severity: "high", action: "disable",
    moderator: "amoderator", versions: ["1.0.0"],
  });
  const job = await measuredJob(root, [disable]);
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual([job.results.compiled, job.results.held], [[SDIS[0]], []],
    "a `disable` was held. The moderator's step-up in the console is its one confirmation (MOD-9 since 6.6.0); a " +
    "second one on GitHub is what sat invisible on 2026-10-29");
  assert.ok(!job.paths.some((p) => p.startsWith("state/holds/")), `a disable entered a hold: ${job.paths.join(" ")}`);
  assert.ok(job.paths.some((p) => /^tools\/revocations\/ASTRA-.*\.json$/.test(p)), `no advisory: ${job.paths.join(" ")}`);
  assert.ok(job.paths.some((p) => /^bot\/moderation\/.*-widgets-revoke\.json$/.test(p)), `no log entry: ${job.paths.join(" ")}`);
  assert.equal(runApply(root).status, 0);
  const landed = headOf(origin);
  const advisory = JSON.parse(sh(["show", `${landed}:${job.paths.find((p) => p.startsWith("tools/revocations/ASTRA-"))}`], root));
  assert.equal(advisory.action, "disable");
  assert.match(sh(["log", "-1", "--format=%B", landed], root), new RegExp(`^Service-Decision: ${SDIS[0]}$`, "m"));

  // A relist: applied in the run, `unlisted` lifted, no hold.
  const delisted = withDocuments(estate({ extra: { "plugins/widgets/plugin.json": plugin("widgets", { unlisted: true }) } }));
  const relisted = await commitJob(delisted, { entries: [relistOf(SDI)] });
  assert.equal(relisted.code, 0, relisted.logs.join("\n"));
  assert.deepEqual([relisted.results.compiled, relisted.results.held], [[SDI], []], "a relist was held (MOD-9 since 6.6.0 holds none)");
  assert.ok(!unlistedOn(delisted, "widgets"), "the relist compiled and did not lift `unlisted`");
  // The unrevoke's own walk is "M_UNREVOKE applies in the run that compiles it" above.
});

test("6.6.0: a fourth takedown in 24 h is held `bound`; it stays while the window is full and releases by itself, with no confirm record, once it admits it", async () => {
  const root = withDocuments(crowd());
  const origin = withRemote(root);
  withdrawnInGit(root, ["gadgets", "gizmos", "doohickeys"], "2026-09-20T11:30:00Z");
  sh(["push", "-q", "origin", "HEAD:main"], root);
  const first = await measuredJob(root, [takedownOf("widgets", 0)], { now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(first.code, 0, first.logs.join("\n"));
  assert.deepEqual(first.results.held.map((h) => [h.service_decision_id, h.held_for]), [[SDIS[0], "bound"]],
    "the fourth takedown in 24 hours was not held: TRUST-26's bound is the guard 6.6.0 keeps");
  assert.equal(runApply(root, dated("2026-09-20T12:35:00Z")).status, 0);

  // A minute before the window frees: still held, and nothing is committed.
  const full = await measuredJob(root, [], { now: new Date("2026-09-21T11:29:00Z") });
  assert.equal(full.code, 0, full.logs.join("\n"));
  assert.deepEqual([full.paths, full.results.released_holds], [[], []], "a bound hold released while the window was still full");
  assert.match(waitingFor(full.results.holds, SDIS[0]), /releases by itself/);

  // The first run with room: released, no confirm record anywhere.
  assert.ok(!fs.existsSync(path.join(root, `state/holds/${SDIS[0]}.confirm.json`)));
  const room = await measuredJob(root, [], { now: new Date("2026-09-21T11:31:00Z") });
  assert.equal(room.code, 0, room.logs.join("\n"));
  assert.deepEqual(room.results.released_holds, [SDIS[0]],
    `the bound hold did not release by itself once the trailing 24 hours admitted it: ${room.logs.join(" | ")}`);
  const step = runApply(root, dated("2026-09-21T11:35:00Z"));
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  assert.ok(unlistedOn(root, "widgets"), "the released takedown did not delist");
  assert.ok(!fs.existsSync(path.join(root, holdEntryPath(SDIS[0]))), "the release left the hold entry");
  assert.match(sh(["log", "-1", "--format=%B", landed], root), new RegExp(`^Service-Decision: ${SDIS[0]}$`, "m"));
  // And the next live run reads that commit as `applied`.
  const next = await historyJob(root, { now: new Date("2026-09-21T11:50:00Z") });
  assert.deepEqual(next.bodies.map((b) => [b.service_decision_id, b.outcome, b.commit]), [[SDIS[0], "applied", landed]]);
});

test("6.6.0: two bound holds and room for one — only the oldest goes, and the other the next time there is room", async () => {
  const root = withDocuments(crowd5());
  withRemote(root);
  withdrawnInGit(root, ["gadgets"], "2026-09-20T09:30:00Z");
  withdrawnInGit(root, ["gizmos", "doohickeys"], "2026-09-20T11:30:00Z");
  // The OLDER hold has the LATER id, so an order by file name would pick wrong.
  boundHold(root, "widgets", SDIS[1], "2026-09-20T12:00:00Z");
  boundHold(root, SPROCKETS, SDIS[0], "2026-09-20T12:30:00Z");
  sh(["push", "-q", "origin", "HEAD:main"], root);

  // 2026-09-21T10:00: gadgets has left the window, so there is room for one.
  const one = await measuredJob(root, [], { now: new Date("2026-09-21T10:00:00Z") });
  assert.equal(one.code, 0, one.logs.join("\n"));
  assert.deepEqual(one.results.released_holds, [SDIS[1]],
    `with room for one, the run released ${JSON.stringify(one.results.released_holds)}; the oldest held (widgets, ` +
    `${SDIS[1]}) goes, and never more than the bound admits`);
  assert.ok(waitingFor(one.results.holds, SDIS[0]), "the newer hold is not reported as waiting");
  assert.equal(runApply(root, dated("2026-09-21T10:05:00Z")).status, 0);
  assert.deepEqual([unlistedOn(root, "widgets"), unlistedOn(root, SPROCKETS)], [true, false]);

  // 11:45: gizmos and doohickeys have left too; widgets' release is inside it. Room again.
  const two = await measuredJob(root, [], { now: new Date("2026-09-21T11:45:00Z") });
  assert.deepEqual(two.results.released_holds, [SDIS[0]], `the second hold did not go when there was room: ${two.logs.join(" | ")}`);
});

test("6.6.0: a takedown that arrives while a bound hold waits queues behind it", async () => {
  const root = withDocuments(crowd5());
  withRemote(root);
  withdrawnInGit(root, ["gadgets"], "2026-09-20T09:30:00Z");
  withdrawnInGit(root, ["gizmos", "doohickeys"], "2026-09-20T11:30:00Z");
  boundHold(root, "widgets", SDIS[1], "2026-09-20T12:00:00Z");
  sh(["push", "-q", "origin", "HEAD:main"], root);
  // Room for one, and a fresh takedown of sprockets in the same run.
  const run = await measuredJob(root, [takedownOf(SPROCKETS, 0)], { now: new Date("2026-09-21T10:00:00Z") });
  assert.equal(run.code, 0, run.logs.join("\n"));
  assert.deepEqual(run.results.released_holds, [SDIS[1]], "the waiting hold lost its room to a takedown that arrived after it");
  assert.deepEqual(run.results.held.map((h) => [h.service_decision_id, h.held_for]), [[SDIS[0], "bound"]],
    "the fresh takedown took room the bound did not have: two withdrawals with room for one");
  assert.deepEqual(run.results.compiled, []);
});

test("6.6.0: MOD-52's confirmation still releases a bound hold at once, over a full window (break-glass)", async () => {
  const root = withDocuments(crowd());
  withRemote(root);
  withdrawnInGit(root, ["gadgets", "gizmos", "doohickeys"], "2026-09-20T11:30:00Z");
  boundHold(root, "widgets", SDIS[0], "2026-09-20T12:00:00Z");
  writeAll(root, { [`state/holds/${SDIS[0]}.confirm.json`]: confirmOf(SDIS[0], "2026-09-20T12:10:00Z") });
  commitAt(root, "2026-09-20T12:10:00Z", "operator: confirm");
  sh(["push", "-q", "origin", "HEAD:main"], root);
  const job = await measuredJob(root, [], { now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.released_holds, [SDIS[0]],
    `an operator's confirmation did not release a bound hold at once with the window full: ${job.logs.join(" | ")}`);
  assert.ok(job.paths.includes(`state/holds/${SDIS[0]}.confirm.json`), "the release does not delete the confirm record");
});

test("6.6.0: a confirmed takedown spends the window before the bound holds do, so one run never takes away more than it admits", async () => {
  const root = withDocuments(crowd5());
  withRemote(root);
  withdrawnInGit(root, ["gadgets"], "2026-09-20T09:30:00Z");
  withdrawnInGit(root, ["gizmos", "doohickeys"], "2026-09-20T11:30:00Z");
  // The older hold waits on the window; the newer one an operator confirmed.
  boundHold(root, "widgets", SDIS[1], "2026-09-20T12:00:00Z");
  boundHold(root, SPROCKETS, SDIS[0], "2026-09-20T12:30:00Z");
  writeAll(root, { [`state/holds/${SDIS[0]}.confirm.json`]: confirmOf(SDIS[0], "2026-09-21T09:00:00Z") });
  commitAt(root, "2026-09-21T09:00:00Z", "operator: confirm");
  sh(["push", "-q", "origin", "HEAD:main"], root);
  // Room for one at 10:00. The confirmed one goes whatever the bound says, and
  // its withdrawal is in the window the next run counts — so it takes the room.
  const job = await measuredJob(root, [], { now: new Date("2026-09-21T10:00:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.released_holds, [SDIS[0]],
    `room for one, a confirmed hold and a waiting one: the run released ${JSON.stringify(job.results.released_holds)} — ` +
    "both would be four withdrawals in 24 hours under a bound of three");
});

test("6.6.0: a `disable_confirmation` left from before is released as a bound hold — by the window, never past it", async () => {
  const leftover = (root) => {
    const d = decision({
      service_decision_id: SDIS[0], code: "M_REVOKE", category: "malicious", severity: "high", action: "disable",
      moderator: "amoderator", versions: ["1.0.0"], decided_at: "2026-09-20T11:50:00Z",
    });
    writeAll(root, { [holdEntryPath(SDIS[0])]: holdFixture(d, { held_for: "disable_confirmation", held_at: "2026-09-20T12:00:00Z" }) });
    commitAt(root, "2026-09-20T12:00:00Z", "registry: moderation (1 hold(s))");
  };
  // With the window full it stays: the old rule recorded a disable over the
  // bound under this kind, so it may be a fourth withdrawal.
  const full = withDocuments(crowd());
  withdrawnInGit(full, ["gadgets", "gizmos", "doohickeys"], "2026-09-20T11:30:00Z");
  leftover(full);
  const held = await measuredJob(full, [], { now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(held.code, 0, held.logs.join("\n"));
  assert.deepEqual([held.paths, held.results.released_holds], [[], []], "a leftover disable was released past a full bound");
  // With room, it is released with no confirm record, and its advisory published.
  const room = withDocuments(crowd());
  leftover(room);
  const released = await measuredJob(room, [], { now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(released.code, 0, released.logs.join("\n"));
  assert.deepEqual(released.results.released_holds, [SDIS[0]],
    `a leftover disable_confirmation with room in the window stayed stuck: nothing will confirm it now: ${released.logs.join(" | ")}`);
  assert.ok(released.paths.some((p) => /^tools\/revocations\/ASTRA-.*\.json$/.test(p)), released.paths.join(" "));
});
// ── R1/R2 (2026-10-29): a decision is applied once, and a release passes the rules ──
//
// Run 40810498499 released game-companion's `disable` (8bd29d5), its rules
// step failed — self-test (b): the deleted hold entry was still in the index —
// the `apply` step pushed anyway, `report` was skipped, and the service listed
// the decision again. Run 40811066008 compiled it as a fresh `disable` and held
// it a second time (abec3f9). Under 6.6.0 that stale listing would have
// applied it twice: a second advisory on every installed copy.

/** Every path the index holds is on disk: what `tools/selftest.mjs`'s (b) compares, and what failed. */
function indexMatchesDisk(root) {
  const tracked = sh(["ls-files", "-z"], root).split("\0").filter(Boolean);
  return tracked.filter((p) => !fs.existsSync(path.join(root, p)));
}
const advisoriesOn = (root) => sh(["ls-files", "--", "tools/revocations/*.json"], root).split("\n").filter(Boolean);
const disableOf = (sdi, id = "widgets", versions = ["1.0.0"]) => decision({
  service_decision_id: sdi, plugin_id: id, code: "M_REVOKE", category: "malicious", severity: "high",
  action: "disable", moderator: "amoderator", versions,
});

test("R1/R2: hold → confirm → release → a stale list still naming the id: one revoke commit, no new hold, and every release passes the index check", async () => {
  const root = withDocuments(crowd());
  const origin = withRemote(root);
  withdrawnInGit(root, ["gadgets", "gizmos", "doohickeys"], "2026-09-20T11:30:00Z");
  sh(["push", "-q", "origin", "HEAD:main"], root);
  const d = disableOf(SDIS[0]);

  const held = await measuredJob(root, [d], { now: new Date("2026-09-20T12:30:00Z") });
  assert.deepEqual(held.results.held.map((h) => [h.service_decision_id, h.held_for]), [[SDIS[0], "bound"]]);
  assert.equal(runApply(root, dated("2026-09-20T12:35:00Z")).status, 0);

  const act = operatorAct({ root, act: "confirm", serviceDecisionId: SDIS[0], now: new Date("2026-09-20T12:40:00Z"), runId: "7" });
  sh(["add", "--", ...act.paths], root);
  sh(["commit", "-q", "-m", act.message], root, dated("2026-09-20T12:40:00Z"));
  sh(["push", "-q", "origin", "HEAD:main"], root);

  const released = await measuredJob(root, [], { now: new Date("2026-09-20T12:50:00Z") });
  assert.deepEqual(released.results.released_holds, [SDIS[0]], released.logs.join(" | "));
  assert.deepEqual(indexMatchesDisk(root), [],
    "the release deleted the hold entry and its confirm record from disk and left both in the index; the rules step's " +
    "self-test (b) then fails every release, which is what pushed 8bd29d5 past a red gate (R2)");
  const step = runApply(root, dated("2026-09-20T12:55:00Z"));
  assert.equal(step.status, 0, step.stderr);
  const releaseCommit = headOf(origin);
  assert.deepEqual(advisoriesOn(root).length, 1);

  // `report` never ran. The service lists the decision again, and again.
  for (const now of ["2026-09-20T13:00:00Z", "2026-09-20T13:10:00Z"]) {
    const stale = await measuredJob(root, [d], { now: new Date(now) });
    assert.equal(stale.code, 0, stale.logs.join("\n"));
    assert.deepEqual([stale.paths, stale.results.held, stale.results.compiled], [[], [], []],
      `a decision main already applied was compiled or held again (${JSON.stringify(stale.results.held)}): the 2026-10-29 re-hold, ` +
      "and under 6.6.0 a second advisory");
    assert.deepEqual(stale.results.already_applied, [{ service_decision_id: SDIS[0], commit: releaseCommit }]);
    const { post } = resultsFromState(stale.results, { commit: "" });
    assert.deepEqual(post.map((r) => [r.service_decision_id, r.outcome, r.commit]), [[SDIS[0], "applied", releaseCommit]],
      "the stale listing was not answered `applied` naming the commit that applied it");
  }
  const revokes = sh(["log", "--format=%H", "origin/main", "--", "tools/revocations"], root).split("\n").filter(Boolean);
  assert.equal(revokes.length, 1, `${revokes.length} commits touched tools/revocations; one decision, one revoke commit`);
  assert.ok(!fs.existsSync(path.join(root, holdEntryPath(SDIS[0]))), "a new hold entry was written for an applied decision");
});

// b41b72b, 2026-10-29T07:07Z: the stray-hold cleanup for 3f996cae removed
// one hold entry and ALSO rewrote registry/v1/revocations.json, `serial` 17 →
// 18 and not one other byte. The formula had moved at ca06321, the merge of a
// branch that forked before 8bd29d5's advisory (`--full-history` counts a
// merge whose tree differs from either parent), and the regeneration wrote
// the new number over an unchanged list. A commit that changes no advisory now
// leaves the list as it is.
test("a release or cleanup that changes no advisory does not rewrite the withdrawal list, even when the serial formula moved", async () => {
  const ID = "3f996cae-45c5-43a2-a24a-fd56ee1fcca0";
  const root = withDocuments(estate({ id: "game-companion", versions: ["0.1.0", "0.1.1"], at: "2026-10-29T02:00:00Z" }));
  const origin = withRemote(root);
  const forkPoint = headOf(origin);
  const d = decision({
    service_decision_id: ID, code: "M_REVOKE", category: "malicious", plugin_id: "game-companion", versions: ["0.1.1"],
    decided_at: "2026-10-29T02:54:07Z", reason: "Using all ai limits, sends request every minute.", severity: "moderate",
    action: "disable", moderator: "mod-1", declared_interest: false,
  });
  assert.deepEqual((await measuredJob(root, [d], { now: new Date("2026-10-29T03:10:00Z") })).results.compiled, [ID]);
  assert.equal(runApply(root, dated("2026-10-29T03:11:10Z")).status, 0);
  // ca06321: a branch from before the advisory, merged after it.
  sh(["checkout", "-q", "-b", "side", forkPoint], root);
  writeAll(root, { "bot/README.txt": "a bot change on a branch\n" });
  sh(["add", "-A"], root);
  sh(["commit", "-q", "-m", "bot: a change"], root, dated("2026-10-29T04:00:00Z"));
  sh(["checkout", "-q", "main"], root);
  sh(["merge", "-q", "--no-ff", "-m", "Merge pull request #478", "side"], root, dated("2026-10-29T05:00:00Z"));
  sh(["push", "-q", "origin", "HEAD:main"], root);
  const listBefore = sh(["show", `HEAD:${REVOCATIONS_FILE}`], root);
  const formula = serialsAt({ root, sha: headOf(origin) }).revocations;
  assert.equal(formula, JSON.parse(listBefore).signed.serial + 1,
    "the fixture's merge did not move the formula, so it does not reproduce ca06321");
  // abec3f9's stray hold, and its cleanup.
  writeAll(root, { [holdEntryPath(ID)]: holdFixture(d, { held_for: "disable_confirmation", held_at: "2026-10-29T05:15:35Z" }) });
  commitAt(root, "2026-10-29T05:17:00Z", "registry: moderation (1 hold(s))");
  sh(["push", "-q", "origin", "HEAD:main"], root);
  const job = await measuredJob(root, [], { now: new Date("2026-10-29T07:07:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.stray_holds, [ID]);
  assert.deepEqual(job.paths, [holdEntryPath(ID)],
    `a cleanup that changes no advisory rewrote ${job.paths.filter((p) => p !== holdEntryPath(ID)).join(", ")}`);
  const step = runApply(root, dated("2026-10-29T07:07:18Z"));
  assert.equal(step.status, 0, step.stderr);
  assert.equal(sh(["show", `${headOf(origin)}:${REVOCATIONS_FILE}`], root), listBefore, "the landed withdrawal list is not the one main had");
  const check = spawnSync(process.execPath, [path.join(REPO, "bot", "moderation-run.mjs"), "--job", "documents-at-head", "--registry-dir", root],
    { cwd: root, encoding: "utf8", env: fixtureEnv(root) });
  assert.equal(check.status, 0, `the re-check refuses a list this commit did not write: ${check.stderr}`);

  // The control: a commit that DOES change an advisory rewrites the list, at
  // the serial the signer gives the commit that lands it.
  const lift = decision({
    service_decision_id: "0192f3a4-5b6c-7d8e-9f01-2345678930aa", code: "M_UNREVOKE", category: "error", plugin_id: "game-companion",
    versions: ["0.1.1"], moderator: "mod-1", reverses: ID, decided_at: "2026-10-29T08:00:00Z",
  });
  const lifted = await measuredJob(root, [lift], { now: new Date("2026-10-29T08:10:00Z") });
  assert.equal(lifted.code, 0, lifted.logs.join("\n"));
  assert.deepEqual(lifted.results.compiled, [lift.service_decision_id], JSON.stringify(lifted.results.refused));
  {
    assert.ok(lifted.paths.includes(REVOCATIONS_FILE), `an advisory change left the list alone: ${lifted.paths.join(", ")}`);
    assert.equal(runApply(root, dated("2026-10-29T08:11:00Z")).status, 0);
    assert.equal(JSON.parse(sh(["show", `${headOf(origin)}:${REVOCATIONS_FILE}`], root)).signed.serial,
      serialsAt({ root, sha: headOf(origin) }).revocations);
  }
});

// Contract 6.7.0 (MOD-57; owner OD-34, 2026-10-29). game-companion (revoke
// 3f996cae…, ASTRA-2026-0002) drained its users' AI quotas, which is harm and
// not malice, and was published `malicious` because §7.2 had no category for
// it and no way to correct one. The correction goes through the console as
// an `M_CORRECT_CATEGORY`, never as a hand edit of the published entry.
test("6.7.0: game-companion's revoke is corrected to `harmful_behaviour` by an appended entry, and nothing else moves", async () => {
  const ID = "3f996cae-45c5-43a2-a24a-fd56ee1fcca0";
  const FIX = "0192f3a4-5b6c-7d8e-9f01-2345678930cd";
  const root = withDocuments(estate({ id: "game-companion", versions: ["0.1.0", "0.1.1"], at: "2026-10-29T02:00:00Z" }));
  const origin = withRemote(root);
  const revoke = decision({
    service_decision_id: ID, code: "M_REVOKE", category: "malicious", plugin_id: "game-companion", versions: ["0.1.1"],
    decided_at: "2026-10-29T02:54:07Z", reason: "Using all ai limits, sends request every minute.", severity: "moderate",
    action: "disable", moderator: "mod-1", declared_interest: false,
  });
  assert.deepEqual((await measuredJob(root, [revoke], { now: new Date("2026-10-29T03:10:00Z") })).results.compiled, [ID]);
  assert.equal(runApply(root, dated("2026-10-29T03:11:10Z")).status, 0);
  const revokeFile = sh(["ls-files", "--", "bot/moderation/*game-companion-revoke*.json"], root).trim();
  assert.ok(revokeFile, "the fixture's revoke left no log entry");
  const before = {
    entry: sh(["show", `HEAD:${revokeFile}`], root),
    list: sh(["show", `HEAD:${REVOCATIONS_FILE}`], root),
    index: sh(["show", `HEAD:${INDEX_FILE}`], root),
  };

  const correct = (over = {}) => decision({
    service_decision_id: FIX, code: "M_CORRECT_CATEGORY", category: "harmful_behaviour", corrects: ID,
    plugin_id: "game-companion", decided_at: "2026-10-30T09:00:00Z", moderator: "mod-1", declared_interest: false,
    reason: "It drained its users' AI quotas, which harms them and is not malice.", ...over,
  });
  // The refusals first, each on its own tree state and each final.
  const refusal = async (over) => {
    const job = await measuredJob(root, [correct(over)], { now: new Date("2026-10-30T09:10:00Z") });
    fs.rmSync(path.join(root, "moderation"), { recursive: true, force: true });
    sh(["checkout", "-q", "--", "."], root);
    return job.results.refused.map((r) => r.refusal);
  };
  assert.deepEqual(await refusal({ corrects: "0192f3a4-5b6c-7d8e-9f01-2345678930ce" }), ["target_changed"], "a correction of nothing applied");
  assert.deepEqual(await refusal({ category: "malicious" }), ["target_changed"], "a correction to the category it already has");
  assert.deepEqual(await refusal({ category: "broken" }), ["kind_refused"], "a category §7.2 does not allow with a revoke");
  assert.deepEqual(await refusal({ plugin_id: "widgets" }), ["target_changed"], "a correction naming another plugin's entry");
  // Review of #480: never to `author_request` (the log would say the author
  // asked) nor to an account-level category.
  for (const category of ["author_request", "account_compromise", "account_sanction"]) {
    assert.deepEqual(await refusal({ category }), ["kind_refused"], `a correction to ${category} was not refused`);
  }

  const job = await measuredJob(root, [correct()], { now: new Date("2026-10-30T09:10:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.compiled, [FIX], JSON.stringify(job.results.refused));
  assert.equal(job.paths.length, 1, `a correction wrote more than its own log entry: ${job.paths.join(", ")}`);
  assert.match(job.paths[0], /^bot\/moderation\/2026-10-30-game-companion-correct\.json$/);
  assert.equal(runApply(root, dated("2026-10-30T09:11:00Z")).status, 0);
  const landed = headOf(origin);
  assert.match(sh(["log", "-1", "--format=%B", landed], root), new RegExp(`^Service-Decision: ${FIX}$`, "m"));
  assert.equal(sh(["show", `${landed}:${revokeFile}`], root), before.entry, "the published revoke entry was rewritten; history is append-only");
  assert.equal(sh(["show", `${landed}:${REVOCATIONS_FILE}`], root), before.list, "the withdrawal list moved for a category");
  assert.equal(sh(["show", `${landed}:${INDEX_FILE}`], root), before.index, "the catalogue moved for a category");
  const fixEntry = JSON.parse(sh(["show", `${landed}:${job.paths[0]}`], root));
  assert.deepEqual([fixEntry.action, fixEntry.corrects, fixEntry.category, fixEntry.previous_category], ["correct", ID, "harmful_behaviour", "malicious"]);

  // The public text: the built log shows the revoke under its new category,
  // with the history, and the words §7.2 publishes for it.
  const log = buildModerationLog({ root });
  const shown = log.entries.find((e) => e.service_decision_id === ID);
  assert.equal(shown.category, "harmful_behaviour", "the log still publishes the revoke as malicious");
  assert.deepEqual(shown.category_history.map((h) => h.category), ["malicious", "harmful_behaviour"]);
  assert.equal(categoryWords(shown.category), "Harms users' accounts, data or resources");
  assert.equal(log.entries.filter((e) => e.action === "correct").length, 1);
  // And the advisory page the site builds says it in §7.2's words.
  const { advisoryPage } = await import("../../site/templates/advisory.mjs");
  const page = advisoryPage({ id: "ASTRA-2026-0001", severity: "moderate", action: "disable", reason: revoke.reason, entries: [] },
    { plugins: new Map(), category: shown.category, categoryWords: categoryWords(shown.category) });
  assert.match(page, /category <strong>Harms users&#39;? accounts, data or resources<\/strong>|category <strong>Harms users(&#x27;|') accounts, data or resources<\/strong>/);
  // A second run over the same listed decision applies nothing twice.
  const again = await measuredJob(root, [correct()], { now: new Date("2026-10-30T09:20:00Z") });
  assert.deepEqual([again.paths, again.results.compiled], [[], []]);
  assert.deepEqual(again.results.already_applied.map((a) => a.service_decision_id), [FIX]);
});

// Review of #480 (LOW): a moderator's delist moved to `author_request` would
// publish that the author asked. Watched red: without the refusal, the
// delist's correction to `author_request` compiles.
test("6.7.0: a moderator's delist is never corrected to `author_request`; a correction to another category it allows compiles", async () => {
  const root = withDocuments(estate());
  withRemote(root);
  const DELIST = "0192f3a4-5b6c-7d8e-9f01-2345678930d1";
  assert.equal((await commitJob(root, { entries: [delistOf(DELIST)] })).code, 0);
  assert.equal(runApply(root).status, 0);
  const fix = (category) => decision({
    service_decision_id: "0192f3a4-5b6c-7d8e-9f01-2345678930d2", code: "M_CORRECT_CATEGORY", category, corrects: DELIST,
    moderator: "amoderator", declared_interest: false, decided_at: "2026-09-21T12:00:00Z",
  });
  const asked = await commitJob(root, { entries: [fix("author_request")], now: new Date("2026-09-21T12:10:00Z") });
  assert.deepEqual(asked.results.refused.map((r) => r.refusal), ["kind_refused"], "a delist was corrected to author_request");
  fs.rmSync(path.join(root, "moderation"), { recursive: true, force: true });
  sh(["checkout", "-q", "--", "."], root);
  const fine = await commitJob(root, { entries: [fix("malicious")], now: new Date("2026-09-21T12:10:00Z") });
  assert.deepEqual(fine.results.compiled, ["0192f3a4-5b6c-7d8e-9f01-2345678930d2"], JSON.stringify(fine.results.refused));
});

// Re-review of #480: nor AWAY from `author_request` or an account-level
// category, which would erase that the author asked or that an account was
// compromised. Watched red: without the refusal, both corrections compile.
test("6.7.0: an entry carrying `author_request` or an account category is never corrected away from it", async () => {
  for (const category of ["author_request", "account_compromise"]) {
    const root = withDocuments(estate());
    withRemote(root);
    const DELIST = "0192f3a4-5b6c-7d8e-9f01-2345678930d3";
    const original = decision({ service_decision_id: DELIST, code: "M_DELIST", category, moderator: "amoderator" });
    const applied = await commitJob(root, { entries: [original] });
    assert.deepEqual(applied.results.compiled, [DELIST], `the fixture: a delist with ${category} applies — ${JSON.stringify(applied.results.refused)}`);
    assert.equal(runApply(root).status, 0);
    const away = await commitJob(root, {
      entries: [decision({
        service_decision_id: "0192f3a4-5b6c-7d8e-9f01-2345678930d4", code: "M_CORRECT_CATEGORY", category: "broken", corrects: DELIST,
        moderator: "amoderator", declared_interest: false, decided_at: "2026-09-21T12:00:00Z",
      })],
      now: new Date("2026-09-21T12:10:00Z"),
    });
    assert.deepEqual(away.results.refused.map((r) => r.refusal), ["kind_refused"], `a delist carrying ${category} was corrected away from it`);
  }
});

test("R1: abec3f9's tree — an applied `disable` and a stray hold for the same id: zero new advisories, the hold removed, `applied`", async () => {
  // 3f996cae…, game-companion 0.1.1, as abec3f9 committed it.
  const ID = "3f996cae-45c5-43a2-a24a-fd56ee1fcca0";
  const root = withDocuments(estate({ id: "game-companion", versions: ["0.1.0", "0.1.1"], at: "2026-10-29T02:00:00Z" }));
  const origin = withRemote(root);
  const d = decision({
    service_decision_id: ID, code: "M_REVOKE", category: "malicious", plugin_id: "game-companion", versions: ["0.1.1"],
    decided_at: "2026-10-29T02:54:07Z", reason: "Using all ai limits, sends request every minute.", severity: "moderate",
    action: "disable", moderator: "mod-1", declared_interest: false,
  });
  const applied = await measuredJob(root, [d], { now: new Date("2026-10-29T03:10:00Z") });
  assert.deepEqual(applied.results.compiled, [ID], applied.logs.join(" | "));
  assert.equal(runApply(root, dated("2026-10-29T03:11:10Z")).status, 0);
  const appliedAt = headOf(origin);
  const before = advisoriesOn(root);
  assert.equal(before.length, 1);
  // abec3f9: the stale listing compiled again and held, under the old rule.
  writeAll(root, { [holdEntryPath(ID)]: holdFixture(d, { held_for: "disable_confirmation", held_at: "2026-10-29T03:15:35Z" }) });
  commitAt(root, "2026-10-29T03:17:00Z", "registry: moderation (1 hold(s))");
  sh(["push", "-q", "origin", "HEAD:main"], root);

  for (const entries of [[d], []]) {
    const job = await measuredJob(root, entries, { now: new Date("2026-10-29T04:00:00Z") });
    assert.equal(job.code, 0, job.logs.join("\n"));
    assert.deepEqual([job.results.compiled, job.results.held, job.results.released_holds], [[], [], []],
      `the stray hold was applied or held again (listed: ${entries.length > 0})`);
    assert.deepEqual(job.results.stray_holds, [ID], "the stray hold entry was not removed by the bot");
    assert.deepEqual(job.paths, [holdEntryPath(ID)], `the stray's removal wrote more than the deletion: ${job.paths.join(" ")}`);
    const { post } = resultsFromState(job.results, { commit: "" });
    assert.deepEqual(post.map((r) => [r.service_decision_id, r.outcome, r.commit]), [[ID, "applied", appliedAt]],
      "the stray was not settled `applied` naming the commit that applied the decision");
    if (entries.length) fs.rmSync(path.join(root, "moderation"), { recursive: true, force: true });
    else {
      const step = runApply(root, dated("2026-10-29T04:05:00Z"));
      assert.equal(step.status, 0, step.stderr);
    }
    sh(["checkout", "-q", "--", "."], root);
    sh(["reset", "-q"], root);
    sh(["checkout", "-q", "--", "."], root);
  }
  assert.deepEqual(advisoriesOn(root), before, "a new advisory was minted for a decision already applied");
  assert.ok(!fs.existsSync(path.join(root, holdEntryPath(ID))), "the stray hold entry is still on main");
  // And the next run reads the removal as `applied` against the original commit, never `cancelled`.
  const next = await historyJob(root, { now: new Date("2026-10-29T04:20:00Z") });
  assert.deepEqual(next.bodies.map((b) => [b.service_decision_id, b.outcome, b.commit]), [[ID, "applied", appliedAt]]);
});

test("R1: two different decision ids on one plugin both apply — the key is the id, never the plugin", async () => {
  const root = withDocuments(crowd());
  withRemote(root);
  const revoke = decision({
    service_decision_id: SDIS[0], code: "M_REVOKE", category: "security_defect", severity: "high",
    action: "block_install", moderator: "amoderator", versions: ["1.0.0"],
  });
  const first = await measuredJob(root, [revoke]);
  assert.deepEqual(first.results.compiled, [SDIS[0]]);
  assert.equal(runApply(root).status, 0);
  const deprecate = decision({
    service_decision_id: SDIS[1], code: "M_DEPRECATE", category: "broken", severity: "low", moderator: "amoderator",
    versions: ["1.1.0"],
  });
  const second = await measuredJob(root, [revoke, deprecate], { now: new Date("2026-09-20T13:00:00Z") });
  assert.equal(second.code, 0, second.logs.join("\n"));
  assert.deepEqual(second.results.compiled, [SDIS[1]],
    "a second decision on a plugin with an applied one was skipped as if applied: the key is the plugin, not the id");
  assert.deepEqual(second.results.already_applied.map((a) => a.service_decision_id), [SDIS[0]]);
});

test("R1: the push runs only after green gates, and `report` runs whenever a push happened", () => {
  const yaml = read(".github/workflows/plugins-moderation.yml");
  const ifOf = (id) => {
    const lines = yaml.split("\n");
    const at = lines.findIndex((l) => new RegExp(`^\\s+id: ${id}\\s*$`).test(l));
    assert.ok(at > 0, `no step with id ${id}`);
    for (let j = at - 2; j <= at + 3; j++) if (/^\s+if:/.test(lines[j] ?? "")) return lines[j];
    return "";
  };
  const apply = ifOf("apply");
  for (const gate of ["documents", "rules"]) {
    assert.match(apply, new RegExp(`steps\\.${gate}\\.conclusion == 'success'`),
      `the apply step pushes without its \`${gate}\` gate being green: a failed gate under \`!cancelled()\` still pushed 8bd29d5`);
  }
  const report = /^ {2}report:\n(?:.*\n)*? {4}if: (.*)$/m.exec(yaml)?.[1] ?? "";
  assert.match(report, /needs\.commit\.outputs\.main_commit != ''/,
    "report does not run after a push the commit job then failed on; the service then lists an applied decision again");
});
// R3 (2026-10-29): the coverage canary went red on the bot's own commits —
// 89c3a66, 7f1e682, 8bd29d5, abec3f9 — because the moderation body listed hold
// paths named by a UUID and the operator's subject named it too. PRIV-2
// exempts a UUID only in the `Service-Decision:` trailer. This runs the
// canary's own message rule over every commit a moderation run and the
// operator compose on a fixture: a hold entered, confirmed, released, a hold
// cancelled, a stray removed, a revert.
test("R3: every commit message the bot and the operator compose passes priv-scan's own message rule", async () => {
  const root = withDocuments(estate({ bound: false }));
  withRemote(root);
  const run = async (entries, now) => {
    const job = await commitJob(root, { entries, now: new Date(now) });
    assert.equal(job.code, 0, job.logs.join("\n"));
    if (job.paths.length) {
      const step = runApply(root, dated(now));
      assert.equal(step.status, 0, `${now}: ${step.stderr} ${step.stdout}`);
    }
  };
  const operator = (act, sdi, now) => {
    const done = operatorAct({ root, act, serviceDecisionId: sdi, now: new Date(now), runId: "7" });
    sh(["add", "--", ...done.paths], root);
    sh(["commit", "-q", "-m", done.message], root, dated(now));
    sh(["push", "-q", "origin", "HEAD:main"], root);
  };
  await run([removalOf(SDI)], "2026-09-20T12:00:00Z");                 // a hold entered
  operator("confirm", SDI, "2026-09-20T12:10:00Z");                    // the operator's confirm
  await run([], "2026-09-20T12:20:00Z");                               // the release
  operator("revert", SDI, "2026-09-20T12:30:00Z");                     // a revert of what it applied
  await run([removalOf(SDI2)], "2026-09-21T12:40:00Z");                // a second hold, a day later …
  operator("cancel", SDI2, "2026-09-21T12:50:00Z");                    // … cancelled by the operator
  await run([], "2026-09-21T13:00:00Z");                               // the cancel commit
  // A stray: an entry for a decision the log already carries.
  writeAll(root, { [holdEntryPath(SDI)]: removalEntry(SDI) });
  commitAt(root, "2026-09-21T13:10:00Z", "fixture: a stray hold entry");
  sh(["push", "-q", "origin", "HEAD:main"], root);
  await run([], "2026-09-21T13:20:00Z");                               // the stray's removal

  const shas = sh(["log", "--format=%H %s", "HEAD"], root).split("\n").filter(Boolean)
    .filter((l) => !/ (fixture|hand )/.test(l)).map((l) => l.split(" ")[0]);
  assert.ok(shas.length >= 8, `the fixture composed ${shas.length} commit(s); the walk above makes at least 8`);
  const findings = [];
  for (const sha of shas) {
    const message = sh(["log", "-1", "--format=%B", sha], root);
    for (const f of shapeFindings(withoutUuidTrailers(withoutAuthorship(message)), { roles: new Set() })) {
      findings.push(`${sha.slice(0, 8)} ${message.split("\n")[0]}: ${f.code}`);
    }
  }
  assert.deepEqual(findings, [],
    "a composed commit message carries a value PRIV-2's canary reports; a UUID belongs only in the `Service-Decision:` trailer");
});




// ── M-T3.5: the operator's five acts (MOD-52, TRUST-33, BOT-70; TRUST-32's `ok`) ─
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

// TRUST-32 since contract 5.8.0: the act `ok` writes `state/ok/<fp>.json`,
// copying `approval_decided_at` from the alert record, and only for the
// owner's pinned numeric id. Watched red (each by hand): the pin widened to
// any id — the stranger's and KNICE's dispatches write a record; the delivery
// check removed — the undelivered alert is answered; `approval_decided_at`
// taken from anywhere but the alert — the record's value disagrees.
const OWNER_ID = "193032699";
function alertOnTree(root, fp, over = {}) {
  // 6.7.0: every alert written binds the whole digest (whose first 16 hex are
  // the label) and the held record it cleared.
  const rec = { schema: "astra.registry.alert/1", fingerprint: fp, event: "approval", approval_decided_at: "2026-09-23T10:00:00Z",
    delivered_at: "2026-09-23T10:01:00Z", run: "1/1", digest: `${fp}${"e".repeat(48)}`, held_decision_id: "1".repeat(32), ...over };
  fs.mkdirSync(path.join(root, "state", "alerts"), { recursive: true });
  fs.writeFileSync(path.join(root, "state", "alerts", `${fp}.json`), `${JSON.stringify(rec, null, 2)}\n`);
  return rec;
}

test("TRUST-32 (5.8.0): `ok` is the owner's alone, ties itself to the delivered alert's approval, and is written once per alert", async () => {
  const { OK_ACTOR_IDS, okAuthority } = await import("../lib/operator-role.mjs");
  const { okRecordProblems, OK_MEMBERS } = await import("../lib/service-decide.mjs");
  assert.deepEqual([...OK_ACTOR_IDS], [OWNER_ID], "the act `ok` admits exactly the owner's id; a second id is OPEN-OWNER-13(p)'s decision, not an edit here");
  const root = crowd();
  const fp = "4f1c9a02be773d15";
  const rec = alertOnTree(root, fp);

  for (const [who, id] of [["a stranger", "700000555"], ["a login, not an id", "mihailinl"], ["nobody", undefined]]) {
    const refused = await operator(root, { ASTRA_ACT: "ok", ASTRA_FINGERPRINT: fp, ...(id === undefined ? {} : { ASTRA_ACTOR_ID: id }) });
    assert.equal(refused.code, 1, `${who} wrote an OK: ${refused.logs.join(" | ")}`);
    assert.deepEqual(refused.paths, []);
    assert.equal(okAuthority({ actorId: id }).ok, false, who);
  }
  assert.equal(fs.existsSync(path.join(root, "state", "ok", `${fp}.json`)), false, "a refused OK left a file");

  const ok = await operator(root, { ASTRA_ACT: "ok", ASTRA_FINGERPRINT: fp, ASTRA_ACTOR_ID: OWNER_ID });
  assert.equal(ok.code, 0, ok.logs.join("\n"));
  assert.deepEqual(ok.paths, [`state/ok/${fp}.json`]);
  const doc = JSON.parse(fs.readFileSync(path.join(root, ok.paths[0]), "utf8"));
  assert.deepEqual(Object.keys(doc).sort(), [...OK_MEMBERS].sort());
  assert.equal(doc.approval_decided_at, rec.approval_decided_at, "the OK names the approval its alert was raised for");
  assert.equal(doc.fingerprint, fp);
  assert.deepEqual(okRecordProblems(doc, { fingerprint: fp }), [], "the reader would not read what the writer wrote");
  assert.match(ok.message, /TRUST-32/);
  assert.equal((await operator(root, { ASTRA_ACT: "ok", ASTRA_FINGERPRINT: fp, ASTRA_ACTOR_ID: OWNER_ID })).code, 1, "an OK was given twice for one alert");

  // A new approval of the same fingerprint is a new alert, and takes a new OK.
  alertOnTree(root, fp, { approval_decided_at: "2026-09-25T09:00:00Z", delivered_at: "2026-09-25T09:01:00Z" });
  const again = await operator(root, { ASTRA_ACT: "ok", ASTRA_FINGERPRINT: fp, ASTRA_ACTOR_ID: OWNER_ID });
  assert.equal(again.code, 0, again.logs.join("\n"));
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, again.paths[0]), "utf8")).approval_decided_at, "2026-09-25T09:00:00Z");

  // Refusals: no alert, an undelivered alert, a denied fingerprint, a service decision named too.
  const none = "5f1c9a02be773d15";
  assert.equal((await operator(root, { ASTRA_ACT: "ok", ASTRA_FINGERPRINT: none, ASTRA_ACTOR_ID: OWNER_ID })).code, 1, "an OK with no alert on main");
  const quiet = "6f1c9a02be773d15";
  alertOnTree(root, quiet, { delivered_at: null });
  const undelivered = await operator(root, { ASTRA_ACT: "ok", ASTRA_FINGERPRINT: quiet, ASTRA_ACTOR_ID: OWNER_ID });
  assert.equal(undelivered.code, 1, "an OK for an alert nobody received");
  assert.ok(undelivered.logs.some((l) => /no reported delivery/.test(l)), undelivered.logs.join(" | "));
  const denied = "7f1c9a02be773d15";
  alertOnTree(root, denied);
  assert.equal((await operator(root, { ASTRA_ACT: "deny", ASTRA_FINGERPRINT: denied })).code, 0);
  assert.equal((await operator(root, { ASTRA_ACT: "ok", ASTRA_FINGERPRINT: denied, ASTRA_ACTOR_ID: OWNER_ID })).code, 1, "an OK beside a deny record");
  assert.equal((await operator(root, { ASTRA_ACT: "ok", ASTRA_FINGERPRINT: fp, ASTRA_ACTOR_ID: OWNER_ID, ASTRA_SERVICE_DECISION_ID: SDIS[0] })).code, 1,
    "an ok naming a service decision too was accepted");
});

test("TRUST-32 (5.8.0): the workflow's own `ok` check runs after `authority`, reads the numeric id, and passes every other act", async () => {
  const { main: operatorMain } = await import("../../tools/operator.mjs");
  const run = async (env) => {
    const logs = [];
    const code = await operatorMain(["--job", "ok-authority"], { env, log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) } });
    return { code, logs };
  };
  assert.equal((await run({ ASTRA_ACT: "ok", ASTRA_ACTOR_ID: OWNER_ID })).code, 0);
  assert.equal((await run({ ASTRA_ACT: "ok", ASTRA_ACTOR_ID: "700000555" })).code, 1);
  assert.equal((await run({ ASTRA_ACT: "ok" })).code, 1, "no id is no owner");
  assert.equal((await run({ ASTRA_ACT: "deny", ASTRA_ACTOR_ID: "700000555" })).code, 0, "the check is `ok`'s alone");
  const yml = fs.readFileSync(path.join(REPO, ".github", "workflows", "operator.yml"), "utf8");
  const at = (needle) => yml.indexOf(needle);
  assert.ok(at("--job authority") > 0 && at("--job ok-authority") > at("--job authority") && at("--job act") > at("--job ok-authority"),
    "operator.yml must run `authority`, then `ok-authority`, then the act");
  assert.match(yml, /ASTRA_ACTOR_ID: \$\{\{ github\.actor_id \}\}/, "the check reads github.actor_id, the numeric id");
  assert.match(yml, /options: \[confirm, cancel, revert, deny, ok, revoke-passkey\]/);
});

test("M-T3.5: the operator's allowlist admits its records, its revert paths and the two documents, and nothing else", async () => {
  const { operatorPath } = await import("../../tools/operator.mjs");
  for (const good of [`state/holds/${SDIS[0]}.confirm.json`, `state/holds/${SDIS[0]}.cancel.json`, "state/deny/4f1c9a02be773d15.json",
    "state/ok/4f1c9a02be773d15.json",
    "plugins/widgets/plugin.json", "bot/moderation/2026-09-24-widgets-relist.json", "bot/moderation/2026-09-24-widgets-unrevoke-2.json",
    "tools/revocations/ASTRA-2026-0001.json", "registry/v1/index.json", "registry/v1/revocations.json"]) {
    assert.equal(operatorPath(good), true, `${good} is a path an operator act writes`);
  }
  for (const bad of [`state/holds/${SDIS[0]}.json`, "state/queue/x.json", "plugins/widgets/versions/1.0.0.json",
    "bot/moderation/2026-09-24-widgets-delist.json", "policy/reserved-ids.json", "state/deny/../../x.json",
    "state/ok/../../x.json", "state/ok/4f1c9a02be773d15.json.bak", "state/alerts/4f1c9a02be773d15.json",
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
// `apply` step: a listing refused `B_REPOSITORY_RECYCLED` is reset, and since
// contract 6.6.0 the reset applies in the run that compiles it (MOD-9 held it
// as a reversal for 24 hours and a confirmation until then), in ONE commit
// carrying `Service-Decision:` — DEC-7's voiding record, the log entry
// `reset`, and in case (ii) the identity record deleted too (ID-40). `report`
// posts it `applied`; detector A9 is silent on it; the listing reads `frozen`
// (ID-25); and the new owner's certificate is held `R_IDENTITY_CHANGED`
// against a voided baseline, never refused `B_REPOSITORY_RECYCLED` again. A
// reset held under the old rule and still on a tree is released by the next
// run, and refused by name when MOD-10 no longer holds.

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

const landedFiles = (root) => sh(["show", "--name-status", "--format=", "HEAD"], root).trim().split("\n").sort();
const voidingKey = `service-decision:${SDI}:widgets::identity_reset`;
const voidingPath = recordPath({ decision_id: decisionId(voidingKey), decided_at: "2026-09-20T12:00:00Z" });

test("B-T4.2 (ii): a bound listing's reset applies in the run that compiles it, in one commit, and is never refused again", async () => {
  const root = recycledEstate({ bound: true });
  const origin = withRemote(root);
  const job = await commitJob(root, { entries: [resetOf()], now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.held, [],
    "the reset was held. MOD-9 holds no reversal since contract 6.6.0: the moderator's step-up in the console is " +
    "its one confirmation, and a hold here waited on GitHub where nobody saw it");
  assert.deepEqual(job.results.compiled, [SDI]);
  assert.ok(!job.paths.includes(holdEntryPath(SDI)), `the reset entered a hold: ${job.paths.join(" ")}`);
  for (const rel of ["plugins/widgets/identity.json", "bot/moderation/2026-09-20-widgets-reset.json", voidingPath]) {
    assert.ok(job.paths.includes(rel), `the reset commit does not list ${rel}: ${job.paths.join(" ")}`);
  }
  const step = runApply(root, dated("2026-09-20T12:45:00Z"));
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  const files = landedFiles(root);
  for (const want of [
    "D\tplugins/widgets/identity.json", "A\tbot/moderation/2026-09-20-widgets-reset.json", `A\t${voidingPath}`,
  ]) assert.ok(files.includes(want), `the landed reset commit lacks ${want}: ${files.join(" | ")}`);
  assert.ok(!files.some((f) => f.includes("state/holds/")), `the reset commit touched state/holds/: ${files.join(" | ")}`);
  assert.match(sh(["log", "-1", "--format=%B", landed], root), new RegExp(`^Service-Decision: ${SDI}$`, "m"));

  // DEC-7's voiding record and MOD-47's entry, as `main` now holds them.
  const record = JSON.parse(fs.readFileSync(path.join(root, voidingPath), "utf8"));
  assert.deepEqual(
    [record.actor, record.trigger, record.state, record.category, record.reasons, record.plugin_id],
    ["moderator", "moderation", "identity_reset", "identity_reset", ["M_IDENTITY_RESET"], "widgets"],
  );
  const entry = JSON.parse(fs.readFileSync(path.join(root, "bot/moderation/2026-09-20-widgets-reset.json"), "utf8"));
  assert.deepEqual(checkEntry(entry), [], "the log refuses the entry the reset wrote");

  // BOT-81: `report` posts it `applied`, naming the commit that landed it.
  const posted = await reportJob({ ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit });
  assert.equal(posted.code, 0, posted.logs.join("\n"));
  assert.deepEqual(posted.bodies.map((b) => [b.service_decision_id, b.outcome, b.commit]), [[SDI, "applied", landed]]);
  // Listed again (its result lost): main already carries it, so it is
  // answered `applied`, naming the commit that applied it, and nothing is
  // compiled or written a second time.
  const again = await commitJob(root, { entries: [resetOf()], now: new Date("2026-09-20T13:00:00Z") });
  assert.equal(again.code, 0, again.logs.join("\n"));
  assert.deepEqual(again.paths, [], "a reset was applied a second time");
  assert.deepEqual(again.results.already_applied, [{ service_decision_id: SDI, commit: landed }]);
  assert.deepEqual(again.results.refused, []);

  // Detector A9 excuses the deletion because the voiding record is beside it.
  const detected = detect({ root });
  assert.ok(detected.ran.includes("A9") && detected.scanned.identity_commits >= 1,
    `A9 did not read the reset commit (ran ${detected.ran.join(", ")}; skipped ` +
    `${JSON.stringify(detected.skipped)}), so its silence below would say nothing`);
  assert.deepEqual(detected.findings.filter((f) => f.detector === "A9"), [],
    "A9 alarmed on the reset's own commit");

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
  const root = recycledEstate({ bound: false });
  withRemote(root);
  const job = await commitJob(root, { entries: [resetOf()], now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual([job.results.compiled, job.results.held], [[SDI], []]);
  assert.ok(!job.paths.some((p) => p.endsWith("identity.json")), "a reset with no identity record touched one");
  assert.equal(runApply(root, dated("2026-09-20T12:45:00Z")).status, 0);
  const records = loadRecords(root).decisions.map((r) => r.doc);
  assert.equal(records.filter((r) => r.category === "identity_reset").length, 1,
    "no voiding record: deleting nothing and writing nothing would leave the refusal where it was");
  const { baseline } = baselineFor({ records, pluginId: "widgets" });
  assert.equal(compareWithBaseline({ identity: identityFromCertificate({ ...CERT, ...NEW_IDS }), baseline }).code, "R_IDENTITY_CHANGED");

  // Under a SHADOW answer the reset is work the answer names, so nothing is
  // written for it and nothing posted (BOT-92) — it applies on the live run.
  const shadowRoot = recycledEstate({ bound: false });
  const shadow = await commitJob(shadowRoot, { entries: [resetOf()], shadow: true, now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(shadow.code, 0, shadow.logs.join("\n"));
  assert.deepEqual([shadow.paths, shadow.results.compiled, shadow.results.shadow_withheld.compiled], [[], [], [SDI]]);
});

/** A reset held as a reversal under the rule before contract 6.6.0, landed on the tree at 2026-09-20T12:45Z. */
function leftoverReset({ bound }) {
  const root = recycledEstate({ bound });
  writeAll(root, { [holdEntryPath(SDI)]: holdFixture(resetOf(), { held_for: "reversal", held_at: "2026-09-20T12:30:00Z" }) });
  commitAt(root, "2026-09-20T12:45:00Z", "registry: moderation (1 hold(s))");
  return root;
}

test("B-T4.2: a reset held before contract 6.6.0 is released by the next run, with no confirmation, in one commit", async () => {
  const root = leftoverReset({ bound: true });
  const origin = withRemote(root);
  const job = await commitJob(root, { entries: [], now: new Date("2026-09-20T13:00:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.released_holds, [SDI],
    `a leftover reset with no confirm record was not released; nothing will ever confirm it now: ${job.logs.join(" | ")}`);
  assert.equal(runApply(root, dated("2026-09-20T13:05:00Z")).status, 0);
  const files = landedFiles(root);
  for (const want of ["D\tplugins/widgets/identity.json", `A\t${voidingPath}`, `D\t${holdEntryPath(SDI)}`]) {
    assert.ok(files.includes(want), `the landed release commit lacks ${want}: ${files.join(" | ")}`);
  }
  const after = walkHolds({ root, now: new Date("2026-09-20T13:10:00Z"), shadow: false });
  assert.deepEqual(after.pending, [{ service_decision_id: SDI, outcome: "applied", commit: headOf(origin) }],
    "the next live run does not read the release commit as `applied`");
});

test("B-T4.2: a leftover reset the tree moved under writes nothing and alerts by name, every run", async () => {
  const root = leftoverReset({ bound: true });
  // Another reset of the same refusal voided the id while this one waited.
  writeAll(root, {
    "log/decisions/2026/09/cccccccccccccccccccccccccccccccc.json": {
      schema: "astra.registry.decision/1", decision_id: "c".repeat(32), decided_at: "2026-09-21T09:00:00Z",
      actor: "moderator", moderator: "amoderator", trigger: "moderation", plugin_id: "widgets",
      state: "identity_reset", reasons: ["M_IDENTITY_RESET"], category: "identity_reset",
    },
  });
  commitAt(root, "2026-09-21T09:00:00Z", "moderation: an earlier reset of widgets");
  for (const now of ["2026-09-21T12:46:00Z", "2026-09-21T13:46:00Z"]) {
    const job = await commitJob(root, { entries: [], now: new Date(now) });
    assert.equal(job.code, 0, job.logs.join("\n"));
    assert.deepEqual(job.paths, [], `a reset MOD-10 now refuses was released: ${job.paths.join(" ")}`);
    assert.ok(job.logs.some((l) => l.startsWith(`::error::hold_release_refused ${SDI}:`) && l.includes("target_changed")),
      job.logs.join(" | "));
  }
  assert.ok(fs.existsSync(path.join(root, "plugins/widgets/identity.json")));
  assert.ok(fs.existsSync(path.join(root, holdEntryPath(SDI))), "the entry left the tree without a commit that names it");
});

// ── M_REVIEW through the run (contract 3.0.0; MOD-56) ───────────────────────
//
// The one service decision that adds trust, end to end on the path the
// workflow runs: the list job's schema, the compile, the commit job's files,
// the workflow's own `apply` lines pushing to a real `origin`, and detector A's
// row 11 reading what landed. MOD-56's Check is the second test, clause for
// clause: "a review naming two versions, one already reviewed, moves one and
// logs one entry; a review that can move none is refused `target_changed`".

const REVIEW_REASON = "A moderator read this version's manifest, permissions and bundle and found nothing wrong.";
const reviewOf = (id, versions) => decision({
  service_decision_id: id, code: "M_REVIEW", category: "review_passed", moderator: "amoderator",
  versions, reason: REVIEW_REASON,
});
/** B.4's landing commit is the first whose version schema declares `review`; the fixture's declares it and nothing else. */
const VERSION_SCHEMA_FIXTURE = {
  $comment: "fixture: contract 3.0.0's member alone, so detector A's row 11 finds its landing commit here",
  properties: { review: { enum: ["unreviewed", "reviewed"] } },
};
const markedVersion = (v, review, opts) => ({ ...version("widgets", v, opts), review });

test("the codes the schema admits, the codes the compiler knows and §7.2's codes in the token file are one list", () => {
  // The design's coupling 4. Three lists of one thing: `schema/moderation-work-v1.json`
  // decides what the `list` job accepts, `KNOWN_CODES` what the compile has an
  // answer for, and the token file's §7.2 cells what the contract says each code
  // writes. A code in the schema and not the compiler throws the whole run on
  // the first such decision; one in the compiler and not the schema is refused
  // `kind_refused`, finally (BOT-81), before the compile ever sees it.
  const schemaCodes = [...workSchema(REPO).$defs.serviceDecision.properties.code.enum].sort();
  const known = Object.keys(compiler.KNOWN_CODES ?? {}).sort();
  assert.ok(schemaCodes.includes("M_REVIEW"), `${SCHEMA_FILE} does not admit M_REVIEW, so the list job refuses every review`);
  assert.deepEqual(schemaCodes, known,
    `${SCHEMA_FILE}'s code enum and bot/lib/compile-decision.mjs's KNOWN_CODES have parted`);
  const tokens = JSON.parse(read("schema/contract-tokens-v1.json"));
  const published = tokens.entries
    .filter((e) => e?.kind === "reason_code" && typeof e.artefact === "string").map((e) => e.name).sort();
  assert.deepEqual(schemaCodes, published,
    `${SCHEMA_FILE}'s code enum and the §7.2 codes the token file (${tokens.contract_version}) publishes have parted`);
  assert.ok(schemaCodes.length >= 12, `${schemaCodes.length} codes; §7.2 names 12 service decisions at contract 3.0.0`);
  // And the comparison can fail: the enum one code short is not the list.
  assert.notDeepEqual(schemaCodes.filter((c) => c !== "M_REVIEW"), known);

  assert.deepEqual(checkServiceDecision(reviewOf(SDI, ["1.0.0"]), { root: REPO }), { ok: true },
    "the list job refuses a well-formed M_REVIEW");
});

test("M_REVIEW end to end: one commit on main moves what can move, logs it once, and detector A's row 11 reads it as a decision", async () => {
  const root = withDocuments(estate({
    versions: [],
    at: "2026-09-20T09:00:00Z",
    extra: {
      "schema/version-v1.json": VERSION_SCHEMA_FIXTURE,
      "plugins/widgets/versions/1.0.0.json": markedVersion("1.0.0", "unreviewed"),
      "plugins/widgets/versions/1.1.0.json": markedVersion("1.1.0", "unreviewed"),
      "plugins/widgets/versions/1.2.0.json": markedVersion("1.2.0", "unreviewed", { yanked: true }),
    },
  }));
  const origin = withRemote(root);
  const markOf = (v) => JSON.parse(fs.readFileSync(path.join(root, `plugins/widgets/versions/${v}.json`), "utf8")).review;

  // A first review, of 1.0.0.
  const first = await commitJob(root, { entries: [reviewOf(SDI, ["1.0.0"])], now: new Date("2026-09-20T12:30:00Z") });
  assert.equal(first.code, 0, first.logs.join("\n"));
  assert.deepEqual(first.results.compiled, [SDI], JSON.stringify(first.results));
  assert.equal(runApply(root, dated("2026-09-20T12:45:00Z")).status, 0);

  // MOD-56's Check: a review naming 1.0.0 (already reviewed), 1.1.0 and 1.2.0
  // (yanked) moves 1.1.0 alone, in one entry.
  const job = await commitJob(root, {
    entries: [reviewOf(SDI2, ["1.0.0", "1.1.0", "1.2.0"])], now: new Date("2026-09-20T13:30:00Z"),
  });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual([job.results.compiled, job.results.refused, job.results.held], [[SDI2], [], []],
    "MOD-9: a review is never held, and one that can move a version is not refused");
  assert.ok(job.paths.includes("plugins/widgets/versions/1.1.0.json"), job.paths.join(" "));
  assert.ok(job.paths.includes("bot/moderation/2026-09-20-widgets-review-2.json"),
    `the day's second review did not take MOD-47's -2: ${job.paths.join(" ")}`);
  for (const stuck of ["1.0.0", "1.2.0"]) {
    assert.ok(!job.paths.includes(`plugins/widgets/versions/${stuck}.json`), `${stuck} cannot move and was written`);
  }
  assert.ok(!job.paths.some((p) => p.startsWith("state/holds/") || p.startsWith("tools/revocations/") || p.startsWith("log/decisions/")),
    `a review wrote a hold, an advisory or a decision record: ${job.paths.join(" ")}`);
  const step = runApply(root, dated("2026-09-20T13:45:00Z"));
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  assert.match(sh(["log", "-1", "--format=%B", landed], root), new RegExp(`^Service-Decision: ${SDI2}$`, "m"));
  assert.deepEqual(["1.0.0", "1.1.0", "1.2.0"].map(markOf), ["reviewed", "reviewed", "unreviewed"]);
  const entry = JSON.parse(fs.readFileSync(path.join(root, "bot/moderation/2026-09-20-widgets-review-2.json"), "utf8"));
  assert.deepEqual([entry.action, entry.versions, entry.category, entry.service_decision_id],
    ["review", ["1.1.0"], "review_passed", SDI2], "the entry names the versions the commit moved, and no other");
  assert.deepEqual(checkEntry(entry), []);

  // A review that can move none is refused `target_changed`, and writes nothing.
  const none = await commitJob(root, { entries: [reviewOf(SDI3, ["1.0.0", "1.2.0"])], now: new Date("2026-09-20T14:30:00Z") });
  assert.equal(none.code, 0, none.logs.join("\n"));
  assert.deepEqual(none.results.refused, [{ service_decision_id: SDI3, refusal: "target_changed" }]);
  assert.deepEqual(none.paths, []);

  // Detector A's row 11 reads both review commits, and finds each a decision.
  const detected = detect({ root });
  assert.ok(detected.ran.includes("A11"), `A11 did not run: ${JSON.stringify(detected.skipped)}`);
  assert.ok(detected.scanned.review_commits >= 2,
    `A11 examined ${detected.scanned.review_commits} commit(s), so its silence below says nothing`);
  assert.equal(detected.scanned.review_landing_commit, sh(["rev-list", "--max-parents=0", "HEAD"], root).trim(),
    "the landing commit is the first whose version schema declares `review`, which is this fixture's first");
  assert.deepEqual(detected.findings.filter((f) => f.detector === "A11"), [],
    "row 11 alarmed on the bot's own review commits");

  // The same commit without its trailer is the forgery row 11 exists for.
  const message = sh(["log", "-1", "--format=%B", "HEAD"], root).split("\n")
    .filter((l) => !l.startsWith("Service-Decision:")).join("\n");
  sh(["commit", "--amend", "-q", "-m", message], root);
  const forged = detect({ root }).findings.filter((f) => f.detector === "A11");
  assert.deepEqual(forged.map((f) => f.code), ["A11_REVIEWED_NO_DECISION"], JSON.stringify(forged));
  assert.match(forged[0].message, /widgets\/versions\/1\.1\.0\.json/);
});

test("M_REVIEW over a full takedown bound is applied, the takedown beside it is held, and the review costs the window nothing", async () => {
  // MOD-9 and TRUST-26, at the level the run asks them: a ledger that is
  // already full, and a batch holding a review and a takedown.
  const root = crowd();
  withdrawnInGit(root, PEERS, "2026-09-20T11:30:00Z");
  withRemote(root);
  assert.equal(countWindow(root, { now: new Date("2026-09-20T12:30:00Z") }).count, TAKEDOWN_BOUND,
    "the fixture's bound is not full, so the hold below is not the bound's");

  const job = await measuredJob(root, [reviewOf(SDIS[0], ["1.0.0"]), takedownOf("widgets", 1)]);
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.compiled, [SDIS[0]], "a review waited behind a full takedown bound");
  assert.deepEqual(job.results.held.map((h) => [h.service_decision_id, h.held_for]), [[SDIS[1], "bound"]],
    "the takedown beside it was not held, so this batch is not over the bound and proves nothing");
  assert.equal(runApply(root, dated("2026-09-20T12:45:00Z")).status, 0);

  const after = countWindow(root, { now: new Date("2026-09-20T13:00:00Z") });
  assert.equal(after.count, TAKEDOWN_BOUND, `the review commit changed the count: ${after.detail.join(" | ")}`);
  assert.ok(!after.ids.some((x) => x.id === "widgets"), "a review was counted as withdrawing its listing");
  assert.ok(sh(["show", "--name-only", "--format=", "HEAD"], root).includes("plugins/widgets/versions/1.0.0.json"),
    "the landed commit carries no review, so the count above did not read one");

  // And the ledger's side: with room for ONE more withdrawal, a review ahead of
  // a takedown in the same batch leaves the room to the takedown. A review
  // that spent it would hold the takedown behind a withdrawal nobody made.
  const room = crowd();
  withdrawnInGit(room, ["gadgets", "gizmos"], "2026-09-20T11:30:00Z");
  const both = await measuredJob(room, [reviewOf(SDIS[0], ["1.0.0"]), takedownOf("doohickeys", 1)]);
  assert.equal(both.code, 0, both.logs.join("\n"));
  assert.deepEqual(both.results.compiled, [SDIS[0], SDIS[1]],
    `a review spent the bound's last place, and the takedown after it was held: ${JSON.stringify(both.results.held)}`);

  // A batch of reviews alone is not a takedown batch: no bound is needed for it.
  assert.equal(moderationRun.hasTakedown([reviewOf(SDI, ["1.1.0"])]), false);
  const alone = compileAll([reviewOf(SDI, ["1.1.0"])], { root });
  assert.deepEqual([alone.compiled.length, alone.held.length, alone.refused.length], [1, 0, 0]);
});

// ── M-T3.3: every hold MOD-9 makes ends in a commit (2026-10-14) ────────────
//
// Until this date the release commit was built for `M_IDENTITY_RESET` alone,
// and the cancel commit for nothing: every other confirmed hold — a relist, an
// unrevoke, a `disable`, a takedown over the bound, an unbound removal request
// — was refused by name every run and sat at `held` for good. These run each
// kind through the commit job and the workflow's own `apply` step against a
// real `origin`, and read back what landed.

const recordOf = (id, act, at = "2026-09-19T13:00:00Z") => ({
  schema: "astra.registry.hold-record/1", act, service_decision_id: id,
  at, actor: "operator", run: "https://github.com/a/b/actions/runs/1",
});

/**
 * A tree with one hold on it and the record answering it (none for `act:
 * null`), committed at `held_at`, with the generated documents and a bare
 * `origin`. A leftover kind (`reversal`, `disable_confirmation`) is written as
 * the rule before contract 6.6.0 wrote it (`holdFixture`).
 */
function oneHold(decisionDoc, { held_for, held_at = "2026-09-18T12:00:00Z", act = "confirm", extra = {}, root = null } = {}) {
  const id = decisionDoc.service_decision_id;
  const files = {
    ...extra,
    [holdEntryPath(id)]: holdFixture(decisionDoc, { held_for, held_at }),
    ...(act ? { [`state/holds/${id}.${act}.json`]: recordOf(id, act) } : {}),
  };
  let tree = root;
  if (tree) {
    writeAll(tree, files);
    commitAt(tree, held_at, `hold ${id}`);
  } else {
    tree = withDocuments(estate({ extra: files, at: held_at }));
  }
  const origin = root ? null : withRemote(tree);
  return { root: tree, origin };
}

/** The commit job over no list work, then the `apply` step: what one run does to a tree holding only holds. */
async function holdsRun(root, { now = new Date("2026-09-20T00:00:00Z"), shadow = false } = {}) {
  const job = await commitJob(root, { entries: [], now, shadow });
  assert.equal(job.code, 0, job.logs.join("\n"));
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  const landed = step.outputs.main_commit || null;
  const show = (rel) => {
    try { return landed ? sh(["show", `${landed}:${rel}`], root) : null; } catch { return null; }
  };
  const names = landed ? sh(["show", "--name-status", "--format=", landed], root).split("\n").filter(Boolean) : [];
  const logs = names.filter((l) => /^A\s+bot\/moderation\//.test(l)).map((l) => JSON.parse(show(l.split(/\s+/)[1])));
  return { job, landed, show, names, logs };
}

test("M-T3.3: a confirmed leftover `disable`, a confirmed takedown over the bound and a confirmed unbound removal are each applied at once", async () => {
  const cases = [
    {
      held_for: "disable_confirmation",
      decision: decision({ code: "M_REVOKE", category: "malicious", severity: "high", action: "disable", moderator: "amoderator", versions: ["1.0.0"] }),
      check: (run) => {
        const added = run.names.filter((l) => /^A\s+tools\/revocations\//.test(l));
        assert.equal(added.length, 1, `the release published ${added.length} advisories: ${run.names.join(" | ")}`);
        const advisory = JSON.parse(run.show(added[0].split(/\s+/)[1]));
        assert.equal(advisory.action, "disable");
        assert.deepEqual(run.logs.map((e) => [e.action, e.advisory, e.service_decision_id]), [["revoke", advisory.id, SDI]]);
        assert.match(run.show(REVOCATIONS_FILE), new RegExp(advisory.id), "the withdrawal list that landed does not carry the advisory");
      },
    },
    {
      held_for: "bound",
      decision: delistOf(SDI),
      check: (run) => {
        assert.equal(JSON.parse(run.show("plugins/widgets/plugin.json")).unlisted, true, "the confirmed takedown did not delist");
        assert.deepEqual(run.logs.map((e) => [e.action, e.service_decision_id]), [["delist", SDI]]);
      },
    },
    {
      held_for: "unbound_removal",
      bound: false,
      decision: decision({ code: "A_REMOVAL_REQUEST", reason: FIXED_REMOVAL }),
      check: (run) => {
        assert.equal(JSON.parse(run.show("plugins/widgets/plugin.json")).unlisted, true, "the confirmed removal did not delist");
        assert.deepEqual(run.logs.map((e) => [e.action, e.category, e.service_decision_id]), [["delist", "author_request", SDI]]);
      },
    },
  ];
  for (const c of cases) {
    const root = withDocuments(estate({
      bound: c.bound ?? true,
      extra: {
        [holdEntryPath(SDI)]: holdFixture(c.decision, { held_for: c.held_for, held_at: "2026-09-18T12:00:00Z" }),
        [`state/holds/${SDI}.confirm.json`]: recordOf(SDI, "confirm"),
      },
      at: "2026-09-18T12:00:00Z",
    }));
    const origin = withRemote(root);
    const run = await holdsRun(root);
    assert.deepEqual(run.job.results.released_holds, [SDI], `${c.held_for}: ${run.job.logs.join(" | ")}`);
    assert.equal(run.landed, headOf(origin), `${c.held_for}: nothing was pushed`);
    assert.equal(run.show(holdEntryPath(SDI)), null, `${c.held_for}: the entry stayed`);
    assert.equal(run.show(`state/holds/${SDI}.confirm.json`), null, `${c.held_for}: the confirm record stayed`);
    assert.match(sh(["log", "-1", "--format=%B", run.landed], root), new RegExp(`^Service-Decision: ${SDI}$`, "m"));
    c.check(run);
    const next = await historyJob(root, { now: new Date("2026-09-20T00:20:00Z") });
    assert.deepEqual(next.bodies.map((b) => [b.service_decision_id, b.outcome, b.commit]), [[SDI, "applied", run.landed]],
      `${c.held_for}: the next live run did not post \`applied\` naming the release commit`);
  }
});

test("M_UNREVOKE applies in the run that compiles it: the advisory the reversed decision published is deleted, and `unrevoke` names both (6.6.0)", async () => {
  // Leg one: an `M_REVOKE` (block_install, so not held) applied and pushed.
  const root = withDocuments(estate({ at: "2026-09-17T09:00:00Z" }));
  const origin = withRemote(root);
  const revoke = decision({
    service_decision_id: SDI2, code: "M_REVOKE", category: "security_defect", severity: "high",
    action: "block_install", moderator: "amoderator", versions: ["1.0.0"], decided_at: "2026-09-17T10:00:00Z",
  });
  const first = await commitJob(root, { entries: [revoke], now: new Date("2026-09-17T10:30:00Z") });
  assert.equal(first.code, 0, first.logs.join("\n"));
  assert.equal(runApply(root, dated("2026-09-17T10:45:00Z")).status, 0);
  const advisory = first.results.written.find((p) => p.startsWith("tools/revocations/ASTRA-"));
  assert.ok(advisory, `the revoke published no advisory: ${first.results.written.join(", ")}`);

  // Leg two: the moderator's `M_UNREVOKE`, compiled and applied in its own
  // run — no hold entry, no 24 hours, no confirmation (MOD-9 since 6.6.0).
  const unrevoke = decision({
    code: "M_UNREVOKE", category: "error", moderator: "amoderator", reverses: SDI2, decided_at: "2026-09-18T11:00:00Z",
    reason: "The advisory named a bundle that was never shipped; the withdrawal is lifted and the listing stands.",
  });
  const lifted = await commitJob(root, { entries: [unrevoke], now: new Date("2026-09-18T11:30:00Z") });
  assert.equal(lifted.code, 0, lifted.logs.join("\n"));
  assert.deepEqual([lifted.results.compiled, lifted.results.held], [[SDI], []],
    `the unrevoke was not applied in the run that compiled it: ${lifted.logs.join(" | ")}`);
  assert.ok(!lifted.paths.some((p) => p.startsWith("state/holds/")), `the unrevoke entered a hold: ${lifted.paths.join(" ")}`);
  const step = runApply(root, dated("2026-09-18T11:45:00Z"));
  assert.equal(step.status, 0, step.stderr);
  const landedAt = headOf(origin);
  const show = (rel) => { try { return sh(["show", `${landedAt}:${rel}`], root); } catch { return null; } };
  const names = sh(["show", "--name-status", "--format=", landedAt], root).split("\n").filter(Boolean);
  const run = {
    names,
    show,
    logs: names.filter((l) => /^A\s+bot\/moderation\//.test(l)).map((l) => JSON.parse(show(l.split(/\s+/)[1]))),
  };
  assert.ok(run.names.some((l) => l === `D\t${advisory}`), `the release did not delete ${advisory}: ${run.names.join(" | ")}`);
  const id = path.basename(advisory, ".json");
  assert.deepEqual(run.logs.map((e) => [e.action, e.advisory, e.reverses, e.service_decision_id]), [["unrevoke", id, SDI2, SDI]]);
  assert.ok(!run.show(REVOCATIONS_FILE).includes(id), "the withdrawal list that landed still carries the lifted advisory");

  // And an unrevoke of the same advisory left on the tree as a hold from
  // before 6.6.0 — released at once, with no confirmation — finds nothing
  // left to lift, and writes nothing.
  const again = oneHold({ ...unrevoke, service_decision_id: SDI3 }, { held_for: "reversal", act: null, root });
  const twice = await commitJob(again.root, { entries: [], now: new Date("2026-09-20T00:00:00Z") });
  assert.equal(twice.code, 0, twice.logs.join("\n"));
  assert.deepEqual(twice.results.released_holds, []);
  assert.deepEqual(twice.results.release_refused.map((r) => [r.service_decision_id, r.refusal]), [[SDI3, "target_changed"]]);

  // The advisory is found from git, by the decision `reverses` names, and only
  // for the listing the unrevoke is about: one naming another listing's revoke
  // lifts nothing. Watched failing by dropping the listing comparison.
  const other = crowd({ at: "2026-09-17T09:00:00Z" });
  withDocuments(other);
  withRemote(other);
  const otherRevoke = await commitJob(other, { entries: [revoke], now: new Date("2026-09-17T10:30:00Z") });
  assert.equal(otherRevoke.code, 0, otherRevoke.logs.join("\n"));
  assert.equal(runApply(other, dated("2026-09-17T10:45:00Z")).status, 0);
  const wrong = await commitJob(other, { entries: [{ ...unrevoke, plugin_id: "gadgets" }], now: new Date("2026-09-20T00:00:00Z") });
  assert.equal(wrong.code, 0, wrong.logs.join("\n"));
  assert.deepEqual(wrong.paths, [], "an unrevoke of gadgets lifted the advisory widgets' revoke published");
  assert.deepEqual(wrong.results.refused.map((r) => [r.service_decision_id, r.refusal]), [[SDI, "target_changed"]]);
});

test("M-T3.3: a release the tree has moved under writes nothing, keeps the entry, and alerts by name every run", async () => {
  // A relist held before 6.6.0 for a listing a MOD-52 revert has already relisted.
  const { root } = oneHold(relistOf(SDI), { held_for: "reversal" });
  const job = await commitJob(root, { entries: [], now: new Date("2026-09-20T00:00:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.paths, [], "a refused release committed something");
  assert.deepEqual(job.results.release_refused.map((r) => [r.service_decision_id, r.refusal]), [[SDI, "target_changed"]]);
  assert.ok(job.logs.some((l) => l.startsWith(`::error::hold_release_refused ${SDI}:`)), job.logs.join(" | "));
  assert.ok(fs.existsSync(path.join(root, holdEntryPath(SDI))), "the refused release deleted the entry anyway");

  // And a takedown confirmed as `bound` whose listing has since lost its
  // identity record is now an unbound case: the confirmation for the bound
  // does not apply it. MOD-9's kinds are strictest first, and a confirmation
  // releases the hold it answers.
  const yank = decision({ code: "A_YANK", versions: ["1.0.0"], reason: FIXED_YANK });
  const moved = withDocuments(estate({
    bound: false,
    extra: {
      [holdEntryPath(SDI2)]: holdEntry({ ...yank, service_decision_id: SDI2 }, { held_for: "bound", held_at: "2026-09-18T12:00:00Z" }),
      [`state/holds/${SDI2}.confirm.json`]: recordOf(SDI2, "confirm"),
    },
    at: "2026-09-18T12:00:00Z",
  }));
  const strict = await commitJob(moved, { entries: [], now: new Date("2026-09-20T00:00:00Z") });
  assert.equal(strict.code, 0, strict.logs.join("\n"));
  assert.deepEqual(strict.paths, [], "a yank confirmed under the bound was applied to a listing with no bound account");
  assert.deepEqual(strict.results.release_refused.map((r) => [r.service_decision_id, r.outcome]), [[SDI2, "held"]]);
});

test("M-T3.3: an applied `author_request` delist cancels an unbound removal request in the same commit, with no log entry of its own", async () => {
  const removal = decision({ service_decision_id: SDI2, code: "A_REMOVAL_REQUEST", reason: FIXED_REMOVAL });
  const root = withDocuments(estate({
    bound: false,
    extra: { [holdEntryPath(SDI2)]: holdEntry(removal, { held_for: "unbound_removal", held_at: "2026-09-18T12:00:00Z" }) },
    at: "2026-09-18T12:00:00Z",
  }));
  const origin = withRemote(root);
  const delist = decision({ code: "M_DELIST", category: "author_request", moderator: "amoderator", decided_at: "2026-09-19T10:00:00Z" });
  const job = await commitJob(root, { entries: [delist], now: new Date("2026-09-20T00:00:00Z") });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.compiled, [SDI]);
  assert.deepEqual(job.results.cancelled_holds, [SDI2], "the removal request the delist settled was not cancelled (MOD-9)");
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);
  const message = sh(["log", "-1", "--format=%B", landed], root);
  for (const id of [SDI, SDI2]) assert.match(message, new RegExp(`^Service-Decision: ${id}$`, "m"));
  // One delist log entry, the moderator's: the cancel writes none, so the next
  // run reads the removal request as cancelled and the delist as applied.
  const next = await historyJob(root, { now: new Date("2026-09-20T00:20:00Z") });
  assert.deepEqual(next.bodies.map((b) => [b.service_decision_id, b.outcome, b.commit]), [[SDI2, "cancelled", landed]]);
});

test("M-T3.3 and MOD-52: a takedown released over the bound is reverted by the operator, unheld, and logged as reversing it", async () => {
  const { root, origin } = oneHold(delistOf(SDI), { held_for: "bound" });
  const run = await holdsRun(root);
  assert.deepEqual(run.job.results.released_holds, [SDI], run.job.logs.join(" | "));
  assert.equal(JSON.parse(run.show("plugins/widgets/plugin.json")).unlisted, true);

  // The operator's revert, as `operator.yml` runs it, over the tree that landed.
  const act = operatorAct({ root, act: "revert", serviceDecisionId: SDI, now: new Date("2026-09-20T01:00:00Z"), runId: "9" });
  assert.ok(act.paths.includes("plugins/widgets/plugin.json"), act.paths.join(", "));
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, "plugins/widgets/plugin.json"), "utf8")).unlisted, undefined,
    "the revert did not relist the plugin the release delisted");
  const logFile = act.paths.find((p) => /^bot\/moderation\/.*-widgets-relist\.json$/.test(p));
  const entry = JSON.parse(fs.readFileSync(path.join(root, logFile), "utf8"));
  assert.deepEqual([entry.action, entry.reverses, entry.category], ["relist", SDI, "error"]);
  assert.match(act.message, new RegExp(`^Service-Decision: ${SDI}$`, "m"));
  assert.equal(headOf(origin), run.landed);
});

// MOD-46, which the release commit made live: until 2026-10-14 nothing
// released a relist or an unrevoke, so a canary that blocks only those blocked
// nothing, and the commit job never asked it. Watched failing by not handing
// the walk `coverageRed`, and by asking the canary when no reversal is due.
test("MOD-46: a red coverage canary holds back only a leftover reversal hold — no takedown, no fresh relist — and is asked only when one is on the tree", async () => {
  const red = () => ({ status: "red", codes: ["MOD_UNLISTED_UNLOGGED"] });
  const unlisted = { "plugins/widgets/plugin.json": plugin("widgets", { unlisted: true }) };
  // A relist held before contract 6.6.0, with no confirm record: nothing will
  // ever confirm it, so only the canary may hold it back, and only a run.
  const relist = oneHold(relistOf(SDI), { held_for: "reversal", act: null, extra: unlisted });
  const blocked = await commitJob(relist.root, { entries: [], now: new Date("2026-09-20T00:00:00Z"), coverage: red });
  assert.equal(blocked.code, 0, blocked.logs.join("\n"));
  assert.deepEqual(blocked.paths, [], "a leftover relist was released under a red coverage canary");
  assert.match(waitingFor(blocked.results.holds, SDI), /MOD-46/);
  assert.ok(blocked.logs.some((l) => l.includes("MOD-46: the coverage canary is red (MOD_UNLISTED_UNLOGGED)")), blocked.logs.join(" | "));
  const broken = await commitJob(relist.root, { entries: [], now: new Date("2026-09-20T00:00:00Z"), coverage: () => { throw new Error("shallow"); } });
  assert.deepEqual(broken.paths, [], "a canary that could not run released a leftover reversal");
  const green = await commitJob(relist.root, { entries: [], now: new Date("2026-09-20T00:00:00Z") });
  assert.deepEqual(green.results.released_holds, [SDI], "and green, it is released with no confirmation: the block above is the canary's");

  // Nothing else waits on it. A takedown released over the bound, a fresh
  // relist the moderator just decided — neither is held, and with no leftover
  // reversal on the tree the canary is not even run.
  let asked = 0;
  const counting = () => { asked += 1; return red(); };
  const takedown = oneHold(delistOf(SDI2), { held_for: "bound" });
  const applied = await commitJob(takedown.root, { entries: [], now: new Date("2026-09-20T00:00:00Z"), coverage: counting });
  assert.deepEqual(applied.results.released_holds, [SDI2], "a red coverage canary held back a takedown (MOD-46 blocks no takedown)");
  const fresh = withDocuments(estate({ extra: unlisted }));
  const relisted = await commitJob(fresh, { entries: [relistOf(SDI3)], now: new Date("2026-09-20T00:00:00Z"), coverage: counting });
  assert.equal(relisted.code, 0, relisted.logs.join("\n"));
  assert.deepEqual(relisted.results.compiled, [SDI3],
    "a red coverage canary stopped a fresh relist; since contract 6.6.0 a relist is no hold, and MOD-46 blocks only a held one");
  assert.equal(asked, 0, "the canary was run with no leftover reversal on the tree");
});

// ── MOD-47's round trip, in CI (MOD-1) ──────────────────────────────────────
//
// MOD-47: "CI runs revoke → unrevoke → log build → sign". MOD-1 keeps
// `M_DEPRECATE`, `M_REVOKE` and `M_UNREVOKE` off the panel until, among other
// things, that round trip passes. Until 2026-10-14 the nearest thing was
// moderation.test.mjs's backing check over hand-written log entries, with the
// signing half left to ROLL-1's walk with real keys — and no unrevoke could be
// produced by the bot at all, because nothing released a held `M_UNREVOKE`.
//
// This is the whole trip on a fixture, through the code a production run
// executes: the commit job compiles the revoke and the workflow's `apply`
// step pushes it; the withdrawal list is rebuilt and signed with a TEST index
// key and verified as a client verifies it; the moderation log is built
// against that signed list; the `M_UNREVOKE` is listed, compiled and pushed in
// that same run (MOD-9 holds no reversal since contract 6.6.0 — until then it
// was held, confirmed by the operator's act and released 24 hours later); and
// the list is rebuilt, re-signed at a higher serial, verified,
// and the log built against it shows the revoke settled by the unrevoke. Never
// a production act: a fixture repository, a bare `origin`, a committed key
// that says TEST-ONLY in its id.
test("MOD-47's round trip: revoke → unrevoke → moderation log build → sign, through the commit job, and every signature verifies", async () => {
  const KEY = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
  const test = loadTestRoot(KEY);
  const signer = { key_id: KEY, privateKey: test.privateKey, public_key: test.publicKeyB64 };
  const keys = [{ key_id: KEY, publicKey: publicKeyFromBase64(test.publicKeyB64) }];
  const committedList = (root, sha) => JSON.parse(sh(["show", `${sha}:${REVOCATIONS_FILE}`], root));

  const root = withDocuments(estate({ at: "2026-09-17T09:00:00Z" }));
  const origin = withRemote(root);

  // ── revoke ──
  const revoke = decision({
    service_decision_id: SDI2, code: "M_REVOKE", category: "security_defect", severity: "high",
    action: "block_install", moderator: "amoderator", versions: ["1.0.0"], decided_at: "2026-09-17T10:00:00Z",
  });
  const first = await commitJob(root, { entries: [revoke], now: new Date("2026-09-17T10:30:00Z") });
  assert.equal(first.code, 0, first.logs.join("\n"));
  assert.equal(runApply(root, dated("2026-09-17T10:45:00Z")).status, 0);
  const revoked = headOf(origin);
  const advisory = path.basename(first.results.written.find((p) => p.startsWith("tools/revocations/ASTRA-")), ".json");

  // The document the commit carried is the generator's own, and it signs.
  assert.equal(stableStringify(committedList(root, revoked)), stableStringify(buildRevocations({ root })),
    "the withdrawal list the revoke commit carried is not what the generator builds from the tree it landed");
  const list1 = signRevocations(committedList(root, revoked), { signer, issuedAt: new Date("2026-09-17T11:00:00Z") });
  assert.deepEqual(verifyEnvelope(list1, REVOCATIONS_SCHEMA, keys), { ok: true, key_id: KEY });
  assert.ok(list1.signed.revocations.some((r) => r.id === advisory), `the signed list does not carry ${advisory}`);

  // ── log build, against the signed list ──
  const log1 = buildModerationLog({ root, revocations: list1.signed.revocations, revocationsSerial: list1.signed.serial });
  const revokeEntry = (log) => log.entries.find((e) => e.action === "revoke" && e.advisory === advisory);
  assert.equal(revokeEntry(log1)?.backed, true, "the revoke is not backed by the signed advisory it names");

  // ── unrevoke: listed, compiled, applied in the same run ──
  const unrevoke = decision({
    code: "M_UNREVOKE", category: "error", moderator: "amoderator", reverses: SDI2, decided_at: "2026-09-18T09:00:00Z",
    reason: "The advisory named a bundle that was never shipped; the withdrawal is lifted and the listing stands.",
  });
  const second = await commitJob(root, { entries: [unrevoke], now: new Date("2026-09-18T09:30:00Z") });
  assert.equal(second.code, 0, second.logs.join("\n"));
  assert.deepEqual([second.results.compiled, second.results.held], [[SDI], []],
    "the unrevoke was not applied in the run that compiled it (MOD-9 holds no reversal since 6.6.0)");
  const step = runApply(root, dated("2026-09-18T09:45:00Z"));
  assert.equal(step.status, 0, step.stderr);
  const lifted = headOf(origin);
  assert.equal(step.outputs.main_commit, lifted);

  // ── sign again: a higher serial, the advisory gone, the signature good ──
  const committed2 = committedList(root, lifted);
  assert.equal(stableStringify(committed2), stableStringify(buildRevocations({ root })),
    "the withdrawal list the unrevoke commit carried is not what the generator builds from the tree it landed");
  const list2 = signRevocations(committed2, { signer, issuedAt: new Date("2026-09-19T11:00:00Z") });
  assert.deepEqual(verifyEnvelope(list2, REVOCATIONS_SCHEMA, keys), { ok: true, key_id: KEY });
  assert.ok(list2.signed.serial > list1.signed.serial,
    `the list lifting ${advisory} is serial ${list2.signed.serial}, not above ${list1.signed.serial}: a client holding the older list keeps the withdrawal`);
  assert.ok(!list2.signed.revocations.some((r) => r.id === advisory), `the signed list still carries ${advisory}`);

  // ── log build, against the re-signed list: the revoke settled, the unrevoke newest ──
  const log2 = buildModerationLog({ root, revocations: list2.signed.revocations, revocationsSerial: list2.signed.serial });
  assert.equal(revokeEntry(log2)?.backed, "settled", "an advisory lifted by an unrevoke is not read as settled (MOD-47)");
  const top = log2.entries[0];
  assert.deepEqual([top.action, top.advisory, top.reverses, top.service_decision_id], ["unrevoke", advisory, SDI2, SDI],
    "the newest log entry is not the unrevoke naming the advisory and the decision it reverses");
  // And against the OLD list the log would still claim the withdrawal: the
  // signature is what makes the second build's answer the served one.
  const stale = buildModerationLog({ root, revocations: list1.signed.revocations, revocationsSerial: list1.signed.serial });
  assert.equal(revokeEntry(stale)?.backed, true, "against the list that still carries it, the advisory reads as in force");

  // The signatures are real: one changed byte in either list fails verification.
  for (const list of [list1, list2]) {
    const forged = JSON.parse(JSON.stringify(list));
    forged.signed.serial += 1;
    assert.equal(verifyEnvelope(forged, REVOCATIONS_SCHEMA, keys).ok, false, "a re-serialled list still verified");
  }
});

// ── BOT-30's submission results, posted (2026-10-14) ────────────────────────
//
// The commit job has written a stop's or an `M_REJECT`'s terminal record since
// M-T3.4, and `report` posted only service-decision results: the record landed
// and the service — which lists a stop until it has confirmed the record
// (BOT-80) — was never told which commit holds it, so it listed it again every
// run. M-T3.4's `report` posts "stop and `M_REJECT` results, with
// `recorded[]`, to `POST bot/results`", 20 seconds per call. Watched failing
// by dropping `recorded`, by naming the pushed commit for a record found
// already on `main`, by leaving the client at its 30-second default, and by
// not posting these at all.
test("a stop and an M_REJECT are posted to bot/results with recorded[], equal to their records, and a re-post is byte-identical", async () => {
  const SUB2 = "0192f3a4-5b6c-7d8e-9f01-2345678901ac";
  const stop = {
    submission_id: SUB, repo: "acme/widgets", tag: "widgets-v1.1.0", trigger: "panel",
    service_repository_id: "912345678", stop_status: "stopped", fingerprints: ["0123456789abcdef"], code: "A_STOP",
  };
  const reject = {
    submission_id: SUB2, repo: "acme/widgets", tag: "widgets-v1.2.0", trigger: "panel",
    service_repository_id: "912345678", fingerprints: ["fedcba9876543210"], code: "M_REJECT",
    category: "malicious", moderator: "amoderator", decided_at: "2026-09-20T12:00:00Z",
  };
  const root = withDocuments(estate());
  const origin = withRemote(root);
  const job = await commitJob(root, { entries: [], submissions: [stop, reject] });
  assert.equal(job.code, 0, job.logs.join("\n"));
  assert.deepEqual(job.results.terminal.map((t) => t.written), [true, true], "the fixture wrote no terminal record");
  const step = runApply(root);
  assert.equal(step.status, 0, step.stderr);
  const landed = headOf(origin);

  const timeouts = [];
  const saved = AbortSignal.timeout;
  AbortSignal.timeout = (ms) => { timeouts.push(ms); return saved.call(AbortSignal, ms); };
  let report;
  try {
    report = await reportJob({ ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: step.outputs.main_commit });
  } finally {
    AbortSignal.timeout = saved;
  }
  assert.equal(report.code, 0, report.logs.join("\n"));
  const results = report.posts.filter((p) => p.path === "bot/results");
  assert.equal(results.length, 2, `report posted ${results.length} submission result(s): ${report.posts.map((p) => p.path).join(", ")}`);
  // Every abort timer the job armed, the token mint's included: none is the
  // client's 30-second default, so each service call ran under 20 seconds.
  assert.ok(timeouts.length >= 2 && !timeouts.includes(CALL_TIMEOUT_MS) && timeouts.includes(20_000),
    `report's calls were given ${timeouts.join(", ")} ms, not 20 s each`);

  for (const [entry, state] of [[stop, "stopped"], [reject, "refused"]]) {
    const body = JSON.parse(results.find((p) => JSON.parse(p.bytes).submission_id === entry.submission_id).bytes);
    const row = job.results.terminal.find((t) => t.result.submission_id === entry.submission_id);
    const record = JSON.parse(sh(["show", `${landed}:${row.path}`], root));
    assert.equal(body.schema, "astra.plugins.bot-result/1");
    assert.equal(body.state, state);
    assert.equal(body.main_commit, landed, `${state}: the result does not name the commit holding its record (BOT-23)`);
    // BOT-23: every DEC-7 member the result carries equals the record's.
    assert.deepEqual(
      [body.state, body.reasons.map((r) => r.code), body.decision_id, body.tag, body.fingerprint, body.repository_id],
      [record.state, record.reasons, record.decision_id, record.tag, record.fingerprint, record.repository_id],
      `${state}: the result disagrees with the record at the commit it names`,
    );
    assert.deepEqual(body.recorded, [{ fingerprint: record.fingerprint, decision_id: record.decision_id }],
      `${state}: recorded[] is not the (fingerprint, decision_id) pair this run recorded (§4.4)`);
    for (const r of body.reasons) assert.deepEqual(Object.keys(r).sort(), ["code", "location", "message", "stage"]);
    for (const m of ["moderator", "category", "declared_interest", "repo", "trigger"]) {
      assert.ok(!Object.hasOwn(body, m), `${state}: the result carries \`${m}\`, which §4.4 does not give it`);
    }
  }

  // The service lists both again until it has confirmed them. The next run
  // finds each record already on `main`, commits nothing, and re-posts the
  // same bytes under the same BOT-82 key, naming the commit that holds it.
  const again = await commitJob(root, { entries: [], submissions: [stop, reject] });
  assert.equal(again.code, 0, again.logs.join("\n"));
  assert.deepEqual(again.paths, [], "a record already on main was committed again");
  const quiet = runApply(root);
  assert.equal(quiet.outputs.main_commit, "");
  const repost = await reportJob(
    { ASTRA_RESULTS: quiet.outputs.results, ASTRA_MAIN_COMMIT: "" },
    { answer: () => ({ status: 200, body: { schema: "astra.plugins.bot-ack/1", shadow: false, outcome: "duplicate" } }) },
  );
  assert.equal(repost.code, 0, `a duplicate acknowledgement failed the job: ${repost.logs.join(" | ")}`);
  assert.deepEqual(repost.posts.filter((p) => p.path === "bot/results").map((p) => p.bytes).sort(), results.map((p) => p.bytes).sort(),
    "the re-post is not byte-identical, so BOT-82's key would record a second landing");

  // A record written by a run that pushed nothing has no commit to name.
  const dry = await reportJob({ ASTRA_RESULTS: step.outputs.results, ASTRA_MAIN_COMMIT: "" })
    .catch((e) => ({ code: 2, posts: [], logs: [e.message] }));
  assert.notEqual(dry.code, 0, "a stop was reported against no commit");
  assert.deepEqual(dry.posts, [], "something was posted before the unnamed result was refused");

  // Shadow: no terminal record, so no submission result (BOT-92).
  const shadowRoot = withDocuments(estate());
  withRemote(shadowRoot);
  const shadowJob = await commitJob(shadowRoot, { entries: [], submissions: [stop, reject], shadow: true });
  const shadowStep = runApply(shadowRoot);
  const shadowReport = await reportJob({ ASTRA_RESULTS: shadowStep.outputs.results, ASTRA_MAIN_COMMIT: shadowStep.outputs.main_commit });
  assert.equal(shadowJob.code, 0);
  assert.deepEqual(shadowReport.posts, [], "report posted a submission result under a shadow answer");
});
