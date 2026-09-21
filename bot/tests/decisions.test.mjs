#!/usr/bin/env node
// `bot/lib/decisions.mjs`: BOT-35's id, DEC-7's author-action record, BOT-36's
// dropped write and BOT-37's trailers. `node --test bot/tests/decisions.test.mjs`.
// No network, no probe; two tests build a temp tree and remove it.
//
// Registry plan B-T2.2. The module is DARK — its four callers are B-T3.4,
// B-T3.7, B-T3.7b and M-T3.8, none of which has landed — so this suite is the
// only thing that executes it, and it is written accordingly.
//
// ── WHAT THIS SUITE IS FOR, WHICH IS NOT "DOES THE HASH HASH" ───────────────
//
// Every failure this module can have is silent. A wrong `decision_id` is 32
// hex characters, like a right one. A record written under a second derivation
// is a valid file in a valid directory. A yank committed without BOT-37's
// `Service-Decision:` trailer is a well-formed commit whose records the
// service's detector B cannot match to their outcome, and the report arrives
// over there, about us, days later. None of that shows up as an exception.
//
// So the assertions are about AGREEMENT — between the two places `main`
// already spells BOT-35's `migration:` key, between this writer and the
// callers that refuse against it by name, between a tuple and the id it gives
// twice — rather than about the shapes, which a schema will catch once B-T2.1
// writes one.
//
// ── WHAT THIS SUITE CANNOT SEE ──────────────────────────────────────────────
//
// `schema/decision-v1.json` (B-T2.1) is not in this checkout, so "validates
// against the schema" is asserted by nothing here. It is not left as a
// comment: `the schema B-T2.1 writes` below goes RED the day that file lands,
// and names the assertion to wire. A promise would have been read once and
// never again.
//
// Detector B is the plugins service's, so the `Service-Decision:` canary below
// asserts what this side RENDERS and nothing about what over there matches.
// That half is OUT OF SCOPE for this repository and is stated rather than
// implied by a green tick.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  AUTHOR_ACTION_FORBIDDEN,
  AUTHOR_ACTION_MEMBERS,
  DECISIONS_DIR,
  DECISION_ID_CHARS,
  DECISION_MEMBERS,
  DECISION_SCHEMA_FILE,
  KEY_DOMAINS,
  RECORD_SCHEMA,
  SUBJECT_ID_PATTERN,
  TRAILERS,
  composeAuthorActions,
  decisionCommitMessage,
  decisionId,
  decisionKey,
  decisionSchema,
  keyDomain,
  legacyKey,
  migrationKey,
  permittedCoordinate,
  privacyFindings,
  recordPath,
  recordsOnMain,
  refusePrivate,
  renderTrailers,
  serviceDecisionKey,
  subjectIdFindings,
  submissionKey,
  writeDecisionRecord,
} from "../lib/decisions.mjs";

import { migrationKey as exportIssuesMigrationKey, resolveWriter } from "../export-issues.mjs";
import { migrationKey as baselineMigrationKey } from "../baseline.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

const SUBMISSION = "0192f3a1-7c4b-7d2e-9f01-2b3c4d5e6f70";
const SERVICE_DECISION = "3f2a11c8-9d44-4b6e-8a01-77c0de91b432";
const YANK = {
  service_decision_id: SERVICE_DECISION,
  plugin_id: "dice-roller",
  versions: ["1.0.0"],
  repo: "teletemagame-dev/dice-roller",
  repository_id: "912345678",
  repository_owner_id: "45678901",
  decided_at: "2026-09-20T11:22:33Z",
};

const trash = [];
process.on("exit", () => {
  for (const d of trash) fs.rmSync(d, { recursive: true, force: true });
});

function tree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-decisions-"));
  trash.push(dir);
  return dir;
}

const read = (root, rel) => JSON.parse(fs.readFileSync(path.join(root, ...rel.split("/")), "utf8"));

// ── BOT-35: one key, one id ─────────────────────────────────────────────────

test("the same tuple gives the same id, on both of BOT-35's tuples", () => {
  // Determinism is the whole requirement: "a retry finds the same id"
  // (BOT-35's Why). A run that retried after a rebase and derived a second id
  // would write a second record for one decision, and BOT-36's dedupe — which
  // matches on the id — would not see it.
  const first = submissionKey({ submission_id: SUBMISSION });
  assert.equal(decisionId(first), decisionId(submissionKey({ submission_id: SUBMISSION })));

  const second = serviceDecisionKey({
    service_decision_id: SERVICE_DECISION, plugin_id: "dice-roller", version: "1.0.0", state: "yanked",
  });
  assert.equal(decisionId(second), decisionId(serviceDecisionKey({
    service_decision_id: SERVICE_DECISION, plugin_id: "dice-roller", version: "1.0.0", state: "yanked",
  })));

  for (const id of [decisionId(first), decisionId(second)]) {
    assert.match(id, new RegExp(`^[0-9a-f]{${DECISION_ID_CHARS}}$`), "§0.7: 32 lowercase hex");
  }
});

test("the second tuple's four members each change the id", () => {
  // BOT-35's second tuple is (`service_decision_id`, `plugin_id`, `version`,
  // `state`) and the plan spells it TWICE — its §1.2 amendment list drops
  // `plugin_id` and `state`. If the short form were the one implemented, two
  // versions of two plugins yanked under one service decision would collide in
  // pairs. This is the assertion that would have caught that, so it names each
  // member rather than asserting "different inputs, different outputs".
  const base = {
    service_decision_id: SERVICE_DECISION, plugin_id: "dice-roller", version: "1.0.0", state: "yanked",
  };
  const id = decisionId(serviceDecisionKey(base));
  const variants = {
    service_decision_id: { ...base, service_decision_id: "3f2a11c8-9d44-4b6e-8a01-77c0de91b433" },
    plugin_id: { ...base, plugin_id: "card-shuffler" },
    version: { ...base, version: "1.0.1" },
    state: { ...base, state: "withdrawn" },
  };
  for (const [member, parts] of Object.entries(variants)) {
    assert.notEqual(decisionId(serviceDecisionKey(parts)), id,
      `changing \`${member}\` did not change the id, so that member is not in the key BOT-35 derives over`);
  }
});

test("`legacy:`, `migration:` and `service-decision:` records for one tag differ", () => {
  const repo = "teletemagame-dev/dice-roller";
  const tag = "v1.0.0";
  const ids = [
    decisionId(migrationKey({ repo, tag })),
    decisionId(legacyKey({ repo, tag })),
    decisionId(serviceDecisionKey({
      service_decision_id: SERVICE_DECISION, plugin_id: "dice-roller", version: "1.0.0", state: "yanked",
    })),
  ];
  assert.equal(new Set(ids).size, 3,
    "two domains derived one id for one release, so one of the two records would land on the other's path");
});

test("a key with no domain is refused — the mutation is dropping the prefix", () => {
  // Watched red by hand: `decisionId("teletemagame-dev/dice-roller@v1.0.0")`
  // without a prefix gives the SAME id for what would have been the migration
  // record and the legacy record of one release.
  assert.throws(() => decisionId("teletemagame-dev/dice-roller@v1.0.0"), /carries none of BOT-35's domains/);
  assert.throws(() => decisionId(`${SUBMISSION}`), /carries none of BOT-35's domains/);
  assert.equal(keyDomain("submission:"), null, "a domain with nothing after it names no decision");

  // And the floor, written before the mutation: four domains, not "some".
  assert.equal(KEY_DOMAINS.length, 4,
    `BOT-35 has four key domains and this module lists ${KEY_DOMAINS.length}; a fifth is a contract amendment ` +
    "(`legacy:` needed ops.22) and a fourth gone silently is two records sharing an id");
  assert.deepEqual([...KEY_DOMAINS].sort(), ["legacy", "migration", "service-decision", "submission"]);
});

test("a malformed id in a key is refused rather than hashed", () => {
  // A key derived over a bad id hashes perfectly well and yields a decision
  // nothing can ever look up. §0.7 is the grammar; this is where it is asked.
  assert.throws(() => submissionKey({ submission_id: "not-a-uuid" }), /lowercase UUID v4 or v7/);
  assert.throws(() => submissionKey({ submission_id: SUBMISSION.toUpperCase() }), /lowercase UUID v4 or v7/);
  assert.throws(() => migrationKey({ repo: "not a repo", tag: "v1.0.0" }), /is not an `owner\/name`/);
  assert.throws(() => migrationKey({ repo: "you/x", tag: "v1 0 0" }), /is not a release tag/);
  assert.throws(() => decisionKey("submissions", { submission_id: SUBMISSION }), /is not one of BOT-35's key domains/);
});

// ── the coupling that already exists on `main` ──────────────────────────────

test("all three spellings of BOT-35's `migration:` key agree", () => {
  // THE FINDING THIS SUITE EXISTS TO HOLD.
  //
  // `migration:<owner/name>@<tag>` is written out three times in this
  // repository: here, in `bot/export-issues.mjs` (over `fact.repository`) and
  // in `bot/baseline.mjs` (over `fact.repo`). Both of those were deliberate —
  // each file argues, correctly, that the collision check belongs beside the
  // facts it is checking — and both say in their own comments that the key is
  // "the domain B-T2.2 states". Nothing compared them until this line.
  //
  // What a drift would look like: `migration:you/x@v1` against
  // `migration:you/x@v1.0.0`, or a `/` that became a `:`. Two ids for one
  // baseline record, the second dispatch writing what the first already wrote,
  // and MIG-20's tree check counting records against versions and finding one
  // too many — reported as a defect in the check.
  const fact = { repo: "teletemagame-dev/dice-roller", repository: "teletemagame-dev/dice-roller", tag: "v1.0.0" };
  const mine = migrationKey(fact);
  assert.equal(exportIssuesMigrationKey(fact), mine,
    "bot/export-issues.mjs spells BOT-35's migration key differently from bot/lib/decisions.mjs");
  assert.equal(baselineMigrationKey(fact), mine,
    "bot/baseline.mjs spells BOT-35's migration key differently from bot/lib/decisions.mjs");
  assert.equal(mine, "migration:teletemagame-dev/dice-roller@v1.0.0");
});

test("no second derivation of a decision id is on the tree", () => {
  // A canary rather than a promise: "an id derived twice is an id that will
  // disagree", and the two composers this module replaced BOTH said in prose
  // that they must not derive one. Prose does not fail.
  //
  // The needle is the derivation's fingerprint — a sha256 truncated to 32 hex
  // — rather than the words `decision_id`, because a copy would be a copy of
  // the ARITHMETIC and could name its variable anything.
  //
  // **`git ls-files`, not a directory walk**, and the first version of this
  // was the walk. `fs.readdirSync(…, {recursive: true})` under `bot/` follows
  // `bot/manifest-probe/_deps/AstraPlugins`, which is a SYMLINK to another
  // repository: the scan read 136 files where the registry tracks 56, sixty of
  // them AstraPlugins'. It would have reported a finding in somebody else's
  // tree, under this repository's name, and the floor would have been set high
  // enough to hide the day the link went missing. Tracked files are the
  // population this rule is about.
  const files = execFileSync("git", ["ls-files", "-z", "--", "*.mjs"], { cwd: REPO_ROOT, encoding: "utf8" })
    .split("\0").filter(Boolean).filter((rel) => !rel.includes("/tests/"));
  assert.ok(files.length >= 100,
    `git ls-files reported ${files.length} non-test .mjs files and there were 130 on 2026-09-20; this is a ` +
    "broken enumeration, not a smaller repository, and a scan of nothing finds nothing and passes");
  const offenders = files.filter((rel) => {
    if (rel === "bot/lib/decisions.mjs") return false;
    const text = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
    return /createHash\(\s*["']sha256["']\s*\)[\s\S]{0,200}?slice\(\s*0\s*,\s*32\s*\)/.test(text);
  });
  assert.deepEqual(offenders, [],
    "a second truncation of a SHA-256 to 32 hex characters, which is what a decision id is. If it is not a " +
    "decision id, say so where it is written; if it is, it belongs in bot/lib/decisions.mjs");
});

// ── DEC-7's author-action record ────────────────────────────────────────────

test("an author-action record carries exactly DEC-7's thirteen members", () => {
  const root = tree();
  const [{ key, record }] = composeAuthorActions(YANK);
  const out = writeDecisionRecord({ key, record, root });
  const doc = read(root, out.path);

  assert.deepEqual(Object.keys(doc).sort(), [...AUTHOR_ACTION_MEMBERS].sort(),
    "DEC-7's sentence is `with only these members`, and the schema B-T2.1 writes will say so too");
  assert.equal(AUTHOR_ACTION_MEMBERS.length, 13,
    `DEC-7 enumerates thirteen author-action members and this module lists ${AUTHOR_ACTION_MEMBERS.length}`);

  assert.equal(doc.schema, RECORD_SCHEMA);
  assert.equal(doc.actor, "author");
  assert.equal(doc.trigger, "moderation");
  assert.equal(doc.state, "yanked");
  assert.equal(doc.category, "author_request");
  assert.deepEqual(doc.reasons, ["A_YANK"]);
  assert.equal(doc.version, "1.0.0");
  assert.match(doc.decision_id, /^[0-9a-f]{32}$/);

  for (const member of AUTHOR_ACTION_FORBIDDEN) {
    assert.equal(member in doc, false, `DEC-7: a yank has no \`${member}\``);
  }
});

test("adding `submission_id` to an author-action record is refused", () => {
  // The mutation B-T2.2's canary list names. It is the one a composer copied
  // from the submission path makes by default, and it is not cosmetic: the
  // service's detector B row 2 matches author-action records BY their having
  // no `submission_id`, so a record carrying one is a record it classifies as
  // something else entirely.
  const [{ key, record }] = composeAuthorActions(YANK);
  assert.throws(
    () => writeDecisionRecord({ key, record: { ...record, submission_id: SUBMISSION }, root: tree() }),
    /an author-action record carries no `submission_id`/,
  );
  assert.throws(
    () => writeDecisionRecord({ key, record: { ...record, fingerprint: "a".repeat(16) }, root: tree() }),
    /an author-action record carries no `fingerprint`/,
  );
});

test("an `A_YANK` naming three versions yields three records with three ids", () => {
  const root = tree();
  const composed = composeAuthorActions({ ...YANK, versions: ["1.0.0", "1.0.1", "2.0.0"] });
  assert.equal(composed.length, 3, "one record per version an `A_YANK` names (DEC-7; BOT-34)");

  const written = composed.map(({ key, record }) => writeDecisionRecord({ key, record, root }));
  assert.equal(new Set(written.map((w) => w.decision_id)).size, 3,
    "two of the three records share an id, so the commit carries fewer records than the versions it names — " +
    "which is exactly what BOT-34's CI refusal counts, and it would count the files, not the intent");
  assert.deepEqual(composed.map((c) => c.record.version), ["1.0.0", "1.0.1", "2.0.0"]);
  for (const c of composed) {
    assert.equal(typeof c.record.version, "string", "DEC-7's `version` is a single member");
  }
});

test("one record with a joined `version` is refused", () => {
  // The mutation: the shape a composer written against the submission record
  // produces, where one submission is one release. `1.0.0 1.0.1 2.0.0` is not
  // a semver, so the grammar catches it — and the grammar is there for exactly
  // this, not for typos.
  assert.throws(
    () => composeAuthorActions({ ...YANK, versions: ["1.0.0 1.0.1 2.0.0"] }),
    /`version` does not match its own grammar/,
  );
  assert.throws(() => composeAuthorActions({ ...YANK, versions: [] }), /names at least one listed version/);
  assert.throws(() => composeAuthorActions({ ...YANK, versions: ["1.0.0", "1.0.0"] }), /is named twice/);
});

test("a yank of a listing with no ids is refused, because FLOW-79 offers it none", () => {
  // Since contract 0.13.0 an unbound listing offers no yank at all — its
  // author asks a moderator (`M_YANK`, category `author_request`). So null ids
  // here are not "a listing we could not resolve": they are a listing M-T3.3
  // holds as `unbound_yank` and never applies. A record with holes in it would
  // be the registry stating a permanent fact it could not check.
  assert.throws(() => composeAuthorActions({ ...YANK, repository_id: null }),
    /`repository_id` does not match its own grammar/);
  assert.throws(() => composeAuthorActions({ ...YANK, repository_id: 912345678 }),
    /`repository_id` does not match its own grammar/);
});

test("the schema B-T2.1 writes", () => {
  // NOT a skip, and not a comment. B-T2.2's canary list asks that an
  // author-action record "validates against `schema/decision-v1.json`". That
  // file is B-T2.1's and is not in this checkout, so the assertion cannot be
  // written — and inventing the schema here would put a second, older answer
  // to DEC-7's shape in the tree on the day B-T2.1 writes the first.
  //
  // This line is what makes that a decision with an end rather than a gap:
  // the day the file lands, this goes RED and names the assertion to wire.
  const { present, file } = decisionSchema(REPO_ROOT);
  assert.equal(present, false,
    `${file} is now in this checkout (B-T2.1). Wire the assertion this line stands in for: validate the record ` +
    "`an author-action record carries exactly DEC-7's thirteen members` builds against it with " +
    "tools/lib/jsonschema.mjs's `validate`, assert it passes, then delete this test. Until then nothing in this " +
    "repository checks a decision record against a schema");
  assert.equal(file, DECISION_SCHEMA_FILE);
});

// ── BOT-37's trailers ───────────────────────────────────────────────────────

test("an `A_YANK` commit carries a `Service-Decision:` trailer", () => {
  const lines = renderTrailers({
    run: "35502265394", decision: decisionId(serviceDecisionKey({
      service_decision_id: SERVICE_DECISION, plugin_id: "dice-roller", version: "1.0.0", state: "yanked",
    })),
    service_decision: SERVICE_DECISION,
    authorAction: true,
  });
  assert.deepEqual(lines, [
    "Run: 35502265394",
    `Decision: ${decisionId(serviceDecisionKey({
      service_decision_id: SERVICE_DECISION, plugin_id: "dice-roller", version: "1.0.0", state: "yanked",
    }))}`,
    `Service-Decision: ${SERVICE_DECISION}`,
  ]);

  // Watched by dropping it — the break detector B row 2 would report, from the
  // far side of a party boundary, as "a decision record with no service
  // outcome". Nothing on this side would have gone red.
  assert.throws(
    () => renderTrailers({ run: "35502265394", authorAction: true }),
    /carrying an author-action record carries a `Service-Decision:` trailer/,
  );
});

test("every bot commit carries `Run:`, and the four trailers have a floor", () => {
  assert.throws(() => renderTrailers({}), /every bot commit carries a `Run:` trailer/);
  assert.equal(TRAILERS.length, 4,
    `BOT-37 names four trailers and this module renders ${TRAILERS.length}`);
  assert.deepEqual([...TRAILERS], ["Run", "Submission", "Decision", "Service-Decision"]);
  assert.deepEqual(renderTrailers({ run: "35502265394" }), ["Run: 35502265394"],
    "the three conditional trailers appear `where they exist` and not as empty lines");
});

test("trailers carry no login", () => {
  // Enforced by GRAMMAR, which is the only thing that can enforce it: a
  // trailer value is free text to git, and there is no value that is both a
  // login and a run id, a UUID or 32 hex.
  for (const bad of [
    { run: "mihailinl" },
    { run: "35502265394", submission: "teletemagame-dev" },
    { run: "35502265394", decision: "github-actions[bot]" },
    { run: "35502265394", service_decision: "@someone" },
  ]) {
    assert.throws(() => renderTrailers(bad), /is not §0\.7's/);
  }
});

// ── PRIV-2 over composed content ────────────────────────────────────────────

test("a valid `submission_id` passes, and the same UUID elsewhere is refused", () => {
  const roles = REPO_ROOT;
  const ok = privacyFindings({
    record: { schema: RECORD_SCHEMA, decision_id: "a".repeat(32), submission_id: SUBMISSION, state: "published" },
    root: roles,
  });
  assert.deepEqual(ok, [], "`submission_id` is exempt by member name (DEC-7 says it holds one)");

  const inRepo = privacyFindings({
    record: { schema: RECORD_SCHEMA, decision_id: "a".repeat(32), repo: `you/${SUBMISSION}`, state: "published" },
    root: roles,
  });
  assert.deepEqual(inRepo.map((f) => f.code), ["E_PRIV_UUID"],
    "the exemption is by member, not by value: the same id in `repo` is an id in a member that never holds one");

  const inTrailer = privacyFindings({
    record: { schema: RECORD_SCHEMA, decision_id: "a".repeat(32), state: "published" },
    trailers: { Decision: `${SUBMISSION}` },
    root: roles,
  });
  assert.ok(inTrailer.some((f) => f.code === "E_PRIV_UUID"),
    "`Decision:` carries 32 hex, so a UUID in it is a UUID somewhere it was not expected");

  // Watched by removing the exemption: with `submission_id` no longer
  // UUID-exempt, the first case above becomes a finding. Asserted from the
  // other direction, because the exemption table is `tools/priv-scan.mjs`'s
  // and this suite does not get to edit it.
  const exemptionMatters = privacyFindings({
    record: { schema: RECORD_SCHEMA, decision_id: "a".repeat(32), commit: SUBMISSION, state: "published" },
    root: roles,
  });
  assert.deepEqual(exemptionMatters.map((f) => f.code), ["E_PRIV_UUID"],
    "if this passes, the UUID rule is off and the exemption above was proving nothing");
});

test("an email is refused, and an undeclared member is refused whatever it holds", () => {
  const withEmail = privacyFindings({
    record: { schema: RECORD_SCHEMA, decision_id: "a".repeat(32), state: "refused", reasons: ["E_X"], moderator: "mod-1", advisory: "write to someone@gmail.com" },
    root: REPO_ROOT,
  });
  assert.ok(withEmail.some((f) => f.code === "E_PRIV_EMAIL"), "PRIV-2 keeps addresses out of git, permanently");

  const undeclared = privacyFindings({
    record: { schema: RECORD_SCHEMA, decision_id: "a".repeat(32), state: "refused", subject: "kXm2Qp7vLr9TnA4b" },
    root: REPO_ROOT,
  });
  assert.deepEqual(undeclared.map((f) => f.code), ["E_PRIV_UNDECLARED_MEMBER"],
    "the position rule is where a subject id lands: there is no declared member whose grammar it could pass");

  assert.throws(() => refusePrivate({
    record: { schema: RECORD_SCHEMA, decision_id: "a".repeat(32), state: "refused", subject: "kXm2Qp7vLr9TnA4b" },
    root: REPO_ROOT,
  }), /PRIV-2 refuses/);

  // The floor under the position rule: DEC-7 has twenty-five members, so a
  // table that lost most of them would refuse everything and read as strict.
  assert.ok(DECISION_MEMBERS.length >= 20,
    `the decision table lists ${DECISION_MEMBERS.length} members and DEC-7 enumerates 25; a shrunken table ` +
    "refuses valid records and a grown one admits members DEC-7 does not");
});

test("PRIV-2's subject-id shape, and the false positive that must stay green", () => {
  assert.equal(SUBJECT_ID_PATTERN, "^[A-Za-z0-9_-]{1,64}$",
    "minice-be's own `account_subject_shape`, cited at data-storage.md:545. Not MBE-PENDING");

  // Where the shape does work: a commit message has no members, so position
  // cannot reach it. `tools/priv-scan.mjs` says so in as many words and names
  // B-T2.2 as what catches it.
  assert.deepEqual(subjectIdFindings("kXm2Qp7vLr9TnA4bZ").map((f) => f.what), ["kXm2Qp7vLr9TnA4bZ"]);
  assert.throws(
    () => decisionCommitMessage({ subject: "yank", body: "kXm2Qp7vLr9TnA4bZ", run: "1" }),
    /lone token of PRIV-2's subject-id shape/,
  );

  // The false positive B-T2.2 names, kept green, and kept green for a reason
  // that is asserted rather than hoped for. An author README line is not a
  // document this module composes — and when such a line IS a lone long token
  // it is almost always a plugin id, which PRIV-2 permits as a coordinate.
  const readme = [
    "# minecraft-for-astra",
    "",
    "teletemagame-dev-minecraft-for-astra",
    "Install it with `astra plugin install minecraft-for-astra`.",
    "0.3.1",
    "a3f5c9e1b7d24680a3f5c9e1b7d24680",
  ].join("\n");
  assert.deepEqual(subjectIdFindings(readme), [],
    "the pattern is wide — 16 to 64 characters of that alphabet match plenty of things that are not subject ids " +
    "— and a canary that is red on a README line is a canary that gets switched off");
  assert.equal(permittedCoordinate("teletemagame-dev-minecraft-for-astra"), true);
  assert.equal(permittedCoordinate("kXm2Qp7vLr9TnA4bZ"), false);

  // And the arithmetic that keeps it switched on, re-run rather than recalled.
  // Every value of a valid author-action record matches the raw pattern; if
  // the rule were applied to members, the first correct record would be red.
  const [{ record }] = composeAuthorActions(YANK);
  const matching = Object.values({ ...record, reasons: record.reasons[0] })
    .filter((v) => typeof v === "string" && new RegExp(SUBJECT_ID_PATTERN).test(v));
  assert.ok(matching.length >= 5,
    `only ${matching.length} member value(s) of a valid record match the raw subject-id pattern; if this is low ` +
    "the record shape changed and the argument for the positional rule wants re-measuring");
});

// ── BOT-36: the write that is dropped ───────────────────────────────────────

test("a record carrying the same tuple is written once", () => {
  const root = tree();
  const [{ key, record }] = composeAuthorActions(YANK);
  const first = writeDecisionRecord({ key, record, root });
  assert.equal(first.written, true);

  const second = writeDecisionRecord({ key, record, root });
  assert.equal(second.written, false, "BOT-36: the commit job drops a write whose tuple is already on `main`");
  assert.match(second.dropped, /^BOT-36/);
  assert.equal(second.path, first.path);
});

test("the dedupe finds a record filed under another month", () => {
  // The case a dedupe that only stat'ed its own path would miss. `recordPath`
  // derives the directory from `decided_at`, and a retry after a rebase can
  // carry a different clock for the same tuple — which is the run BOT-36 is
  // about ("runs, and the two workflows, can race, and the push is the only
  // lock").
  const root = tree();
  const [{ key, record }] = composeAuthorActions(YANK);
  const id = decisionId(key);
  const elsewhere = `${DECISIONS_DIR}/2025/01/${id}.json`;
  fs.mkdirSync(path.join(root, path.dirname(elsewhere)), { recursive: true });
  fs.writeFileSync(path.join(root, elsewhere), "{}\n");

  const out = writeDecisionRecord({ key, record, root });
  assert.equal(out.written, false);
  assert.equal(out.path, elsewhere);
  assert.equal(recordsOnMain(root).length, 1, "and nothing was written beside it");
});

test("a BOT-19 terminal record stops the write, and the answer comes from the caller", () => {
  const root = tree();
  const [{ key, record }] = composeAuthorActions(YANK);
  const out = writeDecisionRecord({ key, record, root, terminal: { reported: "revoked" } });
  assert.equal(out.written, false);
  assert.match(out.dropped, /^BOT-19/);
  assert.deepEqual(recordsOnMain(root), [], "nothing was written");
});

test("a caller that supplies `schema` or `decision_id` has become a second composer", () => {
  const root = tree();
  const [{ key, record }] = composeAuthorActions(YANK);
  for (const member of ["schema", "decision_id"]) {
    assert.throws(
      () => writeDecisionRecord({ key, record: { ...record, [member]: "x" }, root }),
      /has become a second composer/,
      `a record arriving with its own \`${member}\` is a caller that has started deriving ids`,
    );
  }
});

test("the record's path is derived from `decided_at`, and a bad one is refused", () => {
  assert.equal(
    recordPath({ decision_id: "a".repeat(32), decided_at: "2026-09-20T11:22:33Z" }),
    `${DECISIONS_DIR}/2026/09/${"a".repeat(32)}.json`,
  );
  assert.throws(() => recordPath({ decision_id: "a".repeat(32), decided_at: "2026-09-20" }), /RFC 3339 UTC/);
  assert.throws(() => recordPath({ decision_id: "zz", decided_at: "2026-09-20T11:22:33Z" }), /lowercase hex/);
  assert.equal(DECISIONS_DIR, "log/decisions",
    "bot/baseline.mjs's `readDecisionRecords` walks this same path with its own spelling of it");
});

// ── the four callers ────────────────────────────────────────────────────────

test("`bot/export-issues.mjs`'s `resolveWriter` now resolves against this module", () => {
  // The refusal in that file is the specification: "`writeDecisionRecord({
  // key, record, root })`. If B-T2.2 named it something else, this line is the
  // only place that has to change." This asserts it did not have to.
  //
  // It is the one test here that executes a CALLER, and it is worth more than
  // any shape assertion in this file: three of the four callers refuse by name
  // against this module's absence, and a module that satisfied the name but
  // not the signature would leave all three still refusing at the first real
  // run rather than in CI.
  return resolveWriter({ root: path.join(HERE, "..") }).then((write) => {
    assert.equal(typeof write, "function");
    const root = tree();
    const [{ key, record }] = composeAuthorActions(YANK);
    const out = write({ key, record, root });
    assert.equal(typeof out.path, "string", "`--compose` prints `w.path`, so a writer returning nothing prints nothing");
    assert.ok(fs.existsSync(path.join(root, ...out.path.split("/"))));
  });
});

test("a migration record composed the way `bot/baseline.mjs` composes one is written", () => {
  // B-T3.7b's `write` job, end to end from this module's side: baseline's
  // `composeRecords` yields `{ key, record }` with no `schema` and no
  // `decision_id`, and its `RECORD_MEMBERS` allowlist is DEC-7's members with
  // a grammar each. Nothing here re-states that allowlist — that would be the
  // second composer — so this asserts the handover, not the shape.
  const root = tree();
  const record = {
    decided_at: "2026-01-04T09:00:00Z",
    actor: "system",
    trigger: "migration",
    plugin_id: "dice-roller",
    version: "1.0.0",
    repo: "teletemagame-dev/dice-roller",
    tag: "v1.0.0",
    commit: "b".repeat(40),
    fingerprint: "c".repeat(16),
    repository_id: "912345678",
    repository_owner_id: "45678901",
    state: "published",
  };
  const out = writeDecisionRecord({ key: migrationKey(record), record, root });
  assert.equal(out.written, true);
  const doc = read(root, out.path);
  assert.equal(doc.schema, RECORD_SCHEMA);
  assert.equal(doc.trigger, "migration");
  assert.equal(doc.decision_id, decisionId("migration:teletemagame-dev/dice-roller@v1.0.0"));

  // A facts file carrying a login is refused by B-T2.2 — B-T3.7b's own canary,
  // asserted from this side. `submitter` is not a member DEC-7 declares.
  assert.throws(
    () => writeDecisionRecord({ key: legacyKey(record), record: { ...record, submitter: "mihailinl" }, root }),
    /PRIV-2 refuses/,
  );
});

test("a legacy record and a migration record for one release do not overwrite each other", () => {
  // B-T3.7 writes `legacy` records for the same releases MIG-21's export wrote
  // `migration` records for. Same repository, same tag, two decisions, and the
  // only thing separating their files is the domain in front of the key.
  const root = tree();
  const base = {
    decided_at: "2026-02-01T00:00:00Z",
    actor: "system",
    plugin_id: "dice-roller",
    version: "1.0.0",
    repo: "teletemagame-dev/dice-roller",
    tag: "v1.0.0",
    state: "published",
  };
  const a = writeDecisionRecord({ key: migrationKey(base), record: { ...base, trigger: "migration" }, root });
  const b = writeDecisionRecord({ key: legacyKey(base), record: { ...base, trigger: "legacy" }, root });
  assert.equal(a.written, true);
  assert.equal(b.written, true);
  assert.notEqual(a.path, b.path);
  assert.equal(recordsOnMain(root).length, 2);
});

test("a commit message for a yank, whole", () => {
  const message = decisionCommitMessage({
    subject: "yank: three versions of dice-roller, at their author's request",
    body: "One author-action record per version named (DEC-7; FLOW-79). The reason is the registry string\n" +
      "SCOPE-7's token file lists for `A_YANK`, never the author's words (BOT-80; DEC-14).",
    run: "35502265394/1",
    service_decision: SERVICE_DECISION,
    authorAction: true,
  });
  assert.match(message, /^yank: three versions/);
  assert.match(message, /\nRun: 35502265394\/1\n/);
  assert.match(message, new RegExp(`\nService-Decision: ${SERVICE_DECISION}\n$`));
  assert.equal(message.endsWith("\n"), true);
});
