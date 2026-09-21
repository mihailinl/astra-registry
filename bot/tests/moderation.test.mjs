// The moderation log's schema, MOD-41's shared reason corpus, and MOD-47's
// round trip.
//
// ── WHY THIS SUITE EXISTS SEPARATELY FROM `bot/moderation.mjs --check` ──────
//
// `--check` asks whether the six entries on `main` are valid, which is worth
// asking on every push and answers almost nothing about the rules. Every rule
// this file asserts is about an entry that does NOT exist yet: the second
// same-day delist, the unrevoke that settles a revoke, the appeal that carries
// no category, the reason at 299 code points and 303 UTF-16 units. By the time
// one of those is written by hand at the moment of a takedown, the rule has to
// already be right — a moderation entry is written on the worst day of
// somebody's month and it is the worst possible moment to meet a refusal
// nobody had tested.
//
// ── THE CORPUS AND ITS TWO LEGS (attack M-11; ROLL-44) ──────────────────────
//
// `tests/moderation-reasons.json` is MOD-41's and MOD-48's shared vectors.
// This suite runs them against BOTH of this repository's validators — the
// moderation entry's `checkEntry` and the advisory's `checkAdvisory` — because
// the coupling `dev/couplings.md` registers is "bot validator vs service entry
// check", and the half this repository can hold is that its own two readings
// are one reading. The service's half is `plugins-testkit` vendoring the same
// file at a named registry commit; until that lands, this suite binds one leg
// and `tests/README.md` says so out loud rather than letting the green read as
// agreement with somebody who has never seen the file.
//
// The vectors that matter most are `unit-299-cp-303-units` and
// `unit-9-cp-12-units`. Both are accepted by a validator counting code points
// and refused-or-accepted the wrong way by one counting `String.length`, which
// is what this repository did until M-T1.6. Watched failing by putting
// `.length` back; see the commit message.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { execFileSync } from "node:child_process";

import {
  ACTIONS, BACKING, CATEGORIES, ENTRY_MEMBERS, ESCALATING_ACTIONS, OUTCOMES,
  REASON_CLASSES, REASON_FILE_SUFFIXES, REASON_MAX_CODE_POINTS, REASON_MIN_CODE_POINTS,
  SOURCE_DIR, buildModerationLog, checkEntry, codePointLength, cutoverAt, fileNameFor,
  loadEntries, reasonProblems,
} from "../lib/moderation.mjs";
import { checkAdvisory, buildRevocations } from "../../tools/lib/revocations.mjs";
import { DOCUMENT_MEMBERS } from "../../tools/priv-scan.mjs";
import { actionVocabulary, loadLog } from "../../tools/moderation-coverage.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const CORPUS_REL = "tests/moderation-reasons.json";
const corpus = JSON.parse(fs.readFileSync(path.join(REPO, CORPUS_REL), "utf8"));

// ── floors, written before the mutations they guard ─────────────────────────
//
// Every assertion below this line is a loop, and a loop over an empty array is
// green about nothing — a corpus is a set, so it needs a floor. These are the
// numbers on 2026-09-20, as a floor rather than an equality, because adding a
// vector is a legitimate act and this line is not the inventory.
const VECTOR_FLOOR = 30;
const ACCEPT_FLOOR = 10;
const REFUSE_FLOOR = 15;
// `bot/moderation/` held six entries on 2026-09-20, all six written
// retroactively under OPEN-OWNER-21.
const ENTRY_FLOOR = 6;

// ── fixtures ────────────────────────────────────────────────────────────────

const tmps = [];
function root() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-mod-"));
  tmps.push(dir);
  fs.mkdirSync(path.join(dir, SOURCE_DIR), { recursive: true });
  return dir;
}
process.on("exit", () => {
  for (const d of tmps) fs.rmSync(d, { recursive: true, force: true });
});

/** Write an entry at the name `fileNameFor` gives it, and return that name. */
function put(dir, doc, n = 1) {
  const name = fileNameFor(doc, n);
  fs.writeFileSync(path.join(dir, SOURCE_DIR, name), `${JSON.stringify(doc, null, 2)}\n`);
  return name;
}

function putAdvisory(dir, doc) {
  const at = path.join(dir, "tools", "revocations");
  fs.mkdirSync(at, { recursive: true });
  fs.writeFileSync(path.join(at, `${doc.id}.json`), `${JSON.stringify(doc, null, 2)}\n`);
}

const REASON = "A reason long enough to be a reason and short enough for a person to read.";
const DELIST = { date: "2026-09-20", action: "delist", plugin: "alpha", reason: REASON };
const ADVISORY = {
  id: "ASTRA-2026-0007",
  published: "2026-09-20",
  severity: "critical",
  action: "disable",
  reason: "It shipped a build that read the config directory and posted it elsewhere.",
  entries: [{ kind: "digest", value: "a".repeat(64) }, { kind: "id", value: "alpha" }],
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. The corpus itself
// ─────────────────────────────────────────────────────────────────────────────

test("the corpus has a floor in every direction it can go vacuous", () => {
  const accepted = corpus.vectors.filter((v) => v.verdict === "accept");
  const refused = corpus.vectors.filter((v) => v.verdict === "refuse");
  assert.ok(
    corpus.vectors.length >= VECTOR_FLOOR,
    `${CORPUS_REL} holds ${corpus.vectors.length} vector(s); there were ${VECTOR_FLOOR} on 2026-09-20. ` +
    "Every assertion in this file loops over that array, and a loop over a short one passes for the wrong reason",
  );
  assert.ok(accepted.length >= ACCEPT_FLOOR, `only ${accepted.length} accepted vector(s); the floor is ${ACCEPT_FLOOR}`);
  assert.ok(refused.length >= REFUSE_FLOOR, `only ${refused.length} refused vector(s); the floor is ${REFUSE_FLOOR}`);
  assert.equal(corpus.unit, "code_points", "the corpus must state its unit, and it is code points (M-11)");
  assert.deepEqual(
    corpus.bounds,
    { min_code_points: REASON_MIN_CODE_POINTS, max_code_points: REASON_MAX_CODE_POINTS },
    "the corpus and the validator must publish the same bounds",
  );
});

test("every refusal class has a vector, and every vector's class is declared", () => {
  const declared = corpus.classes.map((c) => c.name);
  assert.deepEqual(
    [...declared].sort(), [...REASON_CLASSES].sort(),
    `${CORPUS_REL}'s class list and REASON_CLASSES in bot/lib/moderation.mjs have parted. A class in one and ` +
    "not the other is a clause nobody can write a vector for, or a vector nobody can read",
  );
  const used = new Set(corpus.vectors.flatMap((v) => v.classes));
  const unexercised = REASON_CLASSES.filter((c) => !used.has(c));
  assert.deepEqual(
    unexercised, [],
    `${unexercised.length} refusal class(es) have no vector: ${unexercised.join(", ")}. An examined zero is not a ` +
    "clean bill of health: a clause with no vector is a clause that can be deleted without anything going red",
  );
  for (const v of corpus.vectors) {
    for (const c of v.classes) {
      assert.ok(REASON_CLASSES.includes(c), `${v.name} reports class ${c}, which is not in REASON_CLASSES`);
    }
  }
});

test("the corpus's own lengths are recomputed, never believed", () => {
  // A hand-counted vector is the one thing in this file that could quietly
  // stop being a statement about 299 and 303.
  for (const v of corpus.vectors) {
    if (typeof v.reason !== "string") {
      assert.equal(v.code_points, null, `${v.name} has no reason, so it can have no length`);
      continue;
    }
    const text = v.reason.trim();
    assert.equal(codePointLength(text), v.code_points, `${v.name}: code_points is wrong`);
    assert.equal(text.length, v.utf16_units, `${v.name}: utf16_units is wrong`);
    assert.equal(text, v.reason, `${v.name}: the vector carries leading or trailing whitespace, so the lengths it records are not the lengths the validator counts`);
  }
});

test("the two readings of \"characters\" actually differ in this corpus", () => {
  // The corpus's whole claim is that the unit matters. If no vector had
  // `code_points !== utf16_units`, every assertion about the unit below would
  // pass against a validator counting either one — green, and about nothing.
  const astral = corpus.vectors.filter((v) => typeof v.reason === "string" && v.code_points !== v.utf16_units);
  assert.ok(
    astral.length >= 4,
    `only ${astral.length} vector(s) distinguish code points from UTF-16 units; there were 5 on 2026-09-20. ` +
    "Without them this file cannot tell the two readings apart",
  );
  const overCeiling = astral.find((v) => v.verdict === "accept" && v.code_points === 299);
  assert.ok(overCeiling, "the corpus must carry a 299-code-point vector whose UTF-16 length is over 300 (attack M-11)");
  assert.ok(overCeiling.utf16_units > REASON_MAX_CODE_POINTS, `${overCeiling.name} is not over 300 UTF-16 units`);
  const underFloor = astral.find((v) => v.verdict === "refuse" && v.code_points === 9);
  assert.ok(underFloor, "the corpus must carry a 9-code-point vector whose UTF-16 length is over 10 (attack M-11)");
  assert.ok(underFloor.utf16_units >= REASON_MIN_CODE_POINTS, `${underFloor.name} is not over 10 UTF-16 units`);
});

test("the corpus's file-suffix list and the validator's are one list", () => {
  assert.deepEqual(
    [...corpus.file_suffixes].sort(), [...REASON_FILE_SUFFIXES].sort(),
    `${CORPUS_REL}'s file_suffixes and REASON_FILE_SUFFIXES have parted. The list is the one judgement call in ` +
    "the host-like rule, and a reader of the corpus who cannot see it is reading a rule with a hole in it",
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. The corpus against both validators
// ─────────────────────────────────────────────────────────────────────────────

test("every vector gets its recorded verdict from the moderation entry's validator", () => {
  for (const v of corpus.vectors) {
    const classes = reasonProblems(v.reason).map((p) => p.class);
    assert.deepEqual(
      classes, v.classes,
      `${v.name}: reasonProblems said [${classes.join(", ")}], the corpus records [${v.classes.join(", ")}]`,
    );
    const errs = checkEntry({ ...DELIST, reason: v.reason });
    const refused = errs.length > 0;
    assert.equal(
      refused, v.verdict === "refuse",
      `${v.name}: checkEntry ${refused ? "refused" : "accepted"} a vector the corpus records as ${v.verdict}` +
      (errs.length ? `\n        ${errs.join("\n        ")}` : ""),
    );
  }
});

test("and the same verdict from the advisory's validator, which is the point of the corpus", () => {
  // Two programs in two directories, one paragraph. `checkAdvisory` had its
  // own copy of "10 to 300 characters" until M-T1.6, and a copy is how one of
  // them ends up counting UTF-16 units while the other counts code points.
  for (const v of corpus.vectors) {
    const errs = checkAdvisory({ ...ADVISORY, reason: v.reason });
    const refused = errs.length > 0;
    assert.equal(
      refused, v.verdict === "refuse",
      `${v.name}: checkAdvisory ${refused ? "refused" : "accepted"} a vector the corpus records as ${v.verdict}` +
      (errs.length ? `\n        ${errs.join("\n        ")}` : ""),
    );
  }
});

test("MOD-41's names pass, which is the clause the rule is easiest to get wrong", () => {
  for (const name of ["plugin.toml", "astra-chess.json", "v1.2.3-rc.1"]) {
    assert.deepEqual(reasonProblems(name), [], `${name} must pass (MOD-41)`);
    assert.ok(
      corpus.vectors.some((v) => v.reason === name && v.verdict === "accept"),
      `${name} must be a vector in ${CORPUS_REL}, not only a line in this file`,
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. The six entries on `main`
// ─────────────────────────────────────────────────────────────────────────────

test("every entry on `main` is tracked, valid, and counted with git rather than readdir", () => {
  // `git ls-files`, not `readdir`: an untracked stray in a working tree would
  // pad a readdir count, and a `bot/moderation/` that a merge lost would empty
  // it. The floor's failure has to say which of the two happened.
  const tracked = execFileSync("git", ["-C", REPO, "ls-files", `${SOURCE_DIR}/*.json`], { encoding: "utf8" })
    .split("\n").filter(Boolean);
  assert.ok(
    tracked.length >= ENTRY_FLOOR,
    `git ls-files finds ${tracked.length} moderation entr(y|ies) and there were ${ENTRY_FLOOR} on 2026-09-20. ` +
    "This is a lost directory or a lost tracking, not a smaller log",
  );
  const { entries, errors } = loadEntries({ root: REPO });
  assert.deepEqual(errors, [], "the entries on `main` do not pass their own schema");
  assert.equal(entries.length, tracked.length, "loadEntries and git ls-files disagree about what is in the log");
  for (const e of entries) {
    assert.deepEqual(
      reasonProblems(e.reason), [],
      `a reason already published on \`main\` is refused by MOD-41's rules as this repository now writes them. ` +
      "Either the rule is wrong or a published transparency entry is; it is almost always the rule",
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. The schema: seven actions and six new fields
// ─────────────────────────────────────────────────────────────────────────────

test("MOD-47's three actions are there, and the escalating four are a named subset", () => {
  for (const a of ["relist", "unrevoke", "appeal"]) assert.ok(ACTIONS.includes(a), `ACTIONS is missing ${a} (MOD-47)`);
  for (const a of ESCALATING_ACTIONS) assert.ok(ACTIONS.includes(a), `${a} escalates and is not an action`);
  assert.ok(
    ESCALATING_ACTIONS.length < ACTIONS.length,
    "ESCALATING_ACTIONS exists so that a check about what an action COSTS is not applied to a relist",
  );
  // Every action has a row in the category table, in both directions. A new
  // action with no row would accept any category; a row with no action is a
  // category nobody can use.
  assert.deepEqual([...Object.keys(CATEGORIES)].sort(), [...ACTIONS].sort());
});

test("the member list is declared here and in priv-scan, and they are the same list", () => {
  // Two different questions about one list: this one is what the schema
  // permits, priv-scan's is what PRIV-2 has decided is safe to WALK. An
  // undeclared member there is skipped by the value scan entirely, so the two
  // agreeing is what makes "every member is checked" true.
  assert.deepEqual(
    [...ENTRY_MEMBERS].sort(), [...DOCUMENT_MEMBERS["moderation-entry"].members].sort(),
    "bot/lib/moderation.mjs's ENTRY_MEMBERS and tools/priv-scan.mjs's DOCUMENT_MEMBERS['moderation-entry'] have " +
    "parted. A member the schema accepts and the scan does not declare is a member whose value nothing reads",
  );
});

test("an entry still refuses what it always refused", () => {
  const ok = { ...DELIST };
  assert.deepEqual(checkEntry(ok), []);
  assert.ok(checkEntry({ ...ok, action: "nope" }).some((e) => /must be one of/.test(e)));
  assert.ok(checkEntry({ ...ok, plugin: "../x" }).some((e) => /not a plugin id/.test(e)));
  assert.ok(checkEntry({ ...ok, reason: "short" }).some((e) => /at least 10/.test(e)));
  assert.ok(checkEntry({ ...ok, whatever: 1 }).some((e) => /unknown field/.test(e)));
  assert.ok(checkEntry({ ...ok, action: "revoke" }).some((e) => /must name the advisory/.test(e)));
  assert.ok(checkEntry({ ...ok, advisory: "ASTRA-2026-0001" }).some((e) => /may not name an advisory/.test(e)));
});

test("an unrevoke names the advisory it deleted; a relist names none", () => {
  const un = { ...DELIST, action: "unrevoke", advisory: "ASTRA-2026-0007", reverses: "ASTRA-2026-0007" };
  assert.deepEqual(checkEntry(un), []);
  assert.ok(checkEntry({ ...un, advisory: undefined }).some((e) => /must name the advisory/.test(e)));
  const re = { ...DELIST, action: "relist", reverses: "3f2c1b8a-0d4e-4c7a-9b1f-2e5a6c8d0f13" };
  assert.deepEqual(checkEntry(re), []);
  assert.ok(checkEntry({ ...re, advisory: "ASTRA-2026-0007" }).some((e) => /may not name an advisory/.test(e)));
});

test("`reverses` is a service decision, or a hand advisory's id on an unrevoke alone", () => {
  const uuid = "3f2c1b8a-0d4e-4c7a-9b1f-2e5a6c8d0f13";
  assert.deepEqual(checkEntry({ ...DELIST, action: "relist", reverses: uuid }), []);
  // The hand advisory (D9's break-glass, committed under `Moderation-Exempt:`)
  // has no service decision behind it, so the advisory id is the only thing
  // there is to name — and only an unrevoke can meet one.
  assert.deepEqual(checkEntry({ ...DELIST, action: "unrevoke", advisory: "ASTRA-2026-0007", reverses: "ASTRA-2026-0007" }), []);
  assert.ok(checkEntry({ ...DELIST, action: "relist", reverses: "ASTRA-2026-0007" }).some((e) => /must be a service_decision_id/.test(e)));
  assert.ok(checkEntry({ ...DELIST, reverses: uuid }).some((e) => /reverses nothing/.test(e)));
  assert.ok(checkEntry({ ...DELIST, action: "relist", reverses: "3F2C1B8A-0D4E-4C7A-9B1F-2E5A6C8D0F13" })
    .some((e) => /must be a service_decision_id/.test(e)), "§0.7's UUID is lowercase");
});

test("an appeal carries appeal_of and an outcome, and carries no category", () => {
  const ap = {
    ...DELIST, action: "appeal", appeal_of: "3f2c1b8a-0d4e-4c7a-9b1f-2e5a6c8d0f13", outcome: "reversed",
  };
  assert.deepEqual(checkEntry(ap), []);
  // §0.7 gives an appeal two things it can be OF, and the contract does not say
  // which minter appears here, so both shapes are accepted.
  assert.deepEqual(checkEntry({ ...ap, appeal_of: "a".repeat(32) }), []);
  assert.ok(checkEntry({ ...ap, appeal_of: undefined }).some((e) => /must name what was appealed/.test(e)));
  assert.ok(checkEntry({ ...ap, outcome: undefined }).some((e) => /must carry its outcome/.test(e)));
  assert.ok(checkEntry({ ...ap, outcome: "pending" }).some((e) => /must be one of/.test(e)));
  assert.ok(checkEntry({ ...ap, category: "error" }).some((e) => /carries no category/.test(e)));
  assert.ok(checkEntry({ ...DELIST, outcome: "stands" }).some((e) => /not an appeal/.test(e)));
  assert.ok(checkEntry({ ...DELIST, appeal_of: "a".repeat(32) }).some((e) => /not an appeal/.test(e)));
  assert.deepEqual([...OUTCOMES].sort(), ["reversed", "stands"]);
});

test("§7.2's category table is enforced per action, not merely per spelling", () => {
  // FLOW-79's is the one the plan names: `author_request` on a yank.
  assert.deepEqual(checkEntry({ ...DELIST, action: "yank", category: "author_request" }), []);
  assert.deepEqual(checkEntry({ ...DELIST, category: "author_request" }), []);
  // …and the ones the table does NOT allow there.
  assert.ok(checkEntry({ ...DELIST, action: "yank", category: "naming" }).some((e) => /is not one a yank may carry/.test(e)));
  assert.ok(checkEntry({ ...DELIST, action: "yank", category: "error" }).some((e) => /is not one a yank may carry/.test(e)));
  assert.ok(checkEntry({ ...DELIST, category: "review_passed" }).some((e) => /is not one a delist may carry/.test(e)));
  // MOD-52's revert: `path_test` if the reverted decision had it, else `error`.
  assert.deepEqual(checkEntry({ ...DELIST, action: "relist", category: "path_test" }), []);
  assert.deepEqual(checkEntry({ ...DELIST, action: "unrevoke", advisory: "ASTRA-2026-0007", category: "error" }), []);
  // MOD-1's two, until MOD-16's bound is published.
  for (const c of ["malicious", "security_defect"]) {
    assert.deepEqual(checkEntry({ ...DELIST, action: "revoke", advisory: "ASTRA-2026-0007", category: c }), []);
  }
  assert.deepEqual(checkEntry({ ...DELIST, action: "deprecate", advisory: "ASTRA-2026-0007", category: "path_test" }), []);
});

test("declared_interest is a flag, because a string there would be a moderator's name", () => {
  assert.deepEqual(checkEntry({ ...DELIST, declared_interest: true }), []);
  assert.ok(checkEntry({ ...DELIST, declared_interest: "mod-2" }).some((e) => /is a flag/.test(e)));
  // And priv-scan permits no handle in any member of this document, which is
  // the other half of the same decision.
  assert.deepEqual(DOCUMENT_MEMBERS["moderation-entry"].handleOk, []);
});

test("service_decision_id is §0.7's UUID and nothing else", () => {
  assert.deepEqual(checkEntry({ ...DELIST, service_decision_id: "3f2c1b8a-0d4e-4c7a-9b1f-2e5a6c8d0f13" }), []);
  assert.ok(checkEntry({ ...DELIST, service_decision_id: "not-a-uuid" }).some((e) => /lowercase UUID/.test(e)));
  assert.ok(checkEntry({ ...DELIST, service_decision_id: "3f2c1b8a0d4e4c7a9b1f2e5a6c8d0f13" }).some((e) => /lowercase UUID/.test(e)));
  // And priv-scan has to be willing to see a UUID in that member and nowhere
  // else, or a valid entry is a privacy finding.
  assert.deepEqual(DOCUMENT_MEMBERS["moderation-entry"].uuidOk, ["service_decision_id"]);
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. The appeal URL and the cutover marker
// ─────────────────────────────────────────────────────────────────────────────

test("an appeal URL is accepted before cutover and refused after it", () => {
  const withUrl = { ...DELIST, appeal: "https://github.com/mihailinl/astra-registry/issues/42" };
  // No marker: cutover has not happened (ROLL-33), which is `main` today.
  assert.equal(cutoverAt(REPO), null);
  assert.deepEqual(checkEntry(withUrl), []);
  assert.deepEqual(checkEntry(withUrl, "<entry>", { cutoverAt: "2026-12-01T00:00:00Z" }), []);
  const after = checkEntry(withUrl, "<entry>", { cutoverAt: "2026-09-01T00:00:00Z" });
  assert.ok(
    after.some((e) => /closed at cutover/.test(e)),
    "an entry dated after cutover may not link to the public issue channel, which no longer exists",
  );
  // The day itself counts as after: the channel closes in the cutover commit.
  assert.ok(checkEntry(withUrl, "<entry>", { cutoverAt: "2026-09-20T00:00:00Z" }).some((e) => /closed at cutover/.test(e)));
  // Nothing about the URL's shape changed.
  assert.ok(checkEntry({ ...DELIST, appeal: "http://x.test/1" }).some((e) => /must be an https URL/.test(e)));
});

test("loadEntries reads the marker off the tree it was given", () => {
  const dir = root();
  put(dir, { ...DELIST, appeal: "https://example.test/appeals/1" });
  assert.deepEqual(loadEntries({ root: dir }).errors, []);
  fs.mkdirSync(path.join(dir, "log"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "log", "cutover.json"),
    JSON.stringify({ schema: "astra.registry.cutover/1", cutover_at: "2026-09-01T00:00:00Z" }),
  );
  assert.equal(cutoverAt(dir), "2026-09-01T00:00:00Z");
  assert.ok(loadEntries({ root: dir }).errors.some((e) => /closed at cutover/.test(e)));
  // An unreadable marker is not "after cutover". Guessing there would make an
  // appeal link vanish from the log because a comma was misplaced elsewhere.
  fs.writeFileSync(path.join(dir, "log", "cutover.json"), "{oops");
  assert.equal(cutoverAt(dir), null);
  assert.deepEqual(loadEntries({ root: dir }).errors, []);
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. MOD-47's names
// ─────────────────────────────────────────────────────────────────────────────

test("two same-day entries for one plugin and action, and the log build reads both", () => {
  const dir = root();
  const a = put(dir, DELIST, 1);
  const b = put(dir, { ...DELIST, reason: "A second delist the same day, for a second reason entirely." }, 2);
  assert.equal(a, "2026-09-20-alpha-delist.json", "the first entry keeps the name it has always had");
  assert.equal(b, "2026-09-20-alpha-delist-2.json", "and the second takes MOD-47's suffix");
  const { entries, errors, files } = loadEntries({ root: dir });
  assert.deepEqual(errors, []);
  assert.equal(entries.length, 2, "the log build reads both forms");
  assert.deepEqual([...files].sort(), [a, b].sort());
  const log = buildModerationLog({ root: dir });
  assert.equal(log.entries.length, 2);
  assert.ok(log.$comment.includes("[-<n>]"), "the generated banner must name the form a reader will see");
});

test("a suffix with no predecessor is refused, and so is a name nothing produces", () => {
  // The gap matters because the next writer computes its `n` from the count: a
  // `-3` beside a `-1` makes the next entry `-3` again, and that one silently
  // overwrites somebody's takedown record.
  const dir = root();
  put(dir, DELIST, 1);
  put(dir, { ...DELIST, reason: "A third delist whose second was deleted by hand." }, 3);
  const errs = loadEntries({ root: dir }).errors;
  assert.ok(errs.some((e) => /numbers them from 1 with no gaps/.test(e)), errs.join("; "));

  // `-0`, `-02` and a name nothing produces are all refused by the same
  // rebuild-and-compare, so there is no second spelling of `n` in which two
  // files can claim the same place.
  for (const name of ["2026-09-20-alpha-delist-0.json", "2026-09-20-alpha-delist-02.json", "something-else.json"]) {
    const one = root();
    fs.writeFileSync(path.join(one, SOURCE_DIR, name), JSON.stringify(DELIST));
    assert.ok(
      loadEntries({ root: one }).errors.some((e) => /the file name must be/.test(e)),
      `${name} was accepted as a moderation entry's name`,
    );
  }
});

test("the coverage canary reads both forms, and reads them in write order", () => {
  // `-` sorts before `.`, so a plain name sort puts `…-delist-2.json` ahead of
  // `…-delist.json`. Every rule in `tools/moderation-coverage.mjs` that asks
  // "what happened LAST to this plugin" reads a same-day run backwards then,
  // and it reads it backwards silently.
  const dir = root();
  put(dir, DELIST, 1);
  put(dir, { ...DELIST, reason: "The second delist of the day, for a second reason entirely." }, 2);
  put(dir, { ...DELIST, reason: "The tenth, because ten is where a string sort of numbers goes wrong." }, 10);
  const { entries, bad } = loadLog(dir);
  assert.deepEqual(bad, []);
  assert.deepEqual(
    entries.map((e) => e.name),
    ["2026-09-20-alpha-delist.json", "2026-09-20-alpha-delist-2.json", "2026-09-20-alpha-delist-10.json"],
    "the canary must read MOD-47's entries in the order they were written",
  );
});

test("the action names the coverage canary matches on are names ACTIONS has", () => {
  // Three literals in that file decide what it can see. Renaming one leaves
  // every relist unfound, which is quiet: the canary goes red about plugins
  // that are fine, and a canary red for a reason nobody can find is a canary
  // somebody switches off.
  assert.deepEqual(
    actionVocabulary(), [],
    "tools/moderation-coverage.mjs matches on an action name that bot/lib/moderation.mjs no longer has",
  );
  assert.deepEqual(actionVocabulary(["yank", "delist"]), ["relist"], "and the check itself has to be able to fail");
});

test("fileNameFor is the one place a name is spelled", () => {
  assert.equal(fileNameFor(DELIST), "2026-09-20-alpha-delist.json");
  assert.equal(fileNameFor(DELIST, 1), "2026-09-20-alpha-delist.json");
  assert.equal(fileNameFor(DELIST, 2), "2026-09-20-alpha-delist-2.json");
  assert.equal(fileNameFor(DELIST, 11), "2026-09-20-alpha-delist-11.json");
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. MOD-47's round trip: revoke → log build → unrevoke → log build
// ─────────────────────────────────────────────────────────────────────────────
//
// The signing half of the round trip is ROLL-1's recorded walk with real keys,
// not this suite's — what a signature adds is a statement about `tools/sign-*`,
// which `tools/selftest/signer*.mjs` already holds. What MOD-47 asks HERE is
// that the backing check survives the reversal, and that is a statement about
// two log builds and the document between them.

test("a revoke is backed by its advisory, and stops being a throw once it is unrevoked", () => {
  const dir = root();
  const revoke = { date: "2026-09-20", action: "revoke", plugin: "alpha", advisory: ADVISORY.id, reason: REASON };
  put(dir, revoke);
  putAdvisory(dir, ADVISORY);

  // Leg one: the advisory is in the list the log is checked against.
  const list = buildRevocations({ root: dir, serial: 1 });
  const backed = buildModerationLog({ root: dir, revocations: list.signed.revocations, revocationsSerial: 1 });
  assert.equal(backed.entries.find((e) => e.action === "revoke").backed, true);

  // The advisory goes and nothing else changes: the build must refuse, because
  // this is exactly the state a transparency log may not be in — claiming a
  // signed effect nobody signed.
  fs.rmSync(path.join(dir, "tools", "revocations", `${ADVISORY.id}.json`));
  const empty = buildRevocations({ root: dir, serial: 2 });
  assert.throws(
    () => buildModerationLog({ root: dir, revocations: empty.signed.revocations }),
    /does not contain that advisory/,
  );

  // Leg two: the unrevoke that explains the absence. Now it is SETTLED — the
  // entry is right, the advisory is gone on purpose, and the build emits.
  put(dir, {
    date: "2026-09-21", action: "unrevoke", plugin: "alpha", advisory: ADVISORY.id,
    reverses: ADVISORY.id, category: "error",
    reason: "The advisory named the wrong bundle digest; the withdrawal is lifted and the listing stands.",
  });
  const settled = buildModerationLog({ root: dir, revocations: empty.signed.revocations, revocationsSerial: 2 });
  assert.equal(settled.entries.find((e) => e.action === "revoke").backed, "settled");
  assert.equal(settled.entries.find((e) => e.action === "unrevoke").backed, false);
  assert.equal(settled.entries[0].action, "unrevoke", "newest first: the reversal is the top of the page");
});

test("an unrevoke settles only the advisory it names", () => {
  const dir = root();
  put(dir, { date: "2026-09-20", action: "revoke", plugin: "alpha", advisory: "ASTRA-2026-0007", reason: REASON });
  put(dir, {
    date: "2026-09-21", action: "unrevoke", plugin: "beta", advisory: "ASTRA-2026-0008",
    reason: "A different advisory entirely, lifted for a different listing after review.",
  });
  assert.throws(() => buildModerationLog({ root: dir, revocations: [] }), /does not contain that advisory/);
});

test("the backing check still catches an entry calling an advisory the wrong action", () => {
  const dir = root();
  put(dir, { date: "2026-09-20", action: "deprecate", plugin: "alpha", advisory: ADVISORY.id, reason: REASON });
  putAdvisory(dir, ADVISORY); // action `disable`, which is a revoke
  const list = buildRevocations({ root: dir, serial: 1 });
  assert.throws(
    () => buildModerationLog({ root: dir, revocations: list.signed.revocations }),
    /carries action "disable"/,
  );
  assert.deepEqual(BACKING.deprecate, ["warn"]);
  assert.deepEqual(BACKING.revoke, ["block_install", "disable"]);
  assert.ok(!("unrevoke" in BACKING), "an unrevoke names an advisory that is gone on purpose; it is never backed");
});
