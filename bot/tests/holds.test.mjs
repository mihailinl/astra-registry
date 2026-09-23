#!/usr/bin/env node
// `bot/lib/holds.mjs`: the decisions the bot was told to make and has decided
// not to make yet. `node bot/tests/holds.test.mjs`. No network, no fixtures on
// disk except the temp directories two tests build and remove.
//
// Registry plan M-T3.3. The module is DARK at R2 exit — `bot/moderation-run.mjs`
// (M-T3.4) is the first caller — so this suite is the only thing executing it,
// and it is written accordingly: it asserts the RELEASE RULES rather than the
// shapes, because a hold that releases one hour early, or on the wrong record,
// is the failure, and a hold whose JSON is malformed is caught by the schema.
//
// Each negative case below names the real defect it stands for. The mutations
// they were watched failing on are in the commit message, message by message.
//
// ── WHAT THIS SUITE CANNOT SEE ──────────────────────────────────────────────
//
// TRUST-26's bound is M-T3.2's, not this module's: `holdKindFor` takes
// `overBound` as a BOOLEAN and believes it. So the three-`A_YANK`s case below
// (OPEN-OWNER-45, «Оставить как есть», 2026-09-17) asserts what this side does
// with the answer — the next `block_install` is held — and asserts nothing
// about the counting that produced it. When M-T3.2's counter lands, the pair
// wants one test that runs the real count into this function; it cannot be
// written from here without importing a module that does not exist yet.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  AUTHOR_CODES,
  AUTHOR_FORBIDDEN_MEMBERS,
  HOLDS_DIR,
  HOLD_KINDS,
  HOLD_PERIOD_HOURS,
  RECORD_SCHEMA,
  REVERSAL_CODES,
  SCHEMA,
  checkHoldEntry,
  checkHoldRecord,
  classifyHoldCommit,
  holdEntry,
  holdKindFor,
  holdRecordSchema,
  holdSchema,
  isTakedown,
  readHolds,
  recordFile,
  releaseAfter,
  resolveHold,
  resultKey,
  resultsToPost,
} from "../lib/holds.mjs";
// The members ops entry 101 added, read off the namespace: this suite then runs
// against a module that lacks them and is red test by test, not at import.
import * as holdsModule from "../lib/holds.mjs";

const REPO_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

let passed = 0;
const failures = [];
function section(name) { console.log(`\n${name}`); }
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures.push(name);
    console.log(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
  }
}
function assert(cond, message) { if (!cond) throw new Error(message); }
function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}\n  expected: ${expected}\n  actual:   ${actual}`);
}

// ── fixtures ────────────────────────────────────────────────────────────────

const DECIDED_AT = "2026-09-18T09:00:00Z";
const HELD_AT = "2026-09-18T09:05:00Z";
/** `HELD_AT` + 24 h is 2026-09-19T09:05:00Z. One hour either side of it. */
const BEFORE = new Date("2026-09-19T08:05:00Z");
const AFTER = new Date("2026-09-19T10:05:00Z");

/**
 * TRUST-26's bound, as a LOCAL fixture constant. M-T3.2 owns the real one and
 * the counting; this suite only needs a number to fill, so that the three
 * `A_YANK`s below are three of something rather than three of nothing.
 */
const FIXTURE_BOUND = 3;

const moderatorDecision = (over = {}) => ({
  service_decision_id: "sd-relist-1",
  code: "M_RELIST",
  category: "appeal",
  plugin_id: "astra-chess",
  versions: ["1.2.0"],
  decided_at: DECIDED_AT,
  reason: "the appeal succeeded and the listing is restored",
  reverses: "sd-delist-9",
  moderator: "mod-a",
  declared_interest: false,
  ...over,
});

/** An `A_*` decision: no `moderator`, no `declared_interest` (DEC-14, MOD-41, n4). */
const authorDecision = (over = {}) => ({
  service_decision_id: "sd-yank-1",
  code: "A_YANK",
  category: "author_request",
  plugin_id: "astra-chess",
  versions: ["1.2.0"],
  decided_at: DECIDED_AT,
  reason: "the author withdrew this version from the catalogue",
  ...over,
});

const record = (act, id, over = {}) => ({
  schema: RECORD_SCHEMA,
  act,
  service_decision_id: id,
  plugin_id: "astra-chess",
  at: "2026-09-19T10:00:00Z",
  actor: "operator-a",
  ...over,
});

/** One element of `readHolds`, built without touching a disk. */
function heldHold(decision, held_for, { confirm = null, cancel = null, held_at = HELD_AT } = {}) {
  const entry = holdEntry(decision, { held_for, held_at });
  return { id: decision.service_decision_id, file: "", entry, confirm, cancel, problems: [] };
}

function tmpTree() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "astra-holds-"));
  fs.mkdirSync(path.join(root, HOLDS_DIR), { recursive: true });
  return {
    root,
    write(rel, doc) {
      fs.writeFileSync(path.join(root, rel), `${JSON.stringify(doc, null, 2)}\n`);
    },
    writeRaw(rel, text) { fs.writeFileSync(path.join(root, rel), text); },
    done() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
section("the five kinds, and the two files that have to agree about them");
// ─────────────────────────────────────────────────────────────────────────────

// A kind in the code and not in the schema is a hold nothing can write; a kind
// in the schema and not in the code is a hold nothing knows how to end, and
// `resolveHold` answers it `unknown hold kind` and waits — for ever, silently,
// which is the worse of the two directions. Both are asserted, and the floor is
// written here rather than derived, because two empty sets agree.
await test("HOLD_KINDS and schema/hold-v1.json's held_for enum are the same five", () => {
  const enumerated = holdSchema().properties.held_for.enum;
  assertEqual(enumerated.length, 5,
    `schema/hold-v1.json states ${enumerated.length} hold kinds and there were 5 on 2026-09-19; ` +
    `if a kind was added, add it to HOLD_KINDS and give it a branch in resolveHold`);
  assertEqual(HOLD_KINDS.length, 5, "bot/lib/holds.mjs states a number of kinds other than five");
  const inCodeOnly = HOLD_KINDS.filter((k) => !enumerated.includes(k));
  const inSchemaOnly = enumerated.filter((k) => !HOLD_KINDS.includes(k));
  assertEqual(inCodeOnly.join(", "), "",
    "bot/lib/holds.mjs knows a hold kind schema/hold-v1.json will not let anyone write");
  assertEqual(inSchemaOnly.join(", "), "",
    "schema/hold-v1.json admits a hold kind bot/lib/holds.mjs has no release rule for, and resolveHold " +
    "waits on an unknown kind for ever");
});

// The one thing the record schema must NOT admit. BOT-32's 0.12.0 note: a
// TRUST-42 acknowledgement at the service is not an operator's confirmation and
// must never release a hold. A closed enum of two is what makes admitting one a
// schema change and a code change rather than a value somebody writes in a file.
await test("a hold record can only confirm or cancel — there is no acknowledgement act", () => {
  const acts = holdRecordSchema().properties.act.enum;
  assertEqual(acts.slice().sort().join(","), "cancel,confirm",
    `schema/hold-record-v1.json admits the acts ${acts.join(", ")}; a third one is how a TRUST-42 ` +
    `acknowledgement at the service becomes a release here, which BOT-32 forbids`);
});

// The allowlist `holdEntry` copies through is read out of the schema, so this
// compares the schema against itself unless the derivation is wrong — which is
// exactly the failure worth catching, since the derivation is one `filter`.
// `EVERY_MEMBER` is deliberately a decision no wire would ever carry — an
// `M_REVOKE` that also `reverses` something. It exists to exercise the COPY,
// not the contract: which members BOT-80 names together is M-T3.4's schema to
// say, and this asserts only that none of them is dropped on the way into a
// hold entry, since the entry is all a later run gets.
await test("the members holdEntry copies are the members the schema names, in both directions", () => {
  const named = Object.keys(holdSchema().properties.decision.properties).filter((k) => k !== "$comment");
  assert(named.length >= 10,
    `schema/hold-v1.json names ${named.length} decision members and named 12 on 2026-09-19; this is a ` +
    `truncated schema rather than a smaller contract, and every comparison below it would pass`);
  const EVERY_MEMBER = {
    service_decision_id: "sd-revoke-1",
    code: "M_REVOKE",
    category: "malware",
    plugin_id: "astra-chess",
    versions: ["1.2.0", "1.2.1"],
    decided_at: DECIDED_AT,
    reverses: "sd-unrevoke-4",
    reason: "the bundle ships a keylogger and the estate is disabled",
    severity: "high",
    action: "disable",
    moderator: "mod-a",
    declared_interest: false,
  };
  assertEqual(Object.keys(EVERY_MEMBER).slice().sort().join(","), named.slice().sort().join(","),
    "the fixture and schema/hold-v1.json no longer name the same decision members, so this test is " +
    "comparing the copy against less than the schema admits");
  const entry = holdEntry(EVERY_MEMBER, { held_for: "disable_confirmation", held_at: HELD_AT });
  const dropped = named.filter((m) => !Object.hasOwn(entry.decision, m));
  assertEqual(dropped.join(", "), "",
    "holdEntry drops a member schema/hold-v1.json names, so a hold entry carries less than the release " +
    "that reads it back needs — and the release runs in a later run, with nothing to re-fetch from");
});

// ─────────────────────────────────────────────────────────────────────────────
section("what MOD-9 holds, and what it lets through");
// ─────────────────────────────────────────────────────────────────────────────

await test("every reversal is held, at or under the bound and over it", () => {
  for (const code of REVERSAL_CODES) {
    for (const overBound of [false, true]) {
      assertEqual(holdKindFor(moderatorDecision({ code }), { overBound }), "reversal",
        `a ${code} is not held as a reversal (overBound ${overBound})`);
    }
  }
  assertEqual(REVERSAL_CODES.length, 2, "there are two codes that give something back, and this list has moved");
});

await test("a reversal is never held for the bound, so a full bound cannot stall an un-breaking", () => {
  for (const code of REVERSAL_CODES) {
    assert(!isTakedown(moderatorDecision({ code })),
      `${code} counts as a takedown, so a full takedown bound would hold the thing that undoes a takedown`);
  }
});

await test("an M_REVOKE with action disable is held from the first commit, with no flag and no bound", () => {
  const d = moderatorDecision({ service_decision_id: "sd-revoke-1", code: "M_REVOKE", action: "disable", severity: "high" });
  assertEqual(holdKindFor(d, { overBound: false }), "disable_confirmation",
    "a disable under the bound is not held, so software already running on somebody's machine stops " +
    "without a second person having seen the decision (OPEN-OWNER-14)");
  assertEqual(holdKindFor(d, { overBound: true }), "disable_confirmation",
    "a disable over the bound is recorded as a bound hold, so the bound rising would release it");
});

await test("block_install applies at once under the bound and is held over it", () => {
  const d = moderatorDecision({ service_decision_id: "sd-revoke-2", code: "M_REVOKE", action: "block_install", severity: "high" });
  assertEqual(holdKindFor(d, { overBound: false }), null,
    "a block_install under the bound is held, and OPEN-OWNER-14 lets a moderator stop the spread at once");
  assertEqual(holdKindFor(d, { overBound: true }), "bound",
    "a block_install over the bound is applied, so a compromised service can block installs catalogue-wide " +
    "until a MOD-52 revert — the exemption the owner was shown and rejected on 2026-09-17");
});

// OPEN-OWNER-45's case, walked rather than left to be discovered. He was shown
// it and kept the rule: author actions count toward TRUST-26's bound, so three
// of them fill it and the next moderator action waits on an operator. The
// correction that rides with it (C16) is that FLOW-42's cap means three
// DISTINCT accounts, not one author tidying up — the count is M-T3.2's, and
// only the consequence is asserted here.
await test("three A_YANKs fill the bound and the next block_install is held (OPEN-OWNER-45)", () => {
  const yanks = [1, 2, 3].map((n) => authorDecision({
    service_decision_id: `sd-yank-${n}`,
    plugin_id: `astra-plugin-${n}`,
  }));
  assertEqual(yanks.length, FIXTURE_BOUND, "the fixture no longer fills the bound it says it fills");
  for (const y of yanks) {
    assertEqual(holdKindFor(y, { overBound: false, listingBound: true }), null,
      `${y.service_decision_id} was held under the bound, so it never counted toward filling it`);
    assert(isTakedown(y), `${y.service_decision_id} does not count as a takedown, so it fills no bound`);
  }
  const blockInstall = moderatorDecision({
    service_decision_id: "sd-revoke-3", code: "M_REVOKE", action: "block_install", severity: "high",
  });
  assertEqual(holdKindFor(blockInstall, { overBound: true }), "bound",
    "with the bound filled by three author yanks, a moderator's block_install was applied at once; " +
    "MOD-9 holds it, and this is the case the owner kept on 2026-09-17");
});

await test("an unbound A_YANK and an unbound removal request get their own kinds", () => {
  assertEqual(holdKindFor(authorDecision(), { listingBound: false }), "unbound_yank",
    "an A_YANK for a listing with no identity record is not held under its own kind, so a confirmation " +
    "or a delist could apply a yank the service should never have sent (FLOW-79)");
  assertEqual(holdKindFor(authorDecision({ service_decision_id: "sd-rr-1", code: "A_REMOVAL_REQUEST" }), { listingBound: false }), "unbound_removal",
    "an A_REMOVAL_REQUEST for an unbound listing is not held");
  assertEqual(holdKindFor(authorDecision(), { listingBound: true }), null,
    "a bound listing's A_YANK is held, and FLOW-79 lets the bound account yank");
});

await test("an unbound A_YANK stays unbound_yank even when the bound is also full", () => {
  assertEqual(holdKindFor(authorDecision(), { listingBound: false, overBound: true }), "unbound_yank",
    "an unbound A_YANK over the bound was recorded as a bound hold, and a bound hold releases on a " +
    "confirmation — so the bound rising, or an operator confirming, would apply it");
});

// ─────────────────────────────────────────────────────────────────────────────
section("the 24-hour period, and the record that ends it");
// ─────────────────────────────────────────────────────────────────────────────

await test("a reversal waits out the period, and a confirm inside it does not shorten it", () => {
  assertEqual(HOLD_PERIOD_HOURS, 24, "OPEN-OWNER-4 closed at 24 hours on 2026-09-17");
  const confirm = record("confirm", "sd-relist-1");
  // Landed in the same second it was held, so the period ends at release_after
  // and the reason can be asked for that instant. When the commit lands later,
  // it ends later: the next section.
  const landed = { sha: "c".repeat(40), at: HELD_AT };
  const before = resolveHold(heldHold(moderatorDecision(), "reversal", { confirm }), { now: BEFORE, shadow: false, landed });
  assertEqual(before.act, "wait",
    "a confirmed reversal released before its 24 hours were up, so the period an operator has to object " +
    "to it is whatever the operator's own reflexes are");
  assert(before.reason.includes("2026-09-19T09:05:00Z"), `the wait does not say when it ends: ${before.reason}`);
});

await test("the period passing is not a release: a reversal still needs the record", () => {
  const after = resolveHold(heldHold(moderatorDecision(), "reversal"), { now: AFTER, shadow: false });
  assertEqual(after.act, "wait",
    "a reversal released itself once its period had passed, with nobody having confirmed it");
  assert(after.reason.includes("no operator has confirmed"), `the wait names the wrong reason: ${after.reason}`);
});

await test("period plus confirm releases, and the release is applied", () => {
  const r = resolveHold(
    heldHold(moderatorDecision(), "reversal", { confirm: record("confirm", "sd-relist-1") }),
    { now: AFTER, shadow: false },
  );
  assertEqual(r.act, "release", `a confirmed reversal past its period did not release: ${r.reason}`);
  assertEqual(r.result, "applied", "a released reversal posts something other than applied");
});

await test("a confirm for another decision is ignored, and is not an error either", () => {
  const r = resolveHold(
    heldHold(moderatorDecision(), "reversal", { confirm: record("confirm", "sd-relist-2") }),
    { now: AFTER, shadow: false },
  );
  assertEqual(r.act, "wait",
    "a confirmation naming another decision released this one; matching on the plugin instead of the id " +
    "is what that mutation looks like, and one confirmation then releases every hold against the listing");
  assert(r.reason.includes("sd-relist-2"), `the wait does not name the record it refused: ${r.reason}`);
});

await test("a bound hold and a disable release on the confirmation alone, with no period", () => {
  for (const [held_for, decision] of [
    ["bound", moderatorDecision({ service_decision_id: "sd-revoke-3", code: "M_REVOKE", action: "block_install", severity: "high" })],
    ["disable_confirmation", moderatorDecision({ service_decision_id: "sd-revoke-1", code: "M_REVOKE", action: "disable", severity: "high" })],
  ]) {
    const id = decision.service_decision_id;
    const waiting = resolveHold(heldHold(decision, held_for), { now: BEFORE, shadow: false });
    assertEqual(waiting.act, "wait", `an unconfirmed ${held_for} hold released`);
    const released = resolveHold(
      heldHold(decision, held_for, { confirm: record("confirm", id) }),
      { now: BEFORE, shadow: false },
    );
    assertEqual(released.act, "release",
      `a confirmed ${held_for} hold waited: ${released.reason}. These two release AT ONCE — the period is ` +
      `the operator's window to object, and these are already waiting on that operator`);
    assertEqual(released.result, "applied", `a released ${held_for} hold posts something other than applied`);
  }
});

await test("a disable never releases without a confirm record, at any time", () => {
  const d = moderatorDecision({ service_decision_id: "sd-revoke-1", code: "M_REVOKE", action: "disable", severity: "high" });
  for (const now of [BEFORE, AFTER, new Date("2027-01-01T00:00:00Z")]) {
    const r = resolveHold(heldHold(d, "disable_confirmation"), { now, shadow: false });
    assertEqual(r.act, "wait",
      `a disable released at ${now.toISOString()} with no operator's confirmation; it is the one action ` +
      `that stops software already running on somebody's machine (OPEN-OWNER-14)`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
section("the 24 hours run from the commit that added the entry (MOD-9; ops entry 101)");
// ─────────────────────────────────────────────────────────────────────────────
//
// MOD-9: released only "after a 24 h hold period (OPEN-OWNER-4) has run from
// that commit" — the commit that adds `state/holds/<id>.json`. `held_at` is
// the commit job's clock at the compile, and that commit lands after the gates
// and the push. Until ops entry 101 closed the period ran from `held_at`, so a
// hold compiled at T and committed at T + 15 min was due at T + 24 h: fifteen
// minutes before MOD-9 lets it be. `bot/tests/moderation-run.test.mjs` proves
// the same through the job, the workflow's commit step and real history.

const plusMinutes = (iso, minutes) => new Date(Date.parse(iso) + minutes * 60_000);
const SHA = "c".repeat(40);

await test("a reversal's 24 hours run from the commit that added the entry, not from held_at", () => {
  const confirm = record("confirm", "sd-relist-1");
  const hold = heldHold(moderatorDecision(), "reversal", { confirm });
  // Compiled at HELD_AT, committed fifteen minutes later.
  const landed = { sha: SHA, at: plusMinutes(HELD_AT, 15).toISOString().replace(/\.\d{3}Z$/, "Z") };

  const early = resolveHold(hold, { now: plusMinutes(HELD_AT, 24 * 60 + 1), shadow: false, landed });
  assertEqual(early.act, "wait",
    "a confirmed reversal released 24 h and 1 min after held_at, 14 minutes before 24 hours had run from the " +
    "commit that added its entry — the early direction, the one MOD-9 forbids");
  assert(early.reason.includes("2026-09-19T09:20:00Z") && early.reason.includes(SHA),
    `the wait does not say when the period ends or what it was counted from: ${early.reason}`);

  const due = resolveHold(hold, { now: plusMinutes(HELD_AT, 24 * 60 + 15), shadow: false, landed });
  assertEqual(due.act, "release", `24 hours after the commit, with a confirm record, the reversal waited: ${due.reason}`);

  // And the entry's own release_after still binds: a commit dated before
  // held_at (a hand edit that moved held_at later) cannot bring the release
  // forward of what the directory tells a person.
  const before = { sha: SHA, at: "2026-09-18T08:05:00Z" };
  const notYet = resolveHold(hold, { now: new Date("2026-09-19T08:06:00Z"), shadow: false, landed: before });
  assertEqual(notYet.act, "wait", "a reversal released before its own release_after because its commit is older than held_at");
  assertEqual(resolveHold(hold, { now: new Date("2026-09-19T09:05:00Z"), shadow: false, landed: before }).act, "release",
    "at release_after, with the commit's 24 hours run and a confirm record, the reversal waited");
});

await test("an entry no commit has added has not started its 24 hours", () => {
  const hold = heldHold(moderatorDecision(), "reversal", { confirm: record("confirm", "sd-relist-1") });
  const r = resolveHold(hold, {
    now: new Date("2030-01-01T00:00:00Z"),
    shadow: false,
    landed: { sha: null, at: null, uncommitted: true, why: "state/holds/sd-relist-1.json is in no commit on HEAD" },
  });
  assertEqual(r.act, "wait",
    "a reversal whose entry is in no commit released: MOD-9 counts from that commit, and there is none yet");
  assert(r.reason.includes("not started"), `the wait does not say the period has not started: ${r.reason}`);
});

await test("without its commit, a reversal waits out held_at + 24 h + the commit job's timeout, never earlier", () => {
  const hold = heldHold(moderatorDecision(), "reversal", { confirm: record("confirm", "sd-relist-1") });
  const unread = [
    ["no landing handed in", undefined],
    ["a shallow checkout", { sha: null, at: null, why: "a shallow clone" }],
    ["a landing with no readable time", { sha: SHA, at: "not a time" }],
  ];
  for (const [what, landed] of unread) {
    const r = resolveHold(hold, { now: plusMinutes(HELD_AT, 24 * 60 + 1), shadow: false, landed });
    assertEqual(r.act, "wait",
      `with ${what}, a confirmed reversal released 24 h and 1 min after held_at — counted from the compile, as ` +
      "before ops entry 101, while its commit may have landed up to the commit job's timeout later");
  }
  const slack = holdsModule.HOLD_COMMIT_SLACK_MINUTES;
  assert(Number.isInteger(slack) && slack > 0, `HOLD_COMMIT_SLACK_MINUTES is ${slack}`);
  for (const [what, landed] of unread) {
    const last = new Date(plusMinutes(HELD_AT, 24 * 60 + slack).getTime() - 1000);
    assertEqual(resolveHold(hold, { now: last, shadow: false, landed }).act, "wait",
      `with ${what}, the reversal released a second before held_at + 24 h + ${slack} min`);
    const r = resolveHold(hold, { now: plusMinutes(HELD_AT, 24 * 60 + slack), shadow: false, landed });
    assertEqual(r.act, "release", `with ${what}, the fallback never ends: ${r.reason}`);
    assert(r.reason.includes("could not be read"), `the release does not say it was counted without its commit: ${r.reason}`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
section("the hold no confirmation reaches");
// ─────────────────────────────────────────────────────────────────────────────

await test("an unbound A_YANK is not applied by a confirm record", () => {
  const r = resolveHold(
    heldHold(authorDecision(), "unbound_yank", { confirm: record("confirm", "sd-yank-1") }),
    { now: AFTER, shadow: false },
  );
  assertEqual(r.act, "wait",
    "a confirm record applied an unbound A_YANK. FLOW-79 lets only the bound account yank, so an unbound " +
    "one means the service erred, and an operator confirming it is confirming a fact about an account the " +
    "registry cannot see");
  assert(r.reason.includes("never applied"), `the refusal does not say why: ${r.reason}`);
});

await test("an unbound A_YANK is not applied by time, however much of it passes", () => {
  const r = resolveHold(heldHold(authorDecision(), "unbound_yank"), { now: new Date("2030-01-01T00:00:00Z"), shadow: false });
  assertEqual(r.act, "wait", "an unbound A_YANK aged into a release");
});

await test("an unbound A_YANK is not applied by a delist of the same listing", () => {
  const r = resolveHold(heldHold(authorDecision(), "unbound_yank"), {
    now: AFTER, shadow: false, delistedPlugins: ["astra-chess"],
  });
  assertEqual(r.act, "wait",
    "an applied author_request delist ended an unbound A_YANK. That is MOD-9's rule for a REMOVAL REQUEST: " +
    "a listing delisted for one reason would silently yank versions for another");
});

await test("only a cancel record, or a hand deletion, ends an unbound A_YANK", () => {
  const r = resolveHold(
    heldHold(authorDecision(), "unbound_yank", { cancel: record("cancel", "sd-yank-1") }),
    { now: BEFORE, shadow: false },
  );
  assertEqual(r.act, "cancel", `a cancel record did not end an unbound A_YANK: ${r.reason}`);
  assertEqual(r.result, "cancelled", "ending an unbound A_YANK posts something other than cancelled");
});

await test("an unbound removal request IS ended by a delist, and by a confirmation", () => {
  const d = authorDecision({ service_decision_id: "sd-rr-1", code: "A_REMOVAL_REQUEST" });
  const byDelist = resolveHold(heldHold(d, "unbound_removal"), {
    now: BEFORE, shadow: false, delistedPlugins: ["astra-chess"],
  });
  assertEqual(byDelist.act, "cancel", "MOD-9's delist rule no longer settles an unbound removal request");
  assertEqual(byDelist.result, "cancelled", "a settled removal request posts something other than cancelled");
  const byConfirm = resolveHold(heldHold(d, "unbound_removal", { confirm: record("confirm", "sd-rr-1") }), {
    now: BEFORE, shadow: false,
  });
  assertEqual(byConfirm.act, "release",
    "an operator's confirmation no longer applies an unbound removal request, which would make it the " +
    "same kind as unbound_yank and leave the contrast MOD-9 draws between them saying nothing");
});

// ─────────────────────────────────────────────────────────────────────────────
section("MOD-46's coverage check blocks one thing");
// ─────────────────────────────────────────────────────────────────────────────

await test("a red coverage report blocks a reversal", () => {
  const r = resolveHold(
    heldHold(moderatorDecision(), "reversal", { confirm: record("confirm", "sd-relist-1") }),
    { now: AFTER, shadow: false, coverageRed: true },
  );
  assertEqual(r.act, "wait",
    "a reversal released while MOD-46's coverage check was failing: the registry cannot currently account " +
    "for every withdrawal it has published, and giving something back in that state publishes a claim it " +
    "cannot back");
  assert(r.reason.includes("MOD-46"), `the wait does not name the check: ${r.reason}`);
});

await test("a red coverage report does not block a takedown", () => {
  for (const [held_for, decision] of [
    ["bound", moderatorDecision({ service_decision_id: "sd-revoke-3", code: "M_REVOKE", action: "block_install", severity: "high" })],
    ["disable_confirmation", moderatorDecision({ service_decision_id: "sd-revoke-1", code: "M_REVOKE", action: "disable", severity: "high" })],
  ]) {
    const r = resolveHold(
      heldHold(decision, held_for, { confirm: record("confirm", decision.service_decision_id) }),
      { now: AFTER, shadow: false, coverageRed: true },
    );
    assertEqual(r.act, "release",
      `a red coverage report stalled a ${held_for} takedown: a failing report would then be a way to stop ` +
      `the registry withdrawing anything at all`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
section("shadow: the hold is due, the result waits");
// ─────────────────────────────────────────────────────────────────────────────

await test("under shadow a confirmed hold is still due to release, and nothing is posted for it", () => {
  const r = resolveHold(
    heldHold(moderatorDecision(), "reversal", { confirm: record("confirm", "sd-relist-1") }),
    { now: AFTER, shadow: true },
  );
  assertEqual(r.act, "release",
    "a confirmed hold stopped being due under a shadow answer. It is not work that answer names: the " +
    "settled held result took it off the list and the release is driven by the MOD-52 record in git");
  assertEqual(r.post, false,
    "a run under a shadow answer posted an applied result. An applied or cancelled service-decision result " +
    "SETTLES a decision, which is what BOT-92 calls state-setting");
});

await test("an answer that carries no shadow member is read as shadow", () => {
  const hold = heldHold(moderatorDecision(), "reversal", { confirm: record("confirm", "sd-relist-1") });
  assertEqual(resolveHold(hold, { now: AFTER }).post, false,
    "resolveHold posts when nobody told it whether the run is in shadow; the silent direction has to be " +
    "the one a missing member produces");
  for (const notFalse of [undefined, null, "false", 0]) {
    assertEqual(resolveHold(hold, { now: AFTER, shadow: notFalse }).post, false,
      `resolveHold treated ${JSON.stringify(notFalse)} as "not in shadow"; only the boolean false is`);
  }
});

await test("resultsToPost posts nothing in shadow and the next shadow:false run posts once", () => {
  const pending = [{ service_decision_id: "sd-relist-1", outcome: "applied", commit: "abc1234" }];
  assertEqual(resultsToPost(pending, { shadow: true }).length, 0, "a shadow run posted a hold's result");
  assertEqual(resultsToPost(pending).length, 0, "a run with no shadow member posted a hold's result");
  assertEqual(resultsToPost(pending, { shadow: false }).length, 1, "the first shadow:false run posted nothing");
});

await test("BOT-82's key is the id, the outcome and the commit, and a repeat is one post", () => {
  const one = { service_decision_id: "sd-relist-1", outcome: "applied", commit: "abc1234" };
  assertEqual(resultKey(one), "sd-relist-1|applied|abc1234", "BOT-82's idempotency key has changed shape");
  assertEqual(resultsToPost([one, { ...one }], { shadow: false }).length, 1,
    "the same result was posted twice out of one run");
  assertEqual(resultsToPost([one, { ...one, commit: "def5678" }], { shadow: false }).length, 2,
    "two releases of the same decision in two commits collapsed into one post, so one of them is never " +
    "reported at all");
});

// ─────────────────────────────────────────────────────────────────────────────
section("the service is down, and the runner crashed");
// ─────────────────────────────────────────────────────────────────────────────

// `commit` walks every hold even when `list` failed, so the release path must
// not be able to want an answer. The strong form of that is structural: there
// is no service input to resolveHold, and no way for this module to make a
// call. Both halves are asserted, because "it happens not to call anything
// today" is what a later import quietly changes.
await test("with the service down a confirmed hold is still due to release, because nothing here asks it", () => {
  const r = resolveHold(
    heldHold(moderatorDecision(), "reversal", { confirm: record("confirm", "sd-relist-1") }),
    { now: AFTER, shadow: false },
  );
  assertEqual(r.act, "release", "a release needed something the list answer carries");
  const src = fs.readFileSync(path.join(REPO_ROOT, "bot", "lib", "holds.mjs"), "utf8");
  for (const needle of ["node:http", "node:https", "node:net", "fetch("]) {
    assert(!src.includes(needle),
      `bot/lib/holds.mjs now reaches ${needle}; the commit job walks every hold WITH LIST DOWN, and a ` +
      `module that can call is a module that can hang there`);
  }
});

// The crash the plan names: the release commit landed and the runner died
// before the result was posted. The next run has no hold entry to read — it was
// deleted by the very commit that applied the decision — so the only record of
// what happened is the commit, which is what classifyHoldCommit reads.
await test("a release commit is recognised after a crash, and posts once", () => {
  const c = classifyHoldCommit({
    sha: "abc1234", deletesEntry: true, writesLogEntry: true,
    trailers: { "Service-Decision": "sd-relist-1", "Decided-At": DECIDED_AT },
  });
  assertEqual(c.act, "release", `a release commit was not recognised: ${c.reason}`);
  assertEqual(c.result, "applied", "a release commit reports something other than applied");
  const posts = resultsToPost([{ service_decision_id: "sd-relist-1", outcome: c.result, commit: "abc1234" }], { shadow: false });
  assertEqual(posts.length, 1, "the result of a release the runner crashed after was never posted");
});

await test("a cancel commit is recognised, and a hand deletion is a cancellation", () => {
  const cancelled = classifyHoldCommit({
    sha: "def5678", deletesEntry: true, writesLogEntry: false, trailers: { "Service-Decision": "sd-yank-1" },
  });
  assertEqual(cancelled.act, "cancel", `a cancel commit was not recognised: ${cancelled.reason}`);
  assertEqual(cancelled.hand, false, "a trailered cancel commit was reported as a hand cancellation");

  const byHand = classifyHoldCommit({ sha: "0f0f0f0", deletesEntry: true, writesLogEntry: false, trailers: {} });
  assertEqual(byHand.act, "cancel",
    "a hold entry deleted by hand was not reported as a cancellation. Deleting the file is the documented " +
    "way for a person with no tooling to end a hold (BOT-70), so it must be neither an application nor silent");
  assertEqual(byHand.result, "cancelled", "a hand deletion posts something other than cancelled");
  assertEqual(byHand.hand, true, "a hand cancellation is not marked as one, so nothing alerts on it");
  assert(byHand.reason.includes("0f0f0f0"), `a hand cancellation does not name its commit: ${byHand.reason}`);
});

await test("a deletion with a log entry and no trailer is neither, and posts nothing", () => {
  const c = classifyHoldCommit({ sha: "beefbee", deletesEntry: true, writesLogEntry: true, trailers: {} });
  assertEqual(c.result, null,
    "a commit that deleted the hold entry and WROTE THE LOG ENTRY under no Service-Decision: trailer was " +
    "given a result. Calling it cancelled tells the service nothing happened while the public log says the " +
    "decision was applied, and BOT-82's key then settles every honest retry as a duplicate of that");
  assertEqual(c.act, "unclear", "the fourth shape of a hold commit has stopped being reported as unclear");
});

await test("a commit that did not delete the entry is not a hold commit at all", () => {
  const c = classifyHoldCommit({ sha: "1111111", deletesEntry: false, writesLogEntry: true, trailers: { "Service-Decision": "sd-relist-1" } });
  assertEqual(c.act, "none", "a commit that left the hold entry in the tree was read as ending the hold");
});

// ─────────────────────────────────────────────────────────────────────────────
section("the directory, as an operator leaves it");
// ─────────────────────────────────────────────────────────────────────────────

await test("readHolds pairs an entry with its record, and a missing directory is not an error", () => {
  const t = tmpTree();
  try {
    assertEqual(readHolds(path.join(t.root, "nowhere")).length, 0, "a missing state/holds/ threw instead of answering none");
    t.write(path.join(HOLDS_DIR, "sd-relist-1.json"), holdEntry(moderatorDecision(), { held_for: "reversal", held_at: HELD_AT }));
    t.write(recordFile("sd-relist-1", "confirm"), record("confirm", "sd-relist-1"));
    const holds = readHolds(t.root);
    assertEqual(holds.length, 1, "the walk found the wrong number of holds");
    assertEqual(holds[0].problems.join("; "), "", "a sound hold was reported as unsound");
    assertEqual(holds[0].confirm?.act, "confirm", "the confirm record beside the entry was not paired with it");
    assertEqual(resolveHold(holds[0], { now: AFTER, shadow: false }).act, "release", "a hold read from disk did not release");
  } finally { t.done(); }
});

await test("a hand-edited release_after cannot shorten a hold", () => {
  const t = tmpTree();
  try {
    const entry = holdEntry(moderatorDecision(), { held_for: "reversal", held_at: HELD_AT });
    assertEqual(entry.release_after, releaseAfter(HELD_AT), "holdEntry writes a release_after of its own devising");
    entry.release_after = "2026-09-18T10:00:00Z";
    t.write(path.join(HOLDS_DIR, "sd-relist-1.json"), entry);
    t.write(recordFile("sd-relist-1", "confirm"), record("confirm", "sd-relist-1"));
    const [hold] = readHolds(t.root);
    assert(hold.problems.some((p) => p.includes("cannot shorten a hold")),
      `an entry whose release_after is an hour after held_at was accepted: ${hold.problems.join("; ") || "no problems reported"}`);
    const r = resolveHold(hold, { now: new Date("2026-09-18T11:00:00Z"), shadow: false });
    assertEqual(r.act, "wait", "a hold with a hand-shortened release_after released early");
  } finally { t.done(); }
});

await test("a file named for one decision and holding another is refused", () => {
  const t = tmpTree();
  try {
    t.write(path.join(HOLDS_DIR, "sd-relist-9.json"), holdEntry(moderatorDecision(), { held_for: "reversal", held_at: HELD_AT }));
    const [hold] = readHolds(t.root);
    assert(hold.problems.some((p) => p.includes("matched by id")),
      `a hold file named for sd-relist-9 holding sd-relist-1 was accepted: ${hold.problems.join("; ") || "no problems reported"}`);
    assertEqual(resolveHold(hold, { now: AFTER, shadow: false }).act, "wait", "an unsound hold was acted on");
  } finally { t.done(); }
});

await test("an unreadable hold file waits rather than disappearing", () => {
  const t = tmpTree();
  try {
    t.writeRaw(path.join(HOLDS_DIR, "sd-relist-1.json"), "{ not json");
    const [hold] = readHolds(t.root);
    assertEqual(hold.entry, null, "a truncated hold file parsed");
    assert(hold.problems.length >= 1, "a truncated hold file was reported sound");
    assertEqual(resolveHold(hold, { now: AFTER, shadow: false }).act, "wait",
      "a hold whose file could not be read was ended; a half-written file must not release or cancel anything");
  } finally { t.done(); }
});

await test("an A_* held decision carrying a moderator is refused by name", () => {
  assertEqual(AUTHOR_CODES.slice().sort().join(","), "A_REMOVAL_REQUEST,A_YANK", "the author-action codes have moved");
  assertEqual(AUTHOR_FORBIDDEN_MEMBERS.slice().sort().join(","), "declared_interest,moderator",
    "the members forbidden on an author action have moved");
  for (const member of AUTHOR_FORBIDDEN_MEMBERS) {
    const entry = holdEntry(authorDecision(), { held_for: "unbound_yank", held_at: HELD_AT });
    entry.decision[member] = member === "declared_interest" ? false : "mod-a";
    const problems = checkHoldEntry(entry);
    assert(problems.some((p) => p.includes(member)),
      `an A_YANK carrying "${member}" was accepted into a hold entry. No moderator decided it, and 0.12.0's ` +
      `wording would have committed a moderator handle on an author's action to the public log (DEC-14, MOD-41, n4)`);
  }
});

await test("a record schema violation is a problem, not an exception", () => {
  const problems = checkHoldRecord({ schema: RECORD_SCHEMA, act: "acknowledge", service_decision_id: "sd-relist-1", at: HELD_AT });
  assert(problems.length >= 1,
    "a hold record with act \"acknowledge\" was accepted; a TRUST-42 acknowledgement is not an operator's " +
    "confirmation and must not be expressible (BOT-32)");
});

// ─────────────────────────────────────────────────────────────────────────────
section("writing one: what may not ride into git inside a hold entry");
// ─────────────────────────────────────────────────────────────────────────────

// SCOPE-3's read side says a parser ignores members it does not know, so a
// MINOR that adds an optional member reaches this module as an unnamed key on
// the decision object. The hold entry is the second way into git — the first
// being M-T3.4's composers — and it is written in one run and committed in it,
// so an entry that copied the object wholesale would commit the unknown member
// under `additionalProperties: false`, which refuses it only when it is read
// BACK, one run later.
await test("an unnamed member on a decision does not reach the hold entry", () => {
  const named = Object.keys(holdSchema().properties.decision.properties).filter((k) => k !== "$comment");
  assert(named.length >= 10, `the allowlist is ${named.length} members and was 12 on 2026-09-19`);
  const entry = holdEntry({ ...moderatorDecision(), withheld_since: "2026-09-18T00:00:00Z", x: "surprise" },
    { held_for: "reversal", held_at: HELD_AT });
  assertEqual(Object.keys(entry.decision).filter((k) => !named.includes(k)).join(", "), "",
    "a member schema/hold-v1.json does not name reached the hold entry, and the entry is committed; " +
    "passing the decision object straight through instead of the allowlist is what that looks like");
  assertEqual(JSON.stringify(entry).includes("surprise"), false, "the unnamed member is somewhere else in the entry");
});

await test("holdEntry refuses to write what the directory would refuse to read", () => {
  let threw = "";
  try {
    holdEntry(authorDecision({ moderator: "mod-a" }), { held_for: "unbound_yank", held_at: HELD_AT });
  } catch (e) { threw = e.message; }
  assert(threw.includes("refusing to write"),
    "holdEntry wrote an A_YANK carrying a moderator; the entry would then sit in state/holds/ until the " +
    "next run read it back and refused it, with the moderator handle already in the public history");
});

await test("only a reversal is written with a release_after", () => {
  const d = moderatorDecision({ service_decision_id: "sd-revoke-1", code: "M_REVOKE", action: "disable", severity: "high" });
  const entry = holdEntry(d, { held_for: "disable_confirmation", held_at: HELD_AT });
  assertEqual(entry.release_after, undefined,
    "a disable hold was written with a release_after, and a kind that waits on a person must not look like " +
    "one that waits on a clock");
  assertEqual(entry.schema, SCHEMA, "the entry does not declare its own schema");
});

// ── result ──────────────────────────────────────────────────────────────────

console.log();
if (failures.length) {
  console.log(`FAIL  ${passed} passed, ${failures.length} failed`);
  process.exit(1);
}
console.log(`PASS  ${passed} passed, 0 failed`);
