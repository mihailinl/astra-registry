// MIG-13's migration-notice marker, and the schema contract 0.31.0 let this
// repository write for it (B.4; MIG-13; MIG-14; ROLL-32; dev/couplings.md
// entry 58).
//
// **Why the file did not exist before, and why it does now.** B.4 listed the
// marker's four members and typed none of them, and the token file publishes
// `cutover_planned_at` as `conditional` on `{"iff": {"round": {"not": [1]}}}`
// — a predicate naming the INTEGER `1`, compared by every reader without
// coercion. A marker spelling its round `"1"` makes that condition take its
// other branch, so a conforming round-1 marker is required to carry a date it
// cannot have, at ROLL-32's gate, with the refusal pointing at whoever wrote
// the marker. A schema asserting `integer` while the page said nothing would
// have been a file outrunning its source (SCOPE-1), so 0.31.0 put the types on
// the page first and `schema/migration-notice-v1.json` asserts them second.
//
// **What this module asks, and why each question is its own test.**
//
//   * the SHAPES: every marker B.4 permits validates, and every one B.4 or
//     MIG-14 refuses is refused FOR THE NAMED REASON — a refusal for some
//     other reason is a schema that happens to be red, not one that states
//     the rule. No marker is on this tree (`log/` holds no tracked file until
//     round 1 lands at R4b), so every document here is synthesised: a guard
//     cannot be proven by a corpus that has never contained its case.
//   * the MEMBERS: the schema's member set and flat requiredness are the token
//     file's, read from the committed file, so a member added to one and not
//     the other is red here rather than at the service.
//   * the CONDITION: the schema's `oneOf` and the token file's `when` are two
//     statements of one rule in one repository. They are held to each other
//     BY BEHAVIOUR, over every round from 1 to beyond the highest the
//     predicate names, dated and undated — not by comparing their text, which
//     would pass two spellings that disagree on a round nobody wrote down.
//   * the GATE: `tools/validate.mjs` actually reads the schema when it walks a
//     tree, refuses a string round on it, round-trips both times, and says so
//     when there is no marker at all.
//
// **This module reads the token file's member table and is not a member
// reader**, and `bot/tests/service.test.mjs`'s census says so by name: it
// compares two statements of one condition and judges no marker on a ref. The
// reader the census proves is `tools/cutover-preflight.mjs`. It deliberately
// does NOT import that tool — this directory is in TRUST-31's set and the
// publish path runs it, so an import would make a desk tool outside the set an
// input to every publication, through a dynamic `import()` the set's own
// closure walk cannot follow.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT, loadSchemas } from "../lib/sources.mjs";
import { validate } from "../lib/jsonschema.mjs";
import { NOTICE_NAME, NOTICE_SCHEMA, noticeMarkerProblems } from "../validate.mjs";
import { POSITIVE_INTEGER_LITERAL, topLevelMembers } from "../lib/json-literal.mjs";
import { test, assert, assertEqual, tmp, validateTree } from "./harness.mjs";

const SCHEMA_FILE = "schema/migration-notice-v1.json";
const TOKEN_FILE = "schema/contract-tokens-v1.json";
const CONDITIONAL = "cutover_planned_at";

const S = NOTICE_SCHEMA;
const SENT = "2026-08-01T00:00:00Z";
const PLANNED = "2026-11-01T00:00:00Z";
const marker = (round, extra = {}) => ({ schema: S, round, sent_at: SENT, ...extra });
const dated = (round, extra = {}) => marker(round, { cutover_planned_at: PLANNED, ...extra });

/** The committed schema, read the way tools/validate.mjs reads it. */
const schema = () => loadSchemas(REPO_ROOT).migrationNotice;

/** The token file's entry for the marker, or a thrown reason. */
function tokenEntry() {
  const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, TOKEN_FILE), "utf8"));
  const entry = (doc.entries || []).find((e) => e.kind === "schema" && e.name === S);
  assert(entry && Array.isArray(entry.members),
    `${TOKEN_FILE} publishes no member table for ${S}; the schema beside it is then a statement of nothing the ` +
    "contract publishes, and every comparison below would compare it with an empty list");
  return entry;
}

export async function run() {
  console.log(`\nthe migration-notice marker (${SCHEMA_FILE}; contract B.4 from 0.31.0)`);

  await test("every marker B.4 permits validates, and each one it refuses is refused for its reason", () => {
    const s = schema();
    // The three rounds MIG-13 has, each in the one shape B.4 permits for it.
    for (const [what, doc] of [
      ["round 1, undated", marker(1)],
      ["round 2, dated", dated(2)],
      ["round 3, dated", dated(3)],
      // The ceiling is the acceptor's u32, published in B.4 at their request.
      ["round 4294967295, dated (the published ceiling)", dated(4294967295)],
    ]) {
      assertEqual(validate(s, doc).map((p) => `${p.path} ${p.message}`).join(" | "), "",
        `${what} is a marker B.4 permits and the schema refuses it`);
    }
    // Each refusal names the property the schema must refuse it FOR. A marker
    // refused for a different reason would leave this green over a schema that
    // no longer states the rule in the name.
    const refusals = [
      ["a string round, undated (entry 58's own case)", marker("1"), "$.round expected integer, got string"],
      ["a string round, dated", dated("2"), "$.round expected integer, got string"],
      ["a fractional round", dated(1.5), "$.round expected integer, got number"],
      ["a null round", marker(null), "$.round expected integer, got null"],
      ["round 0", dated(0), "$.round less than 1"],
      ["a negative round", dated(-2), "$.round less than 1"],
      ["round 4294967296, one past the ceiling", dated(4294967296), "$.round greater than 4294967295"],
      ["round 2 with no date (B.4: from round 2)", marker(2), "$ matches 0 of the allowed shapes"],
      ["round 1 carrying a date (MIG-14: never in a marker before it)", dated(1), "$ matches 0 of the allowed shapes"],
      ["a member outside the four (M-T5.3's canary)", marker(1, { accounts: ["x"] }), '$ unknown property "accounts"'],
      ["no `sent_at`", { schema: S, round: 1 }, '$ missing required property "sent_at"'],
      ["another record's schema string", { ...marker(1), schema: "astra.registry.cutover/1" }, "$.schema must be"],
      ["a §0.7 DATE for the cutover, which §0.7 reserves for two other members", dated(2, { cutover_planned_at: "2026-11-01" }), "$.cutover_planned_at does not match"],
      ["fractional seconds", marker(1, { sent_at: "2026-08-01T00:00:00.5Z" }), "$.sent_at does not match"],
      ["an offset instead of `Z`", dated(2, { cutover_planned_at: "2026-11-01T00:00:00+00:00" }), "$.cutover_planned_at does not match"],
      // B.4 from 0.31.0's second round: a real UTC instant, never second 60.
      // The pattern bounds the fields, so these two are refused by the schema;
      // a day that does not exist is not, and the next test holds that.
      ["hour 24 in `sent_at`", marker(1, { sent_at: "2026-08-01T24:00:00Z" }), "$.sent_at does not match"],
      ["second 60 in `cutover_planned_at`", dated(2, { cutover_planned_at: "2026-12-31T23:59:60Z" }), "$.cutover_planned_at does not match"],
    ];
    for (const [what, doc, reason] of refusals) {
      const got = validate(s, doc).map((p) => `${p.path} ${p.message}`);
      assert(got.some((g) => g.startsWith(reason)),
        `${what}: the schema must refuse it with "${reason}…", and said ${JSON.stringify(got)}`);
    }
  });

  await test("the schema's members and their flat requiredness are the token file's", () => {
    const s = schema();
    const entry = tokenEntry();
    const names = (list) => [...list].sort().join(", ");
    assertEqual(names(Object.keys(s.properties)), names(entry.members.map((m) => m.name)),
      `${SCHEMA_FILE} and ${TOKEN_FILE} name different members for ${S}. B.4's "exactly" is one list, and a ` +
      "member in one of them and not the other is a marker one reader admits and another refuses");
    assertEqual(names(s.required), names(entry.members.filter((m) => m.required === true).map((m) => m.name)),
      "the members every marker carries differ between the schema's `required` and the token file's " +
      "`required: true`");
    const cond = entry.members.find((m) => m.name === CONDITIONAL);
    assertEqual(cond?.required, "conditional",
      `${TOKEN_FILE} no longer publishes \`${CONDITIONAL}\` as conditional, and this module's third test is ` +
      "built on it being so — re-derive the schema's `oneOf` from what the file now says");
    assert(s.additionalProperties === false,
      `${SCHEMA_FILE} admits members B.4 does not list; "exactly" is the word it is written against`);
  });

  await test("the schema's condition and the token file's `when` agree on every round, dated and undated", () => {
    const s = schema();
    const when = tokenEntry().members.find((m) => m.name === CONDITIONAL)?.when;
    // The one shape 0.30.0 published. Anything else is a condition this
    // comparison was not written for, and it says so rather than guessing.
    const not = when?.iff?.round?.not;
    assert(
      when && Object.keys(when).length === 1 && Object.keys(when.iff ?? {}).length === 1 &&
        Array.isArray(not) && not.length > 0 && not.every(Number.isInteger),
      `${TOKEN_FILE}'s condition on \`${CONDITIONAL}\` is ${JSON.stringify(when)}, which is not the ` +
      '`{"iff": {"round": {"not": [<integers>]}}}` this comparison evaluates. Re-derive the schema\'s `oneOf` ' +
      "from the new condition, and this test with it",
    );
    // Every round from 1 to three past the highest the predicate names: below
    // the threshold, at it, and above it, including rounds MIG-13 does not
    // have yet — a fourth round falls on the required side, and both files
    // must say so.
    const top = Math.max(...not) + 3;
    const disagree = [];
    let accepted = 0;
    let refused = 0;
    for (let round = 1; round <= top; round += 1) {
      for (const carried of [true, false]) {
        const doc = carried ? dated(round) : marker(round);
        const tokenSays = carried === !not.includes(round);
        const schemaSays = validate(s, doc).length === 0;
        if (tokenSays !== schemaSays) {
          disagree.push(`round ${round} ${carried ? "dated" : "undated"}: token file ${tokenSays}, schema ${schemaSays}`);
        }
        if (schemaSays) accepted += 1;
        else refused += 1;
      }
    }
    assertEqual(disagree.join(" | "), "",
      `${SCHEMA_FILE}'s oneOf and ${TOKEN_FILE}'s \`when\` state one condition and disagree about it`);
    // Not vacuous: both verdicts occur, over at least the three rounds MIG-13
    // has and one it does not.
    assert(accepted >= 4 && refused >= 4 && top >= 4,
      `the comparison ran over rounds 1..${top} and saw ${accepted} accepted and ${refused} refused; below four ` +
      "of each it has stopped comparing the two branches of the condition");
  });

  await test("tools/validate.mjs judges each marker on a tree against the schema, and says when there is none", async () => {
    // Nothing on this tree is a marker, so the absent state is asserted on the
    // committed tree and the present one on a synthesised tree beside it.
    const onTree = await validateTree(REPO_ROOT, { allowStaging: true });
    const absent = onTree.report.items.filter((i) => i.where === "log/migration-notice-<n>.json");
    assertEqual(absent.map((i) => i.level).join(","), "note",
      "with no marker on the tree the validator must say it looked and found none, once, as a note");

    const dir = path.join(tmp, "migration-notice-markers");
    fs.mkdirSync(path.join(dir, "log"), { recursive: true });
    const put = (name, doc) => fs.writeFileSync(path.join(dir, "log", name), JSON.stringify(doc));
    put("migration-notice-1.json", marker("1"));
    put("migration-notice-2.json", dated(2));
    put("migration-notice-3.json", dated(3, { sent_at: "2026-02-31T00:00:00Z" }));
    // A name no reader takes for a marker — the preflight's pattern, and this
    // validator's, both want digits — so it is not judged.
    put("migration-notice-draft.json", { anything: true });
    assert(!NOTICE_NAME.test("migration-notice-draft.json") && NOTICE_NAME.test("migration-notice-2.json"),
      "the marker name pattern moved; the fixture names above were chosen against it");

    const { report } = await validateTree(dir, { allowStaging: true });
    const errors = (file) => report.items.filter((i) => i.where === `log/${file}` && i.level === "error").map((i) => i.message);
    assert(errors("migration-notice-1.json").some((m) => m === "$.round expected integer, got string"),
      `a string round was not refused by name: ${JSON.stringify(errors("migration-notice-1.json"))}`);
    assertEqual(errors("migration-notice-2.json").join(" | "), "", "a conforming round-2 marker was refused");
    assert(errors("migration-notice-3.json").some((m) => m.includes("not a real moment")),
      `a sent_at the pattern admits and no clock has was not refused: ${JSON.stringify(errors("migration-notice-3.json"))}`);
    assertEqual(report.items.filter((i) => i.where === "log/migration-notice-draft.json").length, 0,
      "a file no reader takes for a marker was judged as one");
    assertEqual(report.items.filter((i) => i.where === "log/migration-notice-<n>.json").length, 0,
      "a tree carrying markers was reported as carrying none");
  });

  // Contract 0.31.0, the acceptor's three changes. Each is a rule about the
  // marker's TEXT that the parsed value cannot carry, so every document here is
  // a string of bytes and it is judged by `noticeMarkerProblems` — the same
  // function tools/validate.mjs calls on a tree, not a copy of it.
  await test("a marker's text is judged where a parsed value cannot be: the `round` literal, and a real instant", () => {
    const s = schema();
    const text = (roundLiteral, extra = "") =>
      `{"schema": "${S}", "round": ${roundLiteral}, "sent_at": "${SENT}"${extra}}`;
    const withDate = (roundLiteral, at = PLANNED) => text(roundLiteral, `, "cutover_planned_at": "${at}"`);
    const judged = (t) => noticeMarkerProblems(t, s).map((p) => p.message);
    for (const [what, t] of [
      ["`1`", text("1")],
      ["`2`, dated", withDate("2")],
      ["`3`, dated", withDate("3")],
      ["`4294967295`, dated", withDate("4294967295")],
      ["`1` with RFC 8259 whitespace around the colon", `{"schema":"${S}",\n  "round"\t :\r\n 1 ,"sent_at":"${SENT}"}`],
      ["`1` under a key spelt with an escape, which IS `round`", `{"schema":"${S}","\\u0072ound":1,"sent_at":"${SENT}"}`],
    ]) {
      assertEqual(judged(t).join(" | "), "", `the literal ${what} is one B.4 permits, and the text was refused`);
    }
    const LITERAL = "`round` is written ";
    for (const [what, t, reason] of [
      ["`1.0`", text("1.0"), `${LITERAL}1.0,`],
      ["`1e0`", text("1e0"), `${LITERAL}1e0,`],
      ["`1E0`", text("1E0"), `${LITERAL}1E0,`],
      ["`2.0`, dated", withDate("2.0"), `${LITERAL}2.0,`],
      ["`1.0` under an escaped key", `{"schema":"${S}","\\u0072ound":1.0,"sent_at":"${SENT}"}`, `${LITERAL}1.0,`],
      ["two `round` members, the last one well formed", `{"schema":"${S}","round":"x","round":1,"sent_at":"${SENT}"}`, "carries 2 `round` members"],
      ["`sent_at` on a day that does not exist", `{"schema":"${S}","round":1,"sent_at":"2026-02-30T00:00:00Z"}`, "`sent_at` is \"2026-02-30T00:00:00Z\", which is not a real moment"],
      ["`cutover_planned_at` on a day that does not exist", withDate("2", "2026-02-30T00:00:00Z"), "`cutover_planned_at` is \"2026-02-30T00:00:00Z\", which is not a real moment"],
      ["`sent_at` at hour 24", `{"schema":"${S}","round":1,"sent_at":"2026-08-01T24:00:00Z"}`, "$.sent_at does not match"],
      ["`cutover_planned_at` at second 60", withDate("2", "2026-12-31T23:59:60Z"), "$.cutover_planned_at does not match"],
      ["4294967296, dated", withDate("4294967296"), "$.round greater than 4294967295"],
    ]) {
      const got = judged(t);
      assert(got.some((g) => g.startsWith(reason)),
        `${what}: the marker must be refused with "${reason}…", and was refused with ${JSON.stringify(got)}`);
    }
    // The three a PARSED value cannot show, asserted on the parsed value too,
    // so that the reason this test reads text is a measurement and not a
    // belief: the schema alone admits every one of them.
    for (const t of [text("1.0"), text("1e0"), text("1E0"), withDate("2.0")]) {
      assertEqual(validate(s, JSON.parse(t)).length, 0,
        `the schema refused ${t} on its parsed value, so the raw-text check above is no longer the only thing refusing it`);
    }
  });

  await test("the literal scanner reads depth-one members by their decoded names, and every duplicate", () => {
    // Its own edges, each a way a regular expression over the file gets it
    // wrong. The helper is the whole of the literal check in two readers.
    const rounds = (t) => topLevelMembers(t).filter((m) => m.name === "round").map((m) => m.raw);
    assertEqual(JSON.stringify(rounds('{"a":{"round":1.0},"round":2}')), '["2"]', "a nested `round` was read as the member");
    assertEqual(JSON.stringify(rounds('{"a":"\\"round\\": 1.0","round":2}')), '["2"]', "a `round` inside a string was read as the member");
    assertEqual(JSON.stringify(rounds('{"\\u0072ound":1e0}')), '["1e0"]', "a key spelt with an escape was not read as `round`");
    assertEqual(JSON.stringify(rounds('{"round":1,"round":1.0}')), '["1","1.0"]', "a duplicate was not reported with its own literal");
    assertEqual(JSON.stringify(rounds('{ "round" :\n 3 }')), '["3"]', "whitespace around the member changed its literal");
    let threw = false;
    try {
      topLevelMembers("[1]");
    } catch {
      threw = true;
    }
    assert(threw, "an array was read as an object");
    for (const [lit, ok] of [["1", true], ["4294967295", true], ["1.0", false], ["1e0", false], ["1E0", false], ["01", false], ["-1", false], ["+1", false], ["0", false]]) {
      assertEqual(POSITIVE_INTEGER_LITERAL.test(lit), ok, `the literal ${lit} was judged ${!ok ? "an integer" : "not one"}`);
    }
  });
}
