// The binding deadline, MIG-13's rounds, and ROLL-63's watch — the procedure
// around the two records B.4 fixes, driven with fixture clocks and trees
// (registry plan M-T5.2, M-T5.3, M-T5.4).
//
// **Every document here is synthesised.** No deadline and no marker is on the
// committed tree until the owner commits the one and the sends commit the
// other, and a guard cannot be proven by a corpus that has never contained
// its case. Each case below is the case its task's Canary names, and each is
// watched red by the mutation named beside it (the lane report records the
// runs).
//
// **It imports only `tools/lib/`**, inside TRUST-31's set: this directory is
// the publish path's fifth gate, and a module it loads from outside the set is
// red in `loads.mjs`. The three desk commands (`tools/binding-deadline.mjs`,
// `tools/migration-notice.mjs`, `tools/deadline-watch.mjs`) are driven end to
// end, as a person runs them, by `bot/tests/listing-state.test.mjs`.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT, loadSchemas } from "../lib/sources.mjs";
import {
  DEADLINE_AFTER_CUTOVER_DAYS, POLICY_LINE_ABSENT, POLICY_LINE_PREFIX, deadlineText, planDeadline, policyLine,
  withPolicyLine,
} from "../lib/binding-deadline.mjs";
import {
  NOTICE_DOC, authoritative, judgeIssuePaths, markerText, planResend, planRound, recipients,
  renderRound, roundTemplate,
} from "../lib/migration-notice.mjs";
import { CODES, judge } from "../lib/deadline-watch.mjs";
import { NOTICE_SCHEMA, noticeMarkerProblems } from "../validate.mjs";
import { readMarkers as readRecords } from "../../bot/lib/listing-state.mjs";
import { CODE_PATTERN } from "../../bot/lib/alert-verdict.mjs";
import { test, assert, assertEqual, tmp, validateTree } from "./harness.mjs";

const schema = () => loadSchemas(REPO_ROOT).migrationNotice;

/** A marker as `readMarkers` returns it, from a document. */
const m = (doc, committedAt = null) => ({
  file: `log/migration-notice-${doc.round}.json`,
  nameRound: doc.round,
  doc: { schema: NOTICE_SCHEMA, ...doc },
  problems: noticeMarkerProblems(JSON.stringify({ schema: NOTICE_SCHEMA, ...doc }), schema()).map((p) => p.message),
  committed_at: committedAt,
});
const parsed = (w) => JSON.parse(w.text);

const DEADLINE = "2026-11-26T00:00:00Z";
const R1 = { round: 1, sent_at: "2026-09-10T00:00:00Z" };
const R2 = { round: 2, sent_at: "2026-09-20T00:00:00Z", cutover_planned_at: "2026-10-25T00:00:00Z" };
const R3 = { round: 3, sent_at: "2026-11-01T00:00:00Z", cutover_planned_at: "2026-10-25T00:00:00Z" };

export async function run() {
  console.log("\nthe binding deadline, MIG-13's rounds and ROLL-63's watch (M-T5.2, M-T5.3, M-T5.4)");

  // ── M-T5.2 ─────────────────────────────────────────────────────────────────

  await test("MIG-2: the deadline is the cutover estimate plus 60 days, and each floor refuses by name", () => {
    const beta = planDeadline({ cutoverEstimate: "2026-09-27T00:00:00Z" });
    assertEqual(beta.deadline, "2026-11-26T00:00:00Z", `${DEADLINE_AFTER_CUTOVER_DAYS} days after 2026-09-27 is not what the planner gave`);
    assertEqual(beta.change, "new", "a first deadline is a new one");
    assert(beta.notes.some((n) => n.includes("NOT ASKED")), "with no round-2 estimate the floor must say it was not asked, not pass");

    assertEqual(planDeadline({ cutoverEstimate: "2026-09-27T00:00:00Z", round2Estimate: "2026-09-27T00:00:00Z" }).problems.join(""), "",
      "a round 2 sent on the cutover day is exactly 60 days before the deadline, which MIG-2 permits");
    const late = planDeadline({ cutoverEstimate: "2026-09-27T00:00:00Z", round2Estimate: "2026-10-01T00:00:00Z" });
    assert(late.deadline === null && late.problems.some((p) => p.includes("at least 60")),
      `a round 2 56 days before the deadline was not refused on MIG-2's floor: ${JSON.stringify(late)}`);

    const earlier = planDeadline({ cutoverEstimate: "2026-09-27T00:00:00Z", committed: "2026-12-01T00:00:00Z" });
    assert(earlier.deadline === null && earlier.problems.some((p) => p.includes("MIG-29")),
      `a deadline earlier than the committed one was not refused on MIG-29: ${JSON.stringify(earlier)}`);
    assertEqual(planDeadline({ cutoverEstimate: "2026-09-27T00:00:00Z", committed: DEADLINE }).change, "same",
      "the committed deadline again is no change");
    assertEqual(planDeadline({ cutoverEstimate: "2026-09-27T00:00:00Z", committed: "2026-11-01T00:00:00Z" }).change, "later",
      "a later deadline is MIG-29's permitted move");

    for (const bad of ["2026-09-27", "2026-02-30T00:00:00Z", "2026-09-27T00:00:00.5Z", "2026-09-27T24:00:00Z", null]) {
      const p = planDeadline({ cutoverEstimate: bad });
      assert(p.deadline === null && p.problems.length === 1, `the estimate ${JSON.stringify(bad)} is not a §0.7 time and was accepted`);
    }
  });

  await test("MIG-3: POLICY.md states the deadline on exactly one line, and the committed line agrees with the committed file", () => {
    const text = fs.readFileSync(path.join(REPO_ROOT, "POLICY.md"), "utf8");
    const anchors = text.split("\n").filter((l) => l.startsWith(POLICY_LINE_PREFIX));
    assertEqual(anchors.length, 1, `POLICY.md has ${anchors.length} line(s) starting with ${POLICY_LINE_PREFIX}; the tool needs one`);
    const committed = readRecords(REPO_ROOT).deadline;
    assertEqual(anchors[0], policyLine(committed),
      committed === null
        ? "no deadline is committed and POLICY.md's deadline line says something other than that it is not fixed"
        : `policy/binding-deadline.json commits ${committed} and POLICY.md's deadline line is not the one that states it`);
    assert(!/\d{4}-\d{2}-\d{2}/.test(POLICY_LINE_ABSENT), "the line for an absent deadline carries a date, which MIG-3's scan reads as a claim");

    const moved = withPolicyLine(text, DEADLINE);
    assert(moved.includes(`${POLICY_LINE_PREFIX} 2026-11-26 (\`${DEADLINE}\`)`), "the written line does not carry the date in both forms");
    assertEqual(moved.split("\n").length, text.split("\n").length, "writing the line changed more than the line");
    for (const [what, t] of [["no anchor", "# policy\n"], ["two anchors", `${POLICY_LINE_ABSENT}\n${POLICY_LINE_ABSENT}\n`]]) {
      let threw = false;
      try { withPolicyLine(t, DEADLINE); } catch { threw = true; }
      assert(threw, `a POLICY.md with ${what} was written to instead of refused`);
    }
  });

  await test("the deadline the tool writes is one the bot's reader and tools/validate.mjs both take", async () => {
    const dir = path.join(tmp, "binding-deadline-tree");
    fs.mkdirSync(path.join(dir, "policy"), { recursive: true });
    fs.writeFileSync(path.join(dir, "policy", "binding-deadline.json"), deadlineText(DEADLINE));
    assertEqual(readRecords(dir).deadline, DEADLINE, "bot/lib/listing-state.mjs does not read back what the tool wrote");
    const { report } = await validateTree(dir, { allowStaging: true });
    const mine = report.items.filter((i) => i.where === "policy/binding-deadline.json");
    assertEqual(mine.filter((i) => i.level === "error").map((i) => i.message).join(" | "), "",
      "tools/validate.mjs refuses the deadline the tool wrote");
    assert(mine.length === 0 || mine.every((i) => i.level !== "note" || !i.message.startsWith("absent")),
      "tools/validate.mjs reported the written deadline as absent");
  });

  // ── M-T5.3: markers ───────────────────────────────────────────────────────

  await test("the authoritative marker is the highest round present, not the most recently committed file", () => {
    // Round 2 re-committed AFTER round 3 (a later-branch re-send), so the
    // newest file is round 2's. Watched by keying the reader on committed_at.
    const two = m(R2, "2026-11-05T00:00:00Z");
    const three = m(R3, "2026-11-01T00:00:00Z");
    const { marker, problems } = authoritative([two, three]);
    assertEqual(problems.join(" | "), "", "two conforming markers were refused");
    assertEqual(marker?.doc.round, 3, "the reader took a marker other than the highest round");
    const dup = authoritative([m(R2), { ...m({ ...R2, sent_at: "2026-09-21T00:00:00Z" }), file: "log/migration-notice-9.json", nameRound: 9 }]);
    assert(dup.marker === null && dup.problems.length >= 1, "a second round-2 marker, or a file whose name is not its round, was ordered");
  });

  await test("a round writes one conforming marker, and every wrong turn MIG-13 names is refused", () => {
    const one = planRound({ markers: [], round: 1, sentAt: R1.sent_at, cutover: "2026-10-25T00:00:00Z" });
    assertEqual(one.problems.join(""), "", "round 1 was refused");
    assertEqual(JSON.stringify(parsed(one.writes[0])), JSON.stringify({ schema: NOTICE_SCHEMA, round: 1, sent_at: R1.sent_at }),
      "round 1's marker is not exactly schema, round and sent_at — B.4 never dates it, whatever the notice says");
    const refusals = [
      ["a second round 1", { markers: [m(R1)], round: 1, sentAt: R1.sent_at }, "committed once"],
      ["round 2 with no date", { markers: [m(R1)], round: 2, sentAt: R2.sent_at }, "from round 2"],
      ["round 3 before round 2", { markers: [m(R1)], round: 3, sentAt: R3.sent_at, cutover: R3.cutover_planned_at }, "in order"],
      ["round 2 again", { markers: [m(R1), m(R2)], round: 2, sentAt: R2.sent_at, cutover: R2.cutover_planned_at }, "re-send"],
      ["round 3 announcing a date round 2 does not", { markers: [m(R1), m(R2)], round: 3, sentAt: R3.sent_at, cutover: "2026-12-01T00:00:00Z" }, "n28"],
      ["a fourth round", { markers: [m(R1), m(R2), m(R3)], round: 4, sentAt: R3.sent_at, cutover: R3.cutover_planned_at }, "rounds"],
      ["a sent_at that is no moment", { markers: [], round: 1, sentAt: "2026-02-30T00:00:00Z" }, "§0.7"],
      // Contract 2.0.0: no interval before cutover, and still BEFORE it.
      ["round 2 sent once the date it announces has come", { markers: [m(R1)], round: 2, sentAt: "2026-10-25T00:00:00Z", cutover: "2026-10-25T00:00:00Z" }, "already come"],
    ];
    for (const [what, input, why] of refusals) {
      const p = planRound(input);
      assert(p.writes.length === 0 && p.problems.some((x) => x.includes(why)),
        `${what} was not refused for "${why}": ${JSON.stringify(p.problems)}`);
    }
    let threw = false;
    try { markerText({ round: 1, sent_at: R1.sent_at, accounts: ["x"] }); } catch { threw = true; }
    // markerText writes only the four members, so an extra one never reaches
    // the file; the schema's own refusal of `accounts` is migration-notice.mjs's.
    assert(!threw && !markerText({ round: 1, sent_at: R1.sent_at, accounts: ["x"] }).includes("accounts"),
      "a member outside the four reached a written marker");
  });

  await test("a re-send's branch is read from the dates: later keeps every sent_at, earlier is a new round 2", () => {
    // Round 3 sent early, before the re-send, so every date below is one a
    // real sequence could have: the re-send goes out at `at`, after round 3.
    const r3 = { ...R3, sent_at: "2026-09-26T00:00:00Z" };
    const markers = [m(R1), m(R2), m(r3)];
    const at = "2026-09-28T00:00:00Z";

    const later = planResend({ markers, cutover: "2026-11-01T00:00:00Z", at });
    assertEqual(later.branch, "later", "a later date did not take the later branch");
    assertEqual(later.writes.map((w) => w.file).join(","), "log/migration-notice-2.json,log/migration-notice-3.json",
      "the later branch did not re-commit every dated marker (n28: no marker announces a superseded date)");
    for (const w of later.writes) {
      const doc = parsed(w);
      const was = markers.find((x) => x.file === w.file).doc;
      assertEqual(doc.sent_at, was.sent_at, `${w.file} moved its sent_at on a later re-send, which moves the watch's clocks`);
      assertEqual(doc.cutover_planned_at, "2026-11-01T00:00:00Z", `${w.file} was re-committed without the new date`);
    }

    const earlier = planResend({ markers, cutover: "2026-10-10T00:00:00Z", at });
    assertEqual(earlier.branch, "earlier", "an earlier date did not take the earlier branch");
    const two = parsed(earlier.writes.find((w) => w.file === "log/migration-notice-2.json"));
    assertEqual(two.sent_at, at, "an earlier date re-committed round 2 with its old sent_at instead of sending a new round 2");
    const three = earlier.writes.find((w) => w.file === "log/migration-notice-3.json");
    assert(three, "round 3's marker was left announcing the abandoned date (n28)");
    assertEqual(parsed(three).cutover_planned_at, "2026-10-10T00:00:00Z", "round 3 was re-committed without the new date");
    assertEqual(parsed(three).sent_at, r3.sent_at, "round 3 was re-committed with a sent_at other than its own");

    const tooLate = planResend({ markers, cutover: "2026-11-05T00:00:00Z", at: "2026-11-06T00:00:00Z" });
    assert(tooLate.branch === null || tooLate.branch === "later", "a later date read as earlier");
    const pastEarlier = planResend({ markers, cutover: "2026-10-10T00:00:00Z", at: "2026-10-11T00:00:00Z" });
    assert(pastEarlier.writes.length === 0 && pastEarlier.problems.some((p) => p.includes("already come")),
      "a new round 2 announcing a date that had already come was written (MIG-13 at 2.0.0: sent before the date comes)");
    assertEqual(planResend({ markers, cutover: R2.cutover_planned_at, at }).writes.length, 0,
      "a re-send announcing the date already announced wrote a marker");
    assertEqual(planResend({ markers: [m(R1)], cutover: "2026-10-10T00:00:00Z", at }).branch, "undated",
      "a re-send before round 2 dated a marker that B.4 never dates");

    // The writer and the watch, held to each other: the tree a re-send leaves
    // is one on which the watch finds no superseded date.
    for (const plan of [later, earlier]) {
      const after = new Map(markers.map((x) => [x.file, x]));
      for (const w of plan.writes) after.set(w.file, m(parsed(w)));
      const verdict = judge({ deadline: null, cutoverOnMain: false, markers: [...after.values()], now: at });
      assert(!verdict.codes.includes(CODES.superseded) && !verdict.codes.includes(CODES.earlier),
        `the tree the ${plan.branch} branch leaves is one the watch alarms on: ${verdict.detail.join(" | ")}`);
    }
  });

  await test("every round of the notice states what MIG-14 requires, filled from the tree's values", () => {
    const doc = fs.readFileSync(path.join(REPO_ROOT, NOTICE_DOC), "utf8");
    for (const round of [1, 2, 3]) {
      const text = renderRound(doc, round, { deadline: DEADLINE, cutover: "2026-09-27T00:00:00Z", listings: ["knowledge-graph"] });
      for (const needle of ["2026-11-26", DEADLINE, "2026-09-27", "https://astra.minice.ai/plugins/knowledge-graph"]) {
        assert(text.includes(needle), `round ${round} rendered without ${needle}`);
      }
      assert(!/\{\{|\}\}/.test(text), `round ${round} left a placeholder`);
    }
    const unfixed = renderRound(doc, 1, { deadline: DEADLINE });
    assert(unfixed.includes("not fixed yet"), "round 1 with no cutover date does not say it is not fixed");
    for (const [what, fn] of [
      ["round 2 with no cutover date", () => renderRound(doc, 2, { deadline: DEADLINE })],
      ["a round with no deadline committed", () => renderRound(doc, 1, { deadline: null })],
      ["a template with an unknown placeholder", () => renderRound("<!-- notice:round-1 -->{{account_email}}<!-- /notice:round-1 -->", 1, { deadline: DEADLINE })],
      ["a template holding round 1 twice", () => roundTemplate(`${doc}\n<!-- notice:round-1 --><!-- /notice:round-1 -->`, 1)],
    ]) {
      let threw = false;
      try { fn(); } catch { threw = true; }
      assert(threw, `${what} rendered instead of refusing`);
    }
  });

  await test("an account whose repository takes no issues stops the round for it and becomes the owner's item", () => {
    const dir = path.join(tmp, "migration-recipients");
    const put = (rel, doc) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), JSON.stringify(doc));
    };
    put("publishers/team.json", { owner: "team", tier: "astra_team", covers: ["TeamOrg"] });
    put("plugins/alpha/plugin.json", { id: "alpha", source: { repo: "stranger/alpha" }, added_at: "2026-08-02" });
    put("plugins/beta/plugin.json", { id: "beta", source: { repo: "stranger/beta" }, added_at: "2026-08-01" });
    put("plugins/gamma/plugin.json", { id: "gamma", source: { repo: "other/gamma" }, added_at: "2026-08-03" });
    put("plugins/ours/plugin.json", { id: "ours", source: { repo: "teamorg/ours" }, added_at: "2026-08-01" });
    put("plugins/bound/plugin.json", { id: "bound", source: { repo: "third/bound" }, added_at: "2026-08-01" });
    put("plugins/bound/identity.json", { schema: "x" });
    put("plugins/gone/plugin.json", { id: "gone", source: { repo: "fourth/gone" }, added_at: "2026-08-01", unlisted: true });
    const accounts = recipients(dir);
    assertEqual(accounts.map((a) => `${a.account}:${a.target}:${a.listings.map((l) => l.id).join("+")}`).join(" "),
      "other:other/gamma:gamma stranger:stranger/beta:beta+alpha",
      "the recipients are not the unbound listed third-party accounts, each targeted at its earliest listing");

    const { reachable, ownerItems } = judgeIssuePaths(accounts, {
      "other/gamma": { has_issues: false, archived: false, private: false },
      "stranger/beta": { has_issues: true, archived: false, private: false },
    });
    assertEqual(reachable.map((a) => a.account).join(","), "stranger", "the reachable account was not the one whose repository takes issues");
    assertEqual(ownerItems.map((o) => `${o.account}:${o.listings.join("+")}`).join(","), "other:gamma",
      "an account whose repository has has_issues false was not stopped and handed to the owner");
    for (const [what, reading] of [
      ["an archived repository", { has_issues: true, archived: true, private: false }],
      ["a private repository", { has_issues: true, archived: false, private: true }],
      ["a repository nobody could read", null],
    ]) {
      const j = judgeIssuePaths(accounts.filter((a) => a.account === "stranger"), { "stranger/beta": reading });
      assertEqual(j.ownerItems.length, 1, `${what} was taken for an issue path`);
    }
  });

  // ── M-T5.4: the watch ─────────────────────────────────────────────────────

  await test("ROLL-63 (a), (b), (c): each fires at its threshold, and none keys on a commit's date", () => {
    const at = (now, over = {}) => judge({ deadline: DEADLINE, cutoverOnMain: false, markers: [m(R1)], now, ...over });
    const codesOf = (r) => r.codes.join(",");
    // (a) — 56 days away with no round 2; 67 days away is quiet.
    assert(at("2026-10-01T00:00:00Z").codes.includes(CODES.round2), "(a) did not fire 56 days before the deadline with no round 2");
    assertEqual(codesOf(at("2026-09-20T00:00:00Z")), "", "(a) fired 67 days before the deadline");
    // (a) with round 2 sent 67 days before, and RE-COMMITTED 47 days before
    // (a later-branch re-send). Quiet: it reads sent_at, never the commit.
    const recommitted = m({ ...R2, cutover_planned_at: "2026-11-01T00:00:00Z" }, "2026-10-10T00:00:00Z");
    assertEqual(codesOf(at("2026-10-15T00:00:00Z", { markers: [m(R1), recommitted], cutoverOnMain: true })), "",
      "(a) fired on a round 2 whose sent_at is 67 days before the deadline, because it was re-committed later");
    assert(at("2026-10-15T00:00:00Z", { markers: [m(R1), m({ ...R2, sent_at: "2026-10-10T00:00:00Z" })] }).codes.includes(CODES.round2),
      "(a) did not fire on a round 2 sent 47 days before the deadline");
    // (b) — 25 days away and no cutover marker; with one, quiet.
    assert(at("2026-11-01T00:00:00Z", { markers: [m(R1), m(R2)] }).codes.includes(CODES.cutover),
      "(b) did not fire 25 days before the deadline with no log/cutover.json");
    assert(!at("2026-11-01T00:00:00Z", { markers: [m(R1), m(R2)], cutoverOnMain: true }).codes.includes(CODES.cutover),
      "(b) fired with log/cutover.json on main");
    // (c) — 6 days away and no round 3; round 3 sent 25 days before is quiet.
    assert(at("2026-11-20T00:00:00Z", { markers: [m(R1), m(R2)], cutoverOnMain: true }).codes.includes(CODES.round3),
      "(c) did not fire 6 days before the deadline with no round 3");
    assertEqual(codesOf(at("2026-11-20T00:00:00Z", { markers: [m(R1), m(R2), m(R3)], cutoverOnMain: true })), "",
      "(c) fired with round 3 sent 25 days before the deadline");
    // No deadline: nothing to count down to, and it says so.
    const none = judge({ deadline: null, cutoverOnMain: false, markers: [], now: "2026-12-30T00:00:00Z" });
    assert(none.status === "green" && none.detail.some((d) => d.includes("nothing to count down to")),
      "with no deadline the watch did not say it had nothing to count");
    for (const code of Object.values(CODES)) {
      assert(new RegExp(CODE_PATTERN).test(code), `${code} is not a code the alarm channel will send`);
    }
  });

  await test("the two guards: an earlier date under the same sent_at, and a marker announcing a superseded date", () => {
    const S = R2.sent_at;
    const quiet = { deadline: null, cutoverOnMain: false, now: "2026-10-01T00:00:00Z" };
    const earlierSame = judge({ ...quiet, markers: [m(R1), m({ ...R2, cutover_planned_at: "2026-10-20T00:00:00Z" })],
      histories: { "log/migration-notice-2.json": [{ sent_at: S, cutover_planned_at: "2026-10-30T00:00:00Z" }, { sent_at: S, cutover_planned_at: "2026-10-20T00:00:00Z" }] } });
    assert(earlierSame.codes.includes(CODES.earlier), "a cutover moved earlier under the same sent_at did not alarm (n22)");
    const newRound2 = judge({ ...quiet, markers: [m(R1), m({ round: 2, sent_at: "2026-09-25T00:00:00Z", cutover_planned_at: "2026-10-20T00:00:00Z" })],
      histories: { "log/migration-notice-2.json": [{ sent_at: S, cutover_planned_at: "2026-10-30T00:00:00Z" }, { sent_at: "2026-09-25T00:00:00Z", cutover_planned_at: "2026-10-20T00:00:00Z" }] } });
    assert(!newRound2.codes.includes(CODES.earlier), "a new round 2 with its own sent_at was taken for the wrong turn");
    const laterSame = judge({ ...quiet, markers: [m(R1), m(R2)],
      histories: { "log/migration-notice-2.json": [{ sent_at: S, cutover_planned_at: "2026-10-20T00:00:00Z" }, { sent_at: S, cutover_planned_at: R2.cutover_planned_at }] } });
    assert(!laterSame.codes.includes(CODES.earlier), "a later date under the same sent_at, MIG-13's later branch, alarmed");

    const stale = judge({ ...quiet, markers: [m(R1), m({ ...R2, cutover_planned_at: "2026-11-01T00:00:00Z" }), m(R3)] });
    assert(stale.codes.includes(CODES.superseded), "round 2 announcing a date round 3 does not was not alarmed (n28)");
  });

  await test("the banner cross-check: the served page must carry the authoritative marker's date", () => {
    const base = { deadline: null, cutoverOnMain: false, markers: [m(R1), m(R2)], now: "2026-10-01T00:00:00Z" };
    const banner = (status, body) => ({ id: "knowledge-graph", url: "https://astra.minice.ai/plugins/knowledge-graph", status, body });
    assert(!judge({ ...base, banner: banner(200, "<p>Cutover on 2026-10-25.</p>") }).codes.length, "a banner carrying the date alarmed");
    const differs = judge({ ...base, banner: banner(200, "<p>Cutover on 2026-10-15.</p>") });
    assert(differs.codes.includes(CODES.bannerDiffers) && differs.ids.includes("knowledge-graph"),
      "a banner serving a date the authoritative marker does not carry was not alarmed");
    assert(judge({ ...base, banner: banner(404, null) }).codes.includes(CODES.bannerUnreachable), "a banner that did not load was not alarmed");
    assert(!judge({ ...base, markers: [m(R1)], banner: banner(404, null) }).codes.length,
      "the banner was judged before round 2, when MIG-13's banner shows no date");
  });
}
