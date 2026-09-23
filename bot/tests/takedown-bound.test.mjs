// The takedown bound's own canaries (registry plan M-T3.2).
//
// Every case is a real git repository built in a temp directory, for the same
// reason `bot/tests/moderation-coverage.test.mjs` is: the rule under test is a
// statement about HISTORY, and every interesting part of it — whether a
// listing was listed a commit ago, whether an advisory matched an id before it
// matched it now, whether a withdrawal happened inside a trailing 24 hours —
// is a comparison between a commit and its parent. A fixture that stubbed git
// would be a fixture of the stub.
//
// The canary list comes from M-T3.2 and each one is named as the plan words
// it, so that a reader who has the plan open can find the case that is missing
// rather than the case that is here. Beside each, the mutation it was watched
// failing under — in a throwaway clone, never in the tree:
//
//   at the bound it applies, at bound + 1 it holds      `>` for `>=`
//   two siblings count 2                                one id per advisory
//   an A_YANK counts 1, a removal request counts 1      skip `yank` triggers
//   three A_YANKs fill the bound, the next is held      exempt author actions
//   a Moderation-Exempt: advisory naming two counts 2   the Service-Decision: filter
//   a staging deprecate counts 0, BY ID                 drop the staging check
//   a MOD-52 revert counts 0                            count advisory-deleted
//
// And the window, which is `main`'s (gap 68's shape, found in this file by
// lane M on 2026-09-22):
//
//   a withdrawal merged from a long-lived branch        `--no-merges` for
//     counts at the merge; so does one through a        `--first-parent`, the
//     branch that merged main in, and one a merge       walk before the repair
//     commit carries itself
//   a first-parent commit dated before its parent       `--since` in place of
//     does not hide the withdrawals behind it           the per-commit filter
//   a first-parent line git cannot walk is unknown      `allowFailure: true`
//                                                       on the walk
//
// The last two are the contract's two exclusions and only two (TRUST-26), and
// the fifth is the whole of attack M-2: the counter that filtered on
// `Service-Decision:` returned 0 on the one day the registry was withdrawing
// by hand, and let a fourth withdrawal out unheld.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fixtureEnv } from "../../tools/lib/git-env.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { after } from "node:test";

import { holdKindFor } from "../lib/holds.mjs";
import { TAKEDOWN_BOUND } from "../lib/moderation.mjs";
import { WINDOW_HOURS, countWindow, idsMatchedBy, overBound } from "../lib/takedown-bound.mjs";

const tmpRoots = [];
after(() => {
  for (const dir of tmpRoots) fs.rmSync(dir, { recursive: true, force: true });
});

/** The clock every fixture is built against, so no case depends on the wall. */
const NOW = new Date("2026-09-20T12:00:00Z");
const hoursAgo = (h) => new Date(NOW.getTime() - h * 3600_000).toISOString();

// ── the fixture builder ─────────────────────────────────────────────────────

function fixture(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `astra-bound-${name}-`));
  tmpRoots.push(dir);
  const g = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: fixtureEnv(dir) });
  g("init", "-q", "-b", "main");
  g("config", "user.name", "Fixture");
  g("config", "user.email", "fixture@example.invalid");
  g("config", "commit.gpgsign", "false");

  const api = {
    dir,
    git: g,
    write(rel, content) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, typeof content === "string" ? content : `${JSON.stringify(content, null, 2)}\n`);
      return api;
    },
    remove(rel) { fs.rmSync(path.join(dir, rel), { force: true }); return api; },

    /** A listing. `unlisted` creates it already out of the catalogue (MOD-16's shape). */
    listing(id, { repo = `someone/${id}`, unlisted = false } = {}) {
      return api.write(`plugins/${id}/plugin.json`, {
        schema: "astra.registry.plugin/1",
        id,
        name: id,
        source: { kind: "github", repo },
        ...(unlisted ? { unlisted: true } : {}),
      });
    },
    /** A published version, optionally with an artifact digest a `digest` advisory can name. */
    version(id, version, { yanked = false, sha256 = null } = {}) {
      return api.write(`plugins/${id}/versions/${version}.json`, {
        schema: "astra.registry.version/1",
        id,
        version,
        ...(yanked ? { yanked: true } : {}),
        ...(sha256 ? { artifacts: { "linux-x64": { sha256, url: "https://example.invalid/a", filename: "a", size: 1 } } } : {}),
      });
    },
    advisory(number, entries, { action = "block_install" } = {}) {
      return api.write(`tools/revocations/ASTRA-2026-${number}.json`, {
        schema: "astra.registry.advisory/1",
        id: `ASTRA-2026-${number}`,
        action,
        severity: "high",
        entries,
      });
    },
    reserved(extra = {}) {
      return api.write("policy/reserved-ids.json", { reserved: [], reserved_prefixes: [], ...extra });
    },

    commit(message, { at = hoursAgo(1), authorAt = at } = {}) {
      g("add", "-A");
      execFileSync("git", ["-C", dir, "commit", "-q", "--allow-empty", "-m", message], {
        encoding: "utf8",
        env: { ...fixtureEnv(dir), GIT_AUTHOR_DATE: authorAt, GIT_COMMITTER_DATE: at },
      });
      return api;
    },

    checkout(...args) { g("checkout", "-q", ...args); return api; },

    /**
     * `git merge` at a fixed date — a pull request merged with a merge commit.
     * `noCommit` stops before committing, so a case can change the tree the
     * merge commit records (a conflict resolution) and then `commit()` it.
     */
    merge(branch, { at = hoursAgo(1), noCommit = false } = {}) {
      const how = noCommit ? ["--no-commit"] : ["-m", `Merge ${branch}`];
      execFileSync("git", ["-C", dir, "merge", "-q", "--no-ff", ...how, branch], {
        encoding: "utf8",
        env: { ...fixtureEnv(dir), GIT_AUTHOR_DATE: at, GIT_COMMITTER_DATE: at },
        stdio: ["ignore", "pipe", "pipe"],
      });
      return api;
    },

    /** GitHub's rebase merge: the branch's commit re-created on `main`, committed at `at`. */
    rebaseMerge(branch, { at = hoursAgo(1) } = {}) {
      execFileSync("git", ["-C", dir, "cherry-pick", branch], {
        encoding: "utf8",
        env: { ...fixtureEnv(dir), GIT_COMMITTER_DATE: at },
        stdio: ["ignore", "pipe", "pipe"],
      });
      return api;
    },

    /**
     * Two listed plugins, two listed siblings of one monorepo, and a staging
     * listing created unlisted — committed 30 hours ago, so the base is
     * OUTSIDE every window and no case counts its own setup. The history
     * shapes pass an older `at`, so a branch can be cut from it 37 hours ago
     * without a commit dated before its own parent.
     */
    base({ at = hoursAgo(30) } = {}) {
      api.reserved();
      api.listing("dice-roller").version("dice-roller", "0.1.1", { sha256: "a".repeat(64) });
      api.listing("text-utils").version("text-utils", "0.2.0");
      api.listing("web-chat", { repo: "mihailinl/AstraPlugins" });
      api.listing("echo-stt", { repo: "mihailinl/AstraPlugins" });
      api.listing("staging-probe", { unlisted: true });
      api.commit("base: five listings", { at });
      return api;
    },
  };
  return api;
}

const count = (repo, opts = {}) => countWindow(repo, { now: NOW, ...opts });

/** A moderator `block_install`, the decision every case below asks about. */
const blockInstall = { code: "M_REVOKE", action: "block_install", plugin_id: "text-utils" };

// ── the count, case by case ─────────────────────────────────────────────────

test("a clean window counts 0, and says what it looked at rather than only the number", () => {
  const f = fixture("clean").base();
  f.write("README.md", "# nothing withdrawn\n").commit("docs: a commit that takes nothing away");

  const got = count(f.dir);
  assert.equal(got.count, 0);
  assert.equal(got.unknown, null);
  // An examined-zero is never a clean bill of health, so a zero comes back with
  // the walk beside it: 1 commit read, HEAD named and dated. Without those two
  // numbers "nothing was withdrawn today" and "the walk read nothing" are the
  // same answer.
  assert.equal(got.examined, 1, got.detail.join("\n"));
  assert.ok(got.head?.sha && got.head?.at, `no HEAD reported beside the zero:\n${got.detail.join("\n")}`);
  assert.ok(got.detail.some((d) => d.includes("examined 1 commit")), got.detail.join("\n"));
});

test("a delist and a yank each count their listed plugin id once", () => {
  const f = fixture("delist-yank").base();
  f.listing("dice-roller", { unlisted: true }).commit("mod: delist dice-roller");
  f.version("text-utils", "0.2.0", { yanked: true }).commit("mod: yank text-utils@0.2.0");

  const got = count(f.dir);
  assert.deepEqual(got.ids.map((i) => i.id), ["dice-roller", "text-utils"]);
  assert.equal(got.count, 2);
});

test("two versions of one plugin yanked in one commit count 1, because the unit is a listed id", () => {
  // TRUST-26 counts listed plugin ids and FLOW-42 caps an account at one
  // listed plugin id, so the bound is a cap on how much of the catalogue can
  // be taken away — and taking one plugin away twice takes away one plugin.
  const f = fixture("two-versions").base();
  f.version("dice-roller", "0.1.2").commit("publish 0.1.2", { at: hoursAgo(26) });
  f.version("dice-roller", "0.1.1", { yanked: true, sha256: "a".repeat(64) })
    .version("dice-roller", "0.1.2", { yanked: true })
    .commit("mod: yank both dice-roller versions");

  assert.equal(count(f.dir).count, 1);
});

test("an advisory naming two listed siblings counts 2", () => {
  // The sibling case, and the mutation is one id per advisory: an `identity`
  // advisory against a monorepo withdraws every listed plugin published from
  // it, and a counter that stopped at the first would put the estate at 1 on a
  // day it took two plugins away.
  const f = fixture("siblings").base();
  f.advisory("0001", [{ kind: "identity", value: "github:mihailinl/AstraPlugins" }])
    .commit("mod: advise the monorepo\n\nModeration-Exempt: mihailin: supply-chain report");

  const got = count(f.dir);
  assert.deepEqual(got.ids.map((i) => i.id), ["echo-stt", "web-chat"], got.detail.join("\n"));
  assert.equal(got.count, 2);
});

test("a hand advisory under Moderation-Exempt: counts, which is the whole of attack M-2", () => {
  // The scenario, one day and not an edge: the operator hand-advises three
  // listed plugins after a supply-chain report, each commit carrying
  // `Moderation-Exempt:` and NO `Service-Decision:`. The counter that filtered
  // on that trailer returned 0, the fourth withdrawal applied at once, and
  // four reached installed copies inside 24 h.
  const f = fixture("hand-advisory").base();
  f.advisory("0002", [{ kind: "id", value: "dice-roller" }, { kind: "version_range", value: "text-utils", versions: { introduced: "0.0.0" } }])
    .commit("mod: hand advisory for two listings\n\nModeration-Exempt: mihailin: active report, before the drill");

  const got = count(f.dir);
  assert.equal(got.count, 2, got.detail.join("\n"));
  assert.ok(!f.git("log", "-1", "--format=%B").includes("Service-Decision"),
    "the fixture commit carries the trailer the old filter looked for, so it is not the M-2 case");

  // And the second half of the canary: with the bound at 3 the next
  // `block_install` is not held, and one more hand advisory puts it over.
  assert.equal(overBound(got, { bound: 3 }).over, false);
  assert.equal(holdKindFor(blockInstall, { overBound: overBound(got, { bound: 3 }).over }), null);

  f.advisory("0003", [{ kind: "id", value: "web-chat" }])
    .commit("mod: a third\n\nModeration-Exempt: mihailin: same report");
  const three = count(f.dir);
  assert.equal(three.count, 3, three.detail.join("\n"));
  assert.equal(overBound(three, { bound: 3 }).over, true);
  assert.equal(holdKindFor(blockInstall, { overBound: true }), "bound");
});

test("three author yanks from three listings fill the bound, and the next block_install is held", () => {
  // OPEN-OWNER-45's case, walked rather than argued. An applied `A_YANK`
  // writes `yanked: true` and is indistinguishable in the tree from a
  // moderator's yank, which is exactly what TRUST-26 requires — so there is
  // nothing here to exempt author actions from, and the mutation that would
  // break it is a trailer or an actor test this module deliberately has not
  // got.
  const f = fixture("author-yanks").base();
  f.version("web-chat", "1.0.0").version("echo-stt", "1.0.0").commit("publish", { at: hoursAgo(28) });
  f.version("dice-roller", "0.1.1", { yanked: true, sha256: "a".repeat(64) })
    .commit("yank dice-roller@0.1.1\n\nService-Decision: sd-1");
  f.version("web-chat", "1.0.0", { yanked: true }).commit("yank web-chat@1.0.0\n\nService-Decision: sd-2");
  f.version("echo-stt", "1.0.0", { yanked: true }).commit("yank echo-stt@1.0.0\n\nService-Decision: sd-3");

  const got = count(f.dir);
  assert.equal(got.count, 3, got.detail.join("\n"));
  const over = overBound(got, { bound: 3 });
  assert.equal(over.over, true, over.reason);
  assert.equal(holdKindFor(blockInstall, { overBound: over.over }), "bound");
});

test("an applied removal request counts 1, and a held one counts nothing, without the bot seeing an account", () => {
  // MOD-9 holds an `A_REMOVAL_REQUEST` for an unbound listing (`unbound_removal`)
  // and it never reaches the tree; a bound account's request is APPLIED, which
  // is a delist. So the tree reading gets TRUST-26's "a bound account's removal
  // request counts" right without the bot ever learning which account acted —
  // which it cannot (TRUST-37, DEC-7).
  const f = fixture("removal-request").base();
  f.listing("text-utils", { unlisted: true })
    .commit("delist text-utils on the author's removal request\n\nService-Decision: sd-9");

  assert.equal(count(f.dir).count, 1);
  assert.equal(holdKindFor({ code: "A_REMOVAL_REQUEST", plugin_id: "echo-stt" }, { listingBound: false }),
    "unbound_removal", "an unbound removal request is held, so it writes nothing for this counter to find");
});

test("a staging deprecate counts 0, by id and not by trailer", () => {
  // MOD-16's exclusion. The fixture's staging listing is also created
  // `unlisted`, which is a second reason it cannot be delisted — so the case
  // that proves the ID exclusion is an ADVISORY against it, which the id rule
  // is the only thing that stops.
  const f = fixture("staging").base();
  f.reserved({ staging_listing_id: "staging-probe" })
    .listing("staging-probe")
    .commit("R2: the staging listing, listed", { at: hoursAgo(29) });
  f.advisory("0004", [{ kind: "id", value: "staging-probe" }])
    .commit("mod: deprecate the staging listing\n\nService-Decision: sd-staging");

  const got = count(f.dir);
  assert.equal(got.count, 0, got.detail.join("\n"));
  assert.ok(got.detail.some((d) => d.includes("staging_listing_id")), got.detail.join("\n"));
});

test("with no staging_listing_id committed the exclusion excludes nothing, and says so", () => {
  // Written against the ABSENCE — and **the absence ended on 2026-09-22**, when
  // M-T2.1 landed `staging_listing_id` in `policy/reserved-ids.json` (`bf51592`).
  // The sentence here said "the key is not on `main` until M-T2.1 lands it" and
  // was falsified by M-T2.1 itself.
  //
  // THE TEST IS STILL RIGHT AND IS NOT ABOUT THE TREE. It builds a fixture with
  // no staging id and asserts the exclusion excludes nothing, which is a claim
  // about the code's behaviour on that input — true before M-T2.1 and true
  // after. What went stale is the sentence explaining WHY the case was worth
  // writing, and a stale reason is how a still-correct test gets deleted by
  // somebody tidying up after the thing it waited for.
  const f = fixture("no-staging").base();
  f.advisory("0005", [{ kind: "id", value: "dice-roller" }]).commit("mod: advise dice-roller");

  const got = count(f.dir);
  assert.equal(got.count, 1);
  assert.ok(got.detail.some((d) => d.includes("no staging_listing_id")), got.detail.join("\n"));
});

test("a MOD-52 revert counts 0, in all three shapes a revert takes", () => {
  // M-T3.2 calls this "the one place a trailer test is kept". There is no
  // revert trailer on `main` — `operator.yml` is unwritten and M-T3.5's revert
  // commit carries `Service-Decision:`, the same trailer a takedown carries —
  // and the exclusion needs none: a revert's tree change is the REMOVAL of a
  // withdrawal, and this counter counts only additions. All three shapes, so
  // the claim is measured rather than argued.
  const f = fixture("revert").base();
  f.listing("dice-roller", { unlisted: true })
    .version("text-utils", "0.2.0", { yanked: true })
    .advisory("0006", [{ kind: "id", value: "web-chat" }])
    .commit("mod: three withdrawals", { at: hoursAgo(27) });

  f.listing("dice-roller")                                   // relist: `unlisted` removed
    .version("text-utils", "0.2.0")                          // unyank
    .remove("tools/revocations/ASTRA-2026-0006.json")        // unrevoke: the advisory deleted
    .commit("operator: revert three decisions\n\nService-Decision: sd-revert");

  const got = count(f.dir);
  assert.equal(got.count, 0, got.detail.join("\n"));
  assert.ok(got.detail.some((d) => d.includes("gives a withdrawal back")), got.detail.join("\n"));
});

test("re-signing or narrowing an advisory counts nothing; only a NEW match is a withdrawal", () => {
  const f = fixture("narrow").base();
  f.advisory("0007", [{ kind: "id", value: "dice-roller" }, { kind: "id", value: "text-utils" }])
    .commit("mod: advise two", { at: hoursAgo(27) });

  f.advisory("0007", [{ kind: "id", value: "dice-roller" }])
    .commit("operator: narrow the advisory to the one plugin that was affected");

  assert.equal(count(f.dir).count, 0, "narrowing an advisory took nothing away and must cost nothing");
});

test("a listing created already unlisted is not a delist", () => {
  // The distinction `triggersOf` is reused for: a listing that was never
  // listed is not a listing that was taken away, and MOD-16's staging id is
  // exactly such a listing.
  const f = fixture("created-unlisted").base();
  f.listing("brand-new", { unlisted: true }).commit("land a plugin we are not ready to serve");

  assert.equal(count(f.dir).count, 0);
});

// ── the window ──────────────────────────────────────────────────────────────

test("the window is trailing and on committer date, so a withdrawal 25 hours ago is spent", () => {
  const f = fixture("window").base();
  f.listing("dice-roller", { unlisted: true }).commit("mod: delist, 25 hours ago", { at: hoursAgo(25) });
  f.listing("text-utils", { unlisted: true }).commit("mod: delist, 23 hours ago", { at: hoursAgo(23) });

  const got = count(f.dir);
  assert.deepEqual(got.ids.map((i) => i.id), ["text-utils"], got.detail.join("\n"));
  assert.equal(got.since, "2026-09-19T12:00:00Z");
  assert.equal(WINDOW_HOURS, 24);
});

// ── the window is `main`'s: a withdrawal is dated where main acquired it ─────
//
// TRUST-26 counts listed plugin ids delisted, yanked or newly advised in the
// trailing 24 h, and "listed" is `main`'s tree. A plugin delisted on a branch
// is still listed, and still served, until the branch lands — so the moment
// is the commit on HEAD's first-parent line that brought the change, and for
// a pull request merged with a merge commit that is the merge. Measured
// 2026-09-22 before the repair (`rev-list --no-merges --since`): the first
// three cases below counted 1 (of 2), 0 and 0.

/** A fixture whose base is 60 h old, so a branch can be cut from it 37 h ago. */
const oldBase = (name) => fixture(name).base({ at: hoursAgo(60) });

/** A delist of `id` written on branch `topic` 37 h ago, with `main` moving on meanwhile. */
function delistOnBranch(f, id) {
  f.checkout("-b", "topic");
  f.listing(id, { unlisted: true }).commit(`mod: delist ${id}, on a branch`, { at: hoursAgo(37) });
  f.checkout("main");
  f.write("docs/elsewhere.md", "main moves on while the pull request is open\n")
    .commit("docs: main moves on", { at: hoursAgo(30) });
  return f;
}

const parentsOf = (f, rev) => f.git("show", "-s", "--format=%P", rev).trim().split(" ").filter(Boolean).length;

test("a withdrawal merged from a long-lived branch counts at the merge", () => {
  // Lane M's measurement, 2026-09-22: a delist committed on a branch 37 h
  // before `now`, merged `--no-ff` 2 h before it, beside a direct delist an
  // hour old. Two plugins left the catalogue inside the window and the old
  // walk counted one — too permissive, on the shape every pull request here
  // merges with.
  const f = delistOnBranch(oldBase("merged-branch"), "text-utils");
  f.merge("topic", { at: hoursAgo(2) });
  f.listing("dice-roller", { unlisted: true }).commit("bot: delist dice-roller", { at: hoursAgo(1) });

  const merge = f.git("rev-parse", "HEAD^").trim();
  assert.equal(parentsOf(f, merge), 2, "text-utils did not arrive through a merge commit, so this is not the case");

  const got = count(f.dir);
  assert.deepEqual(got.ids.map((i) => i.id), ["dice-roller", "text-utils"], got.detail.join("\n"));
  assert.equal(got.count, 2);
  const why = got.ids.find((i) => i.id === "text-utils").why.join("; ");
  assert.ok(why.startsWith(merge.slice(0, 8)), `text-utils is not dated at the merge ${merge.slice(0, 8)}: ${why}`);

  // And it fills a bound the old count left room under.
  const over = overBound(got, { bound: 2 });
  assert.equal(over.over, true, over.reason);
  assert.equal(holdKindFor(blockInstall, { overBound: over.over }), "bound");
});

test("a withdrawal merged through a branch that had merged main in counts at the outer merge", () => {
  // Merging `origin/main` into a branch is this repository's rule on conflict,
  // so a branch reaching `main` can be a merge whose second parent is itself a
  // merge. The old walk skipped both merges, and the branch commit was outside
  // the window: 0.
  const f = delistOnBranch(oldBase("merged-main-in"), "dice-roller");
  f.checkout("topic").merge("main", { at: hoursAgo(20) }).checkout("main");
  f.merge("topic", { at: hoursAgo(2) });
  assert.equal(parentsOf(f, "HEAD^2"), 2, "the branch did not merge main in, so this is not the case");

  const got = count(f.dir);
  assert.deepEqual(got.ids.map((i) => i.id), ["dice-roller"], got.detail.join("\n"));
});

test("a withdrawal a merge commit carries itself counts at the merge", () => {
  // A conflict resolved in the merge, or any merge committed with its tree
  // changed: the delist is in no single-parent commit at all, so a
  // `--no-merges` walk cannot see it however it dates things. Measured before
  // the repair: 0.
  const f = oldBase("evil-merge");
  f.checkout("-b", "topic");
  f.write("docs/branch.md", "branch work\n").commit("docs: branch work", { at: hoursAgo(5) });
  f.checkout("main");
  f.merge("topic", { at: hoursAgo(2), noCommit: true });
  f.listing("dice-roller", { unlisted: true }).commit("Merge topic, delisting dice-roller in the resolution", { at: hoursAgo(2) });
  assert.equal(parentsOf(f, "HEAD"), 2, "the fixture made no merge commit, so this is not the case");

  const got = count(f.dir);
  assert.deepEqual(got.ids.map((i) => i.id), ["dice-roller"], got.detail.join("\n"));
});

test("a squash merge, a rebase merge and a bot direct push count at the commit that landed", () => {
  // The three shapes that were right before the repair and must stay right:
  // each lands as one single-parent commit on the first-parent line, committed
  // when it landed, whatever date the branch commit behind it carries.
  const squash = oldBase("squash");
  squash.checkout("-b", "topic");
  squash.listing("dice-roller", { unlisted: true }).commit("delist, on a branch", { at: hoursAgo(37) });
  squash.checkout("main");
  squash.git("merge", "-q", "--squash", "topic");
  squash.commit("mod: delist dice-roller (#1)", { at: hoursAgo(2), authorAt: hoursAgo(37) });

  const rebase = delistOnBranch(oldBase("rebase"), "dice-roller");
  rebase.rebaseMerge("topic", { at: hoursAgo(2) });

  const direct = oldBase("direct");
  direct.listing("dice-roller", { unlisted: true }).commit("bot: delist dice-roller", { at: hoursAgo(2) });

  for (const [shape, f] of [["squash", squash], ["rebase", rebase], ["direct", direct]]) {
    assert.equal(parentsOf(f, "HEAD"), 1, `${shape}: the fixture landed a merge commit, so this is not the case`);
    const got = count(f.dir);
    assert.deepEqual(got.ids.map((i) => i.id), ["dice-roller"], `${shape}:\n${got.detail.join("\n")}`);
  }
});

test("a branch that withdrew and restored a plugin before merging took nothing from main, and costs 0", () => {
  // The direction the repair makes more lenient, and the right one: the
  // listing never left `main`, and no installed copy ever lost it. The old
  // walk read the branch's delist commit, which was inside the window, and
  // counted 1.
  const f = oldBase("undone-on-branch");
  f.checkout("-b", "topic");
  f.listing("dice-roller", { unlisted: true }).commit("delist, on a branch", { at: hoursAgo(5) });
  f.listing("dice-roller").commit("relist, on the same branch", { at: hoursAgo(4) });
  f.checkout("main");
  f.write("docs/elsewhere.md", "main moves on\n").commit("docs: main moves on", { at: hoursAgo(3) });
  f.merge("topic", { at: hoursAgo(2) });

  const got = count(f.dir);
  assert.equal(got.count, 0, got.detail.join("\n"));
  assert.equal(got.examined, 2, `the walk did not read main's two commits in the window:\n${got.detail.join("\n")}`);
});

test("a first-parent commit dated before its parent does not hide the withdrawals behind it", () => {
  // Git stops a `--since` walk at the first commit older than the cut, so one
  // commit dated before its parent — clock skew, or `rebase
  // --committer-date-is-author-date` pushed as a fast-forward — would hide
  // every withdrawal under it. The window is applied per commit instead.
  const f = fixture("skew").base();
  f.listing("dice-roller", { unlisted: true }).commit("mod: delist dice-roller", { at: hoursAgo(7) });
  f.write("docs/skewed.md", "committed with an old date\n").commit("docs: an old committer date", { at: hoursAgo(48) });
  f.listing("text-utils", { unlisted: true }).commit("mod: delist text-utils", { at: hoursAgo(1) });

  const got = count(f.dir);
  assert.deepEqual(got.ids.map((i) => i.id), ["dice-roller", "text-utils"], got.detail.join("\n"));
});

test("a first-parent line git cannot walk is an unknown count, not a count of 0", () => {
  // The walk reads the whole first-parent line, so it reaches objects the old
  // `--since` walk stopped short of. A walk that fails must not become an
  // empty list: that is a count of 0 with no reason beside it, and a takedown
  // applied unheld. HEAD stays readable, so it is the walk that fails here.
  const f = fixture("unwalkable").base();
  f.write("docs/middle.md", "x\n").commit("docs: a middle commit", { at: hoursAgo(26) });
  f.listing("dice-roller", { unlisted: true }).commit("mod: delist dice-roller", { at: hoursAgo(2) });
  const oldest = f.git("rev-parse", "HEAD~2").trim();
  const object = path.join(f.dir, ".git", "objects", oldest.slice(0, 2), oldest.slice(2));
  assert.ok(fs.existsSync(object), `${oldest} is not a loose object here, so removing it would remove nothing`);
  fs.rmSync(object);
  f.git("show", "-s", "HEAD");

  const got = count(f.dir);
  assert.equal(got.count, null, got.detail.join("\n"));
  assert.match(got.unknown ?? "", /first-parent line cannot be walked/);
  assert.equal(overBound(got).over, true);
});

// ── what an unknown count does, which is the M-2 failure by another route ───

test("a shallow checkout is an unknown count, not a count of 0", () => {
  // A shallow clone has no parent for the oldest commit in the window, so
  // every withdrawal in it reads as a file created already withdrawn — which
  // is not a trigger, and would report green for a day spent taking plugins
  // away. The direction that holds a takedown is the direction a counter that
  // cannot see must take.
  const f = fixture("shallow").base();
  f.listing("dice-roller", { unlisted: true }).commit("mod: delist dice-roller");

  const shallowDir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-bound-shallow-clone-"));
  tmpRoots.push(shallowDir);
  execFileSync("git", ["clone", "-q", "--depth", "1", `file://${f.dir}`, shallowDir], { encoding: "utf8", env: fixtureEnv(shallowDir) });

  const got = count(shallowDir);
  assert.equal(got.count, null);
  assert.match(got.unknown, /shallow/);
  const over = overBound(got);
  assert.equal(over.over, true, over.reason);
  assert.match(over.reason, /cannot be counted/);
  assert.equal(holdKindFor(blockInstall, { overBound: over.over }), "bound");
});

test("an advisory kind that cannot be resolved to a listed id is unknown, never 0", () => {
  // Three of the seven kinds name something this registry does not record. A
  // withdrawal published under one of them is a real withdrawal, and reporting
  // 0 for it is attack M-2 arriving through the schema instead of the trailer.
  for (const entry of [
    { kind: "binary", value: "b".repeat(64) },
    { kind: "publisher_key", value: "key-1" },
  ]) {
    const f = fixture(`unresolved-${entry.kind}`).base();
    f.advisory("0008", [{ kind: "id", value: "dice-roller" }, entry]).commit(`mod: a ${entry.kind} advisory`);

    const got = count(f.dir);
    assert.equal(got.count, null, `${entry.kind} was resolved to a number:\n${got.detail.join("\n")}`);
    assert.ok(got.unknown.includes(entry.kind), got.unknown);
    assert.equal(overBound(got).over, true);
  }
});

test("a digest advisory IS resolved, against the artifact the listing published", () => {
  const f = fixture("digest").base();
  f.advisory("0009", [{ kind: "digest", value: "A".repeat(64) }]).commit("mod: withdraw the bad bytes");

  const got = count(f.dir);
  assert.deepEqual(got.ids.map((i) => i.id), ["dice-roller"], got.detail.join("\n"));
});

test("an advisory against an id nobody lists counts 0, and is not an unknown", () => {
  const f = fixture("unlisted-target").base();
  f.advisory("0010", [{ kind: "id", value: "never-listed" }, { kind: "id", value: "staging-probe" }])
    .commit("mod: advise something that is not in the catalogue");

  const got = count(f.dir);
  assert.equal(got.count, 0, got.detail.join("\n"));
  assert.equal(got.unknown, null);
});

// ── the predicate MOD-9 reads ───────────────────────────────────────────────

test("at the bound it applies, at bound + 1 it holds", () => {
  for (const bound of [1, 3]) {
    for (const used of [0, bound - 1]) {
      assert.equal(overBound(used, { bound }).over, false,
        `${used} withdrawals against a bound of ${bound} must still apply: the bound is how many may happen`);
      assert.equal(holdKindFor(blockInstall, { overBound: false }), null);
    }
    assert.equal(overBound(bound, { bound }).over, true,
      `with ${bound} withdrawal(s) already made against a bound of ${bound}, the next must wait for an ` +
      "operator (TRUST-26, MOD-9)");
    assert.equal(overBound(bound + 1, { bound }).over, true);
  }
});

test("a reversal is never held for the bound, however full it is", () => {
  // Holding a relist behind a full takedown bound would mean the bound made
  // the estate harder to un-break. `bot/lib/holds.mjs` owns the rule; this
  // asserts the pair, because the bound is the input that would break it.
  for (const code of ["M_RELIST", "M_UNREVOKE"]) {
    assert.equal(holdKindFor({ code, plugin_id: "text-utils" }, { overBound: true }), "reversal");
  }
});

test("the default bound is the constant, and the constant is what POLICY.md publishes", () => {
  // One statement of the number. The pair with the document is
  // `bot/tests/policy.test.mjs`; this only asserts that the predicate reads
  // the same constant rather than carrying a second copy of it.
  assert.equal(overBound(TAKEDOWN_BOUND).over, true);
  assert.equal(overBound(TAKEDOWN_BOUND - 1).over, false);
});

// ── the entry → listed ids map, on its own ──────────────────────────────────

test("every kind the daemon reads is either mapped to listed ids or named as unresolvable", () => {
  // The exemption list, rather than a silence: a kind added to
  // `tools/lib/revocations.mjs` arrives here as a one-line answer to "does
  // this withdraw a listed id, and how do we know?" instead of as a zero.
  const listed = new Map([
    ["dice-roller", { kind: "github", repo: "someone/dice-roller" }],
    ["web-chat", { kind: "github", repo: "mihailinl/AstraPlugins" }],
    ["echo-stt", { kind: "github", repo: "mihailinl/AstraPlugins" }],
  ]);
  const digests = new Map([["c".repeat(64), "dice-roller"]]);

  const cases = [
    [{ kind: "id", value: "dice-roller" }, ["dice-roller"], null],
    [{ kind: "id_version", value: "dice-roller@0.1.1" }, ["dice-roller"], null],
    [{ kind: "version_range", value: "dice-roller" }, ["dice-roller"], null],
    [{ kind: "identity", value: "github:mihailinl/AstraPlugins" }, ["web-chat", "echo-stt"], null],
    [{ kind: "identity", value: "origin:example.invalid" }, [], null],
    [{ kind: "digest", value: "C".repeat(64) }, ["dice-roller"], null],
    [{ kind: "binary", value: "d".repeat(64) }, [], /entry\.command/],
    [{ kind: "publisher_key", value: "key-1" }, [], /signer_key_id/],
    [{ kind: "invented-tomorrow", value: "x" }, [], /not one this counter maps/],
  ];
  for (const [entry, ids, unresolved] of cases) {
    const got = idsMatchedBy(entry, { listed }, digests);
    assert.deepEqual(got.ids.sort(), [...ids].sort(), `${entry.kind} matched ${got.ids.join(", ")}`);
    if (unresolved) assert.match(got.unresolved ?? "", unresolved);
    else assert.equal(got.unresolved, null, `${entry.kind}: ${got.unresolved}`);
  }
});

test("an origin: advisory is unknown as soon as a listing stops being a GitHub source", () => {
  // `schema/plugin-v1.json` pins `source.kind` to the const `github`, which is
  // why `origin:` resolves to zero today. This asks the LISTINGS rather than
  // the schema, so the day one stops being a GitHub source the answer becomes
  // unknown instead of quietly staying zero.
  const listed = new Map([["sideloaded", { kind: "tarball", repo: null }]]);
  const got = idsMatchedBy({ kind: "identity", value: "origin:example.invalid" }, { listed });
  assert.deepEqual(got.ids, []);
  assert.match(got.unresolved ?? "", /origin host/);
});
