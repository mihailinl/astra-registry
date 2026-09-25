// The releases feed, and the guard on the cut that gave it a module of its own.
//
//     node --test bot/tests/poll.test.mjs
//
// Registry plan B-T2.6. `pollFeed` came out of `bot/watch.mjs` and
// `parseReleasesAtom` out of `bot/lib/notify.mjs`, unchanged, into
// `bot/lib/poll.mjs`, so that the poll's remaining rules — the prefix filter's
// memory, the HMAC-signed Actions cache, the `git ls-remote` sweep — have one
// file to be written in rather than two that three other modules import.
//
// ── why half of this file is about the move and not about the feed ─────────
//
// A split is the dangerous kind of change here, and this repository has said
// why twice: **a function that stops being imported is behaviour that stopped
// running with nobody deciding that it should.** `bot/lib/policy.mjs`'s seven
// submodules and `tools/selftest.mjs`'s twenty-one both carry the same guard
// for it, and both carry it as a list of NAMES. A count cannot do this job —
// one version of the selftest guard let a copy-paste shadow a module while the
// number a reader checks went UP, `PASS 189 passed, 0 failed`, eighteen checks
// gone.
//
// So the first six tests below are the equivalent for this cut, and they are
// the reason this file exists at all:
//
//   * the three surfaces, each pinned as its own ordered list of names, so
//     that neither a name leaking out of `poll.mjs` into the barrel nor a name
//     quietly dropped from it can happen without a red;
//   * the pre-split UNION — the sixteen names `notify.mjs` and `watch.mjs`
//     exported the hour before the cut — every one of which must still be
//     exported by one of the three modules. That is the list that is identical
//     across the cut; the three above say which side of it each name is on;
//   * the two functions moved and were not COPIED: exactly one definition of
//     each in the tree, and it is in `poll.mjs`;
//   * every module under `bot/lib/` is imported by something other than
//     itself, which is the "every module in the directory is imported" half.
//     A new file that nothing imports is the loss a surface pin cannot see:
//     the names are all present, on a module nobody loads.
//
// Each scan asserts a floor on what it found before it asserts anything about
// what it found there, because a glob that matched nothing reads exactly like
// compliance (dev/couplings.md, "Adding a coupling", step 4).

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cleanEnv } from "../../tools/lib/git-env.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import * as poll from "../lib/poll.mjs";
import * as notify from "../lib/notify.mjs";
import * as watch from "../watch.mjs";
import { parseReleasesAtom, pollFeed } from "../lib/poll.mjs";
// The OTHER tag predicate. Imported here so that the two are compared in one
// place rather than each pinned alone; see the last test in this file.
import { safeTag } from "../lib/safe.mjs";
import { loadRecords, loadSources } from "../../tools/lib/sources.mjs";
// B-T5.0: the jobs' side of the same rules, and the relay that sends BOT-87's verdict.
import * as run from "../lib/poll-run.mjs";
import { relayedVerdict } from "../lib/relay-verdict.mjs";
import { claimJob, POLL_MODES } from "../lib/service-jobs.mjs";

const REPO_ROOT = path.resolve(import.meta.dirname, "..", "..");

// ── the tree, read the way every other scan in this repository reads it ────
//
// `git ls-files`, not `readdirSync`: a walk of the working tree returns
// `bot/manifest-probe/target/` on a developer's machine and not in CI, and a
// floor measured against build output is a floor measured against nothing
// (tools/selftest/repo-rules.mjs found that out by going red on the commit
// that added it). Loud on failure rather than empty, for the same reason.
function trackedModules() {
  let listed;
  try {
    listed = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z", "*.mjs"], {
      encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
      env: cleanEnv(),
    });
  } catch (e) {
    throw new Error(
      `\`git ls-files\` failed in ${REPO_ROOT}, so every scan in this file would have found nothing and passed: ` +
      String(e.stderr || e.message).trim(),
    );
  }
  return listed.split("\0").filter(Boolean).sort();
}

// ───────────────────────────────────────────────────────────────────────────
// The cut
// ───────────────────────────────────────────────────────────────────────────

// The new module's own surface. Three names and no more: `isUsableTag` is here
// because both parsers need it and `notify.mjs` imports from this file, so a
// second copy is the only alternative to moving it (dev/couplings.md's whole
// subject). It is exported and it is NOT in the barrel, which is the pair of
// statements that keeps one copy without widening what five importers see.
// Three names from the cut, and B-T2.6's rules after it (2026-09-24): the poll,
// the signed memory, the sweep and BOT-87's alarm. Every name is still pinned,
// because the barrel rule above is unchanged: none of them may leak into
// `bot/lib/notify.mjs`.
// The three functions the cut MOVED here. The single-definition scan below is
// about them; the constants and functions B-T2.6 wrote here afterwards were
// never anywhere else.
const MOVED = ["isUsableTag", "parseReleasesAtom", "pollFeed"];

const POLL_SURFACE = [
  "BOT_87_CODES",
  "MEMORY_FILE",
  "MEMORY_SCHEMA",
  "POLL_INTERVAL_SECONDS",
  "POLL_STALE_INTERVALS",
  "SEAL_SCHEMA",
  "STATE_ENVIRONMENT",
  "STATE_KEY_ENV",
  "STATE_KEY_MIN_BYTES",
  "SWEEP_CHECK",
  "TERMINAL_STATES",
  "bot74Prefix",
  "bot87Verdict",
  "isUsableTag",
  "loadMemory",
  "lsRemoteTags",
  "matchesPrefix",
  "memoryProblem",
  "newMemory",
  "newestListedVersion",
  "openMemory",
  "parseLsRemoteTags",
  "parseReleasesAtom",
  "pollFeed",
  "pollListing",
  "pollableListings",
  "rememberMemory",
  "rememberPoll",
  "runPoll",
  "runSweep",
  "sealMemory",
  "seedFromReleasesSeen",
  "staleListings",
  "stateKey",
  "sweepListing",
  "tagVerdict",
];

// What `bot/lib/notify.mjs` exported at 8e4c0a1, the commit before B-T2.6,
// read out of the module rather than off the plan. Twelve names; `notify.mjs`
// still exports twelve, `parseReleasesAtom` through a re-export.
const NOTIFY_SURFACE = [
  "SEEN_FILE",
  "WATCH_AFTER_DAYS",
  "WATCH_BATCH",
  "findListingByRepo",
  "firstWrittenLine",
  "newReleases",
  "parseReleasePing",
  "parseReleasesAtom",
  "readSeen",
  "resolveSubmitter",
  "serialiseSeen",
  "watchPlan",
];

// And what `bot/watch.mjs` exports now. B-T2.6 took `pollFeed` out;
// `recordedTagsByRepo` joined with B-T3.9, so the backstop and the `/release`
// ping read one derivation of a repository's recorded tags (BOT-74). Cutover
// commit D (registry plan B-T5.2) deleted the backstop and the ping, and with
// them `runWatch`, `bot74Filter` and `recordedTagsByRepo`: the drain is all
// that is left, until commit E deletes the file.
const WATCH_SURFACE = ["runDrain"];

// ── the list that is identical across the cut ─────────────────────────────
//
// The sixteen names `bot/lib/notify.mjs` and `bot/watch.mjs` exported the hour
// before B-T2.6, written out again rather than composed from the three lists
// above, and **that independence is the whole check**. The first version of
// this constant was `NOTIFY_SURFACE ∪ WATCH_SURFACE_BEFORE`, which asserted
// nothing the per-module pins did not: every edit that moved a name also
// edited the list it was being compared against. Derived from them it fires
// only when it is already firing somewhere else.
//
// Written out, it survives the edit the per-module pins are supposed to
// accommodate. A later task moves `newReleases` from `notify.mjs` to
// `poll.mjs`, updates both pins, and forgets to export it at the far end: both
// pins are green about their own files and this one says the name is gone from
// all three. That is the case, and it is the only one.
//
// A name leaves this list when it is RETIRED on purpose, in the commit that
// retires it, where a reviewer reads the removal as the decision it is.
// Cutover commit D retired two: `runWatch`, the release backstop the cutover
// paused and the poll replaced, and `bot74Filter`, its tag-prefix filter
// (`bot/lib/poll.mjs` carries the poll's own, BOT-74).
const SURFACE_BEFORE_THE_CUT = [
  "SEEN_FILE",
  "WATCH_AFTER_DAYS",
  "WATCH_BATCH",
  "findListingByRepo",
  "firstWrittenLine",
  "newReleases",
  "parseReleasePing",
  "parseReleasesAtom",
  "pollFeed",
  "readSeen",
  "resolveSubmitter",
  "runDrain",
  "serialiseSeen",
  "watchPlan",
];

test("bot/lib/poll.mjs exports exactly the names the cut gave it", () => {
  assert.equal(Object.keys(poll).sort().join(", "), POLL_SURFACE.join(", "),
    "bot/lib/poll.mjs's surface has moved. A name added here is a name bot/lib/notify.mjs's barrel may start " +
    "carrying by accident; a name gone is behaviour that stopped running for whoever imported it");
});

test("bot/lib/notify.mjs still exports exactly what it exported before the cut", () => {
  assert.equal(Object.keys(notify).sort().join(", "), NOTIFY_SURFACE.join(", "),
    "bot/lib/notify.mjs's surface changed across a move that was supposed to leave it alone. Missing means the " +
    "re-export of parseReleasesAtom is gone and five importers break at once; extra means poll.mjs's internals " +
    "— isUsableTag is the candidate — leaked into a barrel five files read");
});

test("bot/watch.mjs exports exactly the drain, and not pollFeed", () => {
  assert.equal(Object.keys(watch).sort().join(", "), WATCH_SURFACE.join(", "),
    "bot/watch.mjs's surface is not the one cutover commit D left: the drain alone. A name back here is the " +
    "backstop or the issue path returning, which commit D deleted");
  assert.ok(!Object.keys(watch).includes("pollFeed"),
    "bot/watch.mjs exports pollFeed again. The whole point of the move is that bot/lib/poll.mjs owns it");
});

// The three pins above say which module holds each name today. This one says
// that no name fell between them.
test("every name that existed before the cut is still exported by one of the three modules", () => {
  assert.equal(SURFACE_BEFORE_THE_CUT.length, 14,
    `the pre-cut surface is ${SURFACE_BEFORE_THE_CUT.length} names: it was 16 on 2026-09-20, and cutover commit D ` +
    "retired runWatch and bot74Filter with the backstop. This list is not " +
    "an inventory of today's exports — it is what the backstop exported before the split, and it shrinks only " +
    "when a name is retired on purpose");
  const after = new Set([...Object.keys(poll), ...Object.keys(notify), ...Object.keys(watch)]);
  const lost = SURFACE_BEFORE_THE_CUT.filter((n) => !after.has(n));
  assert.equal(lost.join(", "), "",
    "a name the backstop exported before B-T2.6 is exported by none of bot/lib/poll.mjs, bot/lib/notify.mjs or " +
    "bot/watch.mjs. It did not move between them, it went");
});

// Moved, not copied. The needles are BUILT from the names rather than written
// out, so this file cannot be its own hit and needs no exclusion — the
// spelling `function pollFeed(` never appears in it. That is the belt-and-
// braces `tools/selftest/repo-rules.mjs` uses for the same shape of scan, and
// it is worth more than an exclusion list, because an exclusion is a refusal
// every caller reads as "nothing to check here".
test("the moved functions have exactly one definition each, and it is in bot/lib/poll.mjs", () => {
  const files = trackedModules();
  assert.ok(files.length >= 70,
    `the scan found ${files.length} tracked .mjs files and there were 141 on 2026-09-20; this is a broken walk ` +
    "rather than a smaller repository, and a scan over nothing finds no duplicate and passes");
  const OWNER = "bot/lib/poll.mjs";
  const problems = [];
  for (const name of MOVED) {
    const needle = new RegExp(`(?:^|\\s)(?:export\\s+)?(?:async\\s+)?function\\s+${name}\\s*\\(`);
    const sites = files.filter((rel) => needle.test(fs.readFileSync(path.join(REPO_ROOT, rel), "utf8")));
    if (sites.length !== 1 || sites[0] !== OWNER) {
      problems.push(`${name} is defined in ${sites.join(", ") || "nowhere"} and must be defined only in ${OWNER}`);
    }
  }
  assert.equal(problems.join("; "), "",
    "a function B-T2.6 moved is defined somewhere else as well, or not where it was moved to. A move that leaves " +
    "the old copy behind is the fact-in-two-places bug dev/couplings.md exists for, and here both copies parse a " +
    "stranger's feed");
});

// The half a surface pin is blind to. Every name can be present, on a module
// nothing loads: `checkModuleSet` in tools/selftest.mjs exists for exactly that
// shape, and this is its equivalent one directory over. It is scoped to
// `bot/lib/` rather than to the whole tree because an entry point is SUPPOSED
// to have no importer.
test("every module under bot/lib/ is imported by something other than itself", () => {
  const files = trackedModules();
  const imported = new Set();
  for (const rel of files) {
    const text = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
    // `from "./x.mjs"`, `import("./x.mjs")` and `export … from "./x.mjs"` all
    // read the same way here: a relative specifier resolved against the file
    // that names it. A bare specifier cannot name a file in this repository —
    // there are no dependencies and no import map.
    for (const m of text.matchAll(/(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/g)) {
      const target = path.normalize(path.join(path.dirname(rel), m[1]));
      if (target !== path.normalize(rel)) imported.add(target);
    }
  }
  // `git ls-files` reports forward slashes on every platform, so the prefix is
  // written the way git writes it rather than the way this process joins paths.
  const libs = files.filter((rel) => rel.startsWith("bot/lib/"));
  assert.ok(libs.length >= 20,
    `the scan found ${libs.length} modules under bot/lib/ and there were 34 on 2026-09-20 with poll.mjs in it; ` +
    "this is a broken walk, and a loop over nothing finds no orphan and passes");
  assert.ok(libs.some((rel) => rel.endsWith("poll.mjs")),
    "bot/lib/poll.mjs is not in `git ls-files`. An untracked module is a module CI never sees, and every check " +
    "in this file that scans the tree would be asking its questions about a file that is not there");
  const orphans = libs.filter((rel) => !imported.has(path.normalize(rel)));
  assert.equal(orphans.join(", "), "",
    "a module under bot/lib/ is imported by nothing. Whatever it holds has stopped running, and an unimported " +
    "module is indistinguishable from a module with nothing to say");
});

// ───────────────────────────────────────────────────────────────────────────
// The feed parse
// ───────────────────────────────────────────────────────────────────────────

const REPO = "someone/quiet";

/** One `<entry>`, the shape GitHub's `releases.atom` actually emits. */
const entry = (href, updated = "2026-08-08T10:00:00Z", title = "a release") =>
  `  <entry>\n    <updated>${updated}</updated>\n` +
  `    <link rel="alternate" type="text/html" href="${href}"/>\n    <title>${title}</title>\n  </entry>\n`;

const feed = (...entries) =>
  `<?xml version="1.0" encoding="UTF-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">\n${entries.join("")}</feed>\n`;

const tagUrl = (tag, repo = REPO) => `https://github.com/${repo}/releases/tag/${tag}`;

test("a feed that answers with another repository's releases contributes nothing", () => {
  const xml = feed(
    entry(tagUrl("v0.3.0")),
    entry(tagUrl("v9.9.9", "attacker/elsewhere")),
    // The near miss, because the check is a prefix match on a lowercased URL:
    // a path that merely STARTS with the repository's name is a different
    // repository, and the tag it yields would be fetched from it.
    entry(tagUrl("v8.8.8", "someone/quiet-evil")),
  );
  assert.deepEqual(parseReleasesAtom(xml, REPO).map((e) => e.tag), ["v0.3.0"],
    "the tag comes out of a URL and a later ingest turns that URL into an API call, so a feed that could smuggle " +
    "another repository's tag in would be choosing which repository gets checked");
});

test("the order the feed gives is the order that comes out, newest first", () => {
  const xml = feed(
    entry(tagUrl("v0.3.0"), "2026-08-08T10:00:00Z"),
    entry(tagUrl("v0.2.0"), "2026-01-01T10:00:00Z"),
  );
  const entries = parseReleasesAtom(xml, REPO);
  assert.deepEqual(entries.map((e) => e.tag), ["v0.3.0", "v0.2.0"]);
  assert.equal(entries[0].updated, "2026-08-08T10:00:00Z");
  assert.equal(entries[0].title, "a release", "four fields, and the title is one of them");
});

test("a percent-encoded tag is decoded, and a broken encoding is skipped rather than thrown", () => {
  // Git permits a slash in a tag, so GitHub encodes it in the link.
  const ok = parseReleasesAtom(feed(entry(tagUrl("release%2F2026-08"))), REPO);
  assert.deepEqual(ok.map((e) => e.tag), ["release/2026-08"]);

  // `%zz` makes `decodeURIComponent` throw. One malformed entry must not take
  // the rest of the feed with it: the poll would then report zero releases for
  // a repository that has some, which is silence that reads like quiet.
  const mixed = parseReleasesAtom(feed(entry(tagUrl("v0.3.0%zz")), entry(tagUrl("v0.4.0"))), REPO);
  assert.deepEqual(mixed.map((e) => e.tag), ["v0.4.0"]);
});

test("a tag that is a path traversal is refused at the door", () => {
  const xml = feed(entry(tagUrl("..%2F..%2Fevil")), entry(tagUrl("v0.4.0")));
  assert.deepEqual(parseReleasesAtom(xml, REPO).map((e) => e.tag), ["v0.4.0"],
    "`../../evil` satisfies the tag charset and is a path. It reaches nothing downstream today, and that is three " +
    "encoders' worth of assumption rather than a refusal");
  assert.equal(poll.isUsableTag("../../evil"), false);
  assert.equal(poll.isUsableTag("-rf"), false, "a tag that would be read as a flag");
  assert.equal(poll.isUsableTag("release/2026-08"), true, "and a slash on its own is a legitimate tag");
});

// ───────────────────────────────────────────────────────────────────────────
// The two tag predicates, compared (dev/couplings.md 26)
// ───────────────────────────────────────────────────────────────────────────
//
// This bot validates a tag in two places with two answers. `isUsableTag`
// (above) guards the feed; `safeTag` (`bot/lib/safe.mjs`) parses the
// `/approve owner/repo@tag` a maintainer types. They share one charset —
// `tools/lib/tags.mjs`'s `TAG_PATTERN`, which both import — and `isUsableTag`
// refuses four shapes on top of it. That is deliberate and `safeTag`'s docblock
// says why; what neither file could say before this test is that the difference
// is *these four and no others*, because nothing had ever run the two against
// each other.
//
// The test is written to fail from either side. Loosen `isUsableTag` and a
// shape stops disagreeing; tighten `safeTag` — the owner-gated change this
// register entry deliberately declined — and the same shape stops disagreeing
// from the other end. Either way the failure names the function that did NOT
// move, which is the thing a reader arriving at one file needs and cannot get
// from it.

/** True for exactly the four shapes `isUsableTag` refuses over the charset. */
const HARDENED_AGAINST = {
  "contains `..`": (s) => s.includes(".."),
  "a leading `/`": (s) => s.startsWith("/"),
  "a trailing `/`": (s) => s.endsWith("/"),
  "a leading `-`": (s) => s.startsWith("-"),
};

/** `safeTag` returns the tag or null; `isUsableTag` returns a boolean. */
const bothVerdicts = (s) => [safeTag(s) !== null, poll.isUsableTag(s) === true];

test("the four shapes `isUsableTag` refuses and `safeTag` accepts, one at a time", () => {
  // One witness per shape, chosen so that NO other shape explains it: each of
  // the four has to be carrying its own weight, or three of them are decoration
  // and a reader who deletes one learns nothing.
  const witnesses = {
    "contains `..`": "a..b",
    "a leading `/`": "/a",
    "a trailing `/`": "a/",
    "a leading `-`": "-a",
  };

  for (const [shape, tag] of Object.entries(witnesses)) {
    const explains = Object.entries(HARDENED_AGAINST).filter(([, p]) => p(tag)).map(([k]) => k);
    assert.deepEqual(explains, [shape],
      `${JSON.stringify(tag)} was chosen as the witness for ${shape} alone, and now ${explains.length} ` +
      "shapes match it — it can no longer show that this shape is load-bearing");

    const [safeTakesIt, pollTakesIt] = bothVerdicts(tag);
    assert.equal(safeTakesIt, true,
      `bot/lib/safe.mjs's safeTag now REFUSES ${JSON.stringify(tag)} (${shape}). If that was deliberate, it is a ` +
      "change to what `/approve owner/repo@tag` accepts from a maintainer — an owner's call, per dev/couplings.md " +
      "26 — and bot/lib/poll.mjs's isUsableTag no longer has a difference to be the stricter half of");
    assert.equal(pollTakesIt, false,
      `bot/lib/poll.mjs's isUsableTag now ACCEPTS ${JSON.stringify(tag)} (${shape}). It is the hardened predicate ` +
      "on the feed path; bot/lib/safe.mjs's safeTag is charset-only and did not change, so this shape now " +
      "reaches the ingest from a stranger's releases feed with nothing refusing it");
  }

  // The control. A legitimate tag with a slash in the middle, and a plain one,
  // are accepted by BOTH — without these the test above would still pass if
  // isUsableTag simply refused everything.
  for (const good of ["release/2026-08", "v1.0.0", "a"]) {
    assert.deepEqual(bothVerdicts(good), [true, true],
      `${JSON.stringify(good)} is an ordinary tag and both predicates must take it`);
  }
});

test("and nothing else: the two predicates agree on every other tag", () => {
  // Exhaustive over the characters that can matter — one letter, one digit, and
  // every structural character in the charset — to length four. That is small
  // enough to run in milliseconds and large enough to contain every arrangement
  // of leading, trailing, doubled and interior structure.
  const alphabet = ["a", "0", ".", "/", "-", "_"];
  const corpus = [];
  (function grow(prefix, depth) {
    if (prefix) corpus.push(prefix);
    if (depth === 0) return;
    for (const c of alphabet) grow(prefix + c, depth - 1);
  })("", 4);
  corpus.push("", "release/2026-08", "v1.0.0", "../../evil", "-rf", "a".repeat(128), "a".repeat(129),
    "v1@0", "релиз-1.2.0", "a b");

  assert.ok(corpus.length > 1500,
    `the corpus generator produced ${corpus.length} tags; a sweep over nothing passes every assertion below`);

  const unexplained = [];
  const onlyExplainedBy = new Map(Object.keys(HARDENED_AGAINST).map((k) => [k, 0]));
  const backwards = [];
  let disagreements = 0;

  // Direction is decided BEFORE the shapes are consulted, and each bucket holds
  // one direction only. Written the other way round once, and it cost the
  // reading: a mutation that made `isUsableTag` looser was caught by the
  // `unexplained` assertion, whose message says "taken by safeTag and refused
  // by isUsableTag" — the opposite of what had happened — while the assertion
  // that exists to say so was never reached.
  for (const tag of new Set(corpus)) {
    const [safeTakesIt, pollTakesIt] = bothVerdicts(tag);
    if (safeTakesIt === pollTakesIt) continue;
    disagreements += 1;
    if (pollTakesIt) {
      backwards.push(tag);
      continue;
    }
    const explains = Object.entries(HARDENED_AGAINST).filter(([, p]) => p(tag)).map(([k]) => k);
    if (explains.length === 0) unexplained.push(tag);
    if (explains.length === 1) onlyExplainedBy.set(explains[0], onlyExplainedBy.get(explains[0]) + 1);
  }

  assert.ok(disagreements > 500,
    `only ${disagreements} of ${new Set(corpus).size} tags told the two predicates apart. They are supposed to ` +
    "differ on a large share of this corpus; this few means one of them stopped being called, or both now answer " +
    "the same way and dev/couplings.md 26 has been closed by accident rather than by decision");

  assert.deepEqual(backwards, [],
    `${backwards.length} tag(s) are now ACCEPTED by bot/lib/poll.mjs's isUsableTag and REFUSED by ` +
    "bot/lib/safe.mjs's safeTag. isUsableTag is supposed to be the stricter of the two in every case — it is " +
    "safeTag's charset plus four refusals — so this means the charset the two share stopped being shared, and " +
    `safeTag's docblock now says something false. First few: ${JSON.stringify(backwards.slice(0, 8))}`);

  assert.deepEqual(unexplained, [],
    `${unexplained.length} tag(s) are taken by bot/lib/safe.mjs's safeTag and refused by bot/lib/poll.mjs's ` +
    "isUsableTag for a reason that is none of the four shapes this coupling records — isUsableTag grew a fifth " +
    "rule. Write it into safeTag's docblock and into HARDENED_AGAINST above. First few: " +
    JSON.stringify(unexplained.slice(0, 8)));

  for (const [shape, count] of onlyExplainedBy) {
    assert.ok(count > 0,
      `no tag in the corpus is told apart by ${shape} alone. That rule is either gone from bot/lib/poll.mjs's ` +
      "isUsableTag or now implied by the other three, and either way this coupling records a difference that is " +
      "no longer there");
  }
});

test("the one difference that is not about strictness: a non-string", () => {
  // Not a shape and not a hardening. `safeTag` type-checks first; `isUsableTag`
  // lets the regex coerce and then calls `.includes` on the original, which a
  // number or null does not have.
  //
  // Neither call site can reach this — `bot/lib/poll.mjs` slices a decoded URL
  // and `bot/lib/notify.mjs` wraps in `String(…)` — so this is pinned to keep
  // the claim in `safeTag`'s docblock honest, not because a crash is wanted. If
  // somebody makes `isUsableTag` answer `false` here, that is an improvement:
  // delete this test and the paragraph in the docblock that sends a reader to
  // it, rather than putting the throw back.
  for (const notAString of [null, undefined, 123, ["v1.0.0"]]) {
    assert.equal(safeTag(notAString), null,
      `bot/lib/safe.mjs's safeTag must refuse ${JSON.stringify(notAString) ?? String(notAString)} rather than ` +
      "return it — it is the value echoed back into a public comment");
    assert.throws(() => poll.isUsableTag(notAString), TypeError,
      `bot/lib/poll.mjs's isUsableTag no longer throws on ${JSON.stringify(notAString) ?? String(notAString)}. ` +
      "If it now returns false, that is the fix — remove this assertion and the non-string paragraph of safeTag's " +
      "docblock in bot/lib/safe.mjs, which currently tells readers the two differ here");
  }
});

test("an entry with no usable tag at all, and a feed with no entries, come back empty", () => {
  assert.deepEqual(parseReleasesAtom(feed(entry(tagUrl(""))), REPO), []);
  assert.deepEqual(parseReleasesAtom(feed(), REPO), []);
  assert.deepEqual(parseReleasesAtom("", REPO), []);
  assert.deepEqual(parseReleasesAtom(null, REPO), [], "a 200 with an empty body is not a crash");
});

// ───────────────────────────────────────────────────────────────────────────
// The conditional GET
// ───────────────────────────────────────────────────────────────────────────

/** A `fetch` stand-in that records what it was asked and answers `res`. */
function stubFetch(res) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return res;
    },
  };
}

const ok = (body, etag = 'W/"new"') => ({
  status: 200, ok: true,
  headers: new Map(etag === null ? [] : [["etag", etag]]),
  text: async () => body,
});

test("an unchanged repository costs one 304, and its body is never read", async () => {
  const notModified = {
    status: 304, ok: false, headers: new Map(),
    text: async () => { throw new Error("a 304 has no body to read"); },
  };
  const { calls, fetchImpl } = stubFetch(notModified);
  const res = await pollFeed(REPO, 'W/"abc"', fetchImpl);
  assert.equal(calls[0].init.headers["If-None-Match"], 'W/"abc"', "the remembered etag is fed back");
  assert.deepEqual(res, { changed: false, etag: 'W/"abc"', entries: [] },
    "and the etag survives the 304, because a poll that forgot it would cost a full body next time");
});

test("the first poll of a repository sends no If-None-Match, and always sends the two headers", async () => {
  const { calls, fetchImpl } = stubFetch(ok(feed()));
  await pollFeed(REPO, null, fetchImpl);
  const { url, init } = calls[0];
  assert.equal(url, `https://github.com/${REPO}/releases.atom`,
    "the feed, not the REST releases API: unauthenticated, cached at the edge, and not billed against the rate " +
    "limit the actual ingest needs");
  assert.ok(!("If-None-Match" in init.headers), "there is nothing to be conditional on yet");
  assert.equal(init.headers.Accept, "application/atom+xml");
  assert.equal(init.headers["User-Agent"], "astra-registry-bot");
});

test("a changed feed comes back parsed, with the new etag to remember", async () => {
  const { fetchImpl } = stubFetch(ok(feed(entry(tagUrl("v0.3.0")), entry(tagUrl("v9.9.9", "attacker/elsewhere")))));
  const res = await pollFeed(REPO, 'W/"abc"', fetchImpl);
  assert.equal(res.changed, true);
  assert.equal(res.etag, 'W/"new"');
  // The composition, which is the thing the split just made and the thing
  // neither unit test can see: `pollFeed` is what hands the body to the parse,
  // and it now does it across a module boundary. Byte-identical function
  // bodies say nothing about the seam between them.
  assert.deepEqual(res.entries.map((e) => e.tag), ["v0.3.0"]);
});

test("a 200 that carries no etag remembers null rather than the old one", async () => {
  const { fetchImpl } = stubFetch(ok(feed(entry(tagUrl("v0.3.0"))), null));
  const res = await pollFeed(REPO, 'W/"abc"', fetchImpl);
  assert.equal(res.etag, null,
    "keeping the old etag here would make the next poll conditional on a version this one has already replaced");
});

test("anything that is not a 200 or a 304 throws, naming the status and the URL", async () => {
  const { fetchImpl } = stubFetch({ status: 404, ok: false, headers: new Map(), text: async () => "" });
  await assert.rejects(() => pollFeed(REPO, null, fetchImpl), (e) => {
    assert.match(e.message, /HTTP 404/);
    assert.match(e.message, /someone\/quiet\/releases\.atom/,
      "a repository that has been deleted, renamed or made private is a listing-level problem, and the poll " +
      "records the message per repository — so the message has to say which repository");
    return true;
  });
});

// ───────────────────────────────────────────────────────────────────────────
// The composition, end to end: B-T2.6's first canary
// ───────────────────────────────────────────────────────────────────────────

// Removed at exit, and not only by the `rmSync` at the end of the test that
// makes one: that line runs only when every assertion above it held.
const trees = [];
process.on("exit", () => {
  for (const d of trees) fs.rmSync(d, { recursive: true, force: true });
});

/** The smallest tree `loadSources` will read: one listing, one version. */
function registryTree({ id = "quiet", repo = REPO, version = "0.2.0", tag = "v0.2.0" } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-poll-reg-"));
  trees.push(dir);
  const versions = path.join(dir, "plugins", id, "versions");
  fs.mkdirSync(versions, { recursive: true });
  fs.writeFileSync(path.join(dir, "plugins", id, "plugin.json"), `${JSON.stringify({
    schema: "astra.registry.plugin/1",
    id,
    name: id,
    summary: "A fixture listing, polled and never ingested.",
    license: "MIT",
    source: { kind: "github", repo },
    added_at: "2026-01-01",
  }, null, 2)}\n`);
  fs.writeFileSync(path.join(versions, `${version}.json`), `${JSON.stringify({
    schema: "astra.registry.version/1",
    id,
    version,
    published_at: "2026-01-01T00:00:00Z",
    release: { kind: "github_release", repo, tag },
  }, null, 2)}\n`);
  return dir;
}

// B-T2.6's first canary used to be asserted here through the release backstop,
// `runWatch`, as well as through the poll below. Cutover commit D deleted the
// backstop; the poll's own "canary 1" is the one that stands.

// ───────────────────────────────────────────────────────────────────────────
// B-T2.6's rules: the poll, the signed memory, the sweep, BOT-87's alarm
// ───────────────────────────────────────────────────────────────────────────
//
// The plan's five canaries, each a test below, and each watched failing by a
// mutation of `bot/lib/poll.mjs` recorded in the commit that added them:
//
//   1. a feed with the listed tag and a `cli-v1.2.0` registers nothing;
//   2. an unregistered matching tag across two sweeps alerts;
//   3. a pre-cutover tag never alerts;
//   4. an unsigned cache entry is discarded;
//   5. a failed register leaves the tag unseen.
//
// Plus BOT-87's other half (a feed that keeps failing alarms after three
// intervals, B-T5.1's canary on logic written here), the key's one reader,
// and MIG-30's "unlisted is never polled".

const KEY_HEX = "a".repeat(64);
const OTHER_KEY_HEX = "b".repeat(64);
const keyEnv = (hex = KEY_HEX) => ({ [poll.STATE_KEY_ENV]: hex });
const grandfathered = () => ({ state: "grandfathered", unlisted: false });
const SHA = (n) => String(n).padStart(40, "0").replace(/^0/, "a");

/** The pollable listings of a fixture tree, with every state decided as `grandfathered`. */
function listingsOf(root, stateOf = grandfathered) {
  const sources = loadSources(root);
  return poll.pollableListings({ sources, records: loadRecords(root, sources), stateOf });
}

/** A fetch stub answering each call from a queue of responses, recording what it was sent. */
function queueFetch(...responses) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      const r = responses.shift();
      if (!r) throw new Error(`unexpected fetch of ${url}`);
      return r;
    },
  };
}

test("canary 1: a feed carrying the listed tag and a cli-v release registers nothing", async () => {
  const root = registryTree();
  const { listings } = listingsOf(root);
  assert.equal(listings.length, 1, "the fixture listing is pollable");
  assert.equal(listings[0].prefix, "v", "BOT-74's prefix is the newest listed tag minus its version");
  const { fetchImpl } = queueFetch(ok(feed(
    entry(tagUrl("cli-v1.2.0"), "2026-08-08T10:00:00Z"),
    entry(tagUrl("v0.2.0"), "2026-01-01T10:00:00Z"),
  )));
  const out = await poll.runPoll({ listings, memory: poll.newMemory("2026-09-24T00:00:00Z"), now: new Date("2026-09-24T00:30:00Z"), fetchImpl });
  const res = out.repos[REPO.toLowerCase()];
  assert.equal(res.ok, true);
  assert.deepEqual(res.candidates, [], `nothing registers, and ${JSON.stringify(res.candidates)} would`);
  const why = Object.fromEntries(res.skipped.map((s) => [s.tag, s.why]));
  assert.match(why["cli-v1.2.0"], /prefix/, "the cli-v tag is skipped for its prefix (BOT-74)");
  assert.match(why["v0.2.0"], /recorded by a listed version/, "and the listed tag because a version records it");

  // The positive control, so that "registers nothing" is not a poll that
  // registers nothing ever: a new matching tag in the same feed registers.
  const again = queueFetch(ok(feed(entry(tagUrl("v0.3.0")), entry(tagUrl("cli-v1.2.0")))));
  const out2 = await poll.runPoll({ listings, memory: poll.newMemory("2026-09-24T00:00:00Z"), fetchImpl: again.fetchImpl });
  assert.deepEqual(out2.repos[REPO.toLowerCase()].candidates, ["v0.3.0"]);
});

test("BOT-74's prefix: a tag that does not end in its version admits every tag, and the newest non-yanked version decides", () => {
  assert.equal(poll.bot74Prefix({ version: "0.2.0", tag: "v0.2.0" }), "v");
  assert.equal(poll.bot74Prefix({ version: "0.2.0", tag: "telegram-client-v0.2.0" }), "telegram-client-v");
  assert.equal(poll.bot74Prefix({ version: "0.2.0", tag: "0.2.0" }), "", "a bare-version tag has the empty prefix");
  assert.equal(poll.bot74Prefix({ version: "0.2.0", tag: "release-2026-08" }), null, "does not end in its version");
  assert.equal(poll.matchesPrefix(null, "anything/at-all"), true);
  const newest = poll.newestListedVersion([
    { version: "0.10.0", tag: "x-v0.10.0", yanked: true },
    { version: "0.9.0", tag: "v0.9.0" },
    { version: "0.2.0", tag: "v0.2.0" },
  ]);
  assert.deepEqual(newest, { version: "0.9.0", tag: "v0.9.0" },
    "semver order, not string order, and a yanked version is not the newest LISTED one");
  assert.equal(poll.newestListedVersion([{ version: "1.0.0", tag: "v1.0.0", yanked: true }]).tag, "v1.0.0",
    "when every version is yanked, the recorded shape still decides");
});

test("a tag with a terminal record for this repository_id never registers, and one for another repository does", () => {
  const root = registryTree({ repo: "someone/bound" });
  fs.writeFileSync(path.join(root, "plugins", "quiet", "identity.json"), JSON.stringify({ repository_id: "111" }));
  const dec = path.join(root, "log", "decisions", "2026", "09");
  fs.mkdirSync(dec, { recursive: true });
  fs.writeFileSync(path.join(dec, `${"1".repeat(32)}.json`), JSON.stringify({
    decision_id: "1".repeat(32), state: "refused", tag: "v0.3.0", repo: "someone/bound", repository_id: "111",
  }));
  fs.writeFileSync(path.join(dec, `${"2".repeat(32)}.json`), JSON.stringify({
    decision_id: "2".repeat(32), state: "refused", tag: "v0.4.0", repo: "someone/bound", repository_id: "999",
  }));
  const [listing] = listingsOf(root).listings;
  assert.equal(listing.repository_id, "111");
  assert.equal(poll.tagVerdict(listing, "v0.3.0").register, false, "refused for this repository_id: terminal");
  assert.equal(poll.tagVerdict(listing, "v0.4.0").register, true,
    "a record for another repository_id is about a repository that reused the name, not this one");
});

// BOT-19 and BOT-74 do NOT read one set, and this test used to say they did.
// BOT-74 keeps the poll from registering a tag with a terminal record for its
// repository — `refused`, `revoked`, `yanked`, `withdrawn`, `deprecated` —
// which is `poll.TERMINAL_STATES`. BOT-19 is narrower and names its records
// exactly (registry plan notes): a `published`, `stopped` or `M_REJECT`
// `refused` record carrying this run's fingerprint, and a `stopped` record for
// the same tag of the same repository; "a `held` or `delayed` record MUST NOT
// stop the run", and neither does a bot refusal, which a `/recheck` exists to
// re-decide. Held to one set, one old refusal of a plugin stopped every later
// release of it for ever (B-T3.9). So this asserts the two rules apart.
test("BOT-19's terminal records are its own, and BOT-74's terminal states are the poll's", async () => {
  const { terminalOnMain } = await import("../decide.mjs");
  const byTag = (state, reasons) => terminalOnMain({ records: [{ state, reasons, repo: "a/b", tag: "v1.0.0" }], fingerprint: null, repo: "a/b", tag: "v1.0.0" });
  for (const state of [...poll.TERMINAL_STATES, "published", "held", "delayed"]) {
    assert.equal(byTag(state), null, `a ${state} record for the tag is not BOT-19's; only a stop is`);
  }
  assert.notEqual(byTag("stopped"), null, "a stop of the same tag is BOT-19's (FLOW-26)");
  const byFp = (state, reasons) => terminalOnMain({ records: [{ state, reasons, fingerprint: "0123456789abcdef" }], fingerprint: "0123456789abcdef", repo: "a/b", tag: "v2.0.0" });
  assert.notEqual(byFp("published"), null);
  assert.notEqual(byFp("refused", ["M_REJECT"]), null);
  assert.equal(byFp("refused", ["E_LICENSE_NOT_ALLOWED"]), null, "a bot refusal is re-decided on a recheck");
  assert.ok(poll.TERMINAL_STATES.includes("refused"), "BOT-74 still keeps a refused tag out of the poll");
});

test("MIG-30: an unlisted listing is never polled, and one whose state cannot be decided is skipped out loud", () => {
  const a = registryTree({ id: "hidden" });
  const doc = JSON.parse(fs.readFileSync(path.join(a, "plugins", "hidden", "plugin.json"), "utf8"));
  fs.writeFileSync(path.join(a, "plugins", "hidden", "plugin.json"), JSON.stringify({ ...doc, unlisted: true }));
  const r = listingsOf(a);
  assert.equal(r.listings.length, 0);
  assert.match(r.skipped[0].why, /MIG-30/);
  const b = registryTree();
  const s = listingsOf(b, () => { throw new Error("a shallow checkout"); });
  assert.equal(s.listings.length, 0, "an undecidable state is not a default state");
  assert.match(s.skipped[0].why, /shallow checkout/);
  assert.throws(() => poll.pollableListings({ sources: loadSources(b) }), /stateOf/,
    "which listings are polled is MIG-1's answer, and there is no default for it");
});

test("canary 5: a failed register leaves the tag unseen, and the feed's ETag does not move past it", async () => {
  const root = registryTree();
  const { listings } = listingsOf(root);
  const key = REPO.toLowerCase();
  let memory = poll.newMemory("2026-09-24T00:00:00Z");
  memory.repos[key] = { etag: 'W/"old"', last_success_at: null, registered: [] };

  const first = queueFetch(ok(feed(entry(tagUrl("v0.3.0"))), 'W/"new"'));
  const polled = await poll.runPoll({ listings, memory, now: new Date("2026-09-24T00:30:00Z"), fetchImpl: first.fetchImpl });
  assert.deepEqual(polled.repos[key].candidates, ["v0.3.0"]);

  // claim failed: it registered nothing.
  memory = poll.rememberPoll(memory, polled, []);
  assert.deepEqual(memory.repos[key].registered, [], "a tag claim did not register is not remembered");
  assert.equal(memory.repos[key].etag, 'W/"old"',
    "the new ETag is not kept: kept, the next poll is answered 304 and the tag is never offered again");
  assert.equal(memory.repos[key].last_success_at, "2026-09-24T00:30:00Z", "the POLL succeeded; claim did not");

  const second = queueFetch(ok(feed(entry(tagUrl("v0.3.0"))), 'W/"new"'));
  const again = await poll.runPoll({ listings, memory, fetchImpl: second.fetchImpl });
  assert.equal(second.calls[0].init.headers["If-None-Match"], 'W/"old"', "the next poll asks with the old ETag");
  assert.deepEqual(again.repos[key].candidates, ["v0.3.0"], "and the tag is offered again");

  // claim succeeded this time.
  memory = poll.rememberPoll(memory, again, [{ repo: REPO, tag: "v0.3.0" }]);
  assert.deepEqual(memory.repos[key].registered, ["v0.3.0"]);
  assert.equal(memory.repos[key].etag, 'W/"new"', "every tag the feed produced was registered, so the ETag moves");
  const third = queueFetch(ok(feed(entry(tagUrl("v0.3.0")))));
  const done = await poll.runPoll({ listings, memory, fetchImpl: third.fetchImpl });
  assert.deepEqual(done.repos[key].candidates, [], "a registered tag is not registered twice");

  // claim cannot make remember save a tag the poll never produced.
  const forged = poll.rememberPoll(memory, again, [{ repo: REPO, tag: "v9.9.9" }]);
  assert.ok(!forged.repos[key].registered.includes("v9.9.9"));
});

test("canary 4: an unsigned, altered or foreign-keyed cache entry is discarded, and a sealed one opens", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-poll-mem-"));
  trees.push(dir);
  const file = path.join(dir, "memory.json");
  const now = new Date("2026-09-24T00:00:00Z");
  const memory = poll.newMemory(now);
  memory.repos["someone/quiet"] = { etag: null, last_success_at: null, registered: ["v0.2.0"] };

  assert.deepEqual(poll.loadMemory({ file, env: keyEnv(), now }).discarded, null, "no file is the first run, not a discard");

  poll.rememberMemory({ memory, file, env: keyEnv() });
  const opened = poll.loadMemory({ file, env: keyEnv(), now });
  assert.equal(opened.discarded, null);
  assert.deepEqual(opened.memory, memory, "a sealed memory opens as it was saved");

  const sealed = JSON.parse(fs.readFileSync(file, "utf8"));
  const cases = {
    "unsigned": { schema: poll.SEAL_SCHEMA, memory },
    "altered after signing": { ...sealed, memory: { ...memory, repos: { "someone/quiet": { ...memory.repos["someone/quiet"], registered: ["v0.2.0", "v0.3.0"] } } } },
    "signed with another key": poll.sealMemory(memory, Buffer.from(OTHER_KEY_HEX, "hex")),
    "not an envelope": memory,
  };
  for (const [name, envelope] of Object.entries(cases)) {
    fs.writeFileSync(file, JSON.stringify(envelope));
    const r = poll.loadMemory({ file, env: keyEnv(), now });
    assert.ok(r.discarded, `${name}: the entry was not discarded`);
    assert.deepEqual(r.memory, poll.newMemory(now), `${name}: a discarded entry starts again, it is never repaired`);
  }
  fs.writeFileSync(file, "{not json");
  assert.match(poll.loadMemory({ file, env: keyEnv(), now }).discarded, /not JSON/);

  // A discard is paged: starting again re-seeds the sweep, and a tag that
  // arrived in the gap is seeded rather than alarmed on.
  const v = poll.bot87Verdict({ discarded: "the cache entry carries no signature" });
  assert.deepEqual(v.codes, [poll.BOT_87_CODES.discarded]);
  assert.equal(v.status, "red");
});

test("the key has one reader, refuses a short or missing one, and the poll and the sweep never touch it", () => {
  assert.throws(() => poll.stateKey({}), /BOT_STATE_HMAC_KEY is not set.*bot-state/s);
  assert.throws(() => poll.stateKey(keyEnv("ab".repeat(16 - 1))), /bytes, and the floor is 32/);
  assert.throws(() => poll.stateKey(keyEnv("zz".repeat(32))), /not hex/);
  assert.equal(poll.stateKey(keyEnv()).length, 32);
  for (const fn of [poll.runPoll, poll.pollListing, poll.rememberPoll, poll.runSweep, poll.sweepListing, poll.staleListings]) {
    const src = fn.toString();
    for (const needle of ["stateKey", "STATE_KEY_ENV", "process.env", "loadMemory", "rememberMemory"]) {
      assert.ok(!src.includes(needle), `${fn.name} reaches ${needle}; only load and remember hold the bot-state key`);
    }
  }
});

test("canary 2: a matching tag unregistered across two sweeps alerts, with its SHA and the plugin id", () => {
  const root = registryTree();
  const [listing] = listingsOf(root).listings;
  let memory = poll.newMemory("2026-09-24T00:00:00Z");
  const remote = [{ tag: "v0.2.0", sha: SHA(1) }, { tag: "cli-v1.0.0", sha: SHA(2) }];

  let s = poll.runSweep({ memory, listings: [listing], lsRemote: () => remote });
  assert.equal(s.seeded, true, "the first sweep ever seeds");
  assert.deepEqual(s.alerts, []);
  memory = s.memory;

  const withNew = [...remote, { tag: "v0.3.0", sha: SHA(3) }, { tag: "cli-v1.1.0", sha: SHA(4) }];
  s = poll.runSweep({ memory, listings: [listing], lsRemote: () => withNew });
  assert.deepEqual(s.alerts, [], "a tag seen for the first time is not yet late: ls-remote has no dates, so age is counted in sweeps");
  memory = s.memory;

  s = poll.runSweep({ memory, listings: [listing], lsRemote: () => withNew });
  assert.deepEqual(s.alerts.map((a) => a.tag), ["v0.3.0"],
    "seen at the previous sweep, matching the prefix, and handled by nothing: that is BOT-87's alarm, and the " +
    "cli-v tag next to it is not");
  const v = poll.bot87Verdict({ unregistered: s.alerts });
  assert.deepEqual(v, {
    schema: "astra.registry.alert-verdict/1", check: "poll-and-sweep", status: "red",
    codes: ["BOT_87_TAG_UNREGISTERED"], ids: ["quiet"], hexes: [SHA(3)],
  }, "a stranger's tag never reaches the channel; the id and the SHA find it");

  // Handled by the poll, or named by a decision record: no alarm.
  const registered = structuredClone(memory);
  registered.repos[REPO.toLowerCase()] = { etag: null, last_success_at: null, registered: ["v0.3.0"] };
  assert.deepEqual(poll.runSweep({ memory: registered, listings: [listing], lsRemote: () => withNew }).alerts, [],
    "a tag the poll registered is not missing");
  const named = { ...listing, named_tags: ["v0.3.0"] };
  assert.deepEqual(poll.runSweep({ memory, listings: [named], lsRemote: () => withNew }).alerts, [],
    "a tag a decision record names is not missing either");
});

test("canary 3: a tag that existed when the sweep was seeded never alerts", () => {
  const root = registryTree();
  const [listing] = listingsOf(root).listings;
  const remote = [{ tag: "v0.1.0", sha: SHA(5) }, { tag: "v0.2.0", sha: SHA(6) }];
  let memory = poll.runSweep({ memory: poll.newMemory("2026-09-24T00:00:00Z"), listings: [listing], lsRemote: () => remote, seed: true }).memory;
  for (let i = 0; i < 4; i++) {
    const s = poll.runSweep({ memory, listings: [listing], lsRemote: () => remote });
    assert.deepEqual(s.alerts, [], `sweep ${s.sweep}: v0.1.0 predates the cutover (MIG-23) and was never this poll's to register`);
    memory = s.memory;
  }
  // And a repository swept for the first time later seeds too.
  const late = { ...listing, id: "late", repo: "someone/late" };
  const s = poll.runSweep({ memory, listings: [listing, late], lsRemote: (repo) => (repo === "someone/late" ? [{ tag: "v3.0.0", sha: SHA(7) }] : remote) });
  const s2 = poll.runSweep({ memory: s.memory, listings: [listing, late], lsRemote: (repo) => (repo === "someone/late" ? [{ tag: "v3.0.0", sha: SHA(7) }] : remote) });
  assert.deepEqual(s2.alerts, [], "a newly listed plugin's earlier releases are history, not a missed registration");
});

test("BOT-87: a listing whose last successful poll is older than three intervals alarms, and a failing feed gets there", async () => {
  const root = registryTree();
  const { listings } = listingsOf(root);
  const key = REPO.toLowerCase();
  const start = new Date("2026-09-24T00:00:00Z");
  let memory = poll.newMemory(start);
  const bound = poll.POLL_STALE_INTERVALS * poll.POLL_INTERVAL_SECONDS * 1000;
  assert.equal(bound, 90 * 60 * 1000, "BOT-41's 30 minutes, three times (BOT-87)");
  assert.deepEqual(poll.staleListings(memory, listings, new Date(start.getTime() + bound)), [],
    "a fresh memory is measured from when it started, and 90 minutes exactly is not older than 90");

  const failing = { status: 500, ok: false, headers: new Map(), text: async () => "" };
  for (let i = 1; i <= 4; i++) {
    const at = new Date(start.getTime() + i * poll.POLL_INTERVAL_SECONDS * 1000);
    const out = await poll.runPoll({ listings, memory, now: at, fetchImpl: async () => failing });
    assert.equal(out.repos[key].ok, false);
    memory = poll.rememberPoll(memory, out, []);
    const stale = poll.staleListings(memory, listings, at);
    assert.equal(stale.length, i >= 4 ? 1 : 0,
      `after ${i} failed interval(s) the listing is ${stale.length ? "" : "not "}stale; BOT-87 says more than 3`);
  }
  const v = poll.bot87Verdict({ stale: poll.staleListings(memory, listings, new Date(start.getTime() + 4 * 1800 * 1000)) });
  assert.deepEqual(v.codes, ["BOT_87_POLL_STALE"]);
  assert.deepEqual(v.ids, ["quiet"]);

  // A successful poll resets it.
  const okAt = new Date(start.getTime() + 5 * 1800 * 1000);
  const out = await poll.runPoll({ listings, memory, now: okAt, fetchImpl: async () => ok(feed()) });
  memory = poll.rememberPoll(memory, out, []);
  assert.deepEqual(poll.staleListings(memory, listings, okAt), []);
});

test("`git ls-remote` output is read whole or refused, and the green verdict is one the channel accepts", () => {
  const text = `${SHA(1)}\trefs/tags/v0.2.0\n${SHA(2)}\trefs/tags/cli-v1.0.0\n${SHA(3)}\trefs/tags/../evil\n`;
  assert.deepEqual(poll.parseLsRemoteTags(text).map((t) => t.tag), ["v0.2.0", "cli-v1.0.0"],
    "a tag BOT-74 could never register is not one the sweep can miss");
  assert.throws(() => poll.parseLsRemoteTags("garbage\n"), /not a `git ls-remote/);
  assert.throws(() => poll.parseLsRemoteTags(`${SHA(1)}\trefs/tags/v1^{}\n`), /peeled/);
  assert.throws(() => poll.lsRemoteTags("not a repo"), /owner\/name/);
  assert.deepEqual(poll.bot87Verdict({}), { schema: "astra.registry.alert-verdict/1", check: "poll-and-sweep", status: "green" });
  const many = Array.from({ length: 50 }, (_, i) => ({ id: `plugin-${i}`, repo: "a/b", tag: `v${i}`, sha: SHA(100 + i) }));
  assert.equal(poll.bot87Verdict({ unregistered: many }).ids.length, 40, "capped at the channel's 40, not refused");
});

test("MIG-23: the tag memory seeds from state/releases-seen.json, tags only", () => {
  const seeded = poll.seedFromReleasesSeen(poll.newMemory("2026-09-24T00:00:00Z"), {
    repos: { "Someone/Quiet": { etag: 'W/"legacy"', checked_tags: ["v0.1.0", "cli-v1.0.0"], last_seen_tag: "v0.2.0" } },
  });
  assert.deepEqual(seeded.repos["someone/quiet"], { etag: null, last_success_at: null, registered: ["v0.1.0", "cli-v1.0.0", "v0.2.0"] });
  assert.equal(poll.memoryProblem(seeded), null);
});

// ───────────────────────────────────────────────────────────────────────────
// A monorepo's feed (B-T5.0, found building the shadow poll on B-T2.6)
// ───────────────────────────────────────────────────────────────────────────
//
// `mihailinl/AstraPlugins` hosts six pollable listings, and `runPoll` used to
// walk listings rather than repositories: each one fetched the same feed and
// wrote `out.repos[<repo>]`, so every listing overwrote the one before it and
// only the last listing's candidates survived. A new `bad-apple-v0.1.3` would
// then have been judged by `bad-apple`, found, and thrown away when `text-utils`
// judged the same feed and found nothing — in shadow a missing "would register"
// line, and live a release that never reached the service, which is BOT-87's
// alarm a day later for something the poll had in its hands.

/** A listing in the shape `pollableListings` returns. */
const monoListing = (id, prefix, recorded = [], { terminal = [] } = {}) => ({
  id, repo: "someone/mono", repository_id: null, state: "grandfathered", prefix,
  prefix_from: prefix === null ? { version: "0.1.0", tag: "release-0.1" } : { version: "0.1.0", tag: `${prefix}0.1.0` },
  recorded_tags: recorded, terminal_tags: terminal, named_tags: [...recorded, ...terminal],
});

test("a monorepo's feed is read once and judged by every listing it hosts, none overwriting another", async () => {
  const MONO = "someone/mono";
  const listings = [
    monoListing("alpha", "alpha-v", ["alpha-v0.1.0"]),
    monoListing("beta", "beta-v", ["beta-v0.1.0"]),
  ];
  const xml = feed(
    entry(tagUrl("alpha-v0.2.0", MONO)),
    entry(tagUrl("beta-v0.1.0", MONO)),
    entry(tagUrl("cli-v1.0.0", MONO)),
  );
  const { calls, fetchImpl } = queueFetch(ok(xml), ok(xml));
  const out = await poll.runPoll({ listings, memory: poll.newMemory("2026-09-24T00:00:00Z"), now: new Date("2026-09-24T00:30:00Z"), fetchImpl });
  const res = out.repos[MONO];
  assert.deepEqual(res.candidates, ["alpha-v0.2.0"],
    "alpha's new release is a candidate whichever listing of the repository was judged last");
  assert.equal(calls.length, 1, "one conditional GET per repository, not one per listing it hosts");
  assert.deepEqual(res.ids, ["alpha", "beta"], "and the result says which listings it spoke for");

  // A tag one listing records is not registered because another listing's
  // prefix admits it. `loose` has a tag that does not end in its version, so
  // BOT-74 gives it no prefix and it admits every tag, alpha's included.
  const mixed = [monoListing("alpha", "alpha-v", ["alpha-v0.1.0"]), monoListing("loose", null, [])];
  const again = queueFetch(ok(feed(entry(tagUrl("alpha-v0.1.0", MONO)), entry(tagUrl("gamma-1", MONO)))));
  const out2 = await poll.runPoll({ listings: mixed, memory: poll.newMemory("2026-09-24T00:00:00Z"), fetchImpl: again.fetchImpl });
  assert.deepEqual(out2.repos[MONO].candidates, ["gamma-1"],
    "alpha-v0.1.0 is recorded by alpha's version, and BOT-74 registers no tag a listed version records, " +
    "whichever listing's prefix would have let it through");
  const why = Object.fromEntries(out2.repos[MONO].skipped.map((s) => [s.tag, s.why]));
  assert.match(why["alpha-v0.1.0"], /recorded/);
});

// ───────────────────────────────────────────────────────────────────────────
// B-T5.0: the poll and the sweep as jobs, in shadow
// ───────────────────────────────────────────────────────────────────────────
//
// `bot/lib/poll-run.mjs` is the plumbing between `plugins-ingest.yml`'s jobs; the
// rules above are what it runs. What is asserted here is the plumbing's own
// promises: B-T5.0's canary (a shadow run registers no tag
// `state/releases-seen.json` records, and an emptied copy would), the memory
// saved only on claim's answer, shadow keeping BOT-87's registration alarm out
// of the verdict, the sweep's daily cadence, each job reaching only what it
// holds, and the workflow wired to exactly what each subcommand reads and
// writes.

const RUN_FILE = path.join(REPO_ROOT, "bot", "lib", "poll-run.mjs");
const INGEST_YML = path.join(REPO_ROOT, ".github", "workflows", "plugins-ingest.yml");
const NOW = new Date("2026-09-24T12:00:00Z");

/** A quiet listing of REPO, `v0.2.0` listed. */
const quietListing = () => ({
  id: "quiet", repo: REPO, repository_id: null, state: "grandfathered", prefix: "v",
  prefix_from: { version: "0.2.0", tag: "v0.2.0" }, recorded_tags: ["v0.2.0"], terminal_tags: [], named_tags: [],
});

test("B-T5.0's canary: a shadow run registers no tag releases-seen records, and an emptied copy would", async () => {
  const listings = [quietListing()];
  // `v0.1.9` is a tag the legacy backstop saw and no version records — a
  // refused or never-finished release, exactly the case MIG-23's seed is for.
  const seen = { repos: { [REPO]: { checked_tags: ["v0.1.9"], last_seen_tag: "v0.1.9" } } };
  const xml = feed(entry(tagUrl("v0.1.9")), entry(tagUrl("v0.2.0")), entry(tagUrl("cli-v1.0.0")));

  // The whole path the shadow run takes, through the REAL claim job: load's
  // seeded rows, the poll, the tags it hands on, and claim's register half in
  // shadow — with a client that records every call it is asked to make.
  const shadowRun = async (seenDoc) => {
    const { rows } = run.loadOutputs({ opened: poll.newMemory(NOW), seen: seenDoc, listings, now: NOW, dispatched: true });
    const out = await poll.runPoll({ listings, memory: { repos: rows }, now: NOW, fetchImpl: async () => ok(xml) });
    const { tags } = run.pollOutputs(out, listings);
    const client = stubClient();
    const { lines, log } = quietLog();
    const claimed = await claimJob({ client, polled: tags, mode: "shadow", log });
    assert.deepEqual(client.calls.filter((c) => c.op === "register"), [], "claim registered a tag in shadow");
    return { lines: lines.filter((l) => l.startsWith("would register")), registered: claimed.registered };
  };

  const seeded = await shadowRun(seen);
  assert.deepEqual(seeded.lines, ["would register nothing: the poll offered no tag this run"],
    "a tag state/releases-seen.json records is the legacy backstop's, and the shadow poll offers none of them");
  assert.deepEqual(seeded.registered, [], "and in shadow nothing is registered, whatever the poll offered");

  const emptied = await shadowRun({ repos: {} });
  assert.deepEqual(emptied.lines, [`would register ${REPO}@v0.1.9`],
    "the same run seeded from an emptied copy offers the recorded tag — which is the line the canary watches for");
  assert.deepEqual(emptied.registered, []);
});

test("the memory keeps a polled tag only once claim answered for it", () => {
  const listings = [quietListing()];
  const key = REPO.toLowerCase();
  const memory = poll.newMemory(NOW);
  const polled = { at: "2026-09-24T12:00:00Z", repos: { [key]: { ok: true, candidates: ["v0.3.0"], etag: 'W/"new"' } } };
  const base = { memory, discarded: null, listings, polled, swept: null, sweepDue: false, sweepFailed: false, now: NOW, mode: "shadow" };

  const unanswered = run.composeRemember({ ...base, registered: [] });
  assert.deepEqual(unanswered.memory.repos[key].registered, [],
    "claim registered nothing (shadow, or a register that failed), so the tag stays unseen and is offered again");
  assert.equal(unanswered.memory.repos[key].etag, null,
    "and the feed's new ETag is not kept: saved, the next poll would be a 304 and the tag would never come back");

  const answered = run.composeRemember({ ...base, registered: [{ repo: REPO, tag: "v0.3.0" }] });
  assert.deepEqual(answered.memory.repos[key].registered, ["v0.3.0"]);
  assert.equal(answered.memory.repos[key].etag, 'W/"new"');
});

test("in shadow BOT-87's registration alarm is logged as `would alarm`; live it is sent", () => {
  const listings = [quietListing()];
  const key = REPO.toLowerCase();
  // Three sweeps' worth of memory: seeded, then v0.3.0 first seen, then
  // still unhandled — the case canary 2 alarms on.
  let memory = poll.newMemory(NOW);
  const s0 = [["v0.2.0", SHA(1)]];
  const s1 = [...s0, ["v0.3.0", SHA(3)]];
  const at = (h) => new Date(NOW.getTime() + h * 3600 * 1000);
  // Each step polls successfully too, so that the only thing that could turn
  // the verdict red is the tag nobody registered.
  const polledAt = (h) => ({ at: at(h).toISOString().slice(0, 19) + "Z", repos: { [key]: { ok: true, candidates: [], etag: null } } });
  const step = (tags, h, mode) => run.composeRemember({
    memory, discarded: null, listings, polled: polledAt(h), registered: [], swept: { [key]: { tags } },
    sweepDue: true, sweepFailed: false, now: at(h), mode,
  });
  memory = step(s0, 0, "shadow").memory;
  memory = step(s1, 24, "shadow").memory;

  const shadow = step(s1, 48, "shadow");
  assert.equal(shadow.verdict.status, "green",
    "in shadow the poll registers nothing by construction, so an unregistered tag is not news to page about");
  assert.deepEqual(shadow.wouldAlarm.map((a) => a.tag), ["v0.3.0"], "and it is still found, and said, in the log");

  const live = step(s1, 48, "live");
  assert.deepEqual(live.verdict.codes, ["BOT_87_TAG_UNREGISTERED"]);
  assert.deepEqual(live.verdict.hexes, [SHA(3)]);
  assert.deepEqual(live.wouldAlarm, []);
});

test("a sweep that was due and did not answer is BOT_87_SWEEP_FAILED for every listing, in shadow too", () => {
  const listings = [quietListing(), { ...quietListing(), id: "other", repo: "someone/other" }];
  const r = run.composeRemember({
    memory: poll.newMemory(NOW), discarded: null, listings, polled: null, registered: [], swept: null,
    sweepDue: true, sweepFailed: true, now: NOW, mode: "shadow",
  });
  assert.deepEqual(r.verdict.codes, ["BOT_87_SWEEP_FAILED"]);
  assert.deepEqual(r.verdict.ids, ["other", "quiet"]);
  const notDue = run.composeRemember({
    memory: poll.newMemory(NOW), discarded: null, listings, polled: null, registered: [], swept: null,
    sweepDue: false, sweepFailed: true, now: NOW, mode: "shadow",
  });
  assert.equal(notDue.verdict.status, "green", "a sweep that was not due and was skipped is not a failure");
});

test("the poll every 30 minutes and the sweep daily, and a dispatch forces only the poll", () => {
  const withPoll = (secondsAgo) => {
    const m = poll.newMemory(NOW);
    m.repos["a/b"] = { etag: null, last_success_at: new Date(NOW.getTime() - secondsAgo * 1000).toISOString().slice(0, 19) + "Z", registered: [] };
    return m;
  };
  assert.equal(run.pollDue(poll.newMemory(NOW), NOW).due, true, "nothing polled yet");
  assert.equal(run.pollDue(withPoll(1500), NOW).due, true, "the :33 run, a few minutes early, is due");
  assert.equal(run.pollDue(withPoll(1499), NOW).due, false, "the :23 run is not");
  assert.equal(run.pollDue(withPoll(60), NOW, { dispatched: true }).due, true, "a dispatch means pull now (BOT-4)");

  const swept = (secondsAgo) => {
    const m = poll.newMemory(NOW);
    m.sweep.last_at = new Date(NOW.getTime() - secondsAgo * 1000).toISOString().slice(0, 19) + "Z";
    m.sweep.count = 1;
    return m;
  };
  assert.equal(run.sweepDue(poll.newMemory(NOW), NOW).due, true, "the first sweep seeds, and is due");
  assert.equal(run.sweepDue(swept(86100), NOW).due, true);
  assert.equal(run.sweepDue(swept(86099), NOW).due, false);
  // `loadOutputs` is where a dispatch reaches the two questions, so it is
  // asked there: a dispatched sweep an hour after the last would make a tag
  // the poll has had an hour to register look a sweep old.
  const out = run.loadOutputs({ opened: swept(3600), seen: null, listings: [], now: NOW, dispatched: true });
  assert.equal(out.poll.due, true);
  assert.equal(out.sweep.due, false, "a dispatch does not make the sweep due");
});

test("each answer another job hands on is held to its grammar, and refused whole", () => {
  const listings = [quietListing()];
  const key = REPO.toLowerCase();
  const polled = (res, k = key) => JSON.stringify({ at: "2026-09-24T12:00:00Z", repos: { [k]: res } });
  assert.equal(run.readPolled("", listings), null, "a poll that did not run answered nothing");
  assert.ok(run.readPolled(polled({ ok: true, candidates: ["v0.3.0"], etag: 'W/"x"' }), listings));
  assert.throws(() => run.readPolled(polled({ ok: true, candidates: [], etag: null }, "someone/else"), listings), /load did not list/);
  assert.throws(() => run.readPolled(polled({ ok: true, candidates: ["../evil"], etag: null }), listings), /grammar/);
  assert.throws(() => run.readPolled(polled({ ok: true, candidates: [], etag: "not quoted" }), listings), /grammar/);
  assert.throws(() => run.readPolled(polled({ ok: true, candidates: Array.from({ length: 51 }, (_, i) => `v${i}`), etag: null }), listings), /grammar/,
    "a feed shows ten entries; fifty-one candidates did not come from one");

  assert.deepEqual(run.readRegistered(""), []);
  assert.throws(() => run.readRegistered(JSON.stringify([{ repo: "no slash", tag: "v1" }])), /registered/);

  assert.equal(run.readSwept("", listings), null);
  assert.ok(run.readSwept(JSON.stringify({ [key]: { tags: [["v0.2.0", SHA(1)]] } }), listings));
  assert.ok(run.readSwept(JSON.stringify({ [key]: { error: "HTTP 500" } }), listings));
  assert.throws(() => run.readSwept(JSON.stringify({ [key]: { tags: [["v0.2.0", "short"]] } }), listings), /sweep/);

  assert.throws(() => run.readListings(""), /did `load` run/);
  assert.throws(() => run.readListings(JSON.stringify([{ id: "x" }])), /pollableListings/);
});

test("the sweep asks each repository once, however many listings it hosts", () => {
  const asked = [];
  const listings = [
    { ...quietListing(), id: "a", repo: "Some/Mono" },
    { ...quietListing(), id: "b", repo: "some/mono" },
    { ...quietListing(), id: "c", repo: "some/broken" },
  ];
  const out = run.sweepRemote(listings, (repo) => {
    asked.push(repo);
    if (repo === "some/broken") throw new Error("exit 128");
    return [{ tag: "v1.0.0", sha: SHA(9) }];
  });
  assert.deepEqual(asked, ["Some/Mono", "some/broken"]);
  assert.deepEqual(out, { "some/mono": { tags: [["v1.0.0", SHA(9)]] }, "some/broken": { error: "exit 128" } });
});

test("a job output that would not survive the trip to the next job is refused where it is written", () => {
  assert.equal(run.outputLine("x", { a: 1 }), 'x={"a":1}\n');
  assert.throws(() => run.outputLine("x", "a\nb"), /newline/);
  assert.throws(() => run.outputLine("x", "a".repeat(run.MAX_OUTPUT_BYTES + 1)), /128 KiB/);
});

test("each subcommand reaches only what its job holds", () => {
  // The key: read by `load` and `remember` and by nothing else, as data…
  const keyed = Object.entries(run.JOB_IO).filter(([, io]) => io.reads.includes("BOT_STATE_HMAC_KEY")).map(([c]) => c);
  assert.deepEqual(keyed.sort(), ["load", "remember"]);
  // …and as code: the functions each job runs.
  const src = (cmd) => run.COMMANDS[cmd].toString();
  for (const cmd of ["poll", "sweep"]) {
    for (const needle of ["loadMemory", "rememberMemory", "STATE_KEY_ENV", "BOT_STATE_HMAC_KEY"]) {
      assert.ok(!src(cmd).includes(needle), `${cmd} reaches ${needle}; only load and remember hold the bot-state key`);
    }
  }
  for (const cmd of ["load", "remember"]) {
    for (const needle of ["runPoll", "pollFeed", "sweepRemote", "lsRemoteTags"]) {
      assert.ok(!src(cmd).includes(needle), `${cmd} reaches ${needle}, which reads a stranger's answer`);
    }
  }
  // And a name outside the table is refused at the read, not just in review:
  // `poll` asking for the key is an exception, whatever the environment holds.
  const env = { BOT_STATE_HMAC_KEY: KEY_HEX, ASTRA_POLL_ROWS: "{}" };
  assert.throws(() => run.input("poll", env, "BOT_STATE_HMAC_KEY"), /JOB_IO does not list/);
  assert.throws(() => run.input("sweep", env, "ASTRA_POLL_ROWS"), /JOB_IO does not list/);
  assert.equal(run.input("poll", env, "ASTRA_POLL_ROWS"), "{}");
});

/** Run `node bot/lib/poll-run.mjs <cmd>` in `cwd`, with `env` and nothing ambient but PATH. */
function runCmd(cmd, cwd, env) {
  const outFile = path.join(cwd, `out-${cmd}-${Math.random().toString(36).slice(2)}`);
  let code = 0;
  let stdout = "";
  let stderr = "";
  try {
    stdout = execFileSync(process.execPath, [RUN_FILE, cmd], {
      cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH, HOME: process.env.HOME, GITHUB_OUTPUT: outFile, ...env },
    });
  } catch (e) {
    code = e.status;
    stdout = String(e.stdout ?? "");
    stderr = String(e.stderr ?? "");
  }
  const outputs = {};
  if (fs.existsSync(outFile)) {
    for (const line of fs.readFileSync(outFile, "utf8").split("\n")) {
      const i = line.indexOf("=");
      if (i > 0) outputs[line.slice(0, i)] = line.slice(i + 1);
    }
  }
  return { code, stdout, stderr, outputs };
}

test("claim's register half, in shadow, prints what it would register, calls nothing, and refuses a mode it does not know", async () => {
  const tags = [{ repo: REPO, tag: "v0.3.0" }, { repo: "Some/Mono", tag: "alpha-v0.2.0" }];
  assert.deepEqual([...POLL_MODES], ["shadow", "live"]);
  assert.equal(run.MODES, POLL_MODES, "poll-run and the claim job read one list of modes, not two");

  const shadowClient = stubClient();
  const { lines, log } = quietLog();
  const shadow = await claimJob({ client: shadowClient, polled: tags, mode: "shadow", log });
  assert.ok(lines.includes(`would register ${REPO}@v0.3.0`), lines.join("\n"));
  assert.ok(lines.includes("would register Some/Mono@alpha-v0.2.0"), lines.join("\n"));
  assert.deepEqual(shadow.registered, [], "in shadow claim reports nothing registered, so the memory keeps nothing");
  assert.deepEqual(shadowClient.calls.map((c) => c.op), ["claim"], "shadow made a register call; only the claim half calls");

  // live — B-T5.1's value — registers each tag, and reports it in the form
  // remember reads back.
  const liveClient = stubClient();
  const live = await claimJob({ client: liveClient, polled: tags, mode: "live", log: quietLog().log });
  assert.deepEqual(liveClient.calls.filter((c) => c.op === "register").map((c) => `${c.body.repo}@${c.body.tag}`),
    [`${REPO}@v0.3.0`, "Some/Mono@alpha-v0.2.0"]);
  assert.deepEqual(run.readRegistered(JSON.stringify(live.registered)),
    [{ repo: REPO, tag: "v0.3.0" }, { repo: "Some/Mono", tag: "alpha-v0.2.0" }]);

  for (const mode of [undefined, null, "", "Shadow", "dry"]) {
    const c = stubClient();
    await assert.rejects(claimJob({ client: c, polled: tags, mode, log: quietLog().log }), /POLL_MODE/,
      `POLL_MODE ${JSON.stringify(mode)} must refuse, never default`);
    assert.deepEqual(c.calls, [], `POLL_MODE ${JSON.stringify(mode)} reached the service before refusing`);
  }
  // No tag, no mode needed: the claim half is B-T3.x's and is not the poll's switch.
  const none = stubClient();
  await claimJob({ client: none, polled: [], log: quietLog().log });
  assert.deepEqual(none.calls.map((c) => c.op), ["claim"]);
  // A tag that is not grammar-valid is refused by the job holding the token.
  await assert.rejects(claimJob({ client: stubClient(), polled: [{ repo: REPO, tag: "../x" }], mode: "shadow", log: quietLog().log }),
    /outside the grammar/);
});

const pathToUrl = (p) => new URL(`file://${path.resolve(p)}`).href;

/** A service client that answers `claim` with no lease and records every call. */
function stubClient() {
  const calls = [];
  return {
    calls,
    alerts: [],
    async call(op, body) {
      calls.push({ op, body });
      if (op === "register") return { ok: true, body: {} };
      return { ok: false, wait: "W_SERVICE_UNREACHABLE" };
    },
  };
}
const quietLog = () => { const lines = []; return { lines, log: { log: (l) => lines.push(l), error: (l) => lines.push(l) } }; };

test("remember seals what it saves, and a forged cache entry is discarded and alarmed on", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "poll-run-"));
  const env = {
    POLL_MODE: "shadow", [poll.STATE_KEY_ENV]: KEY_HEX, ASTRA_POLL_LISTINGS: JSON.stringify([quietListing()]),
    ASTRA_SWEEP_DUE: "false", ASTRA_SWEEP_RESULT: "skipped",
  };
  const first = runCmd("remember", dir, env);
  assert.equal(first.code, 0, first.stderr);
  assert.equal(first.outputs.changed, "true", "a first run saves the memory it started");
  assert.equal(JSON.parse(first.outputs.verdict).status, "green");
  const file = path.join(dir, poll.MEMORY_FILE);
  assert.equal(poll.openMemory(JSON.parse(fs.readFileSync(file, "utf8")), poll.stateKey(keyEnv())).discarded, null,
    "what remember wrote opens under the same key");

  const again = runCmd("remember", dir, env);
  assert.equal(again.outputs.changed, "false", "nothing new, nothing saved");

  // Forged: a registered tag added by whoever could write the cache.
  const envelope = JSON.parse(fs.readFileSync(file, "utf8"));
  envelope.memory.repos[REPO.toLowerCase()] = { etag: null, last_success_at: null, registered: ["v0.3.0"] };
  fs.writeFileSync(file, JSON.stringify(envelope));
  const forged = runCmd("remember", dir, env);
  assert.equal(forged.code, 0, forged.stderr);
  assert.deepEqual(JSON.parse(forged.outputs.verdict).codes, ["BOT_87_MEMORY_DISCARDED"]);
  assert.equal(forged.outputs.changed, "true", "and the fresh memory replaces it");

  const loaded = runCmd("load", dir, { [poll.STATE_KEY_ENV]: OTHER_KEY_HEX, GITHUB_EVENT_NAME: "schedule" });
  assert.equal(loaded.code, 0, loaded.stderr);
  assert.match(loaded.outputs.discarded, /does not verify/, "load discards an entry sealed under another key, and says so");

  const keyless = runCmd("remember", dir, { ...env, [poll.STATE_KEY_ENV]: "" });
  assert.equal(keyless.code, 1, "no key, no memory saved and no verdict relayed — poll-alert turns that into a red alarm");
  assert.equal(keyless.outputs.verdict, undefined);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("the relay sends the verdict remember composed, or a red one that says it did not", () => {
  const opts = { check: "poll-and-sweep", code: "BOT_87_DID_NOT_REPORT", run: null };
  const red = { schema: "astra.registry.alert-verdict/1", check: "poll-and-sweep", status: "red", codes: ["BOT_87_DID_NOT_REPORT"] };
  const green = { schema: "astra.registry.alert-verdict/1", check: "poll-and-sweep", status: "green" };
  assert.deepEqual(relayedVerdict(JSON.stringify(green), opts), { verdict: green, why: null });
  for (const [text, why] of [
    [undefined, /reported none/], ["", /reported none/], ["{", /not JSON/],
    [JSON.stringify({ ...green, status: "amber" }), /not sendable/],
    [JSON.stringify({ ...green, check: "ingest-roots" }), /about "ingest-roots"/],
  ]) {
    const r = relayedVerdict(text, opts);
    assert.deepEqual(r.verdict, red, `${JSON.stringify(text)} is relayed as red`);
    assert.match(r.why, why);
  }
  assert.throws(() => relayedVerdict("", { ...opts, code: "not a code" }), /fixed code/);
});

// ── the workflow, held to the table ────────────────────────────────────────

/** `plugins-ingest.yml`'s jobs, each as its lines, by a two-space-indent key under `jobs:`. */
function ingestJobs() {
  const lines = fs.readFileSync(INGEST_YML, "utf8").split("\n");
  const start = lines.indexOf("jobs:");
  assert.ok(start > 0, "plugins-ingest.yml has no jobs: block");
  const jobs = {};
  let name = null;
  for (const line of lines.slice(start + 1)) {
    const m = /^ {2}([a-z][a-z0-9-]*):\s*$/.exec(line);
    if (m) { name = m[1]; jobs[name] = []; continue; }
    if (name && !line.trim().startsWith("#")) jobs[name].push(line);
  }
  return jobs;
}

/** The env keys of the step whose `id:` is `id`, in a job's lines. */
function stepEnv(jobLines, id) {
  const at = jobLines.findIndex((l) => new RegExp(`^\\s+id:\\s*${id}\\s*$`).test(l));
  assert.ok(at >= 0, `no step with id ${id}`);
  let begin = at;
  while (begin > 0 && !/^\s+- (name|uses):/.test(jobLines[begin])) begin--;
  let end = at + 1;
  while (end < jobLines.length && !/^\s+- (name|uses):/.test(jobLines[end])) end++;
  const step = jobLines.slice(begin, end);
  const envAt = step.findIndex((l) => /^\s+env:\s*$/.test(l));
  const keys = [];
  if (envAt >= 0) {
    const indent = step[envAt].search(/\S/);
    for (const l of step.slice(envAt + 1)) {
      if (l.trim() === "") continue;
      if (l.search(/\S/) <= indent) break;
      const k = /^\s+([A-Z][A-Z0-9_]*):/.exec(l);
      if (k) keys.push(k[1]);
    }
  }
  return { keys, text: step.join("\n") };
}

test("every step that runs bot/lib/poll-run.mjs maps what its subcommand reads, and nothing else it could hold", () => {
  const jobs = ingestJobs();
  const workflowEnv = ["DRY_RUN", "POLL_MODE"];
  const src = fs.readFileSync(INGEST_YML, "utf8");
  // B-T5.1 is the cutover commit's (M-T6.2 commit B): POLL_MODE is `live`
  // exactly when log/cutover.json is on the tree, and `shadow` before. A marker
  // without the live poll would be a cutover with no release detection at all
  // (the backstop is paused in the same commit); a live poll before the marker
  // would register tags the legacy path is still handling.
  const cut = fs.existsSync(path.join(REPO_ROOT, "log", "cutover.json"));
  const mode = /^env:\n(?:\s+#.*\n|\s+[A-Z_]+:.*\n)*\s+POLL_MODE: (\w+)\s*$/m.exec(src)?.[1];
  assert.equal(mode, cut ? "live" : "shadow",
    `POLL_MODE is ${mode} and log/cutover.json is ${cut ? "" : "not "}on the tree; B-T5.1 flips the mode in the commit that adds the marker, and in no other`);
  let checked = 0;
  for (const [cmd, io] of Object.entries(run.JOB_IO)) {
    const job = jobs[io.job];
    assert.ok(job, `plugins-ingest.yml has no ${io.job} job for ${cmd}`);
    const { keys, text } = stepEnv(job, io.step);
    assert.match(text, new RegExp(`run: node bot/lib/poll-run\\.mjs ${cmd}\\s*$`, "m"), `${io.job}'s ${io.step} step does not run ${cmd}`);
    for (const name of io.reads) {
      if (workflowEnv.includes(name) || name.startsWith("GITHUB_")) continue;
      assert.ok(keys.includes(name), `${io.job}'s ${io.step} step does not map ${name}, which ${cmd} reads`);
    }
    for (const name of keys) {
      assert.ok(io.reads.includes(name), `${io.job}'s ${io.step} step maps ${name}, which ${cmd} never reads`);
    }
    checked++;
  }
  assert.equal(checked, 4);
  // No other job runs a subcommand: a subcommand is a job.
  const runs = [...src.matchAll(/run: node bot\/lib\/poll-run\.mjs (\S+)/g)].map((m) => m[1]);
  assert.deepEqual(runs.sort(), Object.keys(run.JOB_IO).sort());
});

test("every output a job hands on is one its step writes, and every one read downstream is handed on", () => {
  const jobs = ingestJobs();
  const src = fs.readFileSync(INGEST_YML, "utf8");
  const outputsOf = (lines) => {
    const at = lines.findIndex((l) => /^ {4}outputs:\s*$/.test(l));
    if (at < 0) return {};
    const out = {};
    for (const l of lines.slice(at + 1)) {
      if (l.trim() === "") continue;
      if (!/^ {6}/.test(l)) break;
      const m = /^ {6}([a-z_]+):\s*\$\{\{\s*steps\.([a-z_-]+)\.outputs\.([a-z_-]+)\s*\}\}/.exec(l);
      if (m) out[m[1]] = { step: m[2], name: m[3] };
    }
    return out;
  };
  const problems = [];
  for (const io of Object.values(run.JOB_IO)) {
    for (const [name, o] of Object.entries(outputsOf(jobs[io.job]))) {
      if (o.step !== io.step) continue;
      if (!io.writes.includes(o.name)) problems.push(`${io.job}.outputs.${name} reads ${io.step}'s ${o.name}, which it never writes`);
    }
  }
  let reads = 0;
  for (const m of src.matchAll(/needs\.([a-z-]+)\.outputs\.([a-z_]+)/g)) {
    reads++;
    const out = outputsOf(jobs[m[1]] ?? []);
    if (!out[m[2]]) problems.push(`needs.${m[1]}.outputs.${m[2]} is read and ${m[1]} declares no such output`);
  }
  assert.ok(reads >= 15, `only ${reads} needs.*.outputs reads found; this walk read nothing`);
  assert.equal(problems.join("\n"), "", "an output read downstream is an empty string, which reads as nothing to report");
});

test("poll-alert checks out every file the relay imports, and posts to BOT-87's check", () => {
  const job = ingestJobs()["poll-alert"];
  assert.ok(job, "plugins-ingest.yml has no poll-alert job");
  const listed = new Set(job.map((l) => /^\s{12}(\S+)\s*$/.exec(l)?.[1]).filter(Boolean));
  const closure = (entry, seen = new Set()) => {
    if (seen.has(entry)) return seen;
    seen.add(entry);
    const text = fs.readFileSync(path.join(REPO_ROOT, entry), "utf8");
    for (const m of text.matchAll(/^import\s+[\s\S]*?from\s+"(\.[^"]+)";/gm)) {
      closure(path.relative(REPO_ROOT, path.resolve(path.dirname(path.join(REPO_ROOT, entry)), m[1])), seen);
    }
    return seen;
  };
  const need = closure("bot/lib/relay-verdict.mjs");
  assert.ok(need.size >= 3, `the relay's closure is ${[...need].join(", ")}; this walk read nothing`);
  for (const f of need) assert.ok(listed.has(f), `poll-alert runs bot/lib/relay-verdict.mjs, which needs ${f}, and its sparse checkout omits it`);
  assert.ok(job.some((l) => /^\s+check:\s*poll-and-sweep\s*$/.test(l)), "poll-alert posts to poll-and-sweep");
  assert.ok(job.some((l) => /--check poll-and-sweep --code BOT_87_DID_NOT_REPORT/.test(l)));
});
