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
import { safeTag } from "../lib/intake.mjs";

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
const POLL_SURFACE = ["isUsableTag", "parseReleasesAtom", "pollFeed"];

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

// And what `bot/watch.mjs` exports now: what it exported at that commit, minus
// `pollFeed`. The removal is the one intended surface change in this task.
// `recordedTagsByRepo` joined it with B-T3.9: the backstop and the `/release` ping
// read one derivation of a repository's recorded tags (BOT-74), not two.
const WATCH_SURFACE = ["bot74Filter", "recordedTagsByRepo", "runDrain", "runWatch"];

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
const SURFACE_BEFORE_THE_CUT = [
  "SEEN_FILE",
  "WATCH_AFTER_DAYS",
  "WATCH_BATCH",
  "bot74Filter",
  "findListingByRepo",
  "firstWrittenLine",
  "newReleases",
  "parseReleasePing",
  "parseReleasesAtom",
  "pollFeed",
  "readSeen",
  "resolveSubmitter",
  "runDrain",
  "runWatch",
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

test("bot/watch.mjs exports exactly what it did, minus the function that moved", () => {
  assert.equal(Object.keys(watch).sort().join(", "), WATCH_SURFACE.join(", "),
    "bot/watch.mjs's surface is not the one B-T2.6 left. pollFeed is imported here now and deliberately not " +
    "re-exported: a second door onto it is how two modules end up owning one function");
  assert.ok(!Object.keys(watch).includes("pollFeed"),
    "bot/watch.mjs exports pollFeed again. The whole point of the move is that bot/lib/poll.mjs owns it");
});

// The three pins above say which module holds each name today. This one says
// that no name fell between them.
test("every name that existed before the cut is still exported by one of the three modules", () => {
  assert.equal(SURFACE_BEFORE_THE_CUT.length, 16,
    `the pre-cut surface is ${SURFACE_BEFORE_THE_CUT.length} names and it was 16 on 2026-09-20. This list is not ` +
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
  for (const name of POLL_SURFACE) {
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
// (above) guards the feed; `safeTag` (`bot/lib/intake.mjs`) parses the
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

    const [intakeTakesIt, pollTakesIt] = bothVerdicts(tag);
    assert.equal(intakeTakesIt, true,
      `bot/lib/intake.mjs's safeTag now REFUSES ${JSON.stringify(tag)} (${shape}). If that was deliberate, it is a ` +
      "change to what `/approve owner/repo@tag` accepts from a maintainer — an owner's call, per dev/couplings.md " +
      "26 — and bot/lib/poll.mjs's isUsableTag no longer has a difference to be the stricter half of");
    assert.equal(pollTakesIt, false,
      `bot/lib/poll.mjs's isUsableTag now ACCEPTS ${JSON.stringify(tag)} (${shape}). It is the hardened predicate ` +
      "on the feed path; bot/lib/intake.mjs's safeTag is charset-only and did not change, so this shape now " +
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
    const [intakeTakesIt, pollTakesIt] = bothVerdicts(tag);
    if (intakeTakesIt === pollTakesIt) continue;
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
    "bot/lib/intake.mjs's safeTag. isUsableTag is supposed to be the stricter of the two in every case — it is " +
    "safeTag's charset plus four refusals — so this means the charset the two share stopped being shared, and " +
    `safeTag's docblock now says something false. First few: ${JSON.stringify(backwards.slice(0, 8))}`);

  assert.deepEqual(unexplained, [],
    `${unexplained.length} tag(s) are taken by bot/lib/intake.mjs's safeTag and refused by bot/lib/poll.mjs's ` +
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
      `bot/lib/intake.mjs's safeTag must refuse ${JSON.stringify(notAString) ?? String(notAString)} rather than ` +
      "return it — it is the value echoed back into a public comment");
    assert.throws(() => poll.isUsableTag(notAString), TypeError,
      `bot/lib/poll.mjs's isUsableTag no longer throws on ${JSON.stringify(notAString) ?? String(notAString)}. ` +
      "If it now returns false, that is the fix — remove this assertion and the non-string paragraph of safeTag's " +
      "docblock in bot/lib/intake.mjs, which currently tells readers the two differ here");
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
      "a repository that has been deleted, renamed or made private is a listing-level problem, and runWatch " +
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

// B-T2.6's first canary, and the one of its five the tree can answer today:
// *a feed with the listed tag and a `cli-v1.2.0` registers nothing.* The other
// four are about the sweep and the signed cache, neither of which exists yet.
//
// It is written through `runWatch` rather than through `bot74Filter`, which
// already has its own test in policy.test.mjs, because the claim is about the
// WHOLE path — the conditional GET, the parse, "which of these is new", and
// the prefix filter — and after this task that path crosses three modules
// where it used to cross two.
test("a feed carrying the listed tag and a cli-v release dispatches nothing at all", async () => {
  const root = registryTree();
  const xml = feed(
    entry(tagUrl("cli-v1.2.0"), "2026-08-08T10:00:00Z"),
    entry(tagUrl("v0.2.0"), "2026-01-01T10:00:00Z"),
  );
  // The release lookup SUCCEEDS here, and that is the point. The first version
  // of this test made it throw — "nothing here is worth an API call" — and
  // removing the prefix filter from `runWatch` then produced an `ERR` log line
  // and still no dispatch, so the assertion that matters stayed green and only
  // the one about the log's wording went red. A stub that fails hides the
  // failure it was meant to expose: the filter is what must stop this, not the
  // stub. It records instead, and "no API call was made" becomes an assertion
  // rather than a stub's side effect.
  const lookups = [];
  const { dispatch, seen, log } = await watch.runWatch({
    root,
    now: new Date("2026-08-10T12:00:00Z"),
    deps: {
      fetchImpl: async () => ok(xml),
      fetchRelease: async (repo, tag) => {
        lookups.push(`${repo}@${tag}`);
        return { tag_name: tag, author: { login: "the-author" } };
      },
    },
  });

  assert.equal(dispatch.length, 0, `nothing should be ingested, and ${JSON.stringify(dispatch)} was: ${log.join("\n")}`);
  assert.deepEqual(lookups, [],
    "the filter runs BEFORE the release lookup, so a monorepo's `cli-v` tag costs this registry not one API call");
  assert.ok(log.some((l) => l.includes("cli-v1.2.0") && l.includes("prefix")),
    `the skip has to say why, and the log said:\n${log.join("\n")}`);

  // And recorded once rather than skipped daily for ever. A `cli-v` tag that
  // is not remembered is a tag the backstop re-offers on every run, which from
  // R3 also means a public decision record refusing a release that was never a
  // plugin release (BOT-74).
  const row = seen.repos[REPO];
  assert.deepEqual(row.checked_tags, ["cli-v1.2.0"],
    "the filtered tag is remembered, so tomorrow's poll does not re-offer it");
  assert.equal(row.last_seen_tag, undefined,
    "and nothing was accepted, so there is no new newest tag");
  assert.equal(row.last_error, undefined, `the run was clean: ${JSON.stringify(row)}`);

  fs.rmSync(root, { recursive: true, force: true });
});
