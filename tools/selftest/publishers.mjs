// Who may claim what: publisher records against their schema, and
// tools/validate.mjs judging them at the first gate by the loader's; every badge
// resolving and no record shipped unused, the no-publishers/ fail-closed case,
// expiry firing, homoglyph display-name collisions, `covers` in both orderings,
// reserved prefixes, whole-line proof, the four re-check outcomes, and the
// daily job's expiry being the library's rule rather than a copy of it.
//
// Two tests below declare their own `const tmp` inside the test body, shadowing
// the harness one. Those are per-test trees and the shadows are deliberate,
// which is why this module imports no `tmp` at all.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildIndex } from "../build-index.mjs";
import { validate as validateSchema } from "../lib/jsonschema.mjs";
import { reservedPrefixViolation } from "../lib/reserved.mjs";
import {
  REPO_ROOT,
  expiredPublishers,
  loadPublishers,
  loadSchemas,
  loadSources,
  publisherNameCollisions,
  publisherRecords,
} from "../lib/sources.mjs";
import { checkPublisherRecords, runValidation } from "../validate.mjs";
import { NO_LISTING_FILE, proofNamesOwner, recheck } from "../../bot/recheck-publishers.mjs";
import { test, assert } from "./harness.mjs";

// ── gap 6: a record that reaches no listing ─────────────────────────────────
//
// Three tests guard the badge and all three point FROM a listing outward:
// every listing's publisher resolves, no record ships unused, no two records
// render as one word. Nothing asked the opposite question — is there a
// reviewed record here that reaches no listing at all? — and on 2026-08-19
// `publishers/KnlCE.json` was written, reviewed, correct, and reached nothing
// for three days, because every plugin of his was published from an
// organisation. On 2026-09-12 it went back into that state, deliberately:
// `covers` moved to MINICE-AI when the organisation was renamed, and the one
// listing, under the freed login KNICE-TECH, was frozen unlisted. Nothing
// said so either time.
//
// The entry that records this said the fix had to be a declaration, because a
// record for someone who has not published yet and one whose only plugin was
// withdrawn "are identical in the files". **They are not, and that is what
// lets the second need no declaration**: nothing in this repository deletes a
// listing to withdraw it. A takedown compiles to `"unlisted": true` on
// `plugin.json` (bot/lib/compile-decision.mjs, `delist`), POLICY.md §6 retires
// a plugin the same way, and the directory stays. So a record whose logins own
// only unlisted plugins is a withdrawal, and is REPORTED; a record whose logins
// own no plugin at all is either a mistake or a publisher who has not
// published, and only the declaration can say which.

/**
 * The declarations in `NO_LISTING_FILE`'s text, and every way that text is
 * wrong. The file's shape is held here. One other program reads it: the daily
 * re-check, `bot/recheck-publishers.mjs`, which owns the path this module
 * imports and drops a withdrawn record's declaration by `record` and nothing
 * else — held to this reader by the last test in this module, which runs the
 * job and then this function over what it wrote.
 */
function readNoListing(text) {
  const declared = new Map();
  const problems = [];
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { declared, problems: [`${NO_LISTING_FILE} is not JSON: ${e.message}`] };
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc) || !Array.isArray(doc.declarations)) {
    return { declared, problems: [`${NO_LISTING_FILE} carries no \`declarations\` array`] };
  }
  for (const [i, d] of doc.declarations.entries()) {
    const at = `${NO_LISTING_FILE} declarations[${i}]`;
    if (d === null || typeof d !== "object" || Array.isArray(d)) {
      problems.push(`${at} is not an object`);
      continue;
    }
    // A faulty entry declares nothing: it is refused, and the record it names
    // is judged as though it were absent, so a malformed excuse cannot quiet
    // the finding it was written to quiet.
    const before = problems.length;
    const extra = Object.keys(d).filter((k) => k !== "record" && k !== "reason");
    if (extra.length) problems.push(`${at} carries ${extra.join(", ")}; a declaration is {record, reason} and nothing else`);
    if (typeof d.record !== "string" || !/^publishers\/[^/]+\.json$/.test(d.record)) {
      problems.push(`${at}.record is ${JSON.stringify(d.record)}, not a path of the form publishers/<owner>.json`);
      continue;
    }
    if (typeof d.reason !== "string" || d.reason.trim() === "") {
      problems.push(`${at} declares ${d.record} and gives no reason; the reason is the declaration, a bare entry is an excuse`);
    }
    if (declared.has(d.record)) problems.push(`${at} declares ${d.record} a second time`);
    if (problems.length === before) declared.set(d.record, d.reason);
  }
  return { declared, problems };
}

/**
 * Which listings every publisher record reaches, and what that means.
 *
 * `fail` is what may refuse a gate; `note` is what is reported and never
 * refused. The split is the whole design, because this suite runs as the
 * publish path's fifth check and in the moderation commit job, so anything in
 * `fail` that a bot commit can produce is a bot commit this refuses:
 *
 *   - no plugin at all under the record's logins, undeclared → fail. No bot
 *     write produces it: a publication only adds listings, and a takedown only
 *     sets `unlisted` or `yanked` and deletes nothing.
 *   - only unlisted plugins, undeclared → note. A takedown produces exactly it.
 *   - declared, and now reaching a listed plugin → note. The first publication
 *     of a declared publisher produces exactly it.
 *   - a declaration naming no record → fail. Only a person writes one — or the
 *     daily re-check, deleting an expired record, which runs no suite before it
 *     pushes; its declaration goes in the same change, and this is what says so.
 *
 * WHICH listings a record reaches is the generator's answer, not this
 * function's: a record is reached when `buildIndex` ships it in
 * `signed.publishers`. The owner-half lookup below exists only to find the
 * UNLISTED plugins a record owns, which the generator skips — and it is held
 * to the generator on every listed plugin, so the day `build-index.mjs` keys
 * the badge on something else this is red rather than a second rule.
 */
function publisherReach(root, noListingText) {
  const fail = [];
  const note = [];
  const { declared, problems } = readNoListing(noListingText);
  fail.push(...problems);

  const { plugins } = loadSources(root);
  const { publishers } = loadPublishers(root);
  const index = buildIndex({ root, serial: 1 });
  const shipped = new Set(Object.keys(index.signed.publishers ?? {}));
  const generated = new Map(index.signed.plugins.map((e) => [e.id, e.publisher]));
  const recordOf = (p) => publishers.get(String(p.doc?.source?.repo ?? "").split("/")[0].toLowerCase());

  for (const p of plugins) {
    if (p.doc?.unlisted === true) continue;
    const mine = recordOf(p)?.doc.owner;
    if (generated.get(p.doc?.id) !== mine) {
      fail.push(`${p.file}: this check's lookup finds publisher ${JSON.stringify(mine)} and build-index.mjs emits ` +
        `${JSON.stringify(generated.get(p.doc?.id))}; the badge's rule has moved and the unlisted half of this check has not followed it`);
    }
  }

  const records = publisherRecords(publishers);
  const files = new Set(records.map((r) => r.file));
  for (const rec of records) {
    const listed = [];
    const unlisted = [];
    for (const p of plugins) {
      if (recordOf(p) === rec) (p.doc.unlisted === true ? unlisted : listed).push(`plugins/${p.dir}`);
    }
    if (shipped.has(rec.doc.owner) !== listed.length > 0) {
      fail.push(`${rec.file}: build-index.mjs ${shipped.has(rec.doc.owner) ? "ships" : "does not ship"} it and this ` +
        `check counts ${listed.length} listed plugin(s) under its logins; the two answers to "does it reach a listing" disagree`);
      continue;
    }
    const why = declared.get(rec.file);
    if (listed.length) {
      if (why !== undefined) {
        note.push(`${rec.file} is declared in ${NO_LISTING_FILE} as expecting no listing and now reaches ` +
          `${listed.join(", ")}; delete the declaration. Not refused: the publication that did this ran this suite.`);
      }
      continue;
    }
    if (why !== undefined) continue;
    const logins = [rec.doc.owner, ...(Array.isArray(rec.doc.covers) ? rec.doc.covers : [])].join(", ");
    if (unlisted.length) {
      note.push(`${rec.file} reaches no listed plugin: everything under ${logins} is unlisted (${unlisted.join(", ")}), ` +
        "so no badge ships. Reported and never refused — a takedown sets `unlisted`, and the moderation commit job runs this suite.");
      continue;
    }
    fail.push(`${rec.file} reaches no listing: none of its logins (${logins}) owns the source.repo of any plugin here, ` +
      `listed or unlisted, and ${NO_LISTING_FILE} does not declare it. The badge is keyed on the owner half of ` +
      "source.repo, lowercased — so either `owner`/`covers` names the wrong account, which is how publishers/KnlCE.json " +
      `reached nothing for three days in August 2026, or the publisher has not published yet and ${NO_LISTING_FILE} ` +
      "should say so, with a reason.");
  }
  for (const record of declared.keys()) {
    if (!files.has(record)) {
      fail.push(`${NO_LISTING_FILE} declares ${record}, which is not a publisher record here (${[...files].join(", ")}). ` +
        "A declaration that matches nothing is refused; if the daily re-check withdrew the record, its declaration goes too.");
    }
  }
  return { fail, note, records: records.length, plugins: plugins.length };
}

export async function run() {
  // Through the loader's schema, `loadSchemas().publisher`, and not a read of
  // the file of this test's own. Until gap 91 this opened
  // `schema/publisher-v1.json` directly while `loadSchemas` loaded the same
  // file for nobody: two answers to "which schema judges a publisher", one of
  // them unread. It is one answer now, and `tools/validate.mjs` judges by it
  // too (the test after this one).
  await test("every publishers/ record validates against schema/publisher-v1.json", () => {
    const schema = loadSchemas(REPO_ROOT).publisher;
    const { errors, publishers } = loadPublishers(REPO_ROOT);
    assert(errors.length === 0, errors.map((e) => `${e.file}: ${e.message}`).join("\n"));
    const records = publisherRecords(publishers);
    assert(records.length >= 1, "no publisher records, so this test proves nothing");
    for (const { file, doc } of records) {
      const errs = validateSchema(schema, doc);
      assert(errs.length === 0, `${file}: ` + errs.map((e) => `${e.path} ${e.message}`).join("\n"));
    }
  });

  // Gap 91. `tools/validate.mjs` is the first of the five checks the publish
  // path runs and the only one CI names "Validate the listings"; this module
  // is the fifth. A malformed publisher record used to pass the first — with
  // 0 errors in both modes, measured, for a record no listing reaches — and be
  // refused only here. Three clauses, each with its own subject:
  //
  //   (a) the committed records are judged and pass: `checkPublisherRecords`
  //       over the real tree, with the loader's schema, reports nothing;
  //   (b) it judges by the schema it is HANDED, which is how `runValidation`
  //       gives it the loader's: a tightened copy of that schema turns every
  //       committed record red, so a function that read the file itself — a
  //       second answer — would not follow and this fails;
  //   (c) `runValidation` calls it: a copy of `publishers/` with one wrong-typed
  //       member, one enum miss and one record the loader drops is refused
  //       three times, each by its file and member, and for nothing else.
  //
  // The subjects are synthesised from the committed records, because the
  // committed tree has never contained a malformed one.
  await test("tools/validate.mjs judges every publisher record at the first gate, by the loader's schema", async () => {
    const schemas = loadSchemas(REPO_ROOT);
    const collect = () => {
      const items = [];
      const push = (level) => (where, message) => items.push({ level, where, message });
      return { items, error: push("error"), warn: push("warn"), note: push("note") };
    };

    // (a)
    const clean = collect();
    const committed = loadPublishers(REPO_ROOT);
    const committedFiles = publisherRecords(committed.publishers).map((r) => r.file);
    assert(committedFiles.length >= 2, `${committedFiles.length} committed record(s); (b) below needs at least two to mean anything`);
    checkPublisherRecords({ report: clean, schemas }, committed);
    assert(clean.items.length === 0,
      `the committed publisher records are refused by tools/validate.mjs:\n${clean.items.map((i) => `${i.where}: ${i.message}`).join("\n")}`);

    // (b)
    const tight = collect();
    const tightened = structuredClone(schemas.publisher);
    tightened.properties.display_name.maxLength = 1;
    checkPublisherRecords({ report: tight, schemas: { ...schemas, publisher: tightened } }, committed);
    const judged = new Set(tight.items.filter((i) => i.message.startsWith("$.display_name")).map((i) => i.where));
    const unjudged = committedFiles.filter((f) => !judged.has(f));
    assert(unjudged.length === 0,
      `a one-character display_name limit, handed to checkPublisherRecords as ctx.schemas.publisher, did not refuse ` +
      `${unjudged.join(", ")}; the function is judging by some other schema than the loader's`);

    // (c)
    const tree = fs.mkdtempSync(path.join(os.tmpdir(), "astra-pub-gate-"));
    try {
      fs.cpSync(path.join(REPO_ROOT, "publishers"), path.join(tree, "publishers"), { recursive: true });
      const pick = committedFiles.find((f) => f === "publishers/mihailinl.json") ?? committedFiles[0];
      const other = committedFiles.find((f) => f !== pick);
      const edit = (rel, change) => {
        const full = path.join(tree, rel);
        const before = fs.readFileSync(full);
        const doc = JSON.parse(before);
        change(doc);
        fs.writeFileSync(full, JSON.stringify(doc, null, 2) + "\n");
        assert(!fs.readFileSync(full).equals(before), `the edit to ${rel} changed no byte, so (c) would prove nothing`);
      };
      edit(pick, (d) => { d.display_name = 42; });
      edit(other, (d) => { d.tier = "community"; });
      // A record the loader DROPS — its owner is not its file name — which no
      // schema check can reach, so it must be the loader's refusal that says so.
      fs.writeFileSync(path.join(tree, "publishers", "stray.json"),
        JSON.stringify({ ...JSON.parse(fs.readFileSync(path.join(REPO_ROOT, pick))), owner: "somebody-else" }, null, 2) + "\n");

      const { report } = await runValidation({
        root: tree, allowStaging: true, allowDirect: false, online: false, artifactsDir: null, index: false,
      });
      const mine = report.errors.filter((e) => e.where.startsWith("publishers/"));
      const at = (file, needle) => mine.filter((e) => e.where === file && e.message.includes(needle));
      assert(at(pick, "$.display_name").length === 1,
        `${pick} with display_name 42 is not refused by tools/validate.mjs naming the member:\n` +
        mine.map((e) => `${e.where}: ${e.message}`).join("\n"));
      assert(at(other, "$.tier").length === 1,
        `${other} with tier "community" is not refused by tools/validate.mjs naming the member:\n` +
        mine.map((e) => `${e.where}: ${e.message}`).join("\n"));
      assert(at("publishers/stray.json", "does not match the file name").length === 1,
        "a record the loader drops is not refused by tools/validate.mjs; it would be invisible to every schema check");
      assert(mine.length === 3,
        `expected exactly the three planted refusals under publishers/, got ${mine.length}:\n` +
        mine.map((e) => `${e.where}: ${e.message}`).join("\n"));
    } finally {
      fs.rmSync(tree, { recursive: true, force: true });
    }
  });

  // The badge's whole safety property, asserted on the shipped document rather
  // than on the code that writes it: a listing may only name a publisher the
  // catalogue actually carries a reviewed record for. A dangling key would be a
  // badge a client cannot resolve, and the tempting way to render that is "some
  // publisher" — which is a badge for an account nobody reviewed.
  await test("every listing's publisher resolves, and no record is shipped unused", () => {
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    const map = doc.signed.publishers ?? {};
    const named = new Set(doc.signed.plugins.map((p) => p.publisher).filter(Boolean));
    for (const key of named) {
      assert(Object.hasOwn(map, key), `${key} is named by a listing and absent from signed.publishers`);
    }
    for (const key of Object.keys(map)) {
      assert(named.has(key), `${key} ships a record no listing points at`);
    }
  });

  // Gap 6, the fourth direction, on the committed tree. Today one record needs
  // its declaration: publishers/KnlCE.json covers MINICE-AI and the one plugin
  // of his is frozen unlisted under KNICE-TECH, so its logins own no plugin at
  // all — delete the entry and this is red, naming it.
  await test("every publisher record reaches a listing, or says why it expects none", () => {
    const { fail, note, records, plugins } = publisherReach(REPO_ROOT, fs.readFileSync(path.join(REPO_ROOT, NO_LISTING_FILE), "utf8"));
    assert(records >= 1 && plugins >= 1, `${records} record(s) over ${plugins} plugin(s); an empty walk proves nothing`);
    for (const n of note) console.log(`  note  ${n}`);
    assert(fail.length === 0, fail.join("\n"));
  });

  // The same function over a copy of the tree built so that every branch it
  // distinguishes has a subject, because the committed tree holds two records
  // and exercises two of them. Made from committed material — the real
  // plugins, three of them pointed at synthesised owners — and with a
  // publishers/ of its own, so a record added to or changed on the real tree
  // moves nothing here:
  //
  //   listed-owner      owns text-utils, listed              nothing
  //   covered-person    reaches json-tools ONLY via covers   nothing — a covered login is a login
  //   withdrawn-owner   owns only echo-stt, unlisted         a note, never a failure
  //   not-yet-published owns no plugin at all                FAIL undeclared; nothing declared
  //
  // then a declaration set carrying one of every mistake the file can hold.
  await test("a record with no listing fails unless declared; a withdrawn one and a stale declaration are reported, not refused", () => {
    const tree = fs.mkdtempSync(path.join(os.tmpdir(), "astra-pub-reach-"));
    try {
      for (const dir of ["plugins", "registry", "policy", "schema"]) {
        fs.cpSync(path.join(REPO_ROOT, dir), path.join(tree, dir), { recursive: true });
      }
      fs.mkdirSync(path.join(tree, "publishers"));
      const repoOf = (id, repo) => {
        const file = path.join(tree, "plugins", id, "plugin.json");
        const doc = JSON.parse(fs.readFileSync(file, "utf8"));
        assert(doc.source.repo !== repo, `plugins/${id} already names ${repo}, so the fixture would prove nothing`);
        doc.source.repo = repo;
        fs.writeFileSync(file, JSON.stringify(doc, null, 2) + "\n");
        return doc.unlisted === true;
      };
      assert(repoOf("text-utils", "listed-owner/text-utils") === false, "plugins/text-utils must be LISTED for the owner case");
      assert(repoOf("json-tools", "covered-org/json-tools") === false, "plugins/json-tools must be LISTED for the covers case");
      assert(repoOf("echo-stt", "withdrawn-owner/echo-stt") === true, "plugins/echo-stt must be UNLISTED for the withdrawal case");
      const record = (owner, over = {}) => fs.writeFileSync(path.join(tree, "publishers", `${owner}.json`), JSON.stringify({
        schema: "astra.registry.publisher/1", owner, display_name: `Fixture ${owner}`, tier: "astra_team",
        verified_at: "2026-01-01", evidence: { kind: "first-party", note: "fixture" }, ...over,
      }, null, 2) + "\n");
      record("listed-owner");
      record("covered-person", { covers: ["covered-org"] });
      record("withdrawn-owner");
      record("not-yet-published");

      const none = publisherReach(tree, JSON.stringify({ declarations: [] }));
      assert(none.records === 4, `the fixture loaded ${none.records} record(s), not 4`);
      assert(none.fail.length === 1 && none.fail[0].startsWith("publishers/not-yet-published.json reaches no listing"),
        `with nothing declared, exactly not-yet-published.json should fail:\n${none.fail.join("\n")}`);
      assert(none.note.length === 1 && none.note[0].startsWith("publishers/withdrawn-owner.json reaches no listed plugin"),
        `with nothing declared, exactly the withdrawn owner should be reported, and not refused:\n${none.note.join("\n")}`);

      const ok = publisherReach(tree, JSON.stringify({ declarations: [{ record: "publishers/not-yet-published.json", reason: "fixture: not published yet" }] }));
      assert(ok.fail.length === 0, `a declared record with no listing still failed:\n${ok.fail.join("\n")}`);

      const wrong = publisherReach(tree, JSON.stringify({ declarations: [
        { record: "publishers/not-yet-published.json", reason: "fixture" },
        { record: "publishers/listed-owner.json", reason: "fixture: stale, it reaches text-utils" },
        { record: "publishers/ghost.json", reason: "fixture: names no record" },
        { record: "publishers/not-yet-published.json", reason: "fixture: twice" },
        { record: "publishers/withdrawn-owner.json", reason: "  " },
        { record: "not-yet-published.json", reason: "fixture: not a path" },
        { record: "publishers/covered-person.json", reason: "fixture", until: "someday" },
      ] }));
      const has = (list, needle) => list.filter((m) => m.includes(needle)).length;
      assert(has(wrong.fail, "declares publishers/ghost.json, which is not a publisher record here") === 1, `a declaration matching nothing was not refused:\n${wrong.fail.join("\n")}`);
      assert(has(wrong.fail, "declares publishers/not-yet-published.json a second time") === 1, `a duplicate declaration was not refused:\n${wrong.fail.join("\n")}`);
      assert(has(wrong.fail, "declares publishers/withdrawn-owner.json and gives no reason") === 1, `a blank reason was not refused:\n${wrong.fail.join("\n")}`);
      assert(has(wrong.fail, "not a path of the form publishers/<owner>.json") === 1, `a malformed record path was not refused:\n${wrong.fail.join("\n")}`);
      assert(has(wrong.fail, "carries until") === 1, `an unknown member was not refused:\n${wrong.fail.join("\n")}`);
      assert(wrong.fail.length === 5, `expected exactly the five planted declaration faults, got ${wrong.fail.length}:\n${wrong.fail.join("\n")}`);
      assert(has(wrong.note, "publishers/listed-owner.json is declared") === 1,
        `a stale declaration should be reported, and not refused:\n${wrong.note.join("\n")}`);
      // The blank-reason entry declared nothing, so the withdrawal it named is
      // reported exactly as though it were not there.
      assert(has(wrong.note, "publishers/withdrawn-owner.json reaches no listed plugin") === 1 && wrong.note.length === 2,
        `a faulty declaration quieted the finding it named, or something else was reported:\n${wrong.note.join("\n")}`);
    } finally {
      fs.rmSync(tree, { recursive: true, force: true });
    }
  });

  // Fail closed, and exercised rather than asserted over an empty set. Every
  // listing today HAS a publisher record, so a test that walked the shipped
  // document looking for owners without one would loop over nothing and pass for
  // that reason — the exact vacuity this suite exists to refuse. So the generator
  // is run against a tree with no publishers/ at all, which is also the state
  // every fork and every first day is in.
  await test("with no publishers/ at all, no listing carries a publisher key", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-nopub-"));
    try {
      for (const dir of ["plugins", "registry", "policy", "schema"]) {
        const from = path.join(REPO_ROOT, dir);
        if (fs.existsSync(from)) fs.cpSync(from, path.join(tmp, dir), { recursive: true });
      }
      assert(!fs.existsSync(path.join(tmp, "publishers")), "the copy must not carry publishers/");
      const doc = buildIndex({ root: tmp, serial: 1 });
      assert(doc.signed.plugins.length >= 1, "no listings in the copy, so this proves nothing");
      assert(!Object.hasOwn(doc.signed, "publishers"),
        "signed.publishers is present with no records behind it");
      const badged = doc.signed.plugins.filter((e) => Object.hasOwn(e, "publisher"));
      assert(badged.length === 0,
        `no record exists and ${badged.length} listing(s) still carry a publisher key`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  // The expiry has to be able to fire, or it is a comment. `verified` is stored
  // as live evidence plus the date it last held, precisely so a tier granted once
  // and never revisited cannot go on asserting who somebody used to be.
  await test("an expired publisher record is reported, and a current one is not", () => {
    const stale = new Map([["ghost", { file: "publishers/ghost.json", doc: { owner: "ghost", expires_at: "2020-01-01" } }]]);
    assert(expiredPublishers(stale).length === 1, "an expired record went unreported");
    const fresh = new Map([["ghost", { file: "publishers/ghost.json", doc: { owner: "ghost", expires_at: "2999-01-01" } }]]);
    assert(expiredPublishers(fresh).length === 0, "a current record was reported as expired");
    const committed = loadPublishers(REPO_ROOT).publishers;
    assert(expiredPublishers(committed).length === 0,
      "a committed publisher record is past its own expiry: " +
      expiredPublishers(committed).map((e) => `${e.file} (${e.expires_at})`).join(", "));
  });

  // The display name is the word a user reads beside a trust mark, so two
  // publishers rendering as the same word is an impersonation whether or not
  // anyone meant one. A CLIENT cannot catch this — homoglyphs are exactly as
  // indistinguishable to a renderer as to a reader — so review is the only place
  // it can be caught, and review is what forgets.
  await test("no two publishers render as the same word", () => {
    const { publishers } = loadPublishers(REPO_ROOT);
    const clashes = publisherNameCollisions(publishers);
    assert(clashes.length === 0, clashes.map((c) => `${c.a} vs ${c.b}: ${c.why}`).join("\n"));

    // Exercised, not asserted over a set of two that happens to be fine. This
    // repository contains the pair that motivates it: a capital i against a
    // lowercase L, which case folding leaves distinct and nobody can see.
    const planted = new Map([
      ["one", { file: "publishers/one.json", doc: { owner: "someone-else", display_name: "KNICE" } }],
      ["two", { file: "publishers/two.json", doc: { owner: "KnlCE", display_name: "KNICE" } }],
    ]);
    assert(publisherNameCollisions(planted).length === 1, "two records displaying the same word must clash");

    const distinct = new Map([
      ["one", { file: "publishers/one.json", doc: { owner: "mihailinl", display_name: "Mihailin" } }],
      ["two", { file: "publishers/two.json", doc: { owner: "KnlCE", display_name: "KNICE" } }],
    ]);
    assert(publisherNameCollisions(distinct).length === 0, "two genuinely different publishers must not clash");
  });

  // `covers` lets ONE reviewed record speak for several owner logins, because a
  // person's plugins do not all live under their personal one. Three things have
  // to hold, and the second is the one that would have gone unnoticed.
  await test("a covered owner resolves to the same record, and cannot be claimed twice", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-covers-"));
    const write = (name, doc) =>
      fs.writeFileSync(path.join(tmp, "publishers", name), JSON.stringify(doc, null, 2));
    const load = () => loadPublishers(tmp);
    fs.mkdirSync(path.join(tmp, "publishers"));

    // 1. Every claimed login finds the record, and finds the SAME object.
    write("someone.json", { owner: "someone", covers: ["SOMEONE-TECH"], display_name: "Someone" });
    const { errors, publishers } = load();
    assert(errors.length === 0, `a well-formed record errored: ${JSON.stringify(errors)}`);
    assert(publishers.has("someone") && publishers.has("someone-tech"),
      "a covered login did not resolve; the badge would reach only the personal account");
    assert(publishers.get("someone") === publishers.get("someone-tech"),
      "the two keys must be one record, or a rename becomes two edits that can disagree");

    // 2. The collision check must not see one record as two publishers. Without
    //    `publisherRecords` deduplicating by identity this compares the record
    //    with itself, finds its display name equal to its display name, and
    //    reports every multi-login publisher as impersonating itself.
    assert(publisherNameCollisions(publishers).length === 0,
      "one record under two keys was reported as two publishers colliding");

    // 3. A `covers` entry must not take a login another record owns — in EITHER
    //    direction. `publishers/` is walked in sorted order and a record's file
    //    name must equal its owner, so the two orderings are two different pairs
    //    of names: "aaa.json" cover-first, "contested.json" owner-first. A check
    //    that handled only one of them would pass on half the alphabet.
    fs.rmSync(path.join(tmp, "publishers", "someone.json"));

    write("aaa.json", { owner: "aaa", covers: ["contested"], display_name: "Aaa" });
    write("contested.json", { owner: "contested", display_name: "Contested" });
    const coverFirst = load().errors;
    assert(coverFirst.some((e) => e.file === "publishers/contested.json"),
      `an owner already claimed by a cover was accepted: ${JSON.stringify(coverFirst)}`);

    fs.rmSync(path.join(tmp, "publishers", "aaa.json"));
    write("zzz.json", { owner: "zzz", covers: ["contested"], display_name: "Zzz" });
    const ownerFirst = load().errors;
    assert(ownerFirst.some((e) => e.file === "publishers/zzz.json"),
      `a cover of an already-owned login was accepted: ${JSON.stringify(ownerFirst)}`);

    fs.rmSync(tmp, { recursive: true, force: true });
  });

  // The reserved-prefix rule used to live twice — in `tools/validate.mjs` for a
  // listing already in the tree, and in `bot/lib/derive.mjs` for a submission
  // arriving at ingest. Identical behaviour, two files, and widening the
  // exception is precisely the edit that updates one of them. It is one function
  // now, and this is what says so: both allowlists, both directions, and the
  // malformed case.
  await test("a reserved prefix is refused unless the repo or its owner is first-party", () => {
    const policy = {
      reserved_prefixes: ["astra-", "official-"],
      first_party_repos: ["mihailinl/AstraPlugins"],
      first_party_owners: ["MINICE-AI"],
    };
    const hit = (id, repo) => reservedPrefixViolation(id, repo, policy);

    assert(hit("astra-chess", "somebody/astra-chess")?.prefix === "astra-",
      "an outsider took a reserved prefix");
    assert(hit("astra-chess", "MINICE-AI/astra-chess") === null,
      "a first-party OWNER was refused its own prefix");
    assert(hit("astra-chess", "minice-ai/astra-chess") === null,
      "owner matching must be case-insensitive; GitHub logins are");
    assert(hit("doom", "somebody/doom") === null,
      "an id with no reserved prefix was refused");
    assert(hit("official-thing", "mihailinl/AstraPlugins") === null,
      "a first-party REPO was refused a reserved prefix");
    assert(hit("official-thing", "mihailinl/something-else")?.prefix === "official-",
      "the repo allowlist must match the repo, not its owner — first_party_owners is the wider knob");

    // A listing with no `source.repo` must not buy itself a prefix by being
    // malformed.
    assert(hit("astra-chess", undefined)?.prefix === "astra-", "a missing repo was treated as first-party");
    assert(hit("astra-chess", "")?.prefix === "astra-", "an empty repo was treated as first-party");

    // And the same pair against a policy carrying an EMPTY allowlist entry,
    // which is what makes the two assertions above mean anything. A blank line
    // in JSON is one keystroke, and without the guard in reserved.mjs it turns
    // every malformed listing — no repo, or a repo the caller failed to read —
    // into a first-party one. Written this way because the first version of this
    // test passed with the guard REMOVED: it was asserting behaviour that held
    // for an unrelated reason, which is the same as not asserting it.
    const blank = { ...policy, first_party_repos: [""], first_party_owners: [""] };
    assert(reservedPrefixViolation("astra-chess", "", blank)?.prefix === "astra-",
      "an empty allowlist entry matched an empty repo and granted the prefix");
    assert(reservedPrefixViolation("astra-chess", undefined, blank)?.prefix === "astra-",
      "an empty allowlist entry matched a missing repo and granted the prefix");

    // And the COMMITTED policy really does admit the repository this was widened
    // for, and still refuses everybody else. Asserted against the real file
    // rather than the fixture above, because a fixture cannot notice that
    // somebody edited the policy back.
    const real = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "policy/reserved-ids.json"), "utf8"));
    assert(reservedPrefixViolation("astra-chess", "MINICE-AI/astra-chess", real) === null,
      "policy/reserved-ids.json no longer admits MINICE-AI (named KNICE-TECH until its rename); issue #33 is blocked again");
    // The organisation's OLD login is free for anybody to register once GitHub
    // has renamed it, so it must never be first-party again as an owner. Only
    // the one frozen repository pair survives, and only while every listing
    // under it stays out of the catalogue: that pair plus a listed plugin is
    // exactly the takeover the rename opened.
    assert((real.first_party_owners ?? []).every((o) => o.toLowerCase() !== "knice-tech"),
      "policy/reserved-ids.json trusts the freed login KNICE-TECH as an owner again; anybody who registers it gets every astra- id");
    assert(reservedPrefixViolation("astra-anything", "KNICE-TECH/anything", real)?.prefix === "astra-",
      "a repository under the freed login KNICE-TECH was admitted to a reserved prefix");
    const frozenPairs = (real.first_party_repos ?? []).filter((r) => r.toLowerCase().startsWith("knice-tech/"));
    const pluginsRoot = path.join(REPO_ROOT, "plugins");
    for (const dir of fs.readdirSync(pluginsRoot)) {
      const file = path.join(pluginsRoot, dir, "plugin.json");
      if (!fs.existsSync(file)) continue;
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      const repo = String(doc.source?.repo ?? "").toLowerCase();
      if (frozenPairs.some((r) => r.toLowerCase() === repo)) {
        assert(doc.unlisted === true,
          `plugins/${dir} is listed from ${doc.source.repo}, a repository under the freed login KNICE-TECH that policy/reserved-ids.json keeps only for a frozen listing`);
      }
    }
    assert(reservedPrefixViolation("astra-anything", "someone-else/x", real)?.prefix === "astra-",
      "policy/reserved-ids.json admits everybody; the prefix is no longer reserved");
  });

  // The other two files that can hand the freed login something, and until this
  // test neither was read by anything: the containment above is three guards
  // over `policy/reserved-ids.json` alone, and `policy/reserved-ids.json`'s own
  // note leans on both of these ("E_TRADEMARK refuses any astra- release from a
  // KNICE-TECH repository") without anything checking that they still say so.
  //
  //   - `bot/policy/trademarks.json`'s `allow_repo_owners` is the knob that lets
  //     a mark's real owner list under it, matched against the repository owner
  //     login. `astra` is a mark. An entry for the freed login there is not a
  //     narrow exception, it is the whole `astra-` namespace handed to whoever
  //     registers the name on GitHub — the second of the three guards above,
  //     refusing `KNICE-TECH/anything` the `astra-` prefix at validate time,
  //     would still hold and ingest would admit the release anyway, because the
  //     two rules are different files read by different halves;
  //   - a `publishers/*.json` `owner` or `covers` entry is a verified badge
  //     keyed on the owner half of `source.repo`. `KnlCE.json`'s `covers` said
  //     `KNICE-TECH` until 2026-09-12 and was moved to `MINICE-AI` by hand when
  //     the organisation was renamed, so this is not a hypothetical edit: it is
  //     the edit being undone. Moved back, every listing published from a
  //     repository under a login anybody can register wears Astra's own
  //     `astra_team` badge.
  //
  // Read off the committed files rather than off `loadPublishers`, which skips a
  // record it rejects: a publishers file that fails the owner/file-name rule
  // still ships in the tree, and the question here is what the tree says, not
  // what the index builder was willing to key on.
  await test("the freed login KNICE-TECH has no trademark allowance and no publisher record", () => {
    const FREED = "knice-tech";

    const tm = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "bot/policy/trademarks.json"), "utf8"));
    // Floors first, because every assertion below is a walk and an empty walk
    // passes. A `marks` list that stopped parsing, or an `allow_repo_owners`
    // that lost its `astra` key in a bad merge, would make this test green by
    // having nothing to look at — and the `astra` key is the one whose contents
    // this test exists to police, so its disappearance must be loud rather than
    // convenient. 55 marks and two allowed owners on 2026-09-19.
    assert(Array.isArray(tm.marks) && tm.marks.length >= 50,
      `bot/policy/trademarks.json parsed ${Array.isArray(tm.marks) ? tm.marks.length : "no"} marks and there were 55 ` +
      `on 2026-09-19; this is a broken read of the policy, not a shorter list, and the allowance walk below would pass on it`);
    const astraAllow = tm.allow_repo_owners?.astra;
    // The `astra` floor is two assertions and not one, because the single
    // `Array.isArray(x) && x.length >= 1` it replaces said the WRONG THING
    // about the one case it most has to be right about. Watched on this tree:
    // `"astra": "KNICE-TECH"` — an entry that hands the freed login the whole
    // mark — printed *"has no `astra` entry under allow_repo_owners; the mark
    // this containment is about is no longer allowed to anybody"*. Red for the
    // right reason and wrong in every word of why, which sends the reader to
    // restore a first-party allowance that was never missing and to leave the
    // takeover in the file.
    assert(astraAllow !== undefined,
      "bot/policy/trademarks.json has no `astra` entry under allow_repo_owners; the mark this containment is about " +
      "is no longer allowed to anybody, which is either a first-party release broken or the file read wrong");
    assert(Array.isArray(astraAllow) && astraAllow.length >= 1,
      `bot/policy/trademarks.json's allow_repo_owners.astra is ${JSON.stringify(astraAllow)} and not a non-empty ` +
      `list of logins; read the value, because the walk below is what decides who holds the mark`);

    for (const [mark, owners] of Object.entries(tm.allow_repo_owners ?? {})) {
      // `$comment` is how this file documents itself — `allow_ids` carries one
      // — so a key that is one is not a mark, and an honest note added here
      // must not be a red build.
      if (mark.startsWith("$")) continue;
      // The shape, before the walk over it. `for (const o of "KNICE-TECH")`
      // yields eleven characters and not one of them is the login, so a mark
      // whose value is a bare string is a walk this test passes by not being
      // able to read it. Measured rather than reasoned: `"spotify":
      // "KNICE-TECH"` added to allow_repo_owners left the suite at
      // `PASS  168 passed, 0 failed`, this test green over a file handing the
      // freed login a mark, while its own message below claims to speak for
      // every mark in the object. Nothing else notices either — there is no
      // `schema/trademarks-v1.json`, this file is validated by nothing, and
      // `bot/lib/names.mjs:169` calls `.some()` on the value, so at ingest the
      // same edit is a TypeError rather than a refusal.
      assert(Array.isArray(owners),
        `bot/policy/trademarks.json's allow_repo_owners.${mark} is ${JSON.stringify(owners)} and not a list of ` +
        `logins; the freed-login walk below cannot read it, and bot/lib/names.mjs calls .some() on it at ingest`);
      for (const owner of owners) {
        assert(String(owner).toLowerCase() !== FREED,
          `bot/policy/trademarks.json lets the freed login KNICE-TECH publish under the mark "${mark}"; the ` +
          `organisation renamed to MINICE-AI and GitHub frees a renamed login, so whoever registers it gets ` +
          `E_TRADEMARK's blessing for every "${mark}" name at ingest`);
      }
    }

    const pubDir = path.join(REPO_ROOT, "publishers");
    const pubFiles = fs.readdirSync(pubDir).filter((n) => n.endsWith(".json"));
    assert(pubFiles.length >= 1,
      "publishers/ holds no .json record at all; the covers walk below would pass by having nothing to read");
    for (const name of pubFiles) {
      const doc = JSON.parse(fs.readFileSync(path.join(pubDir, name), "utf8"));
      const claims = [doc.owner, ...(Array.isArray(doc.covers) ? doc.covers : [])];
      for (const claim of claims) {
        assert(String(claim).toLowerCase() !== FREED,
          `publishers/${name} claims the freed login KNICE-TECH as an owner or in covers; that paints its ` +
          `${doc.tier ?? "publisher"} badge on every listing whose source.repo sits under a login anybody can register`);
      }
    }
  });

  // A `verified` badge rests on a document that keeps saying the same thing. The
  // whole-line test is the part that matters: a page MENTIONING a login — a blog
  // post, a directory, somebody else's README — is not that person asserting it,
  // and `includes` would take any of them for proof.
  await test("proof must name the owner on a line of its own", () => {
    assert(proofNamesOwner("knlce\n", "KnlCE"), "an exact line, case-insensitively, is proof");
    assert(proofNamesOwner("# owner\nKnlCE\n", "KnlCE"), "a line among lines is still proof");
    assert(!proofNamesOwner("plugins by KnlCE are great", "KnlCE"), "a mention in prose is not an assertion");
    assert(!proofNamesOwner("KnlCE-fan", "KnlCE"), "a longer word that contains it is not it");
    assert(!proofNamesOwner("", "KnlCE"), "an empty document proves nothing");
  });

  // Four outcomes, each on a tree of its own, because the interesting ones are
  // the three where NOTHING should move. A re-check that quietly renewed a badge
  // whose evidence had gone would be the failure this whole mechanism exists to
  // prevent.
  await test("a re-check renews on proof, and moves nothing without it", async () => {
    const mk = (over = {}) => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), "astra-recheck-"));
      fs.mkdirSync(path.join(root, "publishers"));
      fs.writeFileSync(path.join(root, "publishers", "someone.json"), JSON.stringify({
        schema: "astra.registry.publisher/1", owner: "someone", display_name: "Someone",
        tier: "verified", verified_at: "2026-01-01", expires_at: "2099-01-01",
        evidence: { kind: "domain", domain: "example.com", proof: "https://example.com/p" },
        ...over,
      }, null, 2) + "\n");
      return root;
    };
    const read = (root) => JSON.parse(fs.readFileSync(path.join(root, "publishers", "someone.json"), "utf8"));
    const today = new Date().toISOString().slice(0, 10);

    let root = mk();
    let r = await recheck({ root, write: true, fetcher: async () => ({ ok: true, body: "someone\n" }) });
    assert(r.results[0].state === "confirmed", JSON.stringify(r.results));
    assert(read(root).last_confirmed_at === today, "a confirmed proof records the day it held");
    assert(read(root).expires_at > today, "the window moves forward from today");
    fs.rmSync(root, { recursive: true, force: true });

    root = mk();
    r = await recheck({ root, write: true, fetcher: async () => ({ ok: false, why: "HTTP 503" }) });
    assert(r.results[0].state === "unreachable", JSON.stringify(r.results));
    assert(!read(root).last_confirmed_at, "an unreachable document must renew nothing");
    assert(read(root).expires_at === "2099-01-01", "and must not move the window");
    fs.rmSync(root, { recursive: true, force: true });

    root = mk();
    r = await recheck({ root, write: true, fetcher: async () => ({ ok: true, body: "somebody-else\n" }) });
    assert(r.results[0].state === "mismatched", JSON.stringify(r.results));
    assert(!read(root).last_confirmed_at, "a document naming somebody else must renew nothing");
    fs.rmSync(root, { recursive: true, force: true });

    root = mk({ expires_at: "2020-01-01" });
    r = await recheck({ root, write: true, fetcher: async () => ({ ok: false, why: "HTTP 404" }) });
    assert(r.expired.length === 1, "an expired record is withdrawn");
    assert(!fs.existsSync(path.join(root, "publishers", "someone.json")), "the record is gone, so the badge is");
    fs.rmSync(root, { recursive: true, force: true });
  });

  // The job that takes a badge off, on the record shape that broke it. The
  // map `loadPublishers` returns is keyed by LOGIN, so a record with `covers`
  // is in it once per login; `bot/recheck-publishers.mjs` walked its values,
  // fetched the proof once per login, deleted the file on the first pass and
  // threw ENOENT on the second — so the workflow step failed, the commit never
  // ran, and the badge stayed on for as long as the record did. Measured on
  // this fixture before the repair: 2 fetches, then the throw. The committed
  // tree has no `verified` record, so nothing else here ever held this case.
  await test("an expired record covering two logins is fetched once, withdrawn once, and the write finishes", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "astra-recheck-covers-"));
    try {
      fs.mkdirSync(path.join(root, "publishers"));
      const file = path.join(root, "publishers", "someone.json");
      fs.writeFileSync(file, JSON.stringify({
        schema: "astra.registry.publisher/1", owner: "someone", covers: ["SOMEONE-TECH"], display_name: "Someone",
        tier: "verified", verified_at: "2019-01-01", expires_at: "2020-01-01",
        evidence: { kind: "domain", domain: "example.com", proof: "https://example.com/p" },
      }, null, 2) + "\n");
      const { publishers } = loadPublishers(root);
      assert(publishers.size === 2 && publisherRecords(publishers).length === 1,
        `the fixture must be ONE record under TWO keys or it proves nothing about covers; it loaded ${publishers.size} key(s)`);

      let fetches = 0;
      const fetcher = async () => { fetches += 1; return { ok: false, why: "HTTP 404" }; };
      let r;
      try {
        r = await recheck({ root, write: true, fetcher });
      } catch (e) {
        assert(false, `recheck --write threw on an expired record with covers (${e.code ?? e.message}); the workflow step fails, ` +
          "the commit that withdraws the badge never runs, and it stays on");
      }
      assert(fetches === 1, `one record's proof was fetched ${fetches} times; the job is walking logins, not records`);
      assert(r.errors.length === 0, `the run reported load errors, and the CLI exits 1 on any: ${JSON.stringify(r.errors)}`);
      assert(r.expired.length === 1, `one expired record was reported ${r.expired.length} times`);
      assert(!fs.existsSync(file), "the expired record is still on disk, so the badge is still on");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  // One rule, asked two ways. The first half is agreement over a fixture set
  // that has every shape the rule distinguishes — past, today, future, no
  // date, one login, three logins, both tiers — so an agreement cannot be the
  // agreement of two empty lists. The second half is what agreement cannot
  // show: a COPY of the library agrees with it perfectly until the day one of
  // them is edited. So the library is changed under the job, in a copy of both
  // files outside this tree, and the job has to change with it.
  await test("the daily job's expiry is the library's rule, and follows the library when it changes", async () => {
    const now = new Date("2026-06-15T12:00:00Z");
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "astra-recheck-agree-"));
    const shadow = fs.mkdtempSync(path.join(os.tmpdir(), "astra-recheck-lib-"));
    try {
      fs.mkdirSync(path.join(root, "publishers"));
      const rec = (owner, over) => fs.writeFileSync(path.join(root, "publishers", `${owner}.json`), JSON.stringify({
        schema: "astra.registry.publisher/1", owner, display_name: `Publisher ${owner}`,
        tier: "verified", verified_at: "2019-01-01",
        evidence: { kind: "domain", domain: "example.com", proof: `https://example.com/${owner}` },
        ...over,
      }, null, 2) + "\n");
      rec("past", { expires_at: "2020-01-01" });
      rec("pastmany", { expires_at: "2026-06-14", covers: ["PASTMANY-ORG", "PASTMANY-TWO"] });
      rec("today", { expires_at: "2026-06-15" });
      rec("future", { expires_at: "2999-01-01", covers: ["FUTURE-ORG"] });
      // An `astra_team` record is held to an `expires_at` if it carries one:
      // the library does not ask the tier, and neither does the build's check
      // of the committed tree above. Neither committed record carries one.
      rec("teamdated", { tier: "astra_team", expires_at: "2020-01-01", evidence: { kind: "first-party", note: "fixture" } });
      rec("team", { tier: "astra_team", evidence: { kind: "first-party", note: "fixture" } });

      const { errors, publishers } = loadPublishers(root);
      assert(errors.length === 0, `the fixture set did not load cleanly: ${JSON.stringify(errors)}`);
      const library = expiredPublishers(publishers, now);
      const files = library.map((e) => e.file);
      assert(new Set(files).size === files.length, `the library reported a record twice: ${files.join(", ")}`);
      assert(library.length >= 2 && library.length < publisherRecords(publishers).length,
        `the library called ${library.length} of ${publisherRecords(publishers).length} records expired; an agreement ` +
        "over all or none of them would prove nothing");
      assert(files.includes("publishers/pastmany.json"), "the multi-login record is not in the library's answer, so the covers case is unasked");

      const fetcher = async () => ({ ok: false, why: "HTTP 404" });
      const job = await recheck({ root, write: false, fetcher, now });
      assert(JSON.stringify(job.expired) === JSON.stringify(library),
        `the job and the library disagree on which records are expired:\n  job     ${JSON.stringify(job.expired)}\n  library ${JSON.stringify(library)}`);

      // Change the library, not the job. The job's own import is redirected to
      // a patched copy of `tools/lib/sources.mjs`; every other relative import
      // in both copies is pointed back at the real file, so nothing but that
      // one function differs. Each anchor must match exactly once.
      const here = path.dirname(fileURLToPath(import.meta.url));
      const realLib = path.join(here, "..", "lib", "sources.mjs");
      const realJob = path.join(here, "..", "..", "bot", "recheck-publishers.mjs");
      const absolutise = (src, from) => src.replace(/(\bfrom\s+|\bimport\s*\(\s*)(["'])(\.{1,2}\/[^"']+)\2/g,
        (_m, lead, q, spec) => `${lead}${q}${new URL(spec, pathToFileURL(from)).href}${q}`);
      const once = (src, re, what) => {
        const hits = src.match(new RegExp(re.source, "g")) ?? [];
        if (hits.length !== 1) throw new Error(`${what} matched ${hits.length} times, not once; this test's anchor needs rewriting`);
        return re;
      };
      let lib = fs.readFileSync(realLib, "utf8");
      const decl = once(lib, /export function expiredPublishers\([^{]*\)\s*\{/, "expiredPublishers' declaration in tools/lib/sources.mjs");
      lib = lib.replace(decl, (m) => `${m}\n  return publisherRecords(publishers).filter(({ doc }) => doc.owner === "future")` +
        `.map(({ file, doc }) => ({ file, owner: doc.owner, expires_at: "changed-library" }));\n`);
      fs.writeFileSync(path.join(shadow, "sources.mjs"), absolutise(lib, realLib));

      let jobSrc = fs.readFileSync(realJob, "utf8");
      const imp = /(["'])\.\.\/tools\/lib\/sources\.mjs\1/;
      const hits = jobSrc.match(new RegExp(imp.source, "g")) ?? [];
      assert(hits.length === 1,
        `bot/recheck-publishers.mjs imports tools/lib/sources.mjs ${hits.length} times, not once; a job that no longer ` +
        "imports the library cannot be running its rule");
      jobSrc = jobSrc.replace(imp, JSON.stringify(pathToFileURL(path.join(shadow, "sources.mjs")).href));
      fs.writeFileSync(path.join(shadow, "recheck-publishers.mjs"), absolutise(jobSrc, realJob));

      const patched = await import(pathToFileURL(path.join(shadow, "recheck-publishers.mjs")).href);
      const moved = await patched.recheck({ root, write: false, fetcher, now });
      const want = [{ file: "publishers/future.json", owner: "future", expires_at: "changed-library" }];
      assert(JSON.stringify(moved.expired) === JSON.stringify(want),
        "the library's rule was changed and the job's answer did not follow it, so the job is running its own copy:\n" +
        `  job   ${JSON.stringify(moved.expired)}\n  want  ${JSON.stringify(want)}`);

      // And what the job removes is exactly what it selected: under --write,
      // the real library's expired set is gone and nothing else is.
      const removed = await recheck({ root, write: true, fetcher, now });
      assert(JSON.stringify(removed.expired) === JSON.stringify(library), "the write run selected differently from the report run");
      const left = fs.readdirSync(path.join(root, "publishers")).sort();
      const wantLeft = ["future.json", "team.json", "today.json"];
      assert(JSON.stringify(left) === JSON.stringify(wantLeft),
        `after --write the tree holds ${left.join(", ")}; it should hold ${wantLeft.join(", ")} — the library's selection removed, and nothing else`);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(shadow, { recursive: true, force: true });
    }
  });
  // Gap 6's open half, run rather than composed. The daily re-check deletes an
  // expired record and runs no suite before it pushes; the suite refuses a
  // declaration naming no record. So a withdrawn DECLARED record used to turn
  // `main` red — the publish path's fifth gate with it — for a withdrawal
  // nobody did wrong. Impossible on today's tree (the one declared record
  // cannot expire), so the case is built: the committed publishers and
  // declarations, plus a declared `verified` record that has expired and a
  // declared one that has not. Four clauses:
  //
  //   (a) the committed declarations file round-trips through the job's
  //       rewrite byte for byte, so a withdrawal changes the entry it drops
  //       and nothing else in the file;
  //   (b) the withdrawal takes its declaration and only its declaration, and
  //       this module's own reach check is green over what the job wrote —
  //       while the SAME check over the declarations as they were is red,
  //       naming the record, which is the failure this closes, watched;
  //   (c) withdrawing an undeclared record leaves the file's bytes alone, and
  //       an unreadable file is reported without holding the withdrawal;
  //   (d) the workflow's commit step stages the file, or (b) writes a change
  //       nothing commits and `main` goes red exactly as before.
  await test("a withdrawn record that was declared takes its declaration with it, and the suite stays green", async () => {
    const committedText = fs.readFileSync(path.join(REPO_ROOT, NO_LISTING_FILE), "utf8");
    const committed = JSON.parse(committedText);

    // (a)
    assert(`${JSON.stringify(committed, null, 2)}\n` === committedText,
      `${NO_LISTING_FILE} is not in the two-space, one-newline JSON bot/recheck-publishers.mjs writes back, so the ` +
      "first withdrawal of a declared record would reformat the whole file inside a badge-withdrawal commit");

    const now = new Date("2026-06-15T12:00:00Z");
    const fetcher = async () => ({ ok: false, why: "HTTP 404" });
    const build = (declarations) => {
      const tree = fs.mkdtempSync(path.join(os.tmpdir(), "astra-recheck-declared-"));
      for (const dir of ["plugins", "registry", "policy", "schema", "publishers"]) {
        fs.cpSync(path.join(REPO_ROOT, dir), path.join(tree, dir), { recursive: true });
      }
      const rec = (owner, expires_at) => fs.writeFileSync(path.join(tree, "publishers", `${owner}.json`), JSON.stringify({
        schema: "astra.registry.publisher/1", owner, display_name: `Fixture ${owner}`, tier: "verified",
        verified_at: "2019-01-01", expires_at,
        evidence: { kind: "domain", domain: "example.com", proof: `https://example.com/${owner}` },
      }, null, 2) + "\n");
      rec("lapsed-unpublished", "2020-01-01");
      rec("waiting-unpublished", "2999-01-01");
      const text = `${JSON.stringify({ ...committed, declarations: [...committed.declarations, ...declarations] }, null, 2)}\n`;
      fs.mkdirSync(path.dirname(path.join(tree, NO_LISTING_FILE)), { recursive: true });
      fs.writeFileSync(path.join(tree, NO_LISTING_FILE), text);
      return { tree, text };
    };
    const lapsed = { record: "publishers/lapsed-unpublished.json", reason: "fixture: verified, not published yet" };
    const waiting = { record: "publishers/waiting-unpublished.json", reason: "fixture: verified, not published yet" };

    // (b)
    const { tree, text: before } = build([lapsed, waiting]);
    try {
      const pre = publisherReach(tree, before);
      assert(pre.fail.length === 0, `the built tree is red before the job runs, so it proves nothing:\n${pre.fail.join("\n")}`);
      const r = await recheck({ root: tree, write: true, fetcher, now });
      assert(JSON.stringify(r.expired.map((e) => e.file)) === JSON.stringify([lapsed.record]),
        `the job withdrew ${JSON.stringify(r.expired.map((e) => e.file))}; the case needs exactly ${lapsed.record}`);
      assert(!fs.existsSync(path.join(tree, lapsed.record)), "the expired record is still on disk");
      assert(JSON.stringify(r.undeclared) === JSON.stringify([lapsed.record]) && r.declarationProblem === null,
        `the job reports dropping ${JSON.stringify(r.undeclared)} (problem: ${r.declarationProblem}); it should report ${lapsed.record}`);
      const after = fs.readFileSync(path.join(tree, NO_LISTING_FILE), "utf8");
      const want = `${JSON.stringify({ ...committed, declarations: [...committed.declarations, waiting] }, null, 2)}\n`;
      assert(after === want,
        `after the withdrawal ${NO_LISTING_FILE} is not the file it was minus ${lapsed.record}'s entry:\n${after}`);
      const post = publisherReach(tree, after);
      assert(post.fail.length === 0,
        `the suite is red over the tree the job left, so this withdrawal would turn main red:\n${post.fail.join("\n")}`);
      const stale = publisherReach(tree, before);
      assert(stale.fail.some((m) => m.includes(`declares ${lapsed.record}, which is not a publisher record here`)),
        "over the declarations as they were before the job, the reach check should refuse the withdrawn record's " +
        `declaration — that is the red this closes, and without it this test is not about it:\n${stale.fail.join("\n")}`);
    } finally {
      fs.rmSync(tree, { recursive: true, force: true });
    }

    // (c)
    const quiet = build([waiting]);
    try {
      const r = await recheck({ root: quiet.tree, write: true, fetcher, now });
      assert(r.expired.length === 1 && r.undeclared.length === 0, `an undeclared withdrawal reported ${JSON.stringify(r)}`);
      assert(fs.readFileSync(path.join(quiet.tree, NO_LISTING_FILE), "utf8") === quiet.text,
        `withdrawing an undeclared record rewrote ${NO_LISTING_FILE}`);
    } finally {
      fs.rmSync(quiet.tree, { recursive: true, force: true });
    }
    const broken = build([lapsed]);
    try {
      fs.writeFileSync(path.join(broken.tree, NO_LISTING_FILE), "{ not json");
      const r = await recheck({ root: broken.tree, write: true, fetcher, now });
      assert(!fs.existsSync(path.join(broken.tree, lapsed.record)),
        "an unreadable declarations file held the withdrawal; a badge must not outlive its evidence because of a neighbouring file");
      assert(typeof r.declarationProblem === "string" && r.declarationProblem.includes(NO_LISTING_FILE),
        `an unreadable declarations file was not reported: ${JSON.stringify(r.declarationProblem)}`);
      assert(fs.readFileSync(path.join(broken.tree, NO_LISTING_FILE), "utf8") === "{ not json",
        "the job wrote over a declarations file it could not read");
    } finally {
      fs.rmSync(broken.tree, { recursive: true, force: true });
    }

    // (d)
    const wf = fs.readFileSync(path.join(REPO_ROOT, ".github", "workflows", "publisher-recheck.yml"), "utf8");
    const lines = wf.split("\n").filter((l) => !/^\s*#/.test(l));
    const diffs = lines.filter((l) => /\bgit diff --quiet\b/.test(l));
    const adds = lines.filter((l) => /\bgit add\b/.test(l));
    assert(diffs.length === 1 && adds.length === 1,
      `publisher-recheck.yml has ${diffs.length} \`git diff --quiet\` and ${adds.length} \`git add\` line(s); this check reads exactly one of each`);
    for (const [what, line] of [["decides whether anything moved", diffs[0]], ["stages the commit", adds[0]]]) {
      assert(line.split(/[\s;]+/).includes(NO_LISTING_FILE),
        `publisher-recheck.yml's line that ${what} does not name ${NO_LISTING_FILE}, so a dropped declaration is ` +
        `written and never committed, and main goes red on the withdrawal:\n  ${line.trim()}`);
    }
  });
}
