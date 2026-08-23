#!/usr/bin/env node
// The registry's own test suite. `node tools/selftest.mjs`, no arguments, no
// network, no dependencies.
//
// Half of these tests assert that something is ACCEPTED. The other half assert
// that something is REJECTED, and those are the ones that matter: a validator
// nobody has watched say no is a validator nobody knows works. Each negative
// case is a file a reviewer can open — tests/fixtures/ — or two bytes away from
// one, and each names the real defect it stands for.

import fs from "node:fs";
import os from "node:os";
import crypto from "node:crypto";
import path from "node:path";
import { execFileSync } from "node:child_process";

import {
  checkEveryCapDeclaresItsAuthorSide,
  checkListingLanguage,
  checkLocaleCorpus,
  checkLocaleCorpusCoverage,
  checkLocaleVocabulary,
  checkMirroredListingLimits,
  runValidation,
} from "./validate.mjs";
import { CORPUS_NO_RULE_ID, deriveLocaleText, localeEnumProblems } from "../bot/lib/locales.mjs";
import { summarise } from "../bot/lib/derive.mjs";
import { buildIndex } from "./build-index.mjs";
import {
  CATALOG_TTL_DAYS, INDEX_SCHEMA, REVOCATIONS_SCHEMA, REVOCATION_TTL_DAYS, TRUST_SCHEMA,
  signEnvelope, verifyEnvelope, privateKeyFromSeed, publicKeyBase64,
} from "../bot/lib/sign.mjs";
import { signIndex, indexKeysFromTrust } from "../bot/sign-index.mjs";
import { signRevocations } from "./sign-revocations.mjs";
import { buildRevocations, checkAdvisory } from "./lib/revocations.mjs";
import { fixtureCatalogue, FIXTURE_ISSUED_AT } from "../bot/fixtures/index/regenerate.mjs";
import { loadTestRoot } from "./testkeys/regenerate.mjs";
import { stableStringify, jcs } from "./lib/canonical.mjs";
import { validate as validateSchema } from "./lib/jsonschema.mjs";
import { makeFixtures } from "./make-fixtures.mjs";
import { REPO_ROOT, expiredPublishers, loadPolicy, loadPublishers, loadSchemas, loadSources, publisherNameCollisions } from "./lib/sources.mjs";
import { reservedPrefixViolation } from "./lib/reserved.mjs";
import { proofNamesOwner, recheck } from "../bot/recheck-publishers.mjs";
import { readZip, readEntry, writeZip } from "./lib/zip.mjs";
import { compareSemver } from "./lib/semver.mjs";
import { invalidId, unsafePathComponent, foldId, unsafeDisplayText } from "./lib/ids.mjs";
import {
  checkBundle, manifestDigest, artifactDigest,
  manifestBytesFromLocalHeader, MANIFEST_DIGEST_DOMAIN,
} from "../bot/lib/bundle.mjs";
import { registerSharedVectorTests } from "../tests/shared-vectors.mjs";

const LIMITS = JSON.parse(fs.readFileSync(new URL("../policy/limits.json", import.meta.url), "utf8"));

let passed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok    ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL  ${name}`);
    console.log(`        ${e.message.split("\n").join("\n        ")}`);
    failures.push(name);
  }
}

/**
 * Two values, and the difference printed when they are not one value. `assert`
 * alone reports "expected true" for a mismatch nobody can then see.
 */
function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}\n  expected: ${JSON.stringify(expected)}\n  actual:   ${JSON.stringify(actual)}`);
  }
}

function assert(cond, message) {
  if (!cond) throw new Error(message);
}

/** Run the validator in-process against a tree and return its report. */
function validateTree(dir, opts = {}) {
  return runValidation({
    root: dir, allowStaging: false, allowDirect: false, online: false, artifactsDir: null, index: false, ...opts,
  });
}

function errorsMatching(report, needle) {
  return report.errors.filter((e) => `${e.where} ${e.message}`.includes(needle));
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-registry-selftest-"));

console.log("\ncanonical json");
await test("keys are sorted by code unit, output ends in a newline", () => {
  const s = stableStringify({ b: 1, a: { d: 2, c: 3 }, $z: 4 });
  assert(s === '{\n  "$z": 4,\n  "a": {\n    "c": 3,\n    "d": 2\n  },\n  "b": 1\n}\n', `got ${JSON.stringify(s)}`);
});
await test("jcs is the same document with the whitespace removed", () => {
  const doc = { b: [1, 2], a: "x" };
  assert(jcs(doc) === '{"a":"x","b":[1,2]}', jcs(doc));
  assert(JSON.stringify(JSON.parse(jcs(doc))) === JSON.stringify(JSON.parse(stableStringify(doc))));
});
await test("a non-integer number is refused rather than silently canonicalised", () => {
  let threw = false;
  try { stableStringify({ x: 1.5 }); } catch { threw = true; }
  assert(threw, "1.5 was accepted; RFC 8785 number canonicalisation is not implemented");
});

// ── RFC 8785's own vectors ──────────────────────────────────────────────────
//
// Every assertion below is mirrored in astra-daemon's `plugins::trust` tests,
// including the SHA-256 of the canonical output. That digest is the drift
// detector: signer and verifier canonicalising differently is the classic way a
// signature scheme silently accepts nothing or everything, and neither side's
// own suite can see it.
await test("RFC 8785 §3.2.3: keys sort by UTF-16 code unit, not by code point", () => {
  // The RFC's example document, verbatim, escapes and all.
  const doc = JSON.parse(`{
    "\\u20ac": "Euro Sign",
    "\\r": "Carriage Return",
    "\\u000a": "Newline",
    "1": "One",
    "\\u0080": "Control\\u007f?",
    "\\ud83d\\ude02": "Smiley",
    "\\u00f6": "Latin Small Letter O With Diaeresis",
    "\\ufb33": "Hebrew Letter Dalet With Dagesh",
    "</script>": "Browser Challenge"
  }`);

  // Written out rather than pasted, because the interesting part is a place
  // where the obvious answer is wrong: U+1F602 😂 is the surrogate pair
  // D83D DE02, so as a UTF-16 code-unit sequence it starts at 0xD83D and sorts
  // BEFORE U+FB33 דּ — the opposite of code-point order. §3.2.3 specifies code
  // units, which is also what JavaScript's default sort does and what the Rust
  // side spells out with `encode_utf16`.
  //
  // U+0080 and U+007F stay LITERAL in the output: §3.2.2.2 escapes only `"`, `\`
  // and U+0000–U+001F. A canonicaliser that helpfully escapes more produces
  // bytes the other implementation will not reproduce. They are written here as
  // JavaScript escapes so that this source file survives an editor.
  const expected =
    '{"\\n":"Newline","\\r":"Carriage Return","1":"One","</script>":"Browser Challenge",' +
    '"\u0080":"Control\u007f?","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign",' +
    '"\ud83d\ude02":"Smiley","\ufb33":"Hebrew Letter Dalet With Dagesh"}';
  assert(jcs(doc) === expected, `\n  got      ${JSON.stringify(jcs(doc))}\n  expected ${JSON.stringify(expected)}`);
  assert(jcs(doc).includes("\u0080"), "U+0080 must survive as a literal character, not an escape");

  const digest = crypto.createHash("sha256").update(jcs(doc), "utf8").digest("hex");
  assert(digest === "922a8d820097f8b586beb7fe249dfe2ba26fe491b9780b0ba2e613f54bfcb5d7",
    `canonical form digest is ${digest} — the Rust verifier asserts the same constant`);
});
await test("RFC 8785 §3.2.2.2: the escape set is exactly JSON's, no wider", () => {
  // Every character that must be escaped, one that must not (`/`, which many
  // JSON writers escape as `\\/`), and three that stay literal.
  const doc = { s: 'q"\\\b\t\n\f\r\u001f\u007f\u0080/\u20ac' };
  const expected = '{"s":"q\\"\\\\\\b\\t\\n\\f\\r\\u001f\u007f\u0080/\u20ac"}';
  assert(jcs(doc) === expected, `\n  got      ${JSON.stringify(jcs(doc))}\n  expected ${JSON.stringify(expected)}`);
});
await test("integers canonicalise as JavaScript prints them, and nothing else is allowed in", () => {
  assert(jcs({ n: 0 }) === '{"n":0}');
  assert(jcs({ n: -0 }) === '{"n":0}', "negative zero is zero; two spellings would be two signatures");
  assert(jcs({ n: 9007199254740991 }) === '{"n":9007199254740991}');
  for (const bad of [1e30, 0.1, 1.5, -1e-6, Number.MAX_SAFE_INTEGER + 1]) {
    let threw = false;
    try { jcs({ n: bad }); } catch { threw = true; }
    assert(threw, `${bad} was canonicalised; §3.2.2.3 float formatting is deliberately NOT implemented here`);
  }
});

console.log("\njson schema subset");
await test("an unknown keyword is a hard error, not a silent pass", () => {
  let threw = false;
  try { validateSchema({ type: "string", contentEncoding: "base64" }, "x"); } catch { threw = true; }
  assert(threw, "an unimplemented keyword validated successfully, which is worse than no validator");
});
await test("the three schemas load and accept their own examples", () => {
  const schemas = ["index-v1", "plugin-v1", "version-v1"];
  for (const s of schemas) {
    JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema", `${s}.json`), "utf8"));
  }
  assert(true);
});

console.log("\nids");
await test("safe path components", () => {
  assert(unsafePathComponent("dice-roller") === null);
  assert(unsafePathComponent("..") !== null);
  assert(unsafePathComponent("a/b") !== null);
  assert(unsafePathComponent("con") !== null, "CON is a Windows device name");
  assert(unsafePathComponent("x​") !== null, "a zero-width space passed");
  assert(invalidId("Dice-Roller") !== null, "uppercase passed");
  assert(invalidId("-lead") !== null);
  assert(invalidId("a") !== null, "one character passed");
});
await test("confusable folding collapses 0/o and hyphens", () => {
  assert(foldId("dice-roller") === foldId("dicer0ller"), `${foldId("dice-roller")} vs ${foldId("dicer0ller")}`);
});
// Half a character is not a display trick like the other two — it is a
// serialisation bomb. `tools/lib/canonical.mjs` writes strings with plain
// `JSON.stringify`, which turns an unpaired surrogate into a `\udXXX` escape
// instead of refusing it, and `serde_json` rejects that escape: one listing
// with one bad character makes the ENTIRE signed catalogue unparseable in every
// daemon that fetches it. It belongs here because here is where every string
// that reaches a user's screen is already checked.
await test("display text refuses an unpaired surrogate and keeps a whole one", () => {
  assert(unsafeDisplayText("Dice \ud83c") !== null, "a high surrogate with nothing after it passed");
  assert(unsafeDisplayText("\ude00 Dice") !== null, "a low surrogate with nothing before it passed");
  assert(unsafeDisplayText("Dice 🎲 Roller") === null, "a whole emoji was refused; astral characters are legitimate");
  assert(unsafeDisplayText("Шахматы против бота") === null, "a Russian summary was refused");
  assert(unsafeDisplayText("x\u200b") !== null, "the zero-width check regressed");
});
await test("semver precedence, prerelease included", () => {
  assert(compareSemver("0.10.0", "0.9.0") === 1, "0.10.0 must be newer than 0.9.0");
  assert(compareSemver("1.0.0-alpha", "1.0.0") === -1);
  assert(compareSemver("1.0.0+a", "1.0.0+b") === 0, "build metadata must be ignored");
});

console.log("\nzip reader/writer");
await test("a written archive reads back, entry for entry", () => {
  const { bundle } = makeFixtures(path.join(tmp, "zip"));
  const { entries } = readZip(bundle);
  assert(entries.length === 3, `${entries.length} entries`);
  assert(entries[0].name === "MANIFEST.json", `first entry is ${entries[0].name}, must be MANIFEST.json (§5.2)`);
  assert(entries[0].method === 0, "MANIFEST.json must be stored, not deflated");
  const manifest = JSON.parse(readEntry(bundle, entries[0]).toString("utf8"));
  assert(manifest.schema === "astra.bundle/2", manifest.schema);
  assert((entries[1].unixMode & 0o777) === 0o755, "bin/fixture lost its executable bit");
});
await test("the fixture bundle is byte-identical on a second build", () => {
  const a = makeFixtures(path.join(tmp, "det-a")).bundle;
  const b = makeFixtures(path.join(tmp, "det-b")).bundle;
  assert(a.equals(b), "the deterministic writer is not deterministic");
});

console.log("\nthe real registry");
await test("index.json is byte-identical to a fresh generation", () => {
  const committed = fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8");
  const regenerated = stableStringify(buildIndex({ serial: JSON.parse(committed).signed.serial }));
  assert(committed === regenerated, "registry/v1/index.json is not what tools/build-index.mjs produces");
});
// A catalogue-wide canary for the bug above, on the real document rather than a
// fixture. The predicate is proved able to fail on the very next line, because
// today's catalogue is all ASCII and an assertion that cannot fail is not one.
await test("no string in the catalogue is half a character, and the check can see one", () => {
  const committed = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
  const doc = buildIndex({ serial: committed.signed.serial });
  assert(doc.signed.plugins.length > 0, "an empty catalogue would pass this by having nothing in it");
  const lone = /\\u[dD][89abAB]/;
  assert(!lone.test(stableStringify(doc)),
    "a lone surrogate escape is in the catalogue; serde_json refuses the whole document, not the listing");
  const corrupted = JSON.parse(JSON.stringify(doc));
  corrupted.signed.plugins[0].name += "\ud83c";
  assert(lone.test(stableStringify(corrupted)),
    "the predicate cannot see a lone surrogate at all, so the assertion above was decoration");
});
await test("index.json validates against schema/index-v1.json", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
  const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
  const errs = validateSchema(schema, doc);
  assert(errs.length === 0, errs.map((e) => `${e.path} ${e.message}`).join("\n"));
});
await test("every publishers/ record validates against schema/publisher-v1.json", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/publisher-v1.json"), "utf8"));
  const { errors, publishers } = loadPublishers(REPO_ROOT);
  assert(errors.length === 0, errors.map((e) => `${e.file}: ${e.message}`).join("\n"));
  assert(publishers.size >= 1, "no publisher records, so this test proves nothing");
  for (const { file, doc } of publishers.values()) {
    const errs = validateSchema(schema, doc);
    assert(errs.length === 0, `${file}: ` + errs.map((e) => `${e.path} ${e.message}`).join("\n"));
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
    first_party_owners: ["KNICE-TECH"],
  };
  const hit = (id, repo) => reservedPrefixViolation(id, repo, policy);

  assert(hit("astra-chess", "somebody/astra-chess")?.prefix === "astra-",
    "an outsider took a reserved prefix");
  assert(hit("astra-chess", "KNICE-TECH/astra-chess") === null,
    "a first-party OWNER was refused its own prefix");
  assert(hit("astra-chess", "knice-tech/astra-chess") === null,
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
  assert(reservedPrefixViolation("astra-chess", "KNICE-TECH/astra-chess", real) === null,
    "policy/reserved-ids.json no longer admits KNICE-TECH; issue #33 is blocked again");
  assert(reservedPrefixViolation("astra-anything", "someone-else/x", real)?.prefix === "astra-",
    "policy/reserved-ids.json admits everybody; the prefix is no longer reserved");
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

await test("every staging listing is REJECTED without --allow-staging", async () => {
  // The count is read off the tree, never hardcoded. An earlier version of this
  // test asserted `=== 1`, which was true only while the registry held a single
  // bootstrap listing and went red the day a second one landed — a self-test
  // that breaks on every legitimate addition is a self-test people learn to
  // ignore. What actually matters is the implication, in both directions: every
  // digest-less listing is named, and nothing else is.
  const staging = [];
  for (const p of loadSources(REPO_ROOT).plugins) {
    for (const v of p.versions) if (v.doc?.staging === true) staging.push(v.file);
  }
  assert(staging.length >= 1, "no staging listing exists, so this test proves nothing — delete it");

  const { report } = await runValidation({ root: REPO_ROOT, allowStaging: false, online: false, artifactsDir: null, index: true });
  const hits = errorsMatching(report, "STAGING entry");
  const named = new Set(hits.map((e) => e.where));
  const missed = staging.filter((f) => !named.has(f));
  assert(missed.length === 0,
    `a listing whose artifact does not exist was accepted by default: ${missed.join(", ")}`);
  assert(hits.length === staging.length,
    `${hits.length} staging rejection(s) for ${staging.length} staging listing(s) — a non-staging listing was refused as one`);
});
await test("the bootstrap listing is accepted, loudly, WITH --allow-staging", async () => {
  const { report } = await runValidation({ root: REPO_ROOT, allowStaging: true, online: false, artifactsDir: null, index: true });
  assert(report.errors.length === 0, report.errors.map((e) => `${e.where}: ${e.message}`).join("\n"));

  // "Loudly" is only a claim when there is something to be loud ABOUT, and this
  // catalogue has now run out: every placeholder has a real release behind it.
  // Demanding the warning unconditionally made the arrival of that state a
  // failing test — the same shape as the floor below, one test over, and worth
  // fixing here rather than after it turns a publish red for the second time.
  //
  // Read off the tree rather than assumed, so if a staging version is ever
  // added again the assertion comes back on its own.
  const anyStaging = loadSources(REPO_ROOT).plugins.some(
    (p) => p.doc?.unlisted !== true && (p.versions ?? []).some((v) => v.doc?.staging === true && v.doc?.yanked !== true),
  );
  if (anyStaging) {
    assert(report.warnings.some((w) => w.message.includes("accepted as staging")), "it passed silently");
  }
});
await test("no staging entry offers a download URL to a digest-blind client", () => {
  const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
  const staged = doc.signed.plugins.filter((p) => p.staging === true);

  // Per entry, and exact. This used to demand `staged.length >= 1` so the leak
  // check below could not pass over an empty set — a good instinct that could
  // not tell two things apart: a scraper that broke, and a catalogue that
  // legitimately ran out of staging entries. The second happened, the moment
  // the last placeholder got a real release, and the floor turned the thing it
  // was working towards into a red build.
  //
  // My first repair compared "are there staging versions in the sources" with
  // "are there staging entries in the index" and was wrong for a reason worth
  // keeping: an old staging version stays on disk forever, while the index
  // reflects only the NEWEST release. So the two counts legitimately disagree
  // and the assertion failed on a correct tree.
  //
  // The honest statement is per plugin: an entry is `staging` exactly when its
  // own newest listed version is. That cannot be satisfied by a broken walk in
  // either direction, and it needs no threshold.
  const newestIsStaging = new Map();
  for (const p of loadSources(REPO_ROOT).plugins) {
    if (p.doc?.unlisted === true) continue;
    const live = (p.versions ?? []).map((v) => v.doc).filter((d) => d && d.yanked !== true);
    if (!live.length) continue;
    const newest = live.slice().sort((a, b) => compareSemver(a.version, b.version)).at(-1);
    newestIsStaging.set(p.doc.id, newest.staging === true);
  }
  for (const entry of doc.signed.plugins) {
    const want = newestIsStaging.get(entry.id);
    assert(want !== undefined, `${entry.id} is in the index and not in the sources`);
    assert((entry.staging === true) === want,
      `${entry.id}: the index says staging=${entry.staging === true} and its newest version says ${want}`);
  }

  // Checked across every staging entry, not one named one: the compatibility
  // fields are exactly what a client that cannot read releases[] would follow,
  // and one leaky entry is one unverifiable download.
  const leaky = staged.filter((e) => e.download_url !== "" || Object.keys(e.platform_downloads).length !== 0);
  assert(leaky.length === 0,
    `unverifiable entries are reachable through the compatibility fields: ${leaky.map((e) => e.id).join(", ")}`);
});

console.log("\nrejections");
await test("an id that is not a safe path component is rejected", async () => {
  const { report } = await validateTree(path.join(REPO_ROOT, "tests/fixtures/unsafe-id"));
  assert(errorsMatching(report, "not a safe path component").length >= 1,
    `id '../../etc/passwd' was not rejected as a path component:\n${report.errors.map((e) => e.message).join("\n")}`);
});
await test("two ids that look identical cannot both be listed", async () => {
  const { report } = await validateTree(path.join(REPO_ROOT, "tests/fixtures/id-collision"));
  assert(errorsMatching(report, "indistinguishable").length === 1,
    "dice-roller and dicer0ller were both accepted");
});
await test("a digest that disagrees with its artifact is rejected", async () => {
  const fx = makeFixtures(path.join(tmp, "digest"));
  const { report } = await validateTree(fx.mismatchDir, { artifactsDir: fx.artifactsDir });
  const hits = errorsMatching(report, "DIGEST MISMATCH");
  assert(hits.length === 1, `expected one DIGEST MISMATCH, got:\n${report.errors.map((e) => e.message).join("\n")}`);
  assert(hits[0].message.includes(fx.sha256), "the error does not name the digest the bytes actually have");
});
await test("the same tree with the right digest passes", async () => {
  const fx = makeFixtures(path.join(tmp, "digest2"));
  const { report, counts } = await validateTree(fx.okDir, { artifactsDir: fx.artifactsDir });
  assert(report.errors.length === 0, report.errors.map((e) => `${e.where}: ${e.message}`).join("\n"));
  assert(counts.hashed === 1, `${counts.hashed} digests verified, expected 1`);
});
await test("a hand-edited index is caught by --check", async () => {
  const dir = path.join(tmp, "tampered");
  fs.cpSync(path.join(REPO_ROOT, "plugins"), path.join(dir, "plugins"), { recursive: true });
  fs.mkdirSync(path.join(dir, "registry/v1"), { recursive: true });
  const doc = buildIndex({ root: dir, serial: 7 });
  doc.signed.plugins[0].platform_downloads = { "linux-x64": "https://github.com/evil/x/releases/download/v1/x.astraplugin" };
  fs.writeFileSync(path.join(dir, "registry/v1/index.json"), stableStringify(doc));
  const { report } = await runValidation({ root: dir, allowStaging: true, online: false, artifactsDir: null, index: true });
  assert(errorsMatching(report, "byte-identical").length === 1,
    "an index with a hand-inserted download URL passed the generated-file check");
});
await test("an artifact under a platform key with no host is rejected", async () => {
  const dir = path.join(tmp, "macos");
  fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(dir, "plugins/dice-roller"), { recursive: true });
  const vf = path.join(dir, "plugins/dice-roller/versions/1.0.0.json");
  const v = JSON.parse(fs.readFileSync(vf, "utf8"));
  v.artifacts["macos-arm64"] = { ...v.artifacts["linux-x64"] };
  v.artifacts["macos-arm64"].url = v.artifacts["macos-arm64"].url.replace("linux-x64", "macos-arm64");
  v.artifacts["macos-arm64"].filename = v.artifacts["macos-arm64"].filename.replace("linux-x64", "macos-arm64");
  v.artifacts["macos-arm64"].sha256 = "2".repeat(64);
  fs.writeFileSync(vf, stableStringify(v));
  const { report } = await validateTree(dir);
  assert(errorsMatching(report, "reserved key with no host").length === 1,
    "an artifact was listed for a platform Astra ships no daemon for");
});

/** Run the real validator with $ASTRA_PLUGINS_DIR pointed at a fake checkout. */
async function withFakeAstraPlugins(dirName, limitsYaml, fn) {
  const root = path.join(tmp, dirName);
  fs.mkdirSync(path.join(root, "spec"), { recursive: true });
  fs.writeFileSync(path.join(root, "spec/limits.yaml"), limitsYaml);
  const prev = process.env.ASTRA_PLUGINS_DIR;
  process.env.ASTRA_PLUGINS_DIR = root;
  try {
    const { report } = await runValidation({
      root: REPO_ROOT, allowStaging: true, online: false, artifactsDir: null, index: false,
    });
    await fn(report);
  } finally {
    if (prev === undefined) delete process.env.ASTRA_PLUGINS_DIR;
    else process.env.ASTRA_PLUGINS_DIR = prev;
  }
}

await test("a limit that drifts from AstraPlugins/spec/limits.yaml is caught", async () => {
  // policy/limits.json says these numbers mirror constants in another
  // repository. Two repositories holding one number is a standing invitation
  // for one of them to move, and the damage is silent in both directions: a cap
  // above the daemon's lists bundles that cannot install, one below it rejects
  // bundles that would.
  await withFakeAstraPlugins("fake-ap-drift",
    "max_extract_bytes: 999_999_999\nmax_archive_entries: 10_000\n",
    (report) => {
      const hits = errorsMatching(report, "max_extract_bytes is");
      assert(hits.length === 1, `drift was not caught:\n${report.errors.map((e) => e.message).join("\n")}`);
      assert(hits[0].message.includes("999999999"), "the error does not name the upstream value");
      assert(errorsMatching(report, "max_archive_entries").length === 0,
        "the limit that did NOT drift was reported anyway");
    });
});
// ── the locale couplings ────────────────────────────────────────────────────
//
// Three facts about locales are kept in more than one place, and all three are
// tested by CONSTRUCTING a drift rather than by waiting for one. A mirror check
// nobody has watched fail is a mirror check nobody knows works, and each of
// these is silent in the direction that matters: nothing errors, nothing is
// missing, a document says the right thing, and no program ever asks it.

/**
 * A fake AstraPlugins checkout with exactly the files a case needs, and one
 * check run against it.
 *
 * `$ASTRA_PLUGINS_DIR` is tried before the sibling working copy, so a fake that
 * carries the file under test wins in both places these tests run: a
 * developer's machine with AstraPlugins beside this repository, and CI, where
 * the only checkout is the one the workflow fetched.
 */
function withFakeCheckout(dirName, files, fn) {
  const root = path.join(tmp, dirName);
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), body);
  }
  const found = [];
  const ctx = {
    report: {
      error: (where, message, hint) => found.push({ level: "error", where, message, hint }),
      warn: (where, message, hint) => found.push({ level: "warn", where, message, hint }),
      note: (where, message, hint) => found.push({ level: "note", where, message, hint }),
    },
    policy: loadPolicy(REPO_ROOT),
    schemas: loadSchemas(REPO_ROOT),
    root: REPO_ROOT,
  };
  const prev = process.env.ASTRA_PLUGINS_DIR;
  process.env.ASTRA_PLUGINS_DIR = root;
  try {
    fn(ctx, found);
  } finally {
    if (prev === undefined) delete process.env.ASTRA_PLUGINS_DIR;
    else process.env.ASTRA_PLUGINS_DIR = prev;
  }
  return found;
}

const LOCALES_YAML = "en   English\nru   Русский\nuk   Українська\nde   Deutsch\nfr   Français\n" +
  "es   Español\npt   Português\nja   日本語\nzh   中文\nko   한국어\n";

await test("C15 — the bot's locale list and both schema enums are one vocabulary", () => {
  // The in-repository half, which needs no checkout at all. A bot that emits a
  // locale the schema rejects does not fail that listing: it fails
  // `validateSchema(schemas.index, doc)` on the deploy candidate, which stops
  // the catalogue for every listing because one plugin shipped a translation.
  const schemas = loadSchemas(REPO_ROOT);
  assertEqual(localeEnumProblems(schemas.plugin, "schema/plugin-v1.json").length, 0,
    "the source schema disagrees with bot/lib/locales.mjs today");
  assertEqual(localeEnumProblems(schemas.index, "schema/index-v1.json").length, 0,
    "the index schema disagrees with bot/lib/locales.mjs today");

  // Constructed drift, one in each direction.
  const narrowed = JSON.parse(JSON.stringify(schemas.plugin));
  narrowed.properties.i18n.propertyNames.enum =
    narrowed.properties.i18n.propertyNames.enum.filter((c) => c !== "uk");
  assert(localeEnumProblems(narrowed, "fake").some((p) => p.includes("uk")),
    "a schema that stopped accepting a locale the bot emits was not noticed");

  const widened = JSON.parse(JSON.stringify(schemas.index));
  widened.$defs.plugin.properties.i18n.propertyNames.enum.push("en");
  assert(localeEnumProblems(widened, "fake").some((p) => p.includes('accepts "en"')),
    "`en` as an i18n key is the drift that looks harmless: it duplicates the untranslated card");

  // And the reach of the check itself. Rename the member and this reader must
  // say so, rather than comparing nine codes against nothing and reporting a
  // clean bill of health for a schema it never opened.
  const moved = JSON.parse(JSON.stringify(schemas.plugin));
  delete moved.properties.i18n;
  let threw = null;
  try { localeEnumProblems(moved, "fake"); } catch (e) { threw = e.message; }
  assert(threw?.includes("no i18n member"),
    `a vanished member must be an error, not an empty comparison: ${threw}`);
});

await test("C15 — the vocabulary is compared with spec/locales.yaml, and that parse has a floor", () => {
  const drifted = withFakeCheckout("fake-ap-locales-drift",
    { "spec/locales.yaml": LOCALES_YAML.replace("zh   中文\n", "zh-CN   中文\n") },
    (ctx) => checkLocaleVocabulary(ctx));
  assert(drifted.some((f) => f.level === "error" && f.message.includes("zh-CN")),
    `the spelling that ships an unselectable locale file was not caught: ${JSON.stringify(drifted)}`);

  const agreeing = withFakeCheckout("fake-ap-locales-ok",
    { "spec/locales.yaml": LOCALES_YAML },
    (ctx) => checkLocaleVocabulary(ctx));
  assertEqual(agreeing.filter((f) => f.level === "error").length, 0,
    `agreeing vocabularies were reported as drift: ${JSON.stringify(agreeing)}`);

  // The floor, and it is the difference between "the vocabulary shrank" and
  // "this reader stopped matching the file" — which need opposite fixes and
  // look identical from a green tick.
  const unparseable = withFakeCheckout("fake-ap-locales-shape",
    { "spec/locales.yaml": "# every row is now a comment\n" },
    (ctx) => checkLocaleVocabulary(ctx));
  assert(unparseable.some((f) => f.message.includes("cannot be right")),
    `an empty parse must fail as a broken scan: ${JSON.stringify(unparseable)}`);
});

await test("C20 — the caps AstraPlugins mirrors FROM here, and which side is the copy", () => {
  const mirrors = (nameCap) =>
    `# mirrors: astra-registry/policy/limits.json max_name_length\nmax_name_length: ${nameCap}\n` +
    "# mirrors: astra-registry/policy/limits.json max_summary_length\nmax_summary_length: 200\n" +
    "# mirrors: astra-registry/policy/limits.json max_description_length\nmax_description_length: 4000\n" +
    "# mirrors: astra-registry/schema/version-v1.json $.properties.permissions.patternProperties.*.properties.reason maxLength\n" +
    "max_permission_reason_chars: 140\n" +
    "# mirrors: astra-registry/policy/limits.json max_locale_bytes\nmax_locale_bytes: 262144\n" +
    "# mirrors: astra-registry/policy/limits.json max_locale_keys\nmax_locale_keys: 5000\n" +
    "# mirrors: astra-registry/policy/limits.json max_listing_i18n_bytes\nmax_listing_i18n_bytes: 8192\n";

  const ok = withFakeCheckout("fake-ap-listing-ok", { "spec/listing-limits.yaml": mirrors(64) },
    (ctx) => checkMirroredListingLimits(ctx));
  assertEqual(ok.filter((f) => f.level === "error").length, 0,
    `today's caps were reported as drift: ${JSON.stringify(ok)}`);

  // ── the reverse direction ──────────────────────────────────────────────
  // The one the forward loop structurally cannot run: it walks that file's
  // rows, so a cap that file does not carry is invisible to it however
  // carefully it is written. This is what three locale caps were enforced at
  // ingest and mirrored nowhere behind, for a day, with both halves green.
  //
  // The mutation is a DELETION rather than a bad value, because a bad value is
  // already what the loop above catches. Constructed in the direction the real
  // failure arrived in: the registry holds the cap, upstream does not.
  const unmirrored = withFakeCheckout("fake-ap-listing-reverse",
    { "spec/listing-limits.yaml": mirrors(64).replace(/# mirrors:[^\n]*max_locale_bytes\nmax_locale_bytes: \d+\n/, "") },
    (ctx) => checkMirroredListingLimits(ctx));
  const gone = unmirrored.find((f) => f.level === "error" && f.message.includes("max_locale_bytes"));
  assert(gone, `a cap declared _mirrored_by with no row upstream passed: ${JSON.stringify(unmirrored)}`);
  // The two causes need opposite fixes and look identical from the error alone.
  assert(gone.hint.includes("ASTRA_PLUGINS_REF"),
    "a missing row is as often a stale pin as a deletion, and the message must name both");
  // The repair that greens the check by destroying it.
  assert(gone.hint.includes("Do NOT fix it by deleting"),
    "the fastest green here is deleting the `_mirrored_by` sibling, so the message has to refuse it by name");

  // And its floor: declarations deleted wholesale is the same green as a reader
  // that stopped matching them, and they need opposite fixes.
  const noDeclarations = withFakeCheckout("fake-ap-listing-nodecl",
    { "spec/listing-limits.yaml": mirrors(64) },
    (ctx) => checkMirroredListingLimits({
      ...ctx,
      policy: {
        ...ctx.policy,
        limits: Object.fromEntries(
          Object.entries(ctx.policy.limits).filter(([k]) => !k.endsWith("_mirrored_by"))),
      },
    }));
  assert(noDeclarations.some((f) => f.message.includes("below the floor of")),
    `an empty declaration set must fail as a broken enumeration: ${JSON.stringify(noDeclarations)}`);

  const drift = withFakeCheckout("fake-ap-listing-drift", { "spec/listing-limits.yaml": mirrors(48) },
    (ctx) => checkMirroredListingLimits(ctx));
  const hit = drift.find((f) => f.level === "error");
  assert(hit?.message.includes("48"), `a cap that drifted was not caught: ${JSON.stringify(drift)}`);
  // Which side somebody edits to make a mirror check pass is the whole question
  // for this class of check, and the answer belongs in the message, because the
  // fastest way to green is to edit whichever of the two files is on screen.
  assert(hit.hint.includes("THIS repository owns these numbers"),
    "the message must say which of the two files is the copy");

  // The JSON-pointer target, resolved rather than guessed at: it names a schema
  // keyword rather than a policy key, and a reader that quietly failed to
  // resolve it would leave that cap unpinned in both repositories.
  const pointer = withFakeCheckout("fake-ap-listing-pointer",
    { "spec/listing-limits.yaml": mirrors(64).replace("max_permission_reason_chars: 140", "max_permission_reason_chars: 999") },
    (ctx) => checkMirroredListingLimits(ctx));
  assert(pointer.some((f) => f.message.includes("999")),
    `the schema-pointer mirror did not resolve: ${JSON.stringify(pointer)}`);

  // And the floor: a file this reader can no longer parse is a broken scan, not
  // a shrinking list of caps.
  const shapeless = withFakeCheckout("fake-ap-listing-shape",
    { "spec/listing-limits.yaml": "max_name_length = 64\n" },
    (ctx) => checkMirroredListingLimits(ctx));
  assert(shapeless.some((f) => f.message.includes("below the floor")),
    `a file that stopped parsing must say so: ${JSON.stringify(shapeless)}`);
});

await test("every cap in policy/limits.json says what an author's tree has to do with it", () => {
  const run = (limits) => {
    // `loadPolicy` wraps the file, and every reader unwraps with
    // `ctx.policy.limits ?? ctx.policy`. Passing the bare map exercises the
    // second branch, which is the one a hand-built ctx would otherwise skip.
    const found = [];
    checkEveryCapDeclaresItsAuthorSide({
      report: {
        error: (where, message, hint) => found.push({ level: "error", where, message, hint }),
        warn: (where, message, hint) => found.push({ level: "warn", where, message, hint }),
        note: (where, message, hint) => found.push({ level: "note", where, message, hint }),
      },
      policy: limits,
    });
    return found;
  };

  const real = loadPolicy(REPO_ROOT).limits;
  const today = run(real);
  assertEqual(today.filter((f) => f.level === "error").length, 0,
    `the committed policy has an undeclared cap: ${JSON.stringify(today)}`);

  // The floor first, before any mutation, because a reader that enumerates no
  // caps reports every one of them as correctly declared.
  assert(run({ max_only_one: 1 }).some((f) => f.message.includes("below the floor of")),
    "a policy this reader can barely parse must fail as a broken scan, not pass as a tiny policy");

  // A NEW CAP WITH NO SIBLING is the thing this check exists for: the way three
  // locale caps came to be enforced at ingest and mirrored nowhere was not a
  // decision, it was an absence nobody could see. Adding one must be red until
  // somebody answers `can an author trip this from their own tree?`.
  const added = run({ ...real, max_something_new: 99 });
  const blank = added.find((f) => f.level === "error" && f.message.includes("max_something_new"));
  assert(blank, `a cap with no declaration passed: ${JSON.stringify(added)}`);
  assert(blank.hint.includes("_mirrored_by") && blank.hint.includes("_not_author_facing"),
    "the message has to name the choices, because the person adding a cap is the only one who knows the answer");

  // `_mirrors` and `_mirrored_by` are opposite claims about which repository
  // owns the number. A cap asserting both pins nothing in either direction.
  const both = run({ ...real, max_locale_bytes_mirrors: "AstraPlugins/spec/limits.yaml max_locale_bytes" });
  assert(both.some((f) => f.level === "error" && f.message.includes("2 declarations")),
    `a cap claiming to be both a copy and an original passed: ${JSON.stringify(both)}`);

  // A `_mirrored_by` pointing anywhere else is a copy nothing compares — which
  // is the state this convention exists to end, wearing the convention's badge.
  const elsewhere = run({ ...real, max_locale_keys_mirrored_by: "somewhere/else.yaml max_locale_keys" });
  assert(elsewhere.some((f) => f.level === "error" && f.message.includes("max_locale_keys_mirrored_by")),
    `a declaration naming an uncompared file passed: ${JSON.stringify(elsewhere)}`);

  // `_unmirrored` is recorded debt, not an exemption, and is named on every run
  // rather than counted. Collapsing it into `_not_author_facing` would let real
  // debt hide behind an innocuous word.
  const debt = today.find((f) => f.level === "note" && f.message.includes("an author can trip"));
  assert(debt && debt.message.includes("max_artifact_bytes"),
    `the unmirrored caps must be named, not counted: ${JSON.stringify(today)}`);
});

await test("C16 — an absent or shrunken locale corpus is never read as a clean one", () => {
  const one = "[plugin]\nname = \"x\"\ndescription = \"x\"\n";
  const empty = withFakeCheckout("fake-ap-corpus-empty",
    { "testdata/locales/pass/only/plugin.toml": one },
    (ctx) => checkLocaleCorpus(ctx));
  const floor = empty.find((f) => f.message.includes("floor"));
  assert(floor, `a one-case corpus passed for a full one: ${JSON.stringify(empty)}`);
  assert(floor.hint.includes("this SCAN is what broke"),
    "the floor's message has to separate `the rules shrank` from `the reader is looking in the wrong place`");

  // A fixture expecting a rule this side neither implements nor exempts is a
  // decision nobody made. It is reported, rather than skipped, because the
  // exemption list is the load-bearing half of the arrangement: it turns
  // forgetting into a visible blank.
  const files = {};
  for (let i = 0; i < 4; i++) files[`testdata/locales/pass/p${i}/plugin.toml`] = one;
  for (let i = 0; i < 12; i++) {
    files[`testdata/locales/fail/f${i}/plugin.toml`] = one;
    files[`testdata/locales/fail/f${i}/EXPECT`] = "E1\n";
    files[`testdata/locales/fail/f${i}/locales/ru.json`] = '{"listing.name":"x","listing.description":"x"}';
  }
  files["testdata/locales/fail/f0/EXPECT"] = "E99\n";
  const unknown = withFakeCheckout("fake-ap-corpus-unknown", files, (ctx) => checkLocaleCorpus(ctx));
  assert(unknown.some((f) => f.message.includes("E99")),
    `a rule id from the future was silently ignored: ${JSON.stringify(unknown.map((f) => f.message))}`);
});

await test("C16 — a fixture that provokes an exempt rule is READ, not refused by the reader", () => {
  // The other half of the exemption, and the half that was missing. Declaring
  // `E_METADATA_UNSAFE_TEXT` in `CORPUS_NO_RULE_ID` is only worth something if
  // `corpusIds` then lets a case through that provokes it — and before that
  // entry existed it did the opposite: it THREW `is an error this module can
  // emit and CORPUS_RULE_IDS does not name`, so the reader refused the very
  // fixture that would have made the rule visible. A mutation is what said this
  // needed saying: removing the exemption from `corpusIds` left every other
  // test green, because no committed fixture provokes any of the three.
  //
  // The case belongs in `pass/`, and that is not a mistake. `astra-plugin
  // check` has no display-text scan at all, so the CLI accepts this bundle;
  // the registry refuses it. The corpus compares ERROR ID SETS, and this rule
  // contributes no id to either side — which is exactly the disagreement
  // `CORPUS_NO_RULE_ID` exists to write down instead of hiding.
  const toml = (name, desc) => `[plugin]\nname = "${name}"\ndescription = "${desc}"\n`;
  const plain = toml("x", "x");
  const files = {};
  for (let i = 0; i < 4; i++) files[`testdata/locales/pass/p${i}/plugin.toml`] = plain;
  for (let i = 0; i < 12; i++) {
    files[`testdata/locales/fail/f${i}/plugin.toml`] = plain;
    files[`testdata/locales/fail/f${i}/EXPECT`] = "E1\n";
    files[`testdata/locales/fail/f${i}/locales/ru.json`] = '{"listing.name":"x","listing.description":"x"}';
  }
  // A conforming bundle whose Russian card name carries a right-to-left
  // override. Every parity and card rule is satisfied; the only thing wrong
  // with it is a character nobody can see.
  files["testdata/locales/pass/p0/locales/en.json"] = '{"listing.name":"x","listing.description":"x"}';
  files["testdata/locales/pass/p0/locales/ru.json"] =
    JSON.stringify({ "listing.name": "\u202ex", "listing.description": "x" });

  const found = withFakeCheckout("fake-ap-corpus-exempt", files, (ctx) => checkLocaleCorpus(ctx));
  const unreadable = found.filter((f) => f.level === "error" && /could not be read/.test(f.message));
  assertEqual(unreadable.length, 0,
    "the reader refused a fixture for a rule this repository deliberately has no corpus id for:\n" +
    unreadable.map((f) => `  ${f.message}`).join("\n"));
  // Scoped to `pass/p0` on purpose. This synthetic corpus witnesses one rule,
  // so the "every implemented rule has a fail case" loop rightly complains
  // about the other seven — that is a different check doing its job, and
  // swallowing it here would make this test pass for a reason of its own.
  const aboutTheCase = found.filter((f) => f.level === "error" && /pass\/p0/.test(f.message));
  assertEqual(aboutTheCase.length, 0,
    `an exempt rule became a corpus disagreement: ${JSON.stringify(aboutTheCase.map((f) => f.message))}`);

  // Not vacuous: the fixture really does provoke the rule. Without this the
  // test would pass against a corpus that provokes nothing at all, which is the
  // failure the whole exemption exists to stop.
  const provoked = deriveLocaleText({
    files: [
      { name: "locales/en.json", bytes: Buffer.from('{"listing.name":"x","listing.description":"x"}') },
      { name: "locales/ru.json", bytes: Buffer.from(JSON.stringify({ "listing.name": "\u202ex", "listing.description": "x" })) },
    ],
    facts: { name: "x", description: "x" },
    limits: loadPolicy(REPO_ROOT).limits,
    summarise,
  }).findings;
  assert(provoked.some((f) => f.code === "E_METADATA_UNSAFE_TEXT"),
    `the fixture provokes nothing, so this test proves nothing: ${JSON.stringify(provoked.map((f) => f.code))}`);
});

await test("C16, the direction it never ran in — every locale rule is mapped or exempted", () => {
  // `checkLocaleCorpus` reads the corpus and asks of each id whether this
  // repository implements or exempts it: corpus -> registry. It can only ever
  // see rules somebody already wrote a fixture for. Nothing asked the reverse,
  // and `E_METADATA_UNSAFE_TEXT` is what that cost — enforced on every
  // translated `listing.name` since the locale work landed, provoked by none of
  // the corpus's 104 files, and named in neither map, so `corpusIds` would have
  // THROWN at whoever wrote the first fixture for it.
  //
  // This half needs no checkout, which is the point: `checkLocaleCorpus` skips
  // without one and this must not skip with it.
  const run = () => {
    const found = [];
    checkLocaleCorpusCoverage({
      report: {
        error: (where, message, hint) => found.push({ level: "error", where, message, hint }),
        warn: (where, message, hint) => found.push({ level: "warn", where, message, hint }),
        note: (where, message) => found.push({ level: "note", where, message }),
      },
      policy: loadPolicy(REPO_ROOT),
      schemas: loadSchemas(REPO_ROOT),
      root: REPO_ROOT,
    });
    return found;
  };

  const today = run();
  assertEqual(today.filter((f) => f.level === "error").length, 0,
    `bot/lib/locales.mjs enforces a rule that is neither mapped nor exempted:\n` +
    today.filter((f) => f.level === "error").map((f) => `  ${f.message}`).join("\n"));

  // ── the FLOOR, before the mutation ──
  //
  // This check enumerates a set by scraping `add("error", "E_…")` out of the
  // module's own text. That set is one refactor away from being empty, and an
  // empty enumeration passes for the wrong reason — quietly, for ever, while
  // reading as coverage. So the count is asserted here and again inside the
  // check, and the two failures are made to look different from each other.
  const counted = today.find((f) => f.level === "note" && /locale error rule\(s\) enumerated/.test(f.message));
  assert(counted, `the check reported no count at all: ${JSON.stringify(today)}`);
  const n = Number(/^(\d+)/.exec(counted.message)?.[1] ?? 0);
  assert(n >= 11, `only ${n} locale error rules were found; the module has more, so this SCAN is what broke`);

  // ── and the mutation, watched ──
  //
  // The check reads this repository's own module by design — it is asking about
  // THIS repository's rules — so the drift is constructed in the maps, which is
  // the side an editor touches. An exemption for a rule that no longer exists
  // is the reverse of the failure above and the one that makes a debt look
  // serviced, so it fails too rather than being tidied away.
  const stale = [];
  const before = CORPUS_NO_RULE_ID.E_LOCALE_GONE_TOMORROW;
  CORPUS_NO_RULE_ID.E_LOCALE_GONE_TOMORROW = "a rule this module does not emit";
  try {
    checkLocaleCorpusCoverage({
      report: {
        error: (where, message, hint) => stale.push({ where, message, hint }),
        warn: () => {}, note: () => {},
      },
      policy: loadPolicy(REPO_ROOT), schemas: loadSchemas(REPO_ROOT), root: REPO_ROOT,
    });
  } finally {
    if (before === undefined) delete CORPUS_NO_RULE_ID.E_LOCALE_GONE_TOMORROW;
    else CORPUS_NO_RULE_ID.E_LOCALE_GONE_TOMORROW = before;
  }
  assert(stale.some((f) => f.message.includes("E_LOCALE_GONE_TOMORROW")),
    "an exemption outliving its rule is a reason nobody can check, and it makes the debt look serviced");
});

await test("the hand-edit path checks every card a listing renders, not the English one", async () => {
  // `checkSquatting` built its name index from `p.doc?.name` alone. The moment
  // a listing grew an `i18n` member the asymmetry was back in a new place: the
  // bot ran `checkDisplayName` once per derived locale and this ran once per
  // listing. Constructed below and confirmed against origin/main: the validator
  // printed `PASS … 0 error(s), 0 warning(s)` for a tree `bot/lib/names.mjs`
  // answered R_DISPLAY_NAME_COLLISION and R_DISPLAY_NAME_MIXED_SCRIPT for.
  const dir = path.join(tmp, "i18n-names");
  const mk = (id, name, i18n) => {
    const d = path.join(dir, "plugins", id);
    fs.mkdirSync(path.join(d, "versions"), { recursive: true });
    fs.writeFileSync(path.join(d, "plugin.json"), JSON.stringify({
      schema: "astra.registry.plugin/1",
      id, name, summary: "Roll dice", license: "MIT",
      source: { kind: "github", repo: `someone/${id}` },
      added_at: "2026-08-10", description: "Roll dice", author: { name: "A Stranger" },
      ...(i18n ? { i18n } : {}),
    }, null, 2));
    fs.writeFileSync(path.join(d, "versions", "0.1.0.json"), JSON.stringify({
      schema: "astra.registry.version/1", id, version: "0.1.0",
      published_at: "2026-08-10T00:00:00Z",
      release: { kind: "github_release", repo: `someone/${id}`, tag: "v0.1.0" },
      staging: true, staging_reason: "selftest fixture: no release to pin",
      artifacts: {
        "linux-x64": {
          url: `https://github.com/someone/${id}/releases/download/v0.1.0/${id}-0.1.0-linux-x64.astraplugin`,
          filename: `${id}-0.1.0-linux-x64.astraplugin`,
        },
      },
    }, null, 2));
  };
  mk("dice-roller", "Dice Roller");
  // U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I for the ASCII `i`,
  // and a Cyrillic е inside a German name. Both live ONLY in `i18n`, which is
  // the whole point — the English cards are innocent and were all this looked at.
  mk("lucky-cubes", "Lucky Cubes", {
    ru: { name: "D\u0456ce Roller", summary: "\u0411\u0440\u043e\u0441\u043a\u0438" },
    de: { name: "W\u00fcrf\u0435l Roller", summary: "W\u00fcrfeln" },
  });

  const { report } = await runValidation({
    root: dir, allowStaging: true, allowDirect: false, online: false, artifactsDir: null, index: false,
  });
  const said = report.warnings.map((w) => `${w.where} ${w.message}`).join("\n");
  assert(/i18n\.ru.*matches/.test(said),
    `a localized homoglyph collision produced no finding on the hand-edit path:\n${said}`);
  assert(/i18n\.de.*mixes/.test(said),
    `a localized mixed-script name produced no finding on the hand-edit path:\n${said}`);
  // The floor: if `renderedNames` ever returns only the flat name again, the
  // two assertions above go red — but so does a tree with no listings, and the
  // two must not look alike.
  assertEqual(report.errors.length, 0, `the fixture tree itself is broken:\n${report.errors.map((e) => `${e.where} ${e.message}`).join("\n")}`);
});

await test("the English card rule, and an exemption that has outlived its listing", () => {
  const listing = (id, summary, repo) => ({
    file: `plugins/${id}/plugin.json`,
    doc: { id, summary, source: { kind: "github", repo } },
  });
  const russian = "Шахматы против локального бота или выбранной модели Astra с игровым чатом.";
  const run = (plugins, exempt) => {
    const found = [];
    const ctx = {
      report: {
        error: (where, message, hint) => found.push({ level: "error", where, message, hint }),
        warn: (where, message, hint) => found.push({ level: "warn", where, message, hint }),
        note: () => {},
      },
      policy: { ...loadPolicy(REPO_ROOT), listingLanguage: { exempt } },
    };
    checkListingLanguage(plugins, ctx);
    return found;
  };

  const refused = run([listing("chess", russian, "KNICE-TECH/chess")], []);
  assert(refused.some((f) => f.level === "error"), `a Russian card was listed: ${JSON.stringify(refused)}`);
  assert(refused[0].hint.includes("NOT an edit to this file"),
    "the fix is a release, not a hand edit to a derived document that the next release would contradict");

  const excused = run([listing("chess", russian, "KNICE-TECH/chess")], [{ repo: "KNICE-TECH/chess", reason: "test" }]);
  assertEqual(excused.filter((f) => f.level === "error").length, 0,
    `the exemption did not excuse: ${JSON.stringify(excused)}`);
  // Keyed on the repository and not on the id, because an id can be re-taken
  // under a different repository and a rename would walk straight past it.
  const renamed = run([listing("astra-chess", russian, "KNICE-TECH/astra-chess")], [{ repo: "KNICE-TECH/chess" }]);
  assert(renamed.some((f) => f.level === "error"),
    "an exemption for one repository must not follow the plugin to another one");

  // An unlisted plugin is rendered to nobody in any language, so it is skipped —
  // and it is worth knowing this is live rather than hypothetical: `knice-chess`
  // is in the tree, is unlisted, is Russian, and is the only listing that fails
  // this check today.
  const hidden = run([{ file: "plugins/knice-chess/plugin.json", doc: { id: "knice-chess", summary: russian, unlisted: true, source: { repo: "x/y" } } }], []);
  assertEqual(hidden.length, 0, `an unlisted plugin was audited: ${JSON.stringify(hidden)}`);

  // An exemption nobody needs is a hole nobody is watching: the next release
  // from that repository inherits an excuse no one granted it.
  const stale = run([listing("chess", "Plays chess.", "KNICE-TECH/chess")], [{ repo: "KNICE-TECH/chess" }]);
  assert(stale.some((f) => f.message.includes("not being used")),
    `an exemption for a card that is English now was not reported: ${JSON.stringify(stale)}`);
});

await test("a hand-edited locale name is scanned like every other display string", async () => {
  // The hole this closes: `tools/validate.mjs` applied `unsafeDisplayText` to a
  // hardcoded three-field object literal — name, summary, author — so a
  // maintainer who typed an i18n block into a plugin.json by hand got no
  // display-text scan at all, and CI stayed green because the generator
  // faithfully reproduced whatever the tree said.
  const dir = path.join(tmp, "hand-edited-i18n");
  fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
    path.join(dir, "plugins/dice-roller"), { recursive: true });
  const file = path.join(dir, "plugins/dice-roller/plugin.json");
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  doc.i18n = { ru: { name: "Dice Roller‮", summary: "Бросает кости." } };
  fs.writeFileSync(file, stableStringify(doc));
  const { report } = await validateTree(dir);
  assert(errorsMatching(report, "i18n.ru.name").length === 1,
    `a bidi override in a localized card name reached the store: ${report.errors.map((e) => e.message).join("; ")}`);
});

await test("matching limits produce no finding, and a renamed constant does", async () => {
  await withFakeAstraPlugins("fake-ap-ok",
    "max_extract_bytes: 524_288_000\nmax_archive_entries: 10_000\n",
    (report) => {
      assert(errorsMatching(report, "policy/limits.json").length === 0,
        `agreeing numbers were reported as drift:\n${report.errors.map((e) => e.message).join("\n")}`);
    });
  await withFakeAstraPlugins("fake-ap-renamed",
    "max_extract_bytes: 524_288_000\nmax_archive_entriez: 10_000\n",
    (report) => {
      assert(errorsMatching(report, "which is not in").length === 1,
        "a constant that vanished upstream was not noticed — the mirror check would silently stop checking");
    });
});

await test("a stale asset from an earlier version is rejected by name", async () => {
  // The filename convention is <id>-<version>-<target>.astraplugin, asserted by
  // the CLI and by plugin-release.yml. The case that matters is the plausible
  // one: a 0.1.1 listing pointing at the 0.1.0 asset. Every other check passes —
  // the URL sits under the right release, the digest matches the file that is
  // actually there — because the digest was copied from whatever was uploaded.
  // Only the name says it is the wrong build.
  const dir = path.join(tmp, "stale-asset");
  fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(dir, "plugins/dice-roller"), { recursive: true });
  const vf = path.join(dir, "plugins/dice-roller/versions/1.0.0.json");
  const v = JSON.parse(fs.readFileSync(vf, "utf8"));
  const stale = `${v.id}-0.9.9-linux-x64.astraplugin`;
  v.artifacts["linux-x64"].filename = stale;
  v.artifacts["linux-x64"].url = v.artifacts["linux-x64"].url.replace(/[^/]+\.astraplugin$/, stale);
  fs.writeFileSync(vf, stableStringify(v));
  const { report } = await validateTree(dir);
  const hits = errorsMatching(report, "expected");
  assert(hits.some((e) => e.message.includes(stale)),
    `the previous version's asset was accepted under a ${v.version} listing:\n${report.errors.map((e) => e.message).join("\n")}`);
});

console.log("\nwhere artifacts may come from");
// A listing has to be able to say "these bytes live here" for a here that is not
// github.com. Astra's daemon was built for it — `artifact_download_policy` adds
// the artifact URL's own host to the allow-list, in as many words, "a
// self-hosted or staging catalogue serves its artifacts from its own origin" —
// and until `release.kind: "direct"` existed the schema could not express what
// the daemon already accepted. These four tests are the two halves of that:
// the shape is expressible, and it is pinned exactly as tightly as the GitHub
// shape, to a different anchor.

const DIRECT_BASE = "https://catalogue.internal.example:8443/astra/";

/** A one-plugin tree whose single release is served from a non-GitHub origin. */
function directTree(name, mutate = () => {}) {
  const dir = path.join(tmp, name);
  fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(dir, "plugins/dice-roller"), { recursive: true });
  const vf = path.join(dir, "plugins/dice-roller/versions/1.0.0.json");
  const v = JSON.parse(fs.readFileSync(vf, "utf8"));
  v.release = { kind: "direct", base_url: DIRECT_BASE };
  v.artifacts["linux-x64"].url = `${DIRECT_BASE}${v.artifacts["linux-x64"].filename}`;
  mutate(v);
  fs.writeFileSync(vf, stableStringify(v));
  return dir;
}

await test("a self-hosted origin is expressible — and only behind --allow-direct", async () => {
  const dir = directTree("direct-ok");
  const { report } = await validateTree(dir, { allowDirect: true });
  assert(report.errors.length === 0,
    `a listing served from its own origin was refused:\n${report.errors.map((e) => `${e.where}: ${e.message}`).join("\n")}`);
  assert(report.warnings.some((w) => w.message.includes("accepted as a direct release")),
    "it passed silently; a non-GitHub origin is a thing a reviewer must see");

  // The public catalogue's guarantee is unchanged: the flag is what buys it,
  // exactly like --allow-staging, and nothing in this repository passes it.
  const strict = await validateTree(dir);
  assert(errorsMatching(strict.report, "release.kind is `direct`").length === 1,
    "a non-GitHub origin was accepted by default");
});

await test("a direct artifact that wanders off its base_url is rejected", async () => {
  // The whole value of the anchor. Without this check `direct` would mean "any
  // URL a submitter typed", which is the thing the hardcoded GitHub pattern was
  // there to prevent — the fix has to keep the rule, not drop it.
  const dir = directTree("direct-wander", (v) => {
    v.artifacts["linux-x64"].url = `https://elsewhere.example/${v.artifacts["linux-x64"].filename}`;
  });
  const { report } = await validateTree(dir, { allowDirect: true });
  const hits = errorsMatching(report, "does not sit under the declared release");
  assert(hits.length === 1, `an off-origin URL was accepted:\n${report.errors.map((e) => e.message).join("\n")}`);
  assert(hits[0].hint.includes(DIRECT_BASE), `the error does not name the base_url: ${hits[0].hint}`);
});

await test("a direct release cannot borrow a repo and tag it does not have", async () => {
  // `repo`/`tag` next to a URL those fields did not produce reads as provenance
  // the entry does not carry — a listing that looks attested and is not.
  const dir = directTree("direct-provenance", (v) => {
    v.release.repo = "someone/dice-roller";
    v.release.tag = "v1.0.0";
  });
  const { report } = await validateTree(dir, { allowDirect: true });
  assert(errorsMatching(report, "is set on a `direct` release").length === 2,
    `repo and tag were accepted on a direct release:\n${report.errors.map((e) => e.message).join("\n")}`);
});

await test("widening the URL pattern did not unpin a GitHub release", async () => {
  // The regression this pair of changes could plausibly have introduced. The
  // schema used to be the thing refusing a foreign host; now the schema allows
  // any https origin and the pin lives entirely in the release-prefix check.
  // This is the reviewer's exact case: a loopback URL under a github_release.
  const dir = path.join(tmp, "github-foreign-host");
  fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(dir, "plugins/dice-roller"), { recursive: true });
  const vf = path.join(dir, "plugins/dice-roller/versions/1.0.0.json");
  const v = JSON.parse(fs.readFileSync(vf, "utf8"));
  v.artifacts["linux-x64"].url = `https://127.0.0.1:8443/${v.artifacts["linux-x64"].filename}`;
  fs.writeFileSync(vf, stableStringify(v));
  const { report } = await validateTree(dir, { allowDirect: true });
  const hits = errorsMatching(report, "does not sit under the declared release");
  assert(hits.length === 1,
    `a github_release listing served bytes from another host:\n${report.errors.map((e) => e.message).join("\n")}`);
  assert(hits[0].hint.includes("https://github.com/someone/dice-roller/releases/download/v1.0.0/"),
    `the error does not name the release prefix: ${hits[0].hint}`);
});

await test("a url that climbs back out of its own prefix is rejected", async () => {
  // `startsWith` is a string test and a path is not a string to the client that
  // fetches it. Both spellings, because `%2e%2e` reaches many servers undecoded.
  for (const [name, tail] of [["plain", "../../"], ["encoded", "%2e%2e/%2e%2e/"]]) {
    const dir = directTree(`traversal-${name}`, (v) => {
      v.artifacts["linux-x64"].url = `${DIRECT_BASE}${tail}${v.artifacts["linux-x64"].filename}`;
    });
    const { report } = await validateTree(dir, { allowDirect: true });
    assert(errorsMatching(report, "`..` path segment").length === 1,
      `a ${name} traversal resolved out of its prefix unnoticed:\n${report.errors.map((e) => e.message).join("\n")}`);
  }
});

console.log("\nthe two digest constructions");
// Known-answer vectors. The expected hex below was NOT produced by any of the
// three implementations — it comes from `python3 -c 'hashlib.sha256(...)'` run
// by hand against the written-down rule. That is the whole value of a KAT here:
// the packer (AstraPlugins CLI) and the reader (Astra daemon) were written from
// the same notes, so a mistake in the notes reproduces in both and they agree
// with each other forever. These numbers agree with the notes.
await test("manifest digest is SHA256(\"astra.bundle/2\\0\" || bytes), pinned by known answer", () => {
  assert(MANIFEST_DIGEST_DOMAIN.length === 15, `domain is ${MANIFEST_DIGEST_DOMAIN.length} bytes, expected 15`);
  assert(MANIFEST_DIGEST_DOMAIN[14] === 0, "the domain prefix does not end in NUL");
  assert(MANIFEST_DIGEST_DOMAIN.toString("latin1", 0, 14) === "astra.bundle/2", "wrong domain string");
  assert(manifestDigest(Buffer.from("{}")) === "e2bc471671c92f3b3fb3aed14b43c64ff19bea7985f3099b851dc4ddb46d3438",
    `manifestDigest("{}") = ${manifestDigest(Buffer.from("{}"))}`);
  assert(manifestDigest(Buffer.alloc(0)) === "abebd3e98bc7858e29d047998a939a39ffee25b42d0cfb940479c5dd2cdd7de3",
    `manifestDigest("") = ${manifestDigest(Buffer.alloc(0))}`);
});
await test("a manifest digest can never be mistaken for a file digest", () => {
  // The property the domain prefix exists for. Without it the two constructions
  // are the same function, and a value computed over one thing can be presented
  // as a value computed over another.
  for (const s of ["{}", "", '{"schema":"astra.bundle/2"}']) {
    const b = Buffer.from(s);
    assert(manifestDigest(b) !== artifactDigest(b), `the two digests collide on ${JSON.stringify(s)}`);
  }
  assert(artifactDigest(Buffer.from("{}")) === "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "bare sha256 is not bare sha256");
});
await test("the manifest is read from byte zero, not from the central directory", () => {
  const { bundle } = makeFixtures(path.join(tmp, "digest-localhdr"));
  const local = manifestBytesFromLocalHeader(bundle);
  const zip = readZip(bundle);
  const entry = zip.entries.find((e) => e.name === "MANIFEST.json");
  assert(entry.index === 0, "the fixture does not put MANIFEST.json first");
  assert(local.equals(readEntry(bundle, entry)),
    "the local header and the central directory disagree on a bundle this repo just wrote");
  // And it refuses an archive that does not begin with one.
  const notAZip = Buffer.from("this is not a zip file, not even close");
  let threw = false;
  try { manifestBytesFromLocalHeader(notAZip); } catch { threw = true; }
  assert(threw, "a non-ZIP was accepted as a manifest source");
});
await test("a central directory pointing away from byte zero is caught", () => {
  // The attack the two readings exist to catch: the central directory's entry
  // for MANIFEST.json is repointed at a DIFFERENT local header, so an index
  // reader sees one manifest and a byte-zero reader (the daemon) sees another.
  //
  // The decoy is built to the SAME BYTE LENGTH as the real manifest on purpose.
  // A length mismatch is caught for free — readEntry runs off the end of the
  // file and the bundle is refused as unreadable — and catching it that way
  // proves nothing about the comparison. Equal lengths make the forgery read
  // cleanly, so only comparing the two readings can tell them apart.
  const real = JSON.stringify({
    schema: "astra.bundle/2", plugin_id: "fixture-plugin", version: "1.0.0",
    platform: { os: "linux", arch: "x86_64" }, entry: { command: "./bin/fixture", args: [] }, files: [],
  });
  // Same length by construction — the decoy id is padded to the real id's
  // length rather than hand-counted, so no arithmetic can drift and quietly
  // turn this back into the length check.
  const realId = JSON.parse(real).plugin_id;
  const evilId = "attacker".slice(0, realId.length).padEnd(realId.length, "-");
  const decoy = JSON.stringify({ ...JSON.parse(real), plugin_id: evilId });
  assert(decoy.length === real.length, `decoy ${decoy.length} vs real ${real.length}`);

  const bundle = writeZip([
    { name: "MANIFEST.json", data: Buffer.from(real), mode: 0o644 },
    { name: "decoy.json", data: Buffer.from(decoy), mode: 0o644 },
  ]);
  const zip = readZip(bundle);
  const man = zip.entries.find((e) => e.name === "MANIFEST.json");
  const other = zip.entries.find((e) => e.name === "decoy.json");
  assert(man && other && other.offset !== man.offset, "fixture has nothing to repoint at");
  const forged = Buffer.from(bundle);
  // Rewrite the offset field of MANIFEST.json's CENTRAL directory record only.
  const cd = forged.indexOf(Buffer.from("PK\x01\x02", "latin1"));
  assert(cd > 0, "no central directory found");
  let p = cd, patched = false;
  while (p > 0 && forged.readUInt32LE(p) === 0x02014b50) {
    const nameLen = forged.readUInt16LE(p + 28);
    const name = forged.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    if (name === "MANIFEST.json") { forged.writeUInt32LE(other.offset, p + 42); patched = true; break; }
    p += 46 + nameLen + forged.readUInt16LE(p + 30) + forged.readUInt16LE(p + 32);
  }
  assert(patched, "could not repoint the central directory entry");

  // Sanity: the forgery reads cleanly through the central directory, i.e. it is
  // NOT caught by a length check. Without this the test could pass for the
  // wrong reason and nobody would know the comparison had stopped working.
  const viaCentral = readEntry(forged, readZip(forged).entries.find((e) => e.name === "MANIFEST.json"));
  assert(JSON.parse(viaCentral.toString("utf8")).plugin_id === evilId,
    "the forgery did not take: the central directory still resolves to the real manifest");
  assert(JSON.parse(manifestBytesFromLocalHeader(forged).toString("utf8")).plugin_id === "fixture-plugin",
    "byte zero no longer holds the real manifest");

  const findings = checkBundle(forged, { id: "fixture-plugin", version: "1.0.0", platformKey: "linux-x64" }, LIMITS);
  assert(findings.some((f) => f.code === "E_MANIFEST_HEADER_DISAGREE"),
    `a repointed central directory was accepted:\n${findings.map((f) => `${f.code} ${f.message}`).join("\n")}`);
});

console.log("\nbundle structure (the bot's crypto-free half)");
await test("a sound bundle produces no findings", () => {
  const { bundle } = makeFixtures(path.join(tmp, "bundle-ok"));
  const findings = checkBundle(bundle, { id: "fixture-plugin", version: "1.0.0", platformKey: "linux-x64" }, LIMITS);
  assert(findings.length === 0, findings.map((x) => `${x.code} ${x.message}`).join("\n"));
});
await test("a file swapped inside the bundle is caught by MANIFEST.files", () => {
  const { bundle } = makeFixtures(path.join(tmp, "bundle-tamper"));
  // Same length, different bytes: the archive stays structurally perfect and
  // only the per-file hash disagrees. That is the shape of a real supply-chain
  // edit, and the whole reason MANIFEST.files carries digests at all.
  const i = bundle.indexOf(Buffer.from("echo fixture"));
  assert(i > 0, "fixture payload not found in the archive");
  const tampered = Buffer.from(bundle);
  tampered.write("echo pwned!!", i);
  const findings = checkBundle(tampered, { id: "fixture-plugin", version: "1.0.0", platformKey: "linux-x64" }, LIMITS);
  assert(findings.some((x) => x.code === "E_MANIFEST_HASH_MISMATCH"),
    `expected E_MANIFEST_HASH_MISMATCH, got: ${findings.map((x) => x.code).join(", ") || "nothing"}`);
});
await test("an unlisted extra file, a symlink and a shell entry are each rejected", () => {
  const binary = Buffer.from("#!/bin/sh\necho fixture\n", "utf8");
  const manifest = {
    schema: "astra.bundle/2",
    plugin_id: "evil", version: "1.0.0", platform: { os: "linux", arch: "x86_64" },
    entry: { command: "/bin/sh", args: [] },
    files: [{
      path: "bin/x",
      sha256: crypto.createHash("sha256").update(binary).digest("hex"),
      size: binary.length, mode: "0755",
    }],
  };
  const zip = writeZip([
    { name: "MANIFEST.json", data: stableStringify(manifest) },
    { name: "bin/x", data: binary, mode: 0o755 },
    { name: "bin/stowaway", data: "not in the manifest" },
    { name: "bin/link", data: "../../../etc/passwd", mode: 0o120777 },
  ]);
  const codes = checkBundle(zip, { id: "evil", version: "1.0.0", platformKey: "linux-x64" }, LIMITS).map((x) => x.code);
  for (const want of ["E_MANIFEST_EXTRA_FILE", "E_BUNDLE_SYMLINK", "E_ENTRY_ABSOLUTE"]) {
    assert(codes.includes(want), `${want} not reported; got ${codes.join(", ")}`);
  }
});
await test("a bundle whose manifest names another plugin is rejected", () => {
  const { bundle } = makeFixtures(path.join(tmp, "bundle-idswap"));
  const codes = checkBundle(bundle, { id: "some-other-plugin", version: "1.0.0", platformKey: "linux-x64" }, LIMITS)
    .map((x) => x.code);
  assert(codes.includes("E_MANIFEST_ID_MISMATCH"),
    "a listing for one id served an archive for another — the confusion §5.3 D closes");
});

// ── the shared vectors ──────────────────────────────────────────────────────
//
// Everything above this line is a fixture this repo builds for itself, which is
// precisely the arrangement that lets three implementations of one format drift
// apart while all three suites stay green: each proves it agrees with itself.
// `tests/vectors/` is a vendored copy of AstraPlugins/testdata/bundles, and the
// CLI's reader and the daemon's reader answer the same questions about the same
// bytes with the same expected answers written down beside them.
//
// See tests/shared-vectors.mjs, and testdata/bundles/README.md upstream.
console.log("\nshared bundle vectors (AstraPlugins/testdata/bundles, vendored)");
await registerSharedVectorTests({ test, assert, limits: LIMITS });

// ── the catalogue signature ─────────────────────────────────────────────────
//
// Task 3.2. The daemon believes this catalogue because an index key that a
// root-signed trust.json delegates to signed it — never because of the host it
// was fetched from. Everything below is the signing half of that; the verifying
// half lives in astra-daemon's plugins::trust tests, and bot/fixtures/index/
// is the one artefact both halves read.
console.log("\ncatalogue signature");

const TEST_INDEX_KEY = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
const TEST_STRANGER_KEY = "TEST-ONLY-DO-NOT-TRUST-stranger";
const trustFixture = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "tools/testkeys/fixtures/trust-reserve-signed.json"), "utf8"),
);
const trustedIndexKeys = indexKeysFromTrust(trustFixture);

function signedFixture(keyId = TEST_INDEX_KEY, serial = 12) {
  const k = loadTestRoot(keyId);
  return signIndex(fixtureCatalogue(serial), {
    signer: { key_id: k.key_id, privateKey: k.privateKey },
    issuedAt: FIXTURE_ISSUED_AT,
  });
}

await test("a signed catalogue verifies under the key trust.json delegates to", () => {
  const doc = signedFixture();
  const r = verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys);
  assert(r.ok, `did not verify: ${r.reason}`);
  assert(r.key_id === TEST_INDEX_KEY, `verified under ${r.key_id}`);
});
await test("a catalogue signed by a key trust.json does not name is refused", () => {
  // Syntactically perfect, correctly domain-separated, real Ed25519. The only
  // thing wrong with it is WHOSE key it is, which is the only thing that may
  // decide the outcome.
  const doc = signedFixture(TEST_STRANGER_KEY);
  const r = verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys);
  assert(!r.ok, "a stranger's signature was accepted");
  assert(r.offered.includes(TEST_STRANGER_KEY), `the refusal must name what was offered: ${JSON.stringify(r.offered)}`);
});
await test("a key_id that lies does not change the outcome", () => {
  const doc = signedFixture(TEST_STRANGER_KEY);
  doc.signatures[0].key_id = TEST_INDEX_KEY;   // claim to be the trusted key
  assert(!verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys).ok,
    "a document verified because it claimed the right key_id");

  const honest = signedFixture(TEST_INDEX_KEY);
  honest.signatures[0].key_id = "who-knows";    // and the converse
  assert(verifyEnvelope(honest, INDEX_SCHEMA, trustedIndexKeys).ok,
    "a genuine signature was refused because its key_id was wrong");
});
await test("one byte edited after signing is refused", () => {
  const doc = signedFixture();
  doc.signed.plugins[0].releases[0].artifacts["linux-x64"].sha256 =
    "2222222222222222222222222222222222222222222222222222222222222222";
  assert(!verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys).ok,
    "the digest — the one field the whole chain exists to pin — was editable after signing");
});
await test("nothing outside `signed` is covered, and nothing outside it is read", () => {
  const doc = signedFixture();
  doc.$comment = "an attacker wrote this";
  doc.serial = 9999;
  assert(verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys).ok,
    "editing an unauthenticated member broke the signature, so something outside `signed` is being hashed");
});
await test("a signature cannot be replayed across document types", () => {
  const doc = signedFixture();
  assert(!verifyEnvelope(doc, TRUST_SCHEMA, trustedIndexKeys).ok,
    "an index signature verified as a trust.json signature; the domain separator is not doing its job");
  assert(!verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys).ok,
    "an index signature verified as a revocations.json signature");
});
await test("the freshness window is 30 days from the signing instant, not from the content", () => {
  const doc = signedFixture();
  assert(doc.signed.issued_at === "2026-08-15T00:00:00Z", doc.signed.issued_at);
  const days = (Date.parse(doc.signed.expires_at) - Date.parse(doc.signed.issued_at)) / 86400000;
  assert(days === CATALOG_TTL_DAYS, `${days} days, expected ${CATALOG_TTL_DAYS}`);
  // And the generator, which reads no clock, stamps neither.
  assert(buildIndex({ serial: 1 }).signed.issued_at === undefined,
    "the generator stamped a timestamp; its output is no longer reproducible");
});
await test("the signer refuses a document that is not a catalogue", () => {
  let threw = false;
  try {
    signIndex({ signed: { schema: TRUST_SCHEMA, serial: 1 } }, { signer: loadTestRoot(TEST_INDEX_KEY) });
  } catch { threw = true; }
  assert(threw, "the index key signed a document under the wrong domain");
});
await test("the committed fixtures are exactly what the signer produces", () => {
  // These bytes are embedded in a daemon unit test. If this repository's JCS
  // and Rust's ever disagree, one of the two suites has to notice, and a
  // fixture regenerated silently on every run could not be the one that does.
  execFileSync("node", ["bot/fixtures/index/regenerate.mjs", "--check"], { cwd: REPO_ROOT, stdio: "pipe" });
});
await test("`sign-index.mjs --test-key` will not write into registry/", () => {
  let status = 0;
  try {
    execFileSync("node", [
      "bot/sign-index.mjs", "--test-key", TEST_INDEX_KEY,
      "--in", "registry/v1/index.json", "--out", "registry/v1/index.json",
    ], { cwd: REPO_ROOT, stdio: "pipe" });
  } catch (e) {
    status = e.status;
  }
  assert(status === 2, `exit ${status}: a catalogue that LOOKS signed and is signed with a published key is worse than an unsigned one`);
});
await test("the CI path — key from the environment, verified against trust.json — works end to end", () => {
  // The real signing route, exercised with a throwaway key: the seed arrives in
  // ASTRA_INDEX_SIGNING_KEY as base64 and never on a command line. This is the
  // only test that covers `privateKeyFromSeed`, which is the one piece of the
  // signer that production uses and the --test-key path does not.
  const key = loadTestRoot(TEST_INDEX_KEY);
  const out = path.join(tmp, "ci-index.json");
  execFileSync("node", ["bot/sign-index.mjs", "--in", "registry/v1/index.json", "--out", out], {
    cwd: REPO_ROOT,
    stdio: "pipe",
    env: {
      ...process.env,
      ASTRA_INDEX_SIGNING_KEY: key.seed.toString("base64"),
      ASTRA_INDEX_SIGNING_KEY_ID: key.key_id,
    },
  });
  const signed = JSON.parse(fs.readFileSync(out, "utf8"));
  assert(verifyEnvelope(signed, INDEX_SCHEMA, trustedIndexKeys).ok,
    "a catalogue signed through the environment did not verify");

  // And the verify subcommand CI runs after signing, against a trust.json
  // rather than against the key it just used.
  const trustFile = path.join(tmp, "trust.json");
  fs.writeFileSync(trustFile, JSON.stringify(trustFixture));
  execFileSync("node", ["bot/sign-index.mjs", "--verify", out, "--trust", trustFile], {
    cwd: REPO_ROOT, stdio: "pipe",
  });

  // The content is still exactly what the generator produces — signing adds a
  // timestamp and a signature and touches nothing else.
  execFileSync("node", ["tools/build-index.mjs", "--check", "--out", path.relative(REPO_ROOT, out)], {
    cwd: REPO_ROOT, stdio: "pipe",
  });
});
await test("`sign-index.mjs` with no key at all fails loudly rather than emitting an unsigned file", () => {
  let status = 0;
  let stderr = "";
  try {
    execFileSync("node", ["bot/sign-index.mjs", "--in", "registry/v1/index.json"], {
      cwd: REPO_ROOT, stdio: "pipe",
      env: { ...process.env, ASTRA_INDEX_SIGNING_KEY: "", ASTRA_INDEX_SIGNING_KEY_ID: "" },
    });
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr);
  }
  assert(status === 2, `exit ${status}`);
  assert(stderr.includes("ASTRA_INDEX_SIGNING_KEY"), stderr);
});

// ═══════════════════ 3.9 — the withdrawal list ═══════════════════
//
// Revocation is the only mechanism here that helps after a bad plugin is
// already on somebody's machine, so every test below asserts a REFUSAL: an
// advisory the daemon could not act on, a signature replayed across domains, a
// document signed under the wrong one. A test that proves the format parses
// proves nothing anyone cares about.

console.log("\nwithdrawal list");

function signedRevocations(keyId = TEST_INDEX_KEY, serial = 3, entries = []) {
  const k = loadTestRoot(keyId);
  return signRevocations(
    { signed: { schema: REVOCATIONS_SCHEMA, serial, revocations: entries } },
    { signer: { key_id: k.key_id, privateKey: k.privateKey }, issuedAt: FIXTURE_ISSUED_AT },
  );
}

const GOOD_ADVISORY = {
  id: "ASTRA-2026-0001",
  published: "2026-08-14",
  severity: "critical",
  action: "disable",
  reason: "Exfiltrates the clipboard to a third-party host.",
  advisory_url: "https://example.test/advisories/ASTRA-2026-0001",
  // A digest AND an id. Not decoration: a `digest` entry cannot match a
  // sideloaded source directory (no archive, so no bundle digest), so an
  // advisory that carries only digests leaves "run the same code from a folder"
  // open. `checkAdvisory` now refuses that shape, and the fixture has to be a
  // shape it accepts.
  entries: [
    { kind: "digest", value: "a".repeat(64) },
    { kind: "id", value: "dice-roller" },
  ],
};

await test("a well-formed advisory validates", () => {
  assert(checkAdvisory(GOOD_ADVISORY).length === 0, JSON.stringify(checkAdvisory(GOOD_ADVISORY)));
});
await test("a digest-only advisory is refused: it cannot see a sideloaded directory", () => {
  // The registry's default and recommended advisory shape was a `digest` entry
  // over the `.astraplugin`. `sideload_plugin` builds a subject with an id, a
  // version and the binary hashes — and NO artifact digest, because a directory
  // has no archive. So the withdrawal was fully in force and matched nothing on
  // the one route with nothing else to key on.
  const errs = checkAdvisory({ ...GOOD_ADVISORY, entries: [{ kind: "digest", value: "a".repeat(64) }] });
  assert(errs.some((e) => e.includes("SIDELOADED SOURCE DIRECTORY")), errs.join("; "));
  // `identity` and `publisher_key` do not close it either — a sideloaded
  // directory has neither.
  const weak = checkAdvisory({
    ...GOOD_ADVISORY,
    entries: [{ kind: "digest", value: "a".repeat(64) }, { kind: "identity", value: "github:o/r" }],
  });
  assert(weak.some((e) => e.includes("SIDELOADED SOURCE DIRECTORY")), weak.join("; "));
  // And each of the four that DOES cover a directory is enough.
  for (const entry of [
    { kind: "binary", value: "b".repeat(64) },
    { kind: "id", value: "dice-roller" },
    { kind: "id_version", value: "dice-roller@1.0.0" },
    { kind: "version_range", value: "dice-roller", versions: { introduced: "1.0.0", fixed: "1.2.0" } },
  ]) {
    const ok = checkAdvisory({
      ...GOOD_ADVISORY,
      entries: [{ kind: "digest", value: "a".repeat(64) }, entry],
    });
    assert(ok.length === 0, `${entry.kind} must be enough: ${ok.join("; ")}`);
  }
});
await test("a kind the daemon does not read is refused", () => {
  // The failure this catches is silent by nature: an unknown `kind` matches
  // nothing in the daemon, so the advisory publishes, the workflow is green,
  // and the withdrawal never happens.
  const errs = checkAdvisory({ ...GOOD_ADVISORY, entries: [{ kind: "author", value: "someone" }] });
  assert(errs.some((e) => e.includes("not one the daemon reads")), errs.join("; "));
});
await test("an uppercase or truncated digest is refused", () => {
  for (const value of ["A".repeat(64), "abc", "a".repeat(63)]) {
    const errs = checkAdvisory({ ...GOOD_ADVISORY, entries: [{ kind: "digest", value }] });
    assert(errs.length > 0, `${value} was accepted as a digest`);
  }
});
await test("an action the daemon does not know is refused at the source", () => {
  // The daemon reads an unknown action as `disable`, which is the safe
  // direction — but "safe" is not "intended", and a typo that silently disables
  // more than the maintainer meant is still a bad day. Caught here, where it
  // costs a rerun.
  const errs = checkAdvisory({ ...GOOD_ADVISORY, action: "quarantine" });
  assert(errs.some((e) => e.includes("action")), errs.join("; "));
});
await test("a version range whose bounds are equal covers nothing and is refused", () => {
  const errs = checkAdvisory({
    ...GOOD_ADVISORY,
    entries: [
      { kind: "version_range", value: "example", versions: { introduced: "1.0.0", fixed: "1.0.0" } },
    ],
  });
  assert(errs.some((e) => e.includes("covers nothing")), errs.join("; "));
});
await test("a versions window on a kind that has no versions is refused", () => {
  const errs = checkAdvisory({
    ...GOOD_ADVISORY,
    entries: [{ kind: "digest", value: "a".repeat(64), versions: { fixed: "1.0.0" } }],
  });
  assert(errs.some((e) => e.includes("does not take a versions window")), errs.join("; "));
});
await test("a reason carrying a bidi override is refused", () => {
  // It is shown to the user verbatim, in a notification the daemon marks
  // persistent. A withdrawal notice is the last place to allow invisible
  // reordering of the sentence.
  const errs = checkAdvisory({ ...GOOD_ADVISORY, reason: "Safe‮elbadaolnwod si" });
  assert(errs.some((e) => e.includes("bidirectional")), errs.join("; "));
});
await test("an identity value must be the spelling the daemon pins", () => {
  const ok = checkAdvisory({
    ...GOOD_ADVISORY,
    // Paired with an id, because an identity-only advisory is refused for a
    // different reason — see the sideload test above.
    entries: [{ kind: "identity", value: "github:owner/repo" }, { kind: "id", value: "dice-roller" }],
  });
  assert(ok.length === 0, ok.join("; "));
  const bad = checkAdvisory({
    ...GOOD_ADVISORY,
    entries: [{ kind: "identity", value: "https://github.com/owner/repo" }],
  });
  assert(bad.length > 0, "a URL was accepted where AuthorIdentity::revocation_key was required");
});
await test("the generator flattens an advisory into one entry per key, carrying the advisory", () => {
  const dir = path.join(tmp, "revsrc");
  fs.mkdirSync(path.join(dir, "tools/revocations"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "tools/revocations/ASTRA-2026-0001.json"),
    JSON.stringify({
      ...GOOD_ADVISORY,
      entries: [
        { kind: "digest", value: "b".repeat(64) },
        { kind: "version_range", value: "example", versions: { introduced: "1.0.0", fixed: "1.2.0" } },
      ],
    }),
  );
  const built = buildRevocations({ root: dir, serial: 4 });
  assert(built.signed.revocations.length === 2, JSON.stringify(built.signed.revocations));
  for (const entry of built.signed.revocations) {
    assert(entry.id === "ASTRA-2026-0001", "the advisory id must travel with every entry");
    assert(entry.action === "disable" && entry.severity === "critical", JSON.stringify(entry));
    assert(entry.reason.length > 0 && entry.advisory_url.startsWith("https://"), JSON.stringify(entry));
  }
  // Deterministic: same sources + same serial -> same bytes, which is what makes
  // `--check` and the CI diff mean anything.
  assert(
    stableStringify(built) === stableStringify(buildRevocations({ root: dir, serial: 4 })),
    "the withdrawal-list generator is not deterministic",
  );
  // And it reads no clock — the freshness window is stamped at signing time,
  // for the same reason the catalogue's is.
  assert(built.signed.issued_at === undefined, "the generator stamped a timestamp");
});
await test("the generator refuses to build from an invalid advisory", () => {
  const dir = path.join(tmp, "revbad");
  fs.mkdirSync(path.join(dir, "tools/revocations"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "tools/revocations/ASTRA-2026-0002.json"),
    JSON.stringify({ ...GOOD_ADVISORY, id: "ASTRA-2026-0002", entries: [{ kind: "author", value: "x" }] }),
  );
  let threw = false;
  try {
    buildRevocations({ root: dir, serial: 1 });
  } catch {
    threw = true;
  }
  assert(threw, "an advisory the daemon could not act on was built into a deployable document");
});
await test("a signed withdrawal list verifies under the key trust.json delegates to", () => {
  const doc = signedRevocations();
  const r = verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys);
  assert(r.ok, `did not verify: ${r.reason}`);
  assert(r.key_id === TEST_INDEX_KEY, `verified under ${r.key_id}`);
});
await test("a withdrawal list signed by a stranger is refused", () => {
  const doc = signedRevocations(TEST_STRANGER_KEY);
  assert(
    !verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys).ok,
    "a key trust.json does not delegate to signed a withdrawal list and it was believed",
  );
});
await test("A REVOCATION SIGNED AS AN INDEX IS REJECTED, AND THE CONVERSE", () => {
  // The acceptance criterion, and the reason REVOCATIONS_SCHEMA exists as a
  // separate constant. One key signs both documents (§5.1: "there is no
  // separate revocation role"), so the domain is the ONLY thing keeping them
  // apart. Without it, anyone who could get a single catalogue signed could
  // publish an EMPTY withdrawal list under the same signature and switch off
  // the one mechanism that helps after bad code is already installed.
  const k = loadTestRoot(TEST_INDEX_KEY);
  const payload = { schema: REVOCATIONS_SCHEMA, serial: 3, revocations: [] };
  const asIndex = signEnvelope({
    domain: INDEX_SCHEMA,
    signed: payload,
    signers: [{ key_id: k.key_id, privateKey: k.privateKey }],
  });
  assert(
    verifyEnvelope(asIndex, INDEX_SCHEMA, trustedIndexKeys).ok,
    "the fixture must be a genuine signature, or this test proves nothing",
  );
  assert(
    !verifyEnvelope(asIndex, REVOCATIONS_SCHEMA, trustedIndexKeys).ok,
    "a signature made under the catalogue's domain verified as a withdrawal list",
  );

  const asRevocations = signedRevocations();
  assert(
    !verifyEnvelope(asRevocations, INDEX_SCHEMA, trustedIndexKeys).ok,
    "a withdrawal-list signature verified as a catalogue signature",
  );
  assert(
    !verifyEnvelope(asRevocations, TRUST_SCHEMA, trustedIndexKeys).ok,
    "a withdrawal-list signature verified as a trust.json signature",
  );
});
await test("the signer refuses a document that is not a withdrawal list", () => {
  let threw = false;
  try {
    const k = loadTestRoot(TEST_INDEX_KEY);
    signRevocations(
      { signed: { schema: INDEX_SCHEMA, serial: 1 } },
      { signer: { key_id: k.key_id, privateKey: k.privateKey } },
    );
  } catch {
    threw = true;
  }
  assert(threw, "the index key signed a catalogue under the withdrawal list's domain");
});
await test("the withdrawal list's TTL is 7 days, against the catalogue's 30", () => {
  const doc = signedRevocations();
  const days = (Date.parse(doc.signed.expires_at) - Date.parse(doc.signed.issued_at)) / 86400000;
  assert(days === REVOCATION_TTL_DAYS, `${days} days, expected ${REVOCATION_TTL_DAYS}`);
  assert(
    REVOCATION_TTL_DAYS < CATALOG_TTL_DAYS,
    "the asymmetry IS the freshness policy: a stale catalogue is a banner, a stale withdrawal list is a hard block",
  );
});
await test("one byte edited after signing is refused", () => {
  const doc = signedRevocations(TEST_INDEX_KEY, 3, [
    { kind: "digest", value: "c".repeat(64), id: "ASTRA-2026-0002", action: "disable" },
  ]);
  assert(verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys).ok, "baseline");
  doc.signed.revocations[0].action = "warn";
  assert(
    !verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys).ok,
    "the action — which decides whether an installed plugin is stopped — was editable after signing",
  );
});
await test("the committed withdrawal list is a signed envelope the daemon's schema names", () => {
  const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/revocations.json"), "utf8"));
  assert(doc.signed?.schema === REVOCATIONS_SCHEMA, JSON.stringify(doc.signed?.schema));
  assert(Number.isSafeInteger(doc.signed.serial) && doc.signed.serial >= 1,
    "serial 0 is reserved for 'this daemon has never seen a list'");
  assert(Array.isArray(doc.signed.revocations), "revocations must be an array, even when empty");
});

console.log("\ncli surface");
await test("`build-index.mjs --check` exits 0 on the committed tree", () => {
  execFileSync("node", ["tools/build-index.mjs", "--check"], { cwd: REPO_ROOT, stdio: "pipe" });
});
await test("`build-revocations.mjs --check` exits 0 on the committed tree", () => {
  execFileSync("node", ["tools/build-revocations.mjs", "--check"], { cwd: REPO_ROOT, stdio: "pipe" });
});
await test("`sign-revocations.mjs` refuses to write a TEST signature into registry/", () => {
  let status = 0;
  let stderr = "";
  try {
    execFileSync(
      "node",
      ["tools/sign-revocations.mjs", "--test-key", TEST_INDEX_KEY, "--in", "registry/v1/revocations.json"],
      { cwd: REPO_ROOT, stdio: "pipe" },
    );
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr);
  }
  assert(status === 2, `exit ${status}`);
  assert(stderr.includes("refusing to write a TEST-key signature"), stderr);
});
await test("`sign-revocations.mjs` with no key at all fails loudly rather than emitting an unsigned file", () => {
  let status = 0;
  let stderr = "";
  try {
    execFileSync("node", ["tools/sign-revocations.mjs", "--in", "registry/v1/revocations.json"], {
      cwd: REPO_ROOT,
      stdio: "pipe",
      env: { ...process.env, ASTRA_INDEX_SIGNING_KEY: "", ASTRA_INDEX_SIGNING_KEY_ID: "" },
    });
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr);
  }
  assert(status === 2, `exit ${status}`);
  assert(stderr.includes("ASTRA_INDEX_SIGNING_KEY"), stderr);
});
await test("`validate.mjs` exits non-zero without --allow-staging", () => {
  let code = 0;
  try {
    execFileSync("node", ["tools/validate.mjs"], { cwd: REPO_ROOT, stdio: "pipe" });
  } catch (e) {
    code = e.status;
  }
  assert(code === 1, `exit code was ${code}, expected 1`);
});

// ── the root delegation ─────────────────────────────────────────────────────
//
// `sign-trust.mjs` is run once a year, by hand, on an offline machine, with the
// root key out of its envelope. That is the least-rehearsed command in the whole
// system and the most expensive one to get wrong: a mistake is discovered when a
// user's catalogue still reads UNSIGNED, and fixing it means another trip. So
// its guards are tested here rather than trusted.

console.log("\nroot delegation (sign-trust.mjs)");

/** Build an OpenSSL-shaped PEM for one of the published test roots. */
function testRootPem(keyId) {
  const secret = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "tools", "testkeys", `${keyId}.SECRET-TEST-KEY.json`), "utf8"),
  );
  // `privateKeyFromSeed` already knows the PKCS#8 wrapper; asking Node to
  // re-export it as PEM beats hand-rolling the base64 line wrapping, which is
  // how the first version of this produced a file OpenSSL would not decode.
  const pem = privateKeyFromSeed(Buffer.from(secret.private_key_seed, "base64")).export({
    format: "pem",
    type: "pkcs8",
  });
  const file = path.join(tmp, `${keyId}.pem`);
  fs.writeFileSync(file, pem);
  return { file, publicKey: secret.public_key, keyId: secret.key_id };
}

/**
 * A copy of the repository whose `root.json` publishes `keyId`, so the tool's
 * "is this a published root" guard can be satisfied without a real root key.
 */
function sandboxWithRoot(name, keyId, publicKey) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(path.join(dir, "registry", "v1"), { recursive: true });
  // Only the four files the tool actually loads. Copying `tools/` and `bot/`
  // wholesale drags in `bot/manifest-probe/target/`, which is a Rust build
  // directory and filled /tmp the first time this was written.
  for (const f of ["tools/sign-trust.mjs", "tools/lib/canonical.mjs", "bot/lib/sign.mjs"]) {
    fs.mkdirSync(path.join(dir, path.dirname(f)), { recursive: true });
    fs.copyFileSync(path.join(REPO_ROOT, f), path.join(dir, f));
  }
  fs.writeFileSync(
    path.join(dir, "registry", "v1", "root.json"),
    JSON.stringify({
      schema: "astra.registry.root/1",
      status: "provisioned",
      roots: [{ key_id: keyId, role: "active", algorithm: "ed25519", public_key: publicKey, signs: "trust.json" }],
    }),
  );
  return dir;
}

const TRUST_ROOT_A = testRootPem("TEST-ONLY-DO-NOT-TRUST-root-a");
const INDEX_PUB = path.join(tmp, "index-pub.json");
fs.writeFileSync(
  INDEX_PUB,
  JSON.stringify({
    key_id: "selftest-index",
    algorithm: "ed25519",
    // Any valid 32-byte key; the delegation is what is under test, not this key.
    public_key: publicKeyBase64(crypto.generateKeyPairSync("ed25519").privateKey),
  }),
);

await test("a key that is not a published root is refused, and writes nothing", () => {
  const stranger = path.join(tmp, "stranger.pem");
  fs.writeFileSync(
    stranger,
    crypto.generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }),
  );
  const out = path.join(tmp, "must-not-exist.json");
  let status = 0;
  let stderr = "";
  try {
    execFileSync(
      "node",
      ["tools/sign-trust.mjs", "--root-key", stranger, "--index-key-file", INDEX_PUB,
       "--workflow-sha", "1".repeat(40), "--out", out],
      { cwd: REPO_ROOT, stdio: "pipe" },
    );
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr);
  }
  assert(status === 1, `exit ${status}`);
  assert(stderr.includes("not one of the roots published"), stderr);
  assert(!fs.existsSync(out), "it wrote a document signed by a key no daemon trusts");
});

await test("a signed delegation round-trips through its own verifier", () => {
  const dir = sandboxWithRoot("trust-ok", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
  const out = path.join(dir, "registry", "v1", "trust.json");
  execFileSync(
    "node",
    ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file, "--index-key-file", INDEX_PUB,
     "--workflow-sha", "A".repeat(40), "--serial", "9", "--out", out],
    { cwd: dir, stdio: "pipe" },
  );
  const doc = JSON.parse(fs.readFileSync(out, "utf8"));
  assert(doc.signed.serial === 9, "serial");
  assert(doc.signed.schema === "astra.registry.trust/1", doc.signed.schema);
  // Lowercased on the way in: the bot compares it against what `gh` reports.
  assert(doc.signed.reusable_workflow_shas[0] === "a".repeat(40), "sha not normalised");
  execFileSync("node", ["tools/sign-trust.mjs", "--verify", out], { cwd: dir, stdio: "pipe" });
});

await test("a delegation to nothing is refused", () => {
  // A trust.json with no index key verifies perfectly and grants nothing, so
  // every catalogue would still read UNSIGNED — the failure that looks like
  // success, and the one an operator would not think to check for.
  const dir = sandboxWithRoot("trust-empty", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
  let status = 0;
  let stderr = "";
  try {
    execFileSync(
      "node",
      ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file, "--workflow-sha", "1".repeat(40),
       "--out", path.join(dir, "trust.json")],
      { cwd: dir, stdio: "pipe" },
    );
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr);
  }
  assert(status === 1, `exit ${status}`);
  assert(stderr.includes("no index key"), stderr);
});

await test("a movable tag cannot reach the attestation allowlist", () => {
  // The allowlist is commit SHAs precisely because a tag can be repointed, and
  // this workflow runs inside every plugin author's repository.
  const dir = sandboxWithRoot("trust-tag", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
  let status = 0;
  let stderr = "";
  try {
    execFileSync(
      "node",
      ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file, "--index-key-file", INDEX_PUB,
       "--workflow-sha", "plugin-release/v1", "--out", path.join(dir, "trust.json")],
      { cwd: dir, stdio: "pipe" },
    );
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr);
  }
  assert(status === 1, `exit ${status}`);
  assert(stderr.includes("not a 40-character commit SHA"), stderr);
});

await test("a TEST index key cannot be delegated to", () => {
  // Its private half is committed to this public repository.
  const dir = sandboxWithRoot("trust-testkey", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
  let status = 0;
  let stderr = "";
  try {
    execFileSync(
      "node",
      ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file,
       "--index-key-file", path.join(REPO_ROOT, "tools", "testkeys", "TEST-ONLY-DO-NOT-TRUST-index-2026a.pub.json"),
       "--workflow-sha", "1".repeat(40), "--out", path.join(dir, "trust.json")],
      { cwd: dir, stdio: "pipe" },
    );
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr);
  }
  assert(status === 1, `exit ${status}`);
  assert(stderr.includes("TEST key"), stderr);
});

await test("keygen-index.sh emits a 32-byte seed and the matching public key", () => {
  const dir = path.join(tmp, "idxkey");
  execFileSync("sh", ["tools/keygen-index.sh", "--id", "selftest-index-key", "--out", dir], {
    cwd: REPO_ROOT,
    stdio: "pipe",
  });
  const seed = Buffer.from(fs.readFileSync(path.join(dir, "selftest-index-key.seed.b64"), "utf8").trim(), "base64");
  assert(seed.length === 32, `seed was ${seed.length} bytes; ASTRA_INDEX_SIGNING_KEY takes 32`);
  const pub = JSON.parse(fs.readFileSync(path.join(dir, "selftest-index-key.pub.json"), "utf8"));
  // The seed in the GitHub secret and the public key in trust.json must be two
  // halves of one key, or the catalogue is signed by a key nobody delegated to.
  assert(publicKeyBase64(privateKeyFromSeed(seed)) === pub.public_key, "seed and public key disagree");
});

fs.rmSync(tmp, { recursive: true, force: true });

console.log(`\n${failures.length === 0 ? "PASS" : "FAIL"}  ${passed} passed, ${failures.length} failed`);
if (failures.length) {
  for (const f of failures) console.log(`      - ${f}`);
  process.exit(1);
}
