// The four little libraries everything else is built on: canonical JSON with
// RFC 8785's own vectors and the pinned SHA-256 the Rust verifier asserts, the
// JSON Schema subset where an unknown keyword is a hard error, ids, semver, and
// the zip reader/writer round-trip.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { stableStringify, jcs } from "../lib/canonical.mjs";
import { KNOWN, validate as validateSchema } from "../lib/jsonschema.mjs";
import { ID_PATTERN, invalidId, unsafePathComponent, foldId, unsafeDisplayText } from "../lib/ids.mjs";
import { compareSemver } from "../lib/semver.mjs";
import { readZip, readEntry } from "../lib/zip.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { makeFixtures } from "../make-fixtures.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

export async function run() {
  console.log("\ncanonical json");
  await test("keys are sorted by code unit, output ends in a newline", () => {
    // **`Z` is the repair.** Every key here used to be lowercase ASCII or `$`,
    // and over such keys a code-unit sort and a case-folding one agree.
    // Measured 2026-09-22: `sortedEntries` in tools/lib/canonical.mjs made
    // case-insensitive (lowercased keys compared first) and ALL 317 checks
    // stayed green — this one, the RFC 8785 vector below (none of its nine keys
    // carries an ASCII capital), and every `--check` that regenerates a committed
    // document, since no committed document's key order moves under folding. By code unit
    // every capital sorts before every lowercase letter — `Z` is 0x5A, `a` is
    // 0x61 — and folded, `Z` sorts after `b`.
    //
    // Code-point precision is deliberately NOT asked here, because it is asked
    // below: over ASCII the two orders are one order, and the RFC vector is the
    // fixture where UTF-16 and code-point order differ. A code-point sort and a
    // locale-aware sort were both measured on the same day: this check stayed
    // green and `RFC 8785 §3.2.3` went red for each, which is where they belong.
    const s = stableStringify({ b: 1, a: { d: 2, c: 3 }, $z: 4, Z: 5 });
    assert(s === '{\n  "$z": 4,\n  "Z": 5,\n  "a": {\n    "c": 3,\n    "d": 2\n  },\n  "b": 1\n}\n', `got ${JSON.stringify(s)}`);
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
  // ── the name this check used to carry, and why it is gone ──────────────────
  //
  // It read "the three schemas load and accept their own examples", and its
  // entire body was three `JSON.parse` calls followed by `assert(true)`. It
  // never called the validator. Measured on 2026-09-22 by a recursive walk of
  // every node of `schema/index-v1.json`, `schema/plugin-v1.json` and
  // `schema/version-v1.json`: **zero** `examples`, `example` and `default`
  // members in any of them. The second clause described something that could
  // not happen — there was no example anywhere that could be made
  // unacceptable, so the property could not be falsified, only shown absent.
  // Only deleting a file or corrupting its JSON reddened it.
  //
  // Two ways out, and the first was refused. GIVING THE SCHEMAS EXAMPLES would
  // have been inventing a subject so that a name could stay: these are
  // published contract documents, and the fixtures that matter are the
  // committed registry — `catalogue.mjs` validates `registry/v1/index.json`
  // against `index-v1.json`, `tools/validate.mjs` judges every listing against
  // `plugin-v1`/`version-v1`, and `publishers.mjs` every record against
  // `publisher-v1`. All three are REAL documents. A second, weaker corpus
  // inside the schema files would drift from them, and `validate()` ignores
  // `examples` anyway, so it would have to be walked and fed in by hand.
  //
  // So the name says what is checked, and the check was pointed at the
  // property this module's header is about that nobody was asserting.
  //
  // WHY THE CHECK ABOVE DOES NOT ALREADY HOLD IT. `validate()` throws on an
  // unknown keyword only when it VISITS the subschema carrying it, and it
  // visits one only when a document reaches that position. A keyword in a
  // branch no committed record exercises is a schema rule that is silently
  // unenforced for ever — which is `jsonschema.mjs`'s own header verbatim:
  // "worse than no validator, because it reports success". Measured rather
  // than supposed: on 2026-09-22 `schema/publisher-v1.json` carried
  // `"format": "uri"` on the domain-evidence `proof`, no publisher record uses
  // domain evidence, and the full 25-module suite was green at 317 passed / 0
  // failed. Only a static walk can see that; the run-time throw cannot, and
  // when it finally does see it it will THROW rather than report, taking
  // `tools/validate.mjs` down with it on the first domain-verified publisher.
  await test("every schema parses, and every keyword in it is one the validator implements", () => {
    // `schema/` holds one document that is not a JSON Schema. Named here with
    // its reason rather than skipped by a heuristic: a silent skip is how a
    // walk quietly stops covering things, and "has no $schema" is a property a
    // real schema can acquire by accident.
    const NOT_A_SCHEMA = {
      "contract-tokens-v1.json":
        "the compiled contract token table itself — a DATA document that lives beside the schemas because it " +
        "is versioned with them. It carries no $schema and nothing is validated against it",
    };

    // The same recursion `check()` performs in tools/lib/jsonschema.mjs, and
    // only the same positions. A key of `properties` is a PROPERTY NAME, and an
    // entry of `enum`, `const`, `required`, `examples` or `default` is a VALUE:
    // a walk that descended into either would report this registry's own
    // vocabulary — `source_commit`, `staging_listing_id`, `readme` — as
    // unimplemented keywords, which is the false alarm that would get this
    // check deleted within a week.
    const SUBSCHEMA_MAP = ["$defs", "properties", "patternProperties"];
    const SUBSCHEMA_ONE = ["additionalProperties", "propertyNames", "items", "not"];
    const SUBSCHEMA_LIST = ["prefixItems", "allOf", "anyOf", "oneOf"];

    const offences = [];
    const walk = (node, where) => {
      // `true`/`false` are legal schemas and carry no keywords.
      if (typeof node === "boolean") return;
      if (node === null || typeof node !== "object" || Array.isArray(node)) {
        offences.push(`${where}: a schema position holds ${Array.isArray(node) ? "an array" : typeof node}`);
        return;
      }
      for (const key of Object.keys(node)) {
        if (!KNOWN.has(key)) {
          offences.push(
            `${where}.${key} — tools/lib/jsonschema.mjs does not implement "${key}", so this rule is enforced ` +
            `by nothing until a document reaches it, and then validate() THROWS instead of reporting`,
          );
        }
      }
      for (const k of SUBSCHEMA_MAP) {
        if (node[k] && typeof node[k] === "object" && !Array.isArray(node[k])) {
          for (const name of Object.keys(node[k])) walk(node[k][name], `${where}.${k}.${name}`);
        }
      }
      for (const k of SUBSCHEMA_ONE) if (Object.hasOwn(node, k)) walk(node[k], `${where}.${k}`);
      for (const k of SUBSCHEMA_LIST) {
        if (Array.isArray(node[k])) node[k].forEach((sub, i) => walk(sub, `${where}.${k}[${i}]`));
      }
    };

    const files = fs.readdirSync(path.join(REPO_ROOT, "schema")).filter((f) => f.endsWith(".json")).sort();
    // The floor, for the reason every enumerating check here states one: an
    // empty directory agrees with everything, and `readdirSync` of a moved
    // `schema/` would be the quietest possible way to lose this.
    assert(files.length >= 10,
      `schema/ holds ${files.length} document(s) and held 13 on 2026-09-22; this is a directory that moved, not a ` +
      `repository with fewer schemas`);

    let walked = 0;
    for (const file of files) {
      const rel = `schema/${file}`;
      let doc;
      try {
        // The `load` half of the old name, kept — and now over every document
        // here rather than three of thirteen.
        doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, rel), "utf8"));
      } catch (e) {
        offences.push(`${rel}: is not readable JSON — ${e.message}`);
        continue;
      }
      if (doc?.$schema === undefined) {
        if (!NOT_A_SCHEMA[file]) {
          offences.push(
            `${rel}: no $schema, and it is not one of the documents declared in NOT_A_SCHEMA above. Either it is a ` +
            `schema missing its dialect, or it is a data file that has to say so here with its reason`,
          );
        }
        continue;
      }
      walked += 1;
      walk(doc, rel);
    }
    assert(walked >= 10,
      `only ${walked} of ${files.length} document(s) in schema/ were walked as schemas; the rest declared no ` +
      `$schema, which turns this check into a walk of nothing`);

    assertEqual(offences.join("\n  "), "",
      "a schema in this repository is outside the subset tools/lib/jsonschema.mjs implements. That file's own rule " +
      "is the remedy: \"If you need a keyword that is not here, implement it\" — or say the same thing with a " +
      "keyword that is here. Leaving it costs twice: the rule is enforced by nobody meanwhile, and the first " +
      "document that reaches it makes the validator throw rather than report");
  });

  console.log("\nids");
  await test("safe path components", () => {
    // Every rule `unsafePathComponent` and `invalidId` carry, each asked by an
    // input that trips THAT rule and no other, and each refusal asked for its
    // REASON. Both functions return at the first rule that fires, so an input
    // that trips two proves only the earlier one, and a bare `!== null` cannot
    // tell which rule said no.
    //
    // Measured 2026-09-22 against the eight assertions this list replaces: the
    // NFKC rule, the control-character rule, the trailing dot, the length cap,
    // the NUL rule, the ':' rule, the backslash, the single dot, the empty
    // string, a device name with an extension or in capitals, the double
    // hyphen, and a charset widened to `_` and `.` or to a trailing hyphen
    // were each broken in tools/lib/ids.mjs in turn, and each time ALL 317
    // checks stayed green —
    // `validation.mjs`'s `an id that is not a safe path component is rejected`
    // included, because `../../etc/passwd` trips a separator and a relative
    // component first. These are the rules that stand between a listed id and
    // `remove_dir_all(<plugins_dir>/<id>)` on a stranger's disk.
    const refused = (fn, s, why) => {
      const got = fn(s);
      assert(got !== null && got.includes(why),
        `${fn.name}(${JSON.stringify(s)}) should refuse because it ${why}; it said ${JSON.stringify(got)}`);
    };
    const U = unsafePathComponent;
    assertEqual(U("dice-roller"), null, "an ordinary id was refused");
    refused(U, "", "empty");
    // Over NAME_MAX (255 bytes) on every common filesystem, so this is over the
    // cap whatever the cap is; WHICH number the cap is, and that the two guards
    // and the schemas state one number, is `the id cap is one number…` below.
    refused(U, "a".repeat(256), "longer than");
    refused(U, ".", "relative path component");
    refused(U, "..", "relative path component");
    refused(U, "a/b", "path separator");
    refused(U, "a\\b", "path separator");
    refused(U, "a\0b", "NUL");
    refused(U, "a:b", "alternate-data-stream");
    refused(U, "a\u0001b", "control character");
    refused(U, "x​", "zero-width");
    // U+FB01 LATIN SMALL LIGATURE FI: no control, no zero-width, and NFKC
    // rewrites it to "fi" — so a directory named with it and one named `file`
    // are two names for what a user reads as one.
    refused(U, "ﬁle", "NFKC");
    refused(U, "dice.", "ends in a dot");
    refused(U, "dice ", "ends in a dot or space");
    refused(U, "con", "Windows device name");
    refused(U, "con.txt", "Windows device name");
    refused(U, "Con", "Windows device name");

    const I = invalidId;
    assertEqual(I("dice-roller"), null, "an ordinary id was refused");
    assertEqual(I("a1"), null, "a two-character id was refused");
    for (const [id, what] of [
      ["Dice-Roller", "a capital"], ["-lead", "a leading hyphen"], ["dice-", "a trailing hyphen"],
      ["a", "one character"], ["a_b", "an underscore"], ["a.b", "an interior dot"],
    ]) {
      assert((I(id) ?? "").includes("does not match"), `${what} passed the charset: invalidId(${JSON.stringify(id)}) = ${JSON.stringify(I(id))}`);
    }
    refused(I, "dice--roller", "double hyphen");
  });
  await test("an id is one grammar: every schema publishes ids.mjs's ID_PATTERN, and unsafePathComponent caps where it does", () => {
    // The 64-character cap is written three ways in this repository and none
    // of them imports another: `{0,62}` inside ID_PATTERN, `id.length > 64` in
    // unsafePathComponent (independent ON PURPOSE — "one of the two will one
    // day be relaxed and the other has to still be standing"), and the same
    // pattern copied into six schemas that publish it to other parties.
    // Measured 2026-09-22, before this check: each of `{0,62}` -> `{0,63}` and
    // `{0,61}` in tools/lib/ids.mjs, `> 64` -> `> 65` and `> 63`, and `{0,62}`
    // -> `{0,63}` and `{0,61}` in schema/plugin-v1.json left all 317 checks
    // green; so did widening ID_PATTERN's charset to `_` and `.`. Independent
    // guards are only worth having while they agree, and nothing said when
    // they stopped.
    //
    // The schemas are FOUND, not listed: every `pattern` anywhere under schema/
    // that has the id's shape, whatever number sits in the braces, so a copy
    // that drifted is caught and a new copy is held without anybody adding it
    // here. The floor is today's count, because a walk that finds nothing
    // passes every assertion after it.
    const ID_SHAPED = /^\^\[a-z0-9[^\]]*\]\(\?:\[a-z0-9[^\]]*\]\{0,\d+\}\[a-z0-9[^\]]*\]\)\$$/;
    const copies = [];
    const walk = (node, where) => {
      if (Array.isArray(node)) node.forEach((v, i) => walk(v, `${where}/${i}`));
      else if (node && typeof node === "object") {
        for (const [k, v] of Object.entries(node)) {
          if (k === "pattern" && typeof v === "string" && ID_SHAPED.test(v)) copies.push([where, v]);
          walk(v, `${where}/${k}`);
        }
      }
    };
    const schemaDir = path.join(REPO_ROOT, "schema");
    for (const f of fs.readdirSync(schemaDir).filter((n) => n.endsWith(".json")).sort()) {
      walk(JSON.parse(fs.readFileSync(path.join(schemaDir, f), "utf8")), `schema/${f}#`);
    }
    assert(copies.length >= 6, `found ${copies.length} id patterns under schema/; plugin, version, index, identity, decision and moderation-work each publish one`);
    const drifted = copies.filter(([, v]) => v !== ID_PATTERN).map(([w, v]) => `${w}: ${v}`);
    assertEqual(drifted.join("\n  "), "", `a schema publishes an id grammar that is not tools/lib/ids.mjs's ${ID_PATTERN}`);

    // The length unsafePathComponent stops at, against the length the pattern
    // stops at, both read by asking rather than by parsing either.
    const longestAccepted = (accepts) => {
      let longest = 0;
      for (let n = 1; n <= 1000; n++) if (accepts("a".repeat(n))) longest = n;
      return longest;
    };
    const ID_RE = new RegExp(ID_PATTERN);
    const patternCap = longestAccepted((s) => ID_RE.test(s));
    const guardCap = longestAccepted((s) => unsafePathComponent(s) === null);
    assert(patternCap > 1 && patternCap < 1000, `ID_PATTERN accepts ids up to ${patternCap} characters, which is not a cap`);
    assertEqual(guardCap, patternCap,
      "unsafePathComponent's length cap and ID_PATTERN's are different numbers, so one of the two independent guards " +
      "has already been relaxed or tightened without the other");
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
    // semver.org 2.0.0 §11.4's own example, in order, every adjacent pair both
    // ways. "Prerelease included" used to mean one pair, 1.0.0-alpha < 1.0.0, and
    // measured 2026-09-22 each of the three rules INSIDE a prerelease could be
    // broken in tools/lib/semver.mjs with all 317 checks green: numeric
    // identifiers compared as strings (beta.11 before beta.2), numeric ranked
    // above alphanumeric (alpha.beta before alpha.1), and a longer identifier
    // set ranked below a shorter one (alpha.1 before alpha). Each of those
    // orders two real releases the wrong way round, and the newest release is
    // chosen by this function.
    const chain = [
      "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
      "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
    ];
    for (let i = 0; i + 1 < chain.length; i++) {
      assertEqual(compareSemver(chain[i], chain[i + 1]), -1, `${chain[i]} must precede ${chain[i + 1]} (semver.org §11.4)`);
      assertEqual(compareSemver(chain[i + 1], chain[i]), 1, `${chain[i + 1]} must follow ${chain[i]} (semver.org §11.4)`);
    }
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
}
