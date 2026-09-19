// The four little libraries everything else is built on: canonical JSON with
// RFC 8785's own vectors and the pinned SHA-256 the Rust verifier asserts, the
// JSON Schema subset where an unknown keyword is a hard error, ids, semver, and
// the zip reader/writer round-trip.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { stableStringify, jcs } from "../lib/canonical.mjs";
import { validate as validateSchema } from "../lib/jsonschema.mjs";
import { invalidId, unsafePathComponent, foldId, unsafeDisplayText } from "../lib/ids.mjs";
import { compareSemver } from "../lib/semver.mjs";
import { readZip, readEntry } from "../lib/zip.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { makeFixtures } from "../make-fixtures.mjs";
import { test, assert, tmp } from "./harness.mjs";

/** How many tests run() reports. The runner asserts exactly this many, so
 *  adding a test here is one line of arithmetic in this file and nowhere else. */
export const TESTS = 14;

export async function run() {
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
}
