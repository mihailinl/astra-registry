#!/usr/bin/env node
// The icon and the README — the two files a plugin ships for a human to look
// at.  `node bot/tests/presentation.test.mjs`
//
// These are the only bytes in a listing that Astra renders BEFORE the user has
// agreed to anything. The consent sheet is what a user reads in order to
// decide; the icon and the README are what they read in order to reach the
// consent sheet. So the interesting tests here are not "does a picture survive
// the trip" — they are the ones about what a hostile picture and a hostile
// README are turned into on the way.
//
// Nothing touches the network.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ALLOWED_IMAGE_HOSTS,
  ICON_NAMES,
  MAX_ICON_BYTES,
  MAX_README_BYTES,
  checkIcon,
  cutToBytes,
  iconDataUri,
  pickIcon,
  rewriteReadme,
} from "../lib/assets.mjs";
import { deriveListing } from "../lib/derive.mjs";
import { stableStringify } from "../../tools/lib/canonical.mjs";
import { buildIndex } from "../../tools/build-index.mjs";
import { loadPolicy } from "../../tools/lib/sources.mjs";
import { runValidation } from "../../tools/validate.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

// ── harness ─────────────────────────────────────────────────────────────────

let passed = 0;
const failures = [];
let group = "";
function section(name) { group = name; console.log(`\n${name}`); }
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures.push({ group, name, error: e });
    console.log(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
  }
}
function assert(cond, message) { if (!cond) throw new Error(message); }
/** UTF-8 bytes, the unit the index budget is denominated in. */
function bytes(s) { return Buffer.byteLength(s, "utf8"); }
/** A high surrogate with no low one after it, or a low one with no high before. */
const UNPAIRED = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}\n  expected: ${expected}\n  actual:   ${actual}`);
}

const scratch = [];
process.on("exit", () => { for (const d of scratch) fs.rmSync(d, { recursive: true, force: true }); });
function tmp(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  scratch.push(d);
  return d;
}

const PNG = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  Buffer.from("the rest of a perfectly ordinary png"),
]);
const SVG = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><circle r="8"/></svg>');
const COMMIT = "69e05d20f5d4f4a8ae45226434f4a5e438d21da4";
const REPO = "a-stranger/dice-roller";
const at = { repo: REPO, commit: COMMIT };

// ── the icon ────────────────────────────────────────────────────────────────

section("the icon");

await test("a raster icon is preferred over an SVG when a bundle ships both", () => {
  const chosen = pickIcon([
    { name: "icon.svg", bytes: SVG },
    { name: "icon.png", bytes: PNG },
  ]);
  assertEqual(chosen.name, "icon.png",
    "a raster image has no execution semantics at all, so the common case must not rest on the SVG hardening being complete");
});

await test("every accepted format round-trips through the checker and the data: URI", () => {
  const samples = {
    "icon.png": PNG,
    "icon.webp": Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WEBPVP8 ")]),
    "icon.svg": SVG,
    "icon.jpg": Buffer.concat([Buffer.from([0xff, 0xd8, 0xff]), Buffer.from("jfif and the rest")]),
    "icon.jpeg": Buffer.concat([Buffer.from([0xff, 0xd8, 0xff]), Buffer.from("jfif and the rest")]),
    "icon.ico": Buffer.concat([Buffer.from([0x00, 0x00, 0x01, 0x00]), Buffer.from("one image, allegedly")]),
  };
  assertEqual(Object.keys(samples).length, ICON_NAMES.length,
    "a format was added to ICON_FORMATS without a sample here, so nothing tests it");
  const media = { png: "image/png", webp: "image/webp", svg: "image/svg+xml", jpg: "image/jpeg", jpeg: "image/jpeg", ico: "image/x-icon" };
  for (const [name, bytes] of Object.entries(samples)) {
    const findings = checkIcon({ name, bytes });
    assertEqual(findings.length, 0, `${name} was refused: ${findings.map((f) => f.message).join("; ")}`);
    const want = `data:${media[name.split(".")[1]]};base64,`;
    assert(iconDataUri({ name, bytes }).startsWith(want), `${name} inlined under the wrong media type`);
  }
});

await test("a name that is not an icon filename at all is refused", () => {
  assert(checkIcon({ name: "icon.gif", bytes: PNG }).length > 0,
    "an unlisted extension would be inlined with no media type to give it");
});

await test("a WebP that is only half a WebP is refused", () => {
  // `RIFF` alone is also an AVI and a WAV. The format is named at byte 8.
  const riffButNotWebp = Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("AVI LIST")]);
  assert(checkIcon({ name: "icon.webp", bytes: riffButNotWebp }).length > 0,
    "checking only the container magic accepts any RIFF file as an image");
});

await test("a bundle with no icon yields no icon rather than a placeholder", () => {
  assertEqual(pickIcon([{ name: "plugin.toml", bytes: Buffer.from("") }]), null,
    "inventing an icon would make the store lie about what the author shipped");
});

await test("a clean icon passes both formats", () => {
  assertEqual(checkIcon({ name: "icon.png", bytes: PNG }).length, 0, "the PNG is fine");
  assertEqual(checkIcon({ name: "icon.svg", bytes: SVG }).length, 0, "the SVG is fine");
});

await test("an SVG wearing a .png name is caught by its content", () => {
  const findings = checkIcon({ name: "icon.png", bytes: SVG });
  assert(findings.length > 0,
    "a file called .png but sniffed as SVG is how a script reaches a renderer that trusted the extension");
  assert(/image\/png signature/.test(findings[0].message), `unhelpful message: ${findings[0].message}`);
});

for (const [what, svg] of [
  ["a <script> element", '<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("//evil")</script></svg>'],
  ["an inline event handler", '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><circle r="1"/></svg>'],
  ["a foreignObject", '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body/></foreignObject></svg>'],
  ["an entity declaration", '<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg><text>&x;</text></svg>'],
  ["an external image reference", '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil/pixel"/></svg>'],
  ["a javascript: URL", '<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><circle r="1"/></a></svg>'],
]) {
  await test(`an SVG carrying ${what} is refused`, () => {
    const findings = checkIcon({ name: "icon.svg", bytes: Buffer.from(svg) });
    assert(findings.length > 0,
      `${what} survived. <img> gives this a secure static mode today, but that guarantee lives at the ` +
      "call site — and the call site is in another repository");
  });
}

await test("an icon is not refused for documenting the rule it obeys", () => {
  // Found by `astra-plugin new`: its scaffolded icon carries a header comment
  // saying "no <script>, no <foreignObject>", and a scanner that reads comments
  // refused it for saying so. Every freshly created plugin would have shipped
  // an icon the registry then dropped, with a message accusing the author of
  // the exact thing their file told them not to do.
  const documented = Buffer.from(
    "<!-- Keep it static: no <script>, no on* handlers, no <foreignObject>. -->\n" +
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16"/></svg>',
  );
  const findings = checkIcon({ name: "icon.svg", bytes: documented });
  assertEqual(findings.length, 0,
    `an inert comment was read as markup: ${findings.map((f) => f.message).join("; ")}`);
});

await test("a comment cannot be used to smuggle live markup either", () => {
  // The other direction of the same change: stripping comments must remove the
  // comment, not reopen the document after it.
  const sneaky = Buffer.from(
    '<svg xmlns="http://www.w3.org/2000/svg"><!-- x --><script>alert(1)</script></svg>',
  );
  assert(checkIcon({ name: "icon.svg", bytes: sneaky }).length > 0,
    "a real <script> after a comment went unnoticed");
});

await test("an oversized icon is refused", () => {
  const huge = Buffer.concat([PNG, Buffer.alloc(MAX_ICON_BYTES)]);
  const findings = checkIcon({ name: "icon.png", bytes: huge });
  assert(findings.some((f) => /over the .* cap/.test(f.message)), "the cap did not bite");
});

await test("an empty icon is refused rather than inlined as an empty data: URI", () => {
  assert(checkIcon({ name: "icon.png", bytes: Buffer.alloc(0) }).length > 0, "empty got through");
});

await test("a JPEG wearing a .png name is caught by its content too", () => {
  const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff]), Buffer.from("jfif")]);
  assert(checkIcon({ name: "icon.png", bytes: jpeg }).length > 0,
    "the media type is written from the FILENAME, so a mislabelled file is inlined as something it is not");
});

// ── the README ──────────────────────────────────────────────────────────────

section("the README");

await test("a relative image is pinned to the commit the release was built from", () => {
  const { markdown } = rewriteReadme("![a screenshot](docs/shot.png)", at);
  assertEqual(markdown.trim(),
    `![a screenshot](https://raw.githubusercontent.com/${REPO}/${COMMIT}/docs/shot.png)`,
    "a stored README is rendered far from the repository it came from, and a branch URL can change after review");
});

await test("./ and a leading / resolve the same way", () => {
  for (const form of ["./docs/shot.png", "/docs/shot.png"]) {
    const { markdown } = rewriteReadme(`![s](${form})`, at);
    assert(markdown.includes(`/${COMMIT}/docs/shot.png`), `${form} did not resolve: ${markdown}`);
  }
});

await test("a relative image that climbs out of the repository is dropped", () => {
  const { markdown } = rewriteReadme("![s](../../../etc/passwd)", at);
  assert(!markdown.includes("raw.githubusercontent"), `traversal survived: ${markdown}`);
});

await test("an image on a third-party host becomes its alt text", () => {
  const { markdown } = rewriteReadme("![build status](https://shields.io/badge.svg)", at);
  assert(!markdown.includes("shields.io"),
    "every remote image is a request from the user's machine before they have installed anything");
  assert(markdown.includes("build status"), `the alt text should survive: ${markdown}`);
});

await test("GitHub's own asset hosts are kept, because the listing already points there", () => {
  for (const host of ALLOWED_IMAGE_HOSTS) {
    const url = `https://${host}/a/b.png`;
    const { markdown } = rewriteReadme(`![s](${url})`, at);
    assert(markdown.includes(url), `${host} was dropped: ${markdown}`);
  }
});

await test("http, data: and javascript: image targets are all dropped", () => {
  for (const url of ["http://example.com/a.png", "data:image/png;base64,AAAA", "javascript:alert(1)"]) {
    const { markdown } = rewriteReadme(`![s](${url})`, at);
    assert(!markdown.includes(url), `${url} survived: ${markdown}`);
  }
});

await test("raw HTML is removed, and its text is not", () => {
  const { markdown } = rewriteReadme('<div align="center"><b>Hello</b></div>', at);
  assert(!markdown.includes("<div"), `a tag survived: ${markdown}`);
  assert(!markdown.includes("<b>"), `a tag survived: ${markdown}`);
  assert(markdown.includes("Hello"), `the prose was eaten: ${markdown}`);
});

await test("an <img> tag cannot smuggle a third-party host past the markdown rule", () => {
  const { markdown } = rewriteReadme('<img src="https://evil.example/pixel.gif">', at);
  assert(!markdown.includes("evil.example"),
    "HTML is the obvious way round a rule that only rewrites markdown image syntax");
});

await test("a fenced code block keeps its angle brackets and its example URLs", () => {
  const source = [
    "Use it like this:",
    "",
    "```html",
    '<img src="http://example.com/a.png">',
    "```",
    "",
    "```",
    "![s](../relative.png)",
    "```",
  ].join("\n");
  const { markdown } = rewriteReadme(source, at);
  assert(markdown.includes('<img src="http://example.com/a.png">'),
    `documentation is not markup: ${markdown}`);
  assert(markdown.includes("![s](../relative.png)"),
    `an example inside a fence must not be rewritten: ${markdown}`);
});

await test("an inline code span is left alone too", () => {
  const { markdown } = rewriteReadme("Set `<timeout>` to 30.", at);
  assert(markdown.includes("`<timeout>`"), `inline code was stripped: ${markdown}`);
});

await test("a comparison is not mistaken for a tag", () => {
  const { markdown } = rewriteReadme("Works when a < b and b > c.", at);
  assert(markdown.includes("a < b"), `prose was eaten: ${markdown}`);
});

await test("a reference-style image definition is pinned too", () => {
  const { markdown } = rewriteReadme("![s][shot]\n\n[shot]: docs/shot.png", at);
  assert(markdown.includes(`https://raw.githubusercontent.com/${REPO}/${COMMIT}/docs/shot.png`),
    `the reference form went unrewritten, which is the form a gallery usually uses: ${markdown}`);
});

await test("an over-long README is truncated on a line boundary, and says so", () => {
  const source = `${"a very ordinary line of prose\n".repeat(2000)}`;
  const { markdown, findings } = rewriteReadme(source, at);
  assert(bytes(markdown) <= MAX_README_BYTES, `${bytes(markdown)} bytes got through the cap`);
  assert(markdown.includes("truncated"), "a silently cut README reads as a badly written one");
  assert(findings.some((f) => /truncated/.test(f.message)), "the author is not told");
});

// The cap is a BYTE cap because the thing it bounds is a byte count: this
// markdown is inlined into one signed index that every install fetches whole.
// It used to be compared against `text.length`, which is UTF-16 code units, and
// every README in the catalogue is close enough to ASCII for the two to look
// like the same number.
await test("a README under the cap in UTF-16 units and over it in bytes is still truncated", () => {
  // 12,000 CJK characters: 12,000 code units, 36,000 bytes. The old comparison
  // let this through untouched and put 36 KB into a 16 KiB budget.
  const source = `${`${"設定".repeat(20)}\n`.repeat(300)}`;
  assert(source.length < MAX_README_BYTES, "the fixture must be UNDER the cap in code units, or it proves nothing");
  assert(bytes(source) > MAX_README_BYTES, "the fixture must be OVER the cap in bytes, or it proves nothing");
  const { markdown, findings } = rewriteReadme(source, at);
  assert(bytes(markdown) <= MAX_README_BYTES, `${bytes(markdown)} bytes got through the cap`);
  assert(findings.some((f) => /truncated/.test(f.message)), "the author is not told");
});

// The old cut was `text.slice(0, MAX - 200)` on UTF-16 units, and its fallback
// for prose with no newline in it sliced at exactly that unit — which lands
// between the halves of a surrogate pair whenever the character there is astral.
// A lone surrogate reaches the signed index as a `\udXXX` escape and serde_json
// rejects the whole catalogue.
// Every budget from 1 to 200 bytes over a string of nothing but astral
// characters, so the answer does not depend on which side of a pair one
// particular budget happens to land on.
await test("the byte cut never returns half a character, at any budget", () => {
  const astral = "🙂".repeat(50);
  const mixed = "a🙂b測".repeat(50);
  let cutsSeen = 0;
  for (const s of [astral, mixed]) {
    for (let budget = 1; budget <= 200; budget++) {
      const out = cutToBytes(s, budget);
      assert(!UNPAIRED.test(out), `budget ${budget} left half a character behind`);
      assert(bytes(out) <= budget, `budget ${budget} produced ${bytes(out)} bytes`);
      if (out.length < s.length) cutsSeen++;
    }
  }
  assert(cutsSeen > 300, `only ${cutsSeen} of 400 budgets cut anything; the fixture is too short to prove this`);
});

await test("truncating never cuts a character in half", () => {
  // NO newline anywhere: the line-boundary path is the safe one, and a fixture
  // that reaches it proves nothing. This is the fallback — `cut.length` in the
  // old code — which is where the raw cut happened. (Written with a newline in
  // it first, where the mutation that reverts `cutToBytes` to a UTF-16 slice
  // still passed.)
  const source = "🙂".repeat(20000);
  assert(!source.includes("\n"), "a newline puts this fixture back on the safe path");
  const { markdown } = rewriteReadme(source, at);
  assert(!UNPAIRED.test(markdown), "the cut left half a character behind");
  assert(!/\\u[dD][89abAB]/.test(JSON.stringify(markdown)),
    "the canonical serialisation carries a lone surrogate: serde_json refuses the catalogue, not the listing");
  assert(bytes(markdown) <= MAX_README_BYTES, `${bytes(markdown)} bytes got through the cap`);
});

await test("every rewrite is reported rather than done silently", () => {
  const { findings } = rewriteReadme("<b>x</b>\n\n![a](docs/s.png)\n\n![b](https://evil.example/p.png)", at);
  const text = findings.map((f) => f.message).join("\n");
  assert(/HTML tag/.test(text), `no note about the HTML: ${text}`);
  assert(/pinned/.test(text), `no note about the pinning: ${text}`);
  assert(/dropped/.test(text), `no note about the drop: ${text}`);
});

// ── through the derivation ──────────────────────────────────────────────────

section("through the derivation");

const policy = loadPolicy(REPO_ROOT);
const baseInput = {
  facts: {
    id: "dice-roller",
    name: "Dice Roller",
    version: "0.2.0",
    description: "Rolls dice when you ask it to.",
    author: "A Stranger",
    license: "MIT",
    capabilities: ["tools"],
  },
  manifest: { protocol: 2, permissions: {} },
  repo: REPO,
  tag: "v0.2.0",
  commit: COMMIT,
  publishedAt: "2026-08-11T00:00:00Z",
  artifacts: {},
  existingPlugin: null,
  policy,
};

await test("a bundle's icon and README reach the listing as filenames, not URLs", () => {
  const derived = deriveListing({
    ...baseInput,
    files: [
      { name: "icon.svg", bytes: SVG },
      { name: "README.md", bytes: Buffer.from("# Dice Roller\n\nRolls dice.\n") },
    ],
  });
  assertEqual(derived.plugin.icon, "icon.svg", "the icon was not recorded");
  assertEqual(derived.plugin.readme, "README.md", "the README was not recorded");
  assertEqual(derived.assets.length, 2, "the bytes were not emitted for committing");
  assert(!JSON.stringify(derived.plugin).includes("base64"),
    "a reviewer must see a picture in the diff, not a blob");
});

await test("a curator's homepage survives the next release", () => {
  // It did not, and the deletion was invisible: a maintainer adds `homepage`
  // once, the next release derives a document without it, and the field is gone
  // with nothing in the diff to explain it. Categories and keywords were
  // already carried; this was the same kind of field left out of the same list.
  const derived = deriveListing({
    ...baseInput,
    files: [],
    existingPlugin: { added_at: "2026-01-01", homepage: "https://dice.example", keywords: ["dice"] },
  });
  assertEqual(derived.plugin.homepage, "https://dice.example", "the curated homepage was dropped");
});

await test("a delisting survives the next release, and the author cannot lift it", () => {
  // Found 2026-08-22 while retiring `knice-chess`. `unlisted: true` is not a
  // curator's decoration — `bot/lib/moderation.mjs` documents `delist` as one
  // of the four moderation actions and this field is how it is spelled. It was
  // not in the carry-forward list, so the next release from the same repository
  // derived a document without it and put the plugin back in the store, in a
  // commit whose diff read as a version bump. The party who benefits from that
  // is exactly the party a delisting is about.
  const derived = deriveListing({
    ...baseInput,
    files: [],
    existingPlugin: { added_at: "2026-01-01", unlisted: true },
  });
  assertEqual(derived.plugin.unlisted, true, "a release un-retired a delisted plugin");

  // And no manifest field may reach it. The bundle is written by the author, so
  // if `unlisted` could be set OR cleared from `facts`, the delisting would be
  // theirs to revoke.
  const claimed = deriveListing({
    ...baseInput,
    facts: { ...baseInput.facts, unlisted: false },
    files: [],
    existingPlugin: { added_at: "2026-01-01", unlisted: true },
  });
  assertEqual(claimed.plugin.unlisted, true, "the manifest overrode a delisting");

  // A plugin nobody delisted must not gain the field, or every listing ships a
  // `false` that reads as a decision somebody took.
  const ordinary = deriveListing({ ...baseInput, files: [], existingPlugin: { added_at: "2026-01-01" } });
  assertEqual(ordinary.plugin.unlisted, undefined, "an ordinary listing was marked");
});

await test("the author's own homepage beats the curator's", () => {
  const derived = deriveListing({
    ...baseInput,
    facts: { ...baseInput.facts, homepage: "https://from-the-manifest.example" },
    files: [],
    existingPlugin: { added_at: "2026-01-01", homepage: "https://stale.example" },
  });
  assertEqual(derived.plugin.homepage, "https://from-the-manifest.example",
    "a manifest that states a homepage must not be overridden by an older listing");
});

await test("a bundle with neither leaves both fields absent", () => {
  const derived = deriveListing({ ...baseInput, files: [{ name: "plugin.toml", bytes: Buffer.from("") }] });
  assertEqual(derived.plugin.icon, undefined, "an icon was invented");
  assertEqual(derived.plugin.readme, undefined, "a README was invented");
  assertEqual(derived.assets.length, 0, "assets were invented");
});

await test("a hostile icon costs the author their icon, not their release", () => {
  const derived = deriveListing({
    ...baseInput,
    files: [{ name: "icon.svg", bytes: Buffer.from('<svg onload="alert(1)"><circle r="1"/></svg>') }],
  });
  assertEqual(derived.plugin.icon, undefined, "the icon was carried anyway");
  assert(!derived.findings.some((f) => f.level === "error"),
    "a decorative file must never be a gate on shipping software");
  assert(derived.findings.some((f) => f.level === "warn" && f.code === "W_ICON_DROPPED"),
    "and the author has to be told why their icon vanished");
});

await test("the README the derivation emits is the rewritten one, not the author's", () => {
  const derived = deriveListing({
    ...baseInput,
    files: [{ name: "README.md", bytes: Buffer.from('<b>hi</b>\n\n![s](docs/shot.png)\n') }],
  });
  const written = derived.assets.find((a) => a.path === "README.md").bytes.toString("utf8");
  assert(!written.includes("<b>"), `raw HTML was committed: ${written}`);
  assert(written.includes(COMMIT), `the image was committed unpinned: ${written}`);
});

// ── the summary, and the character it used to cut in half ───────────────────
//
// `summarise` trims plugin.description to policy.limits.max_summary_length. It
// did so with `String.prototype.slice`, which counts UTF-16 code units, so the
// cut could land between the two halves of a surrogate pair. What comes out is
// a lone surrogate; `tools/lib/canonical.mjs` writes it with plain
// `JSON.stringify` as `\udXXX`; `serde_json` refuses that escape — and it is
// refusing the whole catalogue, not the listing that caused it.
//
// It has never fired, because an English description that reaches 200 units has
// long since run out of things to say. A Chinese or Russian one reaches it in
// two sentences, which is what makes this worth fixing before any listing
// carries either.

await test("a description whose cut lands mid-emoji does not produce half a character", () => {
  const cap = policy.limits.max_summary_length;   // 200
  // No spaces anywhere: Chinese prose does not have them, and it is the
  // no-space path that used to slice at a raw unit offset. The emoji sits so
  // that the old cut (`slice(0, cap - 1)`, units) fell between its halves.
  const description = `${"設".repeat(cap - 2)}🙂${"定".repeat(20)}`;
  assert([...description].length > cap, "the fixture must be over the cap, or nothing is cut");
  const derived = deriveListing({ ...baseInput, facts: { ...baseInput.facts, description } });
  const summary = derived.plugin.summary;
  assert(!UNPAIRED.test(summary), `the summary carries half a character: ${JSON.stringify(summary)}`);
  assert([...summary].length <= cap,
    `${[...summary].length} code points, over the ${cap} checkMetadata measures with`);
  assert(!derived.findings.some((f) => f.code === "E_METADATA_UNSAFE_TEXT"),
    "an honest Chinese description was refused");
});

// The other half of the same unit confusion, and the one that costs an author
// text rather than costing everyone the catalogue: `summarise` decided whether
// to cut at all by counting code units, while `checkMetadata` decides whether
// the result is too long by counting code points. A description of 150 emoji is
// 150 code points and 300 units — inside the cap by the rule that judges it,
// over the cap by the rule that cut it.
await test("a description inside the cap in code points is not truncated for being long in code units", () => {
  const cap = policy.limits.max_summary_length;   // 200
  const description = "🎲".repeat(150);
  assert([...description].length <= cap, "the fixture must be INSIDE the cap in code points");
  assert(description.length > cap, "the fixture must be OVER the cap in code units, or it proves nothing");
  const derived = deriveListing({ ...baseInput, facts: { ...baseInput.facts, description } });
  assertEqual(derived.plugin.summary, description,
    "a description the length rule would have accepted whole was cut anyway");
  assert(!derived.plugin.summary.endsWith("…"), "an ellipsis was added to a summary that fits");
});

await test("the catalogue serialisation of that listing carries no lone-surrogate escape", () => {
  const cap = policy.limits.max_summary_length;
  const description = `${"設".repeat(cap - 2)}🙂${"定".repeat(20)}`;
  const derived = deriveListing({ ...baseInput, facts: { ...baseInput.facts, description } });
  const json = stableStringify(derived.plugin);
  assert(!/\\u[dD][89abAB]/.test(json),
    `serde_json refuses this document, and with it every other listing in the index:\n${json}`);
  // Not vacuous: the emoji really is in there, as a whole character.
  assert(JSON.parse(json).description.includes("🙂"), "the fixture lost its emoji before the assertion could see it");
});

await test("a lone surrogate in hand-written metadata is refused outright", () => {
  const derived = deriveListing({
    ...baseInput,
    facts: { ...baseInput.facts, name: `Dice \ud83c` },
  });
  assert(derived.findings.some((f) => f.code === "E_METADATA_UNSAFE_TEXT" && /surrogate/.test(f.message)),
    `half a character reached the catalogue: ${JSON.stringify(derived.findings)}`);
});

// ── and past the repository's own validator ─────────────────────────────────

section("and past the repository's own validator");

/**
 * A minimal registry tree with one listing, so validate.mjs has something to
 * read. Pass an existing `root` and a second `id` to put another listing beside
 * the first — which is how the generator gets asked whether it reports one
 * broken listing or all of them.
 */
function treeWith(files, doc = {}, { root = tmp("astra-presentation-"), id = "dice-roller" } = {}) {
  const dir = path.join(root, "plugins", id);
  fs.mkdirSync(path.join(dir, "versions"), { recursive: true });
  fs.writeFileSync(path.join(dir, "plugin.json"), `${JSON.stringify({
    schema: "astra.registry.plugin/1",
    id,
    name: "Dice Roller",
    summary: "Rolls dice when you ask it to.",
    license: "MIT",
    source: { kind: "github", repo: REPO },
    added_at: "2026-08-11",
    ...doc,
  }, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "versions", "0.2.0.json"), `${JSON.stringify({
    schema: "astra.registry.version/1",
    id,
    version: "0.2.0",
    published_at: "2026-08-11T00:00:00Z",
    release: { kind: "github_release", repo: REPO, tag: "v0.2.0" },
    artifacts: {
      "linux-x64": {
        url: `https://github.com/${REPO}/releases/download/v0.2.0/dice-roller-0.2.0-linux-x64.astraplugin`,
        filename: "dice-roller-0.2.0-linux-x64.astraplugin",
        sha256: "0".repeat(64),
        size: 1024,
      },
    },
  }, null, 2)}\n`);
  for (const [name, bytes] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), bytes);
  return root;
}

const errorsFor = async (root) => {
  const { report } = await runValidation({
    root, allowStaging: true, allowDirect: false, online: false, artifactsDir: null, index: false,
  });
  return report.items.filter((i) => i.level === "error");
};

await test("a listing naming an icon it did not commit is an error", async () => {
  const errors = await errorsFor(treeWith({}, { icon: "icon.png" }));
  assert(errors.some((e) => /not in plugins\//.test(e.message)),
    `a dangling icon reference has to fail the build, or the index generator throws instead: ${JSON.stringify(errors)}`);
});

await test("a hand-dropped hostile icon does not get in behind the bot's back", async () => {
  const root = treeWith({ "icon.svg": '<svg onload="alert(1)"><circle r="1"/></svg>' }, { icon: "icon.svg" });
  const errors = await errorsFor(root);
  assert(errors.some((e) => /event handler/.test(e.message)),
    "the bot sanitises what IT derives; a maintainer editing the tree directly must meet the same rule");
});

await test("a hand-dropped README with a third-party image is an error", async () => {
  const root = treeWith({ "README.md": "![b](https://evil.example/pixel.png)\n" }, { readme: "README.md" });
  const errors = await errorsFor(root);
  assert(errors.some((e) => /evil\.example/.test(e.message)), `the host check did not run: ${JSON.stringify(errors)}`);
});

await test("a hand-dropped README with a relative image is an error", async () => {
  const root = treeWith({ "README.md": "![s](docs/shot.png)\n" }, { readme: "README.md" });
  const errors = await errorsFor(root);
  assert(errors.some((e) => /relative path/.test(e.message)),
    "nothing resolves a relative path at render time, so it would simply be a broken picture");
});

await test("a clean icon and README pass", async () => {
  const root = treeWith(
    {
      "icon.svg": SVG,
      "README.md": `# Dice Roller\n\n![s](https://raw.githubusercontent.com/${REPO}/${COMMIT}/docs/shot.png)\n`,
    },
    { icon: "icon.svg", readme: "README.md" },
  );
  const errors = await errorsFor(root);
  assertEqual(errors.length, 0, `an honest listing was refused: ${JSON.stringify(errors, null, 2)}`);
});

await test("an over-long README is refused rather than silently cut by the generator", async () => {
  const root = treeWith({ "README.md": "x\n".repeat(MAX_README_BYTES) }, { readme: "README.md" });
  const errors = await errorsFor(root);
  assert(errors.some((e) => /over the/.test(e.message)), "the cap is not enforced on a hand-written listing");
});

await test("a hand-written README that is over the cap only in bytes is refused too", async () => {
  const readme = `${`${"設定".repeat(20)}\n`.repeat(300)}`;
  assert(readme.length < MAX_README_BYTES && bytes(readme) > MAX_README_BYTES,
    "the fixture must be under in code units and over in bytes, or it proves nothing");
  const root = treeWith({ "README.md": readme }, { readme: "README.md" });
  const errors = await errorsFor(root);
  assert(errors.some((e) => /over the/.test(e.message)),
    "the tree validator measured code units, so a 36 KB Chinese README read as 12 KB");
});

// ── and past the index generator ────────────────────────────────────────────
//
// The generator is the last reader of the cap and the only one whose failure is
// the catalogue not existing. It used to `throw` out of the middle of its entry
// loop on the first listing it could not render, so a tree with three bad
// listings took three runs to diagnose and each run named one file.
//
// It still fails — it must. A listing quietly dropped from a signed catalogue is
// a plugin that disappears from every user's store with nothing red anywhere.
// What changed is that it says everything it knows before it does.

section("and past the index generator");

const overCapReadme = `${`${"設定".repeat(20)}\n`.repeat(300)}`;

await test("a two-listing tree builds", () => {
  const root = treeWith({ "README.md": "# fine\n" }, { readme: "README.md" });
  treeWith({ "README.md": "# also fine\n" }, { readme: "README.md" }, { root, id: "text-utils" });
  const doc = buildIndex({ root, serial: 1 });
  assertEqual(doc.signed.plugins.length, 2, "the fixture the next test mutates does not build clean");
});

await test("the built entry CARRIES the localized card, in the index's own vocabulary", () => {
  // Omission here is silent — `i18n` is optional, so an entry without it
  // validates cleanly, exactly as `homepage` and `unlisted` did before it — so
  // this asserts what the generator PUTS IN rather than what the schema
  // tolerates. A test that only validated would pass for a catalogue in which
  // localization had quietly stopped happening.
  const root = treeWith({}, { i18n: { ru: { name: "Бросок костей", summary: "Бросает кости." } } });
  const entry = buildIndex({ root, serial: 1 }).signed.plugins[0];
  assertEqual(entry.i18n.ru.name, "Бросок костей", "the locale block did not reach the index");
  assertEqual(entry.i18n.ru.description, "Бросает кости.",
    "`summary` in plugin.json is `description` in the index, and one function does that rename for the flat " +
    "fields and for every locale block — two copies of it is how a 4000-character body ends up under the " +
    "card line's name");
  assertEqual(entry.i18n.ru.summary, undefined, "the source document's spelling must not survive into the index");
  assertEqual(entry.description, "Rolls dice when you ask it to.", "and the flat English is untouched");
  assertEqual(entry.i18n.en, undefined, "`en` is the flat pair, and is never a key here");
});

await test("`details` is gone from every entry the generator writes", () => {
  // 742 bytes across ten listings, byte-identical to `description` in all of
  // them, dropped by serde in every daemon that ever fetched it — and rendered
  // by this repository's own store site as a second paragraph saying the same
  // sentence twice. Deleting it also took a 4,000-character free-text field out
  // of the site's search haystack, which is the one place a "translation" could
  // have been used as a ranking lever against a reviewer reading English.
  const root = treeWith({}, { description: "The long body a listing may carry." });
  const entry = buildIndex({ root, serial: 1 }).signed.plugins[0];
  assertEqual(entry.details, undefined, "the field is back, and nothing deserialises it");
  assert(!JSON.stringify(entry).includes("The long body"),
    "the body reached the index under some other name, which is the same bytes with a new story");
});

await test("an over-cap README fails the build naming every listing, not the first", () => {
  const root = treeWith({ "README.md": overCapReadme }, { readme: "README.md" });
  treeWith({ "README.md": overCapReadme }, { readme: "README.md" }, { root, id: "text-utils" });
  let message = null;
  try {
    buildIndex({ root, serial: 1 });
  } catch (e) {
    message = e.message;
  }
  assert(message !== null, "36 KB of Chinese went into a 16 KiB budget and the generator said nothing");
  assert(/dice-roller\/README\.md/.test(message), `the first offender is unnamed:\n${message}`);
  assert(/text-utils\/README\.md/.test(message),
    `the generator stopped at the first offender, so the second one costs another run:\n${message}`);
  assert(/16384/.test(message), `the cap the reader has to satisfy is not in the message:\n${message}`);
});

await test("a listing naming a README that is not there fails the build rather than shipping without it", () => {
  const root = treeWith({}, { readme: "README.md" });
  let message = null;
  try {
    buildIndex({ root, serial: 1 });
  } catch (e) {
    message = e.message;
  }
  assert(message !== null && /README\.md/.test(message ?? ""),
    `a missing README became an entry with no readme at all: ${message}`);
});

// ── result ──────────────────────────────────────────────────────────────────

console.log();
if (failures.length) {
  console.log(`FAIL  ${passed} passed, ${failures.length} failed`);
  process.exit(1);
}
console.log(`PASS  ${passed} passed, 0 failed`);
