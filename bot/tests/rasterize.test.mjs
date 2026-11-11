#!/usr/bin/env node
// The signed index carries raster icons only.  `node bot/tests/rasterize.test.mjs`
//
// An SVG icon is drawn to a PNG by `bot/lib/rasterize.mjs` before it is inlined,
// an ICO is refused, and the PNG's bytes are the same on every machine because
// the index is signed and the selftests compare bytes. Nothing touches the
// network.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ICON_FORMAT_MESSAGE, checkIcon } from "../lib/assets.mjs";
import { deriveListing } from "../lib/derive.mjs";
import { ICON_RASTER_PX, RasterError, rasterizeSvg } from "../lib/rasterize.mjs";
import { RASTER_ICONS_FROM_SERIAL, buildIndex } from "../../tools/build-index.mjs";
import { loadPolicy } from "../../tools/lib/sources.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures.push(name);
    console.log(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
  }
}
function assert(cond, message) { if (!cond) throw new Error(message); }
function assertEqual(a, b, message) { if (a !== b) throw new Error(`${message}\n  expected: ${b}\n  actual:   ${a}`); }
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

/** A flat icon: a gradient, a rounded square, a path. Fixed forever, because the digest below is of what it draws. */
const FIXTURE_SVG = Buffer.from(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">' +
  '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3b82f6"/>' +
  '<stop offset="1" stop-color="#9333ea"/></linearGradient></defs>' +
  '<rect x="4" y="4" width="56" height="56" rx="12" fill="url(#g)"/>' +
  '<path d="M20 34 L28 42 L45 22" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>' +
  "</svg>",
);

/**
 * sha256 of the PNG the fixture draws. The encoder is inside the pinned wasm module and never calls the
 * system zlib (zlib-ng on one machine and stock zlib on another encode the same pixels to different
 * bytes), so this digest is the same on every machine; if it moves, the pin or the encoder moved.
 */
const GOLDEN_SHA256 = "5a1c49a2e21e4bff128abf1176089c3c3f8b513a3afdb8dffeed3b9477017fb9";

function pngSize(png) { return [png.readUInt32BE(16), png.readUInt32BE(20)]; }

console.log("\nthe rasterizer");

await test("a fixture SVG draws to a PNG whose sha256 is pinned", () => {
  const png = rasterizeSvg(FIXTURE_SVG);
  assert(png.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])), "not a PNG");
  assertEqual(sha256(png), GOLDEN_SHA256, "the PNG the fixture draws changed");
});

await test("the same SVG draws to the same bytes every time", () => {
  assertEqual(sha256(rasterizeSvg(FIXTURE_SVG)), sha256(rasterizeSvg(FIXTURE_SVG)), "two draws differ");
});

await test("the long side is ICON_RASTER_PX, whatever shape the SVG is", () => {
  const wide = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="200" height="50"><rect width="200" height="50" fill="red"/></svg>');
  const tall = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="50" height="200"><rect width="50" height="200" fill="red"/></svg>');
  assertEqual(pngSize(rasterizeSvg(wide)).join("x"), `${ICON_RASTER_PX}x${ICON_RASTER_PX / 4}`, "wide");
  assertEqual(pngSize(rasterizeSvg(tall)).join("x"), `${ICON_RASTER_PX / 4}x${ICON_RASTER_PX}`, "tall");
  assertEqual(pngSize(rasterizeSvg(FIXTURE_SVG)).join("x"), `${ICON_RASTER_PX}x${ICON_RASTER_PX}`, "square");
});

await test("a <script>, an event handler and an external href take no part: the pixels are those of the plain picture", () => {
  const plain = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="32" height="32"><rect width="32" height="32" fill="#0a0"/></svg>');
  const hostile = Buffer.from(
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="32" height="32" onload="alert(1)">' +
    '<script>fetch("https://example.invalid/x")</script>' +
    '<image href="https://example.invalid/pixel.png" width="32" height="32"/>' +
    '<use xlink:href="https://example.invalid/a.svg#b"/>' +
    '<rect width="32" height="32" fill="#0a0" onclick="alert(2)"/></svg>',
  );
  assertEqual(sha256(rasterizeSvg(hostile)), sha256(rasterizeSvg(plain)), "something in the hostile SVG reached the picture");
});

await test("an SVG with text is refused, not drawn without it", () => {
  const withText = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><text x="2" y="20">Hi</text></svg>');
  try { rasterizeSvg(withText); } catch (e) {
    assert(e instanceof RasterError && e.code === "E_SVG_TEXT", `wrong refusal: ${e}`);
    return;
  }
  throw new Error("text was drawn, or silently dropped");
});

await test("an SVG that does not parse is a RasterError, never a thrown anything-else or an empty PNG", () => {
  for (const bad of ["", "not xml", "<svg"]) {
    try { rasterizeSvg(Buffer.from(bad)); } catch (e) {
      assert(e instanceof RasterError && e.code === "E_SVG_RASTERIZE", `${JSON.stringify(bad)}: wrong refusal: ${e}`);
      continue;
    }
    throw new Error(`${JSON.stringify(bad)} was drawn`);
  }
});

console.log("\nICO and SVG at publish");

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
  repo: "someone/dice-roller",
  tag: "v0.2.0",
  commit: "a".repeat(40),
  publishedAt: "2026-08-11T00:00:00Z",
  artifacts: {},
  existingPlugin: null,
  policy,
};
const ICO = Buffer.concat([Buffer.from([0x00, 0x00, 0x01, 0x00]), Buffer.from("one image, allegedly")]);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from("rest")]);

await test("an ICO is refused with the one plain sentence (the bot's messages are English only)", () => {
  assertEqual(ICON_FORMAT_MESSAGE, "the icon must be PNG, JPEG, WebP or SVG", "the sentence changed");
  const checked = checkIcon({ name: "icon.ico", bytes: ICO });
  assert(checked.some((f) => f.message.includes(ICON_FORMAT_MESSAGE)), `checkIcon: ${JSON.stringify(checked)}`);
  const derived = deriveListing({ ...baseInput, files: [{ name: "icon.ico", bytes: ICO }] });
  const f = derived.findings.find((x) => x.code === "E_ICON_FORMAT");
  assert(f && f.level === "error" && f.message.includes(ICON_FORMAT_MESSAGE), `derive: ${JSON.stringify(derived.findings)}`);
  assertEqual(derived.plugin.icon, undefined, "an ICO reached the listing");
});

await test("an ICO beside a supported icon is not the icon, so it is not an error", () => {
  const derived = deriveListing({ ...baseInput, files: [{ name: "icon.ico", bytes: ICO }, { name: "icon.png", bytes: PNG }] });
  assert(!derived.findings.some((x) => x.code === "E_ICON_FORMAT"), "refused for a file nothing would use");
  assertEqual(derived.plugin.icon, "icon.png", "the PNG was not chosen");
});

await test("an SVG that cannot be drawn refuses the release; one with text names its code", () => {
  const broken = deriveListing({ ...baseInput, files: [{ name: "icon.svg", bytes: Buffer.from("<svg><<<") }] });
  assert(broken.findings.some((x) => x.level === "error" && x.code === "E_SVG_RASTERIZE"), JSON.stringify(broken.findings));
  const text = deriveListing({ ...baseInput, files: [{ name: "icon.svg", bytes: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><text>x</text></svg>') }] });
  assert(text.findings.some((x) => x.level === "error" && x.code === "E_SVG_TEXT"), JSON.stringify(text.findings));
  const fine = deriveListing({ ...baseInput, files: [{ name: "icon.svg", bytes: FIXTURE_SVG }] });
  assert(!fine.findings.some((x) => x.level === "error"), JSON.stringify(fine.findings));
  assertEqual(fine.plugin.icon, "icon.svg", "a drawable SVG was not recorded");
});

console.log("\nthe index");

await test("from RASTER_ICONS_FROM_SERIAL no icon in the index is an SVG, and below it nothing moved", () => {
  const mediaOf = (idx) => idx.signed.plugins.filter((p) => p.icon_url).map((p) => /^data:([^;]+);/.exec(p.icon_url)[1]);
  const at = buildIndex({ root: REPO_ROOT, serial: RASTER_ICONS_FROM_SERIAL });
  const media = mediaOf(at);
  assert(media.length >= 20, `only ${media.length} icons examined`);
  assert(media.every((m) => m === "image/png" || m === "image/webp" || m === "image/jpeg"), `a non-raster icon: ${[...new Set(media)]}`);
  const below = mediaOf(buildIndex({ root: REPO_ROOT, serial: RASTER_ICONS_FROM_SERIAL - 1 }));
  assert(below.includes("image/svg+xml"), "the gate does not hold: nothing below it is SVG any more, so the catalogue moved at an unchanged serial");
});

await test("a committed SVG that cannot be drawn fails the build naming its listing", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "raster-"));
  try {
    fs.cpSync(path.join(REPO_ROOT, "plugins"), path.join(root, "plugins"), { recursive: true });
    for (const d of ["policy", "publishers", "schema"]) if (fs.existsSync(path.join(REPO_ROOT, d))) fs.cpSync(path.join(REPO_ROOT, d), path.join(root, d), { recursive: true });
    fs.writeFileSync(path.join(root, "plugins/dice-roller/icon.svg"), "<svg><<<");
    let threw = null;
    try { buildIndex({ root, serial: RASTER_ICONS_FROM_SERIAL }); } catch (e) { threw = e; }
    assert(threw && /dice-roller\/icon\.svg/.test(String(threw.message ?? threw)) && /E_SVG_RASTERIZE/.test(String(threw.message ?? threw)),
      `the build did not name the listing: ${threw?.message ?? "it did not fail"}`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

console.log(failures.length ? `\nFAIL  ${passed} passed, ${failures.length} failed` : `\nok    ${passed} passed`);
process.exit(failures.length ? 1 : 0);
