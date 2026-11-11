#!/usr/bin/env node
// A listing's icon and README as content-addressed files beside the index (contract 6.28.0).
// `node bot/tests/asset-files.test.mjs`
//
// build-index names them (`icon`, `readme_file`) from serial ASSET_FILES_FROM_SERIAL on; the signer
// writes exactly the referenced files into the `signed` commit (BOT-109); the regeneration compares the
// derived set with a candidate's (TRUST-49). The sha256 here is integrity of a file, nothing more.

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ASSET_FILES_FROM_SERIAL, buildAssets, buildIndex, buildIndexAndAssets } from "../../tools/build-index.mjs";
import { assetProblems } from "../../tools/regenerate-signed.mjs";
import { validate as validateSchema } from "../../tools/lib/jsonschema.mjs";
import { cleanEnv } from "../../tools/lib/git-env.mjs";
import { collectAssets, referencedAssets } from "../../tools/signer/assets.mjs";
import { buildSignedCommit } from "../../tools/signer/run.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
let passed = 0;
const failures = [];
async function test(name, fn) {
  try { await fn(); passed++; console.log(`  ok    ${name}`); } catch (e) {
    failures.push(name); console.log(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
  }
}
function assert(c, m) { if (!c) throw new Error(m); }
function assertEqual(a, b, m) { if (a !== b) throw new Error(`${m}\n  expected: ${b}\n  actual:   ${a}`); }
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const dirs = [];
process.on("exit", () => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });
const tmp = (p) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), p)); dirs.push(d); return d; };

const GATE = ASSET_FILES_FROM_SERIAL;
const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
const at = buildIndexAndAssets({ root: REPO_ROOT, serial: GATE });
const entries = at.doc.signed.plugins;

console.log("\nbuild-index");

await test("below the gate no listing carries the pair and no asset is derived", () => {
  const below = buildIndexAndAssets({ root: REPO_ROOT, serial: GATE - 1 });
  assert(below.doc.signed.plugins.every((p) => p.icon === undefined && p.readme_file === undefined), "a member below the gate");
  assertEqual(below.assets.size, 0, "assets below the gate");
});

await test("from the gate each member names the exact bytes inlined, and inline stays", () => {
  let icons = 0, readmes = 0;
  for (const p of entries) {
    if (p.icon) {
      icons++;
      const inline = Buffer.from(p.icon_url.split(",", 2)[1], "base64");
      const bytes = at.assets.get(p.icon.path);
      assert(bytes && bytes.equals(inline), `${p.id}: the file is not the inlined icon`);
      assertEqual(p.icon.sha256, sha(inline), `${p.id}: sha256`);
      assertEqual(p.icon.size, inline.length, `${p.id}: size`);
      assertEqual(p.icon.path, `assets/${p.icon.sha256}.${{ "image/png": "png", "image/webp": "webp", "image/jpeg": "jpg" }[p.icon.media_type]}`, `${p.id}: path`);
      assert(p.icon_url.startsWith(`data:${p.icon.media_type};base64,`), `${p.id}: media_type is not the inline one`);
    } else assertEqual(p.icon_url, "", `${p.id}: an inline icon with no pair`);
    if (p.readme_file) {
      readmes++;
      assert(at.assets.get(p.readme_file.path).equals(Buffer.from(p.readme, "utf8")), `${p.id}: the file is not the inlined README`);
      assertEqual(p.readme_file.path, `assets/${p.readme_file.sha256}.md`, `${p.id}: path`);
    } else assertEqual(p.readme, undefined, `${p.id}: an inline README with no pair`);
  }
  assert(icons >= 30 && readmes >= 10, `only ${icons} icons and ${readmes} READMEs examined`);
});

await test("the derived set is exactly the referenced set, one file per path, and the rest of the index is unchanged", () => {
  const { refs, problems } = referencedAssets(at.doc);
  assertEqual(problems.length, 0, problems.join("; "));
  assertEqual([...refs.keys()].sort().join("\n"), [...at.assets.keys()].sort().join("\n"), "derived and referenced sets differ");
  assert(at.assets.size <= entries.filter((p) => p.icon).length + entries.filter((p) => p.readme_file).length, "a file nobody names was derived");
  // Inline is untouched: the same listing minus the pair is the listing below the gate (both are drawn at the gate).
  const strip = (d) => JSON.stringify(d.signed.plugins.map(({ icon, readme_file, ...rest }) => rest));
  assertEqual(strip(at.doc), strip(buildIndex({ root: REPO_ROOT, serial: GATE })), "stripping the pair is not the inline-only catalogue");
});

await test("the index at the gate validates against the schema, and the schema refuses a bad pair", () => {
  assertEqual(validateSchema(schema, at.doc).length, 0, "the catalogue at the gate does not validate");
  const p = structuredClone(at.doc);
  const e = p.signed.plugins.find((x) => x.icon && x.readme_file);
  const refused = (mutate, what) => {
    const q = structuredClone(p); mutate(q.signed.plugins.find((x) => x.id === e.id));
    assert(validateSchema(schema, q).length > 0, `the schema accepted ${what}`);
  };
  refused((x) => { x.icon.path = "https://example.invalid/a.png"; }, "an absolute icon path");
  refused((x) => { x.icon.path = x.icon.path.replace("assets/", "../assets/"); }, "a path with ..");
  refused((x) => { x.icon.path = x.icon.path.replace(/\.\w+$/, ".md"); }, "an icon path ending .md");
  refused((x) => { x.readme_file.path = x.readme_file.path.replace(/\.md$/, ".png"); }, "a README path ending .png");
  refused((x) => { x.icon.size = 131073; }, "an icon over 131072");
  refused((x) => { x.readme_file.size = 16385; }, "a README over 16384");
  refused((x) => { x.icon.media_type = "image/svg+xml"; }, "an svg media type");
  refused((x) => { x.icon.extra = 1; }, "an extra member");
});

console.log("\nthe signer (BOT-109)");

await test("collectAssets returns exactly the referenced files, byte for byte", () => {
  const got = collectAssets({ root: REPO_ROOT, indexDoc: at.doc, headRef: null });
  assertEqual(got.problems.length, 0, got.problems.join("; "));
  assertEqual([...got.assets.keys()].sort().join("\n"), [...at.assets.keys()].sort().join("\n"), "set");
});

await test("a catalogue naming a file nobody can supply, or supplied with other bytes, is a problem", () => {
  const doc = structuredClone(at.doc);
  const e = doc.signed.plugins.find((x) => x.icon);
  const ghost = "f".repeat(64);
  e.icon = { ...e.icon, path: `assets/${ghost}.png`, sha256: ghost };
  const got = collectAssets({ root: REPO_ROOT, indexDoc: doc, headRef: null });
  assert(got.problems.some((x) => x.includes(`assets/${ghost}.png`)), got.problems.join("; "));
  const bad = structuredClone(at.doc);
  bad.signed.plugins.find((x) => x.icon).icon.size += 1;
  assert(collectAssets({ root: REPO_ROOT, indexDoc: bad, headRef: null }).problems.length > 0, "a wrong size passed");
  const noncanon = structuredClone(at.doc);
  noncanon.signed.plugins.find((x) => x.icon).icon.path = "assets/../x.png";
  assert(collectAssets({ root: REPO_ROOT, indexDoc: noncanon, headRef: null }).problems.length > 0, "a bad path passed");
});

await test("a carried catalogue's assets come from signed's head, and the commit holds them and nothing else", () => {
  const repo = tmp("signer-assets-");
  const git = (...a) => execFileSync("git", ["-C", repo, ...a], { encoding: "utf8", env: cleanEnv() }).trim();
  git("init", "-q");
  const bytes = Buffer.from("not really a png, but its own digest names it");
  const name = `assets/${sha(bytes)}.png`;
  const stray = `assets/${"0".repeat(64)}.png`;
  const head = buildSignedCommit({
    root: repo, parent: null, message: "head",
    files: { "registry/v1/index.json": "{}", [`registry/v1/${name}`]: bytes, [`registry/v1/${stray}`]: Buffer.from("x") },
  });
  const doc = { signed: { serial: 1, plugins: [{ id: "a", icon: { path: name, sha256: sha(bytes), size: bytes.length, media_type: "image/png" } }] } };
  const got = collectAssets({ root: repo, indexDoc: doc, headRef: head });
  assertEqual(got.problems.length, 0, got.problems.join("; "));
  assertEqual([...got.assets.keys()].join(), name, "only the referenced file");
  const sha2 = buildSignedCommit({
    root: repo, parent: head, message: "next",
    files: { "registry/v1/index.json": "{}", ...Object.fromEntries([...got.assets].map(([k, v]) => [`registry/v1/${k}`, v])) },
  });
  const tree = git("ls-tree", "-r", "--name-only", sha2).split("\n");
  assert(tree.includes(`registry/v1/${name}`) && !tree.includes(`registry/v1/${stray}`), `tree: ${tree}`);
  assert(execFileSync("git", ["-C", repo, "show", `${sha2}:registry/v1/${name}`], { env: cleanEnv() }).equals(bytes), "bytes changed in the commit");
});

console.log("\nthe regeneration (TRUST-49)");

await test("the candidate's asset directory must be exactly the derived set", () => {
  const dir = tmp("cand-assets-");
  const put = (rel, b) => { fs.mkdirSync(path.join(dir, "assets"), { recursive: true }); fs.writeFileSync(path.join(dir, rel), b); };
  for (const [rel, b] of at.assets) put(rel, b);
  assertEqual(assetProblems(dir, at.assets).length, 0, "the derived set disagreed with itself");
  const first = [...at.assets.keys()][0];
  const keep = fs.readFileSync(path.join(dir, first));
  fs.rmSync(path.join(dir, first));
  assert(assetProblems(dir, at.assets).some((x) => x.includes("missing")), "a missing file passed");
  put(first, Buffer.from("other bytes"));
  assert(assetProblems(dir, at.assets).some((x) => x.includes("digest")), "tampered bytes passed");
  put(first, keep);
  put(`assets/${sha(Buffer.from("extra"))}.png`, Buffer.from("extra"));
  assert(assetProblems(dir, at.assets).some((x) => x.includes("extra")), "an extra file passed");
  fs.rmSync(path.join(dir, `assets/${sha(Buffer.from("extra"))}.png`));
  put("assets/not-a-hash.png", Buffer.from("x"));
  assert(assetProblems(dir, at.assets).some((x) => x.includes("not assets/<sha256>")), "a non-hash name passed");
});

await test("buildAssets is the derivation build-index uses", () => {
  assertEqual([...buildAssets({ root: REPO_ROOT, serial: GATE }).keys()].sort().join(), [...at.assets.keys()].sort().join(), "two derivations");
});

console.log(failures.length ? `\nFAIL  ${passed} passed, ${failures.length} failed` : `\nok    ${passed} passed`);
process.exit(failures.length ? 1 : 0);
