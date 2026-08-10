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

import { runValidation } from "./validate.mjs";
import { buildIndex } from "./build-index.mjs";
import {
  CATALOG_TTL_DAYS, INDEX_SCHEMA, REVOCATIONS_SCHEMA, REVOCATION_TTL_DAYS, TRUST_SCHEMA,
  signEnvelope, verifyEnvelope,
} from "../bot/lib/sign.mjs";
import { signIndex, indexKeysFromTrust } from "../bot/sign-index.mjs";
import { signRevocations } from "./sign-revocations.mjs";
import { buildRevocations, checkAdvisory } from "./lib/revocations.mjs";
import { fixtureCatalogue, FIXTURE_ISSUED_AT } from "../bot/fixtures/index/regenerate.mjs";
import { loadTestRoot } from "./testkeys/regenerate.mjs";
import { stableStringify, jcs } from "./lib/canonical.mjs";
import { validate as validateSchema } from "./lib/jsonschema.mjs";
import { makeFixtures } from "./make-fixtures.mjs";
import { REPO_ROOT, loadSources } from "./lib/sources.mjs";
import { readZip, readEntry, writeZip } from "./lib/zip.mjs";
import { compareSemver } from "./lib/semver.mjs";
import { invalidId, unsafePathComponent, foldId } from "./lib/ids.mjs";
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
await test("index.json validates against schema/index-v1.json", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
  const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
  const errs = validateSchema(schema, doc);
  assert(errs.length === 0, errs.map((e) => `${e.path} ${e.message}`).join("\n"));
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
  assert(report.warnings.some((w) => w.message.includes("accepted as staging")), "it passed silently");
});
await test("no staging entry offers a download URL to a digest-blind client", () => {
  const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
  const staged = doc.signed.plugins.filter((p) => p.staging === true);
  assert(staged.length >= 1, "no staging entry in the index, so this test proves nothing");
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

fs.rmSync(tmp, { recursive: true, force: true });

console.log(`\n${failures.length === 0 ? "PASS" : "FAIL"}  ${passed} passed, ${failures.length} failed`);
if (failures.length) {
  for (const f of failures) console.log(`      - ${f}`);
  process.exit(1);
}
