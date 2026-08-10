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
  const regenerated = stableStringify(buildIndex({ serial: JSON.parse(committed).serial }));
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
  const staged = doc.plugins.filter((p) => p.staging === true);
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
  doc.plugins[0].platform_downloads = { "linux-x64": "https://github.com/evil/x/releases/download/v1/x.astraplugin" };
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

console.log("\ncli surface");
await test("`build-index.mjs --check` exits 0 on the committed tree", () => {
  execFileSync("node", ["tools/build-index.mjs", "--check"], { cwd: REPO_ROOT, stdio: "pipe" });
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
