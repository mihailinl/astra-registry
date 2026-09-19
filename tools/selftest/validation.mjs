// What tools/validate.mjs refuses on a tree: staging listings without
// --allow-staging and the loud acceptance with it, no download URL for a
// digest-blind client, unsafe ids, id collisions, digest mismatch, a hand-edited
// index, a platform key with no host, and the AstraPlugins limits drift.
//
// `withFakeAstraPlugins` used to be defined in the middle of this section and is
// in ./fixtures.mjs now, because listings.mjs is its second consumer.

import fs from "node:fs";
import path from "node:path";

import { runValidation } from "../validate.mjs";
import { buildIndex } from "../build-index.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { compareSemver } from "../lib/semver.mjs";
import { REPO_ROOT, loadSources } from "../lib/sources.mjs";
import { makeFixtures } from "../make-fixtures.mjs";
import { test, assert, tmp, validateTree, errorsMatching } from "./harness.mjs";
import { withFakeAstraPlugins } from "./fixtures.mjs";

/** How many tests run() reports. The runner asserts exactly this many, so
 *  adding a test here is one line of arithmetic in this file and nowhere else. */
export const TESTS = 10;

export async function run() {
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
}
