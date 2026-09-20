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
import { test, assert, assertEqual, tmp, validateTree, errorsMatching } from "./harness.mjs";
import { withFakeAstraPlugins } from "./fixtures.mjs";

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

  // ID-66's sixteen, as a list something checks rather than as prose.
  //
  // policy/reserved-ids.json deliberately does NOT restate which of its entries
  // are here for the panel: a list written twice is a list with one stale copy,
  // and this repository has been bitten by that shape more than any other. So
  // the enumeration lives here, where the two tests below read it — one against
  // the committed policy, one against what the validator actually does with it.
  //
  // Reserving a name costs an author, not us: it is a name nobody can ever
  // list under. Sixteen ordinary English words is a policy decision and the
  // reason it was taken is in policy/reserved-ids.json's `reserved_note`.
  const PANEL_ROUTES = [
    "search", "publish", "moderation", "transparency", "authors", "account", "new", "api",
    "login", "logout", "about", "help", "docs", "feed", "rss", "sitemap",
  ];

  await test("every panel route name is reserved, and no listing has already taken one", () => {
    const policy = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "policy/reserved-ids.json"), "utf8"));

    // The SHAPE before anything else, and read off the RAW members rather than
    // through the `?? []` the two callers use. Written the other way first and
    // watched saying the wrong thing: `reserved` renamed to `reserved_ids`
    // defaults to `[]`, which is an array, so the shape assertion passed and
    // the name check below reported all sixteen panel routes as dropped. True,
    // and it sends the reader to re-add sixteen names to a file that still has
    // all thirty, under a key nothing reads. `?? []` is right in the predicate
    // — a policy file that lost a member must reserve nothing rather than
    // throw — and it is exactly what a test about that file must not inherit.
    assert(Array.isArray(policy.reserved) && Array.isArray(policy.reserved_prefixes),
      `policy/reserved-ids.json has reserved=${JSON.stringify(policy.reserved)?.slice(0, 40)} and ` +
      `reserved_prefixes=${JSON.stringify(policy.reserved_prefixes)?.slice(0, 40)}; tools/lib/reserved.mjs and ` +
      `tools/validate.mjs read both as arrays and fall back to an empty one, so nothing is reserved right now — ` +
      `the member has been renamed or reshaped, not emptied`);
    const reserved = policy.reserved;
    const prefixes = policy.reserved_prefixes;

    // Then WHICH names, before any count. A dropped name is the failure this
    // test exists for and it has to say the name: with the floor first, taking
    // `rss` back out reports "lists 29 and listed 30", which is true and does
    // not name the word that a stranger may now list under.
    const dropped = PANEL_ROUTES.filter((n) => !reserved.includes(n));
    assertEqual(dropped.join(", "), "",
      "ID-66 names sixteen panel route names the registry must reserve and policy/reserved-ids.json no longer " +
      "carries all of them; the missing ones are free for a stranger to list under");

    // And then the counts, which are about the other fourteen and about the
    // prefixes — the entries no list in this file enumerates.
    assert(reserved.length >= 30,
      `policy/reserved-ids.json lists ${reserved.length} reserved ids and listed 30 on 2026-09-19; every panel ` +
      `route is still there, so this is one of the older reservations taken out, which is a security change`);
    assert(prefixes.length >= 3,
      `policy/reserved-ids.json lists ${prefixes.length} reserved prefixes and listed 3 on 2026-09-19 ` +
      `(astra-, official-, verified-); a prefix dropped here is an impersonation primitive handed back`);

    // Twice in the list is how a merge of two people's additions reads, and the
    // predicate would not notice: `includes` is true either way.
    const dupes = reserved.filter((n, i) => reserved.indexOf(n) !== i);
    assertEqual([...new Set(dupes)].join(", "), "", "a reserved id is listed twice in policy/reserved-ids.json");

    // The collision the preflight asked about, kept as a check rather than as a
    // date in a note. A reserved id that a listing already holds does not fail
    // safe: tools/validate.mjs refuses that listing, so `main` goes red and the
    // catalogue cannot be rebuilt until somebody either unlists a stranger's
    // plugin or takes the reservation back out.
    //
    // The full-tree run two tests above would catch it too, as one more error
    // among however many. This one names the plugin and the name it collides
    // with, which is the difference between a reviewer reverting one line and a
    // reviewer reading a validator transcript.
    const pluginsRoot = path.join(REPO_ROOT, "plugins");
    const dirs = fs.readdirSync(pluginsRoot)
      .filter((d) => fs.existsSync(path.join(pluginsRoot, d, "plugin.json")));
    assert(dirs.length >= 20,
      `the walk of plugins/ found ${dirs.length} listings and there were 22 on 2026-09-19; this is a broken walk ` +
      `rather than a smaller catalogue, and the collision check below would pass by finding nothing`);
    const collisions = [];
    for (const dir of dirs) {
      // Both the directory and the id inside it. tools/validate.mjs refuses the
      // pair when they disagree and reads the id for the reserved rule, so a
      // check that asked only the directory name would be asking the wrong one
      // of the two on exactly the tree where they differ.
      const id = JSON.parse(fs.readFileSync(path.join(pluginsRoot, dir, "plugin.json"), "utf8")).id;
      if (reserved.includes(dir)) collisions.push(`plugins/${dir}`);
      if (id !== dir && reserved.includes(id)) collisions.push(`plugins/${dir} (id ${JSON.stringify(id)})`);
    }
    assertEqual(collisions.join(", "), "",
      "a reserved id is already held by a listing, so tools/validate.mjs refuses the committed tree; either the " +
      "reservation comes back out or that listing is renamed, and both are the owner's call");
  });

  console.log("\nrejections");
  // The canary for the reservation: not that the name is in a file, but that a
  // listing under it is refused. One tree per reserved name, every one of them,
  // so the sixteen added for the panel and the fourteen that were here before
  // are proved by the same loop and a seventeenth is proved the day it lands.
  //
  // The bot refuses the same names at ingest through the same array —
  // bot/lib/derive.mjs reads `policy.reserved.reserved` and raises
  // E_ID_RESERVED — so there is one list and one answer, and no fixture here
  // can drift from what a stranger's submission meets.
  await test("a listing under any reserved id is refused, one tree per name", async () => {
    const src = path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller");
    const reserved = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "policy/reserved-ids.json"), "utf8")).reserved;

    // One listing, renamed throughout — id, directory, source.repo, the release
    // URL and the artifact filename — so that the only thing wrong with the
    // tree is the NAME. A fixture that also tripped the filename rule would
    // give a red validator for a reserved id whatever the policy said.
    const treeFor = (id) => {
      const dir = path.join(tmp, `reserved-${id}`);
      fs.rmSync(dir, { recursive: true, force: true });
      fs.cpSync(src, path.join(dir, "plugins", id), { recursive: true });
      for (const rel of ["plugin.json", "versions/1.0.0.json"]) {
        const file = path.join(dir, "plugins", id, rel);
        const renamed = fs.readFileSync(file, "utf8").replaceAll("dice-roller", id);
        // Parsed and re-serialised rather than written as text, so a rename
        // that produced something that is not JSON any more fails here, in the
        // fixture builder, instead of arriving below as a parse error the
        // assertion would read as a refusal.
        fs.writeFileSync(file, stableStringify(JSON.parse(renamed)));
      }
      return dir;
    };

    // The control, and it is not decoration. The first draft of this test
    // asserted only that a reserved name produces a "is reserved" error, and it
    // would have passed just as well over a fixture that no longer validated at
    // all — which is how the assertion below, that the reserved rule is the
    // ONLY thing refusing these trees, can be made at all.
    assert(!reserved.includes("dice-roller"),
      "the control id is itself reserved now, so this test proves nothing; pick a name nobody reserved");
    const control = await validateTree(treeFor("dice-roller"));
    assert(control.report.errors.length === 0,
      `the fixture tree is refused under a name nobody reserved, so nothing below is about the reservation:\n` +
      control.report.errors.map((e) => `${e.where}: ${e.message}`).join("\n"));

    const problems = [];
    for (const id of reserved) {
      const { report } = await validateTree(treeFor(id));
      const hits = errorsMatching(report, `id ${JSON.stringify(id)} is reserved`);
      if (hits.length !== 1) {
        problems.push(`${id}: ${hits.length} reserved refusals, expected 1 — a stranger may list under it`);
      } else if (report.errors.length !== 1) {
        problems.push(
          `${id}: refused ${report.errors.length} times over, so this tree no longer isolates the reserved rule ` +
          `(${report.errors.map((e) => e.message).join("; ")})`);
      }
    }
    // `assert` and not `assertEqual` here, and the difference is legibility
    // rather than taste: assertEqual JSON-stringifies both sides, so thirty
    // findings print as one line with `\n` in it. Watched, neutering the rule
    // in tools/validate.mjs: the whole list arrived escaped on a single line.
    assert(problems.length === 0,
      `a reserved id was not refused by tools/validate.mjs, so it is free for a stranger to list under:\n` +
      problems.join("\n"));
  });

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
