// What tools/validate.mjs refuses on a tree: staging listings without
// --allow-staging and the loud acceptance with it, no download URL for a
// digest-blind client, unsafe ids, id collisions, digest mismatch, a hand-edited
// index, a platform key with no host, and the AstraPlugins limits drift.
//
// `withFakeAstraPlugins` used to be defined in the middle of this section and is
// in ./fixtures.mjs now, because listings.mjs is its second consumer.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { cleanEnv, fixtureEnv } from "../lib/git-env.mjs";

import { RECORD_ROOTS, checkTreeModes, displayStrings, recordFiles, recordStringProblems, runValidation } from "../validate.mjs";
import { readTree, treeModeProblems, unaskableRoot } from "../lib/tree-modes.mjs";
import { MAX_PATTERN_REPETITION, patternRepetition, schemaPatterns } from "../lib/schema-patterns.mjs";
import { buildIndex } from "../build-index.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { compareSemver } from "../lib/semver.mjs";
import { validate as validateSchema } from "../lib/jsonschema.mjs";
import { REPO_ROOT, loadSources } from "../lib/sources.mjs";
import { stagingListingId } from "../lib/reserved.mjs";
import { RESERVED_KEYS, SUPPORTED_KEYS, platformKeyFromManifest } from "../lib/platform.mjs";
import { CODES } from "../../bot/lib/codes.mjs";
import { ICON_NAMES } from "../../bot/lib/assets.mjs";
import { makeFixtures } from "../make-fixtures.mjs";
import { test, assert, assertEqual, neverAsk, tmp, validateTree, errorsMatching } from "./harness.mjs";
import { withFakeAstraPlugins } from "./fixtures.mjs";

export async function run() {
  // A listing whose every version is yanked is VALID and is left out of the
  // catalogue; a later version that is not yanked brings it back. Decided by
  // the coordinator on 2026-09-24, after the moderation run was measured
  // failing on it: an `M_YANK` or `A_YANK` of a listing's last listed version
  // made `tools/build-index.mjs` throw "every version is yanked or missing"
  // inside the commit job, so every takedown in that batch was lost, and on
  // every run after it until the entry left the list. Eight listings had
  // exactly one version that day. `tools/validate.mjs` refused the same tree
  // ("every version is yanked, but the plugin is still listed"), and the commit
  // job runs it as a gate before it pushes, so fixing only the generator would
  // have moved the failure one step later.
  //
  // What stays refused is a listing with NO version files. That is a broken
  // tree, not a withdrawal: nobody yanked anything, and hiding it would make a
  // plugin vanish from every store with nothing red anywhere.
  await test("a listing with every version yanked validates and leaves the catalogue; a new version brings it back", async () => {
    const src = path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller");
    const tree = (name) => {
      const dir = path.join(tmp, `all-yanked-${name}`);
      fs.rmSync(dir, { recursive: true, force: true });
      fs.cpSync(src, path.join(dir, "plugins", "dice-roller"), { recursive: true });
      return dir;
    };
    const versionFile = (dir, v) => path.join(dir, "plugins", "dice-roller", "versions", `${v}.json`);
    const yank = (dir, v) => {
      const doc = JSON.parse(fs.readFileSync(versionFile(dir, v), "utf8"));
      fs.writeFileSync(versionFile(dir, v), stableStringify({ ...doc, yanked: true }));
    };
    const ids = (dir) => buildIndex({ root: dir, serial: 1 }).signed.plugins.map((p) => p.id);

    const control = tree("control");
    const before = await validateTree(control);
    assertEqual(before.report.errors.map((e) => e.message).join("; "), "", "the fixture listing does not validate as it stands");
    assertEqual(ids(control).join(","), "dice-roller", "the fixture listing is not in its own catalogue");

    const yanked = tree("yanked");
    yank(yanked, "1.0.0");
    const { report } = await validateTree(yanked);
    assertEqual(report.errors.map((e) => `${e.where}: ${e.message}`).join("; "), "",
      "a listing whose only version is yanked is refused by tools/validate.mjs, which the moderation commit job runs " +
      "before it pushes — so an M_YANK of a last version stops the whole batch there");
    let built;
    try {
      built = ids(yanked);
    } catch (err) {
      assert(false, `tools/build-index.mjs threw on a listing whose every version is yanked: ${err.message}`);
    }
    assertEqual(built.join(","), "", "a listing with no installable version is still in the catalogue");

    // A later release that is not yanked: the listing comes back, at that version.
    const doc = JSON.parse(fs.readFileSync(versionFile(control, "1.0.0"), "utf8"));
    const next = JSON.parse(JSON.stringify(doc).replaceAll("1.0.0", "1.1.0"));
    next.published_at = "2026-09-24T00:00:00Z";
    fs.writeFileSync(versionFile(yanked, "1.1.0"), stableStringify(next));
    const back = await validateTree(yanked);
    assertEqual(back.report.errors.map((e) => e.message).join("; "), "", "the listing with a new release does not validate");
    const entry = buildIndex({ root: yanked, serial: 1 }).signed.plugins.find((p) => p.id === "dice-roller");
    assert(entry, "a new release that is not yanked did not bring the listing back");
    assertEqual(entry.version, "1.1.0", "the listing came back at the wrong version");

    // And a listing with NO version files is still a broken tree, refused by both.
    const empty = tree("empty");
    fs.rmSync(path.join(empty, "plugins", "dice-roller", "versions"), { recursive: true, force: true });
    fs.mkdirSync(path.join(empty, "plugins", "dice-roller", "versions"));
    const none = await validateTree(empty);
    assert(errorsMatching(none.report, "contains no version files").length === 1,
      "a listing with no version files validated; that is a broken tree, not a withdrawal");
    let threw = false;
    try { ids(empty); } catch { threw = true; }
    assert(threw, "tools/build-index.mjs left out a listing with no version files instead of refusing the tree");
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

    // ── and the sentence in the name, asked where it can be answered ────────
    //
    // Everything above judges the catalogue AS COMMITTED, and `staged` is an
    // empty array on this tree: 16 entries, none with `staging === true`. So
    // `leaky` was a filter over nothing and the assertion under it could not
    // fail. Measured 2026-09-22 against a4f81e0: replacing the whole refusal in
    // tools/build-index.mjs's flatDownloads with `const installable = true` —
    // the generator's refusal to hand a digest-blind client a URL it cannot
    // verify, which is precisely what this check's name states — left the suite
    // at `INCOMPLETE 317 passed, 0 failed, 1 not asked`, exit 0, with nothing
    // red anywhere, and left the regenerated catalogue byte-identical, because
    // with no staging entry the deleted clause changes no output.
    //
    // The check was armed and correct and the rule it is named for was enforced
    // by nobody. A check whose subject the catalogue is free to run out of is a
    // name that outlives its own measurement — the same shape as the `>= 1`
    // floor removed above, arriving from the other side.
    //
    // So the refusal is also put to a tree built to make it fire. Both ways an
    // entry can be digest-blind are covered, because `installable` is a
    // conjunction and either half could be deleted on its own: a staging newest
    // version, and a newest version with an artifact carrying no digest. The
    // fixture is built out of a committed listing and synthesised rather than
    // found, so this leg cannot go vacuous the way the one above did.
    //
    // The listing it is built from is chosen by the PROPERTY the fixture needs
    // — a newest live version that is soundly released — and not by position.
    // Taking the first listed plugin would make the control below go red the day
    // that listing's newest version happened to be a staging one, which is a
    // legitimate tree turning a self-test red: the shape the `>= 1` floor above
    // was removed for.
    const source = loadSources(REPO_ROOT).plugins.find((p) => {
      if (p.doc?.unlisted === true) return false;
      const live = (p.versions ?? []).map((v) => v.doc).filter((d) => d && d.yanked !== true);
      if (!live.length) return false;
      const newest = live.slice().sort((a, b) => compareSemver(a.version, b.version)).at(-1);
      return newest.staging !== true &&
        Object.values(newest.artifacts ?? {}).every((a) => typeof a.sha256 === "string" && typeof a.size === "number");
    });
    assert(source !== undefined,
      "no listed plugin's newest live version is soundly released, so there is nothing to project and the " +
      "control below would have nothing to control for");

    const projected = (name, mutateNewest) => {
      const dir = path.join(tmp, `digest-blind-${name}`);
      const plugin = path.join(dir, "plugins", source.dir);
      fs.mkdirSync(path.join(dir, "plugins"), { recursive: true });
      fs.cpSync(path.join(REPO_ROOT, "plugins", source.dir), plugin, { recursive: true });
      const versions = path.join(plugin, "versions");
      const live = fs.readdirSync(versions)
        .map((f) => ({ f, doc: JSON.parse(fs.readFileSync(path.join(versions, f), "utf8")) }))
        .filter((v) => v.doc.yanked !== true)
        .sort((a, b) => compareSemver(a.doc.version, b.doc.version));
      const newest = live.at(-1);
      if (mutateNewest) {
        mutateNewest(newest.doc);
        fs.writeFileSync(path.join(versions, newest.f), `${JSON.stringify(newest.doc, null, 2)}\n`);
      }
      const entry = buildIndex({ root: dir, serial: 1 }).signed.plugins.find((e) => e.id === source.doc.id);
      assert(entry !== undefined, `${name}: ${source.doc.id} did not reach the generated catalogue at all`);
      return entry;
    };

    // The control, and the reason the two refusals below mean anything: a
    // projection that emitted nothing for everybody would satisfy them both.
    const sound = projected("sound", null);
    assert(Object.keys(sound.platform_downloads).length > 0,
      `${source.doc.id} is soundly released and the projection still offers no download, so the two ` +
      "refusals below are satisfied by a generator that has simply stopped working");

    // One fixture per CONJUNCT, and the staging one deliberately keeps its
    // digests. Written the other way first — a staging entry with its digests
    // stripped, which is what the registry actually commits — and watched
    // saying the wrong thing: with `latest.staging !== true &&` deleted from
    // the generator and the digest clause left in place, that fixture is still
    // refused for the other reason and the check stays green. A conjunction
    // needs an input that only one half refuses, or the halves cover for each
    // other and one of them can be deleted in silence.
    for (const [name, mutate] of [
      ["staging", (d) => {
        d.staging = true;
        d.staging_reason = "a synthesised staging entry, digests intact so only the staging clause refuses it";
      }],
      ["no-digest", (d) => { delete Object.values(d.artifacts)[0].sha256; }],
    ]) {
      const entry = projected(name, mutate);
      assertEqual(entry.download_url, "",
        `a ${name} entry is handed a download_url a digest-blind client cannot verify`);
      assertEqual(Object.keys(entry.platform_downloads).join(","), "",
        `a ${name} entry is reachable through platform_downloads, which is what a client that cannot read ` +
        "releases[] follows");
    }
  });

  // ID-66's panel names, as two lists something checks rather than as prose.
  //
  // policy/reserved-ids.json deliberately does NOT restate which of its entries
  // are here for the panel: a list written twice is a list with one stale copy,
  // and this repository has been bitten by that shape more than any other. So
  // the enumeration lives here, where the two tests below read it — one against
  // the committed policy, one against what the validator actually does with it.
  //
  // The SECOND list is the one that needs explaining. Reserving a name costs an
  // author and nobody else: it is a name no plugin can ever be called. ID-66
  // asked for sixteen; eight are reserved because they name Astra or the
  // machinery a user is asked to trust, and eight ordinary English words were
  // released on 2026-09-19, once the two risks behind the sixteen were told
  // apart — contract ID-67's `/plugins/_/` settles the route half on its own,
  // and impersonation, which it does not touch, is about the first eight and
  // not about `rss`. `reserved_note` carries that argument. An absence states
  // nothing by itself, so the release is asserted here too: otherwise the next
  // reader re-adds a name as an oversight and no test disagrees.
  const PANEL_NAMES_RESERVED = [
    "account", "api", "authors", "login", "logout", "moderation", "publish", "transparency",
  ];
  const PANEL_NAMES_RELEASED = [
    "about", "docs", "feed", "help", "new", "rss", "search", "sitemap",
  ];

  await test("the panel names that read as Astra are reserved, the ordinary words deliberately are not, " +
    "and no listing has already taken one", () => {
    const policy = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "policy/reserved-ids.json"), "utf8"));

    // The SHAPE before anything else, and read off the RAW members rather than
    // through the `?? []` the two callers use. Written the other way first and
    // watched saying the wrong thing: `reserved` renamed to `reserved_ids`
    // defaults to `[]`, which is an array, so the shape assertion passed and
    // the name check below reported every panel name as dropped. True, and it
    // sends the reader to re-add them to a file that still has all twenty-two,
    // under a key nothing reads. `?? []` is right in the predicate
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
    // `login` back out reports "lists 21 and listed 22", which is true and does
    // not name the word that a stranger may now list under. Watched saying
    // exactly that, both ways round, on 2026-09-19.
    const dropped = PANEL_NAMES_RESERVED.filter((n) => !reserved.includes(n));
    assertEqual(dropped.join(", "), "",
      "these panel names name Astra or the machinery a user is asked to trust, so the registry reserves them " +
      "(ID-66, as narrowed on 2026-09-19) and policy/reserved-ids.json no longer carries all of them; the " +
      "missing ones are free for a stranger to list under");

    // The other half of the same decision, and the half an absence cannot state
    // on its own. Without this, re-adding `rss` is a one-line edit that neither
    // a test nor a reviewer can tell apart from repairing an oversight, which
    // is how a namespace narrows by accident rather than by argument.
    const readded = PANEL_NAMES_RELEASED.filter((n) => reserved.includes(n));
    assertEqual(readded.join(", "), "",
      "policy/reserved-ids.json reserves a panel name that was released on purpose on 2026-09-19 — its " +
      "reserved_note says why each of the eight is an ordinary word an author may want, and reserving one " +
      "again is a policy change: make it in the note and in this list together, never in the array alone");

    // And then the counts, which are about the other fourteen and about the
    // prefixes — the entries no list in this file enumerates.
    assert(reserved.length >= 22,
      `policy/reserved-ids.json lists ${reserved.length} reserved ids and listed 22 on 2026-09-19; every panel ` +
      `name is still there, so this is one of the older reservations taken out, which is a security change`);
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
  // so the eight kept for the panel and the fourteen that were here before are
  // proved by the same loop and a twenty-third is proved the day it lands. The
  // eight released names get the same treatment from the other side, below.
  //
  // The bot refuses the same names at ingest through the same array —
  // bot/lib/derive.mjs reads `policy.reserved.reserved` and raises
  // E_ID_RESERVED — so there is one list and one answer, and no fixture here
  // can drift from what a stranger's submission meets.
  await test("a listing under any reserved id is refused, and one under a released panel name is not", async () => {
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
    // rather than taste: assertEqual JSON-stringifies both sides, so twenty-two
    // findings print as one line with `\n` in it. Watched, neutering the rule
    // in tools/validate.mjs: the whole list arrived escaped on a single line.
    assert(problems.length === 0,
      `a reserved id was not refused by tools/validate.mjs, so it is free for a stranger to list under:\n` +
      problems.join("\n"));

    // The release, proved the same way round. A name missing from the array is
    // only a claim that a plugin may be called that; this runs the validator
    // over a listing that is, for each of the eight. The control above is what
    // makes a red here readable: the fixture is known good under a name nobody
    // reserved, so a refusal is about the name and not about the tree.
    const stillRefused = [];
    for (const id of PANEL_NAMES_RELEASED) {
      const { report } = await validateTree(treeFor(id));
      if (report.errors.length !== 0) {
        stillRefused.push(`${id}: ${report.errors.map((e) => e.message).join("; ")}`);
      }
    }
    assert(stillRefused.length === 0,
      `a panel name policy/reserved-ids.json released on purpose is still refused, so the release is on paper ` +
      `only and an author who takes the name at its word meets a red run:\n` + stillRefused.join("\n"));
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
  await test("the validator's platform keys are the schema's vocabulary and platform.mjs's table, member for member", async () => {
    // One vocabulary, four literals, no import between them: tools/validate.mjs's
    // PLATFORM_KEYS and UNSUPPORTED_KEYS, tools/lib/platform.mjs's SUPPORTED_KEYS
    // and RESERVED_KEYS, and schema/version-v1.json's artifact enum. Measured
    // 2026-09-22 against the check above, which asks one reserved key: adding
    // `freebsd-x64` to PLATFORM_KEYS, deleting `linux-arm64` from it, deleting
    // `linux-arm64` from UNSUPPORTED_KEYS, and deleting it from RESERVED_KEYS
    // each left all 317 checks green. The third is the one that fails OPEN:
    // the schema still allows the key, the validator no longer calls it
    // reserved, and a listing whose artifact can run on no Astra host is
    // accepted.
    //
    // The validator's set is read from the validator — an unknown key's refusal
    // lists every key it knows — rather than from its source, and each side of
    // its partition is asked by listing an artifact under every key of it.
    const probe = async (key, n) => {
      const dir = path.join(tmp, `platform-probe-${n}`);
      fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(dir, "plugins/dice-roller"), { recursive: true });
      const vf = path.join(dir, "plugins/dice-roller/versions/1.0.0.json");
      const v = JSON.parse(fs.readFileSync(vf, "utf8"));
      const art = { ...v.artifacts["linux-x64"] };
      art.url = art.url.replace("linux-x64", key);
      art.filename = art.filename.replace("linux-x64", key);
      v.artifacts = { [key]: art };
      fs.writeFileSync(vf, stableStringify(v));
      return (await validateTree(dir)).report;
    };
    const sorted = (keys) => [...keys].sort().join(" ");
    const schemaEnum = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/version-v1.json"), "utf8"))
      .properties?.artifacts?.propertyNames?.enum;
    assert(Array.isArray(schemaEnum) && schemaEnum.length > 0,
      "schema/version-v1.json no longer states its platform vocabulary at properties.artifacts.propertyNames.enum");

    const unknown = errorsMatching(await probe("no-such-host", 0), "is not a platform key");
    assertEqual(unknown.length, 1, "an artifact under a key nobody defines was not refused as one");
    const listed = /^Known keys: (.+)\. These are /.exec(unknown[0].hint ?? "");
    assert(listed, `the refusal no longer names the keys the validator knows: ${JSON.stringify(unknown[0].hint)}`);
    const known = sorted(listed[1].split(", "));
    assertEqual(known, sorted(schemaEnum),
      "tools/validate.mjs's PLATFORM_KEYS is not schema/version-v1.json's artifact vocabulary");
    assertEqual(known, sorted([...SUPPORTED_KEYS, ...RESERVED_KEYS]),
      "tools/validate.mjs's PLATFORM_KEYS is not tools/lib/platform.mjs's SUPPORTED_KEYS and RESERVED_KEYS");

    let n = 1;
    for (const key of RESERVED_KEYS) {
      assertEqual(errorsMatching(await probe(key, n++), "reserved key with no host").length, 1,
        `${key} is reserved in tools/lib/platform.mjs, and tools/validate.mjs did not refuse an artifact under it as reserved`);
    }
    for (const key of SUPPORTED_KEYS) {
      const refused = (await probe(key, n++)).errors.filter((e) => /platform key|reserved key/.test(e.message));
      assertEqual(refused.map((e) => e.message).join("; "), "",
        `${key} is supported in tools/lib/platform.mjs, and tools/validate.mjs refused an artifact under it`);
    }
  });
  await test("the platform vocabulary's other copies keep their stated relations: every schema enum of platform keys is the vocabulary and no schema pattern spells one, build-index writes a noarch artifact under every supported key, the committed index publishes supported keys only, platform.mjs's manifest table reaches each key once, and E_PLATFORM_UNSUPPORTED's remedy names the supported keys", () => {
    // The check above holds the validator, schema/version-v1.json and
    // tools/lib/platform.mjs to one another. The census of 2026-09-22 found the
    // vocabulary in five more places it did not compare, and not all of them
    // are meant to be the same set. Each is asked here for what it holds, and
    // held to the relation its own comment or description states:
    //
    //   schema/index-v1.json's `$defs.platformKey`   EQUAL to the vocabulary —
    //       reserved names are in the schemas "so nobody else claims the names"
    //   build-index's noarch expansion                EQUAL to SUPPORTED_KEYS —
    //       "written under every supported platform key" (index-v1.json)
    //   the committed registry/v1/index.json          a SUBSET of SUPPORTED_KEYS —
    //       the validator refuses the reserved ones, so the index never carries one
    //   platform.mjs's MANIFEST.platform table         ONTO the vocabulary, one
    //       {os, arch} pair per key
    //   E_PLATFORM_UNSUPPORTED's remedy (bot/lib/codes.mjs, and generated from
    //       it into tools/codes-table.json and the token file)   NAMES
    //       SUPPORTED_KEYS, and "macOS and arm64 names" describes RESERVED_KEYS
    //
    // Measured on main (70df193) before this: widening or narrowing the index
    // schema's enum, and adding a pair to the manifest table, left every check
    // green. Dropping a key from build-index's then-literal noarch expansion
    // was red only as "the committed index is not what the generator
    // produces", which a correct change to the output reads as too, and a
    // remedy naming the wrong hosts only as a stale codes-table.json, which a
    // regeneration satisfies.
    const vocabulary = [...SUPPORTED_KEYS, ...RESERVED_KEYS];
    const sorted = (keys) => [...keys].sort().join(" ");
    const isKeyShaped = (s) => typeof s === "string" && (vocabulary.includes(s) || /^(?:linux|windows|macos|darwin|freebsd|android|ios)-[a-z0-9_]+$/.test(s));

    // (a) the schemas, FOUND by walking: every enum with a platform key in it,
    // and every pattern that spells one — which nothing could compare as a set.
    const enums = [], patterns = [];
    const walk = (node, where) => {
      if (Array.isArray(node)) node.forEach((v, i) => walk(v, `${where}/${i}`));
      else if (node && typeof node === "object") {
        if (Array.isArray(node.enum) && node.enum.some(isKeyShaped)) enums.push([where, node.enum]);
        for (const k of ["pattern"]) {
          if (typeof node[k] === "string" && vocabulary.some((key) => node[k].includes(key))) patterns.push(`${where}: ${node[k]}`);
        }
        for (const [k, v] of Object.entries(node)) walk(v, `${where}/${k}`);
      }
    };
    const schemaDir = path.join(REPO_ROOT, "schema");
    for (const f of fs.readdirSync(schemaDir).filter((n) => n.endsWith(".json")).sort()) {
      walk(JSON.parse(fs.readFileSync(path.join(schemaDir, f), "utf8")), `schema/${f}#`);
    }
    assert(enums.length >= 2, `found ${enums.length} platform enum(s) under schema/; version-v1.json and index-v1.json each publish one`);
    for (const [where, values] of enums) {
      assertEqual(sorted(values), sorted(vocabulary),
        `${where} is a platform enum that is not tools/lib/platform.mjs's vocabulary (SUPPORTED_KEYS and RESERVED_KEYS)`);
    }
    assertEqual(patterns.join("\n  "), "",
      "a schema spells a platform key inside a pattern, which no set comparison can hold; give it an enum or teach this check its relation");

    // (b) build-index, asked: one listing whose only artifact is `noarch`.
    const dir = path.join(tmp, "platform-noarch");
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(dir, "plugins/dice-roller"), { recursive: true });
    const vf = path.join(dir, "plugins/dice-roller/versions/1.0.0.json");
    const v = JSON.parse(fs.readFileSync(vf, "utf8"));
    const art = { ...v.artifacts["linux-x64"] };
    art.url = art.url.replace("linux-x64", "noarch");
    art.filename = art.filename.replace("linux-x64", "noarch");
    v.artifacts = { noarch: art };
    fs.writeFileSync(vf, stableStringify(v));
    const entry = buildIndex({ root: dir, serial: 1 }).signed.plugins.find((p) => p.id === "dice-roller");
    assert(entry && entry.download_url === art.url, "the noarch fixture did not reach the compatibility projection at all, so its keys prove nothing");
    assertEqual(sorted(Object.keys(entry.platform_downloads)), sorted(SUPPORTED_KEYS),
      "tools/build-index.mjs writes a noarch artifact under keys other than every supported key (PLATFORM_KEYS_FOR_NOARCH)");
    for (const [k, url] of Object.entries(entry.platform_downloads)) {
      assertEqual(url, art.url, `build-index wrote the noarch artifact's ${k} download as another URL`);
    }

    // (c) the committed index, which is what a client reads.
    const committed = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    const published = new Set();
    for (const p of committed.signed?.plugins ?? []) {
      for (const k of Object.keys(p.platform_downloads ?? {})) published.add(k);
      for (const r of p.releases ?? []) for (const k of Object.keys(r.artifacts ?? {})) published.add(k);
    }
    assert(published.size > 0, "the committed index publishes no platform key at all, so a subset check on it is vacuous");
    const outside = [...published].filter((k) => !SUPPORTED_KEYS.includes(k));
    assertEqual(outside.join(" "), "", "registry/v1/index.json publishes a platform key tools/lib/platform.mjs does not support");

    // (d) platform.mjs's own table, asked over a domain wider than it.
    const reached = new Map();
    for (const os of ["linux", "windows", "macos", "any", "darwin", "freebsd", ""]) {
      for (const arch of ["x86_64", "aarch64", "any", "x64", "arm64", "i686", "riscv64", ""]) {
        const key = platformKeyFromManifest({ os, arch });
        if (key !== null) reached.set(key, [...(reached.get(key) ?? []), `${os}/${arch}`]);
      }
    }
    assertEqual(sorted(reached.keys()), sorted(vocabulary),
      "tools/lib/platform.mjs's MANIFEST.platform table reaches a set of keys that is not its own vocabulary");
    const twice = [...reached].filter(([, pairs]) => pairs.length !== 1).map(([k, pairs]) => `${k} <- ${pairs.join(", ")}`);
    assertEqual(twice.join("; "), "", "a platform key is reached from more than one MANIFEST.platform pair");

    // (e) the refusal's remedy, which a stranger reads when a bundle is refused.
    const remedy = CODES.E_PLATFORM_UNSUPPORTED?.remedy;
    assert(typeof remedy === "string", "bot/lib/codes.mjs has no E_PLATFORM_UNSUPPORTED remedy");
    const named = [...remedy.matchAll(/`([^`]+)`/g)].map((m) => m[1]).filter(isKeyShaped);
    assertEqual(sorted(named), sorted(SUPPORTED_KEYS),
      "E_PLATFORM_UNSUPPORTED's remedy tells an author the hosts that exist, and they are not tools/lib/platform.mjs's SUPPORTED_KEYS");
    assert(/macOS and arm64 names are reserved/.test(remedy),
      "E_PLATFORM_UNSUPPORTED's remedy no longer says which names are reserved; this check holds the sentence it had");
    const described = (k) => k.startsWith("macos-") || k.endsWith("-arm64");
    assertEqual([...RESERVED_KEYS.filter((k) => !described(k)), ...SUPPORTED_KEYS.filter(described)].join(" "), "",
      "\"macOS and arm64 names are reserved\" (E_PLATFORM_UNSUPPORTED's remedy) no longer describes RESERVED_KEYS");
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

  // ── MOD-16's staging listing, M-T2.1's two guards ────────────────────────
  //
  // (b) first, because (a) is only interesting once (b) holds.

  await test("(b) a committed staging listing that is not unlisted is refused, and an unlisted one is not", async () => {
    const id = stagingListingId(POLICY_RESERVED);
    assert(id !== null,
      "policy/reserved-ids.json reserves no staging_listing_id, so both guards below prove nothing. M-T2.1 " +
      "committed one; if it is gone, the derive rule in bot/lib/derive.mjs and the refusal in " +
      "tools/validate.mjs are both live code reading a member nothing sets, and the canary can be published " +
      "listed");

    // The control first, and it is the whole reason a red below is readable:
    // the same tree under the same id, unlisted, has to be accepted. Written
    // the other way round once — refusal only — and it would have passed just
    // as well over a fixture that no longer validated for some other reason.
    const ok = await validateTree(stagingTree("staging-unlisted", id, { unlisted: true }));
    assert(ok.report.errors.length === 0,
      `the unlisted staging listing is refused, so nothing below is about the unlisted rule:\n` +
      ok.report.errors.map((e) => `${e.where}: ${e.message}`).join("\n"));

    const bad = await validateTree(stagingTree("staging-listed", id, { unlisted: false }));
    const hits = errorsMatching(bad.report, "staging_listing_id and the listing is not unlisted");
    assertEqual(hits.length, 1,
      `a LISTED ${id} was not refused by tools/validate.mjs. The signer reads what is on \`main\`, so the next ` +
      `run would put the id the estate exists to withdraw into a signed catalogue (TRUST-26):\n` +
      bad.report.errors.map((e) => `${e.where}: ${e.message}`).join("\n"));
    assertEqual(bad.report.errors.length, 1,
      `the listed-staging tree is refused ${bad.report.errors.length} times over, so it no longer isolates ` +
      `this rule (${bad.report.errors.map((e) => e.message).join("; ")})`);
  });

  await test("(b) the committed tree's staging listing, if it has one, is unlisted", () => {
    const id = stagingListingId(POLICY_RESERVED);
    const here = loadSources(REPO_ROOT).plugins.find((p) => p.doc?.id === id);
    if (!here) {
      // Not an assertion about nothing: the fixtures above are what prove the
      // rule, and this leg is what turns it on the day M-T2.2 publishes the
      // listing, with no edit here.
      //
      // It said exactly that in a parenthetical and then printed `ok`, so the
      // one check in this suite that has never executed its assertion was
      // counted inside `300 passed` for its whole life. The sentence was true
      // and the colour was wrong, which is Gap 17's shape. `neverAsk` throws,
      // so this cannot become a pass again by somebody adding a line under it.
      neverAsk(
        `no plugins/${id}/ is published on this tree, so there is no committed staging listing to hold to ` +
        `\`"unlisted": true\``,
        "M-T2.2 publishes the listing; this check arms itself on that commit with no edit here",
      );
    }
    assertEqual(here.doc.unlisted, true,
      `plugins/${id}/plugin.json is committed without \`"unlisted": true\`. tools/validate.mjs refuses it, so ` +
      `this is also a red build — but the sentence that matters is the other one: the path-test listing is in ` +
      `the catalogue`);
  });

  await test("(a) the staging repository publishes nothing but the staging id after the reservation", async () => {
    const id = stagingListingId(POLICY_RESERVED);
    assert(id !== null,
      "policy/reserved-ids.json reserves no staging_listing_id, so there is no staging repository to ask " +
      "about and the fixtures below reserve `null`. Stated here as well as in (b) because without it this " +
      "test's red is about a fallback it took, which sends the reader to the wrong file");

    // The guard, watched doing both things, on real git trees rather than on a
    // description of them. The `after` fixture is the one that must be red:
    // the staging repository is first-party enough to list under `astra-`, and
    // a second listing from it is the catalogue quietly acquiring a publisher
    // nobody reviewed.
    const before = stagingRepoFixture("staging-repo-clean", id, { alsoPublish: null });
    const clean = stagingRepoGuard(before);
    assertEqual(clean.problems.join(" | "), "",
      `the guard reports a problem on a tree whose only listing from the staging repository IS the staging ` +
      `listing, plus one that predates the reservation (how: ${clean.how}, ${clean.note ?? ""})`);
    assertEqual(clean.how, "history",
      `the guard fell back to added_at on a fixture with full history (${clean.note ?? ""}); the fallback is ` +
      `for a shallow CI checkout and a fixture that silently takes it proves the weaker rule only`);
    assert(clean.checked >= 1,
      `the guard compared ${clean.checked} sibling listing(s) against the reservation; the fixture commits one ` +
      `before it and one after, so a 0 here is a walk that found nothing and passed`);

    const after = stagingRepoFixture("staging-repo-second", id, { alsoPublish: "late-arrival" });
    const dirty = stagingRepoGuard(after);
    assertEqual(dirty.problems.length, 1,
      `a second listing published from the staging repository AFTER the reservation was not reported ` +
      `(how: ${dirty.how}): ${JSON.stringify(dirty.problems)}`);
    assert(dirty.problems[0].includes("late-arrival"), `the problem does not name the listing: ${dirty.problems[0]}`);
    assert(!dirty.problems[0].includes("grandfathered-plugin"),
      `the listing that predates the reservation was reported too, which is the half of the rule that says a ` +
      `repository already hosting listings keeps them (AP-12, seam 21): ${dirty.problems[0]}`);

    // And the committed tree. Vacuous tonight and deliberately so — nothing on
    // `main` carries the staging id, so the repository it is published from is
    // not knowable from here. The fixtures above are what is actually watched;
    // this leg starts judging on the day M-T2.2's publish commit lands, with
    // no edit to this file.
    const real = stagingRepoGuard(REPO_ROOT);
    assertEqual(real.problems.join(" | "), "",
      `the committed tree publishes a listing from the staging repository that is not the staging listing ` +
      `(how: ${real.how})`);
    console.log(`        (committed tree: ${real.note ?? `${real.checked} sibling(s) checked, via ${real.how}`})`);
  });

  // ── contract §0.7 since 2.16.0: every string of every record ────────────
  //
  // minice-e4's review of its mirror writer (2026-09-25) found the hole, and
  // the client lane measured what it costs: a lone-surrogate escape in one
  // author's `permissions.<id>.reason` passed `schema/version-v1.json`, was
  // copied verbatim into the version record, and reached the signed catalogue,
  // which every Astra client parses WHOLE with serde_json before it reads an
  // entry. serde_json refuses the escape. So one manifest froze every client's
  // catalogue — and a record on `main` is write-once. Two holes, two checks,
  // two tests: `displayStrings` did not reach `permissions` (a), and nothing
  // walked the strings nobody renders (b).

  // What may be tracked as `*.json` and NOT walked by `checkRecordStrings`:
  // test data, some of it malformed on purpose, and two canary configuration
  // files. None is committed by a bot run or served. Named here rather than in
  // tools/validate.mjs, because a path that module names is a gate input by
  // TRUST-31's leg (c), and these are the opposite of one.
  const NOT_RECORDS = ["tests", "tools/testkeys", "tools/selftest", "bot/fixtures", "bot/tests"];
  const NOT_RECORD_FILES = {
    "bot/security-contact.json":
      "the privacy canary's role addresses, read by tools/priv-scan.mjs and kept off every bot run (couplings entry 104)",
    "tools/coverage/priv-scan-exempt.json": "the privacy canary's exemption list, read only by its own history walk",
  };

  const cleanListing = (name) => {
    const dir = path.join(tmp, name);
    fs.rmSync(dir, { recursive: true, force: true });
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
      path.join(dir, "plugins", "dice-roller"), { recursive: true });
    return dir;
  };
  const versionFile = (dir) => path.join(dir, "plugins", "dice-roller", "versions", "1.0.0.json");
  const editVersion = (dir, edit) => {
    const doc = JSON.parse(fs.readFileSync(versionFile(dir), "utf8"));
    edit(doc);
    // `JSON.stringify`, not the canonical serialiser: since ES2019 it writes a
    // lone surrogate as the six-character escape an author's MANIFEST.json
    // carries, and `stableStringify` now refuses to write one at all.
    fs.writeFileSync(versionFile(dir), JSON.stringify(doc, null, 2));
  };

  await test("(a) displayStrings holds a permission's words — every string under a version record's permissions and under each catalogue release's — and the validator refuses a bidi override in a reason", async () => {
    const fields = (doc) => displayStrings(doc).map(([f]) => f).join(",");
    assertEqual(
      fields({ permissions: { fire_trigger: {}, dom_access: { reason: "Draws", types: ["a"], scopes: ["session"] } } }),
      "permissions.dom_access.reason,permissions.dom_access.scopes[0],permissions.dom_access.types[0]",
      "a version record's permission strings are not all display strings");
    assertEqual(
      fields({ name: "Dice", releases: [{ permissions: { client: { reason: "Chats" } } }, { permissions: {} }] }),
      "name,releases[0].permissions.client.reason",
      "a catalogue entry's release permissions are not display strings, so the deploy candidate is not scanned for them");

    // On a tree, with the one character only this clause can see: U+202E is
    // valid Unicode, so no string walk refuses it, and it is how a consent
    // sheet shows one sentence while the record holds another.
    const control = cleanListing("perm-display-control");
    editVersion(control, (d) => { d.permissions = { dom_access: { reason: "Draws the cat over the window" } }; });
    const ok = await validateTree(control);
    assertEqual(ok.report.errors.map((e) => `${e.where} ${e.message}`).join("; "), "",
      "the fixture listing with an ordinary permission reason does not validate");
    const dir = cleanListing("perm-display-bidi");
    editVersion(dir, (d) => { d.permissions = { dom_access: { reason: "Draws the cat ‮over the window" } }; });
    const { report } = await validateTree(dir);
    assertEqual(errorsMatching(report, "permissions.dom_access.reason contains a zero-width or bidirectional").length, 1,
      `a bidi override in a permission reason was not refused:\n${report.errors.map((e) => `${e.where} ${e.message}`).join("\n")}`);
  });

  await test("(b) every record under the root is walked, and a string that is not valid I-JSON is refused wherever it is — catalogue, version, listing, publisher, decision, log, state, moderation entry, advisory — as an escape, as a literal and as a member name, while test data and foreign checkouts are not walked", async () => {
    const dir = cleanListing("record-strings");
    const put = (rel, text) => {
      const file = path.join(dir, rel);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, text);
    };
    const LONE = "\ud800";
    // Each in a member that `displayStrings` does not take, so this clause is
    // the only one that can see it.
    editVersion(dir, (d) => { d.$comment = `derived ${LONE}`; });
    const listing = JSON.parse(fs.readFileSync(path.join(dir, "plugins/dice-roller/plugin.json"), "utf8"));
    put("plugins/dice-roller/plugin.json", JSON.stringify({ ...listing, $comment: `hand-edited \udc00` }, null, 2));
    const expected = {
      "registry/v1/index.json": JSON.stringify({ signed: { schema: "astra.registry.index/1", serial: 1, plugins: [], note: LONE } }),
      "publishers/someone.json": JSON.stringify({ schema: "astra.registry.publisher/1", owner: "someone", display_name: `Some ${LONE}` }),
      "log/decisions/2026/0123456789abcdef0123456789abcdef.json": JSON.stringify({ schema: "astra.registry.decision/1", reason: `r ${LONE}` }),
      "log/rollout/R9-fixture.json": JSON.stringify({ note: [`fine`, `not ${LONE}`] }),
      "state/keepalive-fixture.json": JSON.stringify({ at: LONE }),
      "bot/moderation/2026-01-01-fixture-delist.json": JSON.stringify({ reason: `x ${LONE}` }),
      "tools/revocations/ASTRA-2026-0999.json": JSON.stringify({ id: "ASTRA-2026-0999", reason: `y ${LONE}` }),
      "state/member-name.json": JSON.stringify({ [`k${LONE}`]: 1 }),
      "log/rollout/noncharacter.json": JSON.stringify({ a: "￾" }),
    };
    for (const [rel, text] of Object.entries(expected)) put(rel, text);
    // The literal: a lone surrogate written as the three bytes it would be in
    // UTF-8, which no decoder admits and `readFileSync(…, "utf8")` quietly
    // turns into three U+FFFD.
    put("state/literal.json", Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xed, 0xa0, 0x80]), Buffer.from('"}')]));
    // Test data, which is not a record and is not walked — and what CI checks
    // out INTO the root, which is another repository's test data:
    // `build-index.yml`'s `_astra-plugins/` and `link-deps.sh`'s `_deps/`.
    for (const t of NOT_RECORDS) put(`${t}/fixture-with-a-lone-surrogate.json`, JSON.stringify({ a: LONE }));
    put(".github/fixture-with-a-lone-surrogate.json", JSON.stringify({ a: LONE }));
    put("_astra-plugins/testdata/locales/fixture-with-a-lone-surrogate.json", JSON.stringify({ a: LONE }));
    put("bot/manifest-probe/_deps/AstraPlugins/fixture-with-a-lone-surrogate.json", JSON.stringify({ a: LONE }));

    const { report } = await validateTree(dir);
    const walked = (rel) => report.errors.filter((e) => e.where === rel && / carries /.test(e.message));
    const missed = [
      ...Object.keys(expected),
      "plugins/dice-roller/versions/1.0.0.json",
      "plugins/dice-roller/plugin.json",
      "state/literal.json",
    ].filter((rel) => walked(rel).length === 0);
    assertEqual(missed.join(", "), "", "a record carrying a string no Rust reader can hold was not refused");
    assert(walked("state/literal.json")[0].message.includes("not valid UTF-8"),
      `the literal is refused for another reason: ${walked("state/literal.json")[0].message}`);
    assert(walked("state/member-name.json")[0].message.includes("(the member name)"),
      `a member name is not reported as one: ${walked("state/member-name.json")[0].message}`);
    assert(walked("log/rollout/noncharacter.json")[0].message.includes("noncharacter U+FFFE"),
      `a noncharacter is not reported as one: ${walked("log/rollout/noncharacter.json")[0].message}`);
    const overreach = report.errors.filter((e) => e.where.includes("fixture-with-a-lone-surrogate"));
    assertEqual(overreach.map((e) => e.where).join(", "), "", "test data or a foreign checkout was walked as if it were a record");
    const quoted = report.errors.filter((e) => /\p{Cs}|\p{Noncharacter_Code_Point}/u.test(`${e.where} ${e.message}`));
    assertEqual(quoted.length, 0, "a refusal carries the string it refuses, which makes the report itself unparseable");
  });

  await test("(b) on this tree the walk reads every kind of record there is, every tracked JSON file is a record or test data, and it finds nothing", () => {
    const files = recordFiles(REPO_ROOT);
    // The canary that keeps RECORD_ROOTS from going stale: the list is closed,
    // so a record directory added tomorrow is unwalked unless something says
    // so. This says so, on the day its first file is committed.
    const tracked = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z", "--", "*.json"],
      { encoding: "utf8", env: cleanEnv(), maxBuffer: 64 * 1024 * 1024 }).split("\0").filter(Boolean);
    assert(tracked.length >= 150, `git ls-files listed ${tracked.length} JSON file(s); a list that short is not this tree`);
    const walkedSet = new Set(files);
    const unaccounted = tracked.filter((f) =>
      !walkedSet.has(f) && !NOT_RECORDS.some((t) => f.startsWith(`${t}/`)) && !(f in NOT_RECORD_FILES));
    assertEqual(unaccounted.join(", "), "",
      "a tracked JSON file is neither under tools/validate.mjs's RECORD_ROOTS nor test data nor a declared canary " +
      "file, so contract §0.7's string rule does not reach it. Add its directory to RECORD_ROOTS if a bot commits " +
      "it or the registry serves it; otherwise to NOT_RECORDS here, with the reason");
    const staleNot = Object.keys(NOT_RECORD_FILES).filter((f) => !tracked.includes(f) || walkedSet.has(f));
    assertEqual(staleNot.join(", "), "", "a declared canary file is gone, or is walked after all, so its declaration excuses nothing");
    const phantom = RECORD_ROOTS.filter((r) => !fs.existsSync(path.join(REPO_ROOT, r)));
    assertEqual(phantom.join(", "), "", "RECORD_ROOTS names a path this tree does not have");
    assert(files.length >= 100, `the walk read ${files.length} file(s); a walk that short is not this tree`);
    const kinds = {
      catalogue: /^registry\/v1\/index\.json$/,
      "withdrawal list": /^registry\/v1\/revocations\.json$/,
      "trust document": /^registry\/v1\/trust\.json$/,
      "root document": /^registry\/v1\/root\.json$/,
      listing: /^plugins\/[^/]+\/plugin\.json$/,
      version: /^plugins\/[^/]+\/versions\/[^/]+\.json$/,
      publisher: /^publishers\/[^/]+\.json$/,
      "rollout log": /^log\/rollout\/[^/]+\.json$/,
      state: /^state\/[^/]+\.json$/,
      "moderation entry": /^bot\/moderation\/[^/]+\.json$/,
    };
    const absent = Object.entries(kinds).filter(([, re]) => !files.some((f) => re.test(f))).map(([k]) => k);
    assertEqual(absent.join(", "), "", "the walk does not reach a kind of record this tree holds");
    const inTestData = files.filter((f) => NOT_RECORDS.some((t) => f.startsWith(`${t}/`)));
    assertEqual(inTestData.join(", "), "", "the walk read test data");
    const found = files.flatMap((f) => recordStringProblems(fs.readFileSync(path.join(REPO_ROOT, f)))
      .map((p) => `${f} ${p.path}: ${p.problem}`));
    assertEqual(found.join("\n"), "", "a record on this tree carries a string no Rust reader can hold");
    console.log(`        (${files.length} record file(s) walked)`);
  });

  // ── contract §0.7 since 2.16.0: a version is at most 256 characters ───────
  //
  // With its pre-release and build. The plugins service refuses `len() > 256`
  // before it splits, and records on `main` are write-once, so a longer version
  // in any record the service mirrors would stop its mirror for good. The
  // number is the contract's, written here, not read from tools/lib/semver.mjs.
  const VERSION_MAX = 256;
  const V256 = `1.0.0-${"a".repeat(125)}+${"b".repeat(124)}`;
  const V257 = `${V256}b`;

  // The schemas say the bound as `maxLength`, a keyword every JSON Schema
  // reader speaks. The members are FOUND, by name and by the grammar in their
  // pattern, rather than listed, so a schema that gains a version member
  // tomorrow is asked on the day it does. `min_astra_version` is Astra's
  // version, not a plugin's, and §0.7's row is not about it.
  await test("every schema member that carries a plugin's version says contract §0.7's 256 characters as maxLength, admits a 256-character version and refuses 257 (2.16.0)", () => {
    const dir = path.join(REPO_ROOT, "schema");
    const GRAMMAR_TAIL = String.raw`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`;
    const found = new Map();
    const spelled = [];
    const walk = (node, at, file) => {
      if (Array.isArray(node)) { node.forEach((x, i) => walk(x, `${at}/${i}`, file)); return; }
      if (!node || typeof node !== "object") return;
      if (typeof node.pattern === "string" && node.pattern.endsWith(GRAMMAR_TAIL)) spelled.push(`${file} ${at}`);
      for (const [k, v] of Object.entries(node)) {
        const here = `${at}/${k}`;
        if (k === "properties" && v && typeof v === "object") {
          if (v.version && typeof v.version === "object") found.set(`${file} ${here}/version`, v.version);
          if (v.versions?.items && typeof v.versions.items === "object") found.set(`${file} ${here}/versions/items`, v.versions.items);
        }
        walk(v, here, file);
      }
    };
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
    assert(files.length >= 10, `schema/ holds ${files.length} JSON file(s); a directory that small is not this tree`);
    for (const f of files) walk(JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")), "", `schema/${f}`);

    // Measured on main df41596: these six. A walk that stops finding one has
    // broken, or the member moved and this list says where it went.
    const expected = [
      "schema/decision-v1.json /properties/version",
      "schema/hold-v1.json /properties/decision/properties/versions/items",
      "schema/index-v1.json /$defs/plugin/properties/version",
      "schema/index-v1.json /$defs/release/properties/version",
      "schema/moderation-work-v1.json /$defs/serviceDecision/properties/versions/items",
      "schema/version-v1.json /properties/version",
    ];
    const missing = expected.filter((k) => !found.has(k));
    assertEqual(missing.join("; "), "", "the walk no longer finds a schema member that carries a version");
    const unnamed = spelled.filter((k) => ![...found.keys()].includes(k));
    assertEqual(unnamed.join("; "), "",
      "a schema member spells the semver grammar under a name the walk does not treat as a version, so nothing asks it for the bound");

    const wrong = [];
    for (const [where, member] of found) {
      if (member.maxLength !== VERSION_MAX) wrong.push(`${where} has maxLength ${member.maxLength}`);
      const at256 = validateSchema(member, V256).map((e) => e.message);
      if (at256.length) wrong.push(`${where} refuses a 256-character version: ${at256.join(", ")}`);
      if (!validateSchema(member, V257).some((e) => e.message === `longer than ${VERSION_MAX} characters`)) {
        wrong.push(`${where} does not refuse a 257-character version for its length`);
      }
    }
    assertEqual(wrong.join("\n"), "", "a schema does not hold a version to contract §0.7's 256 characters");
    console.log(`        (${found.size} version member(s) in ${files.length} schema(s))`);
  });

  // tools/validate.mjs over a tree. The record stays `1.0.0.json` because a
  // version record is named after its version and no filesystem this runs on
  // stores a 261-byte name (Linux NAME_MAX is 255): the longest version a
  // record FILE can carry is 250, and `artifacts.*.filename` holds it far below
  // that. So this is a record whose name and version disagree, and what is asked
  // is only whether the LENGTH is refused, and only the length.
  await test("tools/validate.mjs refuses a version record whose version is 257 characters for its length, and does not refuse one of 256 for its length (contract §0.7, 2.16.0)", async () => {
    const lengthErrors = async (name, v) => {
      const dir = cleanListing(name);
      editVersion(dir, (d) => { d.version = v; });
      const { report } = await validateTree(dir);
      return {
        length: errorsMatching(report, `$.version longer than ${VERSION_MAX} characters`)
          .filter((e) => e.where === "plugins/dice-roller/versions/1.0.0.json"),
        all: report.errors.map((e) => `${e.where} ${e.message}`).join("\n"),
      };
    };
    const long = await lengthErrors("version-257", V257);
    assertEqual(long.length.length, 1, `a 257-character version was not refused for its length:\n${long.all}`);
    const edge = await lengthErrors("version-256", V256);
    assertEqual(edge.length.length, 0, `a 256-character version was refused for its length:\n${edge.all}`);
  });

  // ── the review mark's three rules (contract 3.0.0: B.4; DEC-19; MOD-56) ────
  //
  // Each rule is a statement about the COMMIT that added or changed a version
  // record, so each is asked of a real repository with real commits: a pre-
  // landing listing, the landing commit (the first whose schema declares
  // `review`), then one change per case. A stub would be the description of
  // the answer. Every case is also asked of the WORKING TREE, which is where
  // `bot/publish-apply.mjs` and the moderation commit job run the validator,
  // before their commit exists.
  //
  // Watched, each by one edit to tools/lib/review-mark.mjs, every other case
  // staying green:
  //   - `after !== UNREVIEWED` → `after === REVIEWED` in the committed half:
  //     "a record added after the landing commit without the mark" goes red;
  //   - the same in the working-tree half: its working-tree twin goes red;
  //   - `namesReview` returning true: "... with no moderation-log entry" red;
  //   - the trailer condition dropped from judgeMove: "... no trailer" red;
  //   - `serviceDecisionOk` returning true: "... a trailer that names nothing"
  //     red;
  //   - `before === undefined ||` dropped from judgeMove: "a pre-landing
  //     record reviewed with both" red (absent → reviewed is allowed);
  //   - `landingCommit` returning its LAST declaring commit rather than its
  //     first: "... added between two schema edits" red.
  const reviewCase = reviewMarkRepo;
  const marks = async (dir) => {
    const { report } = await validateTree(dir);
    return {
      errors: report.errors.filter((e) => /review mark|marks .* `reviewed`/.test(e.message)),
      all: report.errors.map((e) => `${e.where} ${e.message}`).join("\n"),
      notes: report.notes.filter((n) => n.where === "review marks").map((n) => n.message),
    };
  };
  const clean = (r, what) => assertEqual(r.errors.map((e) => `${e.where}: ${e.message}`).join("\n"), "", what);
  const refused = (r, file, needle, what) => {
    const hit = r.errors.filter((e) => e.where === file && e.message.includes(needle));
    assert(hit.length === 1, `${what}\n  wanted one error on ${file} containing ${JSON.stringify(needle)}; got:\n${r.all || "(none)"}`);
  };
  const V = (v) => `plugins/dice-roller/versions/${v}.json`;

  await test("review mark (B.4): a record added from the landing commit on carries `unreviewed`; one added before it needs none", async () => {
    const r = reviewCase("rm-added");
    r.addVersion("1.1.0", "unreviewed");
    r.commit("publish 1.1.0, marked");
    clean(await marks(r.dir), "a record added after the landing commit WITH the mark, and one added before it without, were refused");

    r.addVersion("1.2.0", undefined);
    r.commit("publish 1.2.0, unmarked");
    refused(await marks(r.dir), V("1.2.0"), "at or after 3.0.0's landing commit",
      "a record added after the landing commit without the mark was not refused");

    const w = reviewCase("rm-added-reviewed");
    w.addVersion("1.1.0", "reviewed");
    w.commit("publish 1.1.0, marked reviewed at birth");
    refused(await marks(w.dir), V("1.1.0"), "at or after 3.0.0's landing commit",
      "a record added already `reviewed` was not refused; the publishing commit writes `unreviewed`");
  });

  await test("review mark (B.4): the landing commit is the FIRST first-parent commit whose schema declares the member", async () => {
    // A second schema edit after the landing commit must not move the landing
    // commit forward: a record added between the two is after the landing.
    const r = reviewCase("rm-first-landing");
    r.addVersion("1.1.0", undefined);
    r.commit("publish 1.1.0, unmarked, between two schema edits");
    r.editSchema((s) => { s.description = `${s.description} (edited again)`; });
    r.commit("edit the schema again");
    refused(await marks(r.dir), V("1.1.0"), "at or after 3.0.0's landing commit",
      "a record added between the landing commit and a later schema edit was read as added before the landing");
  });

  await test("review mark (MOD-56): a move to `reviewed` needs a moderation-log review entry naming the version AND a Service-Decision trailer", async () => {
    const ok = reviewCase("rm-move-ok");
    ok.addVersion("1.1.0", "unreviewed");
    ok.commit("publish 1.1.0");
    ok.setMark("1.1.0", "reviewed");
    ok.addLog({ versions: ["1.1.0"] });
    ok.commit("moderation: review dice-roller 1.1.0", { serviceDecision: true });
    clean(await marks(ok.dir), "an M_REVIEW commit with its log entry and its trailer was refused");

    const noLog = reviewCase("rm-move-nolog");
    noLog.addVersion("1.1.0", "unreviewed");
    noLog.commit("publish 1.1.0");
    noLog.setMark("1.1.0", "reviewed");
    noLog.commit("moderation: review with no log entry", { serviceDecision: true });
    refused(await marks(noLog.dir), V("1.1.0"), "adds no moderation-log `review` entry",
      "a move to `reviewed` with no moderation-log entry was not refused");

    const otherVersion = reviewCase("rm-move-otherlog");
    otherVersion.addVersion("1.1.0", "unreviewed");
    otherVersion.commit("publish 1.1.0");
    otherVersion.setMark("1.1.0", "reviewed");
    otherVersion.addLog({ versions: ["1.0.0"] });
    otherVersion.commit("moderation: review naming another version", { serviceDecision: true });
    refused(await marks(otherVersion.dir), V("1.1.0"), "adds no moderation-log `review` entry",
      "a move to `reviewed` whose log entry names another version was not refused");

    const noTrailer = reviewCase("rm-move-notrailer");
    noTrailer.addVersion("1.1.0", "unreviewed");
    noTrailer.commit("publish 1.1.0");
    noTrailer.setMark("1.1.0", "reviewed");
    noTrailer.addLog({ versions: ["1.1.0"] });
    noTrailer.commit("moderation: review with no trailer");
    refused(await marks(noTrailer.dir), V("1.1.0"), "no `Service-Decision:` trailer",
      "a move to `reviewed` in a commit with no Service-Decision trailer was not refused");

    // A trailer is correlation, and its value has BOT-37's grammar: a
    // decision id nobody can look up names no decision.
    const badTrailer = reviewCase("rm-move-badtrailer");
    badTrailer.addVersion("1.1.0", "unreviewed");
    badTrailer.commit("publish 1.1.0");
    badTrailer.setMark("1.1.0", "reviewed");
    badTrailer.addLog({ versions: ["1.1.0"] });
    badTrailer.commit("moderation: review with a trailer that names nothing", { serviceDecision: "moderator-said-so" });
    refused(await marks(badTrailer.dir), V("1.1.0"), "no `Service-Decision:` trailer",
      "a move to `reviewed` whose Service-Decision trailer is not a decision id was not refused");
  });

  await test("review mark (B.4): a pre-landing record may be reviewed (absent → reviewed), and no commit moves the mark any other way", async () => {
    const pre = reviewCase("rm-pre-reviewed");
    pre.setMark("1.0.0", "reviewed");
    pre.addLog({ versions: ["1.0.0"] });
    pre.commit("moderation: review a version published before 3.0.0", { serviceDecision: true });
    clean(await marks(pre.dir), "an M_REVIEW of a version published before 3.0.0 (absent → reviewed) was refused");

    const back = reviewCase("rm-unreview");
    back.addVersion("1.1.0", "unreviewed");
    back.commit("publish 1.1.0");
    back.setMark("1.1.0", "reviewed");
    back.addLog({ versions: ["1.1.0"] });
    back.commit("moderation: review", { serviceDecision: true });
    back.setMark("1.1.0", "unreviewed");
    back.commit("undo the review", { serviceDecision: true });
    refused(await marks(back.dir), V("1.1.0"), "from \"reviewed\" to \"unreviewed\"",
      "a move from `reviewed` back to `unreviewed` was not refused; no decision reverses a review");

    const stamped = reviewCase("rm-backfill");
    stamped.setMark("1.0.0", "unreviewed");
    stamped.commit("backfill the mark onto a pre-3.0.0 version");
    refused(await marks(stamped.dir), V("1.0.0"), "from absent to \"unreviewed\"",
      "a pre-3.0.0 record given `unreviewed` afterwards was not refused; absence means published before the mark");

    const dropped = reviewCase("rm-drop");
    dropped.addVersion("1.1.0", "unreviewed");
    dropped.commit("publish 1.1.0");
    dropped.setMark("1.1.0", undefined);
    dropped.commit("drop the mark");
    refused(await marks(dropped.dir), V("1.1.0"), "to absent",
      "a record whose mark was removed was not refused");
  });

  await test("review mark: the working tree is held to the same rules, which is where the publish and moderation jobs validate", async () => {
    const r = reviewCase("rm-worktree");
    r.addVersion("1.1.0", undefined);
    refused(await marks(r.dir), V("1.1.0"), "is added by this change",
      "an uncommitted record added after the landing commit without the mark was not refused");
    r.addVersion("1.1.0", "unreviewed");
    clean(await marks(r.dir), "an uncommitted record added with the mark was refused");
    r.commit("publish 1.1.0");

    r.setMark("1.1.0", "reviewed");
    refused(await marks(r.dir), V("1.1.0"), "adds no moderation-log `review` entry",
      "an uncommitted move to `reviewed` with no log entry beside it was not refused");
    r.addLog({ versions: ["1.1.0"] });
    clean(await marks(r.dir), "an uncommitted move to `reviewed` with its log entry was refused (the trailer is the commit's)");
  });

  await test("review mark: before the landing commit nothing is held to it, and a tree with no git of its own says the rules were not asked", async () => {
    const r = reviewCase("rm-prelanding", { land: false });
    r.addVersion("1.1.0", undefined);
    r.commit("publish 1.1.0 before 3.0.0 lands");
    const before = await marks(r.dir);
    clean(before, "a record added before the landing commit, without the mark, was refused");
    assert(before.notes.some((n) => n.includes("landing commit is not on this line")),
      `the run did not say the tree is before the landing commit: ${JSON.stringify(before.notes)}`);

    const plain = path.join(tmp, "rm-no-git");
    fs.rmSync(plain, { recursive: true, force: true });
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(plain, "plugins", "dice-roller"), { recursive: true });
    const none = await marks(plain);
    clean(none, "a fixture directory with no git was refused over review marks");
    assert(none.notes.some((n) => n.startsWith("not asked:")),
      `a tree with no git of its own did not say the review-mark rules were not asked: ${JSON.stringify(none.notes)}`);
  });

  // ── the tree rule (tools/lib/tree-modes.mjs) ──────────────────────────────
  //
  // Each fixture is written straight into a fresh repository's object store
  // with `git hash-object --literally`, one raw tree at a time, and the branch
  // is pointed at the commit with NOTHING checked out. The working tree is
  // empty on purpose: the rule reads git's tree, so a rule that read the
  // filesystem instead would find nothing here to refuse, and every case below
  // would go red. The links are the plugins service's own examples from its
  // mirror_index review (2026-10-03).

  await test("tree rule: a link under plugins/<id>/ is refused by path and mode, and so is the link its target climbs through", async () => {
    const dir = treeFixture("tm-plugin-link", {
      plugins: { alpha: {
        "plugin.json": "{}\n",
        "identity.json": { link: "sub/../x.json" },
        sub: { link: "elsewhere" },
        "x.json": "{}\n",
      } },
    });
    assertEqual(await refusedIn(dir), ["plugins/alpha/identity.json 120000", "plugins/alpha/sub 120000"].join("\n"),
      "tools/validate.mjs must name each link under plugins/<id>/ by path and mode, and neither file beside them");
  });

  await test("tree rule: a link at policy/ is refused, and the record reached through it is never even listed", async () => {
    const dir = treeFixture("tm-policy-link", {
      policy: { link: "real-policy" },
      "real-policy": { "binding-deadline.json": "{}\n" },
      log: { up: { link: "../policy" } },
      publishers: { "someone.json": { link: "x/" } },
    });
    assertEqual(await refusedIn(dir), ["log/up 120000", "policy 120000", "publishers/someone.json 120000"].join("\n"),
      "the link at policy/, the one a log/ path climbs `..` through, and the one ending in `x/` must each be named");
    assert(!readTree(dir).rows.some((r) => r.path.startsWith("policy/")),
      "git listed a path beneath a link, so the fixture is not the shape the service found");
  });

  await test("tree rule: a directory spelled 140000 under log/ is read the way git reads it, as a gitlink, and a checkout of it is empty", async () => {
    const dir = treeFixture("tm-log-140000", {
      log: {
        "baseline.json": "{}\n",
        cutover: { mode: "140000", tree: { "cutover.json": "{}\n" } },
      },
    });
    assertEqual(await refusedIn(dir), "log/cutover 160000",
      "a raw 140000 directory is a gitlink to git, and the rule must name it as one");
    // What a reader of the filesystem would have seen instead: a directory,
    // empty, which no walk of a checkout can tell from an honest one.
    gitIn(dir, ["read-tree", "-u", "--reset", "HEAD"]);
    const cut = path.join(dir, "log", "cutover");
    assert(fs.lstatSync(cut).isDirectory() && fs.readdirSync(cut).length === 0,
      "the checkout was expected to hold log/cutover as an empty directory; the case no longer shows why the rule reads git");
  });

  await test("tree rule: a linked directory with a file reached through it is named once, at the link", async () => {
    const dir = treeFixture("tm-link-dir", {
      plugins: { alpha: { "plugin.json": "{}\n" }, beta: { link: "../elsewhere/beta" } },
      elsewhere: { beta: { "plugin.json": "{}\n" } },
    });
    assertEqual(await refusedIn(dir), "plugins/beta 120000",
      "the link must be named, and nothing beneath it, since git holds nothing beneath a link");
  });

  await test("tree rule: an empty directory, and one holding only empty ones, are refused; `git rev-list -- <path>` never counts the commit that adds them", async () => {
    const base = { queue: { "a@1.0.0.json": "{}\n" } };
    const dir = treeFixture("tm-empty", { state: base, bot: { moderation: { "entry.json": "{}\n" } } });
    commitTree(dir, {
      state: { ...base, holds: {} },
      bot: { moderation: { "entry.json": "{}\n", outer: { inner: {} } } },
    }, "adds only empty trees");
    assertEqual(gitIn(dir, ["rev-list", "--count", "--full-history", "HEAD", "--", "state", "bot/moderation"]).trim(), "1",
      "git's path-limited count saw the commit that adds only empty trees; the hole this rule closes is not the one measured");
    assertEqual(await refusedIn(dir), ["bot/moderation/outer 040000", "state/holds 040000"].join("\n"),
      "each empty directory must be named once, at its outermost: `outer` holds only the empty `inner`, so it is the entry");
  });

  await test("tree rule: files, an executable, directories and a name with a tab in it pass, and every entry is read", async () => {
    const dir = treeFixture("tm-clean", {
      plugins: { alpha: { "plugin.json": "{}\n", versions: { "1.0.0.json": "{}\n" } } },
      tools: { "run.sh": { exec: "#!/bin/sh\n" } },
      docs: { "a\tb.md": "x\n" },
    });
    assertEqual(await refusedIn(dir), "", "a tree of files and directories was refused");
    const { rows } = readTree(dir);
    assertEqual(rows.length, 9, `expected 9 entries, five of them directories: ${JSON.stringify(rows.map((r) => r.path))}`);
    assert(rows.some((r) => r.path === "docs/a\tb.md" && r.mode === "100644"), "the name with a tab was not read as one row");
    assert(rows.some((r) => r.path === "tools/run.sh" && r.mode === "100755"), "the executable was not read with its mode");
    assertEqual(treeModeProblems([{ mode: "100664", type: "blob", object: "0".repeat(40), path: "x" }]).map((p) => p.mode).join(), "100664",
      "a mode git never prints must still be refused by its number, not let through for being unknown");
  });

  await test("tree rule: this repository's own HEAD holds only files and directories, and the rule read all of it", () => {
    // Every lane that runs this suite runs it in a checkout, so a root the
    // rule cannot ask is a broken lane, not an environment to skip in.
    assertEqual(unaskableRoot(REPO_ROOT), null, "this repository's own root is not a git work tree with a HEAD");
    const items = [];
    const report = { error: (where, message) => items.push({ level: "error", where, message }),
      note: (where, message) => items.push({ level: "note", where, message }) };
    checkTreeModes({ report, root: REPO_ROOT });
    assertEqual(items.map((i) => `${i.where}: ${i.message}`).join("\n"), "",
      "HEAD holds an entry that is not a regular file or a non-empty directory, or the rule could not read it");
    const { rows } = readTree(REPO_ROOT);
    // 917 entries at e85403b (702 files, 5 executables, 210 directories). Half
    // of it, so an honest deletion is not red and an empty listing is.
    assert(rows.length >= 450, `git ls-tree listed only ${rows.length} entries at HEAD; this is a broken read`);
  });

  await test("tree rule: a directory that is not the top of a git work tree says the rule was not asked, and never that it passed", async () => {
    const plain = path.join(tmp, "tm-no-git");
    fs.rmSync(plain, { recursive: true, force: true });
    fs.mkdirSync(path.join(plain, "plugins"), { recursive: true });
    for (const root of [plain, path.join(REPO_ROOT, "tests", "fixtures", "id-collision")]) {
      const { report } = await validateTree(root);
      assertEqual(treeErrors(report).join("\n"), "", `${root}: the tree rule refused something in a tree it cannot read`);
      assert(report.notes.some((n) => n.where === "tree modes" && n.message.startsWith("not asked:")),
        `${root}: the run did not say the tree rule was not asked: ${JSON.stringify(report.notes)}`);
    }
  });

  // ── the tree rule's two bounds, and the schema lint (ops couplings 215) ──
  //
  // The plugins service reads every commit on `main` and fails closed on what
  // it cannot hold: its serial reader refuses a tree object over 8 MiB, and
  // from that commit on cannot count any path's history, and its mirror counts
  // a listing's whole subtree against a 400,000-entry cap. One commit past
  // either freezes its reading of that commit and every later one, so the
  // registry refuses well short of both, and B.4 names the two numbers.
  //
  // Each bound is held at the byte and at the entry: a tree at the bound
  // passes and one past it is refused. The wide trees are written in one
  // `hash-object --literally` each (`flatTree`), not one blob per entry, and
  // nothing is checked out, as above.

  // The numbers the contract names for the plugins service (B.4, from the
  // version after 3.4.0). They live in policy/limits.json and nowhere else in
  // this repository; this is the canary that a change there is a change to
  // what B.4 promises.
  const B4_TREE_OBJECT_BYTES = 1048576;
  const B4_LISTING_ENTRIES = 2000;

  await test("tree rule: policy/limits.json holds the two bounds B.4 names for the plugins service, 1 MiB per tree object and 2,000 entries per listing", () => {
    const limits = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "policy", "limits.json"), "utf8"));
    assertEqual(limits.max_tree_object_bytes, B4_TREE_OBJECT_BYTES,
      "max_tree_object_bytes moved; the plugins service relies on it through B.4, so the contract moves first");
    assertEqual(limits.max_listing_tree_entries, B4_LISTING_ENTRIES,
      "max_listing_tree_entries moved; the plugins service relies on it through B.4, so the contract moves first");
    // A listing at max_versions_per_plugin must still fit: its records, plus
    // plugin.json, identity.json, README.md, versions/ and every icon name
    // bot/lib/assets.mjs packs. Otherwise raising the version cap would have
    // the tree rule refuse a listing the version rule allows, naming a bound
    // its author has never heard of.
    const fullest = limits.max_versions_per_plugin + 4 + ICON_NAMES.length;
    assert(fullest <= limits.max_listing_tree_entries,
      `a listing at max_versions_per_plugin (${limits.max_versions_per_plugin}) holds up to ${fullest} entries, over ` +
      `max_listing_tree_entries (${limits.max_listing_tree_entries}); raise the entry bound with the contract, or keep the version cap`);
  });

  await test("tree rule: a tree object one byte over max_tree_object_bytes, as git stores it, is refused at its path, and one at the bound is not", async () => {
    const dir = treeFixture("tm-wide", { "README.md": "x\n" });
    const atBound = flatTree(dir, namesFilling(256, B4_TREE_OBJECT_BYTES));
    const over = flatTree(dir, namesFilling(256, B4_TREE_OBJECT_BYTES + 1));
    assertEqual(gitIn(dir, ["cat-file", "-s", atBound]).trim(), String(B4_TREE_OBJECT_BYTES),
      "the fixture's tree at the bound is not the size the case needs");
    assertEqual(gitIn(dir, ["cat-file", "-s", over]).trim(), String(B4_TREE_OBJECT_BYTES + 1),
      "the fixture's tree past the bound is not the size the case needs");
    commitTree(dir, {
      plugins: { alpha: { "plugin.json": "{}\n" } },
      docs: { "at-the-bound": { raw: atBound }, over: { raw: over } },
    }, "two wide trees");
    assertEqual(await refusedIn(dir), "docs/over 040000",
      "the tree one byte past the bound must be named, and the one at it must not");
  });

  await test("tree rule: the root tree is a tree object too, and one byte over max_tree_object_bytes refuses the commit", async () => {
    const dir = treeFixture("tm-wide-root", { "README.md": "x\n" });
    const root = flatTree(dir, namesFilling(256, B4_TREE_OBJECT_BYTES + 1));
    const commit = gitIn(dir, ["commit-tree", root, "-p", "HEAD", "-m", "a root tree one byte too wide"]).trim();
    gitIn(dir, ["update-ref", "refs/heads/main", commit]);
    assertEqual(await refusedIn(dir), "(the root tree) 040000",
      "the root tree is listed by no `ls-tree` row, and the rule must read its size all the same");
  });

  await test("tree rule: a listing holding one entry more than max_listing_tree_entries, every depth and every directory counted, is refused at plugins/<id>, and one at the bound is not", async () => {
    const dir = treeFixture("tm-entries", { "README.md": "x\n" });
    const files = flatTree(dir, Array.from({ length: B4_LISTING_ENTRIES - 2 }, (_, i) => `${String(i).padStart(4, "0")}.json`));
    commitTree(dir, {
      plugins: {
        // plugin.json, versions/ and 1,998 files: 2,000 entries.
        "at-the-bound": { "plugin.json": "{}\n", versions: { raw: files } },
        // plugin.json, versions/, versions/deep/ and the same 1,998 files:
        // 2,001 entries, only 1,999 of them files, and two at the top.
        over: { "plugin.json": "{}\n", versions: { deep: { raw: files } } },
      },
    }, "two listings, one entry apart");
    const beneath = (id) => gitIn(dir, ["ls-tree", "-r", "-t", "-z", "--name-only", "HEAD", "--", `plugins/${id}/`])
      .split("\0").filter((p) => p.startsWith(`plugins/${id}/`)).length;
    assertEqual(beneath("at-the-bound"), B4_LISTING_ENTRIES, "the listing at the bound is not the size the case needs");
    assertEqual(beneath("over"), B4_LISTING_ENTRIES + 1, "the listing past the bound is not the size the case needs");
    assertEqual(await refusedIn(dir), "plugins/over 040000",
      "the listing one entry past the bound must be named at plugins/<id>, and nothing else: not the one at the " +
      "bound, and not `plugins`, whose 4,003 entries are two listings' and no one listing's");
  });

  await test("schema lint: a pattern under schema/ that repeats one atom more than 1,000 times, by one count or nested ones, is refused by file and pointer", async () => {
    const dir = treeFixture("sp-schemas", {
      schema: {
        // The case the service measured: about 60 s a validation there.
        "heavy.json": JSON.stringify({ properties: { x: { not: { pattern: "a{100000}" } } } }),
        // At 1,000 exactly, by one count and by a product; and braces that
        // are not counts: escaped, in a class, a code point and a property.
        "fine.json": JSON.stringify({
          properties: {
            y: { pattern: "^[a-z]{0,1000}$" },
            z: { pattern: "^\\{1001\\}[{}0-9]{2}\\u{10000}\\p{L}{3}$" },
          },
          patternProperties: { "^(?:[0-9]{10}){100}$": {} },
        }),
        nested: {
          // 10 x 101: no count above 1,000, and 1,010 copies of [0-9].
          "props.json": JSON.stringify({ patternProperties: { "^(?:[0-9]{10}){101}$": {} } }),
          // An open count is its lower bound in copies.
          "open.json": JSON.stringify({ items: { pattern: "^b{1001,}$" } }),
        },
        // Not JSON Schema's to compile, so not read.
        "notes.txt": "a{100000}\n",
      },
    });
    const { report } = await validateTree(dir);
    const got = report.errors.filter((e) => e.where.startsWith("schema/"))
      .map((e) => `${e.where} ${(/ at (\/\S*)/.exec(e.message) ?? [])[1]}`).sort();
    assertEqual(got.join("\n"), [
      "schema/heavy.json /properties/x/not/pattern",
      "schema/nested/open.json /items/pattern",
      "schema/nested/props.json /patternProperties/^(?:[0-9]{10}){101}$",
    ].join("\n"), "each heavy pattern must be named by its file and its JSON pointer, and no other");
  });

  await test("schema lint: a count is read through escapes, classes and group prefixes, and multiplied through the groups it nests in", () => {
    // [pattern, copies, largest single count]
    const cases = [
      ["a{100000}", 100000, 100000],
      ["^[a-z]{0,1000}$", 1000, 1000],
      ["^b{1001,}$", 1001, 1001],
      ["^(?:[0-9]{10}){101}$", 1010, 101],
      ["((a{10}){10}){11}", 1100, 11],
      ["(a{10}|b{20}){30}", 600, 30],
      ["(?<year>[0-9]{4})-(?<=x{5})(?!y{6})z{2}?", 6, 6],
      ["^\\{1001\\}[{}0-9]{2}\\u{10000}\\p{L}{3}$", 3, 3],
      ["[\\]{]{7}", 7, 7],
      ["a*b+c?(d{4})*", 4, 4],
      ["^https://", 1, 0],
    ];
    const wrong = cases.filter(([p, copies, count]) => {
      const r = patternRepetition(p);
      return r.copies !== copies || r.count !== count;
    }).map(([p, copies, count]) => `${p}: expected ${copies} copies, largest ${count}; read ${JSON.stringify(patternRepetition(p))}`);
    assertEqual(wrong.join("\n"), "", "the scanner read a pattern's repetition wrong");
    assertEqual(MAX_PATTERN_REPETITION, 1000, "the schema lint's bound moved; tools/lib/schema-patterns.mjs says why it is 1,000");
  });

  await test("schema lint: this repository's own schemas are read at HEAD, every one, and none asks for more than the bound", () => {
    const { schemas } = readTree(REPO_ROOT);
    const tracked = gitIn(REPO_ROOT, ["ls-files", "-z", "--", "schema"]).split("\0").filter((f) => f.endsWith(".json"));
    assertEqual(schemas.length, tracked.length, `the lint read ${schemas.length} schema file(s) at HEAD and git tracks ${tracked.length} under schema/`);
    const found = schemas.flatMap((f) => schemaPatterns(JSON.parse(f.text)).map((p) => ({ ...p, ...patternRepetition(p.pattern) })));
    // 98 patterns in 15 files at 8837648, the largest count 128. Half, so an
    // honest deletion is not red and a read that finds none is.
    assert(found.length >= 49, `the lint found only ${found.length} pattern(s) in this repository's schemas; this is a broken read`);
    const heavy = found.filter((p) => Math.max(p.copies, p.count) > MAX_PATTERN_REPETITION);
    assertEqual(heavy.map((p) => `${p.pointer} ${p.pattern}`).join("\n"), "", "a schema here asks for more than the bound");
  });

  await test("schema lint: a pattern that does not compile as tools/lib/jsonschema.mjs compiles it, and a schema that is not JSON, are refused", async () => {
    const dir = treeFixture("sp-broken", {
      schema: {
        "reversed.json": JSON.stringify({ pattern: "^a{2,1}$" }),
        "torn.json": "{\"pattern\": ",
      },
    });
    const { report } = await validateTree(dir);
    assertEqual(report.errors.filter((e) => e.where.startsWith("schema/")).map((e) => e.where).sort().join("\n"),
      "schema/reversed.json\nschema/torn.json", "a pattern nothing can read and a file nothing can parse must both be refused");
  });
}

/** The tree rule's refusals in a report, as `<path> <mode>`, sorted. */
function treeErrors(report) {
  return report.errors.filter((e) => /, git mode \d{6}[ ,]/.test(e.message))
    .map((e) => `${e.where} ${/, git mode (\d{6})/.exec(e.message)[1]}`).sort();
}

/** What `tools/validate.mjs`, run whole over `dir`, refuses under the tree rule: one `<path> <mode>` a line. */
async function refusedIn(dir) {
  return treeErrors((await validateTree(dir)).report).join("\n");
}

/**
 * One raw tree for `spec`, written with `hash-object --literally` so that a
 * mode git would never write itself can be, and its id. A string is a file,
 * `{exec}` an executable, `{link}` a symlink to that target, `{mode, tree}` a
 * directory under a raw mode of the caller's, `{raw}` a directory that is the
 * tree object already written under that id, and any other object a
 * directory. Entries are in git's order, a directory sorting as its name and a
 * slash.
 */
function rawTree(dir, spec) {
  const put = (type, body) => execFileSync("git", ["-C", dir, "hash-object", "-t", type, "-w", "--literally", "--stdin"],
    { input: body, encoding: "utf8", env: fixtureEnv(dir) }).trim();
  const entries = Object.entries(spec).map(([name, v]) => {
    if (typeof v === "string") return { name, mode: "100644", sha: put("blob", v) };
    if (v.exec !== undefined) return { name, mode: "100755", sha: put("blob", v.exec) };
    if (v.link !== undefined) return { name, mode: "120000", sha: put("blob", v.link) };
    if (v.raw !== undefined) return { name, mode: "40000", sha: v.raw, dir: true };
    if (v.mode !== undefined) return { name, mode: v.mode, sha: rawTree(dir, v.tree), dir: true };
    return { name, mode: "40000", sha: rawTree(dir, v), dir: true };
  });
  const key = (e) => (e.mode === "40000" ? `${e.name}/` : e.name);
  entries.sort((a, b) => (Buffer.compare(Buffer.from(key(a)), Buffer.from(key(b)))));
  return put("tree", Buffer.concat(entries.map((e) =>
    Buffer.concat([Buffer.from(`${e.mode} ${e.name}\0`), Buffer.from(e.sha, "hex")]))));
}

/** Commit `spec` on top of HEAD (or as the first commit) and move `main` to it. Nothing is checked out. */
function commitTree(dir, spec, message) {
  const tree = rawTree(dir, spec);
  const parent = gitMaybe(dir, ["rev-parse", "--verify", "--quiet", "HEAD"])?.trim();
  const commit = gitIn(dir, ["commit-tree", tree, ...(parent ? ["-p", parent] : []), "-m", message]).trim();
  gitIn(dir, ["update-ref", "refs/heads/main", commit]);
  return commit;
}

/** A fresh repository whose `main` is one commit of `spec`, with an empty working tree. */
function treeFixture(name, spec) {
  const dir = path.join(tmp, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  gitIn(dir, ["init", "-q", "-b", "main"]);
  gitIn(dir, ["config", "user.name", "Fixture"]);
  gitIn(dir, ["config", "user.email", "fixture@example.invalid"]);
  gitIn(dir, ["config", "commit.gpgsign", "false"]);
  commitTree(dir, spec, name);
  return dir;
}

/**
 * One tree of files named `names`, every one the same blob, written in a single
 * `hash-object --literally`, and its id: the thousands of entries the bounds'
 * cases need without a spawn per entry.
 */
function flatTree(dir, names) {
  const put = (type, body) => execFileSync("git", ["-C", dir, "hash-object", "-t", type, "-w", "--literally", "--stdin"],
    { input: body, encoding: "utf8", env: fixtureEnv(dir) }).trim();
  const blob = Buffer.from(put("blob", "{}\n"), "hex");
  const sorted = [...names].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return put("tree", Buffer.concat(sorted.map((n) => Buffer.concat([Buffer.from(`100644 ${n}\0`), blob]))));
}

/**
 * `n` distinct file names whose tree entries come to exactly `total` bytes as
 * git stores the tree: an entry is `100644 <name>\0` and a 20-byte id, so its
 * name's length plus 28.
 */
function namesFilling(n, total) {
  const letters = total - 28 * n;
  const base = Math.floor(letters / n);
  return Array.from({ length: n }, (_, i) => {
    const len = base + (i < letters % n ? 1 : 0);
    return `${String(i).padStart(4, "0")}.`.padEnd(len, "x");
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// MOD-16's staging listing: the two things a tree has to keep true about it.
// ─────────────────────────────────────────────────────────────────────────────

/** Read once. The guards below ask what the registry actually reserves. */
const POLICY_RESERVED = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "policy/reserved-ids.json"), "utf8"));

const gitIn = (dir, args) =>
  execFileSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...fixtureEnv(dir), GIT_PAGER: "cat", GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0" },
  });

const gitMaybe = (dir, args) => {
  try {
    return gitIn(dir, args);
  } catch {
    return null;
  }
};

/** Every `plugins/<id>/plugin.json` on a tree, as the guards need it. */
function listingsOn(root) {
  const dir = path.join(root, "plugins");
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const name of fs.readdirSync(dir).sort()) {
    const file = path.join(dir, name, "plugin.json");
    if (!fs.existsSync(file)) continue;
    try {
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      out.push({ dir: name, id: doc.id, repo: doc.source?.repo ?? "", addedAt: doc.added_at ?? "", unlisted: doc.unlisted === true });
    } catch {
      // A listing that is not JSON is `tools/validate.mjs`'s to report, by
      // path. Swallowed here rather than thrown, because a guard about the
      // staging repository that dies on somebody else's syntax error is a
      // guard that reports nothing about its own subject.
    }
  }
  return out;
}

/**
 * **Guard (a).** Every listing published from the staging repository after the
 * commit that reserved `staging_listing_id` has exactly that id.
 *
 * ── what it is for ─────────────────────────────────────────────────────────
 *
 * The staging repository is, by construction, a repository this estate can
 * publish from without anybody reviewing the plugin: it is under `mihailinl`
 * or `MINICE-AI`, which is what lets `astra-withdrawal-canary` past the
 * reserved-prefix rule and past `bot/policy/trademarks.json`'s `astra` mark at
 * all. That permission was granted for ONE listing. A second listing from the
 * same repository inherits the whole of it — first-party prefix, first-party
 * mark, a store card that reads as ours — and inherits it silently, because
 * every rule it meets says yes.
 *
 * ── "after the reservation", and why not `added_at` first ──────────────────
 *
 * `added_at` is a field in a document somebody can write; the commit that
 * reserved the id is a fact about this repository's history, and it is the
 * line the plan draws. So the primary reading is ancestry: the commit that
 * ADDED `plugins/<id>/plugin.json` is either an ancestor of the commit that
 * introduced `staging_listing_id` — it predates the reservation and is kept
 * (AP-12's `mihailinl/AstraPlugins` branch, seam 21) — or it is not, and then
 * the listing has to be the staging one.
 *
 * `added_at` is the FALLBACK, and it exists because two of the four workflows
 * that run `tools/selftest.mjs` check out at depth 1 (`ingest.yml`,
 * `baseline.yml`); `build-index.yml` and `plugins-moderation.yml` use
 * `fetch-depth: 0`. A shallow clone cannot answer an ancestry question, and a
 * guard that went red on two of its four hosts would be switched off on all
 * four. The weaker rule still runs there, and `how` says which one answered,
 * so a fixture cannot pass by quietly taking the easier road.
 *
 * @param {string} root a repository working tree
 * @returns {{how: string, problems: string[], checked: number, note?: string}}
 */
export function stagingRepoGuard(root) {
  const policyFile = path.join(root, "policy", "reserved-ids.json");
  if (!fs.existsSync(policyFile)) {
    return { how: "no-policy", checked: 0, problems: [], note: `${policyFile} is absent` };
  }
  const id = stagingListingId(JSON.parse(fs.readFileSync(policyFile, "utf8")));
  if (id === null) {
    return { how: "no-id", checked: 0, problems: [], note: "no staging_listing_id is reserved on this tree" };
  }

  const listings = listingsOn(root);
  const staging = listings.find((l) => l.id === id);
  if (!staging) {
    return {
      how: "no-listing", checked: 0, problems: [],
      note: `no listing under ${id}, so the repository it is published from is not knowable from this tree ` +
        "(M-T2.2 publishes it; the repository name is recorded nowhere else)",
    };
  }
  const repo = String(staging.repo).toLowerCase();
  if (!repo) {
    return {
      how: "no-repo", checked: 0,
      problems: [`plugins/${staging.dir}/plugin.json carries no source.repo, so every other listing compares ` +
        "equal to an empty string and this guard would report the whole catalogue or none of it"],
    };
  }

  const siblings = listings.filter((l) => l.id !== id && String(l.repo).toLowerCase() === repo);

  const shallow = (gitMaybe(root, ["rev-parse", "--is-shallow-repository"]) ?? "true").trim() === "true";
  // `-S` over the one path: the oldest commit that changed how many times the
  // member appears in it is the commit that introduced it.
  const reservedAt = shallow ? null : (gitMaybe(root, [
    "log", "--reverse", "--format=%H", "-S", "staging_listing_id", "--", "policy/reserved-ids.json",
  ]) ?? "").split("\n").map((s) => s.trim()).filter(Boolean)[0] ?? null;

  const how = reservedAt ? "history" : "added_at";
  const problems = [];
  for (const l of siblings) {
    let after;
    if (reservedAt) {
      const addedIn = (gitMaybe(root, [
        "log", "--reverse", "--format=%H", "--diff-filter=A", "--", `plugins/${l.dir}/plugin.json`,
      ]) ?? "").split("\n").map((s) => s.trim()).filter(Boolean)[0] ?? null;
      // No adding commit means the file is uncommitted — which is "after"
      // everything, and is the shape a hand-edit arrives in.
      after = addedIn === null || gitMaybe(root, ["merge-base", "--is-ancestor", addedIn, reservedAt]) === null;
    } else {
      after = String(l.addedAt) >= String(staging.addedAt);
    }
    if (!after) continue;
    problems.push(
      `plugins/${l.dir} (id ${JSON.stringify(l.id)}) is published from ${l.repo}, the repository the staging ` +
      `listing ${JSON.stringify(id)} comes from, and was added after the id was reserved (${how}). That ` +
      "repository was made first-party for one listing; every other one it publishes inherits the `astra-` " +
      "prefix and the `astra` trademark exception without anybody deciding to grant them",
    );
  }
  return { how, checked: siblings.length, problems, note: shallow ? "shallow checkout: ancestry unavailable" : undefined };
}

/**
 * A tree holding one listing under `id`, listed or unlisted, and nothing else
 * wrong with it.
 *
 * Renamed out of the id-collision fixture the same way the reserved-id test
 * does it, with one addition: `source.repo` becomes a repository
 * `policy/reserved-ids.json` calls first-party. Without that the tree is
 * refused for the `astra-` PREFIX as well, and an assertion that counts one
 * error would be counting the wrong one.
 */
function stagingTree(name, id, { unlisted }) {
  const src = path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller");
  const dir = path.join(tmp, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.cpSync(src, path.join(dir, "plugins", id), { recursive: true });
  for (const rel of ["plugin.json", "versions/1.0.0.json"]) {
    const file = path.join(dir, "plugins", id, rel);
    // The repository pair FIRST, then the id. The release URL carries both —
    // `github.com/<repo>/releases/download/v1.0.0/<id>-1.0.0-…` — and doing
    // the id first leaves a URL under a repository nobody declared, which
    // `tools/validate.mjs` refuses for its own good reasons and which would
    // have been counted as this rule's refusal. Watched: it was.
    const renamed = fs.readFileSync(file, "utf8")
      .replaceAll("someone/dice-roller", FIRST_PARTY_REPO)
      .replaceAll("dice-roller", id);
    const doc = JSON.parse(renamed);
    if (rel === "plugin.json" && unlisted) doc.unlisted = true;
    fs.writeFileSync(file, stableStringify(doc));
  }
  return dir;
}

/** A repository `policy/reserved-ids.json` already vouches for, so only ONE rule is under test. */
const FIRST_PARTY_REPO = "mihailinl/AstraPlugins";

/**
 * A real git repository shaped like the history guard (a) reads: a listing
 * from the staging repository that PREDATES the reservation, the reservation
 * commit itself, the staging listing, and optionally one more listing from the
 * same repository afterwards.
 *
 * Real commits rather than a stub, because what is under test is a question
 * about ancestry and a stub would be the description of the answer.
 */
function stagingRepoFixture(name, id, { alsoPublish }) {
  const dir = path.join(tmp, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  gitIn(dir, ["init", "-q", "-b", "main"]);
  gitIn(dir, ["config", "user.email", "selftest@example.invalid"]);
  gitIn(dir, ["config", "user.name", "selftest"]);
  gitIn(dir, ["config", "commit.gpgsign", "false"]);

  const STAGING_REPO = "mihailinl/astra-staging-fixture";
  const listing = (dir_, doc) => {
    fs.mkdirSync(path.join(dir, "plugins", dir_), { recursive: true });
    fs.writeFileSync(path.join(dir, "plugins", dir_, "plugin.json"), stableStringify(doc));
  };
  const policy = (extra) => {
    fs.mkdirSync(path.join(dir, "policy"), { recursive: true });
    fs.writeFileSync(path.join(dir, "policy", "reserved-ids.json"),
      stableStringify({ reserved: [], reserved_prefixes: ["astra-"], ...extra }));
  };
  const commit = (message) => { gitIn(dir, ["add", "-A"]); gitIn(dir, ["commit", "-q", "-m", message]); };

  policy({});
  listing("grandfathered-plugin", {
    id: "grandfathered-plugin", source: { kind: "github", repo: STAGING_REPO }, added_at: "2026-01-01",
  });
  commit("a listing from the repository, before anything is reserved");

  policy({ staging_listing_id: id });
  commit("reserve the staging listing id");

  listing(id, { id, source: { kind: "github", repo: STAGING_REPO }, added_at: "2026-09-21", unlisted: true });
  commit("publish the staging listing");

  if (alsoPublish) {
    listing(alsoPublish, {
      id: alsoPublish, source: { kind: "github", repo: STAGING_REPO }, added_at: "2026-09-22",
    });
    commit("a second listing from the staging repository");
  }
  return dir;
}

/**
 * A repository for the review mark's rules: the id-collision fixture's
 * `dice-roller` listing at 1.0.0 with no mark, committed with a
 * schema/version-v1.json that does not declare `review`; then, unless
 * `land: false`, the landing commit, whose schema does. The schema is this
 * repository's own file with the member removed and restored, so the
 * landing commit is found by B.4's recipe and not by a flag.
 */
function reviewMarkRepo(name, { land = true } = {}) {
  const dir = path.join(tmp, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  gitIn(dir, ["init", "-q", "-b", "main"]);
  gitIn(dir, ["config", "user.email", "selftest@example.invalid"]);
  gitIn(dir, ["config", "user.name", "selftest"]);
  gitIn(dir, ["config", "commit.gpgsign", "false"]);
  fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
    path.join(dir, "plugins", "dice-roller"), { recursive: true });
  const schemaFile = path.join(dir, "schema", "version-v1.json");
  const full = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/version-v1.json"), "utf8"));
  const writeSchema = (doc) => {
    fs.mkdirSync(path.dirname(schemaFile), { recursive: true });
    fs.writeFileSync(schemaFile, `${JSON.stringify(doc, null, 2)}\n`);
  };
  const pre = structuredClone(full);
  delete pre.properties.review;
  writeSchema(pre);
  const versions = path.join(dir, "plugins", "dice-roller", "versions");
  const base = JSON.parse(fs.readFileSync(path.join(versions, "1.0.0.json"), "utf8"));
  let logs = 0;
  const r = {
    dir,
    commit(message, { serviceDecision = false } = {}) {
      gitIn(dir, ["add", "-A"]);
      const value = typeof serviceDecision === "string" ? serviceDecision : "01923456-7890-7abc-8def-0123456789ab";
      const body = serviceDecision ? ["-m", `Service-Decision: ${value}`] : [];
      gitIn(dir, ["commit", "-q", "--allow-empty", "-m", message, ...body]);
    },
    addVersion(v, review) {
      const doc = JSON.parse(JSON.stringify(base).replaceAll("1.0.0", v));
      if (review !== undefined) doc.review = review;
      fs.writeFileSync(path.join(versions, `${v}.json`), stableStringify(doc));
    },
    setMark(v, review) {
      const file = path.join(versions, `${v}.json`);
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      if (review === undefined) delete doc.review;
      else doc.review = review;
      fs.writeFileSync(file, stableStringify(doc));
    },
    addLog({ versions: named }) {
      logs += 1;
      const at = path.join(dir, "bot", "moderation");
      fs.mkdirSync(at, { recursive: true });
      fs.writeFileSync(path.join(at, `2026-09-27-dice-roller-review${logs > 1 ? `-${logs}` : ""}.json`), stableStringify({
        date: "2026-09-27", action: "review", plugin: "dice-roller", versions: named,
        reason: "A moderator read these versions' code and found nothing to act on.",
        category: "review_passed", service_decision_id: "01923456-7890-7abc-8def-0123456789ab",
      }));
    },
    editSchema(fn) {
      const doc = JSON.parse(fs.readFileSync(schemaFile, "utf8"));
      fn(doc);
      writeSchema(doc);
    },
  };
  r.commit("a listing published before 3.0.0");
  if (land) {
    writeSchema(full);
    r.commit("3.0.0's landing commit: the schema declares review");
  }
  return r;
}
