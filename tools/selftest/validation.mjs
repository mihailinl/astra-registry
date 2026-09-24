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
import { fixtureEnv } from "../lib/git-env.mjs";

import { runValidation } from "../validate.mjs";
import { buildIndex } from "../build-index.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { compareSemver } from "../lib/semver.mjs";
import { REPO_ROOT, loadSources } from "../lib/sources.mjs";
import { stagingListingId } from "../lib/reserved.mjs";
import { RESERVED_KEYS, SUPPORTED_KEYS, platformKeyFromManifest } from "../lib/platform.mjs";
import { CODES } from "../../bot/lib/codes.mjs";
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
