// The committed catalogue is exactly what the generator produces.
//
// It opens with the serial test, which prints under the previous module's
// "zip reader/writer" header and must keep doing so: the section comments and
// the module boundaries are not the same line, and the printed order is the
// thing under test.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { cleanEnv, fixtureEnv } from "../lib/git-env.mjs";

import { buildIndex, resolveSerial } from "../build-index.mjs";
import { isShallow } from "../coverage/git.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { validate as validateSchema } from "../lib/jsonschema.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, neverAsk, tmp, validateTree, errorsMatching } from "./harness.mjs";

export async function run() {
  await test("the serial counts the commit being made, not the one behind it", () => {
    // `resolveSerial` counts commits touching `plugins/`. At the moment
    // `ingest.yml` regenerates the index its own catalogue change is STAGED, so
    // the count of history is one short of the document being written — and every
    // publish shipped the PREVIOUS catalogue's serial until a follow-up run
    // corrected it. Measured on four consecutive publishes before this was fixed:
    // 30/31, then 31 corrected; 31/32, then 32 corrected. Two catalogues, one
    // serial, both deployed.
    //
    // A temporary git repository, because the real one's cleanliness is not this
    // test's to depend on and a probe file under `plugins/` in the real tree
    // would be a catalogue entry. Under the suite's `tmp`, so a failed assertion
    // below (which skips the `rmSync` at the end) does not leave it in `/tmp`.
    const dir = fs.mkdtempSync(path.join(tmp, "serial-"));
    const git = (...a) => execFileSync("git", a, { cwd: dir, stdio: ["ignore", "pipe", "ignore"], env: fixtureEnv(dir) });
    git("init", "-q");
    git("config", "user.email", "t@example.invalid");
    git("config", "user.name", "t");
    fs.mkdirSync(path.join(dir, "plugins"), { recursive: true });
    fs.writeFileSync(path.join(dir, "plugins", "a.txt"), "one\n");
    git("add", "-A"); git("commit", "-qm", "one");
    assert(resolveSerial({ root: dir }) === 1, "a clean tree counts its own history");

    fs.writeFileSync(path.join(dir, "plugins", "b.txt"), "two\n");
    assert(resolveSerial({ root: dir }) === 2,
      "a pending change under plugins/ is the commit about to be made and must be counted");

    // TWO pending files are still ONE commit. Without this line the obvious wrong
    // implementation — count the dirty entries rather than add one — passes:
    // measured, it did, and the single-file case above could not tell them apart.
    // A publish touches `plugin.json`, a `versions/*.json` and often a README, so
    // that mistake would have shipped a serial three ahead and then a follow-up
    // run pulling it back down. A monotonic counter that goes backwards is worse
    // than one that lags.
    fs.writeFileSync(path.join(dir, "plugins", "c.txt"), "three\n");
    assert(resolveSerial({ root: dir }) === 2,
      "two pending files under plugins/ are still one commit — the serial counts commits, not files");
    fs.rmSync(path.join(dir, "plugins", "c.txt"));

    // A change OUTSIDE plugins/ is not a catalogue change and must not move it.
    fs.rmSync(path.join(dir, "plugins", "b.txt"));
    fs.writeFileSync(path.join(dir, "README.md"), "docs\n");
    assert(resolveSerial({ root: dir }) === 1,
      "a change outside plugins/ is not a catalogue change and must not bump the serial");

    // And an explicit value still wins, because build-index.yml passes one.
    assert(resolveSerial({ root: dir, explicit: 41 }) === 41, "--serial must override");
    fs.rmSync(dir, { recursive: true, force: true });
  });

  console.log("\nthe real registry");
  await test("index.json is byte-identical to a fresh generation", () => {
    const committed = fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8");
    const regenerated = stableStringify(buildIndex({ serial: JSON.parse(committed).signed.serial }));
    assert(committed === regenerated, "registry/v1/index.json is not what tools/build-index.mjs produces");
  });
  // A catalogue-wide canary for the bug above, on the real document rather than a
  // fixture. The predicate is proved able to fail on the very next line, because
  // today's catalogue is all ASCII and an assertion that cannot fail is not one.
  await test("no string in the catalogue is half a character, and the check can see one", () => {
    const committed = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    const doc = buildIndex({ serial: committed.signed.serial });
    assert(doc.signed.plugins.length > 0, "an empty catalogue would pass this by having nothing in it");
    const lone = /\\u[dD][89abAB]/;
    assert(!lone.test(stableStringify(doc)),
      "a lone surrogate escape is in the catalogue; serde_json refuses the whole document, not the listing");
    const corrupted = JSON.parse(JSON.stringify(doc));
    corrupted.signed.plugins[0].name += "\ud83c";
    // `JSON.stringify` writes the escape the predicate is looking for, so the
    // predicate can see one. `stableStringify` no longer writes it at all
    // (contract §0.7, 2.16.0): it refuses the document, which is stronger than
    // the assertion above and is asked in tools/selftest/primitives.mjs.
    assert(lone.test(JSON.stringify(corrupted)),
      "the predicate cannot see a lone surrogate at all, so the assertion above was decoration");
    let refused = null;
    try { stableStringify(corrupted); } catch (e) { refused = String(e.message); }
    assert(refused !== null && refused.includes("unpaired surrogate"),
      `the canonical serialiser wrote a catalogue carrying half a character: ${refused ?? "it wrote it"}`);
  });

  // (c) of contract 2.16.0: the generator of the signed catalogue does not
  // emit a document that carries a string no client can parse. The measured
  // way in was an author's permission reason, copied verbatim into the version
  // record and from there into `releases[].permissions`; the validator and the
  // bot refuse it earlier (tools/selftest/validation.mjs, bot/tests/ingest.test.mjs),
  // and this is the line that holds when a path round both of them did not,
  // because nothing after it can repair a signed document.
  await test("(c) the generator refuses to emit a catalogue carrying a string that is not valid Unicode, and names the listing", () => {
    const dir = path.join(tmp, "catalogue-lone-surrogate");
    const mk = (reason) => {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
        path.join(dir, "plugins", "dice-roller"), { recursive: true });
      const file = path.join(dir, "plugins", "dice-roller", "versions", "1.0.0.json");
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      doc.permissions = { dom_access: { reason } };
      fs.writeFileSync(file, JSON.stringify(doc, null, 2));
    };
    mk("Draws the cat over the window");
    const good = buildIndex({ root: dir, serial: 1 });
    assertEqual(good.signed.plugins[0].releases[0].permissions.dom_access.reason, "Draws the cat over the window",
      "the fixture's permission reason does not reach the catalogue, so refusing it below would prove nothing");
    for (const [what, reason] of [["an unpaired surrogate", "Draws \ud800"], ["a noncharacter", "Draws ￿"]]) {
      mk(reason);
      let thrown = null;
      try {
        buildIndex({ root: dir, serial: 1 });
      } catch (e) {
        thrown = String(e.message);
      }
      assert(thrown !== null && thrown.includes("not valid Unicode") && thrown.includes("(dice-roller)") &&
        thrown.includes("permissions.dom_access.reason"),
        `the generator emitted a catalogue carrying ${what}, or refused it without naming where: ${thrown ?? "it generated"}`);
    }
  });
  await test("index.json validates against schema/index-v1.json", () => {
    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    const errs = validateSchema(schema, doc);
    assert(errs.length === 0, errs.map((e) => `${e.path} ${e.message}`).join("\n"));
  });

  // BOT-79, all three refusals on one fixture.
  //
  // The defect: `tools/build-index.mjs` passed a listing's `icon_url` straight
  // into the signed catalogue whenever no icon file was committed, and
  // `schema/index-v1.json` said out loud that it would carry one — "an
  // `https://` URL for an older hand-written listing … deliberately
  // unpatterned". So one hand-written listing could put a host of its author's
  // choosing inside the signed document, and every store card drawn from it
  // announces the reader to that host and shows unauthenticated bytes beside
  // authenticated ones.
  //
  // Three refusals rather than one because each is reached by a different
  // route: a submission meets the validator, a regeneration on `main` meets
  // the generator, and a hand-edited `registry/v1/index.json` meets only the
  // schema. Watched by restoring the generator's pass-through and the schema's
  // unpatterned string.
  await test("an https icon_url is refused by the validator, the generator and the schema (BOT-79)", async () => {
    const dir = path.join(tmp, "bot79-icon-url");
    const mk = (id, extra) => {
      const d = path.join(dir, "plugins", id);
      fs.mkdirSync(path.join(d, "versions"), { recursive: true });
      fs.writeFileSync(path.join(d, "plugin.json"), JSON.stringify({
        schema: "astra.registry.plugin/1",
        id, name: "Dice Roller", summary: "Roll dice", license: "MIT",
        source: { kind: "github", repo: `someone/${id}` },
        added_at: "2026-08-10", description: "Roll dice", author: { name: "A Stranger" },
        ...extra,
      }, null, 2));
      fs.writeFileSync(path.join(d, "versions", "0.1.0.json"), JSON.stringify({
        schema: "astra.registry.version/1", id, version: "0.1.0",
        published_at: "2026-08-10T00:00:00Z",
        release: { kind: "github_release", repo: `someone/${id}`, tag: "v0.1.0" },
        staging: true, staging_reason: "selftest fixture: no release to pin",
        artifacts: {
          "linux-x64": {
            url: `https://github.com/someone/${id}/releases/download/v0.1.0/${id}-0.1.0-linux-x64.astraplugin`,
            filename: `${id}-0.1.0-linux-x64.astraplugin`,
          },
        },
      }, null, 2));
    };
    mk("dice-roller", { icon_url: "https://icons.example.invalid/dice.png" });

    const { report } = await validateTree(dir, { allowStaging: true });
    assertEqual(errorsMatching(report, "icon_url").length, 1,
      `the validator accepted a listing whose picture is fetched from the author's host:\n${
        report.errors.map((e) => `${e.where} ${e.message}`).join("\n")}`);
    assertEqual(report.errors.length, 1,
      `the fixture tree is failing for some other reason as well, so the assertion above proves less than it ` +
      `looks:\n${report.errors.map((e) => `${e.where} ${e.message}`).join("\n")}`);

    let thrown = null;
    try {
      buildIndex({ root: dir, serial: 1 });
    } catch (e) {
      thrown = String(e.message);
    }
    assert(thrown !== null && thrown.includes("icon_url"),
      `the generator rendered a listing carrying icon_url instead of refusing it: ${thrown ?? "it generated cleanly"}`);

    // The same tree WITHOUT the field generates, which is what makes the two
    // refusals above about `icon_url` rather than about the fixture.
    fs.rmSync(path.join(dir, "plugins", "dice-roller"), { recursive: true, force: true });
    mk("dice-roller", {});
    const doc = buildIndex({ root: dir, serial: 1 });
    assertEqual(doc.signed.plugins.length, 1, "the fixture stopped producing an entry at all");
    assertEqual(doc.signed.plugins[0].icon_url, "", "a listing with no icon must carry the empty string");

    // The schema's own half, on the document rather than on the sources: a
    // hand-edited `registry/v1/index.json` never passes through either check
    // above. Both directions, so the pattern is not merely refusing everything.
    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
    const committed = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    const withIcon = (value) => {
      const copy = JSON.parse(JSON.stringify(committed));
      copy.signed.plugins[0].icon_url = value;
      return validateSchema(schema, copy).map((e) => `${e.path} ${e.message}`);
    };
    assert(withIcon("https://icons.example.invalid/dice.png").length > 0,
      "schema/index-v1.json still admits an https icon in the signed catalogue");
    assert(withIcon("data:text/html;base64,PHNjcmlwdD4=").length > 0,
      "schema/index-v1.json admits a data: URI that is not an image, which a card would render as markup");
    assertEqual(withIcon("").length, 0, "a listing with no picture must still validate");
    assertEqual(withIcon("data:image/png;base64,iVBORw0KGgo=").length, 0,
      "the pattern refuses the data: URI tools/build-index.mjs actually writes");
  });

  // INV-29. The two fields this registry does not keep, on the document rather
  // than in the generator.
  //
  // `tools/build-index.mjs` writes `downloads: 0` and `stars: 0` as literals
  // and the schema says "Always 0" in both descriptions, so the only thing
  // that can put a number there is a hand edit to `registry/v1/index.json` —
  // which is exactly the edit this row is for. A count in a signed catalogue
  // is a claim the registry has no way to substantiate and no way to correct:
  // there is no telemetry behind it, a store sorts by it, and the first
  // listing to carry one is ranked above every honest listing for as long as
  // the document is served.
  await test("no listing in the signed catalogue claims a download or a star (INV-29)", () => {
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    assert(doc.signed.plugins.length >= 5,
      `${doc.signed.plugins.length} entries — a broken read passes any rule below it`);
    const counted = doc.signed.plugins
      .filter((p) => p.downloads !== 0 || p.stars !== 0)
      .map((p) => `${p.id}: downloads=${JSON.stringify(p.downloads)} stars=${JSON.stringify(p.stars)}`);
    assertEqual(counted.join("\n"), "",
      `a signed listing carries a popularity number this registry does not measure:\n${counted.join("\n")}`);
  });

  // INV-39. Where the bytes come from, checked against the entry's OWN source.
  //
  // `tools/validate.mjs` already holds every artifact URL to a prefix — but to
  // the prefix its own `release` object implies, which is a different claim in
  // two ways: a `direct` release anchors itself to any `base_url` it likes,
  // and a `github_release` may name a repo that is not the listing's
  // `source.repo`. Both are the same picture to a user: a card that says one
  // repository and downloads from another. This asks the signed document the
  // question the card asks, and it is the registry's leg of the artifact-host
  // row rather than the submission's.
  await test("every artifact in the catalogue comes from the repository its card names (INV-39)", () => {
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    const wrong = [];
    let urls = 0;
    for (const entry of doc.signed.plugins) {
      const repo = entry.source?.repo;
      assert(typeof repo === "string" && repo.includes("/"), `${entry.id} has no source.repo to be held to`);
      const prefix = `https://github.com/${repo}/releases/download/`;
      const seen = [
        ...(entry.download_url ? [["download_url", entry.download_url]] : []),
        ...Object.entries(entry.platform_downloads ?? {}),
        ...(entry.releases ?? []).flatMap((r) =>
          Object.entries(r.artifacts ?? {}).map(([k, a]) => [`releases[${r.version}].${k}`, a.url])),
      ];
      for (const [where, url] of seen) {
        urls++;
        if (!String(url).startsWith(prefix)) wrong.push(`${entry.id} ${where}: ${url} is not under ${prefix}`);
      }
    }
    // Two floors, because one loop nested in another can empty at either
    // level: a catalogue with no entries and a catalogue whose entries have no
    // artifacts both make the check above vacuous, and they look identical
    // from the assertion's side.
    assert(doc.signed.plugins.length >= 5, `${doc.signed.plugins.length} entries is a broken read, not a small catalogue`);
    assert(urls >= 20, `${urls} artifact URL(s) were examined; the walk into releases[] has stopped finding them`);
    assertEqual(wrong.join("\n"), "",
      `a signed listing downloads from somewhere other than the repository it names:\n${wrong.join("\n")}`);
  });

  // The serial does not move for every change, and the signer only publishes
  // on one that rose.
  //
  // `resolveSerial` counts commits under `plugins/`, so a commit that changes
  // what the catalogue RENDERS without touching a listing — this generator, a
  // policy file, a publisher record — leaves the number where it was. The
  // daemon replaces its set on a strictly greater serial, so the new bytes sit
  // in `main` while every client keeps the old ones, and nothing anywhere says
  // so. The fix is never to suppress the difference: it is to know, at the
  // commit that makes it, that publication waits for the next listing change.
  //
  // `publisher` is excluded deliberately. `bot/recheck-publishers.mjs` moves a
  // badge on a schedule with no listing commit behind it, so including it
  // would turn an honest hourly job red; the cost is that a badge change waits
  // for the next serial too, which is the same wait and a smaller consequence.
  await test("an equal serial means an equal catalogue, or the served one stays until the serial rises", () => {
    const git = (...a) => {
      try {
        return execFileSync("git", ["-C", REPO_ROOT, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: cleanEnv() });
      } catch {
        return null;
      }
    };
    // GAP 81. Both sides of this comparison are history, so a shallow checkout
    // holds neither, and until 2026-09-22 this printed `ok` there.
    //
    // Measured at 97c0b0d, in file:// clones with origin removed. At depth 1
    // `HEAD^` is not in the checkout, so the check printed "(no parent commit
    // here — a shallow checkout or the first commit — so nothing to compare)"
    // and then `ok`, which is how `ingest.yml`'s `selftest` job counted it.
    // At depth 2 the parent IS there, and that was worse: `resolveSerial`
    // counted the 1 fetched commit under plugins/ where the whole history
    // counts 52, so the check printed "(serial 52 → 1: the catalogue's version
    // rose, so a difference publishes)" and `ok`. That is not a parent
    // missing. It is a wrong number, read as the serial rising. Neither run
    // compared a single listing.
    //
    // So the question is asked first, of the checkout, the way
    // `tools/coverage/git.mjs`'s `isShallow` asks it (it throws when git
    // cannot answer, so an unanswered question never reads as "not shallow").
    // No red comes before it, unlike the flag check in revocations.mjs,
    // because nothing here is askable at any depth: a serial counted in a
    // shallow checkout is not the history's, so neither an equal one nor an
    // unequal one says anything about the catalogue. The runner finds this
    // check by reading it (a `neverAsk(` first in the block of an `if` whose
    // whole condition is the shallowness question), prints the live lanes that
    // ask it and fails when there are none. Keep the gate written that way.
    if (isShallow(REPO_ROOT)) {
      neverAsk(
        "this checkout is shallow, so neither side of the comparison is in it: at depth 1 HEAD's parent and the " +
        "catalogue committed there are not fetched, and at any depth the serial is `git rev-list --count` over " +
        "plugins/, which counts only the commits this checkout holds (1 against the whole history's 52 at " +
        "97c0b0d), so an equal serial reads as a risen one and nothing is compared",
        "a checkout with its whole history asks it: the runner prints the live lanes that reach this suite with " +
        "it under the totals and goes red when there are none (`node tools/selftest.mjs --lanes`)",
      );
    }
    // `HEAD^` is the parent on a push and the BASE on a pull request, because
    // the merge commit `actions/checkout` builds has the base as its first
    // parent. One expression for both, rather than a `GITHUB_BASE_REF` branch
    // that is only exercised in CI.
    const base = git("rev-parse", "--verify", "HEAD^")?.trim();
    if (!base) {
      // With the whole history, only a root commit has no parent: the history
      // is all here and no earlier catalogue is in it.
      console.log("      (no parent commit: this is the first commit, so there is no earlier catalogue to compare)");
      return;
    }
    const baseText = git("show", `${base}:registry/v1/index.json`);
    if (baseText === null) {
      console.log(`      (${base.slice(0, 12)} carries no registry/v1/index.json, so there is nothing to compare)`);
      return;
    }
    const baseDoc = JSON.parse(baseText);
    const serial = resolveSerial({ root: REPO_ROOT });
    if (baseDoc.signed.serial !== serial) {
      console.log(`      (serial ${baseDoc.signed.serial} → ${serial}: the catalogue's version rose, so a difference publishes)`);
      return;
    }
    // ID-77's introduction, and only that. The generator learned `owner_id`
    // after 28 listings already had identity records, so the commit teaching
    // it renders them differently at an unchanged serial, and nothing under
    // plugins/ could honestly move with it. That content waits, as TRUST-28
    // means it to: the signer carries the served catalogue until the next
    // listing change raises the serial, and the owner ids publish then. The
    // pass is for a base catalogue that carries no `owner_id` at all, i.e. one
    // generated before the member existed; once any committed catalogue
    // carries one, an equal-serial change of it is red like any other.
    const beforeOwnerIds = baseDoc.signed.plugins.some((e) => Object.hasOwn(e, "owner_id"));
    if (!beforeOwnerIds) {
      console.log("      (the base catalogue predates `owner_id` (ID-77), so its first appearance is not compared; " +
        "it publishes when the next listing change raises the serial)");
    }
    const strip = (entry) => {
      const { publisher, ...rest } = entry;
      if (!beforeOwnerIds) delete rest.owner_id;
      return rest;
    };
    const before = stableStringify(baseDoc.signed.plugins.map(strip)).split("\n");
    const after = stableStringify(buildIndex({ root: REPO_ROOT, serial }).signed.plugins.map(strip)).split("\n");
    let first = null;
    for (let i = 0; i < Math.max(before.length, after.length); i++) {
      if (before[i] !== after[i]) {
        first = `first difference at line ${i + 1}:\n  ${base.slice(0, 12)}: ${before[i] ?? "<end>"}\n  HEAD:         ${after[i] ?? "<end>"}`;
        break;
      }
    }
    assertEqual(first, null,
      `this commit renders a different catalogue at the SAME serial (${serial}), so the signer will keep serving ` +
      `the one clients already have until some listing change bumps the number. Either make the change under ` +
      `plugins/ in the same commit, or expect the content to wait.\n${first}`);
  });

  // And the catalogue on disk, because the three rules above are about what
  // may be written and this is about what IS written. It is the row the
  // renderers' legs (the client plan's C1.5, SERVE-96) are entitled to assume.
  await test("every icon in the committed catalogue is inlined bytes, not somebody's host", () => {
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    assert(doc.signed.plugins.length >= 5,
      `${doc.signed.plugins.length} entries in the catalogue — an empty or broken read passes any rule below it`);
    const remote = doc.signed.plugins
      .filter((p) => p.icon_url !== "" && !p.icon_url.startsWith("data:image/"))
      .map((p) => `${p.id}: ${p.icon_url.slice(0, 60)}`);
    assertEqual(remote.length, 0,
      `a signed store card fetches its picture from a host the author chose:\n${remote.join("\n")}`);
  });

  // ── the review mark (contract 3.0.0: B.4's review-mark paragraph; DEC-19) ──
  //
  // The catalogue is where clients and the panel read the mark, and the copy
  // has to exist before anything writes one: B.4's "the generator learns the
  // member first". A generator that dropped the member would publish every
  // release as though it predated 3.0.0, which reads as "no warning" (decision
  // D4), and the release a warning exists for would ship without one. So the
  // copy is held here against a tree carrying all three states, absent
  // included, and the absent one is held to STAY absent: a default written by
  // the generator would warn on every listing published before the mark
  // existed, or silence one nobody gave.
  //
  // Watched: deleting the `review` spread in `releaseRecord` turns the first
  // assertion red; replacing it with `review: doc.review ?? "unreviewed"` turns
  // the absent-stays-absent one red; deleting `review` from
  // schema/index-v1.json's release turns the schema one red.
  await test("the generator copies each version record's review mark into releases[] byte for byte, and writes none where the record has none (B.4)", () => {
    const dir = path.join(tmp, "review-mark-copy");
    fs.rmSync(dir, { recursive: true, force: true });
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
      path.join(dir, "plugins", "dice-roller"), { recursive: true });
    const versions = path.join(dir, "plugins", "dice-roller", "versions");
    const base = JSON.parse(fs.readFileSync(path.join(versions, "1.0.0.json"), "utf8"));
    const at = (v, review) => {
      const doc = JSON.parse(JSON.stringify(base).replaceAll("1.0.0", v));
      if (review !== undefined) doc.review = review;
      fs.writeFileSync(path.join(versions, `${v}.json`), stableStringify(doc));
    };
    at("1.1.0", "unreviewed");
    at("1.2.0", "reviewed");

    const entry = buildIndex({ root: dir, serial: 1 }).signed.plugins.find((p) => p.id === "dice-roller");
    assert(entry, "the fixture listing is not in its own catalogue");
    const marks = Object.fromEntries(entry.releases.map((r) => [r.version, Object.hasOwn(r, "review") ? r.review : "<absent>"]));
    assertEqual(JSON.stringify(marks), JSON.stringify({ "1.2.0": "reviewed", "1.1.0": "unreviewed", "1.0.0": "<absent>" }),
      "the catalogue's releases do not carry each version record's review mark as the record has it");

    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
    const doc = buildIndex({ root: dir, serial: 1 });
    const errs = validateSchema(schema, doc);
    assert(errs.length === 0, `schema/index-v1.json refuses a catalogue whose releases carry the mark:\n` +
      errs.map((e) => `${e.path} ${e.message}`).join("\n"));
    // And the member is DECLARED, not merely tolerated: a value this registry
    // never writes is refused, so the schema is the writer's statement.
    doc.signed.plugins.find((p) => p.id === "dice-roller").releases[0].review = "approved";
    assert(validateSchema(schema, doc).length > 0,
      "schema/index-v1.json accepts a review mark outside the two this registry writes, so it does not declare the member");
  });

  // ── the tools a release declares Low (`[tools.danger]`, Astra #377) ─────────
  //
  // Astra runs a Low tool of a `reviewed` release without asking, so clients
  // and the panel are shown the list the review covered. The copy is the
  // review mark's: byte for byte where the record carries it, `[]` included
  // (present = probed; Astra honours a Low tool only where the index lists it),
  // absent where it does not, so no record without it moves a byte of
  // `signed.plugins`. The
  // validator holds the record's one written form (sorted, no blank name).
  //
  // Watched: deleting the `low_tools` spread in `releaseRecord` turns the first
  // assertion red; deleting `low_tools` from schema/index-v1.json's release
  // turns the schema one red (additionalProperties); deleting the sortedness
  // check in tools/validate.mjs turns the unsorted one red; putting
  // `maxItems: 64` back on schema/version-v1.json turns the no-caps one red.
  await test("the generator copies each version record's low_tools into releases[], `[]` included, absent stays absent, and the validator holds them sorted and no more", async () => {
    const dir = path.join(tmp, "low-tools-copy");
    fs.rmSync(dir, { recursive: true, force: true });
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
      path.join(dir, "plugins", "dice-roller"), { recursive: true });
    const versions = path.join(dir, "plugins", "dice-roller", "versions");
    const base = JSON.parse(fs.readFileSync(path.join(versions, "1.0.0.json"), "utf8"));
    const at = (v, lowTools) => {
      const doc = JSON.parse(JSON.stringify(base).replaceAll("1.0.0", v));
      if (lowTools !== undefined) doc.low_tools = lowTools;
      fs.writeFileSync(path.join(versions, `${v}.json`), stableStringify(doc));
    };
    at("1.1.0", ["roll", "wipe"]);
    at("1.2.0", []);

    const doc = buildIndex({ root: dir, serial: 1 });
    const entry = doc.signed.plugins.find((p) => p.id === "dice-roller");
    assert(entry, "the fixture listing is not in its own catalogue");
    const lows = Object.fromEntries(entry.releases.map((r) => [r.version, Object.hasOwn(r, "low_tools") ? r.low_tools : "<absent>"]));
    assertEqual(JSON.stringify(lows), JSON.stringify({ "1.2.0": [], "1.1.0": ["roll", "wipe"], "1.0.0": "<absent>" }),
      "the catalogue's releases do not carry each version record's low_tools as the record has it");
    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
    const errs = validateSchema(schema, doc);
    assert(errs.length === 0, `schema/index-v1.json refuses a catalogue whose releases carry low_tools:\n` +
      errs.map((e) => `${e.path} ${e.message}`).join("\n"));

    const clean = await validateTree(dir);
    assertEqual(errorsMatching(clean.report, "low_tools").length, 0,
      `a sorted low_tools is refused: ${JSON.stringify(errorsMatching(clean.report, "low_tools"))}`);
    // No caps on the record: it is what the manifest declares, and the cap
    // lives on the decision (an over-cap review leaves the version unreviewed).
    at("1.1.0", Array.from({ length: 65 }, (_, i) => `t${String(i).padStart(2, "0")}`).concat(["z".repeat(200)]));
    assertEqual(errorsMatching((await validateTree(dir)).report, "low_tools").length, 0,
      "a long low_tools, or a long tool name, is refused on the record");
    at("1.1.0", ["wipe", "roll"]);
    assert(errorsMatching((await validateTree(dir)).report, "low_tools is not sorted").length === 1,
      "an unsorted low_tools is accepted");
    // Which names count is the probe's (Astra's rule, in Rust); JS's trim
    // strips U+FEFF and Rust's does not, so the validator does not re-judge.
    at("1.1.0", ["roll", "\uFEFF"]);
    assertEqual(errorsMatching((await validateTree(dir)).report, "low_tools").length, 0,
      "a name Astra reads as Low (U+FEFF, kept by Rust's trim) is refused on the record");
    at("1.1.0", ["roll", "roll"]);
    assert(errorsMatching((await validateTree(dir)).report, "low_tools").length > 0,
      "a low_tools that repeats a name is accepted (schema/version-v1.json uniqueItems)");
  });

  // ID-77 (contract 6.34.0): Astra installs an update without asking only
  // when the entry's `owner_id` equals the repository owner's numeric id it
  // recorded at install. So the member is the identity record's
  // `repository_owner_id` exactly, as an integer, and it is absent wherever
  // there is nothing trustworthy to compare: no identity record (unbound, or
  // one an M_IDENTITY_RESET removed) and an id that is not a canonical
  // positive safe integer. A present-but-wrong id would be worse than none,
  // because absence makes the client ask.
  //
  // Watched: deleting the `ownerIdEntry` spread in `buildIndex` turns the
  // first assertion red; replacing it with a bare
  // `owner_id: Number(identity.repository_owner_id)` turns the malformed rows
  // red; deleting `owner_id` from schema/index-v1.json's plugin turns the
  // schema one red (additionalProperties).
  await test("ID-77: a bound listing's entry carries its identity record's owner id as an integer; an unbound, reset or malformed one carries none", () => {
    const dir = path.join(tmp, "owner-id");
    fs.rmSync(dir, { recursive: true, force: true });
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
      path.join(dir, "plugins", "dice-roller"), { recursive: true });
    const identityFile = path.join(dir, "plugins", "dice-roller", "identity.json");
    // JSON.stringify, not stableStringify: the malformed rows include a number
    // the canonical writer refuses, and the generator must survive reading one.
    const bind = (ownerId) => fs.writeFileSync(identityFile, `${JSON.stringify({
      schema: "astra.registry.identity/1", plugin_id: "dice-roller", repository_id: "1343092393",
      repository_owner_id: ownerId, repo: "someone/dice-roller", token_hash: "c".repeat(16),
    })}\n`);
    const entryOf = () => buildIndex({ root: dir, serial: 1 }).signed.plugins.find((p) => p.id === "dice-roller");
    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
    const schemaErrors = (doc) => validateSchema(schema, doc).map((e) => `${e.path} ${e.message}`).join("\n");

    const unbound = buildIndex({ root: dir, serial: 1 });
    assert(!Object.hasOwn(unbound.signed.plugins.find((p) => p.id === "dice-roller"), "owner_id"),
      "an unbound listing carries an owner_id");
    assertEqual(schemaErrors(unbound), "", "schema/index-v1.json refuses a catalogue without owner_id");

    bind("280318216");
    const bound = buildIndex({ root: dir, serial: 1 });
    assertEqual(JSON.stringify(bound.signed.plugins.find((p) => p.id === "dice-roller").owner_id), "280318216",
      "a bound listing's entry does not carry its identity record's repository_owner_id as an integer");
    assertEqual(schemaErrors(bound), "", "schema/index-v1.json refuses a catalogue with owner_id");
    const asString = JSON.parse(JSON.stringify(bound));
    asString.signed.plugins.find((p) => p.id === "dice-roller").owner_id = "280318216";
    assert(validateSchema(schema, asString).length > 0, "schema/index-v1.json accepts owner_id as a string");
    asString.signed.plugins.find((p) => p.id === "dice-roller").owner_id = 0;
    assert(validateSchema(schema, asString).length > 0, "schema/index-v1.json accepts owner_id 0");

    for (const bad of ["0280318216", "0", "-5", "28031821x", "", " 280318216", "9007199254740993", 280318216.5, null]) {
      bind(bad);
      assert(!Object.hasOwn(entryOf(), "owner_id"), `an identity record with repository_owner_id ${JSON.stringify(bad)} gave owner_id ${JSON.stringify(entryOf().owner_id)}`);
    }

    // An M_IDENTITY_RESET deletes the identity record; the member goes with it.
    bind("280318216");
    assert(Object.hasOwn(entryOf(), "owner_id"), "the reset control is not bound");
    fs.rmSync(identityFile);
    assert(!Object.hasOwn(entryOf(), "owner_id"), "a reset listing still carries the owner_id of the identity it no longer has");
  });

  // A reviewed record's Low tools were named by its review, checked on the tree
  // as it stands (tools/validate.mjs `checkReviewedLowTools`), so a commit that
  // adds or widens `low_tools` on an already-reviewed record is refused before
  // build-index signs it, not alarmed by A11 after.
  //
  // Watched: deleting the `report.error` in `checkReviewedLowTools` turns the
  // first assertion red.
  await test("a reviewed record with Low tools needs a review entry recording exactly them; an old reviewed record with none is untouched", async () => {
    const dir = path.join(tmp, "low-tools-reviewed");
    fs.rmSync(dir, { recursive: true, force: true });
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
      path.join(dir, "plugins", "dice-roller"), { recursive: true });
    const versions = path.join(dir, "plugins", "dice-roller", "versions");
    const base = JSON.parse(fs.readFileSync(path.join(versions, "1.0.0.json"), "utf8"));
    const at = (v, over) => fs.writeFileSync(path.join(versions, `${v}.json`),
      stableStringify({ ...JSON.parse(JSON.stringify(base).replaceAll("1.0.0", v)), ...over }));
    const entry = (lowTools) => {
      fs.mkdirSync(path.join(dir, "bot", "moderation"), { recursive: true });
      fs.writeFileSync(path.join(dir, "bot", "moderation", "2026-09-20-dice-roller-review.json"), stableStringify({
        date: "2026-09-20", action: "review", plugin: "dice-roller", versions: ["1.1.0"],
        reason: "A moderator read this version's manifest and its Low tools and found nothing wrong.",
        category: "review_passed", service_decision_id: "0192f3a4-5b6c-7d8e-9f01-234567890abc",
        ...(lowTools ? { low_tools: { "1.1.0": lowTools } } : {}),
      }));
    };
    const refused = async () => errorsMatching((await validateTree(dir)).report, "declares Low tools");

    at("1.0.0", { review: "reviewed" }); // old, reviewed, never probed: untouched
    at("1.1.0", { review: "reviewed", low_tools: ["roll", "wipe"] });
    assertEqual((await refused()).length, 1, "a reviewed record with Low tools and no review entry at all is accepted");
    entry(undefined);
    assertEqual((await refused()).length, 1, "a review entry recording no Low tools is accepted as having named them");
    entry(["roll"]);
    assertEqual((await refused()).length, 1, "a review entry recording another set is accepted as having named them");
    entry(["roll", "wipe"]);
    const ok = await refused();
    assertEqual(ok.length, 0, `a review entry recording exactly the set is refused: ${JSON.stringify(ok)}`);
    at("1.1.0", { review: "reviewed", low_tools: ["nuke", "roll", "wipe"] });
    assertEqual((await refused()).length, 1, "a reviewed record's low_tools widened past its review is accepted");
    at("1.1.0", { review: "reviewed", low_tools: [] });
    assertEqual((await refused()).length, 0, "`[]` names no Low tool and needs no review naming one");
    at("1.1.0", { review: "unreviewed", low_tools: ["roll", "wipe", "nuke"] });
    assertEqual((await refused()).length, 0, "an unreviewed record grants nothing and needs no entry");
  });

  // Client session, relayed by the coordinator on 2026-09-26 (C1): the mark is
  // a member INSIDE `astra.registry.index/1`, and the catalogue's schema value
  // does not move. That value is the only catalogue schema a shipped 0.2.x
  // client accepts, and it is the signature domain: SHA-256(value ‖ 0x00 ‖
  // JCS(signed)). A new value — `/2`, or a renamed title the generator then
  // copied — would refuse the whole catalogue on every shipped client at
  // once. Nothing held the four places the value is written to one another.
  //
  // Watched: changing `INDEX_SCHEMA` in bot/lib/sign.mjs to
  // `astra.registry.index/2` turns the first assertion red; changing the
  // schema file's `const` or its `title` turns the second or third red.
  await test("the catalogue's schema value, and so its signing domain, is astra.registry.index/1 in every place it is written", async () => {
    const WANT = "astra.registry.index/1";
    const { INDEX_SCHEMA } = await import("../../bot/lib/sign.mjs");
    assertEqual(INDEX_SCHEMA, WANT,
      "bot/lib/sign.mjs's INDEX_SCHEMA moved. It is the catalogue's schema value and its signature domain, and a " +
      "shipped client accepts one value only");
    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/index-v1.json"), "utf8"));
    assertEqual(schema.$defs?.signed?.properties?.schema?.const, WANT,
      "schema/index-v1.json's `signed.schema` const is not the value shipped clients accept");
    assertEqual(schema.title, WANT, "schema/index-v1.json's title is not the catalogue's schema value");
    assertEqual(buildIndex({ serial: 1 }).signed.schema, WANT, "the generator writes another schema value");
    const committed = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    assertEqual(committed.signed.schema, WANT, "the committed catalogue carries another schema value");
  });

  // The two schema files name one list. The token file's `list:review` is the
  // third copy, held to these two in tools/selftest/contract-tokens.mjs once a
  // contract version publishes it.
  await test("schema/version-v1.json and schema/index-v1.json declare one list of review marks", () => {
    const read = (rel) => JSON.parse(fs.readFileSync(path.join(REPO_ROOT, rel), "utf8"));
    const version = read("schema/version-v1.json").properties?.review?.enum;
    const release = read("schema/index-v1.json").$defs?.release?.properties?.review?.enum;
    assert(Array.isArray(version) && version.length >= 2, "schema/version-v1.json declares no review enum");
    assertEqual(JSON.stringify(release), JSON.stringify(version),
      "the catalogue's release review enum is not the version record's, so the generator can copy a value the " +
      "catalogue schema refuses, or the reverse");
  });

  // Contract 6.32.0: the publish path no longer runs this suite, so the
  // live-data checks above (INV-29, INV-39, inlined icons, the publisher keys)
  // are `tools/validate.mjs`'s too, per listing, and run at every publish.
  // Each is planted once into the real catalogue's `signed` and must be named
  // by the listing it was planted in; the real one must name none.
  //
  // Watched red: each rule's `out.push` removed in turn leaves its plant unnamed.
  await test("tools/validate.mjs holds every listing to the catalogue's live-data rules the publish path used to leave to this suite", async () => {
    const { catalogueListingProblems } = await import("../validate.mjs");
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    assertEqual(JSON.stringify(catalogueListingProblems(doc.signed)), "[]", "the committed catalogue breaks a rule it is published under");
    const withPublisher = doc.signed.plugins.find((p) => p.publisher && p.releases?.length);
    assert(withPublisher, "no listing carries a publisher and a release, so half the plants below have no subject");
    const plant = (mutate) => {
      const copy = JSON.parse(JSON.stringify(doc.signed));
      const entry = copy.plugins.find((p) => p.id === withPublisher.id);
      mutate(entry, copy);
      return catalogueListingProblems(copy).map((x) => `${x.where}: ${x.problem}`);
    };
    const cases = [
      ["INV-29 a download count", (e) => { e.downloads = 7; }, /claims downloads=7/],
      ["INV-29 a star", (e) => { e.stars = 1; }, /stars=1/],
      ["INV-39 an artifact from another repository", (e) => {
        const k = Object.keys(e.releases[0].artifacts)[0];
        e.releases[0].artifacts[k].url = "https://github.com/someone-else/x/releases/download/v1/a.astraplugin";
      }, /is not under https:\/\/github\.com\//],
      ["BOT-79 a hosted icon", (e) => { e.icon_url = "https://example.invalid/i.png"; }, /icon_url fetches from/],
      ["ID-51 a publisher with no key", (e) => { e.publisher = "nobody-signed-this"; }, /not a signed\.publishers key/],
      ["a key no listing names", (e, c) => { c.publishers = { ...c.publishers, "orphan-login": c.publishers[e.publisher] }; }, /signed\.publishers\.orphan-login: is named by no listing/],
    ];
    for (const [what, mutate, re] of cases) {
      const found = plant(mutate);
      assert(found.some((f) => re.test(f)), `${what} was not named: ${found.join(" | ") || "nothing"}`);
    }
    // `--allow-direct` catalogues are self-hosted on purpose, and INV-39 is not asked of them.
    const direct = JSON.parse(JSON.stringify(doc.signed));
    const k = Object.keys(direct.plugins[0].releases[0].artifacts)[0];
    direct.plugins[0].releases[0].artifacts[k].url = "https://downloads.example.invalid/a.astraplugin";
    assertEqual(catalogueListingProblems(direct, { allowDirect: true }).length, 0, "INV-39 was asked under --allow-direct");
  });
}
