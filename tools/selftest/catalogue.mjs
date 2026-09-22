// The committed catalogue is exactly what the generator produces.
//
// It opens with the serial test, which prints under the previous module's
// "zip reader/writer" header and must keep doing so: the section comments and
// the module boundaries are not the same line, and the printed order is the
// thing under test.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

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
    // would be a catalogue entry.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "serial-"));
    const git = (...a) => execFileSync("git", a, { cwd: dir, stdio: ["ignore", "pipe", "ignore"] });
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
    assert(lone.test(stableStringify(corrupted)),
      "the predicate cannot see a lone surrogate at all, so the assertion above was decoration");
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
        return execFileSync("git", ["-C", REPO_ROOT, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
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
    // check by reading it (a test() body whose code names `shallow` before a
    // `neverAsk(`), prints the live lanes that ask it and fails when there are
    // none. Keep the gate on the line above the call.
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
    const strip = (entry) => {
      const { publisher, ...rest } = entry;
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
}
