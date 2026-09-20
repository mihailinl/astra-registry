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
import { stableStringify } from "../lib/canonical.mjs";
import { validate as validateSchema } from "../lib/jsonschema.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, tmp, validateTree, errorsMatching } from "./harness.mjs";

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
