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
import { test, assert } from "./harness.mjs";

/** How many tests run() reports. The runner asserts exactly this many, so
 *  adding a test here is one line of arithmetic in this file and nowhere else. */
export const TESTS = 4;

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
}
