// MIG-20's marker, as the two tools that have to know about it see it.
//
// `log/` is the first directory in this repository that holds records about the
// bot's own decisions rather than about a listing, and `log/baseline.json` is
// its first file. The plan's line for B-T3.7b is "`tools/validate.mjs` and
// `tools/lib/sources.mjs` accept `log/baseline.json`", which reads like the
// removal of a refusal — and there was none to remove. Measured 2026-09-19: a
// `log/baseline.json` written into this tree left `node tools/validate.mjs
// --allow-staging` and `node tools/selftest.mjs` both green and both silent,
// because neither has ever looked outside `plugins/**`.
//
// That silence was the defect. Four mechanisms key on this file — B-T3.7's
// legacy writer, detector A1's ignore set (BOT-75), MIG-28's hold for ids with
// no baseline, and B-T3.6 step 0's work source — it is written once by a
// dispatch that then never runs again, and a marker with a mistyped schema
// string or a count that lies would be read by all four as the thing they were
// waiting for. So "accept" means "know about", and this module is what knowing
// about it is worth.
//
// Registry plan B-T3.7b.

import fs from "node:fs";
import path from "node:path";

import { population } from "../../bot/baseline.mjs";
import { BASELINE_FILE, REPO_ROOT, loadSources, nonStagingVersions } from "../lib/sources.mjs";
import { test, assert, tmp, validateTree, errorsMatching } from "./harness.mjs";

const SOUND = {
  schema: "astra.registry.baseline/1",
  written_at: "2026-01-02T00:00:00Z",
  source_commit: "a".repeat(40),
  version_count: 1,
  record_count: 1,
};

let seq = 0;

/** A one-listing tree, with whatever marker the caller wants (or none). */
function treeWith(marker) {
  const dir = path.join(tmp, `baseline-${++seq}`);
  const id = "fixture-plugin";
  fs.mkdirSync(path.join(dir, "plugins", id, "versions"), { recursive: true });
  fs.writeFileSync(path.join(dir, "plugins", id, "plugin.json"), `${JSON.stringify({
    schema: "astra.registry.plugin/1",
    id,
    name: "Fixture Plugin",
    summary: "A listing that exists so the marker has a tree to be counted against.",
    license: "MIT",
    source: { kind: "github", repo: "astra-fixtures/fixture-plugin" },
    added_at: "2026-01-01",
    description: "A listing that exists so the marker has a tree to be counted against.",
  }, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "plugins", id, "versions", "1.0.0.json"), `${JSON.stringify({
    schema: "astra.registry.version/1",
    id,
    version: "1.0.0",
    published_at: "2026-01-01T00:00:00Z",
    release: { kind: "github_release", repo: "astra-fixtures/fixture-plugin", tag: "v1.0.0", commit: "b".repeat(40) },
    artifacts: {
      "linux-x64": {
        url: "https://github.com/astra-fixtures/fixture-plugin/releases/download/v1.0.0/fixture-plugin-1.0.0-linux-x64.astraplugin",
        filename: "fixture-plugin-1.0.0-linux-x64.astraplugin",
        sha256: "c".repeat(64),
        size: 1024,
      },
    },
    protocol: 1,
  }, null, 2)}\n`);
  if (marker !== undefined) {
    fs.mkdirSync(path.join(dir, "log"), { recursive: true });
    fs.writeFileSync(path.join(dir, "log", "baseline.json"), `${JSON.stringify(marker, null, 2)}\n`);
  }
  return dir;
}

const marked = async (marker) => (await validateTree(treeWith(marker))).report;

export async function run() {
  // Its own header, and last in the runner's list, because the two boundaries
  // the runner's comment protects are both earlier and because `repo-rules.mjs`
  // prints no header of its own: inserting anywhere above it would move that
  // module's names under a header they do not belong to, which is the one thing
  // the order in `MODULES` is load-bearing about.
  console.log("\nthe migration baseline marker");

  await test("with no marker the validator says so rather than saying nothing", async () => {
    // A check that could not run is reported (the Report class's own rule),
    // because a check that quietly did not happen is indistinguishable from a
    // check that passed — and here the thing that did not happen is the one
    // four other mechanisms are waiting for.
    const report = await marked(undefined);
    assert(report.notes.some((n) => n.where === BASELINE_FILE),
      `${BASELINE_FILE} being absent went unremarked; before this module nothing in either tool knew the file existed`);
    assert(errorsMatching(report, BASELINE_FILE).length === 0, "an absent baseline was an error");
  });

  await test("a sound marker over a tree that matches it is clean", async () => {
    const report = await marked(SOUND);
    assert(errorsMatching(report, BASELINE_FILE).length === 0,
      `a correct marker was refused: ${errorsMatching(report, BASELINE_FILE).map((e) => e.message).join("; ")}`);
  });

  await test("a member nobody listed is refused, which is what keeps the marker name-free", async () => {
    // The allowlist, from the side it is for. PRIV-2 keeps names out of git,
    // and the marker is name-free by construction only if every member it may
    // hold is a schema string, a time, a commit or a count — so a member
    // somebody added is refused rather than carried.
    const report = await marked({ ...SOUND, written_by: "somebody" });
    assert(errorsMatching(report, "written_by").length === 1,
      "a member this marker may not hold was accepted");
  });

  await test("a marker over zero versions is a run that stopped working, not an empty registry", async () => {
    const report = await marked({ ...SOUND, version_count: 0, record_count: 0 });
    assert(errorsMatching(report, "zero versions").length === 1, "a baseline over nothing was accepted");
  });

  await test("fewer records than versions is a write that lost some", async () => {
    const report = await marked({ ...SOUND, version_count: 2, record_count: 1 });
    assert(errorsMatching(report, "record(s) for").length === 1, "a short baseline was accepted");
  });

  await test("a count ABOVE the tree means a baselined version file was deleted", async () => {
    // The one direction that stays true for ever. Versions are added after the
    // baseline and never removed — a delisted listing keeps its version files,
    // "because they were published and signed" — so the count may fall behind
    // the tree and may never exceed it. Above it, a `migration` record has
    // been orphaned and the population ROLL-42 and M-T8.1 compare has silently
    // shrunk.
    const report = await marked({ ...SOUND, version_count: 9, record_count: 9 });
    assert(errorsMatching(report, "and this tree holds 1").length === 1,
      "a marker claiming more versions than the tree holds was accepted");
  });

  await test("each member is checked against its own grammar, not merely present", async () => {
    for (const [member, bad] of [
      ["schema", "astra.registry.baseline/2"],
      ["written_at", "2026-01-02"],
      ["source_commit", "not-a-commit"],
      ["version_count", "1"],
    ]) {
      const report = await marked({ ...SOUND, [member]: bad });
      assert(errorsMatching(report, member).length >= 1, `${member} = ${JSON.stringify(bad)} was accepted`);
    }
  });

  await test("a marker that is not readable JSON fails with its path, not a SyntaxError", async () => {
    const dir = treeWith(SOUND);
    fs.writeFileSync(path.join(dir, "log", "baseline.json"), "{ not json\n");
    const { report } = await validateTree(dir);
    assert(errorsMatching(report, "not readable JSON").length === 1, "an unreadable marker was a soft failure");
  });

  await test("the validator and the baseline writer count the same population", async () => {
    // The coupling this module exists to hold, and the one nothing else could.
    // `tools/validate.mjs` compares the marker's `version_count` against
    // `nonStagingVersions`, and `bot/baseline.mjs` writes one `migration`
    // record per member of `population`. If those two ever disagree about what
    // a non-staging published version is, the marker the write job produces is
    // the marker the validator refuses — on `main`, in the single run that
    // cannot be repeated. Asserted by behaviour over the real tree, so it is
    // the answer and not the sentence that is compared.
    const fromValidate = nonStagingVersions(loadSources(REPO_ROOT).plugins).length;
    const { versions, problems } = population(REPO_ROOT);
    assert(problems.length === 0, `a version file on \`main\` cannot be read into a baseline record: ${problems.join("; ")}`);
    assert(fromValidate >= 1, "the non-staging population is empty, so both sides of this comparison are vacuous");
    assert(fromValidate === versions.length,
      `tools/validate.mjs counts ${fromValidate} non-staging published version(s) and bot/baseline.mjs counts ` +
      `${versions.length}; the marker one writes is the marker the other refuses`);
  });
}
