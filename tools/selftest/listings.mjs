// What a listing's cards must survive: the hand-edit path checking every
// rendered locale card rather than the English one, the English card rule and an
// exemption that has outlived its listing, a hand-edited i18n name scanned for
// bidi overrides, matching-versus-renamed upstream limits, and a stale asset from
// an earlier version caught by filename.

import fs from "node:fs";
import path from "node:path";

import { checkListingLanguage, runValidation } from "../validate.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { REPO_ROOT, loadPolicy } from "../lib/sources.mjs";
import { test, assert, assertEqual, tmp, validateTree, errorsMatching } from "./harness.mjs";
import { withFakeAstraPlugins } from "./fixtures.mjs";

/** How many tests run() reports. The runner asserts exactly this many, so
 *  adding a test here is one line of arithmetic in this file and nowhere else. */
export const TESTS = 5;

export async function run() {
  await test("the hand-edit path checks every card a listing renders, not the English one", async () => {
    // `checkSquatting` built its name index from `p.doc?.name` alone. The moment
    // a listing grew an `i18n` member the asymmetry was back in a new place: the
    // bot ran `checkDisplayName` once per derived locale and this ran once per
    // listing. Constructed below and confirmed against origin/main: the validator
    // printed `PASS … 0 error(s), 0 warning(s)` for a tree `bot/lib/names.mjs`
    // answered R_DISPLAY_NAME_COLLISION and R_DISPLAY_NAME_MIXED_SCRIPT for.
    const dir = path.join(tmp, "i18n-names");
    const mk = (id, name, i18n) => {
      const d = path.join(dir, "plugins", id);
      fs.mkdirSync(path.join(d, "versions"), { recursive: true });
      fs.writeFileSync(path.join(d, "plugin.json"), JSON.stringify({
        schema: "astra.registry.plugin/1",
        id, name, summary: "Roll dice", license: "MIT",
        source: { kind: "github", repo: `someone/${id}` },
        added_at: "2026-08-10", description: "Roll dice", author: { name: "A Stranger" },
        ...(i18n ? { i18n } : {}),
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
    mk("dice-roller", "Dice Roller");
    // U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I for the ASCII `i`,
    // and a Cyrillic е inside a German name. Both live ONLY in `i18n`, which is
    // the whole point — the English cards are innocent and were all this looked at.
    mk("lucky-cubes", "Lucky Cubes", {
      ru: { name: "D\u0456ce Roller", summary: "\u0411\u0440\u043e\u0441\u043a\u0438" },
      de: { name: "W\u00fcrf\u0435l Roller", summary: "W\u00fcrfeln" },
    });

    const { report } = await runValidation({
      root: dir, allowStaging: true, allowDirect: false, online: false, artifactsDir: null, index: false,
    });
    const said = report.warnings.map((w) => `${w.where} ${w.message}`).join("\n");
    assert(/i18n\.ru.*matches/.test(said),
      `a localized homoglyph collision produced no finding on the hand-edit path:\n${said}`);
    assert(/i18n\.de.*mixes/.test(said),
      `a localized mixed-script name produced no finding on the hand-edit path:\n${said}`);
    // The floor: if `renderedNames` ever returns only the flat name again, the
    // two assertions above go red — but so does a tree with no listings, and the
    // two must not look alike.
    assertEqual(report.errors.length, 0, `the fixture tree itself is broken:\n${report.errors.map((e) => `${e.where} ${e.message}`).join("\n")}`);
  });

  await test("the English card rule, and an exemption that has outlived its listing", () => {
    const listing = (id, summary, repo) => ({
      file: `plugins/${id}/plugin.json`,
      doc: { id, summary, source: { kind: "github", repo } },
    });
    const russian = "Шахматы против локального бота или выбранной модели Astra с игровым чатом.";
    const run = (plugins, exempt) => {
      const found = [];
      const ctx = {
        report: {
          error: (where, message, hint) => found.push({ level: "error", where, message, hint }),
          warn: (where, message, hint) => found.push({ level: "warn", where, message, hint }),
          note: () => {},
        },
        policy: { ...loadPolicy(REPO_ROOT), listingLanguage: { exempt } },
      };
      checkListingLanguage(plugins, ctx);
      return found;
    };

    const refused = run([listing("chess", russian, "KNICE-TECH/chess")], []);
    assert(refused.some((f) => f.level === "error"), `a Russian card was listed: ${JSON.stringify(refused)}`);
    assert(refused[0].hint.includes("NOT an edit to this file"),
      "the fix is a release, not a hand edit to a derived document that the next release would contradict");

    const excused = run([listing("chess", russian, "KNICE-TECH/chess")], [{ repo: "KNICE-TECH/chess", reason: "test" }]);
    assertEqual(excused.filter((f) => f.level === "error").length, 0,
      `the exemption did not excuse: ${JSON.stringify(excused)}`);
    // Keyed on the repository and not on the id, because an id can be re-taken
    // under a different repository and a rename would walk straight past it.
    const renamed = run([listing("astra-chess", russian, "KNICE-TECH/astra-chess")], [{ repo: "KNICE-TECH/chess" }]);
    assert(renamed.some((f) => f.level === "error"),
      "an exemption for one repository must not follow the plugin to another one");

    // An unlisted plugin is rendered to nobody in any language, so it is skipped —
    // and it is worth knowing this is live rather than hypothetical: `knice-chess`
    // is in the tree, is unlisted, is Russian, and is the only listing that fails
    // this check today.
    const hidden = run([{ file: "plugins/knice-chess/plugin.json", doc: { id: "knice-chess", summary: russian, unlisted: true, source: { repo: "x/y" } } }], []);
    assertEqual(hidden.length, 0, `an unlisted plugin was audited: ${JSON.stringify(hidden)}`);

    // An exemption nobody needs is a hole nobody is watching: the next release
    // from that repository inherits an excuse no one granted it.
    const stale = run([listing("chess", "Plays chess.", "KNICE-TECH/chess")], [{ repo: "KNICE-TECH/chess" }]);
    assert(stale.some((f) => f.message.includes("not being used")),
      `an exemption for a card that is English now was not reported: ${JSON.stringify(stale)}`);
  });

  await test("a hand-edited locale name is scanned like every other display string", async () => {
    // The hole this closes: `tools/validate.mjs` applied `unsafeDisplayText` to a
    // hardcoded three-field object literal — name, summary, author — so a
    // maintainer who typed an i18n block into a plugin.json by hand got no
    // display-text scan at all, and CI stayed green because the generator
    // faithfully reproduced whatever the tree said.
    const dir = path.join(tmp, "hand-edited-i18n");
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"),
      path.join(dir, "plugins/dice-roller"), { recursive: true });
    const file = path.join(dir, "plugins/dice-roller/plugin.json");
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    doc.i18n = { ru: { name: "Dice Roller‮", summary: "Бросает кости." } };
    fs.writeFileSync(file, stableStringify(doc));
    const { report } = await validateTree(dir);
    assert(errorsMatching(report, "i18n.ru.name").length === 1,
      `a bidi override in a localized card name reached the store: ${report.errors.map((e) => e.message).join("; ")}`);
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
}
