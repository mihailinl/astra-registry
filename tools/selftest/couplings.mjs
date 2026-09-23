// The locale facts kept in more than one place, each tested by CONSTRUCTING the
// drift: the bot's locale list against both schema enums, the vocabulary against
// spec/locales.yaml with a parse floor, the caps AstraPlugins mirrors from here
// in both directions, every cap declaring its author side, and the locale corpus
// in both directions including the exemption that outlives its rule — and the
// facts that are not about locales: the pathspecs both serials are counted over,
// the advisory directory and id grammar, and (gap 111) the three files TRUST-43's
// anchor rests on — detector 9's class, the catalogue's serial and the signer's
// `unchanged` — asked end to end.
//
// `withFakeCheckout` below is seventeen lines from `withFakeAstraPlugins` in the
// old file and reads almost the same, but only this module uses it, so it stays
// here while the other one moved.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import {
  astraPluginsCandidates,
  checkEveryCapDeclaresItsAuthorSide,
  checkLocaleCorpus,
  checkLocaleCorpusCoverage,
  checkLocaleDigestVectors,
  checkLocaleVocabulary,
  checkMirroredListingLimits,
} from "../validate.mjs";
import { CORPUS_NO_RULE_ID, deriveLocaleText, localeEnumProblems } from "../../bot/lib/locales.mjs";
import { summarise } from "../../bot/lib/derive.mjs";
import { REPO_ROOT, loadPolicy, loadSchemas } from "../lib/sources.mjs";
import {
  SERIAL_FLAGS, SERIAL_PATHSPEC, SOURCE_DIR, SOURCE_PATHSPEC, checkAdvisory, pathUnder, resolveSerial,
} from "../lib/revocations.mjs";
import { ADVISORY_ID_GRAMMAR, ADVISORY_ID_PATTERN } from "../lib/ids.mjs";
import { validate as validateSchema } from "../lib/jsonschema.mjs";
import { looksLikeAdvisory } from "../coverage/docs-advisory-url.mjs";
import { checkEntry } from "../../bot/lib/moderation.mjs";
import { build as buildSite } from "../../site/build.mjs";
import { RESIGN_AFTER_HOURS, SIGNED_FILES, fetchSignedHead, serialsAt } from "../signer/plan.mjs";
import { buildSignedCommit, commitMessage, signRun } from "../signer/run.mjs";
import { trailersOf } from "../served-set/provenance.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { REVOCATIONS_SCHEMA, TRUST_SCHEMA } from "../../bot/lib/sign.mjs";
import { LIST_PATHSPEC, gather, serve85 } from "../served-set/main-vs-signed.mjs";
import { CATALOGUE_PATHSPEC, resolveSerial as resolveCatalogueSerial } from "../build-index.mjs";
import { serialFor } from "../regenerate-signed.mjs";
import { a7, a9, gitReader } from "../../bot/detectors.mjs";
import { nextAdvisoryId } from "../../bot/lib/compile-decision.mjs";
import { triggersOf } from "../moderation-coverage.mjs";
import { isShallow } from "../coverage/git.mjs";
import { test, assert, assertEqual, neverAsk, tmp } from "./harness.mjs";

export async function run() {
  // ── the locale couplings ────────────────────────────────────────────────────
  //
  // Three facts about locales are kept in more than one place, and all three are
  // tested by CONSTRUCTING a drift rather than by waiting for one. A mirror check
  // nobody has watched fail is a mirror check nobody knows works, and each of
  // these is silent in the direction that matters: nothing errors, nothing is
  // missing, a document says the right thing, and no program ever asks it.

  /**
   * A fake AstraPlugins checkout with exactly the files a case needs, and one
   * check run against it.
   *
   * `$ASTRA_PLUGINS_DIR` is an OVERRIDE in `validate.mjs`, not a first guess:
   * while it is set, the fake is the only checkout the reader can see. That is
   * what lets a fake HIDE a file as well as supply one, and the hiding half is
   * the half these tests need — it is how the `NOT verified` branch is reached
   * on a developer's machine, which has AstraPlugins sitting beside this
   * repository, as well as in CI, which has no sibling at all.
   *
   * It read "tried before the sibling working copy" until the absent case below
   * was watched passing for the wrong reason. Tried-in-order means a fake that
   * omits a file falls through to the real one, so every case here that asserts
   * an ABSENCE asserted it only where no sibling existed. Say it as an override
   * or the next fake that leaves a file out will be answered by this machine.
   */
  function withFakeCheckout(dirName, files, fn) {
    const root = path.join(tmp, dirName);
    for (const [rel, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.writeFileSync(path.join(root, rel), body);
    }
    const found = [];
    const ctx = {
      report: {
        error: (where, message, hint) => found.push({ level: "error", where, message, hint }),
        warn: (where, message, hint) => found.push({ level: "warn", where, message, hint }),
        note: (where, message, hint) => found.push({ level: "note", where, message, hint }),
      },
      policy: loadPolicy(REPO_ROOT),
      schemas: loadSchemas(REPO_ROOT),
      root: REPO_ROOT,
    };
    const prev = process.env.ASTRA_PLUGINS_DIR;
    process.env.ASTRA_PLUGINS_DIR = root;
    try {
      fn(ctx, found);
    } finally {
      if (prev === undefined) delete process.env.ASTRA_PLUGINS_DIR;
      else process.env.ASTRA_PLUGINS_DIR = prev;
    }
    return found;
  }

  const LOCALES_YAML = "en   English\nru   Русский\nuk   Українська\nde   Deutsch\nfr   Français\n" +
    "es   Español\npt   Português\nja   日本語\nzh   中文\nko   한국어\n";

  await test("C15 — the bot's locale list and both schema enums are one vocabulary", () => {
    // The in-repository half, which needs no checkout at all. A bot that emits a
    // locale the schema rejects does not fail that listing: it fails
    // `validateSchema(schemas.index, doc)` on the deploy candidate, which stops
    // the catalogue for every listing because one plugin shipped a translation.
    const schemas = loadSchemas(REPO_ROOT);
    assertEqual(localeEnumProblems(schemas.plugin, "schema/plugin-v1.json").length, 0,
      "the source schema disagrees with bot/lib/locales.mjs today");
    assertEqual(localeEnumProblems(schemas.index, "schema/index-v1.json").length, 0,
      "the index schema disagrees with bot/lib/locales.mjs today");

    // Constructed drift, one in each direction.
    const narrowed = JSON.parse(JSON.stringify(schemas.plugin));
    narrowed.properties.i18n.propertyNames.enum =
      narrowed.properties.i18n.propertyNames.enum.filter((c) => c !== "uk");
    assert(localeEnumProblems(narrowed, "fake").some((p) => p.includes("uk")),
      "a schema that stopped accepting a locale the bot emits was not noticed");

    const widened = JSON.parse(JSON.stringify(schemas.index));
    widened.$defs.plugin.properties.i18n.propertyNames.enum.push("en");
    assert(localeEnumProblems(widened, "fake").some((p) => p.includes('accepts "en"')),
      "`en` as an i18n key is the drift that looks harmless: it duplicates the untranslated card");

    // And the reach of the check itself. Rename the member and this reader must
    // say so, rather than comparing nine codes against nothing and reporting a
    // clean bill of health for a schema it never opened.
    const moved = JSON.parse(JSON.stringify(schemas.plugin));
    delete moved.properties.i18n;
    let threw = null;
    try { localeEnumProblems(moved, "fake"); } catch (e) { threw = e.message; }
    assert(threw?.includes("no i18n member"),
      `a vanished member must be an error, not an empty comparison: ${threw}`);
  });

  await test("C15 — the vocabulary is compared with spec/locales.yaml, and that parse has a floor", () => {
    const drifted = withFakeCheckout("fake-ap-locales-drift",
      { "spec/locales.yaml": LOCALES_YAML.replace("zh   中文\n", "zh-CN   中文\n") },
      (ctx) => checkLocaleVocabulary(ctx));
    assert(drifted.some((f) => f.level === "error" && f.message.includes("zh-CN")),
      `the spelling that ships an unselectable locale file was not caught: ${JSON.stringify(drifted)}`);

    const agreeing = withFakeCheckout("fake-ap-locales-ok",
      { "spec/locales.yaml": LOCALES_YAML },
      (ctx) => checkLocaleVocabulary(ctx));
    assertEqual(agreeing.filter((f) => f.level === "error").length, 0,
      `agreeing vocabularies were reported as drift: ${JSON.stringify(agreeing)}`);

    // The floor, and it is the difference between "the vocabulary shrank" and
    // "this reader stopped matching the file" — which need opposite fixes and
    // look identical from a green tick.
    const unparseable = withFakeCheckout("fake-ap-locales-shape",
      { "spec/locales.yaml": "# every row is now a comment\n" },
      (ctx) => checkLocaleVocabulary(ctx));
    assert(unparseable.some((f) => f.message.includes("cannot be right")),
      `an empty parse must fail as a broken scan: ${JSON.stringify(unparseable)}`);
  });

  await test("C20 — the caps AstraPlugins mirrors FROM here, and which side is the copy", () => {
    // A HAND-WRITTEN STAND-IN FOR `AstraPlugins/spec/listing-limits.yaml`, and
    // therefore a third copy of the same list — which is the shape this whole
    // page is about, so say it plainly rather than let somebody discover it.
    //
    // It has to carry a row for EVERY cap `policy/limits.json` declares
    // `_mirrored_by`, because the reverse loop below walks those declarations and
    // this string is what it walks them against. Adding a `_mirrored_by` sibling
    // without adding the row here is red, immediately, with the same message a
    // real missing row produces — which is how `max_artifact_bytes` was found to
    // need this line on 2026-08-23. That is the right failure: the fixture is
    // wrong in exactly the way the real file would be.
    const mirrors = (nameCap) =>
      `# mirrors: astra-registry/policy/limits.json max_name_length\nmax_name_length: ${nameCap}\n` +
      "# mirrors: astra-registry/policy/limits.json max_summary_length\nmax_summary_length: 200\n" +
      "# mirrors: astra-registry/policy/limits.json max_description_length\nmax_description_length: 4000\n" +
      "# mirrors: astra-registry/schema/version-v1.json $.properties.permissions.patternProperties.*.properties.reason maxLength\n" +
      "max_permission_reason_chars: 140\n" +
      "# mirrors: astra-registry/policy/limits.json max_locale_bytes\nmax_locale_bytes: 262144\n" +
      "# mirrors: astra-registry/policy/limits.json max_locale_keys\nmax_locale_keys: 5000\n" +
      "# mirrors: astra-registry/policy/limits.json max_listing_i18n_bytes\nmax_listing_i18n_bytes: 8192\n" +
      "# mirrors: astra-registry/policy/limits.json max_artifact_bytes\nmax_artifact_bytes: 268435456\n";

    const ok = withFakeCheckout("fake-ap-listing-ok", { "spec/listing-limits.yaml": mirrors(64) },
      (ctx) => checkMirroredListingLimits(ctx));
    assertEqual(ok.filter((f) => f.level === "error").length, 0,
      `today's caps were reported as drift: ${JSON.stringify(ok)}`);

    // ── the reverse direction ──────────────────────────────────────────────
    // The one the forward loop structurally cannot run: it walks that file's
    // rows, so a cap that file does not carry is invisible to it however
    // carefully it is written. This is what three locale caps were enforced at
    // ingest and mirrored nowhere behind, for a day, with both halves green.
    //
    // The mutation is a DELETION rather than a bad value, because a bad value is
    // already what the loop above catches. Constructed in the direction the real
    // failure arrived in: the registry holds the cap, upstream does not.
    const unmirrored = withFakeCheckout("fake-ap-listing-reverse",
      { "spec/listing-limits.yaml": mirrors(64).replace(/# mirrors:[^\n]*max_locale_bytes\nmax_locale_bytes: \d+\n/, "") },
      (ctx) => checkMirroredListingLimits(ctx));
    const gone = unmirrored.find((f) => f.level === "error" && f.message.includes("max_locale_bytes"));
    assert(gone, `a cap declared _mirrored_by with no row upstream passed: ${JSON.stringify(unmirrored)}`);
    // The two causes need opposite fixes and look identical from the error alone.
    assert(gone.hint.includes("ASTRA_PLUGINS_REF"),
      "a missing row is as often a stale pin as a deletion, and the message must name both");
    // The repair that greens the check by destroying it.
    assert(gone.hint.includes("Do NOT fix it by deleting"),
      "the fastest green here is deleting the `_mirrored_by` sibling, so the message has to refuse it by name");

    // And its floor: declarations deleted wholesale is the same green as a reader
    // that stopped matching them, and they need opposite fixes.
    const noDeclarations = withFakeCheckout("fake-ap-listing-nodecl",
      { "spec/listing-limits.yaml": mirrors(64) },
      (ctx) => checkMirroredListingLimits({
        ...ctx,
        policy: {
          ...ctx.policy,
          limits: Object.fromEntries(
            Object.entries(ctx.policy.limits).filter(([k]) => !k.endsWith("_mirrored_by"))),
        },
      }));
    assert(noDeclarations.some((f) => f.message.includes("below the floor of")),
      `an empty declaration set must fail as a broken enumeration: ${JSON.stringify(noDeclarations)}`);

    const drift = withFakeCheckout("fake-ap-listing-drift", { "spec/listing-limits.yaml": mirrors(48) },
      (ctx) => checkMirroredListingLimits(ctx));
    const hit = drift.find((f) => f.level === "error");
    assert(hit?.message.includes("48"), `a cap that drifted was not caught: ${JSON.stringify(drift)}`);
    // Which side somebody edits to make a mirror check pass is the whole question
    // for this class of check, and the answer belongs in the message, because the
    // fastest way to green is to edit whichever of the two files is on screen.
    assert(hit.hint.includes("THIS repository owns these numbers"),
      "the message must say which of the two files is the copy");

    // The JSON-pointer target, resolved rather than guessed at: it names a schema
    // keyword rather than a policy key, and a reader that quietly failed to
    // resolve it would leave that cap unpinned in both repositories.
    const pointer = withFakeCheckout("fake-ap-listing-pointer",
      { "spec/listing-limits.yaml": mirrors(64).replace("max_permission_reason_chars: 140", "max_permission_reason_chars: 999") },
      (ctx) => checkMirroredListingLimits(ctx));
    assert(pointer.some((f) => f.message.includes("999")),
      `the schema-pointer mirror did not resolve: ${JSON.stringify(pointer)}`);

    // And the floor: a file this reader can no longer parse is a broken scan, not
    // a shrinking list of caps.
    const shapeless = withFakeCheckout("fake-ap-listing-shape",
      { "spec/listing-limits.yaml": "max_name_length = 64\n" },
      (ctx) => checkMirroredListingLimits(ctx));
    assert(shapeless.some((f) => f.message.includes("below the floor")),
      `a file that stopped parsing must say so: ${JSON.stringify(shapeless)}`);
  });

  await test("every cap in policy/limits.json says what an author's tree has to do with it", () => {
    const run = (limits) => {
      // `loadPolicy` wraps the file, and every reader unwraps with
      // `ctx.policy.limits ?? ctx.policy`. Passing the bare map exercises the
      // second branch, which is the one a hand-built ctx would otherwise skip.
      const found = [];
      checkEveryCapDeclaresItsAuthorSide({
        report: {
          error: (where, message, hint) => found.push({ level: "error", where, message, hint }),
          warn: (where, message, hint) => found.push({ level: "warn", where, message, hint }),
          note: (where, message, hint) => found.push({ level: "note", where, message, hint }),
        },
        policy: limits,
      });
      return found;
    };

    const real = loadPolicy(REPO_ROOT).limits;
    const today = run(real);
    assertEqual(today.filter((f) => f.level === "error").length, 0,
      `the committed policy has an undeclared cap: ${JSON.stringify(today)}`);

    // The floor first, before any mutation, because a reader that enumerates no
    // caps reports every one of them as correctly declared.
    assert(run({ max_only_one: 1 }).some((f) => f.message.includes("below the floor of")),
      "a policy this reader can barely parse must fail as a broken scan, not pass as a tiny policy");

    // A NEW CAP WITH NO SIBLING is the thing this check exists for: the way three
    // locale caps came to be enforced at ingest and mirrored nowhere was not a
    // decision, it was an absence nobody could see. Adding one must be red until
    // somebody answers `can an author trip this from their own tree?`.
    const added = run({ ...real, max_something_new: 99 });
    const blank = added.find((f) => f.level === "error" && f.message.includes("max_something_new"));
    assert(blank, `a cap with no declaration passed: ${JSON.stringify(added)}`);
    assert(blank.hint.includes("_mirrored_by") && blank.hint.includes("_not_author_facing"),
      "the message has to name the choices, because the person adding a cap is the only one who knows the answer");

    // `_mirrors` and `_mirrored_by` are opposite claims about which repository
    // owns the number. A cap asserting both pins nothing in either direction.
    const both = run({ ...real, max_locale_bytes_mirrors: "AstraPlugins/spec/limits.yaml max_locale_bytes" });
    assert(both.some((f) => f.level === "error" && f.message.includes("2 declarations")),
      `a cap claiming to be both a copy and an original passed: ${JSON.stringify(both)}`);

    // A `_mirrored_by` pointing anywhere else is a copy nothing compares — which
    // is the state this convention exists to end, wearing the convention's badge.
    const elsewhere = run({ ...real, max_locale_keys_mirrored_by: "somewhere/else.yaml max_locale_keys" });
    assert(elsewhere.some((f) => f.level === "error" && f.message.includes("max_locale_keys_mirrored_by")),
      `a declaration naming an uncompared file passed: ${JSON.stringify(elsewhere)}`);

    // `_unmirrored` is recorded debt, not an exemption, and is named on every run
    // rather than counted. Collapsing it into `_not_author_facing` would let real
    // debt hide behind an innocuous word.
    //
    // ON A SYNTHETIC POLICY SINCE 2026-08-23, and the reason is worth the four
    // lines. This assertion used to read the COMMITTED policy and require the
    // note to name `max_artifact_bytes` — which was, at the time it was written,
    // the only `_unmirrored` cap in the file. So the commit that paid that debt
    // off (a row in AstraPlugins/spec/listing-limits.yaml, a rule in
    // `astra-plugin build`, this sibling flipped to `_mirrored_by`) turned this
    // test red, having changed nothing this test is about. A test pinned to
    // today's list of open debts fails when a debt is paid, which puts the
    // person doing the right thing in front of a red check and one keystroke
    // from putting the `_unmirrored` sibling back.
    const withDebt = run({
      ...real,
      max_pretend_bytes: 1,
      max_pretend_bytes_unmirrored: "an author can trip it and nothing local checks it",
    });
    const debt = withDebt.find((f) => f.level === "note" && f.message.includes("an author can trip"));
    assert(debt?.message.includes("max_pretend_bytes"),
      `the unmirrored caps must be named, not counted: ${JSON.stringify(withDebt)}`);

    // And the other end of it: no `_unmirrored` cap means NO note, rather than a
    // note reporting zero. A list of debts is something somebody acts on; a line
    // that says `0 cap(s)` every run is one they learn to skip past, and the day
    // it says 1 they skip that too.
    const noDebt = run(Object.fromEntries(
      Object.entries(real).filter(([k]) => !k.endsWith("_unmirrored"))));
    assert(!noDebt.some((f) => f.level === "note" && f.message.includes("an author can trip")),
      `a policy with nothing unmirrored must produce no debt note: ${JSON.stringify(noDebt)}`);
  });

  await test("C16 — an absent or shrunken locale corpus is never read as a clean one", () => {
    const one = "[plugin]\nname = \"x\"\ndescription = \"x\"\n";
    const empty = withFakeCheckout("fake-ap-corpus-empty",
      { "testdata/locales/pass/only/plugin.toml": one },
      (ctx) => checkLocaleCorpus(ctx));
    const floor = empty.find((f) => f.message.includes("floor"));
    assert(floor, `a one-case corpus passed for a full one: ${JSON.stringify(empty)}`);
    assert(floor.hint.includes("this SCAN is what broke"),
      "the floor's message has to separate `the rules shrank` from `the reader is looking in the wrong place`");

    // A fixture expecting a rule this side neither implements nor exempts is a
    // decision nobody made. It is reported, rather than skipped, because the
    // exemption list is the load-bearing half of the arrangement: it turns
    // forgetting into a visible blank.
    const files = {};
    for (let i = 0; i < 4; i++) files[`testdata/locales/pass/p${i}/plugin.toml`] = one;
    for (let i = 0; i < 12; i++) {
      files[`testdata/locales/fail/f${i}/plugin.toml`] = one;
      files[`testdata/locales/fail/f${i}/EXPECT`] = "E1\n";
      files[`testdata/locales/fail/f${i}/locales/ru.json`] = '{"listing.name":"x","listing.description":"x"}';
    }
    files["testdata/locales/fail/f0/EXPECT"] = "E99\n";
    const unknown = withFakeCheckout("fake-ap-corpus-unknown", files, (ctx) => checkLocaleCorpus(ctx));
    assert(unknown.some((f) => f.message.includes("E99")),
      `a rule id from the future was silently ignored: ${JSON.stringify(unknown.map((f) => f.message))}`);
  });

  await test("C16 — a fixture that provokes an exempt rule is READ, not refused by the reader", () => {
    // The other half of the exemption, and the half that was missing. Declaring
    // `E_METADATA_UNSAFE_TEXT` in `CORPUS_NO_RULE_ID` is only worth something if
    // `corpusIds` then lets a case through that provokes it — and before that
    // entry existed it did the opposite: it THREW `is an error this module can
    // emit and CORPUS_RULE_IDS does not name`, so the reader refused the very
    // fixture that would have made the rule visible. A mutation is what said this
    // needed saying: removing the exemption from `corpusIds` left every other
    // test green, because no committed fixture provokes any of the three.
    //
    // The case belongs in `pass/`, and that is not a mistake. `astra-plugin
    // check` has no display-text scan at all, so the CLI accepts this bundle;
    // the registry refuses it. The corpus compares ERROR ID SETS, and this rule
    // contributes no id to either side — which is exactly the disagreement
    // `CORPUS_NO_RULE_ID` exists to write down instead of hiding.
    const toml = (name, desc) => `[plugin]\nname = "${name}"\ndescription = "${desc}"\n`;
    const plain = toml("x", "x");
    const files = {};
    for (let i = 0; i < 4; i++) files[`testdata/locales/pass/p${i}/plugin.toml`] = plain;
    for (let i = 0; i < 12; i++) {
      files[`testdata/locales/fail/f${i}/plugin.toml`] = plain;
      files[`testdata/locales/fail/f${i}/EXPECT`] = "E1\n";
      files[`testdata/locales/fail/f${i}/locales/ru.json`] = '{"listing.name":"x","listing.description":"x"}';
    }
    // A conforming bundle whose Russian card name carries a right-to-left
    // override. Every parity and card rule is satisfied; the only thing wrong
    // with it is a character nobody can see.
    files["testdata/locales/pass/p0/locales/en.json"] = '{"listing.name":"x","listing.description":"x"}';
    files["testdata/locales/pass/p0/locales/ru.json"] =
      JSON.stringify({ "listing.name": "\u202ex", "listing.description": "x" });

    const found = withFakeCheckout("fake-ap-corpus-exempt", files, (ctx) => checkLocaleCorpus(ctx));
    const unreadable = found.filter((f) => f.level === "error" && /could not be read/.test(f.message));
    assertEqual(unreadable.length, 0,
      "the reader refused a fixture for a rule this repository deliberately has no corpus id for:\n" +
      unreadable.map((f) => `  ${f.message}`).join("\n"));
    // Scoped to `pass/p0` on purpose. This synthetic corpus witnesses one rule,
    // so the "every implemented rule has a fail case" loop rightly complains
    // about the other seven — that is a different check doing its job, and
    // swallowing it here would make this test pass for a reason of its own.
    const aboutTheCase = found.filter((f) => f.level === "error" && /pass\/p0/.test(f.message));
    assertEqual(aboutTheCase.length, 0,
      `an exempt rule became a corpus disagreement: ${JSON.stringify(aboutTheCase.map((f) => f.message))}`);

    // Not vacuous: the fixture really does provoke the rule. Without this the
    // test would pass against a corpus that provokes nothing at all, which is the
    // failure the whole exemption exists to stop.
    const provoked = deriveLocaleText({
      files: [
        { name: "locales/en.json", bytes: Buffer.from('{"listing.name":"x","listing.description":"x"}') },
        { name: "locales/ru.json", bytes: Buffer.from(JSON.stringify({ "listing.name": "\u202ex", "listing.description": "x" })) },
      ],
      facts: { name: "x", description: "x" },
      limits: loadPolicy(REPO_ROOT).limits,
      summarise,
    }).findings;
    assert(provoked.some((f) => f.code === "E_METADATA_UNSAFE_TEXT"),
      `the fixture provokes nothing, so this test proves nothing: ${JSON.stringify(provoked.map((f) => f.code))}`);
  });

  await test("C16, the direction it never ran in — every locale rule is mapped or exempted", () => {
    // `checkLocaleCorpus` reads the corpus and asks of each id whether this
    // repository implements or exempts it: corpus -> registry. It can only ever
    // see rules somebody already wrote a fixture for. Nothing asked the reverse,
    // and `E_METADATA_UNSAFE_TEXT` is what that cost — enforced on every
    // translated `listing.name` since the locale work landed, provoked by none of
    // the corpus's 104 files, and named in neither map, so `corpusIds` would have
    // THROWN at whoever wrote the first fixture for it.
    //
    // This half needs no checkout, which is the point: `checkLocaleCorpus` skips
    // without one and this must not skip with it.
    const run = () => {
      const found = [];
      checkLocaleCorpusCoverage({
        report: {
          error: (where, message, hint) => found.push({ level: "error", where, message, hint }),
          warn: (where, message, hint) => found.push({ level: "warn", where, message, hint }),
          note: (where, message) => found.push({ level: "note", where, message }),
        },
        policy: loadPolicy(REPO_ROOT),
        schemas: loadSchemas(REPO_ROOT),
        root: REPO_ROOT,
      });
      return found;
    };

    const today = run();
    assertEqual(today.filter((f) => f.level === "error").length, 0,
      `bot/lib/locales.mjs enforces a rule that is neither mapped nor exempted:\n` +
      today.filter((f) => f.level === "error").map((f) => `  ${f.message}`).join("\n"));

    // ── the FLOOR, before the mutation ──
    //
    // This check enumerates a set by scraping `add("error", "E_…")` out of the
    // module's own text. That set is one refactor away from being empty, and an
    // empty enumeration passes for the wrong reason — quietly, for ever, while
    // reading as coverage. So the count is asserted here and again inside the
    // check, and the two failures are made to look different from each other.
    const counted = today.find((f) => f.level === "note" && /locale error rule\(s\) enumerated/.test(f.message));
    assert(counted, `the check reported no count at all: ${JSON.stringify(today)}`);
    const n = Number(/^(\d+)/.exec(counted.message)?.[1] ?? 0);
    assert(n >= 11, `only ${n} locale error rules were found; the module has more, so this SCAN is what broke`);

    // ── and the mutation, watched ──
    //
    // The check reads this repository's own module by design — it is asking about
    // THIS repository's rules — so the drift is constructed in the maps, which is
    // the side an editor touches. An exemption for a rule that no longer exists
    // is the reverse of the failure above and the one that makes a debt look
    // serviced, so it fails too rather than being tidied away.
    const stale = [];
    const before = CORPUS_NO_RULE_ID.E_LOCALE_GONE_TOMORROW;
    CORPUS_NO_RULE_ID.E_LOCALE_GONE_TOMORROW = "a rule this module does not emit";
    try {
      checkLocaleCorpusCoverage({
        report: {
          error: (where, message, hint) => stale.push({ where, message, hint }),
          warn: () => {}, note: () => {},
        },
        policy: loadPolicy(REPO_ROOT), schemas: loadSchemas(REPO_ROOT), root: REPO_ROOT,
      });
    } finally {
      if (before === undefined) delete CORPUS_NO_RULE_ID.E_LOCALE_GONE_TOMORROW;
      else CORPUS_NO_RULE_ID.E_LOCALE_GONE_TOMORROW = before;
    }
    assert(stale.some((f) => f.message.includes("E_LOCALE_GONE_TOMORROW")),
      "an exemption outliving its rule is a reason nobody can check, and it makes the debt look serviced");
  });

  await test("C19 — `$ASTRA_PLUGINS_DIR` is an override, and this is asked with or without a sibling", () => {
    // **Gap 41.** The case below ends with an absent one: point the reader at a
    // fake that omits the table and require it to say `NOT verified`. That is
    // the branch `build-index.yml` turns into `exit 1`, and it is the only
    // thing between "the comparison could not run" and a green tick.
    //
    // A passing condition that is an ABSENCE has an environment, and until this
    // test the environment was the whole check. Measured on 2026-09-22 by
    // putting the pre-fix two-candidate resolver back:
    //
    //   with no ../AstraPlugins   INCOMPLETE  312 passed, 0 failed  — green
    //   with one                  FAIL        310 passed, 1 failed  — red
    //
    // Every lane `node tools/selftest.mjs --lanes` reports as LIVE is the first
    // kind. So the fall-through could be reinstated and no run that happens
    // without a human would have said anything, and the developer run that
    // would have is the one nothing schedules.
    //
    // **The fix is not a second environment; it is asking the resolver instead
    // of the resolver's surroundings.** "A file missing from the override is
    // missing" is an absence and needs a sibling to be observable. "The
    // override is the ONLY candidate" is a length, and a length is the same
    // number on both machines. One assertion, red in both.
    //
    // This does not retire the absent case below: that one is end-to-end
    // through `checkLocaleDigestVectors`, and it still catches a reader that
    // resolves a path without going through this list at all. What it does is
    // stop that case being the ONLY place C19's fix is held, which is what made
    // the fix's survival a property of whose machine the suite ran on.
    const prev = process.env.ASTRA_PLUGINS_DIR;
    try {
      // A directory that does not exist, deliberately. The pre-fix resolver
      // appended the sibling to the list and `astraPluginsFile` took the first
      // candidate whose FILE existed, so an override naming nothing at all is
      // precisely the state in which it answered from somewhere else.
      const nowhere = path.join(tmp, "override-that-names-nothing");
      process.env.ASTRA_PLUGINS_DIR = nowhere;
      const overridden = astraPluginsCandidates();
      assertEqual(overridden.length, 1,
        "`$ASTRA_PLUGINS_DIR` is a first guess again, not an override: a file absent from it is answered from " +
        `${overridden.slice(1).join(", ")}. Every NOT verified branch in tools/validate.mjs is then unprovable ` +
        "on any machine that has AstraPlugins beside this repository, which is every machine a person uses");
      assertEqual(overridden[0], nowhere,
        "the override is set and is not the directory looked at");

      delete process.env.ASTRA_PLUGINS_DIR;
      const fallback = astraPluginsCandidates();
      assertEqual(fallback.length, 1,
        `with no override there is exactly one place to look and this reader has ${fallback.length}`);
      assertEqual(fallback[0], path.resolve(REPO_ROOT, "../AstraPlugins"),
        "the sibling this reader falls back to is not the sibling the rest of the estate means by the word. " +
        "`tools/selftest/signer.mjs` recomputes this literal to decide whether its own half of gap 41's pair " +
        "can be asked at all, and `tools/selftest.mjs` reports which lanes are free of it; a rename here and " +
        "those two would be answering about a directory nothing reads");
    } finally {
      if (prev === undefined) delete process.env.ASTRA_PLUGINS_DIR;
      else process.env.ASTRA_PLUGINS_DIR = prev;
    }
  });

  await test("C19 — the lock digest is held to a table neither implementation wrote", () => {
    // **The gap this closes.** `astra-plugin locale sync` WRITES the digests in
    // a bundle's `locales.lock.json`; `englishDigest` READS them. One hash, one
    // input, two languages, two repositories — and nothing compared them. They
    // were run against the same English once and produced the same values,
    // which is agreement by luck: no comparison existed, so none could have
    // noticed the day it stopped holding.
    //
    // `checkLocaleCorpus` above cannot reach it. Staleness is a NOTE in the CLI
    // and a WARNING here, and both readers of that corpus compare ERROR id sets
    // and nothing else — so a case whose lock is one hash behind proves both
    // sides stayed QUIET, never that both computed the SAME NUMBER.
    //
    // Every digest below came from coreutils `sha256sum`, pasted as a literal,
    // for the reason the table itself exists: a fixture this module derived
    // with `englishDigest` would make the test agree with the thing under test.

    // [name, english, the first 12 hex of sha256 of those exact UTF-8 bytes]
    const TABLE = [
      ["lf", "one\ntwo", "21066d108d53"],
      ["crlf", "one\r\ntwo", "29a776bb35ef"],
      ["case-upper", "Chess", "c1aade825397"],
      ["case-lower", "chess", "ac739dccd121"],
      ["nfc-e-acute", "café", "850f7dc43910"],
      ["nfd-e-acute", "café", "81ef060bcd98"],
      ["nfc-short-i", "Краткий", "d5f1c098dec2"],
      ["nfd-short-i", "Краткий", "3c9721e00641"],
      ["empty", "", "e3b0c44298fc"],
      ["single-space", " ", "36a9e7f1c95b"],
      ["f0", "filler 0", "899621a74490"],
      ["f1", "filler 1", "eca4954b2863"],
      ["f2", "filler 2", "6baf98ec1db5"],
      ["f3", "filler 3", "074439fb0cce"],
      ["f4", "filler 4", "0e1b260e0ae4"],
      ["f5", "filler 5", "e467bd8624a8"],
      ["f6", "filler 6", "a64ebdf935d0"],
      ["f7", "filler 7", "d91b95b61265"],
      ["f8", "filler 8", "a599740cf34a"],
      ["f9", "filler 9", "dc0094026d1f"],
      ["f10", "filler 10", "c31c7975f1cb"],
      ["f11", "filler 11", "49e3316bad8f"],
    ];
    const REL = "testdata/locales/digest-vectors.json";
    const tableOf = (rows) => JSON.stringify({
      schema: "astra.locale.digest-vectors/1",
      vectors: rows.map(([name, english, digest]) => ({ name, english, digest, catches: "a selftest fixture" })),
    });
    const runOn = (dirName, rows) =>
      withFakeCheckout(dirName, { [REL]: tableOf(rows) }, (ctx) => checkLocaleDigestVectors(ctx));

    // The negative control FIRST. A table `englishDigest` agrees with must
    // produce no errors at all, or every assertion below passes for the wrong
    // reason — and the coreutils literals above are, in this one line, also the
    // first thing that has ever compared the two implementations of C19 inside
    // this repository's own suite.
    const clean = runOn("fake-ap-digest-clean", TABLE);
    const cleanErrors = clean.filter((f) => f.level === "error");
    assertEqual(cleanErrors.length, 0,
      "englishDigest disagrees with coreutils on a table this repository ships in its own test:\n" +
      cleanErrors.map((f) => `  ${f.message}`).join("\n"));
    // ── the floor under the PRESENT direction ──
    //
    // `no errors` is also what a reader that compared NOTHING returns, so the
    // count is read back out of the note and held to a number rather than
    // eyeballed. This was `some(/22 lock digest vector/)`, which is a true
    // sentence about today's fixture and says nothing at all about a resolver
    // that starts finding an empty table — and the fix that brought the absent
    // case below back to life is exactly a change of which file this reader
    // resolves to, so the direction that must NOT change needs a floor of its
    // own. A fix that makes the absent case pass by never finding anything is
    // worse than the bug it replaced.
    const COMPARED_FLOOR = 20;
    assert(TABLE.length >= COMPARED_FLOOR,
      `the fixture is ${TABLE.length} vectors, under the floor of ${COMPARED_FLOOR} it exists to prove`);
    const verified = clean.find((f) => f.level === "note" && /lock digest vector\(s\) verified/.test(f.message));
    assert(verified, `the check said nothing about what it read: ${JSON.stringify(clean)}`);
    const compared = Number(/^(\d+) lock digest vector/.exec(verified.message)?.[1] ?? NaN);
    assertEqual(compared, TABLE.length,
      `the check compared ${compared} vector(s) against a ${TABLE.length}-vector table: ${verified.message}`);

    // And the pairs, counted for the same reason. Two of the five are pinned by
    // cases below, which name them; emptying DIGEST_PAIRS leaves the other three
    // asserting nothing while this note goes on being printed.
    const pairs = Number(/; (\d+) non-collision pair\(s\) hold/.exec(verified.message)?.[1] ?? NaN);
    assert(pairs >= 5, `only ${pairs} non-collision pair(s) were asserted: ${verified.message}`);

    // ── the mutation, watched: one number moved ──
    const oneWrong = TABLE.map(([n, e, d]) => (n === "f3" ? [n, e, "074439fb0ccf"] : [n, e, d]));
    const drifted = runOn("fake-ap-digest-drift", oneWrong);
    const named = drifted.filter((f) => f.level === "error" && /\bf3\b/.test(f.message));
    assertEqual(named.length, 1,
      `a digest that moved by one character was not reported exactly once: ${JSON.stringify(drifted.map((f) => f.message))}`);
    assert(named[0].hint.includes("W_LOCALE_STALE"),
      "the hint has to say what a disagreement COSTS — every card falling back to English while " +
      "`astra-plugin check` reports the lock fresh — because from an author's side it reads as nothing happening");

    // ── the floor, before any comparison ──
    //
    // A table that stopped parsing, or a checkout that fetched a stump of one,
    // must fail as itself. An eight-row table compared row by row passes eight
    // times and says nothing about the twenty-four rows that went missing.
    const short = runOn("fake-ap-digest-short", TABLE.slice(0, 8));
    const floor = short.find((f) => f.level === "error" && f.message.includes("floor"));
    assert(floor, `an eight-vector table passed for a full one: ${JSON.stringify(short)}`);
    assert(floor.hint.includes("this SCAN is what broke"),
      "the floor's message has to separate `vectors were deleted` from `this reader is looking at the wrong file`");

    // ── the collision a per-vector comparison CANNOT see ──
    //
    // The subtlest failure here, and the reason the pairs are asserted at all.
    // Give `crlf` the same English as `lf` and the digest that English really
    // has: every per-vector comparison passes, the table looks healthy, and the
    // vector that was supposed to catch a newline normalisation has quietly
    // stopped being able to. Nothing else in this file would notice.
    const collided = TABLE.map(([n, e, d]) => (n === "crlf" ? [n, "one\ntwo", "21066d108d53"] : [n, e, d]));
    const pairFound = runOn("fake-ap-digest-pair", collided);
    assertEqual(pairFound.filter((f) => f.level === "error" && /sha256sum says/.test(f.message)).length, 0,
      "the collided table is per-vector CORRECT on purpose; if that is not true this case is testing something else");
    assert(pairFound.some((f) => f.level === "error" && /lf \/ crlf/.test(f.message)),
      `a pair that had already collided passed unremarked: ${JSON.stringify(pairFound.map((f) => f.message))}`);

    // ── a half-missing pair is not a passing pair ──
    const halfGone = runOn("fake-ap-digest-halfpair", TABLE.filter(([n]) => n !== "nfd-short-i"));
    assert(halfGone.some((f) => f.level === "error" && /nfc-short-i \/ nfd-short-i/.test(f.message)),
      `a pair with a deleted half asserted nothing and looked exactly like one that passed: ${JSON.stringify(halfGone.map((f) => f.message))}`);

    // ── no table: a NOTE, never silence, and never a pass ──
    //
    // `build-index.yml` turns every `NOT verified` line into an `::error::` and
    // `exit 1`, so the honest answer stops the catalogue instead of reading as
    // a green tick in a wall of them. That only works if the answer is printed.
    //
    // **This case spent its whole life being answered by another repository.**
    // `validate.mjs` resolved a file by trying $ASTRA_PLUGINS_DIR and then the
    // sibling working copy until one of them EXISTED, so a fake that omits the
    // table fell through to the real `../AstraPlugins` and this assertion was
    // handed "32 lock digest vector(s) verified" — which is not `NOT verified`,
    // and is the only reason anybody looked. It passed in CI throughout, where
    // the selftest step runs before `_astra-plugins` is checked out and there is
    // nothing to fall through to; so the branch that stops the catalogue was
    // proven only in the one environment where it could not be got wrong.
    //
    // **And after the fix it inverted** (gap 41). This case could then only
    // PROVOKE the regression where a sibling exists, so putting the
    // fall-through back was green in every lane and red only on a machine
    // nothing schedules. It is no longer the sole holder of that rule: the test
    // above asks `astraPluginsCandidates()` for the LENGTH of its list, and a
    // length is the same number in both environments. What is left here that a
    // length cannot see is a reader that resolves a path without going through
    // that list at all — and that one still needs a sibling to be observable,
    // which is why this case keeps its place rather than being retired into it.
    const absent = withFakeCheckout("fake-ap-digest-absent",
      { "testdata/locales/pass/only/plugin.toml": "[plugin]\nname = \"x\"\ndescription = \"x\"\n" },
      (ctx) => checkLocaleDigestVectors(ctx));
    const said = absent.find((f) => f.level === "note" && f.message.includes("NOT verified"));
    assert(said, `an absent digest table was passed over in silence: ${JSON.stringify(absent)}`);

    // WHICH absence, and not merely that some absence was named. This fake has
    // a `testdata/locales` and no table in it, which is a PIN older than the
    // table — a different repair from a checkout that never arrived, and the
    // reader is supposed to tell them apart. It is also the assertion that
    // holds the override to being one: "no checkout found" here would mean the
    // reader could not see the fake's own corpus directory either.
    assert(/has testdata\/locales but no digest-vectors\.json/.test(said.message),
      `the reader named the wrong absence, which sends the reader of the log to the wrong file: ${said.message}`);
    assertEqual(absent.filter((f) => f.level === "error").length, 0,
      "a missing checkout is a check that did not run, not a check that failed; the workflow is what makes it fatal");
  });

  // ── the withdrawal list's serial, and the clock that is measured from it ────
  //
  // Gap 64. The serial is `git rev-list --count --full-history <commit> --
  // <pathspec>` + 1 (how it counts is entry 117's check, further down; this one
  // is about WHAT it counts over), and three readers compute or depend on it: the signer's `serialsAt`, the
  // regeneration's `resolveSerial`, and SERVE-85, whose serial window runs from
  // the newest commit under that same pathspec because that commit is the last
  // thing that could have moved the serial. Two of the three typed the string
  // for themselves and nothing compared them; widening the clock's copy was
  // measured on 2026-09-22 to move the clock and leave the serial.
  //
  // They import one export now, and this does not trust that: an import is a
  // promise about the next edit, and the next edit is the thing that drifts.
  // It counts a fixture history each reader sees and asks what each one
  // counted, so a reader that goes back to a string of its own, or reads the
  // export and then counts something else with it, is red here by name.

  await test("gap 64 — the list's serial and SERVE-85's clock count one pathspec: the signer's, the regeneration's and the clock's", () => {
    const dir = path.join(tmp, "couplings-serial-pathspec");
    fs.mkdirSync(dir, { recursive: true });
    const git = (...a) =>
      execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
    git("init", "-q", "-b", "main");
    git("config", "user.email", "couplings-fixture@example.invalid");
    git("config", "user.name", "couplings fixture");
    git("config", "commit.gpgsign", "false");
    const commit = (rel, body, at) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), body);
      git("add", "-A");
      execFileSync("git", ["-C", dir, "commit", "-qm", rel], {
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, GIT_AUTHOR_DATE: at, GIT_COMMITTER_DATE: at },
      });
    };
    const advisory = JSON.stringify({
      id: "ASTRA-2026-0001",
      published: "2026-09-10",
      severity: "high",
      action: "block_install",
      reason: "A fixture advisory, long enough to be a sentence a user can act on.",
      entries: [{ kind: "id", value: "dice-roller" }],
    });

    // Five commits, each one hour apart, so every pathspec a reader could
    // plausibly drift to counts a different number or dates a different
    // commit. The directory's newest commit is a README edit ON PURPOSE: that
    // is the one the list's sources do not see and the serial does.
    //
    // Written under `SOURCE_DIR`, not under a literal `tools/revocations/`:
    // with the literal, a legitimate move of the directory — every reader
    // following the constant — left this fixture in the old place and the
    // check red about a drift that had not happened (measured 2026-09-22 with
    // `SOURCE_DIR = "tools/advisories"`). Gap 72's fixture below was already
    // written this way.
    commit(`${SOURCE_DIR}/README.md`, "advisories\n", "2026-09-19T08:00:00Z");
    commit(`${SOURCE_DIR}/ASTRA-2026-0001.json`, advisory, "2026-09-19T09:00:00Z");
    commit(`${SOURCE_DIR}/README.md`, "advisories, and how to write one\n", "2026-09-19T10:00:00Z");
    commit("tools/README-fixture.md", "under tools/, outside the list's directory\n", "2026-09-19T11:00:00Z");
    commit("plugins/dice-roller/plugin.json", "{}\n", "2026-09-19T12:00:00Z");
    const head = git("rev-parse", "HEAD");
    const count = (spec) => Number(git("rev-list", "--count", ...SERIAL_FLAGS, head, "--", spec));
    const newest = (spec) => git("log", "-1", "--format=%cI", head, "--", spec) || null;
    const expect = { count: count(SERIAL_PATHSPEC), newest: newest(SERIAL_PATHSPEC) };

    // The fixture guard, before any reader is asked. If a neighbour counted
    // the same number AND dated the same commit, a reader drifting to it would
    // be invisible here — so say which neighbour the fixture cannot separate,
    // rather than let a check go green about a difference it could not see.
    // A README-only pathspec dates the same commit by construction; its count
    // is what tells it apart.
    const neighbours = [SOURCE_PATHSPEC, "tools", ".", "plugins", `${SERIAL_PATHSPEC}/README.md`];
    for (const spec of neighbours) {
      assert(spec !== SERIAL_PATHSPEC, `the neighbour ${spec} is the serial's own pathspec; the fixture has nothing to separate`);
      assert(count(spec) !== expect.count,
        `the fixture cannot tell ${spec} from ${SERIAL_PATHSPEC}: both count ${expect.count} commit(s)`);
    }
    for (const spec of [SOURCE_PATHSPEC, "tools", "."]) {
      assert(newest(spec) !== expect.newest,
        `the fixture cannot tell ${spec} from ${SERIAL_PATHSPEC} by date: both newest at ${expect.newest}`);
    }
    const which = (n) => [SERIAL_PATHSPEC, ...neighbours].filter((s) => count(s) === n).join(" or ") || "no pathspec this fixture knows";
    const dated = (at) => [SERIAL_PATHSPEC, ...neighbours].filter((s) => newest(s) === at).join(" or ") || "no pathspec this fixture knows";

    // (a) the signer. `serialsAt` is what `planRun` signs and what SERVE-85's
    // `gather` generates the list at, so it is asked directly.
    const signer = serialsAt({ root: dir, sha: head }).revocations;
    assertEqual(signer, expect.count + 1,
      `the signer's serial counts over ${which(signer - 1)}, and the serial's pathspec is ${SERIAL_PATHSPEC}: ` +
        `tools/signer/plan.mjs's serialsAt has stopped counting over SERIAL_PATHSPEC`);

    // (b) the regeneration. `build-revocations.mjs` writes main's unsigned
    // copy at this serial; an operator's environment override would answer
    // for it, so the override is taken out of the way for the one call.
    const override = process.env.ASTRA_REVOCATIONS_SERIAL;
    delete process.env.ASTRA_REVOCATIONS_SERIAL;
    let regenerated;
    try {
      regenerated = resolveSerial({ root: dir });
    } finally {
      if (override !== undefined) process.env.ASTRA_REVOCATIONS_SERIAL = override;
    }
    assertEqual(regenerated, expect.count + 1,
      `the regeneration's serial counts over ${which(regenerated - 1)}, and the serial's pathspec is ${SERIAL_PATHSPEC}: ` +
        `tools/lib/revocations.mjs's resolveSerial has stopped counting over SERIAL_PATHSPEC`);

    // (c) SERVE-85's clock, both as the constant it names and as the commit it
    // actually dates. The name alone is not enough: `gather` could read the
    // export and log something else, and the constant would still agree.
    assertEqual(LIST_PATHSPEC, SERIAL_PATHSPEC,
      "tools/served-set/main-vs-signed.mjs's LIST_PATHSPEC is a different string from the pathspec the serial is counted over");
    const facts = gather({ root: dir });
    assertEqual(facts.listClock, expect.newest,
      `SERVE-85's clock dates the newest commit under ${dated(facts.listClock)}, and the serial moves on commits under ` +
        `${SERIAL_PATHSPEC}: its window now opens on a commit that did not move the serial`);
    assertEqual(facts.generated?.serial, signer,
      "SERVE-85 generates the list at a serial other than the one the signer assigns at the same commit");
  });

  // ── the catalogue's pathspec, which six readers count over ──────────────────
  //
  // Gap 71, the same class as gap 64 for the other document. The catalogue's
  // serial is `git rev-list --count <commit> -- plugins`, and that one
  // question is asked in six places: `tools/build-index.mjs`'s `resolveSerial`
  // (twice — the count, and whether a change is pending), the signer's
  // `serialsAt`, the carrier's `serialFor` in `tools/regenerate-signed.mjs`,
  // detector A7's plugins half, and the "Compute the serial" step of
  // `build-index.yml`. The first three import `CATALOGUE_PATHSPEC` now; the
  // carrier deliberately loads nothing of the working tree and the step is
  // shell, so those two keep their spelling. None of that is trusted here:
  // each reader is asked what it counted on one fixture history in which every
  // plausible neighbour counts differently.

  await test("gap 71 — the catalogue's serial, its pending commit and A7's clock count one pathspec: build-index's, the signer's, the carrier's, A7's and build-index.yml's", () => {
    const dir = path.join(tmp, "couplings-catalogue-pathspec");
    fs.mkdirSync(dir, { recursive: true });
    const git = (...a) =>
      execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
    git("init", "-q", "-b", "main");
    git("config", "user.email", "couplings-fixture@example.invalid");
    git("config", "user.name", "couplings fixture");
    git("config", "commit.gpgsign", "false");
    const put = (rel, body) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), body);
    };
    const commit = (rel, body, at) => {
      put(rel, body);
      git("add", "-A");
      execFileSync("git", ["-C", dir, "commit", "-qm", rel], {
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, GIT_AUTHOR_DATE: at, GIT_COMMITTER_DATE: at },
      });
      return git("rev-parse", "HEAD");
    };

    // Five commits an hour apart. Two are under the catalogue's directory —
    // `plugin.json` and a README, because a README reaches the catalogue — and
    // the other three sit where a drifting reader would land: `publishers/`,
    // which the index also reads but the serial does not count; `tools/`; and
    // the generated `registry/v1/index.json` itself, which is main's newest.
    const first = commit(`${CATALOGUE_PATHSPEC}/alpha/plugin.json`, "{}\n", "2026-09-19T08:00:00Z");
    commit("publishers/alpha.json", "{}\n", "2026-09-19T09:00:00Z");
    commit(`${CATALOGUE_PATHSPEC}/alpha/README.md`, "alpha\n", "2026-09-19T10:00:00Z");
    commit("tools/README-fixture.md", "under tools/\n", "2026-09-19T11:00:00Z");
    commit("registry/v1/index.json", "{}\n", "2026-09-19T12:00:00Z");
    const head = git("rev-parse", "HEAD");
    const count = (spec, ref = head) => Number(git("rev-list", "--count", ref, "--", spec));
    const newest = (spec) => git("log", "-1", "--format=%H", head, "--", spec) || null;
    const at = (sha) => Number(git("log", "-1", "--format=%ct", sha));
    const expect = { count: count(CATALOGUE_PATHSPEC), newest: newest(CATALOGUE_PATHSPEC) };

    // The fixture guard, before any reader is asked (gap 64's shape): every
    // neighbour must count a different number, and the ones that reach a
    // commit at all must date a different one, or a reader drifting to it
    // would be invisible here.
    const narrow = `${CATALOGUE_PATHSPEC}/*/plugin.json`;
    const neighbours = [".", "publishers", "registry", "tools", narrow, `${CATALOGUE_PATHSPEC}/*/versions`];
    for (const spec of neighbours) {
      assert(spec !== CATALOGUE_PATHSPEC, `the neighbour ${spec} is the catalogue's own pathspec; the fixture has nothing to separate`);
      assert(count(spec) !== expect.count,
        `the fixture cannot tell ${spec} from ${CATALOGUE_PATHSPEC}: both count ${expect.count} commit(s)`);
    }
    for (const spec of [".", "publishers", "registry", narrow]) {
      assert(newest(spec) !== expect.newest,
        `the fixture cannot tell ${spec} from ${CATALOGUE_PATHSPEC} by date: both newest at ${expect.newest}`);
    }
    const which = (n) => [CATALOGUE_PATHSPEC, ...neighbours].filter((s) => count(s) === n).join(" or ") || "no pathspec this fixture knows";

    // (a) and (b): build-index's regeneration, whose environment override is
    // taken out of the way for the calls, as gap 64's check does for the list.
    const override = process.env.ASTRA_REGISTRY_SERIAL;
    delete process.env.ASTRA_REGISTRY_SERIAL;
    let clean, pendingInside, pendingOutside;
    try {
      clean = resolveCatalogueSerial({ root: dir });
      // A pending change INSIDE the directory but outside the narrow neighbour,
      // and one OUTSIDE the directory but inside the wide neighbour. The guard
      // says each actually separates the two, so the verdicts below mean what
      // they say.
      const inside = `${CATALOGUE_PATHSPEC}/alpha/icon.txt`;
      const outside = "publishers/beta.json";
      put(inside, "pending\n");
      assert(git("status", "--porcelain", "--", narrow) === "",
        `the fixture's pending file ${inside} is visible to ${narrow}, so it cannot tell the narrow pathspec apart`);
      pendingInside = resolveCatalogueSerial({ root: dir });
      fs.rmSync(path.join(dir, inside));
      put(outside, "pending\n");
      assert(git("status", "--porcelain", "--", ".") !== "",
        `the fixture's pending file ${outside} is invisible to ".", so it cannot tell the wide pathspec apart`);
      pendingOutside = resolveCatalogueSerial({ root: dir });
      fs.rmSync(path.join(dir, outside));
    } finally {
      if (override !== undefined) process.env.ASTRA_REGISTRY_SERIAL = override;
    }
    assertEqual(git("status", "--porcelain"), "", "the fixture was left with a pending change");
    assertEqual(clean, expect.count,
      `build-index's serial counts over ${which(clean)}, and the catalogue's pathspec is ${CATALOGUE_PATHSPEC}: ` +
        "tools/build-index.mjs's resolveSerial has stopped counting over CATALOGUE_PATHSPEC");
    assertEqual(pendingInside, expect.count + 1,
      `a pending change under ${CATALOGUE_PATHSPEC}/ is the commit about to be made, and build-index did not count it: ` +
        "resolveSerial's pending-commit test has stopped reading CATALOGUE_PATHSPEC");
    assertEqual(pendingOutside, expect.count,
      `a pending change outside ${CATALOGUE_PATHSPEC}/ moved build-index's serial: ` +
        "resolveSerial's pending-commit test has stopped reading CATALOGUE_PATHSPEC");

    // (c) the signer, which assigns the serial that is published.
    const signer = serialsAt({ root: dir, sha: head }).index;
    assertEqual(signer, expect.count,
      `the signer's catalogue serial counts over ${which(signer)}: tools/signer/plan.mjs's serialsAt has stopped counting over CATALOGUE_PATHSPEC`);

    // (d) the carrier, which regenerates a signed catalogue from history.
    const carrier = serialFor(dir, head);
    assertEqual(carrier, expect.count,
      `tools/regenerate-signed.mjs's serialFor counts over ${which(carrier)}, and the signer over ${CATALOGUE_PATHSPEC}: ` +
        "a carrier would regenerate every signed catalogue at a serial it was not signed at");

    // (e) A7's plugins half, asked through the detector itself: `signed` made
    // from the first commit — both trailers naming it, as a signer run whose
    // catalogue and list came from one commit writes them — so the drift A7
    // reports names the commit it dated.
    git("checkout", "-q", "--orphan", "signed");
    git("rm", "-rq", "--cached", ".");
    put("SIGNED", "signed\n");
    git("add", "SIGNED");
    execFileSync("git", ["-C", dir, "commit", "-qm", `signed\n\nSource-Commit: ${first}\nIndex-Source-Commit: ${first}\n`], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GIT_AUTHOR_DATE: "2026-09-19T12:30:00Z", GIT_COMMITTER_DATE: "2026-09-19T12:30:00Z" },
    });
    git("checkout", "-q", "-f", "main");
    const findings = [], skipped = [], scanned = {};
    a7({ git: gitReader(dir), now: Date.parse("2026-09-19T12:30:00Z") }, findings, skipped, scanned);
    // The fixture's `signed` commit has to be one A7 accepts, or the half
    // below is asked of a commit no signer writes: contract 0.32.0's B.4 has
    // every `signed` commit name both trailers, and since astra-registry #227
    // A7 reports a missing `Index-Source-Commit` and does not run the
    // catalogue half's decision. The drift read below is written either way,
    // which is how a one-trailer fixture stayed green here after #227.
    const malformed = findings.filter((f) => /^A7_(NO_SOURCE_COMMIT|SOURCE_COMMIT_UNKNOWN|NO_INDEX_SOURCE_COMMIT|INDEX_SOURCE_COMMIT_UNKNOWN)$/.test(f.code));
    assertEqual(malformed.map((f) => f.code).join(","), "",
      "the fixture's `signed` commit is not one a signer writes, so A7 was asked about a commit it refuses");
    assertEqual(scanned.signed_index_source_commit, first, "A7 did not read the fixture's Index-Source-Commit");
    const drift = Math.floor((at(expect.newest) - at(first)) / 60);
    const datedBy = (m) => [CATALOGUE_PATHSPEC, ...neighbours]
      .filter((s) => newest(s) && Math.floor((at(newest(s)) - at(first)) / 60) === m).join(" or ") || "no pathspec this fixture knows";
    assertEqual(scanned.plugins_drift_minutes, drift,
      `A7's plugins half dates the newest commit under ${datedBy(scanned.plugins_drift_minutes)}, and the catalogue ` +
        `changes on commits under ${CATALOGUE_PATHSPEC}: bot/detectors.mjs has stopped reading CATALOGUE_PATHSPEC`);

    // (f) build-index.yml's own step, run as the workflow runs it: its `run:`
    // block, with the one expression it uses substituted, under bash, writing
    // to a GITHUB_OUTPUT of our own. Twice — with `origin/main` present, which
    // is the branch CI takes, and without it, which is the fallback.
    const yml = fs.readFileSync(path.join(REPO_ROOT, ".github/workflows/build-index.yml"), "utf8").split("\n");
    const named = yml.map((l, i) => [l, i]).filter(([l]) => /^\s+- name: Compute the serial from the commit count on the default branch\s*$/.test(l));
    assertEqual(named.length, 1, "build-index.yml has no single step named \"Compute the serial from the commit count on the default branch\"");
    const stepIndent = named[0][0].indexOf("-");
    let i = named[0][1] + 1;
    while (i < yml.length && !/^\s+run: \|\s*$/.test(yml[i])) {
      if (yml[i].trim() && yml[i].indexOf(yml[i].trim()) <= stepIndent) throw new Error("the serial step in build-index.yml has no `run: |` block");
      i++;
    }
    const runIndent = yml[i].indexOf("run:");
    const body = [];
    for (i += 1; i < yml.length && (!yml[i].trim() || yml[i].search(/\S/) > runIndent); i++) body.push(yml[i]);
    const pad = Math.min(...body.filter((l) => l.trim()).map((l) => l.search(/\S/)));
    const expr = "${{ github.event.repository.default_branch }}";
    let script = body.map((l) => l.slice(pad)).join("\n");
    assertEqual(script.split(expr).length - 1, 1, "the serial step no longer reads the default branch from exactly one expression");
    script = script.replace(expr, "main");
    assert(!script.includes("${{"), "the serial step uses an expression this check does not substitute");
    const step = () => {
      const out = path.join(tmp, "couplings-catalogue-github-output");
      fs.writeFileSync(out, "");
      execFileSync("bash", ["-c", script], { cwd: dir, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, GITHUB_OUTPUT: out } });
      const m = /^serial=(\d+)$/m.exec(fs.readFileSync(out, "utf8"));
      assert(m, "build-index.yml's serial step wrote no serial= line");
      return Number(m[1]);
    };
    git("update-ref", "refs/remotes/origin/main", head);
    const primary = step();
    git("update-ref", "-d", "refs/remotes/origin/main");
    const fallback = step();
    assertEqual(primary, expect.count,
      `build-index.yml's serial step counts origin/main over ${which(primary)}, and the signer over ${CATALOGUE_PATHSPEC}`);
    assertEqual(fallback, expect.count,
      `build-index.yml's serial step, without origin/main, counts HEAD over ${which(fallback)}, and the signer over ${CATALOGUE_PATHSPEC}`);
  });

  // ── entry 117: HOW each serial counts, which gaps 64 and 71 never asked ─────
  //
  // Gaps 64 and 71 hold every reader of each serial to one PATHSPEC, on
  // fixtures that are a straight line — where git's default count,
  // `--full-history` and `--first-parent` all give the same number. So nothing
  // asked how a count simplifies history at a merge, and git's DEFAULT count,
  // which DEC-9 published for both serials until contract 0.35.0, follows only
  // the parent of a merge that is TREESAME to it for the pathspec. Ops lane AV
  // measured two shapes where that makes the list's serial fall or hold at a
  // merge that adds an advisory (ops register entry 117):
  //
  //   (5) main adds an advisory and withdraws it after a branch forked, and the
  //       branch's own advisory merges — default counts 0, 1, 2 and then 1 at
  //       the merge; the signer's SERVE-36 gate refuses the list, D4 carries
  //       the old one under the merge's Source-Commit, and SERVE-85, detector
  //       A7 and row 7 all go quiet with the advisory unpublished;
  //   (6) the same README fix lands on main and inside a pull request that also
  //       adds an advisory — the merge's default count is the commit before it.
  //
  // DEC-9's list serial is `--full-history`'s from 0.35.0 (`SERIAL_FLAGS`):
  // every reachable commit whose tree under the directory differs from at least
  // one parent's. That predicate belongs to each commit, so the count cannot
  // fall along any ancestry and rises at every first-parent commit that changes
  // the list. The first check below holds the three list readers to it on both
  // shapes, built from this tree's own README and real advisories; the second
  // proves the head check below it can see a serial that falls or holds, on the
  // same shapes; the third asks it of main's own head on every run, for both
  // serials — for the list a regression guard, for the catalogue, which 0.35.0
  // did NOT move (the two counts differ at 233 of main's 337 first-parent
  // commits), the canary entry 117 asks for.

  /** A scratch repository whose commits are a minute apart, for the merge shapes. */
  function shapeRepo(name) {
    const dir = path.join(tmp, name);
    fs.mkdirSync(dir, { recursive: true });
    const git = (...a) =>
      execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
    git("init", "-q", "-b", "main");
    git("config", "user.email", "couplings-fixture@example.invalid");
    git("config", "user.name", "couplings fixture");
    git("config", "commit.gpgsign", "false");
    let minute = 0;
    const dated = (args) => {
      const at = new Date(Date.parse("2026-09-19T08:00:00Z") + 60000 * minute++).toISOString().replace(".000Z", "Z");
      execFileSync("git", ["-C", dir, ...args], {
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, GIT_AUTHOR_DATE: at, GIT_COMMITTER_DATE: at },
      });
      return git("rev-parse", "HEAD");
    };
    return {
      dir,
      git,
      put: (rel, body) => {
        fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
        fs.writeFileSync(path.join(dir, rel), body);
      },
      drop: (rel) => fs.rmSync(path.join(dir, rel)),
      commit: (message) => {
        git("add", "-A");
        return dated(["commit", "-qm", message]);
      },
      merge: (branch, message) => dated(["merge", "-q", "--no-ff", "-m", message, branch]),
    };
  }

  /**
   * Entry 117's two shapes under directory `under`: `file(n)` is entry n's
   * [path, bytes], `readme` the directory's README. Each shape is
   * `{name, repo, before, merge}` — `before` main's commit the merge's first
   * parent is, `merge` the merge.
   */
  function entry117Shapes(label, under, file, readme) {
    const fix = "\nA sentence fixed on two branches at once.\n";

    const five = shapeRepo(`couplings-entry117-${label}-5`);
    five.put("README.md", "a registry\n");
    five.commit("seed");
    five.git("checkout", "-q", "-b", "topic");
    five.put(...file(2));
    five.commit("an entry, on a branch");
    five.git("checkout", "-q", "main");
    five.put(...file(1));
    five.commit("an entry, in error");
    five.drop(file(1)[0]);
    const before5 = five.commit("the entry made in error, withdrawn");
    const merge5 = five.merge("topic", "Merge pull request #2 from topic");

    const six = shapeRepo(`couplings-entry117-${label}-6`);
    six.put(`${under}/README.md`, readme);
    six.commit("the directory and its README");
    six.git("checkout", "-q", "-b", "topic");
    six.put(`${under}/README.md`, readme + fix);
    six.put(...file(1));
    six.commit("an entry, and the README fix");
    six.git("checkout", "-q", "main");
    six.put(`${under}/README.md`, readme + fix);
    const before6 = six.commit("the same README fix, on main");
    const merge6 = six.merge("topic", "Merge pull request #3 from topic");

    return [
      { name: "(5) an entry withdrawn on main, a branch's entry merged", repo: five, before: before5, merge: merge5 },
      { name: "(6) one README fix on both sides, an entry merged with it", repo: six, before: before6, merge: merge6 },
    ];
  }

  /** `sha:spec`'s tree id, or null where the path is not in that commit (or there is no commit). */
  const treeAt = (git, sha, spec) => {
    if (!sha) return null;
    try {
      return git("rev-parse", "-q", "--verify", `${sha}:${spec}`);
    } catch {
      return null;
    }
  };

  /**
   * DEC-9's gloss, counted without asking git to simplify anything: the commits
   * reachable from `sha` whose tree under `spec` differs from at least one of
   * their parents' (a root commit's parent is the empty tree).
   */
  function glossCount(git, sha, spec) {
    const trees = new Map();
    const tree = (c) => {
      if (!trees.has(c)) trees.set(c, treeAt(git, c, spec));
      return trees.get(c);
    };
    let n = 0;
    for (const line of git("rev-list", "--parents", sha).split("\n").filter(Boolean)) {
      const [c, ...parents] = line.split(" ");
      if (parents.length === 0 ? tree(c) !== null : parents.some((p) => tree(p) !== tree(c))) n++;
    }
    return n;
  }

  /**
   * Entry 117's canary at one commit: each serial `serialsAt` gives there,
   * against its first parent's, and each pathspec's tree at both. A root
   * commit is compared with the empty history, where nothing is counted and
   * the list is at its reserved zero plus one — a real question with a real
   * answer, so it is asked rather than skipped. Returns the numbers and one
   * problem per serial that fell, or held across a change under its pathspec.
   */
  function headSerialProblems(root, sha = "HEAD") {
    const git = (...a) =>
      execFileSync("git", ["-C", root, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
    const head = git("rev-parse", "--verify", `${sha}^{commit}`);
    let parent = null;
    try {
      parent = git("rev-parse", "-q", "--verify", `${head}^1`);
    } catch {
      parent = null;
    }
    const at = serialsAt({ root, sha: head });
    const before = parent ? serialsAt({ root, sha: parent }) : { index: 0, revocations: 1 };
    const where = parent ? `its first parent ${parent.slice(0, 12)}` : "the empty history before a root commit";
    const problems = [];
    for (const [key, spec, what] of [
      ["revocations", SERIAL_PATHSPEC, "the withdrawal list"],
      ["index", CATALOGUE_PATHSPEC, "the catalogue"],
    ]) {
      const changed = treeAt(git, head, spec) !== treeAt(git, parent, spec);
      if (at[key] < before[key]) {
        problems.push(`${what}'s serial falls from ${before[key]} at ${where} to ${at[key]} at ${head.slice(0, 12)}`);
      } else if (changed && at[key] === before[key]) {
        problems.push(`${what}'s serial holds at ${at[key]} from ${where} to ${head.slice(0, 12)}, across a change under ${spec}/`);
      }
    }
    return { head, parent, at, before, problems };
  }

  const listReadme = fs.readFileSync(path.join(REPO_ROOT, SOURCE_DIR, "README.md"), "utf8");
  const listEntry = (n) => {
    const id = `ASTRA-2026-${String(n).padStart(4, "0")}`;
    const doc = {
      id,
      published: "2026-09-10",
      severity: "high",
      action: "block_install",
      reason: "A fixture advisory, long enough to be a sentence a user can act on.",
      entries: [{ kind: "id", value: `fixture-${n}` }],
    };
    return [`${SOURCE_DIR}/${id}.json`, `${JSON.stringify(doc, null, 2)}\n`];
  };
  const catalogueEntry = (n) => [
    `${CATALOGUE_PATHSPEC}/fixture-${n}/plugin.json`,
    `${JSON.stringify({ schema: "astra.registry.plugin/1", id: `fixture-${n}` }, null, 2)}\n`,
  ];

  await test("entry 117 — the list's serial never falls and rises at every first-parent commit that changes the list, on the two merges git's default count lowers or holds: the signer's, the regeneration's and SERVE-85's", () => {
    // The fixture's own material, first: its advisories are advisories by the
    // validator's word, so SERVE-85's list builds at every commit and a red
    // below is about a count and not about a file the generator refused.
    for (const n of [1, 2]) {
      const [rel, body] = listEntry(n);
      const errs = checkAdvisory(JSON.parse(body), rel);
      assert(errs.length === 0, `the fixture's advisory is not one: ${errs.join("; ")}`);
    }
    const override = process.env.ASTRA_REVOCATIONS_SERIAL;
    delete process.env.ASTRA_REVOCATIONS_SERIAL;
    try {
      for (const shape of entry117Shapes("list", SOURCE_DIR, listEntry, listReadme)) {
        const { repo, before, merge } = shape;
        // The fixture guard: git's default count must hold or fall at this
        // merge, or the shape cannot see the formula 0.35.0 replaced.
        const byDefault = (sha) => Number(repo.git("rev-list", "--count", sha, "--", SERIAL_PATHSPEC));
        assert(byDefault(merge) <= byDefault(before),
          `${shape.name}: git's default count rises at the merge (${byDefault(before)} → ${byDefault(merge)}), so this ` +
            "fixture cannot tell DEC-9's count from the one it replaced");

        // Each reader, at each commit on main's first-parent line, against
        // the commit before it on that line: never lower, and higher wherever
        // the list's tree changed. Then exactly DEC-9's gloss, so a reader that
        // is monotone by some other count is red too.
        const line = repo.git("rev-list", "--first-parent", "--reverse", "main").split("\n");
        const prev = {};
        let prevSha = null;
        for (const sha of line) {
          const want = glossCount(repo.git, sha, SERIAL_PATHSPEC) + 1;
          const changed = prevSha !== null &&
            treeAt(repo.git, sha, SERIAL_PATHSPEC) !== treeAt(repo.git, prevSha, SERIAL_PATHSPEC);
          repo.git("checkout", "-q", "--detach", sha);
          const readers = {
            "the signer's serialsAt": serialsAt({ root: repo.dir, sha }).revocations,
            "the regeneration's resolveSerial": resolveSerial({ root: repo.dir }),
            "SERVE-85's gather": gather({ root: repo.dir }).generated?.serial,
          };
          for (const [who, got] of Object.entries(readers)) {
            if (prevSha !== null) {
              assert(got >= prev[who] && (!changed || got > prev[who]),
                `${shape.name}: ${who} takes the list serial ${prev[who]} → ${got} at ${sha.slice(0, 12)}` +
                  `${changed ? `, a commit that changes ${SERIAL_PATHSPEC}/` : ""} — DEC-9's count may never fall, ` +
                  "and rises wherever the list changes. It has stopped counting with SERIAL_FLAGS (ops register entry 117)");
            }
            assertEqual(got, want,
              `${shape.name}, at ${sha.slice(0, 12)}: ${who} gives the list serial ${got}, and DEC-9's count — every ` +
                `reachable commit whose tree under ${SERIAL_PATHSPEC}/ differs from one of its parents', plus one — ` +
                `gives ${want}. It has stopped counting with SERIAL_FLAGS (ops register entry 117)`);
            prev[who] = got;
          }
          prevSha = sha;
        }
        repo.git("checkout", "-q", "main");
      }
    } finally {
      if (override !== undefined) process.env.ASTRA_REVOCATIONS_SERIAL = override;
    }

    // And what the shape did to the one check that compares main with
    // `signed`: `signed` at (5)'s withdrawal, the merge that adds an advisory
    // after it. With the default count the merge gave the list serial 2 below
    // `signed`'s 3 and SERVE-85 called it the system working, for as long as
    // it lasted; it has to page, and not before its grace.
    const [five] = entry117Shapes("serve85", SOURCE_DIR, listEntry, listReadme);
    const served = serialsAt({ root: five.repo.dir, sha: five.before }).revocations;
    const doc = { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: served, revocations: [] } };
    const head = {
      present: true, reason: null, sha: "a".repeat(40), parseErrors: [],
      bytes: { revocations: stableStringify(doc) }, documents: { revocations: doc },
    };
    const facts = gather({ root: five.repo.dir });
    const merged = five.repo.git("log", "-1", "--format=%cI", five.merge);
    const at = (minutes) => new Date(Date.parse(merged) + minutes * 60000).toISOString();
    assertEqual(serve85({ ...facts, head, now: at(29) }).status, "green",
      `(5): SERVE-85 paged 29 minutes after the merge, inside its grace: ${serve85({ ...facts, head, now: at(29) }).findings.map((f) => f.code)}`);
    const late = serve85({ ...facts, head, now: at(31) });
    assertEqual(late.findings.map((f) => f.code).join(","), "SERVE_85_SERIAL_DRIFT",
      `(5): 31 minutes after a merge that adds an advisory to a list \`signed\` serves at ${served}, SERVE-85 ` +
        `reported ${late.status} (${late.notes.slice(1).join(" | ")}) — the silence ops register entry 117 measured`);
  });

  await test("entry 117 — the head check sees a serial that falls or holds at a merge: red for the catalogue, which counts by git's default, on both shapes, and green for the list", () => {
    // Proved on the shapes, because main's real history has never held either
    // (both serials rise at all 337 first-parent commits at 3653dc5): a check
    // whose case the corpus never contained is proved on a corpus that does.
    const catalogue = entry117Shapes("catalogue", CATALOGUE_PATHSPEC, catalogueEntry, "the plugins\n");
    const list = entry117Shapes("head-list", SOURCE_DIR, listEntry, listReadme);
    const override = process.env.ASTRA_REGISTRY_SERIAL;
    delete process.env.ASTRA_REGISTRY_SERIAL;
    try {
      for (const shape of catalogue) {
        const r = headSerialProblems(shape.repo.dir);
        assertEqual(r.head, shape.merge, `${shape.name}: the head check read ${r.head}, not the merge`);
        assertEqual(r.problems.length, 1,
          `${shape.name}, under ${CATALOGUE_PATHSPEC}/: the head check found ${JSON.stringify(r.problems)} — the ` +
            "catalogue's serial counts by git's default, which holds or lowers here, and the canary on main is only " +
            "as good as its answer on this merge");
        assert(r.problems[0].startsWith("the catalogue's serial"), `${shape.name}: ${r.problems[0]}`);
        // The catalogue's other readers count as the signer does at this
        // merge: gap 71 holds their pathspec on a line, and a line cannot
        // tell one counting mode from another.
        assertEqual(resolveCatalogueSerial({ root: shape.repo.dir }), r.at.index,
          `${shape.name}: build-index's resolveSerial and the signer count the catalogue differently at a merge`);
        assertEqual(serialFor(shape.repo.dir, shape.merge), r.at.index,
          `${shape.name}: the carrier's serialFor and the signer count the catalogue differently at a merge`);
      }
      for (const shape of list) {
        const r = headSerialProblems(shape.repo.dir);
        assertEqual(r.head, shape.merge, `${shape.name}: the head check read ${r.head}, not the merge`);
        assertEqual(r.problems.length, 0,
          `${shape.name}, under ${SERIAL_PATHSPEC}/: ${r.problems.join("; ")} — DEC-9's --full-history count cannot ` +
            "do this, so a list reader has stopped counting with SERIAL_FLAGS (ops register entry 117)");
        assert(r.at.revocations > r.before.revocations,
          `${shape.name}: the list serial is ${r.before.revocations} → ${r.at.revocations} at a merge that adds an advisory`);
      }
    } finally {
      if (override !== undefined) process.env.ASTRA_REGISTRY_SERIAL = override;
    }
  });

  await test("entry 117 — at main's head neither serial falls, or holds across a change under its pathspec: the list's by construction, the catalogue's as the canary", () => {
    // Asked of whatever this suite's own checkout holds: on `main` the commit
    // just pushed, on a pull request the merge `actions/checkout` builds, whose
    // first parent is the base. Both serials are counted over the whole
    // history, so a shallow checkout counts what it was given and nothing here
    // is askable. The runner finds this gate by reading it — a `neverAsk(`
    // first in the block of an `if` whose whole condition is the shallowness
    // question — and prints the live lanes that ask it. Keep it written that way.
    if (isShallow(REPO_ROOT)) {
      neverAsk(
        "this checkout is shallow, and both serials are commit counts over the whole history, so HEAD's and its " +
        "parent's are the commits this checkout holds and a fall or a hold here says nothing about main",
        "a checkout with its whole history asks it: the runner prints the live lanes that reach this suite with " +
        "it under the totals and goes red when there are none (`node tools/selftest.mjs --lanes`)",
      );
    }
    const r = headSerialProblems(REPO_ROOT);
    console.log(
      `      (at ${r.head.slice(0, 12)}: list ${r.before.revocations} → ${r.at.revocations}, catalogue ` +
      `${r.before.index} → ${r.at.index}, from ${r.parent ? r.parent.slice(0, 12) : "the empty history"})`,
    );
    assert(r.problems.length === 0,
      `${r.problems.join("; ")}. For the list this cannot happen under DEC-9's --full-history count (SERIAL_FLAGS), so ` +
        "a reader or the flags have changed. For the catalogue it is the hazard contract 0.35.0 did not carry: its " +
        "serial counts by git's default, which a merge can hold or lower, and the signer refuses the catalogue — " +
        "SERVE-36 for a serial that fell, its equal-serial gate (TRUST-28) for one that held across a change — and " +
        "carries the old one. Ops register entry 117, and item 24 of ops dev/server-registry-contract-pending.md: DEC-9's catalogue formula is the " +
        "decision it waits on");
  });

  // ── TRUST-43's anchor, and the three files that make it narrow ─────────────
  //
  // Gap 111. Contract 0.33.0 moved TRUST-43's hold from a `signed` commit's
  // `Source-Commit` to its catalogue's `Index-Source-Commit`, and its Why argues
  // the move is narrow: *"every commit under `plugins/` moves the catalogue's
  // serial (DEC-9), so a flagged commit makes the next catalogue a changed one,
  // generated from it and held at once, unless that run's catalogue gate
  // fails"*. That sentence is true because of three facts in three files, and
  // none of the three names TRUST-43:
  //
  //   * `CATALOGUE_PATHSPEC` (tools/build-index.mjs) counts every path detector
  //     9 flags, so a commit touching only one of them moves the serial;
  //   * `decideDocument` (tools/signer/plan.mjs) calls a catalogue unchanged
  //     only when everything in `signed` but `issued_at` and `expires_at`
  //     matches, so a moved serial is a `changed` catalogue;
  //   * `signRun` (tools/signer/run.mjs) writes this run's Source-Commit as a
  //     changed catalogue's `Index-Source-Commit`, and keeps the head's for an
  //     unchanged or carried one.
  //
  // The three do not fail alike, and the messages below say which is which.
  // Narrow the pathspec so it skips `identity.json`, or judge `unchanged` on a
  // subset that leaves the serial out, and the run after a hand-committed
  // identity record keeps the head's catalogue and its `Index-Source-Commit`
  // from BEFORE the record: every `signed` commit after it switches
  // unacknowledged until the next catalogue change or re-sign (a `resign`
  // also writes the run's own Source-Commit, at `RESIGN_AFTER_HOURS`). What is
  // served meanwhile carries none of the change — measured, the run an hour
  // after is `unchanged` with the old trailer and the one 21 h after is
  // `resign` with the new — so what breaks is the Why's *"held at once"* and
  // its *"the only case the anchor changes"*, and the hold comes late. Break
  // the third and it is worse: a catalogue GENERATED from the flagged commit,
  // carrying a changed `source`, is served under the head's trailer, and the
  // change itself switches unacknowledged. So this runs the three end to end,
  // as the signer does, on each commit detector 9 flags.
  //
  // **Detector 9's class is read from detector 9, not copied here.** A9 in
  // `bot/detectors.mjs` is the registry's one statement of it (the contract's
  // BOT-44 row 9 is the prose it implements). A9 runs over the fixture and says
  // which commits it flags; a spy on its git reader records every pathspec it
  // scans history for and every status letter it filters a commit's paths by.
  // So a path or a status A9 starts flagging that this fixture has no commit
  // for is red here by name, rather than a class member nobody asked about. The
  // anchor is built by hand — a real `log/baseline.json` would be validated
  // inside the signer's gate, which is not this check's subject — and
  // everything A9 does after it is its own.
  //
  // What this does NOT ask: the gate-failure half of the Why. A commit
  // changing only `source.repo` fails the gate (its releases name the old
  // repo), and the signer carries the head's catalogue and its
  // `Index-Source-Commit` — correctly, since that catalogue carries none of it.
  // Every flagged commit here passes the gate, so the only arm reached is the
  // one TRUST-43 relies on.

  await test("gap 111 — a commit detector 9 flags moves the catalogue's Index-Source-Commit to itself: A9's class, the catalogue's serial, the signer's `unchanged` and its trailer agree, which is what TRUST-43's anchor rests on", async () => {
    const dir = path.join(tmp, "couplings-trust43-anchor");
    fs.mkdirSync(dir, { recursive: true });
    const git = (...a) =>
      execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
    git("init", "-q", "-b", "main");
    git("config", "user.email", "couplings-fixture@example.invalid");
    git("config", "user.name", "couplings fixture");
    git("config", "commit.gpgsign", "false");
    const put = (rel, value) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), typeof value === "string" ? value : stableStringify(value));
    };
    const read = (rel) => JSON.parse(fs.readFileSync(path.join(dir, rel), "utf8"));
    const commit = (message) => {
      git("add", "-A");
      git("commit", "-qm", message);
      return git("rev-parse", "HEAD");
    };

    // The committed TEST key, delegated long past SERVE-30's seven hours so it
    // may sign the catalogue on every run below.
    const KEY = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
    const key = loadTestRoot(KEY);
    const available = [{ key_id: KEY, privateKey: key.privateKey, public_key: key.publicKeyB64 }];
    const delegatedAt = new Map([[KEY, "2026-09-01T00:00:00Z"]]);
    // One hour between the head and the run: inside D4's cadence, so a
    // catalogue the signer thinks unchanged is `unchanged` and keeps the head's
    // trailer. Past it the run would `resign`, which also writes this run's
    // Source-Commit — and would pass for the wrong reason.
    const HEAD_AT = "2026-09-19T00:00:00Z";
    const RUN_AT = "2026-09-19T01:00:00Z";
    assert(RESIGN_AFTER_HOURS > 1,
      `RESIGN_AFTER_HOURS is ${RESIGN_AFTER_HOURS}, so a run an hour after the head re-signs and says nothing about \`unchanged\``);
    const RUN_URL = "https://github.com/mihailinl/astra-registry/actions/runs/111";

    const listing = (id) => ({
      schema: "astra.registry.plugin/1",
      id,
      name: id,
      summary: "A listing that exists so the catalogue is not empty.",
      license: "MIT",
      source: { kind: "github", repo: `someone/${id}` },
      added_at: "2026-08-10",
    });
    const release = (id) => ({
      schema: "astra.registry.version/1",
      id,
      version: "1.0.0",
      published_at: "2026-08-10T00:00:00Z",
      release: { kind: "github_release", repo: `someone/${id}`, tag: "v1.0.0" },
      protocol: 1,
      capabilities: ["tools"],
      artifacts: {
        "linux-x64": {
          url: `https://github.com/someone/${id}/releases/download/v1.0.0/${id}-1.0.0-linux-x64.astraplugin`,
          filename: `${id}-1.0.0-linux-x64.astraplugin`,
          sha256: "a".repeat(64),
          size: 1234,
        },
      },
    });
    // B.4's six members, valid, so the signer's gate passes and the only thing
    // a run can say about the record is what the serial says.
    const identity = (id, n) => ({
      schema: "astra.registry.identity/1",
      plugin_id: id,
      repository_id: String(1000 + n),
      repository_owner_id: String(2000 + n),
      repo: `someone/${id}`,
      token_hash: String(n).repeat(16),
    });

    put(SIGNED_FILES.trust, {
      signatures: [],
      signed: {
        schema: TRUST_SCHEMA,
        serial: 1,
        issued_at: "2026-09-01T00:00:00Z",
        expires_at: "2027-09-01T00:00:00Z",
        index_keys: [{ key_id: KEY, public_key: key.publicKeyB64 }],
      },
    });
    put(SIGNED_FILES.root, { schema: "astra.registry.root/1", roots: [] });
    for (const id of ["alpha", "beta"]) {
      put(`plugins/${id}/plugin.json`, listing(id));
      put(`plugins/${id}/versions/1.0.0.json`, release(id));
    }
    put("plugins/alpha/identity.json", identity("alpha", 1));
    const base = commit("two listings, one of them bound");

    // Row 10's hand commits, one path each: an identity record rewritten, one
    // added to a listing that had none, and `source` changed and nothing else.
    // The committed tree has never held an identity record (`git log --all --
    // 'plugins/*/identity.json'` is empty), so the case is synthesised.
    put("plugins/alpha/identity.json", identity("alpha", 2));
    commit("alpha's identity record, rewritten by hand");
    put("plugins/beta/identity.json", identity("beta", 3));
    commit("an identity record for beta, added by hand");
    const beta = read("plugins/beta/plugin.json");
    beta.source.subdirectory = "plugin";
    put("plugins/beta/plugin.json", beta);
    commit("beta's source, changed by hand");
    const tip = git("rev-parse", "HEAD");

    // Detector 9, asked, through a reader that records what it asks.
    const reader = gitReader(dir);
    const scannedSpecs = new Set();
    const filters = [];
    const spy = {
      ...reader,
      commitsTouching(from, to, specs) {
        for (const s of specs) scannedSpecs.add(s);
        return reader.commitsTouching(from, to, specs);
      },
      changedIn(sha, filter, specs = []) {
        filters.push({ filter, specs });
        return reader.changedIn(sha, filter, specs);
      },
    };
    const findings = [], skipped = [], scanned = {};
    a9({ anchor: { present: true, addedBy: base }, git: spy }, findings, skipped, scanned);
    assertEqual(skipped.map((s) => s.why).join("; "), "", "A9 skipped the fixture, so nothing below asks detector 9 anything");
    assert(scannedSpecs.size > 0, "A9 scanned history for no pathspec, so there is no class here to read");
    // The class as A9 filters it: a status letter and a pathspec, for each
    // filter A9 applies over the pathspecs it scanned for. `log/decisions` is
    // where it looks for the record that excuses a change, not a member.
    const members = new Set();
    for (const { filter, specs } of filters) {
      if (!specs.length || !specs.every((s) => scannedSpecs.has(s))) continue;
      for (const letter of filter) for (const s of specs) members.add(`${letter} ${s}`);
    }
    assert(members.size > 0,
      "A9 filtered no commit's paths by a pathspec it scanned for, so this spy no longer sees how A9 reads its class");
    const flaggedSet = new Set(findings.map((f) => f.hex));
    const flagged = git("rev-list", "--reverse", `${base}..${tip}`).split("\n").filter((sha) => flaggedSet.has(sha));
    assert(flagged.length > 0, "A9 flagged nothing in a history of hand-committed identity and source changes");

    const TRUST43 =
      "TRUST-43 (contract 0.33.0) holds a `signed` commit whose catalogue's Index-Source-Commit descends from a commit " +
      "detector 9 flags, and its Why argues that anchor is narrow because \"every commit under plugins/ moves the " +
      "catalogue's serial (DEC-9), so a flagged commit makes the next catalogue a changed one, generated from it and " +
      "held at once\". That rests on CATALOGUE_PATHSPEC (tools/build-index.mjs) counting every path A9 flags, on " +
      "decideDocument (tools/signer/plan.mjs) calling a catalogue unchanged only when everything but issued_at and " +
      "expires_at matches, and on signRun (tools/signer/run.mjs) writing a changed catalogue's Index-Source-Commit as " +
      "the run's own. This is the contract's argument breaking, not a test: repair the file, or reopen TRUST-43's " +
      "Why (ops dev/couplings.md entry 111) — do not edit this check to match";
    // What each break does, because they differ (the header above has the measurement).
    const LATE =
      "So the run after the flag keeps the head's catalogue and its Index-Source-Commit from before the flag: the " +
      "anchors differ with no failed gate, every `signed` commit after the flag switches unacknowledged until the next " +
      "catalogue change or re-sign, and the Why's \"held at once\" and \"the only case the anchor changes\" are false. " +
      "What is served meanwhile carries none of the change; the hold comes late, not never";
    const SERVED =
      "So a catalogue generated from the flagged commit (carrying the change itself, where the commit changed `source`) " +
      "is served under a trailer from before it, and TRUST-43 lets it switch unacknowledged";

    const covered = new Set();
    const coveredSpecs = new Set();
    for (const [i, sha] of flagged.entries()) {
      const parent = git("rev-parse", `${sha}^`);
      const changed = git("diff-tree", "--no-commit-id", "-r", "--name-status", sha).split("\n").filter(Boolean);
      assertEqual(changed.length, 1,
        `the fixture commit ${sha.slice(0, 12)} changes ${changed.length} paths, and "a commit touching only that path" needs one`);
      const [status, file] = changed[0].split("\t");

      // `signed`'s head: a run at the parent, committed with D2's trailers and
      // read back the way the signer reads its head.
      git("checkout", "-q", "--detach", parent);
      const prior = await signRun({ root: dir, sourceCommit: parent, head: { present: false }, now: HEAD_AT, available, delegatedAt });
      assertEqual(`${prior.documents.index?.decision} ${prior.commit}`, "changed true",
        `the fixture's head could not be signed at ${parent.slice(0, 12)}: ${[...prior.refusals, ...prior.alerts].join(" | ")}`);
      const signedSha = buildSignedCommit({ root: dir, files: prior.files, parent: null, message: commitMessage(prior, RUN_URL) });
      const ref = `refs/astra-signer/trust43-${i}`;
      git("update-ref", ref, signedSha);
      const head = fetchSignedHead({ root: dir, fetch: false, ref });
      assertEqual(trailersOf(git("log", "-1", "--format=%B", signedSha))["Index-Source-Commit"], parent,
        "the fixture's head does not name its parent as Index-Source-Commit, so moving off it proves nothing");

      git("checkout", "-q", "--detach", sha);
      const was = serialsAt({ root: dir, sha: parent }).index;
      const is = serialsAt({ root: dir, sha }).index;
      assert(is > was,
        `${sha.slice(0, 12)} changes only ${file} (${status}), which detector 9 flags, and the catalogue's serial did ` +
          `not move (${was} → ${is}): CATALOGUE_PATHSPEC is ${JSON.stringify(CATALOGUE_PATHSPEC)} and does not count it. ${LATE}. ${TRUST43}`);

      const run = await signRun({ root: dir, sourceCommit: sha, head, now: RUN_AT, available, delegatedAt });
      assertEqual(run.documents.index?.decision, "changed",
        `${sha.slice(0, 12)} changes only ${file} (${status}), which detector 9 flags, and moved the serial ${was} → ${is}, ` +
          `and the signer did not call the catalogue changed${run.alerts.length ? ` (${run.alerts.join(" | ")})` : ""}: ` +
          `decideDocument no longer treats a moved serial as a change. ${LATE}. ${TRUST43}`);
      const trailer = trailersOf(commitMessage(run, RUN_URL))["Index-Source-Commit"];
      assertEqual(trailer, sha,
        `the signer published a changed catalogue generated at ${sha.slice(0, 12)}, which changes only ${file}, under ` +
          `Index-Source-Commit ${String(trailer).slice(0, 12)}${trailer === parent ? " (the head's, from before the flag)" : ""}: ` +
          `signRun no longer writes its own Source-Commit for a changed catalogue. ${SERVED}. ${TRUST43}`);
      assertEqual(`${run.commit} ${run.refusals.join(" | ")}`, "true ",
        `the run at ${sha.slice(0, 12)} would not commit, so no \`signed\` commit carries that trailer`);

      for (const s of scannedSpecs) {
        if (git("diff-tree", "--no-commit-id", "-r", "--name-only", sha, "--", s) !== "") coveredSpecs.add(s);
      }
      for (const m of members) {
        const [letter, spec] = m.split(" ");
        if (letter === status && git("diff-tree", "--no-commit-id", "-r", "--name-only", sha, "--", spec) !== "") covered.add(m);
      }
    }
    git("checkout", "-q", "main");

    // The census, both ways from A9: every pathspec it scans and every status
    // it filters by has a flagged commit above that ran the whole chain. A
    // member A9 grows is a member this fixture must grow a commit for — and
    // if it lies outside plugins/, TRUST-43's "Detector 9's class lies under
    // plugins/**" is the sentence that stops being true.
    const unscanned = [...scannedSpecs].filter((s) => !coveredSpecs.has(s));
    assertEqual(unscanned.join(", "), "",
      `A9 scans history for these and no flagged commit here touches them, so nothing asked whether they move the ` +
        `catalogue's Index-Source-Commit — add a commit for each. ${TRUST43}`);
    const uncovered = [...members].filter((m) => !covered.has(m));
    assertEqual(uncovered.join(", "), "",
      `A9 flags these (status pathspec) and no commit here exercised them — add one for each. ${TRUST43}`);
  });

  // ── the advisory directory, which two readers of history parse ─────────────
  //
  // Gap 72. `nextAdvisoryId` logs `SOURCE_DIR/` and parsed the output with a
  // regex that spelled the directory for itself; the moderation-coverage
  // canary's `ADVISORY_RE` did the same. Moved, the log would list the new
  // paths and neither regex would match one: the next id would be 0001 again
  // and the canary would see no advisory ever written. Both build their
  // pattern from `SOURCE_DIR` now. This asks both, on a history written under
  // `SOURCE_DIR` — so a mutation of the constant moves the fixture, and a
  // reader that did not follow it is red — with decoys a loose pattern takes.

  await test("gap 72 — the advisory directory history is parsed under is the one advisories are written to: the next id's and the coverage canary's", () => {
    const dir = path.join(tmp, "couplings-advisory-dir");
    fs.mkdirSync(dir, { recursive: true });
    const git = (...a) =>
      execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
    git("init", "-q", "-b", "main");
    git("config", "user.email", "couplings-fixture@example.invalid");
    git("config", "user.name", "couplings fixture");
    git("config", "commit.gpgsign", "false");
    const commit = (rel) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), "{}\n");
      git("add", "-A");
      git("commit", "-qm", rel);
      return git("rev-parse", "HEAD");
    };
    commit(`${SOURCE_DIR}/README.md`);
    const real = [commit(`${SOURCE_DIR}/ASTRA-2026-0001.json`), commit(`${SOURCE_DIR}/ASTRA-2026-0002.json`)];
    // Decoys, each an id higher than the real ones, so a reader that took one
    // hands out the wrong next id rather than the right one by luck: a sibling
    // sharing the prefix, the same path under another tree, and a subdirectory.
    const decoys = [
      commit(`${SOURCE_DIR}-archive/ASTRA-2026-0009.json`),
      commit(`docs/${SOURCE_DIR}/ASTRA-2026-0008.json`),
      commit(`${SOURCE_DIR}/drafts/ASTRA-2026-0007.json`),
    ];
    // The fixture guard: the subdirectory decoy is inside the log's own
    // pathspec, so only the pattern can refuse it, and the two real advisories
    // are what the log lists under the directory.
    const logged = git("log", "--diff-filter=A", "--name-only", "--format=", "--", `${SOURCE_DIR}/`).split("\n").filter(Boolean);
    assert(logged.includes(`${SOURCE_DIR}/drafts/ASTRA-2026-0007.json`),
      "the subdirectory decoy is outside nextAdvisoryId's log pathspec, so this fixture cannot hold its pattern's anchor");
    assertEqual(pathUnder(SOURCE_DIR, "x").test(`${SOURCE_DIR}/x`), true, "pathUnder does not match its own directory");
    // The escape, which the committed directory has no character to exercise:
    // a directory name is a literal, and a `.` or a `+` in one is not a pattern.
    assertEqual([pathUnder("a.b+c", "x").test("a.b+c/x"), pathUnder("a.b+c", "x").test("aXbbc/x")].join(","), "true,false",
      "tools/lib/revocations.mjs's pathUnder does not escape the directory it is given");

    // (a) the next id.
    assertEqual(nextAdvisoryId({ root: dir, year: 2026 }), "ASTRA-2026-0003",
      `bot/lib/compile-decision.mjs's nextAdvisoryId did not count exactly the two advisories under ${SOURCE_DIR}/ ` +
        "(0001 means it saw none — its pattern names another directory; 0008 to 0010 means it took a decoy)");

    // (b) the coverage canary, one commit at a time.
    const advisoryTriggers = (sha) => triggersOf(sha, dir).triggers.filter((t) => t.kind === "advisory-written").map((t) => t.advisory);
    real.forEach((sha, n) => assertEqual(JSON.stringify(advisoryTriggers(sha)), JSON.stringify([`ASTRA-2026-000${n + 1}`]),
      `tools/moderation-coverage.mjs's triggersOf did not see the advisory written under ${SOURCE_DIR}/ at ${sha.slice(0, 12)}: ` +
        "its ADVISORY_RE names another directory"));
    for (const sha of decoys) {
      assertEqual(JSON.stringify(advisoryTriggers(sha)), "[]",
        `tools/moderation-coverage.mjs's triggersOf took a decoy at ${sha.slice(0, 12)} for an advisory: its ADVISORY_RE is not anchored to ${SOURCE_DIR}/`);
    }
  });

  // ── the advisory id's grammar, which seven readers and one writer share ─────
  //
  // Gap 72's tails. The id is `ASTRA-`, a four-digit year, `-`, and four OR
  // MORE serial digits: `schema/decision-v1.json` publishes that, and the
  // writer needs it, because `nextAdvisoryId` pads to four and never resets.
  // It was typed in five modules, and the coverage canary's copy took exactly
  // four — measured 2026-09-22: with `ASTRA-2026-10000.json` committed,
  // `triggersOf` returned [] while `nextAdvisoryId` went on to 10001, so from
  // the ten-thousandth advisory on the canary would have been green about
  // withdrawals it could not see. They all read `tools/lib/ids.mjs` now.
  //
  // This does not trust the imports. Every reader is ASKED about one set of
  // ids, through its own entry point, and must answer what the grammar
  // answers; a guard first proves the set separates the grammar from each
  // neighbour a copy could drift to. The docs detector is held to a different
  // relation, and says so: it is a heuristic that must SEE every id, not a
  // validator, so it may take more.

  await test("gap 72's tails — an advisory id is one grammar, tools/lib/ids.mjs's: the validator, the moderation log's advisory and reverses, the site's page guard, every schema that spells one, the next id and the coverage canary take the same ids; the next id writes one; the docs detector sees every one", () => {
    const grammar = new RegExp(ADVISORY_ID_PATTERN);
    // Four- and five-digit serials, a six, a zero-padded five, the last
    // four-digit one — and refusals, each of which some neighbour takes.
    const ids = [
      "ASTRA-2026-0001", "ASTRA-2026-9999", "ASTRA-2026-10000", "ASTRA-2027-123456", "ASTRA-2026-00042",
      "ASTRA-2026-001", "ASTRA-26-0001", "ASTRA-20266-0001", "astra-2026-0001", "ASTRA-2026-0001x",
      "XASTRA-2026-0001", "ASTRA-2026-0001\n", "ASTRA-2026-0001 ", "ASTRA-2026-\u0661\u0662\u0663\u0664",
    ];
    const serialDigits = (id) => (grammar.test(id) ? id.slice(id.lastIndexOf("-") + 1).length : 0);
    assert(ids.some((id) => serialDigits(id) === 4) && ids.some((id) => serialDigits(id) === 5),
      `the fixture holds no four-digit and five-digit id the grammar accepts, so it cannot see gap 72's tails: ${ADVISORY_ID_PATTERN}`);

    // The fixture guard. A reader that drifted to one of these would be
    // invisible if no id here told it from the grammar.
    const neighbours = [
      ["exactly four serial digits", /^ASTRA-[0-9]{4}-[0-9]{4}$/],
      ["three or more serial digits", /^ASTRA-[0-9]{4}-[0-9]{3,}$/],
      ["five or more serial digits", /^ASTRA-[0-9]{4}-[0-9]{5,}$/],
      ["a year of any width", /^ASTRA-[0-9]+-[0-9]{4,}$/],
      ["no anchors", new RegExp(ADVISORY_ID_GRAMMAR)],
      ["no end anchor", new RegExp(`^${ADVISORY_ID_GRAMMAR}`)],
      ["no start anchor", new RegExp(`${ADVISORY_ID_GRAMMAR}$`)],
      ["the i flag", new RegExp(ADVISORY_ID_PATTERN, "i")],
      ["the m flag", new RegExp(ADVISORY_ID_PATTERN, "m")],
      ["any decimal digit", /^ASTRA-\p{Nd}{4}-\p{Nd}{4,}$/u],
    ];
    for (const [what, re] of neighbours) {
      assert(ids.some((id) => re.test(id) !== grammar.test(id)),
        `no fixture id tells the grammar ${ADVISORY_ID_PATTERN} from ${what} (${re}); a reader drifted to it would pass`);
    }
    const said = (yes) => (yes ? "takes" : "refuses");
    const disagreements = [];
    const hold = (reader, answer) => {
      for (const id of ids) {
        const got = answer(id);
        if (got !== grammar.test(id)) {
          disagreements.push(`${reader} ${said(got)} ${JSON.stringify(id)}, which the grammar ${said(!got)}`);
        }
      }
    };

    // (a) the advisory validator. Every other field valid, which the guard says.
    const advisory = (id) => ({
      id, published: "2026-09-10", severity: "high", action: "block_install",
      reason: "A fixture advisory, long enough to be a sentence a user can act on.",
      entries: [{ kind: "id", value: "dice-roller" }],
    });
    assertEqual(checkAdvisory(advisory("ASTRA-2026-0001")).join("; "), "", "the fixture advisory is refused for something other than its id");
    hold("tools/lib/revocations.mjs's checkAdvisory", (id) => checkAdvisory(advisory(id)).length === 0);

    // (b) and (c) the moderation log: a revoke's `advisory`, and an unrevoke's
    // `reverses`, which is the only other clause that reads an advisory id.
    const REASON = "A reason long enough to be a reason and short enough for a person to read.";
    const revoke = (id) => ({ date: "2026-09-20", action: "revoke", plugin: "alpha", reason: REASON, advisory: id });
    const unrevoke = (id) => ({ date: "2026-09-21", action: "unrevoke", plugin: "alpha", reason: REASON, advisory: "ASTRA-2026-0001", reverses: id });
    assertEqual([...checkEntry(revoke("ASTRA-2026-0001")), ...checkEntry(unrevoke("ASTRA-2026-0002"))].join("; "), "",
      "the fixture log entries are refused for something other than the advisory id they name");
    hold("bot/lib/moderation.mjs's checkEntry (a revoke's advisory)", (id) => checkEntry(revoke(id)).length === 0);
    hold("bot/lib/moderation.mjs's checkEntry (an unrevoke's reverses)", (id) => checkEntry(unrevoke(id)).length === 0);

    // (d) the site, which turns the id into a directory: built for real, one
    // signed list per id, against an empty catalogue.
    const siteDir = path.join(tmp, "couplings-advisory-site");
    fs.mkdirSync(siteDir, { recursive: true });
    const index = path.join(siteDir, "index.json");
    fs.writeFileSync(index, JSON.stringify({ signatures: [], signed: { schema: "astra.registry.index/1", serial: 1, plugins: [] } }));
    hold("site/build.mjs's advisory page guard", (id) => {
      const list = path.join(siteDir, "revocations.json");
      fs.writeFileSync(list, JSON.stringify({ signatures: [], signed: { schema: "astra.registry.revocations/1", serial: 2, revocations: [
        { kind: "id", value: "alpha", id, severity: "high", action: "warn", reason: advisory(id).reason },
      ] } }));
      try {
        return buildSite({ index, revocations: list, out: path.join(siteDir, "out") }).advisories.includes(id);
      } catch (e) {
        if (/refusing to write a page for advisory/.test(e.message)) return false;
        throw e;
      }
    });

    // (e) the schemas: every `pattern` under schema/ that spells an advisory
    // id, FOUND by walking, each asked through this repository's validator.
    const spelled = [];
    const walk = (node, where) => {
      if (Array.isArray(node)) node.forEach((v, i) => walk(v, `${where}/${i}`));
      else if (node && typeof node === "object") {
        if (typeof node.pattern === "string" && node.pattern.includes("ASTRA-")) spelled.push([where, node]);
        for (const [k, v] of Object.entries(node)) walk(v, `${where}/${k}`);
      }
    };
    const schemaDir = path.join(REPO_ROOT, "schema");
    for (const f of fs.readdirSync(schemaDir).filter((n) => n.endsWith(".json")).sort()) {
      walk(JSON.parse(fs.readFileSync(path.join(schemaDir, f), "utf8")), `schema/${f}#`);
    }
    assert(spelled.length >= 1, "no schema under schema/ spells an advisory id; schema/decision-v1.json's `advisory` did");
    for (const [where, sub] of spelled) hold(where, (id) => validateSchema(sub, id).length === 0);

    // (f) and (g) the next id and the coverage canary, asked on a history: one
    // advisory file per id, committed, asked about, and reset away. And the
    // writer's own clause: whatever the next id is, the grammar takes it —
    // 9999's successor is the five-digit id the old canary could not see.
    const dir = path.join(tmp, "couplings-advisory-grammar");
    fs.mkdirSync(dir, { recursive: true });
    const git = (...a) =>
      execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
    git("init", "-q", "-b", "main");
    git("config", "user.email", "couplings-fixture@example.invalid");
    git("config", "user.name", "couplings fixture");
    git("config", "commit.gpgsign", "false");
    fs.mkdirSync(path.join(dir, SOURCE_DIR), { recursive: true });
    fs.writeFileSync(path.join(dir, SOURCE_DIR, "README.md"), "advisories\n");
    git("add", "-A");
    git("commit", "-qm", "root");
    const root = git("rev-parse", "HEAD");
    // What the next id is when it saw no advisory: the answer that means
    // "refused", whatever its spelling.
    const none = nextAdvisoryId({ root: dir, year: 2026 });
    const asked = new Map();
    for (const id of ids) {
      const rel = `${SOURCE_DIR}/${id}.json`;
      fs.writeFileSync(path.join(dir, rel), "{}\n");
      git("add", "-A");
      git("commit", "-qm", "an advisory");
      const sha = git("rev-parse", "HEAD");
      const next = nextAdvisoryId({ root: dir, year: 2026 });
      const seen = triggersOf(sha, dir).triggers.filter((t) => t.kind === "advisory-written").map((t) => t.advisory);
      asked.set(id, { next, seen });
      git("reset", "-q", "--hard", root);
    }
    const serial = (id) => Number(id.slice(id.lastIndexOf("-") + 1));
    hold("bot/lib/compile-decision.mjs's nextAdvisoryId", (id) => {
      const { next } = asked.get(id);
      if (next === none) return false;
      assertEqual(serial(next), serial(id) + 1,
        `nextAdvisoryId, with ${JSON.stringify(id)} the only advisory ever added, answered ${JSON.stringify(next)}: ` +
          `neither its successor nor what it answers having seen none, ${JSON.stringify(none)}`);
      return true;
    });
    hold("tools/moderation-coverage.mjs's triggersOf", (id) => {
      const { seen } = asked.get(id);
      assert(seen.length <= 1 && (seen.length === 0 || seen[0] === id),
        `triggersOf saw ${JSON.stringify(seen)} in a commit that wrote ${JSON.stringify(id)} and nothing else`);
      return seen.length === 1;
    });
    assertEqual(asked.get("ASTRA-2026-9999").next, "ASTRA-2026-10000", "the successor of advisory 9999 is not advisory 10000");
    for (const [after, next] of [["no advisory", none], ...[...asked].map(([id, a]) => [JSON.stringify(id), a.next])]) {
      if (!grammar.test(next)) disagreements.push(`nextAdvisoryId writes ${JSON.stringify(next)} after ${after}, and the grammar refuses it`);
    }

    // (h) the docs detector, whose relation is a SUPERSET: it flags a URL that
    // reads as an advisory page, and it must read every id as one. The path
    // carries no `advisory` segment, so only the id can make it say yes.
    for (const id of ids.filter((i) => grammar.test(i))) {
      if (!looksLikeAdvisory(`https://example.invalid/withdrawn/${id}`)) {
        disagreements.push(`tools/coverage/docs-advisory-url.mjs's looksLikeAdvisory does not see ${JSON.stringify(id)}, which the grammar takes`);
      }
    }

    assertEqual(disagreements.join("\n  "), "",
      `a reader of the advisory id does not take tools/lib/ids.mjs's ${ADVISORY_ID_PATTERN}`);
  });
}
