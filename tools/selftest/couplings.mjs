// The locale facts kept in more than one place, each tested by CONSTRUCTING the
// drift: the bot's locale list against both schema enums, the vocabulary against
// spec/locales.yaml with a parse floor, the caps AstraPlugins mirrors from here
// in both directions, every cap declaring its author side, and the locale corpus
// in both directions including the exemption that outlives its rule.
//
// `withFakeCheckout` below is seventeen lines from `withFakeAstraPlugins` in the
// old file and reads almost the same, but only this module uses it, so it stays
// here while the other one moved.

import fs from "node:fs";
import path from "node:path";

import {
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
import { test, assert, assertEqual, tmp } from "./harness.mjs";

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
}
