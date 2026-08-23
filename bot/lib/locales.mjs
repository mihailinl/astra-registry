// The store card, in more than one language.
//
// A plugin carries exactly one language. `PluginMeta.name` and
// `PluginMeta.description` are bare strings and there is nowhere in the type to
// put a second, so a user who sets Astra to Ukrainian gets a Ukrainian shell
// around English text — and until this file existed, nothing in this repository
// had ever asked what language a listing was in.
//
// The mechanism it reads was already there. Every bundle packs `locales/` for
// every language path, unconditionally (`astra-plugin build`), and two keys in
// those files are RESERVED for the store card: `listing.name` and
// `listing.description`. They are read HERE, out of the bundle the bot has
// already downloaded, digested and checked an attestation for — no new
// download, no new attestation surface, no second file format, and no fact the
// author asserts twice.
//
// ── what goes in the index, and what does not ────────────────────────────────
//
// The card's name and one-line summary. Nothing else. Measured on the committed
// `registry/v1/index.json` (10 listings, serial 28, 238,356 bytes) on
// 2026-08-22: icons are 54.4% of that document, READMEs 23.5%, and all the card
// text together — `name` + `description` + the now-deleted `details` — is 0.67%.
// Nine more locales of card text is single-digit percent; nine more locales of
// README is more than three times the whole document, on a file every install
// fetches whole every hour. `policy/limits.json`'s `max_index_bytes_note`
// carries the arithmetic.
//
// ── the rules are implemented twice, on purpose, and pinned once ─────────────
//
// `astra-plugin check` refuses a bundle BEFORE a tag is pushed; this file
// refuses a listing AFTER one is. Two implementations in two languages in two
// repositories is a standing invitation to disagree, and the failure is
// asymmetric and nasty: an author whose release passes every gate they can see
// and dies in a repository they have never opened. So both are held to one
// fixture corpus — `AstraPlugins/testdata/locales/`, coupling C16, read here by
// `tools/validate.mjs` and there by `astra-plugin`'s own unit tests. The ids in
// [`CORPUS_RULE_IDS`] are what make the two comparable, and
// [`CORPUS_NOT_IMPLEMENTED`] is the other half of that: a rule this side does
// NOT enforce is a written-down answer to "does this need it, and why not?",
// never an absence nobody notices.

import crypto from "node:crypto";

import { unsafeDisplayText } from "../../tools/lib/ids.mjs";

/**
 * The languages Astra can be set to, and therefore the only names a plugin's
 * `locales/<code>.json` may take.
 *
 * Mirrored from `AstraPlugins/spec/locales.yaml`, which is itself mirrored from
 * `Astra/astra-core/src/config.rs`'s `SUPPORTED_LANGUAGES`. Three copies, and
 * coupling **C15** is what stops them drifting:
 *
 *   * `tools/selftest.mjs` compares this list against the `propertyNames`
 *     enums in `schema/plugin-v1.json` and `schema/index-v1.json` — by
 *     CONSTRUCTING a drift rather than waiting for one. A bot that emits a
 *     locale the schema rejects red-lines the deploy candidate for every
 *     listing, not for the plugin that shipped it.
 *   * `tools/validate.mjs` compares it against `spec/locales.yaml` when an
 *     AstraPlugins checkout is reachable, and says out loud that it did not
 *     when one is not.
 *
 * Bare ISO-639-1. NO REGION TAGS EXIST ANYWHERE IN THIS SYSTEM: `zh`, never
 * `zh-CN`. Matching is exact string equality in the daemon and in all three
 * SDKs, so a file named anything else is packed, digested, signed, installed
 * and read by nothing — which is why an unknown code is an error here rather
 * than a shrug.
 */
export const LOCALE_CODES = ["en", "ru", "uk", "de", "fr", "es", "pt", "ja", "zh", "ko"];

/**
 * The codes an `i18n` block may be keyed on: the ten above, minus English.
 *
 * `en` is deliberately NOT a key. The flat `name`/`summary`/`description` on a
 * listing ARE the English, they are never removed, and a document that carried
 * the untranslated form twice would eventually carry two different versions of
 * it. (AppStream's rule, and it is the one that survives contact with a
 * translator.)
 */
export const CARD_LOCALE_CODES = LOCALE_CODES.filter((c) => c !== "en");

/** The two keys the store card is read from. Reserved, closed, exactly these. */
export const RESERVED_LISTING_KEYS = ["listing.name", "listing.description"];

/** `locales/<stem>.json` at the TOP level of the bundle. */
const LOCALE_FILE = /^locales\/([^/]+)\.json$/;

/** The lock, at the bundle root — never inside `locales/`, or it is a locale. */
export const LOCK_FILE = "locales.lock.json";

/** CLDR's six cardinal categories, which are a reserved key-suffix namespace. */
const PLURAL_CATEGORIES = new Set(["zero", "one", "two", "few", "many", "other"]);

// ── the English gate ─────────────────────────────────────────────────────────

/**
 * Latin letters and letters, in one string.
 *
 * **Letters, not CASED letters.** Han, kana and hangul have no case at all, so
 * a cased-letter denominator makes an ordinary Japanese description report
 * "contains no letters at all" — a false sentence printed in place of the real
 * reason, for exactly the languages this feature exists to serve. The CLI's
 * `latin_fraction` was corrected the same way and this is the same predicate;
 * `\p{Alphabetic}` is the property Rust's `char::is_alphabetic` tests.
 */
export function latinFraction(text) {
  let letters = 0;
  let latin = 0;
  for (const ch of String(text)) {
    if (!/\p{Alphabetic}/u.test(ch)) continue;
    letters++;
    const cp = ch.codePointAt(0);
    // Basic Latin, Latin-1 Supplement, Latin Extended-A and Latin Extended-B:
    // every language written in a Latin alphabet that Astra can be set to,
    // accents and all.
    if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a) || (cp >= 0xc0 && cp <= 0x24f)) {
      latin++;
    }
  }
  return { latin, letters };
}

/**
 * Below 60% Latin letters, a string is not English.
 *
 * 60% and not 100%: an English sentence quoting a Russian command name must
 * pass. **This is a SCRIPT check, not a language detector** — it catches a card
 * written entirely in another alphabet, which is the accident that actually
 * happened, and it cannot tell English from French. Every message it produces
 * says so in its own last line, because a gate that overstates its reach is one
 * people route around.
 */
export const LATIN_FLOOR = 0.6;

export function isLatinScript(text) {
  const { latin, letters } = latinFraction(text);
  return letters > 0 && latin / letters >= LATIN_FLOOR;
}

/** Why a string failed the script check, in the words the author reads. */
function scriptReason(text) {
  const { latin, letters } = latinFraction(text);
  if (letters === 0) return "it contains no letters at all";
  return `${100 - Math.floor((latin * 100) / letters)}% of its letters are outside the Latin script`;
}

/**
 * Is this repository excused from the English gate?
 *
 * Keyed on `source.repo`, **not on the plugin id**, and that is the whole
 * reason the file has this shape: an id can be re-taken under a different
 * repository and a rename would walk straight past an exemption keyed on it.
 * The repository is what the ownership check proved.
 *
 * There is no dated ratchet anywhere in this feature and this file is why. The
 * cheapest response to a red catalogue build on a fixed morning is to edit the
 * date, and a date edited twice is decoration; an exemption is a reviewed diff
 * with a reason in it.
 */
export function isLanguageExempt(repo, policyDoc) {
  const list = Array.isArray(policyDoc?.exempt) ? policyDoc.exempt : [];
  const want = String(repo ?? "").toLowerCase();
  return want !== "" && list.some((e) => String(e?.repo ?? "").toLowerCase() === want);
}

// ── the lock ─────────────────────────────────────────────────────────────────

/**
 * The first 12 hex of sha256 of the EXACT English UTF-8 bytes, no
 * normalisation — Debian's `Description-md5` idea, as a derived value rather
 * than a state field a human maintains, because a state field lies.
 *
 * Coupling **C19**: `astra-plugin locale sync` writes these digests and this
 * function reads them. Two implementations of one hash over one input, and the
 * input is the thing to get right — the English bytes, not the translation,
 * not either one normalised.
 */
export function englishDigest(english) {
  return crypto.createHash("sha256").update(Buffer.from(String(english), "utf8")).digest("hex").slice(0, 12);
}

// ── reading what the bundle carries ──────────────────────────────────────────

/**
 * A locale file's bytes as a flat string map, or why it cannot be one.
 *
 * **The daemon's parser is the authority.** `load_locales` deserialises
 * `HashMap<String,String>` and drops the WHOLE file on any non-string value —
 * silently, at install time, with no message anywhere. A nested object (the
 * shape every other JSON config invites), a number, a `null`, a top-level
 * array: on a user's machine all four mean "no translations, and nothing said
 * so". This is where that becomes a sentence somebody reads.
 */
function parseFlat(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (e) {
    return { keys: null, error: `not JSON (${e.message})` };
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return {
      keys: null,
      error:
        `the top level is ${Array.isArray(value) ? "an array" : value === null ? "null" : typeof value}, not an object. ` +
        "The daemon deserialises a locale file as a flat map of string to string and drops the whole file on anything else",
    };
  }
  for (const [k, v] of Object.entries(value)) {
    if (typeof v !== "string") {
      return {
        keys: null,
        error:
          `"${k}" is ${v === null ? "null" : Array.isArray(v) ? "an array" : typeof v}, not a string. The daemon drops ` +
          `the WHOLE file on one non-string value — not just that key — so every other translation in it is lost too. ` +
          `Plurals are key suffixes ("${k}.one", "${k}.other"), never nested objects`,
      };
    }
  }
  return { keys: value, error: null };
}

/**
 * Everything under `locales/` in a bundle, plus the root lock.
 *
 * @param {{name: string, bytes: Buffer}[]} files the archive's contents, which
 *   `inspectBundle` has already materialised and hashed
 */
export function readLocales(files, limits = {}) {
  const out = { files: [], oversize: [], lock: null };
  const maxBytes = limits.max_locale_bytes ?? Infinity;
  const maxKeys = limits.max_locale_keys ?? Infinity;

  for (const entry of files) {
    const m = LOCALE_FILE.exec(entry.name);
    if (!m) continue;
    const code = m[1];
    // **Before `JSON.parse`, and before anything else touches the bytes.**
    // `inspectBundle` materialises every listed file as a Buffer bounded only
    // by max_extract_bytes (500 MB); icons are capped at 128 KiB and READMEs at
    // 16 KiB, and locale files were capped by nothing. A 200 MB flat-but-valid
    // en.json would take the ingest runner out mid-derivation and leave the
    // submitter's issue with no verdict at all.
    if (entry.bytes.length > maxBytes) {
      out.oversize.push({ code, bytes: entry.bytes.length, why: `${entry.bytes.length} bytes, over max_locale_bytes (${maxBytes})` });
      continue;
    }
    const { keys, error } = parseFlat(entry.bytes.toString("utf8"));
    if (keys && Object.keys(keys).length > maxKeys) {
      out.oversize.push({
        code,
        bytes: entry.bytes.length,
        why: `${Object.keys(keys).length} keys, over max_locale_keys (${maxKeys})`,
      });
      continue;
    }
    out.files.push({ code, keys: keys ?? {}, error, bytes: entry.bytes.length });
  }
  out.files.sort((a, b) => (a.code < b.code ? -1 : a.code > b.code ? 1 : 0));

  const lock = files.find((f) => f.name === LOCK_FILE);
  if (lock) {
    try {
      const doc = JSON.parse(lock.bytes.toString("utf8"));
      out.lock = doc && typeof doc === "object" ? doc : null;
    } catch {
      // A lock that does not parse is not a listing failure: it costs the
      // staleness demotion below, which is a warning either way. The CLI
      // refuses it at `build` where the author can still fix it.
      out.lock = null;
    }
  }
  return out;
}

/** Files that parsed, `qps` excluded — the set the parity rules run over. */
const real = (set) => set.files.filter((f) => !f.error && f.code !== "qps");

/** `msg.done.few` -> `["msg.done", "few"]`, or `[key, null]`. */
function splitCategory(key) {
  const i = key.lastIndexOf(".");
  if (i <= 0) return [key, null];
  const cat = key.slice(i + 1);
  return PLURAL_CATEGORIES.has(cat) ? [key.slice(0, i), cat] : [key, null];
}

/**
 * Every base that is a plural FAMILY, over the union of every loaded file.
 *
 * **A family is a base carrying at least two distinct CLDR categories
 * somewhere in the union**, and that threshold is the whole reason parity is
 * over families: `astra-plugin locale add ru` writes `msg.done.few` and
 * `msg.done.many`, which `en.json` cannot legally contain, so a raw-key parity
 * rule would fire on a file the CLI itself just wrote. Two is also what stops
 * the collapse from being a trap — a plugin with one genuine key named
 * `something.other` and no siblings is not a plural family.
 *
 * Byte-for-byte the same rule as `plural_families` in
 * `astra-plugin-cli/src/commands/locale.rs`. `pass/plural-families` in the
 * shared corpus (en 2 rows, ru 4, ja 1, all correct at once) is what proves the
 * two agree.
 */
function pluralFamilies(set) {
  const cats = new Map();
  for (const file of real(set)) {
    for (const key of Object.keys(file.keys)) {
      const [base, cat] = splitCategory(key);
      if (!cat) continue;
      if (!cats.has(base)) cats.set(base, new Set());
      cats.get(base).add(cat);
    }
  }
  return new Set([...cats.entries()].filter(([, c]) => c.size >= 2).map(([base]) => base));
}

function familyIds(file, families) {
  return new Set(
    Object.keys(file.keys).map((k) => {
      const [base, cat] = splitCategory(k);
      return cat && families.has(base) ? base : k;
    }),
  );
}

/**
 * A count and at most three examples.
 *
 * Nine locale files each missing four thousand of `en.json`'s five thousand
 * keys would otherwise render megabytes into an issue comment GitHub caps at
 * 65,536 bytes — a bot that does all the work and reports none of it.
 */
function preview(items) {
  const list = [...items];
  const shown = list.slice(0, 3).map((x) => `"${x}"`).join(", ");
  return list.length > 3 ? `${shown} and ${list.length - 3} more` : shown;
}

/**
 * What the bundle says a card looks like in one language, as a canonical
 * string, so the same question can be asked of every platform's bundle.
 *
 * `bot/ingest.mjs` passes `files: first.files` to the derivation with a comment
 * about the icon and the README being one picture across platforms. True for
 * those. **False for locale files**, which reach the installed plugin per
 * platform: a Windows bundle whose `ru.json` says something the Linux one does
 * not is a card that disagrees with the software half the users are running.
 *
 * ── `limits` is REQUIRED, and that is the fix rather than a style choice ─────
 *
 * This used to call `readLocales(files)` with no limits, which defaults
 * `maxBytes`/`maxKeys` to `Infinity`. It runs at ingest **step 7**, where the
 * bundles are compared with each other; the cap runs at **step 11**, inside
 * `deriveLocaleText`. So the real order of operations was: parse every locale
 * file of every bundle unbounded, and THEN refuse the oversized ones. Measured
 * on a flat, valid 43 MiB `en.json`: `readLocales(files, policy.limits)`
 * refuses it in 0 ms; `localeSignature(files)` parsed it in 517 ms, +131 MiB
 * heap, 474 MiB RSS. `inspectBundle` materialises every listed file bounded
 * only by `max_extract_bytes` (500 MB) and a file like that compresses to
 * nothing, so the input is reachable by anyone who can open a listing issue —
 * and `max_artifacts_per_version` is 8, so the first bundle's files were
 * re-parsed once per comparison.
 *
 * A `limits = {}` default would put the same hole back the moment somebody
 * adds a second call site, so an absent one throws. That is the exemption-list
 * discipline rather than a silence: a new caller answers *"which limits?"*
 * instead of inheriting `Infinity` without being asked.
 *
 * **A refused file is still in the signature.** Its bytes were never read —
 * that is the point of the cap — but a bundle shipping a 300 KiB `ru.json` and
 * one shipping no `ru.json` at all are not the same set of languages, and
 * dropping both would make them compare equal.
 *
 * @param {{name: string, bytes: Buffer}[]} files
 * @param {object} limits `policy/limits.json`
 */
export function localeSignature(files, limits) {
  if (limits === undefined || limits === null) {
    throw new Error(
      "localeSignature(files, limits) needs the limits. Without them readLocales parses every locale " +
      "file of every bundle unbounded, which is the one failure mode policy/limits.json's " +
      "max_locale_bytes_note names out loud. Pass policy.limits.",
    );
  }
  const set = readLocales(files, limits);
  const rows = [
    ...real(set).map((f) => [f.code, ...RESERVED_LISTING_KEYS.map((k) => f.keys[k] ?? null)]),
    ...set.oversize.map((o) => [o.code, OVERSIZE_MARKER, o.bytes]),
  ];
  rows.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return JSON.stringify(rows);
}

/**
 * Stands in for a locale file the cap refused, inside a signature. A sentinel
 * rather than the file's contents, because the contents were never read.
 */
const OVERSIZE_MARKER = "\u0000refused-by-max_locale_bytes";

// ── the corpus, and what this side of it implements ──────────────────────────

/**
 * Registry code -> the rule id the shared corpus writes in its `EXPECT` files.
 *
 * The ids are AstraPlugins' — the CLI is where they are printed at an author —
 * and the codes are this repository's, because a code is a published interface
 * a stranger greps. This map is the join, and coupling C16 is only checkable
 * because it exists.
 */
export const CORPUS_RULE_IDS = {
  E_LOCALE_NO_ENGLISH: "E1",
  E_LOCALE_KEY_MISSING: "E2",
  E_LOCALE_KEY_EXTRA: "E3",
  E_LOCALE_UNKNOWN_CODE: "E4",
  E_LOCALE_MALFORMED: "E6",
  E_LISTING_TEXT_MISMATCH: "E8",
  E_LISTING_NOT_ENGLISH: "E11",
  // Two codes, one id, and the id is right: E14 is "card text over the
  // registry's cap", which reaches an English name through `checkMetadata` —
  // the check that has always been there — and a translated one through the
  // locale block. A corpus case that puts a 70-character name in `plugin.toml`
  // AND in `en.json` is asserting that the registry refuses it, not which of
  // its two readers gets there first.
  E_METADATA_TOO_LONG: "E14",
  E_LOCALE_CARD_TOO_LONG: "E14",
};

/**
 * Corpus rule ids this repository does NOT implement, and why not.
 *
 * **An exemption list rather than a silence.** The rule the corpus reader
 * enforces is "every id in a fixture is either implemented here or listed
 * here"; a new id upstream then arrives as a one-line answer to *"does the
 * registry need this, and why not?"* rather than as a fixture whose expectation
 * this side quietly ignores. The exemption list is the load-bearing half — it
 * turns forgetting into a visible blank.
 *
 * Every reason below is the same shape: the rule is about the BUNDLE, and the
 * bundle's gate is `astra-plugin build`, before a tag exists. The registry's
 * business is the CARD.
 */
export const CORPUS_NOT_IMPLEMENTED = {
  E5: "a *.json below locales/'s top level is packed, signed, and read by nothing. It costs bytes in a bundle and changes no card, and by the time the bot sees it the tag is pushed. `astra-plugin build` refuses it where the author can still delete it.",
  E7: "a `$key` in plugin.toml that resolves in no locale file is a run-time defect on the user's machine, not a listing defect: the daemon renders the bare key. Nothing about the card is wrong, and the bot cannot re-render a settings page to find out.",
  E9: "a `listing.` key that is not one of the two reserved is dead weight the bot ignores by construction — it reads exactly two names. The author's expectation is what is wrong, and the CLI is where an expectation gets corrected.",
  E10: "`en.json` without the two reserved keys is not a broken card: the flat name and description still come from plugin.toml, which is where they have always come from. It costs the plugin its locale blocks, which is what W_LOCALE_NO_CARD_TEXT says out loud.",
  E12: "a `[permissions] reason` beginning with `$` is inside `permissions_hash`, which three implementations compute and this registry countersigns. The bytes are already sealed by the time they arrive; refusing them here would refuse a release over text nobody can now change.",
  E13: "a reason over 140 characters is refused by `schema/version-v1.json`'s own maxLength when the derived listing is validated — a rule already enforced twice here, once in the schema and once in the CLI, and not a third time in this module.",
  E15: "the CLDR category table lives in AstraPlugins/spec/i18n.yaml and is generated into three SDKs. Copying it into this repository would make the registry a fourth origin for a rule it never renders and cannot proof-read.",
  E16: "a `$`-leading string in a non-label config position collides with a locale key on the USER's machine, at serve time, in the daemon's resolver. Nothing about the store card is affected and the registry cannot walk a config schema it does not execute.",
  E17: "a `$` label outside `[config] schema` depends on `min_astra_version` and on which daemon the user is running. It is a compatibility rule about released software, not a fact about the listing.",
  E20: "`plugin.name` being a `$key` is caught here by a different rule with a different name: the flat name is checked by `checkNames` and `checkMetadata` exactly as it always has been, and a literal `$action.label` on a card is a name a human reviews.",
  N1: "a locale-named `*.json` outside `locales/` (`src/locales/en.json` is the case) ships working runtime strings and nothing the daemon reads. It is a fact about the source tree, which the CLI can see and a bundle cannot distinguish from any other data file.",
};

/**
 * Errors THIS module can emit that the shared corpus has no rule id for, and
 * why each one is nobody's fixture.
 *
 * **The direction C16 did not run in.** [`CORPUS_RULE_IDS`] and
 * [`CORPUS_NOT_IMPLEMENTED`] between them answer *"every id the corpus writes
 * is either implemented here or exempted here"* — corpus to registry. Nothing
 * asked the reverse: *is every rule this module enforces on locale text a rule
 * some fixture can see?* `E_METADATA_UNSAFE_TEXT` was the proof that the
 * question was worth asking. It has fired on a translated `listing.name` since
 * the locale work landed, no corpus case provokes it (104 fixture files, none
 * carrying an invisible character), and it appeared in neither map — so
 * `corpusIds` would have thrown `is an error this module can emit and
 * CORPUS_RULE_IDS does not name` at whoever wrote the first fixture for it.
 * A rule invisible to both readers, and refusing the fixture that would make
 * it visible.
 *
 * `checkLocaleCorpusCoverage` in `tools/validate.mjs` now enumerates this
 * module's `add("error", …)` calls and holds every one to being in exactly one
 * of the three maps. A new rule therefore arrives as a one-line answer to
 * *"which fixture proves this still fires?"* rather than as an absence.
 *
 * These three are exempt because none of them is a fact about a SOURCE TREE,
 * which is the only thing `astra-plugin check` is ever pointed at.
 */
export const CORPUS_NO_RULE_ID = {
  E_LOCALE_TOO_LARGE:
    "max_locale_bytes and max_locale_keys are registry numbers with no CLI counterpart — `astra-plugin check` " +
    "enforces neither, which is the gap the review filed as its own item. A corpus fixture would have to ship a " +
    "262,145-byte locale file to provoke it, in a directory three repositories vendor. Witnessed instead by " +
    "bot/tests/ingest.test.mjs, against constructed bytes rather than committed ones.",
  E_LOCALE_CARD_TOO_LARGE:
    "max_listing_i18n_bytes bounds the `i18n` member of a LISTING, which is a document this repository writes and " +
    "the CLI never sees. There is nothing in a source tree for a fixture to be about. Witnessed in " +
    "bot/tests/ingest.test.mjs, in both directions — that it fires, and that nine locales at the schema's own " +
    "caps do NOT trip it.",
  E_METADATA_UNSAFE_TEXT:
    "a bidi override or zero-width character in a translated `listing.name` is refused by the same predicate that " +
    "refuses one in `plugin.toml`'s name, and `astra-plugin check` has no display-text scan at all — so a fixture " +
    "here would assert a CLI verdict that does not exist and the two sides would be recorded as agreeing when they " +
    "do not. Witnessed by bot/tests/ingest.test.mjs on both planes, English and translated, so the rule is at least " +
    "visible to one reader instead of none.",
};

// ── the derivation ───────────────────────────────────────────────────────────

/**
 * How many findings ONE rule may contribute to a report before the rest
 * collapse into a single line.
 *
 * Derived from [`LOCALE_CODES`] rather than written down, because the number
 * that must not cost an honest author anything is exactly *how many languages
 * exist*. A bundle translated into all of them and missing one key everywhere
 * produces one finding per file, and a hand-picked 5 silently ate four of
 * them — which a mutation caught and a constant would not have. What this
 * bounds is the count a STRANGER controls: `max_archive_entries` is 10,000 and
 * every one of those entries can be a `locales/<something>.json`.
 */
const MAX_PER_CODE = LOCALE_CODES.length;

/**
 * The per-locale card text, out of the bundle the bot already holds.
 *
 * @param {{files: {name: string, bytes: Buffer}[], facts: object, limits: object,
 *          summarise: (text: string, max: number) => string, repo?: string,
 *          languageExempt?: boolean}} input
 * @returns {{i18n: object|undefined, findings: {level: string, code: string, where?: string, message: string}[]}}
 */
export function deriveLocaleText({ files = [], facts = {}, limits = {}, summarise, languageExempt = false }) {
  const findings = [];
  // ── every rule here is per-FILE, and the file count is a stranger's ───────
  //
  // Almost every rule below runs once per `locales/*.json` in the bundle, and
  // that count is bounded by `max_archive_entries` (10,000) and by nothing
  // else. Measured by driving this function and `renderComment` for real: 100
  // bogus locale files rendered a 41,701-byte issue comment, 200 rendered
  // 82,102 — and GitHub refuses a comment over 65,536 characters with a 422.
  // The report is the only channel this bot has, so a submission that produces
  // enough findings takes away the bot's ability to say anything at all,
  // including to the other submissions in the same run.
  //
  // So `add` bounds itself, per code: the first `MAX_PER_CODE` of a rule are
  // reported in full — which is every honest bundle, since a plugin has at
  // most ten locale files — and the rest collapse into one finding naming a
  // count and a `preview()` of the files. Doing it HERE rather than in each
  // loop is deliberate: a rule added next year is bounded without its author
  // having to remember, and forgetting is what this failure was.
  //
  // The collapsed finding keeps the rule's own code and level, so it still
  // blocks, still reaches "What to do", and still names a file to open.
  const heldBack = new Map();
  const add = (level, code, where, message) => {
    let seen = heldBack.get(code);
    if (!seen) { seen = { level, shown: 0, rest: [] }; heldBack.set(code, seen); }
    if (seen.shown < MAX_PER_CODE) {
      seen.shown++;
      findings.push({ level, code, where, message });
      return;
    }
    seen.rest.push(where);
  };
  /** Append one collapsed finding per over-reported rule. Called at every exit. */
  const done = (i18n) => {
    for (const [code, seen] of heldBack) {
      if (seen.rest.length === 0) continue;
      findings.push({
        level: seen.level,
        code,
        where: "locales/",
        message:
          `…and ${seen.rest.length} more file(s) with the same problem, not listed one by one: ` +
          `${preview(seen.rest)}. Only the first ${MAX_PER_CODE} are shown in full — an issue ` +
          "comment GitHub caps at 65,536 characters is the only way this bot can tell you " +
          "anything, and a report that does not post is a submission with no verdict at all. " +
          "The whole finding list is in the run's `ingest-report-*` artifact.",
      });
    }
    return { i18n, findings };
  };

  // ── the English gate. It does not need `locales/` and does not wait for it.
  const description = String(facts.description ?? "").trim();
  if (description && !isLatinScript(description)) {
    if (languageExempt) {
      add("note", "N_LISTING_LANGUAGE_EXEMPT", "metadata",
        `plugin.description is not in the Latin script, and this repository is on ` +
        `policy/listing-language-exemptions.json. Listed anyway, by a reviewed exception.`);
    } else {
      add("error", "E_LISTING_NOT_ENGLISH", "metadata",
        `plugin.description is not in English: ${scriptReason(description)}.\n` +
        `  ${JSON.stringify(description.slice(0, 120))}\n` +
        "  The store card, the store search index, every client that predates localization, and " +
        "every user whose language you have not translated all show this string. English is the " +
        "base for all of them.\n" +
        "  Fix: write plugin.description in English, and put your own language in " +
        'locales/ru.json under the key "listing.description".\n' +
        "  This is a SCRIPT check, not a language detector. It catches a card written entirely in " +
        "another alphabet. It cannot tell English from French.");
    }
  }
  const name = String(facts.name ?? "").trim();
  if (name && !isLatinScript(name)) {
    // Deliberately a warning, and deliberately not silent. A product name is
    // legitimately anything — refusing one would refuse a plugin doing nothing
    // wrong — but a Cyrillic name over an English summary is worth a human's
    // eye, and the ingest pull request is where a human is already reading.
    add("warn", "W_LISTING_NAME_NOT_LATIN", "metadata",
      `plugin.name ${JSON.stringify(name)} is mostly outside the Latin script. That is allowed — a ` +
      "product name is not prose — but the summary beside it is held to English, so check that the " +
      "two read as one listing.");
  }

  const set = readLocales(files, limits);
  for (const big of set.oversize) {
    add("error", "E_LOCALE_TOO_LARGE", `locales/${big.code}.json`,
      `${big.why}. The whole file is refused unread: a locale file is loaded into memory by the ` +
      "daemon, by the CLI and by this bot, and the only place a runaway one can be stopped " +
      "cheaply is before it is parsed.");
  }
  for (const file of set.files) {
    if (file.error) {
      add("error", "E_LOCALE_MALFORMED", `locales/${file.code}.json`, file.error);
    }
  }

  const parsed = real(set);
  if (parsed.length === 0 && set.files.length === 0) {
    // No `locales/` at all: the overwhelming majority of bundles, for ever.
    // Nothing declared, nothing to check, and no block.
    return done(undefined);
  }

  // Codes outside the vocabulary. Reported per file, and the file is NOT then
  // used for anything: a card in a language Astra cannot select is not a card.
  for (const file of set.files) {
    if (file.error) continue;
    if (LOCALE_CODES.includes(file.code)) continue;
    if (file.code === "qps") {
      // The CLI's pseudo-locale for finding un-externalised strings. `check`
      // permits it and `build` refuses it, so one reaching a published bundle
      // means the bundle was packed by something other than `astra-plugin
      // build` — worth saying, in the same words, because `Settings::validate`
      // refuses `qps` and it can never be selected.
      add("error", "E_LOCALE_UNKNOWN_CODE", "locales/qps.json",
        "qps is the CLI's pseudo-locale, not a language: `Settings::validate` refuses it, so it " +
        "can never be selected. `astra-plugin build` refuses to pack one — a bundle that carries " +
        "it was not packed by the CLI. Delete it and re-release.");
      continue;
    }
    add("error", "E_LOCALE_UNKNOWN_CODE", `locales/${file.code}.json`,
      `${file.code} is not a language Astra can be set to. Astra's languages are: ` +
      `${LOCALE_CODES.join(" ")} (AstraPlugins/spec/locales.yaml). Language matching is exact ` +
      "string equality and there are no region tags anywhere in this system — Chinese is `zh`, " +
      "never `zh-CN`. This file is packed into the bundle, digested, signed, installed, and read " +
      "by nothing.");
  }

  const en = parsed.find((f) => f.code === "en");
  if (!en) {
    if (parsed.length > 0) {
      add("error", "E_LOCALE_NO_ENGLISH", "locales/",
        `locales/ holds ${parsed.length} file(s) and locales/en.json is not one of them: ` +
        `${preview(parsed.map((f) => `${f.code}.json`))}. English is the base every other ` +
        "language falls back to — the released daemon selects one whole locale map and then " +
        "resolves, so without en.json there is nothing to fall back to at all and the key itself " +
        "reaches the screen.");
    }
    // Every rule below needs a loaded en.json. They stand down rather than each
    // restating the same fact in its own words and sending the author to fix
    // the wrong thing.
    return done(undefined);
  }

  // ── parity, over families rather than raw keys ────────────────────────────
  const families = pluralFamilies(set);
  const enIds = familyIds(en, families);
  for (const file of parsed) {
    if (file.code === "en") continue;
    const ids = familyIds(file, families);
    const missing = [...enIds].filter((k) => !ids.has(k));
    if (missing.length) {
      add("error", "E_LOCALE_KEY_MISSING", `locales/${file.code}.json`,
        `${missing.length} key(s) that locales/en.json declares are missing: ${preview(missing)}. ` +
        "Astra's released daemon falls back per FILE, not per key — it picks one whole locale map " +
        "and then resolves — so a key missing here is not filled in from English; the user reads " +
        "the key. Fix: `astra-plugin locale add " + file.code + "` seeds from en.json and leaves " +
        "what is already translated alone.");
    }
    const extra = [...ids].filter((k) => !enIds.has(k));
    if (extra.length) {
      add("error", "E_LOCALE_KEY_EXTRA", `locales/${file.code}.json`,
        `${extra.length} key(s) are declared that locales/en.json does not: ${preview(extra)}. ` +
        "en.json is the base, so a key that is not in it can never be reached from any other " +
        "language and is dead weight in every bundle.");
    }
  }

  // ── C18: the card's English text, in two files, held to being one fact ────
  for (const [key, value, field] of [
    ["listing.name", facts.name, "name"],
    ["listing.description", facts.description, "description"],
  ]) {
    const theirs = en.keys[key];
    if (theirs === undefined) continue;
    if (theirs !== value) {
      add("error", "E_LISTING_TEXT_MISMATCH", "locales/en.json",
        `"${key}" does not match plugin.toml's ${field}.\n` +
        `    plugin.toml:  ${JSON.stringify(value ?? null)}\n` +
        `    en.json:      ${JSON.stringify(theirs)}\n` +
        "  These are the same fact in two files because the manifest crate cannot hold a locale " +
        "table. The card is drawn from plugin.toml and every other language falls back to " +
        "en.json, so a disagreement here is a listing that says two things. Fix: " +
        "`astra-plugin locale sync` rewrites en.json from plugin.toml.");
    }
  }
  if (!RESERVED_LISTING_KEYS.every((k) => en.keys[k] !== undefined)) {
    add("warn", "W_LOCALE_NO_CARD_TEXT", "locales/en.json",
      `locales/en.json declares no ${RESERVED_LISTING_KEYS.filter((k) => en.keys[k] === undefined).join(" or ")}. ` +
      "The card stays English-only: those two keys are the ONLY thing the registry reads out of " +
      "locales/, so a plugin that translates its interface and not its two reserved keys gets a " +
      "Russian settings page under an English card. Fix: `astra-plugin locale sync`.");
  }

  // ── the blocks ───────────────────────────────────────────────────────────
  const lockFor = (code) => set.lock?.locales?.[code] ?? null;
  const i18n = {};
  let stale = 0;
  const staleCodes = new Set();

  for (const code of CARD_LOCALE_CODES) {
    const file = parsed.find((f) => f.code === code);
    if (!file) continue;
    const block = {};
    for (const [key, field, cap] of [
      ["listing.name", "name", limits.max_name_length],
      ["listing.description", "summary", limits.max_description_length],
    ]) {
      const english = en.keys[key];
      let value = file.keys[key];
      if (value === undefined || english === undefined) continue;

      // **Staleness demotes; it does not refuse.** The lock records the English
      // each translation was made against. When today's English no longer
      // matches, the translation describes a plugin that has since changed —
      // and a reader gets a confidently wrong sentence with nothing to tell
      // them. Falling back to English costs them a language; refusing the whole
      // release over prose would cost every user the version. Debian makes the
      // same trade.
      const recorded = lockFor(code)?.[key];
      if (value !== english && recorded !== undefined && recorded !== englishDigest(english)) {
        stale++;
        staleCodes.add(code);
        value = english;
      }

      const trick = unsafeDisplayText(value);
      if (trick) {
        add("error", "E_METADATA_UNSAFE_TEXT", `locales/${code}.json`, `"${key}" ${trick}`);
        continue;
      }
      if (cap !== undefined && [...value].length > cap) {
        add("error", "E_LOCALE_CARD_TOO_LONG", `locales/${code}.json`,
          `"${key}" is ${[...value].length} characters, over the cap of ${cap}. The block is ` +
          "refused, so this language's card falls back to English.");
        continue;
      }
      // The SAME cut the English summary is made with, passed in rather than
      // written again: two implementations of "trim to 200 without splitting a
      // character" is precisely the bug that made one bad summary able to
      // reject the whole catalogue in serde_json.
      block[field] = field === "summary" ? summarise(value, limits.max_summary_length) : value;
    }

    // **Never drop half a block.** A locale whose `listing.name` is legitimately
    // identical to English — which is what a brand name is — must not produce a
    // block with a summary and no name and fail the schema's `required`. Both
    // halves or neither, and the missing half is filled from English rather
    // than omitted.
    if (Object.keys(block).length === 0) continue;
    if (block.name === undefined) block.name = String(facts.name ?? "");
    if (block.summary === undefined) block.summary = summarise(String(facts.description ?? ""), limits.max_summary_length);

    // A block byte-identical to the English card renders identically to no
    // block at all, so it is bytes in a document every install fetches whole
    // every hour in exchange for nothing. This is reachable rather than
    // theoretical: it is what a demoted stale translation and an untranslated
    // seeded file both come to.
    const englishCard = {
      name: String(facts.name ?? ""),
      summary: summarise(String(facts.description ?? ""), limits.max_summary_length),
    };
    if (block.name === englishCard.name && block.summary === englishCard.summary) continue;

    i18n[code] = block;
  }

  if (stale > 0) {
    add("warn", "W_LOCALE_STALE", "locales.lock.json",
      `${stale} translated string(s) in ${preview([...staleCodes])} describe English that has ` +
      "since been rewritten, so those fall back to English on the card. The listing is not " +
      "refused over prose; a confidently wrong sentence in a language nobody here can read is " +
      "worse than a correct one in the wrong language. Fix before the next release: " +
      "`astra-plugin locale sync`.");
  }

  const codes = Object.keys(i18n);
  if (codes.length === 0) return done(undefined);

  // A per-listing budget, checked before the block is emitted. A shared ceiling
  // would let one verbose author stop every other author's publish behind a red
  // catalogue build whose error named no plugin.
  const size = Buffer.byteLength(JSON.stringify(i18n), "utf8");
  const budget = limits.max_listing_i18n_bytes ?? Infinity;
  if (size > budget) {
    add("error", "E_LOCALE_CARD_TOO_LARGE", "locales/",
      `${codes.length} locale block(s) come to ${size} bytes, over max_listing_i18n_bytes ` +
      `(${budget}). The index is one signed document every client fetches whole every hour; this ` +
      "budget is what keeps one listing's translations from being everybody's download.");
    return done(undefined);
  }

  return done(i18n);
}

// ── C15, the in-repository half ──────────────────────────────────────────────

/**
 * The `propertyNames` enum an `i18n` member is keyed by, out of a schema
 * document.
 *
 * **Throws when it cannot find one**, and that is the point. This is a check
 * whose reach could shrink without anybody being told: rename the member, move
 * it under a different `$defs`, and a reader that shrugged would compare an
 * empty list against nine codes and report a clean bill of health for a schema
 * it never opened.
 */
function localeEnum(doc, where) {
  const node = doc?.properties?.i18n ?? doc?.$defs?.plugin?.properties?.i18n;
  if (!node) {
    throw new Error(
      `${where} has no i18n member at properties.i18n or $defs.plugin.properties.i18n. ` +
      "Either it was removed — in which case the bot is about to emit a member the schema " +
      "rejects, for every listing — or it moved and this reader is now looking at nothing.",
    );
  }
  const values = node.propertyNames?.enum;
  if (!Array.isArray(values)) {
    throw new Error(
      `${where}'s i18n member has no propertyNames.enum. Without it the schema accepts any key ` +
      "at all, including a `zh-CN` nothing can select, and the vocabulary is enforced nowhere.",
    );
  }
  return values;
}

/**
 * Does a schema's locale vocabulary agree with this module's?
 *
 * @returns {string[]} one sentence per disagreement, empty when they agree
 */
export function localeEnumProblems(doc, where, codes = CARD_LOCALE_CODES) {
  const declared = localeEnum(doc, where);
  const problems = [];
  const missing = codes.filter((c) => !declared.includes(c));
  const extra = declared.filter((c) => !codes.includes(c));
  if (missing.length) {
    problems.push(
      `${where} rejects ${missing.join(", ")}, which bot/lib/locales.mjs emits. Every listing ` +
      "whose bundle carries one of those fails schema validation, so one plugin's translation " +
      "red-lines the deploy candidate for the whole catalogue.",
    );
  }
  if (extra.length) {
    problems.push(
      `${where} accepts ${extra.join(", ")}, which bot/lib/locales.mjs never emits. A hand-edited ` +
      "listing could then carry a locale block the bot would refuse to derive.",
    );
  }
  if (declared.includes("en")) {
    problems.push(
      `${where} accepts "en" as an i18n key. The flat name and summary ARE the English; a ` +
      "document that can carry it twice will eventually carry two different versions of it.",
    );
  }
  return problems;
}
