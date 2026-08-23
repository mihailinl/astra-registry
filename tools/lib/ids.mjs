// Plugin ids: the string that becomes a directory name on every user's disk.
//
// `<plugins_dir>/<id>` is joined in the Astra daemon and passed to
// `remove_dir_all`. An id is therefore not a label, it is a path component, and
// the registry is the last place that can say no before it reaches a filesystem
// on a stranger's machine. Everything below is deliberately paranoid and
// deliberately independent: `unsafePathComponent()` re-derives what the charset
// regex already implies, because one of the two will one day be relaxed and the
// other has to still be standing.

/** Charset for a listed id. Lowercase, digits, single hyphens, 2..64 chars. */
export const ID_PATTERN = "^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])$";
const ID_RE = new RegExp(ID_PATTERN);

// Windows refuses these names in any directory, with or without an extension.
const WINDOWS_DEVICE_NAMES = new Set([
  "con", "prn", "aux", "nul",
  ...Array.from({ length: 9 }, (_, i) => `com${i + 1}`),
  ...Array.from({ length: 9 }, (_, i) => `lpt${i + 1}`),
]);

/**
 * Is this string safe to use, unescaped, as one path component?
 * @returns {string|null} reason it is not, or null when it is safe
 */
export function unsafePathComponent(id) {
  if (typeof id !== "string") return "not a string";
  if (id.length === 0) return "empty";
  if (id.length > 64) return "longer than 64 characters";
  if (id === "." || id === "..") return `"${id}" is a relative path component`;
  if (id.includes("/") || id.includes("\\")) return "contains a path separator";
  if (id.includes("\0")) return "contains a NUL byte";
  if (id.includes(":")) return "contains ':' (an NTFS alternate-data-stream separator)";
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(id)) return "contains a control character";
  if (/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/.test(id)) {
    return "contains a zero-width or bidirectional-control character";
  }
  if (id !== id.normalize("NFKC")) return "is not NFKC-normalised";
  if (/[. ]$/.test(id)) return "ends in a dot or space (Windows silently strips these)";
  if (WINDOWS_DEVICE_NAMES.has(id.split(".")[0].toLowerCase())) {
    return `"${id}" is a reserved Windows device name`;
  }
  return null;
}

/**
 * Full id check: safe as a path component AND inside the listed charset.
 * @returns {string|null} reason it is rejected, or null when accepted
 */
export function invalidId(id) {
  const unsafe = unsafePathComponent(id);
  if (unsafe) return unsafe;
  if (!ID_RE.test(id)) return `does not match /${ID_PATTERN}/`;
  if (id.includes("--")) return "contains a double hyphen";
  return null;
}

// Squatting: fold the ways two ids look identical to a human but differ to a
// byte comparison. This is a heuristic that catches accidents and lazy
// impersonation, not a determined attacker — POLICY.md says so in those words.
const CONFUSABLES = new Map(Object.entries({
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
}));

/** Fold an id to its "looks like" form, for collision detection only. */
export function foldId(id) {
  let s = id.normalize("NFKC").toLowerCase();
  s = s.replace(/[-_. ]/g, "");
  s = s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/ii/g, "u");
  s = [...s].map((c) => CONFUSABLES.get(c) ?? c).join("");
  return s;
}

/**
 * Latin lookalikes for the letters other alphabets share the shape of.
 *
 * Ids cannot contain any of these — `[a-z0-9-]` sees to that — but a **display
 * name** is unconstrained prose, and the display name is what the store card
 * renders. `Dіce Roller` with a U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-
 * UKRAINIAN I in place of the ASCII `i` is pixel-identical to `Dice Roller` in
 * every common UI font, and NFKC does not touch it: NFKC unifies compatibility
 * variants of the SAME character, not different characters that happen to look
 * alike.
 *
 * Only the unambiguous shapes are here. A Cyrillic or Greek letter with no
 * Latin twin is left alone, so a genuinely Russian or Greek plugin name folds
 * to itself and collides with nothing.
 */
const SCRIPT_LOOKALIKES = new Map(Object.entries({
  // Cyrillic
  "\u0430": "a", "\u0432": "b", "\u0435": "e", "\u043a": "k", "\u043c": "m", "\u043d": "h",
  "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0442": "t", "\u0443": "y", "\u0445": "x",
  "\u0456": "i", "\u0458": "j", "\u04bb": "h", "\u0491": "r", "\u0455": "s", "\u0450": "e",
  // Greek
  "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b7": "n", "\u03b9": "i", "\u03ba": "k",
  "\u03bc": "u", "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c3": "o", "\u03c4": "t",
  "\u03c5": "u", "\u03c7": "x", "\u03bb": "l",
}));

/**
 * Which alphabet a character belongs to, or null for digits/punctuation/emoji.
 *
 * **The CJK scripts are here because leaving them out made this function answer
 * a question about a smaller world than its name claims.** It knew Latin,
 * Cyrillic and Greek, so every Han, kana and Hangul character was
 * indistinguishable from punctuation: `scriptsUsed("Telegram公式")` returned
 * `["Latin"]` — one script, no mixture, nothing to report — and a name written
 * in Han with a single Cyrillic letter dropped into it returned `["Cyrillic"]`,
 * also one script, also silent. That is `dev/couplings.md`'s gap 7 shape: a
 * check that runs, does real work, and returns a true answer about a world
 * three of this system's ten languages are not in.
 *
 * Japanese is deliberately three scripts rather than one bucket. `Script=Han`
 * is shared by Japanese and Chinese; kana and Hangul are not. A name mixing
 * them is what an ordinary Japanese name does, and `honestlyMixed()` in
 * `bot/lib/names.mjs` is where that is said — this function's job is to report
 * what is there, not to decide whether it is innocent.
 */
function scriptOf(ch) {
  if (/\p{Script=Latin}/u.test(ch)) return "Latin";
  if (/\p{Script=Cyrillic}/u.test(ch)) return "Cyrillic";
  if (/\p{Script=Greek}/u.test(ch)) return "Greek";
  if (/\p{Script=Han}/u.test(ch)) return "Han";
  if (/\p{Script=Hiragana}/u.test(ch)) return "Hiragana";
  if (/\p{Script=Katakana}/u.test(ch)) return "Katakana";
  if (/\p{Script=Hangul}/u.test(ch)) return "Hangul";
  return null;
}

/**
 * The scripts a name in one of Astra's CJK languages is ordinarily written in.
 *
 * Exported so `bot/lib/names.mjs` can say what an honest mixture looks like
 * without re-deriving the ranges, and so the two cannot answer differently.
 */
export const CJK_SCRIPTS = ["Han", "Hiragana", "Katakana", "Hangul"];

/**
 * The scripts a string mixes, ignoring digits, spaces and punctuation.
 *
 * A name that draws Latin letters out of two alphabets at once has no honest
 * reading — nobody writes "Dice Roller" and reaches for Cyrillic for one
 * letter. A name written **entirely** in Cyrillic or entirely in Greek is
 * ordinary and returns one script.
 *
 * @returns {string[]} sorted, e.g. `["Cyrillic", "Latin"]`
 */
export function scriptsUsed(s) {
  const seen = new Set();
  for (const ch of String(s).normalize("NFKC")) {
    const script = scriptOf(ch);
    if (script) seen.add(script);
  }
  return [...seen].sort();
}

/**
 * Fold the non-Latin lookalikes of a string to the Latin letters they are
 * drawn as. **For comparison only** — never for anything that is stored or
 * displayed.
 *
 * Deliberately separate from [`foldId`]'s digit table: this folds
 * `\u0456`→`i`, which has no honest use, and does NOT fold `0`→`o`, which
 * would collide "Mp3 Tools" with "Mpo Tools" in a display name.
 */
export function foldLookalikeScripts(s) {
  return [...String(s).normalize("NFKC")]
    .map((c) => SCRIPT_LOOKALIKES.get(c.toLowerCase()) ?? c)
    .join("");
}

/**
 * A **canonical skeleton**: every shape that renders as the same glyph mapped
 * to one representative, so two strings are compared by what they look like
 * rather than by what they are.
 *
 * Why this exists beside [`foldId`]. `foldId`'s table is single-valued, so
 * `1`→`l` and nothing maps `1`→`i`. That caught `Sp0tify Controller` (`0`→`o`)
 * and missed the neighbouring `Spot1fy Controller`, which folds to `spotlfy`
 * and matches no mark. A skeleton has no such asymmetry: `1`, `l` and `i` all
 * become one symbol, so every spelling of the shape meets every other.
 *
 * Used for the **trademark** rule, not for `E_TYPOSQUAT_COLLISION`. Collision
 * is an outright rejection across the whole catalogue and a skeleton this
 * aggressive would reject honest neighbours ("mail-tools" and "mali-tools"
 * share a skeleton); the trademark rule is checked against a short, curated
 * list of marks, where the same aggression costs nothing.
 */
const SKELETON = new Map(Object.entries({
  "1": "i", "l": "i", "!": "i", "|": "i",
  "0": "o",
  "3": "e",
  "4": "a",
  "5": "s",
  "6": "g", "9": "g",
  "7": "t",
  "8": "b",
  "2": "z",
}));

/** [`foldId`], then collapsed to one representative per shape. */
export function confusableSkeleton(s) {
  const folded = foldId(foldLookalikeScripts(s));
  return [...folded].map((c) => SKELETON.get(c) ?? c).join("");
}

/** Damerau-Levenshtein (optimal string alignment) distance. */
export function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[a.length][b.length];
}

/** Metadata strings that reach a user's screen must not carry invisible tricks. */
export function unsafeDisplayText(s) {
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(s)) return "contains a control character";
  if (/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2060-\u2064\ufeff]/.test(s)) {
    return "contains a zero-width or bidirectional-control character";
  }
  // An unpaired surrogate is not a character at all — it is half of one, and
  // it is what a cut through the middle of an emoji leaves behind. The reason
  // it belongs in THIS function rather than in a length check is where it ends
  // up: `tools/lib/canonical.mjs` serialises strings with plain
  // `JSON.stringify`, which escapes a lone surrogate as `\udXXX` rather than
  // refusing it, and `serde_json` rejects that escape. So one such character in
  // one listing makes the whole signed catalogue unparseable in every daemon
  // that fetches it — the blast radius of a display bug with the blast radius
  // of an outage.
  //
  // Matched explicitly rather than with `String.prototype.isWellFormed` so that
  // the two failing shapes are visible: a high surrogate with no low one after
  // it, and a low surrogate with no high one before it.
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s)) {
    return "contains an unpaired surrogate, which is half a character and makes the catalogue unparseable";
  }
  return null;
}
