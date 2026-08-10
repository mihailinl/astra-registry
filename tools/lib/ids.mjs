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
  return null;
}
