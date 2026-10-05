// How much repetition a `pattern` in this repository's own schemas asks a regex
// engine to do, and the refusal of one that asks too much.
//
// **What this closes** (ops `dev/couplings.md` entry 215, asked for by the
// plugins service, minice-e4, 2026-10-03). Every reader of a record compiles
// the patterns of the schema that types it: `tools/lib/jsonschema.mjs` here,
// and the plugins service, which reads each schema at the commit it judges
// (B.4's `schema_path`). A counted repetition costs in proportion to its
// count: a backtracking engine retries it at every position of a near miss,
// and an automaton engine builds that many copies of the atom. Measured here
// on 2026-10-03, `new RegExp("a{100000}", "u")` against a 200,000-character
// near miss took 16.6 s, and the service measured about 60 s for the same
// `not: {pattern: "a{100000}"}` in its own engine — per validation, on a
// field a schema already allows. At `a{1000}` the same field took 0.18 s.
// Nothing an author sends can add a pattern; a commit to `schema/` can, and a
// reviewer reading `{100000}` in a diff sees a number, not a minute. So the
// tree rule (tools/lib/tree-modes.mjs) reads every `schema/**/*.json` at the
// commit it judges and refuses a pattern past `MAX_PATTERN_REPETITION`.
//
// **Why 1,000.** Of the 98 patterns in the 15 schemas here on 2026-10-03
// (8837648), the largest count is 128 (`{1,128}`, a release tag in
// schema/decision-v1.json) and no nesting multiplies past it, so 1,000
// refuses nothing that exists and leaves room for any bounded field this
// repository has a reason to write, while the 200,000-character near miss
// above costs 0.18 s at 1,000.
//
// **What is counted.** Not only a single `{n}`, `{n,}` or `{n,m}` past 1,000:
// counts multiply through the groups they nest in, so `(?:[0-9]{10}){101}` is
// 1,010 copies of `[0-9]` with no count above 101, and costs what `[0-9]{1010}`
// does. An open count `{n,}` is `n` copies and an open tail; `*`, `+` and `?`
// are one copy each, run again, and build nothing. What this does NOT bound is
// backtracking that needs no count at all, `(a+)+$` and its kind, which is a
// different shape of slow and is left to review; it is said here so a green
// run is not read as more.
//
// **Read as `tools/lib/jsonschema.mjs` compiles it**, `new RegExp(p, "u")`.
// Under `u` a brace that is not a count is a syntax error rather than a
// literal, so the scanner below can treat every unescaped `{` outside a class
// as a count; and a pattern that does not compile under `u` is refused too,
// because nothing here can vouch for what it would cost, and every validation
// against it throws.

/** The most copies of one atom a pattern in `schema/**` may ask for, a nested product included. */
export const MAX_PATTERN_REPETITION = 1000;

/**
 * The repetition `pattern` asks for: `count`, its largest single count, and
 * `copies`, the most copies of any one atom once every count on the way out to
 * the top is multiplied in.
 *
 * A scanner over ECMAScript's `u` grammar, not a parser: it skips escapes
 * (`\{`, `\u{…}`, `\p{…}`, `\k<…>`), classes (`[{}]`) and group prefixes
 * (`(?:`, `(?<name>`), and reads the rest as atoms, groups and quantifiers.
 * Malformed input gives some answer rather than throwing; the caller compiles
 * the pattern as well, and refuses one that does not compile.
 *
 * @param {string} pattern
 * @returns {{copies: number, count: number}}
 */
export function patternRepetition(pattern) {
  const s = String(pattern);
  // One frame per open group: the most copies of any atom inside it so far.
  const frames = [{ max: 1 }];
  // The atom just read, as copies, until a quantifier or the next atom folds
  // it into its group.
  let pending = null;
  let count = 0;
  const fold = () => {
    if (pending === null) return;
    const top = frames[frames.length - 1];
    top.max = Math.max(top.max, pending);
    pending = null;
  };
  const skipTo = (close, from) => {
    const end = s.indexOf(close, from);
    return end < 0 ? s.length : end + 1;
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "\\") {
      fold();
      const n = s[i + 1];
      if ((n === "u" || n === "p" || n === "P") && s[i + 2] === "{") i = skipTo("}", i + 3);
      else if (n === "k" && s[i + 2] === "<") i = skipTo(">", i + 3);
      else i += 2;
      pending = 1;
    } else if (c === "[") {
      fold();
      i += 1;
      while (i < s.length && s[i] !== "]") i += s[i] === "\\" ? 2 : 1;
      i += 1;
      pending = 1;
    } else if (c === "(") {
      fold();
      frames.push({ max: 1 });
      i += 1;
      if (s[i] === "?") {
        // (?: (?= (?! take two; (?<= (?<! take three; (?<name> runs to its `>`.
        if (s[i + 1] === "<" && s[i + 2] !== "=" && s[i + 2] !== "!") i = skipTo(">", i + 2);
        else i += s[i + 1] === "<" ? 3 : 2;
      }
    } else if (c === ")") {
      fold();
      // The group is now one atom, as many copies as its widest member.
      pending = frames.length > 1 ? frames.pop().max : 1;
      i += 1;
    } else if (c === "|") {
      fold();
      i += 1;
    } else if (c === "*" || c === "+" || c === "?") {
      fold();
      i += 1;
      if (s[i] === "?") i += 1;
    } else {
      const m = c === "{" ? /^\{(\d+)(?:,(\d*))?\}/.exec(s.slice(i)) : null;
      if (m) {
        const lo = Number(m[1]);
        const n = m[2] ? Math.max(lo, Number(m[2])) : lo;
        count = Math.max(count, n);
        if (pending !== null) pending *= n;
        fold();
        i += m[0].length;
        if (s[i] === "?") i += 1;
      } else {
        fold();
        pending = 1;
        i += 1;
      }
    }
  }
  fold();
  while (frames.length > 1) {
    const inner = frames.pop();
    frames[frames.length - 1].max = Math.max(frames[frames.length - 1].max, inner.max);
  }
  return { copies: frames[0].max, count };
}

/** A member name as a JSON Pointer reference token (RFC 6901). */
const token = (k) => String(k).replace(/~/g, "~0").replace(/\//g, "~1");

/**
 * Every pattern in a parsed schema, with its JSON Pointer: each string under a
 * `pattern` member, and each member name of a `patternProperties` object,
 * which is a pattern too. Every object is walked, `const`, `enum` and
 * `examples` included, so a `pattern` written as data is read as one as well;
 * that errs toward refusing, in files whose author can rename it.
 *
 * @returns {{pointer: string, pattern: string}[]}
 */
export function schemaPatterns(doc) {
  const out = [];
  const walk = (v, at) => {
    if (Array.isArray(v)) {
      v.forEach((x, n) => walk(x, `${at}/${n}`));
      return;
    }
    if (!v || typeof v !== "object") return;
    for (const [k, x] of Object.entries(v)) {
      const here = `${at}/${token(k)}`;
      if (k === "pattern" && typeof x === "string") out.push({ pointer: here, pattern: x });
      if (k === "patternProperties" && x && typeof x === "object" && !Array.isArray(x)) {
        for (const name of Object.keys(x)) out.push({ pointer: `${here}/${token(name)}`, pattern: name });
      }
      walk(x, here);
    }
  };
  walk(doc, "");
  return out;
}

/**
 * What the lint refuses in one schema file's text, as `{pointer, message}`,
 * the message beginning with `pattern at <pointer>` or saying the file is not
 * JSON. Pure.
 *
 * @param {string} text
 * @returns {{pointer: string, message: string}[]}
 */
export function schemaPatternProblems(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return [{ pointer: "", message: `is not JSON (${e.message}), so the patterns in it cannot be read` }];
  }
  const problems = [];
  for (const { pointer, pattern } of schemaPatterns(doc)) {
    const { copies, count } = patternRepetition(pattern);
    const asked = Math.max(copies, count);
    if (asked > MAX_PATTERN_REPETITION) {
      problems.push({
        pointer,
        message: `pattern at ${pointer} asks for ${asked} copies of one atom` +
          (copies > count ? `, counts nested inside counts multiplied (the largest alone is ${count})` : "") +
          `, over the ${MAX_PATTERN_REPETITION} a schema here may ask for: every reader compiles this pattern, and a ` +
          "count costs in proportion to itself on every validation (`a{100000}` took 16.6 s here and about 60 s in " +
          "the plugins service against one 200,000-character field)",
      });
      continue;
    }
    try {
      new RegExp(pattern, "u");
    } catch (e) {
      problems.push({
        pointer,
        message: `pattern at ${pointer} does not compile as tools/lib/jsonschema.mjs compiles it, ` +
          `\`new RegExp(pattern, "u")\` (${e.message}), so every validation against it throws and nothing can say ` +
          "what it would cost",
      });
    }
  }
  return problems;
}

/** What to do about a refused pattern; one sentence, so it can be a hint. */
export const SCHEMA_PATTERN_HINT =
  "Bound the field with `maxLength` and keep the pattern's counts small, or split the check; a schema's pattern " +
  "is compiled by every reader of the records it types, the plugins service among them.";
