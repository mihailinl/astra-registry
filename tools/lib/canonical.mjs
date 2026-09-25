// Canonical JSON: one serialiser, two shapes.
//
//   stableStringify()  pretty, sorted keys, trailing newline — what lands in
//                      registry/v1/index.json, because the file is read by
//                      humans in review diffs.
//   jcs()              RFC 8785, compact, sorted keys — what Phase 3 signs.
//
// Both sort object keys with the default `Array.prototype.sort()`, which
// compares UTF-16 code units. That is exactly RFC 8785 §3.2.3's ordering, so
// the two shapes carry the same key order and a reviewer reading the pretty
// file is reading the bytes that get signed, modulo whitespace.
//
// Numbers: this registry only ever emits integers (serial, size, protocol).
// RFC 8785 §3.2.2's number canonicalisation (ECMAScript Number::toString) is a
// real subtlety for fractions, so rather than get it subtly wrong we refuse
// anything that is not a safe integer. If a future field needs a fraction,
// implement §3.2.2 deliberately — do not let it in by accident.
//
// Strings: I-JSON only (RFC 7493 §2.1), and that is contract §0.7 since 2.16.0.
// RFC 8785 is defined over I-JSON, whose strings MUST NOT carry a surrogate
// that is not half of a pair, or a Unicode noncharacter. `JSON.stringify`
// refuses neither: since ES2019 it writes a lone surrogate as a `\udXXX`
// escape, which is well-formed JSON text and a string no Rust reader can hold.
// `serde_json` refuses that escape ("unexpected end of hex escape"), the
// plugins service's reader does, and Astra's daemon parses the WHOLE catalogue
// envelope, and the withdrawal list, before any entry logic (Astra@5f8f0920
// `trust.rs:1482` `parse_json_strict`, serde_json 1.0.149, in shipped 0.2.5 and
// in R5 alike, as the client lane measured it). So one such string in any
// record the catalogue is generated from, serialised here, would freeze every
// client at its last verified copy of the catalogue — and on the withdrawal
// list, block every install seven days later. On main d8effae a hand-written
// version record carrying one validated clean and this function wrote it into
// the catalogue and into the bytes the signer signs. This serialiser is under
// every document the registry signs and every record it writes with it, so it
// refuses such a string, as a value or as a key, instead of escaping it.

// `\p{Cs}` under the `u` flag matches a surrogate code unit that is NOT one
// half of a pair (a paired one is read as the astral code point it encodes), so
// an emoji passes and half of one does not. `\p{Noncharacter_Code_Point}` is
// U+FDD0..U+FDEF and the last two code points of every plane.
const NOT_IJSON = /\p{Cs}|\p{Noncharacter_Code_Point}/u;
const LONE_SURROGATE = /^\p{Cs}$/u;

/**
 * Why `s` is not an I-JSON string, or `null`. The sentence is ASCII: it names
 * the code point and never quotes it, because a report that carried the lone
 * surrogate it is refusing would be the next document nobody can parse.
 *
 * @param {string} s
 * @returns {string|null}
 */
export function ijsonStringProblem(s) {
  if (typeof s !== "string") return null;
  const m = NOT_IJSON.exec(s);
  if (!m) return null;
  const hex = m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
  return LONE_SURROGATE.test(m[0])
    ? `an unpaired surrogate U+${hex} at code unit ${m.index}`
    : `the noncharacter U+${hex} at code unit ${m.index}`;
}

/**
 * A key as a path segment a log, a report or an issue comment can carry: as it
 * is when it is printable ASCII, and otherwise quoted with every other code
 * unit written as a `\uXXXX` escape.
 */
export function pathSegment(key) {
  const k = String(key);
  if (/^[\x20-\x7e]*$/.test(k)) return `.${k}`;
  const quoted = [...Array(k.length).keys()]
    .map((i) => {
      const u = k.charCodeAt(i);
      if (u === 0x22 || u === 0x5c) return `\\${k[i]}`;
      return u >= 0x20 && u <= 0x7e ? k[i] : `\\u${u.toString(16).padStart(4, "0")}`;
    })
    .join("");
  return `["${quoted}"]`;
}

/**
 * Every string in `value` — each member NAME as well as each string value —
 * that is not an I-JSON string, with where it is.
 *
 * @param {unknown} value
 * @param {string} [at] the path of `value` itself
 * @returns {{path: string, problem: string}[]}
 */
export function ijsonProblems(value, at = "$") {
  const out = [];
  const walk = (v, p) => {
    if (typeof v === "string") {
      const problem = ijsonStringProblem(v);
      if (problem) out.push({ path: p, problem });
    } else if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, `${p}[${i}]`));
    } else if (v !== null && typeof v === "object") {
      for (const k of Object.keys(v)) {
        const problem = ijsonStringProblem(k);
        if (problem) out.push({ path: `${p}${pathSegment(k)} (the member name)`, problem });
        walk(v[k], `${p}${pathSegment(k)}`);
      }
    }
  };
  walk(value, at);
  return out;
}

function refuseNonIJson(s, path) {
  const problem = ijsonStringProblem(s);
  if (problem) {
    throw new Error(
      `${path}: carries ${problem}. Canonical JSON here is I-JSON (RFC 7493 §2.1; contract §0.7 since 2.16.0): ` +
      "serde_json refuses such a string, and every client parses the whole document before any entry, so one " +
      "of them makes the document unreadable to all of them",
    );
  }
}

/** @param {unknown} value */
function assertSerialisable(value, path) {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`${path}: ${value} is not representable in JSON`);
    }
    if (!Number.isSafeInteger(value)) {
      throw new Error(
        `${path}: ${value} is not a safe integer; canonical JSON here is integers only (see tools/lib/canonical.mjs)`,
      );
    }
  }
}

function sortedEntries(obj) {
  return Object.keys(obj)
    .sort()
    .map((k) => [k, obj[k]]);
}

function write(value, path, indent, level, out) {
  assertSerialisable(value, path);
  if (value === null) return out.push("null");
  if (typeof value === "boolean" || typeof value === "number") {
    return out.push(JSON.stringify(value));
  }
  if (typeof value === "string") {
    refuseNonIJson(value, path);
    return out.push(JSON.stringify(value));
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return out.push("[]");
    const pad = indent ? "\n" + " ".repeat(indent * (level + 1)) : "";
    const close = indent ? "\n" + " ".repeat(indent * level) : "";
    out.push("[");
    value.forEach((item, i) => {
      if (i) out.push(",");
      out.push(pad);
      write(item, `${path}[${i}]`, indent, level + 1, out);
    });
    out.push(close, "]");
    return;
  }
  if (typeof value === "object") {
    const entries = sortedEntries(value).filter(([, v]) => v !== undefined);
    if (entries.length === 0) return out.push("{}");
    const pad = indent ? "\n" + " ".repeat(indent * (level + 1)) : "";
    const close = indent ? "\n" + " ".repeat(indent * level) : "";
    out.push("{");
    entries.forEach(([k, v], i) => {
      const at = path ? `${path}${pathSegment(k)}` : pathSegment(k).replace(/^\./, "");
      refuseNonIJson(k, `${at} (the member name)`);
      if (i) out.push(",");
      out.push(pad, JSON.stringify(k), indent ? ": " : ":");
      write(v, at, indent, level + 1, out);
    });
    out.push(close, "}");
    return;
  }
  throw new Error(`${path}: ${typeof value} is not serialisable`);
}

/** Pretty canonical JSON with a trailing newline. */
export function stableStringify(value, indent = 2) {
  const out = [];
  write(value, "$", indent, 0, out);
  out.push("\n");
  return out.join("");
}

/** RFC 8785 JCS. Phase 3 signs SHA256(domain ‖ jcs(signed)). */
export function jcs(value) {
  const out = [];
  write(value, "$", 0, 0, out);
  return out.join("");
}
