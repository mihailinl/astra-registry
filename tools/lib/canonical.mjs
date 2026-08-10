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
  if (typeof value === "string") return out.push(JSON.stringify(value));
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
      if (i) out.push(",");
      out.push(pad, JSON.stringify(k), indent ? ": " : ":");
      write(v, path ? `${path}.${k}` : k, indent, level + 1, out);
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
