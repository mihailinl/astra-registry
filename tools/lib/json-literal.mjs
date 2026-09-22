// A JSON object's top-level members, as the TEXT that wrote them.
//
// Contract 0.31.0, B.4: a migration-notice marker's `round` is "written as an
// integer with no fraction part and no exponent (`1`, never `1.0` or `1e0`)".
// JSON Schema 2020-12's `integer` is a property of the VALUE, and `1.0`, `1e0`
// and `1E0` are the value 1 — so `schema/migration-notice-v1.json` admits them,
// and after `JSON.parse` no JavaScript validator can tell them from `1`. The
// plugins service's reader refuses them (it asks the literal for a u64). A rule
// about how a number is WRITTEN can only be read off the text, and this module
// is that reading.
//
// It is a scanner and not a regular expression over the file, for the three
// ways a regex gets it wrong: a key spelt with escapes (`"round"` IS
// `round` to every JSON parser), a `"round": 1` inside a string or a nested
// object (not the member), and two `round` members (JSON.parse keeps the LAST,
// so a check that read the first would judge a value no reader uses). Keys are
// decoded with JSON.parse and compared decoded; only depth-one members are
// returned; every occurrence is returned, duplicates included, so the caller
// decides what a duplicate is.
//
// WHAT IT CANNOT SEE, stated so nobody leans on it for more: it reads the
// literal and nothing about what the literal means — ranges and types are the
// schema's; it says nothing about members below depth one; and it trusts
// JSON.parse, which it runs first, to have refused malformed text, so it is not
// a validator of JSON and must not be used as one.

/** Whitespace, exactly as RFC 8259 §2 defines it. */
const WS = new Set([" ", "\t", "\n", "\r"]);

/**
 * Every top-level member of the JSON object `text`, in source order, each as
 * `{name, raw}`: `name` decoded, `raw` the value's exact source text.
 *
 * Throws when `text` is not JSON, or is JSON that is not an object.
 *
 * @returns {{name: string, raw: string}[]}
 */
export function topLevelMembers(text) {
  JSON.parse(text); // the gate: everything below assumes well-formed JSON
  let i = 0;
  const ws = () => {
    while (i < text.length && WS.has(text[i])) i += 1;
  };
  const string = () => {
    const start = i;
    i += 1; // opening quote
    while (text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    i += 1; // closing quote
    return text.slice(start, i);
  };
  const value = () => {
    const start = i;
    const c = text[i];
    if (c === '"') {
      string();
    } else if (c === "{" || c === "[") {
      let depth = 0;
      do {
        const ch = text[i];
        if (ch === '"') {
          string();
          continue;
        }
        if (ch === "{" || ch === "[") depth += 1;
        else if (ch === "}" || ch === "]") depth -= 1;
        i += 1;
      } while (depth > 0);
    } else {
      // a number, `true`, `false` or `null`: runs to the next structural
      // character or whitespace
      while (i < text.length && !WS.has(text[i]) && !",}]".includes(text[i])) i += 1;
    }
    return text.slice(start, i);
  };

  ws();
  if (text[i] !== "{") throw new Error("not a JSON object");
  i += 1;
  const out = [];
  ws();
  if (text[i] === "}") return out;
  for (;;) {
    ws();
    const name = JSON.parse(string());
    ws();
    i += 1; // ':'
    ws();
    out.push({ name, raw: value() });
    ws();
    if (text[i] === ",") {
      i += 1;
      continue;
    }
    break; // '}' — JSON.parse above has already refused anything else
  }
  return out;
}

/**
 * A positive integer written as one: digits, no sign, no leading zero, no
 * fraction part, no exponent. `1`, `2`, `4294967295`; never `1.0`, `1e0`,
 * `1E0`, `+1`, `01` or `-1`.
 */
export const POSITIVE_INTEGER_LITERAL = /^[1-9][0-9]*$/;
