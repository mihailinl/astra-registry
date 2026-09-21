#!/usr/bin/env node
// How `vectors.json` is produced. Never edit that file by hand.
//
//     node tests/binding-line/generate.mjs            write vectors.json + SHA256SUMS
//     node tests/binding-line/generate.mjs --check    verify the committed bytes
//
// ── why a generator, for thirty-one small files ────────────────────────────
//
// Four of these cases are over four kilobytes, one carries bytes that are not
// UTF-8 at all, three carry a BOM and one carries a bare CR in the middle of a
// line. None of that survives being typed into a JSON file by a person, and
// none of it survives review once it is base64. The signed-set corpus
// (`tools/testkeys/vectors/`) met the same wall and wrote the answer down: a
// corpus is **generated, never hand-written**, because a hand-written one
// cannot be regenerated after the thing it describes moves, and the first
// person to try pastes the wrong blob into the wrong vector and produces a file
// that is green on both sides and means nothing.
//
// ── the one thing this file must not do ────────────────────────────────────
//
// **It never imports `bot/lib/binding.mjs`.** Every `outcome` below is written
// down by hand from the contract (ID-23, ID-24) and from B-T2.4's numbered
// list; the parser is then measured against them by `bot/tests/binding.test.mjs`.
// A generator that asked the parser what it does would produce a corpus that
// agrees with the parser by construction, pass for ever, and say nothing about
// whether either matches the contract — and the CLI and the plugins service,
// which read these same bytes, would be measured against this repository's bugs
// instead of against the rule.
//
// The only thing this file computes rather than states is `cli_write`, from
// FLOW-50's `[A-Za-z0-9_-]{22,128}`, which is written here as its own literal
// for the same reason.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));

// ── the three grammars, as literals, in the form the contract states them ───
//
// Copied here rather than imported from `bot/lib/binding.mjs` on purpose: this
// file is the corpus's side of the comparison, and a corpus that imports the
// implementation's regex cannot disagree with it. `bot/tests/binding.test.mjs`
// compares all three copies — this one, the module's and `README.md`'s — so a
// change to one of them is red rather than silent.
const ID_23_SOURCE = "^[ \\t]*astra-binding:[ \\t]*([A-Za-z0-9_-]{16,128})[ \\t]*(#.*)?$";
const ID_24_PREFIX_SOURCE = "^[ \\t]*astra-binding[ \\t]*:";
const CLI_WRITE_SOURCE = "^[A-Za-z0-9_-]{22,128}$";

const CLI_WRITE_RE = new RegExp(CLI_WRITE_SOURCE);

const WINDOW_BYTES = 4096;

// ── the token material ──────────────────────────────────────────────────────
//
// Deliberately a cycle of the token charset rather than anything that could be
// mistaken for a real minted token: these files are public, they are mirrored
// into a second public repository, and a string that looks like a credential
// gets treated like one by the next person who greps for it.
const ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
const tok = (n, from = 0) => Array.from({ length: n }, (_, i) => ALPHA[(from + i) % ALPHA.length]).join("");

/** The ordinary 32-character token every "one" case carries unless it says otherwise. */
const VALID = tok(32);
/** A second, different token, for the two-lines case. */
const SECOND = tok(32, 10);

const enc = new TextEncoder();
const bytes = (...parts) => Buffer.concat(parts.map((p) => (typeof p === "string" ? Buffer.from(enc.encode(p)) : Buffer.from(p))));
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const line = (t) => `astra-binding: ${t}\n`;

/** A comment line of exactly `n` bytes, terminator included. */
function pad(n) {
  if (n < 2) throw new Error(`a padding line cannot be ${n} bytes`);
  return `#${"p".repeat(n - 2)}\n`;
}

// ── the vectors ─────────────────────────────────────────────────────────────
//
// Numbered as B-T2.4 numbers them, so the plan, this file, the README and the
// AstraPlugins mirror can all be read side by side. Where the plan's entry
// names several shapes ("15- and 129-character tokens") they are several CASES
// under one vector number, which is why the floor is stated twice: 25 vectors
// and 31 cases.
const CASES = [
  {
    vector: 1, name: "one-exact-line", title: "one exact line",
    why: "The ordinary shape, and the only one an author is ever asked to write.",
    file: bytes(line(VALID)), outcome: "one", token: VALID,
  },
  {
    vector: 2, name: "leading-spaces-and-tabs", title: "leading spaces and tabs",
    why: "ID-23 opens with `[ \\t]*`. An editor that indents the file must not unbind a repository.",
    file: bytes(`  \t ${line(VALID)}`), outcome: "one", token: VALID,
  },
  {
    vector: 3, name: "trailing-comment", title: "a trailing `# comment`",
    why: "ID-23's `(#.*)?`. Authors annotate the line with when and why it was minted.",
    file: bytes(`astra-binding: ${VALID} # minted for the release workflow\n`), outcome: "one", token: VALID,
  },
  {
    vector: 4, name: "trailing-spaces", title: "trailing spaces and tabs",
    why: "ID-23's second `[ \\t]*`, which is what a `echo` into the file leaves behind.",
    file: bytes(`astra-binding: ${VALID} \t \n`), outcome: "one", token: VALID,
  },
  {
    vector: 5, name: "crlf", title: "CRLF",
    why: "ID-23 splits on `\\n` minus ONE `\\r`. A file committed from Windows binds.",
    file: bytes(`astra-binding: ${VALID}\r\n`), outcome: "one", token: VALID,
  },
  {
    vector: 6, name: "cr-cr-lf", title: "`\\r\\r\\n`",
    why:
      "Only one `\\r` is stripped, so a `\\r` survives into the line, `[ \\t]*$` cannot match it, and ID-24's " +
      "case-insensitive prefix then fires. The alternative — strip every trailing `\\r` — would let a file " +
      "carry a line that renders as a binding in one reader and not in another (MBE-PENDING Q3).",
    file: bytes(`astra-binding: ${VALID}\r\r\n`), outcome: "malformed", proposal: "Q3",
  },
  {
    vector: 7, name: "leading-bom", title: "a leading BOM",
    why: "ID-23 ignores a BOM. Committed by an editor the author did not choose, it must not unbind anything.",
    file: bytes(BOM, line(VALID)), outcome: "one", token: VALID, proposal: "Q4",
  },
  {
    vector: 8, name: "bom-on-a-later-line", title: "a BOM on a later line",
    why:
      "The BOM is ignored only at the START of the file (MBE-PENDING Q4). U+FEFF inside the file is an " +
      "ordinary character, it is not `[ \\t]`, so the line matches neither ID-23 nor ID-24's prefix and is " +
      "simply not a binding line. Ignoring it anywhere would let one be smuggled past a reader that does not.",
    file: bytes("# the owner file\n", BOM, line(VALID)), outcome: "none", proposal: "Q4",
  },
  {
    vector: 9, name: "token-15-characters", title: "a 15-character token",
    why: "One short of ID-23's `{16,128}`. The prefix matches, the grammar does not, so ID-24 refuses.",
    file: bytes(line(tok(15))), outcome: "malformed",
  },
  {
    vector: 9, name: "token-129-characters", title: "a 129-character token",
    why: "One over ID-23's `{16,128}`, and the other end of the same refusal.",
    file: bytes(line(tok(129))), outcome: "malformed",
  },
  {
    vector: 10, name: "token-16-characters", title: "a 16-character token",
    why:
      "ID-23's floor. The bot RECOGNISES it; FLOW-50 will not let the CLI WRITE it, because a minted token is " +
      "`{22,128}`. The two grammars differ on purpose and this is the case that says so.",
    file: bytes(line(tok(16))), outcome: "one", token: tok(16),
  },
  {
    vector: 10, name: "token-21-characters", title: "a 21-character token",
    why: "One short of FLOW-50's minted `{22,128}`, and well inside ID-23's. Recognised, never written.",
    file: bytes(line(tok(21))), outcome: "one", token: tok(21),
  },
  {
    vector: 10, name: "token-128-characters", title: "a 128-character token",
    why: "The ceiling both grammars share.",
    file: bytes(line(tok(128))), outcome: "one", token: tok(128),
  },
  {
    vector: 11, name: "newline-at-byte-4096", title: "the `\\n` at byte 4096",
    why:
      "The line is WHOLLY inside the window: its last byte is the terminator, and the terminator is the " +
      "4096th byte of the file. This is the inside edge of MBE-PENDING Q1.",
    file: bytes(pad(WINDOW_BYTES - line(VALID).length), line(VALID)),
    outcome: "one", token: VALID, proposal: "Q1",
  },
  {
    vector: 12, name: "last-content-byte-at-4096", title: "the last content byte at 4096 and `\\n` at 4097",
    why:
      "One byte out. The line's own bytes are all inside the window and its terminator is not, so the line is " +
      "not wholly inside it and does not count. A reader that took the content alone would bind a repository " +
      "on a line it could not prove was complete — which is AV-1, and the reason the window exists.",
    file: bytes(pad(WINDOW_BYTES - line(VALID).length + 1), line(VALID)),
    outcome: "none", proposal: "Q1",
  },
  {
    vector: 13, name: "line-crossing-4096", title: "a line crossing 4096",
    why: "It starts inside the window and ends outside it. A truncated read could see `astra-binding: abc…`.",
    file: bytes(pad(WINDOW_BYTES - 6), line(VALID)),
    outcome: "none", proposal: "Q1",
  },
  {
    vector: 14, name: "line-wholly-past-4096", title: "a line wholly past 4096",
    why:
      "Nothing of it is inside the window, and — unlike vector 13 — the window is full of ordinary complete " +
      "lines, so the reader has parsed 40 of them and stopped. The cheapest way to hide a binding from a " +
      "reader that honours the window while showing it to one that does not.",
    file: bytes(pad(100).repeat(42), line(VALID)),
    outcome: "none", proposal: "Q1",
  },
  {
    vector: 14, name: "case-variant-wholly-past-4096", title: "a case-variant line wholly past 4096",
    why:
      "MBE-PENDING Q2's own case, and the one shape none of B-T2.4's twenty-five reaches. ID-24 counts only " +
      "lines INSIDE the window, so an `Astra-Binding:` line past 4096 is not a malformed line — it is not a " +
      "line at all. Without this case Q2 is a proposal the corpus asserts nothing about, and a reader that " +
      "scanned the whole file for ID-24 candidates while scanning the window for ID-23 matches would pass " +
      "every other vector here.",
    file: bytes(pad(100).repeat(42), `Astra-Binding: ${VALID}\n`),
    outcome: "none", proposal: "Q2",
  },
  {
    vector: 15, name: "three-byte-characters-then-a-line", title: "1400 three-byte characters, then a line within 4096 UTF-16 units",
    why:
      "1400 × U+4E00 is 4200 BYTES and 1400 UTF-16 code units. The binding line that follows begins at byte " +
      "4201 and at unit 1401. A reader that slices 4096 UTF-16 units — which `bot/lib/ownership.mjs`'s login " +
      "reader does today — finds it and binds the repository; a reader that slices 4096 bytes does not. This " +
      "is the vector that tells the two apart, and the unit is BYTES.",
    file: bytes("一".repeat(1400) + "\n", line(VALID)),
    outcome: "none", proposal: "Q1",
  },
  {
    vector: 16, name: "invalid-utf8-earlier", title: "invalid UTF-8 earlier in the file",
    why:
      "0x80 0xFE 0xFF is not UTF-8 in any reading. The line after it is ordinary and inside the window, so the " +
      "outcome is `one`: a stranger's file is a byte string, and a reader that threw, or that re-encoded the " +
      "replacement characters and moved every later byte three places right, would answer a different question.",
    file: bytes("# ", Buffer.from([0x80, 0xfe, 0xff]), "\n", line(VALID)),
    outcome: "one", token: VALID,
  },
  {
    vector: 17, name: "two-valid-lines", title: "two valid lines",
    why: "ID-24's first clause. Two bindings is not a binding — it is a question the bot must not answer itself.",
    file: bytes(line(VALID), line(SECOND)), outcome: "malformed",
  },
  {
    vector: 18, name: "case-variant-key", title: "`Astra-Binding:`",
    why: "ID-23 is case-SENSITIVE and ID-24's prefix is not. A near-miss is refused, never ignored.",
    file: bytes(`Astra-Binding: ${VALID}\n`), outcome: "malformed",
  },
  {
    vector: 19, name: "space-before-colon", title: "`astra-binding :`",
    why: "ID-24's prefix allows `[ \\t]*` before the colon and ID-23 does not, so this is exactly a refusal.",
    file: bytes(`astra-binding : ${VALID}\n`), outcome: "malformed",
  },
  {
    vector: 20, name: "no-token", title: "no token at all",
    why: "The key with nothing after it. It is a line somebody meant as a binding, so it refuses rather than passes.",
    file: bytes("astra-binding:\n"), outcome: "malformed",
  },
  {
    vector: 20, name: "plus-in-token", title: "`+` in the token",
    why: "Outside `[A-Za-z0-9_-]`. Base64's two extra characters are the obvious thing to try.",
    file: bytes("astra-binding: abcdefghij+lmnopqrst\n"), outcome: "malformed",
  },
  {
    vector: 21, name: "bare-login-line", title: "a bare `astra-binding` login line",
    why:
      "`astra-binding` is a legal GitHub login, and the owner file has held one login per line since before a " +
      "token existed (`bot/lib/ownership.mjs`). No colon, so ID-24's prefix does not match and the line is what " +
      "it has always been: a login. Refusing it would break every owner file that happens to name this account.",
    file: bytes("astra-binding\n"), outcome: "none",
  },
  {
    vector: 22, name: "logins-mixed-with-one-line", title: "logins mixed with one line",
    why: "The migration shape: an owner file that already lists logins, with a binding added to it.",
    file: bytes("octocat-example\n# the people who may publish\nanother-login\n", line(VALID), "a-third-login\n"),
    outcome: "one", token: VALID,
  },
  {
    vector: 23, name: "cr-is-not-a-line-break", title: "`login\\rastra-binding: <valid>`",
    why:
      "ID-23 splits on `\\n` and on nothing else. A bare CR does not start a line, so this file holds ONE line " +
      "that begins `login` and binds nothing. A reader that also split on `\\r` — which is what a `splitlines()` " +
      "in most languages does — would bind this repository to a stranger's token off a line the author cannot " +
      "see in their editor.",
    file: bytes(`login-example\rastra-binding: ${VALID}\n`), outcome: "none",
  },
  {
    vector: 24, name: "nbsp-before-the-line", title: "U+00A0 before the line",
    why:
      "A no-break space is not `[ \\t]`. It renders as a space in every editor and is two bytes of something " +
      "else, which makes it the cheapest way to write a line that looks bound to a human and is not.",
    file: bytes(`\u00a0${line(VALID)}`), outcome: "none",
  },
  {
    vector: 25, name: "empty-file", title: "an empty file",
    why: "Zero bytes. Not an error, not malformed: there is no line.",
    file: bytes(""), outcome: "none",
  },
  {
    vector: 25, name: "bom-only", title: "a file holding only a BOM",
    why: "Three bytes, all of them ignored, and nothing left. Still `none`, never a crash (MBE-PENDING Q4).",
    file: bytes(BOM), outcome: "none",
  },
];

// ── assembly ────────────────────────────────────────────────────────────────

function build() {
  const seen = new Set();
  const cases = CASES.map((c) => {
    const id = `${String(c.vector).padStart(2, "0")}-${c.name}`;
    if (seen.has(id)) throw new Error(`two cases are called ${id}`);
    seen.add(id);
    if (c.outcome === "one" && !c.token) throw new Error(`${id} says \`one\` and names no token`);
    if (c.outcome !== "one" && c.token) throw new Error(`${id} names a token and does not say \`one\``);
    const out = {
      case: id,
      vector: c.vector,
      title: c.title,
      why: c.why,
      bytes: c.file.length,
      file_b64: c.file.toString("base64"),
      outcome: c.outcome,
      token: c.token ?? null,
    };
    // FLOW-50 is the CLI's writer grammar, not this reader's. The member is
    // present only where the two DIFFER — the bot recognises the token and the
    // CLI would refuse to write it — because a column that repeated the
    // reader's answer on every row would be a column nothing could disagree
    // with.
    if (c.outcome === "one" && !CLI_WRITE_RE.test(c.token)) out.cli_write = "refuse";
    if (c.proposal) out.proposal = c.proposal;
    return out;
  });

  const vectors = new Set(cases.map((c) => c.vector));
  if (vectors.size !== 25) throw new Error(`${vectors.size} vector numbers, and B-T2.4 numbers 25`);
  for (let n = 1; n <= 25; n++) if (!vectors.has(n)) throw new Error(`vector ${n} has no case`);

  return {
    schema: "astra.testdata.binding-line/1",
    generated_by: "tests/binding-line/generate.mjs",
    canonical: "astra-registry:tests/binding-line/vectors.json",
    window_bytes: WINDOW_BYTES,
    window_unit: "bytes",
    grammar: { id_23: ID_23_SOURCE, id_24_prefix: ID_24_PREFIX_SOURCE, cli_write: CLI_WRITE_SOURCE },
    outcomes: ["none", "one", "malformed"],
    proposals: {
      Q1: "the 4096-byte window",
      Q2: "ID-24 counts only lines inside the window",
      Q3: "`\\r\\r` is malformed",
      Q4: "the BOM is ignored only at the start of the file",
      Q5: "the service's ID-59 read of the default branch gives the bot's none, one or malformed",
    },
    floors: { vectors: 25, cases: 31 },
    cases,
  };
}

const VECTORS = path.join(DIR, "vectors.json");
const SUMS = path.join(DIR, "SHA256SUMS");

const doc = JSON.stringify(build(), null, 2) + "\n";
const sums = `${crypto.createHash("sha256").update(doc).digest("hex")}  vectors.json\n`;

const check = process.argv.includes("--check");
if (check) {
  const problems = [];
  for (const [file, want] of [[VECTORS, doc], [SUMS, sums]]) {
    const rel = path.relative(process.cwd(), file);
    if (!fs.existsSync(file)) problems.push(`${rel} is missing`);
    else if (fs.readFileSync(file, "utf8") !== want) problems.push(`${rel} is not what this generator produces`);
  }
  if (problems.length) {
    console.error(
      `FAIL  ${problems.join("; ")}.\n` +
      "      These bytes are mirrored into AstraPlugins as testdata/binding-line/vectors.json (AP-6, rule\n" +
      "      C31) and pinned for the plugins service, so a hand edit here is a hand edit to two other\n" +
      "      repositories' fixtures. Change tests/binding-line/generate.mjs and re-run it without --check.",
    );
    process.exit(1);
  }
  console.log(`ok    tests/binding-line/vectors.json — ${build().cases.length} cases, ${25} vectors`);
} else {
  fs.writeFileSync(VECTORS, doc);
  fs.writeFileSync(SUMS, sums);
  console.log(`wrote tests/binding-line/vectors.json (${doc.length} bytes) and SHA256SUMS`);
}
