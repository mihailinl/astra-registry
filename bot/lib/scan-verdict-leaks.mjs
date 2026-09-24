// BOT-89's log scan: no verdict, token state or eligibility value in a run's
// logs or step summaries (registry plan B-T3.6 step 3; ROLL-64 step 4).
//
//   node bot/lib/scan-verdict-leaks.mjs <file> [<file> …]
//
// The run logs of this repository are public, and a binding verdict is a fact
// about a person's account. The bot keeps every such value out of what it
// prints by construction — `ask` reduces a verdict to one of four words — and
// this is the check that the construction held, run over one full run's logs
// and summaries at R3 and again in every re-acknowledgement window, because
// any later hashed-path commit can print a value.
//
// ── what counts as a leak ───────────────────────────────────────────────────
//
// §0.8's token-state values (`minted`, `seen`, `bound`, `revoked`, `expired`,
// `superseded`, `unknown`) and eligibility values (`eligible`, `ineligible`,
// `unreadable`), as WHOLE WORDS in a VALUE position: after `:` or `=`,
// optionally quoted, or standing alone as a quoted JSON string. Not the four
// acted outcomes (`pass`, `B_BINDING_UNUSABLE`, `W_ELIGIBILITY_UNREADABLE`,
// `shadow`) — those are what `ask` is allowed to say — and not a word that
// merely contains a value (`releases-seen`, `outbound`), which is prose.
//
// The report names the file, the line and the KEY, and never the value: a
// scanner that printed what it found would be the leak it exists to catch.
//
// It lives under `bot/lib/` rather than as the plan's `bot/scan-verdict-
// leaks.mjs`, because a new top-level `bot/*.mjs` is an entry TRUST-31's set
// enumerates and a contract MINOR publishes it first.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

/** §0.8: token states (B.3's binding states plus `unknown`) and eligibility. */
export const VERDICT_VALUES = Object.freeze([
  "minted", "seen", "bound", "revoked", "expired", "superseded", "unknown",
  "eligible", "ineligible", "unreadable",
]);

/** BOT-89's four acted outcomes, which `ask` may print. */
export const ACTED_OUTCOMES = Object.freeze(["pass", "B_BINDING_UNUSABLE", "W_ELIGIBILITY_UNREADABLE", "shadow"]);

/** A line scanned must be at least this long for the floor to count it. */
export const LINES_FLOOR = 1;

const WORDS = VERDICT_VALUES.join("|");
const BOUNDARY = "(?![A-Za-z0-9_-])";
// `key: value`, `key=value`, `"key": "value"`, `key = 'value'`.
const KEYED = new RegExp(`([A-Za-z0-9_."'-]{0,64})\\s*[:=]\\s*["']?(?:${WORDS})${BOUNDARY}`, "g");
// A value standing alone as a JSON string: `["bound"]`, `, "ineligible"`.
const QUOTED = new RegExp(`(^|[\\[,\\s])"(?:${WORDS})"`, "g");

/**
 * The leaks in one text, as `{line, key}` — never the value.
 *
 * @param {string} text
 */
export function leaksIn(text) {
  const out = [];
  String(text ?? "").split("\n").forEach((line, i) => {
    for (const m of line.matchAll(KEYED)) {
      // A value position preceded by a word character is part of a larger
      // token (`outbound=`, `x-seen:`): the whole-word rule on the left.
      const before = line[m.index - 1];
      if (m[1] === "" && before && /[A-Za-z0-9_-]/.test(before)) continue;
      out.push({ line: i + 1, key: m[1].replace(/["']/g, "") || "(no key)" });
    }
    for (const m of line.matchAll(QUOTED)) {
      if (out.some((o) => o.line === i + 1)) continue;
      out.push({ line: i + 1, key: "(a quoted value)" });
      void m;
    }
  });
  return out;
}

/**
 * The scan over files, with its floors: a scan of nothing finds nothing and
 * passes, so it refuses to report green over no files or no lines.
 *
 * @param {string[]} files
 * @returns {{scanned: number, lines: number, leaks: {file: string, line: number, key: string}[], problems: string[]}}
 */
export function scanFiles(files) {
  const problems = [];
  const leaks = [];
  let lines = 0;
  if (!files.length) problems.push("no file was named, and a scan of nothing finds nothing");
  for (const file of files) {
    let text;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch (e) {
      problems.push(`${file} could not be read (${e.code ?? e.message})`);
      continue;
    }
    lines += text.split("\n").length;
    for (const l of leaksIn(text)) leaks.push({ file, ...l });
  }
  if (files.length && lines < LINES_FLOOR) problems.push(`${lines} line(s) scanned; the floor is ${LINES_FLOOR}`);
  return { scanned: files.length, lines, leaks, problems };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { scanned, lines, leaks, problems } = scanFiles(process.argv.slice(2));
  for (const p of problems) console.error(`::error::${p}`);
  for (const l of leaks) {
    console.error(`::error::${l.file}:${l.line}: a token-state or eligibility value in a value position (key ${l.key}); BOT-89 forbids printing it`);
  }
  console.log(`scanned ${scanned} file(s), ${lines} line(s); ${leaks.length} leak(s)`);
  process.exit(problems.length || leaks.length ? 1 : 0);
}
