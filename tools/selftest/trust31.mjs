// TRUST-31's hashed set, as the registry's copy of it states it, for the test
// modules that hold something to it. Not a test module: it exports no `run()`.
//
// Two readers and one definition. `primitives.mjs` holds the schemas to the set,
// and `publishers.mjs` holds the daily re-check's commit outside it (dev/couplings.md
// entry 109). The reader lived in `primitives.mjs` until the second needed it,
// and `publishers.mjs` cannot import that module: it imports `tools/make-fixtures.mjs`,
// which is outside the set, and `publishers.mjs` reaches nothing outside it
// today (contract pending item 19).

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../lib/sources.mjs";

/** The registry's copy of TRUST-31's set. */
export const TRUST31_COPY = "bot/tests/code-paths.test.mjs";

/**
 * `ENTRIES` in the TRUST-31 copy, read as TEXT and the way astra-plugins-ops'
 * `tools/check-trust31-copies.mjs` reads it, so that the two readers of one
 * list cannot disagree about what it holds.
 *
 * Not imported, because it cannot be: the file is a `node:test` suite, and
 * importing it would run its tests — git calls, the import walk, the set hash —
 * inside this one. Each anchor must occur exactly once, because a second
 * `export const ENTRIES = [` read from the first would be a guess.
 */
export function trust31Entries() {
  const src = fs.readFileSync(path.join(REPO_ROOT, ...TRUST31_COPY.split("/")), "utf8");
  const block = (open, close) => {
    const at = src.indexOf(open);
    if (at < 0 || src.indexOf(open, at + open.length) >= 0) {
      throw new Error(
        `${TRUST31_COPY}: \`${open}\` occurs ${at < 0 ? "nowhere" : "more than once"}, so TRUST-31's set cannot ` +
        `be read off it. astra-plugins-ops' tools/check-trust31-copies.mjs reads the same anchor`,
      );
    }
    const end = src.indexOf(close, at + open.length);
    if (end < 0) throw new Error(`${TRUST31_COPY}: \`${open}\` is never closed`);
    return src.slice(at + open.length, end).replace(/\/\/.*/g, "");
  };
  const workflows = block("const WORKFLOWS = [", "];");
  const entries = block("export const ENTRIES = [", "\n];");
  // `ENTRIES` spreads `WORKFLOWS` in; reading both is right only while it does.
  if (!/^\s*\.\.\.WORKFLOWS,/.test(entries)) {
    throw new Error(`${TRUST31_COPY}: \`ENTRIES\` no longer opens with \`...WORKFLOWS,\`, so reading both lists is a guess`);
  }
  const strings = (body) => [...body.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  return [...strings(workflows), ...strings(entries)];
}

/**
 * Does the set cover `p`? A directory entry covers everything beneath it. For a
 * DIRECTORY `p` (a trailing `/`) the answer is also yes when an entry lies
 * beneath it: a commit that stages the whole directory can stage that entry.
 */
export function trust31Covers(entries, p) {
  if (entries.some((e) => (e.endsWith("/") ? p.startsWith(e) : p === e))) return true;
  return p.endsWith("/") && entries.some((e) => e.startsWith(p));
}
