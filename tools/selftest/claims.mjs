// ── WHAT THIS READS OUTSIDE THIS CHECKOUT, AND ONLY WHAT ───────────────────
//
// Three other checkouts, and only when one is on the machine running it (never
// in registry CI, which has none of them): Astra (`$ASTRA_DIR`, else
// `../Astra`), minice-be (`$ASTRA_SERVICE_DIR`, else `../minice`) and
// astra-plugins-ops (`$ASTRA_OPS_DIR`, else `../astra-plugins-ops`).
//
// **In Astra it reads the files its rows list, and nothing else.** No walk from
// a root and no `git ls-files` of the whole tree: git is asked for exactly the
// listed paths, a listed directory is read one level deep, and a row that gives
// a prefix instead of a list is refused before anything is opened. Why: parts of
// that tree are off limits to the people and agents who run this suite, and a
// walk from a root reads them on the runner's behalf — which it did, until
// 2026-09-22, whenever the suite ran from a checkout with `../Astra` beside
// it. The fence is an allow-list rather than a deny-list because a list of what
// may not be read would publish private paths in a public repository. The
// check "a tree read only through a list" below is what holds it.
//
// In minice-be it reads the tracked files with each row's source extensions,
// because its rows are absences claimed about the whole service; in
// astra-plugins-ops, the one file its row names. Every row prints what it
// walks, and a listed row prints what it read.
//
// ── what this is ───────────────────────────────────────────────────────────
//
// Every claim this repository makes about a reader in ANOTHER repository,
// carrying the literal search that finds it.
//
// ── what this is for ───────────────────────────────────────────────────────
//
// On 2026-09-19 two estates produced the same defect five times in one day: a
// sentence in the present tense about a component in another repository, which
// was not true. The signed-set corpus "vendored into
// `astra-daemon/testdata/signed-set-vectors/`" — that directory does not exist.
// The plugins service reading it "at a pinned commit" — nothing pins it. AV-7's
// advisory-kinds leg "in the plugins service" — no such reader, and no design
// entry for it to be unimplemented from.
//
// **It is worse than an absent implementation.** An absent implementation is a
// hole somebody can see. A row that says a coupling is watched tells a third
// party they may rename the thing, because it would be caught over there. For
// AV-7 that third party is whoever adds a revocation kind, and one unknown kind
// makes the daemon refuse the WHOLE list — so every armed build of that
// population blocks installs seven days later. The false claim is the mechanism
// by which the real failure ships.
//
// So: a claim that names a reader in another repository carries the literal
// search that finds it, and the row fails when the search comes back empty.
// Not a link, not a section number, not a requirement id — the search, run,
// with a floor, saying which tree it read, and recording the expected state in
// BOTH directions.
//
// ── why a table and not another hard-coded pair ─────────────────────────────
//
// `C12`, `C15`, `C16` and `C20` already skip loudly and are the shape this
// copies. What none of them has is a TABLE: each hard-codes one comparison, so
// a claim written tomorrow is checked by nothing until somebody writes a
// sixteenth function. Here the claims are data, and a claim added later is
// checked BY HAVING BEEN WRITTEN.
//
// ── the four verdicts, and why four ─────────────────────────────────────────
//
// Counted rather than felt, by the partner estate, over 26 uses of an
// `unexercised` sentinel and five hand-written bounds. Three of these are not
// FOUND and they fail differently and want opposite remedies:
//
//   FOUND           the search ran, over a tree that was there, and the reader
//                   is in it.
//   MEASURED ABSENT the search ran, over a tree that was there, its walk met
//                   its floor, and the needle matched nothing. Remedy: fix the
//                   claim, or fix the needle. ("not one RAISE was found in 16
//                   migration(s)" — the denominator is what makes this a
//                   finding rather than a shrug.)
//   COULD NOT ASK   the search never ran: no checkout, no `git ls-files`, or a
//                   walk below its floor. Remedy: provide the tree. **COULD
//                   NOT ASK IS NOT NO COVER**, and it is not MEASURED ABSENT
//                   either — collapsing the two makes a broken needle read as
//                   a missing tool, so somebody goes and builds a tool that
//                   already exists, and it makes the instrument report
//                   confident absences about trees it never opened, which is
//                   the defect it exists to catch wearing its own uniform.
//   OUT OF SCOPE    a permanent stated bound on what a row ever covers.
//                   **Never fixed**, because there is nothing to fix; printed
//                   every run so it cannot be read as coverage, and kept out
//                   of every count of what was checked. Collapsing this into
//                   COULD NOT ASK turns a deliberate bound into a to-do
//                   nobody will ever do, and it reads as coverage meanwhile.
//
// The last two are STATEMENTS. They are printed, they are never a pass, and
// they are never a red.
//
// ── the two kinds of subject, and why the second needs saying ───────────────
//
// `kind: "code"` searches a tree for a reader. `kind: "decision"` reads a
// design item's STATE — chosen, open, built, withdrawn — and not merely its
// existence: **a section number that resolves is not a section number that was
// decided.**
//
// The reason is the sharper half of this whole page. **The first kind of false
// claim decays; the second was never true.** A stale claim was right once and
// stopped being, so time and re-measurement find it. A decision written down
// as its expected branch was false the moment somebody who could see both
// branches typed it, and nothing that runs later can tell, because there was
// never a moment when the sentence was right. Re-measuring the other
// repository never finds it — only reading the decision does. So where a claim
// points at a design item, `open` is a legitimate printable answer that is not
// `absent`, and the row asserts the claim's own sentence is hedged to match.
//
// ── the half that runs everywhere ───────────────────────────────────────────
//
// Registry CI checks out no Astra, no minice-be and no astra-plugins-ops, so
// every foreign row is COULD NOT ASK there, for ever, loudly. What runs on
// every machine is the ANCHOR and the HEDGE: the claim's sentence must still be
// in the file that makes it, and a claim whose expected state is `absent` must
// SAY SO in that sentence. That is the check that would have caught all five
// instances at the moment each was typed, with no second checkout anywhere —
// because in every one of them the sentence was in the present tense and the
// thing was not there.
//
// Registry plan: gap 21 of `O:dev/couplings.md`; RC-R1-6 (the AV-7 rows).

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

export const FOUND = "FOUND";
export const MEASURED_ABSENT = "MEASURED ABSENT";
export const COULD_NOT_ASK = "COULD NOT ASK";
export const OUT_OF_SCOPE = "OUT OF SCOPE";

/**
 * This file, as a path in this checkout — and never part of any walk of it.
 *
 * **The file that states the claims is not an instance of them.** Until
 * 2026-09-22 the `signed-set/selftest` row searched `tools/selftest/` for
 * `loadSignedSetVectors`, and two of its nine hits were in this file: the
 * row's own `claim` string and its own `needle` literal. Measured by renaming
 * every occurrence in `index-signature.mjs`, the only reader: the row still
 * resolved FOUND, `2 hit(s)`, both of them here. So the one row in registry CI
 * that asserts a reader is PRESENT could not go red for losing it — it was
 * answered by the question. The canary further down that ASSEMBLES its needle
 * met this on the day it was committed; the real table never did.
 *
 * Derived from this module's own location, for the reason `isSuiteFile` in
 * harness.mjs gives: moving the file moves the exclusion with it. Only this
 * file — `tools/selftest/` as a whole is the SUBJECT of that row, so excluding
 * the suite would make it search nothing.
 */
const SELF = path.relative(REPO_ROOT, fileURLToPath(import.meta.url)).split(path.sep).join("/");

/**
 * The floor on rows RESOLVED — FOUND or MEASURED ABSENT — in one run. Gap 24
 * of `O:dev/couplings.md`.
 *
 * COULD NOT ASK is never a red, and must not become one: registry CI checks out
 * none of the three foreign trees, so a red there would be every fork's PR red
 * about a private repository it cannot see. But that left nothing under the
 * count. A runner change (no `git`, a sparse checkout), an input renamed out
 * from under a row, or a bug in `locate()` turns an answered row into COULD NOT
 * ASK, and the transcript said so in a line nobody reads while the suite
 * printed the same headline. The instrument degrading from asking eleven
 * questions to asking one was a quieter report and nothing else.
 *
 * **3, measured, not chosen.** It is the count on the poorest runner that runs
 * this suite: `build-index.yml`'s `check` job at `89a79b5` (run 35764249417,
 * Node 22.23.2) printed `1 found, 2 measured absent, 7 could not ask, 1 out of
 * scope`, and so does any checkout with no `../Astra`, `../minice` or
 * `../astra-plugins-ops` and no `$ASTRA_*_DIR`. Those three are the rows about
 * THIS checkout — the only tree CI has.
 *
 * **A floor, not an equality.** A row that becomes answerable — a sibling on a
 * laptop, `$ASTRA_OPS_DIR` set, the day a workflow gets a token and a clone —
 * raises the count and reddens nothing. **Raised by hand**, in the commit that
 * makes CI answer more, as `FLOORS` in tools/selftest.mjs is: never from the
 * last run, because this number is a property of the MACHINE. A laptop with all
 * three siblings resolves ten; a floor that followed whichever run came last
 * would be pinned by the richest machine and red on every poorer one, which is
 * the fork-PR red above arriving by a side door.
 *
 * **Lowered only deliberately**, in the same commit as the change that costs
 * the row, and the red says so with the number to lower it to.
 */
export const RESOLVED_FLOOR = 3;

/**
 * The trees a claim can be about, and how to find one.
 *
 * `env` first, then the sibling, which is the order `tools/validate.mjs` uses
 * for `$ASTRA_PLUGINS_DIR`. `probe` is a tracked file that must exist for the
 * directory to count as that tree — a directory that happens to have the right
 * NAME is not a checkout, and pointing at one would produce a walk of nothing
 * and a confident absence.
 *
 * `onlyListedPaths` marks a tree that is read through an explicit list and
 * never walked — see the header for why Astra is one. A row about such a tree
 * gives `paths`, not `under` and `exts`; `listedFiles` asks git for those paths
 * and nothing else, and `resolve` refuses any other shape before it locates the
 * tree. Until 2026-09-22 four rows walked `astra-rs` or
 * `astra-rs/astra-daemon/src` whole (300 and 50 files were their floors), and
 * what each one's claim is about is one to three files that its own sentence,
 * the README it anchors in, or the client plan names.
 */
export const TREES = {
  here: {
    label: "astra-registry (this checkout)",
    env: null,
    siblings: [REPO_ROOT],
    probe: "tools/selftest.mjs",
  },
  astra: {
    label: "Astra (the daemon and the UI; private)",
    env: "ASTRA_DIR",
    siblings: ["../Astra"],
    probe: "astra-rs/Cargo.toml",
    onlyListedPaths: true,
  },
  service: {
    label: "minice-be (the plugins service; private)",
    env: "ASTRA_SERVICE_DIR",
    siblings: ["../minice"],
    probe: "api/Cargo.toml",
  },
  ops: {
    label: "astra-plugins-ops (the plans and the register; private)",
    env: "ASTRA_OPS_DIR",
    siblings: ["../astra-plugins-ops"],
    probe: "dev/couplings.md",
  },
};

/** Where a tree is, and how it was found — or why it could not be asked. */
export function locate(tree) {
  const tried = [];
  const candidates = [];
  if (tree.env) {
    tried.push(`$${tree.env}${process.env[tree.env] ? ` = ${process.env[tree.env]}` : " (unset)"}`);
    if (process.env[tree.env]) candidates.push(process.env[tree.env]);
  }
  for (const rel of tree.siblings) {
    const abs = path.resolve(REPO_ROOT, rel);
    tried.push(abs);
    candidates.push(abs);
  }
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, tree.probe))) return { dir, tried };
  }
  return { dir: null, tried };
}

/**
 * The tracked files of a tree, filtered to what a claim's search is about.
 *
 * `git ls-files` rather than a disk walk, for the reason `walkRepo()` gives:
 * it is the same answer on a developer's machine and in CI, and nothing
 * downloaded, built or vendored-by-a-package-manager is in it. A `target/`
 * with half a million lines of somebody's dependency is not a place a claim
 * about a reader can be true.
 *
 * Throws rather than returning `[]`. An empty list from a failed `git` is the
 * one input that makes every search below come back absent, and it must not be
 * possible to read that as an answer.
 */
export function trackedFiles(dir, { under = [], exts = [] } = {}) {
  let listed;
  try {
    listed = execFileSync("git", ["-C", dir, "ls-files", "-z"], {
      encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    throw new Error(`\`git -C ${dir} ls-files\` failed: ${String(e.stderr || e.message).trim()}`);
  }
  return listed
    .split("\0")
    .filter(Boolean)
    .filter((rel) => under.length === 0 || under.some((u) => rel === u || rel.startsWith(`${u}/`)))
    .filter((rel) => exts.length === 0 || exts.some((x) => rel.endsWith(x)));
}

/** A path that can be written into a pathspec and mean only itself: no glob character, no `.`/`..`, no root. */
const LISTED_PATH = /^[A-Za-z0-9_@-][A-Za-z0-9_.@-]*(?:\/[A-Za-z0-9_@-][A-Za-z0-9_.@-]*)*\/?$/;

/**
 * The tracked files an explicit list names, asked of git by those paths alone.
 *
 * An entry is a FILE, or a DIRECTORY written with a trailing `/`, which is read
 * one level deep: a subdirectory is read only if it is listed itself. Each
 * entry is its own `git ls-files` with a pathspec that cannot mean more:
 *
 *   file  `:(literal)<f>` and `:(exclude,glob)<f>/**` — a bare pathspec also
 *         matches as a LEADING DIRECTORY, so without the exclusion a file entry
 *         that is really a directory would list its whole subtree. With it, such
 *         an entry lists nothing, and `resolve` reports the file as missing.
 *   dir   `:(glob)<d>*` — under `glob` magic `*` does not cross a `/`.
 *
 * So git never prints a name the list does not give, and what it does print is
 * checked against the entry anyway: a path that is neither the file nor a
 * direct child of the directory throws rather than being read. Measured with
 * git 2.55.0 on a scratch repository before this was written: `:(literal)a/b`
 * listed `a/b/c/y.rs`; `:(glob)a/b/*` did not; `:(literal)a/b` with
 * `:(exclude,glob)a/b/**` listed nothing.
 *
 * Throws, like `trackedFiles`, rather than returning `[]` on a failed `git`.
 */
export function listedFiles(dir, paths) {
  const out = [];
  for (const entry of paths) {
    if (typeof entry !== "string" || !LISTED_PATH.test(entry)) {
      throw new Error(`${JSON.stringify(entry)} is not a plain repository-relative path, so no pathspec means only it`);
    }
    const isDir = entry.endsWith("/");
    const spec = isDir ? [`:(glob)${entry}*`] : [`:(literal)${entry}`, `:(exclude,glob)${entry}/**`];
    let listed;
    try {
      listed = execFileSync("git", ["-C", dir, "ls-files", "-z", "--", ...spec], {
        encoding: "utf8", maxBuffer: 16 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      throw new Error(`\`git -C ${dir} ls-files -- ${spec.join(" ")}\` failed: ${String(e.stderr || e.message).trim()}`);
    }
    for (const rel of listed.split("\0").filter(Boolean)) {
      const inside = isDir ? path.posix.dirname(rel) === entry.slice(0, -1) : rel === entry;
      if (!inside) {
        throw new Error(`git answered ${rel} for the listed ${entry}, which is not that path; nothing was read`);
      }
      if (!out.includes(rel)) out.push(rel);
    }
  }
  return out;
}

/**
 * Why a row may not be walked on a tree read only through a list — every
 * reason, or `[]`.
 *
 * One rule, applied twice: `resolve` refuses a row this returns anything for,
 * before it so much as locates the tree, and the check "a tree read only through
 * a list" reds the table on it, so a widened row is red in registry CI and not
 * only on the machine that has the tree.
 *
 *   - `paths` is a non-empty list, and there is no `under` or `exts` — a prefix
 *     and an extension filter are how a walk of a root is written;
 *   - every entry is a plain path, and none is the tree's root or a directory
 *     above its probe file (for Astra, `astra-rs` itself);
 *   - no entry is repeated;
 *   - a DIRECTORY entry is one the row's own claim names, backticked, with or
 *     without its first segment (this repository's sentences drop `astra-rs/`).
 *     A directory reads files nobody chose, so it has to be the thing the claim
 *     is about — the vendored corpus's directory is, `src/` never is.
 */
export function listProblems(claim, tree) {
  const s = claim.subject;
  const problems = [];
  if (s.under !== undefined) problems.push(`gives \`under\` (${JSON.stringify(s.under)}), which is a walk from a prefix`);
  if (s.exts !== undefined) problems.push("gives `exts`, which filters a walk; an explicit list is its own filter");
  if (!Array.isArray(s.paths) || s.paths.length === 0) {
    problems.push("gives no `paths`, or an empty list");
    return problems;
  }
  const probeAncestors = new Set([""]);
  const probeParts = tree.probe.split("/").slice(0, -1);
  for (let i = 1; i <= probeParts.length; i++) probeAncestors.add(probeParts.slice(0, i).join("/"));
  const bare = (p) => (typeof p === "string" && p.endsWith("/") ? p.slice(0, -1) : p);
  s.paths.forEach((p, i) => {
    if (typeof p !== "string" || !LISTED_PATH.test(p)) {
      problems.push(`${JSON.stringify(p)} is not a plain repository-relative path`);
      return;
    }
    if (probeAncestors.has(bare(p))) problems.push(`${p} is the tree's root or a directory above ${tree.probe}`);
    if (s.paths.indexOf(p) !== i) problems.push(`${p} is listed twice`);
    if (p.endsWith("/")) {
      const short = p.split("/").slice(1).join("/");
      if (!claim.claim.includes(`\`${p}\``) && !(short && claim.claim.includes(`\`${short}\``))) {
        problems.push(`${p} is a directory, and the row's own claim does not name it`);
      }
    }
  });
  return problems;
}

/** What a row walks, in one line, for the transcript — so every run says what it would open. */
export function describeWalk(subject) {
  if (subject.paths) {
    return `only ${subject.paths.map((p) => (p.endsWith("/") ? `${p} (one level)` : p)).join(", ")}`;
  }
  const under = subject.under?.length ? `under [${subject.under.join(", ")}]` : "the whole tracked tree";
  const exts = subject.exts?.length ? ` with [${subject.exts.join(", ")}]` : "";
  return `${under}${exts}`;
}

/**
 * One claim, resolved to one of the four verdicts.
 *
 * Pure with respect to the claim: everything it reads is named in the claim or
 * in `TREES`, so the tests below can construct a claim and watch each verdict
 * come out, rather than hoping the real table will one day exercise them.
 */
export function resolve(claim, trees = TREES) {
  if (claim.subject.kind === "bound") {
    return { verdict: OUT_OF_SCOPE, tree: "—", detail: claim.subject.statement };
  }

  const tree = trees[claim.subject.tree];
  if (!tree) return { verdict: COULD_NOT_ASK, tree: claim.subject.tree, detail: "no such tree is declared in TREES" };
  // Before `locate`, so that a widened row opens nothing — not the probe file,
  // not git — and says so identically on a machine with the tree and without.
  if (tree.onlyListedPaths) {
    const problems = listProblems(claim, tree);
    if (problems.length) {
      return {
        verdict: COULD_NOT_ASK,
        tree: tree.label,
        dir: null,
        read: [],
        detail: `not walked, and nothing was opened: this tree is read only through an explicit list of paths, ` +
          `and this row ${problems.join("; ")}`,
      };
    }
  }
  const { dir, tried } = locate(tree);
  if (!dir) {
    return {
      verdict: COULD_NOT_ASK,
      tree: tree.label,
      dir: null,
      detail: `no checkout: looked for ${tree.probe} under ${tried.join(", ")}`,
    };
  }

  const { under = [], exts = [], paths = null, floorFiles = 1, needle } = claim.subject;
  let files;
  try {
    files = paths ? listedFiles(dir, paths) : trackedFiles(dir, { under, exts });
  } catch (e) {
    return { verdict: COULD_NOT_ASK, tree: tree.label, dir, detail: `${dir}: ${e.message}` };
  }
  if (path.resolve(dir) === path.resolve(REPO_ROOT)) files = files.filter((rel) => rel !== SELF);

  // Read first, and floor what was READ. `git ls-files` lists the index, not
  // the disk, so a tracked file can be listed and not be there: deleted and not
  // staged, outside a sparse checkout's cone, a gitlink that is a directory.
  // The floor used to count the LIST and the loop below skipped an unreadable
  // file with a bare `continue` — so, measured on 2026-09-22 with
  // `registry/v1/trust.json` removed from disk and left in the index,
  // `security/not-after-cutoff` reported `0 hit(s) in 1 tracked file(s)`,
  // MEASURED ABSENT, about a file nobody opened. That is the confident absence
  // this instrument exists to refuse, produced by its own walk. A file that was
  // not read is not part of the denominator.
  const hits = [];
  const unread = [];
  const opened = [];
  let read = 0;
  for (const rel of files) {
    let text;
    try {
      text = fs.readFileSync(path.join(dir, rel), "utf8");
    } catch {
      unread.push(rel);
      continue;
    }
    read++;
    opened.push(rel);
    text.split("\n").forEach((line, i) => {
      if (needle.test(line)) hits.push(`${rel}:${i + 1}`);
    });
  }
  const skipped = unread.length
    ? `; ${unread.length} tracked file(s) could not be read and are not counted: ${unread.slice(0, 4).join(", ")}`
    : "";

  // A list's floor is the list: every FILE it names must have been read. A
  // file that moved leaves the row searching what is left of the list, and an
  // absence over the remainder is the confident absence the floor below
  // exists to refuse — one level finer.
  if (paths) {
    const missing = paths.filter((p) => !p.endsWith("/") && !opened.includes(p));
    if (missing.length) {
      return {
        verdict: COULD_NOT_ASK,
        tree: tree.label,
        dir,
        read: opened,
        detail: `the list names ${missing.join(", ")}, which ${dir} does not track as a file or could not be read; ` +
          `a list that has lost a file is a stale list, not an absent reader${skipped}`,
      };
    }
  }

  // The floor, before any conclusion. "I searched and found nothing" and "I
  // searched the wrong tree" are one observation until a minimum is asserted,
  // and the second is the more likely of the two: a path moves, a crate is
  // renamed, an extension list outlives the language. Below the floor this is
  // a broken walk and therefore COULD NOT ASK — never MEASURED ABSENT, which
  // is the collapse the whole instrument is against.
  if (read < floorFiles) {
    return {
      verdict: COULD_NOT_ASK,
      tree: tree.label,
      dir,
      read: opened,
      detail: `the walk of ${dir} read ${read} of ${files.length} tracked file(s), walking ` +
        `${describeWalk(claim.subject)}, and the floor is ` +
        `${floorFiles}; this is a broken walk, not an absent reader, and every conclusion below it would have ` +
        `been a confident absence${skipped}`,
    };
  }

  const seen = `${hits.length} hit(s) in ${read} tracked file(s) read of ${dir}${skipped}`;
  if (claim.subject.kind === "decision") {
    // A design item's STATE, not its existence. A needle that resolves and a
    // state that was decided are different questions, and only the second one
    // is what a sentence citing the item is entitled to assert.
    if (hits.length === 0) {
      return {
        verdict: MEASURED_ABSENT,
        tree: tree.label,
        dir,
        read: opened,
        detail: `the design item itself is not in that tree — ${seen}`,
      };
    }
    const text = [...new Set(hits.map((h) => h.split(":")[0]))]
      .map((rel) => fs.readFileSync(path.join(dir, rel), "utf8"))
      .join("\n")
      .split("\n")
      .filter((line) => claim.subject.needle.test(line))
      .join("\n");
    for (const [state, re] of Object.entries(claim.subject.states)) {
      if (re.test(text)) return { verdict: FOUND, tree: tree.label, dir, read: opened, state, detail: `${seen}; state: ${state}` };
    }
    return {
      verdict: COULD_NOT_ASK,
      tree: tree.label,
      dir,
      read: opened,
      detail: `${seen}, and none of the state markers [${Object.keys(claim.subject.states).join(", ")}] matched ` +
        `any of them; the item's state cannot be read, which is not the same as the item being open`,
    };
  }

  return hits.length
    ? { verdict: FOUND, tree: tree.label, dir, read: opened, detail: `${seen} — ${hits.slice(0, 4).join(", ")}` }
    : { verdict: MEASURED_ABSENT, tree: tree.label, dir, read: opened, detail: seen };
}

// ── the claims ──────────────────────────────────────────────────────────────
//
// Seeded from the claims that exist today, each MEASURED on 2026-09-20 rather
// than copied from the page that records it. Add a row here and it is checked;
// that is the whole design.
//
// Every row carries:
//   source   the file in THIS repository that makes the claim, and a line
//            pattern that finds the sentence. The pattern is the anchor: a
//            claim reworded out from under its row leaves the row checking
//            nothing, so a source that no longer matches is a failure.
//   expect   `found` or `absent`, asserted in BOTH directions. A reader a row
//            says is absent and which now exists is as much a finding as the
//            reverse — that is how "created disarmed" and "not vendored yet"
//            stop being sentences nobody re-checks.
//   hedge    required on every `absent` row: the pattern in the claim's own
//            sentence that says out loud it is not there yet. This is the half
//            that runs with no foreign checkout, and it is the half that would
//            have caught all five of 2026-09-19's instances.
export const CLAIMS = [
  {
    id: "signed-set/selftest",
    claim: "the signer's selftest reads the signed-set corpus, by importing `loadSignedSetVectors`",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /\|\s*the signer's selftest\s*\|/,
    },
    subject: {
      kind: "code",
      tree: "here",
      under: ["tools/selftest"],
      exts: [".mjs"],
      floorFiles: 10,
      needle: /loadSignedSetVectors/,
    },
    expect: "found",
    why: "the corpus's only live reader. If this goes absent the corpus proves nothing at all, in any repository, " +
      "and the eleven vectors and the closed verdict vocabulary are a file nobody opens",
  },
  {
    id: "signed-set/probe",
    claim: "the ROLL-15 probe is not in this repository and does not read the corpus (RC-R1-7 puts it in " +
      "astra-plugins-ops, unbuilt)",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /\|\s*the ROLL-15 probe\s*\|/,
      hedge: /not yet/,
    },
    subject: {
      kind: "code",
      tree: "here",
      // Everything but the generator, its two READMEs and the one live reader
      // above. The question this row asks is whether a SECOND program in this
      // checkout reads the corpus, so the four files that are already
      // accounted for are not an answer to it.
      under: ["bot", "site", ".github", "tools/probe-signed-set"],
      exts: [".mjs", ".js", ".yml", ".yaml", ".json", ".md"],
      floorFiles: 40,
      // The artifact, for the reason the `signed-set/service` row gives at
      // length: `signed-set` on its own is two different things in two
      // estates, and a needle that cannot tell them apart makes a red row
      // mean nothing.
      needle: /signed-set-v1\.json|signed-set-vectors|signed_set_vectors/,
    },
    expect: "absent",
    why: "the table said this in the present tense and in the wrong repository. A reader consults this table " +
      "before renaming a verdict, and a phantom reader tells them the rename would be caught somewhere it " +
      "would not be",
  },
  {
    id: "signed-set/service",
    claim: "the plugins service does not read the corpus yet, and nothing here knows what commit it would pin",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /\|\s*the plugins service\s*\|/,
      hedge: /not yet/,
    },
    subject: {
      kind: "code",
      tree: "service",
      exts: [".rs", ".ts", ".tsx", ".js", ".mjs", ".py", ".sql", ".toml", ".yaml", ".yml"],
      floorFiles: 200,
      // The ARTIFACT's name, not the concept's. Measured 2026-09-20: a needle
      // of `/signed-set/` returns ten hits in that estate, every one of them
      // `"signed-set document"` — SERVE-50's cap on a blob read from the
      // `signed` branch, which is a different thing wearing the same two
      // words. It resolved FOUND, the row went red, and the reader it sent to
      // go and look was right to go. **A needle that names a concept collides
      // across estates; a needle that names a file does not**, and this table
      // is only worth having if a red row means what it says.
      needle: /signed-set-v1\.json|signed-set-vectors|signed_set_vectors/,
    },
    expect: "absent",
    why: "ROLL-61. The day this goes FOUND, the corpus has a third consumer and the README's `not yet` is a lie " +
      "in the other direction — and whether that consumer reads a pin or a live checkout decides whether the " +
      "corpus's two authors can ever see it disagree with them",
  },
  {
    id: "signed-set/daemon",
    claim: "astra-daemon has not vendored the corpus; `astra-daemon/testdata/signed-set-vectors/` does not exist",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /\|\s*`astra-daemon`\s*\|/,
      hedge: /not yet/,
    },
    subject: {
      kind: "code",
      tree: "astra",
      // Every file the client plan's C1.8 says vendoring the corpus touches,
      // and no other: the directory it creates (named in this row's own claim,
      // one level — the file, `SHA256SUMS`, `SOURCE`), the test in
      // `plugins/trust.rs` that iterates every vector, and the two tests in
      // `consistency.rs` that hold the copy to its sums and to this repository.
      // It walked all of `astra-rs` with a floor of 300 until 2026-09-22.
      paths: [
        "astra-rs/astra-daemon/testdata/signed-set-vectors/",
        "astra-rs/astra-daemon/src/plugins/trust.rs",
        "astra-rs/astra-daemon/src/consistency.rs",
      ],
      // The artifact's name as well as the directory's, as the two rows above
      // have it: files INSIDE the vendored directory name the file they sum,
      // not the directory they are in, so a needle of the directory alone would
      // read a vendored `SHA256SUMS` and come back absent.
      needle: /signed-set-v1\.json|signed-set-vectors|signed_set_vectors/,
    },
    expect: "absent",
    why: "client plan C1.8. This is the instance gap 21 was written about: the file said `vendored`, in the " +
      "present tense, inside the document a reader would check it against",
  },
  {
    id: "av7/daemon-enum",
    claim: "`astra-daemon/src/plugins/trust.rs`'s `RevocationKind` is the authority for the kinds this registry " +
      "may publish",
    source: {
      file: "tools/lib/revocations.mjs",
      line: /RevocationKind` is the authority/,
    },
    subject: {
      kind: "code",
      tree: "astra",
      // The file this row's claim names. tools/revocations/README.md records
      // the enum at `astra-daemon/src/plugins/trust.rs:2818`, measured at Astra
      // `2d68bd6f`. It walked all of `astra-daemon/src` until 2026-09-22.
      paths: ["astra-rs/astra-daemon/src/plugins/trust.rs"],
      needle: /pub enum RevocationKind/,
    },
    expect: "found",
    why: "AV-7. `KINDS` and the literal seven in tools/selftest/revocations.mjs are held against this enum by " +
      "hand. If it moves or is renamed, both are comparing against a memory, and one unknown kind makes the " +
      "daemon refuse the WHOLE withdrawal list — every armed build of that population blocks installs 7 days later",
  },
  {
    id: "av7/daemon-comparison",
    claim: "nothing in Astra compares `RevocationKind` with this repository's `KINDS`; `consistency.rs` does not " +
      "name the enum",
    source: {
      file: "tools/selftest/revocations.mjs",
      line: /`consistency\.rs` does not mention it/,
      hedge: /has not been written/,
      // Prose, not a table: the hedge is two lines further down the same
      // block comment. Three is the reach to the end of that sentence and no
      // further — a window that could touch the next bullet would let one
      // claim borrow another's hedge, which is the defect the zero default
      // exists to stop.
      window: 3,
    },
    subject: {
      kind: "code",
      tree: "astra",
      // The file this row's claim names, and the one the client plan's C1.4
      // puts the comparison in. Already one file; now a list of one.
      paths: ["astra-rs/astra-daemon/src/consistency.rs"],
      needle: /RevocationKind/,
    },
    expect: "absent",
    why: "the client plan's C1.4 is the sibling-checkout pair that would close this. Until it lands, the floor in " +
      "tools/selftest/revocations.mjs is the ONLY thing that notices an eighth key — and the day C1.4 lands this " +
      "row goes red, which is the point: the comment claiming nobody compares them has outlived its truth",
  },
  {
    id: "av7/service-leg",
    claim: "the plugins service has no advisory-kinds reader — not unimplemented, unspecified",
    source: {
      file: "tools/selftest/revocations.mjs",
      line: /the plugins service — no reader/,
      hedge: /no reader/,
    },
    subject: {
      kind: "code",
      tree: "service",
      // Source extensions only, and that is a measured decision rather than
      // tidiness. On 2026-09-20 a needle over the whole tree returned two
      // hits, both prose RECORDING this absence — one in that estate's own
      // memory of gap 21, one in an attack document quoting the register row's
      // name. **A search that matches the documentation of an absence reports
      // the absence as present**, which is this instrument failing in its own
      // subject matter. A reader is code.
      exts: [".rs", ".ts", ".tsx", ".js", ".mjs", ".py", ".sql"],
      floorFiles: 200,
      needle: /advisory_kind|RevocationKind|revocation_kind|AV-7/,
    },
    expect: "absent",
    why: "AV-7's third leg. A register row saying this coupling is watched tells whoever adds a kind that the " +
      "rename would be caught over there; there is no over there",
  },
  {
    id: "security/not-after-cutoff",
    claim: "no delegated index key carries a `not_after`, so a compromise is cut off by a trust.json that DROPS " +
      "the key and never by an expiry",
    source: {
      file: "SECURITY.md",
      line: /stop accepting anything the old key signs/,
      hedge: /carries no `not_after`/,
      window: 6,
    },
    subject: {
      kind: "code",
      tree: "here",
      under: ["registry/v1/trust.json"],
      exts: [".json"],
      floorFiles: 1,
      needle: /"not_after"/,
    },
    expect: "absent",
    why: "§5.1 step 1 promised a cut-off nobody could perform: it told an operator to wait out a field that is " +
      "not in the document. This row is also the re-read RC-RN-1 owes — the 2027 renewal ceremony adds a " +
      "`not_after` for `astra-index-2026a` (ROLL-45), and on the day it appears this goes FOUND and red, which " +
      "is the whole difference between a check and a promise to look again later",
  },
  {
    id: "revocations/five-enforcement-points",
    claim: "the daemon enforces the withdrawal list at five places, the fifth being the resolved `entry.command` " +
      "binary that a sideloaded directory is caught by",
    source: {
      file: "tools/revocations/README.md",
      line: /the daemon has five places/,
    },
    subject: {
      kind: "code",
      tree: "astra",
      // The two files the withdrawal list is enforced in, as the contract and
      // the client plan cite them: `plugins/trust.rs` holds the list, its
      // freshness rule and the subject an entry is matched against (a
      // sideload's among them), and `plugins/manager.rs` the call sites — the
      // stale-list block on install and update, `refresh_revocations`, the
      // sideload path. The README this row anchors in says only "five times
      // under `astra-daemon/src/plugins/`", which is a directory of files
      // nobody chose. It walked all of `astra-daemon/src` until 2026-09-22.
      paths: [
        "astra-rs/astra-daemon/src/plugins/trust.rs",
        "astra-rs/astra-daemon/src/plugins/manager.rs",
      ],
      needle: /five enforcement points/,
    },
    expect: "found",
    why: "this README tells an author that a `digest`-only advisory has a hole and which kind closes it. The " +
      "number is the daemon's, and if the daemon ever stops enumerating five, the advice here is advice about a " +
      "program that no longer exists — and the reader it misleads is writing a withdrawal during an incident",
  },
  {
    id: "d10/compromise-half",
    // DECIDED on 2026-09-23 — D10 as proposed, by the coordinator at the
    // owner's delegation, published as contract 0.38.0's SERVE-30 — and the
    // runbook's §5.5 now writes it as the procedure. Until then this row held
    // the runbook to a hedge (`proposal`, `has not answered`, `awaiting the
    // owner`) because the item was OPEN; the row now asserts the other
    // direction: that the plan's status row says DECIDED, so a runbook that
    // prints D10 as the procedure is reading a decision and not a guess. If
    // the item is ever reopened the plan's row says so, this row goes red, and
    // the hedge comes back with the state.
    claim: "OPEN-OWNER-25's compromise half is DECIDED as D10, so the rotation section may write D10 as the " +
      "compromise procedure",
    source: {
      file: "docs/RUNBOOK.md",
      line: /OPEN-OWNER-25/,
    },
    subject: {
      kind: "decision",
      tree: "ops",
      under: ["dev/server-registry-plan-registry.md"],
      exts: [".md"],
      floorFiles: 1,
      // The STATUS row's own spelling, and nothing else in the plan. Fourteen
      // other lines name this item — an exit need, a version-schedule row, a
      // task's ID list — and one of them reads `compromise half answered`
      // while describing what R1 must reach, not what is true today. A state
      // read off prose about the item is a state read off somebody's plan for
      // it, so this needle matches the one line that IS the status.
      needle: /\*\*OPEN-OWNER-25, compromise half: [A-Z]+\*\*/,
      // Read in this order; the first that matches wins, so the decided
      // spellings come first and `open` cannot win by being looser. None
      // matching is COULD NOT ASK, not `open`: an item whose state cannot be
      // read is not an item that was left open, and the two need opposite
      // acts — one waits on a person, the other on a reader that has stopped
      // matching the document.
      states: {
        answered: /compromise half: (ANSWERED|CLOSED|DECIDED)\*\*/,
        withdrawn: /compromise half: WITHDRAWN\*\*/,
        open: /compromise half: OPEN\*\*/,
      },
    },
    expect: "found",
    expectState: "answered",
    why: "this is the kind of false claim that never decays, because it was never true. Until 2026-09-23 D10 was a " +
      "proposal and a runbook that printed it as the compromise procedure presented a decision as an outcome; from " +
      "then it is the procedure, and a runbook still hedging it would send an operator mid-incident looking for an " +
      "answer that exists. Only reading the decision tells the two apart",
  },
  {
    id: "bound/current-bytes",
    claim: "NOT checked here: that a reader this instrument FOUND reads the CURRENT bytes",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /at a commit it will pin/,
    },
    subject: {
      kind: "bound",
      statement:
        "a found reader may be reading a vendored copy from any day, or a live checkout of any commit. Nothing " +
        "in this repository pins any foreign tree, so this instrument can say a reader EXISTS and can never say " +
        "it is in step. That is closed by a pin — ROLL-61 for the service, C1.8's re-vendor for the daemon — and " +
        "not by anything on this line. It is printed every run so it is never read as coverage",
    },
    expect: "out-of-scope",
    why: "a permanent bound, and permanently stated. The alternative is a green row that a reader takes for a " +
      "freshness check somebody already built",
  },
];

/** The four verdicts a table resolves to, in the order they are printed. */
export function resolveAll(claims = CLAIMS) {
  return claims.map((c) => ({ claim: c, ...resolve(c) }));
}

/**
 * The claim's own sentence, as it stands in the file that makes it — each
 * matching line together with the `window` lines after it.
 *
 * **The window defaults to ZERO, and that default was measured rather than
 * chosen.** It was 3, on the reasoning that a claim in prose is a paragraph
 * and the hedge belongs wherever the author put it. Then the canary for the
 * `signed-set/probe` row — restore the false present-tense row and watch the
 * suite go red — came back GREEN. In a markdown table the rows are adjacent
 * LINES, so a three-line window read the NEXT ROW's `**not yet**` and greened
 * the unhedged one above it. A hedge borrowed from the row below is the
 * instrument doing the thing it exists to catch, and it was invisible until a
 * canary was watched rather than assumed.
 *
 * So: zero by default, which is exactly right for a table row, and a `window`
 * stated per row where the claim really is a paragraph — never wide enough to
 * reach a neighbouring claim.
 */
export function sourceLines(claim, root = REPO_ROOT) {
  const file = path.join(root, claim.source.file);
  if (!fs.existsSync(file)) return null;
  const all = fs.readFileSync(file, "utf8").split("\n");
  const window = claim.source.window ?? 0;
  const out = [];
  all.forEach((line, i) => {
    if (claim.source.line.test(line)) out.push(all.slice(i, i + 1 + window).join("\n"));
  });
  return out;
}

export async function run() {
  console.log("\nclaims about readers in other repositories");

  const resolved = resolveAll();

  // The transcript, before any assertion, because two of the four verdicts are
  // never a pass and never a red and a printed line is the only place they can
  // live. A run that says nothing about what it could not ask is a run whose
  // silence reads as coverage.
  //
  // ── and it is CAPTURED, because nothing used to read it ────────────────────
  //
  // The check below is named "OUT OF SCOPE is printed, is never a pass, and is
  // never counted as checked", and until 2026-09-22 its first clause was
  // asserted by nothing: the printing happens here, before any `test()` runs,
  // and the body only inspected the in-memory `resolved` array. Measured — a
  // `continue` on OUT_OF_SCOPE in this loop plus the deletion of the summary's
  // out-of-scope clause made the permanent bound completely invisible in the
  // run, and the suite came back 317 passed, 0 failed, exit 0, with the check
  // still printing `ok`. The paragraph above says a printed line is the only
  // place these verdicts can live; it was the one thing nobody checked.
  //
  // `console.log` is wrapped rather than a second array being built beside the
  // printing, and that distinction is the whole repair. An array appended to
  // next to each `console.log` is two statements that can be separated, and the
  // check would then be asserting that the ARRAY was built — which is what it
  // was already doing wrong, one level down. What is asserted has to be what
  // reached stdout.
  const printed = [];
  const counted = (v) => resolved.filter((r) => r.verdict === v).length;
  {
    const realLog = console.log;
    console.log = (...args) => { printed.push(args.map(String).join(" ")); realLog(...args); };
    try {
      for (const r of resolved) {
        console.log(`        ${r.verdict.padEnd(15)} ${r.claim.id}`);
        console.log(`                        tree: ${r.tree}`);
        // What the row walks, on every run and whatever the verdict, so a
        // transcript says what a machine WITH the tree would have opened; and,
        // for a listed row, what this one did open.
        if (r.claim.subject.kind !== "bound") {
          console.log(`                        walk: ${describeWalk(r.claim.subject)}`);
        }
        if (r.claim.subject.paths) {
          console.log(`                        read: ${r.read?.length ? r.read.join(", ") : "nothing"}`);
        }
        console.log(`                        ${r.detail}`);
      }
      // One line with the four numbers a shrunken run changes: how many rows
      // there are, how many were resolved, how many could not be asked, and
      // the floor the second is held to. Gap 24: the old line had the verdict
      // counts and no denominator and no floor, so `1 found` read the same
      // whether the table asked three questions or eleven.
      console.log(
        `        — ${resolved.length} row(s): ${counted(FOUND) + counted(MEASURED_ABSENT)} resolved ` +
        `(${counted(FOUND)} found, ${counted(MEASURED_ABSENT)} measured absent), ` +
        `${counted(COULD_NOT_ASK)} could not ask, ${counted(OUT_OF_SCOPE)} out of scope (never checked, never fixed); ` +
        `resolved floor ${RESOLVED_FLOOR}`,
      );
    } finally {
      console.log = realLog;
    }
  }

  await test("the claims table has a floor, unique ids, and a well-formed row for each", () => {
    // The floor on the TABLE, for the reason every enumerating check in this
    // repository states one: an empty table agrees with everything. Nine on
    // 2026-09-20; the floor is 6, so retiring a claim whose subject is gone is
    // an ordinary act and does not put the next author in front of a red check
    // with one keystroke between them and zero.
    assert(CLAIMS.length >= 6,
      `the claims table holds ${CLAIMS.length} row(s) and held 9 on 2026-09-20; this is a table that has been ` +
      `emptied rather than a repository with fewer cross-repository claims`);

    const twice = CLAIMS.map((c) => c.id).filter((id, i, a) => a.indexOf(id) !== i);
    assertEqual([...new Set(twice)].join(", "), "", "two claims share an id, so one of them is invisible in the transcript");

    const bad = [];
    for (const c of CLAIMS) {
      if (!["found", "absent", "out-of-scope"].includes(c.expect)) bad.push(`${c.id}: expect is ${c.expect}`);
      if (!c.why) bad.push(`${c.id}: no \`why\`, so a reader of a red row cannot tell what it costs to ignore it`);
      // The hedge is REQUIRED on every `absent` row and forbidden as a
      // decoration on the others: it is the assertion that this repository's
      // own sentence admits the reader is not there. Without it the row would
      // pass while the document went on claiming the reader in the present
      // tense — which is every one of 2026-09-19's five instances.
      if (c.expect === "absent" && !c.source.hedge) bad.push(`${c.id}: an \`absent\` claim with no \`hedge\` pattern`);
      if (c.subject.kind === "decision" && !c.expectState) bad.push(`${c.id}: a decision row with no \`expectState\``);
      if (c.expectState === "open" && !c.source.hedge) bad.push(`${c.id}: an \`open\` decision with no \`hedge\` pattern`);
      // A hedge satisfied by the citation itself asserts nothing. `/open/i`
      // against a sentence whose only content is `OPEN-OWNER-25` is the
      // measured case, and it would have made this row green while the
      // runbook printed an undecided procedure as the procedure.
      if (c.source.hedge && c.source.hedge.test(c.id)) bad.push(`${c.id}: the hedge matches the claim's own id`);
    }
    assertEqual(bad.join("; "), "", "a row in the claims table cannot be resolved");
  });

  await test("every claim's own sentence is still in the file that makes it", () => {
    // The anchor. A claim reworded, moved or deleted out from under its row
    // leaves the row checking a foreign tree for a sentence nobody makes any
    // more — searching, passing, and about nothing. This is the failure a
    // requirement id in place of a search has by construction, and the reason
    // the row carries the literal pattern.
    const orphaned = [];
    for (const c of CLAIMS) {
      const lines = sourceLines(c);
      if (lines === null) orphaned.push(`${c.id}: ${c.source.file} is not in this repository`);
      else if (lines.length === 0) orphaned.push(`${c.id}: nothing in ${c.source.file} matches ${c.source.line}`);
    }
    assertEqual(orphaned.join("; "), "",
      "a claims row has lost the sentence it is about; either restore the sentence or retire the row, and do not " +
      "leave a row that searches another repository on behalf of nobody");
  });

  await test("a claim whose expected state is `absent` says so in its own sentence (the half that needs no checkout)", () => {
    // This is the whole of gap 21 caught from inside one repository, and it is
    // the only part of this module that runs in registry CI. Every one of
    // 2026-09-19's five instances was a sentence in the PRESENT TENSE about a
    // thing that was not there — so the sentence is what is asserted, and no
    // second checkout is needed to assert it.
    const unhedged = [];
    for (const c of CLAIMS) {
      // `absent` rows, and decision rows whose expected state is `open` —
      // which is the same defect in the tense that never decays. A sentence
      // citing an undecided item as though it were decided was false the
      // moment it was typed, so the sentence is where it has to be caught.
      const mustHedge = c.expect === "absent" || c.expectState === "open";
      if (!mustHedge) continue;
      const lines = sourceLines(c) ?? [];
      if (!lines.some((l) => c.source.hedge.test(l))) {
        unhedged.push(`${c.id} — ${c.source.file}: ${JSON.stringify(lines[0] ?? "(no line)")}`);
      }
    }
    assertEqual(unhedged.join("; "), "",
      "this repository states in the PRESENT TENSE that a reader in another repository exists, and the measured " +
      "answer is that it does not. That sentence is not a stale note: it tells the next person to rename the " +
      "thing that the rename would be caught over there, and it would not be. Hedge the sentence or build the " +
      "reader");
  });

  await test("every measurable claim matches its expected state, in BOTH directions", () => {
    const wrong = [];
    for (const r of resolved) {
      if (r.verdict === COULD_NOT_ASK || r.verdict === OUT_OF_SCOPE) continue;
      const want = r.claim.expect === "found" ? FOUND : MEASURED_ABSENT;
      if (r.verdict !== want) {
        wrong.push(
          `${r.claim.id}: expected ${want}, measured ${r.verdict} in ${r.tree} — ${r.detail}. ${r.claim.why}`,
        );
        continue;
      }
      if (r.claim.expectState && r.state !== r.claim.expectState) {
        wrong.push(
          `${r.claim.id}: the design item is there and its state is ${JSON.stringify(r.state)}, and this ` +
          `repository's sentence is written for ${JSON.stringify(r.claim.expectState)} — ${r.claim.why}`,
        );
      }
    }
    assertEqual(wrong.join("\n  "), "", "a claim about another repository does not match that repository");
  });

  await test("this run resolved at least RESOLVED_FLOOR rows, and one printed line says rows, resolved, could not ask and the floor", () => {
    // Gap 24. COULD NOT ASK stays a statement and never a red; what is red is
    // the COUNT of rows that were answered falling below the count the poorest
    // runner answers. See RESOLVED_FLOOR for why 3, why a floor, and why it is
    // raised by hand.
    const answered = resolved.filter((r) => r.verdict === FOUND || r.verdict === MEASURED_ABSENT);
    const unasked = resolved.filter((r) => r.verdict === COULD_NOT_ASK);
    if (answered.length < RESOLVED_FLOOR) {
      // Name the row. A number alone says a row was lost and not which, so the
      // rows that should have answered are listed first: those about THIS
      // checkout, which every runner has, and those whose tree was found and
      // still could not be asked. Either is a renamed input, a broken walk or a
      // runner without `git` — never a missing private checkout.
      const shouldHave = (r) => r.claim.subject.tree === "here" || Boolean(r.dir);
      const lost = unasked.filter(shouldHave).map((r) => `${r.claim.id} — ${r.detail}`);
      const elsewhere = unasked.filter((r) => !shouldHave(r)).map((r) => `${r.claim.id} — ${r.detail}`);
      throw new Error(
        `this run resolved ${answered.length} of ${resolved.length} claims row(s) and the committed floor is ` +
        `${RESOLVED_FLOOR}, so ${RESOLVED_FLOOR - answered.length} row(s) that registry CI answers went unasked and ` +
        `the transcript only said so quietly.\n` +
        `  rows about a tree this run HAD, and could not ask:\n    ${lost.join("\n    ") || "(none)"}\n` +
        `  rows about a tree this run did not have:\n    ${elsewhere.join("\n    ") || "(none)"}\n` +
        `If the loss is deliberate — a row about this checkout retired, or moved to a tree registry CI does not ` +
        `check out — lower RESOLVED_FLOOR in tools/selftest/claims.mjs to ${answered.length} in the SAME commit`,
      );
    }
    // The line, asserted against what reached stdout and written out here
    // rather than rebuilt by the code that prints it, so dropping a clause from
    // the printer is red rather than agreed with. The row count is the TABLE's,
    // not the resolved array's: a resolveAll() that lost a row would print its
    // own smaller denominator and agree with itself.
    const want = [
      `${CLAIMS.length} row(s):`,
      `${answered.length} resolved`,
      `${unasked.length} could not ask`,
      `resolved floor ${RESOLVED_FLOOR}`,
    ];
    assert(printed.some((l) => want.every((w) => l.includes(w))),
      `no line of this run's transcript carries all of ${JSON.stringify(want)}; an empty or shrunken run is ` +
      `only visible if one line says how many rows there are, how many were answered and what they are held ` +
      `to. The summary this run wrote was: ` +
      `${JSON.stringify(printed.filter((l) => l.includes("could not ask"))[0] ?? "(no summary line at all)")}`);
  });

  await test("COULD NOT ASK is not NO COVER: an unreadable tree never resolves to MEASURED ABSENT", () => {
    // The defect one level up, and the reason this verdict exists at all. A
    // sibling checkout goes missing, a path moves, an extension list outlives
    // its language — and a grep that matched nothing because it opened nothing
    // becomes a confident absence. Watched here rather than hoped for, in all
    // three of the ways it can happen.
    const base = {
      id: "synthetic", claim: "x", why: "x", expect: "absent",
      source: { file: "tools/selftest.mjs", line: /MODULES/, hedge: /./ },
    };

    const noTree = resolve({ ...base, subject: { kind: "code", tree: "nowhere", needle: /x/ } });
    assertEqual(noTree.verdict, COULD_NOT_ASK, "an undeclared tree resolved to something other than COULD NOT ASK");

    // A tree that is DECLARED and whose checkout is not on this machine —
    // which is every foreign row of the real table in registry CI, and is
    // therefore the state this module spends most of its life in.
    const absentTree = {
      gone: { label: "a repository nobody has here", env: "ASTRA_NO_SUCH_DIR", siblings: ["../no-such-checkout"], probe: "Cargo.toml" },
    };
    const noCheckout = resolve({ ...base, subject: { kind: "code", tree: "gone", needle: /x/ } }, absentTree);
    assertEqual(noCheckout.verdict, COULD_NOT_ASK, "a tree with no checkout must not resolve to an absence");
    assert(noCheckout.detail.includes("no checkout") && noCheckout.detail.includes("no-such-checkout"),
      "a skip has to NAME what it did not read, or it reads as a pass in a wall of green");

    // The probe file is what separates a checkout from a directory with the
    // right name. Pointed at this repository while asking for Astra's
    // `Cargo.toml`, the answer must still be COULD NOT ASK — otherwise a
    // mistyped env var searches the wrong tree and reports a confident
    // absence about the right one.
    const wrongTree = {
      astra: { label: "Astra", env: "ASTRA_NO_SUCH_DIR", siblings: ["."], probe: "astra-rs/Cargo.toml" },
    };
    assertEqual(resolve({ ...base, subject: { kind: "code", tree: "astra", needle: /x/ } }, wrongTree).verdict,
      COULD_NOT_ASK,
      "a directory without the tree's probe file was accepted as that tree, so the search ran somewhere else and " +
      "its answer would have been reported about the tree it never opened");

    // A tree that IS there, whose walk falls below its floor. This is the
    // subtle one: `git ls-files` succeeded, the directory is a real checkout,
    // and the filter matched nothing — so the needle would have searched zero
    // files and come back empty, which is indistinguishable from an answer.
    const brokenWalk = resolve({
      ...base,
      subject: {
        kind: "code",
        tree: "here",
        under: ["tools/selftest"],
        exts: [".this-extension-does-not-exist"],
        floorFiles: 10,
        needle: /anything/,
      },
    });
    assertEqual(brokenWalk.verdict, COULD_NOT_ASK,
      "a walk below its floor resolved to an absence; it is a broken walk, and reporting it as an absence is " +
      "exactly the confident-absence-about-a-tree-nobody-opened this instrument exists to catch");
    assert(brokenWalk.detail.includes("broken walk"), "the message must say which of the two it is");

    // And the floor is a floor rather than a formality: the same walk with a
    // floor it can meet answers the question instead of refusing it.
    //
    // The needle is ASSEMBLED rather than written, and that is not cleverness.
    // Written as a literal it appeared in this file, which is under
    // `tools/selftest/` — so the moment this module was committed and `git
    // ls-files` began returning it, the search found itself and the canary
    // came back FOUND. It was green for as long as the file was untracked and
    // red on the first run after the commit, which is the most useful way that
    // failure could possibly have arrived. `isSuiteFile` in harness.mjs exists
    // for the same reason: the file that states a rule is not an instance of
    // it. (`SELF` now keeps this file out of every walk of this checkout, since
    // a real row had the same defect; the needle stays assembled so that this
    // canary does not depend on the fix it would be checking.)
    const absentToken = new RegExp(["no", "such", "token", "in", "this", "tree"].join("-"));
    const realWalk = resolve({
      ...base,
      subject: { kind: "code", tree: "here", under: ["tools/selftest"], exts: [".mjs"], floorFiles: 10, needle: absentToken },
    });
    assertEqual(realWalk.verdict, MEASURED_ABSENT,
      "a walk that met its floor and matched nothing is an ANSWER, and refusing to give it would make the floor " +
      "a way of never concluding anything");
  });

  await test("OUT OF SCOPE is printed, is never a pass, and is never counted as checked", () => {
    // A permanent bound is not a to-do and not coverage. Both collapses cost
    // something specific: read as COULD NOT ASK it becomes a task nobody can
    // ever complete, and read as FOUND it becomes a check somebody thinks
    // exists.
    const bounds = resolved.filter((r) => r.verdict === OUT_OF_SCOPE);
    assert(bounds.length >= 1,
      "no row states a permanent bound. This instrument has at least one — it can say a foreign reader EXISTS " +
      "and can never say it reads the current bytes — and an unstated bound is read as coverage");
    for (const b of bounds) {
      assertEqual(b.claim.expect, "out-of-scope", `${b.claim.id} resolved OUT OF SCOPE without declaring it`);
      assert(b.detail && b.detail.length > 40,
        `${b.claim.id}: a bound with no statement is a silence, which is the thing it is here to prevent`);
      // `is printed`, the first clause of this name, asserted against what this
      // run actually wrote to stdout. Not against `resolved`, which is what it
      // used to do and which is true whether or not a single line was emitted.
      assert(printed.some((l) => l.includes(OUT_OF_SCOPE) && l.includes(b.claim.id)),
        `${b.claim.id} resolved OUT OF SCOPE and no line of this run's transcript says so. A bound that is not ` +
        `printed is a bound nobody can read, and a run whose silence about it reads as coverage is the failure ` +
        `this verdict exists to prevent`);
      assert(printed.some((l) => l.includes(b.detail)),
        `${b.claim.id}: the bound's STATEMENT never reached stdout, so the transcript names a bound and does not ` +
        `say what it bounds — which is the collapse into COULD NOT ASK wearing the right label`);
    }
    // And the summary line carries the count with the words that keep it out of
    // both collapses. Deleting the clause is the cheapest way to make a
    // permanent bound invisible while every row below still prints `ok`.
    assert(
      printed.some((l) => l.includes(`${counted(OUT_OF_SCOPE)} out of scope (never checked, never fixed)`)),
      `the summary line does not state ${counted(OUT_OF_SCOPE)} out of scope (never checked, never fixed); a ` +
      `count printed without those words is read as a to-do on one side and as coverage on the other, and the ` +
      `transcript this run wrote was: ${JSON.stringify(printed.filter((l) => l.includes("found,"))[0] ?? "(no summary line at all)")}`,
    );
    // And it is excluded from the counts the line above prints, so "3 found"
    // never quietly includes a row that checks nothing.
    const checkable = resolved.filter((r) => r.verdict === FOUND || r.verdict === MEASURED_ABSENT);
    assert(!checkable.some((r) => r.claim.expect === "out-of-scope"),
      "a bound was counted among the rows that were measured");
  });

  await test("a decision row reads the item's STATE, and an unreadable state is not `open`", () => {
    // "A section number that resolves is not a section number that was
    // decided." The first kind of false claim decays and re-measurement finds
    // it; this kind was never true, so the only thing that finds it is reading
    // what was decided. Three synthetic decisions, one per outcome.
    const base = {
      id: "synthetic-decision", claim: "x", why: "x", expect: "found", expectState: "open",
      source: { file: "tools/selftest.mjs", line: /MODULES/ },
    };
    const subject = (states) => ({
      kind: "decision",
      tree: "here",
      under: ["tools/selftest.mjs"],
      exts: [".mjs"],
      floorFiles: 1,
      needle: /const MODULES = \[/,
      states,
    });

    const open = resolve({ ...base, subject: subject({ answered: /never-appears/, open: /const MODULES/ }) });
    assertEqual(open.verdict, FOUND, "a decision whose item is present must resolve FOUND");
    assertEqual(open.state, "open", "the state a marker matched was not reported");

    // The order is load-bearing: `answered` is asked first, so an item that
    // has been decided cannot be reported as open by a looser fallback.
    const answered = resolve({ ...base, subject: subject({ answered: /const MODULES/, open: /const MODULES/ }) });
    assertEqual(answered.state, "answered", "a decided item was reported as open by the fallback marker");

    // No marker matched. Not `open` — the item's state could not be read, and
    // the two need opposite acts: one is waiting on somebody, the other is a
    // reader that has stopped matching the document.
    const unreadable = resolve({ ...base, subject: subject({ answered: /never-appears/, open: /never-either/ }) });
    assertEqual(unreadable.verdict, COULD_NOT_ASK,
      "a design item whose state markers all missed was reported as a state; an unreadable state is not `open`");
    assert(unreadable.detail.includes("not the same as the item being open"),
      "the message must separate `nobody has decided` from `this reader cannot tell`");

    // And the item not being in the tree at all is an absence rather than an
    // unreadable state, because those need opposite fixes too.
    const gone = resolve({
      ...base,
      subject: { ...subject({ open: /x/ }), needle: /no-such-decision-id-anywhere/ },
    });
    assertEqual(gone.verdict, MEASURED_ABSENT, "a cited design item that is not in the tree must be an absence");
  });

  await test("a tree read only through a list is read through a list: non-empty, no root, no prefix walk, and a directory only where its claim names it", () => {
    // Entry 84 of `O:dev/couplings.md`. Four rows walked `astra-rs` or
    // `astra-rs/astra-daemon/src` whole whenever `../Astra` resolved, which it
    // does in any checkout that has the daemon beside it, and those roots hold
    // paths the people running this suite may not read. Nothing said so: the
    // rows were COULD NOT ASK in CI, and on a laptop they were green.
    //
    // Asked of the TABLE, so a widened row is red here in registry CI, which
    // has no Astra — not only on the machine where widening it does the harm.
    const listedTrees = Object.entries(TREES).filter(([, t]) => t.onlyListedPaths).map(([k]) => k);
    assert(listedTrees.includes("astra"),
      "TREES.astra no longer declares `onlyListedPaths`, so its rows may walk it from a prefix again and nothing " +
      "below applies to them. The daemon tree is read through a list; see this module's header for why");
    const rows = CLAIMS.filter((c) => listedTrees.includes(c.subject.tree));
    // Not vacuous: four rows on 2026-09-22. One is enough to be a question;
    // retiring them all is an ordinary act and leaves this with nothing to ask,
    // which it says rather than passing.
    assert(rows.length >= 1,
      `no row of the claims table is about a tree read only through a list (${listedTrees.join(", ")}), so this ` +
      `check has nothing to hold — retire it with the last such row rather than leave it green over nothing`);
    const bad = rows.flatMap((c) => listProblems(c, TREES[c.subject.tree]).map((p) => `${c.id} ${p}`));
    assertEqual(bad.join("; "), "",
      "a row about a tree that is read only through a list would walk more than its claim is about. Give it the " +
      "files its claim names in `paths`, and a directory only where the claim names that directory; never a " +
      "prefix, and never the tree's root");
  });

  await test("the list is all git is asked for: a file is itself, a directory is one level, a stale list is not an answer, and a prefix row opens nothing", () => {
    // The check above holds the TABLE; this holds the WALKER, on a tree built
    // for it, because the table only ever exercises the shapes it happens to
    // hold. Every file that must not be read carries the needle, so a walker
    // that read one says FOUND where the answer is MEASURED ABSENT.
    const root = path.join(tmp, "claims-listed-tree");
    fs.rmSync(root, { recursive: true, force: true });
    const put = (rel, text) => {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.writeFileSync(path.join(root, rel), text);
    };
    put("ws/Cargo.toml", "[workspace]\n");
    put("ws/crate/src/listed.rs", "nothing here\n");
    put("ws/crate/src/beside.rs", "NEEDLE in a file beside the listed one\n");
    put("ws/crate/src/nested/deeper.rs", "NEEDLE one level below the directory\n");
    put("ws/crate/data/named/top.txt", "nothing here either\n");
    put("ws/crate/data/named/sub/under.txt", "NEEDLE in a subdirectory nobody listed\n");
    execFileSync("git", ["-C", root, "init", "-q"], { stdio: "ignore" });
    execFileSync("git", ["-C", root, "add", "-A"], { stdio: "ignore" });

    const trees = {
      fixture: { label: "a listed fixture", env: null, siblings: [root], probe: "ws/Cargo.toml", onlyListedPaths: true },
    };
    // The claim names the ROOT too, so that the root case at the end is
    // refused by the root rule alone and not also by "the claim does not name
    // it".
    const row = (subject) => ({
      id: "synthetic-listed",
      claim: "x `ws/`, `crate/data/named/` and `crate/data/named/sub/`",
      why: "x",
      expect: "absent",
      source: { file: "tools/selftest.mjs", line: /MODULES/, hedge: /./ },
      subject: { kind: "code", tree: "fixture", needle: /NEEDLE/, ...subject },
    });
    const asked = (subject) => resolve(row(subject), trees);

    // A file is itself — not the file beside it, which shares its directory
    // and carries the needle.
    const file = asked({ paths: ["ws/crate/src/listed.rs"] });
    assertEqual(`${file.verdict} ${JSON.stringify(file.read)}`, `${MEASURED_ABSENT} ["ws/crate/src/listed.rs"]`,
      `a listed file read something besides itself: ${file.detail}`);

    // A directory is one level: its own files, and not a subdirectory's.
    const dir = asked({ paths: ["ws/crate/data/named/"] });
    assertEqual(`${dir.verdict} ${JSON.stringify(dir.read)}`, `${MEASURED_ABSENT} ["ws/crate/data/named/top.txt"]`,
      `a listed directory was read below its own level: ${dir.detail}`);
    // ...unless the subdirectory is listed by name, which is how a row reads
    // one — and the answer changes, which is what shows the level was real.
    const named = asked({ paths: ["ws/crate/data/named/", "ws/crate/data/named/sub/"] });
    assertEqual(named.verdict, FOUND, `a subdirectory listed by name was not read: ${named.detail}`);

    // A file entry that is really a directory lists NOTHING. A bare pathspec
    // matches as a leading directory, so without the exclusion git would
    // print the subtree's names; the message must name the entry and none of
    // them.
    const dirAsFile = asked({ paths: ["ws/crate/src"] });
    assertEqual(dirAsFile.verdict, COULD_NOT_ASK, `a file entry that is a directory was walked: ${dirAsFile.detail}`);
    assert(dirAsFile.detail.includes("does not track as a file") && !/beside|listed\.rs|deeper/.test(dirAsFile.detail),
      `a file entry that is a directory must list nothing and be reported as missing, and this said: ${dirAsFile.detail}`);

    // A stale list — one file of two gone — is not an absence over the other.
    // The floor of one file would be met, so only the list's own floor says so.
    const stale = asked({ paths: ["ws/crate/src/listed.rs", "ws/crate/src/moved-away.rs"] });
    assertEqual(stale.verdict, COULD_NOT_ASK, `a list that lost a file answered from the rest of it: ${stale.detail}`);
    assert(stale.detail.includes("ws/crate/src/moved-away.rs") && stale.detail.includes("stale list"),
      `the refusal must name the file the list lost: ${stale.detail}`);

    // A prefix row is refused before the tree is located: no `dir`, nothing
    // read, and the tree IS there with the needle in it, so a walk would have
    // said FOUND.
    const prefix = asked({ under: ["ws"], exts: [".rs"] });
    assertEqual(`${prefix.verdict} ${prefix.dir ?? null} ${JSON.stringify(prefix.read ?? null)}`, `${COULD_NOT_ASK} null []`,
      `a prefix row on a tree read only through a list was walked: ${prefix.detail}`);
    assert(prefix.detail.includes("nothing was opened"), `the refusal must say nothing was opened: ${prefix.detail}`);

    // And the directory above the probe, written as a directory and named by
    // the claim, is refused the same way: a claim cannot name its way to the
    // whole tree.
    const whole = asked({ paths: ["ws/"] });
    assertEqual(`${whole.verdict} ${whole.dir ?? null}`, `${COULD_NOT_ASK} null`,
      `the directory above the tree's probe was accepted as a listed directory: ${whole.detail}`);
    assert(whole.detail.includes("a directory above ws/Cargo.toml"),
      `the refusal must say it is the tree's root or above its probe: ${whole.detail}`);
  });
}
