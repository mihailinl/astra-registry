// Every entry in the registry's tree is a regular file or a directory, as git
// reads it, and nothing else.
//
// **What this closes.** The plugins service's mirror_index review (2026-10-03)
// found its mirror and this repository's loaders reading a symlink under a
// record path differently: `plugins/<id>/identity.json -> sub/../x.json`
// where `sub` is itself a link, `x/` with a trailing slash on a file, and
// `policy/binding-deadline.json` or `log/cutover.json` reached through `..`
// after a link. The mirror resolved lexically; the loaders here run on a
// checkout and the kernel resolves for them. Two readers of one commit then
// read two different files and both believe they read the record. Agreeing on
// a resolution rule would be a second contract nobody can test exhaustively,
// so neither side resolves: the registry refuses the link before it reaches
// `main`, and a reader that meets one anyway refuses the record.
//
// Until this, a link was refused only where a loader happened to ask the
// filesystem about it: `tools/lib/sources.mjs`'s `dirent` check directly
// under `plugins/` and `publishers/`, and an `isFile()` in `versions/`,
// `state/queue/`, `state/alerts/` and the decision log. Everywhere else it
// was read straight through — `plugins/<id>/plugin.json` and
// `identity.json`, `policy/`, `log/`'s markers, `bot/moderation/` — and a
// link to a directory higher up was followed by every one of them. TRUST-31's
// canary in `bot/tests/code-paths.test.mjs` refuses links, gitlinks and
// non-canonical modes under its own entries only.
//
// **Read from git, never from the filesystem.** A gitlink checks out as an
// EMPTY directory, so a walk of a checkout sees a directory where git sees a
// submodule; a directory spelled `140000` in a raw tree is a gitlink to git
// (`canon_mode` reads any mode that is not a file, a link or a directory as
// one) and a tree to a reader that classifies by type bits (gix 0.64,
// minice-e4's 0050 review, 2026-09-27). `git ls-tree` prints git's canonical
// mode, so `-r -t -z --full-tree` at a commit is the one listing every party
// can reproduce: `-r` enters every directory, `-t` lists the directories
// themselves, a link or a gitlink is listed and never entered, and `-z` keeps
// a path with a newline or a tab one row. The whole tree, and not a list of
// record roots: a rule that names roots is a rule that has to be told about
// the next one, and on `main` at e85403b the whole tree is 917 entries, every
// one `100644`, `100755` or `040000`, with no link or gitlink anywhere in its
// history, so the wider rule refuses nothing that exists.
//
// **An empty directory is refused too.** The service found the second half
// the same day: a tree holding nothing, or only trees that hold nothing, is
// invisible to `git rev-list -- <path>` (git's diff emits leaves only, so the
// commit that adds it is TREESAME), to `git diff --name-only`, to
// `ls-tree -r` without `-t`, and to a checkout, which creates no directory
// for it — while a reader that walks trees, or compares tree ids, sees it.
// Every tool here is on the leaf side (DEC-9's serials, the withdrawal list's
// pending count, detector A, TRUST-31's set hash), so each of them reads such
// a commit as no change at all while the service's mirror reads a change.
// Refusing the tree is what makes the two answers one.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { pathToFileURL } from "node:url";

import { cleanEnv } from "./git-env.mjs";

/** The modes an entry may have, as `git ls-tree` prints them, and what each is. */
export const ACCEPTED_MODES = Object.freeze({
  "100644": "a regular file",
  "100755": "an executable regular file",
  "040000": "a directory",
});

/** What git means by each mode the rule refuses. Anything else is named by its number alone. */
const REFUSED_KINDS = Object.freeze({
  "120000": "a symbolic link",
  "160000": "a gitlink (a submodule, or a directory written with a mode git does not read as one, a raw `140000` among them)",
});

/**
 * The one listing every reader of this rule takes. `--full-tree` makes it the
 * whole tree whatever directory git runs in; dropping `-r`, `-t` or `-z` is
 * watched red by tools/selftest/validation.mjs's tree-rule cases.
 */
export const LS_TREE = Object.freeze(["ls-tree", "-r", "-t", "-z", "--full-tree"]);

const git = (root, args) =>
  execFileSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: { ...cleanEnv(), GIT_PAGER: "cat", GIT_OPTIONAL_LOCKS: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });

/**
 * `git ls-tree -z` output as rows. A row is `<mode> SP <type> SP <object> TAB
 * <path>`, so the first tab ends the header and everything after it is the
 * path, tabs included.
 *
 * @returns {{mode: string, type: string, object: string, path: string}[]}
 */
export function parseLsTree(out) {
  return String(out).split("\0").filter(Boolean).map((row) => {
    const tab = row.indexOf("\t");
    const [mode, type, object] = row.slice(0, tab).split(" ");
    return { mode, type, object, path: row.slice(tab + 1) };
  });
}

/**
 * Every row this rule refuses, in tree order, as `{path, mode, message}`.
 * `message` does not repeat the path, so a caller prints `<path>: <message>`:
 *
 *   log/up: a symbolic link, git mode 120000, in the tree at 609e3e26f755: every entry …
 *   log/cutover: a gitlink (…), git mode 160000, in the tree at …
 *   state/holds: an empty directory, git mode 040000 with no file beneath it, in the tree at …
 *
 * Pure: the rows are whatever `LS_TREE` listed, and `at` names the commit for
 * the message.
 */
export function treeModeProblems(rows, at = "HEAD") {
  const problems = [];
  // A directory is empty when no row beneath it is anything but a directory.
  // A directory holding only a link is NOT empty: the link is refused on its
  // own row, and naming its directory too would point at the wrong entry.
  const holdsSomething = new Set();
  for (const r of rows) {
    if (r.mode === "040000") continue;
    const parts = r.path.split("/");
    for (let i = 1; i < parts.length; i++) holdsSomething.add(parts.slice(0, i).join("/"));
  }
  // Named at the outermost empty directory only: one inside another is part
  // of the same entry, and removing the outer one removes both.
  const empty = new Set(rows.filter((r) => r.mode === "040000" && !holdsSomething.has(r.path)).map((r) => r.path));
  const parentOf = (p) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : null);
  for (const r of rows) {
    if (!Object.hasOwn(ACCEPTED_MODES, r.mode)) {
      const kind = REFUSED_KINDS[r.mode] ?? "an entry that is neither a file nor a directory";
      problems.push({
        path: r.path,
        mode: r.mode,
        message: `${kind}, git mode ${r.mode}, in the tree at ${at}: every entry in the registry's tree is a ` +
          "regular file (100644, 100755) or a directory (040000) as git reads it, and the registry refuses anything " +
          "else rather than resolving it",
      });
    } else if (empty.has(r.path) && !empty.has(parentOf(r.path))) {
      problems.push({
        path: r.path,
        mode: r.mode,
        message: `an empty directory, git mode 040000 with no file beneath it, in the tree at ${at}: ` +
          "git's path-limited history, its diff and a checkout all skip it while a reader that walks trees sees it, " +
          "so the two disagree about whether the commit that added it changed anything",
      });
    }
  }
  return problems;
}

/** What to do about a refused row; one sentence for every kind, so it can be a hint. */
export const TREE_MODE_HINT =
  "A checkout follows a link and a mirror resolves its target by rules of its own, so two readers of one record " +
  "read two files; a gitlink checks out empty; an empty directory exists for one reader and not the other. " +
  "Commit the file or the directory itself, or remove the entry.";

/**
 * The tree at `treeish` in `root`, as rows, with the commit it was read at.
 * Throws when git cannot list it; the caller decides what that means.
 */
export function readTree(root, treeish = "HEAD") {
  const at = git(root, ["rev-parse", "--verify", "--quiet", `${treeish}^{commit}`]).trim();
  return { at, rows: parseLsTree(git(root, [...LS_TREE, at])) };
}

/**
 * Null when `root` is the top of a git work tree whose HEAD names a commit,
 * otherwise why the rule cannot be asked there. A fixture directory inside
 * this checkout is not the top of one: git would answer for the enclosing
 * repository, whose tree is not the tree under test.
 */
export function unaskableRoot(root) {
  let top = null;
  try {
    top = git(root, ["rev-parse", "--show-toplevel"]).trim() || null;
  } catch {
    top = null;
  }
  if (!top || fs.realpathSync(top) !== fs.realpathSync(root)) {
    return `${root} is not the top of a git work tree of its own, and the tree rule reads git's tree at HEAD, ` +
      "never the filesystem";
  }
  try {
    git(root, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]);
  } catch {
    return `${root} has no commit at HEAD, so there is no tree to read`;
  }
  return null;
}

// ── the rule on one commit, from a writer's shell ────────────────────────────
//
//   node tools/lib/tree-modes.mjs HEAD
//
// For the writers that commit and push from a workflow's shell (ops
// `dev/couplings.md` entry 216): the moderation commit job, the operator job,
// baseline, keepalive and the publisher re-check. Each ran `tools/validate.mjs`
// over the commit it STARTED from, if it validated at all — keepalive and the
// re-check never did — so the commit it made met this rule only after the
// push, in Registry index and the Signer's gate, by which time it was `main`.
// `bot/publish-apply.mjs` asks the rule of its own commit in-process; these
// five run this line after their last `git commit` (and after every rebase)
// and before each `git push`. A refusal exits 1, and the step's `set -e` ends
// the shell with nothing pushed. `bot/tests/publish-apply.test.mjs` runs each
// writer's own steps over a commit holding a link and one holding an empty
// directory, and holds every workflow line that pushes to having this line
// before it.
//
// Asked from the top of the checkout, as `tools/validate.mjs` asks it: a
// directory that is not the top of a work tree of its own would have git
// answer for whatever repository encloses it.

/**
 * The rule over `argv[0]` in the repository `root` is the top of. Returns the
 * exit code: 0 clean, 1 refused or unreadable, 2 misused. Everything it says
 * goes to stdout, where the runner reads `::error::`.
 */
export function main(argv, { root = process.cwd(), say = console.log } = {}) {
  if (argv.length !== 1 || argv[0].startsWith("-")) {
    say("usage: node tools/lib/tree-modes.mjs <commit>   (a writer passes HEAD, after its commit and before its push)");
    return 2;
  }
  const unaskable = unaskableRoot(root);
  if (unaskable) {
    say(`::error::the tree rule was not asked, so nothing may be pushed: ${unaskable}`);
    return 1;
  }
  let made;
  try {
    made = readTree(root, argv[0]);
  } catch (err) {
    say(`::error::git could not list the tree at ${argv[0]}, so nothing may be pushed: ` +
      `${String(err?.stderr || err?.message || err).trim().split("\n")[0]}`);
    return 1;
  }
  const at = made.at.slice(0, 12);
  if (made.rows.length === 0) {
    say(`::error::git ls-tree listed nothing at ${at}; a listing of nothing refuses nothing, so this is a broken ` +
      "read, not a clean tree, and nothing may be pushed");
    return 1;
  }
  const problems = treeModeProblems(made.rows, at);
  if (problems.length === 0) {
    say(`ok    the tree at ${at}: ${made.rows.length} entries, each a regular file or a directory with a file beneath it`);
    return 0;
  }
  for (const p of problems) say(`::error::${p.path}: ${p.message}`);
  say(`::error::the commit at ${at} holds ${problems.length} entr${problems.length === 1 ? "y" : "ies"} the registry's ` +
    `tree may not, and it is not pushed. ${TREE_MODE_HINT}`);
  return 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
