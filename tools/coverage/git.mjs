// The git a coverage rule needs, and nothing else.
//
// Both walking tools here — `tools/moderation-coverage.mjs` and
// `tools/priv-scan.mjs` — read history rather than the working tree, and both
// need the same four questions answered: which commits are in range, what each
// one changed, what a file held AT that commit, and what the message said. A
// second copy of any of those is a second copy that can disagree, and the two
// tools disagreeing about "what did this commit change" is the failure mode
// where one of them silently scans a smaller set than the other.
//
// **Everything here is `execFileSync`, never a shell.** A plugin id, a tag and
// a branch name are all strings a stranger chose, and every one of them reaches
// these functions. `execFileSync` with an argument array has no word splitting
// and no metacharacters; a template string in a `sh -c` does.
//
// **Every list is NUL-separated where git offers it.** A path with a newline in
// it is legal in git and illegal nowhere; line-splitting `--name-status` over a
// tree somebody else can add files to is how a walk stops seeing a file that is
// right there.

import { execFileSync } from "node:child_process";

/** 64 MiB. A `git log -p` of this repository is nowhere near it; a runaway is. */
const MAX_BUFFER = 64 * 1024 * 1024;

/**
 * @param {string[]} args
 * @param {{cwd?: string, allowFailure?: boolean}} [opts]
 * @returns {string} stdout, or "" when `allowFailure` and git exited non-zero
 */
export function git(args, opts = {}) {
  const { cwd = process.cwd(), allowFailure = false } = opts;
  try {
    return execFileSync("git", ["-C", cwd, ...args], {
      encoding: "utf8",
      maxBuffer: MAX_BUFFER,
      // A pager or a hook writing to stdout would end up parsed as data.
      env: { ...process.env, GIT_PAGER: "cat", GIT_OPTIONAL_LOCKS: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    if (allowFailure) return "";
    // The cause, not only the command. A spawn that failed because the
    // process table was full, a child killed by a signal and a git that
    // exited 128 on an unknown revision all arrive here, and the first
    // spelling of this message printed the same sentence for all three — so
    // the first one read as "git cannot find this commit", which sent the
    // reader to look at history rather than at the machine.
    const stderr = e && e.stderr ? String(e.stderr).trim() : "";
    const how = [
      e?.code ? `code ${e.code}` : null,
      e?.status !== undefined && e?.status !== null ? `exit ${e.status}` : null,
      e?.signal ? `signal ${e.signal}` : null,
    ].filter(Boolean).join(", ");
    throw new Error(
      `git ${args.join(" ")} failed in ${cwd}` +
      `${how ? ` (${how})` : ""}${stderr ? `: ${stderr}` : ""}` +
      `${!stderr && !how && e?.message ? `: ${e.message}` : ""}`,
    );
  }
}

/** Reachable commits from HEAD. The number a shallow checkout gets wrong. */
export function historyCount(cwd) {
  const n = Number(git(["rev-list", "--count", "HEAD"], { cwd }).trim());
  return Number.isFinite(n) ? n : 0;
}

/** Is this checkout shallow? `fetch-depth: 0` is the only setting that answers no. */
export function isShallow(cwd) {
  return git(["rev-parse", "--is-shallow-repository"], { cwd }).trim() === "true";
}

/**
 * The commit that ADDED `filePath`, or null.
 *
 * This is how both tools find the start of their own range, rather than
 * carrying a hard-coded SHA that cannot be written until the commit exists and
 * is wrong from the second commit that touches the file onward.
 *
 * Oldest addition wins. A file added, deleted and re-added has two, and the
 * first one is the honest start: the rule has existed since then, and history
 * between the two is history nobody re-judged on purpose.
 */
export function introducingCommit(filePath, cwd) {
  const out = git(["log", "--format=%H", "--diff-filter=A", "--", filePath], { cwd, allowFailure: true });
  const shas = out.split("\n").map((s) => s.trim()).filter(Boolean);
  return shas.length ? shas[shas.length - 1] : null;
}

/**
 * Commits in `from..HEAD`, oldest first. `from` itself is EXCLUDED.
 *
 * Both walking rules apply "to commits after the one that introduces it", so
 * the exclusion is the rule rather than a convenience: a rule that judged its
 * own introducing commit would be a rule whose first act is to fail the commit
 * that added it, and the repair reached for is deleting the rule.
 *
 * **Merges are not here, and that is half an answer.** `--no-merges` is right
 * for "who wrote this change": a merge's diff against its first parent is the
 * whole branch again, and judging it would report every branch commit twice.
 * But it also hid the one thing only a merge carries — what its own
 * resolution wrote — and until gap 93 nothing walked that at all: a delist or
 * an address typed while resolving a conflict gave zero findings in both
 * walks. `mergesAfter` and `mergeOwnChanges` below are the other half, and a
 * rule that walks this list without them is blind to merges again.
 */
export function commitsAfter(from, cwd) {
  const out = git(["rev-list", "--reverse", "--no-merges", `${from}..HEAD`], { cwd, allowFailure: true });
  return out.split("\n").map((s) => s.trim()).filter(Boolean);
}

/** Merge commits in `from..HEAD`, oldest first — the complement of `commitsAfter`. */
export function mergesAfter(from, cwd) {
  const out = git(["rev-list", "--reverse", "--merges", `${from}..HEAD`], { cwd, allowFailure: true });
  return out.split("\n").map((s) => s.trim()).filter(Boolean);
}

/**
 * What a merge commit changed ITSELF: the difference between the tree git
 * would have written for its parents and the tree the merge recorded.
 *
 * That is `git show --remerge-diff`'s definition, and this computes the same
 * temporary tree with `git merge-tree --write-tree` (git ≥ 2.38; CI's
 * ubuntu-24.04 runner had 2.55.0 on 2026-09-22) rather than parsing
 * remerge-diff's output, for two reasons: the moderation walk needs the tree
 * itself, to read what a file held before the resolution touched it, and
 * `git log`'s manual says remerge output "is subject to change, and so is its
 * interaction with other options", while merge-tree's is plumbing with a
 * documented format. The coverage tests hold the two to the same answer.
 *
 * **Why not first-parent, and why not `-c`/`--cc`.** First-parent is the whole
 * branch again (every branch change reported twice). A combined diff lists
 * only paths that differ from EVERY parent, so it cannot see a resolution that
 * silently drops one side's change — merging `main` into a branch and
 * deleting a file `main` added gives `--cc` nothing and remerge `D` — and it
 * lists every file both sides edited cleanly, which the resolution did not
 * touch. Measured on eight fixture shapes on 2026-09-22.
 *
 * **`conflicted` matters to a reader of the result.** Where git could not
 * write a file, the temporary tree holds conflict markers, so "what the file
 * held before the resolution" has no parseable answer there; a rule has to
 * ask the parents instead (see the callers).
 *
 * An octopus merge (three or more parents) has no two-sided remerge and comes
 * back `judged: false`. None exists in this repository (0 of the 156 merges
 * reachable at `1d7253c`, 2026-09-22) and GitHub never writes one; a caller
 * reports it rather than passing it, because a merge this walk could not
 * judge is not a clean one.
 *
 * Measured on the real history the same day: merge-tree plus this diff named
 * the same paths as `git show --remerge-diff --name-status` for all 156
 * merges, and 7 of the 142 after the coverage tools landed had changes of
 * their own — every one a conflict resolved in `tools/selftest.mjs` or
 * `bot/detectors.mjs`, none in a composed path.
 *
 * @returns {{judged: boolean, parents: string[], tree: string|null,
 *   conflicted: Set<string>, changes: {status: string, path: string, oldPath: null}[]}}
 */
export function mergeOwnChanges(sha, cwd) {
  const parents = git(["show", "-s", "--format=%P", sha], { cwd }).trim().split(/\s+/).filter(Boolean);
  if (parents.length !== 2) return { judged: false, parents, tree: null, conflicted: new Set(), changes: [] };
  // merge-tree exits 1 when the merge has conflicts and still writes the tree,
  // so exit 1 is an answer and not a failure. Anything else is thrown: a git
  // too old to know `--write-tree` must fail this walk, not empty it.
  let out;
  try {
    out = execFileSync("git", ["-C", cwd, "merge-tree", "--write-tree", "-z", "--name-only", "--no-messages",
      parents[0], parents[1]], {
      encoding: "utf8", maxBuffer: MAX_BUFFER,
      env: { ...process.env, GIT_PAGER: "cat", GIT_OPTIONAL_LOCKS: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    if (e?.status !== 1 || !e.stdout) {
      const stderr = e && e.stderr ? String(e.stderr).trim() : "";
      throw new Error(`git merge-tree --write-tree ${parents.join(" ")} failed in ${cwd}` +
        `${e?.status !== undefined && e?.status !== null ? ` (exit ${e.status})` : ""}${stderr ? `: ${stderr}` : ""}`);
    }
    out = String(e.stdout);
  }
  const [tree, ...conflictedPaths] = out.split("\0").filter((s) => s !== "");
  if (!/^[0-9a-f]{40,64}$/.test(tree ?? "")) {
    throw new Error(`git merge-tree --write-tree ${parents.join(" ")} in ${cwd} wrote no tree: ${JSON.stringify(out.slice(0, 80))}`);
  }
  const diff = git(["diff", "--name-status", "-z", "--no-renames", tree, sha], { cwd });
  const fields = diff.split("\0").filter((s) => s !== "");
  const changes = [];
  for (let i = 0; i < fields.length; i++) {
    const p = fields[++i];
    if (p === undefined) break;
    changes.push({ status: fields[i - 1][0], path: p, oldPath: null });
  }
  return { judged: true, parents, tree, conflicted: new Set(conflictedPaths), changes };
}

/**
 * One commit's message, as written.
 *
 * @returns {{sha: string, author: string, date: string, message: string}}
 */
export function commitMeta(sha, cwd) {
  // NUL-separated, spelled `%x00` in the format rather than written into this
  // file as a byte. A commit message may hold any character but NUL, so any
  // visible separator is a separator a commit subject can forge: one line of a
  // body reading like the next field and the parse silently reassigns it.
  // (Spelled as a literal here once, it also made this file binary to grep and
  // made every `execFileSync` in it die with `ERR_INVALID_ARG_VALUE`, which
  // reads exactly like a bad revision.)
  const out = git(["show", "-s", "--format=%H%x00%an%x00%aI%x00%B", sha], { cwd });
  const [full, author, date, ...rest] = out.split("\0");
  return { sha: full.trim(), author, date, message: rest.join("\0") };
}

/**
 * The values of one trailer key in a commit message.
 *
 * **The whole message is scanned, not the last paragraph.** Git's own trailer
 * rules say a trailer is in the final block, and every commit that reaches
 * `main` here arrives through a squash merge whose final block is
 * `Co-authored-by:` lines GitHub appended. A `Moderation-Exempt:` an operator
 * wrote in the body of their own commit is then not a trailer by git's reading
 * and is by every human's — and the operator learns that only when the canary
 * they were clearing stays red. Anchored to the start of a line so a mention
 * inside a sentence is not one.
 *
 * @returns {string[]} the text after the colon, trimmed, in message order
 */
export function trailerValues(message, key) {
  const re = new RegExp(`^${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:[ \\t]*(.*)$`, "gm");
  return [...message.matchAll(re)].map((m) => m[1].trim()).filter(Boolean);
}

/**
 * What one commit changed, against its first parent.
 *
 * A root commit is compared against the empty tree, so the walk does not skip
 * the one commit in a fixture repository that adds everything.
 *
 * @returns {{status: string, path: string, oldPath: string|null}[]}
 */
export function changedPaths(sha, cwd) {
  const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
  const parents = git(["show", "-s", "--format=%P", sha], { cwd }).trim().split(/\s+/).filter(Boolean);
  const base = parents.length ? parents[0] : EMPTY_TREE;
  const out = git(["diff", "--name-status", "-z", "--no-renames", base, sha], { cwd, allowFailure: true });
  const fields = out.split("\0").filter((s) => s !== "");
  const changes = [];
  for (let i = 0; i < fields.length; i++) {
    const status = fields[i];
    // -z with --no-renames still emits one path per record; keeping the
    // two-field branch would be dead code that reads as if renames were
    // handled, and a rename IS a delete plus an add to every rule here.
    const p = fields[++i];
    if (p === undefined) break;
    changes.push({ status: status[0], path: p, oldPath: null });
  }
  return changes;
}

/**
 * A file's bytes at a commit, or null when it is not in that tree.
 *
 * `allowFailure` rather than a `cat-file -e` first: two git invocations per
 * path over a few hundred commits is the difference between a rule that runs
 * every fifteen minutes and one somebody reschedules.
 */
export function blobAt(sha, filePath, cwd) {
  const out = git(["show", `${sha}:${filePath}`], { cwd, allowFailure: true });
  return out === "" ? (fileExistsAt(sha, filePath, cwd) ? "" : null) : out;
}

function fileExistsAt(sha, filePath, cwd) {
  try {
    git(["cat-file", "-e", `${sha}:${filePath}`], { cwd });
    return true;
  } catch {
    return false;
  }
}

/** `blobAt` parsed as JSON, or null when absent or unparseable. `bad` says which. */
export function jsonAt(sha, filePath, cwd) {
  const raw = blobAt(sha, filePath, cwd);
  if (raw === null) return { present: false, value: null, bad: null };
  try {
    return { present: true, value: JSON.parse(raw), bad: null };
  } catch (e) {
    return { present: true, value: null, bad: String(e.message) };
  }
}

/** The first parent of `sha`, or null for a root commit. */
export function firstParent(sha, cwd) {
  const parents = git(["show", "-s", "--format=%P", sha], { cwd }).trim().split(/\s+/).filter(Boolean);
  return parents.length ? parents[0] : null;
}
