// The one place the signer shells out to git.
//
// Three modules under tools/signer/ read history — plan.mjs for `signed`'s head
// and D3's serials, key-window.mjs for the commit that first delegated a key,
// pages.mjs for D5's latch — and an eight-line `execFileSync` wrapper copied
// into each of them is three chances for one of the copies to stop checking the
// exit status, or to grow a `stdio: "ignore"` on stderr and start reporting a
// failed command as an empty answer. **An empty answer is the dangerous one
// here**: an empty `rev-list --count` reads as serial 0, an empty log reads as
// "the flag was never added", and both of those are a decision rather than an
// error.
//
// So this file throws on a non-zero exit, and the one caller that legitimately
// expects a failure — a `signed` branch that does not exist yet, which is every
// run before the first — asks for it by name with `gitMaybe`.
//
// ── why there are two readers and not one ───────────────────────────────────
//
// `gitText` trims and `gitBytes` does not, and the difference is a carry.
// `stableStringify` ends every document with a newline (tools/lib/canonical.mjs),
// so a `git show signed:registry/v1/index.json` read through a trimming wrapper
// hands back bytes that are one byte short of what `signed` holds. D4 carries a
// failing document forward **byte for byte**; a carry written from a trimmed
// read is a new document, with a different SHA-256, whose signature was made
// over the untrimmed bytes and therefore does not verify. One wrapper with one
// convenience would have made every carry a broken commit, and the convenience
// is wanted everywhere else — a sha, a count and a log line all arrive with a
// newline nobody means.

import { execFileSync } from "node:child_process";

/**
 * Run git in `root` and return its stdout exactly as git wrote it. Throws, with
 * git's own stderr in the message, on any non-zero exit.
 *
 * @param {string[]} args
 * @param {{root: string, maxBuffer?: number}} opts
 */
export function gitBytes(args, { root, maxBuffer = 64 * 1024 * 1024 } = {}) {
  try {
    return execFileSync("git", ["-C", root, ...args], {
      encoding: "utf8",
      maxBuffer,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    const stderr = String(e?.stderr ?? "").trim();
    throw new Error(`git ${args.join(" ")} failed in ${root}: ${stderr || e?.message || "no output"}`);
  }
}

/** The same, trimmed: a sha, a count, a list of log lines. */
export function gitText(args, opts) {
  return gitBytes(args, opts).trimEnd();
}

/**
 * For a command whose failure is an answer — a ref or a blob that is not there
 * yet — rather than a fault. `{ok: false}` instead of a throw.
 *
 * @param {string[]} args
 * @param {{root: string}} opts
 * @returns {{ok: true, out: string} | {ok: false, error: string}}
 */
export function gitMaybe(args, { root } = {}) {
  try {
    return { ok: true, out: gitBytes(args, { root }) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/**
 * D3's counter, at an explicit commit rather than at `HEAD`.
 *
 * `tools/build-index.mjs` and `tools/lib/revocations.mjs` both count at `HEAD`,
 * and only the first adds one for a pending change: build-index when
 * `git status` shows anything under `plugins/`, because it runs inside the
 * workflow that is about to commit. `resolveSerial` in the second adds one
 * unconditionally — serial 0 is reserved — and never looks at the working
 * tree, so a staged advisory does not move it (gap 69; its own comment has the
 * measurement). The signer is the other case: it counts at the
 * Source-Commit, which is already a commit, so there is nothing pending to add.
 * Writing that as `rev-list --count HEAD` here would silently count whatever
 * the signer's own checkout happened to be on.
 *
 * @param {{root: string, sha: string, pathspec: string}} opts
 */
export function revCount({ root, sha, pathspec }) {
  const out = gitText(["rev-list", "--count", sha, "--", pathspec], { root });
  const n = Number(out);
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error(`git rev-list --count ${sha} -- ${pathspec} returned ${JSON.stringify(out)}, not a count`);
  }
  return n;
}

/**
 * A file's bytes at a ref, untouched, or `null` when the ref or the path is not
 * there. This is what a carry copies.
 *
 * @param {{root: string, ref: string, path: string}} opts
 */
export function blobAt({ root, ref, path: p }) {
  const r = gitMaybe(["show", `${ref}:${p}`], { root });
  return r.ok ? r.out : null;
}
