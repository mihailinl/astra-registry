#!/usr/bin/env node
// BOT-54's door: after cutover, no pull request changes a listing or a log.
//
//     node tools/pr-door.mjs --base <sha> --head <sha> [--repo <dir>]
//
// Registry plan B-T5.4. OD-19 (owner, 2026-09-13) closed the hand-edited
// pull-request door for `plugins/**`: only bot commits change listings, and
// pull requests stay for the bot's own code, policy, tools and docs. BOT-54
// words the check: "After ROLL step R6, registry CI MUST fail a pull request
// that adds, changes or deletes any file under `plugins/**` or `log/**`."
//
// ── WHAT THE DOOR WAS, AND WHY IT HAS NO EXCEPTION ──────────────────────────
//
// Until cutover a listing IS a pull request: `bot-checks.yml` runs the bot's
// checks over whatever a PR touches under `plugins/`, and a maintainer merges
// it. That path skips ownership and attestation — the checks read the
// listing, not who is allowed to write it — so once the service path exists it
// is the one way to put a `source` change beside a planted identity record and
// take a listing over without the bot ever deciding anything (contract TRUST-43;
// plan notes BOT-54's Why).
//
// 0.11.1's BOT-54 let one shape through: a PR that only set `yanked` or
// `unlisted`, with its `bot/moderation/` entry. OD-19 closed that with the rest,
// and it is gone here on purpose, not forgotten: a yank or a delist reaches
// `plugins/**` after cutover only through the commits BOT-33 allows — the
// moderation workflow, the operator workflow and the signer's inputs — and
// none of those is a pull request. `bot/tests/pr-door.test.mjs` holds a PR that
// sets `yanked` beside its log entry and asserts it is refused.
//
// ── WHEN IT IS ARMED ────────────────────────────────────────────────────────
//
// "After ROLL step R6" is read off the one record the cutover commit adds and
// nothing else does: `log/cutover.json` (contract B.4, ROLL-33), in the tree
// of the pull request's BASE. Not the head: the cutover commit itself is a
// pull request that adds `log/cutover.json`, and its base is pre-cutover, so
// the commit that arms the door is not refused by it. A base carrying the file
// in any shape arms the door — the marker's schema is `tools/validate.mjs`'s to
// judge, and a malformed marker disarming a security check would be the wrong
// way round.
//
// ── WHAT A PULL REQUEST'S CHANGE IS ─────────────────────────────────────────
//
// What GitHub shows as the PR's files: the head against the merge base of base
// and head (`base...head`), so a branch that merged `main` into itself is not
// charged with `main`'s commits. `--no-renames`, so a file moved OUT of
// `plugins/` is a deletion under `plugins/` and refused, and one moved in is an
// addition. Every status counts — add, modify, delete, type change.
//
// ── WHO JUDGES, AND WITH WHOSE COPY OF THIS FILE ────────────────────────────
//
// The `door` job checks out the BASE commit and runs the base's copy of this
// script, fetching the head only as objects to diff. A pull request that edits
// this file therefore cannot change the verdict on itself; its edit is judged
// by the next pull request, after a reviewer has merged it. What a PR CAN do is
// edit `bot-checks.yml` — GitHub runs a `pull_request` workflow from the PR's
// merge ref — which is a diff to `.github/workflows/` that a reviewer reads.
//
// ── THE RESIDUAL, STATED RATHER THAN HIDDEN ─────────────────────────────────
//
// **A red door blocks no merge.** ROLL-5 allows no required checks on `main`
// (three writers push to it directly), so this is a check a person has to
// read. BOT-40 and BOT-67 bound what a merged record buys, and the owner
// answered that he will not use the door (OD-19). A green door is also not a
// review: it says only that no listing or log file changed.
//
// It holds no token, no secret and no write permission, and reads nothing but
// two commits' trees.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { cleanEnv } from "./lib/git-env.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..");

/** The record whose presence in the base tree arms the door (B.4; ROLL-33). */
export const CUTOVER_MARKER = "log/cutover.json";

/** BOT-54's two trees. A path is refused when it starts with one of these. */
export const CLOSED = Object.freeze(["plugins/", "log/"]);

const SHA_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

/** Is this repository path one BOT-54 closes to pull requests? */
export const isClosed = (p) => CLOSED.some((prefix) => p.startsWith(prefix));

/**
 * The verdict, from the two facts it depends on and nothing else.
 *
 * @param {{armed: boolean, changes: {status: string, path: string}[]}} opts
 * @returns {{ok: boolean, armed: boolean, refused: {status: string, path: string}[]}}
 */
export function doorVerdict({ armed, changes }) {
  if (!armed) return { ok: true, armed: false, refused: [] };
  const refused = changes.filter((c) => isClosed(c.path));
  return { ok: refused.length === 0, armed: true, refused };
}

function git(repo, args) {
  return execFileSync("git", args, {
    cwd: repo, encoding: "utf8", env: cleanEnv(), maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
  });
}

/** Does `sha`'s tree hold `file`? */
export function treeHas(repo, sha, file) {
  try {
    git(repo, ["cat-file", "-e", `${sha}:${file}`]);
    return true;
  } catch {
    return false;
  }
}

/** What the pull request changed: head against the merge base, renames split. */
export function prChanges(repo, base, head) {
  let mergeBase;
  try {
    mergeBase = git(repo, ["merge-base", base, head]).trim();
  } catch {
    // Unrelated histories, or a commit this clone does not have. A door that
    // cannot say what changed has not seen that nothing did.
    throw new Error(`git merge-base ${base} ${head} found no common commit, so the pull request's change cannot be read`);
  }
  const out = git(repo, ["diff", "--name-status", "--no-renames", "-z", mergeBase, head]);
  const fields = out.split("\0").filter((s) => s !== "");
  const changes = [];
  for (let i = 0; i + 1 < fields.length; i += 2) changes.push({ status: fields[i][0], path: fields[i + 1] });
  return changes;
}

/** The whole door, over a repository holding both commits. */
export function run({ repo = DEFAULT_REPO, base, head }) {
  for (const [name, sha] of [["--base", base], ["--head", head]]) {
    if (!SHA_RE.test(String(sha ?? ""))) throw new Error(`${name} must be a full commit SHA, not ${JSON.stringify(sha)}`);
  }
  for (const sha of [base, head]) {
    try {
      git(repo, ["cat-file", "-e", `${sha}^{commit}`]);
    } catch {
      throw new Error(`${sha} is not a commit in ${repo}; fetch it before asking`);
    }
  }
  const armed = treeHas(repo, base, CUTOVER_MARKER);
  return doorVerdict({ armed, changes: armed ? prChanges(repo, base, head) : [] });
}

const STATUS = { A: "adds", M: "changes", D: "deletes", T: "retypes" };

function main(argv) {
  const args = { repo: DEFAULT_REPO };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--repo") args.repo = path.resolve(argv[++i]);
    else if (argv[i] === "--base") args.base = argv[++i];
    else if (argv[i] === "--head") args.head = argv[++i];
    else { console.error(`FAIL  unknown argument ${JSON.stringify(argv[i])}`); return 2; }
  }
  let verdict;
  try {
    verdict = run(args);
  } catch (e) {
    console.error(`::error::${e.message}`);
    return 2;
  }
  const lines = [];
  if (!verdict.armed) {
    lines.push(`ok    not armed: the base carries no ${CUTOVER_MARKER}, so BOT-54 does not apply yet (it applies after ROLL step R6)`);
  } else if (verdict.ok) {
    lines.push(`ok    cutover is on the base, and this pull request changes nothing under ${CLOSED.join(" or ")}`);
  } else {
    for (const r of verdict.refused) {
      lines.push(`::error file=${r.path}::this pull request ${STATUS[r.status] ?? `changes (${r.status})`} ${r.path}. ` +
        "After cutover only bot commits change listings and logs (BOT-54, OD-19); there is no exception for a yank " +
        "or a delist, which reach plugins/** only through the moderation and operator workflows (BOT-33)");
    }
    lines.push(`FAIL  ${verdict.refused.length} file(s) under ${CLOSED.join(" or ")}. A red door blocks no merge ` +
      "(ROLL-5 allows no required checks on main): whoever merges this is overriding BOT-54 by hand");
  }
  for (const l of lines) console.log(l);
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.map((l) => l.replace(/^::error file=[^:]+::/, "- ")).join("\n")}\n`);
  }
  return verdict.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
