// The environment every git command in this repository runs with.
//
// **Why this module exists** (astra-plugins-ops `dev/couplings.md` entries 142
// and 143). git exports `GIT_DIR` to the hooks it runs, and to `rebase -x`
// commands and `!` aliases: from a worktree, an ABSOLUTE path to the
// worktree's gitdir, whose `config` and `refs/heads` are the shared
// repository's. Every child inherits it, and a child git obeys it over its
// `cwd` and over `-C`. On 2026-09-23 a fixture builder in astra-plugins-ops,
// run from that repository's pre-push hook in a worktree, made the shared
// checkout bare, moved its `main` onto a fixture commit and created a `signed`
// branch in it. Measured the same day in this repository: every one of its 93
// git spawns inherited the caller's environment, and seven bot test suites run
// with a hook-shaped `GIT_DIR` wrote `core.bare = true`, a user and a fetch
// refspec into the repository it named, moved its `main` and `side`,
// created five branches and re-pointed its worktree's HEAD.
//
// So every git spawn under `tools/`, `bot/` and anywhere else here takes its
// environment from one of the two functions below, and
// `tools/selftest/git-env.mjs` sweeps the tree for one that does not.
//
//   * `cleanEnv()`: this process's environment without the variables that name
//     a repository. For a command aimed at the repository it names by `cwd` or
//     `-C` — this checkout, a clone the code made, a remote by URL. Nothing
//     else changes: credentials, `HOME`, `GIT_AUTHOR_*` and the rest pass
//     through.
//   * `fixtureEnv(dir)`: `cleanEnv()`, plus `GIT_CEILING_DIRECTORIES` at
//     `dir`'s parent, so a fixture can never resolve to a repository that
//     encloses it — a `TMPDIR` inside a checkout, or a command that runs before
//     the fixture's `git init` or after one that failed. git still looks in
//     `dir` itself, so the fixture (bare or not) is found; a directory that is
//     not a repository is "not a git repository", never its neighbour's. Pass
//     the fixture's ROOT: a command in a subdirectory of it would stop at the
//     ceiling before reaching the fixture's `.git`.
//
// **Which variables.** git's own answer to "which variables are about one
// repository" — `git rev-parse --local-env-vars` — as git 2.55 gives it,
// which already holds the six the ops hook unsets by name. TYPED here rather
// than asked, for one reason: `tools/build-index.mjs` imports this module and
// is in the closure `tools/regenerate-signed.mjs` checks for any way to reach
// the network, where `node:child_process` is allowed in build-index.mjs alone.
// So the list cannot drift silently, `tools/selftest/git-env.mjs` asks the git
// it runs under and is red, by name, for any variable git lists and this does
// not. `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT` carry the outer
// command's `-c` options into a hook; no workflow here passes credentials that
// way (measured: nothing under `.github/` sets either), and the checkout
// action's token lives in the repository's own config, which a command at that
// repository still reads.
//
// **Setting one back on purpose.** A command may set `GIT_INDEX_FILE` to an
// index it made (the signer does, to commit without touching the working
// tree): that names a file the code chose, not one it inherited. The sweep
// refuses `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_OBJECT_DIRECTORY`
// and `GIT_ALTERNATE_OBJECT_DIRECTORIES` set back in an env literal.

import fs from "node:fs";
import path from "node:path";

/** `git rev-parse --local-env-vars`, git 2.55. The six the ops hook names are all in it. */
export const REPOSITORY_VARS = Object.freeze([
  "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
  "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE",
  "GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX", "GIT_SHALLOW_FILE",
  "GIT_COMMON_DIR",
]);

/** Every variable that names one repository. */
export function repositoryVars() {
  return [...REPOSITORY_VARS];
}

/** This process's environment without any variable that names a repository. */
export function cleanEnv() {
  const env = { ...process.env };
  for (const v of repositoryVars()) delete env[v];
  return env;
}

/** `cleanEnv()` with a ceiling at the fixture's parent. `dir` need not exist yet (a clone's target). */
export function fixtureEnv(dir) {
  const parent = path.dirname(path.resolve(dir));
  let ceiling = parent;
  try {
    ceiling = fs.realpathSync(parent);
  } catch {
    // The parent does not exist yet either; the resolved path is still a ceiling.
  }
  return { ...cleanEnv(), GIT_CEILING_DIRECTORIES: ceiling };
}
