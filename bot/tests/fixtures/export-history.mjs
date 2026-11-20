// A throwaway registry with real git history, for the Phase 2 export tests
// (export-state, export-replay, export-assert). D3's serial is a commit count,
// so nothing short of real commits exercises it.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { stableStringify } from "../../../tools/lib/canonical.mjs";
import { fixtureEnv } from "../../../tools/lib/git-env.mjs";
import { REPO_ROOT } from "../../../tools/lib/sources.mjs";

export const HUMAN = Object.freeze({ name: "A Person", email: "person@example.invalid" });

/** The git identity the committing workflows set (plugins-ingest.yml, `git config user.*`). */
export const BOT = Object.freeze({ name: "astra-registry-bot", email: "bot@users.noreply.github.com" });

export const listing = (id) => ({
  schema: "astra.registry.plugin/1",
  id,
  name: id.replace(/-/g, " "),
  summary: "A listing that exists so the catalogue is not empty.",
  license: "MIT",
  source: { kind: "github", repo: `someone/${id}` },
  added_at: "2026-08-10",
});

export const release = (id, version = "1.0.0") => ({
  schema: "astra.registry.version/1",
  id,
  version,
  published_at: "2026-08-10T00:00:00Z",
  release: { kind: "github_release", repo: `someone/${id}`, tag: `v${version}` },
  protocol: 1,
  capabilities: ["tools"],
  artifacts: {
    "linux-x64": {
      url: `https://github.com/someone/${id}/releases/download/v${version}/${id}-${version}-linux-x64.astraplugin`,
      filename: `${id}-${version}-linux-x64.astraplugin`,
      sha256: "a".repeat(64),
      size: 1234,
    },
  },
});

/** A fresh scratch directory under $TMPDIR. */
export function scratch(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `${name}-`));
}

/**
 * A registry repository. `commit(message, who)` commits everything as `who`
 * (author and committer), the bot by default.
 */
export function makeRegistry(name) {
  const dir = path.join(scratch(name), "registry");
  fs.mkdirSync(dir, { recursive: true });
  /** `as` commits as that identity, author and committer, through `-c`, not the environment. */
  const git = (args, as = null) =>
    execFileSync("git", [...(as ? ["-c", `user.name=${as.name}`, "-c", `user.email=${as.email}`] : []), "-C", dir, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: fixtureEnv(dir),
    }).trimEnd();
  git(["init", "-q", "-b", "main"]);
  git(["config", "commit.gpgsign", "false"]);
  // The build reads the first-party record, as every real tree has it.
  const fp = path.join(REPO_ROOT, "policy", "first-party.json");
  const write = (rel, value) => {
    const file = path.join(dir, ...rel.split("/"));
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof value === "string" || Buffer.isBuffer(value) ? value : stableStringify(value));
  };
  const remove = (rel) => fs.rmSync(path.join(dir, ...rel.split("/")), { recursive: true, force: true });
  if (fs.existsSync(fp)) write("policy/first-party.json", fs.readFileSync(fp));
  const commit = (message, who = BOT) => {
    git(["add", "-A"]);
    git(["commit", "-q", "--allow-empty", "-m", message], who);
    return git(["rev-parse", "HEAD"]);
  };
  const addListing = (id, version = "1.0.0") => {
    write(`plugins/${id}/plugin.json`, listing(id));
    write(`plugins/${id}/versions/${version}.json`, release(id, version));
  };
  return { dir, git, write, remove, commit, addListing };
}

/**
 * Five commits on main:
 *   c1 alpha listed                         serial 1
 *   c2 beta listed, a decision logged       serial 2
 *   c3 alpha's README, a second decision    serial 3
 *   c4 a docs-only commit                   serial 3 (the LAST commit at 3)
 *   c5 a log-only commit                    serial 3
 * so c3 and c4 share a state, and c5 holds the same serial with another one.
 */
export function exportHistory(name = "export-history") {
  const r = makeRegistry(name);
  r.addListing("alpha");
  const c1 = r.commit("alpha");
  r.addListing("beta");
  r.write("log/decisions/2026/11/00000000000000000000000000000001.json", { outcome: "accept" });
  const c2 = r.commit("beta");
  r.write("plugins/alpha/README.md", "# alpha\r\n\r\nbytes kept as stored\n");
  r.write("log/decisions/2026/11/00000000000000000000000000000002.json", { outcome: "accept" });
  const c3 = r.commit("alpha readme");
  r.write("README.md", "docs only\n");
  const c4 = r.commit("docs");
  return { ...r, commits: { c1, c2, c3, c4 } };
}

/** Add c5, the log-only commit. */
export function addLogOnly(r) {
  r.write("log/cutover.json", { note: "log only" });
  r.commits.c5 = r.commit("log only");
  return r.commits.c5;
}
