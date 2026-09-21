#!/usr/bin/env node
// MOD-16's other half: is AstraPlugins still leaving the staging listing id
// alone? (registry plan M-T2.1.)
//
//     node tools/coverage/examples-staging-id.mjs [--repo <dir>] [--url <git url>] [--report <file>]
//
// ── WHAT COULD GO WRONG, AND WHY IT IS NOT AN ABSURD WORRY ──────────────────
//
// `policy/reserved-ids.json` reserves `astra-withdrawal-canary` for ONE
// listing: the one the estate publishes in order to delist it, relist it,
// revoke it and un-revoke it, so that a withdrawal is walked end to end
// against something that is not a stranger's plugin.
//
// That id is not on the `reserved` list — it cannot be, because a listing WILL
// exist under it — so the only thing standing between the canary and a real
// plugin of the same name is that nobody else takes the name first. And the
// most likely somebody is us: `AstraPlugins/examples/*/` is where this project
// writes the plugins it ships as demonstrations, `astra-` is a prefix its own
// repository is allowed to use, and "write an example that exercises a
// withdrawal" is a reasonable thing for a person on this project to do. An
// example published under the id would either take the id (the canary is then
// a second listing under a name that is already somebody's) or collide with it
// at ingest, at the worst possible moment: `bot/lib/derive.mjs` would derive
// THAT example unlisted, because the derive rule matches on the id and knows
// nothing about which repository it came from.
//
// ── IT ALERTS AND IT GATES NOTHING (MOD-46) ─────────────────────────────────
//
// Nothing here blocks a publish, a signature or a takedown. The remedy for a
// red is a conversation about a name, which is a human act on a human's
// timescale; wiring it into a gate would mean a withdrawal could be stopped by
// a repository this registry does not own being slow to answer.
//
// ── THE NETWORK, AND WHAT IT MAY NOT DO ─────────────────────────────────────
//
// No credential, in either call. The branch is resolved with `git ls-remote
// --symref <url> HEAD` — `master` here, not `main`, and resolving it is
// cheaper than being wrong about it, because a guess that is wrong reads as
// "the examples are gone", which is the same colour as the alarm this rule
// exists to raise. `defaultBranch` and `astraPluginsRemote` are IMPORTED from
// `./reserved-id-mirror.mjs` rather than written again: that rule asks the
// same forge for the same repository's default branch, and two answers to
// "where is AstraPlugins and what is its default branch" is the shape this
// estate has been bitten by more than any other. When B-T1.4 moves the URL
// declaration into `bot/manifest-probe/astra-plugins.pin`, both rules move
// with it, because there is one function to move.
//
// Then ONE `git clone --depth=1 --filter=blob:none --no-checkout`. A partial
// clone rather than an API call on purpose: listing a directory over HTTP
// means `api.github.com`, which is 60 requests an hour per IP unauthenticated
// and would put this rule one busy afternoon away from a 403 that is
// indistinguishable, here, from "the examples directory was deleted". The
// partial clone fetches commit and tree objects only; the eleven `plugin.toml`
// blobs are fetched on demand by `git show`, and nothing else in the
// repository is transferred.
//
// ── WHAT IT READS, AND THE FLOOR UNDER IT ───────────────────────────────────
//
// Every `examples/<name>/plugin.toml` on the default branch. Two things make
// an example "use" the id — its `[plugin] id`, and its own DIRECTORY name.
// The second is not decoration: `examples/astra-withdrawal-canary/` holding a
// manifest with some other id is a directory a person reads as the canary, a
// path a release workflow is named after, and one rename away from being the
// first thing.
//
// And a floor: at least one example manifest has to have been read. A walk
// that finds nothing reports green, and "the examples directory moved" and
// "no example takes the id" are otherwise the same colour — which is the
// failure this whole file exists to make impossible for one particular name.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { report } from "./rules.mjs";
import { stagingListingId } from "../lib/reserved.mjs";
import { astraPluginsRemote, defaultBranch, repoSlug } from "./reserved-id-mirror.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..", "..");

export const RULE = "examples-staging-id";

/** This repository's half: the id nobody upstream may take. */
export const POLICY = "policy/reserved-ids.json";

/** Which files upstream are examples. One `plugin.toml` per example directory. */
export const EXAMPLE_RE = /^examples\/([^/]+)\/plugin\.toml$/;

/** Long enough for a slow forge, short enough for a fifteen-minute cron. */
const TIMEOUT_MS = 45_000;

/**
 * A `#` that starts a comment: at the start, or after whitespace, outside
 * quotes.
 *
 * `./reserved-id-mirror.mjs` has a function of the same name and the same
 * body, and it is deliberately not shared. That one strips YAML comments and
 * this one strips TOML comments; the two grammars agree about `#` today and
 * owe each other nothing, so a shared helper would be a coupling between two
 * file formats rather than between two readings of one fact. The things that
 * ARE one fact — where AstraPlugins is, and what its default branch is — are
 * imported.
 */
function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

/**
 * `[plugin] id` out of a plugin.toml, or null.
 *
 * The table is tracked rather than the first `id =` taken, because a manifest
 * has other tables and a future one may have a key of the same name. Reading
 * the wrong table's `id` would be the rule answering a question nobody asked —
 * quietly, and in whichever direction that file happened to be written.
 *
 * Not a TOML parser: this rule asks one question of one key, and a tolerant
 * parser that read an unexpected shape as "no id" would report green about a
 * file it could not understand. Anything that is not a plain quoted scalar on
 * its own line is reported as unread by the caller's floor instead.
 */
export function pluginId(text) {
  let table = null;
  for (const raw of String(text).split("\n")) {
    const line = stripComment(raw).trim();
    if (line === "") continue;
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) { table = header[1].trim(); continue; }
    if (table !== "plugin") continue;
    const m = /^id\s*=\s*"([^"]*)"\s*$|^id\s*=\s*'([^']*)'\s*$/.exec(line);
    if (m) return m[1] ?? m[2];
  }
  return null;
}

// ── the remote ──────────────────────────────────────────────────────────────

const gitIn = (dir, args, timeoutMs) =>
  execFileSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "echo", GIT_CONFIG_NOSYSTEM: "1", GIT_PAGER: "cat" },
  });

/**
 * Every example manifest on the default branch (`EXAMPLE_RE`), with its bytes.
 *
 * @returns {Promise<{kind: "examples"|"no-branch"|"unreachable", url: string,
 *                    branch?: string, why?: string, files?: {path: string, text: string}[]}>}
 */
export async function fetchExamples(remoteUrl, { timeoutMs = TIMEOUT_MS } = {}) {
  let branch;
  try {
    branch = defaultBranch(remoteUrl, { timeoutMs });
  } catch (e) {
    return { kind: "no-branch", url: remoteUrl, why: e.message };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-examples-"));
  try {
    // `--filter=blob:none` is what keeps this to commit and tree objects; the
    // blobs below are fetched one at a time, and only for the paths that
    // matched.
    execFileSync("git", [
      "clone", "--quiet", "--depth=1", "--filter=blob:none", "--no-checkout",
      "--single-branch", "--branch", branch, remoteUrl, dir,
    ], {
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "echo", GIT_CONFIG_NOSYSTEM: "1" },
    });
    const paths = gitIn(dir, ["ls-tree", "-r", "--name-only", "-z", "HEAD"], timeoutMs)
      .split("\0").filter((p) => EXAMPLE_RE.test(p)).sort();
    const files = paths.map((p) => ({ path: p, text: gitIn(dir, ["show", `HEAD:${p}`], timeoutMs) }));
    return { kind: "examples", url: remoteUrl, branch, files };
  } catch (e) {
    const stderr = e && e.stderr ? String(e.stderr).trim() : "";
    return { kind: "unreachable", url: remoteUrl, branch, why: stderr || e?.message || String(e) };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ── the rule ────────────────────────────────────────────────────────────────

/**
 * @param {string} repo repository root
 * @returns {Promise<{status: "green"|"red", codes: string[], ids: string[], hexes: string[], detail: string[]}>}
 */
export async function run(repo, { readExamples = fetchExamples, remote = null } = {}) {
  let id;
  try {
    id = stagingListingId(JSON.parse(fs.readFileSync(path.join(repo, POLICY), "utf8")));
  } catch (e) {
    return {
      status: "red",
      codes: ["EXAMPLES_POLICY_UNREADABLE"], ids: [], hexes: [],
      detail: [`${POLICY} could not be read: ${e.message}. This rule's whole subject is one value in it`],
    };
  }
  if (id === null) {
    return {
      status: "red",
      codes: ["EXAMPLES_STAGING_ID_UNRESERVED"], ids: [], hexes: [],
      detail: [
        `${POLICY} carries no staging_listing_id. This rule and the reservation landed in one commit ` +
        "(M-T2.1), so an absent id here is a reservation that has been taken back out — which also silences " +
        "the derive rule in bot/lib/derive.mjs and the refusal in tools/validate.mjs, neither of which says " +
        "anything when the member is gone",
      ],
    };
  }

  const where = remote ?? astraPluginsRemote(repo);
  const got = await readExamples(where.url);

  if (got.kind === "no-branch") {
    return {
      status: "red",
      codes: ["EXAMPLES_BRANCH_UNRESOLVED"], ids: [], hexes: [],
      detail: [
        `the default branch of ${where.url} (named by ${where.source}) could not be resolved: ${got.why}`,
        `Until it resolves, nothing is watching whether an AstraPlugins example takes ${id}, and the silence ` +
        "looks exactly like an answer of no",
      ],
    };
  }
  if (got.kind === "unreachable") {
    return {
      status: "red",
      codes: ["EXAMPLES_UNREACHABLE"], ids: [], hexes: [],
      detail: [
        `${where.url}${got.branch ? ` (branch ${got.branch})` : ""} could not be read: ${got.why}`,
        "A fetch failure is reported rather than skipped: an unread examples tree and an examples tree that " +
        "takes no reserved name are the same colour otherwise",
      ],
    };
  }

  const files = got.files ?? [];
  const detail = [`${repoSlug(where.url)} branch ${got.branch}: ${files.length} examples/*/plugin.toml read`];

  // The floor, before the loop it guards. `examples/` renamed, the manifest
  // renamed, the clone filter dropping trees: every one of those makes the
  // loop below green over nothing, and "no example takes the id" is exactly
  // what green means here.
  if (files.length === 0) {
    return {
      status: "red",
      codes: ["EXAMPLES_NONE_FOUND"], ids: [], hexes: [],
      detail: [
        `no examples/*/plugin.toml on ${repoSlug(where.url)} branch ${got.branch}. There were 11 on ` +
        "2026-09-21, so this is a walk that stopped matching — a renamed directory, a renamed manifest — and " +
        `not an upstream that stopped shipping examples. Everything this rule says about ${id} would be said ` +
        "about an empty list",
      ],
    };
  }

  const codes = [];
  const unreadable = [];
  for (const f of files) {
    const dir = EXAMPLE_RE.exec(f.path)?.[1] ?? "";
    const declared = pluginId(f.text);
    if (declared === null) unreadable.push(f.path);
    if (declared === id) {
      codes.push("EXAMPLES_STAGING_ID_TAKEN");
      detail.push(
        `${f.path} declares \`id = ${JSON.stringify(id)}\`, which ${POLICY} reserves for MOD-16's path-test ` +
        "listing. Whoever publishes first owns the name: either that example becomes the listing the estate " +
        "delists and relists to drill its own withdrawal path, or the canary is a second listing under a " +
        "name that is already taken. Rename one of the two — this rule does not say which",
      );
    } else if (dir === id) {
      codes.push("EXAMPLES_STAGING_ID_TAKEN");
      detail.push(
        `examples/${dir}/ is named for ${POLICY}'s staging_listing_id while its manifest declares ` +
        `${JSON.stringify(declared)}. The id is not taken yet and the directory is: it is what a release ` +
        "workflow is named after, what a reader calls the example, and one rename from being the id",
      );
    }
  }
  if (unreadable.length) {
    codes.push("EXAMPLES_MANIFEST_UNREAD");
    detail.push(
      `no \`[plugin] id\` could be read from ${unreadable.join(", ")}. Reported rather than passed over: an ` +
      "example this rule cannot read is an example it is not checking, and the two are the same colour",
    );
  }
  if (codes.length === 0) {
    detail.push(`no example declares or is named for ${id}`);
  }
  // `ids` stays empty by construction. The one id this rule is about is OURS,
  // it is in `detail` where a human reads it, and the member is for plugin ids
  // a finding is ABOUT — putting a name there would make the alarm's grammar
  // check the thing a reader has to reason about.
  return { status: codes.length ? "red" : "green", codes: [...new Set(codes)], ids: [], hexes: [], detail };
}

async function main(argv) {
  const args = { repo: DEFAULT_REPO, report: process.env.ASTRA_COVERAGE_FINDINGS, url: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--repo") args.repo = path.resolve(argv[++i]);
    else if (argv[i] === "--report") args.report = argv[++i];
    else if (argv[i] === "--url") args.url = argv[++i];
    else { console.error(`FAIL  unknown argument ${JSON.stringify(argv[i])}`); return 2; }
  }
  const remote = args.url ? { url: args.url, source: "--url" } : astraPluginsRemote(args.repo);
  report(RULE, await run(args.repo, { remote }), args.report);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
