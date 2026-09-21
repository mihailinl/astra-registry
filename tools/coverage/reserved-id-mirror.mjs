#!/usr/bin/env node
// OPEN-OPS-11, the registry half: does AstraPlugins still reserve the ids this
// repository reserves? (registry plan M-T5.7.)
//
//     node tools/coverage/reserved-id-mirror.mjs [--repo <dir>] [--url <git url>] [--report <file>]
//
// ── WHAT THE TWO COPIES ARE, AND WHY ONE OF THEM HAS TO EXIST ───────────────
//
// `policy/reserved-ids.json` is what the registry refuses: `tools/lib/ids.mjs`
// and `tools/lib/reserved.mjs` read it, `tools/validate.mjs` applies it to the
// tree and `bot/lib/derive.mjs` applies it at ingest, so what CI refuses and
// what the bot refuses cannot be two answers.
//
// The CLI has to refuse the same names BEFORE a submission exists, in `astra-
// plugin check`, on a machine with no network and no registry checkout — an
// author who learns that `moderation` is reserved from a pull request comment
// has already named their repository, their binary and their crate. So AP-7
// mirrors the list into AstraPlugins as `spec/reserved-ids.yaml`. Two copies,
// deliberately, and the copy is the point.
//
// What is NOT mirrored is the trust half: `first_party_repos` and
// `first_party_owners` stay here, because a second copy of an allowlist is a
// second place to widen one.
//
// ── WHY THIS RULE ALARMS AND DOES NOT GATE ──────────────────────────────────
//
// Drift is asymmetric and neither direction is an emergency:
//
//   a name here and not there — the CLI accepts an id the registry will refuse
//     at ingest, so the author is told late instead of early. Annoying, safe;
//   a name there and not here — the CLI refuses an id the registry would take.
//     An author is turned away from a name nobody is holding.
//
// Neither is worth blocking a takedown or a publish for, which is why this is
// a line in the coverage canary (MOD-46: it gates nothing) and not a check in
// `validate.mjs` or in any signing job. The alarm says "re-mirror" and a human
// decides which side moved.
//
// ── THE NETWORK, AND WHAT IT MAY NOT DO ─────────────────────────────────────
//
// One `git ls-remote --symref` to resolve the default branch — `master` here,
// not `main`, and resolving it is cheaper than being wrong about it — and one
// unauthenticated GET of the raw file. No credential is sent in either
// direction: this rule reads a public file in a public repository, and a token
// in a rule that runs every fifteen minutes is a token in fifteen-minute
// Actions logs.
//
// A fetch that fails is reported, not swallowed (the plan's words: "a fetch
// failure alerts, naming the URL"). It is retried once first, because the
// alternative is an alarm every time GitHub is slow for four seconds, and an
// alarm that cries wolf four times a week is an alarm nobody opens.
//
// ── AP-7 HAS NOT LANDED, AND THAT IS `pending`, NOT RED ─────────────────────
//
// `spec/reserved-ids.yaml` does not exist yet. A rule that is red from the day
// it lands until the day another repository's task lands is a rule somebody
// switches off in between (TRUST-45), so an ABSENT file is `pending` and names
// AP-7. Once AP-7 has landed, absence stops being "not yet" and becomes "not
// any more" — a deletion — and `AP7_LANDED` below is what turns the second one
// red. It is a constant rather than something derived, because the fact it
// records lives in another repository's history and this job has `contents:
// read` on this one; when the fetch succeeds while it is still `false`, the
// run says so in its detail, on every run, until somebody flips it.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { report } from "./rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..", "..");

export const RULE = "reserved-id-mirror";

/** This repository's half of the mirror. */
export const POLICY = "policy/reserved-ids.json";

/** AstraPlugins' half, which AP-7 creates. */
export const SPEC_PATH = "spec/reserved-ids.yaml";

/**
 * AstraPlugins' clone URL.
 *
 * `astraPluginsRemote` prefers whatever the repository already declares, so
 * this constant is the fallback and the thing the test compares against —
 * `bot/tests/moderation-coverage.test.mjs` fails if the declared URL and this
 * one ever differ, in either direction.
 */
export const ASTRAPLUGINS_URL = "https://github.com/mihailinl/AstraPlugins.git";

/**
 * Has AP-7 landed `spec/reserved-ids.yaml` on AstraPlugins' default branch?
 *
 * `false` → a 404 is `pending`, naming AP-7.
 * `true`  → a 404 is a deletion, and a deletion is red.
 *
 * Flip it in the registry commit that follows AP-7 (the plan's commit order:
 * M-T1.1, then AP-7, then this alarm — this alarm landed first, in wave 1).
 *
 * **Flipped 2026-09-20.** AP-7 landed on AstraPlugins `master` as `1b8849c`,
 * and `spec/reserved-ids.yaml` is there. Until this line moved, the rule read
 * its own staleness out loud on every run — *"AP-7 has landed, this run read
 * the file, and `AP7_LANDED` is still false, so a DELETION of the mirror would
 * report as `pending` rather than red. Flip it."* That nag is what found it,
 * not a person: the constant was designed to notice it had gone stale, which
 * is the one thing a hand-maintained fact in this estate can do for itself.
 */
export const AP7_LANDED = true;

/** Both network calls. Long enough for a slow forge, short enough for a 15-minute cron. */
const TIMEOUT_MS = 20_000;

// ── the two halves ──────────────────────────────────────────────────────────

/** @returns {{reserved: string[], prefixes: string[]}} */
export function loadPolicyReserved(repo) {
  const doc = JSON.parse(fs.readFileSync(path.join(repo, POLICY), "utf8"));
  return {
    reserved: Array.isArray(doc.reserved) ? doc.reserved.map(String) : [],
    prefixes: Array.isArray(doc.reserved_prefixes) ? doc.reserved_prefixes.map(String) : [],
  };
}

/** A `#` that starts a comment: at the start, or after whitespace, outside quotes. */
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

const unquote = (s) => {
  const t = s.trim();
  if ((t.startsWith('"') && t.endsWith('"') && t.length > 1) ||
      (t.startsWith("'") && t.endsWith("'") && t.length > 1)) return t.slice(1, -1);
  return t;
};

/**
 * The small corner of YAML `spec/reserved-ids.yaml` is written in, and nothing
 * else.
 *
 * A tolerant parser is the wrong tool here. This rule's whole output is "these
 * two lists differ", so a parser that reads an unexpected shape as an empty
 * list would report every name in this repository as missing upstream — a
 * forty-line alarm about a file that is fine. Anything it does not understand
 * THROWS, naming the line, and the caller turns that into one code that says
 * the spec could not be read.
 *
 * Understood: `key: value`, `key:` followed by `- item` lines, and
 * `key: [a, b]`. Comments, blank lines and quotes. Nothing nested.
 *
 * @returns {Record<string, string|string[]>}
 */
export function parseReservedIdsYaml(text) {
  const doc = {};
  let key = null;
  text.split("\n").forEach((raw, i) => {
    const at = `line ${i + 1}`;
    if (/^\s*\t/.test(raw)) throw new Error(`${at} indents with a tab, which YAML forbids`);
    const line = stripComment(raw).replace(/\s+$/, "");
    if (line.trim() === "") return;
    if (line === "---") return;

    const item = /^\s*-\s+(.+)$/.exec(line);
    if (item) {
      if (key === null) throw new Error(`${at} is a list item under no key`);
      if (!Array.isArray(doc[key])) {
        if (doc[key] !== undefined && doc[key] !== "") throw new Error(`${at} adds a list item to the scalar ${key}`);
        doc[key] = [];
      }
      doc[key].push(unquote(item[1]));
      return;
    }

    const pair = /^([A-Za-z_][A-Za-z0-9_.-]*):\s*(.*)$/.exec(line);
    if (!pair) throw new Error(`${at} is neither a key nor a list item: ${JSON.stringify(raw.slice(0, 80))}`);
    if (/^\s/.test(line)) throw new Error(`${at} is indented; this file has no nested maps`);
    key = pair[1];
    const value = pair[2].trim();
    if (value === "") { doc[key] = ""; return; }
    const flow = /^\[(.*)\]$/.exec(value);
    doc[key] = flow
      ? flow[1].split(",").map((s) => unquote(s)).filter((s) => s !== "")
      : unquote(value);
  });
  return doc;
}

/** @returns {{reserved: string[], prefixes: string[]}} */
export function specReserved(doc) {
  for (const member of ["reserved", "reserved_prefixes"]) {
    if (!Array.isArray(doc[member])) {
      throw new Error(
        `${SPEC_PATH} has no \`${member}\` list (it holds ${JSON.stringify(doc[member] ?? null)}); ` +
        "a renamed member is a comparison against nothing",
      );
    }
  }
  return { reserved: doc.reserved.map(String), prefixes: doc.reserved_prefixes.map(String) };
}

// ── the remote ──────────────────────────────────────────────────────────────

/**
 * Where AstraPlugins is, and who says so.
 *
 * The repository already declares this URL and B-T1.4 is going to move the
 * declaration out of `ingest.yml` into `bot/manifest-probe/astra-plugins.pin`.
 * Both are read, newest home first, so that move is a no-op here rather than a
 * red run on the day it lands.
 */
export function astraPluginsRemote(repo) {
  const pin = path.join(repo, "bot", "manifest-probe", "astra-plugins.pin");
  if (fs.existsSync(pin)) {
    const m = /^\s*ASTRA_PLUGINS_URL\s*=\s*(\S+)\s*$/m.exec(fs.readFileSync(pin, "utf8"));
    if (m) return { url: m[1], source: "bot/manifest-probe/astra-plugins.pin" };
  }
  const ingest = path.join(repo, ".github", "workflows", "ingest.yml");
  if (fs.existsSync(ingest)) {
    const m = /^\s*ASTRA_PLUGINS_URL:\s*(\S+)\s*$/m.exec(fs.readFileSync(ingest, "utf8"));
    if (m) return { url: m[1], source: ".github/workflows/ingest.yml" };
  }
  return { url: ASTRAPLUGINS_URL, source: "tools/coverage/reserved-id-mirror.mjs" };
}

/** `owner/name` out of a clone URL. */
export function repoSlug(url) {
  const cleaned = String(url).replace(/\.git$/, "").replace(/\/+$/, "");
  const parts = cleaned.split("/").filter(Boolean);
  return parts.length >= 2 ? `${parts[parts.length - 2]}/${parts[parts.length - 1]}` : cleaned;
}

/**
 * The default branch, from the remote itself.
 *
 * Not `main`: AstraPlugins' default branch is `master`, and half the rules
 * written against these two repositories have guessed wrong at least once. A
 * guess that is wrong reads as "the file is gone", which is the same shape as
 * the alarm this rule exists to raise.
 *
 * Its own `execFileSync` rather than `./git.mjs`, for two reasons that only
 * apply to a network call: `GIT_TERMINAL_PROMPT=0`, so a forge that asks for
 * credentials fails instead of hanging a job that runs every fifteen minutes,
 * and a timeout, which the local-history helper has no use for.
 */
export function defaultBranch(url, { timeoutMs = TIMEOUT_MS } = {}) {
  const out = execFileSync("git", ["ls-remote", "--symref", url, "HEAD"], {
    encoding: "utf8",
    timeout: timeoutMs,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "echo", GIT_CONFIG_NOSYSTEM: "1" },
  });
  const m = /^ref:\s+refs\/heads\/(\S+)\s+HEAD$/m.exec(out);
  if (!m) throw new Error(`no symbolic HEAD in \`git ls-remote --symref ${url} HEAD\``);
  return m[1];
}

export const rawUrl = (slug, branch, file) =>
  `https://raw.githubusercontent.com/${slug}/${branch.split("/").map(encodeURIComponent).join("/")}/${file}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Read the spec off the default branch.
 *
 * @returns {Promise<{kind: "spec"|"absent"|"unreachable"|"no-branch", url?: string,
 *                    branch?: string, text?: string, why?: string, remote?: string}>}
 */
export async function fetchSpec(remote, { timeoutMs = TIMEOUT_MS, attempts = 2 } = {}) {
  let branch;
  try {
    branch = defaultBranch(remote, { timeoutMs });
  } catch (e) {
    return { kind: "no-branch", remote, why: e.message };
  }
  const url = rawUrl(repoSlug(remote), branch, SPEC_PATH);
  let why = "";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      // No Authorization header, deliberately: a public file, read by a rule
      // whose output is a run log.
      const res = await fetch(url, {
        redirect: "follow",
        signal: AbortSignal.timeout(timeoutMs),
        headers: { accept: "text/plain", "user-agent": "astra-registry-coverage-canary" },
      });
      if (res.status === 200) return { kind: "spec", url, branch, text: await res.text() };
      if (res.status === 404) return { kind: "absent", url, branch };
      why = `HTTP ${res.status}`;
      if (res.status < 500 && res.status !== 429) break;
    } catch (e) {
      why = e?.message ?? String(e);
    }
    if (attempt < attempts) await sleep(2000);
  }
  return { kind: "unreachable", url, branch, why };
}

// ── the rule ────────────────────────────────────────────────────────────────

const difference = (a, b) => a.filter((x) => !b.includes(x)).sort();
const list = (xs) => xs.map((x) => `\`${x}\``).join(", ");

export async function run(repo, { readSpec = fetchSpec, ap7Landed = AP7_LANDED, remote = null } = {}) {
  let mine;
  try {
    mine = loadPolicyReserved(repo);
  } catch (e) {
    return {
      status: "red",
      codes: ["RESERVED_MIRROR_POLICY_UNREADABLE"], ids: [], hexes: [],
      detail: [`${POLICY} could not be read: ${e.message}. This side of the mirror is the authority; with it ` +
        "unreadable there is nothing to compare against"],
    };
  }
  if (mine.reserved.length === 0 || mine.prefixes.length === 0) {
    return {
      status: "red",
      codes: ["RESERVED_MIRROR_POLICY_EMPTY"], ids: [], hexes: [],
      detail: [`${POLICY} declares ${mine.reserved.length} reserved id(s) and ${mine.prefixes.length} prefix(es). ` +
        "An empty list here would report every name AstraPlugins holds as an addition, which is an alarm about " +
        "this file and not about the mirror"],
    };
  }

  const where = remote ?? astraPluginsRemote(repo);
  const got = await readSpec(where.url);

  if (got.kind === "no-branch") {
    return {
      status: "red",
      codes: ["RESERVED_MIRROR_BRANCH_UNRESOLVED"], ids: [], hexes: [],
      detail: [
        `the default branch of ${where.url} (named by ${where.source}) could not be resolved: ${got.why}`,
        "Until it resolves, nothing is comparing the two reserved-id lists, and the silence looks like agreement",
      ],
    };
  }
  if (got.kind === "unreachable") {
    return {
      status: "red",
      codes: ["RESERVED_MIRROR_UNREACHABLE"], ids: [], hexes: [],
      detail: [
        `${got.url} could not be read: ${got.why}`,
        "A fetch failure is reported rather than skipped: an unread mirror and an agreeing mirror are the same " +
        "colour otherwise, and this rule's whole job is to notice a difference nobody would otherwise see",
      ],
    };
  }
  if (got.kind === "absent") {
    if (!ap7Landed) {
      return {
        status: "pending",
        codes: [], ids: [], hexes: [],
        detail: [
          `${got.url} does not exist (404 on branch ${got.branch}). AP-7 creates it — the reserved-id and ` +
          "listing-id mirror, and the CLI's `registry` severity — and nothing blocks AP-7 now that M-T1.1 has landed",
          `this side is ready: ${POLICY} holds ${mine.reserved.length} reserved id(s) and ` +
          `${mine.prefixes.length} prefix(es), and this rule compares both directions the moment the file appears`,
          "pending, not red: a canary red from the day it lands until another repository's task lands is a canary " +
          "somebody switches off, and then it is not watching the drift either (TRUST-45)",
        ],
      };
    }
    return {
      status: "red",
      codes: ["RESERVED_MIRROR_SPEC_DELETED"], ids: [], hexes: [],
      detail: [
        `${got.url} is a 404 and AP7_LANDED says the file has existed. A mirror that has been deleted is not a ` +
        "mirror that is not yet written: the CLI that shipped with it now refuses ids nothing holds, or holds " +
        "none at all",
      ],
    };
  }

  let theirs;
  try {
    theirs = specReserved(parseReservedIdsYaml(got.text));
  } catch (e) {
    return {
      status: "red",
      codes: ["RESERVED_MIRROR_UNPARSEABLE"], ids: [], hexes: [],
      detail: [
        `${got.url} could not be read as the shape AP-7 defines: ${e.message}`,
        "Reported as one unreadable file rather than as a list of differences, because a parser that read an " +
        "unexpected shape as an empty list would alarm about every name in the registry",
      ],
    };
  }

  const codes = [];
  const detail = [`${got.url} (branch ${got.branch}) holds ${theirs.reserved.length} reserved id(s) and ` +
    `${theirs.prefixes.length} prefix(es); ${POLICY} holds ${mine.reserved.length} and ${mine.prefixes.length}`];

  const missingNames = difference(mine.reserved, theirs.reserved);
  const extraNames = difference(theirs.reserved, mine.reserved);
  const missingPrefixes = difference(mine.prefixes, theirs.prefixes);
  const extraPrefixes = difference(theirs.prefixes, mine.prefixes);

  // Names go in `detail` and never in the verdict's `ids`. That member is
  // plugin ids, checked against the id grammar before the channel will carry
  // it, and `astra-` — a reserved PREFIX — is not a plugin id: putting one
  // there would turn a drift alarm into E_VERDICT_UNSENDABLE, which is the
  // alarm arriving as a complaint about itself.
  if (missingNames.length) {
    codes.push("RESERVED_MIRROR_NAME_MISSING");
    detail.push(
      `re-mirror: this registry reserves ${list(missingNames)} and ${SPEC_PATH} does not. The CLI accepts those ` +
      "ids, so an author names a repository, a binary and a crate and is refused at ingest",
    );
  }
  if (extraNames.length) {
    codes.push("RESERVED_MIRROR_NAME_EXTRA");
    detail.push(
      `re-mirror: ${SPEC_PATH} reserves ${list(extraNames)} and this registry does not. The CLI turns an author ` +
      "away from a name nobody here is holding",
    );
  }
  if (missingPrefixes.length) {
    codes.push("RESERVED_MIRROR_PREFIX_MISSING");
    detail.push(`re-mirror: this registry reserves the prefix(es) ${list(missingPrefixes)} and ${SPEC_PATH} does not`);
  }
  if (extraPrefixes.length) {
    codes.push("RESERVED_MIRROR_PREFIX_EXTRA");
    detail.push(`re-mirror: ${SPEC_PATH} reserves the prefix(es) ${list(extraPrefixes)} and this registry does not`);
  }

  if (!ap7Landed) {
    detail.push(
      "AP-7 has landed — this run read the file — and AP7_LANDED in tools/coverage/reserved-id-mirror.mjs is " +
      "still false, so a DELETION of the mirror would report as `pending` rather than red. Flip it",
    );
  }
  return { status: codes.length ? "red" : "green", codes, ids: [], hexes: [], detail };
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
