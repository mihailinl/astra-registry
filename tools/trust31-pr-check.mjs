#!/usr/bin/env node
//
// Does this pull request change the tree the owner acknowledged for the bot?
//
//   node tools/trust31-pr-check.mjs --base <commit> --head <commit> [--merge <commit>]
//                                   [--branch <name>] [--repo <owner/name>] [--head-repo <owner/name>]
//                                   [--dir <checkout>] [--read-url <service>]
//   node tools/trust31-pr-check.mjs --merge <merge commit>        a merged pull request, out of history
//   node tools/trust31-pr-check.mjs --at <commit> [--expect-set <hex>] [--expect-tree <hex>]
//
// ── the failure this closes ─────────────────────────────────────────────────
//
// The plugins service runs the bot live only while the bot-code TREE at the
// run's commit is the one the owner acknowledged (contract TRUST-31). The tree
// is a fixed set of paths. A merge to `main` that changes any of them puts
// every bot call in shadow — no author's release publishes — until the owner
// acknowledges the new tree on the site.
//
// On 2026-11-09 pull request #498, one line in `policy/spdx-allowlist.json`,
// was merged with a note that said "no acknowledgement needed". The note was
// written from memory. The file IS in the set, and three real releases sat
// unpublished for a day. Since contract 6.8.0 the owner can acknowledge a
// branch's tree BEFORE the merge, and then the merge causes no shadow at all;
// nothing told anyone that #498 needed it. This makes it a machine's answer on
// every pull request, and prints the three values the owner compares.
//
// ── the recipe, which is the service's and not this repository's ───────────
//
// `tracked_set_sha256` is the SHA-256 of every entry followed by a newline,
// entries sorted by bytes. `tree_sha256` is the SHA-256 over one line per
// entry, in that order: `<entry> <mode> <object id>`, mode and object id as
// `git ls-tree --full-tree <commit> -- <entry>` prints them, or `<entry> - -`
// for an entry that resolves to nothing.
//
// `bot/tests/code-paths.test.mjs` prints a "set hash" too. That one hashes
// `<blob> <path>` over FILES and carries no mode. It is not what the service
// compares and it is not computed here.
//
// ── where the set is read from ──────────────────────────────────────────────
//
// The contract publishes the set, in a repository this one cannot read. Two
// things here carry it: `ENTRIES` in `bot/tests/code-paths.test.mjs`, the
// registry's copy of the list, and `trust31_tracked_set_sha256` in
// `schema/contract-tokens-v1.json`, the digest the contract's own generator
// computed over its block. The list is read from the first, AT EACH COMMIT,
// out of git objects, and its digest is held to the second. Where they
// disagree this check says it cannot answer, and is red: a tree digest over
// the wrong list is the "no acknowledgement needed" of #498 with a number on
// it.
//
// `ENTRIES` opens with `...WORKFLOWS`, two paths declared forty lines above
// it. A count of the quoted strings between its brackets finds 72 where the
// set has 74, so the reader below follows a spread to its declaration and
// refuses anything that is neither a string nor a spread.
//
// ── what is compared ────────────────────────────────────────────────────────
//
// The base against the MERGE RESULT, which is what `main` would carry: the
// pull request's merge commit when one is given, otherwise the tree
// `git merge-tree` writes for the two. The head is read as well, because the
// owner acknowledges the head: an acknowledgement binds a tree, so a head
// whose tree is not the merge result's (`main` moved inside the set after the
// branch left it) would be acknowledged and then shadow the bot anyway.
//
// Exit 0: nothing in the set or the tree moves, or the service answers that
// exactly this tree is acknowledged. Exit 1: it moves. Exit 2: this check
// could not read what it needed, which is red and is not an answer.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";

import { cleanEnv } from "./lib/git-env.mjs";

/** The registry's copy of TRUST-31's list. */
export const SET_FILE = "bot/tests/code-paths.test.mjs";
/** The contract's token file, and the member that carries the set's digest. */
export const TOKEN_FILE = "schema/contract-tokens-v1.json";
export const TOKEN_MEMBER = "trust31_tracked_set_sha256";
/** This check and its workflow. A pull request that edits either is told so. */
export const OWN_FILES = ["tools/trust31-pr-check.mjs", ".github/workflows/trust31-set.yml"];

export const NOT_TOUCHED =
  "TRUST-31: this PR does not touch the bot's acknowledged tree; no acknowledgement is needed";
export const CHANGED =
  "TRUST-31: this PR changes the bot's acknowledged tree. Merging it before the owner acknowledges the tree " +
  "puts every bot call in shadow (no release publishes).";
export const PRE_ACKNOWLEDGED =
  "TRUST-31: this PR changes the bot's acknowledged tree, and the owner has acknowledged exactly this tree " +
  "before the merge.";
export const CANNOT_SAY =
  "TRUST-31: this check cannot say what the service will compare.";
export const NO_READ_YET =
  "the service has no read for a pre-acknowledgement yet; this check stays red, and the merge waits for the " +
  "owner's word";

const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** A refusal to answer: exit 2, and never a verdict. */
export class CannotRead extends Error {}

// ── the set ─────────────────────────────────────────────────────────────────

/**
 * `ENTRIES` out of the text of `bot/tests/code-paths.test.mjs`, as data. The
 * text is never run: it is the pull request's.
 *
 * A list here is `const NAME = [` up to its `]`, holding quoted strings,
 * comments, commas and `...OTHER` where OTHER is such a list in the same
 * text. Anything else is refused, because a member this reader skipped would
 * be an entry the digest silently lacks.
 */
export function parseEntries(source, name = "ENTRIES") {
  const open = new Set();
  const list = (id) => {
    if (open.has(id)) throw new CannotRead(`${SET_FILE}: \`${id}\` spreads itself`);
    const found = [...source.matchAll(new RegExp(`^(?:export )?const ${id.replace(/\$/g, "\\$")} = \\[`, "gm"))];
    if (found.length !== 1) {
      throw new CannotRead(`${SET_FILE}: ${found.length} declarations of \`const ${id} = [\` at the start of a line, and this reader needs exactly one`);
    }
    open.add(id);
    const out = [];
    let i = found[0].index + found[0][0].length;
    const where = () => `line ${source.slice(0, i).split("\n").length}`;
    for (;;) {
      const c = source[i];
      if (c === undefined) throw new CannotRead(`${SET_FILE}: \`${id}\` never closes`);
      if (c === "]") break;
      if (c === "," || /\s/.test(c)) { i += 1; continue; }
      if (source.startsWith("//", i)) {
        const end = source.indexOf("\n", i);
        if (end < 0) throw new CannotRead(`${SET_FILE}: \`${id}\` never closes`);
        i = end;
        continue;
      }
      if (source.startsWith("/*", i)) {
        const end = source.indexOf("*/", i + 2);
        if (end < 0) throw new CannotRead(`${SET_FILE}: a comment in \`${id}\` never closes`);
        i = end + 2;
        continue;
      }
      if (c === '"' || c === "'") {
        const end = source.indexOf(c, i + 1);
        const value = end < 0 ? "\n" : source.slice(i + 1, end);
        if (/[\\\n]/.test(value)) throw new CannotRead(`${SET_FILE}: a string in \`${id}\` at ${where()} is not a plain one`);
        out.push(value);
        i = end + 1;
        continue;
      }
      if (source.startsWith("...", i)) {
        const other = /^[A-Za-z_$][A-Za-z0-9_$]*/.exec(source.slice(i + 3));
        if (!other) throw new CannotRead(`${SET_FILE}: \`${id}\` spreads something that is not a name, at ${where()}`);
        out.push(...list(other[0]));
        i += 3 + other[0].length;
        continue;
      }
      throw new CannotRead(
        `${SET_FILE}: \`${id}\` holds something at ${where()} that is neither a quoted path nor a spread of a list ` +
        "in the same file, so the set cannot be read as data");
    }
    open.delete(id);
    return out;
  };
  const entries = list(name);
  const problems = entryProblems(entries);
  if (problems.length) throw new CannotRead(`${SET_FILE}: ${problems.join("; ")}`);
  return entries;
}

const SEGMENT = /^[A-Za-z0-9._-]+$/;

/** The grammar `bot/tests/code-paths.test.mjs` states for an entry, and no entry twice. */
export function entryProblems(entries) {
  const problems = [];
  if (!entries.length) problems.push("the set is empty");
  const seen = new Set();
  for (const e of entries) {
    const segments = entryPath(e).split("/");
    if (!segments.every((s) => SEGMENT.test(s) && s !== "." && s !== "..")) problems.push(`${JSON.stringify(e)} is not a literal path`);
    if (seen.has(entryPath(e))) problems.push(`${JSON.stringify(e)} is in the set twice`);
    seen.add(entryPath(e));
  }
  return problems;
}

/** The path git is asked for: the entry, less the `/` that marks a directory. */
export const entryPath = (entry) => entry.replace(/\/$/, "");

/** Sorted by BYTES. A locale's order puts `.github/` after `bot/` and moves the digest. */
export const sortEntries = (entries) =>
  [...entries].sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));

/** `tracked_set_sha256`: every entry followed by a newline, the last one too. */
export const setDigest = (entries) => sha256(sortEntries(entries).map((e) => `${e}\n`).join(""));

/**
 * Is this path at or beneath the entry? By path component, for both kinds of
 * entry: git resolves `bot/ingest.mjs` to that path and to nothing else, so
 * `bot/ingest.mjs.bak` is outside, and `bot/library/x` is outside `bot/lib/`.
 */
export function covers(entry, p) {
  const at = entryPath(entry);
  return p === at || p.startsWith(`${at}/`);
}

// ── the tree ────────────────────────────────────────────────────────────────

/** `git ls-tree`'s lines, by path. A line of another shape is refused, not skipped. */
export function parseLsTree(text) {
  const rows = new Map();
  for (const line of text.split("\n")) {
    if (!line) continue;
    const m = /^([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40}|[0-9a-f]{64})\t(.+)$/.exec(line);
    if (!m) throw new CannotRead(`a line of git ls-tree is not one: ${JSON.stringify(line.slice(0, 120))}`);
    rows.set(m[4], { mode: m[1], type: m[2], oid: m[3] });
  }
  return rows;
}

/** One line per entry, in the set's order: what `tree_sha256` is taken over. */
export function treeLines(entries, rows) {
  return sortEntries(entries).map((entry) => {
    const row = rows.get(entryPath(entry));
    return { entry, mode: row ? row.mode : "-", oid: row ? row.oid : "-" };
  });
}

export const lineText = (l) => `${l.entry} ${l.mode} ${l.oid}`;
export const treeDigest = (lines) => sha256(lines.map((l) => `${lineText(l)}\n`).join(""));

/** Everything this check knows about one tree: the set it carries, and the tree under that set. */
export function stateOf({ source, tokenText = null, lsTree }) {
  const entries = sortEntries(parseEntries(source));
  let token = null;
  if (tokenText !== null) {
    try {
      const value = JSON.parse(tokenText)?.[TOKEN_MEMBER];
      if (typeof value === "string" && HEX64.test(value)) token = value;
    } catch { /* an unreadable token file names no digest, which is said below */ }
  }
  const lines = treeLines(entries, typeof lsTree === "string" ? parseLsTree(lsTree) : lsTree);
  return {
    entries,
    set: setDigest(entries),
    token,
    lines,
    tree: treeDigest(lines),
    unresolved: lines.filter((l) => l.mode === "-").map((l) => l.entry),
  };
}

/**
 * The base against what `main` would carry.
 *
 * `files` is every path that differs between the two trees, set or not (git's
 * own diff). It is asked a second time, a different way: the entries' lines
 * move exactly when one of those paths is at or beneath an entry, so the two
 * must agree, and where they do not `disagreement` says so and the caller
 * refuses to answer.
 */
export function compare(base, merged, files = []) {
  const setChanged = base.set !== merged.set || (base.token !== null && merged.token !== null && base.token !== merged.token);
  const treeChanged = base.tree !== merged.tree;
  const before = new Map(base.lines.map((l) => [l.entry, l]));
  const after = new Map(merged.lines.map((l) => [l.entry, l]));
  const entries = sortEntries([...new Set([...before.keys(), ...after.keys()])]);
  const changed = [];
  for (const entry of entries) {
    const b = before.get(entry) ?? null;
    const a = after.get(entry) ?? null;
    if (b && a && b.mode === a.mode && b.oid === a.oid) continue;
    changed.push({ entry, base: b, merged: a, files: files.filter((f) => covers(entry, f.path)) });
  }
  // The second asking, under the merge result's set alone, so that a change
  // to the list is not counted as a change to what the list holds.
  const sameEntry = merged.entries.filter((e) => before.has(e));
  const linesMoved = sameEntry.some((e) => before.get(e).mode !== after.get(e).mode || before.get(e).oid !== after.get(e).oid);
  const pathsMoved = files.some((f) => sameEntry.some((e) => covers(e, f.path)));
  const disagreement = linesMoved === pathsMoved ? null :
    `the entries' lines ${linesMoved ? "differ" : "do not differ"} between the two trees, and git's diff of the same ` +
    `two trees ${pathsMoved ? "names" : "names no"} path at or beneath an entry`;
  return {
    setChanged,
    treeChanged,
    added: merged.entries.filter((e) => !before.has(e)),
    removed: base.entries.filter((e) => !after.has(e)),
    changed,
    disagreement,
  };
}

// ── the read of a pre-acknowledgement ───────────────────────────────────────

/** The contract's lifetime of a pre-acknowledgement, and the clock difference allowed on top of it. */
const PROPOSED_LIFETIME_MS = 72 * 3600 * 1000;
const CLOCK_SLACK_MS = 5 * 60 * 1000;
const READ_PATH = "/plugins/v1/trust31/proposed";
const MAX_ANSWER_CHARS = 64 * 1024;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** The address asked, from the service's base address (or from the whole endpoint, which is accepted too). */
export function readEndpoint(base, head) {
  let url;
  try { url = new URL(base); } catch { return null; }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return null;
  const trimmed = url.pathname.replace(/\/+$/, "");
  url.pathname = trimmed.endsWith(READ_PATH) ? trimmed : `${trimmed}${READ_PATH}`;
  url.search = `?head=${head}`;
  return url.href;
}

/**
 * Has the owner acknowledged exactly this tree, at this head, before the merge?
 *
 * The read the service owner agreed (2026-11-10; not deployed when this was
 * written): `GET {service}/plugins/v1/trust31/proposed?head=<40 lowercase
 * hex>`, public, no credential, limited by address. Always 200 for a
 * well-formed head, with `{acknowledged, tree_sha256, tracked_set_sha256,
 * expires_at}`; a head it does not know is `acknowledged: false` and the other
 * three `null`; a malformed head is 422.
 *
 * **`expires_at`'s spelling is not fixed yet**, so both are accepted: Unix
 * seconds as a number, or an RFC 3339 string. A number is held to the
 * contract's 72 hours, because milliseconds read as seconds would be a date
 * fifty thousand years off that never expires. When the service settles on
 * one, drop the other here.
 *
 * `ok` is true for one answer only. Everything else is red with its reason,
 * and `kind` keeps "the service did not answer" (429, 5xx, no connection, 10
 * seconds — run it again later) apart from "not acknowledged" (an answer).
 */
export async function proposedRead({ url, head, set, tree, fetch = globalThis.fetch, now = Date.now(), timeoutMs = 10_000 }) {
  const red = (kind, reason) => ({ ok: false, kind, reason });
  if (!url) return red("unset", NO_READ_YET);
  if (!HEX40.test(head)) return red("misconfigured", "the head is not 40 lowercase hex, so there is nothing to ask about");
  const endpoint = readEndpoint(url, head);
  if (!endpoint) {
    return red("misconfigured", "TRUST31_PROPOSED_READ_URL is not an https address without a credential, a query or a fragment");
  }

  let answer;
  const abort = new AbortController();
  let timer;
  try {
    answer = await Promise.race([
      (async () => {
        const res = await fetch(endpoint, { method: "GET", redirect: "error", signal: abort.signal, headers: { accept: "application/json" } });
        return { status: res.status, text: await res.text() };
      })(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`no answer in ${timeoutMs / 1000} s`)), timeoutMs); }),
    ]);
  } catch (e) {
    abort.abort();
    return red("no-answer", `the service did not answer (${String(e?.message ?? e).split("\n")[0].slice(0, 200)}); run this check again later`);
  } finally {
    clearTimeout(timer);
  }

  const { status, text } = answer;
  if (status === 429 || (Number.isInteger(status) && status >= 500 && status <= 599)) {
    return red("no-answer", `the service did not answer (HTTP ${status}); run this check again later`);
  }
  if (status === 422) return red("refused", "the service calls this head malformed (HTTP 422)");
  if (status !== 200) return red("unreadable", `the service answered HTTP ${JSON.stringify(status)}, which this read does not have`);
  if (typeof text !== "string" || text.length > MAX_ANSWER_CHARS) return red("unreadable", "the service's answer is not a short JSON document");

  let body;
  try { body = JSON.parse(text); } catch { return red("unreadable", "the service's answer is not JSON"); }
  const MEMBERS = ["acknowledged", "expires_at", "tracked_set_sha256", "tree_sha256"];
  if (body === null || typeof body !== "object" || Array.isArray(body) ||
      JSON.stringify(Object.keys(body).sort()) !== JSON.stringify(MEMBERS)) {
    return red("unreadable", `the service's answer is not exactly {${MEMBERS.join(", ")}}`);
  }
  if (body.acknowledged === false) {
    if (body.tree_sha256 !== null || body.tracked_set_sha256 !== null || body.expires_at !== null) {
      return red("unreadable", "the service says `acknowledged: false` beside a value that is not null, which this read does not have");
    }
    return red("not-acknowledged", "the service holds no pre-acknowledgement for this head");
  }
  if (body.acknowledged !== true) return red("unreadable", "`acknowledged` is not true or false");
  if (typeof body.tree_sha256 !== "string" || !HEX64.test(body.tree_sha256) ||
      typeof body.tracked_set_sha256 !== "string" || !HEX64.test(body.tracked_set_sha256)) {
    return red("unreadable", "an acknowledged answer's digests are not 64 lowercase hex each");
  }
  let expires;
  if (typeof body.expires_at === "number" && Number.isFinite(body.expires_at) && body.expires_at > 0) {
    expires = body.expires_at * 1000;
  } else if (typeof body.expires_at === "string" && RFC3339.test(body.expires_at) && Number.isFinite(Date.parse(body.expires_at))) {
    expires = Date.parse(body.expires_at);
  } else {
    return red("unreadable", "`expires_at` is neither Unix seconds nor an RFC 3339 time");
  }
  if (body.tracked_set_sha256 !== set) {
    return red("mismatch", `the acknowledgement was read under another set: the service says tracked_set_sha256 ${body.tracked_set_sha256}, this check computed ${set}`);
  }
  if (body.tree_sha256 !== tree) {
    return red("mismatch", `the acknowledgement is of another tree: the service says tree_sha256 ${body.tree_sha256}, this check computed ${tree}`);
  }
  if (expires <= now) return red("expired", `the acknowledgement expired at ${new Date(expires).toISOString()}`);
  if (expires > now + PROPOSED_LIFETIME_MS + CLOCK_SLACK_MS) {
    return red("unreadable", "`expires_at` is further away than the 72 hours a pre-acknowledgement lasts, so it is not a time this check understands");
  }
  return { ok: true, kind: "acknowledged", reason: `acknowledged, until ${new Date(expires).toISOString()}`, expiresAt: new Date(expires).toISOString() };
}

// ── the report ──────────────────────────────────────────────────────────────

/** A value a pull request chose (a branch, a file name), as inert text. */
export const shown = (value) => `\`${String(value).replace(/[\u0000-\u001f\u007f`]/g, "?").slice(0, 200)}\``;

const fileLine = (f) =>
  `${f.status} ${shown(f.path)}${f.status === "M" && f.modeBefore !== f.modeAfter ? ` (mode ${f.modeBefore} → ${f.modeAfter})` : ""}`;
const side = (l) => (l ? `${l.mode} ${l.oid}` : "(not in the set)");

/**
 * The verdict and the text of it. `read` is `proposedRead`'s answer, asked
 * only when the tree changes and an acknowledgement of this head could cover
 * the merge.
 */
export function report({ base, merged, head, diff, refs, read = null }) {
  const out = [];
  const fork = Boolean(refs.repo && refs.headRepo && refs.repo.toLowerCase() !== refs.headRepo.toLowerCase());
  const changed = diff.setChanged || diff.treeChanged;
  const tokenProblem = merged.token === null
    ? `${TOKEN_FILE} names no \`${TOKEN_MEMBER}\` at the merge result`
    : merged.token !== merged.set
      ? `the registry's copy of the set (${merged.entries.length} entries in ${SET_FILE}, digest ${merged.set}) is not the set the ` +
        `contract's token file names (${merged.token})`
      : null;
  const headCovers = head.set === merged.set && head.tree === merged.tree;

  let verdict;
  let exit;
  if (diff.disagreement) {
    verdict = `${CANNOT_SAY} Asked two ways, it got two answers: ${diff.disagreement}.`;
    exit = 2;
  } else if (tokenProblem) {
    verdict = `${CANNOT_SAY} The service compiles the contract's set, and ${tokenProblem}. The digests below are not ones the site will show.`;
    exit = 1;
  } else if (!changed) {
    verdict = NOT_TOUCHED;
    exit = 0;
  } else if (!fork && headCovers && read?.ok) {
    verdict = `${PRE_ACKNOWLEDGED} Merge it without pushing again, before ${read.expiresAt}.`;
    exit = 0;
  } else {
    verdict = CHANGED;
    exit = 1;
  }

  out.push("## TRUST-31 set", "", `**${verdict}**`, "");

  if (changed && exit === 1 && !tokenProblem) {
    out.push("### What to do", "");
    if (fork) {
      out.push(
        `This pull request comes from a fork (${shown(refs.headRepo)}). **A fork's branch can never be pre-acknowledged**: the ` +
        `contract lets the owner name only a branch of the registry's own repository (${shown(refs.repo)}). A maintainer pushes ` +
        "the same commits to a branch here and opens the pull request from that branch; this check then prints that branch's values.",
        "");
    } else if (!headCovers) {
      out.push(
        "**Update the branch first.** `main` moved inside the tracked set after this branch left it, so the merge result's tree " +
        `(\`tree_sha256\` ${merged.tree}) is not the head's (${head.tree}). An acknowledgement binds a tree: one given for this ` +
        "head would not cover the merge, and the bot would go to shadow anyway. Merge or rebase `main` into the branch, push, " +
        "and take the new head's values from this check's next run.",
        "");
    } else {
      out.push(
        `The owner acknowledges branch ${shown(refs.branch ?? "(branch not given)")} at head \`${refs.head}\` on the site's operator page ` +
        "(Workshop → operator → \"pre-acknowledge\"), comparing the two digests below with what the page shows. Then merge " +
        "within 72 hours and without pushing again: a new head needs a new acknowledgement.",
        "");
    }
  }

  if (changed || tokenProblem) {
    out.push(
      `### The three values, for ${refs.branch ? `branch ${shown(refs.branch)}` : "the head"}`, "",
      "```",
      `job_workflow_sha (candidate: the head)  ${refs.head}`,
      `tracked_set_sha256                      ${head.set}`,
      `tree_sha256                             ${head.tree}`,
      "```", "");
    if (head.unresolved.length) {
      out.push(`Entries that resolve to nothing at the head (${head.unresolved.length}), which the site lists too: ` +
        `${head.unresolved.map(shown).join(", ")}.`, "");
    }
  }

  if (changed && !tokenProblem && !diff.disagreement) {
    out.push("### Pre-acknowledgement", "");
    if (fork) out.push("Not asked: a fork's branch cannot have one.", "");
    else if (!headCovers) out.push("Not asked: an acknowledgement of this head would not cover the merge (above).", "");
    else if (!read) out.push("Not asked.", "");
    else if (read.ok) out.push(`The service answers that this head is ${read.reason}, with the same two digests.`, "");
    else out.push(`${read.kind === "unset" ? "Not asked: " : "Red: "}${read.reason}.`, "");
  }

  out.push("### What was read", "",
    `- base: \`${refs.base}\`${refs.baseNote ? ` (${refs.baseNote})` : ""}`,
    `- head: \`${refs.head}\`${refs.branch ? `, branch ${shown(refs.branch)}` : ""}${refs.headRepo ? ` of ${shown(refs.headRepo)}` : ""}`,
    `- merge result, which is what \`main\` would carry: ${refs.mergedNote}`,
    "",
    "| | `tracked_set_sha256` | `tree_sha256` | entries |",
    "|---|---|---|---|",
    `| base | \`${base.set}\` | \`${base.tree}\` | ${base.entries.length} |`,
    `| merge result | \`${merged.set}\` | \`${merged.tree}\` | ${merged.entries.length} |`,
    `| head | \`${head.set}\` | \`${head.tree}\` | ${head.entries.length} |`,
    "",
    `- the set (which paths count): ${diff.setChanged ? "**changed**" : "unchanged"}` +
      (diff.added.length ? `; added ${diff.added.map(shown).join(", ")}` : "") +
      (diff.removed.length ? `; removed ${diff.removed.map(shown).join(", ")}` : "") +
      (diff.setChanged && !diff.added.length && !diff.removed.length ? "; the token file's digest moved and the list did not" : ""),
    `- the tree (what those paths hold): ${diff.treeChanged ? `**changed**, ${diff.changed.length} ${diff.changed.length === 1 ? "entry's line differs" : "entries' lines differ"}` : "unchanged"}`,
    `- the set's digest against \`${TOKEN_MEMBER}\` in the token file, at the merge result: ${tokenProblem ? "**they disagree**" : "equal"}`,
    "");

  if (diff.changed.length) {
    out.push("### Entries whose line differs, base → merge result", "");
    for (const c of diff.changed) {
      out.push(`- ${shown(c.entry)}: ${side(c.base)} → ${side(c.merged)}`);
      const files = c.files.slice(0, 200);
      for (const f of files) out.push(`  - ${fileLine(f)}`);
      if (c.files.length > files.length) out.push(`  - … and ${c.files.length - files.length} more`);
    }
    out.push("");
  }

  if (refs.ownFiles?.length) {
    out.push(
      `Note: this pull request changes the check itself (${refs.ownFiles.map(shown).join(", ")}). ` +
      (refs.judgedBy ? `It was judged by ${refs.judgedBy}.` : "Read the verdict above as the pull request's own."),
      "");
  }
  return { exit, verdict, text: out.join("\n") };
}

// ── git, and the command line ───────────────────────────────────────────────

function git(dir, args, { fail = true } = {}) {
  try {
    return execFileSync("git", ["-C", dir, ...args],
      { encoding: "utf8", env: cleanEnv(), maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    if (!fail) return null;
    throw new CannotRead(`git ${args.slice(0, 3).join(" ")} …: ${String(e.stderr || e.message).trim().split("\n")[0]}`);
  }
}

const commit = (dir, name) => {
  const out = git(dir, ["rev-parse", "--verify", "--quiet", `${name}^{commit}`], { fail: false });
  if (!out) throw new CannotRead(`${JSON.stringify(name)} is not a commit this checkout has (a shallow clone lacks the base; fetch the history)`);
  return out.trim();
};

/** The state of one tree-ish, read out of git objects and never out of the working tree. */
export function readState(dir, treeish) {
  const source = git(dir, ["show", `${treeish}:${SET_FILE}`], { fail: false });
  if (source === null) throw new CannotRead(`${SET_FILE} is not in ${treeish}, so the set cannot be read there`);
  const entries = parseEntries(source);
  const lsTree = git(dir, ["ls-tree", "--full-tree", treeish, "--", ...entries.map(entryPath)]);
  return stateOf({ source, tokenText: git(dir, ["show", `${treeish}:${TOKEN_FILE}`], { fail: false }), lsTree });
}

/** Every path that differs between two trees, whether the set names it or not. */
export function diffFiles(dir, a, b) {
  const raw = git(dir, ["diff-tree", "-r", "--no-renames", "--raw", "--no-abbrev", "-z", a, b]).split("\0");
  const files = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const m = /^:([0-7]{6}) ([0-7]{6}) [0-9a-f]+ [0-9a-f]+ ([A-Z])$/.exec(raw[i]);
    if (!m) throw new CannotRead(`a record of git diff-tree is not one: ${JSON.stringify(raw[i].slice(0, 120))}`);
    files.push({ status: m[3], path: raw[i + 1], modeBefore: m[1], modeAfter: m[2] });
  }
  return files;
}

const USAGE = `usage:
  node tools/trust31-pr-check.mjs --base <commit> --head <commit> [--merge <commit>] [--branch <name>]
                                  [--repo <owner/name>] [--head-repo <owner/name>] [--dir <checkout>]
                                  [--read-url <service>] [--judged-by <text>]
  node tools/trust31-pr-check.mjs --merge <merge commit>
  node tools/trust31-pr-check.mjs --at <commit> [--expect-set <hex>] [--expect-tree <hex>]`;

function parseArgs(argv) {
  const known = ["base", "head", "merge", "branch", "repo", "head-repo", "dir", "read-url", "judged-by", "at", "expect-set", "expect-tree"];
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i].startsWith("--") ? argv[i].slice(2) : null;
    if (!name || !known.includes(name) || argv[i + 1] === undefined || name in args) return null;
    args[name] = argv[i + 1];
  }
  return args;
}

export async function main(argv = process.argv.slice(2), { env = process.env, write = (s) => process.stdout.write(s), fetch = globalThis.fetch } = {}) {
  const args = parseArgs(argv);
  if (!args || !(args.at || args.merge || (args.base && args.head))) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const dir = args.dir ?? process.cwd();
  const emit = (text) => {
    write(`${text}\n`);
    if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, `${text}\n`);
  };

  try {
    if (args.at) {
      const at = commit(dir, args.at);
      const state = readState(dir, at);
      const wrong = [];
      if (args["expect-set"] && args["expect-set"] !== state.set) wrong.push(`tracked_set_sha256 is ${state.set}, and ${args["expect-set"]} was expected`);
      if (args["expect-tree"] && args["expect-tree"] !== state.tree) wrong.push(`tree_sha256 is ${state.tree}, and ${args["expect-tree"]} was expected`);
      write([
        `job_workflow_sha    ${at}`,
        `tracked_set_sha256  ${state.set}   (${state.entries.length} entries${state.token === state.set ? ", the token file's digest" : ", NOT the token file's digest"})`,
        `tree_sha256         ${state.tree}   (${state.unresolved.length} resolving to nothing${state.unresolved.length ? `: ${state.unresolved.join(", ")}` : ""})`,
        ...wrong.map((w) => `WRONG: ${w}`),
        "",
      ].join("\n"));
      return wrong.length ? 1 : 0;
    }

    let base = args.base ? commit(dir, args.base) : null;
    let head = args.head ? commit(dir, args.head) : null;
    let baseNote = null;
    let mergedTree;
    let mergedNote;
    if (args.merge) {
      const merge = commit(dir, args.merge);
      const [first, second, ...more] = git(dir, ["show", "--no-patch", "--format=%P", merge]).trim().split(" ");
      if (!first || !second || more.length) throw new CannotRead(`${merge} is not a merge of two commits`);
      if (head && head !== second) throw new CannotRead(`${merge} merges ${second}, and the head named is ${head}`);
      head = second;
      baseNote = base && base !== first
        ? `the merge commit's first parent; \`--base\` named ${base}, which \`main\` has left since`
        : "the merge commit's first parent";
      base = first;
      mergedTree = merge;
      mergedNote = `commit \`${merge}\`, the pull request's merge commit`;
    } else {
      const written = git(dir, ["merge-tree", "--write-tree", "--no-messages", base, head], { fail: false });
      const tree = written?.split("\n")[0].trim();
      if (tree && HEX40.test(tree)) {
        mergedTree = tree;
        mergedNote = `tree \`${tree}\`, which \`git merge-tree\` writes for the base and the head (no merge commit was given)`;
      } else {
        mergedTree = head;
        mergedNote = `**not available**: the two do not merge cleanly here, so the head \`${head}\` was read in its place`;
      }
    }

    const baseState = readState(dir, base);
    const mergedState = readState(dir, mergedTree);
    const headState = readState(dir, head);
    const files = diffFiles(dir, base, mergedTree);
    const diff = compare(baseState, mergedState, files);
    const fork = Boolean(args.repo && args["head-repo"] && args.repo.toLowerCase() !== args["head-repo"].toLowerCase());
    const headCovers = headState.set === mergedState.set && headState.tree === mergedState.tree;
    const read = (diff.setChanged || diff.treeChanged) && !fork && headCovers && mergedState.token === mergedState.set
      ? await proposedRead({ url: args["read-url"] ?? env.TRUST31_PROPOSED_READ_URL ?? "", head, set: headState.set, tree: headState.tree, fetch })
      : null;
    const result = report({
      base: baseState, merged: mergedState, head: headState, diff, read,
      refs: {
        base, baseNote, head, mergedNote,
        branch: args.branch || null, repo: args.repo || null, headRepo: args["head-repo"] || null,
        ownFiles: OWN_FILES.filter((p) => files.some((f) => f.path === p)),
        judgedBy: args["judged-by"] || null,
      },
    });
    emit(result.text);
    if (env.GITHUB_ACTIONS === "true") write(`::${result.exit === 0 ? "notice" : "error"} title=TRUST-31 set::${result.verdict.split(". ")[0]}\n`);
    return result.exit;
  } catch (e) {
    if (!(e instanceof CannotRead)) throw e;
    emit(`## TRUST-31 set\n\n**${CANNOT_SAY}** ${e.message}\n`);
    return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // A crash is not a verdict: 2, not the 1 that means "changed".
  process.exit(await main().catch((e) => { process.stderr.write(`${e?.stack ?? e}\n`); return 2; }));
}
