#!/usr/bin/env node
// Phase 2 step 2: the pre-sign assertion, asked and reported, never enforced.
//
//   node tools/signer/export-assert.mjs --source-commit <sha>
//
// plugin-phase2-design-2026-11-19 §4 step 4 makes signing conditional on two
// facts about the Source-Commit: its plugins/** and log/** digest equals the
// plugins service's export, and every change to them since the last signing
// came from the export. Until the service's `/export` is live and the staging
// replay agrees with it (§6 step 2), `sign.yml` signs exactly as it did and
// runs this BESIDE it, in a job of its own after `publish`, so that a "no"
// here is an alert and never a withheld catalogue:
//
//   (a) `state_sha256` of the Source-Commit's tree (tools/lib/export-state.mjs);
//   (b) when repository variable `ASTRA_EXPORT_URL` names the service's
//       origin, the export with a bot OIDC token (bot/lib/oidc.mjs, environment
//       `plugins-service`; no stored secret), read up to 64 MiB. It is asked BY
//       COMMIT, `GET <origin>/plugins/v1/export?commit=<Source-Commit>`: the
//       service's serial is its own database sequence, not DEC-9's count, so a
//       serial computed here names nothing over there. Once export commits
//       carry an `Export-Serial:` trailer, the newest one in the Source-Commit's
//       history is asked by that serial instead (`?serial=N`) and compared with
//       that commit's tree. A 200 is compared with the tree and with the digest
//       of its own files; a 404, and a 200 at another serial than the one
//       asked, are the service being elsewhere — a note, never a mismatch; any
//       other answer is unreachable. Unset, the answer is "not asked": reported
//       as that, and never as equal. A service that never lets a comparison
//       happen does not stay green: `export-alert` raises
//       SIGNER_EXPORT_NOT_COMPARED after 24 hours of asking without one
//       (tools/signer/export-memory.mjs);
//   (c) every commit in `<last signed Source-Commit>..<Source-Commit>` that
//       touches plugins/ or log/ is authored AND committed by one of the
//       identities the committing workflows configure, `BOT_IDENTITIES`, or
//       belongs to a pull request merged into main (a note); any other is
//       named, and is one of the job's `hexes`. A merged pull request is a
//       NOTE only while this is assert-only: the step-4 gate must also require
//       an approving review by somebody who is not the pull request's author;
//   (d) any "no" makes the job's status red with a fixed code. The job has
//       its own alert (`export-alert` in sign.yml, check `signer-export`), with
//       its own state, keyed on the foreign commits alone: each one pages once,
//       and an outage that persists pages once (bot/alert.mjs NO_REPEAT_CHECKS).
//
// The status is the job's output, never its exit code: exit 1 means this
// script could not ask at all, which the alert also reports, as a job that
// did not report. Neither can reach the signature: `publish` does not wait for
// this job.
//
// Nothing the service answers is printed as it came: digests and serials are
// printed when they have their grammar and as a quoted 80-character prefix
// otherwise.
//
// (c) reads git's author and committer fields, which whoever pushes can type.
// It catches a hand edit pushed straight to main, not a forger with push
// access; the ruleset of design §2.5 is what closes that.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

import { mintToken } from "../../bot/lib/oidc.mjs";
import { STATE_ROOTS, exportFiles, stateAt, stateSha256 } from "../lib/export-state.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { signedCommits, trailersOf } from "../served-set/provenance.mjs";
import { gitMaybe, gitText } from "./git.mjs";
import { NOT_COMPARED_CODE } from "./export-memory.mjs";
import { fetchSignedHead } from "./plan.mjs";
import { serialAt } from "../export-stub.mjs";

/** The variable that turns (b) on. */
export const EXPORT_URL_VAR = "ASTRA_EXPORT_URL";

/**
 * The git identities the committing workflows set before they commit
 * (`git config user.name` / `user.email`): `astra-registry-bot` in
 * plugins-ingest.yml, plugins-moderation.yml, operator.yml and baseline.yml,
 * `github-actions[bot]` in keepalive.yml and publisher-recheck.yml.
 * `bot/tests/export-assert.test.mjs` reads every workflow and fails when one
 * commits as anybody else, so a workflow cannot start committing under a third
 * name and be reported here as a stranger.
 */
export const BOT_IDENTITIES = Object.freeze([
  Object.freeze({ name: "astra-registry-bot", email: "bot@users.noreply.github.com" }),
  Object.freeze({ name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" }),
]);

const isBot = (name, email) => BOT_IDENTITIES.some((b) => b.name === name && b.email === email);

/** The verdict codes this job can report. Fixed, because the channel refuses a sentence. */
export const CODES = Object.freeze({
  stateMismatch: "SIGNER_EXPORT_STATE_MISMATCH",
  unreachable: "SIGNER_EXPORT_UNREACHABLE",
  foreignCommit: "SIGNER_EXPORT_FOREIGN_COMMIT",
  noBase: "SIGNER_EXPORT_NO_SIGNED_BASE",
  // Raised by export-alert, not by this job (tools/signer/export-memory.mjs):
  // only that job holds the memory of when a comparison last happened.
  notCompared: NOT_COMPARED_CODE,
});

export const FETCH_TIMEOUT_MS = 45_000;

const SHA_RE = /^[0-9a-f]{40}$/;

/**
 * The Source-Commit of the newest `signed` commit that signed something
 * BEFORE this one: its `Source-Commit:` trailer differs from `sourceCommit` and
 * is an ancestor of it. This job runs after `publish`, whose commit (if any)
 * names `sourceCommit` itself and is skipped.
 *
 * @param {{root: string, ref: string, sourceCommit: string}} opts
 * @returns {{sha: string|null, reason: string|null}}
 */
export function lastSignedSource({ root, ref, sourceCommit }) {
  for (const c of signedCommits({ root, ref })) {
    const src = c.trailers["Source-Commit"];
    if (!SHA_RE.test(src ?? "") || src === sourceCommit) continue;
    if (!gitMaybe(["merge-base", "--is-ancestor", src, sourceCommit], { root }).ok) {
      return { sha: null, reason: `${ref}'s last Source-Commit ${src.slice(0, 12)} is not an ancestor of ${sourceCommit.slice(0, 12)}` };
    }
    return { sha: src, reason: null };
  }
  return { sha: null, reason: `no commit on ${ref} names a Source-Commit before ${sourceCommit.slice(0, 12)}` };
}

const UNIT = "\u001f";
const RECORD = "\u001e";

/**
 * The commits in `base..head` that touch plugins/ or log/ and were not both
 * authored and committed as one of `BOT_IDENTITIES`.
 *
 * @param {{root: string, base: string, head: string}} opts
 * @returns {{sha: string, author: string, committer: string}[]}
 */
export function foreignCommits({ root, base, head }) {
  const out = gitText(
    ["log", `--format=%H${UNIT}%an${UNIT}%ae${UNIT}%cn${UNIT}%ce`, `${base}..${head}`, "--", ...STATE_ROOTS],
    { root },
  );
  return out.split("\n").filter(Boolean).map((l) => l.split(UNIT))
    .filter(([, an, ae, cn, ce]) => !isBot(an, ae) || !isBot(cn, ce))
    .map(([sha, an, ae, cn, ce]) => ({ sha, author: `${an} <${ae}>`, committer: `${cn} <${ce}>` }));
}

/** The one origin and path a bot token is ever sent to. */
export const EXPORT_ORIGIN = "https://api.minice.ai";
export const EXPORT_PATH = "/plugins/v1/export";

/** The most of an answer this job reads before it parses anything. */
export const MAX_EXPORT_BYTES = 64 * 1024 * 1024;

/**
 * The export URL for `query` — `{commit}` or `{serial}` — built from the
 * variable's ORIGIN and this file's path, or why not.
 *
 * The variable names the service, and only the service: an origin with no
 * path, query, fragment or credentials. The path is appended here, so no
 * spelling in the variable — a `..`, a `%2e`, a prefix that merely starts
 * like the base — can aim the token anywhere but `EXPORT_ORIGIN` +
 * `EXPORT_PATH`. Both are checked again on the URL that is built.
 *
 * @returns {{url: URL, problem: null} | {url: null, problem: string}}
 */
export function exportUrl(base, query) {
  const refuse = (why) => ({ url: null, problem: `${EXPORT_URL_VAR} ${why}; it is the service's origin, ${EXPORT_ORIGIN}, and nothing else` });
  let b;
  try {
    b = new URL(String(base));
  } catch {
    return refuse("is not a URL");
  }
  if (b.username || b.password) return refuse("carries credentials");
  if (b.search || b.hash || String(base).includes("?") || String(base).includes("#")) return refuse("carries a query or a fragment");
  if (b.pathname !== "/" || /%2e|\.\./i.test(String(base).slice(b.origin.length))) return refuse("carries a path");
  if (b.origin !== EXPORT_ORIGIN) return refuse(`names ${JSON.stringify(b.origin).slice(0, 80)}`);
  const url = new URL(EXPORT_PATH, b.origin);
  if (query && typeof query === "object" && SHA_RE.test(query.commit ?? "")) url.searchParams.set("commit", query.commit);
  else if (query && typeof query === "object" && Number.isSafeInteger(query.serial) && query.serial >= 0) url.searchParams.set("serial", String(query.serial));
  else return refuse("cannot be asked for that: the query is a 40-hex commit or a non-negative serial");
  if (url.origin !== EXPORT_ORIGIN || url.pathname !== EXPORT_PATH) return refuse("does not build the export's URL");
  return { url, problem: null };
}

/** `v` as a person may safely read it in a public log: short, quoted, one line. */
export const shown = (v) => String(JSON.stringify(v) ?? "undefined").slice(0, 80);
const HEX64 = /^[0-9a-f]{64}$/;
const showDigest = (v) => (typeof v === "string" && HEX64.test(v) ? v : shown(v));
const showSerial = (v) => (Number.isSafeInteger(v) ? String(v) : shown(v));

/**
 * The body, read up to `limit` bytes and no further, as text; or why not.
 * Counted on the bytes, not on a header, because a header is the server's
 * claim about the body.
 */
export async function readCapped(res, limit = MAX_EXPORT_BYTES) {
  if (!res.body) return { ok: true, text: "" };
  const reader = res.body.getReader();
  const chunks = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > limit) {
      await reader.cancel().catch(() => {});
      return { ok: false, error: `the answer is larger than ${limit} bytes, and nothing past that is read` };
    }
    chunks.push(value);
  }
  return { ok: true, text: Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8") };
}

/**
 * The export at `serial`, fetched with one bot token. One of:
 *
 *   {kind: "export", doc}                      200, a JSON document
 *   {kind: "elsewhere", current}               404: the service holds no
 *                                              state for what was asked;
 *                                              `current` is its `current_serial`
 *                                              when it says one, else null
 *   {kind: "unreachable", error}               anything else
 *
 * Nothing about the token, and no text of the answer, reaches a returned
 * string: errors carry the HTTP status, and values only through `shown`.
 */
export async function fetchExport({ base, query, env = process.env, fetchImpl = fetch, mint = mintToken, log = console }) {
  const { url, problem } = exportUrl(base, query);
  if (problem) return { kind: "unreachable", error: problem };
  let token;
  try {
    ({ token } = await mint({ env, fetchImpl, log }));
  } catch (e) {
    return { kind: "unreachable", error: `no bot token: ${String(e?.message ?? e).split("\n")[0]}` };
  }
  let res;
  try {
    res = await fetchImpl(url.href, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json", "User-Agent": "astra-registry-bot" },
      redirect: "manual",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (e) {
    return { kind: "unreachable", error: `the export could not be reached: ${e?.name ?? "error"}` };
  }
  if (res.status !== 200 && res.status !== 404) {
    await res.body?.cancel?.().catch(() => {});
    return { kind: "unreachable", error: `the export answered HTTP ${res.status}` };
  }
  let body;
  try {
    const read = await readCapped(res);
    if (!read.ok) return { kind: "unreachable", error: read.error };
    body = res.status === 404 ? (() => { try { return JSON.parse(read.text); } catch { return null; } })() : JSON.parse(read.text);
  } catch {
    return { kind: "unreachable", error: `the export answered HTTP ${res.status} with something that is not JSON` };
  }
  // A 404 alone is a note: the service holds nothing for what was asked. Its
  // `current_serial` is reported when it has the grammar, and nothing else is.
  if (res.status === 404) return { kind: "elsewhere", current: body?.current_serial ?? null };
  return { kind: "export", doc: body };
}

/** The trailer an export commit will carry (design §4 step 2). */
export const EXPORT_SERIAL_TRAILER = "Export-Serial";

/**
 * The newest commit in `sourceCommit`'s history whose message carries an
 * `Export-Serial:` trailer, with that serial; or null while none does.
 *
 * @returns {{sha: string, serial: number} | null}
 */
export function exportSerialAt({ root, sourceCommit }) {
  const out = gitText(
    ["log", "-E", `--grep=^${EXPORT_SERIAL_TRAILER}: [0-9]+$`, `--format=%H${UNIT}%B${RECORD}`, sourceCommit],
    { root },
  );
  for (const rec of out.split(RECORD).map((r) => r.trim()).filter(Boolean)) {
    const [sha, ...body] = rec.split(UNIT);
    const v = trailersOf(body.join(UNIT))[EXPORT_SERIAL_TRAILER];
    const n = Number(v);
    if (/^[0-9]+$/.test(v ?? "") && Number.isSafeInteger(n)) return { sha: sha.trim(), serial: n };
  }
  return null;
}

/**
 * Does GitHub say `sha` belongs to a pull request merged into `main`?
 * `GET /repos/{repo}/commits/{sha}/pulls` with the job's read-only token.
 *
 * @returns {Promise<{merged: number|null, error: string|null}>} the PR number, or null
 */
export async function mergedPullOf({ sha, env = process.env, fetchImpl = fetch }) {
  const repo = env.GITHUB_REPOSITORY;
  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) return { merged: null, error: "GITHUB_REPOSITORY is not set" };
  const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "astra-registry-bot" };
  if (env.GITHUB_TOKEN) headers.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  let res;
  try {
    res = await fetchImpl(`https://api.github.com/repos/${repo}/commits/${sha}/pulls`, {
      headers, redirect: "manual", signal: AbortSignal.timeout(20_000),
    });
  } catch (e) {
    return { merged: null, error: `GitHub could not be reached: ${e?.name ?? "error"}` };
  }
  if (res.status !== 200) return { merged: null, error: `GitHub answered HTTP ${res.status}` };
  let pulls;
  try {
    const read = await readCapped(res, 4 * 1024 * 1024);
    pulls = read.ok ? JSON.parse(read.text) : null;
  } catch {
    pulls = null;
  }
  if (!Array.isArray(pulls)) return { merged: null, error: "GitHub's answer is not a list of pull requests" };
  const pr = pulls.find((p) => p?.merged_at && p?.base?.ref === "main" && Number.isSafeInteger(p?.number));
  return { merged: pr ? pr.number : null, error: null };
}

/**
 * (a) to (d) at one Source-Commit.
 *
 * `hexes` are the foreign commits and nothing else: the alert state keys a
 * page on (code, hex), so a hex that moved with every head — the
 * Source-Commit — would page about the same old commit on every head.
 *
 * @param {{
 *   root?: string, sourceCommit: string, signedRef: string|null,
 *   env?: NodeJS.ProcessEnv, fetchImpl?: typeof fetch, mint?: typeof mintToken,
 *   pullOf?: typeof mergedPullOf, log?: Console,
 * }} opts
 */
export async function assertExport({
  root = REPO_ROOT, sourceCommit, signedRef, env = process.env, fetchImpl = fetch, mint = mintToken,
  pullOf = mergedPullOf, log = console,
}) {
  const lines = [];
  const codes = [];
  const hexes = [];

  // (a)
  const tree = stateAt({ root, commit: sourceCommit });
  const serial = serialAt({ root, commit: sourceCommit });
  lines.push(`ok    Source-Commit ${sourceCommit}: serial ${serial}, ${tree.files.size} files, state_sha256 ${tree.state_sha256}`);

  // (b)
  let exportAnswer;
  const base = String(env[EXPORT_URL_VAR] ?? "").trim();
  if (!base) {
    exportAnswer = "not-asked";
    lines.push(`note  export: not asked (${EXPORT_URL_VAR} is unset). Nothing was compared; this is not a pass.`);
  } else {
    // By trailer once export commits carry one, by commit until then.
    const trailer = exportSerialAt({ root, sourceCommit });
    const query = trailer ? { serial: trailer.serial } : { commit: sourceCommit };
    const against = trailer && trailer.sha !== sourceCommit ? stateAt({ root, commit: trailer.sha }) : tree;
    const asked = trailer ? `serial ${trailer.serial} (${EXPORT_SERIAL_TRAILER} of ${trailer.sha.slice(0, 12)})` : `commit ${sourceCommit.slice(0, 12)}`;
    const got = await fetchExport({ base, query, env, fetchImpl, mint, log });
    if (got.kind === "unreachable") {
      exportAnswer = "unreachable";
      codes.push(CODES.unreachable);
      lines.push(`FAIL  export: ${got.error}`);
    } else if (got.kind === "elsewhere" || (trailer && got.doc?.serial !== trailer.serial)) {
      // The service holds nothing for what was asked, or answers another
      // serial: a lag or a lead, not a different state. Reported, never
      // compared, and never paged by itself (export-memory.mjs pages a
      // service that never lets a comparison happen).
      exportAnswer = "other-serial";
      const at = got.kind === "elsewhere" ? got.current : got.doc?.serial;
      lines.push(`note  export: service at serial ${at === null ? "(not said)" : showSerial(at)}, asked for ${asked}; nothing was compared`);
    } else {
      const { files, problems } = exportFiles(got.doc);
      const own = stateSha256(files);
      const claimed = got.doc?.state_sha256;
      const wrong = problems.length ? [`${problems.length} of its files cannot be read (first: ${shown(problems[0])})`] : [];
      if (claimed !== own) wrong.push(`its state_sha256 ${showDigest(claimed)} is not the digest of its own files, ${own}`);
      if (claimed !== against.state_sha256) wrong.push(`its state_sha256 ${showDigest(claimed)} is not the tree's, ${against.state_sha256}`);
      if (wrong.length) {
        exportAnswer = "differs";
        codes.push(CODES.stateMismatch);
        lines.push(`FAIL  export for ${asked}:`, ...wrong.map((w) => `      ${w}`));
      } else {
        exportAnswer = "equal";
        lines.push(`ok    export for ${asked}: state_sha256 equal`);
      }
    }
  }

  // (c)
  let authors;
  const since = signedRef ? lastSignedSource({ root, ref: signedRef, sourceCommit }) : { sha: null, reason: "no `signed` head was read" };
  if (!since.sha) {
    authors = "no-base";
    codes.push(CODES.noBase);
    lines.push(`FAIL  authors: not checked, ${since.reason}`);
  } else {
    const foreign = [];
    const merged = [];
    for (const f of foreignCommits({ root, base: since.sha, head: sourceCommit })) {
      // A merged pull request is an approved change (design §4 step 4): a
      // note. A lookup that fails counts the commit as foreign.
      const pr = await pullOf({ sha: f.sha, env, fetchImpl });
      if (pr.merged !== null) merged.push({ ...f, pr: pr.merged });
      else foreign.push({ ...f, lookup: pr.error });
    }
    for (const m of merged) lines.push(`note  ${m.sha} (author ${m.author}) is pull request #${m.pr}, merged into main`);
    if (foreign.length) {
      authors = "foreign";
      codes.push(CODES.foreignCommit);
      hexes.push(...foreign.map((f) => f.sha));
      lines.push(
        `FAIL  ${foreign.length} commit(s) since ${since.sha.slice(0, 12)} change ${STATE_ROOTS.map((r) => `${r}/`).join(" or ")}, ` +
        `are not the bot's (${BOT_IDENTITIES.map((b) => b.name).join(" or ")}) and are no merged pull request's:`,
        ...foreign.map((f) => `      ${f.sha} author ${f.author}, committer ${f.committer}${f.lookup ? ` (not asked of GitHub: ${f.lookup})` : ""}`),
      );
    } else {
      authors = merged.length ? "bot-or-merged" : "bot-only";
      lines.push(`ok    authors: every change to ${STATE_ROOTS.join("/ and ")}/ since ${since.sha.slice(0, 12)} is the bot's or a merged pull request's`);
    }
  }

  // (d)
  return {
    status: codes.length ? "red" : "green",
    codes,
    hexes,
    export: exportAnswer,
    authors,
    serial,
    state_sha256: tree.state_sha256,
    lines,
  };
}

function parseArgs(argv) {
  const args = { sourceCommit: null, root: REPO_ROOT };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--source-commit") args.sourceCommit = argv[++i];
    else if (argv[i] === "--registry") args.root = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (!SHA_RE.test(args.sourceCommit ?? "")) throw new Error("--source-commit takes the 40-hex Source-Commit");
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);
  const head = fetchSignedHead({ root: args.root });
  const result = await assertExport({ root: args.root, sourceCommit: args.sourceCommit, signedRef: head.present ? head.ref : null });
  for (const l of result.lines) console.log(l);
  console.log(`${result.status === "green" ? "ok  " : "FAIL"}  assert-only: export ${result.export}, authors ${result.authors}; ` +
    "signing was not and is not affected");
  const outputs = { status: result.status, codes: result.codes.join(" "), hexes: result.hexes.join(" "), export: result.export, authors: result.authors };
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(outputs).map(([k, v]) => `${k}=${v}\n`).join(""));
  }
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Export assertion (assert-only)\n\n\`\`\`\n${result.lines.join("\n")}\n\`\`\`\n`);
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(await main(process.argv.slice(2)));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(1);
  }
}
