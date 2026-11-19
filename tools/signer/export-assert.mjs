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
//   (b) when repository variable `ASTRA_EXPORT_URL` is set, the export, fetched
//       with a bot OIDC token (bot/lib/oidc.mjs, environment `plugins-service`;
//       no stored secret), and its `state_sha256` compared with (a) and with
//       the digest of its own files. Unset, the answer is "not asked": it is
//       reported as that, and never as equal;
//   (c) every commit in `<last signed Source-Commit>..<Source-Commit>` that
//       touches plugins/ or log/ is authored AND committed by one of the
//       identities the committing workflows configure, `BOT_IDENTITIES`; any
//       other is named;
//   (d) any "no" makes the job's status red with a fixed code, which the alert
//       job folds into the run's ONE verdict (tools/signer/verdict.mjs).
//
// The status is the job's output, never its exit code: exit 1 means this
// script could not ask at all, which the verdict also reports, as a job that
// did not report. Neither can reach the signature: `publish` does not wait for
// this job.
//
// (c) reads git's author and committer fields, which whoever pushes can type.
// It catches a hand edit or a merged pull request, not a forger with push
// access; the ruleset of design §2.5 is what closes that.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

import { API_BASE } from "../../bot/lib/service.mjs";
import { mintToken } from "../../bot/lib/oidc.mjs";
import { STATE_ROOTS, exportFiles, stateAt, stateSha256 } from "../lib/export-state.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { signedCommits } from "../served-set/provenance.mjs";
import { gitMaybe, gitText } from "./git.mjs";
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
});

export const FETCH_TIMEOUT_MS = 60_000;

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

/**
 * Why `url` may not be sent a bot token, or `null`. The token speaks for this
 * registry, so it goes to the service's own base and nowhere a typo in a
 * variable could point it.
 */
export function exportUrlProblem(url) {
  if (!url.startsWith(API_BASE)) return `${EXPORT_URL_VAR} is not under ${API_BASE}, and a bot token is sent nowhere else`;
  return null;
}

/**
 * The export, fetched with one bot token, or why not.
 *
 * Nothing about the token reaches a returned string: errors carry the HTTP
 * status, never a header or the body.
 */
export async function fetchExport({ url, env = process.env, fetchImpl = fetch, mint = mintToken, log = console }) {
  const bad = exportUrlProblem(url);
  if (bad) return { ok: false, error: bad };
  let token;
  try {
    ({ token } = await mint({ env, fetchImpl, log }));
  } catch (e) {
    return { ok: false, error: `no bot token: ${String(e?.message ?? e).split("\n")[0]}` };
  }
  let res;
  try {
    res = await fetchImpl(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json", "User-Agent": "astra-registry-bot" },
      redirect: "manual",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (e) {
    return { ok: false, error: `the export could not be reached: ${e?.name ?? "error"}` };
  }
  if (!res.ok) return { ok: false, error: `the export answered HTTP ${res.status}` };
  try {
    return { ok: true, doc: await res.json() };
  } catch {
    return { ok: false, error: "the export answered 2xx with something that is not JSON" };
  }
}

/**
 * (a) to (d) at one Source-Commit.
 *
 * @param {{
 *   root?: string, sourceCommit: string, signedRef: string|null,
 *   env?: NodeJS.ProcessEnv, fetchImpl?: typeof fetch, mint?: typeof mintToken, log?: Console,
 * }} opts
 */
export async function assertExport({ root = REPO_ROOT, sourceCommit, signedRef, env = process.env, fetchImpl = fetch, mint = mintToken, log = console }) {
  const lines = [];
  const codes = [];
  const hexes = [sourceCommit];

  // (a)
  const tree = stateAt({ root, commit: sourceCommit });
  const serial = serialAt({ root, commit: sourceCommit });
  lines.push(`ok    Source-Commit ${sourceCommit}: serial ${serial}, ${tree.files.size} files, state_sha256 ${tree.state_sha256}`);

  // (b)
  let exportAnswer;
  const url = String(env[EXPORT_URL_VAR] ?? "").trim();
  if (!url) {
    exportAnswer = "not-asked";
    lines.push(`note  export: not asked (${EXPORT_URL_VAR} is unset). Nothing was compared; this is not a pass.`);
  } else {
    const got = await fetchExport({ url, env, fetchImpl, mint, log });
    if (!got.ok) {
      exportAnswer = "unreachable";
      codes.push(CODES.unreachable);
      lines.push(`FAIL  export: ${got.error}`);
    } else {
      const { files, problems } = exportFiles(got.doc);
      const own = stateSha256(files);
      const claimed = got.doc?.state_sha256;
      const wrong = [...problems];
      if (claimed !== own) wrong.push(`its state_sha256 ${claimed} is not the digest of its own files, ${own}`);
      if (claimed !== tree.state_sha256) wrong.push(`its state_sha256 ${claimed} is not the Source-Commit's, ${tree.state_sha256}`);
      if (wrong.length) {
        exportAnswer = "differs";
        codes.push(CODES.stateMismatch);
        lines.push(`FAIL  export at serial ${got.doc?.serial} (Source-Commit serial ${serial}):`, ...wrong.map((w) => `      ${w}`));
      } else {
        exportAnswer = "equal";
        lines.push(`ok    export at serial ${got.doc?.serial}: state_sha256 equal`);
      }
    }
  }

  // (c)
  let authors;
  const base = signedRef ? lastSignedSource({ root, ref: signedRef, sourceCommit }) : { sha: null, reason: "no `signed` head was read" };
  if (!base.sha) {
    authors = "no-base";
    codes.push(CODES.noBase);
    lines.push(`FAIL  authors: not checked, ${base.reason}`);
  } else {
    const foreign = foreignCommits({ root, base: base.sha, head: sourceCommit });
    if (foreign.length) {
      authors = "foreign";
      codes.push(CODES.foreignCommit);
      hexes.push(...foreign.map((f) => f.sha));
      lines.push(
        `FAIL  ${foreign.length} commit(s) since ${base.sha.slice(0, 12)} change ${STATE_ROOTS.map((r) => `${r}/`).join(" or ")} and ` +
        `are not the bot's (${BOT_IDENTITIES.map((b) => b.name).join(" or ")}):`,
        ...foreign.map((f) => `      ${f.sha} author ${f.author}, committer ${f.committer}`),
      );
    } else {
      authors = "bot-only";
      lines.push(`ok    authors: every change to ${STATE_ROOTS.join("/ and ")}/ since ${base.sha.slice(0, 12)} is the bot's`);
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
