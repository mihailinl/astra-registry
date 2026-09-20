#!/usr/bin/env node
// The one verdict `served-set.yml`'s alert job sends, built from what its two
// comparison jobs reported.
//
//     node tools/served-set/compose.mjs --out verdict.json
//
// Two jobs, one receiver check, one alarm (registry plan RC-R1-5: "Same
// `alert` job"; `bot/lib/alert-checks.mjs`: SERVE-85 and SERVE-39 are one
// heartbeat because two would page twice for one silence).
//
// **Why this is a module and not a heredoc in the workflow.** The alert job's
// inputs are two other jobs' string outputs, and everything that can go wrong
// with them goes wrong at the worst moment. A code the channel refuses makes
// `bot/lib/alert-verdict.mjs` refuse the whole verdict, so the alarm about a
// real drift is never sent; a job that crashed before writing its outputs
// hands this one empty strings, and an empty string is indistinguishable from
// "nothing to report" unless somebody decided otherwise. Both are decisions,
// both need a test, and a rule inside a workflow step is a rule with no test.
//
// So the two rules this file exists for:
//
//   1. **a job that did not report is red.** `result` is GitHub's own word for
//      what happened to the job — `success`, `failure`, `cancelled`, `skipped`
//      — and anything but `success`, or a `success` with no status in it, is a
//      comparison that did not happen. A missing comparison is not a passing
//      one;
//   2. **an unrenderable finding still sends an alarm.** Anything that fails
//      the channel's grammar is dropped and replaced by one fixed code, rather
//      than being passed through to make the verdict unsendable. The operator
//      gets a page saying something is wrong and a run URL; the alternative is
//      a red job, silence, and a heartbeat that never posts because the alarm
//      step failed first.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

import { CODE_PATTERN, VERDICT_SCHEMA, runUrl, verdictProblems } from "../../bot/lib/alert-verdict.mjs";

const CODE_RE = new RegExp(CODE_PATTERN);
const SHA_RE = /^[0-9a-f]{40}$/;

/** The channel's own cap on a list, so a verdict is never refused for length. */
const MAX_ELEMENTS = 40;

/** What a job that never reported contributes instead of a comparison. */
export const SILENT_JOB_CODE = (job) => `E_${job.toUpperCase().replaceAll("-", "_")}_DID_NOT_REPORT`;

/** What a finding that the channel would refuse is replaced by. */
export const UNRENDERABLE_CODE = "E_UNRENDERABLE_FINDING";

/** The last resort: a verdict this file could not make sendable any other way. */
export const FALLBACK_CODE = "E_VERDICT_UNRENDERABLE";

const words = (s) => String(s ?? "").trim().split(/\s+/).filter(Boolean);

/**
 * @param {object} o
 * @param {string} o.check   the receiver check name, `served-set`
 * @param {{name: string, result: string, status: string, codes: string, hexes: string}[]} o.jobs
 * @param {string|null} [o.run]
 */
export function composeVerdict({ check, jobs, run = runUrl() }) {
  const codes = [];
  const hexes = [];
  let red = false;
  let unrenderable = false;

  for (const job of jobs) {
    const status = String(job.status ?? "").trim();
    if (job.result !== "success" || (status !== "green" && status !== "red")) {
      red = true;
      codes.push(SILENT_JOB_CODE(job.name));
      continue;
    }
    if (status === "red") red = true;
    for (const code of words(job.codes)) {
      if (CODE_RE.test(code)) codes.push(code);
      else unrenderable = true;
    }
    for (const hex of words(job.hexes)) {
      if (SHA_RE.test(hex)) hexes.push(hex);
      else unrenderable = true;
    }
  }
  if (unrenderable) {
    red = true;
    codes.push(UNRENDERABLE_CODE);
  }

  const verdict = {
    schema: VERDICT_SCHEMA,
    check,
    status: red ? "red" : "green",
  };
  const uniqueCodes = [...new Set(codes)].slice(0, MAX_ELEMENTS);
  const uniqueHexes = [...new Set(hexes)].slice(0, MAX_ELEMENTS);
  if (uniqueCodes.length) verdict.codes = uniqueCodes;
  if (uniqueHexes.length) verdict.hexes = uniqueHexes;
  if (run) verdict.run = run;

  const problems = verdictProblems(verdict);
  if (!problems.length) return { verdict, problems: [] };

  // Everything above was supposed to make this impossible, and it is here
  // anyway: the channel is the last word on what it carries, and a verdict it
  // refuses is an alarm nobody receives. A red page with one code beats
  // silence, every time.
  const fallback = { schema: VERDICT_SCHEMA, check, status: "red", codes: [FALLBACK_CODE] };
  if (run) fallback.run = run;
  return { verdict: fallback, problems };
}

function parseArgs(argv) {
  const args = { out: "verdict.json", check: "served-set" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") args.out = argv[++i];
    else if (argv[i] === "--check") args.check = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return args;
}

/**
 * The jobs, read from the environment the workflow puts them in.
 *
 * `ASTRA_SERVED_SET_JOBS` names them, in order, so the workflow states which
 * comparisons this alarm is about rather than this file guessing. A job named
 * here whose variables are absent is a job that did not report, which is rule
 * 1 above — so deleting a job from the workflow and forgetting this list pages
 * rather than going quiet.
 */
export function jobsFromEnv(env = process.env) {
  const names = words(env.ASTRA_SERVED_SET_JOBS);
  return names.map((name) => {
    const stem = name.toUpperCase().replaceAll("-", "_");
    return {
      name,
      result: env[`${stem}_RESULT`] ?? "",
      status: env[`${stem}_STATUS`] ?? "",
      codes: env[`${stem}_CODES`] ?? "",
      hexes: env[`${stem}_HEXES`] ?? "",
    };
  });
}

async function main(argv) {
  const args = parseArgs(argv);
  const jobs = jobsFromEnv();
  if (!jobs.length) {
    console.error(
      "FAIL  ASTRA_SERVED_SET_JOBS names no job, so this alarm would be about nothing. The alert job lists the " +
      "comparison jobs it speaks for.",
    );
    return 1;
  }
  const { verdict, problems } = composeVerdict({ check: args.check, jobs });
  for (const p of problems) console.error(`warn  the composed verdict was refused: ${p}`);
  fs.writeFileSync(args.out, `${JSON.stringify(verdict, null, 2)}\n`);
  console.log(`ok    ${args.out}: ${verdict.status}${verdict.codes ? ` (${verdict.codes.join(" ")})` : ""}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
