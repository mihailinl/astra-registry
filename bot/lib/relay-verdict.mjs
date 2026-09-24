#!/usr/bin/env node
// An alert job's verdict, out of what another job of the same run composed.
//
//     ASTRA_RELAYED_VERDICT='<json>' node bot/lib/relay-verdict.mjs \
//         --check poll-and-sweep --code BOT_87_DID_NOT_REPORT --out verdict.json
//
// Registry plan B-T5.0. `plugins-ingest.yml`'s `remember` job composes BOT-87's
// verdict — it is the one job that has seen the poll, the sweep and the memory
// together — and `poll-alert` sends it. The job that composes cannot send (it
// holds the `bot-state` key, and an environment is a job-level property), and
// the job that sends cannot compose (it holds the alarm channel's credential and
// reads nothing but job outputs, BOT-46). So a verdict crosses a job boundary,
// and this is the half on the receiving side.
//
// **An absent verdict is a red one.** A composing job that died before writing
// its output looks, to a sender that simply forwards what it was given, exactly
// like a job with nothing to say, and that is the shape of every "the alarm was
// never wired up" defect this estate has had. So an empty, unparsable or
// unsendable relay becomes a red verdict carrying `--code`, and so does a
// verdict about some other check: a sender that forwarded one would post this
// check's heartbeat over another check's news.
//
// `bot/check-roots.mjs --relay` is the same rule for the roots check, with its
// check and code fixed; this is the general form, for the jobs written after it.
// It imports `bot/lib/alert-verdict.mjs` and nothing else, because the job that
// runs it checks out only the files it executes.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { CODE_PATTERN, VERDICT_SCHEMA, runUrl, verdictProblems } from "./alert-verdict.mjs";

const CODE_RE = new RegExp(CODE_PATTERN);

/**
 * The verdict to send, and why it is not the one relayed when it is not.
 *
 * @param {string|undefined} text the raw job output
 * @param {{check: string, code: string, run?: string|null}} opts
 * @returns {{verdict: object, why: string|null}}
 */
export function relayedVerdict(text, { check, code, run = runUrl() }) {
  if (!CODE_RE.test(String(code))) throw new Error(`--code ${JSON.stringify(code)} is not a fixed code (${CODE_PATTERN})`);
  const fallback = { schema: VERDICT_SCHEMA, check, status: "red", codes: [code], ...(run ? { run } : {}) };
  const own = verdictProblems(fallback);
  if (own.length) throw new Error(`the fallback verdict for ${JSON.stringify(check)} is not sendable: ${own.join("; ")}`);
  if (typeof text !== "string" || text.trim() === "") {
    return { verdict: fallback, why: "the job that composes this verdict reported none" };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { verdict: fallback, why: `the relayed verdict is not JSON: ${e.message}` };
  }
  const problems = verdictProblems(parsed);
  if (problems.length) return { verdict: fallback, why: `the relayed verdict is not sendable: ${problems.join("; ")}` };
  if (parsed.check !== check) {
    return { verdict: fallback, why: `the relayed verdict is about ${JSON.stringify(parsed.check)}, not ${JSON.stringify(check)}` };
  }
  return { verdict: parsed, why: null };
}

function parseArgs(argv) {
  const args = { check: null, code: null, out: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") args.check = argv[++i];
    else if (a === "--code") args.code = argv[++i];
    else if (a === "--out") args.out = path.resolve(argv[++i]);
    else throw new Error(`unknown argument: ${a}`);
  }
  for (const k of ["check", "code", "out"]) if (!args[k]) throw new Error(`--${k} is required`);
  return args;
}

// It composes a file and exits 0 whatever it relays: whether an alarm goes out
// is `bot/alert.mjs --if-red`'s decision, out of the verdict's own status, and
// a non-zero exit here would fail the step before the alarm could be sent.
function main(argv) {
  const args = parseArgs(argv);
  const { verdict, why } = relayedVerdict(process.env.ASTRA_RELAYED_VERDICT, args);
  fs.writeFileSync(args.out, `${JSON.stringify(verdict, null, 2)}\n`);
  if (why) console.error(`FAIL  ${why}, so this job is sending a red verdict that says so (${args.code})`);
  else console.log(`ok    relaying ${args.check}'s ${verdict.status} verdict`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
