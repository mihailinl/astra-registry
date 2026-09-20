#!/usr/bin/env node
// The one verdict `sign.yml`'s alert job sends.
//
//     node tools/signer/verdict.mjs --out verdict.json --check signer
//
// The rules are `tools/served-set/compose.mjs`'s and are imported rather than
// restated: a job that did not report is red, and a finding the channel's
// grammar refuses is replaced by one fixed code instead of making the whole
// verdict unsendable. Both were argued out there, both have tests there, and a
// second copy here would be a second answer to "is a silent job a passing
// one?" — which is the question this estate keeps getting wrong in the quiet
// direction.
//
// What is this file's own is the ENV NAMES, and only those. `ASTRA_SIGNER_JOBS`
// names the jobs this alarm speaks for, so a job deleted from `sign.yml` and
// forgotten here pages rather than going quiet: a named job with no variables
// is a job that did not report, which is red.
//
// The signer's verdict is red on more than a failure. D4 says **every carry
// alerts**, and a carry is a successful run: the catalogue or the list could
// not be regenerated, `signed`'s copy was re-committed byte for byte, and
// clients are being served something that is no longer being produced. The
// publish job stays green for that — it published — and this is what wakes
// somebody.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

import { composeVerdict } from "../served-set/compose.mjs";

const words = (s) => String(s ?? "").trim().split(/\s+/).filter(Boolean);

/**
 * The jobs, read from the environment `sign.yml` puts them in.
 *
 * @param {NodeJS.ProcessEnv} [env]
 */
export function jobsFromEnv(env = process.env) {
  return words(env.ASTRA_SIGNER_JOBS).map((name) => {
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

function parseArgs(argv) {
  const args = { out: "verdict.json", check: "signer" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") args.out = argv[++i];
    else if (argv[i] === "--check") args.check = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);
  const jobs = jobsFromEnv();
  if (!jobs.length) {
    console.error(
      "FAIL  ASTRA_SIGNER_JOBS names no job, so this alarm would be about nothing. The alert job lists the jobs " +
      "it speaks for.",
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
