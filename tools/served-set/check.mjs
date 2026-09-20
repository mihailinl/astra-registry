#!/usr/bin/env node
// The comparison `served-set.yml` runs, as a command.
//
//     node tools/served-set/check.mjs --job main-vs-signed      # SERVE-85
//
// RC-R1-5 adds the second job, `served-vs-signed`, to this file and to the
// workflow beside it.
//
// This file reads the world and hands it to the decision modules beside it. It
// holds no rule of its own, which is the split the rest of this estate uses
// for the same reason: every rule here decides whether a person is woken, and
// a rule that can only be exercised by a live GitHub run is a rule nothing has
// watched fail.
//
// **It always exits 0 unless it cannot run at all**, and the workflow fails
// the job on the status instead. Two steps rather than one, because a step
// that writes `$GITHUB_OUTPUT` and then exits non-zero is a step whose outputs
// the alert job may or may not see, and the alert job is the whole point of
// the run. A crash still reports: the catch below emits a red verdict with
// `E_CHECK_CRASHED` so the alarm says something, rather than leaving the
// alert job to infer red from an empty string.

import { pathToFileURL } from "node:url";

import { REPO_ROOT } from "../lib/sources.mjs";
import { emit, finding, verdict } from "./report.mjs";
import { gather, serve85 } from "./main-vs-signed.mjs";

async function mainVsSigned({ root, now }) {
  const facts = gather({ root });
  return serve85({ ...facts, now });
}

const JOBS = {
  "main-vs-signed": mainVsSigned,
};

function parseArgs(argv) {
  const args = { job: null, root: REPO_ROOT, now: new Date().toISOString() };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--job") args.job = argv[++i];
    else if (argv[i] === "--root") args.root = argv[++i];
    else if (argv[i] === "--now") args.now = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);
  const job = JOBS[args.job];
  if (!job) {
    console.error(`FAIL  --job must be one of ${Object.keys(JOBS).join(", ")}`);
    return 1;
  }
  const repo = process.env.GITHUB_REPOSITORY ?? "mihailinl/astra-registry";
  const token = process.env.GITHUB_TOKEN ?? null;
  try {
    emit(await job({ root: args.root, now: args.now, repo, token }));
  } catch (e) {
    emit(verdict({
      findings: [finding(
        "E_CHECK_CRASHED",
        `${args.job} could not complete: ${String(e?.stack ?? e)}`,
      )],
    }));
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
