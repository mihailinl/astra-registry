#!/usr/bin/env node
// The two comparisons `served-set.yml` runs, as one command.
//
//     node tools/served-set/check.mjs --job main-vs-signed      # SERVE-85
//     node tools/served-set/check.mjs --job served-vs-signed    # SERVE-39, SERVE-90
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
// alert job to infer red from two empty strings.

import path from "node:path";
import { pathToFileURL } from "node:url";

import { REPO_ROOT } from "../lib/sources.mjs";
import { gitMaybe, gitText } from "../signer/git.mjs";
import { armingState } from "../signer/pages.mjs";
import { fetchSignedHead } from "../signer/plan.mjs";
import { emit, finding, verdict } from "./report.mjs";
import { SIGNER_WORKFLOW, gather, serve85 } from "./main-vs-signed.mjs";
import { fetchServed, serve39 } from "./served-vs-signed.mjs";
import { actionsRunLookup, gitAncestry, provenance, runsInScope, signedCommits } from "./provenance.mjs";
import fs from "node:fs";

/** Where `fetchSignedHead` puts the branch, and where everything below reads it. */
const SIGNED_REF = "refs/astra-signer/signed";

/**
 * `main` as the REMOTE has it, in a ref of this check's own.
 *
 * Not `origin/main`, which in a workspace is whatever the last `actions/checkout`
 * wrote, and not `HEAD`, which in a detached checkout is not a branch. SERVE-90
 * asks whether a Source-Commit is reachable from `main`, and the answer must be
 * about the branch rather than about this job's working copy.
 */
function fetchMain({ root, remote = "origin", ref = "refs/astra-served-set/main" }) {
  const fetched = gitMaybe(["fetch", "--quiet", "--no-tags", remote, `+refs/heads/main:${ref}`], { root });
  return fetched.ok ? ref : null;
}

async function mainVsSigned({ root, now }) {
  const facts = gather({ root });
  return serve85({ ...facts, now });
}

async function servedVsSigned({ root, now, repo, token }) {
  const head = fetchSignedHead({ root });
  const signerWorkflowPresent = fs.existsSync(path.join(root, SIGNER_WORKFLOW));
  const served = await fetchServed();

  let headClock = null;
  let arming = { armed: false, latch_commit: null };
  const extra = [];
  if (head.present) {
    headClock = gitText(["log", "-1", "--format=%cI", head.sha], { root });
    // The latch is read at the commit the `pages` job deployed from — the
    // Source-Commit `signed`'s head names — and not at this job's checkout.
    // The two are usually the same commit and the difference matters exactly
    // when they are not: what Pages should be serving is decided by the tree
    // the deploy was made from.
    const source = signedCommits({ root, ref: SIGNED_REF, limit: 1 })[0]?.trailers["Source-Commit"];
    const at = /^[0-9a-f]{40}$/.test(String(source ?? "")) ? source : gitText(["rev-parse", "HEAD"], { root });
    try {
      arming = armingState({ root, sourceCommit: at });
    } catch (e) {
      extra.push(finding(
        "SERVE_39_LATCH_UNREADABLE",
        `the arming history could not be read at ${String(at).slice(0, 12)}: ${String(e?.message ?? e)}. ` +
        `Without it there is no saying which withdrawal list Pages is supposed to be serving.`,
      ));
    }
  }

  const pages = serve39({ head, headClock, served, arming, signerWorkflowPresent, now });

  // SERVE-90's fallback runs in this job because it is this job that has
  // `actions: read` (RC-R1-5). It is a separate question from what Pages
  // serves — a perfectly-deployed forgery passes every check above — so its
  // findings are merged rather than gated on the ones before them.
  let prov = verdict({});
  if (head.present) {
    const commits = signedCommits({ root, ref: SIGNED_REF });
    const mainRef = fetchMain({ root });
    const ancestry = gitAncestry({ root });
    const runs = new Map();
    if (token) {
      const lookup = actionsRunLookup({ repo, token });
      for (const id of runsInScope({ commits, repo, now })) runs.set(id, await lookup(id));
    }
    if (!token) {
      extra.push(finding(
        "SERVE_90_NO_ACTIONS_READ",
        "this job has no token to read the Actions API with, so no `signed` commit could be shown to have been " +
        "pushed by a signer run. RC-R1-5's job declares `actions: read` precisely for this.",
      ));
    } else if (!mainRef) {
      extra.push(finding(
        "SERVE_90_SOURCE_COMMIT_UNREACHABLE",
        "`main` could not be fetched, so no Source-Commit could be shown to be reachable from it.",
      ));
    } else {
      prov = provenance({
        commits,
        repo,
        runs,
        now,
        reachableFromMain: (sha) => ancestry.reachableFrom(sha, mainRef),
        descendsFrom: ancestry.descendsFrom,
      });
    }
  }

  return verdict({
    findings: [...pages.findings, ...prov.findings, ...extra],
    waiting: [...pages.waiting, ...prov.waiting],
    hexes: [...pages.hexes, ...prov.hexes],
    notes: [...pages.notes, ...prov.notes],
  });
}

const JOBS = {
  "main-vs-signed": mainVsSigned,
  "served-vs-signed": servedVsSigned,
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
