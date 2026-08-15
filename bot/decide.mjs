#!/usr/bin/env node
// Ingest one release, then decide what happens to it.
//
//   node bot/decide.mjs --repo you/dice-roller --tag v0.2.0 --submitter you --out out
//
// PRODUCTION_PLAN task 3.5. `bot/ingest.mjs` (task 3.3) answers *is this
// listable*; `bot/lib/policy.mjs` answers *does it publish itself, and when*.
// This file is the seam between them and the only entry point
// `.github/workflows/ingest.yml` calls, so that the two questions are always
// asked in that order and always answered in one comment.
//
// ── it still writes nothing into the registry ──────────────────────────────
//
// The property task 3.3 built and this file keeps: **the job that reads a
// stranger's archive cannot write to this repository.** Everything lands under
// `--out`, laid out exactly like the repository itself —
//
//     out/plugins/<id>/plugin.json          the listing, when it publishes now
//     out/plugins/<id>/versions/<v>.json
//     out/state/queue/<id>@<v>.json         the waiting release, when it delays
//     out/remove.txt                        paths to delete, one per line
//     out/comment.md                        what the author reads
//     out/decision.json                     what the workflow reads
//
// — so the separate, minimal `publish` job is a copy, a validate and a commit,
// with no JSON handling and no submitter-controlled code anywhere in it.
//
// Exit codes, because a workflow branches on them:
//
//   0  published now          3  held for a maintainer
//   1  refused                4  delayed; it will publish itself
//   2  the bot broke
//
// ── and what a maintainer does about a 3 ───────────────────────────────────
//
// `--approved-by <login> --approved-at <iso>` — a maintainer's `/approve`,
// already permission-checked against the GitHub API by `bot/lib/maintainer.mjs`
// in the triage job. It clears the hold and nothing else. Note where it enters:
// **after** `ingest()` has run in full, so it cannot shorten a single check. It
// reaches `decide()` as two strings and is written into `decision.json` beside
// the digests this run hashed, so "who let this in, when, against which bytes"
// has one answer with no gap in it.

import fs from "node:fs";
import path from "node:path";

import { loadSources, REPO_ROOT } from "../tools/lib/sources.mjs";

import { ingest, writeListing } from "./ingest.mjs";
import {
  decide,
  queueFile,
  readQueueEntry,
  renderPolicySection,
  trackRecord,
} from "./lib/policy.mjs";

const EXIT = { publish: 0, refuse: 1, review: 3, delay: 4 };

/** @param {string[]} argv */
export function parseArgs(argv) {
  const opts = {
    repo: null, tag: null, submitter: null, root: REPO_ROOT, out: null,
    issue: null, rootsFile: null, trustFile: null, signerWorkflow: null,
    hostAstraVersion: null, now: null, approvedBy: null, approvedAt: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--repo") opts.repo = argv[++i];
    else if (a === "--tag") opts.tag = argv[++i];
    else if (a === "--submitter") opts.submitter = String(argv[++i]).replace(/^@/, "");
    else if (a === "--issue") opts.issue = Number(argv[++i]) || null;
    // A maintainer's `/approve`, already permission-checked by
    // `bot/lib/maintainer.mjs` in the triage job. It carries a name and a
    // moment and NOTHING else — no verdict, no digest, no listing. This run
    // ingests the release from scratch; the flag only says that the hold
    // `bot/lib/policy.mjs` would otherwise raise has been answered.
    else if (a === "--approved-by") opts.approvedBy = String(argv[++i] ?? "").replace(/^@/, "");
    else if (a === "--approved-at") opts.approvedAt = argv[++i];
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--roots") opts.rootsFile = path.resolve(argv[++i]);
    else if (a === "--trust") opts.trustFile = path.resolve(argv[++i]);
    else if (a === "--signer-workflow") opts.signerWorkflow = argv[++i];
    else if (a === "--astra-version") opts.hostAstraVersion = argv[++i];
    else if (a === "--out") opts.out = path.resolve(argv[++i]);
    // Tests and a maintainer reproducing a decision: "what would this have
    // decided at that moment". Never set by the workflow.
    else if (a === "--now") opts.now = new Date(argv[++i]);
    else throw new Error(`unknown argument: ${a}`);
  }
  if (!opts.repo || !opts.tag) throw new Error("--repo <owner/name> and --tag <tag> are both required");
  return opts;
}

/**
 * Ingest, then decide. Exported so the tests drive the whole path rather than
 * the halves.
 *
 * @param {object} opts as `parseArgs` returns
 * @param {object} deps the same injection seam `ingest` takes
 */
export async function decideRelease(opts, deps = {}) {
  const result = await ingest(opts, deps);
  const now = opts.now ?? new Date();
  const { plugins } = loadSources(opts.root);
  const existing = result.derived
    ? plugins.find((p) => p.doc?.id === result.derived.plugin.id) ?? null
    : null;

  const decision = decide({
    findings: result.findings,
    derived: result.derived,
    existing,
    repo: opts.repo,
    tag: opts.tag,
    submitter: opts.submitter,
    issue: opts.issue,
    track: trackRecord(opts.root, opts.repo, { plugins }),
    queued: result.derived
      ? readQueueEntry(opts.root, result.derived.plugin.id, result.derived.version.version)
      : null,
    approval: opts.approvedBy ? { by: opts.approvedBy, at: opts.approvedAt ?? now } : null,
    now,
  });

  return {
    ...result,
    decision,
    comment: `${result.comment}\n${renderPolicySection(decision, result.derived)}`,
  };
}

/** Lay the outcome out under `--out` in the shape of the repository. */
export function writeOutputs(out, opts, result) {
  const { decision, derived } = result;
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, "comment.md"), `${result.comment}\n`);
  fs.writeFileSync(
    path.join(out, "decision.json"),
    `${JSON.stringify(
      {
        outcome: decision.outcome,
        repo: opts.repo,
        tag: opts.tag,
        issue: opts.issue,
        id: derived?.plugin?.id ?? null,
        version: derived?.version?.version ?? null,
        publish_after: decision.publish_after,
        sla_deadline: decision.sla_deadline,
        notify_author: decision.notify_author,
        track: decision.track,
        decided_at: decision.decided_at,
        // The audit record, in the file the publish job reads: who cleared the
        // hold, when, and the digests THIS run hashed. All three or none — an
        // approval without the bytes it applied to cannot be checked later.
        approved_by: decision.approved_by,
        approved_at: decision.approved_at,
        artifact_digests: decision.artifact_digests,
        reasons: decision.reasons,
      },
      null,
      2,
    )}\n`,
  );

  const removals = [];

  // `writeListing`, rather than a second copy of it. There were two writers —
  // this one, and `ingest.mjs`'s, which lays out the tree the validator checks.
  // When a listing gained an icon and a README, only one of them learned to
  // write the files. So the validator passed on a tree that had them and this
  // function committed one that did not, and the run died on the repository's
  // own rule: `icon "icon.svg" is named here but the file is not in
  // plugins/dice-roller/`. That is the check working, on a document this
  // function had made wrong.
  if (decision.publishes_now && derived) {
    writeListing(path.join(out, "plugins", derived.plugin.id), derived);
  }

  if (decision.queue_entry) {
    const rel = queueFile(decision.queue_entry.id, decision.queue_entry.version);
    fs.mkdirSync(path.dirname(path.join(out, rel)), { recursive: true });
    fs.writeFileSync(path.join(out, rel), `${JSON.stringify(decision.queue_entry, null, 2)}\n`);
  }

  // A release that has served its delay, and one that a re-check now refuses or
  // hands to a human, both stop waiting. Leaving the entry behind would make
  // the drain re-publish a listing that is no longer allowed.
  if (derived && (decision.drop_queue || decision.outcome === "refuse" || decision.outcome === "review")) {
    removals.push(queueFile(derived.plugin.id, derived.version.version));
  }
  fs.writeFileSync(path.join(out, "remove.txt"), removals.map((r) => `${r}\n`).join(""));
  return { removals };
}

async function main(argv) {
  const opts = parseArgs(argv);
  const result = await decideRelease(opts);
  console.log(result.comment);
  if (opts.out) writeOutputs(opts.out, opts, result);
  return EXIT[result.decision.outcome] ?? 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`bot: ${e.message}`);
      process.exit(2);
    });
}
