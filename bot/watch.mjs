#!/usr/bin/env node
// The half of task 3.5 that runs when a delay ends: which releases waiting in
// `state/queue/` have served their publication delay.
//
//   node bot/watch.mjs --drain --out out     which delayed releases are ripe
//
// It produces `out/dispatch.json` — a list of `{repo, tag, submitter}` the
// workflow turns into ingest runs — and nothing else. **This program never
// decides anything.** It has not downloaded a bundle, checked an attestation
// or read a manifest; it reads files this repository wrote and hands what is
// ripe to the pipeline that verifies from scratch.
//
// It used to run two other modes. `--watch` was the daily release backstop,
// which polled every quiet listing's releases feed and filtered what it found
// by BOT-74's tag-prefix rule; the cutover (M-T6.2 commit B) paused it, and
// `plugins-ingest.yml`'s poll replaced it (B-T5.1). `--sla` reported how late
// the issue review queue was, for the `sla` job commit B removed. Commit D
// (registry plan B-T5.2) deletes both, with `runWatch`, `bot74Filter` and
// `recordedTagsByRepo`, which only the backstop and the issue path's
// `/release` ping read. The drain stays until the queue has run dry; commit E
// deletes this file with `ingest.yml`.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../tools/lib/sources.mjs";

import { readQueue, ripeQueueEntries } from "./lib/policy.mjs";

/** At most this many ingests are started by one cron run. */
const MAX_DISPATCH = 20;

/** Which delayed releases have served their time. */
export function runDrain({ root = REPO_ROOT, now = new Date() } = {}) {
  const queue = readQueue(root);
  const ripe = ripeQueueEntries(queue, now);
  return {
    queue,
    dispatch: ripe.slice(0, MAX_DISPATCH).map((e) => ({
      repo: e.repo,
      tag: e.tag,
      submitter: e.submitter ?? null,
      source: "queue",
      queued_at: e.queued_at,
    })),
    log: queue.map((e) =>
      `  ${new Date(e.publish_after) <= now ? "RIPE" : "wait"}  ${e.id} ${e.version} — publishes at ${e.publish_after} (${e.reason})`,
    ),
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function writeDispatch(out, dispatch) {
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, "dispatch.json"), `${JSON.stringify(dispatch, null, 2)}\n`);
}

async function main(argv) {
  const opts = { mode: null, out: null, root: REPO_ROOT, now: new Date() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--drain") opts.mode = "drain";
    else if (a === "--out") opts.out = path.resolve(argv[++i]);
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--now") opts.now = new Date(argv[++i]);
    // `--watch` and `--sla` are refused by name rather than as unknown words:
    // a workflow still passing either is one commit D's deletions missed.
    else if (a === "--watch" || a === "--sla") {
      throw new Error(`${a} was deleted with the issue path (registry plan B-T5.2, commit D); only --drain remains`);
    } else throw new Error(`unknown argument: ${a}`);
  }

  if (opts.mode === "drain") {
    const { queue, dispatch, log } = runDrain({ root: opts.root, now: opts.now });
    console.log(`publication queue: ${queue.length} waiting, ${dispatch.length} ripe`);
    for (const line of log) console.log(line);
    if (opts.out) writeDispatch(opts.out, dispatch);
    return 0;
  }

  throw new Error("--drain is required");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`watch: ${e.message}`);
      process.exit(2);
    });
}
