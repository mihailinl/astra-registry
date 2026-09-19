// The publication queue: one file per waiting release.
//
// Split out of `bot/lib/policy.mjs` on 2026-09-19.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ── the queue ───────────────────────────────────────────────────────────────
//
// A delayed release is a file in `state/queue/`, committed like everything else
// here. Three properties fall out of that choice and none of them are
// incidental:
//
//   * it survives. There is no server; a delay held in a workflow's memory is a
//     delay that ends when the runner does.
//   * it is auditable. `git log state/queue/` is the list of every release that
//     ever waited, and why.
//   * it is cancellable by a person with no tooling at all: delete the file.
//
// The entry records the digests it was queued for, and `decide` restarts the
// clock when they change. Everything else in it is a convenience for the human
// reading the directory — the publish path re-runs every check from scratch and
// believes none of it.

/** The registry's operational memory: what is waiting, and what it last saw. */
export const STATE_DIR = "state";

/** `state/queue/<id>@<version>.json` — one file per waiting release. */
export function queueFile(id, version) {
  return path.join(STATE_DIR, "queue", `${id}@${version}.json`);
}

export function readQueueEntry(root, id, version) {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, queueFile(id, version)), "utf8"));
  } catch {
    return null;
  }
}

/** Every waiting release, oldest deadline first. Used by the cron drain. */
export function readQueue(root) {
  const dir = path.join(root, STATE_DIR, "queue");
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith(".json"));
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    try {
      const doc = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
      if (doc && doc.repo && doc.tag && doc.publish_after) {
        out.push({ file: `${STATE_DIR}/queue/${name}`, ...doc });
      }
    } catch {
      // A malformed queue entry is a maintainer's problem, not a stranger's:
      // skip it rather than failing the drain for every other release.
    }
  }
  return out.sort((a, b) => (a.publish_after < b.publish_after ? -1 : 1));
}

/** The queued releases whose delay has elapsed. */
export const ripeQueueEntries = (entries, now = new Date()) =>
  entries.filter((e) => new Date(e.publish_after).getTime() <= now.getTime());

/** The digests of every artifact in a derived version document, sorted. */
