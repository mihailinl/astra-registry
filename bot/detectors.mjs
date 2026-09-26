#!/usr/bin/env node
// Detector A (BOT-43): the reconciliation that reads only public git.
//
// Detector A and detector B answer the same eleven questions from two stores
// that share no code (contract §4.8). **Neither repairs.** Each alarms with
// codes, ids and commits, and a person resolves the disagreement through a
// `system` decision record or an audited service correction. Everything in this
// file therefore RETURNS findings; nothing here writes anything anywhere.
//
// Six of the eleven rows are this side's: A1, A3, A5, A7, A9 and A11 (contract
// 3.0.0's review mark). Row 6 — work not taken — is BOT-85's heartbeat and
// belongs to the receiver, not here; rows 2, 4, 8 and 10 are detector B's
// alone.
//
// ── skipping, and why it is loud rather than green ─────────────────────────
//
// Four of the five need something that does not exist yet on `main`:
//
//   * A1, A3, A5 and A9 need `log/baseline.json`. BOT-75 is the reason and it
//     is not a convenience: without the marker there is no "post-baseline", so
//     A1 would report every version file this registry has ever published as
//     unrecorded, A3 every queue entry ever cleared, and A9 every identity
//     record ever written. That is not a detector finding twenty-two
//     disagreements; it is a detector that has not been told where history
//     starts.
//   * A5 and A9 additionally need decision records, which B-T2.2 writes.
//   * A7 needs the `signed` branch, which arrives at R2.
//
// A skip is printed, named, and carries the task that lifts it. It is NOT a
// finding and does not page: an hourly alarm about a state the plan puts weeks
// of work inside is the alarm whose repair is switching the check off, and that
// is the one repair this estate must never reach for (RC-R1-0, attack B-1).
//
// What stops a skip from being permanent is not this file. It is that every
// skip has a named lifter, the count of skips is printed on every run, and
// `bot/tests/detectors.test.mjs` asserts the skip is DERIVED from the thing
// being absent rather than hard-coded — so a detector that skips with its
// input present is red in CI, not quiet in production.
//
// ── the floor ──────────────────────────────────────────────────────────────
//
// Every check that enumerates a set asserts a floor (§2.0). Here the floor is
// conditional and has to be: with no marker there is nothing to scan and a
// floor of zero would be the only honest one, which is no floor at all. So the
// floor is asserted per detector, from the moment that detector's input
// exists — `--floor-records N` for a live run — and a detector that ran with
// its input present and scanned nothing is a finding in its own right.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { cleanEnv } from "../tools/lib/git-env.mjs";

import { readDecisionRecords } from "./baseline.mjs";
import { mergeOwnChanges } from "../tools/coverage/git.mjs";
import { isVoidingRecord } from "./lib/identity.mjs";
import { VERDICT_SCHEMA, runUrl } from "./lib/alert-verdict.mjs";
import {
  BASELINE_FILE,
  REPO_ROOT,
  loadSources,
  nonStagingVersions,
} from "../tools/lib/sources.mjs";
import { SOURCE_PATHSPEC as REVOCATIONS_PATHSPEC } from "../tools/lib/revocations.mjs";
import { CATALOGUE_PATHSPEC } from "../tools/build-index.mjs";
import { GRACE_MINUTES, minutesSince, withinGrace } from "../tools/served-set/report.mjs";

export const DETECTORS = ["A1", "A3", "A5", "A7", "A9", "A11"];

/**
 * §4.8 row 7's two bounds, in minutes: how long `main` may hold a change that
 * `signed` does not carry. §7.3 reads the same two numbers as takedown latency
 * — the signed commit within 2 h of the `main` commit for the catalogue, 30
 * minutes for the withdrawal list — and that is what A7 measures, against the
 * run's clock (gap 76; `a7` says why).
 *
 * The list's is SERVE-85's window, and it is SERVE-85's constant rather than a
 * second 30: row 7 cites SERVE-85 for the number, and both checks ask how long
 * the list may wait for the signer. The catalogue's 2 h has no other reader.
 */
export const A7_BOUND_MINUTES = { plugins: 120, revocations: GRACE_MINUTES };

/**
 * The branch the signer publishes, and the two trailers that say what it was
 * made from (B.4): `Source-Commit`, the run's `main` commit, and
 * `Index-Source-Commit`, the `main` commit the catalogue in it was generated
 * from. Each is anchored at a line start, so neither matches the other's line.
 */
export const SIGNED_REF = "signed";
export const SOURCE_COMMIT_TRAILER = /^Source-Commit:\s*([0-9a-f]{40})\s*$/m;
export const INDEX_SOURCE_COMMIT_TRAILER = /^Index-Source-Commit:\s*([0-9a-f]{40})\s*$/m;

const VERSION_GLOB = "plugins/*/versions/*.json";
const QUEUE_GLOB = "state/queue/*.json";

// ── git, as a value ─────────────────────────────────────────────────────────

/**
 * Every git read this file makes, behind one function, so a test can hand it a
 * fixture tree and so nothing here composes a shell string. `execFileSync` with
 * an argument array: the arguments include tags and repository names that came
 * from a stranger, and a detector that interpolated one into `sh -c` would be a
 * command-injection hole in the thing that watches for tampering.
 */
export function gitReader(root) {
  const git = (args, allowFail = false) => {
    try {
      return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env: cleanEnv() }).replace(/\n$/, "");
    } catch (e) {
      if (allowFail) return null;
      throw new Error(`git ${args.join(" ")}: ${String(e.stderr ?? e.message).trim().split("\n")[0]}`);
    }
  };
  return {
    /** The commit that ADDED a path, oldest first; the first is the one that created it. */
    addedBy(file) {
      const out = git(["log", "--diff-filter=A", "--format=%H", "--", file], true);
      const shas = (out ?? "").split("\n").filter(Boolean);
      return shas.length ? shas[shas.length - 1] : null;
    },
    isAncestor(a, b) {
      try {
        execFileSync("git", ["-C", root, "merge-base", "--is-ancestor", a, b], { stdio: "ignore", env: cleanEnv() });
        return true;
      } catch {
        return false;
      }
    },
    hasRef(ref) {
      return git(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], true) !== null;
    },
    head() {
      return git(["rev-parse", "HEAD"]);
    },
    message(ref) {
      return git(["log", "-1", "--format=%B", ref], true);
    },
    /** Commit time of a ref, as epoch seconds. */
    committedAt(ref) {
      const v = git(["log", "-1", "--format=%ct", ref], true);
      return v === null ? null : Number(v);
    },
    /**
     * The newest commit on `ref`'s FIRST-PARENT line that changed a pathspec —
     * the moment the change became reachable from `ref` — or null when
     * nothing ever has. For a pull request merged with a merge commit that is
     * the merge. A plain `git log -1 -- <pathspec>` simplifies history through
     * the merge, which is TREESAME to its branch parent for the path, and
     * returns the branch commit instead: measured 2026-09-22 (gap 68), a change
     * committed on a branch at 01:00 and merged at 04:00 against a `signed`
     * made at 01:30 gave A7 a drift of -30 minutes and no finding, where the
     * true drift was 150. A fast-forward of an old commit is still dated at
     * its own committer time; git records no time for a ref moving.
     */
    newestTouching(pathspec, ref = "HEAD") {
      const v = git(["log", "-1", "--first-parent", "--format=%H %ct", ref, "--", pathspec], true);
      if (!v) return null;
      const [sha, at] = v.split(" ");
      return { sha, at: Number(at) };
    },
    /**
     * The commits on `ref`'s first-parent line that `since` does not contain
     * and that changed a pathspec, OLDEST first — the changes a `signed` made
     * from `since` does not carry, each dated where main acquired it, as
     * `newestTouching` dates one and for its reason (gap 68). Empty when
     * `since` carries every one, including when `since` is newer than `ref`.
     * Not allowed to fail: an empty answer here reads as "nothing unsigned",
     * so a git error has to stop the run rather than become that answer.
     */
    unsignedTouching(since, pathspec, ref = "HEAD") {
      const out = git(["log", "--first-parent", "--reverse", "--format=%H %ct", `${since}..${ref}`, "--", pathspec]);
      return out.split("\n").filter(Boolean).map((line) => {
        const [sha, at] = line.split(" ");
        return { sha, at: Number(at) };
      });
    },
    /** Paths added between two commits. */
    addedBetween(from, to, pathspec) {
      const out = git(["diff", "--name-only", "--diff-filter=A", from, to, "--", pathspec], true);
      return (out ?? "").split("\n").filter(Boolean);
    },
    /** Commits in (from, to] that touch a pathspec, oldest first. */
    commitsTouching(from, to, pathspecs) {
      const out = git(["log", "--reverse", "--format=%H", `${from}..${to}`, "--", ...pathspecs], true);
      return (out ?? "").split("\n").filter(Boolean);
    },
    /** One commit's changed paths, filtered by status letter. */
    changedIn(sha, filter, pathspecs = []) {
      const out = git(["diff-tree", "--no-commit-id", "-r", "--name-only", `--diff-filter=${filter}`, sha, "--", ...pathspecs], true);
      return (out ?? "").split("\n").filter(Boolean);
    },
    /** A file's bytes at a commit, or null when it is not in that tree. */
    blobAt(sha, file) {
      return git(["show", `${sha}:${file}`], true);
    },
    /** Is this checkout shallow? A walk of a shallow history reads a partial one as whole. */
    isShallow() {
      return git(["rev-parse", "--is-shallow-repository"]) === "true";
    },
    /** HEAD's first-parent line, OLDEST first. Not allowed to fail: an empty line reads as no history. */
    firstParentLine() {
      return git(["rev-list", "--first-parent", "--reverse", "HEAD"]).split("\n").filter(Boolean);
    },
    /**
     * The commits on HEAD's first-parent line that changed a pathspec against
     * their FIRST parent, oldest first — for a merge, what `main` acquired by it.
     */
    firstParentTouching(pathspec) {
      return git(["log", "--first-parent", "--reverse", "--format=%H", "HEAD", "--", pathspec]).split("\n").filter(Boolean);
    },
    /**
     * Every commit reachable from HEAD that changed a pathspec, merged branches
     * included, oldest first: non-merges against their parent, or, with
     * `merges`, the merges that differ from at least one parent there — the
     * superset of the merges whose own resolution could have changed it. With
     * `--full-history`, because git's default simplification drops a side
     * branch whose merge is TREESAME to its first parent, and a change made and
     * undone on a branch is still a change somebody made.
     */
    touching(pathspec, { merges = false } = {}) {
      return git(["rev-list", "--full-history", "--reverse", merges ? "--merges" : "--no-merges", "HEAD", "--", pathspec])
        .split("\n").filter(Boolean);
    },
    /** A commit's parents, first parent first; empty for a root commit. */
    parents(sha) {
      return git(["show", "-s", "--format=%P", sha]).split(/\s+/).filter(Boolean);
    },
    /**
     * What a commit changed against its FIRST parent — the empty tree for a
     * root commit — as `{status, path}`. Not allowed to fail, for
     * `unsignedTouching`'s reason.
     */
    changes(sha) {
      const [first] = this.parents(sha);
      const out = first
        ? git(["diff-tree", "-r", "-z", "--no-renames", "--name-status", first, sha])
        : git(["diff-tree", "-r", "-z", "--no-renames", "--name-status", "--no-commit-id", "--root", sha]);
      const fields = out.split("\0").filter((f) => f !== "");
      const changes = [];
      for (let i = 0; i + 1 < fields.length; i += 2) changes.push({ status: fields[i][0], path: fields[i + 1] });
      return changes;
    },
    /**
     * What a merge's resolution changed ITSELF, against the tree git would have
     * written for its parents (`tools/coverage/git.mjs`'s `mergeOwnChanges`,
     * the one definition the coverage walks use).
     */
    mergeOwn(sha) {
      return mergeOwnChanges(sha, root);
    },
  };
}

function readJsonAt(git, sha, file) {
  const text = git.blobAt(sha, file);
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// ── the context every detector reads ────────────────────────────────────────

/**
 * Where history starts, and the two readings of it that must agree.
 *
 * `source_commit` is the commit `verify` read the population at; the commit
 * that ADDED `log/baseline.json` is one commit later, and `source_commit` must
 * be an ancestor of it. Checking both is what turns BOT-75's "the baseline
 * commit named in `log/baseline.json`" into a sentence that can be executed:
 * the marker names a commit, git says which commit introduced the marker, and a
 * disagreement between them is a marker that was moved.
 */
export function baselineAnchor(root, git) {
  const file = path.join(root, BASELINE_FILE);
  if (!fs.existsSync(file)) return { present: false };
  let marker;
  try {
    marker = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    return { present: true, problem: `${BASELINE_FILE} is not readable JSON — ${e.message}` };
  }
  const addedBy = git.addedBy(BASELINE_FILE);
  if (!addedBy) {
    return { present: true, marker, problem: `${BASELINE_FILE} is on disk and no commit in this history added it` };
  }
  const stated = marker.source_commit;
  if (typeof stated !== "string" || !/^[0-9a-f]{40}$/.test(stated)) {
    return { present: true, marker, addedBy, problem: `${BASELINE_FILE} names no source_commit, so BOT-75's ignore set has only one reading` };
  }
  if (!git.isAncestor(stated, addedBy)) {
    return {
      present: true,
      marker,
      addedBy,
      problem:
        `${BASELINE_FILE} names source_commit ${stated.slice(0, 12)}, which is not an ancestor of ` +
        `${addedBy.slice(0, 12)}, the commit that added the marker`,
    };
  }
  return { present: true, marker, addedBy, sourceCommit: stated };
}

/** One read of everything the five detectors share. */
export function context({ root = REPO_ROOT, now = Date.now(), git = gitReader(root) } = {}) {
  const anchor = baselineAnchor(root, git);
  const { plugins } = loadSources(root);
  const records = readDecisionRecords(root);
  return { root, now, git, anchor, plugins, records, versions: nonStagingVersions(plugins) };
}

const key = (id, version) => `${id}@${version}`;

/** Decision records by the (plugin_id, version) they are about. */
function recordsByVersion(records) {
  const byVersion = new Map();
  for (const { doc } of records) {
    if (!doc?.plugin_id || !doc?.version) continue;
    const k = key(doc.plugin_id, doc.version);
    if (!byVersion.has(k)) byVersion.set(k, []);
    byVersion.get(k).push(doc);
  }
  return byVersion;
}

// ── A1 · published, unrecorded ──────────────────────────────────────────────

/**
 * A post-baseline `versions/*.json` with no `published` or `migration` record,
 * plus MIG-20's tree check.
 *
 * The tree check is here rather than in `bot/baseline.mjs` because it is the
 * only part of B-T3.7b that has to keep being true after the single dispatch:
 * the baseline is written once and then every later commit can break it.
 */
export function a1({ anchor, git, versions, records }, findings, skipped, scanned) {
  if (!anchor.present) {
    skipped.push({ detector: "A1", why: `${BASELINE_FILE} is not on this tree, so there is no post-baseline`, lifted_by: "B-T3.7b's dispatch" });
    return;
  }
  if (anchor.problem) {
    findings.push({ detector: "A1", code: "A1_BASELINE_UNREADABLE", message: anchor.problem });
    return;
  }

  const byVersion = recordsByVersion(records);
  const head = git.head();
  const added = git.addedBetween(anchor.addedBy, head, VERSION_GLOB);
  scanned.versions_post_baseline = added.length;
  scanned.records = records.length;

  // The floor the marker states. Records are never deleted (DEC-7), and the
  // baseline counted the ones it wrote, so a walk that reads fewer than that
  // has lost its input rather than found a quieter registry — and every
  // detector below reads the same records.
  const counted = anchor.marker?.record_count;
  if (Number.isInteger(counted) && records.length < counted) {
    findings.push({
      detector: "A1",
      code: "A1_RECORDS_BELOW_MARKER",
      message: `${BASELINE_FILE} counts ${counted} record(s) written at the baseline and this walk read ${records.length}`,
    });
  }

  for (const file of added) {
    const doc = readJsonAt(git, head, file);
    if (!doc) { findings.push({ detector: "A1", code: "A1_VERSION_UNREADABLE", message: `${file} was added after the baseline and is not readable JSON at HEAD` }); continue; }
    if (doc.staging === true) continue;
    const mine = byVersion.get(key(doc.id, doc.version)) ?? [];
    if (!mine.some((d) => d.state === "published" || d.trigger === "migration")) {
      findings.push({
        detector: "A1",
        code: "A1_PUBLISHED_UNRECORDED",
        message: `${file} was published after the baseline and no decision record says so`,
        plugin_id: doc.id,
      });
    }
  }

  // MIG-20's tree check, in three halves, as B-T3.7b words it: every
  // non-staging version at the baseline commit has exactly one `migration`
  // record; every later version carries both ids in its own record; no staging
  // entry has one. The third half is `mig20Staging`, because it is the only one
  // that has to look at the staging entries this function's population excludes.
  const migrationByVersion = new Map();
  for (const { doc } of records) {
    if (doc?.trigger !== "migration") continue;
    if (!doc.plugin_id || !doc.version) continue;
    const k = key(doc.plugin_id, doc.version);
    migrationByVersion.set(k, (migrationByVersion.get(k) ?? 0) + 1);
  }

  const addedAfter = new Set(added);
  let baselined = 0;
  for (const { plugin, version } of versions) {
    const k = key(version.doc.id, version.doc.version);
    if (addedAfter.has(version.file)) {
      // Every later version carries both ids in its OWN record.
      const own = (byVersion.get(k) ?? []).find((d) => d.state === "published");
      if (own && (!own.repository_id || !own.repository_owner_id)) {
        findings.push({
          detector: "A1",
          code: "MIG20_IDS_MISSING",
          message: `${version.file} is post-baseline and its \`published\` record carries no certificate ids`,
          plugin_id: plugin.id,
        });
      }
      continue;
    }
    baselined++;
    const n = migrationByVersion.get(k) ?? 0;
    if (n !== 1) {
      findings.push({
        detector: "A1",
        code: n === 0 ? "MIG20_NO_MIGRATION_RECORD" : "MIG20_DUPLICATE_MIGRATION_RECORD",
        message: `${version.file} is at or before the baseline and has ${n} \`migration\` record(s); MIG-20 asks for exactly one`,
        plugin_id: plugin.id,
      });
    }
  }
  scanned.versions_baselined = baselined;

  // A floor with the input present: a baseline exists and nothing was
  // enumerated means the walk stopped working, not that the registry is empty.
  if (baselined === 0) {
    findings.push({
      detector: "A1",
      code: "A1_SCANNED_NOTHING",
      message: "a baseline is on this tree and no version was enumerated at or before it; the walk found nothing to check",
    });
  }
}

/** The staging half of MIG-20's tree check: a staging entry never has a record. */
export function mig20Staging({ plugins, records }, findings) {
  const migration = new Set();
  for (const { doc } of records) {
    if (doc?.trigger === "migration" && doc.plugin_id && doc.version) migration.add(key(doc.plugin_id, doc.version));
  }
  for (const plugin of plugins) {
    for (const version of plugin.versions ?? []) {
      if (version.doc?.staging !== true) continue;
      if (migration.has(key(version.doc.id, version.doc.version))) {
        findings.push({
          detector: "A1",
          code: "MIG20_STAGING_BASELINED",
          message: `${version.file} is a staging entry and carries a \`migration\` record; MIG-20 says staging entries never count`,
          plugin_id: version.doc.id,
        });
      }
    }
  }
}

// ── A3 · promised, not queued ───────────────────────────────────────────────

export function a3({ anchor, git, root, records }, findings, skipped, scanned) {
  if (!anchor.present || anchor.problem) {
    skipped.push({ detector: "A3", why: `${BASELINE_FILE} is not usable, so a queue removal has no "post-baseline"`, lifted_by: "B-T3.7b's dispatch" });
    return;
  }
  const head = git.head();

  // A `delayed` record whose queue entry is not on disk — while the promise is
  // still open. A delay ENDS in a later record about the same bytes: the
  // drain's `published`, or the `refused` or `held` a re-check wrote when it
  // took the entry away. Until that was asked, every drained release left its
  // `delayed` record behind with no entry, and A3 alarmed on it for ever —
  // from the first delayed release after the baseline.
  const settles = new Set(["published", "refused", "held", "stopped"]);
  const settled = (d) => records.some(({ doc: o }) =>
    o && o !== d && settles.has(o.state) && String(o.decided_at ?? "") >= String(d.decided_at ?? "") &&
    (d.fingerprint
      ? o.fingerprint === d.fingerprint
      : o.plugin_id === d.plugin_id && o.version === d.version));
  let delayed = 0;
  for (const { doc, file } of records) {
    if (doc?.state !== "delayed") continue;
    delayed++;
    if (settled(doc)) continue;
    const entry = path.join("state", "queue", `${doc.plugin_id}@${doc.version}.json`);
    if (!fs.existsSync(path.join(root, entry))) {
      findings.push({
        detector: "A3",
        code: "A3_DELAYED_NO_ENTRY",
        message: `${file} promises a delayed publication and ${entry} is not on this tree`,
        plugin_id: doc.plugin_id,
      });
    }
  }
  scanned.delayed_records = delayed;

  // A post-baseline queue removal in a commit that added no decision record.
  // A drain deletes the entry and writes the record in one commit (BOT-73), so
  // the two are asked of the same commit rather than of the tree.
  const commits = git.commitsTouching(anchor.addedBy, head, [QUEUE_GLOB]);
  scanned.queue_commits = commits.length;
  for (const sha of commits) {
    const removed = git.changedIn(sha, "D", [QUEUE_GLOB]);
    if (removed.length === 0) continue;
    const wrote = git.changedIn(sha, "A", ["log/decisions"]);
    if (wrote.length === 0) {
      findings.push({
        detector: "A3",
        code: "A3_QUEUE_REMOVED_NO_RECORD",
        message: `${sha.slice(0, 12)} removed ${removed.join(", ")} and added no decision record`,
        hex: sha,
      });
    }
  }
}

// ── A5 · stop bypassed ──────────────────────────────────────────────────────

/**
 * `published` beside `stopped` or `M_REJECT` for ONE FINGERPRINT.
 *
 * Keyed on the fingerprint and not on the version, because that is what the
 * contract's row says and the difference is the whole check: a stop is about
 * the exact bytes a person looked at, and a later republication of the same
 * version with different bytes is a different fingerprint and not a bypass.
 */
export function a5({ anchor, records }, findings, skipped, scanned) {
  if (!anchor.present || anchor.problem) {
    skipped.push({ detector: "A5", why: `${BASELINE_FILE} is not usable, so every historic record would be in scope`, lifted_by: "B-T3.7b's dispatch" });
    return;
  }
  const byFingerprint = new Map();
  for (const { doc } of records) {
    if (!doc?.fingerprint) continue;
    if (!byFingerprint.has(doc.fingerprint)) byFingerprint.set(doc.fingerprint, []);
    byFingerprint.get(doc.fingerprint).push(doc);
  }
  scanned.fingerprints = byFingerprint.size;
  for (const [fingerprint, docs] of [...byFingerprint].sort((a, b) => a[0].localeCompare(b[0]))) {
    const published = docs.find((d) => d.state === "published");
    if (!published) continue;
    const stop = docs.find((d) => d.state === "stopped" || (d.reasons ?? []).includes("M_REJECT"));
    if (stop) {
      findings.push({
        detector: "A5",
        code: "A5_PUBLISHED_BESIDE_STOP",
        message: `fingerprint ${fingerprint} carries a \`published\` record and a ${stop.state === "stopped" ? "`stopped`" : "`M_REJECT`"} one`,
        plugin_id: published.plugin_id,
        hex: fingerprint,
      });
    }
  }
}

// ── A7 · `signed` behind `main` ─────────────────────────────────────────────

/**
 * A change `main` holds and `signed` does not carry, for longer than row 7's
 * bound — measured from the moment main acquired the OLDEST such change to
 * `now`, the way SERVE-85 measures the list from its commit to `now`.
 *
 * Until gap 76 this subtracted the Source-Commit's time from the newest
 * touching commit's and never read `now`, which asks how long main was quiet
 * before a change, not how long the signer has had it. Measured 2026-09-22 on
 * fixtures, before this repair:
 *
 *   * **it alarmed on a push its signer had not had time to sign.** A
 *     Source-Commit three hours old and an advisory pushed three seconds ago
 *     gave `A7_SIGNED_BEHIND_REVOCATIONS`, identical to the answer at three
 *     hours and at ten. `detectors.yml` and `sign.yml` both start on the same
 *     push, and on each of the four pushes the signer has committed for since
 *     `signed` existed, the detector read `signed` first — by 2, 4, 6 and 36
 *     seconds. The only real A7 red there has ever been is this: run
 *     35502265394 fetched `signed` at 09:25:28Z and the same push's signer
 *     committed `ae80bc7` at 09:25:31Z;
 *   * **and it never alarmed on a signer that stopped, if the change landed
 *     within the bound of the last Source-Commit.** An advisory 20 minutes
 *     after it, or a publication 90 minutes after it, with no signer run ever
 *     again, was silent ten hours later — and would have been for ever, since
 *     neither number moves with time.
 *
 * Measured against `now`, the bound is the grace: no second constant, and the
 * signer has exactly the time §7.3 gives it. A7 stays a function of history,
 * `signed` and `now`, so both halves are fixtures. What this costs is that a
 * push's own run cannot page about that push; the run that does is a later
 * one, and `detectors.yml` says what delivers it.
 *
 * The oldest unsigned change, not the newest, because the newest resets: a
 * dead signer on a `main` that takes a publication every 90 minutes would keep
 * the newest inside 2 h for ever — the shape SERVE-85's header refuses for
 * main's head. A change dated more than the bound AFTER `now` is overdue too:
 * its wait cannot be read, and an unreadable clock excuses nothing
 * (`minutesSince`); `withinGrace` holds that edge itself, for every caller.
 *
 * **Which trailer each half reads: row 7 at contract 0.32.0.** The catalogue
 * half asks what the served catalogue's `Index-Source-Commit:` does not
 * contain; the list half asks what `signed`'s `Source-Commit:` does not. B.4
 * records the second trailer from 0.32.0: the `main` commit whose `plugins/**`
 * the catalogue was generated from, equal to `Source-Commit` except where the
 * signer committed the catalogue's bytes unchanged from `signed`'s head — a
 * carry past a failed gate (D4), or an unchanged catalogue not yet due its
 * re-sign (SERVE-41). Row 7's B column says "the same", so detector B asks
 * the catalogue's question of the same trailer.
 *
 * Until 0.32.0 both halves read `Source-Commit`, by decision (astra-registry
 * PR #219; ops register entry 95), and a carry that also committed the list —
 * it changed, or reached its 20-hour re-sign — moved `Source-Commit` to main's
 * head while the catalogue stayed the carried one. Measured 2026-09-22 on a
 * fixture, a publication at 01:00, an advisory at 01:02 and a carry that
 * committed the list at 01:05: reading `Source-Commit`, A7 said nothing at
 * 03:00:00, at 03:00:01 or at 09:00; reading `Index-Source-Commit`, it is
 * silent at 03:00:00 and alarms at 03:00:01 and at 09:00, naming the
 * publication — the bound, counted to now from the oldest `plugins/` commit
 * the served catalogue does not contain. The signer's own
 * `SIGNER_CARRIED_INDEX` still alerts on every run while a carry lasts; that
 * alert stops when the signer does, and this one does not.
 *
 * **Two trailers that differ are not a carry** (ops register entry 96). The
 * two real `signed` commits whose trailers differ, `ae80bc7` and `f2afd04`,
 * each hold an UNCHANGED catalogue, and neither has a commit under `plugins/`
 * on main's first-parent line between its two trailers. Nor can one: the
 * catalogue's serial counts the commits under `plugins/`, and the signer's
 * comparison keeps the serial (`contentOf` in `tools/signer/plan.mjs`), so any
 * such commit makes the catalogue `changed`. An unchanged catalogue is silent
 * here because the walk from its `Index-Source-Commit` finds nothing, not
 * because A7 was told it was unchanged.
 *
 * **The list half stays on `Source-Commit`,** and no longer because row 7
 * says so: from contract 0.34.0 row 7's list half reads the list's serial
 * (DEC-9's formula) — a commit under `tools/revocations/` is carried once
 * the served list's serial is at least the serial that commit gives the list —
 * which is SERVE-85's reading since `9750f2b`, and SERVE-85 is this
 * repository's implementation of that half. This one is narrower: it reads
 * `SOURCE_PATHSPEC` and `Source-Commit`, so it cannot see a carried list or a
 * README commit.
 *
 * **It fires only where row 7's reading does from contract 0.35.0, and not
 * before.** Every commit it flags is on main's first-parent line after the
 * Source-Commit and changes the list's tree against its first parent. The
 * signer signs main's head, which stays on that line while every later head
 * has it on its own first-parent line — as every merge GitHub's merge button
 * makes does — so under DEC-9's
 * `--full-history` count (`SERIAL_FLAGS`) the flagged commit gives the list a
 * serial above the Source-Commit's, and the served list's serial is at most
 * that, carried or not. Under git's default count, which DEC-9 published
 * until 0.35.0, a merge could give the list the serial of the commit before
 * it or a lower one, and this half then flagged a merge whose serial row 7
 * read as carried — measured by ops lane AV on two fixture histories where
 * row 7 flagged nothing (ops register entry 117). This comment said "it fires
 * only where row 7's reading does" through all of that.
 *
 * **A `signed` head with no `Index-Source-Commit:` is a finding, not a
 * fallback.** B.4 has every `signed` commit name both trailers, and falling
 * back to `Source-Commit` is exactly the reading that was blind above. The
 * list half still runs. All eight commits on the real `signed` carry both
 * trailers (`git log origin/signed`, 2026-09-22).
 */
export function a7({ git, now }, findings, skipped, scanned) {
  if (!git.hasRef(SIGNED_REF)) {
    skipped.push({ detector: "A7", why: "there is no `signed` ref in this checkout", lifted_by: "RC-R1-2's signer workflow, at R2" });
    return;
  }
  const message = git.message(SIGNED_REF) ?? "";
  const m = SOURCE_COMMIT_TRAILER.exec(message);
  if (!m) {
    findings.push({ detector: "A7", code: "A7_NO_SOURCE_COMMIT", message: "`signed`'s head carries no `Source-Commit:` trailer, so nothing can say what it was made from" });
    return;
  }
  const sourceCommit = m[1];
  const at = git.committedAt(sourceCommit);
  if (at === null) {
    findings.push({ detector: "A7", code: "A7_SOURCE_COMMIT_UNKNOWN", message: `\`signed\` names Source-Commit ${sourceCommit.slice(0, 12)}, which is not in this checkout`, hex: sourceCommit });
    return;
  }
  scanned.signed_source_commit = sourceCommit;
  // The catalogue half's commit. Null when `signed` cannot name one, and then
  // that half is a finding and does not run; the list half still does.
  let indexSourceCommit = null;
  const im = INDEX_SOURCE_COMMIT_TRAILER.exec(message);
  if (!im) {
    findings.push({
      detector: "A7",
      code: "A7_NO_INDEX_SOURCE_COMMIT",
      message: "`signed`'s head carries no `Index-Source-Commit:` trailer, so nothing can say which commit its catalogue was generated from",
    });
  } else if (git.committedAt(im[1]) === null) {
    findings.push({ detector: "A7", code: "A7_INDEX_SOURCE_COMMIT_UNKNOWN", message: `\`signed\` names Index-Source-Commit ${im[1].slice(0, 12)}, which is not in this checkout`, hex: im[1] });
  } else {
    indexSourceCommit = im[1];
    scanned.signed_index_source_commit = indexSourceCommit;
  }
  // Throws on a clock that is not one, so the run fails rather than reports.
  const nowIso = new Date(now).toISOString();
  // Each half's pathspec is *what that document is built from*, and neither is
  // "the directory it lives in". `plugins` is the whole tree because a README
  // or an icon does reach `registry/v1/index.json`; the withdrawal list's is
  // `SOURCE_PATHSPEC` because its directory also holds a README that reaches
  // nothing. A7 used the directory for both until 2026-09-20, when ten lines
  // of documentation alarmed it — `tools/lib/revocations.mjs` carries the run
  // and the reasoning.
  //
  // And each half's commit is the one row 7 names for it: the catalogue's
  // `Index-Source-Commit`, the list's `Source-Commit` (the comment above says
  // why the two differ, and why a difference is not a carry).
  const halves = [
    ["plugins", CATALOGUE_PATHSPEC, "Index-Source-Commit", indexSourceCommit],
    ["revocations", REVOCATIONS_PATHSPEC, "Source-Commit", sourceCommit],
  ];
  for (const [what, pathspec, trailer, since] of halves) {
    // Dated where main acquired the change, not where a branch wrote it: a
    // merged change dated at its branch commit reads as older than the
    // Source-Commit, and A7 said nothing about a `signed` 150 minutes behind
    // (gap 68; `newestTouching` carries the measurement).
    const newest = git.newestTouching(pathspec);
    if (!newest) continue;
    // How far the Source-Commit trails the newest change by commit time, for
    // both halves. It decided A7 until gap 76 and decides nothing now; it
    // stays in the transcript, and `tools/selftest/couplings.mjs` reads it to
    // ask which pathspec this half dates (gap 71) — so it stays on
    // `Source-Commit` whichever trailer the half's decision reads, and is
    // written even when that trailer is missing.
    scanned[`${what}_drift_minutes`] = Math.floor((newest.at - at) / 60);
    if (since === null) continue;

    const unsigned = git.unsignedTouching(since, pathspec);
    scanned[`${what}_unsigned_commits`] = unsigned.length;
    if (unsigned.length === 0) continue;
    const oldest = unsigned[0];
    const from = new Date(oldest.at * 1000).toISOString();
    const waited = minutesSince(from, nowIso);
    const bound = A7_BOUND_MINUTES[what];
    scanned[`${what}_unsigned_minutes`] = Math.floor(waited);
    if (withinGrace(from, nowIso, bound)) continue;
    findings.push({
      detector: "A7",
      code: what === "plugins" ? "A7_SIGNED_BEHIND_PLUGINS" : "A7_SIGNED_BEHIND_REVOCATIONS",
      message:
        `\`signed\`'s ${trailer} ${since.slice(0, 12)} does not carry ${unsigned.length} commit(s) ` +
        `under ${pathspec}; the oldest, ${oldest.sha.slice(0, 12)}, ` +
        (waited >= 0
          ? `has been on main ${Math.floor(waited)} minutes`
          : `is dated ${Math.ceil(-waited)} minutes after this run's clock, so how long it has waited cannot be read`) +
        `, and the bound is ${bound}`,
      hex: oldest.sha,
    });
  }
}

// ── A9 · identity or source changed without a decision ──────────────────────

export function a9({ anchor, git }, findings, skipped, scanned) {
  if (!anchor.present || anchor.problem) {
    skipped.push({ detector: "A9", why: `${BASELINE_FILE} is not usable, so every identity record ever written would be in scope`, lifted_by: "B-T3.7b's dispatch" });
    return;
  }
  const head = git.head();
  const commits = git.commitsTouching(anchor.addedBy, head, ["plugins/*/identity.json", "plugins/*/plugin.json"]);
  scanned.identity_commits = commits.length;
  for (const sha of commits) {
    const touched = [
      ...git.changedIn(sha, "AM", ["plugins/*/identity.json"]),
      ...git.changedIn(sha, "M", ["plugins/*/plugin.json"]).filter((f) => sourceChangedIn(git, sha, f)),
    ];
    // A DELETION of an identity record, which "AM" never saw (B-T4.2's
    // canary: A9 is silent on the reset commit and alarms on a hand
    // deletion). Deleting `identity.json` by hand does not unbind anything
    // cleanly — the listing is `frozen` (ID-25), and the baseline its later
    // publication records carry still stands — so the one deletion that is a
    // decision is `M_IDENTITY_RESET`'s release commit, which adds the voiding
    // record for that id in the same commit (`isVoidingRecord`). No such
    // record can exist before the contract MINOR adds the category, so until
    // then every deletion alarms, which is the refusal ID-41 says stands.
    const deleted = git.changedIn(sha, "D", ["plugins/*/identity.json"]);
    if (touched.length === 0 && deleted.length === 0) continue;

    const added = git.changedIn(sha, "A", ["log/decisions"]).map((f) => readJsonAt(git, sha, f)).filter(Boolean);
    const addedRecords = added.filter((d) => d.state === "published");
    for (const file of deleted) {
      const id = /^plugins\/([^/]+)\//.exec(file)?.[1] ?? null;
      if (added.some((d) => isVoidingRecord(d) && d.plugin_id === id)) continue;
      findings.push({
        detector: "A9",
        code: "A9_IDENTITY_CHANGED_NO_DECISION",
        message: `${sha.slice(0, 12)} deleted ${file} and added no identity-reset record for ${id ?? "that id"} ` +
          "(B-T4.2's `M_IDENTITY_RESET`, the one commit that may delete one)",
        plugin_id: id,
        hex: sha,
      });
    }

    for (const file of touched) {
      const id = /^plugins\/([^/]+)\//.exec(file)?.[1] ?? null;
      const after = readJsonAt(git, sha, file) ?? {};
      const repo = after.repo ?? after.source?.repo ?? null;
      const matched = addedRecords.some((d) =>
        (!id || d.plugin_id === id) &&
        (!repo || String(d.repo ?? "").toLowerCase() === String(repo).toLowerCase()) &&
        (after.repository_id === undefined || String(d.repository_id ?? "") === String(after.repository_id)) &&
        (after.repository_owner_id === undefined || String(d.repository_owner_id ?? "") === String(after.repository_owner_id)));
      if (!matched) {
        findings.push({
          detector: "A9",
          code: "A9_IDENTITY_CHANGED_NO_DECISION",
          message: `${sha.slice(0, 12)} changed ${file} and added no \`published\` record whose repo and ids match it`,
          plugin_id: id,
          hex: sha,
        });
      }
    }
  }
}

/** Did this commit change `source` in a `plugin.json`, as opposed to anything else in it? */
function sourceChangedIn(git, sha, file) {
  const after = readJsonAt(git, sha, file);
  const before = readJsonAt(git, `${sha}^`, file);
  return JSON.stringify(after?.source ?? null) !== JSON.stringify(before?.source ?? null);
}

// ── A11 · review marked without a decision (contract 3.0.0) ─────────────────

/**
 * §4.8's row 11, detector A's cell, three clauses:
 *
 *   1. a version record whose `review` became `reviewed` in a commit that adds
 *      no moderation-log `review` entry naming that version, or that carries
 *      no `Service-Decision:` trailer — `A11_REVIEWED_NO_DECISION`;
 *   2. any other change to a committed `review` — `A11_REVIEW_CHANGED`;
 *   3. a version record added at or after 3.0.0's landing commit whose
 *      `review` is absent or not `unreviewed` — `A11_ADDED_NOT_UNREVIEWED`.
 *
 * **Clauses 1 and 2 are judged per commit, on what that commit changed
 * itself,** because the row asks what a COMMIT adds and carries. A non-merge
 * is read against its parent; a merge only on its own resolution
 * (`mergeOwnChanges`, the definition `tools/moderation-coverage.mjs` walks
 * merges by since gap 93). Read on its first-parent diff instead, a merge
 * carrying a review made on a branch would show the mark move with no trailer
 * of its own, and every review a pull request brought in would alarm; and the
 * branch commit that set the mark is judged anyway, merged branches included,
 * as BOT-44 has detector 9 read every commit reachable from `main`'s head.
 * They need no marker and no landing commit: before 3.0.0 no commit may write
 * a mark at all, and one that did is exactly what clause 1 names.
 *
 * **"Any other change" is read on the member, present or not.** B.4: only the
 * commit applying an `M_REVIEW` changes a mark, to `reviewed`, and no commit
 * changes it in any other direction. So `reviewed` → `unreviewed`, a mark
 * removed, a value nobody writes, a mark back-filled onto a record published
 * before 3.0.0 (which the coordinator's D4 leaves unmarked, so no warning
 * shows), and a deleted record that carried one all count. A change to a
 * record's other members — a yank of a reviewed version — does not.
 *
 * **Clause 3 is judged where `main` acquired the record**: on HEAD's
 * first-parent line from the landing commit on, each commit against its first
 * parent. B.4 says every record "added on `main`" from that commit carries the
 * mark, and a branch forked before 3.0.0 that adds a record without one lands
 * it on `main` at its merge — which is after the landing commit, whatever the
 * branch commit's own date. The landing commit is the first on that line whose
 * `schema/version-v1.json` declares `review` (B.4's review-mark paragraph,
 * `reviewLandingCommit`). Until one exists the clause has nothing to count from
 * and SKIPS, by clause, loudly, with what lifts it.
 *
 * A shallow checkout is a finding and not a walk: the commits it cannot see
 * are exactly the ones a green answer would vouch for.
 */
export function a11({ git }, findings, skipped, scanned) {
  if (git.isShallow()) {
    findings.push({
      detector: "A11",
      code: "A11_HISTORY_SHALLOW",
      message: "this checkout is shallow, so the commits that changed a version record's `review` cannot all be " +
        "read; `detectors.yml` checks out with `fetch-depth: 0`",
    });
    return;
  }

  let examined = 0;
  for (const sha of git.touching(VERSION_GLOB)) {
    examined++;
    const [parent] = git.parents(sha);
    const changes = git.changes(sha);
    const entries = addedLogEntries(git, sha, changes);
    for (const { status, path: file } of changes) {
      if (!VERSION_RE.test(file)) continue;
      const before = parent ? versionAt(git, parent, file) : ABSENT;
      judgeReview(git, { sha, file, status, before, after: versionAt(git, sha, file), entries }, findings);
    }
  }
  for (const sha of git.touching(VERSION_GLOB, { merges: true })) {
    examined++;
    const own = git.mergeOwn(sha);
    if (!own.judged) {
      findings.push({
        detector: "A11",
        code: "A11_MERGE_UNJUDGED",
        message: `${sha.slice(0, 12)} is a merge of ${own.parents.length} parents, which has no two-sided resolution ` +
          "to read, and it changed a version record",
        hex: sha,
      });
      continue;
    }
    const entries = addedLogEntries(git, sha, own.changes);
    for (const { status, path: file } of own.changes) {
      if (!VERSION_RE.test(file)) continue;
      const after = versionAt(git, sha, file);
      let before;
      if (own.conflicted.has(file)) {
        // Git could not write the file, so the remerged tree holds conflict
        // markers. A mark some parent already had is that side's act, judged
        // on that side's commit; one no parent had is the resolution's own.
        const sides = own.parents.map((p) => versionAt(git, p, file));
        if (!after.bad && sides.some((side) => !side.bad && sameMark(markOf(side), markOf(after)))) continue;
        before = sides[0];
      } else {
        before = versionAt(git, own.tree, file);
      }
      judgeReview(git, { sha, file, status, before, after, entries }, findings);
    }
  }
  scanned.review_commits = examined;

  const landing = reviewLandingCommit(git);
  scanned.review_landing_commit = landing;
  if (!landing) {
    skipped.push({
      detector: "A11",
      clause: 3,
      why: `row 11's third clause counts from 3.0.0's landing commit, the first on HEAD's first-parent line whose ` +
        `${VERSION_SCHEMA_FILE} declares \`review\`, and there is none`,
      lifted_by: "the registry commit that lands contract 3.0.0's version schema",
    });
    return;
  }
  const line = git.firstParentLine();
  const from = line.indexOf(landing);
  const acquired = new Set(git.firstParentTouching(VERSION_GLOB));
  let added = 0;
  for (const sha of line.slice(from)) {
    if (!acquired.has(sha)) continue;
    for (const { status, path: file } of git.changes(sha)) {
      if (status !== "A" || !VERSION_RE.test(file)) continue;
      added++;
      const record = versionAt(git, sha, file);
      const id = VERSION_RE.exec(file)[1];
      if (record.bad) {
        findings.push({ detector: "A11", code: "A11_RECORD_UNREADABLE", message: `${file} is not readable JSON at ${sha.slice(0, 12)}, so its review mark cannot be read`, plugin_id: id, hex: sha });
        continue;
      }
      const mark = markOf(record);
      if (mark.has && mark.value === UNREVIEWED) continue;
      findings.push({
        detector: "A11",
        code: "A11_ADDED_NOT_UNREVIEWED",
        message: `${sha.slice(0, 12)} added ${file} to main at or after 3.0.0's landing commit ` +
          `${landing.slice(0, 12)}, and its review is ${mark.has ? JSON.stringify(mark.value) : "absent"}, not ` +
          `"${UNREVIEWED}" (B.4)`,
        plugin_id: id,
        hex: sha,
      });
    }
  }
  scanned.review_records_added = added;
}

/** B.4's review mark, and the version schema whose history says when it began. */
export const VERSION_SCHEMA_FILE = "schema/version-v1.json";
export const REVIEWED = "reviewed";
export const UNREVIEWED = "unreviewed";
const VERSION_RE = /^plugins\/([^/]+)\/versions\/([^/]+)\.json$/;
const LOG_ENTRY_RE = /^bot\/moderation\/[^/]+\.json$/;
// §0.7's service decision id, as the bot's own trailer grammar writes it, on a
// line of its own: a mention of the trailer inside a sentence is not one.
const SERVICE_DECISION_TRAILER = /^Service-Decision:[ \t]*[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}[ \t]*$/m;
const ABSENT = Object.freeze({ present: false, doc: null, bad: false });

/**
 * B.4's landing commit: the first commit on HEAD's first-parent line whose
 * version schema declares the member `review`, found by walking that file's
 * first-parent history oldest first — B.4's own recipe — or null.
 */
export function reviewLandingCommit(git) {
  for (const sha of git.firstParentTouching(VERSION_SCHEMA_FILE)) {
    const doc = readJsonAt(git, sha, VERSION_SCHEMA_FILE);
    const props = doc?.properties;
    if (props && typeof props === "object" && !Array.isArray(props) && Object.hasOwn(props, "review")) return sha;
  }
  return null;
}

/** A version record at a commit (or tree): absent, unreadable, or its object. */
function versionAt(git, sha, file) {
  const text = git.blobAt(sha, file);
  if (text === null) return ABSENT;
  try {
    const doc = JSON.parse(text);
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { present: true, doc: null, bad: true };
    return { present: true, doc, bad: false };
  } catch {
    return { present: true, doc: null, bad: true };
  }
}

const markOf = (read) => (read.doc && Object.hasOwn(read.doc, "review")
  ? { has: true, value: read.doc.review }
  : { has: false, value: undefined });
const sameMark = (a, b) => a.has === b.has && (!a.has || JSON.stringify(a.value) === JSON.stringify(b.value));
const describeMark = (m) => (m.has ? JSON.stringify(m.value) : "absent");

/** The moderation-log entries a commit adds — its own additions, for a merge. */
function addedLogEntries(git, sha, changes) {
  return changes
    .filter((c) => c.status === "A" && LOG_ENTRY_RE.test(c.path))
    .map((c) => readJsonAt(git, sha, c.path))
    .filter((doc) => doc && typeof doc === "object");
}

/** Clauses 1 and 2 over one changed version record. An addition is clause 3's, on `main`'s line. */
function judgeReview(git, { sha, file, status, before, after, entries }, findings) {
  if (status === "A") return;
  const [, id, version] = VERSION_RE.exec(file);
  if (before.bad || after.bad) {
    findings.push({
      detector: "A11",
      code: "A11_RECORD_UNREADABLE",
      message: `${sha.slice(0, 12)} changed ${file}, which is not readable JSON on one side, so whether its review ` +
        "mark moved cannot be read",
      plugin_id: id,
      hex: sha,
    });
    return;
  }
  const was = markOf(before);
  const now = after.present ? markOf(after) : { has: false, value: undefined };
  if (!after.present) {
    if (!was.has) return;
    findings.push({
      detector: "A11",
      code: "A11_REVIEW_CHANGED",
      message: `${sha.slice(0, 12)} deleted ${file}, which carried review ${describeMark(was)}; no commit changes a ` +
        "committed review but an M_REVIEW's, and that one only to reviewed (B.4)",
      plugin_id: id,
      hex: sha,
    });
    return;
  }
  if (sameMark(was, now)) return;
  if (now.has && now.value === REVIEWED) {
    const named = entries.some((e) => e.action === "review" && e.plugin === id
      && Array.isArray(e.versions) && e.versions.includes(version));
    const trailer = SERVICE_DECISION_TRAILER.test(git.message(sha) ?? "");
    if (named && trailer) return;
    findings.push({
      detector: "A11",
      code: "A11_REVIEWED_NO_DECISION",
      message: `${sha.slice(0, 12)} marked ${file} reviewed (from ${describeMark(was)}) and ` +
        [named ? null : `adds no moderation-log \`review\` entry naming ${version}`,
          trailer ? null : "carries no `Service-Decision:` trailer"].filter(Boolean).join(" and ") +
        " (MOD-56)",
      plugin_id: id,
      hex: sha,
    });
    return;
  }
  findings.push({
    detector: "A11",
    code: "A11_REVIEW_CHANGED",
    message: `${sha.slice(0, 12)} changed ${file}'s review from ${describeMark(was)} to ${describeMark(now)}; only an ` +
      "M_REVIEW changes a mark, and only to reviewed (B.4)",
    plugin_id: id,
    hex: sha,
  });
}

// ── the run ─────────────────────────────────────────────────────────────────

export function detect(opts = {}) {
  const ctx = context(opts);
  const findings = [];
  const skipped = [];
  const scanned = {};
  a1(ctx, findings, skipped, scanned);
  if (ctx.anchor.present && !ctx.anchor.problem) mig20Staging(ctx, findings);
  a3(ctx, findings, skipped, scanned);
  a5(ctx, findings, skipped, scanned);
  a7(ctx, findings, skipped, scanned);
  a9(ctx, findings, skipped, scanned);
  a11(ctx, findings, skipped, scanned);
  // A skip that names a `clause` is one clause of a detector that otherwise
  // ran, and the detector is counted as run; the skip is still printed, with
  // what lifts it, on every run.
  return {
    findings,
    skipped,
    scanned,
    ran: DETECTORS.filter((d) => !skipped.some((s) => s.detector === d && s.clause === undefined)),
  };
}

/**
 * The verdict the `alert` job sends, built from findings and nothing else.
 *
 * `bot/lib/alert-verdict.mjs` refuses any member it does not render and any
 * value outside its grammar, so a detector that found something about a
 * stranger's listing cannot write a sentence into the owner's Telegram: it
 * contributes a code, a plugin id and a hex, and that is all this composes.
 */
export function verdict(result, env = process.env) {
  const codes = [...new Set(result.findings.map((f) => f.code))].sort();
  const ids = [...new Set(result.findings.map((f) => f.plugin_id).filter(Boolean))].sort();
  const hexes = [...new Set(result.findings.map((f) => f.hex).filter(Boolean))].sort();
  const doc = {
    schema: VERDICT_SCHEMA,
    check: "detectors",
    status: result.findings.length ? "red" : "green",
  };
  // The channel caps each list at 40 and refuses a longer one outright. A
  // detector that found two thousand things has to say so in a count and a run
  // URL, so the lists are trimmed here and the trimming is itself a code.
  const cap = (list) => (list.length > 40 ? list.slice(0, 39) : list);
  if (codes.length) doc.codes = cap(codes.length > 40 ? [...codes.slice(0, 39), "A_MANY_MORE"] : codes);
  if (ids.length) doc.ids = cap(ids);
  if (hexes.length) doc.hexes = cap(hexes);
  const run = runUrl(env);
  if (run) doc.run = run;
  return doc;
}

// ── CLI ─────────────────────────────────────────────────────────────────────

const USAGE = `usage:
  bot/detectors.mjs [--registry-dir DIR] [--verdict FILE] [--floor-records N]`;

async function main(argv) {
  const opts = { root: REPO_ROOT, verdict: null, floor: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--verdict") opts.verdict = path.resolve(argv[++i]);
    else if (a === "--floor-records") opts.floor = Number(argv[++i]);
    else throw new Error(`unknown argument: ${a}\n${USAGE}`);
  }

  const result = detect({ root: opts.root });

  // Loud. Every skip, with what lifts it, on every run — this is the whole of
  // "skipping loudly", and it is printed before the findings so that a reader
  // of a green run sees which detectors did not run before they read the zero.
  for (const s of result.skipped) {
    console.log(`SKIP  ${s.detector}: ${s.why}`);
    console.log(`      lifted by ${s.lifted_by}`);
  }
  for (const [k, v] of Object.entries(result.scanned)) console.log(`scan  ${k}: ${v}`);
  for (const f of result.findings) console.log(`ALARM ${f.detector} ${f.code}: ${f.message}`);

  if (opts.floor !== null && Number.isFinite(opts.floor)) {
    const records = result.scanned.records ?? 0;
    if (records < opts.floor) {
      console.log(`ALARM FLOOR: ${records} decision record(s) scanned, under the floor of ${opts.floor}`);
      result.findings.push({ detector: "A1", code: "A_FLOOR_UNMET", message: `${records} records scanned, floor ${opts.floor}` });
    }
  }

  const doc = verdict(result);
  if (opts.verdict) fs.writeFileSync(opts.verdict, `${JSON.stringify(doc, null, 2)}\n`);

  console.log(
    `${result.findings.length ? "FAIL" : "PASS"}  ${result.ran.length} of ${DETECTORS.length} detector(s) ran ` +
    `(${result.ran.join(" ") || "none"}); ${result.skipped.length} skipped; ${result.findings.length} finding(s)`,
  );
  // BOT-46: a failing detector MUST fail its run. The alert job runs anyway —
  // `if: always() && !cancelled()` — so red here is red in both places.
  return result.findings.length ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`bot: ${e.message}`);
      process.exit(2);
    });
}
