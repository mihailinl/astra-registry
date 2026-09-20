#!/usr/bin/env node
// Detector A (BOT-43): the reconciliation that reads only public git.
//
// Detector A and detector B answer the same nine questions from two stores
// that share no code (contract §4.8). **Neither repairs.** Each alarms with
// codes, ids and commits, and a person resolves the disagreement through a
// `system` decision record or an audited service correction. Everything in this
// file therefore RETURNS findings; nothing here writes anything anywhere.
//
// Five of the nine rows are this side's: A1, A3, A5, A7 and A9. Row 6 — work
// not taken — is BOT-85's heartbeat and belongs to the receiver, not here.
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

import { readDecisionRecords } from "./baseline.mjs";
import { VERDICT_SCHEMA, runUrl } from "./lib/alert-verdict.mjs";
import {
  BASELINE_FILE,
  REPO_ROOT,
  loadSources,
  nonStagingVersions,
} from "../tools/lib/sources.mjs";

export const DETECTORS = ["A1", "A3", "A5", "A7", "A9"];

/** §4.8 row 7's two bounds, in minutes. */
export const A7_BOUND_MINUTES = { plugins: 120, revocations: 30 };

/** The branch the signer publishes, and the trailer that says what it was made from. */
export const SIGNED_REF = "signed";
export const SOURCE_COMMIT_TRAILER = /^Source-Commit:\s*([0-9a-f]{40})\s*$/m;

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
      return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).replace(/\n$/, "");
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
        execFileSync("git", ["-C", root, "merge-base", "--is-ancestor", a, b], { stdio: "ignore" });
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
    /** The newest commit touching a pathspec, or null when nothing ever has. */
    newestTouching(pathspec, ref = "HEAD") {
      const v = git(["log", "-1", "--format=%H %ct", ref, "--", pathspec], true);
      if (!v) return null;
      const [sha, at] = v.split(" ");
      return { sha, at: Number(at) };
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

  // A `delayed` record whose queue entry is not on disk.
  let delayed = 0;
  for (const { doc, file } of records) {
    if (doc?.state !== "delayed") continue;
    delayed++;
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
  for (const [what, pathspec] of [["plugins", "plugins"], ["revocations", "tools/revocations"]]) {
    const newest = git.newestTouching(pathspec);
    if (!newest) continue;
    const driftMinutes = Math.floor((newest.at - at) / 60);
    scanned[`${what}_drift_minutes`] = driftMinutes;
    if (driftMinutes > A7_BOUND_MINUTES[what]) {
      findings.push({
        detector: "A7",
        code: what === "plugins" ? "A7_SIGNED_BEHIND_PLUGINS" : "A7_SIGNED_BEHIND_REVOCATIONS",
        message:
          `\`signed\`'s Source-Commit is ${driftMinutes} minutes older than the newest ${pathspec}/ commit ` +
          `${newest.sha.slice(0, 12)}; the bound is ${A7_BOUND_MINUTES[what]}`,
        hex: newest.sha,
      });
    }
  }
  void now;
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
    if (touched.length === 0) continue;

    const addedRecords = git.changedIn(sha, "A", ["log/decisions"])
      .map((f) => readJsonAt(git, sha, f))
      .filter((d) => d && d.state === "published");

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
  return { findings, skipped, scanned, ran: DETECTORS.filter((d) => !skipped.some((s) => s.detector === d)) };
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
