#!/usr/bin/env node
// Apply what the bot decided, hold it to this repository's rules, and get it
// onto `main` — or refuse, saying which of the two it is.
//
//   node bot/publish-apply.mjs --reports reports --watch-state watch-state \
//                              --base "$GITHUB_SHA"
//
// Exit codes, because a workflow branches on them:
//
//   0  committed and pushed, or there was nothing to commit
//   1  refused — the derived output is not something this repository will take
//   2  the bot broke
//   3  conflict — another commit touched the same listing; nothing was committed
//
// ── why this is a file, and not the shell block it replaces ────────────────
//
// The `publish` job used to end with one line:
//
//     git push || { git pull --rebase --autostash && git push; }
//
// which is three separate defects wearing one fallback.
//
// **It re-applies without re-checking.** The rebase puts the bot's commit on
// top of whatever landed in the meantime and pushes it. `registry/v1/index.json`
// in that commit was generated against the tree the job *built on*, not the tree
// it *landed on*, and `build-index.yml` asserts on every push that the committed
// index is byte-identical to a fresh generation. So a rebase that "worked"
// leaves a red build on the next person's commit, with the mismatch attributed
// to them.
//
// **It cannot see a version regression.** Two runs publishing the same id can
// both succeed — a drain of a queued 0.2.0 landing after a fresh 0.3.0 rewrites
// `plugin.json` backwards, and every check in the job passes, because each run
// was individually correct. That is INV-12's publish-time half, and it is
// checked here, per attempt, against the tree as it is at that moment.
//
// **And the pending run it protects can be dropped.** The job carried
// `concurrency: { group: registry-publish, cancel-in-progress: false }`. GitHub
// keeps exactly one *pending* run per group: queue a third and the middle one is
// cancelled. Any stranger who can make this workflow run — a release ping is
// enough — could therefore delete another author's pending publication, and
// nothing anywhere would say so. The group is gone; this file is what makes that
// safe, because two runs racing to push now end in a refusal rather than in a
// lost commit or a silent overwrite.
//
// ── what it does NOT do ────────────────────────────────────────────────────
//
// It runs no submitter code and reads no submitter JSON as JSON beyond the
// version files it must compare. The artifact it copies from was produced by
// `bot/decide.mjs` in a job with no write access; every path is checked against
// the shape it is allowed to have before anything is copied, and the registry's
// own validator runs over the result. This file changes where those checks live,
// not how many there are.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { compareSemver, parseSemver } from "../tools/lib/semver.mjs";
import { invalidId, unsafePathComponent } from "../tools/lib/ids.mjs";

export const EXIT = { ok: 0, refused: 1, broke: 2, conflict: 3 };

/** A refusal names the file it is about, because the comment quotes it. */
export class Refusal extends Error {
  constructor(message, { file } = {}) {
    super(message);
    this.name = "Refusal";
    this.file = file ?? null;
  }
}

// The icon extensions are listed one by one rather than as `icon.*`, and must
// stay in step with `AstraPlugins/spec/icon-formats.yaml`. A glob here would
// accept `icon.sh` out of an artifact this job is about to commit.
const LISTING_FILE =
  /^plugins\/[^/]+\/(plugin\.json|README\.md|icon\.(png|webp|svg|jpg|jpeg|ico)|versions\/[^/]+\.json)$/;
const QUEUE_FILE = /^state\/queue\/[^/]+\.json$/;

/** Every file under `dir`, as paths relative to it, `/`-separated and sorted. */
export function filesUnder(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => path.relative(dir, path.join(e.parentPath ?? e.path, e.name)).split(path.sep).join("/"))
    .sort();
}

/**
 * The id a registry path belongs to, or null.
 *
 * Both shapes carry one: `plugins/<id>/…` and `state/queue/<id>@<version>.json`.
 * The queue's `@` is why this is a function and not a `split("/")[1]`.
 */
export function idOfPath(rel) {
  const listing = /^plugins\/([^/]+)\//.exec(rel);
  if (listing) return listing[1];
  const queued = /^state\/queue\/([^/@]+)@[^/]+\.json$/.exec(rel);
  if (queued) return queued[1];
  return null;
}

/**
 * Which of the paths another commit changed are a conflict with this run.
 *
 * Pure, so the interesting half of the retry loop can be tested without a
 * network, a clone or a race. The rule, from the plan (B-T0.3):
 *
 *  - a listing directory or queue entry of an id THIS run touched is a conflict:
 *    somebody else published the same plugin while this job was working, and
 *    re-applying on top would be this job deciding whose publication wins;
 *  - a path this run is deleting is a conflict for the same reason;
 *  - `state/releases-seen.json` is not a conflict — it is a cache, and the newer
 *    copy is the better one, so this run drops its own;
 *  - anything else is somebody else's plugin, and re-applying is correct.
 */
export function classifyChanges(paths, { touchedIds = new Set(), removals = [] } = {}) {
  const conflicts = [];
  let seenChanged = false;
  for (const rel of paths) {
    if (removals.includes(rel)) {
      conflicts.push(rel);
      continue;
    }
    const id = idOfPath(rel);
    if (id && touchedIds.has(id)) {
      conflicts.push(rel);
      continue;
    }
    if (rel === "state/releases-seen.json") seenChanged = true;
  }
  return { conflicts, seenChanged };
}

/**
 * The newest version already in the tree for `id`, or null.
 *
 * Read off the filenames rather than the documents: a version file is named for
 * the version it carries, `tools/validate.mjs` holds it to that, and this runs
 * before the validator on every attempt.
 */
export function newestVersionInTree(root, id) {
  const dir = path.join(root, "plugins", id, "versions");
  if (!fs.existsSync(dir)) return null;
  const versions = fs
    .readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .map((n) => n.slice(0, -".json".length))
    .filter((v) => parseSemver(v) !== null);
  if (versions.length === 0) return null;
  return versions.sort(compareSemver).at(-1);
}

/**
 * Hold one report directory's version files to the two rules that need the
 * tree, BEFORE anything is copied into it.
 *
 * Both are the same failure from two directions: a publication that rewrites
 * history. The first is a version file that already exists with different bytes
 * — a release re-cut under a tag that is already published, which no listing may
 * silently adopt. The second is INV-12's publish-time half: a version that is
 * not strictly newer than the newest already listed. A queued release drains
 * hours after it was decided, and in those hours a newer one can land; without
 * this, the drain walks the listing backwards and every check still passes.
 *
 * An identical re-publish is allowed through as a no-op, because it is one: the
 * bytes on disk do not change, so nothing is rewritten.
 */
export function refuseVersionRegressions(root, reportDir, rels) {
  for (const rel of rels) {
    const m = /^plugins\/([^/]+)\/versions\/([^/]+)\.json$/.exec(rel);
    if (!m) continue;
    const [, id, version] = m;
    const target = path.join(root, rel);
    const incoming = fs.readFileSync(path.join(reportDir, rel));
    if (fs.existsSync(target)) {
      if (!fs.readFileSync(target).equals(incoming)) {
        throw new Refusal(
          `${rel} is already published with different bytes; a released version is never rewritten`,
          { file: rel },
        );
      }
      continue;
    }
    const newest = newestVersionInTree(root, id);
    if (newest !== null && compareSemver(version, newest) <= 0) {
      throw new Refusal(
        `${rel} is not newer than ${newest}, which is already listed (INV-12)`,
        { file: rel },
      );
    }
  }
}

/**
 * Copy one report directory into the tree, checking every path first.
 *
 * `reports/*\/` globs WITH a trailing slash in the shell this replaces, so
 * `$dir/plugins` was `reports/1//plugins`, `find` printed the doubled separator
 * back verbatim, and stripping the prefix left a LEADING SLASH on every path —
 * `/plugins/x/plugin.json`, which matched neither shape pattern. Both guards
 * therefore rejected every file they were ever handed, and the zero-touch
 * publication this workflow exists to perform had never once run to completion.
 * `path.relative` cannot produce that, which is half of why this is here.
 */
export function applyReport(root, reportDir, state) {
  // Only `plugins/` and `state/` are copied, and that is not tidiness: the
  // artifact this reads is the whole of `bot/decide.mjs`'s output directory, so
  // it also carries `comment.md` and `decision.json` — which the `comment` job
  // downloads from the same artifact and which must never reach the tree. The
  // shell this replaces ignored them by only ever looking inside those two
  // directories, and a stricter "every file must be a listing file" written here
  // would have refused every real publication on its first run. A top-level
  // DIRECTORY that is neither is refused, because that is output nobody
  // designed; a top-level file is ignored, because that is where the bot's own
  // paperwork lives.
  for (const entry of fs.readdirSync(reportDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (entry.name !== "plugins" && entry.name !== "state") {
      throw new Refusal(`${entry.name}/ is not something the publish job knows how to apply`, {
        file: entry.name,
      });
    }
  }

  const rels = [
    ...filesUnder(path.join(reportDir, "plugins")).map((r) => `plugins/${r}`),
    ...filesUnder(path.join(reportDir, "state")).map((r) => `state/${r}`),
  ];

  for (const rel of rels) {
    if (!LISTING_FILE.test(rel) && !QUEUE_FILE.test(rel)) {
      throw new Refusal(`${rel} is not a listing file or a queue entry`, { file: rel });
    }
    const id = idOfPath(rel);
    const bad = id === null ? "has no id" : (unsafePathComponent(id) ?? invalidId(id));
    if (bad) throw new Refusal(`${rel}: ${bad}`, { file: rel });
  }

  refuseVersionRegressions(root, reportDir, rels);

  for (const rel of rels) {
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(reportDir, rel), target);
    state.touchedIds.add(idOfPath(rel));
    if (QUEUE_FILE.test(rel)) state.queued.push(rel);
    state.changed = true;
  }

  // What stops waiting. Only a queue entry may be deleted, and only one this
  // run is entitled to name: `remove.txt` comes out of the same artifact as the
  // files above, from a job that cannot write here.
  const removeFile = path.join(reportDir, "remove.txt");
  if (fs.existsSync(removeFile)) {
    for (const line of fs.readFileSync(removeFile, "utf8").split("\n")) {
      const rel = line.trim();
      if (!rel) continue;
      if (!QUEUE_FILE.test(rel)) throw new Refusal(`refusing to delete ${rel}`, { file: rel });
      state.removals.push(rel);
      state.touchedIds.add(idOfPath(rel));
      const target = path.join(root, rel);
      if (fs.existsSync(target)) {
        fs.rmSync(target);
        state.changed = true;
      }
    }
  }
}

/**
 * Apply everything this run has: the backstop's etag memory, then each report.
 *
 * Returns the state the retry loop reasons about. Every attempt calls this
 * again, against the tree as it is at that moment, which is the point: the
 * version rules above are only true of the tree they were checked against.
 */
export function applyAll(root, { reports, watchState, dropWatchState = false }) {
  const state = {
    changed: false,
    touchedIds: new Set(),
    removals: [],
    queued: [],
    watchState: false,
  };

  // The etag memory the backstop wrote. Not derived from anything a stranger
  // controls beyond an HTTP header, and it is a cache: the worst a bad value
  // does is cost one extra poll. `dropWatchState` is set after a competing
  // commit changed the same file — the newer memory is the better one.
  if (!dropWatchState && watchState && fs.existsSync(watchState)) {
    for (const rel of filesUnder(watchState)) {
      const target = path.join(root, "state", rel);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(watchState, rel), target);
    }
    state.changed = true;
    state.watchState = true;
  }

  if (reports && fs.existsSync(reports)) {
    for (const name of fs.readdirSync(reports).sort()) {
      const dir = path.join(reports, name);
      if (fs.statSync(dir).isDirectory()) applyReport(root, dir, state);
    }
  }

  return state;
}

const git = (root, args, opts = {}) =>
  execFileSync("git", ["-C", root, ...args], { encoding: "utf8", ...opts }).trim();

/** The registry's own rules, in the order that can pass. */
function registryChecks(root, log) {
  // It used to validate first and regenerate second, which cannot pass: the
  // committed index does not describe a listing that was added a moment ago,
  // and `validate.mjs` compares the two. The listings are still checked BEFORE
  // the generator runs, because regenerating first would feed freshly derived
  // documents to the generator ahead of the schema check.
  const steps = [
    ["tools/validate.mjs", "--allow-staging", "--no-index"],
    ["tools/build-index.mjs"],
    ["tools/build-index.mjs", "--check"],
    ["tools/validate.mjs", "--allow-staging"],
    ["tools/selftest.mjs"],
  ];
  for (const step of steps) {
    log(`    ${step.join(" ")}`);
    execFileSync(process.execPath, step, { cwd: root, stdio: "inherit" });
  }
}

/**
 * Apply, check, commit, push; on a rejected push decide whether to retry.
 *
 * `skipChecks` exists for this file's own tests, which run against a toy
 * repository with no listings in it, and `bot/tests/workflows.test.mjs` asserts
 * that no workflow ever passes it. An escape hatch that CI can reach is not an
 * escape hatch, it is the behaviour.
 */
export function run({
  root = process.cwd(),
  reports = "reports",
  watchState = "watch-state",
  base,
  remote = "origin",
  branch = "main",
  attempts = 5,
  message = "registry: publish",
  trailer = "",
  skipChecks = false,
  push = true,
  log = console.log,
} = {}) {
  const abs = (p) => (path.isAbsolute(p) ? p : path.resolve(root, p));
  let at = base ?? git(root, ["rev-parse", "HEAD"]);
  let dropWatchState = false;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    log(`attempt ${attempt} of ${attempts}, base ${at.slice(0, 8)}`);
    const state = applyAll(root, {
      reports: abs(reports),
      watchState: abs(watchState),
      dropWatchState,
    });
    // The queue entries this run is answerable for: the ones that are on disk
    // when it settles. `comment` promises an author "publishes itself at 14:00"
    // and that promise is only true if the file that makes it true reached the
    // repository — so the promise is made from this list, not from the decision.
    const queued = () => state.queued.filter((rel) => fs.existsSync(path.join(root, rel)));

    if (!state.changed) {
      log("nothing to apply");
      return { outcome: "nothing", attempts: attempt, touchedIds: [], queued: [] };
    }

    if (!skipChecks) registryChecks(root, log);

    // Named pathspecs, not `git add -A`: this job's workspace also holds the
    // downloaded artifacts, and a bare `-A` would commit them. Absent ones are
    // dropped rather than passed, because `git add` fails on a pathspec that
    // matches nothing and a registry with no `state/` yet is a legal registry.
    const pathspecs = ["plugins", "state", "registry/v1/index.json"].filter((p) =>
      fs.existsSync(path.join(root, p)),
    );
    if (pathspecs.length > 0) git(root, ["add", "-A", ...pathspecs], { stdio: "pipe" });
    if (git(root, ["diff", "--cached", "--name-only"]) === "") {
      log("nothing to commit");
      return { outcome: "nothing", attempts: attempt, touchedIds: [...state.touchedIds], queued: queued() };
    }
    git(root, ["commit", "-m", message, ...(trailer ? ["-m", trailer] : [])], { stdio: "pipe" });

    if (!push) {
      return { outcome: "committed", attempts: attempt, touchedIds: [...state.touchedIds], queued: queued() };
    }

    try {
      git(root, ["push", remote, `HEAD:${branch}`], { stdio: "pipe" });
      log(`pushed on attempt ${attempt}`);
      return { outcome: "committed", attempts: attempt, touchedIds: [...state.touchedIds], queued: queued() };
    } catch {
      log(`push refused on attempt ${attempt}; reading what landed`);
    }

    git(root, ["fetch", remote, branch], { stdio: "pipe" });
    // FETCH_HEAD, not `origin/main`: whether a one-branch fetch updates the
    // remote-tracking ref depends on the remote's configured refspec, and this
    // runs in a checkout somebody else configured.
    const head = git(root, ["rev-parse", "FETCH_HEAD"]);
    const changed = git(root, ["diff", "--name-only", at, head]).split("\n").filter(Boolean);
    const { conflicts, seenChanged } = classifyChanges(changed, {
      touchedIds: state.touchedIds,
      removals: state.removals,
    });

    if (conflicts.length > 0) {
      git(root, ["reset", "--hard", head], { stdio: "pipe" });
      return {
        outcome: "conflict",
        attempts: attempt,
        conflicts,
        head,
        touchedIds: [...state.touchedIds],
      };
    }

    if (seenChanged) dropWatchState = true;
    git(root, ["reset", "--hard", head], { stdio: "pipe" });
    at = head;
  }

  return { outcome: "exhausted", attempts };
}

function parseArgv(argv) {
  const opts = {};
  const flags = {
    "--root": "root",
    "--reports": "reports",
    "--watch-state": "watchState",
    "--base": "base",
    "--remote": "remote",
    "--branch": "branch",
    "--attempts": "attempts",
    "--message": "message",
    "--trailer": "trailer",
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--skip-checks") opts.skipChecks = true;
    else if (a === "--no-push") opts.push = false;
    else if (flags[a]) opts[flags[a]] = argv[++i];
    else throw new Refusal(`unknown argument ${a}`);
  }
  if (opts.attempts !== undefined) opts.attempts = Number(opts.attempts);
  return opts;
}

function record(result) {
  const out = process.env.GITHUB_OUTPUT;
  if (!out) return;
  const lines = [
    `outcome=${result.outcome}`,
    `attempts=${result.attempts ?? 0}`,
    `changed=${result.outcome === "committed" ? 1 : 0}`,
    `conflicts=${(result.conflicts ?? []).join(" ")}`,
    `queued=${(result.queued ?? []).join(" ")}`,
  ];
  try {
    fs.appendFileSync(out, `${lines.join("\n")}\n`);
  } catch {
    /* a missing summary file is not a reason to fail a publication */
  }
}

if (import.meta.filename === process.argv[1]) {
  let result;
  try {
    result = run(parseArgv(process.argv.slice(2)));
  } catch (err) {
    record({ outcome: "refused", attempts: 0 });
    if (err instanceof Refusal) {
      console.error(`::error::${err.message}`);
      process.exit(EXIT.refused);
    }
    console.error(err?.stack ?? String(err));
    process.exit(EXIT.broke);
  }
  record(result);
  if (result.outcome === "conflict") {
    console.error(`::error::another commit changed ${result.conflicts.join(", ")}; nothing was committed`);
    process.exit(EXIT.conflict);
  }
  if (result.outcome === "exhausted") {
    console.error("::error::the push was refused on every attempt; nothing was committed");
    process.exit(EXIT.conflict);
  }
  process.exit(EXIT.ok);
}
