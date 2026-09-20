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

/** The registry's own rules refused the derived listing. Not a bug in the bot. */
export class ChecksFailed extends Error {
  constructor(message) {
    super(message);
    this.name = "ChecksFailed";
  }
}

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

/**
 * B-T3.4's half of this file, refused by name.
 *
 * Shaped like `bot/baseline.mjs`'s own refusals and for the reason
 * `dev/couplings.md` now carries as a rule: a refusal that holds a defect out
 * of reach is a refusal whose removal SHIPS the defect, so it names what it
 * protects, and whoever lifts it runs what was behind it end to end.
 *
 * B-T3.4 asks this job to commit, in ONE commit: a decision record per state
 * entry, identity records, queue entries carrying `decision_id`, and
 * `state/alerts/` records — with **a version or queue addition carrying no
 * record refused**. The allow-list above is what would have to widen for any
 * of it, and widening it is the whole risk: it is the line between a job that
 * may write four shapes of file and one that may write `log/` as well.
 *
 * ONE THING IS NOT ON `main`, re-measured 2026-09-20 **after** B-T3.1 landed:
 *
 *   * **`bot/lib/decisions.mjs`** (B-T2.2) — the record writer. Without it no
 *     record exists for an addition to be checked against, so "a version
 *     without its record is refused" is either inert or refuses every
 *     publication this registry makes. Inert is the worse of the two: it
 *     reads, in a wall of green, exactly like a check that passed.
 *   * ~~`.github/workflows/plugins-ingest.yml`~~ (B-T3.1) — **landed
 *     `e6520be`**, twelve jobs, and the `publish` job this function belongs
 *     to is one of them. The line above used to say TWO, and this is the
 *     third module header in this repository to state an absence that had
 *     stopped being true — after `bot/baseline.mjs` and `bot/lib/identity.mjs`,
 *     both the same day. A header stating an absence has no reader that can
 *     disagree with it: nothing executes a comment, so there is no run in
 *     which it goes red, and the commits that edit the file around it do not
 *     re-read it.
 *
 * **The refusal below is unchanged, deliberately.** It checks the `available`
 * argument its caller passes, not which files exist, so it stops being a
 * refusal when a caller can supply both — not when one of the two lands.
 * `recordCommitRefusal`'s two-argument shape and `bot/tests/policy.test.mjs`'s
 * assertions stay exactly as they are: landing the piece a refusal names is
 * not a licence to loosen the refusal.
 *
 * So the allow-list is not widened here. Widening it now opens the door
 * before anything is behind it — a `publish` job entitled to write `log/`,
 * with no writer, no record requirement and no canary, is strictly worse than
 * one that cannot — and on the day the writer lands nobody re-reads this
 * function.
 *
 * What IS built: BOT-92's suppression, at `bot/lib/policy/decision.mjs`'s
 * funnel, where a shadow answer empties every member that could cause a write
 * rather than the four kinds the plan happens to name.
 *
 * @param {{decisionsWriter?: unknown, jobGraph?: unknown}} available
 */
export function recordCommitRefusal(available = {}) {
  const missing = [];
  if (!available.decisionsWriter) {
    missing.push(
      "`bot/lib/decisions.mjs` (B-T2.2), which derives BOT-35's `decision_id` and renders BOT-37's " +
      "trailers. Nothing else may compose a record: a second composer is a second answer to what a " +
      "decision id is, and the two collide silently because both are 32 hex characters",
    );
  }
  if (!available.jobGraph) {
    missing.push(
      "`.github/workflows/plugins-ingest.yml` (B-T3.1), whose `publish` job this is. `ingest.yml`'s " +
      "publish job is the legacy one, and B-T3.7 keys its record writing on `log/baseline.json`",
    );
  }
  if (missing.length === 0) return { ok: true, reason: "every input the record commit needs is present" };
  return {
    ok: false,
    reason:
      "this job cannot commit decision records, and says so rather than widening its allow-list to a " +
      "directory nothing writes: " + missing.join("; ") +
      ". BOT-92's suppression is in bot/lib/policy/decision.mjs and is not affected.",
  };
}

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

  // What stops waiting. Only a queue entry may be deleted, and only one this
  // run is entitled to name: `remove.txt` comes out of the same artifact as the
  // files above, from a job that cannot write here.
  //
  // Read and CHECKED here, before the copy loop, and deleted after it. Every
  // refusal this function can raise now happens before it writes anything,
  // which is what lets `applyAll` skip one bad report and keep the rest of the
  // run: a report that is refused half-way through copying is a report that
  // cannot be skipped, only aborted on.
  const removeFile = path.join(reportDir, "remove.txt");
  const removals = !fs.existsSync(removeFile)
    ? []
    : fs
        .readFileSync(removeFile, "utf8")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
  for (const rel of removals) {
    if (!QUEUE_FILE.test(rel)) throw new Refusal(`refusing to delete ${rel}`, { file: rel });
    if (idOfPath(rel) === null) throw new Refusal(`${rel}: has no id`, { file: rel });
  }

  for (const rel of rels) {
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(reportDir, rel), target);
    state.touchedIds.add(idOfPath(rel));
    if (QUEUE_FILE.test(rel)) state.queued.push(rel);
    state.changed = true;
  }

  for (const rel of removals) {
    state.removals.push(rel);
    state.touchedIds.add(idOfPath(rel));
    const target = path.join(root, rel);
    if (fs.existsSync(target)) {
      fs.rmSync(target);
      state.changed = true;
    }
  }
}

/**
 * Report directories in the order the bot decided them, not in the order a
 * string sort puts them.
 *
 * The artifacts are named `ingest-report-<strategy.job-index>`, the index is a
 * decimal that reaches 19 (`MAX_DISPATCH` in `bot/watch.mjs`), and a plain sort
 * gives 0, 1, 10, 11, …, 19, 2, 3 — so on the busiest drains, and only on those,
 * the queue order that `readQueue` carefully sorted by `publish_after` was
 * discarded. Two ripe releases of one plugin would then be applied newest-first,
 * and `refuseVersionRegressions` would refuse the older one for being older,
 * correctly, having been handed them backwards.
 */
export function compareReportNames(a, b) {
  const n = (s) => {
    const m = /(\d+)\s*$/.exec(s);
    return m ? Number(m[1]) : null;
  };
  const [x, y] = [n(a), n(b)];
  if (x !== null && y !== null && x !== y) return x - y;
  return a < b ? -1 : a > b ? 1 : 0;
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
    refusals: [],
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
    for (const name of fs.readdirSync(reports).sort(compareReportNames)) {
      const dir = path.join(reports, name);
      if (!fs.statSync(dir).isDirectory()) continue;
      try {
        applyReport(root, dir, state);
      } catch (err) {
        // One report's refusal is one release's refusal. It used to be the
        // whole run's: a single bad report aborted the process before anything
        // was committed, which also meant the `remove.txt` that would have
        // cleared the offending queue entry was never applied — so the drain
        // re-dispatched the identical set an hour later and refused again, and
        // every other author in that batch lost their publication each time.
        //
        // Safe to continue because `applyReport` raises every refusal it has
        // before it copies anything, so a refused report has written nothing.
        if (!(err instanceof Refusal)) throw err;
        state.refusals.push({ report: path.basename(dir), file: err.file, message: err.message });
      }
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

  // Anything thrown out of an attempt leaves the checkout as it was found. The
  // workspace is a runner and is discarded either way, but three tests assert
  // "the working tree is untouched" and until this existed they only ever
  // asserted it on the refusal paths, which throw before the copy loop and so
  // could not have dirtied it. An assertion that can only pass is not one.
  const attemptFailed = (err) => {
    try {
      git(root, ["reset", "--hard", at], { stdio: "pipe" });
      const present = ["plugins", "state"].filter((d) => fs.existsSync(path.join(root, d)));
      if (present.length > 0) git(root, ["clean", "-qfd", "--", ...present], { stdio: "pipe" });
    } catch {
      /* the tree is already beyond tidying; the thrown error is the news */
    }
    throw err;
  };

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

    const refusals = state.refusals;
    for (const r of refusals) log(`refused ${r.report}: ${r.message}`);

    if (!state.changed) {
      // Nothing landed. Which of the two "nothings" it is matters to the
      // author: an empty run is routine, a run where every report was refused
      // is a refusal and has to exit non-zero and say so.
      log(refusals.length > 0 ? "every report was refused" : "nothing to apply");
      return {
        outcome: refusals.length > 0 ? "refused" : "nothing",
        attempts: attempt,
        touchedIds: [],
        queued: [],
        refusals,
      };
    }

    if (!skipChecks) {
      try {
        registryChecks(root, log);
      } catch (err) {
        // A failed registry check is the derived listing being refused by this
        // repository's own rules — the single most likely real failure of a
        // publication, and not the bot breaking. It used to reach the CLI as a
        // plain Error, which recorded `outcome=refused` and then exited with
        // the code for "the bot broke": three answers to one question, in the
        // exit code, the step output and two comments.
        attemptFailed(new ChecksFailed(`${err?.message ?? err}`.split("\n")[0]));
      }
    }

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
      return { outcome: "nothing", attempts: attempt, touchedIds: [...state.touchedIds], queued: queued(), refusals };
    }
    git(root, ["commit", "-m", message, ...(trailer ? ["-m", trailer] : [])], { stdio: "pipe" });

    if (!push) {
      return { outcome: "committed", attempts: attempt, touchedIds: [...state.touchedIds], queued: queued(), refusals };
    }

    try {
      git(root, ["push", remote, `HEAD:${branch}`], { stdio: "pipe" });
      log(`pushed on attempt ${attempt}`);
      return { outcome: "committed", attempts: attempt, touchedIds: [...state.touchedIds], queued: queued(), refusals };
    } catch (err) {
      // Only a rejection meaning "somebody else got there first" is worth
      // retrying. A branch protection, a revoked token or a hook that declined
      // is refused identically by every attempt, and five retries of that end
      // in a message telling an author another commit changed their listing —
      // which is false, and the kind of false that sends somebody to look in
      // the wrong repository. Anything unrecognised stops here, carrying what
      // git actually said.
      const said = `${err?.stderr ?? ""}${err?.stdout ?? ""}`;
      if (!/non-fast-forward|fetch first|behind its remote|\[rejected\]/i.test(said)) {
        attemptFailed(
          new Error(`the push was refused for a reason that will not change on a retry:\n${said.trim()}`),
        );
      }
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

    // A path another commit touched is not by itself a conflict, and treating
    // it as one told two runs publishing the SAME release that somebody had
    // changed their listing. What decides it is `refuseVersionRegressions`, on
    // the next attempt, against the tree as it now is: identical bytes apply
    // and commit nothing, an older version is refused for being older, and a
    // newer one lands. So this logs what moved and re-applies; the only thing
    // that ends the run with nothing committed is a refusal, which names the
    // release it is about, or running out of attempts.
    if (conflicts.length > 0) {
      log(`another commit changed ${conflicts.join(", ")}; re-applying and letting the version rules judge`);
    }

    if (seenChanged) dropWatchState = true;
    git(root, ["reset", "--hard", head], { stdio: "pipe" });
    at = head;
  }

  return { outcome: "exhausted", attempts, refusals: [], queued: [] };
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
  // These five keys are the whole contract with `.github/workflows/ingest.yml`,
  // which reads them as `steps.apply.outputs.*` and republishes three as job
  // outputs. `bot/tests/workflows.test.mjs` asserts that every key written here
  // is read there and every key read there is written here — this file and that
  // YAML were the only two places that knew, and nothing compared them.
  const lines = [
    `outcome=${result.outcome}`,
    `attempts=${result.attempts ?? 0}`,
    `changed=${result.outcome === "committed" ? 1 : 0}`,
    `queued=${(result.queued ?? []).join(" ")}`,
    `refused=${(result.refusals ?? []).map((r) => r.report).join(" ")}`,
  ];
  try {
    fs.appendFileSync(out, `${lines.join("\n")}\n`);
  } catch {
    /* a missing summary file is not a reason to fail a publication */
  }
}

/** Every outcome `run` can return, and what the process exits with for it. */
export const OUTCOMES = {
  committed: EXIT.ok,
  nothing: EXIT.ok,
  refused: EXIT.refused,
  "checks-failed": EXIT.refused,
  exhausted: EXIT.conflict,
};

if (import.meta.filename === process.argv[1]) {
  let result;
  try {
    result = run(parseArgv(process.argv.slice(2)));
  } catch (err) {
    // The outcome is decided BEFORE it is recorded. The version this replaces
    // wrote `outcome=refused` into the step output and then chose an exit code
    // separately, so a failed registry check reported "refused" to the author's
    // comment and "the bot broke" to the workflow, out of one error.
    const outcome =
      err instanceof ChecksFailed ? "checks-failed" : err instanceof Refusal ? "refused" : "broke";
    record({ outcome, attempts: 0 });
    if (outcome === "checks-failed") {
      console.error(`::error::this repository's own rules refused the derived listing: ${err.message}`);
      process.exit(EXIT.refused);
    }
    if (outcome === "refused") {
      console.error(`::error::${err.message}`);
      process.exit(EXIT.refused);
    }
    console.error(err?.stack ?? String(err));
    process.exit(EXIT.broke);
  }
  record(result);
  for (const r of result.refusals ?? []) {
    console.error(`::warning::${r.report} was refused and the rest of the run went on: ${r.message}`);
  }
  if (result.outcome === "exhausted") {
    console.error(
      `::error::the tree moved under this run ${result.attempts} times running; nothing was committed. ` +
        "Every attempt re-applied and re-checked cleanly and was then beaten to the push, which is a " +
        "publication rate this design did not expect rather than a conflict with any one listing.",
    );
    process.exit(EXIT.conflict);
  }
  const code = OUTCOMES[result.outcome];
  if (code === undefined) {
    console.error(`::error::unknown outcome ${result.outcome}; treating it as a fault in this file`);
    process.exit(EXIT.broke);
  }
  process.exit(code);
}
