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
// `--approved-by <login> --approved-at <iso> --approved-for <fingerprint>` — a
// maintainer's `/approve`, already permission-checked against the GitHub API by
// `bot/lib/maintainer.mjs` in the triage job. It clears the hold and nothing
// else. Note where it enters: **after** `ingest()` has run in full, so it cannot
// shorten a single check. It reaches `decide()` as three strings and is written
// into `decision.json` beside the digests this run hashed, so "who let this in,
// when, against which bytes" has one answer with no gap in it.
//
// The third flag is what makes the first two mean anything. `--approved-for` is
// the fingerprint of the submission the maintainer was looking at, copied out of
// the comment they answered; `bot/lib/policy.mjs` recomputes it from this run
// and refuses the approval when the two differ. Without it an approval says
// "yes" without saying to what, and the repository and tag it applies to were
// re-read from an issue body the author can edit after the hold.

import fs from "node:fs";
import path from "node:path";

import { loadSources, REPO_ROOT } from "../tools/lib/sources.mjs";

import { markerOnMain, readDecisionRecords } from "./baseline.mjs";
import { ingest, writeListing } from "./ingest.mjs";
import {
  decide,
  queueFile,
  readQueueEntry,
  renderPolicySection,
  trackRecord,
} from "./lib/policy.mjs";

const EXIT = { publish: 0, refuse: 1, review: 3, delay: 4 };

// ── the outcomes that are reached before the policy is asked (B-T3.3c) ─────
//
// Three of B-T3.3c's five rules are not policy questions at all. They are
// answers about what is ALREADY in git — a terminal record, a published
// version, a repository no listing names — and the run that meets one has
// nothing to decide and nothing to write.
//
// They live here, in the caller, and not in `decide()`, for the reason
// B-T3.3a wrote down when it refused to add a fifth outcome for a wait:
// `decide()` answers `publish`, `delay`, `review` or `refuse`, and a fifth
// value has to be understood by `bot/lib/policy/comment.mjs`'s headline map
// and by the exit map below — with the failure mode of an unrecognised
// outcome being a comment with no headline and exit 2. A caller that stops
// before asking needs neither.
//
// Each one carries `record.write: false` in the same shape `decide()` returns,
// so the writer downstream asks one question of every answer rather than
// asking a different question of each kind.

/**
 * BOT-19: what `main` already says about this submission.
 *
 * Searched BEFORE the service is asked, so that a stop recorded in the panel
 * stops a ping too. A terminal record is REPORTED and nothing is written: a
 * second record saying the same thing is a second answer to "what did the
 * registry decide", and the two can drift.
 *
 * Terminal is asked as a property of the record's state, over the set of
 * states `records` carries, rather than as a list of the terminal state names
 * that existed when this was written. The set is `main`'s to grow.
 *
 * @param {{records: object[], pluginId: string|null, repo: string, tag: string|null}} opts
 */
export function terminalOnMain({ records = [], pluginId, repo, tag }) {
  const TERMINAL = new Set(["refused", "revoked", "yanked", "withdrawn", "deprecated"]);
  const mine = records.filter((r) =>
    (pluginId && r?.plugin_id === pluginId) ||
    (r?.repo === repo && tag && r?.tag === tag));
  const hit = mine.filter((r) => TERMINAL.has(String(r?.state))).at(-1) ?? null;
  if (!hit) return null;
  return {
    reported: hit.state,
    names: hit.decision_id ?? null,
    record: {
      write: false,
      why:
        `BOT-19: \`main\` already carries a ${hit.state} record for this work ` +
        `(${hit.decision_id ?? "no decision_id"}), and a second record saying the same thing is a second ` +
        "answer to what the registry decided",
    },
  };
}

/**
 * BOT-74: a registered tag already listed with identical digests.
 *
 * Reported `published`, naming the existing record. Not "already listed, so
 * refuse" and not "list it again": the registry's answer to a re-submission of
 * bytes it has already published is the publication it already made, and the
 * result names the record so the asker can go and read it.
 *
 * The digests are what makes this safe. A tag that moved to different bytes is
 * NOT this case — it is a new submission of the same name — and comparing by
 * tag alone would answer `published` for bytes nobody ever verified.
 *
 * @param {{listed: {version: string, artifact_digests?: string[], decision_id?: string}|null,
 *   digests: string[]}} opts
 */
export function alreadyPublished({ listed, digests }) {
  if (!listed || !Array.isArray(digests) || digests.length === 0) return null;
  const theirs = [...(listed.artifact_digests ?? [])].sort();
  const mine = [...digests].sort();
  if (theirs.length === 0 || JSON.stringify(theirs) !== JSON.stringify(mine)) return null;
  return {
    reported: "published",
    names: listed.decision_id ?? null,
    record: {
      write: false,
      why:
        `BOT-74: ${listed.version} is listed already with these exact ${mine.length} artifact digest(s), and ` +
        `the answer to a re-submission of published bytes is the publication that already happened` +
        (listed.decision_id ? ` (${listed.decision_id})` : ""),
    },
  };
}

/**
 * FLOW-67: a `panel` or `ci` submission that no listing names, with no usable
 * binding line.
 *
 * Nothing is written. The submission is from a repository this registry has
 * never listed and which has not said, at the attested commit, that it wants
 * to be — so there is nothing to decide about, and a refusal record would be a
 * durable statement about a stranger's repository made on the strength of one
 * unsolicited call.
 *
 * FLOW-78: the result carries the COMMIT the absence was read at. Without it
 * "no listing names this repository" is a claim about a moving target, and an
 * author who adds the line cannot tell whether the registry looked before or
 * after they pushed it.
 *
 * The two sources are read from the submission rather than hard-coded here,
 * and the rule is "a source that reaches the registry without a thread" — the
 * legacy `issue` and `ping` paths have a thread to answer on, so a refusal
 * there is a sentence somebody reads.
 *
 * @param {{source: string|null, listingNamesRepo: boolean, binding: {present: boolean, code?: string|null}|null,
 *   readCommit: string|null, repo: string}} opts
 */
export function noListingNoBinding({ source, listingNamesRepo, binding, readCommit, repo }) {
  const THREADLESS = new Set(["panel", "ci"]);
  if (!THREADLESS.has(String(source))) return null;
  if (listingNamesRepo) return null;
  const unusable = !binding?.present || binding?.code === "B_BINDING_UNUSABLE";
  if (!unusable) return null;
  return {
    reported: "refused",
    read_commit: readCommit ?? null,
    record: {
      write: false,
      why:
        `FLOW-67: no listing names ${repo} at ${readCommit ?? "the read commit"} and its binding line is ` +
        `${binding?.present ? binding.code : "absent"}. A ${source} submission has no thread to answer on, so a ` +
        "recorded refusal would be a durable statement about a stranger's repository made on one unsolicited call",
    },
  };
}

/** @param {string[]} argv */
export function parseArgs(argv) {
  // No `--roots`: the root keys are compiled into `bot/lib/roots.mjs` and no
  // command line chooses them (B-T1.5). `deps.rootKeys` is the test seam, and
  // it passes straight through `decideRelease` into `ingest`.
  const opts = {
    repo: null, tag: null, submitter: null, root: REPO_ROOT, out: null,
    issue: null, trustFile: null, signerWorkflow: null,
    hostAstraVersion: null, now: null, approvedBy: null, approvedAt: null, approvedFor: null, publishNow: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--repo") opts.repo = argv[++i];
    else if (a === "--tag") opts.tag = argv[++i];
    else if (a === "--submitter") opts.submitter = String(argv[++i]).replace(/^@/, "");
    else if (a === "--issue") opts.issue = Number(argv[++i]) || null;
    // A maintainer's `/approve`, already permission-checked by
    // `bot/lib/maintainer.mjs` in the triage job. It carries a name, a moment
    // and the NAME OF WHAT WAS APPROVED — no verdict, no digest, no listing.
    // This run ingests the release from scratch; the flags only say that the
    // hold `bot/lib/policy.mjs` would otherwise raise has been answered, and
    // which submission it was answered about.
    else if (a === "--approved-by") opts.approvedBy = String(argv[++i] ?? "").replace(/^@/, "");
    else if (a === "--approved-at") opts.approvedAt = argv[++i];
    // The fingerprint out of the comment the maintainer answered. Compared, not
    // trusted: `decide()` recomputes it from the bytes this run hashed.
    else if (a === "--approved-for") opts.approvedFor = String(argv[++i] ?? "").toLowerCase();
    else if (a === "--publish-now") opts.publishNow = true;
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
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
  // FLOW-65: by plugin ID, never by repository. A monorepo's second plugin is
  // a first listing — `R_FIRST_LISTING` is the one check that is a person
  // reading a submission, and keyed on the repository it would be skipped for
  // every plugin after the first in any repository that ships more than one.
  const existing = result.derived
    ? plugins.find((p) => p.doc?.id === result.derived.plugin.id) ?? null
    : null;

  // The listing's binding, if it has one (BOT-77). Read from the checked-out
  // tree rather than passed in as a flag: `ingest.yml` hands this program a
  // repository and a tag, and a workflow input saying "this listing is bound"
  // would be a second, weaker answer to a question `main` already answers.
  const identityRecord = result.derived ? readIdentityRecord(opts.root, result.derived.plugin.id) : null;

  // BOT-19, searched BEFORE anything is decided: a stop recorded in the panel
  // stops a ping. `readDecisionRecords` reads B-T2.2's layout and needs none
  // of B-T2.2's writer, so this works from the first record and answers
  // nothing before that — which is the honest answer, not a skip.
  const records = (deps.readDecisionRecords ?? readDecisionRecords)(opts.root)
    .map((r) => r.doc).filter(Boolean);
  const terminal = terminalOnMain({
    records,
    pluginId: result.derived?.plugin?.id ?? null,
    repo: opts.repo,
    tag: opts.tag,
  });

  const decision = decide({
    identityRecord,
    path: opts.path === "service" ? "service" : "legacy",
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
    approval: opts.approvedBy
      ? { by: opts.approvedBy, at: opts.approvedAt ?? now, for: opts.approvedFor ?? null, publishNow: opts.publishNow === true }
      : null,
    now,
  });

  // BOT-19 overrides the record, and only the record. The decision itself is
  // still computed and still commented on — an author who pings a plugin the
  // registry has revoked is owed the sentence saying so — but nothing is
  // written, because `main` already carries the answer and a second record is
  // a second answer that can drift from the first.
  //
  // And B-T3.7's condition, in the same place and for the same reason: the
  // legacy path writes decision records when, and only when,
  // `log/baseline.json` is on the checked-out `main`. Before the baseline
  // exists there is nothing for a legacy record to be compared against —
  // MIG-28 holds every id with no baseline — and a record written now would
  // be a statement this registry cannot yet check.
  const marker = markerOnMain(opts.root);
  if (terminal) {
    decision.record = terminal.record;
    decision.reported = terminal.reported;
    decision.names_record = terminal.names;
  } else if (!marker.present && decision.record.write) {
    decision.record = {
      write: false,
      why:
        `B-T3.7: \`${marker.file}\` is not on the checked-out main, so the legacy path writes no decision ` +
        "records yet. MIG-20's baseline is what a record is compared against, and one written before it " +
        "exists is a statement nothing can check (B-T3.7b's dispatch writes it).",
    };
  }

  return {
    ...result,
    decision,
    comment: `${result.comment}\n${renderPolicySection(decision, result.derived)}`,
  };
}

/** `plugins/<id>/identity.json` on the checked-out tree, or null. */
export function readIdentityRecord(root, pluginId) {
  if (!pluginId) return null;
  try {
    const doc = JSON.parse(fs.readFileSync(path.join(root, "plugins", pluginId, "identity.json"), "utf8"));
    return doc && typeof doc === "object" ? doc : null;
  } catch {
    // Absent is the ordinary case before R3 and the whole case until a listing
    // is bound. Unreadable is NOT silently the same thing — but the guard this
    // feeds refuses to publish when the record is present, so a parse failure
    // that returned "absent" would be the unsafe direction, and it is reported
    // rather than swallowed.
    if (fs.existsSync(path.join(root, "plugins", pluginId, "identity.json"))) {
      throw new Error(
        `plugins/${pluginId}/identity.json is on main and could not be read. The legacy path must not ` +
        "publish a bound listing (BOT-77), and an unreadable binding is not an absent one.",
      );
    }
    return null;
  }
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
        // The issue the DECISION named, not the one this invocation was given.
        // A cron drain is given none: the release it publishes came in on a
        // thread months ago, and `finishDecision` recovered that number from the
        // queue entry. Writing `opts.issue` here published the release and then
        // answered nobody — the thread stayed open with no comment on it, and a
        // re-held drain opened a second `[notice]` beside it. That is what
        // happened at 126189c and f67a646.
        issue: decision.issue ?? opts.issue ?? null,
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
        // What this submission is called, and — when a command named something
        // else — the command that was refused. Both are the record of the
        // binding: `fingerprint` is what an `/approve` had to say, and
        // `approval_refused` is the one that did not say it.
        fingerprint: decision.fingerprint,
        approval_refused: decision.approval_refused,
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
  //
  // With one exception, and it is the invariant the approval binding rests on:
  // **a refused approval changes nothing.** When the only thing holding this run
  // is `P_APPROVAL_STALE` — a maintainer answered with a fingerprint that names
  // some other state of this release — the submission itself is exactly as it
  // was a minute ago. Deleting its queue entry would take a waiting release out
  // of the queue and restart a 24-hour clock the author is owed, because
  // somebody pasted the wrong line. Every other hold still drops the entry: those
  // are facts about the submission, and a submission that now needs a person must
  // not publish itself on a timer.
  const holds = decision.reasons.filter((r) => r.level === "review");
  const onlyStale = holds.length > 0 && holds.every((r) => r.code === "P_APPROVAL_STALE");
  const handedToAPerson = decision.outcome === "review" && !onlyStale;
  if (derived && (decision.drop_queue || decision.outcome === "refuse" || handedToAPerson)) {
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
