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

import { markerOnMain, readDecisionRecords, runTrailer } from "./baseline.mjs";
import { legacyKey, recordsOnMain, writeDecisionRecord } from "./lib/decisions.mjs";
import { artifactDigests, submissionFingerprint } from "./lib/policy/release.mjs";
import { safeRepo, safeTag } from "./lib/intake.mjs";
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
 * BOT-19: what `main` already says about THIS submission.
 *
 * Exactly the three records BOT-19 names (registry plan notes), and no
 * others: a `published`, `stopped` or `M_REJECT` `refused` record carrying
 * this run's fingerprint; and a `stopped` record for the same tag of the same
 * repository — by `repository_id` where the record carries one, by
 * `owner/name` where it does not (FLOW-26; matching by name there can only
 * withhold). "A `held` or `delayed` record MUST NOT stop the run", and
 * neither does a bot refusal of these bytes: a `/recheck` of them is exactly
 * what an author is told to do.
 *
 * **What this replaced, and why it could not stay.** The first version took
 * any "terminal-looking" state — `refused`, `revoked`, `yanked`, … — of any
 * record for the same PLUGIN ID. One old version refused, or yanked, and every
 * later release of that plugin was `reported refused` with nothing written:
 * the plugin could never publish again on the legacy path, from the first
 * day the decision log existed.
 *
 * A hit is REPORTED and nothing is written: a second record saying the same
 * thing is a second answer to "what did the registry decide".
 *
 * @param {{records: object[], fingerprint: string|null, repo: string, tag: string|null,
 *   repositoryId?: string|null}} opts
 */
export function terminalOnMain({ records = [], fingerprint = null, repo, tag, repositoryId = null }) {
  const sameRepo = (r) => (typeof r?.repository_id === "string" && typeof repositoryId === "string"
    ? r.repository_id === repositoryId
    : String(r?.repo ?? "").toLowerCase() === String(repo ?? "").toLowerCase());
  const hits = records.filter((r) => {
    if (!r) return false;
    if (fingerprint && r.fingerprint === fingerprint) {
      if (r.state === "published" || r.state === "stopped") return true;
      if (r.state === "refused" && (r.reasons ?? []).includes("M_REJECT")) return true;
    }
    return r.state === "stopped" && tag && r.tag === tag && sameRepo(r);
  });
  const hit = hits.at(-1) ?? null;
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
    source: null,
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
    // Where this run came from. DEC-7 records it as the decision's
    // `trigger`; `legacyTrigger` refuses one it cannot map (B-T3.7).
    else if (a === "--source") opts.source = argv[++i];
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

  // BOT-19's records. `readDecisionRecords` reads B-T2.2's layout and needs
  // none of B-T2.2's writer, so this works from the first record and answers
  // nothing before that — which is the honest answer, not a skip. The search
  // itself runs once the fingerprint is known, below: BOT-19 is keyed on it.
  const records = (deps.readDecisionRecords ?? readDecisionRecords)(opts.root)
    .map((r) => r.doc).filter(Boolean);

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

  // DEC-7's `trigger`, derived once and attached to the decision.
  //
  // An unmappable source does NOT throw here, and the reason is worth the
  // paragraph. Throwing was the first shape, and it turned every run that
  // sets no `--source` red at once — which today is the manual dispatch, the
  // CLI, and every caller written before this argument existed. The other
  // obvious shape, defaulting to `legacy`, is the one B-T3.7 forbids: a
  // record would then state that the backstop found a release when nobody
  // knows what found it.
  //
  // So the third: no trigger, and therefore NO RECORD, said out loud in
  // `decision.json`. The run still publishes, comments and closes its thread
  // exactly as it does today; what it cannot do is write a decision record
  // whose `trigger` would be a guess. The day the baseline lands and records
  // start being written, a caller that never set a source produces a visible
  // "no record, and here is the missing argument" rather than a plausible
  // wrong one — and `migration` still throws, because no legacy run has any
  // business composing MIG-20's baseline.
  try {
    decision.trigger = legacyTrigger(opts.source);
  } catch (e) {
    if (String(opts.source) === "migration") throw e;
    decision.trigger = null;
    decision.record = { write: false, why: e.message };
  }

  // BOT-19 over this run's fingerprint — the publication-shaped answer's own
  // one, or, for a refusal that derived no answer, the fingerprint of the
  // bytes this run hashed — and the tag.
  const fingerprint = decision.fingerprint ?? fingerprintOf(result, opts);
  const terminal = terminalOnMain({
    records,
    fingerprint,
    repo: opts.repo,
    tag: opts.tag,
    repositoryId: result.identity?.repository_id ?? null,
  });
  // BOT-74: a registered tag already listed with identical digests is the
  // publication that already happened. Without it, a re-ping of a published
  // tag is refused E_VERSION_NOT_NEW — and from MIG-20's baseline on that
  // refusal is a durable `refused` record about a release this registry
  // published.
  const listedVersion = result.derived && existing
    ? (existing.versions ?? []).map((v) => v.doc).find((d) => d?.version === result.derived.version.version) ?? null
    : null;
  const already = listedVersion
    ? alreadyPublished({
      listed: {
        version: listedVersion.version,
        artifact_digests: artifactDigests(listedVersion),
        decision_id: records.find((r) => r.state === "published" && r.plugin_id === listedVersion.id &&
          r.version === listedVersion.version)?.decision_id ?? null,
      },
      digests: artifactDigests(result.derived.version),
    })
    : null;

  if (terminal) {
    decision.record = terminal.record;
    decision.reported = terminal.reported;
    decision.names_record = terminal.names;
  } else if (already) {
    decision.record = already.record;
    decision.reported = already.reported;
    decision.names_record = already.names;
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

// ── B-T3.7: what a legacy decision record is triggered BY ─────────────────
//
// DEC-7 gives a record a `trigger`, and the legacy path's four are `issue`,
// `ping`, `dispatch`, and `legacy` for the backstop and drain publications.
// `migration` is never one of them, and that is not a naming preference: a
// `migration` record IS MIG-20's baseline, the thing TRUST-23 compares every
// later release against, and `bot/lib/identity.mjs`'s `effectiveBaseline`
// selects baselines by exactly `trigger === "migration" && state ===
// "published"`. A legacy publication that composed one would silently become
// the baseline for that id — written off an issue comment rather than off the
// single audited dispatch MIG-20 requires — and every later identity
// comparison for that plugin would be made against it.
//
// `bot/baseline.mjs` refuses every trigger BUT `migration`; this refuses
// `migration`, and refuses an unmapped source too. An unmapped source does
// not fall through to `legacy`, because "this run came from the backstop" and
// "nobody knows where this run came from" are different facts and a record
// must not state the first when the second is true.

/** The four triggers the legacy path may write (DEC-7; B-T3.7). */
export const LEGACY_TRIGGERS = Object.freeze(["issue", "ping", "dispatch", "legacy"]);

/**
 * The trigger for a legacy run, from the source that started it.
 *
 * @param {string|null} source `bot/triage.mjs`'s mode, or `bot/watch.mjs`'s
 *   dispatch `source`.
 * @returns {string} one of `LEGACY_TRIGGERS`
 */
export function legacyTrigger(source) {
  const SOURCES = {
    form: "issue", issue: "issue", approve: "issue", reject: "issue", recheck: "issue",
    ping: "ping",
    dispatch: "dispatch", repository_dispatch: "dispatch",
    backstop: "legacy", queue: "legacy", drain: "legacy", schedule: "legacy",
  };
  if (source === "migration") {
    throw new Error(
      "the legacy path composed a `migration` record. `migration` is MIG-20's baseline — the record " +
      "TRUST-23 compares every later release against, written once by `baseline.yml`'s single audited " +
      "dispatch — and one composed here would become the baseline for this id on the strength of an " +
      "issue comment (B-T3.7; BOT-39).",
    );
  }
  const trigger = SOURCES[String(source)];
  if (!trigger) {
    throw new Error(
      `\`${source}\` is not a source this registry knows how to trigger a decision record from. It is ` +
      "refused rather than recorded as `legacy`, because \"the run came from the backstop\" and \"nobody " +
      "knows where the run came from\" are different facts, and a record cannot state the first when the " +
      `second is true. The four legacy triggers are ${LEGACY_TRIGGERS.join(", ")} (DEC-7).`,
    );
  }
  return trigger;
}

// ── B-T3.7: the legacy record, composed and written ────────────────────────
//
// `decideRelease` decides whether a record is owed; this is where one is
// WRITTEN, and until B-T3.7 was built nothing was. The end-to-end test said
// `record.write: true` for a drained publication with the marker on main, and
// `log/decisions/` stayed empty — a record owed and never made, on the one
// path every publication before R6 takes.
//
// The record goes into the OUT directory, under `log/decisions/<YYYY>/<MM>/`,
// beside the listing files, because this runs in the `check` job, which holds
// no write access: `bot/publish-apply.mjs` copies it to `main` in the same
// commit as the publication it records (BOT-34, BOT-73), and refuses that
// publication without it once the marker is on the tree.

/** DEC-7's state for each of `decide()`'s four outcomes. `stopped` is the moderation run's. */
export const LEGACY_STATE = Object.freeze({ publish: "published", delay: "delayed", review: "held", refuse: "refused" });

/** A B.7 code as DEC-7's `reasons` holds one (schema/decision-v1.json). */
const REASON_CODE_RE = /^[A-Z]_[A-Z0-9]+(?:_[A-Z0-9]+)*$/;
const SHA1_RE = /^[0-9a-f]{40}$/;
const BASE10_RE = /^[0-9]{1,20}$/;

/**
 * DEC-7's record for one legacy decision, and the BOT-35 key it is filed under.
 *
 * Every member is taken from what THIS run established — the derived listing,
 * the certificate's identity, the policy's answer — and nothing from the
 * issue thread: no login (PRIV-2; a maintainer's `/approve` is recorded as the
 * bot's decision and names nobody), no issue number (OD-2), no free text
 * (`reasons` is codes). Absent where it does not apply, never null.
 *
 * @returns {{key: string, record: object}}
 */
export function composeLegacyRecord(result, opts) {
  const { decision, derived, identity } = result;
  if (!LEGACY_TRIGGERS.includes(decision?.trigger)) {
    throw new Error(
      `a legacy record was asked for with trigger ${JSON.stringify(decision?.trigger ?? null)}. The legacy path ` +
      `writes ${LEGACY_TRIGGERS.join(", ")} and nothing else: \`migration\` is MIG-20's baseline, written once ` +
      "by baseline.yml's single audited dispatch, and a legacy run that composed one would become the baseline " +
      "for this id on the strength of an issue comment (B-T3.7; BOT-39)",
    );
  }
  const state = LEGACY_STATE[decision.outcome];
  if (!state) throw new Error(`${JSON.stringify(decision.outcome)} is not an outcome a legacy record has a state for`);
  if (decision.wait) {
    throw new Error("a wait was handed to the record writer; waits never record (FLOW-72)");
  }
  const repo = safeRepo(derived?.version?.release?.repo ?? null) ?? safeRepo(opts.repo);
  const tag = safeTag(opts.tag);
  if (!repo || !tag) throw new Error("a legacy record names a repository and a tag, and this run has neither in grammar");
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const reasons = [...new Set([
    ...findings.filter((f) => f?.level === "error" || f?.level === "review").map((f) => f.code),
    ...(decision.reasons ?? []).map((r) => r?.code),
  ])].filter((c) => typeof c === "string" && c.length <= 64 && REASON_CODE_RE.test(c)).sort();
  const commit = derived?.version?.release?.commit;
  const ids = identity && typeof identity.repository_id === "string" && BASE10_RE.test(identity.repository_id) &&
    typeof identity.repository_owner_id === "string" && BASE10_RE.test(identity.repository_owner_id)
    ? { repository_id: identity.repository_id, repository_owner_id: identity.repository_owner_id } : {};
  const run = runTrailer(process.env);
  const record = {
    decided_at: decision.decided_at,
    actor: "bot",
    trigger: decision.trigger,
    ...(derived?.plugin?.id ? { plugin_id: derived.plugin.id } : {}),
    ...(derived?.version?.version ? { version: derived.version.version } : {}),
    repo,
    ...ids,
    tag,
    ...(typeof commit === "string" && SHA1_RE.test(commit) ? { commit } : {}),
    ...(Array.isArray(decision.artifact_digests) && decision.artifact_digests.length
      ? { artifact_digests: [...new Set(decision.artifact_digests)].sort() } : {}),
    ...(decision.fingerprint ? { fingerprint: decision.fingerprint } : {}),
    state,
    ...(reasons.length ? { reasons } : {}),
    ...(state === "delayed" && decision.publish_after ? { publish_after: decision.publish_after } : {}),
    ...(run ? { run } : {}),
  };
  return { key: legacyKey({ repo, tag, fingerprint: decision.fingerprint ?? null, state }), record };
}

/** The fingerprint of the bytes this run hashed, when the policy's answer carries none. */
function fingerprintOf(result, opts) {
  const v = result.derived?.version;
  if (!v) return null;
  return submissionFingerprint({
    repo: opts.repo, tag: opts.tag, id: result.derived.plugin.id, version: v.version,
    commit: v.release?.commit ?? null, digests: artifactDigests(v),
  });
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
  // The record is composed BEFORE anything is written, so a refusal — a
  // `migration` trigger, a state with no outcome — leaves no half-written out
  // directory behind for the publish job to find.
  //
  // Asked of the tree the run READ (`opts.root`), twice over: the marker gate
  // again, because this function is the writer and `decideRelease` is only one
  // of its callers; and BOT-36's dedupe, against the records `main` already
  // carries — a re-run, or a drain that re-decides a release it already
  // recorded, finds the same id and writes nothing.
  const root = opts.root ?? REPO_ROOT;
  const planned = decision?.record?.write === true && markerOnMain(root).present
    ? composeLegacyRecord(result, opts)
    : null;
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
        // DEC-7's trigger, and whether this run writes a record at all. The
        // publish job reads both: `record.write` is false for a wait, for a
        // decision `main` already carries, and for every shadow answer, and
        // the four outcomes cannot express any of those three (B-T3.3c,
        // B-T3.4, B-T3.7).
        trigger: decision.trigger,
        record: decision.record,
        shadow: decision.shadow === true,
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

  // BOT-19 and BOT-74: a hit on `main` is REPORTED and writes nothing — no
  // listing, no queue entry, no removal. `decideRelease` already withholds the
  // record on a hit; the listing was still written whenever the policy said
  // `publish`, so a re-run of a release a moderator had rejected (`M_REJECT`
  // on main for these bytes) carried the rejected version into the publish
  // job's tree, and the rejection was undone by a re-run (the canary walk
  // ROLL-25 (2), B-T4.1).
  const hit = typeof decision.reported === "string";

  // `writeListing`, rather than a second copy of it. There were two writers —
  // this one, and `ingest.mjs`'s, which lays out the tree the validator checks.
  // When a listing gained an icon and a README, only one of them learned to
  // write the files. So the validator passed on a tree that had them and this
  // function committed one that did not, and the run died on the repository's
  // own rule: `icon "icon.svg" is named here but the file is not in
  // plugins/dice-roller/`. That is the check working, on a document this
  // function had made wrong.
  if (!hit && decision.publishes_now && derived) {
    writeListing(path.join(out, "plugins", derived.plugin.id), derived);
  }

  if (!hit && decision.queue_entry) {
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
  if (!hit && derived && (decision.drop_queue || decision.outcome === "refuse" || handedToAPerson)) {
    removals.push(queueFile(derived.plugin.id, derived.version.version));
  }
  fs.writeFileSync(path.join(out, "remove.txt"), removals.map((r) => `${r}\n`).join(""));

  const record = planned
    ? writeDecisionRecord({ key: planned.key, record: planned.record, root: out, existing: recordsOnMain(root) })
    : null;
  return { removals, record };
}

async function main(argv) {
  const opts = parseArgs(argv);
  const result = await decideRelease(opts);
  console.log(result.comment);
  if (opts.out) {
    const { record } = writeOutputs(opts.out, opts, result);
    if (record) console.error(`decision record ${record.decision_id}: ${record.written ? `written, ${record.path}` : record.dropped}`);
  }
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
