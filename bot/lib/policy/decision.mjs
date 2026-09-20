// The decision itself — whether a release publishes now, waits, or waits for a
// person.
//
// Split out of `bot/lib/policy.mjs` on 2026-09-19. This is the spine: it is the
// module the other six serve, and the one a change to the policy actually
// edits.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { compareSemver, parseSemver } from "../../../tools/lib/semver.mjs";

import {
  CLEAN_RELEASES_FOR_TRUSTED,
  CONSENT_HIGH_RISK,
  DELAY_HOURS,
  HIGH_RISK,
  KNOWN_AUTHORITY,
  POLICY_CODES,
  REVIEW_SLA_HOURS,
  TRUSTED_DELAY_HOURS,
  policyCodeDef,
} from "./constants.mjs";
import {
  FINGERPRINT_CHARS,
  artifactDigests,
  highRiskIn,
  newestListedVersion,
  requestedAuthority,
  submissionFingerprint,
} from "./release.mjs";
import { loadRevocations, trackRecord } from "./track-record.mjs";
import { queueFile, readQueueEntry, ripeQueueEntries } from "./queue.mjs";
import { HOUR_MS, iso } from "./time.mjs";


/**
 * Decide what happens to one ingested release.
 *
 * Pure: every input is data, `now` included, so a test can stand at any point
 * in a delay window without waiting or stubbing a clock.
 *
 * @param {{
 *   findings: {level: string, code: string, where?: string, message: string}[],
 *   derived: {plugin: object, version: object}|null,
 *   existing: object|null,
 *   repo: string,
 *   tag?: string|null,
 *   submitter?: string|null,
 *   issue?: number|null,
 *   track?: object,
 *   queued?: object|null,
 *   approval?: {by: string, at: string}|null,
 *   now?: Date,
 * }} input
 */
export function decide(input) {
  const { findings = [], derived, existing = null, repo } = input;
  const now = input.now ?? new Date();
  const track = input.track ?? { tier: "new", clean_releases: 0, delay_hours: DELAY_HOURS, revoked: false };
  const queued = input.queued ?? null;
  const typed = normaliseApproval(input.approval);
  const reasons = [];

  // The thread that asked for this release, carried onto every decision so a run
  // that publishes can close it. On the issue paths it is the event's own number;
  // on the cron drain there is no event, and the QUEUE ENTRY is the only thing
  // left that remembers which issue this release came from. Read only when the
  // entry is about this exact release — a stale entry naming some other tag must
  // not lend its issue number to this one.
  const finish = (d) => finishDecision({
    issue: input.issue
      ?? (queued && queued.repo === repo && queued.tag === input.tag ? queued.issue ?? null : null),
    ...d,
  });

  // Which path is asking. It changes what five codes MEAN (FLOW-72: on the
  // service path `E_PROBE_UNAVAILABLE` and its four siblings are waits, not
  // refusals), so it is threaded through every level lookup rather than
  // consulted once. Default `legacy`, which is what every caller on `main`
  // today is.
  const path = input.path === "service" ? "service" : "legacy";
  const add = (code, message) => reasons.push({ code, level: policyCodeDef(code, { path }).level, message });

  // 0 ── FLOW-72: a wait is not a finding about the submission, and waits
  //      never record.
  //
  // Written as a property over the SET of findings, read through the level
  // each code is DECLARED at in `constants.mjs`, and not as a list of the wait
  // codes that existed when this was written. The list-shaped version of this
  // rule is wrong the moment a sibling task coins a sixth wait: the code is
  // handed straight to stage 1 below, `level === "error"` is true of it, and a
  // read that did not happen is written into `log/decisions/` as a refusal of
  // somebody's release. That record cannot be un-written, and the author's
  // answer to it — a `/recheck` — is the one thing that cannot help.
  //
  // Only ever an UPGRADE. `policyCodeDef` answers `error` for every code it
  // does not know, so a downgrade here would quietly re-level the whole of
  // `codes.mjs`; the condition asks whether the code is declared a wait on
  // THIS path, and leaves every other finding exactly as the check left it.
  // **Only an `error` is reclassified**, and this qualifier was not obvious
  // until the rule was run against the real corpus. A code in `codes.mjs`
  // names a CHECK, not an outcome, and the same code carries the check's pass
  // as well as its failure: every green ingest emits `E_TRUST_UNPROVISIONED`
  // at level `pass` with the message "trust.json serial 7 … allows 1
  // release-workflow commit(s)", and `E_DERIVED_LISTING_INVALID` at `pass`
  // with "the derived listing passes tools/validate.mjs". Reclassified on the
  // code alone, every successful service-path run would have waited on its
  // own passing checks, for ever, and the release would never have been
  // decided at all. FLOW-72 reclassifies a REFUSAL into a wait; it has nothing
  // to say about a check that answered.
  const levelled = findings.map((f) => {
    if (f.level !== "error") return f;
    const declared = policyCodeDef(f.code, { path });
    return declared.level === "wait" ? { ...f, level: "wait" } : f;
  });
  const waits = levelled.filter((f) => f.level === "wait");
  if (waits.length) {
    for (const w of waits) reasons.push({ code: w.code, level: "wait", message: w.message });
    return finish({
      // No fifth outcome, on purpose — `bot/lib/policy/comment.mjs`'s headline
      // map and `bot/decide.mjs`'s exit map are two files this task does not
      // own, and an unrecognised outcome renders as a comment with no headline
      // and exit 2. What distinguishes a wait from a refusal is `record.write`
      // and the `wait` member, which is what B-T3.5's result body reads.
      outcome: "refuse",
      reasons,
      track,
      now,
      approval: typed,
      repo,
      tag: input.tag,
      wait: { code: waits[0].code, cause: String(waits[0].message ?? "").slice(0, 512) },
      record: { write: false, why: `FLOW-72: ${waits[0].code} is a wait, and a wait is the absence of a fact` },
    });
  }

  // 1 ── a failed check is not a policy decision.
  const errors = levelled.filter((f) => f.level === "error");
  if (errors.length || !derived?.plugin || !derived?.version) {
    add(
      "P_REFUSED",
      errors.length
        ? `${errors.length} blocking finding(s); the policy never ran`
        : "the ingest produced no listing to decide about",
    );
    // An approval never reaches this branch's outcome. It is recorded — the
    // maintainer did type the command, and a record that omits an approval the
    // registry then ignored is a record that cannot be reconciled with the
    // thread — but it changes nothing: a failed check is a fact about the
    // bytes, and the answer to one is a new release, not a permission.
    return finish({ outcome: "refuse", reasons, track, now, approval: typed, repo, tag: input.tag });
  }

  // 1a ── the identity verdict, before any policy question is asked.
  //
  // Registry plan B-T3.3a. `bot/lib/identity.mjs` compares the certificate's
  // `.15`, `.17` and `.12` with MIG-20's baseline and answers in the
  // CONTRACT's vocabulary; this is where that answer becomes a decision. The
  // two vocabularies are kept apart deliberately — every key of
  // `POLICY_CODES` has to be explained to authors in `docs/POLICY.md`, and the
  // bound world's author-facing text is written once, by reg.61a (B-T3.3b).
  // So the contract code travels in the MESSAGE of a documented policy code
  // rather than becoming an eleventh undocumented one.
  //
  // **`B_REPOSITORY_RECYCLED` is permanent** (ID-41 row 1; OPEN-OWNER-15).
  // No `/recheck`, no new tag and no approval clears it: the refusal is about
  // which repository these bytes came out of, and a maintainer typing
  // `/approve` has not changed that. Only B-T4.2's `identity_reset` record
  // lifts it, and until a contract version adds that code the refusal stands.
  // An approval is still RECORDED, exactly as on the failed-check branch, so
  // the thread can be reconciled with what the registry did.
  //
  // **A read that did not happen is a wait, not a difference** (FLOW-72:
  // waits never record). A rate-limited `fetchRepositoryIds` must not become
  // "the repository moved".
  const identity = input.identity ?? null;
  if (identity?.code === "B_REPOSITORY_RECYCLED") {
    add("P_REFUSED", `B_REPOSITORY_RECYCLED: ${identity.reason}`);
    add("P_REFUSED",
      "This refusal is permanent. A new tag, a `/recheck` or an `/approve` does not clear it — only a " +
      "moderator's identity reset does, and a release published under the reset id is compared again " +
      "from scratch (OPEN-OWNER-15).");
    return finish({ outcome: "refuse", reasons, track, now, approval: typed, repo, tag: input.tag });
  }
  if (identity?.code === "W_GITHUB_RATE_LIMITED") {
    // Deliberately a throw and not a fifth outcome.
    //
    // `decide()` answers `publish`, `delay`, `review` or `refuse`, and each of
    // those four is RECORDED. There is no outcome here that means "ask again
    // next run", and inventing one would have to be understood by
    // `bot/lib/policy/comment.mjs`'s headline map and `bot/decide.mjs`'s exit
    // map — two files this task does not own — with the failure mode of an
    // unrecognised outcome being a comment with no headline and exit 2.
    //
    // A wait is the READER's answer, not the policy's: the job that could not
    // read the identity stops before it ever asks what should happen to the
    // release (FLOW-72, waits never record). A caller that got here anyway has
    // a bug, and a loud job failure is the right size of noise for it —
    // quieter than publishing, and much quieter than recording a refusal for a
    // repository nobody managed to look up.
    throw new Error(
      "decide() was handed an identity that could not be read " +
      `(${identity.reason}). A transient GitHub read is a wait, and a wait never reaches a decision: ` +
      "the caller stops and asks again next run, because a read that did not happen is not a fact " +
      "about the repository (B-T1.3; FLOW-72).",
    );
  }

  // 1c ── BOT-77: the legacy path stops at a bound listing.
  //
  // From R3 a listing can carry `plugins/<id>/identity.json` — the registry's
  // record of which repository it is bound to, written by the service path
  // with a decision record beside it. The legacy path (an issue, a `/release`
  // ping, the backstop, the queue drain) may not publish one, may not queue
  // one, and may not clear a hold on one.
  //
  // Not tidiness. The two paths answer "may this be listed" with different
  // evidence: the service path holds a verdict, an eligibility and a binding
  // line read at the attested commit, and the legacy path holds an issue
  // comment from somebody with write access to THIS repository. Once a listing
  // is bound, letting the weaker path publish it means the binding can be
  // routed around by opening an issue — and the route is open to exactly the
  // people the binding was introduced to stop trusting by default.
  //
  // It expires. From R6 there is no legacy path (B-T5.2 deletes `ingest.yml`),
  // and this guard goes with it.
  const identityRecord = input.identityRecord ?? null;
  if (identityRecord && path !== "service") {
    add(
      "R_CHECK_HELD",
      `${derived.plugin.id} carries an identity record (bound to ${identityRecord.repo ?? "a repository"}, ` +
      `repository ${identityRecord.repository_id ?? "?"}), and this run came in on the legacy path. A bound ` +
      "listing is published by the path that holds the binding evidence — a verdict, an eligibility and the " +
      "line at the attested commit — and an issue comment is none of those (BOT-77).",
    );
    return finish({
      outcome: "review",
      reasons,
      track,
      now,
      sla_deadline: iso(now.getTime() + REVIEW_SLA_HOURS * HOUR_MS),
      // No `artifact_digests`, no `queue_entry` and no `approval`: the three
      // things BOT-77 names are publish, queue and clear-a-hold, and each of
      // them is reachable from one of those members. The approval is carried
      // in `approval_refused` instead, so the thread can still say a
      // maintainer typed a command and the registry did not honour it.
      approval: null,
      refused: typed,
      repo,
      tag: input.tag,
    });
  }

  const requested = requestedAuthority(derived.version);
  // Computed here rather than at the delay branch, because two later decisions
  // need it: the approval record ("against which digest") and the queue clock.
  // Both are only auditable if the digest is the one THIS run hashed.
  const digests = artifactDigests(derived.version);
  // And the name of this submission, which is what an approval must have said.
  const fingerprint = submissionFingerprint({
    repo,
    tag: input.tag,
    id: derived.plugin.id,
    version: derived.version.version,
    // The commit the listing will record and pin every relative README image
    // to. Bound here so that re-pointing the tag at a different tree after a
    // hold invalidates the approval instead of riding it.
    commit: derived.version.release?.commit ?? null,
    digests,
  });

  // Does the queue entry still describe this release and these bytes? Asked
  // once, here, and reused by everything that is allowed to trust the entry.
  const sameRelease = Boolean(queued && queued.repo === repo && queued.tag === input.tag);
  const sameBytes = Boolean(queued && JSON.stringify(queued.artifact_digests ?? []) === JSON.stringify(digests));
  const queueIsAboutThis = sameRelease && sameBytes;

  // An approval reaches a *second* run when the first one cleared the hold and
  // then landed in the publication delay: the hourly drain re-ingests from
  // scratch with no comment behind it, and without this the same hold would be
  // raised again and the release would loop between the queue and the review
  // list for ever.
  //
  // What is carried forward is the maintainer's PERMISSION, never their
  // verdict — every check in this run is still run from scratch, exactly as
  // `queued_at` is carried forward while the bytes are re-hashed. And it is
  // carried only while the entry still describes these bytes: a swapped asset
  // restarts the clock (below) and takes the approval with it, so "approved by
  // X against digest Y" is never a sentence about bytes nobody approved.
  //
  // ── and the approval has to have named THIS submission ────────────────────
  //
  // A typed approval arrives from a comment, and the comment is the one input
  // here that a maintainer composed while looking at a specific run's report. So
  // it carries that run's fingerprint, and it is honoured only when the run in
  // front of us has the same one. An approval with no fingerprint at all is in
  // the same position: it names nothing, so there is nothing to check it
  // against, and "cannot be checked" is not a reason to proceed.
  //
  // This is where the issue-body hole is closed. `bot/triage.mjs` already
  // refuses a `/approve` whose repository and tag disagree with the issue as it
  // stands — but triage has no bytes, so it cannot see a moved tag or a replaced
  // asset. Here there are bytes, and they have just been hashed.
  const bound = typed && typed.for === fingerprint ? typed : null;
  const refusedApproval = typed && !bound ? typed : null;
  if (refusedApproval) {
    add(
      "P_APPROVAL_STALE",
      `@${refusedApproval.by} approved ${refusedApproval.for ? `\`${refusedApproval.for}\`` : "no named submission"}` +
      `, and this run is \`${fingerprint}\` (${repo}@${input.tag ?? "?"}, ${derived.plugin.id} ` +
      `${derived.version.version}, ${digests.length || "no"} artifact digest(s)). The hold stands.`,
    );
  }

  const approval = bound ?? (queueIsAboutThis
    ? normaliseApproval({ by: queued.approved_by, at: queued.approved_at, publishNow: queued.publish_now })
    : null);

  const previous = newestListedVersion(existing);
  const previouslyRequested = requestedAuthority(previous);
  const added = requested.filter((n) => !previouslyRequested.includes(n));
  const newHighRisk = highRiskIn(added);
  const heldHighRisk = highRiskIn(requested);

  // 2 ── the three events that block on a person, and the checks' own holds.
  //
  // R_FIRST_LISTING and R_IDENTITY_CHANGED are raised by the ingest checks
  // (they are facts about the submission); this module adds the third and
  // states all three in one place so POLICY.md has one table to quote.
  const held = levelled.filter((f) => f.level === "review");
  for (const f of held) {
    const code = Object.hasOwn(POLICY_CODES, f.code) ? f.code : "R_CHECK_HELD";
    add(code, f.message);
  }
  if (newHighRisk.length && !held.some((f) => f.code === "R_FIRST_LISTING")) {
    // A first listing already blocks, and saying "and also it wants dom_access"
    // twice does not make the human read it twice.
    add("R_NEW_HIGH_RISK", `this release adds ${newHighRisk.join(", ")}, which the listed ${previous?.version ?? "previous version"} did not have`);
  }
  if (reasons.some((r) => r.level === "review")) {
    if (!approval) {
      return finish({
        outcome: "review",
        reasons,
        track,
        now,
        sla_deadline: iso(now.getTime() + REVIEW_SLA_HOURS * HOUR_MS),
        artifact_digests: digests,
        approval: null,
        refused: refusedApproval,
        repo,
        tag: input.tag,
        fingerprint,
      });
    }
    // The hold is cleared, and only the hold. Execution falls through into the
    // delay rules below, which get no say from this: a person answering "may
    // this be listed at all" has not answered "has the author had a chance to
    // notice", and §5.5's window is the answer to the second question.
    add(
      "P_APPROVED",
      `@${approval.by} cleared the hold at ${approval.at}, against submission \`${fingerprint}\` — ` +
      `${digests.length || "no"} artifact digest(s) hashed in this run: ${digests.join(", ") || "none"}`,
    );
  }

  // 3 ── a permission nobody can name. Reported, never blocking: the daemon
  //      default-denies, so an unknown key grants exactly nothing.
  for (const name of requested) {
    if (!KNOWN_AUTHORITY.includes(name)) {
      add("P_UNKNOWN_PERMISSION", `${name} is not a name this registry knows; it grants nothing until it is one`);
    }
  }

  // 4 ── the delay, and what earns one.
  const delayReasons = [];
  if (heldHighRisk.length) {
    delayReasons.push({
      code: "P_DELAY_HIGH_RISK",
      message: `this plugin holds ${heldHighRisk.join(", ")}`,
    });
  }
  // Only against a release that EXISTS. On a first listing everything is
  // "added" — there is nothing to widen from — so this fired on every first
  // submission and told the author its permissions had grown beyond "the
  // previous release", naming one that had never been cut. A delay reason
  // nobody can act on is a delay nobody can shorten.
  if (previous && added.length) {
    delayReasons.push({
      code: "P_DELAY_WIDENED",
      message: `it asks for ${added.join(", ")}, which ${previous.version} did not`,
    });
  }

  if (delayReasons.length === 0) {
    add("P_PUBLISHED", "identity unchanged, permissions unchanged, every check green, version strictly greater");
    return finish({
      outcome: "publish", reasons, track, now, artifact_digests: digests, approval,
      refused: refusedApproval, repo, tag: input.tag, fingerprint,
    });
  }

  for (const r of delayReasons) add(r.code, r.message);
  if (track.tier === "established") {
    add("P_TRUSTED_AUTHOR", `${track.clean_releases} clean release(s) from @${track.owner} here, so the delay is ${TRUSTED_DELAY_HOURS} h rather than ${DELAY_HOURS} h`);
  }

  // A FIRST listing that a maintainer has approved does not wait, and the
  // reason is who the delay protects.
  //
  // The delay buys a window in which the real author can say "that release is
  // not mine" before a hijacked build reaches anybody. That window is worth a
  // great deal for an UPDATE: every existing install follows it, and the
  // people at risk never chose to take the risk.
  //
  // A first listing has no installs. Nobody is carried along by it; the only
  // people who can be harmed are people who go and choose it after it appears,
  // and a day's delay does not change that — it postpones it. What a first
  // listing does have is the strongest check this registry performs: a person
  // reading the submission, which is exactly what an approval is.
  //
  // So the approval publishes it. Stacking a day on top of a human decision
  // was asking the maintainer to wait out a window that protects nobody who
  // has not already decided to trust them.
  // `/publish` — the maintainer's explicit "not in a day, now".
  //
  // It waives the delay and nothing else: the permission question, the binding
  // to these exact bytes, and every check in this run happened first and
  // happened identically to `/approve`. What it removes is the WAIT, which is
  // the only thing a maintainer was ever able to remove by hand — the queue
  // entry has always said so, and doing it by hand meant a commit from a
  // laptop. This is that same act, typed where the decision is being made.
  //
  // It grants no authority that did not exist: whoever can run it could edit
  // `publish_after`, or write the listing by hand. Unlike writing it by hand,
  // this path re-runs every check from scratch first.
  if (approval?.publishNow && delayReasons.length) {
    add(
      "P_DELAY_WAIVED_BY_COMMAND",
      `@${approval.by} published this without waiting out the ${track.delay_hours ?? DELAY_HOURS} h delay ` +
      `(${delayReasons.map((r) => r.code).join(", ")}); every check in this comment ran again first`,
    );
    return finish({
      outcome: "publish", reasons, track, now, drop_queue: true, artifact_digests: digests, approval,
      refused: refusedApproval, repo, tag: input.tag, fingerprint,
    });
  }

  if (approval && !existing && delayReasons.length) {
    add(
      "P_FIRST_LISTING_APPROVED",
      `@${approval.by} approved the first listing, and a first listing has no installed copies for a delay to protect — ` +
      `${delayReasons.map((r) => r.code).join(", ")} would have applied to an update`,
    );
    return finish({
      outcome: "publish", reasons, track, now, drop_queue: true, artifact_digests: digests, approval,
      refused: refusedApproval, repo, tag: input.tag, fingerprint,
    });
  }

  const delayHours = track.delay_hours ?? DELAY_HOURS;

  // 5 ── has it already waited?
  //
  // The clock is pinned to the bytes. An asset replaced during the window is a
  // new release for this purpose, and the only thing that stops a swap timed
  // for the last minute of the window is starting the clock again. Both
  // questions were asked above, because the carried-forward approval rests on
  // the same answer.
  if (queued && !queueIsAboutThis) {
    add(
      "P_DELAY_BYTES_CHANGED",
      sameRelease
        ? "the assets this was queued for are not the assets on the release now"
        : `it was queued for ${queued.repo}@${queued.tag} and this is ${repo}@${input.tag ?? "?"}`,
    );
  }

  const startedAt = queueIsAboutThis ? new Date(queued.queued_at) : now;
  let publishAfter = new Date(startedAt.getTime() + delayHours * HOUR_MS);

  // A maintainer bringing the publication forward, which every queue entry
  // tells them they may do: *"edit publish_after to bring it forward."*
  //
  // They could not. The line above recomputes the deadline from `queued_at`
  // and nothing ever read the field, so editing it moved only
  // `ripeQueueEntries`: triage picked the release up early, the decision
  // recomputed the same deadline, and it went straight back into the queue.
  // That instruction has been written into every entry this bot has ever
  // produced, and it named an action that did nothing.
  //
  // Honoured only EARLIER, and only for an entry that still describes this
  // release and these bytes. Earlier-only, so a mistyped date cannot park a
  // release indefinitely — the delay is a maximum a maintainer may waive, not
  // a dial they may turn either way. Same-bytes, so a stale entry can never
  // shorten the window for a release it was not written for; that question is
  // already answered above and this reuses the answer.
  //
  // It grants no authority that did not already exist. The file lives in this
  // repository, so moving the date takes a commit from somebody who could
  // publish the listing by hand regardless — and unlike a hand-published
  // listing, this path still re-runs every check from scratch first.
  if (queueIsAboutThis && queued.publish_after) {
    const asked = new Date(queued.publish_after);
    if (!Number.isNaN(asked.getTime()) && asked.getTime() < publishAfter.getTime()) {
      publishAfter = asked;
      add("P_DELAY_BROUGHT_FORWARD",
        `a maintainer moved publish_after to ${iso(asked)}, earlier than the ${delayHours} h default`);
    }
  }

  if (publishAfter.getTime() <= now.getTime()) {
    add("P_DELAY_ELAPSED", `queued at ${iso(startedAt)}, ${delayHours} h ago; every check has just been re-run against today's bytes`);
    return finish({
      outcome: "publish", reasons, track, now, drop_queue: true, artifact_digests: digests, approval,
      refused: refusedApproval, repo, tag: input.tag, fingerprint,
    });
  }

  add("P_DELAY_WAITING", `it publishes itself at ${iso(publishAfter)} — ${delayHours} h after ${iso(startedAt)} — with nobody touching it`);
  return finish({
    outcome: "delay",
    reasons,
    track,
    now,
    publish_after: iso(publishAfter),
    notify_author: true,
    artifact_digests: digests,
    approval,
    refused: refusedApproval,
    repo,
    tag: input.tag,
    fingerprint,
    queue_entry: {
      $comment:
        "A release waiting out PRODUCTION_PLAN §3.5's publication delay. Nothing here is trusted at " +
        "publish time: the whole ingest runs again from scratch. Delete this file to cancel the " +
        "publication; edit publish_after to bring it forward.",
      id: derived.plugin.id,
      version: derived.version.version,
      repo,
      tag: input.tag ?? null,
      // Recorded so the drain can re-run the same ingest, and re-proved against
      // GitHub when it does.
      //
      // **What that re-proof is and is not.** It re-asks the collaborator
      // endpoint, so an author whose `admin`/`maintain` GitHub will state has
      // been withdrawn fails at publish time — which is exactly when it should
      // be asked. It cannot re-prove `release-author`: that method rests on a
      // release published in the past, which stays published. Hence the cap in
      // `bot/lib/ownership.mjs` — the fact expires on its own, because nothing
      // here can expire it — and hence the ownership method being written into
      // the listing's `$comment`, so a listing resting on the weakest of the
      // three says so in `git log`.
      submitter: input.submitter ?? null,
      queued_at: iso(startedAt),
      publish_after: iso(publishAfter),
      delay_hours: delayHours,
      reason: delayReasons.map((r) => r.code).join(","),
      artifact_digests: digests,
      // The maintainer who cleared the hold, so the drain that picks this up in
      // 24 h does not raise it again and bounce the release between the queue
      // and the review list. It carries no verdict: `decide` re-runs every rule
      // above against a bundle this repository will hash again, and it is
      // honoured only while `artifact_digests` still match.
      approved_by: approval?.by ?? null,
      approved_at: approval?.at ?? null,
      // The name that approval was given against, so the entry can be read on
      // its own: `artifact_digests` above is what the check compares, and this
      // is the string the maintainer's comment actually contained.
      approved_for: approval ? fingerprint : null,
      issue: input.issue ?? null,
    },
  });
}

/**
 * `{by, at}`, or nothing at all.
 *
 * Shape-checked here rather than trusted, because this value has travelled
 * through a workflow output, a matrix entry and — on the second run — a JSON
 * file in this repository. A login that is not a login, or a timestamp that is
 * not a timestamp, means the audit record would be a sentence nobody can check,
 * and an unverifiable record of who approved something is worse than none: it
 * reads as evidence.
 */
function normaliseApproval(approval) {
  const by = String(approval?.by ?? "").replace(/^@/, "");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(by)) return null;
  const at = new Date(approval?.at ?? NaN);
  if (Number.isNaN(at.getTime())) return null;
  // `for` is the submission the maintainer named. Shape-checked and otherwise
  // null, never repaired: a fingerprint that is not a fingerprint has to fail
  // the comparison rather than be quietly dropped from it, and a `null` here
  // matches nothing. Absent on an approval read back out of a queue entry
  // written before this field existed, which is why the queue's own binding is
  // `artifact_digests` and not this.
  const named = String(approval?.for ?? "").toLowerCase();
  const forWhat = new RegExp(`^[0-9a-f]{${FINGERPRINT_CHARS}}$`).test(named) ? named : null;
  // `/publish` sets this; `/approve` does not. Boolean-coerced here so a
  // queue entry written before the field existed reads as false rather than
  // undefined — the safe direction, since the flag only ever shortens a wait.
  return { by, at: iso(at), for: forWhat, publishNow: approval?.publishNow === true };
}

function finishDecision(d) {
  return {
    outcome: d.outcome,
    reasons: d.reasons,
    track: d.track,
    decided_at: iso(d.now),
    publish_after: d.publish_after ?? null,
    sla_deadline: d.sla_deadline ?? null,
    notify_author: Boolean(d.notify_author),
    queue_entry: d.queue_entry ?? null,
    drop_queue: Boolean(d.drop_queue),
    // Who cleared the hold, when, and the digests this run hashed. The third
    // is what makes the first two auditable: an approval recorded without the
    // bytes it applied to cannot be checked against anything later.
    approved_by: d.approval?.by ?? null,
    approved_at: d.approval?.at ?? null,
    artifact_digests: d.artifact_digests ?? [],
    // What this submission is called, and what the maintainer's own comment has
    // to say for it to apply. Null on a refusal, where there is no listing to
    // name — the checks failed before anything was derived.
    fingerprint: d.fingerprint ?? null,
    repo: d.repo ?? null,
    tag: d.tag ?? null,
    // The issue to answer on, and — on a publication — to close.
    issue: d.issue ?? null,
    // An approval that named something else. Recorded rather than discarded: a
    // maintainer typed a command and the registry did not honour it, and the
    // thread has to be able to say which of those two things happened.
    approval_refused: d.refused
      ? { by: d.refused.by, at: d.refused.at, for: d.refused.for ?? null }
      : null,
    /** True when the derived listing should be committed by this run. */
    publishes_now: d.outcome === "publish",
    // ── whether this run writes a decision record (B-T3.3c) ────────────────
    //
    // Separate from `outcome`, because the two answer different questions and
    // the four outcomes cannot express the second. `refuse` is the outcome of
    // a failed check AND of a wait AND of a submission no listing names, and
    // exactly one of those three is written down.
    //
    // Default true: a decision this module actually reached is recorded, which
    // is what every path on `main` does today. The no-record cases each say so
    // by name, and `bot/decide.mjs` adds the three it answers before this
    // module is called at all (BOT-19, BOT-74, FLOW-67).
    record: d.record ?? { write: true, why: "a decision was reached, and a decision is recorded (BOT-34)" },
    // FLOW-72's answer, in the shape §4.4 gives a `wait`: `{code, cause}`
    // here, with `started_at` and `earliest_retry_at` added by the job that
    // knows when it started (B-T3.5's determinism rule — a wait's clock comes
    // from the step's recorded start, never from the moment the body is sent).
    wait: d.wait ?? null,
  };
}
