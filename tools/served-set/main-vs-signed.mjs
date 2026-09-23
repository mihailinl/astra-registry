// SERVE-85: the withdrawal list `main` implies, against the one `signed`
// publishes (registry plan RC-R1-4).
//
// The failure this exists for is SERVE-44's: a signer run that gets replaced
// while it is pending drops the advisory it was going to publish, `signed`
// keeps serving the list without it, and every other canary agrees with itself
// — SERVE-39 compares Pages with `signed` and would find them identical.
// Nothing else in the estate ever compares `signed` with `main`.
//
// ── what is compared ────────────────────────────────────────────────────────
//
// D3's formula at `main`'s head, and D4's list build from `tools/revocations/**`
// alone. NOT `main:registry/v1/revocations.json`: that file is an unsigned
// regeneration compared by content at its own serial (ROLL-12), it is stale
// between an advisory commit and the next `build-index` run, and a check that
// read it would be holding a withdrawal back behind the very regeneration the
// signer was designed not to wait for.
//
// ── the two clocks, and why the requirement's one clock is not enough ───────
//
// SERVE-85 says the check fails when the two differ "more than 30 minutes after
// that `main` commit". Read as main's HEAD commit, that window is reset by
// every unrelated commit: a publication, a listing edit, a README fix. On a
// `main` that takes a commit every twenty minutes — an ordinary afternoon — a
// dropped advisory is inside the window continuously and this check never
// fires, which is the one thing it is here to do.
//
// So the clock is chosen per difference, and each choice is exact but for the
// one limit the first of them names:
//
//   * a SERIAL difference is measured from the OLDEST commit on main's
//     FIRST-PARENT line that changed what main holds under
//     `tools/revocations/` and that `signed` does not carry — the moment main
//     acquired the first change the signer still owes. The serial is
//     `rev-list --count --full-history <sha> -- SERIAL_PATHSPEC` + 1, a count
//     of what is reachable, so it moves at that moment: for a direct push or a squash
//     that is the commit itself, and for a pull request merged with a merge
//     commit it is the MERGE. Only a commit that changes main's copy of the
//     directory can open the window. The clock reads the same export as the
//     signer's `serialsAt` rather than a copy of the string, because a copy is
//     what let the two be widened apart (gap 64);
//
//     **oldest, not newest.** Until 2026-09-22 this dated the NEWEST such
//     commit, and that is main's head again one pathspec down: every advisory
//     restarted the window. Measured on fixtures with no signer run at all:
//     advisories at 00:10 and 00:30 were green at 00:41; a third at 00:55 was
//     green at 01:20, with the first 70 minutes unpublished; one advisory
//     alone was red at 00:41. A dead signer on a `main` taking an advisory at
//     least every half hour would never have been reported. Detector A7 had
//     the same shape and was repaired the same way (gap 76); `gather` walks
//     the commits the way A7's `unsignedTouching` does;
//
//     **what `signed` carries is read from its SERIAL, not its trailers.** A
//     first-parent commit is carried when `signed`'s list serial is at least
//     `serialsAt` there — the number the signer would have signed it at. Not
//     `Source-Commit..HEAD`: when D4 carries a list forward the signer still
//     writes this run's `Source-Commit`, so a carried list would read as fully
//     signed, and a carried list is the outage this check exists to page for
//     (registry plan D4: "SERVE-85 fires 30 minutes later");
//
//     **a commit dated more than the grace AFTER `now` is overdue**, not
//     early. Its wait cannot be read, and an unreadable clock excuses nothing
//     (`minutesSince`); `withinGrace` once read the negative wait as inside
//     the window and excused it until its date — measured, an advisory dated
//     2026-06-01 was green at 2026-01-01 — and holds both edges itself now.
//     Skew inside the grace is not that, and stays green. Only the oldest
//     unsigned commit's date is read: every later one reached main after it,
//     so no later date can lengthen the wait and none can shorten it;
//
//     `--first-parent` is what dates a merged change at its merge (gap 68). A
//     plain `git log -- <pathspec>` simplifies history through a merge, which
//     is TREESAME to its branch parent for the path, and dates the BRANCH commit:
//     measured 2026-09-22, an advisory committed on a branch at 09:00 and
//     merged at 12:00 gave a clock of 09:00 and SERVE_85_SERIAL_DRIFT one
//     minute after the merge. The one shape nothing here can date is a
//     fast-forward of an old commit, because git records no time for a ref
//     moving; that commit is dated at its own committer time, as before;
//   * an ENTRY difference at an equal serial is measured from main's head,
//     because at an equal serial the advisories are unchanged and what changed
//     the generated bytes is a commit to the generator — which can be anywhere.
//     A head dated more than the grace after `now` is overdue here too. Main's
//     head DOES reset on a busy `main`, and that limit is this half's: no
//     pathspec names the generator's inputs, so there is no oldest commit to
//     date instead.
//
// The strict half is the half that catches SERVE-44, and it is the half a busy
// `main` used to be able to silence — first through main's head, then through
// the newest advisory.
//
// ── `signed` ahead of the tree we checked out: the race, or a broken count ──
//
// This job reads ONE tree: the commit it checked out. The signer reads `main`
// as it is when it runs. So a run that starts, and a signer that publishes a
// newer `main` while it is running, leaves this check holding an older list and
// a newer `signed` — a difference that is the system working. A serial LOWER
// on `signed` is the failure: `signed` is behind a commit this job can see.
//
// A serial on `signed` GREATER than the one at our commit is the race only
// when `signed` was made from a commit this job does NOT hold. Since contract
// 0.35.0 the list's count is `--full-history`'s (`SERIAL_FLAGS`), which cannot
// fall along main, so when our commit contains `signed`'s `Source-Commit` it
// gives the list at least the serial the signer gave it there — and a list
// carried from before that commit carries a serial no higher. `signed` above
// us then means the formula that assigned its serial is not this one, or
// `signed` was not made from main: SERVE_85_SERIAL_AHEAD, at once, with no
// grace, because waiting does not change it. Until 0.35.0 this was read as
// the race whatever the Source-Commit, and it was exactly the state git's
// default count left behind when a merge lowered the serial: the signer's
// SERVE-36 gate refused the list, D4 carried it under the merge's
// Source-Commit, and this check called main holding an advisory the served
// list lacked "the system working" for as long as it lasted (ops register
// entry 117). A `signed` whose Source-Commit this checkout does not hold, or
// that names none, is still read as the race; provenance (SERVE-90's
// fallback) is the check that asks where a `signed` commit came from.
//
// ── before the signer exists ────────────────────────────────────────────────
//
// `signed` is created by the first run of `sign.yml` (D1, RC-R1-2). Until that
// workflow is on `main` there is nothing that could have created the branch,
// and a check that paged every fifteen minutes about its absence would spend
// R1 teaching its only reader to ignore it — attack B-1's finding, one task
// along. So the absence of `signed` is a stated WAIT while
// `.github/workflows/sign.yml` is absent, and a failure the moment it is there.
// The wait is narrow, self-retiring, and keyed on a file in the same tree; the
// heartbeat is posted either way, so the receiver is armed from the first run.

import fs from "node:fs";
import path from "node:path";

import { stableStringify } from "../lib/canonical.mjs";
import { SERIAL_PATHSPEC, buildRevocations } from "../lib/revocations.mjs";
import { gitMaybe, gitText } from "../signer/git.mjs";
import { SIGNED_FILES, fetchSignedHead, serialsAt } from "../signer/plan.mjs";
import { GRACE_MINUTES, finding, minutesSince, verdict, withinGrace } from "./report.mjs";

/** D1's signer. Its presence on `main` is what arms the missing-branch failure. */
export const SIGNER_WORKFLOW = ".github/workflows/sign.yml";

/**
 * The pathspec D3 counts the list's serial over, and so the serial's own clock.
 * Not a string of its own: it IS `SERIAL_PATHSPEC`, the export the signer's
 * `serialsAt` counts over, kept under this name for the readers that know it.
 */
export const LIST_PATHSPEC = SERIAL_PATHSPEC;

/**
 * `signed`'s `Source-Commit:` trailer. Typed here rather than imported:
 * `provenance.mjs`'s `trailersOf` would close an import cycle with this file,
 * and `bot/detectors.mjs`'s is the bot's. The shape is B.4's, one 40-hex sha.
 */
const SOURCE_COMMIT = /^Source-Commit:[ \t]*([0-9a-f]{40})[ \t]*$/m;

/**
 * SERVE-85's decision, over facts and nothing else.
 *
 * @param {object} o
 * @param {string} o.mainSha              the commit this job read
 * @param {string} o.treeClock            that commit's committer time, RFC 3339
 * @param {string|null} o.listClock       the newest first-parent commit that changed tools/revocations/, RFC 3339.
 *                                        The transcript's; nothing below decides on it
 * @param {{sha: string, at: string, serial: number}[]} o.listCommits  every first-parent commit that changed
 *                                        tools/revocations/, OLDEST first, with the list serial `serialsAt` gives there
 * @param {{serial: number, revocations: unknown[]}|null} o.generated  null when the build failed
 * @param {string|null} o.buildError
 * @param {object} o.head                 from fetchSignedHead
 * @param {{sha: string|null, contained: boolean|null}|null} [o.signedSource]  `signed`'s head
 *                                        Source-Commit, and whether `mainSha` contains it (null: this
 *                                        checkout does not hold it, or `signed` names none)
 * @param {boolean} o.signerWorkflowPresent
 * @param {string} o.now
 * @param {number} [o.graceMinutes]
 */
export function serve85({
  mainSha,
  treeClock,
  listClock,
  listCommits,
  generated,
  buildError = null,
  head,
  signedSource = null,
  signerWorkflowPresent,
  now,
  graceMinutes = GRACE_MINUTES,
}) {
  const findings = [];
  const waiting = [];
  const notes = [`main ${mainSha.slice(0, 12)} committed ${treeClock}; the newest commit under ${LIST_PATHSPEC}/ is dated ${listClock ?? "never"}`];
  const hexes = [mainSha];

  if (!head?.present) {
    if (!signerWorkflowPresent) {
      waiting.push(
        `there is no \`signed\` branch and no ${SIGNER_WORKFLOW} on main to create one, so there is nothing to ` +
        `compare with yet (registry plan D1, RC-R1-2). This is a wait, not a pass: the heartbeat below still ` +
        `posts, so the receiver pages if this check stops running.`,
      );
      return verdict({ findings, waiting, hexes, notes });
    }
    findings.push(finding(
      "SERVE_85_NO_SIGNED_BRANCH",
      `${SIGNER_WORKFLOW} is on main and there is no \`signed\` branch (${head?.reason ?? "no reason given"}). ` +
      `Either no signer run has ever succeeded, or the branch was deleted; every armed client is being served a ` +
      `withdrawal list that nothing is publishing.`,
    ));
    return verdict({ findings, waiting, hexes, notes });
  }

  hexes.push(head.sha);

  if (generated === null) {
    findings.push(finding(
      "SERVE_85_GENERATOR_FAILED",
      `the withdrawal list does not build from tools/revocations/ at main ${mainSha.slice(0, 12)}: ${buildError}. ` +
      `Until it does, nothing here can say whether \`signed\` is serving the right one.`,
    ));
    return verdict({ findings, waiting, hexes, notes });
  }

  const headDoc = head.documents?.revocations ?? null;
  const headSerial = headDoc?.signed?.serial;
  if (headDoc === null || !Number.isSafeInteger(headSerial)) {
    findings.push(finding(
      "SERVE_85_LIST_UNREADABLE",
      `\`signed\`@${head.sha.slice(0, 12)} has no readable ${SIGNED_FILES.revocations} with a serial in it ` +
      `(${head.parseErrors?.join("; ") || "no serial"}). A published branch whose list cannot be parsed is an ` +
      `outage for every armed client, whatever it compares to.`,
    ));
    return verdict({ findings, waiting, hexes, notes });
  }

  if (headSerial > generated.serial) {
    // The header says why a contained Source-Commit makes this a broken count
    // rather than the race, and why it waits for nothing.
    if (signedSource?.contained === true) {
      hexes.push(signedSource.sha);
      findings.push(finding(
        "SERVE_85_SERIAL_AHEAD",
        `\`signed\`@${head.sha.slice(0, 12)} serves list serial ${headSerial}, and main ${mainSha.slice(0, 12)}, ` +
        `which contains its Source-Commit ${signedSource.sha.slice(0, 12)}, gives the list ${generated.serial}. ` +
        `DEC-9's count cannot fall along main, so that serial was assigned by another formula than the one this ` +
        `job counts, or \`signed\` was not made from main. Until it is explained, the signer's SERVE-36 gate ` +
        `refuses every list main gives a serial below ${headSerial}, and carries the old one.`,
      ));
      return verdict({ findings, waiting, hexes, notes });
    }
    notes.push(
      `\`signed\` is at serial ${headSerial} and this commit implies ${generated.serial}, and ` +
      (signedSource?.sha
        ? `\`signed\`'s Source-Commit ${signedSource.sha.slice(0, 12)} is not ${signedSource.contained === false ? "contained in the commit this job read" : "in this checkout"}`
        : "`signed` names no Source-Commit this job can place") +
      `: the signer has published a newer \`main\` than the one this job checked out, which is the system ` +
      `working. The next run compares at that commit.`,
    );
    return verdict({ findings, waiting, hexes, notes });
  }

  if (headSerial < generated.serial) {
    // The serial's clock, and only the serial's clock: the OLDEST first-parent
    // commit under the list's pathspec that `signed`'s serial does not carry.
    // See the header for why oldest, and why the serial decides what is carried.
    if (!Array.isArray(listCommits)) throw new Error("serve85 needs listCommits from gather, and was given none");
    const unsigned = listCommits.filter((c) => c.serial > headSerial);
    const oldest = unsigned[0] ?? null;
    const age = oldest === null ? null : minutesSince(oldest.at, now);
    if (oldest !== null && withinGrace(oldest.at, now, graceMinutes)) {
      notes.push(
        `\`signed\` is at serial ${headSerial} and main implies ${generated.serial}. The oldest of the ` +
        `${unsigned.length} commit(s) under ${LIST_PATHSPEC}/ it does not carry, ${oldest.sha.slice(0, 12)}, ` +
        `reached main ${age.toFixed(1)} minutes ago. The signer has ${graceMinutes} minutes (SERVE-85).`,
      );
      return verdict({ findings, waiting, hexes, notes });
    }
    const when =
      oldest === null
        ? `and no commit on main's first-parent line under ${LIST_PATHSPEC}/ raised the serial past ` +
          `${headSerial}, so how long it has waited cannot be read`
        : age === null
          ? `and the oldest commit under ${LIST_PATHSPEC}/ it does not carry, ${oldest.sha.slice(0, 12)}, has a ` +
            `time that cannot be read`
          : age >= 0
            ? `${age.toFixed(0)} minutes after ${oldest.sha.slice(0, 12)}, the oldest of the ${unsigned.length} ` +
              `commit(s) under ${LIST_PATHSPEC}/ it does not carry`
            : `and the oldest of the ${unsigned.length} commit(s) under ${LIST_PATHSPEC}/ it does not carry, ` +
              `${oldest.sha.slice(0, 12)}, is dated ${Math.ceil(-age)} minutes after this run's clock, so how ` +
              `long it has waited cannot be read`;
    findings.push(finding(
      "SERVE_85_SERIAL_DRIFT",
      `the withdrawal list at main ${mainSha.slice(0, 12)} is serial ${generated.serial} and \`signed\`` +
      `@${head.sha.slice(0, 12)} is still serving serial ${headSerial}, ${when}. A signer run that was ` +
      `replaced while pending drops the advisory it carried (SERVE-44), and every armed client is being served ` +
      `the list without it.`,
    ));
    return verdict({ findings, waiting, hexes, notes });
  }

  const ours = stableStringify(generated.revocations ?? []);
  const theirs = stableStringify(headDoc.signed?.revocations ?? []);
  if (ours === theirs) {
    notes.push(`serial ${generated.serial} on both sides, and the entries are byte-identical`);
    return verdict({ findings, waiting, hexes, notes });
  }

  const age = minutesSince(treeClock, now);
  if (withinGrace(treeClock, now, graceMinutes)) {
    notes.push(
      `the entries differ at the same serial ${generated.serial}, ${age?.toFixed(1)} minutes after main's head ` +
      `commit; a change to the generator publishes within ${graceMinutes} minutes like any other`,
    );
    return verdict({ findings, waiting, hexes, notes });
  }
  findings.push(finding(
    "SERVE_85_ENTRY_DRIFT",
    `main ${mainSha.slice(0, 12)} and \`signed\`@${head.sha.slice(0, 12)} agree on serial ${generated.serial} and ` +
    `disagree on the entries, ` +
    (age === null
      ? "at an unreadable time after main's head commit"
      : age >= 0
        ? `${age.toFixed(0)} minutes after main's head commit`
        : `and main's head commit is dated ${Math.ceil(-age)} minutes after this run's clock, so how long they ` +
          `have differed cannot be read`) +
    `. An equal serial has to mean an equal list: one of the two was generated from something other ` +
    `than tools/revocations/ at a commit on main.`,
  ));
  return verdict({ findings, waiting, hexes, notes });
}

/**
 * Read the world SERVE-85 decides over.
 *
 * Both refs are fetched into refs of this check's own rather than read out of
 * whatever the job's checkout left behind — `origin/main` in a workspace is
 * whatever the last `actions/checkout` wrote, and `HEAD` in a detached checkout
 * is not a branch at all. The tree this reads is the checkout's, so `mainSha`
 * is the checkout's HEAD and not the fetched tip: the serial formula and the
 * generated bytes have to be taken at ONE commit, and the one we hold the tree
 * for is that commit.
 *
 * @param {{root: string, remote?: string}} opts
 */
export function gather({ root, remote = "origin" }) {
  const mainSha = gitText(["rev-parse", "HEAD"], { root });
  const treeClock = gitText(["log", "-1", "--format=%cI", mainSha], { root });
  // `--first-parent`: date the commit that made the change reachable from
  // main, not the branch commit that wrote it. The header says why.
  const listLog = gitMaybe(["log", "-1", "--first-parent", "--format=%cI", mainSha, "--", LIST_PATHSPEC], { root });
  const listClock = listLog.ok && listLog.out.trim() ? listLog.out.trim() : null;
  // The commits the serial clock chooses from: every first-parent commit that
  // changed main's copy of the list's pathspec, oldest first, each with the
  // serial the signer would have signed it at. `serve85` takes the oldest whose
  // serial `signed` has not reached. One `serialsAt` per commit that has ever
  // touched tools/revocations/ — a handful, since advisories are rare — and
  // `gitText`, not `gitMaybe`: an empty answer here reads as "nothing to
  // date", so a git error has to stop the run rather than become that answer.
  const listCommits = gitText(
    ["log", "--first-parent", "--reverse", "--format=%H %cI", mainSha, "--", LIST_PATHSPEC],
    { root },
  )
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [sha, at] = line.split(" ");
      return { sha, at, serial: serialsAt({ root, sha }).revocations };
    });

  const head = fetchSignedHead({ root, remote });
  const signedSource = head?.present ? sourceOf({ root, sha: head.sha, mainSha }) : null;

  const serials = serialsAt({ root, sha: mainSha });
  let generated = null;
  let buildError = null;
  try {
    const doc = buildRevocations({ root, serial: serials.revocations });
    generated = { serial: doc.signed.serial, revocations: doc.signed.revocations };
  } catch (e) {
    buildError = String(e?.message ?? e);
  }

  return {
    mainSha,
    treeClock,
    listClock,
    listCommits,
    generated,
    buildError,
    head,
    signedSource,
    signerWorkflowPresent: fs.existsSync(path.join(root, SIGNER_WORKFLOW)),
  };
}

/**
 * `signed`'s head Source-Commit, and whether `mainSha` contains it: `true`,
 * `false`, or `null` when this checkout does not hold the commit — which is
 * what a Source-Commit newer than the commit this job checked out looks like.
 *
 * @param {{root: string, sha: string, mainSha: string}} opts
 */
export function sourceOf({ root, sha, mainSha }) {
  const m = SOURCE_COMMIT.exec(gitText(["log", "-1", "--format=%B", sha], { root }));
  if (!m) return { sha: null, contained: null };
  const source = m[1];
  if (!gitMaybe(["cat-file", "-e", `${source}^{commit}`], { root }).ok) return { sha: source, contained: null };
  // Exit 0 is an ancestor, 1 is not; both commits are known to be here, so a
  // non-zero exit is the answer and not a fault.
  return { sha: source, contained: gitMaybe(["merge-base", "--is-ancestor", source, mainSha], { root }).ok };
}
