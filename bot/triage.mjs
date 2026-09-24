#!/usr/bin/env node
// Which of these events is a release notification, and of what?
//
//   node bot/triage.mjs --event issue_comment --labels listing,needs-triage \
//        --issue-body issue-body.md --comment-body comment-body.md
//
// PRODUCTION_PLAN task 3.4, layer 1. `.github/workflows/ingest.yml` calls this
// before it spends anything: it answers `mode=form|ping|approve|reject|reply|none`
// and, for a ping or an approval, the values the pipeline needs. Nothing here
// downloads, verifies or decides — it reads two files of stranger text, one
// directory of listings, and (only for a maintainer's command) asks GitHub one
// permission question.
//
// **Every body arrives as a FILE.** `${{ github.event.issue.body }}` inside a
// `run:` block is the standard Actions script-injection hole, and this program
// exists partly so the workflow never has to interpolate one.
//
// ── the rule that makes an unauthenticated ping safe ────────────────────────
//
// A ping on an issue nobody labelled is honoured **only for a repository that
// is already listed**. That is the whole security argument of §3.4 made
// mechanical: the worst a stranger achieves by pinging is causing a re-check of
// a listing that is already pinned to a repository identity, and a re-check
// re-runs every check from scratch and can only ever reach the same conclusion
// or a stricter one. A first listing is not reachable this way at all — it needs
// the labelled template, and it needs a person.
//
// And the ownership that gets proved is the **release author's**, resolved here
// from the release itself, never the pinger's. Whoever typed the line is not
// part of the decision.
//
// ── and the rule that stops it being silent ─────────────────────────────────
//
// Everything above says when this file returns `none`. What it used to do with
// a `none` was *nothing at all*: no comment job, no record, and an author who
// had opened a perfectly good listing request without the label got a green run
// and no reply. So every path that refuses to start work now either starts it
// or produces `mode: reply` and the markdown a human will read. `bot/lib/intake.mjs`
// holds the recognisers and the replies, including the argument for why an
// unlabelled submission is answered rather than auto-labelled.
//
// ── the maintainer's two commands ──────────────────────────────────────────
//
// `/approve <owner/repo>@<tag> <fingerprint>` and `/reject <reason>` are the
// other half of `outcome: "review"`. They are the only thing in this file that
// needs a permission, they are checked against the GitHub API by
// `bot/lib/maintainer.mjs` before anything else happens, and an approval carries
// **no verification with it**: it is recorded on a target, the whole ingest runs
// again from scratch, and what publishes is what this run verified. See
// `bot/lib/policy.mjs` for why that re-run is not optional.
//
// An approval does, however, carry **what it is an approval of**. It has to:
// this file re-parses the issue body at the moment the comment arrives, and that
// body is the author's to edit. Hold a submission, wait for the maintainer to
// read it, change the two form fields, and a bare `/approve` becomes a yes to
// something nobody looked at. So the command names a repository, a tag and the
// fingerprint printed on the comment it answers; the form is checked against
// that name instead of supplying it, and a disagreement is a reply, not a
// target.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT, loadSources } from "../tools/lib/sources.mjs";

import { markerOnMain, readDecisionRecords } from "./baseline.mjs";
import { fetchRelease } from "./lib/github.mjs";
import {
  LISTING_LABEL,
  decidableThread,
  formProblem,
  looksLikeListing,
  looksLikeReleasePing,
  parseMaintainerCommand,
  renderApprovalMoved,
  renderApprovalUnlisted,
  renderApproveNeedsBinding,
  renderCommandRefused,
  renderIncompleteForm,
  renderNothingToDecide,
  renderPingForUnlisted,
  renderPingUnreadable,
  renderRejectNeedsReason,
  renderRejected,
  renderUnlabelled,
  safeLogin,
  safeRepo,
  safeTag,
} from "./lib/intake.mjs";
import { isRecheckCommand, parseIssueForm } from "./lib/issue.mjs";
import { proveMaintainer } from "./lib/maintainer.mjs";

/**
 * Say whether GitHub answered the collaborator-permission question, and with
 * what. Never the login, never the role: the measurement is about the token's
 * reach, not about who asked.
 *
 * **To the log as well as to the job summary, and the second half is the
 * repair.** It wrote only to `$GITHUB_STEP_SUMMARY`, and a step summary is
 * reachable by no API: not on the job object, not in the run's artifacts, not
 * in the logs. Measured 2026-09-20 against run 35485336476 — the measurement
 * ran, and the only copy of its answer was on a web page. R0's runbook duly
 * told the owner to open that page and read a line off it by eye, which is
 * how a measurement ends up being retyped, or skipped, or remembered wrongly
 * by whoever needs it three weeks later. The bot's own answer has to be
 * legible to the thing that asks the question.
 *
 * The summary write stays: it is the copy a person reads without leaving the
 * page they are already on. What changed is that it is no longer the only one.
 */
export function recordPermissionProbe(proof, env = process.env, appendFile = fs.appendFileSync, log = console.log) {
  const line = `collaborator-permission: answered=${proof?.answered === true} outcome=${proof?.outcome ?? "unknown"}`;
  log(line);
  const summary = env.GITHUB_STEP_SUMMARY;
  if (!summary) return false;
  try {
    appendFile(summary, `${line}\n`);
    return true;
  } catch {
    // A summary that cannot be written is not worth failing a triage run over,
    // and since the line is on stdout too, it is no longer a lost measurement.
    return false;
  }
}
import { findListingByRepo, parseReleasePing, resolveSubmitter } from "./lib/notify.mjs";
import { bot74Filter, recordedTagsByRepo } from "./watch.mjs";
import { readIdentityRecord } from "./decide.mjs";
import { readQueue } from "./lib/policy.mjs";

function parseArgs(argv) {
  const opts = {
    event: null, action: null, labels: "", issueBody: null, commentBody: null,
    issueTitle: null, issueAuthor: null, commenter: null,
    registry: null,
    root: REPO_ROOT, modeFile: null, targetsFile: null, replyFile: null, now: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--event") opts.event = argv[++i];
    // `opened`, `edited`, `labeled`, `created`. It decides only how often the
    // bot repeats itself, never whether it may act.
    else if (a === "--action") opts.action = argv[++i];
    else if (a === "--labels") opts.labels = argv[++i] ?? "";
    else if (a === "--issue-body") opts.issueBody = argv[++i];
    else if (a === "--issue-title") opts.issueTitle = argv[++i];
    else if (a === "--comment-body") opts.commentBody = argv[++i];
    else if (a === "--issue-author") opts.issueAuthor = String(argv[++i] ?? "").replace(/^@/, "");
    else if (a === "--commenter") opts.commenter = String(argv[++i] ?? "").replace(/^@/, "");
    // There is no `--commenter-association`, and its absence is load-bearing
    // rather than an omission: no field of the event payload is a permission
    // here. `author_association: OWNER` used to be read as one when the
    // collaborator-permission endpoint declined to answer; run 35487527105
    // showed that it answers, and B-T0.4b deleted the fallback and this
    // argument with it. An `ingest.yml` that still passed the flag would now
    // fail loudly on `unknown argument`, which is the right way for the two
    // halves of this pair to be found disagreeing.
    // THIS registry, `owner/name`. The repository a maintainer's permission is
    // checked against, and the one whose issue template gets linked.
    else if (a === "--repository") opts.registry = argv[++i];
    else if (a === "--registry-dir") opts.root = argv[++i];
    // Two files rather than `$GITHUB_OUTPUT` lines the workflow would have to
    // `source`: sourcing a file written from stranger-influenced input is a
    // shell evaluating text, and no amount of charset validation upstream makes
    // that a thing worth doing.
    else if (a === "--mode-file") opts.modeFile = argv[++i];
    else if (a === "--targets-file") opts.targetsFile = argv[++i];
    // Where the markdown a human will read is written. Same reasoning: the
    // `comment` job posts a FILE out of an artifact and never interpolates it.
    else if (a === "--reply-file") opts.replyFile = argv[++i];
    else if (a === "--now") opts.now = argv[++i];
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

const read = (file) => {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
};

const iso = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;

/**
 * @param {object} opts
 * @param {(repo: string, tag: string) => Promise<object>} [release] injection seam
 * @param {{proveMaintainer?: Function}} [deps] the permission check, injected by the tests
 */
export async function triage(opts, release = fetchRelease, deps = {}) {
  const labels = String(opts.labels ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const labelled = labels.includes(LISTING_LABEL);
  const issueBody = opts.issueBody ? read(opts.issueBody) : "";
  const commentBody = opts.commentBody ? read(opts.commentBody) : "";
  const issueTitle = opts.issueTitle ? read(opts.issueTitle) : "";
  const sources = loadSources(opts.root);
  const form = parseIssueForm(issueBody);
  const registry = opts.registry ?? process.env.GITHUB_REPOSITORY ?? null;
  // Absent means `opened`, because absent information must never be the reason
  // an author hears nothing. The workflow always passes the real action; the
  // default only decides whether a hand-run repeats a comment.
  const action = opts.action || "opened";

  // 0 ── a maintainer's decision, which is the only thing here that needs a
  //      permission. Asked first, and asked of GitHub, so that no later branch
  //      can act on a command whose authority was never established.
  const command = opts.event === "issue_comment" ? parseMaintainerCommand(commentBody) : null;
  if (command) {
    // `sources` and `release` travel with it for B-T0.2's two non-listing
    // checks: is the named repository already listed, and who published the
    // bytes. Both were already loaded for the ping path below; a command off a
    // listing issue needs the same two answers for the same reasons.
    return decideCommand({ command, opts, registry, labelled, issueTitle, form, sources, release, deps });
  }

  // A labelled listing issue, opened or edited, or `/recheck` on one: the
  // submission form owns it, exactly as it did before this file existed — but
  // only when the form carries what `bot/read-submission.mjs` needs. It exits 2
  // on a form it cannot read, and under the workflow's `set -e` that killed the
  // step, produced no target and therefore no comment: a submitter who ticked
  // one box instead of two got a red X and nothing else.
  if (labelled && (opts.event === "issues" || isRecheckCommand(commentBody))) {
    const problem = formProblem(form);
    if (problem) {
      return {
        mode: "reply",
        why: `the form is missing ${[...problem.missing, ...problem.unticked].join("; ")}`,
        reply: renderIncompleteForm({ registry, problem }),
      };
    }
    return { mode: "form", why: "a labelled listing issue" };
  }

  const ping = parseReleasePing(opts.event === "issue_comment" ? commentBody : issueBody);
  if (!ping) {
    return nothingAsked({ opts, action, labelled, registry, issueTitle, form });
  }

  // On a listing issue the repository is already written down; a bare issue has
  // to name it. Never taken from the pinger's word when the issue already says
  // which repository it is about.
  const fromForm = form.repo;
  const repo = (labelled ? fromForm ?? ping.repo : ping.repo ?? fromForm) ?? null;
  if (!repo) {
    // `/release <tag>` with no repository, on an issue that does not say which
    // repository it is about — one word short. That was a silence too, and it
    // is the single most likely way to mistype the command on a new issue.
    return {
      mode: "reply",
      why: "/release named no repository and the issue does not say which one it is about",
      reply: renderPingUnreadable({ registry }),
    };
  }

  const listing = findListingByRepo(sources, repo);
  if (!listing && !labelled) {
    return {
      mode: "reply",
      why:
        `${repo} is not listed, and an unlabelled ping can only re-check a listing that already ` +
        "exists. Open a listing request with the template.",
      reply: renderPingForUnlisted({ registry, repo }),
    };
  }

  // BOT-74's two filters, before anything is spent — the same ones the
  // backstop applies, over the same recorded tags. They applied to the
  // backstop alone, so a `/release <repo> cli-v1.4.0` on a repository this
  // registry lists ran the whole ingest, was refused E_NO_BUNDLE_ASSETS, and
  // from MIG-20's baseline on would have committed a `refused` record for a
  // release that never was a plugin's. A first listing (no listing yet)
  // records no tag, so there is nothing to filter by and the form's path is
  // the human one.
  if (listing) {
    const verdict = bot74Filter({ tag: ping.tag, listedTags: recordedTagsByRepo(sources).get(String(repo).toLowerCase()) ?? [] });
    if (!verdict.pass) {
      return { mode: "none", why: `BOT-74: ${verdict.why}; nothing is ingested and nothing is recorded` };
    }
  }

  let submitter;
  try {
    submitter = await resolveSubmitter(repo, ping.tag, release);
  } catch (e) {
    return { mode: "none", why: `${repo}@${ping.tag}: ${e.message}` };
  }

  return {
    mode: "ping",
    repo,
    tag: ping.tag,
    submitter,
    why: `${repo}@${ping.tag}, published by @${submitter}${listing ? `, listed as ${listing.id}` : ""}`,
  };
}

/**
 * Nothing asked for an ingest — so does anything here ask for an *answer*?
 *
 * This is the branch that used to be the whole bug. `mode: none` is still the
 * common case and still costs nothing, but an issue that is recognisably a
 * listing request now leaves with a comment rather than with silence.
 */
function nothingAsked({ opts, action, labelled, registry, issueTitle, form }) {
  if (labelled) {
    return { mode: "none", why: "a comment that is not a command" };
  }
  if (opts.event !== "issues") {
    return { mode: "none", why: "nothing here asks for an ingest" };
  }
  // Once, on `opened`. An unlabelled issue can be edited for months, and a bot
  // that repeats the same comment on every edit is a bot people mute — which
  // costs more than the extra copies buy. The labelled path above is the one
  // that answers again on an edit, because there an edit is somebody fixing the
  // thing the bot just asked them to fix.
  if (action !== "opened") {
    return { mode: "none", why: `nothing here asks for an ingest (and this is an ${action}, so the intake reply is not repeated)` };
  }
  // The release-ping form, with a command the parser could not read. Answered
  // before the listing check, because the title already says what was intended
  // and guessing at it a second time can only get it wrong.
  if (looksLikeReleasePing(issueTitle)) {
    return {
      mode: "reply",
      why: "the release-ping form was used and no `/release` line survived the edit",
      reply: renderPingUnreadable({ registry }),
    };
  }
  const shape = looksLikeListing({ title: issueTitle, form });
  if (!shape.shaped) {
    return { mode: "none", why: `nothing here asks for an ingest — ${shape.why}` };
  }
  return {
    mode: "reply",
    why:
      `this is a listing request with no \`${LISTING_LABEL}\` label (${shape.why}); nothing will ` +
      "run until somebody applies it, and the author is being told so",
    reply: renderUnlabelled({ registry, repo: form.repo, tag: form.tag, why: shape.why }),
  };
}

/**
 * ── the target this registry is already holding ─────────────────────────────
 *
 * Does the maintainer's line name something this LISTING ISSUE no longer
 * describes? The markdown to say so, or null when it does not.
 *
 * The comparison is against the ISSUE BODY, and that is right for the
 * submission the body describes: the body belongs to its author, who can edit
 * the two form fields between the hold and the answer, and an approval must not
 * land on something nobody read.
 *
 * It is wrong for every release after the first, and it made `/publish`
 * impossible for all of them. An update arrives as a release PING — a
 * `/release v0.3.2` comment — which never touches the body. The ingest verifies
 * it, the delay queues it, and the bot posts the line to publish it now.
 * Meanwhile the body still says the tag the first listing named, for ever,
 * because nothing ever rewrites it. So the bot printed
 * `/publish owner/repo@v0.3.2 <fp>` and then refused that exact line for naming
 * something "this issue no longer describes" — and the remedy the refusal
 * offered, `/recheck`, re-reads the same body and returns the same stale tag.
 * The first listing of a plugin could be published on command and no release
 * after it ever could.
 *
 * The queue is what the maintainer is actually answering, and it is the safe
 * thing to check against for the reason the body is not: it is a committed file
 * in THIS repository, written by the bot from a run that downloaded and hashed
 * the release. A stranger cannot edit it. Nothing else is relaxed — the
 * fingerprint still names the bytes, and `bot/decide.mjs` still re-hashes the
 * release and refuses an approval that names anything else.
 *
 * **It is a listing-issue check and it stays one.** A `[notice]` or `[release]`
 * thread has no form, so there is no second description to disagree with, and
 * running this there would compare the command against two nulls. What plays
 * this rule's part on those threads is B-T0.2's own pair: the named repository
 * must already be listed, and — once the marker is on main — the fingerprint
 * must match a `held` record.
 */
function approvalMoved({ named, namedTag, repo, tag, opts, deps }) {
  const queued = (deps.readQueue ?? readQueue)(opts.root)
    .some((e) => safeRepo(e.repo) === named && safeTag(e.tag) === namedTag);
  if (queued || (named === repo && namedTag === tag)) return null;
  // The loud refusal. Cheap, too: this is the last point before the pipeline
  // starts downloading a stranger's archive, and it is reached without one.
  return renderApprovalMoved({
    approvedRepo: named, approvedTag: namedTag, issueRepo: repo, issueTag: tag,
  });
}

/**
 * `/approve` or `/reject <reason>`, once GitHub has said whether this account
 * may.
 *
 * The permission question is asked before the command is read for anything
 * else, and a refusal is a *reply* rather than a `none`: a maintainer who
 * mistypes their own login, or a stranger trying the command, both learn what
 * happened. Silence would teach exactly the wrong lesson to the second one.
 */
async function decideCommand({ command, opts, registry, labelled, issueTitle, form, sources, release, deps }) {
  const commenter = safeLogin(opts.commenter);
  const at = iso(opts.now ?? new Date());
  if (!commenter) {
    return { mode: "none", why: `/${command.command} arrived with no usable commenter login` };
  }

  const prove = deps.proveMaintainer ?? proveMaintainer;
  const proof = await prove({
    repo: registry,
    login: commenter,
  });
  // R0's measurement (registry plan B-T0.4a), which has been taken: run
  // 35487527105 printed `answered=true outcome=role is 'admin'`, so B-T0.4b
  // deleted the `OWNER` fallback that stood in for a silence nobody had ever
  // observed. The line keeps being written, because a measurement is a fact
  // about one day and this is the only thing that would notice the endpoint
  // going quiet again. **No login** on it: the summary and the log are public,
  // and the question is about the token, not about a person.
  recordPermissionProbe(proof);
  if (!proof.ok) {
    return {
      mode: "reply",
      why: `/${command.command} from @${commenter} is refused: ${proof.detail}`,
      reply: renderCommandRefused({ command: command.command, login: commenter, detail: proof.detail }),
    };
  }

  // ── which thread is this, and may a command decide anything on it? ───────
  //
  // **A hold is not always raised on a listing issue**, and this branch used to
  // assume it was. A second release of a listed plugin arrives as a `/release`
  // ping or off the backstop; when the policy holds it there is no submission
  // issue to comment on, so the bot opens a `[notice]` issue of its own and
  // prints the exact line to clear the hold. Those issues carry no labels (the
  // script that opens them applies none), and `looksLikeListing` excludes their
  // title prefix by name — rightly, because that exclusion is the intake path's
  // only defence against the bot answering itself.
  //
  // So `!labelled && !shape.shaped` was true for every one of them, and this
  // registry spent months printing maintainers a copy-paste `/approve` line and
  // then answering it with "an issue that is not a listing request". Live:
  // issue #74 prints `/approve dwertyfa288/dwertyfa-astra-tg@v0.1.15
  // be6bc6b4f4139c5d` and nothing in this file would ever have read it. The
  // remedy the refusal offered — `/recheck` — is honoured only on a labelled
  // issue, so it did not work there either; every hold raised off a listing
  // issue was unclearable through the documented path.
  //
  // `decidableThread` is the fix, and it is a *widening of the shape*, never of
  // the authority: the collaborator-role question above is unchanged and is
  // still asked first. What the thread buys is only the right to be read
  // (registry plan B-T0.2).
  const shape = looksLikeListing({ title: issueTitle, form });
  const onListing = labelled || shape.shaped;
  const thread = onListing
    ? { kind: "listing", why: labelled ? `the \`${LISTING_LABEL}\` label` : shape.why }
    : decidableThread({ title: issueTitle, issueAuthor: opts.issueAuthor });
  if (!thread.kind) {
    return {
      mode: "reply",
      why: `/${command.command} on an issue that is not a listing request — ${thread.why}`,
      reply: renderNothingToDecide({
        registry,
        command: command.command,
        reason:
          "This issue is neither labelled `listing` nor shaped like a listing request, and it is " +
          "not one of the `[notice]` or `[release]` threads a hold can be raised on either " +
          `(${thread.why}), so there is no submission for the command to decide about.`,
      }),
    };
  }

  if (command.command === "reject") {
    // **`/reject` is a listing-issue command and stays one.** B-T0.2 admits a
    // command to a `[notice]` or `[release]` thread only when it names
    // `owner/repo@tag <fingerprint>`, and `/reject` carries a sentence instead
    // — `parseMaintainerCommand` gives it no binding at all, by construction,
    // because a rejection is a thing said to a submitter about a submission
    // under review. Off a listing issue there is no submission to close and no
    // author to close it for: a `[notice]` belongs to the bot and a `[release]`
    // ping belongs to whoever asked for a re-check. Refusing rather than
    // quietly widening is the whole of it — an unbindable command on an
    // unlabelled thread is exactly the shape this task exists to stop.
    if (!onListing) {
      return {
        mode: "reply",
        why: `/reject on a ${thread.kind} thread, which carries no submission to reject`,
        reply: renderNothingToDecide({
          registry,
          command: "reject",
          reason:
            `This is a \`[${thread.kind}]\` thread rather than a listing request. \`/approve\` and ` +
            "`/publish` are honoured here because they name the release they decide — " +
            "`owner/repo@tag <fingerprint>` — and `/reject` names a reason instead, so there is " +
            "nothing on this thread for it to close. Reject the listing request the submission " +
            "was opened with, or leave the hold to expire.",
        }),
      };
    }
    if (!command.reason) {
      return {
        mode: "reply",
        why: `/reject from @${commenter} carried no reason`,
        reply: renderRejectNeedsReason(),
      };
    }
    return {
      mode: "reject",
      close: true,
      by: commenter,
      at,
      reason: command.reason,
      why: `@${commenter} (\`${proof.role}\`) rejected this submission: ${command.reason}`,
      reply: renderRejected({ login: commenter, reason: command.reason, at }),
    };
  }

  // ── an approval, which is a target and nothing else ───────────────────────
  //
  // It carries no verdict, no cached result and no listing. What it carries is
  // "a person said yes to THIS, at this moment", and the pipeline behind it
  // re-runs every check from scratch before anything is written.
  //
  // The emphasis is the fix for a real hole. This branch used to read the
  // repository and the tag out of `form`, which is `parseIssueForm(issueBody)`
  // re-run at the moment the `/approve` comment is processed — and the issue
  // body belongs to its author, who may edit it at any point, including between
  // the bot posting the hold and the maintainer answering it. Two fields
  // changed and the approval landed on a submission the maintainer had never
  // seen. So the command names its target, and the form is now what that name is
  // CHECKED AGAINST rather than where it comes from.
  //
  // Two threads reach this point and they disagree about only one thing: where
  // the SUBMITTER comes from.
  //
  //   * On a listing issue it is the issue's author, whose ownership of the
  //     repository the pipeline proves again downstream, and the form is the
  //     second copy the command is checked against.
  //   * On a `[notice]` or `[release]` thread there is no form and the author
  //     is `github-actions[bot]` or a stranger who asked for a re-check, so
  //     neither is a submitter. It comes from the release itself, exactly as a
  //     ping's does — the account that published these bytes, which required
  //     push access at that moment (B-T0.2; AV-5; INV-6).
  //
  // Everything else is shared, and deliberately: the same binding, the same
  // `held`-record check, the same target shape, so that a second path into
  // `mode: approve` cannot become a second, shorter set of rules.
  const named = safeRepo(command.repo);
  const namedTag = safeTag(command.tag);
  let submitter;
  if (onListing) {
    const problem = formProblem(form);
    const repo = safeRepo(form.repo);
    const tag = safeTag(form.tag);
    submitter = safeLogin(opts.issueAuthor);
    if (problem || !repo || !tag || !submitter) {
      return {
        mode: "reply",
        why: `/approve on an issue the bot cannot read a submission out of`,
        reply: renderNothingToDecide({
          registry,
          command: "approve",
          reason: problem
            ? `The form is missing ${[...problem.missing, ...problem.unticked].join("; ")}.`
            : submitter
              ? "The repository and tag in this issue are not in a shape the bot will put in a URL."
              : "This issue has no author the ownership check could be run against.",
        }),
      };
    }

    // What the maintainer's own line said. Re-validated here rather than trusted
    // from the parser, because it is about to become a matrix entry and then a URL.
    if (!named || !namedTag || !command.fingerprint) {
      return {
        mode: "reply",
        why: `/approve from @${commenter} named no submission, so there is nothing to bind it to`,
        reply: renderApproveNeedsBinding({ repo, tag }),
      };
    }

    const moved = approvalMoved({ named, namedTag, repo, tag, opts, deps });
    if (moved) {
      return {
        mode: "reply",
        why:
          `/approve from @${commenter} named ${named}@${namedTag} and this issue now says ` +
          `${repo}@${tag}; the submission changed after the hold and nothing is being published`,
        reply: moved,
      };
    }
  } else {
    // ── B-T0.2: a hold raised off the listing issue ───────────────────────
    //
    // The binding is not a nicety here, it is the entire target: there is no
    // form to fall back to and nothing else on the thread names a release. So
    // it is checked first, and a bare `/approve` on a `[notice]` gets the same
    // "name what you are approving" reply it gets anywhere else.
    if (!named || !namedTag || !command.fingerprint) {
      return {
        mode: "reply",
        why:
          `/${command.command} on a ${thread.kind} thread named no submission, and there is no ` +
          "form here to read one out of",
        reply: renderApproveNeedsBinding({ repo: null, tag: null }),
      };
    }

    // Already listed, or nothing. This is the same rule that makes an
    // unauthenticated `/release` ping safe, applied to the same gap in the same
    // way: off a listing issue there is no `listing` label, so nobody decided
    // this repository was worth fetching from, and what stands in for that
    // decision is a pin that already exists. A first listing is not reachable
    // through a command at all.
    if (!findListingByRepo(sources, named)) {
      return {
        mode: "reply",
        why:
          `/${command.command} from @${commenter} named ${named}@${namedTag} on a ${thread.kind} ` +
          "thread, and that repository is not listed — off a listing issue a command may only " +
          "decide releases of a plugin this registry already carries",
        reply: renderApprovalUnlisted({ registry, command: command.command, repo: named, tag: namedTag }),
      };
    }

    // The account that published these bytes. Never the commenter, and never
    // the thread's author: on a `[notice]` that is this bot, and on a
    // `[release]` ping it is whoever asked for the re-check.
    try {
      submitter = await resolveSubmitter(named, namedTag, release);
    } catch (e) {
      return {
        mode: "reply",
        why: `/${command.command} on ${named}@${namedTag}: ${e.message}`,
        reply: renderNothingToDecide({
          registry,
          command: command.command,
          reason:
            `\`${named}@${namedTag}\` could not be resolved to a release author, so there is ` +
            `nobody for the ownership check to be run against: ${e.message}. Nothing was ` +
            "published. If the tag has moved or the release was deleted, that is the thing to " +
            "look at before the command is retyped.",
        }),
      };
    }
  }
  // ── from R4a: a command for a bound listing is the service path's ───────
  //
  // Once `log/rollout/R3-exit.json` is on main, R4a is open and a listing can
  // be bound. BOT-77 already stops the ingest from publishing, queueing or
  // clearing a hold on a listing with an identity record; this stops the
  // COMMAND, so the maintainer is told on the thread rather than by a hold
  // nobody can clear (B-T3.9; ROLL-49). Before the marker no listing is bound
  // and nothing here applies.
  if (fs.existsSync(path.join(opts.root ?? REPO_ROOT, "log", "rollout", "R3-exit.json"))) {
    const bound = (sources.plugins ?? []).filter((p) =>
      String(p.doc?.source?.repo ?? "").toLowerCase() === String(named ?? "").toLowerCase() &&
      readIdentityRecord(opts.root ?? REPO_ROOT, p.doc?.id));
    if (bound.length) {
      return {
        mode: "reply",
        why:
          `/${command.command} from @${commenter} names ${named}@${namedTag}, and ${bound.map((p) => p.doc.id).join(", ")} ` +
          "is bound: from R4a a bound listing's releases are decided on the service path, not by an issue command",
        reply:
          `\`${bound.map((p) => p.doc.id).join("\`, \`")}\` is bound to its repository, and from R4a a bound listing's ` +
          "releases are decided by the plugins service's path — the verdict, the eligibility and the binding line — " +
          "not by an issue command. Nothing was approved. See docs/POLICY.md.",
      };
    }
  }

  // ── stage 2 of B-T0.2: the approval binds to a `held` RECORD on main ─────
  //
  // Everything above binds the approval to what the maintainer was looking at.
  // From R3 there is a third thing to bind to, and it is the durable one: the
  // decision record this registry wrote when it raised the hold. An `/approve`
  // that names a fingerprint no `held` record carries is answering a hold this
  // registry never recorded — a hold from a run whose record was lost, or a
  // fingerprint out of a comment on some other thread.
  //
  // **Gated on the same marker B-T3.7's writer is**, and this is the half that
  // has to be said out loud: before `log/baseline.json` is on `main` the
  // legacy path writes no records at all, so there is no `held` record for any
  // fingerprint and an ungated rule would refuse EVERY approval this registry
  // has ever accepted. The gate is not a softening — it is the condition under
  // which the thing being checked exists.
  const marker = (deps.markerOnMain ?? markerOnMain)(opts.root);
  if (marker.present) {
    const heldFor = (deps.readDecisionRecords ?? readDecisionRecords)(opts.root)
      .map((r) => r.doc)
      .filter((d) => d && d.state === "held" && String(d.fingerprint ?? "") === command.fingerprint);
    if (heldFor.length === 0) {
      return {
        mode: "reply",
        why:
          `/approve from @${commenter} named \`${command.fingerprint}\` and no \`held\` decision record on ` +
          "main carries that fingerprint, so there is no recorded hold for it to clear",
        reply:
          `\`/approve\` names submission \`${command.fingerprint}\`, and this registry has no \`held\` ` +
          "decision record for it.\n\nAn approval clears a hold that was recorded. If the hold comment you " +
          "are answering is older than the decision log, re-run the check with `/recheck` and approve the " +
          "fingerprint the new comment prints — that run records its hold, and the approval binds to it.",
      };
    }
  }

  return {
    mode: "approve",
    // `/publish` is `/approve` and one thing more: it also waives the rest of
    // the publication delay. Everything above this line ran identically for
    // both — the same permission question to GitHub, the same binding to the
    // bytes, the same refusal when the submission moved — because a shortcut
    // that skipped any of them would be a different command wearing this one's
    // checks.
    publishNow: command.command === "publish",
    // The maintainer's values, always — never the form's. On a listing issue
    // the two are equal and the branch above is what makes them equal; on a
    // `[notice]` or `[release]` thread there is no form at all, and the command
    // line is the only thing that names a release. Taking them from the command
    // is what keeps both true if this file is ever edited again.
    repo: named,
    tag: namedTag,
    submitter,
    approvedBy: commenter,
    approvedAt: at,
    // The half triage cannot check: it names bytes, and this job has none. It
    // travels with the target to `bot/decide.mjs`, which re-hashes the release
    // and refuses the approval when the fingerprint does not match what it just
    // computed. A moved tag and a replaced asset are both invisible from here.
    approvedFor: command.fingerprint,
    why:
      `@${commenter} (\`${proof.role}\`) approved ${named}@${namedTag} (\`${command.fingerprint}\`)` +
      `${onListing ? "" : ` on a \`[${thread.kind}]\` thread, a hold raised off the listing issue`}. ` +
      "The hold is cleared only if this run hashes the same submission; every check runs again " +
      "from scratch against the release as it is now",
  };
}

async function main(argv) {
  const opts = parseArgs(argv);
  const out = await triage(opts);
  console.log(`triage: ${out.mode} — ${out.why}`);
  if (opts.modeFile) fs.writeFileSync(opts.modeFile, out.mode);
  if (opts.targetsFile) {
    // `source` travels on every target: DEC-7 records it as the decision's
    // `trigger`, and `bot/decide.mjs` refuses a source it cannot map rather
    // than recording `legacy` for a run whose origin nobody knows (B-T3.7).
    const targets = out.mode === "ping"
      ? [{ repo: out.repo, tag: out.tag, submitter: out.submitter, source: "ping" }]
      : out.mode === "approve"
        // The approval travels ON the target, so that a matrix entry carries its
        // own authority and a second target in the same run cannot borrow it.
        ? [{
          repo: out.repo,
          tag: out.tag,
          submitter: out.submitter,
          approved_by: out.approvedBy,
          approved_at: out.approvedAt,
          // Travels on the target beside the approval, for the same reason: a
          // second target in the same run must not borrow this one's waiver.
          publish_now: out.publishNow === true,
          // The submission the maintainer named. Checked against the bytes in
          // `check`, which is the only job that has any.
          approved_for: out.approvedFor,
          source: "approve",
        }]
        : [];
    fs.writeFileSync(opts.targetsFile, JSON.stringify(targets));
  }
  if (opts.replyFile && out.reply) fs.writeFileSync(opts.replyFile, out.reply);
  // Always 0: "this event was not a release notification" is the normal case,
  // not a failure, and a workflow that treated it as one would show a red X on
  // every unrelated comment in the repository.
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`triage: ${e.message}`);
      process.exit(2);
    });
}
