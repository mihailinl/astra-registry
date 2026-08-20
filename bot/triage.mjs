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

import { REPO_ROOT, loadSources } from "../tools/lib/sources.mjs";

import { fetchRelease } from "./lib/github.mjs";
import {
  LISTING_LABEL,
  formProblem,
  looksLikeListing,
  looksLikeReleasePing,
  parseMaintainerCommand,
  renderApprovalMoved,
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
import { findListingByRepo, parseReleasePing, resolveSubmitter } from "./lib/notify.mjs";
import { readQueue } from "./lib/policy.mjs";

function parseArgs(argv) {
  const opts = {
    event: null, action: null, labels: "", issueBody: null, commentBody: null,
    issueTitle: null, issueAuthor: null, commenter: null, commenterAssociation: null,
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
    // `github.event.comment.author_association`, straight out of the payload.
    // `bot/lib/maintainer.mjs` reads exactly one of its values, `OWNER`, and
    // only when the permission API declined to answer — see the block at the
    // top of that file for why the other values are not permissions.
    else if (a === "--commenter-association") opts.commenterAssociation = argv[++i] ?? null;
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
    return decideCommand({ command, opts, registry, labelled, issueTitle, form, deps });
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
 * `/approve` or `/reject <reason>`, once GitHub has said whether this account
 * may.
 *
 * The permission question is asked before the command is read for anything
 * else, and a refusal is a *reply* rather than a `none`: a maintainer who
 * mistypes their own login, or a stranger trying the command, both learn what
 * happened. Silence would teach exactly the wrong lesson to the second one.
 */
async function decideCommand({ command, opts, registry, labelled, issueTitle, form, deps }) {
  const commenter = safeLogin(opts.commenter);
  const at = iso(opts.now ?? new Date());
  if (!commenter) {
    return { mode: "none", why: `/${command.command} arrived with no usable commenter login` };
  }

  const prove = deps.proveMaintainer ?? proveMaintainer;
  const proof = await prove({
    repo: registry,
    login: commenter,
    association: opts.commenterAssociation,
  });
  if (!proof.ok) {
    return {
      mode: "reply",
      why: `/${command.command} from @${commenter} is refused: ${proof.detail}`,
      reply: renderCommandRefused({ command: command.command, login: commenter, detail: proof.detail }),
    };
  }

  const shape = looksLikeListing({ title: issueTitle, form });
  if (!labelled && !shape.shaped) {
    return {
      mode: "reply",
      why: `/${command.command} on an issue that is not a listing request`,
      reply: renderNothingToDecide({
        registry,
        command: command.command,
        reason:
          "This issue is neither labelled `listing` nor shaped like a listing request, so there " +
          "is no submission for the command to decide about.",
      }),
    };
  }

  if (command.command === "reject") {
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
  const problem = formProblem(form);
  const repo = safeRepo(form.repo);
  const tag = safeTag(form.tag);
  const submitter = safeLogin(opts.issueAuthor);
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
  const named = safeRepo(command.repo);
  const namedTag = safeTag(command.tag);
  if (!named || !namedTag || !command.fingerprint) {
    return {
      mode: "reply",
      why: `/approve from @${commenter} named no submission, so there is nothing to bind it to`,
      reply: renderApproveNeedsBinding({ repo, tag }),
    };
  }
  // ── the target this registry is already holding ─────────────────────────
  //
  // The refusal below compares the maintainer's line against the ISSUE BODY,
  // and that is right for the submission the body describes: the body belongs
  // to its author, who can edit the two form fields between the hold and the
  // answer, and an approval must not land on something nobody read.
  //
  // It is wrong for every release after the first, and it made `/publish`
  // impossible for all of them. An update arrives as a release PING — a
  // `/release v0.3.2` comment — which never touches the body. The ingest
  // verifies it, the delay queues it, and the bot posts the line to publish it
  // now. Meanwhile the body still says the tag the first listing named, for
  // ever, because nothing ever rewrites it. So the bot printed
  // `/publish owner/repo@v0.3.2 <fp>` and then refused that exact line for
  // naming something "this issue no longer describes" — and the remedy the
  // refusal offered, `/recheck`, re-reads the same body and returns the same
  // stale tag. The first listing of a plugin could be published on command and
  // no release after it ever could.
  //
  // The queue is what the maintainer is actually answering, and it is the safe
  // thing to check against for the reason the body is not: it is a committed
  // file in THIS repository, written by the bot from a run that downloaded and
  // hashed the release. A stranger cannot edit it. Nothing else is relaxed —
  // the fingerprint still names the bytes, and `bot/decide.mjs` still re-hashes
  // the release and refuses an approval that names anything else.
  const queued = (deps.readQueue ?? readQueue)(opts.root)
    .some((e) => safeRepo(e.repo) === named && safeTag(e.tag) === namedTag);

  if (!queued && (named !== repo || namedTag !== tag)) {
    // The loud refusal. Cheap, too: this is the last point before the pipeline
    // starts downloading a stranger's archive, and it is reached without one.
    return {
      mode: "reply",
      why:
        `/approve from @${commenter} named ${named}@${namedTag} and this issue now says ` +
        `${repo}@${tag}; the submission changed after the hold and nothing is being published`,
      reply: renderApprovalMoved({
        approvedRepo: named, approvedTag: namedTag, issueRepo: repo, issueTag: tag,
      }),
    };
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
    // The maintainer's values, not the form's. They are equal — the branch above
    // is what makes them equal — and taking them from the command is what keeps
    // that true if this file is ever edited again.
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
      `${queued && namedTag !== tag ? ", a release this registry is holding in its queue" : ""}. ` +
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
    const targets = out.mode === "ping"
      ? [{ repo: out.repo, tag: out.tag, submitter: out.submitter }]
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
