#!/usr/bin/env node
// Which of these events is a release notification, and of what?
//
//   node bot/triage.mjs --event issue_comment --labels listing,needs-triage \
//        --issue-body issue-body.md --comment-body comment-body.md
//
// PRODUCTION_PLAN task 3.4, layer 1. `.github/workflows/ingest.yml` calls this
// before it spends anything: it answers `mode=form|ping|none` and, for a ping,
// the three values the pipeline needs. Nothing here downloads, verifies or
// decides — it reads two files of stranger text and one directory of listings.
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

import fs from "node:fs";

import { REPO_ROOT, loadSources } from "../tools/lib/sources.mjs";

import { fetchRelease } from "./lib/github.mjs";
import { isRecheckCommand, parseIssueForm } from "./lib/issue.mjs";
import { findListingByRepo, parseReleasePing, resolveSubmitter } from "./lib/notify.mjs";

function parseArgs(argv) {
  const opts = {
    event: null, labels: "", issueBody: null, commentBody: null,
    root: REPO_ROOT, modeFile: null, targetsFile: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--event") opts.event = argv[++i];
    else if (a === "--labels") opts.labels = argv[++i] ?? "";
    else if (a === "--issue-body") opts.issueBody = argv[++i];
    else if (a === "--comment-body") opts.commentBody = argv[++i];
    else if (a === "--registry-dir") opts.root = argv[++i];
    // Two files rather than `$GITHUB_OUTPUT` lines the workflow would have to
    // `source`: sourcing a file written from stranger-influenced input is a
    // shell evaluating text, and no amount of charset validation upstream makes
    // that a thing worth doing.
    else if (a === "--mode-file") opts.modeFile = argv[++i];
    else if (a === "--targets-file") opts.targetsFile = argv[++i];
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

/**
 * @param {object} opts
 * @param {(repo: string, tag: string) => Promise<object>} [release] injection seam
 */
export async function triage(opts, release = fetchRelease) {
  const labels = String(opts.labels ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const labelled = labels.includes("listing");
  const issueBody = opts.issueBody ? read(opts.issueBody) : "";
  const commentBody = opts.commentBody ? read(opts.commentBody) : "";
  const sources = loadSources(opts.root);

  // A labelled listing issue, opened or edited, or `/recheck` on one: the
  // submission form owns it, exactly as it did before this file existed.
  if (labelled && (opts.event === "issues" || isRecheckCommand(commentBody))) {
    return { mode: "form", why: "a labelled listing issue" };
  }

  const ping = parseReleasePing(opts.event === "issue_comment" ? commentBody : issueBody);
  if (!ping) {
    return { mode: "none", why: labelled ? "a comment that is not a command" : "nothing here asks for an ingest" };
  }

  // On a listing issue the repository is already written down; a bare issue has
  // to name it. Never taken from the pinger's word when the issue already says
  // which repository it is about.
  const fromForm = parseIssueForm(issueBody).repo;
  const repo = (labelled ? fromForm ?? ping.repo : ping.repo ?? fromForm) ?? null;
  if (!repo) {
    return { mode: "none", why: "/release named no repository and the issue does not say which one it is about" };
  }

  const listing = findListingByRepo(sources, repo);
  if (!listing && !labelled) {
    return {
      mode: "none",
      why:
        `${repo} is not listed, and an unlabelled ping can only re-check a listing that already ` +
        "exists. Open a listing request with the template.",
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

async function main(argv) {
  const opts = parseArgs(argv);
  const out = await triage(opts);
  console.log(`triage: ${out.mode} — ${out.why}`);
  if (opts.modeFile) fs.writeFileSync(opts.modeFile, out.mode);
  if (opts.targetsFile) {
    const targets = out.mode === "ping"
      ? [{ repo: out.repo, tag: out.tag, submitter: out.submitter }]
      : [];
    fs.writeFileSync(opts.targetsFile, JSON.stringify(targets));
  }
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
