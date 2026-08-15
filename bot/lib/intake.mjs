// What happens to an issue nobody labelled, and to a maintainer's answer to it.
//
// This module exists because of a real submission and a real outcome: two
// listing requests arrived carrying the rendered form, both with **zero
// labels**, and `bot/triage.mjs` answered `mode: none`. `check`, `comment` and
// `publish` were all skipped, the run went green, and the author was told
// nothing at all. Not refused — *nothing*. A registry that answers a submission
// with silence has no listing flow; it has a listing flow that happens to work
// when GitHub applied a label.
//
// So there are two halves here, and they are the same idea from the two ends:
//
//   * **the author's end** — an issue that is recognisably a listing request
//     gets an answer within one run, whatever its labels say;
//   * **the maintainer's end** — `/approve` and `/reject`, so that "held for a
//     maintainer" names something a maintainer can actually do.
//
// ── why the bot replies instead of labelling the issue itself ───────────────
//
// Auto-labelling looks like the tidier fix: stamp `listing` on anything shaped
// like a submission and the existing path takes over. It is the wrong fix,
// because in this repository **the label is an authority token, not a
// category.** Read `bot/triage.mjs`'s ping rule: an *unlabelled* `/release` is
// honoured only for a repository that is already listed, so the worst a
// stranger achieves is a re-check of a listing already pinned to a repository
// identity. A *labelled* issue is exempt from that rule — it may drive an
// ingest of a repository this registry has never seen, which is the whole point
// of the submission path.
//
// A bot that mints that label from the shape of an issue body therefore hands
// the exemption to anybody who can copy a form: open an issue, get labelled,
// and now a stranger chooses which repositories this registry downloads
// archives from and runs `gh attestation verify` against. The check that would
// eventually refuse it (ownership) runs *after* the bytes are fetched, so the
// refusal is not the point — the spending is.
//
// A comment costs one API call, tells the author exactly the same thing inside
// the same run, and leaves the label where it belongs: a person's act, one
// click, which the reply names. What the bot must never do is stay quiet.

import { firstWrittenLine } from "./notify.mjs";

const REPO_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const TAG_RE = /^[A-Za-z0-9._/-]{1,128}$/;
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

/** The label that turns an issue into a submission this bot will act on. */
export const LISTING_LABEL = "listing";

/** The template that applies it, and the file a maintainer edits. */
export const LISTING_TEMPLATE = "plugin-listing.yml";

/**
 * Everything echoed back into a comment is re-checked against the charset it
 * claims to be, and dropped rather than printed when it is not.
 *
 * This is a stranger's issue body being quoted into a comment the bot posts
 * with `issues: write`. It reaches no shell — the workflow moves every body
 * through a file — but a value that failed its own validator has no business
 * being repeated as though the bot had understood it.
 */
const safe = (value, re) => (typeof value === "string" && re.test(value) ? value : null);
export const safeRepo = (v) => safe(v, REPO_RE);
export const safeTag = (v) => safe(v, TAG_RE);
export const safeLogin = (v) => safe(v, LOGIN_RE);

// ── the maintainer's two commands ───────────────────────────────────────────

/**
 * `/approve <owner/repo>@<tag> <fingerprint>`, or `/reject <reason>`, and
 * nothing else.
 *
 * Shaped exactly like `/recheck` and `/release` (`bot/lib/issue.mjs`,
 * `bot/lib/notify.mjs`): the whole line, case-insensitive, on the first line
 * anybody wrote. A sentence that mentions the command does not run it, because
 * a bot that reacts to prose is a bot that reacts to a quoted reply — and this
 * is the one command pair in the repository that changes what gets published.
 * `firstWrittenLine` skips a leading blank line and a markdown heading, and
 * nothing else; `> /approve` in a quoted reply is neither.
 *
 * ── why `/approve` takes arguments and `/reject` does not ──────────────────
 *
 * `/approve` used to be the bare word, and everything it applied to was read
 * back out of the issue body at the moment the comment arrived. The author owns
 * that body. Edit the two fields after the bot posts the hold and before the
 * maintainer answers it, and the yes lands on a submission nobody read.
 *
 * So the command names what it approves, and the hold comment prints the line
 * ready to copy: the repository, the tag, and the fingerprint of the bytes that
 * run hashed (`submissionFingerprint` in `bot/lib/policy.mjs`). `bot/triage.mjs`
 * checks the first two against the issue as it stands — a cheap, early refusal
 * that costs no download — and `bot/lib/policy.mjs` checks the third against the
 * bytes, which is the half that catches a moved tag or a replaced asset.
 *
 * `/reject` needs none of it. It publishes nothing, and refusing to close an
 * issue because a fingerprint has moved on would be pedantry with a cost.
 *
 * Parsing says nothing about permission. `bot/lib/maintainer.mjs` answers that,
 * against the GitHub API, and `bot/triage.mjs` refuses to act until it has.
 *
 * @param {string} text a comment body
 * @returns {{command: "approve"|"reject", reason: string|null, repo: string|null,
 *   tag: string|null, fingerprint: string|null}|null}
 */
export function parseMaintainerCommand(text) {
  const m = /^\/(approve|reject)\b\s*(.*)$/i.exec(firstWrittenLine(text));
  if (!m) return null;
  const command = m[1].toLowerCase() === "approve" ? "approve" : "reject";
  // Capped and flattened: it is a maintainer's sentence, quoted back to the
  // author on a public thread, not a document.
  const rest = m[2].trim().slice(0, 500);
  if (command === "reject") {
    return { command, reason: rest || null, repo: null, tag: null, fingerprint: null };
  }
  const bound = APPROVE_BINDING_RE.exec(rest);
  return {
    command,
    reason: null,
    // Null when the line named nothing the parser recognises, which triage
    // answers with the shape that works rather than by guessing at it.
    repo: bound ? bound[1] : null,
    tag: bound ? bound[2] : null,
    fingerprint: bound ? bound[3].toLowerCase() : null,
  };
}

/**
 * `owner/repo@tag <16 hex>` — the same charsets `safeRepo` and `safeTag` allow,
 * anchored, so a line with anything else on it is not a binding at all.
 *
 * A tag may contain `/` and `.` but never `@`, which is what makes the split
 * unambiguous without asking the author's issue body where it is.
 */
const APPROVE_BINDING_RE = /^([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)@([A-Za-z0-9._/-]{1,128})\s+([0-9a-fA-F]{16})$/;

// ── is this issue a listing request at all? ─────────────────────────────────

/**
 * The two facts, and the two confirmations, as `bot/read-submission.mjs`
 * requires them.
 *
 * Same two rules, in the same order, and that duplication is deliberate rather
 * than accidental: `read-submission.mjs` is what the workflow's form branch
 * runs, and it exits 2 on a submission it cannot read. Under `set -e` that
 * killed the triage step — no target, no comment job, and an author who had
 * ticked one box instead of two got a red X and silence. Answering the same
 * question *before* the branch is taken turns that into a comment saying which
 * field is missing.
 *
 * @param {{repo: string|null, tag: string|null, confirmations: {label: string, checked: boolean}[]}} form
 * @returns {{missing: string[], unticked: string[]}|null} null when it is readable
 */
export function formProblem(form) {
  const missing = [];
  if (!form?.repo) missing.push("Source repository");
  if (!form?.tag) missing.push("Release tag carrying the .astraplugin assets");
  const confirmations = form?.confirmations ?? [];
  const unticked = confirmations.length ? confirmations.filter((c) => !c.checked).map((c) => c.label) : [];
  return missing.length || unticked.length ? { missing, unticked } : null;
}

/**
 * Does this issue read as a listing request?
 *
 * Two independent signals, either of which is enough, because the two ways a
 * submission loses its label produce different remains:
 *
 *   * **the title**, `[listing] <owner>/<repo>`, which the template sets and
 *     which survives an issue opened through the API with a copied body;
 *   * **the form's own field headings**, which GitHub renders into the body and
 *     which survive a title somebody rewrote.
 *
 * Deliberately not a keyword search over prose. "I would like to list my
 * plugin" is a question, and the answer to a question is a contact link, not a
 * verification pipeline.
 *
 * The bot's own `[notice]` issues are excluded by name. They cannot start a run
 * today — an event raised with the repository's `GITHUB_TOKEN` starts no
 * workflow — but a bot whose only defence against answering itself is a
 * property of somebody else's credential is one App installation away from a
 * comment loop.
 *
 * So are the other three forms in `.github/ISSUE_TEMPLATE/`, by their title
 * prefixes. An appeal, a report and a release ping are each somebody using the
 * door that was built for them, and answering one with "ask a maintainer for
 * the `listing` label" would be the bot mistaking its own front page for the
 * only room in the building.
 *
 * @param {{title?: string|null, form?: object|null}} input
 */
export function looksLikeListing({ title, form }) {
  const t = String(title ?? "").trim();
  if (/^\[(notice|appeal|report|release)\]/i.test(t)) {
    return { shaped: false, why: "one of this registry's other forms, or one of its own notices" };
  }

  const titled = /^\[listing\]/i.test(t);
  const facts = Boolean(form?.repo || form?.tag);
  if (!titled && !facts) return { shaped: false, why: "neither the title nor the form's fields are here" };

  return {
    shaped: true,
    why: titled && facts
      ? "the title says `[listing]` and the form's fields are in the body"
      : titled
        ? "the title says `[listing]`"
        : "the listing form's own field headings are in the body",
  };
}

/**
 * Somebody opened the release-ping form and the command did not survive.
 *
 * The form ships a working line and a person edits it, so the ways it breaks
 * are a mistyped repository, a missing tag, or an explanation typed above it.
 * All three produce a `parseReleasePing` of `null`, which used to be silence.
 * The title prefix is what identifies the intent, and it is set by the template
 * rather than typed.
 */
export const looksLikeReleasePing = (title) => /^\[release\]/i.test(String(title ?? "").trim());

// ── what the author reads ───────────────────────────────────────────────────

const FOOTER =
  "<sub>Posted by `bot/triage.mjs`. A submission that reaches this registry is answered, every " +
  "time — an unlabelled listing request used to produce no run, no comment and no record, and " +
  "that silence is the bug this comment exists to end.</sub>";

const newIssueUrl = (registry) =>
  safeRepo(registry)
    ? `https://github.com/${registry}/issues/new?template=${LISTING_TEMPLATE}`
    : `\`.github/ISSUE_TEMPLATE/${LISTING_TEMPLATE}\``;

const join = (lines) => `${lines.filter((l) => l !== null).join("\n")}\n`;

/**
 * An issue that is plainly a listing request and carries no `listing` label.
 *
 * It must answer three questions and it must answer them in this order: what
 * happened (nothing), what makes it start (the label), and why the bot will not
 * apply the label itself. The third is not an apology — an author who is told
 * "ask a maintainer" without being told why will reasonably assume the bot is
 * broken.
 */
export function renderUnlabelled({ registry, repo, tag, why }) {
  const r = safeRepo(repo);
  const t = safeTag(tag);
  return join([
    `**Nothing has run on this issue yet, and here is exactly why.**`,
    "",
    `This registry's bot only starts verifying a submission when the issue carries the ` +
      `\`${LISTING_LABEL}\` label. This one carries no labels, so \`bot/triage.mjs\` answered ` +
      "`none` and every later job — the checks, the report, the publication — was skipped. " +
      "The run went green because nothing failed; nothing ran.",
    "",
    `It reads as a listing request: ${why}.`,
    r ? "" : null,
    r ? `| | |\n|---|---|\n| Source repository | \`${r}\` |\n| Release tag | ${t ? `\`${t}\`` : "_not found in this issue_"} |` : null,
    "",
    "**Either of these starts it, and the first one is faster:**",
    "",
    `1. **Ask a maintainer to add the \`${LISTING_LABEL}\` label to this issue.** One click, and ` +
      "labelling fires the same event a new submission does — verification starts on *this* " +
      "issue, within one run. Nothing needs reopening and nothing needs retyping.",
    `2. Or open a fresh request with the form: ${newIssueUrl(registry)}. It applies the label ` +
      "itself, and it asks for the two facts in the shape the bot reads.",
    "",
    `**Why the bot does not just label it for you.** In this repository the \`${LISTING_LABEL}\` ` +
      "label is an authority token rather than a category: an issue carrying it may drive an " +
      "ingest of a repository this registry has never seen, while an unlabelled `/release` may " +
      "only ask for a re-check of a listing that already exists. A bot that stamped that label " +
      "on anything shaped like a form would hand that exemption to anyone who can copy one — so " +
      "the label stays a person's decision, and this comment is the part that must never be " +
      "missing.",
    "",
    FOOTER,
  ]);
}

/** A labelled submission whose form the bot cannot read. */
export function renderIncompleteForm({ registry, problem }) {
  const { missing, unticked } = problem;
  return join([
    "**This submission cannot start, because the form is missing something the bot needs.**",
    "",
    missing.length
      ? `Not found in the issue body:\n${missing.map((m) => `- **${m}**`).join("\n")}`
      : null,
    missing.length ? "" : null,
    unticked.length
      ? `Not ticked:\n${unticked.map((m) => `- ${m}`).join("\n")}`
      : null,
    unticked.length ? "" : null,
    "The confirmations are not evidence — ownership is proved by reading " +
      "`.well-known/astra-plugin-owner` off the default branch, whatever is ticked here — but " +
      "they are the difference between a mistake and a statement, and the template requires " +
      "them.",
    "",
    "**Edit this issue** and the bot reads it again on the edit; there is no command to type and " +
      "nothing to reopen. If the field headings themselves are gone (a body that was pasted " +
      `rather than filled in), open a fresh request with the form instead: ${newIssueUrl(registry)}.`,
    "",
    FOOTER,
  ]);
}

/** The release-ping form, opened, with no readable command in it. */
export function renderPingUnreadable({ registry }) {
  return join([
    "**Nothing has run, because the command in this issue is not one the bot can read.**",
    "",
    "It has to be one line, on its own, with nothing above it but a heading:",
    "",
    "```",
    "/release owner/repo v0.2.0",
    "```",
    "",
    "The usual causes, and the fix for each:",
    "",
    "- **A sentence above the command.** Move it below. The bot reads the first line anybody " +
      "wrote, so an explanation on top hides the command behind it.",
    "- **A repository that is not `owner/name`.** A full `https://github.com/…` URL is accepted; " +
      "anything else is not.",
    "- **A missing tag.** Two words after `/release` on a new issue: the repository and the tag.",
    "",
    "**Edit this issue and the bot reads it again** — there is nothing to reopen and no command " +
      "to type.",
    "",
    `Or comment \`/release <tag>\` on your own listing issue instead, where the repository is ` +
      "already written down and one word is enough.",
    "",
    FOOTER,
  ]);
}

/** `/release <repo> <tag>` on an unlabelled issue, for a repository nobody has listed. */
export function renderPingForUnlisted({ registry, repo }) {
  const r = safeRepo(repo);
  return join([
    `**A release ping cannot create a listing**, so nothing has run.`,
    "",
    `\`/release\` on an unlabelled issue is honoured only for a repository that is **already ` +
      `listed**${r ? `, and \`${r}\` is not` : ""}. That is not a formality: a ping carries no ` +
      "authority and needs no token, so the only thing that keeps it safe is that the worst it " +
      "can do is re-check a listing already pinned to a repository identity.",
    "",
    `A **first** listing goes through the form, which a person reads once: ${newIssueUrl(registry)}. ` +
      "After that, every release from the same repository is zero-touch — tag it, let CI build " +
      "and attest it, and `/release <tag>` on your listing issue is all this ever needs again.",
    "",
    FOOTER,
  ]);
}

/** `/approve` or `/reject` from an account that may not decide. */
export function renderCommandRefused({ command, login, detail }) {
  const who = safeLogin(login);
  return join([
    `**\`/${command}\` is refused.**`,
    "",
    detail,
    "",
    "`/approve` and `/reject` decide what this registry publishes, so they are checked against " +
      "`GET /repos/{owner}/{repo}/collaborators/{login}/permission` on **this** repository and " +
      "require `admin` or `maintain` — the same bar `bot/lib/ownership.mjs` sets for a submitter, " +
      "asked about the registry instead of about the plugin. The comment's `author_association` " +
      "is not a permission — `COLLABORATOR` covers `read` and `triage`, and `CONTRIBUTOR` never " +
      "expires — so the only value of it that counts for anything here is `OWNER`, and only as a " +
      "fallback for when GitHub declines to answer the API at all.",
    "",
    who ? `Nothing about the submission changed, and @${who} has not been blocked from anything ` +
      "else — a maintainer can still run the same command." : null,
    "",
    FOOTER,
  ]);
}

/** `/approve` or `/reject` on something there is nothing to decide about. */
export function renderNothingToDecide({ registry, command, reason }) {
  return join([
    `**\`/${command}\` has nothing to act on here.**`,
    "",
    reason,
    "",
    `A decision applies to a specific release, so it needs the two facts the listing form ` +
      `asks for — the source repository and the release tag. ${newIssueUrl(registry)} is the ` +
      "shape it reads.",
    "",
    FOOTER,
  ]);
}

/** A rejection: the reason, the appeal, and the door left open. */
export function renderRejected({ login, reason, at }) {
  const who = safeLogin(login) ?? "a maintainer";
  return join([
    `**Rejected by @${who}${at ? ` at ${at}` : ""}.**`,
    "",
    `> ${String(reason).replace(/\n/g, " ")}`,
    "",
    "This is a decision about *this* submission, and it is not permanent. What to do with it:",
    "",
    "- If the reason names something you can change — a licence, a name, a permission that needs " +
      "explaining — change it and open a fresh listing request. Nothing here counts against a " +
      "later one.",
    "- If you think the reason is wrong, say so on this issue. It stays open to comments after " +
      "it is closed, and a maintainer answers on the thread rather than in private.",
    "- `docs/POLICY.md` §10 is the appeal route for a decision about a plugin that is already " +
      "listed; this is the earlier case, and a comment here is enough.",
    "",
    "The issue is closed so it leaves the review queue. Closing it *without* this comment is the " +
      "thing this registry does not do.",
    "",
    FOOTER,
  ]);
}

/**
 * `/approve` that did not say what it approves.
 *
 * The reply's whole job is to make the right line easy to find, because the
 * wrong line is the bare word a maintainer typed for months. It does not print
 * a ready-made command: the fingerprint half of one is not knowable here —
 * triage has no bytes — and inventing a line that looks copy-pasteable and is
 * not would teach exactly the habit this binding exists to break.
 */
export function renderApproveNeedsBinding({ repo, tag }) {
  const r = safeRepo(repo);
  const t = safeTag(tag);
  return join([
    "**`/approve` has to name what it is approving.**",
    "",
    "Nothing was published and nothing about this submission changed.",
    "",
    "The bot's **Held for a maintainer** comment prints the line ready to copy. It looks like this:",
    "",
    "```",
    `/approve ${r ?? "owner/repo"}@${t ?? "v0.0.0"} 0123456789abcdef`,
    "```",
    "",
    "The last field is the fingerprint of the submission that comment was about — the repository, " +
      "the tag, the version and the digest of every release asset that run downloaded and hashed. " +
      "Copying it is what ties your yes to the thing you read.",
    "",
    "**Why a bare `/approve` no longer works.** It used to mean *approve whatever this issue says " +
      "right now*, and the issue body belongs to the author: it can be edited between the hold and " +
      "your answer, so the release that published need never have been the one you looked at. The " +
      "line above cannot be edited out from under you — if the release changes, the fingerprint " +
      "changes, and the approval is refused instead of applied to something else.",
    "",
    FOOTER,
  ]);
}

/**
 * `/approve` for a submission the issue no longer describes.
 *
 * The loud case, and the one worth being loud about: this is what an author
 * editing the two form fields between the hold and the answer looks like from
 * here. It is also what a maintainer pasting the wrong comment's line looks
 * like, and the bot cannot tell them apart — which is the argument for refusing
 * both rather than guessing.
 */
export function renderApprovalMoved({ approvedRepo, approvedTag, issueRepo, issueTag }) {
  const ar = safeRepo(approvedRepo);
  const at = safeTag(approvedTag);
  const ir = safeRepo(issueRepo);
  const it = safeTag(issueTag);
  return join([
    "**`/approve` is refused: this issue no longer describes what you approved.**",
    "",
    "| | |",
    "|---|---|",
    `| Your command named | \`${ar ?? "unreadable"}@${at ?? "unreadable"}\` |`,
    `| This issue says | \`${ir ?? "unreadable"}@${it ?? "unreadable"}\` |`,
    "",
    "Nothing was downloaded, nothing was verified and nothing was published.",
    "",
    "The submission form is part of the issue body, and the issue body belongs to its author — it " +
      "can be edited at any time, including after the bot posted the hold you just answered. So an " +
      "approval names its own target, and when the two disagree the registry stops rather than " +
      "picking one. **This is worth looking at before you retype anything:** an edit between a hold " +
      "and an approval is either an author fixing a mistake and saying so on the thread, or an " +
      "author swapping a submission under review.",
    "",
    "If the issue as it now stands is what you meant to approve, comment `/recheck`, read the " +
      "comment that comes back, and copy the `/approve` line out of **that** one.",
    "",
    FOOTER,
  ]);
}

/** `/reject` with nothing after it. */
export function renderRejectNeedsReason() {
  return join([
    "**`/reject` needs a reason.**",
    "",
    "`/reject <one sentence the author can act on>` — the sentence is posted on this issue and " +
      "is the whole point of the command. A rejection with no reason is a silent close with " +
      "extra steps, and the author learns nothing they can fix.",
    "",
    "Nothing has been closed and nothing has changed.",
    "",
    FOOTER,
  ]);
}
