// Whether a release publishes itself, waits, or waits for a person.
//
// PRODUCTION_PLAN task 3.5. `bot/ingest.mjs` (task 3.3) decides whether a
// release is *listable* — every check it runs is about the bytes. This module
// decides whether it is *published without a human*, which is a different
// question with a different failure mode: the bot being too strict here does
// not admit a bad plugin, it drives authors away, and an author who has decided
// the registry is a queue publishes through a side channel instead.
//
// ── the four outcomes ───────────────────────────────────────────────────────
//
//   refuse    a check failed. Nothing publishes. (task 3.3 owns the reason.)
//   review    a person has to decide. Exactly three events, listed below.
//   delay     it will publish itself at a stated time, and the author is told
//             now, so a takeover victim has a window in which to shout.
//   publish   now, with nobody in the loop.
//
// ── why `delay` exists at all ───────────────────────────────────────────────
//
// §5.5, the row nobody enjoys: *"Author's GitHub account compromised — nothing
// cryptographic. Provenance will be perfect and attest a malicious build."* The
// signature chain is exactly as strong as the author's GitHub account, and no
// amount of verification fixes that. The only defences the plan claims are
// policy ones — a publication delay and an out-of-band notification — and this
// module is where they live. It is deliberately not dressed up as more than it
// is: a delay buys time for a human who is watching, and buys nothing at all
// from an attacker nobody is watching.
//
// ── what an approval is, and the one thing it must never become ────────────
//
// `review` used to be a terminus. The bot said "held for a maintainer", the
// ingest exited 3, and nothing in this repository implemented the maintainer's
// next move — no command, no override, nothing in POLICY.md. The queue was a
// place submissions went.
//
// `/approve` (`bot/triage.mjs`, permission-checked by `bot/lib/maintainer.mjs`)
// resolves that, and it is deliberately the smallest possible thing: an
// approval **clears the hold and nothing else**.
//
//   * It cannot clear an error. The refusal branch below runs first, so a
//     maintainer cannot approve away a failed signature, an unproved ownership
//     or a licence this registry does not allow. Those are not decisions; they
//     are facts about the bytes, and the answer to one is a new release.
//   * It does not carry a verdict forward. The approval is a name and a
//     timestamp on a target; `bot/decide.mjs` runs the **entire** ingest again
//     before this function is called at all. Publishing the artifact a previous
//     run verified would be publishing something nobody has looked at since —
//     a tag can be moved, a release asset can be replaced, and the digest that
//     reaches the catalogue must be the digest this run downloaded and hashed.
//     That is the same rule the publication delay follows when its clock runs
//     out, for the same reason, and it is why there is no "approve and publish
//     what you already checked" path anywhere in this file.
//   * It does not waive the publication delay. A held release that is also a
//     widening still waits: the hold and the delay answer different questions
//     (*may this be listed at all* versus *has the author had a chance to
//     notice*), and one person's yes does not answer the second one. The delay
//     has its own documented waiver — editing `publish_after` — which leaves
//     its own commit.
//
// What it does leave behind is a record: `P_APPROVED` in the comment on the
// issue, and `approved_by` / `approved_at` / `artifact_digests` in the
// `decision.json` the publish job reads, so "who let this in, when, and against
// which bytes" has one answer and it is written down in three places that
// cannot disagree.
//
// ── and the thing an approval has to NAME ───────────────────────────────────
//
// Everything above is about the run that publishes. It left a gap one layer up,
// and the gap was real: `/approve` used to carry no identity at all, so
// `bot/triage.mjs` re-read the issue body at the moment the comment arrived and
// took the repository and the tag out of it. The author can edit that body. Hold
// the submission, wait for the maintainer to read it, edit the two fields, and
// the `/approve` they type is an approval of a submission they never saw — the
// same defect as publishing bytes an earlier run verified, moved from the bytes
// to the form that names them.
//
// So an approval names what it approves, and `submissionFingerprint` below is
// what it names: repository, tag, plugin id, version, and the digest of every
// artifact **this run hashed**. Not the issue body — a body is prose, it is
// edited for good reasons, and binding to it would refuse an approval because
// somebody fixed a typo. The digests are the identity that is stable exactly as
// long as the thing being approved is unchanged.
//
// The fingerprint travels in the command (`/approve owner/repo@tag <fp>`, the
// line the hold comment prints ready to copy), and this module recomputes it
// from the run in front of it. A mismatch is `P_APPROVAL_STALE`: the hold stands,
// nothing publishes, and the comment says what was approved and what is here
// now. It is deliberately louder than a silent no-op, because the interesting
// case is not a maintainer fumbling a paste — it is a submission that changed
// underneath one.
//
// ── why the codes are not in bot/lib/codes.mjs ──────────────────────────────
//
// `codes.mjs` is the vocabulary of the *checks* — what a submission got wrong.
// These are the vocabulary of the *publication decision* — what the registry
// chose to do about a submission that got nothing wrong. Keeping them apart
// means `docs/BOT-CHECKS.md` stays a description of the checks and
// `docs/POLICY.md` stays a description of the policy, and neither document has
// to explain the other's rows. The two tables have the same shape, and
// `renderPolicySection` renders them the same way.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { compareSemver, parseSemver } from "../../tools/lib/semver.mjs";

// ── the constants POLICY.md publishes ───────────────────────────────────────
//
// Every number a person is promised in docs/POLICY.md is declared here and
// nowhere else, and `bot/tests/policy.test.mjs` asserts the document quotes
// these values. A published SLA that has drifted from the code is worse than no
// SLA: it teaches people the document is decoration.

/**
 * The permissions and capabilities whose *first appearance* stops a release and
 * asks a person.
 *
 * PRODUCTION_PLAN §3.5 names these four: each one acts on the user's session or
 * on the Astra window rather than inside the plugin, and each is refused
 * outright to a Tier-2 import (§5.5). Two of them (`dom_access`, `client`) are
 * `[capabilities]` keys today and two are `[permissions]` keys from Phase 4, so
 * both sections are searched — the manifest's shape is not the point, the
 * authority requested is.
 */
export const HIGH_RISK = ["client", "dom_access", "send_chat_message", "set_theme_contribution"];

/**
 * The Phase 4 consent sheet's high-risk set (§5.6), which is the one above plus
 * `push_to_ui`.
 *
 * It is NOT the auto-ingest trigger set, and the difference is intentional: a
 * consent checkbox costs the user one read, while blocking review costs the
 * author days. `push_to_ui` draws in a panel the plugin already owns; the four
 * above reach outside it. A newly requested `push_to_ui` is therefore a
 * widening — 24 h and a notification — not a review.
 */
export const CONSENT_HIGH_RISK = [...HIGH_RISK, "push_to_ui"].sort();

/** Hours a widened or high-risk release waits before it publishes itself. */
export const DELAY_HOURS = 24;

/**
 * The graduated delay, and what earns it.
 *
 * The argument for a shorter delay is not that an established author is more
 * trustworthy — a compromised account is a compromised account. It is that the
 * delay's value decays: it is a window for somebody to notice, and an author
 * with a release history has a repository people watch, releases people follow,
 * and a bot that has already told them about four earlier publications. The
 * first release from an account nobody has ever seen is the one where 24 hours
 * buys the most.
 */
export const TRUSTED_DELAY_HOURS = 6;
export const CLEAN_RELEASES_FOR_TRUSTED = 5;

/** The published SLA for the three events that block on a person. */
export const REVIEW_SLA_HOURS = 48;

/**
 * The point at which a missed SLA becomes a policy change rather than a backlog.
 *
 * When review items sit past this, the answer is to make fewer things need
 * review — not to let the queue rot. An author who cannot ship routes around
 * the registry, and a release that auto-published after 24 h is safer for
 * everyone than one that shipped through a side channel, because at least the
 * registry saw it. `slaReport` below makes the breach visible on every cron run
 * so the choice is made deliberately rather than by drift.
 */
export const SLA_BREACH_HOURS = REVIEW_SLA_HOURS * 2;

/** @typedef {{level: string, title: string, remedy: string}} PolicyCodeDef */

/** @type {Record<string, PolicyCodeDef>} */
export const POLICY_CODES = {
  P_PUBLISHED: {
    level: "pass",
    title: "Published, with nobody in the loop",
    remedy: "Nothing to do. This is what a routine release is supposed to look like.",
  },
  P_REFUSED: {
    level: "error",
    title: "Not published, because a check failed",
    remedy: "Fix the blocking findings above and comment `/recheck`. The policy did not reject this; a check did.",
  },
  R_FIRST_LISTING: {
    level: "review",
    title: "First listing — a person reads it, once, ever",
    remedy:
      "Nothing to do but wait. This is one of exactly three events that block on a human, and it " +
      "happens once per plugin: every later release from the same repository is zero-touch.",
  },
  R_IDENTITY_CHANGED: {
    level: "review",
    title: "The repository this plugin is listed from changed",
    remedy:
      "Say in the issue what happened — a rename, a transfer, a fork taking over maintenance. " +
      "Every installed copy carries a pin to the old repository, so this is an author change " +
      "until somebody says otherwise.",
  },
  R_NEW_HIGH_RISK: {
    level: "review",
    title: "The release asks for a high-risk permission it did not have before",
    remedy:
      "Say in the issue what the new permission is for, in one sentence a user would accept. " +
      "The four that block are `client`, `dom_access`, `send_chat_message` and " +
      "`set_theme_contribution`; each reaches outside the plugin's own surface.",
  },
  P_APPROVED: {
    level: "pass",
    title: "A maintainer cleared the hold",
    remedy:
      "Nothing to do. The hold is gone; every check above was re-run from scratch in this run, " +
      "against the release as it is today, and what publishes is what this run verified.",
  },
  P_APPROVAL_STALE: {
    level: "review",
    title: "The approval named a different submission from this one",
    remedy:
      "Nothing published and nothing was lost. An `/approve` carries the fingerprint printed in " +
      "the comment it answers, and this run's fingerprint is different — the repository, the tag, " +
      "the version or the release assets changed after that comment was written. Read the table " +
      "above as it stands now and, if it is still a yes, copy the `/approve` line out of **this** " +
      "comment. An approval has to be about something a person actually read.",
  },
  R_CHECK_HELD: {
    level: "review",
    title: "A check handed the decision to a person",
    remedy:
      "Not a rejection and not one of the three policy events — a near-miss name or a display-name " +
      "collision that the bot is not entitled to rule on. Same 48-hour SLA.",
  },
  P_DELAY_HIGH_RISK: {
    level: "note",
    title: "Held for the publication delay because the plugin holds a high-risk permission",
    remedy:
      "Nothing to do. Every auto-published release of a plugin holding any high-risk permission " +
      "waits, whether or not this release changed anything — §5.5's realistic takeover case is a " +
      "malicious version with *identical* permissions, and a delay that only fired on changes " +
      "would never fire on it.",
  },
  P_DELAY_WIDENED: {
    level: "note",
    title: "Held for the publication delay because the permission set grew",
    remedy:
      "Nothing to do. A widening inside the non-high-risk set publishes itself after the delay; " +
      "the delay exists so the author hears about it first.",
  },
  P_DELAY_BYTES_CHANGED: {
    level: "warn",
    title: "The release assets changed during the delay, so the clock restarted",
    remedy:
      "Do not overwrite a published release asset. The delay is a delay on *these bytes*; " +
      "replacing them mid-window starts it again, which is the only thing that stops a swap " +
      "timed for the end of the window.",
  },
  P_DELAY_WAITING: {
    level: "note",
    title: "Waiting out the publication delay",
    remedy: "Nothing to do. It publishes itself at the time stated above without anybody touching it.",
  },
  P_DELAY_ELAPSED: {
    level: "pass",
    title: "The publication delay has elapsed",
    remedy: "Nothing to do. Every check was re-run from scratch just now, against the bytes as they are today.",
  },
  P_DELAY_BROUGHT_FORWARD: {
    level: "note",
    title: "A maintainer waived part of the publication delay",
    remedy:
      "Nothing to do, but the shortened window is on the record: somebody with write access to this " +
      "registry edited `publish_after` in the queue entry, and the commit that did it says who and when. " +
      "Every check still ran from scratch against today's bytes.",
  },
  P_UNKNOWN_PERMISSION: {
    level: "warn",
    title: "The manifest declares a permission this registry has no name for",
    remedy:
      "Check the spelling against POLICY.md's permission table. An unknown key grants nothing — " +
      "the daemon default-denies — so it is reported rather than blocked, but a permission nobody " +
      "can name is also a permission no consent sheet can describe.",
  },
  P_TRUSTED_AUTHOR: {
    level: "note",
    title: "Shorter delay: this author has a clean release history here",
    remedy: "Nothing to do.",
  },
  P_SLA: {
    level: "note",
    title: "What happens next, and by when",
    remedy: "See docs/POLICY.md. If this passes the stated deadline, say so on this issue — a missed SLA is a bug in the policy, not in your release.",
  },
};

/** @param {string} code */
export function policyCodeDef(code) {
  return (
    POLICY_CODES[code] ?? {
      level: "error",
      title: `undeclared policy code ${code}`,
      remedy: "This is a bug in the registry bot: the code is not in bot/lib/policy.mjs.",
    }
  );
}

// ── reading a release's requested authority ─────────────────────────────────

/**
 * Every name a version document asks for, capabilities and permissions alike,
 * as one sorted set.
 *
 * The two sections answer different questions for the daemon (what I implement
 * vs what I may call), but for this decision they are the same question: what
 * authority is this release asking a user to grant that the last one did not?
 *
 * A listing that predates capability recording carries neither key, and reads
 * here as "asks for nothing". That makes its next release look like a widening:
 * one 24 h delay per legacy listing, once, after which the recorded set is
 * right. Deliberately not special-cased — the alternative is a "we could not
 * tell" branch that silently skips the comparison, and an unknown baseline is
 * the one case where waiting is obviously correct.
 */
export function requestedAuthority(versionDoc) {
  if (!versionDoc) return [];
  const caps = Array.isArray(versionDoc.capabilities) ? versionDoc.capabilities : [];
  const perms = versionDoc.permissions && typeof versionDoc.permissions === "object"
    ? Object.keys(versionDoc.permissions)
    : [];
  return [...new Set([...caps, ...perms].map(String))].sort();
}

/** The high-risk members of a requested set. */
export const highRiskIn = (names) => names.filter((n) => HIGH_RISK.includes(n));

/**
 * The newest version already listed for a plugin, by semver rather than by
 * filename.
 *
 * A listing's newest version is the one a widening is measured against: an
 * author who published 0.3.0 with `dom_access` and then backports 0.2.9 has not
 * newly requested anything.
 */
export function newestListedVersion(existing) {
  const docs = (existing?.versions ?? []).map((v) => v.doc).filter((d) => d && parseSemver(d.version));
  if (docs.length === 0) return null;
  return docs.sort((a, b) => compareSemver(a.version, b.version)).at(-1);
}

// ── the author's track record ───────────────────────────────────────────────

/**
 * How many clean releases this author has published here, and whether anything
 * of theirs has ever been revoked.
 *
 * Counted per *account*, not per plugin: the thing being graduated is an
 * author's history with this registry, and an author's second plugin is not
 * their first rodeo. A revocation anywhere in that account's listings resets it
 * to zero — the counter is a statement about a track record, and a revoked
 * plugin is the definition of not having one.
 *
 * Yanked versions are not counted and do not reset: yanking is the author's own
 * "do not use this one" (POLICY.md §6), not a fault signal.
 */
export function trackRecord(root, repo, { plugins, revocations } = {}) {
  const owner = String(repo ?? "").split("/")[0].toLowerCase();
  const list = plugins ?? [];
  const revoked = revocations ?? loadRevocations(root);

  let clean = 0;
  let revokedHere = false;
  for (const p of list) {
    const pRepo = p.doc?.source?.repo;
    if (!pRepo || String(pRepo).split("/")[0].toLowerCase() !== owner) continue;
    for (const v of p.versions ?? []) {
      const doc = v.doc;
      if (!doc?.version || !parseSemver(doc.version)) continue;
      if (doc.yanked) continue;
      // A staging entry is a listing whose artifact nobody could verify. It is
      // not evidence of a clean release; it is evidence of a bootstrap.
      if (doc.staging) continue;
      if (isRevoked(revoked, p.doc?.id, doc.version)) {
        revokedHere = true;
        continue;
      }
      clean++;
    }
  }

  const tier = !revokedHere && clean >= CLEAN_RELEASES_FOR_TRUSTED ? "established" : "new";
  return {
    owner,
    clean_releases: clean,
    revoked: revokedHere,
    tier,
    delay_hours: tier === "established" ? TRUSTED_DELAY_HOURS : DELAY_HOURS,
  };
}

/** `registry/v1/revocations.json` if task 3.9 has landed it, else nothing. */
export function loadRevocations(root) {
  const file = path.join(root ?? ".", "registry", "v1", "revocations.json");
  try {
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    return doc?.signed?.revocations ?? doc?.revocations ?? [];
  } catch {
    return [];
  }
}

function isRevoked(revocations, id, version) {
  if (!id) return false;
  return revocations.some((r) => {
    if (r.plugin_id && r.plugin_id !== id) return false;
    if (r.id && r.id !== id) return false;
    if (r.version && r.version !== version) return false;
    return Boolean(r.plugin_id || r.id);
  });
}

// ── the queue ───────────────────────────────────────────────────────────────
//
// A delayed release is a file in `state/queue/`, committed like everything else
// here. Three properties fall out of that choice and none of them are
// incidental:
//
//   * it survives. There is no server; a delay held in a workflow's memory is a
//     delay that ends when the runner does.
//   * it is auditable. `git log state/queue/` is the list of every release that
//     ever waited, and why.
//   * it is cancellable by a person with no tooling at all: delete the file.
//
// The entry records the digests it was queued for, and `decide` restarts the
// clock when they change. Everything else in it is a convenience for the human
// reading the directory — the publish path re-runs every check from scratch and
// believes none of it.

/** The registry's operational memory: what is waiting, and what it last saw. */
export const STATE_DIR = "state";

/** `state/queue/<id>@<version>.json` — one file per waiting release. */
export function queueFile(id, version) {
  return path.join(STATE_DIR, "queue", `${id}@${version}.json`);
}

export function readQueueEntry(root, id, version) {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, queueFile(id, version)), "utf8"));
  } catch {
    return null;
  }
}

/** Every waiting release, oldest deadline first. Used by the cron drain. */
export function readQueue(root) {
  const dir = path.join(root, STATE_DIR, "queue");
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith(".json"));
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    try {
      const doc = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
      if (doc && doc.repo && doc.tag && doc.publish_after) {
        out.push({ file: `${STATE_DIR}/queue/${name}`, ...doc });
      }
    } catch {
      // A malformed queue entry is a maintainer's problem, not a stranger's:
      // skip it rather than failing the drain for every other release.
    }
  }
  return out.sort((a, b) => (a.publish_after < b.publish_after ? -1 : 1));
}

/** The queued releases whose delay has elapsed. */
export const ripeQueueEntries = (entries, now = new Date()) =>
  entries.filter((e) => new Date(e.publish_after).getTime() <= now.getTime());

/** The digests of every artifact in a derived version document, sorted. */
export function artifactDigests(versionDoc) {
  const artifacts = versionDoc?.artifacts ?? {};
  return Object.keys(artifacts)
    .sort()
    .map((k) => `${k}:${artifacts[k].sha256 ?? ""}`);
}

/** How long a fingerprint is, in hex characters. */
export const FINGERPRINT_CHARS = 16;

/**
 * The name of one submission: what an `/approve` has to say out loud.
 *
 * Six facts, in one order, hashed: the repository, the tag, the plugin id, the
 * version, the RELEASE COMMIT, and every artifact digest this run computed. It
 * is not a secret and it authorises nothing — the permission is still GitHub's
 * answer about the commenter. It is an *identity*, and its only job is to make
 * "the thing I read" and "the thing you are about to publish" comparable by a
 * string.
 *
 * Why these six and not the issue body: the body is prose that gets edited for
 * good reasons, and a binding that refuses an approval because somebody fixed a
 * typo is a binding maintainers learn to route around. These six change only
 * when what would be published changes.
 *
 * The commit was added after it was pointed out that the design's one
 * post-approval immutability claim rested on the one field the approval did not
 * bind. `bot/lib/assets.mjs` pins every relative README image to
 * `raw.githubusercontent.com/<repo>/<commit>/…` precisely so the picture cannot
 * change after a human approved the listing — and the commit came from
 * `release.target_commitish`, which the author controls. Delete the release and
 * the tag, push a new commit whose `banner.png` is different, re-create both at
 * that commit and re-upload byte-identical assets, and repo, tag, id, version
 * and every digest were unchanged: the fingerprint matched, the hold's
 * `/approve` was still binding, and the store rendered a tree no maintainer had
 * seen. Hashing the commit is what makes that approval refuse.
 *
 * 16 hex characters — 64 bits of a SHA-256. A maintainer copies it out of a
 * comment rather than typing it, so length costs nothing, and 64 bits puts a
 * deliberate collision (rebuild a bundle until its fingerprint matches the one
 * the maintainer read) far past the effort of simply asking for a second
 * approval. Truncation is safe here for the same reason it would not be in a
 * signature: the full digests are recorded beside it in `decision.json`, and
 * this string is a label on them, not a substitute for them.
 */
export function submissionFingerprint({ repo, tag, id, version, commit, digests } = {}) {
  const canonical = [repo ?? "", tag ?? "", id ?? "", version ?? "", commit ?? "", ...(digests ?? [])].join("\n");
  return crypto.createHash("sha256").update(canonical).digest("hex").slice(0, FINGERPRINT_CHARS);
}

// ── the decision ────────────────────────────────────────────────────────────

const HOUR_MS = 3600 * 1000;
const iso = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;

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
  const add = (code, message) => reasons.push({ code, level: policyCodeDef(code).level, message });

  // 1 ── a failed check is not a policy decision.
  const errors = findings.filter((f) => f.level === "error");
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
    ? normaliseApproval({ by: queued.approved_by, at: queued.approved_at })
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
  const held = findings.filter((f) => f.level === "review");
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
  if (added.length) {
    delayReasons.push({
      code: "P_DELAY_WIDENED",
      message: `it asks for ${added.join(", ")}, which ${previous?.version ?? "the previous release"} did not`,
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
  return { by, at: iso(at), for: forWhat };
}

function finish(d) {
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
    // An approval that named something else. Recorded rather than discarded: a
    // maintainer typed a command and the registry did not honour it, and the
    // thread has to be able to say which of those two things happened.
    approval_refused: d.refused
      ? { by: d.refused.by, at: d.refused.at, for: d.refused.for ?? null }
      : null,
    /** True when the derived listing should be committed by this run. */
    publishes_now: d.outcome === "publish",
  };
}

/**
 * Every authority name this registry can describe on a store card.
 *
 * The capability half is the daemon's vocabulary (`astra-plugin-manifest`'s
 * `CAPABILITY_NAMES`); the permission half is PRODUCTION_PLAN §5.6's host-RPC
 * set. It is a list to *describe* by, not a list to reject by — see
 * `P_UNKNOWN_PERMISSION`.
 */
export const KNOWN_AUTHORITY = [
  // [capabilities]
  "tools", "tts", "stt", "ai_provider", "client", "actions", "triggers",
  "ui_contributions", "event_handlers", "dom_access",
  // [permissions] (§5.6)
  "fire_trigger", "subscribe_events", "set_variable", "get_config",
  "send_chat_message", "push_to_ui", "set_theme_contribution",
].sort();

// ── the SLA, made visible ───────────────────────────────────────────────────

/**
 * What the review queue looks like right now.
 *
 * Printed by the cron job on every run. The point is not the number; it is that
 * a breach is *loud*. The policy's own escape hatch — widen auto-publish rather
 * than let the queue rot — only gets exercised if somebody can see that the
 * queue is rotting, and a maintainer who has to go and look never does.
 *
 * @param {{number: number, title: string, created_at: string}[]} openIssues
 */
export function slaReport(openIssues, now = new Date()) {
  const items = (openIssues ?? []).map((i) => ({
    number: i.number,
    title: i.title,
    age_hours: Math.floor((now.getTime() - new Date(i.created_at).getTime()) / HOUR_MS),
  }));
  const late = items.filter((i) => i.age_hours > REVIEW_SLA_HOURS);
  const breached = items.filter((i) => i.age_hours > SLA_BREACH_HOURS);
  return {
    open: items.length,
    late: late.length,
    breached: breached.length,
    oldest_hours: items.reduce((m, i) => Math.max(m, i.age_hours), 0),
    items: items.sort((a, b) => b.age_hours - a.age_hours),
    verdict:
      breached.length > 0
        ? `${breached.length} listing(s) past ${SLA_BREACH_HOURS} h. POLICY.md §Review says what to do about that, and it is not "review harder".`
        : late.length > 0
          ? `${late.length} listing(s) past the ${REVIEW_SLA_HOURS} h SLA.`
          : "within SLA",
  };
}

// ── the comment ─────────────────────────────────────────────────────────────

const GLYPH = { error: "❌", review: "🧑‍⚖️", warn: "⚠️", pass: "✅", note: "ℹ️" };

/**
 * The policy half of the issue comment, appended to the checks' half.
 *
 * Two things it must always answer, because they are the two questions every
 * author actually has: *is it going to publish*, and *when*. A comment that
 * lists nine green checks and does not say "live in 24 hours" has answered
 * neither.
 */
export function renderPolicySection(decision, derived) {
  const id = derived?.plugin?.id ?? "";
  const version = derived?.version?.version ?? "";
  const lines = ["", "---", "", "## Publication"];

  const headline = {
    refuse: "**Not published.** A check above failed; the policy never got a say.",
    review: `**Held for a maintainer.** Nothing is wrong with \`${id} ${version}\` — the decision below is not the bot's to make. The SLA is ${REVIEW_SLA_HOURS} h, by ${decision.sla_deadline}.`,
    delay: `**Publishing itself at ${decision.publish_after}.** \`${id} ${version}\` passed every check; it waits out the publication delay and then goes live with nobody touching it.`,
    publish: `**Published.** \`${id} ${version}\` is live; no human was involved and none was needed.`,
  }[decision.outcome];
  lines.push("", headline, "");

  // A cleared hold still appears in the table below, and it must: the record of
  // what was held is the point. But its remedy ("nothing to do but wait") is
  // now false, so the approval is stated first and the remedies are suppressed.
  //
  // On the refuse path there was no hold, and claiming one was cleared is worse
  // than saying nothing. `decide()` records `approved_by` there deliberately —
  // the maintainer did type the command, and a record that omitted it could not
  // be reconciled with the thread — but rendering the two sentences back to
  // back ("a check failed, the policy never got a say" / "a maintainer cleared
  // the hold") reads to the author as the bot contradicting itself, or as the
  // approval having been lost. So the refusal gets its own line, and it says
  // what actually became of the command.
  // The line a maintainer copies, on the comment they are reading when they
  // decide. It is generated rather than described because the fingerprint in it
  // is the whole binding: an instruction that says "type /approve" cannot be
  // checked against anything later, and one that says "type this exact line"
  // can. `decision.repo` and `decision.tag` come from the run, never from the
  // issue body — that body is the thing the binding exists to stop trusting.
  if (decision.outcome === "review" && decision.fingerprint && decision.repo && decision.tag) {
    lines.push(
      "**A maintainer clears this hold with exactly this line:**",
      "",
      "```",
      `/approve ${decision.repo}@${decision.tag} ${decision.fingerprint}`,
      "```",
      "",
      `\`${decision.fingerprint}\` names this submission: the repository, the tag, \`${id} ${version}\`, ` +
      `and the ${decision.artifact_digests.length || "no"} artifact digest(s) hashed in this run. ` +
      "If the release changes before the line is typed, the approval is refused and this comment is " +
      "posted again with a new one — an approval applies to what somebody read, or to nothing.",
      "",
    );
  }

  // An approval that named something else. Stated before the table, because it
  // is the answer to "I typed the command, why is this still held".
  if (decision.approval_refused) {
    const r = decision.approval_refused;
    lines.push(
      `**@${r.by}'s \`/approve\` was refused.** It named ` +
      (r.for ? `\`${r.for}\`` : "no submission at all") +
      `, and this run is \`${decision.fingerprint ?? "not a listing"}\`. It cleared nothing, and ` +
      "it changed nothing about the outcome above: the command was typed at " +
      `${r.at}, and what it approved is not what is here.`,
      "",
    );
  }

  if (decision.approved_by && decision.outcome !== "refuse") {
    lines.push(
      `A maintainer cleared the hold: **@${decision.approved_by}**, at ${decision.approved_at}. ` +
      "Nothing was carried over from the run that raised it — every check in this comment ran " +
      "again, from scratch, against the release as it is right now.",
      "",
    );
  } else if (decision.approved_by) {
    lines.push(
      `**@${decision.approved_by}** typed \`/approve\` at ${decision.approved_at}. It was recorded ` +
      "and it changed nothing, because a failed check is not a decision an approval can clear — " +
      "nothing was held here for it to clear. Fix what the table below names and push a new " +
      "release, and a maintainer approves the hold *that* release raises: an approval is recorded " +
      "against the digests of the bytes it applied to, and these are not those bytes.",
      "",
    );
  }

  lines.push("| | code | detail |", "|---|---|---|");
  for (const r of decision.reasons) {
    lines.push(`| ${GLYPH[r.level] ?? "•"} | \`${r.code}\` | ${String(r.message).replace(/\|/g, "\\|")} |`);
  }
  lines.push("");

  const actionable = decision.reasons.filter(
    (r) => (r.level === "review" && !decision.approved_by) || r.level === "warn",
  );
  if (actionable.length) {
    const seen = new Set();
    for (const r of actionable) {
      if (seen.has(r.code)) continue;
      seen.add(r.code);
      const def = policyCodeDef(r.code);
      lines.push(`**\`${r.code}\` — ${def.title}.** ${def.remedy}`, "");
    }
  }

  if (decision.outcome === "delay") {
    lines.push(
      `<sub>The delay is ${decision.queue_entry?.delay_hours ?? DELAY_HOURS} h and the waiting release is \`${decision.queue_entry ? queueFile(id, version) : "queue/"}\` in this repository — visible, auditable, and cancellable by deleting the file. ` +
        "If you did not publish this release, say so on this issue now: the delay exists for exactly that, " +
        "and it is the only defence this registry has against a compromised author account (PRODUCTION_PLAN §5.5).</sub>",
      "",
    );
  }
  lines.push(`<sub>Why this outcome and not another: \`docs/POLICY.md\`. The rules are ${HIGH_RISK.length} high-risk names, ${REVIEW_SLA_HOURS} h for the three events that need a person, and ${DELAY_HOURS} h (${TRUSTED_DELAY_HOURS} h after ${CLEAN_RELEASES_FOR_TRUSTED} clean releases) for everything else that is not routine.</sub>`);
  return lines.join("\n");
}
