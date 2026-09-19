// The numbers and vocabularies `docs/POLICY.md` publishes.
//
// Split out of `bot/lib/policy.mjs` on 2026-09-19. That file was 1199 lines and
// fifteen planned tasks touched it, which made it the one place a fleet of
// agents would queue behind. It is the barrel now; this holds the values.
//
// Everything here is read by `docs/POLICY.md`'s own test — the document quotes
// these numbers and `bot/tests/policy.test.mjs` fails when the two disagree.

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
  P_DELAY_WAIVED_BY_COMMAND: {
    level: "note",
    title: "A maintainer published this without waiting",
    remedy:
      "Nothing to do, and the shortened window is on the record. Somebody with write access to this " +
      "registry typed `/publish` against these exact bytes, which is the same act as editing " +
      "`publish_after` by hand and needs the same access — but every check in the comment above it ran " +
      "again from scratch first, which a hand-written listing would not have.",
  },
  P_FIRST_LISTING_APPROVED: {
    level: "note",
    title: "Approved, and published without waiting",
    remedy:
      "Nothing to do. A first listing has no installed copies, so the publication delay would have " +
      "protected nobody who had not already chosen to install it — and a person read this submission, " +
      "which is the check the delay stands in for. The delay still applies to every later release from " +
      "this repository, where existing installs follow an update whether or not anybody looked.",
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
