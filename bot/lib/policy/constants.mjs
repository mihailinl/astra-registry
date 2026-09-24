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

/**
 * `stage` is `policy` for every entry here, and the contract says so rather
 * than this file: FLOW-11 requires a stage with every reason code and fixes it
 * at `policy` for `R_*` and `P_*`, which is all nineteen of these. It is
 * written out per entry rather than defaulted by the emitter, because FLOW-13's
 * table is one entry per code with six members each, and a member a generator
 * supplies when the table omits it is a member that silently keeps the old
 * value after somebody adds a twentieth entry with a different stage.
 *
 * `fix` is FLOW-13's closed list — `recheck`, `new_tag`, `moderator`,
 * `registry`, `none` — and the rule that decides it is stated once, in
 * `bot/lib/codes.mjs`'s header. Here it collapses to four answers: a `review`
 * waits on a person (`moderator`); `P_REFUSED` points at findings the author
 * clears and then re-runs against the same tag (`recheck`);
 * `P_OPERATOR_DENIED` is lifted only by the registry's operator removing the
 * deny record (`registry`); and every other `P_*` reports something that has
 * already happened, which nothing clears (`none`).
 *
 * @typedef {{level: string, title: string, remedy: string, stage: string, fix: string}} PolicyCodeDef
 */

/** @type {Record<string, PolicyCodeDef>} */
export const POLICY_CODES = {
  P_PUBLISHED: {
    level: "pass", stage: "policy", fix: "none",
    title: "Published, with nobody in the loop",
    remedy: "Nothing to do. This is what a routine release is supposed to look like.",
  },
  P_REFUSED: {
    level: "error", stage: "policy", fix: "recheck",
    title: "Not published, because a check failed",
    remedy: "Fix the blocking findings above and comment `/recheck`. The policy did not reject this; a check did.",
  },
  // Contract 2.4.0 (registry plan TRUST-33). A deny record is the operator's
  // stop, outside the service and the moderators; until 2.4.0 it was reported
  // as `P_REFUSED`, whose `recheck` told the author a Recheck could clear it.
  P_OPERATOR_DENIED: {
    level: "error", stage: "policy", fix: "registry",
    title: "Not published: the registry's operator withheld this exact build",
    remedy:
      "An operator deny record on `main` names this fingerprint (TRUST-33). No Recheck, approval or " +
      "moderator decision clears it; only the operator removing the record does. A new tag is a new " +
      "fingerprint and is judged afresh.",
  },
  // The five binding refusals the bot emits (contract B.7; FLOW-13's `fix` per
  // contract 2.5.0, lane S6). They keep their BOUND_WORLD_CODES level below;
  // this entry is what `policyCodeDef` answers first and what
  // tools/gen-codes-table.mjs publishes as their FLOW-13 rows. The two
  // panel-only details of B_BINDING_UNUSABLE are not here: the bot never
  // emits them (BOT-89), and their rows are the service's to render. (Named
  // without quotes on purpose: tools/selftest/scope9.mjs reads a quoted code
  // name in this directory as a code the bot carries.)
  B_UNBOUND: {
    level: "error", stage: "ownership", fix: "new_tag",
    title: "No binding line where the registry needs one",
    remedy:
      "From cutover, a first listing and a frozen listing's next release need an `astra-binding:` line in " +
      "`.well-known/astra-plugin-owner` at the tagged commit (ID-25). Mint a token in the Astra plugins panel, " +
      "commit its line and push a new tag: the line is read at the attested commit, so this tag cannot change.",
  },
  B_BINDING_MALFORMED: {
    level: "error", stage: "ownership", fix: "new_tag",
    title: "The binding file is not one well-formed binding line",
    remedy:
      "`.well-known/astra-plugin-owner` must hold exactly one `astra-binding: <token>` line (ID-24). Fix the file " +
      "and push a new tag: the line is read at the attested commit.",
  },
  B_BINDING_UNUSABLE: {
    level: "error", stage: "ownership", fix: "new_tag",
    title: "The binding token on the tagged commit cannot bind this release",
    remedy:
      "The token in `.well-known/astra-plugin-owner` at the tagged commit cannot bind this repository (ID-9); " +
      "the Astra plugins panel tells the token's owner why. Mint a fresh token there if you need one, commit its " +
      "line and push a new tag.",
  },
  B_OWNER_CHANGED: {
    level: "error", stage: "ownership", fix: "moderator",
    title: "The repository's owner changed since it was bound",
    remedy:
      "The owner the build attestation names differs from the one this listing's identity record carries " +
      "(ID-41). A moderator decides what happens next; a new tag or a Recheck does not clear it.",
  },
  B_REPOSITORY_RECYCLED: {
    level: "error", stage: "ownership", fix: "moderator",
    title: "The repository was re-created under this name by another owner",
    remedy:
      "This refusal is permanent for the repository's recorded identity (ID-41): no Recheck, new tag or approval " +
      "clears it. Only a moderator's identity reset (`M_IDENTITY_RESET`) does, after which the next release is " +
      "reviewed as a first binding.",
  },
  // The bound world's two holds (contract B.7; MIG-10; ID-41 row 6). They moved
  // here from BOUND_WORLD_CODES below on 2026-09-24 with their FLOW-13 rows:
  // B.7 makes every `R_*` a hold until approved (DEC-6), so `moderator`, and
  // FLOW-11 reports every `R_*` at stage `policy`. Until then `decide()` folded
  // them into `R_CHECK_HELD` in the legacy comment, and the published table
  // owed them a title.
  R_FIRST_BINDING: {
    level: "review", stage: "policy", fix: "moderator",
    title: "First binding line on a published listing — a moderator approves it once",
    remedy:
      "This listing was published before it had an identity record, and this release is the first to carry an " +
      "`astra-binding:` line (MIG-10). A moderator approves it once; the approval then waits the operator's " +
      "objection window like every approval (DEC-6). Once a release under this binding is published, later " +
      "releases are not held for this again.",
  },
  R_BINDING_CHANGED: {
    level: "review", stage: "policy", fix: "moderator",
    title: "The binding token changed since this listing was bound",
    remedy:
      "The `astra-binding:` line at the tagged commit carries a different token from the one this listing's " +
      "identity record holds (ID-41 row 6). The account that held the previous binding is told, and a " +
      "moderator's approval publishes it only once the author objection window has passed since that account " +
      "was told, or since its binding was revoked (ID-60; ID-61).",
  },
  R_FIRST_LISTING: {
    level: "review", stage: "policy", fix: "moderator",
    title: "First listing — a person reads it, once, ever",
    remedy:
      "Nothing to do but wait. This is one of exactly three events that block on a human, and it " +
      "happens once per plugin: every later release from the same repository is zero-touch.",
  },
  R_IDENTITY_CHANGED: {
    level: "review", stage: "policy", fix: "moderator",
    title: "The repository this plugin is listed from changed",
    remedy:
      "Say in the issue what happened — a rename, a transfer, a fork taking over maintenance. " +
      "Every installed copy carries a pin to the old repository, so this is an author change " +
      "until somebody says otherwise.",
  },
  R_NEW_HIGH_RISK: {
    level: "review", stage: "policy", fix: "moderator",
    title: "The release asks for a high-risk permission it did not have before",
    remedy:
      "Say in the issue what the new permission is for, in one sentence a user would accept. " +
      "The four that block are `client`, `dom_access`, `send_chat_message` and " +
      "`set_theme_contribution`; each reaches outside the plugin's own surface.",
  },
  P_APPROVED: {
    level: "pass", stage: "policy", fix: "none",
    title: "A maintainer cleared the hold",
    remedy:
      "Nothing to do. The hold is gone; every check above was re-run from scratch in this run, " +
      "against the release as it is today, and what publishes is what this run verified.",
  },
  P_APPROVAL_STALE: {
    level: "review", stage: "policy", fix: "moderator",
    title: "The approval named a different submission from this one",
    remedy:
      "Nothing published and nothing was lost. An `/approve` carries the fingerprint printed in " +
      "the comment it answers, and this run's fingerprint is different — the repository, the tag, " +
      "the version or the release assets changed after that comment was written. Read the table " +
      "above as it stands now and, if it is still a yes, copy the `/approve` line out of **this** " +
      "comment. An approval has to be about something a person actually read.",
  },
  R_CHECK_HELD: {
    level: "review", stage: "policy", fix: "moderator",
    title: "A check handed the decision to a person",
    remedy:
      "Not a rejection and not one of the three policy events — a near-miss name or a display-name " +
      "collision that the bot is not entitled to rule on. Same 48-hour SLA.",
  },
  P_DELAY_WAIVED_BY_COMMAND: {
    level: "note", stage: "policy", fix: "none",
    title: "A maintainer published this without waiting",
    remedy:
      "Nothing to do, and the shortened window is on the record. Somebody with write access to this " +
      "registry typed `/publish` against these exact bytes, which is the same act as editing " +
      "`publish_after` by hand and needs the same access — but every check in the comment above it ran " +
      "again from scratch first, which a hand-written listing would not have.",
  },
  P_FIRST_LISTING_APPROVED: {
    level: "note", stage: "policy", fix: "none",
    title: "Approved, and published without waiting",
    remedy:
      "Nothing to do. A first listing has no installed copies, so the publication delay would have " +
      "protected nobody who had not already chosen to install it — and a person read this submission, " +
      "which is the check the delay stands in for. The delay still applies to every later release from " +
      "this repository, where existing installs follow an update whether or not anybody looked.",
  },
  P_DELAY_HIGH_RISK: {
    level: "note", stage: "policy", fix: "none",
    title: "Held for the publication delay because the plugin holds a high-risk permission",
    remedy:
      "Nothing to do. Every auto-published release of a plugin holding any high-risk permission " +
      "waits, whether or not this release changed anything — §5.5's realistic takeover case is a " +
      "malicious version with *identical* permissions, and a delay that only fired on changes " +
      "would never fire on it.",
  },
  P_DELAY_WIDENED: {
    level: "note", stage: "policy", fix: "none",
    title: "Held for the publication delay because the permission set grew",
    remedy:
      "Nothing to do. A widening inside the non-high-risk set publishes itself after the delay; " +
      "the delay exists so the author hears about it first.",
  },
  P_DELAY_BYTES_CHANGED: {
    level: "warn", stage: "policy", fix: "none",
    title: "The release assets changed during the delay, so the clock restarted",
    remedy:
      "Do not overwrite a published release asset. The delay is a delay on *these bytes*; " +
      "replacing them mid-window starts it again, which is the only thing that stops a swap " +
      "timed for the end of the window.",
  },
  P_DELAY_WAITING: {
    level: "note", stage: "policy", fix: "none",
    title: "Waiting out the publication delay",
    remedy: "Nothing to do. It publishes itself at the time stated above without anybody touching it.",
  },
  P_DELAY_ELAPSED: {
    level: "pass", stage: "policy", fix: "none",
    title: "The publication delay has elapsed",
    remedy: "Nothing to do. Every check was re-run from scratch just now, against the bytes as they are today.",
  },
  P_DELAY_BROUGHT_FORWARD: {
    level: "note", stage: "policy", fix: "none",
    title: "A maintainer waived part of the publication delay",
    remedy:
      "Nothing to do, but the shortened window is on the record: somebody with write access to this " +
      "registry edited `publish_after` in the queue entry, and the commit that did it says who and when. " +
      "Every check still ran from scratch against today's bytes.",
  },
  P_UNKNOWN_PERMISSION: {
    level: "warn", stage: "policy", fix: "none",
    title: "The manifest declares a permission this registry has no name for",
    remedy:
      "Check the spelling against POLICY.md's permission table. An unknown key grants nothing — " +
      "the daemon default-denies — so it is reported rather than blocked, but a permission nobody " +
      "can name is also a permission no consent sheet can describe.",
  },
  P_TRUSTED_AUTHOR: {
    level: "note", stage: "policy", fix: "none",
    title: "Shorter delay: this author has a clean release history here",
    remedy: "Nothing to do.",
  },
  P_SLA: {
    level: "note", stage: "policy", fix: "none",
    title: "What happens next, and by when",
    remedy: "See docs/POLICY.md. If this passes the stated deadline, say so on this issue — a missed SLA is a bug in the policy, not in your release.",
  },

  // ── the decisions a moderator or an author makes through the panel ──────────
  //
  // Contract B.7's `M_*` and `A_*` codes that end or clear a SUBMISSION, and
  // the author's yank, each of which the bot writes into a decision record's
  // `reasons` (BOT-30; BOT-34; DEC-7) and the panel shows with FLOW-13's row.
  // Stage `policy`, which is what `bot/lib/service-decide.mjs`'s `stageOf`
  // reports for them in a result's reason (FLOW-11 fixes a stage only for `R_*`
  // and `P_*`, and the bot falls back to `policy`), so the row the panel reads
  // and the reason the bot reports name one stage. Each `fix` is the
  // clause that says what clears it: an approval blocks nothing (DEC-6); a
  // rejection is reopened only by a reversed appeal, a moderator's decision
  // (FLOW-18; MOD-33); an appeal's outcome is final (MOD-32); a stop or a
  // withdrawal ends its (`repository_id`, tag) for good, so only a new tag is
  // judged again (FLOW-26; MOD-10 refuses to lift a stop); and a yank "cannot
  // be undone by anyone" (FLOW-79; B.3). `A_BINDING_REVOKE`,
  // `A_REMOVAL_REQUEST` and §7.2's listing actions follow this block, because
  // the contract states no `fix` for them.
  M_APPROVE: {
    level: "pass", stage: "policy", fix: "none",
    title: "A moderator approved this submission",
    remedy:
      "Nothing to do. An approval clears holds and nothing else: every check runs again in the run that acts on " +
      "it, and it never shortens a publication delay, a stop or a pending notice (DEC-6).",
  },
  M_REJECT: {
    level: "error", stage: "policy", fix: "moderator",
    title: "A moderator rejected this submission",
    remedy:
      "A Recheck does not reopen a rejection (FLOW-18). You can appeal it from the Astra plugins panel; if a " +
      "moderator reverses the rejection on appeal, exactly one Recheck of this submission is opened (MOD-33).",
  },
  M_APPEAL: {
    level: "note", stage: "policy", fix: "none",
    title: "An appeal was decided",
    remedy:
      "The outcome, `stands` or `reversed`, is recorded with the moderator's public reason and never the " +
      "appeal's own text (MOD-32; MOD-33). A `reversed` appeal becomes a new decision; the one appealed stays " +
      "in the log.",
  },
  A_STOP: {
    level: "error", stage: "policy", fix: "new_tag",
    title: "Stopped by its author",
    remedy:
      "A stop was confirmed from this submission's notice link (TRUST-34), so none of its fingerprints " +
      "publishes. A stop cannot be lifted, and this tag cannot be submitted again (FLOW-26): publish the " +
      "release under a new tag.",
  },
  A_WITHDRAW: {
    level: "error", stage: "policy", fix: "new_tag",
    title: "Withdrawn before it was checked",
    remedy:
      "The submission was withdrawn while it was `received` (FLOW-22), so nothing was checked or published. " +
      "This tag cannot be submitted again (FLOW-26): publish the release under a new tag.",
  },
  A_YANK: {
    level: "note", stage: "policy", fix: "none",
    title: "Yanked at its author's own request",
    remedy:
      "The listing's bound account yanked these versions from the Astra plugins panel (FLOW-79). A yank cannot " +
      "be undone by anyone, and installed copies keep running. A new version is listed as usual.",
  },

  // ── the acts on a listing or a binding, which the contract gives no fix ─────
  //
  // §7.2's listing actions, and the author's two acts on a listing or a
  // binding (B.7's `A_*`). The panel shows each with FLOW-13's row (FLOW-10).
  // Until 2026-09-24 they had no row, so the panel could title none of them.
  // The contract gives none of them a `fix`. Each `fix` and both `A_*` levels
  // are the coordinator's decision under the owner's standing grant
  // (2026-09-23), on lane S10's proposals. Lane S15 chose the `M_*` levels.
  // tools/gen-codes-table.mjs holds all of them in `DECIDED`:
  //   * `none` where nothing is left to clear: an author's own acts; a yank,
  //     which nothing undoes (B.3; MOD-10); the reversals and the reset; and a
  //     binding revocation, whose next release answers `B_BINDING_UNUSABLE`
  //     with that code's own `fix` (§7.2).
  //   * `moderator` for a delist, a deprecation and a revocation. The author
  //     may appeal each one (MOD-31; MOD-32), and only a moderator's `M_RELIST`
  //     or `M_UNREVOKE` undoes it (§7.2).
  // A relist after an author's own removal is a moderator's act. The author
  // asks for it through the panel's report page (MOD-54), not through
  // `A_REMOVAL_REQUEST`, whose `fix` is therefore `none`.
  A_BINDING_REVOKE: {
    level: "note", stage: "policy", fix: "none",
    title: "Binding revoked by its bound account",
    remedy:
      "The listing's bound account revoked its binding token from the Astra plugins panel (ID-17). Nothing " +
      "needs clearing. From the next verdict a release still carrying the old line is refused " +
      "`B_BINDING_UNUSABLE`, and one carrying a fresh token's line is held for a moderator as a changed " +
      "binding (`R_BINDING_CHANGED`).",
  },
  A_REMOVAL_REQUEST: {
    level: "note", stage: "policy", fix: "none",
    title: "Removal requested by its author",
    remedy:
      "The listing's author asked from the Astra plugins panel for it to be removed (FLOW-28). From the bound " +
      "account it is delisted at once: it leaves the catalogue and gets no updates, and installed copies are " +
      "not removed. For a listing with no bound account the request is held, and a moderator decides it " +
      "(MOD-9). Only a moderator lists a plugin again; to ask for that, send a report from the panel's report page.",
  },
  M_YANK: {
    level: "error", stage: "policy", fix: "none",
    title: "A moderator yanked these versions",
    remedy:
      "These versions leave the catalogue and are no longer offered, and installed copies keep running (§7.2). " +
      "A yank cannot be undone by anyone (B.3): an appeal is recorded, but no decision brings these versions " +
      "back (MOD-10). A later release is judged like any other.",
  },
  M_DELIST: {
    level: "error", stage: "policy", fix: "moderator",
    title: "A moderator delisted this plugin",
    remedy:
      "The plugin leaves the catalogue and gets no updates, and installed copies keep running (§7.2). A new " +
      "release does not list it again. You can appeal from the Astra plugins panel (MOD-31); only a " +
      "moderator's relist (`M_RELIST`) brings it back.",
  },
  M_RELIST: {
    level: "note", stage: "policy", fix: "none",
    title: "A moderator listed this plugin again",
    remedy:
      "A moderator lifted the plugin's delisting (§7.2). Like every reversal, it was held and confirmed by the " +
      "registry's operator before it applied (MOD-9). The plugin is back in the catalogue and gets updates " +
      "again. Nothing to do.",
  },
  M_DEPRECATE: {
    level: "warn", stage: "policy", fix: "moderator",
    title: "A moderator deprecated these versions",
    remedy:
      "A moderator published an advisory with action `warn` for these versions (§7.2). They stay listed and " +
      "installable: Astra badges them and tells the user, and blocks and stops nothing. The advisory stands " +
      "until a moderator lifts it (`M_UNREVOKE`). You can appeal from the Astra plugins panel (MOD-31).",
  },
  M_REVOKE: {
    level: "error", stage: "policy", fix: "moderator",
    title: "A moderator revoked these versions",
    remedy:
      "A moderator published an advisory for these versions (§7.2). With action `block_install`, Astra refuses " +
      "new installs and updates and leaves a running copy alone; with `disable`, it also stops installed " +
      "copies, and they do not start again. The advisory stands until a moderator lifts it (`M_UNREVOKE`). " +
      "You can appeal from the Astra plugins panel (MOD-31).",
  },
  M_UNREVOKE: {
    level: "note", stage: "policy", fix: "none",
    title: "A moderator lifted an advisory",
    remedy:
      "A moderator deleted the advisory that deprecated or revoked these versions (§7.2). Like every reversal, " +
      "it was held and confirmed by the registry's operator before it applied (MOD-9). Its effect lifts on each " +
      "machine at the withdrawal list's next higher serial. Nothing to do.",
  },
  M_BINDING_REVOKE: {
    level: "warn", stage: "policy", fix: "none",
    title: "A moderator revoked this repository's binding token",
    remedy:
      "A moderator revoked the binding token this repository is bound with (ID-17). Listed versions are not " +
      "touched. Nothing clears this code: the next release is refused `B_BINDING_UNUSABLE` (§7.2), and that " +
      "code says what clears it.",
  },
  M_IDENTITY_RESET: {
    level: "note", stage: "policy", fix: "none",
    title: "A moderator reset this listing's recorded identity",
    remedy:
      "A moderator voided every identity this plugin id had recorded, and deleted its identity record where it " +
      "had one (§7.2; ID-40). Like every reversal, it was held and confirmed by the registry's operator before " +
      "it applied (MOD-9). It clears `B_REPOSITORY_RECYCLED` for the identities it voided, and nothing clears " +
      "it. The listing is now frozen: its next release needs a binding line, and is held for a moderator as a " +
      "first binding.",
  },
};

// ── the bound world's codes, declared for their LEVEL and nothing else ──────
//
// Registry plan B-T2.3 coins these; B-T3.3b (reg.61a) writes their
// author-facing text into `docs/POLICY.md` in one edit. They are declared here
// FIRST, ahead of both, because three sibling tasks each need to ask "what
// kind of answer is this" and the alternative is three hand-written lists of
// codes — each correct on the day it is written, each silently wrong the day a
// fourth task coins a fifth code.
//
// So: the rules downstream key on the LEVEL. `decide()`'s `add()` already
// reads `policyCodeDef(code).level`, and B-T3.3c's no-record rule is
// `reasons.some((r) => r.level === "wait")` rather than a list of the waits
// that existed when it was written.
//
// **Not in `POLICY_CODES`, deliberately.** `bot/tests/policy.test.mjs` holds
// every key of that object to being explained in `docs/POLICY.md`, and that
// document's bound-world text is reg.61a's single edit. Declaring a level here
// commits to no author-facing sentence and pre-empts none.
//
// **Not exported, also deliberately.** `bot/lib/policy.mjs` re-exports this
// module with `export *`, and `tools/selftest/repo-rules.mjs` holds that
// barrel to exactly the 26 names it had before the split. A new export is a
// change to a surface ten files import; a new level behind `policyCodeDef` is
// not.
//
// ── the level `wait`, and why it is not `error` ────────────────────────────
//
//   wait    this run could not get an answer, so it has none. NOTHING IS
//           RECORDED (FLOW-72) and nothing is posted; the run stops and asks
//           again. The distinction from `error` is the whole point: an error
//           is a fact about the submission and is written down, and a wait is
//           the absence of a fact. A rate-limited read recorded as a refusal
//           cannot be un-written.
//
/** @type {Record<string, {level: string, service_path_only?: boolean}>} */
const BOUND_WORLD_CODES = {
  // B.7's waits. `W_REGISTRY_UNACKNOWLEDGED` is the service's alone — the bot
  // never emits it — and is declared so that a rule which meets one behaves
  // rather than falling through to the undeclared-code default.
  W_GITHUB_RATE_LIMITED: { level: "wait" },
  W_SERVICE_UNREACHABLE: { level: "wait" },
  W_ELIGIBILITY_UNREADABLE: { level: "wait" },
  W_OPERATOR_WINDOW: { level: "wait" },
  W_REGISTRY_UNACKNOWLEDGED: { level: "wait" },

  // FLOW-72 reclassifies these five ON THE SERVICE PATH ONLY, and the
  // qualifier is load-bearing in both directions. On the legacy path they are
  // what they have always been: errors, refused and recorded, answered by a
  // `/recheck`. On the service path there is no issue thread to answer and the
  // same condition means "this run could not check", which must not become a
  // recorded refusal of somebody's release.
  E_ATTESTATION_UNCHECKED: { level: "wait", service_path_only: true },
  E_TRUST_UNPROVISIONED: { level: "wait", service_path_only: true },
  E_PROBE_INPUT: { level: "wait", service_path_only: true },
  E_PROBE_UNAVAILABLE: { level: "wait", service_path_only: true },
  E_DERIVED_LISTING_INVALID: { level: "wait", service_path_only: true },

  // The binding refusals. `B_REPOSITORY_RECYCLED` is terminal (ID-41 row 1);
  // the rest are errors an author can answer.
  B_UNBOUND: { level: "error" },
  B_BINDING_MALFORMED: { level: "error" },
  B_BINDING_UNUSABLE: { level: "error" },
  B_BINDING_INVALID: { level: "error" },
  B_ACCOUNT_INELIGIBLE: { level: "error" },
  B_OWNER_CHANGED: { level: "error" },
  B_REPOSITORY_RECYCLED: { level: "error" },

  // The bound world's two holds, `R_FIRST_BINDING` and `R_BINDING_CHANGED`,
  // are documented `POLICY_CODES` keys since 2026-09-24, as
  // `R_IDENTITY_CHANGED` always was, so they are not declared here: a second
  // declaration is a second answer to what their level is.
};

/**
 * What kind of answer a code is.
 *
 * @param {string} code
 * @param {{path?: "legacy"|"service"}} [opts] which path is asking. **It
 *   defaults to `legacy`**, which is the conservative direction for the five
 *   `E_*` above: a caller that forgets the argument records a refusal, as this
 *   repository has always done, rather than silently waiting for ever on a
 *   release nobody will look at again. `decide()` passes it explicitly and
 *   `bot/tests/policy.test.mjs` fails if it stops.
 */
export function policyCodeDef(code, opts = {}) {
  const documented = POLICY_CODES[code];
  if (documented) return documented;
  const bound = BOUND_WORLD_CODES[code];
  if (bound && (!bound.service_path_only || opts.path === "service")) {
    return {
      level: bound.level,
      title: `${code}`,
      // Deliberately not an author-facing sentence. reg.61a (B-T3.3b) writes
      // those, once, into docs/POLICY.md; a placeholder here would be a second
      // one, and the second one is the one that ships.
      remedy: "See docs/POLICY.md.",
    };
  }
  if (bound) {
    // Declared, but this path is not the one that reclassifies it. Fall
    // through to `codes.mjs`'s own level by way of the default below, which is
    // `error` — which is exactly what these five are on the legacy path.
    return { level: "error", title: `${code}`, remedy: "See docs/BOT-CHECKS.md." };
  }
  return {
    level: "error",
    title: `undeclared policy code ${code}`,
    remedy: "This is a bug in the registry bot: the code is not in bot/lib/policy.mjs.",
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
