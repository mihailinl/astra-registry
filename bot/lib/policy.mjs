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

// ── where the rest of this module went ─────────────────────────────────────
//
// This file was 1199 lines, and fifteen tasks across three rollout steps were
// planned against it. That made it the one place a fleet of agents would queue:
// nine lanes finish, one lane holds the wave. Split 2026-09-19 along the
// section boundaries it already had, with this file kept as the barrel so that
// not one of its ten importers had to change.
//
//   policy/constants.mjs     the numbers and vocabularies POLICY.md publishes
//   policy/release.mjs       what a release asks for, and the bytes it is made of
//   policy/track-record.mjs  the author's history, read against the withdrawal list
//   policy/queue.mjs         one file per waiting release
//   policy/decision.mjs      the spine: publish now, wait, or wait for a person
//   policy/sla.mjs           the review queue, said out loud
//   policy/comment.mjs       the section an author reads
//
// A re-export is not a smaller file, it is a smaller EDIT: a change to the
// delay rules touches decision.mjs and nothing else, and two agents can hold
// two of these at once. The barrel changes only when an export is added or
// removed, which is the one event both of them should notice.

export * from "./policy/constants.mjs";
export * from "./policy/release.mjs";
export * from "./policy/track-record.mjs";
export * from "./policy/queue.mjs";
export * from "./policy/decision.mjs";
export * from "./policy/sla.mjs";
export * from "./policy/comment.mjs";
