// The checks `bot/run-checks.mjs` does NOT do, named out loud.
//
// Every one of these is printed on every run, as a skipped row. That is the
// point. A checklist that shows only what passed reads as a clean bill of
// health, and someone eventually cites "the bot approved it" for a property the
// bot never looked at. So the report always ends with the list of things nobody
// has verified.
//
// ── read this before adding or removing a row ──────────────────────────────
//
// There are two entry points now and they answer different questions:
//
//   `bot/ingest.mjs`     — a RELEASE. Two typed facts, everything else read out
//                          of the attested bundle. It proves ownership, verifies
//                          the attestation against a root-signed
//                          reusable-workflow allowlist, and writes the listing
//                          itself. This is the trust boundary.
//
//   `bot/run-checks.mjs` — a HAND-EDITED listing in a pull request. It reads
//                          files somebody wrote and asks whether they describe
//                          the artifacts they point at. There is no attestation
//                          step here because there is no submitter to attribute
//                          one to: a pull request that edits `plugins/**` is
//                          reviewed by a maintainer, and the maintainer is the
//                          control.
//
// So the rows below are the ones missing from the PULL-REQUEST path, plus the
// ones missing from both. Each keeps the code the implementation uses, so the
// vocabulary in `bot/lib/codes.mjs` and `docs/BOT-CHECKS.md` is the only one
// anybody has to learn.

export const PHASE_3_CHECKS = [
  {
    code: "E_ATTESTATION_MISSING",
    name: "build provenance",
    why: "landed in bot/ingest.mjs (task 3.3), and deliberately NOT here: this path judges a hand-edited listing, whose review is a human reading a pull request. Nothing on THIS report says who produced an artifact.",
  },
  {
    code: "E_WORKFLOW_NOT_ALLOWED",
    name: "reusable-workflow allowlist",
    why: "landed in bot/ingest.mjs, against the root-signed trust.json. Not checked on the pull-request path.",
  },
  {
    code: "E_OWNERSHIP_UNPROVEN",
    name: "repository ownership",
    why: "landed in bot/ingest.mjs (collaborator permission, .well-known fallback, release author). On the pull-request path the reviewer is the check.",
  },
  {
    code: "E_HOST_RPC_UNDECLARED",
    name: "declared-vs-called host RPC scan",
    why: "landed in bot/ingest.mjs. docs/BOT-CHECKS.md states plainly that it is a heuristic which catches accidents, not a determined attacker.",
  },
  {
    code: "E_PERMISSIONS_WIDENED",
    name: "permission ceiling and consent delta",
    why: "the DELTA half landed in bot/lib/policy.mjs (task 3.5), on the release path only: a release asking for authority the newest listed version did not have is held (R_NEW_HIGH_RISK) or delayed (P_DELAY_WIDENED). The CEILING half is still implemented nowhere — nothing caps what a tier may request, and the consent sheet is Phase 4. So is the ENFORCEMENT half: no daemon check reads granted_permissions, PRODUCTION_PLAN §5.6's require_permission is Phase 4.1 and does not exist, so a plugin that declares nothing and calls SetThemeContribution or SendChatMessage anyway is not blocked on the user's machine — the delta half above only measures what an author chose to write down. Neither half runs on this path either: a hand-edited listing is diffed by its reviewer.",
  },
  {
    code: "E_REVOKED",
    name: "revocation list",
    why: "still not checked by either bot path, and note that the missing piece is no longer the document: task 3.9 landed a signed registry/v1/revocations.json and the daemon enforces it at five points. What nobody does is intersect a CANDIDATE artifact's digest with that list before listing it, so the registry can publish a version it has itself already withdrawn and the daemon is the only thing that stops it.",
  },
  // `E_INDEX_UNSIGNED` was here, and 3.2 landed it: registry/v1/index.json is a
  // `{signed, signatures}` envelope, .github/workflows/build-index.yml signs the
  // deploy candidate with the index key held in the `publish` environment, and
  // the daemon verifies it against the index keys a root-signed trust.json
  // delegates to. The row is deleted rather than left saying "done" — a list of
  // things nobody has checked stops being read the moment it also contains
  // things somebody has. `E_IDENTITY_CHANGED` left the same way in 3.3: it is
  // now `R_IDENTITY_CHANGED`, and bot/ingest.mjs holds such a release for a
  // maintainer rather than listing it.
];
