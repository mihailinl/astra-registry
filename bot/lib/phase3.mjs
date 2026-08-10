// The checks this bot does NOT do yet, named out loud.
//
// Every one of these is printed on every run, as a skipped row. That is the
// point. A checklist that shows only what passed reads as a clean bill of
// health, and someone eventually cites "the bot approved it" for a property the
// bot never looked at. So the report always ends with the list of things nobody
// has verified.
//
// Each entry keeps the error code Phase 3 will use, so the vocabulary does not
// change when the implementation lands (PRODUCTION_PLAN task 3.3).

export const PHASE_3_CHECKS = [
  {
    code: "E_ATTESTATION_MISSING",
    name: "build provenance",
    why: "`gh attestation verify --repo <o>/<r> --signer-workflow …` — proves the bytes came from a GitHub Actions run of a named workflow at a named commit. Phase 3.3. Until it exists, NOTHING here says who produced this artifact.",
  },
  {
    code: "E_WORKFLOW_NOT_ALLOWED",
    name: "reusable-workflow allowlist",
    why: "the resolved release-workflow SHA must be one root-signed trust.json allows. Phase 3.1 + 3.3.",
  },
  {
    code: "E_OWNERSHIP_UNPROVEN",
    name: "repository ownership",
    why: "GET /repos/{o}/{r}/collaborators/{u}/permission requiring admin or maintain. Phase 3.3.",
  },
  {
    code: "E_IDENTITY_CHANGED",
    name: "identity continuity",
    why: "a listing that changes its source repo is a different author and takes human review. Phase 3.5.",
  },
  {
    code: "E_PERMISSIONS_WIDENED",
    name: "permission ceiling and consent delta",
    why: "[permissions] does not exist in the manifest yet; the consent sheet is Phase 4.",
  },
  {
    code: "E_HOST_RPC_UNDECLARED",
    name: "declared-vs-called host RPC scan",
    why: "a string scan of the bundle for host RPCs the manifest does not declare. Phase 3.3, and POLICY.md is explicit that it catches accidents, not a determined attacker.",
  },
  {
    code: "E_REVOKED",
    name: "revocation list",
    why: "signed revocations.json does not exist until Phase 3.9.",
  },
  {
    code: "E_INDEX_UNSIGNED",
    name: "index signature",
    why: "the index this repo publishes is UNSIGNED in Phase 2. The daemon trusts it over HTTPS and nothing more. Phase 3.2 signs it with the index key.",
  },
];
