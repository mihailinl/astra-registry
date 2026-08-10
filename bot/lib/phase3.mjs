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
  // `E_INDEX_UNSIGNED` was here, and 3.2 landed it: registry/v1/index.json is a
  // `{signed, signatures}` envelope, .github/workflows/build-index.yml signs the
  // deploy candidate with the index key held in the `publish` environment, and
  // the daemon verifies it against the index keys a root-signed trust.json
  // delegates to. The row is deleted rather than left saying "done" — a list of
  // things nobody has checked stops being read the moment it also contains
  // things somebody has.
];
