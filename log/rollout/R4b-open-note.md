# R4b opens (contract 5.6.0, OD-26)

R4b opens on 2026-10-17 under contract 5.6.0's ROLL-26: MIG-2's date is fixed
(`policy/binding-deadline.json`, 2026-12-15T06:00:00Z) and the panel path has
been walked end to end. ROLL-25's and ROLL-59's walks are walked after
cutover and recorded as each happens; none of them holds R4b, cutover or
R6's gate-in (OD-26).

The panel path, walked:

- 2026-10-14: a first panel submission published, signed and served
  (registry `68053da`), installed in the test client, then delisted through
  moderation and served without it (registry `9512b07`, signed serial 59).
- 2026-10-16: ROLL-32's third-party walk from a test organisation: a first
  listing to served, `unreviewed`, with no moderator act (registry
  `4373734`), and `B_BINDING_UNUSABLE` for a token minted for another
  repository. The run and submission ids are in astra-plugins-ops
  `notes/state.md` (ops.43).
- 2026-10-15: a real author's first binding, held for a moderator and
  approved, published through the service.

MOD-54's report page is live and gated to owners (walked 2026-10-17); its
intake opens with the plugins service's next deploy.
