// Who may list under a first-party-looking id.
//
// `astra-`, `official-` and `verified-` are an impersonation primitive: a store
// card is a name, an icon and an author string, and a name that reads as ours
// IS the impersonation. So the prefixes are refused by default and allowed by
// exception.
//
// ── why this is a module and not two copies ────────────────────────────────
//
// It used to be two. `tools/validate.mjs` held the rule for a listing already
// in the tree and `bot/lib/derive.mjs` held it for a submission arriving at
// ingest, seven lines apart in wording and identical in behaviour. That is the
// shape this system has been bitten by more than any other — a fact kept in two
// places with one of them updated — and widening the exception was exactly the
// edit that would have updated one. A submission the bot admits and CI then
// rejects, or the reverse, is a listing that cannot be published and cannot be
// explained.
//
// ── the two knobs, and why the second one is wider than it looks ───────────
//
//   first_party_repos   an owner/name pair. The narrow knob: one repository.
//   first_party_owners  an owner login. EVERY repository under it, present and
//                       future, including one a collaborator with push access
//                       creates. Only for an account the project would vouch
//                       for as a whole.
//
// Both are matched case-insensitively, because GitHub logins are.

/**
 * Why this id may not be listed from this repository, or null if it may.
 *
 * @param {string} id the plugin id
 * @param {string} repo "owner/name", the repository the ownership check proved
 * @param {{reserved_prefixes: string[], first_party_repos?: string[], first_party_owners?: string[]}} reserved
 *        the parsed policy/reserved-ids.json
 * @returns {{prefix: string} | null}
 */
export function reservedPrefixViolation(id, repo, reserved) {
  const lower = (s) => String(s ?? "").toLowerCase();
  const repoLower = lower(repo);
  const ownerLower = repoLower.split("/")[0];

  // An empty owner would match an empty allowlist entry, so a listing with no
  // `source.repo` at all must not be able to buy itself a first-party prefix by
  // being malformed. Falsy owner => nothing is permitted.
  const permitted =
    (!!repoLower && (reserved.first_party_repos ?? []).some((r) => lower(r) === repoLower)) ||
    (!!ownerLower && (reserved.first_party_owners ?? []).some((o) => lower(o) === ownerLower));

  if (permitted) return null;

  for (const prefix of reserved.reserved_prefixes ?? []) {
    if (String(id).startsWith(prefix)) return { prefix };
  }
  return null;
}
