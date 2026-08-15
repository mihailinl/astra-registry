// May the account that typed this command decide what the registry publishes?
//
// `bot/lib/ownership.mjs` asks whether a *submitter* controls the repository
// they are listing. This asks the other permission question in the system:
// whether a *commenter* on this registry's own issues may clear a hold. Same
// endpoint, same field, deliberately — `collaboratorRole` is shared so the two
// questions cannot come to different conclusions about what `maintain` means.
//
// ── why not `author_association` ────────────────────────────────────────────
//
// The event payload hands a comment's `author_association` over for free —
// `OWNER`, `MEMBER`, `COLLABORATOR`, `CONTRIBUTOR`, `NONE` — and it is the
// obvious thing to gate on. It is the wrong thing, for three reasons and any
// one of them is enough:
//
//   1. It is not a permission. `COLLABORATOR` is true for anybody with *any*
//      collaborator role, `read` and `triage` included, and neither of those
//      may push a byte to this repository. A registry where somebody with
//      `triage` can publish a listing is a registry with two permission models,
//      one of which nobody wrote down.
//   2. `CONTRIBUTOR` means "has had a pull request merged here, once". It is a
//      historical fact that never expires, which is precisely the property
//      `ownership.mjs` refuses to accept for a release author without a cap.
//   3. It arrives in the *event*, and everything else in this pipeline is
//      re-proved against the API at the moment it matters. A permission granted
//      by a payload is a permission an event shape gets to decide.
//
// So the check is `GET /repos/{owner}/{repo}/collaborators/{login}/permission`
// against **this** repository, requiring `admin` or `maintain` — the same bar
// `ownership.mjs` sets for a submitter, asked about the registry instead of
// about the plugin's repository.
//
// ── the one narrowed exception: `OWNER`, when the API says nothing ──────────
//
// The three reasons above are reasons not to trust `author_association` as a
// *permission*. Exactly one of its values is not a permission claim at all:
// `OWNER` is GitHub's own payload asserting that this commenter is the account
// the repository belongs to. The commenter cannot forge it, it cannot be
// inherited from a merged pull request the way `CONTRIBUTOR` can, and it does
// not cover `read` or `triage` the way `COLLABORATOR` does. On a personal
// repository it names exactly one account, and that account has `admin` by
// construction.
//
// It is accepted **only when the API declined to answer**, which is the case it
// exists for. The triage job holds a `GITHUB_TOKEN` with `contents: read`;
// GitHub documents this endpoint as requiring push access, and no permissions
// block can widen it, because `administration` and `members` are not scopes a
// workflow token can request at all. If that is how it behaves in a real run,
// then without this fallback `proveMaintainer` refuses the repository's own
// owner — every held submission becomes unclearable through the documented
// path, silently, and no test can catch it because they all inject a stub.
//
// **This has not been observed in a real Actions run**, and that is the honest
// state of it: the fallback is here so the feature has a happy path either way,
// not because the API path is known to fail. The API is still tried first and
// is still the path that generalises to an organisation, where `OWNER` is the
// org account and the maintainers are collaborators.
//
// An *answered* denial stays a denial. `OWNER` never overrides GitHub saying
// `read`; it only fills a silence.
//
// ── and why it fails closed ─────────────────────────────────────────────────
//
// `proveOwnership` treats "GitHub would not say" as *no answer* and falls
// through to weaker proofs, because refusing every organisation that has not
// installed the registry's app would make third-party publishing theoretical.
// There is no equivalent argument here: there is exactly one repository to ask
// about, this bot's token is issued for it, and the cost of being wrong is not
// a refused submission but a published one. So a missing answer is a refusal,
// and the refusal says which it was — a `read` role and an unreadable endpoint
// are different problems with different fixes, and a maintainer at 2am should
// not have to guess which one they have.

import { CONTROL_ROLES, collaboratorRole } from "./ownership.mjs";

/** GitHub's own login charset: alphanumerics and single hyphens, ≤39 chars. */
export const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

/** `owner/name`, the only shape this bot ever puts in an API path. */
const REPO_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

/**
 * The one `author_association` value that is an identity rather than a
 * permission, and therefore the only one this module will look at.
 */
export const OWNER_ASSOCIATION = "OWNER";

/**
 * @param {{repo: string, login: string, association?: string|null,
 *          token?: string, fetchImpl?: typeof fetch}} opts
 *   `repo` is **this registry**, not the plugin's repository. `association` is
 *   `github.event.comment.author_association` from the event payload, used only
 *   as the `OWNER` fallback described at the top of this file.
 * @returns {Promise<{ok: boolean, role: string|null, detail: string}>}
 */
export async function proveMaintainer(opts) {
  const { repo, login } = opts;
  const isOwner = String(opts.association ?? "").toUpperCase() === OWNER_ASSOCIATION;
  if (!REPO_RE.test(String(repo ?? ""))) {
    return {
      ok: false,
      role: null,
      detail:
        "this registry's own repository was not named, so there is nothing to check the command " +
        "against. That is a fault in the workflow, not in the comment.",
    };
  }
  if (!LOGIN_RE.test(String(login ?? ""))) {
    return { ok: false, role: null, detail: `${JSON.stringify(login ?? null)} is not a GitHub login` };
  }

  const asked = await collaboratorRole(repo, login, {
    token: opts.token ?? process.env.GITHUB_TOKEN,
    fetchImpl: opts.fetchImpl,
  });

  if (!asked.answered) {
    if (isOwner) {
      return {
        ok: true,
        role: "owner",
        detail:
          `GitHub would not say what @${login} has on ${repo} (${asked.outcome}), but the event ` +
          `payload marks the comment \`author_association: OWNER\` — @${login} is the account ` +
          "this repository belongs to. That is an identity GitHub asserts, not a role the " +
          "commenter claimed.",
      };
    }
    return {
      ok: false,
      role: null,
      detail:
        `GitHub would not say what @${login} has on ${repo} (${asked.outcome}), and the comment ` +
        "is not from the repository's owner either, so the command is refused. A command that " +
        "decides what this registry publishes fails closed when the permission behind it cannot " +
        "be read.",
    };
  }
  if (CONTROL_ROLES.includes(asked.role)) {
    return { ok: true, role: asked.role, detail: `GitHub reports @${login} has \`${asked.role}\` on ${repo}` };
  }
  return {
    ok: false,
    role: asked.role,
    detail:
      `GitHub reports @${login} has \`${asked.role}\` on ${repo}, which is neither \`admin\` nor ` +
      "`maintain`. This is checked against the API rather than against how the comment was " +
      "phrased, so there is nothing to rephrase.",
  };
}
