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
// ── the `OWNER` fallback that stood here, and the measurement that ended it ─
//
// Until 2026-09-20 this module had a fourth path. The three reasons above are
// reasons not to trust `author_association` as a *permission*, and exactly one
// of its values is not a permission claim at all: `OWNER` is GitHub's own
// payload asserting that the commenter is the account the repository belongs
// to. So `OWNER` was accepted — but only when the API declined to answer, as a
// stand-in for a silence, never as an override of an answer.
//
// The reasoning was sound and its premise was never checked. The triage job
// holds a `GITHUB_TOKEN` with `contents: read`; GitHub documents this endpoint
// as requiring push access; `administration` and `members` are not scopes a
// workflow token can request at all. From those three facts it followed that
// the endpoint *might* 403 for this token, and that without a fallback every
// held submission would become unclearable through the documented path —
// silently, and invisibly to a suite that injects a stub for `proveMaintainer`
// wherever it matters. The comment that stood here admitted the gap in as many
// words: **"this has not been observed in a real Actions run"**. A fallback for
// a failure nobody had ever seen.
//
// It has now been seen, and it does not fail. Registry issue #93, run
// 35487527105 (2026-09-20), triage step: `collaborator-permission:
// answered=true outcome=role is 'admin'`. The endpoint answers a workflow
// `GITHUB_TOKEN` holding `contents: read`, about this repository, with the
// commenter's real role. "Documented as requiring push access" describes what
// the *caller* needs against a repository they can already see, not a scope
// this token lacks — so the whole fallback was standing in for a silence that
// never comes. Registry plan B-T0.4a is that measurement; B-T0.4b is this
// deletion.
//
// Which leaves what happens if the endpoint goes silent one day — a 403 after
// a settings change, a 404 on a rename, a 5xx. The answer is the paragraph
// below, and it is the answer this module already gave to every account that
// was not the owner: a missing answer is a refusal. The remedy is a rerun, and
// if it persists, the hand path — `bot/run-checks.mjs` and a pull request,
// which never needed a comment to work. What is *not* a remedy is a payload
// field: the endpoint answers, so a fallback could now only fire during a
// genuine outage, which is exactly when this registry should be publishing
// nothing on a maintainer's word alone.
//
// The probe line stays, because it is the thing that would tell us if this
// stopped being true. `bot/triage.mjs` writes it on every command, to the log
// as well as to the step summary.
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
 * @param {{repo: string, login: string,
 *          token?: string, fetchImpl?: typeof fetch}} opts
 *   `repo` is **this registry**, not the plugin's repository. There is no
 *   `association`: no field of the event payload reaches this function any
 *   more, which is the whole of B-T0.4b.
 * @returns {Promise<{ok: boolean, role: string|null, detail: string,
 *           answered: boolean, outcome: string}>}
 *   `answered` and `outcome` are what the collaborator-permission endpoint did,
 *   carried out of here unchanged. They were R0's measurement (registry plan
 *   B-T0.4a) and they stay after it, because "the endpoint answers" is a fact
 *   with a date on it, and the line these two fields feed is the only thing
 *   that would notice the day it stops being one.
 */
export async function proveMaintainer(opts) {
  const { repo, login } = opts;
  if (!REPO_RE.test(String(repo ?? ""))) {
    return {
      ok: false,
      role: null,
      detail:
        "this registry's own repository was not named, so there is nothing to check the command " +
        "against. That is a fault in the workflow, not in the comment.",
      answered: false,
      outcome: "not-asked",
    };
  }
  if (!LOGIN_RE.test(String(login ?? ""))) {
    return {
      ok: false,
      role: null,
      detail: `${JSON.stringify(login ?? null)} is not a GitHub login`,
      answered: false,
      outcome: "not-asked",
    };
  }

  const asked = await collaboratorRole(repo, login, {
    token: opts.token ?? process.env.GITHUB_TOKEN,
    fetchImpl: opts.fetchImpl,
  });

  if (!asked.answered) {
    return {
      ok: false,
      role: null,
      detail:
        `GitHub would not say what @${login} has on ${repo} (${asked.outcome}), so the command is ` +
        "refused. A command that decides what this registry publishes fails closed when the " +
        "permission behind it cannot be read. This endpoint answered when it was measured " +
        "(2026-09-20), so a silence here is an outage or a settings change rather than the normal " +
        "state of things: re-run it, and if it persists, publish through a pull request " +
        "(`bot/run-checks.mjs`) rather than through a comment. Nothing in the event payload is " +
        "accepted in its place — `author_association: OWNER` used to be, and was removed once the " +
        "silence it stood in for was measured and found not to happen.",
      answered: asked.answered,
      outcome: asked.outcome,
    };
  }
  if (CONTROL_ROLES.includes(asked.role)) {
    return {
      ok: true,
      role: asked.role,
      detail: `GitHub reports @${login} has \`${asked.role}\` on ${repo}`,
      answered: asked.answered,
      outcome: asked.outcome,
    };
  }
  return {
    ok: false,
    role: asked.role,
    detail:
      `GitHub reports @${login} has \`${asked.role}\` on ${repo}, which is neither \`admin\` nor ` +
      "`maintain`. This is checked against the API rather than against how the comment was " +
      "phrased, so there is nothing to rephrase.",
    answered: asked.answered,
    outcome: asked.outcome,
  };
}
