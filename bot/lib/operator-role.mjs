// Who may perform an operator act (registry plan M-T3.5; contract MOD-52).
//
// MOD-52 accepts a confirmation, a cancellation or a revert "only from a
// `workflow_dispatch` of a separate operator workflow … by an admin or
// maintainer", and TRUST-33 makes the same workflow the writer of the deny
// record. That workflow is `.github/workflows/operator.yml`; this is the role
// check it runs before it writes anything.
//
// **This check is defence in depth, and it is not the boundary.** It lives in
// the tree at the ref the dispatcher chose, and the GitHub dispatch API takes a
// `ref`: a write-only collaborator who pushed a branch with this file replaced
// by `return { ok: true }` and dispatched on that branch would run THEIR copy
// of it (attack B-2). The boundary is environment `operator` (RC-R0-3a), whose
// deployment-branch policy admits `main` alone, so GitHub refuses that job
// before it starts. What this file adds is the refusal of a LEGITIMATE ref's
// wrong actor: somebody with write access dispatching from `main`.
//
// **Both actors, every time.** `github.actor` is the account that started the
// run; `github.triggering_actor` is the one that started THIS attempt, and on
// a re-run they differ. A re-run is refused outright (`run_attempt` other than
// 1): an operator act is a statement a person makes once, and a re-run of it by
// somebody else would make it theirs without their saying so. Both actors are
// asked anyway, because a check that read one would pass the other's change.
//
// **No OWNER fallback, and an unanswered API is a refusal.** `bot/lib/
// ownership.mjs`'s `collaboratorRole` separates "GitHub said no" from "GitHub
// would not say", and its other caller falls back to the repository's own
// owner file when GitHub would not say. This one does not: an operator act
// that cannot be attributed to an admin or a maintainer is not one, and the
// person who can perform it can dispatch again in a minute. Watched by
// accepting `OWNER` on an unanswered API, which is the one-line change that
// would reopen it.
//
// It deliberately does not use `bot/lib/maintainer.mjs`, which B-T5.2 deletes
// with the issue path.

import { CONTROL_ROLES, collaboratorRole } from "./ownership.mjs";

/** A GitHub login, as GitHub spells one: 1-39 characters, no leading or doubled hyphen. */
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

/**
 * May this run perform an operator act?
 *
 * @param {object} args
 * @param {string} args.repo             `owner/name`, this repository
 * @param {string} args.actor            `github.actor`
 * @param {string} args.triggeringActor  `github.triggering_actor`
 * @param {string|number} args.runAttempt `github.run_attempt`
 * @param {string} [args.token]          the job's GITHUB_TOKEN
 * @param {typeof fetch} [args.fetchImpl]
 * @returns {Promise<{ok: boolean, why: string, roles: Record<string, string|null>}>}
 */
export async function operatorAuthority({ repo, actor, triggeringActor, runAttempt, token, fetchImpl }) {
  const roles = {};
  if (String(runAttempt) !== "1") {
    return {
      ok: false,
      roles,
      why: `this is attempt ${JSON.stringify(String(runAttempt))} of the run, and an operator act is refused on any ` +
        "attempt but the first: a re-run would make somebody else's act the operator's without their saying so " +
        "(MOD-52). Dispatch the workflow again",
    };
  }
  const logins = [...new Set([actor, triggeringActor])];
  for (const login of [actor, triggeringActor]) {
    if (typeof login !== "string" || !LOGIN_RE.test(login)) {
      return { ok: false, roles, why: `${JSON.stringify(login)} is not a GitHub login, so nobody can be asked about it` };
    }
  }
  for (const login of logins) {
    const answer = await collaboratorRole(repo, login, { token, fetchImpl });
    roles[login] = answer.role;
    if (!answer.answered) {
      return {
        ok: false,
        roles,
        why: `GitHub did not say what ${login} may do on ${repo} (${answer.outcome}), and an operator act that cannot ` +
          "be attributed to an admin or a maintainer is not one. There is no fallback to the repository's owner " +
          "file here, on purpose (MOD-52)",
      };
    }
    if (!CONTROL_ROLES.includes(answer.role)) {
      return {
        ok: false,
        roles,
        why: `${login} holds \`${answer.role}\` on ${repo}, and MOD-52 accepts an operator act only from an ` +
          `${CONTROL_ROLES.join(" or ")}`,
      };
    }
  }
  return { ok: true, roles, why: `${logins.join(" and ")} ${logins.length === 1 ? "is" : "are"} ${CONTROL_ROLES.join(" or ")}` };
}

// ── who may end an operator window: the act `ok` (contract 5.8.0) ──────────
//
// TRUST-32 since contract 5.8.0 (DEC-6; OD-28): an operator OK record ends
// the operator objection window of the alert it answers. The act that writes
// one has a role check of its own, which runs AFTER `operatorAuthority` above
// and admits exactly the accounts pinned here, by NUMERIC GitHub id: an id
// is the account, and a login can be renamed and then re-registered by
// somebody else.
//
// **The owner alone.** `193032699` is `mihailinl`, the account that publishes
// Astra and this registry (publishers/mihailinl.json; measured against
// `GET /users/mihailinl` on 2026-10-17). KNICE receives the alert's copies
// (TRUST-14), and **his OK is a condition, not a grant**: his id joins this
// list only after (a) the owner re-opens contract ID-39's premise
// (OPEN-OWNER-13(p)) for a second registry writer, and (b) a ruleset on
// registry `main` restricts its updates to the owner and the bot's own
// identity. Until both hold, write access would not stay inside `ok`: `main`
// refuses no writer's push (ROLL-5), so any writer can rewrite the bot and
// mint its tokens (ID-39; §1 row 10). Adding an id here is that decision, and
// `bot/tests/moderation-run.test.mjs` holds the list to exactly this one.
export const OK_ACTOR_IDS = Object.freeze(["193032699"]);

/**
 * May this run write an operator OK? `actorId` is `github.actor_id`, the
 * numeric id of the account that started the run; `operatorAuthority` has
 * already refused any attempt but the first, so it is also this attempt's.
 *
 * @param {{actorId: string|number|undefined}} args
 * @returns {{ok: boolean, why: string}}
 */
export function okAuthority({ actorId }) {
  const id = String(actorId ?? "");
  if (!/^[0-9]{1,20}$/.test(id)) {
    return { ok: false, why: `${JSON.stringify(actorId ?? null)} is not a numeric GitHub account id, so nobody can be matched against the pin (TRUST-32)` };
  }
  if (!OK_ACTOR_IDS.includes(id)) {
    return {
      ok: false,
      why: `account ${id} may not end an operator window: the act \`ok\` admits only the owner's pinned id (TRUST-32). ` +
        "A second operator's OK waits on contract OPEN-OWNER-13(p) and a ruleset on `main`, never on this check",
    };
  }
  return { ok: true, why: `account ${id} is the owner's pinned id (TRUST-32)` };
}
