#!/usr/bin/env node
//
// The operator's acts, as `.github/workflows/operator.yml` runs them
// (registry plan M-T3.5; contract MOD-52, TRUST-33, BOT-70; TRUST-32's `ok`
// since contract 5.8.0; `revoke-passkey`, the break-glass for the owner's
// passkeys, since the operator-acts-by-passkey design). What each act writes
// and refuses lives in `bot/lib/operator-acts.mjs`, which the moderation run's
// passkey acts share; this file keeps the command line, the role checks and
// the regeneration a revert needs.
//
//   node tools/operator.mjs --job authority          the dispatcher may act (MOD-52)
//   node tools/operator.mjs --job ok-authority       an `ok` is the owner's (TRUST-32)
//   node tools/operator.mjs --job act --out operator write the act, list its paths
//   node tools/operator.mjs --job verdict --out f    the alert job's verdict
//
// ── WHERE THIS FILE LIVES, AND WHY NOT WHERE THE PLAN PUT IT ────────────────
//
// The plan names `bot/operator.mjs`. The tree says every top-level `bot/*.mjs`
// is one of TRUST-31's enumerated entry points (`bot/tests/code-paths.test.mjs`,
// "the two enumerated groups are exactly what is on the tree"), so a new one
// there is a contract MINOR before the file lands — and the plan itself says
// `operator.yml` "is not in TRUST-31's set": it is not a bot workflow, holds no
// bot token and mints none. `tools/` holds the desk and ceremony tools the set
// leaves outside for the same reason, so this is `tools/operator.mjs`, and the
// role check it runs is `bot/lib/operator-role.mjs`, beside the
// `collaboratorRole` it reads.
//
// ── WHAT EACH ACT WRITES, AND NOTHING ELSE ─────────────────────────────────
//
//   confirm   state/holds/<id>.confirm.json   releases a hold MOD-9 made (BOT-70)
//   cancel    state/holds/<id>.cancel.json    ends one
//   revert    the listing edit or the advisory deletion that undoes an applied
//             M_DELIST, M_DEPRECATE or M_REVOKE, its `relist` or `unrevoke`
//             log entry, and the two regenerated documents (MOD-52)
//   deny      state/deny/<fingerprint>.json   withholds a release for ever (TRUST-33)
//   ok        state/ok/<fingerprint>.json     ends the operator window of the alert
//             it answers, and nothing else (TRUST-32, contract 5.8.0)
//   revoke-passkey  state/passkeys/revoked/<kid>.json   the bot accepts no act
//             signed by that key from then on; the owner's pinned id only
//
// `operatorPath` is that list as a predicate, and every path an act would
// write is checked against it before anything is opened. **It posts nothing to
// the service** (MOD-52: "It posts no result; the service reads `main`"), and
// it holds no bot OIDC token to post with.
//
// **A revert is unheld and outside the takedown bound** (MOD-52). It is outside
// structurally, not by a trailer: TRUST-26 counts what a commit ADDS
// (`bot/lib/takedown-bound.mjs`), and a revert only takes away.
//
// ── WHAT IT REFUSES ─────────────────────────────────────────────────────────
//
// Every refusal is a red run with the reason, and writes nothing: a confirm or
// cancel for a hold that is not on `main`, or that already has an answer; a
// confirm of an `unbound_yank`, which no confirmation ever releases (M-T3.3);
// a revert of anything but an applied delist, deprecate or revoke — a yank
// included, which MOD-52 does not make reversible — or of one already
// reverted; a deny of a fingerprint already denied, or of anything that is not
// one; an `ok` by anybody but the owner's pinned id, for a fingerprint whose
// alert has no reported delivery or no record at all, beside a deny record, or
// one already given for that alert's approval; a revoke-passkey by anybody but
// the owner's pinned id, of a key the pin does not hold, or of one already
// revoked.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "./lib/sources.mjs";
import { decisionCommitMessage } from "../bot/lib/decisions.mjs";
import { operatorAuthority, okAuthority } from "../bot/lib/operator-role.mjs";
import { composeVerdict, regenerateDocuments } from "../bot/moderation-run.mjs";
import {
  Refusal,
  SDI_RE,
  answerHold,
  denyFingerprint,
  okFingerprint,
  refuse,
  revertDecision,
  revokePasskey,
  wholeSeconds,
} from "../bot/lib/operator-acts.mjs";

export {
  DENY_DIR,
  DENY_MEMBERS,
  DENY_SCHEMA,
  FINGERPRINT_RE,
  REVERTIBLE,
  REVERT_REASONS,
  operatorPath,
} from "../bot/lib/operator-acts.mjs";

/**
 * The six acts, and no seventh: `act` is a closed enum here and in the
 * workflow. `revoke-passkey` is the break-glass for a passkey the owner can no
 * longer press `revoke_key` with (design §2.3).
 */
export const ACTS = Object.freeze(["confirm", "cancel", "revert", "deny", "ok", "revoke-passkey"]);

/** The acts only the owner's pinned numeric id may dispatch (TRUST-32's pin). */
export const OWNER_ONLY_ACTS = Object.freeze(["ok", "revoke-passkey"]);


/**
 * Perform one act on the tree at `root`. Returns the paths it touched and the
 * commit message; throws a `Refusal` (red, nothing written) or an Error.
 */
export function operatorAct({ root = REPO_ROOT, act, serviceDecisionId, fingerprint, kid = null, now = new Date(), runId = null, run = null, actorId = null }) {
  if (!ACTS.includes(act)) refuse(`${JSON.stringify(act)} is not one of the operator's acts (${ACTS.join(", ")})`);
  const at = wholeSeconds(now);
  let done;
  if (act !== "revoke-passkey" && kid) refuse(`a ${act} names no passkey; leave kid empty`);
  if (act === "revoke-passkey") {
    if (serviceDecisionId || fingerprint) refuse("a revoke-passkey names a kid alone; leave service_decision_id and fingerprint empty");
    // The pin, again, inside the act, as `ok` does: the workflow's own step
    // refuses first, and this makes the act refuse wherever it is run from.
    const who = okAuthority({ actorId });
    if (!who.ok) refuse(who.why);
    done = revokePasskey(root, kid, { at, run });
  } else if (act === "deny") {
    if (serviceDecisionId) refuse("a deny names a fingerprint, not a service decision; leave service_decision_id empty");
    done = denyFingerprint(root, fingerprint, { at, run });
  } else if (act === "ok") {
    if (serviceDecisionId) refuse("an ok names a fingerprint, not a service decision; leave service_decision_id empty");
    done = okFingerprint(root, fingerprint, { at, run, actorId });
  } else {
    if (fingerprint) refuse(`a ${act} names a service decision, not a fingerprint; leave fingerprint empty`);
    if (!SDI_RE.test(String(serviceDecisionId ?? ""))) {
      refuse(`${JSON.stringify(serviceDecisionId)} is not a service_decision_id (§0.7's lowercase UUID v4 or v7)`);
    }
    if (act === "revert") {
      done = revertDecision(root, serviceDecisionId, { at });
      const documents = regenerateDocuments({ root, paths: done.touched });
      done.touched.push(...documents.changed);
    } else {
      done = answerHold(root, act, serviceDecisionId, { at, run });
    }
  }
  const message = decisionCommitMessage({
    subject: done.subject,
    run: runId,
    ...(done.service_decision ? { service_decision: done.service_decision } : {}),
  });
  return { paths: done.touched, message };
}

// ── the command line ────────────────────────────────────────────────────────

const arg = (argv, name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

export async function main(argv = [], { env = process.env, log = console, fetchImpl = fetch, now = new Date() } = {}) {
  const job = arg(argv, "--job");
  const root = arg(argv, "--registry-dir") ?? REPO_ROOT;
  const runUrl = env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID
    ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
    : null;

  if (job === "authority") {
    const answer = await operatorAuthority({
      repo: env.GITHUB_REPOSITORY,
      actor: env.ASTRA_ACTOR,
      triggeringActor: env.ASTRA_TRIGGERING_ACTOR,
      runAttempt: env.ASTRA_RUN_ATTEMPT,
      token: env.GH_TOKEN,
      fetchImpl,
    });
    if (!answer.ok) {
      log.error(`::error::refused: ${answer.why}`);
      return 1;
    }
    log.log(`ok    ${answer.why}`);
    return 0;
  }

  if (job === "ok-authority") {
    // TRUST-32's own role check for the act `ok`, after `authority`. Any other
    // act passes through: their check is `authority` alone.
    if (!OWNER_ONLY_ACTS.includes(env.ASTRA_ACT)) {
      log.log(`ok    the act is ${JSON.stringify(env.ASTRA_ACT ?? null)}, not \`ok\`; TRUST-32's check does not apply`);
      return 0;
    }
    const answer = okAuthority({ actorId: env.ASTRA_ACTOR_ID });
    if (!answer.ok) {
      log.error(`::error::refused: ${answer.why}`);
      return 1;
    }
    log.log(`ok    ${answer.why}`);
    return 0;
  }

  if (job === "act") {
    const out = arg(argv, "--out") ?? "operator";
    fs.mkdirSync(out, { recursive: true });
    try {
      const { paths, message } = operatorAct({
        root,
        act: env.ASTRA_ACT,
        serviceDecisionId: env.ASTRA_SERVICE_DECISION_ID || null,
        fingerprint: env.ASTRA_FINGERPRINT || null,
        kid: env.ASTRA_KID || null,
        now,
        runId: env.GITHUB_RUN_ID ?? null,
        run: runUrl,
        actorId: env.ASTRA_ACTOR_ID ?? null,
      });
      fs.writeFileSync(path.join(out, "paths.txt"), paths.length ? `${paths.join("\n")}\n` : "");
      fs.writeFileSync(path.join(out, "commit-message.txt"), message);
      log.log(`ok    ${env.ASTRA_ACT}: ${paths.length} path(s): ${paths.join(", ")}`);
      return 0;
    } catch (err) {
      if (err instanceof Refusal) {
        log.error(`::error::refused: ${err.message}`);
        return 1;
      }
      throw err;
    }
  }

  if (job === "verdict") {
    // The alert job's verdict: red when the act job did not succeed — a refused
    // dispatch included, which is the case worth a page: somebody with access
    // to dispatch tried an operator act and was refused. A green verdict sends
    // nothing; the act itself is on `main` and on the run page.
    const out = arg(argv, "--out") ?? "verdict.json";
    const result = env.ASTRA_ACT_RESULT;
    const verdict = composeVerdict({
      check: "operator",
      status: result === "success" ? "green" : "red",
      codes: result === "success" ? [] : ["OPERATOR_ACT_NOT_DONE"],
      ids: [],
      run: runUrl,
    });
    fs.writeFileSync(out, `${JSON.stringify(verdict, null, 2)}\n`);
    log.log(`ok    ${out}: ${verdict.status}`);
    return 0;
  }

  throw new Error(`\`--job ${JSON.stringify(job)}\` is not one of authority, ok-authority, act, verdict`);
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err) => {
    console.error(`::error::${err.message}`);
    process.exit(1);
  });
}
