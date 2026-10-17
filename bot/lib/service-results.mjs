// `astra.plugins.bot-result/1`, built from a plan and the commit that landed.
//
// Registry plan B-T3.5. One function composes every result body the ingest
// workflow posts, so the seven shapes §4.4's When column allows are one
// function's seven branches and not seven callers' guesses. Its output is
// what `report` sends, what the golden files under `tests/results/` pin, and
// what a shadow run hashes into the step summary instead of posting.
//
// ── three rules the body obeys, each one a canary ───────────────────────────
//
// **Exactly the members that apply** (BOT-23). A member is present precisely
// under §4.4's When: `publish_after` only with `delayed`, `read_commit` only
// with a FLOW-67 refusal, `objection_window` only with an `R_BINDING_CHANGED`
// hold, the owner-file pair only with an `R_FIRST_BINDING` or
// `R_BINDING_CHANGED` hold, the actor pair only with an `R_FIRST_BINDING` hold
// of a grandfathered or frozen listing. `state` or `wait`, never both.
//
// **The record's members, equal to the record** (BOT-23). A result that names
// a record carries its DEC-7 members as the record has them — the state, the
// reason CODES, the decision id and every identity value — and nothing that
// never enters git (a message, a location, a wait time) is compared. So the
// reasons of a state result are the record's `reasons`, in the record's order,
// each dressed with its stage, location and message.
//
// **Built once, from committed facts** (determinism). The wait's start is the
// decide step's recorded start and its earliest retry comes from a record or
// from that start; nothing here reads a clock, so a retry sends the same bytes
// and a re-run of the report job re-sends the body the first attempt built.

import { OPERATOR_WINDOW_HOURS, WAIT_CAUSE_MAX, boundedEarliest, operatorRetryHint, reasonOf } from "./service-decide.mjs";
import { HOUR_MS, iso } from "./policy/time.mjs";
import { isTime } from "../../tools/lib/time.mjs";

/** The members a result may take from the derived facts (§4.4, "when derived"). */
const DERIVED = Object.freeze([
  "plugin_id", "version", "tag", "commit", "artifact_digests", "fingerprint", "repository_id", "repository_owner_id",
]);

/** The result kinds a golden file exists for, one per §4.4 shape this workflow posts. */
export const RESULT_KINDS = Object.freeze([
  "published", "held", "held-first-binding", "held-binding-changed", "delayed", "refused", "refused-flow67",
  "reported", "wait",
]);

const clip = (text) => {
  const points = [...String(text ?? "")];
  return points.length <= WAIT_CAUSE_MAX ? points.join("") : points.slice(0, WAIT_CAUSE_MAX).join("");
};

/**
 * The reasons of a state result: the record's codes, each dressed from the
 * plan's richer reasons where one carries that code.
 */
function reasonsFor(codes, planReasons) {
  return codes.map((code) => {
    const r = (planReasons ?? []).find((x) => x.code === code);
    return r
      ? { code, stage: r.stage, location: r.location ?? null, message: clip(r.message) }
      : reasonOf(code);
  });
}

/**
 * One result body.
 *
 * `landed.reportedAt` is when the publish job composed the result, which is
 * what TRUST-32's retry hint counts from (contract 5.8.0): a `W_OPERATOR_WINDOW`
 * wait asks to be claimed again at most 15 minutes after its report, and
 * never later than the window's end, so an operator's OK is read within a
 * quarter of an hour. Without it the hint counts from the wait's `started_at`,
 * which is earlier, and so never later than the contract allows.
 *
 * @param {object} plan a `decideSubmission` plan (not `none`)
 * @param {{decisionId?: string|null, mainCommit?: string|null, deliveredAt?: string|null, reportedAt?: string|null,
 *   record?: object|null}} landed  `record`: for a `reported` plan, the record it names, as `main_commit` holds it
 * @returns {object} the body, without `schema` (the client stamps it)
 */
export function resultBody(plan, landed = {}) {
  if (!plan || plan.kind === "none") throw new Error("a plan of kind `none` posts no result (BOT-92; BOT-15)");
  const body = { submission_id: plan.submission_id };
  // BOT-12: the attempt identity is echoed on every ingest result.
  if (plan.attempt !== null && plan.attempt !== undefined) body.attempt = plan.attempt;

  if (plan.kind === "wait") {
    const wait = { ...plan.wait };
    if (plan.alert) {
      // TRUST-14's first read of an event: the composer knows whether the
      // channel reported delivery, and TRUST-32 names the two waits.
      if (isTime(landed.deliveredAt)) {
        wait.code = "W_OPERATOR_WINDOW";
        wait.cause = `TRUST-32: the operator alert was delivered at ${landed.deliveredAt}; the ${OPERATOR_WINDOW_HOURS}-hour objection window runs from there, unless an operator answers it with an OK`;
        wait.window_ends_at = iso(new Date(new Date(landed.deliveredAt).getTime() + OPERATOR_WINDOW_HOURS * HOUR_MS));
      } else {
        wait.code = "W_ALERT_UNDELIVERED";
        wait.cause = "TRUST-32: the channel reported no delivery of the operator alert, so nothing publishes";
      }
    }
    // §4.4 since contract 5.8.0: `window_ends_at` on every `W_OPERATOR_WINDOW`
    // wait and on no other code, and `earliest_retry_at` beside it a retry
    // hint, never the window's end unless the end is sooner.
    const windowEndsAt = wait.code === "W_OPERATOR_WINDOW" && isTime(wait.window_ends_at) ? wait.window_ends_at : null;
    if (windowEndsAt) {
      wait.earliest_retry_at = operatorRetryHint({
        windowEndsAt,
        from: isTime(landed.reportedAt) ? landed.reportedAt : wait.started_at,
      });
    }
    body.wait = {
      code: wait.code,
      started_at: wait.started_at,
      cause: clip(wait.cause),
      // §4.4 (3.12.0), at the last point before the wire: the composer can
      // move the time (the operator window counts from reported delivery).
      earliest_retry_at: boundedEarliest(wait.started_at, wait.earliest_retry_at),
      ...(windowEndsAt ? { window_ends_at: windowEndsAt } : {}),
    };
    body.reasons = (plan.reasons ?? []).map((r) => ({ code: r.code, stage: r.stage, location: r.location ?? null, message: clip(r.message) }));
    if (plan.derived) for (const m of DERIVED) if (plan.derived[m] !== undefined) body[m] = plan.derived[m];
    return body;
  }

  body.state = plan.state;
  if (plan.kind === "norecord") {
    // FLOW-67: no record, and the commit the absence was read at (FLOW-78).
    body.reasons = (plan.reasons ?? []).map((r) => ({ code: r.code, stage: r.stage, location: r.location ?? null, message: clip(r.message) }));
    body.read_commit = plan.read_commit;
    if (plan.derived) for (const m of DERIVED) if (plan.derived[m] !== undefined) body[m] = plan.derived[m];
    return body;
  }

  if (plan.kind === "reported") {
    // BOT-19 / BOT-74 / a pre-fingerprint refusal: the record already on
    // `main`. BOT-23 makes the result's DEC-7 members — the state, the reason
    // codes, `decision_id`, the derived members and `publish_after` — equal
    // that record AT THE COMMIT THE RESULT NAMES, so when the publish job has
    // read the record there (`landed.record`) they are the record's, never
    // this run's. Until 2026-10-17 BOT-74 posted `[P_PUBLISHED]` and this
    // run's facts against a record carrying `P_PUBLISHED, P_REVIEW_PRIORITY`,
    // and a re-tag of identical bytes posted the new tag and commit: each a
    // `record_mismatch` once the result named its commit. Only the
    // submission and the attempt stay the result's own. A plan naming no
    // record (BOT-74 over a version no record on `main` describes) keeps this
    // run's facts, and carries no `decision_id` and no `main_commit`.
    const record = landed.record ?? null;
    if (record) {
      body.state = record.state;
      body.reasons = reasonsFor(Array.isArray(record.reasons) ? record.reasons : [], plan.reasons);
      body.decision_id = record.decision_id;
      if (landed.mainCommit) body.main_commit = landed.mainCommit;
      for (const m of DERIVED) if (record[m] !== undefined) body[m] = record[m];
      if (record.publish_after !== undefined) body.publish_after = record.publish_after;
      return body;
    }
    body.reasons = (plan.reasons ?? []).map((r) => ({ code: r.code, stage: r.stage, location: r.location ?? null, message: clip(r.message) }));
    if (plan.decision_id) body.decision_id = plan.decision_id;
    if (landed.mainCommit) body.main_commit = landed.mainCommit;
    if (plan.derived) for (const m of DERIVED) if (plan.derived[m] !== undefined) body[m] = plan.derived[m];
    return body;
  }

  // kind === "state": the record's members, equal to the record. When BOT-36
  // found the record's key already on `main` (`landed.record`, read at the
  // commit that added it), that record IS the decision the result names, and
  // its members are the result's — not this run's. Since contract 5.8.0 a
  // re-hold reuses the first hold's key, so a re-leased submission that holds
  // again with other codes (`R_FIRST_BINDING`, then `R_BINDING_CHANGED`), or a
  // fingerprinted refusal re-decided with other codes, posted this run's codes
  // against the first record's commit: a `record_mismatch` the service
  // re-leases for ever, the ae402306 loop for fingerprinted records.
  const onMain = landed.record ?? null;
  const record = onMain ?? plan.record;
  if (!record) throw new Error(`a ${plan.state} plan carries no record`);
  if (onMain) body.state = onMain.state;
  body.reasons = reasonsFor(Array.isArray(record.reasons) ? record.reasons : [], plan.reasons);
  if (landed.decisionId) body.decision_id = landed.decisionId;
  if (landed.mainCommit) body.main_commit = landed.mainCommit;
  for (const m of DERIVED) if (record[m] !== undefined) body[m] = record[m];
  if (onMain ? record.publish_after !== undefined : plan.state === "delayed") body.publish_after = record.publish_after;
  // The hold's own members (§4.4: `objection_window` with an
  // `R_BINDING_CHANGED` hold, the owner file with a binding hold, the actor
  // with a first binding) describe these bytes, which the key's fingerprint
  // fixes; over a record already on `main` they ride only where that
  // record's codes are the hold they belong to.
  for (const [k, v] of Object.entries(plan.result_extra ?? {})) {
    if (!onMain || extraApplies(k, record.reasons)) body[k] = v;
  }
  return body;
}

/** §4.4's conditions for the hold-only members, against a record's codes. */
function extraApplies(member, codes) {
  const has = (c) => Array.isArray(codes) && codes.includes(c);
  if (member === "objection_window") return has("R_BINDING_CHANGED");
  if (member === "owner_file_commit" || member === "owner_file_pull_request") return has("R_FIRST_BINDING") || has("R_BINDING_CHANGED");
  if (member === "triggering_actor_id" || member === "triggering_actor_is_owner") return has("R_FIRST_BINDING");
  return false;
}

/**
 * BOT-23, asserted before anything is posted: the result's DEC-7 members
 * equal the record's. A difference is a defect in this module, and it fails
 * the step rather than telling the service one thing and git another.
 */
export function recordAgreement(body, record) {
  const problems = [];
  if (!record) return problems;
  if (body.state !== record.state) problems.push(`state ${body.state} vs the record's ${record.state}`);
  const codes = (body.reasons ?? []).map((r) => r.code);
  if (JSON.stringify(codes) !== JSON.stringify(record.reasons ?? [])) problems.push("the reason codes differ from the record's");
  for (const m of [...DERIVED, "publish_after"]) {
    if (JSON.stringify(body[m]) !== JSON.stringify(record[m])) problems.push(`${m} differs from the record's`);
  }
  if (body.decision_id !== undefined && body.decision_id !== record.decision_id) problems.push("decision_id differs");
  return problems;
}
