// The bot's client for the plugins service: nine operations, one base, and the
// difference between a call that failed and an item that could not be answered.
//
// Registry plan B-T2.5. Contract §4.2 to §4.4, DEC-4, DEC-11, ID-9, ID-71,
// BOT-91, SERVE-93; registry plan BOT-3, BOT-20, BOT-63, BOT-92. Nothing here
// is wired into a workflow: this lands dark at R2 and goes live at R3 (B-T5.1),
// and `plugins-ingest.yml`'s `claim` step still exits 1 naming this task.
//
// ── what is compiled in, and what that costs ───────────────────────────────
//
// The base, the nine operations with their methods and paths, and every body's
// members are values in this file rather than configuration (BOT-20: "compiled
// in"). `bot/tests/service.test.mjs` compares all of them against
// `schema/contract-tokens-v1.json`, which is SCOPE-7's published record of the
// same facts, so the cost of compiling them in is one red test on the day the
// contract moves and not a service that talks to whatever a variable says.
//
// The operation table is keyed BY WORKFLOW, because BOT-91 makes the workflow
// part of the operation: the service refuses a call whose token's
// `job_workflow_ref` names the other workflow, with `token_refused`, which
// BOT-63 turns into a failed run. A single flat table would let a moderation
// run reach `bot/leases` and discover that at the far end. `submission result`
// is in both, which is why the table has nine entries over eight distinct
// paths — the floor the test asserts is nine, and it is a floor over the
// workflow-keyed entries because that is what this client compiles.
//
// ── the four distinctions this file exists to keep ─────────────────────────
//
// **A call-level refusal is not an item-level one** (0.13.0, n13; BOT-63's
// 0.13.0 note). `bot-gates/1` answers `items[]`, and an item whose stop status
// SERVE-93 cannot resolve after a restore carries `stop_status` `unavailable`.
// That is contract DEC-11's wait for THAT SUBMISSION ALONE: nothing is
// published for it and it is asked about again next run, while every other item
// in the same body is answered as it says. It is not `W_SERVICE_UNREACHABLE`,
// which is what a call-level `unavailable` gives, and it never fails the run.
// Treating the two alike costs a whole batched call to one unresolved row.
//
// **A stated wait is not an outage** (attack m-1). An `unavailable` carrying
// `Retry-After` is the service saying when to come back. B-T3.6's W0 drill
// reaches exactly that on its first run after reg.80a: the service's mirror has
// not fetched the new commit, so its content rule's outcome is `absent` rather
// than `differs`, and it answers `unavailable` with `Retry-After: 30`, wakes a
// fetch and leaves the mode unchanged. Both still give `W_SERVICE_UNREACHABLE`
// — there is no other B.7 code for "come back later" — but the ALERT is
// suppressed on the first such wait in a run and raised on the second, and on
// any `unavailable` that carries no `Retry-After`. Without that, the drill's
// first run produces a bot-side alert and no shadow page, and a walk records a
// failure of something it is not testing. minice-be's §9 issue 11 (its W-15)
// asks the contract to say this in as many words; until it does, this comment
// and its two tests are where it is written down.
//
// **Reading is permissive and writing is strict** (attack M-1; SCOPE-3).
// SCOPE-3 binds every party — "within `/n` only optional members are added and
// readers ignore unknown ones" — and this client is a reader. Every
// `astra.plugins.*` success body it parses validates the members it names and
// IGNORES members it does not; there is no closed-world check on a success
// body anywhere in this file, and the test asserts one unknown member per body
// is accepted. The client plan owes the daemon the same discipline three times
// over (its D-C9, "An unknown member is never a failure … No parser here uses
// `deny_unknown_fields`"); this is the registry's direction of it. What stays
// strict is `composeBody`, which refuses a member no schema names.
//
// **A missing marker is not a real answer** (A4; BOT-92). Every §4.2 success
// body except the wake hint's carries the required boolean `shadow`. On `true`
// the answer is returned as shadow and no caller commits or posts a state-
// setting result for the work it names. An answer whose `shadow` is absent or
// is not a boolean FAILS ITS SCHEMA, and the safe direction for a failed schema
// is the withholding one: it is returned as shadow and it alerts. The same
// holds for any other required member — a body this client cannot read is not a
// body it may act on.
//
// ── requiredness is three-valued, and a condition is read, not excepted ────
//
// The token file's readme states the vocabulary, and this file follows it
// rather than paraphrasing it. A member's requiredness is `true`, `false` or
// **`conditional`**, and a `conditional` member "is carried exactly under the
// condition the member's `when` states". A `when` is `{"iff": p}` or
// `{"if": p}` — never both and never neither: `if` requires the member where
// `p` holds and says nothing where it does not; **`iff` also FORBIDS it where
// `p` does not hold**, and that second half is the whole of "never both" for a
// disjunction. A predicate names one sibling member and the values it may take,
// or `{"member": "absent"}`, which holds exactly when that sibling is not
// carried.
//
// A `conditional` that states no `when`, or a `when` this reader cannot
// evaluate, makes the file malformed, and the readme says what to do about it:
// refuse, and "MUST NOT read the member as unconditioned — reading it as
// unconditioned is the looser direction, and the looser direction is the one
// this field exists to close." So `predicateHolds` throws rather than shrugging,
// `composeBody` refuses to write, and `successProblems` — where the withholding
// direction is a problem and not a throw — returns it as one, which makes the
// answer shadow and alerts.
//
// **What used to be here, and why it went.** §4.2's "`state`, or `wait`" (§4.4)
// and "`commit` or `refusal_code`" were once recorded in the token file as BOTH
// REQUIRED, which no conforming body can satisfy, so this file carried
// `EITHER_MEMBERS`: a private list excepting those four members from a rule it
// could not meet, plus a local "exactly one of the pair" check standing in for
// the rule the file did not state. That was a LOCAL PATCH for a narrowing the
// estate had not published.
//
// Contract 0.28.0 published it. The four members became `conditional`, each
// with a biconditional `when`, and the readme now says in as many words that "a
// reader that requires both refuses every conforming body of that schema" —
// which made the patch wrong rather than merely redundant. **Nothing failed at
// that moment**: `bot/tests/service.test.mjs` compared requiredness through
// `m.required ? "" : "?"`, and `true` and `"conditional"` are both truthy, so
// four members went wrong inside a green suite (dev/couplings.md, entry 38).
//
// The exemption list is gone, and what replaces it is not a shorter exemption
// but the file's own conditions, compiled and evaluated. For
// `bot-service-decision-result/1` that is strictly MORE than the patch
// enforced: the patch accepted any one of `commit`/`refusal_code`, while the
// published conditions say `outcome` is what decides which — so a `refused`
// outcome carrying a `commit` was a body the patch composed and the contract
// forbids.

import { BOT_AUDIENCE, mintToken } from "./oidc.mjs";

/**
 * The service API base, compiled in (BOT-20).
 *
 * Every path below is relative to it (§4.2), and `new URL(path, API_BASE)` is
 * what joins them — so a path that ever begins with `/` would silently escape
 * the `plugins/v1/` prefix. `operationProblems` refuses one.
 */
export const API_BASE = "https://api.minice.ai/plugins/v1/";

/** The two bot workflows BOT-91 keys operations by. */
export const WORKFLOWS = Object.freeze(["ingest", "moderation"]);

/** BOT-63: at most 3 attempts per call per run. */
export const MAX_ATTEMPTS = 3;

const CALL_TIMEOUT_MS = 30_000;

/**
 * The operations, keyed by workflow (BOT-91), each carrying the contract's own
 * name so that a rename in the token file is a red test and not a silent
 * translation.
 *
 * `submission result` appears under both workflows with the same path: BOT-91
 * lists its workflow as "both", and the service still refuses an ingest result
 * from a moderation token for anything but a stop or an `M_REJECT`.
 */
export const OPERATIONS = Object.freeze({
  ingest: Object.freeze({
    register: Object.freeze({
      name: "register", method: "POST", path: "bot/submissions",
      request: "astra.plugins.bot-register/1", success: "astra.plugins.bot-registered/1",
    }),
    claim: Object.freeze({
      name: "claim", method: "POST", path: "bot/leases",
      request: "astra.plugins.bot-claim/1", success: "astra.plugins.bot-leases/1",
    }),
    verdict: Object.freeze({
      name: "verdict", method: "POST", path: "bot/verdicts",
      request: "astra.plugins.bot-verdict-query/1", success: "astra.plugins.bot-verdict/1",
    }),
    gates: Object.freeze({
      name: "decisions, stops", method: "POST", path: "bot/gates",
      request: "astra.plugins.bot-gates-query/1", success: "astra.plugins.bot-gates/1",
    }),
    noticeStatus: Object.freeze({
      name: "notice status", method: "POST", path: "bot/notice-status",
      request: "astra.plugins.bot-notice-query/1", success: "astra.plugins.bot-notice-status/1",
    }),
    result: Object.freeze({
      name: "submission result", method: "POST", path: "bot/results",
      request: "astra.plugins.bot-result/1", success: "astra.plugins.bot-ack/1",
    }),
  }),
  moderation: Object.freeze({
    moderationWork: Object.freeze({
      name: "list moderation work", method: "GET", path: "bot/moderation-work",
      request: null, success: "astra.plugins.bot-moderation-work/1",
    }),
    result: Object.freeze({
      name: "submission result", method: "POST", path: "bot/results",
      request: "astra.plugins.bot-result/1", success: "astra.plugins.bot-ack/1",
    }),
    serviceDecisionResult: Object.freeze({
      name: "service-decision result", method: "POST", path: "bot/service-decision-results",
      request: "astra.plugins.bot-service-decision-result/1", success: "astra.plugins.bot-ack/1",
    }),
  }),
});

/**
 * The signer's wake hint (SERVE-94), which is NOT in the table above.
 *
 * It carries no token, its emitter is the registry's signer rather than the
 * bot, and it belongs to no bot workflow — so a client built for `ingest` or
 * `moderation` cannot reach it, which is the point of keeping it here. Its
 * answer is the one §4.2 success body that carries no `shadow`, and it is
 * stated as literal bytes rather than as a shape: `{"schema":"astra.plugins.
 * wake-ack/1"}`, the same whatever arrives.
 */
export const WAKE_HINT = Object.freeze({
  name: "wake hint", method: "POST", path: "signed/wake",
  request: null, success: "astra.plugins.wake-ack/1", token: false,
});

/** The exact bytes the service answers a wake hint with (§4.2; 0.13.0). */
export const WAKE_ACK_BODY = '{"schema":"astra.plugins.wake-ack/1"}';

/**
 * Every body this client writes or reads, with its members and whether each is
 * required, exactly as `schema/contract-tokens-v1.json` records them.
 *
 * A member is `[name, required]`, or `[name, "conditional", when]` — the
 * requiredness is the file's three-valued one and the `when` is the file's own
 * object, copied rather than summarised, so the test can compare both sides
 * with `deepEqual` and a narrowing cannot arrive as a paraphrase.
 *
 * `schema` is not listed: §4.2's "Every body names its schema in `schema`"
 * makes it universal, and the token file records it as a member only for the
 * bodies whose source states them as literal bytes. The test compares the two
 * sides with `schema` removed from both, and asserts separately that every body
 * composed here carries it.
 */
export const BODIES = Object.freeze({
  "astra.plugins.bot-register/1": Object.freeze({
    role: "request",
    members: Object.freeze([["repo", true], ["repository_id", false], ["tag", true], ["trigger", true]]),
  }),
  "astra.plugins.bot-registered/1": Object.freeze({
    role: "success",
    members: Object.freeze([["shadow", true], ["submission_id", true]]),
  }),
  "astra.plugins.bot-claim/1": Object.freeze({
    role: "request",
    members: Object.freeze([["wanted", true]]),
  }),
  "astra.plugins.bot-leases/1": Object.freeze({
    role: "success",
    members: Object.freeze([["shadow", true], ["leases", true]]),
  }),
  "astra.plugins.bot-verdict-query/1": Object.freeze({
    role: "request",
    members: Object.freeze([
      ["submission_id", true], ["binding_token", true], ["repository_id", true],
      ["repository_owner_id", true], ["plugin_id", true],
    ]),
  }),
  "astra.plugins.bot-verdict/1": Object.freeze({
    role: "success",
    members: Object.freeze([
      ["shadow", true], ["token_state", true], ["minted_for_repository", true], ["eligibility", true],
    ]),
  }),
  "astra.plugins.bot-gates-query/1": Object.freeze({
    role: "request",
    members: Object.freeze([["items", true]]),
  }),
  "astra.plugins.bot-gates/1": Object.freeze({
    role: "success",
    members: Object.freeze([["shadow", true], ["items", true]]),
  }),
  "astra.plugins.bot-notice-query/1": Object.freeze({
    role: "request",
    members: Object.freeze([["submission_id", true], ["fingerprint", true], ["kind", true]]),
  }),
  "astra.plugins.bot-notice-status/1": Object.freeze({
    role: "success",
    members: Object.freeze([
      ["shadow", true], ["status", true], ["accepted_at", false], ["ended_at", false],
    ]),
  }),
  "astra.plugins.bot-result/1": Object.freeze({
    role: "request",
    members: Object.freeze([
      ["submission_id", true], ["attempt", false],
      ["state", "conditional", Object.freeze({ iff: Object.freeze({ wait: "absent" }) })],
      ["wait", "conditional", Object.freeze({ iff: Object.freeze({ state: "absent" }) })],
      ["reasons", true],
      ["decision_id", false], ["main_commit", false], ["read_commit", false], ["plugin_id", false],
      ["version", false], ["tag", false], ["commit", false], ["artifact_digests", false],
      ["fingerprint", false], ["repository_id", false], ["repository_owner_id", false],
      ["recorded", false], ["publish_after", false], ["objection_window", false],
      ["owner_file_commit", false], ["owner_file_pull_request", false],
      ["triggering_actor_id", false], ["triggering_actor_is_owner", false],
    ]),
  }),
  "astra.plugins.bot-ack/1": Object.freeze({
    role: "success",
    members: Object.freeze([["shadow", true], ["outcome", true]]),
  }),
  "astra.plugins.bot-moderation-work/1": Object.freeze({
    role: "success",
    members: Object.freeze([["shadow", true], ["submissions", true], ["service_decisions", true]]),
  }),
  "astra.plugins.bot-service-decision-result/1": Object.freeze({
    role: "request",
    members: Object.freeze([
      ["service_decision_id", true], ["outcome", true],
      ["commit", "conditional", Object.freeze({
        iff: Object.freeze({ outcome: Object.freeze(["applied", "held", "cancelled"]) }),
      })],
      ["refusal_code", "conditional", Object.freeze({
        iff: Object.freeze({ outcome: Object.freeze(["refused"]) }),
      })],
    ]),
  }),
  "astra.plugins.wake-ack/1": Object.freeze({
    role: "success",
    members: Object.freeze([["schema", true]]),
  }),
  "astra.plugins.error/1": Object.freeze({
    role: "refusal",
    members: Object.freeze([
      ["schema", true], ["error", true], ["message", true], ["retry_after", false],
    ]),
  }),
});

/** A predicate, in words, for the one message a reader actually meets. */
function describePredicate(predicate) {
  const [name] = Object.keys(predicate);
  const rule = predicate[name];
  if (rule === "absent") return `\`${name}\` is absent`;
  const values = Array.isArray(rule) ? rule : rule.not;
  const list = values.map((v) => `\`${v}\``).join(", ");
  return `\`${name}\` is ${Array.isArray(rule) ? "" : "not "}one of ${list}`;
}

/**
 * Does a `when`'s predicate hold of this body?
 *
 * The three shapes the token file's readme publishes, and only those:
 * `{"member": "absent"}`, which holds exactly when that sibling is not carried;
 * `{"member": [values]}`, which holds when it is carried with one of them; and
 * `{"member": {"not": [values]}}`, their complement — which an ABSENT sibling
 * does not satisfy, because `not` says which value was carried and a member
 * that is not carried has none.
 *
 * Anything else THROWS. The readme makes a `when` a reader cannot evaluate a
 * malformed file and requires that reader to refuse it rather than read the
 * member as unconditioned, which is the looser of the two directions.
 */
export function predicateHolds(predicate, body) {
  const unreadable = () =>
    new Error(
      `a \`when\` predicate this reader cannot evaluate: ${JSON.stringify(predicate ?? null)}. The token file's ` +
      "readme forbids reading the member as unconditioned instead, because that is the looser direction",
    );
  if (predicate === null || typeof predicate !== "object" || Array.isArray(predicate)) throw unreadable();
  const names = Object.keys(predicate);
  if (names.length !== 1) throw unreadable();

  const [name] = names;
  const rule = predicate[name];
  const carried = body !== null && typeof body === "object" && name in body;
  if (rule === "absent") return !carried;
  if (Array.isArray(rule)) return carried && rule.includes(body[name]);
  if (rule !== null && typeof rule === "object" && Array.isArray(rule.not) && Object.keys(rule).length === 1) {
    return carried && !rule.not.includes(body[name]);
  }
  throw unreadable();
}

/**
 * Everything this body gets wrong about a schema's `conditional` members.
 *
 * Both halves of a biconditional are checked, because the readme says what
 * happens to a reader who implements one of them: "a reader who implemented one
 * of the two and not the other would get the looser reading of the member they
 * skipped, which is what this vocabulary exists to end." Under `if`, only the
 * requiring half exists — `if` "says nothing where the predicate does not
 * hold", and inventing the other half here would forbid what the contract
 * permits.
 *
 * Throws on a table it cannot evaluate; callers choose their safe direction.
 *
 * @returns {string[]}
 */
export function conditionalProblems(schema, body, members = BODIES[schema]?.members ?? []) {
  const problems = [];
  for (const [name, required, when] of members) {
    if (required !== "conditional") continue;
    if (when === null || typeof when !== "object" || Array.isArray(when)) {
      throw new Error(
        `\`${name}\` is \`conditional\` in ${schema} and states no \`when\`. The token file's readme makes that a ` +
        "malformed file, and this reader refuses it rather than reading the member as unconditioned",
      );
    }
    const kinds = ["if", "iff"].filter((k) => k in when);
    if (kinds.length !== 1) {
      throw new Error(
        `\`${name}\`'s \`when\` in ${schema} is ${JSON.stringify(when)}; a \`when\` is \`if\` or \`iff\`, never ` +
        "both and never neither, and which of the two applies is decided per condition and never defaulted",
      );
    }
    const [kind] = kinds;
    const predicate = when[kind];
    const holds = predicateHolds(predicate, body);
    const carried = body !== null && typeof body === "object" && name in body;

    if (holds && !carried) {
      problems.push(`\`${name}\` is required by ${schema} where ${describePredicate(predicate)} and is absent`);
    } else if (!holds && carried && kind === "iff") {
      problems.push(
        `\`${name}\` is carried by ${schema} and its \`iff\` forbids it except where ` +
        `${describePredicate(predicate)}`,
      );
    }
  }
  return problems;
}

/** §4.2: the one success body that carries no `shadow`. */
export const SHADOW_EXEMPT = "astra.plugins.wake-ack/1";

/** BOT-58: these come from the verified token and never from a body. */
export const FROM_TOKEN_ONLY = Object.freeze(["run_id", "run_attempt"]);

/** BOT-63: these fail the run with an operator alert. */
export const FATAL_TOKENS = Object.freeze(["token_refused", "replay"]);

/** ID-9: these are the service saying it cannot answer now. */
export const UNREACHABLE_TOKENS = Object.freeze(["unavailable", "rate_limited"]);

/**
 * Refusals a caller must see and decide about: they are answers, not outages.
 * `too_early` is deliberately absent — §0.8 gives it to the panel, and a bot
 * that met one would be meeting a token nobody sends it, which is the unknown
 * case below.
 */
export const RETURNED_TOKENS = Object.freeze(["invalid", "lease_not_held", "conflict"]);

/** B.7's code for a service that could not answer (ID-9). */
export const W_SERVICE_UNREACHABLE = "W_SERVICE_UNREACHABLE";

/** The item-level stop status SERVE-93 answers, which is a per-submission wait. */
export const ITEM_UNAVAILABLE = "unavailable";

/** A refusal or a redirect this run must not continue past (BOT-63). */
export class ServiceRunFailure extends Error {
  constructor(message, { token = null, operation = null } = {}) {
    super(message);
    this.name = "ServiceRunFailure";
    this.token = token;
    this.operation = operation;
  }
}

/** @returns {string[]} everything wrong with the compiled tables themselves */
export function operationProblems(operations = OPERATIONS) {
  const problems = [];
  for (const workflow of Object.keys(operations)) {
    if (!WORKFLOWS.includes(workflow)) problems.push(`${workflow} is not a bot workflow`);
    for (const [id, op] of Object.entries(operations[workflow])) {
      const where = `${workflow}.${id}`;
      if (!["GET", "POST"].includes(op.method)) problems.push(`${where}: method ${op.method}`);
      if (op.path.startsWith("/")) {
        problems.push(`${where}: path ${op.path} is absolute and would escape ${API_BASE}`);
      }
      for (const schema of [op.request, op.success]) {
        if (schema !== null && !BODIES[schema]) problems.push(`${where}: no member table for ${schema}`);
      }
      if (op.method === "GET" && op.request !== null) problems.push(`${where}: a GET with a request body`);
    }
  }
  return problems;
}

/** The nine (workflow, name, method, path) rows this client compiles. */
export function compiledRows(operations = OPERATIONS) {
  const rows = [];
  for (const workflow of Object.keys(operations)) {
    for (const op of Object.values(operations[workflow])) {
      rows.push({ workflow, name: op.name, method: op.method, path: op.path });
    }
  }
  return rows.sort((a, b) => `${a.workflow} ${a.name}`.localeCompare(`${b.workflow} ${b.name}`));
}

/**
 * One request body, as bytes.
 *
 * Strict, and deliberately the only strict side in this file (M-T3.1): a
 * member no schema names is a member the service will not read and a bug here,
 * while an unknown member in an ANSWER is SCOPE-3 doing what it promises.
 *
 * `run_id` and `run_attempt` are refused by name rather than by falling out of
 * the member table, because BOT-58 is about where a fact comes from and not
 * about a typo: the service takes both from the verified token, and a body that
 * carried them would be offering the run a way to name a different one.
 */
export function composeBody(schema, values = {}) {
  const def = BODIES[schema];
  if (!def) throw new Error(`no member table for ${schema}`);
  if (def.role !== "request") throw new Error(`${schema} is a ${def.role} body and this side does not write it`);

  const named = new Map(def.members.map(([member]) => [member, true]));
  const out = { schema };
  const problems = [];

  for (const [key, value] of Object.entries(values)) {
    if (FROM_TOKEN_ONLY.includes(key)) {
      problems.push(
        `\`${key}\` is in the body. The service takes it from the verified token and never from a body ` +
        "(contract BOT-58), so a body that carries it is a body that could name another run",
      );
      continue;
    }
    if (!named.has(key)) {
      problems.push(`\`${key}\` is not a member of ${schema}`);
      continue;
    }
    if (value !== undefined) out[key] = value;
  }

  for (const [member, required] of def.members) {
    if (required !== true) continue;
    if (!(member in out)) problems.push(`\`${member}\` is required by ${schema} and is absent`);
  }
  // The conditional members, both halves of every biconditional, evaluated
  // against the body actually composed. On the WRITE side an unevaluable
  // condition throws out of here (`conditionalProblems` does the throwing),
  // because refusing to write is the safe direction for a composer.
  problems.push(...conditionalProblems(schema, out, def.members));
  if (problems.length) throw new Error(problems.join("\n"));
  return JSON.stringify(out);
}

/**
 * Read a success body under SCOPE-3.
 *
 * `def` is the schema's compiled definition and is a parameter only so that a
 * test can provoke the conditional branches on a definition of its own: no
 * §4.2 SUCCESS body has a `conditional` member today, and a branch reachable in
 * no environment is a branch nobody has watched fail.
 *
 * @returns {{problems: string[]}} empty when the body is readable. Unknown
 * members are not problems and are never even looked at — neither this function
 * nor `conditionalProblems` loops over the body's own keys, which is the shape
 * that cannot regress into a closed world by somebody adding an `else`. A
 * conditional member's predicate reads ONE named sibling and no more.
 */
export function successProblems(schema, body, def = BODIES[schema]) {
  if (!def) return { problems: [`no member table for ${schema}`] };
  const problems = [];
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return { problems: [`the answer is not a JSON object`] };
  }
  if (body.schema !== schema) {
    problems.push(`the answer names schema ${JSON.stringify(body.schema ?? null)} and this call expects ${schema}`);
  }
  for (const [member, required] of def.members) {
    if (member === "schema") continue;
    if (required === true && !(member in body)) problems.push(`\`${member}\` is required by ${schema} and is absent`);
  }
  try {
    problems.push(...conditionalProblems(schema, body, def.members));
  } catch (e) {
    // A compiled `when` this reader cannot evaluate. The readme forbids reading
    // the member as unconditioned instead, and on the READ side the withholding
    // direction is a problem rather than a throw: the answer is returned as
    // shadow and alerts, where a throw would fail a run over a table this file
    // owns and the service never sent.
    problems.push(String(e?.message ?? e));
  }
  if (schema !== SHADOW_EXEMPT && "shadow" in body && typeof body.shadow !== "boolean") {
    problems.push(`\`shadow\` is ${typeof body.shadow} and §4.2 makes it a required boolean`);
  }
  return { problems };
}

/**
 * `bot-gates/1`'s items, split into the ones that answer and the ones that are
 * a wait for their own submission (SERVE-93; DEC-11; n13).
 *
 * The waiting items are returned WITHOUT a B.7 code, and that absence is
 * deliberate rather than unfinished: B.7 has no code for "this stop could not
 * be resolved", `W_SERVICE_UNREACHABLE` is the call-level one and §4.2 says
 * this is not that, and a code invented here would be a name three parties do
 * not have. The caller publishes nothing for these and asks again next run,
 * which needs no code to do.
 */
export function splitGateItems(body) {
  const items = Array.isArray(body?.items) ? body.items : [];
  const answered = [];
  const waiting = [];
  for (const item of items) {
    if (item?.stop_status === ITEM_UNAVAILABLE) waiting.push(item);
    else answered.push(item);
  }
  return { answered, waiting };
}

/** Does this response state when to come back (attack m-1)? */
export function statedRetryAfter(res, body) {
  const header = typeof res?.headers?.get === "function" ? res.headers.get("retry-after") : null;
  if (header !== null && header !== undefined && String(header).trim() !== "") return String(header).trim();
  // §0.8 gives the `retry_after` member to `rate_limited` and `too_early`, so
  // an `unavailable` that states a wait states it in the header. A body that
  // carries it anyway is still the service saying when to come back, and
  // reading it costs nothing; the header is what the drill sends.
  const member = body?.retry_after;
  if (typeof member === "number" && Number.isFinite(member)) return String(member);
  return null;
}

/**
 * A client for one workflow's operations.
 *
 * `mint` is injected so that a test can drive the whole retry path without an
 * Actions runner, and it is called once per ATTEMPT: contract ID-33 refuses a
 * `jti` already seen, so a retry re-sending the first attempt's token would be
 * refused as the `replay` it is, and BOT-63 would fail the run over it. The
 * BODY is the opposite — built once per call and re-sent byte for byte, so a
 * retry cannot become a second, differently-worded request.
 */
export function createClient({
  workflow,
  base = API_BASE,
  fetchImpl = fetch,
  mint = (opts) => mintToken(opts),
  env = process.env,
  log = console,
} = {}) {
  if (!WORKFLOWS.includes(workflow)) {
    throw new Error(`${JSON.stringify(workflow)} is not a bot workflow; BOT-91 keys every operation by one`);
  }
  const table = OPERATIONS[workflow];
  const alerts = [];
  const state = { statedWaits: 0 };

  const alert = (cause, detail, operation) => {
    alerts.push({ cause, detail, operation, workflow });
    log.error(`::error::${cause}: ${detail}`);
  };

  /** One attempt. Never retries, never alerts; it classifies and returns. */
  async function attempt(op, bytes) {
    let token = null;
    if (op.token !== false) {
      const minted = await mint({ env, fetchImpl, log, audience: BOT_AUDIENCE });
      token = minted.token;
    }
    const headers = { Accept: "application/json", "User-Agent": "astra-registry-bot" };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (bytes !== null) headers["Content-Type"] = "application/json";

    let res;
    try {
      res = await fetchImpl(new URL(op.path, base).toString(), {
        method: op.method,
        headers,
        body: bytes ?? undefined,
        redirect: "manual",
        signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
      });
    } catch (e) {
      return { kind: "retry", cause: `the service could not be reached: ${String(e.message ?? e)}` };
    }

    if (res.status >= 300 && res.status < 400) {
      // Never retried and never a wait. The base is compiled in (BOT-20) and
      // the only thing on the other end of it that can redirect is something
      // that is not the service.
      return {
        kind: "fatal",
        cause: `the service answered HTTP ${res.status}, a redirect. The base is compiled in and no redirect ` +
          "is ever followed (registry plan BOT-20), so this is not the service answering",
      };
    }

    let body = null;
    let raw = "";
    try {
      raw = await res.text();
      body = raw === "" ? null : JSON.parse(raw);
    } catch {
      body = null;
    }

    if (res.ok) {
      if (body === null) {
        return { kind: "retry", cause: `the service answered HTTP ${res.status} with something that is not JSON` };
      }
      return { kind: "success", body, raw };
    }

    const refusal = body?.schema === "astra.plugins.error/1" && typeof body.error === "string" ? body : null;
    if (!refusal) {
      return {
        kind: "retry",
        cause: `the service answered HTTP ${res.status} with no \`astra.plugins.error/1\` body`,
      };
    }
    return { kind: "refusal", token: refusal.error, body: refusal, retryAfter: statedRetryAfter(res, refusal) };
  }

  /** Turn a success body into an answer, withholding whatever it cannot read. */
  function answerOf(op, body) {
    const { problems } = successProblems(op.success, body);
    if (problems.length) {
      return {
        ok: true, shadow: true, unreadable: true,
        schema: op.success, body, problems,
      };
    }
    const shadow = op.success === SHADOW_EXEMPT ? false : body.shadow === true;
    const answer = { ok: true, shadow, unreadable: false, schema: op.success, body };
    if (op.success === "astra.plugins.bot-gates/1") {
      const split = splitGateItems(body);
      answer.items = split.answered;
      answer.waiting = split.waiting;
    }
    return answer;
  }

  /**
   * One operation, at most `MAX_ATTEMPTS` times, with one body and at most one
   * alert. Throws `ServiceRunFailure` on `token_refused`, `replay` or a
   * redirect; returns everything else.
   */
  async function call(id, values = undefined) {
    const op = table[id];
    if (!op) {
      throw new Error(
        `${JSON.stringify(id)} is not an operation of the ${workflow} workflow. BOT-91 refuses a call whose ` +
        `token names the other workflow with \`token_refused\`, so reaching for one here is a failed run`,
      );
    }
    // Once per call, re-sent byte for byte on every retry (BOT-63).
    const bytes = op.request === null ? null : composeBody(op.request, values ?? {});

    let last = null;
    for (let n = 1; n <= MAX_ATTEMPTS; n++) {
      const outcome = await attempt(op, bytes);
      last = outcome;

      if (outcome.kind === "fatal") {
        alert("service", outcome.cause, op.name);
        throw new ServiceRunFailure(outcome.cause, { operation: op.name });
      }
      if (outcome.kind === "success") {
        const answer = answerOf(op, outcome.body);
        if (answer.unreadable) {
          // A success body this client cannot read — a missing `shadow`, a
          // missing required member, a `schema` that names something else. It
          // is returned as shadow, never as a real answer, and it alerts: an
          // answer nobody can read is a change at the far end, and the one
          // outcome that must not follow from it is a quiet publication.
          alert(
            "service",
            `a ${op.success} answer failed its schema and is returned as shadow: ${answer.problems.join("; ")}`,
            op.name,
          );
        }
        return { ...answer, attempts: n, bytes };
      }

      if (outcome.kind === "refusal") {
        const t = outcome.token;
        if (FATAL_TOKENS.includes(t)) {
          const cause =
            `the service refused with \`${t}\`. BOT-63 fails the run on it: a bot whose token is refused, or ` +
            "whose `jti` the service has already seen, is a bot that must not keep calling";
          alert("service", cause, op.name);
          throw new ServiceRunFailure(cause, { token: t, operation: op.name });
        }
        if (RETURNED_TOKENS.includes(t)) {
          return {
            ok: false, refused: t, message: String(outcome.body.message ?? ""),
            schema: op.success, attempts: n, bytes,
          };
        }
        if (t === "unavailable" && outcome.retryAfter !== null) {
          // A stated wait. Not retried — the service said when to come back —
          // and silent the first time (attack m-1).
          state.statedWaits += 1;
          if (state.statedWaits > 1) {
            alert(
              "service",
              `a second stated wait in this run: \`unavailable\` with Retry-After ${outcome.retryAfter}. One is ` +
              "the mirror catching up (B-T3.6's W0 drill); two is the service not catching up",
              op.name,
            );
          }
          return {
            ok: false, wait: W_SERVICE_UNREACHABLE, stated: true, retryAfter: outcome.retryAfter,
            attempts: n, bytes,
          };
        }
        if (UNREACHABLE_TOKENS.includes(t)) {
          last = { kind: "retry", cause: `the service refused with \`${t}\`` };
          continue;
        }
        // A well-formed refusal this client has no rule for — `too_early`,
        // which §0.8 gives to the panel, or a code added after this file was
        // written. It is an answer and is not retried, and it alerts because
        // the alternative is a bot that silently does nothing it can explain.
        const cause =
          `the service refused with \`${t}\`, which is not a token the bot is answered with (§0.8). It gives ` +
          `${W_SERVICE_UNREACHABLE} and an alert rather than a guess`;
        alert("service", cause, op.name);
        return { ok: false, wait: W_SERVICE_UNREACHABLE, unknownToken: t, attempts: n, bytes };
      }
      // kind === "retry": go round again with the same bytes and a new token.
    }

    const cause = `${MAX_ATTEMPTS} attempts, and the last of them: ${last?.cause ?? "no answer"}`;
    alert("service", cause, op.name);
    return { ok: false, wait: W_SERVICE_UNREACHABLE, attempts: MAX_ATTEMPTS, cause, bytes };
  }

  return {
    workflow,
    base,
    operations: table,
    alerts,
    call,
    /** An answer this client returned is shadow, or it could not be read. */
    withheld: (answer) => answer?.ok === true && (answer.shadow === true || answer.unreadable === true),
  };
}
