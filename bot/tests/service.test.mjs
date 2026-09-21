// The service client and the bot token, against a server on 127.0.0.1.
//
//     node --test bot/tests/service.test.mjs
//
// Registry plan B-T2.5. `bot/lib/oidc.mjs` mints one token per call and masks
// it; `bot/lib/service.mjs` compiles in nine operations and decides what each
// answer means. Both land dark: no workflow calls either yet, and
// `plugins-ingest.yml`'s `claim` step still exits 1 naming this task.
//
// ── why a socket and not a recording `fetch` ────────────────────────────────
//
// Three of the rules under test are properties of HTTP itself and a function
// standing in for `fetch` cannot hold any of them:
//
//   * `redirect: "manual"` is a request option the RUNTIME honours. A stub that
//     returned `{status: 302}` would prove that this file's stub returns 302,
//     not that the fetch in `service.mjs` declines to follow it — and the whole
//     of BOT-20 is about a redirect not being followed to another host.
//   * `Retry-After` is a header, and "a stated wait is not an outage" (attack
//     m-1) turns on reading one off a real response.
//   * "the mask precedes first use" is a statement about ORDER between a line
//     written to a log and bytes leaving this process. A journal that both the
//     log and the server append to is the only way to compare them; with a
//     stub `fetch` the two events happen in the same function and the ordering
//     is the test's own arrangement rather than the code's.
//
// So the stub serves both ends: the Actions id-token endpoint at `/token` and
// the service under `/plugins/v1/`. `mintToken` runs for real against the
// first, which also means the `::add-mask::` line under test is the one the
// shipped code writes and not one the test arranged.
//
// ── the two floors ─────────────────────────────────────────────────────────
//
// The token-file comparison asserts what it FOUND before it asserts anything
// about what it found there (dev/couplings.md, "Adding a coupling", step 4): a
// filter that matched nothing would compare an empty compiled table with an
// empty expected one and pass. Nine operations and sixteen bodies, and both
// numbers are derived from the file rather than typed beside it.

import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import test from "node:test";

import {
  BOT_AUDIENCE,
  ENVIRONMENT,
  claimProblems,
  claimsReport,
  decodeClaims,
  mintProblems,
  mintToken,
} from "../lib/oidc.mjs";
import {
  API_BASE,
  BODIES,
  EITHER_MEMBERS,
  FROM_TOKEN_ONLY,
  MAX_ATTEMPTS,
  OPERATIONS,
  SHADOW_EXEMPT,
  ServiceRunFailure,
  WAKE_ACK_BODY,
  WAKE_HINT,
  W_SERVICE_UNREACHABLE,
  compiledRows,
  composeBody,
  createClient,
  operationProblems,
  splitGateItems,
  successProblems,
} from "../lib/service.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const TOKEN_FILE = path.join(REPO, "schema", "contract-tokens-v1.json");

// ───────────────────────────────────────────────────────────────────────────
// The stub
// ───────────────────────────────────────────────────────────────────────────

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

/** A token shaped like the runner's, with whatever claims a case needs. */
const fakeToken = (claims = {}) =>
  [
    b64u({ alg: "RS256", kid: "kid-1", typ: "JWT" }),
    b64u({
      iss: "https://token.actions.githubusercontent.com",
      aud: BOT_AUDIENCE,
      environment: ENVIRONMENT,
      job_workflow_ref: "mihailinl/astra-registry/.github/workflows/plugins-ingest.yml@refs/heads/main",
      ref: "refs/heads/main",
      event_name: "schedule",
      run_id: "17301999999",
      run_attempt: "1",
      jti: `jti-${Math.random().toString(16).slice(2)}`,
      ...claims,
    }),
    "not-a-signature",
  ].join(".");

/**
 * One server standing in for the Actions token endpoint and for the service.
 *
 * `plan(call, n)` decides what the service end answers; `n` is 1-based over
 * service calls only, so a case can make the first attempt fail and the second
 * succeed. The journal records the mask lines and the requests in one ordered
 * list, which is what "the mask precedes first use" is asserted against.
 */
function stub(plan, { tokenClaims = {} } = {}) {
  const journal = [];
  const calls = [];
  const tokens = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      if (req.url.startsWith("/token")) {
        const token = fakeToken(tokenClaims);
        tokens.push(token);
        journal.push({ kind: "mint", url: req.url });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ value: token, count: tokens.length }));
        return;
      }
      const call = {
        url: req.url,
        method: req.method,
        raw,
        authorization: req.headers.authorization ?? null,
        contentType: req.headers["content-type"] ?? null,
      };
      calls.push(call);
      journal.push({ kind: "request", url: call.url, authorization: call.authorization });
      const answer = plan(call, calls.length) ?? { status: 200, body: {} };
      const headers = { "Content-Type": "application/json", ...(answer.headers ?? {}) };
      res.writeHead(answer.status, headers);
      res.end(answer.raw ?? JSON.stringify(answer.body ?? {}));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const origin = `http://127.0.0.1:${server.address().port}`;
      resolve({
        origin,
        base: `${origin}/plugins/v1/`,
        env: {
          ACTIONS_ID_TOKEN_REQUEST_URL: `${origin}/token?api-version=2.0`,
          ACTIONS_ID_TOKEN_REQUEST_TOKEN: "the-runner-secret",
        },
        journal,
        calls,
        tokens,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

/** A `console`-shaped sink that appends to the stub's journal. */
const journalLog = (journal, errors = []) => ({
  log: (line) => journal.push({ kind: "log", line: String(line) }),
  error: (line) => {
    journal.push({ kind: "error", line: String(line) });
    errors.push(String(line));
  },
});

const ok = (body) => ({ status: 200, body });
const refusal = (error, message = "no", extra = {}, status = 503, headers = undefined) => ({
  status,
  headers,
  body: { schema: "astra.plugins.error/1", error, message, ...extra },
});

// ───────────────────────────────────────────────────────────────────────────
// The compiled tables against SCOPE-7's file
// ───────────────────────────────────────────────────────────────────────────

const tokenFile = JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));

test("the compiled tables are internally consistent before anything compares them", () => {
  assert.deepEqual(operationProblems(), []);
  assert.equal(API_BASE, "https://api.minice.ai/plugins/v1/");
  assert.equal(BOT_AUDIENCE, "https://api.minice.ai/plugins/v1/bot");
  // The audience is a separate decision from the base and is compiled
  // separately (contract ID-34: "an opaque string that does not move if the
  // service API base moves"). It must not be DERIVED from the base here, or
  // the day the base moves the audience moves with it and no test can see it.
  assert.notEqual(BOT_AUDIENCE, `${API_BASE}bot`.replace("/bot", "bot"));
});

test("the nine workflow-keyed operations are the token file's, with a floor of 9", () => {
  const entries = tokenFile.entries.filter((e) => e.kind === "operation" && (e.emitter ?? []).includes("bot"));
  assert.ok(
    entries.length >= 8,
    `the token file holds ${entries.length} bot operations and there were 8 distinct ones at contract ` +
    `${tokenFile.contract_version}; a filter that matched nothing would compare two empty tables and pass`,
  );

  // Expanded the way BOT-91 keys them: an operation's `workflow` is part of it,
  // and "both (BOT-91)" is two rows. That expansion — not a list typed beside
  // it — is what makes the floor of 9 a count of something.
  const expected = [];
  for (const e of entries) {
    const w = String(e.workflow ?? "");
    const workflows = w.startsWith("both") ? ["ingest", "moderation"] : [w];
    for (const workflow of workflows) {
      expected.push({ workflow, name: e.name, method: e.method, path: e.path });
    }
  }
  expected.sort((a, b) => `${a.workflow} ${a.name}`.localeCompare(`${b.workflow} ${b.name}`));

  assert.ok(
    expected.length >= 9,
    `the token file expands to ${expected.length} workflow-keyed bot operations and the floor is 9. A floor and ` +
    "the thing it counts are two claims; if this ever fails, one of them is wrong and it is not automatically " +
    "the floor",
  );
  assert.deepEqual(compiledRows(), expected);
  assert.equal(compiledRows().length, expected.length);
});

test("the wake hint is the signer's and is in no bot workflow's table", () => {
  const entry = tokenFile.entries.find((e) => e.kind === "operation" && e.name === "wake hint");
  assert.ok(entry, "the token file records no wake hint");
  assert.equal(WAKE_HINT.method, entry.method);
  assert.equal(WAKE_HINT.path, entry.path);
  assert.equal(WAKE_HINT.token, false, "SERVE-94: the signer's wake hint carries no token");
  assert.equal((entry.emitter ?? []).includes("bot"), false, "the wake hint's emitter is the registry, not the bot");
  assert.deepEqual(compiledRows().filter((r) => r.name === "wake hint"), []);

  // §4.2 states the answer as literal bytes. The token file's wake-hint row
  // records `success_schema: null`, so the bytes are compared against the
  // SCHEMA entry — which records exactly one member — rather than against a
  // row that does not name them.
  const schema = tokenFile.entries.find((e) => e.kind === "schema" && e.name === "astra.plugins.wake-ack/1");
  assert.ok(schema, "the token file records no astra.plugins.wake-ack/1");
  assert.deepEqual(schema.members.map((m) => m.name), ["schema"]);
  assert.deepEqual(JSON.parse(WAKE_ACK_BODY), { schema: "astra.plugins.wake-ack/1" });
  assert.equal(WAKE_ACK_BODY, '{"schema":"astra.plugins.wake-ack/1"}');
});

test("every body's members and required flags are the token file's", () => {
  const recorded = new Map(
    tokenFile.entries.filter((e) => e.kind === "schema").map((e) => [e.name, e]),
  );
  assert.ok(recorded.size >= 40, `only ${recorded.size} schemas in the token file; this is a broken read`);

  let compared = 0;
  for (const [name, def] of Object.entries(BODIES)) {
    const entry = recorded.get(name);
    assert.ok(entry, `${name} is compiled into bot/lib/service.mjs and the token file does not record it`);
    assert.equal(entry.members_recorded, true, `${name}: the token file records no members`);
    // `schema` is dropped from both sides: §4.2 makes it universal and the
    // token file lists it only where the source states literal bytes.
    const mine = def.members.filter(([m]) => m !== "schema").map(([m, r]) => `${m}${r ? "" : "?"}`);
    const theirs = entry.members
      .filter((m) => m.name !== "schema")
      .map((m) => `${m.name}${m.required ? "" : "?"}`);
    assert.deepEqual(mine, theirs, `${name}: the compiled members are not the token file's`);
    compared += 1;
  }
  assert.ok(compared >= 16, `only ${compared} bodies compared; the client compiles 16`);

  // And the other direction, so a body added to §4.2 cannot stay unknown here.
  const botBodies = [...recorded.keys()].filter((n) => /^astra\.plugins\.bot-[a-z-]+\/1$/.test(n));
  assert.ok(botBodies.length >= 14, `only ${botBodies.length} bot bodies in the token file; broken read`);
  assert.deepEqual(botBodies.filter((n) => !BODIES[n]), [], "a §4.2 bot body the client does not compile");
});

test("the bot audience is the token file's, and shadow's exemption is the token file's", () => {
  const audience = tokenFile.entries.find((e) => e.kind === "audience" && e.name === "bot");
  assert.ok(audience, "the token file records no bot audience");
  assert.equal(BOT_AUDIENCE, audience.value);

  const member = tokenFile.entries.find((e) => e.kind === "required_member" && e.name === "shadow");
  assert.ok(member, "the token file records no required member `shadow`");
  assert.match(member.applies_to, /except `astra\.plugins\.wake-ack\/1`/);
  assert.equal(SHADOW_EXEMPT, "astra.plugins.wake-ack/1");

  // The one success body with no `shadow` is the exempt one, and every other
  // success body this client reads has it as a required member.
  for (const [name, def] of Object.entries(BODIES)) {
    if (def.role !== "success") continue;
    const has = def.members.some(([m, r]) => m === "shadow" && r);
    assert.equal(has, name !== SHADOW_EXEMPT, `${name}: \`shadow\` required = ${has}`);
  }
});

test("the closed lists this client names are the token file's", () => {
  const list = (name) => {
    const e = tokenFile.entries.find((x) => x.kind === "closed_list" && x.name === name);
    assert.ok(e, `the token file records no closed list ${name}`);
    return e.values;
  };
  // The item-level stop status (0.13.0, n13) and the notice query's kinds, read
  // out of the file rather than out of the plan's summary of it.
  assert.deepEqual(list("stop_status"), ["no_stop", "stopped", "unavailable"]);
  assert.deepEqual(list("notice_query_kind"), ["delayed", "approved", "binding_changed"]);

  // Every refusal token this client has a rule for is one the bot is an
  // acceptor of; `too_early` is not, which is why it has no rule.
  const tokens = new Map(
    tokenFile.entries.filter((e) => e.kind === "refusal_token").map((e) => [e.name, e.acceptor ?? []]),
  );
  assert.ok(tokens.size >= 20, `only ${tokens.size} refusal tokens; broken read`);
  for (const t of ["token_refused", "replay", "unavailable", "rate_limited", "invalid", "lease_not_held", "conflict"]) {
    assert.ok(tokens.get(t)?.includes("bot"), `${t} is not a token the bot accepts`);
  }
  assert.equal(tokens.get("too_early")?.includes("bot"), false, "`too_early` is a panel token (§0.8)");
});

test("the two `or` rows are exactly two, and each is a disagreement, not a rule", () => {
  // §4.2: a member is conditional only under a When column, BOT-80's entry list
  // or one of four qualifiers — "with", "or null", "where it applies", "none
  // for". "or" is not among them, so the token file marks both sides of
  // "`state`, or `wait`" and "`commit` or `refusal_code`" required. The member
  // tables above equal the file; the composer applies the prose. This test
  // exists so the exception cannot grow a third member quietly.
  assert.deepEqual(Object.keys(EITHER_MEMBERS).sort(), [
    "astra.plugins.bot-result/1",
    "astra.plugins.bot-service-decision-result/1",
  ]);
  for (const [schema, pair] of Object.entries(EITHER_MEMBERS)) {
    assert.equal(pair.length, 2, `${schema}: an \`either\` of ${pair.length} members`);
    for (const m of pair) {
      const required = BODIES[schema].members.find(([name]) => name === m)?.[1];
      assert.equal(required, true, `${schema}: \`${m}\` is not recorded required, so there is nothing to except`);
    }
  }
});

// ───────────────────────────────────────────────────────────────────────────
// Composing a request
// ───────────────────────────────────────────────────────────────────────────

test("every composed body names its schema, and an unnamed member is refused", () => {
  const body = JSON.parse(composeBody("astra.plugins.bot-register/1", {
    repo: "someone/quiet", repository_id: "42", tag: "v1.0.0", trigger: "poll",
  }));
  assert.equal(body.schema, "astra.plugins.bot-register/1");
  assert.deepEqual(Object.keys(body).sort(), ["repo", "repository_id", "schema", "tag", "trigger"]);

  assert.throws(
    () => composeBody("astra.plugins.bot-register/1", { repo: "a/b", tag: "v1", trigger: "poll", extra: 1 }),
    /`extra` is not a member/,
    "the WRITE side stays strict (M-T3.1): a member no schema names is a bug here, not a SCOPE-3 extension",
  );
  assert.throws(
    () => composeBody("astra.plugins.bot-register/1", { repo: "a/b", trigger: "poll" }),
    /`tag` is required/,
  );
  assert.throws(
    () => composeBody("astra.plugins.bot-registered/1", { submission_id: "s" }),
    /is a success body and this side does not write it/,
  );
});

test("`run_id` and `run_attempt` are refused by name, whatever else is right", () => {
  assert.deepEqual([...FROM_TOKEN_ONLY], ["run_id", "run_attempt"]);
  for (const member of FROM_TOKEN_ONLY) {
    assert.throws(
      () => composeBody("astra.plugins.bot-result/1", {
        submission_id: "s1", state: "published", reasons: [], [member]: "9",
      }),
      new RegExp(`\`${member}\` is in the body`),
      "contract BOT-58: the service takes both from the verified token, so a body carrying one is a body that " +
      "could name another run",
    );
  }
});

test("a result carries `state` or `wait`, never both and never neither", () => {
  const withState = JSON.parse(composeBody("astra.plugins.bot-result/1", {
    submission_id: "s1", state: "published", reasons: [],
  }));
  assert.equal(withState.state, "published");
  assert.equal("wait" in withState, false);

  const withWait = JSON.parse(composeBody("astra.plugins.bot-result/1", {
    submission_id: "s1", reasons: [],
    wait: { code: W_SERVICE_UNREACHABLE, started_at: "2026-09-21T00:00:00Z", cause: "no answer", earliest_retry_at: null },
  }));
  assert.equal(withWait.wait.code, W_SERVICE_UNREACHABLE);

  assert.throws(() => composeBody("astra.plugins.bot-result/1", { submission_id: "s1", reasons: [] }), /neither/);
  assert.throws(
    () => composeBody("astra.plugins.bot-result/1", {
      submission_id: "s1", reasons: [], state: "published", wait: { code: "W" },
    }),
    /both/,
  );
  assert.throws(
    () => composeBody("astra.plugins.bot-service-decision-result/1", {
      service_decision_id: "d1", outcome: "applied", commit: "a".repeat(40), refusal_code: "kind_refused",
    }),
    /both/,
  );
});

// ───────────────────────────────────────────────────────────────────────────
// Reading an answer: SCOPE-3, and the marker that must be there
// ───────────────────────────────────────────────────────────────────────────

/** The smallest body that satisfies a schema's required members. */
const minimal = (schema) => {
  const body = { schema };
  const either = EITHER_MEMBERS[schema] ?? [];
  for (const [member, required] of BODIES[schema].members) {
    if (member === "schema" || !required) continue;
    if (either.length && either.indexOf(member) > 0) continue;
    body[member] = member === "shadow" ? false : member === "items" || member === "leases" ||
      member === "submissions" || member === "service_decisions" || member === "reasons" ? [] : "x";
  }
  return body;
};

test("a success body carrying an unnamed member is accepted and parsed normally", () => {
  const read = Object.entries(BODIES).filter(([, d]) => d.role === "success");
  assert.ok(read.length >= 8, `only ${read.length} success bodies; broken read`);
  for (const [schema] of read) {
    const body = { ...minimal(schema), x: { anything: [1, 2, 3] } };
    assert.deepEqual(
      successProblems(schema, body).problems, [],
      `${schema}: an unknown member was a problem. SCOPE-3 binds every party — "within /n only optional members ` +
      `are added and readers ignore unknown ones" — and this client is a reader (attack M-1)`,
    );
  }
});

test("a success body missing a required member is a problem, so the scan is not vacuous", () => {
  const body = minimal("astra.plugins.bot-verdict/1");
  delete body.eligibility;
  assert.match(successProblems("astra.plugins.bot-verdict/1", body).problems.join("\n"), /`eligibility` is required/);

  const wrongSchema = minimal("astra.plugins.bot-ack/1");
  wrongSchema.schema = "astra.plugins.bot-registered/1";
  assert.match(successProblems("astra.plugins.bot-ack/1", wrongSchema).problems.join("\n"), /names schema/);
});

test("the wake hint's answer carries no `shadow` and is not asked for one", () => {
  assert.deepEqual(successProblems(SHADOW_EXEMPT, JSON.parse(WAKE_ACK_BODY)).problems, []);
});

test("an item whose stop status is `unavailable` is split out, and the rest are not", () => {
  const body = {
    schema: "astra.plugins.bot-gates/1", shadow: false,
    items: [
      { submission_id: "s1", fingerprint: "f1", stop_status: "no_stop", decisions: [] },
      { submission_id: "s2", fingerprint: "f2", stop_status: "unavailable", decisions: [] },
      { submission_id: "s3", fingerprint: "f3", stop_status: "stopped", decisions: [] },
    ],
  };
  const { answered, waiting } = splitGateItems(body);
  assert.deepEqual(answered.map((i) => i.submission_id), ["s1", "s3"]);
  assert.deepEqual(waiting.map((i) => i.submission_id), ["s2"]);
});

// ───────────────────────────────────────────────────────────────────────────
// The token
// ───────────────────────────────────────────────────────────────────────────

test("a job with no Actions token endpoint is refused, and not treated as a skip", () => {
  assert.equal(mintProblems({}).length, 2);
  assert.match(mintProblems({}).join("\n"), /id-token: write/);
  assert.equal(mintProblems({
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://x/?a=1", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
  }).length, 0);
});

test("a token minted outside environment plugins-service never leaves `mintToken`", async () => {
  const s = await stub(() => ok({}), { tokenClaims: { environment: "bot-state" } });
  try {
    await assert.rejects(
      () => mintToken({ env: s.env, log: journalLog(s.journal) }),
      /`environment` is "bot-state"/,
      "contract ID-34 pins `environment` to plugins-service. GitHub exposes no environment name to a step, so " +
      "the refusal is a read of the token's own claim and not of the runner",
    );
    // And the mask still went out: the token was in this process either way.
    assert.ok(s.journal.some((e) => e.kind === "log" && e.line.startsWith("::add-mask::")));
  } finally {
    await s.close();
  }
});

test("a token minted for another audience never leaves `mintToken`", async () => {
  const s = await stub(() => ok({}), { tokenClaims: { aud: "https://api.minice.ai/plugins/v1/author" } });
  try {
    await assert.rejects(() => mintToken({ env: s.env, log: journalLog(s.journal) }), /`aud` is/);
  } finally {
    await s.close();
  }
  assert.deepEqual(claimProblems({ aud: BOT_AUDIENCE, environment: ENVIRONMENT }), []);
});

test("`--claims` prints what OPEN-OPS-13 measures and never the token", () => {
  const claims = decodeClaims(fakeToken({ run_id: 17301999999, jti: "the-replay-key" }));
  const rows = claimsReport(claims);
  const text = rows.join("\n");
  assert.match(text, /job_workflow_ref = "mihailinl\/astra-registry[^"]*" \(string\)/);
  assert.match(text, /run_id = 17301999999 \(number\)/, "the JSON type is the measurement (§0.7 records it)");
  assert.match(text, /run_attempt = "1" \(string\)/);
  assert.match(text, /^jti sha256:[0-9a-f]{16} \(string\)$/m);
  assert.equal(text.includes("the-replay-key"), false, "ID-33 keys its replay refusal on `jti`");
  assert.equal(text.includes("eyJ"), false, "no part of the token appears");
});

// ───────────────────────────────────────────────────────────────────────────
// Calls
// ───────────────────────────────────────────────────────────────────────────

const client = (s, extra = {}) => {
  const errors = [];
  const c = createClient({
    workflow: "ingest", base: s.base, env: s.env, log: journalLog(s.journal, errors), ...extra,
  });
  c.errors = errors;
  return c;
};

const REGISTER = { repo: "someone/quiet", repository_id: "42", tag: "v1.0.0", trigger: "poll" };

test("a claim from the moderation table is refused locally, before any socket", async () => {
  const s = await stub(() => ok({}));
  try {
    const c = createClient({ workflow: "moderation", base: s.base, env: s.env, log: journalLog(s.journal) });
    await assert.rejects(
      () => c.call("claim", { wanted: 3 }),
      /is not an operation of the moderation workflow/,
      "BOT-91: the service refuses a call whose token's `job_workflow_ref` names the other workflow with " +
      "`token_refused`, and BOT-63 fails the run on that. Discovering it at the far end costs a run",
    );
    assert.equal(s.calls.length, 0, "nothing reached the service");
    assert.equal(s.tokens.length, 0, "and no token was minted for it");
  } finally {
    await s.close();
  }
});

test("the mask precedes first use", async () => {
  const s = await stub(() => ok({ schema: "astra.plugins.bot-registered/1", shadow: false, submission_id: "s1" }));
  try {
    const c = client(s);
    const answer = await c.call("register", REGISTER);
    assert.equal(answer.ok, true);

    const firstMask = s.journal.findIndex((e) => e.kind === "log" && e.line.startsWith("::add-mask::"));
    const firstAuthed = s.journal.findIndex((e) => e.kind === "request" && e.authorization !== null);
    assert.ok(firstMask >= 0, "no `::add-mask::` was written at all");
    assert.ok(firstAuthed >= 0, "no request carried the token, so there was nothing to mask it for");
    assert.ok(
      firstMask < firstAuthed,
      `the mask is entry ${firstMask} and the first request carrying the token is entry ${firstAuthed}. The runner's ` +
      "logs are public; a mask registered after the bytes have left is a mask for the next line",
    );
    // The token in the log is the token on the wire.
    const masked = s.journal[firstMask].line.slice("::add-mask::".length);
    assert.equal(s.journal[firstAuthed].authorization, `Bearer ${masked}`);
  } finally {
    await s.close();
  }
});

test("a redirect is refused, followed by nothing", async () => {
  const s = await stub(() => ({ status: 302, headers: { Location: "https://elsewhere.example/plugins/v1/bot/submissions" }, raw: "" }));
  try {
    const c = client(s);
    await assert.rejects(
      () => c.call("register", REGISTER),
      (e) => e instanceof ServiceRunFailure && /a redirect/.test(e.message),
      "registry plan BOT-20: the base is compiled in and no redirect is followed to another host",
    );
    assert.equal(s.calls.length, 1, "it did not retry a redirect, and it did not follow it");
    assert.equal(c.alerts.length, 1);
    assert.equal(c.alerts[0].operation, "register");
  } finally {
    await s.close();
  }
});

for (const token of ["token_refused", "replay"]) {
  test(`\`${token}\` fails the run with an alert`, async () => {
    const s = await stub(() => refusal(token, "no", {}, 401));
    try {
      const c = client(s);
      await assert.rejects(
        () => c.call("register", REGISTER),
        (e) => e instanceof ServiceRunFailure && e.token === token,
        "registry plan BOT-63",
      );
      assert.equal(c.alerts.length, 1, "one alert, naming the token");
      assert.match(c.alerts[0].detail, new RegExp(token));
      assert.equal(s.calls.length, 1, "a refused token is never retried");
    } finally {
      await s.close();
    }
  });
}

for (const [what, plan] of [
  ["`unavailable`", () => refusal("unavailable")],
  ["`rate_limited`", () => refusal("rate_limited", "slow down", { retry_after: 30 }, 429)],
  ["an HTML 404 with no refusal body", () => ({ status: 404, headers: { "Content-Type": "text/html" }, raw: "<html>no</html>" })],
]) {
  test(`${what} gives ${W_SERVICE_UNREACHABLE} after ${MAX_ATTEMPTS} attempts, with an alert`, async () => {
    const s = await stub(plan);
    try {
      const c = client(s);
      const answer = await c.call("register", REGISTER);
      assert.equal(answer.ok, false);
      assert.equal(answer.wait, W_SERVICE_UNREACHABLE, "contract ID-9");
      assert.equal(answer.attempts, MAX_ATTEMPTS, "registry plan BOT-63: at most 3 attempts per call per run");
      assert.equal(s.calls.length, MAX_ATTEMPTS);
      assert.equal(c.alerts.length, 1, "one alert per call, not one per attempt");
    } finally {
      await s.close();
    }
  });
}

test("retries send identical bytes, and a fresh token each time", async () => {
  const s = await stub(() => refusal("unavailable"));
  try {
    const c = client(s);
    await c.call("register", REGISTER);
    assert.equal(s.calls.length, MAX_ATTEMPTS);
    const bodies = new Set(s.calls.map((call) => call.raw));
    assert.equal(
      bodies.size, 1,
      `${bodies.size} distinct bodies over ${MAX_ATTEMPTS} attempts. The body is built once per CALL and ` +
      "re-sent byte for byte, so a retry cannot become a second, differently-worded request (BOT-63)",
    );
    const auths = new Set(s.calls.map((call) => call.authorization));
    assert.equal(
      auths.size, MAX_ATTEMPTS,
      "every attempt carries a freshly minted token. Contract ID-33 refuses a `jti` already seen, so a retry " +
      "re-sending the first attempt's token would be refused as the `replay` it is, and BOT-63 fails the run on " +
      "`replay`. One token per call (BOT-3) is a ceiling on reuse, not a licence to reuse across attempts",
    );
    assert.equal(s.tokens.length, MAX_ATTEMPTS);
  } finally {
    await s.close();
  }
});

test("an `unavailable` with `Retry-After` is a stated wait: silent once, loud twice", async () => {
  const s = await stub(() => refusal("unavailable", "the mirror has not fetched it", {}, 503, { "Retry-After": "30" }));
  try {
    const c = client(s);
    const first = await c.call("register", REGISTER);
    assert.equal(first.wait, W_SERVICE_UNREACHABLE);
    assert.equal(first.stated, true);
    assert.equal(first.retryAfter, "30");
    assert.equal(first.attempts, 1, "a stated wait is not retried: the service said when to come back");
    assert.deepEqual(
      c.alerts, [],
      "B-T3.6's W0 drill reaches exactly this on its first run after reg.80a — the service's mirror has not " +
      "fetched the new commit, so its content rule's outcome is `absent` rather than `differs`, it answers " +
      "`unavailable` with Retry-After 30, wakes a fetch and leaves the mode unchanged. A bot-side alert there " +
      "makes a walk record a failure of something it is not testing (attack m-1)",
    );

    const second = await c.call("register", REGISTER);
    assert.equal(second.wait, W_SERVICE_UNREACHABLE);
    assert.equal(c.alerts.length, 1, "the second stated wait in a run is the service not catching up");
    assert.match(c.alerts[0].detail, /second stated wait/);
  } finally {
    await s.close();
  }
});

test("an `unavailable` with no `Retry-After` alerts at once, which is how the two differ", async () => {
  const s = await stub(() => refusal("unavailable"));
  try {
    const c = client(s);
    const answer = await c.call("register", REGISTER);
    assert.equal(answer.wait, W_SERVICE_UNREACHABLE);
    assert.equal(answer.stated, undefined);
    assert.equal(c.alerts.length, 1, "no `Retry-After` is an outage, and the first one alerts");
  } finally {
    await s.close();
  }
});

test("`invalid`, `lease_not_held` and `conflict` come back to the caller, unalerted", async () => {
  for (const token of ["invalid", "lease_not_held", "conflict"]) {
    const s = await stub(() => refusal(token, "that is not right", {}, 409));
    try {
      const c = client(s);
      const answer = await c.call("register", REGISTER);
      assert.equal(answer.ok, false);
      assert.equal(answer.refused, token);
      assert.equal(answer.message, "that is not right");
      assert.equal(s.calls.length, 1, "a decided refusal is an answer and is not retried");
      assert.deepEqual(c.alerts, [], `${token} is the service answering, not the service failing`);
    } finally {
      await s.close();
    }
  }
});

test("`too_early` is a panel token: it gives a wait and an alert, never a guess", async () => {
  const s = await stub(() => refusal("too_early", "not yet", { retry_after: 60 }, 409));
  try {
    const c = client(s);
    const answer = await c.call("register", REGISTER);
    assert.equal(answer.wait, W_SERVICE_UNREACHABLE);
    assert.equal(answer.unknownToken, "too_early");
    assert.equal(c.alerts.length, 1);
    assert.equal(s.calls.length, 1);
  } finally {
    await s.close();
  }
});

test("a refusal body carrying an unnamed member is still read (SCOPE-3, the read side)", async () => {
  const s = await stub(() => refusal("invalid", "no", { x: { deep: true } }, 400));
  try {
    const c = client(s);
    const answer = await c.call("register", REGISTER);
    assert.equal(answer.refused, "invalid");
  } finally {
    await s.close();
  }
});

test("a `shadow: true` answer is returned as shadow and does not alert", async () => {
  const s = await stub(() => ok({ schema: "astra.plugins.bot-leases/1", shadow: true, leases: [] }));
  try {
    const c = client(s);
    const answer = await c.call("claim", { wanted: 3 });
    assert.equal(answer.ok, true);
    assert.equal(answer.shadow, true);
    assert.equal(answer.unreadable, false);
    assert.equal(c.withheld(answer), true, "BOT-92: nothing is committed for the work this answer names");
    assert.deepEqual(c.alerts, [], "shadow is the service working as ID-71 says, not a fault");
  } finally {
    await s.close();
  }
});

test("an answer missing `shadow` fails its schema: shadow, and an alert", async () => {
  const s = await stub(() => ok({ schema: "astra.plugins.bot-leases/1", leases: [] }));
  try {
    const c = client(s);
    const answer = await c.call("claim", { wanted: 3 });
    assert.equal(answer.ok, true);
    assert.equal(answer.shadow, true, "never a real answer");
    assert.equal(answer.unreadable, true);
    assert.equal(c.withheld(answer), true);
    assert.equal(c.alerts.length, 1);
    assert.match(c.alerts[0].detail, /`shadow` is required/);
  } finally {
    await s.close();
  }
});

test("a `shadow` that is not a boolean is not a shadow answer either", async () => {
  const s = await stub(() => ok({ schema: "astra.plugins.bot-leases/1", shadow: "false", leases: [] }));
  try {
    const c = client(s);
    const answer = await c.call("claim", { wanted: 3 });
    assert.equal(answer.shadow, true);
    assert.equal(answer.unreadable, true);
    assert.match(c.alerts[0].detail, /required boolean/);
  } finally {
    await s.close();
  }
});

test("a gates body of three items: one waits alone, two are acted on, the run stays green", async () => {
  const s = await stub(() => ok({
    schema: "astra.plugins.bot-gates/1", shadow: false,
    items: [
      { submission_id: "s1", fingerprint: "f1", stop_status: "no_stop", decisions: [] },
      { submission_id: "s2", fingerprint: "f2", stop_status: "unavailable", decisions: [] },
      { submission_id: "s3", fingerprint: "f3", stop_status: "stopped", decisions: [{ code: "M_DELIST" }] },
    ],
  }));
  try {
    const c = client(s);
    const answer = await c.call("gates", { items: [{ submission_id: "s1", fingerprint: "f1" }] });
    assert.equal(answer.ok, true, "an item-level `unavailable` never fails the call");
    assert.equal(answer.wait, undefined, "and it is not mapped to W_SERVICE_UNREACHABLE (0.13.0, n13)");
    assert.equal(answer.shadow, false);
    assert.deepEqual(answer.items.map((i) => i.submission_id), ["s1", "s3"]);
    assert.deepEqual(answer.waiting.map((i) => i.submission_id), ["s2"]);
    assert.deepEqual(
      c.alerts, [],
      "SERVE-93 cannot resolve that one stop after a restore. Treating it as a call-level `unavailable` would " +
      "lose all three, which is the loss n13 was about",
    );
    // No B.7 code is attached, and that absence is the rule: the contract names
    // none for this, `W_SERVICE_UNREACHABLE` is the call-level one and §4.2
    // says this is not that, and a code invented here would be a name three
    // parties do not have.
    assert.equal("wait" in answer.waiting[0], false);
  } finally {
    await s.close();
  }
});

test("a first attempt that fails and a second that answers is one call, one body, no alert", async () => {
  const s = await stub((call, n) =>
    n === 1
      ? { status: 500, headers: { "Content-Type": "text/html" }, raw: "<html>bad gateway</html>" }
      : ok({ schema: "astra.plugins.bot-registered/1", shadow: false, submission_id: "s1" }));
  try {
    const c = client(s);
    const answer = await c.call("register", REGISTER);
    assert.equal(answer.ok, true);
    assert.equal(answer.body.submission_id, "s1");
    assert.equal(answer.attempts, 2);
    assert.equal(new Set(s.calls.map((x) => x.raw)).size, 1);
    assert.deepEqual(c.alerts, [], "a call that succeeded on its second attempt succeeded");
  } finally {
    await s.close();
  }
});

test("the satisfiable direction: every ingest operation answers, and none of it alerts", async () => {
  const answers = {
    "/plugins/v1/bot/submissions": { schema: "astra.plugins.bot-registered/1", shadow: false, submission_id: "s1" },
    "/plugins/v1/bot/leases": { schema: "astra.plugins.bot-leases/1", shadow: false, leases: [] },
    "/plugins/v1/bot/verdicts": {
      schema: "astra.plugins.bot-verdict/1", shadow: false, token_state: "bound",
      minted_for_repository: true, eligibility: "eligible",
    },
    "/plugins/v1/bot/gates": { schema: "astra.plugins.bot-gates/1", shadow: false, items: [] },
    "/plugins/v1/bot/notice-status": {
      schema: "astra.plugins.bot-notice-status/1", shadow: false, status: "sent", accepted_at: "2026-09-21T00:00:00Z",
    },
    "/plugins/v1/bot/results": { schema: "astra.plugins.bot-ack/1", shadow: false, outcome: "accepted" },
  };
  const s = await stub((call) => ok(answers[call.url]));
  try {
    const c = client(s);
    assert.equal((await c.call("register", REGISTER)).body.submission_id, "s1");
    assert.equal((await c.call("claim", { wanted: 3 })).shadow, false);
    assert.equal((await c.call("verdict", {
      submission_id: "s1", binding_token: "t", repository_id: "42",
      repository_owner_id: "7", plugin_id: "someone.quiet",
    })).body.eligibility, "eligible");
    assert.deepEqual((await c.call("gates", { items: [] })).waiting, []);
    assert.equal((await c.call("noticeStatus", {
      submission_id: "s1", fingerprint: "f1", kind: "approved",
    })).body.status, "sent");
    assert.equal((await c.call("result", {
      submission_id: "s1", state: "published", reasons: [], decision_id: "d1", main_commit: "a".repeat(40),
    })).body.outcome, "accepted");

    assert.equal(s.calls.length, 6, "six operations, one attempt each");
    assert.deepEqual(c.alerts, [], "a check nobody can pass is not a check");
    assert.equal(
      new Set(s.calls.map((x) => x.authorization)).size, 6,
      "one token per call (BOT-3), and no two calls carried the same one",
    );
    assert.deepEqual([...new Set(s.calls.map((x) => x.method))], ["POST"]);
  } finally {
    await s.close();
  }
});

test("the moderation workflow's three operations answer, and `claim` is not among them", async () => {
  const answers = {
    "/plugins/v1/bot/moderation-work": {
      schema: "astra.plugins.bot-moderation-work/1", shadow: false, submissions: [], service_decisions: [],
    },
    "/plugins/v1/bot/results": { schema: "astra.plugins.bot-ack/1", shadow: false, outcome: "duplicate" },
    "/plugins/v1/bot/service-decision-results": {
      schema: "astra.plugins.bot-ack/1", shadow: false, outcome: "accepted",
    },
  };
  const s = await stub((call) => ok(answers[call.url]));
  try {
    const errors = [];
    const c = createClient({ workflow: "moderation", base: s.base, env: s.env, log: journalLog(s.journal, errors) });
    assert.deepEqual((await c.call("moderationWork")).body.submissions, []);
    assert.equal((await c.call("result", {
      submission_id: "s1", state: "stopped", reasons: [], recorded: [{ fingerprint: "f1", decision_id: "d1" }],
    })).body.outcome, "duplicate");
    assert.equal((await c.call("serviceDecisionResult", {
      service_decision_id: "d1", outcome: "applied", commit: "b".repeat(40),
    })).body.outcome, "accepted");

    assert.equal(s.calls[0].method, "GET", "§4.2: list moderation work sends the token only");
    assert.equal(s.calls[0].raw, "");
    assert.equal(s.calls[0].contentType, null, "a GET with no body sends no Content-Type");
    assert.deepEqual(c.alerts, []);
    assert.deepEqual(Object.keys(OPERATIONS.moderation).sort(), ["moderationWork", "result", "serviceDecisionResult"]);
  } finally {
    await s.close();
  }
});

test("the default base is the compiled one, and no test's base leaked into it", () => {
  const c = createClient({ workflow: "ingest", env: {}, log: { log: () => {}, error: () => {} } });
  assert.equal(c.base, API_BASE);
  assert.equal(new URL(OPERATIONS.ingest.claim.path, c.base).toString(), "https://api.minice.ai/plugins/v1/bot/leases");
});
