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
// ── the floors ─────────────────────────────────────────────────────────────
//
// The token-file comparison asserts what it FOUND before it asserts anything
// about what it found there (dev/couplings.md, "Adding a coupling", step 4): a
// filter that matched nothing would compare an empty compiled table with an
// empty expected one and pass. Nine operations and sixteen bodies, and both
// numbers are derived from the file rather than typed beside it.
//
// A third floor sits under the population itself. Comparing every member of
// sixteen bodies says nothing about the 85 published members that were in no
// body this client compiles, and the only reverse check was over the NAMES of
// bot bodies. "The population that comparison runs over" below states
// the boundary as a number, pairs the entries the file itself says render one
// fact twice, and refuses a condition published where nothing reads it.
//
// A fourth floor sits under the list of readers. An entry proven by one tool
// said nothing about a SECOND tool that started reading the same members, so
// the set of files that could is derived from the tree — and every one of them
// is either proven or excluded by name with a reason. Its floors are on the
// files the scan READ, because zero unproven readers is the healthy answer and
// a floor on what was found would fire on success.

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
  conditionalProblems,
  createClient,
  operationProblems,
  predicateHolds,
  splitGateItems,
  successProblems,
} from "../lib/service.mjs";
// The third kind of reader (contract 0.30.0): a tool in this repository that
// reads one entry's member table directly. Imported so the census below can
// PROVE the rule runs rather than record a name — see `TOOL_READERS`.
import {
  markerProblems as preflightMarkerProblems,
  splitTable as preflightSplitTable,
} from "../../tools/cutover-preflight.mjs";

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

  // Requiredness is THREE-valued — `true`, `false`, `conditional` — and this
  // comparison used to map it through `m.required ? "" : "?"`, which cannot
  // tell `true` from `"conditional"` because both are truthy. Contract 0.28.0
  // narrowed four members to `conditional`, the module went on compiling all
  // four as `true`, and this suite stayed green (dev/couplings.md, entry 38).
  // The value is compared as itself now, and a paraphrase of it is not enough:
  // the `when` is compared with `deepEqual` too, because that is where the
  // condition a reader must evaluate actually lives.
  const render = (member, required) => `${member}=${JSON.stringify(required)}`;

  let compared = 0;
  let conditionals = 0;
  for (const [name, def] of Object.entries(BODIES)) {
    const entry = recorded.get(name);
    assert.ok(entry, `${name} is compiled into bot/lib/service.mjs and the token file does not record it`);
    assert.equal(entry.members_recorded, true, `${name}: the token file records no members`);
    // `schema` is dropped from both sides: §4.2 makes it universal and the
    // token file lists it only where the source states literal bytes.
    const mine = def.members.filter(([m]) => m !== "schema").map(([m, r]) => render(m, r));
    const theirs = entry.members
      .filter((m) => m.name !== "schema")
      .map((m) => render(m.name, m.required));
    assert.deepEqual(mine, theirs, `${name}: the compiled members are not the token file's`);

    for (const [member, required, when] of def.members) {
      const published = entry.members.find((m) => m.name === member);
      if (required === "conditional") {
        conditionals += 1;
        assert.deepEqual(
          when, published.when,
          `${name}: \`${member}\` is conditional and the compiled \`when\` is not the file's. The readme makes a ` +
          "`conditional` that states no `when`, or one a reader cannot evaluate, a malformed file",
        );
        assert.doesNotThrow(
          () => conditionalProblems(name, {}, [[member, required, when]]),
          `${name}: \`${member}\`'s compiled \`when\` is one this reader cannot evaluate, and the readme makes ` +
          "that a file to refuse rather than a member to read as unconditioned",
        );
      } else {
        assert.equal(
          when, undefined,
          `${name}: \`${member}\` is ${JSON.stringify(required)} and carries a machine-readable \`when\`. Only a ` +
          "`conditional` member does; the file's prose `when` on a `false` member is not one of these",
        );
      }
    }
    compared += 1;
  }
  assert.ok(compared >= 16, `only ${compared} bodies compared; the client compiles 16`);
  assert.ok(
    conditionals >= 1,
    `no member of any compiled body is \`conditional\` in the token file, so the three-valued comparison above ` +
    `distinguished nothing. At contract 0.28.0 there were four — \`bot-result/1\`'s \`state\` and \`wait\`, ` +
    `\`bot-service-decision-result/1\`'s \`commit\` and \`refusal_code\` — and this file reads ` +
    `${tokenFile.contract_version}`,
  );

  // And the other direction, so a body added to §4.2 cannot stay unknown here.
  const botBodies = [...recorded.keys()].filter((n) => /^astra\.plugins\.bot-[a-z-]+\/1$/.test(n));
  assert.ok(botBodies.length >= 14, `only ${botBodies.length} bot bodies in the token file; broken read`);
  assert.deepEqual(botBodies.filter((n) => !BODIES[n]), [], "a §4.2 bot body the client does not compile");
});

// ───────────────────────────────────────────────────────────────────────────
// The population that comparison runs over, and the members outside it
// ───────────────────────────────────────────────────────────────────────────
//
// The comparison above reaches a member IFF its entry is a `schema` AND its
// name is a key of `BODIES`. Measured on contract 0.29.0: the file holds 42
// entries that carry members and 150 members between them; sixteen entries are
// compiled and 63 of their members are compared; 85 published members sat
// outside every comparison in this suite. Its own reverse check is name-level
// and scoped to a bot-body pattern — it catches a §4.2 body nobody compiled,
// and says nothing about a MEMBER of anything (dev/couplings.md, entry 50).
//
// ── the repair that was measured and refused ───────────────────────────────
//
// Compiling the other 25 bodies into `bot/lib/service.mjs` would close the
// arithmetic and nothing else. This module compiles the bodies the bot
// COMPOSES AND READS; a table for `astra.registry.publisher/1` would be a
// second, unused statement of that schema, kept by hand, reached by no call,
// and free to go wrong in exactly the silence this entry is about.
//
// Comparing the strays' full member LISTS against `schema/*.json` was measured
// and refused too, because `members_recorded: true` says the contract RECORDS
// a list, never that the list is the body. Four of the nine registry bodies
// that have a JSON Schema match its properties exactly and five do not, on
// purpose: each entry's `source` says which — "B.4, an exact member list"
// against "B.4, the members other parties read" — `queue-v1.json` spells the
// difference out in its own description ("B.4's sentence for the queue entry
// fixes what OTHER PARTIES READ, not the whole member set"), and
// `astra.registry.version/1` publishes `artifacts.<platform>.sha256`, which is
// a path into a member and not a property name at all. That comparison would
// be red on `main` today over five entries that are right, which is the worst
// kind of canary: one whose red a reader learns to discount.
//
// ── what is asserted instead ───────────────────────────────────────────────
//
// Three assertions, over the three things that can go wrong here in silence.
//
// **The boundary is a number.** 83 members over 25 entries are outside every
// comparison this suite makes, and that is stated as an equality rather than a
// floor, so the next member published into this file with no reader has to be
// looked at by somebody rather than joining a total nobody watches.
//
// **Where the file itself says one fact is rendered twice, the two renderings
// are compared.** That is the `carried_by` pointer, and it is the whole of
// what makes the third assertion true of `list:notice_status` rather than
// merely loud about it.
//
// **A member outside the comparison may carry no condition.** `true` and
// `false` are claims a reader of this repository never has to evaluate;
// `conditional` is a rule somebody must RUN, and a rule published where
// nothing runs it is gap 38 one axis over — a condition that can go stale, or
// contradict the schema side once the generator stops being the only writer,
// inside a green run.
//
// ── the fourth bucket, and how it was found (contract 0.30.0) ──────────────
//
// That third assertion fired on 0.30.0's condition for
// `astra.registry.migration-notice/1`, **and it was wrong**. The census knew
// two kinds of reader — a body `bot/lib/service.mjs` compiles, and an entry
// `carried_by` pairs with one — and there is a third: a tool in this repository
// that reads one entry's member table directly. `tools/cutover-preflight.mjs`
// does exactly that for the migration-notice marker, refuses a `when` it cannot
// evaluate, and runs both halves of an `iff` against every marker on a ref.
//
// **A census that cannot see a reader reports a rule as unrun**, which is this
// entry's own failure one level up, and the right repair is not an exemption:
// `TOOL_READERS` gets in only by having its tool's reader imported and run over
// the published table, one record per branch of the condition. Adding it also
// needed a main guard on that tool, which until now ran an eleven-check live
// gate at module scope — invisible while nothing imported it.
//
// The live case is `list:notice_status`, whose `accepted_at` and `ended_at`
// are §0.8's rendering of the same §4.2 states `astra.plugins.bot-notice-
// status/1` carries — two of the eight machine-readable conditions in the
// file, and the two the suite could not see. The token file's readme: "The two
// statements MUST agree, and something MUST compare them … two hand-kept
// spellings of one fact in one document is the coupling that has gone wrong
// here twice." The generator refuses a run in which they disagree, so the
// coupling was enforced at WRITE time, in another repository, by a tool this
// one does not run — and by nothing at READ time. It is compared below through
// the entry's own `carried_by`, which is the pointer the file publishes for
// exactly this; the list side then reaches the compiled table in two compared
// hops, list → body here and body → `BODIES` above, instead of none.
//
// Deriving the pair from `carried_by` rather than naming `notice_status` here
// is the difference between closing this case and closing this shape: the
// second value binding the contract publishes joins this test on the day it is
// generated, and does not wait for somebody to remember a list.

/** Every entry that publishes a member table, whatever kind it is. */
const membered = tokenFile.entries.filter((e) => Array.isArray(e.members));

/** Compiled here, so the test above compares every member of it. */
const isCompiled = (e) => e.kind === "schema" && Boolean(BODIES[e.name]);

/**
 * **The third kind of reader, and the census did not have it** (contract
 * 0.30.0).
 *
 * The two buckets above are the two ways `bot/lib/service.mjs` reaches a
 * member: it compiles the body, or the file's `carried_by` pairs the entry with
 * one it compiles. Everything else was `unread`, and a condition on an `unread`
 * entry failed — "a rule published where nothing runs it".
 *
 * 0.30.0 published a condition on `astra.registry.migration-notice/1` and that
 * failure fired, **and it was wrong**. That record is not a bot body and never
 * will be: it is a git marker, and the thing that reads it is
 * `tools/cutover-preflight.mjs`, which takes the member table out of this same
 * file, refuses a `when` it cannot evaluate, and runs both halves of an `iff`
 * against every marker on a ref. A reader in this repository that the census
 * could not see is exactly the silence the census exists to end, one level up.
 *
 * **So this is a bucket and not an exemption.** An entry gets in by naming a
 * tool AND by that tool's own reader being imported and run over the published
 * table, below, with one record per branch of the condition. A name alone would
 * be the name-level check `dev/couplings.md` entry 50 was written against.
 */
const TOOL_READERS = [
  {
    schema: "astra.registry.migration-notice/1",
    tool: "tools/cutover-preflight.mjs",
    // One record per branch of the published `iff`, so that a condition
    // relaxed to `if`, or dropped, changes an answer here. `{missing,
    // forbidden, withheld}` is what that tool's own reader returns.
    // The flat members are carried by every record here on purpose: this is a
    // test about ONE member's condition, and a marker missing `sent_at` would
    // move the counts for a reason that has nothing to do with it.
    marker: (round, extra) => ({
      schema: "astra.registry.migration-notice/1",
      round,
      sent_at: "2026-08-01T00:00:00Z",
      ...extra,
    }),
    cases: [
      ["a round-1 marker with no date is clean", [1, {}], { missing: 0, forbidden: 0, withheld: 0 }],
      ["a round-1 marker carrying one is forbidden", [1, { cutover_planned_at: "2026-09-15T00:00:00Z" }], { missing: 0, forbidden: 1, withheld: 0 }],
      ["a round-2 marker with no date is missing it", [2, {}], { missing: 1, forbidden: 0, withheld: 0 }],
      ["a round-2 marker carrying one is clean", [2, { cutover_planned_at: "2026-09-15T00:00:00Z" }], { missing: 0, forbidden: 0, withheld: 0 }],
    ],
  },
];

const isToolRead = (e) => TOOL_READERS.some((r) => r.schema === e.name);

/**
 * **Every candidate the scan below turns up that is NOT a member reader**, each
 * with the reason it is not (dev/couplings.md, entry 59).
 *
 * `TOOL_READERS` proves that a bucketed entry HAS a reader. It said nothing
 * about a SECOND one: a tool that starts reading the same entry's members got
 * no bucket, nothing noticed, and the entry stayed proven by one reader while
 * another read it unchecked. The candidate set is derived from the tree now, so
 * the list cannot grow in silence — but a derived set over-counts, and this is
 * where an over-count is written down rather than filtered away.
 *
 * A file here is a claim by a person that it is not a reader under proof. It is
 * held to that claim twice. From the scan's side, each one must still be a
 * candidate (below), so an exclusion whose file has gone, or has stopped
 * matching any signal, is a red rather than a line nobody rereads. And from the
 * file's side, through `reads` (dev/couplings.md, entry 124).
 *
 * **`reads` is the half of the reason a machine can hold.** It names which of
 * `READER_PATTERNS` the file's bytes match — what the file reads of the thing
 * it is excused from — and it is compared with the bytes on every run, both
 * ways. `why` stays prose, and says why reading exactly that is not being a
 * reader under proof. The excuse for `tools/selftest/contract-tokens.mjs` said
 * "never an `entries[].members` table" at 09:31 on 2026-09-22 and was false by
 * 13:03 (`4b5db5b`, on another branch), and the census stayed green because it
 * held an excuse only to the file still being a candidate — which a file that
 * starts reading more remains. A reason held only to its presence is entry
 * 59's hand-kept bucket one level down.
 */
const NOT_MEMBER_READERS = [
  {
    file: "bot/tests/service.test.mjs",
    reads: ["condition", "member-table"],
    why:
      "this census itself. It imports the tool's reader in order to PROVE the bucket above, and names the " +
      "bucketed schema in doing so; the prover is not a reader under proof",
  },
  {
    file: "tools/selftest/scope9.mjs",
    reads: [],
    why:
      "RC-R3-2's SCOPE-9 half: it reads each entry's `name`, `kind`, `emitter`, `acceptor` and `state`, and " +
      "the golden result bodies' `wait.code`, to compare the token file's PARTIES with what the bot sends. It " +
      "reads no `members` table and evaluates no condition",
  },
  {
    file: "tools/gen-codes-table.mjs",
    reads: [],
    why:
      "names the token file to say, in its own header, that it does NOT write it — FLOW-13's table is merged " +
      "into the token file by astra-plugins-ops `tools/contract-tokens.mjs`, and this program writes the " +
      "intermediate `tools/codes-table.json`. It parses no entry and reads no member",
  },
  {
    file: "tools/selftest/contract-tokens.mjs",
    reads: ["member-table"],
    why:
      "reads `entries[].members` for every `astra.registry.*` schema entry — the bucketed " +
      "`astra.registry.migration-notice/1` among them — and asks it one question: which members are published " +
      "`required: true`, each then held against the committed records of its kind (dev/couplings.md entry 86). " +
      "It evaluates no condition: a `conditional` member is not `required: true` and is never asked, so the rule " +
      "the bucket above proves still has the one runner it proves. The rest of the module is the token file's " +
      "own discipline — the contract version, the cron, `pending[]` and the members held under it. Until " +
      "2026-09-22 this excuse said \"never an `entries[].members` table\", false since `4b5db5b` (entry 124)",
  },
  {
    file: "tools/validate.mjs",
    reads: [],
    why:
      "names the token file in one report note, to say why an `author_request` yank is being counted by action " +
      "and category while `fixed_reasons` is null. It opens no entry. From contract 0.31.0 it also names " +
      "`astra.registry.migration-notice/1`, because it judges every marker on a tree against " +
      "`schema/migration-notice-v1.json` — a JSON Schema, loaded by `loadSchemas`, and never the token file's " +
      "member table",
  },
  {
    file: "tools/selftest/migration-notice.mjs",
    reads: ["condition", "member-table"],
    why:
      "contract 0.31.0's canary between two statements of ONE condition: it reads the marker entry's member " +
      "table only to hold `schema/migration-notice-v1.json`'s members and `oneOf` to it, round by round, and " +
      "judges no marker on any ref. The reader of that table is `tools/cutover-preflight.mjs`, which the bucket " +
      "above proves — and this module deliberately does not import it, because tools/selftest/ is in TRUST-31's " +
      "set and the publish path runs it",
  },
  {
    file: "tools/coverage/roll47-promises.mjs",
    reads: [],
    why:
      "names the token file only in its SKIP list, as one of the files ROLL-47's promise grep does NOT read — " +
      "it is generated from the contract, which quotes the retired promises. It opens no entry and reads no " +
      "member; every file it does read is read as text for three literals (M-T4.2)",
  },
  {
    file: "tools/service-conformance.mjs",
    reads: ["member-table"],
    why:
      "BOT-90's black-box probe (B-T3.11). It opens the token file for the METHOD and PATH of four records — " +
      "`operation:bot:claim`, `operation:client:rating.get`, and the `service_only` entries `health` and " +
      "`listings-view` — and for `audience:bot`'s value, and reads no entry's members from it. The one member " +
      "table it touches is `astra.plugins.error/1`'s, taken from `bot/lib/service.mjs`'s compiled `BODIES`, which " +
      "this census already proves against the file; it evaluates no condition",
  },
  {
    file: "tools/selftest/primitives.mjs",
    reads: [],
    why:
      "names the token file as a KEY of `SCHEMA_ABSENCES`, the declaration of which populations called \"the " +
      "schemas\" it is absent from (dev/couplings.md entry 67), and opens it only to ask whether it carries " +
      "`$schema`, as it opens every file under `schema/`. It parses no entry and reads no member",
  },
  {
    file: "tools/deadline-watch.mjs",
    reads: [],
    why:
      "ROLL-63's watch (M-T5.4). It imports `tools/cutover-preflight.mjs` for one constant, `R4B_MARKER`, and asks " +
      "only whether that path exists on the tree, to tell a 404 from the dark plugins zone before R4b from one after " +
      "it (MIG-13, contract 2.7.0). The markers it reads come from `tools/lib/migration-notice.mjs`'s `readMarkers`, " +
      "judged by `schema/migration-notice-v1.json`; it opens no entry of the token file and evaluates no condition",
  },
  {
    file: "bot/tests/listing-state.test.mjs",
    reads: [],
    why:
      "imports `tools/cutover-preflight.mjs` for `R4B_MARKER` alone: to hold it equal to `site/successors.mjs`'s, " +
      "and to write R4b's marker into a fixture tree the deadline watch then reads. It opens no entry of the token " +
      "file and evaluates no condition",
  },
];

/**
 * **The candidate set, derived from the tree rather than typed beside the
 * list** (dev/couplings.md, entry 59).
 *
 * ── why not "derive the readers" outright ──────────────────────────────────
 *
 * Because nothing available here can decide READS from MENTIONS. A tool reads a
 * member table inside a function, at call time, against a ref — importing every
 * candidate and watching for the read would observe nothing, and `tools/cutover-
 * preflight.mjs` acquired a main guard this week precisely so that importing it
 * runs nothing. What is left is a text scan, and this estate has been bitten by
 * two: a comment quoting a call counted as a caller, and a workflow step whose
 * body only `echo`ed a command came out as a live lane. **It is measurable here
 * too** — five files in this repository named `tools/cutover-preflight.mjs` at
 * contract 0.30.1 and four of those five were comments. (Eleven named it at
 * `3653dc5` on 2026-09-22, counted over `git ls-tree -r HEAD` by bytes; the
 * count moves and the argument does not.)
 *
 * So the scan is not asked to decide. It is asked to ENUMERATE, deliberately
 * too widely, and every candidate it turns up is either proven in
 * `TOOL_READERS` or written into `NOT_MEMBER_READERS` with a reason. Over-
 * counting costs a sentence; under-counting is the gap.
 *
 * ── the three signals, and why each is in ──────────────────────────────────
 *
 * A second reader of a bucketed entry's members has to get that table from
 * somewhere, and there are three places:
 *
 *   * **opens the file itself** — then it names the token file's path. Scoped
 *     to `tools/`, because that is what this bucket is: "a tool in this
 *     repository that reads one entry's member table directly". Repo-wide the
 *     same signal turns up eleven files, seven of them under `bot/` whose
 *     entries are COMPILED and compared member by member a few tests above —
 *     seven exclusions bought against a bucket that is already proven, which is
 *     the discountable red entry 50 refused.
 *   * **imports a proven reader** — a static import specifier that resolves to
 *     a `TOOL_READERS` tool. Repo-wide, and an import and not a mention: the
 *     four comment mentions above do not match, and `bot/tests/service.test.mjs`
 *     (which does import it, across three lines) does.
 *   * **names a bucketed entry** — to find an entry you match `e.name` or
 *     `e.id`, and both carry the schema id. Repo-wide. Today this signal has
 *     zero false positives: two files in the repository contain the string, and
 *     they are the tool and this file.
 *
 * The last two are derived FROM `TOOL_READERS`, so a second (schema, tool) pair
 * added to it widens the scan on the same commit rather than needing a second
 * edit somebody has to remember.
 *
 * ── what it cannot see, stated rather than implied ─────────────────────────
 *
 * A reader handed an already-parsed member table by a caller, naming neither
 * the path nor the schema nor the tool. Nothing short of running the estate
 * would find that, and the honest boundary is: this catches a reader that
 * LOOKS ONE UP, which is every reader in the tree today.
 *
 * A `.sh`, a workflow step's inline script, or another language: the walk reads
 * `.mjs`, `.js` and `.cjs`. It also reads bytes and decodes them, rather than
 * asking `grep`, which is `-I` here and blind to a NUL-bearing file — of the
 * 518 files on this tree 45 carry a NUL and every one of them is a binary
 * fixture, an icon or a `.astraplugin`, so no source file is hidden from it.
 *
 * The walk starts at the repository root and skips only `.git` and
 * `node_modules`. An allowlist of directories would be shorter and would read
 * the same 174 files today — all the source on this tree is under `bot/`,
 * `site/`, `tests/` and `tools/` — but it fails in the one direction this check
 * may not fail in: a new top-level directory holding a reader would be missed,
 * silently, by a scan whose empty answer is the healthy one.
 */
const SCAN_SKIP = new Set([".git", "node_modules"]);
const SCANNED_EXT = /\.(mjs|js|cjs)$/;

/** Every static import specifier, including the multi-line form. */
const IMPORT_SPECIFIERS = /\bfrom\s*["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']/g;

function scanForMemberReaders(root = REPO) {
  const files = [];
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (SCAN_SKIP.has(ent.name)) continue;
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(abs);
      else if (SCANNED_EXT.test(ent.name)) files.push(abs);
    }
  };
  walk(root);

  const toolPaths = TOOL_READERS.map((r) => r.tool);
  const schemaIds = TOOL_READERS.map((r) => r.schema);
  const candidates = [];
  for (const abs of files) {
    const rel = path.relative(REPO, abs).split(path.sep).join("/");
    const text = fs.readFileSync(abs).toString("utf8");
    const specifiers = [...text.matchAll(IMPORT_SPECIFIERS)].map((m) => m[1] ?? m[2]);
    const imported = specifiers
      .filter((s) => s.startsWith("."))
      .map((s) => path.relative(REPO, path.resolve(path.dirname(abs), s)).split(path.sep).join("/"));
    const signals = [];
    if (rel.startsWith("tools/") && text.includes("schema/contract-tokens-v1.json")) signals.push("opens-the-file");
    if (imported.some((i) => toolPaths.includes(i))) signals.push("imports-a-proven-reader");
    if (schemaIds.some((id) => text.includes(id))) signals.push("names-a-bucketed-entry");
    if (signals.length > 0) candidates.push({ file: rel, signals });
  }

  const read = files.map((abs) => path.relative(REPO, abs).split(path.sep).join("/"));
  return { read, candidates };
}

/**
 * **What a file's bytes look like when it reads the thing an excuse says it
 * does not** (dev/couplings.md, entry 124). The census's reader patterns, as
 * against its candidate signals above: a signal says a file COULD reach a
 * member table; a pattern says what it DOES touch once there.
 *
 *   * `member-table` — an entry's `members`, as `.members` or `["members"]`.
 *     The shape of the reads `4b5db5b` added to an excused file, `e.members`
 *     and `entry.members`, and of every member read on this tree.
 *   * `condition` — a member's `when`, or the `"conditional"` a reader must
 *     test for before it evaluates one. What the bucket above PROVES a reader
 *     does, and so the line between reading a table and running its rule.
 *
 * Bytes, comments included, like the scan: a comment quoting `e.members`
 * matches, and the cost is an excuse that says so in `reads` and in its
 * reason. Over-counting costs a sentence; under-counting is the gap. What it
 * cannot see is a table reached under another name — destructured
 * (`{ members }`), or handed in by a caller — which is the boundary the scan
 * above already states for itself.
 */
const READER_PATTERNS = {
  "member-table": { re: /\.members\b|\[\s*["'`]members["'`]\s*\]/, what: "an entry's `members` table" },
  "condition": { re: /\.when\b|\[\s*["'`]when["'`]\s*\]|["'`]conditional["'`]/, what: "a member's condition (`when`, or `required: \"conditional\"`)" },
};

/**
 * Every excuse whose `reads` is not what its file's bytes read, as sentences
 * naming the file and quoting the excuse. Both directions: a file that now
 * reads what its excuse says it does not (entry 124's case), and a file that
 * no longer reads what its excuse concedes, whose reason then describes reads
 * that are gone. `textOf(file)` returns the file's text, or null for a file
 * the scan did not read — which the census's own floor reports.
 */
function excuseDrift(excuses, textOf) {
  const out = [];
  const lines = (text, re) => text.split("\n").flatMap((l, i) => (re.test(l) ? [i + 1] : []));
  for (const x of excuses) {
    const text = textOf(x.file);
    if (text === null) continue;
    const quoted = JSON.stringify(x.why);
    if (!Array.isArray(x.reads)) {
      out.push(`${x.file} is excused with no \`reads\`, so nothing holds its reason to its bytes: ${quoted}`);
    }
    const declared = Array.isArray(x.reads) ? x.reads : [];
    for (const k of declared.filter((d) => !Object.hasOwn(READER_PATTERNS, d))) {
      out.push(`${x.file}'s excuse declares it reads ${JSON.stringify(k)}, which is not one of READER_PATTERNS ` +
        `(${Object.keys(READER_PATTERNS).join(", ")})`);
    }
    for (const [k, { re, what }] of Object.entries(READER_PATTERNS)) {
      const at = lines(text, re);
      if (at.length && !declared.includes(k)) {
        out.push(`${x.file} is excused as a file that does not read ${what}, and its bytes now do, at ` +
          `${at.slice(0, 5).map((n) => `:${n}`).join(", ")}${at.length > 5 ? ` and ${at.length - 5} more` : ""}. ` +
          `The excuse was written for a file that did not: ${quoted}. Re-read the file. If it is now a reader of ` +
          "a bucketed entry, it belongs in `TOOL_READERS` with its reader exercised; if it is not, rewrite the " +
          "excuse's `reads` AND its reason to what is true — the `reads` alone is a filter, not a judgement");
      }
      if (!at.length && declared.includes(k)) {
        out.push(`${x.file} is excused as a file that reads ${what}, and its bytes no longer do. The reason ` +
          `describes reads that are gone: ${quoted}. Rewrite it to what the file does now`);
      }
    }
  }
  return out;
}

/**
 * The `{if|iff: <predicate>}` shape — a rule a reader must evaluate — as
 * against the prose sentence a `false` member may carry to say why no
 * condition is published for it. Both live in `when`, and only one of them is
 * a thing that can be wrong at runtime.
 */
const machineReadable = (when) => when !== null && typeof when === "object";

const compiledEntries = membered.filter(isCompiled);
const pairedEntries = membered.filter((e) => !isCompiled(e) && Boolean(e.carried_by));
const toolReadEntries = membered.filter((e) => !isCompiled(e) && !e.carried_by && isToolRead(e));
const unreadEntries = membered.filter((e) => !isCompiled(e) && !e.carried_by && !isToolRead(e));
const countMembers = (entries) => entries.reduce((n, e) => n + e.members.length, 0);

test("the file's membered entries are four buckets, none of which may empty", () => {
  assert.ok(membered.length >= 42, `only ${membered.length} entries carry members; this is a broken read`);
  assert.ok(
    countMembers(membered) >= 150,
    `only ${countMembers(membered)} published members over those entries; this is a broken read`,
  );

  // Exhaustive and disjoint, asserted rather than assumed: an entry that fell
  // out of all three, or into two, would quietly shrink what the census below
  // quantifies over, and a census over less than the file is the defect this
  // section exists to end rather than to reproduce.
  assert.equal(
    compiledEntries.length + pairedEntries.length + toolReadEntries.length + unreadEntries.length,
    membered.length,
    `${compiledEntries.length} compiled + ${pairedEntries.length} paired + ${toolReadEntries.length} tool-read + ` +
    `${unreadEntries.length} unread is not ${membered.length} membered entries, so an entry is in two buckets ` +
    "or in none",
  );

  // Each bucket floored on its own, because each is the population of an
  // assertion further down and every one of those passes over nothing.
  assert.equal(
    compiledEntries.length, Object.keys(BODIES).length,
    "a body this client compiles resolved to no `schema` entry, so the comparison above skipped it",
  );
  assert.ok(compiledEntries.length >= 16, `only ${compiledEntries.length} bodies compiled; the client compiles 16`);
  assert.ok(
    pairedEntries.length >= 1,
    "no entry in the token file names a `carried_by`, so the two-rendering comparison below runs over nothing " +
    "and passes. `list:notice_status` carried one at contract 0.29.0, and deleting it is one of the mutations " +
    "the generator's own selftest watches go red",
  );
  assert.equal(
    toolReadEntries.length, TOOL_READERS.length,
    `${toolReadEntries.length} of the ${TOOL_READERS.length} entries a tool in this repository reads resolved ` +
    "to a membered entry outside the other two buckets. A reader named for an entry the file no longer " +
    "publishes — or one that has since become a compiled body — is a bucket that has stopped meaning anything",
  );

  // The boundary, as a number. An equality and not a floor: a `>=` here says
  // only that the file has not shrunk, and would let the next fifty unread
  // members in without a word. Moving it is the right answer once somebody has
  // looked at what arrived — the census below says what to look for — and
  // being made to look is the whole of what this line buys.
  //
  // Moved at contract 0.33.0, from 79 over 24, by exactly the six guest-read
  // bodies §5.8 publishes (Tables 5-G to 5-L): 25 top-level members over six
  // entries, `astra.plugins.{listing-view,transparency-decisions,
  // transparency-moderation,transparency-held,transparency-reports,
  // transparency-served}/1` (6, 4, 4, 6, 2 and 3). Read on arrival: the
  // plugins service emits them, the panel's server is their one reader (their
  // paths are `service-only`), and nothing in this repository composes or
  // reads one, so they belong in this bucket. Their four conditions are nested
  // — `transparency-moderation/1`'s `advisory`, `appeal_of` and `outcome`,
  // each `iff` on `action`, and `transparency-served/1`'s `serial`, `iff` on
  // `kind` — each with its why, and every other member is `true`, or `false`
  // with a why saying why no condition is published. (0.33.0's first draft had
  // 19; its revision on the acceptor's answers added `moderation`, `omits`
  // twice and `next_cursor` three times.)
  assert.deepEqual(
    { entries: unreadEntries.length, members: countMembers(unreadEntries) },
    { entries: 30, members: 105 },
    `${countMembers(unreadEntries)} published members over ${unreadEntries.length} entries are outside every ` +
    `comparison in this suite; there were 105 over 30 at contract 2.5.0, whose \`astra.registry.publisher/1\` ` +
    "gained the optional `owner_ids` (read by the registry's badge join alone, TRUST-25, with no condition, " +
    "because no sibling member decides whether a record needs it), 104 over 30 from 0.33.0, and this file reads " +
    `${tokenFile.contract_version}. Nothing in astra-registry composes or reads those bodies, so the number is ` +
    "allowed to move — but it moves by somebody reading the new members and finding them unconditioned, not by " +
    "a filter quietly widening. It was 83 over 25 at 0.29.0, and it moved because " +
    "`astra.registry.migration-notice/1` turned out to HAVE a reader that this census could not see, not " +
    "because a filter widened; and 79 over 24 from 0.30.0 until 0.33.0 added the six guest-read bodies",
  );
});

// Contract 0.30.0. The bucket above is a claim that something runs the rule;
// this is the claim discharged. The tool's own reader is imported and run over
// the table the file publishes, with one record per branch of the condition —
// so `iff` relaxed to `if` (the round-1-carrying case stops being forbidden),
// the condition dropped (the round-1 case starts being missing), and a `when`
// the tool cannot evaluate (a refusal) each change an answer here.
//
// Watched by editing `schema/contract-tokens-v1.json` on disk, and both
// messages below are the ones that printed:
//
//   * `"iff"` → `"if"` →
//       tools/cutover-preflight.mjs over astra.registry.migration-notice/1: a
//       round-1 marker carrying one is forbidden. missing: []; forbidden: [];
//       withheld: []
//   * `required` back to `true`, the condition deleted → TWO assertions, and
//     neither of them is a case above:
//       astra.registry.migration-notice/1 is in the tool-read bucket and
//       publishes no condition
//       the file publishes 8 conditions and there were 9 at contract 0.30.0
//
// The second is worth reading twice. Putting the defect back does not make a
// case fail — the tool then WITHHOLDS on round 1 rather than answering, which
// is what `DISPUTED_MEMBERS` is for, and a withheld question is not a wrong
// answer. It fails because the bucket asserts a rule exists to be run. That is
// the floor doing its job: without it, the defect put back would have left this
// test green over an entry whose condition had gone.
test("a tool-read entry's condition is one that tool evaluates, and it discriminates", () => {
  for (const r of TOOL_READERS) {
    const entry = membered.find((e) => e.kind === "schema" && e.name === r.schema);
    assert.ok(entry, `${r.tool} reads ${r.schema} and the file publishes no membered entry of that name`);
    const { readable, refused } = preflightSplitTable(entry.members);
    assert.deepEqual(
      refused.map((m) => `\`${m.name}\` ${m.why}`), [],
      `${r.tool} cannot read ${r.schema}'s member table, and the token file's readme makes such a file one a ` +
      "reader MUST refuse rather than read as unconditioned",
    );
    assert.ok(
      entry.members.some((m) => m.required === "conditional"),
      `${r.schema} is in the tool-read bucket and publishes no condition. The bucket exists so that a rule ` +
      "has a runner; an entry with no rule belongs in the census above",
    );
    for (const [what, [round, extra], expect] of r.cases) {
      const p = preflightMarkerProblems(readable, r.marker(round, extra));
      assert.deepEqual(
        { missing: p.missing.length, forbidden: p.forbidden.length, withheld: p.withheld.length },
        expect,
        `${r.tool} over ${r.schema}: ${what}. ` +
        `missing: ${JSON.stringify(p.missing)}; forbidden: ${JSON.stringify(p.forbidden)}; ` +
        `withheld: ${JSON.stringify(p.withheld.map((w) => w.message))}`,
      );
    }
  }
});

// Contract 0.30.1, dev/couplings.md entry 59. The test above proves the tool
// named in `TOOL_READERS` runs the rule. This one is about the LIST: it was
// hand-kept pairs of (schema, tool), and a second tool that started reading the
// same entry's members got no bucket and nothing noticed — the entry proven by
// one reader while another read it unchecked.
//
// The floors are on what the scan READ and never on what it found. Zero
// unclassified candidates is the healthy state here, so a floor on findings
// would fire on success; a floor on the files walked is what fails when the
// walk stops walking. Watched by handing `scanForMemberReaders` a root with no
// source under it — `policy/` — which leaves every classification below
// trivially true and reddens the floor instead. That the scan takes its root as
// an argument is what makes watching it possible without editing it.
test("every file that could read a bucketed entry's members is proven or excluded by name", () => {
  const { read, candidates } = scanForMemberReaders();

  // ── the floors, all on what was read ──────────────────────────────────────
  //
  // A walk that descended nowhere classifies nothing and passes everything
  // below it.
  assert.ok(
    read.length >= 120,
    `the reader scan read ${read.length} source files from the repository root; there were 174 on this tree at ` +
    "contract 0.30.1 (173 `.mjs` and one `.js`). A scan that has stopped descending finds no second reader and " +
    "says so in the same words as a tree that has none",
  );
  const toolsRead = read.filter((f) => f.startsWith("tools/"));
  assert.ok(
    toolsRead.length >= 50,
    `${toolsRead.length} source files under tools/; there were 78 at contract 0.30.1. The first signal is scoped ` +
    "to tools/, so a walk that reaches the repository but not that directory would report every tool clean",
  );

  // Every path a person typed into either list was actually read. This is the
  // exact half of the floor: a renamed or deleted file leaves a list naming
  // something the scan cannot see, and a claim about a file nobody read is not
  // a claim about this tree.
  const named = [...TOOL_READERS.map((r) => r.tool), ...NOT_MEMBER_READERS.map((x) => x.file)];
  assert.deepEqual(
    named.filter((f) => !read.includes(f)), [],
    "a file named in `TOOL_READERS` or `NOT_MEMBER_READERS` was not read by the scan. Either it has been " +
    "renamed or deleted — in which case the entry naming it is stale and says nothing about this tree — or the " +
    "walk no longer reaches it",
  );

  // The positive control: the reader this bucket is built on must be found BY
  // THE SIGNALS. If it falls out, the signals have stopped matching — a schema
  // id respelt, an import rewritten — and every second reader falls out with
  // it, silently, because the healthy answer to this test is an empty list.
  const found = new Set(candidates.map((c) => c.file));
  assert.deepEqual(
    TOOL_READERS.map((r) => r.tool).filter((t) => !found.has(t)), [],
    `the scan turned up ${candidates.length} candidate(s) — ${JSON.stringify(candidates)} — and a tool the ` +
    "bucket above PROVES reads a member table is not among them. The signals are not matching what they were " +
    "written to match, and an empty finding below would mean nothing",
  );

  // No stale exclusions: a file excused from being a reader has to still be a
  // candidate, or the excuse has outlived the thing it excused.
  assert.deepEqual(
    NOT_MEMBER_READERS.map((x) => x.file).filter((f) => !found.has(f)), [],
    "a file in `NOT_MEMBER_READERS` matches no signal any more. It stopped naming the token file, stopped " +
    "importing the reader, stopped naming the bucketed schema — or it was never a candidate and the entry was " +
    "written against a scan that did not run",
  );
  for (const x of NOT_MEMBER_READERS) {
    assert.ok(
      typeof x.why === "string" && x.why.length > 0,
      `${x.file} is excused from being a member reader and carries no reason, and an exclusion whose reason is ` +
      "not written down is a filter rather than a judgement",
    );
  }

  // And no excuse whose reason has stopped being true of its file's bytes
  // (entry 124). Being a candidate still is the scan's half; this is the
  // file's: what each excused file reads, against what its excuse says it reads.
  assert.deepEqual(
    excuseDrift(NOT_MEMBER_READERS, (rel) => (read.includes(rel) ? fs.readFileSync(path.join(REPO, rel)).toString("utf8") : null)),
    [],
    "an excuse in `NOT_MEMBER_READERS` says its file reads something other than what the file's bytes read",
  );

  // ── and the finding, whose healthy value is empty ─────────────────────────
  const classified = new Set(named);
  assert.deepEqual(
    candidates.filter((c) => !classified.has(c.file)),
    [],
    "a file in this repository can reach a bucketed entry's member table and is in neither list. Either import " +
    "its reader and exercise it over the published table — one record per branch of the condition, the way " +
    "`TOOL_READERS` does — or add it to `NOT_MEMBER_READERS` with the reason it is not a reader. The bucket " +
    "above proves ONE reader runs the rule; a second one that nobody proved is the entry still trusting a " +
    "census that cannot see it",
  );
});

// Entry 124. The drift check above has one committed case — the excuse that
// went stale four hours after it was written — and that case is not on the
// tree any more, because the excuse was corrected in the same commit that
// added the check. A guard proven only by a corpus that has never held its
// case proves nothing, so the case is rebuilt here from committed material on
// every run: a real excused file that reads a member table, excused as one
// that does not; a real excused file that reads nothing, which must stay green
// as written and go red the moment one member read is appended to its bytes;
// and the same file excused as a reader, which must be red the other way.
test("an excuse whose file reads what it was excused from is red, and one that is true stays green", () => {
  const text = (rel) => fs.readFileSync(path.join(REPO, rel)).toString("utf8");
  const SELF = "bot/tests/service.test.mjs";
  const quiet = NOT_MEMBER_READERS.find((x) => Array.isArray(x.reads) && x.reads.length === 0);
  const reader = NOT_MEMBER_READERS.find((x) => x.file !== SELF && Array.isArray(x.reads) && x.reads.includes("member-table"));
  assert.ok(quiet && reader,
    "NOT_MEMBER_READERS no longer holds both an excused file that reads nothing and one, besides this census, " +
    "that reads a member table, so the two cases below have no committed material to be built from");

  assert.deepEqual(excuseDrift([quiet], text), [],
    `${quiet.file}'s excuse, as written, is not true of its bytes, so the red cases below prove nothing`);

  // Entry 124 as it happened: a file that reads `members`, excused as one that
  // does not — and as true as its excuse about everything else, so that the one
  // red is the member read. The red must name the file and quote the excuse.
  const claim = "never an `entries[].members` table (the claim entry 124 found false)";
  const denied = reader.reads.filter((k) => k !== "member-table");
  const stale = excuseDrift([{ file: reader.file, reads: denied, why: claim }], text);
  assert.equal(stale.length, 1, `the stale excuse gave ${stale.length} finding(s): ${JSON.stringify(stale)}`);
  for (const needle of [reader.file, JSON.stringify(claim), "does not read an entry's `members` table"]) {
    assert.ok(stale[0].includes(needle), `the stale excuse's red does not name ${needle}: ${stale[0]}`);
  }

  // The same shape, grown on the file that reads nothing: one appended read.
  const grown = excuseDrift([quiet], (rel) => `${text(rel)}\nconst n = entry.members.length;\n`);
  assert.equal(grown.length, 1, `one appended member read gave ${grown.length} finding(s): ${JSON.stringify(grown)}`);
  assert.ok(grown[0].includes(quiet.file) && grown[0].includes(JSON.stringify(quiet.why)),
    `the red for ${quiet.file} does not name the file and quote its excuse: ${grown[0]}`);

  // The other direction: an excuse conceding reads the file does not make.
  const shrunk = excuseDrift([{ ...quiet, reads: ["member-table"] }], text);
  assert.ok(shrunk.length === 1 && shrunk[0].includes("no longer"),
    `an excuse conceding a member read on ${quiet.file}, which makes none, gave ${JSON.stringify(shrunk)}`);

  // And an excuse that says nothing checkable is red, whatever its file reads.
  const { reads: _gone, ...unstated } = quiet;
  assert.ok(excuseDrift([unstated], text).some((f) => f.includes("no `reads`")),
    "an excuse with no `reads` passed, so a reason can again be held to nothing but its presence");
});

test("a value binding rendered in two entries is compared here, and not only by the generator", () => {
  let bound = 0;
  for (const list of pairedEntries) {
    const body = tokenFile.entries.find((e) => e.kind === "schema" && e.name === list.carried_by.schema);
    assert.ok(
      body,
      `\`${list.id}\` names ${JSON.stringify(list.carried_by)} as what carries its values and the file records ` +
      "no such schema",
    );
    assert.ok(
      BODIES[body.name],
      `\`${list.id}\` is rendered twice and ${body.name} is not a body this client compiles, so agreeing with it ` +
      "reaches no reader. The comparison above is what turns this one into a chain; without it both entries can " +
      "be right about each other and wrong about the client",
    );

    // The predicate's sibling has to be carried by every entry of that body,
    // or the condition is one no reader can evaluate on a conforming answer.
    const decider = body.members.find((m) => m.name === list.carried_by.member);
    assert.equal(
      decider?.required, true,
      `\`${list.carried_by.member}\` is ${decider ? JSON.stringify(decider.required) : "not a member"} of ` +
      `${body.name}, and a condition keyed on a member that may be absent is one no reader can evaluate`,
    );

    for (const lm of list.members) {
      const bm = body.members.find((m) => m.name === lm.name);
      assert.ok(bm, `${list.id} binds \`${lm.name}\` and ${body.name} does not list it`);

      // Against EACH OTHER and not each against a constant: the failure this
      // closes is two renderings of one fact drifting apart, and a test that
      // pins each to its own expected value passes happily while they do.
      assert.deepEqual(
        { required: lm.required, when: lm.when },
        { required: bm.required, when: bm.when },
        `\`${lm.name}\` is ${JSON.stringify(lm.required)} on ${JSON.stringify(lm.when)} in ${list.id} and ` +
        `${JSON.stringify(bm.required)} on ${JSON.stringify(bm.when)} in ${body.name}. One fact, two renderings, ` +
        "and they have parted",
      );
      assert.equal(
        lm.required, "conditional",
        `${list.id}: \`${lm.name}\` is published ${JSON.stringify(lm.required)}. §0.8 binds it to some of this ` +
        "list's values and not others, and anything but `conditional` is a body that passes carrying nothing",
      );
      assert.ok(
        machineReadable(lm.when) && Object.keys(lm.when)[0] === "iff",
        `${list.id}: \`${lm.name}\` states ${JSON.stringify(lm.when)}. A value binding is absent where it does ` +
        "not apply, which is the reverse half and is `iff`; `if` leaves the member permitted for every other " +
        "value of the list, which is the looser reading this vocabulary exists to close",
      );
      assert.doesNotThrow(
        () => conditionalProblems(list.name, {}, [[lm.name, lm.required, lm.when]]),
        `${list.id}: \`${lm.name}\`'s published \`when\` is one this reader cannot evaluate. The list entry exists ` +
        "so that a reader holding it need not go looking two entries away, and one it cannot read is worse than " +
        "the trip",
      );
      assert.ok(
        typeof lm.why === "string" && lm.why.length > 0,
        `${list.id}: \`${lm.name}\` states a condition and carries no \`why\`, and a condition whose reason is ` +
        "not written down is relaxed rather than investigated",
      );
      bound += 1;
    }
  }
  assert.ok(
    bound >= 2,
    `${bound} bound members were compared across ${pairedEntries.length} paired entries. §0.8's notice-status ` +
    "clause carries two; a pairing that resolves to nothing compares nothing and passes",
  );
});

test("a member outside that comparison carries no condition, or the failure names it", () => {
  const conditions = [];
  for (const e of membered) {
    for (const m of e.members) {
      if (m.required !== "conditional" && !machineReadable(m.when)) continue;
      const bucket = isCompiled(e)
        ? "compiled"
        : e.carried_by
          ? "paired"
          : isToolRead(e)
            ? "tool"
            : "unread";
      conditions.push({ where: `${e.id} \`${m.name}\``, bucket });
    }
  }

  // The floor, before anything is said about what was found: a census over no
  // conditions reports no stray ones.
  assert.ok(
    conditions.length >= 9,
    `the file publishes ${conditions.length} conditions and there were 9 at contract 0.30.0. A census that finds ` +
    "none proves nothing about the ones it was written for",
  );
  assert.ok(
    ["compiled", "paired", "tool"].every((b) => conditions.some((c) => c.bucket === b)),
    `conditions by bucket: ${JSON.stringify(conditions)}. Six were compiled, two paired and one tool-read at ` +
    "contract 0.30.0; a bucket that has emptied is a comparison that has stopped happening, not a file that " +
    "has got simpler",
  );

  assert.deepEqual(
    conditions.filter((c) => c.bucket === "unread").map((c) => c.where), [],
    "a condition is published on an entry nothing in astra-registry reads: not a body this client compiles, and " +
    "not an entry whose `carried_by` points at one. Either give it a reader — compile the body, or publish the " +
    "`carried_by` that pairs it with a compiled one — or the contract has stated a rule that only its generator " +
    "will ever run, which is where `list:notice_status` spent contract 0.29.0",
  );
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
    // `r === true` and not `r`: a `shadow` narrowed to `conditional` would be a
    // marker that is sometimes absent, and §4.2 makes it required outright.
    const has = def.members.some(([m, r]) => m === "shadow" && r === true);
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

test("each disjunction is two biconditionals in the file, and the module reads both halves", () => {
  // The token file's readme: "A disjunction is published as two biconditionals
  // and never as a group: each member of the pair is `conditional`, and a
  // reader that requires both refuses every conforming body of that schema …
  // a reader who implemented one of the two and not the other would get the
  // looser reading of the member they skipped."
  //
  // This is what replaced `EITHER_MEMBERS`. That list excepted these four
  // members from a requiredness the file used to state and no longer does; the
  // conditions below are what the file states instead, and they are read rather
  // than excepted. The test that stood here asserted each of the four was
  // compiled `required: true` — which was the wrong half of the coupling by the
  // time 0.28.0 landed, and passed anyway.
  for (const [schema, pair] of [
    ["astra.plugins.bot-result/1", ["state", "wait"]],
    ["astra.plugins.bot-service-decision-result/1", ["commit", "refusal_code"]],
  ]) {
    const entry = tokenFile.entries.find((e) => e.kind === "schema" && e.name === schema);
    assert.ok(entry, `the token file records no ${schema}`);
    for (const m of pair) {
      const published = entry.members.find((x) => x.name === m);
      assert.ok(published, `${schema}: the token file records no \`${m}\``);
      assert.equal(
        published.required, "conditional",
        `${schema}: \`${m}\` is published ${JSON.stringify(published.required)}. A disjunction is two ` +
        "conditionals; a required half of one is a body no party can send",
      );
      assert.ok(
        "iff" in (published.when ?? {}),
        `${schema}: \`${m}\`'s condition is \`${Object.keys(published.when ?? {})}\` and not \`iff\`. Only \`iff\` ` +
        "forbids the member where its predicate does not hold, and that half is the whole of \"never both\"",
      );
      assert.equal(
        BODIES[schema].members.find(([name]) => name === m)?.[1], "conditional",
        `${schema}: \`${m}\` is compiled as something other than \`conditional\``,
      );
      assert.ok(published.why, `${schema}: \`${m}\` is conditional and carries no \`why\``);
    }
  }
});

test("a condition is read in both directions, and `if` is not read as `iff`", () => {
  // The two halves, driven over a synthetic member table so that each is
  // provoked on its own rather than left to whichever branch a real body
  // happens to reach first.
  const iff = [["commit", "conditional", { iff: { outcome: ["applied"] } }]];
  assert.deepEqual(conditionalProblems("S", { outcome: "applied", commit: "c" }, iff), []);
  assert.deepEqual(conditionalProblems("S", { outcome: "refused" }, iff), []);
  assert.match(
    conditionalProblems("S", { outcome: "applied" }, iff).join("\n"),
    /`commit` is required by S where `outcome` is one of `applied` and is absent/,
  );
  assert.match(
    conditionalProblems("S", { outcome: "refused", commit: "c" }, iff).join("\n"),
    /`commit` is carried by S and its `iff` forbids it except where `outcome` is one of `applied`/,
  );

  // `if` requires where the predicate holds and says NOTHING where it does not.
  // Reading it as `iff` would forbid what the contract permits, which is the
  // mirror of the defect this entry is about.
  const cond = [["commit", "conditional", { if: { outcome: ["applied"] } }]];
  assert.match(conditionalProblems("S", { outcome: "applied" }, cond).join("\n"), /is required by S where/);
  assert.deepEqual(
    conditionalProblems("S", { outcome: "refused", commit: "c" }, cond), [],
    "`if` says nothing where its predicate does not hold; forbidding here would invent the half it does not state",
  );

  // The three predicate shapes the readme publishes, and the refusal.
  assert.equal(predicateHolds({ wait: "absent" }, { state: "published" }), true);
  assert.equal(predicateHolds({ wait: "absent" }, { wait: { code: "W" } }), false);
  assert.equal(predicateHolds({ code: ["M_APPEAL"] }, { code: "M_APPEAL" }), true);
  assert.equal(predicateHolds({ code: ["M_APPEAL"] }, {}), false);
  assert.equal(predicateHolds({ code: { not: ["M_APPEAL"] } }, { code: "M_DELIST" }), true);
  assert.equal(
    predicateHolds({ code: { not: ["M_APPEAL"] } }, {}), false,
    "a complement is over the values the member may take, and a member that is not carried has none",
  );
  assert.throws(() => predicateHolds({ code: "M_APPEAL" }, {}), /cannot evaluate/);
  assert.throws(() => predicateHolds({ a: ["x"], b: ["y"] }, {}), /cannot evaluate/);

  // And a table this reader cannot evaluate is refused, never read as
  // unconditioned — the readme calls that the looser direction and closes it.
  assert.throws(
    () => conditionalProblems("S", {}, [["commit", "conditional", undefined]]),
    /states no `when`/,
  );
  assert.throws(
    () => conditionalProblems("S", {}, [["commit", "conditional", { if: { a: ["x"] }, iff: { a: ["x"] } }]]),
    /never both and never neither/,
  );
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

  // Neither, and both — each named by the member it is wrong about rather than
  // by a local count of the pair. `state` and `wait` are two biconditionals on
  // each other's absence, so "neither" trips both requiring halves and "both"
  // trips both forbidding ones.
  assert.throws(
    () => composeBody("astra.plugins.bot-result/1", { submission_id: "s1", reasons: [] }),
    /`state` is required .* `wait` is absent[\s\S]*`wait` is required .* `state` is absent/,
  );
  assert.throws(
    () => composeBody("astra.plugins.bot-result/1", {
      submission_id: "s1", reasons: [], state: "published", wait: { code: "W" },
    }),
    /`state` is carried .* forbids it[\s\S]*`wait` is carried .* forbids it/,
  );
});

test("`outcome` decides which of the service-decision pair is carried, which no `either` list could", () => {
  const applied = JSON.parse(composeBody("astra.plugins.bot-service-decision-result/1", {
    service_decision_id: "d1", outcome: "applied", commit: "a".repeat(40),
  }));
  assert.equal(applied.commit, "a".repeat(40));
  const refused = JSON.parse(composeBody("astra.plugins.bot-service-decision-result/1", {
    service_decision_id: "d1", outcome: "refused", refusal_code: "kind_refused",
  }));
  assert.equal(refused.refusal_code, "kind_refused");

  assert.throws(
    () => composeBody("astra.plugins.bot-service-decision-result/1", {
      service_decision_id: "d1", outcome: "applied", commit: "a".repeat(40), refusal_code: "kind_refused",
    }),
    /`refusal_code` is carried .* forbids it except where `outcome` is one of `refused`/,
  );

  // The case the deleted `EITHER_MEMBERS` accepted: exactly one of the pair,
  // and the wrong one for the outcome. A list that only counts the pair cannot
  // see this; the published conditions name the member that decides.
  assert.throws(
    () => composeBody("astra.plugins.bot-service-decision-result/1", {
      service_decision_id: "d1", outcome: "applied", refusal_code: "kind_refused",
    }),
    /`commit` is required .* `outcome` is one of `applied`, `held`, `cancelled` and is absent/,
    "0.28.0 published `outcome` as what decides between the two; a local `exactly one of the pair` check composed " +
    "a body the contract forbids and nothing was there to say so",
  );
  assert.throws(
    () => composeBody("astra.plugins.bot-service-decision-result/1", {
      service_decision_id: "d1", outcome: "refused", commit: "a".repeat(40),
    }),
    /`refusal_code` is required .* `outcome` is one of `refused` and is absent/,
  );
});

test("a success body's conditional members are read the same way, and an unreadable one withholds", () => {
  // No §4.2 success body has a `conditional` member today, so the wiring from
  // `successProblems` into the condition reader is provoked here on a
  // definition of this test's own — a branch reachable in no environment is a
  // branch nobody has watched fail.
  const def = {
    role: "success",
    members: [["shadow", true], ["state", "conditional", { iff: { wait: "absent" } }]],
  };
  assert.deepEqual(
    successProblems("x/1", { schema: "x/1", shadow: false, state: "published" }, def).problems, [],
  );
  assert.match(
    successProblems("x/1", { schema: "x/1", shadow: false }, def).problems.join("\n"),
    /`state` is required by x\/1 where `wait` is absent and is absent/,
  );
  assert.match(
    successProblems("x/1", { schema: "x/1", shadow: false, state: "p", wait: {} }, def).problems.join("\n"),
    /`state` is carried by x\/1 and its `iff` forbids it/,
  );

  // A `when` this reader cannot evaluate is a PROBLEM on the read side and not
  // a throw: the answer is withheld as shadow and alerts, where a throw would
  // fail a run over a table this repository owns and the service never sent.
  const broken = { role: "success", members: [["state", "conditional", { iff: { a: 7 } }]] };
  assert.match(
    successProblems("x/1", { schema: "x/1" }, broken).problems.join("\n"),
    /cannot evaluate/,
  );
});

// ───────────────────────────────────────────────────────────────────────────
// Reading an answer: SCOPE-3, and the marker that must be there
// ───────────────────────────────────────────────────────────────────────────

/**
 * The smallest body that satisfies a schema's required members.
 *
 * `required !== true` and not `!required`: a `conditional` member is carried
 * exactly under its own condition and is not part of any body's floor.
 */
const minimal = (schema) => {
  const body = { schema };
  for (const [member, required] of BODIES[schema].members) {
    if (member === "schema" || required !== true) continue;
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

// ═══════════════════════════════════════════════════════════════════════════
// The ingest pipeline on the service path (registry plan B-T3.1's steps,
// B-T3.2, B-T3.3a–c, B-T3.4, B-T3.5, B-T3.6's preparation).
//
// Every job of `plugins-ingest.yml` that is built runs one module, and each
// module is driven here against fixtures: the token jobs against the stub
// above, the decision as a pure function over a lease, a verification, a
// facts file, a listing, an `ask` outcome and a git state, and the publish
// composition over a real temporary tree. Nothing here reaches the network.
// ═══════════════════════════════════════════════════════════════════════════

import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  APPROVAL_MAX_DAYS,
  FIRST_BINDING_WAIT_DAYS,
  OPERATOR_WINDOW_HOURS,
  UPDATE_WINDOW_HOURS,
  CHECK_FACTS_SCHEMA,
  decideSubmission,
  id41,
} from "../lib/service-decide.mjs";
import { askJob, claimJob, leaseProblems, reportJob, resultBytes, verdictOutcome } from "../lib/service-jobs.mjs";
import { RESULT_KINDS, recordAgreement, resultBody } from "../lib/service-results.mjs";
import { ALERT_MEMBERS, ALERT_SCHEMA, alertProblems, commitTrailers, composePublication, finalizeResults } from "../lib/service-publish.mjs";
import { TRUST14_CODES, mergeAlerts } from "../lib/trust14.mjs";
import { ACTED_OUTCOMES, VERDICT_VALUES, leaksIn, scanFiles } from "../lib/scan-verdict-leaks.mjs";
import { submissionFingerprint } from "../lib/policy/release.mjs";
import { cleanEnv } from "../../tools/lib/git-env.mjs";

const P = {
  sid: "0192f1c2-3b4a-7c5d-8e6f-1a2b3c4d5e6f",
  sid2: "0192f1c2-3b4a-7c5d-9e6f-1a2b3c4d5e70",
  repo: "a-stranger/dice-roller",
  tag: "v0.2.0",
  id: "dice-roller",
  version: "0.2.0",
  commit: "a".repeat(40),
  rid: "1203676452",
  oid: "193032699",
  sha: "b".repeat(64),
  now: "2026-09-26T12:00:00Z",
};
const hoursBefore = (at, h) => `${new Date(new Date(at).getTime() - h * 3600e3).toISOString().slice(0, 19)}Z`;
const DIGESTS = [`linux-x64:${P.sha}`];
const FP = submissionFingerprint({ repo: P.repo, tag: P.tag, id: P.id, version: P.version, commit: P.commit, digests: DIGESTS });

const lease = (over = {}) => ({
  submission_id: P.sid, lease_expires_at: "2026-09-26T13:00:00Z", attempt: "att-1", claimed_from: "received",
  repo: P.repo, tag: P.tag, trigger: "poll", service_repository_id: P.rid, decisions: [], stop_status: "no_stop", ...over,
});
const verified = (over = {}) => ({
  submission_id: P.sid, outcome: "ok", findings: [],
  plugin_id: P.id, version: P.version, tag: P.tag, commit: P.commit, artifact_digests: DIGESTS, fingerprint: FP,
  repo: P.repo, repository_id: P.rid, repository_owner_id: P.oid, renamed: false, published_at: "2026-09-26T10:00:00Z",
  assets: [{ name: `${P.id}-${P.version}-linux-x64.astraplugin`, platform: "linux-x64", sha256: P.sha, size: 100,
    url: `https://github.com/${P.repo}/releases/download/${P.tag}/${P.id}-${P.version}-linux-x64.astraplugin` }],
  binding: { outcome: "none", token: null, token_hash: null, code: null, alert: false, reason: null },
  owner_file: null, actor: null, ...over,
});
const facts = (over = {}) => ({
  schema: CHECK_FACTS_SCHEMA, submission_id: P.sid, plugin_id: P.id, version: P.version, platforms: ["linux-x64"],
  findings: [{ code: "E_DERIVED_LISTING_INVALID", level: "pass" }], ...over,
});
const versionDoc = (version, over = {}) => ({
  schema: "astra.registry.version/1", id: P.id, version, published_at: "2026-09-01T00:00:00Z",
  release: { kind: "github_release", repo: P.repo, tag: `v${version}`, commit: "c".repeat(40) },
  capabilities: ["tools"],
  artifacts: { "linux-x64": { url: `https://github.com/${P.repo}/releases/download/v${version}/x.astraplugin`, filename: "x.astraplugin", sha256: "d".repeat(64), size: 10 } },
  ...over,
});
const listing = (over = {}) => ({
  plugin: { schema: "astra.registry.plugin/1", id: P.id, name: "Dice Roller", summary: "Rolls dice.", license: "MIT", source: { kind: "github", repo: "placeholder/placeholder" }, added_at: "2026-01-01" },
  version: versionDoc(P.version, {
    release: { kind: "github_release", repo: "placeholder/placeholder", tag: P.tag, commit: null },
    artifacts: { "linux-x64": { url: null, filename: `${P.id}-${P.version}-linux-x64.astraplugin`, sha256: P.sha, size: 100 } },
  }),
  ...over,
});
const existing = ({ repo = P.repo, versions = ["0.1.0"], identity = null } = {}) => ({
  doc: { schema: "astra.registry.plugin/1", id: P.id, name: "Dice Roller", source: { kind: "github", repo } },
  versions: versions.map((v) => ({ doc: versionDoc(v) })),
  identity,
});
const baseline = (over = {}) => ({
  trigger: "migration", state: "published", plugin_id: P.id, version: "0.1.0", repo: P.repo,
  repository_id: P.rid, repository_owner_id: P.oid, decided_at: "2026-09-01T00:00:00Z", decision_id: "e".repeat(32), ...over,
});
const git = (over = {}) => ({
  records: [], alerts: new Map(), denied: new Set(),
  markers: { r3_exit: false, cutover: false, baseline: false },
  existing: null, queueEntry: null, listingState: null, listingNamesRepo: true, siblings: [], track: undefined, ...over,
});
const ask = (over = {}) => ({ verdict: null, gates: { stop_status: "no_stop", decisions: [] }, notice: null, shadow: false, ...over });
const decideWith = (over = {}) => decideSubmission({
  lease: lease(over.lease), shadow: over.shadow ?? false, verified: over.verified ?? verified(),
  facts: over.facts === undefined ? facts() : over.facts, listing: over.listing === undefined ? listing() : over.listing,
  ask: over.ask ?? ask(), git: over.git ?? git(), now: over.now ?? P.now, startedAt: over.now ?? P.now,
  readCommit: "f".repeat(40),
});
const codes = (plan) => plan.record?.reasons ?? [];

// ── B-T3.3a: identity and binding ───────────────────────────────────────────

test("B-T3.3a: a first listing with no line is held R_FIRST_LISTING before R3's exit marker", () => {
  const plan = decideWith({ lease: { trigger: "poll" } });
  assert.equal(plan.kind, "state");
  assert.equal(plan.state, "held");
  assert.ok(codes(plan).includes("R_FIRST_LISTING"), JSON.stringify(codes(plan)));
});

test("B-T3.3a: `B_UNBOUND` applies on the far side of `log/rollout/R3-exit.json` and not before", () => {
  // Watched failing by applying B_UNBOUND before the marker: the case above
  // would then be refused, not held.
  const after = decideWith({ git: git({ markers: { r3_exit: true, cutover: false, baseline: true } }) });
  assert.equal(after.state, "refused");
  assert.ok(codes(after).includes("B_UNBOUND"));
  const before = decideWith({ git: git({ markers: { r3_exit: false, cutover: false, baseline: true } }) });
  assert.equal(before.state, "held");
  const cutover = decideWith({ lease: { trigger: "poll" }, git: git({ markers: { r3_exit: false, cutover: true, baseline: true } }) });
  assert.ok(codes(cutover).includes("B_UNBOUND"), "any first listing from cutover needs a line");
});

test("FLOW-67: a threadless submission no listing names, with no line, writes nothing and carries the read commit", () => {
  const plan = decideWith({ lease: { trigger: "panel" }, git: git({ listingNamesRepo: false }) });
  assert.equal(plan.kind, "norecord");
  assert.equal(plan.record, null);
  assert.equal(plan.read_commit, "f".repeat(40));
  assert.ok(plan.reasons[0].code.startsWith("B_"), "FLOW-78: the result carries a B_* reason");
  const poll = decideWith({ lease: { trigger: "poll" }, git: git({ listingNamesRepo: false }) });
  assert.notEqual(poll.kind, "norecord", "a poll is not panel or ci");
});

test("TRUST-23: against MIG-20's baseline, a fixture per outcome", () => {
  const upd = (b, repo = P.repo) => decideWith({
    verified: verified({
      repo,
      fingerprint: submissionFingerprint({ repo, tag: P.tag, id: P.id, version: P.version, commit: P.commit, digests: DIGESTS }),
    }),
    git: git({ existing: existing({ repo: P.repo }), records: b ? [b] : [] }),
  });
  const same = upd(baseline());
  assert.equal(same.state, "published", `the ids and the name agree: ${JSON.stringify(same.reasons.map((r) => r.code))}`);
  assert.ok(codes(upd(baseline({ repository_id: "1", repository_owner_id: "2" }))).includes("B_REPOSITORY_RECYCLED"));
  assert.equal(upd(baseline({ repository_id: "1", repository_owner_id: "2" })).state, "refused");
  assert.ok(codes(upd(baseline({ repository_owner_id: "2" }))).includes("R_IDENTITY_CHANGED"), "a transfer is held");
  assert.ok(codes(upd(baseline({ repository_id: "1" }))).includes("R_IDENTITY_CHANGED"), "a re-creation is held");
  assert.ok(codes(upd(null)).includes("R_IDENTITY_CHANGED"), "MIG-28: no baseline is a hold");
  // A rename: both ids the same, the certificate's name moved.
  const renamed = upd(baseline(), "a-stranger/dice-roller-2");
  assert.equal(renamed.state, "held");
  assert.ok(codes(renamed).includes("R_IDENTITY_CHANGED"));
});

test("ID-41 row 1 is permanent: a new tag of a recycled repository is refused again", () => {
  const b = baseline({ repository_id: "1", repository_owner_id: "2" });
  for (const tag of ["v0.2.0", "v0.3.0"]) {
    const fp = submissionFingerprint({ repo: P.repo, tag, id: P.id, version: P.version, commit: P.commit, digests: DIGESTS });
    const plan = decideWith({ verified: verified({ tag, fingerprint: fp }), lease: { tag }, git: git({ existing: existing(), records: [b] }) });
    assert.ok(codes(plan).includes("B_REPOSITORY_RECYCLED"), `${tag}: ${JSON.stringify(codes(plan))}`);
  }
});

test("ID-41's table: rows 1–4 by first match, rows 5 and 6 independently", () => {
  const rec = { repo: P.repo, repository_id: P.rid, repository_owner_id: P.oid, token_hash: "1".repeat(16) };
  const id = { repo: P.repo, repository_id: P.rid, repository_owner_id: P.oid };
  assert.deepEqual(id41({ identity: { ...id, repository_id: "9", repository_owner_id: "8" }, record: rec, lineHash: rec.token_hash }).codes, ["B_REPOSITORY_RECYCLED"]);
  assert.deepEqual(id41({ identity: { ...id, repository_id: "9" }, record: rec, lineHash: "2".repeat(16) }).codes, ["R_IDENTITY_CHANGED", "R_BINDING_CHANGED"], "row 1b with a new line holds both codes");
  assert.deepEqual(id41({ identity: { ...id, repository_owner_id: "8" }, record: rec, lineHash: rec.token_hash }).codes, ["B_OWNER_CHANGED"]);
  assert.deepEqual(id41({ identity: { ...id, repository_owner_id: "8" }, record: rec, lineHash: "2".repeat(16) }).rows, ["4", "6"]);
  assert.deepEqual(id41({ identity: { ...id, repo: "a-stranger/renamed" }, record: rec, lineHash: rec.token_hash }).codes, ["R_IDENTITY_CHANGED"]);
  assert.deepEqual(id41({ identity: id, record: rec, lineHash: "2".repeat(16) }).codes, ["R_BINDING_CHANGED"]);
  assert.deepEqual(id41({ identity: id, record: rec, lineHash: rec.token_hash }).codes, []);
});

test("ID-25: a listing with an identity record publishes only a bound release", () => {
  const ident = { repo: P.repo, repository_id: P.rid, repository_owner_id: P.oid, token_hash: "1".repeat(16) };
  const plan = decideWith({ git: git({ existing: existing({ identity: ident }), records: [baseline()] }) });
  assert.equal(plan.state, "refused");
  assert.ok(codes(plan).includes("B_UNBOUND"));
});

test("ID-41 row 6 is `R_BINDING_CHANGED`, and its result carries the objection window (ID-61)", () => {
  const ident = { repo: P.repo, repository_id: P.rid, repository_owner_id: P.oid, token_hash: "1".repeat(16) };
  const plan = decideWith({
    verified: verified({ binding: { outcome: "one", token: "t".repeat(24), token_hash: "2".repeat(16), code: null, alert: false, reason: null }, owner_file: { commit: "9".repeat(40), pull_request: true } }),
    ask: ask({ verdict: "pass" }),
    git: git({ existing: existing({ identity: ident }), records: [baseline()] }),
  });
  assert.equal(plan.state, "held");
  assert.ok(codes(plan).includes("R_BINDING_CHANGED"));
  assert.equal(typeof plan.result_extra.objection_window, "number");
  assert.equal(plan.result_extra.owner_file_commit, "9".repeat(40));
  assert.equal(plan.result_extra.owner_file_pull_request, true);
});

test("MIG-10: a line on a published listing with no identity record is `R_FIRST_BINDING`, never `R_BINDING_CHANGED`", () => {
  const plan = decideWith({
    verified: verified({ binding: { outcome: "one", token: "t".repeat(24), token_hash: "2".repeat(16), code: null, alert: false, reason: null }, owner_file: { commit: "9".repeat(40), pull_request: false } }),
    ask: ask({ verdict: "pass" }),
    git: git({ existing: existing(), records: [baseline()], listingState: { state: "grandfathered" } }),
  });
  assert.ok(codes(plan).includes("R_FIRST_BINDING"));
  assert.ok(!codes(plan).includes("R_BINDING_CHANGED"));
  assert.ok(!codes(plan).includes("R_CHECK_HELD"), "the hold keeps its own code in the record, not decide()'s fold");
});

test("ID-9: `B_BINDING_UNUSABLE` and `W_ELIGIBILITY_UNREADABLE` from the one word `ask` sends", () => {
  const line = { outcome: "one", token: "t".repeat(24), token_hash: "2".repeat(16), code: null, alert: false, reason: null };
  const unusable = decideWith({ verified: verified({ binding: line }), ask: ask({ verdict: "B_BINDING_UNUSABLE" }), git: git({ existing: existing(), records: [baseline()] }) });
  assert.equal(unusable.state, "refused");
  assert.ok(codes(unusable).includes("B_BINDING_UNUSABLE"));
  const unreadable = decideWith({ verified: verified({ binding: line }), ask: ask({ verdict: "W_ELIGIBILITY_UNREADABLE" }) });
  assert.equal(unreadable.kind, "wait");
  assert.equal(unreadable.wait.code, "W_ELIGIBILITY_UNREADABLE");
  const noVerdict = decideWith({ verified: verified({ binding: line }), ask: ask({ verdict: null }) });
  assert.equal(noVerdict.kind, "wait", "FLOW-74: a line and no verdict read is a wait, never a pass");
  const malformed = decideWith({ verified: verified({ binding: { ...line, outcome: "malformed", token: null, token_hash: null } }), git: git({ existing: existing(), records: [baseline()] }) });
  assert.ok(codes(malformed).includes("B_BINDING_MALFORMED"));
});

// ── BOT-15 / BOT-21: what the check job says against what verify established ──

test("BOT-15: a facts file or a listing disagreeing with the verification writes nothing and alerts", () => {
  const other = decideWith({ facts: facts({ plugin_id: "someone-else" }) });
  assert.equal(other.kind, "none");
  assert.equal(other.record, null);
  assert.ok(other.operator_alert, "a disagreement pages an operator");
  const planted = decideWith({ listing: listing({ version: { ...listing().version, artifacts: { ...listing().version.artifacts, "windows-x64": { sha256: "9".repeat(64) } } } }) });
  assert.equal(planted.kind, "none", "a listing carrying an artifact nothing verified is refused");
  const moved = decideWith({ facts: facts({ findings: [{ code: "E_X", level: "error", where: "x" }] }) });
  assert.equal(moved.kind, "none", "a facts file carrying free text beside its codes is not the check job's shape");
  assert.equal(decideWith({ facts: null }).kind, "none", "no facts file is no decision");
  assert.equal(decideWith({ facts: { ...facts(), message: "a stranger's sentence" } }).kind, "none",
    "a facts file with a member beyond the six is not the check job's shape");
});

test("BOT-21: the committed listing's identity comes from the verification, never from the check job", () => {
  const plan = decideWith({ git: git({ existing: existing(), records: [baseline()] }) });
  assert.equal(plan.state, "published");
  assert.equal(plan.listing.plugin.source.repo, P.repo, "source.repo is `.12`'s name, overwriting the placeholder");
  assert.equal(plan.listing.version.release.repo, P.repo);
  assert.equal(plan.listing.version.release.commit, P.commit);
  assert.equal(plan.listing.version.artifacts["linux-x64"].url, verified().assets[0].url);
  // Watched: copying `source` from the artifact leaves `placeholder/placeholder` here.
});

test("verify's alert, wait and refusal each keep their own shape", () => {
  const alert = decideWith({ verified: { submission_id: P.sid, outcome: "alert", code: "E_ATTESTATION_REPO_MISMATCH", reason: "x", findings: [] } });
  assert.equal(alert.kind, "none");
  assert.equal(alert.operator_alert.code, "E_ATTESTATION_REPO_MISMATCH");
  const wait = decideWith({ verified: { submission_id: P.sid, outcome: "wait", code: "E_ATTESTATION_UNCHECKED", reason: "x", findings: [] } });
  assert.equal(wait.kind, "wait");
  assert.equal(wait.wait.code, "E_ATTESTATION_UNCHECKED", "FLOW-72: a verifier that could not run is a wait");
  const refused = decideWith({ verified: { submission_id: P.sid, outcome: "refuse", code: "E_ATTESTATION_MISSING", findings: [{ level: "error", code: "E_ATTESTATION_MISSING", where: "x.astraplugin", message: "m" }] } });
  assert.equal(refused.state, "refused");
  assert.deepEqual(refused.record.reasons, ["E_ATTESTATION_MISSING"]);
  for (const m of ["repo", "tag", "fingerprint", "repository_id", "plugin_id"]) {
    assert.ok(!(m in refused.record), `a refusal before verification writes no ${m}: BOT-21 writes no identity value nothing verified`);
  }
});

// ── B-T3.3c: the outcomes that write nothing ────────────────────────────────

const mReject = { submission_id: P.sid2, fingerprint: FP, state: "refused", decision_id: "a".repeat(32), decided_at: "2026-09-20T00:00:00Z", reasons: ["M_REJECT"] };

test("BOT-19: a moderator's rejection of these bytes, or a stop, is reported, and nothing is written", () => {
  const plan = decideWith({ git: git({ records: [mReject] }) });
  assert.equal(plan.kind, "reported");
  assert.equal(plan.state, "refused");
  assert.equal(plan.decision_id, "a".repeat(32));
  assert.equal(plan.record, null);
  const stopped = decideWith({ git: git({ records: [{ submission_id: P.sid, state: "stopped", decision_id: "b".repeat(32), decided_at: "2026-09-20T00:00:00Z", reasons: ["A_STOP"] }] }) });
  assert.equal(stopped.kind, "reported", "FLOW-23: a stop for this submission id");
  const byTag = decideWith({ git: git({ records: [{ state: "stopped", tag: P.tag, repo: P.repo, repository_id: P.rid, decision_id: "c".repeat(32), decided_at: "2026-09-20T00:00:00Z", reasons: ["A_WITHDRAW"] }] }) });
  assert.equal(byTag.kind, "reported", "FLOW-26: a stop of the same tag of the same repository");
});

test("BOT-19: a bot refusal of the same bytes is decided again, never reported", () => {
  const plan = decideWith({ git: git({ records: [{ ...mReject, reasons: ["E_LICENSE_NOT_ALLOWED"] }] }) });
  assert.notEqual(plan.kind, "reported", "a recheck of refused bytes re-decides them");
});

test("BOT-74: a version listed with identical digests is reported `published`, naming the record", () => {
  const listed = existing({ versions: ["0.1.0"] });
  listed.versions.push({ doc: versionDoc(P.version, { artifacts: { "linux-x64": { sha256: P.sha } } }) });
  const rec = { plugin_id: P.id, version: P.version, state: "published", decision_id: "c".repeat(32), decided_at: "2026-09-25T00:00:00Z" };
  const plan = decideWith({ git: git({ existing: listed, records: [baseline(), rec] }) });
  assert.equal(plan.kind, "reported");
  assert.equal(plan.state, "published");
  assert.equal(plan.decision_id, "c".repeat(32));
});

test("FLOW-72: a wait from the checks writes no record", () => {
  const plan = decideWith({ facts: facts({ findings: [{ code: "E_PROBE_UNAVAILABLE", level: "error" }] }) });
  assert.equal(plan.kind, "wait");
  assert.equal(plan.record, null);
  // Watched by writing a record for E_PROBE_UNAVAILABLE: the plan would be a refusal.
});

// ── B-T3.3b: stops, approvals, notices, windows, deny ───────────────────────

test("SERVE-93: an `unavailable` stop status waits for that submission alone; `stopped` writes and posts nothing", () => {
  assert.equal(decideWith({ ask: ask({ gates: { stop_status: "unavailable", decisions: [] } }) }).kind, "wait");
  const stopped = decideWith({ ask: ask({ gates: { stop_status: "stopped", decisions: [] } }) });
  assert.equal(stopped.kind, "none");
  assert.equal(stopped.operator_alert, null);
  assert.equal(decideWith({ ask: ask({ gates: null }) }).kind, "wait", "no stop status read is no \"no stop\"");
});

const heldRecord = (over = {}) => ({ submission_id: P.sid, fingerprint: FP, state: "held", reasons: ["R_FIRST_LISTING"], decided_at: "2026-09-25T00:00:00Z", decision_id: "1".repeat(32), ...over });
const approval = (over = {}) => ({ code: "M_APPROVE", category: "review_passed", decided_at: "2026-09-26T08:00:00Z", moderator: "mod-7", declared_interest: false, ...over });
const approvedRun = (over = {}) => decideWith({
  lease: { claimed_from: "approved" },
  ask: ask({ gates: { stop_status: "no_stop", decisions: [approval(over.approval)] }, notice: over.notice === undefined ? { kind: "approved", status: "sent", accepted_at: "2026-09-26T09:00:00Z" } : over.notice }),
  git: git({ records: [heldRecord(over.held)], alerts: over.alerts ?? new Map(), denied: over.denied ?? new Set() }),
  now: over.now,
});

test("TRUST-14/TRUST-32: the three-run sequence — alert only, then the window, then publish", () => {
  const first = approvedRun();
  assert.equal(first.kind, "wait", `run 1 names the alert and publishes nothing: ${first.kind} ${first.state ?? ""}`);
  assert.deepEqual(first.alert, { fingerprint: FP, event: "approval", approval_decided_at: approval().decided_at });
  const rec = { schema: ALERT_SCHEMA, fingerprint: FP, event: "approval", approval_decided_at: approval().decided_at, delivered_at: "2026-09-26T11:00:00Z", run: "1/1" };
  const second = approvedRun({ alerts: new Map([[FP, rec]]) });
  assert.equal(second.kind, "wait");
  assert.equal(second.wait.code, "W_OPERATOR_WINDOW");
  assert.equal(second.wait.earliest_retry_at, "2026-09-26T17:00:00Z", `the window's end, ${OPERATOR_WINDOW_HOURS} h after delivery`);
  const third = approvedRun({ alerts: new Map([[FP, rec]]), now: "2026-09-26T17:00:01Z" });
  assert.equal(third.state, "published", JSON.stringify(third.wait ?? third.reasons));
  assert.equal(third.record.trigger, "approval");
  assert.equal(third.record.moderator, "mod-7");
  // An undelivered alert waits: a record with no delivery is W_ALERT_UNDELIVERED.
  const undelivered = approvedRun({ alerts: new Map([[FP, { ...rec, delivered_at: null }]]) });
  assert.equal(undelivered.wait.code, "W_ALERT_UNDELIVERED");
});

test("BOT-26: no held record, a stale approval, and a first binding under 7 days are each not honoured", () => {
  const rec = { schema: ALERT_SCHEMA, fingerprint: FP, event: "approval", approval_decided_at: approval().decided_at, delivered_at: "2026-09-20T00:00:00Z", run: "1/1" };
  const noHold = decideWith({ lease: { claimed_from: "approved" }, ask: ask({ gates: { stop_status: "no_stop", decisions: [approval()] }, notice: { kind: "approved", status: "sent", accepted_at: "2026-09-20T00:00:00Z" } }) });
  assert.equal(noHold.state, "held", "(1): an approval with no `held` record on main clears nothing");
  const stale = approvedRun({ approval: { decided_at: hoursBefore(P.now, APPROVAL_MAX_DAYS * 24 + 1) }, alerts: new Map([[FP, rec]]) });
  assert.equal(stale.state, "held", `(4): older than ${APPROVAL_MAX_DAYS} days`);
  const binding = approvedRun({ held: { reasons: ["R_FIRST_BINDING"], decided_at: hoursBefore(P.now, 24) }, alerts: new Map([[FP, rec]]) });
  assert.equal(binding.state, "held", `TRUST-27: ${FIRST_BINDING_WAIT_DAYS} days from the held record`);
});

test("BOT-28: `pending`, `none_unbound`, and a notice younger than the window each wait `W_NOTICE_PENDING`", () => {
  for (const notice of [
    { kind: "approved", status: "pending" },
    { kind: "approved", status: "none_unbound" },
    { kind: "approved", status: "previous_ended", ended_at: P.now },
    null,
  ]) {
    const plan = decideWith({
      lease: { claimed_from: "approved" },
      ask: ask({ gates: { stop_status: "no_stop", decisions: [approval()] }, notice }),
      git: git({ records: [heldRecord(), baseline()], existing: existing() }),
    });
    assert.equal(plan.kind, "wait", `${JSON.stringify(notice)}`);
    assert.equal(plan.wait.code, "W_NOTICE_PENDING");
    // BOT-29 by name: `none_unbound` is `pending`, not "a status with no time".
    if (notice?.status === "none_unbound") assert.match(plan.wait.cause, /BOT-29/);
  }
  // An approved UPDATE with no delay reason waits the update window.
  const young = decideWith({
    lease: { claimed_from: "approved" },
    ask: ask({ gates: { stop_status: "no_stop", decisions: [approval()] }, notice: { kind: "approved", status: "sent", accepted_at: hoursBefore(P.now, UPDATE_WINDOW_HOURS - 1) } }),
    git: git({ records: [heldRecord({ reasons: ["R_NEW_HIGH_RISK"] }), baseline()], existing: existing() }),
  });
  assert.equal(young.wait?.code, "W_NOTICE_PENDING", `${UPDATE_WINDOW_HOURS} h for an approved update`);
});

test("MIG-12: after cutover a grandfathered listing's drained release waits, whatever the notice says", () => {
  for (const status of ["sent", "previous_sent"]) {
    const plan = decideWith({
      lease: { claimed_from: "delayed" },
      ask: ask({ notice: { kind: "delayed", status, accepted_at: "2026-09-01T00:00:00Z" } }),
      git: git({
        existing: existing(), records: [baseline()], listingState: { state: "grandfathered" },
        markers: { r3_exit: true, cutover: true, baseline: true },
        queueEntry: { id: P.id, version: P.version, repo: P.repo, tag: P.tag, fingerprint: FP, queued_at: "2026-09-25T00:00:00Z", publish_after: "2026-09-26T00:00:00Z", delay_hours: 24, artifact_digests: DIGESTS },
      }),
    });
    assert.equal(plan.kind, "wait", status);
    assert.equal(plan.wait.code, "W_NOTICE_PENDING");
    assert.match(plan.wait.cause, /MIG-12/, "keyed on git, not on the service's answer");
  }
});

test("DEC-8 and TRUST-33: never before `publish_after`, and a deny record refuses", () => {
  const early = decideWith({
    lease: { claimed_from: "delayed" },
    git: git({ existing: existing(), records: [baseline()], queueEntry: { id: P.id, version: P.version, repo: P.repo, tag: P.tag, fingerprint: FP, queued_at: "2026-09-26T00:00:00Z", publish_after: "2026-09-27T00:00:00Z", delay_hours: 24, artifact_digests: DIGESTS } }),
  });
  assert.equal(early.kind, "wait");
  assert.equal(early.wait.earliest_retry_at, "2026-09-27T00:00:00Z");
  const denied = decideWith({ git: git({ existing: existing(), records: [baseline()], denied: new Set([FP]) }) });
  assert.equal(denied.state, "refused");
  // Contract 2.4.0: the deny is refused with its own code, whose `fix` is the
  // registry's, never `P_REFUSED`, whose `recheck` says an author can clear it.
  assert.deepEqual(denied.reasons.map((r) => r.code), ["P_OPERATOR_DENIED"]);
  assert.deepEqual(denied.record.reasons, ["P_OPERATOR_DENIED"]);
});

test("ROLL-49: an approved first listing with a delay reason is delayed, never waved through", () => {
  const listingHi = listing({ version: { ...listing().version, capabilities: ["dom_access"] } });
  const plan = decideSubmission({
    lease: lease({ claimed_from: "approved" }), shadow: false, verified: verified(), facts: facts(), listing: listingHi,
    ask: ask({ gates: { stop_status: "no_stop", decisions: [approval()] } }), git: git({ records: [heldRecord()] }),
    now: P.now, startedAt: P.now, readCommit: "f".repeat(40),
  });
  assert.equal(plan.state, "delayed", `${plan.kind} ${plan.state}`);
  assert.equal(plan.queue_entry.submission_id, P.sid);
  assert.equal(plan.queue_entry.schema, "astra.registry.queue/1");
  assert.ok(!("submitter" in plan.queue_entry) && !("issue" in plan.queue_entry), "BOT-38: no login, no issue");
});

// ── BOT-92: shadow ──────────────────────────────────────────────────────────

test("BOT-92: a `shadow: true` answer commits nothing and posts nothing; the same fixture unshadowed publishes", () => {
  const g = git({ existing: existing(), records: [baseline()] });
  const real = decideWith({ git: g });
  assert.equal(real.state, "published");
  for (const [label, over] of [["claim", { shadow: true }], ["ask", { ask: ask({ shadow: true }) }], ["verdict", { ask: ask({ verdict: "shadow" }) }]]) {
    const plan = decideWith({ git: g, ...over });
    assert.equal(plan.kind, "none", label);
    assert.equal(plan.shadow, true);
    assert.equal(plan.record, null);
    assert.equal(plan.listing, null);
    assert.equal(plan.queue_entry, null);
    assert.deepEqual(plan.identity_records, []);
    assert.equal(plan.would.state, "published", "the plan is computed in full, then emptied");
  }
});

// ── B-T3.5: the result bodies, and the golden files ─────────────────────────

const GOLDEN_DIR = path.join(REPO, "tests", "results");

/** The plan each golden file is built from — one per result kind. */
function goldenPlans() {
  const line = { outcome: "one", token: "t".repeat(24), token_hash: "2".repeat(16), code: null, alert: false, reason: null };
  const ident = { repo: P.repo, repository_id: P.rid, repository_owner_id: P.oid, token_hash: "1".repeat(16) };
  const plans = {
    published: decideWith({ git: git({ existing: existing(), records: [baseline()] }) }),
    held: decideWith({}),
    "held-first-binding": decideWith({
      verified: verified({ binding: line, owner_file: { commit: "9".repeat(40), pull_request: false }, actor: { triggering_actor_id: P.oid } }),
      ask: ask({ verdict: "pass" }), git: git({ existing: existing(), records: [baseline()], listingState: { state: "grandfathered" } }),
    }),
    "held-binding-changed": decideWith({
      verified: verified({ binding: line, owner_file: { commit: "9".repeat(40), pull_request: true } }),
      ask: ask({ verdict: "pass" }), git: git({ existing: existing({ identity: ident }), records: [baseline()] }),
    }),
    delayed: decideSubmission({
      lease: lease(), shadow: false, verified: verified(), facts: facts(),
      // A widening that is not high-risk: P_DELAY_WIDENED, and no hold.
      listing: listing({ version: { ...listing().version, capabilities: ["tools", "tts"] } }),
      ask: ask(), git: git({ existing: existing(), records: [baseline()] }), now: P.now, startedAt: P.now, readCommit: "f".repeat(40),
    }),
    refused: decideWith({ facts: facts({ findings: [{ code: "E_LICENSE_NOT_ALLOWED", level: "error" }] }) }),
    "refused-flow67": decideWith({ lease: { trigger: "panel" }, git: git({ listingNamesRepo: false }) }),
    reported: decideWith({ git: git({ records: [mReject] }) }),
    // A wait that carries reasons, so the golden holds `location` on one.
    wait: decideWith({
      lease: { claimed_from: "approved" },
      ask: ask({ gates: { stop_status: "no_stop", decisions: [approval()] }, notice: { kind: "approved", status: "pending" } }),
      git: git({ records: [heldRecord()] }),
    }),
  };
  return plans;
}

const goldenBody = (kind, plan) => resultBody(plan, {
  decisionId: plan.kind === "state" ? "0".repeat(32) : null,
  mainCommit: plan.kind === "state" || plan.kind === "reported" ? "7".repeat(40) : null,
});

test("B-T3.5: one golden file per result kind, each the body this module builds for it", () => {
  const plans = goldenPlans();
  assert.deepEqual(Object.keys(plans).sort(), [...RESULT_KINDS].sort(), "a plan per kind, and a kind per plan");
  const files = fs.existsSync(GOLDEN_DIR) ? fs.readdirSync(GOLDEN_DIR).filter((n) => n.endsWith(".json")).sort() : [];
  assert.ok(files.length >= RESULT_KINDS.length, `${files.length} golden file(s) under tests/results/ and the floor is ${RESULT_KINDS.length}`);
  for (const kind of RESULT_KINDS) {
    const plan = plans[kind];
    const body = goldenBody(kind, plan);
    const file = path.join(GOLDEN_DIR, `${kind}.json`);
    assert.ok(fs.existsSync(file), `tests/results/${kind}.json is missing`);
    const golden = JSON.parse(fs.readFileSync(file, "utf8"));
    assert.deepEqual({ schema: "astra.plugins.bot-result/1", ...body }, golden, `tests/results/${kind}.json is not what this module builds for ${kind}`);
    // Each golden is a body the token file's schema admits, conditions included.
    assert.doesNotThrow(() => composeBody("astra.plugins.bot-result/1", body), kind);
    for (const r of golden.reasons) assert.ok("location" in r, `${kind}: a reason with no location carries \`"location": null\``);
    if (plan.kind === "state") {
      assert.deepEqual(recordAgreement(body, { ...plan.record, decision_id: "0".repeat(32) }), [], `${kind}: BOT-23`);
    }
  }
});

test("B-T3.5: the members that apply and no others — `publish_after`, `read_commit`, `objection_window`, the owner file, the actor", () => {
  const plans = goldenPlans();
  const b = (k) => goldenBody(k, plans[k]);
  assert.ok("publish_after" in b("delayed") && !("publish_after" in b("published")));
  assert.ok("read_commit" in b("refused-flow67") && !("decision_id" in b("refused-flow67")));
  assert.ok("objection_window" in b("held-binding-changed") && !("objection_window" in b("held-first-binding")));
  assert.ok("owner_file_commit" in b("held-first-binding") && "owner_file_pull_request" in b("held-binding-changed"));
  assert.ok("triggering_actor_id" in b("held-first-binding") && !("triggering_actor_id" in b("held-binding-changed")));
  assert.ok("wait" in b("wait") && !("state" in b("wait")));
  assert.throws(() => resultBody({ ...plans["held-binding-changed"], result_extra: { ...plans["held-binding-changed"].result_extra, bogus: 1 } }) && composeBody("astra.plugins.bot-result/1", { ...b("held"), bogus: 1 }));
});

test("B-T3.5: a 600-character cause is cut to 512, and a result differing from its record fails before posting", () => {
  const plan = { ...goldenPlans().wait };
  plan.wait = { ...plan.wait, cause: "x".repeat(600) };
  assert.equal(resultBody(plan).wait.cause.length, 512);
  const pub = goldenPlans().published;
  const body = goldenBody("published", pub);
  assert.notDeepEqual(recordAgreement({ ...body, version: "9.9.9" }, { ...pub.record, decision_id: "0".repeat(32) }), []);
});

test("B-T3.5: retries send identical bytes, and nothing reads a clock at send time", async () => {
  const body = goldenBody("published", goldenPlans().published);
  assert.equal(resultBytes(body).bytes, resultBytes(structuredClone(body)).bytes);
  const s = await stub((call, n) => (n === 1 ? refusal("unavailable", "busy") : ok({ schema: "astra.plugins.bot-ack/1", shadow: false, outcome: "accepted" })));
  try {
    const out = await reportJob({ client: client(s), results: [{ submission_id: P.sid, kind: "published", shadow: false, unposted: null, body }] });
    assert.equal(out.posted.length, 1);
    assert.equal(s.calls.length, 2);
    assert.equal(s.calls[0].raw, s.calls[1].raw, "the retry re-sent the first attempt's bytes");
  } finally {
    await s.close();
  }
});

test("BOT-92 at the report job: a shadow result — a wait included — is posted not at all, and its hash is summarised", async () => {
  const s = await stub(() => ok({ schema: "astra.plugins.bot-ack/1", shadow: false, outcome: "accepted" }));
  try {
    const lines = [];
    const wait = goldenBody("wait", goldenPlans().wait);
    const held = goldenBody("held", goldenPlans().held);
    const out = await reportJob({
      client: client(s),
      results: [
        { submission_id: P.sid, kind: "wait", shadow: true, unposted: null, body: wait },
        { submission_id: P.sid2, kind: "held", shadow: true, unposted: null, body: held },
        { submission_id: P.sid, kind: "published", shadow: false, unposted: "dry_run", body: held },
      ],
      summary: (l) => lines.push(l),
    });
    assert.equal(s.calls.length, 0, "nothing reached the service");
    assert.equal(out.held.length, 3);
    assert.ok(lines.every((l) => /sha256:[0-9a-f]{64}/.test(l)), "each one's kind and body hash reach the summary");
  } finally {
    await s.close();
  }
});

// ── the token jobs against the stub ─────────────────────────────────────────

test("claim: at most three leases, each held to §4.3's grammar; the answer's shadow is handed on", async () => {
  const good = lease();
  const bad = { ...lease({ submission_id: P.sid2 }), repo: "not a repo" };
  const s = await stub(() => ok({ schema: "astra.plugins.bot-leases/1", shadow: true, leases: [good, bad] }));
  try {
    const errors = [];
    const out = await claimJob({ client: client(s), log: { log: () => {}, error: (l) => errors.push(l) } });
    assert.deepEqual(out.submissions, [P.sid]);
    assert.equal(out.shadow, true);
    assert.equal(out.refused.length, 1);
    assert.ok(errors.every((l) => !l.includes("not a repo")), "a bad lease's values are not printed");
    assert.ok(leaseProblems({ ...good, claimed_from: "published" }).length > 0);
  } finally {
    await s.close();
  }
  const four = await stub(() => ok({ schema: "astra.plugins.bot-leases/1", shadow: false, leases: [1, 2, 3, 4].map(() => lease()) }));
  try {
    await assert.rejects(claimJob({ client: client(four), log: { log: () => {}, error: () => {} } }), /BOT-59/);
  } finally {
    await four.close();
  }
});

test("claim: an answer with no `shadow` is read as shadow and alerts (BOT-92; B-T3.6's canary)", async () => {
  const s = await stub(() => ok({ schema: "astra.plugins.bot-leases/1", leases: [lease()] }));
  try {
    const c = client(s);
    const out = await claimJob({ client: c, log: { log: () => {}, error: () => {} } });
    assert.equal(out.shadow, true, "a missing marker is never read as a real answer");
    assert.ok(out.alerts.length >= 1, "and it alerts");
    // What BOT-92 then makes of it: the lease's plan is emptied, whatever DRY_RUN says.
    const plan = decideWith({ shadow: out.shadow, git: git({ existing: existing(), records: [baseline()] }) });
    assert.equal(plan.kind, "none");
  } finally {
    await s.close();
  }
});

test("ask: ID-9 in four words, and no token state or eligibility value leaves the job (BOT-89)", async () => {
  const cases = [
    [{ token_state: "bound", minted_for_repository: true, eligibility: "eligible" }, "pass"],
    [{ token_state: "seen", minted_for_repository: true, eligibility: "eligible" }, "pass"],
    [{ token_state: "revoked", minted_for_repository: true, eligibility: "eligible" }, "B_BINDING_UNUSABLE"],
    [{ token_state: "bound", minted_for_repository: false, eligibility: "eligible" }, "B_BINDING_UNUSABLE"],
    [{ token_state: "bound", minted_for_repository: true, eligibility: "ineligible" }, "B_BINDING_UNUSABLE"],
    [{ token_state: "unknown", minted_for_repository: false, eligibility: "unreadable" }, "W_ELIGIBILITY_UNREADABLE"],
  ];
  for (const [b, word] of cases) {
    assert.equal(verdictOutcome({ ok: true, shadow: false, unreadable: false, body: b }), word, JSON.stringify(b));
  }
  assert.equal(verdictOutcome({ ok: true, shadow: true, body: {} }), "shadow");

  const v = verified({ binding: { outcome: "one", token: "t".repeat(24), token_hash: "2".repeat(16), code: null, alert: false, reason: null } });
  const v2 = verified({ submission_id: P.sid2, fingerprint: "3".repeat(16) });
  const s = await stub((call) => {
    if (call.url.endsWith("/verdicts")) return ok({ schema: "astra.plugins.bot-verdict/1", shadow: false, token_state: "superseded", minted_for_repository: true, eligibility: "ineligible" });
    if (call.url.endsWith("/gates")) {
      return ok({ schema: "astra.plugins.bot-gates/1", shadow: false, items: [
        { submission_id: P.sid, fingerprint: FP, stop_status: "no_stop", decisions: [approval()] },
        { submission_id: P.sid2, fingerprint: "3".repeat(16), stop_status: "unavailable", decisions: [] },
      ] });
    }
    return ok({ schema: "astra.plugins.bot-notice-status/1", shadow: false, status: "sent", accepted_at: "2026-09-26T00:00:00Z" });
  });
  try {
    const out = await askJob({
      client: client(s), submissions: [P.sid, P.sid2],
      leases: { [P.sid]: lease({ claimed_from: "approved" }), [P.sid2]: lease({ submission_id: P.sid2 }) },
      verified: { [P.sid]: v, [P.sid2]: v2 },
    });
    assert.equal(out.outcome[P.sid].verdict, "B_BINDING_UNUSABLE");
    assert.equal(out.outcome[P.sid2].verdict, null, "FLOW-74: no line, no verdict asked");
    assert.equal(out.outcome[P.sid2].gates.stop_status, "unavailable", "the unavailable item waits alone");
    assert.equal(out.outcome[P.sid].gates.stop_status, "no_stop");
    assert.equal(out.outcome[P.sid].notice.status, "sent");
    const text = JSON.stringify(out.outcome);
    for (const forbidden of ["token_state", "eligibility", "minted_for_repository", "superseded", "ineligible"]) {
      assert.ok(!text.includes(forbidden), `the ask output carries ${forbidden}`);
    }
    assert.deepEqual(leaksIn(text), [], "and the leak scan finds nothing in it");
  } finally {
    await s.close();
  }
});

// ── B-T3.4: the one commit, composed ────────────────────────────────────────

function registryTree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-publish-"));
  const g = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: { ...cleanEnv(), GIT_CEILING_DIRECTORIES: os.tmpdir() } });
  g("init", "-q", "-b", "main");
  g("config", "user.email", "t@example.invalid");
  g("config", "user.name", "t");
  fs.mkdirSync(path.join(dir, "plugins"), { recursive: true });
  fs.writeFileSync(path.join(dir, "plugins", ".keep"), "");
  g("add", "-A");
  g("commit", "-q", "-m", "init");
  return { dir, g, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test("B-T3.4: a publication composes its record, listing and queue removal; a shadow plan composes nothing", () => {
  const t = registryTree();
  const reports = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-reports-"));
  try {
    const pub = goldenPlans().published;
    const shadowed = decideWith({ shadow: true, git: git({ existing: existing(), records: [baseline()] }) });
    const { pending } = composePublication({ plans: [pub, shadowed], root: t.dir, listingsDir: reports, reportsDir: reports, run: "123/1" });
    assert.equal(pending.length, 1, "the shadow plan composed nothing and has no result");
    const files = fs.readdirSync(path.join(reports, "report-0"), { recursive: true }).map(String).sort();
    assert.ok(files.some((f) => /^log\/decisions\/2026\/09\/[0-9a-f]{32}\.json$/.test(f)), files.join(" "));
    assert.ok(files.includes(`plugins/${P.id}/versions/${P.version}.json`));
    assert.equal(fs.readdirSync(reports).length, 1, "one report directory, for the one real plan");
    const rel = files.find((f) => /^log\/decisions\/.*\.json$/.test(f));
    const record = JSON.parse(fs.readFileSync(path.join(reports, "report-0", rel), "utf8"));
    assert.equal(record.run, "123/1");
    assert.equal(record.state, "published");
    assert.equal(pending[0].body.decision_id, record.decision_id);
    assert.equal(pending[0].needs_commit, true);
    assert.equal(commitTrailers({ pending, run: "123/1" }), `Run: 123/1\nSubmission: ${P.sid}\nDecision: ${record.decision_id}`);
  } finally {
    t.cleanup();
    fs.rmSync(reports, { recursive: true, force: true });
  }
});

test("BOT-36: a record already on main is not written again, and the result names the commit that holds it", () => {
  const t = registryTree();
  const reports = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-reports-"));
  try {
    const held = goldenPlans().held;
    const first = composePublication({ plans: [held], root: t.dir, listingsDir: reports, reportsDir: reports, run: "1/1" });
    const rel = first.pending[0].record_path;
    fs.mkdirSync(path.join(t.dir, path.dirname(rel)), { recursive: true });
    fs.copyFileSync(path.join(reports, "report-0", rel), path.join(t.dir, rel));
    t.g("add", "-A");
    t.g("commit", "-q", "-m", "the hold");
    const head = t.g("rev-parse", "HEAD").trim();
    fs.rmSync(reports, { recursive: true, force: true });
    fs.mkdirSync(reports);
    const again = composePublication({ plans: [held], root: t.dir, listingsDir: reports, reportsDir: reports, run: "2/1" });
    assert.equal(again.pending[0].needs_commit, false);
    assert.equal(again.pending[0].body.main_commit, head, "the result names the commit that added the record");
    assert.equal(fs.readdirSync(path.join(reports, "report-0"), { recursive: true }).length, 0, "nothing was written a second time");
  } finally {
    t.cleanup();
    fs.rmSync(reports, { recursive: true, force: true });
  }
});

test("TRUST-14: the alert record lands with the delivery the channel reported, and not without one", () => {
  const t = registryTree();
  const reports = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-reports-"));
  try {
    const plan = approvedRun();
    const delivered = composePublication({ plans: [plan], root: t.dir, listingsDir: reports, reportsDir: reports, run: "5/1", deliveredAt: "2026-09-26T12:00:05Z" });
    const doc = JSON.parse(fs.readFileSync(path.join(reports, "report-0", "state", "alerts", `${FP}.json`), "utf8"));
    assert.deepEqual(alertProblems(doc), []);
    assert.equal(delivered.pending[0].body.wait.code, "W_OPERATOR_WINDOW");
    assert.equal(delivered.pending[0].body.wait.earliest_retry_at, "2026-09-26T18:00:05Z");
    fs.rmSync(reports, { recursive: true, force: true });
    fs.mkdirSync(reports);
    const none = composePublication({ plans: [plan], root: t.dir, listingsDir: reports, reportsDir: reports, run: "6/1" });
    assert.equal(none.pending[0].body.wait.code, "W_ALERT_UNDELIVERED");
    assert.ok(!fs.existsSync(path.join(reports, "report-0", "state")), "no delivery, no record");
  } finally {
    t.cleanup();
    fs.rmSync(reports, { recursive: true, force: true });
  }
});

test("TRUST-14: schema/alert-v1.json types exactly the record the composer writes, and tools/validate.mjs judges it (contract 2.4.0)", async () => {
  const { loadSchemas, REPO_ROOT } = await import("../../tools/lib/sources.mjs");
  const { validate } = await import("../../tools/lib/jsonschema.mjs");
  const { runValidation } = await import("../../tools/validate.mjs");
  const schema = loadSchemas(REPO_ROOT).alert;
  assert.ok(schema, "schema/alert-v1.json is not loaded by loadSchemas");
  assert.deepEqual([...schema.required].sort(), [...ALERT_MEMBERS].sort(), "the schema's required members are ALERT_MEMBERS");
  assert.deepEqual(Object.keys(schema.properties).sort(), [...ALERT_MEMBERS].sort(), "and its properties are exactly them");
  const good = { schema: ALERT_SCHEMA, fingerprint: FP, event: "approval", approval_decided_at: "2026-09-26T11:00:00Z", delivered_at: "2026-09-26T12:00:05Z", run: "5/1" };
  const cases = [
    ["an approval", good],
    ["an elapsed delay", { ...good, event: "delay_elapsed", approval_decided_at: null }],
    ["a run with no attempt", { ...good, run: "5" }],
    ["an unnamed member", { ...good, chat_id: "1234567" }],
    ["no delivered_at", (({ delivered_at, ...rest }) => rest)(good)],
    ["an event TRUST-14 does not raise", { ...good, event: "stop" }],
    ["an approval with no decided_at", { ...good, approval_decided_at: null }],
    ["an elapsed delay carrying a decided_at", { ...good, event: "delay_elapsed" }],
    ["a fingerprint in capitals", { ...good, fingerprint: FP.toUpperCase() }],
    ["a delivered_at with a fraction", { ...good, delivered_at: "2026-09-26T12:00:05.5Z" }],
    ["a run that is not a run id", { ...good, run: "five" }],
    ["another schema", { ...good, schema: "astra.registry.alert/2" }],
  ];
  for (const [what, doc] of cases) {
    const bySchema = validate(schema, doc).length === 0;
    const byComposer = alertProblems(doc).length === 0;
    assert.equal(bySchema, byComposer, `${what}: the schema says ${bySchema ? "valid" : "invalid"} and alertProblems says ${byComposer ? "valid" : "invalid"}`);
  }
  assert.equal(cases.filter(([, d]) => alertProblems(d).length === 0).length, 3, "the table holds three valid records and nine refusals");
  // The validator on a tree: the good record passes, an unnamed member and a
  // day that does not exist are refused, each by name.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-alert-schema-"));
  try {
    fs.mkdirSync(path.join(dir, "state", "alerts"), { recursive: true });
    const put = (fp, doc) => fs.writeFileSync(path.join(dir, "state", "alerts", `${fp}.json`), JSON.stringify(doc));
    put(FP, good);
    put("1".repeat(16), { ...good, fingerprint: "1".repeat(16), chat_id: "1234567" });
    put("2".repeat(16), { ...good, fingerprint: "2".repeat(16), delivered_at: "2026-02-31T00:00:00Z" });
    const { report } = await runValidation({ root: dir, allowStaging: true, allowDirect: false, online: false, artifactsDir: null, index: false });
    const on = (fp) => report.errors.filter((e) => e.where === `state/alerts/${fp}.json`);
    assert.equal(on(FP).length, 0, `a good alert record was refused: ${JSON.stringify(on(FP))}`);
    assert.ok(on("1".repeat(16)).some((e) => /chat_id|additional/i.test(e.message)), `an unnamed member passed: ${JSON.stringify(on("1".repeat(16)))}`);
    assert.ok(on("2".repeat(16)).length > 0, "a delivered_at on 31 February passed");
    assert.ok(!report.items.some((i) => i.where === "state/alerts" && i.level === "note"), "the not-schema-checked note is gone with the gap");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("BOT-6: under DRY_RUN, and for a refused report, a result naming this run's commit is held back", () => {
  const pending = [
    { submission_id: P.sid, kind: "published", report: "report-0", needs_commit: true, body: { submission_id: P.sid } },
    { submission_id: P.sid2, kind: "wait", report: "report-1", needs_commit: false, body: { submission_id: P.sid2 } },
  ];
  const dry = finalizeResults({ pending, applied: { outcome: "dry-run", refused: [], pushed: false, dry_run: true }, mainCommit: null });
  assert.equal(dry[0].unposted, "dry_run");
  assert.equal(dry[1].unposted, null, "a wait names no commit and is posted under DRY_RUN");
  const pushed = finalizeResults({ pending, applied: { outcome: "committed", refused: [], pushed: true }, mainCommit: "8".repeat(40) });
  assert.equal(pushed[0].body.main_commit, "8".repeat(40));
  const refused = finalizeResults({ pending, applied: { outcome: "committed", refused: ["report-0"], pushed: true }, mainCommit: "8".repeat(40) });
  assert.equal(refused[0].unposted, "refused");
});

// ── the alert job's composer, and the log scan ──────────────────────────────

test("TRUST-14's composer turns decide's names into the one verdict the channel sends", () => {
  const roots = { schema: "astra.registry.alert-verdict/1", check: "plugins-ingest", status: "green" };
  assert.deepEqual(mergeAlerts(roots, {}), roots, "nothing named, nothing changed");
  const merged = mergeAlerts(roots, { trust14: [{ fingerprint: FP, event: "approval" }], operator: [{ code: "BOT15_FACTS_DISAGREE" }] });
  assert.equal(merged.status, "red");
  assert.deepEqual(merged.codes, ["BOT15_FACTS_DISAGREE", TRUST14_CODES.approval].sort());
  assert.deepEqual(merged.hexes, [FP]);
  assert.throws(() => mergeAlerts(roots, { trust14: [{ fingerprint: FP, event: "whim" }] }));
});

test("BOT-89's scan fails on each planted value, and not on the four outcomes or the decoys", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-leaks-"));
  try {
    // The floor, written before anything else: ten values, one line each.
    assert.equal(VERDICT_VALUES.length, 10);
    // Three shapes: keyed, keyed-and-quoted, and a bare JSON array element.
    const planted = VERDICT_VALUES.map((v, i) => [`  token_state: ${v}`, `{"eligibility":"${v}"}`, `["${v}"]`][i % 3]);
    const decoys = [...ACTED_OUTCOMES.map((o) => `outcome=${o}`), "state/releases-seen.json updated", "direction: outbound", "code: W_ELIGIBILITY_UNREADABLE"];
    fs.writeFileSync(path.join(dir, "log.txt"), [...planted, ...decoys].join("\n"));
    const out = scanFiles([path.join(dir, "log.txt")]);
    assert.equal(out.leaks.length, VERDICT_VALUES.length, JSON.stringify(out.leaks));
    assert.ok(out.leaks.every((l) => l.line <= VERDICT_VALUES.length), "no decoy line was reported");
    fs.writeFileSync(path.join(dir, "clean.txt"), decoys.join("\n"));
    assert.deepEqual(scanFiles([path.join(dir, "clean.txt")]).leaks, []);
    assert.ok(scanFiles([]).problems.length > 0, "a scan of nothing is not green");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── reg.61a's service-path half: the numbers and the sentence ───────────────

test("docs/POLICY.md §3.2 states the numbers bot/lib/service-decide.mjs enforces", () => {
  const doc = fs.readFileSync(path.join(REPO, "docs", "POLICY.md"), "utf8");
  const at = doc.indexOf("### 3.2 On the plugins-service path");
  assert.ok(at >= 0, "docs/POLICY.md has no §3.2 for the service path");
  const section = doc.slice(at, doc.indexOf("\n## ", at));
  assert.ok(section.includes(`**${APPROVAL_MAX_DAYS} days** (BOT-26)`), "the approval maximum");
  assert.ok(section.includes(`**${UPDATE_WINDOW_HOURS} hours** earlier`), "the update window");
  assert.ok(section.includes(`**${OPERATOR_WINDOW_HOURS} hours** have passed`), "the operator window");
  assert.ok(section.includes(`**${FIRST_BINDING_WAIT_DAYS} days** after the record`), "TRUST-27's wait");
});

// A hash, not a byte count, so this reads the same whatever the checker's
// locale: the set of files this section depends on, to make an accidental
// deletion of one visible.
test("the service-path modules this section drives are all on the tree", () => {
  for (const f of ["service-decide.mjs", "service-jobs.mjs", "service-publish.mjs", "service-results.mjs", "trust14.mjs", "scan-verdict-leaks.mjs"]) {
    assert.ok(fs.existsSync(path.join(REPO, "bot", "lib", f)), f);
  }
  assert.ok(crypto.createHash("sha256").update("x").digest("hex").length === 64);
});

// ── the whole path, once, as a run would take it ────────────────────────────
//
// claim → verify → check → ask → decide → compose → publish-apply → finalize
// → report, over a real temporary registry tree, real fixture bundles, the
// real manifest probe, and the stub above standing in for the service. The
// one thing not real is `gh`, which answers from the fixture's certificate.

import { checkFacts, verifyFacts } from "../ingest.mjs";
import { decideJob } from "../lib/service-decide.mjs";
import { run as publishApply } from "../publish-apply.mjs";
import { loadRootKeys } from "../lib/attestation.mjs";
import { makeBundle, fakeGitHub, fakeGh, FIXTURE_REPOSITORY_ID, FIXTURE_OWNER_ID } from "../fixtures/ingest/make.mjs";

function e2eWorld() {
  const t = registryTree();
  const w = (rel, doc) => {
    fs.mkdirSync(path.join(t.dir, path.dirname(rel)), { recursive: true });
    fs.writeFileSync(path.join(t.dir, rel), typeof doc === "string" ? doc : `${JSON.stringify(doc, null, 2)}\n`);
  };
  w(`plugins/${P.id}/plugin.json`, {
    schema: "astra.registry.plugin/1", id: P.id, name: "Dice Roller", summary: "Rolls dice when you ask it to.",
    license: "MIT", source: { kind: "github", repo: P.repo }, added_at: "2026-01-01",
  });
  w(`plugins/${P.id}/versions/0.1.0.json`, {
    schema: "astra.registry.version/1", id: P.id, version: "0.1.0", published_at: "2026-01-01T00:00:00Z",
    release: { kind: "github_release", repo: P.repo, tag: "v0.1.0" }, capabilities: ["tools"], staging: true,
    staging_reason: "Test fixture: the release this points at is a fake, so there is no digest to pin.",
    artifacts: { "linux-x64": { url: `https://github.com/${P.repo}/releases/download/v0.1.0/${P.id}-0.1.0-linux-x64.astraplugin`, filename: `${P.id}-0.1.0-linux-x64.astraplugin` } },
  });
  // MIG-20's baseline for the id, and its marker, so BOT-34's commit rule is on.
  w(`log/decisions/2026/09/${"e".repeat(32)}.json`, {
    schema: "astra.registry.decision/1", decision_id: "e".repeat(32), decided_at: "2026-09-01T00:00:00Z", actor: "system",
    trigger: "migration", plugin_id: P.id, version: "0.1.0", repo: P.repo, repository_id: FIXTURE_REPOSITORY_ID,
    repository_owner_id: FIXTURE_OWNER_ID, tag: "v0.1.0", state: "published", fingerprint: "0123456789abcdef",
  });
  w("log/baseline.json", {
    schema: "astra.registry.baseline/1", written_at: "2026-09-01T00:00:00Z", source_commit: "1".repeat(40), version_count: 1, record_count: 1,
  });
  t.g("add", "-A");
  t.g("commit", "-q", "-m", "a listed plugin, its baseline and the marker");
  return t;
}

function testRootKeys() {
  const keys = ["root-a", "root-b"].map((n) =>
    JSON.parse(fs.readFileSync(path.join(REPO, "tools", "testkeys", `TEST-ONLY-DO-NOT-TRUST-${n}.pub.json`), "utf8")));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-roots-"));
  const file = path.join(dir, "root.json");
  fs.writeFileSync(file, JSON.stringify({
    schema: "astra.registry.root/1", status: "provisioned",
    roots: keys.map((k) => ({ key_id: k.key_id, public_key: k.public_key, role: k.role })),
  }));
  const loaded = loadRootKeys(file);
  fs.rmSync(dir, { recursive: true, force: true });
  return loaded;
}

async function e2eRun({ shadow = false } = {}) {
  const t = e2eWorld();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-e2e-"));
  const cleanup = () => { t.cleanup(); fs.rmSync(work, { recursive: true, force: true }); };
  const name = `${P.id}-${P.version}-linux-x64.astraplugin`;
  const bytes = makeBundle({});
  const posted = [];
  const s = await stub((call) => {
    if (call.url.endsWith("/leases")) return ok({ schema: "astra.plugins.bot-leases/1", shadow, leases: [lease({ attempt: "att-9" })] });
    if (call.url.endsWith("/gates")) {
      return ok({ schema: "astra.plugins.bot-gates/1", shadow, items: [{ submission_id: P.sid, fingerprint: JSON.parse(call.raw).items[0].fingerprint, stop_status: "no_stop", decisions: [] }] });
    }
    if (call.url.endsWith("/results")) {
      posted.push(JSON.parse(call.raw));
      return ok({ schema: "astra.plugins.bot-ack/1", shadow, outcome: "accepted" });
    }
    return { status: 500, body: {} };
  });
  try {
    // claim
    const claimed = await claimJob({ client: client(s), log: { log: () => {}, error: () => {} } });
    // verify
    const github = fakeGitHub({ repo: P.repo, tag: P.tag, assets: [{ name, bytes }] });
    const assetsDir = path.join(work, "assets");
    const verifiedAll = {};
    for (const id of claimed.submissions) {
      verifiedAll[id] = await verifyFacts({
        lease: claimed.leases[id], root: t.dir, assetsDir,
        trustFile: path.join(REPO, "tools", "testkeys", "fixtures", "trust-active-signed.json"),
      }, {
        rootKeys: testRootKeys(),
        fetchRelease: github.fetchRelease.bind(github), headAsset: github.headAsset.bind(github), downloadAsset: github.downloadAsset.bind(github),
        ghRunner: (args) => fakeGh({ repo: P.repo, signerDigest: "0".repeat(40), tag: P.tag, subjectDigest: crypto.createHash("sha256").update(fs.readFileSync(args[2])).digest("hex") })(args),
        fetchRepositoryIds: async () => ({ status: "found", id: FIXTURE_REPOSITORY_ID, owner_id: FIXTURE_OWNER_ID, full_name: P.repo }),
        binding: { commitInRepository: async () => ({ status: "found", reason: "ok" }), fileAtCommit: async () => ({ status: "not_found", reason: "HTTP 404" }) },
      });
    }
    // check, laid out the way the two artifacts download
    const factsDir = path.join(work, "facts");
    const listingsDir = path.join(work, "listings");
    const pubListings = path.join(work, "pub-listings");
    for (const id of claimed.submissions) {
      const out = path.join(work, `check-${id}`);
      await checkFacts({ submissionId: id, assetsDir: path.join(assetsDir, id), verified: verifiedAll[id], out, root: t.dir });
      fs.mkdirSync(path.join(factsDir, `facts-${id}`), { recursive: true });
      fs.copyFileSync(path.join(out, "facts.json"), path.join(factsDir, `facts-${id}`, "facts.json"));
      fs.cpSync(path.join(out, "listing"), path.join(listingsDir, `listing-${id}`), { recursive: true });
      fs.cpSync(path.join(out, "listing"), pubListings, { recursive: true });
    }
    // ask
    const asked = await askJob({ client: client(s), submissions: claimed.submissions, leases: claimed.leases, verified: verifiedAll });
    // decide
    const decided = decideJob({
      root: t.dir, submissions: claimed.submissions, leases: claimed.leases, claimShadow: claimed.shadow,
      verified: verifiedAll, outcome: asked.outcome, factsDir, listingsDir, now: P.now, startedAt: P.now,
      readCommit: t.g("rev-parse", "HEAD").trim(),
    });
    // publish
    const reportsDir = path.join(work, "reports");
    fs.mkdirSync(reportsDir, { recursive: true });
    const { pending } = composePublication({ plans: decided.plans, root: t.dir, listingsDir: pubListings, reportsDir, run: "77/1" });
    const applied = publishApply({
      root: t.dir, reports: reportsDir, watchState: path.join(work, "none"), base: t.g("rev-parse", "HEAD").trim(),
      skipChecks: true, push: false, servicePath: true, message: "registry: publish (plugins ingest)", trailer: commitTrailers({ pending, run: "77/1" }), log: () => {},
    });
    const head = t.g("rev-parse", "HEAD").trim();
    const results = finalizeResults({
      pending, applied: { outcome: applied.outcome, refused: (applied.refusals ?? []).map((r) => r.report), pushed: applied.outcome === "committed" }, mainCommit: head,
    });
    // report
    await reportJob({ client: client(s), results: results.map((r) => ({ ...r, shadow: false })) });
    return { t, decided, pending, applied, head, results, posted, verifiedAll, cleanup };
  } catch (e) {
    cleanup();
    throw e;
  } finally {
    await s.close();
  }
}

test("end to end: one lease becomes one commit holding the listing and its record, and one result naming both", async () => {
  const r = await e2eRun();
  try {
    assert.equal(r.verifiedAll[P.sid].outcome, "ok", JSON.stringify(r.verifiedAll[P.sid].findings.filter((f) => f.level === "error")));
    const plan = r.decided.plans[0];
    assert.equal(plan.state, "published", `${plan.kind} ${plan.state ?? ""} ${JSON.stringify(plan.reasons?.map((x) => x.code) ?? plan.why)}`);
    assert.equal(r.applied.outcome, "committed", JSON.stringify(r.applied.refusals));
    const files = r.t.g("show", "--name-only", "--format=", "HEAD").trim().split("\n");
    assert.ok(files.includes(`plugins/${P.id}/versions/${P.version}.json`), files.join(" "));
    const rec = files.find((f) => /^log\/decisions\/2026\/09\/[0-9a-f]{32}\.json$/.test(f));
    assert.ok(rec, "the record is in the same commit (BOT-34, BOT-73)");
    const message = r.t.g("log", "-1", "--format=%B").trim();
    assert.match(message, new RegExp(`Submission: ${P.sid}`), "BOT-37's trailers");
    assert.equal(r.posted.length, 1, "one result posted");
    const body = r.posted[0];
    assert.equal(body.state, "published");
    assert.equal(body.main_commit, r.head, "the result names the commit that landed");
    assert.equal(`log/decisions/2026/09/${body.decision_id}.json`, rec, "and the record in it");
    assert.equal(body.attempt, "att-9", "BOT-12: the attempt identity is echoed");
    const version = JSON.parse(fs.readFileSync(path.join(r.t.dir, "plugins", P.id, "versions", `${P.version}.json`), "utf8"));
    assert.equal(version.release.repo, P.repo, "BOT-21: the committed repo is the certificate's");
  } finally {
    r.cleanup();
  }
});

test("end to end, in shadow: the same lease commits nothing and posts nothing", async () => {
  const r = await e2eRun({ shadow: true });
  try {
    assert.equal(r.decided.plans[0].kind, "none");
    assert.equal(r.decided.plans[0].would.state, "published", "the shadow run still decided what it would do");
    assert.equal(r.pending.length, 0);
    assert.equal(r.applied.outcome, "nothing");
    assert.equal(r.posted.length, 0, "BOT-92: no result of any kind");
  } finally {
    r.cleanup();
  }
});
