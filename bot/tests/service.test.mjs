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
 * A file here is a claim by a person that it does not read a member table. It
 * is held to that claim from the other side: each one must still be a candidate
 * (below), so an exclusion whose file has gone, or has stopped matching any
 * signal, is a red rather than a line nobody rereads.
 */
const NOT_MEMBER_READERS = [
  {
    file: "bot/tests/service.test.mjs",
    why:
      "this census itself. It imports the tool's reader in order to PROVE the bucket above, and names the " +
      "bucketed schema in doing so; the prover is not a reader under proof",
  },
  {
    file: "tools/gen-codes-table.mjs",
    why:
      "names the token file to say, in its own header, that it does NOT write it — FLOW-13's table is merged " +
      "into the token file by astra-plugins-ops `tools/contract-tokens.mjs`, and this program writes the " +
      "intermediate `tools/codes-table.json`. It parses no entry and reads no member",
  },
  {
    file: "tools/selftest/contract-tokens.mjs",
    why:
      "reads the token file's own discipline — the contract version it names, its `pending[]` records, the " +
      "cron it publishes — and never an `entries[].members` table. A member's requiredness is not a thing this " +
      "module has an opinion about",
  },
  {
    file: "tools/validate.mjs",
    why:
      "names the token file in one report note, to say why an `author_request` yank is being counted by action " +
      "and category while `fixed_reasons` is null. It opens no entry. From contract 0.31.0 it also names " +
      "`astra.registry.migration-notice/1`, because it judges every marker on a tree against " +
      "`schema/migration-notice-v1.json` — a JSON Schema, loaded by `loadSchemas`, and never the token file's " +
      "member table",
  },
  {
    file: "tools/selftest/migration-notice.mjs",
    why:
      "contract 0.31.0's canary between two statements of ONE condition: it reads the marker entry's member " +
      "table only to hold `schema/migration-notice-v1.json`'s members and `oneOf` to it, round by round, and " +
      "judges no marker on any ref. The reader of that table is `tools/cutover-preflight.mjs`, which the bucket " +
      "above proves — and this module deliberately does not import it, because tools/selftest/ is in TRUST-31's " +
      "set and the publish path runs it",
  },
  {
    file: "tools/selftest/primitives.mjs",
    why:
      "names the token file as a KEY of `SCHEMA_ABSENCES`, the declaration of which populations called \"the " +
      "schemas\" it is absent from (dev/couplings.md entry 67), and opens it only to ask whether it carries " +
      "`$schema`, as it opens every file under `schema/`. It parses no entry and reads no member",
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
 * too** — five files in this repository name `tools/cutover-preflight.mjs` and
 * four of those five are comments.
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
  // bodies §5.8 publishes (Tables 5-G to 5-L): 19 top-level members over six
  // entries, `astra.plugins.{listing-view,transparency-decisions,
  // transparency-moderation,transparency-held,transparency-reports,
  // transparency-served}/1`. Read on arrival: the plugins service emits them,
  // the panel and guests read them, and nothing in this repository composes or
  // reads one, so they belong in this bucket. Their three conditions are
  // nested in `transparency-moderation/1`'s `entries` — `advisory`,
  // `appeal_of` and `outcome`, each `iff` on `action` with its why — and every
  // other member is `true`, or `false` with a why saying why no condition is
  // published.
  assert.deepEqual(
    { entries: unreadEntries.length, members: countMembers(unreadEntries) },
    { entries: 30, members: 98 },
    `${countMembers(unreadEntries)} published members over ${unreadEntries.length} entries are outside every ` +
    `comparison in this suite; there were 98 over 30 at contract 0.33.0 and this file reads ` +
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
