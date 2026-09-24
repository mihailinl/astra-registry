// BOT-90's harness, against a stub service on 127.0.0.1.
//
//     node --test bot/tests/service-conformance.test.mjs
//
// Registry plan B-T3.11. `tools/service-conformance.mjs` is a black-box check
// of a service that is not answering yet (its R3 handlers open 2026-09-27/28),
// so every assertion here is against a stub that answers each way the real
// one could be wrong. A socket rather than a recording `fetch`, for the reason
// `bot/tests/service.test.mjs` gives: headers, redirects and bodies are
// properties of HTTP, and a function standing in for `fetch` proves only that
// the stand-in returns what the test told it to.
//
// Nothing here reaches api.minice.ai or any other host, and nothing here
// fires a burst anywhere but the stub.

import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ABSENT_ID,
  APPROVAL_SCHEMA,
  BURST_FLOOR,
  BURST_RESULT_SCHEMA,
  CODES,
  LEGS,
  REMOVAL_SCHEMA,
  SERVICE_ONLY_FLOOR,
  absentIdProblems,
  approvalProblems,
  burst,
  completeBurst,
  headerProblems,
  mintNonBotToken,
  probe,
  readTokenFile,
  runnerProblems,
  sha256,
  shapesFor,
  tablePlan,
} from "../../tools/service-conformance.mjs";
import { BOT_AUDIENCE } from "../lib/oidc.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const WORKFLOW = path.join(REPO, ".github", "workflows", "service-conformance.yml");

const trash = [];
process.on("exit", () => {
  for (const d of trash) fs.rmSync(d, { recursive: true, force: true });
});
const scratch = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "astra-conformance-"));
  trash.push(d);
  return d;
};

const quiet = { log() {}, error() {} };
const clone = (x) => JSON.parse(JSON.stringify(x));

// ── the stub ────────────────────────────────────────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json", "X-Content-Type-Options": "nosniff" };
const refusal = (error) => ({ schema: "astra.plugins.error/1", error, message: `the stub refused with ${error}` });

/** The service as the contract says it answers these four legs. */
function conforming(req) {
  const url = new URL(req.url, "http://stub");
  const rel = url.pathname.replace(/^\/plugins\/v1\//, "");
  if (req.method === "POST" && rel === "bot/leases") {
    return { status: req.headers.authorization ? 422 : 422, body: refusal(req.headers.authorization ? "token_refused" : "unauthenticated") };
  }
  if (req.method === "GET" && rel.startsWith("ratings/")) return { status: 422, body: refusal("unauthenticated") };
  if (req.method === "GET" && rel.startsWith("listings/")) return { status: 410, body: refusal("plugin_not_listed") };
  if (req.method === "GET" && rel === "health") return { status: 200, body: { schema: "astra.plugins.health/1" } };
  return { status: 422, body: refusal("invalid") };
}

/** A stub that answers `answer(req, body)` → {status, body, headers?}, and journals every request. */
async function stub(answer = conforming) {
  const journal = [];
  const server = http.createServer((req, res) => {
    let data = "";
    req.on("data", (c) => { data += c; });
    req.on("end", () => {
      journal.push({ method: req.method, url: req.url, headers: req.headers, body: data });
      if (req.url.startsWith("/token")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ value: server.token }));
        return;
      }
      const a = answer(req, data);
      const headers = a.headers ?? JSON_HEADERS;
      res.writeHead(a.status, headers);
      res.end(typeof a.body === "string" ? a.body : JSON.stringify(a.body));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  server.token = jwt({ aud: BOT_AUDIENCE, job_workflow_ref: "mihailinl/astra-registry/.github/workflows/service-conformance.yml@refs/heads/main" });
  return {
    base: `http://127.0.0.1:${port}/plugins/v1/`,
    tokenUrl: `http://127.0.0.1:${port}/token?api-version=2.0`,
    journal,
    server,
    close: () => new Promise((r) => server.close(r)),
  };
}

function jwt(claims) {
  const part = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${part({ alg: "RS256" })}.${part(claims)}.c2ln`;
}

const fakeMint = async () => ({ token: jwt({ aud: BOT_AUDIENCE }) });

async function run(answer, extra = {}) {
  const s = await stub(answer);
  try {
    const report = await probe({ base: s.base, mint: fakeMint, log: quiet, ...extra });
    return { report, journal: s.journal };
  } finally {
    await s.close();
  }
}

// ── the table, against the token file ───────────────────────────────────────

test("every leg is at the path the token file records, and both service-only entries are there", () => {
  const doc = readTokenFile(REPO);
  const plan = tablePlan(doc);
  // The floor, written before the mutation below: four legs compiled, four
  // matched, two of them at service-only paths.
  assert.equal(LEGS.length, 4, "BOT-90 names four expectations and the harness compiles a different number");
  assert.deepEqual(plan.problems, [], "the compiled legs and the token file disagree");
  assert.deepEqual(plan.skipped, [], "a leg is skipped against the committed token file");
  assert.equal(plan.run.length, 4);
  assert.equal(plan.serviceOnlyMatched, SERVICE_ONLY_FLOOR);
  assert.equal(SERVICE_ONLY_FLOOR, 2);
  // What each leg is compared with, by name: SCOPE-8's set for the first two,
  // the service-only list for the other two (plan §2.5, B-T3.11's Step/gate).
  assert.deepEqual(LEGS.map((l) => [l.leg, l.list]), [
    ["token_refused", "entries"],
    ["unauthenticated", "entries"],
    ["plugin_not_listed", "service_only"],
    ["health", "service_only"],
  ]);
});

test("a token file without `health` skips that leg by name and is red at the floor — watched by dropping it", () => {
  const doc = clone(readTokenFile(REPO));
  const before = doc.service_only.length;
  doc.service_only = doc.service_only.filter((e) => e.id !== "service-only:health");
  assert.equal(doc.service_only.length, before - 1, "the mutation removed nothing, so it would prove nothing");
  const plan = tablePlan(doc);
  assert.deepEqual(plan.skipped.map((s) => s.leg), ["health"]);
  assert.match(plan.skipped[0].why, /§1\.3 row 8\.6/);
  assert.equal(plan.run.some((l) => l.leg === "health"), false, "the leg was pointed somewhere else instead of skipped");
  assert.ok(plan.problems.some((p) => /floor is 2/.test(p)), `no floor problem: ${plan.problems.join(" | ")}`);
});

test("a path that moved in the token file is red, and the leg does not run against the old one", () => {
  const doc = clone(readTokenFile(REPO));
  const entry = doc.service_only.find((e) => e.id === "service-only:listings-view");
  entry.path = "listing/{plugin_id}";
  const plan = tablePlan(doc);
  assert.ok(plan.problems.some((p) => /plugin_not_listed: this tool calls GET listings\/\{plugin_id\}/.test(p)));
  assert.equal(plan.run.some((l) => l.leg === "plugin_not_listed"), false);

  const doc2 = clone(readTokenFile(REPO));
  doc2.entries.find((e) => e.id === "audience:bot").value = "https://api.minice.ai/plugins/v1/bots";
  assert.ok(tablePlan(doc2).problems.some((p) => /bot audience/.test(p)), "an audience drift passed");

  const doc3 = clone(readTokenFile(REPO));
  doc3.entries = doc3.entries.filter((e) => e.id !== "operation:bot:claim");
  const plan3 = tablePlan(doc3);
  assert.ok(plan3.problems.some((p) => /operation:bot:claim/.test(p)), "a SCOPE-8 entry went missing and nothing was red");
});

test("the absent id is one no listing carries, and a reserved or listed one is refused", () => {
  assert.deepEqual(absentIdProblems(ABSENT_ID, REPO), []);
  assert.ok(absentIdProblems("moderation", REPO).some((p) => /reserved id/.test(p)));
  assert.ok(absentIdProblems("astra-thing", REPO).some((p) => /reserved prefix/.test(p)));
  const listed = fs.readdirSync(path.join(REPO, "plugins")).find((n) => fs.statSync(path.join(REPO, "plugins", n)).isDirectory());
  assert.ok(listed, "no listing on this tree to hold the absent-id rule against");
  assert.ok(absentIdProblems(listed, REPO).length > 0, `${listed} is listed and passed as absent`);
});

// ── the probe, against a stub ───────────────────────────────────────────────

test("a conforming service is green, and each leg asked what it should with the credential it should", async () => {
  const { report, journal } = await run(conforming);
  assert.deepEqual(report.problems, []);
  assert.equal(report.status, "green");
  assert.equal(report.legs.filter((l) => l.ran).length, 4);
  const leases = journal.filter((r) => r.url === "/plugins/v1/bot/leases");
  assert.equal(leases.length, 1);
  assert.match(leases[0].headers.authorization ?? "", /^Bearer [^.]+\.[^.]+\.[^.]+$/, "the token_refused leg sent no token");
  assert.equal(leases[0].body, '{"schema":"astra.plugins.bot-claim/1","wanted":1}', "the claim body is not a valid bot-claim/1");
  for (const r of journal.filter((x) => x.url !== "/plugins/v1/bot/leases")) {
    assert.equal(r.headers.authorization, undefined, `${r.url} carried a bearer`);
  }
  assert.ok(journal.some((r) => r.url === `/plugins/v1/ratings/${ABSENT_ID}`));
  assert.ok(journal.some((r) => r.url === `/plugins/v1/listings/${ABSENT_ID}`));
  assert.ok(journal.some((r) => r.url === "/plugins/v1/health"));
});

test("statuses are logged and never asserted: the same refusals under other statuses stay green", async () => {
  const { report } = await run((req, body) => {
    const a = conforming(req, body);
    return { ...a, status: a.status === 200 ? 200 : 401 };
  });
  assert.deepEqual(report.problems, [], "a status the service chose was treated as a finding");
});

/** One wrong answer per fixture, and the code each must produce. */
const WRONG = [
  ["health answers text/plain", "SERVE_83_HEADERS", (req, b) => {
    const a = conforming(req, b);
    return req.url.endsWith("/health") ? { ...a, headers: { "Content-Type": "text/plain", "X-Content-Type-Options": "nosniff" } } : a;
  }],
  ["a refusal without nosniff", "SERVE_83_HEADERS", (req, b) => {
    const a = conforming(req, b);
    return req.url.includes("/listings/") ? { ...a, headers: { "Content-Type": "application/json" } } : a;
  }],
  ["application/json with another parameter", "SERVE_83_HEADERS", (req, b) => {
    const a = conforming(req, b);
    return req.url.includes("/ratings/") ? { ...a, headers: { "Content-Type": "application/json; charset=latin1", "X-Content-Type-Options": "nosniff" } } : a;
  }],
  ["a refusal that is not astra.plugins.error/1", "BOT90_UNAUTHENTICATED", (req, b) => {
    const a = conforming(req, b);
    return req.url.includes("/ratings/") ? { ...a, body: { error: "unauthenticated" } } : a;
  }],
  ["an error body carrying a member the token file does not publish", "BOT90_REFUSAL_BODY", (req, b) => {
    const a = conforming(req, b);
    return req.url.includes("/listings/") ? { ...a, body: { ...a.body, subject: "whoever" } } : a;
  }],
  ["an error body missing its message", "BOT90_REFUSAL_BODY", (req, b) => {
    const a = conforming(req, b);
    return req.url.includes("/listings/") ? { ...a, body: { schema: "astra.plugins.error/1", error: "plugin_not_listed" } } : a;
  }],
  ["a 200 lease answer where token_refused is expected", "BOT90_TOKEN_REFUSED", (req, b) => {
    const a = conforming(req, b);
    return req.url.endsWith("/bot/leases") ? { status: 200, body: { schema: "astra.plugins.bot-leases/1", shadow: true, leases: [] } } : a;
  }],
  ["a non-bot token refused with the wrong token", "BOT90_TOKEN_REFUSED", (req, b) => {
    const a = conforming(req, b);
    return req.url.endsWith("/bot/leases") ? { ...a, body: refusal("invalid") } : a;
  }],
  ["an unknown id answered with a listing", "BOT90_PLUGIN_NOT_LISTED", (req, b) => {
    const a = conforming(req, b);
    return req.url.includes("/listings/") ? { status: 200, body: { schema: "astra.plugins.listing-view/1" } } : a;
  }],
  ["the read that must succeed refused unavailable", "BOT90_HEALTH", (req, b) => {
    const a = conforming(req, b);
    return req.url.endsWith("/health") ? { status: 503, body: refusal("unavailable") } : a;
  }],
  ["health answering some other schema", "BOT90_HEALTH", (req, b) => {
    const a = conforming(req, b);
    return req.url.endsWith("/health") ? { status: 200, body: { schema: "astra.plugins.status/1" } } : a;
  }],
  ["a redirect, which is never followed", "BOT90_UNREACHABLE", (req, b) => {
    const a = conforming(req, b);
    return req.url.endsWith("/health") ? { status: 302, headers: { Location: "https://example.invalid/" }, body: "" } : a;
  }],
];

for (const [name, code, answer] of WRONG) {
  test(`a wrong answer is red with ${code}: ${name}`, async () => {
    const { report } = await run(answer);
    assert.equal(report.status, "red", `${name} passed`);
    assert.ok(report.codes.includes(code), `${name} gave ${report.codes.join(", ") || "no code"}, not ${code}`);
    for (const c of report.codes) assert.ok(CODES.includes(c));
  });
}

test("a token that cannot be minted is red, and the token_refused leg is not sent bare", async () => {
  const { report, journal } = await run(conforming, { mint: async () => { throw new Error("no endpoint"); } });
  assert.ok(report.codes.includes("BOT90_TOKEN_MINT"));
  assert.equal(journal.some((r) => r.url === "/plugins/v1/bot/leases"), false,
    "the leg was sent with no token, and its answer would be `unauthenticated` — a different question");
});

// ── the non-bot token ───────────────────────────────────────────────────────

test("the non-bot token carries the bot audience, is masked first, and is refused if it is a bot token", async () => {
  const s = await stub();
  try {
    const env = { ACTIONS_ID_TOKEN_REQUEST_URL: s.tokenUrl, ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token" };
    const lines = [];
    const log = { log: (l) => lines.push(l), error: () => {} };
    const { claims } = await mintNonBotToken({ env, log });
    assert.equal(claims.aud, BOT_AUDIENCE);
    assert.equal(lines[0], `::add-mask::${s.server.token}`, "the token was not masked before anything else");
    assert.match(s.journal[0].url, /audience=https%3A%2F%2Fapi\.minice\.ai%2Fplugins%2Fv1%2Fbot$/);

    s.server.token = jwt({ aud: BOT_AUDIENCE, environment: "plugins-service" });
    await assert.rejects(mintNonBotToken({ env, log }), /would be holding a bot token/);
    s.server.token = jwt({ aud: "https://api.minice.ai/plugins/v1/author" });
    await assert.rejects(mintNonBotToken({ env, log }), /audience/);
    await assert.rejects(mintNonBotToken({ env: {}, log }), /ACTIONS_ID_TOKEN_REQUEST_URL is not set/);
  } finally {
    await s.close();
  }
});

// ── the burst ───────────────────────────────────────────────────────────────

const SOURCE = "198.51.100.7"; // TEST-NET-2, documentation only
const NOW = new Date("2026-09-27T10:00:00Z");
const approvalFor = (over = {}) => ({
  schema: APPROVAL_SCHEMA,
  burst_id: "3f2a11c8-9d44-4b6e-8a01-77c0de91b433",
  trigger: "r3-exit",
  approved_by: "owner",
  approved_at: "2026-09-27T09:00:00Z",
  not_after: "2026-09-27T21:00:00Z",
  statement: `astra-plugins-ops@${"a".repeat(40)}:notes/state.md#burst-approval`,
  service_told_at: "2026-09-27T09:05:00Z",
  source_address_sha256: sha256(SOURCE),
  thresholds: {
    brute_force_overflow_at: 6,
    probing_overflow_at: 11,
    read_at: "2026-09-27T08:00:00Z",
    source: `astra-plugins-ops@${"b".repeat(40)}:notes/state.md#crowdsec-thresholds`,
  },
  ...over,
});
const SELF_HOSTED = { GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "self-hosted", ASTRA_BURST_SOURCE: SOURCE };
// What a dispatch of the workflow gets: the default runner.
const DEFAULT_RUNNER = { GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", RUNNER_OS: "Linux" };

test("a dispatched burst on the default runner is refused before anything is sent", async () => {
  const s = await stub();
  try {
    const out = scratch();
    const r = await burst({ approval: approvalFor(), env: { ...DEFAULT_RUNNER, ASTRA_BURST_SOURCE: SOURCE }, outDir: out, base: s.base, now: () => NOW, sleep: async () => {}, log: quiet });
    assert.equal(r.fired, false);
    assert.ok(r.refusals.some((p) => /GitHub-hosted runner/.test(p)), r.refusals.join(" | "));
    assert.equal(s.journal.length, 0, "a refused burst sent a request");
    assert.deepEqual(fs.readdirSync(out), []);
    // An Actions job that does not say which runner it is on cannot be told
    // from a hosted one, and is refused the same way.
    assert.ok(runnerProblems({ GITHUB_ACTIONS: "true", ASTRA_BURST_SOURCE: SOURCE }).some((p) => /does not say which runner/.test(p)));
  } finally {
    await s.close();
  }
});

test("a burst is refused without an approval, without a source address, and with an approval that does not fit", async () => {
  const cases = [
    ["no approval record", { approval: null, env: SELF_HOSTED }, /no approval record/],
    ["no source address", { approval: approvalFor(), env: { ...SELF_HOSTED, ASTRA_BURST_SOURCE: "" } }, /no ASTRA_BURST_SOURCE/],
    ["another address than the approved one", { approval: approvalFor(), env: { ...SELF_HOSTED, ASTRA_BURST_SOURCE: "198.51.100.8" } }, /not the one the owner approved/],
    ["an expired approval", { approval: approvalFor({ not_after: "2026-09-27T09:30:00Z" }), env: SELF_HOSTED }, /expired/],
    ["a window over a day", { approval: approvalFor({ not_after: "2026-09-28T09:30:00Z" }), env: SELF_HOSTED }, /longer than 24 hours/],
    ["thresholds a day old", { approval: approvalFor({ thresholds: { ...approvalFor().thresholds, read_at: "2026-09-26T08:00:00Z" } }), env: SELF_HOSTED }, /more than 24 hours ago/],
    ["an announcement rather than an approval", { approval: approvalFor({ approved_by: "minice-e4" }), env: SELF_HOSTED }, /not `owner`/],
    ["no ops record of the approval", { approval: approvalFor({ statement: "the owner said so in chat" }), env: SELF_HOSTED }, /astra-plugins-ops commit/],
  ];
  for (const [name, opts, re] of cases) {
    const r = await burst({ ...opts, outDir: scratch(), base: "http://127.0.0.1:9/plugins/v1/", now: () => NOW, sleep: async () => {}, log: quiet });
    assert.equal(r.fired, false, `${name}: fired`);
    assert.ok(r.refusals.some((p) => re.test(p)), `${name}: ${r.refusals.join(" | ")}`);
  }
  assert.deepEqual(approvalProblems(approvalFor(), { now: NOW, source: SOURCE }), [], "the valid approval fixture is not valid");
});

test("an approved burst sends both shapes at their sizes, reads twice 60 s apart, and ends removal-pending", async () => {
  const s = await stub();
  try {
    const out = scratch();
    const slept = [];
    const r = await burst({ approval: approvalFor(), env: SELF_HOSTED, outDir: out, base: s.base, now: () => NOW, sleep: async (ms) => { slept.push(ms); }, log: quiet });
    assert.equal(r.fired, true);
    const shapes = shapesFor(approvalFor(), approvalFor().burst_id);
    assert.equal(shapes.a, 7, "shape A is not above the measured 6th-POST threshold");
    assert.equal(shapes.b, 12, "shape B is not above the measured 11th-path threshold");
    const posts = s.journal.filter((x) => x.method === "POST" && x.url === "/plugins/v1/bot/leases");
    assert.equal(posts.length, 7);
    assert.ok(posts.every((p) => p.headers.authorization === undefined), "a burst POST carried a credential");
    const gets = s.journal.filter((x) => x.method === "GET").map((x) => x.url);
    const shapeB = gets.slice(0, 12);
    assert.equal(new Set(shapeB).size, 12, "shape B's paths are not distinct");
    assert.ok(shapeB.some((u) => /\/conformance-no-such-route-/.test(u)), "shape B has no unknown route");
    assert.ok(shapeB.some((u) => /\/health\?burst=/.test(u)), "shape B has no known route under a distinct query");
    assert.deepEqual(gets.slice(12), ["/plugins/v1/health", "/plugins/v1/health"], "not two ordinary reads after the burst");
    assert.deepEqual(slept, [BURST_FLOOR.second_read_seconds * 1000]);
    assert.equal(r.result.schema, BURST_RESULT_SCHEMA);
    assert.equal(r.result.state, "removal-pending");
    assert.deepEqual(r.result.findings, []);
    assert.ok(fs.existsSync(r.resultFile));
    assert.equal(fs.readFileSync(r.resultFile, "utf8").includes(SOURCE), false, "the source address reached the result file");

    const again = await burst({ approval: approvalFor(), env: SELF_HOSTED, outDir: out, base: s.base, now: () => NOW, sleep: async () => {}, log: quiet });
    assert.equal(again.fired, false);
    assert.ok(again.refusals.some((p) => /one burst per approval/.test(p)));

    // Thresholds that moved size the shapes up, never below the floor.
    const moved = shapesFor(approvalFor({ thresholds: { ...approvalFor().thresholds, brute_force_overflow_at: 9, probing_overflow_at: 4 } }), approvalFor().burst_id);
    assert.equal(moved.a, 10);
    assert.equal(moved.b, 12);
  } finally {
    await s.close();
  }
});

test("a burst after which a read fails is recorded with the finding", async () => {
  const s = await stub((req, b) => (req.url === "/plugins/v1/health" ? { status: 503, body: refusal("unavailable") } : conforming(req, b)));
  try {
    const r = await burst({ approval: approvalFor(), env: SELF_HOSTED, outDir: scratch(), base: s.base, now: () => NOW, sleep: async () => {}, log: quiet });
    assert.equal(r.fired, true);
    assert.ok(r.result.findings.some((f) => /first ordinary read/.test(f)));
    assert.ok(r.result.findings.some((f) => /second ordinary read/.test(f)));
  } finally {
    await s.close();
  }
});

test("a burst is complete only with its decision's removal recorded — watched by dropping the removal", async () => {
  const s = await stub();
  let result;
  try {
    result = (await burst({ approval: approvalFor(), env: SELF_HOSTED, outDir: scratch(), base: s.base, now: () => NOW, sleep: async () => {}, log: quiet })).result;
  } finally {
    await s.close();
  }
  const removal = {
    schema: REMOVAL_SCHEMA,
    burst_id: result.burst_id,
    command: "cscli decisions delete",
    decision_seen: false,
    removed_at: "2026-09-27T10:05:00Z",
    recorded_in: `astra-plugins-ops@${"c".repeat(40)}:notes/state.md#ops-29`,
  };
  assert.equal(completeBurst(result, null).complete, false, "a burst with no removal recorded reported complete");
  assert.equal(completeBurst(result, { ...removal, burst_id: "0f2a11c8-9d44-4b6e-8a01-77c0de91b433" }).complete, false);
  assert.equal(completeBurst(result, { ...removal, removed_at: "2026-09-27T09:59:00Z" }).complete, false,
    "a removal from before the burst ended was accepted");
  assert.equal(completeBurst(result, { ...removal, decision_seen: undefined }).complete, false,
    "a removal that does not say whether a ban was seen was accepted");
  assert.equal(completeBurst(result, { ...removal, command: "echo removed" }).complete, false);
  const done = completeBurst(result, removal);
  assert.equal(done.complete, true, done.problems.join(" | "));
  assert.equal(done.record.state, "complete");
});

// ── the workflow ────────────────────────────────────────────────────────────

test("the workflow probes with no bot token, fires no burst on a schedule, and names the removal step", () => {
  const yaml = fs.readFileSync(WORKFLOW, "utf8");
  const code = yaml.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
  assert.match(yaml, /^name: Service conformance$/m);
  assert.equal(/plugins-service/.test(code), false, "the conformance workflow names plugins-service, which would make it a bot job");
  assert.equal(/--base\b/.test(code), false, "the workflow points the harness at a base other than the compiled one");
  // The schedule is hourly, off the hour, and dark until the service answers.
  const cron = /^\s*#\s*-\s*cron:\s*'([^']+)'/m.exec(yaml)?.[1];
  assert.equal(cron, "29 * * * *");
  assert.equal(/^\s{2}schedule:/m.test(yaml), false, "the schedule is live before the service answers");
  // One boolean dispatch input, `burst`, and the two burst steps are gated on it.
  const inputs = [...yaml.matchAll(/^\s{6}([a-z-]+):\s*$/gm)].map((m) => m[1]).filter((n) => n !== "inputs");
  assert.deepEqual(inputs, ["burst"], `the dispatch takes ${JSON.stringify(inputs)}`);
  assert.match(code, /type: boolean/);
  const steps = code.split(/\n\s+- name: /).slice(1);
  const burstStep = steps.find((s) => /--burst --out-dir/.test(s));
  const removalStep = steps.find((s) => /--burst-complete/.test(s));
  assert.ok(burstStep && /if: inputs\.burst == true/.test(burstStep), "the burst step is not gated on the dispatch input");
  assert.ok(removalStep && /cscli decisions delete/.test(removalStep) && /always\(\)/.test(removalStep),
    "the removal step is missing, unnamed, or skipped when the burst fails");
  // The probe mints, and runs only on the schedule or a dispatch.
  const probeJob = /^ {2}probe:\n([\s\S]*?)(?=^ {2}[a-z]+:\n)/m.exec(code)?.[1] ?? "";
  assert.match(probeJob, /id-token: write/);
  assert.match(probeJob, /if: github\.event_name == 'schedule' \|\| github\.event_name == 'workflow_dispatch'/);
  // The suite runs first, on every event, and is this file.
  assert.match(code, /node --test bot\/tests\/service-conformance\.test\.mjs/);
});
