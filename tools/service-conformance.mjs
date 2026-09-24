#!/usr/bin/env node
// BOT-90's black-box check of the live plugins service, from the outside, with
// no bot token (registry plan B-T3.11; contract SERVE-83, SERVE-73, BOT-62).
//
//     node tools/service-conformance.mjs --probe [--out report.json]
//     node tools/service-conformance.mjs --table
//     node tools/service-conformance.mjs --burst --approval <file> --out-dir <dir>
//     node tools/service-conformance.mjs --burst-complete --result <file> --removal <file>
//
// `.github/workflows/service-conformance.yml` runs `--probe` hourly (once its
// schedule is on) and `--burst` on a dispatch that asks for one — where, on a
// GitHub-hosted runner, the burst REFUSES. That refusal is not a defect; it is
// the one property of the burst a dispatch can watch (below).
//
// ── where this file lives, and why not where the plan puts it ──────────────
//
// The plan names `bot/service-conformance.mjs`. A new top-level `bot/*.mjs` is
// a contract MINOR under TRUST-31 (`bot/tests/code-paths.test.mjs`, "the two
// enumerated groups are exactly what is on the tree"), published before the
// file lands; and `bot/lib/` would put it INSIDE the hashed set, so every edit
// to a probe the bot never runs would drop the bot into shadow and cost an
// operator acknowledgement (ROLL-64). Neither buys anything: no bot workflow
// reaches this file, it writes nothing to git, and nothing the bot decides
// reads what it says. So it is a desk-and-CI tool beside `tools/cutover-
// preflight.mjs`, outside the set, and it IMPORTS the two things it must not
// have a second copy of — the service API base and the request composer from
// `bot/lib/service.mjs`, and the bot audience and token-endpoint names from
// `bot/lib/oidc.mjs` — so a change there is a change here.
//
// ── what is expected, and what is only logged ──────────────────────────────
//
// Four legs, each at a path the token file records and never at one typed
// here and trusted (`LEGS`; `tablePlan` holds the two to each other):
//
//   token_refused      POST bot/leases, a valid `astra.plugins.bot-claim/1`
//                      body, bearing an OIDC token THIS non-bot workflow
//                      minted with the bot audience. BOT-91 refuses a token
//                      whose `job_workflow_ref` names no bot workflow.
//   unauthenticated    GET ratings/<plugin_id> — CLIENT-80's `rating.get` —
//                      with no bearer. The service checks the bearer before
//                      the surface switch, so the answer is `unauthenticated`
//                      whatever the surface's state.
//   plugin_not_listed  GET listings/{plugin_id}, a `service-only` path (§0.8's
//                      named paths, contract 0.24.0), for an id no listing
//                      carries. The only credential-free door that answers it:
//                      every CLIENT-80 operation that does is behind a bearer
//                      this job holds none of (attack M-8).
//   health             GET health, the read that must succeed. The body is
//                      `astra.plugins.health/1`, named in §0.8's prose; the
//                      one refusal it can carry is `unavailable`.
//
// On every answer: `X-Content-Type-Options: nosniff` and an exact
// `Content-Type` (SERVE-83); on every refusal, a body that is exactly
// `astra.plugins.error/1` — its required members, of their types, and no
// member the token file does not publish for it. **Statuses are logged and
// never asserted.** They are the service's (§0.8), and SERVE-73 records
// minice-be's status policy only as its mechanism: a check that asserted 422
// would be red the day they chose 409, about nothing a party agreed.
//
// "An exact `Content-Type`" is read as the media type `application/json`,
// with at most the parameter `charset=utf-8`. SERVE-83 says "exact" and names
// no value; Table 5-A names `application/json` for the catalogue host, which
// is the only value the contract spells. A `text/plain`, an absent header, two
// headers, or `application/json` with any other parameter is a finding.
//
// ── the token-file comparison, and its floor ───────────────────────────────
//
// Two legs are at SCOPE-8 paths — an `operation` entry each, emitted by the
// bot and by the client — and two at `service-only` paths, which carry no
// party and are outside SCOPE-8's two-way test (the token file's readme). So
// the comparison runs against `entries` for the first two and against the
// `service_only` list for the other two, and **the `service_only` half has a
// floor of 2**: both entries are published (0.24.0), and a token file that
// has stopped carrying them is a regression to be red about, not a reason to
// point the leg somewhere else. A leg whose entry is missing is SKIPPED, by
// name, and the floor makes the skip red: the leg is never re-pointed, which
// is how a conformance check becomes decoration (attack M-8).
//
// A `service-only` entry says the path is ROUTED and does not say a handler
// answers it (the readme, verbatim from minice-be). Of the two here, `health`
// was answered at 0.24.0 and `listings-view` was a stub answering 503
// `unavailable`. So the `plugin_not_listed` leg can be red against a live
// service for a reason that is the service's to fix; this file reports it and
// does not soften it.
//
// ── the burst ─────────────────────────────────────────────────────────────
//
// BOT-62's Check is "the burst of registry plan: BOT-90", so it stays, and it
// is built to prove what it claims and to be unable to ban a machine nobody
// controls (attack M-3):
//
//   * OWNER APPROVAL, one per burst. `--approval` names a record of it
//     (`approvalProblems`), bound to one burst id, to a trigger (`r3-exit` or
//     `edge-change`), to a window of at most 24 hours, and to the SHA-256 of
//     the source address. The record lives in astra-plugins-ops, where the
//     owner's approvals are recorded, and it carries a reference to that
//     commit and path — not the owner's words, and not the address.
//   * Never from a GitHub-hosted runner: its address is shared with other
//     tenants and the registry's own next ingest run may draw it. So it
//     refuses when `RUNNER_ENVIRONMENT` is `github-hosted`, and when the
//     process is in Actions and cannot say which runner it is on.
//   * From the address the owner approved, and never one that administers the
//     box: the ban is a port-blind DROP that takes ssh with it. The address is
//     configured on the machine (`ASTRA_BURST_SOURCE`), compared by hash with
//     the approval, and never printed.
//   * Two shapes, sized from thresholds re-read before each burst — the
//     approval carries them and the time they were read, which must be within
//     24 hours, because the crowdsec hub updates nightly and unattended:
//       - A: at least max(7, the brute-force overflow + 1) POSTs to one write
//         path within 10 s, each refused;
//       - B: at least max(12, the probing overflow + 1) distinct raw paths
//         within 10 s, one of them an unknown route and one a known route
//         under a distinct query string.
//     Then one ordinary read that must succeed, and a second from the same
//     address 60 s later: a ban is a DROP, so the first read may merely time
//     out, and one read cannot tell "no ban" from "banned".
//   * The removal of the decision afterwards (`cscli decisions delete` for
//     that address, run on the box by the operator) is a step the burst does
//     not end without. `--burst` ends `removal-pending` and exits non-zero;
//     only `--burst-complete`, handed a removal record for the same burst id
//     written after the burst ended, reports it complete. Whether a ban was
//     seen or not, the removal is recorded.
//
// This file fires nothing on its own schedule. The burst is an owner-approved
// act that the plugins-service session fires; a dispatch of the workflow from
// GitHub is refused by construction, which is the watched failure.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { API_BASE, BODIES, composeBody } from "../bot/lib/service.mjs";
import { BOT_AUDIENCE, REQUEST_TOKEN_VAR, REQUEST_URL_VAR, decodeClaims, mintProblems } from "../bot/lib/oidc.mjs";
import { ID_PATTERN } from "./lib/ids.mjs";
import { isTime } from "./lib/time.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

/** SCOPE-7's file, read from THIS checkout (never from a tree under test). */
export const TOKEN_FILE = "schema/contract-tokens-v1.json";

const USER_AGENT = "astra-registry-conformance (+https://github.com/mihailinl/astra-registry)";
const CALL_TIMEOUT_MS = 20_000;

/**
 * An id no listing carries: shaped as §0.7's plugin id, under no reserved
 * name or prefix, and asserted absent from this checkout's `plugins/` and
 * index before a leg uses it (`absentIdProblems`). A fixed string rather than
 * a random one, so that two hourly runs ask the same question.
 */
export const ABSENT_ID = "conformance-absent-probe";

/** The error schema a refusal must be, with its members as the bot compiles them. */
export const ERROR_SCHEMA = "astra.plugins.error/1";

/** The body the health read names in §0.8's prose. */
export const HEALTH_SCHEMA = "astra.plugins.health/1";

/**
 * The four legs, compiled in. Each names the token-file record it must equal;
 * `tablePlan` compares method and path, and a leg whose record is missing is
 * skipped by name rather than pointed elsewhere.
 */
export const LEGS = Object.freeze([
  Object.freeze({
    leg: "token_refused",
    code: "BOT90_TOKEN_REFUSED",
    record: "operation:bot:claim",
    list: "entries",
    method: "POST",
    path: "bot/leases",
    credential: "non-bot-oidc",
    body: "astra.plugins.bot-claim/1",
    expect: Object.freeze({ refusal: "token_refused" }),
  }),
  Object.freeze({
    leg: "unauthenticated",
    code: "BOT90_UNAUTHENTICATED",
    record: "operation:client:rating.get",
    list: "entries",
    method: "GET",
    path: "ratings/<plugin_id>",
    credential: "none",
    expect: Object.freeze({ refusal: "unauthenticated" }),
  }),
  Object.freeze({
    leg: "plugin_not_listed",
    code: "BOT90_PLUGIN_NOT_LISTED",
    record: "service-only:listings-view",
    list: "service_only",
    method: "GET",
    path: "listings/{plugin_id}",
    credential: "none",
    expect: Object.freeze({ refusal: "plugin_not_listed" }),
  }),
  Object.freeze({
    leg: "health",
    code: "BOT90_HEALTH",
    record: "service-only:health",
    list: "service_only",
    method: "GET",
    path: "health",
    credential: "none",
    expect: Object.freeze({ success: HEALTH_SCHEMA }),
  }),
]);

/** The `service_only` half of the comparison: both published entries, or red. */
export const SERVICE_ONLY_FLOOR = 2;

/** The verdict codes this tool emits, and nothing else: never a sentence, never a service string. */
export const CODES = Object.freeze([
  "BOT90_PATH_TABLE",
  "BOT90_TOKEN_MINT",
  "BOT90_TOKEN_REFUSED",
  "BOT90_UNAUTHENTICATED",
  "BOT90_PLUGIN_NOT_LISTED",
  "BOT90_HEALTH",
  "BOT90_REFUSAL_BODY",
  "BOT90_UNREACHABLE",
  "SERVE_83_HEADERS",
]);

// ── the token file ──────────────────────────────────────────────────────────

export function readTokenFile(root = REPO_ROOT) {
  return JSON.parse(fs.readFileSync(path.join(root, TOKEN_FILE), "utf8"));
}

/**
 * Every leg against the record it names, and the audience against the
 * file's. Returns the legs that may run, the legs skipped (by name, with the
 * wait that lifts them), and the problems, which make the run red.
 *
 * @returns {{run: object[], skipped: {leg: string, why: string}[], problems: string[], serviceOnlyMatched: number}}
 */
export function tablePlan(doc, legs = LEGS) {
  const problems = [];
  const skipped = [];
  const run = [];
  let serviceOnlyMatched = 0;
  const lists = {
    entries: Array.isArray(doc?.entries) ? doc.entries : null,
    service_only: Array.isArray(doc?.service_only) ? doc.service_only : null,
  };
  if (!lists.entries) problems.push(`${TOKEN_FILE} carries no \`entries\` list`);
  if (!lists.service_only) problems.push(`${TOKEN_FILE} carries no \`service_only\` list`);

  const audience = lists.entries?.find((e) => e?.id === "audience:bot");
  if (!audience) problems.push(`${TOKEN_FILE} carries no \`audience:bot\` entry, so the token_refused leg's audience is compared with nothing`);
  else if (audience.value !== BOT_AUDIENCE) {
    problems.push(`the bot audience is ${JSON.stringify(audience.value)} in ${TOKEN_FILE} and ${JSON.stringify(BOT_AUDIENCE)} in bot/lib/oidc.mjs`);
  }

  for (const leg of legs) {
    const found = lists[leg.list]?.find((e) => e?.id === leg.record) ?? null;
    if (!found) {
      const why = leg.list === "service_only"
        ? `${TOKEN_FILE}'s \`service_only\` list carries no \`${leg.record}\`, so this leg has no published path ` +
          "and is not pointed at another (attack M-8). minice-be publishes the entry (registry plan §1.3 row 8.6)"
        : `${TOKEN_FILE} carries no \`${leg.record}\``;
      skipped.push({ leg: leg.leg, why });
      if (leg.list === "entries") problems.push(why);
      continue;
    }
    if (found.method !== leg.method || found.path !== leg.path) {
      problems.push(
        `${leg.leg}: this tool calls ${leg.method} ${leg.path} and ${TOKEN_FILE}'s \`${leg.record}\` is ` +
        `${found.method ?? "(no method)"} ${found.path ?? "(no path)"}. A leg aimed at a path the file does not ` +
        "publish tests the tool, not the service",
      );
      continue;
    }
    if (leg.list === "service_only") {
      if (found.state !== "service-only") problems.push(`${leg.record} is in \`service_only\` with state ${JSON.stringify(found.state)}`);
      serviceOnlyMatched += 1;
    }
    if (leg.list === "entries" && leg.credential === "non-bot-oidc" && !(found.emitter ?? []).includes("bot")) {
      problems.push(`${leg.record} is not a bot operation in ${TOKEN_FILE}, and the token_refused leg is about one`);
    }
    if (leg.expect.refusal) {
      const token = lists.entries?.find((e) => e?.id === `token:${leg.expect.refusal}`);
      if (!token || token.kind !== "refusal_token") {
        problems.push(`${TOKEN_FILE} lists no refusal token \`${leg.expect.refusal}\`, which the ${leg.leg} leg expects`);
        continue;
      }
    }
    run.push(leg);
  }
  if (serviceOnlyMatched < SERVICE_ONLY_FLOOR) {
    problems.push(
      `${serviceOnlyMatched} of the legs at \`service-only\` paths matched an entry in ${TOKEN_FILE}, and the floor ` +
      `is ${SERVICE_ONLY_FLOOR}: both entries were published at contract 0.24.0, so a file without one of them is ` +
      "a regression, and the leg it named is skipped rather than aimed elsewhere",
    );
  }
  return { run, skipped, problems, serviceOnlyMatched };
}

/** The members `astra.plugins.error/1` may carry, as `bot/lib/service.mjs` compiles them. */
export function errorMembers() {
  const def = BODIES[ERROR_SCHEMA];
  if (!def) throw new Error(`bot/lib/service.mjs compiles no ${ERROR_SCHEMA}`);
  const all = def.members.map(([name]) => name);
  const required = def.members.filter(([, req]) => req === true).map(([name]) => name);
  return { all, required };
}

/** Why ABSENT_ID (or another) is not an id no listing here carries, or []. */
export function absentIdProblems(id = ABSENT_ID, root = REPO_ROOT) {
  const problems = [];
  if (!new RegExp(ID_PATTERN).test(id)) problems.push(`${id} is not §0.7's plugin id`);
  const reserved = JSON.parse(fs.readFileSync(path.join(root, "policy", "reserved-ids.json"), "utf8"));
  if ((reserved.reserved ?? []).includes(id)) problems.push(`${id} is a reserved id`);
  if ((reserved.reserved_prefixes ?? []).some((p) => id.startsWith(p))) problems.push(`${id} is under a reserved prefix`);
  if (fs.existsSync(path.join(root, "plugins", id))) problems.push(`plugins/${id}/ exists in this checkout`);
  const index = path.join(root, "registry", "v1", "index.json");
  if (fs.existsSync(index) && fs.readFileSync(index, "utf8").includes(`"${id}"`)) {
    problems.push(`${id} appears in registry/v1/index.json`);
  }
  return problems;
}

// ── one answer ──────────────────────────────────────────────────────────────

/** SERVE-83 on one response. */
export function headerProblems(headers) {
  const problems = [];
  const get = (n) => (typeof headers?.get === "function" ? headers.get(n) : null);
  const nosniff = get("x-content-type-options");
  if (nosniff === null || nosniff.trim().toLowerCase() !== "nosniff") {
    problems.push(`X-Content-Type-Options is ${JSON.stringify(nosniff)} and SERVE-83 requires \`nosniff\``);
  }
  const type = get("content-type");
  if (type === null) {
    problems.push("no Content-Type, and SERVE-83 requires an exact one");
  } else {
    // `Headers.get` joins repeated headers with ", ", which no single
    // `application/json` value contains.
    const [media, ...params] = type.split(";").map((s) => s.trim().toLowerCase());
    const extra = params.filter((p) => p !== "charset=utf-8");
    if (media !== "application/json" || extra.length || type.includes(",")) {
      problems.push(`Content-Type is ${JSON.stringify(type)}; SERVE-83's exact type is \`application/json\`, at most with \`charset=utf-8\``);
    }
  }
  return problems;
}

/** A refusal body, held to `astra.plugins.error/1` exactly. */
export function refusalBodyProblems(body) {
  const problems = [];
  if (body === null || typeof body !== "object" || Array.isArray(body)) return ["the refusal body is not a JSON object"];
  const { all, required } = errorMembers();
  if (body.schema !== ERROR_SCHEMA) problems.push(`the refusal names schema ${JSON.stringify(body.schema ?? null)} and not ${ERROR_SCHEMA}`);
  for (const m of required) if (!(m in body)) problems.push(`\`${m}\` is required by ${ERROR_SCHEMA} and is absent`);
  for (const m of ["error", "message"]) if (m in body && typeof body[m] !== "string") problems.push(`\`${m}\` is not a string`);
  if (typeof body.error === "string" && !/^[a-z][a-z0-9_]{0,63}$/.test(body.error)) problems.push(`\`error\` is not a §0.8 token`);
  for (const m of Object.keys(body)) {
    if (!all.includes(m)) problems.push(`\`${m}\` is not a member ${TOKEN_FILE} publishes for ${ERROR_SCHEMA}`);
  }
  return problems;
}

/**
 * One leg's answer, judged. `answer` is `{status, headers, text}` or
 * `{unreachable: reason}`.
 *
 * @returns {{problems: {code: string, what: string}[], logged: string}}
 */
export function judge(leg, answer) {
  const out = [];
  if (answer.unreachable) {
    return {
      problems: [{ code: "BOT90_UNREACHABLE", what: `${leg.leg}: the service could not be reached: ${answer.unreachable}` }],
      logged: `${leg.leg}: unreachable`,
    };
  }
  for (const p of headerProblems(answer.headers)) out.push({ code: "SERVE_83_HEADERS", what: `${leg.leg}: ${p}` });
  let body = null;
  try {
    body = answer.text === "" ? null : JSON.parse(answer.text);
  } catch {
    body = null;
  }
  const isRefusal = body !== null && typeof body === "object" && body.schema === ERROR_SCHEMA;
  if (isRefusal || leg.expect.refusal) {
    // Every refusal, whichever leg met it, is held to the error body.
    if (isRefusal) for (const p of refusalBodyProblems(body)) out.push({ code: "BOT90_REFUSAL_BODY", what: `${leg.leg}: ${p}` });
  }
  if (leg.expect.refusal) {
    if (!isRefusal) {
      out.push({ code: leg.code, what: `${leg.leg}: expected the refusal \`${leg.expect.refusal}\` and the answer is not an ${ERROR_SCHEMA} body` });
    } else if (body.error !== leg.expect.refusal) {
      out.push({ code: leg.code, what: `${leg.leg}: expected \`${leg.expect.refusal}\` and the service refused with \`${String(body.error)}\`` });
    }
  } else if (leg.expect.success) {
    if (isRefusal) {
      out.push({ code: leg.code, what: `${leg.leg}: the read that must succeed was refused with \`${String(body.error)}\`` });
    } else if (body === null || typeof body !== "object" || body.schema !== leg.expect.success) {
      out.push({ code: leg.code, what: `${leg.leg}: the answer does not name ${leg.expect.success}` });
    }
  }
  const said = isRefusal ? `refused \`${String(body.error)}\`` : body?.schema ? `answered ${String(body.schema)}` : "answered";
  // The status is logged, never asserted (SERVE-73; §0.8).
  return { problems: out, logged: `${leg.leg}: HTTP ${answer.status}, ${said}` };
}

// ── the credential for the one leg that needs one ───────────────────────────

/**
 * An OIDC token this NON-bot workflow mints with the bot audience.
 *
 * Not `bot/lib/oidc.mjs`'s `mintToken`, deliberately: that one refuses a token
 * whose `environment` is not `plugins-service`, which is every token this job
 * can mint. The two checks here are its inverse. The token must carry the bot
 * audience — or the leg asks nothing BOT-91 answers — and it must NOT carry
 * the bot's environment, or this job would be holding a bot token, which
 * BOT-90 forbids. The mask precedes everything, as there.
 */
export async function mintNonBotToken({ env = process.env, fetchImpl = fetch, log = console } = {}) {
  const problems = mintProblems(env);
  if (problems.length) throw new Error(problems.join("\n"));
  const url = `${env[REQUEST_URL_VAR]}&audience=${encodeURIComponent(BOT_AUDIENCE)}`;
  const res = await fetchImpl(url, {
    headers: { Authorization: `Bearer ${env[REQUEST_TOKEN_VAR]}`, Accept: "application/json; api-version=2.0", "User-Agent": USER_AGENT },
    redirect: "manual",
    signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`the Actions token endpoint answered HTTP ${res.status}`);
  const token = (await res.json())?.value;
  if (typeof token !== "string" || token === "") throw new Error("the Actions token endpoint answered with no `value`");
  log.log(`::add-mask::${token}`);
  const claims = decodeClaims(token);
  if (claims.aud !== BOT_AUDIENCE) throw new Error(`the minted token's audience is ${JSON.stringify(claims.aud ?? null)}, not the bot's`);
  if (claims.environment === "plugins-service") {
    throw new Error("the minted token names environment `plugins-service`: this job would be holding a bot token, which BOT-90 forbids");
  }
  return { token, claims };
}

// ── the probe ───────────────────────────────────────────────────────────────

async function call({ base, method, rel, headers = {}, body = null, fetchImpl }) {
  let res;
  try {
    res = await fetchImpl(new URL(rel, base).toString(), {
      method,
      headers: { Accept: "application/json", "User-Agent": USER_AGENT, ...headers },
      body: body ?? undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
    });
  } catch (e) {
    return { unreachable: String(e?.cause?.code ?? e?.message ?? e) };
  }
  const text = await res.text().catch(() => "");
  if (res.status >= 300 && res.status < 400) {
    return { unreachable: `HTTP ${res.status}, a redirect, which is never followed` };
  }
  return { status: res.status, headers: res.headers, text };
}

const fill = (p, id) => p.replace("<plugin_id>", id).replace("{plugin_id}", id);

/**
 * The hourly probe. `base` and `mint` are injected by the tests; the workflow
 * passes neither, so the compiled base and a real mint are what run.
 *
 * @returns {Promise<{status: "green"|"red", codes: string[], legs: object[], skipped: object[], problems: string[]}>}
 */
export async function probe({
  base = API_BASE,
  fetchImpl = fetch,
  mint = (o) => mintNonBotToken(o),
  env = process.env,
  root = REPO_ROOT,
  doc = null,
  absentId = ABSENT_ID,
  log = console,
} = {}) {
  const tokens = doc ?? readTokenFile(root);
  const plan = tablePlan(tokens);
  const findings = plan.problems.map((what) => ({ code: "BOT90_PATH_TABLE", what }));
  for (const s of plan.skipped) log.log(`SKIP  ${s.leg}: ${s.why}`);
  for (const p of absentIdProblems(absentId, root)) findings.push({ code: "BOT90_PATH_TABLE", what: p });

  const legs = [];
  for (const leg of plan.run) {
    const headers = {};
    let body = null;
    if (leg.credential === "non-bot-oidc") {
      try {
        const { token } = await mint({ env, fetchImpl, log });
        headers.Authorization = `Bearer ${token}`;
      } catch (e) {
        findings.push({ code: "BOT90_TOKEN_MINT", what: `token_refused: no token to present: ${String(e?.message ?? e).split("\n")[0]}` });
        legs.push({ leg: leg.leg, ran: false });
        continue;
      }
    }
    if (leg.body) {
      body = composeBody(leg.body, { wanted: 1 });
      headers["Content-Type"] = "application/json";
    }
    const answer = await call({ base, method: leg.method, rel: fill(leg.path, absentId), headers, body, fetchImpl });
    const judged = judge(leg, answer);
    log.log(`      ${judged.logged}`);
    findings.push(...judged.problems);
    legs.push({ leg: leg.leg, ran: true, status: answer.status ?? null, problems: judged.problems.map((p) => p.what) });
  }
  for (const f of findings) log.log(`FAIL  ${f.code} ${f.what}`);
  const codes = [...new Set(findings.map((f) => f.code))].sort();
  for (const c of codes) if (!CODES.includes(c)) throw new Error(`${c} is not one of this tool's codes`);
  return {
    status: findings.length === 0 && plan.skipped.length === 0 ? "green" : "red",
    codes,
    legs,
    skipped: plan.skipped,
    problems: findings.map((f) => `${f.code} ${f.what}`),
  };
}

// ── the burst ───────────────────────────────────────────────────────────────

export const APPROVAL_SCHEMA = "astra.ops.burst-approval/1";
export const REMOVAL_SCHEMA = "astra.ops.burst-removal/1";
export const BURST_RESULT_SCHEMA = "astra.registry.burst-result/1";

/** The measured floors of 2026-09-17 (plan §2.5), below which no approval may size a shape. */
export const BURST_FLOOR = Object.freeze({ shape_a_posts: 7, shape_b_paths: 12, window_seconds: 10, second_read_seconds: 60 });

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OPS_REF_RE = /^astra-plugins-ops@[0-9a-f]{40}:[A-Za-z0-9._/-]+(?:#[A-Za-z0-9._-]+)?$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const HOUR_MS = 3600_000;

export const sha256 = (s) => crypto.createHash("sha256").update(String(s), "utf8").digest("hex");

/**
 * Why this approval record does not license a burst now, or [].
 *
 * One burst per record: its `burst_id` names the result file the burst
 * writes, and `--burst` refuses a record whose result already exists.
 */
export function approvalProblems(a, { now = new Date(), source = null } = {}) {
  const p = [];
  if (a === null || typeof a !== "object" || Array.isArray(a)) return ["the approval is not a JSON object"];
  const members = ["schema", "burst_id", "trigger", "approved_by", "approved_at", "not_after", "statement", "service_told_at", "source_address_sha256", "thresholds"];
  for (const k of Object.keys(a)) if (!members.includes(k)) p.push(`\`${k}\` is not a member of ${APPROVAL_SCHEMA}`);
  if (a.schema !== APPROVAL_SCHEMA) p.push(`schema is ${JSON.stringify(a.schema ?? null)}, not ${APPROVAL_SCHEMA}`);
  if (!UUID_V4_RE.test(String(a.burst_id))) p.push("`burst_id` is not a lowercase UUID v4");
  if (a.trigger !== "r3-exit" && a.trigger !== "edge-change") p.push("`trigger` is neither `r3-exit` nor `edge-change`");
  if (a.approved_by !== "owner") p.push("`approved_by` is not `owner`: a burst is the owner's approval, one per burst, and not an announcement");
  if (!OPS_REF_RE.test(String(a.statement))) p.push("`statement` does not name the astra-plugins-ops commit and path the approval is recorded at");
  for (const k of ["approved_at", "not_after", "service_told_at"]) if (!isTime(a[k])) p.push(`\`${k}\` is not a §0.7 time`);
  if (isTime(a.approved_at) && isTime(a.not_after)) {
    const from = Date.parse(a.approved_at);
    const to = Date.parse(a.not_after);
    if (to <= from) p.push("`not_after` is not after `approved_at`");
    if (to - from > 24 * HOUR_MS) p.push("the approval's window is longer than 24 hours");
    if (now.getTime() < from) p.push("the approval is dated in the future");
    if (now.getTime() > to) p.push("the approval has expired");
  }
  if (!SHA256_RE.test(String(a.source_address_sha256))) p.push("`source_address_sha256` is not a SHA-256");
  else if (source !== null && sha256(source) !== a.source_address_sha256) {
    p.push("the configured source address is not the one the owner approved (their SHA-256 differ)");
  }
  const t = a.thresholds;
  if (t === null || typeof t !== "object") p.push("`thresholds` is missing: they are re-read before each burst");
  else {
    for (const k of ["brute_force_overflow_at", "probing_overflow_at"]) {
      if (!Number.isInteger(t[k]) || t[k] < 1) p.push(`\`thresholds.${k}\` is not a positive integer`);
    }
    if (!isTime(t.read_at)) p.push("`thresholds.read_at` is not a §0.7 time");
    else if (now.getTime() - Date.parse(t.read_at) > 24 * HOUR_MS) {
      p.push("the thresholds were read more than 24 hours ago, and the crowdsec hub updates nightly and unattended");
    }
    if (!OPS_REF_RE.test(String(t.source))) p.push("`thresholds.source` does not name where the re-read is recorded");
  }
  return p;
}

/** The environment's refusals, before any approval is read. */
export function runnerProblems(env = process.env) {
  const p = [];
  if (env.RUNNER_ENVIRONMENT === "github-hosted") {
    p.push("this is a GitHub-hosted runner. Its address is shared with other tenants and controlled by nobody, and the registry's own next ingest run may draw it: the burst never fires from one");
  } else if (env.GITHUB_ACTIONS === "true" && env.RUNNER_ENVIRONMENT !== "self-hosted") {
    p.push("this is an Actions job that does not say which runner it is on, so it cannot be told from a hosted one");
  }
  const source = env.ASTRA_BURST_SOURCE;
  if (typeof source !== "string" || source.trim() === "") {
    p.push("no ASTRA_BURST_SOURCE: the burst is fired only from the address the owner approved, configured on that machine");
  } else if (!/^[0-9a-fA-F:.]{2,45}$/.test(source.trim())) {
    p.push("ASTRA_BURST_SOURCE is not an IP address literal");
  }
  return p;
}

/** The two shapes, sized from the approval's thresholds and never below the floor. */
export function shapesFor(approval, burstId) {
  const a = Math.max(BURST_FLOOR.shape_a_posts, approval.thresholds.brute_force_overflow_at + 1);
  const b = Math.max(BURST_FLOOR.shape_b_paths, approval.thresholds.probing_overflow_at + 1);
  const tag = burstId.slice(0, 8);
  const paths = [
    `conformance-no-such-route-${tag}`,
    `health?burst=${tag}`,
  ];
  for (let k = 1; paths.length < b; k++) paths.push(`listings/conformance-burst-${tag}-${k}`);
  return { a, b, paths };
}

/**
 * Fire one approved burst. Never called by the hourly probe; refused on a
 * hosted runner and without a live approval. Ends `removal-pending`.
 */
export async function burst({
  approval,
  env = process.env,
  outDir,
  base = API_BASE,
  fetchImpl = fetch,
  now = () => new Date(),
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  log = console,
} = {}) {
  const refusals = [...runnerProblems(env)];
  if (!approval) refusals.push("no approval record: a burst is one owner approval, and there is none");
  else refusals.push(...approvalProblems(approval, { now: now(), source: env.ASTRA_BURST_SOURCE?.trim() ?? null }));
  if (!outDir) refusals.push("no --out-dir to write the burst's result into");
  const resultFile = approval && outDir ? path.join(outDir, `burst-${approval.burst_id}.json`) : null;
  if (resultFile && fs.existsSync(resultFile)) refusals.push("this approval's burst has already been fired: one burst per approval");
  if (refusals.length) return { fired: false, refusals };

  const { a, b, paths } = shapesFor(approval, approval.burst_id);
  const started = now();
  const findings = [];
  const timed = async (label, n, one) => {
    const t0 = Date.now();
    const answers = [];
    for (let i = 0; i < n; i++) answers.push(await one(i));
    const secs = (Date.now() - t0) / 1000;
    if (secs > BURST_FLOOR.window_seconds) findings.push(`shape ${label} took ${secs.toFixed(1)} s, over its ${BURST_FLOOR.window_seconds} s window, so it tested no bucket`);
    return { answers, seconds: secs };
  };
  const claim = composeBody("astra.plugins.bot-claim/1", { wanted: 1 });
  const shapeA = await timed("A", a, () =>
    call({ base, method: "POST", rel: "bot/leases", headers: { "Content-Type": "application/json" }, body: claim, fetchImpl }));
  shapeA.answers.forEach((ans, i) => {
    let body = null;
    try { body = JSON.parse(ans.text ?? ""); } catch { body = null; }
    if (ans.unreachable || body?.schema !== ERROR_SCHEMA) findings.push(`shape A post ${i + 1} was not refused with an ${ERROR_SCHEMA} body`);
  });
  const shapeB = await timed("B", paths.length, (i) => call({ base, method: "GET", rel: paths[i], fetchImpl }));
  if (new Set(paths).size !== paths.length || paths.length < BURST_FLOOR.shape_b_paths) findings.push("shape B's paths are not distinct, or too few");
  const health = LEGS.find((l) => l.leg === "health");
  const read = async () => judge(health, await call({ base, method: "GET", rel: "health", fetchImpl }));
  const first = await read();
  await sleep(BURST_FLOOR.second_read_seconds * 1000);
  const second = await read();
  for (const [label, r] of [["first", first], ["second", second]]) {
    for (const p of r.problems) findings.push(`the ${label} ordinary read after the burst: ${p.what}`);
  }
  const result = {
    schema: BURST_RESULT_SCHEMA,
    burst_id: approval.burst_id,
    trigger: approval.trigger,
    started_at: `${started.toISOString().slice(0, 19)}Z`,
    ended_at: `${now().toISOString().slice(0, 19)}Z`,
    shape_a: { posts: a, seconds: Number(shapeA.seconds.toFixed(3)), statuses: shapeA.answers.map((x) => x.status ?? null) },
    shape_b: { paths: paths.length, seconds: Number(shapeB.seconds.toFixed(3)), statuses: shapeB.answers.map((x) => x.status ?? null) },
    reads: [first.logged, second.logged],
    findings,
    state: "removal-pending",
  };
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(resultFile, `${JSON.stringify(result, null, 2)}\n`);
  log.log(`REMOVAL REQUIRED  burst ${approval.burst_id}: the operator runs \`cscli decisions delete\` for the burst's ` +
    "source address on the box, whether or not a ban was seen, and records it in ops.29; " +
    "then `--burst-complete --result <file> --removal <file>` reports the burst complete");
  return { fired: true, result, resultFile };
}

/** Why this removal record does not complete this burst, or []. */
export function removalProblems(removal, result) {
  const p = [];
  if (removal === null || typeof removal !== "object") return ["the removal record is not a JSON object"];
  if (removal.schema !== REMOVAL_SCHEMA) p.push(`schema is ${JSON.stringify(removal.schema ?? null)}, not ${REMOVAL_SCHEMA}`);
  if (removal.burst_id !== result?.burst_id) p.push("the removal names another burst");
  if (removal.command !== "cscli decisions delete") p.push("`command` is not `cscli decisions delete`");
  if (typeof removal.decision_seen !== "boolean") p.push("`decision_seen` is not a boolean: the removal is recorded whether or not a ban was seen");
  if (!isTime(removal.removed_at)) p.push("`removed_at` is not a §0.7 time");
  else if (isTime(result?.ended_at) && Date.parse(removal.removed_at) < Date.parse(result.ended_at)) {
    p.push("`removed_at` is before the burst ended, so it removed nothing this burst could have caused");
  }
  if (!OPS_REF_RE.test(String(removal.recorded_in))) p.push("`recorded_in` does not name the ops.29 record");
  return p;
}

/** The burst is complete only with its removal recorded. */
export function completeBurst(result, removal) {
  if (result?.schema !== BURST_RESULT_SCHEMA || result?.state !== "removal-pending") {
    return { complete: false, problems: ["the result is not a pending burst result"] };
  }
  const problems = removalProblems(removal, result);
  if (problems.length) return { complete: false, problems };
  return {
    complete: true,
    problems: [],
    record: { ...result, state: result.findings.length ? "complete-with-findings" : "complete", removal },
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function output(pairs) {
  const out = process.env.GITHUB_OUTPUT;
  if (!out) return;
  fs.appendFileSync(out, Object.entries(pairs).map(([k, v]) => `${k}=${v}`).join("\n") + "\n");
}

async function main(argv) {
  const arg = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
  if (argv.includes("--table")) {
    const plan = tablePlan(readTokenFile());
    for (const s of plan.skipped) console.log(`SKIP  ${s.leg}: ${s.why}`);
    for (const p of plan.problems) console.log(`FAIL  ${p}`);
    console.log(`${plan.run.length} leg(s) compiled against ${TOKEN_FILE}; ${plan.serviceOnlyMatched} at service-only paths`);
    return plan.problems.length ? 1 : 0;
  }
  if (argv.includes("--probe")) {
    const report = await probe({});
    output({ status: report.status, codes: report.codes.join(" ") });
    if (arg("--out")) fs.writeFileSync(arg("--out"), `${JSON.stringify(report, null, 2)}\n`);
    console.log(`${report.status}  ${report.legs.filter((l) => l.ran).length} leg(s) ran, ${report.skipped.length} skipped`);
    return report.status === "green" ? 0 : 1;
  }
  if (argv.includes("--burst")) {
    const file = arg("--approval") ?? process.env.ASTRA_BURST_APPROVAL ?? null;
    const approval = file && fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : null;
    const r = await burst({ approval, outDir: arg("--out-dir") });
    if (!r.fired) {
      for (const p of r.refusals) console.error(`::error::burst refused: ${p}`);
      return 1;
    }
    return 3; // removal pending: never 0 until `--burst-complete`
  }
  if (argv.includes("--burst-complete")) {
    const read = (f) => (f && fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : null);
    const done = completeBurst(read(arg("--result")), read(arg("--removal") ?? process.env.ASTRA_BURST_REMOVAL ?? null));
    if (!done.complete) {
      for (const p of done.problems) console.error(`::error::the burst is not complete: ${p}`);
      console.error("::error::the crowdsec decision's removal (`cscli decisions delete`, run on the box and recorded in ops.29) has not been recorded for this burst");
      return 1;
    }
    console.log(JSON.stringify(done.record, null, 2));
    return 0;
  }
  console.error("usage: tools/service-conformance.mjs --probe | --table | --burst --approval F --out-dir D | --burst-complete --result F --removal F");
  return 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => {
    console.error(`::error::${String(e?.message ?? e)}`);
    process.exit(2);
  });
}
