// The three jobs of `plugins-ingest.yml` that hold a bot OIDC token: `claim`,
// `ask` and `report` (registry plan B-T3.1, B-T3.3a's ID-9 mapping, B-T3.5).
//
//   node bot/lib/service-jobs.mjs --job claim
//   node bot/lib/service-jobs.mjs --job ask
//   node bot/lib/service-jobs.mjs --job report --results results/results.json
//
// Each runs in environment `plugins-service`, mints one token per call through
// `bot/lib/oidc.mjs` (which refuses to run outside that environment), and
// talks to the service only through `bot/lib/service.mjs`'s compiled table.
// None of them downloads an asset, reads `.well-known/`, calls `gh
// attestation` or runs `bot/ingest.mjs` — `bot/tests/workflows.test.mjs`
// refuses a token job that does any of the four — and none uploads an
// artifact: what a token job learns leaves it as a job output (BOT-55).
//
// It lives under `bot/lib/` rather than beside `bot/moderation-run.mjs`
// because a new top-level `bot/*.mjs` is an entry TRUST-31's published set
// enumerates, and publishing one is a contract MINOR that must come first
// (contract 0.20.0; `bot/tests/code-paths.test.mjs`). `bot/lib/` is a
// directory entry of the set, so everything here is hashed already.
//
// ── what `ask` may say (BOT-89) ────────────────────────────────────────────
//
// The run logs of this repository are public, and a binding verdict is a fact
// about a person's account. So `ask` reduces every verdict to the ONE word the
// bot acts on — `pass`, `B_BINDING_UNUSABLE`, `W_ELIGIBILITY_UNREADABLE` or
// `shadow` — and never prints, summarises or outputs `token_state`,
// `minted_for_repository` or `eligibility`. The stop status, the approvals and
// the notice status travel beside it: none of them is a verdict, the approvals
// carry exactly the members DEC-7 publishes in a record anyway, and `decide`
// cannot decide without them.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { ServiceRunFailure, W_SERVICE_UNREACHABLE, composeBody, createClient } from "./service.mjs";
import { CLAIMED_FROM, VERDICT_OUTCOMES } from "./service-decide.mjs";
import { safeRepo, safeTag } from "./intake.mjs";
import { isTime } from "../../tools/lib/time.mjs";

const UUID_V47_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE10_RE = /^[0-9]{1,20}$/;
/** §0.7: the attempt identity is opaque. It is echoed, so it is held to a shape that is safe to echo. */
const ATTEMPT_RE = /^[A-Za-z0-9._:-]{1,128}$/;
/** §0.7: a moderator handle. */
const HANDLE_RE = /^mod-[1-9][0-9]*$/;

/** DEC-7's triggers a lease may carry (§4.3: copied to the record). */
const LEASE_TRIGGERS = Object.freeze(["panel", "ci", "poll"]);
/** §0.8's stop status. */
const STOP_STATUS = Object.freeze(["no_stop", "stopped", "unavailable"]);
/** §0.8's notice status. */
const NOTICE_STATUS = Object.freeze(["sent", "previous_sent", "previous_ended", "pending", "none_unbound"]);
/** §0.8's token states a verdict may carry, and the three that let a check finish (ID-9). */
const USABLE_TOKEN_STATES = Object.freeze(["minted", "seen", "bound"]);

/** BOT-59: at most three leases per claim. */
export const WANTED = 3;

// ── claim ───────────────────────────────────────────────────────────────────

/**
 * Everything wrong with one lease, against §4.3's table and §0.7's grammar.
 *
 * Reading is permissive about members it does not name (SCOPE-3) and strict
 * about the ones it does: a lease is where `repo` and `tag` come from, and a
 * repository name outside the grammar is one nothing downstream may fetch.
 */
export function leaseProblems(lease) {
  const p = [];
  if (!lease || typeof lease !== "object" || Array.isArray(lease)) return ["the lease is not an object"];
  if (!UUID_V47_RE.test(String(lease.submission_id))) p.push("submission_id is not §0.7's UUID v4 or v7");
  if (!isTime(lease.lease_expires_at)) p.push("lease_expires_at is not a §0.7 time");
  if (!ATTEMPT_RE.test(String(lease.attempt ?? ""))) p.push("attempt is not an opaque identity this bot can echo");
  if (!CLAIMED_FROM.includes(lease.claimed_from)) p.push(`claimed_from ${JSON.stringify(lease.claimed_from)} is not one of ${CLAIMED_FROM.join(", ")}`);
  if (!safeRepo(lease.repo)) p.push("repo is not owner/name");
  if (!safeTag(lease.tag)) p.push("tag is not a release tag");
  if (!LEASE_TRIGGERS.includes(lease.trigger)) p.push(`trigger ${JSON.stringify(lease.trigger)} is not panel, ci or poll`);
  if (lease.service_repository_id !== null && !(typeof lease.service_repository_id === "string" && BASE10_RE.test(lease.service_repository_id))) {
    p.push("service_repository_id is neither null nor a base-10 string");
  }
  if (!STOP_STATUS.includes(lease.stop_status)) p.push("stop_status is not §0.8's");
  if (!Array.isArray(lease.decisions)) p.push("decisions is not an array");
  else for (const d of lease.decisions) p.push(...decisionProblems(d).map((x) => `decisions[]: ${x}`));
  return p;
}

/** One DEC-6 decision, as a lease or a gates item carries it. */
export function decisionProblems(d) {
  const p = [];
  if (!d || typeof d !== "object" || Array.isArray(d)) return ["not an object"];
  if (typeof d.code !== "string" || !/^[A-Z]_[A-Z0-9_]{1,62}$/.test(d.code)) p.push("code");
  if (!isTime(d.decided_at)) p.push("decided_at");
  if (d.category !== undefined && typeof d.category !== "string") p.push("category");
  if (d.moderator !== undefined && !HANDLE_RE.test(String(d.moderator))) p.push("moderator is not a §0.7 handle");
  if (d.declared_interest !== undefined && typeof d.declared_interest !== "boolean") p.push("declared_interest");
  return p;
}

/** The members of a lease this bot carries on, and no others (DEC-14: a field a later bot trusts is one it does not ignore). */
function leaseOf(l) {
  return {
    submission_id: l.submission_id,
    lease_expires_at: l.lease_expires_at,
    attempt: l.attempt,
    claimed_from: l.claimed_from,
    repo: l.repo,
    tag: l.tag,
    trigger: l.trigger,
    service_repository_id: l.service_repository_id,
    decisions: l.decisions.map(decisionOf),
    stop_status: l.stop_status,
  };
}

function decisionOf(d) {
  const out = { code: d.code, decided_at: d.decided_at };
  if (d.category !== undefined) out.category = d.category;
  if (d.moderator !== undefined) out.moderator = d.moderator;
  if (d.declared_interest !== undefined) out.declared_interest = d.declared_interest;
  return out;
}

/**
 * `claim`: register what `poll` found (B-T5.1), then claim at most three.
 *
 * @returns {Promise<{submissions: string[], leases: object, shadow: boolean,
 *   registered: string[], refused: object[], alerts: object[]}>}
 */
export async function claimJob({ client, polled = [], log = console }) {
  const registered = [];
  for (const t of polled) {
    if (!safeRepo(t?.repo) || !safeTag(t?.tag)) {
      throw new Error("poll handed on a tag outside the grammar; poll validates before anything leaves it (BOT-1)");
    }
    const answer = await client.call("register", { repo: t.repo, repository_id: t.repository_id ?? null, tag: t.tag, trigger: "poll" });
    if (answer.ok && !answer.unreadable) registered.push(`${t.repo}@${t.tag}`);
  }

  const answer = await client.call("claim", { wanted: WANTED });
  if (!answer.ok) {
    // No leases this run. A wait or a refusal the client has already alerted
    // on; `lease_not_held`/`conflict` cannot answer a claim, and `invalid`
    // is this bot's own request being wrong, which must fail the run.
    if (answer.refused === "invalid") throw new ServiceRunFailure(`the service refused the claim as \`invalid\`: ${answer.message}`);
    log.log(`claim: no leases this run (${answer.wait ?? answer.refused ?? "no answer"})`);
    return { submissions: [], leases: {}, shadow: true, registered, refused: [], alerts: client.alerts };
  }
  const shadow = answer.shadow === true;
  const list = Array.isArray(answer.body?.leases) ? answer.body.leases : [];
  if (list.length > WANTED) {
    throw new ServiceRunFailure(`the service answered ${list.length} leases to a claim for at most ${WANTED} (BOT-59)`);
  }
  const leases = {};
  const refused = [];
  for (const l of list) {
    const problems = leaseProblems(l);
    if (problems.length) {
      // Ids only: a lease is the service's word, and printing its values
      // would print the stranger text a bad one carries.
      refused.push({ submission_id: UUID_V47_RE.test(String(l?.submission_id)) ? l.submission_id : null, problems });
      continue;
    }
    if (leases[l.submission_id]) throw new ServiceRunFailure(`two leases on ${l.submission_id} in one answer (BOT-12)`);
    leases[l.submission_id] = leaseOf(l);
  }
  for (const r of refused) {
    log.error(`::error::claim: a lease${r.submission_id ? ` for ${r.submission_id}` : ""} is outside §4.3's grammar (${r.problems.length} problem(s)); nothing is fetched for it`);
  }
  return { submissions: Object.keys(leases), leases, shadow, registered, refused, alerts: client.alerts };
}

// ── ask ─────────────────────────────────────────────────────────────────────

/**
 * ID-9, as one of BOT-89's four words.
 *
 * `unreadable` → `W_ELIGIBILITY_UNREADABLE`; `ineligible`, token state
 * `unknown`, `revoked`, `expired` or `superseded`, or a token minted for
 * another `repository_id` → `B_BINDING_UNUSABLE`; `eligible` with a usable
 * token minted for this repository → `pass`. An answer marked shadow, or one
 * this client could not read, is `shadow` — in shadow every verdict is
 * `unknown` and `unreadable` (ID-71), and mapping it would be mapping nothing.
 */
export function verdictOutcome(answer) {
  if (!answer?.ok) return null;
  if (answer.shadow === true || answer.unreadable === true) return "shadow";
  const b = answer.body ?? {};
  if (b.eligibility === "unreadable") return "W_ELIGIBILITY_UNREADABLE";
  if (b.eligibility !== "eligible") return "B_BINDING_UNUSABLE";
  if (b.minted_for_repository !== true) return "B_BINDING_UNUSABLE";
  if (!USABLE_TOKEN_STATES.includes(b.token_state)) return "B_BINDING_UNUSABLE";
  return "pass";
}

/** The notice kind a lease's publication reads (§0.8's closed list). */
export function noticeKind({ lease, heldReasons = [] }) {
  if (heldReasons.includes("R_BINDING_CHANGED")) return "binding_changed";
  if (lease.claimed_from === "approved") return "approved";
  if (lease.claimed_from === "delayed") return "delayed";
  return null;
}

/**
 * `ask`: the verdict, the gates and the notice status for every verified
 * submission, reduced to what `decide` acts on.
 *
 * @param {{client: object, submissions: string[], leases: object, verified: object,
 *   heldReasons?: (fingerprint: string) => string[]}} opts
 */
export async function askJob({ client, submissions, leases, verified, heldReasons = () => [] }) {
  const outcome = {};
  const ready = [];
  for (const id of submissions) {
    const v = verified?.[id];
    if (!v || v.outcome !== "ok") {
      outcome[id] = { verdict: null, gates: null, notice: null, shadow: false, skipped: v?.outcome ?? "unverified" };
      continue;
    }
    ready.push(id);
    outcome[id] = { verdict: null, gates: null, notice: null, shadow: false };
  }

  // The verdict — FLOW-74: only where the attested commit carries a line.
  for (const id of ready) {
    const v = verified[id];
    if (v.binding?.outcome !== "one") continue;
    const answer = await client.call("verdict", {
      submission_id: id,
      binding_token: v.binding.token,
      repository_id: v.repository_id,
      repository_owner_id: v.repository_owner_id,
      plugin_id: v.plugin_id,
    });
    if (!answer.ok) {
      outcome[id].wait = W_SERVICE_UNREACHABLE;
      outcome[id].cause = "the verdict could not be read (ID-9)";
      continue;
    }
    const word = verdictOutcome(answer);
    outcome[id].verdict = word;
    if (word === "shadow") outcome[id].shadow = true;
  }

  // The gates, in one batched call. An `unavailable` item is a wait for that
  // submission alone (n13); a call that failed is a wait for all of them.
  if (ready.length) {
    const answer = await client.call("gates", {
      items: ready.map((id) => ({ submission_id: id, fingerprint: verified[id].fingerprint })),
    });
    if (!answer.ok) {
      for (const id of ready) {
        outcome[id].wait = outcome[id].wait ?? W_SERVICE_UNREACHABLE;
        outcome[id].cause = outcome[id].cause ?? "the stop status and decisions could not be read";
      }
    } else {
      const shadow = answer.shadow === true || answer.unreadable === true;
      const items = [...(answer.items ?? []), ...(answer.waiting ?? [])];
      for (const id of ready) {
        const item = items.find((x) => x?.submission_id === id && x?.fingerprint === verified[id].fingerprint);
        if (shadow) outcome[id].shadow = true;
        if (!item) {
          // An item the service did not answer is not a "no stop" (DEC-11).
          outcome[id].gates = { stop_status: "unavailable", decisions: [] };
          continue;
        }
        const decisions = (Array.isArray(item.decisions) ? item.decisions : []).filter((d) => decisionProblems(d).length === 0).map(decisionOf);
        outcome[id].gates = {
          stop_status: STOP_STATUS.includes(item.stop_status) ? item.stop_status : "unavailable",
          decisions,
        };
      }
    }
  }

  // The notice status, for a publication that reads one (BOT-28; ID-60).
  for (const id of ready) {
    const kind = noticeKind({ lease: leases[id], heldReasons: heldReasons(verified[id].fingerprint) });
    if (!kind) continue;
    const answer = await client.call("noticeStatus", { submission_id: id, fingerprint: verified[id].fingerprint, kind });
    if (!answer.ok) {
      outcome[id].wait = outcome[id].wait ?? W_SERVICE_UNREACHABLE;
      outcome[id].cause = outcome[id].cause ?? "the notice status could not be read";
      continue;
    }
    if (answer.shadow === true || answer.unreadable === true) outcome[id].shadow = true;
    const b = answer.body ?? {};
    if (!NOTICE_STATUS.includes(b.status)) continue;
    const notice = { kind, status: b.status };
    if (isTime(b.accepted_at)) notice.accepted_at = b.accepted_at;
    if (isTime(b.ended_at)) notice.ended_at = b.ended_at;
    outcome[id].notice = notice;
  }

  for (const [id, o] of Object.entries(outcome)) {
    if (o.verdict !== null && !VERDICT_OUTCOMES.includes(o.verdict)) {
      throw new Error(`ask composed ${JSON.stringify(o.verdict)} for ${id}, which is not one of BOT-89's four`);
    }
  }
  return { outcome, alerts: client.alerts };
}

// ── report ──────────────────────────────────────────────────────────────────

/** The bytes a result is posted as, and their hash — what a shadow run prints instead (B-T3.5). */
export function resultBytes(body) {
  const bytes = composeBody("astra.plugins.bot-result/1", body);
  return { bytes, hash: crypto.createHash("sha256").update(bytes).digest("hex") };
}

/**
 * `report`: post each result the publish job composed, once per attempt, the
 * body built once and re-sent byte-identical (BOT-17; B-T3.5).
 *
 * A result marked `shadow` is posted NOT AT ALL, a wait included (BOT-92): a
 * reported wait is a state move of its own under FLOW-19. Its kind and body
 * hash go to the step summary. Under `DRY_RUN`, a result naming a commit that
 * was not pushed is held back the same way.
 *
 * @param {{client: object, results: {submission_id: string, kind: string, shadow: boolean,
 *   unposted?: string|null, body: object}[], summary?: (line: string) => void}} opts
 */
export async function reportJob({ client, results, summary = () => {} }) {
  const posted = [];
  const held = [];
  const failed = [];
  for (const r of results) {
    const { hash } = resultBytes(r.body);
    if (r.shadow === true) {
      held.push({ submission_id: r.submission_id, why: "shadow" });
      summary(`shadow  ${r.kind}  sha256:${hash}`);
      continue;
    }
    if (r.unposted) {
      held.push({ submission_id: r.submission_id, why: r.unposted });
      summary(`held (${r.unposted})  ${r.kind}  sha256:${hash}`);
      continue;
    }
    const answer = await client.call("result", r.body);
    if (answer.ok && !answer.unreadable && ["accepted", "duplicate"].includes(answer.body?.outcome)) {
      posted.push({ submission_id: r.submission_id, outcome: answer.body.outcome });
      summary(`posted  ${r.kind}  ${answer.body.outcome}  sha256:${hash}`);
      continue;
    }
    failed.push({ submission_id: r.submission_id, why: answer.refused ?? answer.wait ?? "unreadable" });
    summary(`FAILED  ${r.kind}  ${answer.refused ?? answer.wait ?? "unreadable"}  sha256:${hash}`);
  }
  return { posted, held, failed, alerts: client.alerts };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function output(name, value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (/\n/.test(text)) throw new Error(`output ${name} would span lines`);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${text}\n`);
  else console.log(`${name}=${text}`);
}

function summaryLine(line) {
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`);
  console.log(line);
}

const parseJson = (text, fallback) => {
  if (text === undefined || text === null || String(text).trim() === "") return fallback;
  return JSON.parse(String(text));
};

/** Held reasons of the `held` record on the checked-out tree, by fingerprint, for the notice kind. */
function heldReasonsOnTree(root) {
  const byFp = new Map();
  const walk = (d) => {
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name.endsWith(".json")) {
        try {
          const r = JSON.parse(fs.readFileSync(full, "utf8"));
          if (r?.state === "held" && typeof r.fingerprint === "string") byFp.set(r.fingerprint, r.reasons ?? []);
        } catch {
          /* not evidence */
        }
      }
    }
  };
  walk(path.join(root, "log", "decisions"));
  return (fp) => byFp.get(fp) ?? [];
}

async function main(argv) {
  const args = { job: null, results: null, root: process.cwd() };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--job") args.job = argv[++i];
    else if (argv[i] === "--results") args.results = argv[++i];
    else if (argv[i] === "--registry-dir") args.root = path.resolve(argv[++i]);
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  const client = createClient({ workflow: "ingest" });

  if (args.job === "claim") {
    const polled = parseJson(process.env.ASTRA_POLLED_TAGS, []);
    const out = await claimJob({ client, polled: Array.isArray(polled) ? polled : [] });
    output("submissions", out.submissions);
    output("count", String(out.submissions.length));
    output("registered", out.registered);
    output("leases", out.leases);
    output("shadow", String(out.shadow));
    summaryLine(`claim: ${out.submissions.length} lease(s)${out.shadow ? ", every one shadow (BOT-92)" : ""}; ${out.refused.length} refused`);
    return out.refused.length || out.alerts.length ? 1 : 0;
  }

  if (args.job === "ask") {
    const out = await askJob({
      client,
      submissions: parseJson(process.env.ASTRA_SUBMISSIONS, []),
      leases: parseJson(process.env.ASTRA_LEASES, {}),
      verified: parseJson(process.env.ASTRA_VERIFIED, {}),
      heldReasons: heldReasonsOnTree(args.root),
    });
    output("outcome", out.outcome);
    // Counts, never values (BOT-89).
    const words = Object.values(out.outcome).map((o) => o.verdict ?? (o.wait ? "wait" : "not asked"));
    summaryLine(`ask: ${words.length} submission(s): ${[...new Set(words)].map((w) => `${words.filter((x) => x === w).length} ${w}`).join(", ") || "none"}`);
    return 0;
  }

  if (args.job === "report") {
    if (!args.results) throw new Error("--job report needs --results");
    const doc = parseJson(fs.readFileSync(args.results, "utf8"), { results: [] });
    const out = await reportJob({ client, results: doc.results ?? [], summary: summaryLine });
    return out.failed.length ? 1 : 0;
  }

  throw new Error("--job claim, ask or report");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`::error::${String(e.message ?? e)}`);
      process.exit(e instanceof ServiceRunFailure ? 1 : 2);
    });
}
