#!/usr/bin/env node
// B-T5.0's poll and sweep, one subcommand per job of
// `.github/workflows/plugins-ingest.yml`:
//
//     node bot/lib/poll-run.mjs load       # `load`:     BOT_STATE_HMAC_KEY and the tree
//     node bot/lib/poll-run.mjs poll       # `poll`:     releases.atom, and no key
//     node bot/lib/poll-run.mjs sweep      # `sweep`:    git ls-remote, and no key
//     node bot/lib/poll-run.mjs remember   # `remember`: BOT_STATE_HMAC_KEY and the answers
//
// The RULES are `bot/lib/poll.mjs`'s (B-T2.6): which listings, which tags, the
// signed memory, the sweep, BOT-87's verdict. What is here is what that module
// deliberately is not — the plumbing between jobs — and the one rule that is
// about the plumbing: **each job reaches only what the workflow's job table says
// it holds.** `poll` and `sweep` never read `BOT_STATE_HMAC_KEY`; `load` and
// `remember` never read a feed or run `git ls-remote`. A subcommand is a job,
// and `bot/tests/poll.test.mjs` holds each one to the job it runs in.
//
// ── what crosses a job boundary, and how ───────────────────────────────────
//
// Job outputs only, never an artifact or a cache (BOT-55, BOT-56): an output
// can be written only by the job that declares it, and every job in a run can
// upload an artifact. So:
//
//   load     → listings, rows (each polled repository's ETag and registered
//              tags), poll_due, sweep_due, discarded
//   poll     → polled (per repository: ok, candidates, etag), tags
//   claim    → registered (`<owner>/<repo>@<tag>` the service answered for; [] in
//              shadow) — bot/lib/service-jobs.mjs's claim job, not this file
//   sweep    → remote (per repository: its tags and SHAs, or an error)
//   remember → verdict (BOT-87's), changed
//
// **The memory itself does not travel.** `remember` restores the SAME cache
// entry `load` verified — by the exact key `load` matched, not by prefix — and
// verifies it again with its own copy of the key. So the signed memory is read
// only by the two jobs that hold the key, and a sweep memory an exploited
// `poll` or `sweep` would like to see signed is never handed to the signer:
// what those jobs hand on is their raw answer, and `remember` re-derives the
// memory from it with `bot/lib/poll.mjs`'s functions.
//
// Every value that crosses is re-read on the receiving side against the
// grammar it must have, and a value that fails is a failed job rather than a
// quietly smaller one: `remember` that refused its inputs saves nothing and
// relays no verdict, and `poll-alert` turns that into a red alarm
// (`BOT_87_DID_NOT_REPORT`).
//
// ── shadow, and what B-T5.1 turns on ───────────────────────────────────────
//
// `POLL_MODE` is set once, at the top of the workflow, and B-T5.1's commit — the
// cutover commit B — is the edit from `shadow` to `live`. In shadow:
//
//   * `claim`'s register half (bot/lib/service-jobs.mjs `claimJob`, which reads
//     the same `POLL_MODE`) prints one `would register <owner>/<repo>@<tag>`
//     line per tag the poll found and registers nothing: no register call is
//     made, and `registered` is `[]`. The claim half beside it is B-T3.x's;
//   * so the memory's registered tags never grow, which is the honest state —
//     the shadow poll offers the same new tag every run until it is live;
//   * BOT-87's unregistered-tag code is printed as `would alarm` and kept out of
//     the verdict. Its premise is "the poll should have registered this", and in
//     shadow the poll registers nothing by construction; the legacy path is the
//     live one until cutover, and a release waiting out its publication delay
//     there would otherwise page the owner about the shadow. The other three
//     codes — a stale feed, a discarded memory, a failed sweep — are about the
//     machinery and not about registration, and they are live in shadow.
//
// ── seeding (MIG-23) ───────────────────────────────────────────────────────
//
// Every run seeds the poll's tag memory from `state/releases-seen.json` while
// that file exists (`seedFromReleasesSeen`, a union): the legacy backstop is
// the live path until cutover, and a tag it has seen is not the poll's to
// register. The first sweep seeds the sweep memory with every tag
// `git ls-remote` shows (`runSweep`), so that nothing that existed before it
// ever alarms.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { loadRecords, loadSources, REPO_ROOT } from "../../tools/lib/sources.mjs";
import { TIME_RE } from "../../tools/lib/time.mjs";
import { runUrl } from "./alert-verdict.mjs";
import { listingStateAt, readMarkers } from "./listing-state.mjs";
import { SEEN_FILE } from "./notify.mjs";
import {
  BOT_87_CODES,
  MEMORY_FILE,
  POLL_INTERVAL_SECONDS,
  STATE_KEY_ENV,
  bot87Verdict,
  isUsableTag,
  loadMemory,
  lsRemoteTags,
  pollableListings,
  rememberMemory,
  rememberPoll,
  runPoll,
  runSweep,
  seedFromReleasesSeen,
  staleListings,
} from "./poll.mjs";
import { jcs } from "../../tools/lib/canonical.mjs";

/**
 * What each subcommand reads from its environment and writes to
 * `$GITHUB_OUTPUT`, and the job and step it runs as.
 *
 * Declared rather than discovered, and ENFORCED in both directions: a
 * subcommand reads its environment only through `input()`, which refuses a
 * name not listed here, and `bot/tests/poll.test.mjs` holds each workflow step
 * to its row — the step maps every name the row reads that the workflow does
 * not set for it already, maps no other `ASTRA_` or `BOT_STATE_` name, and the
 * job hands on only outputs the row writes. A misspelt output is an empty
 * string two jobs away, which reads exactly like "nothing to report"; this
 * table is where that becomes a red test instead.
 *
 * `BOT_STATE_HMAC_KEY` appears in two rows, `load` and `remember`, and in no
 * other — which is the job table's rule about the key, as data.
 */
export const JOB_IO = Object.freeze({
  load: Object.freeze({
    job: "load", step: "load",
    reads: ["BOT_STATE_HMAC_KEY", "GITHUB_EVENT_NAME"],
    writes: ["listings", "rows", "poll_due", "sweep_due", "discarded"],
  }),
  poll: Object.freeze({
    job: "poll", step: "poll",
    reads: ["ASTRA_POLL_LISTINGS", "ASTRA_POLL_ROWS"],
    writes: ["polled", "tags"],
  }),
  sweep: Object.freeze({
    job: "sweep", step: "sweep",
    reads: ["ASTRA_POLL_LISTINGS"],
    writes: ["remote"],
  }),
  remember: Object.freeze({
    job: "remember", step: "remember",
    reads: [
      "POLL_MODE", "BOT_STATE_HMAC_KEY", "ASTRA_POLL_LISTINGS", "ASTRA_POLLED", "ASTRA_REGISTERED",
      "ASTRA_SWEPT", "ASTRA_SWEEP_DUE", "ASTRA_SWEEP_RESULT",
    ],
    writes: ["verdict", "changed"],
  }),
});

/** The two modes `POLL_MODE` may name, declared once beside the claim job that also reads it. */
export { POLL_MODES as MODES } from "./service-jobs.mjs";
import { POLL_MODES as MODES } from "./service-jobs.mjs";

/** BOT-87: the sweep is daily. */
export const SWEEP_INTERVAL_SECONDS = 86400;

/**
 * How early a run may be and still count as due: half of BOT-51's 600 s.
 *
 * The poll rides the ingest workflow's one schedule — BOT-51 is ONE cron, and
 * `bot/tests/workflows.test.mjs` refuses a second — so "every 30 minutes"
 * (BOT-41) is every third run. The time remembered is when the previous poll
 * started, and the next start is 1800 s later only to within the scheduler's
 * jitter: "at least 1800 s" would skip the :33 run over a few seconds and poll
 * every 40 minutes. 300 s is less than one run's interval, so it can never make
 * two consecutive runs both due.
 */
export const DUE_SLACK_SECONDS = 300;

/**
 * The largest job output this file writes. A job output reaches the next job
 * as an environment variable, and Linux refuses to start a process with a
 * single one over 128 KiB (MAX_ARG_STRLEN) — `E2BIG` from a step that never
 * ran a line of this file. So a value near that refuses here, by name, with
 * the measurement, rather than there.
 */
export const MAX_OUTPUT_BYTES = 100_000;

const REPO_RE = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const KEY_RE = /^[a-z0-9_.-]{1,100}\/[a-z0-9_.-]{1,100}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
// An HTTP entity tag as GitHub sends it: strong or weak, quoted, printable.
const ETAG_RE = /^(W\/)?"[\x21\x23-\x7e]{0,256}"$/;
/** A feed shows ten entries; anything past this many candidates is not a feed's answer. */
const MAX_CANDIDATES = 50;

const iso = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;
const repoKey = (repo) => String(repo).toLowerCase();

// ── the mode ────────────────────────────────────────────────────────────────

/** `POLL_MODE`, or a refusal. There is no default: a job that guessed would guess `live` one day. */
export function pollMode(env = process.env) {
  const mode = env.POLL_MODE;
  if (!MODES.includes(mode)) {
    throw new Error(`POLL_MODE is ${JSON.stringify(mode)}; plugins-ingest.yml sets it to one of ${MODES.join(", ")}`);
  }
  return mode;
}

// ── which of the two are due ────────────────────────────────────────────────

/**
 * Is the poll due? A dispatch means "pull now" (BOT-4) and always is.
 * Otherwise when the newest successful poll of any repository is at least one
 * interval, less the slack, ago.
 */
export function pollDue(memory, now, { dispatched = false } = {}) {
  if (dispatched) return { due: true, why: "a dispatch means pull now (BOT-4)" };
  const times = Object.values(memory?.repos ?? {})
    .map((r) => (r?.last_success_at ? Date.parse(r.last_success_at) : NaN))
    .filter(Number.isFinite);
  if (!times.length) return { due: true, why: "no repository has a successful poll remembered" };
  const elapsed = Math.round((new Date(now).getTime() - Math.max(...times)) / 1000);
  const due = elapsed >= POLL_INTERVAL_SECONDS - DUE_SLACK_SECONDS;
  return { due, why: `the last successful poll was ${elapsed} s ago and BOT-41's interval is ${POLL_INTERVAL_SECONDS} s` };
}

/**
 * Is the sweep due? **A dispatch does not make it due.** The sweep counts a
 * tag's age in sweeps, so two sweeps an hour apart would make a tag the poll
 * has had one hour to register look a sweep old, and alarm.
 */
export function sweepDue(memory, now) {
  const last = memory?.sweep?.last_at ? Date.parse(memory.sweep.last_at) : NaN;
  if (!Number.isFinite(last)) return { due: true, why: "no sweep is remembered, so this one seeds" };
  const elapsed = Math.round((new Date(now).getTime() - last) / 1000);
  return {
    due: elapsed >= SWEEP_INTERVAL_SECONDS - DUE_SLACK_SECONDS,
    why: `the last sweep was ${elapsed} s ago and BOT-87's sweep is daily`,
  };
}

// ── the tree ────────────────────────────────────────────────────────────────

/**
 * `state/releases-seen.json`, or null when it has been retired.
 *
 * Absent is a state (BOT-42 retires it after cutover). Present and unreadable
 * is a refusal, not an empty seed: an empty seed offers every tag the legacy
 * backstop has already handled, which live is a registration for each.
 */
export function readReleasesSeen(root = REPO_ROOT) {
  const file = path.join(root, SEEN_FILE);
  if (!fs.existsSync(file)) return null;
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    throw new Error(`${SEEN_FILE} is on the tree and is not JSON (${e.message}); the poll will not seed from half a file`);
  }
  if (!doc || typeof doc !== "object" || !doc.repos || typeof doc.repos !== "object" || Array.isArray(doc.repos)) {
    throw new Error(`${SEEN_FILE} is on the tree and has no \`repos\` object; the poll will not seed from it`);
  }
  return doc;
}

/** The listings the poll and the sweep read, by MIG-1's state (BOT-41, MIG-30). */
export function listingsFor(root = REPO_ROOT, now = new Date()) {
  const sources = loadSources(root);
  const records = loadRecords(root, sources);
  const markers = readMarkers(root);
  const at = iso(now);
  const stateOf = (id) => listingStateAt(root, id, { now: at, markers });
  return { ...pollableListings({ sources, records, stateOf }), errors: [...sources.errors, ...(records.errors ?? [])] };
}

/** The memory `load` and `remember` both start from: what the cache held, seeded. */
export function seededMemory(memory, seen) {
  return seen ? seedFromReleasesSeen(memory, seen) : memory;
}

/**
 * `load`, pure: from what the cache held, `state/releases-seen.json` and the
 * pollable listings, what the rest of the run is handed.
 */
export function loadOutputs({ opened, seen, listings, now, dispatched = false }) {
  const memory = seededMemory(opened, seen);
  const poll = pollDue(memory, now, { dispatched });
  const sweep = sweepDue(memory, now);
  return { memory, rows: pollRows(memory, listings), poll, sweep };
}

/** What `poll` needs of the memory: each polled repository's ETag and registered tags. */
export function pollRows(memory, listings) {
  const rows = {};
  for (const l of listings) {
    const key = repoKey(l.repo);
    const row = memory.repos[key];
    if (row) rows[key] = { etag: row.etag ?? null, registered: row.registered ?? [] };
  }
  return rows;
}

// ── reading what another job handed on ─────────────────────────────────────

const parse = (text, what) => {
  if (typeof text !== "string" || text.trim() === "") return undefined;
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${what} is not JSON: ${e.message}`);
  }
};

/** `load`'s listings, which every other job reads. A malformed one is a defect upstream, not an empty catalogue. */
export function readListings(text) {
  const listings = parse(text, "the listings `load` handed on");
  if (!Array.isArray(listings)) throw new Error("the listings `load` handed on are not a list; did `load` run?");
  for (const l of listings) {
    const ok = l && typeof l.id === "string" && typeof l.repo === "string" && REPO_RE.test(l.repo) &&
      (l.prefix === null || typeof l.prefix === "string") &&
      ["recorded_tags", "terminal_tags", "named_tags"].every((k) => Array.isArray(l[k]) && l[k].every((t) => typeof t === "string"));
    if (!ok) throw new Error(`a listing \`load\` handed on is not one pollableListings returns: ${JSON.stringify(l).slice(0, 200)}`);
  }
  return listings;
}

/** `load`'s per-repository rows, for `poll`. */
export function readRows(text) {
  const rows = parse(text, "the rows `load` handed on") ?? {};
  if (typeof rows !== "object" || Array.isArray(rows)) throw new Error("the rows `load` handed on are not an object");
  for (const [key, row] of Object.entries(rows)) {
    const ok = KEY_RE.test(key) && row && (row.etag === null || typeof row.etag === "string") &&
      Array.isArray(row.registered) && row.registered.every(isUsableTag);
    if (!ok) throw new Error(`the row for ${JSON.stringify(key)} is not {etag, registered}`);
  }
  return rows;
}

/**
 * `poll`'s answer, as `remember` will apply it — or a refusal.
 *
 * It came from the job that parsed a stranger's feed, so every member is held to
 * its grammar: a repository `load` did not list, a candidate that is not a
 * usable tag, an ETag that is not an entity tag, a time that is not §0.7 — each
 * is a refusal of the whole answer, never a filtered one. A poll answer that is
 * only mostly well-formed came from a job that is only mostly this code.
 */
export function readPolled(text, listings) {
  const polled = parse(text, "the poll's answer");
  if (polled === undefined) return null;
  const known = new Set(listings.map((l) => repoKey(l.repo)));
  if (!polled || typeof polled !== "object" || !TIME_RE.test(String(polled.at)) ||
    !polled.repos || typeof polled.repos !== "object" || Array.isArray(polled.repos)) {
    throw new Error("the poll's answer is not {at, repos}");
  }
  for (const [key, res] of Object.entries(polled.repos)) {
    if (!known.has(key)) throw new Error(`the poll answered for ${JSON.stringify(key)}, which load did not list`);
    const ok = res && typeof res.ok === "boolean" && Array.isArray(res.candidates) &&
      res.candidates.length <= MAX_CANDIDATES && res.candidates.every(isUsableTag) &&
      (res.etag === null || (typeof res.etag === "string" && ETAG_RE.test(res.etag)));
    if (!ok) throw new Error(`the poll's answer for ${key} is not {ok, candidates, etag} of the grammar each must have`);
  }
  return polled;
}

/**
 * `claim`'s answer: the tags the service registered, as bot/lib/service-jobs.mjs
 * writes them — `<owner>/<repo>@<tag>` — read back into `{repo, tag}`. A repo
 * slug carries no `@`, so the first one splits. Absent is none.
 */
export function readRegistered(text) {
  const reg = parse(text, "claim's registered tags");
  if (reg === undefined) return [];
  const pairs = Array.isArray(reg) ? reg.map((r) => {
    const s = String(r);
    const at = s.indexOf("@");
    return typeof r === "string" && at > 0 ? { repo: s.slice(0, at), tag: s.slice(at + 1) } : null;
  }) : null;
  if (!pairs || !pairs.every((r) => r && REPO_RE.test(r.repo) && isUsableTag(r.tag))) {
    throw new Error("claim's registered tags are not a list of `<owner>/<repo>@<tag>`");
  }
  return pairs;
}

/** `sweep`'s answer: per repository `{tags: [[tag, sha]…]}` or `{error}`. Absent is null. */
export function readSwept(text, listings) {
  const swept = parse(text, "the sweep's answer");
  if (swept === undefined) return null;
  const known = new Set(listings.map((l) => repoKey(l.repo)));
  if (!swept || typeof swept !== "object" || Array.isArray(swept)) throw new Error("the sweep's answer is not an object");
  for (const [key, res] of Object.entries(swept)) {
    if (!known.has(key)) throw new Error(`the sweep answered for ${JSON.stringify(key)}, which load did not list`);
    if (res && typeof res.error === "string") continue;
    const ok = res && Array.isArray(res.tags) &&
      res.tags.every((t) => Array.isArray(t) && t.length === 2 && isUsableTag(String(t[0])) && SHA_RE.test(String(t[1])));
    if (!ok) throw new Error(`the sweep's answer for ${key} is not {tags: [[tag, sha]…]} or {error}`);
  }
  return swept;
}

// ── what each job computes ─────────────────────────────────────────────────

/** `poll`'s two outputs, from `runPoll`'s answer. */
export function pollOutputs(out, listings) {
  const repoOf = new Map(listings.map((l) => [repoKey(l.repo), l.repo]));
  const polled = { at: out.at, repos: {} };
  const tags = [];
  for (const [key, res] of Object.entries(out.repos)) {
    polled.repos[key] = { ok: res.ok, candidates: res.candidates, etag: res.etag ?? null };
    for (const tag of res.candidates) tags.push({ repo: repoOf.get(key), tag });
  }
  return { polled, tags };
}

/**
 * `sweep`'s answer for every polled repository, one `git ls-remote` each —
 * however many listings a monorepo hosts.
 */
export function sweepRemote(listings, lsRemote = lsRemoteTags) {
  const out = {};
  for (const l of listings) {
    const key = repoKey(l.repo);
    if (out[key]) continue;
    try {
      out[key] = { tags: lsRemote(l.repo).map(({ tag, sha }) => [tag, sha]) };
    } catch (e) {
      out[key] = { error: String(e.message).slice(0, 200) };
    }
  }
  return out;
}

/**
 * `remember`, pure: the memory after this run, and BOT-87's verdict.
 *
 * In order: the poll's answer with claim's registered tags (`rememberPoll`),
 * then the sweep over the result (`runSweep`, fed the sweep job's lists rather
 * than running `git ls-remote` here), then the staleness read over what is left.
 * The sweep reads the memory AFTER the poll, so a tag registered in this run is
 * not alarmed on in this run.
 *
 * @param {{memory: object, discarded: string|null, listings: object[], polled: object|null,
 *   registered: {repo: string, tag: string}[], swept: object|null, sweepDue: boolean,
 *   sweepFailed: boolean, now: Date, mode: string, run?: string|null}} o
 */
export function composeRemember({ memory, discarded, listings, polled, registered, swept, sweepDue: due, sweepFailed, now, mode, run = null }) {
  let next = memory;
  if (polled) next = rememberPoll(next, polled, registered);
  let alerts = [];
  let failed = [];
  if (swept) {
    const lsRemote = (repo) => {
      const res = swept[repoKey(repo)];
      if (!res) throw new Error("the sweep job did not list this repository");
      if (res.error) throw new Error(res.error);
      return res.tags.map(([tag, sha]) => ({ tag, sha }));
    };
    const s = runSweep({ memory: next, listings, lsRemote, now });
    next = s.memory;
    alerts = s.alerts;
    failed = s.failed;
  } else if (due && sweepFailed) {
    // Due, and the job that should have answered did not: every listing went
    // unswept, and saying so is the only way a crashed sweep is not a quiet one.
    failed = listings.map((l) => ({ id: l.id, repo: l.repo, error: "the sweep job did not answer" }));
  }
  const stale = staleListings(next, listings, now);
  const unregistered = mode === "live" ? alerts : [];
  const verdict = bot87Verdict({ unregistered, stale, discarded, failed, run });
  return {
    memory: next,
    verdict,
    changed: jcs(next) !== jcs(memory),
    wouldAlarm: mode === "live" ? [] : alerts,
    alerts,
    stale,
    failed,
  };
}

// ── the job side ────────────────────────────────────────────────────────────

/** One name of a subcommand's environment, refused unless `JOB_IO` lists it for that subcommand. */
export function input(cmd, env, name) {
  if (!JOB_IO[cmd].reads.includes(name)) {
    throw new Error(`${cmd} read ${name}, which JOB_IO does not list for it; the workflow is held to that table`);
  }
  return env[name];
}

/** One job output, or a refusal before it becomes an E2BIG two jobs away. */
export function outputLine(name, value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (text.includes("\n")) throw new Error(`output ${name} holds a newline, which $GITHUB_OUTPUT's name=value form cannot carry`);
  const bytes = Buffer.byteLength(text);
  if (bytes > MAX_OUTPUT_BYTES) {
    throw new Error(
      `output ${name} is ${bytes} bytes and the ceiling is ${MAX_OUTPUT_BYTES}: the next job reads it as one ` +
      "environment variable, and Linux refuses to start a process with one over 128 KiB",
    );
  }
  return `${name}=${text}\n`;
}

function setOutputs(cmd, outputs, env = process.env) {
  const names = Object.keys(outputs);
  if (names.join(",") !== JOB_IO[cmd].writes.join(",")) {
    throw new Error(`${cmd} writes ${names.join(", ")} and JOB_IO says ${JOB_IO[cmd].writes.join(", ")}`);
  }
  const text = Object.entries(outputs).map(([k, v]) => outputLine(k, v)).join("");
  if (env.GITHUB_OUTPUT) fs.appendFileSync(env.GITHUB_OUTPUT, text);
}

function summary(lines, env = process.env) {
  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}\n`);
}

function cmdLoad(env) {
  const now = new Date();
  const key = { [STATE_KEY_ENV]: input("load", env, STATE_KEY_ENV) };
  const { memory: opened, discarded, fresh } = loadMemory({ file: MEMORY_FILE, env: key, now });
  const { listings, skipped, errors } = listingsFor(REPO_ROOT, now);
  for (const e of errors) console.log(`note  ${e.file}: ${e.message}`);
  for (const s of skipped) console.log(`skip  ${s.id}: ${s.why}`);
  console.log(`ok    ${listings.length} listing(s) in ${new Set(listings.map((l) => repoKey(l.repo))).size} repositories are polled`);
  if (discarded) console.log(`::warning::the poll memory in the cache was discarded: ${discarded}`);
  else console.log(fresh ? "note  no poll memory was cached; this run starts one" : "ok    the cached poll memory verified");
  const dispatched = input("load", env, "GITHUB_EVENT_NAME") === "workflow_dispatch";
  const { rows, poll: p, sweep: s } = loadOutputs({ opened, seen: readReleasesSeen(), listings, now, dispatched });
  console.log(`${p.due ? "due " : "skip"}  poll: ${p.why}`);
  console.log(`${s.due ? "due " : "skip"}  sweep: ${s.why}`);
  setOutputs("load", {
    listings,
    rows,
    poll_due: String(p.due),
    sweep_due: String(s.due),
    discarded: discarded ?? "",
  }, env);
  return 0;
}

async function cmdPoll(env) {
  const listings = readListings(input("poll", env, "ASTRA_POLL_LISTINGS"));
  const rows = readRows(input("poll", env, "ASTRA_POLL_ROWS"));
  const out = await runPoll({ listings, memory: { repos: rows }, now: new Date() });
  const lines = [];
  for (const [key, res] of Object.entries(out.repos)) {
    const state = !res.ok ? `ERR ${res.error}` : res.changed ? `200, ${res.candidates.length} candidate(s)` : "304";
    lines.push(`${key} (${res.ids.join(", ")}): ${state}`);
    for (const s of res.skipped ?? []) console.log(`  skip ${key} ${s.why}`);
  }
  for (const l of lines) console.log(l);
  summary(["### the poll", "", ...lines.map((l) => `- ${l}`)], env);
  setOutputs("poll", pollOutputs(out, listings), env);
  return 0;
}

function cmdSweep(env) {
  const listings = readListings(input("sweep", env, "ASTRA_POLL_LISTINGS"));
  const remote = sweepRemote(listings);
  const lines = Object.entries(remote).map(([k, r]) => (r.error ? `${k}: ERR ${r.error}` : `${k}: ${r.tags.length} tag(s)`));
  for (const l of lines) console.log(l);
  summary(["### the sweep (git ls-remote)", "", ...lines.map((l) => `- ${l}`)], env);
  setOutputs("sweep", { remote }, env);
  return 0;
}

function cmdRemember(env) {
  const now = new Date();
  const read = (name) => input("remember", env, name);
  const mode = pollMode({ POLL_MODE: read("POLL_MODE") });
  const listings = readListings(read("ASTRA_POLL_LISTINGS"));
  const key = { [STATE_KEY_ENV]: read(STATE_KEY_ENV) };
  const { memory: opened, discarded } = loadMemory({ file: MEMORY_FILE, env: key, now });
  const memory = seededMemory(opened, readReleasesSeen());
  const r = composeRemember({
    memory,
    discarded,
    listings,
    polled: readPolled(read("ASTRA_POLLED"), listings),
    registered: readRegistered(read("ASTRA_REGISTERED")),
    swept: readSwept(read("ASTRA_SWEPT"), listings),
    sweepDue: read("ASTRA_SWEEP_DUE") === "true",
    sweepFailed: read("ASTRA_SWEEP_RESULT") !== "success",
    now,
    mode,
    run: runUrl(env),
  });
  const lines = [`BOT-87 (${mode}): ${r.verdict.status}${r.verdict.codes ? ` — ${r.verdict.codes.join(", ")}` : ""}`];
  for (const a of r.wouldAlarm) lines.push(`would alarm ${BOT_87_CODES.unregistered}: ${a.repo}@${a.tag} (${a.id}, ${a.sha})`);
  if (mode === "live") for (const a of r.alerts) lines.push(`alarm ${BOT_87_CODES.unregistered}: ${a.id} ${a.sha}`);
  for (const s of r.stale) lines.push(`stale: ${s.id} (${s.repo}), last successful poll ${s.last_success_at ?? "never"}`);
  for (const f of r.failed) lines.push(`sweep failed: ${f.id} (${f.repo}): ${f.error}`);
  if (discarded) lines.push(`the cached memory was discarded: ${discarded}`);
  for (const l of lines) console.log(l);
  summary(["### remember", "", ...lines.map((l) => `- ${l}`)], env);
  // Against what the cache held, not against the seeded copy: a seed that
  // added a tag is a change the cache has not seen yet.
  const changed = jcs(r.memory) !== jcs(opened);
  if (changed) {
    const { hmac } = rememberMemory({ memory: r.memory, file: MEMORY_FILE, env: key });
    console.log(`ok    sealed the memory for the cache (${hmac.slice(0, 16)}…)`);
  } else {
    console.log("ok    nothing changed; the cached entry stands");
  }
  setOutputs("remember", { verdict: r.verdict, changed: String(changed) }, env);
  return 0;
}

/** Exported so that a test can read which job reaches what, by function. */
export const COMMANDS = Object.freeze({ load: cmdLoad, poll: cmdPoll, sweep: cmdSweep, remember: cmdRemember });

export async function main(argv, env = process.env) {
  const [cmd, ...rest] = argv;
  if (!COMMANDS[cmd] || rest.length) {
    console.error(`usage: node bot/lib/poll-run.mjs ${Object.keys(COMMANDS).join("|")}`);
    return 2;
  }
  try {
    return await COMMANDS[cmd](env);
  } catch (e) {
    console.error(`::error::${cmd}: ${e.message}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
