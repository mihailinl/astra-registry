// tools/run-watchdog.mjs: does a run in this repository hang, or has a workflow
// gone quiet?
//
// Why it exists. A run whose job never gets a runner holds its workflow's
// concurrency group for ever: `timeout-minutes` counts only once a job is on a
// runner, and the group has one running and one pending slot, so every newer
// run becomes the pending one and is cancelled by the next. `Moderation
// coverage` did not run from 2026-11-05 16:37 to 2026-11-10 11:00 UTC (run
// 42066476764: `check` succeeded, its `alert` job never got a runner; 69 newer
// runs cancelled, none succeeded). `Plugins ingest` lost 13 hours on 10-30 and
// `Signer` 67 runs on 10-22. Nothing watched run AGE, and the heartbeats have
// a 24-hour bound.
//
// Two verdicts, both red:
//   * STALE: a run in status queued / in_progress / pending / waiting /
//     requested that is older than `stale_minutes` (30). AGE decides, never
//     status: a healthy running run can report `queued`, and a young queued run
//     is not a problem.
//   * SILENT: a scheduled or waker-driven workflow with no successful run for
//     its bound in tools/run-watchdog.json.
// The known ghosts in the data file are runs GitHub will neither cancel nor
// delete; they are said once and are never stale.
//
// Pure functions first, then a thin `gh api` layer. Outside TRUST-31's set.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const UNFINISHED = ["queued", "in_progress", "pending", "waiting", "requested"];
const MS_MINUTE = 60_000;

const here = import.meta.dirname;
export const DATA_FILE = path.join(here, "run-watchdog.json");
export const loadData = (file = DATA_FILE) => JSON.parse(fs.readFileSync(file, "utf8"));

/** Minutes since this run (its latest attempt, once started) began waiting or working. */
export function runAgeMinutes(run, now) {
  const started = run.status === "in_progress" || (run.run_attempt ?? 1) > 1;
  const from = (started && run.run_started_at) || run.created_at;
  return (now.getTime() - Date.parse(from)) / MS_MINUTE;
}

/**
 * Sort the unfinished runs into stale, known ghosts and young ones.
 * Age decides; status only says whether a run is unfinished at all.
 * @param {object[]} runs workflow-run objects as the API returns them
 * @param {{ghostIds: Set<number>, staleMinutes: number, now: Date, selfRunId?: number}} o
 */
export function classify(runs, { ghostIds, staleMinutes, now, selfRunId }) {
  const out = { stale: [], ghosts: [], young: [] };
  for (const run of runs) {
    if (!UNFINISHED.includes(run.status)) continue;
    if (selfRunId !== undefined && run.id === selfRunId) continue;
    const entry = { id: run.id, name: run.name, status: run.status, event: run.event, minutes: Math.round(runAgeMinutes(run, now)), url: run.html_url };
    if (ghostIds.has(run.id)) out.ghosts.push(entry);
    else if (runAgeMinutes(run, now) > staleMinutes) out.stale.push(entry);
    else out.young.push(entry);
  }
  return out;
}

/**
 * Which watched workflows have no successful run inside their bound?
 * @param {{workflow: string, max_minutes: number}[]} silence
 * @param {Map<string, string|null>} lastSuccess workflow name -> ISO time of its newest success, or null
 */
export function silent(silence, lastSuccess, now) {
  const out = [];
  for (const w of silence) {
    const at = lastSuccess.get(w.workflow) ?? null;
    const minutes = at === null ? null : Math.round((now.getTime() - Date.parse(at)) / MS_MINUTE);
    if (minutes === null || minutes > w.max_minutes) out.push({ workflow: w.workflow, max_minutes: w.max_minutes, minutes, last_success: at });
  }
  return out;
}

export const hours = (m) => (m >= 120 ? `${Math.round(m / 6) / 10} h` : `${m} min`);

/** The verdict as the text of $GITHUB_STEP_SUMMARY. */
export function render({ stale, ghosts, silentWorkflows, young, staleMinutes, now }) {
  const red = stale.length > 0 || silentWorkflows.length > 0;
  const lines = [`## Run watchdog: ${red ? "RED" : "green"}`, `${now.toISOString()}`, ""];
  if (stale.length === 0) lines.push(`No unfinished run is older than ${staleMinutes} min.`);
  else {
    lines.push(`**${stale.length} STALE run(s)**, unfinished for more than ${staleMinutes} min (age decides, not status):`, "");
    for (const r of stale) lines.push(`- ${r.name} #${r.id} (${r.event}): ${r.status} for ${hours(r.minutes)} ${r.url ?? ""}`.trimEnd());
    lines.push("", "Re-run it, or cancel it, then see docs/RUNBOOK.md, \"A run that hangs\".");
  }
  lines.push("");
  if (silentWorkflows.length === 0) lines.push("Every watched workflow has a successful run inside its bound.");
  else {
    lines.push(`**${silentWorkflows.length} SILENT workflow(s)**, no successful run inside the bound:`, "");
    for (const s of silentWorkflows) {
      lines.push(`- ${s.workflow}: ${s.minutes === null ? "no successful run found" : `last success ${hours(s.minutes)} ago`}, bound ${hours(s.max_minutes)}`);
    }
  }
  lines.push("");
  if (ghosts.length > 0) lines.push(`Known ghosts (GitHub will neither cancel nor delete them, nothing to do): ${ghosts.map((g) => `${g.name} #${g.id}`).join(", ")}.`);
  if (young.length > 0) lines.push(`${young.length} run(s) in progress or queued and younger than ${staleMinutes} min: fine.`);
  return lines.join("\n") + "\n";
}

/** Red means a person looks: anything stale or silent. */
export const exitCode = ({ stale, silentWorkflows }) => (stale.length > 0 || silentWorkflows.length > 0 ? 1 : 0);

/** The codes a verdict for the alarm channel carries. */
export function alarmCodes({ stale, silentWorkflows }) {
  return [...(stale.length > 0 ? ["A_RUN_STALE"] : []), ...(silentWorkflows.length > 0 ? ["A_WORKFLOW_SILENT"] : [])];
}

// ── cron: the longest gap a schedule leaves, for the canary ─────────────────

function field(spec, lo, hi) {
  const set = new Set();
  for (const part of spec.split(",")) {
    const [range, stepText] = part.split("/");
    const step = stepText === undefined ? 1 : Number(stepText);
    let [a, b] = range === "*" ? [lo, hi] : range.includes("-") ? range.split("-").map(Number) : [Number(range), stepText === undefined ? Number(range) : hi];
    if (![a, b, step].every(Number.isInteger) || step < 1) throw new Error(`cannot read cron field ${JSON.stringify(spec)}`);
    for (let v = a; v <= b; v += step) set.add(v);
  }
  return [...set].sort((x, y) => x - y);
}

/** Longest gap, in minutes, between two firings of a 5-field cron. Day-of-month, month and weekday: `*`, or a day list/range (monthly) / weekday (weekly). */
export function cronMaxGapMinutes(cron) {
  const [min, hour, dom, mon, dow] = cron.trim().split(/\s+/);
  if (mon !== "*") throw new Error(`month field in ${JSON.stringify(cron)} is not read`);
  const minutes = field(min, 0, 59), hrs = field(hour, 0, 23);
  const fires = hrs.flatMap((h) => minutes.map((m) => h * 60 + m));
  let gap = fires[0] + 1440 - fires[fires.length - 1];
  for (let i = 1; i < fires.length; i++) gap = Math.max(gap, fires[i] - fires[i - 1]);
  if (dow !== "*") return gap > 0 ? 7 * 1440 / field(dow, 0, 6).length : gap;
  if (dom !== "*") return 31 * 1440; // a day-of-month list: at most a month apart
  return gap;
}

/** The `cron:` expressions a workflow file schedules (comments are not schedules). */
export function cronsOf(yamlText) {
  return [...yamlText.matchAll(/^\s*-\s*cron:\s*["']?([^"'\n#]+?)["']?\s*(?:#.*)?$/gm)].map((m) => m[1].trim());
}

// ── the thin layer over `gh api` ────────────────────────────────────────────

export function ghJson(args, { exec = execFileSync } = {}) {
  return JSON.parse(exec("gh", ["api", ...args], { encoding: "utf8", maxBuffer: 64 << 20 }));
}

export function fetchUnfinished(repo, exec) {
  const runs = [];
  const notes = [];
  for (const status of UNFINISHED) {
    const page = ghJson([`repos/${repo}/actions/runs?status=${status}&per_page=100`], { exec });
    runs.push(...page.workflow_runs);
    if (page.workflow_runs.length === 100 && page.total_count > 100) notes.push(`${status}: ${page.total_count} runs, the first ${page.workflow_runs.length} were read`);
  }
  return { runs, notes };
}

/** `before`: a past instant to reconstruct (`--now`); only runs created before it count. */
export function fetchLastSuccess(repo, silence, exec, before) {
  const out = new Map();
  for (const w of silence) {
    const page = ghJson([`repos/${repo}/actions/workflows/${w.file}/runs?status=success&per_page=1${before ? `&created=<${before.toISOString().slice(0, 19)}Z` : ""}`], { exec });
    out.set(w.workflow, page.workflow_runs[0]?.updated_at ?? null);
  }
  return out;
}

export function main(argv = process.argv.slice(2), env = process.env, { exec = execFileSync, now = new Date(), write = (s) => process.stdout.write(s) } = {}) {
  const repo = env.GITHUB_REPOSITORY ?? "mihailinl/astra-registry";
  const asOf = argv.includes("--now") ? new Date(argv[argv.indexOf("--now") + 1]) : now;
  const data = loadData();
  const past = argv.includes("--now") ? asOf : undefined;
  const fetched = fetchUnfinished(repo, exec);
  const notes = fetched.notes;
  // Reconstructing a past instant: a run created after it was not there. (Runs that have finished since cannot be seen as they were.)
  const runs = past ? fetched.runs.filter((r) => Date.parse(r.created_at) < past.getTime()) : fetched.runs;
  const { stale, ghosts, young } = classify(runs, {
    ghostIds: new Set(data.ghosts.map((g) => g.id)), staleMinutes: data.stale_minutes, now: asOf,
    selfRunId: env.GITHUB_RUN_ID ? Number(env.GITHUB_RUN_ID) : undefined,
  });
  const silentWorkflows = silent(data.silence, fetchLastSuccess(repo, data.silence, exec, past), asOf);
  const result = { stale, ghosts, young, silentWorkflows, staleMinutes: data.stale_minutes, now: asOf };
  let text = render(result);
  if (notes.length > 0) text += `\nNot every run was read: ${notes.join("; ")}.\n`;
  write(text);
  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, text);
  if (env.GITHUB_OUTPUT) fs.appendFileSync(env.GITHUB_OUTPUT, `status=${exitCode(result) ? "red" : "green"}\ncodes=${alarmCodes(result).join(",")}\n`);
  return exitCode(result);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.exitCode = main(); } catch (e) { process.stderr.write(`run-watchdog: ${e.message}\n`); process.exitCode = 2; }
}
