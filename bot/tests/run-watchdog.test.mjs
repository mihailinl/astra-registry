// tools/run-watchdog.mjs: does a run hang, or has a workflow gone quiet?
//
// On 2026-11-05 a `Moderation coverage` run's `alert` job never got a runner,
// held the workflow's concurrency group, and the canary was dark for five days
// with nothing watching run age. What is held here: AGE decides what is stale
// (never status: a healthy running run reports `queued`), the six runs GitHub
// will neither cancel nor delete are said once and never counted, silence is
// per workflow against bounds that cannot drift from the crons, and the exit
// code is red exactly when somebody has to look.
//
// OUTSIDE TRUST-31's set, with the tool, its data and its workflow.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  alarmCodes, classify, cronMaxGapMinutes, cronsOf, exitCode, fetchLastSuccess, fetchUnfinished, loadData, main,
  render, runAgeMinutes, silent, UNFINISHED,
} from "../../tools/run-watchdog.mjs";

const ROOT = path.resolve(import.meta.dirname, "..", "..");
const NOW = new Date("2026-11-10T12:00:00Z");
const ago = (min) => new Date(NOW.getTime() - min * 60_000).toISOString();
const run = (over) => ({ id: 1, name: "Moderation coverage", status: "queued", event: "schedule", created_at: ago(5), run_started_at: ago(5), run_attempt: 1, html_url: "https://github.com/x/y/actions/runs/1", ...over });
const data = loadData();
const opts = { ghostIds: new Set(data.ghosts.map((g) => g.id)), staleMinutes: data.stale_minutes, now: NOW };

test("a young queued run is not stale, and a young one in progress is not either", () => {
  const r = classify([run({ status: "queued", created_at: ago(29) }), run({ id: 2, status: "in_progress", created_at: ago(29) })], opts);
  assert.deepEqual(r.stale, []);
  assert.equal(r.young.length, 2);
});

test("age decides, never status: every unfinished status goes stale at 31 minutes", () => {
  for (const status of UNFINISHED) {
    const r = classify([run({ status, created_at: ago(31), run_started_at: ago(31) })], opts);
    assert.equal(r.stale.length, 1, `${status} at 31 minutes is stale`);
  }
  assert.deepEqual(classify([run({ status: "completed", created_at: ago(9999) })], opts).stale, [], "finished runs are never stale");
  assert.equal(classify([run({ status: "queued", created_at: ago(30.5) })], opts).stale.length, 1);
});

test("an in_progress run counts from when it started, a later attempt from the attempt", () => {
  assert.equal(Math.round(runAgeMinutes(run({ status: "in_progress", created_at: ago(300), run_started_at: ago(10) }), NOW)), 10);
  assert.equal(Math.round(runAgeMinutes(run({ status: "queued", created_at: ago(300), run_started_at: ago(10), run_attempt: 2 }), NOW)), 10);
  assert.equal(Math.round(runAgeMinutes(run({ status: "queued", created_at: ago(300), run_started_at: ago(10), run_attempt: 1 }), NOW)), 300);
});

test("the six known ghosts are reported once as ghosts and are never stale", () => {
  assert.equal(data.ghosts.length, 6);
  const ghosts = data.ghosts.map((g) => run({ id: g.id, name: g.workflow, created_at: g.created_at, run_started_at: g.created_at, status: "in_progress" }));
  const stranger = run({ id: 99, created_at: ago(60) });
  const r = classify([...ghosts, stranger], opts);
  assert.equal(r.ghosts.length, 6);
  assert.deepEqual(r.stale.map((s) => s.id), [99]);
  const text = render({ ...r, silentWorkflows: [], staleMinutes: 30, now: NOW });
  assert.match(text, /Known ghosts[^\n]*nothing to do/);
  assert.equal(text.match(/#42066476714/g).length, 1, "each ghost once");
  assert.equal(exitCode({ stale: [], silentWorkflows: [] }), 0, "ghosts alone are green");
});

test("this run itself is never judged", () => {
  assert.deepEqual(classify([run({ id: 5, created_at: ago(90) })], { ...opts, selfRunId: 5 }).stale, []);
});

test("silence: per workflow, against its own bound, and 'never' is silent", () => {
  const silence = [{ workflow: "A", max_minutes: 60 }, { workflow: "B", max_minutes: 90 }, { workflow: "C", max_minutes: 60 }];
  const last = new Map([["A", ago(59)], ["B", ago(91)], ["C", null]]);
  const out = silent(silence, last, NOW);
  assert.deepEqual(out.map((s) => s.workflow), ["B", "C"]);
  assert.equal(out[0].minutes, 91);
  assert.equal(out[1].minutes, null);
  assert.deepEqual(silent(silence, new Map([["A", ago(1)], ["B", ago(1)], ["C", ago(1)]]), NOW), []);
});

test("the bounds are in minutes: a day is not 36 minutes and 36 hours is not 36", () => {
  const daily = data.silence.find((w) => w.workflow === "Asset check");
  assert.equal(daily.max_minutes, 36 * 60);
  assert.deepEqual(silent([daily], new Map([["Asset check", ago(35 * 60)]]), NOW), []);
  assert.equal(silent([daily], new Map([["Asset check", ago(37 * 60)]]), NOW).length, 1);
});

test("the verdict text says what is red and what to do", () => {
  const text = render({
    stale: [{ id: 7, name: "Moderation coverage", status: "queued", event: "workflow_run", minutes: 95, url: "https://github.com/x/y/actions/runs/7" }],
    ghosts: [], young: [], staleMinutes: 30, now: NOW,
    silentWorkflows: [{ workflow: "Signer", minutes: 800, max_minutes: 720 }, { workflow: "Detectors", minutes: null, max_minutes: 720 }],
  });
  assert.match(text, /## Run watchdog: RED/);
  assert.match(text, /1 STALE run\(s\)[^\n]*30 min/);
  assert.match(text, /- Moderation coverage #7 \(workflow_run\): queued for 95 min https:\/\/github.com\/x\/y\/actions\/runs\/7/);
  assert.match(text, /- Signer: last success 13\.3 h ago, bound 12 h/);
  assert.match(text, /- Detectors: no successful run found/);
  assert.match(text, /RUNBOOK\.md, "A run that hangs"/);
  assert.match(render({ stale: [], ghosts: [], young: [], silentWorkflows: [], staleMinutes: 30, now: NOW }), /Run watchdog: green/);
});

test("exit is non-zero when anything is stale or silent, zero otherwise; the alarm names both", () => {
  const stale = [{ id: 1 }], sil = [{ workflow: "x" }];
  assert.equal(exitCode({ stale, silentWorkflows: [] }), 1);
  assert.equal(exitCode({ stale: [], silentWorkflows: sil }), 1);
  assert.equal(exitCode({ stale: [], silentWorkflows: [] }), 0);
  assert.deepEqual(alarmCodes({ stale, silentWorkflows: sil }), ["A_RUN_STALE", "A_WORKFLOW_SILENT"]);
  assert.deepEqual(alarmCodes({ stale: [], silentWorkflows: [] }), []);
});

test("main, against a fake gh: a stale run is red and says so in the summary and the outputs", () => {
  const calls = [];
  const exec = (_gh, args) => {
    const url = args[1];
    calls.push(url);
    if (url.includes("/actions/workflows/")) return JSON.stringify({ total_count: 1, workflow_runs: [{ updated_at: ago(5) }] });
    if (url.includes("status=queued")) return JSON.stringify({ total_count: 1, workflow_runs: [run({ id: 42, created_at: ago(120) })] });
    return JSON.stringify({ total_count: 0, workflow_runs: [] });
  };
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR ?? "/tmp", "wd-"));
  const summary = path.join(dir, "summary.md"), output = path.join(dir, "out.txt");
  let printed = "";
  const code = main([], { GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: output, GITHUB_REPOSITORY: "o/r" }, { exec, now: NOW, write: (s) => { printed += s; } });
  assert.equal(code, 1);
  assert.match(fs.readFileSync(summary, "utf8"), /1 STALE run\(s\)/);
  assert.equal(fs.readFileSync(output, "utf8"), "status=red\ncodes=A_RUN_STALE\n");
  assert.equal(printed, fs.readFileSync(summary, "utf8"));
  assert.equal(calls.filter((u) => u.includes("/actions/runs?status=")).length, UNFINISHED.length);
  assert.ok(calls.every((u) => u.startsWith("repos/o/r/")), "asks the repository it runs in");
});

test("a reconstructed past instant asks for successes created before it", () => {
  const seen = [];
  fetchLastSuccess("o/r", [{ workflow: "W", file: "w.yml" }], (_g, a) => { seen.push(a[1]); return JSON.stringify({ workflow_runs: [] }); }, new Date("2026-11-08T12:00:00Z"));
  assert.match(seen[0], /created=<2026-11-08T12:00:00Z/);
  assert.equal(fetchUnfinished("o/r", () => JSON.stringify({ total_count: 0, workflow_runs: [] })).runs.length, 0);
});

// ── the canary: a changed cron without a changed bound fails ────────────────

const workflowFile = (f) => fs.readFileSync(path.join(ROOT, ".github", "workflows", f), "utf8");

test("cron arithmetic: the longest gap a schedule leaves", () => {
  assert.equal(cronMaxGapMinutes("3-59/10 * * * *"), 10);
  assert.equal(cronMaxGapMinutes("*/15 * * * *"), 15);
  assert.equal(cronMaxGapMinutes("7,22,37,52 * * * *"), 15);
  assert.equal(cronMaxGapMinutes("23 * * * *"), 60);
  assert.equal(cronMaxGapMinutes("23 3 * * *"), 1440);
  assert.equal(cronMaxGapMinutes("23 9 * * 1"), 7 * 1440);
  assert.deepEqual(cronsOf("on:\n  schedule:\n    - cron: \"23 3 * * *\"\n    #   - cron: '1 1 * * *'\n    - cron: '*/10 * * * *' # note\n"), ["23 3 * * *", "*/10 * * * *"]);
});

test("every watched workflow's crons are the ones its bound was set against, and the bound leaves room", () => {
  for (const w of data.silence) {
    const crons = cronsOf(workflowFile(w.file));
    assert.deepEqual(crons, w.crons, `${w.file} schedules ${JSON.stringify(crons)} and tools/run-watchdog.json bounds it against ${JSON.stringify(w.crons)}: change the bound with the cron`);
    const gap = Math.max(...crons.map(cronMaxGapMinutes));
    assert.ok(w.max_minutes >= 1.5 * gap, `${w.workflow}: ${w.max_minutes} min is under 1.5 x its cron's longest gap of ${gap} min`);
    assert.match(workflowFile(w.file), new RegExp(`^name: ${w.workflow.replace(/[()]/g, "\\$&")}\\s*$`, "m"), `${w.file} is not named ${w.workflow}`);
  }
});

test("no scheduled workflow escapes the watchdog without a reason", () => {
  const listed = new Set([...data.silence.map((w) => w.file), ...data.unwatched.map((w) => w.file), "run-watchdog.yml"]);
  for (const f of fs.readdirSync(path.join(ROOT, ".github", "workflows")).filter((n) => n.endsWith(".yml"))) {
    if (cronsOf(workflowFile(f)).length === 0) continue;
    assert.ok(listed.has(f), `${f} has a cron and no bound in tools/run-watchdog.json (silence) or reason (unwatched)`);
  }
  for (const u of data.unwatched) assert.ok(u.why.length > 20);
});

test("the watchdog's own workflow: its triggers, permissions, timeout, concurrency and alarm", () => {
  const src = workflowFile("run-watchdog.yml");
  assert.deepEqual(cronsOf(src), ["*/10 * * * *"]);
  assert.match(src, /workflow_run:\n\s+workflows: \[[^\]]*\]\n\s+types: \[completed\]/);
  assert.match(src, /^permissions:\n  actions: read\n  contents: read\n/m);
  assert.match(src, /concurrency:\n  group: run-watchdog\n  cancel-in-progress: true/);
  const watched = /workflows: \[([^\]]*)\]/.exec(src)[1].split(",").map((s) => s.trim().replace(/^'|'$/g, ""));
  assert.ok(!watched.includes("Run watchdog"), "it must not wake itself");
  for (const name of watched) assert.ok(fs.readdirSync(path.join(ROOT, ".github", "workflows")).some((f) => new RegExp(`^name: ${name.replace(/[()]/g, "\\$&")}\\s*$`, "m").test(workflowFile(f))), `no workflow is named ${name}`);
  const verdictJob = /\n  watchdog:\n([\s\S]*?)\n  alert-state:/.exec(src)[1];
  assert.match(verdictJob, /timeout-minutes: 5/);
  assert.doesNotMatch(verdictJob, /environment:|secrets\./, "the verdict job needs nothing from environment alerts, or it could hang like what it watches");
  const alertJob = /\n  alert:\n([\s\S]*?)\n  alert-save:/.exec(src)[1];
  assert.match(alertJob, /environment: alerts/);
  assert.match(alertJob, /needs: \[watchdog, alert-state\]/);
});

test("the data file's ghosts are numbers and the stale bound is thirty minutes", () => {
  assert.equal(data.stale_minutes, 30);
  assert.ok(data.ghosts.every((g) => Number.isInteger(g.id) && g.workflow && g.created_at));
  assert.equal(new Set(data.ghosts.map((g) => g.id)).size, data.ghosts.length);
});
