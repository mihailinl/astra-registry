#!/usr/bin/env node
// When did sign.yml's export check last actually compare anything?
//
//   node tools/signer/export-memory.mjs --verdict verdict.json
//     env: ASTRA_ALERT_STATE (the restored state line), EXPORT_ANSWER
//          (export-assert's `export` output), ASTRA_ALERT_STATE_HMAC_KEY
//
// Phase 2 step 2. `export-assert` (tools/signer/export-assert.mjs) reports a
// 404 or an answer at another serial as a note, because a lagging service is
// not a different state. Alone that has a quiet failure: a service that
// answers 404 to every question keeps the check green for ever with nothing
// ever compared. So `export-alert` remembers when a comparison last happened
// — a 200 that was compared, equal or not — and raises
// SIGNER_EXPORT_NOT_COMPARED once the URL has been set for 24 hours without
// one. The check never repeats a page (bot/alert.mjs NO_REPEAT_CHECKS), so it
// pages once, and it resolves when a comparison happens.
//
// The memory lives in export-alert's own signed alert state, under
// `MEMORY_CHECK`, because that is the only state this check has and the only
// job that can sign it. It is written back every `REFRESH_HOURS` while
// comparisons happen, not on every run, so a healthy hour costs no cache save.
//
// This runs in a job that holds the alarm credential, so it imports
// bot/alert.mjs and nothing else of this repository (BOT-46's sparse checkout).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { readSignedState, signState, stateKey } from "../../bot/alert.mjs";

/** The entry of the alert state that holds this memory. */
export const MEMORY_CHECK = "signer-export-compared";
export const NOT_COMPARED_CODE = "SIGNER_EXPORT_NOT_COMPARED";
export const NOT_COMPARED_HOURS = 24;
export const REFRESH_HOURS = 6;

/** The answers of export-assert that are a comparison. */
const COMPARED = new Set(["equal", "differs"]);
const HOUR = 3600_000;
const iso = (d) => `${d.toISOString().slice(0, 19)}Z`;
const validTime = (t) => typeof t === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(t) && Number.isFinite(Date.parse(t));

/** A memory entry as it may be trusted, or null. */
function readMemory(entry) {
  if (!entry || typeof entry !== "object" || !validTime(entry.asked_since)) return null;
  if (entry.last_compared !== null && !validTime(entry.last_compared)) return null;
  return { asked_since: entry.asked_since, last_compared: entry.last_compared };
}

/**
 * The memory after this run, whether it changed, and whether this run has
 * gone too long without a comparison.
 *
 * `answer` is export-assert's `export` output: `not-asked` forgets (the URL is
 * unset); `equal` or `differs` is a comparison; anything else — `other-serial`,
 * `unreachable`, or empty because the job did not report — is asking without
 * comparing.
 *
 * @returns {{memory: object|null, changed: boolean, notCompared: boolean, since: string|null}}
 */
export function compareMemory({ prior, answer, now = new Date() }) {
  const p = readMemory(prior);
  if (answer === "not-asked") return { memory: null, changed: p !== null, notCompared: false, since: null };
  if (COMPARED.has(answer)) {
    const stale = !p?.last_compared || now.getTime() - Date.parse(p.last_compared) >= REFRESH_HOURS * HOUR;
    const memory = stale ? { asked_since: p?.asked_since ?? iso(now), last_compared: iso(now) } : p;
    return { memory, changed: stale, notCompared: false, since: memory.last_compared };
  }
  // An empty answer is a job that did not report: it starts nothing, but an
  // existing memory keeps counting.
  if (!p && !answer) return { memory: null, changed: false, notCompared: false, since: null };
  const memory = p ?? { asked_since: iso(now), last_compared: null };
  const since = memory.last_compared ?? memory.asked_since;
  return { memory, changed: !p, notCompared: now.getTime() - Date.parse(since) >= NOT_COMPARED_HOURS * HOUR, since };
}

/** The verdict with SIGNER_EXPORT_NOT_COMPARED added, when it is due. */
export function withNotCompared(verdict, notCompared) {
  if (!notCompared) return verdict;
  const codes = [...new Set([...(verdict.codes ?? []), NOT_COMPARED_CODE])];
  return { ...verdict, status: "red", codes };
}

function parseArgs(argv) {
  const args = { verdict: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--verdict") args.verdict = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (!args.verdict) throw new Error("--verdict <file> is required");
  return args;
}

/** One run, as the workflow step does it. Returns the step's outputs. */
export function runMemory({ verdictFile, stateLine, answer, env = process.env, now = new Date(), log = console }) {
  const key = stateKey(env);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "export-memory-"));
  try {
    const file = path.join(tmp, "state.json");
    fs.writeFileSync(file, stateLine ?? "");
    const state = readSignedState(file, key);
    const m = compareMemory({ prior: state.checks?.[MEMORY_CHECK], answer, now });
    const verdict = JSON.parse(fs.readFileSync(verdictFile, "utf8"));
    fs.writeFileSync(verdictFile, `${JSON.stringify(withNotCompared(verdict, m.notCompared), null, 2)}\n`);
    log.log(
      m.since === null
        ? `ok    export comparisons: nothing to remember (export ${JSON.stringify(answer ?? "")})`
        : `${m.notCompared ? "FAIL" : "ok  "}  export comparisons: the last was ${m.memory.last_compared ?? "never"}, asked since ${m.memory.asked_since}` +
          (m.notCompared ? `; ${NOT_COMPARED_HOURS} hours or more without one, ${NOT_COMPARED_CODE}` : ""),
    );
    if (!key) {
      log.log("::warning::ASTRA_ALERT_STATE_HMAC_KEY is not in this job, so the comparison memory is not trusted or saved");
      return { state: stateLine ?? "", changed: false };
    }
    const checks = { ...(state.checks ?? {}) };
    if (m.memory) checks[MEMORY_CHECK] = m.memory;
    else delete checks[MEMORY_CHECK];
    return { state: JSON.stringify(signState({ checks }, key)), changed: m.changed };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function main(argv) {
  const args = parseArgs(argv);
  const out = runMemory({ verdictFile: args.verdict, stateLine: process.env.ASTRA_ALERT_STATE, answer: process.env.EXPORT_ANSWER ?? "" });
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `state=${out.state}\nchanged=${out.changed}\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(1);
  }
}
