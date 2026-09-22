// The load guard's plumbing, with no side effect at import: where the recorder
// lives, how a run is started under it, whether this process is recording, and
// how a record is read back. `hook.mjs` beside this file is the recorder and
// states what it cannot see; `tools/selftest/loads.mjs` is what the record is
// held to. Ops `dev/couplings.md` entry 116, contract pending item 19.
//
// In a subdirectory on purpose: `checkModuleSet` in tools/selftest.mjs imports
// every `.mjs` directly under tools/selftest/ to ask what it exports, and the
// recorder registers a module hook when it is imported. Here it is still under
// TRUST-31's `tools/selftest/` entry, so the instrument is inside the set it
// measures against.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

/** Where the recorder leaves its state in a process it was preloaded into. */
export const LOADS_STATE = Symbol.for("astra-registry.selftest.loads");

/** The recorder, as a file. */
export const HOOK_FILE = fileURLToPath(new URL("./hook.mjs", import.meta.url));

/** Set in the relaunched runner's environment, so a relaunch happens once. */
export const RELAUNCHED = "ASTRA_SELFTEST_LOADS_RELAUNCHED";

/**
 * The oldest Node whose `module.registerHooks` the recorder uses: 22.15.0, and
 * 23.5.0 on the 23 line (the backport and the release it came from).
 */
export const NODE_FLOOR = "22.15.0 (or 23.5.0 on the 23 line)";

/** What the recorder left in this process, or null when it was not preloaded here. */
export function loadsState() {
  return globalThis[LOADS_STATE] ?? null;
}

/**
 * THE question the load checks are gated on, and the one the runner's
 * `ENVIRONMENTS.loads.here` asks of a run: is this process NOT recording what
 * it loads? One function for both, so what the lane scan reads a gate as
 * asking and what a run measures are the same question.
 */
export function loadsUnrecorded() {
  return loadsState()?.recording !== true;
}

/** Why this process is not recording, in a sentence, for a NOT ASKED line. */
export function whyUnrecorded() {
  const state = loadsState();
  if (state) return state.why;
  if (process.env[RELAUNCHED]) {
    return "the runner relaunched itself under tools/selftest/loads/hook.mjs and the recorder did not run in this " +
      "process — something between the relaunch and here dropped NODE_OPTIONS";
  }
  return "this run was not started with `--loads`, so nothing recorded the modules it loaded";
}

/**
 * Relaunch `entry` under the recorder: a fresh log directory, the recorder in
 * NODE_OPTIONS (which every node child that inherits the environment inherits),
 * the same arguments, and the same stdio. Returns the child's exit status; the
 * caller exits with it. The log directory is removed afterwards — the child
 * reads it while it runs, and nothing reads it after.
 */
export function relaunchUnderHook(entry, args) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-registry-loads-"));
  try {
    const hook = pathToFileURL(HOOK_FILE);
    hook.searchParams.set("log", dir);
    const r = spawnSync(process.execPath, [...process.execArgv, entry, ...args], {
      stdio: "inherit",
      env: {
        ...process.env,
        [RELAUNCHED]: "1",
        NODE_OPTIONS: [process.env.NODE_OPTIONS, `--import=${hook.href}`].filter(Boolean).join(" "),
      },
    });
    if (r.error) {
      console.error(`tools/selftest.mjs --loads: could not relaunch under the recorder: ${r.error.message}`);
      return 1;
    }
    return r.status ?? 1;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Every record in a log directory: `{ processes, loads }`, where a process is
 * `{ pid, ppid, argv, execArgv, cwd, node }` and a load is `{ pid, file, parent, sha256? }`.
 * A line that does not parse is thrown on: a record read with a hole in it is
 * a record of less than the run.
 */
export function readRecord(dir) {
  const processes = [];
  const loads = [];
  for (const name of fs.readdirSync(dir).filter((n) => n.endsWith(".jsonl")).sort()) {
    const lines = fs.readFileSync(path.join(dir, name), "utf8").split("\n").filter(Boolean);
    for (const [i, line] of lines.entries()) {
      let rec;
      try {
        rec = JSON.parse(line);
      } catch {
        throw new Error(`the load record ${name}:${i + 1} is not JSON, so this record is not the whole run: ${line.slice(0, 120)}`);
      }
      if (rec.kind === "process") processes.push(rec);
      else if (rec.kind === "load") loads.push(rec);
      else throw new Error(`the load record ${name}:${i + 1} has kind ${JSON.stringify(rec.kind)}, which the recorder never writes`);
    }
  }
  return { processes, loads };
}
