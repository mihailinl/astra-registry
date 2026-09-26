#!/usr/bin/env node
// ROLL-60's rehearsal, one step at a time, onto a rehearsal canary.
//
//   node tools/testkeys/rehearsal-push.mjs --list                  # the steps, and what each carries
//   node tools/testkeys/rehearsal-push.mjs --status                # where the canary's `signed` and Pages are
//   node tools/testkeys/rehearsal-push.mjs --step 1 --dry-run      # everything but the push
//   node tools/testkeys/rehearsal-push.mjs --step 1 --evidence roll60.jsonl
//
// With no `--repo` it serves the cut at T0 2026-09-26 (fixtures/rehearsal-r2b/)
// on `mihailinl/astra-registry-canary-2`. `--repo mihailinl/astra-registry-canary`
// serves the first cut (fixtures/rehearsal-r2/, T0 2026-09-22) there. Each
// canary is refused the other's cut.
//
// Run it from a fresh clone of astra-registry `main`, never from the shared
// checkout: it runs the fixtures' judge, which reads this tree. The runbook is
// astra-plugins-ops `runbooks/roll-60-rehearsal.md`; every decision is in
// `tools/lib/rehearsal-push.mjs`, which the selftest drives against a local
// bare remote. This file only wires the three things a test must not have:
// the real network for Pages, the judge as a child process, and argv.
//
// **The judge.** "The fixtures are self-consistent" means the checks in
// `tools/selftest/rehearsal-r2.mjs` pass, and that module only EXPORTS
// `run()`: `node tools/selftest/rehearsal-r2.mjs` on its own evaluates the
// module, runs no check and exits 0, which reads exactly like a pass. So the
// judge here runs it through the harness, in a child so its output and its
// temp directory stay its own, and refuses a run that passed fewer checks than
// the runner's floor for that module.

import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { main } from "../lib/rehearsal-push.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");

/**
 * `tools/selftest.mjs`'s FLOORS entry for `rehearsal-r2.mjs`. A judge that passed fewer checked less.
 * The two are held equal by `tools/selftest/rehearsal-push.mjs`. The judge
 * judges every cut, so a push of either cut needs both to pass.
 */
const JUDGE_FLOOR = 29;
const MARK = "REHEARSAL-JUDGE ";

function judge() {
  const harness = pathToFileURL(path.join(REPO, "tools", "selftest", "harness.mjs")).href;
  const module = pathToFileURL(path.join(REPO, "tools", "selftest", "rehearsal-r2.mjs")).href;
  const script = [
    `const h = await import(${JSON.stringify(harness)});`,
    `const m = await import(${JSON.stringify(module)});`,
    "await m.run();",
    "await h.drain();",
    "const r = h.results();",
    "h.cleanupTmp();",
    `console.log(${JSON.stringify(MARK)} + JSON.stringify({ passed: r.passed, failures: r.failures, notAsked: r.notAsked }));`,
  ].join("\n");
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], { cwd: REPO, encoding: "utf8" });
  const line = (r.stdout || "").split("\n").reverse().find((l) => l.startsWith(MARK));
  if (r.status !== 0 || !line) {
    return { ok: false, detail: `the judge exited ${r.status} without a verdict: ${(r.stderr || r.stdout || "").trim().slice(-400)}` };
  }
  const v = JSON.parse(line.slice(MARK.length));
  const failing = (r.stdout || "").split("\n").filter((l) => /^\s+FAIL\s/.test(l)).map((l) => l.trim());
  if (v.failures.length || v.notAsked.length || v.passed < JUDGE_FLOOR) {
    return {
      ok: false,
      detail: `${v.passed} passed, ${v.failures.length} failed, ${v.notAsked.length} not asked (floor ${JUDGE_FLOOR})` +
        (failing.length ? `: ${failing.join("; ")}` : ""),
    };
  }
  return { ok: true, detail: `tools/selftest/rehearsal-r2.mjs, ${v.passed} checks, 0 failed, 0 not asked` };
}

process.exit(await main(process.argv.slice(2), { fetchImpl: globalThis.fetch, judge }));
