// THE MODULES A SELFTEST RUN LOADS, HELD TO TRUST-31'S SET — ops
// `dev/couplings.md` entry 116, contract pending item 19. Measure mode, and
// the residual is EMPTY.
//
// `bot/publish-apply.mjs` runs this suite as the last of five checks before a
// publication commits, and the moderation commit job runs it too, so what the
// suite executes decides whether a bot commit lands. TRUST-31's hashed set is
// `ENTRIES` in `bot/tests/code-paths.test.mjs`, and its leg (b) walks the bot's
// STATIC imports; the runner loads the cases by a dynamic `import()`, and the
// cases reach modules no static walk follows. Measured at runtime on
// 2026-09-22 (lane AQ, and again by this module's first run): 31 repository
// modules outside the set. The choice was the owner's, between (a) putting
// them in the set and (c) gating a bot commit only on the cases whose closure
// lies inside it; he asked for it to be decided for him, and on 2026-09-23 it
// was decided (a). Contract 0.38.0 published the 31 as set entries, so the
// table below that declared them is empty, and every out-of-set module a run
// loads is now a hole this module names.
//
// **Still measure mode, deliberately.** With an empty residual, the first
// check below already turns `build-index.yml`'s `check` job red, by name, on
// any out-of-set module the run loads — which is everything a REFUSING hook
// could do in that lane, since it is no gate. Refusing there would add a
// decision this module has no basis for — what to do with the handful of
// loads per run whose bytes match no tracked module (the recorder's header,
// limit 6) — and refusing in a GATE lane would change what a publication is
// held to, which (a) did not decide.
//
// What is asked, when the run records its loads (`node tools/selftest.mjs
// --loads`, which relaunches the runner under `loads/hook.mjs`):
//
//   * every repository module this run loaded outside the set is one RESIDUAL
//     below declares — so a NEW hole is red, by name, with what loaded it;
//   * every module RESIDUAL declares is tracked, outside the set, says why it
//     is loaded and what decision it waits on, and was loaded by this run — so
//     a declaration that matches nothing is red, by name.
//
// The set is read by `tools/selftest/trust31.mjs`, the one reader this suite
// has for it — the way astra-plugins-ops' `tools/check-trust31-copies.mjs`
// reads it. A module a run did not record is not asked about: every check here
// says NOT ASKED, by name, when the run did not record (no `--loads`, or a Node
// older than 22.15.0 — see the recorder's header for what it cannot see even
// when it does). The gates run the suite WITHOUT `--loads`, so there these
// checks are NOT ASKED and change nothing a gate decides; the lane that asks
// them is `build-index.yml`'s `check` job, and `node tools/selftest.mjs --lanes`
// derives that from the workflows rather than this sentence saying so.
//
// This module is LAST in the runner's list because it has to be: it reads what
// the whole run loaded, children included, and a module after it would load
// things it never saw.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, neverAsk, walkRepo } from "./harness.mjs";
import { trust31Entries, trust31Covers, TRUST31_COPY } from "./trust31.mjs";
import { loadsState, loadsUnrecorded, whyUnrecorded, readRecord, NODE_FLOOR } from "./loads/record.mjs";

/**
 * THE DECLARED RESIDUAL: every repository module outside TRUST-31's set that a
 * `--loads` run of this suite loads, why it is loaded, and the decision it
 * waits on. **Empty since contract 0.38.0**, which put the 31 rows this table
 * held into the set (ops pending item 19, decided (a) on 2026-09-23).
 *
 * A row arrives only with a module a case newly loads AND a decision, recorded
 * in the contract's pending register, to leave it outside for now; the second
 * check below refuses a row that names no pending item. The first check is
 * red for a module loaded and not here, and the second for a row here that
 * nothing loaded — so an empty table is a claim, asked on every `--loads` run,
 * that the fifth gate loads nothing the service's acknowledgement does not
 * cover.
 */
export const RESIDUAL = [];

const RESIDUAL_KEYS = ["module", "why", "waits"];

/** Module files, as opposed to data a loader might be handed. */
const CODE = /\.(mjs|cjs|js)$/;

/**
 * Floors on the record, for the reason every walk in this suite has one: a
 * record of nothing agrees with every declaration. Measured on 2026-09-22 with
 * `--loads`: 192 processes and 132 repository modules. Half of each, so an
 * honest retirement of tests does not redden them and a broken inheritance of
 * NODE_OPTIONS — the children stop recording — does.
 *
 * The process floor was re-measured on 2026-09-24 for an honest retirement
 * bigger than half: RC-R3-4(b) moved the update manifest signer and its two
 * case modules into Astra, and those cases ran the signer as a node child per
 * test. Main recorded 208 processes at `1054163`; the tree without them records
 * 84. Half of 84 still reds a broken inheritance — the runner alone is one.
 */
const FLOOR_PROCESSES = 42;
const FLOOR_MODULES = 65;
const FLOOR_DAY = "2026-09-24";

const words = (s) => (typeof s === "string" ? s.trim().split(/\s+/).filter(Boolean).length : 0);

let measured = null;

/**
 * The record of this run, mapped to repository paths: a loaded file under the
 * checkout is its tracked path; a file elsewhere is the tracked module (or
 * modules) whose bytes it has, which is how a copy in a temp tree is named;
 * anything else is code no repository module is byte-identical to, listed and
 * not held (the recorder's header says why that is a limit).
 */
function measure() {
  if (measured) return measured;
  const state = loadsState();
  const root = fs.realpathSync(REPO_ROOT);
  const inside = (f) => f === root || f.startsWith(root + path.sep);
  const relOf = (f) => path.relative(root, f).split(path.sep).join("/");
  const show = (f) => (f && inside(f) ? relOf(f) : f);

  const tracked = new Set(walkRepo().map((abs) => path.relative(REPO_ROOT, abs).split(path.sep).join("/")));
  const bySha = new Map();
  for (const rel of tracked) {
    if (!CODE.test(rel)) continue;
    const h = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, rel))).digest("hex");
    bySha.set(h, [...(bySha.get(h) ?? []), rel]);
  }
  const entries = trust31Entries();
  const covers = (p) => trust31Covers(entries, p);

  const { processes, loads } = readRecord(state.dir);
  const procs = new Map(processes.map((p) => [p.pid, p]));
  // What a reader would type: the flags, then the script and its first argument.
  const argvOf = (p) => [...(p?.execArgv ?? []), ...(p?.argv ?? []).slice(1, 3)].map((a) => show(String(a)).slice(0, 80)).join(" ");
  const who = (l) => {
    const by = l.parent ? `imported by ${show(l.parent)}` : "the process's own script";
    if (l.pid === process.pid) return `${by}, in the runner`;
    const p = procs.get(l.pid);
    const parent = procs.get(p?.ppid);
    return `${by}, in the child \`node ${argvOf(p)}\`${parent ? ` started by \`node ${argvOf(parent)}\`` : ""}`;
  };

  const loaded = new Map();
  const other = [];
  for (const l of loads) {
    if (!CODE.test(l.file)) {
      other.push(`${show(l.file)} (not a module file)`);
      continue;
    }
    let paths;
    if (inside(l.file)) {
      const rel = relOf(l.file);
      if (!tracked.has(rel)) {
        other.push(`${rel} (under the checkout, not tracked)`);
        continue;
      }
      paths = [rel];
    } else if (l.sha256 && bySha.has(l.sha256)) {
      // A copy. Identical bytes in two tracked files cannot be told apart;
      // the set vouches for the bytes if it holds either of them.
      const candidates = bySha.get(l.sha256);
      paths = candidates.some(covers) ? candidates.filter(covers) : candidates;
    } else {
      other.push(path.basename(l.file));
      continue;
    }
    for (const p of paths) {
      if (!loaded.has(p)) loaded.set(p, { copy: false, who: new Set() });
      const e = loaded.get(p);
      if (!inside(l.file)) e.copy = true;
      e.who.add(who(l));
    }
  }
  const outside = new Map([...loaded].filter(([p]) => !covers(p)));
  measured = { processes, loads, loaded, outside, other, tracked, covers, entries };
  return measured;
}

/** `a, b ×2, c` — each name once, sorted, with how many times it was loaded. */
function tally(names) {
  const n = new Map();
  for (const x of names) n.set(x, (n.get(x) ?? 0) + 1);
  return [...n].sort(([a], [b]) => a.localeCompare(b)).map(([x, k]) => (k > 1 ? `${x} ×${k}` : x)).join(", ");
}

function describe(p, e) {
  const whos = [...e.who];
  return `${p}${e.copy ? " (a copy, named by its content)" : ""} — ${whos.slice(0, 3).join("; ")}` +
    `${whos.length > 3 ? `; and ${whos.length - 3} more` : ""}`;
}

export async function run() {
  console.log("\nthe modules this run loaded, held to TRUST-31's set (ops couplings entry 116; --loads)");

  await test("every repository module this run loaded outside TRUST-31's set is one the declared residual names", () => {
    if (loadsUnrecorded()) {
      neverAsk(
        whyUnrecorded(),
        `\`node tools/selftest.mjs --loads\` on Node ${NODE_FLOOR} or newer records it; build-index.yml's \`check\` job does`,
      );
    }
    const m = measure();
    // The record is of this run before anything is judged by it: the runner
    // recorded itself and this module, and children recorded themselves.
    assert(m.processes.some((p) => p.pid === process.pid) && m.loaded.has("tools/selftest.mjs") &&
      m.loaded.has("tools/selftest/loads.mjs"),
      "the record does not hold this runner loading tools/selftest.mjs and tools/selftest/loads.mjs, so it is not a " +
      "record of this run and everything below would be judged against someone else's");
    assert(m.processes.length >= FLOOR_PROCESSES,
      `the record holds ${m.processes.length} process(es), and a --loads run recorded 84 on ${FLOOR_DAY}: node ` +
      "children have stopped recording themselves (NODE_OPTIONS no longer reaches them), so what they load is " +
      "missing from the record and every module only a child loads would look unloaded");
    assert(m.loaded.size >= FLOOR_MODULES,
      `the record names ${m.loaded.size} repository module(s), and there were 132 on ${FLOOR_DAY}; a record this ` +
      "small is a broken recorder, not a smaller suite");
    const declared = new Set(RESIDUAL.map((r) => r?.module));
    console.log(
      `        — recorded ${m.processes.length} process(es) loading ${m.loaded.size} repository module(s): ` +
      `${m.loaded.size - m.outside.size} inside the set, ${m.outside.size} outside it; ` +
      `${m.other.length} loaded file(s) no repository module is byte-identical to` +
      `${m.other.length ? ` (${tally(m.other)})` : ""}`,
    );
    const holes = [...m.outside].filter(([p]) => !declared.has(p)).sort(([a], [b]) => a.localeCompare(b));
    assertEqual(
      holes.map(([p, e]) => describe(p, e)).join("\n"),
      "",
      `this run loaded the module(s) named below, each outside TRUST-31's set (${TRUST31_COPY}, \`ENTRIES\`), and the ` +
      "declared residual in tools/selftest/loads.mjs does not name them. Through the publish path's fifth gate and " +
      "the moderation commit job, a change to such a module changes what a bot commit is held to without returning " +
      "the bot to shadow (ops couplings entry 116). Take the import out of the case, or put the module in the set, " +
      "or — if the owner has accepted it as residual — add a row saying why it is loaded and what it waits on",
    );
  });

  await test("every module the declared residual names is tracked, outside the set, says why and what it waits on, and was loaded by this run", () => {
    if (loadsUnrecorded()) {
      neverAsk(
        whyUnrecorded(),
        `\`node tools/selftest.mjs --loads\` on Node ${NODE_FLOOR} or newer records it; build-index.yml's \`check\` job does`,
      );
    }
    const m = measure();
    const problems = [];
    const seen = new Set();
    RESIDUAL.forEach((r, i) => {
      const label = `RESIDUAL[${i}]${typeof r?.module === "string" ? ` (${r.module})` : ""}`;
      if (!r || typeof r !== "object" || Array.isArray(r)) {
        problems.push(`${label} is not a row: it must be { ${RESIDUAL_KEYS.join(", ")} }`);
        return;
      }
      const unknown = Object.keys(r).filter((k) => !RESIDUAL_KEYS.includes(k));
      if (unknown.length) problems.push(`${label} has key(s) no row has: ${unknown.join(", ")}`);
      if (typeof r.module !== "string" || !r.module) {
        problems.push(`${label} names no module`);
        return;
      }
      if (seen.has(r.module)) problems.push(`${label} names a module an earlier row names`);
      seen.add(r.module);
      if (words(r.why) < 8) {
        problems.push(`${label}'s \`why\` is ${JSON.stringify(r.why ?? null)}: a row says why the module is loaded, ` +
          "in a sentence — below eight words it is a label, and a label is an exemption that reads like a reason");
      }
      if (words(r.waits) < 8 || !/\bpending item \d+\b/.test(r.waits)) {
        problems.push(`${label}'s \`waits\` is ${JSON.stringify(r.waits ?? null)}: a row names the decision it waits ` +
          "on — the contract's pending item — in a sentence, so the day it is decided the row has somewhere to go");
      }
      if (!m.tracked.has(r.module)) {
        problems.push(`${label} is not a tracked file in this repository, so no run can load it`);
      } else if (m.covers(r.module)) {
        problems.push(`${label} is inside TRUST-31's set, so it is no part of the residual; delete the row`);
      } else if (!m.outside.has(r.module)) {
        problems.push(`${label} was not loaded by this run — a declaration that matches nothing. If the case that ` +
          "loaded it stopped, delete the row in the same commit; if this lane did not reach it, the residual is " +
          "measured in build-index.yml's `check` environment, and that is where to ask");
      }
    });
    assertEqual(problems.join("\n"), "", "the declared residual in tools/selftest/loads.mjs does not describe this run");
  });
}
