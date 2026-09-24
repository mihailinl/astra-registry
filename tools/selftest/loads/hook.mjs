// THE LOAD RECORDER — ops `dev/couplings.md` entry 116, contract pending item 19.
//
// WHY IT EXISTS. `bot/publish-apply.mjs` runs `tools/selftest.mjs` as the last
// of its five checks and the moderation commit job runs it too, so whatever the
// suite executes decides whether a bot commit lands. TRUST-31's hashed set
// (`bot/tests/code-paths.test.mjs`, `ENTRIES`) follows the bot's STATIC import
// closure; the runner loads its cases by a dynamic `import()`, and the cases
// reach code no static walk sees — a computed specifier, a temp copy of a bot
// test executed as a child, a generator run as a child. Lane AQ measured it at
// runtime on 2026-09-22: 31 repository modules outside the set. Whether they
// went into the set or out of the gate was the owner's decision (pending item
// 19), decided (a) for him on 2026-09-23 — contract 0.38.0 put them in — and
// either answer needed this first, because a static walk had already
// certified three cases that run outside code. It is what keeps (a) true.
//
// WHAT IT DOES. A preload: `node --import=<this file's URL>?log=<dir> …`. It
// registers a synchronous module hook (`module.registerHooks`) whose `load`
// step appends one line per module FILE this process loads to its own
// `<dir>/<pid>-<uuid>.jsonl`, with the module that imported it, and a SHA-256
// of any file outside this checkout so a copy in a temp directory can be named
// by its content. And it puts itself into this process's `NODE_OPTIONS`, so a
// node child that inherits the environment records itself too.
//
// MEASURE MODE. It never prints, never refuses a module, and never changes what
// is loaded: a run under it asserts exactly what a run without it does, plus
// what `tools/selftest/loads.mjs` holds the record to. A guard that REFUSED
// out-of-set modules would change what a gate does, and that is the owner's
// choice, not this file's. `node tools/selftest.mjs --loads` is how it runs:
// the runner relaunches itself under this file (`record.mjs`), and the last
// module, `loads.mjs`, reads the record.
//
// REQUIRES NODE 22.15.0 (or 23.5.0 on the 23 line), where `module.registerHooks`
// arrived. On an older Node this file loads, records NOTHING, and marks the
// process as not recording with the version it found — so every check that
// reads the record says NOT ASKED, by name, with that version. Never `ok`.
// The lane table in tools/selftest.mjs reads each lane's `node-version` for
// the same reason: a lane pinned below the floor is a lane that does not ask.
//
// WHAT IT CANNOT SEE — each is a way for code to run in a selftest run and be
// absent from the record, and none of them is detected:
//
//   1. A node child that drops NODE_OPTIONS — spawned with an `env` that does
//      not carry it, or through something that scrubs the environment. It
//      records nothing and nothing says it ran. Measured on 2026-09-22 with a
//      throwaway probe wrapping `child_process`: of the 198 node children a
//      `--loads` run starts, 7 drop it, and all 7 are the heartbeat child in
//      `tools/selftest/cli.mjs`, spawned with `{ PATH, <secret> }` as its whole
//      environment — so `bot/heartbeat.mjs` and its imports are not in the
//      record. Its static imports (`bot/lib/alert-checks.mjs`,
//      `bot/lib/alert-verdict.mjs`, `tools/lib/ids.mjs`) are inside the set
//      today; nothing here would notice the day one is not.
//   2. A program that is not node — git, cargo, sh, openssl — and anything it
//      runs in turn. Only node's module loader is hooked.
//   3. Data reads. A JSON, a key or a policy file read with `fs` decides as
//      much as a module does and is not a load. That is leg (c) of
//      `bot/tests/code-paths.test.mjs` (entry 104), a different question.
//   4. Code this run did not execute: an import behind a branch this
//      environment did not take — a sibling AstraPlugins checkout present, a
//      shallow history, a check NOT ASKED — or a module a failing test never
//      reached. The record is of ONE run in ONE lane, and the declared residual
//      in `loads.mjs` is measured in `build-index.yml`'s `check` job's
//      environment: the whole history, and no AstraPlugins beside it.
//   5. Code that is not a module file: `eval`, `new Function`, `vm`, `node -e`,
//      a `data:` import, and worker threads, which in-thread hooks do not reach
//      (nothing in this repository starts one today).
//   6. What was loaded before this file: a process started without it, and the
//      runner that relaunches itself under it — which is why the relaunched
//      runner, not the first one, is the process whose record counts.
//   7. A copy that is not byte-identical to a module in this tree. `loads.mjs`
//      names a copy by its bytes, so a module a case rewrote into a temp tree,
//      or took from another commit, is no repository module to it: listed by
//      file name on every `--loads` run, and held to nothing. Measured on
//      2026-09-22: 6 such loads — the copies of `bot/recheck-publishers.mjs`
//      and `tools/lib/sources.mjs` that `publishers.mjs` changes under the
//      daily job, two copies of `tools/build-index.mjs` that are not today's
//      bytes in the trees `tools/regenerate-signed.mjs` assembles for a
//      generator commit, and the clock stub the update signer's fixtures
//      module wrote. That module moved into Astra with the signer at
//      RC-R3-4(b), so the sixth is gone and the count is five from then.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import nodeModule from "node:module";
import { fileURLToPath } from "node:url";

import { LOADS_STATE, NODE_FLOOR } from "./record.mjs";

const SELF = new URL(import.meta.url);
const ROOT = fs.realpathSync(path.resolve(path.dirname(fileURLToPath(SELF)), "..", "..", ".."));
const DIR = SELF.searchParams.get("log");

const state = { recording: false, why: "", dir: DIR, node: process.version };
globalThis[LOADS_STATE] = state;

// Children first, whatever else happens: a child that inherits this line loads
// this file, and says for itself whether it could record.
{
  const opt = `--import=${SELF.href}`;
  const current = process.env.NODE_OPTIONS ?? "";
  if (!current.split(/\s+/).includes(opt)) process.env.NODE_OPTIONS = [current, opt].filter(Boolean).join(" ");
}

if (typeof nodeModule.registerHooks !== "function") {
  state.why = `Node ${process.version} has no module.registerHooks, which arrived in ${NODE_FLOOR}, so this ` +
    "process could not record the modules it loaded";
} else if (!DIR || !path.isAbsolute(DIR) || !fs.statSync(DIR, { throwIfNoEntry: false })?.isDirectory()) {
  state.why = `the recorder was preloaded with no log directory it could write to (${JSON.stringify(DIR)}); start ` +
    "the run with `node tools/selftest.mjs --loads`, which makes one";
} else {
  const fd = fs.openSync(path.join(DIR, `${process.pid}-${crypto.randomUUID()}.jsonl`), "a");
  const put = (rec) => fs.writeSync(fd, `${JSON.stringify({ ...rec, pid: process.pid })}\n`);
  put({
    kind: "process", ppid: process.ppid, argv: process.argv, execArgv: process.execArgv, cwd: process.cwd(), node: process.version,
  });
  const inside = (f) => f === ROOT || f.startsWith(ROOT + path.sep);
  const parents = new Map();
  nodeModule.registerHooks({
    resolve(specifier, context, nextResolve) {
      const resolved = nextResolve(specifier, context);
      if (context.parentURL && resolved?.url && !parents.has(resolved.url)) parents.set(resolved.url, context.parentURL);
      return resolved;
    },
    load(url, context, nextLoad) {
      if (url.startsWith("file:")) {
        const file = fileURLToPath(url);
        const parentUrl = parents.get(url);
        const rec = { kind: "load", file, parent: parentUrl?.startsWith("file:") ? fileURLToPath(parentUrl) : parentUrl ?? null };
        if (!inside(file)) rec.sha256 = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
        put(rec);
      }
      return nextLoad(url, context);
    },
  });
  state.recording = true;
  state.why = "";
}
