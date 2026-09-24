// SCOPE-9's registry test, the half that can be asked today (registry plan
// RC-R3-2; contract SCOPE-8, SCOPE-9, B.7).
//
// SCOPE-7's token file says, for every code and wait the estate uses, which
// party EMITS it and which ACCEPTS it. The plugins service builds its own half
// from that file. So a code the bot sends that the file gives to another party,
// or a code the file gives to the registry that nothing here emits, is a
// disagreement neither side's own tests can see: each passes against its own
// reading of one file.
//
// **What this module found the day it was written** (2026-09-24, contract
// 2.3.0). The bot sends `W_OPERATOR_WINDOW` and `W_ALERT_UNDELIVERED` in its
// results (`bot/lib/service-results.mjs`, TRUST-32), and the token file lists
// both with emitter `service`. The contract says the opposite — B.7 lists both
// among the waits the registry reports "(registry plan: TRUST-32)", and
// OPEN-OPS-5's row says "which the bot reports as `W_OPERATOR_WINDOW`". The
// cause is in astra-plugins-ops' generator (`tools/contract-tokens.mjs`, the
// wait loop): it marks a wait service-only when "only the service shows"
// follows it within 80 characters, and B.7 lists the three waits in one
// sentence, so the window runs from each of the two into the third's
// parenthesis. The fix is one character class, and it moves the token file,
// so it is a contract version and not this repository's to make.
//
// **What it asks, each its own test:**
//
//   * every wait the bot SENDS is a wait the token file gives to the registry;
//   * every code and wait the token file gives to the registry is one the
//     bot's code carries — "a listed code nothing emits";
//   * no entry naming the registry or the bot is `service-only`, and no
//     `service-only` entry names either (SCOPE-9's 0.13.0 note, n12);
//   * a `reserved` entry — `astra.plugins.card/1` — is referenced by no bot
//     module (SCOPE-8: neither required nor allowed).
//
// **What it does not ask yet**, and why: the operations, paths and audiences
// `bot/lib/service.mjs` and `bot/lib/oidc.mjs` compile are already compared
// with the file in `bot/tests/service.test.mjs`; the FLOW-13 table is held to
// `tools/codes-table.json` in `tools/selftest/contract-tokens.mjs`; the work
// answer's members two ways in `bot/tests/moderation-run.test.mjs`. A second
// copy of each would be a second answer. `fixed_reasons` needs no value
// comparison: `bot/lib/compile-decision.mjs` reads the strings OUT of the token
// file rather than keeping its own.
//
// **Known gaps are rows, and each row expires.** A gap the registry cannot
// close in this commit is sheltered by a row naming who closes it and until
// when: a mis-attribution until the contract version moves (the row applies
// only at the version it was found at), an unemitted code until R3's exit
// marker is on the tree. A row whose gap has closed is itself a failure, so
// a row never outlives its reason and shelters the next gap.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { cleanEnv } from "../lib/git-env.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { CODES } from "../../bot/lib/codes.mjs";
import { test, assert, assertEqual } from "./harness.mjs";

const TOKEN_FILE = "schema/contract-tokens-v1.json";
const OURS = ["registry", "bot"];

/** The gaps known on 2026-09-24, each with who closes it and until when. */
//
// **The two `misattributed` rows went red once already, as designed.** Contract
// 2.4.0 regenerated the token file without the generator fix, the rows stopped
// sheltering, and `Registry index` went red on `main` at `858b238`. They were
// moved to 2.4.0 the same hour, and contract 2.5.0, which carries the fix,
// deleted them: a row whose gap has closed is itself a failure (below).
export const KNOWN = Object.freeze({
  // `wait:W_OPERATOR_WINDOW` and `wait:W_ALERT_UNDELIVERED` were rows here,
  // misattributed through contract 2.4.0: the generator's 80-character
  // lookahead gave both to the service. Contract 2.5.0's generator reads each
  // wait's own annotation and gives both to the registry, so the rows went
  // with the file that no longer needs them.
  "wait:W_LEASE_EXPIRED": {
    gap: "unemitted",
    due: "R3",
    closes: "the service-path results (registry plan B-T3.5): nothing here reports a lease the service expired",
  },
  "wait:W_MODERATION_HOLD": {
    gap: "unemitted",
    due: "R3",
    closes: "the moderation run's `report` job (M-T3.4, BOT-81), a placeholder until the R3-open commit",
  },
  "code:B_BINDING_INVALID": {
    gap: "unemitted",
    due: "R3",
    closes: "ID-9's panel-only details under B_BINDING_UNUSABLE (registry plan B-T3.3a)",
  },
  "code:B_ACCOUNT_INELIGIBLE": {
    gap: "unemitted",
    due: "R3",
    closes: "ID-9's panel-only details under B_BINDING_UNUSABLE (registry plan B-T3.3a)",
  },
});

const tracked = (root) =>
  execFileSync("git", ["-C", root, "ls-files", "-z"], { encoding: "utf8", env: cleanEnv(), maxBuffer: 64 * 1024 * 1024 })
    .split("\0").filter(Boolean);

/** The bot's code: every tracked module under `bot/` and `tools/lib/`, tests and fixtures excluded. */
export function botSources(root = REPO_ROOT) {
  return tracked(root)
    .filter((f) => /\.mjs$/.test(f) && (f.startsWith("bot/") || f.startsWith("tools/lib/")))
    .filter((f) => !f.startsWith("bot/tests/") && !f.startsWith("bot/fixtures/"))
    .map((f) => ({ file: f, text: fs.readFileSync(path.join(root, f), "utf8") }));
}

/** The waits the bot SENDS: every shape a wait is composed in, and the golden bodies. */
export function sentWaits(root = REPO_ROOT, sources = botSources(root)) {
  const warn = new Set(Object.entries(CODES).filter(([, d]) => d.level !== "wait").map(([c]) => c));
  const out = new Map();
  const add = (code, where) => {
    if (warn.has(code)) return; // a warn-level check finding, not a wait (B.7: "Warn-level `W_*` findings are not waits")
    if (!out.has(code)) out.set(code, []);
    out.get(code).push(where);
  };
  const SHAPES = [
    /waitPlan\(\s*"(W_[A-Z0-9_]+)"/g,
    /\bcode:\s*"(W_[A-Z0-9_]+)"/g,
    /\.code\s*=\s*"(W_[A-Z0-9_]+)"/g,
  ];
  for (const { file, text } of sources) {
    for (const re of SHAPES) {
      for (const m of text.matchAll(re)) {
        // A finding composed inline with `level: "warn"` beside its code is a
        // check result, not a wait (`bot/lib/derive.mjs`'s W_ICON_DROPPED).
        if (/level:\s*"warn"/.test(text.slice(Math.max(0, m.index - 120), m.index))) continue;
        add(m[1], `${file}:${text.slice(0, m.index).split("\n").length}`);
      }
    }
  }
  const goldens = path.join(root, "tests", "results");
  if (fs.existsSync(goldens)) {
    for (const g of fs.readdirSync(goldens).filter((n) => n.endsWith(".json")).sort()) {
      const body = JSON.parse(fs.readFileSync(path.join(goldens, g), "utf8"));
      if (typeof body?.wait?.code === "string") add(body.wait.code, `tests/results/${g}`);
    }
  }
  return out;
}

const exitedSteps = (root) => new Set(tracked(root)
  .map((f) => /^log\/rollout\/([A-Za-z0-9]+)-exit\.json$/.exec(f)?.[1]).filter(Boolean));

/** Is this entry's state one the registry must honour today? */
function inForce(entry, exited) {
  if (entry.state === "live") return true;
  const until = /^until (R[0-9]+[ab]?)$/.exec(entry.state ?? "");
  return until ? !exited.has(until[1]) : false;
}

/** Does this row shelter this entry, today? */
function sheltered(id, token, exited) {
  const row = KNOWN[id];
  if (!row) return null;
  if (row.through !== undefined && row.through !== token.contract_version) return null;
  if (row.due !== undefined && exited.has(row.due)) return null;
  return row;
}

export async function run() {
  console.log("\nSCOPE-9: the token file's parties against what the bot sends (RC-R3-2)");

  const root = REPO_ROOT;
  const token = JSON.parse(fs.readFileSync(path.join(root, TOKEN_FILE), "utf8"));
  const entries = [...(token.entries ?? []), ...(token.service_only ?? [])];
  const exited = exitedSteps(root);
  const sources = botSources(root);
  const byName = new Map(entries.filter((e) => e.kind === "wait" || e.kind === "reason_code").map((e) => [e.name, e]));
  const ours = (e) => (e.emitter ?? []).some((p) => OURS.includes(p));
  const stale = [];

  await test("every wait the bot sends is a wait the token file gives to the registry", () => {
    const sent = sentWaits(root, sources);
    assert(sent.size >= 6, `the bot was read as sending ${sent.size} wait(s), and it sent 6 on 2026-09-24; a scan that ` +
      "finds fewer has stopped reading the shapes waits are composed in");
    const problems = [];
    for (const [code, where] of [...sent].sort()) {
      const id = `wait:${code}`;
      const entry = byName.get(code);
      const fault = !entry || entry.kind !== "wait"
        ? `${code} is not a wait the token file lists`
        : !ours(entry)
          ? `${code} is listed with emitter ${JSON.stringify(entry.emitter)}, and the bot sends it`
          : null;
      const row = sheltered(id, token, exited);
      if (fault && row) continue;
      if (!fault && KNOWN[id]?.gap === "misattributed") stale.push(id);
      if (fault) problems.push(`${fault} (${where.slice(0, 3).join(", ")})`);
    }
    assertEqual(problems.join("\n"), "",
      "the bot sends a wait the token file does not give to the registry, so the service's half — built from the " +
      "file — reads it as another party's, or as nobody's (SCOPE-8, SCOPE-9)");
  });

  await test("every code and wait the token file gives to the registry is one the bot's code carries", () => {
    const listed = entries.filter((e) => (e.kind === "wait" || e.kind === "reason_code") && ours(e) && inForce(e, exited));
    assert(listed.length >= 20, `the token file gives the registry ${listed.length} code(s) and wait(s) in force, and ` +
      "gave it 30 at contract 2.3.0; a filter that matched nothing would compare nothing");
    const problems = [];
    for (const e of listed) {
      const quoted = new RegExp(`["'\`]${e.name}["'\`]`);
      const found = sources.some(({ text }) => quoted.test(text));
      const id = `${e.kind === "wait" ? "wait" : "code"}:${e.name}`;
      const row = sheltered(id, token, exited);
      if (!found && row) continue;
      if (found && KNOWN[id]?.gap === "unemitted") stale.push(id);
      if (!found) problems.push(`${e.name} (${e.kind}, ${e.state}) appears in no module under bot/ or tools/lib/`);
    }
    assertEqual(problems.join("\n"), "",
      "the token file tells the service the registry emits these, and nothing here does: a listed code nothing " +
      "emits is a promise the panel renders and the bot never keeps (SCOPE-9)");
  });

  await test("a known gap's row goes the moment its gap closes, and no row names a gap that is not one", () => {
    for (const id of Object.keys(KNOWN)) {
      const [kind, name] = id.split(":");
      const entry = byName.get(name);
      assert(entry && entry.kind === (kind === "wait" ? "wait" : "reason_code"),
        `KNOWN names ${id}, which the token file does not list as a ${kind === "wait" ? "wait" : "reason code"}`);
    }
    assertEqual([...new Set(stale)].sort().join(", "), "",
      "these rows shelter a gap that has closed; delete them, or the next gap of the same shape hides behind them");
  });

  await test("no entry naming the registry or the bot is service-only, and no service-only entry names either", () => {
    const problems = [];
    for (const e of entries) {
      const parties = [...(e.emitter ?? []), ...(e.acceptor ?? [])];
      const namesOurs = parties.some((p) => OURS.includes(p));
      if (e.state === "service-only" && namesOurs) problems.push(`${e.id} is service-only and names ${parties.join(", ")}`);
    }
    assert((token.service_only ?? []).length >= 1, "the token file carries no service_only list, so this proves nothing");
    assertEqual(problems.join("\n"), "",
      "an entry the registry or the bot is a party to is marked service-only, so SCOPE-9 would skip exactly the " +
      "case worth failing on (n12)");
  });

  await test("a reserved entry is referenced by no bot module", () => {
    const reserved = entries.filter((e) => e.state === "reserved");
    assert(reserved.length >= 1, "no reserved entry in the token file; astra.plugins.card/1 was one at 2.3.0");
    const problems = [];
    for (const e of reserved) {
      for (const { file, text } of sources) if (text.includes(e.name)) problems.push(`${file} names ${e.name}`);
    }
    assertEqual(problems.join("\n"), "", "SCOPE-8: a reserved entry is neither required nor allowed");
  });
}
