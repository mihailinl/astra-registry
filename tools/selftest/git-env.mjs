// No git command in this repository can act on a repository it did not name
// (astra-plugins-ops `dev/couplings.md` entries 142 and 143).
//
// **What went wrong, and where.** git exports `GIT_DIR` to a hook, to a
// `rebase -x` command and to a `!` alias — from a worktree, an ABSOLUTE path
// to the worktree's gitdir, whose `config` and `refs/heads` are the shared
// repository's — and a child git obeys it over its `cwd` and over `-C`. On
// 2026-09-23 a fixture builder run from astra-plugins-ops' pre-push hook made
// that repository's shared checkout bare and moved its `main`. Measured here
// the same day: all 93 git spawns in this repository inherited the caller's
// environment, and seven bot suites run under a hook-shaped `GIT_DIR` wrote
// `core.bare = true`, a user and a fetch refspec into the repository it named,
// moved its `main` and `side`, created five branches and re-pointed its
// worktree's HEAD. `node tools/selftest.mjs` refused first only because its
// workflow walk read that repository and found no workflows.
//
// **What holds it now.** Every git spawn takes `cleanEnv()`, or for a fixture
// `fixtureEnv(dir)` (tools/lib/git-env.mjs); the runner drops the variables
// before any case runs; and `bot/tests/workflows.test.mjs` runs every
// fixture-building suite, and this suite, under a hook's environment naming a
// throwaway repository that must come out byte-identical. This module holds
// the first of those, by reading source:
//
//   * every call of `execFileSync`, `spawnSync`, `execSync`, `spawn`,
//     `execFile` or `exec` whose first argument is the literal "git" (or a
//     literal command starting "git ") in a tracked `.mjs`, `.cjs` or `.js`
//     file passes an options object literal whose `env` is `cleanEnv()`,
//     `fixtureEnv(…)`, an object literal whose first member spreads one of
//     those, or a conditional between such;
//   * after that first member an env object spreads only object literals (or
//     a conditional between them) that the sweep can read, and none of it
//     sets `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`,
//     `GIT_OBJECT_DIRECTORY` or `GIT_ALTERNATE_OBJECT_DIRECTORIES` back — a
//     `GIT_INDEX_FILE` the code chose is allowed, the signer commits that way;
//   * the options object spreads only readable literals with no `env` in them,
//     so nothing a caller passes can put an environment back;
//   * a spawn that inherits on purpose says so directly above it, as
//     `// git-env: inherits on purpose — <why>`, and each one is printed;
//   * fewer spawns than FLOOR is red: a reader that stopped matching them would
//     otherwise read as a clean tree.
//
// Strings, template literals, comments and regular expressions are read as
// such, so a stand-in quoted in a test is not a spawn. **What it does not
// see:** a git spawned any other way — a variable holding "git", `sh -c`, a
// tool that runs git for itself. The runner's drop and the hostile run in
// `bot/tests/workflows.test.mjs` are what hold for those.
//
// It imports only modules inside TRUST-31's set and reads every other file as
// bytes, so it adds nothing to what the publish path executes.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { REPO_ROOT } from "../lib/sources.mjs";
import { cleanEnv, fixtureEnv, repositoryVars } from "../lib/git-env.mjs";
import { test, assert, assertEqual, tmp, walkRepo } from "./harness.mjs";

// Git spawns in the tracked tree on 2026-09-23, once every one of them had
// been given a clean environment: 96 — the 93 that inherited, and this
// module's three (git's list of variables, and the ceiling's two). A floor and not an equality: a new spawn needs no edit here, and a
// change that removes spawns lowers this in the same commit and says why.
const FLOOR = 96;

const MARK = /git-env: inherits on purpose — (\S.{9,})/;
const SPAWNERS = ["execFileSync", "spawnSync", "execSync", "execFile", "spawn", "exec"];
const COMMAND_FORM = new Set(["execSync", "exec"]);
const METHOD_OK = new Set(["execFileSync", "spawnSync", "execSync"]);
const REFUSED = new Set(["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"]);

// ── reading source ──────────────────────────────────────────────────────────

/**
 * `src` with the insides of strings, template literals and regular
 * expressions blanked (their delimiters kept) and comments blanked whole,
 * newlines kept, so brackets and calls can be read positionally. Offsets are
 * the original's.
 */
export function mask(src) {
  const out = src.split("");
  const n = src.length;
  const blank = (a, b) => { for (let k = a; k < b && k < n; k++) if (out[k] !== "\n") out[k] = " "; };
  const KEYWORDS = new Set(["return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw",
    "yield", "await", "instanceof"]);

  // Returns the index just past what it consumed; `untilBrace` stops at the
  // `}` that closes a template expression and returns its index.
  function code(i, untilBrace) {
    let depth = 0;
    let prev = "";
    let prevWord = "";
    while (i < n) {
      const c = src[i];
      const d = src[i + 1];
      if (c === "/" && d === "/") {
        const e = src.indexOf("\n", i);
        const end = e < 0 ? n : e;
        blank(i, end);
        i = end;
        continue;
      }
      if (c === "/" && d === "*") {
        const e = src.indexOf("*/", i + 2);
        const end = e < 0 ? n : e + 2;
        blank(i, end);
        i = end;
        continue;
      }
      if (c === '"' || c === "'") {
        let j = i + 1;
        while (j < n && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
        blank(i + 1, j);
        i = j + 1;
        prev = c;
        prevWord = "";
        continue;
      }
      if (c === "`") {
        let j = i + 1;
        while (j < n && src[j] !== "`") {
          if (src[j] === "\\") { j += 2; continue; }
          if (src[j] === "$" && src[j + 1] === "{") { j = code(j + 2, true) + 1; continue; }
          j++;
        }
        blank(i + 1, j);
        i = j + 1;
        prev = "`";
        prevWord = "";
        continue;
      }
      if (c === "/") {
        const regexHere = prev === "" || "(,=:[!&|?{};+-*%<>~^}".includes(prev) || KEYWORDS.has(prevWord);
        if (regexHere) {
          let j = i + 1;
          let cls = false;
          let ok = false;
          while (j < n && src[j] !== "\n") {
            if (src[j] === "\\") { j += 2; continue; }
            if (src[j] === "[") cls = true;
            else if (src[j] === "]") cls = false;
            else if (src[j] === "/" && !cls) { ok = true; break; }
            j++;
          }
          if (ok) {
            blank(i + 1, j);
            i = j + 1;
            while (i < n && /[a-z]/i.test(src[i])) i++;
            prev = "/";
            prevWord = "";
            continue;
          }
        }
      }
      if (c === "{") depth++;
      if (c === "}") {
        if (untilBrace && depth === 0) return i;
        depth--;
      }
      if (/[A-Za-z0-9_$]/.test(c)) {
        let j = i;
        while (j < n && /[A-Za-z0-9_$]/.test(src[j])) j++;
        prevWord = src.slice(i, j);
        prev = "a";
        i = j;
        continue;
      }
      if (!/\s/.test(c)) { prev = c; prevWord = ""; }
      i++;
    }
    return n;
  }
  code(0, false);
  return out.join("");
}

const OPEN = { "(": ")", "[": "]", "{": "}" };
const CLOSE = new Set([")", "]", "}"]);

/** Index of the bracket closing the one at `at` in masked text, or -1. */
function closing(m, at) {
  const stack = [];
  for (let i = at; i < m.length; i++) {
    const c = m[i];
    if (OPEN[c]) stack.push(OPEN[c]);
    else if (CLOSE.has(c)) {
      if (stack.pop() !== c) return -1;
      if (!stack.length) return i;
    }
  }
  return -1;
}

/** Top-level pieces of masked `m` in `[from, to)`, split on `sep`, as spans. */
function split(m, from, to, sep = ",") {
  const pieces = [];
  let depth = 0;
  let start = from;
  for (let i = from; i < to; i++) {
    const c = m[i];
    if (OPEN[c]) depth++;
    else if (CLOSE.has(c)) depth--;
    else if (c === sep && depth === 0) { pieces.push([start, i]); start = i + 1; }
  }
  pieces.push([start, to]);
  return pieces.filter(([a, b]) => m.slice(a, b).trim() !== "");
}

const trimSpan = (m, [a, b]) => {
  while (a < b && /\s/.test(m[a])) a++;
  while (b > a && /\s/.test(m[b - 1])) b--;
  return [a, b];
};

/** `[a, b)` without enclosing parentheses. */
function unparen(m, [a, b]) {
  for (;;) {
    [a, b] = trimSpan(m, [a, b]);
    if (m[a] === "(" && closing(m, a) === b - 1) { a++; b--; continue; }
    return [a, b];
  }
}

/** The top-level `c ? x : y` in `[a, b)`, as `[x, y]` spans, or null. */
function ternary(m, [a, b]) {
  const q = (i) => m[i] === "?" && m[i + 1] !== "." && m[i + 1] !== "?" && m[i - 1] !== "?";
  let depth = 0;
  for (let i = a; i < b; i++) {
    const c = m[i];
    if (OPEN[c]) depth++;
    else if (CLOSE.has(c)) depth--;
    else if (depth === 0 && q(i)) {
      let nested = 0;
      let d2 = 0;
      for (let j = i + 1; j < b; j++) {
        const cj = m[j];
        if (OPEN[cj]) d2++;
        else if (CLOSE.has(cj)) d2--;
        else if (d2 === 0 && q(j)) nested++;
        else if (d2 === 0 && cj === ":") {
          if (nested) { nested--; continue; }
          return [[i + 1, j], [j + 1, b]];
        }
      }
      return null;
    }
  }
  return null;
}

const keyOf = (m, src, entry) => src.slice(...trimSpan(m, split(m, entry[0], entry[1], ":")[0])).replace(/^["'`]|["'`]$/g, "");

/**
 * Why the spread operand at `[a, b)` is not an object literal (or a
 * conditional between them) that sets none of `forbidden`, or null.
 */
function literalProblem(m, src, span, forbidden, what) {
  const [a, b] = unparen(m, span);
  const t = ternary(m, [a, b]);
  if (t) return literalProblem(m, src, t[0], forbidden, what) ?? literalProblem(m, src, t[1], forbidden, what);
  if (m[a] !== "{" || closing(m, a) !== b - 1) {
    return `${what} spreads ${src.slice(a, b).replace(/\s+/g, " ").slice(0, 60)}, which this sweep cannot read`;
  }
  for (const e of split(m, a + 1, b - 1).map((s) => trimSpan(m, s))) {
    if (/^\.\.\./.test(m.slice(...e))) {
      const inner = literalProblem(m, src, [e[0] + 3, e[1]], forbidden, what);
      if (inner) return inner;
      continue;
    }
    const key = keyOf(m, src, e);
    if (forbidden.has(key)) return `${what} sets ${key}, ${forbidden === REFUSED ? "which names a repository" : "which can bring any environment back"}`;
  }
  return null;
}

/** Whether `[a, b)` is exactly one call to a clean helper. */
function isHelper(m, [a, b]) {
  const text = m.slice(a, b);
  if (/^cleanEnv\s*\(\s*\)$/.test(text)) return true;
  const h = /^fixtureEnv\s*\(/.exec(text);
  return Boolean(h) && closing(m, a + h[0].length - 1) === b - 1;
}

/** Why the `env` value at `[a, b)` is not a clean environment, or null. */
function envProblem(m, src, span) {
  const [a, b] = unparen(m, span);
  if (isHelper(m, [a, b])) return null;
  const t = ternary(m, [a, b]);
  if (t) return envProblem(m, src, t[0]) ?? envProblem(m, src, t[1]);
  if (m[a] === "{" && closing(m, a) === b - 1) {
    const [first, ...rest] = split(m, a + 1, b - 1).map((s) => trimSpan(m, s));
    if (!first || !/^\.\.\./.test(m.slice(...first))) {
      return "its env object does not start by spreading cleanEnv() or fixtureEnv()";
    }
    const base = trimSpan(m, [first[0] + 3, first[1]]);
    if (!isHelper(m, base)) return `its env object spreads ${src.slice(...base)}, not cleanEnv() or fixtureEnv()`;
    for (const e of rest) {
      if (/^\.\.\./.test(m.slice(...e))) {
        const p = literalProblem(m, src, [e[0] + 3, e[1]], REFUSED, "its env object");
        if (p) return p;
        continue;
      }
      const key = keyOf(m, src, e);
      if (REFUSED.has(key)) return `its env object sets ${key} back, which names a repository`;
    }
    return null;
  }
  return `its env is ${src.slice(a, b).replace(/\s+/g, " ").slice(0, 80)}, not cleanEnv() or fixtureEnv()`;
}

/** Every git spawn in one file's source: `{ line, fn, ok, problem, mark }`. */
export function spawnsIn(src) {
  const m = mask(src);
  const lines = src.split("\n");
  const lineAt = (i) => src.slice(0, i).split("\n").length;
  const found = [];
  const re = new RegExp(`(?<![\\w$])(${SPAWNERS.join("|")})\\s*\\(`, "g");
  let hit;
  while ((hit = re.exec(m))) {
    const fn = hit[1];
    if (hit.index > 0 && m[hit.index - 1] === "." && !METHOD_OK.has(fn)) continue;
    const paren = hit.index + hit[0].length - 1;
    let q = paren + 1;
    while (q < m.length && /\s/.test(m[q])) q++;
    const quote = src[q];
    if (!["\"", "'", "`"].includes(quote)) continue;
    let e = q + 1;
    while (e < src.length && src[e] !== quote) e += src[e] === "\\" ? 2 : 1;
    const literal = src.slice(q + 1, e);
    const command = COMMAND_FORM.has(fn) && /^git(\s|$)/.test(literal);
    if (literal !== "git" && !command) continue;

    const line = lineAt(hit.index);
    let mark = null;
    for (let k = line - 2; k >= 0 && /^\s*\/\//.test(lines[k]); k--) {
      const mm = MARK.exec(lines[k]);
      if (mm) {
        const more = [];
        for (let j = k + 1; j < line - 1; j++) more.push(lines[j].replace(/^\s*\/\/\s?/, ""));
        mark = [mm[1], ...more].join(" ").trim();
        break;
      }
    }
    const record = (problem) => found.push({ line, fn, ok: !problem, problem, mark });
    if (mark) { record(null); continue; }

    const close = closing(m, paren);
    if (close < 0) { record("its call does not close where this reader can see it"); continue; }
    const args = split(m, paren + 1, close).map((s) => trimSpan(m, s));
    const opt = command ? args[1] : (args[1] && m[args[1][0]] === "{" ? args[1] : args[2]);
    if (!opt) { record("it passes no options, so git inherits every variable this process has"); continue; }
    if (m[opt[0]] !== "{" || closing(m, opt[0]) !== opt[1] - 1) {
      record(`its options are ${src.slice(...opt).replace(/\s+/g, " ").slice(0, 60)}, not an object literal this sweep can read`);
      continue;
    }
    const entries = split(m, opt[0] + 1, opt[1] - 1).map((s) => trimSpan(m, s));
    let problem = null;
    for (const s of entries.filter((x) => /^\.\.\./.test(m.slice(...x)))) {
      problem ??= literalProblem(m, src, [s[0] + 3, s[1]], new Set(["env"]), "its options object");
    }
    if (problem) { record(problem); continue; }
    const envs = entries.filter((s) => !/^\.\.\./.test(m.slice(...s)) && keyOf(m, src, s) === "env");
    if (envs.length !== 1) {
      record(envs.length ? "its options name env more than once" :
        "its options name no env, so git inherits every variable this process has");
      continue;
    }
    const parts = split(m, envs[0][0], envs[0][1], ":");
    if (parts.length < 2) { record("its env is shorthand for a variable this sweep cannot read"); continue; }
    record(envProblem(m, src, [parts[1][0], envs[0][1]]));
  }
  return found;
}

/** The sweep over `[{ rel, text }]`. */
export function sweep(sources) {
  const spawns = [];
  const unreadable = [];
  for (const { rel, text } of sources) {
    const m = mask(text);
    const count = (ch) => m.split(ch).length - 1;
    if (count("(") !== count(")") || count("[") !== count("]") || count("{") !== count("}")) {
      unreadable.push(rel);
      continue;
    }
    for (const s of spawnsIn(text)) spawns.push({ rel, ...s });
  }
  return { spawns, unreadable, files: sources.length };
}

/** Every tracked script, as text. */
function trackedScripts() {
  return walkRepo()
    .map((abs) => path.relative(REPO_ROOT, abs).split(path.sep).join("/"))
    .filter((rel) => /\.(mjs|cjs|js)$/.test(rel))
    .map((rel) => ({ rel, text: fs.readFileSync(path.join(REPO_ROOT, rel), "utf8") }));
}

// ── the cases ───────────────────────────────────────────────────────────────

const CASES = [
  ["clean", "env: cleanEnv()", 'execFileSync("git", ["-C", d, "status"], { encoding: "utf8", env: cleanEnv() });'],
  ["clean", "env: fixtureEnv(dir), with a comment before it", "execFileSync('git', ['init'], {\n  stdio: 'ignore',\n  // a fixture\n  env: fixtureEnv(dir),\n});"],
  ["clean", "an env object spreading cleanEnv() first, with dates", 'spawnSync("git", a, { env: { ...cleanEnv(), GIT_AUTHOR_DATE: d } })'],
  ["clean", "a conditional between a dated fixture env and a bare one", 'execFileSync("git", a, { env: at ? { ...fixtureEnv(dir), GIT_COMMITTER_DATE: at } : fixtureEnv(dir) })'],
  ["clean", "a GIT_INDEX_FILE the code chose, and a readable spread of an identity", 'execFileSync("git", a, { env: { ...cleanEnv(), GIT_INDEX_FILE: f, ...(who ? { GIT_AUTHOR_NAME: who.name } : {}) } })'],
  ["clean", "an options spread of a literal with no env in it", 'execFileSync("git", a, { encoding: "utf8", ...(stdio === undefined ? {} : { stdio }), env: cleanEnv() })'],
  ["clean", "a command-form execSync", 'execSync("git status", { env: cleanEnv() })'],
  ["clean", "wrapped in String(), with a `)` inside a string argument", 'String(execFileSync("git", ["log", "--format=)"], { env: cleanEnv() }))'],
  ["red", "no options at all", 'execFileSync("git", ["status"])', "passes no options"],
  ["red", "options with no env", 'execFileSync("git", ["status"], { encoding: "utf8" })', "name no env"],
  ["red", "env: process.env", 'execFileSync("git", ["status"], { env: process.env })', "not cleanEnv() or fixtureEnv()"],
  ["red", "an env object spreading process.env", 'execFileSync("git", ["status"], { env: { ...process.env, X: 1 } })', "spreads process.env"],
  ["red", "a clean env, then an options spread of a variable", 'execFileSync("git", ["status"], { env: cleanEnv(), ...opts })', "cannot read"],
  ["red", "an options spread of a literal carrying env", 'execFileSync("git", a, { ...(x ? { env: process.env } : {}), encoding: "utf8" })', "sets env"],
  ["red", "a clean env object with GIT_DIR set back", 'execFileSync("git", a, { env: { ...cleanEnv(), GIT_DIR: g } })', "sets GIT_DIR back"],
  ["red", "a clean env object spreading a variable after its base", 'execFileSync("git", a, { env: { ...cleanEnv(), ...extra } })', "cannot read"],
  ["red", "a readable spread that sets GIT_WORK_TREE", 'execFileSync("git", a, { env: { ...cleanEnv(), ...(w ? { GIT_WORK_TREE: w } : {}) } })', "sets GIT_WORK_TREE"],
  ["red", "a conditional with one inheriting branch", 'execFileSync("git", a, { env: c ? cleanEnv() : process.env })', "not cleanEnv()"],
  ["red", "cleanEnv with an argument", 'execFileSync("git", a, { env: cleanEnv(x) })', "not cleanEnv() or fixtureEnv()"],
  ["red", "options held in a variable", 'execFileSync("git", a, opts)', "not an object literal"],
  ["red", "a command-form execSync with no env", 'execSync("git log", { encoding: "utf8" })', "name no env"],
];

// A committed spawn, broken in place: the sweep must say which line. This is
// the fixture builder of the takedown bound's suite, one of the seven that
// wrote into a hook's repository on 2026-09-23.
const BROKEN = {
  rel: "bot/tests/takedown-bound.test.mjs",
  needle: 'const g = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: fixtureEnv(dir) });',
  broken: 'const g = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" });',
};

export async function run() {
  console.log("\nno git command acts on a repository it did not name (ops couplings 142, 143)");

  await test("every git spawn in the tree names a clean environment, and the sweep found at least its floor", () => {
    const r = sweep(trackedScripts());
    assertEqual(r.unreadable.join(", "), "", "a tracked script's brackets do not balance once strings and comments " +
      "are set aside, so its spawns were not read");
    const red = r.spawns.filter((s) => !s.ok);
    assertEqual(red.map((s) => `${s.rel}:${s.line} ${s.problem}`).join("\n"), "",
      "a git spawn takes an environment that can name another repository. Pass env: cleanEnv(), or " +
      "fixtureEnv(dir) for a fixture (tools/lib/git-env.mjs)");
    assert(r.spawns.length >= FLOOR, `the sweep found ${r.spawns.length} git spawn(s) in ${r.files} tracked script(s) ` +
      `and there were ${FLOOR} on 2026-09-23: either spawns were removed (lower FLOOR in tools/selftest/git-env.mjs, ` +
      "saying why) or this reader stopped matching them, and every assertion above would pass about nothing");
    for (const s of r.spawns.filter((x) => x.mark)) console.log(`        inherits on purpose: ${s.rel}:${s.line} — ${s.mark}`);
  });

  await test("each clause of the sweep is red on its own case, and each clean form is clean", () => {
    const wrong = [];
    for (const [want, name, src, why] of CASES) {
      const r = spawnsIn(src);
      if (r.length !== 1) { wrong.push(`${name}: ${r.length} spawn(s) read`); continue; }
      if ((want === "clean") !== r[0].ok) wrong.push(`${name}: ${r[0].ok ? "clean" : `red (${r[0].problem})`}, wanted ${want}`);
      else if (want === "red" && !r[0].problem.includes(why)) wrong.push(`${name}: red for "${r[0].problem}", not "${why}"`);
    }
    assertEqual(wrong.join("\n"), "", "the sweep judged a case wrongly");
  });

  await test("a spawn quoted in a string, a template, a comment or a regex is not a spawn", () => {
    const src = [
      'const s = "execFileSync(\\"git\\", [])";',
      '// execFileSync("git", ["status"])',
      "/* spawnSync(\"git\", []) */",
      "const t = `spawnSync(\"git\", [${x}])`;",
      'const re = /execFileSync\\("git"/;',
      'const m = /^git/.exec("git status");',
    ].join("\n");
    const r = spawnsIn(src);
    assertEqual(r.length, 0, `read spawn(s) out of quoted text: ${JSON.stringify(r)}`);
  });

  await test("a mark with its reason excuses a spawn and is printed; a bare or detached mark does not", () => {
    const marked = spawnsIn('// git-env: inherits on purpose — shown hostile, and it only reads\nexecFileSync("git", ["status"]);');
    assert(marked.length === 1 && marked[0].ok && /shown hostile/.test(marked[0].mark), JSON.stringify(marked));
    const bare = spawnsIn('// git-env: inherits on purpose — \nexecFileSync("git", ["status"]);');
    assert(bare.length === 1 && !bare[0].ok, `a mark with no reason excused a spawn: ${JSON.stringify(bare)}`);
    const far = spawnsIn('// git-env: inherits on purpose — a reason long enough\n\nexecFileSync("git", ["status"]);');
    assert(far.length === 1 && !far[0].ok, "a mark separated from its spawn by a blank line excused it");
  });

  await test("a committed fixture builder with its env removed is red, at its own line", () => {
    const sources = trackedScripts();
    const file = sources.find((s) => s.rel === BROKEN.rel);
    assert(file, `${BROKEN.rel} is not tracked`);
    assertEqual(file.text.split(BROKEN.needle).length, 2, `the needle is not in ${BROKEN.rel} exactly once`);
    const broken = file.text.replace(BROKEN.needle, () => BROKEN.broken);
    assert(broken !== file.text, "the mutation changed nothing");
    const line = file.text.slice(0, file.text.indexOf(BROKEN.needle)).split("\n").length;
    const red = sweep(sources.map((s) => (s === file ? { rel: s.rel, text: broken } : s))).spawns.filter((s) => !s.ok);
    assert(red.length === 1 && red[0].rel === BROKEN.rel && red[0].line === line && /name no env/.test(red[0].problem),
      `the builder broken at ${BROKEN.rel}:${line} came back as ${JSON.stringify(red)}`);
  });

  await test("cleanEnv and fixtureEnv drop every variable git lists and the hook's six; fixtureEnv sets a ceiling", () => {
    const vars = repositoryVars();
    // The list is typed (tools/lib/git-env.mjs says why), so it is held here to
    // the git this suite runs under: a variable git names that the list lacks
    // is one an inherited environment could still carry into every command.
    const listed = execFileSync("git", ["rev-parse", "--local-env-vars"], { encoding: "utf8", env: cleanEnv() })
      .split("\n").map((s) => s.trim()).filter(Boolean);
    assert(listed.includes("GIT_DIR"), `git rev-parse --local-env-vars printed ${JSON.stringify(listed)}, which is not the list`);
    assertEqual(listed.filter((v) => !vars.includes(v)).join(", "), "",
      "the git this suite runs under names a repository variable REPOSITORY_VARS in tools/lib/git-env.mjs lacks");
    for (const v of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
      "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR"]) {
      assert(vars.includes(v), `${v} is not in the set dropped`);
    }
    const saved = { ...process.env };
    const dir = fs.mkdtempSync(path.join(tmp, "git-env-vars-"));
    try {
      for (const v of vars) process.env[v] = "/nowhere/at/all";
      for (const [name, env] of [["cleanEnv", cleanEnv()], ["fixtureEnv", fixtureEnv(dir)]]) {
        const kept = vars.filter((v) => v in env);
        assertEqual(kept.join(", "), "", `${name} kept a variable that names a repository`);
      }
      assertEqual(fixtureEnv(dir).GIT_CEILING_DIRECTORIES, path.dirname(fs.realpathSync(dir)),
        "fixtureEnv's ceiling is not the fixture's parent");
      assertEqual(fixtureEnv(path.join(dir, "not-yet")).GIT_CEILING_DIRECTORIES, fs.realpathSync(dir),
        "a clone target that does not exist yet did not get its parent as the ceiling");
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  });

  await test("the ceiling: inside a repository, a directory resolves to it under cleanEnv and to nothing under fixtureEnv", () => {
    const repo = fs.mkdtempSync(path.join(tmp, "git-env-ceiling-"));
    execFileSync("git", ["-C", repo, "init", "-q"], { stdio: "ignore", env: fixtureEnv(repo) });
    const sub = path.join(repo, "not-yet-a-repository");
    fs.mkdirSync(sub);
    const ask = (fixture) => {
      try {
        return execFileSync("git", ["-C", sub, "rev-parse", "--show-toplevel"], {
          encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: fixture ? fixtureEnv(sub) : cleanEnv(),
        }).trim();
      } catch (e) {
        return `refused: ${String(e.stderr).trim().split("\n")[0]}`;
      }
    };
    assertEqual(ask(false), fs.realpathSync(repo),
      "without a ceiling the directory did not resolve to the repository around it, so the case below proves nothing");
    assert(/^refused: .*not a git repository/.test(ask(true)), `with fixtureEnv it resolved: ${ask(true)}`);
  });

  await test("this run's environment names no repository: the runner dropped whatever it inherited", () => {
    const left = repositoryVars().filter((v) => v in process.env);
    assertEqual(left.join(", "), "", "a variable that names a repository reached the cases; tools/selftest.mjs drops " +
      "them before anything is asked, and every child a case starts would inherit it");
  });
}
