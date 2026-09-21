#!/usr/bin/env node
// Regenerate a catalogue's `signed` member from a pinned generator and a pinned
// set of inputs, with no credential and no network (TRUST-4, OPEN-OPS-19).
//
//   node tools/regenerate-signed.mjs --generator <reviewed sha> --source <Source-Commit>
//
// WHAT THIS ANSWERS, AND WHY IT IS NOT `build-index.mjs --check`
//
// `tools/build-index.mjs --check` asks whether the catalogue in THIS working
// tree is what the generator in THIS working tree produces. Both halves come
// from the same checkout, so it cannot answer the question a carrier has:
//
//   *I am holding a catalogue somebody signed. Does it say what the registry's
//    sources said, under the generator the registry's reviewers read?*
//
// A carrier who answers that by running the checkout's own generator has
// answered nothing: at the Source-Commit the generator is a file like any
// other, and whoever wrote the listing could have written the code that renders
// it. So the two halves are pinned SEPARATELY and taken out of the object
// store, never off the disk:
//
//   * code   — `tools/build-index.mjs`, `tools/lib/**`, `bot/lib/**` at
//              `--generator`, the commit a reviewer approved;
//   * inputs — `plugins/**` and `publishers/**` at `--source`, and nothing
//              else (INV-15).
//
// The serial is computed here, from the history behind `--source`, and is never
// read from anything the carrier hands over. A catalogue that claims serial
// N + 1 over inputs whose history says N regenerates as N and the comparison
// fails, which is the whole point: the serial is a property of the history, not
// a number a document asserts about itself.
//
// WHAT IT PRINTS
//
// `signed` minus `issued_at` and `expires_at` — `indexContent()` from the
// pinned generator, canonicalised by the pinned `stableStringify`. The two
// stripped members are properties of the PUBLICATION, not of the content: a
// generator that reads a clock cannot be reproduced, which is the same reason
// `build-index.mjs` does not stamp them.
//
// NO NETWORK, IN THREE LEGS
//
// The claim OPEN-MBE-27 needs is that a sidecar can run this with the network
// off and get the same answer. Three legs, because each catches what the others
// cannot:
//
//   (a) STATIC. The import closure from `tools/build-index.mjs` is walked
//       inside the assembled tree and refused if it reaches a network builtin,
//       a bare specifier (a dependency is anybody's code), or a dynamic
//       `import()` whose specifier is not a literal. This is the leg that
//       matters for `bot/lib/**`: the archive brings `github.mjs`, `notify.mjs`,
//       `oidc.mjs` and `probe.mjs` onto the disk — every one of them a network
//       client — and NONE of them is imported. Measured on 2026-09-21 the
//       closure is seven files. Listing the directory proves nothing; walking
//       the closure proves it.
//   (b) RUNTIME. `fetch`, `WebSocket`, `XMLHttpRequest`, `EventSource` and
//       `navigator.sendBeacon` are replaced with throwing stubs before the
//       pinned generator is imported. A call added to a reached code path fails
//       loudly instead of succeeding quietly, and it fails the same way whether
//       or not a namespace is available.
//   (c) NAMESPACE. `tools/selftest/regenerate.mjs` re-runs this command under
//       `unshare -n` when the kernel allows it. That leg needs no list of
//       names, which is why it is worth having even though it cannot run
//       everywhere.
//
// Legs (a) and (b) run on every invocation, here, so the proof is a property of
// the command rather than of the harness that happens to call it.
//
// ICONS AND READMES. A listing's picture and prose are read from the listing's
// own directory and inlined, and since BOT-79 an `https` `icon_url` in
// `plugin.json` is REFUSED rather than passed through — so there is no longer a
// field by which a signed catalogue can name a host at all. The plan entry for
// this task still describes the pass-through as live and cites the line it sat
// on; B-T2.7 has landed and `tools/build-index.mjs` now raises an error there.
// Nothing in the presentation path opens a socket either way, and leg (a)
// proves it rather than restating it.
//
// EXIT CODES. 0 the regeneration succeeded, and agreed with `--candidate` if
// one was given; 1 the candidate disagrees; 2 the command could not run — bad
// arguments, a ref that is not a commit, a tree that does not assemble, or a
// network finding. A sidecar has to be able to tell "this catalogue is wrong"
// from "I could not check", and one non-zero code cannot.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

/** The clone this file lives in, used when `--repo` is not given. */
export const DEFAULT_REPO = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/** Code, from `--generator`. */
export const GENERATOR_PATHS = ["tools/build-index.mjs", "tools/lib", "bot/lib"];
/** Inputs, from `--source`. INV-15 says these two and no others. */
export const INPUT_PATHS = ["plugins", "publishers"];
/** The one module the closure starts from. */
export const ENTRY = "tools/build-index.mjs";

// `node:inspector` is on the list because it opens a listening socket, which is
// a network capability whatever it is called.
const NETWORK_BUILTINS = new Set([
  "node:http", "node:https", "node:http2", "node:net", "node:tls",
  "node:dns", "node:dgram", "node:inspector", "node:quic",
  "http", "https", "http2", "net", "tls", "dns", "dgram", "inspector",
]);

// `tools/build-index.mjs` imports `node:child_process` for `resolveSerial`,
// which shells out to `git rev-list`. That path is not taken here — the serial
// is passed in explicitly — but the import is real, so it is allowed BY NAME
// for that one module. Any other module in the closure reaching for a
// subprocess is refused: `child_process` is the one builtin that makes every
// other entry on the deny list decorative.
const CHILD_PROCESS_ALLOWED_IN = new Set(["tools/build-index.mjs"]);

const MAX_BUFFER = 512 * 1024 * 1024;

class Refused extends Error {}

function git(repo, args, { buffer = false } = {}) {
  return execFileSync("git", ["-C", repo, ...args], {
    encoding: buffer ? "buffer" : "utf8",
    maxBuffer: MAX_BUFFER,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

/**
 * A ref to the commit it names, peeled.
 *
 * `git rev-parse v0.2.0` on an ANNOTATED tag returns the tag OBJECT's id, not
 * the commit's. `init-ci` shipped that bug: it recorded a tag object where a
 * commit belonged, every review passed, and it fell out only when somebody ran
 * the thing end to end. Here the consequence would be worse than a wrong id in
 * a file — a `Source-Commit` printed as a tag object is a value no other party
 * can resolve the same way. `^{commit}` peels, and `cat-file -t` is asked
 * afterwards rather than assumed, because a peel that silently did nothing is
 * exactly the failure being guarded.
 */
export function resolveCommit(repo, ref, what) {
  let id;
  try {
    id = git(repo, ["rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`]).trim();
  } catch (e) {
    throw new Refused(
      `--${what} ${JSON.stringify(ref)} does not name a commit in ${repo}: ${String(e.stderr || e.message).trim()}`,
    );
  }
  const type = git(repo, ["cat-file", "-t", id]).trim();
  if (type !== "commit") {
    throw new Refused(`--${what} ${JSON.stringify(ref)} resolved to a ${type} object (${id}), not a commit`);
  }
  return id;
}

function pathExistsAt(repo, commit, p) {
  try {
    git(repo, ["cat-file", "-e", `${commit}:${p}`]);
    return true;
  } catch {
    return false;
  }
}

/** Every blob path under `paths` at `commit`, sorted. The expectation an extraction is checked against. */
function treePaths(repo, commit, paths) {
  const present = paths.filter((p) => pathExistsAt(repo, commit, p));
  if (present.length === 0) return [];
  return git(repo, ["ls-tree", "-r", "--name-only", "-z", commit, "--", ...present])
    .split("\0").filter(Boolean).sort();
}

/**
 * `git archive | tar -x`, out of the object store.
 *
 * Out of the OBJECT STORE is the load-bearing half. Reading the checkout would
 * let an uncommitted file — a neighbour's experiment, a half-applied patch, a
 * stray editor backup under `plugins/` — into a document whose whole claim is
 * that it is a function of two commit ids. It would also be the quietest
 * possible failure: the output looks right, and nobody can ever regenerate it.
 */
function extractInto(repo, commit, paths, dest) {
  const present = paths.filter((p) => pathExistsAt(repo, commit, p));
  if (present.length === 0) return;
  const tarball = execFileSync("git", ["-C", repo, "archive", "--format=tar", commit, "--", ...present], {
    encoding: "buffer", maxBuffer: MAX_BUFFER, stdio: ["ignore", "pipe", "pipe"],
  });
  fs.mkdirSync(dest, { recursive: true });
  execFileSync("tar", ["-x", "-C", dest], { input: tarball, maxBuffer: MAX_BUFFER, stdio: ["pipe", "pipe", "pipe"] });
}

function walkFiles(dir, prefix = "", out = []) {
  let ents;
  try {
    ents = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) walkFiles(path.join(dir, e.name), rel, out);
    else out.push(rel);
  }
  return out;
}

/**
 * Assemble the pin, and then CHECK the assembly rather than trusting it.
 *
 * The two archives cannot overlap today — one is `tools/` and `bot/`, the other
 * `plugins/` and `publishers/` — and that is precisely the kind of fact that is
 * true until somebody moves a file. If the input archive ever wrote over a
 * generator file, the Source-Commit would be supplying the code that renders
 * it, which is the one property this command exists to deny. So both halves are
 * compared against `git ls-tree` at their own commit, by path, both directions.
 */
export function assemble({ repo, generator, source, work }) {
  fs.mkdirSync(work, { recursive: true });
  extractInto(repo, generator, GENERATOR_PATHS, work);
  const afterCode = new Set(walkFiles(work));
  extractInto(repo, source, INPUT_PATHS, work);

  const wantCode = treePaths(repo, generator, GENERATOR_PATHS);
  const wantInputs = treePaths(repo, source, INPUT_PATHS);
  if (wantInputs.length === 0) {
    throw new Refused(
      `the source commit ${source} carries neither plugins/ nor publishers/; there is nothing to regenerate from`,
    );
  }
  if (!wantCode.includes(ENTRY)) {
    throw new Refused(`the generator commit ${generator} has no ${ENTRY}`);
  }

  const onDisk = walkFiles(work);
  const got = new Set(onDisk);
  const expected = new Set([...wantCode, ...wantInputs]);
  const missing = [...expected].filter((p) => !got.has(p));
  const extra = onDisk.filter((p) => !expected.has(p));
  if (missing.length || extra.length) {
    throw new Refused(
      `the assembled tree is not the two commits' paths:${
        missing.length ? `\n  missing: ${missing.slice(0, 10).join(", ")}${missing.length > 10 ? " …" : ""}` : ""
      }${extra.length ? `\n  unexpected: ${extra.slice(0, 10).join(", ")}${extra.length > 10 ? " …" : ""}` : ""}`,
    );
  }
  // The overlap check, stated as a comparison rather than as a claim about
  // which directories the two pathspecs happen to name today.
  const clobbered = wantInputs.filter((p) => afterCode.has(p));
  if (clobbered.length) {
    throw new Refused(
      `the source commit supplies ${clobbered.join(", ")}, which the generator commit also supplies; ` +
      "inputs must never be able to replace code",
    );
  }
  // No `.git` reaches the assembled tree, and that is not tidiness: with one
  // there, `resolveSerial` would answer from whatever history it found and the
  // serial would stop being a function of `--source`. The serial is passed in
  // explicitly below, so this is the second lock on the same door.
  if (fs.existsSync(path.join(work, ".git"))) {
    throw new Refused("the assembled tree carries a .git; the serial would be read from it rather than from --source");
  }
  return { code: wantCode, inputs: wantInputs };
}

// ── leg (a): the import closure ─────────────────────────────────────────────

// Import specifiers only, which is what makes this readable without a parser.
// A comment that says the word "fetch" is not a finding and must not be
// reported as one; a comment that spells a whole `import … from "node:https"`
// would be, and that is the right way round — the false positive is loud and
// one line from being fixed, the false negative is a network client nobody saw.
const STATIC_IMPORT = /(?:^|[\s;})])import\s+(?:[^'"()]*?\sfrom\s+)?["']([^"']+)["']/gm;
const DYNAMIC_IMPORT = /\bimport\s*\(\s*(["'`]?)([^"'`)]*)/g;
const EXPORT_FROM = /(?:^|[\s;})])export\s+(?:[^'"()]*?\s)?from\s+["']([^"']+)["']/gm;

/**
 * Every module `tools/build-index.mjs` can reach inside `work`, and what it
 * reaches for.
 *
 * Returns `{ closure, findings }`. A finding is a sentence naming a file, a
 * line and the reason; the caller refuses on any.
 */
export function scanClosure(work, entry = ENTRY) {
  const closure = [];
  const findings = [];
  const seen = new Set();
  const queue = [entry];

  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    seen.add(rel);
    const abs = path.join(work, rel);
    let text;
    try {
      text = fs.readFileSync(abs, "utf8");
    } catch (e) {
      findings.push(`${rel}: imported and not readable in the assembled tree (${e.code ?? e.message})`);
      continue;
    }
    closure.push(rel);
    const lineOf = (index) => text.slice(0, index).split("\n").length;

    const specs = [];
    for (const re of [STATIC_IMPORT, EXPORT_FROM]) {
      re.lastIndex = 0;
      for (let m; (m = re.exec(text)); ) specs.push({ spec: m[1], at: m.index });
    }
    DYNAMIC_IMPORT.lastIndex = 0;
    for (let m; (m = DYNAMIC_IMPORT.exec(text)); ) {
      if (!m[1]) {
        // `import(someVariable)`. Nothing static can say where that goes, so
        // the closure below would be a claim about a program that has already
        // stopped being knowable.
        findings.push(
          `${rel}:${lineOf(m.index)}: a dynamic import whose specifier is not a literal, so the module ` +
          "closure — and every statement this command makes about it — cannot be computed",
        );
        continue;
      }
      specs.push({ spec: m[2], at: m.index });
    }

    for (const { spec, at } of specs) {
      const line = lineOf(at);
      const bare = !spec.startsWith(".") && !spec.startsWith("/") && !spec.startsWith("node:");
      if (NETWORK_BUILTINS.has(spec)) {
        findings.push(`${rel}:${line}: imports ${spec}, which is a network client`);
        continue;
      }
      if (spec === "node:child_process" || spec === "child_process") {
        if (!CHILD_PROCESS_ALLOWED_IN.has(rel)) {
          findings.push(
            `${rel}:${line}: imports ${spec}. A subprocess can reach the network by any name, so it is ` +
            `allowed only in ${[...CHILD_PROCESS_ALLOWED_IN].join(", ")}`,
          );
        }
        continue;
      }
      if (spec.startsWith("node:")) continue;
      if (bare) {
        findings.push(
          `${rel}:${line}: imports ${JSON.stringify(spec)}, a package rather than a file in this tree. ` +
          "The registry vendors nothing, and a dependency resolved at run time is code no reviewer pinned",
        );
        continue;
      }
      const target = path.relative(work, path.resolve(path.dirname(abs), spec));
      if (target.startsWith("..") || path.isAbsolute(target)) {
        findings.push(`${rel}:${line}: imports ${JSON.stringify(spec)}, which leaves the assembled tree`);
        continue;
      }
      queue.push(target.split(path.sep).join("/"));
    }
  }

  // A floor, because everything above compares lists and an empty walk agrees
  // with everything. Seven modules on 2026-09-21; three is the number below
  // which the walk has stopped working rather than the generator having got
  // smaller.
  if (closure.length < 3) {
    findings.push(
      `the closure walk from ${entry} reached ${closure.length} module(s); this is a broken walk, not a ` +
      "smaller generator, and every check above it would have passed by finding nothing",
    );
  }
  return { closure: closure.sort(), findings };
}

// ── leg (b): the network globals ────────────────────────────────────────────

/**
 * Replace every global that can open a socket with one that throws.
 *
 * Installed BEFORE the pinned generator is imported, because a module that
 * captures `fetch` at import time would otherwise keep the real one.
 */
export function refuseNetworkGlobals(target = globalThis) {
  const thrown = (name) => () => {
    throw new Error(
      `NETWORK REFUSED: the pinned generator called ${name}(). Regeneration is a function of two commit ids ` +
      "and nothing else; a fetch makes the output depend on what some host said at the moment it ran",
    );
  };
  for (const name of ["fetch", "WebSocket", "XMLHttpRequest", "EventSource"]) {
    Object.defineProperty(target, name, { value: thrown(name), configurable: true, writable: true });
  }
  if (target.navigator && typeof target.navigator === "object") {
    try {
      Object.defineProperty(target.navigator, "sendBeacon", {
        value: thrown("navigator.sendBeacon"), configurable: true, writable: true,
      });
    } catch {
      // A frozen `navigator` is fine: nothing could have replaced it either.
    }
  }
}

// ── the regeneration ────────────────────────────────────────────────────────

/**
 * The serial, from the history behind `--source` and from nowhere else.
 *
 * `resolveSerial` in the pinned generator would answer this from the tree it is
 * handed, and the assembled tree has no history at all — it would return 0,
 * deterministically and wrongly, and a catalogue carrying serial 0 looks like a
 * catalogue rather than like a bug. So the count is taken HERE, against the
 * real clone, path-limited to `plugins/` exactly as the generator does it, and
 * passed in explicitly.
 *
 * There is deliberately no `--serial` override. A carrier's document is the one
 * thing that must not be able to tell this command what its own serial is.
 */
export function serialFor(repo, source) {
  const out = git(repo, ["rev-list", "--count", source, "--", "plugins"]).trim();
  const n = Number(out);
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Refused(`the commit count for plugins/ at ${source} came back as ${JSON.stringify(out)}`);
  }
  return n;
}

export async function regenerate({ repo, generator, source, work }) {
  const commits = {
    generator: resolveCommit(repo, generator, "generator"),
    source: resolveCommit(repo, source, "source"),
  };
  const assembled = assemble({ repo, generator: commits.generator, source: commits.source, work });

  const { closure, findings } = scanClosure(work);
  if (findings.length) {
    throw new Refused(
      `the pinned generator can reach the network, so this regeneration proves nothing:\n  ${findings.join("\n  ")}`,
    );
  }

  const serial = serialFor(repo, commits.source);

  refuseNetworkGlobals();
  const gen = await import(pathToFileURL(path.join(work, ENTRY)).href);
  const canonical = await import(pathToFileURL(path.join(work, "tools/lib/canonical.mjs")).href);

  const doc = gen.buildIndex({ root: work, serial });
  if (doc?.signed?.serial !== serial) {
    throw new Refused(
      `the pinned generator wrote serial ${doc?.signed?.serial} where ${serial} was passed in; the serial in ` +
      "the output is no longer the one this command computed",
    );
  }
  const content = gen.indexContent(doc);
  if (content.issued_at !== undefined || content.expires_at !== undefined) {
    throw new Refused("the regenerated content carries a publication stamp, which no generator can reproduce");
  }
  return {
    ...commits, serial, closure, assembled, content,
    text: canonical.stableStringify(content),
    // Handed back rather than re-imported by the caller. A `--candidate` is
    // compared through the PINNED `indexContent` and the PINNED
    // `stableStringify` — the same two functions that produced the other side
    // of the comparison — and re-importing them after the assembled tree has
    // been removed would either read a cache nobody declared or quietly fall
    // back to a second implementation of canonical JSON, which is how two
    // "identical" documents come to differ by a key order nobody chose.
    pinned: { gen, canonical },
  };
}

// ── the command ─────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const opts = {
    repo: DEFAULT_REPO, generator: null, source: null,
    candidate: null, out: null, work: null, keep: false, quiet: false,
  };
  const need = (i, name) => {
    if (i >= argv.length) throw new Refused(`${name} needs a value`);
    return argv[i];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--generator") opts.generator = need(++i, a);
    else if (a === "--source") opts.source = need(++i, a);
    else if (a === "--repo") opts.repo = path.resolve(need(++i, a));
    else if (a === "--candidate") opts.candidate = path.resolve(need(++i, a));
    else if (a === "--out") opts.out = path.resolve(need(++i, a));
    else if (a === "--work") opts.work = path.resolve(need(++i, a));
    else if (a === "--keep") opts.keep = true;
    else if (a === "--quiet") opts.quiet = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else throw new Refused(`unknown argument: ${a}`);
  }
  return opts;
}

const USAGE = `usage: node tools/regenerate-signed.mjs --generator <sha> --source <sha>
                                     [--repo DIR] [--candidate FILE] [--out FILE]
                                     [--work DIR] [--keep] [--quiet]

  --generator <ref>   the reviewed commit the generator code is taken from
  --source <ref>      the Source-Commit the inputs are taken from
  --repo <dir>        the clone to read both out of (default: this file's own)
  --candidate <file>  a carried catalogue to compare the regeneration against
  --out <file>        write the document here instead of to stdout
  --work <dir>        assemble into this directory instead of a fresh temp one
  --keep              leave the assembled tree behind, to be looked at
  --quiet             the document and nothing else

exit: 0 regenerated (and agreed, if --candidate); 1 the candidate disagrees;
      2 the command could not run.`;

function firstDifference(a, b) {
  const x = a.split("\n");
  const y = b.split("\n");
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if (x[i] !== y[i]) {
      return `      first difference at line ${i + 1}:\n` +
        `      candidate:     ${x[i] ?? "<end of file>"}\n` +
        `      regenerated:   ${y[i] ?? "<end of file>"}`;
    }
  }
  return "      the two differ in length only";
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(USAGE);
    return 0;
  }
  if (!opts.generator || !opts.source) {
    throw new Refused(`--generator and --source are both required.\n\n${USAGE}`);
  }

  const work = opts.work ?? fs.mkdtempSync(path.join(os.tmpdir(), "astra-regenerate-"));
  const note = (s) => { if (!opts.quiet) process.stderr.write(`${s}\n`); };
  try {
    return await run(opts, work, note);
  } finally {
    // After the comparison, never before it. An earlier draft removed the tree
    // in a `finally` around `regenerate()` alone and then re-imported the
    // pinned modules to read `--candidate` — which happened to work off Node's
    // module cache, and would have stopped working the day anything imported
    // them by a second specifier. A temp directory removed while the thing
    // that needs it is still running is not a tidy-up, it is a race with one
    // fast participant.
    if (!opts.keep && !opts.work) fs.rmSync(work, { recursive: true, force: true });
  }
}

async function run(opts, work, note) {
  const result = await regenerate({ repo: opts.repo, generator: opts.generator, source: opts.source, work });

  note(`gen   ${result.generator}  (${result.assembled.code.length} file(s) of code)`);
  note(`src   ${result.source}  (${result.assembled.inputs.length} file(s) of input)`);
  note(`net   ${result.closure.length} module(s) in the closure, none of them a network client`);
  note(`ser   ${result.serial}, counted from the history behind --source`);

  if (opts.out) {
    fs.mkdirSync(path.dirname(opts.out), { recursive: true });
    fs.writeFileSync(opts.out, result.text);
    note(`wrote ${opts.out}`);
  } else {
    process.stdout.write(result.text);
  }

  if (!opts.candidate) return 0;

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(opts.candidate, "utf8"));
  } catch (e) {
    throw new Refused(`--candidate ${opts.candidate} is not readable JSON: ${e.message}`);
  }
  // Through the PINNED `indexContent`, so a candidate that is a whole signed
  // envelope and one that is a bare `signed` member are compared the same way,
  // and neither `issued_at` nor a signature is ever part of the comparison.
  const carried = result.pinned.gen.indexContent(parsed);
  const carriedText = result.pinned.canonical.stableStringify(carried);

  if (carriedText === result.text) {
    note(`ok    the candidate is the regeneration of ${result.source} under ${result.generator}`);
    return 0;
  }
  process.stderr.write(
    `FAIL  the candidate is not what ${result.source} regenerates to under ${result.generator}.\n` +
    `${firstDifference(carriedText, result.text)}\n` +
    (carried?.serial !== result.serial
      ? `      the candidate claims serial ${carried?.serial} and the history behind --source says ` +
        `${result.serial}; the computed one is the one that was used\n`
      : ""),
  );
  return 1;
}

const invokedDirectly = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (invokedDirectly) {
  // `process.exitCode`, never `process.exit()`.
  //
  // This cost a day and it is the exact failure this tool exists to prevent,
  // committed by the tool itself. `process.stdout.write` is ASYNCHRONOUS when
  // stdout is a pipe, and `process.exit()` does not wait for it. Piped into
  // anything — `| jq`, `$(…)`, a sidecar's `subprocess.run` — the catalogue
  // came out TRUNCATED: measured at 145,897 bytes of a 575,341-byte document,
  // cut mid-icon, exit status 0 and not one word on stderr. `--out` wrote the
  // whole file, so every check that used a file passed while every consumer
  // that used a pipe got a shorter document and no way to know.
  //
  // A regenerator whose output silently depends on whether its caller used a
  // pipe is worse than no regenerator: it produces a plausible document and
  // a comparison against it fails for a reason that is nowhere near the truth.
  // Setting the code and returning lets Node flush before it exits.
  try {
    process.exitCode = await main(process.argv.slice(2));
  } catch (e) {
    // Everything this command refuses exits 2, including a crash: a sidecar
    // that read a crash as "the catalogue disagrees" would withhold a commit
    // for a reason that has nothing to do with the commit.
    process.stderr.write(`FAIL  ${e instanceof Refused ? e.message : (e.stack ?? e.message)}\n`);
    process.exitCode = 2;
  }
}
