// ROLL-60's rolling re-sign: `tools/lib/rehearsal-resign.mjs`, driven the way
// canary-4's scheduled workflow drives `tools/testkeys/rehearsal-resign.mjs`,
// against local bare repositories standing in for canary-4 and on a fake
// clock, with the real signer doing the signing. git is pointed at the bares
// with `url.<bare>.insteadOf`, and every GitHub URL a check does not redirect
// goes to `github.invalid` (`NOWHERE`), so nothing here reaches the network.
// That has to hold whatever any check names: on 2026-10-03 the push suite,
// half-moved to a new default, pushed to the real canary-2.
//
// What is asked, and why each:
// - a re-sign keeps the serials and the content, and moves only the dates and
//   signatures, because the service refuses anything else at an equal serial;
// - over eight days of scheduled runs, with the worst gap production has
//   measured, a served list is never expired, never past the publisher's
//   min(issued_at, judged_at) + 8 days, and never older than 36 hours;
// - the re-sign goes to canary-4 and nowhere else. The workflow's text, the
//   copy that runs, cannot reach production either.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";

import * as rr from "../lib/rehearsal-resign.mjs";
import * as rp from "../lib/rehearsal-push.mjs";
import { fixtureEnv } from "../lib/git-env.mjs";
import { DOCUMENTS } from "../testkeys/make-rehearsal-r2.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { INDEX_SCHEMA, REVOCATIONS_SCHEMA, signEnvelope } from "../../bot/lib/sign.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

const { documentProblems, lineageProblem, main, workflowProblems, deployedProblems, PIN_PLACEHOLDER, TEMPLATE } = rr;

const ROOT = path.join(tmp, "rehearsal-resign");
const CANARY_4 = "mihailinl/astra-registry-canary-4";
const URL_4 = `https://github.com/${CANARY_4}.git`;
const FIXTURES = "rehearsal-r2d";
const T0 = Date.parse("2026-10-03T00:00:00Z");
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const at = (hours) => T0 + hours * HOUR;
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
const PAGES = "https://pages.invalid/astra-registry-canary-4/";

/** Where a GitHub URL goes that no check sent to a local bare. */
const NOWHERE = "https://github.invalid/";
const redirect = (map) => [`url.${NOWHERE}.insteadOf=https://github.com/`, ...Object.entries(map).map(([from, to]) => `url.${to}.insteadOf=${from}`)];

let serial = 0;
function bare(name) {
  const dir = path.join(ROOT, `${name}-${++serial}.git`);
  fs.mkdirSync(dir, { recursive: true });
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", dir], { env: fixtureEnv(dir), stdio: ["ignore", "pipe", "pipe"] });
  return dir;
}
const gitIn = (dir) => (...args) =>
  execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: fixtureEnv(dir), stdio: ["pipe", "pipe", "pipe"] }).trim();
function refOf(dir, ref) {
  const r = spawnSync("git", ["-C", dir, "rev-parse", "--verify", "--quiet", ref], { encoding: "utf8", env: fixtureEnv(dir) });
  return r.status === 0 ? r.stdout.trim() : null;
}
const docsAt = (dir, ref) => Object.fromEntries(DOCUMENTS.map((rel) => [rel, rr.blobBytes(dir, [], ref, rel)]));
const json = (bytes) => JSON.parse(String(bytes));

/** The cut's sources, exported once, and canary-4's `main` with them merged in with `-s ours`. */
let sources = null;
function sourceBare() {
  if (sources) return sources;
  const dir = bare("sources");
  const heads = rp.exportSource(dir, { fixtures: FIXTURES });
  const run = rp.gitAt(dir);
  const who = { name: "t", email: "t@users.noreply.invalid", date: "2026-10-03T15:00:00Z" };
  const blob = run(["hash-object", "-w", "--stdin"], { input: "a rehearsal canary\n" }).out;
  const tree = run(["mktree"], { input: `100644 blob ${blob}\tREADME.md\n` }).out;
  const before = run(["commit-tree", tree], { input: "the canary's main\n", who }).out;
  const merged = run(["commit-tree", tree, "-p", before, "-p", heads.rotation, "-p", heads.compromise], { input: "sources, -s ours\n", who }).out;
  gitIn(dir)("update-ref", "refs/heads/bare-main", before);
  gitIn(dir)("update-ref", "refs/heads/merged-main", merged);
  sources = dir;
  return dir;
}

const step0 = () => rp.loadSeries("rotation", { fixtures: FIXTURES })[0];

/** A canary-4 stand-in: `main` with (or without) the sources, `signed` at step 0 (or absent). */
function canary4({ main = "merged-main", signed = true } = {}) {
  const dir = bare("canary-4");
  gitIn(dir)("fetch", "--quiet", sourceBare(), `+refs/heads/${main}:refs/heads/main`);
  if (signed) {
    rp.buildCommits(rp.gitAt(dir), [step0()]);
    gitIn(dir)("update-ref", "refs/heads/signed", step0().sha);
  }
  return dir;
}

/** One run of the command line on the fake clock, with canary-4's URL sent to `dir`. */
async function resign(argv, { to = {}, when, env = {}, fetchImpl = null, pagesBase = PAGES } = {}) {
  const lines = [];
  let now = when;
  const code = await main(argv, {
    gitConfig: redirect(to), clock: () => now, sleep: async (ms) => { now += ms; }, log: (l) => lines.push(l), env, fetchImpl,
    ...(pagesBase ? { pagesBase } : {}),
  });
  return { code, out: lines.join("\n") };
}

/** Pages built from `signed` of `dir`. */
const pagesFrom = (dir, base = PAGES) => async (url) => {
  const rel = url.slice(base.length).split("?")[0];
  const b = rr.blobBytes(dir, [], "refs/heads/signed", rel);
  if (!b) return { status: 404, arrayBuffer: async () => new ArrayBuffer(0) };
  return { status: 200, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.length) };
};

/** A document re-signed by the outgoing TEST key, so only the property under test is wrong. */
function signedAs(bytes, domain, edit) {
  const doc = json(bytes);
  const signed = edit(structuredClone(doc.signed));
  const key = loadTestRoot("TEST-ONLY-DO-NOT-TRUST-index-2026a");
  const env = signEnvelope({ domain, signed, signers: [{ key_id: "astra-index-2026a", privateKey: key.privateKey }] });
  return Buffer.from(`${JSON.stringify({ ...doc, ...env }, null, 2)}\n`);
}

export async function run() {
  console.log("\nROLL-60's rolling re-sign of canary-4's step 0 (tools/lib/rehearsal-resign.mjs)");
  const s0 = step0();

  await test("a GitHub URL no check redirects goes nowhere, so this suite cannot re-sign a real canary", async () => {
    const r = await resign([], { to: {}, when: at(21) });
    assertEqual(r.code, 2, `a run with nothing redirected: exit code\n${r.out}`);
    assert(r.out.includes("github.invalid"), `the refusal does not name where git was sent:\n${r.out}`);
  });

  await test("REFUSED: the re-sign goes to canary-4 only: production in every spelling, the other canaries, strangers, and a job holding a real key", async () => {
    assertEqual(rr.resignCanaries().join(" "), CANARY_4, "the re-sign canaries");
    const target = canary4();
    const to = { [URL_4]: target };
    for (const spelling of ["mihailinl/astra-registry", "Mihailinl/Astra-Registry", "https://github.com/mihailinl/astra-registry.git",
      "git@github.com:mihailinl/astra-registry.git", " mihailinl/astra-registry "]) {
      const r = await resign(["--repo", spelling], { to, when: at(21) });
      assertEqual(r.code, 2, `--repo ${JSON.stringify(spelling)}: exit code\n${r.out}`);
      assert(/REFUSED .*production registry/.test(r.out), `--repo ${JSON.stringify(spelling)} was not refused as production:\n${r.out}`);
    }
    for (const other of ["mihailinl/astra-registry-canary", "mihailinl/astra-registry-canary-2", "mihailinl/astra-registry-canary-3"]) {
      const r = await resign(["--repo", other], { to, when: at(21) });
      assertEqual(r.code, 2, `--repo ${other}: exit code\n${r.out}`);
      assert(/not re-signed/.test(r.out), `--repo ${other} was not refused as a canary that is not re-signed:\n${r.out}`);
    }
    for (const stranger of ["mihailinl/astra-registry-canary-5", "someone/astra-registry-canary-4"]) {
      const r = await resign(["--repo", stranger], { to, when: at(21) });
      assertEqual(r.code, 2, `--repo ${stranger}: exit code\n${r.out}`);
    }
    const keyed = await resign([], { to, when: at(21), env: { ASTRA_INDEX_SIGNING_KEY: "irrelevant" } });
    assertEqual(keyed.code, 2, `a real key in the environment: exit code\n${keyed.out}`);
    assert(/ASTRA_INDEX_SIGNING_KEY is set/.test(keyed.out), `the refusal does not name the key:\n${keyed.out}`);
    assertEqual(refOf(target, "refs/heads/signed"), s0.sha, "a refused run moved canary-4's `signed`");
  });

  await test("under 20 hours the signer re-signs nothing and nothing is pushed; at 20 hours it re-signs both, one commit on step 0", async () => {
    const target = canary4();
    const early = await resign(["--event", "schedule"], { to: { [URL_4]: target }, when: at(20) - 60_000 });
    assertEqual(early.code, 0, `19 h 59 m\n${early.out}`);
    assert(/nothing to re-sign: catalogue unchanged, list unchanged/.test(early.out), `the early run did not say it re-signed nothing:\n${early.out}`);
    assertEqual(refOf(target, "refs/heads/signed"), s0.sha, "a run under 20 hours moved `signed`");
    const due = await resign(["--event", "schedule"], { to: { [URL_4]: target }, when: at(20) });
    assertEqual(due.code, 0, `20 h\n${due.out}`);
    const head = refOf(target, "refs/heads/signed");
    assert(head !== s0.sha, `20 hours in, nothing was pushed:\n${due.out}`);
    assertEqual(gitIn(target)("rev-parse", `${head}^`), s0.sha, "the re-sign's parent");
    assertEqual(gitIn(target)("rev-list", "--count", `${s0.sha}..${head}`), "1", "one commit on step 0");
  });

  await test("a re-sign keeps the serials and the content: only issued_at, expires_at and the signatures move, and trust.json and root.json stay step 0's bytes", async () => {
    const target = canary4();
    const when = at(26.5);
    const r = await resign(["--event", "schedule"], { to: { [URL_4]: target }, when });
    assertEqual(r.code, 0, `the re-sign\n${r.out}`);
    const head = refOf(target, "refs/heads/signed");
    const docs = docsAt(target, head);
    for (const rel of ["registry/v1/trust.json", "registry/v1/root.json"]) {
      assert(docs[rel].equals(s0.docs[rel]), `${rel} is not step 0's bytes`);
    }
    const ttl = { "registry/v1/index.json": 30, "registry/v1/revocations.json": 7 };
    for (const rel of ["registry/v1/index.json", "registry/v1/revocations.json"]) {
      const before = json(s0.docs[rel]).signed;
      const after = json(docs[rel]).signed;
      assertEqual(after.serial, before.serial, `${rel}'s serial`);
      const strip = ({ issued_at, expires_at, ...rest }) => JSON.stringify(rest);
      assertEqual(strip(after), strip(before), `${rel}'s signed content, dates aside`);
      assertEqual(after.issued_at, iso(when), `${rel}'s issued_at`);
      assertEqual(after.expires_at, iso(when + ttl[rel] * DAY), `${rel}'s expires_at`);
      assert(json(docs[rel]).signatures[0].sig !== json(s0.docs[rel]).signatures[0].sig, `${rel}'s signature did not move`);
    }
    assertEqual(documentProblems({ bytes: docs, step0: s0, now: when }).join("; "), "", "the re-sign, judged as the service would");
    const message = gitIn(target)("log", "-1", "--format=%an <%ae> %cI%n%B", head);
    const [who, date] = gitIn(target)("log", "-1", "--format=%an <%ae>|%ct", head).split("|");
    assertEqual(who, "astra-registry signer <signer@users.noreply.github.com>", "the re-sign's committer is the signer's identity");
    assertEqual(Number(date) * 1000, when, "the re-sign is committed at its own clock");
    assert(message.includes(`Source-Commit: ${s0.sourceCommit}`), `the commit does not name step 0's Source-Commit:\n${message}`);
    assert(message.includes("Run: https://github.com/mihailinl/astra-registry/actions/runs/0"), `the Run trailer is not the series':\n${message}`);
    // And a second, a day on, re-signs the re-sign: still the same serials, later dates (SERVE-88).
    const again = await resign(["--event", "schedule"], { to: { [URL_4]: target }, when: when + 21 * HOUR });
    assertEqual(again.code, 0, `the second re-sign\n${again.out}`);
    const second = docsAt(target, refOf(target, "refs/heads/signed"));
    assertEqual(json(second["registry/v1/revocations.json"]).signed.serial, json(s0.docs["registry/v1/revocations.json"]).signed.serial, "the list's serial after two re-signs");
    assertEqual(documentProblems({ bytes: second, step0: s0, now: when + 21 * HOUR, previous: docs }).join("; "), "", "the second re-sign against the first");
  });

  await test("a served list is never older than the window: eight days of scheduled runs, one of them 13 hours late, and the list is never expired, never past the publisher's bound, never older than 36 hours", async () => {
    const target = canary4();
    const to = { [URL_4]: target };
    // Every four hours, except one gap of 13: production's longest measured gap between scheduled runs is 13.34 h.
    const ticks = [];
    for (let h = 1; h <= 8 * 24; h += 4) ticks.push(h);
    const gapAt = ticks.indexOf(97);
    ticks.splice(gapAt + 1, 3, 97 + 13);
    let worst = 0;
    let resigns = 0;
    let previous = null;
    for (const h of ticks) {
      const when = at(h);
      const before = docsAt(target, "refs/heads/signed");
      const age = rr.listAgeHours(before, when);
      worst = Math.max(worst, age);
      assert(age < rr.STALE_AFTER_HOURS, `at T0 + ${h} h the served list is ${age.toFixed(2)} h old`);
      const r = await resign(["--event", "schedule"], { to, when });
      assertEqual(r.code, 0, `the run at T0 + ${h} h\n${r.out}`);
      const head = refOf(target, "refs/heads/signed");
      const docs = docsAt(target, head);
      if (head !== previous && previous !== null) resigns++;
      previous = head;
      const problems = documentProblems({ bytes: docs, step0: s0, now: when });
      assertEqual(problems.join("; "), "", `at T0 + ${h} h the served documents would be refused`);
      const list = json(docs["registry/v1/revocations.json"]).signed;
      assert(Date.parse(list.expires_at) > when, `at T0 + ${h} h the served list has expired`);
      assert(Date.parse(list.expires_at) <= Math.min(Date.parse(list.issued_at), when) + rr.SERVICE_LIST_BOUND_DAYS * DAY,
        `at T0 + ${h} h the served list is past min(issued_at, judged_at) + 8 days`);
    }
    assert(worst <= 20 + 13 + 4, `the oldest served list was ${worst.toFixed(2)} h old`);
    assert(resigns >= 7, `${resigns} re-signs in eight days`);
    // The line `signed` carries is step 0 and its re-signs, and nothing else.
    assertEqual(lineageProblem(rp.gitAt(target), s0, refOf(target, "refs/heads/signed")), null, "the line after eight days");
  });

  await test("a push-started run re-signs only at 34 hours, as production's backstop does", async () => {
    const target = canary4();
    const early = await resign(["--event", "push"], { to: { [URL_4]: target }, when: at(30) });
    assertEqual(early.code, 0, `a push run at 30 h\n${early.out}`);
    assertEqual(refOf(target, "refs/heads/signed"), s0.sha, "a push run at 30 h re-signed");
    const late = await resign(["--event", "push"], { to: { [URL_4]: target }, when: at(34) });
    assertEqual(late.code, 0, `a push run at 34 h\n${late.out}`);
    assert(refOf(target, "refs/heads/signed") !== s0.sha, "a push run at 34 h did not re-sign");
  });

  await test("a head that is not step 0 or a line of its re-signs is refused, and nothing is signed or pushed", async () => {
    const target = canary4();
    const g = rp.gitAt(target);
    // A commit on step 0 that changes trust.json: the rotation's step 1, which the series has and the re-sign must not stack on.
    const step1 = rp.loadSeries("rotation", { fixtures: FIXTURES })[1];
    rp.buildCommits(g, rp.loadSeries("rotation", { fixtures: FIXTURES }).slice(0, 2));
    gitIn(target)("update-ref", "refs/heads/signed", step1.sha);
    const r = await resign(["--event", "schedule"], { to: { [URL_4]: target }, when: at(30) });
    assertEqual(r.code, 1, `a head at rotation step 1\n${r.out}`);
    assert(/trust\.json that is not step 0's/.test(r.out), `the refusal does not say why:\n${r.out}`);
    assertEqual(refOf(target, "refs/heads/signed"), step1.sha, "a foreign head was moved");
    // A head that does not descend from step 0 at all.
    const other = canary4({ signed: false });
    gitIn(other)("update-ref", "refs/heads/signed", gitIn(other)("rev-parse", "refs/heads/main"));
    const r2 = await resign(["--event", "schedule"], { to: { [URL_4]: other }, when: at(30) });
    assertEqual(r2.code, 1, `a head off step 0\n${r2.out}`);
    assert(/does not descend from step 0/.test(r2.out), `the refusal does not say why:\n${r2.out}`);
    // No `signed` at all: step 0 is rehearsal-push's to push.
    const empty = canary4({ signed: false });
    const r3 = await resign(["--event", "schedule"], { to: { [URL_4]: empty }, when: at(30) });
    assertEqual(r3.code, 1, `no signed\n${r3.out}`);
    assert(/Push step 0 with rehearsal-push first/.test(r3.out), `the refusal does not say what to run:\n${r3.out}`);
  });

  // A commit that carries step 0's four documents byte for byte and an empty
  // directory beside them. Every leaf-reading question below it — `diff
  // --name-only`, `ls-tree -r` — sees the four documents and nothing else, so
  // until 2026-10-03 this read as a line of re-signs, while a reader of trees
  // sees a fifth entry on `signed` (the plugins service's empty-tree finding).
  // A document committed as a link passed the same way: its path is one of
  // the four.
  await test("a commit on step 0 that adds only an empty directory, or holds a document as a link, is not a re-sign", async () => {
    const target = canary4();
    const g = rp.gitAt(target);
    const s0 = step0();
    // An identity of the fixture's own: a runner has none configured.
    const who = { name: "t", email: "t@users.noreply.invalid", date: "2026-10-03T15:00:00Z" };
    const empty = g(["mktree"], { input: "" }).out;
    const top = g(["ls-tree", s0.sha]).out;
    const withEmpty = g(["mktree"], { input: `${top}\n040000 tree ${empty}\tjunk\n` }).out;
    const head = g(["commit-tree", withEmpty, "-p", s0.sha], { input: "a re-sign that is not one\n", who }).out;
    const why = lineageProblem(g, s0, head);
    assert(why !== null && /junk: an empty directory/.test(why), `a commit carrying an empty directory read as a re-sign: ${why}`);

    const v1 = g(["rev-parse", `${s0.sha}:registry/v1`]).out;
    const rows = g(["ls-tree", v1]).out.split("\n");
    const pointee = g(["hash-object", "-w", "--stdin"], { input: "trust.json" }).out;
    const linked = g(["mktree"], {
      input: `${rows.map((r) => (r.endsWith("\tindex.json") ? `120000 blob ${pointee}\tindex.json` : r)).join("\n")}\n`,
    }).out;
    const registry = g(["mktree"], { input: `040000 tree ${linked}\tv1\n` }).out;
    const rootTree = g(["mktree"], { input: `040000 tree ${registry}\tregistry\n` }).out;
    const head2 = g(["commit-tree", rootTree, "-p", s0.sha], { input: "a document as a link\n", who }).out;
    const why2 = lineageProblem(g, s0, head2);
    assert(why2 !== null && /registry\/v1\/index\.json: a symbolic link, git mode 120000/.test(why2),
      `a commit holding a document as a link was not refused by name and mode: ${why2}`);
  });

  await test("TRUST-3: a canary whose main lacks the cut's sources is refused before anything is signed", async () => {
    const target = canary4({ main: "bare-main" });
    const r = await resign(["--event", "schedule"], { to: { [URL_4]: target }, when: at(30) });
    assertEqual(r.code, 1, `off main\n${r.out}`);
    // The refusal itself, not a line that mentions TRUST-3: watched passing
    // for the wrong reason when the refusal was removed and a later git
    // failure stopped the run instead.
    assert(/^FAIL +TRUST-3: Source-Commit .* not/m.test(r.out), `the run was not refused by TRUST-3:\n${r.out}`);
    assert(!/the signer|re-signed at/.test(r.out), `the signer was started before TRUST-3 was asked:\n${r.out}`);
    assertEqual(refOf(target, "refs/heads/signed"), s0.sha, "a TRUST-3 refusal moved `signed`");
  });

  await test("--dry-run signs and judges the re-sign, and pushes nothing", async () => {
    const target = canary4();
    const r = await resign(["--event", "workflow_dispatch", "--dry-run"], { to: { [URL_4]: target }, when: at(30) });
    assertEqual(r.code, 0, `dry run\n${r.out}`);
    assert(/re-signed at 2026-10-04T06:00:00Z/.test(r.out) && /dry +would push/.test(r.out), `the dry run did not sign and stop:\n${r.out}`);
    assertEqual(refOf(target, "refs/heads/signed"), s0.sha, "a dry run pushed");
  });

  await test("documents the service would refuse are named, each for its own reason: a longer list, a future one, a moved serial, other entries, a foreign trust.json, a bad signature, an older issued_at", () => {
    const target = canary4();
    const when = at(30);
    const good = docsAt(target, "refs/heads/signed");
    const now = at(10);
    assertEqual(documentProblems({ bytes: good, step0: s0, now }).join("; "), "", "step 0 itself, ten hours in");
    const list = "registry/v1/revocations.json";
    const index = "registry/v1/index.json";
    const cases = [
      ["a list valid 9 days", { [list]: signedAs(good[list], REVOCATIONS_SCHEMA, (s) => ({ ...s, expires_at: iso(Date.parse(s.issued_at) + 9 * DAY) })) },
        [/valid 9 days, not the signer's 7/, /past min\(issued_at, now\) \+ 8 days/]],
      ["a list issued a day after the clock", { [list]: signedAs(good[list], REVOCATIONS_SCHEMA, (s) => ({ ...s, issued_at: iso(now + DAY), expires_at: iso(now + 8 * DAY) })) },
        [/after this run's clock/]],
      ["a catalogue at serial 2", { [index]: signedAs(good[index], INDEX_SCHEMA, (s) => ({ ...s, serial: 2 })) }, [/serial 2, and step 0's is 1/]],
      ["a list with an entry dropped", { [list]: signedAs(good[list], REVOCATIONS_SCHEMA, (s) => ({ ...s, revocations: [] })) }, [/signed content, dates aside, is not step 0's/]],
      ["step 1's trust.json", { "registry/v1/trust.json": rp.loadSeries("rotation", { fixtures: FIXTURES })[1].docs["registry/v1/trust.json"] }, [/trust\.json is not step 0's bytes/]],
      ["a flipped signature", { [index]: (() => { const d = json(good[index]); const sig = Buffer.from(d.signatures[0].sig, "base64"); sig[0] ^= 1; d.signatures[0].sig = sig.toString("base64"); return Buffer.from(JSON.stringify(d)); })() },
        [/index\.json does not verify/]],
      ["an expired list", {}, [/revocations\.json expired at 2026-10-10T00:00:00Z/], at(7 * 24)],
    ];
    for (const [what, edits, reds, clock = now] of cases) {
      const problems = documentProblems({ bytes: { ...good, ...edits }, step0: s0, now: clock });
      for (const red of reds) assert(problems.some((p) => red.test(p)), `${what}: no problem matching ${red}: ${JSON.stringify(problems)}`);
    }
    // SERVE-88: a re-sign whose issued_at is not later than the copy it replaces.
    const replay = documentProblems({ bytes: good, step0: s0, now: when, previous: good });
    assert(replay.some((p) => /not later than the copy it replaces/.test(p)), `a replay at an equal issued_at passed: ${JSON.stringify(replay)}`);
  });

  await test("the workflow cannot reach production: the template starts on the schedule and a dispatch only, its token writes this repository and Pages only, it reads no secret, it runs only in canary-4, and its registry is pinned", () => {
    const template = fs.readFileSync(TEMPLATE, "utf8");
    assertEqual(workflowProblems(template).join("; "), "", "the template");
    const sha = "0123456789abcdef0123456789abcdef01234567";
    const deployed = template.split(PIN_PLACEHOLDER).join(sha);
    assertEqual([...workflowProblems(deployed), ...deployedProblems(deployed, template, sha)].join("; "), "", "the template, deployed");
    const swap = (from, to) => { assert(template.includes(from), `the template has no ${JSON.stringify(from)}`); return template.replace(from, to); };
    const cases = [
      ["a push trigger", swap("  workflow_dispatch:\n", "  push:\n  workflow_dispatch:\n"), /not exactly schedule and workflow_dispatch/],
      ["a pull_request_target trigger", swap("  workflow_dispatch:\n", "  pull_request_target:\n  workflow_dispatch:\n"), /not exactly schedule and workflow_dispatch/],
      ["actions: write", swap("  pages: write\n", "  pages: write\n  actions: write\n"), /not exactly contents: write and pages: write/],
      ["write-all", swap("permissions:\n  contents: write\n  pages: write\n", "permissions: write-all\n"), /write-all|not exactly/],
      ["a job's own permissions", swap("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n"), /widens its own permissions/],
      ["a secret", swap("TOKEN: ${{ github.token }}", "TOKEN: ${{ secrets.REGISTRY_PAT }}"), /reads a secret/],
      ["production's environment", swap("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    environment: publish\n"), /environment/],
      ["the guard on production", swap("github.repository == 'mihailinl/astra-registry-canary-4'", "github.repository == 'mihailinl/astra-registry'"), /no job guard/],
      ["the guard removed", swap("    if: github.repository == 'mihailinl/astra-registry-canary-4'\n", ""), /no job guard/],
      ["an unpinned action", swap("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4", "actions/setup-node@v4"), /not pinned to a commit/],
      ["a branch for a pin", swap('REGISTRY_SHA: "@REGISTRY_SHA@"', 'REGISTRY_SHA: "main"'), /not a 40-hex commit/],
      ["the registry from elsewhere", swap("https://github.com/mihailinl/astra-registry.git \"$REGISTRY_SHA\"", "https://example.invalid/astra-registry.git \"$REGISTRY_SHA\""), /not fetched from its public URL/],
      ["a credential for all of github.com", swap('"http.https://github.com/${GITHUB_REPOSITORY}.git.extraheader"', '"http.https://github.com/.extraheader"'), /not scoped to this repository's URL/],
      ["the re-sign aimed at production", swap('--repo "$GITHUB_REPOSITORY" --event', '--repo mihailinl/astra-registry --event'), /not told this repository/],
      ["the Pages wait aimed at production", swap('--wait-pages --repo "$GITHUB_REPOSITORY"', '--wait-pages --repo mihailinl/astra-registry'), /not told this repository/],
      ["a second --repo", swap('--repo "$GITHUB_REPOSITORY" --event', '--repo "$GITHUB_REPOSITORY" --repo mihailinl/astra-registry --event'), /not told this repository/],
    ];
    for (const [what, text, red] of cases) {
      const problems = workflowProblems(text);
      assert(problems.some((p) => red.test(p)), `${what}: the audit did not refuse it (${JSON.stringify(problems)})`);
    }
    // The copy that runs is the template, pinned to the commit it runs.
    const drifted = deployed.replace("timeout-minutes: 20", "timeout-minutes: 30");
    assert(deployedProblems(drifted, template, sha).length === 1, "a deployed copy that differs from the template passed");
    assert(deployedProblems(deployed, template, "f".repeat(40)).length === 1, "a deployed copy pinned to another commit passed");
    assert(deployedProblems(template, template, sha).length === 1, "an unpinned deployed copy passed");
  });

  await test("--wait-pages is done only when Pages serves the head's four documents byte for byte, judged again as served and fresh", async () => {
    const target = canary4();
    const to = { [URL_4]: target };
    const r = await resign(["--event", "schedule"], { to, when: at(21) });
    assertEqual(r.code, 0, `the re-sign\n${r.out}`);
    const served = await resign(["--wait-pages"], { to, when: at(21.1), fetchImpl: pagesFrom(target) });
    assertEqual(served.code, 0, `Pages from \`signed\`\n${served.out}`);
    assert(/Pages serves .* byte for byte .* every signature verifies/.test(served.out), `the served bytes were not judged:\n${served.out}`);
    // Pages still on step 0 while `signed` has moved: it times out, named.
    const stale = canary4();
    const stalePages = pagesFrom(stale);
    const lagging = await resign(["--wait-pages", "--pages-timeout", "60"], { to, when: at(21.2), fetchImpl: stalePages });
    assertEqual(lagging.code, 1, `Pages serving step 0 after the re-sign\n${lagging.out}`);
    assert(/Pages does not serve/.test(lagging.out), `the failure does not say Pages lags:\n${lagging.out}`);
    // A served list 37 hours old: valid, and a red run, because the schedule is not keeping it fresh.
    const old = canary4();
    const aged = await resign(["--wait-pages"], { to: { [URL_4]: old }, when: at(37), fetchImpl: pagesFrom(old) });
    assertEqual(aged.code, 1, `a 37-hour-old served list\n${aged.out}`);
    assert(/37\.00 h old, past 36 h/.test(aged.out), `the failure does not say the list is stale:\n${aged.out}`);
  });

  await test("--status names the head, how many times step 0 has been re-signed, the list's age, and whether Pages serves it", async () => {
    const target = canary4();
    const to = { [URL_4]: target };
    await resign(["--event", "schedule"], { to, when: at(21) });
    const r = await resign(["--status"], { to, when: at(22), fetchImpl: pagesFrom(target) });
    assertEqual(r.code, 0, `status\n${r.out}`);
    assert(r.out.includes(`step 0 ${s0.sha}`) && /step 0 re-signed 1 time\(s\)/.test(r.out), `status does not name step 0 and the re-signs:\n${r.out}`);
    assert(/issued 2026-10-03T21:00:00Z \(1\.00 h ago\)/.test(r.out), `status does not give the list's age:\n${r.out}`);
    assert(/Pages: serving the head/.test(r.out), `status does not say what Pages serves:\n${r.out}`);
  });
}
