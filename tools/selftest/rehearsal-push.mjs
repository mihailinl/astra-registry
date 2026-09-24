// ROLL-60's rehearsal, pushed: `tools/lib/rehearsal-push.mjs`, driven the way
// the operator's `tools/testkeys/rehearsal-push.mjs --step N` drives it, against
// local bare repositories standing in for the canary and for the production
// registry. git is pointed at them with `url.<bare>.insteadOf` for the real
// GitHub URLs, so the code under test builds, checks and pushes to exactly the
// URL it would on the day, and nothing here reaches the network: every rewrite
// target that is not a local bare is a `.invalid` host.
//
// **Why these and not a first run.** The day this runs for real, a staging
// service and a debug daemon accept or refuse a key rotation on the strength of
// what it pushed, one commit at a time, onto a branch that cannot be rewound —
// and the one refusal that matters most, never to push to
// `mihailinl/astra-registry`, has no second chance at all. So each rule is
// asked here, and each was watched failing by breaking the line it names.

import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fixtureEnv } from "../lib/git-env.mjs";

import {
  CANARY_SLUG, PRODUCTION_SLUG, SERIES, buildCommits, effectiveUrlProblem, exportSource, gitAt, githubUrl,
  loadSeries, main, sourceCheck, targetProblem, waitPages,
} from "../lib/rehearsal-push.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

const ROOT = path.join(tmp, "rehearsal-push");
const CANARY_URL = githubUrl(CANARY_SLUG);
const PRODUCTION_URL = githubUrl(PRODUCTION_SLUG);
const PAGES = "https://pages.invalid/astra-registry-canary/";

let serial = 0;
/** A bare repository under the suite's temp directory. */
function bare(name) {
  const dir = path.join(ROOT, `${name}-${++serial}.git`);
  fs.mkdirSync(dir, { recursive: true });
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", dir], { env: fixtureEnv(dir), stdio: ["ignore", "pipe", "pipe"] });
  return dir;
}

const gitIn = (dir) => (...args) =>
  execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: fixtureEnv(dir), stdio: ["pipe", "pipe", "pipe"] }).trim();

/** The ref's sha, or null. */
function refOf(dir, ref) {
  const r = spawnSync("git", ["-C", dir, "rev-parse", "--verify", "--quiet", ref], { encoding: "utf8", env: fixtureEnv(dir) });
  return r.status === 0 ? r.stdout.trim() : null;
}

const refsOf = (dir) => gitIn(dir)("for-each-ref", "--format=%(refname)").split("\n").filter(Boolean);

/** `-c` options sending each GitHub URL to a local bare (or anywhere). */
const redirect = (map) => Object.entries(map).map(([from, to]) => `url.${to}.insteadOf=${from}`);

/**
 * BOT-88's `main`, and the same `main` after the rehearsal's sources were
 * merged in with `-s ours` — the canary pull request, rebuilt here from
 * `exportSource`'s refs, so TRUST-3 is asked of the shape the canary really has.
 */
let sourceBare = null;
function sourceHistory() {
  if (sourceBare) return sourceBare;
  sourceBare = bare("sources");
  const heads = exportSource(sourceBare);
  const g = gitIn(sourceBare);
  const run = gitAt(sourceBare);
  const who = { name: "t", email: "t@users.noreply.invalid", date: "2026-09-24T00:00:00Z" };
  const commit = (args, message) => run(["commit-tree", ...args], { input: message, who }).out;
  const blob = run(["hash-object", "-w", "--stdin"], { input: "BOT-88's test repository\n" }).out;
  const tree = run(["mktree"], { input: `100644 blob ${blob}\tREADME.md\n` }).out;
  const bot88 = commit([tree], "BOT-88's main\n");
  const merged = commit([tree, "-p", bot88, "-p", heads.rotation, "-p", heads.compromise], "the rehearsal's sources, -s ours\n");
  g("update-ref", "refs/heads/bot88-main", bot88);
  g("update-ref", "refs/heads/merged-main", merged);
  return sourceBare;
}

/** A canary stand-in whose `main` is `which` of the two above. */
function canary(which = "merged-main") {
  const dir = bare("canary");
  gitIn(dir)("fetch", "--quiet", sourceHistory(), `+refs/heads/${which}:refs/heads/main`);
  return dir;
}

/** Pages built from `branch` of `dir`, the way the canary's legacy Pages build serves `signed`. */
function pagesFrom(dir, branch = "signed") {
  return async (url) => {
    const rel = url.slice(PAGES.length).split("?")[0];
    const r = spawnSync("git", ["-C", dir, "cat-file", "blob", `refs/heads/${branch}:${rel}`], { env: fixtureEnv(dir) });
    if (r.status !== 0) return { status: 404, arrayBuffer: async () => new ArrayBuffer(0) };
    const b = Buffer.from(r.stdout);
    return { status: 200, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.length) };
  };
}

const okJudge = () => ({ ok: true, detail: "a stub" });

/** One run of the command line, with the day's URLs sent to local bares. */
async function push(argv, { to = {}, gitConfig = [], fetchImpl = null, judge = okJudge, at = "2026-09-26T10:00:00Z" } = {}) {
  const lines = [];
  let now = Date.parse(at);
  const code = await main(argv, {
    gitConfig: [...redirect(to), ...gitConfig],
    fetchImpl,
    judge,
    log: (l) => lines.push(l),
    sleep: async (ms) => { now += ms; },
    clock: () => now,
    pagesBase: PAGES,
  });
  return { code, out: lines.join("\n") };
}

export async function run() {
  console.log("\nROLL-60's rehearsal, pushed one step at a time (tools/lib/rehearsal-push.mjs)");

  const rotation = loadSeries("rotation");
  const compromise = loadSeries("compromise");
  const sha = (i) => rotation[i].sha;

  await test("every commit of both lines rebuilds to the sha the real signer committed (manifest.json)", () => {
    for (const [name, steps] of [["rotation", rotation], ["compromise", compromise]]) {
      const shas = buildCommits(gitAt(bare(`rebuild-${name}`)), steps);
      assertEqual(shas.length, SERIES[name].steps.length, `${name}: every step rebuilt`);
      steps.forEach((s, i) => assertEqual(shas[i], s.sha, `${name} step ${i} (${s.id})`));
    }
    assertEqual(rotation.length, 6, "the rotation line is the base and ROLL-60's five commits");
    assertEqual(compromise[3].parent, sha(2), "the compromise commit forks from rotation step 2, as the fixture README says");
  });

  await test("REFUSED: every spelling of mihailinl/astra-registry, and its bare stand-in is left with no `signed`", async () => {
    const production = canary();
    const target = canary();
    const spellings = [
      "mihailinl/astra-registry", "Mihailinl/Astra-Registry", "https://github.com/mihailinl/astra-registry.git",
      "git@github.com:mihailinl/astra-registry.git", "https://github.com/mihailinl/astra-registry/",
    ];
    for (const spelling of spellings) {
      const r = await push(["--step", "0", "--repo", spelling, "--skip-pages"], { to: { [CANARY_URL]: target, [PRODUCTION_URL]: production } });
      assertEqual(r.code, 2, `--repo ${spelling}: exit code\n${r.out}`);
      assert(/REFUSED .*production registry/.test(r.out), `--repo ${spelling} was not refused as the production registry:\n${r.out}`);
    }
    const other = await push(["--step", "0", "--repo", "mihailinl/AstraPlugins", "--skip-pages"], { to: { [CANARY_URL]: target } });
    assertEqual(other.code, 2, `--repo mihailinl/AstraPlugins: exit code\n${other.out}`);
    assertEqual(refOf(production, "refs/heads/signed"), null, "the production stand-in got a `signed` branch");
    assertEqual(refOf(target, "refs/heads/signed"), null, "a refused run pushed to the canary instead");
    assertEqual(targetProblem(CANARY_SLUG), null, "the canary itself is refused");
  });

  await test("an insteadOf or pushInsteadOf that sends the canary's URL elsewhere is refused before git fetches or pushes", async () => {
    assertEqual(effectiveUrlProblem(CANARY_URL, CANARY_URL, "push"), null, "the canary's own URL");
    assertEqual(effectiveUrlProblem("/tmp/x.git", CANARY_URL, "push"), null, "a local bare");
    assert(effectiveUrlProblem(PRODUCTION_URL, CANARY_URL, "push") !== null, "the production URL passed as the canary's");
    assert(effectiveUrlProblem("git@github.com:mihailinl/astra-registry.git", CANARY_URL, "fetch") !== null, "an ssh rewrite passed");
    const target = canary();
    const fetchAway = await push(["--step", "0", "--skip-pages"], { to: { [CANARY_URL]: "https://github.invalid/mihailinl/astra-registry.git" } });
    assertEqual(fetchAway.code, 2, `insteadOf to another host: exit code\n${fetchAway.out}`);
    assert(/insteadOf/.test(fetchAway.out), `the refusal does not name the rewrite:\n${fetchAway.out}`);
    const pushAway = await push(["--step", "0", "--skip-pages"], {
      to: { [CANARY_URL]: target },
      gitConfig: [`url.https://github.invalid/mihailinl/astra-registry.git.pushInsteadOf=${CANARY_URL}`],
    });
    assertEqual(pushAway.code, 2, `pushInsteadOf to another host: exit code\n${pushAway.out}`);
    assertEqual(refOf(target, "refs/heads/signed"), null, "a refused run pushed");
  });

  const day = canary();
  const to = { [CANARY_URL]: day };

  await test("step 0 creates `signed` at the signer's own commit, and running it again pushes nothing", async () => {
    const first = await push(["--step", "0", "--skip-pages"], { to });
    assertEqual(first.code, 0, `first run\n${first.out}`);
    assertEqual(refOf(day, "refs/heads/signed"), sha(0), "`signed` after step 0");
    assert(/TRUST-3: Source-Commit/.test(first.out), `TRUST-3 was not asked:\n${first.out}`);
    const again = await push(["--step", "0", "--skip-pages"], { to });
    assertEqual(again.code, 0, `second run\n${again.out}`);
    assert(/already at step 0.*nothing pushed/.test(again.out), `the second run did not say it pushed nothing:\n${again.out}`);
    assertEqual(refOf(day, "refs/heads/signed"), sha(0), "`signed` after step 0 twice");
  });

  await test("one commit per step: a skipped step, a passed step and a foreign head are refused and move nothing", async () => {
    const skipped = await push(["--step", "2", "--skip-pages"], { to });
    assertEqual(skipped.code, 1, `step 2 from step 0\n${skipped.out}`);
    assert(/run `--step 1` first/.test(skipped.out), `the refusal does not say what to run:\n${skipped.out}`);
    assertEqual(refOf(day, "refs/heads/signed"), sha(0), "a skipped step moved `signed`");

    const one = await push(["--step", "1", "--skip-pages"], { to });
    assertEqual(one.code, 0, `step 1\n${one.out}`);
    assertEqual(refOf(day, "refs/heads/signed"), sha(1), "`signed` after step 1");
    assertEqual(gitIn(day)("rev-list", "--count", `${sha(0)}..${sha(1)}`), "1", "step 1 is one commit on step 0");

    const back = await push(["--step", "0", "--skip-pages"], { to });
    assertEqual(back.code, 1, `step 0 from step 1\n${back.out}`);
    assert(/past step 0/.test(back.out), `the refusal does not say the step was passed:\n${back.out}`);
    assertEqual(refOf(day, "refs/heads/signed"), sha(1), "a passed step moved `signed`");

    const foreign = canary();
    gitIn(foreign)("update-ref", "refs/heads/signed", refOf(foreign, "refs/heads/main"));
    const r = await push(["--step", "1", "--skip-pages"], { to: { [CANARY_URL]: foreign } });
    assertEqual(r.code, 1, `a foreign head\n${r.out}`);
    assert(/no commit of this series/.test(r.out), `the refusal does not say the head is foreign:\n${r.out}`);
  });

  await test("--dry-run pushes nothing and names the commit a real run would push", async () => {
    const fresh = canary();
    const r = await push(["--step", "0", "--dry-run", "--skip-pages"], { to: { [CANARY_URL]: fresh } });
    assertEqual(r.code, 0, `dry run\n${r.out}`);
    assert(r.out.includes(`would push ${sha(0)}`), `the dry run does not name the commit:\n${r.out}`);
    assertEqual(refOf(fresh, "refs/heads/signed"), null, "a dry run pushed");
  });

  await test("TRUST-3: a Source-Commit the canary's main does not reach is refused; --allow-source-off-main says why it went on", async () => {
    const bot88 = canary("bot88-main");
    const refused = await push(["--step", "0", "--skip-pages"], { to: { [CANARY_URL]: bot88 } });
    assertEqual(refused.code, 1, `off main\n${refused.out}`);
    assert(/TRUST-3: Source-Commit .* not reachable/.test(refused.out), `the refusal is not TRUST-3's:\n${refused.out}`);
    assertEqual(refOf(bot88, "refs/heads/signed"), null, "a TRUST-3 refusal pushed");
    const dry = await push(["--step", "0", "--dry-run", "--skip-pages"], { to: { [CANARY_URL]: bot88 } });
    assertEqual(dry.code, 1, `a dry run that the real run would refuse exits 1\n${dry.out}`);
    const allowed = await push(["--step", "0", "--skip-pages", "--allow-source-off-main", "the service applies no TRUST-3"],
      { to: { [CANARY_URL]: bot88 } });
    assertEqual(allowed.code, 0, `allowed\n${allowed.out}`);
    assert(/going on because: the service applies no TRUST-3/.test(allowed.out), `the reason was not printed:\n${allowed.out}`);
    // The byte-identity half, on committed material: step 1's trust.json at step 0's Source-Commit is not step 1's.
    const g = gitAt(day);
    assertEqual(sourceCheck(g, rotation[1], "refs/heads/main").ok, true, "step 1 against the merged main");
    const swapped = { ...rotation[1], sourceCommit: rotation[0].sourceCommit };
    const verdict = sourceCheck(g, swapped, "refs/heads/main");
    assert(!verdict.ok && /trust\.json .* not byte-identical/.test(verdict.why), `a differing trust.json passed: ${JSON.stringify(verdict)}`);
  });

  await test("a judge that fails, or no judge at all, stops the run before git is asked anything", async () => {
    const fresh = canary();
    const failing = await push(["--step", "0", "--skip-pages"], { to: { [CANARY_URL]: fresh }, judge: () => ({ ok: false, detail: "1 failed" }) });
    assertEqual(failing.code, 1, `a failing judge\n${failing.out}`);
    assert(/did not pass their judge: 1 failed/.test(failing.out), `the judge's verdict was not printed:\n${failing.out}`);
    const none = await push(["--step", "0", "--skip-pages"], { to: { [CANARY_URL]: fresh }, judge: null });
    assertEqual(none.code, 1, `no judge\n${none.out}`);
    assertEqual(refOf(fresh, "refs/heads/signed"), null, "a run with a failing judge pushed");
  });

  await test("Pages: a step is done only when Pages serves its four documents byte for byte", async () => {
    const served = await push(["--step", "1"], { to, fetchImpl: pagesFrom(day) });
    assertEqual(served.code, 0, `Pages from \`signed\`\n${served.out}`);
    assert(/Pages serves step 1's four documents/.test(served.out), `Pages was not checked:\n${served.out}`);
    const notFound = async () => ({ status: 404, arrayBuffer: async () => new ArrayBuffer(0) });
    const absent = await push(["--step", "1", "--pages-timeout", "60"], { to, fetchImpl: notFound });
    assertEqual(absent.code, 1, `Pages not enabled\n${absent.out}`);
    assert(/404: is Pages enabled on branch `signed`\?/.test(absent.out), `the failure does not say Pages is absent:\n${absent.out}`);
    const stepZero = async (url) => {
      const b = rotation[0].docs[url.slice(PAGES.length).split("?")[0]];
      return { status: 200, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.length) };
    };
    const stale = await push(["--step", "1", "--pages-timeout", "60"], { to, fetchImpl: stepZero });
    assertEqual(stale.code, 1, `Pages still serving step 0\n${stale.out}`);
    assert(/Pages serves step 0, not step 1/.test(stale.out), `the failure does not name the step Pages serves:\n${stale.out}`);
    // A build that lands on the third poll is waited for, and the wait is reported.
    let polls = 0;
    const real = pagesFrom(day);
    const late = async (url) => (++polls <= 8 ? notFound() : real(url));
    let now = 0;
    const waited = await waitPages(late, rotation, 1, { timeoutMs: 600_000, intervalMs: 10_000, sleep: async (ms) => { now += ms; }, clock: () => now, base: PAGES });
    assert(waited.ok && waited.waited_ms === 20_000, `the late build was not waited for: ${JSON.stringify({ ok: waited.ok, ms: waited.waited_ms })}`);
  });

  await test("the compromise line goes to `signed-compromise`, never `signed`, and ends at the compromise commit", async () => {
    const fresh = canary();
    for (let n = 0; n < compromise.length; n++) {
      const r = await push(["--series", "compromise", "--step", String(n)], { to: { [CANARY_URL]: fresh } });
      assertEqual(r.code, 0, `compromise step ${n}\n${r.out}`);
    }
    assertEqual(refOf(fresh, "refs/heads/signed-compromise"), compromise[3].sha, "`signed-compromise` after its last step");
    assertEqual(refOf(fresh, "refs/heads/signed"), null, "the compromise line touched `signed`");
  });

  await test("--export-source writes every Source-Commit the manifest names, on the line it belongs to", () => {
    const g = gitIn(sourceHistory());
    for (const s of [...rotation, compromise[3]]) {
      const line = s.id.startsWith("compromise/") ? "compromise" : "rotation";
      execFileSync("git", ["-C", sourceHistory(), "merge-base", "--is-ancestor", s.sourceCommit, `refs/rehearsal-source/${line}`],
        { env: fixtureEnv(sourceHistory()) });
    }
    assert(refsOf(sourceHistory()).includes("refs/rehearsal-source/rotation"), "no rotation ref");
    assertEqual(g("cat-file", "-t", rotation[5].sourceCommit), "commit", "the last rotation Source-Commit");
  });

  await test("--status names the step each branch is at and whether TRUST-3 holds for every step", async () => {
    const r = await push(["--status"], { to, fetchImpl: pagesFrom(day) });
    assertEqual(r.code, 0, `status\n${r.out}`);
    assert(r.out.includes(`\`signed\`: step 1 (rotation/01-delegate) ${sha(1)}`), `status does not name step 1:\n${r.out}`);
    assert(/5 {2}rotation\/05-after-root +pending {2}TRUST-3 holds/.test(r.out), `status does not ask TRUST-3 of step 5:\n${r.out}`);
    assert(/Pages: serving step 1/.test(r.out), `status does not name the Pages step:\n${r.out}`);
  });

  await test("a step whose list has expired is refused before anything is pushed (SERVE-22; the hard end, 2026-09-29)", async () => {
    const fresh = canary();
    const late = await push(["--step", "0", "--skip-pages"], { to: { [CANARY_URL]: fresh }, at: "2026-09-29T00:00:00Z" });
    assertEqual(late.code, 1, `at the list's expiry\n${late.out}`);
    assert(/registry\/v1\/revocations\.json expired at 2026-09-29T00:00:00Z/.test(late.out), `the refusal does not name the list:\n${late.out}`);
    assertEqual(refOf(fresh, "refs/heads/signed"), null, "an expired step was pushed");
    const inTime = await push(["--step", "0", "--skip-pages"], { to: { [CANARY_URL]: fresh }, at: "2026-09-28T23:59:59Z" });
    assertEqual(inTime.code, 0, `a second before the expiry\n${inTime.out}`);
    const status = await push(["--status"], { to: { [CANARY_URL]: fresh }, at: "2026-09-30T00:00:00Z" });
    assert(/hard end: .* 2026-09-29T00:00:00Z — PASSED/.test(status.out), `--status does not say the hard end passed:\n${status.out}`);
  });

  await test("the command line refuses what it cannot parse, with exit 2", async () => {
    for (const argv of [[], ["--step", "1", "--status"], ["--step", "one"], ["--step", "6"], ["--series", "other", "--list"], ["--push"]]) {
      const r = await push(argv, { to });
      assertEqual(r.code, 2, `${JSON.stringify(argv)}\n${r.out}`);
    }
    assertEqual(refOf(day, "refs/heads/signed"), sha(1), "a refused command line moved `signed`");
  });
}
