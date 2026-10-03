// ROLL-60's rehearsal, pushed: `tools/lib/rehearsal-push.mjs`, driven the way
// the operator's `tools/testkeys/rehearsal-push.mjs --step N` drives it, against
// local bare repositories standing in for the three canaries and for the
// production registry. git is pointed at them with `url.<bare>.insteadOf` for
// the real GitHub URLs, so the code under test builds, checks and pushes to
// exactly the URL it would on the day, and nothing here reaches the network:
// every rewrite target that is not a local bare is a `.invalid` host, and so
// is every GitHub URL a check did not redirect (`NOWHERE`, below).
//
// **Why these and not a first run.** The day this runs for real, a staging
// service and a debug daemon accept or refuse a key rotation on the strength of
// what it pushed, one commit at a time, onto a branch that cannot be rewound —
// and the one refusal that matters most, never to push to
// `mihailinl/astra-registry`, has no second chance at all. Nor has the second:
// a cut pushed to another cut's canary burns that canary's `signed` for good.
// So each rule is asked here, and each was watched failing by breaking the line
// it names.
//
// The library is imported whole and read off the namespace, so a name it stops
// exporting fails the checks that use it, by name, rather than failing to load.

import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fixtureEnv } from "../lib/git-env.mjs";

import * as rp from "../lib/rehearsal-push.mjs";
import { REHEARSALS } from "../testkeys/make-rehearsal-r2.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

const {
  CANARIES, DEFAULT_CANARY, PRODUCTION_SLUG, SERIES, buildCommits, effectiveUrlProblem, exportSource, fixturesProblem,
  gitAt, loadSeries, main, pagesBaseOf, sourceCheck, targetProblem, waitPages,
} = rp;

const ROOT = path.join(tmp, "rehearsal-push");
/** The first canary, which serves the first cut (T0 2026-09-22). */
const CANARY_1 = "mihailinl/astra-registry-canary";
/** The second, which serves the cut at T0 2026-09-26 (hard end 2026-10-03). */
const CANARY_2 = "mihailinl/astra-registry-canary-2";
/** The third, which serves the cut at T0 2026-10-24 (hard end 2026-10-31): the default. */
const CANARY_3 = "mihailinl/astra-registry-canary-3";
const OLD = "rehearsal-r2";
const MID = "rehearsal-r2b";
const NEW = "rehearsal-r2c";
const URL_1 = `https://github.com/${CANARY_1}.git`;
const URL_2 = `https://github.com/${CANARY_2}.git`;
const URL_3 = `https://github.com/${CANARY_3}.git`;
const PRODUCTION_URL = "https://github.com/mihailinl/astra-registry.git";
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

/**
 * Where a GitHub URL goes that no check sent to a local bare: a host that does
 * not exist. git rewrites with the longest matching `insteadOf`, so a check's
 * own full-URL redirect still wins over this prefix.
 */
const NOWHERE = "https://github.invalid/";

/** `-c` options sending each GitHub URL to a local bare (or anywhere), and every other one to `NOWHERE`. */
const redirect = (map) => [
  `url.${NOWHERE}.insteadOf=https://github.com/`,
  ...Object.entries(map).map(([from, to]) => `url.${to}.insteadOf=${from}`),
];

/**
 * A canary's `main` before and after the rehearsal's sources were merged in
 * with `-s ours` — the canary pull request, rebuilt here from `exportSource`'s
 * refs for one cut, so TRUST-3 is asked of the shape each canary really has.
 */
const sourceBares = new Map();
function sourceHistory(fixtures = NEW) {
  if (sourceBares.has(fixtures)) return sourceBares.get(fixtures);
  const dir = bare(`sources-${fixtures}`);
  const heads = exportSource(dir, { fixtures });
  const g = gitIn(dir);
  const run = gitAt(dir);
  const who = { name: "t", email: "t@users.noreply.invalid", date: "2026-09-24T00:00:00Z" };
  const commit = (args, message) => run(["commit-tree", ...args], { input: message, who }).out;
  const blob = run(["hash-object", "-w", "--stdin"], { input: "a rehearsal canary\n" }).out;
  const tree = run(["mktree"], { input: `100644 blob ${blob}\tREADME.md\n` }).out;
  const before = commit([tree], "the canary's main\n");
  const merged = commit([tree, "-p", before, "-p", heads.rotation, "-p", heads.compromise], "the rehearsal's sources, -s ours\n");
  g("update-ref", "refs/heads/bot88-main", before);
  g("update-ref", "refs/heads/merged-main", merged);
  sourceBares.set(fixtures, dir);
  return dir;
}

/** A canary stand-in whose `main` is `which` of the two above, for `fixtures`' sources. */
function canary(which = "merged-main", fixtures = NEW) {
  const dir = bare(`canary-${fixtures}`);
  gitIn(dir)("fetch", "--quiet", sourceHistory(fixtures), `+refs/heads/${which}:refs/heads/main`);
  return dir;
}

/** Pages built from `branch` of `dir`, the way a canary's legacy Pages build serves `signed`. */
function pagesFrom(dir, branch = "signed", base = PAGES) {
  return async (url) => {
    const rel = url.slice(base.length).split("?")[0];
    const r = spawnSync("git", ["-C", dir, "cat-file", "blob", `refs/heads/${branch}:${rel}`], { env: fixtureEnv(dir) });
    if (r.status !== 0) return { status: 404, arrayBuffer: async () => new ArrayBuffer(0) };
    const b = Buffer.from(r.stdout);
    return { status: 200, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.length) };
  };
}

const okJudge = () => ({ ok: true, detail: "a stub" });

/** One run of the command line, with the day's URLs sent to local bares. `pagesBase: null` asks the canary's own. */
async function push(argv, { to = {}, gitConfig = [], fetchImpl = null, judge = okJudge, at = "2026-09-26T12:00:00Z", pagesBase = PAGES } = {}) {
  const lines = [];
  let now = Date.parse(at);
  const code = await main(argv, {
    gitConfig: [...redirect(to), ...gitConfig],
    fetchImpl,
    judge,
    log: (l) => lines.push(l),
    sleep: async (ms) => { now += ms; },
    clock: () => now,
    ...(pagesBase ? { pagesBase } : {}),
  });
  return { code, out: lines.join("\n") };
}

export async function run() {
  console.log("\nROLL-60's rehearsal, pushed one step at a time (tools/lib/rehearsal-push.mjs)");

  await test("a GitHub URL no check redirects goes nowhere, so this suite cannot push to a real canary whatever the default is", async () => {
    // On 2026-10-03 it did. The checks had been moved to canary-3, the new
    // default, before the library had; the library still defaulted to
    // canary-2, which no check's `to` named any more, so git took the real
    // https://github.com/mihailinl/astra-registry-canary-2.git with the
    // operator's credentials and pushed rotation steps 1 and 2 and the whole
    // compromise line onto it. Its `signed` is append-only and stays so.
    // Nothing here may depend on every check naming every canary.
    const probe = bare("nowhere");
    const g = gitAt(probe, redirect({}));
    for (const url of [URL_1, URL_2, URL_3, PRODUCTION_URL, "https://github.com/mihailinl/astra-registry-canary-4.git"]) {
      g(["remote", "add", "x", url]);
      for (const args of [["remote", "get-url", "x"], ["remote", "get-url", "--push", "x"]]) {
        const got = g(args).out;
        assert(got.startsWith(NOWHERE), `with no redirect, git would ${args.includes("--push") ? "push to" : "fetch from"} ${url} as ${got}`);
      }
      g(["remote", "remove", "x"]);
    }
    // And the run itself, for every canary, with nothing redirected: refused
    // before git fetches, because the URL git would use is not the canary's.
    for (const extra of [[], ["--repo", CANARY_1], ["--repo", CANARY_2], ["--repo", CANARY_3]]) {
      const r = await push(["--step", "0", "--skip-pages", ...extra], { to: {} });
      assertEqual(r.code, 2, `--step 0 ${extra.join(" ")} with nothing redirected: exit code\n${r.out}`);
      assert(r.out.includes("github.invalid"), `the refusal does not name where git was sent:\n${r.out}`);
    }
  });

  const cut = (fixtures) => ({ rotation: loadSeries("rotation", { fixtures }), compromise: loadSeries("compromise", { fixtures }) });
  const cuts = { [OLD]: cut(OLD), [MID]: cut(MID), [NEW]: cut(NEW) };
  const rotation = cuts[NEW].rotation;
  const compromise = cuts[NEW].compromise;
  const sha = (i) => rotation[i].sha;

  await test("every commit of both lines of every cut rebuilds to the sha the real signer committed (manifest.json)", () => {
    for (const [fixtures, lines] of Object.entries(cuts)) {
      for (const [name, steps] of Object.entries(lines)) {
        const shas = buildCommits(gitAt(bare(`rebuild-${fixtures}-${name}`)), steps);
        assertEqual(shas.length, SERIES[name].steps.length, `${fixtures} ${name}: every step rebuilt`);
        steps.forEach((s, i) => assertEqual(shas[i], s.sha, `${fixtures} ${name} step ${i} (${s.id})`));
      }
      assertEqual(lines.rotation.length, 6, `${fixtures}: the rotation line is the base and ROLL-60's five commits`);
      assertEqual(lines.compromise[3].parent, lines.rotation[2].sha, `${fixtures}: the compromise commit forks from rotation step 2`);
    }
    // The first two cuts are records: each canary's `signed` carries its step 0.
    assertEqual(cuts[OLD].rotation[0].sha, "753cf52cc5a56817b519684bfbc1dc0466a13113", "the first cut's step 0 moved");
    assertEqual(cuts[MID].rotation[0].sha, "45da22f4d9f962635b90f7d15ae3c56d102af7b0", "the second cut's step 0 moved");
    // A manifest whose T0 is not the generator's is refused, so a cut and its directory cannot drift apart.
    const drifted = path.join(ROOT, "drifted-manifest.json");
    fs.mkdirSync(ROOT, { recursive: true });
    const m = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "tools", "testkeys", "fixtures", NEW, "manifest.json"), "utf8"));
    fs.writeFileSync(drifted, JSON.stringify({ ...m, t0: REHEARSALS[OLD].t0 }));
    let refused = null;
    try { loadSeries("rotation", { fixtures: NEW, manifestFile: drifted }); } catch (e) { refused = e; }
    assert(refused && refused.code === "FIXTURE" && /T0/.test(refused.message),
      `a manifest with another cut's T0 was loaded: ${refused?.message ?? "no refusal"}`);
  });

  await test("REFUSED: every spelling of mihailinl/astra-registry, with any cut, and every bare stand-in is left with no `signed`", async () => {
    const production = canary();
    const one = canary("merged-main", OLD);
    const two = canary("merged-main", MID);
    const three = canary();
    const to = { [URL_1]: one, [URL_2]: two, [URL_3]: three, [PRODUCTION_URL]: production };
    const spellings = [
      "mihailinl/astra-registry", "Mihailinl/Astra-Registry", "MIHAILINL/ASTRA-REGISTRY", "mihailinl/astra-registry.git",
      "https://github.com/mihailinl/astra-registry.git", "https://github.com/mihailinl/astra-registry",
      "http://github.com/mihailinl/astra-registry", "https://www.github.com/mihailinl/astra-registry/",
      "git@github.com:mihailinl/astra-registry.git", "ssh://git@github.com/mihailinl/astra-registry.git",
      " mihailinl/astra-registry ",
    ];
    for (const spelling of spellings) {
      for (const extra of [[], ["--fixtures", OLD], ["--fixtures", MID], ["--fixtures", NEW]]) {
        const r = await push(["--step", "0", "--repo", spelling, ...extra, "--skip-pages"], { to });
        assertEqual(r.code, 2, `--repo ${JSON.stringify(spelling)} ${extra.join(" ")}: exit code\n${r.out}`);
        assert(/REFUSED .*production registry/.test(r.out), `--repo ${JSON.stringify(spelling)} was not refused as the production registry:\n${r.out}`);
      }
    }
    for (const other of ["mihailinl/AstraPlugins", "mihailinl/astra-registry-canary-4", "someone/astra-registry-canary-3",
      "mihailinl/astra-registry-canary-3-old", "mihailinl/astra-registry-canary3", "mihailinl/astra-registry-canary-2-old",
      "mihailinl/astra-registry-canary2"]) {
      const r = await push(["--step", "0", "--repo", other, "--skip-pages"], { to });
      assertEqual(r.code, 2, `--repo ${other}: exit code\n${r.out}`);
      assert(/REFUSED .*not one of/.test(r.out), `--repo ${other} was not refused as a stranger:\n${r.out}`);
    }
    for (const dir of [production, one, two, three]) assertEqual(refOf(dir, "refs/heads/signed"), null, `a refused run pushed to ${dir}`);
    assertEqual(targetProblem(CANARY_1), null, "the first canary itself is refused");
    assertEqual(targetProblem(CANARY_2), null, "the second canary itself is refused");
    assertEqual(targetProblem(CANARY_3), null, "the third canary itself is refused");
    assert(targetProblem(PRODUCTION_SLUG) !== null, "the production registry is accepted");
  });

  await test("a cut is served on its own canary only: every cut on every other canary is refused, pushing nothing", async () => {
    // CANARIES is the one table, and it is a bijection with the generator's cuts.
    assertEqual(Object.keys(CANARIES).sort().join(" "), [CANARY_1, CANARY_2, CANARY_3].sort().join(" "), "the canaries");
    assertEqual(Object.values(CANARIES).map((c) => c.fixtures).sort().join(" "), Object.keys(REHEARSALS).sort().join(" "),
      "every cut has exactly one canary");
    assertEqual(CANARIES[CANARY_1].fixtures, OLD, "the first canary's cut");
    assertEqual(CANARIES[CANARY_2].fixtures, MID, "canary-2's cut");
    assertEqual(CANARIES[CANARY_3].fixtures, NEW, "canary-3's cut");
    // The default is the canary whose cut ends last. A default left on a cut
    // whose hard end has passed sends every bare `--step N` to a refusal, and
    // the runbook's commands carry no `--repo`.
    const latest = Object.keys(REHEARSALS).sort((a, b) => Date.parse(REHEARSALS[b].t0) - Date.parse(REHEARSALS[a].t0))[0];
    assertEqual(CANARIES[DEFAULT_CANARY].fixtures, latest, "the default canary does not serve the cut that ends last");
    assertEqual(DEFAULT_CANARY, CANARY_3, "the default canary is the one the day's walk reads");
    for (const [repo, fixtures] of [[CANARY_1, OLD], [CANARY_2, MID], [CANARY_3, NEW]]) {
      assertEqual(fixturesProblem(repo, fixtures), null, `${fixtures} on its own canary ${repo}`);
    }

    const one = canary("merged-main", OLD);
    const two = canary("merged-main", MID);
    const three = canary();
    const to = { [URL_1]: one, [URL_2]: two, [URL_3]: three };
    const owner = { [OLD]: CANARY_1, [MID]: CANARY_2, [NEW]: CANARY_3 };
    for (const repo of [CANARY_1, CANARY_2, CANARY_3]) {
      for (const fixtures of [OLD, MID, NEW]) {
        if (owner[fixtures] === repo) continue;
        const own = owner[fixtures];
        assert(fixturesProblem(repo, fixtures) !== null, `${fixtures} is accepted on ${repo}`);
        for (const mode of [["--step", "0", "--skip-pages"], ["--step", "0", "--dry-run", "--skip-pages"], ["--status"], ["--list"]]) {
          const r = await push([...mode, "--repo", repo, "--fixtures", fixtures], { to });
          assertEqual(r.code, 2, `${mode.join(" ")} --repo ${repo} --fixtures ${fixtures}: exit code\n${r.out}`);
          assert(r.out.includes(`REFUSED ${fixtures}`) && r.out.includes(own),
            `the refusal does not name the cut and its own canary (${own}):\n${r.out}`);
        }
      }
    }
    for (const [dir, name] of [[one, "the first canary"], [two, "canary-2"], [three, "canary-3"]]) {
      assertEqual(refOf(dir, "refs/heads/signed"), null, `another cut reached ${name}`);
    }

    // Either knob alone names the pair: no --repo is canary-3 with the newest
    // cut; --repo alone derives the cut, and --fixtures alone derives the canary.
    const byDefault = await push(["--step", "0", "--skip-pages"], { to });
    assertEqual(byDefault.code, 0, `the default\n${byDefault.out}`);
    assertEqual(refOf(three, "refs/heads/signed"), cuts[NEW].rotation[0].sha, "the default pushed something other than the newest cut to canary-3");
    const byRepo = await push(["--step", "0", "--repo", CANARY_1, "--skip-pages"], { to });
    assertEqual(byRepo.code, 0, `--repo ${CANARY_1}\n${byRepo.out}`);
    assertEqual(refOf(one, "refs/heads/signed"), cuts[OLD].rotation[0].sha, "--repo alone did not serve the old cut");
    const byRepo2 = await push(["--step", "0", "--repo", CANARY_2, "--dry-run", "--skip-pages"], { to });
    assertEqual(byRepo2.code, 0, `--repo ${CANARY_2}\n${byRepo2.out}`);
    assert(byRepo2.out.includes(`would push ${cuts[MID].rotation[0].sha}`), `--repo ${CANARY_2} alone did not derive its cut:\n${byRepo2.out}`);
    const byFixtures = await push(["--step", "1", "--fixtures", OLD, "--dry-run", "--skip-pages"], { to });
    assertEqual(byFixtures.code, 0, `--fixtures ${OLD}\n${byFixtures.out}`);
    assert(byFixtures.out.includes(`would push ${cuts[OLD].rotation[1].sha}`), `--fixtures alone did not aim at the first canary:\n${byFixtures.out}`);
  });

  await test("no two cuts share a commit or a Source-Commit, so one cut's head is a foreign head to another", async () => {
    const shasOf = (fixtures) => [...cuts[fixtures].rotation, ...cuts[fixtures].compromise].flatMap((s) => [s.sha, s.sourceCommit]);
    const names = Object.keys(cuts);
    for (let i = 0; i < names.length; i++) {
      for (let j = i + 1; j < names.length; j++) {
        const seen = new Set(shasOf(names[i]));
        const shared = shasOf(names[j]).filter((s) => seen.has(s));
        assertEqual(shared.join(" "), "", `a commit is in both ${names[i]} and ${names[j]}`);
      }
    }
    // canary-3 with the second cut's step 0 on `signed`, as a push that got
    // past the refusal above would have left it: the next step is refused, not stacked.
    const three = canary();
    buildCommits(gitAt(three), cuts[MID].rotation.slice(0, 1));
    gitIn(three)("update-ref", "refs/heads/signed", cuts[MID].rotation[0].sha);
    const r = await push(["--step", "1", "--skip-pages"], { to: { [URL_3]: three } });
    assertEqual(r.code, 1, `the newest cut on top of another's head\n${r.out}`);
    assert(/no commit of this series/.test(r.out), `the refusal does not say the head is foreign:\n${r.out}`);
    assertEqual(refOf(three, "refs/heads/signed"), cuts[MID].rotation[0].sha, "a foreign head was moved");
  });

  await test("an insteadOf or pushInsteadOf that sends a canary's URL elsewhere, the other canary included, is refused before git fetches or pushes", async () => {
    assertEqual(effectiveUrlProblem(URL_3, URL_3, "push"), null, "canary-3's own URL");
    assertEqual(effectiveUrlProblem("/tmp/x.git", URL_3, "push"), null, "a local bare");
    assert(effectiveUrlProblem(PRODUCTION_URL, URL_3, "push") !== null, "the production URL passed as canary-3's");
    assert(effectiveUrlProblem(URL_1, URL_3, "push") !== null, "the first canary's URL passed as canary-3's");
    assert(effectiveUrlProblem(URL_2, URL_3, "push") !== null, "canary-2's URL passed as canary-3's");
    assert(effectiveUrlProblem("git@github.com:mihailinl/astra-registry.git", URL_3, "fetch") !== null, "an ssh rewrite passed");
    const target = canary();
    const fetchAway = await push(["--step", "0", "--skip-pages"], { to: { [URL_3]: "https://github.invalid/mihailinl/astra-registry.git" } });
    assertEqual(fetchAway.code, 2, `insteadOf to another host: exit code\n${fetchAway.out}`);
    assert(/insteadOf/.test(fetchAway.out), `the refusal does not name the rewrite:\n${fetchAway.out}`);
    const pushAway = await push(["--step", "0", "--skip-pages"], {
      to: { [URL_3]: target },
      gitConfig: [`url.https://github.invalid/mihailinl/astra-registry.git.pushInsteadOf=${URL_3}`],
    });
    assertEqual(pushAway.code, 2, `pushInsteadOf to another host: exit code\n${pushAway.out}`);
    const two = canary("merged-main", MID);
    const crossed = await push(["--step", "0", "--skip-pages"], {
      to: { [URL_2]: two, [URL_3]: target },
      gitConfig: [`url.${URL_2}.pushInsteadOf=${URL_3}`],
    });
    assertEqual(crossed.code, 2, `canary-3's push rewritten to canary-2: exit code\n${crossed.out}`);
    assertEqual(refOf(target, "refs/heads/signed"), null, "a refused run pushed");
    assertEqual(refOf(two, "refs/heads/signed"), null, "a refused run pushed the newest cut to canary-2");
  });

  const day = canary();
  const to = { [URL_3]: day };

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
    const r = await push(["--step", "1", "--skip-pages"], { to: { [URL_3]: foreign } });
    assertEqual(r.code, 1, `a foreign head\n${r.out}`);
    assert(/no commit of this series/.test(r.out), `the refusal does not say the head is foreign:\n${r.out}`);
  });

  await test("--dry-run pushes nothing and names the commit a real run would push", async () => {
    const fresh = canary();
    const r = await push(["--step", "0", "--dry-run", "--skip-pages"], { to: { [URL_3]: fresh } });
    assertEqual(r.code, 0, `dry run\n${r.out}`);
    assert(r.out.includes(`would push ${sha(0)}`), `the dry run does not name the commit:\n${r.out}`);
    assertEqual(refOf(fresh, "refs/heads/signed"), null, "a dry run pushed");
  });

  await test("TRUST-3: a Source-Commit the canary's main does not reach is refused, the other cut's merge included; --allow-source-off-main says why it went on", async () => {
    const before = canary("bot88-main");
    const refused = await push(["--step", "0", "--skip-pages"], { to: { [URL_3]: before } });
    assertEqual(refused.code, 1, `off main\n${refused.out}`);
    assert(/TRUST-3: Source-Commit .* not reachable/.test(refused.out), `the refusal is not TRUST-3's:\n${refused.out}`);
    assertEqual(refOf(before, "refs/heads/signed"), null, "a TRUST-3 refusal pushed");
    // A main that merged ANOTHER cut's sources: a regenerated series needs its own -s ours merge.
    const wrongMerge = canary("merged-main", MID);
    const other = await push(["--step", "0", "--skip-pages"], { to: { [URL_3]: wrongMerge } });
    assertEqual(other.code, 1, `a main carrying the old cut's sources\n${other.out}`);
    assert(/TRUST-3: Source-Commit .* not reachable/.test(other.out), `the refusal is not TRUST-3's:\n${other.out}`);
    const dry = await push(["--step", "0", "--dry-run", "--skip-pages"], { to: { [URL_3]: before } });
    assertEqual(dry.code, 1, `a dry run that the real run would refuse exits 1\n${dry.out}`);
    const allowed = await push(["--step", "0", "--skip-pages", "--allow-source-off-main", "the service applies no TRUST-3"],
      { to: { [URL_3]: before } });
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
    const failing = await push(["--step", "0", "--skip-pages"], { to: { [URL_3]: fresh }, judge: () => ({ ok: false, detail: "1 failed" }) });
    assertEqual(failing.code, 1, `a failing judge\n${failing.out}`);
    assert(/did not pass their judge: 1 failed/.test(failing.out), `the judge's verdict was not printed:\n${failing.out}`);
    const none = await push(["--step", "0", "--skip-pages"], { to: { [URL_3]: fresh }, judge: null });
    assertEqual(none.code, 1, `no judge\n${none.out}`);
    assertEqual(refOf(fresh, "refs/heads/signed"), null, "a run with a failing judge pushed");
  });

  await test("Pages: a step is done only when the canary's own Pages serves its four documents byte for byte", async () => {
    assertEqual(pagesBaseOf(CANARY_3), "https://mihailinl.github.io/astra-registry-canary-3/", "canary-3's Pages");
    assertEqual(pagesBaseOf(CANARY_2), "https://mihailinl.github.io/astra-registry-canary-2/", "canary-2's Pages");
    assertEqual(pagesBaseOf(CANARY_1), "https://mihailinl.github.io/astra-registry-canary/", "the first canary's Pages");
    // With no override, the URLs asked are the canary's own project Pages.
    const asked = [];
    const recorder = async (url) => { asked.push(url); return { status: 404, arrayBuffer: async () => new ArrayBuffer(0) }; };
    await push(["--status"], { to, fetchImpl: recorder, pagesBase: null });
    assert(asked.length === 4 && asked.every((u) => u.startsWith("https://mihailinl.github.io/astra-registry-canary-3/registry/v1/")),
      `--status asked Pages somewhere else: ${asked.join(" ")}`);

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
      const r = await push(["--series", "compromise", "--step", String(n)], { to: { [URL_3]: fresh } });
      assertEqual(r.code, 0, `compromise step ${n}\n${r.out}`);
    }
    assertEqual(refOf(fresh, "refs/heads/signed-compromise"), compromise[3].sha, "`signed-compromise` after its last step");
    assertEqual(refOf(fresh, "refs/heads/signed"), null, "the compromise line touched `signed`");
  });

  await test("--export-source writes every Source-Commit each cut's manifest names, on the line it belongs to", () => {
    for (const fixtures of [OLD, NEW]) {
      const dir = sourceHistory(fixtures);
      const g = gitIn(dir);
      for (const s of [...cuts[fixtures].rotation, cuts[fixtures].compromise[3]]) {
        const line = s.id.startsWith("compromise/") ? "compromise" : "rotation";
        execFileSync("git", ["-C", dir, "merge-base", "--is-ancestor", s.sourceCommit, `refs/rehearsal-source/${line}`],
          { env: fixtureEnv(dir) });
      }
      assert(refsOf(dir).includes("refs/rehearsal-source/rotation"), `${fixtures}: no rotation ref`);
      assertEqual(g("cat-file", "-t", cuts[fixtures].rotation[5].sourceCommit), "commit", `${fixtures}: the last rotation Source-Commit`);
    }
  });

  await test("--status names the canary, the cut, the step each branch is at and whether TRUST-3 holds for every step", async () => {
    const r = await push(["--status"], { to, fetchImpl: pagesFrom(day) });
    assertEqual(r.code, 0, `status\n${r.out}`);
    assert(r.out.includes(`${CANARY_3}, fixtures ${NEW} (T0 2026-10-24T00:00:00Z)`), `status does not name the canary and the cut:\n${r.out}`);
    assert(r.out.includes("hard end: the series' first list expires at 2026-10-31T00:00:00Z"), `status does not print canary-3's hard end:\n${r.out}`);
    assert(r.out.includes(`\`signed\`: step 1 (rotation/01-delegate) ${sha(1)}`), `status does not name step 1:\n${r.out}`);
    assert(/5 {2}rotation\/05-after-root +pending {2}TRUST-3 holds/.test(r.out), `status does not ask TRUST-3 of step 5:\n${r.out}`);
    assert(/Pages: serving step 1/.test(r.out), `status does not name the Pages step:\n${r.out}`);
  });

  await test("a step whose list has expired is refused before anything is pushed (SERVE-22; hard ends 2026-09-29, 2026-10-03 and 2026-10-31)", async () => {
    // The first cut, on the first canary.
    const one = canary("merged-main", OLD);
    const late1 = await push(["--step", "0", "--repo", CANARY_1, "--skip-pages"], { to: { [URL_1]: one }, at: "2026-09-29T00:00:00Z" });
    assertEqual(late1.code, 1, `the first cut at its list's expiry\n${late1.out}`);
    assert(/registry\/v1\/revocations\.json expired at 2026-09-29T00:00:00Z/.test(late1.out), `the refusal does not name the list:\n${late1.out}`);
    assertEqual(refOf(one, "refs/heads/signed"), null, "an expired step was pushed to the first canary");
    const inTime1 = await push(["--step", "0", "--repo", CANARY_1, "--skip-pages"], { to: { [URL_1]: one }, at: "2026-09-28T23:59:59Z" });
    assertEqual(inTime1.code, 0, `the first cut a second before its expiry\n${inTime1.out}`);

    // The second cut, on canary-2: alive past the first hard end, refused at its own.
    const two = canary("merged-main", MID);
    const pastFirst = await push(["--step", "0", "--repo", CANARY_2, "--dry-run", "--skip-pages"], { to: { [URL_2]: two }, at: "2026-09-29T00:00:00Z" });
    assertEqual(pastFirst.code, 0, `the second cut at the first cut's hard end\n${pastFirst.out}`);
    const late2 = await push(["--step", "0", "--repo", CANARY_2, "--skip-pages"], { to: { [URL_2]: two }, at: "2026-10-03T00:00:00Z" });
    assertEqual(late2.code, 1, `the second cut at its list's expiry\n${late2.out}`);
    assert(/registry\/v1\/revocations\.json expired at 2026-10-03T00:00:00Z/.test(late2.out), `the refusal does not name the list:\n${late2.out}`);
    assertEqual(refOf(two, "refs/heads/signed"), null, "an expired step was pushed to canary-2");
    const inTime2 = await push(["--step", "0", "--repo", CANARY_2, "--skip-pages"], { to: { [URL_2]: two }, at: "2026-10-02T23:59:59Z" });
    assertEqual(inTime2.code, 0, `the second cut a second before its expiry\n${inTime2.out}`);

    // The third cut, on canary-3, the default: alive past the second hard end
    // and through the service's serve (no earlier than 2026-10-06), refused at its own.
    const three = canary();
    const pastSecond = await push(["--step", "0", "--dry-run", "--skip-pages"], { to: { [URL_3]: three }, at: "2026-10-03T00:00:00Z" });
    assertEqual(pastSecond.code, 0, `the third cut at the second cut's hard end\n${pastSecond.out}`);
    const late3 = await push(["--step", "0", "--skip-pages"], { to: { [URL_3]: three }, at: "2026-10-31T00:00:00Z" });
    assertEqual(late3.code, 1, `the third cut at its list's expiry\n${late3.out}`);
    assert(/registry\/v1\/revocations\.json expired at 2026-10-31T00:00:00Z/.test(late3.out), `the refusal does not name the list:\n${late3.out}`);
    assertEqual(refOf(three, "refs/heads/signed"), null, "an expired step was pushed to canary-3");
    const inTime3 = await push(["--step", "0", "--skip-pages"], { to: { [URL_3]: three }, at: "2026-10-30T23:59:59Z" });
    assertEqual(inTime3.code, 0, `the third cut a second before its expiry\n${inTime3.out}`);

    const status3 = await push(["--status"], { to: { [URL_3]: three }, at: "2026-11-01T00:00:00Z" });
    assert(/hard end: .* 2026-10-31T00:00:00Z — PASSED/.test(status3.out), `--status does not say the third hard end passed:\n${status3.out}`);
    const status2 = await push(["--status", "--repo", CANARY_2], { to: { [URL_2]: two }, at: "2026-10-04T00:00:00Z" });
    assert(/hard end: .* 2026-10-03T00:00:00Z — PASSED/.test(status2.out), `--status does not say the second hard end passed:\n${status2.out}`);
    const status1 = await push(["--status", "--repo", CANARY_1], { to: { [URL_1]: one }, at: "2026-09-30T00:00:00Z" });
    assert(/hard end: .* 2026-09-29T00:00:00Z — PASSED/.test(status1.out), `--status does not say the first hard end passed:\n${status1.out}`);
  });

  await test("the command line refuses what it cannot parse, with exit 2", async () => {
    for (const argv of [[], ["--step", "1", "--status"], ["--step", "one"], ["--step", "6"], ["--series", "other", "--list"], ["--push"],
      ["--fixtures"], ["--fixtures", "rehearsal-r3", "--list"], ["--fixtures", "rehearsal-r2d", "--list"], ["--fixtures", "--list"]]) {
      const r = await push(argv, { to });
      assertEqual(r.code, 2, `${JSON.stringify(argv)}\n${r.out}`);
    }
    assertEqual(refOf(day, "refs/heads/signed"), sha(1), "a refused command line moved `signed`");
  });

  await test("the CLI's judge floor is the runner's floor for rehearsal-r2.mjs", () => {
    // Two numbers that mean one thing: `tools/testkeys/rehearsal-push.mjs`
    // refuses a judge that passed fewer checks than JUDGE_FLOOR, and the runner
    // refuses a module that passed fewer than its FLOORS entry. Read as text,
    // because importing either file runs it.
    const cli = fs.readFileSync(path.join(REPO_ROOT, "tools", "testkeys", "rehearsal-push.mjs"), "utf8");
    const runner = fs.readFileSync(path.join(REPO_ROOT, "tools", "selftest.mjs"), "utf8");
    const judgeFloor = /^const JUDGE_FLOOR = (\d+);$/m.exec(cli);
    const floors = [...runner.matchAll(/^\s*"rehearsal-r2\.mjs": (\d+),$/gm)];
    assert(judgeFloor, "tools/testkeys/rehearsal-push.mjs no longer declares `const JUDGE_FLOOR = N;`");
    assertEqual(floors.length, 1, "tools/selftest.mjs does not have exactly one FLOORS line for rehearsal-r2.mjs");
    assertEqual(judgeFloor?.[1], floors[0]?.[1], "JUDGE_FLOOR and the runner's floor for rehearsal-r2.mjs");
  });
}
