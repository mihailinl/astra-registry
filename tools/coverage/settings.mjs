#!/usr/bin/env node
// Are the settings GitHub serves the ones this estate depends on? ops
// `dev/couplings.md` gap 22.
//
//     node tools/coverage/settings.mjs [--repo <dir>] [--expectation <file>] [--report <file>]
//     node tools/coverage/settings.mjs --print-live        # the live read, in the expectation's shape
//
// ── WHAT IT COMPARES ────────────────────────────────────────────────────────
//
// `policy/settings-expected.json` against two things, for every repository it
// lists — astra-registry, AstraPlugins, and BOT-88's test repository
// `mihailinl/astra-registry-canary`, whose environment `canary-tag` holds a
// write deploy key behind a main-only branch policy (registry plan B-T1.6):
//
//   * what GitHub says NOW — every environment with its deployment-branch
//     policy (all refs, protected branches, or a custom list, with every
//     entry's name and type), its protection-rule types and its admin bypass;
//     every ruleset with its target, enforcement, ref conditions and rule
//     types; the default branch; and the rules GitHub says are in force on it.
//     Both directions: a live environment or ruleset the file does not list is
//     red, and so is one the file lists and GitHub does not have;
//   * what the WORKFLOWS say — every environment a job names must be live with
//     a custom branch policy, or listed as pending creation and named only by
//     jobs a literal `if: false` holds. Delete the `if: false` in front of
//     `bot-state` before B-T5.0 creates it, and this is red naming the job and
//     the environment: that job's first run would have GitHub create
//     `bot-state` with no branch policy, which is how `alerts` was found. And
//     an environment no job names is red unless the file says why.
//
// The comparison itself is `tools/lib/settings.mjs`, which reads nothing; this
// file only reads the world and reports.
//
// ── NO CREDENTIAL THAT CAN WRITE, AND THE ONE IT MAY USE ────────────────────
//
// Every read here answers HTTP 200 to a caller with no credential at all,
// because both repositories are public — measured 2026-09-22 for
// `/environments`, `/environments/{name}/deployment-branch-policies`,
// `/rulesets`, `/rulesets/{id}`, `/rules/branches/{branch}` and the repository
// itself. The step passes the workflow's own read-only `GITHUB_TOKEN` for one
// reason, the rate limit: about eighteen reads a run, four runs an hour, is
// over the 60 an hour GitHub gives an unauthenticated address, and a runner's
// address is shared. A read the token is refused is asked again without it,
// and the run says which way each repository was read. It never holds, asks
// for or prints anything that could change a setting.
//
// ── WHAT IT CANNOT ASK, SAID ON EVERY RUN ───────────────────────────────────
//
// `NOT_ASKED` below. Which secrets exist where answers 401 without a
// credential; ruleset bypass actors are left out of a ruleset's detail for a
// caller who cannot write it. Neither is guessed at, and neither is left out
// of the run log: an unasked question printed as nothing reads exactly like an
// answer of none.
//
// A read that FAILS — a timeout, a 5xx, an exhausted rate limit — is red with
// `SETTINGS_NOT_ASKED` and the route by name, never green: an unread setting
// and a setting that matched are otherwise the same colour. Everything that
// could still be read is still compared.
//
// ── IT ALERTS AND IT GATES NOTHING (MOD-46) ─────────────────────────────────
//
// Like every rule in this canary. The repair for a red is a person deciding
// whether the setting or the file is wrong, and changing a setting is an owner
// act (ROLL-3); no job here may do it.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { cleanEnv } from "../lib/git-env.mjs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { report } from "./rules.mjs";
import { astraPluginsRemote, defaultBranch, repoSlug } from "./reserved-id-mirror.mjs";
import {
  EXPECTATION_SCHEMA, branchRulesFromApi, compareSettings, compareTree, environmentFromApi,
  expectationProblems, policyKind, rulesetFromApi, workflowJobs,
} from "../lib/settings.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..", "..");

export const RULE = "repo-settings";

/** The committed expectation. Read by this rule and by no bot run. */
export const EXPECTATION = "policy/settings-expected.json";

const API = "https://api.github.com";

/** Every network call. Long enough for a slow forge, short enough for a fifteen-minute cron. */
const TIMEOUT_MS = 20_000;

/**
 * What this rule does not ask, printed on every run, green included.
 *
 * Each names what it would take to ask it, so that the next reader knows the
 * difference between "checked, and fine" and "not checkable from here".
 */
export const NOT_ASKED = [
  "which secrets exist where, in any repository listed — `/actions/secrets` and `/environments/{name}/secrets` answer 401 " +
    "without a credential, and this rule holds none that can read them. SERVE-9's rule, the R0 runbook's \"zero secrets\" " +
    "in `plugins-service` and `operator`, and `NPM_TOKEN`'s scope are therefore not checked here; the owner's own read " +
    "(ops `tools/read-settings.mjs`) is where they are",
  "ruleset bypass actors — GitHub leaves `bypass_actors` out of a ruleset's detail for a caller who cannot write it, " +
    "so the R0 record's \"zero bypass actors\" is not checked here",
  "whether GitHub actually REFUSES a job in one of these environments from another ref (ROLL-8's watch 4) — a read " +
    "shows the policy, not the refusal",
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * A GET against api.github.com that never throws.
 *
 * With a token, and again without one when the token itself is refused (401,
 * or a 403 that is not the rate limit): every route here is a public read, so
 * a token that cannot read it says something about the token and nothing
 * about the setting. A 5xx, a 429 or a network error is retried once; a
 * rate limit that is exhausted is not, because two seconds will not refill it.
 *
 * @returns {Promise<{ok: true, data: any, auth: string} | {ok: false, why: string}>}
 */
export function githubGetter({ token = process.env.GITHUB_TOKEN || null, timeoutMs = TIMEOUT_MS, attempts = 2, fetchImpl = fetch } = {}) {
  const once = async (route, withToken) => {
    const headers = {
      accept: "application/vnd.github+json",
      "user-agent": "astra-registry-coverage-canary",
      "x-github-api-version": "2022-11-28",
    };
    if (withToken) headers.authorization = `Bearer ${token}`;
    const res = await fetchImpl(`${API}/${route}`, { headers, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
    return { status: res.status, text: await res.text(), remaining: res.headers.get("x-ratelimit-remaining") };
  };
  return async function get(route) {
    let why = "";
    for (let attempt = 1; attempt <= attempts; attempt++) {
      try {
        let r = await once(route, Boolean(token));
        let auth = token ? "the workflow token" : "no credential";
        if (token && (r.status === 401 || r.status === 403) && r.remaining !== "0") {
          r = await once(route, false);
          auth = "no credential (the workflow token was refused)";
        }
        if (r.status === 200) {
          try {
            return { ok: true, data: JSON.parse(r.text), auth };
          } catch {
            return { ok: false, why: `${route}: HTTP 200 and the body is not JSON` };
          }
        }
        let message = "";
        try { message = String(JSON.parse(r.text).message ?? ""); } catch { /* not JSON; the status says enough */ }
        const exhausted = r.remaining === "0";
        why = `${route}: HTTP ${r.status}${exhausted ? ", rate limit exhausted" : ""}${message ? ` — ${message.slice(0, 120)}` : ""}`;
        if (exhausted || (r.status < 500 && r.status !== 429)) break;
      } catch (e) {
        why = `${route}: ${e?.message ?? String(e)}`;
      }
      if (attempt < attempts) await sleep(2000);
    }
    return { ok: false, why };
  };
}

/** A list endpoint's `total_count` against what it returned: one page is all this reads. */
const truncated = (data, list) => typeof data?.total_count === "number" && data.total_count !== list.length;

/**
 * One repository's live settings, normalised to the expectation's shape.
 *
 * A member is present in `live` only when EVERY read behind it succeeded:
 * `compareSettings` compares what is there, and a half-read member would be
 * compared as though the unread half were empty.
 *
 * @returns {Promise<{live: object, notAsked: string[], auth: string[]}>}
 */
export async function readLive(slug, get, { branch = null } = {}) {
  const live = {};
  const notAsked = [];
  const auth = new Set();
  const ask = async (route) => {
    const r = await get(route);
    if (r.ok) auth.add(r.auth);
    return r;
  };

  const repo = await ask(`repos/${slug}`);
  if (repo.ok) live.default_branch = repo.data.default_branch;
  else notAsked.push(`${slug}'s default branch: ${repo.why}`);

  const envs = await ask(`repos/${slug}/environments?per_page=100`);
  if (!envs.ok) {
    notAsked.push(`${slug}'s environments: ${envs.why}`);
  } else {
    const list = envs.data?.environments ?? [];
    let complete = !truncated(envs.data, list);
    if (!complete) notAsked.push(`${slug}'s environments: ${envs.data.total_count} exist and one page held ${list.length}`);
    const out = {};
    for (const env of list) {
      let policies = null;
      if (policyKind(env.deployment_branch_policy) === "custom") {
        const p = await ask(`repos/${slug}/environments/${encodeURIComponent(env.name)}/deployment-branch-policies?per_page=100`);
        if (!p.ok) {
          notAsked.push(`${slug} environment \`${env.name}\`'s branch policies: ${p.why}`);
          complete = false;
          continue;
        }
        policies = p.data?.branch_policies ?? [];
        if (truncated(p.data, policies)) {
          notAsked.push(`${slug} environment \`${env.name}\`'s branch policies: more than one page`);
          complete = false;
        }
      }
      out[env.name] = environmentFromApi(env, policies);
    }
    if (complete) live.environments = out;
  }

  const sets = await ask(`repos/${slug}/rulesets?per_page=100`);
  if (!sets.ok) {
    notAsked.push(`${slug}'s rulesets: ${sets.why}`);
  } else {
    const list = Array.isArray(sets.data) ? sets.data : [];
    let complete = list.length < 100;
    if (!complete) notAsked.push(`${slug}'s rulesets: a full page of 100, so there may be more`);
    const out = [];
    for (const r of list) {
      const d = await ask(`repos/${slug}/rulesets/${r.id}`);
      if (!d.ok) {
        notAsked.push(`${slug} ruleset \`${r.name}\`: ${d.why}`);
        complete = false;
        continue;
      }
      out.push({ name: d.data.name, ...rulesetFromApi(d.data) });
    }
    if (complete) live.rulesets = out;
  }

  const onBranch = live.default_branch ?? branch;
  if (onBranch) {
    const rules = await ask(`repos/${slug}/rules/branches/${encodeURIComponent(onBranch)}?per_page=100`);
    if (rules.ok) live.rules_on_default_branch = branchRulesFromApi(rules.data);
    else notAsked.push(`${slug}'s rules in force on \`${onBranch}\`: ${rules.why}`);
  }
  return { live, notAsked, auth: [...auth] };
}

// ── the trees ───────────────────────────────────────────────────────────────

const WORKFLOW_RE = /^\.github\/workflows\/[^/]+\.ya?ml$/;

/** This checkout's workflow files. GitHub reads the directory's top level only, and so does this. */
export function localWorkflows(repo) {
  const dir = path.join(repo, ".github", "workflows");
  return fs.readdirSync(dir)
    .filter((n) => /\.ya?ml$/.test(n))
    .sort()
    .map((n) => ({ path: `.github/workflows/${n}`, text: fs.readFileSync(path.join(dir, n), "utf8") }));
}

const gitIn = (dir, args, timeoutMs) =>
  execFileSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...cleanEnv(), GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "echo", GIT_CONFIG_NOSYSTEM: "1", GIT_PAGER: "cat" },
  });

/**
 * Another repository's workflow files, off its default branch.
 *
 * The branch from the remote itself (`defaultBranch`, shared with the two
 * AstraPlugins rules — `master` there, and a guess of `main` reads as "the
 * workflows are gone"), then one partial clone, `--filter=blob:none`, and one
 * blob per workflow file. No API call: a directory listing over HTTP would
 * spend the same rate limit the settings reads need.
 *
 * @returns {Promise<{kind: "files", branch: string, files: {path: string, text: string}[]}
 *                  | {kind: "no-branch"|"unreachable", why: string}>}
 */
export async function fetchWorkflows(remoteUrl, { timeoutMs = TIMEOUT_MS * 2 } = {}) {
  let branch;
  try {
    branch = defaultBranch(remoteUrl, { timeoutMs });
  } catch (e) {
    return { kind: "no-branch", why: e.message };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-settings-workflows-"));
  try {
    execFileSync("git", [
      "clone", "--quiet", "--depth=1", "--filter=blob:none", "--no-checkout",
      "--single-branch", "--branch", branch, remoteUrl, dir,
    ], {
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...cleanEnv(), GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "echo", GIT_CONFIG_NOSYSTEM: "1" },
    });
    const paths = gitIn(dir, ["ls-tree", "--name-only", "-z", "HEAD", ".github/workflows/"], timeoutMs)
      .split("\0").filter((p) => WORKFLOW_RE.test(p)).sort();
    const files = paths.map((p) => ({ path: p, text: gitIn(dir, ["show", `HEAD:${p}`], timeoutMs) }));
    return { kind: "files", branch, files };
  } catch (e) {
    const stderr = e && e.stderr ? String(e.stderr).trim() : "";
    return { kind: "unreachable", why: `${remoteUrl} (branch ${branch}): ${stderr || e?.message || String(e)}` };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ── the rule ────────────────────────────────────────────────────────────────

/**
 * @param {string} repo repository root
 * @returns {Promise<{status: "green"|"red", codes: string[], ids: string[], hexes: string[], detail: string[]}>}
 */
export async function run(repo, {
  get = githubGetter(),
  readRemote = fetchWorkflows,
  readLocal = localWorkflows,
  expectation = path.join(repo, EXPECTATION),
  env = process.env,
} = {}) {
  const red = (code, detail) => ({ status: "red", codes: [code], ids: [], hexes: [], detail });
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(expectation, "utf8"));
  } catch (e) {
    return red("SETTINGS_EXPECTATION_UNREADABLE", [
      `${path.relative(repo, expectation) || expectation} could not be read: ${e.message}. Without it there is nothing to ` +
      "compare the live settings to, and a comparison with nothing is not a green one",
    ]);
  }
  const problems = expectationProblems(doc);
  if (problems.length) {
    return red("SETTINGS_EXPECTATION_MALFORMED", problems.map((p) => `${EXPECTATION}: ${p}`));
  }

  const codes = new Set();
  const detail = [];
  const notAsked = [];
  const note = (findings) => {
    for (const f of findings) {
      codes.add(f.code);
      detail.push(`${f.code}  ${f.detail}`);
    }
  };

  for (const [slug, expected] of Object.entries(doc.repositories)) {
    // ── the tree
    let files = null;
    if (expected.tree === "checkout") {
      if (env.GITHUB_REPOSITORY && env.GITHUB_REPOSITORY.toLowerCase() !== slug.toLowerCase()) {
        note([{ code: "SETTINGS_EXPECTATION_REPO", detail: `this checkout is ${env.GITHUB_REPOSITORY}, and ${EXPECTATION} reads it as ${slug}` }]);
      } else {
        files = readLocal(repo);
      }
    } else {
      // A repository that names its own `remote` is read there; one that does
      // not is AstraPlugins, read at the remote this checkout declares, and a
      // declaration that moved is red below rather than followed silently.
      const where = expected.remote
        ? { url: expected.remote, source: `${EXPECTATION}'s own \`remote\`` }
        : astraPluginsRemote(repo);
      if (repoSlug(where.url).toLowerCase() !== slug.toLowerCase()) {
        note([{
          code: "SETTINGS_EXPECTATION_REPO",
          detail: `${EXPECTATION} reads ${slug}'s workflows over git, and ${where.source} says AstraPlugins is ${where.url}. ` +
            "One of the two moved; the expectation has to follow the declaration",
        }]);
      } else {
        const got = await readRemote(where.url);
        if (got.kind === "files") files = got.files;
        else notAsked.push(`${slug}'s workflow tree: ${got.why}`);
      }
    }
    if (files) {
      if (files.length === 0) {
        note([{ code: "SETTINGS_TREE_EMPTY", detail: `${slug}: no workflow file was read, so every environment would read as named by nobody` }]);
      } else {
        const tree = { jobs: [], problems: [] };
        for (const f of files) {
          const r = workflowJobs(f.text, f.path);
          tree.jobs.push(...r.jobs);
          tree.problems.push(...r.problems);
        }
        const { findings, notes } = compareTree(slug, expected, tree);
        note(findings);
        const naming = tree.jobs.filter((j) => j.environment !== null);
        detail.push(`${slug} tree: ${files.length} workflow file(s), ${naming.length} job(s) name an environment ` +
          `(${[...new Set(naming.map((j) => j.environment))].sort().join(", ") || "none"})`);
        detail.push(...notes);
      }
    }

    // ── the live settings
    const { live, notAsked: unread, auth } = await readLive(slug, get, { branch: expected.default_branch });
    notAsked.push(...unread);
    note(compareSettings(slug, expected, live));
    const envNames = live.environments ? Object.keys(live.environments).sort() : null;
    detail.push(`${slug} live, read with ${auth.join(" and ") || "nothing — every read failed"}: ` +
      `${envNames ? `${envNames.length} environment(s) (${envNames.join(", ")})` : "environments not read"}, ` +
      `${live.rulesets ? `${live.rulesets.length} ruleset(s)` : "rulesets not read"}, ` +
      `default branch ${live.default_branch ? `\`${live.default_branch}\`` : "not read"}`);
  }

  for (const n of notAsked) {
    codes.add("SETTINGS_NOT_ASKED");
    detail.push(`NOT ASKED (this run): ${n}`);
  }
  for (const n of NOT_ASKED) detail.push(`NOT ASKED (by design): ${n}`);
  return { status: codes.size ? "red" : "green", codes: [...codes].sort(), ids: [], hexes: [], detail };
}

/**
 * The live read in the expectation's shape, for a person to review and commit.
 *
 * Everything GitHub cannot say — which tree a repository is read from, which
 * environments are pending and why, why one is named by no workflow — is
 * carried over from the committed file. The result is a DRAFT: review it
 * against what the tree claims before committing it, because a setting that
 * drifted and is then re-read into the file is a drift the file now blesses.
 */
export async function printLive(repo, { get = githubGetter(), expectation = path.join(repo, EXPECTATION) } = {}) {
  const doc = JSON.parse(fs.readFileSync(expectation, "utf8"));
  const unread = [];
  const out = { ...doc, schema: EXPECTATION_SCHEMA, repositories: {} };
  for (const [slug, expected] of Object.entries(doc.repositories)) {
    const { live, notAsked } = await readLive(slug, get, { branch: expected.default_branch });
    unread.push(...notAsked);
    const environments = {};
    for (const [name, e] of Object.entries(live.environments ?? {}).sort(([a], [b]) => (a < b ? -1 : 1))) {
      const kept = expected.environments?.[name] ?? {};
      environments[name] = {
        ...("$comment" in kept ? { $comment: kept.$comment } : {}),
        ...("because" in kept ? { because: kept.because } : {}),
        ...("named_by_no_workflow" in kept ? { named_by_no_workflow: kept.named_by_no_workflow } : {}),
        ...e,
      };
    }
    const rulesets = {};
    for (const r of [...(live.rulesets ?? [])].sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const { name, ...rest } = r;
      const kept = expected.rulesets?.[name] ?? {};
      rulesets[name] = { ...("$comment" in kept ? { $comment: kept.$comment } : {}), ...rest };
    }
    out.repositories[slug] = {
      ...("$comment" in expected ? { $comment: expected.$comment } : {}),
      tree: expected.tree,
      ...("remote" in expected ? { remote: expected.remote } : {}),
      default_branch: live.default_branch ?? expected.default_branch,
      environments,
      ...(expected.pending_environments ? { pending_environments: expected.pending_environments } : {}),
      rulesets,
      rules_on_default_branch: live.rules_on_default_branch ?? expected.rules_on_default_branch,
    };
  }
  return { doc: out, unread };
}

async function main(argv) {
  const args = { repo: DEFAULT_REPO, report: process.env.ASTRA_COVERAGE_FINDINGS, expectation: null, printLive: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--repo") args.repo = path.resolve(argv[++i]);
    else if (argv[i] === "--report") args.report = argv[++i];
    else if (argv[i] === "--expectation") args.expectation = path.resolve(argv[++i]);
    else if (argv[i] === "--print-live") args.printLive = true;
    else { console.error(`FAIL  unknown argument ${JSON.stringify(argv[i])}`); return 2; }
  }
  const expectation = args.expectation ?? path.join(args.repo, EXPECTATION);
  if (args.printLive) {
    const { doc, unread } = await printLive(args.repo, { expectation });
    console.log(JSON.stringify(doc, null, 2));
    for (const u of unread) console.error(`NOT ASKED  ${u}`);
    return unread.length ? 1 : 0;
  }
  report(RULE, await run(args.repo, { expectation }), args.report);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
