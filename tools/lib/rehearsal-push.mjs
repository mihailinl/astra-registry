// ROLL-60's rehearsal, served one step at a time: the fixture series RC-R2-5
// committed, pushed as the `signed` commits it already is, to the one
// repository that cut may go to. The command line is `tools/testkeys/rehearsal-push.mjs`;
// everything that decides anything is here, where the selftest can run it
// against a local bare remote (`tools/selftest/rehearsal-push.mjs`).
//
// ── what it pushes, and why it builds nothing ───────────────────────────────
//
// Each cut of the series (`tools/testkeys/fixtures/rehearsal-r2/`, T0
// 2026-09-22; `…/rehearsal-r2b/`, T0 2026-09-26) holds, per step, the four documents a
// `signed` commit carried and that commit's message, and `manifest.json` holds
// the sha the real signer gave the commit. The commit is a function of those
// bytes, its parent, the signer's identity and the step's `now`, so it is
// rebuilt here with plumbing and **refused unless it is the manifest's sha,
// bit for bit**. Nothing is signed and nothing is chosen: a rehearsal commit
// the service accepts is exactly the commit `tools/signer/run.mjs` made when
// the series was generated, or it is not pushed at all.
//
// ── where it may go ─────────────────────────────────────────────────────────
//
// Two canaries, each serving one cut and nothing else (`CANARIES`):
// `mihailinl/astra-registry-canary`, BOT-88's test repository, the first cut;
// `mihailinl/astra-registry-canary-2`, a static source made for the second,
// because a `signed` that has carried one cut can never carry another (SERVE-18)
// and the plugins service compiles the branch name `signed` in. The push URL is
// DERIVED from `--repo` — so the refusal below is the only thing between a typo
// and `mihailinl/astra-registry`'s `signed` branch, which every Astra
// installation reads, and it is watched failing by making it accept that name.
// A cut named for the other canary is refused the same way, before the
// network. The URL git would really use, after any `url.<base>.insteadOf` or
// `pushInsteadOf` in the operator's config, is asked of git and must be that
// canary's own or a local path (the selftest's bare remote). No force, ever:
// git refuses a non-fast-forward without it, and SERVE-18 means a service
// would refuse to follow one anyway.
//
// ── the order a step does things in ─────────────────────────────────────────
//
//   1. the target, before anything touches the network;
//   2. the fixtures' own judge (the caller's; the CLI runs
//      `tools/selftest/rehearsal-r2.mjs` through the harness, because
//      `node tools/selftest/rehearsal-r2.mjs` on its own runs nothing and
//      exits 0);
//   3. every commit of the series rebuilt and matched to the manifest;
//   4. `signed`'s head on the canary, and the one move that is allowed from
//      it: nothing (already there), one commit forward, or a refusal;
//   5. TRUST-3, as the service will ask it: the step's `Source-Commit` is
//      reachable from the canary's `main`, and trust.json and root.json there
//      are byte-identical to the step's;
//   6. the push, and the head read back;
//   7. Pages, which serves branch `signed` itself: the step's four documents,
//      byte for byte, at the Pages URL. `signed` is pushed first and Pages
//      follows it, so the serial Pages serves is never above the head's
//      (SERVE-37).
//
// A step that is already on the canary does 1-5 and 7 and pushes nothing, so
// `--step N` can be run as often as the day needs.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

import { fixtureEnv } from "./git-env.mjs";
import { DOCUMENTS, REHEARSALS, buildSeries, fixtureDirOf, manifestFileOf } from "../testkeys/make-rehearsal-r2.mjs";

/**
 * The repositories this may push to, each with the one cut it serves (a name
 * in `REHEARSALS`). A cut and its canary are one decision: the first canary's
 * `signed` carries the first cut's step 0 and can carry nothing else, and
 * canary-2 was made empty for the second.
 */
export const CANARIES = Object.freeze({
  "mihailinl/astra-registry-canary": Object.freeze({ fixtures: "rehearsal-r2" }),
  "mihailinl/astra-registry-canary-2": Object.freeze({ fixtures: "rehearsal-r2b" }),
});
/** The canary with no `--repo` and no `--fixtures`: the one the day's walk reads. */
export const DEFAULT_CANARY = "mihailinl/astra-registry-canary-2";
/** The production registry, named so its refusal can say what it would have cost. */
export const PRODUCTION_SLUG = "mihailinl/astra-registry";
/** What the push URL is, for a slug. Derived, so the refusal is load-bearing. */
export const githubUrl = (slug) => `https://github.com/${slug}.git`;
/** Where Pages serves a canary: project Pages, no custom domain. Derived, so it cannot name the other one. */
export const pagesBaseOf = (slug) => {
  const [owner, name] = slug.split("/");
  return `https://${owner}.github.io/${name}/`;
};
/** The canary that serves a cut. */
const canaryOf = (fixtures) => Object.keys(CANARIES).find((slug) => CANARIES[slug].fixtures === fixtures) ?? null;
const canaryList = () => Object.keys(CANARIES).join(" and ");

/**
 * The signer's commit identity (tools/signer/run.mjs, `buildSignedCommit`).
 * Not imported, because that function builds in a work tree's index and this
 * one needs none; it does not have to be trusted either, because every commit
 * built with it is compared with the manifest's sha, and a change there
 * reddens `tools/selftest/rehearsal-push.mjs` on the next regeneration.
 */
const SIGNER = { name: "astra-registry signer", email: "signer@users.noreply.github.com" };

/**
 * The two lines of the series, as `signed`-shaped branches.
 *
 * `rotation` is ROLL-60's four acceptances in the order they need: the base,
 * (a) trust.json at serial + 1, (b) the new index key under SERVE-30 over its
 * seven hours (two commits, because the fixture has both sides of the
 * boundary and the second's parent is the first), (c) the root.json change,
 * (d) what follows it. `compromise` forks from rotation's step 2 and cannot
 * share a branch with steps 3-5: SERVE-18 refuses a head that does not
 * descend from the last accepted commit. Pages serves `signed` only.
 */
export const SERIES = Object.freeze({
  rotation: Object.freeze({
    branch: "signed",
    pages: true,
    steps: Object.freeze([
      "rotation/00-baseline",
      "rotation/01-delegate",
      "rotation/02-mid-window",
      "rotation/03-window-open",
      "rotation/04-root-change",
      "rotation/05-after-root",
    ]),
  }),
  compromise: Object.freeze({
    branch: "signed-compromise",
    pages: false,
    steps: Object.freeze([
      "rotation/00-baseline",
      "rotation/01-delegate",
      "rotation/02-mid-window",
      "compromise/00-drop-2026a",
    ]),
  }),
});

/** Which of ROLL-60's clauses a step carries. Printed; the verdicts come from the bytes. */
export const CLAUSE = Object.freeze({
  "rotation/00-baseline": "the base: trust.json at serial 2, one index key, one signature on each document",
  "rotation/01-delegate": "ROLL-60 (a): trust.json at serial + 1 delegating the incoming key; the list dual-signed, outgoing first",
  "rotation/02-mid-window": "ROLL-60 (b), 3 h in: the catalogue still by the outgoing key alone; the list dual-signed",
  "rotation/03-window-open": "ROLL-60 (b), 8 h in: the new index key signs the catalogue (SERVE-30's 7 h have passed)",
  "rotation/04-root-change": "ROLL-60 (c): root.json drops root-a (SERVE-16, SERVE-92); trust.json re-signed by root-b, same serial and payload",
  "rotation/05-after-root": "ROLL-60 (d): the trust.json and catalogue that follow the root change",
  "compromise/00-drop-2026a": "D10 (record, not a pass): trust.json at serial 4 drops the outgoing key; list and catalogue by the incoming key alone",
});

/** Why a run stopped, with the exit code it maps to. */
export class Refusal extends Error {
  constructor(code, message, exit = 1) {
    super(message);
    this.code = code;
    this.exit = exit;
  }
}

// ── the target ──────────────────────────────────────────────────────────────

/**
 * `owner/name`, lower-cased, from the spellings an operator might type, or
 * null. GitHub names are case-insensitive, so `Mihailinl/Astra-Registry` is
 * the production registry and must be read as it.
 */
export function repoSlug(spec) {
  if (typeof spec !== "string") return null;
  const s = spec.trim();
  const m =
    /^(?:https?:\/\/(?:www\.)?github\.com\/|ssh:\/\/git@github\.com\/|git@github\.com:)?([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?\/?$/.exec(s);
  if (!m) return null;
  return `${m[1]}/${m[2]}`.toLowerCase();
}

/** Null when `spec` names one of the canaries; otherwise the sentence the refusal prints. */
export function targetProblem(spec) {
  const slug = repoSlug(spec);
  if (slug === null) return `${JSON.stringify(spec)} is not a GitHub repository this tool can name`;
  if (Object.hasOwn(CANARIES, slug)) return null;
  if (slug === PRODUCTION_SLUG) {
    return `${slug} is the production registry. Its \`signed\` branch is what every Astra installation reads, and these ` +
      `commits are signed with keys whose private halves are public. This tool pushes to ${canaryList()} and nowhere else`;
  }
  return `${slug} is not one of ${canaryList()}, the repositories ROLL-60's rehearsal is served from`;
}

/**
 * Null when `fixtures` is the cut `slug` serves; otherwise the sentence the
 * refusal prints. `slug` has passed `targetProblem`. A cut pushed to the other
 * canary would leave that canary's `signed` on a commit its own cut can never
 * follow, and the day it was made for would have nothing to serve.
 */
export function fixturesProblem(slug, fixtures) {
  if (!Object.hasOwn(REHEARSALS, fixtures)) {
    return `${JSON.stringify(fixtures)} is no cut of the series; there are ${Object.keys(REHEARSALS).join(" and ")}`;
  }
  const own = canaryOf(fixtures);
  if (CANARIES[slug]?.fixtures === fixtures) return null;
  return `${fixtures} (T0 ${REHEARSALS[fixtures].t0}) is served on ${own} only, and ${slug} serves ` +
    `${CANARIES[slug]?.fixtures} (T0 ${REHEARSALS[CANARIES[slug]?.fixtures]?.t0}). A cut on the other canary's \`signed\` ` +
    "is a head that canary's own cut can never follow (SERVE-18)";
}

const isLocal = (url) => url.startsWith("/") || url.startsWith("file://");

/**
 * Null when the URL git will really fetch from or push to is the one asked
 * for, or a local path; otherwise why not. An `insteadOf` in somebody's
 * global config is invisible in the command line and would send the canary's
 * commits wherever it points.
 */
export function effectiveUrlProblem(effective, expected, which) {
  if (effective === expected || isLocal(effective)) return null;
  return `git would ${which} ${expected} as ${effective} (a url.<base>.${which === "push" ? "pushInsteadOf or insteadOf" : "insteadOf"} ` +
    "rewrite in the git config); refusing, because that is not the canary";
}

// ── git ─────────────────────────────────────────────────────────────────────

/**
 * A git runner at `dir`, with `-c` options for every call (the selftest's
 * insteadOf). `who` is a commit's identity and date, named key by key so the
 * git-environment sweep can read every variable this spawn sets; without it
 * those keys are undefined, which a spawn leaves out.
 */
export function gitAt(dir, config = []) {
  const pre = config.flatMap((c) => ["-c", c]);
  return (args, { input, who, allowFail = false } = {}) => {
    const r = spawnSync("git", [...pre, "-C", dir, ...args], {
      input,
      encoding: "utf8",
      env: {
        ...fixtureEnv(dir),
        GIT_AUTHOR_NAME: who?.name, GIT_AUTHOR_EMAIL: who?.email, GIT_AUTHOR_DATE: who?.date,
        GIT_COMMITTER_NAME: who?.name, GIT_COMMITTER_EMAIL: who?.email, GIT_COMMITTER_DATE: who?.date,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    if (r.error) throw r.error;
    if (r.status !== 0 && !allowFail) {
      throw new Refusal("GIT", `git ${args.join(" ")} exited ${r.status}: ${(r.stderr || "").trim()}`);
    }
    return { ok: r.status === 0, status: r.status, out: (r.stdout || "").trim(), err: (r.stderr || "").trim() };
  };
}

// ── the series ──────────────────────────────────────────────────────────────

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

/**
 * One line of one cut, read from the committed fixtures: per step its four
 * documents, its message, the sha the signer gave it and the parent it had.
 *
 * The manifest's `t0` must be the cut's T0 in the generator's `REHEARSALS`:
 * the two are written by one program, and a directory regenerated under one
 * name and committed under the other would otherwise be pushed with the
 * wrong expiry believed of it.
 */
export function loadSeries(name, { fixtures = CANARIES[DEFAULT_CANARY].fixtures, fixtureDir, manifestFile } = {}) {
  const series = SERIES[name];
  if (!series) throw new Refusal("USAGE", `no series ${JSON.stringify(name)}; there are ${Object.keys(SERIES).join(" and ")}`, 2);
  if (!Object.hasOwn(REHEARSALS, fixtures)) {
    throw new Refusal("USAGE", `no cut ${JSON.stringify(fixtures)}; there are ${Object.keys(REHEARSALS).join(" and ")}`, 2);
  }
  fixtureDir ??= fixtureDirOf(fixtures);
  manifestFile ??= manifestFileOf(fixtures);
  const manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
  if (manifest.t0 !== REHEARSALS[fixtures].t0) {
    throw new Refusal("FIXTURE", `${path.basename(manifestFile)} of ${fixtures} says T0 ${manifest.t0}, and the generator's ` +
      `REHEARSALS says ${REHEARSALS[fixtures].t0}. Regenerate it with \`node tools/testkeys/make-rehearsal-r2.mjs --fixtures ${fixtures}\``);
  }
  const byId = new Map((manifest.steps ?? []).map((s) => [s.id, s]));
  return series.steps.map((id, n) => {
    const m = byId.get(id);
    if (!m) throw new Refusal("FIXTURE", `${id} is not in ${fixtures}'s ${path.basename(manifestFile)}`);
    if (!m.committed || !/^[0-9a-f]{40}$/.test(m.signed_sha ?? "")) {
      throw new Refusal("FIXTURE", `${id} made no \`signed\` commit, so there is nothing to serve`);
    }
    const dir = path.join(fixtureDir, ...id.split("/"));
    const docs = {};
    for (const rel of DOCUMENTS) docs[rel] = fs.readFileSync(path.join(dir, rel));
    const message = fs.readFileSync(path.join(dir, "commit-message.txt"), "utf8");
    const json = (rel) => JSON.parse(docs[rel].toString("utf8"));
    const trust = json("registry/v1/trust.json");
    const index = json("registry/v1/index.json");
    const list = json("registry/v1/revocations.json");
    const root = json("registry/v1/root.json");
    return {
      n,
      id,
      clause: CLAUSE[id],
      sha: m.signed_sha,
      parent: m.parent,
      sourceCommit: m.source_commit,
      now: m.now,
      docs,
      sha256: Object.fromEntries(DOCUMENTS.map((rel) => [rel, sha256(docs[rel])])),
      message,
      expires: {
        "registry/v1/trust.json": trust.signed?.expires_at,
        "registry/v1/index.json": index.signed?.expires_at,
        "registry/v1/revocations.json": list.signed?.expires_at,
      },
      facts: {
        trust: {
          serial: trust.signed?.serial,
          signed_by: (trust.signatures ?? []).map((s) => s.key_id),
          index_keys: (trust.signed?.index_keys ?? []).map((k) => k.key_id),
        },
        catalogue: { serial: index.signed?.serial, signed_by: (index.signatures ?? []).map((s) => s.key_id) },
        list: {
          serial: list.signed?.serial,
          signed_by: (list.signatures ?? []).map((s) => s.key_id),
          expires_at: list.signed?.expires_at,
        },
        roots: (root.roots ?? []).map((r) => `${r.key_id} (${r.role})`),
      },
    };
  });
}

/** A tree of the four documents, written with `mktree` from the leaves up, so a bare repository will do. */
function treeOf(git, docs) {
  const root = new Map();
  for (const [rel, bytes] of Object.entries(docs)) {
    const parts = rel.split("/");
    let node = root;
    for (const dir of parts.slice(0, -1)) {
      if (!node.has(dir)) node.set(dir, new Map());
      node = node.get(dir);
    }
    node.set(parts[parts.length - 1], git(["hash-object", "-w", "--stdin"], { input: bytes }).out);
  }
  const write = (node) => git(["mktree"], {
    input: [...node].map(([name, v]) => (v instanceof Map ? `040000 tree ${write(v)}\t${name}` : `100644 blob ${v}\t${name}`)).join("\n") + "\n",
  }).out;
  return write(root);
}

/**
 * Rebuild every commit of a series in `git`'s repository and hold each to the
 * manifest. The message is the fixture's `commit-message.txt` plus the newline
 * `git log --format=%B` trimmed when it was saved.
 */
export function buildCommits(git, steps) {
  let parent = null;
  for (const step of steps) {
    if ((step.parent ?? null) !== parent) {
      throw new Refusal("FIXTURE",
        `${step.id}'s parent in the manifest is ${step.parent ?? "none"}, and the commit before it in this series is ${parent ?? "none"}`);
    }
    const tree = treeOf(git, step.docs);
    const who = { ...SIGNER, date: step.now };
    const sha = git(["commit-tree", tree, ...(parent ? ["-p", parent] : [])], { input: `${step.message}\n`, who }).out;
    if (sha !== step.sha) {
      throw new Refusal("FIXTURE",
        `${step.id} rebuilds to ${sha} and the manifest says the signer committed ${step.sha}. The committed bytes are not ` +
        "the commit the service would be rehearsing; regenerate with `node tools/testkeys/make-rehearsal-r2.mjs` and read the diff");
    }
    parent = sha;
  }
  return steps.map((s) => s.sha);
}

/**
 * The step's documents whose `expires_at` has passed at `now`. SERVE-22
 * refuses a changed document already past it, and a daemon refuses an
 * expired list, so a step with one is a step nobody will accept. The series'
 * lists run out seven days after T0 (2026-09-29 for rehearsal-r2, 2026-10-03
 * for rehearsal-r2b), and that date is the cut's hard end.
 */
export function expiredDocuments(step, now) {
  return Object.entries(step.expires)
    .filter(([, at]) => typeof at === "string" && Date.parse(at) <= now)
    .map(([rel, at]) => `${rel} expired at ${at}`);
}

/** Where `signed`'s head is in a series: the step index, -1 for no branch, null for a commit not in it. */
export function positionOf(steps, head) {
  if (head === null) return -1;
  const at = steps.findIndex((s) => s.sha === head);
  return at === -1 ? null : at;
}

/**
 * The one move allowed from `head` towards step `n`: nothing, one commit, or
 * a refusal that says what to do instead.
 */
export function planStep(steps, n, head, branch) {
  const at = positionOf(steps, head);
  const name = (i) => `step ${i} (${steps[i].id})`;
  if (at === null) {
    return { action: "refuse", code: "HEAD_FOREIGN", why:
      `\`${branch}\` on the canary is at ${head}, which is no commit of this series. Something other than this tool pushed ` +
      "there, and nothing is stacked on a head nobody can account for" };
  }
  if (at === n) return { action: "noop", why: `\`${branch}\` is already at ${name(n)}` };
  if (at > n) {
    return { action: "refuse", code: "PAST", why:
      `\`${branch}\` is at ${name(at)}, past ${name(n)}. The branch is append-only by rule here and SERVE-18 makes the service ` +
      "refuse a head that does not descend from the one it accepted, so a step once passed is never served again" };
  }
  if (at === n - 1) return { action: "push", from: head };
  return { action: "refuse", code: "GAP", why:
    `\`${branch}\` is ${at === -1 ? "absent" : `at ${name(at)}`}; ${name(n)} is ${n - at} commits ahead. Each step is its own ` +
    `acceptance, so steps are pushed one at a time: run \`--step ${at + 1}\` first` };
}

// ── TRUST-3 ─────────────────────────────────────────────────────────────────

/**
 * The service refuses a `signed` commit whose `Source-Commit` is not reachable
 * from `main`, or whose trust.json or root.json differs from `main`'s at that
 * commit (contract TRUST-3). The canary's `main` is BOT-88's history, so the
 * rehearsal's sources reach it only if they were merged in (see
 * `exportSource`). Asked here exactly as the service asks it.
 */
export function sourceCheck(git, step, mainRef) {
  const sc = step.sourceCommit;
  const present = git(["cat-file", "-e", `${sc}^{commit}`], { allowFail: true }).ok;
  if (!present) return { ok: false, why: `Source-Commit ${sc} is not reachable from the canary's \`main\` (it is not even in its history)` };
  const reach = git(["merge-base", "--is-ancestor", sc, mainRef], { allowFail: true });
  if (reach.status !== 0) return { ok: false, why: `Source-Commit ${sc} is not an ancestor of the canary's \`main\`` };
  for (const rel of ["registry/v1/trust.json", "registry/v1/root.json"]) {
    const blob = git(["rev-parse", "--verify", "--quiet", `${sc}:${rel}`], { allowFail: true });
    const want = git(["hash-object", "--stdin"], { input: step.docs[rel] }).out;
    if (!blob.ok || blob.out !== want) {
      return { ok: false, why: `${rel} at Source-Commit ${sc.slice(0, 12)} is not byte-identical to the step's` };
    }
  }
  return { ok: true, why: `Source-Commit ${sc.slice(0, 12)} is on the canary's \`main\`, with the step's trust.json and root.json` };
}

/**
 * The rehearsal's `main` history, written into the git repository at `into`
 * as `refs/rehearsal-source/rotation` and `refs/rehearsal-source/compromise`.
 *
 * It is the generator's own throwaway registry, rebuilt (it is deterministic:
 * fixed identities, dates and signer clocks), and every Source-Commit the
 * manifest names is checked to be in it. Merging those two refs into the
 * canary's `main` with `-s ours` makes TRUST-3 hold without changing one byte
 * of `main`'s tree.
 */
export function exportSource(into, { gitConfig = [], fixtures = CANARIES[DEFAULT_CANARY].fixtures } = {}) {
  if (!Object.hasOwn(REHEARSALS, fixtures)) {
    throw new Refusal("USAGE", `no cut ${JSON.stringify(fixtures)}; there are ${Object.keys(REHEARSALS).join(" and ")}`, 2);
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rehearsal-source-"));
  try {
    const work = path.join(tmp, "registry");
    const out = path.join(tmp, "out");
    fs.mkdirSync(out);
    const manifest = buildSeries({ outDir: out, work, t0: REHEARSALS[fixtures].t0 });
    const src = gitAt(work, gitConfig);
    const heads = {
      rotation: src(["rev-parse", "refs/heads/main"]).out,
      compromise: src(["rev-parse", "refs/heads/compromise-source"]).out,
    };
    // The COMMITTED manifest's Source-Commits, which are the ones the pushed
    // commits name, as well as the fresh build's: the two agree whenever the
    // cut's `--check` does, and when they do not, this says so here rather
    // than as a TRUST-3 refusal on the day.
    const committed = JSON.parse(fs.readFileSync(manifestFileOf(fixtures), "utf8"));
    for (const step of [...manifest.steps, ...(committed.steps ?? [])].filter((s) => s.committed)) {
      const line = step.id.startsWith("compromise/") ? "compromise" : "rotation";
      if (!src(["merge-base", "--is-ancestor", step.source_commit, heads[line]], { allowFail: true }).ok) {
        throw new Refusal("FIXTURE", `${fixtures}: ${step.id}'s Source-Commit ${step.source_commit} is not in the rebuilt ${line} history`);
      }
    }
    const dst = gitAt(into, gitConfig);
    dst(["fetch", "--quiet", "--no-tags", work,
      `+refs/heads/main:refs/rehearsal-source/rotation`, `+refs/heads/compromise-source:refs/rehearsal-source/compromise`]);
    return heads;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// ── Pages ───────────────────────────────────────────────────────────────────

/**
 * What Pages serves now: for each document its HTTP status and SHA-256, and
 * the step whose four documents it matches, if any. A query string defeats the
 * CDN's ten-minute cache, so a new deployment is seen when it is live.
 */
export async function pagesState(fetchImpl, steps, { base } = {}) {
  if (typeof base !== "string") throw new Error("pagesState needs the canary's Pages base (pagesBaseOf)");
  const served = {};
  for (const rel of DOCUMENTS) {
    try {
      const r = await fetchImpl(`${base}${rel}?rehearsal=${Date.now()}`);
      const bytes = r.status === 200 ? Buffer.from(await r.arrayBuffer()) : null;
      served[rel] = { status: r.status, sha256: bytes ? sha256(bytes) : null };
    } catch (e) {
      served[rel] = { status: null, sha256: null, error: String(e?.message ?? e) };
    }
  }
  const step = steps.findIndex((s) => DOCUMENTS.every((rel) => served[rel].sha256 === s.sha256[rel]));
  const absent = DOCUMENTS.every((rel) => served[rel].status === 404);
  return { served, step: step === -1 ? null : step, absent };
}

/** Wait until Pages serves step `n`'s four documents byte for byte, or the timeout. */
export async function waitPages(fetchImpl, steps, n, { timeoutMs, intervalMs = 10_000, sleep, clock = Date.now, base } = {}) {
  const start = clock();
  for (;;) {
    const state = await pagesState(fetchImpl, steps, { base });
    if (state.step === n) return { ...state, waited_ms: clock() - start, ok: true };
    if (clock() - start >= timeoutMs) return { ...state, waited_ms: clock() - start, ok: false };
    await sleep(intervalMs);
  }
}

// ── the command line ────────────────────────────────────────────────────────

export const USAGE = `usage: node tools/testkeys/rehearsal-push.mjs --step N [--series rotation|compromise] [--dry-run]
         [--repo owner/name] [--fixtures ${Object.keys(REHEARSALS).join("|")}] [--skip-pages] [--pages-timeout SECONDS]
         [--allow-source-off-main REASON] [--evidence FILE]
       node tools/testkeys/rehearsal-push.mjs --status [--series …] [--repo …] [--fixtures …]
       node tools/testkeys/rehearsal-push.mjs --list [--series …] [--repo …] [--fixtures …]
       node tools/testkeys/rehearsal-push.mjs --export-source <git repository> [--repo …] [--fixtures …]
     --repo and --fixtures name one pair: ${Object.entries(CANARIES).map(([s, c]) => `${s} serves ${c.fixtures}`).join(", ")}.
     Either alone names the other; neither is ${DEFAULT_CANARY}; the two naming different pairs is refused.`;

export function parseArgs(argv) {
  const a = { step: null, series: "rotation", repo: null, fixtures: null, dryRun: false, status: false, list: false,
    skipPages: false, pagesTimeout: 600, allowSourceOffMain: null, evidence: null, exportSource: null };
  const value = (i, flag) => {
    const v = argv[i];
    if (v === undefined || v.startsWith("--")) throw new Refusal("USAGE", `${flag} needs a value\n${USAGE}`, 2);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    if (f === "--step") {
      const v = value(++i, f);
      if (!/^\d+$/.test(v)) throw new Refusal("USAGE", `--step takes a step number, not ${JSON.stringify(v)}`, 2);
      a.step = Number(v);
    } else if (f === "--series") a.series = value(++i, f);
    else if (f === "--repo") a.repo = value(++i, f);
    else if (f === "--fixtures") a.fixtures = value(++i, f);
    else if (f === "--dry-run") a.dryRun = true;
    else if (f === "--status") a.status = true;
    else if (f === "--list") a.list = true;
    else if (f === "--skip-pages") a.skipPages = true;
    else if (f === "--pages-timeout") a.pagesTimeout = Number(value(++i, f));
    else if (f === "--allow-source-off-main") a.allowSourceOffMain = value(++i, f);
    else if (f === "--evidence") a.evidence = value(++i, f);
    else if (f === "--export-source") a.exportSource = value(++i, f);
    else throw new Refusal("USAGE", `unknown argument ${JSON.stringify(f)}\n${USAGE}`, 2);
  }
  const modes = [a.step !== null, a.status, a.list, a.exportSource !== null].filter(Boolean).length;
  if (modes !== 1) throw new Refusal("USAGE", `name exactly one of --step, --status, --list, --export-source\n${USAGE}`, 2);
  if (!(a.pagesTimeout >= 0)) throw new Refusal("USAGE", "--pages-timeout takes seconds", 2);
  if (a.fixtures !== null && !Object.hasOwn(REHEARSALS, a.fixtures)) {
    throw new Refusal("USAGE", `--fixtures takes ${Object.keys(REHEARSALS).join(" or ")}, not ${JSON.stringify(a.fixtures)}`, 2);
  }
  return a;
}

/**
 * The canary and the cut a run is for, or a Refusal (exit 2) before anything
 * touches the network or the fixtures. Either flag alone names the pair; with
 * neither, the pair is `DEFAULT_CANARY`'s. The target is judged first, so
 * `mihailinl/astra-registry` is refused as what it is whatever cut is named.
 */
export function resolvePair(a) {
  const spec = a.repo ?? (a.fixtures !== null ? canaryOf(a.fixtures) : DEFAULT_CANARY);
  const problem = targetProblem(spec);
  if (problem) throw new Refusal("TARGET", problem, 2);
  const slug = repoSlug(spec);
  const fixtures = a.fixtures ?? CANARIES[slug].fixtures;
  const mismatch = fixturesProblem(slug, fixtures);
  if (mismatch) throw new Refusal("FIXTURES", mismatch, 2);
  return { slug, fixtures, t0: REHEARSALS[fixtures].t0 };
}

const describe = (s) =>
  `trust.json serial ${s.facts.trust.serial} signed by ${s.facts.trust.signed_by.join("+")}, delegating ${s.facts.trust.index_keys.join(", ")}; ` +
  `catalogue serial ${s.facts.catalogue.serial} signed by ${s.facts.catalogue.signed_by.join("+")}; ` +
  `list serial ${s.facts.list.serial} signed by ${s.facts.list.signed_by.join("+")} (expires ${s.facts.list.expires_at}); ` +
  `root.json ${s.facts.roots.join(", ")}`;

/**
 * The whole run. Returns the exit code: 0 done (or already done), 1 a check
 * did not hold, 2 refused before anything was asked (a usage error, a target
 * that is not a canary, or a cut that is not the target's).
 *
 * @param {string[]} argv
 * @param {{fetchImpl?: Function, judge?: () => {ok: boolean, detail: string}, gitConfig?: string[],
 *          log?: (line: string) => void, sleep?: (ms: number) => Promise<void>, clock?: () => number,
 *          pagesBase?: string, fixtureDir?: string, manifestFile?: string}} deps
 */
export async function main(argv, deps = {}) {
  const log = deps.log ?? ((l) => console.log(l));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rehearsal-push-"));
  try {
    return await run(argv, { ...deps, log, tmp });
  } catch (e) {
    if (e instanceof Refusal) {
      log(`${e.exit === 2 ? "REFUSED" : "FAIL "} ${e.message}`);
      return e.exit;
    }
    throw e;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function run(argv, { fetchImpl, judge, gitConfig = [], log, sleep, clock, pagesBase, fixtureDir, manifestFile, tmp }) {
  const a = parseArgs(argv);

  // 1. The target and its cut, before anything reads the network or the fixtures.
  const { slug, fixtures, t0 } = resolvePair(a);
  const url = githubUrl(slug);
  pagesBase ??= pagesBaseOf(slug);
  const pair = `${slug}, fixtures ${fixtures} (T0 ${t0})`;

  if (a.exportSource) {
    const heads = exportSource(path.resolve(a.exportSource), { gitConfig, fixtures });
    log(`ok    wrote ${fixtures}'s refs/rehearsal-source/rotation (${heads.rotation}) and refs/rehearsal-source/compromise ` +
      `(${heads.compromise}) into ${a.exportSource}`);
    log(`      to make TRUST-3 hold on ${slug}, merge both into its main with the tree unchanged:`);
    log("        git merge -s ours --no-ff --allow-unrelated-histories refs/rehearsal-source/rotation refs/rehearsal-source/compromise");
    return 0;
  }

  const series = SERIES[a.series];
  const steps = loadSeries(a.series, { fixtures, fixtureDir, manifestFile });
  if (a.list) {
    log(pair);
    log(`series ${a.series}, branch \`${series.branch}\`${series.pages ? `, served on Pages at ${pagesBase}` : ""}`);
    for (const s of steps) log(`  ${s.n}  ${s.sha.slice(0, 12)}  ${s.id}\n       ${s.clause}\n       ${describe(s)}`);
    return 0;
  }
  if (a.step !== null && a.step >= steps.length) {
    throw new Refusal("USAGE", `series ${a.series} has steps 0 to ${steps.length - 1}`, 2);
  }

  // 2. The fixtures' judge.
  if (a.step !== null) {
    const verdict = judge ? judge() : { ok: false, detail: "no judge was given" };
    if (!verdict.ok) throw new Refusal("JUDGE", `the rehearsal fixtures did not pass their judge: ${verdict.detail}`);
    log(`ok    the fixtures pass their judge: ${verdict.detail}`);
  }

  // 3. Every commit, rebuilt and held to the manifest.
  const work = path.join(tmp, "work.git");
  fs.mkdirSync(work);
  const git = gitAt(work, gitConfig);
  git(["init", "-q", "--bare"]);
  buildCommits(git, steps);
  log(`ok    ${steps.length} commit(s) of series ${a.series} rebuild to the signer's own shas`);

  // The URL git will really use, both ways, before it is used.
  git(["remote", "add", "canary", url]);
  for (const [which, args] of [["fetch", ["remote", "get-url", "canary"]], ["push", ["remote", "get-url", "--push", "canary"]]]) {
    const effective = git(args).out;
    const p = effectiveUrlProblem(effective, url, which);
    if (p) throw new Refusal("TARGET", p, 2);
  }

  // 4. Where the canary is.
  const refs = git(["ls-remote", "canary", `refs/heads/${series.branch}`, "refs/heads/main"]).out;
  const remote = Object.fromEntries(refs.split("\n").filter(Boolean).map((l) => l.split(/\s+/)).map(([sha, ref]) => [ref, sha]));
  const head = remote[`refs/heads/${series.branch}`] ?? null;
  const hasMain = Boolean(remote["refs/heads/main"]);
  if (hasMain) git(["fetch", "--quiet", "--no-tags", "canary", "+refs/heads/main:refs/rehearsal/canary-main"]);
  const at = positionOf(steps, head);

  const nowMs = (clock ?? Date.now)();
  const firstExpiry = steps.map((s) => s.expires["registry/v1/revocations.json"]).filter(Boolean).sort()[0];
  if (a.status) {
    log(pair);
    log(`hard end: the series' first list expires at ${firstExpiry}${Date.parse(firstExpiry) <= nowMs ? " — PASSED; the service and the daemon will refuse it" : ""}`);
    log(`\`${series.branch}\`: ${head === null ? "absent" : at === null ? `${head}, NOT a commit of this series` : `step ${at} (${steps[at].id}) ${head}`}`);
    for (const s of steps) {
      const src = hasMain ? sourceCheck(git, s, "refs/rehearsal/canary-main") : { ok: false, why: "the canary has no main" };
      log(`  ${s.n}  ${s.id.padEnd(26)} ${at !== null && s.n <= at ? "pushed " : "pending"}  TRUST-3 ${src.ok ? "holds" : `FAILS: ${src.why}`}`);
    }
    if (series.pages && fetchImpl) {
      const p = await pagesState(fetchImpl, steps, { base: pagesBase });
      log(`Pages: ${p.absent ? "not serving (404: not enabled, or not built yet)" : p.step === null ? "serving bytes that are no step's" : `serving step ${p.step} (${steps[p.step].id})`}`);
    }
    return 0;
  }

  const n = a.step;
  const target = steps[n];
  const expired = expiredDocuments(target, nowMs);
  if (expired.length) {
    throw new Refusal("EXPIRED", `step ${n} (${target.id}) cannot be accepted any more: ${expired.join("; ")}. SERVE-22 refuses a changed ` +
      "document past its expires_at and a daemon refuses an expired list. The hard end of ${fixtures} has passed: cut the series " +
      "again at a later T0 (REHEARSALS in tools/testkeys/make-rehearsal-r2.mjs) and serve it from a repository whose `signed` " +
      "has never carried another cut (CANARIES here)");
  }
  log(`step ${n}: ${target.id} → ${slug} \`${series.branch}\` at ${target.sha}`);
  log(`      ${target.clause}`);
  log(`      ${describe(target)}`);
  const plan = planStep(steps, n, head, series.branch);
  if (plan.action === "refuse") throw new Refusal(plan.code, plan.why);

  // 5. TRUST-3, as the service asks it.
  const src = hasMain ? sourceCheck(git, target, "refs/rehearsal/canary-main") : { ok: false, why: "the canary has no `main`" };
  let failed = false;
  if (src.ok) log(`ok    TRUST-3: ${src.why}`);
  else if (a.allowSourceOffMain) log(`note  TRUST-3 would refuse this commit (${src.why}); going on because: ${a.allowSourceOffMain}`);
  else if (plan.action === "push" && a.dryRun) {
    log(`FAIL  TRUST-3: ${src.why}. The real run stops here; the service would refuse this commit whole (SERVE-91)`);
    failed = true;
  } else if (plan.action === "push") {
    throw new Refusal("TRUST3", `TRUST-3: ${src.why}. The service refuses such a commit whole (SERVE-91). Merge the rehearsal's ` +
      "sources into the canary's main first (--export-source), or pass --allow-source-off-main with the reason it may not matter");
  } else log(`FAIL  TRUST-3: ${src.why} (the step is already pushed, so this is reported, not refused)`);

  // 6. The push.
  let action = "already";
  if (plan.action === "push") {
    if (a.dryRun) {
      log(`dry   would push ${target.sha} to \`${series.branch}\` (${head === null ? "creating the branch" : `fast-forward from ${head}`}); pushed nothing`);
      action = "would-push";
    } else {
      git(["push", "--quiet", "canary", `${target.sha}:refs/heads/${series.branch}`]);
      const after = git(["ls-remote", "canary", `refs/heads/${series.branch}`]).out.split(/\s+/)[0] || null;
      if (after !== target.sha) throw new Refusal("PUSH", `pushed, and \`${series.branch}\` reads back as ${after}, not ${target.sha}`);
      log(`ok    pushed: \`${series.branch}\` is ${target.sha}${head ? ` (one commit on ${head.slice(0, 12)})` : " (created)"}`);
      action = "pushed";
    }
  } else log(`ok    ${plan.why}; nothing pushed`);

  // 7. Pages.
  let pages = null;
  if (!series.pages) log(`note  series ${a.series} is not served on Pages (Pages serves \`signed\`)`);
  else if (a.skipPages || !fetchImpl) log("note  Pages not asked (--skip-pages)");
  else if (a.dryRun || action === "would-push") {
    pages = await pagesState(fetchImpl, steps, { base: pagesBase });
    log(`dry   Pages serves ${pages.absent ? "nothing (404)" : pages.step === null ? "bytes that are no step's" : `step ${pages.step}`}`);
  } else {
    pages = await waitPages(fetchImpl, steps, n, {
      timeoutMs: a.pagesTimeout * 1000, sleep: sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))), clock, base: pagesBase,
    });
    if (!pages.ok) {
      throw new Refusal("PAGES", `after ${Math.round(pages.waited_ms / 1000)} s Pages serves ` +
        `${pages.absent ? "nothing (404: is Pages enabled on branch `signed`?)" : pages.step === null ? "bytes that are no step's" : `step ${pages.step}`}, ` +
        `not step ${n}. \`signed\` is pushed; run --step ${n} again once Pages has built, or pass --skip-pages`);
    }
    log(`ok    Pages serves step ${n}'s four documents byte for byte (after ${Math.round(pages.waited_ms / 1000)} s)`);
  }

  if (a.evidence && !a.dryRun) {
    const record = {
      schema: "astra.registry.rehearsal-push/1", at: new Date((clock ?? Date.now)()).toISOString(), repo: slug, fixtures, t0,
      series: a.series,
      branch: series.branch, step: n, id: target.id, action, signed_sha: target.sha, parent: head,
      source_commit: target.sourceCommit, trust3: src.ok ? "holds" : `fails: ${src.why}`,
      allow_source_off_main: a.allowSourceOffMain, documents_sha256: target.sha256, facts: target.facts,
      pages: pages ? { step: pages.step, waited_ms: pages.waited_ms ?? null } : null,
    };
    fs.mkdirSync(path.dirname(path.resolve(a.evidence)), { recursive: true });
    fs.appendFileSync(a.evidence, `${JSON.stringify(record)}\n`);
    log(`ok    evidence appended to ${a.evidence}`);
  }
  return failed ? 1 : 0;
}
