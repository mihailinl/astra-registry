#!/usr/bin/env node
// RC-R4-1: which URLs the redirected pages would send a reader to, whether each
// of them answers, and the one edit that arms a set once they all do.
//
//   node site/successors.mjs                  the committed sets: list, probe
//   node site/successors.mjs --propose R4b    Table 5-F's R4b rows instead
//   node site/successors.mjs --list [...]     the targets only, no network
//   node site/successors.mjs --arm R4b --edge-review <where ROLL-54 is recorded>
//   [--index registry/v1/index.json] [--revocations registry/v1/revocations.json]
//   [--redirects site/redirects.json] [--tokens schema/contract-tokens-v1.json] [--json]
//
// ── WHY THIS IS A TOOL AND NOT A SENTENCE IN A PLAN ─────────────────────────
//
// ROLL-55 says `/p/<id>/`, `/` and `/search/` become static redirects before
// R4b, "and not before ROLL-54's edge review is recorded"; RC-R4-1 adds that
// the set is committed only after a probe shows each successor answering 200
// (SERVE-84). A non-empty set in `site/redirects.json` IS the arming act — the
// next `sign.yml` run deploys it — so "only after" has to be something the
// arming commit runs, not something its author remembers. `--arm` is that: it
// writes the set only when every target answers 200 and only when it is told
// where the edge review is recorded, and it writes that answer into the set it
// arms, so the commit carries its own evidence.
//
// ── THE TARGETS ARE READ OUT OF THE PAGES, NOT RE-DERIVED ───────────────────
//
// `site/build.mjs`'s `applyRedirects` decides which generated page a pattern
// matches and what it expands to. A second copy of that expansion here would be
// a second opinion that can drift, and the thing a reader is sent to is what
// the STUB says, whatever either copy thinks. So this builds the site the way
// the deploy does, with the redirects file in question, and reads each
// redirected page's canonical link. The probe fetches exactly what Pages would
// serve.
//
// ── THE SUCCESSORS ARE THE TOKEN FILE'S ─────────────────────────────────────
//
// Table 5-F is in `schema/contract-tokens-v1.json` (SCOPE-7), one `page` entry
// per row, with `pages_today` and `successors` as paths under the panel's
// origin. `--propose` and `--arm` take the rows ROLL-55 moves at R4b from
// there, and the origin from the absolute page URLs the same file carries
// (FLOW-77's submit page, MOD-13's advisory base), so neither the host nor a
// path is typed here. The only thing this file decides is WHICH rows move at
// which step, because that is ROLL-55's sentence and the token file does not
// carry it.
//
// ── WHAT IT DOES NOT CHECK ──────────────────────────────────────────────────
//
// A 200 is a status, not a page. A successor that answers 200 with "no such
// plugin" passes. SERVE-74 makes the panel render a guest page for exactly the
// catalogue's entries, and this probe trusts that and does not read bodies.
// A redirect is NOT followed: a stub's canonical link says "this is the same
// resource", and a target that itself moves somewhere is a target the
// canonical link names wrongly, so a 3xx is reported with its Location.
// ROLL-54's review is a record a person makes; this tool can refuse to arm
// without being told where it is, and cannot tell whether it is there.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { build } from "./build.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");

/** No credential, and a name that says who is asking and where to complain. */
export const USER_AGENT = "astra-registry-lane (+https://github.com/mihailinl/astra-registry)";

/**
 * ROLL-55's split of Table 5-F by step: the token file's row ids that move at
 * each. R4b is `/p/<id>/`, `/` and `/search/`. R9a is every other row
 * (RC-R9-1), and `404.html` is the one generated page no set moves.
 */
export const STEP_ROWS = Object.freeze({
  R4b: Object.freeze(["page:5F:/,/search/", "page:5F:/p/<id>/"]),
  R9a: Object.freeze([
    "page:5F:/publisher/<owner>/", "page:5F:/publish/", "page:5F:/policy/,/security/",
    "page:5F:/transparency/", "page:5F:/advisory/<id>/",
  ]),
});

/**
 * The generated page no set moves (RC-R9-1). It is what Pages serves for a path
 * that matches nothing; redirecting it would send every mistyped URL into the
 * service's guest zone, which is the traffic SERVE-105 and ROLL-54 are about.
 */
export const UNMOVED_PAGES = Object.freeze(["404.html"]);

/** The registry marker R5 exits with: R9a's request follows it at once (registry plan §2.10). */
export const R5_EXIT_MARKER = "log/rollout/R5-exit.json";


/** Where a set's own evidence lives once `--arm` has written it. */
export const ARMED_MEMBER = "armed";

/** The registry marker R4b opens with (registry plan §2.7, landing order step 3). */
export const R4B_MARKER = "log/rollout/R4b-open.json";

/** Which marker says a step's set must be armed by now. */
const STEP_MARKER = Object.freeze({ R4b: R4B_MARKER, R9a: R5_EXIT_MARKER });

/** §0.7: RFC 3339 UTC, whole seconds, `Z`. */
const TIME_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;

/**
 * A redirects document holding only `step`'s set. A step's canary is about
 * that step: once R9a is armed too, a build with both sets would show R4b
 * "moving" `/policy/`, which is R9a's doing and not R4b's.
 */
export function onlyStep(doc, step) {
  return { ...doc, sets: (doc.sets ?? []).filter((s) => s?.step === step) };
}

const unescapeHtml = (s) =>
  s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

/**
 * The panel's origin, as every absolute page URL in the token file spells it.
 * One origin or a throw: two would mean the file disagrees with itself about
 * where the panel is, and a redirect built on either half of that is a guess.
 */
export function panelOrigin(tokens) {
  const urls = (tokens?.entries ?? []).filter((e) => e?.kind === "page" && typeof e.url === "string").map((e) => e.url);
  const origins = [...new Set(urls.map((u) => new URL(u).origin))];
  if (origins.length !== 1) {
    throw new Error(
      `the token file's absolute page URLs name ${origins.length} origin(s) (${origins.join(", ") || "none"}); ` +
        "Table 5-F's successors are paths under ONE panel origin",
    );
  }
  if (!origins[0].startsWith("https://")) throw new Error(`the panel origin ${origins[0]} is not https`);
  return origins[0];
}

/**
 * The `paths` object ROLL-55 commits for `step`, from the token file's Table
 * 5-F rows. Each page today maps to its row's FIRST successor: `/` and
 * `/search/` both to the index (search is `/plugins?q=`, and a static stub
 * carries no query), `/p/<id>/` to `/plugins/<id>`.
 */
export function tableSet(tokens, step) {
  const rows = STEP_ROWS[step];
  if (!rows) throw new Error(`no Table 5-F rows are assigned to step ${JSON.stringify(step)} here; R9a is RC-R9-1's`);
  const origin = panelOrigin(tokens);
  const paths = {};
  for (const id of rows) {
    const row = (tokens.entries ?? []).find((e) => e?.id === id);
    if (!row) throw new Error(`the token file carries no ${id} entry, so Table 5-F's successor for it is unknown`);
    if (row.state !== "live") throw new Error(`${id} is ${JSON.stringify(row.state)} in the token file, not live`);
    const all = Array.isArray(row.successors) ? row.successors : [];
    const [successor] = all;
    if (typeof successor !== "string" || !successor.startsWith("/")) {
      throw new Error(`${id} has no successor path to redirect to`);
    }
    if (!Array.isArray(row.pages_today) || !row.pages_today.length) throw new Error(`${id} names no page today`);
    // Positional only where the row pairs pages with pages: `/policy/,/security/`
    // lists one successor page each. `/,/search/` lists the search QUERY second
    // and `/transparency/` its document second, so there the first successor
    // is every page's (the plan: `/` and `/search/` → `/plugins`).
    const pagesOnly = all.length === row.pages_today.length && all.every((x) => typeof x === "string" && x.startsWith("/") && !/[?#]|\.json$/.test(x));
    row.pages_today.forEach((page, i) => { paths[page] = `${origin}${pagesOnly ? all[i] : successor}`; });
  }
  return paths;
}

/** A copy of a redirects document with `step`'s paths replaced. */
export function withSet(doc, step, paths, extra = {}) {
  const copy = JSON.parse(JSON.stringify(doc));
  const set = copy.sets?.find((s) => s?.step === step);
  if (!set) throw new Error(`the redirects document has no set ${JSON.stringify(step)}`);
  set.paths = paths;
  Object.assign(set, extra);
  return copy;
}

function walk(root) {
  const out = new Map();
  const go = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) go(full);
      else out.set(path.relative(root, full).split(path.sep).join("/"), fs.readFileSync(full));
    }
  };
  go(root);
  return out;
}

/**
 * Build the site twice, the way `sign.yml`'s `pages` job does — once with no
 * redirects and once with `redirectsDoc` — and say what the second did.
 *
 * @returns {{ids: string[], redirected: {file: string, target: string}[],
 *            plain: Map<string, Buffer>, moved: Map<string, Buffer>}}
 */
export function expand({ index, revocations = null, registryDir = null, redirectsDoc, root = REPO }) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-successors-"));
  try {
    const file = path.join(tmp, "redirects.json");
    fs.writeFileSync(file, JSON.stringify(redirectsDoc));
    const common = { index, revocations, registryDir, root };
    const log = console.log;
    let result;
    // `applyRedirects` prints a note for a pattern that matched nothing; this
    // tool's own output is the list, so the build's is kept out of it.
    console.log = () => {};
    try {
      build({ ...common, out: path.join(tmp, "plain") });
      result = build({ ...common, out: path.join(tmp, "moved"), redirects: file });
    } finally {
      console.log = log;
    }
    const plain = walk(path.join(tmp, "plain"));
    const moved = walk(path.join(tmp, "moved"));
    const redirected = result.redirects.map((rel) => {
      const html = moved.get(rel)?.toString("utf8") ?? "";
      const m = /<link rel="canonical" href="([^"]*)">/.exec(html);
      if (!m) throw new Error(`${rel} was reported redirected and carries no canonical link`);
      return { file: rel, target: unescapeHtml(m[1]) };
    });
    const ids = JSON.parse(fs.readFileSync(index, "utf8")).signed.plugins.map((p) => p.id).sort();
    return { ids, redirected, plain, moved };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * RC-R9-1's canary: every generated HTML page is redirected by one set or the
 * other, `UNMOVED_PAGES` aside. Asked of a build with BOTH sets applied, before
 * R9a's request (from R5's exit marker), because a page in neither set is a
 * page Pages keeps serving after the owner is told the site has moved.
 */
export function allPathsProblems({ plain, redirected }) {
  const moved = new Set(redirected.map((r) => r.file));
  return [...plain.keys()].filter((k) => k.endsWith(".html")).sort()
    .filter((k) => !moved.has(k) && !UNMOVED_PAGES.includes(k))
    .map((k) => `${k} is in neither set R4b nor set R9a, and RC-R9-1 moves every generated page before R9a's request`);
}

/** The registry marker R9b exits with (registry plan §2.10, landing order step 4). */
export const R9B_MARKER = "log/rollout/R9b-exit.json";

/**
 * Every workflow job that deploys to GitHub Pages: a job in environment
 * `github-pages`, or one that runs `actions/deploy-pages`. RC-R9-3's canary is
 * that none is left once R9b's marker is on the tree. The owner disables Pages
 * first (a setting) and `reg.100c` removes the `pages` job the same hour
 * (ROLL-57); a deploy job still in a workflow after R9b is a job that fails
 * every run, or one that re-enables what the owner switched off.
 *
 * @param {{file: string, text: string}[]} workflows
 * @returns {string[]} `file:job`, sorted
 */
export function pagesDeployers(workflows) {
  const out = [];
  for (const { file, text } of workflows) {
    const lines = text.split("\n");
    const jobsAt = lines.findIndex((l) => /^jobs:\s*$/.test(l));
    if (jobsAt < 0) continue;
    let job = null;
    for (let i = jobsAt + 1; i < lines.length; i++) {
      const l = lines[i];
      if (/^\S/.test(l)) break;
      const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(l);
      if (m) { job = m[1]; continue; }
      if (!job || /^\s*#/.test(l)) continue;
      if (/^\s+(?:-\s+)?uses:\s*actions\/deploy-pages@/.test(l) || /^\s+(environment|name):\s*github-pages\s*$/.test(l)) {
        out.push(`${file}:${job}`);
      }
    }
  }
  return [...new Set(out)].sort();
}

/** RC-R9-3's canary: after R9b's marker, no job deploys Pages. */
export function r9bProblems({ markerPresent, deployers }) {
  if (!markerPresent) return [];
  return deployers.map((d) => `${d} still deploys GitHub Pages, and ${R9B_MARKER} is on the tree: R9b switched Pages off (ROLL-57; RC-R9-3)`);
}

/** Every distinct URL a set of redirected pages points at, sorted. */
export const targetsOf = (redirected) => [...new Set(redirected.map((r) => r.target))].sort();

/**
 * RC-R4-1's canary over one expansion: every page ROLL-55 moves at `step` is a
 * redirect to its Table 5-F successor, at least `ids.length + 2` pages moved,
 * nothing outside the step's rows moved, and `registry/v1/*` and
 * `transparency/moderation-log.json` are the same bytes with and without it.
 *
 * @returns {string[]} problems; empty is green
 */
export function coverageProblems({ step, expected, ids, redirected, plain, moved }) {
  const problems = [];
  const origin = new URL(expected["/"] ?? Object.values(expected)[0]).origin;
  const want = new Map();
  if (step === "R4b") {
    const index = expected["/"];
    const search = expected["/search/"];
    const perPlugin = expected["/p/<id>/"];
    if (!index || !search || !perPlugin) {
      problems.push("the expected R4b set does not name `/`, `/search/` and `/p/<id>/`, so there is nothing to hold it to");
      return problems;
    }
    want.set("index.html", index);
    want.set("search/index.html", search);
    for (const id of ids) want.set(`p/${id}/index.html`, perPlugin.replace("<id>", id));
  } else if (step === "R9a") {
    // Every generated page each R9a pattern matches, with its captured value.
    const htmlFiles = [...plain.keys()].filter((k) => k.endsWith(".html"));
    for (const [sitePath, target] of Object.entries(expected)) {
      const rel = sitePath.replace(/^\//, "");
      const filePattern = rel === "" || rel.endsWith("/") ? `${rel}index.html` : rel;
      const names = [...filePattern.matchAll(/<([a-z][a-z0-9_]*)>/g)].map((m) => m[1]);
      const re = new RegExp(`^${filePattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/<[a-z][a-z0-9_]*>/g, "([^/]+)")}$`);
      for (const f of htmlFiles) {
        const m = re.exec(f);
        if (!m) continue;
        let t = target;
        names.forEach((n, i) => { t = t.replace(`<${n}>`, m[i + 1]); });
        want.set(f, t);
      }
    }
    if (!["publish/index.html", "policy/index.html", "security/index.html", "transparency/index.html"].every((f) => want.has(f))) {
      problems.push("the expected R9a set does not reach publish, policy, security and transparency, so there is nothing to hold it to");
      return problems;
    }
  } else {
    problems.push(`no canary is written for step ${step}`);
    return problems;
  }

  const got = new Map(redirected.map((r) => [r.file, r.target]));
  for (const [file, target] of want) {
    if (!got.has(file)) problems.push(`${file} is not redirected, and ROLL-55 moves it at ${step} to ${target}`);
    else if (got.get(file) !== target) problems.push(`${file} redirects to ${got.get(file)}, and Table 5-F says ${target}`);
  }
  for (const [file, target] of got) {
    if (!want.has(file)) problems.push(`${file} is redirected (to ${target}), and ${step} does not move it`);
  }
  if (step === "R4b") {
    const floor = ids.length + 2;
    if (redirected.length < floor) {
      problems.push(`${redirected.length} page(s) redirected; the floor is the catalogue's ${ids.length} plugin page(s) + 2`);
    }
    if (!ids.length) problems.push("the catalogue has no plugins, so the floor held nothing");
  }
  // R9a's floor is the four fixed pages its `want` must reach, asserted above:
  // every page `want` holds is then checked one by one, so a count here could
  // never fail on its own (measured: disabling it left the suite green).

  const pinned = [...plain.keys()].filter((k) => k.startsWith("registry/v1/") || k === "transparency/moderation-log.json");
  if (!pinned.some((k) => k === "transparency/moderation-log.json")) {
    problems.push("the plain build wrote no transparency/moderation-log.json, so its bytes were compared with nothing");
  }
  for (const k of pinned) {
    if (!moved.has(k)) problems.push(`${k} is missing from the redirected build (ROLL-55 keeps it byte-identical)`);
    else if (!moved.get(k).equals(plain.get(k))) problems.push(`${k} changed when ${step}'s redirects were applied (ROLL-55)`);
  }
  for (const r of redirected) {
    if (new URL(r.target).origin !== origin) problems.push(`${r.file} points off the panel origin, at ${r.target}`);
  }
  return problems;
}

/**
 * Fetch each target once, unauthenticated, not following redirects. Sequential
 * on purpose: this runs from CI and from a probe host, and eighteen requests in
 * a row is polite where eighteen at once looks like the crawl crowdsec's
 * scenarios exist to stop (SERVE-105).
 *
 * @returns {Promise<{url: string, status: number|null, ok: boolean, location?: string, error?: string}[]>}
 */
export async function probeTargets(targets, { fetchImpl = globalThis.fetch, timeoutMs = 15000 } = {}) {
  const out = [];
  for (const url of targets) {
    try {
      const res = await fetchImpl(url, {
        method: "GET",
        redirect: "manual",
        headers: { "user-agent": USER_AGENT, accept: "text/html" },
        signal: AbortSignal.timeout(timeoutMs),
      });
      const row = { url, status: res.status, ok: res.status === 200 };
      const location = res.headers?.get?.("location");
      if (location) row.location = location;
      out.push(row);
    } catch (e) {
      out.push({ url, status: null, ok: false, error: String(e?.message ?? e) });
    }
  }
  return out;
}

/**
 * The arming edit, and every precondition it has, in one place.
 *
 * Writes `redirectsFile` with `step`'s set filled from Table 5-F and an
 * `armed` record — the time, how many successors answered 200, and where
 * ROLL-54's review is recorded — only when the canary is green over the
 * committed catalogue AND every target answered 200. Otherwise it writes
 * nothing and says why.
 */
export async function arm({
  step, edgeReview, redirectsFile, tokens, index, revocations = null, registryDir = null,
  fetchImpl, now = new Date(), root = REPO,
}) {
  if (step === "R4b" && (typeof edgeReview !== "string" || !edgeReview.trim())) {
    return { armed: false, problems: ["ROLL-55: R4b's redirects are not committed before ROLL-54's edge review is recorded; pass --edge-review <where it is recorded>"] };
  }
  const text = fs.readFileSync(redirectsFile, "utf8");
  const doc = JSON.parse(text);
  const current = doc.sets?.find((s) => s?.step === step);
  if (!current) return { armed: false, problems: [`the redirects file has no set ${step}`] };
  if (Object.keys(current.paths ?? {}).length) {
    return { armed: false, problems: [`set ${step} already carries paths; arming is a one-time edit, and this is not it`] };
  }
  const expected = tableSet(tokens, step);
  const proposed = withSet(doc, step, expected);
  const x = expand({ index, revocations, registryDir, redirectsDoc: onlyStep(proposed, step), root });
  const problems = coverageProblems({ step, expected, ...x });
  const targets = targetsOf(x.redirected);
  const probed = problems.length ? [] : await probeTargets(targets, { fetchImpl });
  for (const p of probed) {
    if (!p.ok) {
      problems.push(`${p.url} answered ${p.status ?? p.error}${p.location ? ` → ${p.location}` : ""}; SERVE-84 wants 200 before ${step}`);
    }
  }
  if (problems.length) return { armed: false, problems, targets, probed };

  const record = {
    at: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
    successors_answered_200: probed.length,
    ...(step === "R4b" ? { edge_review: edgeReview.trim() } : {}),
  };
  const next = withSet(doc, step, expected, { [ARMED_MEMBER]: record });
  const trailing = text.endsWith("\n") ? "\n" : "";
  fs.writeFileSync(redirectsFile, JSON.stringify(next, null, 2) + trailing);
  return { armed: true, problems: [], targets, probed, record };
}

/**
 * The committed set, judged: RC-R4-1's canary "from the R4b marker, every
 * path in set R4b redirects", in both of the directions a tree can be wrong.
 *
 *   * marker on the tree, set empty — R4b opened and every Pages page still
 *     serves the page the service replaced;
 *   * set armed — then it covers every catalogue page (`coverageProblems`),
 *     and it carries the `armed` record `arm` writes: when, how many
 *     successors answered 200, and (for R4b) where ROLL-54's review is. A set
 *     filled by hand with no record is a set nobody can show was probed.
 *
 * @returns {string[]} problems; empty is green
 */
export function armedSetProblems({ doc, step = "R4b", markerPresent, tokens, index, revocations = null, registryDir = null, root = REPO }) {
  const set = doc.sets?.find((s) => s?.step === step);
  if (!set) return [`the redirects file has no set ${step}`];
  const problems = [];
  if (!Object.keys(set.paths ?? {}).length) {
    if (markerPresent) {
      problems.push(step === "R4b"
        ? `${R4B_MARKER} is on the tree and set ${step} is empty: R4b opened with every Pages page still serving ` +
          "the page the service replaced (ROLL-55; RC-R4-1)"
        : `${STEP_MARKER[step] ?? "its marker"} is on the tree and set ${step} is empty: R5 exited and R9a's request ` +
          "would go with the old pages still serving what the service replaced (ROLL-55; RC-R9-1)");
    }
    return problems;
  }
  const expected = tableSet(tokens, step);
  const x = expand({ index, revocations, registryDir, redirectsDoc: onlyStep(doc, step), root });
  problems.push(...coverageProblems({ step, expected, ...x }));
  const rec = set[ARMED_MEMBER];
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) {
    problems.push(
      `set ${step} carries paths and no \`${ARMED_MEMBER}\` record, so nothing shows its successors were probed ` +
        "before it was committed (SERVE-84); arm it with `node site/successors.mjs --arm`",
    );
    return problems;
  }
  if (typeof rec.at !== "string" || !TIME_RE.test(rec.at)) problems.push(`set ${step}'s ${ARMED_MEMBER}.at is not a §0.7 time`);
  if (!Number.isInteger(rec.successors_answered_200) || rec.successors_answered_200 < 1) {
    problems.push(`set ${step}'s ${ARMED_MEMBER}.successors_answered_200 is not a positive count`);
  }
  if (step === "R4b" && !(typeof rec.edge_review === "string" && rec.edge_review.trim())) {
    problems.push(`set R4b's ${ARMED_MEMBER}.edge_review is empty; ROLL-55 does not redirect before ROLL-54's review is recorded`);
  }
  return problems;
}

function parseArgs(argv) {
  const a = {
    index: path.join(REPO, "registry", "v1", "index.json"),
    revocations: path.join(REPO, "registry", "v1", "revocations.json"),
    redirects: path.join(REPO, "site", "redirects.json"),
    tokens: path.join(REPO, "schema", "contract-tokens-v1.json"),
    propose: null, arm: null, edgeReview: null, list: false, json: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const v = () => {
      if (i + 1 >= argv.length) throw new Error(`${k} needs a value`);
      return argv[++i];
    };
    if (k === "--index") a.index = path.resolve(v());
    else if (k === "--revocations") a.revocations = path.resolve(v());
    else if (k === "--redirects") a.redirects = path.resolve(v());
    else if (k === "--tokens") a.tokens = path.resolve(v());
    else if (k === "--propose") a.propose = v();
    else if (k === "--arm") a.arm = v();
    else if (k === "--edge-review") a.edgeReview = v();
    else if (k === "--list") a.list = true;
    else if (k === "--json") a.json = true;
    else throw new Error(`unknown argument ${JSON.stringify(k)}`);
  }
  if (a.propose && a.arm) throw new Error("--propose and --arm are two different questions; ask one");
  return a;
}

async function main(argv) {
  let a;
  try {
    a = parseArgs(argv);
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    return 2;
  }
  const tokens = JSON.parse(fs.readFileSync(a.tokens, "utf8"));
  const revocations = fs.existsSync(a.revocations) ? a.revocations : null;
  const registryDir = path.dirname(a.index);

  if (a.arm) {
    const r = await arm({
      step: a.arm, edgeReview: a.edgeReview, redirectsFile: a.redirects, tokens,
      index: a.index, revocations, registryDir,
    });
    if (a.json) console.log(JSON.stringify(r, null, 2));
    for (const p of r.probed ?? []) console.log(`${p.ok ? "ok  " : "FAIL"}  ${p.status ?? p.error}  ${p.url}${p.location ? ` → ${p.location}` : ""}`);
    for (const p of r.problems) console.error(`FAIL  ${p}`);
    if (r.armed) console.log(`armed set ${a.arm} in ${path.relative(process.cwd(), a.redirects)}: ${r.targets.length} successor(s) answered 200`);
    else console.error(`NOT ARMED: ${path.relative(process.cwd(), a.redirects)} is unchanged`);
    return r.armed ? 0 : 1;
  }

  let doc = JSON.parse(fs.readFileSync(a.redirects, "utf8"));
  let expected = null;
  if (a.propose) {
    expected = tableSet(tokens, a.propose);
    doc = withSet(doc, a.propose, expected);
  }
  const x = expand({ index: a.index, revocations, registryDir, redirectsDoc: a.propose ? onlyStep(doc, a.propose) : doc });
  const problems = a.propose ? coverageProblems({ step: a.propose, expected, ...x }) : [];
  const targets = targetsOf(x.redirected);
  if (!targets.length) {
    console.log("no set in the redirects file is armed, so there is no successor to probe");
    return 0;
  }
  const probed = a.list ? [] : await probeTargets(targets);
  const failed = probed.filter((p) => !p.ok);
  if (a.json) console.log(JSON.stringify({ pages: x.redirected, targets, probed, problems }, null, 2));
  else {
    if (a.list) for (const t of targets) console.log(t);
    for (const p of probed) console.log(`${p.ok ? "ok  " : "FAIL"}  ${p.status ?? p.error}  ${p.url}${p.location ? ` → ${p.location}` : ""}`);
    for (const p of problems) console.error(`FAIL  ${p}`);
    console.log(`${x.redirected.length} page(s) redirected, ${targets.length} distinct successor(s)` +
      (a.list ? "; not fetched (--list)" : `, ${probed.filter((p) => p.ok).length} answered 200`));
  }
  return problems.length || failed.length ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
