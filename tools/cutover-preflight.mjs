#!/usr/bin/env node
// ROLL-32's gate, asked one question at a time, before the cutover commit.
//
//     node tools/cutover-preflight.mjs
//     node tools/cutover-preflight.mjs --ref origin/main
//     node tools/cutover-preflight.mjs --astraplugins ../AstraPlugins
//     node tools/cutover-preflight.mjs --astra ~/src/Astra/astra-rs
//     node tools/cutover-preflight.mjs --no-github     # nothing leaves the box
//     node tools/cutover-preflight.mjs --selftest      # the fixtures below
//
// Registry plan M-T6.1, commit row reg.93. It is run by astra-plugins-ops and
// its output is pasted into that estate's `notes/state.md` (ops.43), which is
// the record the cutover commit's gate is read from.
//
// ── THE ONE DISTINCTION THIS FILE EXISTS TO KEEP ────────────────────────────
//
// Eleven preconditions, and a preflight that answers all eleven with PASS or
// FAIL is wrong in one specific way, which is the way that gets a cutover done
// on a question nobody asked.
//
// Five of the eleven CANNOT BE ANSWERED by any tool run from this repository.
// MOD-54's report page needs a signed-in `astraUser` session. OPEN-OWNER-20's
// delivery proof is the owner reading a mailbox. ROLL-32's walk needs a second
// Astra owner and the panel. BOT-85's heartbeats live at a dead-man receiver
// whose credential deliberately does not cross the party line (ROLL-44, "no
// dead-man credential crosses the party line"). OPEN-OPS-14's observation is an
// OWNER-APPROVED change to another repository that has not been made.
//
// A tool that prints FAIL for those five in the same words it prints FAIL for
// "seven `listing` issues are open" has told the operator that eleven questions
// were asked and eleven answers came back no. Six were asked. Five were not.
// Those are different facts and the operator acts on them differently: an
// answered no is work, and an unasked question is a person to go and find.
//
// So there are three words and they are never merged:
//
//     PASS · MET        asked here, on a named commit, and the answer is yes
//     FAIL · UNMET      asked here, on a named commit, and the answer is no
//     FAIL · NOT ASKED  this tool did not ask, and says who can
//
// and three exit codes, so the distinction survives a pipe: 0 when every check
// is MET, 1 when something is UNMET, 2 when nothing is UNMET but something was
// never asked. 2 is not "nearly zero"; it is "go and find five people".
//
// ── WHY THERE IS NO --attested FLAG ─────────────────────────────────────────
//
// The obvious next feature is a way to tell the tool that a walk happened, so
// the five NOT ASKED lines can go green. It is not here on purpose. A flag that
// turns "I could not ask" into PASS on the operator's say-so makes this file a
// place to record a belief, and the whole point of it is to be the one place in
// the cutover that records only measurements. The five walks are recorded in
// ops.43 in prose, dated, beside this output, by the person who did them, and
// the gate is read from the pair. This output is one half of that record and
// never the whole of it.
//
// ── IT PRINTS FAIL ON THE TREE IT LANDS ON, AND THAT IS THE DESIGN ──────────
//
// reg.93's row says so: "must print FAIL on the tree it lands on". At R0/R1
// almost no precondition of R6 is met, so a correct preflight is red on day
// one. A version of this that prints PASS tonight is a broken tool, and the
// first thing to suspect if it ever goes green early is this file, not the
// estate.
//
// ── WHAT IT READS, AND FROM WHERE ───────────────────────────────────────────
//
// Every tree fact is read from a named git ref with `git show <ref>:<path>` and
// `git ls-tree`, NEVER from the working copy. Several agents share this
// checkout; a neighbour's uncommitted file lying in `state/queue/` or a
// half-written `policy/binding-deadline.json` must not be able to move a
// verdict. The ref, its sha and its date are printed above the checks, and
// every tree verdict is a statement about that sha and nothing else.
//
// The one input that is not a tree fact is the open `listing` issue count,
// which is a live GitHub read through `gh`. When `gh` is missing, not logged
// in, or `--no-github` is given, that check is NOT ASKED — not PASS, and not
// UNMET. The tool never guesses a zero it did not count.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { REPO_ROOT, QUEUE_DIR } from "./lib/sources.mjs";
import { validate } from "./lib/jsonschema.mjs";
// The deadline's path comes from the module that DECIDES on it (M-T5.1), so
// this preflight cannot end up looking at a path the bot stopped writing.
import { DEADLINE_FILE, DEADLINE_SCHEMA } from "../bot/lib/listing-state.mjs";

const DAY = 86_400_000;
const THIRTY_DAYS = 30 * DAY;

/** `log/migration-notice-<n>.json` — MIG-13's markers, one per round (n10). */
const MARKER_DIR = "log";
const MARKER_RE = /^log\/migration-notice-(\d+)\.json$/;
const MARKER_SCHEMA = "astra.registry.migration-notice/1";

/** The workflow that carries BOT-87's poll and sweep, and the three jobs
 *  B-T5.0 turns on. Until they are on, no shadow poll has run or could have. */
const POLL_WORKFLOW = ".github/workflows/plugins-ingest.yml";
const POLL_JOBS = ["load", "poll", "remember"];

/** MOD-54's report page (§1.3 row 7, closed: minice-be `panel-site.md`:439). */
const REPORT_PAGE = "https://astra.minice.ai/plugins/_/report?plugin=<id>";

/** The two greps of check 5. They do not return the same thing, on purpose. */
const LINK_GREPS = [
  {
    name: "A",
    pattern: "astra-registry/issues",
    sees: "a registry issue URL written out in full",
  },
  {
    name: "B",
    pattern: "issues/new",
    sees: "any issue-opening URL, including the ones the CLI BUILDS at runtime",
  },
];

/** Why the entry says "by both greps" and means it. */
const LINK_GREPS_WHY = [
  "the CLI writes `https://github.com/{REGISTRY_REPO}/issues/new?template=…`, with the slug a",
  "constant substituted at compile time, so the literal `astra-registry/` is nowhere in the source",
  "and grep A cannot see the CLI's two live registry links at all. Grep A alone reports the author",
  "docs clean while the tool the author runs still opens an issue. Neither grep is the count.",
];

/** C30's reasoned exemptions that are identifiable by path. */
const LINK_EXEMPT = (p) =>
  path.posix.basename(p) === "CHANGELOG.md" || p === "PRODUCTION_PLAN.md";

// ── three words, never merged ───────────────────────────────────────────────

const MET = "PASS · MET";
const UNMET = "FAIL · UNMET";
const NOT_ASKED = "FAIL · NOT ASKED";

const met = (headline, lines = []) => ({ verdict: MET, headline, lines });
const unmet = (headline, lines = []) => ({ verdict: UNMET, headline, lines });
const notAsked = (headline, who, lines = []) => ({
  verdict: NOT_ASKED,
  headline,
  lines: [...lines, `answered by: ${who}`],
});

// ── git, always against a ref ───────────────────────────────────────────────

function git(args, cwd) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function gitQuiet(args, cwd) {
  try {
    return git(args, cwd);
  } catch {
    return null;
  }
}

/** The default branch of a checkout, asked of the checkout and never assumed.
 *  The registry is `main`; AstraPlugins is `master`. A tool that hardcodes one
 *  reads the wrong tree in the other repository and reports it as a fact. */
function defaultRef(cwd) {
  const head = gitQuiet(["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], cwd);
  if (head) {
    const name = head.trim().replace(/^refs\/remotes\//, "");
    if (gitQuiet(["rev-parse", "--verify", "--quiet", name], cwd)) return name;
  }
  for (const c of ["origin/main", "origin/master", "main", "master", "HEAD"]) {
    if (gitQuiet(["rev-parse", "--verify", "--quiet", c], cwd)) return c;
  }
  return "HEAD";
}

function refInfo(cwd, ref) {
  const sha = gitQuiet(["rev-parse", ref], cwd);
  if (!sha) return null;
  const date = gitQuiet(["log", "-1", "--format=%cI", ref], cwd);
  const subject = gitQuiet(["log", "-1", "--format=%s", ref], cwd);
  return { ref, sha: sha.trim(), date: (date || "").trim(), subject: (subject || "").trim() };
}

/** A tracked file's content at a ref, or null when the ref does not carry it. */
const showFile = (cwd, ref, p) => gitQuiet(["show", `${ref}:${p}`], cwd);

/** Every tracked path under a directory at a ref. An absent directory is an
 *  empty list, which is a reading of the tree and not a failure to read it. */
function lsTree(cwd, ref, dir) {
  const out = gitQuiet(["ls-tree", "-r", "--name-only", ref, "--", dir], cwd);
  return out === null ? [] : out.split("\n").filter(Boolean);
}

// ── dates ───────────────────────────────────────────────────────────────────

/** §0.7's shape, and a date that survives a round trip. Returns null on both
 *  failures, and the caller says which record was unreadable. */
function rfc3339(v) {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)) return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime()) || d.toISOString().replace(/\.\d{3}Z$/, "Z") !== v) return null;
  return d;
}

const days = (ms) => (ms / DAY).toFixed(1);

// ── the evaluators, pure so the selftest can drive them ─────────────────────

/**
 * MIG-13's markers. Three rules live here and each has cost somebody a plan
 * revision:
 *
 *   n10  the clock is the marker's `sent_at`, NEVER the commit date. A re-send
 *        that moves cutover LATER re-commits the marker and leaves `sent_at`
 *        alone; a reader keyed on the commit would restart the 30 days and
 *        delay a cutover the authors had already had notice of.
 *   n22  a cutover date moved EARLIER is a new round 2 with its own `sent_at`,
 *        so the clock is the LATEST round-2 marker's, not the first one's.
 *   n28  every later round's marker is re-committed with the new date, so no
 *        marker on `main` announces a superseded date. Two markers disagreeing
 *        about `cutover_planned_at` is the procedure done wrong, and it is
 *        red here rather than quietly counted from one of them.
 *
 * The authoritative marker is the one with the HIGHEST `round` present — not
 * the most recently committed file (M-T5.3, "which marker is authoritative").
 */
export function evalRound2(markers, now) {
  if (markers.length === 0) {
    return unmet("no migration-notice marker is on this ref at all", [
      `looked at: ${MARKER_DIR}/migration-notice-<n>.json`,
      "round 2 has not been sent, so ROLL-32's 30 days have not started.",
    ]);
  }
  const bad = markers.filter((m) => !Number.isInteger(m.doc?.round));
  if (bad.length) {
    return unmet("a marker carries no integer `round`", bad.map((m) => `  ${m.file}`));
  }
  // The file name carries the round too (`migration-notice-<n>.json`), and two
  // readers pick different ones: this preflight and M-T5.4's watch read the
  // record, a person reading `log/` reads the name. They must not disagree.
  const misnamed = markers.filter((m) => m.round !== undefined && m.round !== m.doc.round);
  if (misnamed.length) {
    return unmet("a marker's file name and its `round` disagree", [
      ...misnamed.map((m) => `  ${m.file} carries round ${m.doc.round}`),
      "a reader going by the name and a reader going by the record would take different markers.",
    ]);
  }
  const rounds = new Map();
  for (const m of markers) {
    if (!rounds.has(m.doc.round)) rounds.set(m.doc.round, []);
    rounds.get(m.doc.round).push(m);
  }
  for (const [round, group] of rounds) {
    if (group.length > 1) {
      return unmet(`round ${round} has ${group.length} markers, and MIG-13 says one per round`, [
        ...group.map((m) => `  ${m.file}`),
        "which one a reader takes is then undefined, and two readers can take different ones.",
      ]);
    }
  }
  const authoritative = [...rounds.keys()].sort((a, b) => b - a)[0];
  const lines = [
    `markers on this ref: ${markers.map((m) => `${m.file} (round ${m.doc.round})`).join(", ")}`,
    `authoritative marker: round ${authoritative} — the highest round present, not the newest file`,
  ];

  // n28. Every marker must announce the authoritative date.
  const announced = rounds.get(authoritative)[0].doc.cutover_planned_at;
  const disagree = markers.filter(
    (m) => m.doc.round >= 2 && m.doc.cutover_planned_at !== announced,
  );
  if (disagree.length) {
    return unmet("markers announce different cutover dates (n28)", [
      ...lines,
      ...disagree.map(
        (m) => `  ${m.file} announces ${m.doc.cutover_planned_at}, round ${authoritative} announces ${announced}`,
      ),
      "a marker on `main` is announcing a superseded date; re-commit it before reading any clock from it.",
    ]);
  }

  const two = rounds.get(2)?.[0];
  if (!two) {
    return unmet("no round-2 marker is on this ref", [
      ...lines,
      "ROLL-32 counts from round 2's marker, and there is not one.",
    ]);
  }
  const sentAt = rfc3339(two.doc.sent_at);
  const plannedAt = rfc3339(two.doc.cutover_planned_at);
  if (!sentAt || !plannedAt) {
    return unmet("round 2's marker has no readable `sent_at`/`cutover_planned_at`", [
      ...lines,
      `  ${two.file}: sent_at=${JSON.stringify(two.doc.sent_at)} cutover_planned_at=${JSON.stringify(two.doc.cutover_planned_at)}`,
      "§0.7 is RFC 3339 UTC, whole seconds, ending in Z, and a date that round-trips.",
    ]);
  }
  lines.push(
    `round 2 sent_at: ${two.doc.sent_at} — read from the record, never from the commit (n10)`,
    `round 2 cutover_planned_at: ${two.doc.cutover_planned_at}`,
  );
  const age = now.getTime() - sentAt.getTime();
  if (age < THIRTY_DAYS) {
    return unmet(`round 2 is ${days(age)} days old; ROLL-32 needs 30`, lines);
  }
  if (now.getTime() < plannedAt.getTime()) {
    return unmet(
      `the announced cutover date has not come (${days(plannedAt.getTime() - now.getTime())} days away)`,
      lines,
    );
  }
  return met(`round 2 is ${days(age)} days old and its announced date has come`, lines);
}

/** MIG-29/ROLL-32: the deadline is at least 30 days away from now. */
export function evalDeadline(doc, now) {
  if (doc === null) {
    return unmet(`no ${DEADLINE_FILE} on this ref`, [
      "the deadline is the owner's, committed by hand before R4b (MIG-2; reg.87, OWNER DECISION).",
      "absence is a state and not an error for the bot (every listing is `grandfathered`),",
      "but ROLL-32 cannot be met by a deadline that does not exist.",
    ]);
  }
  const at = rfc3339(doc.deadline);
  if (!at) {
    return unmet(`${DEADLINE_FILE} carries no readable \`deadline\``, [
      `  deadline=${JSON.stringify(doc.deadline)}`,
    ]);
  }
  const away = at.getTime() - now.getTime();
  const lines = [`deadline: ${doc.deadline} (${days(away)} days away)`];
  if (away < THIRTY_DAYS) {
    return unmet("the deadline is under 30 days away", [
      ...lines,
      "MIG-29: the owner moves it later (never earlier) before cutover can begin.",
    ]);
  }
  return met("the deadline is more than 30 days away", lines);
}

/**
 * The publication queue. `readQueue` in bot/lib/policy/queue.mjs keeps only the
 * entries carrying `repo`, `tag` and `publish_after` and silently skips the
 * rest — right for a drain that must not stop for one malformed file, wrong for
 * a preflight, because a skipped entry is a release the drain will never empty
 * and nobody will see it go. So this lists the DIRECTORY and names what the
 * drain's own reader would drop.
 */
export function evalQueue(entries) {
  const lines = [`${QUEUE_DIR}/ holds ${entries.length} entr${entries.length === 1 ? "y" : "ies"}`];
  const invisible = entries.filter((e) => !(e.doc && e.doc.repo && e.doc.tag && e.doc.publish_after));
  for (const e of entries) {
    lines.push(`  ${e.file}${e.doc?.publish_after ? ` — publish_after ${e.doc.publish_after}` : ""}`);
  }
  if (invisible.length) {
    return unmet(`${invisible.length} queue entr${invisible.length === 1 ? "y is" : "ies are"} invisible to the drain`, [
      ...lines,
      ...invisible.map(
        (e) =>
          `  INVISIBLE: ${e.file} — ` +
          (e.doc === null
            ? "does not parse as JSON"
            : `missing ${["repo", "tag", "publish_after"].filter((k) => !e.doc[k]).join(", ")}`),
      ),
      "bot/lib/policy/queue.mjs's readQueue skips these, so the hourly drain will never empty them",
      "and landing order step 4 would wait on a file nothing is processing.",
    ]);
  }
  if (entries.length === 0) {
    return met("the queue is empty; nothing for the drain to empty", [
      ...lines,
      "re-read at the cutover commit: an ingest run can queue a release at any time until the triggers go.",
    ]);
  }
  return met("every queue entry is listed and visible to the drain", lines);
}

// ── the checks ──────────────────────────────────────────────────────────────

function checkListingIssues(ctx) {
  if (ctx.noGithub) {
    return notAsked(
      "--no-github was given, so no issue was counted",
      "whoever runs this without --no-github, or `gh issue list --repo " +
        `${ctx.slug} --label listing --state open\``,
    );
  }
  let out;
  try {
    out = execFileSync(
      "gh",
      ["issue", "list", "--repo", ctx.slug, "--label", "listing", "--state", "open",
        "--limit", "200", "--json", "number,title,createdAt"],
      { encoding: "utf8", timeout: 60_000, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (e) {
    return notAsked(`\`gh\` could not answer: ${String(e.message || e).split("\n")[0]}`,
      "an operator with `gh auth login`, or the repository's issue list in a browser");
  }
  let issues;
  try {
    issues = JSON.parse(out);
  } catch {
    return notAsked("`gh` returned something this tool could not parse",
      "an operator reading the issue list directly");
  }
  // The real clock, not --now: this one line is a live reading and is dated as
  // one even when the tree checks are being run against a fixed moment.
  const at = new Date().toISOString();
  if (issues.length === 0) {
    return met("zero open `listing` issues", [`counted live in ${ctx.slug} at ${at}`]);
  }
  return unmet(`${issues.length} open \`listing\` issue${issues.length === 1 ? "" : "s"}`, [
    `counted live in ${ctx.slug} at ${at}`,
    ...issues.map((i) => `  #${i.number} ${i.title} (${i.createdAt})`),
    "MIG-19: each close is an OWNER APPROVAL act, with a pointer to the panel, recorded.",
  ]);
}

function checkRound2(ctx) {
  const markers = [];
  for (const p of lsTree(ctx.repo, ctx.ref, MARKER_DIR)) {
    const m = MARKER_RE.exec(p);
    if (!m) continue;
    const raw = showFile(ctx.repo, ctx.ref, p);
    let doc = null;
    try {
      doc = JSON.parse(raw);
    } catch {
      doc = null;
    }
    markers.push({ file: p, round: Number(m[1]), doc: doc ?? {} });
  }
  const r = evalRound2(markers, ctx.now);
  // The member list comes from the contract's own token file rather than from a
  // literal here, so a member added or retired by a contract release reaches
  // this check without an edit — and a token file that stops naming the record
  // is loud instead of silently checking nothing.
  const members = markerMembers(ctx);
  if (!members) {
    return unmet("schema/contract-tokens-v1.json no longer names " + MARKER_SCHEMA, [
      "this preflight takes the marker's required members from the token file.",
      "if the contract retired the record, this check is checking nothing until somebody says what replaced it.",
    ]);
  }
  r.lines.push(`required members, from schema/contract-tokens-v1.json: ${members.join(", ")}`);
  for (const m of markers) {
    // B.4 (contract §2, "On `main`") reads: exactly `schema`, `round`, `sent_at`,
    // "and `cutover_planned_at` FROM ROUND 2". The token file's member list has
    // nowhere to put that condition and records the member as required outright,
    // so a round-1 marker that conforms to B.4 fails a plain member check. The
    // condition is applied here, and the mismatch is noted rather than enforced.
    const required = m.doc?.round === 1 ? members.filter((k) => k !== "cutover_planned_at") : members;
    const missing = required.filter((k) => !(k in (m.doc || {})));
    if (missing.length) r.lines.push(`  ${m.file} is missing ${missing.join(", ")}`);
  }
  return r;
}

function markerMembers(ctx) {
  const raw = showFile(ctx.repo, ctx.ref, "schema/contract-tokens-v1.json");
  if (!raw) return null;
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    return null;
  }
  const entry = (doc.entries || []).find((e) => e.name === MARKER_SCHEMA);
  if (!entry) return null;
  return (entry.members || []).filter((m) => m.required).map((m) => m.name);
}

function checkDeadline(ctx) {
  const raw = showFile(ctx.repo, ctx.ref, DEADLINE_FILE);
  if (raw === null) return evalDeadline(null, ctx.now);
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    return unmet(`${DEADLINE_FILE} is not JSON`, []);
  }
  const r = evalDeadline(doc, ctx.now);
  // Judged by the registry's own schema, from the same ref, so this tool and
  // bot/lib/listing-state.mjs cannot disagree about what a deadline record is.
  const schemaRaw = showFile(ctx.repo, ctx.ref, "schema/deadline-v1.json");
  if (schemaRaw) {
    const problems = validate(JSON.parse(schemaRaw), doc);
    if (problems.length) {
      return unmet(`${DEADLINE_FILE} does not validate against schema/deadline-v1.json`, [
        ...r.lines,
        ...problems.slice(0, 8).map((p) => `  ${p.path || "$"}: ${p.message || p}`),
      ]);
    }
    r.lines.push(`validated against schema/deadline-v1.json (${DEADLINE_SCHEMA})`);
  }
  return r;
}

function checkQueue(ctx) {
  const entries = [];
  for (const p of lsTree(ctx.repo, ctx.ref, QUEUE_DIR)) {
    if (!p.endsWith(".json")) continue;
    let doc = null;
    try {
      doc = JSON.parse(showFile(ctx.repo, ctx.ref, p));
    } catch {
      doc = null;
    }
    entries.push({ file: p, doc });
  }
  const r = evalQueue(entries);
  // Two facts that must agree: the predicate named above and the one the drain
  // actually applies. When they stop agreeing, the list of invisible entries is
  // a guess, so say so rather than printing it.
  const src = showFile(ctx.repo, ctx.ref, "bot/lib/policy/queue.mjs") || "";
  if (!/doc\.repo\s*&&\s*doc\.tag\s*&&\s*doc\.publish_after/.test(src)) {
    return unmet("the drain's own filter has moved", [
      ...r.lines,
      "bot/lib/policy/queue.mjs no longer filters on `doc.repo && doc.tag && doc.publish_after`,",
      "so this check's list of entries the drain cannot see is out of date. Fix this file, then re-run.",
    ]);
  }
  return r;
}

function checkLinks(ctx) {
  if (!ctx.astraPlugins) {
    return notAsked("no AstraPlugins checkout was found", "whoever runs this with --astraplugins <dir>", [
      "looked for: " + ctx.astraPluginsTried.join(", "),
    ]);
  }
  const { dir, ref, info } = ctx.astraPlugins;
  const lines = [`read ${ref} = ${info.sha.slice(0, 12)} (${info.date}) in ${dir}`];
  const hits = {};
  for (const g of LINK_GREPS) {
    const out = gitQuiet(["grep", "-n", "-I", "--no-color", "-e", g.pattern, ref], dir);
    const rows = (out || "")
      .split("\n")
      .filter(Boolean)
      .map((l) => l.replace(new RegExp(`^${ref.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:`), ""))
      .map((l) => {
        const i = l.indexOf(":");
        const j = l.indexOf(":", i + 1);
        return { file: l.slice(0, i), line: l.slice(i + 1, j), text: l.slice(j + 1) };
      });
    hits[g.name] = rows;
    const exempt = rows.filter((r) => LINK_EXEMPT(r.file));
    lines.push(
      `grep ${g.name} \`${g.pattern}\`: ${rows.length} line${rows.length === 1 ? "" : "s"} in ` +
        `${new Set(rows.map((r) => r.file)).size} files` +
        (exempt.length ? `, of which ${exempt.length} in C30-exempt paths` : "") +
        ` — ${g.sees}`,
    );
  }
  // The pair only means something while A's hits are a subset of B's. If A ever
  // sees a line B does not, one of the two patterns has been edited and "both
  // greps" has quietly become "two unrelated greps".
  lines.push(...LINK_GREPS_WHY);
  const bKeys = new Set(hits.B.map((r) => `${r.file}:${r.line}`));
  const onlyA = hits.A.filter((r) => !bKeys.has(`${r.file}:${r.line}`));
  if (onlyA.length) {
    return unmet("the two greps have drifted apart", [
      ...lines,
      ...onlyA.map((r) => `  only grep A: ${r.file}:${r.line}`),
      "grep A is meant to be a subset of grep B. It is not, so the pair no longer measures what it says.",
    ]);
  }
  const onlyB = hits.B.filter((r) => !hits.A.some((a) => `${a.file}:${a.line}` === `${r.file}:${r.line}`));
  lines.push(
    `the deliberate difference: grep B sees ${onlyB.length} line${onlyB.length === 1 ? "" : "s"} grep A cannot —`,
  );
  for (const l of byFile(onlyB)) lines.push(`  ${l}`);

  const counted = hits.B.filter((r) => !LINK_EXEMPT(r.file));
  if (counted.length) {
    lines.push(
      `counted: ${counted.length} lines in ${new Set(counted.map((r) => r.file)).size} files ` +
        "(grep B, C30-exempt paths removed) —",
    );
    for (const l of byFile(counted)) lines.push(`  ${l}`);
  }
  if (counted.length === 0) {
    if (!/(^|\/)(master|main)$/.test(ref)) {
      return notAsked(`zero links, but on ${ref} rather than the default branch`,
        "whoever re-runs this against AstraPlugins' default branch", lines);
    }
    return met("no registry-issue link is left in AstraPlugins", lines);
  }
  return unmet(
    `${counted.length} registry-issue link${counted.length === 1 ? "" : "s"} are still in AstraPlugins ` +
      "(C30-exempt paths excluded)",
    [
      ...lines,
      "commit set A (AP-15 to AP-18) lands these edits before the registry's cutover commit B.",
      "C30's third exemption, the FLOW-47 `--notify` stub, is a code region and not a path, so it is counted here.",
    ],
  );
}

/** `path:line,line` per file, so a 29-line grep is readable in a record. */
function byFile(rows) {
  const m = new Map();
  for (const r of rows) {
    if (!m.has(r.file)) m.set(r.file, []);
    m.get(r.file).push(r.line);
  }
  return [...m].map(([f, ls]) => `${f}:${ls.join(",")}${LINK_EXEMPT(f) ? "   (C30-exempt)" : ""}`);
}

function checkShadowPoll(ctx) {
  const yaml = showFile(ctx.repo, ctx.ref, POLL_WORKFLOW);
  if (yaml === null) {
    return unmet(`${POLL_WORKFLOW} is not on this ref`, [
      "BOT-87's poll and sweep live in it; without the file there is no shadow poll to record.",
    ]);
  }
  const lines = [];
  const dark = [];
  for (const job of POLL_JOBS) {
    const block = jobBlock(yaml, job);
    if (block === null) {
      dark.push(job);
      lines.push(`  job \`${job}\`: not in ${POLL_WORKFLOW}`);
      continue;
    }
    const off = /^\s{4}if:\s*false\s*$/m.test(block);
    lines.push(`  job \`${job}\`: ${off ? "if: false — never runs" : "enabled"}`);
    if (off) dark.push(job);
  }
  const scheduled = /^\s*schedule:\s*$/m.test(yaml.replace(/^\s*#.*$/gm, ""));
  lines.push(`  schedule: ${scheduled ? "live" : "commented out — the workflow has no cron"}`);
  if (dark.length) {
    return unmet(`B-T5.0's jobs are still off (${dark.join(", ")})`, [
      ...lines,
      "no shadow poll has run, so there is nothing recorded, nothing seeded from state/releases-seen.json,",
      "and no evidence that it registers no recorded tag. reg.94 turns them on at R5.",
    ]);
  }
  return notAsked(
    "the jobs are on, but whether a run seeded its memory and registered no recorded tag is not a tree fact",
    "ops.40's shadow-poll record and W2's acknowledgement, which name the run",
    lines,
  );
}

/** One job's YAML block, from `^  <name>:` to the next job at the same indent. */
function jobBlock(yaml, name) {
  const lines = yaml.split("\n");
  const start = lines.findIndex((l) => l === `  ${name}:`);
  if (start === -1) return null;
  const out = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {2}[A-Za-z0-9_-]+:/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join("\n");
}

function checkReportPage() {
  return notAsked(
    "MOD-54's report page has not been walked",
    "an operator signed in as an `astraUser`, recorded in ops.43",
    [
      `walk: ${REPORT_PAGE}, from a plugin page's report link`,
      "why this tool cannot: the page is gated to a signed-in astraUser and no session belongs to this side.",
      "MOD-54 is a gate of R6 (§2.9 Gate in, \"MOD-54 live\"), and M-T6.2's commit C points config.yml's",
      "first contact link at that action, so the page existing is a precondition of the link naming it.",
    ],
  );
}

function checkDeliveryProof() {
  return notAsked(
    "OPEN-OWNER-20's delivery proof is not recorded here",
    "the owner, recorded in ops.43",
    [
      "prove: mail reaches security@minice.ai and the owner reads it.",
      "why this tool cannot: it is a mailbox the owner reads, and no registry credential opens it.",
      "AP-17 is HARD-GATED on it (plug.24), because that commit is the one that prints the address.",
    ],
  );
}

function checkThirdPartyWalk() {
  return notAsked(
    "ROLL-32's third-party walk is not recorded here",
    "an Astra owner OTHER THAN the project owner, recorded in ops.43",
    [
      "walk: a first listing to `served`, and one `B_BINDING_UNUSABLE` (panel: `B_BINDING_INVALID`)",
      "      with a token minted for another repository (contract ROLL-32).",
      "why this tool cannot: it needs the panel and a second person; a walk one person reports of themselves",
      "      is the thing ROLL-32 asks a second owner for.",
    ],
  );
}

function checkHeartbeats() {
  return notAsked(
    "BOT-85's heartbeats for the poll and the sweep are not visible from here",
    "an operator at the dead-man receiver, recorded in ops.43",
    [
      "look at: receiver check \"BOT-87's poll and sweep\" (B-T5.0, B-T5.1), within its silence bound",
      "         — the longer of 3 × the interval and 90 minutes, recalibrated at R3 (OPEN-OPS-13).",
      "why this tool cannot, and must not: ROLL-44's row is \"no dead-man credential crosses the party line\".",
      "         A preflight holding a receiver credential would be the leak that row forbids.",
    ],
  );
}

function checkOpenOps14(ctx) {
  const lines = [
    "do: on the TEST repository, remove its forms, keep `blank_issues_enabled: false`,",
    "    open the old client's exact URL shape, and record what GitHub shows.",
    "OWNER APPROVAL is required for any change to that repository (ext.14).",
  ];
  if (ctx.astra) {
    const p = "astra-daemon/src/server/services/plugin.rs";
    const file = path.join(ctx.astra, p);
    let found = null;
    try {
      const src = fs.readFileSync(file, "utf8").split("\n");
      const i = src.findIndex((l) => l.includes("issues/new?labels="));
      if (i !== -1) found = { line: i + 1, text: src[i].trim() };
    } catch {
      found = null;
    }
    if (found) {
      lines.push(`URL shape, read at A:${p}:${found.line}: ${found.text}`);
    } else {
      lines.push(
        `A:${p} carries no \`issues/new?labels=\` line any more. The shape to observe comes from the`,
        "daemon build the observation is about, so check the reference before walking it.",
      );
    }
  } else {
    lines.push(
      "URL shape: not read — pass --astra <astra-rs> to have it read out of the daemon source",
      "           (astra-daemon/src/server/services/plugin.rs).",
    );
  }
  return notAsked("OPEN-OPS-14's observation has not been made", "the owner, then ops.43", lines);
}

const CHECKS = [
  { id: "listing-issues", clause: "zero open `listing` issues (MIG-19)", run: checkListingIssues },
  { id: "round-2-marker", clause: "round 2 is 30 days old and its announced date has come (ROLL-32; n10, n22, n28)", run: checkRound2 },
  { id: "binding-deadline", clause: "the deadline is at least 30 days away (MIG-29)", run: checkDeadline },
  { id: "queue-drain", clause: "`state/queue/` entries are listed", run: checkQueue },
  { id: "astraplugins-issue-links", clause: "the AstraPlugins registry-issue link count, by both greps", run: checkLinks },
  { id: "mod-54-report-page", clause: "MOD-54's page, from a signed-in walk", run: checkReportPage },
  { id: "owner-20-delivery-proof", clause: "OPEN-OWNER-20's delivery proof", run: checkDeliveryProof },
  { id: "roll-32-third-party-walk", clause: "ROLL-32's third-party walk", run: checkThirdPartyWalk },
  { id: "shadow-poll", clause: "B-T5.0's shadow poll recorded, seeded, registering no recorded tag", run: checkShadowPoll },
  { id: "bot-85-heartbeats", clause: "BOT-85 heartbeats for the poll and the sweep, at the receiver", run: checkHeartbeats },
  { id: "open-ops-14", clause: "OPEN-OPS-14's test-repository observation", run: checkOpenOps14 },
];

// ── running ─────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = { ref: null, astraPlugins: null, astra: null, noGithub: false, selftest: false, now: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--ref") out.ref = argv[++i];
    else if (a === "--astraplugins") out.astraPlugins = argv[++i];
    else if (a === "--astra") out.astra = argv[++i];
    else if (a === "--now") out.now = argv[++i];
    else if (a === "--no-github") out.noGithub = true;
    else if (a === "--selftest") out.selftest = true;
    else if (a === "--attested" || a.startsWith("--attested=")) {
      console.error(
        "There is no --attested flag, on purpose. A walk this tool could not make is recorded in\n" +
          "ops.43 by the person who made it, beside this output, and the gate is read from the pair.\n" +
          "See the header, \"WHY THERE IS NO --attested FLAG\".",
      );
      process.exit(64);
    } else {
      console.error(`unknown argument: ${a}`);
      process.exit(64);
    }
  }
  return out;
}

function findAstraPlugins(explicit) {
  const tried = [];
  const candidates = explicit
    ? [explicit]
    : [
        path.resolve(REPO_ROOT, "..", "AstraPlugins"),
        path.resolve(os.homedir(), "Documents/GitHub/AstraPlugins"),
      ];
  for (const dir of candidates) {
    tried.push(dir);
    if (!fs.existsSync(path.join(dir, ".git"))) continue;
    const ref = defaultRef(dir);
    const info = refInfo(dir, ref);
    if (info) return { found: { dir, ref, info }, tried };
  }
  return { found: null, tried };
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.selftest) return selftest();

  const repo = REPO_ROOT;
  const ref = args.ref || defaultRef(repo);
  const info = refInfo(repo, ref);
  if (!info) {
    console.error(`cannot resolve ref ${ref} in ${repo}`);
    return 70;
  }
  const now = args.now ? new Date(args.now) : new Date();
  if (Number.isNaN(now.getTime())) {
    console.error(`--now ${args.now} is not a date`);
    return 64;
  }
  const ap = findAstraPlugins(args.astraPlugins);
  const remote = gitQuiet(["remote", "get-url", "origin"], repo) || "";
  const slug = (/github\.com[:/]([^/]+\/[^/.]+)/.exec(remote.trim()) || [, "mihailinl/astra-registry"])[1];

  const ctx = {
    repo,
    ref,
    info,
    now,
    slug,
    noGithub: args.noGithub,
    astra: args.astra,
    astraPlugins: ap.found,
    astraPluginsTried: ap.tried,
  };

  const out = [];
  const say = (s = "") => out.push(s);

  say("astra-registry cutover preflight — M-T6.1 / reg.93, ROLL-32's gate");
  say(`run at ${now.toISOString()}`);
  say(`registry tree read at ${ref} = ${info.sha} (${info.date})`);
  say(`                      ${info.subject}`);
  const localMain = refInfo(repo, "main");
  if (localMain && localMain.sha !== info.sha) {
    say(`  note: this clone's \`main\` is ${localMain.sha.slice(0, 12)}, which is not the ref above.`);
  }
  say("tree facts come from `git show <ref>:<path>`, never from the working copy.");
  say("");
  say("Three words, never merged:");
  say("  PASS · MET        asked here, on the ref above, and the answer is yes");
  say("  FAIL · UNMET      asked here, on the ref above, and the answer is no");
  say("  FAIL · NOT ASKED  this tool did not ask. It is not a no; it is a question still open.");
  say("");

  const results = [];
  for (const [i, check] of CHECKS.entries()) {
    let r;
    try {
      r = check.run(ctx);
    } catch (e) {
      r = notAsked(`this check threw: ${String(e.message || e).split("\n")[0]}`,
        "whoever fixes tools/cutover-preflight.mjs — a check that throws has asked nothing");
    }
    results.push({ ...check, ...r });
    say(`${r.verdict.padEnd(16)} ${String(i + 1).padStart(2)}. ${check.id} — ${check.clause}`);
    say(`${" ".repeat(20)}${r.headline}`);
    for (const l of r.lines) say(`${" ".repeat(20)}${l}`);
    say("");
  }

  const n = (v) => results.filter((r) => r.verdict === v).length;
  say("─".repeat(78));
  say(`${String(n(MET)).padStart(2)}  PASS · MET`);
  say(`${String(n(UNMET)).padStart(2)}  FAIL · UNMET      — asked on ${info.sha.slice(0, 12)}, and the answer is no`);
  say(`${String(n(NOT_ASKED)).padStart(2)}  FAIL · NOT ASKED  — nobody asked. "I could not ask" is not "the answer is no".`);
  say("");
  if (n(UNMET) === 0 && n(NOT_ASKED) === 0) {
    say("ROLL-32's preconditions are met on this ref. The cutover commit's gate is open.");
  } else {
    say("NOT CLEARED FOR CUTOVER.");
    if (n(NOT_ASKED)) {
      say(`${n(NOT_ASKED)} of the ${CHECKS.length} were never asked; each names who answers it and where the`);
      say("answer is recorded (ops.43). No amount of re-running this tool will change them.");
    }
  }
  console.log(out.join("\n"));
  if (n(UNMET)) return 1;
  if (n(NOT_ASKED)) return 2;
  return 0;
}

// ── selftest ────────────────────────────────────────────────────────────────
//
// The evaluators are driven against fixtures, including the three the plan
// warns about by name: reading the commit date instead of `sent_at`, reading
// the FIRST round-2 marker instead of the latest, and letting two markers
// announce different dates. Each fixture is a case where a plausible wrong
// implementation gives the opposite answer, which is the only kind worth
// asserting.

function selftest() {
  const fails = [];
  const is = (what, got, want) => {
    if (got !== want) fails.push(`${what}: got ${got}, want ${want}`);
  };
  const T = (s) => new Date(s);
  const marker = (round, sent, planned, file = `log/migration-notice-${round}.json`) => ({
    file,
    round,
    doc: { schema: MARKER_SCHEMA, round, sent_at: sent, cutover_planned_at: planned },
  });

  // The three words are three words.
  is("the verdicts are distinct", new Set([MET, UNMET, NOT_ASKED]).size, 3);

  // No marker at all.
  is("no marker", evalRound2([], T("2026-09-21T00:00:00Z")).verdict, UNMET);

  // n10: the clock is `sent_at`, not the commit. A marker re-committed today
  // whose `sent_at` is 40 days old is MET — an implementation keyed on the
  // commit date would call this UNMET and delay a cutover already noticed.
  is(
    "n10: 40 days by sent_at, re-committed today",
    evalRound2(
      [marker(2, "2026-08-12T00:00:00Z", "2026-09-20T00:00:00Z")],
      T("2026-09-21T00:00:00Z"),
    ).verdict,
    MET,
  );

  // 29 days is not 30.
  is(
    "29 days",
    evalRound2([marker(2, "2026-08-23T00:00:00Z", "2026-09-20T00:00:00Z")], T("2026-09-21T00:00:00Z")).verdict,
    UNMET,
  );

  // The announced date has not come.
  is(
    "date not come",
    evalRound2([marker(2, "2026-08-01T00:00:00Z", "2026-10-30T00:00:00Z")], T("2026-09-21T00:00:00Z")).verdict,
    UNMET,
  );

  // n22: an earlier date is a NEW round 2 with its own `sent_at`. One file per
  // round, so the latest content is what is read — 10 days old here, and UNMET.
  is(
    "n22: a new round 2, 10 days old",
    evalRound2([marker(2, "2026-09-11T00:00:00Z", "2026-09-20T00:00:00Z")], T("2026-09-21T00:00:00Z")).verdict,
    UNMET,
  );

  // n28: rounds 2 and 3 announcing different dates is the procedure done wrong,
  // and it is red here even though round 2 alone would pass.
  is(
    "n28: markers disagree",
    evalRound2(
      [
        marker(2, "2026-08-01T00:00:00Z", "2026-09-20T00:00:00Z"),
        marker(3, "2026-09-01T00:00:00Z", "2026-10-15T00:00:00Z"),
      ],
      T("2026-09-21T00:00:00Z"),
    ).verdict,
    UNMET,
  );

  // Rounds 2 and 3 agreeing: the clock is round 2's `sent_at`, not round 3's.
  // Round 3's own sent_at is 3 days old; taking it would give UNMET.
  is(
    "the clock is round 2's, with round 3 present",
    evalRound2(
      [
        marker(2, "2026-08-01T00:00:00Z", "2026-09-20T00:00:00Z"),
        marker(3, "2026-09-18T00:00:00Z", "2026-09-20T00:00:00Z"),
      ],
      T("2026-09-21T00:00:00Z"),
    ).verdict,
    MET,
  );

  // Round 1 alone is not round 2.
  is(
    "round 1 only",
    evalRound2([marker(1, "2026-06-01T00:00:00Z", undefined)], T("2026-09-21T00:00:00Z")).verdict,
    UNMET,
  );

  // Two files claiming the same round: MIG-13 says one per round.
  is(
    "two round-2 markers",
    evalRound2(
      [
        marker(2, "2026-08-01T00:00:00Z", "2026-09-20T00:00:00Z"),
        marker(2, "2026-08-20T00:00:00Z", "2026-09-20T00:00:00Z", "log/migration-notice-2.json.old"),
      ],
      T("2026-09-21T00:00:00Z"),
    ).verdict,
    UNMET,
  );

  // The file name and the record disagreeing about the round.
  {
    const m = marker(2, "2026-08-01T00:00:00Z", "2026-09-20T00:00:00Z");
    m.round = 3;
    is("name and record disagree", evalRound2([m], T("2026-09-21T00:00:00Z")).verdict, UNMET);
  }

  // A date that matches §0.7's pattern and is not a date.
  is(
    "2026-02-31 is not a date",
    evalRound2([marker(2, "2026-02-31T00:00:00Z", "2026-09-20T00:00:00Z")], T("2026-09-21T00:00:00Z")).verdict,
    UNMET,
  );

  // The deadline.
  is("no deadline file", evalDeadline(null, T("2026-09-21T00:00:00Z")).verdict, UNMET);
  is(
    "deadline 31 days away",
    evalDeadline({ deadline: "2026-10-22T00:00:00Z" }, T("2026-09-21T00:00:00Z")).verdict,
    MET,
  );
  is(
    "deadline 29 days away",
    evalDeadline({ deadline: "2026-10-20T00:00:00Z" }, T("2026-09-21T00:00:00Z")).verdict,
    UNMET,
  );
  is(
    "deadline in the past",
    evalDeadline({ deadline: "2026-09-01T00:00:00Z" }, T("2026-09-21T00:00:00Z")).verdict,
    UNMET,
  );

  // The queue, and the entry the drain cannot see.
  is("empty queue", evalQueue([]).verdict, MET);
  is(
    "one good entry",
    evalQueue([{ file: "state/queue/a@1.0.0.json", doc: { repo: "x/y", tag: "v1", publish_after: "2026-09-22T00:00:00Z" } }]).verdict,
    MET,
  );
  is(
    "an entry the drain skips",
    evalQueue([{ file: "state/queue/a@1.0.0.json", doc: { repo: "x/y" } }]).verdict,
    UNMET,
  );
  is("an unparseable entry", evalQueue([{ file: "state/queue/a@1.0.0.json", doc: null }]).verdict, UNMET);

  if (fails.length) {
    for (const f of fails) console.error(`selftest: ${f}`);
    console.error(`${fails.length} selftest failure(s)`);
    return 1;
  }
  console.log("selftest: ok");
  return 0;
}

// `process.exitCode`, never `process.exit`: stdout to a pipe is asynchronous on
// POSIX, and exiting on the line after `console.log` truncates the record this
// tool exists to produce. The output is the deliverable; the code is a summary
// of it.
process.exitCode = main(process.argv.slice(2));
