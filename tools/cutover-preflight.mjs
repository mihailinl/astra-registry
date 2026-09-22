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
// ── WHAT A `conditional` MEMBER IS WORTH TO A VERDICT ───────────────────────
//
// `schema/contract-tokens-v1.json` states a member's requiredness in THREE
// values — `true`, `false` and `"conditional"` — and this file used to read it
// with two:
//
//     (entry.members || []).filter((m) => m.required)
//
// `"conditional"` is a truthy string, so a member the contract carries only
// under a stated condition was counted as carried by every marker, and printed
// into this record as required outright. It was silent because no member of
// `astra.registry.migration-notice/1` is conditional yet; it would stop being
// silent the day one is, which is what SCOPE-8's N11 is scheduled to do.
// dev/couplings.md entry 46, and entry 38 for the same read one file over.
//
// A conditional member is not one question. It is two, and WHICH of the two a
// gate is looking at is decided by the marker in front of it, not by the
// member:
//
//   condition HOLDS, member absent            UNMET. Asked on this ref, of
//                                             this marker, answer no.
//   condition DOES NOT HOLD, member absent    nothing at all. The contract
//                                             does not ask this marker for it,
//                                             and a gate that reports it anyway
//                                             fails a CONFORMING marker, which
//                                             reads downstream as a defect in
//                                             whoever wrote the marker.
//   condition does not hold, member CARRIED,  UNMET. `iff` forbids it there,
//   under `iff`                               and a reader that checks only the
//                                             requiring half gets the looser
//                                             reading of the half it skipped.
//   condition CANNOT BE EVALUATED             NOT ASKED.
//
// That last line is the one worth arguing about, so here is the argument. A
// `when` this reader cannot evaluate — a `conditional` that states none, an
// `if` and an `iff` together, a predicate shape the readme does not publish —
// makes the file malformed, and the readme says what a reader must then do:
// refuse, and "MUST NOT read the member as unconditioned … the looser
// direction is the one this field exists to close". MET is that looser
// direction. UNMET is not available either: it would say this tool asked a
// question of the marker and the marker answered no, when what happened is
// that the tool could not read what the contract asks — a no printed beside a
// marker that may be perfectly conforming. NOT ASKED is the only one of the
// three that is true, and it is not a shrug: it still fails, it still exits 2,
// and it names the party who can answer, which for a member table is whoever
// publishes the token file and never the marker's author.
//
// Within one check the three words compose as a conjunction: an answered no
// stands whatever else was unasked, because a conjunction with a false conjunct
// is false; a yes beside an unasked question is NOT ASKED. That is the same
// rule the summary at the bottom applies across the eleven.
//
// ── AND THE ONE QUESTION THIS FILE USED TO ANSWER WITH A BELIEF ─────────────
//
// B.4 states the marker as an exact member list — `schema`, `round`, `sent_at`,
// "and `cutover_planned_at` FROM ROUND 2". The token file states that member
// `required: true`, flat. SCOPE-8's N11 is that disagreement, and it is open.
// This file used to settle it privately:
//
//     const required = m.doc?.round === 1
//       ? members.filter((k) => k !== "cutover_planned_at") : members;
//
// A local reading of one published document over another, made silently,
// printed nowhere, in the one tool in the cutover whose charter is to record
// measurements and not beliefs. It is the same shape as the `EITHER_MEMBERS`
// list entry 38 deleted from bot/lib/service.mjs, and it has the same end: a
// private workaround does not announce itself when the public repair lands, it
// just stops being right.
//
// So it is gone. Where two published documents state a member's requiredness
// differently, and for the markers they differ about, this tool DOES NOT ASK —
// it says so, names N11, and names who discharges it. Withholding is the
// direction the readme calls safe, and an unasked question in this tool is a
// person to go and find, which is exactly what an unowned escalation needs.
// The day the token file publishes a `when` for that member there is no
// disagreement left to withhold over and the condition is simply read; nothing
// here has to be edited for that to happen, and the selftest pins both states.
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
import { fileURLToPath } from "node:url";
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

/** SCOPE-7's token file: where this tool takes the marker's members from. */
const TOKEN_FILE = "schema/contract-tokens-v1.json";

/**
 * The members whose requiredness two published documents state differently,
 * and which markers they differ about. See the header. There is exactly one
 * today, SCOPE-8's N11, and it is here rather than inline so that a second one
 * has to be written down beside it with the finding that owns it.
 *
 * `disagreesAbout` decides only whether the question may be ASKED — never what
 * the answer is. That is the whole difference between this and the local
 * exemption it replaced: the old one answered (silently, "not required, so not
 * missing"), this one withholds, and withholding is the direction the token
 * file's readme names as the safe one.
 *
 * An entry applies only while the file states the member `required: true`. A
 * published `when` is the disagreement discharged: the condition is read, this
 * entry stops matching on its own, and nobody has to notice.
 */
const DISPUTED_MEMBERS = Object.freeze([
  Object.freeze({
    member: "cutover_planned_at",
    finding: "SCOPE-8's N11",
    prose:
      "B.4 states the marker as an exact member list of `schema`, `round`, `sent_at`, " +
      "and `cutover_planned_at` FROM ROUND 2",
    disagreesAbout: (doc) => doc?.round === 1,
    who:
      "the contract lane that discharges SCOPE-8's N11 — a `when` on this member in " +
      `${TOKEN_FILE} ends the disagreement, and this tool reads it with no edit here`,
  }),
]);

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
  const raw = showFile(ctx.repo, ctx.ref, TOKEN_FILE);
  let table = null;
  if (raw !== null) {
    try {
      table = memberTable(JSON.parse(raw));
    } catch {
      table = null;
    }
  }
  if (!table) {
    return unmet(`${TOKEN_FILE} no longer names ${MARKER_SCHEMA}`, [
      ...r.lines,
      "this preflight takes the marker's members from the token file.",
      "if the contract retired the record, this check is checking nothing until somebody says what replaced it.",
    ]);
  }

  // Requiredness is read as the three-valued field it is, and a condition is
  // evaluated rather than excepted. The header says what each of the three
  // answers is worth here, and why an unevaluable condition is NOT ASKED.
  const lines = [...r.lines, ...describeTable(table)];
  const { readable, refused } = splitTable(table);
  const no = [];
  const unasked = [];
  for (const m of refused) {
    unasked.push({
      message: `  ${TOKEN_FILE}: \`${m.name}\` ${m.why}`,
      who:
        `whoever publishes ${TOKEN_FILE} — the readme makes such a member a file to refuse, ` +
        "never a member to read as unconditioned",
    });
  }
  for (const m of markers) {
    const p = markerProblems(readable, m.doc);
    for (const x of [...p.missing, ...p.forbidden]) no.push(`  ${m.file}: ${x}`);
    for (const w of p.withheld) unasked.push({ message: `  ${m.file}: ${w.message}`, who: w.who });
  }
  if (no.length) {
    lines.push(
      `${no.length} member${no.length === 1 ? "" : "s"} of a marker on this ref disagree with the contract:`,
      ...no,
    );
  }
  if (unasked.length) {
    lines.push(
      `${unasked.length} member question${unasked.length === 1 ? "" : "s"} this tool did not ask:`,
      ...unasked.map((u) => u.message),
    );
  }

  // An answered no about the clock stands whatever else went unasked: a
  // conjunction with a false conjunct is false. Only where the clock is MET do
  // the member readings decide the word.
  if (r.verdict === UNMET) return { ...r, lines };
  if (no.length) {
    return unmet("the clock is met, and a marker does not carry the members the contract states", [
      `the clock: ${r.headline}`,
      ...lines,
    ]);
  }
  if (unasked.length) {
    return notAsked(
      "the clock is met, and this tool cannot say what a conforming marker is",
      [...new Set(unasked.map((u) => u.who))].join("; and "),
      [`the clock: ${r.headline}`, ...lines],
    );
  }
  return { ...r, lines };
}

/**
 * The marker schema's members, exactly as the token file records them — the
 * three-valued `required` and the `when` object itself, copied and never
 * summarised, because the condition a reader must evaluate lives in it.
 *
 * null when the file no longer names the schema, which the caller reports.
 */
export function memberTable(doc) {
  const entry = (doc?.entries || []).find((e) => e.name === MARKER_SCHEMA);
  if (!entry || !Array.isArray(entry.members)) return null;
  return entry.members;
}

/**
 * The members this reader can evaluate, and the ones it must refuse.
 *
 * Refusal is a table fact and not a marker fact, and it is found here, once, so
 * that an unevaluable condition is loud on a ref carrying NO markers at all —
 * which is every ref before round 1 is sent, and is the state this tool spends
 * its life in. A refusal discovered only while walking markers would be a check
 * that goes quiet exactly when there is nothing to check it against.
 */
export function splitTable(table) {
  const readable = [];
  const refused = [];
  for (const m of table) {
    if (m === null || typeof m !== "object" || Array.isArray(m) || typeof m.name !== "string") {
      refused.push({ name: JSON.stringify(m), why: "is not a member record this reader can read" });
      continue;
    }
    if (m.required === true || m.required === false) {
      readable.push(m);
      continue;
    }
    if (m.required !== "conditional") {
      refused.push({
        name: m.name,
        why:
          `states requiredness ${JSON.stringify(m.required)}, and the token file's readme states three ` +
          "values — `true`, `false`, `conditional` — and no fourth",
      });
      continue;
    }
    try {
      // Provoked on an empty body, which no predicate shape can depend on: this
      // asks whether the CONDITION is readable, never whether it holds.
      predicateHolds(readWhen(m).predicate, {});
      readable.push(m);
    } catch (e) {
      refused.push({ name: m.name, why: String(e.message || e) });
    }
  }
  return { readable, refused };
}

/**
 * A member's `when`, as `{kind, predicate}`.
 *
 * `if` or `iff`, never both and never neither, and which of the two applies is
 * decided per condition and never defaulted. Throws, because every caller is
 * one that must refuse rather than guess: defaulting to `if` would drop the
 * forbidding half, and defaulting to `iff` would forbid what the contract
 * permits.
 */
export function readWhen(member) {
  const when = member.when;
  if (when === null || typeof when !== "object" || Array.isArray(when)) {
    throw new Error(
      "is `conditional` and states no `when`, which the token file's readme makes a malformed file this " +
      "reader must refuse rather than read as unconditioned",
    );
  }
  const kinds = ["if", "iff"].filter((k) => k in when);
  if (kinds.length !== 1) {
    throw new Error(
      `states \`when\` ${JSON.stringify(when)}; a \`when\` is \`if\` or \`iff\`, never both and never neither`,
    );
  }
  return { kind: kinds[0], predicate: when[kinds[0]] };
}

/**
 * Does a `when`'s predicate hold of this marker?
 *
 * The three shapes the token file's readme publishes, and only those:
 * `{"member": "absent"}`, which holds exactly when that sibling is not carried;
 * `{"member": [values]}`, which holds when it is carried with one of them; and
 * `{"member": {"not": [values]}}`, their complement — which an ABSENT sibling
 * does not satisfy, because `not` is over the values the member may take and a
 * member that is not carried has none.
 *
 * Anything else throws, and `splitTable` turns that into a refusal.
 */
export function predicateHolds(predicate, doc) {
  const unreadable = () =>
    new Error(`carries a \`when\` predicate this reader cannot evaluate: ${JSON.stringify(predicate ?? null)}`);
  if (predicate === null || typeof predicate !== "object" || Array.isArray(predicate)) throw unreadable();
  const names = Object.keys(predicate);
  if (names.length !== 1) throw unreadable();
  const [name] = names;
  const rule = predicate[name];
  const carried = doc !== null && typeof doc === "object" && name in doc;
  if (rule === "absent") return !carried;
  if (Array.isArray(rule)) return carried && rule.includes(doc[name]);
  if (rule !== null && typeof rule === "object" && Array.isArray(rule.not) && Object.keys(rule).length === 1) {
    return carried && !rule.not.includes(doc[name]);
  }
  throw unreadable();
}

/** A predicate, in words, for the one line a reader of the record meets. */
export function describePredicate(predicate) {
  const [name] = Object.keys(predicate);
  const rule = predicate[name];
  if (rule === "absent") return `\`${name}\` is absent`;
  const values = Array.isArray(rule) ? rule : rule.not;
  return `\`${name}\` is ${Array.isArray(rule) ? "" : "not "}one of ${values.map((v) => `\`${v}\``).join(", ")}`;
}

/**
 * The member table as this record should carry it: three values, not two, and
 * every condition spelled out. The line this replaced read "required members:
 * schema, round, sent_at, cutover_planned_at" whatever the file stated, which
 * is a false sentence about the contract on the day one of them is conditional.
 */
export function describeTable(table) {
  const flat = [];
  const optional = [];
  const conditional = [];
  const unreadable = [];
  for (const m of table) {
    if (m === null || typeof m !== "object" || typeof m.name !== "string") unreadable.push(JSON.stringify(m));
    else if (m.required === true) flat.push(m.name);
    else if (m.required === false) optional.push(m.name);
    else if (m.required === "conditional") conditional.push(m);
    else unreadable.push(`\`${m.name}\` (required: ${JSON.stringify(m.required)})`);
  }
  const lines = [
    `members of ${MARKER_SCHEMA}, from ${TOKEN_FILE}:`,
    `  required of every marker: ${flat.length ? flat.join(", ") : "none"}`,
  ];
  for (const m of conditional) {
    let where;
    try {
      const { kind, predicate } = readWhen(m);
      where =
        kind === "iff"
          ? `carried exactly where ${describePredicate(predicate)}, and forbidden where it is not`
          : `carried where ${describePredicate(predicate)}; the contract says nothing where it is not`;
    } catch {
      where = "a condition this tool cannot evaluate — see below";
    }
    lines.push(`  conditional: \`${m.name}\` — ${where}`);
  }
  if (optional.length) lines.push(`  permitted, no condition published: ${optional.join(", ")}`);
  if (unreadable.length) lines.push(`  unreadable: ${unreadable.join(", ")}`);
  return lines;
}

/**
 * What this marker gets wrong about a readable member table, and what this tool
 * must not ask of it.
 *
 * Never throws: `splitTable` has already taken the unreadable members out, and
 * a refusal is a return value rather than an exception because the caller is
 * the one that owns the three words.
 *
 * Unknown members are not problems and are never looked at — there is no loop
 * over the marker's own keys here, which is the shape that cannot regress into
 * a closed world by somebody adding an `else`.
 *
 * @returns {{missing: string[], forbidden: string[], withheld: {message: string, who: string}[]}}
 */
export function markerProblems(readable, doc) {
  const body = doc !== null && typeof doc === "object" ? doc : {};
  const missing = [];
  const forbidden = [];
  const withheld = [];
  for (const m of readable) {
    if (m.required === "conditional") {
      const { kind, predicate } = readWhen(m);
      const holds = predicateHolds(predicate, body);
      const carried = m.name in body;
      // Both halves of a biconditional, and only the requiring half of an `if`:
      // a reader who implements one and not the other gets the looser reading
      // of the half it skipped, which is what this vocabulary exists to end.
      if (holds && !carried) {
        missing.push(`\`${m.name}\` is required where ${describePredicate(predicate)}, and is absent`);
      } else if (!holds && carried && kind === "iff") {
        forbidden.push(
          `\`${m.name}\` is carried, and its \`iff\` permits it only where ${describePredicate(predicate)}`,
        );
      }
      continue;
    }
    // `false` publishes no condition and asks nothing of any marker.
    if (m.required !== true) continue;
    const dispute = DISPUTED_MEMBERS.find((d) => d.member === m.name && d.disagreesAbout(body));
    if (dispute) {
      withheld.push({
        message:
          `\`${m.name}\`: the token file states it \`required: true\`, flat, and ${dispute.prose}. ` +
          `${dispute.finding} is that disagreement and it is open; this tool does not decide which of two ` +
          "published documents is wrong, so it did not ask whether this marker carries it",
        who: dispute.who,
      });
      continue;
    }
    if (!(m.name in body)) missing.push(`\`${m.name}\` is required of every marker, and is absent`);
  }
  return { missing, forbidden, withheld };
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

  // ── the member table, and the three-valued `required` ─────────────────────
  //
  // Entry 46. The line these fixtures replaced was
  //
  //     (entry.members || []).filter((m) => m.required)
  //
  // and `"conditional"` is a truthy string, so every fixture below is one
  // where that read gives a different answer from the file it is reading.

  const MEMBER = "cutover_planned_at";
  const iffWhen = { iff: { round: { not: [1] } } };
  const ifWhen = { if: { round: { not: [1] } } };
  const flatTable = [
    { name: "schema", required: true },
    { name: "round", required: true },
    { name: "sent_at", required: true },
    { name: MEMBER, required: true },
  ];
  const publishedTable = [...flatTable.slice(0, 3), { name: MEMBER, required: "conditional", when: iffWhen }];
  const r1 = { schema: MARKER_SCHEMA, round: 1, sent_at: "2026-07-01T00:00:00Z" };
  const r1Dated = { ...r1, cutover_planned_at: "2026-09-15T00:00:00Z" };
  const r2 = { schema: MARKER_SCHEMA, round: 2, sent_at: "2026-08-01T00:00:00Z" };
  const r2Dated = { ...r2, cutover_planned_at: "2026-09-15T00:00:00Z" };

  const read = (table, doc) => {
    const { readable, refused } = splitTable(table);
    return { ...markerProblems(readable, doc), refused };
  };
  const counts = (table, doc) => {
    const p = read(table, doc);
    return `${p.missing.length}/${p.forbidden.length}/${p.withheld.length}/${p.refused.length}`;
  };

  is("the table is the file's entry", memberTable({ entries: [{ name: MARKER_SCHEMA, members: flatTable }] }).length, 4);
  is("a retired schema is null", memberTable({ entries: [] }), null);

  // The list itself. A conditional member is not required of every marker, and
  // the truthiness read put it in exactly that sentence.
  is(
    "a conditional member is not in the required-of-every-marker list",
    describeTable(publishedTable)[1],
    "  required of every marker: schema, round, sent_at",
  );
  is(
    "and it is printed as the condition it is",
    describeTable(publishedTable)[2],
    "  conditional: `cutover_planned_at` — carried exactly where `round` is not one of `1`, and forbidden where it is not",
  );

  // ── a published condition, which is what N11 will publish ────────────────
  // The requiring half, where the condition holds.
  is("published: round 2 without the date is missing it", counts(publishedTable, r2), "1/0/0/0");
  is("published: round 2 with the date is clean", counts(publishedTable, r2Dated), "0/0/0/0");
  // The half the old read could not have: a CONFORMING round-1 marker. The
  // truthiness read counted this member required of every marker.
  is("published: round 1 without the date is clean", counts(publishedTable, r1), "0/0/0/0");
  // The forbidding half of an `iff`, which nothing here used to check at all.
  is("published: round 1 carrying the date is forbidden", counts(publishedTable, r1Dated), "0/1/0/0");
  // `if` requires where its predicate holds and says NOTHING where it does not.
  // Reading it as `iff` would forbid what the contract permits.
  const ifTable = [...flatTable.slice(0, 3), { name: MEMBER, required: "conditional", when: ifWhen }];
  is("`if` is not read as `iff`", counts(ifTable, r1Dated), "0/0/0/0");
  is("`if` still requires where it holds", counts(ifTable, r2), "1/0/0/0");

  // ── a condition this reader cannot evaluate: refused, never relaxed ───────
  const unreadable = [
    ["no `when` at all", { name: MEMBER, required: "conditional" }],
    ["`if` and `iff` together", { name: MEMBER, required: "conditional", when: { if: ifWhen.if, iff: iffWhen.iff } }],
    ["a predicate shape the readme does not publish", { name: MEMBER, required: "conditional", when: { iff: { round: 2 } } }],
    ["a predicate naming two siblings", { name: MEMBER, required: "conditional", when: { iff: { round: [2], sent_at: [""] } } }],
    ["a fourth requiredness", { name: MEMBER, required: "maybe" }],
  ];
  for (const [what, member] of unreadable) {
    is(`refused: ${what}`, counts([...flatTable.slice(0, 3), member], r2), "0/0/0/1");
  }
  is(
    "a refused member is refused on a ref with no markers at all",
    splitTable([...flatTable.slice(0, 3), unreadable[0][1]]).refused.length,
    1,
  );

  // ── SCOPE-8's N11, while it is open ───────────────────────────────────────
  // Two published documents state this member's requiredness differently, and
  // the tool withholds on the round they differ about rather than answering.
  // The line this replaced answered it, silently, in the marker's favour.
  is("N11 open: round 1 is withheld, not answered", counts(flatTable, r1), "0/0/1/0");
  is("N11 open: round 2 without the date is asked, and the answer is no", counts(flatTable, r2), "1/0/0/0");
  is("N11 open: round 2 with the date is clean", counts(flatTable, r2Dated), "0/0/0/0");
  // And the withholding retires itself the day the file states the condition.
  is("N11 discharged: nothing is withheld any more", counts(publishedTable, r1), "0/0/0/0");
  is(
    "the withheld line names the finding",
    (read(flatTable, r1).withheld[0]?.message ?? "").includes("SCOPE-8's N11"),
    true,
  );

  // The three predicate shapes, and the refusal.
  is("`absent` holds when the sibling is not carried", predicateHolds({ wait: "absent" }, { state: "x" }), true);
  is("`absent` fails when it is", predicateHolds({ wait: "absent" }, { wait: {} }), false);
  is("a value list holds on a listed value", predicateHolds({ round: [2] }, { round: 2 }), true);
  is("a value list fails when the sibling is absent", predicateHolds({ round: [2] }, {}), false);
  is("a complement holds on an unlisted value", predicateHolds({ round: { not: [1] } }, { round: 2 }), true);
  is(
    "a complement fails when the sibling is absent — a member not carried has no value",
    predicateHolds({ round: { not: [1] } }, {}),
    false,
  );

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
//
// And only when this file IS the program. It exports ten readers, and until
// contract 0.30.0 nothing imported them, so running the whole gate at module
// scope cost nothing and was invisible. `bot/tests/service.test.mjs` now
// imports `splitTable` and `markerProblems` to prove that the condition this
// file evaluates is one something in this repository actually runs — and an
// import that ran eleven checks, a live `gh` query and a walk of four
// repositories would make that proof unaffordable. Watched: the first attempt
// printed the entire cutover gate into the test output before the first
// assertion.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
