#!/usr/bin/env node
// MIG-21's historic export: the decisions that exist only on an issue thread,
// turned into facts, and those facts turned into `migration` records.
//
// Every refusal and approval this registry made before the plugins service
// existed is a markdown comment on a GitHub issue. MIG-21 says they have to
// reach the decision log before ROLL-42 switches Issues off, and PRIV-10 says
// what may cross: the decision, and nothing about the people in the thread. So
// this file is **split at the stranger's bytes**, and the split is the whole
// design:
//
//   * `--facts` reads issues and comments — a stranger's repository, a
//     stranger's prose, a maintainer's login, a reporter's text — and emits a
//     fixed, tiny grammar: repository, tag, plugin id, version, state, date and
//     refusal codes. It is the only half that ever sees the bytes.
//   * `--compose` reads that grammar and nothing else, and turns each fact into
//     one `migration` record with actor `system`.
//
// Nothing in the second half can quote the first half's input, because the
// first half never emitted it. That is stronger than remembering not to copy a
// login: `composeRecords` refuses any member it was not told to expect, and
// each member it does expect is checked against its own grammar rather than
// against a blocklist of bad shapes (PRIV-2, PRIV-10).
//
// ── what a decision looks like, measured rather than assumed ───────────────
//
// The plan says "comments by the bot's own identity carrying its decision
// marker" and leaves the marker to whoever writes this. Read off the live
// repository on 2026-09-19 — 218 comments and 51 issues — there are three
// facts a grammar has to survive, and none of them is guessable from the plan:
//
//  1. **The marker is the ingest heading**, `## Registry ingest — \`repo@tag\``,
//     and all 128 of them were posted by `github-actions[bot]`, user type
//     `Bot`. That heading is composed from the RUN — `bot/ingest.mjs` takes
//     `repo` and `tag` from the arguments the workflow passed, never from the
//     issue body — which is why it, and not the form, is what a repository and
//     a tag may be read out of. The issue body belongs to its author and can be
//     edited after the fact; `bot/lib/intake.mjs`'s approval binding exists
//     because of exactly that.
//
//  2. **The verdict is NOT the heading's next line.** That line is the checks'
//     verdict, and "Every check passed; no human is needed" is printed on
//     releases the policy then held for a maintainer. The decision is in the
//     `## Publication` section `bot/lib/policy/comment.mjs` appends, and it has
//     four shapes: `Not published` (a check failed), `Published`, `Publishing
//     itself at <t>` (the delay, which is an approval that has not landed yet)
//     and `Held for a maintainer` (not a decision at all — the thread's later
//     `Published` comment is the decision). Reading the first line would have
//     recorded 20 held submissions as approvals.
//
//  3. **Eight decisions are not in a comment.** When a release reaches the
//     registry with no submission issue — a `[release]` ping, or the daily
//     backstop finding a tag nobody mentioned — `ingest.yml`'s `comment` job
//     opens a `[notice]` issue and puts the whole report in the ISSUE BODY.
//     All eight `[notice]` issues on this repository carry a marker in their
//     body and were opened by the bot. A comment-only export drops every one of
//     them, and they are precisely the population with no other record.
//
// ── what is deliberately NOT read ──────────────────────────────────────────
//
// A maintainer's `/reject` closes a submission with `renderRejected`, which
// quotes the reason and names the login. That comment carries no marker, so it
// is outside the grammar here, and it stays outside it: the two things it holds
// that a record would need are a moderator's login and a moderator's free text,
// and PRIV-2 forbids both in git. It is counted, not exported, and the count is
// what makes the loss visible in the commit message MIG-21 asks for.
//
// Report and appeal issues are out of scope by title, so their text is never
// even read into memory.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { CODES } from "./lib/codes.mjs";
import { LISTING_LABEL, looksLikeReleasePing, safeRepo, safeTag } from "./lib/intake.mjs";
import { ID_PATTERN } from "../tools/lib/ids.mjs";
import { SEMVER_PATTERN } from "../tools/lib/semver.mjs";

const ID_RE = new RegExp(ID_PATTERN);
const SEMVER_RE = new RegExp(SEMVER_PATTERN);
const DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * The accounts whose comments are decisions.
 *
 * `ingest.yml`'s `comment` job posts through `actions/github-script` with the
 * default `GITHUB_TOKEN`, so every decision on this repository was authored by
 * `github-actions[bot]`. The `[bot]` suffix cannot be registered as a user
 * login, but that is GitHub's rule and not this file's guarantee, so the type
 * is checked too: a document counts only when the login matches AND the API
 * called its author a `Bot`.
 */
export const BOT_LOGINS = ["github-actions[bot]"];

/**
 * The decision marker, as `bot/ingest.mjs` renders it.
 *
 * A tag may hold `/` and may not hold `@` (`tools/lib/tags.mjs` says why), so
 * the single `@` splits the pair unambiguously. Both halves are re-checked
 * against their own grammars below; matching here is only the recognition step.
 */
export const MARKER_RE = /^## Registry ingest — `([^`@]+)@([^`]+)`$/;

/** Where `bot/lib/policy/comment.mjs` starts the half that holds the decision. */
export const PUBLICATION_HEADING = "## Publication";

/**
 * The four publication verdicts, and the state each one is.
 *
 * MIG-21 allows two states — `refused` and `approved`, never `published`, so
 * that an export record can never be mistaken for MIG-20's migration baseline.
 * A delay is an approval: the policy said yes and the queue entry is what makes
 * it happen. A hold is not a decision, and is counted rather than exported.
 */
const VERDICTS = [
  { state: "refused", re: /^\*\*Not published\.\*\*/ },
  { state: "approved", re: /^\*\*Published\.\*\* `([^`\s]+) ([^`]+)` is live/ },
  { state: "approved", re: /^\*\*Publishing itself at [^*]+\.\*\* `([^`\s]+) ([^`]+)` passed every check/ },
  { state: "held", re: /^\*\*Held for a maintainer\.\*\* Nothing is wrong with `([^`\s]+) ([^`]+)`/ },
];

/** A blocking finding in the checks' table: the glyph, then a code in backticks. */
const ERROR_ROW_RE = /^\| ❌ \| `([A-Za-z0-9_]+)` \|/;

/** The ingest half's own verdict line, which is where a refusal's id and version are not. */
const LISTING_LINE_RE = /^\*\*Listing ([^\s*]+) ([^*]+)\.\*\* Every check passed/;

/** The one timestamp spelling this repository writes: seconds, UTC, no offset. */
function normaliseTime(value) {
  const d = new Date(String(value ?? ""));
  return Number.isNaN(d.getTime()) ? null : `${d.toISOString().slice(0, 19)}Z`;
}

/**
 * Which issues this export is allowed to read at all.
 *
 * By SHAPE rather than by label, because the label is not a category here. The
 * listing form applies `listing`; `release-ping.yml` deliberately applies
 * nothing — the label is an authority token and a template that stamped it
 * would hand the exemption to anyone who can open an issue — and the bot's own
 * `[notice]` issues carry no label either. Selecting on the label alone would
 * read 30 issues of the 49 that exist and miss ten decisions on `[release]`
 * threads and eight in `[notice]` bodies.
 *
 * Two `[listing]`-titled issues carry no label at all, which is the hole
 * `config.yml` closed by turning blank issues off; the title catches them.
 *
 * Everything else is out of scope and its bytes are never looked at. That
 * matters for the report and appeal threads specifically: they hold exactly the
 * text PRIV-2 keeps out of git, and the cheapest way not to compose it is not
 * to read it.
 *
 * @returns {"listing"|"release-ping"|"notice"|null}
 */
export function issueScope(issue) {
  const labels = (issue?.labels ?? []).map((l) => (typeof l === "string" ? l : l?.name));
  const title = String(issue?.title ?? "").trim();
  if (labels.includes(LISTING_LABEL)) return "listing";
  if (/^\[listing\]/i.test(title)) return "listing";
  if (looksLikeReleasePing(title)) return "release-ping";
  if (/^\[notice\]/i.test(title)) return "notice";
  return null;
}

/**
 * One document — an issue body or a comment — read for a decision.
 *
 * Returns either a fact, or the named reason it is not one. Every return is
 * counted by the caller; "anything outside the grammar is dropped and counted"
 * is only true if every drop has a name.
 *
 * @param {{body: string, login: string, type: string, date: string}} doc
 * @param {{botLogins?: string[]}} [opts]
 */
export function readDecision(doc, opts = {}) {
  const botLogins = opts.botLogins ?? BOT_LOGINS;

  // Identity first, before a single byte of the body is parsed. A stranger can
  // type the marker; a stranger cannot be `github-actions[bot]` with user type
  // `Bot`. This is the line the imitation canary lands on.
  if (!botLogins.includes(String(doc.login ?? "")) || String(doc.type ?? "") !== "Bot") {
    return { drop: "not_the_bot" };
  }

  const lines = String(doc.body ?? "").replace(/\r\n/g, "\n").split("\n");
  const markers = lines.map((l) => MARKER_RE.exec(l)).filter(Boolean);
  if (markers.length === 0) return { drop: "no_marker" };
  // Two markers in one document is a shape nothing renders. It would mean a
  // report quoted inside another, and there is no way to tell which verdict
  // belongs to which pair, so it is dropped rather than guessed at.
  if (markers.length > 1) return { drop: "marker_repeated" };

  const repository = safeRepo(markers[0][1]);
  const tag = safeTag(markers[0][2]);
  if (!repository) return { drop: "bad_repo" };
  if (!tag) return { drop: "bad_tag" };

  const date = normaliseTime(doc.date);
  if (!date) return { drop: "bad_date", where: `${repository}@${tag}` };

  const at = lines.indexOf(PUBLICATION_HEADING);
  if (at < 0) return { drop: "no_publication_section", where: `${repository}@${tag}` };
  const headline = lines.slice(at + 1).find((l) => l.trim() !== "") ?? "";

  const hit = VERDICTS.map((v) => ({ v, m: v.re.exec(headline) })).find((x) => x.m);
  if (!hit) return { drop: "verdict_unrecognised", where: `${repository}@${tag}` };
  if (hit.v.state === "held") return { drop: "held", where: `${repository}@${tag}` };

  // A refusal names no plugin and no version anywhere: the checks failed before
  // anything was derived, so `**Not listed — N blocking finding(s).**` is all
  // there is and the ids do not exist to be recovered. DEC-7 allows both
  // members to be absent, which is the honest record of that.
  let plugin_id = null;
  let version = null;
  if (hit.m.length > 1) {
    plugin_id = hit.m[1];
    version = hit.m[2];
  } else {
    const listing = lines.map((l) => LISTING_LINE_RE.exec(l)).find(Boolean);
    if (listing) {
      plugin_id = listing[1];
      version = listing[2];
    }
  }
  const dropped = [];
  if (plugin_id !== null && !ID_RE.test(plugin_id)) {
    plugin_id = null;
    dropped.push("bad_plugin_id");
  }
  if (version !== null && !SEMVER_RE.test(version)) {
    version = null;
    dropped.push("bad_version");
  }

  // Refusal codes come from the CHECKS' table, because a refusal is a check
  // that failed — `P_REFUSED`'s own remedy says so: "the policy did not reject
  // this; a check did". Only the blocking glyph's rows, and only codes
  // `bot/lib/codes.mjs` declares: a code this registry no longer has is a code
  // no reader can resolve, so it is dropped and counted rather than carried
  // into a record as an opaque string.
  const reasons = [];
  if (hit.v.state === "refused") {
    // Above the `## Publication` heading only. The policy's own table below it
    // carries `P_REFUSED`, which restates the outcome rather than naming the
    // check that produced it, and DEC-7's `reasons` is the second thing.
    for (const line of lines.slice(0, at)) {
      const m = ERROR_ROW_RE.exec(line);
      if (!m) continue;
      if (!Object.prototype.hasOwnProperty.call(CODES, m[1])) {
        dropped.push("unknown_code");
        continue;
      }
      if (!reasons.includes(m[1])) reasons.push(m[1]);
    }
  }

  return {
    fact: { repository, tag, plugin_id, version, state: hit.v.state, date, reasons },
    dropped,
  };
}

/**
 * Every in-scope document, read once.
 *
 * @param {{issues: any[], comments: any[], botLogins?: string[]}} input
 */
export function exportFacts({ issues = [], comments = [], botLogins } = {}) {
  const counts = {
    issues_read: 0,
    issues_in_scope: 0,
    documents_read: 0,
    facts: 0,
    dropped: {},
  };
  const drop = (name) => { counts.dropped[name] = (counts.dropped[name] ?? 0) + 1; };

  const scope = new Map();
  for (const issue of issues) {
    // A pull request is an issue to this endpoint and is never a submission.
    if (issue?.pull_request) continue;
    counts.issues_read++;
    const s = issueScope(issue);
    if (!s) continue;
    counts.issues_in_scope++;
    scope.set(Number(issue.number), s);
  }

  /** @type {{body: string, login: string, type: string, date: string}[]} */
  const docs = [];
  for (const issue of issues) {
    if (!scope.has(Number(issue?.number))) continue;
    docs.push({
      body: issue.body ?? "",
      login: issue.user?.login ?? "",
      type: issue.user?.type ?? "",
      date: issue.created_at ?? "",
    });
  }
  for (const c of comments) {
    const n = Number(c?.issue_number ?? /\/issues\/(\d+)$/.exec(String(c?.issue_url ?? ""))?.[1]);
    if (!scope.has(n)) continue;
    docs.push({
      body: c.body ?? "",
      login: c.user?.login ?? "",
      type: c.user?.type ?? "",
      date: c.created_at ?? "",
    });
  }

  const facts = [];
  const unrecoverable = [];
  for (const doc of docs) {
    counts.documents_read++;
    const r = readDecision(doc, { botLogins });
    if (r.drop) {
      drop(r.drop);
      // `not_the_bot` and `no_marker` are the ordinary bulk of a thread — a
      // `/recheck`, a question, the form itself. Naming those as losses would
      // bury the ones that matter. A document that carried the marker and still
      // produced no fact is the one MIG-21's commit message has to list.
      if (r.where && r.drop !== "held") unrecoverable.push(`${r.where} (${r.drop})`);
      continue;
    }
    for (const d of r.dropped) drop(d);
    facts.push(r.fact);
    counts.facts++;
  }

  facts.sort((a, b) => (a.date === b.date
    ? `${a.repository}@${a.tag}`.localeCompare(`${b.repository}@${b.tag}`)
    : a.date.localeCompare(b.date)));

  return { facts, counts, unrecoverable: [...new Set(unrecoverable)].sort(), collisions: keyCollisions(facts) };
}

/**
 * The BOT-35 key each record's id is derived over.
 *
 * `migration:<owner/name>@<tag>` is the domain B-T2.2 states, and for
 * B-T3.7b's baseline it is unique by construction: one `published` record per
 * version. It is NOT unique here. This registry decided
 * `teletemagame-dev/minecraft-for-astra@v0.3.1` more than once — a refusal, a
 * re-check, an approval — and MIG-21 asks for "one `migration` record each".
 * Two facts over one key derive one id, so the second record would land on the
 * first's path and the count ROLL-42 and M-T8.1 compare would be short without
 * anything going red.
 *
 * So the key is derived in one place, the collision is measured in `--facts`
 * and refused in `--compose`, and widening the domain is not this file's to do:
 * `legacy:` needed an amendment to BOT-35 (ops.22) and so does this.
 */
export const migrationKey = (fact) => `migration:${fact.repository}@${fact.tag}`;

export function keyCollisions(facts) {
  const seen = new Map();
  for (const f of facts) {
    const k = migrationKey(f);
    seen.set(k, (seen.get(k) ?? 0) + 1);
  }
  return [...seen].filter(([, n]) => n > 1).map(([key, facts_sharing_it]) => ({ key, facts_sharing_it })).sort(
    (a, b) => a.key.localeCompare(b.key),
  );
}

/**
 * DEC-7's members this export composes, and the grammar each one must match.
 *
 * An ALLOWLIST, not a scan for bad shapes. PRIV-2's own Check is an id-shape
 * canary, and an id shape is a pattern — `^[A-Za-z0-9_-]{1,64}$` matches a
 * Minice subject id and also matches a GitHub login, a plugin id and most
 * words. Asking "does this value look personal" of a value that could be
 * anything is a question with no safe answer; asking "is this value a semver"
 * of a member that may only ever be a semver is a question with one. A login
 * copied into a fact fails because `login` is not a member here, and if it were
 * written into `plugin_id` it would have to also be a valid plugin id — and
 * then it is indistinguishable from a plugin id, which is a repository
 * coordinate PRIV-2 explicitly permits.
 *
 * `schema` and `decision_id` are absent on purpose: B-T2.2's writer stamps the
 * first and derives the second from `migrationKey` above. A second module that
 * also knew how to derive a decision id would be a second module that could
 * disagree about one.
 */
const RECORD_MEMBERS = {
  decided_at: (v) => DATE_RE.test(v),
  actor: (v) => v === "system",
  trigger: (v) => v === "migration",
  plugin_id: (v) => ID_RE.test(v),
  version: (v) => SEMVER_RE.test(v),
  repo: (v) => safeRepo(v) !== null,
  tag: (v) => safeTag(v) !== null,
  state: (v) => v === "refused" || v === "approved",
  reasons: (v) => Array.isArray(v) && v.every((c) => Object.prototype.hasOwnProperty.call(CODES, c)),
};

/**
 * One `migration` record per fact, actor `system`.
 *
 * PRIV-10: every historic approver becomes `system`, because no mapping from a
 * historic GitHub login to a moderator handle exists and PRIV-2 keeps logins
 * out of git anyway. There is nothing to lose by not trying: a record that
 * named an approver would name a person, and a record that named the wrong one
 * would be worse than one that names nobody.
 *
 * @param {any[]} facts
 * @returns {{key: string, record: Record<string, any>}[]}
 */
export function composeRecords(facts) {
  const collisions = keyCollisions(facts);
  if (collisions.length) {
    throw new Error(
      `${collisions.length} of BOT-35's \`migration:<owner/name>@<tag>\` keys are shared by more than one ` +
      "decision, so the records would derive one id and overwrite each other: " +
      `${collisions.slice(0, 3).map((c) => `${c.key} (${c.facts_sharing_it})`).join(", ")}` +
      `${collisions.length > 3 ? ", …" : ""}. MIG-21 asks for one record per refusal and approval; the ` +
      "domain separates versions, not decisions about one version. Widening it is an amendment to BOT-35 " +
      "(ops.22, §1.3 row 6), not a change to this file.",
    );
  }
  return facts.map((fact) => {
    const record = {
      decided_at: fact.date,
      actor: "system",
      trigger: "migration",
      repo: fact.repository,
      tag: fact.tag,
      state: fact.state,
    };
    if (fact.plugin_id) record.plugin_id = fact.plugin_id;
    if (fact.version) record.version = fact.version;
    if (fact.reasons?.length) record.reasons = [...fact.reasons];
    refuseUncomposable(record);
    return { key: migrationKey(fact), record };
  });
}

/** The allowlist, enforced. Throws rather than returning, because it has no caller who could continue. */
export function refuseUncomposable(record) {
  for (const [member, value] of Object.entries(record)) {
    const grammar = RECORD_MEMBERS[member];
    if (!grammar) {
      throw new Error(
        `\`${member}\` is not a member this export composes, and PRIV-2 forbids composing anything ` +
        "this file was not told to expect. DEC-7's member list and RECORD_MEMBERS are what may cross.",
      );
    }
    if (!grammar(value)) {
      throw new Error(`\`${member}\` does not match its own grammar, so it is not the thing it claims to be`);
    }
  }
  return record;
}

// ── reading GitHub, and reading a file instead ──────────────────────────────

const API = "https://api.github.com";

function headers() {
  const h = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "astra-registry-bot",
  };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

/** Every page of a list endpoint, following `Link: rel="next"` and nothing else. */
async function fetchAll(url, fetchImpl = fetch) {
  const out = [];
  let next = url;
  while (next) {
    const res = await fetchImpl(next, { headers: headers() });
    if (!res.ok) throw new Error(`GitHub returned HTTP ${res.status} for ${next}`);
    out.push(...(await res.json()));
    const link = res.headers.get("link") ?? "";
    next = /<([^>]+)>;\s*rel="next"/.exec(link)?.[1] ?? null;
  }
  return out;
}

/**
 * `gh api --paginate` writes concatenated arrays, and a hand-saved page is one
 * array. Both, and an array of arrays, read the same way here.
 */
function readJsonArray(file) {
  const text = fs.readFileSync(file, "utf8").trim();
  const parsed = JSON.parse(text.startsWith("[") && /\]\s*\[/.test(text) ? `[${text.replace(/\]\s*\[/g, ",")}]` : text);
  return Array.isArray(parsed) ? parsed.flat() : [parsed];
}

// ── CLI ─────────────────────────────────────────────────────────────────────

const USAGE = `usage:
  bot/export-issues.mjs --facts --repo <owner/name> [--from <dir>] [--out <file>]
  bot/export-issues.mjs --compose --facts-file <file> [--registry-dir <dir>]`;

function parseArgs(argv) {
  const opts = { mode: null, repo: null, from: null, out: null, factsFile: null, root: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--facts") opts.mode = "facts";
    else if (a === "--compose") opts.mode = "compose";
    else if (a === "--repo") opts.repo = argv[++i];
    else if (a === "--from") opts.from = path.resolve(argv[++i]);
    else if (a === "--out") opts.out = path.resolve(argv[++i]);
    else if (a === "--facts-file") opts.factsFile = path.resolve(argv[++i]);
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else throw new Error(`unknown argument: ${a}\n${USAGE}`);
  }
  if (!opts.mode) throw new Error(`one of --facts or --compose is required\n${USAGE}`);
  return opts;
}

/**
 * B-T2.2's writer, or a refusal that names it.
 *
 * `--compose` does not write a record file and does not derive a decision id.
 * Both belong to `bot/lib/decisions.mjs`, which B-T2.2 builds and which is not
 * on `main` yet. Writing a second composer here to fill the gap would be two
 * writers for one record shape — and the second one would be the one nobody
 * remembers to change. So this refuses, by name, and the refusal is the thing
 * that gets fixed when the writer lands.
 */
export async function resolveWriter({ root, load = (s) => import(s) } = {}) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const file = path.join(root ?? here, "lib", "decisions.mjs");
  if (!fs.existsSync(file)) {
    throw new Error(
      `${path.relative(process.cwd(), file)} is not in this checkout, so there is nothing to write the ` +
      "records with. It is B-T2.2's decision-record writer: it derives BOT-35's `decision_id` over the " +
      "domain-separated key, runs PRIV-2 over the composed content and places the file under " +
      "`log/decisions/`. This export composes the members and nothing else, deliberately — a second " +
      "module that also derived a decision id would be a second module that could disagree about one.",
    );
  }
  const mod = await load(file);
  if (typeof mod.writeDecisionRecord !== "function") {
    throw new Error(
      `${path.relative(process.cwd(), file)} exports no \`writeDecisionRecord\`, which is the one thing ` +
      "this export asks of it: `writeDecisionRecord({ key, record, root })`. If B-T2.2 named it something " +
      "else, this line is the only place that has to change.",
    );
  }
  return mod.writeDecisionRecord;
}

async function main(argv) {
  const opts = parseArgs(argv);

  if (opts.mode === "facts") {
    let issues;
    let comments;
    if (opts.from) {
      issues = readJsonArray(path.join(opts.from, "issues.json"));
      comments = readJsonArray(path.join(opts.from, "comments.json"));
    } else {
      if (!safeRepo(opts.repo)) throw new Error("--repo <owner/name> is required when --from is not given");
      issues = await fetchAll(`${API}/repos/${opts.repo}/issues?state=all&per_page=100`);
      comments = await fetchAll(`${API}/repos/${opts.repo}/issues/comments?per_page=100`);
    }
    const result = exportFacts({ issues, comments });
    const doc = {
      generated_at: `${new Date().toISOString().slice(0, 19)}Z`,
      ...result,
    };
    const json = `${JSON.stringify(doc, null, 2)}\n`;
    if (opts.out) fs.writeFileSync(opts.out, json);
    else process.stdout.write(json);
    console.error(
      `facts ${result.facts.length} from ${result.counts.documents_read} document(s) in ` +
      `${result.counts.issues_in_scope} of ${result.counts.issues_read} issue(s); ` +
      `${result.unrecoverable.length} unrecoverable; ${result.collisions.length} shared key(s)`,
    );
    // A floor, and the only one this half can have: an export that finds no
    // decision at all has not found that there were none — the archive it
    // reads holds 99 — it has stopped working, and a `write` job that composed
    // zero records from it would commit a baseline with the export silently
    // missing and nothing red anywhere.
    return result.facts.length === 0 ? 1 : 0;
  }

  if (!opts.factsFile) throw new Error(`--compose needs --facts-file <file>\n${USAGE}`);
  const doc = JSON.parse(fs.readFileSync(opts.factsFile, "utf8"));
  const composed = composeRecords(doc.facts ?? []);
  const write = await resolveWriter({});
  const written = [];
  for (const { key, record } of composed) written.push(await write({ key, record, root: opts.root }));
  console.error(`composed ${composed.length} migration record(s)`);
  for (const w of written) if (w?.path) console.log(w.path);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`bot: ${e.message}`);
      process.exit(2);
    });
}
