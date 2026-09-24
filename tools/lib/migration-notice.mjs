// MIG-13's rounds, as procedure rather than prose: which marker a reader
// believes, what a round or a re-send writes, what each notice says, and
// which accounts a round cannot reach (registry plan M-T5.3; contract MIG-13,
// MIG-14, MIG-29).
//
// ── WHY THE PROCEDURE IS CODE ──────────────────────────────────────────────
//
// The marker's shape has been judged since contract 0.31.0
// (`schema/migration-notice-v1.json`, `tools/validate.mjs`), and the marker's
// SEMANTICS are MIG-13's longest sentence: one marker per round, round 1's
// committed once and never dated, a re-send that moves cutover LATER
// re-committing the latest round's marker with that round's own `sent_at`, an
// EARLIER date being a new round 2 with a new `sent_at`, every later round
// re-committed with the new date (n28), and the reader taking the highest
// `round` present — not the newest file. Every clause of that is a way to
// move the watch's clocks or leave a superseded date on `main`, and every one
// of them was going to be applied by hand, at a desk, on the day. The plan's
// own history is three corrections of exactly that procedure (n10, n22, n28).
// So the procedure is here, and a person runs `tools/migration-notice.mjs`,
// which asks this module what to write.
//
// ── WHAT A RE-SEND WRITES, AND ONE CLAUSE THE CONTRACT LEAVES IMPLICIT ─────
//
// MIG-13's later branch says a re-send "re-commits the latest round's marker
// with the new date and that round's own `sent_at`". Read alone, that leaves
// round 2's marker announcing the old date whenever round 3's is on `main`
// too — and MIG-13's own n28 clause, "no marker announces a superseded date",
// forbids that state, as does the cutover preflight's n28 check, which
// refuses a ref whose markers disagree. So the later branch here re-commits
// EVERY dated marker, each with its own `sent_at`. No `sent_at` moves, so no
// clock moves; the only difference from the one-marker reading is that the
// tree stays one the preflight accepts. Recorded as a plan/contract reading in
// the lane report.
//
// ── NOTHING HERE SENDS ANYTHING ────────────────────────────────────────────
//
// It computes files and texts. Opening an issue in a stranger's repository is
// an owner-approved act (M-T5.3's OWNER APPROVAL), and the marker is committed
// with the sends, never before them.

import fs from "node:fs";
import path from "node:path";

import { isTime } from "./time.mjs";
import { REPO_ROOT, loadSchemas } from "./sources.mjs";
import { NOTICE_DIR, NOTICE_NAME, NOTICE_SCHEMA, noticeMarkerProblems } from "../validate.mjs";

/** The template, one file, three rounds. */
export const NOTICE_DOC = "docs/migration-notice.md";

/** MIG-13 has three rounds. A fourth is a re-send, never a round. */
export const ROUNDS = [1, 2, 3];

/** The listing page MIG-13's banner is on (OD-4; MIG-7). */
export const LISTING_PAGE = (id) => `https://astra.minice.ai/plugins/${id}`;

const markerFile = (round) => `${NOTICE_DIR}/migration-notice-${round}.json`;

/**
 * A marker as it is written: the four members in B.4's order, `round` an
 * integer literal (never `1.0`), two-space indented, one trailing newline.
 * Judged by the same `noticeMarkerProblems` the tree check uses before it is
 * handed back, so this module cannot produce a marker the gate refuses.
 */
export function markerText(doc, schema = loadSchemas(REPO_ROOT).migrationNotice) {
  const ordered = { schema: NOTICE_SCHEMA, round: doc.round, sent_at: doc.sent_at };
  if (doc.cutover_planned_at !== undefined) ordered.cutover_planned_at = doc.cutover_planned_at;
  const text = `${JSON.stringify(ordered, null, 2)}\n`;
  const problems = noticeMarkerProblems(text, schema);
  if (problems.length) {
    throw new Error(`the marker this would write is one the tree check refuses: ${problems.map((p) => p.message).join("; ")}`);
  }
  return text;
}

/**
 * Every marker on a tree, each with the problems the tree check finds in it.
 * @returns {{file: string, nameRound: number, doc: object|null, problems: string[]}[]}
 */
export function readMarkers(root = REPO_ROOT, schema = loadSchemas(REPO_ROOT).migrationNotice) {
  const dir = path.join(root, NOTICE_DIR);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => NOTICE_NAME.test(f)).sort().map((name) => {
    const text = fs.readFileSync(path.join(dir, name), "utf8");
    const problems = noticeMarkerProblems(text, schema).map((p) => p.message);
    let doc = null;
    try { doc = JSON.parse(text); } catch { /* reported in problems */ }
    return { file: `${NOTICE_DIR}/${name}`, nameRound: Number(NOTICE_NAME.exec(name)[1]), doc, problems };
  });
}

/**
 * The marker a reader believes: the one with the HIGHEST `round` present.
 * Not the most recently committed file, and not the latest `sent_at` — a
 * re-commit under MIG-13's branches changes a file's content without changing
 * which round it is (M-T5.3, "which marker is authoritative"; attack §3.1
 * row 8). Refuses rather than choosing when the markers cannot be ordered: a
 * marker the tree check refuses, a file whose name and `round` disagree, or
 * two markers of one round.
 *
 * @returns {{marker: object|null, problems: string[]}}
 */
export function authoritative(markers) {
  const problems = [];
  for (const m of markers) {
    for (const p of m.problems) problems.push(`${m.file}: ${p}`);
    if (m.doc && Number.isInteger(m.doc.round) && m.doc.round !== m.nameRound) {
      problems.push(`${m.file} carries round ${m.doc.round}: a reader going by the name and one going by the record would take different markers`);
    }
  }
  const byRound = new Map();
  for (const m of markers) {
    if (!m.doc || !Number.isInteger(m.doc.round)) continue;
    byRound.set(m.doc.round, [...(byRound.get(m.doc.round) ?? []), m]);
  }
  for (const [round, group] of byRound) {
    if (group.length > 1) problems.push(`round ${round} has ${group.length} markers (${group.map((m) => m.file).join(", ")}), and MIG-13 says one per round`);
  }
  if (problems.length) return { marker: null, problems };
  const rounds = [...byRound.keys()].sort((a, b) => b - a);
  return { marker: rounds.length ? byRound.get(rounds[0])[0] : null, problems };
}

/**
 * The trailer a commit that RE-COMMITS a marker carries.
 *
 * `tools/moderation-coverage.mjs` refuses any change or deletion under `log/`
 * (MOD-34's append-only rule, `log-tree-edited`), and a marker re-commit is a
 * change under `log/`: every MIG-13 re-send and every new round 2 is one. The
 * canary is right that `log/` is append-only for the records MOD-34 is about,
 * and a marker is not one of them — but carving the markers out of the rule is
 * a contract question about MOD-34's reach, and the rule's own clearing path
 * already exists. So a re-commit clears itself on its own commit, in the
 * grammar the canary reads (`Moderation-Exempt: <actor>: <reason>`), and the
 * act stays visible in history as a declared one. A first commit of a marker
 * is an addition and needs nothing.
 */
export const RECOMMIT_TRAILER =
  "Moderation-Exempt: migration-notice: MIG-13 re-commits a migration-notice marker with the announced cutover date";

/** Markers that carry a date, which from round 2 is every one of them (B.4). */
const dated = (markers) => markers.filter((m) => m.doc && m.doc.round >= 2);

/**
 * What sending round `round` writes. Nothing is written before the sends it
 * records; this is what the person commits WITH them.
 *
 * Refuses: a round outside MIG-13's three; round 1 carrying a date (B.4,
 * MIG-14) or a second round-1 marker ("round 1's is committed once" — a later
 * first listing's round 1 writes no marker); a later round with no date, with
 * the round before it absent, or with a marker already there (that is a
 * re-send, `planResend`); and a later round announcing a date the markers on
 * `main` do not already carry. An earlier date is a new round 2, and a later
 * one a re-send — both `planResend`'s — so that a round never becomes the
 * back door past the branch MIG-13 reads off the dates.
 *
 * @returns {{writes: {file: string, text: string}[], problems: string[], notes: string[]}}
 */
export function planRound({ markers, round, sentAt, cutover = null }) {
  const problems = [];
  const notes = [];
  const { marker: top, problems: unreadable } = authoritative(markers);
  if (unreadable.length) return { writes: [], problems: unreadable, notes };
  if (!ROUNDS.includes(round)) problems.push(`MIG-13 has rounds ${ROUNDS.join(", ")}; ${JSON.stringify(round)} is not one`);
  if (!isTime(sentAt)) problems.push(`--sent-at ${JSON.stringify(sentAt)} is not a §0.7 time; it is the moment the round went out`);
  if (cutover !== null && !isTime(cutover)) problems.push(`--cutover ${JSON.stringify(cutover)} is not a §0.7 time`);
  if (problems.length) return { writes: [], problems, notes };

  const have = new Map(markers.map((m) => [m.doc.round, m]));
  if (round === 1) {
    if (cutover !== null) {
      notes.push("round 1's marker carries no date (B.4; MIG-14: never in a marker before round 2); the notice text " +
        `states ${cutover}, and the banner shows none until round 2's marker`);
    }
    if (have.has(1)) {
      problems.push("round 1's marker is already on this tree, and it is committed once: a round 1 sent at a later " +
        "first listing writes no second marker (MIG-13). Record that account's send in notes/state.md");
      return { writes: [], problems, notes };
    }
    return { writes: [{ file: markerFile(1), text: markerText({ round: 1, sent_at: sentAt }) }], problems, notes };
  }
  if (cutover === null) problems.push(`round ${round} states the cutover date, and its marker carries it (B.4: from round 2)`);
  if (!have.has(round - 1)) problems.push(`round ${round - 1}'s marker is not on this tree; rounds are sent in order`);
  if (have.has(round)) problems.push(`round ${round}'s marker is already on this tree; a second notice for it is a re-send (planResend)`);
  if (top && top.doc.round >= 2 && cutover !== null && top.doc.cutover_planned_at !== cutover) {
    problems.push(`round ${round} would announce ${cutover} while round ${top.doc.round} announces ` +
      `${top.doc.cutover_planned_at}. A changed date is a re-send first — later re-commits every dated marker, ` +
      "earlier is a new round 2 — and this round then states the date the markers already carry (MIG-13, n28)");
  }
  // Contract 2.0.0: round 2 goes out "with the cutover date, before cutover,
  // with no interval required" — so the one floor left is that its date has
  // not already come. ROLL-32's 30 days from `sent_at` are gone.
  if (round === 2 && Date.parse(sentAt) >= Date.parse(cutover)) {
    problems.push(`round 2 is sent at ${sentAt}, and the cutover date it announces, ${cutover}, has already come; ` +
      "MIG-13 sends round 2 before cutover (contract 2.0.0)");
  }
  if (problems.length) return { writes: [], problems, notes };
  return {
    writes: [{ file: markerFile(round), text: markerText({ round, sent_at: sentAt, cutover_planned_at: cutover }) }],
    problems,
    notes,
  };
}

/**
 * What a MIG-29 re-send announcing `cutover` writes, at the moment `at`.
 *
 * The branch is READ FROM THE DATES, never chosen (M-T5.3):
 *
 *   * no dated marker yet (only round 1, or none) — `undated`: nothing is
 *     written, because round 1's marker never carries a date (B.4). The send
 *     is recorded per account in notes/state.md, like every re-send.
 *   * the date the authoritative marker already announces — `same`: a
 *     re-send that announces nothing new writes no marker.
 *   * LATER — `later`: every dated marker is re-committed with the new date
 *     and ITS OWN `sent_at`, so the dates ROLL-63 counts from do not move
 *     (MIG-13; see the header for why every one and not only the latest).
 *   * EARLIER — `earlier`: a new round 2, `sent_at` = `at`, from which
 *     sent before the earlier date comes (contract 2.0.0, which took ROLL-32's
 *     30 days from it away); and every later round's marker already
 *     committed is re-committed with the new date and its own `sent_at`
 *     (n28), so no marker on `main` announces the abandoned date.
 *
 * @returns {{branch: string|null, writes: {file: string, text: string}[], problems: string[], notes: string[]}}
 */
export function planResend({ markers, cutover, at }) {
  const problems = [];
  const notes = [];
  if (!isTime(cutover)) problems.push(`--cutover ${JSON.stringify(cutover)} is not a §0.7 time`);
  if (!isTime(at)) problems.push(`--at ${JSON.stringify(at)} is not a §0.7 time; it is the moment the re-send went out`);
  const { marker: top, problems: unreadable } = authoritative(markers);
  problems.push(...unreadable);
  if (problems.length) return { branch: null, writes: [], problems, notes };

  const withDate = dated(markers);
  if (!top || withDate.length === 0) {
    notes.push("no marker carries a date yet (round 1's never does), so this re-send writes no marker; record it per " +
      "account in notes/state.md (MIG-13)");
    return { branch: "undated", writes: [], problems, notes };
  }
  const announced = top.doc.cutover_planned_at;
  const was = Date.parse(announced);
  const now = Date.parse(cutover);
  if (now === was) {
    notes.push(`${cutover} is the date round ${top.doc.round} already announces; a re-send announcing nothing new writes no marker`);
    return { branch: "same", writes: [], problems, notes };
  }
  const two = markers.find((m) => m.doc.round === 2);
  if (!two) {
    problems.push(`round ${top.doc.round}'s marker is on this tree and round 2's is not; rounds are sent in order, ` +
      "and every re-send branch reads round 2's sent_at");
    return { branch: null, writes: [], problems, notes };
  }
  if (Date.parse(at) < Date.parse(two.doc.sent_at)) {
    problems.push(`--at ${at} is before round 2's sent_at ${two.doc.sent_at}; a re-send is sent after the round it follows`);
    return { branch: null, writes: [], problems, notes };
  }
  if (now > was) {
    notes.push(`${cutover} is LATER than the announced ${announced}: every dated marker is re-committed with it and its ` +
      "own sent_at, so no clock moves (MIG-13)");
    return {
      branch: "later",
      writes: withDate.map((m) => ({
        file: m.file,
        text: markerText({ round: m.doc.round, sent_at: m.doc.sent_at, cutover_planned_at: cutover }),
      })),
      problems,
      notes,
    };
  }
  if (Date.parse(at) >= now) {
    problems.push(`${cutover} is EARLIER than the announced ${announced}, which makes this a new round 2, and it is ` +
      `sent at ${at}, when that earlier date has already come; MIG-13 sends it before the date comes (contract 2.0.0)`);
    return { branch: null, writes: [], problems, notes };
  }
  notes.push(`${cutover} is EARLIER than the announced ${announced}: this is a new round 2 with sent_at ${at}, sent ` +
    "before the earlier date comes (MIG-13)");
  const writes = [{ file: markerFile(2), text: markerText({ round: 2, sent_at: at, cutover_planned_at: cutover }) }];
  for (const m of withDate.filter((x) => x.doc.round > 2)) {
    writes.push({ file: m.file, text: markerText({ round: m.doc.round, sent_at: m.doc.sent_at, cutover_planned_at: cutover }) });
    notes.push(`${m.file} is re-committed with ${cutover} and its own sent_at ${m.doc.sent_at} (n28)`);
  }
  return { branch: "earlier", writes, problems, notes };
}

// ── the notice text ─────────────────────────────────────────────────────────

const opener = (round) => `<!-- notice:round-${round} -->`;
const closer = (round) => `<!-- /notice:round-${round} -->`;

/** One round's template, exactly as `docs/migration-notice.md` holds it between its two markers. */
export function roundTemplate(docText, round) {
  const a = docText.split(opener(round)).length - 1;
  const b = docText.split(closer(round)).length - 1;
  if (a !== 1 || b !== 1) {
    throw new Error(`${NOTICE_DOC} holds ${a} opening and ${b} closing marker(s) for round ${round}; each is written once`);
  }
  const start = docText.indexOf(opener(round)) + opener(round).length;
  const end = docText.indexOf(closer(round));
  if (end < start) throw new Error(`${NOTICE_DOC}'s round ${round} closes before it opens`);
  return docText.slice(start, end).trim();
}

/** The placeholders a template may use. Anything else left in braces is a refusal. */
export const PLACEHOLDERS = ["deadline", "deadline_date", "cutover", "listings"];

/**
 * One round's notice, filled. `deadline` is the committed §0.7 time and is
 * REQUIRED: MIG-14 says every notice states it, so there is no notice without
 * one. `cutover` is required from round 2 (MIG-14: always by round 2); in
 * round 1 an unfixed date reads as not fixed. `listings` are the account's
 * plugin ids, each rendered with its page.
 */
export function renderRound(docText, round, { deadline, cutover = null, listings = [] }) {
  if (!isTime(deadline)) {
    throw new Error("MIG-14: every notice states the deadline, and no policy/binding-deadline.json is committed " +
      `(or it is not a §0.7 time: ${JSON.stringify(deadline)}), so there is no notice to render`);
  }
  if (round >= 2 && !isTime(cutover)) {
    throw new Error(`round ${round} states the cutover date (MIG-14: always by round 2), and none was given`);
  }
  const values = {
    deadline,
    deadline_date: deadline.slice(0, 10),
    cutover: cutover === null ? "not fixed yet — the next notice states it" : `${cutover.slice(0, 10)} (\`${cutover}\`)`,
    listings: listings.length ? listings.map((id) => `- \`${id}\` — ${LISTING_PAGE(id)}`).join("\n") : "- (none)",
  };
  const text = roundTemplate(docText, round).replace(/\{\{([a-z_]+)\}\}/g, (whole, name) => {
    if (!PLACEHOLDERS.includes(name)) throw new Error(`${NOTICE_DOC} round ${round} uses {{${name}}}, which is not a placeholder`);
    return values[name];
  });
  if (/\{\{|\}\}/.test(text)) throw new Error(`${NOTICE_DOC} round ${round} left braces unfilled`);
  return text;
}

// ── who a round reaches ─────────────────────────────────────────────────────

const lower = (s) => String(s ?? "").toLowerCase();

/**
 * MIG-13's recipients on a tree: every account holding a listed plugin with
 * no identity record whose owner no `astra_team` publisher record speaks for.
 * One issue per account, in the repository of its EARLIEST listing (the
 * least `added_at`, then the id), naming every one of its listings.
 *
 * @returns {{account: string, target: string, listings: {id: string, repo: string, added_at: string}[]}[]}
 */
export function recipients(root = REPO_ROOT) {
  const team = new Set();
  const pubDir = path.join(root, "publishers");
  if (fs.existsSync(pubDir)) {
    for (const f of fs.readdirSync(pubDir).filter((n) => n.endsWith(".json"))) {
      const p = JSON.parse(fs.readFileSync(path.join(pubDir, f), "utf8"));
      if (p.tier !== "astra_team") continue;
      team.add(lower(p.owner));
      for (const c of p.covers ?? []) team.add(lower(c));
    }
  }
  const byAccount = new Map();
  const pluginsDir = path.join(root, "plugins");
  for (const id of fs.readdirSync(pluginsDir).sort()) {
    const dir = path.join(pluginsDir, id);
    if (!fs.existsSync(path.join(dir, "plugin.json"))) continue;
    const p = JSON.parse(fs.readFileSync(path.join(dir, "plugin.json"), "utf8"));
    if (p.unlisted === true || fs.existsSync(path.join(dir, "identity.json"))) continue;
    const repo = p.source?.repo;
    if (typeof repo !== "string" || !repo.includes("/")) continue;
    const account = repo.split("/")[0];
    if (team.has(lower(account))) continue;
    const key = lower(account);
    if (!byAccount.has(key)) byAccount.set(key, { account, listings: [] });
    byAccount.get(key).listings.push({ id, repo, added_at: String(p.added_at ?? "") });
  }
  return [...byAccount.values()].map(({ account, listings }) => {
    const sorted = [...listings].sort((a, b) => a.added_at.localeCompare(b.added_at) || a.id.localeCompare(b.id));
    return { account, target: sorted[0].repo, listings: sorted };
  }).sort((a, b) => lower(a.account).localeCompare(lower(b.account)));
}

/**
 * Which accounts a round can reach through its one outbound issue.
 *
 * MIG-13 is conjunctive — a banner AND an issue — and OD-9 stops the releases
 * of an author who is not told. So the reading comes BEFORE the round, per
 * target repository (attack m-6): `has_issues` true, `archived` false, and
 * public. Anything else, including a repository this run could not read, is
 * no issue path, and the account becomes an OWNER ITEM: the round does not go
 * out to it until the owner decides (direct contact, a commit comment, or
 * accepting the freeze). A reading that did not happen is not a reachable
 * repository.
 *
 * @param readings {Record<string, {has_issues?: boolean, archived?: boolean, private?: boolean, visibility?: string}|null>}
 * @returns {{reachable: object[], ownerItems: {account: string, target: string, listings: string[], why: string}[]}}
 */
export function judgeIssuePaths(accounts, readings) {
  const reachable = [];
  const ownerItems = [];
  for (const a of accounts) {
    const r = readings[a.target] ?? readings[lower(a.target)] ?? null;
    const why = [];
    if (r === null || typeof r !== "object") why.push("the repository could not be read, so whether it takes issues is unknown");
    else {
      if (r.has_issues !== true) why.push(`has_issues is ${JSON.stringify(r.has_issues)}`);
      if (r.archived !== false) why.push(`archived is ${JSON.stringify(r.archived)}`);
      if (r.private === true || (r.visibility !== undefined && r.visibility !== "public")) why.push("the repository is not public");
    }
    if (why.length) {
      ownerItems.push({ account: a.account, target: a.target, listings: a.listings.map((l) => l.id), why: why.join("; ") });
    } else {
      reachable.push(a);
    }
  }
  return { reachable, ownerItems };
}
