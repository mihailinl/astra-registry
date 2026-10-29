// Holds: the decisions the bot has been told to make and has decided not to
// make yet, and the four ways one of them ends.
//
// Registry plan M-T3.3. Pure and offline. `bot/moderation-run.mjs` (M-T3.4)
// imports it: its `commit` job enters a hold with `holdEntry`, walks every hold
// here even when `list` failed — a hold's release is driven by git, a record or
// the takedown window counted from the tree, and not by anything the service
// answers — and reads each commit that deleted
// an entry with `classifyHoldCommit`. That job runs on a dispatch since B-T5.1
// (2026-10-14); its schedule stays commented until its first post arms BOT-83's
// receiver.
//
// ── WHY A HOLD IS A FILE ────────────────────────────────────────────────────
//
// The same three reasons `state/queue/` is a file, and one more that is specific
// to this directory. It survives a runner; it is auditable (`git log
// state/holds/` is every decision that ever waited); it is cancellable by a
// person with no tooling, by deleting it. The fourth: **the run that releases a
// hold is not the run that took it.** A release happens hours later, possibly
// after the service has been unreachable the whole time, so the entry has to
// carry the whole decision rather than a pointer to one — which is why
// `schema/hold-v1.json` copies BOT-80's members into the file instead of
// recording an id to re-fetch.
//
// ── THE KINDS, AND WHAT ENDS EACH ───────────────────────────────────────────
//
// MOD-9 since contract 6.6.0 (the owner, 2026-10-29: the console's step-up is
// the only confirmation). Three kinds are written:
//
//   bound                 a takedown above TRUST-26's bound, `block_install` and
//                         `disable` included. Ends BY ITSELF: released in the
//                         first moderation run whose trailing 24 h, re-counted
//                         from the tree at that run, admits it — oldest held
//                         first, and never more in one run than the bound
//                         admits (`bot/moderation-run.mjs`'s
//                         `admitHeldTakedowns` spends TRUST-26's ledger for it
//                         and hands the answer in as `boundAdmits`). A confirm
//                         record releases it at once, over the bound: MOD-52 is
//                         the break-glass path, and nothing waits for it.
//   unbound_removal       an `A_REMOVAL_REQUEST` for a listing with no identity
//                         record. Ends: an applied `author_request` delist of
//                         the same listing (the moderator's console act, and the
//                         normal end), or a cancel record; OR a confirm record.
//                         (MOD-9 states the two cancellations and not the
//                         confirmation; the confirmation is this plan's reading,
//                         and it is the reading the contrast with `unbound_yank`
//                         below forces — `unbound_yank` is called out as the
//                         kind that is *never applied*, which says nothing is
//                         wrong with applying this one on an operator's say-so.)
//   unbound_yank          an `A_YANK` for a listing with no identity record.
//                         NEVER APPLIED. Ends only by a cancel record or by the
//                         entry being deleted by hand (BOT-70).
//
// Two more are READ and never written — the kinds the rule before 6.6.0 wrote,
// kept so that a run meeting an entry left from then can end it and nothing
// written under the old rule stays stuck:
//
//   reversal              an `M_RELIST`, `M_UNREVOKE` or `M_IDENTITY_RESET`
//                         held for 24 hours and a confirmation (OPEN-OWNER-4,
//                         superseded). Released AT ONCE, with no period and no
//                         confirm record: those codes now apply in the run that
//                         compiles them, so a leftover one waits for nothing a
//                         fresh one would not. A failing MOD-46 coverage check
//                         still holds it a run — MOD-46 blocks the release of a
//                         held relist or unrevoke, and this is the only kind
//                         that can still be one.
//   disable_confirmation  an `M_REVOKE` with action `disable` held for an
//                         operator's confirmation (OPEN-OWNER-14, superseded).
//                         Released like a `bound` hold, NOT at once: the old
//                         rule recorded a disable that was also over the bound
//                         under this kind (strictest first), so the entry cannot
//                         say whether the bound would have held it, and a
//                         disable is a takedown. Releasing it unconditionally
//                         could put a fourth withdrawal into the window.
//
// **A TRUST-42 acknowledgement at the service is not a confirmation** and ends
// nothing here (BOT-32's 0.12.0 note). There is no acknowledgement input to this
// module at all, and `astra.registry.hold-record/1`'s `act` is a closed enum of
// two, so admitting one would be a schema change and a code change rather than
// a field somebody sets.
//
// ── WHY `unbound_yank` IS ITS OWN KIND ──────────────────────────────────────
//
// FLOW-79, since contract 0.13.0, says outright that a listing with no bound
// account offers no yank: its author asks a moderator (`M_YANK`, category
// `author_request`) until it is bound. So the bot meets an unbound `A_YANK`
// only if the service erred, and there is no confirmation that makes an
// erroneous one right — the operator confirming it would be confirming a fact
// about an account the registry cannot see (TRUST-37, DEC-7: the bot never
// learns which account acted). Folding it into `unbound_removal` would give it
// MOD-9's delist rule, and an applied `author_request` delist settles a removal
// request, not a yank: a listing delisted for one reason would silently yank
// versions for another. The kind is raised for the contract in §1.3 row 6 and
// is registry-only until then.
//
// ── SHADOW, AND WHAT A DUE HOLD BECOMES TODAY ───────────────────────────────
//
// **A due hold is released or cancelled by a commit, in shadow or out of it.**
// When `resolveHold` answers `release`, the commit job's `releaseHolds`
// composes M-T3.3's release commit — the held decision applied from the entry,
// its log entry, the entry and any confirm record deleted, under
// `Service-Decision:`; when it answers `cancel`, `cancelHolds` composes the
// cancel commit — the entry and its records deleted under the trailer, and no
// log entry. Both were built on 2026-10-14 (the reset's release on B-T4.2).
// Until then a due hold was filed as `due`, refused by name
// (`hold_end_not_built`) every run and left on the tree (ops entry 99), and
// before 2026-09-22 this header claimed a confirmed hold "is released and
// committed" when nothing did either.
//
// What this module decides is WHEN a hold is due, and that answer is the same
// under a `shadow: true` list answer and with `list` down: a hold is not work
// that answer names, the `held` result already took it off the list (BOT-81),
// and the release is driven by git — a MOD-52 record, or TRUST-26's window
// counted from the tree — so the release and cancel commits are made in
// shadow too. Its `applied` or
// `cancelled` result, though, SETTLES a decision, which is what BOT-92 calls
// state-setting, so it is posted only in a run whose list answer is `shadow:
// false` — the next such run, not this one, re-posted until accepted. "Until
// accepted" is a fact this side records: `bot/lib/settled.mjs` keeps each one
// the service answered `accepted` or `duplicate`, and the walk skips it (ops
// entry 100).
// `resultsToPost` is where that split lives, and `resultKey` is BOT-82's
// idempotency key, which answers a repeat `duplicate` with no time limit (so
// there is no re-post window to expire). Every `applied` or `cancelled`
// result for a hold is posted from a commit in history that ended it — the
// bot's own release or cancel commit, or a person's — which
// `classifyHoldCommit` reads.
//
// ── THE 24 HOURS THAT ARE GONE ──────────────────────────────────────────────
//
// Until contract 6.6.0 a reversal waited 24 hours from the commit that added
// its entry, and this module counted them (`reversalDue`, `releaseAfter`,
// `HOLD_PERIOD_HOURS`, `HOLD_COMMIT_SLACK_MINUTES`; ops entry 101). Nothing is
// held for a period any more, so those are gone. A leftover entry still
// carries `release_after`; it is read as a member the old rule wrote and
// decides nothing.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { validate } from "../../tools/lib/jsonschema.mjs";

export const SCHEMA = "astra.registry.hold/1";
export const RECORD_SCHEMA = "astra.registry.hold-record/1";

/** `state/holds/` — one `<id>.json`, and at most one `<id>.confirm.json` or `<id>.cancel.json`. */
export const HOLDS_DIR = path.join("state", "holds");

/**
 * The kinds this module WRITES, in the order `holdKindFor` tries them, which is
 * STRICTEST FIRST. A decision can qualify for two — an unbound `A_YANK` issued
 * while the estate is at the bound is both `unbound_yank` and `bound` — and
 * the one recorded must be the one whose release rule is hardest to satisfy,
 * so that a widening somewhere else (the window making room) can never release
 * something that was held for another reason.
 */
export const WRITTEN_KINDS = ["unbound_yank", "unbound_removal", "bound"];

/**
 * The kinds the rule before contract 6.6.0 wrote, and this module now only
 * READS and ends (see "THE KINDS" in the header). `holdEntry` refuses to write
 * one.
 */
export const LEFTOVER_KINDS = ["reversal", "disable_confirmation"];

/**
 * Every kind a hold entry on the tree can carry. Compared against
 * `schema/hold-v1.json`'s `held_for` enum by `bot/tests/holds.test.mjs`: a kind
 * in one and not the other is either a hold nothing knows how to end or an end
 * for a hold nothing can write. The schema keeps the two leftover kinds valid
 * so that an entry from before 6.6.0 is read, and released, rather than
 * refused as unsound and left on the tree for ever.
 */
export const HOLD_KINDS = [...WRITTEN_KINDS, ...LEFTOVER_KINDS];

/**
 * The kinds TRUST-26's window releases by itself (`boundAdmits`): a `bound`
 * hold, and a leftover `disable_confirmation`, which is a takedown the old rule
 * may have recorded over the bound.
 */
export const BOUND_GATED_KINDS = ["bound", "disable_confirmation"];

/**
 * `M_RELIST`, `M_UNREVOKE` and `M_IDENTITY_RESET`: the three codes MOD-9 called
 * reversals and held until contract 6.6.0. Now they apply in the run that
 * compiles them, and this list is what a leftover `reversal` entry may carry.
 */
export const REVERSAL_CODES = ["M_RELIST", "M_UNREVOKE", "M_IDENTITY_RESET"];

/** The author-action codes. Neither carries a moderator (DEC-14, MOD-41, n4). */
export const AUTHOR_CODES = ["A_REMOVAL_REQUEST", "A_YANK"];

/** Members `schema/hold-v1.json` forbids on an author action's held decision. */
export const AUTHOR_FORBIDDEN_MEMBERS = ["moderator", "declared_interest"];

export const holdFile = (id) => path.join(HOLDS_DIR, `${id}.json`);
export const recordFile = (id, act) => path.join(HOLDS_DIR, `${id}.${act}.json`);

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

/** `schema/hold-v1.json`, read from disk so the file is the single statement. */
export const holdSchema = (root = REPO_ROOT) =>
  readJson(path.join(root, "schema", "hold-v1.json"));

/** `schema/hold-record-v1.json`. */
export const holdRecordSchema = (root = REPO_ROOT) =>
  readJson(path.join(root, "schema", "hold-record-v1.json"));

// ── writing one ─────────────────────────────────────────────────────────────

/**
 * The hold entry for a decision the run has decided not to apply.
 *
 * `decision` is copied member by member through an ALLOWLIST, and the allowlist
 * is READ OUT OF THE SCHEMA rather than written here. Both halves matter:
 *
 *   - an allowlist, because `schema/hold-v1.json`'s own description claims that
 *     "a member the bot ignored on read must not be able to reach git by riding
 *     inside a hold entry", and `additionalProperties: false` cannot make that
 *     claim true — it refuses the entry when the entry is read back, which is
 *     after the commit. M-T3.4 allowlists on the wire; a hold is the second way
 *     into git and needs its own, because the entry is written in one run and
 *     applied in another;
 *   - derived from the schema, because a second hand-written list of BOT-80's
 *     members is a second thing to update when the contract adds one, and the
 *     one that is not updated is this one. `bot/tests/holds.test.mjs` compares
 *     what this copies against the schema's properties in both directions.
 *
 * The caller has already decided WHICH kind (`holdKindFor`); this only writes
 * it down. The entry is checked before it is returned, so a composer that
 * produces something the directory would refuse fails here rather than at the
 * next run.
 */
export function holdEntry(decision, { held_for, held_at, run, root = REPO_ROOT } = {}) {
  if (LEFTOVER_KINDS.includes(held_for)) {
    // Read and ended, never written (contract 6.6.0). A caller asking for one
    // is a compile that still believes the old rule, and the entry it wrote
    // would be released by the next run with no hold having meant anything.
    throw new Error(
      `refusing to write a \`${held_for}\` hold: MOD-9 holds no reversal and no disable since contract 6.6.0, ` +
      "and this kind is only read, for an entry left from before",
    );
  }
  const schema = holdSchema(root);
  const allowed = Object.keys(schema.properties.decision.properties).filter((k) => k !== "$comment");
  const copied = {};
  for (const member of allowed) {
    // `hasOwn` and not `!== undefined` alone: a member present and explicitly
    // undefined is a caller that meant to say something and said nothing, and
    // copying it writes `"action": undefined` — which `JSON.stringify` drops
    // from the file while `validate` refuses it in memory, so the entry is
    // refused here and the same bytes on disk would have been accepted. Skip
    // it, and let `required` speak if the member was one.
    if (Object.hasOwn(decision ?? {}, member) && decision[member] !== undefined) {
      copied[member] = decision[member];
    }
  }
  const entry = {
    schema: SCHEMA,
    held_for,
    service_decision_id: decision?.service_decision_id,
    held_at,
    ...(run ? { run } : {}),
    decision: copied,
  };
  const problems = checkHoldEntry(entry, { schema });
  if (problems.length) {
    throw new Error(`refusing to write a hold entry that the directory would refuse: ${problems.join("; ")}`);
  }
  return entry;
}

// ── which kind, if any ──────────────────────────────────────────────────────

/**
 * What MOD-9 holds this decision for, or `null` when it applies at once.
 *
 * Since contract 6.6.0 nothing is held for a person's confirmation: a reversal
 * (`M_RELIST`, `M_UNREVOKE`, `M_IDENTITY_RESET`) and an `M_REVOKE` with action
 * `disable` apply in the run that compiles them, like any other decision. The
 * moderator's own step-up in the console is the one confirmation (the owner,
 * 2026-10-29). What is left is TRUST-26's bound and the two unbound author
 * actions.
 *
 * @param {object} decision   BOT-80's members for the code.
 * @param {object} ctx
 * @param {boolean} ctx.overBound     the estate is at or above TRUST-26's bound
 *                                    and this decision is a takedown (M-T3.2
 *                                    counts; this module only believes it).
 * @param {boolean} ctx.listingBound  the listing has an identity record on `main`.
 */
export function holdKindFor(decision, { overBound = false, listingBound = true } = {}) {
  const code = decision?.code;
  if (!code) return null;

  // `A_YANK` first, and unconditionally on the listing being unbound: this is
  // the one kind no later fact can release, so anything that shadowed it would
  // be a way to apply a yank the service should never have sent.
  if (code === "A_YANK" && !listingBound) return "unbound_yank";
  if (code === "A_REMOVAL_REQUEST" && !listingBound) return "unbound_removal";

  // Every takedown, `disable` and `block_install` alike, waits only when the
  // bound is full — the limit OPEN-OWNER-45 was shown and kept on 2026-09-17
  // («Оставить как есть»), and the registry's one guard against a compromised
  // service withdrawing the catalogue. Exempting any takedown here is the
  // mutation bot/tests/holds.test.mjs watches.
  if (overBound && isTakedown(decision)) return "bound";

  return null;
}

/**
 * A takedown in TRUST-26's sense: it takes something away. The reversals give
 * something back and are never `bound`-held — holding a relist behind a full
 * takedown bound would mean the bound made the estate harder to un-break.
 */
export function isTakedown(decision) {
  const code = decision?.code;
  return ["M_YANK", "M_DELIST", "M_DEPRECATE", "M_REVOKE", "A_REMOVAL_REQUEST", "A_YANK"].includes(code);
}

// ── reading the directory ───────────────────────────────────────────────────

/**
 * Everything `schema/hold-v1.json` cannot say, said here with a message that
 * names the defect rather than the keyword.
 *
 * @returns {string[]} empty when the entry is sound.
 */
export function checkHoldEntry(entry, { file = "", schema = holdSchema() } = {}) {
  const where = file ? `${file}: ` : "";
  const problems = validate(schema, entry, "$").map((e) => `${where}${e.path} ${e.message}`);
  if (problems.length) return problems;

  const id = entry.service_decision_id;
  if (file) {
    const base = path.basename(file, ".json");
    if (base !== id) {
      problems.push(`${where}the file is named for ${base} and the entry is for ${id}; a hold is matched by id, so these must agree`);
    }
  }
  if (entry.decision.service_decision_id !== id) {
    problems.push(`${where}the entry holds decision ${entry.decision.service_decision_id} under id ${id}`);
  }

  if (AUTHOR_CODES.includes(entry.decision.code)) {
    for (const m of AUTHOR_FORBIDDEN_MEMBERS) {
      if (Object.hasOwn(entry.decision, m)) {
        problems.push(`${where}an ${entry.decision.code} carries "${m}", and no moderator decided it (DEC-14, MOD-41)`);
      }
    }
  }

  if (entry.held_for === "reversal") {
    if (!REVERSAL_CODES.includes(entry.decision.code)) {
      problems.push(`${where}held as a reversal but the code is ${entry.decision.code}`);
    }
    // A leftover from before contract 6.6.0 carries the `release_after` the
    // old rule wrote. It is read and decides nothing — the leftover releases
    // at once — so its value is not checked against a period that no longer
    // exists.
  } else if (entry.release_after !== undefined) {
    problems.push(`${where}${entry.held_for} records a release_after, and only a leftover reversal carries one`);
  }

  if (entry.held_for === "unbound_yank" && entry.decision.code !== "A_YANK") {
    problems.push(`${where}held as unbound_yank but the code is ${entry.decision.code}`);
  }
  if (entry.held_for === "unbound_removal" && entry.decision.code !== "A_REMOVAL_REQUEST") {
    problems.push(`${where}held as unbound_removal but the code is ${entry.decision.code}`);
  }
  if (entry.held_for === "disable_confirmation" &&
      !(entry.decision.code === "M_REVOKE" && entry.decision.action === "disable")) {
    problems.push(`${where}held for a disable confirmation but the decision is not an M_REVOKE with action disable`);
  }
  return problems;
}

/** @returns {string[]} empty when the record is sound. */
export function checkHoldRecord(record, { file = "", schema = holdRecordSchema() } = {}) {
  const where = file ? `${file}: ` : "";
  const problems = validate(schema, record, "$").map((e) => `${where}${e.path} ${e.message}`);
  if (problems.length) return problems;
  if (file) {
    const base = path.basename(file, ".json");
    const want = `${record.service_decision_id}.${record.act}`;
    if (base !== want) {
      problems.push(`${where}a ${record.act} for ${record.service_decision_id} must be named ${want}.json`);
    }
  }
  return problems;
}

/**
 * Every hold on disk, with the records that answer it, oldest first.
 *
 * Pairing is BY FILENAME and the id inside each record is then re-checked
 * against the entry's. Two handles on the same identity, because one of them is
 * a path an operator typed.
 */
export function readHolds(root = REPO_ROOT, { schemaRoot = REPO_ROOT } = {}) {
  const dir = path.join(root, HOLDS_DIR);
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith(".json"));
  } catch {
    return [];
  }
  // Read once. `checkHoldEntry`'s default argument re-reads the file per call,
  // which is fine for one entry and is a readdir's worth of syscalls per run
  // here — and, worse, would let two entries in one walk be judged by two
  // different versions of the schema if the tree changed underneath.
  //
  // `schemaRoot` is separate from `root` deliberately: the holds being read may
  // be a fixture directory, but the schema they are judged by is always this
  // repository's.
  const schema = holdSchema(schemaRoot);
  const recordSchema = holdRecordSchema(schemaRoot);
  const entries = names.filter((n) => !n.endsWith(".confirm.json") && !n.endsWith(".cancel.json"));
  const out = [];
  for (const name of entries.sort()) {
    const id = name.slice(0, -".json".length);
    const rel = path.join(HOLDS_DIR, name);
    let entry = null;
    let problems = [];
    try {
      entry = readJson(path.join(dir, name));
    } catch (err) {
      out.push({ id, file: rel, entry: null, confirm: null, cancel: null, problems: [`${rel}: ${err.message}`] });
      continue;
    }
    problems = checkHoldEntry(entry, { file: rel, schema });
    const pick = (act) => {
      const f = `${id}.${act}.json`;
      if (!names.includes(f)) return null;
      const r = path.join(HOLDS_DIR, f);
      try {
        const doc = readJson(path.join(dir, f));
        problems.push(...checkHoldRecord(doc, { file: r, schema: recordSchema }));
        return doc;
      } catch (err) {
        problems.push(`${r}: ${err.message}`);
        return null;
      }
    };
    out.push({ id, file: rel, entry, confirm: pick("confirm"), cancel: pick("cancel"), problems });
  }
  // Oldest first, and the same order every run: TRUST-26's window releases
  // `bound` holds in this order (`admitHeldTakedowns`), so two entries held in
  // one run — the same `held_at` — are told apart by id rather than left to a
  // comparator that answers "after" both ways.
  return out.sort((a, b) =>
    String(a.entry?.held_at ?? "").localeCompare(String(b.entry?.held_at ?? "")) || a.id.localeCompare(b.id));
}

// ── what to do with one ─────────────────────────────────────────────────────

/**
 * `wait`, `release` or `cancel`, and whether this run may post the result.
 *
 * Whether a hold is due is NOT conditional on `post`: the release is driven by
 * git — a record, or TRUST-26's window counted from the tree — so it is due in
 * a shadow run too, and only the posting waits. (The commit job's
 * `releaseHolds` and `cancelHolds` act on the answer; see the header.)
 *
 * `shadow` defaults to TRUE here for the same reason it does in
 * `resultsToPost`, and the two defaults have to be the same one: a caller that
 * forgets the member, or a list answer that carries none, must get the SILENT
 * direction. Defaulting it to `false` — which this module did until the suite
 * below was written — makes an omission post, and BOT-92's whole point is that
 * nothing state-setting leaves the registry while shadow holds. `post` is
 * therefore `shadow === false` and not `!shadow`: `undefined`, `null` and the
 * string `"false"` are all not-false, and each of them is an answer this run
 * did not understand.
 *
 * `boundAdmits` defaults to FALSE for the same reason: it is the one input
 * that releases a takedown with nobody's record, so a caller that did not
 * count the window must get the direction that keeps it held.
 *
 * @param {object} hold          one element of `readHolds`.
 * @param {object} ctx
 * @param {boolean} ctx.shadow          the list answer's `shadow` member.
 * @param {string[]} ctx.delistedPlugins listings with an applied `author_request`
 *                                       delist on `main` (MOD-9's cancellation
 *                                       for a removal request).
 * @param {boolean} ctx.coverageRed     MOD-46's check is failing.
 * @param {boolean} ctx.boundAdmits     TRUST-26's trailing 24 h, counted from the
 *                                       tree at this run, has room for THIS hold
 *                                       after every older one and every
 *                                       confirmed takedown released this run
 *                                       (`bot/moderation-run.mjs`'s
 *                                       `admitHeldTakedowns`, which spends the
 *                                       run's ledger for it).
 * @returns {{act: "wait"|"release"|"cancel", result: string|null, post: boolean, reason: string,
 *   gate?: "bound"}} `gate: "bound"` marks a release the window admitted rather
 *   than a record.
 */
export function resolveHold(hold, {
  shadow = true,
  delistedPlugins = [],
  coverageRed = false,
  boundAdmits = false,
} = {}) {
  const { entry, confirm, cancel } = hold;
  const stay = (reason) => ({ act: "wait", result: null, post: false, reason });
  const done = (act, result, reason, extra = {}) => ({ act, result, post: shadow === false, reason, ...extra });

  if (!entry) return stay("no readable hold entry");
  if (hold.problems?.length) return stay(`the hold entry is not sound: ${hold.problems[0]}`);

  const id = entry.service_decision_id;
  const matches = (record) => record && record.service_decision_id === id;

  // A cancel record ends every kind, including the one no confirmation reaches.
  if (cancel) {
    if (!matches(cancel)) return stay(`the cancel record names ${cancel.service_decision_id}, not ${id}`);
    return done("cancel", "cancelled", "an operator cancelled it (MOD-52)");
  }

  if (confirm && !matches(confirm)) {
    // Not an error and not a release: a record for another decision is simply
    // not this decision's answer. Matching on the plugin instead of the id is
    // the mutation the suite watches, and what it buys an attacker is one
    // confirmation releasing every held decision against the same listing.
    return stay(`the confirm record names ${confirm.service_decision_id}, not ${id}`);
  }

  switch (entry.held_for) {
    case "unbound_yank":
      // Never applied. Not on a confirm record, not after any period, not on an
      // applied `author_request` delist. FLOW-79 lets only a bound account yank.
      return stay(
        confirm
          ? `an unbound A_YANK is never applied: the confirm record for ${id} releases nothing, and only a cancel record or a hand deletion ends it (FLOW-79, BOT-70)`
          : "an unbound A_YANK is never applied; it ends only by a cancel record or a hand deletion (FLOW-79, BOT-70)",
      );

    case "unbound_removal":
      if (delistedPlugins.includes(entry.decision.plugin_id)) {
        return done("cancel", "cancelled", `an applied author_request delist of ${entry.decision.plugin_id} settles the removal request (MOD-9)`);
      }
      if (confirm) return done("release", "applied", "an operator confirmed it (MOD-52)");
      return stay("an unbound removal request waits for a moderator's author_request delist in the console, or a cancel record");

    case "reversal":
      // A leftover from before contract 6.6.0, released at once: the codes it
      // can carry apply in the run that compiles them now, so a leftover waits
      // for nothing a fresh one would not — no period, no confirm record.
      if (coverageRed) {
        // MOD-46, and ONLY here: it blocks the release of a held relist or
        // unrevoke, and a leftover is the one such hold that can still exist.
        // A red coverage report says the registry cannot currently account for
        // every withdrawal it has published; giving something back from a hold
        // in that state would be publishing a claim it cannot back. It holds
        // the leftover a run, which costs time and nothing else.
        return stay("MOD-46's coverage check is failing, and the release of a held reversal is the one thing it blocks");
      }
      return done("release", "applied",
        "a reversal held under the rule before contract 6.6.0, which MOD-9 no longer holds, so it is released at once " +
        "with no period and no confirmation");

    case "disable_confirmation":
    case "bound":
      // A confirm record releases it at once, over the bound: MOD-52 is the
      // break-glass path, and the one way to apply a takedown the window would
      // not yet admit. Otherwise TRUST-26's window decides, counted from the
      // tree at this run; nothing waits for a person.
      if (confirm) return done("release", "applied", "an operator confirmed it (MOD-52), which releases it at once over the bound");
      if (boundAdmits) {
        return done("release", "applied",
          "TRUST-26's trailing 24 hours, counted from the tree at this run, now admit it, so it releases by itself " +
          `(MOD-9 since contract 6.6.0)${entry.held_for === "disable_confirmation" ? "; a disable held for a confirmation before 6.6.0 is released as a bound hold" : ""}`,
          { gate: "bound" });
      }
      return stay(
        "the estate is at TRUST-26's takedown bound: it releases by itself in the first run whose trailing 24 hours " +
        "admit it, oldest held first, or at once on an operator's MOD-52 confirmation");

    default:
      return stay(`unknown hold kind ${entry.held_for}`);
  }
}

// ── what a commit that touched a hold was ───────────────────────────────────

/**
 * BOT-70. A hold entry can leave the tree several ways, and the record of which
 * one it was is the commit itself, so this reads a commit rather than a file.
 *
 * A hand deletion is a CANCELLATION — it is the documented way for a person
 * with no tooling to end a hold, so it must not be reported as an application
 * and must not be silent.
 *
 * **The fourth shape is why this returns four acts and not three.** The plan
 * names three — release (log entry + `Service-Decision:`), cancel (trailer, no
 * log entry), hand cancellation (neither) — and says "an entry deleted without
 * both is a hand cancellation", which reads two ways. Under "missing either",
 * a commit that deleted the entry AND WROTE THE LOG ENTRY under no trailer is a
 * hand cancellation; under "missing both", it is unstated. The two readings
 * differ only on that commit, and one of them posts `cancelled` for a decision
 * that was in fact APPLIED — the public log already says the plugin was yanked
 * while the service is told nothing happened, and BOT-82's key then settles
 * every honest retry as a duplicate of the lie. So it is neither: `unclear`,
 * with no result to post and a reason an operator can act on. Raised in the
 * report as a question for the plan rather than decided here.
 *
 * @param {object} commit {sha, deletesEntry, writesLogEntry, trailers: {}}
 */
export function classifyHoldCommit(commit) {
  const { sha = "", deletesEntry = false, writesLogEntry = false, trailers = {} } = commit ?? {};
  if (!deletesEntry) return { act: "none", result: null, hand: false, reason: "the hold entry is still in the tree" };
  const hasTrailer = Boolean(trailers["Service-Decision"]);
  if (writesLogEntry && hasTrailer) {
    return { act: "release", result: "applied", hand: false, reason: "a release commit: the held decision, its log entry and a Service-Decision: trailer" };
  }
  if (hasTrailer) {
    return { act: "cancel", result: "cancelled", hand: false, reason: "a cancel commit: the entry deleted under a Service-Decision: trailer" };
  }
  if (writesLogEntry) {
    return {
      act: "unclear",
      result: null,
      hand: true,
      reason: `${sha || "an untrailered commit"} deleted the hold entry and wrote a log entry under no Service-Decision: trailer, so it applied a decision it does not name; it is not a hand cancellation and no result may be posted for it (BOT-70)`,
    };
  }
  return {
    act: "cancel",
    result: "cancelled",
    hand: true,
    reason: `a hand cancellation in ${sha || "an untrailered commit"}: the entry was deleted with neither a log entry nor a Service-Decision: trailer (BOT-70)`,
  };
}

// ── posting the result ──────────────────────────────────────────────────────

/** BOT-82's idempotency key. A repeat under it answers `duplicate`, with no time limit. */
export const resultKey = (r) => `${r.service_decision_id}|${r.outcome}|${r.commit}`;

/**
 * What a run may POST for released and cancelled holds. Nothing, under a
 * `shadow: true` list answer — an `applied` or `cancelled` service-decision
 * result settles a decision, and BOT-92 calls that state-setting. The next run
 * answered `shadow: false` posts it, once, and BOT-82 settles a repeat.
 *
 * `shadow` defaults to TRUE, and an answer that carries no `shadow` member is
 * read as shadow: the silent direction has to be the one a missing member
 * produces.
 */
export function resultsToPost(pending, { shadow = true } = {}) {
  if (shadow !== false) return [];
  const seen = new Set();
  return pending.filter((r) => {
    const k = resultKey(r);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
