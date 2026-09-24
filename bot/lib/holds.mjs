// Holds: the decisions the bot has been told to make and has decided not to
// make yet, and the four ways one of them ends.
//
// Registry plan M-T3.3. Pure and offline. `bot/moderation-run.mjs` (M-T3.4)
// imports it: its `commit` job enters a hold with `holdEntry`, walks every hold
// here even when `list` failed — a hold's release is driven by a record in git
// and not by anything the service answers — and reads each commit that deleted
// an entry with `classifyHoldCommit`. That job is itself dark — its schedule is
// commented out and its list call is a placeholder until the R3-open commit —
// so none of this has run in a workflow yet.
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
// ── THE FIVE KINDS, AND WHAT ENDS EACH ──────────────────────────────────────
//
// MOD-9 as published, with OPEN-OWNER-4 closed at 24 hours and OPEN-OWNER-14
// closed at "an operator's confirmation for each `disable`, none for
// `block_install`":
//
//   reversal              every `M_RELIST`, `M_UNREVOKE` and `M_IDENTITY_RESET`
//                         (MOD-9 names the reset a reversal since contract 2.5.0).
//                         Ends: the 24-hour period AND a confirm record.
//                         A failing MOD-46 coverage check blocks THIS AND
//                         NOTHING ELSE — a red coverage report must never be
//                         able to stall a takedown.
//   disable_confirmation  every `M_REVOKE` with action `disable`.
//                         Ends: a confirm record, at once. No period.
//   bound                 a takedown above TRUST-26's bound, `block_install`
//                         included. Ends: a confirm record, at once.
//   unbound_removal       an `A_REMOVAL_REQUEST` for a listing with no identity
//                         record. Ends: a confirm record; OR is cancelled by an
//                         applied `author_request` delist of the same listing,
//                         or by a cancel record. (MOD-9 states the two
//                         cancellations and not the confirmation; the
//                         confirmation is this plan's reading, and it is the
//                         reading the contrast with `unbound_yank` below forces
//                         — `unbound_yank` is called out as the kind that is
//                         *never applied*, which says nothing is wrong with
//                         applying this one on an operator's say-so.)
//   unbound_yank          an `A_YANK` for a listing with no identity record.
//                         NEVER APPLIED. Ends only by a cancel record or by the
//                         entry being deleted by hand (BOT-70).
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
// **A due hold is not released and not committed, in shadow or out of it.**
// M-T3.3's release commit — apply the held decision from the entry, write its
// log entry, delete the entry and its confirm record under `Service-Decision:`
// — and its cancel commit are not built, here or in `bot/moderation-run.mjs`.
// So when `resolveHold` answers `release` or `cancel`, the commit job's
// `walkHolds` files the hold as `due`, refuses it by name (`hold_end_not_built`,
// every run), posts nothing for it and leaves the entry on the tree (ops entry
// 99). This header said until 2026-09-22 that a confirmed hold "is released and
// committed"; nothing ever did either.
//
// What this module decides is WHEN a hold is due, and that answer is the same
// under a `shadow: true` list answer and with `list` down: a hold is not work
// that answer names, the `held` result already took it off the list (BOT-81),
// and the release is driven by the MOD-52 record in git — so the release
// commit, once built, is meant to be made in shadow too. Its `applied` or
// `cancelled` result, though, SETTLES a decision, which is what BOT-92 calls
// state-setting, so it is posted only in a run whose list answer is `shadow:
// false` — the next such run, not this one, re-posted until accepted. "Until
// accepted" is a fact this side records: `bot/lib/settled.mjs` keeps each one
// the service answered `accepted` or `duplicate`, and the walk skips it (ops
// entry 100).
// `resultsToPost` is where that split lives, and `resultKey` is BOT-82's
// idempotency key, which answers a repeat `duplicate` with no time limit (so
// there is no re-post window to expire). The only `applied` or `cancelled`
// results posted today are for holds a commit in history already ended — a
// hand deletion, or a release or cancel commit a person made — which
// `classifyHoldCommit` reads.
//
// ── WHEN A REVERSAL'S 24 HOURS START ────────────────────────────────────────
//
// MOD-9: a reversal is released only on a confirmation "after a 24 h hold period
// (OPEN-OWNER-4) has run from that commit" — the commit that adds
// `state/holds/<id>.json`. Not from `held_at`. `held_at` is the commit job's
// clock when it compiled the hold, and the commit that lands it comes after the
// job's gates and its push, which the job's `timeout-minutes` bounds and
// nothing else does. Until 2026-09-23 the period was counted from `held_at`, so
// a hold could be due up to that timeout before 24 hours had run from its
// commit (ops entry 101) — early, the one direction MOD-9 forbids.
//
// So `resolveHold` is handed where the entry LANDED (`bot/moderation-run.mjs`'s
// `entryLanding`: the commit on HEAD's first-parent line that added the file,
// at its committer time — a hold merged from a branch is dated at the merge
// that brought it onto `main`, as TRUST-26's window dates a withdrawal, ops
// entries 92 and 93), and `reversalDue` counts from that. Three answers:
//
//   landed      the later of `release_after` and that commit + 24 h. The
//               entry's own `release_after` still binds: a release is never
//               earlier than the directory tells a person it will be.
//   not started the file is in no commit yet — the entry this run just wrote.
//               There is no commit for the 24 hours to run from, so it waits.
//   unknown     the history cannot be read (a shallow checkout, a git that
//               failed, or a caller that read nothing). Then `held_at` + 24 h
//               + HOLD_COMMIT_SLACK_MINUTES, which is the commit job's timeout
//               and a minute more: never earlier than the commit could have
//               landed, for any hold that job entered.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { validate } from "../../tools/lib/jsonschema.mjs";

export const SCHEMA = "astra.registry.hold/1";
export const RECORD_SCHEMA = "astra.registry.hold-record/1";

/** `state/holds/` — one `<id>.json`, and at most one `<id>.confirm.json` or `<id>.cancel.json`. */
export const HOLDS_DIR = path.join("state", "holds");

/**
 * OPEN-OWNER-4, closed at 24 hours on 2026-09-17. It applies to `reversal` and
 * to nothing else: the other four kinds wait on a person, not on a clock, and
 * giving them a period would mean a `disable` releasing itself.
 */
export const HOLD_PERIOD_HOURS = 24;

/**
 * How long after its `held_at` a hold's commit can land, when the commit itself
 * cannot be read (see "WHEN A REVERSAL'S 24 HOURS START" above).
 *
 * `held_at` is the commit job's `now`, taken in its compile step; the commit
 * that adds the entry is made in the same job's `apply` step, after the gates,
 * and a job that has not finished inside `plugins-moderation.yml`'s
 * `timeout-minutes` for `commit` is cancelled with nothing pushed. So that
 * timeout bounds the gap — plus one minute, because both stamps are truncated
 * to the second and a runner's cancellation is not instantaneous.
 * `bot/tests/moderation-run.test.mjs` holds this above that job's timeout, so
 * raising the timeout without raising this is red.
 *
 * It bounds only a hold that job entered. `held_at` on an entry a person wrote
 * is that person's claim, which is why the commit, when it can be read, is
 * what the period is counted from.
 */
export const HOLD_COMMIT_SLACK_MINUTES = 21;

/**
 * The five kinds, in the order `holdKindFor` tries them, which is STRICTEST
 * FIRST. A decision can qualify for two — a `disable` issued while the estate is
 * already at the bound is both `disable_confirmation` and `bound` — and the one
 * recorded must be the one whose release rule is hardest to satisfy, so that a
 * widening somewhere else (the bound rising, coverage going green) can never
 * release something that was held for another reason.
 *
 * Compared against `schema/hold-v1.json`'s `held_for` enum by
 * `bot/tests/holds.test.mjs`: a kind in one and not the other is either a hold
 * nothing knows how to end or an end for a hold nothing can write.
 */
export const HOLD_KINDS = [
  "unbound_yank",
  "unbound_removal",
  "reversal",
  "disable_confirmation",
  "bound",
];

/**
 * `M_RELIST`, `M_UNREVOKE` and `M_IDENTITY_RESET`: the three codes MOD-9 calls
 * reversals, released only on a MOD-52 confirmation after the 24-hour period.
 * The reset joined in contract 2.5.0: it gives back a repository name that
 * `B_REPOSITORY_RECYCLED` had closed for good (OPEN-OWNER-15).
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
    ...(held_for === "reversal" ? { release_after: releaseAfter(held_at) } : {}),
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
  if (REVERSAL_CODES.includes(code)) return "reversal";

  // OPEN-OWNER-14, and the half of it that is not conditional: `disable` stops
  // software that is already running on somebody's machine, so it waits for a
  // second person whatever the bound says. There is no flag on this — the
  // 0.11.1 plan's `disable_confirmation` flag is gone, because MOD-9 requires
  // the hold from the first commit.
  if (code === "M_REVOKE" && decision.action === "disable") return "disable_confirmation";

  // The other half: `block_install` refuses only NEW installs, so a moderator
  // may stop the spread at once — *while the bound is not already full*.
  // Above the bound it waits like every other takedown, which is the limit
  // OPEN-OWNER-45 was shown and kept on 2026-09-17 («Оставить как есть»).
  // Exempting it here is the mutation bot/tests/holds.test.mjs watches.
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

const isoPlusMinutes = (iso, minutes) =>
  new Date(new Date(iso).getTime() + minutes * 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");
const isoPlusHours = (iso, hours) => isoPlusMinutes(iso, hours * 60);

/**
 * `held_at` + HOLD_PERIOD_HOURS, to the second, as the entry records it. The
 * EARLIEST a reversal can be due, and not when it is: MOD-9 counts the 24 hours
 * from the commit that added the entry, which lands after `held_at`
 * (`reversalDue`).
 */
export const releaseAfter = (heldAt) => isoPlusHours(heldAt, HOLD_PERIOD_HOURS);

const later = (a, b) => (Date.parse(a) >= Date.parse(b) ? a : b);

/**
 * When a reversal's 24 hours end, and what they were counted from (see "WHEN A
 * REVERSAL'S 24 HOURS START" in the header, and ops entry 101).
 *
 * @param {object} entry   a sound `astra.registry.hold/1` entry.
 * @param {object} [landed] `bot/moderation-run.mjs`'s `entryLanding` for it:
 *   `{sha, at}` — the first-parent commit that added it, at its committer time;
 *   `{sha: null, uncommitted: true, why}` — in no commit yet;
 *   `{sha: null, why}` or nothing at all — the history could not be read.
 * @returns {{due: string|null, from: "commit"|"not_started"|"fallback", why: string}}
 *   `due` null means the period has not started.
 */
export function reversalDue(entry, landed) {
  const floor = entry.release_after ?? releaseAfter(entry.held_at);
  if (landed?.uncommitted) {
    return {
      due: null,
      from: "not_started",
      why: `no commit has added the entry yet, so its ${HOLD_PERIOD_HOURS} hours have not started (MOD-9: from that commit)` +
        (landed.why ? `: ${landed.why}` : ""),
    };
  }
  if (landed?.sha && typeof landed.at === "string" && Number.isFinite(Date.parse(landed.at))) {
    return {
      due: later(floor, isoPlusHours(landed.at, HOLD_PERIOD_HOURS)),
      from: "commit",
      why: `counted from ${landed.sha}, the commit that added the entry, at ${landed.at} (MOD-9)`,
    };
  }
  // The history could not be read. Counting from `held_at` alone is the
  // defect this replaced; the commit job's timeout is the most the commit can
  // trail it by.
  return {
    due: later(floor, isoPlusMinutes(entry.held_at, HOLD_PERIOD_HOURS * 60 + HOLD_COMMIT_SLACK_MINUTES)),
    from: "fallback",
    why: `the commit that added the entry could not be read (${landed?.why ?? "no commit was read for it"}), so it is ` +
      `counted from held_at ${entry.held_at} plus the commit job's ${HOLD_COMMIT_SLACK_MINUTES} minutes, the latest that commit can land`,
  };
}

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
    const want = releaseAfter(entry.held_at);
    if (entry.release_after === undefined) {
      problems.push(`${where}a reversal records no release_after; it should be ${want}`);
    } else if (entry.release_after !== want) {
      problems.push(`${where}release_after is ${entry.release_after} and ${HOLD_PERIOD_HOURS} hours after held_at is ${want}; a hand edit cannot shorten a hold`);
    }
  } else if (entry.release_after !== undefined) {
    problems.push(`${where}${entry.held_for} records a release_after, and only a reversal waits out a period`);
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
  return out.sort((a, b) => ((a.entry?.held_at ?? "") < (b.entry?.held_at ?? "") ? -1 : 1));
}

// ── what to do with one ─────────────────────────────────────────────────────

/**
 * `wait`, `release` or `cancel`, and whether this run may post the result.
 *
 * Whether a hold is due is NOT conditional on `post`: the release is driven by
 * a record in git, so it is due in a shadow run too, and only the posting
 * waits. (The release commit that would act on a `release` answer is not built
 * — the commit job refuses a due hold by name instead; see the header.)
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
 * @param {object} hold          one element of `readHolds`.
 * @param {object} ctx
 * @param {Date}    ctx.now
 * @param {boolean} ctx.shadow          the list answer's `shadow` member.
 * @param {string[]} ctx.delistedPlugins listings with an applied `author_request`
 *                                       delist on `main` (MOD-9's cancellation
 *                                       for a removal request).
 * @param {boolean} ctx.coverageRed     MOD-46's check is failing.
 * @param {object}  [ctx.landed]        where the entry landed on `main`
 *                                       (`entryLanding`), which a reversal's
 *                                       24 hours run from (`reversalDue`).
 *                                       Omitted, it is read as a history that
 *                                       could not be read — the later answer,
 *                                       for `shadow`'s reason.
 */
export function resolveHold(hold, {
  now = new Date(),
  shadow = true,
  delistedPlugins = [],
  coverageRed = false,
  landed = null,
} = {}) {
  const { entry, confirm, cancel } = hold;
  const stay = (reason) => ({ act: "wait", result: null, post: false, reason });
  const done = (act, result, reason) => ({ act, result, post: shadow === false, reason });

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
      return stay("an unbound removal request waits for an operator's confirmation, a delist, or a cancel record");

    case "reversal": {
      if (coverageRed) {
        // MOD-46, and ONLY here. A red coverage report says the registry cannot
        // currently account for every withdrawal it has published; giving
        // something back in that state would be publishing a claim it cannot
        // back. Blocking a takedown on it would be the opposite mistake.
        return stay("MOD-46's coverage check is failing, and a reversal is the one thing it blocks");
      }
      const { due, why } = reversalDue(entry, landed);
      if (due === null) return stay(why);
      if (now.getTime() < new Date(due).getTime()) {
        return stay(`the ${HOLD_PERIOD_HOURS}-hour period ends at ${due}, ${why}`);
      }
      if (!confirm) return stay(`the ${HOLD_PERIOD_HOURS}-hour period has passed and no operator has confirmed it`);
      return done("release", "applied", `the period ended at ${due}, ${why}, and an operator confirmed it (MOD-52, OPEN-OWNER-4)`);
    }

    case "disable_confirmation":
    case "bound":
      // At once on the confirmation, with no period: the period exists to give
      // an operator time to object to something the registry is about to do on
      // its own, and these two are already waiting on that same operator.
      if (!confirm) {
        return stay(entry.held_for === "bound"
          ? "the estate is at TRUST-26's takedown bound and no operator has confirmed it"
          : "an M_REVOKE with action disable waits for an operator's confirmation (OPEN-OWNER-14)");
      }
      return done("release", "applied", "an operator confirmed it (MOD-52)");

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
