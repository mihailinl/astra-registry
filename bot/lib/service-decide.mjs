// The service path's decision: one claimed submission, everything the run
// established about it, and what — if anything — this run may write or post.
//
// Registry plan B-T3.3a (binding and identity), B-T3.3b (approvals, stops,
// notices, windows, deny), B-T3.3c (the outcomes that write nothing), with
// BOT-92's shadow rule applied at the one place every outcome passes through.
// `bot/decide.mjs --service` is the caller, in `plugins-ingest.yml`'s `decide`
// job, which holds no token, no write access and no stranger archive: its
// inputs are job outputs (`claim`, `verify`, `ask`), the two artifacts the
// `check` job uploaded, and git.
//
// ── what each input is allowed to say ──────────────────────────────────────
//
//   lease     the service's: submission id, attempt, the state it was claimed
//             from, trigger, the repository and tag it was registered under.
//             Never an identity value (BOT-21, §4.3's "never" row).
//   verified  the `verify` job's, which hashed the bytes and verified the
//             bundle: every identity value — plugin id and version from the
//             attested asset names, both ids and `.12` from the certificate,
//             the commit, the digests, the binding line, the fingerprint.
//   facts     the `check` job's, which OPENED a stranger's archive: codes and
//             levels from a closed vocabulary, and nothing that names anything.
//   listing   the same job's listing files, re-validated by the publish job,
//             whose identity members are overwritten from `verified` before a
//             byte of them is compared or written (BOT-21's second bullet).
//   ask       the `ask` job's, reduced to the outcome the bot acts on (BOT-89):
//             the verdict as one of four words, the stop status, the approval
//             decisions, the notice status and its time.
//   git       the tree this run checked out: records, the identity record, the
//             baseline, the queue entry, alert and deny records, the markers.
//
// A disagreement between `facts`/`listing` and `verified` writes nothing,
// posts nothing, and alerts (BOT-15; B-T3.2): the lease expires and BOT-15
// counts it, which is the service's way of noticing a submission whose checks
// cannot be believed.
//
// ── the output ─────────────────────────────────────────────────────────────
//
// One plan per submission, of one of five kinds:
//
//   state     a record is committed (held, published, refused) and the
//             result names it; `delayed` since contract 3.0.0 never, because
//             nothing on this path is delayed (DEC-19);
//   wait      nothing is committed; a `wait` result is posted (FLOW-72);
//   reported  `main` already carries the answer (BOT-19, BOT-74): nothing is
//             committed, and the result names the record that is there;
//   norecord  FLOW-67's refusal: nothing is committed, the result carries the
//             commit the absence was read at (FLOW-78);
//   none      nothing is committed and NOTHING IS POSTED — a stop the
//             moderation run records, an alert about a disagreement, or work
//             a `shadow: true` answer named (BOT-92).
//
// Under shadow the plan is computed in full — R3's shadow runs exist to time
// exactly this — and then emptied: `shadow: true`, kind `none`, and the result
// it WOULD have posted is kept only so the caller can print its kind and body
// hash to the step summary (B-T3.5).

import fs from "node:fs";
import path from "node:path";

import { decide } from "./policy/decision.mjs";
// B-T3.3c's two rules, written in `bot/decide.mjs` and waiting for this
// caller: BOT-74's "already published with identical digests" and FLOW-67's
// "no listing names the repository and no usable line". Imported, not
// re-written — a second copy of a no-record rule is a second answer to when
// the registry writes nothing.
import { alreadyPublished, noListingNoBinding, terminalOnMain } from "../decide.mjs";
import { CHECK_FACTS_SCHEMA } from "../ingest.mjs";
import { artifactDigests, submissionDigest, submissionFingerprint } from "./policy/release.mjs";
import { HOUR_MS, iso } from "./policy/time.mjs";
import { CODES } from "./codes.mjs";
import { POLICY_CODES } from "./policy/constants.mjs";
import { applyIdentity, compareWithBaseline, effectiveBaseline } from "./identity.mjs";
import { safeRepo, safeTag } from "./safe.mjs";
import { execFileSync } from "node:child_process";
import { trackRecord } from "./policy/track-record.mjs";
import { listingStateAt } from "./listing-state.mjs";
import { loadSources } from "../../tools/lib/sources.mjs";
import { cleanEnv } from "../../tools/lib/git-env.mjs";
import { isTime } from "../../tools/lib/time.mjs";
import { decisionId, submissionKey } from "./decisions.mjs";
import { ID_PATTERN } from "../../tools/lib/ids.mjs";
import { SEMVER_PATTERN } from "../../tools/lib/semver.mjs";

const ID_RE = new RegExp(ID_PATTERN);
const SEMVER_RE = new RegExp(SEMVER_PATTERN);
const UUID_V47_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FINGERPRINT_RE = /^[0-9a-f]{16}$/;
const SHA1_RE = /^[0-9a-f]{40}$/;
const BASE10_RE = /^[0-9]{1,20}$/;
const DIGEST_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*:[0-9a-f]{64}$/;

// ── the numbers (B-T3.3b; reg.61a's service-path half) ──────────────────────
//
// Each is the owner's answer of 2026-09-13 as contract 0.12.0 and 0.20.0
// record it, and `docs/POLICY.md` §3.2 states each one; `bot/tests/service.
// test.mjs` fails when a constant and that sentence disagree. They live here
// rather than in `bot/lib/policy/constants.mjs` because that module is held,
// through its barrel, to the exact export surface it had before the split
// (`tools/selftest/repo-rules.mjs`), and a new export there is a change to a
// surface ten files import.

// There is no approval maximum any more. From contract 3.7.0 to 5.7.0 BOT-26
// (4) refused an approval older than 7 days (OPEN-OWNER-5) and re-held the
// submission; 5.8.0 removed the condition (OD-28), because what it voided
// were approvals of releases waiting on something else — Voltur792/SPT
// v1.2.1's waited 46 hours on a notice nobody could receive, and would have
// lost its approval on day 7. BOT-26 (2) still voids an approval the moment
// the release it names changes, which is all an age limit ever guarded.

/**
 * BOT-28: the author objection window for an approved change of hands
 * (OPEN-OWNER-6; DEC-19 since 3.0.0). Since contract 5.8.0 only a hold that
 * a second account may be in — `R_BINDING_CHANGED` on the held record or in
 * this run, or no binding line at all — waits it (`noticeExempt`).
 */
export const UPDATE_WINDOW_HOURS = 6;
/** TRUST-32 / DEC-6: the operator objection window, counted from reported delivery. */
export const OPERATOR_WINDOW_HOURS = 6;
/**
 * TRUST-32 since contract 5.8.0: while the operator window runs, the wait's
 * `earliest_retry_at` is a retry hint at most this far after the report, and
 * never later than the window's end, which travels as `window_ends_at`. BOT-60
 * keeps a waiting submission unclaimable until its earliest retry, so the
 * window's end there would leave an operator's OK unread for up to 6 hours.
 */
export const OPERATOR_RETRY_HINT_MINUTES = 15;
/**
 * TRUST-27: an `R_FIRST_BINDING` approval waits this long after its `held`
 * record reached `main`. **0 since contract 2.1.0**, on the owner's "i allow
 * to remove 7 days wait"; the code kept 7 until 2026-10-06, when the owner
 * answered the inbox card by allowing the edit. The deferral path below stays
 * for MIG-31's floor, which TRUST-27 at 0 does not touch.
 */
export const FIRST_BINDING_WAIT_DAYS = 0;
/** BOT-51's interval, for the earliest retry of a wait no record dates. */
export const NEXT_RUN_SECONDS = 600;
/** §4.4: `wait.cause` is at most this many characters. */
export const WAIT_CAUSE_MAX = 512;

const DAY_MS = 24 * HOUR_MS;

/**
 * §4.4 (contract 3.12.0): a wait's `earliest_retry_at` is at most this many
 * days after the service receives the result, MIG-31's 14-day floor plus a
 * day. The bot counts from its run's start, which is earlier than receipt, so
 * holding itself to the same number never sends what the service refuses.
 */
export const MAX_WAIT_DAYS = 15;

/**
 * The earliest retry a wait may carry. Past §4.4's bound the service refuses
 * the whole result as `invalid`. A value that far out would also leave the
 * submission unclaimable (BOT-60) with no alarm, since FLOW-31 exempts the
 * deferral and the operator window until it. So a defect that computes one
 * fails this run loudly instead: the lease runs out, and BOT-15 counts it.
 */
export function boundedEarliest(startedAt, earliest) {
  const bound = new Date(startedAt).getTime() + MAX_WAIT_DAYS * DAY_MS;
  const at = new Date(earliest).getTime();
  if (!Number.isFinite(at) || at > bound) {
    throw new Error(
      `§4.4: a wait's earliest retry (${earliest}) must be a time at most ${MAX_WAIT_DAYS} days after this run's start ` +
      `(${startedAt}); the service refuses a later one as \`invalid\` (contract 3.12.0)`,
    );
  }
  return earliest;
}

/** The five plan kinds, and only these. */
export const PLAN_KINDS = Object.freeze(["state", "wait", "reported", "norecord", "none"]);

/** §4.3: the states a lease may be claimed from (BOT-60). */
export const CLAIMED_FROM = Object.freeze(["received", "approved", "delayed"]);

/** BOT-89's four, and what `ask` may carry for a submission it did not ask about. */
export const VERDICT_OUTCOMES = Object.freeze(["pass", "B_BINDING_UNUSABLE", "W_ELIGIBILITY_UNREADABLE", "shadow"]);

/**
 * TRUST-14's events. One since contract 3.0.0: an approval, which now exists
 * only for a change-of-hands hold (DEC-6; decision D2). The second event, a
 * delayed fingerprint past its `publish_after`, went with the service path's
 * delay (DEC-19): nothing there is delayed, so nothing is drained.
 */
export const ALERT_EVENTS = Object.freeze(["approval"]);

/**
 * TRUST-32's operator OK record (contract 5.8.0; DEC-6; B.4 lists the path as
 * registry-only, beside the deny record): `state/ok/<fingerprint>.json`,
 * written by `operator.yml`'s act `ok` alone (BOT-33's operator row) and read
 * here. Exactly these members. `approval_decided_at` is copied from the alert
 * record the act answered, which ties the OK to that approval: a new approval
 * of the same fingerprint raises a new alert and needs a new OK.
 */
export const OK_SCHEMA = "astra.registry.ok/1";
export const OK_DIR = "state/ok";
export const OK_MEMBERS = Object.freeze(["schema", "fingerprint", "approval_decided_at", "run", "at", "digest", "held_decision_id"]);
const OK_RUN_RE = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/actions\/runs\/[0-9]+$/;

/** Why `doc` is not an OK record for `fingerprint` (its file name's stem), or `[]`. */
export function okRecordProblems(doc, { fingerprint }) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return ["not an object"];
  const p = [];
  for (const k of Object.keys(doc)) if (!OK_MEMBERS.includes(k)) p.push(`an unnamed member \`${k}\``);
  for (const k of OK_MEMBERS) if (!(k in doc)) p.push(`no \`${k}\``);
  if (doc.schema !== OK_SCHEMA) p.push(`schema ${JSON.stringify(doc.schema)}`);
  if (!FINGERPRINT_RE.test(String(fingerprint ?? ""))) p.push("the file name is not a fingerprint");
  if (doc.fingerprint !== fingerprint) p.push("the `fingerprint` member is not the fingerprint the file name carries");
  if (!isTime(doc.approval_decided_at)) p.push("approval_decided_at");
  if (!isTime(doc.at)) p.push("at");
  // Contract 6.7.0: an OK binds the whole digest and the held record, copied
  // from the alert it answers. One without them (none was ever on `main`) is
  // not read: an OK shortens a wait, so the side a missing binding errs to is
  // the window running out by itself.
  if (!/^[0-9a-f]{64}$/.test(String(doc.digest ?? ""))) p.push("digest");
  else if (doc.digest.slice(0, 16) !== doc.fingerprint) p.push("a `digest` the fingerprint is not the first 16 hex of");
  if (!/^[0-9a-f]{32}$/.test(String(doc.held_decision_id ?? ""))) p.push("held_decision_id");
  if (!OK_RUN_RE.test(String(doc.run ?? ""))) p.push("run");
  return p;
}

// ── small grammar helpers ───────────────────────────────────────────────────

const isStr = (v) => typeof v === "string" && v !== "";
const clip = (text, max = WAIT_CAUSE_MAX) => {
  const points = [...String(text ?? "")];
  return points.length <= max ? points.join("") : points.slice(0, max).join("");
};
const plusMs = (at, ms) => iso(new Date(new Date(at).getTime() + ms));

/**
 * FLOW-11's reason object, from a code the registry owns.
 *
 * `location` is ALWAYS present, and `null` when there is none (§4.4 since
 * 0.13.0, n4): an absent member and a null one are different bodies, and a
 * reader that accepts the absent one accepts a body the service refuses.
 * `message` is the registry's own sentence for the code. It is never text the
 * check job produced: that job opened a stranger's archive, and its facts file
 * carries codes and levels only.
 */
export function reasonOf(code, { location = null, message = null } = {}) {
  return {
    code,
    stage: stageOf(code),
    location: typeof location === "string" && location !== "" ? location : null,
    message: clip(message ?? titleOf(code), WAIT_CAUSE_MAX),
  };
}

/**
 * FLOW-11's stage, which is the stage FLOW-13's row for the code publishes.
 * That is the declared one, read from the two tables `tools/gen-codes-table.mjs`
 * builds the rows from: `bot/lib/codes.mjs` for a check code, and
 * `POLICY_CODES` for a policy, binding, moderation or author code. Anything
 * undeclared is `policy`, FLOW-11's word for every `R_*` and `P_*`.
 *
 * Until 2026-09-24 this answered `binding` for every `B_*` absent from
 * `CODES`. That was a placeholder for rows reg.61a had not written. The rows
 * were then written at stage `ownership` (contract 2.5.0, lane S6), and the
 * placeholder stayed. So the five binding refusals reached the panel with one
 * stage in the result and another in the row (ops couplings 161).
 * `bot/tests/service.test.mjs` now holds every row the bot reports to this.
 */
export function stageOf(code) {
  if (Object.hasOwn(CODES, code)) return CODES[code].stage;
  if (Object.hasOwn(POLICY_CODES, code)) return POLICY_CODES[code].stage;
  return "policy";
}

/** The registry's own sentence for a code, or the code itself where none is written yet. */
function titleOf(code) {
  if (Object.hasOwn(CODES, code)) return CODES[code].title;
  if (Object.hasOwn(POLICY_CODES, code)) return POLICY_CODES[code].title;
  return code;
}

// ── the git half: what `main` already says ──────────────────────────────────

/**
 * Everything this module reads from the checked-out tree, in one object, so
 * `decideSubmission` stays pure and a test can hand it a tree it built.
 *
 * @param {string} root
 * @param {{now: string}} opts
 */
export function readGitState(root, { markersOverride = null } = {}) {
  const records = readJsonTree(path.join(root, "log", "decisions"));
  const alerts = new Map();
  for (const { doc } of readJsonDir(path.join(root, "state", "alerts"))) {
    if (doc && FINGERPRINT_RE.test(String(doc.fingerprint ?? ""))) alerts.set(doc.fingerprint, doc);
  }
  const denied = new Set();
  for (const { name, doc } of readJsonDir(path.join(root, "state", "deny"))) {
    // The file NAME is the key (B.4: `state/deny/<fingerprint>.json`), and the
    // member is read too: a deny record is honoured when either names the
    // fingerprint, because the direction a disagreement errs in is withholding.
    const stem = name.slice(0, -".json".length);
    if (FINGERPRINT_RE.test(stem)) denied.add(stem);
    if (doc && FINGERPRINT_RE.test(String(doc.fingerprint ?? ""))) denied.add(doc.fingerprint);
  }
  // TRUST-32 since contract 5.8.0: an operator OK ends the operator window of
  // the alert it answers. Unlike a deny record, an OK SHORTENS a wait, so the
  // disagreement that errs safe is the opposite one: it counts only when its
  // file name and its `fingerprint` member name the same fingerprint, and it
  // is read whole or not at all.
  const oks = new Map();
  for (const { name, doc } of readJsonDir(path.join(root, ...OK_DIR.split("/")))) {
    const stem = name.slice(0, -".json".length);
    if (okRecordProblems(doc, { fingerprint: stem }).length === 0) oks.set(stem, doc);
  }
  const markers = markersOverride ?? {
    r3_exit: fs.existsSync(path.join(root, "log", "rollout", "R3-exit.json")),
    cutover: fs.existsSync(path.join(root, "log", "cutover.json")),
    baseline: fs.existsSync(path.join(root, "log", "baseline.json")),
  };
  return { root, records: records.map((r) => r.doc).filter(Boolean), alerts, denied, oks, markers };
}

function readJsonDir(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out = [];
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (!e.isFile() || !e.name.endsWith(".json")) continue;
    try {
      out.push({ name: e.name, doc: JSON.parse(fs.readFileSync(path.join(dir, e.name), "utf8")) });
    } catch {
      // An unreadable record is tools/validate.mjs's to refuse. Here it is
      // simply not evidence, which is the withholding direction for a deny
      // record and the conservative one for an alert record (no delivery is
      // read, so the window never opens on it).
    }
  }
  return out;
}

function readJsonTree(dir) {
  const out = [];
  const walk = (d) => {
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && e.name.endsWith(".json")) {
        try {
          out.push({ file: full, doc: JSON.parse(fs.readFileSync(full, "utf8")) });
        } catch {
          /* tools/validate.mjs refuses it; it is no evidence here */
        }
      }
    }
  };
  walk(dir);
  return out;
}

/** `plugins/<id>/plugin.json` and its version files on the checked-out tree, or null. */
export function readListingOnMain(root, pluginId) {
  if (!pluginId || !ID_RE.test(pluginId)) return null;
  const dir = path.join(root, "plugins", pluginId);
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(path.join(dir, "plugin.json"), "utf8"));
  } catch {
    return null;
  }
  const versions = [];
  for (const { doc: v } of readJsonDir(path.join(dir, "versions"))) if (v) versions.push({ doc: v });
  let identity = null;
  const idFile = path.join(dir, "identity.json");
  if (fs.existsSync(idFile)) {
    // An identity record that cannot be read is not an absent one, and the
    // direction that matters is the binding: `bot/decide.mjs`'s
    // `readIdentityRecord` throws for the same reason on the legacy path.
    identity = JSON.parse(fs.readFileSync(idFile, "utf8"));
  }
  return { dir, doc, versions, identity };
}

/** Does any listing on the tree name this repository — by id, or by `source.repo`? (FLOW-67.) */
export function listingNamesRepository(root, { repo, repositoryId }) {
  const base = path.join(root, "plugins");
  let names;
  try {
    names = fs.readdirSync(base, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return false;
  }
  const want = String(repo ?? "").toLowerCase();
  for (const id of names) {
    try {
      const doc = JSON.parse(fs.readFileSync(path.join(base, id, "plugin.json"), "utf8"));
      if (want && String(doc?.source?.repo ?? "").toLowerCase() === want) return true;
    } catch {
      /* not a listing */
    }
    try {
      const ident = JSON.parse(fs.readFileSync(path.join(base, id, "identity.json"), "utf8"));
      if (repositoryId && String(ident?.repository_id) === String(repositoryId)) return true;
    } catch {
      /* no identity record */
    }
  }
  return false;
}

/** `state/queue/<id>@<version>.json` on the tree, or null. */
export function readQueueOnMain(root, pluginId, version) {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, "state", "queue", `${pluginId}@${version}.json`), "utf8"));
  } catch {
    return null;
  }
}

// ── BOT-19, for THIS submission ─────────────────────────────────────────────

/**
 * BOT-19's search, on this path: `bot/decide.mjs`'s `terminalOnMain` — the
 * one implementation of the rule, which names BOT-19's records exactly (a
 * `published`, `stopped` or `M_REJECT` `refused` record carrying this
 * fingerprint, and a stop of the same tag of the same repository) — plus the
 * clause it has no submission to ask about: a `stopped` record for this
 * `submission_id` (FLOW-23).
 *
 * A bot refusal of the same bytes is NOT a hit: a `/recheck`, or a re-claim,
 * exists to decide them again. The first cut of this function reported any
 * refused record for the fingerprint, which was the same over-match
 * `terminalOnMain` had by plugin id, one clause narrower.
 */
export function terminalForSubmission({ records, submissionId, fingerprint, repo = null, tag = null, repositoryId = null }) {
  const list = records ?? [];
  const stop = [...list].reverse().find((r) => r?.state === "stopped" && submissionId && r.submission_id === submissionId);
  if (stop) return stop;
  const hit = terminalOnMain({ records: list, fingerprint, repo, tag, repositoryId });
  if (!hit) return null;
  return list.find((r) => r?.decision_id && r.decision_id === hit.names) ?? { state: hit.reported, decision_id: hit.names, reasons: [] };
}

/**
 * The identity baseline for a listing with no identity record (TRUST-23;
 * MIG-28; ID-74).
 *
 * MIG-20's `migration` record first, through `effectiveBaseline`, which ends
 * a baseline at the newest voiding record. **Failing that, the first
 * `published` record carrying both ids**, and this is a reading this module
 * records rather than one the plan spells: a plugin first listed through the
 * service path after R3 has no `migration` record by construction — MIG-20
 * writes those once, over the listings that existed at R3 — and ID-74 says
 * every later release of an id is "compared with that listing under DEC-17".
 * Read as `migration` alone, MIG-28 would hold every update of every plugin
 * listed after the baseline `R_IDENTITY_CHANGED` for ever. MIG-20's tree check
 * ("every later version carries both ids in its own record") is what makes the
 * first publication record a baseline in all but name.
 */
export function baselineFor({ records, pluginId }) {
  const { baseline, voidedAt } = effectiveBaseline({ records, pluginId });
  if (baseline) return { baseline, source: "migration" };
  const published = (records ?? [])
    .filter((r) => r?.plugin_id === pluginId && r?.state === "published" && r?.trigger !== "migration")
    .filter((r) => BASE10_RE.test(String(r.repository_id ?? "")) && BASE10_RE.test(String(r.repository_owner_id ?? "")))
    .filter((r) => !voidedAt || String(r.decided_at) > voidedAt)
    .sort((a, b) => String(a.decided_at).localeCompare(String(b.decided_at)));
  return published.length ? { baseline: published[0], source: "first-publication" } : { baseline: null, source: null };
}

// ── ID-41: with an identity record ──────────────────────────────────────────

/** §0.7: `token_hash` is the first 16 lowercase hex of the token's SHA-256. */
export function tokenHash(token, hash) {
  return hash(String(token)).slice(0, 16);
}

/**
 * ID-41's table, against the identity record, whatever the verdict says.
 *
 * Rows 1 to 4 by first match; rows 5 and 6 independently. The outcomes are
 * contract codes: `B_REPOSITORY_RECYCLED` (permanent), `B_OWNER_CHANGED`,
 * `R_IDENTITY_CHANGED`, `R_BINDING_CHANGED`.
 *
 * @param {{identity: {repo: string, repository_id: string, repository_owner_id: string},
 *   record: {repo: string, repository_id: string, repository_owner_id: string, token_hash: string},
 *   lineHash: string|null}} opts
 * @returns {{codes: string[], rows: string[]}}
 */
export function id41({ identity, record, lineHash }) {
  const codes = [];
  const rows = [];
  const sameName = String(identity.repo).toLowerCase() === String(record.repo).toLowerCase();
  const sameRepoId = String(identity.repository_id) === String(record.repository_id);
  const sameOwnerId = String(identity.repository_owner_id) === String(record.repository_owner_id);
  const sameHash = lineHash !== null && lineHash === record.token_hash;

  if (sameName && !sameRepoId && !sameOwnerId) { codes.push("B_REPOSITORY_RECYCLED"); rows.push("1"); }
  else if (sameName && !sameRepoId) { codes.push("R_IDENTITY_CHANGED"); rows.push("1b"); }
  else if (!sameRepoId && !sameName) { codes.push("R_IDENTITY_CHANGED"); rows.push("2"); }
  else if (sameRepoId && !sameOwnerId && sameHash) { codes.push("B_OWNER_CHANGED"); rows.push("3"); }
  else if (sameRepoId && !sameHash) { rows.push("4"); }

  // Row 5 — the `source.repo` spelling moved — independently of the above.
  if (!sameName && !codes.includes("R_IDENTITY_CHANGED")) { codes.push("R_IDENTITY_CHANGED"); rows.push("5"); }
  // Row 6 — the token hash differs from the record's — independently.
  if (lineHash !== null && !sameHash) { codes.push("R_BINDING_CHANGED"); rows.push("6"); }
  return { codes, rows };
}

// ── the approval (BOT-26) ───────────────────────────────────────────────────

/** Is the owner file's newest commit the repository owner's own direct commit (ID-63; MIG-10's self path)? */
function ownFile(ownerFile, ids) {
  // The linked author alone is GitHub's mapping of the git author's EMAIL,
  // which a write collaborator can set to the owner's noreply address, so the
  // commit must also carry a signature GitHub verified (re-review of #480).
  // An unsigned owner's first binding is a moderator's, on the site.
  return Boolean(ownerFile)
    && typeof ownerFile.commit === "string" && /^[0-9a-f]{40}$/.test(ownerFile.commit)
    && ownerFile.pull_request === false
    && isStr(ownerFile.author_id) && ownerFile.author_id === ids?.repository_owner_id
    && ownerFile.verified === true;
}

/** The accounts whose own first binding needs no moderator (contract 6.7.0, MIG-10): what `compareActor` calls them. */
export const FIRST_BINDING_SELF_BASES = Object.freeze(["owner", "admin", "maintain"]);

/**
 * MIG-10 since contract 6.7.0: does this release's binding need no
 * `R_FIRST_BINDING` hold? Two ways, and nothing else changes: every ID-*
 * check (ID-41's rows, the recycled repository, the owner id, ID-25) runs
 * before and after exactly as it did.
 *
 *  - `self`: the account that ran the build is the repository's owner, or
 *    GitHub shows it `admin` or `maintain` on the repository (MIG-31's check,
 *    `verify`), AND the service answered the binding line `pass` for this
 *    repository id (ID-9: the token is live and the repository's). Public
 *    membership of the owning organisation alone does not count here: a
 *    member binding an organisation's listing to their own account is the
 *    takeover DEC-10 holds for.
 *  - `approved`: a moderator already approved a first binding of this
 *    listing under THIS binding token. The approval is on `main` as the
 *    alert TRUST-14 raised for it (`state/alerts/<fp>.json`, carrying
 *    `token_hash` and `held_decision_id` since 6.7.0), whose held record is
 *    an `R_FIRST_BINDING` hold of the same plugin id, repository id and owner
 *    id, and whose fingerprint no deny record names. Until 6.7.0 every later
 *    tag re-held until that first release was published, and each needed a
 *    second approval of the same binding. Such a release waits out the
 *    approved one's operator window (TRUST-32) before it publishes, so an
 *    operator who denies the first never finds the second already out.
 *
 * @returns {{by: string, alert?: object, windowEndsAt?: string}|null}
 */
export function firstBindingCleared({ actor, verdict, lineHash, records = [], alerts = null, denied = null, ids, pluginId, oks = null, fingerprint = null, ownerFile = null }) {
  if (!lineHash || verdict !== "pass") return null;
  // The self path needs the owner FILE to be the owner's too (ID-63): a
  // stranger's merged pull request can carry a token the stranger minted —
  // anyone can mint one for any repository id (ID-10, ID-13), so the service
  // says `pass` — and the owner's own next build would then bind the listing
  // to the stranger. So the newest commit touching the owner file must be
  // known, tied to no pull request, and linked to the owner's GitHub account.
  // Anything unread or otherwise holds for a moderator, as before.
  if (actor?.privileged === true && FIRST_BINDING_SELF_BASES.includes(actor.basis) && ownFile(ownerFile, ids)) return { by: actor.basis };
  for (const [fp, alert] of alerts ?? []) {
    // The approved release itself is not covered by its own approval: it
    // publishes through that approval, with its moderator on the record.
    if (fp === fingerprint) continue;
    if (alert?.event !== "approval" || alert.token_hash !== lineHash || !isStr(alert.held_decision_id)) continue;
    if (denied?.has(fp)) continue;
    // MIG-10: "a rejected, stopped, refused or pending hold exempts nothing".
    // An approved release later rejected (`M_REJECT`, a `refused` record),
    // refused by the bot, or stopped by its author covers no later tag.
    if (records.some((r) => r?.fingerprint === fp && (r.state === "stopped" || r.state === "refused"))) continue;
    const held = records.find((r) => r?.decision_id === alert.held_decision_id && r?.state === "held");
    if (!held || held.fingerprint !== fp || !(held.reasons ?? []).includes("R_FIRST_BINDING")) continue;
    if (held.plugin_id !== pluginId || held.repository_id !== ids.repository_id || held.repository_owner_id !== ids.repository_owner_id) continue;
    // The same rule for the SUBMISSION, not only the fingerprint (re-review of
    // #480): a stop or an `M_REJECT` record names one fingerprint of its
    // submission (`terminalSubmissionRecord` records the first, and a stop
    // may carry none), so re-uploading assets under the same tag leaves the
    // approved fingerprint unnamed. A `stopped` record, or a `refused` one
    // carrying `M_REJECT`, of the held record's submission — or, as
    // `terminalOnMain` matches, a stop of the same tag of the same repository
    // id — ends the cover.
    const sameRelease = (r) => (isStr(held.submission_id) && r?.submission_id === held.submission_id)
      || (isStr(held.tag) && r?.tag === held.tag && r?.repository_id === held.repository_id);
    if (records.some((r) => sameRelease(r) && (r.state === "stopped" || (r.state === "refused" && (r.reasons ?? []).includes("M_REJECT"))))) continue;
    if (!isTime(alert.delivered_at)) continue;
    const okd = oks?.get(fp) && okAnswers({ ok: oks.get(fp), record: alert, fingerprint: fp, digest: alert.digest, heldDecisionId: alert.held_decision_id });
    const windowEndsAt = okd ? alert.delivered_at : iso(new Date(new Date(alert.delivered_at).getTime() + OPERATOR_WINDOW_HOURS * HOUR_MS));
    return { by: "approved", alert, fingerprint: fp, windowEndsAt };
  }
  return null;
}

/**
 * The whole SHA-256 of the six facts a decision record on `main` carries
 * (`submissionDigest`), or null when they are not all there or do not hash to
 * the record's own 16-hex label — a record whose label is not its facts' is
 * not one this bot wrote, and nothing is bound to it. Every `held` record on
 * `main` carries all six (measured 2026-10-29: the 47 that do not are
 * `migration` records written before artifact digests were recorded, and none
 * is a hold), so the digest of the hold an approval clears is DERIVED, never
 * trusted from a member.
 */
export function recordDigest(record) {
  if (!record || typeof record !== "object") return null;
  const digests = Array.isArray(record.artifact_digests) ? [...record.artifact_digests].sort() : [];
  if (!digests.length || !digests.every((d) => DIGEST_RE.test(String(d)))) return null;
  if (![record.repo, record.tag, record.plugin_id, record.version].every(isStr)) return null;
  if (!SHA1_RE.test(String(record.commit ?? ""))) return null;
  const digest = submissionDigest({
    repo: record.repo, tag: record.tag, id: record.plugin_id, version: record.version, commit: record.commit, digests,
  });
  return digest.slice(0, 16) === record.fingerprint ? digest : null;
}

/**
 * The approval `ask` reported for this fingerprint, held to BOT-26's three
 * conditions and TRUST-27's wait. Returns what `decide()` should be given as
 * its approval, and why anything that arrived was not honoured.
 *
 * (1) a `main` record shows `held` for exactly this fingerprint; (2) the full
 * ingest recomputes the fingerprint — `decide()` asks that itself and answers
 * `P_APPROVAL_STALE`; (3) no `E_*` or `B_*` finding — `decide()`'s step 1
 * refuses before an approval is read. ROLL-49: no approval carries a delay
 * waiver. An approval does not age (contract 5.8.0): from 3.7.0 to 5.7.0 a
 * fourth condition refused one older than 7 days and re-held the submission
 * with `P_APPROVAL_STALE` in the hold's record, keyed `held:after:` (BOT-35).
 * Those records stay on `main` and are read like any other; none is written.
 *
 * **What a refusal leaves behind.** Every refusal below returns `why`, which
 * the caller adds to the run's reasons as `P_APPROVAL_STALE`. A `held` result
 * posts only its record's codes (BOT-23), so none of these reaches a record:
 * (1) has no hold of this fingerprint to return to, and TRUST-27's and
 * MIG-31's are waits the approval outlives.
 *
 * **MIG-31 (since contract 6.7.0) defers nothing here.** Until 6.7.0 a
 * grandfathered or frozen listing's first binding built by an account other
 * than the owner waited 14 days after its hold before an approval counted, and
 * that hit every organisation's repository, since the account that presses a
 * button is never the organisation. The floor is gone; `verify` CHECKS the
 * account instead (`compareActor`: owner, `admin`/`maintain`, or a public
 * member of the owning organisation), and where a moderator decides, the
 * decision takes effect when it is given.
 */
export function honourApproval({ decisions, fingerprint, heldRecord, heldCodes, now, digest = null, repositoryId = null }) {
  const approvals = (decisions ?? []).filter((d) => d?.code === "M_APPROVE");
  if (approvals.length === 0) return { approval: null, why: null, decision: null };
  // The newest, by the service's own time. Two approvals of one fingerprint
  // are the same answer given twice; the older is not a second permission.
  const decision = [...approvals].sort((a, b) => String(a.decided_at).localeCompare(String(b.decided_at))).at(-1);
  if (!isTime(decision.decided_at)) {
    return { approval: null, why: "BOT-26: the approval carries no §0.7 `decided_at`, so its age cannot be read", decision };
  }
  if (!heldRecord) {
    return {
      approval: null,
      why: "BOT-26 (1): no record on `main` shows `held` for this fingerprint, so there is no hold for this approval to clear",
      decision,
    };
  }
  // Contract 6.7.0: the hold is the one these bytes are, by the whole digest.
  // The 16-hex label is a name: an author who controls both sides of a
  // collision can give two releases one label, get the benign one approved
  // and re-tag the other, and a label match alone honoured that approval.
  const heldDigest = recordDigest(heldRecord);
  if (!heldDigest || !/^[0-9a-f]{64}$/.test(String(digest ?? ""))) {
    return {
      approval: null,
      why: "BOT-26 (1): the `held` record's whole SHA-256 cannot be derived from its six facts, or this run has none to " +
        "compare it with, and a 16-hex label alone never honours an approval",
      decision,
    };
  }
  if (heldDigest !== digest) {
    return {
      approval: null,
      why: `BOT-26 (2): the \`held\` record ${heldRecord.decision_id ?? ""} is for SHA-256 ${heldDigest} and this release is ` +
        `${digest}; they share the 64-bit label ${fingerprint} and nothing else, so the approval of one does not clear the other`,
      decision,
    };
  }
  if (isStr(heldRecord.repository_id) && isStr(repositoryId) && heldRecord.repository_id !== repositoryId) {
    return {
      approval: null,
      why: `BOT-26 (1): the \`held\` record names repository ${heldRecord.repository_id} and this release comes from ${repositoryId}`,
      decision,
    };
  }
  // No age check (contract 5.8.0 removed BOT-26 (4)): an approval clears the
  // hold it names whatever its `decided_at`, and (2) voids it the moment the
  // release changes. No MIG-31 floor either (contract 6.7.0): an approval of
  // a first binding takes effect when it is given, whoever ran the build —
  // the moderator's decision on the site IS the check the floor stood for.
  if ((heldCodes ?? []).includes("R_FIRST_BINDING")) {
    const since = new Date(now).getTime() - new Date(heldRecord.decided_at).getTime();
    if (since < FIRST_BINDING_WAIT_DAYS * DAY_MS) {
      return {
        approval: null,
        why:
          `TRUST-27: an \`R_FIRST_BINDING\` approval is honoured ${FIRST_BINDING_WAIT_DAYS} days after its \`held\` ` +
          `record reached main (${heldRecord.decided_at}), not before`,
        decision,
        earliest: plusMs(heldRecord.decided_at, FIRST_BINDING_WAIT_DAYS * DAY_MS),
        cause:
          `TRUST-27: the approval stands and takes effect at ${plusMs(heldRecord.decided_at, FIRST_BINDING_WAIT_DAYS * DAY_MS)}. ` +
          `An \`R_FIRST_BINDING\` approval is honoured ${FIRST_BINDING_WAIT_DAYS} days after its hold reached main ` +
          `(${heldRecord.decided_at}). The release publishes then, unless something about it changes.`,
      };
    }
  }
  return {
    approval: {
      by: String(decision.moderator ?? "moderator"),
      at: decision.decided_at,
      for: fingerprint,
      publishNow: false,
    },
    why: null,
    decision,
    // What TRUST-14's alert and an operator OK bind (6.7.0).
    digest,
    held_decision_id: heldRecord.decision_id ?? null,
  };
}

// ── BOT-28 / ID-60: the notice ──────────────────────────────────────────────

/**
 * BOT-28 since contract 5.8.0 (DEC-8; OD-28): does this approved hold wait
 * for no notice? Only when BOTH hold:
 *
 *   - neither the held record's codes nor this run's include
 *     `R_BINDING_CHANGED` — the approval clears the hold a moderator saw, the
 *     run publishes what it reads now, and either one naming a changed
 *     binding means a second account is in play (ID-60's wait);
 *   - this run's binding outcome is `one`: exactly one ID-23 line at the
 *     attested commit, which ID-24 did not refuse. With no line BOT-29's wait
 *     stands; only `one` gives FLOW-69 a single account to name.
 *
 * Then the notices go to one account, the one that made the release, and a
 * notice telling it of its own release protects nobody: Voltur792/SPT
 * v1.2.1 waited 46 hours on 92 `pending` answers for an account with no
 * notice destination. What that notice would have caught — a stolen account
 * with push access — the approving moderator and the operator window still
 * catch. Such a hold reads stop status alone, which step 6 already did.
 *
 * `ask` (bot/lib/service-jobs.mjs) asks the same question before it calls
 * notice status, from the tree's held record and the identity record's
 * token hash, so an exempt hold is not asked at all and a failed notice read
 * cannot hold it.
 */
/**
 * The held reasons BOT-28's exemption reads for a fingerprint: the UNION of
 * the codes of every `held` record of it on the tree, in a fixed order. One
 * rule, read by `decide` here and by `ask` (bot/lib/service-jobs.mjs's
 * `heldReasonsOnTree`) before it calls notice status. Until 2026-10-17 the
 * two picked different records — `ask` whichever one `readdir` returned
 * last, `decide` this submission's first hold — so with a historical
 * `held:after:` re-hold beside a first hold the two could disagree about
 * `R_BINDING_CHANGED`, and `ask` would skip a notice `decide` then waited
 * for. A union errs toward the wait: any hold of these bytes that named a
 * changed binding keeps ID-60's.
 */
export function heldReasonsFor(records, fingerprint) {
  const out = new Set();
  for (const r of records ?? []) {
    if (r?.state !== "held" || r?.fingerprint !== fingerprint) continue;
    for (const c of Array.isArray(r.reasons) ? r.reasons : []) if (typeof c === "string") out.add(c);
  }
  return [...out].sort();
}

export function noticeExempt({ heldReasons = [], runReasons = [], bindingOutcome }) {
  if (bindingOutcome !== "one") return false;
  return ![...(heldReasons ?? []), ...(runReasons ?? [])].includes("R_BINDING_CHANGED");
}

/**
 * Has the author objection window passed, by the notice status read in this
 * run? The bot compares; the service only reports when the notice was
 * accepted (BOT-28's Why).
 *
 * @returns {{ok: boolean, why: string, earliest: string|null}}
 */
export function noticeElapsed({ notice, windowSeconds, bindingChanged, now }) {
  if (!notice || !isStr(notice.status)) {
    return { ok: false, why: "no notice status was read in this run, and no answer means wait (DEC-11)", earliest: null };
  }
  const status = notice.status;
  // BOT-29: `none_unbound` is `pending`; POLICY.md commits no exception (OPEN-OWNER-2).
  if (status === "pending" || status === "none_unbound") {
    return { ok: false, why: `the notice status is \`${status}\` (BOT-28; BOT-29)`, earliest: null };
  }
  let from = null;
  if (status === "previous_ended") from = notice.ended_at;
  else if (status === "sent" || status === "previous_sent") from = notice.accepted_at;
  if (bindingChanged && status === "sent") {
    return {
      ok: false,
      why: "ID-60: an `R_BINDING_CHANGED` fingerprint publishes only on `previous_sent` or `previous_ended`; an incoming-account notice never counts",
      earliest: null,
    };
  }
  if (!isTime(from)) {
    return { ok: false, why: `the \`${status}\` answer carries no §0.7 time to count the window from`, earliest: null };
  }
  const due = new Date(from).getTime() + windowSeconds * 1000;
  if (due > new Date(now).getTime()) {
    return {
      ok: false,
      why: `the notice was ${status === "previous_ended" ? "ended" : "accepted"} at ${from}, less than the ${windowSeconds} s window before this read`,
      earliest: iso(new Date(due)),
    };
  }
  return { ok: true, why: `the notice window of ${windowSeconds} s has passed since ${from}`, earliest: null };
}

// ── TRUST-14 / TRUST-32: the alert and its window ───────────────────────────

/**
 * Has the operator had the window to object? One alert record per
 * fingerprint, carrying the event it was raised for (TRUST-14).
 *
 * @returns {{ok: boolean, name: object|null, wait: object|null}}
 */
export function operatorWindow({
  record, fingerprint, event, approvalDecidedAt, now, ok = null, hintFrom = now, digest = null, heldDecisionId = null, tokenHash = null,
}) {
  // Contract 6.7.0: an alert record from 6.7.0 on binds the whole digest, and
  // one that names another digest under the same 16-hex label is an alert
  // about other bytes — this release's alert has not gone out. A record from
  // before carries none; it is read for the release whose approval
  // `honourApproval` has already bound by the whole digest to its held record,
  // which is the only way this function is reached, and its
  // `approval_decided_at` ties it to that approval.
  const otherBytes = record && "digest" in record && (record.digest !== digest || record.held_decision_id !== heldDecisionId);
  if (!record || otherBytes || record.event !== event || (event === "approval" && record.approval_decided_at !== approvalDecidedAt)) {
    // First read of this event: TRUST-14 names it, and this run cannot publish
    // it — the window is counted from a delivery that has not happened yet.
    return {
      ok: false,
      name: {
        fingerprint, event, approval_decided_at: event === "approval" ? approvalDecidedAt : null,
        digest, held_decision_id: heldDecisionId,
        // 6.7.0 (MIG-10): the binding the approval covers, for later tags.
        ...(tokenHash ? { token_hash: tokenHash } : {}),
      },
      wait: null,
    };
  }
  if (!isTime(record.delivered_at)) {
    return {
      ok: false,
      name: null,
      wait: { code: "W_ALERT_UNDELIVERED", cause: "TRUST-32: the alert record carries no reported delivery", earliest: null },
    };
  }
  // Since contract 5.8.0 an operator OK ends the window — this one and nothing
  // else: it is read only here, after the delivery check above, so it never
  // ends `W_ALERT_UNDELIVERED`, and the deny record, the stop and every other
  // wait are decided elsewhere and before.
  if (okAnswers({ ok, record, fingerprint, digest, heldDecisionId })) return { ok: true, name: null, wait: null, okd: true };
  const due = new Date(record.delivered_at).getTime() + OPERATOR_WINDOW_HOURS * HOUR_MS;
  if (due > new Date(now).getTime()) {
    return {
      ok: false,
      name: null,
      wait: {
        code: "W_OPERATOR_WINDOW",
        cause: `TRUST-32: the alert was delivered at ${record.delivered_at}; the ${OPERATOR_WINDOW_HOURS}-hour operator objection window is still running, unless an operator answers it with an OK`,
        earliest: operatorRetryHint({ windowEndsAt: iso(new Date(due)), from: hintFrom }),
        window_ends_at: iso(new Date(due)),
      },
    };
  }
  return { ok: true, name: null, wait: null };
}

/**
 * Does this OK record end the window of this alert record? Its `fingerprint`
 * names the fingerprint (`readGitState` has already held the file name to the
 * same), and its `approval_decided_at` is the alert's: an OK given for an
 * earlier approval of the same fingerprint answers an alert that is no longer
 * the one on `main`.
 */
export function okAnswers({ ok, record, fingerprint, digest = null, heldDecisionId = null }) {
  if (!ok || !record) return false;
  if (okRecordProblems(ok, { fingerprint }).length) return false;
  // 6.7.0: the OK, the alert it answers and this release are one digest and
  // one held record; a label in common is not enough to shorten a window.
  if (ok.digest !== digest || ok.held_decision_id !== heldDecisionId) return false;
  if ("digest" in record && (record.digest !== ok.digest || record.held_decision_id !== ok.held_decision_id)) return false;
  return isTime(record.approval_decided_at) && ok.approval_decided_at === record.approval_decided_at;
}

/** TRUST-32's retry hint: 15 minutes after `from`, or the window's end if that is sooner. */
export function operatorRetryHint({ windowEndsAt, from }) {
  const hint = new Date(from).getTime() + OPERATOR_RETRY_HINT_MINUTES * 60_000;
  return iso(new Date(Math.min(hint, new Date(windowEndsAt).getTime())));
}

// ── the input grammar ───────────────────────────────────────────────────────

/** The `verified` entry for one submission, refused rather than trusted when it is not what `verify` writes. */
export function verifiedProblems(v) {
  const p = [];
  if (!v || typeof v !== "object") return ["no verified entry"];
  if (!["ok", "wait", "alert", "refuse"].includes(v.outcome)) p.push(`outcome ${JSON.stringify(v.outcome)}`);
  if (v.outcome === "refuse" && !/^[A-Z]_[A-Z0-9_]{1,62}$/.test(String(v.code ?? ""))) p.push("a refusal names no code");
  if (v.outcome !== "ok") return p;
  if (!ID_RE.test(String(v.plugin_id))) p.push("plugin_id");
  if (!SEMVER_RE.test(String(v.version))) p.push("version");
  if (!safeTag(v.tag)) p.push("tag");
  if (!SHA1_RE.test(String(v.commit))) p.push("commit");
  if (!FINGERPRINT_RE.test(String(v.fingerprint))) p.push("fingerprint");
  if (!safeRepo(v.repo)) p.push("repo");
  if (!BASE10_RE.test(String(v.repository_id))) p.push("repository_id");
  if (!BASE10_RE.test(String(v.repository_owner_id))) p.push("repository_owner_id");
  if (!Array.isArray(v.artifact_digests) || !v.artifact_digests.length || !v.artifact_digests.every((d) => DIGEST_RE.test(d))) {
    p.push("artifact_digests");
  }
  if (!Array.isArray(v.assets) || !v.assets.length) p.push("assets");
  if (!v.binding || !["none", "one", "malformed", "wait"].includes(v.binding.outcome)) p.push("binding");
  return p;
}

/** The check job's facts file for one submission: codes and levels, nothing else (BOT-55). */
export function factsProblems(f, { submissionId }) {
  const p = [];
  if (!f || typeof f !== "object" || Array.isArray(f)) return ["the facts file is not an object"];
  const allowed = new Set(["schema", "submission_id", "plugin_id", "version", "platforms", "findings"]);
  for (const k of Object.keys(f)) if (!allowed.has(k)) p.push(`an unnamed member \`${k}\``);
  if (f.schema !== CHECK_FACTS_SCHEMA) p.push(`schema ${JSON.stringify(f.schema)}`);
  if (f.submission_id !== submissionId) p.push("submission_id is not this lease's");
  if (!ID_RE.test(String(f.plugin_id))) p.push("plugin_id");
  if (!SEMVER_RE.test(String(f.version))) p.push("version");
  if (!Array.isArray(f.platforms)) p.push("platforms");
  if (!Array.isArray(f.findings)) p.push("findings");
  else {
    for (const x of f.findings) {
      if (!x || typeof x !== "object" || Object.keys(x).some((k) => k !== "code" && k !== "level")) {
        p.push("a finding carries a member other than `code` and `level`");
        break;
      }
      if (!/^[A-Z]_[A-Z0-9_]{1,62}$/.test(String(x.code)) || !["error", "review", "warn", "note", "pass", "skip"].includes(x.level)) {
        p.push(`a finding ${JSON.stringify(x)} is not a code and a level`);
        break;
      }
    }
  }
  return p;
}

/** The check job's facts file schema string, defined once, beside its writer. */
export { CHECK_FACTS_SCHEMA };

// ── the decision ────────────────────────────────────────────────────────────

/**
 * Decide one claimed submission.
 *
 * @param {object} input
 * @param {object} input.lease            a lease `claim` validated
 * @param {boolean} input.shadow          the claim answer's `shadow`
 * @param {object} input.verified         `verify`'s entry for this submission
 * @param {object|null} input.facts       `check`'s facts file
 * @param {{plugin: object, version: object}|null} input.listing  `check`'s listing
 * @param {object|null} input.ask         `ask`'s entry for this submission
 * @param {object} input.git              from `readGitState`, plus the per-listing reads
 * @param {string} input.now              §0.7 time of this read
 * @param {string} input.startedAt        the decide step's recorded start (B-T3.5)
 * @param {string} input.readCommit       the `main` commit this run read
 */
export function decideSubmission(input) {
  const { lease, verified } = input;
  const now = input.now;
  const startedAt = input.startedAt ?? now;
  const sid = lease.submission_id;
  const shadowed = input.shadow === true || input.ask?.shadow === true || input.ask?.verdict === "shadow";

  const plan = (kind, fields) => finishPlan({
    submission_id: sid,
    attempt: lease.attempt ?? null,
    kind,
    ...fields,
  }, { shadowed, startedAt });

  const nextRun = () => plusMs(startedAt, NEXT_RUN_SECONDS * 1000);
  const waitPlan = (code, cause, { earliest = null, reasons = [], derived = null, operatorAlert = null, windowEndsAt = null } = {}) =>
    plan("wait", {
      wait: {
        code, started_at: startedAt, cause: clip(cause), earliest_retry_at: boundedEarliest(startedAt, earliest ?? nextRun()),
        // §4.4 since contract 5.8.0: the operator window's end, on every
        // `W_OPERATOR_WINDOW` wait and on no other code.
        ...(code === "W_OPERATOR_WINDOW" && windowEndsAt ? { window_ends_at: windowEndsAt } : {}),
      },
      reasons,
      derived,
      operator_alert: operatorAlert,
    });

  // 1 ── what `verify` could not establish ─────────────────────────────────
  const vp = verifiedProblems(verified);
  if (vp.length) {
    return plan("none", {
      why: `the verify job's entry for ${sid} is not one it writes (${vp.join(", ")}); nothing is written or posted`,
      operator_alert: { code: "BOT21_VERIFY_UNREADABLE", reason: vp.join(", ") },
    });
  }
  if (verified.outcome === "alert") {
    // BOT-21 / BOT-15: the download and the certificate disagree about where
    // the bytes came from. Nothing is written, no result is posted, and the
    // lease expires under BOT-15, which is how the service counts it.
    return plan("none", {
      why: `BOT-21: ${verified.code ?? "the verification"} — ${verified.reason ?? "the certificate and the download disagree"}`,
      operator_alert: { code: String(verified.code ?? "BOT21_MISMATCH"), reason: String(verified.reason ?? "") },
    });
  }
  if (verified.outcome === "wait") {
    return waitPlan(verified.code ?? "W_GITHUB_RATE_LIMITED", verified.reason ?? "a GitHub read did not happen");
  }
  if (verified.outcome === "refuse") {
    // No bundle verified, so no identity value was established and none is
    // written: the record carries the submission, the state and the codes,
    // and DEC-7's "absent where they do not apply" covers the rest. A `repo`
    // or `tag` here would be the lease's word, which BOT-21 never writes.
    const codes = [...new Set([
      verified.code,
      ...(verified.findings ?? []).filter((f) => f.level === "error").map((f) => f.code),
    ].filter((c) => /^[A-Z]_[A-Z0-9]+(?:_[A-Z0-9]+)*$/.test(String(c))))];
    // BOT-19 / BOT-23 before anything new is planned. A refusal before the
    // fingerprint is keyed by the submission and the state alone —
    // `submission:<id>::refused`, the key service-publish.mjs derives for a
    // record with no fingerprint (BOT-35) — so every later refusal of the same
    // submission derives the SAME id, whatever its reason. Submission ae402306
    // was refused `E_ATTESTATION_MISSING` (record 209913af on main); the
    // service did not settle it, the bot leased it three more times, and each
    // run refused `E_RELEASE_NOT_FOUND` (the release had since been deleted)
    // under that id. BOT-36 found the id on main and wrote nothing, and the
    // result named the old record with the new reason, which the service
    // settles as `record_mismatch`. The record on main is the decision; the
    // result reports it.
    const refusedId = decisionId(submissionKey({ submission_id: sid, fingerprint: null, state: "refused" }));
    const onMain = (input.git?.records ?? []).find((r) => r?.decision_id === refusedId && r?.state === "refused");
    if (onMain) {
      const mainCodes = Array.isArray(onMain.reasons) ? onMain.reasons : [];
      return plan("reported", {
        state: "refused",
        decision_id: refusedId,
        reasons: mainCodes.map((c) => reasonOf(c)),
        why:
          `BOT-19/BOT-23: main already carries this submission's refusal (${refusedId}, ${mainCodes.join(", ") || "no codes"}); ` +
          `a second reason under the same id is a record mismatch, so this run's ${codes.join(", ") || "refusal"} is not recorded`,
      });
    }
    const trigger = lease.claimed_from === "approved" ? "approval" : lease.claimed_from === "delayed" ? "drain" : lease.trigger;
    return plan("state", {
      state: "refused",
      reasons: codes.map((c) => reasonOf(c, {
        location: (verified.findings ?? []).find((f) => f.code === c)?.where ?? null,
        message: (verified.findings ?? []).find((f) => f.code === c)?.message ?? null,
      })),
      record: { submission_id: sid, actor: "bot", trigger, decided_at: startedAt, state: "refused", reasons: codes },
    });
  }

  // Every identity value from here on is `verified`'s and nothing else's.
  const derivedFacts = {
    plugin_id: verified.plugin_id,
    version: verified.version,
    tag: verified.tag,
    commit: verified.commit,
    artifact_digests: [...verified.artifact_digests].sort(),
    fingerprint: verified.fingerprint,
    repository_id: verified.repository_id,
    repository_owner_id: verified.repository_owner_id,
  };

  // The fingerprint `verify` reported is recomputed here from the facts it
  // reported, so a verify job that got one of the six wrong disagrees with
  // itself before anything is written under its name.
  const recomputed = submissionFingerprint({
    repo: verified.repo, tag: verified.tag, id: verified.plugin_id, version: verified.version,
    commit: verified.commit, digests: derivedFacts.artifact_digests,
  });
  // The whole SHA-256 the label is cut from: what an approval binds (6.7.0).
  const digest = submissionDigest({
    repo: verified.repo, tag: verified.tag, id: verified.plugin_id, version: verified.version,
    commit: verified.commit, digests: derivedFacts.artifact_digests,
  });
  if (recomputed !== verified.fingerprint) {
    return plan("none", {
      why: "the verified fingerprint is not the one its own facts hash to; nothing is written or posted",
      operator_alert: { code: "BOT15_FINGERPRINT_DISAGREES", reason: `${verified.fingerprint} vs ${recomputed}` },
    });
  }

  // 2 ── BOT-15: the check job against the verification ───────────────────
  const fp = input.facts ? factsProblems(input.facts, { submissionId: sid }) : ["no facts file"];
  const listingProblems = compareListing(input.listing, verified);
  const disagreements = [
    ...fp,
    ...(input.facts && !fp.length && (input.facts.plugin_id !== verified.plugin_id || input.facts.version !== verified.version)
      ? [`the facts file names ${input.facts.plugin_id} ${input.facts.version} and verify verified ${verified.plugin_id} ${verified.version}`]
      : []),
    ...listingProblems,
  ];
  if (disagreements.length) {
    return plan("none", {
      why: `BOT-15: the check job's output disagrees with the verification: ${disagreements.join("; ")}`,
      operator_alert: { code: "BOT15_FACTS_DISAGREE", reason: disagreements.join("; ") },
    });
  }

  const git = input.git;
  const records = git.records ?? [];
  const existing = git.existing ?? null;
  const identityRecord = existing?.identity ?? null;

  // 3 ── BOT-19: a terminal answer already on `main` ───────────────────────
  const terminal = terminalForSubmission({
    records, submissionId: sid, fingerprint: verified.fingerprint,
    repo: verified.repo, tag: verified.tag, repositoryId: verified.repository_id,
  });
  if (terminal) {
    return plan("reported", {
      state: terminal.state,
      decision_id: terminal.decision_id ?? null,
      reasons: (terminal.reasons ?? []).map((c) => reasonOf(c)),
      derived: derivedFacts,
      why: `BOT-19: main already carries a ${terminal.state} record for this work (${terminal.decision_id})`,
    });
  }

  // 4 ── BOT-74: this exact version is listed already with these digests ────
  const listedVersion = (existing?.versions ?? []).map((v) => v.doc).find((d) => d?.version === verified.version) ?? null;
  const listedRecord = listedVersion
    ? [...records].reverse().find((r) =>
      r?.plugin_id === verified.plugin_id && r?.version === verified.version && r?.state === "published") ?? null
    : null;
  const already = alreadyPublished({
    listed: listedVersion
      ? { version: listedVersion.version, artifact_digests: artifactDigests(listedVersion), decision_id: listedRecord?.decision_id ?? null }
      : null,
    digests: derivedFacts.artifact_digests,
  });
  if (already) {
    return plan("reported", {
      state: already.reported,
      decision_id: already.names,
      reasons: [reasonOf("P_PUBLISHED", { message: already.record.why })],
      derived: derivedFacts,
      why: already.record.why,
    });
  }

  // 5 ── the binding line, and what `ask` said about it ────────────────────
  const binding = verified.binding;
  if (binding.outcome === "wait") {
    return waitPlan("W_GITHUB_RATE_LIMITED", binding.reason ?? "the binding line could not be read", {
      derived: derivedFacts,
      operatorAlert: binding.alert ? { code: "ID22_COMMIT_NOT_IN_REPOSITORY", reason: String(binding.reason ?? "") } : null,
    });
  }
  const ask = input.ask ?? null;
  if (ask?.wait) {
    return waitPlan(ask.wait, ask.cause ?? "the plugins service could not be asked (ID-9)", { derived: derivedFacts });
  }
  const verdict = ask?.verdict ?? null;
  if (binding.outcome === "one" && verdict === null && !shadowed) {
    return waitPlan("W_SERVICE_UNREACHABLE", "FLOW-74: the attested commit carries a binding line and no verdict was read", { derived: derivedFacts });
  }
  if (verdict === "W_ELIGIBILITY_UNREADABLE") {
    return waitPlan("W_ELIGIBILITY_UNREADABLE", "the eligibility behind the binding line could not be read (ID-9; DEC-11)", { derived: derivedFacts });
  }

  // FLOW-67: a threadless submission from a repository no listing names, with
  // no usable line. Nothing is recorded; the result carries the read commit.
  const flow67 = noListingNoBinding({
    source: lease.trigger,
    listingNamesRepo: git.listingNamesRepo === true,
    binding: binding.outcome === "one" || binding.outcome === "malformed"
      ? { present: true, code: verdict === "B_BINDING_UNUSABLE" ? "B_BINDING_UNUSABLE" : null }
      : { present: false, code: null },
    readCommit: input.readCommit ?? null,
    repo: verified.repo,
    // T2 (2026-10-24 incident): the author's OWN tagged commit, never this
    // registry's `readCommit`, so the message below cannot read to a
    // stranger as a claim about their repository made from a commit of ours.
    authorCommit: verified.commit ?? null,
  });
  if (flow67) {
    return plan("norecord", {
      state: flow67.reported,
      read_commit: flow67.read_commit,
      // FLOW-78: the result that names no record carries a `B_*` reason. The
      // author-facing text is `record.message` (plain words, the author's own
      // commit); `record.why` stays this run's own diagnostic, carried only
      // in `why` below for the decide job's `plan.json` (an operator record,
      // never posted).
      reasons: [reasonOf(binding.outcome === "none" ? "B_UNBOUND" : "B_BINDING_UNUSABLE", { message: flow67.record.message })],
      derived: derivedFacts,
      why: flow67.record.why,
    });
  }

  // 6 ── the stop, and the approvals (DEC-6, SERVE-93) ─────────────────────
  const gates = ask?.gates ?? null;
  if (!gates && !shadowed) {
    return waitPlan("W_SERVICE_UNREACHABLE", "no stop status was read in this run, and no answer means wait (DEC-11)", { derived: derivedFacts });
  }
  if (gates?.stop_status === "unavailable") {
    // n13: a wait for THIS submission alone. The other items of the same
    // gates body are decided normally by their own plans.
    return waitPlan("W_SERVICE_UNREACHABLE", "the stop status of this submission is `unavailable` after a restore (SERVE-93)", { derived: derivedFacts });
  }
  if (gates?.stop_status === "stopped") {
    return plan("none", {
      why: "the author stopped this submission; the moderation run records the stop (BOT-30), and this run writes and posts nothing for it",
    });
  }

  // 7 ── the listing, with identity from the certificate (BOT-21) ──────────
  const derived = composeDerived(input.listing, verified);

  const findings = [
    ...(verified.findings ?? []).map((f) => ({ ...f, where: f.where ?? null, message: f.message ?? titleOf(f.code) })),
    ...(input.facts.findings ?? []).map((f) => ({ code: f.code, level: f.level, where: null, message: titleOf(f.code) })),
  ];

  // 8 ── B-T3.3a: identity and binding ─────────────────────────────────────
  const identity = { repo: verified.repo, repository_id: verified.repository_id, repository_owner_id: verified.repository_owner_id };
  const lineHash = binding.outcome === "one" ? binding.token_hash ?? null : null;
  const heldCodes = [];
  let recycled = null;
  let firstCleared = null;
  const listingState = git.listingState ?? null;

  if (binding.outcome === "malformed") {
    findings.push({ level: "error", code: "B_BINDING_MALFORMED", where: ".well-known/astra-plugin-owner", message: binding.reason ?? "the binding line is malformed" });
  }
  if (verdict === "B_BINDING_UNUSABLE") {
    findings.push({ level: "error", code: "B_BINDING_UNUSABLE", where: null, message: "the binding line cannot be used for this repository (ID-9)" });
  }

  if (identityRecord) {
    const t = id41({ identity, record: identityRecord, lineHash });
    for (const c of t.codes) {
      if (c === "B_REPOSITORY_RECYCLED") recycled = `ID-41 row 1: ${identity.repo} now attests repository ${identity.repository_id} (owner ${identity.repository_owner_id}); the identity record names ${identityRecord.repository_id} (owner ${identityRecord.repository_owner_id})`;
      else if (c === "B_OWNER_CHANGED") findings.push({ level: "error", code: c, where: null, message: `ID-41 row 3: the owner id moved from ${identityRecord.repository_owner_id} to ${identity.repository_owner_id} under the same token` });
      else heldCodes.push(c);
    }
    if (binding.outcome === "none") {
      findings.push({ level: "error", code: "B_UNBOUND", where: null, message: "ID-25: a listing with an identity record publishes only a release whose attested commit carries its binding line" });
    }
  } else if (existing) {
    const { baseline } = baselineFor({ records, pluginId: verified.plugin_id });
    const compared = compareWithBaseline({ identity: { ok: true, ...identity, missing: [] }, baseline });
    if (compared.code === "B_REPOSITORY_RECYCLED") recycled = compared.reason;
    else if (compared.code === "R_IDENTITY_CHANGED") heldCodes.push("R_IDENTITY_CHANGED");
    // TRUST-23's second half: the certificate's name against the listing's
    // `source.repo` on main, never against a lookup.
    const listedRepo = String(existing.doc?.source?.repo ?? "");
    if (listedRepo && listedRepo.toLowerCase() !== identity.repo.toLowerCase() && !heldCodes.includes("R_IDENTITY_CHANGED")) {
      heldCodes.push("R_IDENTITY_CHANGED");
    }
    // MIG-10; ID-41: never R_BINDING_CHANGED. Since 6.7.0 not for the
    // repository's own owner or admin with a live token, nor under a binding
    // a moderator already approved (`firstBindingCleared`).
    if (binding.outcome === "one") {
      firstCleared = firstBindingCleared({
        actor: verified.actor, verdict, lineHash, records, alerts: git.alerts, denied: git.denied, oks: git.oks,
        ids: identity, pluginId: verified.plugin_id, fingerprint: verified.fingerprint, ownerFile: verified.owner_file,
      });
      if (!firstCleared) heldCodes.push("R_FIRST_BINDING");
    }
    if (binding.outcome === "none" && listingState?.state === "frozen") {
      findings.push({ level: "error", code: "B_UNBOUND", where: null, message: "ID-25: a `frozen` listing publishes only a bound release" });
    }
  } else {
    // A first listing (ID-74: nothing held the id before this release). Not a
    // hold since contract 3.0.0 (DEC-19): `decide()` publishes it at once with
    // `P_REVIEW_PRIORITY`, reading "a first listing" off `existing` itself, so
    // nothing is pushed here. The binding rule below is unchanged.
    const serviceFirst = ["panel", "ci", "poll"].includes(lease.trigger) && git.markers?.r3_exit === true;
    const anyFirstAfterCutover = git.markers?.cutover === true;
    if (binding.outcome === "none" && (serviceFirst || anyFirstAfterCutover)) {
      findings.push({ level: "error", code: "B_UNBOUND", where: null, message: "ID-25: a first listing now needs a binding line at the attested commit" });
    }
  }

  for (const c of heldCodes) {
    findings.push({ level: "review", code: c, where: null, message: titleOf(c) });
  }

  // 9 ── B-T3.3b: the approval, before the policy is asked ─────────────────
  // The hold an approval clears, and the one TRUST-27's wait and MIG-31's
  // floor count from: this submission's FIRST entry into `held`, found by the
  // id BOT-35 derives for it. From contract 3.10.0 to 5.7.0 a hold an aged
  // approval sent back wrote a record of its own (BOT-34), keyed
  // `held:after:`, and those records stay on `main`: a fingerprint can have
  // several `held` records, and the newest may be such a re-hold. Counting
  // from it would restart a 14-day floor that had already run. Nothing writes
  // one since 5.8.0; this reads past them. A tree with no first-hold record
  // (a hold written before this submission had an id of its own, or a
  // test's) falls back to main's earlier reading.
  const firstHoldId = decisionId(submissionKey({ submission_id: sid, fingerprint: verified.fingerprint, state: "held" }));
  const heldRecord = records.find((r) => r?.decision_id === firstHoldId && r?.state === "held")
    ?? [...records].reverse().find((r) => r?.fingerprint === verified.fingerprint && r?.state === "held") ?? null;
  const honoured = honourApproval({
    decisions: gates?.decisions ?? [],
    fingerprint: verified.fingerprint,
    heldRecord,
    heldCodes: heldRecord?.reasons ?? heldCodes,
    now,
    digest,
    repositoryId: verified.repository_id,
  });

  const queued = git.queueEntry ?? null;
  const decision = decide({
    path: "service",
    findings,
    derived,
    existing,
    repo: verified.repo,
    tag: verified.tag,
    submitter: null,
    issue: null,
    track: git.track,
    queued: queued && queued.fingerprint && queued.fingerprint !== verified.fingerprint ? null : queued,
    approval: honoured.approval,
    identity: recycled ? { code: "B_REPOSITORY_RECYCLED", reason: recycled } : null,
    now: new Date(now),
    shadow: shadowed,
  });

  // `decide()` answers in the legacy vocabulary; the service path has no
  // `/publish` waiver and no approved-first-listing shortcut (ROLL-49;
  // B-T3.3b retires both — `P_DELAY_WAIVED_BY_COMMAND` and
  // `P_FIRST_LISTING_APPROVED` are `until R3` in the token file).
  const reasonCodes = decision.reasons.map((r) => r.code);
  if (reasonCodes.includes("P_DELAY_WAIVED_BY_COMMAND") || reasonCodes.includes("P_FIRST_LISTING_APPROVED")) {
    throw new Error(
      "decide() took a legacy shortcut on the service path (a /publish waiver or the approved-first-listing " +
      "shortcut); ROLL-49 and B-T3.3b retire both, so this is a defect in bot/lib/policy/decision.mjs's guard",
    );
  }

  // The reasons, as FLOW-11 wants them: every blocking or holding finding
  // with its own code — `decide()` summarises the checks as one `P_REFUSED`
  // and folds every hold it has no documented policy code for into
  // `R_CHECK_HELD`, which is right for the legacy comment and wrong for a
  // record: `R_FIRST_BINDING` read back as `R_CHECK_HELD` is a hold TRUST-27
  // cannot find — then the policy's own codes, minus that fold.
  const reasons = [];
  const seen = new Set();
  const push = (code, opts) => {
    const key = `${code}|${opts?.message ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    reasons.push(reasonOf(code, opts));
  };
  // What held is what `decide()` held, read off its reasons rather than off
  // the findings: since contract 3.0.0 a review-level finding holds on this
  // path only when it is one of DEC-19's three changes of hands, and
  // `decide()` is the one place that list is written. A finding it did not
  // hold — a first listing, a check's flag — reaches the result as the
  // `P_REVIEW_PRIORITY` hint, never as its own `R_*` (BOT-23: the result's
  // codes are the record's).
  const heldHere = new Set(decision.reasons.filter((r) => r.level === "review").map((r) => r.code));
  const holding = (f) => f.level === "review" && heldHere.has(f.code);
  const blocking = findings.filter((f) => f.level === "error" || holding(f));
  for (const f of blocking) push(f.code, { location: f.where ?? null, message: f.message });
  if (recycled) push("B_REPOSITORY_RECYCLED", { message: recycled });
  for (const r of decision.reasons) {
    if (r.code === "R_CHECK_HELD") continue;
    if (r.level === "pass" && !/^P_/.test(r.code)) continue;
    push(r.code, { message: r.message });
  }
  // A deferred approval (TRUST-27's wait, MIG-31's floor) is not stale: it
  // stands, and this run answers with `W_APPROVAL_DEFERRED` below.
  const deferred = Boolean(honoured.earliest);
  if (honoured.why && !deferred) push("P_APPROVAL_STALE", { message: honoured.why });

  // A FLOW-72 wait from the checks themselves.
  if (decision.wait) {
    return waitPlan(decision.wait.code, decision.wait.cause, { reasons, derived: derivedFacts });
  }

  /** The codes a record of this outcome carries (DEC-7: B.7 codes, at least one). */
  const codesOf = (outcome) => {
    const errors = [
      ...findings.filter((f) => f.level === "error").map((f) => f.code),
      ...(recycled ? ["B_REPOSITORY_RECYCLED"] : []),
    ];
    const holds = [
      ...findings.filter(holding).map((f) => f.code),
      ...decision.reasons.filter((r) => r.level === "review" && r.code !== "R_CHECK_HELD").map((r) => r.code),
      // From contract 3.7.0 to 5.7.0 an aged approval's hold carried
      // `P_APPROVAL_STALE` here beside the hold's codes (BOT-26 (4)). 5.8.0
      // removed the age limit, so nothing adds it to a hold any more; BOT-26
      // (2) still raises it from `decide()`.
    ];
    const pick = {
      refuse: errors.length ? errors : ["P_REFUSED"],
      review: holds.length ? holds : ["R_CHECK_HELD"],
      // DEC-19: `P_REVIEW_PRIORITY` is a `note`, and it is written beside
      // `P_PUBLISHED` in the record, so moderators can find these releases
      // from git as well as from the result.
      publish: decision.reasons
        .filter((r) => (r.level === "pass" && /^P_/.test(r.code)) || r.code === "P_REVIEW_PRIORITY")
        .map((r) => r.code),
    }[outcome] ?? [];
    const out = [...new Set(pick.filter((c) => /^[A-Z]_[A-Z0-9]+(?:_[A-Z0-9]+)*$/.test(c)))];
    return out.length ? out : [outcome === "publish" ? "P_PUBLISHED" : "P_REFUSED"];
  };

  const trigger = lease.claimed_from === "approved" ? "approval" : lease.claimed_from === "delayed" ? "drain" : lease.trigger;
  const baseRecord = {
    submission_id: sid,
    actor: "bot",
    trigger,
    plugin_id: verified.plugin_id,
    version: verified.version,
    repo: verified.repo,
    repository_id: verified.repository_id,
    repository_owner_id: verified.repository_owner_id,
    tag: verified.tag,
    commit: verified.commit,
    artifact_digests: derivedFacts.artifact_digests,
    fingerprint: verified.fingerprint,
  };
  if (decision.outcome === "refuse") {
    return plan("state", {
      state: "refused",
      reasons,
      derived: derivedFacts,
      record: { ...baseRecord, decided_at: startedAt, state: "refused", reasons: codesOf("refuse") },
      drop_queue: Boolean(queued),
    });
  }

  if (decision.outcome === "review" && deferred) {
    // MIG-31's "deferred, not lost", and TRUST-27's wait. The approval came
    // before this lease was claimed, so a `held` result here was a NEW
    // transition `approved → held` under BOT-17's act clause (3.9.0), which
    // took the approval back, and the bot never claims `held`; under 3.10.0
    // it named the first hold's record and was a suppressed repeat, which
    // BOT-15's brake counts toward a park. It is a wait instead: no record
    // and no commit (FLOW-72), the submission stays approved, and the earliest
    // retry is the moment the approval takes effect, which the panel shows.
    // The hold it would otherwise have been is the one this approval clears:
    // since contract 3.0.0 every service-path hold is a change of hands
    // (DEC-19), and an approval clears exactly those (DEC-6).
    return waitPlan("W_APPROVAL_DEFERRED", honoured.cause, { earliest: honoured.earliest, reasons, derived: derivedFacts });
  }

  if (decision.outcome === "review") {
    const heldBy = codesOf("review");
    const extras = {};
    if (heldBy.includes("R_BINDING_CHANGED")) {
      // ID-61: the service learns the window only from here.
      extras.objection_window = UPDATE_WINDOW_HOURS * 3600;
    }
    if (heldBy.includes("R_FIRST_BINDING") || heldBy.includes("R_BINDING_CHANGED")) {
      if (verified.owner_file?.commit) extras.owner_file_commit = verified.owner_file.commit;
      if (typeof verified.owner_file?.pull_request === "boolean") extras.owner_file_pull_request = verified.owner_file.pull_request;
    }
    if (heldBy.includes("R_FIRST_BINDING") && ["grandfathered", "frozen"].includes(listingState?.state)) {
      if (verified.actor?.triggering_actor_id) {
        extras.triggering_actor_id = verified.actor.triggering_actor_id;
        extras.triggering_actor_is_owner = verified.actor.triggering_actor_id === verified.repository_owner_id;
      }
    }
    return plan("state", {
      state: "held",
      reasons,
      derived: derivedFacts,
      record: { ...baseRecord, decided_at: startedAt, state: "held", reasons: heldBy },
      result_extra: extras,
      // A hold stops the queue clock for these bytes (bot/decide.mjs's rule).
      drop_queue: Boolean(queued),
    });
  }

  if (decision.outcome === "delay") {
    // DEC-19 (3.0.0): nothing on the service path is delayed, and `decide()`
    // returns before its delay rules there. A `delay` here is a defect in that
    // module, and a loud job failure is the right size for it: a queue entry
    // and a `delayed` record written by this path would be a promise to wait
    // that the contract no longer makes. B.3's `delayed` state stays in the
    // vocabulary (FLOW-76's canary lives in it); this path never enters it.
    throw new Error(
      "decide() answered `delay` on the service path; since contract 3.0.0 (DEC-19) nothing there is delayed, " +
      "so this is a defect in bot/lib/policy/decision.mjs's service-path branch",
    );
  }

  // decision.outcome === "publish": B-T3.3b's gates, in order.
  //
  // Approved means an approval cleared a hold THIS run raised, which since
  // contract 3.0.0 is a change of hands (DEC-6; DEC-19). An approval that
  // arrives for a release nothing holds any more — a first listing held under
  // 2.22.0 and approved after 3.0.0 landed — clears nothing, and the release
  // publishes at once like any other: no window stands between the checks and
  // a release nothing holds.
  const approved = Boolean(honoured.approval) && decision.reasons.some((r) => r.code === "P_APPROVED");

  // TRUST-33 — an operator deny record withholds, whatever else is true.
  if (git.denied?.has(verified.fingerprint)) {
    return plan("state", {
      state: "refused",
      reasons: [reasonOf("P_OPERATOR_DENIED", { message: "an operator deny record on main names this fingerprint (TRUST-33)" })],
      derived: derivedFacts,
      record: { ...baseRecord, decided_at: startedAt, state: "refused", reasons: ["P_OPERATOR_DENIED"] },
      drop_queue: Boolean(queued),
    });
  }

  // MIG-10 since 6.7.0: a release under a binding a moderator approved waits
  // out that approval's operator window, so a deny of the approved release
  // within it is never outrun by this one.
  if (firstCleared?.by === "approved" && new Date(firstCleared.windowEndsAt).getTime() > new Date(now).getTime()) {
    return waitPlan("W_OPERATOR_WINDOW",
      `TRUST-32: this release's binding was approved with ${firstCleared.fingerprint}, whose operator window runs until ` +
      `${firstCleared.windowEndsAt}; it publishes then, unless an operator denies that release`, {
        earliest: operatorRetryHint({ windowEndsAt: firstCleared.windowEndsAt, from: startedAt }),
        windowEndsAt: firstCleared.windowEndsAt, reasons, derived: derivedFacts,
      });
  }

  // DEC-8 — never before the queue entry's `publish_after` on main.
  if (queued && isTime(queued.publish_after) && new Date(queued.publish_after).getTime() > new Date(now).getTime()) {
    return waitPlan("W_NOTICE_PENDING", `DEC-8: the queue entry on main says ${queued.publish_after}`, {
      earliest: queued.publish_after, reasons, derived: derivedFacts,
    });
  }

  if (approved) {
    // MIG-12 — evaluated before the notice read, and ignoring it.
    if (git.markers?.cutover === true && listingState?.state === "grandfathered" && binding.outcome === "none") {
      return waitPlan("W_NOTICE_PENDING", "MIG-12: a grandfathered listing publishes an approved release only once it is bound", {
        reasons, derived: derivedFacts,
      });
    }
    // BOT-28 / ID-60 — the author objection window, from the service's time:
    // for an approved change of hands, the POLICY.md number (DEC-19). Since
    // contract 5.8.0 a hold with one account in it waits for no notice: it
    // read stop status at step 6, and that is all it reads (`noticeExempt`).
    // The held records' codes (`heldReasonsFor`: every hold of these bytes,
    // the rule `ask` uses too) AND this run's are asked, and either naming
    // `R_BINDING_CHANGED` keeps ID-60's wait on the previous account's notice.
    const heldReasons = heldReasonsFor(records, verified.fingerprint);
    const exempt = noticeExempt({ heldReasons, runReasons: heldCodes, bindingOutcome: binding.outcome });
    if (!exempt) {
      const window = UPDATE_WINDOW_HOURS * 3600;
      const n = noticeElapsed({
        notice: ask?.notice ?? null,
        windowSeconds: window,
        bindingChanged: heldReasons.includes("R_BINDING_CHANGED") || heldCodes.includes("R_BINDING_CHANGED"),
        now,
      });
      if (!n.ok) {
        return waitPlan("W_NOTICE_PENDING", `BOT-28: ${n.why}`, { earliest: n.earliest, reasons, derived: derivedFacts });
      }
    }
    // TRUST-14 / TRUST-32 — the operator alert and its window (decision D2),
    // which an operator OK ends sooner (contract 5.8.0).
    const event = "approval";
    const w = operatorWindow({
      record: git.alerts?.get(verified.fingerprint) ?? null,
      fingerprint: verified.fingerprint,
      event,
      approvalDecidedAt: honoured.decision?.decided_at ?? null,
      now,
      ok: git.oks?.get(verified.fingerprint) ?? null,
      hintFrom: startedAt,
      digest,
      heldDecisionId: honoured.held_decision_id ?? null,
      tokenHash: lineHash,
    });
    if (w.name) {
      return plan("wait", {
        // The composer decides between the two waits: `W_OPERATOR_WINDOW` from
        // the delivery the alert job reports, `W_ALERT_UNDELIVERED` without one.
        wait: { code: "W_ALERT_UNDELIVERED", started_at: startedAt, cause: "TRUST-14: the operator alert goes out in this run", earliest_retry_at: nextRun() },
        alert: w.name,
        reasons,
        derived: derivedFacts,
      });
    }
    if (w.wait) {
      return waitPlan(w.wait.code, w.wait.cause, {
        earliest: w.wait.earliest, windowEndsAt: w.wait.window_ends_at ?? null, reasons, derived: derivedFacts,
      });
    }
  }

  // ID-40 and ID-64: a bound publication writes the identity record, and the
  // same commit rewrites every sibling listing naming the repository id —
  // unlisted ones and baseline-named ones included. Nothing is written under
  // `publishers/` (ID-52).
  let identityRecords = [];
  if (binding.outcome === "one" && lineHash) {
    const ids = [...new Set([verified.plugin_id, ...(git.siblings ?? [])])].sort();
    identityRecords = ids.map((pluginId) => ({
      plugin_id: pluginId,
      record: {
        schema: "astra.registry.identity/1",
        plugin_id: pluginId,
        repository_id: verified.repository_id,
        repository_owner_id: verified.repository_owner_id,
        repo: verified.repo,
        token_hash: lineHash,
      },
    }));
  }

  return plan("state", {
    state: "published",
    reasons,
    derived: derivedFacts,
    listing: derived,
    identity_records: identityRecords,
    record: {
      ...baseRecord,
      decided_at: startedAt,
      state: "published",
      reasons: codesOf("publish"),
      ...(approved ? approvalMembers(honoured.decision, honoured.approval) : {}),
    },
    drop_queue: Boolean(queued),
  });
}

/** DEC-7's approval members, from the service's decision, when an approval cleared the hold. */
function approvalMembers(decision, approval) {
  if (!decision || !approval) return {};
  const out = {};
  if (typeof decision.moderator === "string" && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(decision.moderator)) {
    out.moderator = decision.moderator;
  }
  if (typeof decision.category === "string") out.category = decision.category;
  if (typeof decision.declared_interest === "boolean") out.declared_interest = decision.declared_interest;
  return out;
}

/**
 * The check job's listing against the verification (BOT-15; B-T3.2's
 * "a facts file disagreeing with `verify` writes nothing").
 */
export function compareListing(listing, verified) {
  const p = [];
  if (!listing?.plugin || !listing?.version) return ["no listing"];
  if (listing.plugin.id !== verified.plugin_id) p.push(`the listing's plugin.json is ${listing.plugin.id}`);
  if (listing.version.id !== verified.plugin_id) p.push(`the listing's version file names ${listing.version.id}`);
  if (listing.version.version !== verified.version) p.push(`the listing's version is ${listing.version.version}`);
  const mine = Object.fromEntries((verified.assets ?? []).map((a) => [a.platform, a.sha256]));
  const theirs = listing.version.artifacts ?? {};
  const keys = new Set([...Object.keys(mine), ...Object.keys(theirs)]);
  for (const k of keys) {
    if (!mine[k]) p.push(`the listing carries a ${k} artifact nothing verified`);
    else if (!theirs[k]) p.push(`the listing omits the verified ${k} artifact`);
    else if (theirs[k].sha256 !== mine[k]) p.push(`the listing's ${k} digest is not the one verify computed`);
  }
  return p;
}

/**
 * The listing as it will be committed: the check job's card, with every
 * identity member overwritten from the verification (BOT-21).
 */
export function composeDerived(listing, verified) {
  const applied = applyIdentity(listing, { repo: verified.repo });
  if (!applied.ok) throw new Error(`BOT-21: ${applied.reason}`);
  const { plugin } = applied.derived;
  const version = structuredClone(applied.derived.version);
  version.id = verified.plugin_id;
  version.version = verified.version;
  version.release = {
    ...(version.release ?? {}),
    kind: "github_release",
    repo: verified.repo,
    tag: verified.tag,
    commit: verified.commit,
  };
  if (isTime(verified.published_at)) version.published_at = verified.published_at;
  // DEC-19 / B.4: the publishing commit writes `unreviewed`, whatever the
  // check job's listing said. That job opened a stranger's archive (BOT-21's
  // second bullet), so a listing arriving with `reviewed` — or with no member,
  // or with a value nobody defined — is overwritten here like every identity
  // member above, and never compared or carried. Only an applied `M_REVIEW`
  // moves it afterwards (MOD-56).
  version.review = "unreviewed";
  const artifacts = {};
  for (const a of verified.assets) {
    artifacts[a.platform] = {
      ...(version.artifacts?.[a.platform] ?? {}),
      url: a.url,
      filename: a.name,
      sha256: a.sha256,
      size: a.size,
    };
  }
  version.artifacts = artifacts;
  return { ...applied.derived, plugin, version };
}

/**
 * BOT-92, at the one exit every plan passes through. Deny-by-default: a
 * shadowed plan keeps only what the step summary needs to say what it WOULD
 * have done, and its kind becomes `none`.
 */
function finishPlan(p, { shadowed, startedAt }) {
  const out = {
    reasons: [],
    derived: null,
    record: null,
    queue_entry: null,
    listing: null,
    alert: null,
    drop_queue: false,
    operator_alert: null,
    result_extra: {},
    identity_records: [],
    ...p,
    decided_at: startedAt,
    shadow: shadowed,
  };
  if (!PLAN_KINDS.includes(out.kind)) throw new Error(`a plan of kind ${JSON.stringify(out.kind)} is not one of ${PLAN_KINDS.join(", ")}`);
  if (!shadowed) return out;
  const would = { kind: out.kind, state: out.state ?? null, wait: out.wait ?? null };
  return {
    submission_id: out.submission_id,
    attempt: out.attempt,
    kind: "none",
    shadow: true,
    would,
    // What the result would have been, so the caller can print its kind and
    // body hash and nothing else (B-T3.5). Never posted, never committed.
    shadow_result: out,
    reasons: [],
    derived: null,
    record: null,
    queue_entry: null,
    listing: null,
    alert: null,
    drop_queue: false,
    operator_alert: out.operator_alert,
    result_extra: {},
    identity_records: [],
    decided_at: startedAt,
    why: `BOT-92: a \`shadow: true\` answer named this work, so nothing is committed and no result is posted for it (it would have been ${out.kind}${out.state ? ` ${out.state}` : ""}${out.wait ? ` ${out.wait.code}` : ""})`,
  };
}

// ── the decide job ──────────────────────────────────────────────────────────

/**
 * Every listing naming this repository id, by identity record or by MIG-20's
 * baseline record (ID-64: "baseline-named ones included").
 */
export function siblingsOf(root, records, repositoryId) {
  const out = new Set();
  const base = path.join(root, "plugins");
  let names = [];
  try {
    names = fs.readdirSync(base, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    /* no listings */
  }
  for (const id of names) {
    try {
      const ident = JSON.parse(fs.readFileSync(path.join(base, id, "identity.json"), "utf8"));
      if (String(ident?.repository_id) === String(repositoryId)) out.add(id);
    } catch {
      /* no identity record */
    }
  }
  for (const r of records ?? []) {
    if (r?.trigger === "migration" && String(r.repository_id) === String(repositoryId) && ID_RE.test(String(r.plugin_id))) {
      out.add(r.plugin_id);
    }
  }
  return [...out].sort();
}

/** A listing out of one `listing-<submission_id>` artifact, as the decide job downloads it. */
export function readListingArtifact(dir, pluginId) {
  if (!ID_RE.test(String(pluginId))) return null;
  const pdir = path.join(dir, "plugins", pluginId);
  try {
    const plugin = JSON.parse(fs.readFileSync(path.join(pdir, "plugin.json"), "utf8"));
    const versions = fs.readdirSync(path.join(pdir, "versions")).filter((n) => n.endsWith(".json"));
    if (versions.length !== 1) return null;
    const version = JSON.parse(fs.readFileSync(path.join(pdir, "versions", versions[0]), "utf8"));
    return { plugin, version };
  } catch {
    return null;
  }
}

/**
 * The whole decide job: every claimed submission, from the job outputs and
 * the two artifacts each `check` leg uploaded, against the checked-out tree.
 *
 * @returns {{plans: object[], alerts: object, publish: boolean}}
 */
export function decideJob({ root, submissions, leases, claimShadow, verified, outcome, factsDir, listingsDir, now, startedAt, readCommit, deps = {} }) {
  const git = readGitState(root);
  const { plugins } = loadSources(root);
  const plans = [];
  for (const id of submissions) {
    const lease = leases?.[id];
    if (!lease) throw new Error(`claim reported ${id} and handed on no lease for it`);
    const v = verified?.[id] ?? null;
    const pluginId = v?.outcome === "ok" ? v.plugin_id : null;
    const facts = (() => {
      try {
        return JSON.parse(fs.readFileSync(path.join(factsDir, `facts-${id}`, "facts.json"), "utf8"));
      } catch {
        return null;
      }
    })();
    const listing = pluginId ? readListingArtifact(path.join(listingsDir, `listing-${id}`), pluginId) : null;
    const existing = pluginId ? readListingOnMain(root, pluginId) : null;
    // MIG-1's state, read from history as `listing-state.mjs` reads it. `now`
    // goes in as §0.7's string: the reader holds its tree to that grammar, and
    // until 2026-09-24 this call passed a `Date`, which it refused on every run.
    // A `catch` here turned that refusal into "no state", so the three rules
    // that read it — `B_UNBOUND` on a `frozen` listing (ID-25), MIG-12's wait
    // for a grandfathered listing after cutover, and MIG-31's report of the
    // triggering actor — never fired, and nothing said so. The `catch` claimed
    // a missing state "blocks nothing they would not also block with one",
    // which was false for the first two: both are refusals or waits that only
    // a state can trigger. So a tree the reader cannot answer from — shallow,
    // commit-less, or with a marker it refuses — now fails the job, the way
    // `readListingOnMain` fails it for an unreadable identity record: loudly,
    // with the lease left to expire under BOT-15, rather than deciding the
    // release as though the listing had no state at all.
    let listingState = null;
    if (existing) {
      try {
        listingState = (deps.listingStateAt ?? listingStateAt)(root, pluginId, { now: iso(now) });
      } catch (e) {
        throw new Error(
          `MIG-1's state of ${pluginId} cannot be read from this tree (${e.message}); deciding its release without ` +
          "one would skip B_UNBOUND on a frozen listing, MIG-12 and MIG-31's report, so this run decides nothing",
        );
      }
    }
    const perListing = {
      ...git,
      existing,
      queueEntry: pluginId ? readQueueOnMain(root, pluginId, v.version) : null,
      listingState,
      listingNamesRepo: v?.outcome === "ok"
        ? listingNamesRepository(root, { repo: v.repo, repositoryId: v.repository_id }) ||
          git.records.some((r) => r?.trigger === "migration" && String(r.repository_id) === String(v.repository_id))
        : false,
      siblings: v?.outcome === "ok" ? siblingsOf(root, git.records, v.repository_id) : [],
      track: v?.outcome === "ok" ? trackRecord(root, v.repo, { plugins }) : undefined,
    };
    plans.push(decideSubmission({
      lease,
      shadow: claimShadow,
      verified: v,
      facts,
      listing,
      ask: outcome?.[id] ?? null,
      git: perListing,
      now,
      startedAt,
      readCommit,
    }));
  }
  const trust14 = plans.filter((p) => !p.shadow && p.alert).map((p) => ({ ...p.alert }));
  const operator = plans.filter((p) => p.operator_alert).map((p) => ({ submission_id: p.submission_id, code: p.operator_alert.code }));
  const publish = plans.some((p) => !p.shadow && p.kind !== "none");
  return { plans, alerts: { trust14, operator }, publish };
}

async function cli(argv) {
  const args = { root: process.cwd(), facts: "facts", listings: "listings", out: "decisions" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--decide") continue;
    else if (a === "--registry-dir") args.root = path.resolve(argv[++i]);
    else if (a === "--facts") args.facts = path.resolve(argv[++i]);
    else if (a === "--listings") args.listings = path.resolve(argv[++i]);
    else if (a === "--out") args.out = path.resolve(argv[++i]);
    else throw new Error(`unknown argument: ${a}`);
  }
  const json = (name, fallback) => {
    const t = process.env[name];
    return t === undefined || t.trim() === "" ? fallback : JSON.parse(t);
  };
  const readCommit = execFileSync("git", ["-C", args.root, "rev-parse", "HEAD"], { encoding: "utf8", env: cleanEnv() }).trim();
  // B-T3.5: a wait's start is this step's recorded start, taken once.
  const startedAt = `${new Date().toISOString().slice(0, 19)}Z`;
  const result = decideJob({
    root: args.root,
    submissions: json("ASTRA_SUBMISSIONS", []),
    leases: json("ASTRA_LEASES", {}),
    claimShadow: String(process.env.ASTRA_CLAIM_SHADOW ?? "true") !== "false",
    verified: json("ASTRA_VERIFIED", {}),
    outcome: json("ASTRA_OUTCOME", {}),
    factsDir: args.facts,
    listingsDir: args.listings,
    now: startedAt,
    startedAt,
    readCommit,
  });
  fs.mkdirSync(args.out, { recursive: true });
  fs.writeFileSync(path.join(args.out, "plan.json"), `${JSON.stringify({ started_at: startedAt, read_commit: readCommit, plans: result.plans }, null, 2)}\n`);
  const { resultBody } = await import("./service-results.mjs");
  const { resultBytes } = await import("./service-jobs.mjs");
  const lines = [];
  for (const p of result.plans) {
    if (p.shadow) {
      const would = p.shadow_result && p.shadow_result.kind !== "none"
        ? resultBytes(resultBody(p.shadow_result, {})).hash
        : null;
      lines.push(`${p.submission_id}  shadow — would have been ${p.would.kind}${p.would.state ? ` ${p.would.state}` : ""}${p.would.wait ? ` ${p.would.wait.code}` : ""}${would ? `  sha256:${would}` : ""}`);
    } else {
      lines.push(`${p.submission_id}  ${p.kind}${p.state ? ` ${p.state}` : ""}${p.wait ? ` ${p.wait.code}` : ""}`);
    }
  }
  for (const l of lines) console.log(l);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}\n`);
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `alerts=${JSON.stringify(result.alerts)}\npublish=${result.publish}\n`);
  }
  return 0;
}

if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  cli(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`::error::${String(e?.stack ?? e)}`);
      process.exit(2);
    });
}
