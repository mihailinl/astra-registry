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
//   state     a record is committed (held, delayed, published, refused) and
//             the result names it;
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
import { artifactDigests, submissionFingerprint } from "./policy/release.mjs";
import { DELAY_HOURS } from "./policy/constants.mjs";
import { HOUR_MS, iso } from "./policy/time.mjs";
import { CODES } from "./codes.mjs";
import { POLICY_CODES } from "./policy/constants.mjs";
import { applyIdentity, compareWithBaseline, effectiveBaseline } from "./identity.mjs";
import { safeRepo, safeTag } from "./intake.mjs";
import { execFileSync } from "node:child_process";
import { trackRecord } from "./policy/track-record.mjs";
import { listingStateAt } from "./listing-state.mjs";
import { loadSources } from "../../tools/lib/sources.mjs";
import { cleanEnv } from "../../tools/lib/git-env.mjs";
import { isTime } from "../../tools/lib/time.mjs";
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

/** BOT-26 (4): an approval older than this is not honoured (OPEN-OWNER-5). */
export const APPROVAL_MAX_DAYS = 7;
/** BOT-28: the author objection window for an approved update with no delay reason (OPEN-OWNER-6). */
export const UPDATE_WINDOW_HOURS = 6;
/** TRUST-32 / DEC-6: the operator objection window, counted from reported delivery. */
export const OPERATOR_WINDOW_HOURS = 6;
/** TRUST-27: an `R_FIRST_BINDING` approval waits this long after its `held` record reached `main`. */
export const FIRST_BINDING_WAIT_DAYS = 7;
/** BOT-51's interval, for the earliest retry of a wait no record dates. */
export const NEXT_RUN_SECONDS = 600;
/** §4.4: `wait.cause` is at most this many characters. */
export const WAIT_CAUSE_MAX = 512;

const DAY_MS = 24 * HOUR_MS;

/** The five plan kinds, and only these. */
export const PLAN_KINDS = Object.freeze(["state", "wait", "reported", "norecord", "none"]);

/** §4.3: the states a lease may be claimed from (BOT-60). */
export const CLAIMED_FROM = Object.freeze(["received", "approved", "delayed"]);

/** BOT-89's four, and what `ask` may carry for a submission it did not ask about. */
export const VERDICT_OUTCOMES = Object.freeze(["pass", "B_BINDING_UNUSABLE", "W_ELIGIBILITY_UNREADABLE", "shadow"]);

/** TRUST-14's two events. */
export const ALERT_EVENTS = Object.freeze(["approval", "delay_elapsed"]);

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
 * FLOW-11's stage: the check's own for a check code (`bot/lib/codes.mjs`),
 * `policy` for every `R_*` and `P_*` (FLOW-11's words), and `binding` for the
 * bound world's `B_*`, whose FLOW-13 rows reg.61a has not written yet.
 */
export function stageOf(code) {
  if (Object.hasOwn(CODES, code)) return CODES[code].stage;
  if (/^[PR]_/.test(code)) return "policy";
  if (/^B_/.test(code)) return "binding";
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
  const markers = markersOverride ?? {
    r3_exit: fs.existsSync(path.join(root, "log", "rollout", "R3-exit.json")),
    cutover: fs.existsSync(path.join(root, "log", "cutover.json")),
    baseline: fs.existsSync(path.join(root, "log", "baseline.json")),
  };
  return { root, records: records.map((r) => r.doc).filter(Boolean), alerts, denied, markers };
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

/**
 * The approval `ask` reported for this fingerprint, held to BOT-26's four
 * conditions and TRUST-27's wait. Returns what `decide()` should be given as
 * its approval, and why anything that arrived was not honoured.
 *
 * (1) a `main` record shows `held` for exactly this fingerprint; (2) the full
 * ingest recomputes the fingerprint — `decide()` asks that itself and answers
 * `P_APPROVAL_STALE`; (3) no `E_*` or `B_*` finding — `decide()`'s step 1
 * refuses before an approval is read; (4) `decided_at` is younger than the
 * committed maximum. ROLL-49: no approval carries a delay waiver.
 */
export function honourApproval({ decisions, fingerprint, heldRecord, heldCodes, now }) {
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
  const age = new Date(now).getTime() - new Date(decision.decided_at).getTime();
  if (age > APPROVAL_MAX_DAYS * DAY_MS) {
    return {
      approval: null,
      why: `BOT-26 (4): the approval was decided at ${decision.decided_at}, more than ${APPROVAL_MAX_DAYS} days ago`,
      decision,
    };
  }
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
  };
}

// ── BOT-28 / ID-60: the notice ──────────────────────────────────────────────

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
export function operatorWindow({ record, fingerprint, event, approvalDecidedAt, now }) {
  if (!record || record.event !== event || (event === "approval" && record.approval_decided_at !== approvalDecidedAt)) {
    // First read of this event: TRUST-14 names it, and this run cannot publish
    // it — the window is counted from a delivery that has not happened yet.
    return {
      ok: false,
      name: { fingerprint, event, approval_decided_at: event === "approval" ? approvalDecidedAt : null },
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
  const due = new Date(record.delivered_at).getTime() + OPERATOR_WINDOW_HOURS * HOUR_MS;
  if (due > new Date(now).getTime()) {
    return {
      ok: false,
      name: null,
      wait: {
        code: "W_OPERATOR_WINDOW",
        cause: `TRUST-32: the alert was delivered at ${record.delivered_at}; the ${OPERATOR_WINDOW_HOURS}-hour operator objection window is still running`,
        earliest: iso(new Date(due)),
      },
    };
  }
  return { ok: true, name: null, wait: null };
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
  const waitPlan = (code, cause, { earliest = null, reasons = [], derived = null, operatorAlert = null } = {}) =>
    plan("wait", {
      wait: { code, started_at: startedAt, cause: clip(cause), earliest_retry_at: earliest ?? nextRun() },
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
  });
  if (flow67) {
    return plan("norecord", {
      state: flow67.reported,
      read_commit: flow67.read_commit,
      // FLOW-78: the result that names no record carries a `B_*` reason.
      reasons: [reasonOf(binding.outcome === "none" ? "B_UNBOUND" : "B_BINDING_UNUSABLE", { message: flow67.record.why })],
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
    if (binding.outcome === "one") heldCodes.push("R_FIRST_BINDING"); // MIG-10; ID-41: never R_BINDING_CHANGED
    if (binding.outcome === "none" && listingState?.state === "frozen") {
      findings.push({ level: "error", code: "B_UNBOUND", where: null, message: "ID-25: a `frozen` listing publishes only a bound release" });
    }
  } else {
    // A first listing (ID-74: nothing held the id before this release).
    heldCodes.push("R_FIRST_LISTING");
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
  const heldRecord = [...records].reverse().find((r) => r?.fingerprint === verified.fingerprint && r?.state === "held") ?? null;
  const honoured = honourApproval({
    decisions: gates?.decisions ?? [],
    fingerprint: verified.fingerprint,
    heldRecord,
    heldCodes: heldRecord?.reasons ?? heldCodes,
    now,
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
  const blocking = findings.filter((f) => f.level === "error" || f.level === "review");
  for (const f of blocking) push(f.code, { location: f.where ?? null, message: f.message });
  if (recycled) push("B_REPOSITORY_RECYCLED", { message: recycled });
  for (const r of decision.reasons) {
    if (r.code === "R_CHECK_HELD") continue;
    if (r.level === "pass" && !/^P_/.test(r.code)) continue;
    push(r.code, { message: r.message });
  }
  if (honoured.why) push("P_APPROVAL_STALE", { message: honoured.why });

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
      ...findings.filter((f) => f.level === "review").map((f) => f.code),
      ...decision.reasons.filter((r) => r.level === "review" && r.code !== "R_CHECK_HELD").map((r) => r.code),
    ];
    const pick = {
      refuse: errors.length ? errors : ["P_REFUSED"],
      review: holds.length ? holds : ["R_CHECK_HELD"],
      delay: decision.reasons.filter((r) => /^P_DELAY_/.test(r.code)).map((r) => r.code),
      publish: decision.reasons.filter((r) => r.level === "pass" && /^P_/.test(r.code)).map((r) => r.code),
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

  if (decision.outcome === "review") {
    const heldBy = codesOf("review");
    const extras = {};
    if (heldBy.includes("R_BINDING_CHANGED")) {
      // ID-61: the service learns the window only from here.
      extras.objection_window = windowSeconds({ queued, existing, reasons: decision.reasons, approved: false });
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
    const entry = decision.queue_entry;
    return plan("state", {
      state: "delayed",
      reasons,
      derived: derivedFacts,
      publish_after: decision.publish_after,
      record: {
        ...baseRecord,
        decided_at: startedAt,
        state: "delayed",
        reasons: codesOf("delay"),
        publish_after: decision.publish_after,
        ...approvalMembers(honoured.decision, honoured.approval),
      },
      queue_entry: {
        schema: "astra.registry.queue/1",
        submission_id: sid,
        // `decision_id` is stamped by the composer, which derives it once.
        publish_after: decision.publish_after,
        id: verified.plugin_id,
        version: verified.version,
        repo: verified.repo,
        tag: verified.tag,
        fingerprint: verified.fingerprint,
        queued_at: entry?.queued_at ?? startedAt,
        delay_hours: entry?.delay_hours ?? DELAY_HOURS,
        reason: entry?.reason ?? "",
        artifact_digests: derivedFacts.artifact_digests,
        approved_by: entry?.approved_by ?? null,
        approved_at: entry?.approved_at ?? null,
      },
    });
  }

  // decision.outcome === "publish": B-T3.3b's gates, in order.
  const approved = Boolean(honoured.approval);
  const drained = Boolean(queued) && lease.claimed_from === "delayed";

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

  // DEC-8 — never before the queue entry's `publish_after` on main.
  if (queued && isTime(queued.publish_after) && new Date(queued.publish_after).getTime() > new Date(now).getTime()) {
    return waitPlan("W_NOTICE_PENDING", `DEC-8: the queue entry on main says ${queued.publish_after}`, {
      earliest: queued.publish_after, reasons, derived: derivedFacts,
    });
  }

  if (approved || drained) {
    // MIG-12 — evaluated before the notice read, and ignoring it.
    if (git.markers?.cutover === true && listingState?.state === "grandfathered" && binding.outcome === "none") {
      return waitPlan("W_NOTICE_PENDING", "MIG-12: a grandfathered listing publishes a delayed or approved release only once it is bound", {
        reasons, derived: derivedFacts,
      });
    }
    // BOT-28 / ID-60 — the author objection window, from the service's time.
    const window = windowSeconds({ queued: drained ? queued : null, existing, reasons: decision.reasons, approved });
    const n = noticeElapsed({
      notice: ask?.notice ?? null,
      windowSeconds: window,
      bindingChanged: (heldRecord?.reasons ?? []).includes("R_BINDING_CHANGED"),
      now,
    });
    if (!n.ok) {
      return waitPlan("W_NOTICE_PENDING", `BOT-28: ${n.why}`, { earliest: n.earliest, reasons, derived: derivedFacts });
    }
    // TRUST-14 / TRUST-32 — the operator alert and its window.
    const event = approved ? "approval" : "delay_elapsed";
    const w = operatorWindow({
      record: git.alerts?.get(verified.fingerprint) ?? null,
      fingerprint: verified.fingerprint,
      event,
      approvalDecidedAt: honoured.decision?.decided_at ?? null,
      now,
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
      return waitPlan(w.wait.code, w.wait.cause, { earliest: w.wait.earliest, reasons, derived: derivedFacts });
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
      ...approvalMembers(honoured.decision, honoured.approval),
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
 * BOT-28's window: `delay_hours` for a delayed fingerprint, 0 for an approved
 * first listing with no delay reason, and the update window for an approved
 * update with no delay reason.
 */
function windowSeconds({ queued, existing, reasons, approved }) {
  if (queued && Number.isFinite(queued.delay_hours)) return Math.round(queued.delay_hours * 3600);
  const delayed = (reasons ?? []).some((r) => /^P_DELAY_(HIGH_RISK|WIDENED)$/.test(r.code));
  if (delayed) return DELAY_HOURS * 3600;
  if (approved && !existing) return 0;
  return UPDATE_WINDOW_HOURS * 3600;
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
    let listingState = null;
    if (existing) {
      try {
        listingState = (deps.listingStateAt ?? listingStateAt)(root, pluginId, { now: new Date(now) });
      } catch {
        // MIG-1 could not be decided from this tree; the rules that need it
        // (B_UNBOUND on a frozen listing, MIG-12) then see no state, which
        // blocks nothing they would not also block with one.
        listingState = null;
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
