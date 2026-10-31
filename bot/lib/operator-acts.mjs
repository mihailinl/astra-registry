// The operator's acts, applied to a tree: the code `tools/operator.mjs`
// (operator.yml, break-glass) and the moderation run (the owner's passkey acts,
// `bot/lib/operator-act.mjs` verifies them) share, so one act has one writer
// whichever door it came through (astra-plugins-ops
// `dev/operator-acts-by-passkey-design.md` §4.4).
//
// Moved here from `tools/operator.mjs` unchanged in what each act writes and
// refuses, with two differences of placement: nothing here regenerates the
// documents (the moderation run does once per commit; `tools/operator.mjs`
// does for its revert), and the passkey acts gain `applyOperatorAct`, which
// also writes the act record `state/acts/<jti>.json`, and `revoke_key`, which
// writes `state/passkeys/revoked/<kid>.json`.
//
// `operatorPath` is BOT-33's operator row: the paths operator.yml may write.
// A passkey act may also write its act record; nothing else widens.

import fs from "node:fs";
import path from "node:path";

import { ADVISORY_ID, SOURCE_DIR as REVOCATIONS_DIR } from "../../tools/lib/revocations.mjs";
import { ADVISORY_ID_GRAMMAR, ID_PATTERN } from "../../tools/lib/ids.mjs";
import { isTime } from "../../tools/lib/time.mjs";
import { HOLDS_DIR, RECORD_SCHEMA, checkHoldRecord, readHolds } from "./holds.mjs";
import {
  SOURCE_DIR as MODERATION_DIR,
  checkEntry,
  cutoverAt,
  fileNameFor,
  loadEntries,
  suffixOf,
} from "./moderation.mjs";
import { okAuthority } from "./operator-role.mjs";
import { OK_DIR, OK_SCHEMA, okRecordProblems } from "./service-decide.mjs";
import { ACTS_DIR, KID_RE, REVOKED_DIR, keyByKid, loadPin, revokedRecord } from "./operator-act.mjs";

/** `astra.registry.deny/1`, TRUST-33's record: exactly these members (B.4). */
export const DENY_SCHEMA = "astra.registry.deny/1";
export const DENY_DIR = "state/deny";
export const DENY_MEMBERS = Object.freeze(["schema", "fingerprint", "run", "at"]);

/** A submission fingerprint: 16 lowercase hex, as `schema/decision-v1.json` has it. */
export const FINGERPRINT_RE = /^[0-9a-f]{16}$/;

/** §0.7's service decision id: a lowercase UUID v4 or v7. */
export const SDI_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** The log actions MOD-52 can revert, and what each revert logs. */
export const REVERTIBLE = Object.freeze({ delist: "relist", deprecate: "unrevoke", revoke: "unrevoke" });

/**
 * The fixed public reason each revert logs. A reason is shown to the public for
 * ever (MOD-41), and the operator's workflow takes no free text: the act and
 * the id are the whole input, so there is nothing a mistyped or pasted
 * sentence could put into the log.
 */
export const REVERT_REASONS = Object.freeze({
  error: "Reverted by the registry operator: the decision this entry reverses was made in error.",
  path_test: "Reverted by the registry operator: the decision this entry reverses was a test of the withdrawal path.",
});

const HOLDS = HOLDS_DIR.split(path.sep).join("/");
const HOLD_RECORD_RE = new RegExp(`^${HOLDS}/[0-9a-f-]{36}\\.(confirm|cancel)\\.json$`);
const DENY_RE = new RegExp(`^${DENY_DIR}/[0-9a-f]{16}\\.json$`);
const OK_RE = new RegExp(`^${OK_DIR}/[0-9a-f]{16}\\.json$`);
// The id grammars are tools/lib/ids.mjs's and are never spelled here: the
// selftest's "only tools/lib/ids.mjs says what a plugin id is" refuses a copy.
const ID = ID_PATTERN.slice(1, -1);
const PLUGIN_RE = new RegExp(`^plugins/${ID}/plugin\\.json$`);
const LOG_RE = new RegExp(`^${MODERATION_DIR}/[0-9]{4}-[0-9]{2}-[0-9]{2}-${ID}-(relist|unrevoke)(-[0-9]+)?\\.json$`);
const ADVISORY_RE = new RegExp(`^${REVOCATIONS_DIR}/${ADVISORY_ID_GRAMMAR}\\.json$`);
const DOCUMENTS = new Set(["registry/v1/index.json", "registry/v1/revocations.json"]);
const REVOKED_RE = new RegExp(`^${REVOKED_DIR}/[a-z0-9-]{1,32}\\.json$`);
const ACT_RE = new RegExp(`^${ACTS_DIR}/[0-9a-f]{32}\\.json$`);

/** BOT-33's operator row: the only paths an operator act may write or delete. */
export function operatorPath(rel) {
  return HOLD_RECORD_RE.test(rel) || DENY_RE.test(rel) || OK_RE.test(rel) || PLUGIN_RE.test(rel) || LOG_RE.test(rel) ||
    ADVISORY_RE.test(rel) || DOCUMENTS.has(rel) || REVOKED_RE.test(rel);
}

/** A passkey act's paths: the operator row, and its own act record. */
export const passkeyActPath = (rel) => operatorPath(rel) || ACT_RE.test(rel);

export class Refusal extends Error {}
export const refuse = (why) => { throw new Refusal(why); };

export const wholeSeconds = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

function write(root, rel, doc, touched, allowed = operatorPath) {
  if (!allowed(rel)) throw new Error(`an operator act names ${rel}, which the operator's allowlist does not carry`);
  const full = path.join(root, ...rel.split("/"));
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, `${JSON.stringify(doc, null, 2)}\n`);
  touched.push(rel);
}

function remove(root, rel, touched) {
  if (!ADVISORY_RE.test(rel)) throw new Error(`an operator act may delete an advisory and nothing else; ${rel} is not one`);
  fs.rmSync(path.join(root, ...rel.split("/")));
  touched.push(rel);
}

// ── confirm and cancel ──────────────────────────────────────────────────────

export function answerHold(root, act, sdi, { at, run }) {
  const holds = readHolds(root);
  const hold = holds.find((h) => h.id === sdi);
  if (!hold) {
    refuse(`there is no hold ${HOLDS}/${sdi}.json on main, so there is nothing to ${act}. A confirmation names ` +
      "the entry it answers (BOT-70), and an answer to no entry would be a record of nothing");
  }
  if (hold.problems.length) refuse(`the hold ${hold.file} does not read cleanly: ${hold.problems.join("; ")}`);
  if (hold.confirm || hold.cancel) {
    refuse(`the hold ${sdi} already carries a${hold.confirm ? " confirm" : " cancel"} record, and a hold is answered once`);
  }
  if (act === "confirm" && hold.entry?.held_for === "unbound_yank") {
    refuse(`the hold ${sdi} is an unbound_yank, which no confirmation releases: FLOW-79 lets the service accept an ` +
      "A_YANK only from the bound account, so an unbound one means the service erred. It ends only on a cancel (M-T3.3)");
  }
  const record = {
    schema: RECORD_SCHEMA,
    act,
    service_decision_id: sdi,
    ...(typeof hold.entry?.decision?.plugin_id === "string" ? { plugin_id: hold.entry.decision.plugin_id } : {}),
    at,
    ...(run ? { run } : {}),
  };
  const problems = checkHoldRecord(record, { file: `${HOLDS}/${sdi}.${act}.json` });
  if (problems.length) throw new Error(`refusing to write a hold record the directory would refuse: ${problems.join("; ")}`);
  const touched = [];
  write(root, `${HOLDS}/${sdi}.${act}.json`, record, touched);
  // The id rides in the `Service-Decision:` trailer and nowhere else: PRIV-2's
  // scan exempts a UUID only there (tools/priv-scan.mjs), and until 2026-10-29
  // this subject carried it, which turned the coverage canary red (7f1e682).
  return { touched, subject: `operator: ${act} a moderation hold (MOD-52)`, service_decision: sdi };
}

// ── revert ──────────────────────────────────────────────────────────────────

export function revertDecision(root, sdi, { at }) {
  const { entries, files } = loadEntries({ root });
  const found = entries.map((e, i) => ({ e, file: files[i] })).filter(({ e }) => e.service_decision_id === sdi);
  if (found.length === 0) {
    refuse(`no entry in ${MODERATION_DIR}/ carries service_decision_id ${sdi}, so no applied decision names it. ` +
      "MOD-52 reverts an APPLIED M_DELIST, M_DEPRECATE or M_REVOKE, which always has its log entry");
  }
  if (found.length > 1) refuse(`${found.length} log entries carry service_decision_id ${sdi}; a revert of which one is a guess`);
  const { e: reverted } = found[0];
  const logs = REVERTIBLE[reverted.action];
  if (!logs) {
    refuse(`the decision ${sdi} was a ${reverted.action}, and MOD-52 reverts a delist, a deprecate or a revoke only. ` +
      "A yank is not reversible by anyone; an author's yank says so before it is made (FLOW-79)");
  }
  if (entries.some((e) => e.reverses === sdi)) refuse(`the decision ${sdi} is already reverted; a log entry reverses it`);

  const touched = [];
  const plugin = reverted.plugin;
  if (reverted.action === "delist") {
    const rel = `plugins/${plugin}/plugin.json`;
    const full = path.join(root, ...rel.split("/"));
    if (!fs.existsSync(full)) refuse(`${rel} is not on main, so there is no listing to relist`);
    const doc = readJson(full);
    if (doc.unlisted !== true) refuse(`${plugin} is not unlisted on main, so the delist is already undone by something else`);
    delete doc.unlisted;
    write(root, rel, doc, touched);
  } else {
    if (typeof reverted.advisory !== "string" || !ADVISORY_ID.test(reverted.advisory)) {
      refuse(`the ${reverted.action} ${sdi} names no advisory, so there is nothing to delete`);
    }
    const rel = `${REVOCATIONS_DIR}/${reverted.advisory}.json`;
    if (!fs.existsSync(path.join(root, ...rel.split("/")))) {
      refuse(`${rel} is not on main, so the advisory is already gone and there is nothing to unrevoke`);
    }
    remove(root, rel, touched);
  }

  const category = reverted.category === "path_test" ? "path_test" : "error";
  const entry = {
    date: at.slice(0, 10),
    action: logs,
    plugin,
    reason: REVERT_REASONS[category],
    category,
    reverses: sdi,
    ...(logs === "unrevoke" ? { advisory: reverted.advisory } : {}),
  };
  const problems = checkEntry(entry, "<revert>", { cutoverAt: cutoverAt(root) });
  if (problems.length) throw new Error(`refusing to write a log entry the log would refuse: ${problems.join("; ")}`);
  // MOD-47's `-<n>`, read off the names actually taken, as the compiler reads them.
  const taken = new Set();
  const all = loadEntries({ root });
  all.entries.forEach((e, i) => {
    if (e.date !== entry.date || e.plugin !== entry.plugin || e.action !== entry.action) return;
    const n = suffixOf(all.files[i], e);
    if (n !== null) taken.add(n);
  });
  let n = 1;
  while (taken.has(n)) n += 1;
  write(root, `${MODERATION_DIR}/${fileNameFor(entry, n)}`, entry, touched);

  // The documents are regenerated by the caller, once per commit
  // (`tools/operator.mjs`'s `operatorAct`; the moderation run's own pass).
  return { touched, subject: `operator: revert ${reverted.action} of ${plugin} (${logs}, MOD-52)`, service_decision: sdi };
}

// ── deny ────────────────────────────────────────────────────────────────────

export function denyFingerprint(root, fingerprint, { at, run }) {
  if (!FINGERPRINT_RE.test(String(fingerprint ?? ""))) {
    refuse(`${JSON.stringify(fingerprint)} is not a submission fingerprint (16 lowercase hex), so no release can be denied by it`);
  }
  const rel = `${DENY_DIR}/${fingerprint}.json`;
  if (fs.existsSync(path.join(root, ...rel.split("/")))) refuse(`${rel} is already on main; a deny is permanent and written once`);
  const record = { schema: DENY_SCHEMA, fingerprint, run: run ?? "", at };
  if (!record.run) refuse("a deny record carries the run that wrote it, and this run has no run URL");
  const touched = [];
  write(root, rel, record, touched);
  return { touched, subject: `operator: deny a release by its fingerprint (TRUST-33)`, service_decision: null };
}

// ── ok ──────────────────────────────────────────────────────────────────────
//
// TRUST-32 since contract 5.8.0: the owner's answer to an alert he has read.
// The record is tied to the alert it answers by copying that alert's
// `approval_decided_at`, so a new approval of the same fingerprint — a new
// alert — needs a new OK, and an OK given for the old one ends nothing
// (`okAnswers` in bot/lib/service-decide.mjs). It ends the operator window
// and nothing else: an alert never reported delivered is refused here, and a
// deny record, a stop, a notice and every other wait are decided before the
// window is ever read.

export function okFingerprint(root, fingerprint, { at, run, actorId }) {
  // The pin, again, inside the act: the workflow's own step refuses first,
  // and this makes the act refuse on its own wherever it is run from.
  const who = okAuthority({ actorId });
  if (!who.ok) refuse(who.why);
  if (!FINGERPRINT_RE.test(String(fingerprint ?? ""))) {
    refuse(`${JSON.stringify(fingerprint)} is not a submission fingerprint (16 lowercase hex), so no alert can be answered by it`);
  }
  const alertRel = `state/alerts/${fingerprint}.json`;
  const alertFile = path.join(root, ...alertRel.split("/"));
  if (!fs.existsSync(alertFile)) refuse(`${alertRel} is not on main: there is no operator alert for this fingerprint to answer`);
  let alert;
  try {
    alert = readJson(alertFile);
  } catch {
    refuse(`${alertRel} is not readable JSON, so the approval it names cannot be copied`);
  }
  if (alert?.fingerprint !== fingerprint) refuse(`${alertRel} names ${JSON.stringify(alert?.fingerprint ?? null)}, not this fingerprint`);
  if (alert.event !== "approval" || !isTime(alert.approval_decided_at)) {
    refuse(`${alertRel} is not an approval's alert with a §0.7 \`approval_decided_at\`, so an OK could not name what it answers`);
  }
  if (!isTime(alert.delivered_at)) {
    refuse(`${alertRel} has no reported delivery: an alert nobody received is answered by nobody, and the window it would open has not started (TRUST-32)`);
  }
  // Contract 6.7.0: an OK binds the whole digest and the held record the
  // approval cleared, copied from the alert. An alert from before 6.7.0 names
  // only the 16-hex label, which two releases can share; its window is not
  // shortened, and runs out by itself.
  if (!/^[0-9a-f]{64}$/.test(String(alert.digest ?? "")) || !/^[0-9a-f]{32}$/.test(String(alert.held_decision_id ?? ""))) {
    refuse(`${alertRel} names no whole digest and held record (it predates contract 6.7.0), so an OK could bind only a 64-bit label; its window runs out by itself`);
  }
  if (fs.existsSync(path.join(root, DENY_DIR, `${fingerprint}.json`))) {
    refuse(`${DENY_DIR}/${fingerprint}.json is on main: this fingerprint is denied for ever, and an OK never overrides a deny (TRUST-33)`);
  }
  const rel = `${OK_DIR}/${fingerprint}.json`;
  const full = path.join(root, ...rel.split("/"));
  if (fs.existsSync(full)) {
    let prior = null;
    try {
      prior = readJson(full);
    } catch {
      /* replaced below, as any record that is not one */
    }
    if (prior?.approval_decided_at === alert.approval_decided_at) {
      refuse(`${rel} already answers the alert for the approval of ${alert.approval_decided_at}; an OK is given once per alert`);
    }
  }
  if (!run) refuse("an OK record carries the run that wrote it, and this run has no run URL");
  const record = {
    schema: OK_SCHEMA, fingerprint, approval_decided_at: alert.approval_decided_at, run, at,
    digest: alert.digest, held_decision_id: alert.held_decision_id,
  };
  const problems = okRecordProblems(record, { fingerprint });
  if (problems.length) throw new Error(`the OK record this act composed is malformed: ${problems.join(", ")}`);
  const touched = [];
  write(root, rel, record, touched);
  return { touched, subject: "operator: OK an approved release's operator window by its fingerprint (TRUST-32)", service_decision: null };
}

// ── revoke a passkey ────────────────────────────────────────────────────────
//
// `state/passkeys/revoked/<kid>.json`: from that run on the bot accepts no act
// signed by the key, the ingest's owner approval included (design §2.3). The
// owner's own, by his passkey (`revoke_key`) or by operator.yml's
// `revoke-passkey` under his pinned numeric id. A key is never deleted from
// the pin, so its old act records keep verifying.

export function revokePasskey(root, kid, { at, run, pin = loadPin() }) {
  if (!KID_RE.test(String(kid ?? ""))) refuse(`${JSON.stringify(kid)} is not a passkey kid`);
  const key = keyByKid(pin, kid);
  if (!key) refuse(`${kid} is not a pinned key (bot/lib/operator-passkeys.json), so there is nothing to revoke`);
  const rel = `${REVOKED_DIR}/${kid}.json`;
  if (key.status === "revoked" || fs.existsSync(path.join(root, ...rel.split("/")))) refuse(`${kid} is already revoked`);
  if (!run) refuse("a revocation record carries the run that wrote it, and this run has no run URL");
  const touched = [];
  write(root, rel, revokedRecord({ kid, at, run }), touched);
  return { touched, subject: `operator: revoke the passkey ${kid}`, service_decision: null };
}

// ── a passkey act, applied ──────────────────────────────────────────────────

/**
 * Apply one passkey act `bot/lib/operator-act.mjs` has verified (`verdict:
 * "apply"`), on the tree at `root`, and write its act record. Never
 * regenerates documents; the moderation run does once for its commit.
 *
 *   approve      the act record only; the ingest honours it from git (§4.7)
 *   deny         `state/deny/<fp>.json`, unless one is already there (a deny
 *                is never answered: the second press records itself)
 *   confirm      `state/holds/<sdi>.confirm.json`, released in the same commit
 *   cancel       `state/holds/<sdi>.cancel.json`
 *   revert       what operator.yml's revert writes (MOD-52)
 *   revoke_key   `state/passkeys/revoked/<kid>.json`
 *
 * @returns {{paths: string[], trailers: string[][], serviceDecision: string|null}}
 */
export function applyOperatorAct({ root, act, target, at, run, jti, record, pin = loadPin() }) {
  let done;
  if (act === "approve") done = { touched: [], service_decision: null };
  else if (act === "deny") {
    const rel = `${DENY_DIR}/${target.fingerprint}.json`;
    done = fs.existsSync(path.join(root, ...rel.split("/")))
      ? { touched: [], service_decision: null }
      : denyFingerprint(root, target.fingerprint, { at, run });
  } else if (act === "confirm" || act === "cancel") done = answerHold(root, act, target.service_decision_id, { at, run });
  else if (act === "revert") done = revertDecision(root, target.service_decision_id, { at });
  else if (act === "revoke_key") done = revokePasskey(root, target.kid, { at, run, pin });
  else refuse(`${JSON.stringify(act)} is not a passkey act`);

  const paths = [...done.touched];
  if (record) {
    if (record.jti !== jti) throw new Error("the act record is not this act's");
    write(root, `${ACTS_DIR}/${jti}.json`, record, paths, passkeyActPath);
  }
  const trailers = [["Operator-Act", jti]];
  if (done.service_decision) trailers.push(["Service-Decision", done.service_decision]);
  return { paths, trailers, serviceDecision: done.service_decision ?? null };
}
