#!/usr/bin/env node
//
// The operator's five acts, as `.github/workflows/operator.yml` runs them
// (registry plan M-T3.5; contract MOD-52, TRUST-33, BOT-70; TRUST-32's `ok`
// since contract 5.8.0).
//
//   node tools/operator.mjs --job authority          the dispatcher may act (MOD-52)
//   node tools/operator.mjs --job ok-authority       an `ok` is the owner's (TRUST-32)
//   node tools/operator.mjs --job act --out operator write the act, list its paths
//   node tools/operator.mjs --job verdict --out f    the alert job's verdict
//
// ── WHERE THIS FILE LIVES, AND WHY NOT WHERE THE PLAN PUT IT ────────────────
//
// The plan names `bot/operator.mjs`. The tree says every top-level `bot/*.mjs`
// is one of TRUST-31's enumerated entry points (`bot/tests/code-paths.test.mjs`,
// "the two enumerated groups are exactly what is on the tree"), so a new one
// there is a contract MINOR before the file lands — and the plan itself says
// `operator.yml` "is not in TRUST-31's set": it is not a bot workflow, holds no
// bot token and mints none. `tools/` holds the desk and ceremony tools the set
// leaves outside for the same reason, so this is `tools/operator.mjs`, and the
// role check it runs is `bot/lib/operator-role.mjs`, beside the
// `collaboratorRole` it reads.
//
// ── WHAT EACH ACT WRITES, AND NOTHING ELSE ─────────────────────────────────
//
//   confirm   state/holds/<id>.confirm.json   releases a hold MOD-9 made (BOT-70)
//   cancel    state/holds/<id>.cancel.json    ends one
//   revert    the listing edit or the advisory deletion that undoes an applied
//             M_DELIST, M_DEPRECATE or M_REVOKE, its `relist` or `unrevoke`
//             log entry, and the two regenerated documents (MOD-52)
//   deny      state/deny/<fingerprint>.json   withholds a release for ever (TRUST-33)
//   ok        state/ok/<fingerprint>.json     ends the operator window of the alert
//             it answers, and nothing else (TRUST-32, contract 5.8.0)
//
// `operatorPath` is that list as a predicate, and every path an act would
// write is checked against it before anything is opened. **It posts nothing to
// the service** (MOD-52: "It posts no result; the service reads `main`"), and
// it holds no bot OIDC token to post with.
//
// **A revert is unheld and outside the takedown bound** (MOD-52). It is outside
// structurally, not by a trailer: TRUST-26 counts what a commit ADDS
// (`bot/lib/takedown-bound.mjs`), and a revert only takes away.
//
// ── WHAT IT REFUSES ─────────────────────────────────────────────────────────
//
// Every refusal is a red run with the reason, and writes nothing: a confirm or
// cancel for a hold that is not on `main`, or that already has an answer; a
// confirm of an `unbound_yank`, which no confirmation ever releases (M-T3.3);
// a revert of anything but an applied delist, deprecate or revoke — a yank
// included, which MOD-52 does not make reversible — or of one already
// reverted; a deny of a fingerprint already denied, or of anything that is not
// one; an `ok` by anybody but the owner's pinned id, for a fingerprint whose
// alert has no reported delivery or no record at all, beside a deny record, or
// one already given for that alert's approval.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "./lib/sources.mjs";
import { ADVISORY_ID, SOURCE_DIR as REVOCATIONS_DIR } from "./lib/revocations.mjs";
import { ADVISORY_ID_GRAMMAR, ID_PATTERN } from "./lib/ids.mjs";
import { decisionCommitMessage } from "../bot/lib/decisions.mjs";
import { HOLDS_DIR, RECORD_SCHEMA, checkHoldRecord, readHolds } from "../bot/lib/holds.mjs";
import {
  SOURCE_DIR as MODERATION_DIR,
  checkEntry,
  cutoverAt,
  fileNameFor,
  loadEntries,
  suffixOf,
} from "../bot/lib/moderation.mjs";
import { okAuthority, operatorAuthority } from "../bot/lib/operator-role.mjs";
import { OK_DIR, OK_SCHEMA, okRecordProblems } from "../bot/lib/service-decide.mjs";
import { isTime } from "./lib/time.mjs";
import { composeVerdict, regenerateDocuments } from "../bot/moderation-run.mjs";

/** The five acts, and no sixth: `act` is a closed enum here and in the workflow. */
export const ACTS = Object.freeze(["confirm", "cancel", "revert", "deny", "ok"]);

/** `astra.registry.deny/1`, TRUST-33's record: exactly these members (B.4). */
export const DENY_SCHEMA = "astra.registry.deny/1";
export const DENY_DIR = "state/deny";
export const DENY_MEMBERS = Object.freeze(["schema", "fingerprint", "run", "at"]);

/** A submission fingerprint: 16 lowercase hex, as `schema/decision-v1.json` has it. */
export const FINGERPRINT_RE = /^[0-9a-f]{16}$/;

/** §0.7's service decision id: a lowercase UUID v4 or v7. */
const SDI_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

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

/** BOT-33's operator row: the only paths an operator act may write or delete. */
export function operatorPath(rel) {
  return HOLD_RECORD_RE.test(rel) || DENY_RE.test(rel) || OK_RE.test(rel) || PLUGIN_RE.test(rel) || LOG_RE.test(rel) ||
    ADVISORY_RE.test(rel) || DOCUMENTS.has(rel);
}

class Refusal extends Error {}
const refuse = (why) => { throw new Refusal(why); };

const wholeSeconds = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

function write(root, rel, doc, touched) {
  if (!operatorPath(rel)) throw new Error(`an operator act names ${rel}, which the operator's allowlist does not carry`);
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

function answerHold(root, act, sdi, { at, run }) {
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

function revertDecision(root, sdi, { at }) {
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

  const documents = regenerateDocuments({ root, paths: touched });
  touched.push(...documents.changed);
  return { touched, subject: `operator: revert ${reverted.action} of ${plugin} (${logs}, MOD-52)`, service_decision: sdi };
}

// ── deny ────────────────────────────────────────────────────────────────────

function denyFingerprint(root, fingerprint, { at, run }) {
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

function okFingerprint(root, fingerprint, { at, run, actorId }) {
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

/**
 * Perform one act on the tree at `root`. Returns the paths it touched and the
 * commit message; throws a `Refusal` (red, nothing written) or an Error.
 */
export function operatorAct({ root = REPO_ROOT, act, serviceDecisionId, fingerprint, now = new Date(), runId = null, run = null, actorId = null }) {
  if (!ACTS.includes(act)) refuse(`${JSON.stringify(act)} is not one of the operator's acts (${ACTS.join(", ")})`);
  const at = wholeSeconds(now);
  let done;
  if (act === "deny") {
    if (serviceDecisionId) refuse("a deny names a fingerprint, not a service decision; leave service_decision_id empty");
    done = denyFingerprint(root, fingerprint, { at, run });
  } else if (act === "ok") {
    if (serviceDecisionId) refuse("an ok names a fingerprint, not a service decision; leave service_decision_id empty");
    done = okFingerprint(root, fingerprint, { at, run, actorId });
  } else {
    if (fingerprint) refuse(`a ${act} names a service decision, not a fingerprint; leave fingerprint empty`);
    if (!SDI_RE.test(String(serviceDecisionId ?? ""))) {
      refuse(`${JSON.stringify(serviceDecisionId)} is not a service_decision_id (§0.7's lowercase UUID v4 or v7)`);
    }
    done = act === "revert"
      ? revertDecision(root, serviceDecisionId, { at })
      : answerHold(root, act, serviceDecisionId, { at, run });
  }
  const message = decisionCommitMessage({
    subject: done.subject,
    run: runId,
    ...(done.service_decision ? { service_decision: done.service_decision } : {}),
  });
  return { paths: done.touched, message };
}

// ── the command line ────────────────────────────────────────────────────────

const arg = (argv, name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

export async function main(argv = [], { env = process.env, log = console, fetchImpl = fetch, now = new Date() } = {}) {
  const job = arg(argv, "--job");
  const root = arg(argv, "--registry-dir") ?? REPO_ROOT;
  const runUrl = env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID
    ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
    : null;

  if (job === "authority") {
    const answer = await operatorAuthority({
      repo: env.GITHUB_REPOSITORY,
      actor: env.ASTRA_ACTOR,
      triggeringActor: env.ASTRA_TRIGGERING_ACTOR,
      runAttempt: env.ASTRA_RUN_ATTEMPT,
      token: env.GH_TOKEN,
      fetchImpl,
    });
    if (!answer.ok) {
      log.error(`::error::refused: ${answer.why}`);
      return 1;
    }
    log.log(`ok    ${answer.why}`);
    return 0;
  }

  if (job === "ok-authority") {
    // TRUST-32's own role check for the act `ok`, after `authority`. Any other
    // act passes through: their check is `authority` alone.
    if (env.ASTRA_ACT !== "ok") {
      log.log(`ok    the act is ${JSON.stringify(env.ASTRA_ACT ?? null)}, not \`ok\`; TRUST-32's check does not apply`);
      return 0;
    }
    const answer = okAuthority({ actorId: env.ASTRA_ACTOR_ID });
    if (!answer.ok) {
      log.error(`::error::refused: ${answer.why}`);
      return 1;
    }
    log.log(`ok    ${answer.why}`);
    return 0;
  }

  if (job === "act") {
    const out = arg(argv, "--out") ?? "operator";
    fs.mkdirSync(out, { recursive: true });
    try {
      const { paths, message } = operatorAct({
        root,
        act: env.ASTRA_ACT,
        serviceDecisionId: env.ASTRA_SERVICE_DECISION_ID || null,
        fingerprint: env.ASTRA_FINGERPRINT || null,
        now,
        runId: env.GITHUB_RUN_ID ?? null,
        run: runUrl,
        actorId: env.ASTRA_ACTOR_ID ?? null,
      });
      fs.writeFileSync(path.join(out, "paths.txt"), paths.length ? `${paths.join("\n")}\n` : "");
      fs.writeFileSync(path.join(out, "commit-message.txt"), message);
      log.log(`ok    ${env.ASTRA_ACT}: ${paths.length} path(s): ${paths.join(", ")}`);
      return 0;
    } catch (err) {
      if (err instanceof Refusal) {
        log.error(`::error::refused: ${err.message}`);
        return 1;
      }
      throw err;
    }
  }

  if (job === "verdict") {
    // The alert job's verdict: red when the act job did not succeed — a refused
    // dispatch included, which is the case worth a page: somebody with access
    // to dispatch tried an operator act and was refused. A green verdict sends
    // nothing; the act itself is on `main` and on the run page.
    const out = arg(argv, "--out") ?? "verdict.json";
    const result = env.ASTRA_ACT_RESULT;
    const verdict = composeVerdict({
      check: "operator",
      status: result === "success" ? "green" : "red",
      codes: result === "success" ? [] : ["OPERATOR_ACT_NOT_DONE"],
      ids: [],
      run: runUrl,
    });
    fs.writeFileSync(out, `${JSON.stringify(verdict, null, 2)}\n`);
    log.log(`ok    ${out}: ${verdict.status}`);
    return 0;
  }

  throw new Error(`\`--job ${JSON.stringify(job)}\` is not one of authority, ok-authority, act, verdict`);
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err) => {
    console.error(`::error::${err.message}`);
    process.exit(1);
  });
}
