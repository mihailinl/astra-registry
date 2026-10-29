#!/usr/bin/env node
// One alarm, through Telegram's Bot API, to the alarm group the owner and
// KNICE share — and to a separate copy chat only if one is set.
//
//     node bot/alert.mjs --verdict <file>        send, and print delivered_at
//     node bot/alert.mjs --verdict <file> --ack  … with the acknowledgement link
//     node bot/alert.mjs --check-credentials     is the channel reachable at all
//
// **This script fails closed, loudly, and that is the whole of its design.**
// An alert that cannot be sent looks exactly like nothing having gone wrong,
// and every failure mode below was reached for by asking "what does the
// estate look like the morning after". So: a missing secret is not a warning,
// an unreachable API is not a warning, and `ok: false` is not a warning. Each
// exits non-zero with no `delivered_at`, the job goes red, and — because the
// composite action posts the BOT-85 heartbeat only after this succeeds — the
// dead-man receiver hears nothing either and pages on silence. Two independent
// paths to a person, and the one that is left when the channel is the thing
// that broke is the one that does not use the channel.
//
// That holds here whatever the caller is doing: this script never treats a
// missing secret as a skip, because the reading that a missing secret is a
// skip is the reading that makes an estate with no alarm channel
// indistinguishable from an estate with nothing to report.
//
// **One state is decided one level up, and not here** (2026-09-19). Before the
// owner performs §2.12's R1 act — environment `alerts`, the registry's own
// Telegram bot, the receiver account — NONE of the channel secrets exists, and
// that is not the same fact as one of them having gone missing. The composite
// action `.github/actions/alert/action.yml` is where the two are told apart:
// all of them absent is said out loud, once, and is green there; anything else
// is this script's business and is red. `--check-credentials` still exits
// non-zero on an empty environment, and `runAlert` still refuses to send with
// a secret missing — the distinction is which job calls them, never what they
// answer.
//
// **`delivered_at` is TRUST-32's value.** It is the message time the Bot API
// reports (`result.date`) for the ALARM chat, in §0.7's format, and it is
// what B-T3.3b writes into `state/alerts/<fingerprint>.json` and what gates
// publication. It is never synthesised from the local clock: a time this
// process made up would say an alarm was delivered when the API never said so.
//
// **The registry's bot is its own** (0.13.0, n9). minice-be measured on
// 2026-09-17 that the relay's credential is byte-identical to the storefront
// bot token, so one rotation would drop every page the service raises, in
// silence. A registry sharing it would die the same way, and the destination
// check RC-R1-0 puts in ops.7 asserts that `ASTRA_ALERT_TELEGRAM_TOKEN` is
// neither of those two.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { renderVerdict, verdictProblems } from "./lib/alert-verdict.mjs";
import { secretName } from "./lib/alert-checks.mjs";

/** The one host this script talks to. There is no override, by design. */
export const TELEGRAM_API = "https://api.telegram.org";

const SEND_TIMEOUT_MS = 20_000;

/**
 * The two secrets environment `alerts` must hold for a page to reach a
 * person, and what each one's absence means.
 *
 * **KNICE sees every page by being in the alarm chat, not by a second
 * message** (the owner's decision of 2026-09-23). OPEN-OWNER-35 closed with
 * one responder at launch and KNICE receiving a copy of every page; this
 * repository first built that as two chats, the owner's and a copy chat of
 * KNICE's, and made the copy a required secret. The owner then chose ONE
 * group holding both of them. So `ASTRA_ALERT_CHAT_ID` is that group, and the
 * copy chat is optional.
 *
 * What that costs, said here because nothing else can say it: whether KNICE
 * is actually IN the group is a fact about Telegram, and no job here can see
 * it. A group he has left pages the owner alone and looks, from every run in
 * this repository, exactly like a group he is in. The owner's runbook checks
 * it by hand; BOT-86's escalation to KNICE goes through the receiver, not
 * through this chat, and does not depend on it.
 */
export const REQUIRED_SECRETS = [
  ["ASTRA_ALERT_TELEGRAM_TOKEN", "the registry's own Telegram bot token (never the storefront's, never astra-alarm-watch's)"],
  ["ASTRA_ALERT_CHAT_ID", "the alarm chat: the one group the owner and KNICE share (2026-09-23)"],
];

/**
 * Channel secrets a job reads when they are set and does not miss when they
 * are not. Every alert job still MAPS them (`bot/tests/workflows.test.mjs`),
 * because an environment secret reaches only the jobs that name it, and a copy
 * chat the owner sets later must reach every page and not only some.
 *
 * `ASTRA_ALERT_COPY_CHAT_ID`, and what it does:
 *
 *   * absent, or blank — the page goes to the alarm chat alone;
 *   * the alarm chat itself — the page is sent ONCE. Two identical messages in
 *     one chat are not a copy, they are noise the reader learns to scroll past;
 *   * any other chat — the page goes to the alarm chat and then to it, as
 *     before 2026-09-23, and a failed copy never withholds `delivered_at`.
 */
export const OPTIONAL_SECRETS = [
  ["ASTRA_ALERT_COPY_CHAT_ID", "a separate chat that receives a second copy of every page (optional since 2026-09-23)"],
];

const present = (value) => typeof value === "string" && value.trim() !== "";

/**
 * Where the second copy goes, or null when there is none to send: the copy
 * chat is absent or blank, or it is the alarm chat itself. Compared trimmed,
 * because a pasted id with a stray space is still the same chat and would
 * otherwise page the group twice.
 */
export function copyChat(env = process.env) {
  const copy = env.ASTRA_ALERT_COPY_CHAT_ID;
  if (!present(copy)) return null;
  if (present(env.ASTRA_ALERT_CHAT_ID) && copy.trim() === env.ASTRA_ALERT_CHAT_ID.trim()) return null;
  return copy;
}

/** One sentence on the copy chat, for a log line. */
function copySentence(env) {
  if (!present(env.ASTRA_ALERT_COPY_CHAT_ID)) {
    return "no separate copy chat is set, so every page goes to the alarm chat alone — KNICE sees it by being in that group";
  }
  if (copyChat(env) === null) return "ASTRA_ALERT_COPY_CHAT_ID is the alarm chat itself, so each page is sent once";
  return "ASTRA_ALERT_COPY_CHAT_ID is a separate chat, which gets a second copy of each page";
}

/** @returns {string[]} one sentence per secret that is absent or blank */
export function credentialProblems(env = process.env) {
  const problems = [];
  for (const [name, what] of REQUIRED_SECRETS) {
    if (!present(env[name])) {
      problems.push(
        `${name} is not set in this job — ${what}. It is a secret of environment \`alerts\`, which the owner ` +
        `creates in astra-registry admitting only \`main\` (registry plan RC-R1-0, §2.12's R1 row). No alarm can ` +
        `leave this run until he has.`,
      );
    }
  }
  return problems;
}

/** §0.7: RFC 3339 UTC, whole seconds, ending in Z. */
export function rfc3339(unixSeconds) {
  return `${new Date(unixSeconds * 1000).toISOString().slice(0, 19)}Z`;
}

/**
 * One `sendMessage`. Returns the API's `result` or throws — and the throw
 * carries no URL, because the URL carries the bot token.
 */
async function sendMessage({ token, chatId, text, apiBase, fetchImpl }) {
  let res;
  try {
    res = await fetchImpl(`${apiBase}/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "astra-registry-alert" },
      body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
  } catch (e) {
    throw new Error(`the Bot API could not be reached: ${String(e.message ?? e)}`);
  }
  if (!res.ok) throw new Error(`the Bot API answered HTTP ${res.status}`);
  let body;
  try {
    body = await res.json();
  } catch {
    throw new Error("the Bot API answered 2xx with something that is not JSON");
  }
  if (body?.ok !== true) {
    // `description` is the API's own string and the one thing worth repeating
    // from it; it never contains the token.
    throw new Error(`the Bot API answered ok: false (${String(body?.description ?? "no description")})`);
  }
  return body.result;
}

// ── R4: one page per state, not one per run (2026-10-29) ────────────────────
//
// Until 2026-10-29 every red run paged: about twenty an hour across the
// estate, and Deadline watch sent the same message daily for nine days. An
// alarm that repeats on the correct state is one nobody reads by the time it
// fires on a new one. So a check's alarm is keyed by (check, code, id):
//
//   * a check turning red pages at once;
//   * a code or id it has not paged for since it turned red pages at once;
//   * the same state pages again at most once a day (`REPEAT_HOURS`);
//   * a check turning green after a page sends "resolved", once.
//
// The state is a small file (`--state`). A missing or unreadable file is
// "never paged", so every fault is a page sent, never one withheld.
//
// **Where it lives (wired 2026-10-29).** In the Actions cache — and never in
// the job that holds the alarm credential, which bot/tests/workflows.test.mjs
// forbids a cache, an artifact and the GitHub token, because a restore
// extracts bytes into that job. So the state crosses into it only as a JOB
// OUTPUT, a string this file re-reads against its schema:
//
//   * `<alert job>-state` (no environment, no secret) restores the cache and
//     emits the state as one line (`--emit-state`);
//   * the alert job hands that line to `.github/actions/alert` as `state:`,
//     decides here, and outputs `next_state` when the state moved;
//   * `<alert job>-save` (no environment, no secret) writes that line back
//     (`--save-state`) and saves it under a new cache key.
//
// The jobs whose page is an EVENT never pass it: ingest's and moderation's
// `alert` (TRUST-14, TRUST-32 and MOD-8 gate publication on their
// `delivered_at`), the weekly drill (BOT-86 must see it every week), and the
// operator's refused act (each refusal is somebody trying). A state can only
// QUIET a red verdict whose every (code, id) was paged in the last 24 hours,
// at a time not in the future; a state from the future pages.

/** How long the same red state goes without a repeat page. */
export const REPEAT_HOURS = 24;

const pairsOf = (verdict) => {
  const codes = verdict.codes?.length ? verdict.codes : [""];
  const ids = [...(verdict.ids ?? []), ...(verdict.hexes ?? [])];
  return codes.flatMap((c) => (ids.length ? ids : [""]).map((i) => `${c}|${i}`)).sort();
};

/** The state file: `{schema, checks: {<check>: {pairs, first_red, last_sent}}}`, or an empty one. */
export function readAlertState(file) {
  try {
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    if (doc?.schema === "astra.registry.alert-state/1" && doc.checks && typeof doc.checks === "object") return doc;
  } catch { /* absent or unreadable: nothing was paged, so the next red pages */ }
  return { schema: "astra.registry.alert-state/1", checks: {} };
}

/** The state as the one line a job output carries (`--emit-state`): always a whole, valid document. */
export function stateLine(file) {
  return JSON.stringify(readAlertState(file));
}

/**
 * The `save` job's half (`--save-state`): the line the alert job handed on,
 * written to `file` only when it is a state document. Anything else writes
 * nothing, so the cache keeps the state it had and the next red pages.
 */
export function saveStateLine(text, file) {
  let doc;
  try {
    doc = JSON.parse(text ?? "");
  } catch {
    return false;
  }
  if (doc?.schema !== "astra.registry.alert-state/1" || !doc.checks || typeof doc.checks !== "object" || Array.isArray(doc.checks)) return false;
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
  return true;
}

/** What the alert step appends to `$GITHUB_OUTPUT` after `runAlert`. */
export function stepOutputs(out, stateFile = null) {
  const lines = [
    `alerted=${out.alerted}`,
    `delivered_at=${out.delivered_at ?? ""}`,
    `copy_delivered=${out.copy_delivered ?? "none"}`,
    `state_changed=${out.state_changed === true}`,
  ];
  if (stateFile && out.state_changed === true) lines.push(`next_state=${stateLine(stateFile)}`);
  return `${lines.join("\n")}\n`;
}

/**
 * What to do with this verdict, given the state: `page` (with why), `resolve`,
 * or `quiet`, and the state to save after it is done.
 */
export function alertDecision(verdict, state, { now = new Date() } = {}) {
  const prior = state.checks?.[verdict.check] ?? null;
  const next = { ...state, checks: { ...(state.checks ?? {}) } };
  if (verdict.status !== "red") {
    if (!prior) return { act: "quiet", why: "green, and nothing was paged", state: next, changed: false };
    delete next.checks[verdict.check];
    return { act: "resolve", why: `green again after ${prior.pairs.length} paged state(s)`, prior, state: next, changed: true };
  }
  const pairs = pairsOf(verdict);
  const at = `${now.toISOString().slice(0, 19)}Z`;
  const page = (why) => {
    next.checks[verdict.check] = { pairs, first_red: prior?.first_red ?? at, last_sent: at };
    return { act: "page", why, state: next, changed: true };
  };
  if (!prior || !Array.isArray(prior.pairs)) return page("the check turned red");
  const fresh = pairs.filter((p) => !prior.pairs.includes(p));
  if (fresh.length) return page(`a code or id not paged since it turned red: ${fresh.join(", ")}`);
  const since = now.getTime() - Date.parse(prior.last_sent);
  // A page "sent" in the future is not one this registry sent: the state is
  // forged or the clock is wrong, and either way the page goes out. Without
  // this a `last_sent` in year 9999 would quiet the state for ever.
  if (since < -5 * 60_000) return page(`the state says it was paged at ${prior.last_sent}, which is in the future`);
  if (!(since < REPEAT_HOURS * 3600_000)) return page(`still red, and the last page was ${REPEAT_HOURS} hours or more ago`);
  return {
    act: "quiet",
    why: `the same red state was paged at ${prior.last_sent}; it repeats at most once in ${REPEAT_HOURS} hours`,
    state: next,
    changed: false,
  };
}

/** The "resolved" message: plain, and naming what had been paged. */
export function renderResolved(verdict, prior) {
  return [
    "ASTRA REGISTRY — resolved",
    `check: ${verdict.check}`,
    "status: green",
    `was: ${prior.pairs.map((p) => p.replace(/\|$/, "")).join(" ")}`,
    ...(verdict.run ? [`run: ${verdict.run}`] : []),
  ].join("\n");
}

/**
 * `copy_delivered` is `true` when a separate copy chat got the page, `false`
 * when it was sent one and did not, and `null` when no copy was sent at all —
 * there is no separate copy chat, or nothing was sent. `false` therefore means
 * one thing only: a copy that was tried and failed.
 *
 * @returns {Promise<{code: number, delivered_at: string|null, copy_delivered: boolean|null, alerted: boolean, problems: string[]}>}
 */
export async function runAlert({
  verdict,
  ack = false,
  ifRed = false,
  env = process.env,
  fetchImpl = fetch,
  apiBase = TELEGRAM_API,
  log = console,
  stateFile = null,
  now = new Date(),
} = {}) {
  const fail = (problems) => {
    for (const p of problems) log.error(`FAIL  ${p}`);
    return { code: 1, delivered_at: null, copy_delivered: null, alerted: false, problems };
  };

  const missing = credentialProblems(env);
  if (missing.length) return fail(missing);

  const bad = verdictProblems(verdict);
  if (bad.length) {
    return fail([
      "the verdict this job wrote is not one the alarm channel will carry, so nothing was sent:",
      ...bad,
    ]);
  }

  // A green verdict is checked and not sent. The check is not skipped with the
  // send: a verdict whose grammar is wrong is wrong on the green runs too, and
  // the green runs are the ones there are hundreds of. Finding it on the run
  // that had nothing to say is the difference between a red CI job and an
  // alarm that could not be rendered on the night it mattered.
  // R4: with a state file, the same state pages once (`alertDecision`).
  const decided = stateFile ? alertDecision(verdict, readAlertState(stateFile), { now }) : null;
  const save = () => {
    if (!decided?.changed) return;
    fs.mkdirSync(path.dirname(path.resolve(stateFile)), { recursive: true });
    fs.writeFileSync(stateFile, `${JSON.stringify(decided.state, null, 2)}\n`);
  };
  if (decided?.act === "resolve") {
    try {
      await sendMessage({ token: env.ASTRA_ALERT_TELEGRAM_TOKEN, chatId: env.ASTRA_ALERT_CHAT_ID, text: renderResolved(verdict, decided.prior), apiBase, fetchImpl });
    } catch (e) {
      // Kept as unresolved: the next green run tries again, and a red one in
      // between pages as the state it is.
      log.error(`::warning::the "resolved" message for ${verdict.check} did not send: ${e.message}`);
      return { code: 0, delivered_at: null, copy_delivered: null, alerted: false, resolved: false, state_changed: false, problems: [] };
    }
    save();
    log.log(`ok    ${verdict.check} is green again; "resolved" sent once`);
    return { code: 0, delivered_at: null, copy_delivered: null, alerted: false, resolved: true, state_changed: true, problems: [] };
  }
  if (ifRed && verdict.status !== "red") {
    log.log(`ok    verdict for ${verdict.check} is green; its grammar is sound and there is nothing to send`);
    return { code: 0, delivered_at: null, copy_delivered: null, alerted: false, problems: [] };
  }
  if (decided?.act === "quiet") {
    log.log(`quiet ${verdict.check}: ${decided.why}`);
    return { code: 0, delivered_at: null, copy_delivered: null, alerted: false, state_changed: false, problems: [] };
  }

  // The acknowledgement link comes from the receiver's own secret, never from
  // the verdict: a URL a job could put in a verdict is a URL a job could put
  // in a message the owner is being asked to click.
  let ackUrl;
  if (ack) {
    const name = secretName("alarm-ack", "success");
    ackUrl = env[name];
    if (typeof ackUrl !== "string" || !ackUrl.startsWith("https://")) {
      return fail([
        `--ack was asked for and ${name} is not an https URL in this job. The weekly alarm without its ` +
        `acknowledgement link is an alarm BOT-86 can never see acknowledged, which escalates to KNICE 48 hours ` +
        `later for no reason, so it is not sent.`,
      ]);
    }
  }

  const text = renderVerdict(verdict, ackUrl);
  const token = env.ASTRA_ALERT_TELEGRAM_TOKEN;

  let result;
  try {
    result = await sendMessage({ token, chatId: env.ASTRA_ALERT_CHAT_ID, text, apiBase, fetchImpl });
  } catch (e) {
    return fail([`the alarm did not reach the owner's chat: ${e.message}`]);
  }

  // No time, no delivery. TRUST-32 gates publication on this value, and a
  // 2xx with no `date` in it is an answer that did not say when — which is not
  // the same as an answer that said now.
  if (!Number.isInteger(result?.date)) {
    return fail([
      "the Bot API accepted the message and reported no `result.date`, so there is no delivered_at to record; " +
      "TRUST-32 has nothing to gate on and this run is red rather than quietly publishing",
    ]);
  }
  const deliveredAt = rfc3339(result.date);

  // The separate copy, only when there is one (`copyChat`). A failed copy is
  // reported once, here, and never withholds `delivered_at`: the alarm chat
  // was paged, and holding back a publication because a COPY failed would
  // punish the wrong thing. It is still visible — the annotation is in the
  // run, and `copy_delivered=false` is a step output somebody can gate on.
  const copy = copyChat(env);
  let copyDelivered = null;
  if (copy !== null) {
    try {
      await sendMessage({ token, chatId: copy, text, apiBase, fetchImpl });
      copyDelivered = true;
    } catch (e) {
      copyDelivered = false;
      log.error(`::warning::the copy of this alarm to ASTRA_ALERT_COPY_CHAT_ID did not send: ${e.message}`);
    }
  }

  save();
  log.log(`ok    alarm delivered to the alarm chat at ${deliveredAt}; ${copySentence(env)}` +
    (decided ? ` (${decided.why})` : ""));
  if (copyDelivered === false) log.log("warn  the separate copy did not send; delivered_at stands");
  return { code: 0, delivered_at: deliveredAt, copy_delivered: copyDelivered, alerted: true, state_changed: Boolean(decided), problems: [] };
}

function parseArgs(argv) {
  const args = { verdict: null, ack: false, ifRed: false, checkCredentials: false, state: null, emitState: null, saveState: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--verdict") args.verdict = argv[++i];
    else if (a === "--ack") args.ack = true;
    else if (a === "--if-red") args.ifRed = true;
    else if (a === "--check-credentials") args.checkCredentials = true;
    else if (a === "--state") args.state = argv[++i];
    else if (a === "--emit-state") args.emitState = argv[++i];
    else if (a === "--save-state") args.saveState = argv[++i];
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);

  // R4's two secret-less jobs. Neither sends anything or reads a channel
  // secret; each moves the state between the cache and a job output.
  if (args.emitState) {
    const line = `state=${stateLine(args.emitState)}\n`;
    if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, line);
    else process.stdout.write(line);
    return 0;
  }
  if (args.saveState) {
    if (saveStateLine(process.env.ASTRA_ALERT_NEXT_STATE, args.saveState)) {
      console.log(`ok    the alert state is written to ${args.saveState}`);
      return 0;
    }
    console.log("::warning::the alert job handed on no state document, so none is saved; the cache keeps the one it had");
    return 0;
  }

  // Asked on every alert job, red or green, BEFORE the heartbeat. A green run
  // whose channel is missing its token is the state this whole task exists to
  // make impossible: it looks identical to a green run whose channel works,
  // and the first person to learn otherwise is the person who needed the
  // alarm. So the credentials are proved present on every pass, not on the
  // pass that happens to have something to say.
  if (args.checkCredentials) {
    const problems = credentialProblems();
    for (const p of problems) console.error(`FAIL  ${p}`);
    if (problems.length) return 1;
    console.log(`ok    environment \`alerts\` carries every required channel secret (${REQUIRED_SECRETS.map(([n]) => n).join(", ")}); ${copySentence(process.env)}`);
    return 0;
  }

  if (!args.verdict) {
    console.error("FAIL  --verdict <file> is required (or --check-credentials)");
    return 1;
  }
  let verdict;
  try {
    verdict = JSON.parse(fs.readFileSync(args.verdict === "-" ? 0 : path.resolve(args.verdict), "utf8"));
  } catch (e) {
    console.error(`FAIL  the verdict could not be read as JSON: ${String(e.message ?? e)}`);
    return 1;
  }

  const out = await runAlert({ verdict, ack: args.ack, ifRed: args.ifRed, stateFile: args.state });
  if (out.delivered_at) console.log(`delivered_at=${out.delivered_at}`);
  if (process.env.GITHUB_OUTPUT && out.code === 0) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, stepOutputs(out, args.state));
  }
  return out.code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
