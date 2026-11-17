#!/usr/bin/env node
// One alarm, through Telegram's Bot API, to the alarm group the owner and
// KNICE share — and to a separate copy chat only if one is set. An alarm only
// the owner can act on goes to his quiet chat instead, once he has set one
// (`ownerChat`, registry fix No. 2).
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

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { renderVerdict, verdictProblems } from "./lib/alert-verdict.mjs";
import { ownerCodes, secretName } from "./lib/alert-checks.mjs";

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
  ["ASTRA_ALERT_OWNER_CHAT_ID", "the owner's quiet chat: the alarms only he can act on, and nothing else (registry fix No. 2)"],
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

/**
 * The owner's quiet chat (registry fix No. 2), or null when there is none to
 * route to: absent or blank, or the alarm chat itself — then every page goes
 * where it went before, exactly as if the secret did not exist.
 *
 * Why a second chat at all. The alarm group carried 160 to 206 messages a day
 * in the week to 2026-11-10, and the few that only the owner can answer — a
 * run GitHub will not end, a trust document running out, the service holding
 * every bot call for his acknowledgement — drowned in them. With this set, a
 * page whose codes are all owner-class (`ownerCodes`, decided by the check's
 * row in bot/lib/alert-checks.mjs and nowhere here) goes to this chat ONLY;
 * one whose codes are all something else stays in the alarm chat (and its
 * copy); a page carrying both goes to both, so nobody loses a line they had.
 * The first page, the daily repeat and "resolved" all follow the same rule.
 */
export function ownerChat(env = process.env) {
  const owner = env.ASTRA_ALERT_OWNER_CHAT_ID;
  if (!present(owner)) return null;
  if (present(env.ASTRA_ALERT_CHAT_ID) && owner.trim() === env.ASTRA_ALERT_CHAT_ID.trim()) return null;
  // The copy chat receives every shared page, so an owner chat that IS the
  // copy chat would be a quiet chat with all the noise in it, and an owner
  // page there would look like a copy. Refused: today's routing, and a
  // warning that says why (`ownerSentence`; review of #506, S7).
  if (present(env.ASTRA_ALERT_COPY_CHAT_ID) && owner.trim() === env.ASTRA_ALERT_COPY_CHAT_ID.trim()) return null;
  return owner;
}

/** The code of a state pair, `<code>|<id>`; empty for a red verdict with no codes. */
const codeOf = (pair) => pair.split("|")[0];
const codesOf = (pairs) => [...new Set(pairs.map(codeOf).filter(Boolean))];

/**
 * Where a page about these codes of this check goes: `{ shared, owner }`, each
 * true or false, never both false. A red verdict with no codes is not
 * owner-class: the class is a list of codes, and an empty one matches none.
 */
export function routeOf(check, codes, env = process.env) {
  if (ownerChat(env) === null) return { shared: true, owner: false };
  const mine = ownerCodes(check);
  const list = Array.isArray(codes) ? codes : [];
  const owner = list.some((c) => mine.has(c));
  const shared = list.length === 0 || list.some((c) => !mine.has(c));
  return { shared, owner };
}

/** The warning for an owner chat that is the copy chat, or null (S7). */
export function ownerChatRefusal(env = process.env) {
  if (!present(env.ASTRA_ALERT_OWNER_CHAT_ID) || !present(env.ASTRA_ALERT_COPY_CHAT_ID)) return null;
  if (env.ASTRA_ALERT_OWNER_CHAT_ID.trim() !== env.ASTRA_ALERT_COPY_CHAT_ID.trim()) return null;
  if (present(env.ASTRA_ALERT_CHAT_ID) && env.ASTRA_ALERT_OWNER_CHAT_ID.trim() === env.ASTRA_ALERT_CHAT_ID.trim()) return null;
  return "ASTRA_ALERT_OWNER_CHAT_ID is the copy chat (ASTRA_ALERT_COPY_CHAT_ID), which receives every shared page, so it is " +
    "ignored and owner-class alarms go to the alarm chat with the rest; give the owner a chat of his own";
}

/** One sentence on the owner chat, for a log line. */
function ownerSentence(env) {
  if (!present(env.ASTRA_ALERT_OWNER_CHAT_ID)) return "no owner chat is set, so owner-class alarms go to the alarm chat with the rest";
  if (ownerChat(env) === null && present(env.ASTRA_ALERT_CHAT_ID) && env.ASTRA_ALERT_OWNER_CHAT_ID.trim() === env.ASTRA_ALERT_CHAT_ID.trim()) {
    return "ASTRA_ALERT_OWNER_CHAT_ID is the alarm chat itself, so it changes nothing";
  }
  if (ownerChat(env) === null) return "ASTRA_ALERT_OWNER_CHAT_ID is the copy chat, so it is ignored (the warning above says why)";
  return "ASTRA_ALERT_OWNER_CHAT_ID is set, so owner-class alarms go there only";
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
//
// **The state is signed** (review of #480, MEDIUM). Any job on the default
// branch can save an Actions cache entry under any key, ingest's `check` —
// "the job to assume exploited" — included, so an unsigned state could be
// planted to silence a new alarm for a day. The state carries an HMAC-SHA256
// (`mac`) under `ASTRA_ALERT_STATE_HMAC_KEY`, a secret held only in
// environment `alerts` and mapped only into the alert jobs that take a state
// (bot/tests/workflows.test.mjs). The secret-less jobs either side carry the
// signed blob and cannot check it; only the alert job verifies it. A missing
// key, a key under 32 characters, a missing or wrong `mac`: the state is
// "never paged", the alarm goes out, and nothing is saved. What a signature
// cannot stop is a REPLAY of an older genuine state of the same check, which
// can quiet only pairs it shows paged within the last 24 hours.

/** How long the same red state goes without a repeat page. */
export const REPEAT_HOURS = 24;

const pairsOf = (verdict) => {
  const codes = verdict.codes?.length ? verdict.codes : [""];
  const ids = [...(verdict.ids ?? []), ...(verdict.hexes ?? [])];
  return codes.flatMap((c) => (ids.length ? ids : [""]).map((i) => `${c}|${i}`)).sort();
};

/** The signing key, or null when it is absent or too short to be one: then nothing is trusted or saved. */
export function stateKey(env = process.env) {
  const key = env.ASTRA_ALERT_STATE_HMAC_KEY;
  return typeof key === "string" && key.trim().length >= 32 ? key : null;
}

const STATE_SCHEMA = "astra.registry.alert-state/1";
const macOf = (doc, key) => crypto.createHmac("sha256", key)
  .update(`${STATE_SCHEMA}\n${JSON.stringify({ schema: doc.schema, checks: doc.checks })}`).digest("hex");

/** The state, signed: what the alert job writes and the save job stores. */
export function signState(doc, key) {
  const body = { schema: STATE_SCHEMA, checks: doc?.checks ?? {} };
  return { ...body, mac: macOf(body, key) };
}

/** Does `doc` carry the shape of a signed state (what a secret-less job can check)? */
export function signedShape(doc) {
  return doc?.schema === STATE_SCHEMA && doc.checks && typeof doc.checks === "object" && !Array.isArray(doc.checks)
    && typeof doc.mac === "string" && /^[0-9a-f]{64}$/.test(doc.mac);
}

/**
 * The state the alert job may act on: the file's, when its `mac` verifies
 * under `key`, and otherwise an empty one ("never paged"), so a forged, a
 * replayed-from-elsewhere-shaped or an unsigned state pages.
 */
export function readSignedState(file, key) {
  const empty = { schema: STATE_SCHEMA, checks: {} };
  if (!key) return empty;
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return empty;
  }
  if (!signedShape(doc)) return empty;
  const want = Buffer.from(macOf(doc, key), "hex");
  const have = Buffer.from(doc.mac, "hex");
  if (want.length !== have.length || !crypto.timingSafeEqual(want, have)) return empty;
  return { schema: STATE_SCHEMA, checks: doc.checks };
}

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
  // The secret-less restore job cannot verify the signature, so it hands on
  // what the cache held when it has a signed state's shape, and an empty
  // (unsigned) state otherwise; the alert job decides whether to trust it.
  try {
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    if (signedShape(doc)) return JSON.stringify(doc);
  } catch { /* absent or unreadable */ }
  return JSON.stringify({ schema: STATE_SCHEMA, checks: {} });
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
  // Signed or not saved: an unsigned document would be "never paged" when
  // read back anyway, and saving it would only displace a signed one.
  if (!signedShape(doc)) return false;
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
  // `fresh`: the pairs this page is FOR — all of them, or only the new ones.
  // The page goes to the chats those pairs route to (`routeOf`), so a pair
  // already paged in one chat is not paged there again because another chat
  // owed a different one (review of #506, S3).
  const page = (why, fresh = pairs) => {
    next.checks[verdict.check] = { pairs, first_red: prior?.first_red ?? at, last_sent: at };
    return { act: "page", why, fresh, state: next, changed: true };
  };
  if (!prior || !Array.isArray(prior.pairs)) return page("the check turned red");
  const fresh = pairs.filter((p) => !prior.pairs.includes(p));
  if (fresh.length) return page(`a code or id not paged since it turned red: ${fresh.join(", ")}`, fresh);
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
  let saved = false;
  // `state_changed` rides on a failure too: a page that reached one chat of
  // two saved that chat's pairs (S3), and the save job must carry them on.
  const fail = (problems) => {
    for (const p of problems) log.error(`FAIL  ${p}`);
    return { code: 1, delivered_at: null, copy_delivered: null, alerted: false, state_changed: saved, problems };
  };
  const refused = ownerChatRefusal(env);
  if (refused) log.error(`::warning::${refused}`);

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
  // Signed (review of #480): with no key nothing is trusted and nothing is
  // saved, so every red pages — the failure is the safe one.
  const key = stateKey(env);
  if (stateFile && !key) log.error("::warning::ASTRA_ALERT_STATE_HMAC_KEY is not in this job, so the alert state is not trusted or saved and every red pages");
  const decided = stateFile ? alertDecision(verdict, readSignedState(stateFile, key), { now }) : null;
  const save = () => {
    if (!decided?.changed || !key) return;
    fs.mkdirSync(path.dirname(path.resolve(stateFile)), { recursive: true });
    fs.writeFileSync(stateFile, `${JSON.stringify(signState(decided.state, key), null, 2)}\n`);
    saved = true;
  };
  if (decided?.act === "resolve") {
    // To the chats the page went to: the route of the codes that were paged.
    const to = routeOf(verdict.check, codesOf(decided.prior.pairs), env);
    const text = renderResolved(verdict, decided.prior);
    let sharedSent = false;
    try {
      if (to.shared) {
        await sendMessage({ token: env.ASTRA_ALERT_TELEGRAM_TOKEN, chatId: env.ASTRA_ALERT_CHAT_ID, text, apiBase, fetchImpl });
        sharedSent = true;
      }
      if (to.owner) await sendMessage({ token: env.ASTRA_ALERT_TELEGRAM_TOKEN, chatId: ownerChat(env), text, apiBase, fetchImpl });
    } catch (e) {
      // Per chat (review of #506, S3): the chat that got "resolved" is done;
      // only the owner's pairs stay in the state, so the next green run sends
      // "resolved" to the owner chat alone.
      if (sharedSent && decided) {
        const mine = ownerCodes(verdict.check);
        decided.state.checks[verdict.check] = { ...decided.prior, pairs: decided.prior.pairs.filter((p) => mine.has(codeOf(p))) };
        save();
      }
      // Kept as unresolved: the next green run tries again, and a red one in
      // between pages as the state it is.
      log.error(`::warning::the "resolved" message for ${verdict.check} did not send: ${e.message}`);
      return { code: 0, delivered_at: null, copy_delivered: null, alerted: false, resolved: false, state_changed: saved, problems: [] };
    }
    save();
    log.log(`ok    ${verdict.check} is green again; "resolved" sent once`);
    return { code: 0, delivered_at: null, copy_delivered: null, alerted: false, resolved: true, state_changed: saved, problems: [] };
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
  const to = routeOf(verdict.check, decided ? codesOf(decided.fresh) : verdict.codes, env);

  // The alarm chat when the page is for it, then the owner chat when it is
  // for him. Each is a destination the page was owed, so either failing fails
  // the run; `delivered_at` is the alarm chat's time, or the owner chat's for
  // a page that went to him alone.
  let result = null;
  if (to.shared) {
    try {
      result = await sendMessage({ token, chatId: env.ASTRA_ALERT_CHAT_ID, text, apiBase, fetchImpl });
    } catch (e) {
      return fail([`the alarm did not reach the alarm chat: ${e.message}`]);
    }
  }
  if (to.owner) {
    let mine;
    try {
      mine = await sendMessage({ token, chatId: ownerChat(env), text, apiBase, fetchImpl });
    } catch (e) {
      // Per chat (review of #506, S3): the alarm chat WAS paged. Its pairs are
      // saved as paged, the owner's are left out, so the next run pages the
      // owner chat alone instead of the alarm group again on every run.
      if (to.shared && decided) {
        const owned = ownerCodes(verdict.check);
        const entry = decided.state.checks[verdict.check];
        entry.pairs = entry.pairs.filter((p) => !owned.has(codeOf(p)));
        if (entry.pairs.length) save();
      }
      return fail([`the alarm did not reach the owner chat (ASTRA_ALERT_OWNER_CHAT_ID): ${e.message}`]);
    }
    if (!to.shared) result = mine;
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
  const copy = to.shared ? copyChat(env) : null;
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
  const where = to.shared && to.owner ? "the alarm chat and the owner chat" : to.owner ? "the owner chat alone" : "the alarm chat";
  log.log(`ok    alarm delivered to ${where} at ${deliveredAt}; ${copySentence(env)}; ${ownerSentence(env)}` +
    (decided ? ` (${decided.why})` : ""));
  if (copyDelivered === false) log.log("warn  the separate copy did not send; delivered_at stands");
  return { code: 0, delivered_at: deliveredAt, copy_delivered: copyDelivered, alerted: true, state_changed: saved, problems: [] };
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
    const refusedChat = ownerChatRefusal(process.env);
    if (refusedChat) console.error(`::warning::${refusedChat}`);
    console.log(`ok    environment \`alerts\` carries every required channel secret (${REQUIRED_SECRETS.map(([n]) => n).join(", ")}); ${copySentence(process.env)}; ${ownerSentence(process.env)}`);
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
  if (process.env.GITHUB_OUTPUT && (out.code === 0 || out.state_changed === true)) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, stepOutputs(out, args.state));
  }
  return out.code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
