#!/usr/bin/env node
// One alarm, through Telegram's Bot API, to the owner and to KNICE.
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
// Until the owner performs §2.12's R1 act — environment `alerts`, the
// registry's own Telegram bot, the receiver account — that is the state of
// `main`: every job with an `alert` step is red, on every run, naming the
// secret it has not got. That is deliberate. The alternative reading, that a
// missing secret should be a skip, is the reading that makes an estate with no
// alarm channel indistinguishable from an estate with nothing to report.
//
// **`delivered_at` is TRUST-32's value.** It is the message time the Bot API
// reports (`result.date`) for the OWNER's chat, in §0.7's format, and it is
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
 * The three secrets environment `alerts` must hold for a page to reach a
 * person, and what each one's absence means.
 *
 * The copy is not optional. OPEN-OWNER-35 closed with one responder at launch
 * and KNICE receiving a copy of every page, and BOT-86 escalates to KNICE when
 * the owner does not acknowledge. An estate that quietly stopped copying has
 * one responder and no escalation, and nothing about it looks different.
 */
export const REQUIRED_SECRETS = [
  ["ASTRA_ALERT_TELEGRAM_TOKEN", "the registry's own Telegram bot token (never the storefront's, never astra-alarm-watch's)"],
  ["ASTRA_ALERT_CHAT_ID", "the owner's alarm chat"],
  ["ASTRA_ALERT_COPY_CHAT_ID", "KNICE's copy of every page (OPEN-OWNER-35)"],
];

/** @returns {string[]} one sentence per secret that is absent or blank */
export function credentialProblems(env = process.env) {
  const problems = [];
  for (const [name, what] of REQUIRED_SECRETS) {
    const value = env[name];
    if (typeof value !== "string" || value.trim() === "") {
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

/**
 * @returns {Promise<{code: number, delivered_at: string|null, copy_delivered: boolean, problems: string[]}>}
 */
export async function runAlert({
  verdict,
  ack = false,
  ifRed = false,
  env = process.env,
  fetchImpl = fetch,
  apiBase = TELEGRAM_API,
  log = console,
} = {}) {
  const fail = (problems) => {
    for (const p of problems) log.error(`FAIL  ${p}`);
    return { code: 1, delivered_at: null, copy_delivered: false, alerted: false, problems };
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
  if (ifRed && verdict.status !== "red") {
    log.log(`ok    verdict for ${verdict.check} is green; its grammar is sound and there is nothing to send`);
    return { code: 0, delivered_at: null, copy_delivered: false, alerted: false, problems: [] };
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

  // KNICE's copy. A failed copy is reported once, here, and never withholds
  // `delivered_at`: the owner was paged, the estate's one responder knows, and
  // holding back a publication because a COPY failed would punish the wrong
  // thing. It is still visible — the annotation is in the run, and
  // `copy_delivered=false` is a step output somebody can gate on later.
  let copyDelivered = true;
  try {
    await sendMessage({ token, chatId: env.ASTRA_ALERT_COPY_CHAT_ID, text, apiBase, fetchImpl });
  } catch (e) {
    copyDelivered = false;
    log.error(`::warning::KNICE's copy of this alarm did not send: ${e.message} (OPEN-OWNER-35)`);
  }

  log.log(`ok    alarm delivered to the owner's chat at ${deliveredAt}`);
  if (!copyDelivered) log.log("warn  KNICE's copy did not send; delivered_at stands");
  return { code: 0, delivered_at: deliveredAt, copy_delivered: copyDelivered, alerted: true, problems: [] };
}

function parseArgs(argv) {
  const args = { verdict: null, ack: false, ifRed: false, checkCredentials: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--verdict") args.verdict = argv[++i];
    else if (a === "--ack") args.ack = true;
    else if (a === "--if-red") args.ifRed = true;
    else if (a === "--check-credentials") args.checkCredentials = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);

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
    console.log("ok    environment `alerts` carries the three channel secrets");
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

  const out = await runAlert({ verdict, ack: args.ack, ifRed: args.ifRed });
  if (out.delivered_at) console.log(`delivered_at=${out.delivered_at}`);
  if (process.env.GITHUB_OUTPUT && out.code === 0) {
    fs.appendFileSync(
      process.env.GITHUB_OUTPUT,
      `alerted=${out.alerted}\ndelivered_at=${out.delivered_at ?? ""}\ncopy_delivered=${out.copy_delivered}\n`,
    );
  }
  return out.code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
