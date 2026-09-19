#!/usr/bin/env node
// BOT-85's heartbeat: one POST to the dead-man receiver, saying this check ran.
//
//     node bot/heartbeat.mjs --check served-set
//     node bot/heartbeat.mjs --check alarm-ack --signal start
//
// **One whole URL per check, out of that check's own secret** (attack M-5).
// This script composes no URL and holds no base. The alternative —
// `ASTRA_DEADMAN_BASE_URL` plus a check name — is a project-level ping key,
// and it cuts both ways. A registry writer, or anyone who reads one Actions
// secret, could silence the check the plugins service pages through, so when
// the Almaty box dies nobody is paged and the on-box Telegram path is dead by
// construction, because the relay dies with the box. And a compromised
// service, which must hold a URL under the same base to post at all, could
// silence ROLL-62, SERVE-39, SERVE-85, ROLL-15, BOT-88, BOT-90 and the
// moderation-run checks. The contract's threat table gives the service no
// power over the registry's alarms and a registry writer none over the
// service's; one shared key gives each of them the other's.
//
// The receiver PRODUCT stays one, which is Q-O2's settled answer. What stops
// being one is the credential inside it.
//
// **A failure here fails the step**, so silence at the receiver and red in the
// run agree. A heartbeat that swallowed its own failure would be the worst of
// the three states: the receiver hears nothing and pages on silence while the
// run says everything is fine, and the reader who compares them believes the
// run.
//
// **The `start` signal is a second secret, not a suffix.** BOT-86's escalation
// needs a start signal and a success ping on `alarm-ack`, and every receiver
// product spells that pair differently — most as `<ping-url>/start`. Appending
// that here would pin this repository to one product's protocol before the
// owner has chosen one (§1.3 row 2: the receiver's product and shape are still
// to be recorded), and it would be the first composed URL in a file whose
// whole argument is that it composes none. So each signal is its own whole
// URL, in its own secret, and an absent one fails closed with the name.

import { pathToFileURL } from "node:url";

import { CHECKS, findCheck, secretName } from "./lib/alert-checks.mjs";
import { runUrl } from "./lib/alert-verdict.mjs";

const POST_TIMEOUT_MS = 10_000;

/**
 * @returns {Promise<{code: number, url: string|null, problems: string[]}>}
 */
export async function postHeartbeat({
  check,
  signal = "success",
  env = process.env,
  fetchImpl = fetch,
  log = console,
} = {}) {
  const fail = (problems) => {
    for (const p of problems) log.error(`FAIL  ${p}`);
    return { code: 1, url: null, problems };
  };

  // A name that is not in the table is a typo, or a check nobody created. Both
  // end the same way — the receiver never hears from this job and pages on
  // silence, on a schedule, for ever — and the message a reader gets from a
  // 404 on a URL they cannot see is not the message that leads them here.
  const known = findCheck(check);
  if (!known) {
    const names = CHECKS.filter((c) => c.party === "registry").map((c) => c.name).join(", ");
    return fail([
      `there is no receiver check called ${JSON.stringify(check)} in bot/lib/alert-checks.mjs. ` +
      `The registry posts to: ${names}. A check this estate posts to is created by the owner with the rest ` +
      `(registry plan RC-R1-0), and adding a poster before adding the check is how a check ends up paging ` +
      `about silence nobody meant.`,
    ]);
  }
  if (!known.signals.includes(signal)) {
    return fail([`check ${check} takes ${known.signals.join(" and ")}, not ${JSON.stringify(signal)}`]);
  }
  if (known.party !== "registry") {
    return fail([
      `check ${check} is posted to by ${known.party}, not by this repository. Environment \`alerts\` holds no ` +
      `URL for it and must not: no credential the registry holds may resolve a check the plugins service posts ` +
      `to, and none of the service's may resolve a registry check (attack M-5).`,
    ]);
  }

  const name = secretName(check, signal);
  const url = env[name];
  if (typeof url !== "string" || url.trim() === "") {
    return fail([
      `${name} is not set in this job. It carries the WHOLE ping URL of receiver check ${check}, and it is a ` +
      `secret of environment \`alerts\`, which the owner creates with the receiver account (registry plan ` +
      `RC-R1-0, §2.12's R1 row). Nothing is posted, and this step is red rather than letting a check that was ` +
      `never pinged look like a check that is healthy.`,
    ]);
  }
  if (!url.startsWith("https://")) {
    return fail([`${name} is not an https URL; a ping sent in clear is a ping anybody on the path can forge`]);
  }

  // A body only so the receiver's own log says which run pinged it. It is the
  // run URL and nothing else, through the same grammar a verdict's `run` goes
  // through, because `GITHUB_SERVER_URL` is a workflow-settable string.
  const body = runUrl(env) ?? "";

  let res;
  try {
    res = await fetchImpl(url, {
      method: "POST",
      headers: { "Content-Type": "text/plain", "User-Agent": "astra-registry-heartbeat" },
      body,
      signal: AbortSignal.timeout(POST_TIMEOUT_MS),
    });
  } catch (e) {
    return fail([`the receiver could not be reached for check ${check}: ${String(e.message ?? e)}`]);
  }
  if (!res.ok) return fail([`the receiver answered HTTP ${res.status} for check ${check}`]);

  log.log(`ok    ${signal} posted for receiver check ${check}`);
  return { code: 0, url, problems: [] };
}

function parseArgs(argv) {
  const args = { check: null, signal: "success" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") args.check = argv[++i];
    else if (a === "--signal") args.signal = argv[++i];
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (!args.check) {
    console.error("FAIL  --check <name> is required");
    return 1;
  }
  const out = await postHeartbeat(args);
  return out.code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
