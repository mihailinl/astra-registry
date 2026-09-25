#!/usr/bin/env node
// RC-R1-0's reach assertion, the registry's half: no ping credential the
// registry holds resolves a check the plugins service posts to (attack M-5).
//
//     node tools/reach-assertion.mjs --out verdict.json
//
// Run by `.github/workflows/reach-assertion.yml`, dispatched at each exit walk,
// in environment `alerts`, which is the one place the credentials are. It
// prints secret names, check names, HTTP statuses and fingerprints, and never a
// credential: a fingerprint is the first 16 hex of SHA-256 over a check's
// 122-bit random UUID, which cannot be turned back into the UUID.
//
// ── WHAT THE RECEIVER ANSWERS, AND WHY THE PLAN'S 404 WAS THE WRONG ONE ─────
//
// The plan said: POST each registry credential at each service check name and
// record the 404. Lane S16 measured healthchecks.io on 2026-09-25, with values
// that address no check:
//
//     hc-ping.com/<uuid>/<name>          400 invalid url format
//     hc-ping.com/<uuid>/start/<name>    400 invalid url format
//     hc-ping.com/<ping key>/<name>      404 not found   (no check has that slug)
//     hc-ping.com/<uuid>                 200 OK (not found)
//
// So a healthy credential, one whole `hc-ping.com/<uuid>` URL, answers 400, and
// 404 is what a LEAKED PING KEY answers. The literal method recorded the
// failure as the pass. Here the healthy answer is `400 invalid url format`, and
// its failure is a 404 or any 2xx (or anything else the receiver says).
//
// ── WHAT THE POST CANNOT SEE, AND WHAT SEES IT ─────────────────────────────
//
// A service check's own UUID URL, pasted into an `alerts` secret by mistake
// (the trap at the top of ops `runbooks/registry-alerts.md`), also answers 400
// to the POST. Two things see what the POST cannot:
//
//   1. **Shape, offline and first.** Each credential must be one whole
//      `https://hc-ping.com/<uuid>` URL, with `/start` exactly on a `start`
//      signal's secret. Anything else is never POSTed: were it a ping-key base
//      and a service check had a slug, the POST itself would ping — and arm —
//      that service check. One UUID may not sit behind two checks' secrets, and
//      a check's `start` secret must be its own UUID's.
//   2. **Fingerprints, compared off this repository.** Each credential's
//      fingerprint is printed. The operator compares them with the same
//      fingerprints of the receiver's checks, computed with the receiver's API
//      key on the owner's desk: each must match its own check and no service
//      check's. The key never enters this repository (SERVE-104a), so that
//      half cannot run here.
//
// It posts no heartbeat (it is not a schedule) and pages only when red.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { CHECKS, secretName } from "../bot/lib/alert-checks.mjs";
import { VERDICT_SCHEMA, runUrl } from "../bot/lib/alert-verdict.mjs";

/** The verdict's receiver-check name. It is no receiver check: this job posts no heartbeat. */
export const CHECK = "reach-assertion";

// Floors, written before the loops they guard: every loop below over an empty
// table is green about nothing. Fourteen ping URLs are what `alerts` holds on
// 2026-09-25 (thirteen registry checks, `alarm-ack` twice); four service check
// names are what contract 2.12.0 records. Floors, not equalities: a check
// added is not a broken walk.
export const CREDENTIAL_FLOOR = 14;
export const SERVICE_NAME_FLOOR = 4;

export const CREDENTIAL_SHAPE =
  /^https:\/\/hc-ping\.com\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(\/start)?$/;

/** The healthy answer to `<credential>/<service check name>`, measured 2026-09-25. */
export const HEALTHY = { status: 400, body: "invalid url format" };

// What hc-ping.com reads after a UUID as a signal: `/start`, `/fail`, `/log`
// and an exit status. A service check with such a name would turn the POST
// into a signal to the REGISTRY's check, so none is posted at all.
const SIGNAL_WORD = /^(start|fail|log|[0-9]+)$/;

const UUID_ANYWHERE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

export const USER_AGENT = "astra-registry-reach-assertion";
const POST_TIMEOUT_MS = 10_000;

/** @returns {string} the first 16 hex of SHA-256 over a UUID, as ops' receiver-side half computes it */
export function fingerprint(uuid) {
  return crypto.createHash("sha256").update(uuid).digest("hex").slice(0, 16);
}

/** Every ping credential the registry holds: one per registry check and signal. */
export function credentials(checks = CHECKS) {
  return checks
    .filter((c) => c.party === "registry" && typeof c.name === "string")
    .flatMap((c) => c.signals.map((signal) => ({ check: c.name, signal, secret: secretName(c.name, signal) })));
}

/** Every service check name recorded, which is what each credential is POSTed at. */
export function serviceNames(checks = CHECKS) {
  return checks.filter((c) => c.party === "plugins-service" && typeof c.name === "string").map((c) => c.name);
}

const label = (c) => (c.signal === "success" ? c.check : `${c.check} (${c.signal})`);

/**
 * @returns {Promise<{status: "green"|"red", codes: string[], fingerprints: object[], posts: number, lines: string[]}>}
 */
export async function reach({ env = process.env, fetchImpl = fetch, checks = CHECKS } = {}) {
  const codes = new Set();
  const lines = [];
  const red = (code, line) => { codes.add(code); lines.push(`RED   ${line}`); };

  const creds = credentials(checks);
  const service = serviceNames(checks);
  if (creds.length < CREDENTIAL_FLOOR) {
    red("REACH_FLOOR_CREDENTIALS", `the table names ${creds.length} registry ping credential(s), under the floor of ${CREDENTIAL_FLOOR}`);
  }
  if (service.length < SERVICE_NAME_FLOOR) {
    red("REACH_FLOOR_SERVICE_NAMES", `the table names ${service.length} service check name(s), under the floor of ${SERVICE_NAME_FLOOR}`);
  }
  for (const name of service.filter((n) => SIGNAL_WORD.test(n))) {
    red("REACH_SERVICE_NAME_IS_A_SIGNAL",
      `service check name ${JSON.stringify(name)} is a word hc-ping.com reads after a UUID as a signal, so the POST ` +
      "would signal the registry's own check; nothing was posted");
  }

  // 1. Shape, offline, before anything leaves the runner.
  const good = [];
  for (const c of creds) {
    const raw = env[c.secret];
    // fetch strips surrounding white space from a URL, and so does this.
    const value = typeof raw === "string" ? raw.trim() : "";
    const m = CREDENTIAL_SHAPE.exec(value);
    if (!value) {
      red("REACH_CREDENTIAL_NOT_ONE_CHECK", `${c.secret} (${label(c)}) is not set in this job; not posted`);
      continue;
    }
    if (!m || Boolean(m[2]) !== (c.signal === "start")) {
      red("REACH_CREDENTIAL_NOT_ONE_CHECK",
        `${c.secret} (${label(c)}) is not one check's whole https://hc-ping.com/<uuid> URL` +
        `${c.signal === "start" ? " followed by /start" : ""}; not posted`);
      continue;
    }
    good.push({ ...c, url: value, fingerprint: fingerprint(m[1]) });
  }
  const byFingerprint = new Map();
  for (const c of good) byFingerprint.set(c.fingerprint, [...(byFingerprint.get(c.fingerprint) ?? []), c]);
  for (const [fp, holders] of byFingerprint) {
    const owners = [...new Set(holders.map((h) => h.check))];
    if (owners.length > 1) {
      red("REACH_CREDENTIAL_SHARED",
        `${holders.map((h) => h.secret).join(" and ")} hold one check's URL (fingerprint ${fp}), so ${owners.join(" and ")} ` +
        "are one check at the receiver: either job keeps both quiet");
    }
  }
  for (const check of new Set(good.map((c) => c.check))) {
    const fps = [...new Set(good.filter((c) => c.check === check).map((c) => c.fingerprint))];
    if (fps.length > 1) {
      red("REACH_START_ELSEWHERE",
        `${check}'s signals carry ${fps.length} different UUIDs (${fps.join(", ")}), so its start goes to a check its ` +
        "success never reaches");
    }
  }
  for (const c of good) lines.push(`ok    ${label(c).padEnd(24)} ${c.secret.padEnd(38)} fingerprint ${c.fingerprint}`);

  // 2. The POST, only when every credential has the shape and every name is safe.
  let posts = 0;
  let healthy = 0;
  if (!codes.size) {
    for (const c of good) {
      for (const name of service) {
        posts++;
        let status = null;
        let body = "";
        try {
          const res = await fetchImpl(`${c.url}/${name}`, {
            method: "POST",
            headers: { "User-Agent": USER_AGENT },
            body: "",
            signal: AbortSignal.timeout(POST_TIMEOUT_MS),
          });
          status = res.status;
          body = String(await res.text()).trim();
        } catch {
          // status stays null: no answer
        }
        if (status === HEALTHY.status && body === HEALTHY.body) {
          healthy++;
          continue;
        }
        const said = status === null
          ? "no answer"
          : `HTTP ${status} ${JSON.stringify(body.replace(UUID_ANYWHERE, "<uuid>").slice(0, 40))}`;
        if (status !== null && status >= 200 && status < 300) {
          red("REACH_SERVICE_CHECK_RESOLVED",
            `${c.secret} (${label(c)}) at ${name}: ${said}. A 2xx means the receiver took this as a ping: a registry ` +
            "credential reaches a service check");
        } else if (status === 404) {
          red("REACH_ANSWERED_404",
            `${c.secret} (${label(c)}) at ${name}: ${said}. A 404 is the answer a ping key gets for a slug, so the ` +
            "receiver did not read this credential as one check's UUID");
        } else {
          red("REACH_UNEXPECTED_ANSWER",
            `${c.secret} (${label(c)}) at ${name}: ${said}, not ${HEALTHY.status} ${JSON.stringify(HEALTHY.body)}`);
        }
      }
    }
  } else {
    lines.push("note  nothing was posted: a credential or a name above is refused, and a POST of it could reach a check");
  }
  lines.push(
    `${codes.size ? "RED" : "ok "}   ${good.length} of ${creds.length} credential(s) one whole hc-ping.com/<uuid> URL; ` +
    `${healthy} of ${posts} POST(s) answered ${HEALTHY.status} ${JSON.stringify(HEALTHY.body)} ` +
    `(service check names: ${service.join(", ") || "none"})`,
  );
  lines.push(
    "note  the other half is off this repository: each fingerprint above must be its own check's, and no service " +
    "check's, as the receiver's API computes them on the owner's desk (ops runbooks/registry-alerts.md §6 (iii))",
  );
  return {
    status: codes.size ? "red" : "green",
    codes: [...codes],
    fingerprints: good.map(({ check, signal, secret, fingerprint: fp }) => ({ check, signal, secret, fingerprint: fp })),
    posts,
    lines,
  };
}

/** The alert action's verdict: fixed codes and the run URL, nothing else. */
export function verdictOf(result, env = process.env) {
  const verdict = { schema: VERDICT_SCHEMA, check: CHECK, status: result.status };
  if (result.codes.length) verdict.codes = result.codes;
  const run = runUrl(env);
  if (run) verdict.run = run;
  return verdict;
}

async function main(argv) {
  let out = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") out = argv[++i];
    else {
      console.error(`FAIL  unknown argument ${JSON.stringify(argv[i])}`);
      return 2;
    }
  }
  if (!out) {
    console.error("FAIL  --out <verdict.json> is required");
    return 2;
  }
  const result = await reach();
  for (const line of result.lines) console.log(line);
  fs.writeFileSync(path.resolve(out), `${JSON.stringify(verdictOf(result))}\n`);
  return result.status === "red" ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
