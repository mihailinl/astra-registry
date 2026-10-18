// SERVE-39's catalogue-host half, and the path probes SERVE-52 and INV-40 are
// checked by (registry plan RC-R2-3, commit (i)).
//
// ── what the host is held to ───────────────────────────────────────────────
//
// `https://registry.minice.ai/registry/v1/` serves the four signed-set
// documents (SERVE-1; DEC-18), each "exactly that file's bytes at the last
// `signed` commit the service accepted, identical after content decoding,
// except a withdrawal list past its `expires_at`" (INV-26). SERVE-39 fails
// when a document the host serves differs from `signed`'s head more than 30
// minutes after that head was committed. That is the Pages half's rule with
// two differences, and both are why this is a module of its own rather than a
// second base URL handed to `serve39`:
//
//   * **no latch.** Pages carries D5's arming latch because every shipped
//     0.2.x daemon reads it and arming is one-way in the field. The host has
//     no old clients: it serves `signed`'s withdrawal list from its first
//     answer, so all four documents are compared from the first run;
//   * **an expired list is not served** (TRUST-38; TRUST-46). When `signed`'s
//     head carries a list whose `expires_at` has passed, the correct answer
//     from the host is NOT those bytes, and a 200 carrying them is the breach.
//
// **Since 5.4.0 (DEC-18) there are two catalogue hosts, not one.**
// `registry.minice.ai` is served through Cloudflare, proxied in front of the
// same origin; from 2026-10-15 ~19:50Z, `registry.knice.tech` is a new RU
// client's compiled URL, served direct from the RU box because Cloudflare is
// throttled in Russia. DEC-18 says plainly that "from the day it serves, a
// requirement on 'both hosts' or on the catalogue host reads it too", so the
// byte-equality rule above runs unchanged over each of `CATALOGUE_HOSTS`,
// each reported on its own: `serve39Host` takes a `host` and `serve39Hosts`
// below runs it once per host and merges the findings, so one host being down
// never hides what the other reports.
//
// **The path probes stay scoped to `registry.minice.ai` alone.** M-12's
// refusal below is specific to that origin's own judgement of direct peers
// through its CDN; the RU box is a different origin with no such history, and
// DEC-18 does not ask for the probes to cover it.
//
// DEC-18 also binds a CDN's cache to the origin's own `max-age` ("MUST NOT
// keep a copy past" it). `hostAgeVerdict`/`hostAgeVerdicts`, beside
// `serve39Host`, check that bound from each host's `Age` and `Cache-Control`
// response headers — as a warning that does not fail the job today (see
// `AGE_OVER_MAX_AGE_IS_FATAL`).
//
// ── what the probes are for, and the one address they may be sent to ───────
//
// SERVE-52: nothing under `registry/v1/` but the four documents. INV-40: no
// plugin artifact anywhere on the host. A CDN offers no directory listing, so
// both are checked by asking for named paths and expecting each to be
// unserved (SERVE-39's Why). The list is fixed, has a floor of eleven, and
// gains the name of one real artifact from the catalogue at four prefixes.
//
// **It is sent to `registry.minice.ai` through the CDN and to nothing else**
// (attack M-12). Every name on it is a 404 at the origin. The origin's vhost
// judges direct peers, and its judgement was written for "our own probes,
// which read the five fixed names": the eleventh distinct 404 from one address
// overflows `http-probing` and bans that address port-blind for four hours
// across api, auth and both storefronts. Through the CDN the lines go to a log
// crowdsec never acquires. So:
//
//   * the base is a constant, as `PAGES_BASE` is, and `probeExtraPaths`
//     refuses any other — the suite hands it a `fetchImpl`, never a host;
//   * every URL it builds is checked, after resolution, to name that host, so
//     a catalogue filename cannot steer a request elsewhere;
//   * there is no `--resolve`, no address and no lookup override here at all.
//     The name is resolved by the runner's resolver, which follows the public
//     CNAME to gcore. **What this module does not do** is refuse an answer
//     from an origin address, as ops' D6 prober does with its configured
//     `origin_addresses`: those addresses are the plugins service's, and this
//     repository is public. A resolver that returned the origin would put
//     these probes on the acquired log, and ops' prober is where that case
//     pages.

import { createHash } from "node:crypto";

import { SIGNED_FILES } from "../signer/plan.mjs";
import { GRACE_MINUTES, finding, minutesSince, verdict, withinGrace } from "./report.mjs";

/** The primary catalogue host's name (DEC-18). Also where SERVE-52's and INV-40's probes go, and nowhere else (M-12). */
export const HOST = "registry.minice.ai";

/** What a new client fetches, minus the file. The paths in SIGNED_FILES are relative to it. */
export const HOST_BASE = `https://${HOST}/`;

/** The RU edition's catalogue host (DEC-18), served direct from the RU box from 2026-10-15 ~19:50Z. */
export const RU_HOST = "registry.knice.tech";

/**
 * Every host DEC-18 means by "both hosts" or "the catalogue host", from the
 * day each one serves. `registry.minice.ai` is first; `registry.knice.tech`
 * joins it in this list at the commit that adds it here, which is this one.
 */
export const CATALOGUE_HOSTS = Object.freeze([HOST, RU_HOST]);

/**
 * The suffix a non-primary catalogue host's codes carry, so the channel's
 * compact (de-duplicated) code list still shows which host a finding was
 * about, without changing `HOST`'s own codes at all — `serve39Host`'s default
 * `host` is `HOST`, so every code `registry.minice.ai` can raise is spelled
 * exactly as it was before DEC-18 added a second host.
 */
const HOST_CODE_SUFFIX = Object.freeze({ [HOST]: "", [RU_HOST]: "_RU" });

const FETCH_TIMEOUT_MS = 20_000;

// ── SERVE-39 on an armed host (registry plan SERVE-39; contract INV-30,
// SERVE-108, SERVE-109, Table 5-N; since 6.0.0) ─────────────────────────────
//
// Since 6.0.0 a catalogue host MAY require a catalogue ticket for
// `registry/v1/index.json` (INV-30) and for nothing else that this file
// compares — `registry/v1/trust.json`, `registry/v1/revocations.json` and
// `registry/v1/root.json` are never gated (OD-6), so a 422 on any of those is
// still a failure, exactly as a 404 or a 500 always was.
//
// A ticketless read of `index.json` answering 422 with a JSON body whose
// `error` is `"unauthenticated"` and a `Cache-Control` naming `no-store` is
// the armed state SERVE-39 reads as "not a difference" rather than as the
// unreachable/redirect finding below. Anything else — a 422 missing
// `no-store`, a 422 naming another `error`, any other status — is not that
// shape, so it falls straight through to the finding every other failure has
// always gotten: SERVE-39 says plainly that "one answering it without
// no-store is a failure", and "stays a failure, as today" needs no new code.
//
// On the armed state, `index.json`'s own bytes cannot be read ticketless, so
// SERVE-39 compares the host with `signed` through its witness instead
// (`registry/v1/served.json`, SERVE-109; Table 5-N): `index.sha256` against
// the SHA-256 of `signed`'s head `index.json`, and `index.serial` against its
// `signed.serial`. `stats` is in no `signed` commit and is not compared
// (SERVE-39's own words) — this file never fetches `stats/v1/stats.json`,
// since nothing here has ever compared it, armed or not.
//
// A witness SERVE-109 calls a failure — missing, unreadable, the wrong
// schema or members, written more than 15 minutes before the read, or naming
// bytes other than `signed`'s head — is read again once, after SERVE-109's
// 60 s, before SERVE-39 reports it; the second read is final.

/** `astra.plugins.served/1`'s path (SERVE-109), relative to the host's base. */
export const SERVED_JSON_PATH = "registry/v1/served.json";

/** SERVE-109's freshness bound: a witness written before this, read now, is a witness failure. */
export const WITNESS_GRACE_MINUTES = 15;

/** SERVE-109's "reads it again after 60 s before it alarms on a difference". */
export const WITNESS_REREAD_MS = 60_000;

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Is `got` — an already-failed read of `index.json` — INV-30's armed state:
 * 422, a JSON body whose `error` is `"unauthenticated"`, and a `Cache-Control`
 * naming `no-store`? Anything else returns `false`, so the caller's existing
 * unreachable/redirect branch reports it exactly as it always has — SERVE-39's
 * "stays a failure, as today" needs no second code path.
 */
export function isArmedGateRefusal(got) {
  if (!got || got.ok || got.status !== 422) return false;
  let body;
  try {
    body = JSON.parse(got.body ?? "");
  } catch {
    return false;
  }
  return Boolean(body) && body.error === "unauthenticated" && /no-store/i.test(String(got.cacheControl ?? ""));
}

/**
 * One read of `served.json`, judged against `signed`'s head. `null` means the
 * witness checks out; otherwise the sentence SERVE-39 reports.
 */
function witnessProblem({ fetched, head, now, graceMinutes = WITNESS_GRACE_MINUTES }) {
  if (!fetched?.ok) return `could not be read (${fetched?.error ?? "no answer"})`;
  let doc;
  try {
    doc = JSON.parse(fetched.body);
  } catch (e) {
    return `is not readable JSON (${e.message})`;
  }
  if (doc?.schema !== "astra.plugins.served/1") {
    return `names schema ${JSON.stringify(doc?.schema ?? null)}, not astra.plugins.served/1 (Table 5-N)`;
  }
  const serial = doc?.index?.serial;
  const sha = doc?.index?.sha256;
  const at = doc?.at;
  if (!Number.isInteger(serial)) return "index.serial is missing or not an integer (Table 5-N)";
  if (typeof sha !== "string" || !/^[0-9a-f]{64}$/.test(sha)) return "index.sha256 is missing or not 64 lowercase hex (Table 5-N)";
  if (typeof at !== "string" || !Number.isFinite(Date.parse(at))) return "`at` is missing or unreadable (Table 5-N)";
  const age = minutesSince(at, now);
  if (age === null || age > graceMinutes) {
    return `was written ${age === null ? "at an unreadable time" : `${age.toFixed(1)} minutes`} before this read, past SERVE-109's ${graceMinutes}-minute bound`;
  }
  const wantHex = createHash("sha256").update(String(head.bytes?.index ?? ""), "utf8").digest("hex");
  if (sha !== wantHex) return `names index.sha256 ${sha}, not \`signed\`@${head.sha.slice(0, 12)}'s index.json (${wantHex})`;
  const wantSerial = head.documents?.index?.signed?.serial;
  if (Number.isInteger(wantSerial) && serial !== wantSerial) {
    return `names index.serial ${serial}, not \`signed\`@${head.sha.slice(0, 12)}'s ${wantSerial}`;
  }
  return null;
}

/** Fetch `served.json` once. Never thrown: a network failure is `{ok: false}`, as `fetchHost` treats one. */
export async function fetchWitness({ host = HOST, fetchImpl = fetch } = {}) {
  const url = new URL(SERVED_JSON_PATH, `https://${host}/`).toString();
  try {
    const res = await fetchImpl(url, {
      cache: "no-store",
      redirect: "manual",
      headers: { "Cache-Control": "no-cache", Pragma: "no-cache", "User-Agent": "astra-registry-served-set" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (res.status !== 200) return { ok: false, url, status: res.status, body: null, error: `HTTP ${res.status}` };
    return { ok: true, url, status: 200, body: await res.text(), error: null };
  } catch (e) {
    return { ok: false, url, status: null, body: null, error: String(e?.message ?? e) };
  }
}

/**
 * The armed-host comparison (SERVE-39; SERVE-109): `served.json` read once,
 * and read again after `WITNESS_REREAD_MS` on any problem, with the second
 * read final either way.
 *
 * @param {{host: string, head: object, now: string, fetchImpl?: typeof fetch, sleepImpl?: (ms: number) => Promise<void>}} o
 */
export async function armedWitnessVerdict({ host, head, now, fetchImpl = fetch, sleepImpl = defaultSleep }) {
  let fetched = await fetchWitness({ host, fetchImpl });
  let problem = witnessProblem({ fetched, head, now });
  let rereadAttempted = false;
  if (problem) {
    rereadAttempted = true;
    await sleepImpl(WITNESS_REREAD_MS);
    fetched = await fetchWitness({ host, fetchImpl });
    problem = witnessProblem({ fetched, head, now });
  }
  return { problem, fetched, rereadAttempted };
}

/**
 * The fixed names SERVE-52 and INV-40 are probed with. None may be served.
 *
 * Under `registry/v1/`: what a mis-configured static root or a sloppy deploy
 * leaves beside the four — detached signatures, backups, editor files, a
 * directory index, the stats document one directory too high, a VCS
 * directory. Anywhere: a plugin bundle at the paths an artifact mirror would
 * use. The catalogue adds one real artifact name at the same four prefixes.
 */
export const EXTRA_PATHS = Object.freeze([
  "registry/v1/",
  "registry/v1/extra.json",
  "registry/v1/index.json.sig",
  "registry/v1/revocations.json.sig",
  "registry/v1/index.json.bak",
  "registry/v1/index.json~",
  "registry/v1/stats.json",
  "registry/v1/moderation-log.json",
  "registry/v1/.git/HEAD",
  "plugin.astraplugin",
  "plugins/plugin.astraplugin",
  "download/plugin.astraplugin",
  "releases/plugin.astraplugin",
]);

/** The plan's floor: eleven or more distinct names (RC-R2-3; attack M-12). */
export const EXTRA_PATHS_FLOOR = 11;

/** Where an artifact mirror would put a bundle (INV-40). */
export const ARTIFACT_PREFIXES = Object.freeze(["", "plugins/", "download/", "releases/"]);

const ARTIFACT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*\.astraplugin$/;

if (new Set(EXTRA_PATHS).size !== EXTRA_PATHS.length || EXTRA_PATHS.length < EXTRA_PATHS_FLOOR) {
  throw new Error(`EXTRA_PATHS holds ${new Set(EXTRA_PATHS).size} distinct names and the floor is ${EXTRA_PATHS_FLOOR}`);
}

class Refused extends Error {}

/**
 * Fetch the four documents from a catalogue host.
 *
 * `redirect: "manual"`: INV-26 asks for the file's bytes at this address, and
 * a 3xx is the host sending the reader somewhere else, which is reported as
 * itself rather than followed into a comparison of someone else's bytes.
 *
 * `age` and `cacheControl` are the raw `Age` and `Cache-Control` response
 * headers, read on every status (not only 200): `hostAgeVerdict` (DEC-18)
 * only ever reads them off a 200, but `isArmedGateRefusal` (SERVE-39, since
 * 6.0.0) reads `cacheControl` off a 422, and `null` where a header is absent
 * is not itself a finding either way, only something that check cannot
 * compare. `body` is likewise read on every status, since a gated refusal's
 * JSON `error` is read from it too (INV-30; SERVE-108).
 *
 * `head` and `now`, when given, let an armed `index.json` (SERVE-39's armed
 * state; `isArmedGateRefusal`) be compared with `signed` through
 * `served.json` instead (SERVE-109; Table 5-N): the result lands at
 * `served.witness`, resolved — reread included — before this returns, so
 * `serve39Host` stays a synchronous read of already-settled data like every
 * other comparison in this file. Omitted (as every call before 6.0.0 omitted
 * them), `served.witness` is simply never set, and nothing else changes.
 *
 * @param {{host?: string, fetchImpl?: typeof fetch, head?: object|null, now?: string, sleepImpl?: (ms: number) => Promise<void>}} opts
 */
export async function fetchHost({ host = HOST, fetchImpl = fetch, head = null, now = new Date().toISOString(), sleepImpl = defaultSleep } = {}) {
  const base = `https://${host}/`;
  const served = {};
  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    const url = new URL(rel, base).toString();
    try {
      const res = await fetchImpl(url, {
        cache: "no-store",
        redirect: "manual",
        headers: { "Cache-Control": "no-cache", Pragma: "no-cache", "User-Agent": "astra-registry-served-set" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      const age = typeof res.headers?.get === "function" ? res.headers.get("age") : null;
      const cacheControl = typeof res.headers?.get === "function" ? res.headers.get("cache-control") : null;
      let body = null;
      try {
        body = await res.text();
      } catch {
        body = null;
      }
      served[name] = res.status === 200
        ? { ok: true, url, status: 200, body, error: null, age, cacheControl }
        : { ok: false, url, status: res.status, body, error: `HTTP ${res.status}`, age, cacheControl };
    } catch (e) {
      served[name] = { ok: false, url, status: null, body: null, error: String(e?.message ?? e), age: null, cacheControl: null };
    }
  }
  if (head?.present && isArmedGateRefusal(served.index)) {
    served.witness = await armedWitnessVerdict({ host, head, now, fetchImpl, sleepImpl });
  }
  return served;
}

/** Fetch the four documents from every catalogue host, keyed by host. */
export async function fetchHosts({ hosts = CATALOGUE_HOSTS, fetchImpl = fetch, head = null, now, sleepImpl } = {}) {
  const byHost = {};
  for (const host of hosts) byHost[host] = await fetchHost({ host, fetchImpl, head, now, sleepImpl });
  return byHost;
}

/** The withdrawal list's `expires_at`, if `signed`'s head carries a readable one. */
function listExpiry(head) {
  const at = head?.documents?.revocations?.signed?.expires_at;
  return typeof at === "string" && Number.isFinite(Date.parse(at)) ? at : null;
}

/**
 * SERVE-39 for one catalogue host, over facts and nothing else.
 *
 * Defaults to `HOST` (`registry.minice.ai`) so every call and test from
 * before DEC-18's second host is unchanged, byte for byte, code for code.
 *
 * @param {object} o
 * @param {string} [o.host]          which catalogue host this is (DEC-18)
 * @param {object} o.head           from fetchSignedHead
 * @param {string|null} o.headClock the `signed` head's committer time, RFC 3339
 * @param {object} o.served         from fetchHost
 * @param {string} o.now
 * @param {number} [o.graceMinutes]
 */
export function serve39Host({ host = HOST, head, headClock, served, now, graceMinutes = GRACE_MINUTES }) {
  const findings = [];
  const waiting = [];
  const notes = [];
  const hexes = [];
  const suffix = HOST_CODE_SUFFIX[host] ?? "";

  if (!head?.present) {
    // Unlike Pages, there is no "before the signer" state to wait out: this
    // comparison lands after `signed` has existed for weeks. A missing branch
    // is a finding.
    findings.push(finding(
      "SERVE_39_NO_SIGNED_BRANCH",
      `there is no \`signed\` branch to compare ${host} with, so the catalogue host is serving bytes nothing publishes.`,
    ));
    return verdict({ findings, waiting, hexes, notes });
  }

  hexes.push(head.sha);
  const age = minutesSince(headClock, now);
  const excused = withinGrace(headClock, now, graceMinutes);
  const expiry = listExpiry(head);
  const expired = expiry !== null && Date.parse(expiry) <= Date.parse(now);
  notes.push(
    `${host} against \`signed\`@${head.sha.slice(0, 12)}, committed ${headClock}, ` +
    `${age === null ? "an unreadable time" : `${age.toFixed(1)} minutes`} ago; its list expires ${expiry ?? "at an unreadable time"}`,
  );

  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    const want = head.bytes?.[name];
    const got = served?.[name];
    if (typeof want !== "string") {
      findings.push(finding(
        "SERVE_39_SIGNED_INCOMPLETE",
        `\`signed\`@${head.sha.slice(0, 12)} has no ${rel}; a published commit missing one of D2's four files is ` +
        "a commit no client can be served from.",
      ));
      continue;
    }

    if (name === "revocations" && expired) {
      // TRUST-38: the service removes an expired list from the origin, and
      // TRUST-46: the edge does not serve it stale. So the correct answer is
      // "not these bytes", and a 200 with them is the breach — with no grace,
      // because the list is already past the moment a client must stop
      // trusting it.
      if (got?.ok && got.body === want) {
        findings.push(finding(
          `SERVE_39_HOST_EXPIRED_LIST${suffix}`,
          `${got.url} still serves \`signed\`@${head.sha.slice(0, 12)}'s withdrawal list, whose expires_at ${expiry} ` +
          `has passed. TRUST-38 removes an expired list from the origin and TRUST-46 forbids the edge serving it stale.`,
        ));
      } else {
        notes.push(`\`signed\`'s list expired at ${expiry} and ${host} does not serve it (${got?.error ?? "other bytes"}), as TRUST-38 asks`);
      }
      continue;
    }

    if (name === "index" && !got?.ok && isArmedGateRefusal(got)) {
      // INV-30's armed state (since 6.0.0): a ticketless index.json refuses
      // with 422 unauthenticated and Cache-Control: no-store, which is not a
      // difference (SERVE-39) — the host is compared through served.json
      // instead (SERVE-109; Table 5-N). trust.json, revocations.json and
      // root.json never reach this branch (OD-6: they are never gated, so a
      // 422 on one of them falls through to the finding below, as always).
      const w = served?.witness;
      if (!w || w.problem) {
        findings.push(finding(
          `SERVE_39_HOST_WITNESS_FAILS${suffix}`,
          `${host} refuses a ticketless ${rel} as INV-30's armed state (422 unauthenticated, Cache-Control: ` +
          `no-store), so SERVE-39 compares it through served.json instead — and that witness ${w?.problem ?? "was never read"} ` +
          "(SERVE-109). A gate the registry cannot compare from outside is one the registry cannot vouch for.",
        ));
      } else {
        notes.push(
          `${host} is armed (INV-30): a ticketless ${rel} answers 422 unauthenticated with Cache-Control: no-store, ` +
          `and served.json's witness names \`signed\`@${head.sha.slice(0, 12)}'s index.json, read ${w.rereadAttempted ? "on its reread" : "on the first read"}`,
        );
      }
      continue;
    }

    if (!got?.ok) {
      const code = typeof got?.status === "number" && got.status >= 300 && got.status < 400
        ? `SERVE_39_HOST_REDIRECT${suffix}`
        : `SERVE_39_HOST_UNREACHABLE${suffix}`;
      findings.push(finding(
        code,
        `${got?.url ?? rel} could not be read as the document itself: ${got?.error ?? "no answer"}. Every new client ` +
        "that refreshes now gets the same answer.",
      ));
      continue;
    }
    if (got.body === want) continue;
    if (excused) {
      notes.push(`${rel} on ${host} is not \`signed\`'s yet, ${age?.toFixed(1)} minutes in; the service has ${graceMinutes}`);
      continue;
    }
    findings.push(finding(
      `SERVE_39_HOST_DRIFT${suffix}`,
      `${host} serves a ${rel} that is not \`signed\`@${head.sha.slice(0, 12)}'s, ` +
      `${age === null ? "at an unreadable time" : `${age.toFixed(0)} minutes`} after that commit (served ` +
      `${got.body.length} bytes, \`signed\` holds ${want.length}). A split view between the branch and the ` +
      "catalogue host is what SERVE-39 exists to find.",
    ));
  }
  return verdict({ findings, waiting, hexes, notes });
}

/**
 * SERVE-39's catalogue-host half, over every host DEC-18 means by "the
 * catalogue host" or "both hosts", each compared and reported on its own.
 *
 * `head.present` is checked once, not once per host: there being no `signed`
 * branch is one finding, not a duplicate per host, since it says nothing
 * about either host's serving and everything about `signed`.
 *
 * @param {object} o
 * @param {string[]} [o.hosts]
 * @param {object} o.head
 * @param {string|null} o.headClock
 * @param {Record<string, object>} o.servedByHost keyed by host, each from `fetchHost`
 * @param {string} o.now
 * @param {number} [o.graceMinutes]
 */
export function serve39Hosts({ hosts = CATALOGUE_HOSTS, head, headClock, servedByHost, now, graceMinutes = GRACE_MINUTES }) {
  if (!head?.present) return serve39Host({ host: hosts[0] ?? HOST, head, headClock, served: {}, now, graceMinutes });
  const findings = [];
  const waiting = [];
  const notes = [];
  const hexes = [];
  for (const host of hosts) {
    const v = serve39Host({ host, head, headClock, served: servedByHost?.[host] ?? {}, now, graceMinutes });
    findings.push(...v.findings);
    waiting.push(...v.waiting);
    hexes.push(...v.hexes);
    notes.push(...v.notes);
  }
  return verdict({ findings, waiting, hexes, notes });
}

/**
 * DEC-18: "a CDN's cache MUST NOT keep a copy past the origin's `max-age`" —
 * bytes that are correct (serve39Host already catches a BYTE difference) but
 * STALE at the edge past the bound the origin set for them.
 *
 * `AGE_GRACE_SECONDS` is DEC-18's own 30 s grace on top of `max-age`.
 */
const AGE_GRACE_SECONDS = 30;

/**
 * The one constant that promotes `SERVE_39_HOST_AGE_OVER_MAX_AGE` from a
 * warning (printed, job stays green) to a finding (job goes red).
 *
 * **2026-10-15: `false`, on purpose, and that is a known gap, not a design
 * choice to keep.** Measured today, gcore serves `registry.minice.ai` with
 * `Age` 190–1264 s against whatever `max-age` the origin sends — already well
 * past any reasonable grace — so a failing version of this check would be red
 * from the moment it merged, for a cause nobody has fixed yet: either gcore's
 * cache configuration, or the already-planned move of that host's traffic
 * behind Cloudflare (DEC-18). Flip this to `true` once one of those lands, or
 * once the operator decides the warning has stood long enough on its own;
 * nothing else in this file needs to change.
 */
export const AGE_OVER_MAX_AGE_IS_FATAL = false;

function parseMaxAgeSeconds(cacheControl) {
  const m = /(?:^|,)\s*max-age=(\d+)/i.exec(String(cacheControl ?? ""));
  return m ? Number(m[1]) : null;
}

/**
 * DEC-18's Age-vs-max-age bound, for one host's four documents.
 *
 * Silent (a note, never a finding) wherever `Age` or `max-age` is unreadable:
 * a host served direct from its origin, with no CDN in front of it, may carry
 * neither header at all, and that is correct, not a fault this check can see.
 * `served` entries that `serve39Host` already reports as unreachable or
 * redirected are skipped here too — one finding per cause, not two.
 *
 * @param {{host?: string, served: object}} o
 */
export function hostAgeVerdict({ host = HOST, served }) {
  const findings = [];
  const notes = [];
  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    const got = served?.[name];
    if (!got?.ok) continue;
    // `Number(null)` is 0, not NaN, and 0 is a finite age that would pass the
    // check below for a header that was never there — so a null/absent `Age`
    // is excluded before Number() ever sees it, not folded into the same
    // "unreadable" branch by its arithmetic.
    const ageSeconds = got.age == null ? NaN : Number(got.age);
    const maxAge = parseMaxAgeSeconds(got.cacheControl);
    if (!Number.isFinite(ageSeconds) || maxAge === null) {
      notes.push(
        `${host} ${rel}: no readable Age/max-age to hold to DEC-18's bound ` +
        `(Age ${got.age ?? "absent"}, Cache-Control ${got.cacheControl ?? "absent"})`,
      );
      continue;
    }
    if (ageSeconds > maxAge + AGE_GRACE_SECONDS) {
      const f = finding(
        "SERVE_39_HOST_AGE_OVER_MAX_AGE",
        `${got.url}: Age ${ageSeconds}s is past max-age ${maxAge}s plus DEC-18's ${AGE_GRACE_SECONDS}s grace — a CDN ` +
        `cache held this document ${ageSeconds - maxAge}s longer than the origin allowed (warning only; see ` +
        "AGE_OVER_MAX_AGE_IS_FATAL).",
      );
      if (AGE_OVER_MAX_AGE_IS_FATAL) findings.push(f);
      else notes.push(`WARN  ${f.code}: ${f.message}`);
    } else {
      notes.push(`${host} ${rel}: Age ${ageSeconds}s is within max-age ${maxAge}s (+${AGE_GRACE_SECONDS}s grace)`);
    }
  }
  return verdict({ findings, notes });
}

/** The Age-vs-max-age check, over every catalogue host, each reported on its own. */
export function hostAgeVerdicts({ hosts = CATALOGUE_HOSTS, servedByHost }) {
  const findings = [];
  const notes = [];
  for (const host of hosts) {
    const v = hostAgeVerdict({ host, served: servedByHost?.[host] ?? {} });
    findings.push(...v.findings);
    notes.push(...v.notes);
  }
  return verdict({ findings, notes });
}

/**
 * The one real artifact name the probes add, from `signed`'s catalogue.
 *
 * The first bundle `filename`, sorted, of any release in the catalogue
 * (`signed.plugins[].releases[].artifacts.<platform>.filename`) that is a plain
 * `<name>.astraplugin`. The filename is the catalogue's, and the catalogue is
 * authors' text, so a name that is anything else — a slash, a dot-dot, a
 * query — is not probed at all.
 */
export function artifactNameFrom(index) {
  const names = new Set();
  for (const p of index?.signed?.plugins ?? []) {
    for (const r of p?.releases ?? []) {
      for (const a of Object.values(r?.artifacts ?? {})) {
        if (typeof a?.filename === "string" && ARTIFACT_NAME.test(a.filename)) names.add(a.filename);
      }
    }
  }
  return [...names].sort()[0] ?? null;
}

/** Every path the probes ask for: the fixed list, then the artifact name at each prefix. */
export function probePaths(artifactName) {
  const out = [...EXTRA_PATHS];
  if (artifactName && ARTIFACT_NAME.test(artifactName)) {
    for (const prefix of ARTIFACT_PREFIXES) out.push(`${prefix}${artifactName}`);
  }
  return [...new Set(out)];
}

/**
 * Ask for each probe path and report any the host serves.
 *
 * Refuses, by throwing, any base but `HOST_BASE` and any URL whose host is not
 * `HOST` — the refusal M-12 asks for, and the only way a caller can learn that
 * it pointed the list somewhere it must never go.
 *
 * "Served" is a 2xx, or a 3xx, which is the host pointing a reader at the
 * thing (INV-40's "serve or mirror"). A 4xx is the answer wanted. A 5xx or no
 * answer says nothing either way and is counted, not judged: the documents'
 * comparison above is what pages on a host that is down.
 *
 * @param {{paths: string[], base?: string, fetchImpl?: typeof fetch}} o
 * @returns {Promise<{served: {path: string, status: number}[], unanswered: string[], asked: number}>}
 */
export async function probeExtraPaths({ paths, base = HOST_BASE, fetchImpl = fetch }) {
  if (base !== HOST_BASE) {
    throw new Refused(
      `SERVE-52's path list is sent to ${HOST_BASE} through the CDN and to nothing else (attack M-12); refusing ` +
      `${JSON.stringify(base)}. The origin judges direct peers, and the eleventh 404 bans the address for four hours.`,
    );
  }
  const served = [];
  const unanswered = [];
  for (const p of paths) {
    const url = new URL(p, base);
    if (url.protocol !== "https:" || url.hostname !== HOST || url.port !== "") {
      throw new Refused(`probe path ${JSON.stringify(p)} resolves to ${url.origin}, not ${HOST_BASE}; refusing it`);
    }
    try {
      const res = await fetchImpl(url.toString(), {
        method: "GET",
        cache: "no-store",
        redirect: "manual",
        headers: { "User-Agent": "astra-registry-served-set" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (res.status >= 200 && res.status < 400) served.push({ path: p, status: res.status });
      else if (res.status >= 500) unanswered.push(`${p} (HTTP ${res.status})`);
    } catch (e) {
      unanswered.push(`${p} (${String(e?.message ?? e)})`);
    }
  }
  return { served, unanswered, asked: paths.length };
}

/** SERVE-52's and INV-40's findings, from what the probes saw. */
export function extraPathVerdict({ probes }) {
  const findings = [];
  const notes = [];
  for (const s of probes.served) {
    const artifact = s.path.endsWith(".astraplugin");
    findings.push(finding(
      artifact ? "INV_40_HOST_SERVES_ARTIFACT" : "SERVE_52_HOST_SERVES_EXTRA",
      artifact
        ? `${HOST_BASE}${s.path} answered ${s.status}: the catalogue host serves or points at a plugin bundle, and ` +
          "any download host but GitHub releases derives an origin identity the client refuses (INV-40)."
        : `${HOST_BASE}${s.path} answered ${s.status}: the catalogue host serves something under registry/v1/ ` +
          "beyond the four signed-set documents (SERVE-52).",
    ));
  }
  notes.push(
    `${probes.asked} probe path(s) asked of ${HOST}: ${probes.served.length} served, ${probes.unanswered.length} ` +
    `unanswered${probes.unanswered.length ? ` (${probes.unanswered.slice(0, 5).join("; ")})` : ""}`,
  );
  return verdict({ findings, notes });
}
