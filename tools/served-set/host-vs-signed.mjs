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
// SERVE-108, SERVE-109, Table 5-N; since 6.0.0; review of PR #467 applied
// here — ops #583 fixed the same gaps in the prober, and the shapes below
// mirror it so both monitors agree) ─────────────────────────────────────────
//
// Since 6.0.0 a catalogue host MAY require a catalogue ticket for
// `registry/v1/index.json` and `stats/v1/stats.json` (INV-30) and for
// nothing else — `registry/v1/trust.json`, `registry/v1/revocations.json`
// and `registry/v1/root.json` are never gated (OD-6), so a 4xx on any of
// those is still a failure, exactly as a 404 or a 500 always was.
//
// A ticketless read answering INV-30's armed shape — any 4xx, a
// `Cache-Control` naming `no-store` that is not itself a CDN's own cached
// copy of the refusal, and a JSON body `{"schema": "astra.plugins.error/1",
// "error": "unauthenticated", "message": <string>}` — is the armed state
// SERVE-39 reads as "not a difference". Anything else (another status,
// `no-store` missing, a CDN cache hit, a body that is not exactly this
// shape) is not that shape, so it falls straight through to the finding
// every other failure has always gotten.
//
// `index.json`'s bytes, on the armed state, cannot be read ticketless, so
// SERVE-39 compares the host with `signed` through its witness instead
// (`registry/v1/served.json`, SERVE-109; Table 5-N): `index.sha256` against
// the SHA-256 of `signed`'s head `index.json`, and `index.serial` against its
// `signed.serial`. `stats.json` is fetched too (never compared — it is in no
// `signed` commit) only to tell INV-30's armed gate apart from an outage.
//
// A witness that is missing, unreadable, the wrong schema or members, or off
// either clock edge — more than 15 minutes stale, or more than 60 s ahead of
// the moment it was read — is a witness failure and always an immediate
// finding, read again once after SERVE-109's 60 s first. A witness that
// checks out but NAMES OTHER BYTES than `signed`'s head is read the same way
// a plain byte difference is everywhere else in this file: a note while
// `signed`'s own head is still within SERVE-39's 30-minute grace, a finding
// (after one more 60 s read) once that grace has passed.

/** `astra.plugins.served/1`'s path (SERVE-109), relative to the host's base. */
export const SERVED_JSON_PATH = "registry/v1/served.json";

/** `stats/v1/stats.json`'s path: fetched, never compared (SERVE-39's own words). */
export const STATS_PATH = "stats/v1/stats.json";

/** SERVE-109's freshness bound: a witness written before this, read now, is a witness failure. */
export const WITNESS_GRACE_MINUTES = 15;

/** SERVE-109's "reads it again after 60 s before it alarms on a difference". */
export const WITNESS_REREAD_MS = 60_000;

/** A witness `at` ahead of its own read by more than this is a clock neither side can be trusted to have read right. */
export const WITNESS_FORWARD_SKEW_MS = 60_000;

const WITNESS_SCHEMA = "astra.plugins.served/1";
const ERROR_SCHEMA = "astra.plugins.error/1";
const WITNESS_AT_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Whether a response's headers show a CDN served it from cache rather than
 * passing the request to the origin's gate: an `Age` over zero, or a known
 * cache-status header saying so (Cloudflare's `cf-cache-status`, gcore's
 * `Cache`, the generic `x-cache`). Table 5-A gives a gated document "no edge
 * copy", so a hit here is evidence about the edge — a copy the CDN kept from
 * before the host armed, or before this read — never evidence that the
 * origin is now gated (mirrors ops #583's `cdnHit`).
 */
function cdnCacheHit(got) {
  const age = Number.parseInt(got?.age ?? "", 10);
  if (Number.isFinite(age) && age > 0) return true;
  for (const v of [got?.cfCacheStatus, got?.cache, got?.xCache]) {
    if (typeof v === "string" && v.toUpperCase().includes("HIT")) return true;
  }
  return false;
}

/**
 * Is `got` — an already-failed read of `index.json` or `stats.json` on
 * `host` — INV-30's armed state (mirrors ops #583's `isArmedRefusal`
 * exactly, so both monitors agree)? All of these, never only the status:
 *
 *   * any 4xx (Table 5-A names 422 and 503 as today's statuses, not a closed
 *     list);
 *   * a `Cache-Control` naming `no-store`;
 *   * on `HOST` (`registry.minice.ai`) alone — the CDN-fronted host —
 *     headers that are not a CDN's own cached copy of the refusal
 *     (`cdnCacheHit`). `RU_HOST` is served direct from the RU box with no
 *     CDN in front of it (DEC-18), so an `Age` header there answers a
 *     different question (or none) and is never evidence of a stale edge
 *     copy of a gated document;
 *   * a JSON body that is exactly §0.8's refusal shape: `schema`
 *     `"astra.plugins.error/1"`, `error` `"unauthenticated"`, and a string
 *     `message`.
 *
 * Anything else returns `false`, so the caller's existing unreachable/
 * redirect branch reports it exactly as it always has — SERVE-39's "stays a
 * failure, as today" needs no second code path.
 *
 * @param {object} got
 * @param {string} [host]
 */
export function isArmedGateRefusal(got, host = HOST) {
  if (!got || got.ok) return false;
  if (!(got.status >= 400 && got.status <= 499)) return false;
  if (typeof got.cacheControl !== "string" || !got.cacheControl.toLowerCase().includes("no-store")) return false;
  if (host === HOST && cdnCacheHit(got)) return false;
  if (!got.body) return false;
  let body;
  try {
    body = JSON.parse(got.body);
  } catch {
    return false;
  }
  return body?.schema === ERROR_SCHEMA && body?.error === "unauthenticated" && typeof body?.message === "string";
}

/**
 * Does `got`'s body merely CLAIM `error: "unauthenticated"` on a 4xx,
 * whether or not it is INV-30's exact armed shape? Point 1's stats.json
 * rule needs this distinction: a host that tried to answer unauthenticated
 * but got the shape wrong (no `no-store`, the wrong schema or message, a
 * CDN's cached copy) is a fault worth a finding; a host that simply does
 * not serve `stats/v1/stats.json` at all — SERVE-109 allows that — is not.
 */
function looksUnauthenticated(got) {
  if (!got || got.ok) return false;
  if (!(typeof got.status === "number" && got.status >= 400 && got.status <= 499)) return false;
  let body;
  try {
    body = JSON.parse(got.body ?? "");
  } catch {
    return false;
  }
  return body?.error === "unauthenticated";
}

/**
 * SERVE-109's clock, both edges: `null` when `at` checks out, otherwise the
 * sentence SERVE-39 reports. `readAt` is when THIS witness read returned
 * (`fetchWitness`'s own clock), never the job's start — a run can be minutes
 * old by the time a reread completes, and both bounds are about the witness.
 */
function witnessClockProblem(at, readAt, graceMinutes = WITNESS_GRACE_MINUTES) {
  const atMs = Date.parse(at);
  const readAtMs = Date.parse(readAt);
  if (!Number.isFinite(atMs) || !Number.isFinite(readAtMs)) return "`at` is unreadable";
  if (readAtMs - atMs < -WITNESS_FORWARD_SKEW_MS) {
    return `names \`at\` ${((atMs - readAtMs) / 1000).toFixed(0)}s ahead of this read, past the 60 s clock-skew bound`;
  }
  if (!withinGrace(at, readAt, graceMinutes)) {
    const mins = minutesSince(at, readAt);
    return `was written ${mins === null ? "at an unreadable time" : `${mins.toFixed(1)} minutes`} before this read, past SERVE-109's ${graceMinutes}-minute bound`;
  }
  return null;
}

/**
 * One read of `served.json`, judged against `signed`'s head (Table 5-N;
 * §0.7). `null` means the witness checks out. Otherwise `{kind, message}`:
 * `"malformed"` for anything SERVE-109 calls a witness failure — missing,
 * unreadable, the wrong schema or members, or off either clock edge — which
 * is always an immediate finding regardless of `signed`'s own grace;
 * `"mismatch"` for a witness that reads fine but names other bytes or
 * another serial than `signed`'s head, which the caller may read as a note
 * while `signed`'s head is still within its own 30-minute grace, exactly as
 * an unarmed host's stale bytes are today.
 */
function witnessProblem({ fetched, head }) {
  if (!fetched?.ok) return { kind: "malformed", message: `could not be read (${fetched?.error ?? "no answer"})` };
  let doc;
  try {
    doc = JSON.parse(fetched.body);
  } catch (e) {
    return { kind: "malformed", message: `is not readable JSON (${e.message})` };
  }
  if (!doc || typeof doc !== "object" || doc.schema !== WITNESS_SCHEMA) {
    return { kind: "malformed", message: `names schema ${JSON.stringify(doc?.schema ?? null)}, not ${WITNESS_SCHEMA} (Table 5-N)` };
  }
  const idx = doc.index;
  if (!idx || typeof idx !== "object" || !Number.isSafeInteger(idx.serial) || idx.serial < 0 || typeof idx.sha256 !== "string" || !HEX64_RE.test(idx.sha256)) {
    return { kind: "malformed", message: "index.serial is missing or not a non-negative integer, or index.sha256 is missing or not 64 lowercase hex (Table 5-N)" };
  }
  if (!("stats" in doc) || !(doc.stats === null || (doc.stats && typeof doc.stats === "object" && typeof doc.stats.sha256 === "string" && HEX64_RE.test(doc.stats.sha256)))) {
    return { kind: "malformed", message: "stats is missing, or is neither null nor {sha256: 64 lowercase hex} (Table 5-N)" };
  }
  if (typeof doc.at !== "string" || !WITNESS_AT_RE.test(doc.at)) {
    return { kind: "malformed", message: "`at` is missing or not a §0.7 time (Table 5-N)" };
  }
  // The regex alone admits calendar nonsense a Date happily normalises
  // instead of rejecting — `T24:00:00Z`, or `02-30` rolled into March. A
  // round trip through Date catches both: the instant it parses to must
  // print back out, byte for byte, as the string that was sent.
  const atMs = Date.parse(doc.at);
  const roundTrip = Number.isFinite(atMs) ? new Date(atMs).toISOString().replace(".000Z", "Z") : null;
  if (roundTrip !== doc.at) {
    return { kind: "malformed", message: `names \`at\` ${JSON.stringify(doc.at)}, which is not a real instant (Table 5-N)` };
  }
  const clockProblem = witnessClockProblem(doc.at, fetched.readAt);
  if (clockProblem) return { kind: "malformed", message: clockProblem };

  const wantHex = createHash("sha256").update(String(head.bytes?.index ?? ""), "utf8").digest("hex");
  if (idx.sha256 !== wantHex) {
    return { kind: "mismatch", message: `names index.sha256 ${idx.sha256}, not \`signed\`@${head.sha.slice(0, 12)}'s index.json (${wantHex})` };
  }
  const wantSerial = head.documents?.index?.signed?.serial;
  if (Number.isInteger(wantSerial) && idx.serial !== wantSerial) {
    return { kind: "mismatch", message: `names index.serial ${idx.serial}, not \`signed\`@${head.sha.slice(0, 12)}'s ${wantSerial}` };
  }
  return null;
}

/**
 * Fetch `served.json` once. Never thrown: a network failure is `{ok: false}`,
 * as `fetchHost` treats one. `readAt` is this read's own clock (SERVE-109),
 * taken the moment the response arrives, not when the caller started.
 */
export async function fetchWitness({ host = HOST, fetchImpl = fetch } = {}) {
  const url = new URL(SERVED_JSON_PATH, `https://${host}/`).toString();
  try {
    const res = await fetchImpl(url, {
      cache: "no-store",
      redirect: "manual",
      headers: { "Cache-Control": "no-cache", Pragma: "no-cache", "User-Agent": "astra-registry-served-set" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    const readAt = new Date().toISOString();
    if (res.status !== 200) {
      let body = null;
      try {
        body = await res.text();
      } catch {
        body = null;
      }
      return { ok: false, url, status: res.status, body, error: `HTTP ${res.status}`, readAt };
    }
    return { ok: true, url, status: 200, body: await res.text(), error: null, readAt };
  } catch (e) {
    return { ok: false, url, status: null, body: null, error: String(e?.message ?? e), readAt: new Date().toISOString() };
  }
}

/**
 * The armed-host comparison (SERVE-39; SERVE-109): `served.json` read once.
 * A malformed witness is always read again after `WITNESS_REREAD_MS` before
 * being reported — it "stays an immediate failure" regardless of grace. A
 * mismatch is read again only when `excused` is false: while `signed`'s head
 * is still within SERVE-39's own grace, one read is enough to log the note,
 * exactly as an unarmed host's stale bytes cost no retry either.
 *
 * @param {{host: string, head: object, excused?: boolean, fetchImpl?: typeof fetch, sleepImpl?: (ms: number) => Promise<void>}} o
 */
export async function armedWitnessVerdict({ host, head, excused = false, fetchImpl = fetch, sleepImpl = defaultSleep }) {
  let fetched = await fetchWitness({ host, fetchImpl });
  let problem = witnessProblem({ fetched, head });
  let rereadAttempted = false;
  if (problem && (problem.kind === "malformed" || !excused)) {
    rereadAttempted = true;
    await sleepImpl(WITNESS_REREAD_MS);
    fetched = await fetchWitness({ host, fetchImpl });
    problem = witnessProblem({ fetched, head });
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

/** A failure placeholder, shared by every `fetchOne`/`fetchWitness` catch — one shape, never retyped at each call site. */
function fetchFailed(url, e) {
  return { ok: false, url, status: null, body: null, error: String(e?.message ?? e), age: null, cacheControl: null, cfCacheStatus: null, cache: null, xCache: null };
}

/**
 * Fetch one document from a catalogue host.
 *
 * `redirect: "manual"`: INV-26 asks for the file's bytes at this address, and
 * a 3xx is the host sending the reader somewhere else, which is reported as
 * itself rather than followed into a comparison of someone else's bytes.
 *
 * Every header this file or `isArmedGateRefusal` reads is read on every
 * status, not only 200 — `null` where a header is absent is not itself a
 * finding either way, only something that check cannot compare. `body` is
 * likewise read on every status, since a gated refusal's JSON `error` is
 * read from it too (INV-30; SERVE-108).
 *
 * **On a 200, a body-read failure is NOT caught here.** It propagates to the
 * caller's own `catch`, exactly as it did before `isArmedGateRefusal` needed
 * a body read off other statuses too: catching it locally would turn a
 * genuine read failure into `{ok: true, body: null}` — a 200 whose `body`
 * does not equal `signed`'s bytes, which a run inside SERVE-39's 30-minute
 * grace reads as "not synced yet, and said so" (a false pass hiding a real
 * outage) and a run past the grace crashes on, since nothing here expects
 * `body.length` to be called on `null`.
 */
async function fetchOne({ url, fetchImpl }) {
  const res = await fetchImpl(url, {
    cache: "no-store",
    redirect: "manual",
    headers: { "Cache-Control": "no-cache", Pragma: "no-cache", "User-Agent": "astra-registry-served-set" },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const header = (name) => (typeof res.headers?.get === "function" ? res.headers.get(name) : null);
  const age = header("age");
  const cacheControl = header("cache-control");
  const cfCacheStatus = header("cf-cache-status");
  const cache = header("cache");
  const xCache = header("x-cache");
  if (res.status !== 200) {
    let body = null;
    try {
      body = await res.text();
    } catch {
      body = null;
    }
    return { ok: false, url, status: res.status, body, error: `HTTP ${res.status}`, age, cacheControl, cfCacheStatus, cache, xCache };
  }
  return { ok: true, url, status: 200, body: await res.text(), error: null, age, cacheControl, cfCacheStatus, cache, xCache };
}

/**
 * Fetch the four signed documents, and `stats/v1/stats.json` beside them
 * (point 3: fetched ticketless, never compared — SERVE-39's own words say
 * `stats` is in no `signed` commit), from a catalogue host.
 *
 * `head`, `headClock` and `now`, when given, let an armed `index.json`
 * (SERVE-39's armed state; `isArmedGateRefusal`) be compared with `signed`
 * through `served.json` instead (SERVE-109; Table 5-N): the result lands at
 * `served.witness`, resolved — reread included — before this returns, so
 * `serve39Host` stays a synchronous read of already-settled data like every
 * other comparison in this file. `excused` here is the SAME formula
 * `serve39Host` itself uses (`withinGrace(headClock, now, GRACE_MINUTES)`),
 * so the decision to skip a mismatch's reread here agrees with the decision
 * to read that mismatch as a note there. Omitted (as every call before 6.0.0
 * omitted them), `served.witness` is simply never set, and nothing else
 * changes.
 *
 * @param {{host?: string, fetchImpl?: typeof fetch, head?: object|null, headClock?: string|null, now?: string, sleepImpl?: (ms: number) => Promise<void>}} opts
 */
export async function fetchHost({ host = HOST, fetchImpl = fetch, head = null, headClock = null, now = new Date().toISOString(), sleepImpl = defaultSleep } = {}) {
  const base = `https://${host}/`;
  const served = {};
  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    const url = new URL(rel, base).toString();
    try {
      served[name] = await fetchOne({ url, fetchImpl });
    } catch (e) {
      served[name] = fetchFailed(url, e);
    }
  }
  {
    const url = new URL(STATS_PATH, base).toString();
    try {
      served.stats = await fetchOne({ url, fetchImpl });
    } catch (e) {
      served.stats = fetchFailed(url, e);
    }
  }
  if (head?.present && isArmedGateRefusal(served.index, host)) {
    const excused = withinGrace(headClock, now, GRACE_MINUTES);
    served.witness = await armedWitnessVerdict({ host, head, excused, fetchImpl, sleepImpl });
  }
  return served;
}

/** Fetch the four documents and stats.json from every catalogue host, keyed by host. */
export async function fetchHosts({ hosts = CATALOGUE_HOSTS, fetchImpl = fetch, head = null, headClock = null, now, sleepImpl } = {}) {
  const byHost = {};
  for (const host of hosts) byHost[host] = await fetchHost({ host, fetchImpl, head, headClock, now, sleepImpl });
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

    if (name === "index" && !got?.ok && isArmedGateRefusal(got, host)) {
      // INV-30's armed state (since 6.0.0): a ticketless index.json refuses
      // with INV-30's shape, which is not a difference (SERVE-39) — the host
      // is compared through served.json instead (SERVE-109; Table 5-N).
      // trust.json, revocations.json and root.json never reach this branch
      // (OD-6: they are never gated, so a 4xx on one of them falls through to
      // the finding below, as always).
      const w = served?.witness;
      const problem = w?.problem ?? null;
      if (!w || (problem && (problem.kind === "malformed" || !excused))) {
        findings.push(finding(
          `SERVE_39_HOST_WITNESS_FAILS${suffix}`,
          `${host} refuses a ticketless ${rel} as INV-30's armed state (${got.status} unauthenticated, Cache-Control: ` +
          `no-store), so SERVE-39 compares it through served.json instead — and that witness ${problem?.message ?? "was never read"} ` +
          "(SERVE-109). A gate the registry cannot compare from outside is one the registry cannot vouch for.",
        ));
      } else if (problem) {
        // a sha256/serial mismatch, but `signed`'s own head is still inside
        // SERVE-39's 30-minute grace: a note, exactly as an unarmed host's
        // stale bytes read today a few lines below.
        notes.push(
          `${host}'s served.json witness ${problem.message}, but \`signed\`@${head.sha.slice(0, 12)} is only ` +
          `${age?.toFixed(1)} minutes old; the service has ${graceMinutes}`,
        );
      } else {
        notes.push(
          `${host} is armed (INV-30): a ticketless ${rel} answers ${got.status} unauthenticated with Cache-Control: ` +
          `no-store, and served.json's witness names \`signed\`@${head.sha.slice(0, 12)}'s index.json, read ` +
          `${w.rereadAttempted ? "on its reread" : "on the first read"}`,
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

  // stats/v1/stats.json (point 3): fetched ticketless, never compared — it
  // is in no `signed` commit (SERVE-39's own words). SERVE-109 allows a host
  // with no stats document at all, so this is deliberately not symmetric
  // with index.json's gate:
  //
  //   * a 200, or INV-30's exact armed shape, is silent — both are the host
  //     doing something SERVE-109 already accounts for;
  //   * a 4xx whose body CLAIMS `error: "unauthenticated"` but fails
  //     `isArmedGateRefusal` — missing `no-store`, the wrong schema or
  //     message, or a CDN's cached copy — is a fault: a gate the registry
  //     cannot tell apart from a real refusal is one it cannot read at all,
  //     exactly as SERVE-39 reports a host document it cannot read;
  //   * everything else not serving the document — a 404, a 5xx, a 3xx, a
  //     transport failure — is simply a host with no stats document, which
  //     SERVE-39 never required and logs as a note, not a finding.
  {
    const got = served?.stats;
    if (!(got?.ok || isArmedGateRefusal(got, host))) {
      if (looksUnauthenticated(got)) {
        findings.push(finding(
          `SERVE_39_HOST_UNREACHABLE${suffix}`,
          `${got.url} answers unauthenticated on ${STATS_PATH} but not INV-30's exact armed shape (missing ` +
          "Cache-Control: no-store, the wrong refusal body, or a CDN's own cached copy) — a gate the registry " +
          "cannot tell apart from a real refusal is one it cannot read at all.",
        ));
      } else {
        notes.push(
          `${host}'s ${STATS_PATH} answered ${got?.error ?? `HTTP ${got?.status}`}; SERVE-109 allows a host with ` +
          "no stats document, and SERVE-39 never compares its bytes.",
        );
      }
    }
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
