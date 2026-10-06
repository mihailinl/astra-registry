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

import { SIGNED_FILES } from "../signer/plan.mjs";
import { GRACE_MINUTES, finding, minutesSince, verdict, withinGrace } from "./report.mjs";

/** The catalogue host's name (DEC-18). */
export const HOST = "registry.minice.ai";

/** What a new client fetches, minus the file. The paths in SIGNED_FILES are relative to it. */
export const HOST_BASE = `https://${HOST}/`;

const FETCH_TIMEOUT_MS = 20_000;

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
 * Fetch the four documents from the catalogue host.
 *
 * `redirect: "manual"`: INV-26 asks for the file's bytes at this address, and
 * a 3xx is the host sending the reader somewhere else, which is reported as
 * itself rather than followed into a comparison of someone else's bytes.
 *
 * @param {{fetchImpl?: typeof fetch}} opts
 */
export async function fetchHost({ fetchImpl = fetch } = {}) {
  const served = {};
  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    const url = new URL(rel, HOST_BASE).toString();
    try {
      const res = await fetchImpl(url, {
        cache: "no-store",
        redirect: "manual",
        headers: { "Cache-Control": "no-cache", Pragma: "no-cache", "User-Agent": "astra-registry-served-set" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (res.status !== 200) {
        served[name] = { ok: false, url, status: res.status, body: null, error: `HTTP ${res.status}` };
        continue;
      }
      served[name] = { ok: true, url, status: 200, body: await res.text(), error: null };
    } catch (e) {
      served[name] = { ok: false, url, status: null, body: null, error: String(e?.message ?? e) };
    }
  }
  return served;
}

/** The withdrawal list's `expires_at`, if `signed`'s head carries a readable one. */
function listExpiry(head) {
  const at = head?.documents?.revocations?.signed?.expires_at;
  return typeof at === "string" && Number.isFinite(Date.parse(at)) ? at : null;
}

/**
 * SERVE-39 for the catalogue host, over facts and nothing else.
 *
 * @param {object} o
 * @param {object} o.head           from fetchSignedHead
 * @param {string|null} o.headClock the `signed` head's committer time, RFC 3339
 * @param {object} o.served         from fetchHost
 * @param {string} o.now
 * @param {number} [o.graceMinutes]
 */
export function serve39Host({ head, headClock, served, now, graceMinutes = GRACE_MINUTES }) {
  const findings = [];
  const waiting = [];
  const notes = [];
  const hexes = [];

  if (!head?.present) {
    // Unlike Pages, there is no "before the signer" state to wait out: this
    // comparison lands after `signed` has existed for weeks. A missing branch
    // is a finding.
    findings.push(finding(
      "SERVE_39_NO_SIGNED_BRANCH",
      `there is no \`signed\` branch to compare ${HOST} with, so the catalogue host is serving bytes nothing publishes.`,
    ));
    return verdict({ findings, waiting, hexes, notes });
  }

  hexes.push(head.sha);
  const age = minutesSince(headClock, now);
  const excused = withinGrace(headClock, now, graceMinutes);
  const expiry = listExpiry(head);
  const expired = expiry !== null && Date.parse(expiry) <= Date.parse(now);
  notes.push(
    `${HOST} against \`signed\`@${head.sha.slice(0, 12)}, committed ${headClock}, ` +
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
          "SERVE_39_HOST_EXPIRED_LIST",
          `${got.url} still serves \`signed\`@${head.sha.slice(0, 12)}'s withdrawal list, whose expires_at ${expiry} ` +
          `has passed. TRUST-38 removes an expired list from the origin and TRUST-46 forbids the edge serving it stale.`,
        ));
      } else {
        notes.push(`\`signed\`'s list expired at ${expiry} and ${HOST} does not serve it (${got?.error ?? "other bytes"}), as TRUST-38 asks`);
      }
      continue;
    }

    if (!got?.ok) {
      const code = typeof got?.status === "number" && got.status >= 300 && got.status < 400
        ? "SERVE_39_HOST_REDIRECT"
        : "SERVE_39_HOST_UNREACHABLE";
      findings.push(finding(
        code,
        `${got?.url ?? rel} could not be read as the document itself: ${got?.error ?? "no answer"}. Every new client ` +
        "that refreshes now gets the same answer.",
      ));
      continue;
    }
    if (got.body === want) continue;
    if (excused) {
      notes.push(`${rel} on ${HOST} is not \`signed\`'s yet, ${age?.toFixed(1)} minutes in; the service has ${graceMinutes}`);
      continue;
    }
    findings.push(finding(
      "SERVE_39_HOST_DRIFT",
      `${HOST} serves a ${rel} that is not \`signed\`@${head.sha.slice(0, 12)}'s, ` +
      `${age === null ? "at an unreadable time" : `${age.toFixed(0)} minutes`} after that commit (served ` +
      `${got.body.length} bytes, \`signed\` holds ${want.length}). A split view between the branch and the ` +
      "catalogue host is what SERVE-39 exists to find.",
    ));
  }
  return verdict({ findings, waiting, hexes, notes });
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
