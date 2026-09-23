// Which index key signs which document, and when a new one is allowed to.
//
// SERVE-30's rotation has one shape and one exception, and both are here rather
// than in the workflow, because a workflow step is a place where a rule is
// spelled in shell and nothing can test it.
//
// ── the rotation (SERVE-30) ─────────────────────────────────────────────────
//
// A new index key appears when a root ceremony publishes a trust.json that
// delegates it. From the FIRST `signed` commit carrying that trust.json:
//
//   * every withdrawal list is signed by the outgoing key first, then the
//     incoming one. A client holding either trust.json verifies it, because the
//     verifier tries every trusted key against every offered signature
//     (bot/lib/sign.mjs), and the list is the document clients refresh most
//     often — within 6 hours (§5.1) — so it is the document that carries the
//     new key into circulation;
//   * the catalogue is NOT signed by the incoming key for seven hours. Seven,
//     against a six-hour refresh, is the margin: after it, a client that is
//     still running has fetched the trust.json that delegates the incoming key.
//
// `astra-index-2026a` is exempt, and the exemption is not a courtesy. It is the
// key today's trust.json delegates, and there is no `signed` branch yet — so
// there is no commit whose trust.json delegates it, so its window has not
// started, so without the exemption the first signer run refuses to sign the
// catalogue, carries nothing (there is no head to carry from), and `signed` is
// never created. The bootstrap key is exempt; every key after it waits.
//
// ── the exception (D10, DECIDED 2026-09-23) ─────────────────────────────────
//
// OPEN-OWNER-25's compromise half is closed, as D10: decided by the coordinator
// at the owner's delegation on 2026-09-23 and published as contract 0.38.0's
// SERVE-30. A compromised index key is dropped and the catalogue re-signed at
// once; SERVE-30's overlap — the outgoing key signing every list until R9b —
// applies to a PLANNED RETIREMENT only.
//
// Compromise mode is selected by the trust.json at the Source-Commit DROPPING a
// key the head's trust.json delegated, when no retirement record (below) names
// that key. In it:
//
//   * the list is signed by the delegated key alone — there is no outgoing key
//     to go first, because the outgoing key is the compromised one;
//   * the seven-hour window is waived;
//   * the catalogue is re-signed in the same run and MUST NOT be carried.
//
// That last one is the whole reason the exception exists, and SERVE-30's own
// Why says it: a carried catalogue is the old bytes, signed by the key the new
// trust.json no longer delegates. SERVE-15 verifies every candidate document
// against the candidate trust.json and SERVE-91 then refuses the whole commit —
// withholding the new trust.json and the list signed by the new key along with
// it, and leaving the compromised key's last bytes served. The cost of the
// waiver is one refused catalogue fetch on a client that has not refreshed
// trust.json yet; the cost of not waiving it is that the repair does not land.
//
// ── a planned retirement is not a compromise, and the record says which ─────
//
// SERVE-30 keeps the outgoing key signing until R9b — now right after R5
// (OPEN-OWNER-27) — and the trust.json that ends that overlap ALSO drops a key
// the head delegated. Until 0.38.0 this module could not tell the two apart and
// called R9b's retirement a compromise: on that day a catalogue whose gates
// failed was BLOCKED rather than carried, and a blocked run publishes no
// withdrawal list either (D2: a commit holds all four documents). It was left
// that way on purpose while D10 was a proposal, because narrowing the detector
// would have answered the owner's question on his behalf (ops couplings entry
// 20, the detector half).
//
// Now the answer exists, and the shape of the answer decides the shape of the
// detector: a retirement is PLANNED, so it can be written down before it
// happens; a compromise cannot. So the operator who performs SERVE-30's
// retirement commits `policy/index-key-retirements.json` naming the key, and
// every dropped key that file does not name — no file, a malformed file, a
// different key, a time not yet reached — is a compromise. The default is the
// strict mode, because the mistake in that direction is a catalogue blocked on
// a red day, loudly, and the mistake in the other direction is a compromised
// key's catalogue carried for another hour.
//
// A retirement is then ordinary mode with the drop named: the window applies
// (to nothing, since the key that remains was delegated long ago), a failing
// catalogue may be carried, and the carry is still held to `refusesDroppedKey`
// in the run (SERVE-95) — which at R9b passes, because the head's catalogue is
// dual-signed by then. The record cannot make a drop happen and cannot make an
// undelegated key sign: only a root ceremony writes a trust.json that drops a
// key, and the record only says which kind of drop it is.

import { REVOCATIONS_SCHEMA, INDEX_SCHEMA, verifyEnvelope, publicKeyFromBase64 } from "../../bot/lib/sign.mjs";
import { isTime } from "../lib/time.mjs";
import { blobAt, gitMaybe, gitText } from "./git.mjs";

/** SERVE-30's margin over the client's 6-hour trust.json refresh. */
export const INDEX_KEY_WINDOW_HOURS = 7;

/**
 * The bootstrap key. See the note above: exempt because its delegating commit
 * is the one that cannot exist yet.
 */
export const WINDOW_EXEMPT_KEY_IDS = ["astra-index-2026a"];

const HOUR_MS = 3600 * 1000;

/**
 * The record of planned index-key retirements (D10, decided; SERVE-30), read
 * at the Source-Commit. Committed by the operator in the retirement's own
 * commit, beside the trust.json that drops the key:
 *
 *     {"schema": "astra.registry.index-key-retirements/1",
 *      "retirements": [{"key_id": "astra-index-2026a", "retired_from": "2027-06-15T00:00:00Z"}]}
 *
 * Exactly those members, a §0.7 time. Nothing else reads it, and it is not a
 * rule a bot run judges by: TRUST-31's set does not hold it (a record, like
 * `policy/pages-withdrawal-list.json`), and it decides only which of two modes
 * a drop the root ceremony has ALREADY made is read in.
 */
export const RETIREMENTS_PATH = "policy/index-key-retirements.json";
export const RETIREMENTS_SCHEMA = "astra.registry.index-key-retirements/1";

/**
 * Which keys the record calls planned retirements at `now`, and what is wrong
 * with it. Pure. A record that is not exactly the shape above names NOTHING —
 * every problem is returned, and every dropped key then reads as a compromise,
 * which is the strict direction. A row whose `retired_from` is later than `now`
 * names nothing yet: a key dropped before its planned retirement is dropped for
 * some other reason.
 *
 * @param {{record: unknown, now: string}} opts  `record` is the parsed document, or null when absent
 * @returns {{retired: Map<string, string>, problems: string[]}}  key_id → retired_from
 */
export function plannedRetirements({ record, now }) {
  const retired = new Map();
  if (record === null || record === undefined) return { retired, problems: [] };
  const problems = [];
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  if (!isObject(record)) {
    problems.push(`${RETIREMENTS_PATH} is not a JSON object`);
  } else {
    const extra = Object.keys(record).filter((k) => k !== "schema" && k !== "retirements");
    if (record.schema !== RETIREMENTS_SCHEMA) {
      problems.push(`${RETIREMENTS_PATH}'s schema is ${JSON.stringify(record.schema ?? null)}, not ${RETIREMENTS_SCHEMA}`);
    }
    if (extra.length) problems.push(`${RETIREMENTS_PATH} carries member(s) no record has: ${extra.join(", ")}`);
    if (!Array.isArray(record.retirements)) {
      problems.push(`${RETIREMENTS_PATH}'s retirements is not an array`);
    } else {
      record.retirements.forEach((row, i) => {
        const at = `${RETIREMENTS_PATH}'s retirements[${i}]`;
        if (!isObject(row)) { problems.push(`${at} is not an object`); return; }
        const rowExtra = Object.keys(row).filter((k) => k !== "key_id" && k !== "retired_from");
        if (rowExtra.length) problems.push(`${at} carries member(s) no row has: ${rowExtra.join(", ")}`);
        if (typeof row.key_id !== "string" || !row.key_id) problems.push(`${at} names no key_id`);
        if (!isTime(row.retired_from)) {
          problems.push(`${at}'s retired_from is ${JSON.stringify(row.retired_from ?? null)}, not a §0.7 time`);
        }
        if (typeof row.key_id === "string" && retired.has(row.key_id)) problems.push(`${at} names ${row.key_id} twice`);
        if (typeof row.key_id === "string" && isTime(row.retired_from)) retired.set(row.key_id, row.retired_from);
      });
    }
  }
  if (problems.length) return { retired: new Map(), problems };
  for (const [keyId, from] of [...retired]) {
    if (Date.parse(from) > Date.parse(now)) retired.delete(keyId);
  }
  return { retired, problems: [] };
}

/**
 * The retirement record at a commit: the parsed document, null when the commit
 * has none, or a problem when it does not parse. Read from the Source-Commit and
 * never from a working tree, like every other input of the run.
 *
 * @returns {{record: unknown, problem: string|null}}
 */
export function retirementRecordAt({ root, sha, recordPath = RETIREMENTS_PATH }) {
  const text = blobAt({ root, ref: sha, path: recordPath });
  if (text === null) return { record: null, problem: null };
  try {
    return { record: JSON.parse(text), problem: null };
  } catch (e) {
    return { record: undefined, problem: `${recordPath} at ${sha.slice(0, 12)} is not JSON (${e.message})` };
  }
}

/** The key ids a trust.json delegates, in the order the document lists them. */
export function delegatedKeyIds(trustDoc) {
  const entries = trustDoc?.signed?.index_keys ?? trustDoc?.index_keys ?? [];
  return entries.map((e) => e?.key_id).filter((k) => typeof k === "string");
}

/** The same entries as verifier keys. */
export function delegatedVerifierKeys(trustDoc) {
  const entries = trustDoc?.signed?.index_keys ?? trustDoc?.index_keys ?? [];
  return entries
    .filter((e) => typeof e?.key_id === "string" && typeof e?.public_key === "string")
    .map((e) => ({ key_id: e.key_id, publicKey: publicKeyFromBase64(e.public_key) }));
}

/**
 * When each key was FIRST delegated, from the `signed` commits, oldest first.
 *
 * Pure, so the walk that produces `commits` can be a git read in production and
 * a literal in a test. `commits` is `[{sha, committed_at, key_ids}]` in commit
 * order, oldest first.
 *
 * First and not latest: a key dropped and re-delegated does not get a fresh
 * seven hours, because the clients that matter are the ones that saw it the
 * first time.
 *
 * @returns {Map<string, string>} key_id → RFC 3339 commit time
 */
export function delegationTimes(commits) {
  const first = new Map();
  for (const c of commits) {
    for (const keyId of c.key_ids ?? []) {
      if (!first.has(keyId)) first.set(keyId, c.committed_at);
    }
  }
  return first;
}

/**
 * `delegationTimes` over a real `signed` branch.
 *
 * Reads only the commits that TOUCHED trust.json — a rotation is rare and the
 * branch gets a commit an hour, so walking every commit would read thousands of
 * identical blobs to learn one date.
 *
 * **`--first-parent`, so a key is dated where `signed` acquired it** (gap 68's
 * shape; astra-registry #197). The window is the time clients have had the
 * delegating trust.json, and Pages serves `signed`'s head, so the clock starts
 * at the first commit on `signed`'s own line that carries it. A plain walk
 * simplifies through a merge that is TREESAME to its side parent and dates the
 * SIDE commit: measured 2026-09-22 on a fixture, a key delegated on a side
 * branch at 09:00 and merged into `signed` at 12:00 read as delegated at 09:00,
 * so at 16:30 the seven hours read as served where clients had had four and a
 * half — the incoming key would have signed the catalogue early, which is the
 * failure the window exists to prevent. The signer writes `signed` one parent
 * at a time (`buildSignedCommit`), so a merge there is somebody else's push;
 * the real branch has none (8 commits, 0 merges at 5966ccf), and this walk
 * lists the same commits either way there.
 *
 * @param {{root: string, ref?: string, trustPath?: string}} opts
 */
export function readDelegationTimes({ root, ref = "FETCH_HEAD", trustPath = "registry/v1/trust.json" }) {
  const listed = gitMaybe(["log", "--first-parent", "--reverse", "--format=%H %cI", ref, "--", trustPath], { root });
  if (!listed.ok) return new Map();
  const commits = [];
  for (const line of listed.out.split("\n").filter(Boolean)) {
    const [sha, committedAt] = line.trim().split(/\s+/);
    if (!sha) continue;
    const text = blobAt({ root, ref: sha, path: trustPath });
    if (text === null) continue;
    let doc;
    try {
      doc = JSON.parse(text);
    } catch {
      // A trust.json that does not parse is a real problem, but it is not this
      // function's to report: it cannot have delegated anything, so it
      // contributes no delegation time and the document it signed will fail
      // verification in refusesDroppedKey below, where the message is useful.
      continue;
    }
    commits.push({ sha, committed_at: committedAt, key_ids: delegatedKeyIds(doc) });
  }
  return delegationTimes(commits);
}

/** The head commit of a fetched `signed`, or null. */
export function signedHeadSha({ root, ref = "FETCH_HEAD" }) {
  const r = gitMaybe(["rev-parse", ref], { root });
  return r.ok ? r.out.trim() : null;
}

/** Hours between two instants, negative when `at` is before `since`. */
function hoursSince(since, at) {
  return (Date.parse(at) - Date.parse(since)) / HOUR_MS;
}

/**
 * Decide, for one run, which keys sign the catalogue and which sign the list.
 *
 * A key the head's trust.json delegated and the candidate's drops is a planned
 * retirement when `retirements` — `retirementRecordAt`'s answer — names it from
 * a time not later than `now`, and a compromise otherwise. One unplanned drop
 * makes the whole run compromise mode.
 *
 * @param {object} opts
 * @param {object} opts.candidateTrust  trust.json at the Source-Commit — the one that will be committed
 * @param {object|null} opts.headTrust  trust.json at `signed`'s head, null before the first run
 * @param {Map<string,string>} opts.delegatedAt  key_id → first delegating commit's time
 * @param {string} opts.now  RFC 3339
 * @param {{key_id: string}[]} opts.available  the signers the environment holds, in env order
 * @param {{record: unknown, problem: string|null}} [opts.retirements]  the record at the Source-Commit
 * @param {number} [opts.windowHours]
 * @returns {{mode: "normal"|"retirement"|"compromise", dropped: string[], retired: string[], carryCatalogueAllowed: boolean,
 *           index: {signers: object[], refused: string|null},
 *           revocations: {signers: object[], refused: string|null},
 *           notes: string[]}}
 */
export function keyPlan({
  candidateTrust,
  headTrust,
  delegatedAt = new Map(),
  now,
  available,
  retirements = { record: null, problem: null },
  windowHours = INDEX_KEY_WINDOW_HOURS,
}) {
  const notes = [];
  const delegated = delegatedKeyIds(candidateTrust);

  // A key the environment holds and the candidate trust.json does not delegate
  // must not sign: the document would be committed beside a trust.json that
  // cannot verify it, and SERVE-91 would refuse the whole commit. Dropping it
  // silently is the wrong repair, so it is dropped loudly.
  const usable = [];
  for (const signer of available) {
    if (delegated.includes(signer.key_id)) usable.push(signer);
    else notes.push(`${signer.key_id} is in the environment and the Source-Commit's trust.json does not delegate it`);
  }

  // Outgoing first. "Outgoing" is "delegated earlier", read from `signed`'s own
  // history rather than from the order trust.json happens to list keys in — the
  // document's order is a property of whoever ran the ceremony, and SERVE-30's
  // ordering is a property of which key the clients have had longer.
  const rank = (s) => {
    const at = delegatedAt.get(s.key_id);
    // Never seen on `signed`: it is being delegated by the commit this run is
    // about to make, so it is the newest thing there is.
    return at === undefined ? Number.POSITIVE_INFINITY : Date.parse(at);
  };
  const ordered = [...usable].sort((a, b) => rank(a) - rank(b) || available.indexOf(a) - available.indexOf(b));

  const headKeys = headTrust ? delegatedKeyIds(headTrust) : [];
  const dropped = headKeys.filter((k) => !delegated.includes(k));
  // Read on every run, not only on the day of a drop: a malformed record found
  // on the day of the retirement turns it into compromise mode, and a note on
  // every run before that day is how somebody finds out in time.
  const planned = plannedRetirements({ record: retirements?.record ?? null, now });
  const problems = [...(retirements?.problem ? [retirements.problem] : []), ...planned.problems];
  for (const p of problems) notes.push(`the retirement record names nothing, so every dropped key is a compromise: ${p}`);
  const retired = problems.length ? [] : dropped.filter((k) => planned.retired.has(k));
  const unplanned = dropped.filter((k) => !retired.includes(k));
  const mode = unplanned.length > 0 ? "compromise" : dropped.length > 0 ? "retirement" : "normal";

  if (mode === "compromise") {
    notes.push(
      `compromise mode (D10): the Source-Commit's trust.json drops ${unplanned.join(", ")}, which ` +
      `signed the head, and ${RETIREMENTS_PATH} records no planned retirement of ` +
      `${unplanned.length === 1 ? "it" : "them"} from a time already reached. The seven-hour window is waived and ` +
      `the catalogue may not be carried.`,
    );
    const refused = ordered.length === 0
      ? "the trust.json that drops the compromised key delegates no key this run holds"
      : null;
    return {
      mode,
      dropped,
      retired,
      carryCatalogueAllowed: false,
      index: { signers: ordered, refused },
      revocations: { signers: ordered, refused },
      notes,
    };
  }

  const withinWindow = [];
  const catalogueSigners = [];
  for (const signer of ordered) {
    if (WINDOW_EXEMPT_KEY_IDS.includes(signer.key_id)) {
      catalogueSigners.push(signer);
      continue;
    }
    const at = delegatedAt.get(signer.key_id);
    const age = at === undefined ? 0 : hoursSince(at, now);
    if (age >= windowHours) catalogueSigners.push(signer);
    else {
      withinWindow.push(
        `${signer.key_id} was first delegated ${at === undefined ? "by this run" : `at ${at}`}` +
        `, ${age.toFixed(2)} h ago; it may sign the catalogue after ${windowHours} h`,
      );
    }
  }
  for (const line of withinWindow) notes.push(line);
  if (mode === "retirement") {
    notes.push(
      `planned retirement (SERVE-30; D10): the Source-Commit's trust.json drops ${retired.join(", ")}, which ` +
      `${RETIREMENTS_PATH} records as retired from ${retired.map((k) => planned.retired.get(k)).join(", ")}. ` +
      `This is not compromise mode: the window applies and a failing catalogue may be carried, if what is ` +
      `carried verifies under the trust.json beside it (SERVE-95).`,
    );
  }

  return {
    mode,
    dropped,
    retired,
    carryCatalogueAllowed: true,
    index: {
      signers: catalogueSigners,
      refused: catalogueSigners.length === 0
        ? `no index key may sign the catalogue yet: ${withinWindow.join("; ") || "the environment holds no delegated key"}`
        : null,
    },
    revocations: {
      signers: ordered,
      refused: ordered.length === 0 ? "the environment holds no key the Source-Commit's trust.json delegates" : null,
    },
    notes,
  };
}

/**
 * The refusal the compromise procedure turns on, and the one this module exists
 * to make impossible to forget.
 *
 * Every document about to be committed must verify under the trust.json
 * committed beside it. The case it catches is narrow and specific: a catalogue
 * CARRIED from `signed`'s head, signed by a key the new trust.json has just
 * dropped. Nothing else in the run notices — the carry is byte-perfect, the
 * signature is a real signature by a key that was trusted when it was made, and
 * the commit is well formed. It is only wrong relative to the file next to it.
 *
 * @param {{trust: object, documents: {name: string, domain: string, doc: object}[]}} opts
 * @returns {string[]} one line per document that would not verify; empty is the pass
 */
export function refusesDroppedKey({ trust, documents }) {
  const keys = delegatedVerifierKeys(trust);
  const problems = [];
  for (const { name, domain, doc } of documents) {
    const r = verifyEnvelope(doc, domain, keys);
    if (!r.ok) {
      problems.push(
        `${name} does not verify against the trust.json it would be committed beside ` +
        `(${r.reason}; offered ${r.offered?.join(", ") || "nothing"}; delegated ` +
        `${keys.map((k) => k.key_id).join(", ") || "nothing"})`,
      );
    }
  }
  return problems;
}

/** The two domains `refusesDroppedKey` is called with, so no caller types them. */
export const DOCUMENT_DOMAINS = { index: INDEX_SCHEMA, revocations: REVOCATIONS_SCHEMA };

/** Read a trust.json out of a working tree or a ref. Convenience for the workflow. */
export function trustAt({ root, ref, trustPath = "registry/v1/trust.json" }) {
  const text = ref ? blobAt({ root, ref, path: trustPath }) : null;
  if (text === null) return null;
  return JSON.parse(text);
}

/** The Source-Commit's own trust.json, by sha. */
export function trustAtCommit({ root, sha, trustPath = "registry/v1/trust.json" }) {
  gitText(["rev-parse", "--verify", `${sha}^{commit}`], { root });
  return trustAt({ root, ref: sha, trustPath });
}
