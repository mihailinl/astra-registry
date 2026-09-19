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
// ── the exception (D10, and it is a PROPOSAL) ───────────────────────────────
//
// OPEN-OWNER-25's compromise half is open. What is implemented here is this
// plan's proposal, and the owner's answer may rewrite it (RC-R1-10(c)).
//
// Compromise mode is selected by the trust.json at the Source-Commit DROPPING a
// key the head's trust.json delegated. In it:
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

import { REVOCATIONS_SCHEMA, INDEX_SCHEMA, verifyEnvelope, publicKeyFromBase64 } from "../../bot/lib/sign.mjs";
import { blobAt, gitMaybe, gitText } from "./git.mjs";

/** SERVE-30's margin over the client's 6-hour trust.json refresh. */
export const INDEX_KEY_WINDOW_HOURS = 7;

/**
 * The bootstrap key. See the note above: exempt because its delegating commit
 * is the one that cannot exist yet.
 */
export const WINDOW_EXEMPT_KEY_IDS = ["astra-index-2026a"];

const HOUR_MS = 3600 * 1000;

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
 * @param {{root: string, ref?: string, trustPath?: string}} opts
 */
export function readDelegationTimes({ root, ref = "FETCH_HEAD", trustPath = "registry/v1/trust.json" }) {
  const listed = gitMaybe(["log", "--reverse", "--format=%H %cI", ref, "--", trustPath], { root });
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
 * @param {object} opts
 * @param {object} opts.candidateTrust  trust.json at the Source-Commit — the one that will be committed
 * @param {object|null} opts.headTrust  trust.json at `signed`'s head, null before the first run
 * @param {Map<string,string>} opts.delegatedAt  key_id → first delegating commit's time
 * @param {string} opts.now  RFC 3339
 * @param {{key_id: string}[]} opts.available  the signers the environment holds, in env order
 * @param {number} [opts.windowHours]
 * @returns {{mode: "normal"|"compromise", dropped: string[], carryCatalogueAllowed: boolean,
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
  const mode = dropped.length > 0 ? "compromise" : "normal";

  if (mode === "compromise") {
    notes.push(
      `compromise mode (D10): the Source-Commit's trust.json drops ${dropped.join(", ")}, which ` +
      `signed the head. The seven-hour window is waived and the catalogue may not be carried.`,
    );
    const refused = ordered.length === 0
      ? "the trust.json that drops the compromised key delegates no key this run holds"
      : null;
    return {
      mode,
      dropped,
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

  return {
    mode,
    dropped,
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
