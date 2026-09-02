// Signing and verifying the registry's own documents.
//
// One construction, three documents. `trust.json` is signed by a ROOT key (see
// tools/testkeys/sign-trust.mjs, and tools/keygen-root.sh for the real
// ceremony); `index.json` and — from 3.9 — `revocations.json` are signed by the
// INDEX key that a root-signed `trust.json` delegates to.
//
//     sig = Ed25519(priv, SHA-256( domain ‖ 0x00 ‖ JCS(signed) ))
//
// `domain` is the document's schema string and the NUL is what stops one domain
// that is a prefix of another from colliding with it. **The verifier supplies
// the domain from its own constant, never from the `schema` member of the file
// it is reading** — otherwise a signature over a trust.json could be replayed as
// a signature over an index.json by changing one string.
//
// JCS is RFC 8785 canonical JSON, from ../../tools/lib/canonical.mjs. Signer and
// verifier canonicalising differently is the classic way a signature scheme
// silently accepts nothing or everything, so there is exactly one canonicaliser
// in this repository, `astra-daemon/src/plugins/trust.rs` reimplements it in
// Rust, and `bot/fixtures/index/` holds a document this file signed which that
// Rust test verifies byte-for-byte. Neither side can drift without a red build.
//
// ── the envelope ────────────────────────────────────────────────────────────
//
//   { "$comment": …, "signed": { … }, "signatures": [ { "key_id", "sig" } ] }
//
// Only `signed` is hashed. Everything outside it — the banner, the signature
// list itself — is unauthenticated by construction and nothing may be read out
// of it. `key_id` in particular is a HINT for logging and key selection; the
// verifier tries every trusted key against every offered signature, so a
// document that lies about who signed it still verifies if a trusted key
// actually did, and never verifies because it claimed the right name.

import crypto from "node:crypto";

import { jcs } from "../../tools/lib/canonical.mjs";

/** The catalogue's schema string, and therefore its signature domain. */
export const INDEX_SCHEMA = "astra.registry.index/1";

/** `trust.json`'s. Here so the two constants sit side by side and cannot be confused. */
export const TRUST_SCHEMA = "astra.registry.trust/1";

/** `revocations.json`'s. Reserved by 3.9; nothing signs it yet. */
export const REVOCATIONS_SCHEMA = "astra.registry.revocations/1";

/**
 * The Astra update manifest's schema, and therefore its signature domain.
 *
 * It sits here beside the other three rather than in the signer that uses it, for
 * the reason the comment above gives: a domain string is what stops a signature
 * over one document being replayed as a signature over another, and four of them
 * in four files is four chances for two to drift into agreement.
 *
 * Read by `astra-daemon/src/updates/manifest.rs` as its own constant — never from
 * the file it is checking. The full contract is `api/docs/update-manifest.md` in
 * the minice repository, and it is frozen: the signature covers the serialised
 * bytes, so a field cannot be added without a new domain.
 */
export const UPDATE_SCHEMA = "astra.update.v1";

/**
 * How long a signed catalogue claims to be current — PRODUCTION_PLAN §5.5.
 *
 * Thirty days, and the asymmetry with the revocation list's seven is the whole
 * freshness policy: a stale catalogue downgrades Browse to a banner and
 * **cached, digest-pinned records stay installable**, because the digest is the
 * security property and a digest does not expire. A stale REVOCATION list is
 * the opposite case — "keep going" there means "keep installing something we
 * may already have withdrawn" — so that one is a hard block. Both numbers are
 * duplicated in `astra-daemon/src/plugins/trust.rs`; they are policy, and
 * policy that lives in one repository only is policy the other one guesses at.
 */
export const CATALOG_TTL_DAYS = 30;

/** The revocation list's TTL. 3.9 signs the document; the daemon already blocks on it. */
export const REVOCATION_TTL_DAYS = 7;

// PKCS#8 prefix for a raw Ed25519 seed: SEQUENCE { 0, AlgId(1.3.101.112),
// OCTET STRING { OCTET STRING (32) } }. Node has no "import a raw Ed25519 seed"
// API and this repository has no dependencies, so the wrapper is written out.
// Identical to the one in tools/testkeys/regenerate.mjs, deliberately: that file
// derives TEST keys from a phrase and this one imports a REAL key from a secret,
// and merging them would put a `seed_phrase` field one refactor away from
// production key handling.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * The 32 bytes a signature covers.
 *
 * @param {string} domain the document's schema string
 * @param {unknown} signed the `signed` member, exactly as it will be published
 * @returns {Buffer}
 */
export function signingDigest(domain, signed) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(domain, "utf8"))
    .update(Buffer.from([0x00]))
    .update(Buffer.from(jcs(signed), "utf8"))
    .digest();
}

/**
 * An Ed25519 private key from a raw 32-byte seed.
 *
 * @param {Buffer} seed
 */
export function privateKeyFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw new Error(`an Ed25519 seed is 32 bytes; got ${Buffer.isBuffer(seed) ? seed.length : typeof seed}`);
  }
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

/**
 * An Ed25519 public key from a raw 32-byte base64 key, as `trust.json` records it.
 *
 * @param {string} b64
 */
export function publicKeyFromBase64(b64) {
  const raw = Buffer.from(String(b64).trim(), "base64");
  if (raw.length !== 32) {
    throw new Error(`an Ed25519 public key is 32 raw bytes; got ${raw.length}`);
  }
  // SPKI wrapper: SEQUENCE { AlgId(1.3.101.112), BIT STRING (32) }.
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}

/** The base64 raw public half of a private key. */
export function publicKeyBase64(privateKey) {
  const spki = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return spki.subarray(spki.length - 32).toString("base64");
}

/**
 * Sign one document.
 *
 * `null` is how Node spells "Ed25519 hashes internally, do not pre-hash for me";
 * the message handed to it is already our own SHA-256 digest, which is what the
 * construction says it is.
 *
 * @param {{domain: string, signed: unknown, signers: {key_id: string, privateKey: import("node:crypto").KeyObject}[]}} opts
 */
export function signEnvelope({ domain, signed, signers }) {
  if (!signers?.length) throw new Error("signEnvelope needs at least one signer");
  const digest = signingDigest(domain, signed);
  return {
    signed,
    signatures: signers.map((s) => ({
      key_id: s.key_id,
      sig: crypto.sign(null, digest, s.privateKey).toString("base64"),
    })),
  };
}

/**
 * Verify a document against a set of trusted keys.
 *
 * Every key is tried against every offered signature. Returns the `key_id` of
 * the key that verified — never the `key_id` the document claimed.
 *
 * @param {unknown} doc the whole envelope
 * @param {string} domain the verifier's own constant, not the document's `schema`
 * @param {{key_id: string, publicKey: import("node:crypto").KeyObject}[]} keys
 * @returns {{ok: true, key_id: string} | {ok: false, reason: string, offered: string[]}}
 */
export function verifyEnvelope(doc, domain, keys) {
  if (!doc || typeof doc !== "object") return { ok: false, reason: "not a JSON object", offered: [] };
  if (!("signed" in doc)) return { ok: false, reason: "no `signed` member", offered: [] };
  const signatures = Array.isArray(doc.signatures) ? doc.signatures : null;
  if (!signatures) return { ok: false, reason: "no `signatures` array", offered: [] };

  const digest = signingDigest(domain, doc.signed);
  const offered = signatures.map((s) => (typeof s?.key_id === "string" ? s.key_id : "<unnamed>"));
  for (const entry of signatures) {
    if (typeof entry?.sig !== "string") continue;
    let sig;
    try {
      sig = Buffer.from(entry.sig, "base64");
    } catch {
      continue;
    }
    if (sig.length !== 64) continue;
    for (const candidate of keys) {
      if (crypto.verify(null, digest, candidate.publicKey, sig)) {
        return { ok: true, key_id: candidate.key_id };
      }
    }
  }
  return {
    ok: false,
    reason: keys.length === 0 ? "no trusted key was supplied" : "no trusted key signed this document",
    offered,
  };
}

/**
 * `Date` → the `YYYY-MM-DDTHH:MM:SSZ` spelling every timestamp in this registry
 * uses. Seconds precision, no milliseconds, no offset: two spellings of one
 * instant are two different signed documents.
 *
 * @param {Date} date
 */
export function rfc3339(date) {
  return `${date.toISOString().slice(0, 19)}Z`;
}

/** @param {Date} date @param {number} days */
export function addDays(date, days) {
  return new Date(date.getTime() + days * 86400 * 1000);
}

/**
 * Read the index signing key out of the environment.
 *
 * **Environment, never an argument.** A private key on a command line lands in
 * the shell history, in `ps` output for every other user on the box, and in the
 * Actions log if anyone ever echoes the command. `ASTRA_INDEX_SIGNING_KEY` holds
 * the base64 of the raw 32-byte seed and comes from the `publish` environment's
 * secret, with the maintainer as a required reviewer (PRODUCTION_PLAN §5.1).
 *
 * @param {{env?: NodeJS.ProcessEnv}} opts
 */
export function indexSignerFromEnv({ env = process.env } = {}) {
  const seedB64 = env.ASTRA_INDEX_SIGNING_KEY;
  const keyId = env.ASTRA_INDEX_SIGNING_KEY_ID;
  if (!seedB64) return null;
  if (!keyId) {
    throw new Error(
      "ASTRA_INDEX_SIGNING_KEY is set but ASTRA_INDEX_SIGNING_KEY_ID is not. The key_id has to " +
        "match an entry in the root-signed trust.json, or the daemon will refuse the signature it " +
        "cannot attribute.",
    );
  }
  const seed = Buffer.from(seedB64.trim(), "base64");
  const privateKey = privateKeyFromSeed(seed);
  return { key_id: keyId, privateKey, public_key: publicKeyBase64(privateKey) };
}
