// The owner's acts on the site, each confirmed by one passkey, verified here
// and nowhere else (astra-plugins-ops `dev/operator-acts-by-passkey-design.md`
// §4.3, as amended by its adversarial review of 2026-10-31).
//
// The plugins service relays an act and verifies nothing; minice-id holds no
// key. What makes an act the owner's is a WebAuthn assertion, made on an act
// page the registry owns, under a key pinned in `bot/lib/operator-passkeys.json`
// — a file inside TRUST-31's set through the `bot/lib/` entry, loaded here by
// literal path from this checkout and never from a tree under test.
//
// `verifyAct` runs the twelve checks of §4.3 in order; the first that fails
// names the code, and nothing is written for a refused act. Checks 1–9 need
// only the act and the pin, so the moderation run's `list` job asks them with
// no tree; checks 10–12 read the tree (`treeView`), and the `commit` job asks
// all twelve again before it applies anything.
//
// What the review changed, and where it lives here:
//   * the act page runs top-level, so `crossOrigin` must be `false` and there
//     is no `topOrigin` (check 5);
//   * `exp` is at most 3 h after `iat` for approve, confirm, cancel and revert,
//     and 24 h for deny and revoke_key (check 9, `LIFETIME_S`);
//   * a deny is never `act_already_answered` (check 12);
//   * in a batch, revoke_key and deny apply first, and an approve signed by a
//     key the batch revokes is refused (`verifyBatch`);
//   * a key added to the pin is `pending` until a second change makes it
//     `active`; only an `active` key signs an act (check 3).

import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { cleanEnv } from "../../tools/lib/git-env.mjs";
import { validate as validateSchema } from "../../tools/lib/jsonschema.mjs";
import { ADVISORY_ID_PATTERN, ID_PATTERN } from "../../tools/lib/ids.mjs";
import { isTime } from "../../tools/lib/time.mjs";
import { HOLD_KINDS, readHolds } from "./holds.mjs";
import { loadEntries } from "./moderation.mjs";
import { recordDigest } from "./service-decide.mjs";

// ── names ───────────────────────────────────────────────────────────────────

export const BODY_SCHEMA = "astra.registry.operator-act-body/1";
export const RECORD_SCHEMA = "astra.registry.operator-act/1";
export const PIN_SCHEMA = "astra.registry.operator-passkeys/1";
export const ENROL_SCHEMA = "astra.registry.passkey-enrol/1";
export const REVOKED_SCHEMA = "astra.registry.passkey-revoked/1";

/** Where the pin lives, relative to a registry root; read by literal path (`PIN_FILE`). */
export const PIN_REL = "bot/lib/operator-passkeys.json";
export const PIN_FILE = new URL("./operator-passkeys.json", import.meta.url);
/** `schema/operator-act-v1.json`, from THIS repository (contract 6.8.0's TRUST-31 entry). */
export const RECORD_SCHEMA_FILE = new URL("../../schema/operator-act-v1.json", import.meta.url);

/** The act record's schema, read by literal path; a tree under test never supplies it. */
export function actRecordSchema() {
  return JSON.parse(fs.readFileSync(RECORD_SCHEMA_FILE, "utf8"));
}
export const ACTS_DIR = "state/acts";
export const REVOKED_DIR = "state/passkeys/revoked";
export const DENY_DIR = "state/deny";

/** The six acts, and no seventh. */
export const ACTS = Object.freeze(["approve", "deny", "confirm", "cancel", "revert", "revoke_key"]);

/** The refusal codes, in the order §4.3 asks the checks. */
export const ACT_CODES = Object.freeze([
  "act_malformed",
  "act_signature",
  "act_not_permitted",
  "act_origin",
  "act_expired",
  "act_replayed",
  "act_target_mismatch",
  "act_already_answered",
]);

/** The body's members, exactly (§3.1). */
export const BODY_MEMBERS = Object.freeze(["act", "aud", "exp", "iat", "jti", "main", "schema", "target"]);
export const ASSERTION_MEMBERS = Object.freeze(["authenticator_data", "client_data_json", "credential_id", "signature"]);
export const WIRE_MEMBERS = Object.freeze(["assertion", "body", "jti"]);
export const RECORD_MEMBERS = Object.freeze(["assertion", "at", "body", "jti", "run", "schema"]);

const RELEASE_TARGET = ["commit", "digest", "fingerprint", "held_decision_id", "plugin_id", "repo", "repository_id", "tag", "version"];
const HOLD_TARGET = ["code", "held_at", "held_for", "plugin_id", "service_decision_id"];

/** Each act's target members, exactly. A revert of a deprecate or revoke also names its `advisory`. */
export const TARGET_MEMBERS = Object.freeze({
  approve: RELEASE_TARGET,
  deny: RELEASE_TARGET,
  confirm: HOLD_TARGET,
  cancel: HOLD_TARGET,
  revert: ["action", "entry", "plugin_id", "service_decision_id"],
  revoke_key: ["credential_id", "kid"],
});

/** The longest `exp − iat` per act, in seconds (review finding 8). */
export const LIFETIME_S = Object.freeze({
  approve: 3 * 3600,
  confirm: 3 * 3600,
  cancel: 3 * 3600,
  revert: 3 * 3600,
  deny: 24 * 3600,
  revoke_key: 24 * 3600,
});

/** How far `iat` may run ahead of the bot's clock. */
export const CLOCK_SKEW_S = 300;

/** Check 1's caps, in bytes: the body as UTF-8, the rest once decoded. */
export const CAPS = Object.freeze({
  body: 2048,
  client_data_json: 1024,
  authenticator_data: 512,
  signature: 512,
  credential_id: 1023,
});

/** The algorithms a pinned key may name, and what each must be. */
export const ALGS = Object.freeze(["ES256", "RS256", "EdDSA"]);

export const KID_RE = /^(?!-)(?!.*-$)[a-z0-9-]{1,32}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{16}$/;
const SDI_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PLUGIN_RE = new RegExp(ID_PATTERN);
const ADVISORY_RE = new RegExp(ADVISORY_ID_PATTERN);
const REPO_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const CODE_RE = /^[A-Z][A-Z0-9_]{1,63}$/;
const ENTRY_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z0-9-]+\.json$/;
const RUN_RE = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/actions\/runs\/[0-9]+$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/** The revertible actions (tools/operator.mjs's REVERTIBLE keys). */
const REVERT_ACTIONS = ["delist", "deprecate", "revoke"];

// ── bytes ───────────────────────────────────────────────────────────────────

/**
 * Strict base64url: the URL alphabet, no padding, no whitespace, and the one
 * spelling that re-encodes to itself (so two strings never name one byte
 * string). `null` for anything else, or anything longer than `cap` bytes.
 */
export function b64urlBytes(s, cap) {
  if (typeof s !== "string" || s.length === 0) return null;
  if (s.length > Math.ceil((cap * 4) / 3) + 1) return null;
  if (!B64URL_RE.test(s) || s.length % 4 === 1) return null;
  const buf = Buffer.from(s, "base64url");
  if (buf.toString("base64url") !== s) return null;
  if (buf.length === 0 || buf.length > cap) return null;
  return buf;
}

export const b64url = (buf) => Buffer.from(buf).toString("base64url");
export const sha256 = (data) => crypto.createHash("sha256").update(data).digest();

/**
 * §3.1's canonical form: an object's keys sorted (JS default order) at every
 * level, no whitespace, `JSON.stringify`'s escaping, and nothing but strings,
 * arrays of strings and objects of those. Throws on a number, a boolean, a
 * null or anything else, so a body that carries one cannot be canonical.
 */
export function canonical(value) {
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => {
      if (typeof v !== "string") throw new TypeError("an array holds strings only");
      return JSON.stringify(v);
    }).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  throw new TypeError(`${value === null ? "null" : typeof value} is not a canonical value`);
}

/** The parsed body when `text` is exactly its own canonical form, else null. */
export function canonicalBody(text) {
  if (typeof text !== "string") return null;
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  try {
    return canonical(doc) === text ? doc : null;
  } catch {
    return null;
  }
}

/** The WebAuthn challenge for a body: SHA-256 of its bytes, base64url (§3.2). */
export const challengeOf = (bodyText) => b64url(sha256(Buffer.from(bodyText, "utf8")));

/** A pinned key's fingerprint: the first 16 hex of SHA-256(SPKI), in four groups. */
export function keyFingerprint(publicKeyB64url) {
  const spki = Buffer.from(String(publicKeyB64url ?? ""), "base64url");
  const hex = sha256(spki).toString("hex").slice(0, 16);
  return hex.match(/.{4}/g).join(" ");
}

const seconds = (t) => Math.floor(new Date(t).getTime() / 1000);

/** The four bytes of authenticatorData that carry the signature counter. */
export function signCountOf(authData) {
  return authData.length >= 37 ? authData.readUInt32BE(33) : 0;
}

// ── the pin ─────────────────────────────────────────────────────────────────

/** The pin from THIS checkout (`PIN_FILE`), or from a registry root's literal path. */
export function loadPin(root = null) {
  const file = root ? path.join(root, ...PIN_REL.split("/")) : PIN_FILE;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** A key object for a pinned key, held to its `alg`; throws when it is not one. */
export function publicKeyOf(key) {
  const der = b64urlBytes(key?.public_key, 4096);
  if (!der) throw new Error("public_key is not strict base64url");
  const k = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  if (key.alg === "ES256") {
    if (k.asymmetricKeyType !== "ec" || k.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error("ES256 names a P-256 key");
  } else if (key.alg === "RS256") {
    if (k.asymmetricKeyType !== "rsa" || (k.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error("RS256 names an RSA key of 2048 bits or more");
  } else if (key.alg === "EdDSA") {
    if (k.asymmetricKeyType !== "ed25519") throw new Error("EdDSA names an Ed25519 key");
  } else {
    throw new Error(`alg ${JSON.stringify(key.alg)} is none of ${ALGS.join(", ")}`);
  }
  return k;
}

/** The pinned key a credential id names, or null. */
export const keyByCredential = (pin, credentialId) =>
  (Array.isArray(pin?.keys) ? pin.keys : []).find((k) => k?.credential_id === credentialId) ?? null;
export const keyByKid = (pin, kid) =>
  (Array.isArray(pin?.keys) ? pin.keys : []).find((k) => k?.kid === kid) ?? null;

// ── checks 4–8: one assertion under one key ─────────────────────────────────

/**
 * Checks 4 to 8 of §4.3 for one assertion over one body, under one pinned key:
 * the client data, the origin, the authenticator data, its flags, and the
 * signature. The same five checks hold an enrolment's self-signature, an
 * endorsement and every act record `tools/validate.mjs` re-reads.
 *
 * @returns {{ok: true, signCount: number} | {ok: false, code: string, why: string}}
 */
export function verifyAssertion({ key, bodyText, assertion, pin }) {
  const fail = (code, why) => ({ ok: false, code, why });
  const cdBytes = b64urlBytes(assertion?.client_data_json, CAPS.client_data_json);
  const authData = b64urlBytes(assertion?.authenticator_data, CAPS.authenticator_data);
  const sig = b64urlBytes(assertion?.signature, CAPS.signature);
  if (!cdBytes || !authData || !sig) return fail("act_malformed", "an assertion member is not strict base64url within its cap");

  let cd;
  try {
    cd = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(cdBytes));
  } catch {
    return fail("act_malformed", "clientDataJSON is not UTF-8 JSON");
  }
  if (!cd || typeof cd !== "object" || Array.isArray(cd)) return fail("act_malformed", "clientDataJSON is not an object");

  // 4. what was signed, and over which body
  if (cd.type !== "webauthn.get") return fail("act_signature", `clientDataJSON.type is ${JSON.stringify(cd.type)}, not webauthn.get`);
  if (cd.challenge !== challengeOf(bodyText)) return fail("act_signature", "clientDataJSON.challenge is not SHA-256 of this body");

  // 5. where: the act page, top-level (review finding 2)
  const origins = Array.isArray(pin?.origins) ? pin.origins : [];
  if (typeof cd.origin !== "string" || !origins.includes(cd.origin)) {
    return fail("act_origin", `origin ${JSON.stringify(cd.origin)} is not a pinned act-page origin`);
  }
  if (cd.crossOrigin !== false) return fail("act_origin", "the ceremony did not run top-level (crossOrigin is not false)");
  if ("topOrigin" in cd) return fail("act_origin", "the ceremony names a topOrigin; the act page runs top-level only");

  // 6. which relying party
  if (authData.length < 37) return fail("act_origin", "authenticatorData is shorter than 37 bytes");
  if (typeof pin?.rp_id !== "string" || pin.rp_id === "" || !authData.subarray(0, 32).equals(sha256(pin.rp_id))) {
    return fail("act_origin", "rpIdHash is not SHA-256 of the pinned rp_id");
  }

  // 7. flags: user present and verified; no attested data, no extensions;
  //    not backup-eligible where the key is pinned device-bound
  const flags = authData[32];
  if (!(flags & 0x01)) return fail("act_signature", "the UP flag is clear");
  if (!(flags & 0x04)) return fail("act_signature", "the UV flag is clear");
  if (flags & 0x40) return fail("act_signature", "the AT flag is set on an assertion");
  if (flags & 0x80) return fail("act_signature", "the ED flag is set; no extension is asked for");
  if (key.device_bound === "yes" && (flags & 0x08)) return fail("act_signature", "the BE flag is set on a key pinned device-bound");
  if (authData.length !== 37) return fail("act_signature", "authenticatorData carries bytes past its 37 with AT and ED clear");

  // 8. the signature, over authenticatorData ‖ SHA-256(clientDataJSON)
  let pub;
  try {
    pub = publicKeyOf(key);
  } catch (err) {
    return fail("act_signature", `the pinned key does not load: ${err.message}`);
  }
  const signed = Buffer.concat([authData, sha256(cdBytes)]);
  let good = false;
  try {
    if (key.alg === "ES256") good = crypto.verify("sha256", signed, { key: pub, dsaEncoding: "der" }, sig);
    else if (key.alg === "RS256") good = crypto.verify("sha256", signed, { key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, sig);
    else good = crypto.verify(null, signed, pub, sig);
  } catch {
    good = false;
  }
  if (!good) return fail("act_signature", "the signature does not verify under the pinned key");
  return { ok: true, signCount: signCountOf(authData) };
}

// ── checks 1–2: shape ───────────────────────────────────────────────────────

const exact = (doc, members) =>
  doc && typeof doc === "object" && !Array.isArray(doc) &&
  Object.keys(doc).sort().join(",") === [...members].sort().join(",");

const STRING_MAX = 256;
const str = (v) => typeof v === "string" && v !== "" && v.length <= STRING_MAX;

/** Why a target is not one of `act`'s, or null. */
export function targetProblem(act, t) {
  const members = act === "revert" && ["deprecate", "revoke"].includes(t?.action)
    ? [...TARGET_MEMBERS.revert, "advisory"]
    : TARGET_MEMBERS[act];
  if (!exact(t, members)) return `the target of ${act} carries ${Object.keys(t ?? {}).sort().join(",")}, not ${[...members].sort().join(",")}`;
  if (!Object.values(t).every(str)) return "every target member is a non-empty string";
  switch (act) {
    case "approve":
    case "deny":
      if (!HEX32.test(t.held_decision_id)) return "held_decision_id";
      if (!HEX64.test(t.digest)) return "digest";
      if (!HEX16.test(t.fingerprint) || t.digest.slice(0, 16) !== t.fingerprint) return "fingerprint is not the first 16 hex of digest";
      if (!PLUGIN_RE.test(t.plugin_id)) return "plugin_id";
      if (!REPO_RE.test(t.repo)) return "repo";
      if (!/^[0-9]{1,20}$/.test(t.repository_id)) return "repository_id";
      if (!HEX40.test(t.commit)) return "commit";
      return null;
    case "confirm":
    case "cancel":
      if (!SDI_RE.test(t.service_decision_id)) return "service_decision_id";
      if (!CODE_RE.test(t.code)) return "code";
      if (!PLUGIN_RE.test(t.plugin_id)) return "plugin_id";
      if (!HOLD_KINDS.includes(t.held_for)) return "held_for";
      if (!isTime(t.held_at)) return "held_at";
      return null;
    case "revert":
      if (!SDI_RE.test(t.service_decision_id)) return "service_decision_id";
      if (!REVERT_ACTIONS.includes(t.action)) return "action";
      if (!PLUGIN_RE.test(t.plugin_id)) return "plugin_id";
      if (!ENTRY_RE.test(t.entry)) return "entry";
      if ("advisory" in t && !ADVISORY_RE.test(t.advisory)) return "advisory";
      return null;
    case "revoke_key":
      if (!KID_RE.test(t.kid)) return "kid";
      if (!b64urlBytes(t.credential_id, CAPS.credential_id)) return "credential_id";
      return null;
    default:
      return `act ${JSON.stringify(act)}`;
  }
}

const carries = (doc, members) =>
  doc && typeof doc === "object" && !Array.isArray(doc) && members.every((m) => Object.hasOwn(doc, m));

/**
 * Checks 1 and 2: the wire item's shape, the caps, strict base64url, and a
 * body that is canonical, exact, addressed to this registry and naming a
 * target of its act's shape. Returns the parsed body, or a refusal.
 *
 * The wire item and its assertion may carry members beyond the ones read here
 * — SCOPE-3's read side, as every answer from the service is read: nothing
 * unsigned that this file does not read can change what it decides, and a
 * refused act is a final answer, so a member the service adds in a legal
 * MINOR must not refuse every act. The BODY is the signed part, and it is
 * exact, byte for byte.
 */
export function shapeOf(item, pin) {
  const fail = (why) => ({ ok: false, code: "act_malformed", why });
  if (!carries(item, WIRE_MEMBERS)) return fail("the act does not carry jti, body and assertion");
  if (!carries(item.assertion, ASSERTION_MEMBERS)) return fail("the assertion does not carry its four members");
  if (typeof item.body !== "string" || Buffer.byteLength(item.body, "utf8") > CAPS.body) return fail(`the body is not a string of at most ${CAPS.body} bytes`);
  for (const m of ASSERTION_MEMBERS) {
    if (!b64urlBytes(item.assertion[m], CAPS[m])) return fail(`assertion.${m} is not strict base64url within ${CAPS[m]} bytes`);
  }
  const body = canonicalBody(item.body);
  if (!body) return fail("the body is not its own canonical form");
  if (!exact(body, BODY_MEMBERS)) return fail(`the body carries ${Object.keys(body).sort().join(",")}`);
  if (body.schema !== BODY_SCHEMA) return fail(`schema ${JSON.stringify(body.schema)}`);
  if (typeof pin?.aud !== "string" || body.aud !== pin.aud) return fail("aud is not this registry's");
  if (!ACTS.includes(body.act)) return fail(`act ${JSON.stringify(body.act)}`);
  if (!HEX32.test(String(body.jti)) || body.jti !== item.jti) return fail("jti is not 32 hex, or not the act's own");
  if (!isTime(body.iat) || !isTime(body.exp)) return fail("iat and exp are §0.7 whole-second times");
  if (!HEX40.test(String(body.main))) return fail("main is not a 40-hex commit");
  const problem = targetProblem(body.act, body.target);
  if (problem) return fail(`target: ${problem}`);
  return { ok: true, body };
}

// ── the batch ───────────────────────────────────────────────────────────────

/** What one run has applied so far, so later acts in it are judged against it. */
export function newBatch() {
  return {
    jtis: new Set(),
    revoked: new Set(),
    counts: new Map(),
    approvals: new Set(),
    denies: new Set(),
    holds: new Set(),
    reverts: new Set(),
  };
}

function remember(batch, v) {
  batch.jtis.add(v.jti);
  if (v.signCount > 0) batch.counts.set(v.kid, Math.max(batch.counts.get(v.kid) ?? 0, v.signCount));
  const t = v.body.target;
  if (v.act === "revoke_key") batch.revoked.add(t.kid);
  if (v.act === "deny") batch.denies.add(t.fingerprint);
  if (v.act === "approve") batch.approvals.add(t.held_decision_id);
  if (v.act === "confirm" || v.act === "cancel") batch.holds.add(t.service_decision_id);
  if (v.act === "revert") batch.reverts.add(t.service_decision_id);
}

// ── verifyAct ───────────────────────────────────────────────────────────────

/**
 * §4.3, in order; the first failure names the code.
 *
 * @param item  `{jti, body, assertion}` as the service relays it
 * @param opts.pin   the pin, from this checkout (`loadPin()`)
 * @param opts.now   the bot's clock (Date or ms)
 * @param opts.view  `treeView(root)`, or null in `list` (no tree: checks 1–9)
 * @param opts.batch what this run applied before this act (`newBatch()`)
 * @returns {{verdict: "apply"|"applied"|"refused"|"verified", code?: string, why?: string,
 *            jti?: string, act?: string, kid?: string, body?: object, signCount?: number}}
 */
export function verifyAct(item, { pin, now, view = null, batch = newBatch() }) {
  const refused = (code, why, extra = {}) => ({ verdict: "refused", code, why, jti: typeof item?.jti === "string" ? item.jti : null, ...extra });

  // 1–2
  const shape = shapeOf(item, pin);
  if (!shape.ok) return refused(shape.code, shape.why);
  const body = shape.body;
  const base = { jti: body.jti, act: body.act };

  // A byte-identical re-presentation of an act already on main is answered
  // `applied`, whatever has happened since: it was verified when it landed,
  // and answering writes nothing.
  const prior = view?.actRecord(body.jti) ?? null;
  if (prior && prior.body === item.body && exact(prior.assertion, ASSERTION_MEMBERS) &&
      ASSERTION_MEMBERS.every((m) => prior.assertion[m] === item.assertion[m])) {
    return { verdict: "applied", ...base, why: "this act is already on main, byte for byte" };
  }

  // 3. which key, and may it
  const key = keyByCredential(pin, item.assertion.credential_id);
  if (!key) return refused("act_signature", "the credential is not a pinned key", base);
  const kid = key.kid;
  if (key.status !== "active") return refused("act_not_permitted", `key ${kid} is ${key.status}, not active`, { ...base, kid });
  if (batch.revoked.has(kid) || view?.revoked(kid)) return refused("act_not_permitted", `key ${kid} is revoked`, { ...base, kid });
  if (!Array.isArray(key.acts) || !key.acts.includes(body.act)) return refused("act_not_permitted", `key ${kid} may not ${body.act}`, { ...base, kid });
  if (body.act === "confirm" && body.target.held_for === "unbound_yank") {
    return refused("act_not_permitted", "an unbound_yank ends only on a cancel; no confirmation releases it (M-T3.3)", { ...base, kid });
  }

  // 4–8
  const sig = verifyAssertion({ key, bodyText: item.body, assertion: item.assertion, pin });
  if (!sig.ok) return refused(sig.code, sig.why, { ...base, kid });

  // 9. time
  const t = Math.floor((now instanceof Date ? now.getTime() : Number(now)) / 1000);
  const iat = seconds(body.iat);
  const exp = seconds(body.exp);
  if (iat > t + CLOCK_SKEW_S) return refused("act_expired", "iat is more than 300 s ahead of the bot's clock", { ...base, kid });
  if (!(t < exp)) return refused("act_expired", "exp has passed", { ...base, kid });
  if (!(exp > iat) || exp - iat > LIFETIME_S[body.act]) {
    return refused("act_expired", `exp − iat is not within (0, ${LIFETIME_S[body.act]}] s for ${body.act}`, { ...base, kid });
  }

  const verified = { ...base, kid, body, signCount: sig.signCount };
  if (!view) return { verdict: "verified", ...verified };

  // 10. replay: the jti, and the counter
  if (prior || batch.jtis.has(body.jti)) return refused("act_replayed", "this jti is already used", { ...base, kid });
  const highest = Math.max(view.highestSignCount(kid), batch.counts.get(kid) ?? 0);
  if ((sig.signCount !== 0 || highest !== 0) && !(sig.signCount > highest)) {
    return refused("act_replayed", `signCount ${sig.signCount} does not exceed ${highest}, the highest recorded for ${kid}`, { ...base, kid });
  }

  // 11. built on main, and still true of it
  if (!view.isAncestor(body.main)) return refused("act_target_mismatch", "main is not an ancestor of the tree", { ...base, kid });
  const facts = view.facts(body.act, body.target);
  if (!facts || canonical(facts) !== canonical(body.target)) {
    return refused("act_target_mismatch", "the target is not what the tree says", { ...base, kid });
  }

  // 12. answered once (a deny never is: review finding 7)
  const answered = view.answered(body.act, body.target, batch);
  if (answered) return refused("act_already_answered", answered, { ...base, kid });

  return { verdict: "apply", ...verified };
}

/** The order a batch applies in: every revoke_key, then every deny, then the rest, each in arrival order. */
export function batchOrder(items) {
  const rank = (it) => {
    const act = canonicalBody(it?.body)?.act;
    return act === "revoke_key" ? 0 : act === "deny" ? 1 : 2;
  };
  return items.map((it, i) => ({ it, i })).sort((a, b) => rank(a.it) - rank(b.it) || a.i - b.i).map(({ it }) => it);
}

/**
 * A run's acts, verified in `batchOrder`, each against what the ones before it
 * applied. Returns the verdicts in that order; the caller applies the `apply`
 * ones in the same order.
 */
export function verifyBatch(items, { pin, now, view = null }) {
  const batch = newBatch();
  const out = [];
  for (const item of batchOrder(items)) {
    const v = verifyAct(item, { pin, now, view, batch });
    if (v.verdict === "apply") remember(batch, v);
    out.push({ item, ...v });
  }
  return out;
}

// ── the tree ────────────────────────────────────────────────────────────────

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function listJson(dir) {
  try {
    return fs.readdirSync(dir).filter((n) => n.endsWith(".json")).sort();
  } catch {
    return [];
  }
}

/** Every act record under `state/acts/` of a registry root, by jti. */
export function readActRecords(root) {
  const dir = path.join(root, ...ACTS_DIR.split("/"));
  const out = new Map();
  for (const name of listJson(dir)) {
    const doc = readJson(path.join(dir, name));
    if (doc && typeof doc.jti === "string" && name === `${doc.jti}.json`) out.set(doc.jti, doc);
  }
  return out;
}

/** A decision record by its id, wherever its month files it. */
function decisionRecord(root, id) {
  const top = path.join(root, "log", "decisions");
  let years = [];
  try {
    years = fs.readdirSync(top);
  } catch {
    return null;
  }
  for (const y of years) {
    let months = [];
    try {
      months = fs.readdirSync(path.join(top, y));
    } catch {
      continue;
    }
    for (const m of months) {
      const f = path.join(top, y, m, `${id}.json`);
      if (fs.existsSync(f)) return readJson(f);
    }
  }
  return null;
}

/** The target an act on this tree would carry, from the tree alone; null when there is none. */
export function factsOf(root, act, target, pin) {
  switch (act) {
    case "approve":
    case "deny": {
      const r = decisionRecord(root, target.held_decision_id);
      if (!r || r.state !== "held" || r.decision_id !== target.held_decision_id) return null;
      const digest = recordDigest(r);
      if (!digest) return null;
      const facts = {
        held_decision_id: r.decision_id, digest, fingerprint: r.fingerprint, plugin_id: r.plugin_id,
        version: r.version, tag: r.tag, repo: r.repo, repository_id: r.repository_id, commit: r.commit,
      };
      return Object.values(facts).every((v) => typeof v === "string") ? facts : null;
    }
    case "confirm":
    case "cancel": {
      const hold = readHolds(root).find((h) => h.id === target.service_decision_id);
      if (!hold || hold.problems.length || !hold.entry) return null;
      const facts = {
        service_decision_id: hold.id, code: hold.entry.decision?.code, plugin_id: hold.entry.decision?.plugin_id,
        held_for: hold.entry.held_for, held_at: hold.entry.held_at,
      };
      return Object.values(facts).every((v) => typeof v === "string") ? facts : null;
    }
    case "revert": {
      const { entries, files } = loadEntries({ root });
      const found = entries.map((e, i) => ({ e, file: files[i] })).filter(({ e }) => e.service_decision_id === target.service_decision_id);
      if (found.length !== 1) return null;
      const { e, file } = found[0];
      if (!REVERT_ACTIONS.includes(e.action)) return null;
      const facts = { service_decision_id: e.service_decision_id, action: e.action, plugin_id: e.plugin, entry: path.basename(file) };
      if (e.action !== "delist") facts.advisory = e.advisory;
      return Object.values(facts).every((v) => typeof v === "string") ? facts : null;
    }
    case "revoke_key": {
      const k = keyByKid(pin, target.kid);
      return k ? { kid: k.kid, credential_id: k.credential_id } : null;
    }
    default:
      return null;
  }
}

/**
 * What a registry root says, for checks 10–12. `root` is the moderation run's
 * one checkout, whose bot and tree are the same commit.
 */
export function treeView(root, { pin, git = defaultGit } = {}) {
  const records = readActRecords(root);
  const counts = new Map();
  for (const doc of records.values()) {
    const k = keyByCredential(pin, doc?.assertion?.credential_id);
    const ad = b64urlBytes(doc?.assertion?.authenticator_data, CAPS.authenticator_data);
    if (!k || !ad) continue;
    counts.set(k.kid, Math.max(counts.get(k.kid) ?? 0, signCountOf(ad)));
  }
  const exists = (rel) => fs.existsSync(path.join(root, ...rel.split("/")));
  const revoked = (kid) => KID_RE.test(String(kid)) && (exists(`${REVOKED_DIR}/${kid}.json`) || keyByKid(pin, kid)?.status === "revoked");
  return {
    root,
    actRecord: (jti) => (HEX32.test(String(jti)) ? records.get(jti) ?? null : null),
    records,
    highestSignCount: (kid) => counts.get(kid) ?? 0,
    revoked,
    isAncestor: (main) => HEX40.test(String(main)) && git.isAncestor(root, main),
    facts: (act, target) => factsOf(root, act, target, pin),
    answered(act, target, batch = newBatch()) {
      switch (act) {
        case "approve": {
          if (batch.denies.has(target.fingerprint) || exists(`${DENY_DIR}/${target.fingerprint}.json`)) {
            return `fingerprint ${target.fingerprint} is denied; an approve never stands beside a deny`;
          }
          if (batch.approvals.has(target.held_decision_id)) return "this held record is already approved in this run";
          for (const doc of records.values()) {
            const b = canonicalBody(doc?.body);
            if (b?.act === "approve" && b.target?.held_decision_id === target.held_decision_id) return "this held record already has the owner's approve";
          }
          return null;
        }
        case "deny":
          return null;
        case "confirm":
        case "cancel": {
          if (batch.holds.has(target.service_decision_id)) return "this hold is already answered in this run";
          const hold = readHolds(root).find((h) => h.id === target.service_decision_id);
          if (hold?.confirm || hold?.cancel) return `the hold already carries a${hold.confirm ? " confirm" : " cancel"} record`;
          return null;
        }
        case "revert": {
          if (batch.reverts.has(target.service_decision_id)) return "this decision is already reverted in this run";
          const { entries } = loadEntries({ root });
          if (entries.some((e) => e.reverses === target.service_decision_id)) return "a log entry already reverses this decision";
          return null;
        }
        case "revoke_key":
          return batch.revoked.has(target.kid) || revoked(target.kid) ? `key ${target.kid} is already revoked` : null;
        default:
          return "unknown act";
      }
    },
  };
}

export const defaultGit = {
  isAncestor(root, commit) {
    try {
      execFileSync("git", ["-C", root, "merge-base", "--is-ancestor", commit, "HEAD"], { stdio: "ignore", env: cleanEnv() });
      return true;
    } catch {
      return false;
    }
  },
};

// ── records ─────────────────────────────────────────────────────────────────

/** `state/acts/<jti>.json`, exactly its six members (§4.5). */
export function actRecord(item, { run, at }) {
  return {
    schema: RECORD_SCHEMA,
    jti: item.jti,
    body: item.body,
    assertion: Object.fromEntries(ASSERTION_MEMBERS.map((m) => [m, item.assertion[m]])),
    run,
    at,
  };
}

/** `state/passkeys/revoked/<kid>.json`. */
export const revokedRecord = ({ kid, at, run }) => ({ schema: REVOKED_SCHEMA, kid, at, run });

/**
 * Why an act record is not one (§4.6), or `[]`: its shape, its name, its
 * canonical body, and its signature under the key its credential names,
 * whatever that key's status is now. Time is not re-checked: the run that
 * wrote it did, and a record stays true after its `exp`.
 */
export function actRecordProblems(doc, { file, pin, schema = actRecordSchema() }) {
  const p = [];
  if (!exact(doc, RECORD_MEMBERS)) return [`${file}: carries ${Object.keys(doc ?? {}).sort().join(",")}, not ${[...RECORD_MEMBERS].sort().join(",")}`];
  for (const e of validateSchema(schema, doc)) p.push(`${file}: ${e.path} ${e.message}`);
  if (doc.schema !== RECORD_SCHEMA) p.push(`${file}: schema ${JSON.stringify(doc.schema)}`);
  if (!HEX32.test(String(doc.jti)) || path.posix.basename(file) !== `${doc.jti}.json`) p.push(`${file}: is not named by its jti`);
  if (!RUN_RE.test(String(doc.run))) p.push(`${file}: run is not a workflow run URL`);
  if (!isTime(doc.at)) p.push(`${file}: at is not a §0.7 time`);
  const shape = shapeOf({ jti: doc.jti, body: doc.body, assertion: doc.assertion }, pin);
  if (!shape.ok) {
    p.push(`${file}: ${shape.why}`);
    return p;
  }
  const key = keyByCredential(pin, doc.assertion.credential_id);
  if (!key) {
    p.push(`${file}: its credential is not a pinned key`);
    return p;
  }
  const v = verifyAssertion({ key, bodyText: doc.body, assertion: doc.assertion, pin });
  if (!v.ok) p.push(`${file}: ${v.why}`);
  return p;
}

export const RECORD_RUN_RE = RUN_RE;

// ── the pin's own rules (design §2.2–§2.3, §4.6; review findings 4, 5, 10) ──

export const PIN_MEMBERS = Object.freeze(["aud", "keys", "origins", "rp_id", "schema"]);
export const KEY_MEMBERS = Object.freeze([
  "acts", "added", "alg", "credential_id", "device_bound", "endorsed_by", "endorsement", "enrolment", "kid", "public_key", "status",
]);
export const KEY_STATUSES = Object.freeze(["pending", "active", "revoked"]);
export const ENROL_MEMBERS = Object.freeze(["acts", "alg", "aud", "credential_id", "iat", "kid", "public_key", "schema"]);
const STATUS_MOVES = new Set(["pending>pending", "active>active", "revoked>revoked", "pending>active", "pending>revoked", "active>revoked"]);
const HOST_RE = /^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/;

/** The enrol body a pinned key must carry, as text, from the key itself. */
export function enrolBodyOf(key, aud, iat) {
  return canonical({ schema: ENROL_SCHEMA, aud, kid: key.kid, credential_id: key.credential_id, alg: key.alg, public_key: key.public_key, acts: key.acts, iat });
}

/**
 * Everything wrong with a pin, alone and against the pin it replaces.
 *
 *   * alone: its shape; each key's members, grammar and loadable key; an
 *     enrolment that is the key's own canonical enrol body, self-signed by
 *     the key (possession); a genesis key (`endorsed_by: ""`) only first, or
 *     after every key listed before it is revoked (review finding 10); every
 *     other key endorsed by a key listed before it, whose assertion over the
 *     same enrol body verifies.
 *   * against `base` (the pin at the commit this one replaces): nothing
 *     removed or reordered, and nothing of a kept key changed but its status,
 *     which only moves pending → active → revoked; `aud` and `rp_id` fixed
 *     once a key exists, and no origin dropped, so old act records keep
 *     verifying; a key ADDED here is `pending` (review finding 4), and its
 *     endorser, if any, was `active` at `base` (review finding 5).
 *
 * `revokedNow(kid)` and `revokedAtBase(kid)` answer whether a revocation
 * record `state/passkeys/revoked/<kid>.json` stands in the tree and at the
 * base. `base` undefined means the base could not be read: the relative rules
 * are not asked, and the caller says so.
 */
export function pinProblems(pin, { base, revokedNow = () => false, revokedAtBase = () => false } = {}) {
  const p = [];
  if (!exact(pin, PIN_MEMBERS)) return [`the pin carries ${Object.keys(pin ?? {}).sort().join(",")}, not ${[...PIN_MEMBERS].join(",")}`];
  if (pin.schema !== PIN_SCHEMA) p.push(`schema ${JSON.stringify(pin.schema)}`);
  if (typeof pin.aud !== "string" || !/^astra-registry:[0-9]{1,20}$/.test(pin.aud)) p.push("aud is not `astra-registry:<repository_id>`");
  if (typeof pin.rp_id !== "string" || (pin.rp_id !== "" && !HOST_RE.test(pin.rp_id))) p.push("rp_id is not a host name");
  if (!Array.isArray(pin.origins) || new Set(pin.origins).size !== pin.origins.length) p.push("origins is not a list of distinct origins");
  else {
    for (const o of pin.origins) {
      const host = typeof o === "string" && /^https:\/\/([^/:?#]+)$/.exec(o)?.[1];
      if (!host || !(host === pin.rp_id || host.endsWith(`.${pin.rp_id}`))) p.push(`origin ${JSON.stringify(o)} is not https on rp_id ${pin.rp_id || "(none)"}`);
    }
  }
  if (!Array.isArray(pin.keys)) return [...p, "keys is not a list"];
  if (pin.keys.length > 0 && (pin.rp_id === "" || !pin.origins?.length)) p.push("a pin with a key names its rp_id and its origins");
  if (p.length) return p;

  const kids = new Set();
  const creds = new Set();
  pin.keys.forEach((key, i) => {
    const at = `keys[${i}]${key?.kid ? ` (${key.kid})` : ""}`;
    if (!exact(key, KEY_MEMBERS)) {
      p.push(`${at} carries ${Object.keys(key ?? {}).sort().join(",")}, not ${KEY_MEMBERS.join(",")}`);
      return;
    }
    if (!KID_RE.test(String(key.kid)) || kids.has(key.kid)) p.push(`${at}: kid is not a distinct kid`);
    kids.add(key.kid);
    if (!b64urlBytes(key.credential_id, CAPS.credential_id) || creds.has(key.credential_id)) p.push(`${at}: credential_id is not a distinct strict base64url id`);
    creds.add(key.credential_id);
    if (!KEY_STATUSES.includes(key.status)) p.push(`${at}: status ${JSON.stringify(key.status)}`);
    if (!Array.isArray(key.acts) || key.acts.length === 0 || new Set(key.acts).size !== key.acts.length || !key.acts.every((a) => ACTS.includes(a))) {
      p.push(`${at}: acts is not a list of distinct acts`);
    }
    if (!["yes", "no"].includes(key.device_bound)) p.push(`${at}: device_bound is "yes" or "no"`);
    if (typeof key.added !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(key.added)) p.push(`${at}: added is a YYYY-MM-DD date`);
    try {
      publicKeyOf(key);
    } catch (err) {
      p.push(`${at}: ${err.message}`);
      return;
    }

    // Possession: the key's own enrol body, signed by the key.
    const enrolment = key.enrolment;
    const body = canonicalBody(enrolment?.body);
    if (!exact(enrolment, ["assertion", "body"]) || !body || !exact(body, ENROL_MEMBERS) || !isTime(body.iat) ||
        enrolment.body !== enrolBodyOf(key, pin.aud, body.iat)) {
      p.push(`${at}: enrolment is not this key's canonical enrol body`);
      return;
    }
    if (!exact(enrolment.assertion, ASSERTION_MEMBERS) || enrolment.assertion.credential_id !== key.credential_id) {
      p.push(`${at}: the enrolment is not signed by this credential`);
    } else {
      const v = verifyAssertion({ key, bodyText: enrolment.body, assertion: enrolment.assertion, pin });
      if (!v.ok) p.push(`${at}: the enrolment does not verify under this key: ${v.why}`);
    }

    if (key.endorsed_by === "") {
      if (key.endorsement !== null) p.push(`${at}: a genesis key carries no endorsement`);
      const live = pin.keys.slice(0, i).filter((k) => !(k?.status === "revoked" || revokedNow(k?.kid)));
      if (live.length) {
        p.push(`${at}: a second genesis key is admitted only when every key listed before it is revoked; ${live.map((k) => k.kid).join(", ")} is not`);
      }
      return;
    }
    const j = pin.keys.findIndex((k) => k?.kid === key.endorsed_by);
    if (j < 0 || j >= i) {
      p.push(`${at}: endorsed_by ${JSON.stringify(key.endorsed_by)} is not a key listed before it`);
      return;
    }
    const endorser = pin.keys[j];
    const e = key.endorsement;
    if (!exact(e, ["assertion"]) || !exact(e.assertion, ASSERTION_MEMBERS) || e.assertion.credential_id !== endorser.credential_id) {
      p.push(`${at}: the endorsement is not an assertion by ${endorser.kid}`);
      return;
    }
    const v = verifyAssertion({ key: endorser, bodyText: enrolment.body, assertion: e.assertion, pin });
    if (!v.ok) p.push(`${at}: the endorsement does not verify under ${endorser.kid}: ${v.why}`);
  });
  if (p.length || base === undefined) return p;

  // Against the pin this one replaces.
  const before = base && Array.isArray(base.keys) ? base.keys : [];
  if (before.length) {
    if (base.aud !== pin.aud) p.push("aud changed after a key was pinned");
    if (base.rp_id !== pin.rp_id) p.push("rp_id changed after a key was pinned; every act record would stop verifying");
    for (const o of base.origins ?? []) if (!pin.origins.includes(o)) p.push(`origin ${o} was dropped; act records made there would stop verifying`);
  }
  before.forEach((old, i) => {
    const now = pin.keys[i];
    if (!now || now.kid !== old?.kid) {
      p.push(`key ${old?.kid} was removed or moved; a key is never deleted, only revoked`);
      return;
    }
    const strip = ({ status, ...rest }) => canonicalish(rest);
    if (strip(now) !== strip(old)) p.push(`key ${old.kid} changed in more than its status`);
    if (!STATUS_MOVES.has(`${old.status}>${now.status}`)) p.push(`key ${old.kid} moved from ${old.status} to ${now.status}`);
  });
  for (const key of pin.keys.slice(before.length)) {
    if (key.status !== "pending") p.push(`key ${key.kid} is added as ${key.status}; a new key is pinned pending, and made active by a second change after its fingerprint is compared`);
    if (key.endorsed_by !== "") {
      const endorser = before.find((k) => k?.kid === key.endorsed_by);
      if (!endorser || endorser.status !== "active" || revokedAtBase(endorser.kid)) {
        p.push(`key ${key.kid} is endorsed by ${key.endorsed_by}, which was not an active key before this change`);
      }
    }
  }
  return p;
}

/** A stable text of any JSON value, for "changed in nothing but" comparisons. */
function canonicalish(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalish).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalish(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/** Why a revocation record is not one, or `[]`. */
export function revokedRecordProblems(doc, { file, pin }) {
  if (!exact(doc, ["at", "kid", "run", "schema"])) return [`${file}: carries ${Object.keys(doc ?? {}).sort().join(",")}, not at,kid,run,schema`];
  const p = [];
  if (doc.schema !== REVOKED_SCHEMA) p.push(`${file}: schema ${JSON.stringify(doc.schema)}`);
  if (!KID_RE.test(String(doc.kid)) || path.posix.basename(file) !== `${doc.kid}.json`) p.push(`${file}: is not named by its kid`);
  else if (!keyByKid(pin, doc.kid)) p.push(`${file}: revokes ${doc.kid}, which is not a pinned key`);
  if (!isTime(doc.at)) p.push(`${file}: at is not a §0.7 time`);
  if (!RUN_RE.test(String(doc.run))) p.push(`${file}: run is not a workflow run URL`);
  return p;
}

// ── the owner's approvals, as the ingest reads them (design §4.7) ───────────

/**
 * Every approve act on the tree at `root` that the ingest may honour now: its
 * record verifies under its pinned key, its `aud` is this registry's, and its
 * key is `active` NOW and may approve — no revocation record and no
 * `revoked` status. A key revoked after the act was applied is not honoured
 * (§4.7): the release falls back to a moderator's approval with its operator
 * window, or stays held. `exp` is not re-checked: the moderation run applied
 * the act inside it.
 *
 * @returns {{jti: string, kid: string, at: string, target: object}[]}
 */
export function ownerApprovalsAt(root, { pin = loadPin() } = {}) {
  const out = [];
  if (pinRefusal(pin).length) return out;
  const revokedAt = (kid) => fs.existsSync(path.join(root, ...REVOKED_DIR.split("/"), `${kid}.json`));
  for (const doc of readActRecords(root).values()) {
    const body = canonicalBody(doc?.body);
    if (body?.act !== "approve" || body.aud !== pin?.aud) continue;
    if (actRecordProblems(doc, { file: `${ACTS_DIR}/${doc.jti}.json`, pin }).length) continue;
    const key = keyByCredential(pin, doc.assertion.credential_id);
    if (!key || key.status !== "active" || revokedAt(key.kid) || !key.acts?.includes("approve")) continue;
    out.push({ jti: doc.jti, kid: key.kid, at: doc.at, target: body.target });
  }
  return out;
}

// ── a pin the bot may act under ─────────────────────────────────────────────

const pinChecked = new WeakMap();

/**
 * The pin's own rules, alone (`pinProblems(pin, {})`), remembered per pin
 * object. While any fails, the bot accepts NO act under it — not in `list`,
 * not in `commit`, not at the ingest, not before a push (review of PR #484,
 * finding 8): a pin a writer bent past `tools/validate.mjs` is not a list of
 * the owner's keys.
 */
export function pinRefusal(pin) {
  if (!pin || typeof pin !== "object") return ["no pin"];
  if (!pinChecked.has(pin)) pinChecked.set(pin, pinProblems(pin, {}));
  return pinChecked.get(pin);
}
