// A software WebAuthn authenticator, for tests only.
//
// It makes what a browser and a platform authenticator make together for a
// `navigator.credentials.get()`: `clientDataJSON` (the browser's), the 37-byte
// `authenticatorData` and a signature over `authenticatorData ‖
// SHA-256(clientDataJSON)` (WebAuthn §6.3.3) — with throwaway keys made in
// memory by `crypto.generateKeyPairSync` and never written anywhere. Every
// field a test wants wrong can be made wrong, so the verifier's refusals are
// asserted on bytes it really receives rather than on a mock of it.

import crypto from "node:crypto";

import { ACTS, BODY_SCHEMA, ENROL_SCHEMA, PIN_SCHEMA, b64url, canonical, challengeOf, sha256 } from "../../lib/operator-act.mjs";

export const RP_ID = "astra-acts.github.io";
export const ORIGIN = `https://${RP_ID}`;
export const AUD = "astra-registry:1331176498";

const GEN = {
  ES256: () => crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }),
  RS256: () => crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }),
  EdDSA: () => crypto.generateKeyPairSync("ed25519"),
};

let serial = 0;

/** A new credential: the pin's entry for it, and the private half the test signs with. */
export function makeKey(alg = "ES256", { kid = `key-${++serial}`, acts = [...ACTS], device_bound = "no", status = "active" } = {}) {
  const { publicKey, privateKey } = GEN[alg]();
  const credential_id = b64url(crypto.randomBytes(16));
  const pinKey = {
    kid, status, acts, credential_id, alg,
    public_key: b64url(publicKey.export({ format: "der", type: "spki" })),
    device_bound, added: "2026-10-31", endorsed_by: "", enrolment: null, endorsement: null,
  };
  const key = { pinKey, privateKey, alg };
  // Self-signed at enrolment, as the act page enrols one: a pin whose key
  // carries no enrolment fails its own rules, and the bot refuses every act
  // under such a pin.
  pinKey.enrolment = enrol(key);
  return key;
}

/** authenticatorData: rpIdHash ‖ flags ‖ signCount, and any extra bytes a test appends. */
export function authData({ rpId = RP_ID, flags = 0x05, signCount = 0, extra = Buffer.alloc(0) } = {}) {
  extra ??= Buffer.alloc(0);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(signCount >>> 0);
  return Buffer.concat([sha256(rpId), Buffer.from([flags]), count, extra]);
}

/** clientDataJSON in the order browsers write it, with whatever a test overrides. */
export function clientData(bodyText, { type = "webauthn.get", challenge = challengeOf(bodyText), origin = ORIGIN, crossOrigin = false, omitCrossOrigin = false, topOrigin, extra = {} } = {}) {
  const doc = { type, challenge, origin };
  if (!omitCrossOrigin) doc.crossOrigin = crossOrigin;
  if (topOrigin !== undefined) doc.topOrigin = topOrigin;
  Object.assign(doc, extra);
  return Buffer.from(JSON.stringify(doc), "utf8");
}

/** Sign `authData ‖ SHA-256(clientDataJSON)` with the credential's key, as the authenticator does. */
export function signWith(key, data) {
  if (key.alg === "ES256") return crypto.sign("sha256", data, { key: key.privateKey, dsaEncoding: "der" });
  if (key.alg === "RS256") return crypto.sign("sha256", data, key.privateKey);
  return crypto.sign(null, data, key.privateKey);
}

/** A whole assertion over `bodyText`; `opts` reaches authData, clientData and the credential id. */
export function assertion(key, bodyText, opts = {}) {
  const ad = opts.authenticatorData ?? authData({ rpId: opts.rpId, flags: opts.flags, signCount: opts.signCount, extra: opts.authExtra });
  const cd = opts.clientDataJSON ?? clientData(bodyText, opts);
  const sig = signWith(key, Buffer.concat([ad, sha256(cd)]));
  return {
    credential_id: opts.credentialId ?? key.pinKey.credential_id,
    authenticator_data: b64url(ad),
    client_data_json: b64url(cd),
    signature: b64url(sig),
  };
}

/** A pin holding these keys. */
export function pinOf(keys, over = {}) {
  return { schema: PIN_SCHEMA, aud: AUD, rp_id: RP_ID, origins: [ORIGIN], keys: keys.map((k) => k.pinKey ?? k), ...over };
}

const iso = (s) => `${new Date(s * 1000).toISOString().slice(0, 19)}Z`;

/** A canonical act body. Times are whole seconds from `now`. */
export function body({ act = "approve", target, jti = crypto.randomBytes(16).toString("hex"), now = Date.parse("2026-10-31T12:00:00Z"), iatOffset = 0, lifetime = 3600, main = "a".repeat(40), aud = AUD } = {}) {
  const t = Math.floor(now / 1000) + iatOffset;
  return canonical({ schema: BODY_SCHEMA, aud, act, jti, iat: iso(t), exp: iso(t + lifetime), main, target });
}

/** The wire item the service relays: `{jti, body, assertion}`. */
export function act(key, bodyText, opts = {}) {
  return { jti: JSON.parse(bodyText).jti, body: bodyText, assertion: assertion(key, bodyText, opts) };
}

/** An enrol body for `key`, and its self-signature: the pin's `enrolment`. */
export function enrol(key, { aud = AUD, iat = "2026-10-31T12:00:00Z", signer = key, opts = {} } = {}) {
  const k = key.pinKey;
  const text = canonical({ schema: ENROL_SCHEMA, aud, kid: k.kid, credential_id: k.credential_id, alg: k.alg, public_key: k.public_key, acts: k.acts, iat });
  return { body: text, assertion: assertion(signer, text, opts) };
}
