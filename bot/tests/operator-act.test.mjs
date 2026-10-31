// `bot/lib/operator-act.mjs`: the owner's passkey acts, verified by the bot
// (astra-plugins-ops `dev/operator-acts-by-passkey-design.md` §4.3 and §7 lane
// 2, as amended by its adversarial review of 2026-10-31).
//
// The authenticator is software, in this file (`fixtures/authenticator.mjs`):
// P-256, RSA-2048 and Ed25519 keys made in memory, `authenticatorData` and
// `clientDataJSON` built byte for byte, and the signature made per WebAuthn
// §6.3.3. So every refusal below is the verifier's answer to bytes it really
// receives. Each mutation of §7's lane 2 list is one case, and each must be
// REFUSED — the verifier never writes, and the moderation run's tests hold the
// "and nothing is written" half.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ACT_CODES,
  CAPS,
  actRecord,
  actRecordProblems,
  b64url,
  b64urlBytes,
  batchOrder,
  canonical,
  canonicalBody,
  challengeOf,
  keyFingerprint,
  shapeOf,
  treeView,
  verifyAct,
  verifyBatch,
} from "../lib/operator-act.mjs";
import { submissionDigest } from "../lib/policy/release.mjs";
import { holdEntry } from "../lib/holds.mjs";
import { fixtureEnv } from "../../tools/lib/git-env.mjs";
import * as A from "./fixtures/authenticator.mjs";

const NOW = Date.parse("2026-10-31T12:00:00Z");
const VECTORS = JSON.parse(fs.readFileSync(new URL("./fixtures/operator-act-vectors.json", import.meta.url), "utf8"));

// ── a held release, as `log/decisions/` carries one ─────────────────────────

const FACTS = { repo: "someone/voice-text-input", tag: "v1.2.1", id: "voice-text-input", version: "1.2.1", commit: "c".repeat(40), digests: [`sha256:${"d".repeat(64)}`] };
const DIGEST = submissionDigest(FACTS);
const HELD_ID = "0123456789abcdef0123456789abcdef";
const heldRecord = (over = {}) => ({
  schema: "astra.registry.decision/1", decision_id: HELD_ID, submission_id: "s-1", decided_at: "2026-10-31T10:00:00Z",
  actor: "bot", trigger: "panel", plugin_id: FACTS.id, version: FACTS.version, repo: FACTS.repo, repository_id: "424242",
  repository_owner_id: "99", tag: FACTS.tag, commit: FACTS.commit, artifact_digests: FACTS.digests,
  fingerprint: DIGEST.slice(0, 16), state: "held", reasons: ["R_BINDING_CHANGED"], ...over,
});
const releaseTarget = (over = {}) => ({
  held_decision_id: HELD_ID, digest: DIGEST, fingerprint: DIGEST.slice(0, 16), plugin_id: FACTS.id,
  version: FACTS.version, tag: FACTS.tag, repo: FACTS.repo, repository_id: "424242", commit: FACTS.commit, ...over,
});

const SDI = "0192f3a4-5b6c-7d8e-9f01-234567890abc";
const holdTarget = (over = {}) => ({ service_decision_id: SDI, code: "M_DELIST", plugin_id: "widgets", held_for: "bound", held_at: "2026-10-31T09:00:00Z", ...over });

// ── a view that says yes to every tree question, so one mutation is the only "no" ──

const yes = (over = {}) => ({
  actRecord: () => null,
  highestSignCount: () => 0,
  revoked: () => false,
  isAncestor: () => true,
  facts: (_act, t) => t,
  answered: () => null,
  ...over,
});

const KEYS = { ES256: A.makeKey("ES256", { kid: "owner-phone" }), RS256: A.makeKey("RS256", { kid: "owner-pc" }), EdDSA: A.makeKey("EdDSA", { kid: "owner-key" }) };
const PIN = A.pinOf(Object.values(KEYS));
const owner = KEYS.ES256;

const approve = (opts = {}, bodyOpts = {}, key = owner) => A.act(key, A.body({ act: "approve", target: releaseTarget(), now: NOW, ...bodyOpts }), opts);
const check = (item, { pin = PIN, now = NOW, view = yes() } = {}) => verifyAct(item, { pin, now, view });

function refusedWith(item, code, opts, label = "") {
  const v = check(item, opts);
  assert.equal(v.verdict, "refused", `${label}: accepted (${JSON.stringify(v).slice(0, 200)})`);
  assert.equal(v.code, code, `${label}: refused as ${v.code} (${v.why}), not ${code}`);
  assert.ok(ACT_CODES.includes(v.code));
  return v;
}

const flipBit = (s, at, bit = 0) => {
  const b = Buffer.from(s, "base64url");
  const i = at < 0 ? b.length + at : at;
  b[i] ^= 1 << bit;
  return b64url(b);
};

// ── the controls ────────────────────────────────────────────────────────────

test("an approve signed by each pinned algorithm verifies and is applied", () => {
  for (const [alg, key] of Object.entries(KEYS)) {
    const v = check(approve({}, {}, key));
    assert.equal(v.verdict, "apply", `${alg}: ${v.code} ${v.why}`);
    assert.equal(v.kid, key.pinKey.kid);
  }
});

test("a browser's extra clientDataJSON member is signed data, not a refusal", () => {
  const v = check(approve({ extra: { other_keys_can_be_added_here: "do not compare clientDataJSON against a template. See https://goo.gl/yabPex" } }));
  assert.equal(v.verdict, "apply", `${v.code} ${v.why}`);
});

test("without a tree (`list`), checks 1–9 run and a good act is `verified`, not applied", () => {
  const v = verifyAct(approve(), { pin: PIN, now: NOW, view: null });
  assert.equal(v.verdict, "verified", `${v.code} ${v.why}`);
});

// ── 1–2: shape, caps, canonical body ────────────────────────────────────────

test("every cap +1 is malformed, and every cap exactly is not refused for size", () => {
  // The body: 2049 bytes refused for its size; 2048 passes the cap (and is
  // refused for something else, since no real target is that long).
  const pad = (n) => {
    const base = A.body({ target: releaseTarget({ tag: "" }), now: NOW });
    return base.replace('"tag":""', `"tag":"${"x".repeat(n - Buffer.byteLength(base))}"`);
  };
  for (const [n, over] of [[CAPS.body, false], [CAPS.body + 1, true]]) {
    const text = pad(n);
    assert.equal(Buffer.byteLength(text), n);
    const v = check({ jti: JSON.parse(text).jti, body: text, assertion: A.assertion(owner, text) });
    assert.equal(v.verdict, "refused");
    assert.equal(/at most 2048 bytes/.test(v.why), over, `body of ${n} bytes: ${v.why}`);
  }

  // clientDataJSON: padded to exactly 1024 bytes it verifies end to end; 1025 is malformed.
  const text = A.body({ target: releaseTarget(), now: NOW });
  const plain = A.clientData(text, { extra: { pad: "" } });
  const at1024 = A.clientData(text, { extra: { pad: "p".repeat(CAPS.client_data_json - plain.length) } });
  assert.equal(at1024.length, 1024);
  assert.equal(check({ jti: JSON.parse(text).jti, body: text, assertion: A.assertion(owner, text, { clientDataJSON: at1024 }) }).verdict, "apply");
  const at1025 = A.clientData(text, { extra: { pad: "p".repeat(CAPS.client_data_json + 1 - plain.length) } });
  refusedWith({ jti: JSON.parse(text).jti, body: text, assertion: A.assertion(owner, text, { clientDataJSON: at1025 }) }, "act_malformed", {}, "clientDataJSON 1025");

  // authenticatorData: 512 is within the cap (and refused at check 7); 513 is malformed.
  const ad = (n) => A.authData({ extra: Buffer.alloc(n - 37) });
  const v512 = check({ jti: JSON.parse(text).jti, body: text, assertion: A.assertion(owner, text, { authenticatorData: ad(512) }) });
  assert.equal(v512.code, "act_signature", v512.why);
  refusedWith({ jti: JSON.parse(text).jti, body: text, assertion: A.assertion(owner, text, { authenticatorData: ad(513) }) }, "act_malformed", {}, "authData 513");

  // signature: 512 bytes is within the cap; 513 is malformed.
  const item = approve();
  const sig = (n) => b64url(Buffer.alloc(n, 1));
  assert.equal(check({ ...item, assertion: { ...item.assertion, signature: sig(512) } }).code, "act_signature");
  refusedWith({ ...item, assertion: { ...item.assertion, signature: sig(513) } }, "act_malformed", {}, "signature 513");

  // credential id: 1023 is within the cap (an unknown key); 1024 is malformed.
  assert.equal(check({ ...item, assertion: { ...item.assertion, credential_id: sig(1023) } }).code, "act_signature");
  refusedWith({ ...item, assertion: { ...item.assertion, credential_id: sig(1024) } }, "act_malformed", {}, "credential id 1024");
});

test("base64url is strict: padding, the other alphabet, whitespace and a non-canonical tail are malformed", () => {
  const item = approve();
  const s = item.assertion.signature;
  const variants = {
    padding: `${s}${"=".repeat((4 - (s.length % 4)) % 4 || 2)}`,
    plus: s.replace(/-/g, "+").replace(/_/g, "/").replace(/^./, "+"),
    space: `${s.slice(0, 4)} ${s.slice(4)}`,
    newline: `${s}\n`,
    empty: "",
  };
  for (const [name, bad] of Object.entries(variants)) {
    refusedWith({ ...item, assertion: { ...item.assertion, signature: bad } }, "act_malformed", {}, name);
  }
  // Two spellings of one byte string: "AB" and "AA" both decode to 0x00 if
  // the tail bits are ignored. Only the canonical one is base64url here.
  assert.notEqual(b64urlBytes("AA", 8), null);
  assert.equal(b64urlBytes("AB", 8), null);
});

test("a non-canonical body is malformed, whatever signs it", () => {
  const good = A.body({ target: releaseTarget(), now: NOW });
  const doc = JSON.parse(good);
  const bodies = {
    whitespace: JSON.stringify(doc, null, 1),
    "a trailing newline": `${good}\n`,
    "keys out of order": good.replace(/^\{"act":"approve","aud":"[^"]+",/, (m) => m.replace(/^\{("act":"approve"),("aud":"[^"]+"),/, "{$2,$1,")),
    "a duplicate key": good.replace('"act":"approve",', '"act":"deny","act":"approve",'),
    "a number": canonicalFrom(doc, (d) => { d.target.repository_id = 424242; }),
    "a boolean": canonicalFrom(doc, (d) => { d.target.extra = true; }),
    "a null": canonicalFrom(doc, (d) => { d.target.extra = null; }),
    "a needless escape": good.replace('"approve"', '"\\u0061pprove"'),
    "an extra member": canonical({ ...doc, note: "x" }),
    "a missing member": canonical(Object.fromEntries(Object.entries(doc).filter(([k]) => k !== "main"))),
    "another schema": canonical({ ...doc, schema: "astra.registry.operator-act-body/2" }),
    "an unknown act": canonical({ ...doc, act: "publish" }),
    "a jti of 31 hex": canonical({ ...doc, jti: doc.jti.slice(1) }),
    "an iat with milliseconds": canonical({ ...doc, iat: doc.iat.replace("Z", ".000Z") }),
    "a short main": canonical({ ...doc, main: "a".repeat(39) }),
    "a target member too many": canonical({ ...doc, target: { ...doc.target, note: "x" } }),
    "a target member too few": canonical({ ...doc, target: Object.fromEntries(Object.entries(doc.target).filter(([k]) => k !== "tag")) }),
    "a fingerprint that is not the digest's": canonical({ ...doc, target: { ...doc.target, fingerprint: "f".repeat(16) } }),
    "a deny's target on a confirm": canonical({ ...doc, act: "confirm" }),
  };
  for (const [name, text] of Object.entries(bodies)) {
    const jti = (() => {
      try {
        return JSON.parse(text).jti;
      } catch {
        return doc.jti;
      }
    })();
    refusedWith({ jti: typeof jti === "string" ? jti : doc.jti, body: text, assertion: A.assertion(owner, text) }, "act_malformed", {}, name);
  }
});

function canonicalFrom(doc, mutate) {
  const d = JSON.parse(JSON.stringify(doc));
  mutate(d);
  // The canonical ORDER with a non-string value inside: what a lax writer emits.
  const enc = (v) => (v && typeof v === "object" && !Array.isArray(v)
    ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${enc(v[k])}`).join(",")}}`
    : JSON.stringify(v));
  return enc(d);
}

test("an aud of another registry is malformed", () => {
  refusedWith(approve({}, { aud: "astra-registry:1" }), "act_malformed", {}, "aud");
});

test("a jti that is not its body's, or a missing member, is malformed; an unsigned extra member is read past (SCOPE-3)", () => {
  const item = approve();
  refusedWith({ ...item, jti: "f".repeat(32) }, "act_malformed", {}, "jti");
  refusedWith({ jti: item.jti, body: item.body }, "act_malformed", {}, "no assertion");
  const { signature, ...three } = item.assertion;
  assert.ok(signature);
  refusedWith({ ...item, assertion: three }, "act_malformed", {}, "three assertion members");
  // A member the service adds in a MINOR is unsigned and unread: it cannot
  // change the verdict, and refusing it would refuse every act at once.
  assert.equal(check({ ...item, received_at: "x" }).verdict, "apply");
  assert.equal(check({ ...item, assertion: { ...item.assertion, user_handle: "AA" } }).verdict, "apply");
  // The record keeps the four it read, and nothing else.
  assert.deepEqual(Object.keys(actRecord({ ...item, assertion: { ...item.assertion, user_handle: "AA" } }, { run: "https://github.com/o/r/actions/runs/1", at: "2026-10-31T12:00:00Z" }).assertion).sort(),
    ["authenticator_data", "client_data_json", "credential_id", "signature"]);
});

// ── 3: which key, and may it ────────────────────────────────────────────────

test("an unpinned, revoked, pending or not-permitted credential is refused", () => {
  const stranger = A.makeKey("ES256", { kid: "stranger" });
  refusedWith(approve({}, {}, stranger), "act_signature", {}, "unpinned");

  const revoked = A.makeKey("ES256", { kid: "revoked", status: "revoked" });
  refusedWith(approve({}, {}, revoked), "act_not_permitted", { pin: A.pinOf([owner, revoked]) }, "revoked in the pin");
  refusedWith(approve(), "act_not_permitted", { view: yes({ revoked: (kid) => kid === "owner-phone" }) }, "revoked by its record");

  const pending = A.makeKey("ES256", { kid: "pending", status: "pending" });
  refusedWith(approve({}, {}, pending), "act_not_permitted", { pin: A.pinOf([owner, pending]) }, "pending");

  const denyOnly = A.makeKey("ES256", { kid: "knice", acts: ["deny"] });
  const pin = A.pinOf([owner, denyOnly]);
  refusedWith(approve({}, {}, denyOnly), "act_not_permitted", { pin }, "not permitted");
  const deny = A.act(denyOnly, A.body({ act: "deny", target: releaseTarget(), now: NOW }));
  assert.equal(check(deny, { pin }).verdict, "apply");
});

test("a confirm of an unbound_yank is not permitted; a cancel of it is", () => {
  const t = holdTarget({ code: "A_YANK", held_for: "unbound_yank" });
  refusedWith(A.act(owner, A.body({ act: "confirm", target: t, now: NOW })), "act_not_permitted", {}, "confirm");
  assert.equal(check(A.act(owner, A.body({ act: "cancel", target: t, now: NOW }))).verdict, "apply");
});

// ── 4–8: the assertion ──────────────────────────────────────────────────────

test("one bit flipped in the signature, authenticatorData, clientDataJSON or body is refused", () => {
  const item = approve();
  refusedWith({ ...item, assertion: { ...item.assertion, signature: flipBit(item.assertion.signature, 10) } }, "act_signature", {}, "signature");
  refusedWith({ ...item, assertion: { ...item.assertion, authenticator_data: flipBit(item.assertion.authenticator_data, -1) } }, "act_signature", {}, "authData counter");
  refusedWith({ ...item, assertion: { ...item.assertion, authenticator_data: flipBit(item.assertion.authenticator_data, 0) } }, "act_origin", {}, "authData rpIdHash");
  // "webauthn.get" → "webauthn.fet": one bit of the `g`.
  const cd = Buffer.from(item.assertion.client_data_json, "base64url");
  const at = cd.indexOf("webauthn.get") + "webauthn.".length;
  refusedWith({ ...item, assertion: { ...item.assertion, client_data_json: flipBit(item.assertion.client_data_json, at) } }, "act_signature", {}, "clientDataJSON");
  // A body still canonical, one bit away: version 1.2.1 → 1.2.0.
  const body = item.body.replace('"version":"1.2.1"', '"version":"1.2.0"');
  assert.notEqual(body, item.body);
  refusedWith({ ...item, body }, "act_signature", {}, "body");
});

test("the same signature over another body is refused", () => {
  const a = approve();
  const b = approve();
  refusedWith({ jti: b.jti, body: b.body, assertion: a.assertion }, "act_signature", {}, "borrowed assertion");
});

test("rpIdHash of astra.minice.ai, origin https://astra.minice.ai, and any framed ceremony are refused", () => {
  refusedWith(approve({ rpId: "astra.minice.ai" }), "act_origin", {}, "rpId");
  refusedWith(approve({ origin: "https://astra.minice.ai" }), "act_origin", {}, "origin");
  refusedWith(approve({ crossOrigin: true }), "act_origin", {}, "crossOrigin true, no topOrigin");
  refusedWith(approve({ crossOrigin: true, topOrigin: "https://evil.example" }), "act_origin", {}, "crossOrigin true, evil topOrigin");
  refusedWith(approve({ crossOrigin: true, topOrigin: "https://astra.minice.ai" }), "act_origin", {}, "crossOrigin true, the console as topOrigin");
  refusedWith(approve({ topOrigin: "https://astra.minice.ai" }), "act_origin", {}, "a topOrigin with crossOrigin false");
  refusedWith(approve({ omitCrossOrigin: true }), "act_origin", {}, "no crossOrigin member");
  refusedWith(approve(), "act_origin", { pin: { ...PIN, rp_id: "" } }, "an empty pinned rp_id");
});

test("type webauthn.create, and every flag the design names, are refused", () => {
  refusedWith(approve({ type: "webauthn.create" }), "act_signature", {}, "create");
  refusedWith(approve({ flags: 0x04 }), "act_signature", {}, "UP off");
  refusedWith(approve({ flags: 0x01 }), "act_signature", {}, "UV off");
  refusedWith(approve({ flags: 0x45 }), "act_signature", {}, "AT set");
  refusedWith(approve({ flags: 0x85 }), "act_signature", {}, "ED set");
  const bound = A.makeKey("ES256", { kid: "yubikey", device_bound: "yes" });
  const pin = A.pinOf([owner, bound]);
  refusedWith(approve({ flags: 0x0d }, {}, bound), "act_signature", { pin }, "BE on a device-bound key");
  // BE and BS on a synced passkey are what one looks like, and are accepted.
  assert.equal(check(approve({ flags: 0x1d }), { pin }).verdict, "apply");
  assert.equal(check(approve({ flags: 0x05 }, {}, bound), { pin }).verdict, "apply");
});

// ── 9: time ─────────────────────────────────────────────────────────────────

test("an act past exp, one living too long for its kind, and one from the future are refused", () => {
  refusedWith(approve({}, { iatOffset: -7200, lifetime: 3600 }), "act_expired", {}, "exp passed");
  refusedWith(approve({}, { lifetime: 3 * 3600 + 1 }), "act_expired", {}, "approve exp − iat = 10801");
  assert.equal(check(approve({}, { lifetime: 3 * 3600 })).verdict, "apply", "approve at exactly 3 h");
  for (const act of ["confirm", "cancel"]) {
    refusedWith(A.act(owner, A.body({ act, target: holdTarget(), now: NOW, lifetime: 10801 })), "act_expired", {}, `${act} 10801`);
  }
  const deny = (lifetime) => A.act(owner, A.body({ act: "deny", target: releaseTarget(), now: NOW, lifetime }));
  refusedWith(deny(86401), "act_expired", {}, "deny exp − iat = 86401");
  assert.equal(check(deny(86400)).verdict, "apply", "deny at exactly 24 h");
  refusedWith(approve({}, { iatOffset: 301 }), "act_expired", {}, "iat = now + 301");
  assert.equal(check(approve({}, { iatOffset: 300 })).verdict, "apply", "iat = now + 300");
  refusedWith(approve({}, { lifetime: 0 }), "act_expired", {}, "exp = iat");
});

// ── 10: replay ──────────────────────────────────────────────────────────────

test("a jti on main, a jti twice in a batch, and a counter that does not rise are refused", () => {
  const item = approve();
  const other = approve();
  // On main with other bytes: replayed. With the same bytes: answered `applied`.
  refusedWith(item, "act_replayed", { view: yes({ actRecord: () => ({ body: other.body, assertion: other.assertion }) }) }, "jti on main");
  const same = check(item, { view: yes({ actRecord: () => ({ body: item.body, assertion: item.assertion }) }) });
  assert.equal(same.verdict, "applied", "a byte-identical re-presentation is answered applied");

  const batch = verifyBatch([item, item], { pin: PIN, now: NOW, view: yes() });
  assert.deepEqual(batch.map((v) => v.verdict), ["apply", "refused"]);
  assert.equal(batch[1].code, "act_replayed");

  refusedWith(approve({ signCount: 5 }), "act_replayed", { view: yes({ highestSignCount: () => 5 }) }, "equal counter");
  refusedWith(approve({ signCount: 4 }), "act_replayed", { view: yes({ highestSignCount: () => 5 }) }, "lower counter");
  refusedWith(approve({ signCount: 0 }), "act_replayed", { view: yes({ highestSignCount: () => 5 }) }, "a counter back to zero");
  assert.equal(check(approve({ signCount: 6 }), { view: yes({ highestSignCount: () => 5 }) }).verdict, "apply");
  assert.equal(check(approve({ signCount: 0 }), { view: yes({ highestSignCount: () => 0 }) }).verdict, "apply", "a synced passkey's zero");

  const twoCounts = verifyBatch([approve({ signCount: 7 }), A.act(owner, A.body({ act: "deny", target: releaseTarget({ held_decision_id: "1".repeat(32) }), now: NOW }), { signCount: 7 })], { pin: PIN, now: NOW, view: yes() });
  assert.deepEqual(twoCounts.map((v) => [v.act, v.verdict, v.code ?? null]), [["deny", "apply", null], ["approve", "refused", "act_replayed"]]);
});

// ── 11: built on main, and still true of it ─────────────────────────────────

test("main not an ancestor, and each target member changed, are refused", () => {
  refusedWith(approve(), "act_target_mismatch", { view: yes({ isAncestor: () => false }) }, "main");
  const truth = releaseTarget();
  const view = yes({ facts: () => truth });
  const changed = {
    held_decision_id: "1".repeat(32),
    digest: DIGEST.slice(0, 16) + "0".repeat(48),
    fingerprint: null,
    plugin_id: "other-plugin",
    version: "1.2.2",
    tag: "v1.2.2",
    repo: "someone/else",
    repository_id: "424243",
    commit: "e".repeat(40),
  };
  for (const [member, value] of Object.entries(changed)) {
    const target = member === "fingerprint"
      ? releaseTarget({ digest: `${"f".repeat(16)}${DIGEST.slice(16)}`, fingerprint: "f".repeat(16) })
      : releaseTarget({ [member]: value });
    refusedWith(A.act(owner, A.body({ act: "approve", target, now: NOW })), "act_target_mismatch", { view }, member);
  }
  for (const [member, value] of Object.entries({ service_decision_id: "0192f3a4-5b6c-7d8e-9f01-234567890abd", code: "M_DEPRECATE", plugin_id: "gadgets", held_for: "unbound_removal", held_at: "2026-10-31T09:00:01Z" })) {
    refusedWith(A.act(owner, A.body({ act: "confirm", target: holdTarget({ [member]: value }), now: NOW })), "act_target_mismatch", { view: yes({ facts: () => holdTarget() }) }, member);
  }
  refusedWith(approve(), "act_target_mismatch", { view: yes({ facts: () => null }) }, "no such target");
});

// ── 12: answered once ───────────────────────────────────────────────────────

test("a target already answered is refused, and a deny never is", () => {
  refusedWith(approve(), "act_already_answered", { view: yes({ answered: () => "already" }) }, "approve");
  const deny = A.act(owner, A.body({ act: "deny", target: releaseTarget(), now: NOW }));
  // A deny is judged by the real `answered`, which never refuses one.
  const root = treeFixture();
  const v = verifyAct(deny, { pin: PIN, now: NOW, view: { ...treeView(root, { pin: PIN }), isAncestor: () => true } });
  assert.equal(v.verdict, "apply", `${v.code} ${v.why}`);
});

// ── the batch ───────────────────────────────────────────────────────────────

test("in a batch, revoke_key and deny apply first: an approve by a key the batch revokes, or beside its deny, is refused", () => {
  const phone = KEYS.ES256;
  const pc = KEYS.RS256;
  const approveByPhone = approve({}, {}, phone);
  const revokePhone = A.act(pc, A.body({ act: "revoke_key", target: { kid: phone.pinKey.kid, credential_id: phone.pinKey.credential_id }, now: NOW, lifetime: 86400 }));
  const out = verifyBatch([approveByPhone, revokePhone], { pin: PIN, now: NOW, view: yes() });
  assert.deepEqual(out.map((v) => [v.act, v.verdict, v.code ?? null]), [["revoke_key", "apply", null], ["approve", "refused", "act_not_permitted"]]);

  const root = treeFixture();
  const view = { ...treeView(root, { pin: PIN }), isAncestor: () => true };
  const approveByPc = approve({}, {}, pc);
  const deny = A.act(phone, A.body({ act: "deny", target: releaseTarget(), now: NOW }));
  const out2 = verifyBatch([approveByPc, deny], { pin: PIN, now: NOW, view });
  assert.deepEqual(out2.map((v) => [v.act, v.verdict, v.code ?? null]), [["deny", "apply", null], ["approve", "refused", "act_already_answered"]]);

  assert.deepEqual(batchOrder([approveByPc, deny, revokePhone]).map((i) => canonicalBody(i.body).act), ["revoke_key", "deny", "approve"]);
});

// ── the tree ────────────────────────────────────────────────────────────────

const roots = [];
process.on("exit", () => {
  for (const r of roots) fs.rmSync(r, { recursive: true, force: true });
});
const git = (root, ...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8", env: fixtureEnv(root) }).trim();
const writeJson = (root, rel, doc) => {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), `${JSON.stringify(doc, null, 2)}\n`);
};
const DELIST_SDI = "0192f3a4-5b6c-7d8e-9f01-234567890abd";

function treeFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "operator-act-"));
  roots.push(root);
  writeJson(root, `log/decisions/2026/10/${HELD_ID}.json`, heldRecord());
  writeJson(root, `state/holds/${SDI}.json`, holdEntry(
    { service_decision_id: SDI, code: "M_DELIST", plugin_id: "widgets", decided_at: "2026-10-31T08:00:00Z", reason: "Broken on every platform.", category: "broken", moderator: "amoderator" },
    { held_for: "bound", held_at: "2026-10-31T09:00:00Z" },
  ));
  writeJson(root, "bot/moderation/2026-10-30-widgets-delist.json", {
    date: "2026-10-30", action: "delist", plugin: "widgets", reason: "Broken on every platform.", category: "broken",
    service_decision_id: DELIST_SDI, declared_interest: false,
  });
  git(root, "init", "-q", "-b", "main");
  git(root, "add", "-A");
  git(root, "commit", "-q", "-m", "fixture");
  return root;
}

test("the tree view: facts for every act, main's ancestry, and each act answered once", () => {
  const root = treeFixture();
  const head = git(root, "rev-parse", "HEAD");
  const view = treeView(root, { pin: PIN });
  const on = (act, target, extra = {}) => verifyAct(A.act(owner, A.body({ act, target, now: NOW, main: head, lifetime: act === "deny" || act === "revoke_key" ? 86400 : 3600, ...extra })), { pin: PIN, now: NOW, view });

  assert.deepEqual(view.facts("approve", { held_decision_id: HELD_ID }), releaseTarget());
  for (const act of ["approve", "deny"]) assert.equal(on(act, releaseTarget()).verdict, "apply", act);
  for (const act of ["confirm", "cancel"]) {
    const v = on(act, holdTarget({ code: "M_DELIST" }));
    assert.equal(v.verdict, "apply", `${act}: ${v.code} ${v.why}`);
  }
  const revert = on("revert", { service_decision_id: DELIST_SDI, action: "delist", plugin_id: "widgets", entry: "2026-10-30-widgets-delist.json" });
  assert.equal(revert.verdict, "apply", `${revert.code} ${revert.why}`);
  const revoke = on("revoke_key", { kid: "owner-pc", credential_id: KEYS.RS256.pinKey.credential_id });
  assert.equal(revoke.verdict, "apply", `${revoke.code} ${revoke.why}`);

  // An act built on a commit the tree does not descend from.
  const v = on("approve", releaseTarget(), { main: "f".repeat(40) });
  assert.equal(v.code, "act_target_mismatch");
  // A held record that is not held.
  writeJson(root, `log/decisions/2026/10/${HELD_ID}.json`, heldRecord({ state: "published" }));
  assert.equal(on("approve", releaseTarget()).code, "act_target_mismatch");
  writeJson(root, `log/decisions/2026/10/${HELD_ID}.json`, heldRecord());

  // Answered: an approve record, a deny, a confirm record, a revert, a revocation.
  const first = A.act(owner, A.body({ act: "approve", target: releaseTarget(), now: NOW, main: head }));
  writeJson(root, `state/acts/${first.jti}.json`, actRecord(first, { run: "https://github.com/o/r/actions/runs/1", at: "2026-10-31T12:00:00Z" }));
  const view2 = treeView(root, { pin: PIN });
  assert.equal(verifyAct(first, { pin: PIN, now: NOW, view: view2 }).verdict, "applied", "byte-identical re-presentation");
  assert.equal(verifyAct(A.act(owner, A.body({ act: "approve", target: releaseTarget(), now: NOW, main: head })), { pin: PIN, now: NOW, view: view2 }).code, "act_already_answered");

  writeJson(root, "state/deny/" + DIGEST.slice(0, 16) + ".json", { schema: "astra.registry.deny/1", fingerprint: DIGEST.slice(0, 16), run: "x", at: "2026-10-31T12:00:00Z" });
  fs.rmSync(path.join(root, `state/acts/${first.jti}.json`));
  assert.equal(on("approve", releaseTarget()).code, "act_already_answered", "approve beside a deny");
  assert.equal(on("deny", releaseTarget()).verdict, "apply", "a second deny is never answered");

  writeJson(root, `state/holds/${SDI}.confirm.json`, { schema: "astra.registry.hold-record/1", act: "confirm", service_decision_id: SDI, plugin_id: "widgets", at: "2026-10-31T11:00:00Z" });
  assert.equal(on("cancel", holdTarget({ code: "M_DELIST" })).code, "act_already_answered");

  writeJson(root, "bot/moderation/2026-10-31-widgets-relist.json", {
    date: "2026-10-31", action: "relist", plugin: "widgets", reason: "Reverted by the registry operator: the decision this entry reverses was made in error.",
    category: "error", reverses: DELIST_SDI,
  });
  assert.equal(on("revert", { service_decision_id: DELIST_SDI, action: "delist", plugin_id: "widgets", entry: "2026-10-30-widgets-delist.json" }).code, "act_already_answered");

  writeJson(root, "state/passkeys/revoked/owner-pc.json", { schema: "astra.registry.passkey-revoked/1", kid: "owner-pc", at: "2026-10-31T12:00:00Z", run: "x" });
  assert.equal(on("revoke_key", { kid: "owner-pc", credential_id: KEYS.RS256.pinKey.credential_id }).code, "act_already_answered");
  const byPc = verifyAct(A.act(KEYS.RS256, A.body({ act: "deny", target: releaseTarget(), now: NOW, main: head, lifetime: 86400 })), { pin: PIN, now: NOW, view: treeView(root, { pin: PIN }) });
  assert.equal(byPc.code, "act_not_permitted", "a key revoked by its record signs nothing");
});

test("the tree view reads the highest counter recorded for a key", () => {
  const root = treeFixture();
  const head = git(root, "rev-parse", "HEAD");
  const counted = A.act(owner, A.body({ act: "deny", target: releaseTarget(), now: NOW, main: head }), { signCount: 9 });
  writeJson(root, `state/acts/${counted.jti}.json`, actRecord(counted, { run: "https://github.com/o/r/actions/runs/1", at: "2026-10-31T12:00:00Z" }));
  const view = treeView(root, { pin: PIN });
  assert.equal(view.highestSignCount("owner-phone"), 9);
  const v = verifyAct(A.act(owner, A.body({ act: "deny", target: releaseTarget(), now: NOW, main: head }), { signCount: 9 }), { pin: PIN, now: NOW, view });
  assert.equal(v.code, "act_replayed");
});

// ── records ─────────────────────────────────────────────────────────────────

test("an act record verifies under its key whatever the key's status now; a tampered one does not", () => {
  const item = approve();
  const rec = actRecord(item, { run: "https://github.com/o/r/actions/runs/1", at: "2026-10-31T12:00:00Z" });
  const file = `state/acts/${item.jti}.json`;
  assert.deepEqual(actRecordProblems(rec, { file, pin: PIN }), []);
  const revokedPin = { ...PIN, keys: PIN.keys.map((k) => (k.kid === "owner-phone" ? { ...k, status: "revoked" } : k)) };
  assert.deepEqual(actRecordProblems(rec, { file, pin: revokedPin }), [], "a revoked key's old records keep verifying");
  assert.notDeepEqual(actRecordProblems({ ...rec, body: rec.body.replace("1.2.1", "1.2.0") }, { file, pin: PIN }), []);
  assert.notDeepEqual(actRecordProblems(rec, { file: "state/acts/other.json", pin: PIN }), []);
  assert.notDeepEqual(actRecordProblems({ ...rec, account: "x" }, { file, pin: PIN }), [], "no account id rides in a record");
});

// ── the vectors the act page reuses ─────────────────────────────────────────

test("the canonical-body vectors hold, and the act page can reuse them byte for byte", () => {
  assert.ok(VECTORS.valid.length >= 6 && VECTORS.invalid.length >= 6);
  for (const v of VECTORS.valid) {
    assert.equal(canonical(v.value), v.canonical, v.name);
    assert.deepEqual(canonicalBody(v.canonical), v.value, v.name);
    assert.equal(challengeOf(v.canonical), v.challenge, v.name);
    if (v.value.schema === "astra.registry.operator-act-body/1") {
      const s = shapeOf({ jti: v.value.jti, body: v.canonical, assertion: approve().assertion }, { ...PIN, aud: v.value.aud });
      assert.ok(s.ok, `${v.name}: ${s.why}`);
    }
  }
  for (const v of VECTORS.invalid) assert.equal(canonicalBody(v.text), null, v.name);
  for (const k of VECTORS.fingerprints) assert.equal(keyFingerprint(k.public_key), k.fingerprint);
});

test("a key's fingerprint is four groups of the first 16 hex of SHA-256(SPKI)", () => {
  const fp = keyFingerprint(owner.pinKey.public_key);
  assert.match(fp, /^[0-9a-f]{4}( [0-9a-f]{4}){3}$/);
  assert.equal(fp.replace(/ /g, ""), crypto.createHash("sha256").update(Buffer.from(owner.pinKey.public_key, "base64url")).digest("hex").slice(0, 16));
});

// ── the pin (design §2.2–§2.3, §4.6; review findings 4, 5 and 10) ───────────

import { loadPin, pinProblems, revokedRecordProblems } from "../lib/operator-act.mjs";
import { checkOperatorPasskeys } from "../../tools/validate.mjs";

/** A key enrolled as the act page enrols one: self-signed, and endorsed when `by` is given. */
function enrolled(alg, opts = {}, by = null) {
  const key = A.makeKey(alg, { status: "active", ...opts });
  key.pinKey.enrolment = A.enrol(key);
  if (by) {
    key.pinKey.endorsed_by = by.pinKey.kid;
    key.pinKey.endorsement = { assertion: A.assertion(by, key.pinKey.enrolment.body) };
  }
  return key;
}
const pinWith = (...keys) => A.pinOf(keys.map((k) => ({ ...(k.pinKey ?? k) })));
const withStatus = (k, status) => ({ ...k.pinKey, status });

test("the committed pin is the empty one, and it passes alone", () => {
  const pin = loadPin();
  assert.deepEqual(pin.keys, []);
  assert.equal(pin.aud, "astra-registry:1331176498");
  assert.deepEqual(pinProblems(pin, { base: undefined }), []);
});

test("a genesis key alone passes; a second genesis passes only when every key before it is revoked", () => {
  const phone = enrolled("ES256", { kid: "owner-phone" });
  assert.deepEqual(pinProblems(pinWith(phone), { base: undefined }), []);
  const fresh = enrolled("EdDSA", { kid: "owner-new" });
  assert.match(pinProblems(pinWith(phone, fresh), { base: undefined }).join(" "), /second genesis key/);
  assert.deepEqual(pinProblems(pinWith(withStatus(phone, "revoked"), fresh), { base: undefined }), []);
  assert.deepEqual(pinProblems(pinWith(phone, fresh), { base: undefined, revokedNow: (kid) => kid === "owner-phone" }), []);
});

test("a later key needs an endorsement, by a key listed before it, over its own enrol body", () => {
  const phone = enrolled("ES256", { kid: "owner-phone" });
  const pc = enrolled("RS256", { kid: "owner-pc" }, phone);
  assert.deepEqual(pinProblems(pinWith(phone, pc), { base: undefined }), []);

  const unendorsed = { ...pc.pinKey, endorsed_by: "nobody" };
  assert.match(pinProblems(pinWith(phone, unendorsed), { base: undefined }).join(" "), /not a key listed before it/);
  // Listed after the key it endorses.
  const late = enrolled("EdDSA", { kid: "late" });
  const early = enrolled("ES256", { kid: "early" }, late);
  assert.match(pinProblems(pinWith(phone, early, { ...late.pinKey, endorsed_by: "owner-phone", endorsement: { assertion: A.assertion(phone, late.pinKey.enrolment.body) } }), { base: undefined }).join(" "), /not a key listed before it/);
  // Signed by another key than the one it names, or over another body.
  const stranger = enrolled("ES256", { kid: "stranger" });
  const forged = { ...pc.pinKey, endorsement: { assertion: { ...A.assertion(stranger, pc.pinKey.enrolment.body), credential_id: phone.pinKey.credential_id } } };
  assert.match(pinProblems(pinWith(phone, forged), { base: undefined }).join(" "), /endorsement does not verify/);
  const otherBody = { ...pc.pinKey, endorsement: { assertion: A.assertion(phone, stranger.pinKey.enrolment.body) } };
  assert.match(pinProblems(pinWith(phone, otherBody), { base: undefined }).join(" "), /endorsement does not verify/);
});

test("an enrolment that is not the key's own, or not signed by it, is refused", () => {
  const phone = enrolled("ES256", { kid: "owner-phone" });
  const other = enrolled("ES256", { kid: "other" });
  const notSelf = { ...phone.pinKey, enrolment: { body: phone.pinKey.enrolment.body, assertion: { ...A.assertion(other, phone.pinKey.enrolment.body), credential_id: phone.pinKey.credential_id } } };
  assert.match(pinProblems(pinWith(notSelf), { base: undefined }).join(" "), /enrolment does not verify/);
  const wrongBody = { ...phone.pinKey, enrolment: other.pinKey.enrolment };
  assert.match(pinProblems(pinWith(wrongBody), { base: undefined }).join(" "), /not this key's canonical enrol body/);
  const wrongActs = { ...phone.pinKey, acts: ["deny"] };
  assert.match(pinProblems(pinWith(wrongActs), { base: undefined }).join(" "), /not this key's canonical enrol body/);
  assert.match(pinProblems({ ...pinWith(phone), rp_id: "" }, { base: undefined }).join(" "), /names its rp_id/);
});

test("against the pin it replaces: nothing deleted, only status moves forward, an added key is pending, its endorser was active", () => {
  const phone = enrolled("ES256", { kid: "owner-phone" });
  const pc = enrolled("RS256", { kid: "owner-pc" }, phone);
  const base = pinWith(phone);
  const ok = (pin, opts = {}) => pinProblems(pin, { base, ...opts });

  assert.deepEqual(ok(pinWith(phone, withStatus(pc, "pending"))), []);
  assert.match(ok(pinWith(phone, pc)).join(" "), /added as active/);
  assert.match(ok(pinWith(withStatus(pc, "pending"))).join(" "), /removed or moved|not a key listed before it/, "the genesis key deleted");
  assert.match(pinProblems(pinWith(phone), { base: pinWith(phone, withStatus(pc, "pending")) }).join(" "), /owner-pc was removed/);
  assert.match(ok(pinWith({ ...phone.pinKey, acts: ["deny"] })).join(" "), /enrol body|more than its status/);
  assert.match(ok(pinWith({ ...phone.pinKey, device_bound: "yes" })).join(" "), /more than its status/);
  assert.deepEqual(ok(pinWith(withStatus(phone, "revoked"))), [], "active → revoked");
  assert.match(pinProblems(pinWith(phone), { base: pinWith(withStatus(phone, "revoked")) }).join(" "), /from revoked to active/);
  assert.deepEqual(pinProblems(pinWith(phone), { base: pinWith(withStatus(phone, "pending")) }), [], "pending → active");
  assert.match(pinProblems(pinWith(withStatus(phone, "pending")), { base: pinWith(phone) }).join(" "), /from active to pending/);

  // The endorser must have been active BEFORE this change (review finding 5).
  assert.match(pinProblems(pinWith(phone, withStatus(pc, "pending")), { base: pinWith(withStatus(phone, "pending")) }).join(" "), /not an active key before this change/);
  assert.match(pinProblems(pinWith(phone, withStatus(pc, "pending")), { base, revokedAtBase: (k) => k === "owner-phone" }).join(" "), /not an active key before this change/);
  assert.match(pinProblems(pinWith(phone, withStatus(pc, "pending")), { base: pinWith() }).join(" "), /added as active|not an active key before this change/, "an endorser added in the same change");

  assert.match(ok({ ...pinWith(phone, withStatus(pc, "pending")), rp_id: "other-acts.github.io", origins: ["https://other-acts.github.io"] }).join(" "), /rp_id changed|does not verify/);
});

test("a revocation record names a pinned key, by its own name", () => {
  const phone = enrolled("ES256", { kid: "owner-phone" });
  const pin = pinWith(phone);
  const rec = { schema: "astra.registry.passkey-revoked/1", kid: "owner-phone", at: "2026-10-31T12:00:00Z", run: "https://github.com/o/r/actions/runs/1" };
  assert.deepEqual(revokedRecordProblems(rec, { file: "state/passkeys/revoked/owner-phone.json", pin }), []);
  assert.notDeepEqual(revokedRecordProblems(rec, { file: "state/passkeys/revoked/other.json", pin }), []);
  assert.notDeepEqual(revokedRecordProblems({ ...rec, kid: "ghost" }, { file: "state/passkeys/revoked/ghost.json", pin }), []);
  assert.notDeepEqual(revokedRecordProblems({ ...rec, account: "1" }, { file: "state/passkeys/revoked/owner-phone.json", pin }), []);
});

/** A registry root of its own, with a pin committed at each step. */
function pinRepo(...steps) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "operator-pin-"));
  roots.push(root);
  git(root, "init", "-q", "-b", "main");
  for (const pin of steps) {
    writeJson(root, "bot/lib/operator-passkeys.json", pin);
    git(root, "add", "-A");
    git(root, "commit", "-q", "-m", "pin");
  }
  return root;
}
const errorsOf = (root, pinRoot = root) => {
  const errors = [];
  checkOperatorPasskeys({ root, report: { error: (w, m) => errors.push(`${w}: ${m}`), note() {}, warn() {} } }, { pinRoot });
  return errors;
};

test("validate judges the pin against the commit it replaces: the working tree against HEAD, else HEAD against its parent", () => {
  const phone = enrolled("ES256", { kid: "owner-phone" });
  const pc = enrolled("RS256", { kid: "owner-pc" }, phone);
  const genesis = pinWith(withStatus(phone, "pending"));
  const root = pinRepo(genesis, pinWith(phone));
  assert.deepEqual(errorsOf(root), [], "pending → active on the last commit");

  // Uncommitted: an endorsed key added active.
  writeJson(root, "bot/lib/operator-passkeys.json", pinWith(phone, pc));
  assert.match(errorsOf(root).join(" "), /added as active/);
  writeJson(root, "bot/lib/operator-passkeys.json", pinWith(phone, withStatus(pc, "pending")));
  assert.deepEqual(errorsOf(root), []);

  // Committed: HEAD is judged against HEAD^1, as a pull request's merge commit is.
  git(root, "add", "-A");
  git(root, "commit", "-q", "-m", "add pc");
  assert.deepEqual(errorsOf(root), []);
  writeJson(root, "bot/lib/operator-passkeys.json", pinWith(phone));
  git(root, "add", "-A");
  git(root, "commit", "-q", "-m", "drop the pc");
  assert.match(errorsOf(root).join(" "), /owner-pc was removed or moved/);

  // An endorser revoked by its record before the change does not endorse.
  const r2 = pinRepo(pinWith(withStatus(phone, "pending")), pinWith(phone));
  writeJson(r2, "state/passkeys/revoked/owner-phone.json", { schema: "astra.registry.passkey-revoked/1", kid: "owner-phone", at: "2026-10-31T12:00:00Z", run: "https://github.com/o/r/actions/runs/1" });
  git(r2, "add", "-A");
  git(r2, "commit", "-q", "-m", "revoke the phone");
  writeJson(r2, "bot/lib/operator-passkeys.json", pinWith(phone, withStatus(pc, "pending")));
  assert.match(errorsOf(r2).join(" "), /not an active key before this change/);
});

test("validate re-verifies every act record under its key, and refuses one that does not", () => {
  const phone = enrolled("ES256", { kid: "owner-phone" });
  const pinRoot = pinRepo(pinWith(withStatus(phone, "pending")), pinWith(phone));
  const item = A.act(phone, A.body({ act: "deny", target: releaseTarget(), now: NOW }));
  writeJson(pinRoot, `state/acts/${item.jti}.json`, actRecord(item, { run: "https://github.com/o/r/actions/runs/1", at: "2026-10-31T12:00:00Z" }));
  assert.deepEqual(errorsOf(pinRoot), []);
  writeJson(pinRoot, `state/acts/${item.jti}.json`, actRecord({ ...item, body: item.body.replace("1.2.1", "1.2.0") }, { run: "https://github.com/o/r/actions/runs/1", at: "2026-10-31T12:00:00Z" }));
  assert.match(errorsOf(pinRoot).join(" "), /challenge is not SHA-256 of this body/);
  writeJson(pinRoot, "state/passkeys/revoked/ghost.json", { schema: "astra.registry.passkey-revoked/1", kid: "ghost", at: "2026-10-31T12:00:00Z", run: "https://github.com/o/r/actions/runs/1" });
  assert.match(errorsOf(pinRoot).join(" "), /not a pinned key/);
});

// ── applying: one writer whichever door an act came through (design §4.4) ──

import { applyOperatorAct, operatorPath, passkeyActPath, revokePasskey } from "../lib/operator-acts.mjs";

const RUN = "https://github.com/o/r/actions/runs/7";
const AT = "2026-10-31T12:30:00Z";
const recordOf = (item) => actRecord(item, { run: RUN, at: AT });
const applyItem = (root, item, extra = {}) => {
  const b = JSON.parse(item.body);
  return applyOperatorAct({ root, act: b.act, target: b.target, at: AT, run: RUN, jti: item.jti, record: recordOf(item), pin: PIN, ...extra });
};

test("applyOperatorAct writes each act's effect and its act record, and nothing else", () => {
  const root = treeFixture();
  writeJson(root, "plugins/widgets/plugin.json", { id: "widgets", unlisted: true });

  const approveItem = A.act(owner, A.body({ act: "approve", target: releaseTarget(), now: NOW }));
  const a = applyItem(root, approveItem);
  assert.deepEqual(a.paths, [`state/acts/${approveItem.jti}.json`], "an approve writes its act record alone");
  assert.deepEqual(a.trailers, [["Operator-Act", approveItem.jti]]);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, a.paths[0]), "utf8")), recordOf(approveItem));

  const denyItem = A.act(owner, A.body({ act: "deny", target: releaseTarget(), now: NOW }));
  const d = applyItem(root, denyItem);
  assert.deepEqual(d.paths, [`state/deny/${DIGEST.slice(0, 16)}.json`, `state/acts/${denyItem.jti}.json`]);
  const again = A.act(owner, A.body({ act: "deny", target: releaseTarget(), now: NOW }));
  assert.deepEqual(applyItem(root, again).paths, [`state/acts/${again.jti}.json`], "a second deny records itself and leaves the deny as it was");

  const confirmItem = A.act(owner, A.body({ act: "confirm", target: holdTarget(), now: NOW }));
  const c = applyItem(root, confirmItem);
  assert.deepEqual(c.paths, [`state/holds/${SDI}.confirm.json`, `state/acts/${confirmItem.jti}.json`]);
  assert.deepEqual(c.trailers, [["Operator-Act", confirmItem.jti], ["Service-Decision", SDI]]);

  const revertItem = A.act(owner, A.body({ act: "revert", target: { service_decision_id: DELIST_SDI, action: "delist", plugin_id: "widgets", entry: "2026-10-30-widgets-delist.json" }, now: NOW }));
  const r = applyItem(root, revertItem);
  assert.deepEqual(r.paths, ["plugins/widgets/plugin.json", "bot/moderation/2026-10-31-widgets-relist.json", `state/acts/${revertItem.jti}.json`],
    "a revert writes the listing and its log entry, and regenerates no document: the moderation run does, once");
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, "plugins/widgets/plugin.json"), "utf8")).unlisted, undefined);

  const revokeItem = A.act(owner, A.body({ act: "revoke_key", target: { kid: "owner-pc", credential_id: KEYS.RS256.pinKey.credential_id }, now: NOW, lifetime: 86400 }));
  const k = applyItem(root, revokeItem);
  assert.deepEqual(k.paths, ["state/passkeys/revoked/owner-pc.json", `state/acts/${revokeItem.jti}.json`]);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, k.paths[0]), "utf8")), { schema: "astra.registry.passkey-revoked/1", kid: "owner-pc", at: AT, run: RUN });

  assert.throws(() => applyItem(root, approveItem, { jti: "f".repeat(32) }), /not this act's/);
  for (const p of [...a.paths, ...d.paths, ...c.paths, ...r.paths, ...k.paths]) assert.ok(passkeyActPath(p), p);
  assert.equal(operatorPath(`state/acts/${approveItem.jti}.json`), false, "operator.yml writes no act record");
  assert.equal(operatorPath("state/passkeys/revoked/owner-pc.json"), true, "operator.yml's revoke-passkey writes a revocation");
});

test("revoke-passkey: a pinned key, not yet revoked, by the owner's pinned id alone", async () => {
  const root = treeFixture();
  assert.throws(() => revokePasskey(root, "ghost", { at: AT, run: RUN, pin: PIN }), /not a pinned key/);
  assert.throws(() => revokePasskey(root, "owner-pc", { at: AT, run: null, pin: PIN }), /no run URL/);
  assert.deepEqual(revokePasskey(root, "owner-pc", { at: AT, run: RUN, pin: PIN }).touched, ["state/passkeys/revoked/owner-pc.json"]);
  assert.throws(() => revokePasskey(root, "owner-pc", { at: AT, run: RUN, pin: PIN }), /already revoked/);

  const { main, ACTS } = await import("../../tools/operator.mjs");
  assert.ok(ACTS.includes("revoke-passkey"));
  const run = async (job, env) => {
    const logs = [];
    const out = path.join(root, "operator-out");
    const code = await main(["--job", job, "--registry-dir", root, "--out", out], {
      env: { GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "o/r", GITHUB_RUN_ID: "7", ...env },
      log: { log: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
      now: new Date(AT),
    });
    return { code, logs };
  };
  // The workflow's own step: the owner's numeric id, for revoke-passkey as for ok.
  assert.equal((await run("ok-authority", { ASTRA_ACT: "revoke-passkey", ASTRA_ACTOR_ID: "700000555" })).code, 1);
  assert.equal((await run("ok-authority", { ASTRA_ACT: "revoke-passkey", ASTRA_ACTOR_ID: "193032699" })).code, 0);
  // The act itself refuses a stranger too, and a kid the committed (empty) pin does not hold.
  const stranger = await run("act", { ASTRA_ACT: "revoke-passkey", ASTRA_KID: "owner-pc", ASTRA_ACTOR_ID: "700000555" });
  assert.equal(stranger.code, 1, stranger.logs.join("\n"));
  assert.match(stranger.logs.join("\n"), /TRUST-32/);
  const unpinned = await run("act", { ASTRA_ACT: "revoke-passkey", ASTRA_KID: "owner-pc", ASTRA_ACTOR_ID: "193032699" });
  assert.equal(unpinned.code, 1);
  assert.match(unpinned.logs.join("\n"), /not a pinned key/);
  const mixed = await run("act", { ASTRA_ACT: "deny", ASTRA_FINGERPRINT: DIGEST.slice(0, 16), ASTRA_KID: "owner-pc" });
  assert.equal(mixed.code, 1, "a deny naming a kid was accepted");
});

// ── `--writer moderation` (design §4.6) ─────────────────────────────────────

import { checkModerationWriter } from "../../tools/validate.mjs";
import { actAlarms } from "../moderation-run.mjs";

test("--writer moderation: a deny, a hold record, a revocation or an operator revert needs an act record added beside it", () => {
  const phone = enrolled("ES256", { kid: "owner-phone" });
  const pinRoot = pinRepo(pinWith(withStatus(phone, "pending")), pinWith(phone));
  const root = treeFixture();
  const writer = () => {
    const errors = [];
    checkModerationWriter({ root, report: { error: (w, m) => errors.push(`${w}: ${m}`), note() {}, warn() {} } }, { pinRoot });
    return errors;
  };
  assert.deepEqual(writer(), []);
  const fp = DIGEST.slice(0, 16);
  const deny = { schema: "astra.registry.deny/1", fingerprint: fp, run: RUN, at: AT };
  writeJson(root, `state/deny/${fp}.json`, deny);
  writeJson(root, `state/holds/${SDI}.cancel.json`, { schema: "astra.registry.hold-record/1", act: "cancel", service_decision_id: SDI, plugin_id: "widgets", at: AT, run: RUN });
  writeJson(root, "state/passkeys/revoked/owner-phone.json", { schema: "astra.registry.passkey-revoked/1", kid: "owner-phone", at: AT, run: RUN });
  writeJson(root, "bot/moderation/2026-10-31-widgets-relist.json", { date: "2026-10-31", action: "relist", plugin: "widgets", reason: "Reverted by the registry operator: the decision this entry reverses was made in error.", category: "error", reverses: DELIST_SDI });
  const red = writer().join("\n");
  for (const what of [`state/deny/${fp}.json`, `state/holds/${SDI}.cancel.json`, "state/passkeys/revoked/owner-phone.json", "2026-10-31-widgets-relist.json"]) {
    assert.match(red, new RegExp(what.replace(/[.]/g, "\\.")), `${what} was written by a moderation commit with no act`);
  }
  // Backed by verified acts applied in their time: green.
  const head = git(root, "rev-parse", "HEAD");
  const now = Date.parse(AT);
  const mk = (act, target, lifetime = 3600) => A.act(phone, A.body({ act, target, now, main: head, lifetime }));
  for (const item of [
    mk("deny", releaseTarget(), 86400),
    mk("cancel", holdTarget({ code: "M_DELIST" })),
    mk("revoke_key", { kid: "owner-phone", credential_id: phone.pinKey.credential_id }, 86400),
    mk("revert", { service_decision_id: DELIST_SDI, action: "delist", plugin_id: "widgets", entry: "2026-10-30-widgets-delist.json" }),
  ]) writeJson(root, `state/acts/${item.jti}.json`, actRecord(item, { run: RUN, at: AT }));
  assert.deepEqual(writer(), []);
  // An act applied after its exp backs nothing.
  const late = mk("deny", releaseTarget(), 60);
  for (const n of fs.readdirSync(path.join(root, "state", "acts"))) {
    const doc = JSON.parse(fs.readFileSync(path.join(root, "state", "acts", n), "utf8"));
    if (canonicalBody(doc.body).act === "deny") fs.rmSync(path.join(root, "state", "acts", n));
  }
  writeJson(root, `state/acts/${late.jti}.json`, actRecord(late, { run: RUN, at: "2026-10-31T13:00:00Z" }));
  assert.match(writer().join("\n"), /outside its own time/);
});

test("alert announces each act by kind, plugin, release fingerprint and key fingerprint", () => {
  const item = A.act(owner, A.body({ act: "approve", target: releaseTarget(), now: NOW }));
  const a = actAlarms([item], { pin: PIN });
  assert.deepEqual(a.codes, ["OPERATOR_ACT_APPROVE"]);
  assert.deepEqual(a.ids, ["voice-text-input"]);
  assert.deepEqual(a.hexes, [DIGEST.slice(0, 16), keyFingerprint(owner.pinKey.public_key).replace(/ /g, "")]);
});
