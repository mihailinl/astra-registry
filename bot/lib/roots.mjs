// The trust roots, compiled into the bot (registry plan B-T1.5, BOT-7).
//
// **Public keys only.** Nothing here is secret, nothing here is signed with,
// and the private halves live in the owner's envelopes and have never been on
// a machine that runs this code. A root key's whole job is to be *known* by
// the verifier before it reads anything, which is the property this file
// exists to give the bot and which a file in the repository cannot.
//
// ── why these bytes are here and not read from registry/v1/root.json ────────
//
// `bot/ingest.mjs` decides whether a stranger's release may enter the
// catalogue, and the first thing it does is read a reusable-workflow allowlist
// out of a `trust.json` that a ROOT key signed. Until this file existed, the
// keys it checked that signature against came from `registry/v1/root.json` —
// a file in this repository, in the same tree as the bot, writable by anybody
// who can land a commit and by the bot's own `publish` job.
//
// So the anchor was inside the thing it anchors. A registry writer could add
// a key of their own to root.json, sign a trust.json with it that allowlists a
// reusable workflow they control, and every ingest after that commit would
// verify — correctly, against the roots it was told about — an attestation
// from a build they made. The daemon would refuse the result, because the
// daemon compiles the same two keys in and would not recognise the signature;
// but the daemon refuses it at the far end, in a user's install, days later,
// and what the registry publishes in the meantime is a catalogue nobody can
// read. "The client catches it" is not a boundary, it is a delay.
//
// Compiled in, the set cannot move without a code review of this file, and
// `bot/check-roots.mjs` makes a divergence between this file and the published
// root.json an alarm rather than a silent change of anchor.
//
// **This is not a claim that a compiled constant is unforgeable.** Anybody who
// can land a commit in this repository can edit this file too. What changes is
// where the edit is and what it looks like: a new root key here is a diff in a
// module whose every line says "root key", in a file no ordinary change ever
// touches, next to a fingerprint that must be recomputed to match — rather
// than one more object in a JSON document the publish job rewrites on its own.
// SERVE-92's three steps are the supported way to move the set, and the middle
// step is precisely that the two disagree for a while, on purpose, with the
// alarm saying so.
//
// ── where these bytes came from ────────────────────────────────────────────
//
// Copied from `registry/v1/root.json` as of a60ba781347571b988ba700929a1595037dd5347,
// where they were published by `b13759a feat(trust): publish the root keys`
// (2026-08-11) out of the ceremony `tools/keygen-root.sh` describes. Read from
// the committed file and pasted; `bot/check-roots.mjs` and
// `bot/tests/roots.test.mjs` both assert that they still agree with it, so a
// paste error is red before it is trusted.
//
// The same two keys are compiled into `astra-daemon`'s `PRODUCTION_ROOT_KEYS`.
// Three believers now hold this set — the daemon, this module and the
// published file — and only two of them are in this repository, so only two
// of them can be checked from here. `bot/check-roots.mjs` checks those two.
//
// ── changing the set ───────────────────────────────────────────────────────
//
// Under SERVE-92, in this order, and never in one commit:
//
//   1. the incoming root is added HERE, so the bot accepts a trust.json signed
//      by either key before any published document is signed by the new one;
//   2. root.json gains it (a TRUST-31 acknowledgement after R3, because
//      root.json is in the hashed set);
//   3. the outgoing root is dropped here, last, once nothing is signed by it.
//
// Step 1 and step 3 each leave the two documents disagreeing, which is what
// `SERVE_92_STEP` below is for: the check reports the divergence and does not
// alarm on it, but only for the shape SERVE-92 actually produces — a superset
// in one named direction — and never for a key that changed value.

import crypto from "node:crypto";

import { publicKeyFromBase64 } from "./sign.mjs";

/** The commit of `registry/v1/root.json` these were copied from. */
export const ROOT_SOURCE_COMMIT = "a60ba781347571b988ba700929a1595037dd5347";

/**
 * The root keys this bot will verify a `trust.json` under, and no others.
 *
 * `fingerprint_sha256` is `sha256` over the raw 32 bytes of the public key —
 * the same value `tools/keygen-root.sh` printed at the ceremony and the same
 * one root.json records. It is redundant with `public_key` on purpose: the two
 * are checked against each other by `compiledSetProblems()` below, so a single
 * character changed in either one is caught by this file alone, without
 * reference to root.json, to the daemon, or to anything a commit could change
 * in the same breath.
 */
export const COMPILED_ROOTS = Object.freeze([
  Object.freeze({
    key_id: "astra-root-2026a",
    role: "active",
    algorithm: "ed25519",
    public_key: "gJqu8KVZ4bVKjogevpDnXlG7IEjD74aLTKsXrIc0PSE=",
    fingerprint_sha256: "52e9b0c78f84d6cc4df6aab06ec4b1132f4e7d630ef9b2eea64461ccbb627ba8",
  }),
  Object.freeze({
    key_id: "astra-root-2026a-reserve",
    role: "reserve",
    algorithm: "ed25519",
    public_key: "3Jo/0nEEe2mITfRQbRw7QPWz87dJgPk1qdMWzJHDaGk=",
    fingerprint_sha256: "eedb701da0f9014ea0fc01f63d636d87ee3a31b54c992976db94a40ec7aa8d10",
  }),
]);

/** The three fixed codes `bot/check-roots.mjs` can put in an alarm. */
export const ROOT_CODES = {
  /** The compiled table contradicts itself: a key and its fingerprint disagree. */
  CORRUPT: "E_ROOT_COMPILED_CORRUPT",
  /** `registry/v1/root.json` cannot be read, parsed, or says it has no roots. */
  UNREADABLE: "E_ROOT_FILE_UNREADABLE",
  /** The published file and the compiled set are not the same set of keys. */
  DIVERGED: "E_ROOT_SET_DIVERGED",
};

/** `sha256` over the raw public key bytes, as the ceremony computes it. */
export function fingerprintOf(publicKeyBase64) {
  return crypto.createHash("sha256").update(Buffer.from(publicKeyBase64, "base64")).digest("hex");
}

/**
 * The root keys, as a verifier wants them.
 *
 * Shaped exactly like `loadRootKeys()`'s return so that the one production
 * caller can stop naming a file without anything else changing, and so that a
 * test can still hand in a set built from `tools/testkeys` through the same
 * seam. `status` is `compiled` and not `provisioned`: they are different
 * statements, and a reader who sees the latter goes looking for the file.
 *
 * @returns {{status: string, keys: {key_id: string, publicKey: import("node:crypto").KeyObject}[]}}
 */
export function compiledRootKeys() {
  return {
    status: "compiled",
    keys: COMPILED_ROOTS.map((r) => ({ key_id: r.key_id, publicKey: publicKeyFromBase64(r.public_key) })),
  };
}

/**
 * Is the compiled table internally consistent?
 *
 * Asked before the table is compared with anything, because a comparison
 * between two corrupted halves can agree. Every finding names the key.
 *
 * @returns {string[]} empty means sound
 */
export function compiledSetProblems(roots = COMPILED_ROOTS) {
  const problems = [];
  if (roots.length === 0) {
    return ["the compiled root set is empty, so this bot would verify no trust.json at all"];
  }
  const seen = new Set();
  for (const r of roots) {
    if (seen.has(r.key_id)) problems.push(`${r.key_id}: compiled twice, so one of the two entries is never read`);
    seen.add(r.key_id);
    if (r.algorithm !== "ed25519") {
      problems.push(`${r.key_id}: algorithm ${JSON.stringify(r.algorithm)} is not one this verifier implements`);
    }
    let raw;
    try {
      raw = Buffer.from(r.public_key, "base64");
    } catch {
      raw = Buffer.alloc(0);
    }
    if (raw.length !== 32) {
      problems.push(`${r.key_id}: the public key is ${raw.length} bytes decoded and an ed25519 key is 32`);
      continue;
    }
    const fp = fingerprintOf(r.public_key);
    if (fp !== r.fingerprint_sha256) {
      problems.push(
        `${r.key_id}: the compiled public key fingerprints as ${fp} and the compiled fingerprint says ` +
        `${r.fingerprint_sha256}. One of the two was edited; neither is trustworthy until a person says which.`,
      );
    }
  }
  if (!roots.some((r) => r.role === "active")) {
    problems.push("no compiled root has role `active`, so no key is the one that signs today");
  }
  return problems;
}

/**
 * Compare a parsed `registry/v1/root.json` with the compiled set.
 *
 * Two lists of findings, and the split is the whole value of this function.
 * `problems` is a divergence nobody planned — a key whose value changed, a key
 * the file has and this module does not — and is an alarm. `expected` is the
 * one shape SERVE-92's rotation produces on purpose: the compiled set holding
 * a key the published file has not published yet (step 1), or the published
 * file still carrying a key this module has dropped (step 3). Those are
 * reported and are not an alarm, because a rotation that paged the owner twice
 * for doing it correctly is a rotation somebody does wrong next time to keep
 * the channel quiet.
 *
 * A key that is in BOTH and whose bytes differ is never expected, in any step:
 * SERVE-92 adds and removes keys, it never edits one.
 *
 * @param {unknown} doc the parsed root.json
 * @returns {{problems: string[], expected: string[], fingerprints: string[]}}
 */
export function rootFileProblems(doc, roots = COMPILED_ROOTS) {
  const problems = [];
  const expected = [];
  const fingerprints = [];

  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    return { problems: ["registry/v1/root.json is not a JSON object"], expected, fingerprints };
  }
  const published = Array.isArray(doc.roots) ? doc.roots : null;
  if (published === null) {
    return { problems: ["registry/v1/root.json has no `roots` array"], expected, fingerprints };
  }
  if (doc.status !== "provisioned") {
    problems.push(
      `registry/v1/root.json says status ${JSON.stringify(doc.status ?? null)} and this bot has ` +
      `${roots.length} root key(s) compiled in. A file that says the ceremony has not been run, beside a ` +
      `verifier that holds its output, is two answers to "is there an anchor".`,
    );
  }

  const byId = new Map();
  for (const r of published) {
    if (typeof r?.key_id !== "string") {
      problems.push("registry/v1/root.json carries a root with no `key_id`");
      continue;
    }
    if (byId.has(r.key_id)) problems.push(`${r.key_id}: listed twice in registry/v1/root.json`);
    byId.set(r.key_id, r);
  }

  for (const compiled of roots) {
    fingerprints.push(compiled.fingerprint_sha256);
    const there = byId.get(compiled.key_id);
    if (!there) {
      expected.push(
        `${compiled.key_id} is compiled into the bot and is not in registry/v1/root.json. That is SERVE-92 ` +
        `step 1 — the incoming root reaches the verifier before it reaches the published file — and it is the ` +
        `state between that commit and the one that publishes it.`,
      );
      continue;
    }
    if (there.public_key !== compiled.public_key) {
      problems.push(
        `${compiled.key_id}: registry/v1/root.json publishes a DIFFERENT public key under this id. The ` +
        `compiled key fingerprints as ${compiled.fingerprint_sha256}; the published one as ` +
        `${fingerprintOf(String(there.public_key ?? ""))}. A rotation adds an id and removes an id; it never ` +
        `changes what one means, so this is not a rotation.`,
      );
    }
    if (there.fingerprint_sha256 !== compiled.fingerprint_sha256) {
      problems.push(
        `${compiled.key_id}: registry/v1/root.json records fingerprint ${there.fingerprint_sha256} and the ` +
        `compiled set records ${compiled.fingerprint_sha256}`,
      );
    }
  }

  const compiledIds = new Set(roots.map((r) => r.key_id));
  for (const [key_id, r] of byId) {
    if (compiledIds.has(key_id)) continue;
    // A published root this bot does not hold is the dangerous direction and
    // the harmless one at the same time, depending on which way the estate is
    // moving — so it is reported either way, and it is an alarm.
    //
    // Harmless: SERVE-92 step 3 has dropped it here and the file has not
    // caught up, and the bot simply refuses signatures by a key it no longer
    // trusts, which is what dropping it meant.
    //
    // Dangerous: somebody added a key to the published file that nobody added
    // here. Then the file tells every third-party reader — and the ceremony's
    // own audit trail — that a key is a root of this registry, while the bot
    // that guards the catalogue has never heard of it. Both directions are one
    // sentence and one alarm, because the difference between them is intent
    // and a check cannot read intent.
    problems.push(
      `${key_id}: registry/v1/root.json publishes a root key this bot does not hold (fingerprint ` +
      `${fingerprintOf(String(r.public_key ?? ""))}). Either SERVE-92 step 3 dropped it here and the file has ` +
      `not caught up — in which case this is the last step of a rotation and the commit that finishes it ` +
      `clears this — or a key was published that nobody compiled in, which is the change this check exists ` +
      `to find.`,
    );
  }

  return { problems, expected, fingerprints };
}
