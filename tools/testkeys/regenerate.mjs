#!/usr/bin/env node
// Rederive the TEST-ONLY root keys in this directory, and the signed-set
// vectors under ./vectors/.
//
// THESE ARE NOT PRODUCTION KEYS. The production ceremony is
// ../keygen-root.sh, it runs offline, and its output never enters this
// repository. See ./README.md.
//
// The keys are deterministic — seed = SHA-256(phrase) — for one reason: the
// daemon compiles the *public* halves in as literals, and a deterministic
// derivation lets both sides prove they hold the same key from the phrase alone,
// with no file shared across the two repositories.
//
//   node tools/testkeys/regenerate.mjs          rewrite the key files and the vectors
//   node tools/testkeys/regenerate.mjs --check  verify them, write nothing

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "../lib/canonical.mjs";
import {
  CATALOG_TTL_DAYS,
  INDEX_SCHEMA,
  REVOCATIONS_SCHEMA,
  REVOCATION_TTL_DAYS,
  TRUST_SCHEMA,
  addDays,
  rfc3339,
  signEnvelope,
} from "../../bot/lib/sign.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

const BANNER =
  "TEST KEY MATERIAL — NOT A PRODUCTION ROOT. The private half of this key is " +
  "committed to a public repository. Astra trusts it only in a debug build " +
  "compiled with --features insecure-test-trust-roots, or in the daemon's own " +
  "unit tests; a release build cannot compile that feature. Never sign anything " +
  "a user will install with this key.";

/** The two roots `astra-daemon` compiles in under `insecure-test-trust-roots`. */
export const TEST_ROOTS = [
  {
    key_id: "TEST-ONLY-DO-NOT-TRUST-root-a",
    role: "active",
    seed_phrase: "astra-registry TEST-ONLY root key A - NOT FOR PRODUCTION",
  },
  {
    key_id: "TEST-ONLY-DO-NOT-TRUST-root-b",
    role: "reserve",
    seed_phrase:
      "astra-registry TEST-ONLY root key B (reserve) - NOT FOR PRODUCTION",
  },
];

/**
 * Everything else the fixtures need. **None of these is a root** — the daemon
 * has never heard of them.
 *
 * - the two `index` keys are what a root-signed `trust.json` delegates index
 *   signing to, with a deliberate 30-day overlap so the rotation window itself
 *   is exercised (3.2 consumes them);
 * - `stranger` is a well-formed Ed25519 key that signs a syntactically perfect
 *   `trust.json` which must still be rejected, because rejection has to come
 *   from *whose* key it is and nothing else.
 */
export const TEST_OTHER_KEYS = [
  {
    key_id: "TEST-ONLY-DO-NOT-TRUST-index-2026a",
    role: "index",
    seed_phrase: "astra-registry TEST-ONLY index key 2026a - NOT FOR PRODUCTION",
  },
  {
    key_id: "TEST-ONLY-DO-NOT-TRUST-index-2026b",
    role: "index",
    seed_phrase: "astra-registry TEST-ONLY index key 2026b - NOT FOR PRODUCTION",
  },
  {
    key_id: "TEST-ONLY-DO-NOT-TRUST-stranger",
    role: "not-a-root",
    seed_phrase: "astra-registry TEST-ONLY stranger key - NOT A ROOT",
  },
];

export const TEST_KEYS = [...TEST_ROOTS, ...TEST_OTHER_KEYS];

// PKCS#8 prefix for a raw Ed25519 seed: SEQUENCE { 0, AlgId(1.3.101.112),
// OCTET STRING { OCTET STRING (32) } }. Node has no "import a raw Ed25519 seed"
// API, so we wrap it ourselves rather than take a dependency.
const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/** @param {string} phrase */
export function deriveTestRoot(phrase) {
  const seed = crypto.createHash("sha256").update(phrase, "utf8").digest();
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = crypto
    .createPublicKey(privateKey)
    .export({ format: "der", type: "spki" });
  const publicRaw = spki.subarray(spki.length - 32);
  return {
    seed,
    privateKey,
    publicRaw,
    publicKeyB64: publicRaw.toString("base64"),
    fingerprint: crypto.createHash("sha256").update(publicRaw).digest("hex"),
  };
}

/** Load one test key's signing key. Used by sign-trust.mjs. */
export function loadTestRoot(keyId) {
  const spec = TEST_KEYS.find((r) => r.key_id === keyId);
  if (!spec) {
    throw new Error(
      `unknown test key ${JSON.stringify(keyId)}; known: ${TEST_KEYS.map((r) => r.key_id).join(", ")}`,
    );
  }
  return { ...spec, ...deriveTestRoot(spec.seed_phrase) };
}

// ─────────────────────── the signed-set vectors (RC-R1-3) ───────────────────
//
// One corpus, four readers: this repository's selftest (through
// `bot/lib/sign.mjs`'s verifier), the ROLL-15 probe, the plugins service at a
// pinned commit, and `astra-daemon`, which VENDORS the file into
// `astra-daemon/testdata/signed-set-vectors/` and iterates it from Rust.
//
// It is generated here rather than hand-written because a hand-written corpus
// of signed documents is a corpus nobody can regenerate after a key changes:
// every signature would have to be recomputed by hand, and the first person to
// try would paste a signature from the wrong vector and produce a file that is
// green on both sides and means nothing.
//
// **The shape is fixed and stated in ./vectors/README.md**, because two
// independent implementations read it. Without a stated shape both canaries can
// be green on incompatible readings of the same bytes.

/**
 * The closed verdict vocabulary, in the order ./vectors/README.md's mapping
 * table lists it.
 *
 * Closed on purpose. An open vocabulary lets one side invent a verdict the
 * other has never heard of, and the reader that does not know it either skips
 * the vector or maps it to "not accepted" — which is the same green either way.
 */
export const SIGNED_SET_VERDICTS = [
  "accepted",
  "bad_domain",
  "unknown_key",
  "key_outside_window",
  "unsafe_integer",
  "no_signatures",
  "serial_reused",
  "entries_shrank",
  "older_issued_at",
];

/**
 * The floor both readers assert before they look at a single vector.
 *
 * A floor and not an equality: adding a vector is an ordinary act and must not
 * turn the other repository red on a commit it cannot see. Losing one is not
 * ordinary — a truncated vendoring, a bad merge, a `--check` somebody "fixed"
 * by deleting the mismatching entry — and a reader that iterates whatever it
 * finds reports PASS over the remainder.
 */
export const SIGNED_SET_FLOOR = 11;

export const VECTORS_DIR = path.join(HERE, "vectors");
export const SIGNED_SET_FILE = path.join(VECTORS_DIR, "signed-set-v1.json");

const KEY_A = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
const KEY_B = "TEST-ONLY-DO-NOT-TRUST-index-2026b";
const STRANGER = "TEST-ONLY-DO-NOT-TRUST-stranger";
const ROOT_B = "TEST-ONLY-DO-NOT-TRUST-root-b";

// The same two windows `fixtures/trust-unsigned.json` publishes, to the second.
// One story about when each test key is good for what, told once: a corpus that
// invented its own windows would exercise a rotation nothing else in either
// repository has ever seen.
const WINDOWS = {
  [KEY_A]: { not_before: "2026-08-01T00:00:00Z", not_after: "2026-11-01T00:00:00Z" },
  [KEY_B]: { not_before: "2026-10-02T00:00:00Z", not_after: "2027-02-01T00:00:00Z" },
};

/**
 * The largest integer JCS will emit here, plus one.
 *
 * `Number.MAX_SAFE_INTEGER + 1` is the smallest number that survives a JSON
 * round trip unchanged and still fails `Number.isSafeInteger`, which is exactly
 * the document a signer must refuse to canonicalise and a verifier must refuse
 * to read. `tools/lib/canonical.mjs` and `astra-core`'s `jcs` both bound
 * themselves at MAX_SAFE_INTEGER, and they have to refuse the same documents or
 * a signature means two things.
 */
const UNSAFE_SERIAL = Number.MAX_SAFE_INTEGER + 1;

/** The roots every vector carries, so no reader needs a second copy of them. */
function rootDocument() {
  return {
    schema: "astra.registry.root/1",
    status: "provisioned",
    roots: TEST_ROOTS.map((r) => ({
      key_id: r.key_id,
      role: r.role,
      algorithm: "ed25519",
      public_key: deriveTestRoot(r.seed_phrase).publicKeyB64,
      signs: "trust.json",
    })),
  };
}

/**
 * A root-signed `trust.json` delegating to `keyIds`.
 *
 * Signed by the RESERVE root, for the reason ../README.md gives: a reserve that
 * is never exercised is a reserve that does not work.
 */
function trustDocument(keyIds, serial) {
  const root = loadTestRoot(ROOT_B);
  const signed = {
    schema: TRUST_SCHEMA,
    serial,
    issued_at: "2026-08-10T00:00:00Z",
    expires_at: "2027-08-10T00:00:00Z",
    index_keys: keyIds.map((id) => ({
      key_id: id,
      public_key: loadTestRoot(id).publicKeyB64,
      ...WINDOWS[id],
    })),
    reusable_workflow_shas: ["0".repeat(40)],
  };
  return signEnvelope({
    domain: TRUST_SCHEMA,
    signed,
    signers: [{ key_id: root.key_id, privateKey: root.privateKey }],
  });
}

const plugin = (n) => ({
  id: `vector-plugin-${n}`,
  name: `Vector Plugin ${n}`,
  version: "1.0.0",
});

function catalogue({ serial, issuedAt, count }) {
  return {
    schema: INDEX_SCHEMA,
    serial,
    issued_at: issuedAt,
    expires_at: rfc3339(addDays(new Date(issuedAt), CATALOG_TTL_DAYS)),
    plugins: Array.from({ length: count }, (_, i) => plugin(i + 1)),
  };
}

function withdrawals({ serial, issuedAt, count }) {
  return {
    schema: REVOCATIONS_SCHEMA,
    serial,
    issued_at: issuedAt,
    expires_at: rfc3339(addDays(new Date(issuedAt), REVOCATION_TTL_DAYS)),
    revocations: Array.from({ length: count }, (_, i) => ({
      kind: "id",
      value: `vector-plugin-${i + 1}`,
      id: `ASTRA-TEST-000${i + 1}`,
      severity: "high",
      action: "block_install",
      reason: "TEST VECTOR — no plugin by this id exists.",
    })),
  };
}

/** Sign `signed` under `domain` with each of `keyIds`, in the order given. */
function sign(domain, signed, keyIds) {
  return signEnvelope({
    domain,
    signed,
    signers: keyIds.map((id) => {
      const k = loadTestRoot(id);
      return { key_id: k.key_id, privateKey: k.privateKey };
    }),
  });
}

/**
 * The corpus.
 *
 * Eleven vectors, nine verdicts, every verdict exercised at least once. Each
 * carries its own `root_json` and `trust_json` so a reader needs nothing from
 * this repository but the file itself — which is the whole reason Astra can
 * vendor it into a CI that has no registry checkout.
 */
export function buildSignedSetVectors() {
  const trustBoth = trustDocument([KEY_A, KEY_B], 7);
  const trustIncomingOnly = trustDocument([KEY_B], 8);

  /** @type {{id: number, name: string, document_kind: string, document: object, trust_json: object, root_json: object, prior_state: object|null, now: string, verdict: string}[]} */
  const vectors = [];
  const add = (v) => vectors.push({ ...v, root_json: rootDocument() });

  // 1. The one that must be accepted. Everything below is this, with one thing
  //    wrong, so a reader that refuses everything fails here first.
  add({
    id: 1,
    name: "valid",
    document_kind: "index",
    document: sign(INDEX_SCHEMA, catalogue({ serial: 41, issuedAt: "2026-09-01T00:00:00Z", count: 2 }), [KEY_A]),
    trust_json: trustBoth,
    prior_state: null,
    now: "2026-09-01T12:00:00Z",
    verdict: "accepted",
  });

  // 2. The catalogue's own bytes, signed under the WITHDRAWAL LIST's domain.
  //    If the domain separator were not in the hash, this signature would
  //    verify as a catalogue signature — and anyone who could get one list
  //    signed could publish a catalogue.
  add({
    id: 2,
    name: "wrong domain",
    document_kind: "index",
    document: sign(REVOCATIONS_SCHEMA, catalogue({ serial: 42, issuedAt: "2026-09-01T00:00:00Z", count: 2 }), [KEY_A]),
    trust_json: trustBoth,
    prior_state: null,
    now: "2026-09-01T12:00:00Z",
    verdict: "bad_domain",
  });

  // 3. Syntactically perfect, correctly domain-separated, real Ed25519. The
  //    only thing wrong with it is whose key it is, which is the only thing
  //    that may decide the outcome.
  add({
    id: 3,
    name: "unknown key",
    document_kind: "index",
    document: sign(INDEX_SCHEMA, catalogue({ serial: 43, issuedAt: "2026-09-01T00:00:00Z", count: 2 }), [STRANGER]),
    trust_json: trustBoth,
    prior_state: null,
    now: "2026-09-01T12:00:00Z",
    verdict: "unknown_key",
  });

  // 4. The incoming key, signing three weeks before trust.json lets it. A
  //    delegated key is delegated FOR A WINDOW; the signature is genuine and
  //    that is not enough.
  add({
    id: 4,
    name: "key outside its window",
    document_kind: "index",
    document: sign(INDEX_SCHEMA, catalogue({ serial: 44, issuedAt: "2026-09-15T00:00:00Z", count: 2 }), [KEY_B]),
    trust_json: trustBoth,
    prior_state: null,
    now: "2026-09-15T12:00:00Z",
    verdict: "key_outside_window",
  });

  // 5. A genuine signature over a document whose serial no canonicaliser here
  //    will emit. The document is signed FIRST and the number swapped in
  //    after, so the refusal comes from the number and not from a signature
  //    that was never valid.
  const unsafe = sign(INDEX_SCHEMA, catalogue({ serial: 45, issuedAt: "2026-09-01T00:00:00Z", count: 2 }), [KEY_A]);
  unsafe.signed = { ...unsafe.signed, serial: UNSAFE_SERIAL };
  add({
    id: 5,
    name: "unsafe integer",
    document_kind: "index",
    document: unsafe,
    trust_json: trustBoth,
    prior_state: null,
    now: "2026-09-01T12:00:00Z",
    verdict: "unsafe_integer",
  });

  // 6. Nothing offered. Distinct from "nothing verified": an unsigned
  //    catalogue is the registry before the root ceremony, and a catalogue
  //    whose signature fails is tampering. Reporting one as the other is how
  //    an install gate ends up switched off by a deletion.
  add({
    id: 6,
    name: "empty signatures",
    document_kind: "index",
    document: {
      signed: catalogue({ serial: 46, issuedAt: "2026-09-01T00:00:00Z", count: 2 }),
      signatures: [],
    },
    trust_json: trustBoth,
    prior_state: null,
    now: "2026-09-01T12:00:00Z",
    verdict: "no_signatures",
  });

  // 7. A serial names one document. This one is signed, in window, and says
  //    something else at a serial already accepted — a registry mistake or a
  //    substitution, and neither is passed over in silence.
  add({
    id: 7,
    name: "serial reused",
    document_kind: "index",
    document: sign(INDEX_SCHEMA, catalogue({ serial: 47, issuedAt: "2026-09-02T00:00:00Z", count: 3 }), [KEY_A]),
    trust_json: trustBoth,
    prior_state: { serial: 47, issued_at: "2026-09-01T00:00:00Z", entry_count: 2 },
    now: "2026-09-02T12:00:00Z",
    verdict: "serial_reused",
  });

  // 8. The one the withdrawal list's equal-serial rule exists for. Equal
  //    serials are legitimate — the list is re-signed on a schedule so it does
  //    not expire in a quiet week — so "same serial, fewer entries" is exactly
  //    the shape of a replay from before a withdrawal landed.
  add({
    id: 8,
    name: "equal serial, fewer entries",
    document_kind: "revocations",
    document: sign(REVOCATIONS_SCHEMA, withdrawals({ serial: 5, issuedAt: "2026-09-08T00:00:00Z", count: 1 }), [KEY_A]),
    trust_json: trustBoth,
    prior_state: { serial: 5, issued_at: "2026-09-01T00:00:00Z", entry_count: 2 },
    now: "2026-09-08T12:00:00Z",
    verdict: "entries_shrank",
  });

  // 9. The same serial, republished with an EARLIER publication instant. A
  //    re-sign moves `issued_at` forward; nothing legitimate moves it back.
  add({
    id: 9,
    name: "equal serial, older issued_at",
    document_kind: "index",
    document: sign(INDEX_SCHEMA, catalogue({ serial: 48, issuedAt: "2026-09-01T00:00:00Z", count: 2 }), [KEY_A]),
    trust_json: trustBoth,
    prior_state: { serial: 48, issued_at: "2026-09-05T00:00:00Z", entry_count: 2 },
    now: "2026-09-05T12:00:00Z",
    verdict: "older_issued_at",
  });

  // 10. The planned rotation, mid-overlap: both windows are open and the
  //     document carries the OUTGOING key's signature first, so a daemon that
  //     stops at the first signature it can check keeps working across the
  //     rotation (SERVE-30).
  add({
    id: 10,
    name: "dual-signed, outgoing key first",
    document_kind: "index",
    document: sign(INDEX_SCHEMA, catalogue({ serial: 49, issuedAt: "2026-10-15T00:00:00Z", count: 2 }), [KEY_A, KEY_B]),
    trust_json: trustBoth,
    prior_state: null,
    now: "2026-10-15T12:00:00Z",
    verdict: "accepted",
  });

  // 11. D10, the compromise path: trust.json has DROPPED the outgoing key, and
  //     the list is signed by the incoming key alone. The dual-signing rule
  //     above is not a rule about this document — a list still carrying the
  //     dropped key's signature is the thing D10 exists to stop.
  add({
    id: 11,
    name: "incoming key alone after the outgoing key was dropped",
    document_kind: "revocations",
    document: sign(REVOCATIONS_SCHEMA, withdrawals({ serial: 6, issuedAt: "2026-10-15T00:00:00Z", count: 2 }), [KEY_B]),
    trust_json: trustIncomingOnly,
    prior_state: null,
    now: "2026-10-15T12:00:00Z",
    verdict: "accepted",
  });

  return { version: 1, vectors };
}

/**
 * Read the committed corpus, with the floor and the vocabulary asserted before
 * a caller sees a single vector.
 *
 * The assertions are HERE rather than in each reader on purpose: a reader that
 * iterates whatever it finds reports PASS over a truncated file, and every
 * reader would have to remember to check. `astra-daemon`'s vendored copy
 * re-states the same two assertions in Rust, because it cannot call this.
 */
export function loadSignedSetVectors(file = SIGNED_SET_FILE) {
  const corpus = JSON.parse(fs.readFileSync(file, "utf8"));
  if (corpus.version !== 1) {
    throw new Error(`${file}: version ${JSON.stringify(corpus.version)}; this reader knows version 1 only`);
  }
  const vectors = corpus.vectors;
  if (!Array.isArray(vectors) || vectors.length < SIGNED_SET_FLOOR) {
    throw new Error(
      `${file}: ${Array.isArray(vectors) ? vectors.length : "no"} vectors, floor ${SIGNED_SET_FLOOR}. A reader that ` +
      "iterates what it finds would have reported PASS over the remainder.",
    );
  }
  const problems = [];
  const seen = new Set();
  for (const [i, v] of vectors.entries()) {
    const at = `vector ${v?.id ?? `#${i}`}`;
    if (!Number.isSafeInteger(v?.id)) problems.push(`${at}: no integer id`);
    else if (seen.has(v.id)) problems.push(`${at}: id used twice, so a reader failing "by vector id" names two vectors`);
    else seen.add(v.id);
    if (typeof v?.name !== "string" || !v.name) problems.push(`${at}: no name`);
    if (v?.document_kind !== "index" && v?.document_kind !== "revocations") {
      problems.push(`${at}: document_kind ${JSON.stringify(v?.document_kind)} is not "index" or "revocations"`);
    }
    if (!v?.document || typeof v.document !== "object") problems.push(`${at}: no document`);
    if (!v?.trust_json || typeof v.trust_json !== "object") problems.push(`${at}: no trust_json`);
    if (!v?.root_json || typeof v.root_json !== "object") problems.push(`${at}: no root_json`);
    if (typeof v?.now !== "string") problems.push(`${at}: no now`);
    if (v?.prior_state !== null && typeof v?.prior_state !== "object") {
      problems.push(`${at}: prior_state must be an object or null, never absent`);
    }
    if (!SIGNED_SET_VERDICTS.includes(v?.verdict)) {
      problems.push(
        `${at}: verdict ${JSON.stringify(v?.verdict)} is outside the closed vocabulary ` +
        `(${SIGNED_SET_VERDICTS.join(", ")}); a reader that has never heard of it skips the vector or reads it as ` +
        "\"not accepted\", and both are green",
      );
    }
  }
  if (problems.length) throw new Error(`${file}:\n  ${problems.join("\n  ")}`);
  return vectors;
}

// NOT `stableStringify`. That one refuses a number outside the safe-integer
// range, which is the point of vector 5 — canonicalising the corpus with the
// canonicaliser the corpus exists to test would make the file unwritable. This
// is a fixture, not a signed document: no signature covers these bytes, and the
// determinism `--check` needs comes from the object being built the same way
// every time.
function vectorsText(corpus) {
  return `${JSON.stringify(corpus, null, 2)}\n`;
}

function publicFile(root, derived) {
  return {
    $banner: BANNER,
    schema: "astra.registry.root-key/1",
    key_id: root.key_id,
    role: root.role,
    algorithm: "ed25519",
    public_key: derived.publicKeyB64,
    fingerprint_sha256: derived.fingerprint,
    comment:
      "TEST ONLY — deterministic key derived from a phrase published in tools/testkeys/README.md.",
    seed_phrase: root.seed_phrase,
  };
}

function secretFile(root, derived) {
  return {
    $banner: BANNER,
    $warning:
      "This file contains a PRIVATE KEY on purpose. It is worthless: it is public, " +
      "it is deterministic, and no shipped Astra build trusts it. Do not copy this " +
      "file's shape for a real key — a real root private key never touches a repository.",
    schema: "astra.registry.root-key-secret/1",
    key_id: root.key_id,
    role: root.role,
    algorithm: "ed25519",
    private_key_seed: derived.seed.toString("base64"),
    public_key: derived.publicKeyB64,
    fingerprint_sha256: derived.fingerprint,
    seed_phrase: root.seed_phrase,
  };
}

function main() {
  const check = process.argv.includes("--check");
  let failed = 0;

  for (const root of TEST_KEYS) {
    const derived = deriveTestRoot(root.seed_phrase);
    const targets = [
      [`${root.key_id}.pub.json`, publicFile(root, derived)],
      [`${root.key_id}.SECRET-TEST-KEY.json`, secretFile(root, derived)],
    ];
    for (const [name, body] of targets) {
      const file = path.join(HERE, name);
      const want = stableStringify(body);
      if (check) {
        const have = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
        if (have !== want) {
          console.error(`MISMATCH ${name} — rerun without --check`);
          failed += 1;
        }
      } else {
        fs.writeFileSync(file, want);
        console.log(`wrote ${name}`);
      }
    }
    console.log(
      `${root.key_id}  ${derived.publicKeyB64}  fp ${derived.fingerprint}`,
    );
  }

  // The vectors are derived from the keys above, so they are rewritten in the
  // same run: a corpus signed by a key that has since been rederived is a
  // corpus that verifies nowhere, and `--check` on the keys alone would have
  // said everything was fine.
  const vectorsWant = vectorsText(buildSignedSetVectors());
  const vectorsName = path.relative(path.dirname(HERE), SIGNED_SET_FILE);
  // Ed25519 over a canonicalised document is deterministic, and this corpus has
  // no clock in it. If that ever stops being true, `--check` would fail on a
  // tree nobody touched and the message would name the committed file — sending
  // the reader to the one place the defect is not.
  if (vectorsText(buildSignedSetVectors()) !== vectorsWant) {
    console.error(`FAIL  ${vectorsName}: the generator produced two different corpora in one run`);
    process.exit(1);
  }
  if (check) {
    const have = fs.existsSync(SIGNED_SET_FILE) ? fs.readFileSync(SIGNED_SET_FILE, "utf8") : null;
    if (have !== vectorsWant) {
      console.error(
        `MISMATCH ${vectorsName} — rerun without --check. These bytes are vendored into ` +
        "astra-daemon/testdata/signed-set-vectors/, so a hand edit here is a hand edit to another repository's " +
        "fixtures.",
      );
      failed += 1;
    }
  } else {
    fs.mkdirSync(VECTORS_DIR, { recursive: true });
    fs.writeFileSync(SIGNED_SET_FILE, vectorsWant);
    console.log(`wrote ${vectorsName}`);
  }

  if (failed) process.exit(1);
  if (check) console.log("all test key files match their seed phrases, and the signed-set vectors match the generator");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main();
}
