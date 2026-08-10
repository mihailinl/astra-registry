#!/usr/bin/env node
// Rederive the TEST-ONLY root keys in this directory.
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
//   node tools/testkeys/regenerate.mjs          rewrite the key files
//   node tools/testkeys/regenerate.mjs --check  verify them, write nothing

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "../lib/canonical.mjs";

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

  if (failed) process.exit(1);
  if (check) console.log("all test key files match their seed phrases");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main();
}
