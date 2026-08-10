#!/usr/bin/env node
// Sign the catalogue.
//
//   node bot/sign-index.mjs --in dist/index.json --out dist/index.json
//   node bot/sign-index.mjs --test-key TEST-ONLY-DO-NOT-TRUST-index-2026a --in … --out …
//   node bot/sign-index.mjs --verify dist/index.json --trust path/to/trust.json
//
// The real key comes from the environment — `ASTRA_INDEX_SIGNING_KEY` (base64
// of the raw 32-byte Ed25519 seed) and `ASTRA_INDEX_SIGNING_KEY_ID` — held as a
// GitHub Environment secret on the `publish` environment with the maintainer as
// a required reviewer (PRODUCTION_PLAN §5.1). **Never as a command-line
// argument**: a key on a command line is a key in the shell history, in `ps`
// output for every other account on the machine, and in the Actions log the
// first time somebody turns on command tracing.
//
// `--test-key` uses the clearly-labelled throwaway keys in tools/testkeys/,
// whose private halves are committed on purpose. It exists to produce the
// fixtures under bot/fixtures/index/ that prove the JavaScript signer and the
// Rust verifier canonicalise identically, and it refuses to write into
// registry/v1/.
//
// ── what this adds that the generator could not ──────────────────────────────
//
// `issued_at` and `expires_at`. They are properties of the publication, not of
// the catalogue's content: stamping them in tools/build-index.mjs would make a
// catalogue nobody edited for 31 days expire itself, and would make the
// generator's output unreproducible. Signing is the moment the registry asserts
// "this is current", so signing is where the assertion is written down.
//
// Thirty days, from bot/lib/sign.mjs's CATALOG_TTL_DAYS. What expiry buys is
// bounded, and the daemon is built around the bound: a stale catalogue
// downgrades Browse to a banner, and **records the user already has, pinned by
// digest, stay installable**. A digest does not expire. The hard block lives on
// the revocation list instead, at seven days, because that is the one document
// whose staleness means "we may be about to install something already
// withdrawn".

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "../tools/lib/canonical.mjs";
import {
  CATALOG_TTL_DAYS,
  INDEX_SCHEMA,
  addDays,
  indexSignerFromEnv,
  publicKeyFromBase64,
  rfc3339,
  signEnvelope,
  verifyEnvelope,
} from "./lib/sign.mjs";
import { loadTestRoot } from "../tools/testkeys/regenerate.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..");

/**
 * Stamp the freshness window onto a catalogue's `signed` member.
 *
 * @param {object} signed
 * @param {{issuedAt: Date, ttlDays: number}} opts
 */
export function stampFreshness(signed, { issuedAt, ttlDays = CATALOG_TTL_DAYS } = {}) {
  const issued = issuedAt ?? new Date();
  return {
    ...signed,
    issued_at: rfc3339(issued),
    expires_at: rfc3339(addDays(issued, ttlDays)),
  };
}

/**
 * Sign one catalogue document.
 *
 * @param {object} doc a `{signed, signatures}` envelope, or a bare `signed`
 * @param {{signer: {key_id: string, privateKey: import("node:crypto").KeyObject}, issuedAt?: Date, ttlDays?: number}} opts
 */
export function signIndex(doc, { signer, issuedAt, ttlDays } = {}) {
  const raw = doc?.signed ?? doc;
  if (raw?.schema !== INDEX_SCHEMA) {
    throw new Error(
      `refusing to sign a document whose schema is ${JSON.stringify(raw?.schema)}; this signs ` +
        `${INDEX_SCHEMA} only. The signature domain is the schema, and signing the wrong one is ` +
        "how a catalogue signature becomes a trust.json signature.",
    );
  }
  const signed = stampFreshness(raw, { issuedAt, ttlDays });
  const envelope = signEnvelope({ domain: INDEX_SCHEMA, signed, signers: [signer] });
  // The banner travels outside `signed` and is therefore unauthenticated — it
  // is a note for a human reading the file, never an input to a decision.
  return doc?.$comment ? { $comment: doc.$comment, ...envelope } : envelope;
}

/** Index keys a `trust.json` delegates to, as verifier keys. No window check here — see the note. */
export function indexKeysFromTrust(trustDoc) {
  // Deliberately NOT filtered by not_before/not_after. This is a signing-side
  // tool; the window is a decision the daemon makes against its own clock, and
  // a CI job that silently agreed with itself about the window would hide
  // exactly the rotation bug the window exists to catch. `--verify` here proves
  // the signature, and `astra-daemon`'s tests prove the window.
  const entries = trustDoc?.signed?.index_keys ?? trustDoc?.index_keys ?? [];
  return entries.map((e) => ({ key_id: e.key_id, publicKey: publicKeyFromBase64(e.public_key) }));
}

function arg(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}

function usage() {
  console.error(
    "usage: sign-index.mjs [--in FILE] [--out FILE] [--ttl-days N] [--issued-at RFC3339]\n" +
      "                     [--test-key <key_id>]\n" +
      "       sign-index.mjs --verify FILE --trust FILE\n" +
      "\n" +
      "The production key comes from ASTRA_INDEX_SIGNING_KEY / ASTRA_INDEX_SIGNING_KEY_ID in the\n" +
      "environment. It is never a command-line argument.",
  );
}

function main(argv) {
  if (argv.includes("--help") || argv.includes("-h")) {
    usage();
    return 0;
  }

  const verifyTarget = arg(argv, "--verify");
  if (verifyTarget) {
    const trustPath = arg(argv, "--trust");
    if (!trustPath) {
      console.error("FAIL  --verify needs --trust <trust.json>: a signature is only meaningful against a named key set");
      return 2;
    }
    const doc = JSON.parse(fs.readFileSync(verifyTarget, "utf8"));
    const trust = JSON.parse(fs.readFileSync(trustPath, "utf8"));
    const keys = indexKeysFromTrust(trust);
    const result = verifyEnvelope(doc, INDEX_SCHEMA, keys);
    if (!result.ok) {
      console.error(
        `FAIL  ${verifyTarget}: ${result.reason} (offered: ${result.offered.join(", ") || "none"}; ` +
          `trusted: ${keys.map((k) => k.key_id).join(", ") || "none"})`,
      );
      return 1;
    }
    console.log(
      `ok    ${verifyTarget} verifies under ${result.key_id}; serial ${doc.signed.serial}, ` +
        `issued ${doc.signed.issued_at}, expires ${doc.signed.expires_at}`,
    );
    return 0;
  }

  const inFile = path.resolve(arg(argv, "--in") ?? path.join(REPO_ROOT, "registry/v1/index.json"));
  const outFile = arg(argv, "--out") ? path.resolve(arg(argv, "--out")) : null;
  const ttlDays = arg(argv, "--ttl-days") !== undefined ? Number(arg(argv, "--ttl-days")) : CATALOG_TTL_DAYS;
  const issuedAtArg = arg(argv, "--issued-at");
  const issuedAt = issuedAtArg ? new Date(issuedAtArg) : new Date();
  if (Number.isNaN(issuedAt.getTime())) {
    console.error(`FAIL  --issued-at ${JSON.stringify(issuedAtArg)} is not a date`);
    return 2;
  }
  if (!Number.isSafeInteger(ttlDays) || ttlDays <= 0) {
    console.error(`FAIL  --ttl-days ${arg(argv, "--ttl-days")} is not a positive integer`);
    return 2;
  }

  const testKeyId = arg(argv, "--test-key");
  let signer;
  if (testKeyId) {
    const key = loadTestRoot(testKeyId);
    signer = { key_id: key.key_id, privateKey: key.privateKey };
    console.error(
      `WARNING: signing with ${key.key_id}, a TEST key whose private half is committed to this ` +
        "repository. Nothing a user installs may be signed with it.",
    );
    // A test signature inside registry/v1/ would be a catalogue that looks
    // signed and is not. Refused at the door rather than caught in review.
    const target = outFile ?? inFile;
    if (path.resolve(target).startsWith(path.join(REPO_ROOT, "registry"))) {
      console.error(`FAIL  refusing to write a TEST-key signature into ${path.relative(REPO_ROOT, target)}`);
      return 2;
    }
  } else {
    signer = indexSignerFromEnv();
    if (!signer) {
      console.error(
        "FAIL  no signing key. Set ASTRA_INDEX_SIGNING_KEY and ASTRA_INDEX_SIGNING_KEY_ID in the\n" +
          "      environment (the `publish` environment's secrets), or pass --test-key <key_id>\n" +
          "      to sign with the throwaway keys in tools/testkeys/.",
      );
      return 2;
    }
  }

  const doc = JSON.parse(fs.readFileSync(inFile, "utf8"));
  const out = signIndex(doc, { signer, issuedAt, ttlDays });
  const text = stableStringify(out);
  if (outFile) {
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, text);
    console.error(
      `wrote ${outFile}: serial ${out.signed.serial}, signed by ${signer.key_id}, ` +
        `issued ${out.signed.issued_at}, expires ${out.signed.expires_at}`,
    );
  } else {
    process.stdout.write(text);
  }
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(1);
  }
}
