#!/usr/bin/env node
// Sign a `trust.json` with one of the TEST-ONLY roots in this directory.
//
// THIS SIGNS WITH A KEY WHOSE PRIVATE HALF IS PUBLIC. It produces fixtures for
// the daemon's trust tests and documents that a staging catalogue can be signed
// at all. The production ceremony is ../keygen-root.sh and it is a different
// script for a reason: the real root private key never comes near this repo,
// this directory, or a script that takes it as a CLI argument.
//
//   node tools/testkeys/sign-trust.mjs --key <key_id> --in <file> --out <file>
//   node tools/testkeys/sign-trust.mjs --key <key_id> --in <file> --tamper-serial 1
//
// `--in` may be either a bare `signed` object or a full document with a
// `signed` member; only `signed` is ever hashed.
//
// The construction, from PRODUCTION_PLAN.md §5.2:
//
//     sig = Ed25519(root_priv, SHA-256( "astra.registry.trust/1" ‖ 0x00 ‖ JCS(signed) ))
//
// The domain string is the document's own schema, so a signature over a
// `trust.json` can never be replayed as a signature over an `index.json`. The
// verifier uses its own compiled-in constant for the domain, never the `schema`
// field it just read out of the file.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { jcs, stableStringify } from "../lib/canonical.mjs";
import { loadTestRoot } from "./regenerate.mjs";

export const TRUST_SCHEMA = "astra.registry.trust/1";

/**
 * The bytes an Ed25519 root signature covers.
 * @param {string} domain  the document's schema string
 * @param {unknown} signed the `signed` member, exactly as it will be published
 */
export function signingDigest(domain, signed) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(domain, "utf8"))
    .update(Buffer.from([0x00]))
    .update(Buffer.from(jcs(signed), "utf8"))
    .digest();
}

/** @param {string} keyId @param {unknown} signed */
export function signTrust(keyId, signed) {
  const root = loadTestRoot(keyId);
  const digest = signingDigest(TRUST_SCHEMA, signed);
  // `null` is how Node spells "Ed25519 hashes internally, do not pre-hash for
  // me" — the message we hand it is already our own SHA-256 digest.
  const sig = crypto.sign(null, digest, root.privateKey);
  return { key_id: root.key_id, sig: sig.toString("base64") };
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function main() {
  const keyId = arg("--key");
  const input = arg("--in");
  const output = arg("--out");
  if (!keyId || !input) {
    console.error(
      "usage: sign-trust.mjs --key <key_id> --in <file> [--out <file>]\n" +
        "                     [--serial N] [--tamper-serial N] [--banner TEXT]",
    );
    process.exit(2);
  }

  const parsed = JSON.parse(fs.readFileSync(input, "utf8"));
  let signed = parsed.signed ?? parsed;

  // `--serial` rewrites the serial BEFORE signing: a legitimately signed
  // document that happens to be older. That is the rollback fixture, and it has
  // to be genuinely valid or the test would be proving the wrong thing.
  const serial = arg("--serial");
  if (serial !== undefined) signed = { ...signed, serial: Number(serial) };

  const doc = { signed, signatures: [signTrust(keyId, signed)] };

  // `--tamper-serial` rewrites it AFTER signing: the signature no longer covers
  // the bytes on the page.
  const tamper = arg("--tamper-serial");
  if (tamper !== undefined) doc.signed = { ...signed, serial: Number(tamper) };

  const banner = arg("--banner") ?? parsed.$banner;
  if (banner) doc.$banner = banner;

  const text = stableStringify(doc);
  if (output) {
    fs.writeFileSync(output, text);
    console.error(`wrote ${output} signed by ${keyId}`);
  } else {
    process.stdout.write(text);
  }
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  main();
}
