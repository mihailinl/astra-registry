#!/usr/bin/env node
// Sign the withdrawal list.
//
//   node tools/sign-revocations.mjs --in dist/revocations.json --out dist/revocations.signed.json
//   node tools/sign-revocations.mjs --test-key TEST-ONLY-DO-NOT-TRUST-index-2026a --in … --out …
//   node tools/sign-revocations.mjs --verify dist/revocations.json --trust registry/v1/trust.json
//
// The real key comes from the environment — `ASTRA_INDEX_SIGNING_KEY` and
// `ASTRA_INDEX_SIGNING_KEY_ID`, the SAME index key that signs the catalogue
// (PRODUCTION_PLAN §5.1: "there is no separate revocation role; revocations are
// signed with the index key and bounded by a short TTL"). **Never as a
// command-line argument**: a key on a command line is a key in the shell
// history, in `ps` output for every other account on the machine, and in the
// Actions log the first time somebody turns on command tracing.
//
// ── THE DOMAIN IS THE WHOLE POINT ──────────────────────────────────────────
//
// One key, two documents, two domains. The signature covers
//
//     SHA-256( "astra.registry.revocations/1" ‖ 0x00 ‖ JCS(signed) )
//
// and the catalogue's covers the same construction with
// "astra.registry.index/1". If they shared a domain, a signature over a
// catalogue would verify as a signature over a withdrawal list — so anybody who
// could get one catalogue signed could publish an *empty* withdrawal list and
// switch off the only mechanism that helps after bad code is already installed.
//
// This file therefore refuses to sign a document whose schema is not
// REVOCATIONS_SCHEMA, and refuses to verify one under any other domain.
// tools/selftest.mjs asserts both directions of the substitution.
//
// ── THE TTL ────────────────────────────────────────────────────────────────
//
// Seven days, from bot/lib/sign.mjs's REVOCATION_TTL_DAYS, against the
// catalogue's thirty. The asymmetry is §5.5's whole freshness policy: a stale
// catalogue downgrades Browse to a banner and cached digest-pinned records stay
// installable, because a digest does not expire. A stale withdrawal list means
// "we may be about to install something already withdrawn", and that is the one
// hard block in the design — `astra-daemon`'s `RevocationFreshness::Stale`
// refuses new installs with a message that says so.
//
// Which is why this list is re-signed on a schedule even when no advisory has
// changed, at the SAME serial. The daemon replaces its set on a strictly
// greater serial and may only add on an equal one, so a scheduled re-sign is
// the safe republication and bumping the serial for it would not be.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "./lib/canonical.mjs";
import { OUTPUT_FILE } from "./lib/revocations.mjs";
import {
  REVOCATIONS_SCHEMA,
  REVOCATION_TTL_DAYS,
  addDays,
  indexSignerFromEnv,
  publicKeyFromBase64,
  rfc3339,
  signEnvelope,
  verifyEnvelope,
} from "../bot/lib/sign.mjs";
import { loadTestRoot } from "./testkeys/regenerate.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..");

/** Stamp the freshness window onto a withdrawal list's `signed` member. */
export function stampFreshness(signed, { issuedAt, ttlDays = REVOCATION_TTL_DAYS } = {}) {
  const issued = issuedAt ?? new Date();
  return {
    ...signed,
    issued_at: rfc3339(issued),
    expires_at: rfc3339(addDays(issued, ttlDays)),
  };
}

/**
 * Sign one withdrawal list.
 *
 * @param {object} doc a `{signed, signatures}` envelope, or a bare `signed`
 * @param {{signer: {key_id: string, privateKey: import("node:crypto").KeyObject}, issuedAt?: Date, ttlDays?: number}} opts
 */
export function signRevocations(doc, { signer, issuedAt, ttlDays } = {}) {
  const raw = doc?.signed ?? doc;
  if (raw?.schema !== REVOCATIONS_SCHEMA) {
    throw new Error(
      `refusing to sign a document whose schema is ${JSON.stringify(raw?.schema)}; this signs ` +
        `${REVOCATIONS_SCHEMA} only. The signature domain is the schema, and signing the wrong ` +
        "one is how a withdrawal-list signature becomes a catalogue signature.",
    );
  }
  const signed = stampFreshness(raw, { issuedAt, ttlDays });
  const envelope = signEnvelope({ domain: REVOCATIONS_SCHEMA, signed, signers: [signer] });
  return doc?.$comment ? { $comment: doc.$comment, ...envelope } : envelope;
}

/** Index keys a `trust.json` delegates to, as verifier keys. */
export function indexKeysFromTrust(trustDoc) {
  // Deliberately NOT filtered by not_before/not_after — the window is a decision
  // the daemon makes against its own clock, and a CI job that agreed with itself
  // about the window would hide the rotation bug the window exists to catch.
  const entries = trustDoc?.signed?.index_keys ?? trustDoc?.index_keys ?? [];
  return entries.map((e) => ({ key_id: e.key_id, publicKey: publicKeyFromBase64(e.public_key) }));
}

function arg(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}

function usage() {
  console.error(
    "usage: sign-revocations.mjs [--in FILE] [--out FILE] [--ttl-days N] [--issued-at RFC3339]\n" +
      "                           [--test-key <key_id>]\n" +
      "       sign-revocations.mjs --verify FILE --trust FILE\n" +
      "\n" +
      "The production key comes from ASTRA_INDEX_SIGNING_KEY / ASTRA_INDEX_SIGNING_KEY_ID in the\n" +
      "environment. It is never a command-line argument.",
  );
}

export function main(argv) {
  if (argv.includes("--help") || argv.includes("-h")) {
    usage();
    return 0;
  }

  const verifyTarget = arg(argv, "--verify");
  if (verifyTarget) {
    const trustPath = arg(argv, "--trust");
    if (!trustPath) {
      console.error(
        "FAIL  --verify needs --trust <trust.json>: a signature is only meaningful against a named key set",
      );
      return 2;
    }
    const doc = JSON.parse(fs.readFileSync(verifyTarget, "utf8"));
    const trust = JSON.parse(fs.readFileSync(trustPath, "utf8"));
    const keys = indexKeysFromTrust(trust);
    const result = verifyEnvelope(doc, REVOCATIONS_SCHEMA, keys);
    if (!result.ok) {
      console.error(
        `FAIL  ${verifyTarget}: ${result.reason} (offered: ${result.offered.join(", ") || "none"}; ` +
          `trusted: ${keys.map((k) => k.key_id).join(", ") || "none"})`,
      );
      return 1;
    }
    if (doc?.signed?.schema !== REVOCATIONS_SCHEMA) {
      console.error(
        `FAIL  ${verifyTarget}: the signature verifies but the document declares schema ` +
          `${JSON.stringify(doc?.signed?.schema)}, not ${REVOCATIONS_SCHEMA}`,
      );
      return 1;
    }
    console.log(
      `ok    ${verifyTarget} verifies under ${result.key_id}; serial ${doc.signed.serial}, ` +
        `${doc.signed.revocations?.length ?? 0} entry(ies), issued ${doc.signed.issued_at}, ` +
        `expires ${doc.signed.expires_at}`,
    );
    return 0;
  }

  const inFile = path.resolve(arg(argv, "--in") ?? path.join(REPO_ROOT, OUTPUT_FILE));
  const outFile = arg(argv, "--out") ? path.resolve(arg(argv, "--out")) : null;
  const ttlDays =
    arg(argv, "--ttl-days") !== undefined ? Number(arg(argv, "--ttl-days")) : REVOCATION_TTL_DAYS;
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
        "repository. Nothing a user's daemon acts on may be signed with it.",
    );
    const target = outFile ?? inFile;
    if (path.resolve(target).startsWith(path.join(REPO_ROOT, "registry"))) {
      console.error(
        `FAIL  refusing to write a TEST-key signature into ${path.relative(REPO_ROOT, target)}`,
      );
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
  const out = signRevocations(doc, { signer, issuedAt, ttlDays });
  const text = stableStringify(out);
  if (outFile) {
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, text);
    console.error(
      `wrote ${outFile}: serial ${out.signed.serial}, ${out.signed.revocations?.length ?? 0} ` +
        `entry(ies), signed by ${signer.key_id}, issued ${out.signed.issued_at}, ` +
        `expires ${out.signed.expires_at}`,
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
