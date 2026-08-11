#!/usr/bin/env node
// Sign `registry/v1/trust.json` with a production root key.
//
//   node tools/sign-trust.mjs --root-key ~/astra-root-ceremony-…/astra-root-2026a.private.pem \
//     --index-key-file ~/astra-index-key-…/astra-index-2026a.pub.json \
//     --workflow-sha 1111111111111111111111111111111111111111 \
//     --out registry/v1/trust.json
//
//   node tools/sign-trust.mjs --verify registry/v1/trust.json
//
// ── what this document is for ──────────────────────────────────────────────
//
// A root key does not sign a catalogue. It signs THIS, and this names the index
// key that signs the catalogue. That indirection is the whole trust model: the
// root private key can stay on a machine that has never been online, while the
// key doing daily work lives in CI and can be replaced by re-signing one small
// file. Until a signed `trust.json` exists, nothing is delegated, there is no
// key to check a catalogue signature against, and every daemon classifies every
// catalogue `UNSIGNED` — which is the correct fail-closed state, and also why
// the catalogue does not work yet.
//
//     sig = Ed25519(root_priv, SHA-256( "astra.registry.trust/1" ‖ 0x00 ‖ JCS(signed) ))
//
// The domain is this document's own schema. A signature over a `trust.json` can
// therefore never be replayed as a signature over an `index.json`, and the
// verifier supplies the domain from its own constant rather than from the
// `schema` member of the file it is reading.
//
// ── the root key is a CLI argument here, and only here ─────────────────────
//
// Every other signer in this repository takes its key from the environment,
// because a key on a command line is a key in the shell history and in `ps`. The
// argument here is a PATH, not a key: the bytes are read from a file that never
// leaves the machine you run this on. That machine should be the offline one
// from the ceremony — this script does no network I/O, so you can run it there
// and carry the resulting JSON out.
//
// ── the guard that matters ─────────────────────────────────────────────────
//
// Signing with the wrong key produces a document that looks perfect and that
// every daemon silently refuses, and you would find out from a user. So the
// public half of whatever key you passed is derived and checked against
// `registry/v1/root.json` before anything is written. A key that is not a
// published root is refused, by name.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "./lib/canonical.mjs";
import {
  TRUST_SCHEMA,
  publicKeyBase64,
  publicKeyFromBase64,
  signEnvelope,
  verifyEnvelope,
} from "../bot/lib/sign.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const ROOT_JSON = path.join(REPO, "registry", "v1", "root.json");
const DEFAULT_OUT = path.join(REPO, "registry", "v1", "trust.json");

/**
 * How long the document claims to be current.
 *
 * A year, and deliberately not the catalogue's thirty days. Re-signing this
 * means getting the offline machine out, so a short window would turn the whole
 * catalogue off on a date nobody had written down. A year is long enough to be
 * an appointment and short enough that a delegation cannot outlive the operator
 * who made it.
 */
const DEFAULT_EXPIRY_DAYS = 365;

function die(message) {
  console.error(`sign-trust: ${message}`);
  process.exit(1);
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

/** Every occurrence of a repeatable flag. */
function args(name) {
  const out = [];
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i] === name && process.argv[i + 1] !== undefined) out.push(process.argv[i + 1]);
  }
  return out;
}

/** The published roots, as `verifyEnvelope` wants them. */
function publishedRoots() {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(ROOT_JSON, "utf8"));
  } catch (e) {
    die(`cannot read ${ROOT_JSON}: ${e.message}`);
  }
  if (doc.status !== "provisioned") {
    die(
      `${ROOT_JSON} says status ${JSON.stringify(doc.status)} — run tools/keygen-root.sh first, ` +
        "and publish its public keys here and in astra-daemon's PRODUCTION_ROOT_KEYS.",
    );
  }
  const roots = Array.isArray(doc.roots) ? doc.roots : [];
  if (!roots.length) die(`${ROOT_JSON} lists no roots`);
  return roots;
}

/**
 * Load the root private key and prove it is one of the published roots.
 *
 * This is the check that turns "the signature is valid" into "the signature is
 * valid AND made by a key every shipped daemon trusts". Without it the happy
 * path of a mistake — the reserve key, last year's key, a key from a test
 * directory — writes a file that verifies against itself and against nothing
 * else.
 */
function loadRootSigner(pemPath) {
  let pem;
  try {
    pem = fs.readFileSync(pemPath);
  } catch (e) {
    die(`cannot read the root key at ${pemPath}: ${e.message}`);
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(pem);
  } catch (e) {
    die(`${pemPath} is not a private key OpenSSL wrote: ${e.message}`);
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    die(`${pemPath} is a ${privateKey.asymmetricKeyType} key; the roots are ed25519`);
  }

  const pub = publicKeyBase64(privateKey);
  const match = publishedRoots().find((r) => r.public_key === pub);
  if (!match) {
    die(
      `the key at ${pemPath} is not one of the roots published in ${path.relative(REPO, ROOT_JSON)}.\n` +
        `  its public half:  ${pub}\n` +
        `  published roots:  ${publishedRoots().map((r) => `${r.key_id} (${r.public_key})`).join("\n                    ")}\n` +
        "Signing with it would produce a document every daemon refuses.",
    );
  }
  if (match.role !== "active") {
    console.error(
      `sign-trust: WARNING — signing with the ${match.role} root ${match.key_id}. ` +
        "That is correct only if you are rotating away from the active one.",
    );
  }
  return { key_id: match.key_id, privateKey, role: match.role };
}

/** One `index_keys` entry, from a `--index-key-file` written by keygen-index.sh. */
function indexKeyFromFile(file) {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    die(`cannot read the index key at ${file}: ${e.message}`);
  }
  if (!doc.key_id || !doc.public_key) {
    die(`${file} has no key_id/public_key — is it the .pub.json keygen-index.sh wrote?`);
  }
  if (/^TEST-ONLY/i.test(doc.key_id)) {
    die(
      `${file} is a TEST key (${doc.key_id}). Its private half is published in this repository; ` +
        "delegating to it would hand the catalogue to anyone who can read git.",
    );
  }
  return { key_id: String(doc.key_id), public_key: String(doc.public_key) };
}

function assertUsableEd25519PublicKey(entry) {
  try {
    publicKeyFromBase64(entry.public_key);
  } catch (e) {
    die(`index key ${entry.key_id} is unusable: ${e.message}`);
  }
}

function isFortyHex(s) {
  return /^[0-9a-f]{40}$/.test(s);
}

/** The serial already published, so the default is "one more than that". */
function previousSerial(outPath) {
  try {
    const doc = JSON.parse(fs.readFileSync(outPath, "utf8"));
    const n = Number(doc?.signed?.serial);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

function verify(file) {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    die(`cannot read ${file}: ${e.message}`);
  }
  const keys = publishedRoots().map((r) => ({
    key_id: r.key_id,
    publicKey: publicKeyFromBase64(r.public_key),
  }));
  const verdict = verifyEnvelope(doc, TRUST_SCHEMA, keys);
  if (!verdict.ok) {
    die(
      `${file} is NOT signed by a published root: ${verdict.reason}. ` +
        `It offers signatures from: ${verdict.offered.join(", ") || "nothing"}.`,
    );
  }

  const signed = doc.signed ?? {};
  const keyRows = (signed.index_keys ?? []).map(
    (k) => `    ${k.key_id}  ${k.public_key}${k.not_after ? `  (until ${k.not_after})` : ""}`,
  );
  console.log(
    [
      `ok  ${path.relative(REPO, path.resolve(file))} verifies under root ${verdict.key_id}`,
      `    schema  ${signed.schema}`,
      `    serial  ${signed.serial}`,
      `    issued  ${signed.issued_at ?? "—"}`,
      `    expires ${signed.expires_at ?? "never"}`,
      `  index keys it delegates to:`,
      ...(keyRows.length ? keyRows : ["    (none — nothing can sign a catalogue)"]),
      `  reusable-workflow SHAs it allows:`,
      ...((signed.reusable_workflow_shas ?? []).map((s) => `    ${s}`) || []),
    ].join("\n"),
  );
  if (!(signed.reusable_workflow_shas ?? []).length) {
    console.log("    (none — every ingest will stop at E_WORKFLOW_NOT_ALLOWED)");
  }
}

function main() {
  const toVerify = arg("--verify");
  if (toVerify) {
    verify(toVerify);
    return;
  }

  const rootKeyPath = arg("--root-key");
  if (!rootKeyPath) {
    console.error(
      [
        "usage:",
        "  sign-trust.mjs --root-key <root.private.pem>",
        "                 --index-key-file <index.pub.json>   (repeatable)",
        "                 --workflow-sha <40-hex>              (repeatable)",
        "                 [--serial N] [--expires-days N] [--out <file>]",
        "  sign-trust.mjs --verify <file>",
      ].join("\n"),
    );
    process.exit(2);
  }

  const outPath = path.resolve(arg("--out") ?? DEFAULT_OUT);
  const signer = loadRootSigner(rootKeyPath);

  const indexKeys = args("--index-key-file").map(indexKeyFromFile);
  const inlineId = arg("--index-key-id");
  const inlineKey = arg("--index-key");
  if (inlineKey || inlineId) {
    if (!inlineKey || !inlineId) die("--index-key and --index-key-id go together");
    indexKeys.push({ key_id: inlineId, public_key: inlineKey });
  }
  if (!indexKeys.length) {
    die(
      "no index key given. A trust.json that delegates to nothing is a document that " +
        "verifies and grants nothing: every catalogue would still read UNSIGNED. " +
        "Run tools/keygen-index.sh first.",
    );
  }
  indexKeys.forEach(assertUsableEd25519PublicKey);

  const seen = new Set();
  for (const k of indexKeys) {
    if (seen.has(k.key_id)) die(`index key id ${k.key_id} appears twice`);
    seen.add(k.key_id);
  }

  const workflowShas = args("--workflow-sha").map((s) => s.trim().toLowerCase());
  for (const sha of workflowShas) {
    if (!isFortyHex(sha)) {
      die(
        `--workflow-sha ${JSON.stringify(sha)} is not a 40-character commit SHA. ` +
          "A tag will not do: a tag can be repointed, and the allowlist exists precisely " +
          "because the reusable workflow runs inside every plugin author's repository.",
      );
    }
  }
  if (!workflowShas.length) {
    console.error(
      "sign-trust: WARNING — no --workflow-sha given, so the build-attestation allowlist " +
        "is empty and every release ingest will stop at E_WORKFLOW_NOT_ALLOWED. That is " +
        "the safe direction, but it means no plugin can be listed from a release.",
    );
  }

  const now = new Date();
  const expiresDays = Number(arg("--expires-days") ?? DEFAULT_EXPIRY_DAYS);
  if (!Number.isFinite(expiresDays) || expiresDays <= 0) die("--expires-days must be a positive number");
  const expires = new Date(now.getTime() + expiresDays * 86400_000);

  const serialArg = arg("--serial");
  const serial = serialArg !== undefined ? Number(serialArg) : previousSerial(outPath) + 1;
  if (!Number.isInteger(serial) || serial < 1) die("--serial must be an integer of at least 1");

  const signed = {
    schema: TRUST_SCHEMA,
    serial,
    issued_at: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
    expires_at: expires.toISOString().replace(/\.\d{3}Z$/, "Z"),
    index_keys: indexKeys.map((k) => ({
      key_id: k.key_id,
      public_key: k.public_key,
      not_before: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
      // No `not_after`. The document's own `expires_at` is the outer bound, and
      // a second deadline on the key buys nothing except another date on which
      // the catalogue can stop working for a reason nobody remembers. A
      // rotation sets one explicitly, on the key being retired, so the two
      // windows overlap while daemons refresh.
    })),
    reusable_workflow_shas: workflowShas,
  };

  const doc = {
    $comment:
      "The Astra registry's delegation document. Signed by a ROOT key; names the index key " +
      "that signs index.json and revocations.json, and the reusable-workflow commits the bot " +
      "will accept in a build attestation. Only the `signed` member is covered by the " +
      "signatures. Produced by tools/sign-trust.mjs; verify with --verify.",
    ...signEnvelope({ domain: TRUST_SCHEMA, signed, signers: [signer] }),
  };

  // Verify what we are about to write, with the same code the bot verifies it
  // with. Signing and then shipping without reading it back is how a signer
  // that quietly produced garbage stays undiscovered until a user finds it.
  const roots = publishedRoots().map((r) => ({
    key_id: r.key_id,
    publicKey: publicKeyFromBase64(r.public_key),
  }));
  const check = verifyEnvelope(doc, TRUST_SCHEMA, roots);
  if (!check.ok) die(`the document this just signed does not verify (${check.reason}) — refusing to write it`);

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${stableStringify(doc)}\n`);

  console.error(
    [
      `wrote ${path.relative(REPO, outPath)}`,
      `  signed by   ${signer.key_id} (${signer.role} root)`,
      `  serial      ${serial}`,
      `  expires     ${signed.expires_at}  — re-sign before this or the catalogue stops verifying`,
      `  delegates   ${indexKeys.map((k) => k.key_id).join(", ")}`,
      `  allows      ${workflowShas.length} reusable-workflow commit(s)`,
      "",
      "  Commit it, then make sure ASTRA_INDEX_SIGNING_KEY in the `publish`",
      "  environment holds the private half of the key named above.",
    ].join("\n"),
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main();
}
