#!/usr/bin/env node
// Sign the Astra update manifest with a production root key.
//
//   node tools/sign-update-manifest.mjs \
//     --root-key /run/media/$USER/ASTRA-ROOT/keys/astra-root-2026a.private.pem \
//     --artifact ~/Astra-Installer-0.2.1.exe \
//     --version 0.2.1 \
//     --notes-en notes.en.txt --notes-ru notes.ru.txt --notes-uk notes.uk.txt \
//     --out manifest.json
//
//   node tools/sign-update-manifest.mjs --verify manifest.json
//
// ── what this document is for ──────────────────────────────────────────────
//
// Every installed Astra asks `GET /api/updates/manifest` on a timer and believes
// what it finds only if this signature verifies against a root compiled into the
// binary. The server holds no key and cannot make one: it serves the file's bytes
// unchanged and refuses a bad file, which means a compromised API can withhold an
// update but can never ship one.
//
//     sig = Ed25519(root_priv, SHA-256( "astra.update.v1" ‖ 0x00 ‖ JCS(signed) ))
//
// Same construction, same canonicaliser and same envelope as `sign-trust.mjs`,
// with this document's own domain. That is not tidiness: the daemon has exactly
// one Ed25519 verification and one canonicaliser, and a second signer that agreed
// with it *nearly* would produce manifests that verify here and nowhere else.
//
// ── the root key is a PATH, and only ever a path ───────────────────────────
//
// A key on a command line is a key in the shell history and in `ps`. What is
// passed is the path to a file that never leaves the machine you run this on, and
// that machine should be the offline one from the ceremony — this script does no
// network I/O, so you can run it there and carry the JSON out on the same stick
// the key came in on.
//
// ── the guards, and why each exists ────────────────────────────────────────
//
// **The key is proved to be a published root before anything is written.** The
// happy path of a mistake — the reserve key by accident, a key from a test
// directory, last year's key — writes a document that verifies against itself and
// against no shipped daemon, and you would find out from a user who never got an
// update. Borrowed wholesale from `sign-trust.mjs`, for the reason its own
// comment gives.
//
// **The size and digest are computed from the artefact, never accepted as
// arguments.** A manifest naming a file that is not there is August's webhook
// failure with a different noun: every delivery fails, nothing notices. If the
// installer is not on this machine, put it on this machine.
//
// **The filename must be in the closed set the client already accepts.** It
// becomes a URL component and a path on disk over there, so `..`, a separator or
// a `%00` is a write outside the intended directory. The client widens that set
// BEFORE this publishes a new shape, never after.
//
// **Release notes are refused if they carry markup or a link.** The client renders
// them as plain text and the server refuses them too; a refusal on three ends is a
// property rather than an agreement.
//
// **The signature is verified against the published roots before the file is
// written.** Signing and then not checking is how you find out from a user.
//
// ── signing with BOTH roots, and the one day it matters ────────────────────
//
// `--also-reserve` adds a second signature from the reserve key. The verifier
// tries every key against every signature, so a manifest carrying both is
// accepted by clients that have learned a new root and by clients that have not.
// That is what makes burning the active root a rotation rather than a day-X: on
// any other day one signature is enough and a second is noise.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  UPDATE_SCHEMA,
  addDays,
  publicKeyBase64,
  publicKeyFromBase64,
  rfc3339,
  signEnvelope,
  verifyEnvelope,
} from "../bot/lib/sign.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const ROOT_JSON = path.join(REPO, "registry", "v1", "root.json");

/**
 * How long the manifest claims to be current.
 *
 * Thirty days, and the number is a trade rather than a preference. A signature
 * proves we wrote a document, never that we wrote it recently, so a cache or a
 * middlebox can replay one for ever and updates simply stop — `expires` is what
 * bounds that freeze. But the signing key is offline on purpose, so a short expiry
 * becomes a standing obligation to get the key out on a calendar; forget it and
 * every client refuses the manifest at once, auto-update stops silently and
 * completely, and it looks like the server is down.
 *
 * Thirty days, and the server publishes how many are left with an alarm a week
 * out. A number that must not approach zero is something an alert can watch;
 * "somebody must remember" is not a mechanism.
 */
const DEFAULT_EXPIRY_DAYS = 30;

/**
 * The artefact names the shipped client accepts. Widen THERE first, then here.
 *
 * `Astra-Installer-<semver>.exe` is the OUTER Slint launcher — the file a person downloads and
 * runs. The inner Inno setup is called `Astra-Setup-<semver>.exe`, is embedded in the launcher and
 * unpacked to %TEMP% for the seconds an install takes, and can never be on a CDN. This regex named
 * the inner one until 2026-09-02; it matched a file that does not exist.
 *
 * Windows only, by the owner's decision: a closed set should name what is actually published, and
 * today that is one file. The Linux shapes are in the contract for the day they ship.
 */
const FILENAME = /^Astra-Installer-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\.exe$/;

const PLATFORMS = new Set(["windows-x64"]);

function die(message) {
  console.error(`sign-update-manifest: ${message}`);
  process.exit(1);
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function has(name) {
  return process.argv.includes(name);
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
      `${ROOT_JSON} says status ${JSON.stringify(doc.status)} — the ceremony has not run, so no ` +
        "shipped daemon trusts anything and there is nothing to sign with.",
    );
  }
  const roots = Array.isArray(doc.roots) ? doc.roots : [];
  if (!roots.length) die(`${ROOT_JSON} lists no roots`);
  return roots.map((r) => ({ key_id: r.key_id, publicKey: publicKeyFromBase64(r.public_key) }));
}

/**
 * Load a root private key and prove it is one of the published roots.
 *
 * Without this, the happy path of a mistake writes a document that verifies
 * against itself and against nothing that ships.
 */
function loadRoot(pemPath, expectRole) {
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
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(ROOT_JSON, "utf8"));
  } catch (e) {
    die(`cannot read ${ROOT_JSON}: ${e.message}`);
  }
  const match = (doc.roots ?? []).find((r) => r.public_key === pub);
  if (!match) {
    die(
      `the key at ${pemPath} is not one of the roots published in registry/v1/root.json. ` +
        "A manifest signed with it would verify against itself and be refused by every shipped " +
        "Astra, and the first you would hear of it is a user who never got an update.",
    );
  }
  if (expectRole && match.role !== expectRole) {
    die(`${pemPath} is the ${match.role} root; --${expectRole.toLowerCase()} was asked for`);
  }
  return { key_id: match.key_id, privateKey, role: match.role };
}

/** Read release notes, and refuse anything the client would not render as text. */
function notes() {
  const out = {};
  for (const locale of ["en", "ru", "uk"]) {
    const where = arg(`--notes-${locale}`);
    if (where === undefined) continue;
    let text;
    try {
      text = fs.readFileSync(where, "utf8");
    } catch (e) {
      die(`cannot read the ${locale} notes at ${where}: ${e.message}`);
    }
    text = text.trim();
    if (!text) die(`the ${locale} notes at ${where} are empty — omit the flag instead`);
    if (/[<>]|\]\(|https?:\/\//.test(text)) {
      die(
        `the ${locale} notes carry markup or a link. The client renders notes as PLAIN TEXT and ` +
          "the server refuses them as well, so this would be published and then refused by both.",
      );
    }
    out[locale] = text;
  }
  if (!out.en) {
    die("--notes-en is required: a locale nobody wrote falls back to English, so English must exist");
  }
  return out;
}

/** Size and digest, from the bytes themselves. Never from an argument. */
function artefact() {
  const where = arg("--artifact");
  if (!where) die("--artifact is required — the size and digest are computed, never accepted");
  let bytes;
  try {
    bytes = fs.readFileSync(where);
  } catch (e) {
    die(
      `cannot read the artefact at ${where}: ${e.message}. If the installer is not on this ` +
        "machine, put it on this machine: a manifest naming a file nobody checked is the same " +
        "defect as a webhook naming a host that was never deployed.",
    );
  }
  const filename = path.basename(where);
  const m = FILENAME.exec(filename);
  if (!m) {
    die(
      `the artefact is named ${filename}, which is outside the set the shipped client accepts. ` +
        "That name becomes a URL component AND a path on disk over there. Rename it to " +
        "Astra-Installer-<semver>.exe, or widen the set in the CLIENT first and ship that before " +
        "publishing a new shape here.",
    );
  }
  const version = arg("--version") ?? m[1];
  if (version !== m[1]) {
    die(`--version ${version} disagrees with the filename's ${m[1]} — one of them is wrong`);
  }
  return {
    platform: arg("--platform") ?? "windows-x64",
    kind: arg("--kind") ?? "installer",
    filename,
    sizeBytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    version,
  };
}

function verifyFile(where) {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(where, "utf8"));
  } catch (e) {
    die(`cannot read ${where}: ${e.message}`);
  }
  const result = verifyEnvelope(doc, UPDATE_SCHEMA, publishedRoots());
  if (!result.ok) {
    die(`${where} does not verify: ${result.reason} (offered: ${result.offered.join(", ") || "none"})`);
  }
  const signed = doc.signed ?? {};
  if (signed.schema !== UPDATE_SCHEMA) {
    die(
      `${where} verifies but declares schema ${JSON.stringify(signed.schema)}. A body of one ` +
        "version signed under another's domain VERIFIES, because the domain is not read from the " +
        "file — which is exactly why this is checked separately.",
    );
  }
  const left = (new Date(signed.expires) - Date.now()) / 86400000;
  console.log(`ok  ${where}`);
  console.log(`    signed by      ${result.key_id}`);
  console.log(`    version        ${signed.latest?.version}`);
  console.log(`    expires        ${signed.expires}  (${left.toFixed(1)} days left)`);
  for (const a of signed.latest?.artifacts ?? []) {
    console.log(`    ${a.platform}  ${a.filename}  ${a.sizeBytes} bytes  ${a.sha256.slice(0, 16)}…`);
  }
}

function main() {
  const verify = arg("--verify");
  if (verify) return verifyFile(verify);

  const keyPath = arg("--root-key");
  if (!keyPath) die("--root-key <path to the ceremony's private key> is required");
  const out = arg("--out") ?? "manifest.json";

  const art = artefact();
  if (!PLATFORMS.has(art.platform)) {
    die(`--platform ${art.platform} is not one the client knows (${[...PLATFORMS].join(", ")})`);
  }

  const now = new Date();
  const days = Number(arg("--expires-days") ?? DEFAULT_EXPIRY_DAYS);
  if (!Number.isFinite(days) || days < 1 || days > 365) {
    die(`--expires-days ${days} is not a number of days between 1 and 365`);
  }

  const signed = {
    schema: UPDATE_SCHEMA,
    channel: arg("--channel") ?? "stable",
    signedAt: rfc3339(now),
    expires: rfc3339(addDays(now, days)),
    min_supported_version: arg("--min-supported") ?? art.version,
    latest: {
      version: art.version,
      releasedAt: arg("--released-at") ?? rfc3339(now),
      placeholder: false,
      notes: notes(),
      artifacts: [
        {
          platform: art.platform,
          kind: art.kind,
          filename: art.filename,
          sizeBytes: art.sizeBytes,
          sha256: art.sha256,
        },
      ],
    },
  };

  const signers = [loadRoot(keyPath, has("--reserve") ? "reserve" : undefined)];
  const also = arg("--also-reserve");
  if (also) signers.push(loadRoot(also, "reserve"));

  const doc = signEnvelope({ domain: UPDATE_SCHEMA, signed, signers });

  // **Verified before it is written, against the published roots rather than against
  // the key just used.** Signing and then trusting the arithmetic is how you find out
  // from a user; this is the same check every shipped daemon will make.
  const check = verifyEnvelope(doc, UPDATE_SCHEMA, publishedRoots());
  if (!check.ok) {
    die(`the document this just signed does not verify: ${check.reason} — nothing written`);
  }

  fs.writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`wrote ${out}`);
  console.log(`  signed by      ${signers.map((s) => `${s.key_id} (${s.role})`).join(" + ")}`);
  console.log(`  version        ${art.version}`);
  console.log(`  artefact       ${art.filename}  ${art.sizeBytes} bytes`);
  console.log(`  sha256         ${art.sha256}`);
  console.log(`  expires        ${signed.expires}  (${days} days)`);
  console.log("");
  console.log("Carry it to the box and point updates.manifest_path at it. The server will refuse");
  console.log("to serve it if anything above is wrong, and answers 404 until the path is set.");
}

main();
