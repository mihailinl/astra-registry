#!/usr/bin/env node
// Sign an update manifest with a key whose PRIVATE HALF IS PUBLISHED, for rehearsing
// the whole update path without publishing anything.
//
//   node tools/testkeys/rehearse-manifest.mjs \
//     --artifact ~/Downloads/Astra-Installer-0.2.2.exe \
//     --version  0.2.2 \
//     --notes-en releases/0.2.2/notes.en.txt \
//     --notes-ru releases/0.2.2/notes.ru.txt \
//     --out      /tmp/rehearsal-0.2.2.json
//
// ── why this exists beside the production signer ───────────────────────────
//
// The real ceremony must not be the first attempt. A key is decrypted, a document is
// signed, a file reaches a box and a client is asked to believe it — and every step
// between "the signature verifies" and "the offer appears" is untested until somebody
// runs it end to end. This lets that happen with a key no shipped binary will ever
// accept, so a rehearsal cannot become a publication by accident.
//
// ── it mirrors the production signer's REFUSALS, deliberately ──────────────
//
// A rehearsal that validates less than the real thing rehearses the wrong system: it
// would pass a document the ceremony then refuses, at the exact moment the offline key
// is out of its envelope. So the filename set, the platform set and the notes predicate
// are the same three checks, in the same order, and this file states them rather than
// importing them — the production signer must stay readable as one self-contained
// procedure, and a shared helper would make BOTH files depend on a third that neither
// reader opens.
//
// The one thing it does NOT check is that the key is a published root, because the
// whole point is that it is not one.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import { loadTestRoot } from "./regenerate.mjs";
import {
  signEnvelope,
  verifyEnvelope,
  publicKeyFromBase64,
  UPDATE_SCHEMA,
} from "../../bot/lib/sign.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** The closed set the CLIENT accepts. A name outside it is refused here as well. */
const FILENAME = /^Astra-Installer-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\.exe$/;
const PLATFORMS = new Set(["windows-x64"]);
const DEFAULT_EXPIRY_DAYS = 3650;

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function die(message) {
  console.error(`rehearse-manifest: ${message}`);
  process.exit(1);
}

function rfc3339(d) {
  return `${d.toISOString().slice(0, 19)}Z`;
}

/**
 * Release notes, refused if they carry anything the client would not render as text.
 *
 * The same predicate the production signer applies, for the same reason: the client
 * renders notes as PLAIN TEXT and the server refuses markup too, so a document carrying
 * it would be published and then refused by both ends.
 */
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
        `the ${locale} notes carry markup or a link. The client renders notes as PLAIN TEXT ` +
          "and the server refuses them as well, so a rehearsal that accepted them would " +
          "rehearse a document the real ceremony refuses.",
      );
    }
    out[locale] = text;
  }
  if (!out.en) die("--notes-en is required: a locale nobody wrote falls back to English");
  return out;
}

/** Size and digest FROM THE BYTES. Never accepted as arguments, exactly as in production. */
function artefact() {
  const where = arg("--artifact");
  if (!where) die("--artifact is required — the size and digest are computed, never given");
  let bytes;
  try {
    bytes = fs.readFileSync(where);
  } catch (e) {
    die(`cannot read the artefact at ${where}: ${e.message}. If the build is not on this machine, put it on this machine.`);
  }
  const filename = path.basename(where);
  const m = FILENAME.exec(filename);
  if (!m) {
    die(
      `${filename} is not a name the client accepts. The closed set is ` +
        "Astra-Installer-<version>.exe — it becomes a URL component and a path on disk over " +
        "there, so the set is checked rather than the string sanitised.",
    );
  }
  const version = arg("--version") ?? m[1];
  if (version !== m[1]) {
    die(
      `--version ${version} disagrees with the filename's ${m[1]}. A manifest whose version and ` +
        "artefact disagree is one the client resolves in whichever direction it happens to read " +
        "first, which is not a thing to discover during a rehearsal.",
    );
  }
  const platform = arg("--platform") ?? "windows-x64";
  if (!PLATFORMS.has(platform)) {
    die(`--platform ${platform} is not one the client knows (${[...PLATFORMS].join(", ")})`);
  }
  return {
    platform,
    kind: arg("--kind") ?? "installer",
    filename,
    sizeBytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    version,
  };
}

function main() {
  const art = artefact();
  const days = Number(arg("--expires-days") ?? DEFAULT_EXPIRY_DAYS);
  if (!Number.isFinite(days) || days < 1) die(`--expires-days ${days} is not a number of days`);

  // A FIXED instant, not the clock. `Date.now()` would make two runs of the same rehearsal
  // produce two different documents, and "the bytes changed" is the first thing anybody
  // diffs when a verification fails.
  const now = new Date(arg("--now") ?? "2026-09-03T00:00:00Z");
  const expires = new Date(now.getTime() + days * 86400000);

  const signed = {
    schema: UPDATE_SCHEMA,
    channel: arg("--channel") ?? "stable",
    signedAt: rfc3339(now),
    expires: rfc3339(expires),
    min_supported_version: arg("--min-supported") ?? art.version,
    latest: {
      version: art.version,
      releasedAt: rfc3339(now),
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

  const keyId = arg("--key") ?? "TEST-ONLY-DO-NOT-TRUST-root-a";
  const root = loadTestRoot(keyId);
  const doc = signEnvelope({
    domain: UPDATE_SCHEMA,
    signed,
    signers: [{ key_id: root.key_id, privateKey: root.privateKey }],
  });

  // Verified here too, so a rehearsal fixture can never be produced that this repository
  // itself would refuse — that failure looks identical to a Rust-side disagreement and
  // costs an afternoon telling the two apart.
  const check = verifyEnvelope(doc, UPDATE_SCHEMA, [
    { key_id: root.key_id, publicKey: publicKeyFromBase64(root.publicKeyB64) },
  ]);
  if (!check.ok) die(`this repository cannot verify what it just signed: ${check.reason}`);

  const out = arg("--out") ?? path.join(HERE, "fixtures", `rehearsal-${art.version}.json`);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);

  console.log(`wrote ${out}`);
  console.log(`  version        ${art.version}`);
  console.log(`  filename       ${art.filename}`);
  console.log(`  sizeBytes      ${art.sizeBytes}`);
  console.log(`  sha256         ${art.sha256}`);
  console.log(`  expires        ${signed.expires}`);
  console.log(`  signed by      ${root.key_id}`);
  console.log("");
  console.log("  *** NOT PUBLISHABLE. This key's private half is published in");
  console.log("  *** tools/testkeys/README.md, and no shipped binary compiles these");
  console.log("  *** roots in. Serving this from production would be a manifest every");
  console.log("  *** installed client refuses, silently, at debug level.");
}

main();
