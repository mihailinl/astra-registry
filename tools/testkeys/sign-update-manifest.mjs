#!/usr/bin/env node
// Produce the cross-repository interop fixture for the Astra update manifest.
//
//   node tools/testkeys/sign-update-manifest.mjs --out tools/testkeys/fixtures/update-manifest-interop.json
//
// THIS SIGNS WITH A KEY WHOSE PRIVATE HALF IS PUBLIC. Nothing a user installs may
// be signed with it; `astra-daemon` compiles these roots in only under
// `#[cfg(test)]` or an explicitly named non-default feature. The production
// signer is `../sign-update-manifest.mjs` and takes a path to an offline key.
//
// ── what this fixture is FOR, and it is not "an example manifest" ──────────
//
// The manifest is signed by JavaScript in this repository and verified by Rust in
// another. Between them sit two independent implementations of RFC 8785:
// `tools/lib/canonical.mjs` here and `plugins::trust::jcs` there. Every test on
// either side signs with its own language and verifies with its own language, so
// **the one thing that has never been checked is that the two agree** — and they
// can disagree on key order above the BMP, on string escaping, on number form, on
// an empty object.
//
// The failure is silent and one-directional. A divergence produces a document
// this repository considers perfectly signed and every installed Astra refuses,
// logging at debug level; the operator sees a correct manifest being served. And
// the cost is unbounded in time: clients that cannot verify a manifest can never
// receive an update, including the update that would fix the canonicaliser. Which
// is the same shape as the four cases already written into the contract — the
// cure is behind the door of the disease.
//
// So this file is deliberately hostile to a canonicaliser rather than
// representative of a real release. Every field below that looks odd is a place
// two implementations are known to part company:
//
//   · Cyrillic — multi-byte UTF-8 that must be emitted literally, not \uXXXX;
//   · an emoji — a non-BMP character, i.e. a surrogate PAIR in UTF-16. §3.2.3
//     sorts keys by UTF-16 code unit, which stops agreeing with byte order
//     exactly here, and §3.2.2.2 must still emit it as literal UTF-8;
//   · a quote, a backslash and a control character — the three escapes with
//     short forms, where an encoder may legitimately choose 	 over \t;
//   · a key that sorts differently under the two orders, to catch §3.2.3;
//   · integers at the edge of what both sides accept.
//
// If the Rust side verifies this document byte for byte, the two canonicalisers
// agree on everything either has ever been asked to encode. If it does not, we
// learn it here rather than from a fleet that stopped updating.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { jcs } from "../lib/canonical.mjs";
import { loadTestRoot } from "./regenerate.mjs";
import { signEnvelope, verifyEnvelope, publicKeyFromBase64, UPDATE_SCHEMA } from "../../bot/lib/sign.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

/**
 * The document.
 *
 * `expires` is 2031 on purpose. A fixture that goes stale starts failing on a
 * date nobody wrote down, and the test it breaks is the one that would have told
 * you why — so it outlives any plausible life of this test rather than modelling
 * a real thirty-day window, which the production signer computes from the clock.
 */
function manifest() {
  return {
    schema: UPDATE_SCHEMA,
    channel: "stable",
    signedAt: "2026-09-02T08:00:00Z",
    expires: "2031-01-01T00:00:00Z",
    min_supported_version: "0.2.1",
    latest: {
      version: "0.2.2",
      releasedAt: "2026-09-02T07:40:00Z",
      placeholder: false,
      notes: {
        // ASCII, the easy case, and the fallback every other locale lands on.
        en: "Automatic updates. Quote \" backslash \\ tab\tend.",
        // Cyrillic: multi-byte UTF-8 that RFC 8785 §3.2.2.2 requires be emitted
        // LITERALLY. An encoder that escapes it as А produces different
        // bytes, the same string, and a signature neither side can reproduce.
        ru: "Автоматические обновления. Кавычка \" слэш \\ табуляция\tконец.",
        // Non-BMP: one code point, two UTF-16 code units. This is where sorting
        // by code unit stops agreeing with sorting by byte, and where an encoder
        // that reasons in UTF-16 can emit a lone surrogate.
        uk: "Автоматичні оновлення 🛠 готово.",
      },
      artifacts: [
        {
          platform: "windows-x64",
          kind: "installer",
          filename: "Astra-Installer-0.2.2.exe",
          sizeBytes: 87437592,
          sha256: "b779a4e8c4e076451014d1237717a815bb77f1e71e800aba797279b98ff3d185",
        },
        {
          // Present so the fixture can be exercised on a Linux developer machine
          // as well as on Windows, and so the reader's platform-selection step is
          // covered rather than assumed.
          platform: "linux-x64",
          kind: "package",
          filename: "Astra-linux-x64.tar.gz",
          sizeBytes: 91234567,
          sha256: "3f786850e387550fdab836ed7e6dc881de23001b3a55a4cf6ec1a3ff4a63b3ba",
        },
      ],
    },
    // **Unknown to both readers today, and that is the test.** `verify_envelope`
    // keeps every member of `signed`, known or not, so a future field must round
    // trip through the signature unchanged. The key is Cyrillic so that §3.2.3's
    // UTF-16 code-unit ordering is exercised on a KEY and not only on a value —
    // the one place where the two canonicalisers' sort orders can part company.
    "проба": {
      "🛠": "non-BMP key, sorted by UTF-16 code unit",
      empty_object: {},
      empty_array: [],
      max_safe: 9007199254740991,
      negative: -1,
      zero: 0,
    },
  };
}

function main() {
  const out = arg("--out") ?? path.join(HERE, "fixtures", "update-manifest-interop.json");
  const keyId = arg("--key") ?? "TEST-ONLY-DO-NOT-TRUST-root-a";
  const root = loadTestRoot(keyId);

  const signed = manifest();

  // Printed rather than hidden: if the Rust side reports a different digest, the
  // canonical form is the first thing to diff, and having it in the run output
  // saves reproducing the exact object.
  const canonical = jcs(signed);
  console.log(`canonical JCS: ${canonical.length} bytes`);

  const doc = signEnvelope({
    domain: UPDATE_SCHEMA,
    signed,
    signers: [{ key_id: root.key_id, privateKey: root.privateKey }],
  });

  // Verified here too, so a fixture can never be committed that this repository
  // itself would refuse. That failure would look identical to a Rust-side
  // disagreement and cost an afternoon telling them apart.
  const check = verifyEnvelope(doc, UPDATE_SCHEMA, [
    { key_id: root.key_id, publicKey: publicKeyFromBase64(root.publicKeyB64) },
  ]);
  if (!check.ok) {
    console.error(`sign-update-manifest: this repository cannot verify what it just signed: ${check.reason}`);
    process.exit(1);
  }

  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`wrote ${out}`);
  console.log(`  signed by  ${root.key_id}`);
  console.log(`  verifies   here, with this repository's own canonicaliser`);
  console.log("");
  console.log("Now feed it to astra-daemon's `evaluate` under #[cfg(test)]. If it verifies there");
  console.log("too, the two independent RFC 8785 implementations agree. If it does not, no");
  console.log("installed client would ever have accepted a real manifest either.");
}

main();
