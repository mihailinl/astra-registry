#!/usr/bin/env node
// The signed-catalogue fixtures, and the reason they exist.
//
//   node bot/fixtures/index/regenerate.mjs          rewrite them
//   node bot/fixtures/index/regenerate.mjs --check  verify them, write nothing
//
// Two programs decide what a catalogue signature covers:
//
//   signer    astra-registry/bot/lib/sign.mjs + tools/lib/canonical.mjs
//   verifier  Astra/astra-daemon/src/plugins/trust.rs
//
// They are two implementations of RFC 8785 in two languages in two
// repositories. Signer and verifier canonicalising differently is the classic
// way a signature scheme silently accepts nothing (every install breaks) or
// everything (nobody notices for a year), and neither failure shows up in a
// suite where each side checks its own work.
//
// `catalogue-signed.json` is the cure: these exact bytes are embedded in a
// daemon unit test, which verifies them with the Rust canonicaliser against the
// key that this script's JavaScript signed with. A change to either JCS
// implementation that the other does not match turns that test red.
//
// Everything here is signed with TEST keys whose private halves are committed
// to this repository on purpose. `issued_at` is FIXED, not `new Date()` — a
// fixture that changes every time it is regenerated cannot be committed, and a
// signature over a clock reading is not reproducible by anyone.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "../../../tools/lib/canonical.mjs";
import { INDEX_SCHEMA, verifyEnvelope, publicKeyFromBase64 } from "../../lib/sign.mjs";
import { signIndex } from "../../sign-index.mjs";
import { loadTestRoot } from "../../../tools/testkeys/regenerate.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "../../..");

/** The instant every fixture claims to have been published at. */
export const FIXTURE_ISSUED_AT = new Date("2026-08-15T00:00:00Z");

/** The index key inside its `trust.json` window (2026-08-01 → 2026-11-01). */
export const FIXTURE_KEY_ID = "TEST-ONLY-DO-NOT-TRUST-index-2026a";

const BANNER =
  "TEST FIXTURE — signed with a key whose private half is published in " +
  "astra-registry/tools/testkeys/. astra-daemon embeds these exact bytes in a plugins::trust " +
  "unit test so the JavaScript signer and the Rust verifier cannot canonicalise differently in " +
  "silence. Regenerate with `node bot/fixtures/index/regenerate.mjs`.";

/**
 * A catalogue small enough to read in one screen and complete enough to
 * exercise every shape the daemon deserialises: the flat compatibility fields,
 * a `releases[]` entry with a digest and a size, a `noarch` artifact, and a
 * non-ASCII string so the canonicaliser's escaping is not merely assumed.
 */
export function fixtureCatalogue(serial = 12) {
  return {
    $comment: BANNER,
    signatures: [],
    signed: {
      schema: INDEX_SCHEMA,
      serial,
      plugins: [
        {
          added_at: "2026-08-01",
          author: "Astra Team",
          capabilities: ["tools"],
          description: "Rolls dice — würfelt, 🎲, in any notation.",
          download_url: "",
          downloads: 0,
          icon_url: "",
          id: "dice-roller",
          license: "MIT",
          name: "Dice Roller",
          platform_downloads: {
            "linux-x64": "https://github.com/mihailinl/AstraPlugins/releases/download/dice-roller-v0.1.1/dice-roller-0.1.1-linux-x64.astraplugin",
          },
          releases: [
            {
              artifacts: {
                "linux-x64": {
                  filename: "dice-roller-0.1.1-linux-x64.astraplugin",
                  sha256: "1111111111111111111111111111111111111111111111111111111111111111",
                  size: 4096,
                  url: "https://github.com/mihailinl/AstraPlugins/releases/download/dice-roller-v0.1.1/dice-roller-0.1.1-linux-x64.astraplugin",
                },
              },
              published_at: "2026-08-01T00:00:00Z",
              release: { kind: "github_release", repo: "mihailinl/AstraPlugins", tag: "dice-roller-v0.1.1" },
              version: "0.1.1",
            },
          ],
          repository_url: "https://github.com/mihailinl/AstraPlugins",
          source: { kind: "github", repo: "mihailinl/AstraPlugins" },
          stars: 0,
          updated_at: "2026-08-01T00:00:00Z",
          version: "0.1.1",
        },
      ],
    },
  };
}

/**
 * Every fixture, as `[filename, bytes]`.
 *
 * The serials are the point of the second one: 11 is a legitimately signed
 * catalogue that is simply older than 12. Rejecting it has to come from the
 * serial and from nothing else, so it must be genuinely valid — a tampered
 * document would prove the signature check, not the rollback check.
 */
export function fixtures() {
  const signer = loadTestRoot(FIXTURE_KEY_ID);
  const sign = (serial) =>
    signIndex(fixtureCatalogue(serial), {
      signer: { key_id: signer.key_id, privateKey: signer.privateKey },
      issuedAt: FIXTURE_ISSUED_AT,
    });

  return [
    ["catalogue-unsigned.json", stableStringify(fixtureCatalogue(12))],
    ["catalogue-signed.json", stableStringify(sign(12))],
    ["catalogue-signed-serial11.json", stableStringify(sign(11))],
  ];
}

function main(argv) {
  const check = argv.includes("--check");
  let failed = 0;

  for (const [name, text] of fixtures()) {
    const file = path.join(HERE, name);
    if (check) {
      const have = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
      if (have !== text) {
        console.error(`MISMATCH ${name} — rerun without --check`);
        failed += 1;
      }
    } else {
      fs.writeFileSync(file, text);
      console.log(`wrote ${path.relative(REPO_ROOT, file)}`);
    }
  }

  // A fixture nobody verified is a fixture that proves the signer agrees with
  // itself. This at least closes the loop on this side; the Rust test closes it
  // across the two.
  const trust = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "tools/testkeys/fixtures/trust-reserve-signed.json"), "utf8"),
  );
  const keys = trust.signed.index_keys.map((e) => ({
    key_id: e.key_id,
    publicKey: publicKeyFromBase64(e.public_key),
  }));
  const signed = JSON.parse(fs.readFileSync(path.join(HERE, "catalogue-signed.json"), "utf8"));
  const result = verifyEnvelope(signed, INDEX_SCHEMA, keys);
  if (!result.ok) {
    console.error(`FAIL  catalogue-signed.json does not verify against the trust.json fixture: ${result.reason}`);
    failed += 1;
  } else {
    console.log(`ok    catalogue-signed.json verifies under ${result.key_id}`);
  }

  if (failed) return 1;
  if (check) console.log("all catalogue fixtures match");
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exit(main(process.argv.slice(2)));
}
