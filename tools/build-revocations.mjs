#!/usr/bin/env node
// Generates registry/v1/revocations.json from tools/revocations/**.
// Nothing else writes it.
//
//   node tools/build-revocations.mjs            regenerate in place
//   node tools/build-revocations.mjs --check    fail if the committed file is
//                                               not what this script produces
//   node tools/build-revocations.mjs --stdout   print, write nothing
//   node tools/build-revocations.mjs --serial N override the serial
//
// The same two properties tools/build-index.mjs protects, for the same reasons:
//
// 1. DETERMINISM. Same sources + same serial → same bytes. No clock is read
//    here; `issued_at`/`expires_at` are stamped by tools/sign-revocations.mjs,
//    because they are properties of the *publication* and a generator that read
//    a clock could not be reproduced by anybody auditing the signature.
//
// 2. THE COMMITTED FILE IS NOT A SECOND SOURCE. `--check` regenerates from
//    tools/revocations/** and compares. Editing a digest straight into the
//    deployed document — adding a withdrawal nobody reviewed, or quietly
//    dropping one — is the single highest-value edit an attacker with commit
//    access could make here, and it is a red build rather than a merge.
//
// WHY THE SOURCES LIVE UNDER tools/. An advisory is not a listing: it is not
// submitted by an author, it is not generated from a release, and it is written
// by the maintainer at the moment of an incident. Keeping the source files
// beside the generator that consumes them keeps `plugins/**` meaning exactly
// one thing — "things people asked us to list" — and keeps the ingest bot's
// validator from having an opinion about advisories it never sees.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "./lib/canonical.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { OUTPUT_FILE, SOURCE_DIR, buildRevocations, loadAdvisories } from "./lib/revocations.mjs";

/** The content half of the document — everything a fresh generation can reproduce. */
function content(doc) {
  const signed = doc?.signed ?? {};
  return { schema: signed.schema, serial: signed.serial, revocations: signed.revocations ?? [] };
}

function arg(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}

export function main(argv = []) {
  const root = REPO_ROOT;
  const outFile = path.join(root, OUTPUT_FILE);
  const serialArg = arg(argv, "--serial");
  const serial = serialArg === undefined ? undefined : Number(serialArg);
  if (serialArg !== undefined && (!Number.isSafeInteger(serial) || serial < 1)) {
    console.error(`FAIL  --serial ${serialArg} is not a positive integer`);
    return 2;
  }

  // Report the sources' problems before anything else: a build that fails with
  // "cannot read" three layers down teaches nobody which file is wrong.
  const { advisories, errors } = loadAdvisories({ root });
  if (errors.length) {
    console.error("FAIL  the advisory sources are invalid:");
    for (const e of errors) console.error(`      ${e}`);
    return 1;
  }

  if (argv.includes("--check")) {
    if (!fs.existsSync(outFile)) {
      console.error(`FAIL  ${OUTPUT_FILE} does not exist. Generate it: node tools/build-revocations.mjs`);
      return 1;
    }
    const committed = fs.readFileSync(outFile, "utf8");
    let parsed;
    try {
      parsed = JSON.parse(committed);
    } catch (e) {
      console.error(`FAIL  ${OUTPUT_FILE} is not JSON (${e.message})`);
      return 1;
    }
    if (!parsed?.signed) {
      console.error(`FAIL  ${OUTPUT_FILE} has no \`signed\` member; it must be a signed envelope`);
      return 1;
    }
    const fresh = buildRevocations({ root, serial: parsed.signed.serial });
    // Same two comparisons build-index.mjs makes, and the second is the one
    // that must always hold: a file that has been signed carries `issued_at`,
    // `expires_at` and signatures that no clock-free, key-free generator can
    // reproduce — but its CONTENT still has to be exactly what the sources say,
    // and that is where a hand-added or hand-removed withdrawal would land.
    const stamped = parsed.signed.issued_at !== undefined || (parsed.signatures?.length ?? 0) > 0;
    const same = stableStringify(content(parsed)) === stableStringify(content(fresh));
    if (same && (stamped || committed === stableStringify(fresh))) {
      console.log(
        `ok    ${OUTPUT_FILE} is ${stamped ? "content-identical" : "byte-identical"} to a fresh ` +
          `generation (serial ${parsed.signed.serial}, ${parsed.signed.revocations?.length ?? 0} ` +
          `entry(ies) from ${advisories.length} advisory(ies))`,
      );
      return 0;
    }
    console.error(`FAIL  ${OUTPUT_FILE} is not what the generator produces.`);
    const a = stableStringify(content(parsed)).split("\n");
    const b = stableStringify(content(fresh)).split("\n");
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i] !== b[i]) {
        console.error(`      first difference at line ${i + 1}:`);
        console.error(`      committed:   ${a[i] ?? "<end of file>"}`);
        console.error(`      generated:   ${b[i] ?? "<end of file>"}`);
        break;
      }
    }
    console.error("      Fix by running: node tools/build-revocations.mjs");
    return 1;
  }

  const doc = buildRevocations({ root, serial });
  const text = stableStringify(doc);
  if (argv.includes("--stdout")) {
    process.stdout.write(text);
    return 0;
  }
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  const before = fs.existsSync(outFile) ? fs.readFileSync(outFile, "utf8") : null;
  fs.writeFileSync(outFile, text);
  console.log(
    before === text
      ? `ok    ${OUTPUT_FILE} unchanged`
      : `wrote ${OUTPUT_FILE}: serial ${doc.signed.serial}, ${doc.signed.revocations.length} ` +
        `entry(ies) from ${advisories.length} advisory(ies) in ${SOURCE_DIR}/`,
  );
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
