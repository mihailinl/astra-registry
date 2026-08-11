#!/usr/bin/env node
// Build and check the moderation log.
//
//   node bot/moderation.mjs --check                  the sources are valid
//   node bot/moderation.mjs --stdout                 print the log
//   node bot/moderation.mjs --revocations F --stdout print it, backing-checked
//
// The site build calls `buildModerationLog` directly, with the SIGNED
// withdrawal list it is deploying in the same job, so the published log cannot
// claim a revocation that was not signed. This CLI exists for the maintainer
// writing an entry and for CI, which runs `--check` on every push: an entry that
// would fail at deploy time should fail in the pull request that added it.

import fs from "node:fs";

import { REPO_ROOT } from "../tools/lib/sources.mjs";
import { buildModerationLog, loadEntries, SOURCE_DIR } from "./lib/moderation.mjs";

function arg(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}

export function main(argv = []) {
  const root = arg(argv, "--registry-dir") ?? REPO_ROOT;
  const revFile = arg(argv, "--revocations");

  const { entries, errors } = loadEntries({ root });
  if (errors.length) {
    console.error("FAIL  the moderation sources are invalid:");
    for (const e of errors) console.error(`      ${e}`);
    return 1;
  }

  let revocations = null;
  let revocationsSerial;
  if (revFile) {
    const doc = JSON.parse(fs.readFileSync(revFile, "utf8"));
    revocations = doc?.signed?.revocations ?? [];
    revocationsSerial = doc?.signed?.serial;
  }

  let log;
  try {
    log = buildModerationLog({ root, revocations, revocationsSerial });
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    return 1;
  }

  if (argv.includes("--stdout")) {
    process.stdout.write(`${JSON.stringify(log, null, 2)}\n`);
    return 0;
  }

  const counts = {};
  for (const e of log.entries) counts[e.action] = (counts[e.action] ?? 0) + 1;
  console.log(
    `ok    ${entries.length} moderation entr${entries.length === 1 ? "y" : "ies"} in ${SOURCE_DIR}/` +
      (log.entries.length ? ` — ${Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(", ")}` : "") +
      (revocations ? ` (backing checked against ${log.entries.filter((e) => e.backed).length} signed advisory reference(s))` : " (no withdrawal list given, so nothing was backing-checked)"),
  );
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(2);
  }
}
