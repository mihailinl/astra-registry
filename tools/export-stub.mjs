#!/usr/bin/env node
// The export the plugins service must answer, generated from main's own tree.
//
//   node tools/export-stub.mjs --at <commit> [--registry <dir>] [--out <file>]
//
// Phase 2 step 1 (plugin-phase2-design-2026-11-19 §6): the service's
// `GET /plugins/v1/export` is gated on reproducing today's `main` byte for byte,
// commit by commit. Until it exists, this is what it must equal: at `<commit>`,
//
//   serial        DEC-9's catalogue serial, `git rev-list --count <commit> --
//                 CATALOGUE_PATHSPEC` (tools/build-index.mjs) — the number the
//                 signer stamps on the catalogue signed from that commit;
//   state_sha256  tools/lib/export-state.mjs's digest of the files below;
//   files         every `100644` file under plugins/ and log/, path to base64
//                 bytes, keys in byte order, read from git objects.
//
// `tools/export-replay.mjs` reads either this or the service's answer, so the
// two can be compared by the same harness.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { CATALOGUE_PATHSPEC } from "./build-index.mjs";
import { filesMember, stateAt } from "./lib/export-state.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { gitText, revCount } from "./signer/git.mjs";

/** DEC-9's catalogue serial at a commit. */
export function serialAt({ root, commit }) {
  return revCount({ root, sha: commit, pathspec: CATALOGUE_PATHSPEC });
}

/**
 * The export document at a commit.
 *
 * @param {{root?: string, commit: string}} opts
 */
export function stubExport({ root = REPO_ROOT, commit }) {
  const sha = gitText(["rev-parse", "--verify", `${commit}^{commit}`], { root });
  const { files, state_sha256 } = stateAt({ root, commit: sha });
  return { serial: serialAt({ root, commit: sha }), state_sha256, files: filesMember(files) };
}

/** One export as the bytes this tool writes. */
export const exportText = (doc) => `${JSON.stringify(doc)}\n`;

function parseArgs(argv) {
  const args = { at: null, root: REPO_ROOT, out: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--at") args.at = argv[++i];
    else if (a === "--registry") args.root = path.resolve(argv[++i]);
    else if (a === "--out") args.out = argv[++i];
    else if (a === "--help" || a === "-h") args.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.help || !args.at) {
    console.error("usage: node tools/export-stub.mjs --at <commit> [--registry <dir>] [--out <file>]");
    return args.help ? 0 : 2;
  }
  const doc = stubExport({ root: args.root, commit: args.at });
  if (args.out) {
    fs.writeFileSync(args.out, exportText(doc));
    console.error(`ok    ${args.out}: serial ${doc.serial}, ${Object.keys(doc.files).length} files, state_sha256 ${doc.state_sha256}`);
  } else {
    process.stdout.write(exportText(doc));
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(1);
  }
}
