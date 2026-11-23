#!/usr/bin/env node
// Does an export reproduce main, byte for byte?
//
//   node tools/export-replay.mjs --export <file|dir> [--registry <dir>] [--ref <ref>] [--keep]
//
// Phase 2 step 1's gate (plugin-phase2-design-2026-11-19 §6): the plugins
// service's `/export` replaces git as the source of plugins/** and log/** only
// once its answer equals main on every replayed commit. This is that
// comparison, and it reads the service's answer and `tools/export-stub.mjs`'s
// alike. For each export — one file, or a directory of `*.json` files, one per
// serial —
//
//   1. the commit is the LAST commit on `--ref`'s first-parent line (default
//      `HEAD`) whose DEC-9 serial equals the export's `serial`;
//   2. the export's files are written into a fresh scratch tree under $TMPDIR,
//      over a copy of that commit's tree with its plugins/ and log/ removed,
//      and read back — so what is compared is what a commit of the export
//      would hold, not what the export says it holds;
//   3. they are compared with the commit's plugins/** and log/**, read from git
//      objects, and every missing, extra and differing path is named; the
//      export's `state_sha256` is held to its own files and to the commit's;
//   4. `buildCatalogue` runs at that serial over the scratch tree and over the
//      commit's own tree, and the two catalogues and their asset files are
//      compared byte for byte.
//
// Exit 0 when every export is equal on all of it, 1 on any difference, 2 on a
// usage error.
//
// **A serial does not name one state, and this says so rather than guessing.**
// DEC-9 counts commits that touch plugins/, so a commit that touches log/ alone
// keeps the serial of the commit before it: 84 of main's first-parent commits
// on 2026-11-19 are such commits. An export taken at an earlier commit of a
// serial is therefore compared with that serial's LAST commit and fails; when
// an earlier commit of the same serial does match, the report names it, so the
// difference reads as "superseded by a log-only commit" and not as a broken
// export.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { buildCatalogue } from "./build-index.mjs";
import { catalogueStringify } from "./lib/canonical.mjs";
import { sha256Hex } from "../bot/lib/assets.mjs";
import {
  STATE_ROOTS, blobsAt, compareStatePaths, exportFiles, stateAt, stateSha256, treeEntriesAt,
} from "./lib/export-state.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { gitText } from "./signer/git.mjs";
import { serialAt } from "./export-stub.mjs";

/**
 * Every commit on `ref`'s first-parent line, newest first, with its serial.
 *
 * @param {{root: string, ref?: string}} opts
 * @returns {{sha: string, serial: number}[]}
 */
export function serialLine({ root, ref = "HEAD" }) {
  const shas = gitText(["rev-list", "--first-parent", ref], { root }).split("\n").filter(Boolean);
  return shas.map((sha) => ({ sha, serial: serialAt({ root, commit: sha }) }));
}

/** Write `commit`'s whole tree into `dir`, leaving out `skip`'s top-level directories. */
function materialize({ root, commit, dir, skip = [] }) {
  const entries = treeEntriesAt({ root, commit, roots: [] })
    .filter((e) => !skip.some((r) => e.path.startsWith(`${r}/`)));
  const blobs = entries.filter((e) => e.type === "blob");
  const bytes = blobsAt(root, blobs.map((e) => e.oid));
  blobs.forEach((e, i) => {
    const file = path.join(dir, ...e.path.split("/"));
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (e.mode === "120000") fs.symlinkSync(bytes[i].toString("utf8"), file);
    else fs.writeFileSync(file, bytes[i], { mode: e.mode === "100755" ? 0o755 : 0o644 });
  });
}

/** Every regular file under `dir`'s state roots, as path to bytes. */
function readState(dir) {
  const files = new Map();
  const walk = (rel) => {
    const abs = path.join(dir, ...rel.split("/"));
    for (const d of fs.readdirSync(abs, { withFileTypes: true })) {
      const child = `${rel}/${d.name}`;
      if (d.isDirectory()) walk(child);
      else files.set(child, fs.readFileSync(path.join(abs, d.name)));
    }
  };
  for (const r of STATE_ROOTS) if (fs.existsSync(path.join(dir, r))) walk(r);
  return files;
}

/** missing / extra / differing, each sorted in byte order. */
export function compareStates(want, got) {
  const sorted = (xs) => xs.sort(compareStatePaths);
  return {
    missing: sorted([...want.keys()].filter((p) => !got.has(p))),
    extra: sorted([...got.keys()].filter((p) => !want.has(p))),
    differing: sorted([...want.keys()].filter((p) => got.has(p) && !want.get(p).equals(got.get(p)))),
  };
}

/**
 * The catalogue at `serial` over a tree, and its asset files (contract 6.28.0)
 * folded into the text compared: one line per file, `<path> <sha256 of the
 * bytes>`, after the document. The members already name each file by its
 * digest, so this adds the one thing they cannot say — that the files the
 * signer would write from this tree are those bytes (TRUST-49's set).
 */
function indexOf(root, serial) {
  try {
    const { doc, assets } = buildCatalogue({ root, serial });
    const files = [...assets].map(([rel, bytes]) => `${rel} ${sha256Hex(bytes)}`).sort();
    return { text: catalogueStringify(doc) + files.map((l) => `${l}\n`).join("") };
  } catch (e) {
    return { error: String(e?.message ?? e) };
  }
}

/**
 * Replay one export against the history at `root`.
 *
 * @param {{root?: string, doc: object, line: {sha: string, serial: number}[], tmp?: string, keep?: boolean}} opts
 */
export function replayExport({ root = REPO_ROOT, doc, line, tmp = os.tmpdir(), keep = false }) {
  const report = { serial: doc?.serial, commit: null, problems: [], missing: [], extra: [], differing: [], index: null, equal: false };
  if (!Number.isSafeInteger(doc?.serial) || doc.serial < 0) {
    report.problems.push(`the export's serial is ${JSON.stringify(doc?.serial)}, not a non-negative integer`);
    return report;
  }
  const sameSerial = line.filter((c) => c.serial === doc.serial);
  if (!sameSerial.length) {
    report.problems.push(`no commit on the first-parent line has serial ${doc.serial}`);
    return report;
  }
  const commit = sameSerial[0].sha;
  report.commit = commit;

  const { files: exported, problems } = exportFiles(doc);
  report.problems.push(...problems);
  const own = stateSha256(exported);
  if (doc.state_sha256 !== own) {
    report.problems.push(`the export's state_sha256 ${doc.state_sha256} is not the digest of its own files, ${own}`);
  }
  const want = stateAt({ root, commit });
  if (doc.state_sha256 !== want.state_sha256) {
    report.problems.push(`the export's state_sha256 ${doc.state_sha256} is not ${commit.slice(0, 12)}'s, ${want.state_sha256}`);
    const earlier = sameSerial.slice(1).find((c) => stateAt({ root, commit: c.sha }).state_sha256 === doc.state_sha256);
    if (earlier) {
      report.problems.push(
        `it is the state of ${earlier.sha.slice(0, 12)}, an earlier commit at the same serial that a log-only commit ` +
        `superseded (DEC-9 counts plugins/ only)`,
      );
    }
  }

  const scratch = fs.mkdtempSync(path.join(tmp, "export-replay-"));
  try {
    const fromExport = path.join(scratch, "export");
    const fromCommit = path.join(scratch, "commit");
    materialize({ root, commit, dir: fromExport, skip: STATE_ROOTS });
    materialize({ root, commit, dir: fromCommit });
    for (const [p, bytes] of exported) {
      const file = path.join(fromExport, ...p.split("/"));
      try {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, bytes, { flag: "wx" });
      } catch (e) {
        report.problems.push(`${p} could not be written into the scratch tree: ${e.code ?? e.message}`);
      }
    }
    Object.assign(report, compareStates(want.files, readState(fromExport)));

    const a = indexOf(fromCommit, doc.serial);
    const b = indexOf(fromExport, doc.serial);
    if (a.text !== undefined && a.text === b.text) report.index = { equal: true, bytes: Buffer.byteLength(a.text) };
    else if (a.error !== undefined && a.error === b.error) {
      // The generator of today refuses this commit's own tree too. The files
      // above are still compared; there is no catalogue to compare.
      report.index = { equal: true, refusedBoth: a.error.split("\n")[0] };
    } else {
      report.index = { equal: false, commit: a.error ?? `${Buffer.byteLength(a.text)} bytes`, export: b.error ?? `${Buffer.byteLength(b.text)} bytes` };
      if (a.text !== undefined && b.text !== undefined) {
        const x = a.text.split("\n");
        const y = b.text.split("\n");
        const i = x.findIndex((l, n) => l !== y[n]);
        report.index.firstDifference = { line: (i < 0 ? x.length : i) + 1, commit: x[i] ?? "<end>", export: y[i] ?? "<end>" };
      }
    }
  } finally {
    if (!keep) fs.rmSync(scratch, { recursive: true, force: true });
    else report.scratch = scratch;
  }

  report.equal = !report.problems.length && !report.missing.length && !report.extra.length && !report.differing.length &&
    report.index?.equal === true;
  return report;
}

/** The export documents at `p`: one file, or every `*.json` in a directory. */
export function readExports(p) {
  const files = fs.statSync(p).isDirectory()
    ? fs.readdirSync(p).filter((f) => f.endsWith(".json")).sort().map((f) => path.join(p, f))
    : [p];
  return files.map((file) => ({ file, doc: JSON.parse(fs.readFileSync(file, "utf8")) }));
}

/**
 * Replay every export at `exportPath`.
 *
 * @returns {{equal: boolean, reports: object[]}}
 */
export function replay({ root = REPO_ROOT, exportPath, ref = "HEAD", tmp = os.tmpdir(), keep = false }) {
  const line = serialLine({ root, ref });
  const reports = readExports(exportPath).map(({ file, doc }) => ({ file, ...replayExport({ root, doc, line, tmp, keep }) }));
  return { equal: reports.length > 0 && reports.every((r) => r.equal), reports };
}

/** The lines a person reads, one block per export. */
export function renderReport({ reports }) {
  const out = [];
  if (!reports.length) out.push("FAIL  no export to replay");
  for (const r of reports) {
    const at = r.commit ? ` at ${r.commit.slice(0, 12)}` : "";
    out.push(`${r.equal ? "ok  " : "FAIL"}  ${r.file}: serial ${r.serial}${at}`);
    for (const p of r.problems) out.push(`      ${p}`);
    for (const [what, paths] of [["missing", r.missing], ["extra", r.extra], ["differing", r.differing]]) {
      for (const p of paths) out.push(`      ${what}: ${p}`);
    }
    if (r.index && !r.index.equal) {
      out.push(`      index.json differs (commit: ${r.index.commit}; export: ${r.index.export})`);
      if (r.index.firstDifference) {
        const d = r.index.firstDifference;
        out.push(`      first difference at line ${d.line}:`, `        commit: ${d.commit}`, `        export: ${d.export}`);
      }
    } else if (r.index?.refusedBoth) {
      out.push(`      note: today's build-index refuses this commit's tree too, so no catalogue was compared: ${r.index.refusedBoth}`);
    }
  }
  return out.join("\n");
}

function parseArgs(argv) {
  const args = { exportPath: null, root: REPO_ROOT, ref: "HEAD", keep: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--export") args.exportPath = argv[++i];
    else if (a === "--registry") args.root = path.resolve(argv[++i]);
    else if (a === "--ref") args.ref = argv[++i];
    else if (a === "--keep") args.keep = true;
    else if (a === "--help" || a === "-h") args.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.help || !args.exportPath) {
    console.error("usage: node tools/export-replay.mjs --export <file|dir> [--registry <dir>] [--ref <ref>] [--keep]");
    return args.help ? 0 : 2;
  }
  const result = replay({ root: args.root, exportPath: args.exportPath, ref: args.ref, keep: args.keep });
  console.log(renderReport(result));
  const bad = result.reports.filter((r) => !r.equal).length;
  console.log(`${result.equal ? "ok  " : "FAIL"}  ${result.reports.length - bad} of ${result.reports.length} export(s) reproduce main`);
  return result.equal ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(2);
  }
}
