#!/usr/bin/env node
// Builds the fixtures that need a real artifact, into a directory of your
// choosing (tools/selftest.mjs uses a temp dir; nothing binary is committed).
//
//   node tools/make-fixtures.mjs /tmp/fx
//
// Two registry trees that differ in ONE hex character:
//
//   <out>/digest-ok/        listing digest == the bundle's real sha256
//   <out>/digest-mismatch/  listing digest has its last nibble flipped
//   <out>/artifacts/        the one .astraplugin both trees point at
//
// That pair is the whole point of the exercise. A registry that cannot tell
// those two apart is a registry that will happily hand a user bytes nobody
// checked, which is the failure mode the digest exists to prevent — so it is
// worth a fixture that proves the check fires, not just one that proves the
// happy path passes.
//
// The bundle is written by tools/lib/zip.mjs's deterministic writer: stored
// entries, fixed 1980 timestamps, fixed order. Same inputs, same bytes, same
// digest, on every machine and every rerun.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import { writeZip } from "./lib/zip.mjs";
import { stableStringify } from "./lib/canonical.mjs";

const ID = "fixture-plugin";
const VERSION = "1.0.0";
const REPO = "astra-fixtures/fixture-plugin";
const TAG = "v1.0.0";
const FILENAME = `${ID}-${VERSION}-linux-x64.astraplugin`;

/** A minimal, structurally valid v2 bundle (PRODUCTION_PLAN §5.2). */
export function buildFixtureBundle() {
  const binary = Buffer.from("#!/bin/sh\necho fixture\n", "utf8");
  const pluginToml = Buffer.from(
    [
      "[plugin]",
      `id = "${ID}"`,
      'name = "Fixture Plugin"',
      `version = "${VERSION}"`,
      'license = "MIT"',
      "",
      "[entry]",
      'command = "bin/fixture"',
      "",
    ].join("\n"),
    "utf8",
  );

  const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
  const manifest = {
    schema: "astra.bundle/2",
    plugin_id: ID,
    version: VERSION,
    platform: { os: "linux", arch: "x86_64" },
    protocol: 1,
    capabilities: ["tools"],
    entry: { command: "bin/fixture", args: [] },
    files: [
      { path: "bin/fixture", sha256: sha(binary), size: binary.length, mode: "0755" },
      { path: "plugin.toml", sha256: sha(pluginToml), size: pluginToml.length, mode: "0644" },
    ],
  };

  // MANIFEST.json first, stored — §5.2. The rest sorted by path.
  return writeZip([
    { name: "MANIFEST.json", data: stableStringify(manifest), mode: 0o644 },
    { name: "bin/fixture", data: binary, mode: 0o755 },
    { name: "plugin.toml", data: pluginToml, mode: 0o644 },
  ]);
}

function writeListing(dir, sha256, size) {
  const pluginDir = path.join(dir, "plugins", ID);
  fs.mkdirSync(path.join(pluginDir, "versions"), { recursive: true });
  fs.writeFileSync(
    path.join(pluginDir, "plugin.json"),
    stableStringify({
      schema: "astra.registry.plugin/1",
      id: ID,
      name: "Fixture Plugin",
      summary: "A listing that exists so the digest check has something to check.",
      license: "MIT",
      source: { kind: "github", repo: REPO },
      added_at: "2026-08-10",
    }),
  );
  fs.writeFileSync(
    path.join(pluginDir, "versions", `${VERSION}.json`),
    stableStringify({
      schema: "astra.registry.version/1",
      id: ID,
      version: VERSION,
      published_at: "2026-08-10T00:00:00Z",
      release: { kind: "github_release", repo: REPO, tag: TAG },
      protocol: 1,
      capabilities: ["tools"],
      artifacts: {
        "linux-x64": {
          url: `https://github.com/${REPO}/releases/download/${TAG}/${FILENAME}`,
          filename: FILENAME,
          sha256,
          size,
        },
      },
    }),
  );
}

/** @returns {{artifactsDir: string, okDir: string, mismatchDir: string, sha256: string, bundle: Buffer}} */
export function makeFixtures(outDir) {
  const bundle = buildFixtureBundle();
  const sha256 = crypto.createHash("sha256").update(bundle).digest("hex");

  const artifactsDir = path.join(outDir, "artifacts");
  fs.mkdirSync(artifactsDir, { recursive: true });
  fs.writeFileSync(path.join(artifactsDir, FILENAME), bundle);

  const okDir = path.join(outDir, "digest-ok");
  const mismatchDir = path.join(outDir, "digest-mismatch");
  writeListing(okDir, sha256, bundle.length);
  // One nibble. That is all it should take.
  const wrong = sha256.slice(0, 63) + (sha256.endsWith("0") ? "1" : "0");
  writeListing(mismatchDir, wrong, bundle.length);

  return { artifactsDir, okDir, mismatchDir, sha256, wrong, bundle, filename: FILENAME };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const out = process.argv[2];
  if (!out) {
    console.error("usage: node tools/make-fixtures.mjs <output-directory>");
    process.exit(2);
  }
  const r = makeFixtures(path.resolve(out));
  console.log(`bundle    ${path.join(r.artifactsDir, r.filename)}`);
  console.log(`sha256    ${r.sha256}  (${r.bundle.length} bytes)`);
  console.log(`ok tree   ${r.okDir}`);
  console.log(`bad tree  ${r.mismatchDir}  (digest ends ...${r.wrong.slice(-8)})`);
}
