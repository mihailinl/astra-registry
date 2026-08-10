#!/usr/bin/env node
// Generates registry/v1/index.json from plugins/**. Nothing else writes it.
//
//   node tools/build-index.mjs            regenerate in place
//   node tools/build-index.mjs --check    fail if the committed file is not
//                                         exactly what this script produces
//   node tools/build-index.mjs --stdout   print, write nothing
//   node tools/build-index.mjs --serial N override the serial
//   node tools/build-index.mjs --registry-dir DIR  generate another tree's index
//
// TWO PROPERTIES THIS FILE EXISTS TO PROTECT
//
// 1. Determinism. Same sources + same serial -> same bytes. No clock read, no
//    map iteration order, no locale collation: keys are sorted by UTF-16 code
//    unit (tools/lib/canonical.mjs), plugins by id, releases by semver. That is
//    what makes `--check` meaningful and what will let a third party in Phase 3
//    reproduce the signed index from the git tree and diff it against ours.
//
// 2. The flat fields are a projection, not a second source. `version`,
//    `platform_downloads` and `download_url` exist because the daemon shipping
//    today reads exactly those (Astra astra-daemon/src/plugins/registry_client.rs);
//    `releases[]` is the real record. They are computed here, in one pass, from
//    the same release object, so they cannot drift the way two hand-kept fields
//    always eventually do.
//
// THE SERIAL. Commit count of `main`, path-limited to plugins/. Never
// read-and-increment a counter file: two PRs merging within the same minute
// both read N and both write N+1, and the second one silently un-bumps the
// first. A commit count cannot do that — it is a property of the history, not
// of a file, so concurrent merges get distinct values by construction. It is
// path-limited so that a commit touching only docs or this generator does not
// move the catalogue's version number, and so a future bot that regenerates and
// commits the index cannot trigger itself in a loop.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { stableStringify } from "./lib/canonical.mjs";
import { compareSemver } from "./lib/semver.mjs";
import { loadSources, REPO_ROOT } from "./lib/sources.mjs";

const BANNER =
  "GENERATED FILE — DO NOT EDIT. Source of truth: plugins/<id>/plugin.json and " +
  "plugins/<id>/versions/<semver>.json. Regenerate with `node tools/build-index.mjs`. " +
  "CI (.github/workflows/build-index.yml) fails when this file differs by one byte from " +
  "what the generator produces, so a hand edit is not a shortcut, it is a red build.";

const PLATFORM_KEYS_FOR_NOARCH = ["linux-x64", "windows-x64"];

export function resolveSerial({ explicit, root = REPO_ROOT } = {}) {
  if (explicit !== undefined && explicit !== null) return explicit;
  if (process.env.ASTRA_REGISTRY_SERIAL) {
    const n = Number(process.env.ASTRA_REGISTRY_SERIAL);
    if (!Number.isSafeInteger(n) || n < 0) {
      throw new Error(`ASTRA_REGISTRY_SERIAL=${process.env.ASTRA_REGISTRY_SERIAL} is not a non-negative integer`);
    }
    return n;
  }
  try {
    const out = execFileSync("git", ["rev-list", "--count", "HEAD", "--", "plugins"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return Number(out.trim());
  } catch {
    // No git history (a fresh checkout of the files, or the repo before its
    // first commit). 0 is the honest answer and it is deterministic.
    return 0;
  }
}

/** Latest-first, yanked releases removed. */
function listedReleases(plugin) {
  return plugin.versions
    .map((v) => v.doc)
    .filter((d) => d && d.yanked !== true)
    .sort((a, b) => -compareSemver(a.version, b.version));
}

function releaseRecord(doc) {
  const artifacts = {};
  for (const [key, art] of Object.entries(doc.artifacts ?? {})) {
    artifacts[key] = {
      url: art.url,
      filename: art.filename,
      ...(art.sha256 !== undefined ? { sha256: art.sha256 } : {}),
      ...(art.size !== undefined ? { size: art.size } : {}),
    };
  }
  return {
    version: doc.version,
    published_at: doc.published_at,
    ...(doc.protocol !== undefined ? { protocol: doc.protocol } : {}),
    ...(doc.min_astra_version !== undefined ? { min_astra_version: doc.min_astra_version } : {}),
    ...(doc.capabilities !== undefined ? { capabilities: [...doc.capabilities].sort() } : {}),
    ...(doc.permissions !== undefined ? { permissions: doc.permissions } : {}),
    ...(doc.changelog_url !== undefined ? { changelog_url: doc.changelog_url } : {}),
    ...(doc.staging === true ? { staging: true } : {}),
    ...(doc.staging === true && doc.staging_reason ? { staging_reason: doc.staging_reason } : {}),
    // Field by field, and each one only when the source carries it. `repo`/`tag`
    // belong to a github_release and `base_url` to a direct one; writing an
    // absent key as `undefined` would drop out of the JSON silently and take
    // with it the only statement of where these bytes are allowed to come from.
    release: {
      kind: doc.release.kind,
      ...(doc.release.repo !== undefined ? { repo: doc.release.repo } : {}),
      ...(doc.release.tag !== undefined ? { tag: doc.release.tag } : {}),
      ...(doc.release.commit !== undefined ? { commit: doc.release.commit } : {}),
      ...(doc.release.base_url !== undefined ? { base_url: doc.release.base_url } : {}),
    },
    artifacts,
  };
}

/**
 * The compatibility projection. Deliberately refuses to emit a download URL for
 * anything it cannot pin by digest: a client that only understands the flat
 * fields has no way to verify what it downloads, so the only safe thing to hand
 * it is nothing at all.
 */
function flatDownloads(latest) {
  const installable =
    latest.staging !== true &&
    Object.values(latest.artifacts).every((a) => typeof a.sha256 === "string" && typeof a.size === "number");
  if (!installable) return { download_url: "", platform_downloads: {} };

  const platform_downloads = {};
  let download_url = "";
  for (const [key, art] of Object.entries(latest.artifacts)) {
    if (key === "noarch") {
      // §5.2: one artifact for every host. Write it under every supported key
      // so no client has to learn the word "noarch".
      download_url = art.url;
      platform_downloads.noarch = art.url;
      for (const k of PLATFORM_KEYS_FOR_NOARCH) platform_downloads[k] = art.url;
    } else {
      platform_downloads[key] = art.url;
    }
  }
  return { download_url, platform_downloads };
}

export function buildIndex({ root = REPO_ROOT, serial } = {}) {
  const { errors, plugins } = loadSources(root);
  if (errors.length) {
    const lines = errors.map((e) => `  ${e.file}: ${e.message}`).join("\n");
    throw new Error(`cannot generate the index, the sources do not load:\n${lines}`);
  }

  const entries = [];
  for (const plugin of plugins) {
    if (plugin.doc.unlisted === true) continue;
    const releases = listedReleases(plugin);
    if (releases.length === 0) {
      throw new Error(
        `plugins/${plugin.dir}: every version is yanked or missing; delete the listing or add a release`,
      );
    }
    const records = releases.map(releaseRecord);
    const latest = records[0];
    const { download_url, platform_downloads } = flatDownloads(latest);
    const p = plugin.doc;

    entries.push({
      id: p.id,
      name: p.name,
      version: latest.version,
      description: p.summary,
      ...(p.description !== undefined ? { details: p.description } : {}),
      ...(p.author?.name !== undefined ? { author: p.author.name } : {}),
      ...(p.author?.url !== undefined ? { author_url: p.author.url } : {}),
      license: p.license,
      capabilities: latest.capabilities ?? [],
      ...(p.categories !== undefined ? { categories: [...p.categories].sort() } : {}),
      ...(p.keywords !== undefined ? { keywords: [...p.keywords].sort() } : {}),
      ...(p.homepage !== undefined ? { homepage: p.homepage } : {}),
      repository_url: `https://github.com/${p.source.repo}`,
      icon_url: p.icon_url ?? "",
      source: {
        kind: p.source.kind,
        repo: p.source.repo,
        ...(p.source.subdirectory !== undefined ? { subdirectory: p.source.subdirectory } : {}),
      },
      downloads: 0,
      stars: 0,
      updated_at: latest.published_at,
      added_at: p.added_at,
      ...(latest.staging === true ? { staging: true } : {}),
      download_url,
      platform_downloads,
      releases: records,
    });
  }

  entries.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  return {
    $comment: BANNER,
    schema: "astra.registry.index/1",
    serial: resolveSerial({ explicit: serial, root }),
    plugins: entries,
  };
}

function parseArgs(argv) {
  const opts = { check: false, stdout: false, serial: undefined, out: null, root: REPO_ROOT };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") opts.check = true;
    else if (a === "--stdout") opts.stdout = true;
    else if (a === "--serial") opts.serial = Number(argv[++i]);
    else if (a === "--out") opts.out = argv[++i];
    // Generate SOMEONE ELSE'S catalogue — a self-hosted or staging tree, the
    // same tree tools/validate.mjs judges with its own --registry-dir. Without
    // this the generator could only ever produce this repository's index, and
    // the documented way to run your own catalogue would have been to fork the
    // generator, which is how two generators start disagreeing.
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--help" || a === "-h") opts.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log("usage: node tools/build-index.mjs [--check] [--stdout] [--serial N] [--out FILE] [--registry-dir DIR]");
    return 0;
  }
  const outFile = path.resolve(opts.root, opts.out ?? "registry/v1/index.json");

  if (opts.check) {
    if (!fs.existsSync(outFile)) {
      console.error(`FAIL  ${path.relative(opts.root, outFile)} does not exist. Run: node tools/build-index.mjs`);
      return 1;
    }
    const committed = fs.readFileSync(outFile, "utf8");
    // Regenerate at the serial the committed file claims. The serial moves with
    // every listing commit, so comparing it here would fail on every push and
    // teach everyone to ignore this check. What is being checked is that the
    // CONTENT is generated — that nobody hand-edited a URL or a digest into it.
    let claimed;
    try {
      claimed = JSON.parse(committed).serial;
    } catch (e) {
      console.error(`FAIL  ${path.relative(opts.root, outFile)} is not valid JSON: ${e.message}`);
      return 1;
    }
    const regenerated = stableStringify(buildIndex({ root: opts.root, serial: claimed }));
    if (regenerated === committed) {
      console.log(`ok    ${path.relative(opts.root, outFile)} is byte-identical to a fresh generation (serial ${claimed})`);
      return 0;
    }
    console.error(`FAIL  ${path.relative(opts.root, outFile)} is not what the generator produces.`);
    const a = committed.split("\n");
    const b = regenerated.split("\n");
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i] !== b[i]) {
        console.error(`      first difference at line ${i + 1}:`);
        console.error(`      committed:   ${a[i] ?? "<end of file>"}`);
        console.error(`      generated:   ${b[i] ?? "<end of file>"}`);
        break;
      }
    }
    console.error("      Fix by running: node tools/build-index.mjs");
    return 1;
  }

  const text = stableStringify(buildIndex({ root: opts.root, serial: opts.serial }));
  if (opts.stdout) {
    process.stdout.write(text);
    return 0;
  }
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  const before = fs.existsSync(outFile) ? fs.readFileSync(outFile, "utf8") : null;
  fs.writeFileSync(outFile, text);
  const rel = path.relative(opts.root, outFile);
  console.log(before === text ? `ok    ${rel} unchanged` : `wrote ${rel}`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(1);
  }
}
