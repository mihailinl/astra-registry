#!/usr/bin/env node
// The PULL-REQUEST path: judge a hand-edited listing against its artifacts.
//
// The RELEASE path is `bot/ingest.mjs`, which is the trust boundary — two typed
// facts, everything else read out of an attested bundle, ownership proved, and
// the listing written rather than reviewed. This file is the other half: a
// human edited `plugins/**` and something has to check that what they wrote
// matches the bytes it names. See bot/lib/phase3.mjs for what that leaves out.
//
//   node bot/run-checks.mjs --plugin dice-roller
//   node bot/run-checks.mjs --plugin dice-roller --version 0.1.1
//   node bot/run-checks.mjs --plugin fixture --bundle-dir ./assets --offline
//
// Flags: --registry-dir DIR (judge another tree), --allow-staging (tolerate the
// bootstrap listing) and --allow-direct (tolerate a non-GitHub artifact origin),
// both with the same meaning and the same danger as in tools/validate.mjs.
//
// It prints the comment it would post, in markdown, and exits 1 if any check
// failed. Read bot/README.md before extending it — in particular the list of
// what this file deliberately does NOT prove.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import { runValidation } from "../tools/validate.mjs";
import { loadSources, loadPolicy, REPO_ROOT } from "../tools/lib/sources.mjs";
import { checkBundle, manifestDigest, manifestBytesFromLocalHeader } from "./lib/bundle.mjs";
import { fetchRelease, downloadAsset } from "./lib/github.mjs";
import { PHASE_3_CHECKS } from "./lib/phase3.mjs";

class Findings {
  constructor() {
    this.items = [];
  }
  add(level, code, where, message) {
    this.items.push({ level, code, where, message });
  }
  error(code, where, message) { this.add("error", code, where, message); }
  warn(code, where, message) { this.add("warn", code, where, message); }
  skip(code, where, message) { this.add("skip", code, where, message); }
  pass(code, where, message) { this.add("pass", code, where, message); }
  get errors() { return this.items.filter((i) => i.level === "error"); }
}

function parseArgs(argv) {
  const opts = { plugin: null, version: null, offline: false, bundleDir: null, root: REPO_ROOT, allowStaging: false, allowDirect: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--plugin") opts.plugin = argv[++i];
    else if (a === "--version") opts.version = argv[++i];
    else if (a === "--offline") opts.offline = true;
    else if (a === "--bundle-dir") opts.bundleDir = path.resolve(argv[++i]);
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--allow-staging") opts.allowStaging = true;
    else if (a === "--allow-direct") opts.allowDirect = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  if (!opts.plugin) throw new Error("--plugin <id> is required");
  return opts;
}

async function main(argv) {
  const opts = parseArgs(argv);
  const f = new Findings();
  const policy = loadPolicy(REPO_ROOT);
  const { plugins } = loadSources(opts.root);
  const plugin = plugins.find((p) => p.dir === opts.plugin || p.doc?.id === opts.plugin);
  if (!plugin) {
    console.error(`no listing at plugins/${opts.plugin}/`);
    return 2;
  }

  // ── 1. the listing itself ────────────────────────────────────────────────
  // Delegated whole to tools/validate.mjs rather than reimplemented: the bot
  // and CI must not be able to disagree about what a valid listing is, and the
  // only way to guarantee that is for there to be one implementation. Schema,
  // id safety, reserved names, squatting, license allowlist, size caps and the
  // URL-under-the-declared-release rule all land here.
  const { report } = await runValidation({
    root: opts.root, allowStaging: opts.allowStaging, allowDirect: opts.allowDirect,
    online: false, artifactsDir: null, index: false,
  });
  const prefix = `plugins/${plugin.dir}/`;
  const mine = report.items.filter((i) => i.where.startsWith(prefix) || i.where.startsWith("plugins/ "));
  for (const i of mine) {
    f.add(i.level === "error" ? "error" : "warn", "E_LISTING", i.where, i.message);
  }
  if (mine.length === 0) f.pass("E_LISTING", plugin.file, "listing is schema-clean, the id is safe, the license is allowed");

  // ── 2. the artifacts ─────────────────────────────────────────────────────
  const versions = plugin.versions.filter((v) => !opts.version || v.doc?.version === opts.version);
  if (versions.length === 0) {
    console.error(`plugins/${plugin.dir}/versions/${opts.version}.json does not exist`);
    return 2;
  }

  for (const v of versions) {
    const doc = v.doc;
    const releaseCache = new Map();
    for (const [key, art] of Object.entries(doc.artifacts ?? {})) {
      const where = `${v.file} artifacts.${key}`;

      // A staging entry has no release and no digest. Under --allow-staging the
      // listing checks already said so, loudly; there is nothing here to fetch,
      // and pretending otherwise would fill the report with 404s that mean
      // "the bootstrap entry is still the bootstrap entry".
      if (doc.staging === true && opts.allowStaging) {
        f.skip("E_ASSET_MISSING", where, `staging (${doc.staging_reason ?? "no reason given"}): there are no bytes to check`);
        continue;
      }

      let bytes = null;
      if (opts.bundleDir) {
        const file = path.join(opts.bundleDir, art.filename);
        if (fs.existsSync(file)) {
          bytes = fs.readFileSync(file);
          f.pass("E_ASSET_MISSING", where, `read ${art.filename} from ${opts.bundleDir}`);
        } else {
          f.error("E_ASSET_MISSING", where, `${art.filename} is not in ${opts.bundleDir}`);
          continue;
        }
      } else if (opts.offline) {
        f.skip("E_ASSET_MISSING", where, "offline: cannot confirm the release asset exists");
        f.skip("E_DIGEST_MISMATCH", where, "offline: cannot hash the artifact");
        f.skip("E_BUNDLE", where, "offline: cannot inspect the bundle");
        continue;
      } else if (doc.release?.kind === "direct") {
        // No release API to ask, by construction: a direct release is bytes at a
        // URL. Everything downstream — the digest, the size cap, the bundle
        // structure — still runs on the real bytes; only the "does the named
        // release carry an asset by this name" question has no counterpart, and
        // it is skipped by name rather than faked into a pass.
        f.skip("E_ASSET_MISSING", where,
          `release.kind is direct: there is no release to list assets of, fetching ${art.url} instead`);
        try {
          bytes = await downloadAsset(art.url, policy.limits.max_artifact_bytes);
        } catch (e) {
          f.error("E_ASSET_MISSING", where, e.message);
          continue;
        }
      } else {
        const cacheKey = `${doc.release.repo}@${doc.release.tag}`;
        try {
          if (!releaseCache.has(cacheKey)) releaseCache.set(cacheKey, await fetchRelease(doc.release.repo, doc.release.tag));
          const release = releaseCache.get(cacheKey);
          const asset = release.assets.find((a) => a.name === art.filename);
          if (!asset) {
            f.error("E_ASSET_MISSING", where,
              `the release has no asset named ${art.filename} (it has: ${release.assets.map((a) => a.name).join(", ") || "nothing"})`);
            continue;
          }
          if (art.size !== undefined && asset.size !== art.size) {
            f.error("E_ASSET_SIZE", where, `the release asset is ${asset.size} bytes, the listing says ${art.size}`);
          }
          f.pass("E_ASSET_MISSING", where, `release asset ${art.filename} exists`);
          bytes = await downloadAsset(art.url, policy.limits.max_artifact_bytes);
        } catch (e) {
          f.error("E_ASSET_MISSING", where, e.message);
          continue;
        }
      }

      const actual = crypto.createHash("sha256").update(bytes).digest("hex");
      if (art.sha256 === undefined) {
        f.error("E_DIGEST_MISSING", where, `the listing pins no digest; these bytes hash to ${actual}`);
      } else if (actual !== art.sha256) {
        f.error("E_DIGEST_MISMATCH", where, `the listing says ${art.sha256}, the bytes hash to ${actual}`);
      } else {
        f.pass("E_DIGEST_MISMATCH", where, `sha256 matches (${actual.slice(0, 16)}…)`);
      }
      if (art.size !== undefined && bytes.length !== art.size) {
        f.error("E_ASSET_SIZE", where, `the listing says ${art.size} bytes, the artifact is ${bytes.length}`);
      }
      if (bytes.length > policy.limits.max_artifact_bytes) {
        f.error("E_ARTIFACT_TOO_LARGE", where,
          `${bytes.length} bytes, over policy/limits.json max_artifact_bytes (${policy.limits.max_artifact_bytes})`);
      }

      const bundleFindings = checkBundle(bytes, { id: doc.id, version: doc.version, platformKey: key }, policy.limits);
      for (const b of bundleFindings) f.add(b.level, b.code, where, b.message);
      if (bundleFindings.every((b) => b.level !== "error")) {
        // The manifest digest is printed, not compared: no listing field carries
        // it yet. It is here because it is the value Phase 3's countersignature
        // binds, and a reviewer can hold this line next to `astra-plugin verify`
        // and the daemon's own reading and see three programs agree today —
        // before anything starts depending on them agreeing.
        let digestNote = "";
        try {
          digestNote = `; manifest digest ${manifestDigest(manifestBytesFromLocalHeader(bytes)).slice(0, 16)}…`;
        } catch { /* the structure findings above already say why it is unreadable */ }
        f.pass("E_BUNDLE", where,
          "bundle structure is sound: MANIFEST.json first and stored, file table exhaustive both ways, " +
          `no symlinks, entry command jailed${digestNote}`);
      }
    }
  }

  // ── 3. what this run did not check ───────────────────────────────────────
  for (const c of PHASE_3_CHECKS) f.skip(c.code, "—", `${c.name}: ${c.why}`);

  // ── report ───────────────────────────────────────────────────────────────
  // `note` is validate.mjs's "this check could not run" level. Today the only
  // note is about policy/limits.json, which the per-plugin filter above drops —
  // but a missing glyph renders as `undefined` in the report table, so the map
  // covers every level the Report class can produce rather than every level it
  // happens to produce right now.
  const glyph = { error: "❌", warn: "⚠️", pass: "✅", skip: "⏭️", note: "ℹ️" };
  const lines = [
    `## Registry checks — \`${plugin.doc.id}\`${opts.version ? ` @ ${opts.version}` : ""}`,
    "",
    "| | check | where | detail |",
    "|---|---|---|---|",
  ];
  for (const i of f.items) {
    lines.push(`| ${glyph[i.level]} | \`${i.code}\` | ${i.where} | ${i.message.replace(/\|/g, "\\|")} |`);
  }
  lines.push("");
  lines.push(
    f.errors.length === 0
      ? "**No blocking findings.** This report says the listing describes the artifacts it points at. It does **not** say who built them: provenance, ownership and the workflow allowlist live on the release path (`bot/ingest.mjs`), and the ⏭️ rows below name what nobody checked here. On this path the reviewer is the control."
      : `**${f.errors.length} blocking finding(s).** Nothing is listed until they are resolved.`,
  );
  console.log(lines.join("\n"));
  return f.errors.length === 0 ? 0 : 1;
}

main(process.argv.slice(2))
  .then((c) => process.exit(c))
  .catch((e) => {
    console.error(`bot: ${e.message}`);
    process.exit(2);
  });
