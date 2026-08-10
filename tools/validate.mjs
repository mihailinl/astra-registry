#!/usr/bin/env node
// Validates the registry. Offline by default, on purpose.
//
//   node tools/validate.mjs                        sources + index, no network
//   node tools/validate.mjs --allow-staging        tolerate digest-free entries
//   node tools/validate.mjs --allow-direct         tolerate non-GitHub origins
//   node tools/validate.mjs --artifacts DIR        also hash local bundles
//   node tools/validate.mjs --online               also fetch and hash artifacts
//   node tools/validate.mjs --registry-dir DIR     validate some other tree
//   node tools/validate.mjs --no-index             skip registry/v1/index.json
//
// WHY OFFLINE IS THE DEFAULT: this is the last gate before a listing reaches a
// stranger's machine, so it has to be a gate that always runs. A check that
// needs the network is a check that gets skipped the first time GitHub is slow,
// and then quietly forever. Everything structural — ids, paths, schemas, URL
// shape, license, sizes, the index being a faithful generation — is decided
// from files alone. Only "do these bytes hash to what the listing claims"
// genuinely needs the artifact, and there are two ways to give it one:
// --artifacts DIR (what the bot uses after it downloads) and --online.
//
// EXIT CODES: 0 clean (warnings allowed), 1 at least one error, 2 the tool
// itself could not run (bad arguments, unreadable schema).

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import { validate as validateSchema } from "./lib/jsonschema.mjs";
import { stableStringify } from "./lib/canonical.mjs";
import { compareSemver, parseSemver } from "./lib/semver.mjs";
import { invalidId, unsafePathComponent, foldId, editDistance, unsafeDisplayText } from "./lib/ids.mjs";
import { loadSources, loadPolicy, loadSchemas, readJson, REPO_ROOT } from "./lib/sources.mjs";
import { buildIndex } from "./build-index.mjs";

const PLATFORM_KEYS = new Set([
  "linux-x64", "windows-x64", "noarch",
  "linux-arm64", "windows-arm64", "macos-x64", "macos-arm64",
]);
// Reserved names, listed in the schema so the vocabulary is fixed, but not
// emitted and not accepted: Astra's release workflow ships no daemon for these
// hosts, so an artifact under one of them would have nowhere to run.
const UNSUPPORTED_KEYS = new Set(["linux-arm64", "windows-arm64", "macos-x64", "macos-arm64"]);

class Report {
  constructor() {
    this.items = [];
  }
  error(where, message, hint) {
    this.items.push({ level: "error", where, message, hint });
  }
  warn(where, message, hint) {
    this.items.push({ level: "warn", where, message, hint });
  }
  /**
   * Something a reader needs to know that is not a defect in this tree — most
   * importantly a check that COULD NOT RUN. Notes never fail the run, and they
   * are printed rather than swallowed, because a check that quietly did not
   * happen is indistinguishable from a check that passed.
   */
  note(where, message, hint) {
    this.items.push({ level: "note", where, message, hint });
  }
  get errors() {
    return this.items.filter((i) => i.level === "error");
  }
  get warnings() {
    return this.items.filter((i) => i.level === "warn");
  }
  get notes() {
    return this.items.filter((i) => i.level === "note");
  }
  print() {
    const tags = { error: "ERROR", warn: "warn ", note: "note " };
    for (const i of this.items) {
      console.error(`${tags[i.level]} ${i.where}: ${i.message}`);
      if (i.hint) console.error(`      -> ${i.hint}`);
    }
  }
}

function sha256File(file) {
  const h = crypto.createHash("sha256");
  h.update(fs.readFileSync(file));
  return h.digest("hex");
}

// ── source-tree checks ──────────────────────────────────────────────────────

function checkPluginDoc(plugin, ctx) {
  const { report, schemas, policy } = ctx;
  const where = plugin.file;

  for (const e of validateSchema(schemas.plugin, plugin.doc)) {
    report.error(where, `${e.path} ${e.message}`);
  }

  const id = plugin.doc.id;

  // The check the acceptance test names: an id is a path component before it is
  // a label. `<plugins_dir>/<id>` is joined and remove_dir_all'd by the daemon.
  const unsafe = unsafePathComponent(id);
  if (unsafe) {
    report.error(where, `id ${JSON.stringify(id)} is not a safe path component: ${unsafe}`,
      "The daemon joins this onto its plugins directory. It never leaves the registry.");
    return;
  }
  const bad = invalidId(id);
  if (bad) {
    report.error(where, `id ${JSON.stringify(id)} ${bad}`);
    return;
  }
  if (id !== plugin.dir) {
    report.error(where, `id ${JSON.stringify(id)} does not match its directory plugins/${plugin.dir}`,
      "The directory name is what `git log plugins/<id>/` audits. They must be the same string.");
  }

  if (policy.reserved.reserved.includes(id)) {
    report.error(where, `id ${JSON.stringify(id)} is reserved`, "See policy/reserved-ids.json.");
  }
  for (const prefix of policy.reserved.reserved_prefixes) {
    if (id.startsWith(prefix) && !policy.reserved.first_party_repos.includes(plugin.doc.source?.repo)) {
      report.error(where, `id ${JSON.stringify(id)} uses the reserved prefix "${prefix}"`,
        "Prefixes that read as first-party are an impersonation primitive. See policy/reserved-ids.json.");
    }
  }

  const license = plugin.doc.license;
  if (license !== undefined &&
      !policy.spdx.allowed.includes(license) &&
      !policy.spdx.allowed_expressions.includes(license)) {
    report.error(where, `license ${JSON.stringify(license)} is not on the SPDX allowlist`,
      "Add it to policy/spdx-allowlist.json in its own PR, with a sentence on why.");
  }

  for (const [field, value] of Object.entries({
    name: plugin.doc.name,
    summary: plugin.doc.summary,
    author: plugin.doc.author?.name,
  })) {
    if (typeof value !== "string") continue;
    const trick = unsafeDisplayText(value);
    if (trick) {
      report.error(where, `${field} ${trick}`,
        "Metadata is rendered in Astra's store. Invisible characters there are a spoofing tool.");
    }
    if (value.trim() !== value) report.warn(where, `${field} has leading or trailing whitespace`);
  }
}

/**
 * The one prefix every artifact URL of this release must start with — the rule
 * that binds listed bytes to a named origin rather than to the registry's
 * say-so. Derived from `release` once per version file, then applied to every
 * artifact, so the two kinds differ in exactly one string and nowhere else.
 *
 *   github_release  https://github.com/<repo>/releases/download/<tag>/
 *   direct          release.base_url
 *
 * Returns null when the release object is too broken to imply a prefix; the
 * schema has already said why, and inventing a prefix out of `undefined` would
 * bury that under a second, misleading error.
 */
function artifactUrlPrefix(doc, where, report) {
  const rel = doc.release;
  if (!rel || typeof rel !== "object") return null;

  if (rel.kind === "github_release") {
    if (rel.base_url !== undefined) {
      report.error(where, "release.base_url is set on a github_release",
        "base_url anchors a `direct` release. On a GitHub release the prefix is derived from repo and tag, " +
        "and a second, disagreeing anchor is exactly the ambiguity this check exists to prevent.");
    }
    if (typeof rel.repo !== "string" || typeof rel.tag !== "string") return null;
    return `https://github.com/${rel.repo}/releases/download/${rel.tag}/`;
  }

  if (rel.kind === "direct") {
    for (const field of ["repo", "tag", "commit"]) {
      if (rel[field] !== undefined) {
        report.error(where, `release.${field} is set on a \`direct\` release`,
          "A direct release is bytes at a URL; it is not a GitHub release. Naming a repo and tag next to a URL " +
          "that does not come from them reads as provenance the entry does not have. Drop it, or use kind github_release.");
      }
    }
    if (typeof rel.base_url !== "string") {
      report.error(where, "release.kind is `direct` but there is no release.base_url",
        "A direct release is anchored by the prefix its artifacts must sit under. Without one there is nothing " +
        "to pin the URLs to, and the listing could point anywhere on the next edit.");
      return null;
    }
    if (!rel.base_url.endsWith("/")) {
      report.error(where, `release.base_url ${JSON.stringify(rel.base_url)} does not end in "/"`,
        "It is a prefix, and a prefix that does not end at a path boundary makes " +
        "https://host/plugins-evil/x a URL that \"sits under\" https://host/plugins.");
      return null;
    }
    return rel.base_url;
  }

  return null; // an unknown kind; the schema named it already
}

/**
 * True when the URL's path has a `..` segment, encoded or not.
 *
 * Read off the RAW string, deliberately: `new URL()` resolves `..` while
 * parsing, so asking the parsed object would answer about the destination
 * rather than about what the listing says — and what the listing says is
 * precisely what the release-prefix check compares against.
 */
function climbsOutOfItsPath(url) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*(\/[^?#]*)?/i.exec(url);
  if (!m) return false; // not a URL at all; the schema pattern says so already
  let p = m[1] ?? "";
  try {
    p = decodeURIComponent(p);
  } catch { /* a lone % is not a traversal; judge what is there */ }
  return p.split("/").includes("..");
}

function checkVersionDoc(plugin, version, ctx) {
  const { report, schemas, policy, allowStaging, allowDirect } = ctx;
  const where = version.file;
  const doc = version.doc;

  for (const e of validateSchema(schemas.version, doc)) {
    report.error(where, `${e.path} ${e.message}`);
  }
  if (typeof doc.version !== "string" || !parseSemver(doc.version)) return;

  if (doc.version !== version.basename) {
    report.error(where, `declares version ${JSON.stringify(doc.version)} but the file is named ${version.basename}.json`,
      "One file per version, named after it — that is what makes a release a new file instead of an edit.");
  }
  if (doc.id !== plugin.doc.id) {
    report.error(where, `id ${JSON.stringify(doc.id)} does not match plugins/${plugin.dir}/plugin.json (${JSON.stringify(plugin.doc.id)})`);
  }
  if (doc.release?.repo && plugin.doc.source?.repo && doc.release.repo !== plugin.doc.source.repo) {
    report.error(where, `release.repo ${JSON.stringify(doc.release.repo)} is not the listing's source repo ${JSON.stringify(plugin.doc.source.repo)}`,
      "The identity a user pins at install is the source repo. A release from anywhere else is a different author.");
  }

  // A `direct` release is expressible on purpose — a self-hosted or staging
  // catalogue serves its artifacts from its own origin, and Astra's daemon
  // supports exactly that (PluginManager::artifact_download_policy allows the
  // host the index itself named). What it does not carry is a named GitHub
  // release: no build to attest in Phase 3, no assets endpoint for the bot to
  // read, nothing but a URL and a digest. So it is expressible, and it is not
  // acceptable in THIS catalogue without someone typing the flag — the same
  // bargain as --allow-staging, for the same reason.
  const prefix = artifactUrlPrefix(doc, where, report);
  if (doc.release?.kind === "direct") {
    if (!allowDirect) {
      report.error(where, "release.kind is `direct`: these bytes are pinned by digest but not to any named release",
        "Pass --allow-direct when validating a self-hosted or staging catalogue. The public registry lists " +
        "github_release only, because that is the only kind whose provenance a third party can re-derive.");
    } else {
      report.warn(where, `accepted as a direct release (--allow-direct): artifacts come from ${doc.release.base_url}`);
    }
  }

  const staging = doc.staging === true;
  if (staging) {
    if (!allowStaging) {
      report.error(where, "is a STAGING entry: it has no artifact digest, so nothing can verify what a user would download",
        "Pass --allow-staging if you deliberately want to accept an unverifiable bootstrap listing. Never pass it on a registry users fetch.");
    } else {
      report.warn(where, `accepted as staging (--allow-staging): ${doc.staging_reason ?? "no reason given"}`);
    }
    if (!doc.staging_reason) {
      report.error(where, "is staging but gives no staging_reason", "Say in the file why there is no digest.");
    }
  }

  const artifacts = Object.entries(doc.artifacts ?? {});
  if (artifacts.length === 0) {
    report.error(where, "lists no artifacts");
  }
  if (artifacts.some(([k]) => k === "noarch") && artifacts.length > 1) {
    report.error(where, "mixes `noarch` with per-platform artifacts",
      "`noarch` means one file serves every host. If two files differ, they are not noarch.");
  }

  const seenUrls = new Map();
  for (const [key, art] of artifacts) {
    const at = `${where} artifacts.${key}`;
    if (!PLATFORM_KEYS.has(key)) {
      report.error(at, `${JSON.stringify(key)} is not a platform key`,
        `Known keys: ${[...PLATFORM_KEYS].join(", ")}. These are byte-identical to the CLI's --target strings.`);
      continue;
    }
    if (UNSUPPORTED_KEYS.has(key)) {
      report.error(at, `${JSON.stringify(key)} is a reserved key with no host`,
        "Astra ships no daemon for that platform, so the artifact could never run. The name is reserved, not usable.");
    }

    // Bind the bytes to the origin the listing named, not to the registry's
    // say-so. For a github_release the daemon re-derives this same URL prefix at
    // install time (PRODUCTION_PLAN §5.3 A.6); if the registry and the daemon
    // disagree here, the install fails on the user's machine, so the
    // disagreement has to be caught in CI instead. For a `direct` release the
    // anchor is base_url and the rule is identical — which is the point of
    // deriving the prefix from the release object instead of hardcoding one.
    if (prefix !== null && typeof art.url === "string" && !art.url.startsWith(prefix)) {
      report.error(at, `url does not sit under the declared release`,
        `expected it to start with ${prefix}`);
    }
    // `startsWith` is a string test, and a path can climb back out of the prefix
    // it starts with: `<prefix>/../../elsewhere/x.astraplugin` passes the test
    // above and then resolves somewhere else entirely, because the client
    // normalises the path and the validator did not. Percent-encoded segments
    // are decoded once before looking, since `%2e%2e` reaches many servers
    // undecoded and comes back out as `..`.
    if (typeof art.url === "string" && climbsOutOfItsPath(art.url)) {
      report.error(at, "url contains a `..` path segment",
        "It would resolve outside the prefix it appears to sit under, which makes the release-prefix check " +
        "above meaningless. A release asset never needs one.");
    }
    if (typeof art.url === "string" && typeof art.filename === "string" &&
        !art.url.endsWith(`/${art.filename}`)) {
      report.error(at, `url does not end in the declared filename ${JSON.stringify(art.filename)}`);
    }
    // The filename convention, checked exactly rather than approximately.
    //
    // `<id>-<version>-<target>.astraplugin` is not a nicety: it is the one
    // string that ties a release asset back to the listing that claims it.
    // AstraPlugins' astra-plugin-cli derives it in `Manifest::artifact_name`,
    // reports it as `expected_name` from `astra-plugin verify --json`, and
    // plugin-release.yml fails the build when the file it just packed is named
    // anything else. So by the time a URL reaches this validator the name is
    // already decided upstream, and anything else means the listing is pointing
    // at an asset this pipeline did not produce.
    //
    // This used to be a warning that only asked whether the target key appeared
    // ANYWHERE in the name. That accepts `dice-roller-0.1.0-linux-x64.astraplugin`
    // under a 0.1.1 listing — a stale asset from the previous release, which is
    // the single most likely way a wrong-but-plausible file gets served, and the
    // digest check cannot catch it because the digest is copied from whatever
    // file was uploaded.
    if (typeof art.filename === "string") {
      const expected = `${doc.id}-${doc.version}-${key}.astraplugin`;
      if (art.filename !== expected) {
        report.error(at, `filename is ${JSON.stringify(art.filename)}, expected ${JSON.stringify(expected)}`,
          "The CLI names bundles <id>-<version>-<target>.astraplugin and the release workflow asserts it. " +
          "A different name means this listing points at an asset the pipeline did not produce — most often " +
          "a stale bundle from an earlier version, or one build leg's file listed under another leg's key.");
      }
    }
    if (typeof art.url === "string") {
      const prev = seenUrls.get(art.url);
      if (prev && prev !== "noarch") {
        report.error(at, `serves the same URL as artifacts.${prev}`,
          "Two platform keys pointing at one file is either a `noarch` bundle mislabelled, or a build leg that uploaded the wrong asset.");
      }
      seenUrls.set(art.url, key);
    }

    if (art.sha256 === undefined || art.size === undefined) {
      if (!staging) {
        report.error(at, "has no sha256/size",
          "Every listed artifact is pinned by digest. Only a `staging: true` entry may omit them, and only behind --allow-staging.");
      }
    } else if (staging) {
      report.error(at, "carries a digest but the entry is marked staging",
        "Drop `staging`/`staging_reason` — an entry with a digest is a real listing.");
    }
    if (typeof art.size === "number" && art.size > policy.limits.max_artifact_bytes) {
      report.error(at, `size ${art.size} exceeds the listing cap of ${policy.limits.max_artifact_bytes} bytes`,
        "See policy/limits.json max_artifact_bytes.");
    }
  }
}

function checkPluginVersions(plugin, ctx) {
  const { report, policy } = ctx;
  const listed = plugin.versions.filter((v) => v.doc?.yanked !== true);
  if (plugin.versions.length === 0) {
    report.error(`plugins/${plugin.dir}/versions/`, "contains no version files");
  } else if (listed.length === 0 && plugin.doc.unlisted !== true) {
    report.error(`plugins/${plugin.dir}/versions/`, "every version is yanked, but the plugin is still listed",
      "Set `\"unlisted\": true` in plugin.json to retire it while keeping the audit trail.");
  }
  if (plugin.versions.length > policy.limits.max_versions_per_plugin) {
    report.error(`plugins/${plugin.dir}/versions/`,
      `${plugin.versions.length} versions exceeds the cap of ${policy.limits.max_versions_per_plugin}`);
  }
  const seen = new Set();
  for (const v of plugin.versions) {
    const key = v.doc?.version;
    if (typeof key !== "string") continue;
    if (seen.has(key)) {
      report.error(v.file, `version ${key} is listed twice`);
    }
    seen.add(key);
  }
}

function checkSquatting(plugins, ctx) {
  const { report, policy } = ctx;
  const folded = new Map();
  for (const p of plugins) {
    const id = p.doc?.id;
    if (typeof id !== "string") continue;
    const f = foldId(id);
    const prev = folded.get(f);
    if (prev && prev !== id) {
      report.error(p.file, `id ${JSON.stringify(id)} is indistinguishable from ${JSON.stringify(prev)} after confusable folding`,
        "Two listings that look identical in a store card cannot both exist. See POLICY.md §Names.");
    } else {
      folded.set(f, id);
    }
  }
  const ids = [...folded.values()].sort();
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const d = editDistance(foldId(ids[i]), foldId(ids[j]));
      if (d > 0 && d <= policy.limits.typosquat_flag_distance) {
        report.warn("plugins/", `${JSON.stringify(ids[i])} and ${JSON.stringify(ids[j])} differ by ${d} character(s)`,
          "Not a rejection — a human decides. POLICY.md §Names says plainly that this heuristic catches accidents, not a determined attacker.");
      }
    }
  }
}

// ── artifact digest checks ──────────────────────────────────────────────────

function eachArtifact(plugins) {
  const out = [];
  for (const p of plugins) {
    for (const v of p.versions) {
      for (const [key, art] of Object.entries(v.doc?.artifacts ?? {})) {
        out.push({ plugin: p, version: v, key, art });
      }
    }
  }
  return out;
}

function checkLocalArtifacts(plugins, ctx) {
  const { report, artifactsDir } = ctx;
  let checked = 0;
  for (const { version, key, art } of eachArtifact(plugins)) {
    if (typeof art.filename !== "string") continue;
    const file = path.join(artifactsDir, art.filename);
    const at = `${version.file} artifacts.${key}`;
    if (!fs.existsSync(file)) {
      if (version.doc.staging === true) continue;
      report.error(at, `${art.filename} is not in ${artifactsDir}`,
        "--artifacts checks digests against local files; every non-staging artifact must be there.");
      continue;
    }
    const actualSize = fs.statSync(file).size;
    const actual = sha256File(file);
    if (art.sha256 === undefined) {
      report.error(at, `has no sha256, but ${art.filename} exists and hashes to ${actual}`,
        "The artifact is real. Pin it: put that digest in the listing and drop `staging`.");
      continue;
    }
    checked++;
    if (actual !== art.sha256) {
      report.error(at, `DIGEST MISMATCH — listing says ${art.sha256}, ${art.filename} hashes to ${actual}`,
        "The listing does not describe these bytes. Do not publish; find out which side changed.");
    }
    if (art.size !== undefined && art.size !== actualSize) {
      report.error(at, `size mismatch — listing says ${art.size}, ${art.filename} is ${actualSize} bytes`);
    }
  }
  return checked;
}

async function checkOnlineArtifacts(plugins, ctx) {
  const { report, policy } = ctx;
  let checked = 0;
  for (const { version, key, art } of eachArtifact(plugins)) {
    const at = `${version.file} artifacts.${key}`;
    if (version.doc.staging === true) {
      report.warn(at, "skipped: staging entries have no artifact to fetch");
      continue;
    }
    if (typeof art.url !== "string") continue;
    let res;
    try {
      res = await fetch(art.url, { redirect: "follow" });
    } catch (e) {
      report.error(at, `could not fetch ${art.url}: ${e.message}`);
      continue;
    }
    if (!res.ok) {
      report.error(at, `release asset is missing: HTTP ${res.status} for ${art.url}`,
        "A listing whose artifact does not exist is worse than no listing: the store offers an install that cannot work.");
      continue;
    }
    const bytes = Buffer.from(await res.arrayBuffer());
    if (bytes.length > policy.limits.max_artifact_bytes) {
      report.error(at, `downloaded ${bytes.length} bytes, over the cap of ${policy.limits.max_artifact_bytes}`);
    }
    const actual = crypto.createHash("sha256").update(bytes).digest("hex");
    checked++;
    if (actual !== art.sha256) {
      report.error(at, `DIGEST MISMATCH — listing says ${art.sha256}, the asset hashes to ${actual}`);
    }
    if (art.size !== undefined && art.size !== bytes.length) {
      report.error(at, `size mismatch — listing says ${art.size}, the asset is ${bytes.length} bytes`);
    }
  }
  return checked;
}

// ── index checks ────────────────────────────────────────────────────────────

function checkIndex(ctx) {
  const { report, schemas, root } = ctx;
  const file = path.join(root, "registry", "v1", "index.json");
  const rel = "registry/v1/index.json";
  if (!fs.existsSync(file)) {
    report.error(rel, "does not exist", "Run: node tools/build-index.mjs");
    return;
  }
  let text;
  let doc;
  try {
    text = fs.readFileSync(file, "utf8");
    doc = JSON.parse(text);
  } catch (e) {
    report.error(rel, `is not valid JSON: ${e.message}`);
    return;
  }

  for (const e of validateSchema(schemas.index, doc)) {
    report.error(rel, `${e.path} ${e.message}`);
  }

  let regenerated;
  try {
    regenerated = stableStringify(buildIndex({ root, serial: doc.serial }));
  } catch (e) {
    report.error(rel, `cannot be regenerated from plugins/: ${e.message}`);
    return;
  }
  if (regenerated !== text) {
    report.error(rel, "is not byte-identical to a fresh generation from plugins/",
      "It is a generated file. Run `node tools/build-index.mjs` and commit the result; do not edit it.");
  }

  // Ordering is a property the daemon may lean on and a reviewer definitely
  // does, so assert it rather than trusting the generator that just ran.
  const ids = doc.plugins?.map((p) => p.id) ?? [];
  if ([...ids].sort().join("\u0000") !== ids.join("\u0000")) {
    report.error(rel, "plugins are not sorted by id");
  }
  for (const p of doc.plugins ?? []) {
    const versions = p.releases.map((r) => r.version);
    for (let i = 1; i < versions.length; i++) {
      if (compareSemver(versions[i - 1], versions[i]) <= 0) {
        report.error(rel, `${p.id}: releases are not newest-first (${versions[i - 1]} before ${versions[i]})`);
      }
    }
    if (p.version !== versions[0]) {
      report.error(rel, `${p.id}: flat \`version\` (${p.version}) is not releases[0].version (${versions[0]})`);
    }
    const latest = p.releases[0];
    const digested = Object.values(latest.artifacts).every((a) => a.sha256 && a.size);
    if (!digested && Object.keys(p.platform_downloads).length > 0) {
      report.error(rel, `${p.id}: offers platform_downloads for a release with no digest`,
        "A client reading only the flat fields would download bytes nothing can verify.");
    }
    if (latest.staging === true && p.staging !== true) {
      report.error(rel, `${p.id}: latest release is staging but the entry is not marked staging`);
    }
  }
}

// ── the mirrored limits ─────────────────────────────────────────────────────

/**
 * The `*_mirrors` entries in policy/limits.json name constants that live in
 * AstraPlugins/spec/limits.yaml. Two repositories holding the same number is a
 * standing invitation for one of them to change, and the failure is silent and
 * bad in both directions: too high here and the registry lists a bundle the
 * daemon will refuse to extract; too low and it rejects one that installs fine.
 *
 * So when an AstraPlugins checkout is reachable, the numbers are compared for
 * real. When it is not, that is reported as a note — never passed over in
 * silence, because "the check did not run" and "the check passed" are the two
 * things a mirror check must never confuse.
 *
 * Located by `$ASTRA_PLUGINS_DIR`, else the usual sibling checkout.
 */
export function checkMirroredLimits(ctx) {
  const where = "policy/limits.json";
  const mirrors = Object.entries(ctx.policy.limits ?? ctx.policy)
    .filter(([k]) => k.endsWith("_mirrors"))
    .map(([k, v]) => [k.slice(0, -"_mirrors".length), String(v)]);
  if (mirrors.length === 0) return;

  const candidates = [
    process.env.ASTRA_PLUGINS_DIR,
    path.resolve(REPO_ROOT, "../AstraPlugins"),
  ].filter(Boolean);
  const specFile = candidates
    .map((d) => path.join(d, "spec/limits.yaml"))
    .find((f) => fs.existsSync(f));

  if (!specFile) {
    ctx.report.note(where, `${mirrors.length} mirrored limit(s) NOT verified: no AstraPlugins checkout found`,
      `Looked in ${candidates.join(", ")}. Set ASTRA_PLUGINS_DIR to check them. ` +
      "These numbers must equal the constants named in their `_mirrors` fields.");
    return;
  }

  // A deliberately tiny reader for the one shape these keys have:
  // `name: 123_456` at column zero. Anything else is not parsed and not
  // guessed at — an unreadable value is reported, not defaulted.
  const text = fs.readFileSync(specFile, "utf8");
  const spec = new Map();
  for (const line of text.split("\n")) {
    const m = /^([a-z0-9_]+):\s*([0-9_]+)\s*(#.*)?$/.exec(line);
    if (m) spec.set(m[1], Number(m[2].replace(/_/g, "")));
  }

  for (const [key, source] of mirrors) {
    const name = source.split(/\s+/).pop();
    const ours = (ctx.policy.limits ?? ctx.policy)[key];
    if (!spec.has(name)) {
      ctx.report.error(where, `${key} claims to mirror ${JSON.stringify(source)}, which is not in ${specFile}`,
        "Either the constant was renamed upstream or the `_mirrors` string is wrong. Both are drift.");
      continue;
    }
    const theirs = spec.get(name);
    if (ours !== theirs) {
      ctx.report.error(where, `${key} is ${ours} but ${name} in spec/limits.yaml is ${theirs}`,
        "A registry cap above the daemon's lists bundles that cannot install; one below it rejects bundles that would. " +
        "Change spec/limits.yaml first, then mirror it here.");
    }
  }
}

// ── driver ──────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const opts = {
    allowStaging: false, allowDirect: false, online: false, artifactsDir: null,
    root: REPO_ROOT, index: true,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--allow-staging") opts.allowStaging = true;
    else if (a === "--allow-direct") opts.allowDirect = true;
    else if (a === "--online") opts.online = true;
    else if (a === "--artifacts") opts.artifactsDir = path.resolve(argv[++i]);
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--no-index") opts.index = false;
    else if (a === "--help" || a === "-h") opts.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

export async function runValidation(opts) {
  const report = new Report();
  const ctx = {
    report,
    root: opts.root,
    // Schemas and policy always come from THIS repo, never from the tree under
    // test. --registry-dir points at sources to be judged; it does not get to
    // supply the rules it is judged by. (It is also what lets tests/fixtures/
    // hold nothing but the files whose rejection they demonstrate.)
    schemas: loadSchemas(REPO_ROOT),
    policy: loadPolicy(REPO_ROOT),
    allowStaging: opts.allowStaging,
    allowDirect: opts.allowDirect,
    artifactsDir: opts.artifactsDir,
  };

  checkMirroredLimits(ctx);

  const { errors, plugins } = loadSources(opts.root);
  for (const e of errors) report.error(e.file, e.message);

  const usable = plugins.filter((p) => p.doc && typeof p.doc === "object");
  for (const plugin of usable) {
    checkPluginDoc(plugin, ctx);
    checkPluginVersions(plugin, ctx);
    for (const version of plugin.versions) {
      if (version.doc && typeof version.doc === "object") checkVersionDoc(plugin, version, ctx);
    }
  }
  checkSquatting(usable, ctx);

  let hashed = 0;
  if (opts.artifactsDir) hashed += checkLocalArtifacts(usable, ctx);
  if (opts.online) hashed += await checkOnlineArtifacts(usable, ctx);
  if (opts.index) checkIndex(ctx);

  return { report, counts: { plugins: usable.length, hashed } };
}

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    console.error(e.message);
    console.error("usage: node tools/validate.mjs [--allow-staging] [--allow-direct] [--online] [--artifacts DIR] [--registry-dir DIR] [--no-index]");
    return 2;
  }
  if (opts.help) {
    console.log("usage: node tools/validate.mjs [--allow-staging] [--allow-direct] [--online] [--artifacts DIR] [--registry-dir DIR] [--no-index]");
    return 0;
  }

  const { report, counts } = await runValidation(opts);
  report.print();

  const modes = [
    opts.allowStaging ? "staging tolerated" : "staging rejected",
    opts.allowDirect ? "direct releases tolerated" : null,
    opts.artifactsDir ? `local artifacts from ${path.relative(process.cwd(), opts.artifactsDir) || "."}` : null,
    opts.online ? "artifacts fetched" : "offline",
    opts.index ? "index checked" : "index skipped",
  ].filter(Boolean);

  console.log(
    `${report.errors.length === 0 ? "PASS" : "FAIL"}  ${counts.plugins} plugin(s), ` +
    `${counts.hashed} artifact digest(s) verified, ` +
    `${report.errors.length} error(s), ${report.warnings.length} warning(s)` +
    `${report.notes.length ? `, ${report.notes.length} note(s)` : ""}  [${modes.join(", ")}]`,
  );
  return report.errors.length === 0 ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
