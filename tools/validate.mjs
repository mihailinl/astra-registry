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
import { reservedPrefixViolation } from "./lib/reserved.mjs";
import {
  editDistance,
  foldId,
  invalidId,
  scriptsUsed,
  unsafeDisplayText,
  unsafePathComponent,
} from "./lib/ids.mjs";
import { loadSources, loadPolicy, loadSchemas, readJson, REPO_ROOT } from "./lib/sources.mjs";
import { ALLOWED_IMAGE_HOSTS, ICON_NAMES, MAX_README_BYTES, checkIcon } from "../bot/lib/assets.mjs";
import { checkMetadata, summarise } from "../bot/lib/derive.mjs";
import { foldDisplayName, renderedNames } from "../bot/lib/names.mjs";
import {
  CORPUS_NOT_IMPLEMENTED,
  CORPUS_NO_RULE_ID,
  CORPUS_RULE_IDS,
  LOCALE_CODES,
  deriveLocaleText,
  isLanguageExempt,
  isLatinScript,
  latinFraction,
  localeEnumProblems,
} from "../bot/lib/locales.mjs";
import { buildIndex, indexContent } from "./build-index.mjs";

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

/**
 * Every string in a listing that a person reads off a card, with the name it
 * goes by in the document.
 *
 * **This used to be a three-field object literal** — `name`, `summary`,
 * `author?.name` — and the day a listing gained a fourth display string it
 * became a hole rather than a check. That day is this one: `i18n.<code>.name`
 * is a store card's title in another language, and a maintainer who typed one
 * into `plugins/<id>/plugin.json` by hand would have got no display-text scan
 * at all, with CI green because the generator faithfully reproduced whatever
 * the tree said. `bot/lib/assets.mjs`'s own header explains why this
 * second-opinion path exists: the bot sanitises what it derives, and a
 * hand-edited listing has never been near the bot.
 *
 * A walk rather than a list, so the next field of this kind is covered by
 * construction — and it works on an INDEX entry as well as on a source
 * listing, which is how the deploy candidate comes to be scanned as a document
 * rather than trusted because its inputs were.
 *
 * @returns {[string, string][]} `["i18n.ru.name", "…"]`
 */
export function displayStrings(doc) {
  const out = [];
  const take = (field, value) => {
    if (typeof value === "string" && value.length > 0) out.push([field, value]);
  };
  take("name", doc?.name);
  // `summary` is plugin.json's spelling of the card line and `description` is
  // the index's. Both are taken, and whichever is absent costs nothing.
  take("summary", doc?.summary);
  take("description", doc?.description);
  take("author", typeof doc?.author === "string" ? doc.author : doc?.author?.name);
  const i18n = doc?.i18n;
  if (i18n && typeof i18n === "object") {
    for (const code of Object.keys(i18n).sort()) {
      const block = i18n[code];
      if (!block || typeof block !== "object") continue;
      for (const key of Object.keys(block).sort()) take(`i18n.${code}.${key}`, block[key]);
    }
  }
  return out;
}

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
  // The predicate lives in tools/lib/reserved.mjs and `bot/lib/derive.mjs`
  // imports the same one, so what CI refuses in the tree and what the bot
  // refuses at ingest cannot be two answers.
  const prefixHit = reservedPrefixViolation(id, plugin.doc.source?.repo, policy.reserved);
  if (prefixHit) {
    report.error(where, `id ${JSON.stringify(id)} uses the reserved prefix "${prefixHit.prefix}"`,
      "Prefixes that read as first-party are an impersonation primitive. See policy/reserved-ids.json.");
  }

  const license = plugin.doc.license;
  if (license !== undefined &&
      !policy.spdx.allowed.includes(license) &&
      !policy.spdx.allowed_expressions.includes(license)) {
    report.error(where, `license ${JSON.stringify(license)} is not on the SPDX allowlist`,
      "Add it to policy/spdx-allowlist.json in its own PR, with a sentence on why.");
  }

  for (const [field, value] of displayStrings(plugin.doc)) {
    const trick = unsafeDisplayText(value);
    if (trick) {
      report.error(where, `${field} ${trick}`,
        "Metadata is rendered in Astra's store. Invisible characters there are a spoofing tool.");
    }
    if (value.trim() !== value) report.warn(where, `${field} has leading or trailing whitespace`);
  }

  checkPresentationFiles(plugin, ctx);
}

/**
 * The icon and the README, held to the same rules whoever wrote them.
 *
 * `bot/lib/assets.mjs` already sanitises what it derives, so on the ingest path
 * this is a second opinion. It is not redundant: a listing can also be
 * hand-written or hand-edited, and a maintainer dropping a nicer icon into a
 * plugin directory after the fact would otherwise bypass every check the bot
 * makes. The bot's output is validated by this same function
 * (`bot/ingest.mjs` → `validateDerived`), so the two can never disagree about
 * what is allowed.
 */
function checkPresentationFiles(plugin, ctx) {
  const { report } = ctx;
  const where = plugin.file;
  const dir = path.join(ctx.root, "plugins", plugin.dir);

  const icon = plugin.doc.icon;
  if (icon !== undefined) {
    const file = path.join(dir, icon);
    if (!fs.existsSync(file)) {
      report.error(where, `icon ${JSON.stringify(icon)} is named here but the file is not in plugins/${plugin.dir}/`,
        "The bytes are committed beside the listing; the index inlines them at build time.");
    } else {
      for (const f of checkIcon({ name: icon, bytes: fs.readFileSync(file) })) {
        report.error(`plugins/${plugin.dir}/${icon}`, f.message,
          "An icon is rendered before the user has agreed to anything. See bot/lib/assets.mjs.");
      }
    }
  }

  const readme = plugin.doc.readme;
  if (readme !== undefined) {
    const file = path.join(dir, readme);
    if (!fs.existsSync(file)) {
      report.error(where, `readme ${JSON.stringify(readme)} is named here but the file is not in plugins/${plugin.dir}/`);
      return;
    }
    const text = fs.readFileSync(file, "utf8");
    // Bytes, the same unit bot/lib/assets.mjs truncates to and the same unit
    // tools/build-index.mjs refuses on. Three readers of one number, and until
    // this commit all three measured UTF-16 code units instead — which for a
    // Russian or Chinese README is roughly half to a third of the bytes the
    // signed index would actually carry.
    const bytes = Buffer.byteLength(text, "utf8");
    if (bytes > MAX_README_BYTES) {
      report.error(`plugins/${plugin.dir}/${readme}`,
        `${bytes} bytes, over the ${MAX_README_BYTES} the index allows`,
        "Trim it, or let bot/ingest.mjs derive it — that path truncates on a line boundary.");
    }
    // The two properties the renderer is entitled to assume, checked directly
    // rather than by re-deriving: this file may have been hand-edited since the
    // bot wrote it, and what matters is what it says NOW.
    const prose = stripFences(text);
    if (/<\/?[a-zA-Z][^>]*>/.test(prose)) {
      report.error(`plugins/${plugin.dir}/${readme}`, "contains raw HTML outside a code fence",
        "Astra renders this with raw HTML disabled, so the tags would silently vanish. Remove them.");
    }
    for (const m of prose.matchAll(/!\[[^\]]*\]\(\s*<?([^\s)>]+)>?[^)]*\)/g)) {
      const url = m[1];
      let host = null;
      try {
        host = new URL(url).hostname.toLowerCase();
      } catch { /* relative, handled below */ }
      if (host === null) {
        report.error(`plugins/${plugin.dir}/${readme}`, `image ${JSON.stringify(url)} is a relative path`,
          "A stored README is rendered far from the repository it came from. Images must be absolute and pinned to a commit — bot/ingest.mjs does that when it derives one.");
      } else if (!url.startsWith("https://") || !ALLOWED_IMAGE_HOSTS.has(host)) {
        report.error(`plugins/${plugin.dir}/${readme}`, `image ${JSON.stringify(url)} points at ${host}`,
          `Only GitHub's own asset hosts are rendered (${[...ALLOWED_IMAGE_HOSTS].join(", ")}), so that opening the store does not announce the user to a third party.`);
      }
    }
  }
}

/** Everything outside fenced code blocks, for checks that must not read examples. */
function stripFences(text) {
  return text.replace(/^\s{0,3}(`{3,}|~{3,})[\s\S]*?^\s{0,3}\1\s*$/gm, "");
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

  // ── the DISPLAY NAME, which this validator did not look at at all ──
  //
  // `checkSquatting` folded ids and stopped there, so the pull-request path —
  // the one a hand-written listing takes — held listings to a weaker rule than
  // the bot held submissions to. The store card renders the NAME; the id is
  // protected by `[a-z0-9-]` and the name is unconstrained prose, which makes
  // the name the softer target of the two.
  //
  // Same two rules `bot/lib/names.mjs` applies, and warnings rather than errors
  // for the same reason: a human decides. Two plugins genuinely called "Notes"
  // is a thing that happens; it is still a thing somebody should look at.
  //
  // ── and EVERY name, not the English one ─────────────────────────────────────
  //
  // This loop read `p.doc?.name` and nothing else, so the moment a listing grew
  // an `i18n` member the asymmetry was back in a new place: the bot ran
  // `checkDisplayName` once per derived locale and this ran once per listing.
  // Constructed against a two-listing tree — `lucky-cubes` with a `ru` card
  // named `Dіce Roller` (U+0456 for the ASCII `i`, colliding with the listed
  // `Dice Roller`) and a `de` card named `Würfеl Roller` (Cyrillic е) — this
  // validator printed `PASS … 0 error(s), 0 warning(s)` while
  // `bot/lib/names.mjs` returned `R_DISPLAY_NAME_COLLISION` and
  // `R_DISPLAY_NAME_MIXED_SCRIPT` for the same two strings. A maintainer editing
  // a listing by hand had no rule at all on nine of its ten cards.
  //
  // `renderedNames` and `foldDisplayName` are IMPORTED rather than rebuilt, and
  // that is what keeps it fixed. The fold used to be re-derived inline here —
  // `foldLookalikeScripts(name).toLowerCase().replace(/\s+/g, " ").trim()`,
  // which is `foldDisplayName`'s body, one edit away from the two paths folding
  // differently for ever. `bot/lib/names.mjs` exists to be the one predicate;
  // `dev/couplings.md` records the reserved-prefix rule being collapsed the same
  // way, and the residual risk is the same one: nothing stops somebody
  // re-inlining it.
  const byName = new Map();
  for (const p of plugins) {
    const id = p.doc?.id;
    if (typeof id !== "string") continue;

    for (const { name, locale } of renderedNames(p.doc)) {
      const at = locale ? ` (i18n.${locale})` : "";

      const scripts = scriptsUsed(name);
      if (scripts.length > 1) {
        report.warn(p.file,
          `the display name ${JSON.stringify(name)}${at} mixes ${scripts.join(" and ")} letters`,
          "Write the name in one alphabet. A name that borrows one Cyrillic or Greek letter for its Latin " +
          "shape renders as a name it does not contain, and the id charset cannot catch it. See POLICY.md §Names.");
      }

      const key = foldDisplayName(name);
      const prev = byName.get(key);
      if (prev && prev.id !== id) {
        report.warn(p.file,
          `the display name ${JSON.stringify(name)}${at} matches ${JSON.stringify(prev.name)} (listed as ` +
          `${JSON.stringify(prev.id)}${prev.locale ? `, in ${prev.locale}` : ""}) once case, whitespace and ` +
          "lookalike letters are ignored",
          "The store shows names, not ids, so two identical names are two identical cards. See POLICY.md §Names.");
      } else if (!prev) {
        byName.set(key, { id, name, locale });
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

  // The same walk, over the assembled document. The per-listing scan above
  // runs on the sources; this one runs on what is about to be signed, so the
  // deploy candidate is scanned as a document rather than trusted because its
  // inputs were. It is not redundant with the schema, which constrains lengths
  // and shapes and has nothing to say about a bidi override inside a
  // well-formed string.
  for (const entry of doc.signed?.plugins ?? doc.plugins ?? []) {
    for (const [field, value] of displayStrings(entry)) {
      const trick = unsafeDisplayText(value);
      if (trick) report.error(rel, `${entry.id}: ${field} ${trick}`);
    }
  }

  // Since 3.2 the catalogue is a `{signed, signatures}` envelope: only `signed`
  // is generated and only `signed` is covered by a signature. The fallback to a
  // bare document keeps this readable for a tree that predates the envelope —
  // the fields and their meanings are unchanged, only their depth is.
  const signed = doc.signed ?? doc;

  let regenerated;
  try {
    regenerated = stableStringify(buildIndex({ root, serial: signed.serial }));
  } catch (e) {
    report.error(rel, `cannot be regenerated from plugins/: ${e.message}`);
    return;
  }
  // A *published* catalogue carries `issued_at`, `expires_at` and signatures
  // that no generator holding no key and reading no clock can reproduce, so the
  // byte comparison holds only for the unsigned committed file — which is what
  // this validator is pointed at. For a signed one the same defect (a URL or a
  // digest edited straight into the catalogue) is caught by comparing the
  // content projection instead.
  const stamped = signed.issued_at !== undefined || (doc.signatures?.length ?? 0) > 0;
  if (!stamped) {
    if (regenerated !== text) {
      report.error(rel, "is not byte-identical to a fresh generation from plugins/",
        "It is a generated file. Run `node tools/build-index.mjs` and commit the result; do not edit it.");
    }
  } else if (stableStringify(indexContent(doc)) !== stableStringify(indexContent(JSON.parse(regenerated)))) {
    report.error(rel, "was signed over content that is not a fresh generation from plugins/",
      "Regenerate with `node tools/build-index.mjs`, then re-sign. Never edit a signed catalogue.");
  }

  // Ordering is a property the daemon may lean on and a reviewer definitely
  // does, so assert it rather than trusting the generator that just ran.
  const ids = signed.plugins?.map((p) => p.id) ?? [];
  if ([...ids].sort().join("\u0000") !== ids.join("\u0000")) {
    report.error(rel, "plugins are not sorted by id");
  }
  for (const p of signed.plugins ?? []) {
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
/**
 * The icon formats this registry accepts, against the ones AstraPlugins packs.
 *
 * Same shape of coupling as [`checkMirroredLimits`] and the same reason: two
 * programs in two repositories, neither able to see the other, agreeing on a
 * list by hand. Disagreement here is silent in BOTH directions — a format
 * `astra-plugin build` packs and this repository does not accept is an icon
 * that reaches the bundle and never reaches a store card, with no error
 * anywhere; a format accepted here and not packed there never arrives to be
 * accepted. Either way the author sees a blank card and nothing to act on.
 *
 * A missing checkout is reported as a note, never as a pass: a check that
 * quietly did not run must not look like a check that succeeded.
 */
export function checkMirroredIconFormats(ctx) {
  const where = "bot/lib/assets.mjs";
  const candidates = [
    process.env.ASTRA_PLUGINS_DIR,
    path.resolve(REPO_ROOT, "../AstraPlugins"),
  ].filter(Boolean);
  const specFile = candidates
    .map((d) => path.join(d, "spec/icon-formats.yaml"))
    .find((f) => fs.existsSync(f));

  if (!specFile) {
    ctx.report.note(where, "icon formats NOT verified against AstraPlugins: no checkout found",
      `Looked in ${candidates.join(", ")}. Set ASTRA_PLUGINS_DIR to check them.`);
    return;
  }

  const declared = fs.readFileSync(specFile, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

  if (declared.join(",") !== ICON_NAMES.join(",")) {
    ctx.report.error(where,
      `ICON_FORMATS is [${ICON_NAMES.join(", ")}] but spec/icon-formats.yaml declares [${declared.join(", ")}]`,
      "Order matters — it is the preference order used when a bundle ships more than one icon. " +
      "Change spec/icon-formats.yaml first, then mirror it here and in astra-plugin-cli.");
  }
}

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

// ── the locale couplings ────────────────────────────────────────────────────

/** Where an AstraPlugins checkout might be, best first. */
function astraPluginsCandidates() {
  return [process.env.ASTRA_PLUGINS_DIR, path.resolve(REPO_ROOT, "../AstraPlugins")].filter(Boolean);
}

function astraPluginsFile(rel) {
  return astraPluginsCandidates().map((d) => path.join(d, rel)).find((f) => fs.existsSync(f)) ?? null;
}

/**
 * **C15** — the ten locale codes, in three places on this side alone.
 *
 * `bot/lib/locales.mjs` decides which locale blocks the bot EMITS and the two
 * schemas decide which ones this repository ACCEPTS. Disagreement is silent
 * until the moment it is catastrophic: a bot that emits a code the schema
 * rejects fails `validateSchema(schemas.index, doc)` on the deploy candidate,
 * which stops the catalogue for every listing because one plugin shipped a
 * translation.
 *
 * The schema half runs always, needs nothing checked out, and `selftest.mjs`
 * constructs a drift to prove it fires. The `spec/locales.yaml` half is the
 * cross-repository one and says out loud when it did not run.
 */
export function checkLocaleVocabulary(ctx) {
  const where = "bot/lib/locales.mjs";
  for (const [name, doc] of [["schema/plugin-v1.json", ctx.schemas.plugin], ["schema/index-v1.json", ctx.schemas.index]]) {
    let problems;
    try {
      problems = localeEnumProblems(doc, name);
    } catch (e) {
      // The member is gone or has moved. That is a broken SCAN, not a passing
      // check, and it is reported as an error rather than swallowed.
      ctx.report.error(where, e.message,
        "Restore the i18n member's propertyNames.enum, or update localeEnum() in bot/lib/locales.mjs to find where it went.");
      continue;
    }
    for (const p of problems) {
      ctx.report.error(where, p,
        "The vocabulary is AstraPlugins/spec/locales.yaml. Mirror it into LOCALE_CODES and into both schema enums, and never into only one.");
    }
  }

  const specFile = astraPluginsFile("spec/locales.yaml");
  if (!specFile) {
    ctx.report.note(where, "the locale vocabulary is NOT verified against AstraPlugins: no checkout found",
      `Looked in ${astraPluginsCandidates().join(", ")}. Set ASTRA_PLUGINS_DIR to check it. ` +
      "LOCALE_CODES must equal spec/locales.yaml, which mirrors Astra's SUPPORTED_LANGUAGES.");
    return;
  }
  // One row per line: the code, the endonym, and an optional trailing
  // `maintained`. Only the first field is read here — `maintained` is a
  // different subset of the same ten codes and conflating the two is how an
  // unselectable locale file gets shipped.
  const declared = fs.readFileSync(specFile, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => l.split(/\s+/)[0]);
  // The floor, before the comparison: a reader that matched nothing would
  // otherwise compare ten codes against an empty list and report the drift
  // backwards, naming every code as missing upstream.
  if (declared.length < 5) {
    ctx.report.error(where, `${specFile} yielded ${declared.length} locale row(s), which cannot be right`,
      "The file's row format changed, so THIS READER is what broke — not the vocabulary. Fix the parse before believing any comparison it makes.");
    return;
  }
  if (declared.join(" ") !== LOCALE_CODES.join(" ")) {
    ctx.report.error(where,
      `LOCALE_CODES is [${LOCALE_CODES.join(" ")}] but spec/locales.yaml declares [${declared.join(" ")}]`,
      "Order matters: `en` is first because it is the base every other locale falls back to. " +
      "Change Astra's SUPPORTED_LANGUAGES first, then spec/locales.yaml, then this list and both schema enums.");
  }
}

/** The four siblings a cap in `policy/limits.json` may carry, exactly one of. */
const CAP_DECLARATIONS = ["_mirrors", "_mirrored_by", "_not_author_facing", "_unmirrored"];

/** Where a `_mirrored_by` sibling is allowed to point. One file, today. */
const MIRRORED_BY_FILE = "AstraPlugins/spec/listing-limits.yaml";

/**
 * **Every cap says what its relationship to an author's source tree is.**
 *
 * The check that would have caught the thing the two C20 halves could not.
 * Both of those enumerate `spec/listing-limits.yaml` and ask, of each row,
 * *"does this name a real constant here, and equal it?"* — a question with the
 * same answer whether this repository holds four author-facing caps or forty.
 * So when `max_locale_bytes`, `max_locale_keys` and `max_listing_i18n_bytes`
 * were added and wired into `bot/lib/locales.mjs` as blocking errors, nothing
 * on either side could observe that no copy of them existed upstream. An
 * author's 521,032-byte `en.json` passed `astra-plugin check` with `OK`, and
 * `deriveLocaleText` refused the same bytes as `E_LOCALE_TOO_LARGE` — after a
 * tag, in a repository they had never opened, which is the exact failure that
 * spec file's own header describes itself as existing to prevent.
 *
 * A rule of the form *"every X must be handled"* is only as good as its
 * enumeration of X, and the enumeration has to be of the side where a new X is
 * born. New caps are born HERE. So the declaration is here: one of
 * [`CAP_DECLARATIONS`] per numeric cap, and a cap with none is an error rather
 * than a silence. That is the exemption-list discipline — a new cap arrives as
 * a one-line answer to *"can an author trip this from their own tree?"* instead
 * of as an absence nobody notices.
 *
 * **`_unmirrored` is not an exemption and is not printed like one.** It says an
 * author CAN trip the cap and nothing local checks it; every one is named on
 * every run. Collapsing it into `_not_author_facing` would let real debt hide
 * behind an innocuous word, which is the failure this whole check is about.
 *
 * **Which side should somebody edit when this goes red?** This one — the cap
 * that has no sibling was just added here, and only the person adding it knows
 * the answer. The one repair to refuse is deleting a sibling to make a
 * *downstream* check pass: see [`checkMirroredListingLimits`]. That repair used
 * to be the fastest green available and is now the loudest failure, because a
 * cap with no sibling fails here.
 *
 * **What this cannot refuse**, measured rather than assumed: relabelling a true
 * `_mirrored_by` as `_not_author_facing` with a false sentence greens every
 * check on both sides, and no program can tell. That is the floor of any
 * exemption list. It is why the sibling carries prose and not a boolean — the
 * escape hatch was turned into a written claim that shows up in a diff and can
 * be disagreed with, not closed. A silence became a sentence; a sentence is
 * what review is for.
 *
 * Needs no checkout. Runs everywhere, on every `validate.mjs` and every
 * `selftest.mjs`.
 */
export function checkEveryCapDeclaresItsAuthorSide(ctx) {
  const where = "policy/limits.json";
  const limits = ctx.policy.limits ?? ctx.policy;
  const caps = Object.entries(limits).filter(([, v]) => typeof v === "number");

  // The floor, written before anything is compared. A reader that enumerates
  // no caps reports a clean bill of health for a file it never opened, and
  // "the caps were deleted" and "this reader broke" need opposite fixes.
  const MIN_CAPS = 10;
  if (caps.length < MIN_CAPS) {
    ctx.report.error(where, `${caps.length} numeric cap(s) found, below the floor of ${MIN_CAPS}`,
      "If that file still holds `\"name\": <number>` members, THIS READER is what broke and the caps are fine. " +
      "If it does not, most of this registry's policy has just been deleted.");
    return;
  }

  const unmirrored = [];
  for (const [name] of caps) {
    const carried = CAP_DECLARATIONS.filter((s) => limits[name + s] !== undefined);
    if (carried.length === 0) {
      ctx.report.error(where, `${name} carries none of ${CAP_DECLARATIONS.join(", ")}`,
        "Every cap here declares what an author's source tree has to do with it, because the way three locale " +
        "caps came to be enforced at ingest and mirrored nowhere was not a decision — it was an absence nobody " +
        "could see. Pick one: `_mirrors` (this number is a copy of an AstraPlugins constant), `_mirrored_by` " +
        `(an author can trip it and ${MIRRORED_BY_FILE} carries a copy so \`astra-plugin\` refuses it before a ` +
        "tag), `_not_author_facing` (nothing in a source tree decides it — the sentence is the claim), or " +
        "`_unmirrored` (an author can trip it and nothing local checks it, recorded as debt). See this file's " +
        "$comment for what each obliges.");
      continue;
    }
    if (carried.length > 1) {
      ctx.report.error(where, `${name} carries ${carried.length} declarations: ${carried.join(", ")}`,
        "Exactly one. `_mirrors` and `_mirrored_by` in particular are opposite claims about which repository " +
        "owns the number, and a cap asserting both pins nothing in either direction.");
      continue;
    }
    if (carried[0] === "_mirrored_by" && !String(limits[name + "_mirrored_by"]).startsWith(MIRRORED_BY_FILE)) {
      ctx.report.error(where,
        `${name}_mirrored_by names ${JSON.stringify(limits[name + "_mirrored_by"])}, which is not ${MIRRORED_BY_FILE}`,
        `Only ${MIRRORED_BY_FILE} is compared, by checkMirroredListingLimits below and by ` +
        "`tools/check-locales.py --rules C20` from the other end. A sibling naming somewhere else is a copy " +
        "nothing compares, which is the state this whole convention exists to end.");
      continue;
    }
    if (carried[0] === "_unmirrored") unmirrored.push(name);
  }

  // Recorded debt, named on every run rather than counted once. A number would
  // let one drop out of the list without the count moving in a way anybody
  // reads; the names are what somebody can act on.
  if (unmirrored.length > 0) {
    ctx.report.note(where,
      `${unmirrored.length} cap(s) an author can trip with nothing local checking: ${unmirrored.join(", ")}`,
      "Each carries an `_unmirrored` sentence saying what that costs. This is recorded debt, not an exemption: " +
      "the fix for any of them is a row in " + MIRRORED_BY_FILE + ", a rule in `astra-plugin`, and the sibling " +
      "changed to `_mirrored_by`.");
  }
}

/**
 * **C20** — the listing caps AstraPlugins mirrors FROM here, in both directions.
 *
 * The other mirror check in this file points outward: `policy/limits.json`
 * declares that its numbers are copies of AstraPlugins' constants. This one
 * points inward. `spec/listing-limits.yaml` exists so that `astra-plugin check`
 * can refuse a 141-character permission reason at pack time instead of letting
 * an author discover it at ingest, in a repository they have never opened,
 * after they have pushed a tag they cannot move.
 *
 * **Which side should somebody edit to make this pass?** Theirs. These are this
 * repository's numbers and that file says so in its own header; a lower value
 * there refuses a listing this registry would have accepted, and a higher one
 * walks an author into a refusal they cannot act on. The message says which way
 * round, because the fastest way to green a mirror check is to edit whichever
 * file is in front of you.
 *
 * **The reverse direction, added 2026-08-23.** Everything above enumerates the
 * rows that file happens to carry, so a cap it does not carry is invisible to
 * it by construction — which is how three locale caps were enforced here and
 * mirrored nowhere for a day. The second loop enumerates the `_mirrored_by`
 * declarations instead, and asks whether each one's copy is really there.
 *
 * The wrong repair for THAT failure is the interesting one, because it is one
 * keystroke and it looks like tidying: delete the `_mirrored_by` sibling. Both
 * halves of C20 go green, the cap goes on being enforced at ingest exactly as
 * before, and the number is unpinned in both repositories. The hint says so,
 * and so does this file's `$comment`, because the person about to do it is
 * looking at `policy/limits.json` and nothing else.
 *
 * **A missing row is usually the pin, not a deletion.** `build-index.yml`
 * checks AstraPlugins out at `ASTRA_PLUGINS_REF`, pinned in `ingest.yml`, so a
 * row added there arrives here when the pin moves — not when it merges. The
 * message names both causes because they need opposite fixes.
 */
export function checkMirroredListingLimits(ctx) {
  const where = "AstraPlugins/spec/listing-limits.yaml";
  const specFile = astraPluginsFile("spec/listing-limits.yaml");
  if (!specFile) {
    ctx.report.note("policy/limits.json", "the listing caps AstraPlugins mirrors are NOT verified: no checkout found",
      `Looked in ${astraPluginsCandidates().map((d) => path.join(d, "spec/listing-limits.yaml")).join(", ")}. ` +
      "Set ASTRA_PLUGINS_DIR to check them.");
    return;
  }

  // `# mirrors: <file> <path…>` on a comment line, then `name: <integer>`.
  // The comment is the machine-readable half ON PURPOSE: it is read by a human
  // and by this regex, and by nothing that would break if it were reworded.
  const pairs = [];
  let pending = null;
  for (const line of fs.readFileSync(specFile, "utf8").split("\n")) {
    const mirror = /^#\s*mirrors:\s*(.+?)\s*$/.exec(line);
    if (mirror) { pending = mirror[1]; continue; }
    const value = /^([a-z0-9_]+):\s*([0-9_]+)\s*(#.*)?$/.exec(line);
    if (value) {
      pairs.push({ name: value[1], value: Number(value[2].replace(/_/g, "")), target: pending });
      pending = null;
    }
  }

  // The floor, written before the comparison and not derived from it. Four
  // values are declared there today; a reader that finds fewer than three has
  // stopped matching the file rather than found a shrinking list, and those two
  // need opposite fixes.
  const MIN_MIRRORS = 3;
  if (pairs.length < MIN_MIRRORS) {
    ctx.report.error(where, `${pairs.length} mirrored cap(s) found, below the floor of ${MIN_MIRRORS}`,
      "If that file still holds `# mirrors:` comments above `name: integer` lines, THIS READER is what broke. " +
      "If it does not, the caps upstream were deleted and nothing over there is checking these numbers any more.");
    return;
  }

  for (const { name, value, target } of pairs) {
    if (!target) {
      ctx.report.error(where, `${name} has no \`# mirrors:\` line above it`,
        "Every value in that file is a copy of one of ours. One without a source is a number nobody can check.");
      continue;
    }
    const parts = target.split(/\s+/);
    const [file, ...rest] = parts;
    let ours;
    if (file === "astra-registry/policy/limits.json" && rest.length === 1) {
      ours = (ctx.policy.limits ?? ctx.policy)[rest[0]];
    } else if (file === "astra-registry/schema/version-v1.json" && rest.length === 2) {
      // `$.properties.permissions.patternProperties.*.properties.reason maxLength`
      // — a JSON pointer with one wildcard, resolved rather than guessed at.
      let node = ctx.schemas.version;
      for (const step of rest[0].replace(/^\$\.?/, "").split(".")) {
        if (node === undefined || node === null) break;
        if (step === "*") {
          const keys = Object.keys(node);
          node = keys.length === 1 ? node[keys[0]] : undefined;
        } else {
          node = node[step];
        }
      }
      ours = node?.[rest[1]];
    }
    if (ours === undefined) {
      ctx.report.error(where, `${name} claims to mirror ${JSON.stringify(target)}, which resolves to nothing here`,
        "Either the value moved in this repository or the `mirrors:` line is wrong. Both are drift, and both leave that file's copy unpinned.");
      continue;
    }
    if (ours !== value) {
      ctx.report.error(where, `${name} is ${value} there and ${ours} here (${target})`,
        "THIS repository owns these numbers; that file is the copy. Fix the copy — unless the number here is what is wrong, " +
        "in which case change it here first and mirror it there in the same breath, because between the two commits every " +
        "author is checked against a cap this registry does not enforce.");
    }
  }

  // ── the reverse direction ────────────────────────────────────────────────
  // Enumerated from THIS side's declarations rather than from that file's
  // rows, because a row that does not exist cannot be walked.
  const limits = ctx.policy.limits ?? ctx.policy;
  const declared = Object.keys(limits)
    .filter((k) => k.endsWith("_mirrored_by"))
    .map((k) => k.slice(0, -"_mirrored_by".length));

  // The floor again, and for the same reason as the one above: an enumeration
  // that finds nothing reports every cap as correctly mirrored.
  const MIN_DECLARED = 3;
  if (declared.length < MIN_DECLARED) {
    ctx.report.error("policy/limits.json",
      `${declared.length} \`_mirrored_by\` declaration(s) found, below the floor of ${MIN_DECLARED}`,
      "If policy/limits.json still carries `\"<cap>_mirrored_by\"` siblings, THIS READER is what broke. " +
      "If it does not, those declarations were deleted — which greens this check by unpinning the numbers, " +
      "and is the one repair this convention exists to refuse. See checkEveryCapDeclaresItsAuthorSide.");
    return;
  }

  const present = new Set(pairs.map((p) => p.name));
  for (const name of declared) {
    if (present.has(name)) continue;
    ctx.report.error(where, `${name} is declared \`_mirrored_by\` this file, which has no \`${name}\` row`,
      `This registry enforces ${name} at ingest, on a bundle whose tag is already pushed. The copy is what is ` +
      "missing, and the copy is what to add: a `# mirrors: astra-registry/policy/limits.json " + name + "` " +
      "comment above a `" + name + ": " + limits[name] + "` row there, mirrored into " +
      "astra-plugin-cli/src/listing-limits.yaml, with a rule in `astra-plugin` that executes on it. " +
      "TWO CAUSES, opposite fixes: the row may never have landed upstream, OR it landed and ASTRA_PLUGINS_REF " +
      "in .github/workflows/ingest.yml still points at a commit from before it — this job checks that " +
      "repository out at the pin, so a merge upstream does not reach here until the pin moves. " +
      "Do NOT fix it by deleting the `_mirrored_by` sibling: that greens both halves of C20 in one keystroke, " +
      "leaves the cap enforced here exactly as it was, and puts the number back to being a copy nobody compares.");
  }
}

/**
 * **The English store card**, over the committed tree.
 *
 * `bot/lib/locales.mjs` refuses a non-English card at ingest. This is the other
 * half: a listing can also be hand-written or hand-edited, and one that is
 * already in the tree was ingested before this rule existed. The predicate is
 * imported rather than restated, so what the bot admits cannot be what CI then
 * refuses.
 *
 * **`unlisted: true` is skipped, explicitly.** Such a plugin is not in the
 * generated index and is rendered to nobody in any language, so an exemption
 * protecting one would be decoration nobody could observe firing. This is not
 * hypothetical: `knice-chess` is unlisted, its summary is Russian, and it is
 * the only listing in the tree that fails this check.
 */
export function checkListingLanguage(plugins, ctx) {
  const exemptions = ctx.policy.listingLanguage;
  const used = new Set();

  for (const plugin of plugins) {
    const doc = plugin.doc ?? {};
    if (doc.unlisted === true) continue;
    const repo = doc.source?.repo;
    const summary = typeof doc.summary === "string" ? doc.summary : "";
    if (!summary || isLatinScript(summary)) continue;
    if (isLanguageExempt(repo, exemptions)) {
      used.add(String(repo).toLowerCase());
      ctx.report.warn(plugin.file,
        `summary is not in the Latin script; listed by an exemption for ${repo}`,
        "policy/listing-language-exemptions.json. Every user whose language this plugin has not translated reads this string.");
      continue;
    }
    const { latin, letters } = latinFraction(summary);
    ctx.report.error(plugin.file,
      `summary is not in English: ${letters === 0 ? "it contains no letters at all" : `${100 - Math.floor((latin * 100) / letters)}% of its letters are outside the Latin script`}`,
      "The card, the search index and every client that predates localization all show this string, and so does every " +
      "user whose language the plugin has not translated. The fix is a release whose plugin.toml description is English " +
      "with the original in locales/<code>.json under `listing.description` — NOT an edit to this file, which is derived " +
      "and would disagree with the bundle at the next release. If the listing must stand as it is, add its source.repo to " +
      "policy/listing-language-exemptions.json with a reason.");
  }

  // An exemption nobody needs is a hole nobody is watching: the next release
  // from that repository inherits an excuse no one granted it.
  for (const entry of exemptions?.exempt ?? []) {
    const repo = String(entry?.repo ?? "");
    if (!used.has(repo.toLowerCase())) {
      ctx.report.warn("policy/listing-language-exemptions.json",
        `the exemption for ${JSON.stringify(repo)} is not being used by any listed plugin`,
        "Either the card is English now — delete the entry — or the plugin is unlisted or not listed at all, in which case " +
        "the entry is protecting nothing and will silently excuse whatever that repository publishes next.");
    }
  }
}

/**
 * **C16** — the shared locale rule corpus, as this repository reads it.
 *
 * `AstraPlugins/testdata/locales/` holds one directory per case with the
 * verdict written down beside it, and two implementations of one rule set are
 * held to it: `astra-plugin check` there, and `bot/lib/locales.mjs` here. The
 * CLI refuses a bundle before a tag is pushed and this repository refuses a
 * listing after one is, so a disagreement is an author whose release passes
 * every gate they can see and dies somewhere they have never looked.
 *
 * This side implements a SUBSET, because the two halves are asked different
 * questions — the CLI is asked about a source tree and this is asked about a
 * published card. The subset is declared in `bot/lib/locales.mjs`
 * (`CORPUS_RULE_IDS`) and everything outside it is declared too
 * (`CORPUS_NOT_IMPLEMENTED`), with a reason. A fixture whose ids are all
 * outside the subset is not skipped: it is asserted to produce NO errors here,
 * which is the useful half of that case — this repository does not invent a
 * refusal for a defect it cannot see.
 */
export function checkLocaleCorpus(ctx) {
  const where = "AstraPlugins/testdata/locales";
  const dir = astraPluginsCandidates().map((d) => path.join(d, "testdata/locales")).find((d) => fs.existsSync(d));
  if (!dir) {
    ctx.report.note(where, "the shared locale corpus is NOT verified: no checkout found",
      `Looked in ${astraPluginsCandidates().map((d) => path.join(d, "testdata/locales")).join(", ")}. ` +
      "Set ASTRA_PLUGINS_DIR, or add testdata/locales to the sparse-checkout that fetches it. " +
      "An absent corpus reads exactly like a clean one, which is why this is printed rather than passed over.");
    return;
  }

  const cases = (kind) => {
    const root = path.join(dir, kind);
    if (!fs.existsSync(root)) return [];
    return fs.readdirSync(root, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => path.join(root, e.name))
      .sort();
  };
  const pass = cases("pass");
  const fail = cases("fail");

  // The floor, BEFORE any comparison, and the two failures it separates look
  // nothing alike: a shrunken corpus is somebody deleting a rule's only
  // witness; an empty one is this reader looking in the wrong place. The
  // numbers are the CLI's own floors, so neither reader can drift below the
  // other without saying so.
  const MIN_PASS = 4;
  const MIN_FAIL = 12;
  if (pass.length < MIN_PASS || fail.length < MIN_FAIL) {
    ctx.report.error(where,
      `found ${pass.length} pass and ${fail.length} fail case(s) (floor: ${MIN_PASS}/${MIN_FAIL})`,
      "If that directory still holds one subdirectory per case, the RULES are what shrank and somebody deleted a fixture. " +
      "If it does not, this SCAN is what broke — the corpus moved, or the checkout that fetched it does not include it.");
    return;
  }

  const covered = new Set();
  const mismatches = [];
  for (const kind of ["pass", "fail"]) {
    for (const caseDir of kind === "pass" ? pass : fail) {
      const name = `${kind}/${path.basename(caseDir)}`;
      let got;
      try {
        got = corpusIds(caseDir, ctx);
      } catch (e) {
        ctx.report.error(where, `${name} could not be read: ${e.message}`,
          "A case this reader cannot load is a case it is not checking. Fix the reader or the fixture; do not skip it.");
        continue;
      }
      let expect = new Set();
      if (kind === "fail") {
        const file = path.join(caseDir, "EXPECT");
        if (!fs.existsSync(file)) {
          ctx.report.error(where, `${name} has no EXPECT file`);
          continue;
        }
        const all = fs.readFileSync(file, "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
        for (const id of all) {
          if (Object.values(CORPUS_RULE_IDS).includes(id)) { expect.add(id); covered.add(id); continue; }
          if (Object.hasOwn(CORPUS_NOT_IMPLEMENTED, id)) continue;
          ctx.report.error(where, `${name} expects ${id}, which this repository neither implements nor exempts`,
            "Add it to CORPUS_RULE_IDS in bot/lib/locales.mjs, or to CORPUS_NOT_IMPLEMENTED with one sentence on why the " +
            "registry does not need it. An id that is silently ignored is a rule nobody decided about.");
        }
      }
      const a = [...expect].sort().join(",");
      const b = [...got].sort().join(",");
      if (a !== b) mismatches.push(`${name}: expected [${a || "none"}], got [${b || "none"}]`);
    }
  }
  for (const m of mismatches) {
    ctx.report.error(where, m,
      "The CLI and this repository disagree about one bundle. Read the case's WHY file: it says what the rule is for, " +
      "and which of the two implementations is wrong is a decision, not a diff.");
  }

  // Every implemented rule has a witness in the corpus, or the corpus has
  // stopped proving the rule still fires.
  for (const id of new Set(Object.values(CORPUS_RULE_IDS))) {
    if (!covered.has(id)) {
      ctx.report.error(where, `rule ${id} is implemented here and has no fail case in the corpus`,
        "A rule with no witness may already have stopped firing. Add a case in AstraPlugins/testdata/locales/fail/, or " +
        "remove the rule from CORPUS_RULE_IDS if it no longer exists.");
    }
  }
  ctx.report.note(where,
    `${pass.length} pass and ${fail.length} fail case(s) read; ${new Set(Object.values(CORPUS_RULE_IDS)).size} rule(s) ` +
    `implemented here, ${Object.keys(CORPUS_NOT_IMPLEMENTED).length} declared not implemented`);
}

/**
 * One corpus case, through the checks a submission's card text goes through.
 *
 * Both of them: `checkMetadata` is where an over-long or invisible-charactered
 * ENGLISH name is refused, and `deriveLocaleText` is where everything about the
 * translations is. At ingest they run one after the other on the same facts, so
 * running one alone here would be testing half the answer.
 */
function corpusIds(caseDir, ctx) {
  const facts = readFixtureManifest(path.join(caseDir, "plugin.toml"));
  const files = [];
  const localesDir = path.join(caseDir, "locales");
  if (fs.existsSync(localesDir)) {
    for (const e of fs.readdirSync(localesDir, { withFileTypes: true })) {
      if (e.isFile()) files.push({ name: `locales/${e.name}`, bytes: fs.readFileSync(path.join(localesDir, e.name)) });
    }
  }
  const lock = path.join(caseDir, "locales.lock.json");
  if (fs.existsSync(lock)) files.push({ name: "locales.lock.json", bytes: fs.readFileSync(lock) });

  const limits = ctx.policy.limits;
  const findings = [
    ...checkMetadata({
      name: facts.name,
      description: facts.description,
      summary: summarise(facts.description, limits.max_summary_length),
    }, limits),
    ...deriveLocaleText({ files, facts, limits, summarise }).findings,
  ];
  const ids = new Set();
  for (const f of findings) {
    if (f.level !== "error") continue;
    const id = CORPUS_RULE_IDS[f.code];
    if (id) { ids.add(id); continue; }
    // A rule this repository enforces that the corpus has no id for, declared
    // as such in `CORPUS_NO_RULE_ID` with the reason. It contributes no id, so
    // the case's EXPECT file is unaffected — a fixture may provoke one of these
    // in passing without being about it. What used to happen instead was a
    // throw, which is why writing the first fixture for `E_METADATA_UNSAFE_TEXT`
    // would have been refused by this reader rather than welcomed by it.
    if (Object.hasOwn(CORPUS_NO_RULE_ID, f.code)) continue;
    throw new Error(
      `${f.code} is an error this module can emit and neither CORPUS_RULE_IDS nor CORPUS_NO_RULE_ID names. Every ` +
      "error the corpus can provoke has to map to a rule id or to a written-down reason there is none, or a real " +
      "disagreement with the CLI shows up as an unexplained extra finding.",
    );
  }
  return ids;
}

/**
 * **The direction C16 never ran in.** Every error `bot/lib/locales.mjs` can
 * emit is either mapped to a corpus rule id or declared to have none.
 *
 * `checkLocaleCorpus` above reads the corpus and asks, of each id in it,
 * whether this repository implements or exempts it. That is corpus → registry,
 * and it can only ever see rules somebody already wrote a fixture for. Nothing
 * asked the reverse, so a registry rule applied to locale text with no fixture
 * was a member neither reader could see — which is exactly what
 * `E_METADATA_UNSAFE_TEXT` was: live on every translated `listing.name` since
 * the locale work landed, provoked by none of the corpus's 104 files, and named
 * in neither map.
 *
 * It reads the module as TEXT rather than executing it, which is
 * `bot/manifest-probe`'s pattern — the only way to enumerate what a function
 * *can* emit rather than what one call did. **Runs everywhere**: no checkout, no
 * secret, no corpus. That matters, because `checkLocaleCorpus` skips without an
 * AstraPlugins checkout and this is the half that must not skip with it.
 *
 * The floor is written before the comparison and its failure separates the two
 * causes: a scan that finds fewer codes than the module has is a scan that
 * broke, and a scan that finds none is a reader pointed at the wrong file.
 */
export function checkLocaleCorpusCoverage(ctx) {
  const where = "bot/lib/locales.mjs";
  const file = path.join(REPO_ROOT, "bot", "lib", "locales.mjs");
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    ctx.report.error(where, `cannot be read to enumerate its rules: ${e.message}`,
      "This reader scrapes the module's own `add(\"error\", …)` calls. If it cannot open the file it is not " +
      "checking anything, and an unreadable module must not pass for a module with no rules.");
    return;
  }

  const codes = new Set([...text.matchAll(/add\("error",\s*"([A-Z][A-Z0-9_]+)"/g)].map((m) => m[1]));

  // The floor, BEFORE any comparison. Eleven today; a number rather than a
  // range because this set grows by somebody adding a rule, and a rule added
  // without an answer to "which fixture proves it fires?" is the whole point.
  const MIN_CODES = 8;
  if (codes.size < MIN_CODES) {
    ctx.report.error(where,
      `found ${codes.size} error rule(s) (floor: ${MIN_CODES})`,
      "If deriveLocaleText still calls add(\"error\", \"E_…\") for each rule, then RULES are what shrank and somebody " +
      "deleted one. If it does not, this SCAN is what broke — the helper was renamed or the calls were reshaped, " +
      "and a scan that matches nothing reads exactly like a module with nothing to check.");
    return;
  }

  for (const code of [...codes].sort()) {
    const mapped = Object.hasOwn(CORPUS_RULE_IDS, code);
    const exempt = Object.hasOwn(CORPUS_NO_RULE_ID, code);
    if (mapped && exempt) {
      ctx.report.error(where, `${code} is in BOTH CORPUS_RULE_IDS and CORPUS_NO_RULE_ID`,
        "A rule either has a corpus witness or has a written reason it cannot. Two answers is no answer.");
    } else if (!mapped && !exempt) {
      ctx.report.error(where, `${code} is enforced on locale text and neither maps to a corpus rule id nor declares why it cannot`,
        "Add it to CORPUS_RULE_IDS in bot/lib/locales.mjs with the AstraPlugins rule id whose fixture proves it fires, or " +
        "to CORPUS_NO_RULE_ID with one sentence on why no fixture can. A rule with neither is invisible to both readers " +
        "of the shared corpus, which is how E_METADATA_UNSAFE_TEXT came to be enforced on every translated card with " +
        "nothing anywhere proving it still fires.");
    }
  }

  // The other direction of the same page: an exemption for a rule that no
  // longer exists is a reason nobody can check, and it makes the debt look
  // serviced. `dev/couplings.md`'s step 6 asks for the exemption list to fail
  // when an entry stops being needed, the way C6's pending-exception list does.
  for (const code of Object.keys(CORPUS_NO_RULE_ID)) {
    if (!codes.has(code)) {
      ctx.report.error(where, `CORPUS_NO_RULE_ID exempts ${code}, which this module no longer emits`,
        "Delete the entry. An exemption outliving its rule is a sentence that reads as a decision and guards nothing.");
    }
  }

  ctx.report.note(where,
    `${codes.size} locale error rule(s) enumerated; ` +
    `${[...codes].filter((c) => Object.hasOwn(CORPUS_RULE_IDS, c)).length} carry a corpus rule id, ` +
    `${[...codes].filter((c) => Object.hasOwn(CORPUS_NO_RULE_ID, c)).length} declare why they cannot`);
}

/**
 * `[plugin] name` and `description` out of a fixture's `plugin.toml`.
 *
 * A five-line reader for a five-line file, and it is deliberately unforgiving:
 * every fixture in the corpus declares both, so a missing one means the format
 * moved and this reader is now inventing facts. `[config] schema` in some
 * fixtures is a multi-line string full of `"key": "value"` lines, which is why
 * reading stops at the next section header rather than scanning the file.
 */
function readFixtureManifest(file) {
  const text = fs.readFileSync(file, "utf8");
  const out = {};
  let inPlugin = false;
  for (const line of text.split("\n")) {
    const header = /^\s*\[([^\]]+)\]/.exec(line);
    if (header) { inPlugin = header[1] === "plugin"; continue; }
    if (!inPlugin) continue;
    const kv = /^\s*(name|description)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$/.exec(line);
    if (kv) out[kv[1]] = JSON.parse(`"${kv[2]}"`);
  }
  if (typeof out.name !== "string" || typeof out.description !== "string") {
    throw new Error(
      `${file} yielded no [plugin] name/description. Every fixture declares both, so this READER is what broke — ` +
      "probably a multi-line or single-quoted value it does not parse.",
    );
  }
  return out;
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
  checkMirroredIconFormats(ctx);
  checkEveryCapDeclaresItsAuthorSide(ctx);
  checkMirroredListingLimits(ctx);
  checkLocaleVocabulary(ctx);
  checkLocaleCorpus(ctx);
  checkLocaleCorpusCoverage(ctx);

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
  checkListingLanguage(usable, ctx);

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
