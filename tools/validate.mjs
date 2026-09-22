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
import { POSITIVE_INTEGER_LITERAL, topLevelMembers } from "./lib/json-literal.mjs";
import { stableStringify } from "./lib/canonical.mjs";
import { compareSemver, parseSemver } from "./lib/semver.mjs";
import { reservedPrefixViolation, stagingListingId } from "./lib/reserved.mjs";
import {
  editDistance,
  foldId,
  invalidId,
  scriptsUsed,
  unsafeDisplayText,
  unsafePathComponent,
} from "./lib/ids.mjs";
import {
  ALERTS_DIR,
  BASELINE_FILE,
  BASELINE_SCHEMA,
  DECISIONS_DIR,
  DECISION_SCHEMA,
  IDENTITY_SCHEMA,
  QUEUE_SCHEMA,
  loadBaseline,
  loadPolicy,
  loadPublishers,
  loadRecords,
  loadSchemas,
  loadSources,
  nonStagingVersions,
  publisherRecords,
  readJson,
  REPO_ROOT,
} from "./lib/sources.mjs";
import {
  AUTHOR_ACTION_FORBIDDEN,
  AUTHOR_ACTION_MEMBERS,
  refuseUncomposableAuthorAction,
} from "../bot/lib/decisions.mjs";
import { SOURCE_DIR as MODERATION_DIR, loadEntries as loadModerationEntries } from "../bot/lib/moderation.mjs";
import { fixedReason } from "../bot/lib/compile-decision.mjs";
import { ALLOWED_IMAGE_HOSTS, ICON_NAMES, MAX_README_BYTES, checkIcon } from "../bot/lib/assets.mjs";
import {
  CUTOVER_FILE,
  CUTOVER_SCHEMA,
  DEADLINE_FILE,
  DEADLINE_SCHEMA,
  cutoverSchema,
  deadlineSchema,
  parseTime,
} from "../bot/lib/listing-state.mjs";
import { checkMetadata, summarise } from "../bot/lib/derive.mjs";
import { foldDisplayName, renderedNames } from "../bot/lib/names.mjs";
import {
  CORPUS_NOT_IMPLEMENTED,
  CORPUS_NO_RULE_ID,
  CORPUS_RULE_IDS,
  LOCALE_CODES,
  deriveLocaleText,
  englishDigest,
  isLanguageExempt,
  isLatinScript,
  latinFraction,
  localeEnumProblems,
} from "../bot/lib/locales.mjs";
import { buildIndex, indexContent } from "./build-index.mjs";
import { RESERVED_KEYS, SUPPORTED_KEYS } from "./lib/platform.mjs";
import { isTime } from "./lib/time.mjs";

// `tools/lib/platform.mjs`'s table, not a copy of it. Until 2026-09-22 these
// were two literals of this file's own, and platform.mjs's RESERVED_KEYS was
// read by nothing that refuses a listing, only by the selftest that compares
// the two. Measured that day: dropping a key from the literal refusal list
// failed OPEN, and a linux-arm64-only listing validated.
const PLATFORM_KEYS = new Set([...SUPPORTED_KEYS, ...RESERVED_KEYS]);
// Reserved names, listed in the schema so the vocabulary is fixed, but not
// emitted and not accepted: Astra's release workflow ships no daemon for these
// hosts, so an artifact under one of them would have nowhere to run.
const UNSUPPORTED_KEYS = new Set(RESERVED_KEYS);

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

  // MOD-16's staging listing, on the tree. `bot/lib/derive.mjs` derives it
  // `unlisted: true` and no manifest can lift that — but derivation is only the
  // path a RELEASE takes. A hand-written commit, a revert of the derive rule,
  // a merge that resolved `plugin.json` the wrong way: each of those puts a
  // listed `astra-withdrawal-canary` on `main` without the bot being involved
  // at all, and the next signer run puts it in a signed catalogue. This is the
  // rule that reads what is actually committed, which is what the signer reads.
  //
  // It is an error and not a warning because of what the listing IS: the id
  // the estate delists, relists, revokes and un-revokes to drill its own
  // withdrawal path. A store card for it is a card for a plugin that will be
  // taken away on purpose, under this registry's name.
  const staging = stagingListingId(policy.reserved);
  if (staging !== null && id === staging && plugin.doc.unlisted !== true) {
    report.error(where,
      `id ${JSON.stringify(id)} is policy/reserved-ids.json's staging_listing_id and the listing is not unlisted`,
      "The path-test listing (MOD-16) exists to be withdrawn, never to be offered. Set `\"unlisted\": true` in " +
      "plugin.json. A release derives it that way on its own (bot/lib/derive.mjs); a listed one on the tree is " +
      "a hand edit, a revert or a bad merge.");
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

  // BOT-79, the input side. `icon_url` names a host the plugin author controls,
  // and the listing's own schema still describes the field, so a hand-written
  // or hand-edited listing can carry one. Refused here rather than at generation
  // alone, because this is the check a submission meets: the author gets a
  // sentence in the pull request instead of a red `build-index` run on `main`
  // that names a file they did not touch. `tools/build-index.mjs` refuses it
  // again on the generating side and `schema/index-v1.json` refuses it in the
  // signed document, and the three are watched together in
  // `tools/selftest/catalogue.mjs`.
  if (plugin.doc.icon_url !== undefined) {
    report.error(where, `carries icon_url ${JSON.stringify(plugin.doc.icon_url)}`,
      "The signed catalogue takes a committed icon or nothing (BOT-79): an https icon is fetched from the " +
      "author's host once per listing every time a store card is drawn, and it puts unauthenticated bytes " +
      "beside authenticated ones inside a signed document. Commit the picture beside plugin.json as icon.png, " +
      ".webp, .svg, .jpg, .jpeg or .ico and name it in `icon`.");
  }

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
 * Located by [`astraPluginsCandidates`]: `$ASTRA_PLUGINS_DIR` when it is set,
 * else the usual sibling checkout — and when it is set it is the ONLY place
 * looked at. See that function for why the difference is the whole check.
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
  // Its own copy of the candidate list once, which meant its own copy of the
  // fall-through. One resolver, so one set of semantics: see
  // [`astraPluginsCandidates`].
  const specFile = astraPluginsFile("spec/icon-formats.yaml");

  if (!specFile) {
    ctx.report.note(where, "icon formats NOT verified against AstraPlugins: no checkout found",
      `Looked in ${astraPluginsCandidates().map((d) => path.join(d, "spec/icon-formats.yaml")).join(", ")}. ` +
      astraPluginsHowTo());
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

  const specFile = astraPluginsFile("spec/limits.yaml");

  if (!specFile) {
    ctx.report.note(where, `${mirrors.length} mirrored limit(s) NOT verified: no AstraPlugins checkout found`,
      `Looked in ${astraPluginsCandidates().map((d) => path.join(d, "spec/limits.yaml")).join(", ")}. ` +
      `${astraPluginsHowTo()} ` +
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

/**
 * Where an AstraPlugins checkout might be.
 *
 * **`$ASTRA_PLUGINS_DIR` is an OVERRIDE, not a first guess.** When it is set it
 * is the only directory looked at, and a file missing from it is MISSING — not
 * a reason to go and read the sibling working copy instead.
 *
 * This was a list of two tried in order until one of the *files* existed, and
 * the difference is not academic. Every one of these checks reports a missing
 * checkout as `NOT verified`, which `build-index.yml` turns into an `::error::`
 * and `exit 1`; that branch is the only thing standing between "the comparison
 * could not run" and a green tick. A list tried file-by-file means the branch
 * cannot be provoked on any machine that has AstraPlugins beside this
 * repository — point the reader at an empty directory and it quietly answers
 * from the real one. `tools/selftest/couplings.mjs`'s absent case did exactly
 * that from the day C19 landed: it asserted `NOT verified` and was handed "32
 * vectors verified" off the sibling checkout, and it only ever passed in CI,
 * where the fall-through had nothing to fall through to.
 *
 * So: set means set. A caller that wants the sibling unsets the variable —
 * `tools/signer/plan.mjs` already does precisely that.
 *
 * **Exported so that the rule can be asked of the resolver instead of inferred
 * from the resolver's surroundings** (gap 41). For a year the only thing that
 * held this was `tools/selftest/couplings.mjs`'s absent case, which provokes the
 * fall-through by pointing the reader at a fake that omits a file and looking at
 * what comes back — and that case can only tell an honoured override from an
 * empty fall-through on a machine that HAS a sibling to fall through to.
 * Measured on 2026-09-22: put the two-candidate list back and the suite is
 * `INCOMPLETE 312 passed, 0 failed` with no sibling beside this repository and
 * `FAIL 310 passed, 1 failed` with one. Every lane that runs the suite is the
 * first kind, so the regression was undetectable in every environment that runs
 * automatically.
 *
 * The length of this list is not an absence and needs no environment. Asked
 * directly it is one assertion that is red in both.
 */
export function astraPluginsCandidates() {
  const override = process.env.ASTRA_PLUGINS_DIR;
  if (override) return [override];
  return [path.resolve(REPO_ROOT, "../AstraPlugins")];
}

/**
 * What to tell a reader who was told `no checkout found`, which is a different
 * sentence depending on whether they already pointed us somewhere.
 */
function astraPluginsHowTo() {
  return process.env.ASTRA_PLUGINS_DIR
    ? `$ASTRA_PLUGINS_DIR is set to ${process.env.ASTRA_PLUGINS_DIR} and is the ONLY place looked at, so that ` +
      "is the checkout missing the file — widen the sparse-checkout that fetches it, or unset the variable to " +
      "fall back to a sibling ../AstraPlugins."
    : "Set ASTRA_PLUGINS_DIR to an AstraPlugins checkout, or put one beside this repository.";
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
      `Looked in ${astraPluginsCandidates().map((d) => path.join(d, "spec/locales.yaml")).join(", ")}. ` +
      `${astraPluginsHowTo()} ` +
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
 * checks AstraPlugins out at `ASTRA_PLUGINS_REF`, pinned in
 * `bot/manifest-probe/astra-plugins.pin` (B-T1.4; it used to be in
 * `ingest.yml`, which R6 deletes), so a
 * row added there arrives here when the pin moves — not when it merges. The
 * message names both causes because they need opposite fixes.
 */
export function checkMirroredListingLimits(ctx) {
  const where = "AstraPlugins/spec/listing-limits.yaml";
  const specFile = astraPluginsFile("spec/listing-limits.yaml");
  if (!specFile) {
    ctx.report.note("policy/limits.json", "the listing caps AstraPlugins mirrors are NOT verified: no checkout found",
      `Looked in ${astraPluginsCandidates().map((d) => path.join(d, "spec/listing-limits.yaml")).join(", ")}. ` +
      astraPluginsHowTo());
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

  // The floor, written before the comparison and not derived from it: a reader
  // that finds fewer than three rows has stopped matching the file rather than
  // found a shrinking list, and those two need opposite fixes.
  //
  // It does NOT track the row count, and that is deliberate rather than
  // neglect. This comment used to open "Four values are declared there today",
  // which was true when the file had four rows and silently false from the
  // evening it gained three more — a count in a comment beside a list is a
  // second copy of the list. What actually covers a deleted row is the reverse
  // loop at the bottom of this function, which names each `_mirrored_by` cap
  // and asks for it. The one row neither reaches is
  // `max_permission_reason_chars`, whose upstream is a JSON pointer into
  // schema/version-v1.json rather than a key in policy/limits.json, so nothing
  // here declares it; `MIN_LIMIT_ROWS` in AstraPlugins' own check-locales.py is
  // what catches its deletion, and that floor does sit at the count.
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
      "in bot/manifest-probe/astra-plugins.pin still points at a commit from before it — this job checks that " +
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
      `${astraPluginsHowTo()} Or add testdata/locales to the sparse-checkout that fetches it. ` +
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
 * The fewest digest vectors this reader may load before it concludes that IT
 * broke rather than that the table shrank.
 *
 * A floor rather than today's count, written above the reader: adding a vector
 * upstream must be free, and reading none must not be.
 */
const MIN_DIGEST_VECTORS = 20;

/**
 * The pairs in the table that must NOT hash the same.
 *
 * Each is one normalisation somebody could add to either implementation. A
 * per-vector comparison cannot see a pair that has *already* collided — both
 * halves would agree with the table and with each other, and the vector that
 * was supposed to catch that normalisation would have quietly stopped being
 * able to. So the pairs are asserted separately, here and in the CLI's reader
 * and in `digest-handcheck.sh`.
 */
const DIGEST_PAIRS = [
  ["lf", "crlf"],
  ["case-upper", "case-lower"],
  ["nfc-e-acute", "nfd-e-acute"],
  ["nfc-short-i", "nfd-short-i"],
  ["empty", "single-space"],
];

/**
 * **C19** — the lock digest, and the half of it nothing used to check.
 *
 * `locales.lock.json` records, per translated key, the first 12 hex of sha256
 * over the English bytes that translation was made against. `astra-plugin
 * locale sync` WRITES those digests (`digest` in
 * `AstraPlugins/astra-plugin-cli/src/commands/locale.rs`) and `englishDigest`
 * in `bot/lib/locales.mjs` READS them. One hash, one input, two languages, two
 * repositories — and until `testdata/locales/digest-vectors.json` existed,
 * nothing had ever compared the two. They were run against the same English
 * once and produced the same values, which is agreement by luck: no comparison
 * existed, so none could have noticed the day it stopped holding.
 *
 * What a disagreement costs is quiet and asymmetric. Either every translation
 * looks stale here — `W_LOCALE_STALE`, every card silently falling back to
 * English — while `astra-plugin check` reports the lock fresh; or a genuinely
 * stale translation is published as current. From an author's side both read as
 * nothing happening.
 *
 * **`checkLocaleCorpus` above cannot do this and could not be made to.**
 * Staleness is a NOTE in the CLI and a WARNING here, and both readers of that
 * corpus compare ERROR id sets and nothing else — so a case whose lock is one
 * hash behind proves that both sides stayed *quiet*, never that both computed
 * the *same number*. `pass/plural-families` ships digests that deliberately
 * match no English in it, which is what pins that note as a note.
 *
 * **The table was written by neither implementation.** Every digest in it is
 * what coreutils `sha256sum` returns for the vector's exact UTF-8 bytes, and
 * AstraPlugins' `couplings` job re-derives all of them that way on every run.
 * Two programs that share a mistake can agree with each other; they cannot
 * agree with coreutils — the same argument `tests/shared-vectors.mjs` makes
 * about the three bundle readers.
 *
 * Like `checkLocaleCorpus`, this needs the AstraPlugins checkout and says out
 * loud when it did not run. `build-index.yml` fetches `testdata/locales` in its
 * sparse-checkout and turns any `NOT verified` line into an `::error::` and
 * `exit 1`, on every push to `main` and every pull request, which is what stops
 * the honest answer from reading as a passing one.
 */
export function checkLocaleDigestVectors(ctx) {
  const where = "AstraPlugins/testdata/locales/digest-vectors.json";
  const rel = "testdata/locales/digest-vectors.json";
  const file = astraPluginsFile(rel);
  if (!file) {
    // **Two absences, and they need opposite fixes.** No checkout at all is a
    // workflow that did not fetch one; a checkout whose `testdata/locales` is
    // there but carries no table is a PIN older than the table, and a reader
    // told "no checkout found" in that second case goes and looks at the
    // sparse-checkout, which is already right. Both say NOT verified, because
    // `build-index.yml` turns that string into an `::error::` and neither state
    // may read as a pass.
    const corpus = astraPluginsFile("testdata/locales");
    if (corpus) {
      ctx.report.note(where,
        "the lock digest is NOT verified against AstraPlugins: the checkout has testdata/locales but no digest-vectors.json",
        `Found ${corpus} without the table, so the CHECKOUT is fine and the PIN is behind it. ` +
        "Move ASTRA_PLUGINS_REF in bot/manifest-probe/astra-plugins.pin to a master commit that carries " +
        `${rel}. Until then this side of C19 is not comparing anything, which is the state the whole coupling ` +
        "was in for a month.");
      return;
    }
    ctx.report.note(where, "the lock digest is NOT verified against AstraPlugins: no checkout found",
      `Looked in ${astraPluginsCandidates().map((d) => path.join(d, rel)).join(", ")}. ` +
      `${astraPluginsHowTo()} Or add testdata/locales to the sparse-checkout that fetches it. ` +
      "This is the only thing that compares englishDigest with the `digest` that writes the values it reads.");
    return;
  }

  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    ctx.report.error(where, `cannot be read: ${e.message}`,
      "A table this reader cannot parse is a table it is not checking, and an unparseable file must not " +
      "pass for a file with nothing in it. Re-derive it with AstraPlugins/testdata/locales/digest-handcheck.sh.");
    return;
  }

  const vectors = Array.isArray(doc?.vectors) ? doc.vectors : null;
  // The floor, BEFORE any comparison, and the two failures it separates need
  // opposite fixes: a shorter table is somebody deleting a vector upstream, and
  // an empty one is this reader pointed at the wrong file or handed a checkout
  // that did not include it.
  if (!vectors || vectors.length < MIN_DIGEST_VECTORS) {
    ctx.report.error(where,
      `found ${vectors ? vectors.length : 0} vector(s) (floor: ${MIN_DIGEST_VECTORS})`,
      "If that file still holds one object per vector under `vectors`, VECTORS are what shrank. If it does not, " +
      "this SCAN is what broke — the table moved or changed shape, and a reader that enumerates nothing passes " +
      "quietly for ever while reading as coverage.");
    return;
  }

  // Every mismatch, not the first. A normalisation added to `englishDigest`
  // breaks one CLASS of vector and leaves the rest alone, and which class it is
  // names the change — four whitespace vectors is a trim, two NFC/NFD pairs is
  // a `String.prototype.normalize`, all of them is a width or an encoding.
  const wrong = [];
  const widths = [];
  for (const v of vectors) {
    const name = String(v?.name ?? "(unnamed)");
    const english = v?.english;
    const want = v?.digest;
    if (typeof english !== "string" || typeof want !== "string") {
      ctx.report.error(where, `vector ${name} has no string \`english\`/\`digest\``,
        "Every vector is { name, english, digest, catches }. A vector this reader cannot read is a vector it is not checking.");
      continue;
    }
    const got = englishDigest(english);
    if (got !== want) wrong.push(`${name}: sha256sum says ${want}, englishDigest says ${got} — it catches: ${v?.catches ?? "(nothing written down)"}`);
    if (!/^[0-9a-f]{12}$/.test(got)) widths.push(`${name}: ${JSON.stringify(got)}`);
  }

  for (const w of wrong) {
    ctx.report.error(where, w,
      "The rule is the first 12 hex of sha256 over the EXACT English UTF-8 bytes, with no normalisation of either " +
      "side. A digest this repository computes differently from `astra-plugin locale sync`'s makes every recorded " +
      "entry look stale — W_LOCALE_STALE on every listing, every translated card silently falling back to English — " +
      "while `astra-plugin check` reports the lock fresh. Re-derive the table with " +
      "AstraPlugins/testdata/locales/digest-handcheck.sh before believing it is the table that is wrong.");
  }

  // The width, said separately. A `slice(0, 12)` that becomes `slice(0, 16)` is
  // one of the two changes gap 9 was recorded for, and it would otherwise
  // arrive as thirty-odd identical-looking mismatches with no sentence naming
  // the one thing they have in common.
  for (const w of widths) {
    ctx.report.error(where, `englishDigest returned ${w}, which is not 12 lower-case hex`,
      "The lock has one rule and that is it. A width or case change here is silent on this side and turns every " +
      "digest `astra-plugin locale sync` ever wrote into a mismatch.");
  }

  const by = new Map(vectors.filter((v) => typeof v?.english === "string").map((v) => [String(v.name), v.english]));
  for (const [a, b] of DIGEST_PAIRS) {
    if (!by.has(a) || !by.has(b)) {
      ctx.report.error(where, `the pair ${a} / ${b} is not both in the table`,
        "That pair exists because one normalisation added to one side of C19 would make its two halves equal. " +
        "A pair with a missing half asserts nothing, and it looks exactly like a pair that passed.");
      continue;
    }
    if (englishDigest(by.get(a)) === englishDigest(by.get(b))) {
      ctx.report.error(where, `the pair ${a} / ${b} hashes the same here`,
        "So the normalisation that pair exists to catch is already in englishDigest — or the two vectors were " +
        "edited into each other upstream. Either way every per-vector comparison above still passes, which is why " +
        "this is asked separately.");
    }
  }

  ctx.report.note(where,
    `${vectors.length} lock digest vector(s) verified against englishDigest; ${DIGEST_PAIRS.length} non-collision pair(s) hold`);
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

// ── MIG-20's baseline marker ────────────────────────────────────────────────

/**
 * What `log/baseline.json` may hold, and the grammar of each member.
 *
 * An ALLOWLIST, for the reason `bot/export-issues.mjs` gives at length: PRIV-2
 * keeps names out of git, and "does this value look like a person" has no safe
 * answer for a value that could be anything. "Is this a count" has one. The
 * marker is name-free by construction if and only if every member it may hold
 * is a schema string, a §0.7 time, a commit or a number — so a member nobody
 * listed is refused outright rather than passed through.
 *
 * `source_commit` is NOT in the plan's sentence and is here on purpose; the
 * reason is in `checkBaselineMarker` below.
 */
const BASELINE_MEMBERS = {
  schema: (v) => v === BASELINE_SCHEMA,
  written_at: (v) => isTime(v),
  source_commit: (v) => typeof v === "string" && /^[0-9a-f]{40}$/.test(v),
  version_count: (v) => Number.isInteger(v) && v >= 0,
  record_count: (v) => Number.isInteger(v) && v >= 0,
};

/**
 * The marker MIG-20's baseline is recognised by, checked when it is there.
 *
 * **Why this check exists at all, when nothing rejected the file before it.**
 * The plan's line is "`tools/validate.mjs` and `tools/lib/sources.mjs` accept
 * `log/baseline.json`", which reads like the removal of a refusal. There is no
 * refusal to remove: a `log/` directory was written into this tree and both
 * tools stayed green and silent, because neither has ever looked outside
 * `plugins/**`. That silence is the defect. Four mechanisms key on this file —
 * B-T3.7's legacy writer, detector A1's ignore set (BOT-75), MIG-28's hold, and
 * B-T3.6 step 0 — and it is written once, by one dispatch, by a job that then
 * never runs again. A marker with a mistyped schema string or a count that lies
 * would be read by all four as the thing they were waiting for. So "accept"
 * means "know about", and this is what knowing about it looks like.
 *
 * **The counts are compared with the tree, in the one direction that stays
 * true.** `version_count` is the number of non-staging published versions at
 * the commit the baseline was taken over. Versions are added afterwards and
 * never removed — a delisted listing keeps its version files, "because they
 * were published and signed" (`plugins/astra-chess/plugin.json`) — so the count
 * may fall behind the tree and may never exceed it. A marker claiming more
 * versions than the tree holds means a baselined version file has been deleted,
 * which orphans its `migration` record and silently shrinks the population
 * ROLL-42 and M-T8.1 compare. That is an error. Being behind is not.
 */
export function checkBaselineMarker(plugins, ctx) {
  const { report } = ctx;
  const loaded = loadBaseline(ctx.root);
  if (loaded === null) {
    report.note(
      BASELINE_FILE,
      "absent: MIG-20's baseline has not been written, so B-T3.7's legacy writer stays off, detector A1 skips " +
      "and MIG-28 holds every id with no baseline",
      "This is the state before R3. B-T3.7b's single dispatch writes it.",
    );
    return;
  }
  if (loaded.error) {
    report.error(loaded.file, `is not readable JSON — ${loaded.error}`,
      "Four mechanisms read this file. An unreadable one is not a soft failure for any of them.");
    return;
  }

  const doc = loaded.doc;
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    report.error(loaded.file, "is not a JSON object");
    return;
  }

  for (const member of Object.keys(doc)) {
    if (!Object.prototype.hasOwnProperty.call(BASELINE_MEMBERS, member)) {
      report.error(loaded.file, `carries ${JSON.stringify(member)}, which is not a member this marker may hold`,
        `The marker is name-free by allowlist: ${Object.keys(BASELINE_MEMBERS).join(", ")} and nothing else.`);
    }
  }
  for (const [member, grammar] of Object.entries(BASELINE_MEMBERS)) {
    if (doc[member] === undefined) {
      report.error(loaded.file, `is missing ${JSON.stringify(member)}`);
    } else if (!grammar(doc[member])) {
      report.error(loaded.file, `${member} is ${JSON.stringify(doc[member])}, which is not the thing it claims to be`);
    }
  }
  if (report.errors.some((e) => e.where === loaded.file)) return;

  // A baseline over nothing is a baseline that did not run. The same floor
  // `bot/export-issues.mjs --facts` takes on its own output, for the same
  // reason: the failure mode is a `verify` job that returned an empty list and
  // a `write` job that committed the marker anyway, with nothing red.
  if (doc.version_count === 0) {
    report.error(loaded.file, "records a baseline over zero versions",
      "MIG-20's population is every non-staging published version, and this tree has some. A zero count is a run " +
      "that stopped working, not a registry with nothing in it.");
  }
  if (doc.record_count < doc.version_count) {
    report.error(loaded.file,
      `records ${doc.record_count} record(s) for ${doc.version_count} version(s)`,
      "MIG-20 asks for one `migration` record per non-staging published version, and MIG-21's historic export " +
      "adds more on top. Fewer records than versions is a write that lost some.");
  }

  const inTree = nonStagingVersions(plugins).length;
  if (doc.version_count > inTree) {
    report.error(loaded.file,
      `claims ${doc.version_count} non-staging published version(s) and this tree holds ${inTree}`,
      "Versions are added after the baseline and never removed — a delisted listing keeps its version files. A " +
      "count above the tree means a baselined version file was deleted, orphaning its `migration` record.");
  } else if (doc.version_count < inTree) {
    report.note(loaded.file,
      `baselined ${doc.version_count} version(s); ${inTree - doc.version_count} have been published since`);
  }
}

// ── MIG-1's two records: the deadline and the cutover marker ────────────────

/**
 * `policy/binding-deadline.json` and `log/cutover.json`, checked when they are
 * there (registry plan M-T5.1; contract B.4).
 *
 * **Why a validator at all, for two files with two members each.** Between them
 * they decide every listing's state: MIG-1 grandfathers a listing with no
 * identity record until the LATER of the deadline and cutover, and freezes it
 * afterwards. Four readers act on that — the bot through
 * `bot/lib/listing-state.mjs`, the plugins service from git at the served
 * `Source-Commit` (MIG-7), the listing banner that tells third-party accounts
 * the date (MIG-13), and `bot/tests/policy.test.mjs`, which holds POLICY.md to
 * quoting it (MIG-3). Both files are written by hand — the owner commits the
 * deadline (MIG-2), the cutover commit adds the marker (ROLL-33) — and neither
 * has ever been read by anything in this repository, so a mistyped member would
 * have reached all four as the thing they were waiting for.
 *
 * **Absent is a state, not a finding.** Neither file exists today, and that is
 * the ordinary state: no deadline means everything unbound stays
 * `grandfathered` and nothing alerts (BOT-72), no marker means cutover has not
 * happened. Both are notes, so a reader can tell "checked and absent" from "not
 * checked".
 *
 * **The grammar cannot say the date is real.** `2026-02-31T00:00:00Z` matches
 * the pattern in both schemas, and `Date` rolls it forward to 3 March rather
 * than refusing. So each value is round-tripped through the same `parseTime`
 * the bot's reader uses — one grammar, in one place, rather than a second
 * opinion here.
 */
export function checkMigrationMarkers(ctx) {
  const { report } = ctx;
  const specs = [
    { file: DEADLINE_FILE, member: "deadline", schemaString: DEADLINE_SCHEMA, schema: deadlineSchema(REPO_ROOT),
      absent: "absent: no binding deadline is committed, so every listing with no identity record — and none ever — " +
        "is `grandfathered` and nothing alerts (MIG-1, BOT-72)",
      absentHint: "The owner commits it before R4b (MIG-2), with the same date in POLICY.md (MIG-3)." },
    { file: CUTOVER_FILE, member: "cutover_at", schemaString: CUTOVER_SCHEMA, schema: cutoverSchema(REPO_ROOT),
      absent: "absent: cutover has not happened, so the issue channel is still open and no listing freezes (MIG-1, ROLL-33)",
      absentHint: "Only the cutover commit adds it." },
  ];

  const times = {};
  for (const spec of specs) {
    const abs = path.join(ctx.root, spec.file);
    if (!fs.existsSync(abs)) {
      report.note(spec.file, spec.absent, spec.absentHint);
      continue;
    }
    let doc;
    try {
      doc = readJson(abs);
    } catch (e) {
      report.error(spec.file, `is not readable JSON — ${e.message}`,
        "Four readers key on this file. An unreadable one is not a soft failure for any of them.");
      continue;
    }
    const problems = validateSchema(spec.schema, doc, "$");
    for (const p of problems) {
      report.error(spec.file, `${p.path} ${p.message}`,
        `B.4 fixes ${spec.schemaString}'s members exactly; the plugins service parses this record too.`);
    }
    if (problems.length) continue;
    try {
      times[spec.member] = parseTime(doc[spec.member], `${spec.file}'s \`${spec.member}\``);
    } catch (e) {
      report.error(spec.file, e.message,
        "The pattern admits dates that are not moments; this is the round-trip that does not.");
    }
  }

  // MIG-2's floor, which is a fact about the two files TOGETHER: the deadline
  // is kept at least 30 days after cutover, and ROLL-32 refuses to begin
  // cutover unless it is. Nothing else compares them — the bot reads each on
  // its own and the service reads them at a served commit — so if this check
  // does not make the comparison, nobody does.
  //
  // A WARNING RATHER THAN AN ERROR, deliberately. This tool gates the signer
  // (D4), and an error here would stop the catalogue over a policy date that
  // changes no listing's bytes: a self-inflicted outage in the one job whose
  // failure users see. The fix is the owner's (MIG-29 lets him move the date
  // later and never earlier), and it wants a person, not a red signer.
  if (times.deadline !== undefined && times.cutover_at !== undefined) {
    const days = (times.deadline - times.cutover_at) / 86_400_000;
    if (days < 30) {
      report.warn(DEADLINE_FILE,
        `is ${days.toFixed(1)} day(s) after ${CUTOVER_FILE}'s cutover_at, and MIG-2 keeps it at least 30`,
        "MIG-29 permits moving the deadline later and never earlier, and ROLL-32 holds cutover until the deadline " +
        "is at least 30 days away. Not an error only because this tool gates the signer.");
    }
  }
}

// ── MIG-13's migration-notice markers (contract B.4, 0.31.0) ──────────────

/** `log/migration-notice-<n>.json` — one per MIG-13 round (B.4). */
export const NOTICE_DIR = "log";
export const NOTICE_NAME = /^migration-notice-(\d+)\.json$/;
export const NOTICE_SCHEMA = "astra.registry.migration-notice/1";

/**
 * Every migration-notice marker on the tree, judged against
 * `schema/migration-notice-v1.json` (contract B.4 from 0.31.0; MIG-13; MIG-14).
 *
 * **Why here, and why an error.** The marker is written by a person committing
 * a file with each round's sends (registry plan M-T5.3), and the first program
 * that ever read one was ROLL-32's cutover preflight — at R6, months after
 * round 1 lands at R4b. A marker spelling its round `"1"` would have passed
 * every check between the two and been found at the gate that decides whether
 * the catalogue may move (dev/couplings.md entry 58). Judged here, it is
 * refused on the pull request that commits it, which is where the person who
 * can fix it is standing. It is an ERROR for the reason every B.4 record is:
 * the plugins service parses this file too, and a marker one party admits and
 * another refuses is a two-way-test failure (§0.8) found in production.
 *
 * **What this does not judge, and says so.** That a file's `<n>` is its
 * `round`, that there is one marker per round, and that no marker announces a
 * superseded date are facts about several files and about the procedure, not
 * about one record, and no published sentence states the first of them; the
 * preflight asks all three. A file under `log/` whose name is not
 * `migration-notice-<digits>.json` is not a marker to any reader and is not
 * judged here.
 *
 * **Absent is a state, not a finding.** No marker is the ordinary state until
 * ROLL-26 sends round 1, so it is a note — a reader can tell "checked and
 * absent" from "not checked".
 */
export function checkNoticeMarkers(ctx) {
  const { report } = ctx;
  const where = `${NOTICE_DIR}/migration-notice-<n>.json`;
  const dir = path.join(ctx.root, NOTICE_DIR);
  const files = fs.existsSync(dir)
    ? fs.readdirSync(dir).filter((f) => NOTICE_NAME.test(f)).sort()
    : [];
  if (!files.length) {
    report.note(where, "absent: no MIG-13 round has been sent, so there is no marker to judge",
      "ROLL-26 sends round 1 the day R4b opens; its marker is committed with the sends (registry plan M-T5.3).");
    return;
  }
  for (const name of files) {
    const file = `${NOTICE_DIR}/${name}`;
    for (const p of noticeMarkerProblems(fs.readFileSync(path.join(dir, name), "utf8"), ctx.schemas.migrationNotice)) {
      report.error(file, p.message, p.hint);
    }
  }
}

/**
 * Everything B.4 says a marker's TEXT must be, as a list of problems — empty
 * when the marker is one. Pure, and exported, so the selftest judges exactly
 * what `checkNoticeMarkers` judges rather than a copy of it.
 *
 * Three readings, because a parsed document cannot carry all of B.4:
 *
 *   * the schema, over the parsed value — members, types, the ceiling, the
 *     condition on `cutover_planned_at`, and each time's field ranges;
 *   * the RAW TEXT of `round`, through tools/lib/json-literal.mjs: exactly one
 *     top-level `round`, written `1` and never `1.0`, `1e0` or `1E0`, which
 *     are the value 1 to the schema and to `JSON.parse` and are refused by the
 *     plugins service's reader. A duplicate `round` is refused outright,
 *     because JSON.parse keeps the last and a reader that keeps the first
 *     would see a different round;
 *   * each time round-tripped through `parseTime` — `Date`, and the ISO string
 *     compared — so that a day that does not exist (`2026-02-30`) is refused
 *     where the pattern cannot see it. Second 60 and hour 24 are refused by
 *     the pattern and by the round trip both.
 *
 * NOT READ: any other member's literal, and duplicates of any other member.
 *
 * @returns {{message: string, hint: string}[]}
 */
export function noticeMarkerProblems(text, schema) {
  const typesHint =
    `B.4 fixes ${NOTICE_SCHEMA}'s members exactly and, from contract 0.31.0, their types: \`round\` a JSON ` +
    "integer from 1 to 4294967295 written with no fraction part and no exponent, `sent_at` and " +
    "`cutover_planned_at` §0.7 times naming a real UTC instant with no second 60, the date carried exactly from round 2.";
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return [{ message: `is not readable JSON — ${e.message}`,
      hint: "The cutover preflight, the deadline watch and the plugins service's banner all read this file." }];
  }
  const problems = validateSchema(schema, doc, "$").map((p) => ({ message: `${p.path} ${p.message}`, hint: typesHint }));
  let members = [];
  try {
    members = topLevelMembers(text);
  } catch (e) {
    problems.push({ message: `is not a JSON object — ${e.message}`, hint: typesHint });
    return problems;
  }
  const rounds = members.filter((m) => m.name === "round");
  if (rounds.length > 1) {
    problems.push({
      message: `carries ${rounds.length} \`round\` members; JSON.parse keeps the last and a reader that keeps the first sees another round`,
      hint: typesHint,
    });
  }
  for (const r of rounds) {
    if (!POSITIVE_INTEGER_LITERAL.test(r.raw)) {
      problems.push({
        message: `\`round\` is written ${r.raw}, and B.4 writes it as an integer with no fraction part and no exponent (\`1\`, never \`1.0\` or \`1e0\`)`,
        hint: typesHint,
      });
    }
  }
  const failedAt = new Set(problems.map((p) => p.message.split(" ")[0]));
  for (const member of ["sent_at", "cutover_planned_at"]) {
    if (doc === null || typeof doc !== "object" || doc[member] === undefined || failedAt.has(`$.${member}`)) continue;
    try {
      parseTime(doc[member], `\`${member}\``);
    } catch (e) {
      problems.push({ message: e.message,
        hint: "B.4: a real UTC instant. The pattern admits days that do not exist; ROLL-32 and ROLL-63 count days from this one." });
    }
  }
  return problems;
}

// ── B.4's other records (registry plan B-T2.1) ──────────────────────────────

/**
 * A `decided_at` that a pattern accepts and a clock does not.
 *
 * The same second half checkMigrationMarkers applies to the deadline: the
 * pattern admits `2026-02-31T00:00:00Z`, and a date two independent
 * implementations compare a clock against has to be a moment.
 */
function unreadableTime(value, what) {
  try {
    parseTime(value, what);
    return null;
  } catch (e) {
    return e.message;
  }
}

/**
 * Is this DEC-7's author-action record?
 *
 * DISCRIMINATED BY `reasons`, AND NOT BY `actor`, which is the reading that
 * looks obvious and is wrong. `actor` `author` is a legitimate value on the
 * SUBMISSION record too — an `A_WITHDRAW` or an `A_STOP` is an author's act on
 * a submission, and those records carry a `submission_id` and must. DEC-7 ties
 * the author-action shape to one code: it is "one further file, per version an
 * `A_YANK` names", `reasons` `["A_YANK"]`. So the code is the discriminant, and
 * discriminating on `actor` would have refused `submission_id` on every record
 * an author ever caused — a rule that is red on correct records and silent on
 * the one it was written for.
 */
function isAuthorAction(doc) {
  const r = doc?.reasons;
  return Array.isArray(r) && r.length === 1 && r[0] === "A_YANK";
}

/**
 * The two rules `schema/decision-v1.json` cannot state and `schema/queue-v1.json`
 * will not yet, plus the schema check for all four of B.4's other record trees.
 *
 * WHY THE CONDITIONALS ARE HERE AND NOT IN THE SCHEMAS. tools/lib/jsonschema.mjs
 * implements no `if`/`then`/`else`, and it does not ignore an unknown keyword —
 * it throws, deliberately, because "a validator that silently ignores the one
 * keyword the schema author was relying on is worse than no validator". So a
 * conditional written into a schema file would not be a weak check; it would be
 * a tool that refuses to run. `oneOf` could express the decision record's two
 * shapes, and the reason not to reach for it is the error message: a record
 * that fails a two-branch `oneOf` reports "matches 0 of the allowed shapes",
 * which tells an author nothing about WHICH member was wrong on the branch they
 * meant. These say it.
 */
export function checkRecords(ctx, sources, records = loadRecords(ctx.root, sources)) {
  const { report, schemas } = ctx;
  const { identities, decisions, alerts, queue, errors } = records;

  for (const e of errors) report.error(e.file, e.message);

  // ── identity records: B.4's six, exactly ──────────────────────────────────
  for (const { file, doc } of identities) {
    const problems = validateSchema(schemas.identity, doc, "$");
    for (const p of problems) {
      report.error(file, `${p.path} ${p.message}`,
        `B.4 fixes ${IDENTITY_SCHEMA}'s members exactly ("has exactly these required members"); the plugins ` +
        "service parses this record to decide whether a submission is `bound` (ID-15).");
    }
    if (problems.length) continue;
    const dir = file.split("/")[1];
    if (doc.plugin_id !== dir) {
      report.error(file, `plugin_id ${JSON.stringify(doc.plugin_id)} is not the listing it sits in (${dir})`,
        "ID-41 and TRUST-23 compare a certificate against the record for THE LISTING BEING PUBLISHED, found by " +
        "path. A record naming another id is one that will be read for this listing and believed about another.");
    }
  }

  // ── decision records: DEC-7's members, and the shape a schema cannot pick ──
  for (const { file, doc } of decisions) {
    const problems = validateSchema(schemas.decision, doc, "$");
    for (const p of problems) {
      report.error(file, `${p.path} ${p.message}`,
        `DEC-7's sentence is "with only these members, absent where they do not apply", and ${DECISION_SCHEMA} ` +
        "is read by the plugins service, the panel and a guest (SCOPE-3).");
    }
    if (problems.length) continue;

    const bad = unreadableTime(doc.decided_at, `${file}'s \`decided_at\``);
    if (bad) {
      report.error(file, bad,
        "The pattern admits dates that are not moments; this is the round-trip that does not.");
      continue;
    }

    // The name IS the id, and the directories ARE the month. bot/lib/decisions.mjs's
    // `recordPath` derives both from the record; a file that disagrees with its
    // own contents is one BOT-36's dedupe looks for under a path it is not at,
    // and the second write lands somewhere else with nothing red anywhere.
    const expected = `${DECISIONS_DIR}/${doc.decided_at.slice(0, 4)}/${doc.decided_at.slice(5, 7)}/${doc.decision_id}.json`;
    if (file !== expected) {
      report.error(file, `is not where its own contents put it (${expected})`,
        "`decision_id` is the basename and `decided_at` is the two directories (DEC-7; registry plan BOT-35). " +
        "A record found only by a path nobody derives is a record BOT-36 will write a second copy of.");
    }

    if (!isAuthorAction(doc)) continue;

    // DEC-7's author-action record, and the rule the schema library has no
    // conditional for. `refuseUncomposableAuthorAction` is bot/lib/decisions.mjs's
    // own refusal, called here rather than restated: the writer and the
    // validator disagreeing about DEC-7's thirteen members is exactly the
    // two-answer failure this whole task exists to stop, and a second copy of
    // the list is how that starts.
    const { schema: _s, decision_id: _d, ...rest } = doc;
    try {
      refuseUncomposableAuthorAction(rest);
    } catch (e) {
      report.error(file, e.message,
        `An author-action record carries exactly DEC-7's ${AUTHOR_ACTION_MEMBERS.length} members ` +
        `(${AUTHOR_ACTION_MEMBERS.join(", ")}) and none of ${AUTHOR_ACTION_FORBIDDEN.join(", ")}. The service's ` +
        "detector B row 2 matches such a record BY its having no `submission_id`, so one that carries either is " +
        "classified over there as something else entirely (FLOW-79; BOT-34).");
    }
  }

  // ── queue entries: the floor the service reads, for entries that claim it ──
  for (const { file, doc } of queue) {
    if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
      report.error(file, "is not a JSON object");
      continue;
    }
    if (!Object.hasOwn(doc, "schema")) {
      // Contract §214, in its own words: "today's entries carry neither id nor
      // `schema`". Refusing them would make this tool red about twenty-odd
      // files git already carries, for a member BOT-38 has not required yet.
      report.note(file, `carries no \`schema\`, so it is a pre-BOT-38 queue entry and ${QUEUE_SCHEMA} does not apply`,
        "BOT-38 adds `schema`, `submission_id` and `decision_id` to the entries the service path writes. Until " +
        "then bot/publish-apply.mjs owns this shape and the record is not one other parties read.");
      continue;
    }
    for (const p of validateSchema(schemas.queue, doc, "$")) {
      report.error(file, `${p.path} ${p.message}`,
        `This entry declares itself ${QUEUE_SCHEMA}, which B.4 lets the plugins service read. An entry that ` +
        "claims the schema and then omits a member the service reads is a different thing from an entry " +
        "written before the member existed, and only the first is a defect (registry plan BOT-38).");
    }
    if (typeof doc.publish_after === "string") {
      const bad = unreadableTime(doc.publish_after, `${file}'s \`publish_after\``);
      if (bad) report.error(file, bad, "The pattern admits dates that are not moments.");
    }
  }

  // ── alert records: the path is accepted; the members are RC-R1-4's ────────
  for (const { file, doc } of alerts) {
    if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
      report.error(file, "is not a JSON object");
      continue;
    }
    if (typeof doc.schema !== "string" || doc.schema.length === 0) {
      report.error(file, "carries no `schema` string",
        "Every record in this repository that another party may read says what it is. This one's member set is " +
        "contract TRUST-14's and registry plan RC-R1-4's to fix; until that schema exists this is the whole of " +
        "what can be checked, and it is checked rather than assumed.");
    }
  }
  if (alerts.length) {
    report.note(ALERTS_DIR,
      `${alerts.length} alert record(s) accepted by path and not schema-checked: TRUST-14's member set is ` +
      "RC-R1-4's schema to write, and inventing one here would put a second, older answer in the tree",
      "This note exists so a reader meets the gap rather than reading a silent pass as a check.");
  }
}

/**
 * BOT-34's second Check clause: n versions yanked under an `A_YANK`, n records.
 *
 * NO PER-RECORD SCHEMA CAN EXPRESS THIS, and that is not a limitation of the
 * schema library — it is a statement about a SET of files in which every member
 * can be individually valid while the set is wrong. An `A_YANK` names listed
 * versions, PLURAL; DEC-7's `version` is a single member; so a yank of three
 * versions is three records, and the failure mode is a compiler written against
 * the submission path, where one submission is one release, emitting one.
 *
 * The count is taken over the tree rather than over a commit's diff, which is
 * what makes it runnable here at all — and it is the same count: the moderation
 * entry states which versions the yank covered, and the decision log either has
 * a record per version or does not.
 *
 * ── WHICH LOG ENTRIES ARE AUTHOR YANKS, AND WHY THAT IS NOT OBVIOUS ─────────
 *
 * `action: yank` with `category: author_request` is NOT the same set as "an
 * `A_YANK`". FLOW-79 sends the author of an UNBOUND listing to a moderator —
 * "its author asks a moderator (`M_YANK`, category `author_request`) until it
 * is bound" — and §7.2's category table allows `author_request` on `M_YANK`.
 * An `M_YANK` writes no author-action record (BOT-34 writes them "for an
 * `A_YANK`" and instead of a submission record), so counting one here refuses a
 * legal tree for carrying zero of the records it does not owe.
 *
 * The log entry cannot say which: MOD-47 fixes its member set and neither the
 * decision code nor a moderator handle is in it (PRIV-2 keeps the handle out).
 * What separates them is the REASON. An `A_YANK`'s log reason is the one fixed
 * registry string SCOPE-7's file lists for that code, which no moderator and no
 * author types (BOT-80; DEC-14; MOD-41), and `bot/lib/compile-decision.mjs`
 * compiles exactly that string. An `M_YANK` carries the moderator's own MOD-48
 * reason, which MOD-41 requires to be 10 to 300 code points of free-ish text.
 *
 * **Today that string is not published**, so the discriminant falls back to
 * (action, category) and a note says so. The fallback is the strict direction —
 * it reads an `M_YANK` with `author_request` as an author yank and asks it for
 * records — and it is live rather than dormant, which matters because no yank
 * of either kind is on `main` yet and a check that waited for ops.15 would be
 * a check nobody had ever seen run.
 */
export function checkAuthorActionRecords(ctx, sources, records = loadRecords(ctx.root, sources)) {
  const { report } = ctx;
  const { decisions } = records;
  const { entries, files } = loadModerationEntries({ root: ctx.root });

  // Read from REPO_ROOT and never from the tree under test: this is a contract
  // fact, and `--registry-dir` supplies sources to be judged, not the rules it
  // is judged by. `ctx.authorYankReason` is how `runValidation` hands it over,
  // and how a test supplies one without a published token file.
  const fixed = Object.hasOwn(ctx, "authorYankReason")
    ? ctx.authorYankReason
    : fixedReason("A_YANK", { root: REPO_ROOT });

  const allYanks = entries.map((doc, i) => ({ doc, file: `${MODERATION_DIR}/${files[i]}` }))
    .filter(({ doc }) => doc.action === "yank" && doc.category === "author_request");

  const yanks = fixed === null ? allYanks : allYanks.filter(({ doc }) => doc.reason === fixed);

  if (fixed === null && allYanks.length > 0) {
    report.note(MODERATION_DIR,
      `${allYanks.length} \`author_request\` yank(s) are being counted as \`A_YANK\`s by action and category ` +
      "alone, because `schema/contract-tokens-v1.json` carries `fixed_reasons: null`",
      "SCOPE-7's fixed `A_YANK` reason is what tells an author's yank from an `M_YANK` a moderator took on an " +
      "unbound listing's behalf (FLOW-79), and it lands with contract version ops.15. Until it does this check " +
      "is strict in the safe direction — it asks an `M_YANK` for records it does not owe, which is a red a " +
      "person resolves, rather than letting a short-counted `A_YANK` through, which nothing else catches.");
  }
  if (yanks.length === 0) return;

  const authorActions = decisions.filter(({ doc }) => isAuthorAction(doc));

  for (const { doc, file } of yanks) {
    const versions = Array.isArray(doc.versions) ? doc.versions : [];
    if (versions.length === 0) {
      report.error(file, "is an author yank naming no version",
        "FLOW-79's `A_YANK` names at least one listed version. A yank that yanked nothing passes a count of " +
        "zero against zero, which is the one way this check could be satisfied by a record that says nothing.");
      continue;
    }

    const mine = authorActions.filter(({ doc: d }) => d.plugin_id === doc.plugin && versions.includes(d.version));
    const covered = new Set(mine.map(({ doc: d }) => d.version));
    const missing = versions.filter((v) => !covered.has(v));

    if (missing.length) {
      report.error(file,
        `yanks ${versions.length} version(s) of ${doc.plugin} and the decision log carries ${covered.size} ` +
        `author-action record(s); no record for ${missing.join(", ")}`,
        "BOT-34: a commit whose changed listings show n versions moved to `yanked` under an `A_YANK` carries n " +
        "author-action records, one per version, and is refused otherwise. BOT-35's second tuple carries " +
        "`version` precisely so their ids differ; one record with a joined `version` is the shape a composer " +
        "written against the submission path produces, and it is not a semver, so it never reaches this count.");
    }
    if (mine.length > covered.size) {
      report.error(file,
        `${mine.length} author-action records cover ${covered.size} version(s) of ${doc.plugin}`,
        "Two records for one version derive one id from BOT-35's tuple, so one of them has overwritten the " +
        "other and the log is short a decision.");
    }

    // The other half of BOT-34's sentence: the listings must actually show it.
    for (const version of versions) {
      const entry = (sources?.plugins ?? []).find((p) => p.dir === doc.plugin);
      const record = entry?.versions?.find((v) => v.basename === version);
      if (!record) continue; // a yank of a version this tree does not carry is MOD-33's to report
      if (record.doc?.yanked !== true) {
        report.error(record.file, `is named by the author yank in ${file} and is not \`yanked\``,
          "The log entry and the listing are two halves of one act (bot/moderation/README.md: a yank IS " +
          "`\"yanked\": true` on the version record). A published entry whose listing does not show it is the " +
          "registry claiming a takedown it did not take.");
      }
    }
  }
}

// ── publisher records (gap 91) ──────────────────────────────────────────────

/**
 * Every `publishers/*.json` against `schema/publisher-v1.json`, at the first
 * gate.
 *
 * Until this function, `loadSchemas().publisher` was loaded by the bot's own
 * loader, sat in TRUST-31's hashed set, and was read by nothing that judged a
 * record: this file never mentioned publishers, and the one judge was
 * `tools/selftest/publishers.mjs`, which opened the schema file itself and
 * runs as the FIFTH of the five checks `bot/publish-apply.mjs` makes.
 *
 * What that left, measured on 2026-09-22 at `95a6e5a`: `checkIndex` holds the
 * five members the index CARRIES to `schema/index-v1.json`, and only for a
 * record some listing reaches, only in index mode, and naming
 * `registry/v1/index.json` rather than the record. So `publishers/KnlCE.json`
 * with `display_name: 42` and domain evidence missing `domain` and `proof`
 * passed this file with 0 errors in both modes — it reaches no listing, so it
 * is in no index — and `publishers/mihailinl.json` with `tier: "community"`
 * passed under `--no-index`, which is how the publish path's first check runs.
 * `owner`, `covers`, `evidence` and `expires_at` are in no index at all.
 *
 * The schema is `ctx.schemas.publisher`: `runValidation` takes it from
 * `loadSchemas(REPO_ROOT)`, THIS repository's copy and never the tree under
 * test's, for the reason every other record schema here is taken that way.
 * A second read of the file would be a second answer to "which schema judges
 * a publisher", and the selftest holds this function to the one it is handed.
 *
 * The loader's own refusals are reported first, as `checkRecords` reports
 * `loadRecords`'. `loadPublishers` drops a record whose `owner` is not its file
 * name, or whose `owner` or `covers` claims a login another record already
 * holds, and a dropped record is one no schema check below can see — so
 * without these lines it would be invisible here rather than refused.
 * `build-index.mjs` throws on the same list; in `--no-index` mode, which is how
 * the publish path's first check runs, nothing else would say it.
 *
 * Each record is judged once, not once per login it covers: `publisherRecords`
 * and not the map's values, which yield a `covers` record under every key.
 */
export function checkPublisherRecords(ctx, loaded = loadPublishers(ctx.root)) {
  const { report, schemas } = ctx;
  for (const e of loaded.errors) report.error(e.file, e.message);
  for (const { file, doc } of publisherRecords(loaded.publishers)) {
    for (const p of validateSchema(schemas.publisher, doc, "$")) {
      report.error(file, `${p.path} ${p.message}`,
        "schema/publisher-v1.json. A publisher record is joined into `signed.publishers`, inside the signature a " +
        "client verifies, and a client renders the badge on exact membership of `tier`; a member of the wrong " +
        "shape is a claim the registry signs without having checked (docs/POLICY.md §7).");
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
    // SCOPE-7's fixed `A_YANK` reason, from THIS repository's token file for the
    // same reason `schemas` and `policy` are: it is a rule, not a source.
    // `null` until contract version ops.15 publishes it; see
    // `checkAuthorActionRecords` for what the null does.
    authorYankReason: fixedReason("A_YANK", { root: REPO_ROOT }),
  };

  checkMirroredLimits(ctx);
  checkMirroredIconFormats(ctx);
  checkEveryCapDeclaresItsAuthorSide(ctx);
  checkMirroredListingLimits(ctx);
  checkLocaleVocabulary(ctx);
  checkLocaleCorpus(ctx);
  checkLocaleCorpusCoverage(ctx);
  checkLocaleDigestVectors(ctx);

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
  checkBaselineMarker(usable, ctx);
  checkMigrationMarkers(ctx);
  checkNoticeMarkers(ctx);

  // B.4's other record trees, walked once and handed to both checks: the
  // second one counts author-action records against the yanks a moderation
  // entry names, and a second walk would be a second answer to "what is in the
  // decision log" taken a moment apart.
  const records = loadRecords(opts.root, { plugins: usable });
  checkRecords(ctx, { plugins: usable }, records);
  checkAuthorActionRecords(ctx, { plugins: usable }, records);
  checkPublisherRecords(ctx);

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
