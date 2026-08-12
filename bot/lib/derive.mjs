// The listing, written from the bundle.
//
// PRODUCTION_PLAN §3.5: the submitter types **two facts** — the repository and
// the release tag — and nothing else. Id, version, name, summary, licence,
// capabilities, permissions, platforms, digests and sizes are read out of the
// attested bundle.
//
// That is not a convenience. Everything derived here is covered by the build
// attestation, which makes it strictly more trustworthy than anything a person
// typed into a form, and it deletes an entire rejection class: there is no
// "your checkbox disagrees with plugin.toml" here, because there is no
// checkbox. The two facts that *are* typed are exactly the two the bundle
// cannot vouch for — which repository the bytes came from, and which release —
// and both are then checked against GitHub rather than believed.
//
// What this module does NOT decide: whether the listing is allowed. It builds
// the documents; `bot/ingest.mjs` runs them past the same `tools/validate.mjs`
// that guards every hand-written listing in this repository, so the bot's
// output is held to the rules its input would have been.

import { unsafeDisplayText } from "../../tools/lib/ids.mjs";
import { README_NAME, checkIcon, pickIcon, rewriteReadme } from "./assets.mjs";

/** Trim to a length without cutting a word or leaving a dangling space. */
function summarise(text, max) {
  const flat = String(text).replace(/\s+/g, " ").trim();
  if (flat.length <= max) return flat;
  const cut = flat.slice(0, max - 1);
  const lastSpace = cut.lastIndexOf(" ");
  return `${(lastSpace > max / 2 ? cut.slice(0, lastSpace) : cut).trimEnd()}…`;
}

/**
 * Reject strings that render as something other than what they contain.
 *
 * Zero-width joiners, bidi overrides and control characters are how a card
 * shows one name and a listing holds another; the store renders these fields
 * verbatim, so this is the last place to catch it.
 *
 * @returns {{level: string, code: string, message: string}[]}
 */
export function checkMetadata(fields, limits) {
  const findings = [];
  const caps = {
    name: limits.max_name_length,
    summary: limits.max_summary_length,
    description: limits.max_description_length,
    author: limits.max_name_length,
  };
  for (const [field, value] of Object.entries(fields)) {
    if (typeof value !== "string" || value.length === 0) continue;
    const trick = unsafeDisplayText(value);
    if (trick) {
      findings.push({
        level: "error",
        code: "E_METADATA_UNSAFE_TEXT",
        message: `plugin.${field} ${trick}`,
      });
    }
    const cap = caps[field];
    if (cap !== undefined && [...value].length > cap) {
      findings.push({
        level: "error",
        code: "E_METADATA_TOO_LONG",
        message: `plugin.${field} is ${[...value].length} characters, over the cap of ${cap}`,
      });
    }
  }
  return findings;
}

/**
 * The two files a plugin ships for a person to look at.
 *
 * Both are optional and neither can fail a submission on its own: an author who
 * ships no icon gets the letter avatar, and one whose SVG is refused gets the
 * same. What they must never do is reach the store unchecked — see
 * `bot/lib/assets.mjs` for why this content is treated differently from the
 * rest of the bundle.
 *
 * @param {{name: string, bytes: Buffer}[]} files
 * @param {{repo: string, commit: string|null}} at
 * @returns {{assets: {path: string, bytes: Buffer}[], icon: string|null,
 *            readme: string|null, findings: object[]}}
 */
function derivePresentation(files, { repo, commit }) {
  const findings = [];
  const assets = [];
  let icon = null;
  let readme = null;

  const found = pickIcon(files);
  if (found) {
    const problems = checkIcon(found);
    if (problems.length === 0) {
      assets.push({ path: found.name, bytes: found.bytes });
      icon = found.name;
    } else {
      // Downgraded to a warning on purpose. The listing is still correct without
      // an icon, and refusing the whole release over a decorative file would
      // make a picture a gate on shipping software.
      findings.push(...problems.map((p) => ({ ...p, level: "warn", code: "W_ICON_DROPPED" })));
    }
  }

  const source = files.find((f) => f.name === README_NAME);
  if (source) {
    const { markdown, findings: notes } = rewriteReadme(source.bytes.toString("utf8"), { repo, commit });
    findings.push(...notes);
    if (markdown.trim().length > 0) {
      assets.push({ path: README_NAME, bytes: Buffer.from(markdown, "utf8") });
      readme = README_NAME;
    }
  }

  return { assets, icon, readme, findings };
}

/**
 * @param {{facts: object, manifest: object, repo: string, tag: string,
 *          commit: string|null, publishedAt: string, artifacts: object,
 *          files: {name: string, bytes: Buffer}[], existingPlugin: object|null,
 *          policy: object}} input
 * @returns {{findings: object[], plugin: object|null, version: object|null,
 *            assets: {path: string, bytes: Buffer}[]}}
 */
export function deriveListing(input) {
  const {
    facts, manifest, repo, tag, commit, publishedAt, artifacts, existingPlugin, policy,
    ownershipMethod = null, files = [],
  } = input;
  const findings = [];

  findings.push(...checkMetadata(
    {
      name: facts.name,
      description: facts.description,
      author: facts.author,
      summary: summarise(facts.description, policy.limits.max_summary_length),
    },
    policy.limits,
  ));

  if (!facts.description) {
    findings.push({
      level: "error",
      code: "E_METADATA_MISSING",
      message: "plugin.description is empty, so the store card would have no summary on it",
    });
  }

  // Licence. An allowlist, and the expression forms are listed explicitly
  // rather than parsed: an SPDX expression parser is a lot of code to decide a
  // question with ten right answers.
  if (!facts.license) {
    findings.push({ level: "error", code: "E_LICENSE_MISSING", message: "plugin.license is empty" });
  } else if (
    !policy.spdx.allowed.includes(facts.license) &&
    !policy.spdx.allowed_expressions.includes(facts.license)
  ) {
    findings.push({
      level: "error",
      code: "E_LICENSE_NOT_ALLOWED",
      message:
        `plugin.license is ${JSON.stringify(facts.license)}; the allowlist is ` +
        `${policy.spdx.allowed.join(", ")} (and ${policy.spdx.allowed_expressions.join(", ")})`,
    });
  }

  // Reserved ids and prefixes. `first_party_repos` is matched against the
  // repository the ownership check already proved, not against a claim.
  if (policy.reserved.reserved.includes(facts.id)) {
    findings.push({ level: "error", code: "E_ID_RESERVED", message: `id ${JSON.stringify(facts.id)} is reserved` });
  }
  for (const prefix of policy.reserved.reserved_prefixes) {
    if (facts.id.startsWith(prefix) && !policy.reserved.first_party_repos.includes(repo)) {
      findings.push({
        level: "error",
        code: "E_ID_RESERVED_PREFIX",
        message: `id ${JSON.stringify(facts.id)} uses the reserved prefix ${JSON.stringify(prefix)}`,
      });
    }
  }

  // `added_at` is the day the plugin was FIRST listed and never moves; on a
  // re-listing it is copied from the existing document rather than recomputed,
  // or a plugin's provenance would silently become "added today" on every
  // release.
  const addedAt = existingPlugin?.added_at ?? publishedAt.slice(0, 10);

  const plugin = {
    $comment: `Derived from ${repo}@${tag} by bot/ingest.mjs. Every field below is read out of the attested bundle except source.repo, which the submitter names and the ownership check proves.`,
    schema: "astra.registry.plugin/1",
    id: facts.id,
    name: facts.name,
    summary: summarise(facts.description, policy.limits.max_summary_length),
    license: facts.license,
    source: { kind: "github", repo },
    added_at: addedAt,
  };
  if (facts.description) plugin.description = facts.description;
  if (facts.author) plugin.author = { name: facts.author };
  if (facts.homepage) plugin.homepage = facts.homepage;

  // The icon and the README are recorded as FILENAMES, not URLs: the bytes are
  // committed next to this document, so a reviewer sees the actual picture in
  // the pull request rather than a base64 blob, and nothing outside the
  // repository is named. `tools/build-index.mjs` inlines them at build time.
  const presentation = derivePresentation(files, { repo, commit });
  findings.push(...presentation.findings);
  if (presentation.icon) plugin.icon = presentation.icon;
  if (presentation.readme) plugin.readme = presentation.readme;
  // Categories and keywords are the two fields no bundle carries and no bot can
  // invent. They stay whatever a human put there, and are absent on a first
  // listing rather than guessed.
  if (existingPlugin?.categories) plugin.categories = existingPlugin.categories;
  if (existingPlugin?.keywords) plugin.keywords = existingPlugin.keywords;

  const version = {
    $comment:
      `Derived from ${repo}@${tag}. Digests are of the bytes the bot downloaded and the ` +
      `attestation covers. Ownership proved by: ${ownershipMethod ?? "unrecorded"}.`,
    schema: "astra.registry.version/1",
    id: facts.id,
    version: facts.version,
    published_at: publishedAt,
    release: { kind: "github_release", repo, tag, ...(commit ? { commit } : {}) },
    artifacts,
  };
  if (Number.isInteger(manifest.protocol)) version.protocol = manifest.protocol;
  if (facts.min_astra_version) version.min_astra_version = facts.min_astra_version;
  if (facts.capabilities.length) version.capabilities = [...facts.capabilities].sort();
  if (manifest.permissions && Object.keys(manifest.permissions).length) {
    version.permissions = manifest.permissions;
  }

  return { findings, plugin, version, assets: presentation.assets };
}
