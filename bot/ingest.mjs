#!/usr/bin/env node
// The registry bot — PRODUCTION_PLAN task 3.3.
//
//   node bot/ingest.mjs --repo you/dice-roller --tag v0.2.0 --submitter you
//
// This is the program that makes a stranger's release listable without a human
// reading it, so what it refuses is the only thing standing between the
// catalogue and a malicious plugin. Read docs/BOT-CHECKS.md next to it: every
// code it can emit is declared in bot/lib/codes.mjs with the sentence a
// stranger is supposed to act on.
//
// ── the shape of the argument ───────────────────────────────────────────────
//
// The submitter supplies **two facts**: a repository and a release tag. The bot
// then, in order:
//
//   1. reads the reusable-workflow allowlist out of a ROOT-SIGNED trust.json,
//      and stops here if there is no root (which is today's state, on purpose);
//   2. proves the submitter controls the repository;
//   3. finds the release and its `.astraplugin` assets, and checks each URL
//      sits under that repository's release namespace;
//   4. HEADs, downloads under a cap, and hashes;
//   5. verifies the build attestation against the repository AND the pinned
//      reusable-workflow commit — the second is what makes the first mean
//      something;
//   6. and only then opens the archive, because until step 5 the bytes are a
//      stranger's and nothing read out of them is worth anything.
//
// Everything after step 6 — id, version, name, licence, capabilities,
// permissions, platform, sizes — is read out of bytes the attestation covers.
// There is no form to disagree with.
//
// ── what it is allowed to do ───────────────────────────────────────────────
//
// Read the network, read this repository, write a report. It never writes to
// the registry: `--out DIR` puts the derived listing where a separate, minimal
// job can commit it. A bot that can push is a bot whose compromise is a
// supply-chain event.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { runValidation } from "../tools/validate.mjs";
import { loadSources, loadPolicy, REPO_ROOT } from "../tools/lib/sources.mjs";
import { compareSemver, parseSemver } from "../tools/lib/semver.mjs";
import { SUPPORTED_KEYS } from "../tools/lib/platform.mjs";
import { TAG_PATTERN } from "../tools/lib/tags.mjs";

import { inspectBundle } from "./lib/bundle.mjs";
import { CODES, LEVEL_GLYPH, codeDef } from "./lib/codes.mjs";
import { deriveListing } from "./lib/derive.mjs";
import * as gh from "./lib/github.mjs";
import { loadWorkflowAllowlist, verifyAttestation } from "./lib/attestation.mjs";
import { checkBundlesAgree } from "./lib/certificate.mjs";
import {
  applyIdentity,
  checkDownloadRepository,
  compareActor,
  idAndVersionFromAssetName,
  identityFromCertificate,
} from "./lib/identity.mjs";
import { readBindingLine } from "./lib/binding.mjs";
import { OWNER_FILE } from "./lib/ownership.mjs";
import { submissionFingerprint } from "./lib/policy/release.mjs";
import { localeSignature } from "./lib/locales.mjs";
import { checkDisplayName, checkNames, loadTrademarks } from "./lib/names.mjs";
import { proveOwnership } from "./lib/ownership.mjs";
import { runProbe } from "./lib/probe.mjs";
import { scanHostRpcs } from "./lib/rpcscan.mjs";

const REPO_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
// One place decides what a tag is: tools/lib/tags.mjs.
const TAG_RE = new RegExp(TAG_PATTERN);

/**
 * The reusable workflow every listed plugin is built by, in the form
 * `gh attestation verify --signer-workflow` wants.
 *
 * Pinning the *path* here and the *commit* in root-signed trust.json is
 * deliberate: the path is public knowledge and changing it is a code review,
 * while the commit is the thing an attacker would want to move and changing it
 * is a root-key ceremony.
 *
 * **It has to be the real filename.** This once read `release-plugin.yml`, and
 * the file in AstraPlugins is `plugin-release.yml` — every other reference in
 * this repository already said so. `gh attestation verify --signer-workflow`
 * matches on that path, so a transposed name matches no attestation at all:
 * every honest submission would have come back `E_ATTESTATION_MISSING`, telling
 * the author to add an attestation they already had, and 3.3's headline claim —
 * two facts become a listing with no human — would have been unreachable for
 * every plugin. The basename is asserted against
 * `AstraPlugins/.github/workflows/` by `the-signer-workflow-pin-names-a-file-
 * that-exists`, so the pair cannot drift again.
 */
export const DEFAULT_SIGNER_WORKFLOW =
  "mihailinl/AstraPlugins/.github/workflows/plugin-release.yml";

class Findings {
  constructor() { this.items = []; }
  add(level, code, where, message) {
    this.items.push({ level, code, where, message });
    return this;
  }
  error(code, where, message) { return this.add("error", code, where, message); }
  review(code, where, message) { return this.add("review", code, where, message); }
  warn(code, where, message) { return this.add("warn", code, where, message); }
  note(code, where, message) { return this.add("note", code, where, message); }
  pass(code, where, message) { return this.add("pass", code, where, message); }
  skip(code, where, message) { return this.add("skip", code, where, message); }
  /**
   * Adopt a sub-check's findings, which carry their own level and code — and
   * their own `where` when they have one. A locale finding names
   * `locales/ru.json`, which is the file the author has to open; collapsing
   * nine of those into one `metadata` would make the report name a stage
   * instead of a file.
   */
  absorb(list, where) {
    for (const i of list) this.add(i.level, i.code, i.where ?? where, i.message);
    return this;
  }
  get errors() { return this.items.filter((i) => i.level === "error"); }
  get reviews() { return this.items.filter((i) => i.level === "review"); }
}

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/**
 * @param {{repo: string, tag: string, submitter: string|null, root?: string,
 *          trustFile?: string, signerWorkflow?: string,
 *          hostAstraVersion?: string|null}} opts
 * @param {object} deps injection seam for the tests; production passes nothing.
 *   `deps.rootKeys` is where a test's `tools/testkeys` root set comes in. It
 *   is a DEP and not an opt, and moving it there was the point of B-T1.5:
 *   `opts` are arguments a production caller supplies, so a roots file among
 *   them was a way for a run to choose its own anchor — and `--roots` on the
 *   command line was that way spelled out loud.
 */
export async function ingest(opts, deps = {}) {
  const f = new Findings();
  const root = opts.root ?? REPO_ROOT;
  const policy = loadPolicy(REPO_ROOT);
  const trademarks = loadTrademarks();
  const signerWorkflow = opts.signerWorkflow ?? DEFAULT_SIGNER_WORKFLOW;

  const fetchRelease = deps.fetchRelease ?? gh.fetchRelease;
  const headAsset = deps.headAsset ?? gh.headAsset;
  const downloadAsset = deps.downloadAsset ?? gh.downloadAsset;
  const ownership = deps.proveOwnership ?? proveOwnership;
  const probe = deps.runProbe ?? runProbe;
  const attest = deps.verifyAttestation ?? verifyAttestation;

  // ── 0. the two facts ──────────────────────────────────────────────────────
  if (!REPO_RE.test(opts.repo ?? "")) {
    f.error("E_INPUT_REPO", "submission", `${JSON.stringify(opts.repo ?? "")} is not \`owner/name\``);
  }
  if (!TAG_RE.test(opts.tag ?? "")) {
    f.error("E_INPUT_TAG", "submission", `${JSON.stringify(opts.tag ?? "")} is not a usable tag`);
  }
  if (f.errors.length) return finish(f, null, opts);

  // ── 1. the allowlist, from a root-signed document ─────────────────────────
  //
  // First, not last. Every later check is cheaper to skip than to run, and more
  // importantly: if there is no root, the bot has no basis for any of its
  // conclusions and should not spend a stranger's bandwidth pretending
  // otherwise.
  //
  // The ROOTS are not read from `root`'s tree (B-T1.5). `--registry-dir` names
  // the catalogue this run judges against, and it used to name the root keys
  // too — so a run pointed at any directory was a run whose anchor came out of
  // that directory. The keys are compiled in now; the trust.json is still read
  // from the tree, which is correct, because a signature by a compiled key is
  // what makes that document worth reading wherever it was found.
  const trust = loadWorkflowAllowlist({
    trustFile: opts.trustFile ?? path.join(root, "registry", "v1", "trust.json"),
    roots: deps.rootKeys,
  });
  if (!trust.ok) {
    f.error(trust.code, "trust", trust.message);
    return finish(f, null, opts);
  }
  f.pass("E_TRUST_UNPROVISIONED", "trust",
    `trust.json serial ${trust.serial}, signed by ${trust.key_id}, allows ${trust.allowlist.length} release-workflow commit(s)`);

  // ── 2. the release ────────────────────────────────────────────────────────
  let release;
  try {
    release = await fetchRelease(opts.repo, opts.tag);
  } catch (e) {
    f.error("E_RELEASE_NOT_FOUND", "release", e.message);
    return finish(f, null, opts);
  }

  const bundles = (release.assets ?? []).filter((a) => a.name.endsWith(".astraplugin"));
  if (bundles.length === 0) {
    f.error("E_NO_BUNDLE_ASSETS", "release",
      `${opts.repo}@${opts.tag} carries ${release.assets?.length ?? 0} asset(s) and none of them ends in .astraplugin`);
    return finish(f, null, opts);
  }
  f.pass("E_NO_BUNDLE_ASSETS", "release", `${bundles.length} bundle(s) on ${opts.repo}@${opts.tag}`);

  // ── 3. ownership ──────────────────────────────────────────────────────────
  //
  // Does the account asking control the repository? The attestation already
  // binds the bytes to a repository and the listing is already pinned to it;
  // this is the one thing neither of those says, and it is what keeps a
  // stranger from listing somebody else's plugin.
  //
  // What the author is asked for is `.well-known/astra-plugin-owner` on the
  // default branch, and the submission form asks for it before a run ever
  // happens. The other two methods are a free shortcut and a re-listing
  // mechanism respectively; neither can fire for an honest first submission,
  // which is why leading a refusal with them was a bug rather than a wording
  // problem. `bot/lib/ownership.mjs` has the whole argument.
  const owner = await ownership({
    repo: opts.repo,
    login: opts.submitter,
    releaseAuthor: release.author?.login ?? null,
    // The release's own date, so `release-author` can expire. Without it that
    // method is a permanent historical fact — "@x published a release once" —
    // and it would keep granting an account after the access that created it
    // was revoked. See bot/lib/ownership.mjs.
    releasePublishedAt: release.published_at ?? null,
  });
  if (owner.ok) {
    f.pass("E_OWNERSHIP_UNPROVEN", "ownership", `${owner.detail} (via ${owner.method})`);
  } else {
    f.error("E_OWNERSHIP_UNPROVEN", "ownership", owner.detail);
  }

  // ── 4-6. every bundle, in order ───────────────────────────────────────────
  const artifacts = {};
  const perBundle = [];
  const releasePrefix = `https://github.com/${opts.repo}/releases/download/${opts.tag}/`;

  for (const asset of bundles) {
    const where = asset.name;
    const url = asset.browser_download_url;

    // The URL belongs to the repository being listed. This is the check the
    // daemon repeats locally against its TOFU pin (§5.3-A.6), so a listing that
    // fails it here would fail there — with the difference that here nobody has
    // downloaded anything yet.
    if (typeof url !== "string" || !url.startsWith(releasePrefix)) {
      f.error("E_ASSET_URL_FOREIGN", where,
        `${url} does not sit under ${releasePrefix}`);
      continue;
    }

    let head;
    try {
      head = await headAsset(url);
    } catch (e) {
      f.error("E_ASSET_HEAD_FAILED", where, e.message);
      continue;
    }
    if (head.size > policy.limits.max_artifact_bytes) {
      f.error("E_ARTIFACT_TOO_LARGE", where,
        `the origin declares ${head.size} bytes, over max_artifact_bytes (${policy.limits.max_artifact_bytes})`);
      continue;
    }

    let bytes;
    try {
      bytes = await downloadAsset(url, policy.limits.max_artifact_bytes);
    } catch (e) {
      f.error("E_ASSET_HEAD_FAILED", where, e.message);
      continue;
    }
    if (asset.size !== undefined && bytes.length !== asset.size) {
      f.error("E_ASSET_SIZE", where,
        `the release API says ${asset.size} bytes, the download is ${bytes.length}`);
      continue;
    }
    const digest = sha256(bytes);

    // ── the attestation, before anything is read out of the archive ─────────
    const spilled = spill(bytes, asset.name);
    let att;
    try {
      att = await attest({
        file: spilled.file,
        repo: opts.repo,
        signerWorkflow,
        allowlist: trust.allowlist,
        artifactSha256: digest,
        // ID-28 row .14: the ref that built these bytes is the tag being
        // listed. Only this function knows which tag was submitted.
        tag: opts.tag,
        runner: deps.ghRunner,
      });
    } finally {
      // The copy exists for one subprocess and no longer. A runner that
      // accumulated strangers' archives across jobs would be a place to leave
      // something behind.
      spilled.cleanup();
    }
    f.absorb(att.findings, where);
    if (att.findings.some((x) => x.level === "error")) continue;
    f.pass("E_ATTESTATION_MISSING", where,
      `built by ${att.facts?.signerUri ?? signerWorkflow} at ${att.facts?.signerDigest?.slice(0, 12) ?? "?"}…, ` +
      `source ${att.facts?.sourceDigest?.slice(0, 12) ?? "?"}…, subject sha256:${digest.slice(0, 12)}…`);

    // ── the archive ────────────────────────────────────────────────────────
    const inspected = inspectBundle(bytes, { id: null, version: null, platformKey: null }, policy.limits);
    f.absorb(inspected.findings, where);
    if (!inspected.manifest || inspected.findings.some((x) => x.level === "error")) continue;

    const toml = inspected.files.find((x) => x.name === "plugin.toml");
    if (!toml) {
      f.error("E_PLUGIN_TOML_MISSING", where, "no plugin.toml in MANIFEST.files");
      continue;
    }

    const probed = await probe({
      pluginToml: toml.bytes.toString("utf8"),
      manifestJson: inspected.manifestBytes.toString("utf8"),
      hostAstraVersion: opts.hostAstraVersion ?? null,
    });
    f.absorb(probed.findings, where);
    if (!probed.manifest || probed.findings.some((x) => x.level === "error")) continue;

    const key = inspected.platformKey;
    if (!SUPPORTED_KEYS.includes(key)) {
      f.error("E_PLATFORM_UNSUPPORTED", where,
        `the bundle targets ${key}, and Astra ships a daemon for ${SUPPORTED_KEYS.join(", ")} only`);
      continue;
    }
    if (artifacts[key]) {
      f.error("E_MANIFEST_PLATFORM_MISMATCH", where,
        `${artifacts[key].filename} already claims ${key}; one release cannot carry two bundles for one host`);
      continue;
    }

    // The name, against the id/version/target the bundle itself declares.
    //
    // Checked here rather than left to the derived listing's validation,
    // because a stranger reading `E_DERIVED_LISTING_INVALID` learns that the
    // registry has a bug, and this is not a registry bug — it is the most
    // likely way a plausible-but-wrong file gets served, and the digest cannot
    // catch it because the digest is taken of whatever was uploaded.
    const expectedName = `${probed.manifest.id}-${probed.manifest.version}-${key}.astraplugin`;
    if (asset.name !== expectedName) {
      f.error("E_ASSET_FILENAME", where,
        `the bundle declares ${probed.manifest.id} ${probed.manifest.version} for ${key}, so the asset should be ${expectedName}`);
      continue;
    }

    artifacts[key] = { url, filename: asset.name, sha256: digest, size: bytes.length };
    perBundle.push({
      where, facts: probed.manifest, manifest: inspected.manifest, files: inspected.files,
      // The commit the CERTIFICATE names (.13). Kept so step 10 can insist the
      // Release agrees with it; see the check there for why that matters. It
      // used to be read from the signed predicate, which ID-28 forbids.
      sourceDigest: att.facts?.sourceDigest ?? null,
      // The ten ID-28 fields for this bundle, so step 7a can hold the bundles
      // of one release to one identity and B-T3.2 can write it into the
      // listing. `.21` travels this way to B-T3.3a's actor check (MIG-31).
      certificate: att.facts?.fields ?? null,
      certificateSource: att.facts?.fieldSource ?? null,
    });
    f.pass("E_DIGEST_MISMATCH", where, `sha256 ${digest.slice(0, 16)}…, ${bytes.length} bytes, ${key}`);
  }

  if (perBundle.length === 0) {
    return finish(f, null, opts);
  }

  // ── 7. the bundles have to agree with each other ──────────────────────────
  const first = perBundle[0];
  // Taken ONCE, outside the loop. It used to be recomputed on every comparison,
  // so at `max_artifacts_per_version: 8` the first bundle's locale files were
  // parsed seven times over — and until this commit that parse had no size cap
  // in front of it at all. `policy.limits` is what puts the cap before the
  // parse; `localeSignature` now refuses to run without it.
  const firstSignature = localeSignature(first.files, policy.limits);
  for (const b of perBundle.slice(1)) {
    if (b.facts.id !== first.facts.id) {
      f.error("E_MANIFEST_ID_MISMATCH", b.where,
        `this bundle is ${b.facts.id} and ${first.where} is ${first.facts.id}; one release lists one plugin`);
    }
    if (b.facts.version !== first.facts.version) {
      f.error("E_VERSION_INCONSISTENT", b.where,
        `this bundle is ${b.facts.version} and ${first.where} is ${first.facts.version}`);
    }
    // The card is derived from the FIRST bundle's files, with a comment saying
    // the icon and the README are one picture across platforms. True for those.
    // **False for locale files**, which reach the installed plugin per
    // platform: a Windows build whose ru.json says something the Linux build's
    // does not is a store card that describes the software half the users are
    // running. No extra download — these bytes are already in hand.
    if (localeSignature(b.files, policy.limits) !== firstSignature) {
      f.error("E_LOCALE_BUNDLE_MISMATCH", b.where,
        `this bundle's locale files disagree with ${first.where}'s — a different set of languages, ` +
        "or different `listing.name`/`listing.description` in one of them. The store card is " +
        "derived from one bundle and every platform installs its own, so the two would describe " +
        "different plugins. Build every platform from the same tree.");
    }
  }

  // ── 7a. and about where they came from (ID-28) ────────────────────────────
  //
  // The bundles of one release attest one tree, built by one run, in one
  // repository — or at least one of them is not this release. ID-28 names
  // .13, .14, .15 and .17; .12 is compared too and flagged for the contract
  // (B-T1.1), because .12 is the name BOT-21 writes into the listing.
  //
  // **No tree can make this fire today**, and that is measured: B-T1.2 found
  // one bundle per RELEASE, not per artifact — the six listings shipping two
  // artifacts verify both against the same attestation, which carries both as
  // subjects. The fixtures in `ingest.test.mjs` are the only place this is
  // exercised, and anybody who checks it against the catalogue will conclude,
  // wrongly, that it does nothing.
  f.absorb(
    checkBundlesAgree(perBundle.filter((b) => b.certificate).map((b) => ({ where: b.where, fields: b.certificate }))),
    "provenance",
  );
  if (f.errors.length) return finish(f, null, opts);

  const facts = first.facts;
  if (!parseSemver(facts.version)) {
    f.error("E_VERSION_INCONSISTENT", "version", `${JSON.stringify(facts.version)} is not a semver version`);
    return finish(f, null, opts);
  }

  // ── 8. against everything already listed ──────────────────────────────────
  const { plugins } = loadSources(root);
  const existing = plugins.find((p) => p.doc?.id === facts.id) ?? null;

  // Every listing, and every NAME every listing renders — the English one and
  // each localized card name. A collision between two Russian cards is a
  // collision; it is only invisible to somebody who reads the catalogue in
  // English, which is everybody who has ever reviewed one.
  const catalogue = plugins
    .filter((p) => p.doc?.id)
    .map((p) => ({ id: p.doc.id, name: p.doc.name ?? "", i18n: p.doc.i18n }));
  const repoOwner = opts.repo.split("/")[0];
  f.absorb(
    checkNames(
      { id: facts.id, name: facts.name, repoOwner },
      catalogue,
      { flagDistance: policy.limits.typosquat_flag_distance, trademarks },
    ),
    "names",
  );

  if (!existing) {
    f.review("R_FIRST_LISTING", "version",
      `${facts.id} has never been listed. A human reads the first submission, once.`);
  } else {
    const listedRepo = existing.doc?.source?.repo;
    if (listedRepo && listedRepo !== opts.repo) {
      f.review("R_IDENTITY_CHANGED", "version",
        `${facts.id} is listed from ${listedRepo} and this release is from ${opts.repo}. ` +
        "Every installed copy carries a pin to the old repository.");
    }
    const versions = existing.versions.map((v) => v.doc?.version).filter((v) => parseSemver(v));
    if (versions.includes(facts.version)) {
      f.error("E_VERSION_NOT_NEW", "version",
        `${facts.id} ${facts.version} is already listed. Bump the version rather than republishing one.`);
    } else {
      const highest = versions.sort(compareSemver).at(-1);
      if (highest && compareSemver(facts.version, highest) <= 0) {
        f.error("E_VERSION_NOT_NEW", "version",
          `${facts.version} is not newer than the listed ${highest}`);
      }
    }
  }

  // ── 9. the host-RPC heuristic ─────────────────────────────────────────────
  for (const b of perBundle) {
    f.absorb(
      scanHostRpcs(b.files, { capabilities: b.facts.capabilities, permissions: b.manifest.permissions }),
      b.where,
    );
  }

  // ── 10. the commit the listing will record ────────────────────────────────
  //
  // `release.target_commitish` is author-supplied and mutable: `gh release
  // create <tag> --target <sha>` sets it to anything in the repository, and
  // nothing about the attestation constrains it, because an attestation is
  // checked against the ARTIFACT's digest rather than against the Release. The
  // signed predicate does name a source commit, and until now nothing compared
  // the two — so `version.release.commit`, the provenance field a reader would
  // trust, and the base URL `bot/lib/assets.mjs` pins every relative README
  // image to, were both taken from the mutable field.
  //
  // The attested commit is the one to prefer, and a disagreement is an error
  // rather than a silent preference: the two naming different trees is a fact
  // about the Release that the author has to fix, not a detail to paper over.
  const attestedCommit = perBundle.map((b) => b.sourceDigest).find((c) => /^[0-9a-f]{40}$/.test(c ?? "")) ?? null;
  const releaseCommit = /^[0-9a-f]{40}$/.test(release.target_commitish ?? "") ? release.target_commitish : null;
  if (attestedCommit && releaseCommit && attestedCommit !== releaseCommit) {
    f.error("E_RELEASE_COMMIT_MISMATCH", "provenance",
      `the Release names ${releaseCommit.slice(0, 12)}… and the attestation names ` +
      `${attestedCommit.slice(0, 12)}…; a listing may record only the commit that built the bytes`);
    return finish(f, null, opts);
  }
  // When the Release's commitish is a branch name rather than a SHA — the
  // common case for a tag pushed off a branch — the attested commit is used
  // instead of dropping the field, which used to leave every relative README
  // image with nothing to resolve against.
  const commit = releaseCommit ?? attestedCommit;

  // ── write the listing, then hold it to this repository's own rules ────────
  const derived = deriveListing({
    facts,
    manifest: first.manifest,
    repo: opts.repo,
    tag: opts.tag,
    commit,
    publishedAt: normaliseTime(release.published_at),
    artifacts,
    // The bundle's own contents, for the icon and the README. Taken from the
    // first bundle because these two files are the plugin's, not the platform's
    // — a Windows build and a Linux build of one release ship the same picture.
    files: first.files,
    // Written into the listing's `$comment` so `git log` answers "how did this
    // get in" without re-running anything. The three methods are not equally
    // strong and a listing resting on the weakest one should say so.
    ownershipMethod: owner.ok ? owner.method : null,
    existingPlugin: existing?.doc ?? null,
    policy,
  });
  f.absorb(derived.findings, "metadata");

  // ── the listing's repository name comes from the certificate (B-T3.2) ─────
  //
  // BOT-21: `source.repo` and every `release.repo` are `.12`'s owner/name, not
  // the string the submitter typed. On this path the two are equal —
  // `verifyAttestation` refuses a certificate naming another repository — and
  // the point of doing it here anyway is that the listing's belief about where
  // it came from now has exactly one source. `publish` does the same
  // overwrite on the service path, from the same function.
  const identity = identityFromCertificate(first.certificate ?? {});
  if (identity.ok) {
    const applied = applyIdentity(derived, identity);
    if (applied.ok) {
      derived.plugin = applied.derived.plugin;
      derived.version = applied.derived.version;
    }
  }

  // ── the name rules, once per language the card is drawn in ────────────────
  //
  // `checkNames` above runs once, on `facts.name` — the English name out of
  // plugin.toml. That was the whole card until this release. It is not any
  // more: a bundle whose en.json says `Media Tools` and whose ru.json says
  // `Telegram` would put a card named Telegram in front of every Russian user,
  // on a listing a human approved by reading a clean English card.
  //
  // The same predicate, not a second one, and it runs on the DERIVED block
  // rather than on the raw locale file — so a name that was demoted to English
  // as stale is checked as the string that will actually be rendered.
  for (const [code, block] of Object.entries(derived.plugin?.i18n ?? {})) {
    f.absorb(
      checkDisplayName(
        { id: facts.id, name: block.name, repoOwner, locale: code },
        catalogue,
        { trademarks },
      ),
      `locales/${code}.json`,
    );
  }

  // Hold the bot's own output to the rules its input would have been held to —
  // except across an identity change, where the tree is inconsistent BY
  // CONSTRUCTION: the old versions point at the old repository and the new
  // plugin.json at the new one, and which of those survives is precisely the
  // question a maintainer is being asked. Running the validator there would
  // report the registry's own `E_DERIVED_LISTING_INVALID` at a stranger for a
  // decision nobody has made yet.
  if (f.errors.length === 0) {
    if (f.items.some((i) => i.code === "R_IDENTITY_CHANGED")) {
      f.skip("E_DERIVED_LISTING_INVALID", "derive",
        "not checked: until a maintainer decides how the repository change is resolved, the listing " +
        "necessarily disagrees with its own history");
    } else {
      f.absorb(await validateDerived(root, derived, opts), "derive");
    }
  }

  return finish(f, derived, opts, identity.ok ? identity : null);
}

/**
 * Put a derived listing on disk: the two JSON documents and the presentation
 * files that go beside them.
 *
 * One function, used by both the validation copy and `--out`, so the tree the
 * bot checks is byte-for-byte the tree the bot proposes. When these were two
 * blocks of similar code the icon and the README existed in only one of them,
 * which is a validator that passes because it is looking at a different thing.
 *
 * @param {string} dir `plugins/<id>` under whichever root
 * @param {{plugin: object, version: object, assets?: {path: string, bytes: Buffer}[]}} derived
 */
export function writeListing(dir, derived) {
  fs.mkdirSync(path.join(dir, "versions"), { recursive: true });
  fs.writeFileSync(path.join(dir, "plugin.json"), `${JSON.stringify(derived.plugin, null, 2)}\n`);
  fs.writeFileSync(
    path.join(dir, "versions", `${derived.version.version}.json`),
    `${JSON.stringify(derived.version, null, 2)}\n`,
  );
  for (const asset of derived.assets ?? []) {
    fs.writeFileSync(path.join(dir, asset.path), asset.bytes);
  }
}

/**
 * Run the derived listing past `tools/validate.mjs` — the same code CI runs
 * against every hand-written listing in this repository.
 *
 * The bot's output has to survive the rules the bot's input would have been
 * held to, or the registry has two standards: one for people and a laxer one
 * for the program that replaced them. It runs against a COPY of the tree with
 * the new files dropped in, so a submission is never able to observe or disturb
 * the real one.
 */
async function validateDerived(root, derived, opts) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-ingest-"));
  try {
    fs.cpSync(path.join(root, "plugins"), path.join(tmp, "plugins"), { recursive: true });
    writeListing(path.join(tmp, "plugins", derived.plugin.id), derived);
    const { report } = await runValidation({
      root: tmp, allowStaging: true, allowDirect: false, online: false, artifactsDir: null, index: false,
    });
    const mine = report.items.filter(
      (i) => i.level === "error" && i.where.startsWith(`plugins/${derived.plugin.id}/`),
    );
    if (mine.length === 0) {
      return [{
        level: "pass",
        code: "E_DERIVED_LISTING_INVALID",
        message: `the derived listing passes tools/validate.mjs — the same rules a hand-written one is held to`,
      }];
    }
    return mine.map((i) => ({
      level: "error",
      code: "E_DERIVED_LISTING_INVALID",
      message: `${i.where}: ${i.message}`,
    }));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Put the bundle where `gh` can see it.
 *
 * `gh attestation verify` takes a path, not bytes, so this is the one moment a
 * stranger's archive reaches a filesystem. It is written whole, into a
 * `mkdtemp` directory created with the process umask, under its own name, and
 * **nothing is ever extracted from it** — no entry of the archive is written
 * anywhere, here or in any other file in bot/.
 */
function spill(bytes, name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-bundle-"));
  const file = path.join(dir, path.basename(name));
  fs.writeFileSync(file, bytes);
  return { file, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

/** The registry's one timestamp spelling: seconds precision, UTC, no offset. */
function normaliseTime(value) {
  const d = new Date(value ?? Date.now());
  return `${(Number.isNaN(d.getTime()) ? new Date() : d).toISOString().slice(0, 19)}Z`;
}

function finish(f, derived, opts, identity = null) {
  return {
    findings: f.items,
    derived,
    blocked: f.errors.length > 0,
    needsReview: f.reviews.length > 0,
    comment: renderComment(f, derived, opts),
    // What the certificate said about where these bytes came from: `.12`'s
    // owner/name, `.15`, `.17`, the attested commit and `.21`'s run. Returned
    // rather than printed, because its readers are programs — B-T3.3a's
    // identity comparison and MIG-31's actor read — and because a report that
    // recited two repository ids at a stranger would be a report nobody
    // finishes. Null when the run never got to a verified certificate.
    identity,
  };
}

/**
 * GitHub refuses an issue comment over this many characters with a 422.
 *
 * Not a style limit — it is the boundary between a report that posts and a
 * submission with no verdict at all, and `bot/lib/locales.mjs`'s `preview()`
 * already reasons about it by name.
 */
export const GITHUB_COMMENT_MAX = 65536;

/** Rendered table rows, before the rest collapse into one line. */
const MAX_ROWS = 50;

/**
 * Characters the whole table may take, whatever the row count.
 *
 * A row cap alone is not a bound on a document: fifty rows at the cell cap is
 * over a hundred thousand characters. Budgeting the table rather than only
 * counting it is what keeps the two things a reader actually needs — the "and
 * N more" line and the "What to do" section — inside the comment, instead of
 * letting the final cut take them off the end.
 */
const TABLE_BUDGET = 40000;

/** Characters of ONE cell, before it is cut. Above every message this bot writes. */
const MAX_CELL = 2000;

/**
 * One table cell, for EVERY column rather than for the message alone.
 *
 * This used to escape the `detail` column and interpolate `${i.where}` raw, and
 * `where` is not the bot's string: for a locale finding it is
 * `locales/${file.code}.json`, where `code` is captured by
 * `/^locales\/([^/]+)\.json$/` from a ZIP entry name — and `[^/]` matches
 * newlines and pipes. A bundle carrying one entry named
 * `locales/ru\n| ✅ | \`E_OWNERSHIP_PROVEN\` | ownership | proved by … |\nx.json`
 * was built and run through the real `inspectBundle`: **zero errors**, the name
 * passed through, and `renderComment` rendered two forged four-column rows with
 * green ticks above the real finding — while the identical bytes in the
 * `detail` column came out escaped. That asymmetry was the whole bug. A
 * maintainer reads this table before typing `/approve`.
 *
 * Three jobs, in this order:
 *   * cut at `MAX_CELL` **code points**, not units, so the cut never lands
 *     between the halves of an emoji and leaves a lone surrogate — the same
 *     rule `summarise` learned, and for the same reason. First, so the count it
 *     reports is the length of what arrived rather than of what survived the
 *     stripping, which is the number a reader wants;
 *   * strip control characters and invisible ones, so nothing can restart a
 *     row, hide itself, or reverse what the rest of the cell reads as;
 *   * escape `|` and turn every newline into `<br>`, so the cell stays one
 *     cell.
 *
 * Cutting matters here beyond tidiness: `where` and several messages
 * interpolate an entry name, which the archive format bounds at 64 KiB. One
 * such entry is on its own enough to push the comment past GitHub's cap.
 */
function cell(value, max = MAX_CELL) {
  let s = String(value ?? "");
  const points = [...s];
  if (points.length > max) s = `${points.slice(0, max).join("")}… (cut, ${points.length} characters)`;
  return s
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g, "")
    .replace(/\|/g, "\\|")
    // `\r\n`, a bare `\r` and a bare `\n` all end a row in a rendered table.
    .replace(/\r\n?|\n/g, "<br>");
}

/**
 * The comment a stranger reads.
 *
 * Ordered errors first, then the decisions a human owes them, then everything
 * that passed — and the notes last, always printed, because a report that lists
 * only what passed reads as a clean bill of health for properties nobody
 * checked.
 *
 * **Bounded in four places, and they are not redundant.** `MAX_ROWS` bounds how
 * many rows a person has to read; `MAX_CELL` bounds how wide one is;
 * `TABLE_BUDGET` bounds the table, because fifty rows at the cell cap is over a
 * hundred thousand characters and a row count is not a size; and only measuring
 * the finished document bounds the thing GitHub actually refuses — the "What to
 * do" section is one paragraph per distinct code and nothing above has any say
 * over it. The first three are what keep the report *useful*; the last is what
 * keeps it *postable*, and each has its own witness in `bot/tests/`.
 *
 * `bot/lib/locales.mjs` additionally collapses repeated findings of one rule
 * before they ever get here, so these are the backstop for every OTHER check
 * rather than the locale rules' only defence.
 */
export function renderComment(f, derived, opts) {
  const rank = { error: 0, review: 1, warn: 2, pass: 3, skip: 4, note: 5 };
  const items = [...f.items].sort((a, b) => rank[a.level] - rank[b.level]);
  const lines = [
    `## Registry ingest — \`${cell(opts.repo)}@${cell(opts.tag)}\``,
    "",
  ];

  if (f.errors.length === 0 && f.reviews.length === 0) {
    lines.push(`**Listing ${cell(derived?.plugin?.id ?? "")} ${cell(derived?.version?.version ?? "")}.** Every check passed; no human is needed.`, "");
  } else if (f.errors.length > 0) {
    lines.push(`**Not listed — ${f.errors.length} blocking finding(s).** Each one below says what to do about it.`, "");
  } else {
    lines.push(`**Held for a maintainer.** Nothing is wrong with the release; ${f.reviews.length} decision(s) below are not the bot's to make.`, "");
  }

  lines.push("| | code | where | detail |", "|---|---|---|---|");
  let shown = 0;
  let spent = 0;
  for (const i of items) {
    if (shown >= MAX_ROWS || spent >= TABLE_BUDGET) break;
    const row = `| ${LEVEL_GLYPH[i.level] ?? "•"} | \`${cell(i.code, 80)}\` | ${cell(i.where, 200)} | ${cell(i.message)} |`;
    lines.push(row);
    spent += row.length;
    shown++;
  }
  if (shown < items.length) {
    const rest = items.length - shown;
    const worst = items.slice(shown).filter((i) => i.level === "error" || i.level === "review").length;
    lines.push(
      `| … | | | **and ${rest} more finding(s)**, ${worst} of them blocking or for a maintainer, ` +
      "not rendered here. The complete list is in this run's `ingest-report-*` artifact. |",
    );
  }
  lines.push("");

  const actionable = items.filter((i) => i.level === "error" || i.level === "review");
  if (actionable.length) {
    lines.push("### What to do", "");
    const seen = new Set();
    for (const i of actionable) {
      if (seen.has(i.code)) continue;
      seen.add(i.code);
      const def = codeDef(i.code);
      lines.push(`**\`${cell(i.code, 80)}\` — ${def.title}.** ${def.remedy}`, "");
    }
  }

  lines.push(
    "<sub>Everything except the repository and the tag was read out of the bundle, which the build " +
    "attestation covers. See `docs/BOT-CHECKS.md` for what each code means and, just as importantly, " +
    "for what none of them prove.</sub>",
  );

  // The guarantee, as opposed to the two estimates above it. A row cap and a
  // cell cap each bound one dimension of a document with several; only
  // measuring the finished thing bounds the thing GitHub actually refuses. It
  // costs one `length` on every honest report and it is the difference between
  // a truncated verdict and no verdict.
  const body = lines.join("\n");
  if (body.length <= GITHUB_COMMENT_MAX) return body;
  const tail =
    "\n\n---\n\n**This report was cut to fit.** GitHub refuses an issue comment over " +
    `${GITHUB_COMMENT_MAX} characters, and the full one is ${body.length}. Nothing was decided by ` +
    "the cut — the verdict is the exit code, and the complete finding list is in this run's " +
    "`ingest-report-*` artifact.";
  return `${[...body].slice(0, GITHUB_COMMENT_MAX - tail.length - 1).join("")}${tail}`;
}

// ── the service path: the same checks, split at the stranger's bytes ────────
//
// Registry plan B-T3.2. `ingest()` above does everything in one process —
// fetch, hash, verify, unpack, probe, derive — because on the legacy path one
// job holds all of it and nothing else. `plugins-ingest.yml` splits the same
// work across two jobs, and the split is the point (BOT-55): `verify` holds
// `GITHUB_TOKEN` with `contents: read`, downloads and hashes the assets and
// verifies them, and NEVER UNPACKS ANYTHING; `check` opens the archive and
// holds nothing at all. Every identity value — both ids, `.12`'s name, the
// commit, the digests, the binding line, the fingerprint, the plugin id and
// version from the ATTESTED asset names (BOT-21) — comes out of `verify`, and
// `check`'s output is a facts file of codes and levels plus the card.
//
// The two functions below are those two jobs' whole programs, and they reuse
// every check `ingest()` runs rather than restating one: the same
// `verifyAttestation`, `inspectBundle`, `runProbe`, `checkNames`,
// `deriveListing` and `validateDerived`, called in the same order. What is
// new is only what the split needs — the certificate's ids against the
// repository the bytes were downloaded from (`checkDownloadRepository`), the
// binding line at the attested commit, and the rename that agreeing ids under a
// different name is (TRUST-23; ID-41).

/**
 * `verify`'s answer for one lease: every identity value, or why there is none.
 *
 * `outcome` is `ok` (every value below is the verification's), `wait` (a read
 * that did not happen, FLOW-72 — nothing is recorded), `alert` (the download
 * and the certificate disagree about where the bytes came from, BOT-21 — nothing
 * is written or posted, and an operator is paged), or `refuse` (the release has
 * no verifiable bundle; the result is a refusal, and its record carries no
 * identity value, because none was established).
 *
 * @param {{lease: object, root?: string, assetsDir: string, trustFile?: string,
 *   signerWorkflow?: string}} opts
 * @param {object} deps the same seam `ingest` takes, plus the by-id readers
 */
export async function verifyFacts(opts, deps = {}) {
  const { lease } = opts;
  const root = opts.root ?? REPO_ROOT;
  const policy = loadPolicy(REPO_ROOT);
  const signerWorkflow = opts.signerWorkflow ?? DEFAULT_SIGNER_WORKFLOW;
  const fetchRelease = deps.fetchRelease ?? gh.fetchRelease;
  const headAsset = deps.headAsset ?? gh.headAsset;
  const downloadAsset = deps.downloadAsset ?? gh.downloadAsset;
  const attest = deps.verifyAttestation ?? verifyAttestation;
  const repoIds = deps.fetchRepositoryIds ?? gh.fetchRepositoryIds;
  const findings = [];
  const out = (outcome, extra = {}) => {
    // `assets-<submission_id>` is uploaded with `if-no-files-found: error`; a
    // lease this job refused or waited on still leaves one file, so the upload
    // of the next lease's bytes is not failed by this one's absence.
    const dir = path.join(opts.assetsDir, lease.submission_id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "verify-outcome.txt"), `${outcome}\n`);
    return { submission_id: lease.submission_id, outcome, findings, ...extra };
  };
  const refuse = (code, where, message) => {
    findings.push({ level: "error", code, where, message });
    return out("refuse", { code });
  };

  if (!REPO_RE.test(lease.repo ?? "") || !TAG_RE.test(lease.tag ?? "")) {
    return refuse("E_INPUT_REPO", "submission", "the lease names a repository or a tag outside §0.7's grammar");
  }

  const trust = loadWorkflowAllowlist({
    trustFile: opts.trustFile ?? path.join(root, "registry", "v1", "trust.json"),
    roots: deps.rootKeys,
  });
  if (!trust.ok) {
    // FLOW-72: on this path an unprovisioned trust set is a wait, never a
    // recorded refusal of somebody's release.
    findings.push({ level: "error", code: trust.code, where: "trust", message: trust.message });
    return out("wait", { code: trust.code, reason: trust.message });
  }

  let release;
  try {
    release = await fetchRelease(lease.repo, lease.tag);
  } catch (e) {
    return refuse("E_RELEASE_NOT_FOUND", "release", e.message);
  }
  const bundles = (release.assets ?? []).filter((a) => typeof a?.name === "string" && a.name.endsWith(".astraplugin"));
  if (bundles.length === 0) return refuse("E_NO_BUNDLE_ASSETS", "release", `${lease.repo}@${lease.tag} carries no .astraplugin asset`);

  const releasePrefix = `https://github.com/${lease.repo}/releases/download/${lease.tag}/`;
  const dir = path.join(opts.assetsDir, lease.submission_id);
  fs.mkdirSync(dir, { recursive: true });
  const assets = [];
  const certificates = [];
  let sourceDigest = null;
  let certRepoMismatch = false;

  for (const asset of bundles) {
    const where = asset.name;
    const url = asset.browser_download_url;
    // BOT-21: plugin id and version from the ATTESTED asset name, and the
    // name is attested only once its digest verifies below.
    const named = idAndVersionFromAssetName(asset.name);
    if (!named.ok) return refuse("E_ASSET_FILENAME", where, `${where} is not <id>-<version>-<platform>.astraplugin`);
    if (typeof url !== "string" || !url.startsWith(releasePrefix)) {
      return refuse("E_ASSET_URL_FOREIGN", where, `${url} does not sit under ${releasePrefix}`);
    }
    let head;
    try {
      head = await headAsset(url);
    } catch (e) {
      return refuse("E_ASSET_HEAD_FAILED", where, e.message);
    }
    if (head.size > policy.limits.max_artifact_bytes) {
      return refuse("E_ARTIFACT_TOO_LARGE", where, `the origin declares ${head.size} bytes, over max_artifact_bytes`);
    }
    let bytes;
    try {
      bytes = await downloadAsset(url, policy.limits.max_artifact_bytes);
    } catch (e) {
      return refuse("E_ASSET_HEAD_FAILED", where, e.message);
    }
    if (asset.size !== undefined && bytes.length !== asset.size) {
      return refuse("E_ASSET_SIZE", where, `the release API says ${asset.size} bytes, the download is ${bytes.length}`);
    }
    const digest = sha256(bytes);
    // The one place a stranger's archive reaches this job's disk: whole, under
    // its own name, for `gh` and for the `check` job's download. Nothing is
    // extracted from it here or anywhere in this job.
    const file = path.join(dir, path.basename(asset.name));
    fs.writeFileSync(file, bytes);

    const att = await attest({
      file, repo: lease.repo, signerWorkflow, allowlist: trust.allowlist, artifactSha256: digest,
      tag: lease.tag, runner: deps.ghRunner,
    });
    for (const x of att.findings) {
      // A certificate naming another repository is a RENAME when the ids agree
      // with the download repository's (TRUST-23; ID-41), and an alert when
      // they do not — `checkDownloadRepository` below decides which, so the
      // finding is held back rather than refused here.
      if (x.code === "E_ATTESTATION_REPO_MISMATCH" && att.facts?.fields) {
        certRepoMismatch = true;
        continue;
      }
      findings.push({ ...x, where });
    }
    const blocking = att.findings.filter((x) => x.level === "error" && !(x.code === "E_ATTESTATION_REPO_MISMATCH" && att.facts?.fields));
    if (blocking.length) {
      const code = blocking[0].code;
      // FLOW-72: a verifier that could not run is a wait, never a refusal.
      if (code === "E_ATTESTATION_UNCHECKED") return out("wait", { code, reason: blocking[0].message });
      return out("refuse", { code });
    }
    certificates.push({ where, fields: att.facts?.fields ?? {} });
    sourceDigest = sourceDigest ?? att.facts?.sourceDigest ?? null;
    if (assets.some((a) => a.platform === named.platformKey)) {
      return refuse("E_MANIFEST_PLATFORM_MISMATCH", where, `two bundles claim ${named.platformKey}`);
    }
    if (!SUPPORTED_KEYS.includes(named.platformKey)) return refuse("E_PLATFORM_UNSUPPORTED", where, `${named.platformKey}`);
    assets.push({ name: asset.name, platform: named.platformKey, sha256: digest, size: bytes.length, url, id: named.id, version: named.version });
  }

  const ids = new Set(assets.map((a) => a.id));
  const versions = new Set(assets.map((a) => a.version));
  if (ids.size !== 1) return refuse("E_MANIFEST_ID_MISMATCH", "release", `the attested asset names disagree about the plugin id: ${[...ids].join(", ")}`);
  if (versions.size !== 1) return refuse("E_VERSION_INCONSISTENT", "release", `the attested asset names disagree about the version: ${[...versions].join(", ")}`);
  const agree = checkBundlesAgree(certificates);
  for (const x of agree) findings.push({ ...x, where: x.where ?? "provenance" });
  if (agree.some((x) => x.level === "error")) return out("refuse", { code: agree.find((x) => x.level === "error").code });

  const identity = identityFromCertificate(certificates[0].fields);
  if (!identity.ok) {
    return out("alert", { code: "E_ATTESTATION_INVALID", reason: `the certificate is missing ${identity.missing.join(", ")}` });
  }

  // BOT-21: `.15` against the id of the repository the bytes came from.
  const download = await repoIds(lease.repo);
  const checked = checkDownloadRepository({
    identity,
    downloadRepoIds: download?.status === "found"
      ? { status: "found", id: download.id, owner_id: download.owner_id, full_name: download.full_name }
      : { status: download?.status ?? "transient", reason: download?.reason ?? "no answer" },
  });
  if (checked.outcome === "wait") return out("wait", { code: checked.code, reason: checked.reason });
  if (checked.outcome === "alert") return out("alert", { code: checked.code, reason: checked.reason });
  if (certRepoMismatch) {
    // The certificate names another repository than the lease, and the ids
    // agree with the repository the bytes were downloaded from: the name moved
    // between signing and now. That is a rename, and TRUST-23 or ID-41 rules
    // on it — never this job, and never by refusing here.
    findings.push({ level: "note", code: "E_ATTESTATION_REPO_MISMATCH", where: "provenance", message: "the ids agree and the name differs: a rename, which the identity comparison decides" });
  }

  const attested = identity.commit && /^[0-9a-f]{40}$/.test(identity.commit) ? identity.commit : sourceDigest;
  if (!attested || !/^[0-9a-f]{40}$/.test(attested)) {
    return out("alert", { code: "E_ATTESTATION_INVALID", reason: "the certificate names no source commit (.13)" });
  }
  const releaseCommit = /^[0-9a-f]{40}$/.test(release.target_commitish ?? "") ? release.target_commitish : null;
  if (releaseCommit && releaseCommit !== attested) {
    return refuse("E_RELEASE_COMMIT_MISMATCH", "provenance", `the Release names ${releaseCommit} and the attestation names ${attested}`);
  }

  // ID-22: the binding line at the ATTESTED commit, by repository id.
  const line = await readBindingLine({ repositoryId: identity.repository_id, commit: attested, deps: deps.binding ?? {} });
  const binding = {
    outcome: line.outcome,
    token: line.outcome === "one" ? line.token : null,
    token_hash: line.outcome === "one" ? sha256(Buffer.from(line.token, "utf8")).slice(0, 16) : null,
    code: line.code ?? null,
    alert: line.alert === true,
    reason: line.reason ?? null,
  };

  // ID-63 and MIG-31: read only where a binding line makes them matter.
  let ownerFile = null;
  let actor = null;
  if (binding.outcome === "one") {
    const last = await (deps.lastCommitTouching ?? gh.lastCommitTouching)(identity.repository_id, attested, OWNER_FILE);
    if (last.status !== "found") return out("wait", { code: "W_GITHUB_RATE_LIMITED", reason: `ID-63: ${last.reason}` });
    let pr = null;
    if (last.commit) {
      const pulls = await (deps.pullsForCommit ?? gh.pullsForCommit)(identity.repository_id, last.commit);
      if (pulls.status !== "found") return out("wait", { code: "W_GITHUB_RATE_LIMITED", reason: `ID-63: ${pulls.reason}` });
      pr = pulls.pulls.length > 0;
    }
    ownerFile = { commit: last.commit, pull_request: pr };
    if (identity.run_id) {
      const run = await (deps.workflowRun ?? gh.workflowRun)(identity.repository_id, identity.run_id);
      const cmp = compareActor({ identity, actor: run?.status === "found" ? { status: "found", triggering_actor_id: run.triggering_actor_id } : { status: "transient", reason: run?.reason } });
      if (cmp.outcome === "wait") return out("wait", { code: cmp.code, reason: cmp.reason });
      actor = { triggering_actor_id: run.triggering_actor_id, floor_days: cmp.floor_days };
    }
  }

  const digests = assets.map((a) => `${a.platform}:${a.sha256}`).sort();
  const [pluginId] = ids;
  const [version] = versions;
  return out("ok", {
    plugin_id: pluginId,
    version,
    tag: lease.tag,
    commit: attested,
    artifact_digests: digests,
    fingerprint: submissionFingerprint({ repo: identity.repo, tag: lease.tag, id: pluginId, version, commit: attested, digests }),
    repo: identity.repo,
    repository_id: identity.repository_id,
    repository_owner_id: identity.repository_owner_id,
    renamed: Boolean(checked.renamed),
    published_at: normaliseTime(release.published_at),
    assets: assets.map(({ id: _i, version: _v, ...a }) => a),
    binding,
    owner_file: ownerFile,
    actor,
  });
}

/**
 * `check`'s program for one submission: open the verified bytes, probe them,
 * derive the card, and write exactly two things — a facts file of codes and
 * levels, and the listing files.
 *
 * It takes `verified` for the name the card is derived under (BOT-21: never
 * the lease's, never a name this job read) and reads nothing else from it; the
 * decide job compares everything this writes against `verified` again, because
 * this is the job to assume exploited.
 *
 * @param {{submissionId: string, assetsDir: string, verified: object, out: string, root?: string,
 *   hostAstraVersion?: string|null}} opts
 */
export async function checkFacts(opts, deps = {}) {
  const f = new Findings();
  const root = opts.root ?? REPO_ROOT;
  const policy = loadPolicy(REPO_ROOT);
  const trademarks = loadTrademarks();
  const probe = deps.runProbe ?? runProbe;
  const v = opts.verified ?? {};
  const files = fs.existsSync(opts.assetsDir)
    ? fs.readdirSync(opts.assetsDir).filter((n) => n.endsWith(".astraplugin")).sort()
    : [];
  const perBundle = [];
  const artifacts = {};

  for (const name of files) {
    const bytes = fs.readFileSync(path.join(opts.assetsDir, name));
    const inspected = inspectBundle(bytes, { id: null, version: null, platformKey: null }, policy.limits);
    f.absorb(inspected.findings, name);
    if (!inspected.manifest || inspected.findings.some((x) => x.level === "error")) continue;
    const toml = inspected.files.find((x) => x.name === "plugin.toml");
    if (!toml) { f.error("E_PLUGIN_TOML_MISSING", name, "no plugin.toml in MANIFEST.files"); continue; }
    const probed = await probe({
      pluginToml: toml.bytes.toString("utf8"),
      manifestJson: inspected.manifestBytes.toString("utf8"),
      hostAstraVersion: opts.hostAstraVersion ?? null,
    });
    f.absorb(probed.findings, name);
    if (!probed.manifest || probed.findings.some((x) => x.level === "error")) continue;
    const key = inspected.platformKey;
    const expected = `${probed.manifest.id}-${probed.manifest.version}-${key}.astraplugin`;
    if (name !== expected) { f.error("E_ASSET_FILENAME", name, `the bundle declares ${expected}`); continue; }
    const asset = (v.assets ?? []).find((a) => a.name === name);
    artifacts[key] = { url: asset?.url ?? null, filename: name, sha256: sha256(bytes), size: bytes.length };
    perBundle.push({ where: name, facts: probed.manifest, manifest: inspected.manifest, files: inspected.files });
  }

  const write = (derived) => {
    fs.mkdirSync(opts.out, { recursive: true });
    const first = perBundle[0]?.facts ?? null;
    const facts = {
      schema: CHECK_FACTS_SCHEMA,
      submission_id: opts.submissionId,
      plugin_id: first?.id ?? null,
      version: first?.version ?? null,
      platforms: Object.keys(artifacts).sort(),
      // Codes and levels, and nothing that names anything: `where` and
      // `message` interpolate entry names out of a stranger's archive.
      findings: f.items.map((i) => ({ code: i.code, level: i.level })),
    };
    fs.writeFileSync(path.join(opts.out, "facts.json"), `${JSON.stringify(facts, null, 2)}\n`);
    const listingDir = path.join(opts.out, "listing");
    fs.mkdirSync(listingDir, { recursive: true });
    if (derived?.plugin && derived?.version) writeListing(path.join(listingDir, "plugins", derived.plugin.id), derived);
    // `listing-<submission_id>` is uploaded with `if-no-files-found: error`,
    // and a refused bundle derives no card: the marker keeps "nothing to list"
    // an answer rather than a failed upload that takes the other legs' work
    // down with it.
    else fs.writeFileSync(path.join(listingDir, "NO-LISTING"), "this submission derived no listing; its facts file says why\n");
    return { facts, derived };
  };

  if (perBundle.length === 0) {
    if (files.length === 0) f.error("E_NO_BUNDLE_ASSETS", "release", "the verify job handed this job no bundle");
    return write(null);
  }
  const first = perBundle[0];
  const firstSignature = localeSignature(first.files, policy.limits);
  for (const b of perBundle.slice(1)) {
    if (b.facts.id !== first.facts.id) f.error("E_MANIFEST_ID_MISMATCH", b.where, "the bundles name two plugins");
    if (b.facts.version !== first.facts.version) f.error("E_VERSION_INCONSISTENT", b.where, "the bundles name two versions");
    if (localeSignature(b.files, policy.limits) !== firstSignature) f.error("E_LOCALE_BUNDLE_MISMATCH", b.where, "the bundles' locale files disagree");
  }
  if (f.errors.length) return write(null);

  const facts = first.facts;
  const { plugins } = loadSources(root);
  const existing = plugins.find((p) => p.doc?.id === facts.id) ?? null;
  const catalogue = plugins.filter((p) => p.doc?.id).map((p) => ({ id: p.doc.id, name: p.doc.name ?? "", i18n: p.doc.i18n }));
  const repo = typeof v.repo === "string" ? v.repo : null;
  const repoOwner = repo ? repo.split("/")[0] : "";
  f.absorb(checkNames({ id: facts.id, name: facts.name, repoOwner }, catalogue, { flagDistance: policy.limits.typosquat_flag_distance, trademarks }), "names");
  if (existing) {
    const listed = existing.versions.map((x) => x.doc?.version).filter((x) => parseSemver(x));
    if (listed.includes(facts.version)) f.error("E_VERSION_NOT_NEW", "version", `${facts.id} ${facts.version} is already listed`);
    else {
      const highest = listed.sort(compareSemver).at(-1);
      if (highest && compareSemver(facts.version, highest) <= 0) f.error("E_VERSION_NOT_NEW", "version", `${facts.version} is not newer than ${highest}`);
    }
  }
  for (const b of perBundle) {
    f.absorb(scanHostRpcs(b.files, { capabilities: b.facts.capabilities, permissions: b.manifest.permissions }), b.where);
  }
  const derived = deriveListing({
    facts, manifest: first.manifest, repo: repo ?? "unknown/unknown", tag: v.tag ?? null, commit: v.commit ?? null,
    publishedAt: typeof v.published_at === "string" ? v.published_at : normaliseTime(null),
    artifacts, files: first.files, ownershipMethod: null, existingPlugin: existing?.doc ?? null, policy,
  });
  f.absorb(derived.findings, "metadata");
  for (const [code, block] of Object.entries(derived.plugin?.i18n ?? {})) {
    f.absorb(checkDisplayName({ id: facts.id, name: block.name, repoOwner, locale: code }, catalogue, { trademarks }), `locales/${code}.json`);
  }
  const listedRepo = existing?.doc?.source?.repo ?? null;
  if (f.errors.length === 0) {
    if (listedRepo && repo && listedRepo.toLowerCase() !== repo.toLowerCase()) {
      f.skip("E_DERIVED_LISTING_INVALID", "derive", "not checked: the listing's repository changed, and the identity comparison decides first");
    } else {
      f.absorb(await validateDerived(root, derived, opts), "derive");
    }
  }
  return write(derived);
}

/**
 * The check job's facts file schema string: registry-internal, never
 * committed, and read only by `bot/lib/service-decide.mjs`, which refuses a
 * facts file carrying any member but the six it names.
 */
export const CHECK_FACTS_SCHEMA = "astra.registry.check-facts/1";

// ── CLI ─────────────────────────────────────────────────────────────────────

// Exported so `bot/tests/roots.test.mjs` can ask this function what flags
// exist rather than asking the file's text (B-T1.5). A test that greps for a
// string is a test that passes the day the string moves into a variable.
export function parseArgs(argv) {
  // No `--roots`. There was one, and it let a command line choose which keys
  // this bot would verify a trust.json under — the anchor as an argument
  // (B-T1.5). The keys are compiled into `bot/lib/roots.mjs`; a test hands its
  // own set in through `deps.rootKeys`, which no command line can reach.
  const opts = {
    repo: null, tag: null, submitter: null, root: REPO_ROOT,
    trustFile: null, signerWorkflow: null, out: null,
    hostAstraVersion: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--repo") opts.repo = argv[++i];
    else if (a === "--tag") opts.tag = argv[++i];
    else if (a === "--submitter") opts.submitter = String(argv[++i]).replace(/^@/, "");
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--trust") opts.trustFile = path.resolve(argv[++i]);
    else if (a === "--signer-workflow") opts.signerWorkflow = argv[++i];
    else if (a === "--astra-version") opts.hostAstraVersion = argv[++i];
    else if (a === "--out") opts.out = path.resolve(argv[++i]);
    else throw new Error(`unknown argument: ${a}`);
  }
  if (!opts.repo || !opts.tag) throw new Error("--repo <owner/name> and --tag <tag> are both required");
  return opts;
}

/**
 * The service path's two modes, parsed apart from the legacy flags so that
 * `parseArgs` — which `bot/tests/roots.test.mjs` asks what flags exist — keeps
 * saying exactly what the legacy command line takes.
 */
export function parseServiceArgs(argv) {
  const opts = { mode: null, leases: null, submissions: null, assetsDir: null, out: null, submissionId: null, verified: null, root: REPO_ROOT, hostAstraVersion: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--verify-facts") opts.mode = "verify";
    else if (a === "--check-facts") opts.mode = "check";
    else if (a === "--leases") opts.leases = argv[++i];
    else if (a === "--submissions") opts.submissions = argv[++i];
    else if (a === "--assets-dir") opts.assetsDir = path.resolve(argv[++i]);
    else if (a === "--submission-id") opts.submissionId = argv[++i];
    else if (a === "--verified") opts.verified = argv[++i];
    else if (a === "--out") opts.out = path.resolve(argv[++i]);
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--astra-version") opts.hostAstraVersion = argv[++i];
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

/** A JSON job output, from the text a `needs.*.outputs` value arrives as. */
function jsonInput(text, what) {
  if (text === null || text === undefined || String(text).trim() === "") return null;
  try {
    return JSON.parse(String(text));
  } catch (e) {
    throw new Error(`${what} is not JSON: ${e.message}`);
  }
}

async function serviceMain(argv) {
  const opts = parseServiceArgs(argv);
  if (opts.mode === "verify") {
    const leases = jsonInput(opts.leases, "--leases") ?? {};
    const ids = jsonInput(opts.submissions, "--submissions") ?? Object.keys(leases);
    if (!opts.assetsDir) throw new Error("--verify-facts needs --assets-dir");
    const verified = {};
    for (const id of ids) {
      const lease = leases[id];
      if (!lease) throw new Error(`claim reported ${id} and handed on no lease for it`);
      verified[id] = await verifyFacts({ lease, root: opts.root, assetsDir: opts.assetsDir });
      console.log(`${id}: ${verified[id].outcome}${verified[id].code ? ` ${verified[id].code}` : ""}`);
    }
    const text = JSON.stringify(verified);
    if (opts.out) fs.writeFileSync(opts.out, `${text}\n`);
    if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `verified=${text}\n`);
    return 0;
  }
  if (opts.mode === "check") {
    if (!opts.submissionId || !opts.assetsDir || !opts.out) throw new Error("--check-facts needs --submission-id, --assets-dir and --out");
    const all = jsonInput(opts.verified, "--verified") ?? {};
    const { facts } = await checkFacts({
      submissionId: opts.submissionId, assetsDir: opts.assetsDir, verified: all[opts.submissionId] ?? {},
      out: opts.out, root: opts.root, hostAstraVersion: opts.hostAstraVersion,
    });
    const blocking = facts.findings.filter((x) => x.level === "error").length;
    console.log(`${opts.submissionId}: ${facts.findings.length} finding(s), ${blocking} blocking`);
    return 0;
  }
  throw new Error("one of --verify-facts or --check-facts is required");
}

async function main(argv) {
  if (argv[0] === "--verify-facts" || argv[0] === "--check-facts") return serviceMain(argv);
  const opts = parseArgs(argv);
  const result = await ingest(opts);
  console.log(result.comment);

  if (opts.out && result.derived && !result.blocked) {
    writeListing(path.join(opts.out, "plugins", result.derived.plugin.id), result.derived);
    console.error(`wrote the derived listing under ${opts.out}`);
  }

  // 0 listed, 1 blocked, 3 held for a human. Three outcomes, three exit codes:
  // a workflow that treated "needs review" as a failure would page somebody
  // every time the process worked exactly as designed.
  if (result.blocked) return 1;
  if (result.needsReview) return 3;
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`bot: ${e.message}`);
      process.exit(2);
    });
}

export { CODES };
