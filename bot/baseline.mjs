#!/usr/bin/env node
// MIG-20's migration baseline is one `migration` record per non-staging
// published version, MIG-21's historic records, and the marker that says the
// baseline was taken — `log/baseline.json` — in one commit, once, at R3
// (BOT-73). This file composes and writes the per-version records. Whatever of
// the rest a run does not do, `--write` names in the refusal it ends on
// whenever it leaves no marker on the tree (the marker floor, in `main`).
//
// Four things wait on that marker (registry plan B-T3.7b): B-T3.7's legacy
// decision writer, detector A1's ignore set (BOT-75), MIG-28's hold for every
// id with no baseline, and B-T3.6 step 0's work source. It is meant to run
// ONCE: `--write` refuses when `log/baseline.json` is already on the tree,
// which can stop a second dispatch only after a first one has committed the
// marker. So everything here is either computed from bytes already in git, or
// refused by name.
//
// ── the split, and why it is not the same split as the export's ────────────
//
// `bot/export-issues.mjs` is split at the stranger's BYTES, because it reads a
// stranger's prose. This file reads no prose at all. Its split is at the
// CREDENTIAL and at the network:
//
//   * `--population` is git alone. Every non-staging published version, with
//     the six facts its fingerprint is hashed over, read out of the committed
//     version files. No token, no network, no `gh`.
//   * `--verify` takes that population and adds what only a verified
//     certificate can say: `repository_id` and `repository_owner_id`, as
//     base-10 strings or null. It downloads and hashes the assets and runs
//     `gh attestation verify`. It never unpacks an archive.
//   * `--write` composes one record per version from those two outputs and
//     writes each through B-T2.2's writer. It also reads MIG-21's historic
//     export; the historic records, the marker and the commit are the rest of
//     its job, and the refusal it ends on names whichever of them a run left
//     undone. It reads no network and no stranger bytes (INV-37: the writing
//     job composes from facts it re-reads, never from a job that parsed
//     submitter bytes).
//
// ── what is refused by name, and why nothing stands in for it ──────────────
//
// **All three of this task's gates have landed, and this paragraph went on
// naming one of them as absent for two days after the last one did.**
// `edab81a` landed both `certificateIds` (`bot/lib/certificate.mjs`) and
// `fetchRepositoryIds` (`bot/lib/github.mjs`); `f1a9d49` then edited this file
// and left the header saying they were missing; `407b2ae` landed B-T2.2's
// `bot/lib/decisions.mjs` on 2026-09-20 and the sentence here that called it
// `MEASURED ABSENT` was still being read as true on 2026-09-22. Nothing
// executes a comment, so there was no run in which it could go red.
//
// **The refusal stopped refusing with the module, and that is the half a
// re-measurement of the file list would have missed.** `resolveWriter` in
// `bot/export-issues.mjs` checks `fs.existsSync` and then asks for
// `writeDecisionRecord`; `bot/lib/decisions.mjs` exports it. So `--write`
// resolves a writer today. (This sentence went on "where the bullet below
// says it is refused by name" — written by `e64e312` in the same commit that
// changed the bullet to say LANDED.) Whether `--write` is otherwise ready is
// B-T3.7b's question; that it is no longer stopped HERE is this file's.
//
// `tools/absent-scan.mjs` is the reader that can now disagree with an absence
// stated in this file: written as `@absent <path> (<task>)` on a comment line
// of its own, it goes red the day git tracks the path. Every claim in the
// paragraph above is prose and stays out of its reach — which is exactly why
// they lasted.
//
// @absent log/baseline.json (MIG-20)
//
// That marker is the one absence here a machine can hold. `--write` refuses
// when `log/baseline.json` already exists and `log/` is untracked today; the
// day it is not, the marker goes red — which is the day "it is meant to run
// ONCE" and "four things wait on that marker" both need re-reading, by whoever
// is running the R3 ceremony rather than by whoever finds this file next.
//
// That is not a tidying note. Two sentences a few lines down — "unreachable
// until B-T1.1 lands" over `verifyOne`, and the refusals that "stand in for
// the parts that cannot be built yet" — stopped being true at the same moment,
// and **`--verify` runs to its end now.** It was run: 41 facts, 0 verified,
// exit 0. Which is how the missing floor below was found. It had still
// downloaded nothing: run again on 2026-09-22 at `1ae13d2` it gave 42 facts,
// 0 verified, exit 1 at that floor, because `--population` emits no
// `artifact_url` and `verifyOne` fetches nothing without one.
//
// The three gates as they were, kept because the reasoning is still the
// reasoning and only the tense has moved:
//
//   * **B-T1.1** — `bot/lib/certificate.mjs`. LANDED `edab81a`.
//     `bot/lib/attestation.mjs`'s
//     `extractSignerFacts` returns `sourceRepo`, `sourceDigest`, `signerUri`
//     and the subject digests, and no ids: OIDs .15 and .17 are exactly the
//     two fields B-T1.1 adds and the two MIG-20's baseline is FOR. There is no
//     second place to read them from — ID-28 forbids a predicate fallback and
//     forbids a name lookup — so `--verify` refuses, by name, rather than
//     writing `null` ids for forty versions whose certificates are fine.
//     Null means "this certificate could not be verified" (MIG-20), and a run
//     that wrote it for a missing READER would be a baseline that recorded a
//     registry-wide attestation failure that never happened, permanently, in
//     a file that is written once.
//   * **B-T1.3** — `fetchRepositoryIds` in `bot/lib/github.mjs`. LANDED
//     `edab81a`. `--names` needs it, and refuses by name once there is a
//     baseline to compare.
//   * **B-T2.2** — `bot/lib/decisions.mjs`, which derives BOT-35's
//     `decision_id` and places the record. LANDED `407b2ae`, and with it the
//     refusal: `--write` asks through `resolveWriter`, which is imported from
//     `bot/export-issues.mjs` rather than re-written here so that the two
//     composers cannot come to disagree about which module owns an id — and
//     `resolveWriter` now returns `writeDecisionRecord` instead of throwing.
//
// Each refusal names the module, the task and the one function it wants. That
// is the whole of what this file can honestly do about them.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { resolveWriter } from "./export-issues.mjs";
// `verifyOne`'s `catch` has called this since `256aac7` moved the reading into
// `bot/lib/attestation.mjs`, and nothing imported it: the first `gh` failure a
// `--verify` run met would have stopped it with `classifyVerifyFailure is not
// defined`, exit 2 — never reached, because no version carries an
// `artifact_url` for `verifyOne` to get as far as `gh`.
import { classifyVerifyFailure } from "./lib/attestation.mjs";
import { decisionCommitMessage } from "./lib/decisions.mjs";
import { artifactDigests, submissionFingerprint } from "./lib/policy/release.mjs";
import { safeRepo, safeTag } from "./lib/safe.mjs";
import { DEFAULT_SIGNER_WORKFLOW } from "./ingest.mjs";
import { ID_PATTERN } from "../tools/lib/ids.mjs";
import { SEMVER_PATTERN } from "../tools/lib/semver.mjs";
import { isTime } from "../tools/lib/time.mjs";
import {
  BASELINE_FILE,
  BASELINE_SCHEMA,
  REPO_ROOT,
  loadSources,
  nonStagingVersions,
} from "../tools/lib/sources.mjs";

const execFileAsync = promisify(execFile);

const ID_RE = new RegExp(ID_PATTERN);
const SEMVER_RE = new RegExp(SEMVER_PATTERN);
const SHA1_RE = /^[0-9a-f]{40}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const FINGERPRINT_RE = /^[0-9a-f]{16}$/;

/**
 * Certificate ids are **base-10 strings**, never numbers (SCOPE-5).
 *
 * A GitHub repository id is past 2^31 and heading for 2^53; JSON has one number
 * type and it is a double. Writing it as a number is a record that is correct
 * today and silently wrong later, in a file written once and never rewritten.
 */
const BASE10_RE = /^[0-9]{1,20}$/;

// ── the population: git alone ───────────────────────────────────────────────

/**
 * Every non-staging published version, with the six facts its fingerprint is
 * hashed over.
 *
 * MIG-20's population, and the sentence it is read from: "one `migration`
 * record per non-staging published version". `staging` entries are excluded by
 * `nonStagingVersions`, which is in `tools/lib/sources.mjs` because three
 * readers need the same answer.
 *
 * The fingerprint is recomputed here from the committed file rather than read
 * from anywhere, and that is the point: `submissionFingerprint` hashes repo,
 * tag, id, version, release commit and every artifact digest, and all six are
 * in `plugins/<id>/versions/<v>.json`. A baseline record's fingerprint must be
 * the same string a publication would have produced, or it names nothing.
 *
 * @returns {{versions: object[], problems: string[]}}
 */
export function population(root = REPO_ROOT) {
  const { errors, plugins } = loadSources(root);
  const problems = errors.map((e) => `${e.file}: ${e.message}`);
  const versions = [];
  const commitless = [];

  for (const { plugin, version } of nonStagingVersions(plugins)) {
    const doc = version.doc;
    const where = version.file;
    const release = doc.release ?? {};
    const repo = safeRepo(release.repo);
    const tag = safeTag(release.tag);
    const commit = typeof release.commit === "string" ? release.commit : null;

    // Every one of these is a refusal rather than a null, and the difference
    // matters: a null id means a certificate did not verify, which is a fact
    // about the world MIG-20 asks to be recorded. A version file the baseline
    // cannot read is a fact about THIS TREE, and committing a baseline over a
    // tree that has one is committing a baseline that is missing a record
    // nobody will ever notice is missing.
    if (!ID_RE.test(String(doc.id ?? ""))) { problems.push(`${where}: id is not a plugin id`); continue; }
    if (!SEMVER_RE.test(String(doc.version ?? ""))) { problems.push(`${where}: version is not a semver`); continue; }
    if (!repo) { problems.push(`${where}: release.repo is not owner/name`); continue; }
    if (!tag) { problems.push(`${where}: release.tag is not a release tag`); continue; }
    if (commit !== null && !SHA1_RE.test(commit)) { problems.push(`${where}: release.commit is present and is not a 40-hex commit`); continue; }
    if (doc.id !== plugin.id) { problems.push(`${where}: id ${doc.id} is not the listing's id ${plugin.id}`); continue; }

    const digests = artifactDigests(doc);
    if (digests.length === 0) { problems.push(`${where}: no artifact digests, so it has no fingerprint`); continue; }
    for (const d of digests) {
      const sha = d.slice(d.indexOf(":") + 1);
      if (!SHA256_RE.test(sha)) problems.push(`${where}: ${d} is not a sha256`);
    }

    // **One published version in this registry has no release commit, and it
    // is not a defect in the file.** `release.commit` is optional in
    // `schema/version-v1.json` and was added to the fingerprint later, after it
    // was pointed out that the one post-approval immutability claim rested on
    // the one field the approval did not bind
    // (`bot/lib/policy/release.mjs`). `plugins/dice-roller/versions/0.1.2.json`
    // was published before that (R@2f9d379) and carries none. Measured
    // 2026-09-19: it is the only one of the 38 non-staging published versions.
    //
    // So a missing commit is carried, not refused, and it is carried the way
    // the publishing run carried it: `submissionFingerprint` hashes `commit ??
    // ""`, so recomputing with null gives the same string that run produced,
    // which is the only property that makes a baseline fingerprint mean
    // anything. It is counted and named — `--population` prints it and emits
    // it as `commitless`, and B-T3.7b has the baseline commit's message list
    // it beside the versions whose certificate was unrecoverable — because a
    // baseline record with no `commit` is a record ID-22's reads cannot be run
    // against, and that is a fact about this registry a reader should meet in
    // the run's own words rather than in a detector two steps later.
    //
    // Carried here is not recorded there. Whether a commitless version can
    // have a record is `RECORD_MEMBERS.commit`'s answer, below, and measured
    // 2026-09-22 at `1ae13d2` it cannot: over the real population `--write`
    // exits 2 on this version with "`commit` does not match its own grammar",
    // before it writes any record.
    if (commit === null) commitless.push(`${doc.id} ${doc.version} (${where})`);

    versions.push({
      plugin_id: doc.id,
      version: doc.version,
      repo,
      tag,
      commit,
      artifact_digests: digests,
      // What `--verify` downloads: every asset, by the URL and digest the
      // version file records. `--population` emitted no URL until B-T3.7b was
      // walked end to end, and `verifyOne` fetched nothing without one — 42
      // facts, 0 verified, every time. Every platform, not the first: a
      // two-platform release is two downloads and two attestation checks, and
      // its record is only as verified as the weaker of them.
      artifacts: artifactList(doc),
      fingerprint: submissionFingerprint({
        repo,
        tag,
        id: doc.id,
        version: doc.version,
        commit,
        digests,
      }),
      published_at: typeof doc.published_at === "string" ? doc.published_at : null,
      file: where,
    });
  }

  versions.sort((a, b) => (a.plugin_id === b.plugin_id
    ? a.version.localeCompare(b.version)
    : a.plugin_id.localeCompare(b.plugin_id)));
  return { versions, problems, commitless };
}

/** `artifacts.<platform>` as `[{platform, url, sha256}]`, sorted by platform. */
function artifactList(doc) {
  const out = [];
  const artifacts = doc?.artifacts && typeof doc.artifacts === "object" ? doc.artifacts : {};
  for (const platform of Object.keys(artifacts).sort()) {
    const a = artifacts[platform] ?? {};
    out.push({
      platform,
      url: typeof a.url === "string" ? a.url : null,
      sha256: typeof a.sha256 === "string" && SHA256_RE.test(a.sha256) ? a.sha256 : null,
    });
  }
  return out;
}

// ── the certificate half ────────────────────────────────────────────────────

/**
 * B-T1.1's certificate reader, or a refusal that names it.
 *
 * Deliberately shaped like `bot/export-issues.mjs`'s `resolveWriter`, and for
 * the same reason: the gap is a module that is planned and not landed, and the
 * thing that must not happen is a second implementation growing here to fill
 * it. A second reader of OIDs .15 and .17 would be a second answer to "which
 * repository published this", which is the question the whole identity chain
 * rests on.
 */
export async function resolveCertificateReader({ root, load = (s) => import(s) } = {}) {
  const here = path.dirname(new URL(import.meta.url).pathname);
  const file = path.join(root ?? here, "lib", "certificate.mjs");
  if (!fs.existsSync(file)) {
    throw new Error(
      `${path.relative(process.cwd(), file)} is not in this checkout, so no certificate id can be read. It is ` +
      "B-T1.1's reader: OIDs 1.3.6.1.4.1.57264.1.15 (`repository_id`) and .17 (`repository_owner_id`), taken " +
      "from the certificate of the result that verified the downloaded digest, or DER-parsed from the bundle " +
      "the same step verified. `bot/lib/attestation.mjs`'s `extractSignerFacts` returns neither and no " +
      "predicate field may stand in for them (ID-28). This run writes no baseline: a null id means a " +
      "certificate that did not verify, and writing it for a reader that is missing would record a " +
      "registry-wide attestation failure that did not happen, once, permanently.",
    );
  }
  const mod = await load(file);
  if (typeof mod.certificateIds !== "function") {
    throw new Error(
      `${path.relative(process.cwd(), file)} exports no \`certificateIds\`, which is the one thing this file ` +
      "asks of it: `certificateIds({ bundle, artifactSha256 })` → `{ repository_id, repository_owner_id }` as " +
      "base-10 strings or null. If B-T1.1 named it something else, this line is the only place that changes.",
    );
  }
  return mod.certificateIds;
}

/**
 * One verification fact per version: the fixed schema the `write` job composes
 * from, and the only shape that crosses between the two jobs.
 *
 * `outcome` is `verified` or `unverified`, and the ids are present only for
 * `verified`. The two are separate members rather than one nullable id, because
 * "the certificate verified and carries no .15" and "we never got a
 * certificate" are different facts and MIG-20 treats them the same way only by
 * accident of both producing null.
 *
 * @param {object[]} versions from `population`
 * @param {(v: object) => Promise<{outcome: string, repository_id: string|null,
 *   repository_owner_id: string|null}>} verify one version, verified
 */
export async function verificationFacts(versions, verify) {
  const facts = [];
  const unrecoverable = [];
  // "The verifier could not run" is not a verdict about anybody's bytes, and it
  // is the one answer that must never be written down. Counted separately from
  // `unrecoverable` — which is a real, recordable "this did not verify" — so
  // the caller can refuse the whole run rather than record the wrong thing.
  const unchecked = [];
  for (const v of versions) {
    const answer = await verify(v);
    if (answer?.outcome === "unchecked") {
      unchecked.push(`${v.plugin_id} ${v.version} (${v.repo}@${v.tag}): ${answer.why ?? "the verifier could not run"}`);
    }
    const outcome = answer?.outcome === "verified" ? "verified" : "unverified";
    const fact = {
      plugin_id: v.plugin_id,
      version: v.version,
      repo: v.repo,
      tag: v.tag,
      commit: v.commit,
      fingerprint: v.fingerprint,
      outcome,
      repository_id: outcome === "verified" ? (answer.repository_id ?? null) : null,
      repository_owner_id: outcome === "verified" ? (answer.repository_owner_id ?? null) : null,
    };
    for (const member of ["repository_id", "repository_owner_id"]) {
      if (fact[member] === null) continue;
      // **`String(v)` is not the check, and this is the line that proves it.**
      // The first spelling here coerced and then matched the pattern, which
      // accepts a JSON number: `9007199254740993` parses to
      // `9007199254740992`, `String` gives the rounded digits, the pattern is
      // happy, and the record names a repository that is not the one that
      // published the bytes. The precision is gone before any grammar sees the
      // value, so the type is what has to be refused, not the shape (SCOPE-5).
      if (typeof fact[member] !== "string" || !BASE10_RE.test(fact[member])) {
        throw new Error(
          `${v.plugin_id} ${v.version}: ${member} is ${JSON.stringify(fact[member])} ` +
          `(${typeof fact[member]}) and not a base-10 STRING (SCOPE-5). A repository id past 2^53 arriving as a ` +
          "JSON number has already lost its last digits, and coercing it to a string makes the loss unreadable.",
        );
      }
    }
    if (outcome !== "verified" || fact.repository_id === null || fact.repository_owner_id === null) {
      unrecoverable.push(`${v.plugin_id} ${v.version} (${v.repo}@${v.tag})`);
    }
    facts.push(fact);
  }
  return { facts, unrecoverable, unchecked };
}

// ── the records ─────────────────────────────────────────────────────────────

/**
 * DEC-7's members a baseline record may hold, and the grammar of each.
 *
 * The same allowlist discipline `bot/export-issues.mjs` argues for, and the
 * same reason it is an allowlist: PRIV-2 keeps names out of git, and BOT-39
 * says migration-time ids live in `migration` records and never in
 * `identity.json`. A member nobody listed is refused rather than passed on.
 *
 * `schema` and `decision_id` are absent on purpose. B-T2.2's writer stamps the
 * first and derives the second.
 */
const RECORD_MEMBERS = {
  decided_at: (v) => isTime(v),
  actor: (v) => v === "system",
  trigger: (v) => v === "migration",
  plugin_id: (v) => ID_RE.test(v),
  version: (v) => SEMVER_RE.test(v),
  repo: (v) => safeRepo(v) !== null,
  tag: (v) => safeTag(v) !== null,
  commit: (v) => typeof v === "string" && SHA1_RE.test(v),
  fingerprint: (v) => FINGERPRINT_RE.test(v),
  // A string, never null. schema/decision-v1.json: "ABSENT MEANS ABSENT, NOT
  // NULL" — an unverified certificate's ids are carried by OMITTING both
  // members, and MIG-20's "null ids never count" is read as "no ids". This
  // grammar admitted null until the dispatch was walked end to end, and a
  // record carrying one is a record tools/validate.mjs refuses on `main`,
  // after the run that cannot be repeated.
  repository_id: (v) => typeof v === "string" && BASE10_RE.test(v),
  repository_owner_id: (v) => typeof v === "string" && BASE10_RE.test(v),
  state: (v) => v === "published",
};

export function refuseUncomposable(record) {
  for (const [member, value] of Object.entries(record)) {
    const grammar = RECORD_MEMBERS[member];
    if (!grammar) {
      throw new Error(
        `\`${member}\` is not a member a baseline record composes, and PRIV-2 forbids composing anything this ` +
        "file was not told to expect. DEC-7's member list and RECORD_MEMBERS are what may cross.",
      );
    }
    if (!grammar(value)) {
      throw new Error(`\`${member}\` does not match its own grammar, so it is not the thing it claims to be`);
    }
  }
  return record;
}

/**
 * BOT-35's key for a baseline record.
 *
 * `migration:<owner/name>@<tag>` is the domain B-T2.2 states. **Here it is
 * unique by construction and there it is not**, which is the whole of the
 * difference between this file and `bot/export-issues.mjs --compose`: MIG-20
 * writes one `published` record per VERSION, and a version has one tag. MIG-21
 * writes one record per DECISION, and this registry refused and then approved
 * the same tag two to eight times.
 *
 * So the collision check is here too, asserted rather than assumed. If a tree
 * ever does carry two non-staging versions under one `owner/name@tag` — a
 * re-pointed tag, a hand-edited version file — the baseline would derive one id
 * for both and commit one record where two are owed, which is the same silent
 * shortfall for the same reason, in the run that has no second chance.
 */
export const migrationKey = (fact) => `migration:${fact.repo}@${fact.tag}`;

export function keyCollisions(facts) {
  const seen = new Map();
  for (const f of facts) {
    const k = migrationKey(f);
    seen.set(k, (seen.get(k) ?? 0) + 1);
  }
  return [...seen].filter(([, n]) => n > 1).map(([key, facts_sharing_it]) => ({ key, facts_sharing_it })).sort(
    (a, b) => a.key.localeCompare(b.key),
  );
}

/**
 * One `migration` record per verified version, state `published`, actor
 * `system`.
 *
 * `decided_at` is the version's own `published_at` and not the run's clock: the
 * record is about a publication that happened, and dating it now would put
 * forty decisions on one afternoon in the public log.
 *
 * @param {object[]} facts from `verificationFacts`
 * @param {Map<string, string>} publishedAt plugin_id@version -> §0.7 time
 */
export function composeRecords(facts, publishedAt) {
  const collisions = keyCollisions(facts);
  if (collisions.length) {
    throw new Error(
      `${collisions.length} of BOT-35's \`migration:<owner/name>@<tag>\` keys are shared by more than one ` +
      "non-staging published version, so their records would derive one id and overwrite each other: " +
      `${collisions.slice(0, 3).map((c) => `${c.key} (${c.facts_sharing_it})`).join(", ")}` +
      `${collisions.length > 3 ? ", …" : ""}. MIG-20 asks for one record per version and the domain separates ` +
      "versions, so this is a tree with two versions under one tag, not a domain that is too narrow.",
    );
  }
  return facts.map((fact) => {
    const at = publishedAt.get(`${fact.plugin_id}@${fact.version}`);
    if (!at || !isTime(at)) {
      throw new Error(
        `${fact.plugin_id} ${fact.version}: no §0.7 \`published_at\` in its version file, so this record would ` +
        "be dated by the run's clock and would say the publication happened today",
      );
    }
    // Absent where it does not apply (DEC-7), never null: a commitless
    // version (dice-roller 0.1.2 predates `release.commit` being bound) has no
    // `commit`, and a certificate that did not verify has no ids. Both are
    // named in the commit message instead, which is where a reader of a
    // record-with-a-hole is sent.
    const record = {
      decided_at: at,
      actor: "system",
      trigger: "migration",
      plugin_id: fact.plugin_id,
      version: fact.version,
      repo: fact.repo,
      tag: fact.tag,
      ...(fact.commit === null || fact.commit === undefined ? {} : { commit: fact.commit }),
      fingerprint: fact.fingerprint,
      // Both ids or neither. A baseline with a repository id and no owner id
      // is half an anchor: TRUST-23 compares the pair, and a reader that found
      // one member would compare it against nothing.
      ...(typeof fact.repository_id === "string" && typeof fact.repository_owner_id === "string"
        ? { repository_id: fact.repository_id, repository_owner_id: fact.repository_owner_id } : {}),
      state: "published",
    };
    refuseUncomposable(record);
    return { key: migrationKey(fact), record };
  });
}

// ── the marker ──────────────────────────────────────────────────────────────

/**
 * `log/baseline.json`: name-free, registry-only, written once.
 *
 * **`source_commit` is not in the plan's sentence, and it is here because
 * BOT-75 cannot be implemented without it.** BOT-75 says detectors A1 and A3
 * ignore version files and queue changes "reachable from the baseline commit
 * named in `log/baseline.json`", and the marker the plan describes — `schema`,
 * `written_at`, `version_count`, `record_count` — names no commit. It cannot
 * name its own: the marker is committed by the commit it would have to name.
 *
 * A detector could dig the commit out with `git log --diff-filter=A --
 * log/baseline.json`, and that is what it falls back to. But that is
 * archaeology over a rewritable history, and it answers a slightly different
 * question: the commit that ADDED the marker is one commit later than the tree
 * the baseline was computed over. `source_commit` is the commit `verify` read,
 * so a detector can both take its ignore set from a stated value and check that
 * value against the commit that added the file — `source_commit` must be an
 * ancestor of it. Two readings that must agree, where the plan had one that
 * could not be written down.
 */
export function marker({ writtenAt, sourceCommit, versionCount, recordCount }) {
  const doc = {
    schema: BASELINE_SCHEMA,
    written_at: writtenAt,
    source_commit: sourceCommit,
    version_count: versionCount,
    record_count: recordCount,
  };
  const problems = markerProblems(doc);
  if (problems.length) throw new Error(`refusing to write a marker four mechanisms read:\n  - ${problems.join("\n  - ")}`);
  return doc;
}

export function markerProblems(doc) {
  const problems = [];
  if (doc?.schema !== BASELINE_SCHEMA) problems.push(`schema is ${JSON.stringify(doc?.schema)}`);
  if (!isTime(doc?.written_at)) problems.push("written_at is not a §0.7 time");
  if (!SHA1_RE.test(String(doc?.source_commit))) problems.push("source_commit is not a 40-hex commit");
  if (!Number.isInteger(doc?.version_count) || doc.version_count < 1) {
    problems.push("version_count is not a positive integer; a baseline over nothing is a run that stopped working");
  }
  if (!Number.isInteger(doc?.record_count) || doc.record_count < (doc?.version_count ?? 0)) {
    problems.push("record_count is below version_count; MIG-20 asks for one record per version and MIG-21 adds more");
  }
  return problems;
}

// ── the dispatch's own checks and message ───────────────────────────────────

/**
 * Every way a facts file fails to describe the population exactly.
 *
 * By `plugin_id@version` and by fingerprint: a fact for the right version
 * whose fingerprint differs is a fact computed over a different tree — a
 * re-cut tag, a version file edited between `verify` and `write` — and
 * writing it would baseline bytes the tree does not describe.
 */
export function coverageProblems(versions, facts) {
  const problems = [];
  const byKey = new Map();
  for (const f of facts ?? []) {
    const k = `${f?.plugin_id}@${f?.version}`;
    if (byKey.has(k)) problems.push(`${f?.plugin_id} ${f?.version} is in the facts file twice`);
    byKey.set(k, f);
  }
  const seen = new Set();
  for (const v of versions) {
    const k = `${v.plugin_id}@${v.version}`;
    seen.add(k);
    const f = byKey.get(k);
    if (!f) { problems.push(`${v.plugin_id} ${v.version} is in the population and not in the facts file`); continue; }
    for (const member of ["repo", "tag", "fingerprint"]) {
      if (f[member] !== v[member]) {
        problems.push(`${v.plugin_id} ${v.version}: the facts file says ${member} ${JSON.stringify(f[member])} and the tree says ${JSON.stringify(v[member])}`);
      }
    }
    if ((f.commit ?? null) !== (v.commit ?? null)) {
      problems.push(`${v.plugin_id} ${v.version}: the facts file says commit ${JSON.stringify(f.commit ?? null)} and the tree says ${JSON.stringify(v.commit ?? null)}`);
    }
  }
  for (const k of byKey.keys()) {
    if (!seen.has(k)) problems.push(`${k.replace("@", " ")} is in the facts file and not in the population`);
  }
  return problems;
}

/** BOT-37's `Run:` value from the Actions environment, or null outside one. */
export function runTrailer(env = process.env) {
  const id = /^[0-9]{1,20}$/.test(String(env.GITHUB_RUN_ID ?? "")) ? env.GITHUB_RUN_ID : null;
  if (!id) return null;
  const attempt = /^[0-9]{1,5}$/.test(String(env.GITHUB_RUN_ATTEMPT ?? "")) ? env.GITHUB_RUN_ATTEMPT : null;
  return attempt ? `${id}/${attempt}` : id;
}

/**
 * BOT-73's one commit message: what was written, what could not be, and what
 * this commit does NOT carry — in the run's own words, because a reader of a
 * record with no ids or no commit is sent here to find out why (B-T3.7b:
 * "names every version whose certificate or approver was unrecoverable").
 */
export function baselineCommitMessage({ sourceCommit, written, versions, unrecoverable, historic, run }) {
  if (!run) throw new Error("the baseline commit carries BOT-37's `Run:` trailer; pass --run or run inside Actions");
  const commitless = versions.filter((v) => v.commit === null).map((v) => `${v.plugin_id} ${v.version} (${v.repo}@${v.tag})`);
  const lines = [
    `MIG-20's baseline over ${sourceCommit}: ${written} \`migration\` record(s), one per non-staging published ` +
      `version (${versions.length}), and log/baseline.json.`,
    "",
    `Certificate ids unrecoverable, recorded with no ids (${unrecoverable.length}):`,
    ...(unrecoverable.length ? unrecoverable.map((u) => `- ${u}`) : ["- none"]),
    "",
    `Published with no release commit, recorded with no \`commit\` (${commitless.length}):`,
    ...(commitless.length ? commitless.map((c) => `- ${c}`) : ["- none"]),
    "",
    `Not in this commit: ${historic} MIG-21 historic decision(s) the export read from issue threads. BOT-35's ` +
      "`migration:<owner/name>@<tag>` domain separates versions, not decisions about one version, so they would " +
      "derive shared ids; they are composed once an amendment to BOT-35 widens the domain (ops.22).",
  ];
  return decisionCommitMessage({
    subject: `baseline: MIG-20's migration records and marker, over ${sourceCommit.slice(0, 12)}`,
    body: lines.join("\n"),
    run,
  });
}

// ── the daily name watch (MIG-20's last sentence) ───────────────────────────

/**
 * B-T1.3's by-id reader, or a refusal that names it.
 *
 * MIG-20: "The bot MUST alarm when a baseline repository's current name
 * differs, never re-baselining from a name." Both halves need the same
 * function: the id is what is looked up, and the name is what comes back.
 */
export async function resolveNameReader({ root, load = (s) => import(s) } = {}) {
  const here = path.dirname(new URL(import.meta.url).pathname);
  const file = path.join(root ?? here, "lib", "github.mjs");
  const mod = await load(file);
  if (typeof mod.fetchRepositoryIds !== "function") {
    throw new Error(
      `${path.relative(process.cwd(), file)} exports no \`fetchRepositoryIds\`, which is B-T1.3's by-id read: ` +
      "`fetchRepositoryIds(owner/name)` → `{id, owner_id, full_name}`, following a rename redirect. This job " +
      "compares a baseline `repository_id` with the name GitHub gives for it TODAY, and there is no other way " +
      "to ask: MIG-20 forbids re-baselining from a name, so a name lookup is exactly what must not stand in.",
    );
  }
  return mod.fetchRepositoryIds;
}

/**
 * Every baseline repository whose current `full_name` is not the `source.repo`
 * the catalogue serves.
 *
 * It alarms and changes nothing — MIG-20's own sentence — because a rename is
 * the one thing a name-keyed registry cannot tell apart from a recycled login
 * (threat row 18), and the repair is a person's.
 *
 * @param {{repository_id: string, repo: string, plugin_id: string}[]} baselined
 * @param {(id: string) => Promise<{full_name: string|null, answer: string}>} lookup
 */
export async function nameDrift(baselined, lookup) {
  const drifted = [];
  const unread = [];
  const byId = new Map();
  for (const b of baselined) {
    if (!b.repository_id) continue;
    // **The one lookup MIG-20 forbids, refused here rather than avoided by
    // convention.** "Never re-baselining from a name" is not only about what
    // is written back: a watch that ASKED by name would ask the recycled
    // login, get the squatter's repository, find the name unchanged and report
    // no drift — the exact case threat row 18 is about, answered with silence.
    // A name cannot reach this function, because a name is not base-10.
    if (!/^[0-9]+$/.test(String(b.repository_id))) {
      throw new Error(
        `the rename watch was handed ${JSON.stringify(b.repository_id)} to look up, which is not a repository ` +
        "id. MIG-20 forbids re-baselining from a name, and a watch that asks by name asks the account that " +
        "holds the name today — which is the squatter, and which answers that nothing has changed.",
      );
    }
    if (!byId.has(b.repository_id)) byId.set(b.repository_id, { ...b, plugin_ids: new Set() });
    byId.get(b.repository_id).plugin_ids.add(b.plugin_id);
  }
  for (const [id, b] of [...byId].sort((a, c) => a[0].localeCompare(c[0]))) {
    const answer = await lookup(id);
    // A read that could not happen is NOT a rename. `transient` mapped to
    // absence is how a rate limit becomes an alarm about every repository at
    // once, which is the alarm nobody reads (B-T1.3: callers map `transient`
    // to `W_GITHUB_RATE_LIMITED`, never to absence).
    if (answer?.answer !== "found" || typeof answer.full_name !== "string") {
      unread.push(`${id} (${answer?.answer ?? "no answer"})`);
      continue;
    }
    if (answer.full_name.toLowerCase() !== b.repo.toLowerCase()) {
      drifted.push({
        repository_id: id,
        baselined_as: b.repo,
        now: answer.full_name,
        plugin_ids: [...b.plugin_ids].sort(),
      });
    }
  }
  return { drifted, unread, read: byId.size };
}

// ── reading what is already in git ──────────────────────────────────────────

/**
 * Every `migration` record on the checked-out tree, read from the decision log.
 *
 * `log/decisions/<YYYY>/<MM>/<decision_id>.json` is B-T2.2's layout. Reading it
 * does not need B-T2.2's writer, so this works the moment records exist, and
 * returns nothing before that — which is the honest answer, not a skip.
 */
export function readDecisionRecords(root = REPO_ROOT, dir = path.join("log", "decisions")) {
  const base = path.join(root, dir);
  const out = [];
  const walk = (d) => {
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!e.isFile() || !e.name.endsWith(".json")) continue;
      try {
        out.push({ file: path.relative(root, full), doc: JSON.parse(fs.readFileSync(full, "utf8")) });
      } catch (err) {
        out.push({ file: path.relative(root, full), error: String(err.message ?? err) });
      }
    }
  };
  walk(base);
  return out;
}

/** MIG-20's marker, which B-T3.7's condition is keyed on. */
export function markerOnMain(root) {
  const file = path.join("log", "baseline.json");
  try {
    const doc = JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
    return { present: doc?.schema === "astra.registry.baseline/1", file, doc };
  } catch {
    return { present: false, file, doc: null };
  }
}

// ── CLI ─────────────────────────────────────────────────────────────────────

const USAGE = `usage:
  bot/baseline.mjs --population [--registry-dir DIR] [--out FILE]
  bot/baseline.mjs --verify --population-file FILE [--out FILE]
  bot/baseline.mjs --write --facts-file FILE --historic-file FILE --source-commit SHA [--registry-dir DIR]
                   [--message-out FILE] [--run RUN_ID[/ATTEMPT]]
  bot/baseline.mjs --names [--registry-dir DIR]`;

function parseArgs(argv) {
  const opts = {
    mode: null, root: REPO_ROOT, out: null, populationFile: null, factsFile: null, historicFile: null,
    sourceCommit: null, messageOut: null, run: null,
    // The escape hatch for a catalogue that really is wholly unattested, and
    // it is a NUMBER rather than a boolean on purpose: a flag that means "yes,
    // whatever it is" is a flag somebody adds to a red run without reading it.
    // Saying the count out loud makes the operator state what they expect, and
    // the run refuses if the tree disagrees.
    expectUnverified: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--population") opts.mode = "population";
    else if (a === "--verify") opts.mode = "verify";
    else if (a === "--write") opts.mode = "write";
    else if (a === "--names") opts.mode = "names";
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--out") opts.out = path.resolve(argv[++i]);
    else if (a === "--population-file") opts.populationFile = path.resolve(argv[++i]);
    else if (a === "--facts-file") opts.factsFile = path.resolve(argv[++i]);
    else if (a === "--historic-file") opts.historicFile = path.resolve(argv[++i]);
    else if (a === "--source-commit") opts.sourceCommit = argv[++i];
    else if (a === "--message-out") opts.messageOut = path.resolve(argv[++i]);
    else if (a === "--run") opts.run = argv[++i];
    else if (a === "--expect-unverified") {
      const raw = argv[++i];
      if (!/^\d+$/.test(String(raw))) throw new Error(`--expect-unverified needs a count, not ${JSON.stringify(raw)}\n${USAGE}`);
      opts.expectUnverified = Number(raw);
    }
    else throw new Error(`unknown argument: ${a}\n${USAGE}`);
  }
  if (!opts.mode) throw new Error(`one of --population, --verify, --write or --names is required\n${USAGE}`);
  return opts;
}

function emit(opts, doc) {
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  if (opts.out) fs.writeFileSync(opts.out, json);
  else process.stdout.write(json);
}

async function main(argv) {
  const opts = parseArgs(argv);

  if (opts.mode === "population") {
    const { versions, problems, commitless } = population(opts.root);
    emit(opts, { generated_at: `${new Date().toISOString().slice(0, 19)}Z`, versions, problems, commitless });
    console.error(
      `population ${versions.length} non-staging published version(s); ${commitless.length} with no release ` +
      `commit; ${problems.length} problem(s)`,
    );
    for (const c of commitless) console.error(`  no release commit: ${c}`);
    for (const p of problems) console.error(`  - ${p}`);
    // Both floors. Zero versions is a reader that stopped working, and any
    // problem at all is a tree the baseline must not be taken over: this run
    // happens once, so a version it could not read is a record nobody will
    // notice is missing.
    if (versions.length === 0) {
      console.error("bot: no non-staging published version was found, and this registry has some");
      return 1;
    }
    return problems.length === 0 ? 0 : 1;
  }

  if (opts.mode === "verify") {
    if (!opts.populationFile) throw new Error(`--verify needs --population-file <file>\n${USAGE}`);
    const doc = JSON.parse(fs.readFileSync(opts.populationFile, "utf8"));
    // Refuses here, before a single asset is downloaded, because the answer is
    // the same afterwards and forty downloads to reach it would read like a
    // network problem.
    const certificateIds = await resolveCertificateReader({});
    const { facts, unrecoverable, unchecked } = await verificationFacts(doc.versions ?? [], (v) => verifyOne(v, certificateIds));
    emit(opts, { generated_at: `${new Date().toISOString().slice(0, 19)}Z`, facts, unrecoverable, unchecked });
    console.error(`verified ${facts.length - unrecoverable.length} of ${facts.length} version(s)`);
    for (const u of unchecked) console.error(`  NOT CHECKED: ${u}`);
    if (facts.length === 0) {
      console.error("bot: the population held no version, so this run verified nothing");
      return 1;
    }
    // Two floors, and `population` mode has had both since it was written.
    // `--verify` had neither, so `41 of 41 unverified` exited 0 and `--write`
    // — which needs only that this job succeeded — would then have composed
    // forty-one permanent records saying the catalogue is unattested.
    if (unchecked.length) {
      console.error(
        `bot: ${unchecked.length} of ${facts.length} version(s) were NOT CHECKED — the verifier could not run, ` +
        "which is not a fact about anybody's artifact. MIG-20's baseline is written once and cannot be " +
        "corrected, so this run stops rather than recording a runner problem as a registry-wide attestation " +
        "failure. Run it again.",
      );
      return 1;
    }
    if (unrecoverable.length === facts.length) {
      console.error(
        `bot: not one of ${facts.length} version(s) verified. A wholesale failure is a broken tool far more ` +
        "often than it is a catalogue where every attestation is bad — measured 2026-09-19, dropping " +
        "`--signer-workflow` alone did exactly this to 12 of 18. If the catalogue really is in that state, " +
        "say so with --expect-unverified " + facts.length + ".",
      );
      return opts.expectUnverified === facts.length ? 0 : 1;
    }
    return 0;
  }

  if (opts.mode === "names") {
    const markerFile = path.join(opts.root, BASELINE_FILE);
    if (!fs.existsSync(markerFile)) {
      // Loud, and green. There is nothing to compare and nothing has gone
      // wrong: this is every scheduled run between the day this workflow lands
      // and the day the baseline is dispatched. A red run here would page for
      // a state the plan puts weeks of work inside.
      console.log(`ok    no ${BASELINE_FILE} on this tree, so there is no baseline repository to watch a rename of`);
      console.log("      MIG-20's name alarm starts at B-T3.7b's dispatch; until then this job proves its own schedule is alive");
      return 0;
    }
    const baselined = readDecisionRecords(opts.root)
      .map((r) => r.doc)
      .filter((d) => d?.trigger === "migration" && d?.state === "published" && d?.repository_id)
      .map((d) => ({ repository_id: String(d.repository_id), repo: d.repo, plugin_id: d.plugin_id }));
    const fetchRepositoryIds = await resolveNameReader({});
    const { drifted, unread, read } = await nameDrift(baselined, async (id) => {
      const answer = await fetchRepositoryIds(id);
      return { answer: answer?.answer ?? "not_found", full_name: answer?.full_name ?? null };
    });
    for (const d of drifted) {
      console.log(`ALARM ${d.repository_id} baselined as ${d.baselined_as} and GitHub now calls it ${d.now} (${d.plugin_ids.join(" ")})`);
    }
    for (const u of unread) console.log(`warn  ${u} could not be read; a read that did not happen is not a rename`);
    console.log(`ok    ${read} baseline repository id(s) read; ${drifted.length} renamed`);
    return drifted.length === 0 ? 0 : 1;
  }

  if (!opts.factsFile || !opts.historicFile) throw new Error(`--write needs --facts-file and --historic-file\n${USAGE}`);
  if (!SHA1_RE.test(String(opts.sourceCommit))) throw new Error("--write needs --source-commit <40 hex>");
  if (fs.existsSync(path.join(opts.root, BASELINE_FILE))) {
    throw new Error(
      `${BASELINE_FILE} is already on this tree. MIG-20's baseline is written once, at R3, and a second run ` +
      "would write a second `migration` record for every version under the same BOT-35 key.",
    );
  }
  const verified = JSON.parse(fs.readFileSync(opts.factsFile, "utf8"));
  // The facts file is an artifact handed between two jobs, so `--write` checks
  // it rather than trusting that `--verify` succeeded. The `write` job needs
  // only `[verify, export]`, and "the verify job exited 0" is a weaker claim
  // than "this file says nothing went unchecked" — a re-run, a hand-edited
  // artifact or a future change to either job's gating all break the first and
  // none of them break the second.
  if (Array.isArray(verified.unchecked) && verified.unchecked.length) {
    throw new Error(
      `the facts file records ${verified.unchecked.length} version(s) the verifier could not check:\n  ` +
      verified.unchecked.slice(0, 3).join("\n  ") +
      (verified.unchecked.length > 3 ? `\n  … and ${verified.unchecked.length - 3} more` : "") +
      "\nMIG-20's baseline is written once. A version nobody could check is not a version that failed, and " +
      "recording it as one is permanent.",
    );
  }
  const factList = verified.facts ?? [];
  const noneVerified = factList.length > 0 && factList.every((f) => f.outcome !== "verified");
  if (noneVerified && opts.expectUnverified !== factList.length) {
    throw new Error(
      `not one of ${factList.length} fact(s) in the facts file is \`verified\`, and this write is the one that ` +
      "cannot be taken back. Dropping `--signer-workflow` produced exactly this shape on 12 of 18 good " +
      `attestations. If the catalogue really is unattested, say the number: --expect-unverified ${factList.length}.`,
    );
  }
  const historic = JSON.parse(fs.readFileSync(opts.historicFile, "utf8"));
  const { versions, problems: treeProblems } = population(opts.root);
  if (treeProblems.length) {
    throw new Error(
      `this tree has ${treeProblems.length} version file(s) the baseline cannot read, and a baseline taken over it ` +
      `is missing a record nobody will notice is missing:\n  ${treeProblems.slice(0, 5).join("\n  ")}`,
    );
  }
  // The facts file must cover the population EXACTLY, checked before a single
  // record is written. `write` needs only that `verify` succeeded, and a facts
  // file that dropped a version — a re-run over a changed tree, a hand-edited
  // artifact — would otherwise leave that version with no `migration` record,
  // in a baseline written once, with detector A1 reporting it for ever.
  const coverage = coverageProblems(versions, factList);
  if (coverage.length) {
    throw new Error(
      `the facts file does not describe the population this tree holds (${coverage.length} difference(s)):\n  ` +
      coverage.slice(0, 5).join("\n  ") + (coverage.length > 5 ? `\n  … and ${coverage.length - 5} more` : ""),
    );
  }
  const publishedAt = new Map(versions.map((v) => [`${v.plugin_id}@${v.version}`, v.published_at]));
  const composed = composeRecords(factList, publishedAt);
  const write = await resolveWriter({});
  const written = [];
  for (const { key, record } of composed) {
    const out = await write({ key, record, root: opts.root });
    // A dropped write here is a SECOND baseline: a `migration` record for this
    // version is already on the tree. The marker guard above stops a second
    // dispatch; this stops a tree that carries records without a marker —
    // a half-taken baseline — from being papered over with a new marker.
    if (out && out.written === false) {
      throw new Error(`${record.plugin_id} ${record.version}: ${out.dropped}. A baseline is taken once, over a tree with no \`migration\` records`);
    }
    written.push(out);
  }

  // MIG-21's historic decisions: exported, counted, and NOT composed here.
  //
  // `bot/export-issues.mjs --compose` refuses the live archive, because
  // BOT-35's `migration:<owner/name>@<tag>` domain separates versions, not
  // decisions about one version: this registry refused and then approved one
  // tag two to eight times, and each of those derives one id. The same domain
  // also collides with THIS run's records — a historic approval of a tag that
  // is now a published version derives the id of that version's baseline
  // record. Widening the domain is an amendment to BOT-35 (ops.22), not an
  // edit here, so this commit carries MIG-20's records and the marker, and
  // its message says how many historic decisions are waiting and on what.
  // Nothing MIG-20 feeds waits on them: B-T3.7's writer, detector A1, MIG-28
  // and B-T3.6's work source all key on the baseline records and the marker.
  const historicFacts = Array.isArray(historic?.facts) ? historic.facts : [];
  const markerDoc = marker({
    writtenAt: `${new Date().toISOString().slice(0, 19)}Z`,
    sourceCommit: opts.sourceCommit,
    versionCount: versions.length,
    recordCount: written.length,
  });
  fs.mkdirSync(path.join(opts.root, "log"), { recursive: true });
  fs.writeFileSync(path.join(opts.root, BASELINE_FILE), `${JSON.stringify(markerDoc, null, 2)}\n`);
  console.error(
    `wrote ${written.length} baseline record(s) and ${BASELINE_FILE}; ${historicFacts.length} MIG-21 historic ` +
    "decision(s) exported and not composed (BOT-35's migration domain cannot separate them; ops.22)",
  );

  if (opts.messageOut) {
    fs.writeFileSync(opts.messageOut, baselineCommitMessage({
      sourceCommit: opts.sourceCommit,
      written: written.length,
      versions,
      unrecoverable: Array.isArray(verified.unrecoverable) ? verified.unrecoverable : [],
      historic: historicFacts.length,
      run: opts.run ?? runTrailer(process.env),
    }));
  }

  // ── the marker floor ──
  //
  // Kept after the write that now makes it pass, because it is the one thing
  // this run can check about itself: whether the marker is on the tree when
  // it ends. Until B-T3.7b was walked end to end no version of `--write` wrote
  // one, and every earlier dispatch would have gone green with nothing for
  // A1, B-T3.7 or MIG-28 to key on. A future edit that drops the write above
  // is refused here by name, not discovered at R3.
  const onTree = markerOnMain(opts.root);
  if (!onTree.present || JSON.stringify(onTree.doc) !== JSON.stringify(markerDoc)) {
    throw new Error(
      `this --write leaves no ${BASELINE_FILE} on the tree matching the marker it composed, so it has not taken ` +
      "MIG-20's baseline, and it will not exit 0 as if it had.",
    );
  }
  return 0;
}

/**
 * One version, verified: download, hash, `gh attestation verify`, read the ids.
 *
 * **Reachable since `edab81a`.** This said "unreachable until B-T1.1 lands,
 * because `resolveCertificateReader` refuses before this is called", and that
 * stopped being true when B-T1.1 landed — which nothing noticed, because a
 * docstring saying a function cannot run is not a thing anything executes.
 *
 * It is worth keeping the original reason it was written out in full rather
 * than left as a TODO: so that what the `verify` job does is a thing a reader
 * can check against the plan rather than a hole shaped like one. The sentence
 * that followed it is now the interesting one — the day it became reachable,
 * `--verify` ran end to end and exited **0** having verified **0 of 41**,
 * because the only floor it had was `facts.length === 0`.
 */
async function verifyOne(v, certificateIds, deps = {}) {
  const assets = Array.isArray(v.artifacts) ? v.artifacts : [];
  const none = { repository_id: null, repository_owner_id: null };
  if (assets.length === 0) {
    return { outcome: "unverified", why: "the version file names no artifact to download", ...none };
  }
  // Every asset, and the version is only as verified as the weakest of them:
  // one bundle that did not verify is a release whose certificate cannot be
  // said to cover what the listing serves.
  const answers = [];
  for (const a of assets) answers.push(await verifyAsset(v, a, certificateIds, deps));
  const unchecked = answers.find((x) => x.outcome === "unchecked");
  if (unchecked) return unchecked;
  const failed = answers.find((x) => x.outcome !== "verified");
  if (failed) return { outcome: "unverified", why: failed.why ?? null, ...none };
  // One release, one repository. Two assets whose certificates name different
  // ids are not a release this baseline can anchor to either of them.
  const ids = new Set(answers.map((x) => `${x.repository_id}/${x.repository_owner_id}`));
  if (ids.size !== 1) {
    return { outcome: "unverified", why: `its ${answers.length} assets' certificates name ${ids.size} different repositories`, ...none };
  }
  return { outcome: "verified", repository_id: answers[0].repository_id, repository_owner_id: answers[0].repository_owner_id };
}

/**
 * One asset: download, hash against the recorded digest, `gh attestation
 * verify`, read the ids. Never unpacked.
 */
async function verifyAsset(v, a, certificateIds, deps = {}) {
  const fetchImpl = deps.fetch ?? fetch;
  const run = deps.run ?? ((args) => execFileAsync("gh", args, { maxBuffer: 16 * 1024 * 1024, timeout: 120_000 }));
  const none = { repository_id: null, repository_owner_id: null };
  if (!a?.url) return { outcome: "unverified", why: `${a?.platform ?? "an asset"} has no URL`, ...none };
  let res;
  try {
    res = await fetchImpl(a.url);
  } catch (e) {
    // A download that could not happen is a fact about the network, not about
    // the artifact, and this record is written once.
    return { outcome: "unchecked", why: `the ${a.platform} asset could not be downloaded: ${String(e?.message ?? e)}`, ...none };
  }
  if (!res.ok) {
    if (res.status >= 500 || res.status === 429) {
      return { outcome: "unchecked", why: `the ${a.platform} asset's host answered HTTP ${res.status}`, ...none };
    }
    return { outcome: "unverified", why: `the ${a.platform} asset is gone (HTTP ${res.status})`, ...none };
  }
  // Hashed, never unpacked: a baseline run must not be the thing that opens
  // forty strangers' archives (B-T3.7b: "never unpacking an archive").
  const bytes = Buffer.from(await res.arrayBuffer());
  const artifactSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  // The bytes at the URL have to be the bytes the listing recorded. An
  // attestation over different bytes is an attestation about a different
  // artifact, however well it verifies.
  if (a.sha256 && artifactSha256 !== a.sha256) {
    return { outcome: "unverified", why: `the ${a.platform} asset's bytes are not the ones its version file records`, ...none };
  }
  const tmp = path.join(fs.mkdtempSync(path.join(process.env.RUNNER_TEMP ?? os.tmpdir(), "astra-baseline-")), "asset");
  fs.writeFileSync(tmp, bytes);
  try {
    // `--signer-workflow` is not optional here, and leaving it out is not a
    // weaker check — it is a failing one. `gh` derives its certificate-identity
    // matcher from `--repo`, and the SAN in these certificates is the URI of
    // the REUSABLE workflow in AstraPlugins, not of the plugin's own
    // repository. Measured 2026-09-19 over every listing: the command without
    // the flag fails on **12 of 18** perfectly good attestations, with
    // `Error: verifying with issuer "sigstore.dev"` and no named check.
    const { stdout } = await run([
      "attestation", "verify", tmp, "--repo", v.repo,
      "--signer-workflow", DEFAULT_SIGNER_WORKFLOW,
      "--format", "json",
    ]);
    const ids = await certificateIds({ bundle: JSON.parse(stdout), artifactSha256 });
    return { outcome: "verified", repository_id: ids?.repository_id ?? null, repository_owner_id: ids?.repository_owner_id ?? null };
  } catch (e) {
    // `gh` exits 1 whether the attestation is absent, wrong, or **never
    // checked at all** — no network, Sigstore's trust root unreachable, a
    // timeout. Collapsing the third into "unverified" writes a fact about the
    // RUNNER into a record about the ARTIFACT, in a file that is written once
    // and can never be corrected. So the third is its own outcome and it stops
    // the run: `unchecked` never reaches a record.
    const said = `${e?.stderr ?? ""}${e?.message ?? ""}`;
    const { unavailable } = classifyVerifyFailure(said);
    return {
      outcome: unavailable ? "unchecked" : "unverified",
      why: (String(e?.stderr ?? e?.message ?? "").trim().split("\n")[0]) || "the verifier could not run",
      ...none,
    };
  } finally {
    fs.rmSync(path.dirname(tmp), { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`bot: ${e.message}`);
      process.exit(2);
    });
}
