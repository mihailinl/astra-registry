#!/usr/bin/env node
// BOT-88's weekly release canary, the registry's half (registry plan B-T1.6,
// reg.24).
//
//     node tools/release-canary.mjs --verify [--out report.json]
//
// Once a week `mihailinl/astra-registry-canary` pushes one tag per caller of
// AstraPlugins' `plugin-release.yml` — one caller per commit trust.json's
// `reusable_workflow_shas` allowlists — and each tag builds, signs and attests
// a Release through that commit exactly as an author's tag would. Nothing else
// exercises those commits between real releases, and each pulls moving action
// tags and a moving toolchain, so a GitHub-side break would otherwise be found
// by the first third-party author to tag (BOT-88; OPEN-OPS-17's emergency
// ceremony is what a red here sets off). This file is the half that looks.
//
// For every allowlisted commit it takes the newest canary Release built
// through it, downloads and hashes each bundle, runs `gh attestation verify`
// through the SAME `verifyAttestation` ingest uses — ID-28's ten fields, `.10`
// against the root-signed allowlist, the subject digest, `.12` — and then asks
// what only the canary can ask:
//
//   * `.10` is THIS commit, not merely an allowlisted one. A caller whose pin
//     moved to the other allowlisted commit builds a perfectly valid release
//     under this commit's tag prefix, and the commit the prefix names would be
//     reported healthy while nothing had built through it;
//   * `.13` is the commit the tag points at (ID-28's `E_RELEASE_COMMIT_MISMATCH`
//     row), read from the tag, not from `target_commitish`;
//   * `.15` and `.17` are the canary repository's own two ids, pinned below as
//     an identity record would pin them;
//   * the owner file at `.13`, read by `.15` (ID-22), carries exactly one line
//     of ID-23's grammar (B-T2.4's parser). The canary's line is a token nobody
//     minted and nothing asks a verdict about it (BOT-88: "the canary asks no
//     verdict"), so it is grammar and nothing else;
//   * this week's tag has a Release, and the newest Release is not older than
//     `STALE_DAYS`. A release workflow that broke on GitHub's side leaves a tag
//     and no Release, and a canary that only verified "the newest Release"
//     would verify last week's for ever.
//
// It commits nothing and writes nothing but its report. It exits 0 green, 1
// red and 2 when it could not run, and the workflow's `alert` job carries the
// verdict — codes and the failing commits, never a sentence — to the alarm
// chat and posts the `release-canary` heartbeat (BOT-85).
//
// ── where this file lives, and why not where the plan puts it ──────────────
//
// The plan names `bot/release-canary.mjs`. A new top-level `bot/*.mjs` is a
// contract MINOR under TRUST-31, published before the file lands
// (`bot/tests/code-paths.test.mjs`, "the two enumerated groups are exactly
// what is on the tree"), and `bot/lib/` would put it inside the hashed set, so
// every edit to a canary the bot never runs would drop the bot into shadow
// from R3 and cost an operator acknowledgement (ROLL-64). Neither buys
// anything: no bot workflow reaches this file, it runs under no bot token (it
// asks the service nothing), and nothing the bot decides reads what it says.
// So it sits beside `tools/service-conformance.mjs` (BOT-90's canary, which
// made the same move for the same reason, contract 2.5.0), outside the set,
// and it IMPORTS every rule it must not hold a second copy of: the allowlist
// loader, `verifyAttestation`, `checkBundlesAgree`, `readBindingLine`, the
// asset download and the signer-workflow path.
//
// ── the credential ─────────────────────────────────────────────────────────
//
// The plan says the verify job holds "no token". `gh` will not run without one
// (gh 2.100.0 with `GITHUB_ACTIONS=true` and none: exit 4, measured by
// B-T3.7b), so the job carries its own `github.token` at `contents: read` —
// the same decision `baseline.yml`'s `verify` job made — which can read this
// repository and public data and write nothing anywhere. The canary
// repository is public; its Releases, tags and attestations need no grant.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { loadWorkflowAllowlist, verifyAttestation } from "../bot/lib/attestation.mjs";
import { checkBundlesAgree } from "../bot/lib/certificate.mjs";
import { readBindingLine } from "../bot/lib/binding.mjs";
import { downloadAsset } from "../bot/lib/github.mjs";
import { DEFAULT_SIGNER_WORKFLOW } from "../bot/ingest.mjs";
import { VERDICT_SCHEMA } from "../bot/lib/alert-verdict.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

/**
 * The test repository, and the two ids its certificates must carry (`.15`,
 * `.17`). Measured 2026-09-23 off `release-canary-c3f3424-v0.20260923.1`'s
 * certificate and `GET /repos/mihailinl/astra-registry-canary`, which agree.
 * Pinned as an identity record pins a listing's: a re-created repository of
 * the same name is a different id, and a canary that followed the name would
 * verify a stranger's releases.
 */
export const CANARY = Object.freeze({
  repo: "mihailinl/astra-registry-canary",
  repository_id: "1383247080",
  repository_owner_id: "193032699",
});

/** The reusable workflow every canary caller pins, the same path ingest verifies against. */
export const SIGNER_WORKFLOW = DEFAULT_SIGNER_WORKFLOW;

/**
 * How old the newest Release may be. The canary tags every Monday at 06:17
 * UTC and this runs the same day, hours later, so a healthy week sees a
 * Release a few hours old and a week whose tag never happened sees one about
 * seven days old. Nine days is seven plus room for GitHub holding a schedule
 * back (13 hours measured, `bot/lib/alert-checks.mjs`) on either side, so a
 * late tag is not a page; two missed weeks in a row always are. A tag that
 * started a Release which never finished is caught the same week by
 * `RELEASE_CANARY_TAG_UNRELEASED`, which is the case this canary exists for.
 */
export const STALE_DAYS = 9;

/** ID-28's grammar for the commit the canary is about. */
const SHA_RE = /^[0-9a-f]{40}$/;

/** The receiver check, `bot/lib/alert-checks.mjs`'s row. */
export const CHECK = "release-canary";

/**
 * Every code this tool emits, and nothing else: never a sentence, never a
 * value a repository chose. The `E_*`, `B_*` and `W_*` codes are the registry's
 * own, as `verifyAttestation`, `readBindingLine` and ingest name them; the
 * `RELEASE_CANARY_*` ones are this canary's.
 */
export const CODES = Object.freeze([
  "E_TRUST_UNPROVISIONED",
  "RELEASE_CANARY_EMPTY_ALLOWLIST",
  "RELEASE_CANARY_LIST_FAILED",
  "RELEASE_CANARY_NO_RELEASE",
  "RELEASE_CANARY_TAG_UNRELEASED",
  "RELEASE_CANARY_TAG_MISSING",
  "RELEASE_CANARY_STALE",
  "RELEASE_CANARY_NO_BUNDLE",
  "RELEASE_CANARY_DOWNLOAD_FAILED",
  "E_ASSET_URL_FOREIGN",
  "E_ATTESTATION_MISSING",
  "E_ATTESTATION_UNCHECKED",
  "E_ATTESTATION_INVALID",
  "E_ATTESTATION_SUBJECT_MISMATCH",
  "E_ATTESTATION_REPO_MISMATCH",
  "E_WORKFLOW_NOT_ALLOWED",
  "RELEASE_CANARY_WRONG_SIGNER",
  "E_RELEASE_COMMIT_MISMATCH",
  "RELEASE_CANARY_IDS",
  "B_BINDING_MALFORMED",
  "RELEASE_CANARY_BINDING_ABSENT",
  "W_GITHUB_RATE_LIMITED",
]);

/**
 * A canary tag for one allowlisted commit: `release-canary-<sha7>-v0.<YYYYMMDD>.<n>`,
 * `n` from 1 with no leading zero — the canary repository's `canaryTagPattern`
 * over the prefix its callers use. Anchored at both ends: one commit's pattern
 * never matches another's tag, or a suffixed one.
 */
export function tagPattern(sha) {
  if (!SHA_RE.test(String(sha))) throw new Error(`${JSON.stringify(sha)} is not a 40-hex commit`);
  return new RegExp(`^release-canary-${sha.slice(0, 7)}-v0\\.([0-9]{8})\\.([1-9][0-9]*)$`);
}

/** `[date, n]` of a tag under `re`, or null. Compared as numbers, never as strings. */
function orderOf(re, name) {
  const m = re.exec(String(name ?? ""));
  return m ? [Number(m[1]), Number(m[2])] : null;
}
const newer = (a, b) => (a[0] !== b[0] ? a[0] > b[0] : a[1] > b[1]);

function newestBy(re, items, nameOf) {
  let best = null;
  let bestOrder = null;
  for (const item of items) {
    const o = orderOf(re, nameOf(item));
    if (!o) continue;
    if (!best || newer(o, bestOrder)) { best = item; bestOrder = o; }
  }
  return best ? { item: best, order: bestOrder } : null;
}

const finding = (sha, code, message, where = null) => ({ sha, code, where, message });

/**
 * Which Release each allowlisted commit is judged by, and what is wrong
 * before a byte is downloaded. Pure.
 *
 * @param {{allowlist: string[], releases: object[], tags: {name: string, commit: string}[], now: Date}} opts
 *   `releases` as `GET /repos/{repo}/releases` returns them; `tags` with each
 *   tag's COMMIT (an annotated tag already dereferenced by the caller).
 * @returns {{selected: {sha: string, release: object, tagCommit: string|null}[], findings: object[]}}
 */
export function selectReleases({ allowlist, releases, tags, now }) {
  const findings = [];
  const selected = [];
  if (!Array.isArray(allowlist) || allowlist.length === 0) {
    findings.push(finding(null, "RELEASE_CANARY_EMPTY_ALLOWLIST",
      "trust.json allowlists no reusable-workflow commit, so there is nothing to hold a canary to; a green run " +
      "over nothing would read exactly like a healthy week"));
    return { selected, findings };
  }
  const published = (releases ?? []).filter((r) => r && r.draft !== true && r.prerelease !== true);
  for (const sha of allowlist) {
    const re = tagPattern(sha);
    const rel = newestBy(re, published, (r) => r.tag_name);
    if (!rel) {
      findings.push(finding(sha, "RELEASE_CANARY_NO_RELEASE",
        `no published Release in ${CANARY.repo} matches release-canary-${sha.slice(0, 7)}-v0.<YYYYMMDD>.<n>, so ` +
        `nothing shows that ${sha} still builds a release (BOT-88's floor: one release per allowlisted commit)`));
      continue;
    }
    const release = rel.item;
    const tag = newestBy(re, tags ?? [], (t) => t.name);
    if (tag && newer(tag.order, rel.order)) {
      findings.push(finding(sha, "RELEASE_CANARY_TAG_UNRELEASED",
        `tag ${tag.item.name} is newer than the newest Release (${release.tag_name}): the release it started never ` +
        `published, which is the GitHub-side break in ${sha} this canary exists to find`));
      continue;
    }
    const own = (tags ?? []).find((t) => t.name === release.tag_name) ?? null;
    if (!own || !SHA_RE.test(String(own.commit))) {
      findings.push(finding(sha, "RELEASE_CANARY_TAG_MISSING",
        `${release.tag_name} has a Release and no tag pointing at a commit, so the certificate's .13 has nothing ` +
        "to be compared with"));
      continue;
    }
    const at = Date.parse(String(release.published_at ?? ""));
    const age = now.getTime() - at;
    if (!Number.isFinite(at) || age > STALE_DAYS * 24 * 3600e3) {
      findings.push(finding(sha, "RELEASE_CANARY_STALE",
        `the newest Release through ${sha}, ${release.tag_name}, was published ${release.published_at ?? "at no time GitHub reported"}, ` +
        `more than ${STALE_DAYS} days before this run: the weekly tag has stopped reaching this commit`));
      continue;
    }
    selected.push({ sha, release, tagCommit: own.commit });
  }
  return { selected, findings };
}

/** `readBindingLine`'s answer, as this canary judges it. */
export function bindingFinding(sha, parsed, tag) {
  if (parsed.outcome === "one") return null;
  if (parsed.outcome === "malformed") {
    return finding(sha, "B_BINDING_MALFORMED", `${tag}'s owner file: ${parsed.reason} (ID-23, ID-24)`);
  }
  if (parsed.outcome === "none") {
    return finding(sha, "RELEASE_CANARY_BINDING_ABSENT",
      `${tag}'s owner file carries no binding line (${parsed.reason}); the canary commits one on every tag commit, ` +
      "so the parser is no longer exercised by anything that builds");
  }
  return finding(sha, "W_GITHUB_RATE_LIMITED", `${tag}'s owner file could not be read: ${parsed.reason}`);
}

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/**
 * One bundle: download, hash, verify, and the canary's own comparisons.
 * Returns its findings and, when the certificate was read, its fields.
 */
async function verifyBundle({ sha, release, tagCommit, asset, allowlist, deps, dir }) {
  const out = [];
  const where = asset.name;
  const prefix = `https://github.com/${CANARY.repo}/releases/download/${release.tag_name}/`;
  const url = asset.browser_download_url;
  if (typeof url !== "string" || !url.startsWith(prefix)) {
    out.push(finding(sha, "E_ASSET_URL_FOREIGN", `${url} does not sit under ${prefix}`, where));
    return { findings: out, fields: null };
  }
  let bytes;
  try {
    bytes = await deps.download(url, deps.maxBytes);
  } catch (e) {
    out.push(finding(sha, "RELEASE_CANARY_DOWNLOAD_FAILED", `${url}: ${e.message}`, where));
    return { findings: out, fields: null };
  }
  const file = path.join(dir, path.basename(asset.name));
  fs.writeFileSync(file, bytes);
  const verified = await verifyAttestation({
    file,
    repo: CANARY.repo,
    signerWorkflow: SIGNER_WORKFLOW,
    allowlist,
    artifactSha256: sha256(bytes),
    tag: release.tag_name,
    runner: deps.ghRunner,
  });
  for (const f of verified.findings) {
    if (f.level === "error") out.push(finding(sha, f.code, f.message, where));
  }
  const fields = verified.facts?.fields ?? null;
  if (!fields) return { findings: out, fields: null };

  if (fields.job_workflow_sha !== null && fields.job_workflow_sha !== sha) {
    out.push(finding(sha, "RELEASE_CANARY_WRONG_SIGNER",
      `${release.tag_name} is filed under ${sha} and its certificate's .10 is ${fields.job_workflow_sha}: the caller's ` +
      `pin moved, and nothing this week built through ${sha}`, where));
  }
  if (fields.sha !== null && fields.sha !== tagCommit) {
    out.push(finding(sha, "E_RELEASE_COMMIT_MISMATCH",
      `the certificate's .13 is ${fields.sha} and ${release.tag_name} points at ${tagCommit}`, where));
  }
  if (fields.repository_id !== CANARY.repository_id || fields.repository_owner_id !== CANARY.repository_owner_id) {
    out.push(finding(sha, "RELEASE_CANARY_IDS",
      `the certificate's .15/.17 are ${fields.repository_id}/${fields.repository_owner_id}; ${CANARY.repo} is ` +
      `${CANARY.repository_id}/${CANARY.repository_owner_id}`, where));
  }
  return { findings: out, fields };
}

/**
 * The whole canary over one listing of the test repository.
 *
 * @param {{allowlist: string[], releases: object[], tags: {name: string, commit: string}[], now: Date,
 *   deps: {download: Function, ghRunner?: Function, bindingDeps?: object, maxBytes?: number, tmpDir?: string}}} opts
 * @returns {Promise<{status: "green"|"red", findings: object[], checked: object[]}>}
 */
export async function runCanary({ allowlist, releases, tags, now, deps }) {
  const { selected, findings } = selectReleases({ allowlist, releases, tags, now });
  const checked = [];
  const dir = fs.mkdtempSync(path.join(deps.tmpDir ?? os.tmpdir(), "release-canary-"));
  try {
    for (const { sha, release, tagCommit } of selected) {
      const bundles = (release.assets ?? []).filter((a) => typeof a?.name === "string" && a.name.endsWith(".astraplugin"));
      if (bundles.length === 0) {
        findings.push(finding(sha, "RELEASE_CANARY_NO_BUNDLE", `${release.tag_name} carries no .astraplugin asset`));
        continue;
      }
      const read = [];
      let verifiedCount = 0;
      for (const asset of bundles) {
        const r = await verifyBundle({ sha, release, tagCommit, asset, allowlist, deps, dir });
        findings.push(...r.findings);
        if (r.fields) read.push({ where: asset.name, fields: r.fields });
        if (r.fields && r.findings.length === 0) verifiedCount++;
      }
      for (const f of checkBundlesAgree(read)) findings.push(finding(sha, f.code, f.message, f.where));

      // ID-22: the line at the ATTESTED commit, by the certificate's repository
      // id. Only once a bundle's certificate was read: without `.13` and `.15`
      // there is no commit to read it at, and that failure is already named.
      let binding = null;
      const first = read.find((b) => b.fields.repository_id && b.fields.sha);
      if (first) {
        const parsed = await readBindingLine({
          repositoryId: first.fields.repository_id,
          commit: first.fields.sha,
          deps: deps.bindingDeps ?? {},
        });
        binding = parsed.outcome;
        const f = bindingFinding(sha, parsed, release.tag_name);
        if (f) findings.push(f);
      }
      checked.push({ sha, tag: release.tag_name, bundles: verifiedCount, binding });
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return { status: findings.length ? "red" : "green", findings, checked };
}

/**
 * The alert verdict (`astra.registry.alert-verdict/1`): the codes, and the
 * allowlisted commits whose canary failed as `hexes`. Nothing a repository
 * wrote reaches it.
 */
export function verdictOf(report, run) {
  const codes = [...new Set(report.findings.map((f) => f.code))].sort();
  const hexes = [...new Set(report.findings.map((f) => f.sha).filter((s) => SHA_RE.test(String(s))))].sort().slice(0, 40);
  const v = { schema: VERDICT_SCHEMA, check: CHECK, status: report.status };
  if (codes.length) v.codes = codes;
  if (hexes.length) v.hexes = hexes;
  if (run) v.run = run;
  return v;
}

// ── the reads (I/O) ─────────────────────────────────────────────────────────

const API = "https://api.github.com";

function apiHeaders() {
  const h = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "astra-registry-bot",
  };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

async function apiGet(url) {
  const res = await fetch(url, { headers: apiHeaders(), signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`GitHub returned HTTP ${res.status} for ${url}`);
  return res.json();
}

/** Every Release of the test repository, newest pages first; the prune job keeps eight per caller. */
export async function listReleases() {
  const out = [];
  for (let page = 1; page <= 5; page++) {
    const batch = await apiGet(`${API}/repos/${CANARY.repo}/releases?per_page=100&page=${page}`);
    if (!Array.isArray(batch)) throw new Error("the releases listing is not an array");
    out.push(...batch);
    if (batch.length < 100) return out;
  }
  throw new Error(`more than 500 Releases in ${CANARY.repo}; the prune job keeps eight per caller`);
}

/** Every `release-canary-*` tag with the COMMIT it names; an annotated tag is dereferenced. */
export async function listTags() {
  const refs = await apiGet(`${API}/repos/${CANARY.repo}/git/matching-refs/tags/release-canary-`);
  if (!Array.isArray(refs)) throw new Error("the tag listing is not an array");
  const out = [];
  for (const r of refs) {
    const name = String(r.ref ?? "").replace(/^refs\/tags\//, "");
    let commit = r.object?.sha ?? null;
    if (r.object?.type === "tag") {
      const t = await apiGet(`${API}/repos/${CANARY.repo}/git/tags/${commit}`);
      commit = t.object?.type === "commit" ? t.object.sha : null;
    } else if (r.object?.type !== "commit") {
      commit = null;
    }
    out.push({ name, commit });
  }
  return out;
}

function output(pairs) {
  const out = process.env.GITHUB_OUTPUT;
  if (!out) return;
  fs.appendFileSync(out, Object.entries(pairs).map(([k, v]) => `${k}=${v}`).join("\n") + "\n");
}

async function main(argv) {
  const arg = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
  if (!argv.includes("--verify")) {
    console.error("usage: tools/release-canary.mjs --verify [--out report.json]");
    return 2;
  }
  const say = (report) => {
    const v = verdictOf(report, null);
    output({ status: report.status, codes: (v.codes ?? []).join(" "), hexes: (v.hexes ?? []).join(" ") });
    const lines = [];
    for (const c of report.checked) lines.push(`checked  ${c.sha}  ${c.tag}  ${c.bundles} bundle(s) verified  binding line: ${c.binding}`);
    for (const f of report.findings) lines.push(`${f.code}  ${f.sha ?? "-"}  ${f.where ?? ""}  ${f.message}`);
    lines.push(`${report.status}  ${report.checked.length} release(s) checked, ${report.findings.length} finding(s)`);
    for (const l of lines) console.log(l);
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\`\`\`\n${lines.join("\n")}\n\`\`\`\n`);
    if (arg("--out")) fs.writeFileSync(arg("--out"), `${JSON.stringify(report, null, 2)}\n`);
    return report.status === "green" ? 0 : 1;
  };

  const trust = loadWorkflowAllowlist({ trustFile: path.join(REPO_ROOT, "registry", "v1", "trust.json") });
  if (!trust.ok) {
    return say({ status: "red", checked: [], findings: [finding(null, trust.code, trust.message)] });
  }
  let releases;
  let tags;
  try {
    [releases, tags] = await Promise.all([listReleases(), listTags()]);
  } catch (e) {
    return say({ status: "red", checked: [], findings: [finding(null, "RELEASE_CANARY_LIST_FAILED", e.message)] });
  }
  const policy = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "policy", "limits.json"), "utf8"));
  const report = await runCanary({
    allowlist: trust.allowlist,
    releases,
    tags,
    now: new Date(),
    deps: {
      download: (url, max) => downloadAsset(url, max),
      maxBytes: policy.max_artifact_bytes,
      tmpDir: process.env.RUNNER_TEMP || os.tmpdir(),
    },
  });
  return say(report);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => {
    console.error(`::error::${String(e?.message ?? e)}`);
    process.exit(2);
  });
}
