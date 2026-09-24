// BOT-88's weekly release canary, the registry's half (registry plan B-T1.6,
// reg.24), against fixtures.
//
//     node --test bot/tests/release-canary.test.mjs
//
// `tools/release-canary.mjs` verifies, once a week, the newest canary Release
// that `mihailinl/astra-registry-canary` built through each commit trust.json
// allowlists. The live answer depends on GitHub, Sigstore and that
// repository's weekly tag, so every assertion here is against a world built
// from committed and measured material and nothing reaches the network:
//
//   * the allowlist is the COMMITTED `registry/v1/trust.json`, verified under
//     the compiled roots exactly as the tool loads it — so the floor below
//     ("one release per allowlisted SHA") counts the real list, and a third
//     SHA added by a ceremony is a third release this suite demands;
//   * `gh attestation verify` is `bot/fixtures/ingest/make.mjs`'s `fakeGh`,
//     the stub the ingest suite drives B-T1.1's reader with, run through the
//     REAL `verifyAttestation` — so the ID-28 rows here are the rows ingest
//     enforces, not a second copy of them;
//   * the tag commit, the canary repository's two ids and the owner file are
//     the values measured on 2026-09-23 off `release-canary-c3f3424-v0.
//     20260923.1` (commit `81d3c57e…`, repository 1383247080, owner
//     193032699), and the binding line is read through the real
//     `readBindingLine` and `parseBindingFile` (B-T2.4) with the two GitHub
//     reads stubbed.
//
// Each test names the mutation of `tools/release-canary.mjs` it was watched
// failing on.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CANARY,
  CODES,
  SIGNER_WORKFLOW,
  STALE_DAYS,
  runCanary,
  selectReleases,
  tagPattern,
  verdictOf,
} from "../../tools/release-canary.mjs";
import { loadWorkflowAllowlist } from "../lib/attestation.mjs";
import { CERTIFICATE_FIELDS } from "../lib/certificate.mjs";
import { CHECKS } from "../lib/alert-checks.mjs";
import { verdictProblems } from "../lib/alert-verdict.mjs";
import { fakeGh } from "../fixtures/ingest/make.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const WORKFLOW = path.join(REPO, ".github", "workflows", "release-canary.yml");

// ── the world ───────────────────────────────────────────────────────────────

const TRUST = loadWorkflowAllowlist({ trustFile: path.join(REPO, "registry", "v1", "trust.json") });
const SHAS = TRUST.ok ? TRUST.allowlist : [];

/** The commit both 2026-09-23 canary tags point at (measured). */
const COMMIT = "81d3c57e6a167f1a756434595b11c6ee72847673";
const VERSION = "0.20260923.1";
const NOW = new Date("2026-09-24T12:17:00Z");
const PUBLISHED = "2026-09-23T10:56:34Z";

/** The owner file at that commit, byte for byte (measured). */
const OWNER_FILE =
  "# Who may submit on this repository's behalf, for astra-registry's owner check.\n" +
  "# BOT-88's canary adds a binding line on its own tag commits only; main carries none.\n" +
  "mihailinl\n" +
  "astra-binding: bot88-canary-grammar-only-never-minted  # BOT-88 canary: grammar only, never minted\n";

const sha7 = (sha) => sha.slice(0, 7);
const tagOf = (sha, version = VERSION) => `release-canary-${sha7(sha)}-v${version}`;
const bundleName = (sha, platform, version = VERSION) => `release-canary-${sha7(sha)}-${version}-${platform}.astraplugin`;
const urlOf = (tag, name) => `https://github.com/${CANARY.repo}/releases/download/${tag}/${name}`;
const bytesOf = (name) => Buffer.from(`the bytes of ${name}\n`);
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function release(sha, { version = VERSION, published = PUBLISHED, draft = false, bundles = ["linux-x64", "windows-x64"] } = {}) {
  const tag = tagOf(sha, version);
  const assets = bundles.map((p) => {
    const name = bundleName(sha, p, version);
    return { name, size: bytesOf(name).length, browser_download_url: urlOf(tag, name) };
  });
  assets.push({ name: "SHA256SUMS.txt", size: 10, browser_download_url: urlOf(tag, "SHA256SUMS.txt") });
  return { tag_name: tag, draft, prerelease: false, published_at: published, assets };
}

/**
 * A healthy week: one release and one tag per allowlisted SHA, every bundle
 * attested by that SHA from the canary repository at `COMMIT`.
 *
 * `cert` overrides fakeGh's options for one SHA's bundles; `owner` replaces
 * the owner file; `drop` removes a SHA's release; `tags` replaces the tags.
 */
function world({ cert = {}, owner = OWNER_FILE, releases = null, tags = null, binding = null } = {}) {
  const rel = releases ?? SHAS.map((s) => release(s));
  const tagList = tags ?? rel.map((r) => ({ name: r.tag_name, commit: COMMIT }));
  const calls = { download: [], gh: [], commit: [], file: [] };
  const table = new Map();
  for (const r of rel) for (const a of r.assets) table.set(a.browser_download_url, bytesOf(a.name));
  const deps = {
    download: async (url) => {
      calls.download.push(url);
      const b = table.get(url);
      if (!b) throw new Error(`HTTP 404 for ${url}`);
      return b;
    },
    ghRunner: async (args) => {
      calls.gh.push(args);
      const file = args[2];
      const name = path.basename(file);
      const sha = SHAS.find((s) => name.startsWith(`release-canary-${sha7(s)}-`)) ?? SHAS[0];
      const tag = rel.find((r) => r.assets.some((a) => a.name === name))?.tag_name ?? null;
      const gh = fakeGh({
        repo: CANARY.repo,
        signerWorkflow: SIGNER_WORKFLOW,
        signerDigest: sha,
        signerUri: `https://github.com/${SIGNER_WORKFLOW}@${sha}`,
        subjectDigest: sha256(fs.readFileSync(file)),
        tag,
        sourceCommit: COMMIT,
        repositoryId: CANARY.repository_id,
        repositoryOwnerId: CANARY.repository_owner_id,
        runId: "35851138643",
        ...(cert[sha] ?? {}),
      });
      return gh(args);
    },
    bindingDeps: binding ?? {
      commitInRepository: async (id, sha) => {
        calls.commit.push([id, sha]);
        return { status: "found", reason: "HTTP 200", sha };
      },
      fileAtCommit: async (id, sha, file) => {
        calls.file.push([id, sha, file]);
        return { status: "found", reason: "HTTP 200", content: owner };
      },
    },
  };
  return { allowlist: SHAS, releases: rel, tags: tagList, now: NOW, deps, calls };
}

const run = async (w) => runCanary(w);
const codesOf = (report) => [...new Set(report.findings.map((f) => f.code))].sort();
const findingsFor = (report, sha) => report.findings.filter((f) => f.sha === sha);

// ── the premise ─────────────────────────────────────────────────────────────

test("the committed trust.json verifies under the compiled roots and allowlists at least two commits", () => {
  // Everything below counts this list. If it stopped verifying, every test
  // would be about an empty allowlist and pass or fail for that reason alone.
  assert.equal(TRUST.ok, true, TRUST.message);
  assert.ok(SHAS.length >= 2, `trust.json allowlists ${SHAS.length}; there were 2 on 2026-09-23`);
  for (const s of SHAS) assert.match(s, /^[0-9a-f]{40}$/);
});

// ── the happy week ──────────────────────────────────────────────────────────

// Watched failing: with `runCanary` returning after `selectReleases` (no
// bundle verified), `verified` is 0 and this is red; with the binding read
// given the tag name instead of `.13`, the `file` call names the wrong ref.
test("a healthy week is green: one release per allowlisted SHA, every bundle verified, the line read at the attested commit", async () => {
  const w = world();
  const report = await run(w);
  assert.deepEqual(report.findings, [], JSON.stringify(report.findings, null, 2));
  assert.equal(report.status, "green");
  // The floor: one checked release per allowlisted SHA, by name.
  assert.deepEqual(report.checked.map((c) => c.sha).sort(), [...SHAS].sort());
  for (const c of report.checked) {
    assert.equal(c.tag, tagOf(c.sha));
    assert.equal(c.bundles, 2, `${c.tag}: both bundles verified`);
    assert.equal(c.binding, "one", `${c.tag}: the owner file's line parsed`);
  }
  // `gh` was asked with the canary repository and the reusable workflow, once
  // per bundle, and never for SHA256SUMS.txt or the .sigstore.jsonl.
  assert.equal(w.calls.gh.length, SHAS.length * 2);
  for (const args of w.calls.gh) {
    assert.equal(args[args.indexOf("--repo") + 1], CANARY.repo);
    assert.equal(args[args.indexOf("--signer-workflow") + 1], SIGNER_WORKFLOW);
    assert.match(path.basename(args[2]), /\.astraplugin$/);
  }
  // ID-22: at the ATTESTED commit (.13), by the certificate's repository id
  // (.15) — never by name, never at a branch.
  assert.ok(w.calls.file.length >= 1);
  for (const [id, sha, file] of w.calls.file) {
    assert.equal(id, CANARY.repository_id);
    assert.equal(sha, COMMIT);
    assert.equal(file, ".well-known/astra-plugin-owner");
  }
});

// ── BOT-88's three fixtures ────────────────────────────────────────────────

// Watched failing: with `runCanary` dropping the error findings
// `verifyAttestation` returns (the `for` over `verified.findings` made to
// push nothing), this is green-by-omission for E_WORKFLOW_NOT_ALLOWED and red.
test("BOT-88: a release whose .10 is not allowlisted fails, E_WORKFLOW_NOT_ALLOWED", async () => {
  const [a] = SHAS;
  const report = await run(world({ cert: { [a]: { signerDigest: "f".repeat(40), signerUri: `https://github.com/${SIGNER_WORKFLOW}@${"f".repeat(40)}` } } }));
  assert.equal(report.status, "red");
  assert.ok(findingsFor(report, a).some((f) => f.code === "E_WORKFLOW_NOT_ALLOWED"), JSON.stringify(report.findings));
  const v = verdictOf(report, null);
  assert.ok(v.hexes.includes(a), "the alarm names the allowlisted commit whose canary failed");
});

// Watched failing: with the `.10 === sha` comparison deleted from
// `verifyBundle`, a release built through ANOTHER allowlisted commit passes as
// this one's, and this is green.
test("BOT-88: a release filed under one SHA but built through another allowlisted SHA fails, RELEASE_CANARY_WRONG_SIGNER", async () => {
  const [a, b] = SHAS;
  const report = await run(world({ cert: { [a]: { signerDigest: b, signerUri: `https://github.com/${SIGNER_WORKFLOW}@${b}` } } }));
  assert.equal(report.status, "red");
  assert.deepEqual(findingsFor(report, a).map((f) => f.code).filter((c) => c === "RELEASE_CANARY_WRONG_SIGNER").length, 2,
    "both bundles of the mis-built release are named");
  assert.ok(!findingsFor(report, a).some((f) => f.code === "E_WORKFLOW_NOT_ALLOWED"),
    "the other commit IS allowlisted: only the canary's own comparison can see this");
});

// Watched failing: the same mutation as the .10 test (verifyAttestation's
// error findings dropped) turns every one of these ten green.
for (const field of CERTIFICATE_FIELDS) {
  test(`BOT-88: a certificate missing ID-28's ${field} fails, E_ATTESTATION_INVALID`, async () => {
    const [a] = SHAS;
    const report = await run(world({ cert: { [a]: { omitFields: [field] } } }));
    assert.equal(report.status, "red", `${field} missing and the canary is green`);
    assert.ok(findingsFor(report, a).some((f) => f.code === "E_ATTESTATION_INVALID"), JSON.stringify(findingsFor(report, a)));
  });
}

// Watched failing: with `bindingFinding` treating `malformed` as a line
// (`outcome !== "none"` for `outcome === "one"`), both of these are green.
test("BOT-88: a malformed binding line fails, B_BINDING_MALFORMED (ID-23, ID-24)", async () => {
  const near = OWNER_FILE.replace("bot88-canary-grammar-only-never-minted", "too-short");
  const two = `${OWNER_FILE}astra-binding: a-second-line-of-valid-grammar\n`;
  for (const owner of [near, two]) {
    const report = await run(world({ owner }));
    assert.equal(report.status, "red");
    for (const s of SHAS) {
      assert.ok(findingsFor(report, s).some((f) => f.code === "B_BINDING_MALFORMED"), JSON.stringify(report.findings));
    }
  }
});

// Watched failing: with the `none` branch of `bindingFinding` deleted, a tag
// commit that lost its line is green, and the canary no longer exercises the
// parser at all.
test("a canary commit with no binding line fails, RELEASE_CANARY_BINDING_ABSENT", async () => {
  const report = await run(world({ owner: OWNER_FILE.split("\n").filter((l) => !l.startsWith("astra-binding")).join("\n") }));
  assert.equal(report.status, "red");
  assert.deepEqual(codesOf(report), ["RELEASE_CANARY_BINDING_ABSENT"]);
});

test("a binding read that did not happen is red and says so, never green and never `none`", async () => {
  // Watched failing: with `wait` mapped to no finding, this is green.
  const report = await run(world({
    binding: {
      commitInRepository: async () => ({ status: "transient", reason: "HTTP 503" }),
      fileAtCommit: async () => { throw new Error("must not be reached"); },
    },
  }));
  assert.equal(report.status, "red");
  assert.deepEqual(codesOf(report), ["W_GITHUB_RATE_LIMITED"]);
});

// ── the floor, and the week the release did not happen ─────────────────────

// Watched failing: with `selectReleases` skipping a SHA that has no release
// (`continue` without a finding), this is green — the plan's own watch,
// "pointing one SHA at a missing release".
test("the floor: an allowlisted SHA with no release fails by name, RELEASE_CANARY_NO_RELEASE", async () => {
  const [a] = SHAS;
  const releases = SHAS.filter((s) => s !== a).map((s) => release(s));
  const report = await run(world({ releases }));
  assert.equal(report.status, "red");
  assert.deepEqual(findingsFor(report, a).map((f) => f.code), ["RELEASE_CANARY_NO_RELEASE"]);
  assert.ok(verdictOf(report, null).hexes.includes(a));
  assert.equal(report.checked.length, SHAS.length - 1, "the other SHA is still verified");
});

test("an empty allowlist is red, never a green run that checked nothing", async () => {
  // Watched failing: with the empty-allowlist refusal removed, zero SHAs give
  // zero findings and a green verdict.
  const report = await run({ ...world(), allowlist: [] });
  assert.equal(report.status, "red");
  assert.deepEqual(codesOf(report), ["RELEASE_CANARY_EMPTY_ALLOWLIST"]);
});

// Watched failing: with the newest-tag comparison deleted from
// `selectReleases`, last week's release is verified green while this week's
// tag started a release that never finished — the GitHub-side break BOT-88 is
// for (OPEN-OPS-17's emergency ceremony).
test("this week's tag with no Release fails, RELEASE_CANARY_TAG_UNRELEASED", async () => {
  const [a] = SHAS;
  const releases = SHAS.map((s) => release(s));
  const tags = [
    ...releases.map((r) => ({ name: r.tag_name, commit: COMMIT })),
    { name: tagOf(a, "0.20260924.1"), commit: "9".repeat(40) },
  ];
  const report = await run(world({ releases, tags }));
  assert.equal(report.status, "red");
  assert.deepEqual(findingsFor(report, a).map((f) => f.code), ["RELEASE_CANARY_TAG_UNRELEASED"]);
});

// Watched failing: with `STALE_DAYS` compared as `> Infinity`, a canary that
// stopped tagging months ago keeps verifying its last release green.
test(`a newest release older than ${STALE_DAYS} days fails, RELEASE_CANARY_STALE`, async () => {
  const old = new Date(NOW.getTime() - (STALE_DAYS * 24 + 1) * 3600e3).toISOString().replace(/\.\d{3}Z$/, "Z");
  const fresh = new Date(NOW.getTime() - (STALE_DAYS * 24 - 1) * 3600e3).toISOString().replace(/\.\d{3}Z$/, "Z");
  const [a] = SHAS;
  const stale = await run(world({ releases: SHAS.map((s) => release(s, { published: s === a ? old : PUBLISHED })) }));
  assert.deepEqual(findingsFor(stale, a).map((f) => f.code), ["RELEASE_CANARY_STALE"]);
  const ok = await run(world({ releases: SHAS.map((s) => release(s, { published: s === a ? fresh : PUBLISHED })) }));
  assert.equal(ok.status, "green", JSON.stringify(ok.findings));
});

test("the newest canary release per SHA is chosen by date and counter; drafts and other prefixes are not candidates", () => {
  // Watched failing: with the sort comparing tag names as strings,
  // `0.20260923.10` sorts before `0.20260923.9` and the older one is picked.
  const [a, b] = SHAS;
  const releases = [
    release(a, { version: "0.20260916.1" }),
    release(a, { version: "0.20260923.9" }),
    release(a, { version: "0.20260923.10" }),
    release(a, { version: "0.20260930.1", draft: true }),
    release(b),
    { ...release(b), tag_name: `release-canary-${sha7(b)}-v1.0.0` },
  ];
  const { selected, findings } = selectReleases({
    allowlist: SHAS,
    releases,
    // A draft is a Release GitHub has not published, and its tag is not
    // pushed until it is; the listing here has the published ones' tags.
    tags: releases.filter((r) => !r.draft).map((r) => ({ name: r.tag_name, commit: COMMIT })),
    now: NOW,
  });
  assert.deepEqual(findings, []);
  assert.equal(selected.find((s) => s.sha === a).release.tag_name, tagOf(a, "0.20260923.10"));
  assert.equal(selected.find((s) => s.sha === b).release.tag_name, tagOf(b));
  assert.ok(tagPattern(a).test(tagOf(a)));
  assert.ok(!tagPattern(a).test(tagOf(b)), "one SHA's pattern never matches another's tag");
  assert.ok(!tagPattern(a).test(`${tagOf(a)}-rc`), "anchored at both ends");
});

// ── the certificate against the canary's own facts ──────────────────────────

// Watched failing: with the `.13 === tag commit` comparison deleted, a
// release whose attestation names another commit than its tag is green.
test("a certificate naming another commit than the tag's fails, E_RELEASE_COMMIT_MISMATCH", async () => {
  const [a] = SHAS;
  const report = await run(world({ cert: { [a]: { sourceCommit: "e".repeat(40) } } }));
  assert.equal(report.status, "red");
  assert.ok(findingsFor(report, a).some((f) => f.code === "E_RELEASE_COMMIT_MISMATCH"), JSON.stringify(report.findings));
});

// Watched failing: with the ids comparison deleted, a canary released from a
// re-created repository of the same name (a different .15) is green.
test("a certificate naming other repository ids than the canary's fails, RELEASE_CANARY_IDS", async () => {
  const [a] = SHAS;
  for (const over of [{ repositoryId: "1383247081" }, { repositoryOwnerId: "1" }]) {
    const report = await run(world({ cert: { [a]: over } }));
    assert.equal(report.status, "red", JSON.stringify(over));
    assert.ok(findingsFor(report, a).some((f) => f.code === "RELEASE_CANARY_IDS"), JSON.stringify(report.findings));
  }
});

test("a verifier that could not run is red, E_ATTESTATION_UNCHECKED, and not an unattested release", async () => {
  // Watched failing: with `verifyBundle` returning no finding when `facts` is
  // null, a Sigstore outage is a green week.
  const [a] = SHAS;
  const report = await run(world({ cert: { [a]: { fail: "public good verifier is not available (initialization failed)" } } }));
  assert.equal(report.status, "red");
  assert.ok(findingsFor(report, a).every((f) => f.code === "E_ATTESTATION_UNCHECKED"), JSON.stringify(report.findings));
});

test("an asset URL outside the canary's own release is refused before it is downloaded, E_ASSET_URL_FOREIGN", async () => {
  // Watched failing: with the prefix check removed, the foreign URL is
  // downloaded (the stub's call list names it).
  const [a] = SHAS;
  const releases = SHAS.map((s) => release(s));
  const r = releases.find((x) => x.tag_name === tagOf(a));
  r.assets[0] = { ...r.assets[0], browser_download_url: `https://example.com/${r.assets[0].name}` };
  const w = world({ releases });
  const report = await run(w);
  assert.ok(findingsFor(report, a).some((f) => f.code === "E_ASSET_URL_FOREIGN"));
  assert.ok(!w.calls.download.some((u) => u.startsWith("https://example.com/")), "the foreign URL was fetched");
});

// ── what reaches the alarm ──────────────────────────────────────────────────

test("every code the tool can emit is a fixed code, and a red verdict is one the channel will carry", async () => {
  for (const c of CODES) assert.match(c, /^[A-Z][A-Z0-9_]{0,47}$/, c);
  const [a] = SHAS;
  const report = await run(world({ cert: { [a]: { omitFields: ["run"] } } }));
  for (const f of report.findings) assert.ok(CODES.includes(f.code), `${f.code} is emitted and not in CODES`);
  const v = verdictOf(report, "https://github.com/mihailinl/astra-registry/actions/runs/1");
  assert.deepEqual(verdictProblems(v), []);
  assert.equal(v.check, "release-canary");
  assert.equal(v.status, "red");
  const green = verdictOf(await run(world()), null);
  assert.deepEqual(verdictProblems(green), []);
  assert.equal(green.status, "green");
  assert.equal(green.codes, undefined, "a green verdict carries no empty codes list");
});

test("the receiver check this posts to is `release-canary`, a registry check with a weekly interval", () => {
  const row = CHECKS.find((c) => c.name === "release-canary");
  assert.ok(row, "bot/lib/alert-checks.mjs has no release-canary row");
  assert.equal(row.party, "registry");
  assert.equal(row.interval_seconds, 7 * 24 * 3600);
});

// ── the workflow ────────────────────────────────────────────────────────────

const uncommented = (text) => text.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
function job(text, name) {
  const at = text.indexOf(`\n  ${name}:\n`);
  assert.ok(at >= 0, `release-canary.yml has no job \`${name}\``);
  return text.slice(at + 1).split(/\n  [A-Za-z0-9_-]+:\s*\n/)[0];
}

test("release-canary.yml: the verify job reads, holds no secret and no write, and runs only after the suite", () => {
  const text = uncommented(fs.readFileSync(WORKFLOW, "utf8"));
  assert.match(text, /^permissions: \{\}$/m, "workflow-level permissions are empty");
  const verify = job(text, "verify");
  assert.match(verify, /needs: suite/);
  assert.match(verify, /permissions:\n\s+contents: read\n/);
  assert.doesNotMatch(verify, /secrets\./, "the verify job reads a secret");
  assert.doesNotMatch(verify, /: write/, "the verify job holds a write permission");
  assert.doesNotMatch(verify, /environment:/, "the verify job runs in an environment");
  assert.match(verify, /node tools\/release-canary\.mjs --verify/);
  const suite = job(text, "suite");
  assert.match(suite, /node --test bot\/tests\/release-canary\.test\.mjs/);
  const alert = job(text, "alert");
  assert.match(alert, /environment: alerts/);
  assert.match(alert, /check: release-canary/);
  assert.match(alert, /ASTRA_DEADMAN_URL_RELEASE_CANARY: \$\{\{ secrets\.ASTRA_DEADMAN_URL_RELEASE_CANARY \}\}/);
});

test("release-canary.yml: its weekly schedule runs hours after the canary's Monday 06:17 tag", () => {
  // The schedule may be commented out (until the receiver check's first
  // heartbeat arms it, bot/lib/alert-checks.mjs); the expression is held
  // either way, so un-commenting it cannot un-comment a wrong one.
  const text = fs.readFileSync(WORKFLOW, "utf8");
  const crons = [...text.matchAll(/^\s*#?\s*-\s*cron:\s*'([^']+)'/gm)].map((m) => m[1]);
  assert.equal(crons.length, 1, `one schedule line, found ${JSON.stringify(crons)}`);
  const [min, hour, dom, mon, dow] = crons[0].split(/\s+/);
  assert.equal(dow, "1", "Mondays, the canary's day");
  assert.equal(dom, "*");
  assert.equal(mon, "*");
  assert.ok(Number(hour) * 60 + Number(min) >= 6 * 60 + 17 + 4 * 60,
    `${crons[0]} is less than four hours after the tag push at 06:17; a release takes about half an hour and GitHub delays schedules by hours`);
});
