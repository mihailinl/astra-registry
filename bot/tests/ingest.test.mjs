#!/usr/bin/env node
// The registry bot's own suite.  `node bot/tests/ingest.test.mjs`
//
// Three things are being asserted, and they are not the same thing:
//
//   1. **The shared corpus.** Every one of the golden bundles vendored from
//      AstraPlugins/testdata/bundles is fed through the WHOLE ingest pipeline —
//      release, attestation, archive, manifest probe, names, derivation — and
//      has to produce the verdict recorded in `vectors.json`'s `expect.registry`
//      column. tools/selftest.mjs already checks the structural half against the
//      same file; this checks the program a submission actually meets.
//
//   2. **One test per failure class**, each asserting the FIXED CODE. The
//      acceptance criterion for task 3.3 is that every failure class produces a
//      fixed code and an actionable comment, and a code nobody asserts is a code
//      that quietly becomes E_MANIFEST_INVALID.
//
//   3. **The conforming case ingests with zero human action.** That is the
//      whole point of the task, and it is the one test that would fail silently
//      if the bot became too strict — a bot that rejects everything passes every
//      negative test in this file.
//
// Nothing here touches the network. `bot/fixtures/ingest/make.mjs` builds the
// bundles and a GitHub that answers from a table, which is also why the tests
// can assert things a live GitHub would never let them arrange — an asset URL
// pointing at another repository, an attestation for the wrong bytes.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ingest, renderComment, GITHUB_COMMENT_MAX, DEFAULT_SIGNER_WORKFLOW } from "../ingest.mjs";
import { CODES, codeDef } from "../lib/codes.mjs";
import { LOCALE_CODES, deriveLocaleText, localeSignature, readLocales } from "../lib/locales.mjs";
import { summarise } from "../lib/derive.mjs";
import { loadPolicy } from "../../tools/lib/sources.mjs";
import { stagingListingId } from "../../tools/lib/reserved.mjs";
import { classifyFile, scanHostRpcs } from "../lib/rpcscan.mjs";
import { checkDisplayName, checkNames, foldDisplayName, loadTrademarks } from "../lib/names.mjs";
import { scriptsUsed } from "../../tools/lib/ids.mjs";
import { extractSignerFacts, loadRootKeys, loadWorkflowAllowlist } from "../lib/attestation.mjs";
import * as gh from "../lib/github.mjs";
import { certificateIds } from "../lib/certificate.mjs";
import { applyIdentity } from "../lib/identity.mjs";
import { proveOwnership } from "../lib/ownership.mjs";
import { isRecheckCommand, parseIssueForm } from "../lib/issue.mjs";
import { findProbe, runProbe } from "../lib/probe.mjs";
import { makeBundle, fakeGitHub, fakeGh, fakeOwnership, FIXTURE_SIGNER_WORKFLOW, FIXTURE_REPOSITORY_ID, FIXTURE_OWNER_ID } from "../fixtures/ingest/make.mjs";

const REPO_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const VECTOR_DIR = path.join(REPO_ROOT, "tests", "vectors");

// ── a test harness, in twenty lines ─────────────────────────────────────────

let passed = 0;
const failures = [];
let group = "";
/** Every code any test saw the bot emit, for the canary at the end. */
const emitted = new Set();

function section(name) { group = name; console.log(`\n${name}`); }
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures.push({ group, name, error: e });
    console.log(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
  }
}
function assert(cond, message) { if (!cond) throw new Error(message); }
function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}\n  expected: ${expected}\n  actual:   ${actual}`);
}

// ── the world every test starts from ────────────────────────────────────────

const REPO = "a-stranger/dice-roller";
const TAG = "v0.2.0";
const SUBMITTER = "a-stranger";
/** The one commit `tools/testkeys/fixtures/trust-active-signed.json` allows. */
const ALLOWED_WORKFLOW_SHA = "0".repeat(40);

/**
 * Every scratch tree these tests made, removed when the run ends.
 *
 * Declared here, above the first directory this file makes, and not beside
 * `registryWith` where it used to be: the roots file below is written at import
 * time, before a declaration further down exists, so it could not be listed
 * here and was left in `/tmp` on every run, as was the probe test's empty
 * directory.
 */
const scratch = [];
process.on("exit", () => {
  for (const d of scratch) fs.rmSync(d, { recursive: true, force: true });
});

/**
 * A root.json carrying the TEST roots, written to a temp file.
 *
 * Built from `tools/testkeys/*.pub.json` rather than committed, so it cannot
 * drift from the keys that signed the trust fixture, and so no file in this
 * repository ever looks like a provisioned production root.
 *
 * It reaches the bot through `deps.rootKeys` and not through an argument
 * (B-T1.5): the production roots are compiled into `bot/lib/roots.mjs`, and a
 * roots file that a caller could name would be the anchor as a parameter. The
 * comment here used to say "the real `registry/v1/root.json` stays empty" —
 * it has not been empty since `b13759a` published the two roots on
 * 2026-08-11, and one of the tests below now asserts that a trust.json signed
 * by THESE keys is refused against the compiled set no matter what that file
 * says.
 */
function testRootsFile() {
  const keys = ["root-a", "root-b"].map((n) =>
    JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "tools", "testkeys", `TEST-ONLY-DO-NOT-TRUST-${n}.pub.json`), "utf8")));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-testroots-"));
  scratch.push(dir);
  const file = path.join(dir, "root.json");
  fs.writeFileSync(file, JSON.stringify({
    $banner: "TEST ROOTS — generated by bot/tests/ingest.test.mjs, never committed, never trusted by a daemon.",
    schema: "astra.registry.root/1",
    status: "provisioned",
    roots: keys.map((k) => ({ key_id: k.key_id, public_key: k.public_key, role: k.role })),
  }, null, 2));
  return file;
}

const ROOTS_FILE = testRootsFile();
/** The TEST roots as a verifier wants them, for `deps.rootKeys`. */
const TEST_ROOT_KEYS = loadRootKeys(ROOTS_FILE);
const TRUST_FILE = path.join(REPO_ROOT, "tools", "testkeys", "fixtures", "trust-active-signed.json");

/**
 * Run one ingest against a world assembled from the arguments.
 *
 * Every dependency is injected. Production passes none of them, so this is a
 * seam and not a mode: there is no flag on `bot/ingest.mjs` that turns the
 * attestation check off, which there would have to be if the tests needed one.
 */
async function run({
  assets, repo = REPO, tag = TAG, submitter = SUBMITTER, root = REPO_ROOT,
  signerDigest = ALLOWED_WORKFLOW_SHA, attestRepo = repo, ghFail = null,
  ownershipOk = true, signerUri = undefined, subjectOverride = null, certRepo = null,
  rootKeys = TEST_ROOT_KEYS, trustFile = TRUST_FILE,
  signerWorkflow = DEFAULT_SIGNER_WORKFLOW,
  // ID-28's other rows, so a test can move one field of the certificate and
  // leave the rest of a healthy release alone (registry plan B-T1.1).
  cert = {},
  /** Per-bundle certificates, by asset name: the cross-bundle canary. */
  certByAsset = null,
} = {}) {
  const github = fakeGitHub({ repo, tag, assets });
  const result = await ingest(
    { repo, tag, submitter, root, trustFile, signerWorkflow },
    {
      rootKeys,
      fetchRelease: github.fetchRelease.bind(github),
      headAsset: github.headAsset.bind(github),
      downloadAsset: github.downloadAsset.bind(github),
      proveOwnership: fakeOwnership(ownershipOk),
      ghRunner: (args) => {
        // The digest `gh` is asked about is the digest of the file on disk, so
        // the fake computes it the same way the real one would: from the bytes
        // it was handed.
        const file = args[2];
        const bytes = fs.readFileSync(file);
        const digest = subjectOverride ?? crypto.createHash("sha256").update(bytes).digest("hex");
        const perAsset = certByAsset?.[path.basename(file)] ?? {};
        return fakeGh({
          repo: attestRepo, signerDigest, subjectDigest: digest, signerUri, certRepo, fail: ghFail,
          // The tag is handed to the stub because `.14` is `refs/tags/<tag>`
          // and a fixture whose certificate says otherwise is a fixture of a
          // release built from another ref.
          tag,
          ...cert,
          ...perAsset,
        })(args);
      },
    },
  );
  for (const i of result.findings) emitted.add(i.code);
  return result;
}

const codes = (r) => r.findings.map((i) => i.code);
const errorCodes = (r) => r.findings.filter((i) => i.level === "error").map((i) => i.code);
function assertBlockedWith(r, code) {
  assert(r.blocked, `expected a block; got ${JSON.stringify(r.findings.map((i) => `${i.level}:${i.code}`))}`);
  assert(errorCodes(r).includes(code),
    `expected ${code}; the blocking codes were ${JSON.stringify(errorCodes(r))}`);
}

/** A registry tree holding one already-listed plugin, so updates can be tested. */
function registryWith({ id = "dice-roller", version = "0.1.0", repo = REPO, name = "Dice Roller", i18n } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-reg-"));
  scratch.push(dir);
  const pdir = path.join(dir, "plugins", id, "versions");
  fs.mkdirSync(pdir, { recursive: true });
  fs.writeFileSync(path.join(dir, "plugins", id, "plugin.json"), JSON.stringify({
    schema: "astra.registry.plugin/1",
    id, name,
    summary: "Rolls dice when you ask it to.",
    license: "MIT",
    source: { kind: "github", repo },
    added_at: "2026-01-01",
    // A listing that already carries localized card names, so a submission can
    // be compared against the names a Russian user actually reads rather than
    // only against the English ones a reviewer does.
    ...(i18n ? { i18n } : {}),
  }, null, 2));
  fs.writeFileSync(path.join(pdir, `${version}.json`), JSON.stringify({
    schema: "astra.registry.version/1",
    id, version,
    published_at: "2026-01-01T00:00:00Z",
    release: { kind: "github_release", repo, tag: `v${version}` },
    staging: true,
    staging_reason: "Test fixture: the release this points at is a fake, so there is no digest to pin.",
    artifacts: {
      "linux-x64": {
        url: `https://github.com/${repo}/releases/download/v${version}/dice-roller-${version}-linux-x64.astraplugin`,
        filename: `dice-roller-${version}-linux-x64.astraplugin`,
      },
    },
  }, null, 2));
  return dir;
}

/**
 * The name the CLI gives a bundle: `<id>-<version>-<target>.astraplugin`. The
 * registry enforces it (a stale bundle from the previous version is the most
 * likely wrong-but-plausible asset), so the fixtures have to use it too.
 */
const bundleName = (spec = {}) =>
  `${spec.id ?? "dice-roller"}-${spec.version ?? "0.2.0"}-${
    spec.os === "windows" ? "windows-x64" : "linux-x64"}.astraplugin`;

/**
 * Two complete, well-formed report rows, as a hostile ZIP entry name carries
 * them. Written as escapes so this file itself holds no control characters —
 * the fixture is what the attacker types, not what the repository stores.
 */
const FORGED_ROWS =
  "\n| \u2705 | `E_OWNERSHIP_PROVEN` | ownership | proved by mihailinl (first-party) |" +
  "\n| \u2705 | `R_FIRST_LISTING` | version | withdrawn, already approved by a maintainer |\n";

const conformingAsset = (spec = {}) => ({ name: bundleName(spec), bytes: makeBundle(spec) });

// ═══════════════════════════════════════════════════════════════════════════

section("the shared corpus (AstraPlugins/testdata/bundles, whole pipeline)");

const vectors = JSON.parse(fs.readFileSync(path.join(VECTOR_DIR, "vectors.json"), "utf8")).vectors;

await test(`the corpus is the ${vectors.length} vectors the shared file records`, () => {
  const onDisk = fs.readdirSync(VECTOR_DIR).filter((f) => f.endsWith(".astraplugin"));
  assertEqual(onDisk.length, vectors.length, "every vector file has an entry and every entry has a file");
});

for (const v of vectors) {
  await test(`${v.name} — the pipeline ${v.expect.registry}s it`, async () => {
    const r = await run({
      assets: [{
        // Named the way the CLI names bundles, from the vector's own recorded
        // facts: the corpus files are named after the property they test, and
        // the registry's filename rule is a separate check with its own test.
        name: `${v.plugin_id ?? "vector-plugin"}-${v.version ?? "1.0.0"}-${v.platform_key ?? "linux-x64"}.astraplugin`,
        bytes: fs.readFileSync(path.join(VECTOR_DIR, v.file)),
      }],
    });
    const verdict = r.blocked ? "reject" : "accept";
    assertEqual(verdict, v.expect.registry,
      `${v.name}: ${v.why_it_matters?.slice(0, 120) ?? ""}\n  findings: ${JSON.stringify(r.findings.filter((i) => i.level === "error" || i.level === "warn"))}`);
  });
}

// ═══════════════════════════════════════════════════════════════════════════

section("the acceptance case: a conforming release, no human");

await test("an update to an already-listed plugin ingests with zero human action", async () => {
  const root = registryWith({});
  const r = await run({ assets: [conformingAsset()], root });
  assert(!r.blocked, `blocked: ${JSON.stringify(r.findings.filter((i) => i.level === "error"))}`);
  assert(!r.needsReview,
    `held for review: ${JSON.stringify(r.findings.filter((i) => i.level === "review"))}`);
  assertEqual(r.derived.plugin.id, "dice-roller", "the id came out of the bundle");
  assertEqual(r.derived.version.version, "0.2.0", "so did the version");
  assertEqual(r.derived.plugin.license, "MIT", "and the licence");
  assertEqual(r.derived.version.artifacts["linux-x64"].size, conformingAsset().bytes.length, "and the size");
  assert(codes(r).includes("E_DERIVED_LISTING_INVALID"),
    "the derived listing is run past tools/validate.mjs and the row is recorded either way");
  assert(r.findings.some((i) => i.code === "E_DERIVED_LISTING_INVALID" && i.level === "pass"),
    "…and it passed");
});

// ── the permission declaration survives derivation ──────────────────────────
//
// `permissions` on a derived record has THREE states and the daemon reads all
// three. `{…}` is "asks for these", `{}` is "asks for nothing", and the key
// being ABSENT is "this record cannot answer" — which
// `RegistryRelease::declared_permissions()` turns into `known: false`,
// `permissions_absence()` reports as `no_declaration`, and the consent sheet
// turns into a disabled Install button. Only the third is a refusal.
//
// `derive.mjs` tested `Object.keys(...).length`, so the second state collapsed
// into the third: a plugin that asked for nothing derived a record with no key
// and nobody could install it. `sub-models-for-astra 0.14.0` sat in the
// catalogue in exactly that state — one release, author's own plugin.toml
// comment reading "this plugin asks for nothing at all" — and `web-stt 0.4.0`
// did for the 20 h it was the listed version.
//
// The trap these close is worth naming, because it is why the suite agreed
// with the bug for a month: `makeBundle`'s DEFAULT is `permissions = {}`, so
// every acceptance run above has been exercising the broken case since the day
// it was written, and not one of them asked what came out the other end.
// A fixture whose default is the failing input is not coverage.

await test("a plugin that asks for nothing derives `permissions: {}`, not a missing key", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({}) });
  assert(!r.blocked, `blocked: ${JSON.stringify(r.findings.filter((i) => i.level === "error"))}`);
  assert("permissions" in r.derived.version,
    "the key is missing, which Astra reads as `no_declaration` and refuses to install");
  assertEqual(JSON.stringify(r.derived.version.permissions), "{}",
    "and what it carries is the empty set, not something falsy");
});

await test("a plugin that asks for something carries exactly what the bundle declared", async () => {
  const declared = { fire_trigger: { reason: "Fires on_roll_value so your commands can react." } };
  const r = await run({
    assets: [conformingAsset({ permissions: declared })],
    root: registryWith({}),
  });
  assert("permissions" in r.derived.version, "the key is present");
  assertEqual(JSON.stringify(r.derived.version.permissions), JSON.stringify(declared),
    "copied through unchanged, which is what schema/version-v1.json promises a reader");
});

await test("a bundle with no permissions member at all still derives `{}`", async () => {
  // The manifest layer does not distinguish absent from empty — AstraPlugins
  // `docs/en/spec/permissions.md` §2 ("a missing section is not 'unspecified';
  // it is a complete answer, and the answer is no") and §7 ("`null` and `{}`
  // are the same value and hash the same"). `bot/lib/bundle.mjs` already reads
  // it that way when it hashes, so deriving normalises rather than passing the
  // absence through. That leaves absence in an INDEX record with exactly one
  // meaning — the record predates this rule — which is the only meaning the
  // daemon's fail-closed branch needs it to have.
  const r = await run({
    assets: [conformingAsset({ omitPermissionsMember: true })],
    root: registryWith({}),
  });
  assert(!r.blocked, `blocked: ${JSON.stringify(r.findings.filter((i) => i.level === "error"))}`);
  assert("permissions" in r.derived.version,
    "an old bundle must not derive a record Astra classifies as unreadable");
  assertEqual(JSON.stringify(r.derived.version.permissions), "{}", "normalised to the empty set");
});

await test("a first listing is held for a human, and nothing else is wrong with it", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({ id: "something-else" }) });
  assert(!r.blocked, `nothing should block: ${JSON.stringify(errorCodes(r))}`);
  assert(r.needsReview, "a first listing is one of the three events a human owns");
  assert(codes(r).includes("R_FIRST_LISTING"), JSON.stringify(codes(r)));
});

// ── MOD-16's staging listing, born unlisted (M-T2.1) ────────────────────────
//
// The FIRST derivation is the whole of the test. Every other path to `unlisted`
// in `bot/lib/derive.mjs` carries the flag forward off an existing
// `plugin.json`, and on a first listing there is no existing document to carry
// anything from — which is exactly the moment the path-test listing would
// otherwise be born LISTED and sit in the catalogue until a second commit took
// it out. A signer run in that window signs it (TRUST-26: never a listed id).
//
// The repository matters as much as the id and is asserted by being used: the
// bundle is published from `mihailinl/AstraPlugins`, and the listing has to
// pass two independent first-party gates on the way — `policy/reserved-ids
// .json`'s `astra-` prefix, whose exception is `first_party_repos`, and
// `bot/policy/trademarks.json`'s `astra` mark, whose exception is
// `allow_repo_owners`. Both are matched against the repository the ownership
// check proved, never against a claim, and a display name whose first word is
// the mark is the other half of the second one.

await test("MOD-16 — a first listing under the staging id derives `unlisted: true`", async () => {
  const id = stagingListingId(loadPolicy(REPO_ROOT).reserved);
  assert(id !== null,
    "policy/reserved-ids.json reserves no staging_listing_id, so the derive rule in bot/lib/derive.mjs reads a " +
    "member nothing sets and the path-test listing would be published listed");

  const r = await run({
    repo: "mihailinl/AstraPlugins",
    assets: [conformingAsset({ id, name: "Astra Withdrawal Canary" })],
    // No existing listing under the staging id: this is its first appearance.
    root: registryWith({ id: "something-else" }),
  });
  assert(!r.blocked, `nothing should block: ${JSON.stringify(r.findings.filter((i) => i.level === "error"))}`);
  assertEqual(r.derived.plugin.unlisted, true,
    `${id} derived a LISTED document on its first release. tools/validate.mjs refuses that on the tree, so the ` +
    "publish commit cannot be made at all — but the failure to read is the other one: the id the estate " +
    "publishes in order to withdraw it would have been offered to users first");
  assert(r.findings.some((i) => i.code === "E_DERIVED_LISTING_INVALID" && i.level === "pass"),
    "the derived listing did not pass tools/validate.mjs, so the two halves of the rule disagree: " +
    `${JSON.stringify(r.findings.filter((i) => i.code === "E_DERIVED_LISTING_INVALID"))}`);
  assert(codes(r).includes("R_FIRST_LISTING"),
    "a first listing is still a human's to approve; being born unlisted does not publish it unattended");
});

// M-T2.2 publishes the staging listing from BOT-88's test repository,
// `mihailinl/astra-registry-canary`, and not from AstraPlugins (registry plan
// §1.2: the staging repository is the test repository under mihailinl). The
// test above proves the derive rule from AstraPlugins, which was first-party
// already; this one proves the repository the listing will actually come
// from gets past both first-party gates. Before M-T2.1's widening of
// `first_party_repos` it did not: the owner's own `/approve` would have been
// answered `E_ID_RESERVED_PREFIX`, and the release would have had to be cut
// again from somewhere else. The widening is ONE repository, not the owner —
// `first_party_owners` is the wider knob and `mihailinl` is deliberately not
// in it — so another repository under the same login is still refused.
await test("MOD-16 — the staging id released from the test repository passes both first-party gates, and nothing wider does", async () => {
  const id = stagingListingId(loadPolicy(REPO_ROOT).reserved);
  assert(id !== null, "policy/reserved-ids.json reserves no staging_listing_id");

  const canary = await run({
    repo: "mihailinl/astra-registry-canary",
    assets: [conformingAsset({ id, name: "Astra Withdrawal Canary" })],
    root: registryWith({ id: "something-else" }),
  });
  assert(!canary.blocked,
    `the staging listing's first release from mihailinl/astra-registry-canary is blocked: ` +
    `${JSON.stringify(canary.findings.filter((i) => i.level === "error"))}. M-T2.2's publish commit cannot be made ` +
    "from the repository the plan names, and the owner's /approve would be answered with a refusal");
  assertEqual(canary.derived.plugin.unlisted, true, `${id} from the test repository derived a listed document`);
  assert(codes(canary).includes("R_FIRST_LISTING"),
    "a first listing from the test repository is still a human's to approve");

  const sibling = await run({
    repo: "mihailinl/some-other-repository",
    assets: [conformingAsset({ id, name: "Astra Withdrawal Canary" })],
    root: registryWith({ id: "something-else" }),
  });
  assertBlockedWith(sibling, "E_ID_RESERVED_PREFIX");
});

await test("MOD-16 — no `facts.*` can lift the staging listing back into the catalogue", async () => {
  // The bundle is written by whoever publishes the canary, and the canary is
  // published from a repository the estate controls — which is a statement
  // about people. This is the statement about the code: the only thing read
  // out of the bundle here is the id, and the value written is a constant.
  const id = stagingListingId(loadPolicy(REPO_ROOT).reserved);
  const r = await run({
    repo: "mihailinl/AstraPlugins",
    assets: [conformingAsset({ id, name: "Astra Withdrawal Canary", extraFiles: [
      { name: "unlisted", data: "false" },
    ] })],
    root: registryWith({ id: "something-else" }),
  });
  assertEqual(r.derived.plugin.unlisted, true, "a file in the bundle changed what the derivation decided");
});

await test("two platforms in one release become two artifact keys", async () => {
  const root = registryWith({});
  const r = await run({
    assets: [
      { name: "dice-roller-0.2.0-linux-x64.astraplugin", bytes: makeBundle({ os: "linux" }) },
      { name: "dice-roller-0.2.0-windows-x64.astraplugin", bytes: makeBundle({ os: "windows" }) },
    ],
    root,
  });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assertEqual(Object.keys(r.derived.version.artifacts).sort().join(","), "linux-x64,windows-x64", "both hosts listed");
});

await test("everything except the repository and the tag comes out of the bundle", async () => {
  const root = registryWith({});
  const r = await run({
    assets: [conformingAsset({
      name: "Dice Roller Deluxe",
      description: "Rolls polyhedral dice and reads the result aloud.",
      author: "Someone Else Entirely",
      license: "Apache-2.0",
      capabilities: ["tools", "tts"],
    })],
    root,
  });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assertEqual(r.derived.plugin.name, "Dice Roller Deluxe", "the display name is the manifest's");
  assertEqual(r.derived.plugin.author.name, "Someone Else Entirely", "so is the author");
  assertEqual(r.derived.plugin.license, "Apache-2.0", "so is the licence");
  assertEqual(r.derived.version.capabilities.join(","), "tools,tts", "so are the capabilities");
  assertEqual(r.derived.plugin.source.repo, REPO, "and the repository is the one fact that was typed");
});

// ═══════════════════════════════════════════════════════════════════════════

section("failing closed");

await test("with no signed trust.json, nothing is listed and the reason says so", async () => {
  // The absent file is named deliberately. This pointed at the REAL
  // `registry/v1/trust.json` and passed because that file did not exist — so
  // the day one was signed and published it began failing with
  // `expected E_TRUST_UNPROVISIONED; the blocking codes were
  // ["E_WORKFLOW_NOT_ALLOWED"]`. That is the run getting further, correctly:
  // the test was asserting a state of the world, not a behaviour.
  //
  // What it exists for survives. With nothing delegated there is no allowlist
  // to check an attestation against, and the bot must stop at the anchor rather
  // than proceed on a catalogue nobody vouched for.
  const r = await run({
    assets: [conformingAsset()],
    // The COMPILED roots, which is what production uses: `rootKeys` is left
    // out rather than named, so this test runs the production path.
    rootKeys: undefined,
    trustFile: path.join(REPO_ROOT, "registry", "v1", "trust.json.no-such-file"),
  });
  assertBlockedWith(r, "E_TRUST_UNPROVISIONED");
  assert(r.findings.length === 1, "and it stops there rather than spending a stranger's bandwidth");
});

await test("the published trust.json delegates a non-empty allowlist", () => {
  // The other half, assertable only now that one is signed: the committed
  // document verifies under the committed roots and yields an allowlist. If it
  // ever stops doing so — expired, a key rotated out, the file edited — every
  // ingest silently returns to the state above, and the message a submitter
  // gets says the anchor is missing rather than that it went stale.
  const verdict = loadWorkflowAllowlist({
    trustFile: path.join(REPO_ROOT, "registry", "v1", "trust.json"),
  });
  assert(verdict.ok, verdict.message ?? "the committed trust.json does not verify under the roots");
  assert(
    verdict.allowlist.length > 0,
    "it verifies but delegates no reusable-workflow commit, so every release ingest would stop at E_WORKFLOW_NOT_ALLOWED",
  );
});

await test("a trust.json signed by a stranger is not a trust.json", () => {
  const verdict = loadWorkflowAllowlist({
    trustFile: path.join(REPO_ROOT, "tools", "testkeys", "fixtures", "trust-stranger-signed.json"),
    roots: TEST_ROOT_KEYS,
  });
  assert(!verdict.ok, "a document signed by a key no root vouches for must not deliver an allowlist");
  assertEqual(verdict.code, "E_TRUST_UNPROVISIONED", verdict.message);
});

await test("a trust.json tampered with after signing is refused", () => {
  const verdict = loadWorkflowAllowlist({
    trustFile: path.join(REPO_ROOT, "tools", "testkeys", "fixtures", "trust-reserve-signed-tampered.json"),
    roots: TEST_ROOT_KEYS,
  });
  assert(!verdict.ok, verdict.message ?? "");
});

await test("the reserve root is a root", () => {
  const verdict = loadWorkflowAllowlist({
    trustFile: path.join(REPO_ROOT, "tools", "testkeys", "fixtures", "trust-reserve-signed.json"),
    roots: TEST_ROOT_KEYS,
  });
  assert(verdict.ok, "replacing a root must be a signature, not a flag day");
});

await test("a missing manifest probe fails the run rather than skipping the check", async () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "astra-noprobe-"));
  scratch.push(empty);
  const saved = process.env.ASTRA_MANIFEST_PROBE;
  delete process.env.ASTRA_MANIFEST_PROBE;
  try {
    const out = await runProbe({ pluginToml: "", botDir: empty });
    assertEqual(out.findings[0].code, "E_PROBE_UNAVAILABLE", JSON.stringify(out.findings));
    assertEqual(out.manifest, null, "nothing is reported about a manifest nothing parsed");
    emitted.add(out.findings[0].code);
  } finally {
    if (saved !== undefined) process.env.ASTRA_MANIFEST_PROBE = saved;
  }
});

await test("the probe the tests run is the real one, built from the daemon's crate", () => {
  assert(findProbe() !== null,
    "build it: bot/manifest-probe/link-deps.sh && cargo build --release --manifest-path bot/manifest-probe/Cargo.toml");
});

// ═══════════════════════════════════════════════════════════════════════════

section("the two typed facts");

await test("E_INPUT_REPO — a repository that is not owner/name", async () => {
  const r = await run({ assets: [conformingAsset()], repo: "https://github.com/a/b" });
  assertBlockedWith(r, "E_INPUT_REPO");
});

await test("E_INPUT_TAG — a tag with a space in it", async () => {
  const r = await run({ assets: [conformingAsset()], tag: "v0.2.0 latest" });
  assertBlockedWith(r, "E_INPUT_TAG");
});

await test("E_RELEASE_NOT_FOUND — the tag does not exist", async () => {
  const github = fakeGitHub({ repo: REPO, tag: "v9.9.9", assets: [conformingAsset()] });
  const r = await ingest(
    { repo: REPO, tag: TAG, submitter: SUBMITTER, root: REPO_ROOT, trustFile: TRUST_FILE },
    { rootKeys: TEST_ROOT_KEYS, fetchRelease: github.fetchRelease.bind(github), proveOwnership: fakeOwnership() },
  );
  for (const i of r.findings) emitted.add(i.code);
  assertBlockedWith(r, "E_RELEASE_NOT_FOUND");
});

await test("E_NO_BUNDLE_ASSETS — a release with no .astraplugin on it", async () => {
  const r = await run({ assets: [{ name: "dice-roller.tar.gz", bytes: Buffer.from("nope") }] });
  assertBlockedWith(r, "E_NO_BUNDLE_ASSETS");
});

await test("E_OWNERSHIP_UNPROVEN — the submitter does not control the repository", async () => {
  const r = await run({ assets: [conformingAsset()], ownershipOk: false });
  assertBlockedWith(r, "E_OWNERSHIP_UNPROVEN");
});

section("the asset");

await test("E_ASSET_URL_FOREIGN — an asset served from another repository's release", async () => {
  const r = await run({
    assets: [{
      name: "dice-roller-0.2.0-linux-x64.astraplugin",
      bytes: makeBundle(),
      url: "https://github.com/someone-else/other/releases/download/v1/dice-roller-0.2.0-linux-x64.astraplugin",
    }],
  });
  assertBlockedWith(r, "E_ASSET_URL_FOREIGN");
});

await test("E_ASSET_FILENAME — a stale bundle from the previous version", async () => {
  const r = await run({
    assets: [{ name: "dice-roller-0.1.9-linux-x64.astraplugin", bytes: makeBundle() }],
    root: registryWith({}),
  });
  assertBlockedWith(r, "E_ASSET_FILENAME");
});

await test("E_ASSET_SIZE — the bytes are not the bytes the release advertised", async () => {
  const r = await run({
    assets: [{ name: "dice-roller-0.2.0-linux-x64.astraplugin", bytes: makeBundle(), apiSize: 12 }],
  });
  assertBlockedWith(r, "E_ASSET_SIZE");
});

await test("E_ARTIFACT_TOO_LARGE — refused from the HEAD, before the download", async () => {
  const r = await run({
    assets: [{ name: "dice-roller-0.2.0-linux-x64.astraplugin", bytes: makeBundle(), headSize: 1024 ** 3 }],
  });
  assertBlockedWith(r, "E_ARTIFACT_TOO_LARGE");
});

section("provenance");

await test("E_ATTESTATION_MISSING — a hand-built bundle", async () => {
  const r = await run({ assets: [conformingAsset()], ghFail: "no attestations found for a-stranger/dice-roller" });
  assertBlockedWith(r, "E_ATTESTATION_MISSING");
});

await test("E_ATTESTATION_INVALID — the verification failed for some other reason", async () => {
  const r = await run({ assets: [conformingAsset()], ghFail: "signature verification failed" });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
});

await test("E_ATTESTATION_SUBJECT_MISMATCH — attested bytes that are not these bytes", async () => {
  const r = await run({ assets: [conformingAsset()], subjectOverride: "f".repeat(64) });
  assertBlockedWith(r, "E_ATTESTATION_SUBJECT_MISMATCH");
});

await test("E_ATTESTATION_REPO_MISMATCH — built somewhere other than the listed repository", async () => {
  const r = await run({ assets: [conformingAsset()], attestRepo: "someone-else/other" });
  // `gh --repo` would refuse it too; the bot checks the certificate itself so
  // the answer does not depend on which flags a future gh honours.
  assert(r.blocked, JSON.stringify(codes(r)));
  assert(errorCodes(r).some((c) => c.startsWith("E_ATTESTATION")), JSON.stringify(errorCodes(r)));
});

await test("E_ATTESTATION_REPO_MISMATCH — a certificate naming another repository", async () => {
  const r = await run({ assets: [conformingAsset()], certRepo: "someone-else/other" });
  assertBlockedWith(r, "E_ATTESTATION_REPO_MISMATCH");
});

await test("E_WORKFLOW_NOT_ALLOWED — a valid attestation from a workflow nobody pinned", async () => {
  const r = await run({ assets: [conformingAsset()], signerDigest: "c".repeat(40) });
  assertBlockedWith(r, "E_WORKFLOW_NOT_ALLOWED");
  const finding = r.findings.find((i) => i.code === "E_WORKFLOW_NOT_ALLOWED");
  assert(finding.message.includes("c".repeat(40)), "the comment names the commit that was refused");
});

await test("the default signer-workflow pin names a file that actually exists", () => {
  // **The transposition this catches.** The constant read
  // `release-plugin.yml` while the file in AstraPlugins is
  // `plugin-release.yml`. `gh attestation verify --signer-workflow` matches on
  // that path, so the pin matched no attestation ever produced — every honest
  // submission would have come back E_ATTESTATION_MISSING and the failure would
  // have looked like the author's fault. No fixture could catch it, because the
  // fake `gh` ignored the flag entirely.
  //
  // Asserted against the real directory when it is reachable, and against the
  // fixture constant always, so the pair cannot drift even off a machine that
  // does not have AstraPlugins checked out beside this repository.
  assertEqual(DEFAULT_SIGNER_WORKFLOW, FIXTURE_SIGNER_WORKFLOW,
    "the pin and the workflow the fixtures are signed by must be one string");
  const [owner, repo, ...rest] = DEFAULT_SIGNER_WORKFLOW.split("/");
  assertEqual(`${owner}/${repo}`, "mihailinl/AstraPlugins", "the pin names the Astra repository");
  const relative = rest.join("/");
  assert(relative.startsWith(".github/workflows/"), `not a workflow path: ${relative}`);
  const checkout = path.resolve(REPO_ROOT, "..", "AstraPlugins");
  const dir = path.join(checkout, ".github", "workflows");
  if (!fs.existsSync(dir)) return; // not checked out beside us; the pair above still held
  const names = fs.readdirSync(dir);
  assert(names.includes(path.basename(relative)),
    `${DEFAULT_SIGNER_WORKFLOW} names a workflow that does not exist. ` +
    `AstraPlugins/.github/workflows/ contains ${JSON.stringify(names)}`);
});

await test("E_ATTESTATION_MISSING — a pin that matches no attestation", async () => {
  // The class the transposition belonged to, made catchable: `gh` is asked
  // about a workflow path the build was not signed by, and answers the way the
  // real one does. Before `fakeGh` read `--signer-workflow` this test passed
  // whatever the constant said.
  const r = await run({
    assets: [conformingAsset()],
    signerWorkflow: "mihailinl/AstraPlugins/.github/workflows/release-plugin.yml",
  });
  assertBlockedWith(r, "E_ATTESTATION_MISSING");
});

await test("an attestation carrying no resolved signer commit proves nothing", () => {
  const facts = extractSignerFacts([{
    verificationResult: { statement: { subject: [{ digest: { sha256: "a".repeat(64) } }] } },
  }]);
  assertEqual(facts.signerDigest, null, "a field that is absent must be null, never a default");
});

// ── ID-28, one fixture per row (registry plan B-T1.1) ───────────────────────
//
// The rows are enforced because B-T1.2's survey found every listing passing
// them (ID-29): 18 ids, 24 artifacts, all ten OIDs present, `.9` under the
// reusable workflow, `.10` in `reusable_workflow_shas`, `.11` `github-hosted`,
// `.13` equal to `release.commit`, `.14` `refs/tags/<tag>`, `.20` `push`, on
// 18/18. Enforcing a row the catalogue fails would have delisted the
// catalogue; the survey is why these are errors and not notes.

await test("ID-28 .9 — a build signed by some other workflow's path", async () => {
  const r = await run({
    assets: [conformingAsset()],
    signerUri: `https://github.com/mihailinl/AstraPlugins/.github/workflows/something-else.yml@${"c".repeat(40)}`,
  });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
  assert(r.findings.some((i) => i.message.includes("job_workflow_ref (.9)")), JSON.stringify(errorCodes(r)));
});

await test("ID-28 .9 — the suffix is a commit today, and the matcher still takes any ref", async () => {
  // The survey measured it: `.9`'s suffix is a 40-hex SHA on all 24 artifacts,
  // never a symbolic ref. ID-28's row says "@ any ref" all the same, and a
  // matcher written `@refs/…` would have refused the entire catalogue — so
  // both spellings pass here, deliberately, and this test is the record of
  // why the stricter one was not written.
  for (const suffix of ["c".repeat(40), "refs/heads/main", "refs/tags/v1"]) {
    const r = await run({
      assets: [conformingAsset()],
      signerUri: `https://github.com/${DEFAULT_SIGNER_WORKFLOW}@${suffix}`,
    });
    assert(!r.blocked, `@${suffix} was refused: ${JSON.stringify(errorCodes(r))}`);
  }
});

await test("ID-28 .11 — a self-hosted runner is a machine the registry knows nothing about", async () => {
  const r = await run({ assets: [conformingAsset()], cert: { runnerEnvironment: "self-hosted" } });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
  assert(r.findings.some((i) => i.message.includes("runner_environment (.11)")), JSON.stringify(errorCodes(r)));
});

await test("ID-28 .14 — built from a ref that is not the tag being listed", async () => {
  const r = await run({ assets: [conformingAsset()], cert: { ref: "refs/heads/main" } });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
  assert(r.findings.some((i) => i.message.includes("ref (.14)")), JSON.stringify(errorCodes(r)));
});

await test("ID-28 .20 — a dispatch somebody typed is not a tag push", async () => {
  const r = await run({ assets: [conformingAsset()], cert: { eventName: "workflow_dispatch" } });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
  assert(r.findings.some((i) => i.message.includes("event_name (.20)")), JSON.stringify(errorCodes(r)));
});

await test("ID-28 — a missing field is refused by name, one row at a time", async () => {
  for (const [field, oid] of Object.entries({
    job_workflow_ref: ".9", job_workflow_sha: ".10", runner_environment: ".11",
    source_repository_uri: ".12", sha: ".13", ref: ".14", repository_id: ".15",
    repository_owner_id: ".17", event_name: ".20", run: ".21",
  })) {
    const r = await run({ assets: [conformingAsset()], cert: { omitFields: [field] } });
    assertBlockedWith(r, "E_ATTESTATION_INVALID");
    assert(r.findings.some((i) => i.message.includes(field)),
      `${oid} went missing and the report did not name ${field}: ${JSON.stringify(errorCodes(r))}`);
  }
});

await test("ID-28 .15/.17 — the two ids reach the caller, as base-10 strings", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({}) });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  const facts = extractSignerFacts(JSON.parse((await fakeGh({
    repo: REPO, signerDigest: ALLOWED_WORKFLOW_SHA, subjectDigest: "d".repeat(64), tag: TAG,
  })(["attestation", "verify", "x", "--repo", REPO])).stdout), "d".repeat(64));
  assertEqual(facts.fields.repository_id, FIXTURE_REPOSITORY_ID, ".15 is read from the certificate");
  assertEqual(facts.fields.repository_owner_id, FIXTURE_OWNER_ID, ".17 is read from the certificate");
  assertEqual(typeof facts.fields.repository_id, "string", "SCOPE-5: base-10 STRINGS, never numbers");
  assert(facts.fields.run.includes("/actions/runs/"), ".21 is returned for B-T3.3a's actor read (MIG-31)");
});

await test("SCOPE-5 — an id that arrives as a JSON number is refused, never coerced", async () => {
  // `9007199254740993` parses to `…992`. `String(n)` then hands the registry
  // plausible digits naming a repository that never published anything. The
  // type is refused before any grammar sees the value.
  const r = await run({
    assets: [conformingAsset()],
    cert: { certificateOverrides: { sourceRepositoryIdentifier: 9007199254740993 } },
  });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
  assert(r.findings.some((i) => i.message.includes("SCOPE-5")), JSON.stringify(errorCodes(r)));
});

await test("a predicate-only attestation proves nothing — the fallbacks are gone", async () => {
  // The predicate carries a repository, a signer path and a commit, all
  // correct, and there is no certificate at all.
  const r = await run({ assets: [conformingAsset()], cert: { predicateOnly: true } });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
  assert(r.findings.some((i) => i.message.includes("carries no")), JSON.stringify(errorCodes(r)));
});

await test("a field the certificate omits is NOT taken from the predicate", async () => {
  // The sharp version of the rule, and the one that is a canary: everything
  // about this release is perfect except that `.12` is absent from the
  // certificate, while the predicate names the repository correctly. Before
  // B-T1.1 `extractSignerFacts` read `externalParameters.workflow.repository`
  // whenever the certificate had no `sourceRepositoryURI` — so this ingested,
  // and the listing's `source.repo` came from a string the builder composed.
  // Restoring that one fallback turns this test green, which is how it was
  // watched failing.
  const r = await run({
    assets: [conformingAsset()],
    root: registryWith({}),
    cert: { omitFields: ["source_repository_uri"], predicateFacts: true },
  });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
  assert(r.findings.some((i) => i.message.includes("source_repository_uri")),
    `the report must name the field it would not guess: ${JSON.stringify(errorCodes(r))}`);
});

await test("the DER fallback reads a field gh's JSON has no key for", async () => {
  // Dead code for today's catalogue and kept anyway: B-T1.2 found all ten
  // fields in gh 2.100.0's JSON on 18/18 bundles, AND found a live example of
  // the class this exists for — `.24` is on every certificate and in nobody's
  // JSON. Here `.15` and `.21` are hidden from the JSON and left in the DER,
  // which is what a gh that renamed or dropped a key would look like.
  const r = await run({
    assets: [conformingAsset()],
    root: registryWith({}),
    cert: { derOnlyFields: ["repository_id", "run"] },
  });
  assert(!r.blocked, `the DER fallback did not fire: ${JSON.stringify(errorCodes(r))}`);
});

await test("an attestation for another file of the same release contributes no field", async () => {
  // B-T1.1's "a release-file bundle naming other ids is ignored". gh answers
  // with an array; only the attestation whose subject is THESE bytes may say
  // anything about where they came from.
  const other = {
    verificationResult: {
      signature: {
        certificate: {
          buildSignerURI: `https://github.com/${DEFAULT_SIGNER_WORKFLOW}@${"c".repeat(40)}`,
          buildSignerDigest: "e".repeat(40),
          sourceRepositoryURI: "https://github.com/someone-else/other",
          sourceRepositoryDigest: "b".repeat(40),
          sourceRepositoryRef: "refs/tags/v9.9.9",
          sourceRepositoryIdentifier: "999999",
          sourceRepositoryOwnerIdentifier: "888888",
          runnerEnvironment: "self-hosted",
          buildTrigger: "workflow_dispatch",
          runInvocationURI: "https://github.com/someone-else/other/actions/runs/9",
        },
      },
      statement: { subject: [{ name: "other.astraplugin", digest: { sha256: "9".repeat(64) } }] },
    },
  };
  const r = await run({ assets: [conformingAsset()], root: registryWith({}), cert: { extraResults: [other] } });
  assert(!r.blocked, `the wrong attestation was read: ${JSON.stringify(errorCodes(r))}`);
});

await test("two bundles of one release disagreeing on .15, or on .12, are refused", async () => {
  // **A fixture is the only place this can be exercised, and that is
  // measured.** B-T1.2: one bundle per RELEASE, not per artifact — the six
  // listings shipping two artifacts verify both against the same attestation,
  // which carries both as subjects and produces byte-identical JSON. No tree
  // in the catalogue can make this fire, so nobody should conclude from a
  // clean catalogue that it works.
  const linux = conformingAsset();
  const windows = conformingAsset({ os: "windows", arch: "x86_64" });
  for (const [field, override] of Object.entries({
    ".15": { repositoryId: "999999" },
    ".12": { certRepo: "someone-else/other" },
  })) {
    const r = await run({
      assets: [linux, windows],
      root: registryWith({}),
      certByAsset: { [windows.name]: override },
    });
    assert(errorCodes(r).includes("E_ATTESTATION_INVALID") || errorCodes(r).includes("E_ATTESTATION_REPO_MISMATCH"),
      `${field}: expected a refusal, got ${JSON.stringify(errorCodes(r))}`);
  }
});

await test("gh's policy refusal is not a missing attestation", async () => {
  // The survey's finding, as a test. `Error: verifying with issuer
  // "sigstore.dev"` is exit 1 with nothing on stdout and no named check —
  // and it means the flags and the certificate disagree, which is the
  // registry's problem. Reading it as E_ATTESTATION_MISSING tells an author to
  // add an attestation they already have, which is what happened to 12 of 18
  // ids in the survey's first pass.
  const r = await run({ assets: [conformingAsset()], ghFail: 'Error: verifying with issuer "sigstore.dev"' });
  assertBlockedWith(r, "E_ATTESTATION_INVALID");
  assert(!errorCodes(r).includes("E_ATTESTATION_MISSING"), "a policy refusal is not an absence");
  const finding = r.findings.find((i) => i.code === "E_ATTESTATION_INVALID");
  assert(finding.message.includes("NOT a missing attestation"), finding.message);
});

await test("a 404 is the only thing that means there is no attestation", async () => {
  const r = await run({
    assets: [conformingAsset()],
    ghFail: "Error: HTTP 404: Not Found (https://api.github.com/repos/a-stranger/dice-roller/attestations/sha256:abc)",
  });
  assertBlockedWith(r, "E_ATTESTATION_MISSING");
});

await test("the two functions bot/baseline.mjs refuses to run without", async () => {
  // MIG-20's baseline is written ONCE, and `bot/baseline.mjs` refuses to
  // write it until two functions exist under exactly these names:
  // `certificateIds` in `bot/lib/certificate.mjs` and `fetchRepositoryIds` in
  // `bot/lib/github.mjs`. Its own suite asserts the REFUSAL, against a
  // fixture directory — so nothing, until now, asserted that the real modules
  // satisfy it. Renaming either function would restore a refusal that reads
  // like an unstarted task, on a file whose comment says the task is done.
  const bundle = JSON.parse((await fakeGh({
    repo: REPO, signerDigest: ALLOWED_WORKFLOW_SHA, subjectDigest: "e".repeat(64), tag: TAG,
  })(["attestation", "verify", "x", "--repo", REPO])).stdout);
  const ids = certificateIds({ bundle, artifactSha256: "e".repeat(64) });
  assertEqual(ids.repository_id, FIXTURE_REPOSITORY_ID, "base-10 string or null, and this one is the string");
  assertEqual(ids.repository_owner_id, FIXTURE_OWNER_ID, "the same for .17");
  const none = certificateIds({ bundle, artifactSha256: "f".repeat(64) });
  assertEqual(none.repository_id, null, "a bundle that does not cover these bytes yields null, never a guess");
  assertEqual(typeof gh.fetchRepositoryIds, "function", "B-T1.3's by-id read, under the name baseline.mjs asks for");
});

section("identity, from the certificate (B-T3.2)");

await test("the listing's repository name comes from .12, not from the submission", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({}) });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assertEqual(r.derived.plugin.source.repo, REPO, "source.repo");
  assertEqual(r.derived.version.release.repo, REPO, "release.repo");
  // The two are equal here because the attestation check refuses a
  // certificate naming another repository — so the pipeline cannot, by
  // itself, tell which of the two strings was used. That is why the rule is
  // asserted directly below as well, on a listing where they differ.
  const applied = applyIdentity(
    { plugin: { source: { kind: "github", repo: "submitter/typed-this" } }, version: { release: { repo: "submitter/typed-this" } } },
    { repo: "certificate/says-this" },
  );
  assert(applied.ok, applied.reason);
  assertEqual(applied.derived.plugin.source.repo, "certificate/says-this", "BOT-21: .12 wins over the submission");
  assertEqual(applied.derived.version.release.repo, "certificate/says-this", "and over every release.repo");
});

await test("the run returns the identity the certificate stated", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({}) });
  assertEqual(r.identity.repository_id, FIXTURE_REPOSITORY_ID, ".15 travels to the caller");
  assertEqual(r.identity.repository_owner_id, FIXTURE_OWNER_ID, "and .17");
  assertEqual(r.identity.repo, REPO, "and .12's owner/name");
  assertEqual(r.identity.run_id, "1", "and the run id out of .21, for MIG-31");
});

await test("INV-14 — a reserved id is refused whichever path asked", async () => {
  const r = await run({ assets: [conformingAsset({ id: "astra" })] });
  assert(r.blocked, JSON.stringify(codes(r)));
  assert(errorCodes(r).some((c) => c.startsWith("E_ID_RESERVED")), JSON.stringify(errorCodes(r)));
});

section("GitHub, read by id (B-T1.3)");

/**
 * A GitHub that answers from a table of URLs, with headers.
 *
 * Nothing here touches the network. The SHAPES are not invented: each was
 * measured against api.github.com on 2026-09-19 and the measurements are
 * recorded at the top of `bot/lib/github.mjs` — including the one that matters
 * most, that a renamed repository answers `301` with
 * `location: https://api.github.com/repositories/<id>`.
 */
function stubFetch(routes) {
  const seen = [];
  const impl = async (url) => {
    seen.push(String(url));
    const route = routes[String(url)];
    if (!route) throw new Error(`the stub was not told about ${url}`);
    if (route.throws) throw new Error(route.throws);
    const headers = new Map(Object.entries(route.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    return {
      status: route.status,
      ok: route.status >= 200 && route.status < 300,
      headers: { get: (k) => headers.get(k.toLowerCase()) ?? null },
      async text() { return route.body ?? ""; },
    };
  };
  impl.seen = seen;
  return impl;
}

const API = "https://api.github.com";

await test("a renamed repository answers 301, and the id survives the rename", async () => {
  const fetchImpl = stubFetch({
    [`${API}/repos/KNICE-TECH/astra-chess`]: {
      status: 301,
      headers: { location: `${API}/repositories/1343092393` },
    },
    [`${API}/repositories/1343092393`]: {
      status: 200,
      body: JSON.stringify({
        id: 1343092393, full_name: "MINICE-AI/astra-chess",
        owner: { login: "MINICE-AI", id: 280318216 },
      }),
    },
  });
  const answer = await gh.fetchRepositoryIds("KNICE-TECH/astra-chess", { fetchImpl });
  assertEqual(answer.status, "found", answer.reason);
  assertEqual(answer.id, "1343092393", "the id of the repository the assets came from (BOT-21)");
  assertEqual(answer.owner_id, "280318216", "and its owner's");
  assertEqual(answer.full_name, "MINICE-AI/astra-chess", "the name GitHub uses TODAY, not the one we asked with");
  assert(answer.renamed, "a caller has to be able to say that a rename happened");
  // The live pair this fixture copies: the certificate of both chess listings
  // says `KNICE-TECH/astra-chess`, and `KNICE-TECH` is a freed login anybody
  // can register. The name froze at signing; the id did not move.
});

await test("a 404 is absence and a 403 is not", async () => {
  const gone = await gh.fetchRepositoryIds("nobody/nothing", {
    fetchImpl: stubFetch({ [`${API}/repos/nobody/nothing`]: { status: 404 } }),
  });
  assertEqual(gone.status, "not_found", gone.reason);

  const limited = await gh.fetchRepositoryIds("a/b", {
    fetchImpl: stubFetch({
      [`${API}/repos/a/b`]: {
        status: 403,
        headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1758300000" },
      },
    }),
  });
  assertEqual(limited.status, "transient", limited.reason);
  assert(limited.reason.includes("rate-limit"), limited.reason);
  assertEqual(limited.id, null, "a read that did not happen produces no id");

  const refused = await gh.fetchRepositoryIds("a/b", {
    fetchImpl: stubFetch({ [`${API}/repos/a/b`]: { status: 403 } }),
  });
  assertEqual(refused.status, "transient", "a bare 403 is a refusal, and a refusal is never absence");
});

await test("a 502 and a dropped connection are both reads that did not happen", async () => {
  const bad = await gh.fetchRepositoryIds("a/b", {
    fetchImpl: stubFetch({ [`${API}/repos/a/b`]: { status: 502 } }),
  });
  assertEqual(bad.status, "transient", bad.reason);
  const dropped = await gh.fetchRepositoryIds("a/b", {
    fetchImpl: stubFetch({ [`${API}/repos/a/b`]: { throws: "ECONNRESET" } }),
  });
  assertEqual(dropped.status, "transient", dropped.reason);
  assert(dropped.reason.includes("ECONNRESET"), dropped.reason);
});

await test("an id past 2^53 comes out of the response text, not out of JSON.parse", async () => {
  // `JSON.parse` turns 9007199254740993 into …992 before any code here sees
  // it, and `String()` then makes the loss unreadable. SCOPE-5 says base-10
  // strings for exactly this, and this is the test that proves the string is
  // not just a coercion of the lossy number.
  const body = '{"id":9007199254740993,"full_name":"big/repo","owner":{"login":"big","id":9007199254740995}}';
  const answer = await gh.fetchRepositoryIds("big/repo", {
    fetchImpl: stubFetch({ [`${API}/repos/big/repo`]: { status: 200, body } }),
  });
  assertEqual(answer.id, "9007199254740993", "the digits GitHub sent");
  assertEqual(answer.owner_id, "9007199254740995", "and the owner's");
  assert(answer.reason.includes("2^53"), "and the answer says where they came from");
  assert(String(JSON.parse(body).id) !== answer.id, "the parse really does lose it — the premise holds");
});

await test("ID-63's two reads: the owner-file commit, and whether a pull request carried it", async () => {
  const listUrl = `${API}/repositories/1203676452/commits` +
    `?sha=${"a".repeat(40)}&path=.well-known%2Fastra-plugin-owner&per_page=1`;
  const withPull = stubFetch({
    [listUrl]: { status: 200, body: JSON.stringify([{ sha: "b".repeat(40) }]) },
    [`${API}/repositories/1203676452/commits/${"b".repeat(40)}/pulls`]: {
      status: 200, body: JSON.stringify([{ number: 17 }]),
    },
  });
  const last = await gh.lastCommitTouching(1203676452, "a".repeat(40), ".well-known/astra-plugin-owner", { fetchImpl: withPull });
  assertEqual(last.status, "found", last.reason);
  assertEqual(last.commit, "b".repeat(40), "the newest commit touching the file up to the attested one");
  const pulls = await gh.pullsForCommit(1203676452, "b".repeat(40), { fetchImpl: withPull });
  assertEqual(pulls.status, "found", pulls.reason);
  assertEqual(pulls.pulls.join(","), "17", "GitHub ties it to #17");

  const noPull = await gh.pullsForCommit(1203676452, "c".repeat(40), {
    fetchImpl: stubFetch({
      [`${API}/repositories/1203676452/commits/${"c".repeat(40)}/pulls`]: { status: 200, body: "[]" },
    }),
  });
  assertEqual(noPull.status, "found", noPull.reason);
  assertEqual(noPull.pulls.length, 0, "tied to no pull request is an answer");
});

await test("a transient read reports no pull request — it reports that it did not read", async () => {
  // The distinction the record has to keep. "GitHub was rate-limited" and
  // "this commit reached the default branch with nobody reviewing it" look
  // the same to anyone reading `pull_request: false`, and only one of them is
  // evidence. `pulls` is null, never an empty list, when the read failed.
  const answer = await gh.pullsForCommit(1203676452, "d".repeat(40), {
    fetchImpl: stubFetch({
      [`${API}/repositories/1203676452/commits/${"d".repeat(40)}/pulls`]: {
        status: 403, headers: { "retry-after": "60" },
      },
    }),
  });
  assertEqual(answer.status, "transient", answer.reason);
  assertEqual(answer.pulls, null, "an unread list is null, never []");
});

await test("a file is read at the attested commit, by repository id", async () => {
  // ID-22: at the attested commit, whatever the default branch says today.
  const url = `${API}/repositories/1203676452/contents/.well-known/astra-plugin-owner?ref=${"a".repeat(40)}`;
  const answer = await gh.fileAtCommit(1203676452, "a".repeat(40), ".well-known/astra-plugin-owner", {
    fetchImpl: stubFetch({ [url]: { status: 200, body: "astra-binding: tok_example\n" } }),
  });
  assertEqual(answer.status, "found", answer.reason);
  assert(answer.content.includes("astra-binding:"), answer.content);

  const absent = await gh.fileAtCommit(1203676452, "a".repeat(40), ".well-known/astra-plugin-owner", {
    fetchImpl: stubFetch({ [url]: { status: 404 } }),
  });
  assertEqual(absent.status, "not_found", "no file is a fact; a rate limit is not");
});

await test("the run's triggering actor, for MIG-31's comparison with .17", async () => {
  const answer = await gh.workflowRun("mihailinl/AstraPlugins", "32409258885", {
    fetchImpl: stubFetch({
      [`${API}/repos/mihailinl/AstraPlugins/actions/runs/32409258885`]: {
        status: 200,
        body: JSON.stringify({ id: 32409258885, actor: { id: 1 }, triggering_actor: { login: "mihailinl", id: 193032699 } }),
      },
    }),
  });
  assertEqual(answer.status, "found", answer.reason);
  assertEqual(answer.triggering_actor_id, "193032699", "read as a base-10 string, and from triggering_actor");
  // The live value: run 32409258885 of text-utils 0.1.3 was triggered by
  // account 193032699, which is `.17` on that same certificate.
});

await test("a repository id that is not an id is refused before a request is made", async () => {
  const impl = stubFetch({});
  const answer = await gh.commitInRepository("mihailinl/AstraPlugins", "a".repeat(40), { fetchImpl: impl });
  assertEqual(answer.status, "transient", answer.reason);
  assertEqual(impl.seen.length, 0, "a name where an id belongs must not become a URL");
});

section("names");

await test("E_TYPOSQUAT_COLLISION — an id that folds onto a listed one", async () => {
  const r = await run({ assets: [conformingAsset({ id: "diceroller" })], root: registryWith({}) });
  assertBlockedWith(r, "E_TYPOSQUAT_COLLISION");
});

await test("R_TYPOSQUAT_NEAR — one edit away is a decision, not a rejection", async () => {
  const r = await run({ assets: [conformingAsset({ id: "dice-rollers" })], root: registryWith({}) });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assert(codes(r).includes("R_TYPOSQUAT_NEAR"), JSON.stringify(codes(r)));
});

await test("R_DISPLAY_NAME_COLLISION — same name, different spacing", () => {
  const found = checkNames(
    { id: "other-thing", name: "Dice  Roller", repoOwner: "x" },
    [{ id: "dice-roller", name: "Dice Roller" }],
    { flagDistance: 1, trademarks: loadTrademarks() },
  );
  assert(found.some((i) => i.code === "R_DISPLAY_NAME_COLLISION"), JSON.stringify(found));
  for (const i of found) emitted.add(i.code);
});

await test("a display name folds on case and whitespace only, never on digits", () => {
  assertEqual(foldDisplayName("  Dice   ROLLER "), "dice roller", "case and runs of space");
  assert(foldDisplayName("Mp3 Tools") !== foldDisplayName("Mpo Tools"),
    "an id fold would collide these two; a display name must not");
});

await test("R_DISPLAY_NAME_COLLISION — a BYTE-IDENTICAL name is the strongest case, not an exception", async () => {
  // The rule read `folds equal && other.name !== candidate.name`. The second
  // clause excluded the exactly-equal case, so every weaker variant was held
  // for a human and the strongest one published unattended: an already-listed
  // plugin could repaint its store card as a popular plugin's, exactly, with no
  // review and no delay.
  const found = checkNames(
    { id: "roll-dice-pro", name: "Dice Roller", repoOwner: "mallory" },
    [{ id: "dice-roller", name: "Dice Roller" }],
    { flagDistance: 1, trademarks: loadTrademarks() },
  );
  assert(found.some((i) => i.code === "R_DISPLAY_NAME_COLLISION"),
    `an identical name must be held: ${JSON.stringify(found)}`);
  for (const i of found) emitted.add(i.code);

  // And end to end, through the decision: the whole point is that it stops
  // being an unattended publish.
  const r = await run({
    assets: [conformingAsset({ id: "roll-dice-pro", name: "Dice Roller" })],
    root: registryWith({}),
  });
  assert(codes(r).includes("R_DISPLAY_NAME_COLLISION"), JSON.stringify(codes(r)));
});

await test("R_DISPLAY_NAME_MIXED_SCRIPT — one Cyrillic letter in a Latin name", async () => {
  // U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I where the ASCII `i`
  // belongs. NFKC does not touch it — it unifies compatibility variants of the
  // same character, not two characters that are drawn alike — and
  // `unsafeDisplayText` does not either, because a homoglyph is not invisible.
  // The card was pixel-identical to the listed plugin's and published with no
  // finding at all.
  const homoglyph = "D\u0456ce Roller";
  assert(homoglyph !== "Dice Roller", "the fixture must actually differ byte-wise");
  const found = checkNames(
    { id: "roll-dice-pro", name: homoglyph, repoOwner: "mallory" },
    [{ id: "dice-roller", name: "Dice Roller" }],
    { flagDistance: 1, trademarks: loadTrademarks() },
  );
  assert(found.some((i) => i.code === "R_DISPLAY_NAME_MIXED_SCRIPT"), JSON.stringify(found));
  assert(found.some((i) => i.code === "R_DISPLAY_NAME_COLLISION"),
    `and it must fold onto the name it is drawn as: ${JSON.stringify(found)}`);
  for (const i of found) emitted.add(i.code);

  // A name written entirely in one alphabet is ordinary and says nothing.
  const cyrillic = checkNames(
    { id: "kosti", name: "\u0418\u0433\u0440\u0430 \u0432 \u043a\u043e\u0441\u0442\u0438", repoOwner: "x" },
    [{ id: "dice-roller", name: "Dice Roller" }],
    { flagDistance: 1, trademarks: loadTrademarks() },
  );
  assertEqual(cyrillic.length, 0, `a Russian name is not a homoglyph attack: ${JSON.stringify(cyrillic)}`);
});

await test("the trademark table catches spot1fy as well as sp0tify", () => {
  // `foldId`'s table is single-valued: `1`→`l`, and nothing maps `1`→`i`. So
  // `Sp0tify Controller` was caught (`0`→`o`) and `Spot1fy Controller` folded
  // to `spotlfy` and matched no mark — the table caught one digit substitution
  // and missed the one next to it. The trademark rule compares SKELETONS now.
  const tm = loadTrademarks();
  for (const name of ["Sp0tify Controller", "Spot1fy Controller", "SpotIfy Controller"]) {
    const found = checkNames({ id: "media-tool", name, repoOwner: "x" }, [], { flagDistance: 1, trademarks: tm });
    assert(found.some((i) => i.code === "E_TRADEMARK"), `${name} must be caught: ${JSON.stringify(found)}`);
  }
  // And the id side of the same rule.
  const byId = checkNames({ id: "spot1fy-tools", name: "Media Tool", repoOwner: "x" }, [], { flagDistance: 1, trademarks: tm });
  assert(byId.some((i) => i.code === "E_TRADEMARK"), JSON.stringify(byId));
});

await test("E_TRADEMARK — a plugin named for somebody else's service", async () => {
  const r = await run({ assets: [conformingAsset({ id: "spotify-tools", name: "Spotify Tools" })] });
  assertBlockedWith(r, "E_TRADEMARK");
});

await test("…and a plugin that merely says which service it talks to is fine", () => {
  const found = checkNames(
    { id: "music-for-spotify", name: "Music controls for Spotify", repoOwner: "x" },
    [],
    { flagDistance: 1, trademarks: loadTrademarks() },
  );
  assertEqual(found.length, 0, `naming the service you integrate with is not a claim: ${JSON.stringify(found)}`);
});

await test("E_ID_RESERVED / E_ID_RESERVED_PREFIX — names that read as first-party", async () => {
  const a = await run({ assets: [conformingAsset({ id: "registry" })] });
  assertBlockedWith(a, "E_ID_RESERVED");
  const b = await run({ assets: [conformingAsset({ id: "astra-tools" })] });
  assertBlockedWith(b, "E_ID_RESERVED_PREFIX");
});

section("metadata, licence, platform");

await test("E_LICENSE_NOT_ALLOWED — a licence nobody here has read", async () => {
  // BUSL-1.1, and it has to be a licence that is genuinely absent from
  // `policy/spdx-allowlist.json` rather than one that merely was. This said
  // `GPL-3.0-only` and stopped testing anything the day the copyleft family was
  // added to the allowlist: the fixture kept naming "a licence nobody here has
  // read" while naming one that had been read and admitted.
  //
  // BUSL is a good long-term choice for this. It is a real, widely used licence
  // and it is source-available rather than open source, so it is not a candidate
  // for the allowlist while §4 of POLICY.md says open source only — which is
  // what this check is enforcing.
  const r = await run({ assets: [conformingAsset({ license: "BUSL-1.1" })] });
  assertBlockedWith(r, "E_LICENSE_NOT_ALLOWED");
});

await test("E_LICENSE_MISSING — no licence at all", async () => {
  const r = await run({ assets: [conformingAsset({ license: "" })] });
  assertBlockedWith(r, "E_LICENSE_MISSING");
});

await test("E_METADATA_UNSAFE_TEXT — a right-to-left override in the display name", async () => {
  const r = await run({ assets: [conformingAsset({ name: "Dice ‮RolleR‬" })] });
  assertBlockedWith(r, "E_METADATA_UNSAFE_TEXT");
});

await test("E_METADATA_MISSING — a manifest that does not say what the plugin is", async () => {
  const r = await run({ assets: [conformingAsset({ description: "" })] });
  assertBlockedWith(r, "E_METADATA_MISSING");
});

await test("E_METADATA_TOO_LONG — a display name past the card's width", async () => {
  const r = await run({ assets: [conformingAsset({ name: "D".repeat(200) })] });
  assertBlockedWith(r, "E_METADATA_TOO_LONG");
});

await test("E_CAPABILITY_UNKNOWN — the capability that drifted", async () => {
  const r = await run({ assets: [conformingAsset({ capabilities: ["ui_panels"] })] });
  assertBlockedWith(r, "E_CAPABILITY_UNKNOWN");
  assert(r.findings.find((i) => i.code === "E_CAPABILITY_UNKNOWN").message.includes("ui_contributions"),
    "the daemon's crate names the correct spelling and the bot passes it through");
});

await test("E_MIN_ASTRA_TOO_NEW — a plugin that needs an Astra nobody has", async () => {
  const github = fakeGitHub({ repo: REPO, tag: TAG, assets: [conformingAsset({ minAstraVersion: "99.0.0" })] });
  const r = await ingest(
    { repo: REPO, tag: TAG, submitter: SUBMITTER, root: registryWith({}),
      trustFile: TRUST_FILE, hostAstraVersion: "0.9.0" },
    {
      rootKeys: TEST_ROOT_KEYS,
      fetchRelease: github.fetchRelease.bind(github),
      headAsset: github.headAsset.bind(github),
      downloadAsset: github.downloadAsset.bind(github),
      proveOwnership: fakeOwnership(true),
      ghRunner: (args) => fakeGh({
        repo: REPO, signerDigest: ALLOWED_WORKFLOW_SHA, tag: TAG,
        subjectDigest: crypto.createHash("sha256").update(fs.readFileSync(args[2])).digest("hex"),
      })(args),
    },
  );
  for (const i of r.findings) emitted.add(i.code);
  assertBlockedWith(r, "E_MIN_ASTRA_TOO_NEW");
});

await test("E_MIN_ASTRA_INVALID — a requirement that requires nothing", async () => {
  const r = await run({ assets: [conformingAsset({ minAstraVersion: "nightly" })] });
  assertBlockedWith(r, "E_MIN_ASTRA_INVALID");
});

await test("E_PLATFORM_UNSUPPORTED — a host Astra ships no daemon for", async () => {
  const r = await run({ assets: [conformingAsset({ os: "macos" })] });
  assertBlockedWith(r, "E_PLATFORM_UNSUPPORTED");
});

// ═══════════════════════════════════════════════════════════════════════════

section("the card, in more than one language");

// Every case here is a real bundle through the real pipeline. The rules
// themselves are pinned against AstraPlugins/testdata/locales by
// tools/validate.mjs — that is coupling C16, and it is what stops the CLI and
// this repository refusing different things. What these tests add is the half a
// corpus cannot carry: that the rule reaches a submission at all, that the
// finding names the file the author has to open, and that what comes out is
// what a store renders.

/** A `locales/<code>.json` entry for `makeBundle`'s `extraFiles`. */
const locale = (code, keys) => ({
  name: `locales/${code}.json`,
  data: Buffer.from(JSON.stringify(keys, null, 2), "utf8"),
});
const EN_CARD = {
  "listing.name": "Dice Roller",
  "listing.description": "Rolls dice when you ask it to.",
};
const RU_CARD = {
  "listing.name": "Бросок костей",
  "listing.description": "Бросает кости, когда вы попросите.",
};

await test("a bundle's Russian card reaches the listing, and it is the only thing read out of locales/", async () => {
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", { ...EN_CARD, "action.roll.label": "Roll" }),
        locale("ru", { ...RU_CARD, "action.roll.label": "Бросить" }),
      ],
    })],
    root: registryWith({}),
  });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assertEqual(r.derived.plugin.i18n.ru.name, "Бросок костей", "the Russian card name was not derived");
  assertEqual(r.derived.plugin.i18n.ru.summary, "Бросает кости, когда вы попросите.", "nor the summary");
  assertEqual(r.derived.plugin.i18n.en, undefined,
    "`en` must never be a key: the flat name and summary ARE the English, and a document that can " +
    "carry it twice will eventually carry two different versions of it");
  // **That assertion alone has no teeth**, and a mutation is what showed it: an
  // `en` block built from a conforming `en.json` is identical to the English
  // card and is dropped by the rule below it, so widening the loop to all ten
  // codes changed nothing here. The case where the two differ is the case that
  // can actually reach a store, so it is the one asserted.
  const disagreeing = deriveLocaleText({
    files: [{ name: "locales/en.json", bytes: Buffer.from(JSON.stringify({ ...EN_CARD, "listing.name": "Something Else" }), "utf8") }],
    facts: { name: "Dice Roller", description: "Rolls dice when you ask it to." },
    limits: loadPolicy(REPO_ROOT).limits,
    summarise,
  });
  assertEqual(disagreeing.i18n?.en, undefined,
    "English reached the i18n member as a second, disagreeing copy of the card it is supposed to be");
  assertEqual(JSON.stringify(Object.keys(r.derived.plugin.i18n.ru).sort()), '["name","summary"]',
    "the interface strings (action.roll.label) are the daemon's business, not the card's");
});

await test("a locale block is never half a block — the missing half comes from English", async () => {
  // **This test was wrong when it was first written, and a mutation is what
  // said so.** It used a German file carrying BOTH reserved keys, so the fill
  // it claimed to exercise never ran: deleting the fill left every assertion
  // green. The path that actually reaches it is a plugin whose `en.json`
  // declares only `listing.description` — parity then permits every other
  // locale to declare only that too, and a block would otherwise be emitted
  // with a summary and no name, which the schema's `required` refuses.
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", { "listing.description": "Rolls dice when you ask it to." }),
        locale("ru", { "listing.description": "Бросает кости, когда вы попросите." }),
      ],
    })],
    root: registryWith({}),
  });
  assert(!r.blocked, `a half block reached the schema: ${JSON.stringify(errorCodes(r))}`);
  assertEqual(r.derived.plugin.i18n.ru.name, "Dice Roller",
    "the missing half must be filled from English, not left out of the block");
  assertEqual(r.derived.plugin.i18n.ru.summary, "Бросает кости, когда вы попросите.",
    "and the half that IS translated must survive the fill");
});

await test("…and a name identical to English is kept, because that is what a brand is", async () => {
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", EN_CARD),
        locale("de", { "listing.name": "Dice Roller", "listing.description": "Würfelt, wenn Sie fragen." }),
      ],
    })],
    root: registryWith({}),
  });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assertEqual(r.derived.plugin.i18n.de.name, "Dice Roller", "a brand name repeated in another locale was dropped");
  assertEqual(r.derived.plugin.i18n.de.summary, "Würfelt, wenn Sie fragen.", "and the German summary with it");
});

await test("a long localized description is cut to the card line, by the same cut the English one gets", async () => {
  // `listing.description` may be up to 4,000 characters — it is the manifest's
  // description — and the card line is 200. The English one has always been
  // summarised; a locale block that was not would be refused by the schema and
  // the author would be told the registry has a bug.
  const long = `${"Бросает кости, когда вы попросите. ".repeat(20)}`;
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", { ...EN_CARD, "listing.description": "Rolls dice when you ask it to." }),
        locale("ru", { "listing.name": "Бросок костей", "listing.description": long }),
      ],
    })],
    root: registryWith({}),
  });
  assert(!r.blocked, `an unsummarised locale block reached the schema: ${JSON.stringify(errorCodes(r))}`);
  const summary = r.derived.plugin.i18n.ru.summary;
  assert([...summary].length <= 200, `the Russian card line is ${[...summary].length} code points`);
  assert(summary.endsWith("…"), `and it must be marked as cut rather than merely short: ${JSON.stringify(summary)}`);
});

await test("a block that says exactly what the English card says is not emitted", async () => {
  const r = await run({
    assets: [conformingAsset({ extraFiles: [locale("en", EN_CARD), locale("fr", EN_CARD)] })],
    root: registryWith({}),
  });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assertEqual(r.derived.plugin.i18n, undefined,
    "a French block identical to the English card renders identically to no block, and costs every user its bytes");
});

await test("E_LOCALE_NO_ENGLISH — translations with nothing to fall back to", async () => {
  const r = await run({ assets: [conformingAsset({ extraFiles: [locale("ru", RU_CARD)] })] });
  assertBlockedWith(r, "E_LOCALE_NO_ENGLISH");
});

await test("E_LOCALE_UNKNOWN_CODE — the region tag that exists nowhere in this system", async () => {
  // `zh-CN` is the spelling this project used in its own documentation tree for
  // months. Astra's Chinese is `zh`, matching is exact string equality, and a
  // file named anything else is packed, digested, signed, installed and read by
  // nothing, with no error at any point.
  const r = await run({
    assets: [conformingAsset({ extraFiles: [locale("en", EN_CARD), locale("zh-CN", EN_CARD)] })],
  });
  assertBlockedWith(r, "E_LOCALE_UNKNOWN_CODE");
  assertEqual(r.findings.find((i) => i.code === "E_LOCALE_UNKNOWN_CODE").where, "locales/zh-CN.json",
    "the finding must name the file, not the stage");
});

await test("E_LOCALE_MALFORMED — the nested shape the daemon drops whole, silently", async () => {
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [{
        name: "locales/en.json",
        data: Buffer.from(JSON.stringify({ listing: { name: "Dice Roller" } }), "utf8"),
      }],
    })],
  });
  assertBlockedWith(r, "E_LOCALE_MALFORMED");
});

await test("E_LOCALE_KEY_MISSING and E_LOCALE_KEY_EXTRA — parity, in both directions", async () => {
  const missing = await run({
    assets: [conformingAsset({
      extraFiles: [locale("en", { ...EN_CARD, greeting: "Hello" }), locale("ru", RU_CARD)],
    })],
  });
  assertBlockedWith(missing, "E_LOCALE_KEY_MISSING");

  const extra = await run({
    assets: [conformingAsset({
      extraFiles: [locale("en", EN_CARD), locale("ru", { ...RU_CARD, extra: "Лишний" })],
    })],
  });
  assertBlockedWith(extra, "E_LOCALE_KEY_EXTRA");
});

await test("parity is over plural FAMILIES, or it fires on a file the CLI itself wrote", async () => {
  // `astra-plugin locale add ru` writes `msg.done.few` and `msg.done.many`,
  // which `en.json` cannot legally contain. A raw-key parity rule would refuse
  // the bundle its own toolchain produced and recommended.
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", { ...EN_CARD, "msg.done.one": "Rolled {n} die", "msg.done.other": "Rolled {n} dice" }),
        locale("ru", {
          ...RU_CARD,
          "msg.done.one": "{n} бросок", "msg.done.few": "{n} броска",
          "msg.done.many": "{n} бросков", "msg.done.other": "{n} броска",
        }),
      ],
    })],
    root: registryWith({}),
  });
  assert(!r.blocked, `the four Russian plural rows were refused: ${JSON.stringify(errorCodes(r))}`);
});

await test("E_LISTING_TEXT_MISMATCH — the card and the manifest saying two things", async () => {
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [locale("en", { ...EN_CARD, "listing.name": "Something Else" })],
    })],
  });
  assertBlockedWith(r, "E_LISTING_TEXT_MISMATCH");
});

await test("W_LOCALE_NO_CARD_TEXT — a plugin that translates its interface and not its card", async () => {
  const r = await run({
    assets: [conformingAsset({ extraFiles: [locale("en", { greeting: "Hello" }), locale("ru", { greeting: "Привет" })] })],
    root: registryWith({}),
  });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assert(codes(r).includes("W_LOCALE_NO_CARD_TEXT"), JSON.stringify(codes(r)));
  assertEqual(r.derived.plugin.i18n, undefined, "nothing to put on a card is not something to put on a card");
});

await test("E_LISTING_NOT_ENGLISH — the failure this whole feature was filed from", async () => {
  // The live one, word for word: a listing published through the correct
  // zero-touch path, in Russian, because nothing in this system had ever asked
  // what language a listing was in.
  const r = await run({
    assets: [conformingAsset({
      description: "Шахматы против локального бота или выбранной модели Astra с игровым чатом.",
    })],
  });
  assertBlockedWith(r, "E_LISTING_NOT_ENGLISH");
  const message = r.findings.find((i) => i.code === "E_LISTING_NOT_ENGLISH").message;
  assert(message.includes("SCRIPT check"),
    "a gate that overstates its reach is one people route around: the message has to say it cannot tell English from French");
});

await test("…and an English sentence quoting a Russian word still passes", async () => {
  const r = await run({
    assets: [conformingAsset({ description: "Plays chess against a local bot. The UI button says Шахматы." })],
    root: registryWith({}),
  });
  assert(!errorCodes(r).includes("E_LISTING_NOT_ENGLISH"),
    `60% and not 100% is the whole point: ${JSON.stringify(errorCodes(r))}`);
});

await test("W_LISTING_NAME_NOT_LATIN — a product name is not prose, and is not left unobserved either", async () => {
  const r = await run({
    assets: [conformingAsset({ name: "Бросок костей" })],
    root: registryWith({}),
  });
  assert(!errorCodes(r).includes("W_LISTING_NAME_NOT_LATIN"), "a name must not block a release");
  assert(codes(r).includes("W_LISTING_NAME_NOT_LATIN"), JSON.stringify(codes(r)));
});

await test("E_TRADEMARK — an honest English card and an impersonating Russian one", async () => {
  // The hole that mattered most. `checkNames` ran exactly once, on the English
  // name out of plugin.toml, so a bundle whose en.json said `Dice Roller` and
  // whose ru.json said `Telegram` would have put a card named Telegram in front
  // of every Russian user — on a listing a human approved by reading a clean
  // English card.
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", EN_CARD),
        locale("ru", { "listing.name": "Telegram", "listing.description": "Бросает кости, когда вы попросите." }),
      ],
    })],
    root: registryWith({}),
  });
  assertBlockedWith(r, "E_TRADEMARK");
  assertEqual(r.findings.find((i) => i.code === "E_TRADEMARK").where, "locales/ru.json",
    "the finding has to name the language, or the author reads the English name and sees nothing wrong");
});

await test("R_DISPLAY_NAME_COLLISION — two cards that are the same card in Russian", async () => {
  const root = registryWith({
    id: "other-dice",
    name: "Something Else",
    i18n: { ru: { name: "Бросок костей", summary: "Кости." } },
  });
  const r = await run({
    assets: [conformingAsset({ extraFiles: [locale("en", EN_CARD), locale("ru", RU_CARD)] })],
    root,
  });
  assert(codes(r).includes("R_DISPLAY_NAME_COLLISION"),
    `a collision only a Russian user can see is still a collision: ${JSON.stringify(codes(r))}`);
});

await test("a Cyrillic name that borrows a Latin brand is not a homoglyph attack", async () => {
  // `Клиент Telegram` is what an honest Russian name for a third-party client
  // looks like. Flagging it would put every honest Cyrillic listing in a review
  // queue, which ends with the rule switched off inside a week.
  const r = await run({
    assets: [conformingAsset({
      id: "chat-bridge",
      name: "Chat Bridge",
      extraFiles: [
        locale("en", { "listing.name": "Chat Bridge", "listing.description": "Rolls dice when you ask it to." }),
        locale("ru", { "listing.name": "Мост Chat", "listing.description": "Бросает кости, когда вы попросите." }),
      ],
    })],
    root: registryWith({}),
  });
  assert(!codes(r).includes("R_DISPLAY_NAME_MIXED_SCRIPT"),
    `an honest Russian name was held for a human: ${JSON.stringify(codes(r))}`);
});

await test("W_LOCALE_STALE — a translation of English that has since been rewritten", async () => {
  // Debian's Description-md5, as a derived value: the lock records a digest of
  // the English each translation was made against. When it stops matching, the
  // string falls back to English rather than the release being refused —
  // showing a confidently wrong sentence in a language nobody here can
  // proof-read is worse than showing a correct one in the wrong language.
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", EN_CARD),
        locale("ru", RU_CARD),
        {
          name: "locales.lock.json",
          data: Buffer.from(JSON.stringify({
            schema: "astra.plugin.locales/1",
            source: "en",
            locales: { ru: { "listing.name": "0".repeat(12), "listing.description": "0".repeat(12) } },
          }), "utf8"),
        },
      ],
    })],
    root: registryWith({}),
  });
  assert(!r.blocked, `a stale translation must not refuse a release: ${JSON.stringify(errorCodes(r))}`);
  assert(codes(r).includes("W_LOCALE_STALE"), JSON.stringify(codes(r)));
  assertEqual(r.derived.plugin.i18n, undefined,
    "both strings demote to English, which leaves a block identical to the English card, which is not emitted");
});

await test("…and a lock that matches today's English is not stale", async () => {
  const digest = (s) => crypto.createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex").slice(0, 12);
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", EN_CARD),
        locale("ru", RU_CARD),
        {
          name: "locales.lock.json",
          data: Buffer.from(JSON.stringify({
            schema: "astra.plugin.locales/1",
            source: "en",
            locales: {
              ru: {
                "listing.name": digest(EN_CARD["listing.name"]),
                "listing.description": digest(EN_CARD["listing.description"]),
              },
            },
          }), "utf8"),
        },
      ],
    })],
    root: registryWith({}),
  });
  assert(!codes(r).includes("W_LOCALE_STALE"),
    `the digests agree, so nothing is stale: ${JSON.stringify(codes(r))}`);
  assertEqual(r.derived.plugin.i18n.ru.name, "Бросок костей", "a fresh translation must survive");
});

await test("E_LOCALE_CARD_TOO_LONG — a name past the card's width, in one language", async () => {
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", EN_CARD),
        locale("ru", { "listing.name": "Б".repeat(70), "listing.description": "Бросает кости." }),
      ],
    })],
  });
  assertBlockedWith(r, "E_LOCALE_CARD_TOO_LONG");
});

await test("E_LOCALE_TOO_LARGE — refused before the parse, not after it", async () => {
  // inspectBundle materialises every listed file as a Buffer bounded only by
  // max_extract_bytes (500 MB). Icons are capped at 128 KiB and READMEs at
  // 16 KiB; locale files were capped by nothing, and a flat-but-valid 200 MB
  // en.json would take the ingest runner out mid-derivation and leave the
  // submitter's issue with no verdict at all.
  const fat = {};
  for (let i = 0; i < 400; i++) fat[`k${i}`] = "x".repeat(1024);
  const r = await run({
    assets: [conformingAsset({ extraFiles: [locale("en", { ...EN_CARD, ...fat })] })],
  });
  assertBlockedWith(r, "E_LOCALE_TOO_LARGE");
});

await test("E_LOCALE_BUNDLE_MISMATCH — one release, two platforms, two different cards", async () => {
  // `deriveListing` is handed the FIRST bundle's files, with a comment saying
  // the icon and the README are one picture across platforms. True for those.
  // False for locale files, which reach the installed plugin per platform.
  const r = await run({
    assets: [
      {
        name: "dice-roller-0.2.0-linux-x64.astraplugin",
        bytes: makeBundle({ os: "linux", extraFiles: [locale("en", EN_CARD), locale("ru", RU_CARD)] }),
      },
      {
        name: "dice-roller-0.2.0-windows-x64.astraplugin",
        bytes: makeBundle({
          os: "windows",
          extraFiles: [locale("en", EN_CARD), locale("ru", { ...RU_CARD, "listing.name": "Другое имя" })],
        }),
      },
    ],
    root: registryWith({}),
  });
  assertBlockedWith(r, "E_LOCALE_BUNDLE_MISMATCH");
});

await test("a plugin that ships no locales/ is not asked about any of this", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({}) });
  assert(!codes(r).some((c) => c.startsWith("E_LOCALE") || c.startsWith("W_LOCALE")),
    `the overwhelming majority of bundles, for ever: ${JSON.stringify(codes(r))}`);
});

await test("E_LOCALE_CARD_TOO_LARGE and the exemption note, at the unit they are decided in", async () => {
  // Two codes with no end-to-end fixture, and they are here rather than absent.
  // The budget needs nine locales of maximum-length CJK, which is a bundle
  // fixture testing arithmetic and nothing else; the exemption needs an entry in
  // the real policy/listing-language-exemptions.json, and a test that edits the
  // shipped policy file in order to prove the shipped policy file is read is a
  // test that can pass for the wrong reason.
  const limits = loadPolicy(REPO_ROOT).limits;
  const files = [{ name: "locales/en.json", bytes: Buffer.from(JSON.stringify(EN_CARD), "utf8") }];
  for (const code of ["ru", "uk", "de", "fr", "es", "pt", "ja", "zh", "ko"]) {
    files.push({
      name: `locales/${code}.json`,
      bytes: Buffer.from(JSON.stringify({
        "listing.name": "名".repeat(64),
        "listing.description": "説".repeat(200),
      }), "utf8"),
    });
  }
  const codesOf = (x) => x.findings.map((i) => i.code);
  const facts = { name: "Dice Roller", description: "Rolls dice when you ask it to." };

  // The rule, at a budget low enough to reach: the number is policy and the
  // mechanism is what this asserts.
  const over = deriveLocaleText({ files, facts, limits: { ...limits, max_listing_i18n_bytes: 512 }, summarise });
  assert(codesOf(over).includes("E_LOCALE_CARD_TOO_LARGE"),
    `the per-listing budget did not fire: ${JSON.stringify(codesOf(over))}`);
  assertEqual(over.i18n, undefined, "and nothing is emitted, rather than the budget being advisory");
  for (const i of over.findings) emitted.add(i.code);

  // And the shipped number, from the other side. **This is the assertion that
  // matters more**, because the way this ceiling goes wrong is not that it
  // fails to fire — it is that somebody lowers it and every honest CJK listing
  // starts losing its translations with a message about a budget. Nine locales
  // at the schema's own caps, in three-byte characters, is the worst case a
  // listing can legitimately reach.
  const worst = deriveLocaleText({ files, facts, limits, summarise });
  assert(!codesOf(worst).includes("E_LOCALE_CARD_TOO_LARGE"),
    "nine locales at 64 + 200 characters each satisfies every per-string cap and must not be refused by the total: " +
    `${Buffer.byteLength(JSON.stringify(worst.i18n ?? {}), "utf8")} bytes against a ceiling of ${limits.max_listing_i18n_bytes}`);
  assertEqual(Object.keys(worst.i18n ?? {}).length, 9, "the worst case must actually have been built");

  const exempt = deriveLocaleText({
    files: [],
    facts: { name: "Шахматы", description: "Шахматы против локального бота." },
    limits,
    summarise,
    languageExempt: true,
  });
  assert(!codesOf(exempt).includes("E_LISTING_NOT_ENGLISH"), "an exemption must actually excuse the rule");
  assert(codesOf(exempt).includes("N_LISTING_LANGUAGE_EXEMPT"),
    `and must say so rather than passing quietly: ${JSON.stringify(codesOf(exempt))}`);
  for (const i of exempt.findings) emitted.add(i.code);
});

// ═══════════════════════════════════════════════════════════════════════════

section("the ingest path, against somebody who is not an author");

// Everything in this section is reachable by anyone who can open a listing
// issue. None of it needs an attestation, an approved workflow or an ownership
// proof — the bundle is opened at step 6 and these are properties of what is
// inside it — so the input is a stranger's and the cost of getting it wrong is
// not the submission's, it is the registry's.

await test("localeSignature caps a locale file BEFORE parsing it, and refuses to run uncapped", () => {
  // The cap ran in `deriveLocaleText`, at step 11. `localeSignature` ran at
  // step 7 and called `readLocales(files)` with no limits at all, which
  // defaults maxBytes to Infinity — so the real order of operations was parse
  // first, refuse afterwards. Measured on this fixture before the fix: 517 ms,
  // +131 MiB heap, 474 MiB RSS for a file the cap exists to refuse in 0 ms,
  // and `max_artifacts_per_version` is 8.
  const limits = loadPolicy(REPO_ROOT).limits;
  const big = {};
  // Comfortably over max_locale_bytes (262,144) and flat, valid JSON: nothing
  // about it is malformed, which is the point — a parser error would have
  // stopped it.
  for (let i = 0; i < 20000; i++) big[`k.${i}`] = "x".repeat(40);
  // A reserved key with a distinctive value, so the signature SAYS whether the
  // file was parsed. Without it the signature of a parsed-but-cardless file is
  // `[["en",null,null]]`, which is indistinguishable from a refused one — an
  // assertion that cannot tell the two apart is how `readLocales(files, {})`
  // survived a mutation.
  big["listing.name"] = "PARSED-DESPITE-THE-CAP";
  const bytes = Buffer.from(JSON.stringify(big), "utf8");
  assert(bytes.length > limits.max_locale_bytes,
    `the fixture must be over the cap, or this proves nothing: ${bytes.length} vs ${limits.max_locale_bytes}`);
  const files = [{ name: "locales/en.json", bytes }];

  const sig = localeSignature(files, limits);
  assert(!sig.includes("PARSED-DESPITE-THE-CAP"),
    `the file was parsed despite being over the cap: ${sig.slice(0, 200)}`);
  // Not vacuous: the same bytes under an uncapped read DO show the value, so
  // the assertion above is measuring the cap and not the fixture.
  assert(JSON.stringify(readLocales(files, {}).files).includes("PARSED-DESPITE-THE-CAP"),
    "the fixture does not carry a value the signature would show, so the assertion above proves nothing");

  // An absent `limits` is a throw rather than Infinity. A default of {} would
  // put the hole straight back the next time somebody adds a call site.
  let threw = null;
  try { localeSignature(files); } catch (e) { threw = e; }
  assert(threw !== null, "localeSignature(files) with no limits must refuse, not default to Infinity");
  assert(/limits/.test(threw.message), `and must say what is missing: ${threw.message}`);

  // A refused file is still a language this bundle ships. Dropping it silently
  // would make a bundle carrying a 300 KiB ru.json compare equal to one
  // carrying no ru.json at all, and E_LOCALE_BUNDLE_MISMATCH would not fire.
  const withOversize = localeSignature([{ name: "locales/ru.json", bytes }], limits);
  const without = localeSignature([], limits);
  assert(withOversize !== without,
    "an oversize locale file must still show in the signature, or the bundles-agree check cannot see it");
});

await test("E_BUNDLE_CONTROL_CHARACTER — an entry name that forges rows in the maintainer's report", async () => {
  // `renderComment` escaped the message column and interpolated `${i.where}`
  // raw. For a locale finding `where` is `locales/${code}.json`, and `code`
  // comes out of /^locales\/([^/]+)\.json$/ — where `[^/]` matches newlines and
  // pipes. A real .astraplugin built with the entry name below returned ZERO
  // errors from `inspectBundle`, and the report rendered two forged
  // four-column rows with green ticks above the real finding, in the one
  // document a human reads before typing `/approve`.
  const forged =
    "locales/ru" + FORGED_ROWS + "x.json";
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [{ name: forged, data: Buffer.from(JSON.stringify({ "listing.name": "X" })), mode: 0o644 }],
    })],
  });
  assertBlockedWith(r, "E_BUNDLE_CONTROL_CHARACTER");

  // And the report is sound even so, because the escaping is the half that
  // does not depend on anybody having thought of this shape. Two defences on
  // purpose: one refuses the name, the other makes the name harmless.
  const rows = r.comment.split("\n").filter((l) => l.startsWith("|"));
  const bad = rows.filter((l) => /`(E_OWNERSHIP_PROVEN|R_FIRST_LISTING)`\s*\|/.test(l));
  assertEqual(bad.length, 0, `forged rows rendered as real ones:\n${bad.join("\n")}`);
  // The property, not the instance: a table row is four columns and five
  // unescaped pipes, whatever a stranger put in any of them.
  for (const row of rows) {
    assertEqual((row.match(/(?<!\\)\|/g) ?? []).length, 5,
      `a stranger's bytes changed the shape of the table:\n${row}`);
  }
});

await test("renderComment escapes every column, not only the message", () => {
  // The asymmetry WAS the bug: the same bytes came out escaped in `detail` and
  // raw in `where`. This asserts the property rather than the instance, so a
  // future column added without `cell()` is a failure here.
  const f = {
    items: [{ level: "error", code: "E_LOCALE_UNKNOWN_CODE", where: "locales/a|b" + FORGED_ROWS, message: "m" }],
    errors: [{}], reviews: [],
  };
  const body = renderComment(f, null, { repo: "o/r", tag: "v1" });
  const rows = body.split("\n").filter((l) => l.startsWith("|"));
  for (const row of rows) {
    assertEqual((row.match(/(?<!\\)\|/g) ?? []).length, 5,
      `every rendered row must have exactly five unescaped pipes (four columns):\n${row}`);
  }

  // Pipes and newlines are the injection; the invisible characters are the
  // other half, and they need their own assertion because escaping the first
  // two does nothing about them. A right-to-left override in an entry name
  // makes the rendered row read as a row it does not contain — the same trick
  // `unsafeDisplayText` refuses in a plugin's metadata, arriving through a
  // column nothing checked.
  const tricky = {
    items: [{ level: "error", code: "E_LOCALE_UNKNOWN_CODE", where: "locales/\u202egnp.exe", message: "m\u0007\ufeff" }],
    errors: [{}], reviews: [],
  };
  const shady = renderComment(tricky, null, { repo: "o/r", tag: "v1" });
  for (const ch of ["\u202e", "\u0007", "\ufeff"]) {
    assert(!shady.includes(ch),
      `${JSON.stringify(ch)} reached the report a maintainer reads before typing /approve`);
  }
});

await test("the report stays inside GitHub's 65,536-character cap however many findings there are", async () => {
  // Driven through the real `deriveLocaleText` and the real `renderComment`.
  // Before this was bounded: 100 bogus locale files rendered 41,701 bytes, 200
  // rendered 82,102 — over the cap — and 1,000 rendered 405,304. The count is
  // bounded only by max_archive_entries, which is 10,000. A submission that
  // produced enough findings took the bot's only channel away, and
  // `ingest.yml`'s comment loop had no try/catch, so the other submissions in
  // the same run lost their reports too.
  const limits = loadPolicy(REPO_ROOT).limits;
  for (const n of [10, 200, 2000]) {
    const files = [];
    for (let i = 0; i < n; i++) {
      files.push({
        name: `locales/xx${i}.json`,
        bytes: Buffer.from(JSON.stringify({ "listing.name": "N", "listing.description": "D" })),
      });
    }
    const { findings } = deriveLocaleText({
      files, facts: { name: "Demo", description: "A demo plugin" }, limits, summarise,
    });
    const f = { items: findings, errors: findings.filter((i) => i.level === "error"), reviews: [] };
    const body = renderComment(f, null, { repo: "o/r", tag: "v1.0.0" });
    assert(body.length <= GITHUB_COMMENT_MAX,
      `${n} bogus locale files rendered ${body.length} characters, over GitHub's ${GITHUB_COMMENT_MAX}`);
    // Bounded, and still honest about it: a reader must be able to tell a
    // complete report from a collapsed one.
    if (n > 10) {
      assert(/more file\(s\) with the same problem|more finding\(s\)|Cut to fit|cut, /.test(body),
        `${n} files collapsed silently — a report that hides its own truncation is worse than a long one`);
    }
  }
});

await test("renderComment bounds a report the locale rules did not produce", () => {
  // The per-code collapse in `bot/lib/locales.mjs` handles the locale rules,
  // which is why the test above cannot reach these two bounds — and a bound
  // nothing reaches is a bound nobody has watched. `renderComment` is what
  // stands behind EVERY other check in the pipeline, several of which emit one
  // finding per file with no collapse of their own.
  //
  // THREE bounds, and they are not redundant: the row cap bounds the count, the
  // cell cap bounds the width, and only measuring the finished document bounds
  // the thing GitHub actually refuses. The fixture is deliberately wide as well
  // as long, because the row cap on its own is not enough — fifty rows at the
  // cell cap is over a hundred thousand characters, so a report can clear the
  // first two bounds and still not post.
  // One finding is enough on its own: an entry name is bounded by the archive
  // format at 64 KiB, and both `where` and several messages interpolate one.
  const huge = {
    items: [{ level: "error", code: "E_LOCALE_UNKNOWN_CODE", where: `locales/${"a".repeat(60000)}.json`, message: "b".repeat(60000) }],
    errors: [{}], reviews: [],
  };
  // The cell cap is 2,000 characters and a row holds four cells plus its
  // furniture. Anything near that is cut; anything far past it is not.
  const MAX_CELL_ALLOWANCE = 6000;

  const many = { items: [], errors: [{}], reviews: [] };
  for (let i = 0; i < 4000; i++) {
    many.items.push({ level: "error", code: "E_ASSET_FILENAME", where: `asset-${i}`, message: "x".repeat(3000) });
  }
  const capped = renderComment(many, null, { repo: "o/r", tag: "v1" });
  assert(capped.length <= GITHUB_COMMENT_MAX,
    `4,000 wide findings rendered ${capped.length} characters, over GitHub's ${GITHUB_COMMENT_MAX}`);
  assert(/more finding\(s\)/.test(capped),
    "the rows were dropped without the report saying how many, which is a partial answer dressed as a whole one");
  assert(!/cut to fit/i.test(capped),
    "the table budget is what should have bounded this, and it must leave the `and N more` line and " +
    "the `What to do` section standing rather than letting the final cut take them off the end");

  // The three bounds own three different properties, and a report can satisfy
  // one while failing another. Stated separately so each is a witness for its
  // own bound rather than all three resting on the byte count.
  //
  // The ROW cap owns "few enough rows to read". A budget alone would let four
  // thousand narrow findings render five hundred rows and still fit.
  const narrow = { items: [], errors: [{}], reviews: [] };
  for (let i = 0; i < 4000; i++) {
    narrow.items.push({ level: "error", code: "E_ASSET_FILENAME", where: `a${i}`, message: "short" });
  }
  const rows = renderComment(narrow, null, { repo: "o/r", tag: "v1" })
    .split("\n").filter((l) => l.startsWith("|"));
  assert(rows.length <= 55,
    `${rows.length} rows rendered — a report nobody scrolls to the end of is a report nobody reads`);

  // The CELL cap owns "no row is wider than a screen". The bounds after it
  // would keep the DOCUMENT small by cutting it short instead, which loses the
  // report rather than narrowing it.
  const widest = Math.max(...renderComment(huge, null, { repo: "o/r", tag: "v1" })
    .split("\n").filter((l) => l.startsWith("|")).map((l) => l.length));
  assert(widest < MAX_CELL_ALLOWANCE,
    `one row is ${widest} characters wide; a 64 KiB entry name must be cut in its cell, not left to ` +
    "push the rest of the report over the edge");

  // And the section NOTHING above bounds: "What to do" prints one paragraph per
  // distinct actionable code, out of `bot/lib/codes.mjs`. The table budget has
  // no say over it, so a report carrying enough distinct codes clears every
  // bound above and still cannot post. This is the case the final cut exists
  // for, and it is why a row cap and a cell cap are two estimates rather than a
  // guarantee.
  const wide = { items: [], errors: [{}], reviews: [] };
  for (const code of Object.keys(CODES)) {
    wide.items.push({ level: "error", code, where: "everywhere", message: "y".repeat(3000) });
  }
  const forced = renderComment(wide, null, { repo: "o/r", tag: "v1" });
  assert(forced.length <= GITHUB_COMMENT_MAX,
    `${Object.keys(CODES).length} distinct codes rendered ${forced.length} characters, over GitHub's ${GITHUB_COMMENT_MAX}`);
  assert(/cut to fit/i.test(forced),
    "the report was cut and did not say so, which is the one thing a truncated verdict must never do");

  const cut = renderComment(huge, null, { repo: "o/r", tag: "v1" });
  assert(cut.length <= GITHUB_COMMENT_MAX,
    `one hostile entry name rendered ${cut.length} characters, over GitHub's ${GITHUB_COMMENT_MAX}`);
  assert(/cut, \d+ characters|cut to fit/i.test(cut), "a cut cell must say it was cut");
});

await test("a hostile file count collapses per rule, and an honest ten-locale bundle does not", () => {
  const limits = loadPolicy(REPO_ROOT).limits;
  const mk = (n) => {
    const files = [];
    for (let i = 0; i < n; i++) {
      files.push({ name: `locales/xx${i}.json`, bytes: Buffer.from(JSON.stringify({ "listing.name": "N" })) });
    }
    return deriveLocaleText({ files, facts: { name: "Demo", description: "A demo" }, limits, summarise }).findings;
  };
  const many = mk(500);
  assert(many.length < 20, `500 files produced ${many.length} findings; the collapse did not run`);
  const collapsed = many.filter((i) => /more file\(s\) with the same problem/.test(i.message));
  assert(collapsed.length > 0, "the collapse must leave a finding saying how many were held back");
  assertEqual(collapsed[0].level, "error",
    "a collapsed error is still an error — bounding the report must not unblock the release");

  // The honest case loses nothing. Ten is every locale Astra has, so no author
  // ever meets the bound; only a stranger who wrote 10,000 files does.
  const files = LOCALE_CODES.filter((c) => c !== "en").map((c) => ({
    name: `locales/${c}.json`,
    bytes: Buffer.from(JSON.stringify({ "listing.name": "N", "unknown.key": "x" })),
  }));
  files.push({ name: "locales/en.json", bytes: Buffer.from(JSON.stringify({ "listing.name": "Demo" })) });
  const honest = deriveLocaleText({
    files, facts: { name: "Demo", description: "A demo" }, limits, summarise,
  }).findings;
  assert(!honest.some((i) => /more file\(s\) with the same problem/.test(i.message)),
    `a nine-locale bundle must be reported in full, one file at a time: ${JSON.stringify(honest.map((i) => i.where))}`);
});

await test("E_METADATA_UNSAFE_TEXT — a bidi override in a TRANSLATED card name", async () => {
  // The rule has run on every translated `listing.name` since the locale work
  // landed and nothing anywhere proved it fires. The two tests that named this
  // code were both about the English metadata, through `checkMetadata`; the
  // corpus's 104 fixture files carry no invisible character at all; and the
  // code appeared in neither CORPUS_RULE_IDS nor CORPUS_NOT_IMPLEMENTED, so
  // `corpusIds` would have THROWN at whoever wrote the first fixture for it.
  // `CORPUS_NO_RULE_ID` is the written-down reason there is no fixture, and
  // this is the witness that reason costs nothing.
  const RLO = "\u202e";
  const r = await run({
    assets: [conformingAsset({
      extraFiles: [
        locale("en", EN_CARD),
        locale("ru", { ...RU_CARD, "listing.name": `${RLO}Dice Roller` }),
      ],
    })],
  });
  assertBlockedWith(r, "E_METADATA_UNSAFE_TEXT");
  assertEqual(r.findings.find((i) => i.code === "E_METADATA_UNSAFE_TEXT").where, "locales/ru.json",
    "the finding must name the file the author has to open, not the stage it was found in");
  // And it is not merely refused: nothing invisible reaches a card.
  assert(!JSON.stringify(r.derived?.plugin?.i18n ?? {}).includes("\\u202e"),
    "the override reached the derived listing anyway");
});

await test("the trademark rule reaches ja, zh and ko — it used to collapse to exact equality there", () => {
  // `leadingToken` splits a display name on " ". Japanese, Chinese and Korean
  // do not write one, so for three of the ten languages this feature exists to
  // serve, "the first word" was the whole name and the rule became equality
  // with a mark. Driven against the real bot/policy/trademarks.json before the
  // fix: `Telegram Official` (en) and `Telegram Offiziell` (de) were refused,
  // and every row below produced NOTHING AT ALL while a bare `Telegram` in the
  // same file was refused.
  //
  // These are this repository's witnesses for the rule. They are here and not
  // in AstraPlugins/testdata/locales because the trademark rule is not a corpus
  // rule — `astra-plugin check` has no marks list and never will, since the
  // catalogue is the only place the question "is this name already somebody
  // else's" can be asked at all.
  const tm = loadTrademarks();
  const claim = (locale, name) =>
    checkDisplayName({ id: "media-tools", name, repoOwner: "a-stranger", locale }, [], { trademarks: tm })
      .map((o) => o.code);

  const impersonation = [
    ["ja", "Telegram公式"], ["zh", "Telegram官方版"], ["ja", "Spotify公式クライアント"],
    ["ja", "Astra公式"], ["ja", "Astra公式プラグイン"], ["ko", "Telegram공식"],
    ["ja", "Telegram用クライアント"], ["en", "Telegram Official"], ["de", "Telegram Offiziell"],
  ];
  for (const [locale, name] of impersonation) {
    assert(claim(locale, name).includes("E_TRADEMARK"),
      `${locale} ${JSON.stringify(name)} leads with somebody else's mark and was not refused: ${claim(locale, name)}`);
  }

  // The narrowness the rule has always had, kept. `Astral Projection`
  // skeletonises to `astraiprojection`, which begins with the mark `astra` — a
  // bare prefix test would refuse it. The character after the prefix is what
  // separates a name that LEADS with a mark from one that merely starts with
  // the same letters.
  const honest = [
    ["en", "Astral Projection"], ["en", "Music controls for Spotify"], ["en", "Notes for Notion"],
    ["ja", "チェス 対局"], ["zh", "国际象棋"], ["ko", "체스 게임"],
    ["ja", "Chess 日本語版"], ["zh", "Chess 中文版"], ["ru", "Клиент Telegram"],
  ];
  for (const [locale, name] of honest) {
    assertEqual(claim(locale, name).join(","), "",
      `${locale} ${JSON.stringify(name)} is an honest name and must produce nothing`);
  }

  // The floor: if the marks list ever empties, every assertion above passes for
  // the wrong reason and this is the only thing that notices.
  assert(tm.marks.length >= 40, `the marks list holds ${tm.marks.length} entries; this scan needs a real one`);
});

await test("scriptsUsed knows the CJK scripts, so a name mixing them with another alphabet is visible", () => {
  // `scriptOf` knew Latin, Cyrillic and Greek. Han, kana and Hangul were
  // indistinguishable from punctuation, so `scriptsUsed("Telegram公式")`
  // returned ["Latin"] — one script, no mixture, nothing to report — and
  // R_DISPLAY_NAME_MIXED_SCRIPT could never fire on a CJK card whatever was
  // hidden in it. A true answer about a smaller world than the name claims.
  assertEqual(scriptsUsed("Telegram公式").join(","), "Han,Latin", "Han was invisible");
  assertEqual(scriptsUsed("Telegram공식").join(","), "Hangul,Latin", "Hangul was invisible");
  assertEqual(scriptsUsed("チェス").join(","), "Katakana", "katakana alone is one script and ordinary");

  const tm = loadTrademarks();
  const at = (locale, name) =>
    checkDisplayName({ id: "x", name, repoOwner: "s", locale }, [], { trademarks: tm }).map((o) => o.code);

  // The finding this buys: a Cyrillic letter dropped into a Han name. Before,
  // that string reported ["Cyrillic"] — one script — and said nothing.
  assert(at("ja", "игра公式").includes("R_DISPLAY_NAME_MIXED_SCRIPT"),
    "a Cyrillic letter among Han characters must be visible");

  // And what it must NOT buy: a Japanese name is ordinarily Han, kana and
  // Latin all at once. Flagging those would put every honest CJK listing in a
  // review queue, which ends with the rule switched off within a week.
  for (const [locale, name] of [["ja", "Chess 日本語版"], ["ja", "アストラ Chess"], ["zh", "Chess 中文版"], ["ko", "Chess 한국어"]]) {
    assertEqual(at(locale, name).join(","), "",
      `${locale} ${JSON.stringify(name)} is what an ordinary name in that language looks like`);
  }
});

// ═══════════════════════════════════════════════════════════════════════════

section("versions and identity");

await test("E_VERSION_NOT_NEW — republishing a version that is already listed", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({ version: "0.2.0" }) });
  assertBlockedWith(r, "E_VERSION_NOT_NEW");
});

await test("E_VERSION_NOT_NEW — a release that goes backwards", async () => {
  const r = await run({ assets: [conformingAsset({ version: "0.1.5" })], root: registryWith({ version: "0.3.0" }) });
  assertBlockedWith(r, "E_VERSION_NOT_NEW");
});

await test("E_VERSION_INCONSISTENT — one release, two versions", async () => {
  const r = await run({
    assets: [
      { name: "dice-roller-0.2.0-linux-x64.astraplugin", bytes: makeBundle({ os: "linux", version: "0.2.0" }) },
      { name: "dice-roller-0.2.1-windows-x64.astraplugin", bytes: makeBundle({ os: "windows", version: "0.2.1" }) },
    ],
    root: registryWith({}),
  });
  assertBlockedWith(r, "E_VERSION_INCONSISTENT");
});

await test("E_MANIFEST_ID_MISMATCH — one release carrying two different plugins", async () => {
  const r = await run({
    assets: [
      { name: "dice-roller-0.2.0-linux-x64.astraplugin", bytes: makeBundle({ os: "linux" }) },
      { name: "other-thing-0.2.0-windows-x64.astraplugin", bytes: makeBundle({ os: "windows", id: "other-thing", name: "Other Thing" }) },
    ],
    root: registryWith({}),
  });
  assertBlockedWith(r, "E_MANIFEST_ID_MISMATCH");
});

await test("R_IDENTITY_CHANGED — the same plugin from a different repository", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({ repo: "someone-else/dice-roller" }) });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assert(codes(r).includes("R_IDENTITY_CHANGED"), JSON.stringify(codes(r)));
});

await test("ID-74 — an id belongs to the first release that published under it", async () => {
  // Checked rather than quoted. B-T3.3a says "the bot already works this way
  // at the pin" and cites two line ranges; this is that claim as a test, so
  // the service path cannot grow a second answer to it.
  //
  // Nothing held before the first publication counts — no reservation, no
  // binding token, no pending submission — and afterwards a release of the
  // same id from another repository is compared with the listing that exists
  // rather than being offered the first-listing path.
  const first = await run({ assets: [conformingAsset()], root: registryWith({ id: "something-else" }) });
  assert(codes(first).includes("R_FIRST_LISTING"),
    `an id nobody has listed is a first listing: ${JSON.stringify(codes(first))}`);

  const second = await run({
    assets: [conformingAsset()],
    root: registryWith({ repo: "the-first-publisher/dice-roller" }),
  });
  assert(codes(second).includes("R_IDENTITY_CHANGED"), JSON.stringify(codes(second)));
  assert(!codes(second).includes("R_FIRST_LISTING"),
    "the second repository is never offered the first-listing path, which is what ID-74 forbids");
});

section("the host-RPC heuristic");

await test("E_HOST_RPC_UNDECLARED — author source calling one of the four", async () => {
  const r = await run({
    assets: [conformingAsset({
      capabilities: ["tools"],
      extraFiles: [{ name: "handler.py", data: "def go(host):\n    host.FireTrigger('x')\n" }],
    })],
    root: registryWith({}),
  });
  assertBlockedWith(r, "E_HOST_RPC_UNDECLARED");
});

await test("…and declaring the capability makes it legitimate", async () => {
  const r = await run({
    assets: [conformingAsset({
      capabilities: ["tools", "triggers"],
      extraFiles: [{ name: "handler.py", data: "def go(host):\n    host.FireTrigger('x')\n" }],
    })],
    root: registryWith({}),
  });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
});

await test("W_HOST_RPC_UNDECLARED — the rest warn instead of blocking", async () => {
  const r = await run({
    assets: [conformingAsset({
      capabilities: ["tools"],
      extraFiles: [{ name: "handler.py", data: "host.PushToUi({})\n" }],
    })],
    root: registryWith({}),
  });
  assert(!r.blocked, JSON.stringify(errorCodes(r)));
  assert(codes(r).includes("W_HOST_RPC_UNDECLARED"), JSON.stringify(codes(r)));
});

await test("a vendored SDK stub is not evidence of anything", () => {
  const findings = scanHostRpcs(
    [{ name: "site-packages/astra_plugin_sdk/plugin_pb2.py", bytes: Buffer.from("FireTrigger SetVariable SendChatMessage") }],
    { capabilities: ["tools"], permissions: {} },
  );
  assert(!findings.some((i) => i.level === "error"),
    `the Python SDK's descriptor names every method of every service: ${JSON.stringify(findings)}`);
  for (const i of findings) emitted.add(i.code);
});

await test("a compiled file is reported, never held against the author", () => {
  const findings = scanHostRpcs(
    [{ name: "bin/plugin", bytes: Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from("FireTrigger")]) }],
    { capabilities: ["tools"], permissions: {} },
  );
  assert(findings.some((i) => i.code === "W_HOST_RPC_IN_OPAQUE_FILE"), JSON.stringify(findings));
  assert(!findings.some((i) => i.level === "error"), "a linked client carries every method name");
  for (const i of findings) emitted.add(i.code);
});

await test("the scan's scope is printed on every run, passing or not", () => {
  const findings = scanHostRpcs([], { capabilities: [], permissions: {} });
  assert(findings.some((i) => i.code === "N_HOST_RPC_SCAN_SCOPE"),
    "a checklist that shows only what passed reads as a clean bill of health");
});

await test("classifyFile puts each kind of file in the right bucket", () => {
  assertEqual(classifyFile("src/index.js", Buffer.from("x")), "source", "author source");
  assertEqual(classifyFile("node_modules/x/index.js", Buffer.from("x")), "vendored", "somebody else's source");
  assertEqual(classifyFile("bin/plugin", Buffer.from([0, 1, 2])), "opaque", "a compiled file");
  assertEqual(classifyFile("LICENSE", Buffer.from("MIT")), "source", "text with no extension is still text");
  assertEqual(classifyFile("generated/evil.py", Buffer.from("x")), "weak-vendor",
    "a directory name the bundle author chose is not evidence of a toolchain");
  assertEqual(classifyFile("vendor/evil.py", Buffer.from("x")), "weak-vendor", "same");
});

await test("renaming a directory does not turn the scan off", () => {
  // The hole: `generated/` and `vendor/` were silent skips, and both are
  // directory names the bundle author picks. The identical file produced
  // E_HOST_RPC_UNDECLARED at `src/evil.py` and NOTHING at `generated/evil.py`,
  // where it published unattended — and the note row reported it as somebody
  // else's code.
  const evil = Buffer.from("host.SendChatMessage(x)\nhost.SetThemeContribution(y)\n");
  const declared = { capabilities: [], permissions: {} };

  const inSrc = scanHostRpcs([{ name: "src/evil.py", bytes: evil }], declared);
  assert(inSrc.some((i) => i.code === "E_HOST_RPC_UNDECLARED"), JSON.stringify(inSrc));

  for (const dir of ["generated", "vendor"]) {
    const found = scanHostRpcs([{ name: `${dir}/evil.py`, bytes: evil }], declared);
    for (const i of found) emitted.add(i.code);
    assert(found.some((i) => i.code === "R_HOST_RPC_IN_VENDOR_DIR"),
      `${dir}/ must still be searched: ${JSON.stringify(found)}`);
    // `review` and not `warn`: policy.mjs holds on review and publishes through
    // everything softer, so a warn would leave the bypass in place.
    assert(found.some((i) => i.level === "review"), JSON.stringify(found));
    const note = found.find((i) => i.code === "N_HOST_RPC_SCAN_SCOPE");
    assert(!note.message.includes("skipped:"), `nothing was skipped: ${note.message}`);
  }
});

await test("node_modules is believed only when the bundle corroborates it", () => {
  const evil = Buffer.from("host.FireTrigger('x')\n");
  const declared = { capabilities: [], permissions: {} };

  // A lone `node_modules/` with no package metadata anywhere: the author's own
  // code under somebody else's directory name.
  const bare = scanHostRpcs([{ name: "node_modules/evil/index.js", bytes: evil }], declared);
  assert(bare.some((i) => i.code === "E_HOST_RPC_UNDECLARED"), JSON.stringify(bare));

  // The same file beside a `package.json`, which is what a package manager
  // actually writes.
  const real = scanHostRpcs([
    { name: "node_modules/evil/package.json", bytes: Buffer.from("{}") },
    { name: "node_modules/evil/index.js", bytes: evil },
  ], declared);
  assert(!real.some((i) => i.level === "error"), JSON.stringify(real));
});

await test("N_HOST_RPC_SCAN_SCOPE names what it skipped, it does not just count it", () => {
  const found = scanHostRpcs([
    { name: "site-packages/sdk/plugin_pb2.py", bytes: Buffer.from("FireTrigger") },
    { name: "src/main.py", bytes: Buffer.from("print(1)") },
  ], { capabilities: ["tools"], permissions: {} });
  const note = found.find((i) => i.code === "N_HOST_RPC_SCAN_SCOPE");
  assert(note.message.includes("site-packages/sdk/plugin_pb2.py"),
    `a count reads as somebody else's code whatever the files are: ${note.message}`);
});

await test("[permissions] satisfies the scan too, so Phase 4 does not break this check", () => {
  const findings = scanHostRpcs(
    [{ name: "handler.py", bytes: Buffer.from("host.FireTrigger()") }],
    { capabilities: [], permissions: { fire_trigger: { reason: "…" } } },
  );
  assert(!findings.some((i) => i.level === "error"), JSON.stringify(findings));
});

await test("[capabilities] actions does not buy SetVariable; only [permissions] set_variable does", () => {
  // Decided 2026-09-23 (astra-plugins-ops couplings entry 32). Until then
  // `actions` was accepted in place of the permission, so a plugin declaring
  // only the capability scanned clean here and — hooks.yaml gating SetVariable
  // on `set_variable` and no capability, `[permissions]` being default-deny —
  // was refused the call on the user's machine.
  const src = [{ name: "handler.py", bytes: Buffer.from("host.SetVariable('k', 'v')") }];
  const legacy = scanHostRpcs(src, { capabilities: ["actions"], permissions: {} });
  const e = legacy.find((i) => i.code === "E_HOST_RPC_UNDECLARED" && i.message.includes("`SetVariable`"));
  assert(e, `an actions-only manifest calling SetVariable must be an error: ${JSON.stringify(legacy)}`);
  assert(e.message.includes("[permissions] set_variable") && !e.message.includes("[capabilities]"),
    `the remedy must not offer an arm the daemon does not honour: ${e.message}`);
  const declared = scanHostRpcs(src, { capabilities: [], permissions: { set_variable: { reason: "…" } } });
  assert(!declared.some((i) => i.level === "error"), JSON.stringify(declared));
});

section("ownership, in detail");

// The world every one of these is about, observed in a real Actions run on
// 2026-08-14 against `astra-registry#13` and `#14`: every cryptographic check
// passed and the submission was refused on ownership alone, because the fast
// path answered 403 (the bot's token belongs to `astra-registry`, and GitHub
// will not disclose a third party's collaborators to it) and the release had
// been published by `@github-actions[bot]`, which is what the documented
// `plugin-release.yml` does. Neither arm can fire for an honest first
// submission, so the file has to be the thing an author is asked for — and the
// refusal has to lead with it.

const RECENT_RELEASE = new Date(Date.now() - 3 * 86_400_000).toISOString();

/** A world where the bot can see nothing and the file does not exist. */
const blind = async (url) => ({ ok: false, status: url.includes("/collaborators/") ? 403 : 404 });

await test("a 403 from the fast path is not a refusal by itself", async () => {
  // The whole defect, in one assertion: 403 means "the bot cannot see", and the
  // run has to carry on to the proof the author was actually asked for.
  const out = await proveOwnership({
    repo: "org/thing", login: "someone", releaseAuthor: null, token: null,
    fetchImpl: async (url) =>
      url.includes("/collaborators/")
        ? { ok: false, status: 403 }
        : { ok: true, status: 200, text: async () => "someone\n" },
  });
  assert(out.ok, `a 403 must not decide anything: ${JSON.stringify(out)}`);
  assertEqual(out.method, "well-known", JSON.stringify(out.tried));
});

await test("a 403 is never reported to the author as a finding against them", async () => {
  const out = await proveOwnership({
    repo: "org/thing", login: "someone", releaseAuthor: "github-actions[bot]",
    releasePublishedAt: RECENT_RELEASE, token: null, fetchImpl: blind,
  });
  assert(!out.ok, "with no file there is nothing to grant on");
  assert(!/403/.test(out.detail),
    `a 403 is a fact about the bot's token, not about the submitter: ${out.detail}`);
  assert(!/collaborator-permission/.test(out.detail),
    `nor is the name of a check the author cannot influence: ${out.detail}`);
  // It stays in the audit trail, which is where "how did this get decided"
  // is answered — just not in the comment a stranger reads.
  assert(out.tried.some((t) => t.method === "collaborator-permission" && /403/.test(t.outcome)),
    JSON.stringify(out.tried));
});

await test("a 403 plus a release published by CI is the real #13/#14 case", async () => {
  const out = await proveOwnership({
    repo: "Rel0d1x/command-intent-guard", login: "Rel0d1x",
    releaseAuthor: "github-actions[bot]", releasePublishedAt: RECENT_RELEASE,
    token: null, fetchImpl: blind,
  });
  assert(!out.ok, JSON.stringify(out));
  // Not "three checks failed". One instruction, first, naming the exact path.
  assert(out.detail.startsWith("**Commit `.well-known/astra-plugin-owner`"), out.detail);
  assert(out.detail.includes("Rel0d1x/command-intent-guard's default branch"), out.detail);
  assert(out.detail.includes("`Rel0d1x`"), "and the exact line to put in it");
  assert(out.detail.includes("/recheck"), "and how to run it again");
  assert(!/github-actions/.test(out.detail),
    `who pressed the button in CI is not something the author can act on: ${out.detail}`);
});

await test("the missing-file refusal says the file is missing, not that the author is", async () => {
  const out = await proveOwnership({
    repo: "org/thing", login: "someone", releaseAuthor: null, token: null, fetchImpl: blind,
  });
  assert(out.detail.includes("there is no `.well-known/astra-plugin-owner` on that branch (HTTP 404)"),
    out.detail);
});

await test("a file naming somebody else refuses, and prints who it does name", async () => {
  // The typo case. `Rel0dlx` and `Rel0d1x` differ by one glyph, and the whole
  // point of printing the file's contents is that the author can see it.
  const out = await proveOwnership({
    repo: "org/thing", login: "Rel0d1x", releaseAuthor: null, token: null,
    fetchImpl: async (url) =>
      url.includes("/collaborators/")
        ? { ok: false, status: 403 }
        : { ok: true, status: 200, text: async () => "# owners\nRel0dlx\n" },
  });
  assert(!out.ok, "a file that names somebody else proves nothing about this submitter");
  assertEqual(out.method, null, JSON.stringify(out.tried));
  assert(out.detail.includes("`Rel0dlx`"), `it has to show what the file says: ${out.detail}`);
  assert(out.detail.startsWith("**Commit `.well-known/astra-plugin-owner`"), out.detail);
});

await test("a stranger cannot list a repository whose file does not name them", async () => {
  // The property the whole check exists for, stated as a test rather than as a
  // comment: the file is on the victim's default branch, and mallory is not in
  // it. Nothing else in the pipeline asks this question.
  const out = await proveOwnership({
    repo: "victim/plugin", login: "mallory", releaseAuthor: "victim",
    releasePublishedAt: RECENT_RELEASE, token: null,
    fetchImpl: async (url) =>
      url.includes("/collaborators/")
        ? { ok: false, status: 403 }
        : { ok: true, status: 200, text: async () => "victim\n" },
  });
  assert(!out.ok, JSON.stringify(out));
});

await test("the file is compared case-insensitively, and `@` and comments are forgiven", async () => {
  const out = await proveOwnership({
    repo: "org/thing", login: "SomeOne", releaseAuthor: null, token: null,
    fetchImpl: async (url) =>
      url.includes("/collaborators/")
        ? { ok: false, status: 403 }
        : { ok: true, status: 200, text: async () => "# who may list this\n@someone   # the author\n" },
  });
  assert(out.ok && out.method === "well-known", JSON.stringify(out));
});

await test("a 403 with no file still lets a release ping through, which is what carries every later release", async () => {
  // `resolveSubmitter` (bot/lib/notify.mjs) makes the submitter the release's
  // own author on the ping and backstop paths, so this arm is the only one that
  // can answer there. It is circular and says so; what protects that path is the
  // pin — a ping may only name a repository that is already listed.
  const out = await proveOwnership({
    repo: "org/thing", login: "someone", releaseAuthor: "someone",
    releasePublishedAt: RECENT_RELEASE, token: null, fetchImpl: blind,
  });
  assert(out.ok, "an already-listed plugin must keep releasing with nobody in the loop");
  assertEqual(out.method, "release-author", JSON.stringify(out.tried));
});

await test("a 200 saying `write` is a DENIAL, and the owner file does not get a vote", async () => {
  // The one place the owner file does NOT win, and the reason is the same
  // reason a 403 does not lose: GitHub answering and GitHub declining are
  // different facts. Here it answered — about this person, on this repository,
  // just now — and said `write`. The file speaks where GitHub will not; it does
  // not overrule GitHub where it will, or a contributor could add themselves in
  // a pull request and outrank an explicit non-maintainer role.
  const out = await proveOwnership({
    repo: "victim/plugin", login: "mallory", releaseAuthor: "mallory",
    releasePublishedAt: RECENT_RELEASE, token: null,
    fetchImpl: async (url) => {
      if (url.includes("/collaborators/")) {
        return { ok: true, status: 200, json: async () => ({ role_name: "write" }) };
      }
      // A file listing mallory, and a release mallory published. Neither may win.
      if (url.includes("well-known")) return { ok: true, status: 200, text: async () => "mallory\n" };
      return { ok: false, status: 404 };
    },
  });
  assert(!out.ok, `an explicit non-owner role must end it: ${JSON.stringify(out)}`);
  assertEqual(out.method, null, JSON.stringify(out.tried));
  assertEqual(out.tried.length, 1, "and the weaker checks are not even run: " + JSON.stringify(out.tried));
});

await test("a 200 saying `none` is a denial too — the removed collaborator case", async () => {
  const out = await proveOwnership({
    repo: "victim/plugin", login: "mallory", releaseAuthor: "mallory",
    releasePublishedAt: RECENT_RELEASE, token: null,
    fetchImpl: async (url) =>
      url.includes("/collaborators/")
        ? { ok: true, status: 200, json: async () => ({ role_name: "none" }) }
        : { ok: true, status: 200, text: async () => "mallory\n" },
  });
  assert(!out.ok, JSON.stringify(out));
});

await test("release-author expires — a permanent fact must not be permanent access", async () => {
  // The module's own header rejects a challenge file because it "survives the
  // author being removed from the organisation". Method 3 did exactly that: an
  // ex-collaborator could still get their pre-removal release listed. It is now
  // capped, so the claim it makes is "they had access recently" rather than
  // "they had access once".
  const stale = new Date(Date.now() - 400 * 86_400_000).toISOString();
  const answer = async (url) => ({ ok: false, status: url.includes("/collaborators/") ? 403 : 404 });
  const fresh = await proveOwnership({
    repo: "org/thing", login: "x", releaseAuthor: "x", releasePublishedAt: RECENT_RELEASE,
    token: null, fetchImpl: answer,
  });
  assert(fresh.ok && fresh.method === "release-author", JSON.stringify(fresh));
  const old = await proveOwnership({
    repo: "org/thing", login: "x", releaseAuthor: "x", releasePublishedAt: stale,
    token: null, fetchImpl: answer,
  });
  assert(!old.ok, `a 400-day-old release is not proof of current access: ${JSON.stringify(old)}`);
  assert(old.detail.includes("400 days ago"), old.detail);
  assert(old.tried.some((t) => t.method === "release-author" && t.outcome.includes("400 days old")),
    JSON.stringify(old.tried));
  // Even here the refusal leads with the fix rather than with the expiry.
  assert(old.detail.startsWith("**Commit `.well-known/astra-plugin-owner`"), old.detail);
});

await test("maintain counts, write does not", async () => {
  const answer = (role) => async (url) =>
    url.includes("/collaborators/")
      ? { ok: true, status: 200, json: async () => ({ role_name: role }) }
      : { ok: false, status: 404 };
  const maintain = await proveOwnership({ repo: "o/r", login: "u", fetchImpl: answer("maintain") });
  assert(maintain.ok && maintain.method === "collaborator-permission", JSON.stringify(maintain));
  const write = await proveOwnership({ repo: "o/r", login: "u", fetchImpl: answer("write") });
  assert(!write.ok, "push access is not maintainership");
});

await test("the owner file is read, not claimed", async () => {
  const out = await proveOwnership({
    repo: "org/thing", login: "someone", releaseAuthor: "nobody",
    fetchImpl: async (url) =>
      url.includes(".well-known/astra-plugin-owner")
        ? { ok: true, status: 200, text: async () => "# owners\n@someone\nother\n" }
        : { ok: false, status: 404 },
  });
  assert(out.ok && out.method === "well-known", JSON.stringify(out));
  assert(out.detail.includes("read live on this run"),
    `and the run says so, because live reading is what makes removal a revocation: ${out.detail}`);
});

// ── the loop, closed at the source ──────────────────────────────────────────
//
// The refusal is now useful, but the point of the exercise is that an honest
// author never sees it. That means three files have to name the same path, and
// nothing but a test keeps them agreeing.

await test("the submission form asks for the file, with the exact path, before the submission", () => {
  const form = fs.readFileSync(
    path.join(REPO_ROOT, ".github", "ISSUE_TEMPLATE", "plugin-listing.yml"), "utf8");
  assert(form.includes(".well-known/astra-plugin-owner"),
    "the form must name the file an author is refused for not having");
  assert(/echo YOUR-GITHUB-LOGIN > \.well-known\/astra-plugin-owner/.test(form),
    "and give the line that creates it, so it is a copy rather than a translation");
  assert(/one commit/i.test(form), "and say what it costs");
  // A required confirmation, not a paragraph somebody scrolls past.
  const confirmations = [...form.matchAll(/- label: ([\s\S]*?)\n\s+required: true/g)].map((m) => m[1]);
  assert(confirmations.some((c) => c.includes(".well-known/astra-plugin-owner")),
    `the owner file has to be one of the required confirmations: ${JSON.stringify(confirmations)}`);
  // `bot/lib/issue.mjs` reads every `- [ ]` line in the rendered body and
  // `bot/lib/intake.mjs` refuses an unticked one, so adding it here needs no
  // parser change — but a prose block that is not a checkbox would be read by
  // nothing at all.
});

await test("the fixed remedy and the run's own message name the same file", () => {
  const remedy = codeDef("E_OWNERSHIP_UNPROVEN").remedy;
  assert(remedy.startsWith("Commit `.well-known/astra-plugin-owner`"),
    `the remedy has to lead with the fix, not with the diagnosis: ${remedy}`);
  assert(remedy.includes("/recheck"), remedy);
  assert(/write access, not of legal ownership/.test(remedy),
    "and be honest about what the file proves");
});

section("the submission form");

const ISSUE_BODY = [
  "### Source repository", "", "you/dice-roller", "",
  "### Release tag carrying the .astraplugin assets", "", "v0.2.0", "",
  "### What does it do, and why should it be listed?", "", "It rolls dice.", "",
  "### Confirmations", "",
  "- [X] I own or maintain this repository.",
  "- [X] I have read POLICY.md, including the data-handling section.",
].join("\n");

await test("the two facts come out of the rendered form", () => {
  const parsed = parseIssueForm(ISSUE_BODY);
  assertEqual(parsed.repo, "you/dice-roller", "the repository");
  assertEqual(parsed.tag, "v0.2.0", "the tag");
  assertEqual(parsed.confirmations.filter((c) => c.checked).length, 2, "both confirmations");
});

await test("a pasted URL, a stray @ and backticks are all the same repository", () => {
  const body = ISSUE_BODY.replace("you/dice-roller", "`https://github.com/you/dice-roller.git/`");
  assertEqual(parseIssueForm(body).repo, "you/dice-roller", "people paste the address bar");
});

await test("an unfilled optional field is not a value", () => {
  const body = ISSUE_BODY.replace("It rolls dice.", "_No response_");
  assertEqual(parseIssueForm(body).why, null, "`_No response_` is GitHub's placeholder, not prose");
});

await test("a form with no tag yields no tag, rather than a plausible one", () => {
  const body = ISSUE_BODY.replace("### Release tag carrying the .astraplugin assets\n\nv0.2.0\n\n", "");
  assertEqual(parseIssueForm(body).tag, null, "missing must read as missing");
});

await test("/recheck is a command only when it is the whole line", () => {
  assert(isRecheckCommand("/recheck"), "the command");
  assert(isRecheckCommand("  /RECHECK  "), "case and spacing do not matter");
  assert(!isRecheckCommand("I think you should /recheck this"), "a mention is not a command");
});

section("the comment a stranger reads");

await test("every blocking finding is followed by what to do about it", async () => {
  // Same licence as the check above, and for the same reason: it has to be one
  // the allowlist really refuses, or this asserts the text of a finding that
  // never happens.
  const r = await run({ assets: [conformingAsset({ license: "BUSL-1.1" })] });
  assert(r.comment.includes("E_LICENSE_NOT_ALLOWED"), "the code is in the comment");
  assert(r.comment.includes(codeDef("E_LICENSE_NOT_ALLOWED").remedy.slice(0, 40)),
    "and so is the sentence that says what to do");
  assert(r.comment.includes("### What to do"), "under a heading somebody will read");
});

await test("a clean run says what was not checked, not just what passed", async () => {
  const r = await run({ assets: [conformingAsset()], root: registryWith({}) });
  assert(r.comment.includes("N_HOST_RPC_SCAN_SCOPE"), "the heuristic's scope is on every report");
  assert(r.comment.includes("what none of them prove"), "and the report points at the document that says so");
});

await test("docs/BOT-CHECKS.md describes exactly the codes that exist", async () => {
  const { execFileSync } = await import("node:child_process");
  execFileSync(process.execPath, [path.join(REPO_ROOT, "bot", "gen-checks-doc.mjs"), "--check"],
    { cwd: REPO_ROOT, stdio: "pipe" });
});

await test("no code reaches a comment without a declaration behind it", () => {
  const undeclared = [...emitted].filter((c) => !Object.hasOwn(CODES, c));
  assertEqual(undeclared.join(", "), "",
    "every code the bot can emit must be in bot/lib/codes.mjs with a title and a remedy");
  // The reverse direction is a warning rather than a failure: codes for
  // failure classes that are hard to provoke (a corrupt central directory, a
  // derived listing this repository's own validator rejects) are declared and
  // documented before they are ever seen in the wild.
  const unseen = Object.keys(CODES).filter((c) => !emitted.has(c));
  console.log(`        ${emitted.size}/${Object.keys(CODES).length} codes exercised; not yet provoked: ${unseen.join(", ") || "none"}`);
});

// ═══════════════════════════════════════════════════════════════════════════

section("the service path's split: verify never unpacks, check never names (B-T3.2)");

const { verifyFacts, checkFacts } = await import("../ingest.mjs");
const SVC_SID = "0192f1c2-3b4a-7c5d-8e6f-1a2b3c4d5e6f";
const svcLease = { submission_id: SVC_SID, repo: REPO, tag: TAG, trigger: "poll", claimed_from: "received" };

/** One `verify` run against a world assembled from the arguments. */
async function verifyRun({ assets, certRepo = null, repoIds = null, ghFail = null, ownerFile = null } = {}) {
  const github = fakeGitHub({ repo: REPO, tag: TAG, assets });
  const assetsDir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-assets-"));
  scratch.push(assetsDir);
  const v = await verifyFacts({ lease: svcLease, root: REPO_ROOT, assetsDir, trustFile: TRUST_FILE }, {
    rootKeys: TEST_ROOT_KEYS,
    fetchRelease: github.fetchRelease.bind(github),
    headAsset: github.headAsset.bind(github),
    downloadAsset: github.downloadAsset.bind(github),
    ghRunner: (args) => fakeGh({
      repo: REPO, signerDigest: ALLOWED_WORKFLOW_SHA, certRepo, fail: ghFail, tag: TAG,
      subjectDigest: crypto.createHash("sha256").update(fs.readFileSync(args[2])).digest("hex"),
    })(args),
    fetchRepositoryIds: async () => repoIds ?? { status: "found", id: FIXTURE_REPOSITORY_ID, owner_id: FIXTURE_OWNER_ID, full_name: REPO },
    binding: {
      commitInRepository: async () => ({ status: "found", reason: "HTTP 200" }),
      fileAtCommit: async () => (ownerFile === null ? { status: "not_found", reason: "HTTP 404" } : { status: "found", reason: "HTTP 200", content: ownerFile }),
    },
    lastCommitTouching: async () => ({ status: "found", reason: "HTTP 200", commit: "9".repeat(40) }),
    pullsForCommit: async () => ({ status: "found", reason: "HTTP 200", pulls: [4] }),
    workflowRun: async () => ({ status: "found", reason: "HTTP 200", triggering_actor_id: FIXTURE_OWNER_ID }),
  });
  return { v, assetsDir };
}

await test("verify: a conforming release yields every identity value from the certificate, and the bytes on disk", async () => {
  const { v, assetsDir } = await verifyRun({ assets: [conformingAsset()] });
  assertEqual(v.outcome, "ok", JSON.stringify(v.findings.filter((f) => f.level === "error")));
  assertEqual(v.plugin_id, "dice-roller", "the id comes from the attested asset name");
  assertEqual(v.version, "0.2.0", "and the version");
  assertEqual(v.repository_id, FIXTURE_REPOSITORY_ID, ".15");
  assertEqual(v.repository_owner_id, FIXTURE_OWNER_ID, ".17");
  assertEqual(v.repo, REPO, ".12");
  assertEqual(v.commit, "a".repeat(40), ".13");
  assertEqual(v.binding.outcome, "none", "no owner file, no line");
  assert(/^[0-9a-f]{16}$/.test(v.fingerprint), "a fingerprint");
  const onDisk = fs.readdirSync(path.join(assetsDir, SVC_SID));
  assert(onDisk.includes(bundleName()), `the verified bytes are left for check: ${onDisk.join(", ")}`);
  assert(onDisk.includes("verify-outcome.txt"), "and the upload is never empty");
});

await test("verify: a certificate naming another repository id than the download's writes nothing and alerts (BOT-21)", async () => {
  const { v } = await verifyRun({ assets: [conformingAsset()], repoIds: { status: "found", id: "999", owner_id: FIXTURE_OWNER_ID, full_name: REPO } });
  assertEqual(v.outcome, "alert", JSON.stringify(v));
  assertEqual(v.code, "E_ATTESTATION_REPO_MISMATCH", "the two repositories cannot both have produced one artifact");
});

await test("verify: agreeing ids under another name are a rename for the identity comparison, not a refusal", async () => {
  const { v } = await verifyRun({ assets: [conformingAsset()], certRepo: "a-stranger/dice-roller-old" });
  assertEqual(v.outcome, "ok", JSON.stringify(v.findings));
  assertEqual(v.repo, "a-stranger/dice-roller-old", "`.12` is what the listing will be compared under (TRUST-23; ID-41)");
});

await test("verify: no attestation is a refusal; a transient id read is a wait (FLOW-72)", async () => {
  const missing = await verifyRun({ assets: [conformingAsset()], ghFail: "HTTP 404: Not Found (no attestations found)" });
  assertEqual(missing.v.outcome, "refuse", JSON.stringify(missing.v));
  assertEqual(missing.v.code, "E_ATTESTATION_MISSING", "the author's fix, named");
  const transient = await verifyRun({ assets: [conformingAsset()], repoIds: { status: "transient", reason: "HTTP 403 with rate-limit headers" } });
  assertEqual(transient.v.outcome, "wait", JSON.stringify(transient.v));
  assertEqual(transient.v.code, "W_GITHUB_RATE_LIMITED", "a read that did not happen is not a difference");
});

await test("verify: a binding line at the attested commit, with ID-63's and MIG-31's reads beside it", async () => {
  const token = "Abcdefghijklmnopqrstuv0123";
  const { v } = await verifyRun({ assets: [conformingAsset()], ownerFile: `astra-binding: ${token}\n` });
  assertEqual(v.binding.outcome, "one", JSON.stringify(v.binding));
  assertEqual(v.binding.token_hash, crypto.createHash("sha256").update(token).digest("hex").slice(0, 16), "§0.7's token_hash");
  assertEqual(v.owner_file.commit, "9".repeat(40), "ID-63's owner-file commit");
  assertEqual(v.owner_file.pull_request, true, "and whether a pull request carried it");
  assertEqual(v.actor.triggering_actor_id, FIXTURE_OWNER_ID, "MIG-31's actor");
});

await test("check: the facts file carries codes and levels and nothing that names anything; the card is derived under `.12`", async () => {
  const { v, assetsDir } = await verifyRun({ assets: [conformingAsset()] });
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-check-"));
  scratch.push(out);
  const { facts } = await checkFacts({ submissionId: SVC_SID, assetsDir: path.join(assetsDir, SVC_SID), verified: v, out, root: REPO_ROOT });
  assertEqual(facts.findings.filter((f) => f.level === "error").length, 0, JSON.stringify(facts.findings));
  for (const f of facts.findings) assertEqual(Object.keys(f).sort().join(","), "code,level", "no `where`, no `message`");
  const written = JSON.parse(fs.readFileSync(path.join(out, "facts.json"), "utf8"));
  assertEqual(written.plugin_id, "dice-roller", "facts.json on disk");
  const plugin = JSON.parse(fs.readFileSync(path.join(out, "listing", "plugins", "dice-roller", "plugin.json"), "utf8"));
  assertEqual(plugin.source.repo, REPO, "the card is derived under verify's name");
});

await test("check: a reserved id is refused on the service path too", async () => {
  const asset = conformingAsset({ id: "moderation" });
  const { v, assetsDir } = await verifyRun({ assets: [asset] });
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "astra-svc-check-"));
  scratch.push(out);
  const { facts } = await checkFacts({ submissionId: SVC_SID, assetsDir: path.join(assetsDir, SVC_SID), verified: v, out, root: REPO_ROOT });
  assert(facts.findings.some((f) => f.level === "error" && f.code.startsWith("E_ID_RESERVED")), JSON.stringify(facts.findings));
  assert(fs.existsSync(path.join(out, "listing")), "the listing upload still has its directory");
});

// ── result ──────────────────────────────────────────────────────────────────

console.log();
if (failures.length) {
  console.log(`FAIL  ${passed} passed, ${failures.length} failed`);
  process.exit(1);
}
console.log(`PASS  ${passed} passed, 0 failed`);
