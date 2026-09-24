#!/usr/bin/env node
// The publication policy's own suite.  `node bot/tests/policy.test.mjs`
//
// Task 3.5's acceptance is one sentence — *"a normal patch release is live
// without a human; a `dom_access` request is not"* — and both halves are the
// first two tests below, run through the **whole** pipeline against the bot's
// fixture corpus: a real bundle, a real archive walk, the real manifest probe,
// the real derivation, and then the policy. Asserting the policy function in
// isolation would prove that `decide()` returns what `decide()` returns; these
// prove that a release does or does not reach the catalogue.
//
// Everything else here exists because the interesting half of this task is not
// the happy path. A delay that never ends, a queue entry that republishes a
// release the checks have since started refusing, a clock that a swapped asset
// can wait out — each of those is a way for "zero-touch" to mean "unsupervised
// and wrong", and each has a test.
//
// Nothing touches the network.

import { execFileSync } from "node:child_process";
import { cleanEnv } from "../../tools/lib/git-env.mjs";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { markerOnMain } from "../baseline.mjs";
import { LEGACY_TRIGGERS, alreadyPublished, decideRelease, legacyTrigger, noListingNoBinding, readIdentityRecord, terminalOnMain, writeOutputs } from "../decide.mjs";
import { recordCommitRefusal } from "../publish-apply.mjs";
import { bot74Filter } from "../watch.mjs";
import { DEFAULT_SIGNER_WORKFLOW } from "../ingest.mjs";
import { BOT_AUTHOR, decidableThread, parseMaintainerCommand, safeLogin } from "../lib/intake.mjs";
import {
  CLEAN_RELEASES_FOR_TRUSTED,
  DELAY_HOURS,
  HIGH_RISK,
  POLICY_CODES,
  REVIEW_SLA_HOURS,
  TRUSTED_DELAY_HOURS,
  decide,
  policyCodeDef,
  queueFile,
  readQueue,
  requestedAuthority,
  slaReport,
  trackRecord,
} from "../lib/policy.mjs";
import { loadRootKeys } from "../lib/attestation.mjs";
import { proveMaintainer } from "../lib/maintainer.mjs";
import {
  WATCH_AFTER_DAYS,
  findListingByRepo,
  newReleases,
  parseReleasePing,
  parseReleasesAtom,
  watchPlan,
} from "../lib/notify.mjs";
// `pollFeed` moved to `bot/lib/poll.mjs` with B-T2.6, and `watch.mjs` imports
// it rather than re-exporting it, so this import follows the function. The
// `parseReleasesAtom` above deliberately still comes from `notify.mjs`, which
// re-exports it: that re-export is what keeps five importers unchanged, and a
// test that stopped reading it would stop witnessing it.
import { pollFeed } from "../lib/poll.mjs";
// The canary walks (B-T4.1) run B-T3.3a's inputs through the modules that own
// them, so a gap is judged against real readers rather than hand-made shapes.
import { parseBindingFile } from "../lib/binding.mjs";
import { bindingDecision } from "../lib/identity.mjs";
import { listingState } from "../lib/listing-state.mjs";
import { runDrain, runWatch } from "../watch.mjs";
import { recordPermissionProbe, triage } from "../triage.mjs";
import { makeBundle, fakeGitHub, fakeGh, fakeOwnership, FIXTURE_COMMIT } from "../fixtures/ingest/make.mjs";
import { loadSources } from "../../tools/lib/sources.mjs";

const REPO_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

/** `loadSources`, named for what the assertions below are actually asking. */
const requireSources = (root) => loadSources(root);

// ── harness ─────────────────────────────────────────────────────────────────

let passed = 0;
const failures = [];
let group = "";
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

const scratch = [];
process.on("exit", () => { for (const d of scratch) fs.rmSync(d, { recursive: true, force: true }); });
function tmp(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  scratch.push(d);
  return d;
}

// ── the world ───────────────────────────────────────────────────────────────

const REPO = "a-stranger/dice-roller";
/** This registry itself — what a maintainer's permission is checked against. */
const REGISTRY_REPO = "mihailinl/astra-registry";
const TAG = "v0.2.0";
const SUBMITTER = "a-stranger";
const ALLOWED_WORKFLOW_SHA = "0".repeat(40);
const NOW = new Date("2026-08-10T12:00:00Z");

function testRootsFile() {
  const keys = ["root-a", "root-b"].map((n) =>
    JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "tools", "testkeys", `TEST-ONLY-DO-NOT-TRUST-${n}.pub.json`), "utf8")));
  const file = path.join(tmp("astra-policy-roots-"), "root.json");
  fs.writeFileSync(file, JSON.stringify({
    $banner: "TEST ROOTS — generated by bot/tests/policy.test.mjs, never committed, never trusted by a daemon.",
    schema: "astra.registry.root/1",
    status: "provisioned",
    roots: keys.map((k) => ({ key_id: k.key_id, public_key: k.public_key, role: k.role })),
  }, null, 2));
  return file;
}
const ROOTS_FILE = testRootsFile();
/**
 * The TEST roots as a verifier wants them.
 *
 * Handed in through `deps.rootKeys`, not through an argument: the production
 * roots are compiled into `bot/lib/roots.mjs` and `--roots` no longer exists
 * (registry plan B-T1.5).
 */
const TEST_ROOT_KEYS = loadRootKeys(ROOTS_FILE);
const TRUST_FILE = path.join(REPO_ROOT, "tools", "testkeys", "fixtures", "trust-active-signed.json");

/**
 * A registry tree, written from a description.
 *
 * `staging: false` matters here in a way it does not in the ingest suite: a
 * staging entry is not a clean release (nobody could verify its artifact), so
 * the graduation test has to write listings that carry digests.
 */
function registryTree(specs) {
  const dir = tmp("astra-policy-reg-");
  for (const spec of specs) {
    const id = spec.id ?? "dice-roller";
    const repo = spec.repo ?? REPO;
    const pdir = path.join(dir, "plugins", id, "versions");
    fs.mkdirSync(pdir, { recursive: true });
    fs.writeFileSync(path.join(dir, "plugins", id, "plugin.json"), `${JSON.stringify({
      schema: "astra.registry.plugin/1",
      id,
      // Derived from the id unless a test says otherwise. Two fixture listings
      // sharing one display name is now a finding in its own right
      // (R_DISPLAY_NAME_COLLISION covers the byte-identical case), and a
      // fixture that trips a real rule by accident tests the wrong thing.
      name: spec.name ?? (id === "dice-roller" ? "Dice Roller" : id),
      summary: "Rolls dice when you ask it to.",
      license: "MIT",
      source: { kind: "github", repo },
      added_at: "2026-01-01",
      ...(spec.unlisted ? { unlisted: true } : {}),
    }, null, 2)}\n`);
    for (const v of spec.versions ?? [{ version: "0.1.0" }]) {
      const staging = v.staging ?? true;
      fs.writeFileSync(path.join(pdir, `${v.version}.json`), `${JSON.stringify({
        schema: "astra.registry.version/1",
        id,
        version: v.version,
        published_at: v.published_at ?? "2026-01-01T00:00:00Z",
        release: { kind: "github_release", repo, tag: v.tag ?? `v${v.version}` },
        ...(staging
          ? { staging: true, staging_reason: "Test fixture: the release this points at is a fake." }
          : {}),
        // Always recorded, the way `bot/lib/derive.mjs` records it: a listing
        // that predates capability recording reads as "asks for nothing",
        // which makes its next release look like a widening. That is a
        // one-off 24 h delay per legacy listing and it fails safe, but a
        // fixture that reproduced it in every test would be measuring the
        // fixture rather than the policy.
        capabilities: v.capabilities ?? ["tools"],
        ...(v.permissions ? { permissions: v.permissions } : {}),
        artifacts: {
          "linux-x64": {
            url: `https://github.com/${repo}/releases/download/v${v.version}/${id}-${v.version}-linux-x64.astraplugin`,
            filename: `${id}-${v.version}-linux-x64.astraplugin`,
            ...(staging ? {} : { sha256: "b".repeat(64), size: 1024 }),
          },
        },
      }, null, 2)}\n`);
    }
  }
  return dir;
}

const bundleName = (spec = {}) =>
  `${spec.id ?? "dice-roller"}-${spec.version ?? "0.2.0"}-${spec.os === "windows" ? "windows-x64" : "linux-x64"}.astraplugin`;
const conforming = (spec = {}) => ({ name: bundleName(spec), bytes: makeBundle(spec) });

/** One ingest-and-decide against a world assembled from the arguments. */
async function run({
  assets = [conforming()], repo = REPO, tag = TAG, submitter = SUBMITTER, root,
  now = NOW, out = null, issue = null, approvedBy = null, approvedAt = null, approvedFor = null,
  publishNow = false, source = null,
  // Which path the run came in on. `null` is the legacy path every caller
  // above means; the canary walks at the end of this file ask the service
  // path, which is where a bound listing is published (BOT-77).
  via = null,
  // The commit the Release names and the commit the attestation names. Equal by
  // default, because in a healthy release they are the same commit; a test that
  // moves one and not the other is asking about `E_RELEASE_COMMIT_MISMATCH`.
  commit = FIXTURE_COMMIT, attestedCommit = commit,
} = {}) {
  const github = fakeGitHub({ repo, tag, assets, commit });
  return decideRelease(
    {
      repo, tag, submitter, root, issue, now, approvedBy, approvedAt, approvedFor, publishNow, source,
      ...(via ? { path: via } : {}),
      trustFile: TRUST_FILE, signerWorkflow: DEFAULT_SIGNER_WORKFLOW,
      out,
    },
    {
      rootKeys: TEST_ROOT_KEYS,
      fetchRelease: github.fetchRelease.bind(github),
      headAsset: github.headAsset.bind(github),
      downloadAsset: github.downloadAsset.bind(github),
      proveOwnership: fakeOwnership(true),
      ghRunner: (args) => fakeGh({
        repo,
        signerDigest: ALLOWED_WORKFLOW_SHA,
        sourceCommit: attestedCommit,
        // `.14` is `refs/tags/<tag>` on every bundle in the catalogue and the
        // bot now enforces it (ID-28; registry plan B-T1.1), so the stub is
        // told which tag it is attesting rather than omitting the field.
        tag,
        subjectDigest: crypto.createHash("sha256").update(fs.readFileSync(args[2])).digest("hex"),
      })(args),
    },
  );
}

/**
 * What a maintainer actually does: read the comment on a held run, copy the
 * `/approve` line out of it, and answer with that.
 *
 * Two runs, because that is two runs in production too — and because a test
 * that computed the fingerprint from the same expression the code does would
 * assert that a function equals itself. This takes the string out of the
 * rendered markdown a human would have copied.
 */
async function approveFromComment(world, { by = "the-maintainer", at = "2026-08-10T11:59:00Z" } = {}) {
  const held = await run(world);
  const line = /^\/approve (\S+)@(\S+) ([0-9a-f]{16})$/m.exec(held.comment);
  if (!line) throw new Error(`the held comment printed no /approve line:\n${held.comment}`);
  const approved = await run({ ...world, approvedBy: by, approvedAt: at, approvedFor: line[3] });
  return { held, approved, line: line[0], fingerprint: line[3] };
}

const codes = (r) => r.decision.reasons.map((x) => x.code);
const hours = (a, b) => Math.round((new Date(a).getTime() - new Date(b).getTime()) / 3600000);

// ═══════════════════════════════════════════════════════════════════════════

section("the acceptance criterion, end to end");

await test("a normal patch release goes live with no human", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0" }] }]);
  const out = tmp("astra-policy-out-");
  const r = await run({ root });
  assertEqual(r.decision.outcome, "publish",
    `${JSON.stringify(r.findings.filter((f) => f.level === "error" || f.level === "review"))} / ${JSON.stringify(r.decision.reasons)}`);
  assert(r.decision.publishes_now, "and it publishes on this run, not a later one");
  assertEqual(r.decision.publish_after, null, "nothing to wait for");
  assert(codes(r).includes("P_PUBLISHED"), JSON.stringify(codes(r)));

  writeOutputs(out, { repo: REPO, tag: TAG, issue: null }, r);
  assert(fs.existsSync(path.join(out, "plugins", "dice-roller", "versions", "0.2.0.json")),
    "the listing the publish job commits is on disk");
  assertEqual(fs.readFileSync(path.join(out, "remove.txt"), "utf8"), "", "nothing to delete");
  assert(r.comment.includes("**Published.**"), "and the author is told, in the comment, in those words");
});

await test("a dom_access request does not", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const out = tmp("astra-policy-out-");
  const r = await run({ root, assets: [conforming({ capabilities: ["tools", "dom_access"] })] });
  assertEqual(r.decision.outcome, "review", JSON.stringify(r.decision.reasons));
  assert(codes(r).includes("R_NEW_HIGH_RISK"), JSON.stringify(codes(r)));
  assert(!r.decision.publishes_now, "nothing publishes");
  assertEqual(hours(r.decision.sla_deadline, NOW), REVIEW_SLA_HOURS, "and the author is given the deadline");

  writeOutputs(out, { repo: REPO, tag: TAG, issue: null }, r);
  assert(!fs.existsSync(path.join(out, "plugins")), "no listing is produced for a held release");
  assert(r.comment.includes("R_NEW_HIGH_RISK"), "the comment names the reason");
  assert(r.comment.includes(POLICY_CODES.R_NEW_HIGH_RISK.remedy.slice(0, 40)),
    "…and says what to do about it");
});

section("/publish — the maintainer's \"not in a day, now\"");

// The flag has to be able to fire AND to be absent, or one of the two is a
// comment. Same tree, same bytes, same approval; the only difference is the
// word the maintainer typed.
await test("/publish waives the delay, and /approve alone does not", async () => {
  const tree = () => registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools", "client"] }] }]);
  const assets = [conforming({ capabilities: ["tools", "client"] })];

  // The fingerprint the maintainer would copy out of the hold comment. An
  // approval that names nothing is stale by design, which is a different test.
  const first = await run({ root: tree(), assets });
  const fp = first.decision.fingerprint;

  const approved = await run({
    root: tree(), assets,
    approvedBy: "maint", approvedAt: NOW.toISOString(), approvedFor: fp,
  });
  assertEqual(approved.decision.outcome, "delay", JSON.stringify(codes(approved)));
  assert(!approved.decision.publishes_now, "an approval alone still waits");

  const published = await run({
    root: tree(), assets,
    approvedBy: "maint", approvedAt: NOW.toISOString(), approvedFor: fp, publishNow: true,
  });
  assertEqual(published.decision.outcome, "publish", JSON.stringify(codes(published)));
  assert(published.decision.publishes_now, "/publish does not wait");
  assert(codes(published).includes("P_DELAY_WAIVED_BY_COMMAND"), JSON.stringify(codes(published)));
  assert(published.comment.includes("P_DELAY_WAIVED_BY_COMMAND"),
    "the shortened window is stated where the author reads it");
});

// It waives the WAIT and nothing else. Without an approval at all there is
// nothing to waive, and a hold is not a delay.
await test("/publish does not stand in for an approval", async () => {
  const r = await run({
    root: registryTree([{ id: "something-else" }]),
    publishNow: true,
  });
  assertEqual(r.decision.outcome, "review", JSON.stringify(codes(r)));
  assert(codes(r).includes("R_FIRST_LISTING"), JSON.stringify(codes(r)));
  assert(!codes(r).includes("P_DELAY_WAIVED_BY_COMMAND"),
    "a waiver nobody approved must not appear");
});

// An instruction is checked by RUNNING it, not by reading it. Both lines the
// bot prints are fed back to the parser that will receive them, so a comment
// that tells a maintainer to type something the bot cannot understand fails
// here rather than in front of them.
await test("the lines the bot prints are lines the bot accepts", async () => {
  const held = await run({ root: registryTree([{ id: "something-else" }]) });
  assertEqual(held.decision.outcome, "review", JSON.stringify(codes(held)));

  for (const verb of ["approve", "publish"]) {
    const line = new RegExp(`^/${verb} \\S+@\\S+ [0-9a-f]{16}$`, "m").exec(held.comment);
    assert(line, `the hold comment offers no ready-made /${verb} line:\n${held.comment.slice(0, 400)}`);
    const parsed = parseMaintainerCommand(line[0]);
    assert(parsed, `/${verb} line does not parse: ${line[0]}`);
    assertEqual(parsed.command, verb, line[0]);
    assertEqual(parsed.fingerprint, held.decision.fingerprint, "and it names this submission");
    assertEqual(parsed.repo, held.decision.repo, line[0]);
    assertEqual(parsed.tag, held.decision.tag, line[0]);
  }
});

// The state our owner was in: approved, waiting, and no command in front of
// them. The waiver was documented as editing a file from a machine with a
// checkout.
await test("a delayed release offers the line that publishes it now", async () => {
  const tree = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools", "client"] }] }]);
  const first = await run({ root: tree, assets: [conforming({ capabilities: ["tools", "client"] })] });
  const delayed = await run({
    root: tree, assets: [conforming({ capabilities: ["tools", "client"] })],
    approvedBy: "maint", approvedAt: NOW.toISOString(), approvedFor: first.decision.fingerprint,
  });
  assertEqual(delayed.decision.outcome, "delay", JSON.stringify(codes(delayed)));

  const line = /^\/publish \S+@\S+ [0-9a-f]{16}$/m.exec(delayed.comment);
  assert(line, `a waiting release offers no /publish line:\n${delayed.comment.slice(-600)}`);
  const parsed = parseMaintainerCommand(line[0]);
  assertEqual(parsed?.command, "publish", line[0]);
  assertEqual(parsed?.fingerprint, delayed.decision.fingerprint, "bound to these bytes");
});

section("the three events that block on a person, and nothing else");

await test("a first listing blocks, and says it is the only time", async () => {
  const r = await run({ root: registryTree([{ id: "something-else" }]) });
  assertEqual(r.decision.outcome, "review", JSON.stringify(r.decision.reasons));
  assert(codes(r).includes("R_FIRST_LISTING"), JSON.stringify(codes(r)));
});

await test("a repository change blocks", async () => {
  const r = await run({ root: registryTree([{ repo: "someone-else/dice-roller" }]) });
  assertEqual(r.decision.outcome, "review", JSON.stringify(r.decision.reasons));
  assert(codes(r).includes("R_IDENTITY_CHANGED"), JSON.stringify(codes(r)));
});

await test("a first listing that also wants dom_access says it once, not twice", async () => {
  const r = await run({
    root: registryTree([{ id: "something-else" }]),
    assets: [conforming({ capabilities: ["tools", "dom_access"] })],
  });
  assertEqual(r.decision.outcome, "review", "");
  assert(codes(r).includes("R_FIRST_LISTING"), JSON.stringify(codes(r)));
  assert(!codes(r).includes("R_NEW_HIGH_RISK"),
    "a human is already reading it; a second row saying so tells them nothing");
});

await test("a check the bot cannot rule on is held with the same SLA", async () => {
  // A name one edit away from a listed plugin: task 3.3 raises it as `review`,
  // and the policy adopts any such finding rather than inventing a fourth
  // blocking event of its own.
  const r = await run({
    root: registryTree([{ versions: [{ version: "0.1.0" }] }]),
    assets: [conforming({ id: "dice-rollers" })],
  });
  assertEqual(r.decision.outcome, "review", JSON.stringify(r.decision.reasons));
  assert(codes(r).includes("R_CHECK_HELD"), JSON.stringify(codes(r)));
});

await test("a failed check is a refusal, and the policy says it never got a say", async () => {
  // The licence has to be one `policy/spdx-allowlist.json` really refuses, or
  // there is no failed check and this asserts nothing. It was `GPL-3.0-only`
  // until the copyleft family joined the allowlist — after which the run went
  // green, the decision came back `publish`, and the property under test — that
  // a failed check outranks the policy engine entirely — stopped being
  // exercised at all. `BUSL-1.1` is source-available rather than open source,
  // so it stays refused for as long as POLICY.md §4 says open source only.
  const r = await run({
    root: registryTree([{ versions: [{ version: "0.1.0" }] }]),
    assets: [conforming({ license: "BUSL-1.1" })],
  });
  assertEqual(r.decision.outcome, "refuse", JSON.stringify(r.decision.reasons));
  assertEqual(codes(r).join(","), "P_REFUSED", "one row, and it points at the checks above it");
});

section("the delay");

await test("the tree the publish job commits carries the icon and the README", async () => {
  // There were two writers of a listing: `ingest.mjs`'s, which lays out the
  // tree the validator checks, and `decide.mjs`'s, which lays out the tree the
  // workflow commits. When a listing gained presentation files only the first
  // learned to write them, so validation passed on one tree and the workflow
  // committed a different one — and the run died on this repository's own rule,
  // `icon "icon.svg" is named here but the file is not in plugins/dice-roller/`.
  //
  // Asserting the FILES, not the fields: `plugin.json` naming an icon it did
  // not ship is exactly the state that got through.
  const root = registryTree([{ versions: [{ version: "0.1.0" }] }]);
  const out = tmp("astra-policy-out-");
  const r = await run({
    root,
    assets: [conforming({
      extraFiles: [
        { name: "icon.svg", data: '<svg xmlns="http://www.w3.org/2000/svg"><rect width="16" height="16"/></svg>' },
        { name: "README.md", data: "# Dice Roller\n\nRolls dice.\n" },
      ],
    })],
  });
  assertEqual(r.decision.outcome, "publish", JSON.stringify(r.decision.reasons));

  writeOutputs(out, { repo: REPO, tag: TAG, issue: null }, r);
  const dir = path.join(out, "plugins", "dice-roller");
  const doc = JSON.parse(fs.readFileSync(path.join(dir, "plugin.json"), "utf8"));
  assertEqual(doc.icon, "icon.svg", "the document has to name the icon");
  assertEqual(doc.readme, "README.md", "and the README");
  assert(fs.existsSync(path.join(dir, "icon.svg")),
    "plugin.json names an icon the committed tree does not contain");
  assert(fs.existsSync(path.join(dir, "README.md")),
    "plugin.json names a README the committed tree does not contain");
});

await test("a plugin already holding dom_access waits, even with nothing changed", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["dom_access", "tools"] }] }]);
  const r = await run({ root, assets: [conforming({ capabilities: ["tools", "dom_access"] })] });
  assertEqual(r.decision.outcome, "delay", JSON.stringify(r.decision.reasons));
  assert(codes(r).includes("P_DELAY_HIGH_RISK"), JSON.stringify(codes(r)));
  assertEqual(hours(r.decision.publish_after, NOW), DELAY_HOURS, "24 h from now");
  assert(r.decision.notify_author, "and the author hears about it now, which is the point");
});

await test("a widening inside the non-high-risk set waits too, and publishes itself", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const r = await run({ root, assets: [conforming({ capabilities: ["tools", "tts"] })] });
  assertEqual(r.decision.outcome, "delay", JSON.stringify(r.decision.reasons));
  assert(codes(r).includes("P_DELAY_WIDENED"), JSON.stringify(codes(r)));
  assert(r.decision.queue_entry.reason.includes("P_DELAY_WIDENED"), "the queue file records why it waited");
  assert(r.comment.includes("Publishing itself at"), "the comment gives the time, not a shrug");
});

await test("a narrowing is not a widening", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools", "tts"] }] }]);
  const r = await run({ root, assets: [conforming({ capabilities: ["tools"] })] });
  assertEqual(r.decision.outcome, "publish", JSON.stringify(r.decision.reasons));
});

await test("the queue entry the workflow commits lands under state/queue/", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const out = tmp("astra-policy-out-");
  const r = await run({ root, assets: [conforming({ capabilities: ["tools", "tts"] })] });
  writeOutputs(out, { repo: REPO, tag: TAG, issue: 7 }, r);
  const file = path.join(out, queueFile("dice-roller", "0.2.0"));
  assert(fs.existsSync(file), `expected ${queueFile("dice-roller", "0.2.0")}`);
  const entry = JSON.parse(fs.readFileSync(file, "utf8"));
  assertEqual(entry.repo, REPO, "the repository it is waiting on");
  assertEqual(entry.submitter, SUBMITTER, "and whose ownership gets re-proved when it drains");
  assertEqual(entry.artifact_digests.length, 1, "and the exact bytes the clock is running on");
  assert(!fs.existsSync(path.join(out, "plugins")), "a delayed release publishes nothing yet");
});

await test("the issue number survives the queue, so the drain knows which thread it answered", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const asset = conforming({ capabilities: ["tools", "tts"] });

  // Round one is driven by the submission issue, so the number is in the event.
  const first = await run({ root, assets: [asset], issue: 41 });
  assertEqual(first.decision.outcome, "delay", JSON.stringify(first.decision.reasons));
  assertEqual(first.decision.issue, 41, "the decision names the thread it is answering");
  assertEqual(first.decision.queue_entry.issue, 41, "and the queue entry keeps it");

  const qfile = path.join(root, queueFile("dice-roller", "0.2.0"));
  fs.mkdirSync(path.dirname(qfile), { recursive: true });
  fs.writeFileSync(qfile, `${JSON.stringify(first.decision.queue_entry, null, 2)}\n`);

  // Round two is the cron drain: no issue, no comment, no event at all. The
  // queue entry is the only thing left that remembers, and the publication has
  // to be able to close the thread that asked for it.
  const later = new Date(NOW.getTime() + (DELAY_HOURS + 1) * 3600000);
  const second = await run({ root, assets: [asset], now: later, issue: null });
  assertEqual(second.decision.outcome, "publish", JSON.stringify(second.decision.reasons));
  assertEqual(second.decision.issue, 41, "recovered from the queue entry with no event to read");
});

await test("the permission check says what the endpoint did, and the probe line names no one", async () => {
  // B-T0.4a. Two fields out of `proveMaintainer`, and a summary line that is
  // about the token rather than about a person.
  const silent = await proveMaintainer({
    repo: "mihailinl/astra-registry",
    login: "someone",
    fetchImpl: async () => ({ ok: false, status: 404, json: async () => ({}) }),
  });
  assertEqual(silent.answered, false, "a 404 is GitHub declining to say");
  assert(String(silent.outcome).length > 0, "and the outcome token says which silence it was");

  const answered = await proveMaintainer({
    repo: "mihailinl/astra-registry",
    login: "someone",
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ permission: "admin" }) }),
  });
  assertEqual(answered.answered, true, "an answer is an answer");
  assertEqual(answered.ok, true, "and admin may decide");

  const lines = [];
  const logged = [];
  const wrote = recordPermissionProbe(answered, { GITHUB_STEP_SUMMARY: "/dev/null" }, (_p, l) => lines.push(l), (l) => logged.push(l));
  assertEqual(wrote, true, "the line is written when a summary exists");
  assertEqual(lines.length, 1, "one line");
  assert(lines[0].startsWith("collaborator-permission: answered=true outcome="), lines[0]);
  assert(!lines[0].includes("someone"), "the summary is public, so it carries no login");

  // The measurement has to reach the thing that asks for it. A step summary is
  // reachable by no API — not on the job object, not in the run's artifacts,
  // not in the logs — so for three weeks R0's answer existed only on a web
  // page, and the runbook told the owner to read it off that page by eye.
  // Measured 2026-09-20 on run 35485336476: the line was written, and nothing
  // but a browser could retrieve it.
  assertEqual(logged.length, 1, "and the same line goes to the log, which an API can read");
  assertEqual(logged[0], lines[0].trimEnd(), "the two copies are one line, not two spellings of it");
  assert(!logged[0].includes("someone"), "the log is public too");

  const outsideActions = [];
  assertEqual(recordPermissionProbe(answered, {}, () => {}, (l) => outsideActions.push(l)), false,
    "and nothing is written to a summary outside Actions");
  assertEqual(outsideActions.length, 1, "but the line is still logged, because a local run is a measurement too");
});

await test("and the file the publish job reads carries that recovered number, not the empty one", async () => {
  // The decision knowing the thread is not enough: `publish.yml` reads
  // `out/decision.json`, so the recovery has to survive being written down.
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const asset = conforming({ capabilities: ["tools", "tts"] });

  const first = await run({ root, assets: [asset], issue: 41 });
  const qfile = path.join(root, queueFile("dice-roller", "0.2.0"));
  fs.mkdirSync(path.dirname(qfile), { recursive: true });
  fs.writeFileSync(qfile, `${JSON.stringify(first.decision.queue_entry, null, 2)}\n`);

  const later = new Date(NOW.getTime() + (DELAY_HOURS + 1) * 3600000);
  const second = await run({ root, assets: [asset], now: later, issue: null });

  // Through `tmp`, which removes it at exit: an `rmSync` after the assertion
  // ran only when the assertion held, so every failing run left one behind.
  const out = tmp("astra-bot-drain-out-");
  writeOutputs(out, { repo: REPO, tag: TAG, issue: null }, second);
  const written = JSON.parse(fs.readFileSync(path.join(out, "decision.json"), "utf8"));
  assertEqual(written.issue, 41, "the drain answers the thread that asked for the release");
});

await test("a queue entry about a different release does not lend this one its issue", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const asset = conforming({ capabilities: ["tools", "tts"] });

  const first = await run({ root, assets: [asset], issue: 41 });
  const stale = { ...first.decision.queue_entry, tag: "v9.9.9", issue: 41 };
  const qfile = path.join(root, queueFile("dice-roller", "0.2.0"));
  fs.mkdirSync(path.dirname(qfile), { recursive: true });
  fs.writeFileSync(qfile, `${JSON.stringify(stale, null, 2)}\n`);

  const second = await run({ root, assets: [asset], issue: null });
  assertEqual(second.decision.issue, null,
    "the entry names another tag, so its thread is not this release's thread");
});

await test("when the delay has elapsed the same release publishes, and stops waiting", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const asset = conforming({ capabilities: ["tools", "tts"] });

  // Round one: it queues. Round two: the queue entry is on disk and the clock
  // has run out. The whole ingest runs again — this is not a resume.
  const first = await run({ root, assets: [asset] });
  const qfile = path.join(root, queueFile("dice-roller", "0.2.0"));
  fs.mkdirSync(path.dirname(qfile), { recursive: true });
  fs.writeFileSync(qfile, `${JSON.stringify(first.decision.queue_entry, null, 2)}\n`);

  const later = new Date(NOW.getTime() + (DELAY_HOURS + 1) * 3600000);
  const out = tmp("astra-policy-out-");
  const second = await run({ root, assets: [asset], now: later });
  assertEqual(second.decision.outcome, "publish", JSON.stringify(second.decision.reasons));
  assert(codes(second).includes("P_DELAY_ELAPSED"), JSON.stringify(codes(second)));
  writeOutputs(out, { repo: REPO, tag: TAG, issue: null }, second);
  assertEqual(fs.readFileSync(path.join(out, "remove.txt"), "utf8").trim(),
    queueFile("dice-roller", "0.2.0"), "and the queue entry is deleted by the same commit");
});

// `iso` is declared further down this file, and these run at import time.
const stamp = (d) => new Date(d).toISOString();

await test("a maintainer can bring the publication forward, which every entry has claimed", async () => {
  // Every queue entry this bot has ever written says "edit publish_after to
  // bring it forward". Nothing read the field: the deadline was recomputed
  // from `queued_at`, so an edited date moved only which entries triage picked
  // up, and the decision put them straight back. The instruction named an
  // action that did nothing.
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const asset = conforming({ capabilities: ["tools", "tts"] });

  const first = await run({ root, assets: [asset] });
  assertEqual(first.decision.outcome, "delay", "it has to be waiting before it can be brought forward");

  const qfile = path.join(root, queueFile("dice-roller", "0.2.0"));
  fs.mkdirSync(path.dirname(qfile), { recursive: true });
  fs.writeFileSync(qfile, `${JSON.stringify(
    { ...first.decision.queue_entry, publish_after: stamp(NOW) }, null, 2,
  )}\n`);

  const second = await run({ root, assets: [asset], now: new Date(NOW.getTime() + 60_000) });
  assertEqual(second.decision.outcome, "publish", JSON.stringify(second.decision.reasons));
  assert(codes(second).includes("P_DELAY_BROUGHT_FORWARD"),
    `the waiver went unrecorded: ${JSON.stringify(codes(second))}`);
});

await test("but only earlier — a date pushed out cannot park a release", async () => {
  // Earlier-only, so a mistyped year is a typo rather than an indefinite hold,
  // and so this field can never extend a window past what the policy decided.
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const asset = conforming({ capabilities: ["tools", "tts"] });

  const first = await run({ root, assets: [asset] });
  const qfile = path.join(root, queueFile("dice-roller", "0.2.0"));
  fs.mkdirSync(path.dirname(qfile), { recursive: true });
  fs.writeFileSync(qfile, `${JSON.stringify(
    { ...first.decision.queue_entry, publish_after: stamp(NOW.getTime() + 400 * 24 * 3600000) }, null, 2,
  )}\n`);

  const later = new Date(NOW.getTime() + (DELAY_HOURS + 1) * 3600000);
  const second = await run({ root, assets: [asset], now: later });
  assertEqual(second.decision.outcome, "publish",
    `a date pushed a year out held the release: ${JSON.stringify(second.decision.reasons)}`);
});

await test("a stale entry cannot shorten the window for bytes it was not written for", async () => {
  // An entry naming an earlier date must not survive the assets changing under
  // it, or swapping the release would inherit a waiver granted for something
  // else — which would turn the maintainer override into the swap attack the
  // same-bytes guard exists to stop.
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const first = await run({ root, assets: [conforming({ capabilities: ["tools", "tts"] })] });
  const qfile = path.join(root, queueFile("dice-roller", "0.2.0"));
  fs.mkdirSync(path.dirname(qfile), { recursive: true });
  fs.writeFileSync(qfile, `${JSON.stringify(
    { ...first.decision.queue_entry, publish_after: stamp(NOW) }, null, 2,
  )}\n`);

  const swapped = {
    name: bundleName(),
    bytes: makeBundle({ capabilities: ["tools", "tts"], extraFiles: [{ name: "extra.txt", data: "surprise" }] }),
  };
  const second = await run({ root, assets: [swapped], now: new Date(NOW.getTime() + 60_000) });
  assertEqual(second.decision.outcome, "delay",
    `swapped bytes inherited a waiver: ${JSON.stringify(second.decision.reasons)}`);
  assert(codes(second).includes("P_DELAY_BYTES_CHANGED"), JSON.stringify(codes(second)));
});

await test("an asset swapped during the window restarts the clock", async () => {
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const first = await run({ root, assets: [conforming({ capabilities: ["tools", "tts"] })] });
  const qfile = path.join(root, queueFile("dice-roller", "0.2.0"));
  fs.mkdirSync(path.dirname(qfile), { recursive: true });
  fs.writeFileSync(qfile, `${JSON.stringify(first.decision.queue_entry, null, 2)}\n`);

  const later = new Date(NOW.getTime() + (DELAY_HOURS + 1) * 3600000);
  const swapped = {
    name: bundleName(),
    bytes: makeBundle({ capabilities: ["tools", "tts"], extraFiles: [{ name: "extra.txt", data: "surprise" }] }),
  };
  const second = await run({ root, assets: [swapped], now: later });
  assertEqual(second.decision.outcome, "delay", JSON.stringify(second.decision.reasons));
  assert(codes(second).includes("P_DELAY_BYTES_CHANGED"), JSON.stringify(codes(second)));
  assertEqual(hours(second.decision.publish_after, later), DELAY_HOURS,
    "a swap timed for the last minute of the window buys the attacker nothing");
});

await test("a release the checks have since started refusing stops waiting", async () => {
  // The drain re-runs everything, so a queued release whose repository changed
  // hands the decision to a human — and the queue entry is removed rather than
  // left to be retried every hour for ever.
  const root = registryTree([{ repo: "someone-else/dice-roller", versions: [{ version: "0.1.0" }] }]);
  const out = tmp("astra-policy-out-");
  const r = await run({ root });
  assertEqual(r.decision.outcome, "review", "");
  writeOutputs(out, { repo: REPO, tag: TAG, issue: null }, r);
  assertEqual(fs.readFileSync(path.join(out, "remove.txt"), "utf8").trim(),
    queueFile("dice-roller", "0.2.0"), "");
});

section("the author's track record");

await test(`${CLEAN_RELEASES_FOR_TRUSTED} clean releases buy a shorter delay`, () => {
  const versions = Array.from({ length: CLEAN_RELEASES_FOR_TRUSTED }, (_, i) => ({
    version: `0.${i + 1}.0`, staging: false,
  }));
  const root = registryTree([{ id: "other-thing", versions }]);
  const { plugins } = requireSources(root);
  const record = trackRecord(root, REPO, { plugins });
  assertEqual(record.tier, "established", JSON.stringify(record));
  assertEqual(record.delay_hours, TRUSTED_DELAY_HOURS, "");
});

await test("a staging listing is not a clean release", () => {
  const root = registryTree([{ id: "other-thing", versions: [{ version: "0.1.0", staging: true }] }]);
  const { plugins } = requireSources(root);
  assertEqual(trackRecord(root, REPO, { plugins }).clean_releases, 0,
    "nobody could verify its artifact, so it is not evidence of anything");
});

await test("a revocation resets the counter, a yank does not", () => {
  const versions = Array.from({ length: CLEAN_RELEASES_FOR_TRUSTED + 2 }, (_, i) => ({
    version: `0.${i + 1}.0`, staging: false,
  }));
  const root = registryTree([{ id: "other-thing", versions }]);
  const { plugins } = requireSources(root);
  const revoked = trackRecord(root, REPO, {
    plugins,
    revocations: [{ plugin_id: "other-thing", version: "0.2.0" }],
  });
  assertEqual(revoked.tier, "new", JSON.stringify(revoked));
  assertEqual(revoked.delay_hours, DELAY_HOURS, "");
});

await test("the shorter delay actually reaches the decision", async () => {
  const versions = Array.from({ length: CLEAN_RELEASES_FOR_TRUSTED }, (_, i) => ({
    version: `0.${i + 1}.0`, staging: false,
  }));
  const root = registryTree([
    { versions: [{ version: "0.1.0", capabilities: ["tools"] }] },
    { id: "other-thing", repo: `${SUBMITTER}/other-thing`, versions },
  ]);
  const r = await run({ root, assets: [conforming({ capabilities: ["tools", "tts"] })] });
  assertEqual(r.decision.outcome, "delay", "");
  assertEqual(hours(r.decision.publish_after, NOW), TRUSTED_DELAY_HOURS, JSON.stringify(r.decision.track));
  assert(codes(r).includes("P_TRUSTED_AUTHOR"), JSON.stringify(codes(r)));
});

section("the identity verdict, before the policy has a say (B-T3.3a)");

/** A release that would otherwise publish itself with nobody in the loop. */
const cleanRelease = () => ({
  findings: [],
  derived: {
    plugin: { id: "astra-chess", source: { kind: "github", repo: "KNICE-TECH/astra-chess" } },
    version: { version: "0.1.18", capabilities: ["tools"], release: { repo: "KNICE-TECH/astra-chess", tag: "v0.1.18" } },
  },
  existing: { versions: [{ doc: { version: "0.1.17", capabilities: ["tools"] } }] },
  repo: "KNICE-TECH/astra-chess",
  tag: "v0.1.18",
  now: NOW,
});

const RECYCLED = {
  code: "B_REPOSITORY_RECYCLED",
  terminal: true,
  reason:
    "KNICE-TECH/astra-chess was baselined as repository 1343092393 (owner 280318216) and this release " +
    "attests repository 2000000001 (owner 2000000002) under the same name",
};

await test("B_REPOSITORY_RECYCLED refuses a release that would otherwise publish itself", () => {
  const d = decide({ ...cleanRelease(), identity: RECYCLED });
  assertEqual(d.outcome, "refuse", JSON.stringify(d.reasons));
  assert(d.reasons.some((r) => r.message.includes("B_REPOSITORY_RECYCLED")), JSON.stringify(d.reasons));
  assert(d.reasons.some((r) => r.message.includes("1343092393") && r.message.includes("2000000001")),
    "the refusal names both id pairs, or nobody can tell what happened");
});

await test("the recycled refusal is permanent: not a new tag, not an approval", () => {
  // ID-41 row 1 with OPEN-OWNER-15's answer. The refusal is about which
  // repository produced the bytes; a maintainer typing `/approve` has not
  // changed that, and neither has the author pushing another tag. Only
  // B-T4.2's identity reset lifts it.
  const underANewTag = decide({
    ...cleanRelease(), tag: "v0.1.19",
    derived: { plugin: { id: "astra-chess" }, version: { version: "0.1.19", capabilities: ["tools"] } },
    identity: RECYCLED,
  });
  assertEqual(underANewTag.outcome, "refuse", "a new tag is refused again");

  const approved = decide({
    ...cleanRelease(),
    identity: RECYCLED,
    approval: { by: "a-maintainer", at: "2026-09-19T10:00:00Z", for: "0".repeat(12) },
  });
  assertEqual(approved.outcome, "refuse", "an approval does not clear it");
  assertEqual(approved.approved_by, "a-maintainer",
    "and it is still recorded, so the thread and the record can be reconciled");
  assert(approved.reasons.some((r) => r.message.includes("permanent")), JSON.stringify(approved.reasons));
});

await test("a rename is a hold, not a refusal, and it names both id pairs", () => {
  // The identity module answers `R_IDENTITY_CHANGED` for a rename, a transfer
  // and a re-creation; the ingest raises it as a review finding, and the
  // policy's job is to hand it to a person rather than to rule on it.
  const d = decide({
    ...cleanRelease(),
    findings: [{
      level: "review", code: "R_IDENTITY_CHANGED", where: "version",
      message: "both ids are unchanged (1343092393/280318216) and the name moved from KNICE-TECH/astra-chess to MINICE-AI/astra-chess: a rename",
    }],
  });
  assertEqual(d.outcome, "review", JSON.stringify(d.reasons));
  assert(d.reasons.some((r) => r.code === "R_IDENTITY_CHANGED"), JSON.stringify(d.reasons));
});

await test("a transient identity read never becomes a decision", () => {
  // A wait is the reader's answer, not the policy's. A rate-limited
  // `fetchRepositoryIds` that reached `decide()` would be recorded as
  // something — and every one of the four outcomes is a record about a
  // repository nobody managed to look up.
  let threw = null;
  try {
    decide({ ...cleanRelease(), identity: { code: "W_GITHUB_RATE_LIMITED", reason: "HTTP 403 with rate-limit headers" } });
  } catch (e) {
    threw = e;
  }
  assert(threw, "a wait must not be turned into an outcome");
  assert(threw.message.includes("a read that did not happen is not a fact"), threw.message);
});

await test("no identity verdict changes nothing — the legacy path still decides", () => {
  const d = decide(cleanRelease());
  assertEqual(d.outcome, "publish", JSON.stringify(d.reasons));
});

section("the decision function on its own");

await test("an unknown permission is reported and not blocked", () => {
  const d = decide({
    findings: [],
    derived: {
      plugin: { id: "x" },
      version: { version: "1.0.0", capabilities: ["tools"], permissions: { teleport: {} } },
    },
    existing: { versions: [{ doc: { version: "0.9.0", capabilities: ["tools"] } }] },
    repo: REPO,
    now: NOW,
  });
  assert(d.reasons.some((r) => r.code === "P_UNKNOWN_PERMISSION"), JSON.stringify(d.reasons));
  assertEqual(d.outcome, "delay", "it is still a widening, so it still waits");
});

await test("capabilities and permissions are one question", () => {
  assertEqual(
    requestedAuthority({ capabilities: ["tools"], permissions: { fire_trigger: {}, tools: {} } }).join(","),
    "fire_trigger,tools",
    "declared twice is asked for once",
  );
});

await test("a backported patch is measured against the newest listing, not the last file", () => {
  const existing = {
    versions: [
      { doc: { version: "0.9.0", capabilities: ["tools", "dom_access"] } },
      { doc: { version: "0.10.0", capabilities: ["tools", "dom_access"] } },
    ],
  };
  const d = decide({
    findings: [],
    derived: { plugin: { id: "x" }, version: { version: "0.10.1", capabilities: ["tools", "dom_access"] } },
    existing, repo: REPO, now: NOW,
  });
  assertEqual(d.outcome, "delay", "held dom_access all along; delayed, not reviewed");
  assert(!d.reasons.some((r) => r.code === "R_NEW_HIGH_RISK"), JSON.stringify(d.reasons));
});

await test("every high-risk name blocks on first request", () => {
  for (const name of HIGH_RISK) {
    const d = decide({
      findings: [],
      derived: { plugin: { id: "x" }, version: { version: "1.0.0", permissions: { [name]: {} } } },
      existing: { versions: [{ doc: { version: "0.9.0" } }] },
      repo: REPO, now: NOW,
    });
    assertEqual(d.outcome, "review", `${name} must ask a person`);
  }
});

section("the review SLA, made visible");

await test("a queue past the breach threshold says what to do about it", () => {
  const report = slaReport([
    { number: 1, title: "[listing] a/b", created_at: "2026-08-01T00:00:00Z" },
    { number: 2, title: "[listing] c/d", created_at: "2026-08-10T06:00:00Z" },
  ], NOW);
  assertEqual(report.open, 2, "");
  assertEqual(report.late, 1, "");
  assertEqual(report.breached, 1, "");
  assert(report.verdict.includes("not \"review harder\""), report.verdict);
});

await test("an empty queue is within SLA and says so quietly", () => {
  assertEqual(slaReport([], NOW).verdict, "within SLA", "");
});

// ═══════════════════════════════════════════════════════════════════════════

section("the ping (task 3.4, layer 1)");

await test("/release takes one argument on a listing issue and two on a new one", () => {
  assertEqual(parseReleasePing("/release v0.2.0").tag, "v0.2.0", "");
  assertEqual(parseReleasePing("/release v0.2.0").repo, null, "one argument names no repository");
  const two = parseReleasePing("/release you/dice-roller v0.2.0");
  assertEqual(two.repo, "you/dice-roller", "");
  assertEqual(two.tag, "v0.2.0", "");
});

await test("people paste the address bar, and that is the same repository", () => {
  const p = parseReleasePing("/release `https://github.com/you/dice-roller.git/` v0.2.0");
  assertEqual(p.repo, "you/dice-roller", "");
});

await test("a mention is not a command", () => {
  assert(parseReleasePing("please /release v0.2.0 for me") === null, "");
  assert(parseReleasePing("/releases v0.2.0") === null, "");
  assert(parseReleasePing("") === null, "");
});

await test("a ping cannot smuggle a shell argument or a second repository", () => {
  assert(parseReleasePing("/release you/dice-roller v0.2.0; rm -rf /") === null, "");
  assert(parseReleasePing("/release ../../etc/passwd v1") === null, "");
  assert(parseReleasePing("/release you/dice-roller ../../evil") === null, "a `..` tag is not a tag");
});

await test("an unlabelled ping may only name a repository that is already listed", () => {
  const sources = requireSources(registryTree([{ versions: [{ version: "0.1.0" }] }]));
  assertEqual(findListingByRepo(sources, REPO).id, "dice-roller", "");
  assertEqual(findListingByRepo(sources, "A-Stranger/Dice-Roller").id, "dice-roller",
    "GitHub is case-insensitive here and so is the lookup");
  assertEqual(findListingByRepo(sources, "someone/unlisted"), null,
    "so the worst a stranger can do is re-check a listing that is already pinned");
});

section("the backstop (task 3.4, layer 2)");

await test("a listing that released recently is not polled at all", () => {
  const sources = requireSources(registryTree([
    { id: "fresh", versions: [{ version: "1.0.0", published_at: "2026-08-09T00:00:00Z" }] },
    { id: "quiet", repo: "someone/quiet", versions: [{ version: "1.0.0", published_at: "2026-01-01T00:00:00Z" }] },
  ]));
  const plan = watchPlan(sources, { repos: {} }, NOW);
  assertEqual(plan.quiet.length, 1, JSON.stringify(plan.quiet));
  assertEqual(plan.poll.length, 1, JSON.stringify(plan.poll));
  assertEqual(plan.poll[0].id, "quiet", `only listings quiet for ${WATCH_AFTER_DAYS} days cost anything`);
});

await test("an unlisted plugin is not watched", () => {
  const sources = requireSources(registryTree([
    { id: "gone", unlisted: true, versions: [{ version: "1.0.0", published_at: "2026-01-01T00:00:00Z" }] },
  ]));
  assertEqual(watchPlan(sources, { repos: {} }, NOW).poll.length, 0, "");
});

await test("the batch rotates oldest-checked first", () => {
  const sources = requireSources(registryTree(
    ["a", "b", "c"].map((id) => ({
      id, repo: `someone/${id}`, versions: [{ version: "1.0.0", published_at: "2026-01-01T00:00:00Z" }],
    })),
  ));
  const seen = { repos: {
    "someone/a": { last_checked: "2026-08-09T00:00:00Z" },
    "someone/b": { last_checked: "2026-06-01T00:00:00Z" },
  } };
  const plan = watchPlan(sources, seen, NOW, { batch: 2 });
  assertEqual(plan.poll.map((p) => p.id).join(","), "c,b", "never polled, then longest ago");
  assertEqual(plan.deferred.length, 1, "and the rest wait for the next run rather than being dropped");
});

await test("an unchanged repository costs one 304 and nothing else", async () => {
  let seenHeader = null;
  const res = await pollFeed("someone/quiet", 'W/"abc"', async (url, init) => {
    seenHeader = init.headers["If-None-Match"];
    return { status: 304, ok: false, headers: new Map(), text: async () => { throw new Error("a 304 has no body"); } };
  });
  assertEqual(seenHeader, 'W/"abc"', "the etag is fed back");
  assertEqual(res.changed, false, "");
  assertEqual(res.entries.length, 0, "");
});

const ATOM = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>tag:github.com,2008:Repository/1/v0.3.0</id>
    <updated>2026-08-08T10:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/someone/quiet/releases/tag/v0.3.0"/>
    <title>v0.3.0</title>
  </entry>
  <entry>
    <id>tag:github.com,2008:Repository/1/v0.2.0</id>
    <updated>2026-01-01T10:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/someone/quiet/releases/tag/v0.2.0"/>
    <title>v0.2.0</title>
  </entry>
  <entry>
    <updated>2026-08-09T10:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/attacker/elsewhere/releases/tag/v9.9.9"/>
    <title>not ours</title>
  </entry>
</feed>`;

await test("the feed parse takes four fields and refuses another repository's releases", () => {
  const entries = parseReleasesAtom(ATOM, "someone/quiet");
  assertEqual(entries.map((e) => e.tag).join(","), "v0.3.0,v0.2.0", "newest first, ours only");
  assertEqual(entries[0].updated, "2026-08-08T10:00:00Z", "");
});

await test("a release already listed, or already tried, is not re-ingested", () => {
  const entries = parseReleasesAtom(ATOM, "someone/quiet");
  assertEqual(newReleases({ listed_tag: "v0.2.0" }, entries, {}).map((e) => e.tag).join(","), "v0.3.0", "");
  assertEqual(newReleases({ listed_tag: "v0.2.0" }, entries, { checked_tags: ["v0.3.0"] }).length, 0,
    "a release this registry refused is not retried every hour for ever");
});

await test("the backstop finds a missed release and hands it to the pipeline", async () => {
  const root = registryTree([
    { id: "quiet", repo: "someone/quiet", versions: [{ version: "0.2.0", tag: "v0.2.0", published_at: "2026-01-01T00:00:00Z" }] },
  ]);
  const { dispatch, seen, log } = await runWatch({
    root,
    now: NOW,
    deps: {
      fetchImpl: async () => ({
        status: 200, ok: true,
        headers: new Map([["etag", 'W/"new"']]),
        text: async () => ATOM,
      }),
      fetchRelease: async (repo, tag) => ({ tag_name: tag, author: { login: "the-author" } }),
    },
  });
  assertEqual(dispatch.length, 1, JSON.stringify(log));
  assertEqual(dispatch[0].repo, "someone/quiet", "");
  assertEqual(dispatch[0].tag, "v0.3.0", "");
  assertEqual(dispatch[0].submitter, "the-author",
    "the ownership that gets proved is the release author's, never the pinger's");
  assertEqual(seen.repos["someone/quiet"].last_seen_tag, "v0.3.0", "and it is remembered");
});

await test("a repository that has gone away is recorded, not fatal", async () => {
  const root = registryTree([
    { id: "quiet", repo: "someone/quiet", versions: [{ version: "0.2.0", published_at: "2026-01-01T00:00:00Z" }] },
  ]);
  const { dispatch, seen } = await runWatch({
    root, now: NOW,
    deps: { fetchImpl: async () => ({ status: 404, ok: false, headers: new Map(), text: async () => "" }) },
  });
  assertEqual(dispatch.length, 0, "");
  assert(seen.repos["someone/quiet"].last_error.includes("404"), JSON.stringify(seen.repos));
});

section("the drain");

await test("only a ripe queue entry is dispatched, and the rest are reported", () => {
  const root = tmp("astra-policy-queue-");
  fs.mkdirSync(path.join(root, "state", "queue"), { recursive: true });
  const write = (id, version, publishAfter) =>
    fs.writeFileSync(path.join(root, queueFile(id, version)), `${JSON.stringify({
      id, version, repo: `someone/${id}`, tag: `v${version}`, submitter: "someone",
      queued_at: "2026-08-09T12:00:00Z", publish_after: publishAfter, reason: "P_DELAY_HIGH_RISK",
    })}\n`);
  write("ripe-one", "1.0.0", "2026-08-10T11:00:00Z");
  write("still-waiting", "2.0.0", "2026-08-11T11:00:00Z");

  assertEqual(readQueue(root).length, 2, "both are visible to a maintainer");
  const { dispatch, log } = runDrain({ root, now: NOW });
  assertEqual(dispatch.length, 1, JSON.stringify(dispatch));
  assertEqual(dispatch[0].repo, "someone/ripe-one", "");
  assertEqual(dispatch[0].submitter, "someone", "whose ownership is proved again on the way in");
  assert(log.some((l) => l.includes("wait") && l.includes("still-waiting")), log.join("\n"));
});

section("what the workflow asks before it spends anything");

/** Write two bodies to files, the way `.github/workflows/ingest.yml` does. */
function bodies({ issue = "", comment = "" }) {
  const dir = tmp("astra-policy-body-");
  fs.writeFileSync(path.join(dir, "issue.md"), issue);
  fs.writeFileSync(path.join(dir, "comment.md"), comment);
  return { issueBody: path.join(dir, "issue.md"), commentBody: path.join(dir, "comment.md") };
}

const FORM = [
  "### Source repository", "", REPO, "",
  "### Release tag carrying the .astraplugin assets", "", TAG, "",
  "### Confirmations", "",
  "- [X] I own or maintain this repository.",
].join("\n");

const releaseBy = (login) => async (repo, tag) => ({ tag_name: tag, author: { login } });

await test("a labelled listing issue is still the submission form's", async () => {
  const out = await triage({
    event: "issues", labels: "listing,needs-triage", root: registryTree([{}]),
    ...bodies({ issue: FORM }),
  }, releaseBy("a-stranger"));
  assertEqual(out.mode, "form", out.why);
});

await test("`/release v0.2.0` on a listing issue takes the repository from the issue", async () => {
  const out = await triage({
    event: "issue_comment", labels: "listing", root: registryTree([{}]),
    ...bodies({ issue: FORM, comment: "/release v0.3.0" }),
  }, releaseBy("the-author"));
  assertEqual(out.mode, "ping", out.why);
  assertEqual(out.repo, REPO, "named by the issue, not by whoever commented");
  assertEqual(out.tag, "v0.3.0", "");
  assertEqual(out.submitter, "the-author", "the release author, never the pinger");
});

await test("an unlabelled ping is honoured only for a listing that already exists", async () => {
  const root = registryTree([{}]);
  const listed = await triage({
    event: "issues", labels: "", root,
    ...bodies({ issue: `/release ${REPO} v0.3.0\n\nnew release!` }),
  }, releaseBy("the-author"));
  assertEqual(listed.mode, "ping", listed.why);

  const stranger = await triage({
    event: "issues", labels: "", root,
    ...bodies({ issue: "/release somebody/brand-new v1.0.0" }),
  }, releaseBy("the-author"));
  // `none` until the intake fix: a stranger's ping for an unlisted repository
  // still starts nothing — that restriction is what makes a ping safe to accept
  // without a token — but it is now a `reply` rather than a silence, and the
  // reply is what points at the form a first listing actually goes through.
  assertEqual(stranger.mode, "reply", "a first listing is not reachable this way");
  assert(stranger.why.includes("template"), stranger.why);
  assert(stranger.reply.includes("already listed"), stranger.reply);
  assert(!stranger.repo && !stranger.tag, "and nothing is queued for verification");
});

await test("a release ping survives being rendered by an issue form", async () => {
  // `.github/ISSUE_TEMPLATE/config.yml` turned blank issues off, so the
  // ping-as-a-new-issue path docs/POLICY.md §5 promises now goes through
  // `release-ping.yml` — and GitHub renders every form as `### <label>`, a
  // blank line, then the value. Under the old first-line-only rule the command
  // was never on line 1 again and the path stopped working the day the form
  // became mandatory.
  const rendered = "### The command\n\n/release " + REPO + " v0.3.0\n";
  const out = await triage({
    event: "issues", labels: "", root: registryTree([{}]),
    ...bodies({ issue: rendered }),
  }, releaseBy("the-author"));
  assertEqual(out.mode, "ping", out.why);
  assertEqual(out.tag, "v0.3.0", "");

  // And the relaxation is exactly two things — a blank line and a heading.
  // Prose above the command still hides it, which is what stops a quoted reply
  // from re-triggering an ingest.
  const prose = await triage({
    event: "issues", labels: "", root: registryTree([{}]),
    ...bodies({ issue: `here you go\n\n/release ${REPO} v0.3.0` }),
  }, releaseBy("the-author"));
  assert(prose.mode !== "ping", `prose above the command must not run it: ${prose.mode}`);
});

await test("/recheck still means recheck, and prose still means nothing", async () => {
  const root = registryTree([{}]);
  assertEqual((await triage({
    event: "issue_comment", labels: "listing", root, ...bodies({ issue: FORM, comment: "/recheck" }),
  }, releaseBy("x"))).mode, "form", "");
  assertEqual((await triage({
    event: "issue_comment", labels: "listing", root,
    ...bodies({ issue: FORM, comment: "any news on this? maybe /release it" }),
  }, releaseBy("x"))).mode, "none", "");
});

await test("a ping for a tag that has no release is dropped, not ingested", async () => {
  const out = await triage({
    event: "issues", labels: "", root: registryTree([{}]),
    ...bodies({ issue: `/release ${REPO} v9.9.9` }),
  }, async () => { throw new Error("no release tagged v9.9.9 (404)"); });
  assertEqual(out.mode, "none", out.why);
  assert(out.why.includes("404"), out.why);
});

// ═══════════════════════════════════════════════════════════════════════════
//
// Defect 1: a submission that reached this registry and was answered with
// nothing at all. Two of them, `#13` and `#14`. Both carried the rendered form
// and zero labels, because there was no `.github/ISSUE_TEMPLATE/config.yml` and
// blank issues were on, so they bypassed the template that applies the label.
// `triage` answered `none`, `targets=[]`, every later job was skipped, and the
// run went green — it had succeeded at deciding to do nothing.

section("no listing request is answered with silence");

/** The two facts, both boxes, and nothing else — a form GitHub has rendered. */
const form = ({ repo = REPO, tag = TAG, boxes = 2, headings = true } = {}) => [
  ...(headings ? ["### Source repository", "", repo, ""] : [repo, ""]),
  ...(headings ? ["### Release tag carrying the .astraplugin assets", "", tag, ""] : [tag, ""]),
  "### Confirmations", "",
  `- [${boxes >= 1 ? "x" : " "}] I own or maintain this repository.`,
  `- [${boxes >= 2 ? "x" : " "}] I have read POLICY.md, including the data-handling section.`,
].join("\n");

/**
 * `mihailinl/astra-registry#14`, verbatim, as `gh issue view 14 --json body`
 * returned it on 2026-08-12 — trimmed only of the prose paragraph, which the
 * bot never reads.
 *
 * Embedded rather than fetched: this suite touches no network, and a regression
 * test that needs GitHub to be up is a regression test that goes quiet on the
 * day the network is the problem. The title and the empty label array are the
 * two facts that mattered.
 */
const ISSUE_14 = {
  title: "[listing] Rel0d1x/command-intent-guard",
  labels: "",
  body: [
    "### Source repository", "", "Rel0d1x/command-intent-guard", "",
    "### Release tag carrying the .astraplugin assets", "", "v0.1.0", "",
    "### What does it do, and why should it be listed?", "",
    "Adds a `tools` capability that tells a spoken command apart from a question.", "",
    "### Confirmations", "",
    "- [x] I own or maintain this repository.",
    "- [x] I have read POLICY.md, including the data-handling section.",
  ].join("\n"),
};

/** The three files the workflow writes, plus the arguments it passes with them. */
function intake({ issue = "", comment = "", title = "", labels = "", action = "opened", event = "issues", root, ...rest }) {
  const dir = tmp("astra-policy-intake-");
  fs.writeFileSync(path.join(dir, "issue.md"), issue);
  fs.writeFileSync(path.join(dir, "comment.md"), comment);
  fs.writeFileSync(path.join(dir, "title.md"), title);
  return {
    event, action, labels, root: root ?? registryTree([{}]),
    registry: "mihailinl/astra-registry",
    issueBody: path.join(dir, "issue.md"),
    commentBody: path.join(dir, "comment.md"),
    issueTitle: path.join(dir, "title.md"),
    ...rest,
  };
}

await test("the real #14 — the form, no labels — no longer decides `none`", async () => {
  const out = await triage(intake({
    issue: ISSUE_14.body, title: ISSUE_14.title, labels: ISSUE_14.labels,
    root: registryTree([{ id: "something-else" }]),
  }), releaseBy("Rel0d1x"));
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("Rel0d1x/command-intent-guard"),
    "the reply has to name the repository the author asked about");
  assert(out.reply.includes("v0.1.0"), "and the tag");
});

await test("the reply names the label, the one click, and why the bot will not click it", async () => {
  const out = await triage(intake({ issue: form(), title: "[listing] a-stranger/dice-roller" }),
    releaseBy("a-stranger"));
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("`listing` label"), "the missing thing has a name");
  assert(/one click/i.test(out.reply), "and a fix that is one action, not a resubmission");
  assert(out.reply.includes("authority token"),
    "an author told to go and ask somebody, with no reason, assumes the bot is broken");
  // The whole argument for replying instead of auto-labelling: the label is an
  // exemption from the already-listed rule, so minting it from the shape of a
  // body would let a stranger choose which repositories this registry
  // downloads archives from.
  assertEqual(out.mode !== "form", true, "and nothing was verified for a repository nobody proved");
});

await test("either signal alone is enough: a rewritten title, or a rewritten body", async () => {
  const titleOnly = await triage(intake({ issue: "please list my plugin, thanks", title: "[listing] me/mine" }),
    releaseBy("me"));
  assertEqual(titleOnly.mode, "reply", titleOnly.why);

  const bodyOnly = await triage(intake({ issue: form(), title: "can you add this one" }), releaseBy("me"));
  assertEqual(bodyOnly.mode, "reply", bodyOnly.why);
});

await test("an ordinary issue is still free, and still silent", async () => {
  const out = await triage(intake({ issue: "the website is down", title: "site 500s" }), releaseBy("x"));
  assertEqual(out.mode, "none", out.why);
  assertEqual(out.reply, undefined, "no comment, no API call, no noise");
});

await test("the bot does not answer its own notices, or the other three forms", async () => {
  for (const title of [
    "[notice] dice-roller 0.2.0 publishes itself at 2026-08-11T12:00:00Z",
    "[appeal] dice-roller",
    "[report] dice-roller",
  ]) {
    const out = await triage(intake({ issue: form(), title }), releaseBy("x"));
    assertEqual(out.mode, "none", `${title} → ${out.why}`);
  }
});

await test("the intake comment is posted once, not on every edit", async () => {
  const opened = await triage(intake({ issue: form(), title: "[listing] x/y", action: "opened" }), releaseBy("x"));
  assertEqual(opened.mode, "reply", opened.why);
  const edited = await triage(intake({ issue: form(), title: "[listing] x/y", action: "edited" }), releaseBy("x"));
  assertEqual(edited.mode, "none", "a bot that repeats itself on every edit is a bot people mute");
});

await test("a labelled form the bot cannot read gets a comment, not a red X", async () => {
  // `bot/read-submission.mjs` exits 2 on an unticked confirmation, and the
  // workflow step runs under `set -e`. That killed the step: no target, no
  // comment job, and a submitter who ticked one box instead of two got a red X
  // and silence. Triage now answers the same question with the same parser
  // first.
  const out = await triage(intake({ issue: form({ boxes: 1 }), title: "[listing] x/y", labels: "listing" }),
    releaseBy("x"));
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("POLICY.md"), "and it names the box that is not ticked");
  assert(out.reply.includes("Edit this issue"), "with a fix that is not 'open a new one'");
});

await test("the release-ping form with a broken command is answered too", async () => {
  const out = await triage(intake({
    issue: "### The command\n\n/release i-forgot-the-tag\n",
    title: "[release] owner/repo v0.0.0",
  }), releaseBy("x"));
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("/release owner/repo v0.2.0"), "and shows the shape that works");
});

// ═══════════════════════════════════════════════════════════════════════════
//
// Defect 2: `outcome: "review"` was a terminus. The bot said "held for a
// maintainer", `decide.mjs` exited 3, and nothing in this repository
// implemented the maintainer's next move — `git grep -nE "/approve|approved-by"`
// over `bot/`, `docs/` and `.github/` returned nothing.

section("the maintainer's two commands");

/** `bot/lib/maintainer.mjs`, answered from a table instead of from GitHub. */
const roles = (table) => async ({ repo, login }) => {
  const role = table[login];
  if (role === undefined) {
    return {
      ok: false,
      role: null,
      detail: `GitHub would not say what @${login} has on ${repo} (HTTP 403 — not visible to the bot), so the command is refused.`,
    };
  }
  if (role === "admin" || role === "maintain") {
    return { ok: true, role, detail: `GitHub reports @${login} has \`${role}\` on ${repo}` };
  }
  return {
    ok: false,
    role,
    detail: `GitHub reports @${login} has \`${role}\` on ${repo}, which is neither \`admin\` nor \`maintain\`.`,
  };
};

const MAINTAINERS = roles({ "the-maintainer": "admin", "a-second-pair-of-eyes": "maintain", "a-stranger": "read", "a-triager": "triage" });

const command = (text, commenter, extra = {}) => triage(
  intake({
    event: "issue_comment", action: "created", labels: "listing",
    issue: form(), title: "[listing] a-stranger/dice-roller",
    comment: text, commenter, issueAuthor: SUBMITTER, now: NOW, ...extra,
  }),
  releaseBy(SUBMITTER),
  { proveMaintainer: extra.prove ?? MAINTAINERS },
);

await test("/approve from somebody with no write access is refused, and told why", async () => {
  const out = await command("/approve", "a-stranger");
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("`/approve` is refused"), out.reply);
  assert(out.reply.includes("`read`"), "the role GitHub actually reported, not a shrug");
  assert(out.reply.includes("author_association"),
    "and the reason the obvious cheaper check was not the one used");
  assert(!out.repo && !out.tag, "and no target — nothing was verified and nothing published");
});

await test("a `triage` collaborator is not a maintainer either", async () => {
  // The exact case `author_association` gets wrong: the event payload calls
  // this account `COLLABORATOR`, and it cannot push a byte to this repository.
  const out = await command("/approve", "a-triager");
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("`triage`"), out.reply);
});

await test("when GitHub will not answer, the command fails closed", async () => {
  const out = await command("/approve", "somebody-unknown");
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("would not say"), out.reply);
  // `proveOwnership` treats a missing answer as "no answer" and falls through
  // to weaker proofs, because refusing every organisation that has not
  // installed an app would make third-party publishing theoretical. There is no
  // equivalent argument here: one repository, this bot's own token, and the
  // cost of being wrong is a published listing rather than a refused one.
  assert(!out.repo, "and no target is emitted on a permission nobody could read");
});

// The real `proveMaintainer`, against a stubbed `fetch`. Every test above
// injects a stub for it, which is exactly why the endpoint's own behaviour went
// unexercised for so long: `GET /collaborators/{login}/permission` is
// documented as requiring push access, the triage job's `GITHUB_TOKEN` holds
// `contents: read`, and `administration` is not a scope a workflow token can
// request — so from here a 403 was entirely plausible, and no stubbed test
// could tell. It took a live run to find out. Registry issue #93, run
// 35487527105, 2026-09-20: `collaborator-permission: answered=true outcome=role
// is 'admin'`. B-T0.4a is that measurement, B-T0.4b is the deletion it
// authorised, and the three tests below are what the deletion changed.
const respond = (status, body) => async () => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body ?? {},
});

await test("a silent permission endpoint refuses everybody, the repository's owner included", async () => {
  // What the `OWNER` fallback used to do here: return `ok: true, role: "owner"`
  // for a 403 plus `author_association: OWNER`. It was a happy path for a
  // silence that the measurement says does not happen — so what is left is the
  // fail-closed refusal this module always gave everybody else, and the module
  // no longer has a second way to say yes.
  const denied = await proveMaintainer({
    repo: REGISTRY_REPO, login: "the-maintainer", fetchImpl: respond(403),
  });
  assertEqual(denied.ok, false, denied.detail);
  assertEqual(denied.role, null, "and no role is invented out of a silence");
  assertEqual(denied.answered, false, "the probe still reports which it was");
  assert(denied.detail.includes("would not say"), denied.detail);
  // A refusal, not a crash and not a bare `false`: whoever reads it has to be
  // able to tell an unreadable endpoint from a `read` role, because the two
  // have different fixes.
  assert(/re-run|pull request/i.test(denied.detail),
    `a refusal on an outage has to name the way round it: ${denied.detail}`);
});

await test("no `author_association` value is a permission any more, `OWNER` included", async () => {
  // The floor matters: `association` is no longer a parameter, so a loop that
  // passed nothing would pass vacuously. Every value the payload can carry is
  // enumerated, `OWNER` first, and each is handed in the way the caller used
  // to hand it in.
  const values = ["OWNER", "COLLABORATOR", "MEMBER", "CONTRIBUTOR", "NONE", "", null];
  assert(values.includes("OWNER") && values.length === 7,
    "the enumeration is what this test is; shrinking it silently is the failure mode");
  for (const association of values) {
    const silent = await proveMaintainer({
      repo: REGISTRY_REPO, login: "the-maintainer", association, fetchImpl: respond(403),
    });
    assertEqual(silent.ok, false, `${association} must not stand in for a permission`);
    assertEqual(silent.role, null, `${association}`);

    // And it does not subtract either: an answered `admin` is still an
    // approval, whatever the payload said about the commenter.
    const answered = await proveMaintainer({
      repo: REGISTRY_REPO, login: "the-maintainer", association,
      fetchImpl: respond(200, { role_name: "admin" }),
    });
    assertEqual(answered.ok, true, `${association}: ${answered.detail}`);
    assertEqual(answered.role, "admin", `${association}`);
  }
});

await test("an answered `read` is still a denial, which is what it always was", async () => {
  const out = await proveMaintainer({
    repo: REGISTRY_REPO, login: "a-stranger", fetchImpl: respond(200, { role_name: "read" }),
  });
  assertEqual(out.ok, false, out.detail);
  assertEqual(out.role, "read", "");
});

await test("no workflow reads `author_association`, and the scan has a floor", () => {
  // B-T0.4b's second canary. The plan puts it in `workflows.test.mjs`; that
  // file belongs to another lane this wave, so it lives here until it can be
  // moved, and moving it is a cut-and-paste — it imports nothing from this
  // suite.
  //
  // The coupling it guards: `bot/lib/maintainer.mjs` no longer accepts an
  // `association`, and `bot/triage.mjs` no longer parses
  // `--commenter-association`. A workflow that still exported
  // `github.event.comment.author_association` would either be dead YAML or,
  // worse, the first half of somebody reintroducing the fallback.
  const dir = path.join(REPO_ROOT, ".github", "workflows");
  const files = fs.readdirSync(dir).filter((n) => n.endsWith(".yml") || n.endsWith(".yaml"));

  // The floor, written before the assertion and measured against what git
  // actually tracks — a `readdirSync` of a renamed directory returns [] and an
  // empty scan reads exactly like a pass.
  const tracked = execFileSync("git", ["ls-files", ".github/workflows"], { cwd: REPO_ROOT, encoding: "utf8", env: cleanEnv() })
    .split("\n").filter((l) => /\.ya?ml$/.test(l));
  assertEqual(files.length, tracked.length,
    `scanned ${files.length} workflow file(s), git tracks ${tracked.length} — the scan is reading the wrong place`);
  assert(files.length >= 8, `only ${files.length} workflow(s) found; this scan has stopped covering the estate`);

  for (const name of files) {
    const body = fs.readFileSync(path.join(dir, name), "utf8");
    for (const [i, line] of body.split("\n").entries()) {
      if (line.trim().startsWith("#")) continue;
      assert(!line.includes("author_association"),
        `${name}:${i + 1} reads author_association, which B-T0.4b removed from this pipeline:\n  ${line.trim()}`);
      assert(!line.includes("--commenter-association"),
        `${name}:${i + 1} passes --commenter-association, an argument bot/triage.mjs no longer accepts:\n  ${line.trim()}`);
    }
  }
});

/** A fingerprint of the right shape. Whether it names these bytes is decided later. */
const FP = "0123456789abcdef";

await test("/approve from a maintainer emits a target carrying the approval, and nothing else", async () => {
  const out = await command(`/approve ${REPO}@${TAG} ${FP}`, "the-maintainer");
  assertEqual(out.mode, "approve", out.why);
  assertEqual(out.repo, REPO, "");
  assertEqual(out.tag, TAG, "");
  assertEqual(out.submitter, SUBMITTER, "the issue author, whose ownership is proved again downstream");
  assertEqual(out.approvedBy, "the-maintainer", "");
  assertEqual(out.approvedFor, FP, "and what it is an approval OF");
  assert(/^2026-/.test(out.approvedAt), out.approvedAt);
  // The property the whole design rests on: an approval is a name, a moment, and
  // the name of a submission. No verdict, no digest, no listing — so there is no
  // second, shorter route into the catalogue for a release somebody said yes to.
  assert(!("findings" in out) && !("derived" in out) && !("decision" in out),
    `an approval must carry no verification with it: ${Object.keys(out).join(", ")}`);
});

// ── an approval is bound to the submission it approves ──────────────────────
//
// The hole: `decideCommand` re-parses the issue body at the moment the
// `/approve` comment is processed, and the author owns that body. Hold the
// submission, wait for the maintainer to read it, edit the two form fields, and
// the yes lands on a release nobody looked at. Nothing downstream could catch
// it — every check would then pass, honestly, against the substituted
// repository, and the audit record would name a maintainer who never saw it.

await test("a bare /approve no longer approves whatever the issue says today", async () => {
  const out = await command("/approve", "the-maintainer");
  assertEqual(out.mode, "reply", out.why);
  assert(!out.repo && !out.tag, "and emits no target at all");
  assert(out.reply.includes("has to name what it is approving"), out.reply);
  assert(out.reply.includes("the issue body belongs to the author"),
    "and says why the bare word stopped being enough");
});

await test("an approval for a submission this issue no longer describes is refused, loudly", async () => {
  // The whole defect in one call: the maintainer read `a-stranger/dice-roller
  // v0.2.0` and typed a command naming it; by the time the comment is processed
  // the form says something else entirely.
  const out = await command(`/approve ${REPO}@${TAG} ${FP}`, "the-maintainer", {
    issue: form({ repo: "someone-else/not-what-you-read", tag: "v9.9.9" }),
  });
  assertEqual(out.mode, "reply", out.why);
  assert(!out.repo && !out.tag,
    "no target: an approval that cannot be matched to a submission must not start an ingest");
  assert(out.reply.includes("no longer describes what you approved"), out.reply);
  assert(out.reply.includes(REPO) && out.reply.includes("someone-else/not-what-you-read"),
    "and shows both, because which of the two is the surprise is the maintainer's call");
});

/**
 * A queue entry, written where `readQueue` looks for it.
 *
 * A real file rather than a stubbed dependency: the thing under test is
 * "does a maintainer's line match something this registry is holding", and a
 * stub would have asserted that the code calls a function rather than that the
 * two halves agree about where the queue lives.
 */
function queued(root, { repo = REPO, tag = "v0.3.2", id = "dice-roller", version = "0.3.2" } = {}) {
  const dir = path.join(root, "state", "queue");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}@${version}.json`), JSON.stringify({
    id, version, repo, tag,
    submitter: SUBMITTER,
    queued_at: "2026-08-20T17:26:42Z",
    publish_after: "2026-08-21T17:26:42Z",
    delay_hours: 24,
    reason: "P_DELAY_HIGH_RISK",
  }));
  return root;
}

await test("/publish works for an UPDATE, whose tag the issue body never names", async () => {
  // The defect this exists to stop, end to end: a listed plugin's second
  // release arrives as a `/release` ping, is verified, is queued for the delay,
  // and the bot posts the line to publish it now. The issue body still names
  // the tag of the FIRST listing, because nothing ever rewrites it — so the
  // line the bot printed was refused for describing "something this issue no
  // longer describes", every time, for every plugin, for every release after
  // the first.
  const root = queued(registryTree([{}]));
  const out = await command(`/publish ${REPO}@v0.3.2 ${FP}`, "the-maintainer", { root });
  assertEqual(out.mode, "approve", out.why);
  assertEqual(out.tag, "v0.3.2", "the target is the tag the maintainer named, not the body's");
  assertEqual(out.publishNow, true, "and /publish still waives the delay");
  assertEqual(out.approvedFor, FP, "and still carries the fingerprint the bytes are checked against");
});

await test("a queue entry for a DIFFERENT tag does not let the command through", async () => {
  // The relaxation is "this exact release is one we are holding", not "this
  // repository has something in the queue". Without this the fix would turn one
  // pending release into a skeleton key for any tag of the same repository.
  const root = queued(registryTree([{}]), { tag: "v0.3.2" });
  const out = await command(`/publish ${REPO}@v9.9.9 ${FP}`, "the-maintainer", { root });
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("no longer describes"), out.reply);
  assert(!out.repo && !out.tag, "and no target");
});

await test("an empty queue still refuses a tag the issue does not name", async () => {
  // The original guard, unchanged. Constructed rather than assumed: with no
  // queue directory at all, `readQueue` returns [] and the refusal is reached
  // by the same path it always was.
  const out = await command(`/publish ${REPO}@v0.3.2 ${FP}`, "the-maintainer", {
    root: registryTree([{}]),
  });
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("no longer describes"), out.reply);
});

await test("a tag edited under a hold is caught too, not just a repository", async () => {
  const out = await command(`/approve ${REPO}@${TAG} ${FP}`, "the-maintainer", {
    issue: form({ tag: "v0.3.0" }),
  });
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("no longer describes"), out.reply);
});

await test("a line that is nearly the command is not the command", async () => {
  for (const line of [
    `/approve ${REPO} ${FP}`,             // no tag
    `/approve ${REPO}@${TAG}`,            // no fingerprint
    `/approve ${REPO}@${TAG} not-a-hash`, // not a fingerprint
    `/approve ${REPO}@${TAG} ${FP} and also ship it`,
  ]) {
    const out = await command(line, "the-maintainer");
    assertEqual(out.mode, "reply", `${line} → ${out.why}`);
    assert(out.reply.includes("has to name what it is approving"), line);
  }
});

await test("the permission is still asked first, so a stranger learns nothing from the shape", async () => {
  // Ordering matters for the same reason it did before: an account that may not
  // decide must get the same answer whatever it typed, or the bot becomes an
  // oracle for what a well-formed command looks like.
  const out = await command("/approve", "a-stranger");
  assert(out.reply.includes("`/approve` is refused"), out.reply);
  assert(!out.reply.includes("has to name what it is approving"), out.reply);
});

await test("/reject with no reason changes nothing and says so", async () => {
  const out = await command("/reject", "the-maintainer");
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("needs a reason"), out.reply);
  assert(out.reply.includes("Nothing has been closed"), out.reply);
});

await test("/reject closes the loop for the author: the reason, and what to do next", async () => {
  const out = await command("/reject the licence is not one this registry allows", "a-second-pair-of-eyes");
  assertEqual(out.mode, "reject", out.why);
  assertEqual(out.close, true, "the issue leaves the review queue");
  assertEqual(out.by, "a-second-pair-of-eyes", "");
  assert(out.reply.includes("the licence is not one this registry allows"),
    "the reason is quoted back on the thread, which is the whole point of the command");
  assert(out.reply.includes("open a fresh listing request"), "a rejection is not permanent");
  assert(!out.repo, "and nothing is ingested");
});

await test("a command on an issue with nothing to decide about says so", async () => {
  const out = await command("/approve", "the-maintainer", {
    issue: "the website is down", title: "site 500s", labels: "",
  });
  assertEqual(out.mode, "reply", out.why);
  assert(out.reply.includes("nothing to act on"), out.reply);
});

await test("prose that mentions the command is not the command", async () => {
  const out = await command("I think we should /approve this one", "the-maintainer");
  assert(out.mode !== "approve", `${out.mode}: ${out.why}`);
});

await test("a quoted reply does not re-run the command", async () => {
  const out = await command("> /approve\n\nno, not yet", "the-maintainer");
  assert(out.mode !== "approve", `${out.mode}: ${out.why}`);
});

// ═══════════════════════════════════════════════════════════════════════════
//
// B-T0.2 stage 1: a hold raised OFF the listing issue.
//
// Every test above goes through `command()`, which hardcodes
// `labels: "listing"` and `title: "[listing] a-stranger/dice-roller"` — so the
// whole of the section above proves only that the commands work on the one
// thread shape they were written for. That is why the defect survived: a
// listed plugin's second release is held on a `[notice]` issue the bot opens
// itself, with no label and a title `looksLikeListing` excludes by name, and
// `decideCommand`'s `!labelled && !shape.shaped` early return answered the
// copy-paste line the same bot had just printed with "an issue that is not a
// listing request". Reproduced before it was fixed, on a tree where
// `a-stranger/dice-roller` is listed and the commenter proves `admin`:
//
//     { "mode": "reply", "why": "/approve on an issue that is not a listing request" }
//
// and live, where issue #74 prints
// `/approve dwertyfa288/dwertyfa-astra-tg@v0.1.15 be6bc6b4f4139c5d` on a
// thread nothing would ever have read it off.
//
// `command()` stays as it is — it is the listing-issue path, and that path did
// not change. These use a sibling that names the thread instead.

section("a hold raised off the listing issue (B-T0.2)");

/** The bot's own `[notice]` title, in the shape `bot/comment.mjs` writes it. */
const NOTICE_TITLE = "[notice] dice-roller 0.2.0 publishes itself at 2026-08-11T12:00:00Z";

/**
 * `command()`'s sibling, for threads that are not listing requests.
 *
 * No `listing` label and no `[listing]` title, because those are the two things
 * a `[notice]` does not have; the body is the bot's notice rather than a form,
 * for the same reason. Everything else — the permission stub, the clock, the
 * release — is the same, so a difference in the result is a difference in the
 * thread and nothing else.
 */
const onThread = (text, commenter, { title = NOTICE_TITLE, issueAuthor = BOT_AUTHOR, ...extra } = {}) => triage(
  intake({
    event: "issue_comment", action: "created", labels: "",
    issue: "`a-stranger/dice-roller@v0.2.0` reached the registry without a submission issue.\n",
    title,
    comment: text, commenter, issueAuthor, now: NOW, ...extra,
  }),
  releaseBy(SUBMITTER),
  { proveMaintainer: extra.prove ?? MAINTAINERS },
);

await test("canary 1 — /approve on a bot-authored [notice] for a LISTED repository approves", async () => {
  const out = await onThread(`/approve ${REPO}@${TAG} ${FP}`, "the-maintainer");
  assertEqual(out.mode, "approve", out.why);
  assertEqual(out.repo, REPO, "the target is the one the maintainer's line named");
  assertEqual(out.tag, TAG, "");
  assertEqual(out.approvedBy, "the-maintainer", "");
  assertEqual(out.approvedFor, FP, "and it still carries what it is an approval OF");
  // The submitter cannot be the issue author here: the issue author is the bot,
  // and `github-actions[bot]` is not even a login the charset admits. It comes
  // from the release, exactly as a ping's does.
  assertEqual(out.submitter, SUBMITTER, "resolved from the release author, not from the thread");
  assert(!("findings" in out) && !("decision" in out),
    `an approval carries no verification with it: ${Object.keys(out).join(", ")}`);
});

await test("canary 1b — /publish too, and it still waives the delay", async () => {
  const out = await onThread(`/publish ${REPO}@${TAG} ${FP}`, "the-maintainer");
  assertEqual(out.mode, "approve", out.why);
  assertEqual(out.publishNow, true, "`/publish` is `/approve` plus the waiver, on every thread");
});

await test("canary 2 — an UNLISTED repository gets a reply, and no target", async () => {
  // The rule that makes an unlabelled thread safe at all, and it is the same
  // one that makes an unauthenticated `/release` ping safe: off a listing issue
  // nobody applied the label, so the only thing standing in for a person's
  // decision is a pin that already exists. A first listing is not reachable
  // through a command.
  const out = await onThread(`/approve a-stranger/never-listed@${TAG} ${FP}`, "the-maintainer");
  assertEqual(out.mode, "reply", out.why);
  assert(!out.repo && !out.tag, "and emits no target: nothing is fetched for a repository with no pin");
  assert(out.reply.includes("is not listed"), out.reply);
  assert(out.reply.includes("a-stranger/never-listed"), "the reply names what was refused");
});

await test("a [release] thread qualifies whoever opened it, because the other three checks do the work", async () => {
  // The release-ping form is a stranger's door by design. What keeps this safe
  // is not the author: it is `admin`/`maintain` on THIS registry, an already
  // listed repository, and `bot/decide.mjs` re-hashing the release.
  const out = await onThread(`/approve ${REPO}@${TAG} ${FP}`, "the-maintainer", {
    title: `[release] ${REPO} ${TAG}`, issueAuthor: "a-stranger",
  });
  assertEqual(out.mode, "approve", out.why);

  // And the authority is unchanged on it — the stranger who opened it cannot
  // answer their own thread.
  const refused = await onThread(`/approve ${REPO}@${TAG} ${FP}`, "a-stranger", {
    title: `[release] ${REPO} ${TAG}`, issueAuthor: "a-stranger",
  });
  assertEqual(refused.mode, "reply", refused.why);
  assert(refused.reply.includes("`/approve` is refused"), refused.reply);
});

await test("a [notice] somebody else opened is not one of the bot's, and is refused", async () => {
  // A human-authored `[notice]` is an imitation of the thread this registry
  // prints copy-paste commands on. Not a wall — anyone can retitle an issue
  // `[release]` and meet the other three checks instead — but a maintainer who
  // copies a line out of a fake notice gets a refusal rather than a publication.
  const out = await onThread(`/approve ${REPO}@${TAG} ${FP}`, "the-maintainer", {
    issueAuthor: "a-stranger",
  });
  assertEqual(out.mode, "reply", out.why);
  assert(!out.repo, "and no target");
  assert(out.reply.includes("nothing to act on"), out.reply);
  assert(out.why.includes(BOT_AUTHOR), out.why);
});

await test("a bare /approve on a [notice] has nothing to fall back on, and says so", async () => {
  // On a listing issue a bare `/approve` is refused because the form it would
  // have read is the author's to edit. Here there is no form at all, so the
  // command line is the only thing that names a release — and the reply is the
  // same one, because the fix is the same: name what you are approving.
  for (const line of ["/approve", `/approve ${REPO}`, `/approve ${REPO}@${TAG}`]) {
    const out = await onThread(line, "the-maintainer");
    assertEqual(out.mode, "reply", `${line} → ${out.why}`);
    assert(out.reply.includes("has to name what it is approving"), line);
    assert(!out.repo, `${line} emitted a target`);
  }
});

await test("/reject stays a listing-issue command, because it can never name a release", async () => {
  // B-T0.2 admits a command to these threads only when it names
  // `owner/repo@tag <fingerprint>`, and `parseMaintainerCommand` gives
  // `/reject` a sentence instead — by construction, because a rejection is
  // something said to a submitter about a submission under review. A `[notice]`
  // belongs to the bot; there is nothing on it to close and nobody to close it
  // for. Refusing is the point: an unbindable command on an unlabelled thread
  // is the exact shape this task exists to stop.
  const out = await onThread("/reject this one is not ready", "the-maintainer");
  assertEqual(out.mode, "reply", out.why);
  assertEqual(out.close, undefined, "and nothing is closed");
  assert(out.reply.includes("nothing to act on"), out.reply);

  // Unchanged where it belongs.
  const onListing = await command("/reject the licence is not one this registry allows", "the-maintainer");
  assertEqual(onListing.mode, "reject", onListing.why);
});

await test("the permission is still asked first on these threads too", async () => {
  // Ordering, for the same reason as on a listing issue: an account that may
  // not decide gets the same answer whatever it typed, or the bot becomes an
  // oracle for which threads are decidable and which repositories are listed.
  const out = await onThread(`/approve a-stranger/never-listed@${TAG} ${FP}`, "a-stranger");
  assert(out.reply.includes("`/approve` is refused"), out.reply);
  assert(!out.reply.includes("is not listed"),
    "a stranger must not learn from the refusal whether that repository is listed");
});

await test("an ordinary issue is still not decidable, which is the half that must not widen", async () => {
  // The floor under all of the above. `decidableThread` admits two title
  // prefixes and nothing else; if it ever admitted "any issue with no form"
  // then every one of this registry's issues would be a command surface, and
  // every test above would still pass.
  for (const [title, issueAuthor] of [
    ["site 500s", BOT_AUTHOR],
    ["[appeal] dice-roller", BOT_AUTHOR],
    ["[report] dice-roller", BOT_AUTHOR],
    ["", BOT_AUTHOR],
  ]) {
    const out = await onThread(`/approve ${REPO}@${TAG} ${FP}`, "the-maintainer", { title, issueAuthor });
    assertEqual(out.mode, "reply", `${JSON.stringify(title)} → ${out.why}`);
    assert(!out.repo, `${JSON.stringify(title)} emitted a target`);
    assert(out.reply.includes("nothing to act on"), out.reply);
  }
});

await test("B-T0.2's admissible threads are exactly two, and the list is asserted, not described", () => {
  // The rule as a table rather than as four calls, so that widening it is an
  // edit to something a reviewer can count. `decidableThread` is pure, so this
  // costs nothing and covers the cases the calls above do not.
  const cases = [
    [NOTICE_TITLE, BOT_AUTHOR, "notice"],
    ["[NOTICE] shouting is still a notice", BOT_AUTHOR, "notice"],
    [NOTICE_TITLE, "a-stranger", null],
    [NOTICE_TITLE, "", null],
    [NOTICE_TITLE, "github-actions", null],
    [`[release] ${REPO} ${TAG}`, "a-stranger", "release"],
    [`[release] ${REPO} ${TAG}`, BOT_AUTHOR, "release"],
    ["[listing] a-stranger/dice-roller", BOT_AUTHOR, null],
    ["[appeal] dice-roller", BOT_AUTHOR, null],
    ["[report] dice-roller", BOT_AUTHOR, null],
    ["site 500s", BOT_AUTHOR, null],
    ["", BOT_AUTHOR, null],
    [null, null, null],
  ];
  assertEqual(cases.length, 13, "the enumeration IS the test; shrinking it silently is the failure mode");
  for (const [title, issueAuthor, kind] of cases) {
    assertEqual(decidableThread({ title, issueAuthor }).kind, kind,
      `${JSON.stringify(title)} by ${JSON.stringify(issueAuthor)}`);
  }
  // `github-actions[bot]` is not a login GitHub's charset admits, which is what
  // makes it unregisterable and therefore worth comparing against. If this ever
  // starts passing `safeLogin`, the author check above has become forgeable.
  assertEqual(safeLogin(BOT_AUTHOR), null, "the bot's name must stay outside the login charset");
});

section("an approval clears the hold, and only the hold");

/**
 * A world where `dice-roller` is listed and something else has taken its
 * display name, so a re-release is held on `R_DISPLAY_NAME_COLLISION` — a hold
 * that is not about the bytes and not about the permissions, which is what
 * makes it the clean case for "approval clears the hold and the release
 * publishes".
 */
const collidingTree = () => registryTree([
  { versions: [{ version: "0.1.0" }] },
  { id: "bingo-cards", name: "Dice Roller", versions: [{ version: "1.0.0" }] },
]);

await test("without an approval it is held, with the SLA and no listing", async () => {
  const r = await run({ root: collidingTree() });
  assertEqual(r.decision.outcome, "review", JSON.stringify(codes(r)));
  assertEqual(r.decision.publishes_now, false, "");
  assertEqual(r.decision.approved_by, null, "");
  // And the comment says what to type, in full, because "comment /approve" is
  // an instruction that cannot be checked against anything afterwards and
  // "comment this exact line" is one that can.
  assert(r.comment.includes(`/approve ${REPO}@${TAG} ${r.decision.fingerprint}`),
    `the hold comment must print the line ready to copy:\n${r.comment}`);
  assert(/^[0-9a-f]{16}$/.test(r.decision.fingerprint), r.decision.fingerprint);
});

await test("a maintainer's yes re-runs every check and publishes what THIS run hashed", async () => {
  const assets = [conforming()];
  const { approved: r } = await approveFromComment({ root: collidingTree(), assets });
  assertEqual(r.decision.outcome, "publish", JSON.stringify(codes(r)));
  assert(codes(r).includes("P_APPROVED"), JSON.stringify(codes(r)));
  assertEqual(r.decision.approved_by, "the-maintainer", "");
  assertEqual(r.decision.approved_at, "2026-08-10T11:59:00Z", "");

  // The hold is still on the record — the point of an audit trail is that the
  // thing that was cleared is still visible.
  assert(codes(r).includes("R_CHECK_HELD"), JSON.stringify(codes(r)));

  // "Against which digest" has to be the digest of the bytes this run
  // downloaded, or the record is a sentence nobody can check later.
  const expected = crypto.createHash("sha256").update(assets[0].bytes).digest("hex");
  assert(r.decision.artifact_digests.some((d) => d.endsWith(`:${expected}`)),
    `${JSON.stringify(r.decision.artifact_digests)} does not contain ${expected}`);

  // And the comment does not still tell the author to wait for a maintainer.
  assert(r.comment.includes("A maintainer cleared the hold: **@the-maintainer**"), "");
  assert(!r.comment.includes("Nothing to do but wait"),
    "a cleared hold must not keep printing the remedy for an uncleared one");
});

await test("an approval cannot clear a failed check", async () => {
  const r = await run({
    root: collidingTree(),
    assets: [conforming({ license: "BUSL-1.1" })],
    approvedBy: "the-maintainer", approvedAt: "2026-08-10T11:59:00Z",
  });
  assertEqual(r.decision.outcome, "refuse", JSON.stringify(codes(r)));
  assertEqual(codes(r).join(","), "P_REFUSED", "the refusal branch runs first and ends it");
  // Recorded even so: the maintainer did type the command, and a record that
  // omitted an approval the registry then ignored could not be reconciled with
  // the thread.
  assertEqual(r.decision.approved_by, "the-maintainer", "");

  // The rendered markdown is the only artefact the author ever sees, so it is
  // the one worth asserting on. It used to print "Not published. A check above
  // failed; the policy never got a say." and then, in the very next paragraph,
  // "A maintainer cleared the hold" — two sentences that cannot both be true,
  // about a hold that was never raised.
  assert(!r.comment.includes("cleared the hold"),
    "nothing was held on a refusal, so nothing can have been cleared:\n" + r.comment);
  assert(r.comment.includes("typed `/approve`") && r.comment.includes("changed nothing"),
    "the refusal still has to account for the command the maintainer typed:\n" + r.comment);
});

await test("an approval does not waive the publication delay, and the queue remembers it", async () => {
  const { approved: r } = await approveFromComment({
    root: collidingTree(),
    assets: [conforming({ capabilities: ["tools", "tts"] })],
  });
  assertEqual(r.decision.outcome, "delay", JSON.stringify(codes(r)));
  assert(codes(r).includes("P_APPROVED") && codes(r).includes("P_DELAY_WIDENED"), JSON.stringify(codes(r)));
  assertEqual(hours(r.decision.publish_after, NOW), DELAY_HOURS, "");
  // The hold and the delay answer different questions — *may this be listed at
  // all* versus *has the author had a chance to notice* — and one person's yes
  // does not answer the second one.
  assertEqual(r.decision.queue_entry.approved_by, "the-maintainer",
    "and without this the hourly drain raises the same hold again in 24 h and the release loops");
});

await test("the drain honours the approval in the queue without a second comment", async () => {
  const root = collidingTree();
  const assets = [conforming({ capabilities: ["tools", "tts"] })];
  const { approved: first } = await approveFromComment({ root, assets });
  assertEqual(first.decision.outcome, "delay", "");

  // Commit the queue entry the publish job would have committed, then let the
  // clock run out. No `--approved-by` this time: a cron drain has no comment
  // behind it, which is exactly the run that used to bounce it back to review.
  const entry = first.decision.queue_entry;
  const file = path.join(root, queueFile(entry.id, entry.version));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(entry, null, 2)}\n`);

  const later = await run({ root, assets, now: new Date(NOW.getTime() + 25 * 3600 * 1000) });
  assertEqual(later.decision.outcome, "publish", JSON.stringify(codes(later)));
  assertEqual(later.decision.approved_by, "the-maintainer", "carried forward from the queue entry");
  assert(codes(later).includes("P_DELAY_ELAPSED"), JSON.stringify(codes(later)));
});

await test("swapping the assets mid-window takes the approval with the clock", async () => {
  const root = collidingTree();
  const { approved: first } = await approveFromComment({
    root, assets: [conforming({ capabilities: ["tools", "tts"] })],
  });
  const entry = first.decision.queue_entry;
  const file = path.join(root, queueFile(entry.id, entry.version));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(entry, null, 2)}\n`);

  // Same repository, same tag, different bytes — §5.5's timed swap.
  const swapped = await run({
    root,
    assets: [conforming({ capabilities: ["tools", "tts"], description: "Rolls dice. Differently." })],
    now: new Date(NOW.getTime() + 23 * 3600 * 1000),
  });
  assertEqual(swapped.decision.outcome, "review",
    "the hold comes back, because nobody has approved THESE bytes");
  assertEqual(swapped.decision.approved_by, null,
    "an approval recorded against a digest must never be reused for a different one");
});

section("an approval names what it approves, and only that");

// The layer below `bot/triage.mjs`. Triage refuses a command whose repository
// and tag disagree with the issue in front of it — but triage has no bytes, so
// it cannot see a tag moved onto a different commit or a release asset replaced
// in place. Both of those are §5.5's timed swap aimed at the review queue
// instead of at the publication delay, and this is where they are caught.

await test("an approval is refused when the release changed after the hold", async () => {
  const root = collidingTree();

  // 1. It is held, and the comment prints the line to copy.
  const held = await run({ root, assets: [conforming()] });
  assertEqual(held.decision.outcome, "review", JSON.stringify(codes(held)));
  const approvedFor = held.decision.fingerprint;

  // 2. The author replaces the asset on the same repository and the same tag
  //    while the maintainer is reading. Nothing about the issue changed.
  const swapped = [conforming({ description: "Rolls dice. Differently." })];

  // 3. The maintainer answers the comment they read.
  const r = await run({
    root, assets: swapped,
    approvedBy: "the-maintainer", approvedAt: "2026-08-10T11:59:00Z", approvedFor,
  });

  assertEqual(r.decision.outcome, "review",
    `the hold has to stand: ${JSON.stringify(codes(r))}`);
  assertEqual(r.decision.publishes_now, false, "and nothing is written");
  assertEqual(r.decision.approved_by, null,
    "the approval did not apply, so the record must not claim a hold was cleared");
  assert(codes(r).includes("P_APPROVAL_STALE"), JSON.stringify(codes(r)));
  assert(!codes(r).includes("P_APPROVED"), JSON.stringify(codes(r)));

  // Refused loudly, not silently: who typed it, what it named, and what is here.
  assertEqual(r.decision.approval_refused.by, "the-maintainer", "");
  assertEqual(r.decision.approval_refused.for, approvedFor, "");
  assert(r.decision.fingerprint !== approvedFor,
    "the premise of the test: different bytes are a different submission");
  assert(r.comment.includes("`/approve` was refused"), r.comment);
  assert(r.comment.includes(approvedFor) && r.comment.includes(r.decision.fingerprint),
    "the comment names both, so the maintainer can see which one moved");
  // And it prints the line for the release as it is now, which is the remedy.
  assert(r.comment.includes(`/approve ${REPO}@${TAG} ${r.decision.fingerprint}`), r.comment);
});

await test("an approval is refused when only the release commit moved", async () => {
  // The narrower cousin of the test above, and the one the fingerprint used to
  // fail. Every hashed fact was repo, tag, id, version and the artifact digests
  // — so an author could delete the release and the tag, push a commit with a
  // different `banner.png`, re-create both at that commit and re-upload
  // BYTE-IDENTICAL assets, and the fingerprint would not move. The maintainer's
  // `/approve` still bound, the listing published, and `bot/lib/assets.mjs`
  // pinned every relative README image to a tree nobody had reviewed. The
  // commit is in the hash now, so this is a different submission.
  const root = collidingTree();
  const assets = [conforming()];
  const held = await run({ root, assets });
  assertEqual(held.decision.outcome, "review", JSON.stringify(codes(held)));
  const approvedFor = held.decision.fingerprint;

  const moved = "c".repeat(40);
  const r = await run({
    root, assets, commit: moved,
    approvedBy: "the-maintainer", approvedAt: "2026-08-10T11:59:00Z", approvedFor,
  });

  assert(r.decision.fingerprint !== approvedFor,
    "the premise: the same bytes at a different commit are a different submission");
  assertEqual(r.decision.outcome, "review", `the hold has to stand: ${JSON.stringify(codes(r))}`);
  assertEqual(r.decision.publishes_now, false, "and nothing is written");
  assertEqual(r.decision.approved_by, null, "");
  assert(codes(r).includes("P_APPROVAL_STALE"), JSON.stringify(codes(r)));
  assert(!codes(r).includes("P_APPROVED"), JSON.stringify(codes(r)));
});

await test("a Release pointed at a commit the attestation does not name is refused", async () => {
  // Independent of approvals: it applies to every listing, auto-published ones
  // included. `release.target_commitish` is whatever `gh release create --target`
  // was given, the attestation names the commit that actually built the bytes,
  // and nothing used to compare them — so the catalogue could record, and pin
  // every relative README image to, an unrelated tree that verified fine.
  const root = registryTree([{ versions: [{ version: "0.1.0" }] }]);
  const r = await run({ root, commit: "d".repeat(40), attestedCommit: FIXTURE_COMMIT });
  const errors = r.findings.filter((x) => x.level === "error").map((x) => x.code);
  assert(errors.includes("E_RELEASE_COMMIT_MISMATCH"), JSON.stringify(errors));
  assertEqual(r.decision.publishes_now, false, "and nothing is published on a mismatch");
});

await test("an approval for one repository does not clear a hold on another", async () => {
  const root = collidingTree();
  const mine = await run({ root, assets: [conforming()] });

  // Same bytes, same version, a different source repository — the shape of the
  // issue-body edit, arriving through a path where no issue was parsed at all.
  const elsewhere = await run({
    root, repo: "someone-else/dice-roller", submitter: "someone-else",
    assets: [conforming()],
    approvedBy: "the-maintainer", approvedAt: "2026-08-10T11:59:00Z",
    approvedFor: mine.decision.fingerprint,
  });
  assert(elsewhere.decision.outcome !== "publish", JSON.stringify(codes(elsewhere)));
  assertEqual(elsewhere.decision.approved_by, null, "");
  assert(codes(elsewhere).includes("P_APPROVAL_STALE"), JSON.stringify(codes(elsewhere)));
});

await test("an approval that names nothing at all is not an approval", async () => {
  // `--approved-by` with no `--approved-for`: the exact shape every approval had
  // before this binding existed, and the reason the flag is not optional.
  const r = await run({
    root: collidingTree(),
    approvedBy: "the-maintainer", approvedAt: "2026-08-10T11:59:00Z",
  });
  assertEqual(r.decision.outcome, "review", JSON.stringify(codes(r)));
  assertEqual(r.decision.approved_by, null, "");
  assert(codes(r).includes("P_APPROVAL_STALE"), JSON.stringify(codes(r)));
  assert(r.comment.includes("no submission at all"), r.comment);
});

await test("the line the hold comment prints is the line that works", async () => {
  // The round trip, exactly as a maintainer performs it: read the comment,
  // copy the line, comment it, watch it publish. If these two ever disagree the
  // binding is unusable, and an unusable binding is one somebody removes.
  const { held, approved, line, fingerprint } = await approveFromComment({ root: collidingTree() });
  assertEqual(held.decision.outcome, "review", "");
  assertEqual(line, `/approve ${REPO}@${TAG} ${fingerprint}`, "");
  assertEqual(approved.decision.outcome, "publish", JSON.stringify(codes(approved)));
  assertEqual(approved.decision.approved_by, "the-maintainer", "");
  assertEqual(approved.decision.approval_refused, null, "");
  assert(approved.comment.includes(`\`${fingerprint}\``),
    "and the record says which submission was approved, not just that one was");
});

await test("the fingerprint is of the submission, not of the prose around it", async () => {
  // The reason the binding is not a hash of the issue body: an author fixing a
  // typo in their justification, or a maintainer editing the title, must not
  // invalidate an approval. Two runs over identical bytes agree.
  const root = collidingTree();
  const a = await run({ root });
  const b = await run({ root, issue: 41 });
  assertEqual(a.decision.fingerprint, b.decision.fingerprint, "");

  // And it moves for each of the five things it is made of.
  const other = await run({ root, tag: "v0.2.0-rc1" });
  assert(other.decision.fingerprint !== a.decision.fingerprint, "a different tag is a different submission");
});

await test("a refused approval does not take a waiting release out of the queue", async () => {
  // The invariant: a refused approval changes NOTHING. A delayed release has a
  // clock its author is owed, and the clock lives in a queue entry that a
  // `review` outcome deletes. Without this, a maintainer pasting the wrong line
  // would restart somebody's 24 hours.
  const root = registryTree([{ versions: [{ version: "0.1.0", capabilities: ["tools"] }] }]);
  const assets = [conforming({ capabilities: ["tools", "tts"] })];
  const waiting = await run({ root, assets });
  assertEqual(waiting.decision.outcome, "delay", JSON.stringify(codes(waiting)));

  const entry = waiting.decision.queue_entry;
  const file = path.join(root, queueFile(entry.id, entry.version));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(entry, null, 2)}\n`);

  const out = tmp("astra-policy-out-");
  const fumbled = await run({
    root, assets, now: new Date(NOW.getTime() + 3600 * 1000),
    approvedBy: "the-maintainer", approvedAt: "2026-08-10T12:30:00Z",
    approvedFor: "ffffffffffffffff",
  });
  assertEqual(fumbled.decision.outcome, "review", JSON.stringify(codes(fumbled)));
  assert(codes(fumbled).includes("P_APPROVAL_STALE"), JSON.stringify(codes(fumbled)));
  writeOutputs(out, { repo: REPO, tag: TAG, issue: null }, fumbled);
  assertEqual(fs.readFileSync(path.join(out, "remove.txt"), "utf8"), "",
    "the entry the author is waiting on must still be there");

  // And it still publishes itself on the original clock.
  const later = await run({ root, assets, now: new Date(NOW.getTime() + 25 * 3600 * 1000) });
  assertEqual(later.decision.outcome, "publish", JSON.stringify(codes(later)));
  assert(codes(later).includes("P_DELAY_ELAPSED"), JSON.stringify(codes(later)));
});

await test("a real hold still stops a release waiting, stale approval or not", async () => {
  // The other half of the exception above: `P_APPROVAL_STALE` is the only hold
  // that leaves a queue entry alone. A submission that a re-check now hands to a
  // person must not publish itself on a timer while it waits.
  const root = collidingTree();
  const assets = [conforming({ capabilities: ["tools", "tts"] })];
  const out = tmp("astra-policy-out-");
  const held = await run({
    root, assets,
    approvedBy: "the-maintainer", approvedAt: "2026-08-10T11:59:00Z", approvedFor: "ffffffffffffffff",
  });
  assertEqual(held.decision.outcome, "review", JSON.stringify(codes(held)));
  assert(codes(held).includes("R_CHECK_HELD") && codes(held).includes("P_APPROVAL_STALE"),
    JSON.stringify(codes(held)));
  writeOutputs(out, { repo: REPO, tag: TAG, issue: null }, held);
  assert(fs.readFileSync(path.join(out, "remove.txt"), "utf8").includes("state/queue/"),
    "a genuine hold still takes the release out of the queue");
});

await test("decision.json carries the binding, for the run that publishes and the one that refuses", async () => {
  const root = collidingTree();
  const out = tmp("astra-policy-out-");
  const held = await run({ root });
  const r = await run({
    root, approvedBy: "the-maintainer", approvedAt: "2026-08-10T11:59:00Z",
    approvedFor: held.decision.fingerprint,
  });
  writeOutputs(out, { repo: REPO, tag: TAG, issue: 7 }, r);
  const doc = JSON.parse(fs.readFileSync(path.join(out, "decision.json"), "utf8"));
  assertEqual(doc.fingerprint, r.decision.fingerprint, "");
  assertEqual(doc.approved_by, "the-maintainer", "");
  assertEqual(doc.approval_refused, null, "");
  assert(Array.isArray(doc.artifact_digests) && doc.artifact_digests.length > 0,
    "the digests the fingerprint is a label on are still written out in full");
});

section("what the workflow may cancel, and what it may never");

// `.github/workflows/ingest.yml` grouped every event on an issue under one
// concurrency key with `cancel-in-progress: true`. That was fine while a comment
// could only ever start a re-check; it stopped being fine when `/approve` began
// starting a full ingest on that same key, because then an edit — or any second
// comment, including `/recheck` — cancelled a decision that was already running.
//
// A cancelled run is not a run that did nothing. `publish` is the only job that
// commits, so cancelling it leaves the listing unwritten, the backstop's etag
// memory thrown away, and — the one that does not heal — the QUEUE ENTRY for a
// delayed release never committed, after `comment` has already told the author
// it publishes itself at a stated time. Nothing retries that. The `/approve`
// itself is spent too: GitHub does not redeliver the comment.
//
// `cancel-in-progress: false` fixed the in-progress half and only that half. A
// PENDING run is still replaced by a newer one in the same group, which is why
// the question below is which events share a key — and why the answer is "all
// of an issue's", so that a replaced run is always a duplicate of the same
// submission rather than a stranger's release.
//
// Asserted against the file rather than argued in prose, because the argument
// is only as good as the two lines it is about.

const ingestWorkflow = fs.readFileSync(
  path.join(REPO_ROOT, ".github", "workflows", "ingest.yml"), "utf8");

/** The top-level block of a workflow file: column 0 key, indented body. */
function topLevelBlock(yaml, key) {
  const lines = yaml.split("\n");
  const start = lines.findIndex((l) => l === `${key}:` || l.startsWith(`${key}:`) && !l.startsWith(" "));
  if (start < 0) return null;
  const body = [lines[start]];
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].trim() === "" || /^\s/.test(lines[i])) body.push(lines[i]);
    else break;
  }
  return body.join("\n");
}

const indexWorkflow = fs.readFileSync(
  path.join(REPO_ROOT, ".github", "workflows", "build-index.yml"), "utf8");

await test("a publication signs and deploys promptly, not at the top of the next hour", async () => {
  // `ingest.yml`'s publish job commits with the repository's own GITHUB_TOKEN,
  // and GitHub does not raise workflow-starting events from that token — so the
  // push that publishes a listing cannot start the file that SIGNS it. Left at
  // that, the catalogue users fetch trails the repository by up to an hour.
  // Measured: 0.3.3 published at 18:03 and the site served 0.3.1 until 18:09.
  const on = topLevelBlock(indexWorkflow, "on");
  assert(on, "build-index.yml has no top-level `on:` block");
  assert(/workflow_run:/.test(on),
    "no prompt trigger: a publication waits for the cron, which is the whole defect");
  assert(/schedule:/.test(on),
    "the cron must survive the prompt trigger — the catalogue expires whether or not anybody publishes");
});

// ── which workflows `build-index.yml` must hear (BOT-50) ─────────────────────
//
// The shape here is LIFTED from `bot/tests/workflows.test.mjs`'s "the signer
// hears every workflow that commits, by the name in the file": the same
// `contents: write` predicate, the same exception map carrying a reason per
// entry, the same assertion that refuses an exception which has gone stale.
// One rule — *a workflow that commits to `main` must be heard by the file that
// acts on what it committed* — asked of two hearers.
//
// **Do not give this one a second mechanism.** A path glob over the YAML is the
// obvious alternative and it is wrong for a reason already paid for: `Ingest`
// commits `plugins/**` from inside `bot/publish-apply.mjs`, not from a line of
// YAML, so a scan of the workflow files finds nothing and passes over the one
// committer that exists.
//
// What this hearer wants is NOT what the signer wants, which is why the two
// exception maps differ rather than being one list. The signer asks *does this
// commit reach a document I sign*; this file asks *does this commit reach
// anything my `check` job asserts* — the regenerated index, the listings, the
// index size ceiling, the site's page set, and the cross-repository couplings,
// which run here or nowhere: `sign.yml`'s header states that its publish job
// has no AstraPlugins checkout and must never grow one (seam 4), and that
// `build-index.yml` has it and is right to turn a `NOT verified` into exit 1.
// That is the answer to "the signer already hears it, so this file need not":
// they hear it for different things, and only one of them can do this one.

const WORKFLOW_DIR = path.join(REPO_ROOT, ".github", "workflows");
const workflowFiles = fs.readdirSync(WORKFLOW_DIR).filter((n) => /\.ya?ml$/.test(n));
const readWorkflow = (n) => fs.readFileSync(path.join(WORKFLOW_DIR, n), "utf8");

/**
 * Every job in every workflow, as `{file, job, body}`.
 *
 * The STARTS are collected in a first pass rather than in one scan, because a
 * comment indented two spaces between two jobs ends the earlier job's body in
 * the scanning version and matches no job name either — so the rest of that job
 * vanishes from the check, silently, in a test whose whole subject is silence.
 */
function allWorkflowJobs() {
  const out = [];
  for (const file of workflowFiles) {
    const lines = readWorkflow(file).split("\n");
    const at = lines.findIndex((l) => /^jobs:\s*$/.test(l));
    if (at < 0) continue;
    const starts = [];
    for (let i = at + 1; i < lines.length; i++) {
      if (/^\S/.test(lines[i])) break;
      const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(lines[i]);
      if (m) starts.push([i, m[1]]);
    }
    for (let k = 0; k < starts.length; k++) {
      const [i, job] = starts[k];
      let end = k + 1 < starts.length ? starts[k + 1][0] : lines.length;
      for (let j = i + 1; j < end; j++) if (/^\S/.test(lines[j])) { end = j; break; }
      out.push({ file, job, body: lines.slice(i, end) });
    }
  }
  return out;
}

const workflowJobs = allWorkflowJobs();
const jobCode = (job) => job.body.filter((l) => !l.trim().startsWith("#"));

/**
 * Does any JOB in this workflow declare `contents: write`?
 *
 * Job-scoped, not file-scoped: a top-level `permissions:` block would otherwise
 * answer for a file whose jobs each narrow it. The trailing-comment form is not
 * decoration — `publisher-recheck.yml` says `contents: write   # commit a
 * renewed window, or a withdrawal`, and a `$`-anchored needle walks straight
 * past the one job whose own comment says out loud that it commits.
 */
const commitsAnything = (file) =>
  workflowJobs.some((j) => j.file === file
    && jobCode(j).some((l) => /^\s+contents:\s*write\s*(#.*)?$/.test(l)));

/** A workflow's own `name:`, read from the file. Never inferred from the path. */
function workflowName(file) {
  const line = readWorkflow(file).split("\n").find((l) => /^name:\s*\S/.test(l));
  return line ? line.replace(/^name:\s*/, "").trim().replace(/^["']|["']$/g, "") : null;
}

// The committing workflows `build-index.yml` deliberately does NOT hear, each
// with what it writes and why that reaches nothing this file asserts.
const INDEX_NOT_HEARD = new Map([
  [
    "Signer",
    "commits to the `signed` branch, never to `main` (D1). This file regenerates and checks what is on " +
    "`main`, so a signer run changes nothing it reads — and hearing the hourly signer would start an " +
    "index build every hour over a tree no signer run touched.",
  ],
  [
    "Migration baseline",
    "holds contents: write for BOT-73's one commit of MIG-20's records and marker, log/decisions/** and " +
    "log/baseline.json. `build-index.mjs` reads plugins/** and publishers/**, so such a commit cannot move " +
    "the document this file regenerates. `validate.mjs` does read log/baseline.json: the `write` job has a " +
    "`validate.mjs` step of its own (BOT-71), and this file's hourly run reads the marker after that.",
  ],
  [
    "Keepalive",
    "commits state/keepalive.json alone, and that commit exists in order to BE a commit: ROLL-62's monthly " +
    "keepalive (RC-R1-9(b)) is what keeps GitHub from disabling every schedule in this repository after 60 " +
    "days of quiet. No generator this file runs reads state/.",
  ],
]);

// Heard, and unable to commit anything today. Each entry carries its reason AND
// a predicate that reads that reason back out of the workflow file, so a
// dormancy which outlives its cause fails here instead of sitting in a comment:
// "it cannot go red yet" is one edit away from "it never goes red", and that
// edit is invisible. When R3 lands these go red and the entries come out.
const INDEX_DORMANT = new Map([
  [
    "Plugins ingest",
    {
      file: "plugins-ingest.yml",
      why: "its BOT-51 schedule is commented out until R3 (plan row reg.52, \"R2 exit, dark\") and its " +
        "publish job's first step exits 1 on B-T3.4",
      dormant: (src) => !/^\s{2}schedule:\s*$/m.test(topLevelBlock(src, "on") ?? ""),
    },
  ],
  [
    "Plugins moderation",
    {
      file: "plugins-moderation.yml",
      why: "its commit job's compile step exits 1 on M-T3.2 — ASTRA_OVER_BOUND, TRUST-26's count for the " +
        "run, is supplied by nothing — and every later step in that job is gated on its success",
      dormant: (src) => /ASTRA_OVER_BOUND/.test(src) && /^\s+exit 1\s*$/m.test(src),
    },
  ],
]);

await test("build-index.yml hears every workflow that commits, by the name in the file", async () => {
  // The coupling this has that nothing else would: `workflows: [...]` is matched
  // against another file's `name:`, by string, at dispatch time. Rename a
  // workflow and NOTHING fails — no error, no warning, no run. The trigger
  // simply stops firing and what it committed is checked at the top of the next
  // hour, or never.
  const on = topLevelBlock(indexWorkflow, "on");
  const named = /workflows:\s*\[([^\]]*)\]/.exec(on ?? "");
  assert(named, `no \`workflows:\` list under workflow_run:\n${on}`);
  const heard = [...named[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);

  // The assertion this test grew out of, kept by name: `ingest.yml` is the one
  // committer that is live today, and it is the one whose rename would cost
  // something the same afternoon.
  const ingestName = /^name:\s*(.+)$/m.exec(ingestWorkflow)?.[1]?.trim().replace(/^["']|["']$/g, "");
  assert(ingestName, "ingest.yml has no top-level `name:`");
  assert(heard.includes(ingestName),
    `build-index.yml waits on ${JSON.stringify(heard)} and ingest.yml is called ` +
    `"${ingestName}" — the trigger will never fire`);

  const committers = workflowFiles.filter((f) => f !== "build-index.yml" && commitsAnything(f));
  const problems = [];
  const heardCommitters = [];
  for (const file of committers) {
    const name = workflowName(file);
    if (name === null) {
      problems.push(`${file} has a contents: write job and no name: line, so nothing can put it in build-index.yml's list`);
      continue;
    }
    if (heard.includes(name)) { heardCommitters.push(name); continue; }
    if (INDEX_NOT_HEARD.has(name)) continue;
    problems.push(
      `${file} is named ${JSON.stringify(name)}, holds a contents: write job, and build-index.yml does not ` +
      `hear it (BOT-50). GITHUB_TOKEN pushes start no push runs, so whatever it commits is checked at the top ` +
      `of the next hour or not at all — and an index left disagreeing with its own generator is a red build ` +
      `attributed to whoever pushes next. Add the name to build-index.yml's workflow_run list, or add it to ` +
      `INDEX_NOT_HEARD here with what it writes and why no check in that file reads it.`,
    );
  }

  // An exception that no longer names a workflow is an exception nobody will
  // notice has stopped applying.
  for (const [name, why] of INDEX_NOT_HEARD) {
    const file = workflowFiles.find((f) => workflowName(f) === name);
    assert(file, `INDEX_NOT_HEARD names ${JSON.stringify(name)} and no workflow is called that any more (${why})`);
    assert(commitsAnything(file),
      `INDEX_NOT_HEARD excuses ${JSON.stringify(name)} and ${file} no longer has a contents: write job; delete the entry`);
  }

  // The floor, and it is the whole defence against passing because there was
  // nothing to ask. Seven committing workflows on 2026-09-22, four of them
  // heard. A scan that finds fewer is a broken read of the YAML — losing one
  // job to an indented comment would empty the loop above and report a
  // build-index that hears everything because it hears nothing.
  assert(committers.length >= 5,
    `the contents: write scan found ${committers.length} committing workflows and found 7 on 2026-09-22; ` +
    `this is a broken read of the workflow YAML, not a smaller repository`);
  assert(heardCommitters.length >= 3,
    `build-index.yml hears ${heardCommitters.length} of this repository's committing workflows and heard 4 on ` +
    `2026-09-22; a name was dropped from the list, or a workflow was renamed out from under it`);

  // DORMANT gets its own word in the output rather than being folded into the
  // pass, the way `tools/cutover-preflight.mjs` gives "never asked" its own
  // count and its own exit code. The distinction is real and is the thing most
  // likely to be misread here: the assertions ABOVE are over workflow files
  // that exist and run today, in full. What is inert until R3 is what the
  // trigger buys at RUN time for two of the four names.
  // Every finding goes into `problems` rather than throwing where it is found,
  // so one failure carries the whole picture. Asserting here would mask the
  // committer loop's message above, which is the one that says what to do.
  const stillDormant = [];
  for (const [name, d] of INDEX_DORMANT) {
    if (!heard.includes(name)) {
      problems.push(
        `INDEX_DORMANT names ${JSON.stringify(name)} and build-index.yml does not hear it — a workflow that ` +
        `commits nothing yet is exactly the one whose name gets dropped with nothing going red`);
    }
    const file = workflowFiles.find((f) => workflowName(f) === name);
    if (!file) {
      problems.push(
        `INDEX_DORMANT names ${JSON.stringify(name)} and no workflow is called that any more; it was ${d.file}`);
      continue;
    }
    if (file !== d.file) {
      problems.push(`INDEX_DORMANT says ${JSON.stringify(name)} is ${d.file}; it is now ${file}`);
    }
    if (d.dormant(readWorkflow(file))) { stillDormant.push(name); continue; }
    problems.push(
      `INDEX_DORMANT says ${JSON.stringify(name)} cannot commit — ${d.why} — and ${file} no longer reads that ` +
      `way, so it can commit now and the entry is stale. Delete it: the note below has been telling readers ` +
      `to expect nothing from a trigger that is live.`,
    );
  }

  assert(problems.length === 0, `a workflow commits and build-index.yml will not hear it:\n${problems.join("\n")}`);

  if (stillDormant.length) {
    console.log(`        note  DORMANT: ${stillDormant.join(", ")} — heard, and committing nothing until R3. ` +
      `The assertions above are over the workflow files and ran in full; it is the trigger's run-time effect ` +
      `that is inert, until reg.52 uncomments the schedule and M-T3.2 lands the takedown bound.`);
  }
});

await test("no event can cancel an ingest that is already running", async () => {
  const block = topLevelBlock(ingestWorkflow, "concurrency");
  assert(block, "the workflow has no top-level concurrency block at all");
  const flag = /cancel-in-progress:\s*(.+)/.exec(block);
  assert(flag, block);
  assertEqual(flag[1].trim(), "false",
    "an expression here is a run that cancels a publish for some value of github.event_name");
  // The spending argument the cancellation was there for survives: a group with
  // cancel-in-progress false still serialises, and a newer event replaces the
  // *pending* run rather than the in-flight one.
  assert(/group:/.test(block), block);
});

await test("a maintainer's decision gets its own lane; everything else shares the issue's", async () => {
  // Read the two sentences this replaces before changing it back, because this
  // assertion has now been inverted twice and each inversion was right at the
  // time.
  //
  // It first said a comment must key on ITSELF (`comment-<id>`). That was wrong
  // in a way `cancel-in-progress: false` hides: GitHub keeps one running and one
  // PENDING run per group, and a third arrival replaces the pending one. A
  // per-comment key did not remove that — it turned every comment into its own
  // run, and all of those runs' `publish` jobs then queued on the single
  // repo-wide `registry-publish` group, where the same rule applies BETWEEN
  // AUTHORS. `/release <listed-repo> <tag>` requires no authority at all, so a
  // stranger could drop somebody else's pending publish at will.
  //
  // It then said everything on one issue must share one key, which was right
  // for exactly as long as that repo-wide lane existed.
  //
  // The lane is gone (registry plan B-T0.3): `publish` has no `concurrency:`,
  // because `bot/publish-apply.mjs` makes two publishes racing a survivable
  // event. So the premise of the second sentence is gone with it, and the
  // decision commands take their own key — `/approve`, `/publish` and `/reject`
  // are SPENT comments that GitHub will not redeliver, so a run replaced while
  // pending takes the decision with it and nobody is told. Everything else still
  // shares the issue's key, so an edit storm is still bounded.
  const block = topLevelBlock(ingestWorkflow, "concurrency");
  assert(/github\.event\.comment\.id/.test(block),
    `a spent /approve must not share a lane with the next event on the issue:\n${block}`);
  assert(/github\.event\.issue\.number/.test(block),
    `every other event on an issue has to share one lane:\n${block}`);
  for (const command of ["/approve", "/publish", "/reject"]) {
    assert(block.includes(command),
      `the per-comment key must be gated on the decision commands; ${command} is not named:\n${block}`);
  }
  // And the gate is what keeps a stranger's `/release` ping out of its own lane:
  // a key nobody can aim is the whole reason the per-comment key is safe now.
  assert(!block.includes("/release"),
    `a ping that needs no authority must not get its own lane:\n${block}`);
});

await test("the job that commits queues behind nobody, and handles the race itself", async () => {
  // This asserted the opposite until B-T0.3: `group: registry-publish,
  // cancel-in-progress: false`, the only job that writes to the catalogue,
  // serialised. Its own comment named what that did not promise — a pending
  // `publish` could still be replaced by a newer one — and said the durable fix
  // was recovery rather than a key. This is that fix: the lane is gone, and two
  // publishes racing to push now end in a re-apply or a refusal, in
  // `bot/publish-apply.mjs`, instead of one of them never starting.
  //
  // `bot/tests/workflows.test.mjs` asserts the same absence by scanning the
  // publish job's block. The overlap is deliberate and small: that suite runs
  // only in `bot-tests.yml`, and this one also runs inside `ingest.yml` before
  // every ingest, which is the run where being wrong about this costs a
  // publication.
  // Comment lines are skipped, and not as a convenience: the job's own comment
  // names the group it used to have, so that somebody reading the YAML learns
  // why it is absent. A scan of the raw file would make that explanation
  // indistinguishable from the thing it explains — the same trap that caught
  // `tools/selftest.mjs`'s signer rule and `workflows.test.mjs`'s submitter
  // rule, both of which now skip comments for this reason.
  const lane = ingestWorkflow
    .split("\n")
    .filter((l) => !l.trim().startsWith("#"))
    .filter((l) => /group:\s*registry-publish/.test(l));
  assertEqual(lane.join(" | "), "",
    "the repo-wide publish lane is back; a stranger's ping can drop another author's pending publish");
  assert(/node bot\/publish-apply\.mjs/.test(ingestWorkflow),
    "the publish job no longer goes through the file that makes a racing push survivable");
});

// ── the close on a publication ──────────────────────────────────────────────
//
// The one job in this workflow whose effect is invisible until a stranger
// publishes something: it closes the submission issue. Asserting its YAML is
// not enough — the interesting parts are in the script, and a script that
// closed the wrong thread, or closed one whose publication never landed, would
// look exactly like a correct one in a diff. So it is EXTRACTED and RUN here,
// against a fake `github` and a fake filesystem.

/** The `script: |` body of a named job in a workflow file, dedented. */
function jobScript(yaml, job) {
  const lines = yaml.split("\n");
  const start = lines.findIndex((l) => l === `  ${job}:`);
  if (start < 0) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^  \S/.test(lines[i])) { end = i; break; }
  }
  const body = lines.slice(start, end);
  const at = body.findIndex((l) => /^\s*script:\s*\|\s*$/.test(l));
  if (at < 0) return null;
  const indent = /^(\s*)/.exec(body[at + 1])[1];
  const out = [];
  for (let i = at + 1; i < body.length; i++) {
    if (body[i].trim() !== "" && !body[i].startsWith(indent)) break;
    out.push(body[i].slice(indent.length));
  }
  return out.join("\n");
}

const CLOSE_SCRIPT = jobScript(ingestWorkflow, "close");

/**
 * Runs the extracted script over `reports`, a map of directory name to
 * decision, and returns every call it made.
 */
async function runClose(reports, { issue = "", refused = "", failOn = [] } = {}) {
  const calls = [];
  const warnings = [];
  const fakeFs = {
    readdirSync: (dir) => {
      if (dir !== "reports") throw new Error(`ENOENT: ${dir}`);
      return Object.keys(reports);
    },
    readFileSync: (file) => {
      const m = /^reports\/([^/]+)\/decision\.json$/.exec(file);
      if (!m || !(m[1] in reports)) throw new Error(`ENOENT: ${file}`);
      return JSON.stringify(reports[m[1]]);
    },
  };
  const github = {
    rest: {
      issues: {
        update: async (args) => {
          if (failOn.includes(args.issue_number)) throw new Error(`#${args.issue_number} is locked`);
          calls.push(args);
        },
      },
    },
  };
  const core = { warning: (m) => warnings.push(m) };
  const context = { repo: { owner: "mihailinl", repo: "astra-registry" } };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const fn = new AsyncFunction("github", "context", "core", "require", "process", CLOSE_SCRIPT);
  await fn(github, context, core, (m) => (m === "node:fs" ? fakeFs : require(m)), {
    env: { ISSUE: issue, REFUSED: refused },
  });
  return { calls, warnings };
}

await test("the close job's script was found, so the tests below are about something", async () => {
  // The extraction is the whole rest of this section's premise. A rename in the
  // workflow that made `jobScript` return null would otherwise turn every test
  // below into a test of an empty string that passes.
  assert(CLOSE_SCRIPT, "no `script: |` under a `close:` job in ingest.yml");
  assert(/state_reason/.test(CLOSE_SCRIPT), CLOSE_SCRIPT);
  assert(CLOSE_SCRIPT.split("\n").length > 10, CLOSE_SCRIPT);
});

await test("a publication closes its issue, as completed", async () => {
  const { calls } = await runClose({ "ingest-report-1": { outcome: "publish", issue: 5 } }, { issue: "5" });
  assertEqual(calls.length, 1, JSON.stringify(calls));
  assertEqual(calls[0].issue_number, 5, "the thread that asked");
  assertEqual(calls[0].state, "closed", "");
  assertEqual(calls[0].state_reason, "completed",
    "`not_planned` is what a rejection uses; this request got what it asked for");
});

await test("nothing that did not publish closes anything", async () => {
  for (const outcome of ["delay", "review", "refuse"]) {
    const { calls } = await runClose({ "ingest-report-1": { outcome, issue: 5 } }, { issue: "5" });
    assertEqual(calls.length, 0, `${outcome} closed the issue: ${JSON.stringify(calls)}`);
  }
});

await test("a drained release closes the thread the queue entry remembered", async () => {
  // The cron path: no event, so no ISSUE in the environment. The number comes
  // out of the decision, which got it from the queue entry.
  const { calls } = await runClose({ "ingest-report-1": { outcome: "publish", issue: 12 } }, { issue: "" });
  assertEqual(calls.length, 1, JSON.stringify(calls));
  assertEqual(calls[0].issue_number, 12, "recovered with no event to read");
});

await test("a publication with no thread behind it closes nothing", async () => {
  // A release ping or the backstop. There is no issue; §0's answer to that is
  // the [notice] the comment job opens, not a close.
  const { calls } = await runClose({ "ingest-report-1": { outcome: "publish", issue: null } }, { issue: "" });
  assertEqual(calls.length, 0, JSON.stringify(calls));
});

await test("one issue carrying two releases is closed once", async () => {
  const { calls } = await runClose({
    "ingest-report-1": { outcome: "publish", issue: 5 },
    "ingest-report-2": { outcome: "publish", issue: 5 },
  }, { issue: "5" });
  assertEqual(calls.length, 1, JSON.stringify(calls));
});

await test("an unreadable report is skipped rather than fatal", async () => {
  const { calls } = await runClose({
    "ingest-report-1": undefined,
    "ingest-report-2": { outcome: "publish", issue: 5 },
  }, { issue: "5" });
  assertEqual(calls.length, 1, "the readable one still closed");
});

await test("a report that was refused does not get its issue closed", async () => {
  // The gate above says the RUN committed. It does not say every release in it
  // did: one report's refusal is one release's refusal now, and the run carries
  // on. Closing that author's thread would tell them to stop watching for a
  // listing this registry refused.
  const { calls } = await runClose(
    {
      "ingest-report-0": { outcome: "publish", issue: 7 },
      "ingest-report-1": { outcome: "publish", issue: 8 },
    },
    { refused: "ingest-report-0" },
  );
  assertEqual(calls.map((c) => c.issue_number).join(","), "8",
    `only the release that landed may be closed: ${JSON.stringify(calls)}`);
});

await test("one unclosable issue does not strand every other author in the run", async () => {
  // `comment` learned this the expensive way — one oversized report threw out of
  // the step and every other submission in the run got no answer at all — and
  // the same loop in `close` was left without the same guard. A close is worse:
  // nothing tries it again, so the thread stays open for ever over a listing
  // that is in the catalogue.
  const { calls, warnings } = await runClose(
    {
      "ingest-report-0": { outcome: "publish", issue: 11 },
      "ingest-report-1": { outcome: "publish", issue: 12 },
      "ingest-report-2": { outcome: "publish", issue: 13 },
    },
    { failOn: [12] },
  );
  assertEqual(calls.map((c) => c.issue_number).join(","), "11,13",
    `the other two authors' threads still close: ${JSON.stringify(calls)}`);
  assertEqual(warnings.length, 1, `the failure has to be said out loud: ${JSON.stringify(warnings)}`);
  assert(/#12/.test(warnings[0]), warnings[0]);
});

await test("the close waits for the commit, and for the comment", async () => {
  // Two orderings, both load-bearing, both expressed in YAML rather than in the
  // script — so they are asserted separately from the run above.
  const lines = ingestWorkflow.split("\n");
  const start = lines.findIndex((l) => l === "  close:");
  assert(start > 0, "no close job");
  const head = lines.slice(start, start + 6).join("\n");

  assert(/needs:.*\bpublish\b/.test(head),
    `the close must depend on the job that lands the commit:\n${head}`);
  assert(/needs:.*\bcomment\b/.test(head),
    `a close that races the comment is the silent close §0 forbids:\n${head}`);
  const cond = /if:\s*(.+)/.exec(head);
  assert(cond, head);
  // This asserted `needs.publish.result == 'success'` until B-T0.3, and the
  // reason it gave — "an outcome of \"publish\" is a decision, not a commit" —
  // is the same reason it now asserts something stronger. `result` is `success`
  // whenever publish-apply exited 0, and it exits 0 for `outcome=nothing` too:
  // a run that applied nothing, which happens whenever both artifact downloads
  // fail. So the job result stopped being the fact this gate needs on the day
  // the publish job gained an outcome that says what landed.
  assert(/needs\.publish\.outputs\.outcome\s*==\s*'committed'/.test(cond[1]),
    `the close must gate on what LANDED, not on the job exiting 0:\n${cond[1]}`);
  assert(!/needs\.publish\.result/.test(cond[1]),
    `the job result is success for a run that committed nothing:\n${cond[1]}`);
  assert(!/decision\.outcome/.test(cond[1]),
    `an outcome of "publish" is a decision, not a commit:\n${cond[1]}`);
  // `always()` here would run the close even when the comment or the publish
  // failed, which is exactly the pair of failures it must not survive.
  assert(!/always\(\)/.test(cond[1]), cond[1]);
});

await test("the approval's binding is wired from triage's target to decide's flag", async () => {
  // Three names for one field, in three files, and a typo in any of them makes
  // the approval unbound rather than loud: `triage.mjs` writes `approved_for`
  // into the target, the matrix carries it, and `decide.mjs` reads
  // `--approved-for`.
  const triageSrc = fs.readFileSync(path.join(REPO_ROOT, "bot", "triage.mjs"), "utf8");
  assert(/approved_for: out\.approvedFor/.test(triageSrc), "triage must put it on the target");
  assert(/APPROVED_FOR: \$\{\{ matrix\.approved_for \}\}/.test(ingestWorkflow),
    "the matrix entry has to reach the check job");
  assert(/--approved-for "\$APPROVED_FOR"/.test(ingestWorkflow),
    "and the check job has to pass it to decide.mjs");
});

section("the document and the code say the same thing");

await test("docs/POLICY.md quotes the numbers the code enforces", () => {
  const doc = fs.readFileSync(path.join(REPO_ROOT, "docs", "POLICY.md"), "utf8");
  for (const needle of [
    `${DELAY_HOURS} h`,
    `${TRUSTED_DELAY_HOURS} h`,
    `${REVIEW_SLA_HOURS} h`,
    `${CLEAN_RELEASES_FOR_TRUSTED} clean`,
    `${WATCH_AFTER_DAYS} days`,
  ]) {
    assert(doc.includes(needle), `docs/POLICY.md never says "${needle}", so the published policy has drifted from the code`);
  }
  for (const name of HIGH_RISK) {
    assert(doc.includes(`\`${name}\``), `docs/POLICY.md does not list ${name} as high-risk`);
  }
  for (const code of Object.keys(POLICY_CODES)) {
    assert(doc.includes(code), `docs/POLICY.md does not explain ${code}, which an author can be shown`);
  }
});

await test("docs/POLICY.md quotes the triage clock the moderation code declares", async () => {
  const { TRIAGE_ACK_HOURS, TRIAGE_HARM_HOURS, TRIAGE_DECISION_DAYS, APPEAL_RESPONSE_DAYS, ACTIONS } =
    await import("../lib/moderation.mjs");
  const doc = fs.readFileSync(path.join(REPO_ROOT, "docs", "POLICY.md"), "utf8");
  for (const needle of [
    `**${TRIAGE_ACK_HOURS} h**`,
    `**${TRIAGE_HARM_HOURS} h**`,
    `**${TRIAGE_DECISION_DAYS} days**`,
    `**${APPEAL_RESPONSE_DAYS} days**`,
  ]) {
    assert(doc.includes(needle),
      `docs/POLICY.md never says "${needle}", so the published triage clock has drifted from the code`);
  }
  // The four escalating actions, each named where a reporter will look for it.
  for (const action of ACTIONS) {
    const titled = action[0].toUpperCase() + action.slice(1);
    assert(doc.includes(`**${titled}**`), `docs/POLICY.md does not name the ${action} action`);
  }
  // And the appeals template, which is what an author is told to use.
  assert(doc.includes("[appeal] <plugin-id>"), "docs/POLICY.md carries no appeals template");
});

await test("POLICY.md points at the detail rather than restating it", () => {
  const doc = fs.readFileSync(path.join(REPO_ROOT, "POLICY.md"), "utf8");
  assert(doc.includes("docs/POLICY.md"), "the listing policy has to link the publication policy");
  assert(doc.includes(`${REVIEW_SLA_HOURS} hours`) || doc.includes(`${REVIEW_SLA_HOURS} h`),
    "and §8 has to carry the number now that there is one");
});

// MIG-3, and the shape of it that can run TODAY. The bot reads the binding
// deadline only from `policy/binding-deadline.json` (contract MIG-2), and a
// registry test must fail when that file and POLICY.md disagree. Neither the
// file nor the sentence exists yet — the date is the owner's, committed before
// R4b with the POLICY.md line in the same commit (M-T5.2, reg.87) — so the
// check is written against the ABSENCE, and is live from today in both
// directions:
//
//   file absent  → no policy document may state a deadline date. A date in
//                  prose that no committed record backs is MIG-3's failure
//                  arriving from the side nobody watches: the bot would read
//                  no deadline at all while the published policy promised one,
//                  and every listing would stay `grandfathered` past it.
//   file present → at least one policy document states it, and every deadline
//                  date either document carries is that one.
//
// The comparison is on the ISO form: a date counts as a deadline claim when
// `deadline` appears within 200 characters of it, and the committed value is a
// §0.7 time, so the prose must carry `YYYY-MM-DD` (spelling the date out as
// well is fine). That requirement is this check's own rather than MIG-3's, and
// it is the only way a machine can hold two documents to one date.
await test("MIG-3 — the deadline is in one place, and no document states one that is not there", async () => {
  const { DEADLINE_FILE, readMarkers } = await import("../lib/listing-state.mjs");
  const committed = readMarkers(REPO_ROOT).deadline;

  const claims = [];
  for (const rel of ["POLICY.md", "docs/POLICY.md"]) {
    const text = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
    for (const m of text.matchAll(/\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?/g)) {
      const around = text.slice(Math.max(0, m.index - 200), m.index + m[0].length + 200);
      if (/deadline/i.test(around)) {
        claims.push({ file: rel, date: m[0], line: text.slice(0, m.index).split("\n").length });
      }
    }
  }
  const where = claims.map((c) => `${c.file}:${c.line} ${c.date}`).join(", ");

  if (committed === null) {
    assertEqual(claims.length, 0,
      `${DEADLINE_FILE} is not committed, so the bot reads no binding deadline — and these say there is one: ` +
      `${where}. The date lands in the same commit as the file (MIG-2, MIG-3), never before it`);
    return;
  }
  assert(claims.length >= 1,
    `${DEADLINE_FILE} commits ${committed} and neither POLICY.md states it. MIG-14's notices send authors to the ` +
    "published policy for the date, so write it there as `YYYY-MM-DD` and this check will compare the two");
  for (const c of claims) {
    assert(c.date === committed || c.date === committed.slice(0, 10),
      `${c.file}:${c.line} states the deadline ${c.date} and ${DEADLINE_FILE} commits ${committed}. The bot reads ` +
      "the file (MIG-3), so the document is the half that is wrong");
  }
});

// M-T3.2's half of reg.61a, written — like MIG-3 above — against the ABSENCE,
// because the number is not published yet and inventing one here would be the
// registry promising a blast-radius cap nobody can read.
//
// `TAKEDOWN_BOUND` in `bot/lib/moderation.mjs` decides how many listed plugin
// ids the estate may withdraw in a trailing 24 h before the next takedown
// waits for an operator (TRUST-26, MOD-9). The owner closed OPEN-OWNER-3 at 3;
// reg.61a lands that 3 and the POLICY.md §7 sentence together, and until it
// does the constant is 1 — the strictest value that is still a bound. Both
// directions are live from today:
//
//   no published bound → the constant is 1. A bot enforcing 3 against a policy
//                        that promises nothing is a promise with no document
//                        behind it, and the day somebody reads the constant as
//                        the published rule is the day the estate learns it was
//                        never published.
//   a published bound  → the constant is that number, every policy document
//                        stating one states the same one, and the document also
//                        says that above the bound a takedown waits for an
//                        operator, that a removal request counts and that an
//                        author's yank counts. So reg.61a cannot land half of
//                        itself in either order.
//
// THE CANONICAL FORM is this check's own requirement, as `YYYY-MM-DD` is
// MIG-3's: a bound is claimed by a number — digit or word — followed within 40
// characters by "in any/a/the trailing 24 hours". It is how `docs/RUNBOOK.md`
// §7.10 already writes it, and it is the only way a machine can hold three
// documents to one number.
//
// FLOW-42's PER-ACCOUNT CAP IS EXCLUDED BY NAME, and that exclusion is the
// subtle half. "each account at one listed plugin id in any trailing 24 hours"
// is a different number in identical units, it is the SERVICE's cap and not the
// registry's — the bot never learns which account acted (TRUST-37, DEC-7) — and
// a scan that conflated them would pin TRUST-26's bound to FLOW-42's 1 and be
// green about it. Any claim with "account" within 120 characters is not this
// bound.
//
// docs/RUNBOOK.md IS IN THE SCAN, and not as decoration. It is the operator's
// document, not the published policy, and it has stated the bound at 3 since
// before any code counted one. Nothing compared it with anything. The leg
// asserted here is the one that is live today and non-vacuous: the code may
// never hold LATER than the runbook says it will. Holding sooner is a surprise
// in the safe direction; holding later means an operator who planned by §7.10
// watched a fourth withdrawal go out.
await test("M-T3.2 — the takedown bound the code enforces is the one a document publishes", async () => {
  const { TAKEDOWN_BOUND } = await import("../lib/moderation.mjs");
  const { execFileSync } = await import("node:child_process");

  assert(Number.isInteger(TAKEDOWN_BOUND) && TAKEDOWN_BOUND >= 1,
    `TAKEDOWN_BOUND is ${JSON.stringify(TAKEDOWN_BOUND)}; a bound below 1 holds the first withdrawal of every ` +
    "day, which is a stop and not a bound");

  // The floor, measured against the TRACKED set rather than a readdir: a third
  // published policy document is a document this scan would never open, and the
  // absence branch would go on being green about the number in it.
  const tracked = execFileSync("git", ["-C", REPO_ROOT, "ls-files"], { encoding: "utf8", env: cleanEnv() })
    .split("\n").filter((p) => /(^|\/)POLICY\.md$/.test(p)).sort();
  assertEqual(tracked.join(", "), "POLICY.md, docs/POLICY.md",
    "the published policy documents are not the two this check reads; a document it does not open can state " +
    "any bound it likes and nothing here will notice");

  const WORDS = { one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9 };
  const CLAIM = /\b(\d+|one|two|three|four|five|six|seven|eight|nine)\b[^.\n]{0,40}?\bin\s+(?:any|a|the)\s+trailing\s+24\s+hours?\b/gi;
  const read = (rel) => fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
  const claimsIn = (rel) => {
    const text = read(rel);
    const out = [];
    for (const m of text.matchAll(CLAIM)) {
      const around = text.slice(Math.max(0, m.index - 120), m.index + m[0].length + 120);
      if (/\baccounts?\b/i.test(around)) continue;            // FLOW-42's cap, not TRUST-26's bound
      const raw = m[1].toLowerCase();
      out.push({ where: `${rel}:${text.slice(0, m.index).split("\n").length}`, value: WORDS[raw] ?? Number(raw) });
    }
    return out;
  };

  // ── the operator's document, which has carried the number all along ───────
  const runbook = claimsIn("docs/RUNBOOK.md");
  assertEqual(runbook.length, 1,
    `docs/RUNBOOK.md §7.10 states ${runbook.length} takedown bound(s) in the form this check reads ` +
    `(${runbook.map((c) => `${c.where} ${c.value}`).join(", ") || "none"}); it stated exactly one on 2026-09-20, ` +
    "and a scan that finds none reports every number as agreeing");
  assert(TAKEDOWN_BOUND <= runbook[0].value,
    `bot/lib/moderation.mjs enforces ${TAKEDOWN_BOUND} and ${runbook[0].where} tells an operator the bound is ` +
    `${runbook[0].value}. The code may hold sooner than the runbook promises, never later: an operator who ` +
    "planned a day's withdrawals by §7.10 would watch the one past the bound go out unheld");

  // ── the published policy, which does not carry it yet ─────────────────────
  const published = tracked.flatMap(claimsIn);
  const mentions = tracked.filter((rel) => /takedown/i.test(read(rel)));
  const refers = mentions.filter((rel) => /takedown bound|bound[^.\n]{0,40}takedown/i.test(read(rel)));

  // THREE STATES, NOT TWO — and the two it shipped with were not the wrong two,
  // they were a conjunction standing in for one of them. The silent branch
  // asserts `no bound is published` AND `the constant is 1`: two claims about
  // two different subjects, the document and the value. While both held, one
  // branch covered both. On 2026-09-20 M-T1.6 wrote one true sentence into
  // docs/POLICY.md — a reverted delist applies at once, "outside the takedown
  // bound" — and the conjunction broke. This check reported it in the only
  // vocabulary it had: THE NUMBER IS MISSING. Right that something changed,
  // wrong about what.
  //
  // That mattered because the remedy a failure names decides what gets done.
  // "Write the number" makes the cheapest green a reword of the sentence until
  // the regex stops matching — which would have deleted the only thing pointing
  // at the gap while leaving the gap. The gap is OLDER than the sentence: this
  // document promised nothing and defined nothing, and that was safe only while
  // it also said nothing. A reader who is told a bound exists and cannot look
  // it up is worse off than one who was never told, and reverting the sentence
  // restores invisibility rather than correctness.
  //
  // So the third state gets its own branch and its message names the DOCUMENT
  // rather than the constant. Same verdict either way; opposite cheapest
  // repair, and that is the entire difference.
  if (mentions.length === 0) {
    assertEqual(published.length, 0,
      `no published policy document mentions a takedown and yet ${published.map((c) => c.where).join(", ")} ` +
      "states a trailing-24-hour bound; a number with nothing around it saying what it bounds is worse than none");
    assertEqual(TAKEDOWN_BOUND, 1,
      `POLICY.md and docs/POLICY.md publish no takedown bound, so bot/lib/moderation.mjs must enforce 1 — the ` +
      `strictest bound that is still one — and it enforces ${TAKEDOWN_BOUND}. reg.61a lands the owner's 3 ` +
      "(OPEN-OWNER-3) and the POLICY.md §7 sentence in ONE commit (M-T3.2, B-T3.3b); neither half lands alone");
    return;
  }

  if (published.length === 0) {
    assert(refers.length === 0,
      `${refers.join(" and ")} refer${refers.length === 1 ? "s" : ""} to THE TAKEDOWN BOUND and never states ` +
      "it. This is a defect in the document, not in the constant: a reader is told a bound exists and is given " +
      "no way to learn it, and the only place the number is written down is docs/RUNBOOK.md, which is the " +
      "operator's document and not the published policy. TWO REPAIRS, AND THEY ARE NOT EQUAL. Land reg.61a — " +
      "the owner's 3 (OPEN-OWNER-3) and the §7 sentence in ONE commit (M-T3.2 with B-T3.3b), gated at rollout " +
      "step R3 — or delete the reference. Deleting it restores INVISIBILITY, not correctness: this document " +
      "was incomplete before the sentence was written, and the sentence is the only thing pointing at it. " +
      "Prefer the first, and while R3 is unreached prefer a red main with this message to a green one without");
    assert(false,
      `${mentions.join(" and ")} discuss${mentions.length === 1 ? "es" : ""} takedowns and publish` +
      `${mentions.length === 1 ? "es" : ""} no bound this check can read. Write it as ` +
      "`<n> in any trailing 24 hours` — a digit or the word — and this check " +
      "will compare it with bot/lib/moderation.mjs");
  }
  for (const c of published) {
    assertEqual(c.value, TAKEDOWN_BOUND,
      `${c.where} publishes a takedown bound of ${c.value} and bot/lib/moderation.mjs enforces ${TAKEDOWN_BOUND}. ` +
      "The published number is the promise; the constant is what keeps it");
  }
  // What the sentence has to carry beside the number (OPEN-OWNER-3, OPEN-OWNER-14,
  // FLOW-79, and the C16 correction reg.61a's line must say rather than the
  // overstated framing the owner was shown).
  const paragraphs = mentions
    .flatMap((rel) => read(rel).split(/\n\s*\n/).map((p) => ({ rel, p })))
    .filter(({ p }) => /takedown/i.test(p));
  const said = paragraphs.map(({ p }) => p).join("\n\n");
  for (const [what, re] of [
    ["that above the bound a takedown waits for an operator", /\boperator\b/i],
    ["that a removal request counts toward it", /removal request/i],
    ["that an author's yank counts toward it", /\byank/i],
  ]) {
    assert(re.test(said),
      `the published takedown-bound paragraphs never say ${what}. An author reads that sentence before using ` +
      "the yank, and it is the only place this side reduces the surprise (M-T3.2, OPEN-OWNER-45's C16)");
  }
});


// ── B-T3.3c: the outcomes that write nothing ────────────────────────────────

section("no-record outcomes (B-T3.3c)");

// A minimal `decide()` input that publishes, so each test below changes one
// thing and the change is what the assertion is about.
function publishable(over = {}) {
  return {
    findings: [],
    derived: {
      plugin: { id: "dice-roller", source: { kind: "github", repo: "you/dice-roller" } },
      version: { version: "1.0.1", release: { repo: "you/dice-roller", commit: "a".repeat(40) }, artifacts: [] },
    },
    existing: null,
    repo: "you/dice-roller",
    tag: "v1.0.1",
    now: new Date("2026-09-20T00:00:00Z"),
    ...over,
  };
}

await test("FLOW-72 — a wait on the service path gives a wait and writes nothing", () => {
  const d = decide(publishable({
    path: "service",
    findings: [{ level: "error", code: "E_PROBE_UNAVAILABLE", where: "probe", message: "the manifest probe did not answer" }],
  }));
  assertEqual(d.record.write, false, "a wait was going to be written into log/decisions/ as a refusal");
  assertEqual(d.wait?.code, "E_PROBE_UNAVAILABLE", "the result carries no wait for the caller to re-ask on");
  assert(d.reasons.every((r) => r.code !== "P_REFUSED"),
    "the wait reached stage 1 and came out as a refusal of the author's release");
});

// The watched failure the plan names, in the direction it would actually
// arrive: the SAME code on the legacy path is an error and IS recorded,
// because there the author has a thread and a `/recheck`.
await test("FLOW-72 — the same code on the legacy path still refuses, and still records", () => {
  const d = decide(publishable({
    findings: [{ level: "error", code: "E_PROBE_UNAVAILABLE", where: "probe", message: "the manifest probe did not answer" }],
  }));
  assertEqual(d.outcome, "refuse", "the legacy path stopped refusing a probe failure");
  assertEqual(d.record.write, true,
    "the legacy path stopped recording a refusal the author can answer with /recheck; FLOW-72's " +
    "reclassification is the SERVICE path's and widening it silently drops the legacy decision log");
  assertEqual(d.wait, null, "a legacy refusal is not a wait");
});

// The property, not the list. This is the failure mode the plan names for this
// task: B-T3.3c listing the wait codes by hand, and a sibling coining a sixth.
await test("FLOW-72 is keyed on the declared level, so a wait nobody enumerated still waits", () => {
  for (const code of ["W_SERVICE_UNREACHABLE", "W_ELIGIBILITY_UNREADABLE", "W_OPERATOR_WINDOW",
                      "W_GITHUB_RATE_LIMITED", "W_REGISTRY_UNACKNOWLEDGED", "E_ATTESTATION_UNCHECKED",
                      "E_TRUST_UNPROVISIONED", "E_PROBE_INPUT", "E_DERIVED_LISTING_INVALID"]) {
    const d = decide(publishable({
      path: "service",
      findings: [{ level: "error", code, where: "x", message: `${code} happened` }],
    }));
    assertEqual(d.record.write, false, `${code} is declared a wait and was recorded anyway`);
    assertEqual(d.wait?.code, code, `${code} is declared a wait and produced no wait`);
  }
  // And the floor: if `policyCodeDef` stopped answering `wait` for anything,
  // every assertion above would pass vacuously on an empty loop. It does not
  // loop over an empty set, but it does loop over a list — so the floor is
  // that the list is a SUBSET of what is declared, checked from the other end.
  const declaredWaits = ["W_SERVICE_UNREACHABLE", "W_ELIGIBILITY_UNREADABLE", "W_OPERATOR_WINDOW",
                         "W_GITHUB_RATE_LIMITED", "W_REGISTRY_UNACKNOWLEDGED"]
    .filter((c) => policyCodeDef(c).level === "wait");
  assertEqual(declaredWaits.length, 5,
    "a W_* code stopped being declared a wait in constants.mjs, and every rule above keys on that level");
});

await test("a check that PASSED is never reclassified as a wait", () => {
  // Found by running the rule against the real corpus rather than by reading
  // it. `codes.mjs` codes name a CHECK, and the same code carries its pass:
  // every green ingest emits `E_TRUST_UNPROVISIONED` at level `pass` ("trust.json
  // serial 7 … allows 1 release-workflow commit(s)") and
  // `E_DERIVED_LISTING_INVALID` at level `pass`. Keyed on the code alone, a
  // service-path run waits on its own passing checks and the release is never
  // decided at all.
  const d = decide(publishable({
    path: "service",
    findings: [
      { level: "pass", code: "E_TRUST_UNPROVISIONED", where: "trust", message: "trust.json serial 7 allows 1 commit" },
      { level: "pass", code: "E_DERIVED_LISTING_INVALID", where: "derive", message: "the derived listing passes tools/validate.mjs" },
    ],
  }));
  assertEqual(d.wait, null, "a passing check was reclassified as a wait, and this release will never be decided");
  assertEqual(d.outcome, "publish", "a green service-path run did not publish");
  assertEqual(d.record.write, true, "a green service-path run wrote no record");
});

await test("a wait never reaches the delay clock or the queue", () => {
  const d = decide(publishable({
    path: "service",
    findings: [{ level: "error", code: "W_SERVICE_UNREACHABLE", where: "ask", message: "no answer" }],
  }));
  assertEqual(d.queue_entry, null, "a wait queued the release, so an unanswered call starts a publication clock");
  assertEqual(d.publishes_now, false, "a wait published");
});

await test("`decide()` passes the path to every level lookup", () => {
  // Watched by dropping the argument: with `path` ignored, the service-path
  // run below reads `E_PROBE_UNAVAILABLE` at `codes.mjs`'s level — `error` —
  // and records a refusal. The two runs differ only in `path`.
  const service = decide(publishable({ path: "service", findings: [{ level: "error", code: "E_PROBE_INPUT", where: "p", message: "m" }] }));
  const legacy = decide(publishable({ findings: [{ level: "error", code: "E_PROBE_INPUT", where: "p", message: "m" }] }));
  assert(service.record.write !== legacy.record.write,
    "the same code on the two paths produced the same answer, so `path` is not reaching policyCodeDef " +
    "and FLOW-72's whole distinction is inert");
});

await test("BOT-19 — a terminal record on main is reported, and nothing is written", () => {
  const hit = terminalOnMain({
    records: [{ plugin_id: "dice-roller", state: "revoked", decision_id: "d0" }],
    pluginId: "dice-roller", repo: "you/dice-roller", tag: "v1.0.1",
  });
  assertEqual(hit?.reported, "revoked", "a panel stop in git did not stop a ping");
  assertEqual(hit.record.write, false, "a second record was written for a decision main already carries");
  assertEqual(hit.names, "d0", "the report names no existing record, so nobody can go and read it");
  // A non-terminal record does not stop anything.
  assertEqual(
    terminalOnMain({ records: [{ plugin_id: "dice-roller", state: "published", decision_id: "d1" }], pluginId: "dice-roller", repo: "you/dice-roller", tag: "v1.0.1" }),
    null,
    "a published record was read as terminal, which stops every later release of a live plugin",
  );
});

await test("BOT-74 — a tag already listed with identical digests is reported `published`", () => {
  const digests = ["sha256:aa", "sha256:bb"];
  const same = alreadyPublished({ listed: { version: "1.0.1", artifact_digests: [...digests].reverse(), decision_id: "d7" }, digests });
  assertEqual(same?.reported, "published", "a re-submission of published bytes was not recognised");
  assertEqual(same.record.write, false, "a second record was written for a version already listed");
  assertEqual(same.names, "d7", "the `published` result names no record (BOT-23)");
  // The tag moved to different bytes: that is a new submission, not a
  // re-submission, and answering `published` for it would report a
  // publication of bytes nobody verified.
  assertEqual(
    alreadyPublished({ listed: { version: "1.0.1", artifact_digests: ["sha256:aa"], decision_id: "d7" }, digests }),
    null,
    "different bytes under the same version were reported as already published",
  );
  assertEqual(
    alreadyPublished({ listed: { version: "1.0.1", artifact_digests: [], decision_id: "d7" }, digests }),
    null,
    "a listing with no recorded digests compared equal to something, which makes the digest check decoration",
  );
});

await test("FLOW-67 — a threadless submission no listing names writes nothing, and carries the read commit", () => {
  const commit = "b".repeat(40);
  for (const source of ["panel", "ci"]) {
    const out = noListingNoBinding({ source, listingNamesRepo: false, binding: { present: false }, readCommit: commit, repo: "stranger/thing" });
    assertEqual(out?.record.write, false, `a ${source} submission from an unlisted repository was recorded`);
    assertEqual(out.read_commit, commit, "FLOW-78: the result carries no read commit, so the absence is a claim about a moving target");
  }
  // `B_BINDING_UNUSABLE` is the same case as an absent line.
  assertEqual(
    noListingNoBinding({ source: "panel", listingNamesRepo: false, binding: { present: true, code: "B_BINDING_UNUSABLE" }, readCommit: "c".repeat(40), repo: "stranger/thing" })?.record.write,
    false,
    "an unusable binding line was treated as a usable one",
  );
  // A USABLE line is a request to be listed, and is decided rather than dropped.
  assertEqual(
    noListingNoBinding({ source: "panel", listingNamesRepo: false, binding: { present: true, code: null }, readCommit: "c".repeat(40), repo: "stranger/thing" }),
    null,
    "a repository that asked to be listed was silently dropped",
  );
  // A listed repository is decided, whatever its line says.
  assertEqual(
    noListingNoBinding({ source: "panel", listingNamesRepo: true, binding: { present: false }, readCommit: "c".repeat(40), repo: "you/dice-roller" }),
    null,
    "a listing this registry already carries stopped being decided because its line went missing",
  );
  // And the legacy sources keep their thread: a refusal there is a sentence
  // somebody reads on an issue.
  for (const source of ["issue", "ping", "backstop", "queue"]) {
    assertEqual(
      noListingNoBinding({ source, listingNamesRepo: false, binding: { present: false }, readCommit: "c".repeat(40), repo: "stranger/thing" }),
      null,
      `a ${source} submission stopped being answered, and that path's only output is the answer`,
    );
  }
});

await test("FLOW-65 — a new id from a listed monorepo meets the first-listing rules", () => {
  // The rule is a property of how `existing` is looked up: by plugin ID, never
  // by repository. Keyed on the repository, a monorepo's second plugin would
  // inherit the first one's listing and skip R_FIRST_LISTING — the one check
  // that is a person reading a submission, skipped for every plugin after the
  // first in any repository that ships more than one.
  const d = decide(publishable({
    existing: null,   // no listing carries THIS id, though the repo is listed
    findings: [{ level: "review", code: "R_FIRST_LISTING", where: "version", message: "never listed" }],
  }));
  assertEqual(d.outcome, "review", "a new id from a listed monorepo published without a person reading it");
  assert(d.reasons.some((r) => r.code === "R_FIRST_LISTING"), "and it did not raise the first-listing hold");
  assertEqual(d.record.write, true, "a first-listing hold is a decision, and a decision is recorded");
});


// ── B-T3.9: the legacy path under the new records (R3 to R6) ───────────────

section("the legacy path under the new records (B-T3.9)");

await test("BOT-77 — a legacy run on a bound listing publishes nothing, queues nothing, clears nothing", () => {
  const identityRecord = {
    schema: "astra.registry.identity/1", plugin_id: "dice-roller",
    repository_id: "111", repository_owner_id: "222", repo: "you/dice-roller",
  };
  // The strongest case, and it has to be built rather than described: a clean
  // release with a maintainer's `/publish` BOUND to this run's own
  // fingerprint. Written with a made-up fingerprint the first time, this test
  // passed with the guard removed — the approval was refused as stale and the
  // `P_APPROVAL_STALE` hold produced the same `review` the guard does, so four
  // of its five assertions were about a code path the mutation never reached.
  const fingerprint = decide(publishable({})).fingerprint;
  assert(fingerprint, "the clean run produced no fingerprint to bind an approval to");
  const d = decide(publishable({
    identityRecord,
    approval: { by: "maintainer", at: "2026-09-19T00:00:00Z", for: fingerprint, publishNow: true },
  }));
  assertEqual(d.outcome, "review", "the legacy path published a bound listing");
  assertEqual(d.publishes_now, false, "the legacy path published a bound listing");
  assertEqual(d.queue_entry, null, "the legacy path queued a bound listing");
  assertEqual(d.approved_by, null,
    "a `/publish` on the legacy path cleared the hold on a bound listing — which is the binding being " +
    "routed around by whoever can comment on an issue in this repository");
  assert(d.reasons.some((r) => String(r.message).includes("BOT-77")), "and the comment does not say why");
  // The same release, unbound, publishes. Without this the assertions above
  // pass for a `decide()` that refuses everything.
  const unbound = decide(publishable({}));
  assertEqual(unbound.outcome, "publish", "the floor: an unbound listing stopped publishing, so BOT-77's guard proves nothing");
});

await test("BOT-77 does not bind the service path, which is the path that holds the binding", () => {
  const d = decide(publishable({
    path: "service",
    identityRecord: { schema: "astra.registry.identity/1", plugin_id: "dice-roller", repo: "you/dice-roller" },
  }));
  assertEqual(d.outcome, "publish",
    "BOT-77 stopped the service path too, which would leave a bound listing publishable by nothing at all");
});

await test("BOT-74 — a `cli-v` ping gives no ingest, and so no record", () => {
  const listedTags = ["v0.1.0", "v0.2.0"];
  assertEqual(bot74Filter({ tag: "cli-v1.4.0", listedTags }).pass, false,
    "a monorepo's CLI tag was dispatched as a plugin release, and from R3 the refusal is a public record");
  assertEqual(bot74Filter({ tag: "v0.3.0", listedTags }).pass, true,
    "the listing's own next release was filtered out, which stops the backstop working at all");
  assertEqual(bot74Filter({ tag: "v0.2.0", listedTags }).pass, false,
    "a tag already recorded on the listing was re-ingested");
  // The prefix set is read from the recorded tags, so a listing that uses a
  // prefix nothing in this repository uses still works. This is the property,
  // not a list of `v` and `cli-v`.
  assertEqual(bot74Filter({ tag: "release-2026.3", listedTags: ["release-2026.1", "release-2026.2"] }).pass, true,
    "the filter has a hard-coded idea of what a release tag looks like, and this listing does not share it");
  assertEqual(bot74Filter({ tag: "nightly-2026.3", listedTags: ["release-2026.1"] }).pass, false,
    "a second tag shape on a listing that only ever used one was dispatched");
  // A first listing has no evidence to filter by, and inventing some here
  // would be this module deciding what a release tag is.
  assertEqual(bot74Filter({ tag: "anything", listedTags: [] }).pass, true,
    "a listing with no recorded tag cannot be filtered, and a filter that refuses everything there " +
    "silently turns the backstop off for every new listing");
});

await test("B-T3.7 — the legacy path writes no record until the baseline marker is on main", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "b4-marker-"));
  try {
    assertEqual(markerOnMain(dir).present, false, "a tree with no log/baseline.json reported a marker");
    fs.mkdirSync(path.join(dir, "log"), { recursive: true });
    fs.writeFileSync(path.join(dir, "log", "baseline.json"), JSON.stringify({ schema: "astra.registry.baseline/1", version_count: 1, record_count: 1 }));
    assertEqual(markerOnMain(dir).present, true, "a real marker was not recognised");
    // The shape is checked, not merely the path: an empty file, or somebody
    // else's JSON, is not MIG-20's baseline and must not switch the writer on.
    fs.writeFileSync(path.join(dir, "log", "baseline.json"), JSON.stringify({ schema: "something.else/1" }));
    assertEqual(markerOnMain(dir).present, false, "any JSON at that path switched the legacy decision log on");
    fs.writeFileSync(path.join(dir, "log", "baseline.json"), "not json");
    assertEqual(markerOnMain(dir).present, false, "an unreadable marker switched the legacy decision log on");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

await test("an unreadable identity.json is not an absent one", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "b4-identity-"));
  try {
    assertEqual(readIdentityRecord(dir, "dice-roller"), null, "an absent binding was not absent");
    fs.mkdirSync(path.join(dir, "plugins", "dice-roller"), { recursive: true });
    fs.writeFileSync(path.join(dir, "plugins", "dice-roller", "identity.json"), "{ broken");
    let threw = null;
    try { readIdentityRecord(dir, "dice-roller"); } catch (e) { threw = e; }
    assert(threw, "an unreadable binding read as absent, and BOT-77's guard is keyed on present-or-absent: " +
      "a corrupt file would have let the legacy path publish a bound listing");
    assert(String(threw.message).includes("BOT-77"), "and the failure does not say what it protects");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


await test("B-T0.2 stage 2 — /approve is refused when no `held` record on main carries its fingerprint", async () => {
  const fp = "a".repeat(16);
  const line = `/approve ${REPO}@${TAG} ${fp}`;

  // Before the baseline marker there are no records at all, and the rule is
  // OFF. Ungated, it would refuse every approval this registry has ever
  // accepted — the gate is the condition under which the thing being checked
  // exists, not a softening of it.
  const noMarker = await command(line, "the-maintainer");
  assertEqual(noMarker.mode, "approve",
    "the held-record rule fired before any record could exist, so every /approve is refused at once");

  // With the marker on main and no matching `held` record, it is refused.
  const root = registryTree([{}]);
  fs.mkdirSync(path.join(root, "log"), { recursive: true });
  fs.writeFileSync(path.join(root, "log", "baseline.json"),
    JSON.stringify({ schema: "astra.registry.baseline/1", version_count: 1, record_count: 1 }));
  const unrecorded = await command(line, "the-maintainer", { root });
  assertEqual(unrecorded.mode, "reply", unrecorded.why);
  assert(unrecorded.reply.includes(fp), "the refusal does not name the fingerprint it could not find");

  // And accepted once the record is there. Without this the assertion above
  // passes for a rule that refuses everything.
  fs.mkdirSync(path.join(root, "log", "decisions", "2026", "09"), { recursive: true });
  fs.writeFileSync(path.join(root, "log", "decisions", "2026", "09", "held1.json"),
    JSON.stringify({ schema: "astra.registry.decision/1", decision_id: "held1", state: "held", fingerprint: fp }));
  const recorded = await command(line, "the-maintainer", { root });
  assertEqual(recorded.mode, "approve", recorded.why);

  // A `held` record for SOME OTHER fingerprint does not do. This is the case
  // the rule exists for: a fingerprint copied out of a comment on another
  // thread reads exactly like a valid one until it is compared.
  fs.rmSync(path.join(root, "log", "decisions", "2026", "09", "held1.json"));
  fs.writeFileSync(path.join(root, "log", "decisions", "2026", "09", "held2.json"),
    JSON.stringify({ schema: "astra.registry.decision/1", decision_id: "held2", state: "held", fingerprint: "b".repeat(16) }));
  assertEqual((await command(line, "the-maintainer", { root })).mode, "reply",
    "an approval bound to somebody else's hold");

  // A record that is not `held` is not a hold. A `published` record naming the
  // same fingerprint is the ordinary aftermath of the hold being cleared, and
  // reading it as a hold would make every approval replayable for ever.
  fs.rmSync(path.join(root, "log", "decisions", "2026", "09", "held2.json"));
  fs.writeFileSync(path.join(root, "log", "decisions", "2026", "09", "pub.json"),
    JSON.stringify({ schema: "astra.registry.decision/1", decision_id: "pub", state: "published", fingerprint: fp }));
  assertEqual((await command(line, "the-maintainer", { root })).mode, "reply",
    "a published record was read as a standing hold, which makes every cleared approval replayable");

  // And the same on a `[notice]` thread, which is where stage 1 opened a second
  // way in. Stage 2's bind is the durable one and it is shared code — asserted
  // rather than assumed, because "it is the same code path" is exactly the
  // sentence that stops being true one refactor later, and a second route into
  // `mode: approve` that skipped this would be a second set of rules.
  assertEqual((await onThread(line, "the-maintainer", { root })).mode, "reply",
    "a hold raised off the listing issue bypassed the held-record bind");
  fs.rmSync(path.join(root, "log", "decisions", "2026", "09", "pub.json"));
  fs.writeFileSync(path.join(root, "log", "decisions", "2026", "09", "held3.json"),
    JSON.stringify({ schema: "astra.registry.decision/1", decision_id: "held3", state: "held", fingerprint: fp }));
  assertEqual((await onThread(line, "the-maintainer", { root })).mode, "approve",
    "and with the record there it goes through, so the assertion above is not passing for a rule that refuses everything");
});


// ── B-T3.4: one commit holding every record, and none at all in shadow ─────

section("shadow suppression (B-T3.4, BOT-92)");

// BOT-92's Check is a PAIR, and it has to be one fixture: "a stubbed service
// answering `shadow: true` yields no commit for that work, and the same
// fixture answered `shadow: false` publishes". Two fixtures would let the
// shadow half pass because the fixture never published in the first place.
await test("the same submission publishes under `shadow: false` and commits nothing under `shadow: true`", () => {
  const notShadow = decide(publishable({ shadow: false }));
  assertEqual(notShadow.outcome, "publish", "the not-shadow half of the pair does not publish, so the pair proves nothing");
  assertEqual(notShadow.publishes_now, true, "same");
  assertEqual(notShadow.record.write, true, "same");

  const shadow = decide(publishable({ shadow: true }));
  assertEqual(shadow.publishes_now, false, "a shadow answer published a listing");
  assertEqual(shadow.record.write, false, "a shadow answer wrote a decision record");
  assertEqual(shadow.queue_entry, null, "a shadow answer wrote a queue entry");
  assertEqual(shadow.shadow, true, "the answer does not say it was shadow, so the step summary cannot");
  assert(String(shadow.record.why).includes("BOT-92"), "and it does not say which rule withheld it");
});

// The named risk for this task: the suppression enumerating record kinds, and
// a sibling adding a fifth. This is the property that makes that impossible —
// suppression is deny-by-default over everything the decision returns, so a
// member added later is withheld without anybody editing the shadow rule.
await test("a member nobody thought about is suppressed by construction", () => {
  // A DELAY, chosen deliberately: it is the only outcome that carries a
  // `publish_after`, a `queue_entry` and a `notify_author` at once, and
  // `publish_after` is the member the plan's own wording — "no publication,
  // decision, identity or queue record" — does not name. Written the first
  // time against a `review` fixture, this test passed for a suppression that
  // blanked exactly those four kinds, because a review carries none of the
  // other three anyway. A fixture that cannot leak proves nothing about a
  // leak.
  // The plugin already HOLDS `client` in its listed version, so nothing is
  // newly requested (no `R_NEW_HIGH_RISK` hold) and `P_DELAY_HIGH_RISK` is
  // what remains: the delay branch, reached with nobody in the loop.
  const delaying = (over = {}) => publishable({
    existing: { versions: [{ doc: { version: "1.0.0", capabilities: ["client"] } }] },
    derived: {
      plugin: { id: "dice-roller", source: { kind: "github", repo: "you/dice-roller" } },
      version: {
        version: "1.0.1", capabilities: ["client"],
        release: { repo: "you/dice-roller", commit: "a".repeat(40) }, artifacts: [],
      },
    },
    ...over,
  });
  assert(decide(delaying()).publish_after,
    "the fixture no longer produces a `publish_after`, so it cannot detect one leaking");
  const shadow = decide(delaying({ shadow: true }));
  const ALLOWED = new Set([
    "outcome", "reasons", "track", "decided_at", "sla_deadline", "notify_author",
    "fingerprint", "repo", "tag", "issue", "artifact_digests", "wait", "shadow",
    "approval_refused", "approved_by", "approved_at", "record",
  ]);
  const leaked = Object.entries(shadow)
    .filter(([m, v]) => !ALLOWED.has(m))
    .filter(([, v]) => !(v === null || v === false || (Array.isArray(v) && v.length === 0)))
    .map(([m]) => m);
  assertEqual(leaked.join(", "), "",
    "a shadow answer carried a member that is not on the allow-list and is not empty. Either the " +
    "suppression stopped being deny-by-default, or a new output was added to the allow-list without " +
    "a reason — and the whole point of BOT-92's shape is that the second is a visible edit");
  // And the floor from the other end: the allow-list is not the whole object,
  // or "deny by default" denies nothing.
  assert(Object.keys(shadow).some((m) => !ALLOWED.has(m)),
    "every member of a decision is on the shadow allow-list, so the suppression suppresses nothing");
});

await test("an answer with no `shadow` member is read as shadow, never as not-shadow", () => {
  // The default direction is the whole safety of the shadow period: an answer
  // that lost the member — a mis-deployed service, a proxy stripping it — must
  // not publish. `decide()` reads `input.shadow === true`, so anything that is
  // not the literal `true` is shadow at the CALLER, and the caller is the one
  // that knows an answer arrived at all. What this asserts is the half that
  // lives here: nothing in `decide()` invents a not-shadow answer.
  const d = decide(publishable({ shadow: undefined }));
  assertEqual(d.shadow, false,
    "`decide()` is given no verdict at all on the legacy path, and a legacy run is not a shadow run — " +
    "the not-shadow default belongs to the caller that saw the answer, and B-T3.6's canary is the one " +
    "that watches a missing member being read as shadow");
});

await test("B-T3.4's record commit is refused by name, and this file grows no second writer", () => {
  const refused = recordCommitRefusal({});
  assertEqual(refused.ok, false, "the record commit reported itself buildable, and neither half is on main");
  assert(refused.reason.includes("bot/lib/decisions.mjs"), "the refusal does not name the writer it needs");
  assert(refused.reason.includes("plugins-ingest.yml"), "the refusal does not name the job graph it belongs to");
  assertEqual(recordCommitRefusal({ decisionsWriter: {}, jobGraph: {} }).ok, true,
    "the refusal cannot be lifted, so it is a wall rather than a gap somebody can close");
});


// ── B-T3.7: the legacy half of the decision log ───────────────────────────

section("legacy decision records (B-T3.7)");

await test("the legacy path's four triggers, and the one it may never write", () => {
  assertEqual(legacyTrigger("ping"), "ping", "a /release ping");
  assertEqual(legacyTrigger("approve"), "issue", "a maintainer's command is an issue trigger");
  assertEqual(legacyTrigger("form"), "issue", "the submission form is an issue trigger");
  assertEqual(legacyTrigger("backstop"), "legacy", "the backstop's publications are `legacy`");
  assertEqual(legacyTrigger("queue"), "legacy", "the drain's publications are `legacy`");
  assertEqual(legacyTrigger("repository_dispatch"), "dispatch", "a dispatch");
  for (const t of ["issue", "ping", "dispatch", "legacy"]) {
    assert(LEGACY_TRIGGERS.includes(t), `${t} is not in LEGACY_TRIGGERS, so DEC-7's four are not four`);
  }
  assertEqual(LEGACY_TRIGGERS.length, 4, "the legacy path grew a fifth trigger, which DEC-7 does not have");
});

await test("a legacy `migration` composition is refused, loudly", () => {
  // `migration` is MIG-20's baseline, and `bot/lib/identity.mjs` selects
  // baselines by exactly `trigger === "migration" && state === "published"`.
  // One composed here becomes the baseline this plugin's every later identity
  // comparison is made against — written off an issue comment rather than off
  // `baseline.yml`'s single audited dispatch.
  let threw = null;
  try { legacyTrigger("migration"); } catch (e) { threw = e; }
  assert(threw, "the legacy path composed a `migration` record");
  assert(String(threw.message).includes("MIG-20"), "and the refusal does not say what it would have overwritten");
  // The refusal reaches the whole program, not just the helper: `decideRelease`
  // re-throws for `migration` specifically rather than turning it into a
  // no-record, because "do not write this" and "write the wrong baseline" are
  // not the same mistake.
  assert(String(threw.message).includes("baseline"), "and it does not name the thing it protects");
});

await test("a source nobody mapped writes no record, and never writes `legacy`", () => {
  // Three shapes were possible here and two are wrong. Throwing turns every
  // caller that predates `--source` red at once. Defaulting to `legacy` is
  // what B-T3.7 forbids: a record stating the backstop found a release when
  // nobody knows what found it. What is built is the third — no trigger, so
  // no record, said out loud.
  let threw = null;
  try { legacyTrigger("something-new"); } catch (e) { threw = e; }
  assert(threw, "an unmapped source was silently given a trigger");
  assert(!String(threw.message).includes("came from the backstop\", and"),
    "the refusal must not read as though `legacy` were the fallback");
  assert(String(threw.message).includes("legacy"), "the refusal names the four triggers so the caller can pick one");
});

await test("end to end — a drained publication with the marker on main carries one `legacy` trigger", async () => {
  // The thing itself, run the way the drain runs it: a real bundle, the real
  // archive walk, the real manifest probe, the real derivation and the real
  // policy — with `log/baseline.json` on the tree and `--source queue`, which
  // is what `bot/watch.mjs --drain` puts on every dispatch entry.
  const root = registryTree([{}]);
  fs.mkdirSync(path.join(root, "log"), { recursive: true });
  fs.writeFileSync(path.join(root, "log", "baseline.json"),
    JSON.stringify({ schema: "astra.registry.baseline/1", version_count: 1, record_count: 1 }));

  const drained = await run({ root, source: "queue" });
  assertEqual(drained.decision.outcome, "publish", JSON.stringify(codes(drained)));
  assertEqual(drained.decision.trigger, "legacy",
    "a drained publication is a `legacy` trigger — it has no thread and no command behind it");
  assertEqual(drained.decision.record.write, true,
    "the marker is on main and the drain published, and still no record is owed");

  // And the gate, from the other side, on the same tree and the same bytes.
  const beforeBaseline = await run({ root: registryTree([{}]), source: "queue" });
  assertEqual(beforeBaseline.decision.outcome, "publish", "the floor: the same release without the marker");
  assertEqual(beforeBaseline.decision.record.write, false,
    "a record was written before MIG-20's baseline exists, and a record with nothing to be compared " +
    "against is a statement this registry cannot check (B-T3.7)");
  assert(String(beforeBaseline.decision.record.why).includes("baseline.json"),
    "and it does not name the marker it is waiting for");

  // What the publish job actually reads, written out as a user's run would
  // write it. Asserted from the FILE rather than from the object, because the
  // object is not what `plugins-ingest.yml` will read.
  const outDir = tmp("astra-b4-legacy-out-");
  writeOutputs(outDir, { repo: REPO, tag: TAG, issue: null }, drained);
  const written = JSON.parse(fs.readFileSync(path.join(outDir, "decision.json"), "utf8"));
  assertEqual(written.trigger, "legacy", "decision.json carries no trigger, so the writer has nothing to stamp");
  assertEqual(written.record?.write, true, "decision.json does not say whether a record is owed");
  assertEqual(written.shadow, false, "decision.json does not say whether the answer was shadow");
});

// ═══════════════════════════════════════════════════════════════════════════
// The canary walks, the bot's half (registry plan B-T4.1 and M-T5.5).
//
// Contract ROLL-25 walks R4a on `mihailinl/AstraPlugins`, bound before any
// third party, and ROLL-59 walks R4b's defences on a second account's staging
// listing. Both are live acts — the owner's mint, his tags, a second GitHub
// account, the plugins service — and none of them can be walked from a test.
// B-T4.1 says what comes first: "the fixtures first; the live walks recorded
// with run URLs". These are the fixtures.
//
// ── TWO KINDS OF ENTRY, AND THE DIFFERENCE IS THE POINT ─────────────────────
//
// `test()` is a walk step whose code is on `main`: it asserts the outcome the
// contract names for that step, through the whole pipeline where the step is
// a release, and each was watched failing on the mutation its comment names.
//
// `gap()` is a walk step whose code is NOT on `main`. It runs the step anyway,
// against what is there, and asserts the walk's outcome — which fails today,
// because the task that builds it has not landed. A gap is not a pass and is
// not counted as one; the summary line names how many there are and each one
// prints the task it is blocked on. It is strict in both directions:
//
//   * when the outcome starts to hold, the gap FAILS, saying the task has
//     landed and the entry must move from `gap()` to `test()` — so the walk's
//     fixture is held from the day its code exists, rather than remembered;
//   * while it does not hold, `standing` asserts the blocker is still exactly
//     the thing the gap names. If the code changes and the walk still does not
//     pass, the gap FAILS too, because a gap re-pointed at nothing is a green
//     that means nothing — the vacuous pass this file exists to refuse.
//
// A gap whose own fixture breaks (anything but a `walkExpects` failure) is a
// FAIL, not a gap, for the same reason.
//
// The walk's world. `mihailinl/AstraPlugins` is ROLL-25's repository by name,
// and the two listings are two of its ten (ID-64's count, which the
// walk compares its binding commit with, is a ruling this file does not make). Both are BOUND: step (1)'s mint and binding commit
// come before every step fixtured here, so each listing carries
// `plugins/<id>/identity.json` and every release reaches the service path —
// the legacy path holds a bound listing `R_CHECK_HELD` (BOT-77), which is the
// thing walk (6)'s mutation below proves these runs are not on.
// ═══════════════════════════════════════════════════════════════════════════

class WalkUnmet extends Error {}
/** The walk's own assertion, the only failure a `gap()` may count as a gap. */
function walkExpects(cond, message) { if (!cond) throw new WalkUnmet(message); }

const gaps = [];
async function gap(name, { blocker, standing, walk }) {
  const fail = (message) => {
    failures.push({ group, name, error: new Error(message) });
    console.log(`  FAIL  ${name}\n        ${message.split("\n").join("\n        ")}`);
  };
  let unmet = null;
  try {
    await walk();
  } catch (e) {
    if (!(e instanceof WalkUnmet)) {
      fail(`this gap's fixture broke rather than meeting the gap it names (${e.message}). A gap may fail ` +
        "only by the walk's own assertion, or a broken fixture would read as a known absence");
      return;
    }
    unmet = e.message;
  }
  if (unmet === null) {
    fail(`the gap has closed: ${blocker} — and this walk step now has the outcome the contract names. ` +
      "Move it from gap() to test() in this file, so the outcome is held rather than remembered (B-T4.1)");
    return;
  }
  let still = false;
  try { still = (await standing()) === true; } catch { still = false; }
  if (!still) {
    fail(`the code this gap names has changed and the walk still does not pass. Blocked on: ${blocker}. ` +
      "Re-point the gap at the interface that task actually landed, so it runs the walk against real code " +
      `again; the walk's unmet assertion was: ${unmet}`);
    return;
  }
  gaps.push({ group, name, blocker });
  console.log(`  gap   ${name}\n        blocked on ${blocker}\n        unmet: ${unmet.split("\n")[0]}`);
}

section("the canary walks, the bot's half (B-T4.1, M-T5.5; ROLL-25, ROLL-59)");

const WALK_REPO = "mihailinl/AstraPlugins";
const WALK_NOW = new Date("2026-09-25T12:00:00Z");
const walkTag = (id, v) => `${id}-v${v}`;

/** The two bound listings, with MIG-20's marker so records are owed. */
function walkTree() {
  const root = registryTree([
    {
      id: "telegram-client", name: "Telegram Client", repo: WALK_REPO,
      versions: [{ version: "0.3.0", staging: false, tag: walkTag("telegram-client", "0.3.0"), capabilities: ["tools", "dom_access"] }],
    },
    {
      id: "json-tools", name: "JSON Tools", repo: WALK_REPO,
      versions: [{ version: "0.1.2", staging: false, tag: walkTag("json-tools", "0.1.2"), capabilities: ["tools"] }],
    },
  ]);
  for (const id of ["telegram-client", "json-tools"]) {
    fs.writeFileSync(path.join(root, "plugins", id, "identity.json"), `${JSON.stringify({
      schema: "astra.registry.identity/1",
      plugin_id: id,
      repository_id: "700000001",
      repository_owner_id: "700000002",
      repo: WALK_REPO,
      token_hash: "c".repeat(16),
    }, null, 2)}\n`);
    // A monorepo tags `<id>-v<version>`, and `registryTree` writes each
    // artifact under `v<version>`; the validator refuses a URL outside the
    // declared release, so the walk's versions are pointed at their own tag.
    const vdir = path.join(root, "plugins", id, "versions");
    for (const name of fs.readdirSync(vdir)) {
      const file = path.join(vdir, name);
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      for (const a of Object.values(doc.artifacts)) {
        a.url = `https://github.com/${WALK_REPO}/releases/download/${doc.release.tag}/${a.filename}`;
      }
      fs.writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
    }
  }
  fs.mkdirSync(path.join(root, "log"), { recursive: true });
  fs.writeFileSync(path.join(root, "log", "baseline.json"),
    JSON.stringify({ schema: "astra.registry.baseline/1", version_count: 2, record_count: 2 }));
  return root;
}

/** A decision record on the tree's `main`, as B-T2.2's layout reads it. */
function walkRecord(root, doc) {
  const dir = path.join(root, "log", "decisions", "2026", "09");
  fs.mkdirSync(dir, { recursive: true });
  const full = {
    schema: "astra.registry.decision/1", decided_at: "2026-09-25T10:00:00Z", repo: WALK_REPO, ...doc,
  };
  fs.writeFileSync(path.join(dir, `${doc.decision_id}.json`), `${JSON.stringify(full, null, 2)}\n`);
  return full;
}

const telegram = (version) => ({
  repo: WALK_REPO, tag: walkTag("telegram-client", version), via: "service", now: WALK_NOW,
  assets: [conforming({ id: "telegram-client", name: "Telegram Client", version, capabilities: ["tools", "dom_access"] })],
});
const jsonTools = (version) => ({
  repo: WALK_REPO, tag: walkTag("json-tools", version), via: "service", now: WALK_NOW,
  assets: [conforming({ id: "json-tools", name: "JSON Tools", version, capabilities: ["tools"] })],
});

// ROLL-25 (2)'s record for json-tools 0.1.3 — `M_REJECT`, which BOT-19 makes
// terminal for that submission and burns the version — and (4)'s stop of
// telegram-client 0.4.0.
const REJECTED_0_1_3 = {
  decision_id: "a1".repeat(16), actor: "moderator", trigger: "approval", state: "refused",
  plugin_id: "json-tools", version: "0.1.3", tag: walkTag("json-tools", "0.1.3"), reasons: ["M_REJECT"],
};
const STOPPED_0_4_0 = {
  decision_id: "b2".repeat(16), actor: "author", trigger: "stop", state: "stopped",
  plugin_id: "telegram-client", version: "0.4.0", tag: walkTag("telegram-client", "0.4.0"), reasons: ["A_STOP"],
};

// ── ROLL-25 (5): a new telegram-client tag waits out its delay and publishes ─
//
// Watched failing: with the `publishAfter <= now` comparison in
// `bot/lib/policy/decision.mjs` made `<`-and-a-day (the drain never ripe), the
// second half is red; with `P_DELAY_HIGH_RISK` never pushed, the first half
// publishes at once and is red.
await test("ROLL-25 (5) — a bound release holding dom_access waits out its delay, then publishes itself", async () => {
  const root = walkTree();
  const out = tmp("astra-walk-out-");
  const first = await run({ ...telegram("0.4.1"), root });
  assertEqual(first.decision.outcome, "delay",
    `step (5) needs a delay to wait out, and ${WALK_REPO}'s telegram-client got ${first.decision.outcome}: ` +
    JSON.stringify(codes(first)));
  assert(codes(first).includes("P_DELAY_HIGH_RISK"), `the delay is not P_DELAY_HIGH_RISK: ${JSON.stringify(codes(first))}`);
  assertEqual(hours(first.decision.publish_after, WALK_NOW), first.decision.track.delay_hours ?? DELAY_HOURS,
    "the release waits the track record's delay, from this run");
  writeOutputs(out, { repo: WALK_REPO, tag: telegram("0.4.1").tag, issue: null }, first);
  assert(!fs.existsSync(path.join(out, "plugins")), "a delayed release published on its first run");

  // The queue entry, committed as the publish job commits it, and the drain
  // one minute after `publish_after`.
  const qrel = queueFile("telegram-client", "0.4.1");
  fs.mkdirSync(path.dirname(path.join(root, qrel)), { recursive: true });
  fs.copyFileSync(path.join(out, qrel), path.join(root, qrel));
  const ripe = new Date(new Date(first.decision.publish_after).getTime() + 60_000);
  const out2 = tmp("astra-walk-out-");
  const drained = await run({ ...telegram("0.4.1"), root, now: ripe });
  assertEqual(drained.decision.outcome, "publish", `the delay was waited out and nothing published: ${JSON.stringify(codes(drained))}`);
  assert(codes(drained).includes("P_DELAY_ELAPSED"), JSON.stringify(codes(drained)));
  writeOutputs(out2, { repo: WALK_REPO, tag: telegram("0.4.1").tag, issue: null }, drained);
  assert(fs.existsSync(path.join(out2, "plugins", "telegram-client", "versions", "0.4.1.json")),
    "the drain decided to publish and the publish job's tree holds no version file");
  assertEqual(fs.readFileSync(path.join(out2, "remove.txt"), "utf8"), `${qrel}\n`,
    "the served delay leaves its queue entry behind, so the drain would publish it again");
});

// ── ROLL-25 (6): a new json-tools tag publishes unheld ──────────────────────
//
// Watched failing: with BOT-77's guard in `decide()` made to apply on both
// paths (`path !== "service"` → `true`), this run is held `R_CHECK_HELD` —
// which is what proves the walk runs on the service path and not the legacy
// one, where a bound listing never publishes.
await test("ROLL-25 (6) — a bound release with nothing to hold or delay publishes on the service path", async () => {
  const root = walkTree();
  const out = tmp("astra-walk-out-");
  const r = await run({ ...jsonTools("0.1.4"), root });
  assertEqual(r.decision.outcome, "publish", `step (6) did not publish unheld: ${JSON.stringify(r.decision.reasons)}`);
  assert(r.decision.publishes_now, "and it publishes on this run");
  assert(codes(r).includes("P_PUBLISHED"), JSON.stringify(codes(r)));
  const held = r.decision.reasons.filter((x) => x.level === "review" || x.code.startsWith("P_DELAY"));
  assertEqual(held.length, 0, `step (6) is an UNHELD publication and this carries ${JSON.stringify(held)}`);
  writeOutputs(out, { repo: WALK_REPO, tag: jsonTools("0.1.4").tag, issue: null }, r);
  assert(fs.existsSync(path.join(out, "plugins", "json-tools", "versions", "0.1.4.json")),
    "the publish job's tree holds no version file for step (6)");
});

// ── ROLL-25 (4) → (5): a stop is about ONE submission ───────────────────────
//
// BOT-19 finds a stop "for the same tag of the same repository_id" (FLOW-26),
// never for the plugin. Today `stopped` is not a terminal state at all (the
// gap below), so this holds for the wrong reason; it is here for the day that
// gap closes. Watched failing: add `"stopped"` to `terminalOnMain`'s set as
// its matching stands — by `plugin_id` alone — and this is red, because
// 0.4.0's stop would then stop 0.4.1, which is walk step (5) itself.
await test("ROLL-25 (4)→(5) — the stop of telegram-client 0.4.0 does not stop 0.4.1", async () => {
  const root = walkTree();
  walkRecord(root, STOPPED_0_4_0);
  assertEqual(
    terminalOnMain({ records: [STOPPED_0_4_0], pluginId: "telegram-client", repo: WALK_REPO, tag: telegram("0.4.1").tag }),
    null,
    "a stop recorded for 0.4.0 is a hit for 0.4.1, so every later tag of a stopped plugin stops too — and ROLL-25 " +
    "step (5) can never walk after step (4)",
  );
  const r = await run({ ...telegram("0.4.1"), root });
  assertEqual(r.decision.outcome, "delay", `0.4.1 after 0.4.0's stop: ${JSON.stringify(codes(r))}`);
  assertEqual(r.decision.record?.write, false,
    "the service path's records are B-T3.4's; this run must not claim one from the legacy trigger map");
});

// ── the gaps: steps whose code is not on `main` ─────────────────────────────

await gap("ROLL-25 (4) — a `stopped` record for this tag is a terminal hit (BOT-19; FLOW-26)", {
  blocker: "B-T3.3c (BOT-19): `terminalOnMain` in bot/decide.mjs has no `stopped` in its terminal set",
  standing: () =>
    terminalOnMain({ records: [STOPPED_0_4_0], pluginId: "telegram-client", repo: WALK_REPO, tag: STOPPED_0_4_0.tag }) === null,
  walk: () => {
    const hit = terminalOnMain({ records: [STOPPED_0_4_0], pluginId: "telegram-client", repo: WALK_REPO, tag: STOPPED_0_4_0.tag });
    walkExpects(hit?.reported === "stopped",
      `a stop the author recorded for ${STOPPED_0_4_0.tag} is not found by the git fence, so a drain after a restore ` +
      "publishes the release the author stopped (FLOW-26; SERVE-93)");
  },
});

await gap("ROLL-25 (2) — a re-run of the rejected json-tools 0.1.3 writes nothing (BOT-19's \"write nothing\")", {
  blocker: "B-T3.3c (BOT-19): a terminal hit sets only `decision.record`, and `writeOutputs` still writes the listing " +
    "whenever `publishes_now` is true",
  standing: async () => {
    const root = walkTree();
    walkRecord(root, REJECTED_0_1_3);
    const out = tmp("astra-walk-out-");
    const r = await run({ ...jsonTools("0.1.3"), root });
    writeOutputs(out, { repo: WALK_REPO, tag: REJECTED_0_1_3.tag, issue: null }, r);
    return r.decision.reported === "refused" && r.decision.record?.write === false &&
      fs.existsSync(path.join(out, "plugins", "json-tools", "versions", "0.1.3.json"));
  },
  walk: async () => {
    // The control, asserted as the fixture's own premise (a plain throw, so a
    // failure here is a broken fixture and never a gap): WITHOUT the record,
    // the same run publishes. Otherwise "nothing was written" could be the
    // fixture refusing for a reason of its own — which is exactly how this gap
    // first read as closed, on a tree the validator refused.
    const control = await run({ ...jsonTools("0.1.3"), root: walkTree() });
    assertEqual(control.decision.outcome, "publish",
      `the control run does not publish, so this gap cannot tell a stop from a broken fixture: ${JSON.stringify(codes(control))}`);
    const root = walkTree();
    walkRecord(root, REJECTED_0_1_3);
    const out = tmp("astra-walk-out-");
    const r = await run({ ...jsonTools("0.1.3"), root });
    writeOutputs(out, { repo: WALK_REPO, tag: REJECTED_0_1_3.tag, issue: null }, r);
    walkExpects(!fs.existsSync(path.join(out, "plugins", "json-tools", "versions", "0.1.3.json")),
      "main records json-tools 0.1.3 as `refused` under M_REJECT, BOT-19 says a hit writes nothing, and the " +
      "publish job's tree carries the rejected version's listing — the moderator's rejection is undone by a re-run");
  },
});

await gap("ROLL-25 (2)→(6) — the rejection of 0.1.3 is not a hit for 0.1.4 (BOT-19 matches the submission)", {
  blocker: "B-T3.3c (BOT-19): `terminalOnMain` matches a terminal record by `plugin_id` alone",
  standing: () =>
    terminalOnMain({ records: [REJECTED_0_1_3], pluginId: "json-tools", repo: WALK_REPO, tag: jsonTools("0.1.4").tag })
      ?.reported === "refused",
  walk: () => {
    const hit = terminalOnMain({ records: [REJECTED_0_1_3], pluginId: "json-tools", repo: WALK_REPO, tag: jsonTools("0.1.4").tag });
    walkExpects(hit === null,
      `0.1.3's M_REJECT is a terminal hit for 0.1.4 (${hit?.reported}), so step (6)'s publication is written with ` +
      "no decision record — and every later release of a plugin that was ever refused loses its record, which MIG-20 " +
      "reads the next baseline from");
  },
});

// A first binding on a `grandfathered` listing, with every input B-T3.3a's
// refusal names present and each taken from the module that owns it.
const firstBindingInputs = () => ({
  listingState: listingState({
    plugin_id: "json-tools", now: "2026-09-25T12:00:00Z", unlisted: false,
    identity: null, ever_identity: false, deadline: null, cutover: null,
  }),
  bindingLine: parseBindingFile(`astra-binding: ${"T".repeat(32)}\n`),
  verdict: { shadow: false, token_state: "seen", minted_for_repository: true, eligibility: "eligible" },
  marker: { r3_exit: true, cutover: false },
});
const placeholderAnswer = (r) =>
  r?.ok === true && r?.code === null && /every input a binding decision needs is present/.test(String(r?.reason));

await gap("ROLL-25 (2)/(3) — a grandfathered listing's first binding line is held `R_FIRST_BINDING` (MIG-10)", {
  blocker: "B-T3.3a (MIG-10; ID-41): `bindingDecision` in bot/lib/identity.mjs decides no row — with every input " +
    "present it answers `code: null`",
  standing: () => {
    const inputs = firstBindingInputs();
    return inputs.listingState.state === "grandfathered" && inputs.bindingLine.outcome === "one" &&
      placeholderAnswer(bindingDecision(inputs));
  },
  walk: () => {
    const r = bindingDecision(firstBindingInputs());
    walkExpects(r.code === "R_FIRST_BINDING",
      `a grandfathered listing's first binding line is answered ${JSON.stringify(r.code)}, not held R_FIRST_BINDING`);
  },
});

// ROLL-59 (a), (c) and (d)'s bot half: the rows ID-41 decides WITH an
// identity record. The members `identityRecord` and `identity` are the
// contract's inputs (the record on `main`, and the certificate's ids and line
// token), named as the plan names them; `bindingDecision` reads neither yet,
// and `standing` is what makes the guess safe — the day it reads anything, each
// of these fails until it is pointed at what B-T3.3a actually takes.
const RECORD = { plugin_id: "json-tools", repository_id: "700000001", repository_owner_id: "700000002", repo: WALK_REPO, token_hash: "c".repeat(16) };
const boundInputs = ({ verdict = {}, identity = {}, line = "T".repeat(32) } = {}) => ({
  listingState: listingState({
    plugin_id: "json-tools", now: "2026-09-25T12:00:00Z", unlisted: false,
    identity: { ...RECORD }, ever_identity: true, deadline: null, cutover: null,
  }),
  bindingLine: parseBindingFile(`astra-binding: ${line}\n`),
  verdict: { shadow: false, token_state: "bound", minted_for_repository: true, eligibility: "eligible", ...verdict },
  marker: { r3_exit: true, cutover: false },
  identityRecord: { ...RECORD },
  identity: {
    ok: true, repo: WALK_REPO, repository_id: RECORD.repository_id, repository_owner_id: RECORD.repository_owner_id, ...identity,
  },
});
const boundRow = (label, inputs, code, why) => gap(label, {
  blocker: "B-T3.3a (ID-41): `bindingDecision` decides no row, and reads no identity record",
  standing: () => placeholderAnswer(bindingDecision(inputs())),
  walk: () => {
    const r = bindingDecision(inputs());
    walkExpects(r.code === code, `${why}; answered ${JSON.stringify(r.code)}`);
  },
});

// A different token hash under an unchanged repository: the second account's
// own line (ID-41 row 6).
await boundRow("ROLL-59 (a) — a second account's own line under a bound listing is held `R_BINDING_CHANGED`",
  () => boundInputs({ line: "U".repeat(32), verdict: { token_state: "seen" } }), "R_BINDING_CHANGED",
  "the line's token is not the recorded one, and the release was not held for the bound account's notice");
// The owner id moved and the repository id did not: a transfer (ID-41).
await boundRow("ROLL-59 (c) — after a transfer, a bound listing's release is refused `B_OWNER_CHANGED`",
  () => boundInputs({ identity: { repository_owner_id: "700000999" } }), "B_OWNER_CHANGED",
  "the certificate's owner id is not the identity record's, and the release was not refused B_OWNER_CHANGED");
// The recorded token is `revoked` (A_BINDING_REVOKE) and the line still
// carries it (ID-9).
await boundRow("ROLL-59 (d) — after `A_BINDING_REVOKE`, a release still carrying the old line is `B_BINDING_UNUSABLE`",
  () => boundInputs({ verdict: { token_state: "revoked" } }), "B_BINDING_UNUSABLE",
  "the recorded token is revoked and the release carrying it was not refused B_BINDING_UNUSABLE");
// A rebind: a new line after the revocation (ID-41 row 6), approved later.
await boundRow("ROLL-59 (d) — after `A_BINDING_REVOKE`, a release carrying a new line is held `R_BINDING_CHANGED`",
  () => boundInputs({ line: "V".repeat(32), verdict: { token_state: "seen" } }), "R_BINDING_CHANGED",
  "a new line after the revocation was not held R_BINDING_CHANGED for review");

// ROLL-25 (3): the approval of the text-utils hold. TRUST-27 honours no
// `R_FIRST_BINDING` approval before 7 days from its held record, and TRUST-32
// waits the operator window after a delivered alert. A day after the hold,
// with an approval naming this exact submission, nothing may publish.
const firstBindingHeld = (over = {}) => decide(publishable({
  path: "service",
  findings: [{ level: "review", code: "R_FIRST_BINDING", where: "binding", message: "a first binding line (MIG-10)" }],
  now: new Date("2026-09-26T12:00:00Z"),
  ...over,
}));
await gap("ROLL-25 (3) — an approved `R_FIRST_BINDING` hold publishes nothing a day after its held record (TRUST-27; TRUST-32)", {
  blocker: "B-T3.3b (TRUST-27, TRUST-32): `decide()` lets an approval clear any `R_*` hold on the run it arrives in",
  standing: () => {
    const fingerprint = firstBindingHeld().fingerprint;
    const d = firstBindingHeld({ approval: { by: "the-moderator", at: "2026-09-26T11:00:00Z", for: fingerprint } });
    return d.outcome === "publish" && d.reasons.some((x) => x.code === "P_APPROVED");
  },
  walk: () => {
    const fingerprint = firstBindingHeld().fingerprint;
    walkExpects(typeof fingerprint === "string" && fingerprint.length > 0, "the held run names no fingerprint to approve");
    const d = firstBindingHeld({ approval: { by: "the-moderator", at: "2026-09-26T11:00:00Z", for: fingerprint } });
    walkExpects(d.outcome !== "publish" && !d.publishes_now,
      `an R_FIRST_BINDING approval a day after the hold published (${JSON.stringify(d.reasons.map((x) => x.code))}); ` +
      "TRUST-27 honours none before 7 days, and TRUST-32 waits the operator window after the alert is delivered");
  },
});

// ROLL-59 (f): a deny record withholds an approved fingerprint (TRUST-33).
// The fingerprint is the one the maintainer's `/approve` names, copied out of
// the held run's comment as `approveFromComment` copies it. The hold is
// `collidingTree`'s display-name collision, the clean case for "an approval
// clears the hold and the release publishes" — so the control, with no deny
// record, publishes, and the gap can only close on the deny being read. It
// first read as closed on a world whose approved release went on to a delay,
// which is not a withheld fingerprint.
async function approvedRun({ deny }) {
  const root = collidingTree();
  const world = { root, assets: [conforming()] };
  const held = await run(world);
  const line = /^\/approve (\S+)@(\S+) ([0-9a-f]{16})$/m.exec(held.comment);
  assert(line !== null, "the held run printed no /approve line to approve or deny");
  if (deny) {
    fs.mkdirSync(path.join(root, "state", "deny"), { recursive: true });
    fs.writeFileSync(path.join(root, "state", "deny", `${line[3]}.json`),
      `${JSON.stringify({ fingerprint: line[3], reason: "operator objection inside the window" }, null, 2)}\n`);
  }
  return run({ ...world, approvedBy: "the-maintainer", approvedAt: "2026-08-10T11:59:00Z", approvedFor: line[3] });
}
await gap("ROLL-59 (f) — an operator deny record on main withholds an approved fingerprint (TRUST-33)", {
  blocker: "B-T3.3b and M-T3.5 (TRUST-33): nothing reads `state/deny/`, and `operator.yml`, which writes it, is not on main",
  standing: async () => (await approvedRun({ deny: true })).decision.outcome === "publish",
  walk: async () => {
    const control = await approvedRun({ deny: false });
    assertEqual(control.decision.outcome, "publish",
      `the control approval does not publish, so this gap cannot tell a deny from a broken fixture: ${JSON.stringify(codes(control))}`);
    const r = await approvedRun({ deny: true });
    walkExpects(r.decision.outcome !== "publish" && !r.decision.publishes_now && !r.decision.queue_entry,
      `a fingerprint named by state/deny/ was published on its approval (${JSON.stringify(codes(r))})`);
  },
});

// ── result ──────────────────────────────────────────────────────────────────

console.log();
if (failures.length) {
  console.log(`FAIL  ${passed} passed, ${failures.length} failed${gaps.length ? `, ${gaps.length} walk gap(s) named` : ""}`);
  process.exit(1);
}
// A gap is neither a pass nor a failure, and the line says how many there
// are so a reader of the run cannot mistake the walks for done (B-T4.1).
const named = gaps.length ? `, ${gaps.length} walk gap(s) named, each blocked on its task` : "";
console.log(`PASS  ${passed} passed, 0 failed${named}`);
