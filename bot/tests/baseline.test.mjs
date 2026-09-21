// MIG-20's baseline, and the four refusals that stand in for the parts of it
// that cannot be built yet.
//
// This suite is unusual in what it spends its assertions on. The baseline run
// itself is one dispatch that has not happened and cannot happen — three of its
// gates are not on `main` — so most of what is here asserts the REFUSALS: that
// each of the three missing modules is named rather than worked around, that
// the population is exactly MIG-20's population, and that a record which would
// silently lose a version cannot be composed.
//
// That is not a weaker thing to test than the run. The run happens once, and
// every one of those refusals is a place where a later author, under time
// pressure, could write four lines that make the run go green and the baseline
// wrong for ever.
//
// Registry plan B-T3.7b.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  composeRecords,
  keyCollisions,
  marker,
  markerProblems,
  nameDrift,
  population,
  refuseUncomposable,
  resolveCertificateReader,
  resolveNameReader,
  verificationFacts,
} from "../baseline.mjs";
import { classifyVerifyFailure } from "../lib/attestation.mjs";
import { resolveWriter } from "../export-issues.mjs";
import { submissionFingerprint } from "../lib/policy/release.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";

const write = (root, rel, body) => {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), typeof body === "string" ? body : `${JSON.stringify(body, null, 2)}\n`);
};

const trash = [];
process.on("exit", () => {
  for (const d of trash) fs.rmSync(d, { recursive: true, force: true });
});

function tree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "astra-baseline-"));
  trash.push(dir);
  return dir;
}

function listed(dir, id, version, extra = {}) {
  write(dir, `plugins/${id}/plugin.json`, { schema: "astra.registry.plugin/1", id, name: id, source: { kind: "github", repo: `example/${id}` } });
  write(dir, `plugins/${id}/versions/${version}.json`, {
    schema: "astra.registry.version/1",
    id,
    version,
    published_at: "2026-01-01T00:00:00Z",
    release: { kind: "github_release", repo: `example/${id}`, tag: `v${version}`, commit: "a".repeat(40) },
    artifacts: { noarch: { url: `https://example.invalid/${id}`, filename: `${id}.astraplugin`, sha256: "b".repeat(64), size: 1 } },
    ...extra,
  });
}

// ── the population is MIG-20's population ───────────────────────────────────

test("a staging entry is not in the baseline's population", () => {
  // MIG-20's own sentence, and the reason B-T3.6 step 0's shadow lease has to
  // name a NON-staging listing: a staging entry gets no record, so a lease on
  // one would be a lease on an id MIG-28 holds.
  const dir = tree();
  listed(dir, "alpha", "1.0.0");
  listed(dir, "beta", "0.1.0", { staging: true, staging_reason: "no release yet" });
  const { versions, problems } = population(dir);
  assert.deepEqual(problems, []);
  assert.deepEqual(versions.map((v) => v.plugin_id), ["alpha"]);
});

test("the fingerprint is the string a publication would have produced", () => {
  // A baseline record whose fingerprint is computed differently from a
  // publication's names nothing: A5 keys on it, TRUST-45 alerts with it, and
  // an `/approve` is compared against it. Asserted by behaviour against the
  // one function that defines it, never by repeating its formula here.
  const dir = tree();
  listed(dir, "alpha", "1.0.0");
  const [v] = population(dir).versions;
  assert.equal(v.fingerprint, submissionFingerprint({
    repo: "example/alpha",
    tag: "v1.0.0",
    id: "alpha",
    version: "1.0.0",
    commit: "a".repeat(40),
    digests: [`noarch:${"b".repeat(64)}`],
  }));
});

test("a published version with no release commit is carried and named, not refused", () => {
  // `plugins/dice-roller/versions/0.1.2.json` on `main`: `release.commit` is
  // optional in the schema and was added to the fingerprint later, so one
  // published version predates it. Refusing it would stop the baseline over a
  // file that is not wrong; dropping it silently would leave a published
  // version with no `migration` record, which detector A1 would then report
  // for ever.
  const dir = tree();
  listed(dir, "alpha", "1.0.0");
  const doc = JSON.parse(fs.readFileSync(path.join(dir, "plugins/alpha/versions/1.0.0.json"), "utf8"));
  delete doc.release.commit;
  write(dir, "plugins/alpha/versions/1.0.0.json", doc);

  const { versions, problems, commitless } = population(dir);
  assert.deepEqual(problems, []);
  assert.equal(versions.length, 1);
  assert.equal(versions[0].commit, null);
  assert.deepEqual(commitless, ["alpha 1.0.0 (plugins/alpha/versions/1.0.0.json)"]);
  assert.equal(versions[0].fingerprint, submissionFingerprint({
    repo: "example/alpha", tag: "v1.0.0", id: "alpha", version: "1.0.0", commit: null,
    digests: [`noarch:${"b".repeat(64)}`],
  }));
});

test("the real catalogue's population is what MIG-20 will be taken over", () => {
  // A floor and a liveness check in one, over the tree this actually runs on.
  // Written against the measurement of 2026-09-19 — 39 non-staging published
  // versions, one of them with no release commit — as a floor rather than an
  // equality, so publishing more does not fire it.
  const { versions, problems, commitless } = population(REPO_ROOT);
  assert.deepEqual(problems, [], "a version file on `main` cannot be read into a baseline record");
  assert.ok(versions.length >= 39, `the population is ${versions.length}; it was 39 on 2026-09-19`);
  assert.ok(commitless.length <= 1, `${commitless.length} published versions have no release commit: ${commitless.join(", ")}`);
});

// ── the three refusals ──────────────────────────────────────────────────────

test("B-T1.1's certificate reader is refused by name, and the refusal says why a null will not do", async () => {
  const dir = tree();
  await assert.rejects(
    () => resolveCertificateReader({ root: dir }),
    (e) => {
      assert.match(e.message, /certificate\.mjs is not in this checkout/);
      assert.match(e.message, /57264\.1\.15/);
      assert.match(e.message, /would record a registry-wide attestation failure that did not happen/);
      return true;
    },
  );
});

test("a certificate module that exports the wrong name is refused with the name it wants", async () => {
  // The failure the existence check alone misses: B-T1.1 lands, names the
  // function something else, and this file calls `undefined` four frames later
  // with a TypeError about a property of an object nobody can find.
  const dir = tree();
  write(dir, "lib/certificate.mjs", "export const somethingElse = () => null;\n");
  await assert.rejects(
    () => resolveCertificateReader({ root: dir, load: async () => ({ somethingElse: () => null }) }),
    /exports no `certificateIds`/,
  );
});

test("B-T2.2's record writer is refused by name, and this file grows no second one", async () => {
  // Imported from `bot/export-issues.mjs` rather than re-implemented, so that
  // the two composers cannot come to disagree about who derives an id.
  const dir = tree();
  await assert.rejects(() => resolveWriter({ root: dir }), /decisions\.mjs is not in this checkout/);
});

test("B-T1.3's by-id read is refused by name, and a name lookup may not stand in", async () => {
  await assert.rejects(
    () => resolveNameReader({ load: async () => ({}) }),
    (e) => {
      assert.match(e.message, /exports no `fetchRepositoryIds`/);
      assert.match(e.message, /MIG-20 forbids re-baselining from a name/);
      return true;
    },
  );
});

// ── what may be composed ────────────────────────────────────────────────────

const fact = (over = {}) => ({
  plugin_id: "alpha",
  version: "1.0.0",
  repo: "example/alpha",
  tag: "v1.0.0",
  commit: "a".repeat(40),
  fingerprint: "0123456789abcdef",
  outcome: "verified",
  repository_id: "111",
  repository_owner_id: "222",
  ...over,
});
const at = new Map([["alpha@1.0.0", "2026-01-01T00:00:00Z"], ["beta@1.0.0", "2026-02-02T00:00:00Z"]]);

test("a baseline record carries DEC-7's members and is dated by the publication, not the run", () => {
  const [composed] = composeRecords([fact()], at);
  assert.equal(composed.key, "migration:example/alpha@v1.0.0");
  assert.deepEqual(composed.record, {
    decided_at: "2026-01-01T00:00:00Z",
    actor: "system",
    trigger: "migration",
    plugin_id: "alpha",
    version: "1.0.0",
    repo: "example/alpha",
    tag: "v1.0.0",
    commit: "a".repeat(40),
    fingerprint: "0123456789abcdef",
    repository_id: "111",
    repository_owner_id: "222",
    state: "published",
  });
});

test("a version with no §0.7 published_at is refused rather than dated today", () => {
  // Watched failing by `decided_at: new Date()…`: forty publications spread
  // over a year all land on one afternoon in the public log, and nothing is
  // red.
  assert.throws(() => composeRecords([fact()], new Map()), /would be dated by the run's clock/);
});

test("an unverifiable certificate gives null ids, and the run names it", async () => {
  // **The stub hands back ids WITH the `unverified` outcome, and that is the
  // whole test.** The first spelling of this returned `{outcome:
  // "unverified"}` and nothing else, so forcing the outcome to `verified` in
  // the module under test changed nothing: the ids were null either way and
  // the assertion passed over the mutation. An unverified certificate that
  // produced ids is exactly the thing that must not reach a record — MIG-20's
  // baseline is the ids of "the newest published version whose certificate
  // VERIFIED" — so the ids are here to be dropped.
  const { facts, unrecoverable } = await verificationFacts(
    [{ plugin_id: "alpha", version: "1.0.0", repo: "example/alpha", tag: "v1.0.0", commit: "a".repeat(40), fingerprint: "0123456789abcdef" }],
    async () => ({ outcome: "unverified", repository_id: "111", repository_owner_id: "222" }),
  );
  assert.equal(facts[0].repository_id, null);
  assert.equal(facts[0].repository_owner_id, null);
  assert.deepEqual(unrecoverable, ["alpha 1.0.0 (example/alpha@v1.0.0)"]);
  // And it still composes: MIG-20 says null ids never COUNT toward a baseline,
  // not that the version gets no record.
  const [composed] = composeRecords([fact({ outcome: "unverified", repository_id: null, repository_owner_id: null })], at);
  assert.equal(composed.record.repository_id, null);
});

test("a certificate id that is a JSON number is refused (SCOPE-5)", async () => {
  // Found by writing this test against the first spelling of the check, which
  // was `BASE10_RE.test(String(v))` and passed: `9007199254740993` is already
  // `…92` by the time `String` sees it, the digits match the pattern, and the
  // record names a repository that never published anything. The type is what
  // is refused now, and the id below is the one that rounds.
  await assert.rejects(
    () => verificationFacts(
      [{ plugin_id: "alpha", version: "1.0.0", repo: "example/alpha", tag: "v1.0.0", commit: "a".repeat(40), fingerprint: "0123456789abcdef" }],
      async () => ({ outcome: "verified", repository_id: 9007199254740993, repository_owner_id: "222" }),
    ),
    /not a base-10 STRING/,
  );
});

test("a login cannot be composed into a baseline record, however it is spelled", () => {
  // PRIV-2's allowlist, from the other side. `login` is refused because it is
  // not a member; a login written INTO `repo` has to also be an `owner/name`,
  // and then it is a repository coordinate, which PRIV-2 permits.
  assert.throws(() => refuseUncomposable({ actor: "system", login: "somebody" }),
    /`login` is not a member a baseline record composes/);
  assert.throws(() => refuseUncomposable({ actor: "system", moderator: "somebody" }),
    /`moderator` is not a member a baseline record composes/);
  assert.throws(() => refuseUncomposable({ actor: "system", reasons: ["free text"] }),
    /`reasons` is not a member a baseline record composes/);
});

test("two versions under one tag would derive one id, and the baseline refuses", () => {
  // Here the collision is a defect in the TREE, and that is the difference
  // from `bot/export-issues.mjs`, where 24 of them are the ordinary shape of
  // the archive. MIG-20 writes one record per version and a version has one
  // tag, so this cannot happen unless a tag was re-pointed.
  const two = [fact(), fact({ version: "1.0.1", plugin_id: "alpha" })];
  assert.deepEqual(keyCollisions(two), [{ key: "migration:example/alpha@v1.0.0", facts_sharing_it: 2 }]);
  assert.throws(() => composeRecords(two, at), /would derive one id and overwrite each other/);
});

// ── "the verifier could not run" is not "the artifact does not verify" ──────

test("a verifier that could not run is its own outcome, and never `unverified`", async () => {
  // The bare `catch` this replaces turned three answers into one. `gh` exits 1
  // whether the attestation is absent, wrong, or never checked — no network,
  // Sigstore's trust root unreachable, a timeout — and only the first two are
  // facts about anybody's artifact. The third is a fact about the runner, and
  // MIG-20's record is written once and cannot be corrected.
  const versions = [
    { plugin_id: "alpha", version: "1.0.0", repo: "example/alpha", tag: "v1.0.0", commit: "a".repeat(40), fingerprint: "c".repeat(64) },
    { plugin_id: "beta", version: "1.0.0", repo: "example/beta", tag: "v1.0.0", commit: "b".repeat(40), fingerprint: "d".repeat(64) },
  ];
  const { facts, unrecoverable, unchecked } = await verificationFacts(versions, (v) =>
    v.plugin_id === "alpha"
      ? { outcome: "unchecked", why: "public good verifier is not available (initialization)", repository_id: null, repository_owner_id: null }
      : { outcome: "unverified", repository_id: null, repository_owner_id: null });
  assert.equal(unchecked.length, 1, JSON.stringify(unchecked));
  assert.match(unchecked[0], /alpha 1\.0\.0 \(example\/alpha@v1\.0\.0\)/);
  assert.match(unchecked[0], /verifier is not available/);
  // Both still become `unverified` IN THE FACT, because that vocabulary is
  // DEC-7's and this change does not widen it. What `unchecked` buys is that
  // the run refuses before any of it is written down.
  assert.deepEqual(facts.map((f) => f.outcome), ["unverified", "unverified"]);
  assert.equal(unrecoverable.length, 2);
});

test("the three readings of a failed `gh attestation verify`, and which one wins", () => {
  // One owner, in bot/lib/attestation.mjs, because there were two readers and
  // one reading: `verifyAttestation` classified and `verifyOne` did not.
  assert.deepEqual(classifyVerifyFailure("HTTP 404: Not Found (.../attestations/sha256:aa)"),
    { missing: true, policyRefusal: false, unavailable: false });
  assert.deepEqual(classifyVerifyFailure('Error: verifying with issuer "sigstore.dev"'),
    { missing: false, policyRefusal: true, unavailable: false });
  assert.deepEqual(classifyVerifyFailure("public good verifier is not available (initialization failed)"),
    { missing: false, policyRefusal: false, unavailable: true });
  // A 404 is a fact about the artifact, and the word "connection" turning up
  // elsewhere in the same stderr does not make it less of one. Written the
  // other way first, and this is the case that caught it.
  assert.equal(classifyVerifyFailure("connection reset\nHTTP 404: Not Found").missing, true);
  assert.equal(classifyVerifyFailure("connection reset\nHTTP 404: Not Found").unavailable, false);
});

test("--write refuses a facts file that records anything as not checked", () => {
  // Checked at the WRITE, not only at the verify, because the facts file is an
  // artifact handed between two jobs and `write` needs only that `verify`
  // exited 0. A re-run, a hand-edited artifact, or any future change to either
  // job's gating breaks that claim; this one reads the file in front of it.
  const dir = tree();
  write(dir, "facts.json", {
    facts: [{ plugin_id: "alpha", version: "1.0.0", outcome: "unverified", repository_id: null, repository_owner_id: null }],
    unchecked: ["alpha 1.0.0 (example/alpha@v1.0.0): public good verifier is not available"],
  });
  let message = "";
  try {
    execFileSync(process.execPath, [
      path.join(REPO_ROOT, "bot", "baseline.mjs"), "--write",
      "--facts-file", path.join(dir, "facts.json"),
      "--historic-file", path.join(dir, "facts.json"),
      "--source-commit", "a".repeat(40),
      "--registry-dir", dir,
    ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    message = `${e.stdout ?? ""}${e.stderr ?? ""}`;
  }
  assert.match(message, /1 version\(s\) the verifier could not check/);
  assert.match(message, /written once/);
});

test("--write refuses a wholly unverified baseline unless the operator says the number", () => {
  // The shape that actually happened: dropping `--signer-workflow` failed 12
  // of 18 perfectly good attestations with exit 1 and no named check. A
  // wholesale failure is a broken tool far more often than it is a catalogue
  // in which every attestation is bad — so it is refused, and the escape is a
  // COUNT rather than a flag, because a flag meaning "yes, whatever it is" is
  // one somebody adds to a red run without reading it.
  const dir = tree();
  listed(dir, "alpha", "1.0.0");
  listed(dir, "beta", "1.0.0");
  const facts = [
    { plugin_id: "alpha", version: "1.0.0", repo: "example/alpha", tag: "v1.0.0", commit: "a".repeat(40), fingerprint: "c".repeat(16), outcome: "unverified", repository_id: null, repository_owner_id: null },
    { plugin_id: "beta", version: "1.0.0", repo: "example/beta", tag: "v1.0.0", commit: "b".repeat(40), fingerprint: "d".repeat(16), outcome: "unverified", repository_id: null, repository_owner_id: null },
  ];
  write(dir, "facts.json", { facts, unchecked: [] });
  const run = (extra) => {
    try {
      execFileSync(process.execPath, [
        path.join(REPO_ROOT, "bot", "baseline.mjs"), "--write",
        "--facts-file", path.join(dir, "facts.json"),
        "--historic-file", path.join(dir, "facts.json"),
        "--source-commit", "a".repeat(40),
        "--registry-dir", dir,
        ...extra,
      ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      return "";
    } catch (e) {
      return `${e.stdout ?? ""}${e.stderr ?? ""}`;
    }
  };
  assert.match(run([]), /not one of 2 fact\(s\) in the facts file is `verified`/);
  // The wrong number is not an answer either: an operator who expected one and
  // got two has learnt something, and the run should not proceed.
  assert.match(run(["--expect-unverified", "1"]), /not one of 2 fact\(s\)/);
  // With the right number it gets past this gate and refuses at the next one,
  // which is B-T2.2's writer. That it is a DIFFERENT refusal is the assertion.
  // Until 2026-09-20 this line read `assert.match(past, /decisions\.mjs/)` and
  // its comment said "with the right number it gets past this gate and refuses
  // at the next one, which is B-T2.2's writer". B-T2.2 landed, so the next one
  // is not a refusal any more: the run succeeds. The tripwire did exactly what
  // it was for — it went red on the day its premise stopped holding, in the
  // commit that changed it, which is more than the four module headers that
  // stated an absence and could not.
  const past = run(["--expect-unverified", "2"]);
  assert.doesNotMatch(past, /not one of 2 fact\(s\)/);
  assert.doesNotMatch(past, /decisions\.mjs is not in this checkout/,
    "the writer is on main since B-T2.2; a refusal naming it means resolveWriter regressed");
});

test("a second dispatch with the marker present writes nothing, and the refusal comes first", () => {
  // Asserted through the CLI, because the guard is in the CLI, and matched on
  // the MESSAGE rather than on the exit code: the refusal has to fire BEFORE
  // `resolveWriter`, or the only thing between a second dispatch and a second
  // `migration` record for every version is the accident that B-T2.2 has not
  // landed. Today both refuse; the day B-T2.2 lands only one of them does.
  const dir = tree();
  write(dir, "log/baseline.json", { schema: "astra.registry.baseline/1" });
  write(dir, "facts.json", { facts: [] });
  let message = "";
  try {
    execFileSync(process.execPath, [
      path.join(REPO_ROOT, "bot", "baseline.mjs"), "--write",
      "--facts-file", path.join(dir, "facts.json"),
      "--historic-file", path.join(dir, "facts.json"),
      "--source-commit", "a".repeat(40),
      "--registry-dir", dir,
    ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    message = `${e.stdout ?? ""}${e.stderr ?? ""}`;
  }
  assert.match(message, /log\/baseline\.json is already on this tree/);
  assert.doesNotMatch(message, /decisions\.mjs is not in this checkout/,
    "the marker guard did not fire first; today B-T2.2's absence hides that, and the day it lands nothing will");
});

// ── the marker ──────────────────────────────────────────────────────────────

test("the marker names the commit the baseline was computed over", () => {
  const doc = marker({ writtenAt: "2026-01-02T00:00:00Z", sourceCommit: "a".repeat(40), versionCount: 39, recordCount: 138 });
  assert.deepEqual(Object.keys(doc), ["schema", "written_at", "source_commit", "version_count", "record_count"]);
  assert.equal(doc.schema, "astra.registry.baseline/1");
});

test("a marker over zero versions, or with fewer records than versions, is refused", () => {
  assert.ok(markerProblems({ schema: "astra.registry.baseline/1", written_at: "2026-01-02T00:00:00Z", source_commit: "a".repeat(40), version_count: 0, record_count: 0 })
    .some((p) => /positive integer/.test(p)));
  assert.ok(markerProblems({ schema: "astra.registry.baseline/1", written_at: "2026-01-02T00:00:00Z", source_commit: "a".repeat(40), version_count: 39, record_count: 38 })
    .some((p) => /below version_count/.test(p)));
  assert.ok(markerProblems({ schema: "astra.registry.baseline/1", written_at: "2026-01-02T00:00:00Z", source_commit: "nope", version_count: 1, record_count: 1 })
    .some((p) => /source_commit/.test(p)));
});

// ── the rename watch ────────────────────────────────────────────────────────

const baselined = [
  { repository_id: "111", repo: "example/alpha", plugin_id: "alpha" },
  { repository_id: "333", repo: "example/beta", plugin_id: "beta" },
];

test("the rename watch reads by id and alarms on the name", async () => {
  const { drifted, read } = await nameDrift(baselined, async (id) => (
    id === "111" ? { answer: "found", full_name: "somebody-else/alpha" } : { answer: "found", full_name: "example/beta" }
  ));
  assert.equal(read, 2);
  assert.deepEqual(drifted, [{ repository_id: "111", baselined_as: "example/alpha", now: "somebody-else/alpha", plugin_ids: ["alpha"] }]);
});

test("the watch refuses to look up a NAME, which is the plan's named mutation", async () => {
  // "Watched by comparing by name instead of id." Written as a refusal inside
  // `nameDrift` rather than as an assertion about this file's fixture, because
  // an assertion about the fixture is a test of the fixture: the mutation is
  // in the CALLER — `--names` passing `d.repo` where it passes
  // `d.repository_id` — and only a refusal in the callee sees it.
  //
  // What the mutation would otherwise produce is silence in the one case the
  // watch exists for: asked by name, GitHub answers with whatever account
  // holds that name today, which after a recycle is the squatter's repository,
  // whose `full_name` is exactly the name that was asked for.
  await assert.rejects(
    () => nameDrift([{ repository_id: "example/alpha", repo: "example/alpha", plugin_id: "alpha" }], async () => ({ answer: "found", full_name: "example/alpha" })),
    /which is not a repository id/,
  );
});

test("a read that could not happen is not a rename", async () => {
  // B-T1.3's rule, from the caller's side: `transient` mapped to absence is
  // how one rate-limited minute becomes an alarm naming every repository in
  // the catalogue, which is the alarm nobody reads twice.
  const { drifted, unread } = await nameDrift(baselined, async () => ({ answer: "transient", full_name: null }));
  assert.deepEqual(drifted, []);
  assert.deepEqual(unread, ["111 (transient)", "333 (transient)"]);
});

test("a rename that is only a change of case is not a rename", async () => {
  // GitHub logins are case-insensitive, and `tools/lib/sources.mjs` keys
  // publishers on the lowercased login for the same reason.
  const { drifted } = await nameDrift([baselined[0]], async () => ({ answer: "found", full_name: "Example/Alpha" }));
  assert.deepEqual(drifted, []);
});
