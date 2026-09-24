#!/usr/bin/env node
// `bot/lib/identity.mjs`: which repository published these bytes.
//
//   node --test bot/tests/identity.test.mjs
//
// Registry plan B-T3.2 and the comparison half of B-T3.3a. Everything under
// test is pure, so every fixture below is a world rather than a stub: a
// rename, a transfer, a re-creation, a freed login somebody else registered,
// and a baseline that a reset has ended.
//
// **The values are not invented.** The two chess listings are the live pair
// this module exists for: both certificates say `KNICE-TECH/astra-chess` with
// `.15` `1343092393` and `.17` `280318216`, and GitHub answers
// `MINICE-AI/astra-chess` for that id today (B-T1.2's survey, 2026-09-19, and
// `GET /repositories/1343092393` re-read the same day). The fixtures use those
// numbers so that a reader can check them against something real.

import assert from "node:assert/strict";
import test from "node:test";

import {
  ACTOR_MISMATCH_FLOOR_DAYS,
  IDENTITY_CODES,
  applyIdentity,
  bindingDecision,
  checkDownloadRepository,
  compareActor,
  compareFactsFile,
  compareWithBaseline,
  effectiveBaseline,
  idAndVersionFromAssetName,
  isVoidingRecord,
  identityFromCertificate,
  refuseUnclaimedEntries,
} from "../lib/identity.mjs";

/** The ten certificate fields of a healthy release of `astra-chess`. */
const CHESS_FIELDS = {
  job_workflow_ref: `https://github.com/mihailinl/AstraPlugins/.github/workflows/plugin-release.yml@${"c".repeat(40)}`,
  job_workflow_sha: "c".repeat(40),
  runner_environment: "github-hosted",
  source_repository_uri: "https://github.com/KNICE-TECH/astra-chess",
  sha: "a".repeat(40),
  ref: "refs/tags/v0.1.17",
  repository_id: "1343092393",
  repository_owner_id: "280318216",
  event_name: "push",
  run: "https://github.com/KNICE-TECH/astra-chess/actions/runs/33439738030/attempts/1",
};

const baselineOf = (over = {}) => ({
  plugin_id: "astra-chess",
  repo: "KNICE-TECH/astra-chess",
  repository_id: "1343092393",
  repository_owner_id: "280318216",
  ...over,
});

test("the certificate's ten become an identity, and a missing one is named", () => {
  const identity = identityFromCertificate(CHESS_FIELDS);
  assert.equal(identity.ok, true);
  assert.equal(identity.repo, "KNICE-TECH/astra-chess");
  assert.equal(identity.repository_id, "1343092393");
  assert.equal(identity.repository_owner_id, "280318216");
  assert.equal(identity.run_id, "33439738030", "the run id comes out of .21 for MIG-31");

  const missing = identityFromCertificate({ ...CHESS_FIELDS, repository_id: null });
  assert.equal(missing.ok, false);
  assert.ok(missing.missing.join(" ").includes("(.15)"), missing.missing.join(", "));

  const notAnId = identityFromCertificate({ ...CHESS_FIELDS, repository_owner_id: "280318216 " });
  assert.equal(notAnId.ok, false, "a value that is not base-10 digits is not an id (SCOPE-5)");
});

test("BOT-21: the listing's repository name is .12's, whatever the submission said", () => {
  const derived = {
    plugin: { id: "astra-chess", source: { kind: "github", repo: "somebody/typed-this" } },
    version: { version: "0.1.17", release: { kind: "github_release", repo: "somebody/typed-this", tag: "v0.1.17" } },
  };
  const applied = applyIdentity(derived, identityFromCertificate(CHESS_FIELDS));
  assert.equal(applied.ok, true, applied.reason);
  assert.equal(applied.derived.plugin.source.repo, "KNICE-TECH/astra-chess");
  assert.equal(applied.derived.version.release.repo, "KNICE-TECH/astra-chess");
  assert.equal(derived.plugin.source.repo, "somebody/typed-this", "and the input is not mutated under the caller");
});

test("BOT-21: the id and version come from the attested asset name", () => {
  assert.deepEqual(
    idAndVersionFromAssetName("astra-chess-0.1.17-linux-x64.astraplugin"),
    { ok: true, id: "astra-chess", version: "0.1.17", platformKey: "linux-x64" },
  );
  assert.equal(idAndVersionFromAssetName("astra-chess.astraplugin").ok, false);
  assert.equal(idAndVersionFromAssetName("../../etc/passwd").ok, false);
});

test(".15 against the repository the assets were downloaded from", () => {
  const identity = identityFromCertificate(CHESS_FIELDS);

  const agree = checkDownloadRepository({
    identity,
    downloadRepoIds: { status: "found", id: "1343092393", owner_id: "280318216", full_name: "KNICE-TECH/astra-chess" },
  });
  assert.equal(agree.outcome, "ok");
  assert.equal(agree.renamed, false);

  // The live shape: the ids agree and GitHub has a different name for them.
  const renamed = checkDownloadRepository({
    identity,
    downloadRepoIds: { status: "found", id: "1343092393", owner_id: "280318216", full_name: "MINICE-AI/astra-chess" },
  });
  assert.equal(renamed.outcome, "ok", "a rename does not stop the download check; TRUST-23 rules on it");
  assert.equal(renamed.renamed, true);

  const wrong = checkDownloadRepository({
    identity,
    downloadRepoIds: { status: "found", id: "999999", owner_id: "280318216", full_name: "someone/else" },
  });
  assert.equal(wrong.outcome, "alert", "nothing is written and no result is posted");
  assert.ok(wrong.reason.includes("1343092393"), wrong.reason);

  const unread = checkDownloadRepository({
    identity,
    downloadRepoIds: { status: "transient", reason: "HTTP 403 with rate-limit headers" },
  });
  assert.equal(unread.outcome, "wait", "a read that did not happen is not a difference");
  assert.equal(unread.code, IDENTITY_CODES.W_GITHUB_RATE_LIMITED);
});

test("BOT-15/INV-37: a facts file that disagrees with this run writes nothing", () => {
  const claimed = [{
    plugin_id: "astra-chess", version: "0.1.17", repo: "KNICE-TECH/astra-chess",
    repository_id: "1343092393", repository_owner_id: "280318216",
  }];

  assert.equal(compareFactsFile({ claimed, factsFile: { facts: claimed } }).ok, true);

  const hostile = compareFactsFile({
    claimed,
    factsFile: {
      facts: [{
        plugin_id: "astra-chess", version: "0.1.17", repo: "KNICE-TECH/astra-chess",
        repository_id: "1203676452", repository_owner_id: "193032699",
      }],
    },
  });
  assert.equal(hostile.ok, false, "another repository's ids, under this run's plugin id");
  assert.ok(hostile.problems.join(" ").includes("repository_id"), hostile.problems.join("; "));

  const extra = compareFactsFile({
    claimed,
    factsFile: { facts: [...claimed, { plugin_id: "somebody-else", version: "1.0.0", repo: "x/y", repository_id: "1", repository_owner_id: "2" }] },
  });
  assert.equal(extra.ok, false, "work this run never claimed (INV-36)");
});

test("INV-36: a planted listing entry is refused", () => {
  const ok = refuseUnclaimedEntries({ entries: ["listing-astra-chess"], claimedIds: ["astra-chess"] });
  assert.equal(ok.ok, true);
  const planted = refuseUnclaimedEntries({
    entries: ["listing-astra-chess", "listing-telegram-client"],
    claimedIds: ["astra-chess"],
  });
  assert.equal(planted.ok, false);
  assert.deepEqual(planted.refused, ["listing-telegram-client"]);
});

// ── TRUST-23's Check: a fixture per outcome ────────────────────────────────

test("TRUST-23: the same name with both ids changed is a recycled login", () => {
  // The terminal one, and the one where the name AGREEING is the evidence.
  // `KNICE-TECH` became registrable when the organisation renamed itself; a
  // stranger who took it would publish under exactly this shape.
  const verdict = compareWithBaseline({
    identity: identityFromCertificate({
      ...CHESS_FIELDS, repository_id: "2000000001", repository_owner_id: "2000000002",
    }),
    baseline: baselineOf(),
  });
  assert.equal(verdict.code, IDENTITY_CODES.B_REPOSITORY_RECYCLED);
  assert.equal(verdict.terminal, true);
  assert.ok(verdict.reason.includes("1343092393") && verdict.reason.includes("2000000001"),
    "the refusal names both id pairs");
});

test("TRUST-23: a rename, a transfer and a re-creation are each held, showing both id pairs", () => {
  const rename = compareWithBaseline({
    identity: identityFromCertificate({ ...CHESS_FIELDS, source_repository_uri: "https://github.com/MINICE-AI/astra-chess" }),
    baseline: baselineOf(),
  });
  assert.equal(rename.code, IDENTITY_CODES.R_IDENTITY_CHANGED);
  assert.equal(rename.terminal, false);
  assert.ok(rename.reason.includes("rename"), rename.reason);

  const transfer = compareWithBaseline({
    identity: identityFromCertificate({
      ...CHESS_FIELDS, source_repository_uri: "https://github.com/someone/astra-chess", repository_owner_id: "193032699",
    }),
    baseline: baselineOf(),
  });
  assert.equal(transfer.code, IDENTITY_CODES.R_IDENTITY_CHANGED);
  assert.ok(transfer.reason.includes("transfer"), transfer.reason);
  assert.ok(transfer.reason.includes("280318216") && transfer.reason.includes("193032699"), transfer.reason);

  const recreated = compareWithBaseline({
    identity: identityFromCertificate({
      ...CHESS_FIELDS, source_repository_uri: "https://github.com/KNICE-TECH/astra-chess-2", repository_id: "2000000001",
    }),
    baseline: baselineOf(),
  });
  assert.equal(recreated.code, IDENTITY_CODES.R_IDENTITY_CHANGED);
  assert.ok(recreated.reason.includes("re-creation"), recreated.reason);
});

test("TRUST-23: ids and name agreeing is the only pass", () => {
  const verdict = compareWithBaseline({ identity: identityFromCertificate(CHESS_FIELDS), baseline: baselineOf() });
  assert.equal(verdict.code, IDENTITY_CODES.OK);
});

test("a name agreeing is never, by itself, agreement", () => {
  // `.12` equals the registry's `source.repo` for both chess listings only
  // because the record is stale in the same direction as the certificate. Two
  // stale strings agreeing is not a match — so a comparison that looked at the
  // name would pass the recycled fixture above, which is the whole attack.
  const byNameWouldPass = compareWithBaseline({
    identity: identityFromCertificate({ ...CHESS_FIELDS, repository_id: "2000000001", repository_owner_id: "2000000002" }),
    baseline: baselineOf(),
  });
  assert.notEqual(byNameWouldPass.code, IDENTITY_CODES.OK);
});

test("MIG-28: an id with no baseline is held, not passed", () => {
  const verdict = compareWithBaseline({ identity: identityFromCertificate(CHESS_FIELDS), baseline: null });
  assert.equal(verdict.code, IDENTITY_CODES.R_IDENTITY_CHANGED);
  assert.ok(verdict.reason.includes("no migration baseline"), verdict.reason);
});

test("a baseline ends at the newest voiding record, and the reset is not refused twice", () => {
  // Without this rule the reset B-T4.2 exists to perform does nothing: the old
  // certificate ids stay the baseline, TRUST-23 compares against them again,
  // and the release is refused `B_REPOSITORY_RECYCLED` a second time.
  const records = [
    { plugin_id: "astra-chess", trigger: "migration", state: "published", decided_at: "2026-10-01T00:00:00Z", repo: "KNICE-TECH/astra-chess", repository_id: "1343092393", repository_owner_id: "280318216" },
    { plugin_id: "astra-chess", actor: "moderator", trigger: "moderation", category: "identity_reset", decided_at: "2026-11-01T00:00:00Z" },
    { plugin_id: "other", trigger: "migration", state: "published", decided_at: "2026-10-02T00:00:00Z", repo: "x/y", repository_id: "7", repository_owner_id: "8" },
  ];
  const { baseline, voidedAt } = effectiveBaseline({ records, pluginId: "astra-chess" });
  assert.equal(voidedAt, "2026-11-01T00:00:00Z");
  assert.equal(baseline, null, "every baseline older than the reset is ended by it");

  const after = compareWithBaseline({
    identity: identityFromCertificate({ ...CHESS_FIELDS, repository_id: "2000000001", repository_owner_id: "2000000002" }),
    baseline,
  });
  assert.equal(after.code, IDENTITY_CODES.R_IDENTITY_CHANGED, "held under MIG-28");
  assert.notEqual(after.code, IDENTITY_CODES.B_REPOSITORY_RECYCLED, "and never refused a second time");

  const rebaselined = effectiveBaseline({
    records: [...records, { plugin_id: "astra-chess", trigger: "migration", state: "published", decided_at: "2026-12-01T00:00:00Z", repo: "MINICE-AI/astra-chess", repository_id: "2000000001", repository_owner_id: "2000000002" }],
    pluginId: "astra-chess",
  });
  assert.equal(rebaselined.baseline.repository_id, "2000000001", "a baseline written after the reset counts");
});

test("a record that only looks like a reset voids nothing, so a permanent refusal stays permanent", () => {
  // Until 2026-09-24 the reader keyed on `trigger: "identity_reset"` — not a
  // DEC-7 trigger, so no valid record could carry it — OR on `state`, which let
  // any record saying `identity_reset` end a baseline and turn a permanent
  // `B_REPOSITORY_RECYCLED` into a hold. The voiding record is the plan's four
  // members, all of them.
  const baselineRecord = { plugin_id: "astra-chess", trigger: "migration", state: "published", decided_at: "2026-10-01T00:00:00Z", repo: "KNICE-TECH/astra-chess", repository_id: "1343092393", repository_owner_id: "280318216" };
  const reset = { plugin_id: "astra-chess", actor: "moderator", trigger: "moderation", category: "identity_reset", decided_at: "2026-11-01T00:00:00Z" };
  assert.ok(isVoidingRecord(reset));
  for (const [what, lookalike] of [
    ["the old trigger guess", { plugin_id: "astra-chess", trigger: "identity_reset", decided_at: "2026-11-01T00:00:00Z" }],
    ["a state that says so", { ...baselineRecord, trigger: "issue", state: "identity_reset", decided_at: "2026-11-01T00:00:00Z" }],
    ["a bot, not a moderator", { ...reset, actor: "bot" }],
    ["another trigger", { ...reset, trigger: "panel" }],
    ["another category", { ...reset, category: "error" }],
    ["another plugin", { ...reset, plugin_id: "other" }],
  ]) {
    assert.equal(isVoidingRecord(lookalike), what === "another plugin", what);
    const { baseline, voidedAt } = effectiveBaseline({ records: [baselineRecord, lookalike], pluginId: "astra-chess" });
    assert.equal(voidedAt, null, `${what} voided the baseline`);
    assert.equal(baseline?.repository_id, "1343092393", `${what} ended the baseline`);
    const again = compareWithBaseline({
      identity: identityFromCertificate({ ...CHESS_FIELDS, repository_id: "2000000001", repository_owner_id: "2000000002" }),
      baseline,
    });
    assert.equal(again.code, IDENTITY_CODES.B_REPOSITORY_RECYCLED, `${what}: the recycled repository was not refused`);
  }
});

test("MIG-31: a different account pressing the button waits; a failed read decides nothing", () => {
  const identity = identityFromCertificate(CHESS_FIELDS);

  const owner = compareActor({ identity, actor: { status: "found", triggering_actor_id: "280318216" } });
  assert.equal(owner.outcome, "ok");
  assert.equal(owner.floor_days, 0);

  const someoneElse = compareActor({ identity, actor: { status: "found", triggering_actor_id: "193032699" } });
  assert.equal(someoneElse.outcome, "floor");
  assert.equal(someoneElse.floor_days, ACTOR_MISMATCH_FLOOR_DAYS);

  for (const actor of [
    { status: "transient", reason: "HTTP 502" },
    { status: "not_found", reason: "HTTP 404" },
    { status: "found", triggering_actor_id: null },
    // The shape that catches a reader keying on the FIELD instead of on the
    // STATUS: a caller that filled the id in anyway — from a cache, from a
    // retry, from a half-written object — while the read itself failed. The
    // status is what says whether GitHub answered.
    { status: "transient", triggering_actor_id: "193032699", reason: "HTTP 502" },
  ]) {
    const answer = compareActor({ identity, actor });
    assert.equal(answer.outcome, "wait", JSON.stringify(actor));
    assert.notEqual(answer.floor_days, ACTOR_MISMATCH_FLOOR_DAYS,
      "a read that did not happen must not impose the floor either — it decides nothing at all");
  }
});

test("a binding decision this tree cannot make is refused by name", () => {
  const refusal = bindingDecision({});
  assert.equal(refusal.ok, false);
  for (const wanted of ["listing-state.mjs", "B-T2.4", "B-T3.1", "log/rollout/R3-exit.json"]) {
    assert.ok(refusal.reason.includes(wanted), `the refusal must name ${wanted}: ${refusal.reason}`);
  }
  assert.ok(refusal.reason.includes("TRUST-23"), "and say what it did decide");
  assert.equal(bindingDecision({ listingState: {}, bindingLine: {}, verdict: {}, marker: {} }).ok, true);
});
