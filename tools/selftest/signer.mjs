// The signer library: D3's serials, D4's per-document gates and cadence,
// SERVE-30's key windows, D10's compromise mode, and D5's Pages latch.
//
// None of this has a workflow yet — RC-R1-2 writes `sign.yml` next — and that
// is the reason these are tests rather than a first run. Every rule below
// decides what a key signs and what a client is served, and the first time any
// of them runs for real it will run in a job that holds the index key, against
// `signed`, with no way to take a commit back. So each one is exercised here
// against a fixture tree and a fixture head, and each is watched failing by
// deleting the guard it names.
//
// The fixture heads are envelopes signed by the committed TEST index keys, and
// their trust.json documents carry no root signature: the root layer is
// root-delegation.mjs's subject, and what is under test here is which INDEX key
// signed what, and when it was allowed to.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fixtureEnv } from "../lib/git-env.mjs";

import { buildIndex, indexContent } from "../build-index.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { signIndex } from "../../bot/sign-index.mjs";
import { signRevocations } from "../sign-revocations.mjs";
import { fixtureCatalogue } from "../../bot/fixtures/index/regenerate.mjs";
import {
  REVOCATIONS_SCHEMA, TRUST_SCHEMA, indexSignersFromEnv, publicKeyFromBase64, signerList, verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import {
  DOCUMENT_DOMAINS, INDEX_KEY_WINDOW_HOURS, RETIREMENTS_PATH, RETIREMENTS_SCHEMA, WINDOW_EXEMPT_KEY_IDS,
  delegationTimes, keyPlan, readDelegationTimes, refusesDroppedKey,
} from "../signer/key-window.mjs";
import {
  RESIGN_AFTER_HOURS, SIGNED_FILES, catalogueGate, contentOf, decideDocument, fetchSignedHead,
  gateVerdict, indexSizeVerdict, listGate, maxIndexBytes, planRun, serialsAt,
} from "../signer/plan.mjs";
import { armingState, pagesRegistryFiles, pagesTree } from "../signer/pages.mjs";
import { test, assert, assertEqual, neverAsk, tmp } from "./harness.mjs";

const KEY_A = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
const KEY_B = "TEST-ONLY-DO-NOT-TRUST-index-2026b";
const testKeys = { [KEY_A]: loadTestRoot(KEY_A), [KEY_B]: loadTestRoot(KEY_B) };

const signerFor = (keyId) => ({
  key_id: keyId,
  privateKey: testKeys[keyId].privateKey,
  public_key: testKeys[keyId].publicKeyB64,
});

const trustDelegating = (keyIds, serial = 1) => ({
  signatures: [],
  signed: {
    schema: TRUST_SCHEMA,
    serial,
    issued_at: "2026-09-01T00:00:00Z",
    expires_at: "2027-09-01T00:00:00Z",
    index_keys: keyIds.map((keyId) => ({ key_id: keyId, public_key: testKeys[keyId].publicKeyB64 })),
  },
});

const keyIdsOf = (signers) => signers.map((s) => s.key_id).join(",");

/**
 * A `signed` head from four documents, with the bytes and the parsed copies
 * agreeing — which is what `fetchSignedHead` returns and what a carry copies.
 */
function headFrom({ index, revocations, trust = trustDelegating([KEY_A]), root = { schema: "astra.registry.root/1" }, sha = "0".repeat(40) }) {
  const bytes = {};
  const documents = {};
  for (const [name, doc] of Object.entries({ index, revocations, trust, root })) {
    bytes[name] = stableStringify(doc);
    documents[name] = JSON.parse(bytes[name]);
  }
  return { present: true, reason: null, sha, bytes, documents, parseErrors: [] };
}

const listing = (id, extra = {}) => ({
  schema: "astra.registry.plugin/1",
  id,
  name: id.replace(/-/g, " "),
  summary: "A listing that exists so the catalogue is not empty.",
  license: "MIT",
  source: { kind: "github", repo: `someone/${id}` },
  added_at: "2026-08-10",
  ...extra,
});

const release = (id, { sha256 = "a".repeat(64) } = {}) => ({
  schema: "astra.registry.version/1",
  id,
  version: "1.0.0",
  published_at: "2026-08-10T00:00:00Z",
  release: { kind: "github_release", repo: `someone/${id}`, tag: "v1.0.0" },
  protocol: 1,
  capabilities: ["tools"],
  artifacts: {
    "linux-x64": {
      url: `https://github.com/someone/${id}/releases/download/v1.0.0/${id}-1.0.0-linux-x64.astraplugin`,
      filename: `${id}-1.0.0-linux-x64.astraplugin`,
      sha256,
      size: 1234,
    },
  },
});

const advisory = (id = "ASTRA-2026-0001", pluginId = "dice-roller") => ({
  id,
  published: "2026-09-10",
  severity: "high",
  action: "block_install",
  reason: "A fixture advisory, long enough to be a sentence a user can act on.",
  entries: [{ kind: "id", value: pluginId }],
});

/** A throwaway registry tree with real git history, because D3 counts commits. */
function makeTree(name) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  const git = (...a) =>
    execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: fixtureEnv(dir) }).trimEnd();
  git("init", "-q", "-b", "main");
  git("config", "user.email", "signer-fixture@example.invalid");
  git("config", "user.name", "signer fixture");
  git("config", "commit.gpgsign", "false");
  const write = (rel, value) => {
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof value === "string" ? value : stableStringify(value));
  };
  const commit = (message) => {
    git("add", "-A");
    git("commit", "-qm", message);
    return git("rev-parse", "HEAD");
  };
  const addListing = (id, opts = {}) => {
    write(`plugins/${id}/plugin.json`, listing(id, opts.plugin ?? {}));
    write(`plugins/${id}/versions/1.0.0.json`, release(id, opts));
  };
  return { dir, git, write, commit, addListing, head: () => git("rev-parse", "HEAD") };
}

const NUMERALS = { 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten" };

/**
 * The rotation model, as the two documents a person reads describe it, against
 * the one number the signer holds.
 *
 * Written 2026-09-20, after the operator-runbook lane found that `SECURITY.md`
 * and `docs/RUNBOOK.md` both still opened with *"Quarterly, and immediately on
 * suspicion… with a **30-day overlap** between the outgoing and incoming
 * key"*. That is the model SERVE-30 replaced: the outgoing key does not stop
 * after an overlap measured in days, it keeps signing until R9b, and what a
 * rotation starts is a SEVEN-HOUR window against the client's six-hour
 * `trust.json` refresh.
 *
 * **Four lines below its own wrong sentence, `RUNBOOK.md` §5 had been saying
 * the right thing the whole time.** So this is not a document that was never
 * written; it is one where a reader who stops at the opening line schedules a
 * quarterly rotation and then finds no step in the procedure that matches.
 *
 * Two assertions, and they fail for different reasons on purpose. The first
 * catches the number drifting from the code — the ordinary coupling. The
 * second catches the MODEL coming back, which is the thing that was actually
 * wrong: no overlap measured in days, anywhere in either file, because a
 * duration in days is only sayable about the model that no longer exists.
 */
function rotationModel() {
  const docs = ["SECURITY.md", "docs/RUNBOOK.md"];
  const word = NUMERALS[INDEX_KEY_WINDOW_HOURS];
  for (const rel of docs) {
    const text = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");

    // The number, spelled either way. A prose window that disagrees with the
    // code is a reader computing a margin against the wrong figure.
    const hasNumber = text.includes(`${INDEX_KEY_WINDOW_HOURS} hours`) ||
      (word && (text.includes(`${word} hours`) || text.includes(`${word}-hour`)));
    assert(
      hasNumber,
      `${rel} never states the index-key window, which is ${INDEX_KEY_WINDOW_HOURS} hours ` +
      "(INDEX_KEY_WINDOW_HOURS, tools/signer/key-window.mjs). A document about rotating the key that does " +
      "not carry the one number a rotation turns on sends its reader to guess it",
    );

    // The retired model. `30-day overlap` is the exact phrase that was there;
    // the pattern is general because the next spelling of a wrong idea is
    // never the previous spelling of it.
    const overlapInDays = text.match(/\b(?:\d+|thirty|sixty|ninety)[ -]day\b[^.\n]{0,40}overlap/i);
    assert(
      !overlapInDays,
      `${rel} describes the index-key overlap in DAYS — "${overlapInDays?.[0]}" — and SERVE-30 replaced that ` +
      "model: the outgoing key keeps signing until R9b, and a rotation starts a window of hours, not an " +
      "overlap of days. This exact sentence sat four lines above the correct one in docs/RUNBOOK.md §5 " +
      "until 2026-09-20",
    );
  }
}

export async function run() {
  // ── SERVE-30's key windows, and D10's one exception ─────────────────────────
  console.log("\nthe signer's key windows");

  await test("the two documents a person reads describe the window the signer implements", () => {
    rotationModel();
  });

  await test("the delegation time of a key is the FIRST `signed` commit that delegated it", () => {
    const times = delegationTimes([
      { sha: "1", committed_at: "2026-09-01T00:00:00Z", key_ids: [KEY_A] },
      { sha: "2", committed_at: "2026-09-10T00:00:00Z", key_ids: [KEY_A, KEY_B] },
      { sha: "3", committed_at: "2026-09-11T00:00:00Z", key_ids: [KEY_A, KEY_B] },
    ]);
    assertEqual(times.get(KEY_A), "2026-09-01T00:00:00Z", "the first delegation, not the latest");
    assertEqual(times.get(KEY_B), "2026-09-10T00:00:00Z", "the first delegation, not the latest");
  });

  await test("a newly delegated key is refused the catalogue at 6 h 59 min and allowed at 7 h", () => {
    // SERVE-30's margin over the client's 6-hour trust.json refresh. Without it
    // a catalogue goes out signed by a key that no running client has been
    // told about, and every one of them refuses the catalogue until its next
    // refresh — for a rotation, which is a planned act, and therefore for
    // nothing.
    const candidateTrust = trustDelegating([KEY_A, KEY_B]);
    const delegatedAt = new Map([[KEY_A, "2026-09-01T00:00:00Z"], [KEY_B, "2026-09-10T00:00:00Z"]]);
    const available = [signerFor(KEY_A), signerFor(KEY_B)];

    const within = keyPlan({
      candidateTrust, headTrust: candidateTrust, delegatedAt, available, now: "2026-09-10T06:59:00Z",
    });
    assertEqual(keyIdsOf(within.index.signers), KEY_A, "the incoming key signed the catalogue inside its window");
    assertEqual(keyIdsOf(within.revocations.signers), `${KEY_A},${KEY_B}`,
      "the LIST is dual-signed from the delegating commit — it is what carries the new key into circulation");
    assert(within.notes.some((n) => n.includes(KEY_B) && n.includes("after 7 h")),
      `the refusal has to say when it lifts: ${JSON.stringify(within.notes)}`);

    const after = keyPlan({
      candidateTrust, headTrust: candidateTrust, delegatedAt, available, now: "2026-09-10T07:00:00Z",
    });
    assertEqual(keyIdsOf(after.index.signers), `${KEY_A},${KEY_B}`, "the window elapsed and the catalogue is still single-signed");
    assertEqual(INDEX_KEY_WINDOW_HOURS, 7, "SERVE-30's window");
  });

  await test("a key delegated on a branch merged into `signed` starts its seven hours at the merge", () => {
    // Gap 68's shape in the window's clock (ops register, entry 93). The seven
    // hours are the time clients have had the delegating trust.json, and Pages
    // serves `signed`'s head, so they start where `signed`'s own line first
    // carries it. A plain `git log -- trust.json` simplifies through a merge
    // that is TREESAME to its side parent and dates the SIDE commit: measured
    // before the repair, delegated 09:00 on a side branch and merged 12:00
    // read as 09:00, and at 16:30 the incoming key signed the catalogue with
    // four and a half hours served. The signer never writes a merge to
    // `signed`; somebody else's push is the only way one gets there, and the
    // window must not open early on the day it does.
    const t = makeTree("key-window-merged");
    const at = (when, ...a) => execFileSync("git", ["-C", t.dir, ...a], {
      stdio: ["ignore", "pipe", "pipe"], env: { ...fixtureEnv(t.dir), GIT_AUTHOR_DATE: when, GIT_COMMITTER_DATE: when },
    });
    t.git("checkout", "-q", "-b", "signed");
    t.write("registry/v1/trust.json", trustDelegating([KEY_A]));
    t.git("add", "-A");
    at("2026-09-01T00:00:00Z", "commit", "-qm", "a trust.json delegating A");
    t.git("checkout", "-q", "-b", "side");
    t.write("registry/v1/trust.json", trustDelegating([KEY_A, KEY_B]));
    t.git("add", "-A");
    at("2026-09-10T09:00:00Z", "commit", "-qm", "B delegated, on a side branch");
    t.git("checkout", "-q", "signed");
    t.write("registry/v1/index.json", { signed: {} });
    t.git("add", "-A");
    at("2026-09-10T10:00:00Z", "commit", "-qm", "a signer run meanwhile");
    at("2026-09-10T12:00:00Z", "merge", "-q", "--no-ff", "-m", "the side branch, merged into signed", "side");

    const delegatedAt = readDelegationTimes({ root: t.dir, ref: "signed" });
    assertEqual(delegatedAt.get(KEY_B), "2026-09-10T12:00:00Z",
      "the incoming key is dated at the side commit that delegated it, not where `signed` first carried the delegation");
    assertEqual(delegatedAt.get(KEY_A), "2026-09-01T00:00:00Z", "the outgoing key's first delegation moved");

    const candidateTrust = trustDelegating([KEY_A, KEY_B]);
    const plan = (now) => keyPlan({
      candidateTrust, headTrust: candidateTrust, delegatedAt, available: [signerFor(KEY_A), signerFor(KEY_B)], now,
    });
    assertEqual(keyIdsOf(plan("2026-09-10T16:30:00Z").index.signers), KEY_A,
      "the incoming key signed the catalogue four and a half hours after `signed` first carried its delegation");
    assertEqual(keyIdsOf(plan("2026-09-10T19:00:00Z").index.signers), `${KEY_A},${KEY_B}`,
      "seven hours after the merge the window is served, and the catalogue is still single-signed");
  });

  await test("the bootstrap key is exempt, and nothing else is", () => {
    // Not a courtesy. `astra-index-2026a` is what today's trust.json delegates
    // and there is no `signed` branch, so no commit has ever delegated it, so
    // its window has not started. Without the exemption the first signer run
    // refuses the catalogue, has no head to carry from, and `signed` is never
    // created — R1 cannot start.
    assertEqual(WINDOW_EXEMPT_KEY_IDS.join(","), "astra-index-2026a", "the exempt set is one key");
    const bootstrap = { key_id: "astra-index-2026a", public_key: testKeys[KEY_A].publicKeyB64 };
    const candidateTrust = {
      signatures: [],
      signed: { schema: TRUST_SCHEMA, serial: 1, index_keys: [bootstrap] },
    };
    const plan = keyPlan({
      candidateTrust, headTrust: null, delegatedAt: new Map(), available: [bootstrap], now: "2026-09-19T00:00:00Z",
    });
    assertEqual(keyIdsOf(plan.index.signers), "astra-index-2026a", "the first run could not sign the catalogue");
    assertEqual(plan.index.refused, null, "the first run was refused");
  });

  await test("a dual-signed list carries the OUTGOING signature first, and each key verifies it alone", () => {
    // The order is read from `signed`'s history, never from the environment and
    // never from the order trust.json lists keys in — both of those are
    // whatever the last person to edit them typed. Proved by handing the plan
    // the environment in the WRONG order and the trust document in the wrong
    // order, and asserting it still puts the older delegation first.
    const candidateTrust = trustDelegating([KEY_B, KEY_A]);
    const delegatedAt = new Map([[KEY_A, "2026-09-01T00:00:00Z"], [KEY_B, "2026-09-10T00:00:00Z"]]);
    const plan = keyPlan({
      candidateTrust,
      headTrust: candidateTrust,
      delegatedAt,
      available: [signerFor(KEY_B), signerFor(KEY_A)],
      now: "2026-09-11T00:00:00Z",
    });
    assertEqual(keyIdsOf(plan.revocations.signers), `${KEY_A},${KEY_B}`, "outgoing first");

    const doc = signRevocations(
      { signed: { schema: REVOCATIONS_SCHEMA, serial: 4, revocations: [] } },
      { signers: plan.revocations.signers, issuedAt: new Date("2026-09-11T00:00:00Z") },
    );
    assertEqual(doc.signatures.length, 2, "a rotation dual-signs");
    assertEqual(doc.signatures[0].key_id, KEY_A, "the outgoing key's signature is not first");
    for (const keyId of [KEY_A, KEY_B]) {
      const r = verifyEnvelope(doc, REVOCATIONS_SCHEMA, [
        { key_id: keyId, publicKey: publicKeyFromBase64(testKeys[keyId].publicKeyB64) },
      ]);
      assert(r.ok, `a client holding only ${keyId}'s trust.json could not verify the list: ${r.reason}`);
    }
  });

  await test("a key the environment holds and trust.json does not delegate never signs", () => {
    // It would be committed beside a trust.json that cannot verify it, and
    // SERVE-91 would refuse the whole commit — withholding the list as well.
    // Dropped loudly rather than silently, because a secret that is in the
    // environment and not in the document is a half-finished ceremony.
    const plan = keyPlan({
      candidateTrust: trustDelegating([KEY_A]),
      headTrust: trustDelegating([KEY_A]),
      delegatedAt: new Map([[KEY_A, "2026-09-01T00:00:00Z"]]),
      available: [signerFor(KEY_A), signerFor(KEY_B)],
      now: "2026-09-11T00:00:00Z",
    });
    assertEqual(keyIdsOf(plan.revocations.signers), KEY_A, "an undelegated key signed");
    assert(plan.notes.some((n) => n.includes(KEY_B) && n.includes("does not delegate it")),
      `the drop has to be said out loud: ${JSON.stringify(plan.notes)}`);
  });

  await test("the signer never commits a catalogue signed by a dropped key beside the trust.json that drops it", () => {
    // D10 step 4, and the one selftest RC-R1-1 names for key-window.mjs.
    //
    // The shape: a root ceremony publishes a trust.json delegating only the new
    // key. If the catalogue's gates then fail, D4's ordinary answer is to carry
    // `signed`'s copy forward — and that copy is signed by the key this very
    // commit drops. SERVE-15 verifies every candidate document against the
    // candidate trust.json, SERVE-91 refuses the whole commit, and the repair
    // does not land: the new trust.json and the list signed by the new key are
    // withheld together, and the compromised key's last bytes stay served.
    const headTrust = trustDelegating([KEY_A]);
    const candidateTrust = trustDelegating([KEY_B], 2);
    const delegatedAt = new Map([[KEY_A, "2026-09-01T00:00:00Z"], [KEY_B, "2026-09-10T00:00:00Z"]]);
    const now = "2026-09-10T02:00:00Z"; // two hours in — inside the seven-hour window

    const plan = keyPlan({ candidateTrust, headTrust, delegatedAt, available: [signerFor(KEY_B)], now });
    assertEqual(plan.mode, "compromise", "dropping the head's key is what selects compromise mode");
    assertEqual(plan.dropped.join(","), KEY_A, "the dropped key is not named");
    assertEqual(keyIdsOf(plan.index.signers), KEY_B,
      "the seven-hour window was not waived, so the catalogue cannot be re-signed and would be carried");
    assertEqual(plan.carryCatalogueAllowed, false, "a carry is still allowed in compromise mode");

    const headIndex = signIndex(fixtureCatalogue(5), {
      signer: signerFor(KEY_A), issuedAt: new Date("2026-09-09T00:00:00Z"),
    });
    const head = headFrom({
      index: headIndex,
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
      trust: headTrust,
    });
    const gate = { ok: false, failures: ["a listing does not validate"], notes: [], candidate: null, bytes: null, serial: 5 };

    const decided = decideDocument({
      name: "index", file: SIGNED_FILES.index, gate, head, now, carryAllowed: plan.carryCatalogueAllowed,
    });
    assertEqual(decided.decision, "blocked", "the run carried a catalogue the new trust.json cannot verify");

    // The fixture has to be ABLE to produce the bad commit, or the refusal
    // below is asserting something that cannot happen.
    const bad = decideDocument({ name: "index", file: SIGNED_FILES.index, gate, head, now, carryAllowed: true });
    assertEqual(bad.decision, "carry", "the carry this test is about cannot be constructed");
    const problems = refusesDroppedKey({
      trust: candidateTrust,
      documents: [{ name: SIGNED_FILES.index, domain: DOCUMENT_DOMAINS.index, doc: JSON.parse(bad.bytes) }],
    });
    assertEqual(problems.length, 1, `the carried catalogue was accepted beside the trust.json that drops its signer: ${problems}`);
    assert(problems[0].includes("does not verify"), problems[0]);

    // And what the compromise plan actually produces passes the same refusal.
    const resigned = signIndex(fixtureCatalogue(6), { signers: plan.index.signers, issuedAt: new Date(now) });
    assertEqual(
      refusesDroppedKey({
        trust: candidateTrust,
        documents: [{ name: SIGNED_FILES.index, domain: DOCUMENT_DOMAINS.index, doc: resigned }],
      }).join("; "),
      "",
      "the catalogue re-signed by the incoming key was refused",
    );
  });

  await test("a planned retirement is not compromise mode, and a dropped key without a retirement record is", () => {
    // D10, decided 2026-09-23 (contract 0.38.0's SERVE-30): a compromised key is
    // dropped and the catalogue re-signed at once; the overlap is for a PLANNED
    // retirement only. Both end with a trust.json that drops a key the head
    // delegated, and until 0.38.0 this module read both as a compromise — so
    // R9b's retirement, on a day the catalogue was red, blocked the whole
    // commit and the withdrawal list with it (ops couplings entry 20).
    //
    // The shape is R9b's: the head delegates the outgoing and the incoming key,
    // the incoming one long past its seven hours, and the candidate drops the
    // outgoing one. Only the record decides which kind of drop it is, and every
    // way of not having one — none, the wrong key, a time not yet reached, a
    // malformed file, a file that does not parse, a second drop it does not
    // name — is a compromise.
    const headTrust = trustDelegating([KEY_A, KEY_B]);
    const candidateTrust = trustDelegating([KEY_B], 2);
    const delegatedAt = new Map([[KEY_A, "2026-01-01T00:00:00Z"], [KEY_B, "2026-06-01T00:00:00Z"]]);
    const now = "2026-09-19T00:00:00Z";
    const record = (rows, extra = {}) => ({ schema: RETIREMENTS_SCHEMA, retirements: rows, ...extra });
    const plan = (retirements, trusts = { headTrust, candidateTrust }) =>
      keyPlan({ ...trusts, delegatedAt, available: [signerFor(KEY_B)], now, retirements });

    const planned = plan({ record: record([{ key_id: KEY_A, retired_from: "2026-09-18T00:00:00Z" }]), problem: null });
    assertEqual(planned.mode, "retirement", "a drop the record names from a time already reached is still a compromise");
    assertEqual(planned.dropped.join(","), KEY_A, "the dropped key");
    assertEqual(planned.retired.join(","), KEY_A, "the retired key");
    assertEqual(planned.carryCatalogueAllowed, true, "a planned retirement may not carry a failing catalogue");
    assertEqual(keyIdsOf(planned.index.signers), KEY_B, "the key that remains does not sign the catalogue");
    assert(planned.notes.some((n) => n.includes("planned retirement") && n.includes(RETIREMENTS_PATH)),
      `the run has to say it read the drop as a retirement, and from what: ${JSON.stringify(planned.notes)}`);
    // Exactly the time: `retired_from` equal to `now` has been reached.
    assertEqual(plan({ record: record([{ key_id: KEY_A, retired_from: now }]), problem: null }).mode, "retirement",
      "a retirement is not in effect at the instant it names");

    const compromises = [
      ["no record at all", { record: null, problem: null }],
      ["a record naming the other key", { record: record([{ key_id: KEY_B, retired_from: "2026-09-18T00:00:00Z" }]), problem: null }],
      ["a retirement planned for a later time", { record: record([{ key_id: KEY_A, retired_from: "2026-09-19T00:00:01Z" }]), problem: null }],
      ["a record under another schema", { record: { schema: "astra.registry.index-key-retirement/1", retirements: [{ key_id: KEY_A, retired_from: "2026-09-18T00:00:00Z" }] }, problem: null }],
      ["a record with a member no record has", { record: record([{ key_id: KEY_A, retired_from: "2026-09-18T00:00:00Z" }], { reason: "planned" }), problem: null }],
      ["a row with a member no row has", { record: record([{ key_id: KEY_A, retired_from: "2026-09-18T00:00:00Z", by: "operator" }]), problem: null }],
      ["a time that is not §0.7's", { record: record([{ key_id: KEY_A, retired_from: "2026-02-30T00:00:00Z" }]), problem: null }],
      ["a malformed row beside a good one", { record: record([{ key_id: KEY_A, retired_from: "2026-09-18T00:00:00Z" }, { retired_from: "2026-09-18T00:00:00Z" }]), problem: null }],
      ["a record that does not parse", { record: undefined, problem: `${RETIREMENTS_PATH} at 000000000000 is not JSON (Unexpected end of JSON input)` }],
    ];
    for (const [what, retirements] of compromises) {
      const p = plan(retirements);
      assertEqual(p.mode, "compromise", `${what} read as ${p.mode}`);
      assertEqual(p.carryCatalogueAllowed, false, `${what}: a compromise may carry a catalogue`);
      assertEqual(p.retired.join(","), "", `${what}: a retired key was named`);
    }
    const malformed = plan(compromises[4][1]);
    assert(malformed.notes.some((n) => n.includes("names nothing") && n.includes("reason")),
      `a malformed record has to be named, not ignored: ${JSON.stringify(malformed.notes)}`);
    // An unparseable record is a compromise by construction — it names no key —
    // so the mode alone cannot show the run noticed it. The note is the proof.
    const unparsed = plan(compromises[8][1]);
    assert(unparsed.notes.some((n) => n.includes("names nothing") && n.includes("is not JSON")),
      `a record that does not parse has to be named, not read as absent: ${JSON.stringify(unparsed.notes)}`);

    // Two keys dropped, one planned: the other is a compromise, and one is enough.
    const stranger = { key_id: "TEST-ONLY-DO-NOT-TRUST-stranger", public_key: testKeys[KEY_A].publicKeyB64 };
    const three = { ...headTrust, signed: { ...headTrust.signed, index_keys: [...headTrust.signed.index_keys, stranger] } };
    const both = plan({ record: record([{ key_id: KEY_A, retired_from: "2026-09-18T00:00:00Z" }]), problem: null },
      { headTrust: three, candidateTrust });
    assertEqual(both.mode, "compromise", "a second drop the record does not name was read as planned");
    assertEqual(both.dropped.join(","), `${KEY_A},${stranger.key_id}`, "the dropped keys");

    // And a record read on a day nothing is dropped changes nothing, but says
    // so when it is malformed — the day of the retirement is too late to find out.
    const quiet = plan(compromises[4][1], { headTrust: candidateTrust, candidateTrust });
    assertEqual(quiet.mode, "normal", "a record with nothing dropped changed the mode");
    assert(quiet.notes.some((n) => n.includes("names nothing")), "a malformed record was silent until the day it matters");
  });

  await test("one signer or two, and never both spellings at once", () => {
    const a = signerFor(KEY_A);
    assertEqual(signerList({ signer: a }).length, 1, "one signer");
    assertEqual(signerList({ signers: [a, signerFor(KEY_B)] }).length, 2, "two signers");
    for (const [opts, why] of [
      [{ signer: a, signers: [a] }, "both spellings hide which key signs first"],
      [{}, "nothing to sign with"],
    ]) {
      let threw = false;
      try { signerList(opts); } catch { threw = true; }
      assert(threw, why);
    }
  });

  await test("ASTRA_INDEX_SIGNING_KEY_NEXT is one more signer, and a copy of the first is not a rotation", () => {
    const a = testKeys[KEY_A];
    const b = testKeys[KEY_B];
    const base = {
      ASTRA_INDEX_SIGNING_KEY: a.seed.toString("base64"),
      ASTRA_INDEX_SIGNING_KEY_ID: KEY_A,
    };
    assertEqual(keyIdsOf(indexSignersFromEnv({ env: base })), KEY_A, "no rotation is one signer — no secret is added at R1");
    assertEqual(
      keyIdsOf(indexSignersFromEnv({
        env: { ...base, ASTRA_INDEX_SIGNING_KEY_NEXT: b.seed.toString("base64"), ASTRA_INDEX_SIGNING_KEY_NEXT_ID: KEY_B },
      })),
      `${KEY_A},${KEY_B}`,
      "the incoming key did not reach the signer",
    );
    assertEqual(indexSignersFromEnv({ env: {} }).length, 0, "no key at all is not an error here; the caller reports it");

    for (const [env, needle] of [
      [{ ...base, ASTRA_INDEX_SIGNING_KEY_NEXT: b.seed.toString("base64") }, "ASTRA_INDEX_SIGNING_KEY_NEXT_ID"],
      // The rotation that is not one: the live secret copied into the `_NEXT`
      // slot. Two signatures by one key look dual-signed to every reader, and a
      // client holding only the old trust.json is exactly as stuck as before.
      [{ ...base, ASTRA_INDEX_SIGNING_KEY_NEXT: a.seed.toString("base64"), ASTRA_INDEX_SIGNING_KEY_NEXT_ID: KEY_B }, "same Ed25519 key"],
    ]) {
      let message = "";
      try { indexSignersFromEnv({ env }); } catch (e) { message = e.message; }
      assert(message.includes(needle), `expected a refusal naming ${needle}, got ${JSON.stringify(message)}`);
    }
  });

  // ── D3's serials and D4's per-document gates ────────────────────────────────
  console.log("\nthe signer's plan");

  await test("the serials are D3's two formulas, counted at the Source-Commit and not at HEAD", () => {
    const t = makeTree("serials");
    t.addListing("dice-roller");
    const first = t.commit("a listing");
    assertEqual(serialsAt({ root: t.dir, sha: first }).index, 1, "one commit under plugins/");
    assertEqual(serialsAt({ root: t.dir, sha: first }).revocations, 1, "no advisory commit yet, and serial 0 is reserved");

    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    const second = t.commit("an advisory");
    const at = serialsAt({ root: t.dir, sha: second });
    assertEqual(at.index, 1, "an advisory commit is not a catalogue commit");
    assertEqual(at.revocations, 2, "the list's serial is the advisory commit count plus one");

    // The difference from `tools/build-index.mjs`'s counter, which adds one for
    // a staged change because it runs inside the workflow that is about to
    // commit. The signer counts at a commit that exists, so a dirty tree adds
    // nothing — and if it did, two runs over one Source-Commit would publish
    // two serials for one catalogue.
    t.addListing("second-plugin");
    assertEqual(serialsAt({ root: t.dir, sha: second }).index, 1,
      "an uncommitted listing moved the serial the signer counts at a commit");

    // And the older commit still counts what it counted.
    assertEqual(serialsAt({ root: t.dir, sha: first }).revocations, 1, "the count at an older commit moved");
  });

  await test("SERVE-49's cap is policy/limits.json's number, refused one byte over", () => {
    const limit = maxIndexBytes();
    assertEqual(limit, 1048576, "max_index_bytes is not 1 MiB; SERVE-50 and this test disagree");
    assertEqual(indexSizeVerdict(limit, limit).ok, true, "a catalogue exactly at the cap is refused");
    const over = indexSizeVerdict(limit + 1, limit);
    assertEqual(over.ok, false, "1,048,577 bytes was accepted");
    assert(over.message.includes("SERVE-49") && over.message.includes(String(limit + 1)),
      `the refusal has to name the size and the rule: ${over.message}`);
  });

  await test("a lower serial than `signed`'s head is refused", async () => {
    // SERVE-36. D3 says the counts only rise, because ROLL-5 forbids rewriting
    // `main` — so a serial that fell is not a smaller catalogue, it is evidence
    // that something the serial rests on stopped being true, and publishing it
    // would make every armed client refuse the document that follows.
    const head = headFrom({
      index: signIndex(fixtureCatalogue(9), { signer: signerFor(KEY_A), issuedAt: new Date("2026-09-18T00:00:00Z") }),
      revocations: signRevocations(
        { signed: { schema: REVOCATIONS_SCHEMA, serial: 9, revocations: [] } },
        { signer: signerFor(KEY_A), issuedAt: new Date("2026-09-18T00:00:00Z") },
      ),
    });
    const t = makeTree("lower-serial");
    t.addListing("dice-roller");
    t.commit("a listing");

    const gate = await catalogueGate({ root: t.dir, serial: 8, head, limit: 1048576 });
    assertEqual(gate.ok, false, "a serial below the head's was accepted");
    assert(gate.failures.some((f) => f.includes("SERVE-36") && f.includes("8") && f.includes("9")),
      `the refusal has to name both serials: ${JSON.stringify(gate.failures)}`);

    const list = listGate({ root: t.dir, serial: 8, head });
    assertEqual(list.ok, false, "the list took a lower serial than the head's");
    assert(list.failures.some((f) => f.includes("SERVE-36")), JSON.stringify(list.failures));
  });

  await test("an unchanged document is a no-op at 19 h and re-signed at 20 h", () => {
    // D4's cadence. Twenty hours sits inside the list's seven-day TTL with room
    // for a missed run, and an unchanged document re-signed every hour would
    // put a `signed` commit an hour in front of every reader of SERVE-85 for no
    // content change at all.
    const doc = signRevocations(
      { signed: { schema: REVOCATIONS_SCHEMA, serial: 3, revocations: [] } },
      { signer: signerFor(KEY_A), issuedAt: new Date("2026-09-18T00:00:00Z") },
    );
    const head = headFrom({ index: signIndex(fixtureCatalogue(3), { signer: signerFor(KEY_A) }), revocations: doc });
    const gate = {
      ok: true, failures: [], notes: [], serial: 3,
      candidate: { signed: { schema: REVOCATIONS_SCHEMA, serial: 3, revocations: [] } },
    };
    const at = (hours) =>
      decideDocument({
        name: "revocations", file: SIGNED_FILES.revocations, gate, head,
        now: new Date(Date.parse("2026-09-18T00:00:00Z") + hours * 3600 * 1000).toISOString().replace(/\.\d+Z$/, "Z"),
      });
    assertEqual(at(19).decision, "unchanged", "a re-sign at 19 h");
    assertEqual(at(19).bytes, head.bytes.revocations, "an unchanged document must re-commit the head's exact bytes");
    assertEqual(at(20).decision, "resign", "no re-sign at 20 h");
    assertEqual(RESIGN_AFTER_HOURS, 20, "D4's cadence");
  });

  await test("an unchanged list beside a changed catalogue keeps the list's bytes", async () => {
    // D4: each document stands alone, in both directions. The catalogue moving
    // must not restamp a list that did not move — a re-signed list at the same
    // serial is a new document every reader of SERVE-85 has to account for.
    const t = makeTree("one-moves");
    t.addListing("dice-roller");
    const first = t.commit("a listing");

    const headList = signRevocations(
      { $comment: "x", signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
      { signer: signerFor(KEY_A), issuedAt: new Date("2026-09-19T00:00:00Z") },
    );
    const headIndex = signIndex(buildIndex({ root: t.dir, serial: 1 }), {
      signer: signerFor(KEY_A), issuedAt: new Date("2026-09-19T00:00:00Z"),
    });
    const head = headFrom({ index: headIndex, revocations: headList, sha: first });

    t.addListing("second-plugin");
    const second = t.commit("a second listing");

    const plan = await planRun({ root: t.dir, sourceCommit: second, head, now: "2026-09-19T01:00:00Z" });
    assertEqual(plan.documents.index.decision, "changed", "a new listing did not change the catalogue");
    assertEqual(plan.documents.revocations.decision, "unchanged", "the list moved because the catalogue did");
    assertEqual(plan.documents.revocations.bytes, head.bytes.revocations, "the list's bytes were not the head's");
    assertEqual(plan.alerts.join("; "), "", "an unchanged document must not alert");
    assertEqual(plan.commit, true, "the run had a changed document and decided to commit nothing");
  });

  await test("each of D4's three catalogue failures still commits the list, carries the catalogue and alerts", async () => {
    // Per-document isolation, the property the whole design rests on: a
    // catalogue problem must never hold a withdrawal back. Three failures, one
    // per gate, each a different thing going wrong in the tree.
    const headList = signRevocations(
      { signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
      { signer: signerFor(KEY_A), issuedAt: new Date("2026-09-19T00:00:00Z") },
    );

    // Each case names the failure it is supposed to produce. Without that, all
    // three could fail for one reason — the fixture never building, say — and
    // the test would report three isolated gates it had exercised once.
    const cases = [
      ["an invalid listing",
        (t) => { t.addListing("broken-one", { sha256: "not-a-digest" }); t.commit("a broken listing"); },
        { because: "$.artifacts.linux-x64.sha256 does not match" }],
      ["an oversize catalogue",
        (t) => { t.addListing("second-plugin"); t.commit("a listing"); },
        { limit: 200, because: "SERVE-49" }],
      // Equal-serial drift: the serial is taken at the Source-Commit and the
      // tree under it says something else — here a listing that is not
      // committed, which is the shape whatever produced it. TRUST-28 needs an
      // equal serial to mean equal listings, so the served catalogue is
      // carried until a commit under plugins/ raises it.
      ["equal-serial drift", (t) => { t.addListing("second-plugin"); }, { because: "TRUST-28" }],
    ];

    for (const [label, mutate, opts] of cases) {
      const t = makeTree(`isolation-${label.replace(/\W+/g, "-")}`);
      t.addListing("dice-roller");
      const first = t.commit("a listing");
      const headIndex = signIndex(buildIndex({ root: t.dir, serial: 1 }), {
        signer: signerFor(KEY_A), issuedAt: new Date("2026-09-19T00:00:00Z"),
      });
      const head = headFrom({ index: headIndex, revocations: headList, sha: first });

      // The list changes in every case, so "the list still committed" is a real
      // observation rather than an unchanged document sitting still.
      t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
      t.commit("an advisory");
      mutate(t);
      const sourceCommit = t.head();

      const plan = await planRun({
        root: t.dir, sourceCommit, head, now: "2026-09-19T02:00:00Z", limit: opts.limit ?? 1048576,
      });
      assertEqual(plan.documents.index.decision, "carry", `${label}: the catalogue was not carried`);
      assertEqual(plan.documents.index.bytes, head.bytes.index, `${label}: the carry is not byte-for-byte the head`);
      assertEqual(plan.documents.revocations.decision, "changed", `${label}: the withdrawal list was held back`);
      assertEqual(plan.alerts.length, 1, `${label}: every carry alerts (${plan.alerts.join("; ")})`);
      assert(plan.alerts[0].includes(SIGNED_FILES.index), `${label}: ${plan.alerts[0]}`);
      assertEqual(plan.commit, true, `${label}: the run refused to commit at all`);
      assertEqual(plan.refusals.join("; "), "", `${label}: a carry is not a refusal`);
      assert(plan.documents.index.reasons.some((r) => r.includes(opts.because)),
        `${label}: the gate refused for some other reason than the one this case is about ` +
        `(wanted ${opts.because}): ${JSON.stringify(plan.documents.index.reasons)}`);
    }
  });

  await test("a stale committed revocations.json on main does not stop a changed list", () => {
    // ROLL-12: `main:registry/v1/revocations.json` is an unsigned regeneration,
    // and between an advisory commit and the next `build-index` run it is
    // simply out of date. The list the signer publishes is built from
    // `tools/revocations/**` alone, so a stale copy on main cannot hold a
    // withdrawal back — which is the one delay this design exists to remove.
    const t = makeTree("stale-main-list");
    t.addListing("dice-roller");
    t.write("registry/v1/revocations.json", {
      $comment: "stale: regenerated before the advisory below existed",
      signatures: [],
      signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] },
    });
    t.commit("a listing and a list");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    const sourceCommit = t.commit("an advisory, and nobody regenerated the committed list");

    const serials = serialsAt({ root: t.dir, sha: sourceCommit });
    const gate = listGate({ root: t.dir, serial: serials.revocations, head: { present: false } });
    assertEqual(gate.ok, true, `the list did not build: ${gate.failures.join("; ")}`);
    assertEqual(gate.candidate.signed.revocations.length, 1, "the advisory did not reach the list");
    assertEqual(gate.candidate.signed.revocations[0].value, "dice-roller", "the wrong entry");
    assertEqual(gate.candidate.signed.serial, 2, "the serial is the advisory commit count plus one");
  });

  await test("before the first run there is no head, so a failing document is blocked rather than carried", () => {
    // R1's opening state, and the reason `carry` is not the answer to
    // everything: a commit on `signed` holds all four documents (D2), so the
    // first run cannot publish half of one.
    const t = makeTree("no-head");
    t.addListing("dice-roller");
    t.commit("a listing");
    const head = fetchSignedHead({ root: t.dir, remote: "origin", fetch: true });
    assertEqual(head.present, false, "a repository with no `signed` branch reported a head");
    assert(head.reason.includes("origin"), head.reason);

    const decided = decideDocument({
      name: "index", file: SIGNED_FILES.index, head,
      gate: { ok: false, failures: ["a listing does not validate"], notes: [], candidate: null, serial: 1 },
      now: "2026-09-19T00:00:00Z",
    });
    assertEqual(decided.decision, "blocked", "there was nothing to carry and the run carried it anyway");
    assert(decided.blocked_because.includes("no usable copy"), decided.blocked_because);
  });

  await test("`signed`'s head comes back byte for byte, trailing newline included", () => {
    // What a carry copies. `stableStringify` ends every document with a
    // newline; a read that trimmed it would produce a carry whose bytes differ
    // from the head's by one byte, whose SHA-256 differs, and whose signature
    // was made over the other bytes — so it would not verify, on a path that
    // only runs when something has already gone wrong.
    const t = makeTree("head-bytes");
    t.addListing("dice-roller");
    t.commit("a listing");
    const list = signRevocations(
      { signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
      { signer: signerFor(KEY_A), issuedAt: new Date("2026-09-19T00:00:00Z") },
    );
    const wrote = {
      "registry/v1/index.json": stableStringify(signIndex(fixtureCatalogue(4), { signer: signerFor(KEY_A) })),
      "registry/v1/revocations.json": stableStringify(list),
      "registry/v1/trust.json": stableStringify(trustDelegating([KEY_A])),
      "registry/v1/root.json": stableStringify({ schema: "astra.registry.root/1" }),
    };
    t.git("checkout", "-q", "--orphan", "signed");
    t.git("rm", "-rq", "--cached", ".");
    for (const f of fs.readdirSync(path.join(t.dir)).filter((n) => n !== ".git")) {
      fs.rmSync(path.join(t.dir, f), { recursive: true, force: true });
    }
    for (const [rel, text] of Object.entries(wrote)) t.write(rel, text);
    const signedSha = t.commit("the first signed set");
    t.git("checkout", "-q", "main");

    const head = fetchSignedHead({ root: t.dir, remote: t.dir, branch: "signed" });
    assertEqual(head.present, true, `no head: ${head.reason}`);
    assertEqual(head.sha, signedSha, "the head is a different commit");
    for (const [name, rel] of Object.entries(SIGNED_FILES)) {
      // The cheap assertion first, and on purpose: the whole-document
      // comparison below prints both documents, and a missing newline is the
      // one difference a reader would have to count characters to find.
      assert(head.bytes[name].endsWith("}\n"), `${rel} lost its trailing newline`);
      assertEqual(head.bytes[name].length, wrote[rel].length, `${rel} came back a different length`);
      assertEqual(head.bytes[name], wrote[rel], `${rel} did not round-trip byte for byte`);
    }
    assertEqual(head.parseErrors.join("; "), "", "the head did not parse");
  });

  await test("the content projection is the catalogue's own, extended to the list", () => {
    // `contentOf` decides what "unchanged" means for both documents, and
    // `tools/build-index.mjs`'s `indexContent` decides it for `--check`. Two
    // answers to one question is how a catalogue becomes "unchanged" to the
    // signer and "different" to CI, or the reverse.
    const doc = signIndex(fixtureCatalogue(7), { signer: signerFor(KEY_A) });
    // Key sets first, so a projection that started dropping or inventing a
    // member says which one rather than printing two catalogues.
    assertEqual(Object.keys(contentOf(doc)).sort().join(","), Object.keys(indexContent(doc)).sort().join(","),
      "the signer and build-index project a catalogue onto different members");
    assertEqual(stableStringify(contentOf(doc)), stableStringify(indexContent(doc)),
      "the signer and build-index disagree about what a catalogue's content is");
    assert(!Object.hasOwn(contentOf(doc), "issued_at") && !Object.hasOwn(contentOf(doc), "expires_at"),
      "the publication stamps are content, so every run would look changed");
    assertEqual(contentOf(doc).serial, 7, "the serial is content");
  });

  // One valid tree, built the same way for both halves of seam 4, so the two
  // tests below cannot drift into asking about different trees.
  //
  // The name is a parameter because `makeTree` is a directory under `tmp` keyed
  // by it: two calls with one name reuse the tree, and the second `commit()`
  // has nothing to commit and throws. Watched — the split below went red with
  // "nothing to commit" in the one environment where both tests actually run
  // their bodies, which is the environment CI is.
  const gateOnAValidTree = async (name) => {
    const t = makeTree(name);
    t.addListing("dice-roller");
    t.commit("a listing");
    return catalogueGate({ root: t.dir, serial: 1, head: { present: false }, limit: 1048576 });
  };

  await test("a `NOT verified` note never decides anything, and the catalogue gate passes without a checkout", async () => {
    // Seam 4. `tools/validate.mjs` emits one note per cross-repository check it
    // could not run, and `build-index.yml` turns those into exit 1 — correctly,
    // because it HAS the checkout. The signer must never grow one: signing that
    // waits on another repository stops when that repository is unavailable,
    // which is the state a withdrawal is most likely to be needed in.
    //
    // Hermetic first, because the end-to-end half below can only see notes on a
    // machine that has no sibling AstraPlugins checkout.
    const verdict = gateVerdict({
      errors: [],
      notes: [
        { where: "policy/limits.json", message: "2 mirrored limit(s) NOT verified: no AstraPlugins checkout found" },
        { where: "bot/lib/assets.mjs", message: "icon formats NOT verified against AstraPlugins: no checkout found" },
      ],
    });
    assertEqual(verdict.ok, true, "a NOT verified note failed the catalogue gate");
    assertEqual(verdict.notes.length, 2, "the notes were dropped instead of recorded");
    assertEqual(gateVerdict({ errors: [{ where: "x", message: "y" }], notes: [] }).ok, false,
      "an error did not fail the gate, so the gate decides nothing at all");

    const gate = await gateOnAValidTree("gate-hermetic");
    assertEqual(gate.ok, true, `a valid tree failed the catalogue gate: ${gate.failures.join("; ")}`);
  });

  // Split out of the test above, where it was an `if (!existsSync(…))` around
  // the only assertion that reads the real environment.
  //
  // Inside that `if`, this check ran in CI and NEVER on a developer's machine,
  // and the test printed `ok` either way — so on every machine that has
  // AstraPlugins beside this repository, one of this suite's checks was a
  // silent no-op counted inside `300 passed`. Measured, not argued: a coverage
  // diff of the suite run with and against a sibling checkout differs in
  // exactly one span, and it is this one.
  //
  // It was described here as the MIRROR of C19 — that case provokable only WITH
  // a sibling, this one askable only WITHOUT one, and no environment asking
  // both. **Half of that is no longer true, and it was the half that could be
  // repaired** (gap 41). C19's fix is now asked of the resolver rather than
  // inferred from the resolver's surroundings: `astraPluginsCandidates()`
  // returns ONE directory when the override is set, and a length is the same
  // number on a developer's machine and in CI. See
  // `tools/selftest/couplings.mjs`'s ``C19 — `$ASTRA_PLUGINS_DIR` is an
  // override``. So the run you are reading asks both halves' subject matter;
  // what it cannot do is ask THIS one, here, with a checkout beside it.
  //
  // That part is irreducible and is not an oversight. `validateForSigning`
  // DELETES `$ASTRA_PLUGINS_DIR` on purpose — a signer that can be pointed at a
  // checkout is a signer that can be pointed at the wrong one — so the only way
  // the gate sees a `NOT verified` note is for there really to be no checkout.
  // With one present the premise is environmentally false, and `neverAsk` is
  // the honest word for that.
  //
  // What stands behind the second sentence below is no longer the sentence.
  // `checkAbsenceEnvironment` in tools/selftest.mjs derives, from
  // `.github/workflows/`, which live lanes reach this suite with nothing before
  // them naming an AstraPlugins checkout, prints the count beside the totals on
  // every run, and `checkAskedSomewhere` FAILS when it reaches zero — naming
  // this check, which it finds by its gate: a `neverAsk(` first in the block of
  // an `if` whose whole condition asks whether that path exists (gap 106). Keep
  // the gate written that way. A lane acquiring a sibling, or the last sibling-free lane
  // dropping the suite, is now a red build rather than this line quietly
  // becoming false.
  await test("with no sibling checkout the catalogue gate RECORDS the checks it could not run", async () => {
    const sibling = path.resolve(REPO_ROOT, "../AstraPlugins");
    if (fs.existsSync(sibling)) {
      neverAsk(
        `${sibling} exists, so tools/validate.mjs finds the checkout and emits no \`NOT verified\` note ` +
        "for this check to read",
        "a lane with no AstraPlugins beside the checkout asks it, and the runner prints how many of those " +
        "there are on the line under the totals — `node tools/selftest.mjs --lanes` names them, and the suite " +
        "goes red when that count reaches zero. To ask it here, move or rename the sibling checkout for one run",
      );
    }
    const gate = await gateOnAValidTree("gate-no-sibling");
    assert(gate.notes.some((n) => n.includes("NOT verified")),
      `with no AstraPlugins checkout the gate has to RECORD the checks it could not run: ${JSON.stringify(gate.notes)}`);
  });

  // ── D5: Pages, the arming flag and the latch ───────────────────────────────
  console.log("\nPages and the arming latch");

  await test("with no flag in history Pages gets main's unsigned list", () => {
    // Early arming is the failure this stops. The moment Pages serves a list
    // that verifies, every shipped 0.2.x daemon arms itself, and seven days
    // after its last accepted fetch a stale list blocks installs — before
    // ROLL-14's drill has run and before the owner has approved it.
    const t = makeTree("pages-unarmed");
    t.addListing("dice-roller");
    t.write("registry/v1/revocations.json", {
      $comment: "GENERATED FILE",
      signatures: [],
      signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] },
    });
    const sourceCommit = t.commit("a listing and the unsigned list");

    const arming = armingState({ root: t.dir, sourceCommit });
    assertEqual(arming.armed, false, "the latch closed with no flag in history");

    const head = headFrom({
      index: signIndex(fixtureCatalogue(2), { signer: signerFor(KEY_A) }),
      revocations: signRevocations(
        { signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
        { signer: signerFor(KEY_A) },
      ),
    });
    const { files, list_source } = pagesRegistryFiles({ root: t.dir, head, arming, sourceCommit });
    assertEqual(list_source, "main", "Pages took the signed list before the flag existed");
    const served = JSON.parse(files[SIGNED_FILES.revocations]);
    assertEqual(JSON.stringify(served.signatures), "[]",
      "Pages served a list carrying a signature before arming; every shipped client has now armed itself");
    assertEqual(files[SIGNED_FILES.index], head.bytes.index, "Pages did not get `signed`'s catalogue");
  });

  await test("the latch is the first commit that ADDED the flag, and deleting it does not reopen it", () => {
    // Arming is one-way in the field: a client that has seen a valid list does
    // not disarm. So a revert of the flag commit must change nothing here — if
    // it did, Pages would put an unsigned list back in front of armed clients
    // and they would block installs a week later, with a green build behind it.
    const t = makeTree("pages-latch");
    t.addListing("dice-roller");
    t.write("registry/v1/revocations.json", {
      signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] },
    });
    t.commit("a listing and the unsigned list");
    t.write("policy/pages-withdrawal-list.json", {
      schema: "astra.registry.pages-withdrawal-list/1",
      armed_at: "2026-09-20T10:00:00Z",
    });
    const latch = t.commit("arm the withdrawal list on Pages");
    fs.rmSync(path.join(t.dir, "policy", "pages-withdrawal-list.json"));
    const afterRevert = t.commit("revert the arming (this must change nothing)");

    const arming = armingState({ root: t.dir, sourceCommit: afterRevert });
    assertEqual(arming.armed, true, "deleting the flag reopened the latch");
    assertEqual(arming.latch_commit, latch, "the latch is not the commit that added the flag");
    assertEqual(arming.armed_at, "2026-09-20T10:00:00Z", "armed_at is read from the flag at the latch");
    assert(!fs.existsSync(path.join(t.dir, "policy", "pages-withdrawal-list.json")),
      "the fixture has to have the flag deleted, or this proves nothing");

    const head = headFrom({
      index: signIndex(fixtureCatalogue(2), { signer: signerFor(KEY_A) }),
      revocations: signRevocations(
        { signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
        { signer: signerFor(KEY_A) },
      ),
    });
    const { files, list_source } = pagesRegistryFiles({ root: t.dir, head, arming, sourceCommit: afterRevert });
    assertEqual(list_source, "signed", "Pages went back to main's unsigned list after a revert");
    assertEqual(files[SIGNED_FILES.revocations], head.bytes.revocations, "Pages' list is not `signed`'s bytes");

    // And the tree the job deploys: the documents go OVER the rendered site, so
    // a site that could not render cannot take them down with it (MOD-46).
    const { tree, overwritten } = pagesTree({
      site: { "index.html": "<!doctype html>", [SIGNED_FILES.index]: "a stale copy from the pages-site artifact" },
      registry: files,
    });
    assertEqual(tree[SIGNED_FILES.index], head.bytes.index, "a stale site artifact overwrote this run's catalogue");
    assertEqual(tree["index.html"], "<!doctype html>", "the site was dropped");
    assertEqual(overwritten.join(","), SIGNED_FILES.index, "the overlay did not report what it replaced");
  });
}
