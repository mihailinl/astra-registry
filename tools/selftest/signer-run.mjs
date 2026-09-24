// The signer's ACTS: what it writes, what it commits, what it pushes, and the
// one refusal that stops all three.
//
// `signer.mjs` next door tests the decisions — D3's serials, D4's gates and
// cadence, SERVE-30's windows, D5's latch. This module tests
// `tools/signer/run.mjs`, which is the only file under `tools/signer/` that
// does anything: it holds the index key for the length of one function, writes
// the four documents, makes the `signed` commit and pushes it.
//
// **Why any of this is a test rather than a first run.** Every rule here runs,
// for real, in a job with `contents: write` and the production index key,
// against a branch every Astra installation reads, with no way to take a
// commit back. So each one is exercised against a throwaway git tree and the
// committed TEST keys, and each is watched failing by removing the guard it
// names.
//
// ── SERVE-95's caller, which is what this module was written for ───────────
//
// `refusesDroppedKey` has been in `tools/signer/key-window.mjs` since RC-R1-1
// with **no caller**: a correct invariant, tested in isolation, wired to
// nothing. `dev/couplings.md` gap 20 says the `publish` job is where it goes,
// and the first test below is what says it is there. The case it catches is
// the one nothing else in the run can see — a document the signer is about to
// re-commit BYTE FOR BYTE, correctly signed by a key that was trusted when the
// signature was made, beside a trust.json that does not delegate that key. The
// carry is perfect. The plan is satisfied. SERVE-91 refuses the whole commit at
// every client, withholding the three documents that were fine along with the
// one that was not.

import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fixtureEnv } from "../lib/git-env.mjs";

import { buildIndex } from "../build-index.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { signIndex } from "../../bot/sign-index.mjs";
import { signRevocations } from "../sign-revocations.mjs";
import { REVOCATIONS_SCHEMA, TRUST_SCHEMA } from "../../bot/lib/sign.mjs";
import { RETIREMENTS_PATH, RETIREMENTS_SCHEMA, WINDOW_EXEMPT_KEY_IDS } from "../signer/key-window.mjs";
import { SIGNED_FILES, planRun } from "../signer/plan.mjs";
import { trailersOf } from "../served-set/provenance.mjs";
import { buildSignedCommit, commitMessage, pushSigned, signRun, writeTree } from "../signer/run.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

const KEY_A = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
const KEY_B = "TEST-ONLY-DO-NOT-TRUST-index-2026b";
/**
 * The bootstrap key's ID over a TEST key's bytes.
 *
 * `WINDOW_EXEMPT_KEY_IDS` is the literal string `astra-index-2026a`, so the
 * one run that cannot be reproduced with a test key id is the one that matters
 * most — **the first**, which creates `signed`. Written out: with no `signed`
 * branch, no commit has delegated anything, so every key's window reads as
 * having started this instant, so the catalogue may not be signed, so there is
 * nothing to carry, so the run is BLOCKED and the branch is never created.
 * Only the exemption breaks that, and it is keyed on the id. So the first-run
 * test below borrows the production ID and signs with a test key's bytes, the
 * way `signer.mjs` does for the same reason.
 */
const BOOTSTRAP = "astra-index-2026a";
const testKeys = { [KEY_A]: loadTestRoot(KEY_A), [KEY_B]: loadTestRoot(KEY_B), [BOOTSTRAP]: loadTestRoot(KEY_A) };

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

const ROOT_DOC = { schema: "astra.registry.root/1", roots: [] };

const listing = (id) => ({
  schema: "astra.registry.plugin/1",
  id,
  name: id.replace(/-/g, " "),
  summary: "A listing that exists so the catalogue is not empty.",
  license: "MIT",
  source: { kind: "github", repo: `someone/${id}` },
  added_at: "2026-08-10",
});

const release = (id) => ({
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
      sha256: "a".repeat(64),
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

/**
 * A throwaway registry with real git history, holding what the signer reads at
 * the Source-Commit: `plugins/**`, `tools/revocations/**`, and the trust.json
 * and root.json that D2 copies byte for byte.
 */
function makeTree(name, { trustKeys = [KEY_A] } = {}) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  const git = (...a) =>
    execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: fixtureEnv(dir) }).trimEnd();
  git("init", "-q", "-b", "main");
  git("config", "user.email", "signer-run-fixture@example.invalid");
  git("config", "user.name", "signer run fixture");
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
  const addListing = (id) => {
    write(`plugins/${id}/plugin.json`, listing(id));
    write(`plugins/${id}/versions/1.0.0.json`, release(id));
  };
  write(SIGNED_FILES.trust, trustDelegating(trustKeys));
  write(SIGNED_FILES.root, ROOT_DOC);
  return { dir, git, write, commit, addListing, head: () => git("rev-parse", "HEAD") };
}

/** A `signed` head as `fetchSignedHead` returns one: bytes and parsed copies agreeing. */
function headFrom({ index, revocations, trust, sha = "0".repeat(40) }) {
  const bytes = {};
  const documents = {};
  for (const [name, doc] of Object.entries({ index, revocations, trust, root: ROOT_DOC })) {
    bytes[name] = stableStringify(doc);
    documents[name] = JSON.parse(bytes[name]);
  }
  return { present: true, reason: null, sha, ref: "refs/astra-signer/signed", bytes, documents, parseErrors: [] };
}

export async function run() {
  console.log("\nthe signer's acts");

  await test("a document that does not verify against the trust.json beside it stops the whole commit", async () => {
    // SERVE-95, and the closure of `dev/couplings.md` gap 20.
    //
    // The shape, and every part of it is ordinary:
    //
    //   * `signed`'s head carries a withdrawal list signed by a key its own
    //     trust.json does not delegate. However that happened — a hand push, a
    //     rotation applied in the wrong order, a bug in a run nobody watched —
    //     it is a fact about the branch now;
    //   * the list has not changed and is not yet 20 hours old, so D4's answer
    //     is `unchanged`: re-commit the head's exact bytes;
    //   * the catalogue HAS changed, so the run commits.
    //
    // Nothing in the plan objects. The carry is byte-perfect, the signature is
    // a real signature, and the commit is well formed. It is only wrong
    // relative to the file beside it, and SERVE-91 refuses all four documents
    // at every client on that basis — withholding the catalogue this run was
    // published for.
    const t = makeTree("serve95");
    t.addListing("dice-roller");
    const first = t.commit("a listing, the trust document and the root document");

    const headList = signRevocations(
      { signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
      // KEY_B, which the trust.json below does NOT delegate.
      { signer: signerFor(KEY_B), issuedAt: new Date("2026-09-19T00:00:00Z") },
    );
    const headIndex = signIndex(buildIndex({ root: t.dir, serial: 1 }), {
      signer: signerFor(KEY_A), issuedAt: new Date("2026-09-19T00:00:00Z"),
    });
    const head = headFrom({ index: headIndex, revocations: headList, trust: trustDelegating([KEY_A]), sha: first });

    t.addListing("second-plugin");
    const sourceCommit = t.commit("a second listing");
    const now = "2026-09-19T01:00:00Z";

    // The fixture has to be able to produce the bad commit, or the refusal
    // below is asserting something that cannot happen. This is the run as the
    // PLAN sees it, with no key and no verification: it commits.
    const plan = await planRun({ root: t.dir, sourceCommit, head, now });
    assertEqual(plan.documents.revocations.decision, "unchanged", "the fixture's list is not the carried-forward one");
    assertEqual(plan.documents.index.decision, "changed", "the fixture's catalogue did not change");
    assertEqual(plan.refusals.join("; "), "", "the plan already refused, so the refusal below proves nothing");
    assertEqual(plan.commit, true, "the plan would not have committed, so there is nothing for SERVE-95 to stop");

    // And the run, which asks.
    const record = await signRun({
      root: t.dir, sourceCommit, head, now,
      available: [signerFor(KEY_A)],
      delegatedAt: new Map([[KEY_A, "2026-09-01T00:00:00Z"]]),
    });
    assertEqual(record.key_mode, "normal",
      "compromise mode would refuse this carry for a different reason, and the test would pass without a caller");
    assertEqual(record.commit, false, "the run committed a document the trust.json beside it cannot verify");
    assertEqual(record.codes.includes("SIGNER_TRUST_REFUSED_DOCUMENT"), true,
      `the refusal is not reported as SERVE-95's: ${record.codes.join(" ")}`);
    assertEqual(record.refusals.length, 1, `one refusal, one document: ${record.refusals.join(" | ")}`);
    assert(record.refusals[0].includes(SIGNED_FILES.revocations) && record.refusals[0].includes("SERVE-95"),
      `the refusal has to name the document and the rule: ${record.refusals[0]}`);
    assertEqual(record.status, "red", "a run that publishes nothing reported green");
  });

  await test("a commit holds all four documents, and trust.json and root.json are the Source-Commit's bytes", async () => {
    // D2 and TRUST-3. The two documents the signer does NOT produce are copied
    // out of the tree it signed over, never regenerated and never re-signed:
    // this job holds no root key, and a trust.json assembled here would be a
    // trust.json the root ceremony did not make.
    //
    // This is also the FIRST run — no head, no branch — and it is run with the
    // bootstrap key id for the reason given at BOOTSTRAP above: without the
    // exemption the run that creates `signed` is the one run that cannot
    // succeed.
    const t = makeTree("four-documents", { trustKeys: [BOOTSTRAP] });
    t.addListing("dice-roller");
    const sourceCommit = t.commit("a listing");
    assertEqual(WINDOW_EXEMPT_KEY_IDS.join(","), BOOTSTRAP,
      "the exempt set is not the bootstrap key alone, so the first run below is testing something else");
    const record = await signRun({
      root: t.dir, sourceCommit, head: { present: false }, now: "2026-09-19T00:00:00Z",
      available: [signerFor(BOOTSTRAP)],
    });
    assertEqual(record.refusals.join("; "), "", "the first run refused");
    assertEqual(record.commit, true, "the first run, which creates `signed`, decided to commit nothing");
    assertEqual(Object.keys(record.files).sort().join(" "), Object.values(SIGNED_FILES).sort().join(" "),
      "a `signed` commit holds exactly four files");

    for (const name of ["trust", "root"]) {
      const onMain = fs.readFileSync(path.join(t.dir, SIGNED_FILES[name]), "utf8");
      assertEqual(record.files[SIGNED_FILES[name]], onMain, `${SIGNED_FILES[name]} is not main's bytes`);
    }
    assertEqual(record.index_source_commit, sourceCommit, "a freshly generated catalogue's Index-Source-Commit");

    // And `writeTree` puts them on disk untouched. A carry is byte-for-byte or
    // it is a new document whose signature was made over other bytes, so a
    // helpful re-serialise here would break exactly the path that only runs
    // when something has already gone wrong.
    const out = path.join(tmp, "four-documents-out");
    writeTree({ out, files: record.files });
    for (const [rel, bytes] of Object.entries(record.files)) {
      const back = fs.readFileSync(path.join(out, rel), "utf8");
      assertEqual(back.length, bytes.length, `${rel} changed length on the way to disk`);
      assertEqual(back, bytes, `${rel} did not round-trip`);
      assert(back.endsWith("}\n"), `${rel} lost its trailing newline`);
    }
  });

  await test("a catalogue no key may sign yet is carried, and the withdrawal list still publishes", async () => {
    // SERVE-30's seven hours, inside a real run. The incoming key may sign the
    // LIST from the delegating commit — that is what carries it into
    // circulation — and may not sign the catalogue until clients have had time
    // to fetch the trust.json that delegates it. With no other key in the
    // environment the catalogue therefore cannot be signed at all this run, and
    // the answer is a carry with an alert, never a silent drop and never a
    // blocked run that holds the withdrawal back too.
    const t = makeTree("window-carry", { trustKeys: [KEY_B] });
    t.addListing("dice-roller");
    const first = t.commit("a listing");

    const headIndex = signIndex(buildIndex({ root: t.dir, serial: 1 }), {
      signer: signerFor(KEY_B), issuedAt: new Date("2026-09-19T00:00:00Z"),
    });
    const headList = signRevocations(
      { signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
      { signer: signerFor(KEY_B), issuedAt: new Date("2026-09-19T00:00:00Z") },
    );
    const head = headFrom({ index: headIndex, revocations: headList, trust: trustDelegating([KEY_B]), sha: first });

    t.addListing("second-plugin");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    const sourceCommit = t.commit("a second listing and an advisory");

    const record = await signRun({
      root: t.dir, sourceCommit, head, now: "2026-09-19T02:00:00Z",
      available: [signerFor(KEY_B)],
      // Delegated two hours ago: inside the seven.
      delegatedAt: new Map([[KEY_B, "2026-09-19T00:00:00Z"]]),
    });
    assertEqual(record.documents.index.decision, "carry", "the catalogue was signed inside the key's window");
    assertEqual(record.files[SIGNED_FILES.index], head.bytes.index, "the carry is not byte-for-byte the head's");
    assertEqual(record.documents.revocations.decision, "changed", "the withdrawal list waited for the catalogue");
    assertEqual(record.commit, true, "the run refused to publish the withdrawal");
    assertEqual(record.codes.includes("SIGNER_CARRIED_INDEX"), true, `${record.codes.join(" ")}`);
    assertEqual(record.codes.includes("SIGNER_NO_INDEX_KEY"), true, `${record.codes.join(" ")}`);
    assertEqual(record.alerts.length, 1, `every carry alerts: ${record.alerts.join(" | ")}`);
    assert(record.alerts[0].includes("after 7 h"), `the alert has to say when the refusal lifts: ${record.alerts[0]}`);
    assertEqual(record.status, "red", "a carry reported green");

    // D4: the carried catalogue keeps the Index-Source-Commit it was published
    // with. Here there is no head trailer to read, so it stays this run's — the
    // case that matters is the one below, in the commit message.
    assertEqual(typeof record.index_source_commit, "string", "no Index-Source-Commit at all");
  });

  await test("R9b's retirement on a red day carries the catalogue and publishes the list, and only the committed record makes it one", async () => {
    // D10, decided 2026-09-23 (contract 0.38.0): SERVE-30's overlap is for a
    // planned retirement, and a compromise drops the key and re-signs at once.
    // The day that turns on it is R9b's: the trust.json that ends the overlap
    // drops the outgoing key, and the catalogue's gates happen to fail. Read as
    // a compromise, the catalogue may not be carried, the run is blocked, and
    // a blocked run commits NOTHING — the withdrawal list included (D2). Read
    // as the retirement it is, the dual-signed catalogue is carried, it
    // verifies under the new trust.json (SERVE-95 asks, in this run), and the
    // list publishes.
    //
    // Three runs over one tree, each through `signRun`, which is the only
    // reader of the record: with no record; with the record in the WORKING
    // TREE only, which a run must not read; and with it committed.
    const t = makeTree("retirement-red-day", { trustKeys: [KEY_A, KEY_B] });
    t.addListing("dice-roller");
    const first = t.commit("a listing, both keys delegated");
    const issuedAt = new Date("2026-09-18T00:00:00Z");
    const both = [signerFor(KEY_A), signerFor(KEY_B)];
    const catalogue = buildIndex({ root: t.dir, serial: 1 });
    const headIndex = signIndex(catalogue, { signers: both, issuedAt });
    const headList = signRevocations(
      { signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } }, { signers: both, issuedAt },
    );
    const head = headFrom({ index: headIndex, revocations: headList, trust: trustDelegating([KEY_A, KEY_B]), sha: first });

    // The root ceremony that ends the overlap, a listing that makes the
    // catalogue's gate fail, and an advisory so the list has changed.
    t.write(SIGNED_FILES.trust, trustDelegating([KEY_B], 2));
    t.write("plugins/broken/plugin.json", "{ this is not JSON");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    const unrecorded = t.commit("R9b: the outgoing key retired, on a day a listing is broken");
    const run = (sourceCommit) => signRun({
      root: t.dir, sourceCommit, head, now: "2026-09-19T00:00:00Z",
      available: [signerFor(KEY_B)],
      delegatedAt: new Map([[KEY_A, "2026-01-01T00:00:00Z"], [KEY_B, "2026-06-01T00:00:00Z"]]),
    });

    const record = { schema: RETIREMENTS_SCHEMA, retirements: [{ key_id: KEY_A, retired_from: "2026-09-18T12:00:00Z" }] };
    t.write(RETIREMENTS_PATH, record);
    const dirty = await run(unrecorded);
    assertEqual(dirty.key_mode, "compromise",
      "the record was read from the working tree; the run reads its inputs at the Source-Commit and nowhere else");
    assertEqual(dirty.documents.index.decision, "blocked", "a compromise carried a catalogue");
    assertEqual(dirty.commit, false, "the fixture's red catalogue did not block the compromise run");

    const retired = await run(t.commit("the retirement, recorded"));
    assertEqual(retired.key_mode, "retirement", "a recorded retirement read as a compromise");
    assertEqual(retired.documents.index.decision, "carry", "the red catalogue was not carried on the retirement day");
    assertEqual(retired.files[SIGNED_FILES.index], head.bytes.index, "the carry is not byte-for-byte the head's");
    assertEqual(retired.documents.revocations.decision, "changed", "the withdrawal list did not publish");
    assertEqual(retired.refusals.join(" | "), "",
      "the carried catalogue did not verify beside the trust.json that drops the outgoing key");
    assertEqual(retired.commit, true, "the retirement day committed nothing");

    // And the record cannot make an unsafe carry: a head catalogue signed by
    // the retired key ALONE is refused beside the new trust.json, record or not.
    const soloIndex = signIndex(catalogue, { signer: signerFor(KEY_A), issuedAt });
    const soloHead = headFrom({ index: soloIndex, revocations: headList, trust: trustDelegating([KEY_A, KEY_B]), sha: first });
    const solo = await signRun({
      root: t.dir, sourceCommit: t.head(), head: soloHead, now: "2026-09-19T00:00:00Z",
      available: [signerFor(KEY_B)],
      delegatedAt: new Map([[KEY_A, "2026-01-01T00:00:00Z"], [KEY_B, "2026-06-01T00:00:00Z"]]),
    });
    assertEqual(solo.key_mode, "retirement", "the solo-signed head changed the mode");
    assertEqual(solo.commit, false, "a record carried a catalogue the new trust.json cannot verify");
    assertEqual(solo.codes.includes("SIGNER_TRUST_REFUSED_DOCUMENT"), true,
      `the refusal is not SERVE-95's: ${solo.codes.join(" ")}`);
  });

  await test("the commit message carries D2's four trailers, and a carry keeps its Index-Source-Commit", async () => {
    // The trailers are not decoration: `tools/served-set/provenance.mjs` reads
    // `Run:` and `Source-Commit:` to decide whether a `signed` commit was made
    // by a signer run at all (SERVE-90), and `Index-Source-Commit` is what says
    // which tree a CARRIED catalogue was generated from. Parsed back with the
    // same reader that check uses, so a message this test accepts is a message
    // that check accepts.
    const source = "c".repeat(40);
    const carriedFrom = "d".repeat(40);
    const run = "https://github.com/mihailinl/astra-registry/actions/runs/123456";
    const record = {
      source_commit: source,
      index_source_commit: carriedFrom,
      serials: { index: 46, revocations: 3 },
      documents: { index: { decision: "carry", serial: 45 }, revocations: { decision: "changed", serial: 3 } },
      alerts: ["CARRY registry/v1/index.json: a listing does not validate."],
    };
    const trailers = trailersOf(commitMessage(record, run));
    assertEqual(trailers["Source-Commit"], source, "Source-Commit");
    assertEqual(trailers.Run, run, "Run");
    assertEqual(trailers.Signer, "sign.yml", "Signer");
    assertEqual(trailers["Index-Source-Commit"], carriedFrom,
      "a carried catalogue must keep the Source-Commit of the tree it was generated from, not take this run's");

    const fresh = { ...record, index_source_commit: source, documents: { index: { decision: "changed", serial: 46 }, revocations: { decision: "unchanged", serial: 3 } }, alerts: [] };
    assertEqual(trailersOf(commitMessage(fresh, run))["Index-Source-Commit"], source,
      "a freshly generated catalogue's Index-Source-Commit is this run's Source-Commit");
    assert(commitMessage(record, run).includes("CARRY registry/v1/index.json"),
      "the carry is not in the commit message, so `git log signed` cannot say why a document stopped moving");
  });

  await test("the first `signed` commit is an orphan, the next is its child, and neither touches the working tree", async () => {
    // Plumbing, and never `git checkout signed`. The working tree in the
    // publish job is `main` at the Source-Commit — the tree the documents were
    // generated from — and a job that switches branches to make a commit is a
    // job whose failure leaves a checkout of `signed` behind for whatever runs
    // next. It also gives the run that CREATES the branch the same code path as
    // every run after it.
    const t = makeTree("plumbing");
    t.addListing("dice-roller");
    t.commit("a listing");
    const before = t.git("rev-parse", "--abbrev-ref", "HEAD");
    const tracked = t.git("ls-files").split("\n").sort().join("\n");

    const files = { [SIGNED_FILES.index]: "{}\n", [SIGNED_FILES.revocations]: "{}\n", [SIGNED_FILES.trust]: "{}\n", [SIGNED_FILES.root]: "{}\n" };
    const first = buildSignedCommit({ root: t.dir, files, parent: null, message: "first\n\nSigner: sign.yml\n" });
    assertEqual(t.git("rev-list", "--count", first), "1", "the first `signed` commit has a parent");
    assertEqual(
      t.git("ls-tree", "-r", "--name-only", first).split("\n").sort().join(" "),
      Object.values(SIGNED_FILES).sort().join(" "),
      "the `signed` tree holds something other than the four documents",
    );

    const second = buildSignedCommit({
      root: t.dir, files: { ...files, [SIGNED_FILES.index]: '{"x":1}\n' }, parent: first, message: "second\n",
    });
    assertEqual(t.git("rev-parse", `${second}^`), first, "the second commit is not the first's child");

    assertEqual(t.git("rev-parse", "--abbrev-ref", "HEAD"), before, "the working tree changed branch");
    assertEqual(t.git("ls-files").split("\n").sort().join("\n"), tracked, "the working tree's index changed");
    assertEqual(t.git("status", "--porcelain"), "", "the working tree is dirty after making a commit in it");
    assert(!fs.existsSync(path.join(t.dir, ".git", "astra-signer-index")),
      "the signer's temporary index was left behind, so the next `git` call in this job reads it");
  });

  await test("the push is retried while the plan holds, and refused the moment `signed` has moved", async () => {
    // "Fast-forward only, retried after a fetch only while the plan still
    // holds" (RC-R1-2). The plan holds iff `signed`'s head is still the commit
    // this run planned against. If it is not, the documents in hand were
    // generated and signed against a head that is gone — pushing them would
    // either lose that commit or stack a document on a parent it was never
    // compared with, and TRUST-28's equal-serial rule and SERVE-36 are both
    // decided against that parent.
    const bare = path.join(tmp, "push-remote.git");
    execFileSync("git", ["init", "-q", "--bare", "-b", "main", bare], { env: fixtureEnv(bare) });
    const t = makeTree("push");
    t.addListing("dice-roller");
    t.commit("a listing");
    t.git("remote", "add", "origin", bare);
    t.git("push", "-q", "origin", "main");

    const files = { [SIGNED_FILES.index]: "{}\n", [SIGNED_FILES.revocations]: "{}\n", [SIGNED_FILES.trust]: "{}\n", [SIGNED_FILES.root]: "{}\n" };
    const first = buildSignedCommit({ root: t.dir, files, parent: null, message: "first\n" });
    const opening = pushSigned({ root: t.dir, sha: first, parent: null });
    assertEqual(opening.pushed, true, `the first push failed: ${opening.reason}`);
    assertEqual(opening.attempts, 1, "the opening push took more than one attempt");
    assertEqual(t.git("ls-remote", "origin", "refs/heads/signed").split("\t")[0], first, "`signed` is not at the new commit");

    // Somebody else moves `signed`. From this run's point of view that is a
    // second publisher, a run that overtook it, or a hand push; all three are
    // the same fact and the same answer.
    const overtaking = buildSignedCommit({
      root: t.dir, files: { ...files, [SIGNED_FILES.index]: '{"someone":"else"}\n' }, parent: first, message: "overtaking\n",
    });
    t.git("push", "-q", "origin", `${overtaking}:refs/heads/signed`);

    const mine = buildSignedCommit({
      root: t.dir, files: { ...files, [SIGNED_FILES.index]: '{"mine":true}\n' }, parent: first, message: "mine\n",
    });
    const refused = pushSigned({ root: t.dir, sha: mine, parent: first, attempts: 3 });
    assertEqual(refused.pushed, false, "a push whose parent is no longer the head succeeded, which means it was forced");
    assertEqual(refused.attempts, 1, "the run kept retrying a push whose plan had stopped holding");
    assertEqual(refused.head, overtaking, "the refusal does not say where `signed` actually is");
    assert(refused.reason.includes("no longer holds"), refused.reason);
    assertEqual(t.git("ls-remote", "origin", "refs/heads/signed").split("\t")[0], overtaking,
      "the other publisher's commit was overwritten");
  });

  await test("an equal-serial re-sign is the schedule's: a push or workflow_run run leaves it alone until 34 h, and the CLI reads the event", async () => {
    // ROLL-14's first condition is three CONSECUTIVE UNATTENDED re-signs, and
    // on 2026-09-24 four of the five re-signs `signed` had ever received were
    // fired by a `push`: a pull request merged minutes after the 20-hour mark
    // took the refresh from the schedule and reset the count (ops
    // notes/state.md, RC-R1-9(c)). The decision was blind to what started the
    // run. So this is asked through the command line `sign.yml` runs, with
    // `--event` as sign.yml passes it, and with GITHUB_EVENT_NAME set to
    // something else to show the flag, not the environment, decides: an event
    // that never reaches the plan is a rule that holds only in a unit test.
    const t = makeTree("event-cadence", { trustKeys: [BOOTSTRAP] });
    t.addListing("dice-roller");
    const sourceCommit = t.commit("a listing");
    const T0 = Date.parse("2026-09-20T00:00:00Z");
    const at = (hours) => new Date(T0 + hours * 3600 * 1000).toISOString().replace(/\.\d+Z$/, "Z");
    const opening = await signRun({
      root: t.dir, sourceCommit, head: { present: false }, now: at(0), available: [signerFor(BOOTSTRAP)],
    });
    assertEqual(opening.commit, true, "the opening run, which creates `signed`, committed nothing");
    const signedSha = buildSignedCommit({
      root: t.dir, files: opening.files, parent: null, message: commitMessage(opening, "https://example.invalid/runs/1"),
    });
    t.git("update-ref", "refs/heads/signed", signedSha);
    t.git("remote", "add", "origin", t.dir);

    const RUN = path.join(import.meta.dirname, "..", "signer", "run.mjs");
    const cli = (event, hours) => {
      const out = path.join(tmp, `event-cadence-${event ?? "none"}-${event === "" ? "empty-" : ""}${hours}`);
      const record = `${out}.json`;
      // Nothing of the job this suite runs in may reach the child: not its
      // GITHUB_OUTPUT (the child would append to the real step's outputs),
      // not its own event, and never a signing key (`--test-key` refuses one).
      const env = Object.fromEntries(Object.entries(fixtureEnv(t.dir)).filter(([k]) =>
        !k.startsWith("GITHUB_") && !k.startsWith("ASTRA_INDEX_SIGNING_KEY")));
      env.GITHUB_EVENT_NAME = "pull_request";
      const r = spawnSync(process.execPath, [
        RUN, "--step", "sign", "--root", t.dir, "--source-commit", sourceCommit, "--now", at(hours),
        ...(event === null ? [] : ["--event", event]),
        "--test-key", `${BOOTSTRAP}=${KEY_A}`, "--out", out, "--record", record,
      ], { env, encoding: "utf8" });
      return {
        status: r.status,
        said: `${r.stdout}${r.stderr}`,
        record: r.status === 0 ? JSON.parse(fs.readFileSync(record, "utf8")) : null,
      };
    };
    const expect = (event, hours, resigned) => {
      const r = cli(event, hours);
      const who = `${event ?? "a run with no --event"} at ${hours} h`;
      assertEqual(r.status, 0, `${who} exited ${r.status}: ${r.said}`);
      for (const name of ["index", "revocations"]) {
        assertEqual(r.record.documents[name].decision, resigned ? "resign" : "unchanged",
          `${who}: the ${name} decision`);
      }
      assertEqual(r.record.commit, resigned, `${who}: commit`);
    };
    expect("schedule", 20, true);
    expect("workflow_dispatch", 20, true);
    expect("push", 25, false);
    expect("workflow_run", 25, false);
    expect("push", 33, false);
    expect("push", 34, true);
    expect("workflow_run", 34, true);
    expect("schedule", 19, false);
    expect(null, 20, true);

    const odd = cli("pull_request", 25);
    assertEqual(odd.status, 2, `an event sign.yml does not list was planned anyway: ${odd.said}`);
    assert(odd.said.includes("pull_request") && odd.said.includes("RESIGN_HOURS_BY_EVENT"),
      `the refusal does not name the event: ${odd.said}`);
    const empty = cli("", 25);
    assertEqual(empty.status, 2, `an empty --event was planned as a shell run: ${empty.said}`);
  });
}
