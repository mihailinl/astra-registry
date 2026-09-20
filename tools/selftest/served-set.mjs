// The served-set canaries: SERVE-85, SERVE-39's Pages half, D5's latch,
// SERVE-90's provenance fallback (registry plan RC-R1-4, RC-R1-5) and
// ROLL-45's trust.json runway (RC-R1-6's one live row).
//
// Every rule in `tools/served-set/` decides whether a person is woken, and
// none of them will ever run anywhere but a scheduled job on GitHub against a
// branch and a CDN. So each is exercised here against a fixture tree, a
// fixture `signed` head and a fixture deployment, and each is watched failing
// by removing the guard it names. The canaries RC-R1-4 and RC-R1-5 ask for are
// below by the names they are asked for by — a hand-pushed commit copying a
// real run's trailers, a Pages copy held back 31 minutes, a signed list before
// the flag, an unsigned list after a flag that was deleted, and a queued run
// that must raise nothing.
//
// One of these tests is not in either task's list and is the reason this
// module found a hole rather than only covering one: *the 30 minutes run from
// the commit under `tools/revocations/`, not from main's head*. SERVE-85's own
// words are "more than 30 minutes after that `main` commit", and read as main's
// HEAD commit that window is reset by every unrelated commit on a busy
// afternoon — so the dropped advisory the requirement exists for stays inside
// the window for ever.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { REVOCATIONS_SCHEMA, TRUST_SCHEMA } from "../../bot/lib/sign.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { signRevocations } from "../sign-revocations.mjs";
import { armingState } from "../signer/pages.mjs";
import { SIGNED_FILES } from "../signer/plan.mjs";
import { GRACE_MINUTES, emit, finding, verdict } from "../served-set/report.mjs";
import { gather, serve85 } from "../served-set/main-vs-signed.mjs";
import { serve39 } from "../served-set/served-vs-signed.mjs";
import {
  PROVENANCE_WINDOW_DAYS, parseRunUrl, provenance, receiptName, signedCommits, trailersOf,
} from "../served-set/provenance.mjs";
import { SILENT_JOB_CODE, UNRENDERABLE_CODE, composeVerdict, jobsFromEnv } from "../served-set/compose.mjs";
import { RUNWAY_DAYS, runwayVerdict } from "../served-set/runway.mjs";
import { JOBS } from "../served-set/check.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

const KEY_A = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
const testKey = loadTestRoot(KEY_A);
const signerFor = () => ({ key_id: KEY_A, privateKey: testKey.privateKey, public_key: testKey.publicKeyB64 });

const trustDelegating = () => ({
  signatures: [],
  signed: {
    schema: TRUST_SCHEMA,
    serial: 1,
    issued_at: "2026-09-01T00:00:00Z",
    expires_at: "2027-09-01T00:00:00Z",
    index_keys: [{ key_id: KEY_A, public_key: testKey.publicKeyB64 }],
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

/** A throwaway registry tree with real git history: D3 counts commits, D5 reads them. */
function makeTree(name) {
  const dir = path.join(tmp, `served-set-${name}`);
  fs.mkdirSync(dir, { recursive: true });
  const git = (...a) =>
    execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
  git("init", "-q", "-b", "main");
  git("config", "user.email", "served-set-fixture@example.invalid");
  git("config", "user.name", "served-set fixture");
  git("config", "commit.gpgsign", "false");
  const write = (rel, value) => {
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof value === "string" ? value : stableStringify(value));
  };
  // `at` is not decoration: D3 counts commits and SERVE-85's window is
  // measured from one of them, so a fixture whose commits are all "now" can
  // only ever test the inside of the window.
  const commit = (message, { at } = {}) => {
    git("add", "-A");
    execFileSync("git", ["-C", dir, "commit", "-qm", message], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: at ? { ...process.env, GIT_AUTHOR_DATE: at, GIT_COMMITTER_DATE: at } : process.env,
    });
    return git("rev-parse", "HEAD");
  };
  return { dir, git, write, commit, head: () => git("rev-parse", "HEAD") };
}

/** A `signed` head, in the shape `fetchSignedHead` returns. */
function headFrom({ revocations, trust = trustDelegating(), index = { signed: { schema: "x" } }, root = { schema: "astra.registry.root/1" }, sha = "a".repeat(40) }) {
  const bytes = {};
  const documents = {};
  for (const [name, doc] of Object.entries({ index, revocations, trust, root })) {
    bytes[name] = stableStringify(doc);
    documents[name] = JSON.parse(bytes[name]);
  }
  return { present: true, reason: null, sha, bytes, documents, parseErrors: [] };
}

/** A deployment that serves exactly what `signed`'s head holds. */
const servedFrom = (head, overrides = {}) => {
  const served = {};
  for (const name of Object.keys(SIGNED_FILES)) {
    served[name] = { ok: true, url: `https://example.invalid/${name}`, status: 200, body: head.bytes[name], error: null };
  }
  return { ...served, ...overrides };
};

const minutesAgo = (from, n) => new Date(Date.parse(from) + n * 60000).toISOString();
const codesOf = (v) => v.findings.map((f) => f.code).join(",");

const HEAD_CLOCK = "2026-09-19T12:00:00Z";
const REPO = "mihailinl/astra-registry";

const signerRun = (overrides = {}) => ({
  ok: true,
  path: ".github/workflows/sign.yml",
  head_branch: "main",
  event: "schedule",
  head_sha: "b".repeat(40),
  artifacts: [],
  ...overrides,
});

export async function run() {
  // ── the grammar the alarm channel will carry ───────────────────────────────
  console.log("\nthe served-set report, and what the channel will carry");

  await test("a code the alarm channel would refuse is refused here, not in the alert job", () => {
    // The failure this stands for: a lower-case or over-long code reaches
    // `bot/lib/alert-verdict.mjs`, which refuses the WHOLE verdict, so
    // `bot/alert.mjs` exits non-zero and the alarm about a real drift is never
    // sent. The run goes red where nobody is looking and the heartbeat never
    // posts, because the alarm step failed before it. Caught here it is a red
    // CI run with its author standing in front of it.
    let threw = null;
    try {
      finding("serve_85_drift", "a code the channel will not carry");
    } catch (e) {
      threw = e.message;
    }
    assert(threw !== null && threw.includes("alarm channel"), `a refused code was accepted: ${threw}`);
    assertEqual(finding("SERVE_85_DRIFT", "x").code, "SERVE_85_DRIFT", "a real code was refused");
  });

  await test("emit writes the three outputs the alert job reads, and nothing else", () => {
    const out = path.join(tmp, "served-set-outputs");
    fs.writeFileSync(out, "");
    const v = verdict({
      findings: [finding("SERVE_85_SERIAL_DRIFT", "x"), finding("SERVE_85_SERIAL_DRIFT", "again")],
      hexes: ["c".repeat(40)],
    });
    emit(v, { out, log: { log() {}, error() {} } });
    const written = fs.readFileSync(out, "utf8");
    assertEqual(written, `status=red\ncodes=SERVE_85_SERIAL_DRIFT\nhexes=${"c".repeat(40)}\n`,
      "the alert job reads these three by name; a fourth line or a duplicated code is a verdict it cannot build");
  });

  await test("a hex that is not a commit sha never reaches a verdict", () => {
    // The channel takes 16, 40 and 64 hex characters, so a 12-character one is
    // refused there — in the alert job, after the drift was found.
    let threw = null;
    try {
      verdict({ hexes: ["abc123"] });
    } catch (e) {
      threw = e.message;
    }
    assert(threw !== null, "a short hex was accepted into a verdict");
  });

  // ── SERVE-85 ───────────────────────────────────────────────────────────────
  console.log("\nSERVE-85: the list on `main` against the list on `signed`");

  await test("an advisory main carries and `signed` never published goes red at 31 minutes, not at 29", () => {
    // RC-R1-4's canary, on a real tree: an advisory commit and no signer run.
    const t = makeTree("advisory-drift");
    t.write("tools/revocations/README.md", "fixtures\n");
    t.commit("a revocations directory", { at: "2026-09-19T09:00:00Z" });
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory nobody signed", { at: "2026-09-19T11:00:00Z" });

    const facts = gather({ root: t.dir });
    assertEqual(facts.generated.serial, 3, "D3's formula: two commits under tools/revocations, plus one");
    assertEqual(facts.generated.revocations.length, 1, "the advisory is in the generated list");

    // `signed` is still on the commit before the advisory.
    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 2, revocations: [] } },
    });

    const early = serve85({ ...facts, head, now: minutesAgo(facts.listClock, 29) });
    assertEqual(early.status, "green", `the signer has ${GRACE_MINUTES} minutes: ${codesOf(early)}`);

    const late = serve85({ ...facts, head, now: minutesAgo(facts.listClock, 31) });
    assertEqual(codesOf(late), "SERVE_85_SERIAL_DRIFT", "an unpublished advisory went unreported");
    assert(late.findings[0].message.includes("SERVE-44"),
      "the message has to name the failure it stands for: a pending run replaced, and the advisory dropped");
  });

  await test("the 30 minutes run from the commit under tools/revocations/, not from main's head", () => {
    // Not in RC-R1-4's list, and the reason this module exists in this shape.
    //
    // SERVE-85 says "more than 30 minutes after that `main` commit". Read as
    // main's HEAD commit, the window is reset by every unrelated commit — a
    // publication, a listing edit, a README fix — so on a `main` that takes a
    // commit every twenty minutes the dropped advisory is inside the window
    // continuously and this check never fires. Measured from the commit that
    // raised the serial, which is by construction the last thing that could
    // have changed it, an unrelated commit moves nothing.
    const t = makeTree("busy-main");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory, three hours ago", { at: "2026-09-19T09:00:00Z" });
    t.write("plugins/dice-roller/plugin.json", { schema: "astra.registry.plugin/1", id: "dice-roller" });
    t.commit("a publication, one minute ago", { at: "2026-09-19T11:59:00Z" });

    const facts = gather({ root: t.dir });
    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
    });
    const v = serve85({ ...facts, head, now: "2026-09-19T12:00:00Z" });
    assertEqual(codesOf(v), "SERVE_85_SERIAL_DRIFT",
      "a publication one minute old excused a withdrawal three hours old; SERVE-85's own clock does that");
  });

  await test("a `signed` ahead of the commit this job read is the system working, not drift", () => {
    // This job reads one tree — the commit it checked out — and the signer
    // reads `main` as it is when it runs. A signer that publishes a newer
    // `main` while this run is in flight leaves a higher serial on `signed`,
    // and reporting that as drift would page on every busy afternoon.
    const t = makeTree("signer-ahead");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory", { at: "2026-09-19T09:00:00Z" });
    const facts = gather({ root: t.dir });
    const head = headFrom({
      revocations: {
        signatures: [],
        signed: { schema: REVOCATIONS_SCHEMA, serial: facts.generated.serial + 1, revocations: [] },
      },
    });
    const v = serve85({ ...facts, head, now: "2026-09-19T23:00:00Z" });
    assertEqual(v.status, "green", `a signer ahead of this checkout paged: ${codesOf(v)}`);
    assert(v.notes.some((n) => n.includes("the system working")), "the reason is not in the transcript");
  });

  await test("entries that differ at one serial are drift, because an equal serial has to mean an equal list", () => {
    const t = makeTree("entry-drift");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory", { at: "2026-09-19T09:00:00Z" });
    const facts = gather({ root: t.dir });
    const head = headFrom({
      revocations: {
        signatures: [],
        signed: { schema: REVOCATIONS_SCHEMA, serial: facts.generated.serial, revocations: [] },
      },
    });
    const v = serve85({ ...facts, head, now: "2026-09-19T23:00:00Z" });
    assertEqual(codesOf(v), "SERVE_85_ENTRY_DRIFT", "an emptied list at the same serial was accepted");
  });

  await test("no `signed` branch is a stated wait until sign.yml exists, and a failure the moment it does", () => {
    // attack B-1's finding, one task along: a check that paged every fifteen
    // minutes through the whole of R1 about a branch nothing had yet been
    // written to create would be switched off by the third night, and R1 is
    // the step whose exit arms every shipped client's 7-day block. The wait is
    // keyed on a file in the same tree, so it retires itself.
    const t = makeTree("no-branch");
    t.write("tools/revocations/README.md", "fixtures\n");
    t.commit("a tree", { at: "2026-09-19T09:00:00Z" });
    const facts = gather({ root: t.dir });
    const absent = { present: false, reason: "no origin/signed", sha: null, bytes: {}, documents: {} };

    const waiting = serve85({ ...facts, head: absent, signerWorkflowPresent: false, now: "2026-09-19T23:00:00Z" });
    assertEqual(waiting.status, "green", "a branch nothing could have created was paged about");
    assertEqual(waiting.waiting.length, 1, "the wait has to be stated, not silent");

    const armed = serve85({ ...facts, head: absent, signerWorkflowPresent: true, now: "2026-09-19T23:00:00Z" });
    assertEqual(codesOf(armed), "SERVE_85_NO_SIGNED_BRANCH",
      "sign.yml is on main and a missing `signed` was still treated as a wait");
  });

  // ── SERVE-39 and the latch ─────────────────────────────────────────────────
  console.log("\nSERVE-39: what Pages serves, and D5's arming latch");

  await test("a Pages copy held back 31 minutes fails, and at 29 it does not", () => {
    // RC-R1-5's canary, and the same shape answers "a run queued behind
    // another while `main` moves raises no alarm": the window is measured from
    // the `signed` commit, so a deployment that has not caught up with a
    // commit made five minutes ago is silent.
    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 2, revocations: [] } },
    });
    const stale = servedFrom(head, {
      index: { ok: true, url: "https://example.invalid/index", status: 200, body: "{\"old\":true}\n", error: null },
    });
    const args = { head, headClock: HEAD_CLOCK, served: stale, arming: { armed: false }, signerWorkflowPresent: true };

    const queued = serve39({ ...args, now: minutesAgo(HEAD_CLOCK, 5) });
    assertEqual(queued.status, "green", `a deploy five minutes behind paged: ${codesOf(queued)}`);

    const within = serve39({ ...args, now: minutesAgo(HEAD_CLOCK, 29) });
    assertEqual(within.status, "green", `a deploy 29 minutes behind paged: ${codesOf(within)}`);

    const over = serve39({ ...args, now: minutesAgo(HEAD_CLOCK, 31) });
    assertEqual(codesOf(over), "SERVE_39_DOCUMENT_DRIFT", "a split view between `signed` and the deployment");
  });

  await test("a withdrawal list that VERIFIES on Pages before the flag is early arming, with no grace at all", () => {
    // Every shipped 0.2.x daemon arms itself on the first list it can verify
    // and blocks installs seven days after its last accepted one. Arming is
    // one-way in the field, so there is nothing to wait thirty minutes for:
    // the clients that fetched in the last fifteen minutes have already armed.
    const signedList = signRevocations(
      { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 2, revocations: [] } },
      { signer: signerFor(), issuedAt: new Date(HEAD_CLOCK) },
    );
    const head = headFrom({ revocations: signedList });
    const v = serve39({
      head,
      headClock: HEAD_CLOCK,
      served: servedFrom(head),
      arming: { armed: false },
      signerWorkflowPresent: true,
      now: HEAD_CLOCK,
    });
    assertEqual(codesOf(v), "SERVE_39_EARLY_ARMING", "a verifiable list before the flag was served and not reported");
    assert(v.findings[0].message.includes(KEY_A), "the alarm has to name the key that would have armed a client");
  });

  await test("an unsigned list after a flag that was then DELETED still fails: the latch is history", () => {
    // Reading the current tree would let a revert of the flag commit put an
    // unsigned list back in front of clients that have already armed. They do
    // not disarm — they block installs a week later — and the person who
    // reverted sees a green build. `armingState` reads the history, and this
    // is the test that says so from the check's side.
    const t = makeTree("flag-reverted");
    t.write("policy/pages-withdrawal-list.json", { schema: "astra.registry.pages-withdrawal-list/1", armed_at: HEAD_CLOCK });
    t.commit("arm Pages", { at: "2026-09-19T10:00:00Z" });
    fs.rmSync(path.join(t.dir, "policy/pages-withdrawal-list.json"));
    t.commit("revert the flag", { at: "2026-09-19T10:30:00Z" });

    const arming = armingState({ root: t.dir, sourceCommit: t.head() });
    assertEqual(arming.armed, true, "a deleted flag disarmed the latch; clients in the field do not disarm");

    const head = headFrom({
      revocations: signRevocations(
        { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 2, revocations: [] } },
        { signer: signerFor(), issuedAt: new Date(HEAD_CLOCK) },
      ),
    });
    const unsigned = servedFrom(head, {
      revocations: {
        ok: true,
        url: "https://example.invalid/revocations",
        status: 200,
        body: stableStringify({ signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 2, revocations: [] } }),
        error: null,
      },
    });
    const v = serve39({
      head, headClock: HEAD_CLOCK, served: unsigned, arming, signerWorkflowPresent: true,
      now: minutesAgo(HEAD_CLOCK, 31),
    });
    assertEqual(codesOf(v), "SERVE_39_DISARMING", "an unsigned list in front of armed clients was accepted");
  });

  await test("Pages that cannot be read at all is reported, not skipped", () => {
    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 2, revocations: [] } },
    });
    const down = servedFrom(head, {
      index: { ok: false, url: "https://example.invalid/index", status: 404, body: null, error: "HTTP 404" },
    });
    const v = serve39({
      head, headClock: HEAD_CLOCK, served: down, arming: { armed: false }, signerWorkflowPresent: true,
      now: minutesAgo(HEAD_CLOCK, 31),
    });
    assertEqual(codesOf(v), "SERVE_39_PAGES_UNREACHABLE", "a 404 read as `nothing differs`");
  });

  // ── SERVE-90 ───────────────────────────────────────────────────────────────
  console.log("\nSERVE-90: every `signed` commit shown to be a signer run's");

  const NOW = "2026-09-19T12:00:00Z";
  const commitOf = ({ sha, minutesOld = 10, run = "77", source = "b".repeat(40) }) => ({
    sha,
    committed_at: new Date(Date.parse(NOW) - minutesOld * 60000).toISOString(),
    trailers: {
      "Source-Commit": source,
      Run: `https://github.com/${REPO}/actions/runs/${run}`,
      Signer: "sign.yml",
    },
  });
  const ancestry = { reachableFromMain: () => true, descendsFrom: () => true };

  await test("a hand-pushed commit that copied a real run's trailers fails: the receipt names the other commit", () => {
    // RC-R1-5's first canary. Everything about the forged commit is real — the
    // trailers are a working run's, the documents can be lifted from the
    // branch's own history — and the one thing the forger cannot produce is an
    // artifact named after a commit they made after the run finished.
    const real = "1".repeat(40);
    const forged = "2".repeat(40);
    const runs = new Map([["77", signerRun({ artifacts: [receiptName(real)] })]]);

    const honest = provenance({ commits: [commitOf({ sha: real })], repo: REPO, runs, now: NOW, ...ancestry });
    assertEqual(honest.status, "green", `an honest commit was refused: ${codesOf(honest)}`);

    const v = provenance({ commits: [commitOf({ sha: forged })], repo: REPO, runs, now: NOW, ...ancestry });
    assertEqual(codesOf(v), "SERVE_90_NO_RECEIPT", "a commit citing somebody else's run was accepted");
  });

  await test("two `signed` commits citing one run fails, even when the older is outside the 7-day window", () => {
    // The duplicate check is over the WHOLE branch and the others are over the
    // window, and that difference is the check: a forged commit's cheapest
    // disguise is a run URL copied off a commit old enough that nothing
    // re-examines it.
    const old = commitOf({ sha: "3".repeat(40), minutesOld: (PROVENANCE_WINDOW_DAYS + 3) * 1440, run: "99" });
    const fresh = commitOf({ sha: "4".repeat(40), minutesOld: 5, run: "99" });
    const runs = new Map([["99", signerRun({ artifacts: [receiptName(fresh.sha), receiptName(old.sha)] })]]);
    const v = provenance({ commits: [fresh, old], repo: REPO, runs, now: NOW, ...ancestry });
    assert(codesOf(v).includes("SERVE_90_RUN_CITED_TWICE"),
      `one run made two commits and nothing said so: ${codesOf(v)}`);
  });

  await test("a run of another workflow, another branch or an event the signer never runs on is refused", () => {
    const sha = "5".repeat(40);
    const commits = [commitOf({ sha })];
    for (const [what, run] of [
      ["another workflow", signerRun({ path: ".github/workflows/build-index.yml", artifacts: [receiptName(sha)] })],
      ["another branch", signerRun({ head_branch: "wip", artifacts: [receiptName(sha)] })],
      ["a pull request", signerRun({ event: "pull_request", artifacts: [receiptName(sha)] })],
      ["a run that is gone", { ok: false, error: "HTTP 404" }],
    ]) {
      const v = provenance({ commits, repo: REPO, runs: new Map([["77", run]]), now: NOW, ...ancestry });
      assertEqual(codesOf(v), "SERVE_90_RUN_NOT_A_SIGNER_RUN", `${what} was accepted as a signer run`);
    }
  });

  await test("a Source-Commit the run could not have read, or that `main` cannot reach, is refused", () => {
    // The Source-Commit is deliberately NOT the run's own head here: the rule
    // is "equal to, or a descendant of", and a fixture where the two are equal
    // passes through the equality half and never reaches the predicate under
    // test. It did, in the first draft, and the test was green with
    // `descendsFrom` returning false.
    const sha = "6".repeat(40);
    const commits = [commitOf({ sha, source: "c".repeat(40) })];
    const runs = new Map([["77", signerRun({ artifacts: [receiptName(sha)] })]]);

    const notDescendant = provenance({
      commits, repo: REPO, runs, now: NOW,
      reachableFromMain: () => true,
      descendsFrom: () => false,
    });
    assertEqual(codesOf(notDescendant), "SERVE_90_SOURCE_COMMIT_NOT_DESCENDANT",
      "a tree the run could not have read was accepted as the tree it signed");

    const offMain = provenance({
      commits, repo: REPO, runs, now: NOW,
      reachableFromMain: () => false,
      descendsFrom: () => true,
    });
    assertEqual(codesOf(offMain), "SERVE_90_SOURCE_COMMIT_UNREACHABLE",
      "bytes signed over a tree that is not in public history were accepted");
  });

  await test("the head is checked however old it is, and older commits fall out of the window", () => {
    // Artifacts expire, so a receipt for last year's commit is gone and a
    // check demanding one would be permanently red about history nobody can
    // re-attest. The head is the exception because the head is what is served.
    const head = commitOf({ sha: "7".repeat(40), minutesOld: 400 * 1440, run: "70" });
    const older = commitOf({ sha: "8".repeat(40), minutesOld: 500 * 1440, run: "71" });
    const runs = new Map([["70", signerRun({ artifacts: [] })], ["71", signerRun({ artifacts: [] })]]);
    const v = provenance({ commits: [head, older], repo: REPO, runs, now: NOW, ...ancestry });
    assertEqual(codesOf(v), "SERVE_90_NO_RECEIPT", "the head's receipt was not required, or an old commit's was");
    assert(v.hexes.length === 1 && v.hexes[0] === head.sha, "the window let a commit outside it be examined");
  });

  await test("a run URL in another repository proves nothing, and a missing one is not a pass", () => {
    assertEqual(parseRunUrl("https://github.com/o/r/actions/runs/12")?.run_id, "12", "a plain run URL");
    assertEqual(parseRunUrl("https://evil.example/o/r/actions/runs/12"), null, "a run URL off github.com");
    // Everything about this commit is in order EXCEPT the repository its run
    // URL names: the receipt is there, the run is a signer run, the ancestry
    // holds. Written any other way the test passes for another reason — the
    // first draft put no run in the table at all, so deleting the repository
    // check left the commit failing on "the run could not be read", the code
    // came out identical, and the guard was covered by nothing. Watched
    // failing by deleting the check: green, 220 passed.
    const sha = "9".repeat(40);
    const foreign = commitOf({ sha, source: "c".repeat(40) });
    foreign.trailers.Run = "https://github.com/someone/else/actions/runs/77";
    const runs = new Map([["77", signerRun({ artifacts: [receiptName(sha)] })]]);
    const v = provenance({ commits: [foreign], repo: REPO, runs, now: NOW, ...ancestry });
    assertEqual(codesOf(v), "SERVE_90_RUN_NOT_A_SIGNER_RUN", "a fork's run was accepted as this repository's");
    assert(v.findings[0].message.includes("someone/else"),
      `the refusal has to name the repository that is not ours: ${v.findings[0].message}`);

    const bare = { sha, committed_at: NOW, trailers: {} };
    const none = provenance({ commits: [bare], repo: REPO, runs: new Map(), now: NOW, ...ancestry });
    assertEqual(codesOf(none), "SERVE_90_NO_RUN_TRAILER", "a commit that says nothing was read as saying it is fine");
  });

  await test("the trailers are read off a real commit, not only off a fixture object", () => {
    // Everything above hands `provenance` objects. This is the one test that
    // asks git, because a parse that is never run against a real commit
    // message is a parse that can be wrong in exactly one way — silently, by
    // returning no trailers, which reads as `SERVE_90_NO_RUN_TRAILER` about
    // every honest commit and gets switched off.
    const t = makeTree("trailers");
    t.write("registry/v1/revocations.json", { signed: {} });
    execFileSync("git", ["-C", t.dir, "add", "-A"], { stdio: "ignore" });
    execFileSync(
      "git",
      ["-C", t.dir, "commit", "-qm", "signed: the withdrawal list\n\nSource-Commit: " + "b".repeat(40) +
        "\nRun: https://github.com/" + REPO + "/actions/runs/4242\nSigner: sign.yml"],
      { stdio: "ignore", env: { ...process.env, GIT_AUTHOR_DATE: NOW, GIT_COMMITTER_DATE: NOW } },
    );
    const [commit] = signedCommits({ root: t.dir, ref: "HEAD" });
    assertEqual(commit.trailers["Source-Commit"], "b".repeat(40), "Source-Commit did not survive the parse");
    assertEqual(parseRunUrl(commit.trailers.Run)?.run_id, "4242", "the run URL did not survive the parse");
    assertEqual(trailersOf("Run: x\nRun: y").Run, "y", "the last occurrence wins; trailers live at the end");
  });

  // ── the one verdict ────────────────────────────────────────────────────────
  console.log("\nthe one alarm the two comparisons send");

  await test("a comparison that did not report is red, never silent", () => {
    // The failure: `main-vs-signed` crashes before writing its outputs, the
    // alert job reads two empty strings, and an empty string is
    // indistinguishable from "nothing to report" unless somebody decided
    // otherwise. This is that decision.
    const { verdict: v } = composeVerdict({
      check: "served-set",
      jobs: [
        { name: "main-vs-signed", result: "failure", status: "", codes: "", hexes: "" },
        { name: "served-vs-signed", result: "success", status: "green", codes: "", hexes: "" },
      ],
      run: null,
    });
    assertEqual(v.status, "red", "a job that never reported was read as a job with nothing to say");
    assert(v.codes.includes(SILENT_JOB_CODE("main-vs-signed")), `the silent job has to be named: ${v.codes}`);
  });

  await test("a finding the channel would refuse still gets an alarm out", () => {
    // The worst outcome is not a lost detail: it is an unsendable verdict, a
    // red alert job, and no heartbeat — because the alarm step fails before
    // the heartbeat step runs, so the receiver's path goes down with the
    // channel's for a reason that is nobody's fault but this file's.
    const { verdict: v } = composeVerdict({
      check: "served-set",
      jobs: [
        { name: "main-vs-signed", result: "success", status: "red", codes: "SERVE_85_SERIAL_DRIFT not-a-code", hexes: "zz" },
        { name: "served-vs-signed", result: "success", status: "green", codes: "", hexes: "" },
      ],
      run: null,
    });
    assertEqual(v.status, "red", "a red comparison went out green");
    assert(v.codes.includes("SERVE_85_SERIAL_DRIFT"), "the real finding was dropped with the bad one");
    assert(v.codes.includes(UNRENDERABLE_CODE), "the dropped finding left no trace in the message");
    assertEqual(v.hexes, undefined, "a hex the channel refuses was passed through");
  });

  await test("two green comparisons are one green verdict the drill would not send", () => {
    const { verdict: v, problems } = composeVerdict({
      check: "served-set",
      jobs: [
        { name: "main-vs-signed", result: "success", status: "green", codes: "", hexes: "" },
        { name: "served-vs-signed", result: "success", status: "green", codes: "", hexes: "" },
      ],
      run: "https://github.com/mihailinl/astra-registry/actions/runs/12",
    });
    assertEqual(problems.join("; "), "", "the channel refused a verdict this file built");
    assertEqual(v.status, "green", "two green comparisons paged");
    assertEqual(v.codes, undefined, "a green verdict carried codes");
  });

  // ── ROLL-45's runway ───────────────────────────────────────────────────────
  console.log("\nROLL-45: how much runway trust.json has left");

  // Its own clock, named apart from the SERVE-90 section's `NOW` above: these
  // fixtures measure months and that one measures minutes, and a shared
  // constant between two sections with different units is a constant somebody
  // eventually moves for one of them.
  const RUNWAY_NOW = "2026-09-19T12:00:00Z";
  const plusDays = (n) => new Date(Date.parse(RUNWAY_NOW) + n * 86400000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const trustExpiring = (when, keys = [{ key_id: "astra-index-2026a" }]) =>
    ({ signed: { schema: TRUST_SCHEMA, serial: 2, issued_at: "2026-08-19T11:00:49Z", expires_at: when, index_keys: keys } });

  await test("89 days of runway pages and 91 does not, so the ceremony is the alarm and not the outage", () => {
    // The whole value of this row is WHEN it fires. Renewal is a hand-run root
    // ceremony with a dress rehearsal in front of it (ROLL-45 fixes the
    // rehearsal at 2027-05-01 and the ceremony at 2027-06-15 for an expiry of
    // 2027-08-19), so an alarm that first speaks the week the document expires
    // is an alarm about an outage. Both sides of the boundary, because a
    // threshold asserted from one side is satisfied by a check that fires
    // always or never.
    const near = runwayVerdict({ documents: [{ where: "main", doc: trustExpiring(plusDays(RUNWAY_DAYS - 1)) }], now: RUNWAY_NOW });
    assertEqual(near.status, "red", `${RUNWAY_DAYS - 1} days of runway did not alarm`);
    assertEqual(codesOf(near), "ROLL_45_TRUST_EXPIRES_SOON", "the wrong code reached the channel");

    const far = runwayVerdict({ documents: [{ where: "main", doc: trustExpiring(plusDays(RUNWAY_DAYS + 1)) }], now: RUNWAY_NOW });
    assertEqual(far.status, "green", `${RUNWAY_DAYS + 1} days of runway alarmed, which is the shape of an alarm nobody reads`);
    assert(far.notes.join(" ").includes("days out"), "a green runway says nothing about how long is left");

    // And the document this repository actually carries, at the same clock the
    // job will use. A fixture-only threshold is a threshold nothing measures.
    const real = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, SIGNED_FILES.trust), "utf8"));
    const live = runwayVerdict({ documents: [{ where: `main:${SIGNED_FILES.trust}`, doc: real }], now: new Date().toISOString() });
    assertEqual(live.status, "green",
      `registry/v1/trust.json is inside ROLL-45's ${RUNWAY_DAYS}-day runway NOW: ${live.findings.map((f) => f.message).join("; ")}`);
  });

  await test("an index key's not_after is the same ceremony under another name, and is watched too", () => {
    // ROLL-45's renewal batches a `not_after` for `astra-index-2026a`, which
    // the key does not carry today. Without this the requirement's own commit
    // would silently narrow what is watched: the envelope would still say
    // 2027-08-19 while the key signing every catalogue under it went dead
    // months earlier, and nothing would have said so.
    const doc = trustExpiring(plusDays(400), [{ key_id: "astra-index-2026a", not_after: plusDays(30) }]);
    const v = runwayVerdict({ documents: [{ where: "main", doc }], now: RUNWAY_NOW });
    assertEqual(v.status, "red", "a key that lapses in 30 days passed because the envelope was far from expiry");
    assertEqual(codesOf(v), "ROLL_45_INDEX_KEY_EXPIRES_SOON", "the finding did not name the key's own window");
    assert(v.findings[0].message.includes("astra-index-2026a"), "the operator is not told which key");
  });

  await test("an expiry nothing can read is the fault, and an empty set is never a clean bill of health", () => {
    for (const [what, doc] of [
      ["no expires_at", trustExpiring(undefined)],
      ["a date that is not an instant", trustExpiring("soon")],
      ["no signed member", { signatures: [] }],
    ]) {
      const v = runwayVerdict({ documents: [{ where: "main", doc }], now: RUNWAY_NOW });
      assertEqual(v.status, "red", `${what} was read as a healthy runway`);
      assertEqual(codesOf(v), "ROLL_45_TRUST_UNREADABLE", `${what} reported the wrong code`);
    }
    // The floor ROLL-44 asks every set-enumerating check for: this rule is a
    // loop, and a loop over nothing is green.
    const empty = runwayVerdict({ documents: [], now: RUNWAY_NOW });
    assertEqual(empty.status, "red", "no trust document at all was reported as nothing to report");
    assertEqual(codesOf(empty), "ROLL_45_NO_TRUST_DOCUMENT", "an empty population reported the wrong code");
  });

  await test("every comparison job in served-set.yml is named to the alarm, wired to it, and one check.mjs can run", () => {
    // The third job is the reason this exists. `compose.mjs` reports a job
    // named in `ASTRA_SERVED_SET_JOBS` with no variables as one that did not
    // report, which is red — but the converse is silent: a job added to the
    // workflow and forgotten in that list, or in the alert job's `needs`,
    // contributes nothing to the verdict, and the alarm goes out GREEN while
    // one comparison is red in a tab nobody has open. Line-oriented, the way
    // bot/tests/workflows.test.mjs reads workflows, because this repository
    // has no YAML parser and this rule must run when a lockfile is being
    // argued about.
    const src = fs.readFileSync(path.join(REPO_ROOT, ".github/workflows/served-set.yml"), "utf8");
    const lines = src.split("\n");
    const at = lines.findIndex((l) => /^jobs:\s*$/.test(l));
    assert(at >= 0, "served-set.yml has no `jobs:` key, so every assertion below would be about an empty list");
    const jobNames = [];
    for (let i = at + 1; i < lines.length; i++) {
      if (/^\S/.test(lines[i])) break;
      const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(lines[i]);
      if (m) jobNames.push(m[1]);
    }
    assert(jobNames.length >= 3, `the walk found ${jobNames.length} job(s) in served-set.yml; it is broken, not smaller`);

    const declared = /ASTRA_SERVED_SET_JOBS:\s*(.+)/.exec(src)?.[1].trim().split(/\s+/) ?? [];
    const comparisons = jobNames.filter((n) => n !== "alert");
    assertEqual(comparisons.slice().sort().join(" "), declared.slice().sort().join(" "),
      "the jobs in served-set.yml and the jobs ASTRA_SERVED_SET_JOBS names are not the same set, so a comparison " +
      "either pages for nothing or reports into nothing");

    const needs = /^\s+needs:\s*\[(.+)\]\s*$/m.exec(src)?.[1].split(",").map((s) => s.trim()) ?? [];
    for (const name of declared) {
      assert(needs.includes(name), `the alert job does not wait for ${name}, so its result may not be read at all`);
      assert(Object.keys(JOBS).includes(name),
        `served-set.yml names a job \`${name}\` that tools/served-set/check.mjs cannot run`);
      const stem = name.toUpperCase().replaceAll("-", "_");
      for (const part of ["RESULT", "STATUS", "CODES", "HEXES"]) {
        assert(src.includes(`${stem}_${part}:`), `the alert job maps no ${stem}_${part}, so ${name} reports nothing`);
      }
    }

    // And the mapping the workflow writes is the one compose.mjs reads: the
    // two agree on the env-var spelling here rather than at 3 a.m.
    const env = { ASTRA_SERVED_SET_JOBS: declared.join(" ") };
    for (const name of declared) {
      const stem = name.toUpperCase().replaceAll("-", "_");
      env[`${stem}_RESULT`] = "success";
      env[`${stem}_STATUS`] = "green";
    }
    const jobs = jobsFromEnv(env);
    assertEqual(jobs.length, declared.length, "compose.mjs read a different number of jobs than the workflow declares");
    assertEqual(jobs.filter((j) => j.status === "green").length, declared.length,
      "compose.mjs could not find a status for every job the workflow declares; the env-var spellings differ");
  });
}
