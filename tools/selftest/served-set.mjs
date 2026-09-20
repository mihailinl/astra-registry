// The served-set canaries: SERVE-85, the list `main` implies against the one
// `signed` publishes (registry plan RC-R1-4). RC-R1-5 adds the Pages half,
// D5's latch and SERVE-90's provenance fallback to this module, beside them.
//
// Every rule in `tools/served-set/` decides whether a person is woken, and
// none of them will ever run anywhere but a scheduled job on GitHub against a
// branch and a CDN. So each is exercised here against a fixture tree, a
// fixture `signed` head, and each is watched failing by removing the guard it
// names. RC-R1-4's own canary is below by the name it is asked for by — a
// fixture clone with an advisory commit and no signer run, red after 30
// minutes.
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
import { GRACE_MINUTES, emit, finding, verdict } from "../served-set/report.mjs";
import { gather, serve85 } from "../served-set/main-vs-signed.mjs";
import { SILENT_JOB_CODE, UNRENDERABLE_CODE, composeVerdict } from "../served-set/compose.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

const KEY_A = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
const testKey = loadTestRoot(KEY_A);
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

const minutesAgo = (from, n) => new Date(Date.parse(from) + n * 60000).toISOString();
const codesOf = (v) => v.findings.map((f) => f.code).join(",");

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
}
