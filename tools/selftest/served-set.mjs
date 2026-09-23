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
import { SIGNED_FILES, serialsAt } from "../signer/plan.mjs";
import { SERIAL_PATHSPEC } from "../lib/revocations.mjs";
import { GRACE_MINUTES, emit, finding, minutesSince, verdict } from "../served-set/report.mjs";
import { gather, serve85, sourceOf } from "../served-set/main-vs-signed.mjs";
import { serve39 } from "../served-set/served-vs-signed.mjs";
// PROVENANCE_WINDOW_DAYS is deliberately NOT imported. Both fixtures that used
// to compute an age from it could not see it move (2026-09-22: 7 → 1, nothing
// red anywhere in the suite), and they now write the window's two edges as
// literal hours either side of seven days. Importing it again is how this
// module stopped being able to test it.
import { parseRunUrl, provenance, receiptName, signedCommits, trailersOf } from "../served-set/provenance.mjs";
import { SILENT_JOB_CODE, UNRENDERABLE_CODE, composeVerdict, jobsFromEnv } from "../served-set/compose.mjs";
import { compose as composeCoverage } from "../coverage-verdict.mjs";
import { VERDICT_SCHEMA, verdictProblems } from "../../bot/lib/alert-verdict.mjs";
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
    // continuously and this check never fires. Measured from the oldest commit
    // under `tools/revocations/` that `signed` does not carry, an unrelated
    // commit moves nothing — and neither does a later advisory, which is the
    // test after the next.
    //
    // **Three commits and three clocks, because two could not tell the
    // pathspec apart.** This fixture used to hold exactly two — the advisory
    // under `tools/revocations/` and the publication under `plugins/` — and
    // measured 2026-09-22 that was not enough to aim it: LIST_PATHSPEC widened
    // from "tools/revocations" to "tools" still selected the advisory commit,
    // because no other commit in the tree was under `tools/` at all, and this
    // check stayed green at the full suite. A check that cannot tell the
    // pathspec in its own name from a strictly wider one is a check about
    // `git log -1` and not about SERVE-85's clock.
    //
    // The middle commit closes that: it touches `tools/` OUTSIDE
    // `tools/revocations/` and is two minutes old, so the three candidate
    // clocks below are 180, 2 and 1 minutes old, and ONLY the narrow pathspec
    // leaves the difference outside the 30-minute grace. Widen the pathspec and
    // the fixture guard fires first, by name; read main's head instead and the
    // verdict assertion fires.
    const t = makeTree("busy-main");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory, three hours ago", { at: "2026-09-19T09:00:00Z" });
    t.write("tools/README-fixture.md", "a commit under tools/ that is not an advisory\n");
    t.commit("a tools/ change two minutes ago", { at: "2026-09-19T11:58:00Z" });
    t.write("plugins/dice-roller/plugin.json", { schema: "astra.registry.plugin/1", id: "dice-roller" });
    t.commit("a publication, one minute ago", { at: "2026-09-19T11:59:00Z" });

    const facts = gather({ root: t.dir });
    // The fixture guard, stated separately from the verdict so a widened
    // pathspec is reported as what it is rather than as a missing finding.
    const listAge = minutesSince(facts.listClock, "2026-09-19T12:00:00Z");
    assert(listAge !== null && listAge > 170 && listAge < 190,
      `the list's own clock is ${facts.listClock}, ${listAge} minute(s) old. It has to be the advisory commit's, ` +
      `three hours back. A pathspec wider than tools/revocations reaches the tools/ commit two minutes old, and ` +
      `main's head is the publication one minute old; either excuses a withdrawal that was dropped three hours ago`);

    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 1, revocations: [] } },
    });
    const v = serve85({ ...facts, head, now: "2026-09-19T12:00:00Z" });
    assertEqual(codesOf(v), "SERVE_85_SERIAL_DRIFT",
      "a publication one minute old excused a withdrawal three hours old; SERVE-85's own clock does that");
  });

  await test("an advisory merged from a long-lived branch is dated at the merge", () => {
    // Gap 68. The serial moves when an advisory becomes REACHABLE from main,
    // and for a pull request merged with a merge commit that is the merge.
    // `git log -1 -- <pathspec>` does not answer that: it simplifies history
    // through the merge, which is TREESAME to its branch parent for the path,
    // and dates the branch commit. Measured 2026-09-22 on this fixture before
    // the repair: the advisory committed at 09:00, merged at 12:00, listClock
    // 09:00, and SERVE_85_SERIAL_DRIFT one minute after the merge — "181
    // minutes after the commit" — for a signer that had had one minute. Every
    // advisory PR open longer than the grace paged the moment it merged.
    //
    // The fixture is the shape GitHub's merge button makes: the branch forks,
    // main moves on without touching tools/revocations/, and the merge is a
    // real two-parent commit three hours after the advisory.
    const t = makeTree("merged-from-branch");
    t.write("tools/revocations/README.md", "fixtures\n");
    t.commit("a revocations directory", { at: "2026-09-19T08:00:00Z" });
    t.git("checkout", "-q", "-b", "advisory");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory, on a branch, at nine", { at: "2026-09-19T09:00:00Z" });
    t.git("checkout", "-q", "main");
    t.write("plugins/dice-roller/plugin.json", { schema: "astra.registry.plugin/1", id: "dice-roller" });
    const before = t.commit("main moves on while the pull request is open", { at: "2026-09-19T09:30:00Z" });
    execFileSync("git", ["-C", t.dir, "merge", "-q", "--no-ff", "-m", "Merge pull request #1 from advisory", "advisory"], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GIT_AUTHOR_DATE: "2026-09-19T12:00:00Z", GIT_COMMITTER_DATE: "2026-09-19T12:00:00Z" },
    });
    const merge = t.head();

    // The fixture guards, before the clock is asked. The merge has to be a
    // merge; the serial has to move AT it and not before it on main; and the
    // plain path-limited log has to date the branch commit — otherwise this
    // fixture cannot tell the two clocks apart and the check below would be
    // green about a difference it could not see.
    assertEqual(t.git("rev-list", "--parents", "-n", "1", merge).split(" ").length, 3,
      "the fixture's merge is not a two-parent commit, so there is no branch to date");
    const serialBefore = serialsAt({ root: t.dir, sha: before }).revocations;
    const serialAt = serialsAt({ root: t.dir, sha: merge }).revocations;
    // By two, not one, from contract 0.35.0: DEC-9's `--full-history` count
    // takes the branch's advisory commit AND the merge, whose tree under the
    // directory differs from its first parent's (ops register entry 117).
    assert(serialAt > serialBefore,
      `the serial is ${serialBefore} on main before the merge and ${serialAt} at it; the fixture has to move it at the merge`);
    assertEqual(t.git("log", "-1", "--format=%cI", merge, "--", SERIAL_PATHSPEC), "2026-09-19T09:00:00Z",
      "a plain path-limited log no longer dates the branch commit here, so this fixture no longer separates the two clocks");

    const facts = gather({ root: t.dir });
    assertEqual(facts.listClock, "2026-09-19T12:00:00Z",
      `SERVE-85's clock dates ${facts.listClock}, and the advisory became reachable from main at the merge, ` +
      `2026-09-19T12:00:00Z: tools/served-set/main-vs-signed.mjs has stopped reading main's first-parent line`);

    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: serialBefore, revocations: [] } },
    });
    const early = serve85({ ...facts, head, now: "2026-09-19T12:01:00Z" });
    assertEqual(early.status, "green",
      `one minute after the merge the signer has had one minute, not ${GRACE_MINUTES}: ${codesOf(early)}`);
    // The control. A repair that stopped the clock firing at all would pass
    // the half above; the grace still has to run out, from the merge.
    const late = serve85({ ...facts, head, now: "2026-09-19T12:31:00Z" });
    assertEqual(codesOf(late), "SERVE_85_SERIAL_DRIFT",
      "31 minutes after the merge a withdrawal the signer never published went unreported");
  });

  await test("a busy main does not reset the clock: the 30 minutes run from the oldest list commit `signed` does not carry", () => {
    // Until 2026-09-22 the serial's clock was the NEWEST commit under
    // tools/revocations/, which is main's head one pathspec down: every
    // advisory restarted the window. Measured on this fixture before the
    // repair, with no signer run at all: two advisories, green at 00:41; a
    // third, green at 01:20 with the first 70 minutes unpublished. One
    // advisory alone was red at 00:41. A signer that died on a `main` taking
    // an advisory at least every half hour would never have been reported,
    // and SERVE-44's dropped advisory is the one most likely to have another
    // behind it.
    const t = makeTree("busy-list");
    t.write("tools/revocations/README.md", "fixtures\n");
    const lastSigned = t.commit("the list `signed` last published", { at: "2026-09-19T00:00:00Z" });
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory("ASTRA-2026-0001"));
    const first = t.commit("an advisory at 00:10", { at: "2026-09-19T00:10:00Z" });
    t.write("tools/revocations/ASTRA-2026-0002.json", advisory("ASTRA-2026-0002", "other-plugin"));
    const second = t.commit("another at 00:30", { at: "2026-09-19T00:30:00Z" });
    const two = gather({ root: t.dir });

    const signedAt = (sha) => headFrom({
      revocations: {
        signatures: [],
        signed: { schema: REVOCATIONS_SCHEMA, serial: serialsAt({ root: t.dir, sha }).revocations, revocations: [] },
      },
    });
    const dead = signedAt(lastSigned);

    // The fixture guard: at 00:41 the NEWEST list commit is 11 minutes old, so
    // this tree separates the two clocks, and a check dating the newest would
    // be green here for a reason other than the signer being on time.
    assertEqual(minutesSince(two.listClock, "2026-09-19T00:41:00Z"), 11,
      `the newest list commit is dated ${two.listClock}; the fixture needs it inside the grace at 00:41`);

    assertEqual(serve85({ ...two, head: dead, now: "2026-09-19T00:39:00Z" }).status, "green",
      "29 minutes after the first advisory the signer is still inside its window");
    const late = serve85({ ...two, head: dead, now: "2026-09-19T00:41:00Z" });
    assertEqual(codesOf(late), "SERVE_85_SERIAL_DRIFT",
      "the first advisory has waited 31 minutes and SERVE-85 dated the wait from the second");
    assert(late.findings[0].message.includes(first.slice(0, 12)),
      `the finding has to name the oldest commit \`signed\` does not carry, ${first.slice(0, 12)}: ${late.findings[0].message}`);

    t.write("tools/revocations/ASTRA-2026-0003.json", advisory("ASTRA-2026-0003", "third-plugin"));
    t.commit("a third at 00:55", { at: "2026-09-19T00:55:00Z" });
    const three = gather({ root: t.dir });
    assertEqual(codesOf(serve85({ ...three, head: dead, now: "2026-09-19T01:20:00Z" })), "SERVE_85_SERIAL_DRIFT",
      "the first advisory has waited 70 minutes and a third one, 25 minutes old, excused it");

    // The other direction, so "oldest" cannot become "oldest ever": what
    // `signed` carries is read from its serial, and once it carries the first
    // advisory the window is the second's.
    const caughtUp = signedAt(first);
    assertEqual(serve85({ ...two, head: caughtUp, now: "2026-09-19T00:59:00Z" }).status, "green",
      "`signed` carries the first advisory and the second has waited 29 minutes, and SERVE-85 still dated the first");
    const behindSecond = serve85({ ...two, head: caughtUp, now: "2026-09-19T01:01:00Z" });
    assertEqual(codesOf(behindSecond), "SERVE_85_SERIAL_DRIFT", "the second advisory has waited 31 minutes, unreported");
    assert(behindSecond.findings[0].message.includes(second.slice(0, 12)),
      `the finding names a commit other than the one \`signed\` does not carry: ${behindSecond.findings[0].message}`);
  });

  await test("the window opens at the commit that moved the serial, a README commit included", () => {
    // SERVE-85 compares SERIALS, and a README commit under tools/revocations/
    // moves the serial (gap 70: every serial this registry has published came
    // from one). So the walk that finds the oldest unsigned commit reads the
    // serial's pathspec, not the advisories' `*.json` that detector A7's list
    // half reads. Walking the advisories alone skips the README commit here
    // and dates the wait from the advisory 20 minutes later.
    const t = makeTree("readme-moves-serial");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    const lastSigned = t.commit("the list `signed` last published", { at: "2026-09-19T00:00:00Z" });
    t.write("tools/revocations/README.md", "How to write an advisory.\n");
    const readme = t.commit("docs: how to write an advisory", { at: "2026-09-19T00:10:00Z" });
    t.write("tools/revocations/ASTRA-2026-0002.json", advisory("ASTRA-2026-0002", "other-plugin"));
    t.commit("an advisory", { at: "2026-09-19T00:30:00Z" });
    assertEqual(serialsAt({ root: t.dir, sha: readme }).revocations, serialsAt({ root: t.dir, sha: lastSigned }).revocations + 1,
      "the fixture's README commit has to move the serial, or it cannot tell the two pathspecs apart");
    const facts = gather({ root: t.dir });
    const head = headFrom({
      revocations: {
        signatures: [],
        signed: { schema: REVOCATIONS_SCHEMA, serial: serialsAt({ root: t.dir, sha: lastSigned }).revocations, revocations: [] },
      },
    });
    const v = serve85({ ...facts, head, now: "2026-09-19T00:41:00Z" });
    assertEqual(codesOf(v), "SERVE_85_SERIAL_DRIFT", "the serial moved 31 minutes ago and SERVE-85 dated the wait from a later commit");
    assert(v.findings[0].message.includes(readme.slice(0, 12)),
      `the finding names a commit other than the README commit that moved the serial: ${v.findings[0].message}`);
  });

  await test("a future-dated list commit is overdue, not early", () => {
    // A negative wait is inside any window, so `withinGrace` alone excused an
    // advisory until the date its committer's clock wrote. Measured before the
    // repair: an advisory dated 2026-06-01, green at 2026-01-01 — five months
    // of a withdrawal nobody was told had not been published. Past the grace's
    // own width the wait cannot be read, and an unreadable clock excuses
    // nothing; skew inside it is a runner and a committer disagreeing by
    // minutes, and must not page.
    const t = makeTree("future-list");
    t.write("tools/revocations/README.md", "fixtures\n");
    const lastSigned = t.commit("the list `signed` last published", { at: "2025-12-31T23:00:00Z" });
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory from a committer whose clock is five months fast", { at: "2026-06-01T00:00:00Z" });
    const facts = gather({ root: t.dir });
    const head = headFrom({
      revocations: {
        signatures: [],
        signed: { schema: REVOCATIONS_SCHEMA, serial: serialsAt({ root: t.dir, sha: lastSigned }).revocations, revocations: [] },
      },
    });

    const v = serve85({ ...facts, head, now: "2026-01-01T00:00:00Z" });
    assertEqual(codesOf(v), "SERVE_85_SERIAL_DRIFT", "an advisory dated five months after the run's clock was excused until its date");
    assert(v.findings[0].message.includes("cannot be read"), `the finding has to say the wait is unreadable: ${v.findings[0].message}`);
    assertEqual(serve85({ ...facts, head, now: minutesAgo("2026-06-01T00:00:00Z", -29) }).status, "green",
      "an advisory dated 29 minutes after the run's clock paged; that is skew inside the grace");
    assertEqual(codesOf(serve85({ ...facts, head, now: minutesAgo("2026-06-01T00:00:00Z", -31) })), "SERVE_85_SERIAL_DRIFT",
      "an advisory dated 31 minutes after the run's clock was excused");
  });

  await test("a serial difference no first-parent commit explains is overdue, not undated", () => {
    // `signed` behind a serial that no commit on main's first-parent line
    // raised is a formula disagreement, not a signer still inside its window,
    // so there is no clock to excuse it by. Until 2026-09-22 this fell back to
    // main's head, which a busy `main` resets.
    const t = makeTree("unexplained-serial");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory", { at: "2026-09-19T11:59:00Z" });
    const facts = gather({ root: t.dir });
    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: facts.generated.serial - 1, revocations: [] } },
    });
    assertEqual(serve85({ ...facts, head, now: "2026-09-19T12:00:00Z" }).status, "green",
      "the fixture's control: one minute after the advisory, with its commit in listCommits, the signer is on time");
    const v = serve85({ ...facts, listCommits: [], head, now: "2026-09-19T12:00:00Z" });
    assertEqual(codesOf(v), "SERVE_85_SERIAL_DRIFT", "a serial difference with no commit to date it from was excused");
    assert(v.findings[0].message.includes("cannot be read"), `the finding has to say why there is no wait: ${v.findings[0].message}`);
  });

  await test("a future-dated head excuses no entry drift either", () => {
    // The entry half's clock is main's head, and it had the same `withinGrace`.
    const t = makeTree("future-entries");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    t.commit("an advisory, dated five months ahead", { at: "2026-06-01T00:00:00Z" });
    const facts = gather({ root: t.dir });
    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: facts.generated.serial, revocations: [] } },
    });
    assertEqual(codesOf(serve85({ ...facts, head, now: "2026-01-01T00:00:00Z" })), "SERVE_85_ENTRY_DRIFT",
      "an emptied list at the same serial was excused until main's head's date");
    assertEqual(serve85({ ...facts, head, now: minutesAgo("2026-06-01T00:00:00Z", -29) }).status, "green",
      "a head dated 29 minutes after the run's clock paged; that is skew inside the grace");
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

  await test("a `signed` ahead of a commit that contains its Source-Commit is a broken count, not the system working", () => {
    // Ops register entry 117. Under git's default count a merge could give the
    // list a serial below the one `signed` already served; the signer's
    // SERVE-36 gate then refused the list and carried the old one under the
    // merge's Source-Commit, and the test above's reading — `signed` ahead is
    // the race — called that state green for as long as it lasted. From
    // contract 0.35.0 DEC-9 counts `--full-history`, which cannot fall along
    // main, so `signed` ahead of a commit that CONTAINS its Source-Commit can
    // only be a count that is not DEC-9's, or a `signed` not made from main.
    const t = makeTree("signer-ahead-contained");
    t.write("tools/revocations/ASTRA-2026-0001.json", advisory());
    const source = t.commit("an advisory", { at: "2026-09-19T09:00:00Z" });
    t.write("plugins/dice-roller/plugin.json", { schema: "astra.registry.plugin/1", id: "dice-roller" });
    const later = t.commit("main moves on", { at: "2026-09-19T09:30:00Z" });
    // A `signed` commit in the signer's form, one naming a commit main holds,
    // one naming the future and one naming nothing, each read by `sourceOf`.
    const signedWith = (trailer) => {
      const tree = t.git("mktree");
      const body = `signed: a fixture\n\n${trailer}\nRun: none\n`;
      return execFileSync("git", ["-C", t.dir, "commit-tree", tree, "-m", body],
        { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    };
    const contained = sourceOf({ root: t.dir, sha: signedWith(`Source-Commit: ${source}`), mainSha: later });
    assertEqual(JSON.stringify(contained), JSON.stringify({ sha: source, contained: true }),
      "a Source-Commit the checked-out commit contains was not read as contained");
    const newer = sourceOf({ root: t.dir, sha: signedWith(`Source-Commit: ${later}`), mainSha: source });
    assertEqual(newer.contained, false, "a Source-Commit newer than the checked-out commit was read as contained");
    const absent = sourceOf({ root: t.dir, sha: signedWith(`Source-Commit: ${"f".repeat(40)}`), mainSha: later });
    assertEqual(absent.contained, null, "a Source-Commit this checkout does not hold was read as an answer");
    assertEqual(sourceOf({ root: t.dir, sha: signedWith("Index-Source-Commit: none"), mainSha: later }).sha, null,
      "a `signed` commit with no Source-Commit was read as naming one");

    const facts = gather({ root: t.dir });
    const head = headFrom({
      revocations: {
        signatures: [],
        signed: { schema: REVOCATIONS_SCHEMA, serial: facts.generated.serial + 1, revocations: [] },
      },
    });
    const v = serve85({ ...facts, head, signedSource: contained, now: "2026-09-19T09:31:00Z" });
    assertEqual(codesOf(v), "SERVE_85_SERIAL_AHEAD",
      `\`signed\` serves a serial main never reached at a commit main contains, one minute on, and SERVE-85 said ` +
        `${v.status}: ${v.notes.slice(1).join(" | ")}`);
    assert(v.hexes.includes(source), "the finding does not name the Source-Commit it measured from");
    // The control: the same serials with a Source-Commit this checkout does
    // not contain are still the race.
    for (const other of [newer, absent, null]) {
      const race = serve85({ ...facts, head, signedSource: other, now: "2026-09-19T09:31:00Z" });
      assertEqual(race.status, "green", `the race read as a broken count (${JSON.stringify(other)}): ${codesOf(race)}`);
    }

    // And end to end, the way the job reads it: a real `signed` branch in the
    // signer's form, fetched by `gather` from a remote, whose Source-Commit
    // the checked-out commit contains. Without this, `gather` could stop
    // asking `sourceOf` and every line above would still pass.
    const signedTree = (() => {
      const blob = execFileSync("git", ["-C", t.dir, "hash-object", "-w", "--stdin"], {
        input: stableStringify(head.documents.revocations), encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
      }).trim();
      const v1 = execFileSync("git", ["-C", t.dir, "mktree"], {
        input: `100644 blob ${blob}\trevocations.json\n`, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
      }).trim();
      const registry = execFileSync("git", ["-C", t.dir, "mktree"], {
        input: `040000 tree ${v1}\tv1\n`, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
      }).trim();
      return execFileSync("git", ["-C", t.dir, "mktree"], {
        input: `040000 tree ${registry}\tregistry\n`, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
      }).trim();
    })();
    const signedCommit = execFileSync("git", ["-C", t.dir, "commit-tree", signedTree, "-m",
      `signed: a fixture\n\nSource-Commit: ${source}\nRun: none\n`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    t.git("update-ref", "refs/heads/signed", signedCommit);
    t.git("remote", "add", "origin", t.dir);
    const fetched = gather({ root: t.dir });
    assertEqual(fetched.head?.sha, signedCommit, `gather did not fetch the fixture's \`signed\`: ${fetched.head?.reason}`);
    assertEqual(JSON.stringify(fetched.signedSource), JSON.stringify({ sha: source, contained: true }),
      "gather does not say which Source-Commit `signed` names, or whether the checked-out commit contains it");
    assertEqual(codesOf(serve85({ ...fetched, now: "2026-09-19T09:31:00Z" })), "SERVE_85_SERIAL_AHEAD",
      "read through gather, a `signed` above a commit that contains its Source-Commit was not reported");
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

  await test("a `signed` head dated after the run's clock excuses no drift on Pages, before the latch or after it", () => {
    // A negative wait is inside any window, so SERVE-39's plain `withinGrace`
    // excused a split view until the date the head's committer clock wrote.
    // Measured before the repair, with the head's time read the way check.mjs
    // reads it (`git log -1 --format=%cI` of a real commit): a head dated
    // 2027-02-01 was green at 2026-09-22 with Pages serving another index, and
    // green again with the latch closed and another withdrawal list — both
    // until 29 minutes after its date. SERVE-85 and A7 had each added the
    // bound by hand; it is `withinGrace`'s own now, so this is its test too.
    const FUTURE = "2027-02-01T00:00:00Z";
    const head = headFrom({
      revocations: { signatures: [], signed: { schema: REVOCATIONS_SCHEMA, serial: 2, revocations: [] } },
    });
    const staleIndex = servedFrom(head, {
      index: { ok: true, url: "https://example.invalid/index", status: 200, body: "{\"old\":true}\n", error: null },
    });
    const args = { head, headClock: FUTURE, served: staleIndex, arming: { armed: false }, signerWorkflowPresent: true };
    assertEqual(codesOf(serve39({ ...args, now: "2026-09-22T00:00:00Z" })), "SERVE_39_DOCUMENT_DRIFT",
      "a `signed` head dated 132 days after the run's clock excused Pages serving another index");
    assertEqual(serve39({ ...args, now: minutesAgo(FUTURE, -29) }).status, "green",
      "a head dated 29 minutes after the run's clock paged; that is skew inside the grace");
    assertEqual(codesOf(serve39({ ...args, now: minutesAgo(FUTURE, -31) })), "SERVE_39_DOCUMENT_DRIFT",
      "a head dated 31 minutes after the run's clock excused a split view");

    const otherList = servedFrom(head, {
      revocations: { ok: true, url: "https://example.invalid/revocations", status: 200, body: "{\"unsigned\":true}\n", error: null },
    });
    const armed = { ...args, served: otherList, arming: { armed: true, latch_commit: "c".repeat(40) } };
    assertEqual(codesOf(serve39({ ...armed, now: "2026-09-22T00:00:00Z" })), "SERVE_39_DISARMING",
      "after the latch, a head dated 132 days ahead excused Pages serving armed clients another list");
    assertEqual(serve39({ ...armed, now: minutesAgo(FUTURE, -29) }).status, "green",
      "after the latch, skew inside the grace paged");
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
    //
    // ── what this check does NOT hold, stated because it looks as if it does ──
    //
    // The artifact lists below are built by calling `receiptName`, the same
    // function `provenance` calls, so the SPELLING of the receipt is not under
    // test here and cannot be: measured 2026-09-22, `signed-commit-${sha}` was
    // renamed to `signed_commit_${sha}` in tools/served-set/provenance.mjs and
    // every check in this module stayed green, because both sides moved
    // together. What IS under test is the relationship the name states — a
    // receipt that names the OTHER commit is refused — and that is real: the
    // honest commit passes and the forged one fails on the same run's
    // artifacts.
    //
    // The spelling is a coupling to `.github/workflows/sign.yml`, which is what
    // uploads the receipt, and it IS enforced — by `the receipt sign.yml
    // uploads is the artifact SERVE-90 looks for` in bot/tests/workflows.test.mjs,
    // run by bot-tests.yml and ingest.yml. Re-measured under the same rename on
    // 2026-09-22: that suite goes red with "sign.yml uploads the receipt under a
    // name provenance.mjs does not look for". So this is a BOUNDARY of
    // tools/selftest.mjs and not an unenforced coupling, and the honest repair
    // is this pointer rather than a second copy of the assertion here: a
    // spelling pinned in this file would be pinned to a literal in this file,
    // not to the workflow that has to agree with it, which is the shape of the
    // problem and not a fix for it.
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
    //
    // **`7 * 1440 + 60` is a literal, and the +60 is the whole point.** This
    // age used to read `(PROVENANCE_WINDOW_DAYS + 3) * 1440`, so the old commit
    // followed the constant and stayed outside whatever the window happened to
    // be. Measured 2026-09-22: PROVENANCE_WINDOW_DAYS moved 7 → 1 and this
    // check stayed green at the full suite, because a fixture computed from the
    // constant under test cannot test the constant — it proved the duplicate
    // index is wider than the window and said nothing about the window being
    // seven days.
    //
    // An hour PAST seven days pins the window's upper edge here: widen it and
    // the old commit comes into scope, `hexes` grows to two and the assertion
    // below fails by name. The lower edge is pinned in `the head is checked
    // however old it is…` further down, whose fixture puts a commit an hour
    // INSIDE seven days and requires it to be examined. It has to be pinned
    // there and not here, and the pointer is the reason: the fresh commit below
    // is `commits[0]`, and the head is in scope whatever the window says, so
    // narrowing is a thing THIS fixture is structurally unable to see.
    const old = commitOf({ sha: "3".repeat(40), minutesOld: 7 * 1440 + 60, run: "99" });
    const fresh = commitOf({ sha: "4".repeat(40), minutesOld: 5, run: "99" });
    const runs = new Map([["99", signerRun({ artifacts: [receiptName(fresh.sha), receiptName(old.sha)] })]]);
    const v = provenance({ commits: [fresh, old], repo: REPO, runs, now: NOW, ...ancestry });
    assert(codesOf(v).includes("SERVE_90_RUN_CITED_TWICE"),
      `one run made two commits and nothing said so: ${codesOf(v)}`);
    assertEqual(v.hexes.join(","), fresh.sha,
      "the older commit was EXAMINED, so the duplicate above was found inside the window and this check no longer " +
      "says anything about the case it is named for: a run URL copied off a commit nothing re-examines");
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

    // And a Source-Commit that is not a commit id at all, which no run could
    // have read. Every fixture here answers the two ancestry questions with a
    // constant, so the 40-hex rule is the only thing between this commit and a
    // pass: measured 2026-09-22, deleting it from provenance.mjs left all 317
    // checks green. (In production `git merge-base` would refuse the string and
    // the commit would fail as NOT_DESCENDANT — refused, for the wrong reason.)
    for (const [what, source] of [["missing", undefined], ["a branch name", "main"], ["an abbreviated sha", "c".repeat(12)]]) {
      const odd = commitOf({ sha });
      if (source === undefined) delete odd.trailers["Source-Commit"];
      else odd.trailers["Source-Commit"] = source;
      const v = provenance({ commits: [odd], repo: REPO, runs, now: NOW, ...ancestry });
      assertEqual(codesOf(v), "SERVE_90_SOURCE_COMMIT_UNREACHABLE", `a Source-Commit that is ${what} was accepted`);
      assert(v.findings[0].message.includes("no 40-hex `Source-Commit`"), `${what}: refused for another reason: ${v.findings[0].message}`);
    }
  });

  await test("the head is checked however old it is, and older commits fall out of the 7-day window", () => {
    // Artifacts expire, so a receipt for last year's commit is gone and a
    // check demanding one would be permanently red about history nobody can
    // re-attest. The head is the exception because the head is what is served.
    //
    // **The two ages an hour either side of seven days are the check.** This
    // fixture used to be a 400-day head and a 500-day second commit, which is
    // outside every window from one day to three hundred and ninety-nine, so it
    // told the two apart at no particular value. Measured 2026-09-22:
    // PROVENANCE_WINDOW_DAYS moved 7 → 1 and NOTHING in the whole 25-module
    // suite went red. The window was pinned only from above — widening it to
    // 600 did red this check, because the 500-day commit came into scope — and
    // narrowing was silent. Narrowing is the direction that costs coverage:
    // SERVE-90 would quietly stop examining every `signed` commit between one
    // and seven days old while this transcript stayed green.
    //
    // Now an hour INSIDE seven days must be examined and an hour OUTSIDE must
    // not, so the window cannot move a day in either direction without this
    // failing. This is the lower edge that `two signed commits citing one run…`
    // above points at; that check holds the upper edge and cannot hold this one,
    // because its fresh commit is the head and a head is never out of scope.
    const head = commitOf({ sha: "7".repeat(40), minutesOld: 400 * 1440, run: "70" });
    const justInside = commitOf({ sha: "8".repeat(40), minutesOld: 7 * 1440 - 60, run: "71" });
    const justOutside = commitOf({ sha: "e".repeat(40), minutesOld: 7 * 1440 + 60, run: "72" });
    const runs = new Map([
      // No receipt: the head is checked however old it is, so this is the one
      // finding the verdict may carry.
      ["70", signerRun({ artifacts: [] })],
      // In scope and in order, so all this commit contributes is its presence.
      ["71", signerRun({ artifacts: [receiptName(justInside.sha)] })],
      // Out of scope and broken, so a window wide enough to reach it says so
      // with a second SERVE_90_NO_RECEIPT rather than passing quietly.
      ["72", signerRun({ artifacts: [] })],
    ]);
    const v = provenance({ commits: [head, justInside, justOutside], repo: REPO, runs, now: NOW, ...ancestry });
    assertEqual(codesOf(v), "SERVE_90_NO_RECEIPT",
      "the head's receipt was not required, or a commit outside the window was asked for one");
    assertEqual(v.hexes.join(","), [head.sha, justInside.sha].join(","),
      "the window examined the wrong set. It is the head whatever its age, plus every commit younger than seven " +
      "days: an hour inside is in, an hour outside is out, and a window that is not seven days gets one of those wrong");
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

  await test("every composer caps a list where the channel does: as many as it will send, and not one more", () => {
    // Three files write `MAX_ELEMENTS = 40` and none imports another:
    // bot/lib/alert-verdict.mjs, which REFUSES a verdict whose list is longer,
    // and the two composers that cut their lists to fit it,
    // tools/served-set/compose.mjs and tools/coverage-verdict.mjs. Measured
    // 2026-09-22: each composer's 40 moved to 41 and to 39, and all 317 checks
    // stayed green all four times. Too high and a real alarm is refused by the
    // channel and replaced by its fallback, every code in it lost; too low and
    // the fortieth finding is dropped from a message that had room for it.
    //
    // The channel's cap is READ from the channel — the longest list
    // verdictProblems accepts — rather than written here, so this compares the
    // composers with the file they have to agree with and not with a third copy.
    const codes = (n) => Array.from({ length: n }, (_, i) => `E_CAP_PROBE_${i}`);
    const hexes = (n) => Array.from({ length: n }, (_, i) => i.toString(16).padStart(40, "0"));
    let cap = 0;
    while (cap < 1000 && verdictProblems({ schema: VERDICT_SCHEMA, check: "served-set", status: "red", codes: codes(cap + 1) }).length === 0) {
      cap++;
    }
    assert(cap > 0 && cap < 1000, `the channel's list cap could not be read: it accepted ${cap}`);
    const many = cap * 2 + 5;

    const { verdict: served, problems } = composeVerdict({
      check: "served-set",
      jobs: [{ name: "main-vs-signed", result: "success", status: "red", codes: codes(many).join(" "), hexes: hexes(many).join(" ") }],
      run: null,
    });
    assertEqual(problems.join("; "), "",
      "tools/served-set/compose.mjs built a verdict the channel refuses, so what pages is the fallback and every real code is lost");
    assertEqual(served.codes?.length, cap, `tools/served-set/compose.mjs sends a different number of codes than the channel's ${cap}`);
    assertEqual(served.hexes?.length, cap, `tools/served-set/compose.mjs sends a different number of hexes than the channel's ${cap}`);

    const { verdict: coverage } = composeCoverage(
      { lines: [{ rule: "cap-probe", status: "red", codes: codes(many), ids: [], hexes: hexes(many) }], bad: [] },
      { rules: [{ name: "cap-probe", owner: "selftest", script: "none" }], run: null },
    );
    assertEqual(coverage.codes?.length, cap, `tools/coverage-verdict.mjs sends a different number of codes than the channel's ${cap}`);
    assertEqual(coverage.hexes?.length, cap, `tools/coverage-verdict.mjs sends a different number of hexes than the channel's ${cap}`);
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
    //
    // **89 and 91 are literals, and that is the repair.** They used to read
    // `plusDays(RUNWAY_DAYS - 1)` and `plusDays(RUNWAY_DAYS + 1)`, so both
    // fixtures followed the constant wherever it went and the two numbers in
    // this check's own name were decorative. Measured 2026-09-22: RUNWAY_DAYS
    // moved 90 → 30 in tools/served-set/runway.mjs and this check stayed green.
    // The only thing that went red was the sibling below, whose `plusDays(30)`
    // happened to collide with the new value — so the threshold in ROLL-45's
    // name was pinned, in the whole suite, by an accident in another check's
    // fixture.
    //
    // Written as literals the two assertions bracket the threshold: 89 must
    // alarm, so RUNWAY_DAYS > 89, and 91 must not, so RUNWAY_DAYS <= 91. The
    // assertEqual closes the one day of slack a two-sided bracket leaves — not
    // as a restatement of the constant but because ROLL-45's runbook table
    // quotes 90 to an operator scheduling a root ceremony, and a reader of that
    // table is entitled to have the code agree with it to the day.
    assertEqual(RUNWAY_DAYS, 90,
      "ROLL-45's runway is 90 days and this check's name says 89 and 91 about it; the runbook quotes 90 too, so " +
      "moving the constant is moving a date somebody has already put in a calendar");

    const near = runwayVerdict({ documents: [{ where: "main", doc: trustExpiring(plusDays(89)) }], now: RUNWAY_NOW });
    assertEqual(near.status, "red", "89 days of runway did not alarm");
    assertEqual(codesOf(near), "ROLL_45_TRUST_EXPIRES_SOON", "the wrong code reached the channel");

    const far = runwayVerdict({ documents: [{ where: "main", doc: trustExpiring(plusDays(91)) }], now: RUNWAY_NOW });
    assertEqual(far.status, "green", "91 days of runway alarmed, which is the shape of an alarm nobody reads");
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
    //
    // The `plusDays(30)` below is a key comfortably inside a 90-day runway and
    // nothing more. Until 2026-09-22 it was also, by accident, the only thing
    // in the whole suite that pinned RUNWAY_DAYS — the check above computed
    // both its fixtures from the constant, so moving 90 to 30 reddened this
    // row and not the one named for the number. That is fixed above, where it
    // belongs; do not read 30 here as a threshold, and do not rewrite it as
    // an expression of RUNWAY_DAYS, which is how the check above came to be
    // unable to see its own constant move.
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
      // The fourth expiry this rule reads, and until 2026-09-22 the only one no
      // fixture carried: an index key's own `not_after`. The sibling check above
      // asks only a READABLE one. Measured that day, dropping the unreadable
      // branch from runway.mjs left all 317 checks green — a key whose lapse
      // date nobody can parse went unwatched while the envelope said 400 days.
      ["an index key's not_after that is not an instant",
        trustExpiring(plusDays(400), [{ key_id: "astra-index-2026a", not_after: "soon" }])],
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
    // "Broken, not smaller" is a claim about the workflow's SIZE, and until
    // 2026-09-22 it was held by the literal 3, against a workflow of four
    // jobs: three comparisons and the alert. Measured that day: deleting the trust-runway job from served-set.yml consistently
    // (the job, its `needs` entry, its ASTRA_SERVED_SET_JOBS word and its four
    // mappings) left three jobs, satisfied `>= 3`, and all 317 checks stayed
    // green while ROLL-45's alarm stopped running; so did adding a job to
    // check.mjs's JOBS that no workflow runs. The size the workflow must not
    // fall below is the set of comparisons tools/served-set/check.mjs can run,
    // and that is what it is now held to, in both directions, below.
    const runnable = Object.keys(JOBS).sort();
    assert(runnable.length >= 1, "tools/served-set/check.mjs's JOBS names no comparison, so there is nothing to hold the workflow to");
    assert(jobNames.length > runnable.length,
      `the walk found ${jobNames.length} job(s) in served-set.yml, fewer than check.mjs's ${runnable.length} comparisons and ` +
      "the alert; it is broken, or the workflow is smaller than what it has to run");

    const declared = /ASTRA_SERVED_SET_JOBS:\s*(.+)/.exec(src)?.[1].trim().split(/\s+/) ?? [];
    const comparisons = jobNames.filter((n) => n !== "alert");
    assertEqual(comparisons.slice().sort().join(" "), declared.slice().sort().join(" "),
      "the jobs in served-set.yml and the jobs ASTRA_SERVED_SET_JOBS names are not the same set, so a comparison " +
      "either pages for nothing or reports into nothing");
    assertEqual(comparisons.slice().sort().join(" "), runnable.join(" "),
      "the comparisons served-set.yml runs are not the comparisons tools/served-set/check.mjs can run: one that " +
      "check.mjs knows and no job runs is an alarm that is never raised, and nothing else would say so");

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
