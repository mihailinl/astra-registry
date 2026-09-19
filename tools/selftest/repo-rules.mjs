// R0: the properties that kept this repository from having two signers, and from
// saying things about itself that were not true.
//
// walkRepo and grepRepo moved to ./harness.mjs when the suite became a directory,
// because grepRepo's own documentation names `revoke.yml` and would otherwise be
// a hit for the last test in this file. The exclusion that used to be the single
// path `tools/selftest.mjs` is `isSuiteFile` now; two of the tests below carry
// the canary that a predicate needs and a name did not.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, walkRepo, grepRepo, isSuiteFile } from "./harness.mjs";

export async function run() {
  // ─────────────────────────────────────────────────────────────────────────────
  // R0: the properties that kept this repository from having two signers, and
  // from saying things about itself that were not true (registry plan RC-R0-1).
  // Each was watched failing before it was committed.
  // ─────────────────────────────────────────────────────────────────────────────

  const WORKFLOW_DIR = path.join(REPO_ROOT, ".github", "workflows");
  const workflowFiles = () =>
    fs.readdirSync(WORKFLOW_DIR).filter((n) => n.endsWith(".yml") || n.endsWith(".yaml"));

  // One implementation of what a plugin id is (registry plan B-T0.5, B-T0.3).
  //
  // `ingest.yml` carried an inline `grep -Eq` copy whose second character group
  // was optional, so it admitted a one-character id the rest of the registry
  // refuses. B-T0.5 deleted it; B-T0.3 then moved the publish path into
  // `bot/publish-apply.mjs`, which IMPORTS the predicate — and at that point
  // `workflows.test.mjs` was the only thing watching, and it only scans YAML.
  //
  // So this is the hole that move left: a second copy of the predicate written
  // into a .mjs file is what nothing was looking for.
  //
  // The detector is a heuristic and says so here rather than pretending: it
  // matches the character class and a `{0,NN}` quantifier on one line, which is
  // the spelling `tools/lib/ids.mjs` uses and therefore the spelling a copy is
  // made from. A re-derivation written differently enough — a different
  // quantifier, the pattern built by concatenation, a regex assembled from a
  // string — walks past it. It catches the copy somebody makes, not the one
  // somebody designs. The rule is the same one
  // `dev/couplings.md` states for every fact kept twice — one implementation, and
  // a check that fails when a second appears.
  await test("only tools/lib/ids.mjs says what a plugin id is", async () => {
    const OWNER = path.join("tools", "lib", "ids.mjs");
    // Excluded for the reason given above isSuiteFile: a file may contain a
    // pattern in order to forbid it. Test files are excluded because a test that
    // asserts the predicate's behaviour has to name it.
    //
    // Belt and braces, as it was before the suite became a directory: neither
    // needle can match this file anyway, because they are regex SOURCE — what is
    // written here is `\[a-z0-9\]`, and the backslash before the `]` means the
    // literal `[a-z0-9]` never appears. Verified by running both regexes over
    // every line of the pre-split file: zero hits — and re-measured on
    // 2026-09-19 over all eighteen modules and the runner, when the tag needle
    // below grew the escape and the prose explaining it: still zero.
    const offenders = [];
    for (const file of walkRepo()) {
      const rel = path.relative(REPO_ROOT, file);
      if (!rel.endsWith(".mjs") || rel === OWNER || isSuiteFile(rel) || rel.includes(`${path.sep}tests${path.sep}`)) continue;
      let text;
      try {
        text = fs.readFileSync(file, "utf8");
      } catch {
        continue;
      }
      text.split("\n").forEach((line, i) => {
        if (/\[a-z0-9\][^\n]*\{0,\d\d\}/.test(line)) offenders.push(`${rel}:${i + 1}`);
      });
    }
    assertEqual(offenders.join(", "), "",
      "a second implementation of the plugin-id pattern; tools/lib/ids.mjs is the one that decides");
  });

  // One implementation of what a release TAG is, and a schema that agrees with it.
  //
  // A tag arrives from a stranger and is used four ways: to fetch a release, as
  // part of the queue and decision records, as text echoed into a public comment,
  // and as half of the `owner/repo@tag` binding a maintainer types. It was written
  // out five times — bot/ingest.mjs, bot/lib/notify.mjs, bot/lib/intake.mjs twice
  // (once inside the approval grammar) and once more as a `pattern` in
  // schema/version-v1.json — with nothing comparing them. All five agreed, which
  // is what a coupling looks like the day before it stops agreeing.
  //
  // Found by measuring, not by reading: minice-be reported its own sender refusing
  // `pkg@1.2.3`, and asking what THIS side does with that tag is what turned up
  // the five copies.
  await test("only tools/lib/tags.mjs says what a release tag is", async () => {
    const OWNER = path.join("tools", "lib", "tags.mjs");
    const offenders = [];
    for (const file of walkRepo()) {
      const rel = path.relative(REPO_ROOT, file);
      if (!rel.endsWith(".mjs") || rel === OWNER || isSuiteFile(rel) || rel.includes(`${path.sep}tests${path.sep}`)) continue;
      let text;
      try {
        text = fs.readFileSync(file, "utf8");
      } catch {
        continue;
      }
      // The `\\?` is the whole point of this needle and was missing from it.
      // `tools/lib/tags.mjs` keeps the pattern as a STRING, where the slash is
      // bare. A copy made into a regex LITERAL cannot leave it bare — an
      // unescaped `/` ends the literal — so it comes out as
      // `[A-Za-z0-9._\/-]`, and a needle demanding the bare slash walked
      // straight past the only spelling a copy can have. Watched both ways with
      // a second tags module planted under bot/lib/: the string spelling was
      // caught and the regex-literal spelling was not. Open since 9c4957b,
      // where this needle was written; not the suite split's doing.
      //
      // Still cannot match this file: the two spellings above are written
      // without a quantifier beside them, and the needle wants the character
      // class and the `{1,NNN}` on ONE line.
      text.split("\n").forEach((line, i) => {
        if (/\[A-Za-z0-9\._\\?\/-\][^\n]*\{1,\s*128\}/.test(line)) offenders.push(`${rel}:${i + 1}`);
      });
    }
    assertEqual(offenders.join(", "), "",
      "a second implementation of the release-tag pattern; tools/lib/tags.mjs is the one that decides");
  });

  await test("the version schema's tag rule is the same rule, asserted by behaviour", async () => {
    const { isTag, TAG_MAX } = await import("../lib/tags.mjs");
    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/version-v1.json"), "utf8"));
    // Located rather than searched for: a fallback that hunts the tree for
    // something tag-shaped would keep passing after somebody moved the field,
    // which is the failure this test is for.
    const rule = schema.properties?.release?.properties?.tag;
    assert(rule && rule.pattern, "schema/version-v1.json no longer states a tag pattern");
    const re = new RegExp(rule.pattern);
    const max = rule.maxLength ?? Infinity;
    // Compared by BEHAVIOUR rather than by string, because the two are allowed to
    // spell the bound differently — the module puts `{1,128}` in the pattern and
    // the schema carries `maxLength` beside a `+`. What must not differ is the
    // answer, so the answers are compared on the cases that sit on each edge.
    const probes = [
      "v1.2.3", "feature/x-1.0", "a", "a".repeat(TAG_MAX), "a".repeat(TAG_MAX + 1),
      "", "pkg@1.2.3", "@scope/pkg@1.2.3", "релиз-1.2.0", "v1.2.3 ", "v1.2.3\n", "tag with space",
    ];
    const disagreements = probes.filter((t) => isTag(t) !== (re.test(t) && t.length <= max && t.length >= 1));
    assertEqual(JSON.stringify(disagreements), "[]",
      "schema/version-v1.json and tools/lib/tags.mjs disagree about these tags");
  });

  // `bot/lib/policy.mjs`'s public surface, pinned.
  //
  // That file was 1199 lines and fifteen planned tasks edited it, so on
  // 2026-09-19 it became a barrel over seven modules under `bot/lib/policy/`.
  // Ten files import it and none of them changed, which is the whole point —
  // and also the risk: a barrel can silently grow when a submodule adds an
  // `export`, and can silently shrink when a function moves and nobody
  // re-exports it. The first leaks an internal name into ten importers, the
  // second breaks them all at once.
  //
  // So the surface is a list, not a count. `time.mjs` is deliberately absent:
  // `HOUR_MS` and `iso` were never public and the split is only honest if it
  // kept the same 26 names it had.
  await test("bot/lib/policy.mjs still exports exactly what it used to", async () => {
    const mod = await import("../../bot/lib/policy.mjs");
    const expected = [
      "CLEAN_RELEASES_FOR_TRUSTED",
      "CONSENT_HIGH_RISK",
      "DELAY_HOURS",
      "FINGERPRINT_CHARS",
      "HIGH_RISK",
      "KNOWN_AUTHORITY",
      "POLICY_CODES",
      "REVIEW_SLA_HOURS",
      "SLA_BREACH_HOURS",
      "STATE_DIR",
      "TRUSTED_DELAY_HOURS",
      "artifactDigests",
      "decide",
      "highRiskIn",
      "loadRevocations",
      "newestListedVersion",
      "policyCodeDef",
      "queueFile",
      "readQueue",
      "readQueueEntry",
      "renderPolicySection",
      "requestedAuthority",
      "ripeQueueEntries",
      "slaReport",
      "submissionFingerprint",
      "trackRecord",
    ];
    const actual = Object.keys(mod).sort();
    const missing = expected.filter((n) => !actual.includes(n));
    const extra = actual.filter((n) => !expected.includes(n));
    assertEqual(missing.join(", "), "",
      "a name ten importers rely on stopped being re-exported by the barrel");
    assertEqual(extra.join(", "), "",
      "a submodule's internal name leaked into the barrel; either export it on purpose and add it here, or keep it internal");
  });

  // The withdrawal list must have exactly one signer. The workflow that was the
  // second one failed on every run it ever made and was deleted at R0; `sign.yml`
  // takes that path at R1. This fails the day a second one appears.
  await test("no workflow but sign.yml can sign a withdrawal list", async () => {
    const offenders = [];
    for (const name of workflowFiles()) {
      if (name === "sign.yml") continue;
      const text = fs.readFileSync(path.join(WORKFLOW_DIR, name), "utf8");
      // Invoking the list signer at all is the offence. Holding the index key is
      // not: `build-index.yml` holds it to sign the catalogue, and the same job
      // copies `revocations.json` into the deploy tree without signing it — so a
      // co-occurrence test would fail on the honest case and teach nothing.
      if (text.includes("tools/sign-revocations.mjs")) offenders.push(`${name} invokes the list signer`);
    }
    assertEqual(offenders.join("; "), "", "a second signer of the withdrawal list exists");
  });

  // Signing happens in CI, into `dist/`, never on `main`. A signature in the
  // committed tree means a key ran where it should not have, or that a signed
  // artefact was committed back, which is how a stale signature outlives its bytes.
  await test("main carries no signature on the catalogue or the withdrawal list", async () => {
    for (const rel of ["registry/v1/index.json", "registry/v1/revocations.json"]) {
      const full = path.join(REPO_ROOT, rel);
      if (!fs.existsSync(full)) continue;
      const doc = JSON.parse(fs.readFileSync(full, "utf8"));
      const sigs = Array.isArray(doc.signatures) ? doc.signatures : [];
      assertEqual(sigs.length, 0, `${rel} carries ${sigs.length} signature(s) on main`);
    }
  });

  // A job declaring `environment: publish` can read the signing key; a workflow
  // that runs on a pull request runs for strangers. Where both are possible the
  // job must refuse the pull-request case in its own `if:`, with both guards and
  // no `||` — an `||` is how a guard stops guarding.
  //
  // Line-oriented on purpose: this repository has no dependencies, so there is no
  // YAML parser here and adding one would make the gate need a lockfile.
  await test("no job that can reach the publish environment runs on a pull request", async () => {
    const problems = [];
    let jobsChecked = 0;
    for (const name of workflowFiles()) {
      const text = fs.readFileSync(path.join(WORKFLOW_DIR, name), "utf8");
      const lines = text.split("\n");
      const onBlock = text.slice(0, text.indexOf("\njobs:") + 1);
      const runsOnPullRequest = /^\s{2}pull_request(_target)?:/m.test(onBlock);
      const jobStarts = [];
      let inJobs = false;
      lines.forEach((l, i) => {
        if (l === "jobs:") inJobs = true;
        else if (inJobs && /^  [A-Za-z0-9_-]+:\s*$/.test(l)) jobStarts.push(i);
      });
      jobStarts.forEach((start, k) => {
        const end = k + 1 < jobStarts.length ? jobStarts[k + 1] : lines.length;
        const body = lines.slice(start, end);
        const declaresPublish = body.some(
          (l) => /^\s{4}environment:\s*publish\s*$/.test(l) || /^\s{6}name:\s*publish\s*$/.test(l),
        );
        if (!declaresPublish) return;
        jobsChecked++;
        if (!runsOnPullRequest) return;
        const ifAt = body.findIndex((l) => /^\s{4}if:/.test(l));
        let ifText = "";
        if (ifAt >= 0) {
          let j = ifAt + 1;
          while (j < body.length && !/^\s{4}[a-z]/.test(body[j])) j++;
          ifText = body.slice(ifAt, j).join(" ");
        }
        const guarded = ifText.includes("refs/heads/main") && ifText.includes("pull_request");
        if (!guarded) problems.push(`${name} ${lines[start].trim()} reaches publish with no guard`);
        else if (ifText.includes("||")) problems.push(`${name} ${lines[start].trim()} guards with an ||, which is not a guard`);
      });
    }
    assertEqual(problems.join("; "), "", "a publish-capable job is reachable from a pull request");
    assert(jobsChecked >= 1, "no job declares the publish environment at all, so this check proved nothing");
  });

  // Six places said the `publish` environment carried a required reviewer. None
  // was ever configured. That claim is worse than silence: it tells the next
  // reader a human approves every signature, so nobody adds one.
  await test("nothing claims the publish environment has a required reviewer", async () => {
    // The three needles below are string literals in THIS file, so before the
    // suite became a directory `grepRepo` excluded one path by name and that was
    // enough. It is a predicate now, and a predicate one keystroke from matching
    // everything needs its scope asserted rather than assumed: `isSuiteFile`
    // must be true for every file the walk finds inside the suite directory, and
    // false for the nearest files outside it. Excluding all of `tools/` — the
    // tempting widening — goes red here.
    const suite = walkRepo().map((f) => path.relative(REPO_ROOT, f))
      .filter((rel) => rel.startsWith(`tools${path.sep}selftest${path.sep}`));
    assert(suite.length >= 15, `the walk found ${suite.length} suite modules; the exclusion is looking in the wrong place`);
    const unseen = suite.filter((rel) => !isSuiteFile(rel));
    assertEqual(unseen.join(", "), "", "a module of this suite is not excluded from the self-scan");
    const outside = ["tools/validate.mjs", "tools/lib/ids.mjs", "tools/build-index.mjs", "bot/lib/policy.mjs"]
      .map((p) => p.split("/").join(path.sep)).filter((rel) => isSuiteFile(rel));
    assertEqual(outside.join(", "), "", "the suite exclusion reaches files that are not the suite");

    const hits = [
      ...grepRepo("with the maintainer as a required reviewer"),
      ...grepRepo("required reviewer (PRODUCTION_PLAN"),
      ...grepRepo("maintainer as required reviewer"),
    ];
    assertEqual(hits.join(", "), "", "a required reviewer is claimed somewhere");
  });

  // The deleted withdrawal workflow may still be named in the runbook, and only
  // until the real path is written at R1 (RC-R1-2 rewrites §7 then).
  await test("only the runbook still names the deleted withdrawal workflow", async () => {
    const all = grepRepo("revoke.yml");
    // The liveness floor, and the reason it is here rather than in a test of its
    // own: `revoke.yml` is written in this file and in grepRepo's own
    // documentation in harness.mjs, so the suite exclusion has to cover the whole
    // directory — and an exclusion that swallowed the tree would make the line
    // below pass by finding nothing at all. The runbook names it twice; if
    // grepRepo stops seeing even one of them, it has stopped seeing the tree.
    assert(all.some((h) => h.startsWith("docs/RUNBOOK.md:")),
      "grepRepo found no revoke.yml in docs/RUNBOOK.md, where there are two; the exclusion is now swallowing the repository");
    const stray = all.filter((h) => !h.startsWith("docs/RUNBOOK.md:"));
    assertEqual(stray.join(", "), "", "a file other than the runbook still points at revoke.yml");
  });

  // The guards that watch this suite for shrinking cannot be deleted quietly.
  //
  // A split of a library and a split of a TEST file fail differently. A module
  // of a library that stops being imported takes ten call sites down with it. A
  // module of a suite that stops being imported takes nothing down: the run is
  // shorter, every remaining check still passes, and the last line still says
  // PASS — about less. So `tools/selftest.mjs` carries `checkModuleSet()` and
  // `shrinkage()`, and they are in the RUNNER rather than in a module here
  // because a guard against modules disappearing must not be one of the things
  // that can disappear.
  //
  // Which leaves the ordinary hole: nothing was watching the runner. Deleting
  // two calls out of a 113-line file is a small, green, reviewable diff, and
  // this repository's two worst bugs were both small green reviewable diffs.
  //
  // So it is an interlock, not a chain. Deleting this test means deleting this
  // file's `run()`, and then `checkModuleSet` reports repo-rules.mjs as listed
  // by the runner and exporting no run(); `checkModuleSet` and `shrinkage`
  // cannot be dropped without this going red. Textual, because the runner is a
  // script with nothing to import: it asserts the calls are made, not what they
  // do. What they do was watched failing — every mutation in this comment's
  // neighbourhood, re-run and re-read on 2026-09-19 after the guards were
  // repaired, in the message of the commit that repaired them.
  await test("the runner still runs the guards that catch a suite getting smaller", async () => {
    const runner = fs.readFileSync(path.join(REPO_ROOT, "tools", "selftest.mjs"), "utf8");
    // Occurrences rather than an exact call spelling: each guard is written once
    // and called at least once, so fewer than two means it is defined and never
    // reached — or gone. Counting this way survives the arguments being renamed,
    // which a literal `shrinkage(silent, ...)` needle would not.
    const unreached = ["checkModuleSet", "shrinkage"].filter(
      (g) => runner.split(`${g}(`).length - 1 < 2,
    );
    assertEqual(unreached.join(", "), "",
      "a runner guard is defined and never called, or no longer there; a suite that runs fewer modules still prints PASS");

    // The floor is a number, and a number can be edited down to nothing by
    // somebody clearing a red build. So it is ratcheted: it may go up, and it
    // may not go below what it was on the day this was measured.
    //
    // FLOOR_PINNED is a literal on purpose, and the first version of this line
    // was not. It compared TEST_FLOOR against something DERIVED — the count of
    // `await test(` sites under tools/selftest/, 133 of them then — on the
    // theory that a bound read off the suite cannot go stale. Two different
    // quantities, 33 apart, and the derived one grows: append 34 tests and a
    // strictly larger, wholly green suite went RED here, with a message telling
    // its author the floor was too low. The edit that message asks for is
    // `TEST_FLOOR` in the runner — the one shared line the split existed to
    // take out of ten concurrent tasks' path — so the guard against the suite
    // shrinking was, on the only axis anybody was going to move it, a guard
    // that fired on growth. A pinned literal cannot do that: it is the same
    // shape as the `onDisk.length < 10` walk floor in the runner, a number that
    // says what was true once and is never asked to track anything.
    //
    // 166 on 2026-09-19, the same measurement TEST_FLOOR itself carries. Two
    // copies of one number is a coupling, and this assertion is the thing that
    // enforces it: they can only disagree in the safe direction.
    const FLOOR_PINNED = 166;
    const floor = Number(/^const TEST_FLOOR = (\d+);$/m.exec(runner)?.[1] ?? -1);
    assert(floor >= FLOOR_PINNED,
      `tools/selftest.mjs sets TEST_FLOOR to ${floor}, and it was ${FLOOR_PINNED} on 2026-09-19; ` +
      `a floor that has been lowered is a floor somebody moved out of the way of a lost check`);
  });
}
