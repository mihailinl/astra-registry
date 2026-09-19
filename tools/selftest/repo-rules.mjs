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
  // Every rule below that scans the repository asks `walkRepo`, and `walkRepo`
  // answers with a list. A skip in its exclusion list does not make a rule fail
  // — it makes the rule find nothing, which is the same output as compliance.
  // **An exclusion is a refusal that every caller reads as "nothing to check
  // here", and the condition is a name in a list one word long.** Watched: one
  // word, `|| e.name === ".github"`, and every workflow-shape rule below passes
  // vacuously — `PASS`, exit 0, the same 166 names, while a planted
  // `maintainer as required reviewer` in a workflow goes unseen.
  //
  // This is what the split created rather than inherited, and it is the reason
  // it is guarded now. Before 2026-09-19 the walk and the rules that use it were
  // one file: widening the skip list and weakening a rule were the same edit, in
  // front of the same reviewer. `walkRepo` now lives in harness.mjs and eighteen
  // modules depend on it, so the two are far apart and only one of them looks
  // like a change to a check. The generalisation is minice-be's, from an SSRF
  // that lived in neither of the two careful functions that composed it: **when
  // a split preserves each unit's behaviour, the thing to attack is the
  // composition.** Byte-identical test bodies and a byte-identical transcript
  // say nothing about the seam the split just made.
  //
  // The floors are what the walk reached on 2026-09-19 — **335 tracked files,
  // the same number in CI and on a developer's machine** — halved and rounded
  // down so honest deletion does not fire them. They are not an inventory: the
  // question each one asks is "is this area still being looked at at all".
  //
  // The first version of this test had `bot` at 150, and CI went red on the
  // commit that added it. The walk was a `readdirSync` then, so on this machine
  // it returned 633 files and in CI 335 — the difference being
  // `bot/manifest-probe/target/` and `_deps/`, git-ignored Rust build output.
  // **The floor was measured against build artifacts**, which is the same
  // defect as a floor that states a count it never took: minice-be reported
  // exactly that in its own scanners the same morning, four messages whose
  // "16 migrations examined" was a literal. A floor's whole job is to say how
  // much was looked at, so a floor with an unmeasured denominator is the one
  // kind of check that cannot do its job at all. The walk asks `git ls-files`
  // now and the two trees agree.
  await test("the walk still reaches every area the rules below are about", () => {
    const seen = walkRepo().map((f) => path.relative(REPO_ROOT, f));
    const AREAS = [
      [".github/workflows", 4, "every workflow-shape rule — one signer, no required reviewer, the publish guard"],
      ["bot", 30, "the plugin-id and policy-surface scans"],
      ["tools", 30, "the id and tag scans: the modules they are about live here too"],
      ["docs", 2, "the runbook rules, including the one that allows revoke.yml only there"],
      ["policy", 2, "the reserved-id and limits rules"],
      ["schema", 2, "the schema-versus-module comparisons"],
    ];
    const blind = [];
    for (const [dir, floor, whatGoesVacuous] of AREAS) {
      const n = seen.filter((r) => r.startsWith(`${dir}${path.sep}`)).length;
      if (n < floor) blind.push(`${dir}: ${n} files, floor ${floor} — ${whatGoesVacuous} now passes by finding nothing`);
    }
    assertEqual(blind.join("; "), "",
      "walkRepo no longer reaches somewhere the rules are about, so those rules are green because they are blind");
    assert(seen.length >= 200,
      `the walk returned ${seen.length} tracked files and returned 335 on 2026-09-19; this is a broken walk rather ` +
      `than a smaller repository, and every scan below it would have passed`);
  });

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

  // The way this suite gets smaller that no count can see: a whole module
  // deleted from disk AND from the runner's list. Both sides agree, every
  // surviving module still reports tests, and the run is eighteen checks
  // shorter and green. A global floor of 166 allowed exactly this once the
  // suite had grown past it — `PASS  196 passed`, delete the module, `PASS  191
  // passed`, exit 0.
  //
  // So it is a NAME LIST rather than a number, and a subset assertion rather
  // than an equality: the modules that were here on 2026-09-19 must still be
  // here. Adding a module does not REQUIRE touching this list — the property no
  // floor ever had, and the reason the first floor fired on growth — and it
  // cannot be outgrown, because growing the suite does not make a name go away.
  // Retiring a module is still allowed: take its name out of SPLIT_MODULES in
  // the same commit, where a reviewer reads the removal as the decision it is.
  //
  // A new module is added here anyway, the same day it lands, and that is about
  // what the list is for rather than about tidiness. The loss it catches is a
  // module deleted from disk AND from the runner's list in one commit;
  // `checkModuleSet` compares those two sides with each other and is silent
  // whenever they agree. A module missing from the list below has exactly that
  // hole, and its author is the last person who will ever think about it.
  // `signer.mjs` was added on 2026-09-19 with RC-R1-1, watched failing by
  // deleting the file and its runner entry together.
  //
  // Two checks per name, and together they say the module still RUNS: it is on
  // disk and exports `run`; and it is still in the runner's `MODULES`, read out
  // of the runner's source rather than inferred, because `checkModuleSet` is the
  // only other thing that would notice an unlisting and this test must not lean
  // on a guard it is standing in for.
  //
  // What this does NOT do, said plainly because two guards that stood here
  // before pretended otherwise.
  //
  // Nothing watches the runner's loop. The test that used to sit on this line
  // counted textual occurrences of `checkModuleSet(` and `shrinkage(` in the
  // runner and called that an interlock; it was not one. Changing
  // `shrinkage(silent, passed + failures.length)` to `shrinkage(silent,
  // TEST_FLOOR)` keeps both occurrences, keeps that test green, and disarms the
  // floor outright — one argument, no growth required. Text cannot tell a live
  // call from a present one, so there is no stronger spelling to write, and it
  // was deleted rather than reworded.
  //
  // And nothing here — or anywhere in this suite — notices a module that keeps
  // fourteen tests of eighteen, or a test body hollowed to `() => {}`, or a
  // `for` over a table with one row removed. Those were measured, not assumed:
  // each leaves the count, the name and the whole printed transcript unchanged.
  // A suite cannot audit its own assertions from inside, and the guards here are
  // against the accident — a module that stops being imported, a file that never
  // ran, a copy that shadowed its sibling — not against an author editing the
  // check. That distinction is the only honest claim available and it is made
  // here so the next reader does not infer a stronger one from the effort.
  const SPLIT_MODULES = [
    "primitives.mjs", "catalogue.mjs", "publishers.mjs", "validation.mjs", "couplings.mjs",
    "listings.mjs", "origins.mjs", "bundles.mjs", "index-signature.mjs", "revocations.mjs",
    "cli.mjs", "root-delegation.mjs", "update-signing.mjs", "update-notes.mjs", "repo-rules.mjs",
    "signer.mjs",
  ];
  await test("no module has left the runner's list since the suite was split", async () => {
    const runner = fs.readFileSync(path.join(REPO_ROOT, "tools", "selftest.mjs"), "utf8");
    const listSrc = /^const MODULES = \[([\s\S]*?)^\];$/m.exec(runner)?.[1];
    // The parse is the thing this test stands on, so it says so when it fails
    // rather than reporting fifteen missing modules.
    assert(listSrc !== undefined,
      "could not find `const MODULES = [ … ];` in tools/selftest.mjs; the list this test reads has been renamed or " +
      "reshaped, and every name below would report as missing for the wrong reason");
    const listed = [...listSrc.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    const unlisted = SPLIT_MODULES.filter((n) => !listed.includes(n));
    assertEqual(unlisted.join(", "), "",
      "a module the runner ran on 2026-09-19 is no longer in its list, so its checks no longer run; if it was " +
      "retired on purpose, remove its name from SPLIT_MODULES in this test in the same commit");

    const hollow = [];
    for (const name of SPLIT_MODULES) {
      if (!fs.existsSync(path.join(REPO_ROOT, "tools", "selftest", name))) {
        hollow.push(`${name} is listed and not on disk`);
        continue;
      }
      const mod = await import(`./${name}`);
      if (typeof mod.run !== "function") hollow.push(`${name} exports no run()`);
    }
    assertEqual(hollow.join(", "), "",
      "a module from the split is on disk and no longer exports run(), so the runner imports it and runs nothing");
  });
}
