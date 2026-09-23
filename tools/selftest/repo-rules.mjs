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

  // A suite's first job is to prove its subject loaded.
  //
  // On 2026-09-19 `bot/lib/holds.mjs` reached this repository carrying 474
  // lines of hold-release rules and **would not import**: its last line was
  // `export { loadSchema };` for a binding no line declares, so every `import()`
  // of it threw `Export 'loadSchema' is not defined in module`. Nothing had a
  // wrong answer. There was no answer, and a module nothing imports is
  // indistinguishable from a module with nothing to say — the suite was green,
  // the file was on a branch, and the first thing that would have executed it
  // was the run that needed it.
  //
  // It is a link error rather than a syntax error, so `node --check` does not
  // see it: the bindings resolve when the module graph is linked, one step
  // after parsing. Only an actual import finds it.
  //
  // **Scoped to `*/lib/*.mjs` on purpose, and the scope is the whole design.**
  // A library is a module whose import must do nothing — measured, not
  // assumed: all 39 import silently, and this test would be a liability over
  // the entry points, where `bot/gen-checks-doc.mjs` writes `docs/BOT-CHECKS.md`
  // when imported and another calls `process.exit`. A sweep over everything
  // found that out by dirtying a tree, which is the argument for the narrower
  // rule rather than for a list of exceptions that would go stale.
  //
  // The floor is 20 against 39 measured, because a library being retired is
  // legitimate and this line is not the inventory.
  await test("every library module can be imported", async () => {
    const libs = walkRepo()
      .map((f) => path.relative(REPO_ROOT, f))
      .filter((rel) => /(^|\/)lib\/[^/]+\.mjs$/.test(rel))
      .sort();
    assert(libs.length >= 20,
      `found ${libs.length} modules under */lib/ and there were 39 on 2026-09-19; this is a broken walk, and a ` +
      `loop over nothing imports nothing and passes`);
    const broken = [];
    for (const rel of libs) {
      try {
        await import(path.join(REPO_ROOT, rel));
      } catch (e) {
        broken.push(`${rel}: ${String(e.message).split("\n")[0]}`);
      }
    }
    assertEqual(broken.join("; "), "",
      "a module in this repository cannot be loaded at all, so whatever it contains has never run and its absence " +
      "reads exactly like a module with nothing to say");
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

  // One grammar for an ADVISORY id too, and the same shape of rule. It was
  // typed in five modules until 2026-09-22 (gap 72's tails) and one copy took
  // exactly four serial digits where the others took four or more.
  // `tools/selftest/couplings.mjs` asks every reader it knows what it accepts;
  // this is what catches the reader it does not know yet — a sixth copy.
  //
  // The needle is `ASTRA-` followed by a digit class, `\d` or `[0-9]`, with or
  // without a capture paren and in string or regex spelling: every way the five
  // copies were written. A prose id (`ASTRA-2026-0001`, `ASTRA-YYYY-NNNN`) has
  // a literal digit or letter there and is not a grammar. `schema/` is left to
  // the couplings check, which finds and asks every schema that spells one.
  // One file is allowed a looser pattern, and it is the one whose relation to
  // the grammar is held there as a superset: the docs detector must flag every
  // advisory-looking URL, not validate one.
  await test("only tools/lib/ids.mjs says what an advisory id is", async () => {
    const OWNER = path.join("tools", "lib", "ids.mjs");
    const HEURISTIC = path.join("tools", "coverage", "docs-advisory-url.mjs");
    const offenders = [];
    let heuristicSeen = false;
    for (const file of walkRepo()) {
      const rel = path.relative(REPO_ROOT, file);
      if (rel === OWNER || isSuiteFile(rel) || rel.includes(`${path.sep}tests${path.sep}`)) continue;
      if (rel.startsWith(`schema${path.sep}`) || rel.startsWith(`tests${path.sep}`)) continue;
      let text;
      try {
        text = fs.readFileSync(file, "utf8");
      } catch {
        continue;
      }
      text.split("\n").forEach((line, i) => {
        if (!/ASTRA-\(?(?:\\{1,2}d|\[0-9\])/.test(line)) return;
        if (rel === HEURISTIC) heuristicSeen = true;
        else offenders.push(`${rel}:${i + 1}`);
      });
    }
    // The needle's own control: the one spelling it is allowed must still be
    // found, or a needle that matches nothing would pass this for ever.
    assert(heuristicSeen, `the needle no longer finds the looser pattern in ${HEURISTIC}; it cannot be trusted to find a copy`);
    assertEqual(offenders.join(", "), "",
      "a second implementation of the advisory-id grammar; tools/lib/ids.mjs's ADVISORY_ID_PATTERN is the one that decides");
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

  // The deleted withdrawal workflow, now named nowhere.
  //
  // RC-R0-1 deleted `revoke.yml` and allowed `docs/RUNBOOK.md` to go on naming
  // it, because §7 described a procedure that ran through it and there was no
  // other procedure to describe. **That exception ends here** (RC-R1-2): §7 is
  // rewritten around `sign.yml`, so a surviving mention is a reader sent to
  // run a workflow that does not exist, in the middle of a withdrawal.
  await test("nothing in this repository names the deleted withdrawal workflow", async () => {
    // The liveness anchor, and it is not decoration. Both needles are written
    // in this file and in `grepRepo`'s own documentation in harness.mjs, so
    // the suite exclusion covers that whole directory — and an exclusion that
    // swallowed the tree would make the assertion below pass by finding
    // nothing at all, which is the same output as compliance. The old floor
    // was "the runbook names revoke.yml twice"; removing those two lines is
    // the point of this commit, so the floor moves to what replaced them.
    const signer = grepRepo("sign.yml");
    assert(signer.some((h) => h.startsWith("docs/RUNBOOK.md:")),
      "grepRepo found no sign.yml in docs/RUNBOOK.md, where §7's procedure now runs through it; either the " +
      "runbook stopped naming the signer, or the exclusion is swallowing the repository");
    const hits = grepRepo("revoke.yml");
    assertEqual(hits.join(", "), "",
      "a file still points at revoke.yml, which was deleted at R0. docs/RUNBOOK.md §7 is the procedure now, and " +
      "it runs through .github/workflows/sign.yml");
  });

  // ─────────────────────────────────────────────────────────────────────────
  // ROLL-44's "One publisher" rows (registry plan D1, RC-R1-2).
  //
  // Two documents, one branch, one origin, and exactly one thing allowed to
  // write any of them. Every row below was watched failing, in turn, by adding
  // a second deploy-pages workflow, by putting `id-token: write` in `publish`,
  // by dropping `!cancelled()` from `pages`, and by adding an AstraPlugins
  // checkout to `publish`.
  // ─────────────────────────────────────────────────────────────────────────

  /** Every job in every workflow, as `{file, job, line, body}`. Comments kept. */
  const workflowJobs = () => {
    const out = [];
    for (const name of workflowFiles()) {
      const lines = fs.readFileSync(path.join(WORKFLOW_DIR, name), "utf8").split("\n");
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
        for (let j = i + 1; j < end; j++) {
          if (/^\S/.test(lines[j])) { end = j; break; }
        }
        out.push({ file: name, job, line: i + 1, body: lines.slice(i, end).filter((l) => !l.trim().startsWith("#")) });
      }
    }
    return out;
  };

  await test("exactly one workflow writes `signed`, and exactly one deploys Pages", async () => {
    const pushers = new Set();
    const deployers = new Set();
    for (const job of workflowJobs()) {
      const body = job.body.join("\n");
      if (/--step\s+commit/.test(body) || /git push[^\n]*\bsigned\b/.test(body)) pushers.add(job.file);
      if (/actions\/deploy-pages/.test(body)) deployers.add(job.file);
    }
    assertEqual([...pushers].sort().join(", "), "sign.yml",
      "the `signed` branch has more than one writer, or none. D1: one publisher, and a two-publisher interval is " +
      "the race this design removes");
    assertEqual([...deployers].sort().join(", "), "sign.yml",
      "something other than the signer deploys Pages. Two deployers is two answers to what a shipped 0.2.x " +
      "daemon is served, decided by whichever finished last");
  });

  await test("every publishing job is serialised, and none of them may be cancelled", async () => {
    // A cancelled signer run is a run that may have signed and not pushed, or
    // pushed and not uploaded its receipt. `cancel-in-progress: true` on
    // either group would make the newer run kill the older one mid-publication
    // — and the older one is the one holding the key.
    const GROUPS = ["registry-signer", "pages"];
    const problems = [];
    let checked = 0;
    for (const name of workflowFiles()) {
      const text = fs.readFileSync(path.join(WORKFLOW_DIR, name), "utf8");
      const lines = text.split("\n");
      lines.forEach((line, i) => {
        const m = /^\s*group:\s*(\S+)\s*$/.exec(line);
        if (!m || !GROUPS.includes(m[1])) return;
        checked++;
        // The `cancel-in-progress:` belonging to this group is the next
        // non-blank line at the same indentation; read as the neighbour
        // rather than searched for in the file, because a workflow may carry
        // several concurrency blocks and the wrong one would answer.
        const indent = line.search(/\S/);
        let next = i + 1;
        while (next < lines.length && lines[next].trim() === "") next++;
        const sibling = lines[next] ?? "";
        if (sibling.search(/\S/) !== indent || !/^\s*cancel-in-progress:\s*false\s*$/.test(sibling)) {
          problems.push(`${name}:${i + 1} group ${m[1]} is not immediately followed by \`cancel-in-progress: false\``);
        }
      });
    }
    assert(checked >= 2, `only ${checked} publishing concurrency group(s) found; the signer declares two`);
    assertEqual(problems.join("; "), "", "a publishing run can be cancelled by a newer one");
  });

  await test("the signing job holds the key and nothing else", async () => {
    const job = workflowJobs().find((j) => j.file === "sign.yml" && j.job === "publish");
    assert(job !== undefined, "sign.yml has no `publish` job, so every rule in this test passes by finding nothing");
    const body = job.body.join("\n");

    const FORBIDDEN = [
      [/^\s+id-token:\s*write\s*$/m,
        "an OIDC token. The one job that can publish to every Astra installation is the last place to mint a " +
        "credential for something outside this repository"],
      [/actions\/download-artifact/m,
        "an artifact download. The signer generates what it signs, at the Source-Commit, in this job — bytes " +
        "another job produced are bytes this one did not gate"],
      [/actions\/cache/m, "a cache; a cache is bytes a pull request can poison"],
      [/repository:\s*mihailinl\/AstraPlugins/m,
        "an AstraPlugins checkout. Signing that waits on another repository stops when that repository is " +
        "unavailable, which is the state a withdrawal is most likely to be needed in (seam 4)"],
      [/ASTRA_PLUGINS_DIR/m,
        "$ASTRA_PLUGINS_DIR, which is the same checkout by another name: `validate.mjs` would then gate signing " +
        "on a sibling tree"],
    ];
    const problems = [];
    for (const [pattern, what] of FORBIDDEN) {
      if (pattern.test(body)) problems.push(`sign.yml's publish job holds ${what}`);
    }

    // TRUST-5. One URL is allowed in this job and it is SERVE-94's wake hint:
    // a POST with no token and an empty body, whose answer is discarded. Any
    // other host reached from the job that holds the index key is a job that
    // can be made to hand it somewhere.
    const WAKE = "https://api.minice.ai/plugins/v1/signed/wake";
    for (const line of job.body) {
      for (const m of line.matchAll(/https?:\/\/[^\s"'`)]+/g)) {
        if (m[0] === WAKE) continue;
        problems.push(`sign.yml's publish job reaches ${m[0]}, and the only URL it may name is the wake hint (TRUST-5)`);
      }
    }
    assertEqual(problems.join("; "), "", "the job that holds the index signing key can do more than sign");
  });

  await test("Pages is redeployed even when the publish job failed", async () => {
    // D5. Pages serves `signed`'s head, and that head exists whether or not
    // this run added to it. A `pages` job gated on `success()` would let one
    // failed publish age the withdrawal list on the one surface every shipped
    // 0.2.x client reads — and the failure that produced it is already being
    // alerted on, so the deploy would be withheld precisely when somebody is
    // looking at something else.
    const job = workflowJobs().find((j) => j.file === "sign.yml" && j.job === "pages");
    assert(job !== undefined, "sign.yml has no `pages` job");
    const condition = job.body.find((l) => /^\s{4}if:/.test(l))?.trim() ?? "";
    assert(/!cancelled\(\)/.test(condition),
      `sign.yml's pages job runs on ${JSON.stringify(condition)}; D5 asks for !cancelled(), so that a failed ` +
      `publish still redeploys what \`signed\` holds`);
    assert(!/success\(\)/.test(condition),
      `sign.yml's pages job asks for success(): ${JSON.stringify(condition)}`);
    assert(job.body.some((l) => /^\s+needs:\s*publish\s*$/.test(l)),
      "sign.yml's pages job does not need `publish`, so it can deploy `signed`'s old head beside a run that was " +
      "about to move it");
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
  // deleting the file and its runner entry together; `served-set.mjs` the same
  // day with RC-R1-4 and RC-R1-5, watched the same way and also by leaving it
  // out of this list — which is the silent half, since omitting a name here
  // costs nothing and fails nothing.
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
    // `roots.mjs` was added on 2026-09-19 with B-T1.5, watched failing by
    // deleting the file and its runner entry together — which is the one loss
    // `checkModuleSet` is silent about, because that guard compares those two
    // sides with each other and is quiet whenever they agree.
    "roots.mjs",
    // `baseline.mjs` was added on 2026-09-19 with B-T3.7b, watched failing
    // both ways: unlisted from the runner — `a module the runner ran on
    // 2026-09-19 is no longer in its list` — and deleted from disk together
    // with its runner entry, which is the loss `checkModuleSet` cannot see
    // because the two sides it compares agree that the module is gone.
    "baseline.mjs",
    "served-set.mjs",
    // `signer-run.mjs` was added on 2026-09-19 with RC-R1-2 — the signer's
    // acts, SERVE-95's caller among them. Watched both ways: deleted from disk
    // together with its runner entry, which is the loss `checkModuleSet`
    // cannot see because the two sides it compares agree that the module is
    // gone; and left out of this list, which is the silent half, since
    // omitting a name here costs nothing and fails nothing.
    "signer-run.mjs",
    // `claims.mjs` was added on 2026-09-20 with gap 21's instrument — the
    // table of claims this repository makes about readers in OTHER
    // repositories, each carrying the literal search that finds it. Watched
    // both ways: deleted from disk together with its runner entry, which is
    // the loss `checkModuleSet` cannot see because the two sides it compares
    // agree that the module is gone; and left out of this list, which is the
    // silent half, since omitting a name here costs nothing and fails
    // nothing. It is the module a name list matters most for: nearly every
    // row in it is COULD NOT ASK in CI, so a suite that stopped running it
    // would look identical to a suite that ran it.
    "claims.mjs",
    // `contract-tokens.mjs` was added on 2026-09-21 with RC-R2-2 — the token
    // file's own version discipline, and the register of which half of the
    // cron-versus-file comparison lives here and which lives in
    // `bot/tests/workflows.test.mjs`. Watched both ways: deleted from disk
    // together with its runner entry, which is the loss `checkModuleSet` cannot
    // see because the two sides it compares agree that the module is gone; and
    // left out of this list, which is the silent half, since omitting a name
    // here costs nothing and fails nothing. It matters for this module in
    // particular because one of its four checks is a canary over a DELEGATION:
    // a suite that stopped running it would leave "the other half compares
    // that" true of nothing, and look identical to a suite that ran it.
    "contract-tokens.mjs",
    // `rehearsal-r2.mjs` was added on 2026-09-21 with RC-R2-5 — the ROLL-60
    // rehearsal fixtures, judged the way the plugins service will judge them.
    // Watched both ways: deleted from disk together with its runner entry,
    // which is the loss `checkModuleSet` cannot see because the two sides it
    // compares agree that the module is gone; and left out of this list, which
    // is the silent half, since omitting a name here costs nothing and fails
    // nothing. It matters for this module in particular because the bytes it
    // judges are the ones a staging service and a debug 0.2.x daemon will one
    // day accept or refuse a real key rotation on the strength of — and a
    // suite that stopped running it would leave forty-four signed documents
    // with nothing checking that they still verify.
    "rehearsal-r2.mjs",
    // `trust-anchor.mjs` was added on 2026-09-22 with couplings gap 48 — the
    // root of the estate's trust, verified at HEAD with the estate's own
    // verifier. Watched both ways: deleted from disk together with its runner
    // entry, which is the loss `checkModuleSet` cannot see because the two
    // sides it compares agree that the module is gone; and left out of this
    // list, which is the silent half, since omitting a name here costs nothing
    // and fails nothing. It matters for this module more than for most,
    // because the state it ends is the state where the anchor is unchecked and
    // the suite prints `300 passed, 0 failed` — a suite that stopped running
    // it would return to that state and look exactly like one that had not.
    "trust-anchor.mjs",
    // `loads.mjs` was added on 2026-09-22 with ops couplings entry 116 — the
    // modules a `--loads` run executes, held to TRUST-31's set and to the
    // residual declared beside the checks. Watched both ways: deleted from disk
    // together with its runner and FLOORS entries, which only this list turns
    // red; and left out of this list, which is silent. It matters for
    // this module because both of its checks say NOT ASKED in every lane but
    // one, so a suite that stopped running it would print the same count of
    // NOT ASKED minus two and look like a suite that had less to skip.
    "loads.mjs",
  ];
  // A literal control character in a tracked source file is invisible, and that
  // is the whole of the defect. `bot/lib/moderation.mjs` carried three NUL
  // bytes as a Map-key separator from the day it was written. `file(1)` called
  // it `data`; **`grep` treated it as binary and printed nothing, exit 1, for
  // every pattern** — including `^export`, of which there are 25. That silence
  // is byte-identical to a true absence, and over one night it produced four
  // wrong facts in briefings handed to lanes, one of them nearly a repair that
  // would have invented a value for a published safety bound.
  //
  // The rule is a grammar and not a blocklist: anything below 0x20 that is not
  // tab, newline or carriage return, plus DEL. Escapes are unaffected — `\u0000`
  // in source is six printable characters — so this costs nothing and every
  // future instance arrives as a named failure instead of as a quiet one.
  //
  // It is here rather than in a linter because the subject is the REPOSITORY,
  // not a language: the same silence would hide a control character in a
  // workflow, a schema or a policy document, and `walkRepo` already reaches all
  // of them.
  await test("no tracked text file carries a literal control character", async () => {
    const BAD = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
    const offenders = [];
    let scanned = 0;
    for (const abs of walkRepo()) {
      const rel = path.relative(REPO_ROOT, abs);
      if (/\.(png|jpe?g|gif|ico|webp|woff2?|zip|gz|astraplugin|wasm)$/i.test(rel)) continue;
      // No `catch { continue }` here: a read that throws is a file this rule did
      // not look at, and swallowing it is how the first draft scanned zero files
      // and would have passed without the floor below.
      const text = fs.readFileSync(abs, "utf8");
      scanned += 1;
      const at = text.search(BAD);
      if (at === -1) continue;
      const line = text.slice(0, at).split("\n").length;
      const code = text.charCodeAt(at).toString(16).padStart(4, "0");
      offenders.push(`${rel}:${line} carries U+${code.toUpperCase()}`);
    }
    // The floor first, so a walk that reached nothing cannot report compliance.
    assert(scanned >= 150,
      `this rule read ${scanned} tracked text file(s) and there were 335 on 2026-09-19; a walk that reaches ` +
      "nothing passes this check and every other rule in this file for the same reason");
    assertEqual(offenders.join(", "), "",
      "a tracked text file carries a literal control character. It is invisible in an editor, `file(1)` reports " +
      "the file as `data`, and `grep` prints nothing and exits 1 for EVERY pattern — a silence that cannot be " +
      "told from a true absence. Write it as an escape (`\\u0000`) instead; that is six printable characters and " +
      "the same value");
  });

  await test("no module has left the runner's list since the suite was split", async () => {
    // The list itself first. It is a SUBSET assertion, so a name appearing
    // twice changes nothing it checks and nothing reports it — and a
    // rebase that resolves a conflict by keeping both sides produces exactly
    // that. It happened on 2026-09-19 when two lanes added a module in the
    // same commit position: `signer.mjs` landed twice, the suite printed
    // `PASS 223 passed, 0 failed`, and the only reason anyone looked was that
    // the conflict had just been resolved by hand. The runner's own MODULES
    // list is checked for duplicates because a repeat there prints a module's
    // names twice; here a repeat prints nothing at all, which is why it needs
    // its own line rather than inheriting that one's.
    const twice = SPLIT_MODULES.filter((n, i) => SPLIT_MODULES.indexOf(n) !== i);
    assertEqual([...new Set(twice)].join(", "), "",
      "a module is pinned twice in SPLIT_MODULES; this list is a subset assertion, so a duplicate asserts nothing " +
      "extra and nothing else in the suite would say so");

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
