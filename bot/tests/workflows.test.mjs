// What the workflow files may and may not say.
//
// The other suites test code. This one tests the YAML, because several of the
// properties this registry depends on are properties of the workflows and of
// nothing else: which job can reach a signing key, whether a shell re-derives a
// predicate that already has one implementation, and whether a dispatch can
// name a submitter. A reviewer checks those by reading; this file checks them
// every run.
//
// Line-oriented, with no YAML parser, for the same reason the rest of the
// repository has no dependencies: the gate has to still run when a lockfile is
// being argued about (registry plan B-T0.3 creates this file; B-T0.5 and B-T0.6
// extend it).

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { REQUIRED_SECRETS } from "../alert.mjs";
import { CHECKS, alertsEnvironmentSecrets, secretName } from "../lib/alert-checks.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const DIR = path.join(REPO, ".github", "workflows");
const files = fs.readdirSync(DIR).filter((n) => n.endsWith(".yml") || n.endsWith(".yaml"));
const read = (n) => fs.readFileSync(path.join(DIR, n), "utf8");

/**
 * Every job in every workflow, as `{file, job, line, body}`.
 *
 * Line-oriented like the rest of this file: two-space keys under `jobs:`,
 * each running to the next one or to the next top-level key. Written as a
 * first pass over the STARTS rather than as one scan, because a comment
 * indented two spaces between two jobs ended the earlier job's body in the
 * scanning version and matched no job name either, so the rest of that job
 * vanished from every check below — a silent false green in a file whose
 * whole subject is silent false greens.
 */
function allJobs() {
  const out = [];
  for (const file of files) {
    const lines = read(file).split("\n");
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
      out.push({ file, job, line: i + 1, body: lines.slice(i, end) });
    }
  }
  return out;
}

/** Is this job pinned to environment `name`? Both spellings YAML allows. */
function inEnvironment(job, name) {
  const bare = new RegExp(`^\\s+environment:\\s*${name}\\s*$`);
  const named = new RegExp(`^\\s+name:\\s*${name}\\s*$`);
  for (let i = 0; i < job.body.length; i++) {
    if (bare.test(job.body[i])) return true;
    if (/^\s+environment:\s*$/.test(job.body[i]) && named.test(job.body[i + 1] ?? "")) return true;
  }
  return false;
}

/** Is this job pinned to environment `alerts`? */
const inAlerts = (job) => inEnvironment(job, "alerts");

const code = (job) => job.body.filter((l) => !l.trim().startsWith("#"));
const where = (job) => `${job.file}:${job.line} (job ${job.job})`;

/**
 * A job's whole `if:` expression, folded block scalar or not.
 *
 * Line-oriented like everything else here, and for a reason this file learned
 * the hard way: a regex over the joined body stops at the end of the `if: >-`
 * line and reports the marker as the condition, which reads as a condition
 * that satisfies every rule asked of it. The continuation lines are the ones
 * indented deeper than the `if:` itself.
 */
function condition(job) {
  const lines = code(job);
  const i = lines.findIndex((l) => /^\s+if:/.test(l));
  if (i < 0) return "";
  const indent = lines[i].search(/\S/);
  const parts = [lines[i].replace(/^\s*if:\s*/, "").replace(/^[>|][-+]?$/, "")];
  for (let k = i + 1; k < lines.length; k++) {
    if (lines[k].trim() === "") continue;
    if (lines[k].search(/\S/) <= indent) break;
    parts.push(lines[k].trim());
  }
  return parts.join(" ").trim();
}

test("there are workflows to check at all", () => {
  assert.ok(files.length >= 5, `only ${files.length} workflow(s) found; this suite would prove nothing`);
});

// B-T0.5 (ROLL-51, ID-65). A plugin id becomes a directory name on a stranger's
// disk. `tools/lib/ids.mjs` is the one place that decides what one is, and the
// copy that used to live in `ingest.yml` was wrong: its second character group
// was optional, so it accepted a one-character id the rest of the registry
// refuses. A second copy of a predicate is a second answer waiting to happen.
test("no workflow carries its own plugin-id pattern", () => {
  const offenders = [];
  for (const name of files) {
    read(name).split("\n").forEach((line, i) => {
      if (line.includes("tools/lib/ids.mjs")) return;
      if (/\[a-z0-9\][^\n]*\{0,\d\d\}/.test(line)) offenders.push(`${name}:${i + 1}`);
    });
  }
  assert.equal(offenders.join(", "), "", "a workflow re-derives what a plugin id is");
});

// The publish path asks `tools/lib/ids.mjs` what a plugin id is. Where that
// question is asked moved in B-T0.3 — out of a shell block in `ingest.yml` and
// into `bot/publish-apply.mjs`, which imports the module rather than shelling
// out to it — so this test moved with it rather than being deleted. A coupling
// test that is removed because the code it watched was refactored is how a
// coupling stops being checked without anybody deciding that it should.
test("the publish path asks ids.mjs, wherever it lives", () => {
  const applier = fs.readFileSync(path.join(REPO, "bot", "publish-apply.mjs"), "utf8");
  assert.match(
    applier,
    /from "\.\.\/tools\/lib\/ids\.mjs"/,
    "bot/publish-apply.mjs no longer asks the one id predicate what an id is",
  );
  assert.match(
    read("ingest.yml"),
    /node bot\/publish-apply\.mjs/,
    "ingest.yml's publish job no longer goes through publish-apply.mjs",
  );
});

// B-T0.3. The `publish` job had `concurrency: { group: registry-publish }`,
// which serialised commits and in exchange let a stranger's release ping
// replace another author's PENDING publish — GitHub keeps one pending run per
// group. Racing publishes are handled in `publish-apply.mjs` now; a group here
// would bring the hazard back with nothing saying so.
test("the publish job serialises nothing", () => {
  const lines = read("ingest.yml").split("\n");
  const at = lines.findIndex((l) => /^  publish:/.test(l));
  assert.ok(at >= 0, "ingest.yml has no publish job");
  let end = at + 1;
  while (end < lines.length && !/^  \S/.test(lines[end])) end++;
  const offenders = lines
    .slice(at, end)
    .map((l, i) => [l, at + i + 1])
    .filter(([l]) => /^\s+concurrency:/.test(l))
    .map(([, n]) => `ingest.yml:${n}`);
  assert.equal(offenders.join(", "), "", "the publish job is in a concurrency group again");
});

// The promise "publishes itself at 14:00" is made by `comment` and made true by
// `publish`. While they ran side by side, an author could be told a time by a
// run whose queue entry never reached the repository, and nothing retried it.
test("comment waits for publish", () => {
  const lines = read("ingest.yml").split("\n");
  const at = lines.findIndex((l) => /^  comment:/.test(l));
  assert.ok(at >= 0, "ingest.yml has no comment job");
  const needs = lines.slice(at, at + 12).find((l) => /^\s+needs:/.test(l));
  assert.match(needs ?? "", /publish/, "comment no longer waits for the job that makes its promise true");
});

// B-T1.5 (BOT-7). `ingest.yml`'s first job compares the published root.json
// with the keys `bot/lib/roots.mjs` compiles in, and the value of putting it
// first is entirely in the edge from it to everything else: a run that reaches
// `publish` while the registry's anchor is in dispute commits a listing on a
// trust set nobody can name.
//
// Two rules, because the second is how the first stops being true without
// anybody deciding that it should. `always()` in an `if:` runs a job over a
// dependency that FAILED, so `needs: roots` alone says nothing about the two
// jobs that carry one — and those two are `comment`, which talks to the
// author, and `publish`, which is the only job that commits.
//
// **Written over every workflow that HAS a roots job, not over `ingest.yml`**
// (B-T3.1). `plugins-ingest.yml` is the second, and the rule is the same one
// for the same reason — it is the file whose `publish` job commits and whose
// `claim` job speaks for this registry to the plugins service. A rule scoped
// to one file is a rule the next file does not inherit, and the next file
// arrived three weeks later written by somebody who never read this one.
test("every job in a workflow that has a roots check waits for it", () => {
  const withRoots = files.filter((f) => allJobs().some((j) => j.file === f && j.job === "roots"));
  // The floor. Two on 2026-09-20 — `ingest.yml` and `plugins-ingest.yml` — and
  // without it a renamed job leaves this test looping over nothing and green.
  assert.ok(
    withRoots.length >= 2,
    `only ${withRoots.length} workflow(s) have a roots job (${withRoots.join(", ") || "none"}); there were 2 on ` +
    `2026-09-20. A file that lost its roots job lost the edge this rule is about, silently`,
  );
  assert.ok(withRoots.includes("ingest.yml") && withRoots.includes("plugins-ingest.yml"),
    `the two files this rule was written for are ${withRoots.join(", ")}; one of them no longer has a roots job`);

  const jobs = allJobs().filter((j) => withRoots.includes(j.file));
  for (const file of withRoots) {
    const n = jobs.filter((j) => j.file === file).length;
    assert.ok(n >= 8, `only ${n} job(s) in ${file}; this check would prove little`);
  }

  const problems = [];
  for (const job of jobs) {
    if (job.job === "roots") continue;
    const body = code(job).join("\n");
    const needs = /^\s+needs:\s*(.+)$/m.exec(body)?.[1] ?? "";
    if (!/\broots\b/.test(needs)) {
      problems.push(`${where(job)} does not need the roots job, so it can run on an anchor nobody checked`);
      continue;
    }
    // `alert` is the one job that MUST run when roots failed: it is the job
    // that says so.
    if (job.job === "alert") continue;
    const cond = condition(job);
    // The floor, and it is not decoration. The first spelling of this read
    // the condition with `/^\s+if:\s*([\s\S]*?)(?=…|$)/m` over the joined
    // body and captured the two characters ">-" — `$` under /m matches at the
    // end of the `if: >-` line, and `publish`'s whole condition is on the two
    // lines below it. So the rule reported as satisfied over the one job in
    // this file that commits, having never seen its condition. Found by
    // deleting the gate and watching this test stay green.
    if (/^\s+if:/m.test(body)) {
      assert.ok(cond.length > 2 && !/^[>|]/.test(cond),
        `${where(job)}: this test read ${JSON.stringify(cond)} as an if-condition, which it is not`);
    }
    if (/always\(\)/.test(cond) && !/needs\.roots\.result\s*==\s*'success'/.test(cond)) {
      problems.push(
        `${where(job)} runs on always() and never asks whether the roots check passed, so it runs anyway when ` +
        `the published root keys and the compiled ones disagree`,
      );
    }
  }
  assert.equal(problems.join("\n"), "", "a job can outrun the check that says the anchor is sound");
});

// B-T1.5. A sparse checkout that forgot one module fails four lines later with
// a Node resolver error about a file nobody asked for, and it fails that way
// only when the job runs — which for `roots` and `alert` is on a schedule,
// where the first reader is whoever eventually looks. The composite alert
// action says this in its own first step for its own five files; these two
// jobs run scripts of their own, and this is the same assertion for those.
//
// Scoped to `ingest.yml` on purpose. The rule is general — every job with a
// sparse checkout owes it — but the other workflows that will have one belong
// to tasks that are still being written, and a test that went red on their
// branches before they were finished would be a test they worked around.
test("ingest.yml's sparse checkouts hold everything the scripts they run import", () => {
  const REPO_FILE = /^(?:\.\.\/|\.\/)/;
  const closure = (entry) => {
    const seen = new Set();
    const stack = [entry];
    while (stack.length) {
      const file = stack.pop();
      if (seen.has(file)) continue;
      seen.add(file);
      const src = fs.readFileSync(path.join(REPO, file), "utf8");
      for (const m of src.matchAll(/^import\s+[\s\S]*?from\s+"([^"]+)";/gm)) {
        if (!REPO_FILE.test(m[1])) continue;
        stack.push(path.relative(REPO, path.resolve(path.dirname(path.join(REPO, file)), m[1])));
      }
    }
    return seen;
  };

  const problems = [];
  let checked = 0;
  for (const job of allJobs().filter((j) => j.file === "ingest.yml")) {
    const body = code(job).join("\n");
    if (!/sparse-checkout-cone-mode:\s*false/.test(body)) continue;
    const listed = new Set(
      [...body.matchAll(/^\s{12}(\S+)\s*$/gm)].map((m) => m[1]).filter((p) => !p.endsWith(":")),
    );
    // The floor: a list this test could not read is a list every assertion
    // below agrees with.
    if (listed.size < 3) {
      problems.push(`${where(job)}: this test read ${listed.size} sparse-checkout path(s), which cannot be right`);
      continue;
    }
    for (const m of body.matchAll(/node\s+(bot\/[\w./-]+\.mjs)/g)) {
      checked++;
      for (const file of closure(m[1])) {
        if (!listed.has(file)) {
          problems.push(`${where(job)} runs ${m[1]}, which imports ${file}, and its sparse checkout omits it`);
        }
      }
    }
  }
  assert.ok(checked >= 2, `only ${checked} script(s) checked; ingest.yml's sparse jobs run more than that`);
  assert.equal(problems.join("\n"), "", "a job will die on a module its checkout did not fetch");
});

// B-T0.6 (AV-5, INV-6, OPEN-OPS-6). A dispatch that names a submitter lets
// whoever may dispatch decide whose ownership gets re-proved. The submitter is
// resolved from the release instead, and nothing in the workflows may hand one
// in.
test("no workflow lets a caller name the submitter", () => {
  const offenders = [];
  for (const name of files) {
    read(name).split("\n").forEach((line, i) => {
      // Comments are excluded on purpose: the rule is about what a workflow
      // reads, not about what it says. `ingest.yml` names the field in a comment
      // precisely to record that it is NOT read, and a test that forbade the
      // words would delete the explanation and keep the behaviour.
      if (line.trim().startsWith("#")) return;
      if (/inputs\.submitter|client_payload\.submitter|INPUT_SUBMITTER|DISPATCH_SUBMITTER/.test(line)) {
        offenders.push(`${name}:${i + 1}`);
      }
    });
  }
  assert.equal(offenders.join(", "), "", "a workflow takes the submitter from its caller");
});

// B-T0.3. `bot/publish-apply.mjs` takes `--skip-checks` so its own tests can run
// against a toy repository with no catalogue in it. That flag turns off
// `validate.mjs`, `build-index.mjs --check` and `selftest.mjs` — every rule this
// registry holds a publication to. An escape hatch CI can reach is not an escape
// hatch, it is the behaviour, so the one place it may appear is a test file.
test("no workflow turns the publish path's own checks off", () => {
  const offenders = [];
  for (const name of files) {
    read(name).split("\n").forEach((line, i) => {
      if (line.trim().startsWith("#")) return;
      if (line.includes("--skip-checks") || line.includes("--no-push")) offenders.push(`${name}:${i + 1}`);
    });
  }
  assert.equal(offenders.join(", "), "", "a workflow passes publish-apply.mjs a flag meant for its tests");
});

// B-T0.3. `bot/publish-apply.mjs`'s `record()` writes the step outputs and
// `ingest.yml` reads them as `steps.apply.outputs.*`. Two files, one vocabulary,
// nothing comparing them — so a renamed key would leave the workflow reading an
// empty string, and an empty string is what every one of those reads means
// "nothing happened". That is the failure mode this whole change was about: a
// job that says a publication landed when it did not.
//
// The check is deliberately one-directional. A key the YAML reads and nobody
// writes fails silently and is a defect; a key written and nobody reads is
// information in the step log and is not. The test names the second set rather
// than forbidding it.
test("every step output the workflow reads is one publish-apply writes", () => {
  const applier = fs.readFileSync(path.join(REPO, "bot", "publish-apply.mjs"), "utf8");
  const written = new Set(
    [...applier.matchAll(/`([a-z_]+)=\$\{/g)].map((m) => m[1]),
  );
  assert.ok(written.size >= 4, `record() writes ${written.size} keys; this suite would prove little`);

  const ingest = read("ingest.yml");
  const readKeys = new Set([...ingest.matchAll(/steps\.apply\.outputs\.([a-z_]+)/g)].map((m) => m[1]));
  assert.ok(readKeys.size >= 3, `ingest.yml reads ${readKeys.size} of them; the publish job lost its outputs`);

  const missing = [...readKeys].filter((k) => !written.has(k));
  assert.equal(
    missing.join(", "),
    "",
    "ingest.yml reads a step output publish-apply.mjs never writes; it will always be empty",
  );
});

test("ingest's manual dispatch takes no inputs", () => {
  const ingest = read("ingest.yml").split("\n");
  const at = ingest.findIndex((l) => /^\s{2}workflow_dispatch:/.test(l));
  assert.ok(at >= 0, "ingest.yml has no workflow_dispatch trigger");
  // Everything indented under the trigger, up to the next two-space key.
  let end = at + 1;
  while (end < ingest.length && (ingest[end].trim() === "" || /^\s{4}/.test(ingest[end]))) end++;
  const body = ingest.slice(at + 1, end).filter((l) => l.trim() && !l.trim().startsWith("#"));
  assert.equal(
    body.join("\n"),
    "",
    "a no-input dispatch runs the drain and the backstop; inputs let a caller aim one run at one release",
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Environment `alerts` (registry plan RC-R1-0; BOT-46, BOT-85).
//
// `alerts` holds the only credential in this repository that reaches a person:
// the registry's own Telegram bot token, the two chat ids, and one whole ping
// URL per dead-man check. BOT-46's rule is that the credential sits in an
// environment admitting only `main`, in jobs that run no submitter code — and
// "no submitter code" is not a property a reviewer can check by reading a job
// once, because the way it stops being true is a step added later.
//
// So the shape is asserted instead: an alert job reads a verdict its own
// workflow computed, sends it, posts a heartbeat, and can do nothing else. It
// cannot write to the repository, cannot mint an OIDC token, cannot pull an
// artifact or a cache (both are bytes another job produced, and a cache is
// bytes a pull request can poison), and cannot read the releases feed.
// ─────────────────────────────────────────────────────────────────────────────

const ALERTS_FORBIDDEN = [
  [/:\s*write\s*$/, "a write permission; an alert job commits nothing and mints no token"],
  [/actions\/download-artifact/, "an artifact download; those are bytes another job produced"],
  [/actions\/cache/, "a cache; a cache is bytes a pull request can poison"],
  [/releases\.atom/, "the releases feed, which is a stranger's bytes"],
  [/secrets\.GITHUB_TOKEN|github\.token/, "the GitHub token"],
  [/^\s+token:\s*\S/, "a `token:` input"],
];

test("every job in environment `alerts` can do nothing but alert", () => {
  const alertJobs = allJobs().filter(inAlerts);
  // The floor, written before the mutation: with none found, every loop below
  // runs over nothing and the whole section is green about a rule it never
  // applied.
  assert.ok(alertJobs.length >= 1, "no job in environment `alerts` was found; this section would prove nothing");

  const offenders = [];
  for (const job of alertJobs) {
    code(job).forEach((line, i) => {
      for (const [pattern, what] of ALERTS_FORBIDDEN) {
        if (pattern.test(line)) offenders.push(`${job.file}:${job.line + i} (job ${job.job}) holds ${what}`);
      }
    });
  }
  assert.equal(offenders.join("\n"), "", "a job holding the alarm channel's credential can do more than alert");
});

test("an `alerts` job maps the channel's secrets and no ping URL that is not its own", () => {
  // An environment secret is not ambient: a job reads one only where it names
  // it. That makes the `env:` block of an alert job an exact statement of what
  // that job can reach, and the statement has to be the minimum. A job that
  // mapped a second check's URL would be a job whose compromise silences a
  // check it never posts to — which is attack M-5 one level down from the base
  // URL this estate refused, and the reason `ASTRA_DEADMAN_URL_*` is one
  // secret per check rather than one per repository.
  const known = new Set(alertsEnvironmentSecrets());
  const problems = [];
  for (const job of allJobs().filter(inAlerts)) {
    const named = new Set([...code(job).join("\n").matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]));
    for (const secret of ["ASTRA_ALERT_TELEGRAM_TOKEN", "ASTRA_ALERT_CHAT_ID", "ASTRA_ALERT_COPY_CHAT_ID"]) {
      if (!named.has(secret)) {
        // This used to be caught twice — here, and by every run of the job
        // going red. Since 2026-09-19 it is caught only here: an alert job
        // that maps NONE of the three is indistinguishable, from inside the
        // job, from the repository before §2.12's R1 act, and the action
        // reports that state and stays green. So a forgotten `env:` block is
        // now a silent alert job that pages nobody, and this assertion is the
        // whole of what stands between the two.
        problems.push(
          `${where(job)} never maps ${secret}, so that secret cannot reach it: an environment secret is not ` +
          `ambient. A job mapping none of the three looks exactly like a repository whose owner has not created ` +
          `the channel yet, which the alert action reports and does NOT fail on — so nothing but this line is ` +
          `between a forgotten env: block and an alert job that is green and pages nobody`,
        );
      }
    }
    for (const secret of named) {
      if (!known.has(secret)) {
        problems.push(`${where(job)} maps ${secret}, which is not a secret environment \`alerts\` holds`);
      }
    }
  }
  assert.equal(problems.join("\n"), "", "an alert job's credentials are not the ones it needs, or are more");
});

test("every job that calls the alert action is in `alerts` and names checks that exist", () => {
  const registryChecks = new Set(CHECKS.filter((c) => c.party === "registry").map((c) => c.name));
  const problems = [];
  let callers = 0;
  for (const job of allJobs()) {
    const body = code(job).join("\n");
    if (!/uses:\s*\.\/\.github\/actions\/alert\s*$/m.test(body)) continue;
    callers++;
    // Without the environment the three secrets are simply absent, every run
    // is red, and the reason is a line nobody wrote rather than a line
    // somebody deleted.
    if (!inAlerts(job)) problems.push(`${where(job)} calls the alert action outside environment \`alerts\``);
    const named = new Set([...body.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]));
    // `ack-check` is counted for the secrets it needs and NOT for the rule
    // below. They are different questions: BOT-86's start signal says an alarm
    // went out, and a BOT-85 heartbeat says this job ran. Counting them
    // together is how the first version of this passed with the drill's own
    // `check:` deleted — the job still "named a check", and the one workflow
    // whose silence nothing else watches would have posted no heartbeat at
    // all.
    const main = [...body.matchAll(/^\s+check:\s*([a-z0-9-]+)\s*$/gm)].map((m) => [m[1], ["success"]]);
    const wants = [
      ...main,
      ...[...body.matchAll(/^\s+ack-check:\s*([a-z0-9-]+)\s*$/gm)].map((m) => [m[1], ["success", "start"]]),
    ];
    // Exactly one of a check and a reason there is none. An alert job that
    // posts no heartbeat is invisible — the receiver has nothing to be silent
    // about — so the omission is a sentence somebody wrote, not an empty
    // input.
    //
    // **AND A SENTENCE SOMEBODY WROTE IS THE WHOLE TEST, WHICH IS THE DEFECT.**
    // The regex below checks that the field is NON-EMPTY. `ingest.yml` carried
    // a sentence in it for eight weeks in which every clause named a different
    // file — BOT-51 is `plugins-ingest.yml`, not this workflow — and because
    // the sentence existed, **this guard went green on it**. The false claim
    // was not merely unhelpful: it was the thing that turned the check green,
    // and so the thing that stopped anybody looking, on the workflow that
    // publishes every delayed release.
    //
    // The general form, which is why this comment is long: **a free-text field
    // that satisfies a structural check is a place where a claim of coverage
    // buys silence.** Measured and displaced 2026-09-22 by
    // `tools/coverage/drain-age.mjs` (PR #160). The facts a real check would
    // need are all in this tree: compare each `no-heartbeat-because` against
    // `CHECKS`'s sources and against the workflow's own cron.
    const excused = /^\s+no-heartbeat-because:\s*\S/m.test(body);
    if (main.length === 0 && !excused) {
      problems.push(`${where(job)} calls the alert action and names neither a receiver check nor a reason it posts none`);
    }
    if (main.length > 0 && excused) {
      problems.push(`${where(job)} names a receiver check and a reason it posts no heartbeat; it can mean only one`);
    }
    for (const [check, signals] of wants) {
      if (!registryChecks.has(check)) {
        problems.push(`${where(job)} posts to ${check}, which bot/lib/alert-checks.mjs does not list as this repository's`);
        continue;
      }
      for (const signal of signals) {
        const secret = secretName(check, signal);
        if (!named.has(secret)) problems.push(`${where(job)} posts ${signal} to ${check} and never maps ${secret}`);
      }
    }
  }
  assert.ok(callers >= 1, "nothing calls the alert action; this check would prove nothing");
  assert.equal(problems.join("\n"), "", "an alert job cannot reach the check it says it posts to");
});

test("the alert action itself reaches for nothing an `alerts` job may not hold", () => {
  // The composite action runs INSIDE those jobs, so a step added here has
  // every permission the job has. It is also in TRUST-31's hashed set (§2.4)
  // precisely because it outputs the `delivered_at` TRUST-32 gates publication
  // on, and a change to it that did not return bot calls to shadow is what
  // that set exists to prevent.
  const file = path.join(REPO, ".github", "actions", "alert", "action.yml");
  const src = fs.readFileSync(file, "utf8");
  const offenders = [];
  src.split("\n").forEach((line, i) => {
    if (line.trim().startsWith("#")) return;
    for (const [pattern, what] of ALERTS_FORBIDDEN) {
      if (pattern.test(line)) offenders.push(`.github/actions/alert/action.yml:${i + 1} holds ${what}`);
    }
  });
  assert.equal(offenders.join("\n"), "", "the step every alert job calls can do more than alert");

  // The order that makes the two paths to a person independent. If the
  // heartbeat went first, a job that then could not deliver its alarm would
  // already have told the receiver everything was fine.
  //
  // Keyed on the EXACT line that posts the caller's own check, and asserted to
  // appear once. The first spelling of this looked for the last occurrence of
  // `node bot/heartbeat.mjs --check` and was beaten by the mutation it was
  // written for: moving that step to the top leaves BOT-86's `--signal start`
  // line, which is also a heartbeat call and also sits after the alarm, as the
  // last match. Green, with the heartbeat first.
  const BEAT = 'node bot/heartbeat.mjs --check "$ASTRA_ALERT_CHECK"';
  assert.equal(src.split(BEAT).length - 1, 1,
    "the step that posts this check's heartbeat is not in this file exactly once, so the order below is being " +
    "read off the wrong line");
  const alarmAt = src.indexOf("node bot/alert.mjs --verdict");
  assert.ok(alarmAt > 0, "nothing in the alert action sends an alarm");
  assert.ok(src.indexOf(BEAT) > alarmAt,
    "BOT-85's heartbeat must be posted after the alarm, so a channel that is broken takes the receiver's path " +
    "down with it instead of certifying a run that paged nobody");
});

// ─────────────────────────────────────────────────────────────────────────────
// "Never configured yet" is not "configured and broken" (2026-09-19).
//
// The alert action treats the absence of ALL THREE channel secrets as the
// repository before §2.12's R1 act: it says so once, loudly, sets `configured`
// to `false`, sends nothing, posts no heartbeat and does not fail. Anything
// else — one secret present and two gone, a Bot API refusal, a 2xx with no
// `result.date` — is red, unweakened.
//
// Three things have to hold together for that to be an improvement rather than
// a mute button, and each is a separate mutation:
//
//   * the derivation covers every secret `bot/alert.mjs` requires. A fourth
//     added there and not here means a channel missing only its fourth reads
//     as "never created" and goes quiet;
//   * the alarm and the heartbeat are actually skipped in that state, and
//     `--check-credentials` still runs in every other, so the refusals in
//     `bot/alert.mjs` are reached exactly as before;
//   * `alarm-drill.yml` is RED while `configured` is not `true`. Delete that
//     and the state is visible nowhere — which is the failure the noise was
//     protecting against, arrived at from the other side.
// ─────────────────────────────────────────────────────────────────────────────

const ACTION = path.join(REPO, ".github", "actions", "alert", "action.yml");

/** A step list from a `steps:` block, line-oriented like everything else here. */
function stepsOf(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s+- (name|uses):/.test(lines[i])) continue;
    let end = i + 1;
    while (end < lines.length && !/^\s+- (name|uses):/.test(lines[end])) end++;
    out.push({ line: i + 1, body: lines.slice(i, end) });
    i = end - 1;
  }
  return out;
}

const GUARD = "steps.channel.outputs.configured == 'true'";

test("the unconfigured state is derived from the secrets bot/alert.mjs requires, and from nothing else", () => {
  const src = fs.readFileSync(ACTION, "utf8");
  const loop = /\n\s*for name in ([A-Z0-9_ ]+); do\n/.exec(src);
  assert.ok(loop,
    "the alert action no longer counts the channel secrets by name, so nothing here can say what it treats as " +
    "an unconfigured channel");
  assert.deepEqual(
    loop[1].trim().split(/\s+/).sort(),
    REQUIRED_SECRETS.map(([name]) => name).sort(),
    "the action decides `never configured` over a different set of secrets than bot/alert.mjs requires: a " +
    "channel missing only the secret this loop has never heard of would read as a repository whose owner has " +
    "not acted yet, and go quiet",
  );

  // No switch. The state is the absence of all three, and a repository that
  // can declare it can be told to stop alarming for a reason that outlives
  // whoever had it.
  const inputs = src.slice(src.indexOf("\ninputs:"), src.indexOf("\noutputs:"));
  assert.equal(
    [...inputs.matchAll(/^ {2}([a-z0-9-]+):$/gm)].map((m) => m[1]).sort().join(" "),
    "ack-check check no-heartbeat-because verdict",
    "an input was added to the alert action; if it can turn the alarm off, the unconfigured state stopped being " +
    "derived and became declared",
  );
});

test("no alarm and no heartbeat go out while the channel does not exist, and the refusals are otherwise untouched", () => {
  const lines = fs.readFileSync(ACTION, "utf8").split("\n");
  const steps = stepsOf(lines.slice(lines.findIndex((l) => /^\s+steps:\s*$/.test(l))));
  const find = (needle) => steps.find((s) => s.body.some((l) => !l.trim().startsWith("#") && l.includes(needle)));

  const channel = find("node bot/alert.mjs --check-credentials");
  assert.ok(channel, "nothing in the alert action asks bot/alert.mjs whether the channel is whole");
  assert.equal(channel.body.find((l) => /^\s+id:\s*channel\s*$/.test(l)) !== undefined, true,
    "the step that classifies the channel is not `id: channel`, so the guards below name a step that is gone");
  assert.equal(channel.body.some((l) => /^\s+if:/.test(l)), false,
    "the step that asks whether a channel exists is itself conditional; on the run where the condition is false " +
    "nothing asks the question at all");

  for (const [needle, what] of [
    ["node bot/alert.mjs --verdict", "the alarm"],
    ['node bot/heartbeat.mjs --check "$ASTRA_ALERT_CHECK"', "BOT-85's heartbeat"],
  ]) {
    const step = find(needle);
    assert.ok(step, `${what} is no longer in the alert action`);
    const guard = step.body.find((l) => /^\s+if:/.test(l));
    assert.equal(guard?.trim(), `if: ${GUARD}`,
      `${what} is not guarded on the channel existing. Unguarded, every alert job is red again on a state with ` +
      `a named owner act in front of it; guarded on anything but this, it is a switch`);
  }

  // The output the drill reads, sourced from the step that sets it. Deleted,
  // `steps.alert.outputs.configured` is empty everywhere, the drill is red for
  // ever and the reason a reader finds is the wrong one.
  assert.match(fs.readFileSync(ACTION, "utf8"),
    /\n\s*configured:\n[\s\S]*?value: \$\{\{ steps\.channel\.outputs\.configured \}\}/,
    "the alert action declares no `configured` output from the step that decides it");
});

test("the weekly drill is red while the channel does not exist", () => {
  const lines = read("alarm-drill.yml").split("\n");
  const steps = stepsOf(lines);
  const caller = steps.find((s) => s.body.some((l) => /uses:\s*\.\/\.github\/actions\/alert\s*$/.test(l)));
  assert.ok(caller, "the alarm drill no longer calls the alert action");
  const id = caller.body.map((l) => /^\s+id:\s*([A-Za-z0-9_-]+)\s*$/.exec(l)).find(Boolean)?.[1];
  assert.ok(id, "the drill's alert step has no id, so nothing in this workflow can read whether a channel existed");

  const assertion = steps.find((s) => {
    const body = s.body.join("\n");
    return body.includes(`steps.${id}.outputs.configured`) && /\bexit 1\b/.test(body);
  });
  assert.ok(assertion,
    "no step of the alarm drill fails on an unconfigured channel. Every other alert job is green with a notice " +
    "in that state, so this workflow is the one place it is loud: without this step a repository with no way to " +
    "reach a person is green everywhere, which is the failure ninety-six red runs a day were paying for");
  const guard = assertion.body.find((l) => /^\s+if:/.test(l))?.trim();
  assert.equal(guard, `if: steps.${id}.outputs.configured != 'true'`,
    "the drill's assertion does not fire on exactly `not configured`; a condition that also covers the broken " +
    "channel reports the wrong one of the two states");
});

// ─────────────────────────────────────────────────────────────────────────────
// The signer (registry plan D1, RC-R1-2; RC-R3-3; M-T1.7b; M-T3.6).
//
// `sign.yml` is the one publisher of the catalogue, the withdrawal list and
// Pages. Three of its properties are properties of the YAML and of nothing
// else, so they are here rather than in `tools/selftest/`:
//
//   * it HEARS every workflow that commits, by name, read out of the files;
//   * the jobs that publish run none of the checks that must not gate a
//     withdrawal (M-T1.7b);
//   * the receipt it uploads is spelled the way the check that reads it spells
//     it.
// ─────────────────────────────────────────────────────────────────────────────

const SIGNER = "sign.yml";

/** Every name in sign.yml's `workflow_run.workflows:` list. */
function signerHears() {
  const src = read(SIGNER);
  const at = src.indexOf("\n  workflow_run:");
  assert.ok(at > 0, "sign.yml has no workflow_run trigger, so no committer starts it at all");
  const list = /workflows:\s*\[([^\]]*)\]/.exec(src.slice(at));
  assert.ok(list, "sign.yml's workflow_run trigger names no `workflows:` list this test can read");
  return [...list[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

/** A workflow's own `name:`, read from the file. Never inferred from the path. */
function workflowName(file) {
  const line = read(file).split("\n").find((l) => /^name:\s*\S/.test(l));
  return line ? line.replace(/^name:\s*/, "").trim() : null;
}

/** Does any job in this workflow declare `contents: write`? */
const commitsAnything = (file) =>
  // The trailing-comment form is not decoration: `publisher-recheck.yml` says
  // `contents: write   # commit a renewed window, or a withdrawal`, and a
  // `$`-anchored needle walked straight past the one job in this repository
  // whose own comment says out loud that it commits.
  allJobs().some((j) => j.file === file && code(j).some((l) => /^\s+contents:\s*write\s*(#.*)?$/.test(l)));

// The workflows that hold `contents: write` and that the signer deliberately
// does NOT hear, each with the paths it writes. An exception list rather than
// a path scan, and the difference is deliberate: `Ingest` commits `plugins/**`
// from inside `bot/publish-apply.mjs`, not from a line of YAML, so a scan of
// the workflow files would find nothing and pass over the one committer that
// exists. Naming the exceptions puts the question in front of whoever adds the
// next `contents: write` job — which is the moment it can still be answered
// cheaply — and the assertion below refuses an entry that has gone stale.
const NOT_HEARD = new Map([
  [
    "Migration baseline",
    "writes log/decisions/** and log/baseline.json (MIG-20, BOT-73). None of them reaches a signed document: " +
    "D3 counts the catalogue's serial over plugins/ and the list's over tools/revocations/.",
  ],
  [
    "Keepalive",
    "commits state/keepalive.json alone, and that commit exists in order to BE a commit: ROLL-62's monthly " +
    "keepalive (RC-R1-9(b)) is what keeps GitHub from disabling every schedule in this repository after 60 " +
    "days of quiet. state/ is outside both paths D3 counts a serial over — plugins/ for the catalogue and " +
    "tools/revocations/ for the withdrawal list — so there is no document for the signer to refresh, and a " +
    "signer run a month over nothing is one of the three outcomes that workflow's header is written against.",
  ],
  [
    "publisher re-check",
    "commits publishers/** alone. A badge change does reach the catalogue — build-index embeds a publisher " +
    "block per listing — but it reaches it at the next serial rise by design: publishers/ is outside the path " +
    "D3 counts, which is exactly why TRUST-28's equal-serial comparison takes the publisher block off each entry.",
  ],
]);

test("the signer hears every workflow that commits, by the name in the file", () => {
  const heard = signerHears();
  // D1's two names and RC-R3-3's two. Three of the four have no file yet and a
  // trigger naming an absent workflow is inert, so they are listed early on
  // purpose: the alternative is a signer that goes deaf on the day one of them
  // lands and waits an hour for the cron, with nothing red.
  //
  // **This list is RC-R3-3's whole testable half today**, and it is asserted
  // over sign.yml's text rather than over the workflows, because the two R3
  // names have nothing behind them yet. The floor below — how many COMMITTING
  // workflows the signer actually hears — is the half that cannot rise until
  // they land. Watched by removing `Operator` from sign.yml's list, and by
  // removing `Ingest`.
  for (const name of ["Ingest", "Plugins ingest", "Plugins moderation", "Operator"]) {
    assert.ok(heard.includes(name), `sign.yml's workflow_run list does not name ${JSON.stringify(name)} (D1, RC-R3-3)`);
  }

  const committers = files.filter((f) => f !== SIGNER && commitsAnything(f));
  const problems = [];
  const heardCommitters = [];
  for (const file of committers) {
    const name = workflowName(file);
    if (name === null) {
      problems.push(`${file} has a contents: write job and no name: line, so nothing can put it in sign.yml's list`);
      continue;
    }
    if (heard.includes(name)) {
      heardCommitters.push(name);
      continue;
    }
    if (NOT_HEARD.has(name)) continue;
    problems.push(
      `${file} is named ${JSON.stringify(name)}, holds a contents: write job, and sign.yml does not hear it. ` +
      `GITHUB_TOKEN pushes start no push runs (D1), so whatever it commits waits up to an hour for the signer's ` +
      `cron. Add the name to sign.yml's workflow_run list, or add it to NOT_HEARD here with the paths it writes.`,
    );
  }
  // The floor, and it is the one RC-R3-3 raises. One committing workflow is
  // heard today — `Ingest`. It becomes three when M-T3.4's `Plugins
  // moderation` and M-T3.5's `Operator` land, and this number rises with them,
  // in RC-R3-3's commit, which is the task that adds both names to `sign.yml`'s
  // `workflow_run` list. Without it the loop above runs over nothing and
  // reports a signer that hears everything because there is nothing to hear.
  //
  // This comment said "B-T3.10's `Operator`" and was wrong twice, in a way
  // that sent a reader to the wrong task and would have sent a lane to edit a
  // file it did not own. `operator.yml` is M-T3.5's; B-T3.10 publishes what
  // the plugins service pins about the BOT, and its own values say in terms
  // that `operator.yml` is not a bot workflow — it holds no bot token, mints
  // none, and MOD-52 binds it through environment `operator` instead
  // (contract 0.20.0's TRUST-31; registry plan §1.2 and M-T3.5). The floor
  // raise itself is RC-R3-3's `Repo/files` line, not B-T3.10's. Both halves
  // of the sentence had been true of some task; neither was true of that one.
  assert.ok(
    heardCommitters.length >= 1,
    `sign.yml hears ${heardCommitters.length} of this repository's committing workflows and heard 1 on ` +
    `2026-09-19; this is a broken read, not a smaller repository`,
  );
  // An exception that no longer names a workflow is an exception nobody will
  // notice has stopped applying.
  for (const [name, why] of NOT_HEARD) {
    const file = files.find((f) => workflowName(f) === name);
    assert.ok(file, `NOT_HEARD names ${JSON.stringify(name)} and no workflow is called that any more (${why})`);
    assert.ok(
      commitsAnything(file),
      `NOT_HEARD excuses ${JSON.stringify(name)} and ${file} no longer has a contents: write job; delete the entry`,
    );
  }
  assert.equal(problems.join("\n"), "", "a workflow commits and the signer will not hear it");
});

test("the signer runs on a committer's COMPLETION and never on its success", () => {
  // D1: "a run that committed and then failed a later job must not leave its
  // takedown waiting for the cron". `build-index.yml` gates on success for the
  // opposite and correct reason — a failed ingest published nothing to
  // re-check — and the two rules being opposites is exactly how one gets
  // copied into the other.
  const src = read(SIGNER);
  const at = src.indexOf("\n  workflow_run:");
  const trigger = src.slice(at, src.indexOf("\n  schedule:", at));
  assert.match(trigger, /types:\s*\[completed\]/, "sign.yml's workflow_run trigger is not completion-only");
  const offenders = src
    .split("\n")
    .map((l, i) => [l, i + 1])
    .filter(([l]) => !l.trim().startsWith("#") && /workflow_run\.conclusion/.test(l))
    .map(([, n]) => `${SIGNER}:${n}`);
  assert.equal(
    offenders.join(", "),
    "",
    "sign.yml reads the triggering run's conclusion. A committer that failed a later job still committed, and " +
    "gating on success leaves its withdrawal waiting for the hourly cron",
  );
});

// M-T1.7b (MOD-3, MOD-46). What a publishing job may not run.
//
// The rule is one sentence: **nothing that can fail for a reason unrelated to
// the documents may stand between a withdrawal and its publication.** The
// moderation log's own consistency, the coverage canary, the whole registry
// selftest and PRIV-2's scan are all checks this repository needs and all of
// them are checks of something else. A withdrawal held back because
// `log/moderation/**` disagreed with its schema is a plugin left installed.
//
// `site/build.mjs` is the one that is allowed, and only inside a step that
// cannot fail the job: the website is prose, and prose must not be able to
// take the catalogue and the withdrawal list down with it (MOD-46, ROLL-55).
const MUST_NOT_GATE_A_PUBLICATION = [
  "bot/moderation.mjs",
  "tools/moderation-coverage.mjs",
  "tools/selftest.mjs",
  "tools/priv-scan.mjs",
];

/** Does this job publish — hold the key, write `signed`, or deploy Pages? */
function publishes(job) {
  const body = code(job).join("\n");
  if (/^\s+environment:\s*publish\s*$/m.test(body) || /^\s+name:\s*publish\s*$/m.test(body)) return "the publish environment";
  // Pages BEFORE the push heuristic, because the `pages` job reads `signed`
  // through a `git fetch +refs/heads/signed:…` and a needle for that string
  // alone would report it as a pusher — true answer, wrong sentence, and the
  // sentence is what a reader acts on.
  if (/actions\/deploy-pages|upload-pages-artifact/.test(body)) return "a Pages deploy";
  if (/--step\s+commit/.test(body) || /git push[^\n]*\bsigned\b/.test(body)) return "a push to `signed`";
  return null;
}

test("no publishing job runs a check that is about something other than the documents", () => {
  const publishing = allJobs().map((j) => [j, publishes(j)]).filter(([, why]) => why !== null);
  // The floor, written before the mutation: with none found every loop below
  // runs over nothing. Two today — sign.yml's `publish` and `pages`.
  assert.ok(
    publishing.length >= 2,
    `only ${publishing.length} publishing job(s) found and there were 2 on 2026-09-19; this rule would pass by ` +
    `finding nothing`,
  );
  assert.ok(
    publishing.some(([j]) => j.file === SIGNER && j.job === "publish"),
    "sign.yml has no `publish` job, so M-T1.7b's floor is being met by something else",
  );

  const problems = [];
  for (const [job, why] of publishing) {
    const lines = code(job);
    for (let i = 0; i < lines.length; i++) {
      for (const script of MUST_NOT_GATE_A_PUBLICATION) {
        if (lines[i].includes(script)) {
          problems.push(
            `${job.file}:${job.line + i} (job ${job.job}) holds ${why} and runs ${script}; a withdrawal must not ` +
            `wait behind a check that is about something else (M-T1.7b)`,
          );
        }
      }
      if (!lines[i].includes("site/build.mjs")) continue;
      // The step this line is in, and whether that step may fail the job.
      let start = i;
      while (start > 0 && !/^\s+- (name|uses):/.test(lines[start])) start--;
      let end = start + 1;
      while (end < lines.length && !/^\s+- (name|uses):/.test(lines[end])) end++;
      const step = lines.slice(start, end).join("\n");
      if (!/^\s+continue-on-error:\s*true\s*$/m.test(step)) {
        problems.push(
          `${job.file}:${job.line + i} (job ${job.job}) holds ${why} and runs site/build.mjs in a step that can ` +
          `fail the job. A template that cannot render would take the catalogue and the withdrawal list down ` +
          `with it (M-T1.7b, MOD-46, ROLL-55)`,
        );
      }
    }
  }
  assert.equal(problems.join("\n"), "", "a job that publishes can be held back by a check about something else");
});

// SERVE-90's receipt, spelled once (registry plan RC-R1-5, `dev/couplings.md`).
//
// `tools/served-set/provenance.mjs` asks a run for the artifact
// `signed-commit-<the commit's sha>` before it will believe a `Run:` trailer,
// and `sign.yml` is what uploads it. Nothing tied those two spellings
// together: a signer uploading `signed_commit_<sha>`, or a `pages-site`-style
// suffix, makes SERVE-90 red on EVERY `signed` commit for ever — which reads
// as noise and gets switched off, and the check that goes with it is the only
// control left, because SERVE-90 through a ruleset is not expressible on this
// repository (measured 2026-09-19: the bypass list offers four installed Apps,
// roles and deploy keys, and `GitHub Actions` is not among them).
test("the receipt sign.yml uploads is the artifact SERVE-90 looks for", async () => {
  const { SIGNER_EVENTS, receiptName } = await import("../../tools/served-set/provenance.mjs");
  const { SIGNER_WORKFLOW } = await import("../../tools/served-set/main-vs-signed.mjs");

  assert.equal(
    SIGNER_WORKFLOW,
    `.github/workflows/${SIGNER}`,
    "SERVE-90 compares a run's `path` with this string; a signer at another path fails every commit",
  );
  assert.ok(fs.existsSync(path.join(REPO, SIGNER_WORKFLOW)), `${SIGNER_WORKFLOW} is not on disk`);

  const sha = "b".repeat(40);
  const spellings = [...new Set(
    [...read(SIGNER).matchAll(/^\s+name:\s*(signed-commit-.*?)\s*$/gm)].map((m) => m[1]),
  )];
  assert.equal(
    spellings.length,
    1,
    `sign.yml uploads ${spellings.length} distinct receipt name(s) (${spellings.join(" | ") || "none"}); it uploads ` +
    `one name from two steps, the second being the retry, and two spellings would mean one of them is unread`,
  );
  const uploaded = spellings;
  // The template, rendered with a sha, against the function the check uses.
  // Compared as strings rather than by a shared regex, because the failure
  // this is about is two spellings that each look right on their own.
  const rendered = uploaded[0].replace(/\$\{\{[^}]*\}\}/g, sha);
  assert.equal(
    rendered,
    receiptName(sha),
    "sign.yml uploads the receipt under a name provenance.mjs does not look for; SERVE-90 would be red on every " +
    "`signed` commit, and a check that is red on every run is a check somebody turns off",
  );

  // The other half of the same coupling: an event the signer can be started by
  // and SERVE-90 does not accept is a commit the check calls a forgery.
  // The `on:` block ALONE. The first spelling of this took everything above
  // `jobs:` and reported `group` — the workflow's concurrency key — as an
  // event SERVE-90 refuses, which is a test failing for a reason that has
  // nothing to do with what it is about.
  const src = read(SIGNER);
  const lines = src.split("\n");
  const from = lines.findIndex((l) => /^on:\s*$/.test(l));
  assert.ok(from >= 0, "sign.yml has no `on:` block this test can read");
  let to = from + 1;
  while (to < lines.length && !/^\S/.test(lines[to])) to++;
  const triggers = lines
    .slice(from + 1, to)
    .map((l) => /^ {2}([a-z_]+):/.exec(l))
    .filter(Boolean)
    .map((m) => m[1]);
  assert.ok(triggers.length >= 4, `this test read ${triggers.length} trigger(s) in sign.yml; D1 names four`);
  const unaccepted = triggers.filter((t) => !SIGNER_EVENTS.includes(t));
  assert.equal(
    unaccepted.join(", "),
    "",
    `sign.yml can be started by an event SERVE-90 does not list as one the signer runs on (${SIGNER_EVENTS.join(", ")}); ` +
    `every commit a run of that kind makes would be reported as a hand-pushed forgery`,
  );
});

// An alarm speaks for a list of jobs, and the list is written twice.
//
// `sign.yml`'s alert job names `ASTRA_SIGNER_JOBS: publish pages`, and
// `served-set.yml`'s names `ASTRA_SERVED_SET_JOBS: main-vs-signed
// served-vs-signed`. Both composers treat a named job with no variables as a
// job that DID NOT REPORT, which is red — so deleting a job from a workflow
// and forgetting the list pages rather than going quiet, and that direction is
// safe by construction.
//
// **The other direction is silent, and this is the assertion for it.** A job
// that exists, that the alert job waits for, and that is NOT in the list is a
// job whose failure the alarm never mentions: the composer never looks for it,
// the verdict comes out green, and the heartbeat posts. The run is red in the
// Actions tab, where nothing is watching at three in the morning — that is the
// whole reason the alarm channel exists.
//
// Written over every alert job rather than over `sign.yml`'s, because the two
// that exist have the same shape and a rule scoped to one of them is a rule
// the next one will not inherit.
test("an alert job's verdict speaks for every job it waits for", () => {
  const problems = [];
  let checked = 0;
  for (const job of allJobs().filter(inAlerts)) {
    const body = code(job).join("\n");
    const listed = /^\s+ASTRA_[A-Z0-9_]*JOBS:\s*(.+)$/m.exec(body);
    // Not every alert job composes from other jobs — `alarm-drill.yml`'s sends
    // a synthetic alarm of its own — so the absence of a list is not a defect.
    // A list that is present and short is.
    if (!listed) continue;
    checked++;
    const speaksFor = new Set(listed[1].trim().split(/\s+/).filter(Boolean));
    const needs = /^\s+needs:\s*\[?([^\]\n]+)\]?\s*$/m.exec(body)?.[1] ?? "";
    const waitsFor = needs.split(",").map((n) => n.trim()).filter(Boolean);
    assert.ok(
      waitsFor.length >= 1,
      `${where(job)} composes a verdict from other jobs and this test read no \`needs:\`, so it would compare ` +
      `two empty lists`,
    );
    for (const name of waitsFor) {
      if (!speaksFor.has(name)) {
        problems.push(
          `${where(job)} waits for ${name} and its verdict does not speak for it. The composer only looks at the ` +
          `jobs it is named, so a failure of ${name} produces a GREEN verdict and a posted heartbeat, and the ` +
          `only place it shows is a red run nobody is watching`,
        );
      }
    }
    for (const name of speaksFor) {
      if (!waitsFor.includes(name)) {
        problems.push(
          `${where(job)}'s verdict speaks for ${name} and it does not wait for it, so ${name} reports nothing and ` +
          `every run is red about a job that may be fine`,
        );
      }
    }
  }
  assert.ok(checked >= 2, `only ${checked} verdict-composing alert job(s) found; there were 2 on 2026-09-19`);
  assert.equal(problems.join("\n"), "", "an alarm is silent about a job whose failure it is there to report");
});

// ── B-T1.4: the AstraPlugins pin lives in one file ──────────────────────────
//
// Written as a property over the SET of workflows rather than as a list of the
// three that read the pin today. A list is correct on the day it is written:
// the fourth reader is added by somebody who never sees this file, and the way
// it goes wrong is that they copy a literal SHA rather than a `grep` — which a
// list-shaped test cannot notice, because the workflow it would have to notice
// is not on the list.
//
// The pin's old home was `.github/workflows/ingest.yml`, which B-T5.2 DELETES
// at R6. Three readers grepped it out of there, and two of the three turned a
// grep that matched nothing into an error. The third did not.

const PIN_FILE = path.join(REPO, "bot", "manifest-probe", "astra-plugins.pin");
const PIN_REL = "bot/manifest-probe/astra-plugins.pin";

/** The pin file, parsed the way a shell would read it. */
function pinValues() {
  const out = {};
  for (const line of fs.readFileSync(PIN_FILE, "utf8").split("\n")) {
    const m = /^([A-Z_][A-Z0-9_]*)=(.*)$/.exec(line);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

test("the pin file yields a 40-hex ref and an https url", () => {
  assert.ok(fs.existsSync(PIN_FILE), `${PIN_REL} does not exist. It is the only place ASTRA_PLUGINS_REF is written (B-T1.4), and every reader below resolves to nothing without it`);
  const pin = pinValues();
  assert.match(
    pin.ASTRA_PLUGINS_REF ?? "",
    /^[0-9a-f]{40}$/,
    `${PIN_REL} must carry a full 40-hex commit, and carries ${JSON.stringify(pin.ASTRA_PLUGINS_REF ?? null)}. ` +
    "An abbreviated sha is ambiguous to `git fetch` against a repository this one does not control",
  );
  assert.match(
    pin.ASTRA_PLUGINS_URL ?? "",
    /^https:\/\/\S+$/,
    `${PIN_REL}'s ASTRA_PLUGINS_URL must be an https url, and is ${JSON.stringify(pin.ASTRA_PLUGINS_URL ?? null)}. ` +
    "A `git@`/ssh remote needs a key no read-only job holds, and an http one is a manifest rule-set a network can rewrite",
  );
  // The shape a workflow appends to `$GITHUB_ENV`, and a shell sources. A YAML
  // `KEY: VALUE` line here would be read by `grep -E '^KEY='` as nothing, and
  // `>> "$GITHUB_ENV"` would then export nothing, silently.
  assert.ok(
    !/^\s*ASTRA_PLUGINS_(REF|URL)\s*:/m.test(fs.readFileSync(PIN_FILE, "utf8")),
    `${PIN_REL} carries a YAML-style \`KEY: VALUE\` line. This file is KEY=VALUE: every reader greps for the '=' form`,
  );
});

test("every workflow that judges manifests by the pin reads it from the pin file, and none writes it as a literal", () => {
  const mentions = files.filter((f) => /ASTRA_PLUGINS_(REF|URL)/.test(read(f)));
  const readers = [];
  const problems = [];

  for (const f of mentions) {
    const body = read(f);
    // A literal: the name assigned a value that would actually WORK as a pin —
    // a commit-shaped hex string, or a clonable url. Defined that way, rather
    // than as "anything that is not one of these known-good spellings",
    // because the second is a list and this has to hold for a spelling nobody
    // has written yet. A `$VAR`, a `${{ }}` expression, or the pattern inside
    // a `grep -oP` assigns nothing usable and is not a second copy of the
    // decision.
    //
    // This is the mutation the canary is watched by — re-adding the pin to a
    // workflow — and it is the shape a fourth reader arrives in.
    const usable = { REF: /^[0-9a-f]{7,40}$/, URL: /^(https?:\/\/|git@)\S+$/ };
    for (const m of body.matchAll(/^[^#\n]*?ASTRA_PLUGINS_(REF|URL)\s*[:=]\s*(\S+)/gm)) {
      const value = m[2].replace(/^["']|["']$/g, "");
      if (!usable[m[1]].test(value)) continue;
      problems.push(
        `${f} writes ASTRA_PLUGINS_${m[1]} as the literal ${JSON.stringify(value)}. The pin is one decision — ` +
        `which AstraPlugins commit states the manifest rules a stranger's listing is judged by — and a second ` +
        `copy of it is a copy that goes stale with nothing going red. Read ${PIN_REL} instead.`,
      );
    }
    if (body.includes(PIN_REL)) readers.push(f);
    else {
      problems.push(
        `${f} uses ASTRA_PLUGINS_REF/URL and never names ${PIN_REL}, so it is reading the pin from somewhere ` +
        `else. There is nowhere else: ingest.yml stopped carrying it (B-T1.4) and is deleted outright at R6 ` +
        `(B-T5.2), and a grep against a file that is not there yields the empty string, not an error.`,
      );
    }
  }

  // `sign.yml` is not among the readers, and this is a seam rather than a
  // tidiness rule: no signing job reads another repository (registry plan
  // seam 4). A signing job that checks AstraPlugins out has fetched a stranger
  // repository's bytes into the one process that holds a key.
  assert.ok(
    !readers.includes("sign.yml") && !/ASTRA_PLUGINS_(REF|URL)/.test(read("sign.yml")),
    "sign.yml reads the AstraPlugins pin. No signing job reads another repository (seam 4): the pin fetches a " +
    "stranger's tree, and the one job that must not is the one holding a key",
  );

  assert.equal(
    problems.join("\n"),
    "",
    "the pin is written or read somewhere other than " + PIN_REL + ".\n\n" +
    "IF THE FAILURE NAMES bot-tests.yml, THIS IS THE STEP IT IS OWED. This lane may not edit that file; the " +
    "step below replaces its `The AstraPlugins pin ingest.yml judges manifests by` step verbatim:\n\n" +
    "      - name: The AstraPlugins pin this bot judges manifests by\n" +
    "        id: pin\n" +
    "        run: |\n" +
    "          set -euo pipefail\n" +
    "          pin=bot/manifest-probe/astra-plugins.pin\n" +
    "          if [ ! -f \"$pin\" ]; then\n" +
    "            echo \"::error::$pin is missing. It is the only place ASTRA_PLUGINS_REF is written (B-T1.4).\"\n" +
    "            exit 1\n" +
    "          fi\n" +
    "          ref=$(grep -oP '^ASTRA_PLUGINS_REF=\\K[0-9a-f]+' \"$pin\" || true)\n" +
    "          if ! [[ \"$ref\" =~ ^[0-9a-f]{40}$ ]]; then\n" +
    "            echo \"::error::ASTRA_PLUGINS_REF is not a 40-hex commit in $pin: '$ref'\"\n" +
    "            exit 1\n" +
    "          fi\n" +
    "          url=$(grep -oP '^ASTRA_PLUGINS_URL=\\K\\S+' \"$pin\" || true)\n" +
    "          if [ -z \"$url\" ]; then\n" +
    "            echo \"::error::ASTRA_PLUGINS_URL is not in $pin\"\n" +
    "            exit 1\n" +
    "          fi\n" +
    "          echo \"ASTRA_PLUGINS_REF=$ref\" >> \"$GITHUB_ENV\"\n" +
    "          echo \"ASTRA_PLUGINS_URL=$url\" >> \"$GITHUB_ENV\"\n" +
    "          echo \"ok    judging manifests by $ref from $url\"\n",
  );

  // The floor. Without it the whole test above passes vacuously the day
  // somebody renames the variable, or moves the last reader to a composite
  // action: zero mentions is zero problems.
  assert.ok(
    readers.length >= 3,
    `only ${readers.length} workflow(s) read ${PIN_REL} (${readers.join(", ") || "none"}); there were 3 when ` +
    "B-T1.4 landed — ingest.yml, build-index.yml and bot-tests.yml. A reader that stopped reading it is either " +
    "a workflow that no longer needs the pin, or one that grew a second copy somewhere this scan does not look",
  );
});

// ── §2.0, as a check rather than as a sentence in two `Repo/files` lines ─────

test("every suite under bot/tests/ is named by a workflow, and the list has a floor", () => {
  // The failure this ends, measured 2026-09-20: `bot/tests/baseline.test.mjs`
  // (21 tests) and `bot/tests/detectors.test.mjs` (25) had been on `main` for
  // a day and **no workflow ran either of them**. 46 tests, all green on a
  // laptop, executed by nothing — including the one test in the repository
  // that can tell a derived skip from a hard-coded one.
  //
  // It was not a mistake anybody could see. §2.0 says *a new registry test
  // file is a check only once a workflow names it*, and that rule governs
  // forty-seven tasks while being written into the `Repo/files` line of two.
  // A derivation over per-item fields cannot see a rule that quantifies over
  // items, so the lane's plan entry did not carry it, the coordinator added
  // eleven other steps in the same batch, and CI — which only runs what it is
  // told to run — reported green about a suite it had never heard of.
  //
  // Nothing globs here, deliberately: a glob would have hidden this by making
  // every file run, and would also have made a half-written suite a required
  // check the moment it was saved. The answer is not a glob, it is this.
  //
  // Watched red twice, both ways: by deleting the `baseline.test.mjs` step
  // from bot-tests.yml, which names it; and by adding an empty
  // `bot/tests/nobody-runs-this.test.mjs`, which is named as the unrun file.
  // **COMMENT LINES ARE STRIPPED, and that is part of the check rather than
  // tidiness.** The scan is a substring search for the suite's path, so a
  // workflow that MENTIONS a suite in a comment satisfied it exactly as well
  // as one that runs it. A lane could then land a new suite, a header comment
  // saying which suite asserts what about its file, and a green §2.0 check
  // over a test nothing executes — which is this test's own subject arriving
  // one level up, at the check written to hold it. Measured 2026-09-21:
  // `plugins-moderation.yml` landed with M-T3.4's suite named in its header
  // and in no `run:` line, and this assertion stayed green.
  const testsDir = path.join(REPO, "bot", "tests");
  const suites = fs.readdirSync(testsDir).filter((n) => n.endsWith(".test.mjs")).sort();
  const uncommented = (text) => text.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  const everyWorkflow = files.map((f) => uncommented(read(f))).join("\n");

  const unrun = suites.filter((n) => !everyWorkflow.includes(`bot/tests/${n}`));
  assert.deepEqual(
    unrun,
    [],
    `${unrun.length} suite(s) under bot/tests/ are run by no workflow: ${unrun.join(", ")}. ` +
    "A test file no workflow names is a check that does not run, and it reports nothing while it does not " +
    "run — add a step to .github/workflows/bot-tests.yml (§2.0). If a suite is deliberately not a gate, " +
    "that is a decision and it needs a line here saying so, not an absence",
  );

  // Two floors, because this scan can go vacuous in two directions: a readdir
  // that returns nothing makes `unrun` empty, and a workflow set that returns
  // nothing makes every suite look unrun — the second fails loudly, the first
  // does not, which is the one that needs the number.
  assert.ok(
    suites.length >= 14,
    `only ${suites.length} suite(s) found under bot/tests/; there were 14 on 2026-09-20. A walk that lost ` +
    "its directory reports every suite as run",
  );
  assert.ok(files.length >= 10, `only ${files.length} workflow file(s) read; there were 13 on 2026-09-20`);

});
// ─────────────────────────────────────────────────────────────────────────────
// The bot workflows' job graph (registry plan B-T3.1; BOT-1, BOT-2, BOT-4,
// BOT-5, BOT-6, BOT-51, BOT-55, BOT-56, BOT-89, ID-38, INV-7).
//
// `plugins-ingest.yml` is twelve jobs, and every property that makes it safe
// is a property of the YAML: which job may mint a token that speaks for this
// registry, which may write to `main`, which may open a stranger's archive,
// which may reach the alarm channel — and, above all, that no job may do two
// of those. None of it is expressible in the scripts those jobs run, because
// the thing being constrained is what the RUNNER hands the job before a line
// of script executes.
//
// The rule underneath all of them: **each job holds at most one of a bot OIDC
// token, `contents: write`, stranger bytes, an `alerts` credential.** The
// lints below are that sentence taken apart into the mutations that would
// each break one piece of it, because the sentence itself is not checkable and
// the pieces are.
// ─────────────────────────────────────────────────────────────────────────────

// The two workflows that hold a bot OIDC token. Named, rather than derived
// from "mentions plugins-service", because two of the rules below are about
// what a file must NOT contain — and a set defined by a needle cannot hold a
// rule about that needle's absence.
const BOT_WORKFLOWS = ["plugins-ingest.yml", "plugins-moderation.yml"];
const botWorkflows = () => BOT_WORKFLOWS.filter((f) => files.includes(f));

const INGEST = "plugins-ingest.yml";

/** Does this job declare `id-token: write`? */
const mintsToken = (job) => code(job).some((l) => /^\s+id-token:\s*write\s*$/.test(l));
/** Does this job declare `contents: write`? */
const writesRepo = (job) => code(job).some((l) => /^\s+contents:\s*write\s*(#.*)?$/.test(l));
/** Does this job name the plugins-service environment, anywhere? */
const namesService = (job) => code(job).some((l) => l.includes("plugins-service"));

/** The keys of a two-level block (`outputs:`, `env:`) inside a job body. */
function blockKeys(job, block) {
  const lines = code(job);
  const at = lines.findIndex((l) => new RegExp(`^\\s+${block}:\\s*$`).test(l));
  if (at < 0) return null;
  const indent = lines[at].search(/\S/);
  const keys = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (lines[i].trim() === "") continue;
    const here = lines[i].search(/\S/);
    if (here <= indent) break;
    const m = new RegExp(`^\\s{${indent + 2}}([A-Za-z0-9_-]+):`).exec(lines[i]);
    if (m) keys.push(m[1]);
  }
  return keys;
}

/** One job of one file, or a failure that says which is missing. */
function jobOf(file, name) {
  const job = allJobs().find((j) => j.file === file && j.job === name);
  assert.ok(job, `${file} has no \`${name}\` job; the rule below has no subject`);
  return job;
}

test("the bot workflows exist, and this section has something to check", () => {
  const present = botWorkflows();
  assert.ok(
    present.includes(INGEST),
    `${INGEST} is not in .github/workflows. B-T3.1 creates it, and every rule below would pass by finding ` +
    `nothing without it`,
  );
  // The floor B-T3.1 names. Twelve jobs: roots, load, poll, claim, remember,
  // verify, check, ask, decide, alert, publish, report. Fewer means two of
  // them were merged, and merging any two of them is exactly the move every
  // rule in this section exists to refuse.
  const jobs = allJobs().filter((j) => j.file === INGEST);
  assert.ok(
    jobs.length >= 12,
    `${INGEST} has ${jobs.length} jobs and B-T3.1's graph is 12 (${jobs.map((j) => j.job).join(", ")}). ` +
    `The split between them is the whole subject of that file: a job that holds two of {a bot token, ` +
    `contents: write, stranger bytes, the alarm credential} is one exploit away from a bot that can both ` +
    `speak for this registry and write its catalogue`,
  );
  for (const name of ["roots", "claim", "verify", "check", "ask", "decide", "alert", "publish", "report"]) {
    assert.ok(jobs.some((j) => j.job === name), `${INGEST} has no \`${name}\` job`);
  }
});

// BOT-1 and ID-38. A job that mints a token which speaks for this registry
// runs no submitter code, downloads no submitter file and parses no stranger
// text beyond grammar-validated values. "Runs no submitter code" is not a
// property a reviewer can check by reading a job once — the way it stops being
// true is a step added later — so the three things that WOULD make it false
// are named instead, and asserted absent.
//
// Written over every job in the repository rather than over the bot workflows,
// because the property is about the token and the token is what the
// `plugins-service` environment gates.
const SERVICE_JOB_FORBIDDEN = [
  [/gh attestation/, "calls `gh attestation`, which verifies a stranger's bundle"],
  [/gh release download|releases\/download\//, "downloads a release asset"],
  [/\.well-known\//, "reads `.well-known/`, which is a stranger's server's answer"],
  [/bot\/ingest\.mjs/, "runs bot/ingest.mjs, which downloads and unpacks"],
  [/actions\/upload-artifact/, "uploads an artifact; a token job's output travels as a job output (BOT-55)"],
];

test("no job that reaches the plugins service also reaches a stranger's bytes", () => {
  const service = allJobs().filter(namesService);
  // The floor, written before the mutation. With none found the loop runs over
  // nothing and this whole rule is green about a file it never opened.
  assert.ok(
    service.length >= 3,
    `only ${service.length} job(s) reference plugins-service and there were 3 on 2026-09-20 (claim, ask, ` +
    `report); this is a broken read, not a smaller graph`,
  );
  const offenders = [];
  for (const job of service) {
    code(job).forEach((line, i) => {
      for (const [pattern, what] of SERVICE_JOB_FORBIDDEN) {
        if (pattern.test(line)) offenders.push(`${job.file}:${job.line + i} (job ${job.job}) ${what}`);
      }
    });
  }
  assert.equal(
    offenders.join("\n"),
    "",
    "a job holding a bot OIDC token can reach a stranger's bytes. The token is not a read credential: it " +
    "claims submissions, reads binding verdicts and posts results the service records as this registry's " +
    "word (DEC-4). One exploited unpack in that job is a bot that speaks for the registry",
  );
});

// BOT-2. One compromised job must not both speak for the bot and write the
// catalogue. The two halves of the estate's trust in a publication are "the
// service said so" and "the registry committed it", and a job holding both is
// a job that can manufacture the agreement.
test("no job mints a bot token and writes the repository", () => {
  const offenders = allJobs()
    .filter((j) => mintsToken(j) && writesRepo(j))
    .map((j) => where(j));
  assert.equal(
    offenders.join(", "),
    "",
    "a job holds `id-token: write` and `contents: write`. Whoever reaches that job can both claim a " +
    "submission as this registry and commit the listing it claimed (BOT-2)",
  );
});

// ID-38, second half. In a bot workflow, a job either mints a token — and then
// it references `plugins-service` — or it declares `id-token: none` out loud.
//
// The declaration is the point. GitHub's default for an unlisted scope under a
// job-level `permissions:` block is already `none`, so this rule buys nothing
// at run time; it buys the review. A job that grows a token later is then a
// one-line diff from `none` to `write`, in front of a reviewer, instead of a
// `permissions:` block that never mentioned the scope at all.
test("every job in a bot workflow declares what it does about an OIDC token", () => {
  const present = botWorkflows();
  assert.ok(present.length >= 1, "no bot workflow is on disk; this rule has no subject");
  const problems = [];
  let checked = 0;
  for (const job of allJobs().filter((j) => present.includes(j.file))) {
    checked++;
    const declares = code(job).some((l) => /^\s+id-token:\s*(write|none)\s*$/.test(l));
    if (!declares) {
      problems.push(
        `${where(job)} declares no \`id-token:\`. ID-38: the jobs of a bot workflow that do not mint a token ` +
        `say \`id-token: none\`, so that growing one is a visible edit`,
      );
      continue;
    }
    if (mintsToken(job) && !namesService(job)) {
      problems.push(
        `${where(job)} declares \`id-token: write\` and never references plugins-service. ID-38 binds the two: ` +
        `bot/lib/oidc.mjs refuses to run outside that environment, so a token job that is not in it is either ` +
        `red on every run or minting for something else`,
      );
    }
  }
  assert.ok(checked >= 12, `only ${checked} job(s) checked across ${present.join(", ")}; the graph is 12`);
  assert.equal(problems.join("\n"), "", "a bot workflow job is silent about whether it holds a bot OIDC token");
});

// ID-38's last sentence. Outside the bot workflows, `id-token: write` is
// allowed — the Pages deploys need it — but only in jobs that do not reference
// `plugins-service`. An OIDC token minted in a job the service's audience
// would accept, from a workflow nobody is holding to BOT-1, is the boundary
// gone by a different door.
test("`id-token: write` outside the bot workflows never sits beside plugins-service", () => {
  const present = botWorkflows();
  const offenders = allJobs()
    .filter((j) => !present.includes(j.file) && mintsToken(j) && namesService(j))
    .map((j) => where(j));
  assert.equal(
    offenders.join(", "),
    "",
    "a workflow outside the bot's own mints an OIDC token in a job that names plugins-service (ID-38)",
  );
  // The floor: `id-token: write` exists somewhere outside them, so the filter
  // above is filtering something. `sign.yml`'s `pages` job is the case.
  const minters = allJobs().filter((j) => !present.includes(j.file) && mintsToken(j));
  assert.ok(
    minters.length >= 1,
    `no job outside ${present.join(", ")} declares id-token: write, and sign.yml's pages job did on ` +
    `2026-09-20; this rule is passing by finding nothing`,
  );
});

// The `bot-state` environment (B-T5.0, BOT-42), held by `load` and `remember`
// and by nothing else.
//
// Its secret is the HMAC key over the poll and sweep memory, and the attack it
// is guarded against is not theft of the key but FORGERY with it: a writer who
// could read that key could sign a sweep memory in which an unregistered tag
// reads as already seen, and `load`'s signature check would pass because the
// forgery carries the real key. What that suppresses is BOT-87 — the only
// detector for a release that silently never reached the service.
//
// So a `bot-state` job holds the key and nothing else: no token, no write
// access, no release feed, no release download. It DOES restore a cache, which
// is the one difference from an `alerts` job and is the whole reason the
// environment exists.
const BOT_STATE_FORBIDDEN = [
  [/^\s+contents:\s*write\s*(#.*)?$/, "`contents: write`; the memory lives in the Actions cache, never in git"],
  [/^\s+id-token:\s*write\s*$/, "a bot OIDC token"],
  [/secrets\.GITHUB_TOKEN|github\.token/, "the GitHub token"],
  [/releases\.atom/, "the releases feed, which is a stranger's bytes"],
  [/gh release download|releases\/download\//, "a release download"],
];

test("every job in environment `bot-state` holds the memory key and nothing else", () => {
  const stateJobs = allJobs().filter((j) => inEnvironment(j, "bot-state"));
  assert.ok(
    stateJobs.length >= 2,
    `${stateJobs.length} job(s) are in environment bot-state and B-T3.1's graph has 2 (load, remember); ` +
    `with none found every loop below runs over nothing`,
  );
  const offenders = [];
  for (const job of stateJobs) {
    code(job).forEach((line, i) => {
      for (const [pattern, what] of BOT_STATE_FORBIDDEN) {
        if (pattern.test(line)) offenders.push(`${job.file}:${job.line + i} (job ${job.job}) holds ${what}`);
      }
    });
  }
  assert.equal(
    offenders.join("\n"),
    "",
    "a job holding the poll memory's signing key can do more than sign the poll memory. Whoever reaches it " +
    "can forge a sweep memory in which an unregistered tag reads as seen, and BOT-87 — the only detector " +
    "for a release that silently never reached the service — goes quiet about it (attack M-6)",
  );
});

// BOT-4 and BOT-5. Two lints, one test, because they fail the same way: a
// dispatch that can be aimed, and a job group that can drop a pending run.
//
// **Inputs.** A dispatch of a token-holding workflow may mean exactly one
// thing, "pull now". An input is how it comes to mean "pull THIS release, for
// THIS account" — and whoever may dispatch then chooses whose authority the
// run re-proves. `ingest.yml` had exactly that shape and B-T0.6 removed it.
//
// **Job-level concurrency.** GitHub keeps one PENDING run per group and
// cancels the middle one when a third queues. On a workflow-level group that
// is harmless: a run that has not started has claimed nothing. On a JOB-level
// group inside a run that has already claimed leases, it is not — those
// submissions are then leased to a run that will never report, and they wait
// out the lease before anybody can have them.
test("a bot workflow takes no dispatch input and puts no job in its own group", () => {
  const present = botWorkflows();
  assert.ok(present.length >= 1, "no bot workflow is on disk; this rule has no subject");
  const problems = [];
  for (const file of present) {
    const lines = read(file).split("\n");

    const at = lines.findIndex((l) => /^\s{2}workflow_dispatch:/.test(l));
    assert.ok(at >= 0, `${file} has no workflow_dispatch trigger`);
    let end = at + 1;
    while (end < lines.length && (lines[end].trim() === "" || /^\s{4}/.test(lines[end]))) end++;
    const body = lines.slice(at + 1, end).filter((l) => l.trim() && !l.trim().startsWith("#"));
    if (body.length > 0) {
      problems.push(
        `${file}'s workflow_dispatch carries ${JSON.stringify(body.join(" ").trim())}. BOT-4: a dispatch of a ` +
        `token-holding workflow means "pull now" and nothing else; an input lets whoever may press the button ` +
        `aim one run at one release`,
      );
    }

    for (const trigger of ["repository_dispatch"]) {
      const line = lines.findIndex((l) => new RegExp(`^\\s{2}${trigger}:`).test(l));
      if (line >= 0) problems.push(`${file}:${line + 1} declares ${trigger}, which BOT-4 refuses in a bot workflow`);
    }

    for (const job of allJobs().filter((j) => j.file === file)) {
      code(job).forEach((l, i) => {
        if (/^\s+concurrency:/.test(l)) {
          problems.push(
            `${file}:${job.line + i} (job ${job.job}) is in a concurrency group of its own. BOT-5: one group ` +
            `for the workflow, cancel-in-progress: false, and none on a job — a cancelled job inside a run ` +
            `that already claimed leaves those leases to expire`,
          );
        }
      });
    }

    const src = read(file);
    const workflowGroup = /^concurrency:\n(?:\s+#.*\n)*\s+group:\s*\S+/m.test(src);
    if (!workflowGroup) problems.push(`${file} declares no workflow-level concurrency group (BOT-5)`);
    if (!/^\s{2}cancel-in-progress:\s*false\s*$/m.test(src)) {
      problems.push(`${file}'s workflow-level group is not cancel-in-progress: false (BOT-5)`);
    }
  }
  assert.equal(problems.join("\n"), "", "a bot workflow can be aimed, or can drop a run that already claimed");
});

// BOT-56. A bot job holding a bot OIDC token or `contents: write` restores no
// Actions cache and downloads no artifact by pattern.
//
// Both are bytes some other job produced. An artifact pattern in the job that
// commits is the door `ingest.yml`'s publish job still has — it downloads
// `pattern: ingest-report-*` — and that is tolerable there only because the
// job that produces them holds no token. In `plugins-ingest.yml` the producing
// job unpacks a stranger's archive, so the credentialled jobs take exactly the
// names `claim` reported and nothing that merely matches them.
test("no token job and no write job in a bot workflow globs an artifact or restores a cache", () => {
  const present = botWorkflows();
  assert.ok(present.length >= 1, "no bot workflow is on disk; this rule has no subject");
  const credentialled = allJobs().filter((j) => present.includes(j.file) && (mintsToken(j) || writesRepo(j)));
  assert.ok(
    credentialled.length >= 4,
    `${credentialled.length} credentialled job(s) found in ${present.join(", ")} and there were 4 on ` +
    `2026-09-20 (claim, ask, report, publish); this rule would pass by finding nothing`,
  );
  const problems = [];
  for (const job of credentialled) {
    const lines = code(job);
    lines.forEach((line, i) => {
      if (/^\s+pattern:\s*\S/.test(line)) {
        problems.push(
          `${job.file}:${job.line + i} (job ${job.job}) downloads artifacts by pattern while holding a ` +
          `credential. BOT-56: a pattern takes whatever was uploaded under a matching name, and the job that ` +
          `uploads in this graph is the one that opened a stranger's archive`,
        );
      }
      if (/uses:\s*actions\/cache/.test(line)) {
        problems.push(
          `${job.file}:${job.line + i} (job ${job.job}) restores an Actions cache while holding a credential. ` +
          `BOT-56: a cache is bytes a pull request can poison`,
        );
      }
    });
  }
  assert.equal(problems.join("\n"), "", "a credentialled bot job takes bytes another job chose the name of");
});

// BOT-55. What `decide` may take from the job that opened the archive, and
// what `publish` and `report` may take from anybody.
//
// `decide` holds nothing — no token, no write, no key — so it is the one place
// in the graph where globbing over other jobs' uploads costs nothing, and it
// is therefore the funnel. Everything downstream of it takes one artifact by
// one exact name. The rule below is the property that makes the funnel real:
// the two `check` artifacts are `facts-` and `listing-` and there is no third.
test("`check` uploads exactly the two artifacts the rest of the graph expects", () => {
  const job = jobOf(INGEST, "check");
  // The `name:` of each upload step, read out of that step and not out of the
  // job: a job-wide scan for `name:` takes every step's own title and every
  // download's artifact too, and reports a job that uploads nine things.
  const uploaded = stepsOf(code(job))
    .filter((s) => s.body.some((l) => /uses:\s*actions\/upload-artifact/.test(l)))
    .map((s) => /^\s+name:\s*(.+?)\s*$/m.exec(s.body.join("\n"))?.[1] ?? "(no name:)");
  assert.deepEqual(
    uploaded,
    ["facts-${{ matrix.submission_id }}", "listing-${{ matrix.submission_id }}"],
    "the job that unpacks a stranger's archive uploads something other than exactly `facts-<submission_id>` " +
    "and `listing-<submission_id>`. A third artifact is a third channel out of the one job in this graph " +
    "that runs code from a release, and nothing downstream validates a name it was not expecting (BOT-55)",
  );
});

// BOT-89, and it is a privacy rule as much as a security one.
//
// The run logs of this repository are public. A binding verdict is a fact
// about a person's GitHub account and the state of a token they hold; an
// eligibility value is a fact about whether the service will let them publish.
// Contract BOT-89: the bot MUST NOT print any of it in a run log, a step
// summary, an artifact or a commit — the job that asks outputs only the
// outcome the bot acts on, and that outcome comes from a closed list of four.
//
// Two assertions, because the list and the output are two different ways to
// leak. A second declared output is a value in the run's own metadata; a fifth
// word in the list is a value the step may write into the one output there is.
test("`ask` declares one output, and the four words it is allowed to contain", () => {
  const job = jobOf(INGEST, "ask");

  assert.deepEqual(
    blockKeys(job, "outputs"),
    ["outcome"],
    "the verdict job declares an output other than `outcome`. BOT-89: what it asked the service is a fact " +
    "about somebody's account, and this repository's run metadata is public — the job outputs the outcome " +
    "the bot ACTS on and nothing it was told",
  );

  const declared = /^\s+ASTRA_ASK_OUTCOMES:\s*(.+)$/m.exec(code(job).join("\n"))?.[1];
  assert.ok(
    declared,
    "the verdict job declares no ASTRA_ASK_OUTCOMES. The four values BOT-89 allows are written in the job " +
    "rather than only inside a script so that a fifth one is a visible edit, and so that this test can see " +
    "the list the step validates against",
  );
  assert.deepEqual(
    declared.trim().split(/\s+/).sort(),
    ["B_BINDING_UNUSABLE", "W_ELIGIBILITY_UNREADABLE", "pass", "shadow"].sort(),
    "the verdict job's outcome vocabulary is not BOT-89's four (`pass`, `B_BINDING_UNUSABLE`, " +
    "`W_ELIGIBILITY_UNREADABLE`, `shadow`). A fifth value is either a verdict reaching a public log, or a " +
    "state the deciding job has no rule for",
  );
});

// BOT-6. The report job runs only after its commit job SUCCEEDED.
//
// `needs: publish` alone does not say that: under `always()` a job runs over a
// dependency that failed, and this is the job that tells the service — and
// through it the author — that something landed. A promise without a commit is
// this registry's oldest defect.
test("`report` cannot outrun the commit whose result it reports", () => {
  const job = jobOf(INGEST, "report");
  const needs = /^\s+needs:\s*(.+)$/m.exec(code(job).join("\n"))?.[1] ?? "";
  assert.match(needs, /\bpublish\b/, "the report job does not wait for publish (BOT-6)");
  const cond = condition(job);
  assert.ok(
    !/always\(\)/.test(cond) || /needs\.publish\.result\s*==\s*'success'/.test(cond),
    `the report job's condition is ${JSON.stringify(cond)}: it runs on always() and never asks whether the ` +
    `commit succeeded, so a failed publish still posts a result the service records as this registry's word`,
  );
});

// A placeholder that exits 0 is the failure this estate has paid for twice.
//
// `plugins-ingest.yml` lands before the scripts of most of its jobs exist, and
// each such step says so and exits non-zero, naming the task that replaces it.
// The mutation this guards is not malice: it is somebody wiring up half a job,
// leaving the other half's placeholder in place, and softening it to an echo
// so the run goes green. The run then reports success for work nobody wrote —
// which is what a release workflow whose comment described a checkout step
// that was never written looked like from outside.
test("a step marked `not built` cannot let its job report success", () => {
  const problems = [];
  let found = 0;
  for (const job of allJobs().filter((j) => j.file === INGEST)) {
    const lines = code(job);
    for (let i = 0; i < lines.length; i++) {
      if (!/^\s+- name:.*\(not built:/.test(lines[i])) continue;
      found++;
      let end = i + 1;
      while (end < lines.length && !/^\s+- (name|uses):/.test(lines[end])) end++;
      const step = lines.slice(i, end).join("\n");
      const label = `${INGEST}:${job.line + i} (job ${job.job})`;
      if (!/\bexit 1\b/.test(step)) {
        problems.push(
          `${label} is marked \`not built\` and cannot fail its job. A placeholder that exits 0 reports ` +
          `success for work nobody has written`,
        );
      }
      if (/^\s+continue-on-error:\s*true\s*$/m.test(step)) {
        problems.push(`${label} is marked \`not built\` and carries continue-on-error: true, which is the same thing`);
      }
      if (!/::error::/.test(step)) {
        problems.push(`${label} is marked \`not built\` and prints no ::error::, so the reason is not in the log`);
      }
    }
  }
  // The floor. When every job is built this number is 0 and the rule becomes
  // vacuous — correctly, and visibly, because this assertion is what has to be
  // deleted for that to happen.
  assert.ok(
    found >= 1,
    `no \`not built\` step was found in ${INGEST}, and there were 10 on 2026-09-20 — counted from the step ` +
    `names and not from the marker, which also appears once in the file's header comment. Either every job is ` +
    `now ` +
    `built — in which case delete this floor in the commit that builds the last one — or the marker was ` +
    `renamed and this rule has stopped applying to anything`,
  );
  assert.equal(problems.join("\n"), "", "a placeholder step can let its job report success");
});

// ── BOT-51's interval, and the two places it is written ─────────────────────
//
// The ingest workflow claims on a schedule whose interval is at most 600 s.
// Since contract amendment A6 that is a MUST, recorded in SCOPE-7's token file
// and in ROLL-7's R0 file, and SCOPE-1 makes an interval change a contract
// MINOR version published BEFORE the cron edit. So the cron line is not a
// tuning knob: it is one end of a three-way agreement between this file, the
// token file and a published contract version.
//
// This is the workflow half. RC-R2-2 runs the same comparison from
// `tools/selftest/` once `schema/contract-tokens-v1.json` exists, and the
// interval is asserted here as a literal as well, so that the check says
// something on the day the token file does not exist yet — which is today.
//
// **The cron line is read whether it is commented out or not.** The file lands
// dark at R2 exit with the schedule commented and the R3-open commit
// uncomments it (§2.5). A test that only read a live `schedule:` block would
// assert nothing for the whole of R2 and then start asserting, unwatched, in a
// commit about something else.

const BOT51_INTERVAL_SECONDS = 600;
const TOKEN_FILE = path.join(REPO, "schema", "contract-tokens-v1.json");

/** Every `- cron: '…'` in a workflow, live or commented, with its line. */
function crons(file) {
  const out = [];
  read(file).split("\n").forEach((line, i) => {
    const m = /^\s*#?\s*-\s*cron:\s*['"]([^'"]+)['"]/.exec(line);
    if (m) out.push({ expr: m[1], line: i + 1, commented: /^\s*#/.test(line) });
  });
  return out;
}

/** Does the minute field of a cron expression fire at this minute? */
function firesAt(field, minute) {
  return field.split(",").some((part) => {
    const [range, stepText] = part.split("/");
    const step = stepText === undefined ? 1 : Number(stepText);
    if (!Number.isInteger(step) || step < 1) return false;
    let from;
    let to;
    if (range === "*") { from = 0; to = 59; }
    else if (/^\d+-\d+$/.test(range)) { [from, to] = range.split("-").map(Number); }
    else if (/^\d+$/.test(range)) { from = Number(range); to = stepText === undefined ? from : 59; }
    else return false;
    return minute >= from && minute <= to && (minute - from) % step === 0;
  });
}

/**
 * The seconds between two firings of a cron expression, or a reason there is
 * no single such number.
 *
 * Computed from the minutes it actually fires at rather than read off the
 * `/n`, because `/n` is not the interval: `3-40/10` fires at 3, 13, 23 and 33
 * and then waits thirty minutes for the next hour. A rule that read the `10`
 * would call that a 600-second schedule, which is the number BOT-51 is a MUST
 * about.
 */
function cronIntervalSeconds(expr) {
  const fields = expr.trim().split(/\s+/);
  if (fields.length !== 5) return { error: `${JSON.stringify(expr)} is not five cron fields` };
  if (fields.slice(1).some((f) => f !== "*")) {
    return { error: `${JSON.stringify(expr)} is not every hour of every day, so it has no single interval` };
  }
  const fire = [];
  for (let m = 0; m < 60; m++) if (firesAt(fields[0], m)) fire.push(m);
  if (fire.length < 2) return { error: `${JSON.stringify(expr)} fires ${fire.length} time(s) an hour` };
  const gaps = fire.map((m, i) => (i === 0 ? fire[0] + 60 - fire[fire.length - 1] : m - fire[i - 1]));
  const distinct = [...new Set(gaps)];
  if (distinct.length !== 1) {
    return { error: `${JSON.stringify(expr)} fires at uneven gaps of ${distinct.join(", ")} minutes` };
  }
  return { seconds: distinct[0] * 60, minutes: fire };
}

/** Every `{path, value}` in the token file that looks like the ingest interval. */
function tokenFileIngestIntervals() {
  const json = JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));
  const found = [];
  const walk = (node, at) => {
    if (Array.isArray(node)) { node.forEach((v, i) => walk(v, `${at}[${i}]`)); return; }
    if (node === null || typeof node !== "object") return;
    const context = JSON.stringify(node);
    for (const [key, value] of Object.entries(node)) {
      if (typeof value === "number" && /interval/i.test(key) && /ingest/i.test(context) && !/moderation/i.test(context)) {
        found.push({ path: `${at}.${key}`, value });
      }
      walk(value, `${at}.${key}`);
    }
  };
  walk(json, "$");
  return found;
}

test("the ingest cron is BOT-51's interval, and the token file agrees once it exists", () => {
  const found = crons(INGEST);
  assert.equal(
    found.length,
    1,
    `${INGEST} carries ${found.length} cron expression(s) (${found.map((c) => c.expr).join(" | ") || "none"}) ` +
    `and BOT-51 is one schedule. A second one is a second interval, and the token file records one number`,
  );

  const [cron] = found;
  const interval = cronIntervalSeconds(cron.expr);
  assert.ok(!interval.error, `${INGEST}:${cron.line}: ${interval.error}`);
  assert.equal(
    interval.seconds,
    BOT51_INTERVAL_SECONDS,
    `${INGEST}:${cron.line} claims every ${interval.seconds} s and BOT-51 pins ${BOT51_INTERVAL_SECONDS} s. ` +
    `That number is a contract MUST since amendment A6 and is recorded in the token file and in ROLL-7's R0 ` +
    `file; SCOPE-1 makes a change to it a contract MINOR version published BEFORE this line moves. Changing ` +
    `the cron first is the wrong order, and it also silently moves BOT-47's, BOT-76's and BOT-84's alarm ` +
    `bounds, which are all "max(5400 s, 3 × this interval)"`,
  );
  // Minutes off the hour, as BOT-51 words it: the moderation run's cron sits
  // five minutes away from these, so a run of each never starts in the same
  // minute as the other.
  assert.ok(
    !interval.minutes.includes(0),
    `${INGEST}:${cron.line} fires on the hour. BOT-51 says "at minutes off the hour", and BOT-83 puts the ` +
    `moderation run five minutes from these`,
  );

  if (!fs.existsSync(TOKEN_FILE)) {
    // Not a skip. The comparison RC-R2-1's file makes possible is not running,
    // and the reason is a file that does not exist yet — which this test says
    // out loud rather than passing quietly on one of its two halves.
    console.log(
      `note  schema/contract-tokens-v1.json is not on disk (RC-R2-1, due before R2 opens), so the cron above ` +
      `was compared with BOT-51's literal ${BOT51_INTERVAL_SECONDS} and with nothing else. RC-R2-2 runs the ` +
      `same comparison from tools/selftest/ once the file exists.`,
    );
    return;
  }

  const recorded = tokenFileIngestIntervals();
  assert.ok(
    recorded.length >= 1,
    `schema/contract-tokens-v1.json exists and this test found no ingest schedule interval in it. SCOPE-7 ` +
    `says the file carries "the schedule interval of the ingest and moderation workflows (BOT-51; BOT-83)", ` +
    `so either RC-R2-1's generator does not emit it — which is the defect — or it emits it under a shape this ` +
    `walk does not recognise, in which case teach the walk rather than deleting this assertion. A cron and a ` +
    `token file that are never compared are the two ends of SCOPE-1 with nothing between them`,
  );
  for (const { path: at, value } of recorded) {
    assert.equal(
      value,
      interval.seconds,
      `the token file records ${value} s for the ingest schedule at ${at} and ${INGEST}:${cron.line} claims ` +
      `every ${interval.seconds} s. The service computes BOT-47's silence bound from the token file's number ` +
      `and this workflow runs on the other one, so the two disagree about when a missing run is an outage`,
    );
  }
});

// The service path commits through the same file the legacy path does.
//
// `bot/publish-apply.mjs` carries the BOT-33 allow-list, the re-validation and
// the race handling, and its own refusal function says out loud that the
// `publish` job it belongs to is this workflow's. Two committers with two
// allow-lists is two answers to "what may a bot job write", and the second one
// is written by somebody who has not read the first.
test("`plugins-ingest.yml`'s publish job commits through publish-apply and not by hand", () => {
  const job = jobOf(INGEST, "publish");
  const body = code(job).join("\n");
  assert.match(
    body,
    /node bot\/publish-apply\.mjs/,
    "the service path's publish job does not go through bot/publish-apply.mjs. That file is where BOT-33's " +
    "allow-list, INV-12's version check and the two-runs-racing refusal live; a second committer is a second " +
    "answer to what a bot job may write to `main`",
  );
  assert.ok(
    !/^\s+run:[\s\S]*?git (commit|push)/m.test(body.replace(/node bot\/publish-apply\.mjs[\s\S]*/, "")),
    "the service path's publish job runs `git commit` or `git push` of its own before publish-apply.mjs, so " +
    "something reaches `main` without the rules that file holds",
  );
});
