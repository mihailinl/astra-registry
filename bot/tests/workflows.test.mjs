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

/** Is this job pinned to environment `alerts`? Both spellings YAML allows. */
function inAlerts(job) {
  for (let i = 0; i < job.body.length; i++) {
    if (/^\s+environment:\s*alerts\s*$/.test(job.body[i])) return true;
    if (/^\s+environment:\s*$/.test(job.body[i]) && /^\s+name:\s*alerts\s*$/.test(job.body[i + 1] ?? "")) return true;
  }
  return false;
}

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
test("every job in ingest.yml waits for the roots check", () => {
  const jobs = allJobs().filter((j) => j.file === "ingest.yml");
  assert.ok(jobs.length >= 8, `only ${jobs.length} job(s) in ingest.yml; this check would prove little`);
  assert.ok(jobs.some((j) => j.job === "roots"), "ingest.yml has no roots job");

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
  assert.equal(problems.join("\n"), "", "a job in ingest.yml can outrun the check that says the anchor is sound");
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
    // input. `ingest.yml` is the case that exists: BOT-51's schedule is
    // deliberately outside BOT-85's list because the service's BOT-47 watches
    // it.
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
