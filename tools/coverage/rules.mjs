// Every rule the coverage canary's `check` job runs, and the one way a rule
// reports what it found.
//
// ── WHY THERE IS A REGISTER AT ALL ──────────────────────────────────────────
//
// The registry plan gives M-T1.5's `check` job EIGHT rules and six of them
// belong to other tasks, landing across R1, R2, R3 and R6: M-T1.3's docs grep,
// M-T5.7's mirror-staleness alarm, M-T2.1's examples rule, M-T5.8's badge
// trailer, the ROLL-47 promise greps, RC-R1-9(b)'s keepalive age, and M-T6.2's
// no-issue-channel rule. Six of the eight have landed; the seam below carries
// what is left. Eight steps in one job, each `if: always()` so one red
// rule does not hide the next, is easy. The failure that shape permits is not:
// a step that never ran — a typo in a path, a `continue-on-error` somebody
// added while debugging, a step deleted in a merge, a rule that threw before
// it printed anything — leaves the job green, the verdict green, and the alarm
// silent, about a rule nobody can tell was not applied.
//
// So the job does not compose its own verdict out of exit codes. Each rule
// APPENDS a line to one findings file; `tools/coverage-verdict.mjs` reads that
// file and compares the reporters against the list below. A rule that is
// listed and did not report is red (`E_RULE_DID_NOT_REPORT`), and a rule that
// reported and is not listed is red too (`E_RULE_UNDECLARED`). Both directions,
// because both are somebody halfway through landing a rule.
//
// ── HOW A NEW RULE LANDS (M-T1.3, M-T5.7, M-T2.1, M-T5.8, M-T6.2) ───────────
//
// Three things, in one commit:
//
//   1. a script that ends with `report(<name>, {status, codes, ids, hexes,
//      detail})` from this file, and exits 0 whether it found anything or not
//      — the exit code is not the signal, the line is;
//   2. one entry in `RULES` below;
//   3. one step in `.github/workflows/moderation-coverage.yml`'s `check` job,
//      `if: always()`, running that script with
//      `--report "$ASTRA_COVERAGE_FINDINGS"`.
//
// Miss (2) and the verdict is red naming your rule. Miss (3) and it is red
// naming your rule. Miss (1) and the step fails, which is also red. There is no
// arrangement of the three that is quietly green, and that is the whole point
// of the register.
//
// A rule that needs the network (M-T5.7 and M-T2.1 both fetch an AstraPlugins
// default branch with no credential; `repo-settings` reads api.github.com, with
// the workflow's own read-only token for the rate limit and never one that can
// write) sets `network: true`. Nothing branches on it today; it is there so that
// the first person who has to say "which of these can fail because GitHub was
// slow" can read the answer instead of grepping for `fetch`.
//
// ── WHAT A RULE MAY PUT IN A VERDICT ────────────────────────────────────────
//
// `codes`, `ids` and `hexes`, and nothing else — the three lists
// `bot/lib/alert-verdict.mjs` will render. `detail` is for the run log and the
// job summary and NEVER reaches Telegram. That split is not tidiness: a
// moderation reason, a plugin's name and a commit subject are all bytes a
// stranger chose, the alarm channel is this estate's one path to a person, and
// a stranger who can write into it is a stranger who can bury the alarm
// underneath their own text. The verdict grammar refuses free text; `detail`
// is where the sentence a human needs goes, on the run page, behind a login.

import fs from "node:fs";
import path from "node:path";

/**
 * The rules the `check` job runs. Order is the order they are listed in the
 * job summary; it has no other meaning.
 *
 * `owner` is the task that owns the RULE, which is not always the task that
 * owns this file — M-T1.5 owns the job and the register, and M-T1.3 owns what
 * its own grep asserts.
 */
export const RULES = [
  {
    name: "moderation-coverage",
    owner: "M-T1.5 (MOD-39, MOD-34, MOD-46)",
    script: "tools/moderation-coverage.mjs",
    what: "every delist, yank and advisory in state and in the walk is covered by a log entry, an author-action record or a trailer",
    network: false,
  },
  {
    name: "priv-scan",
    owner: "M-T1.5 (PRIV-2's published check, PRIV-10)",
    script: "tools/priv-scan.mjs",
    what: "no composed document or commit body carries an address, a handle, a Telegram id or a stray UUID",
    network: false,
  },
  {
    name: "keepalive-age",
    owner: "M-T1.5 for the alarm, RC-R1-9(b) (ROLL-62) for the commit",
    script: "tools/coverage/keepalive-age.mjs",
    what: "state/keepalive.json is no more than 35 days old, so no schedule in this repository is 60 days from being disabled",
    network: false,
  },
  {
    name: "drain-age",
    owner: "M-T1.5 for the alarm, PRODUCTION_PLAN 3.4/3.5 (BOT-33, BOT-38) for the schedule it watches",
    script: "tools/coverage/drain-age.mjs",
    what:
      "ingest.yml still routes a live cron to `bot/watch.mjs --drain`, state/releases-seen.json is under 72 h " +
      "old, and no queue entry is more than 24 h past its own publish_after — a stopped drain and a drain that " +
      "runs and publishes nothing are different faults and only the second has any other symptom",
    network: false,
  },
  {
    name: "docs-advisory-url",
    owner: "M-T1.3 (MOD-13, precondition)",
    script: "tools/coverage/docs-advisory-url.mjs",
    what: "tools/revocations/README.md names no github.com or github.io advisory URL, no advisory_url under another base, and still tells an operator what to do with the field",
    network: false,
  },
  {
    name: "reserved-id-mirror",
    owner: "M-T5.7 (OPEN-OPS-11, the registry half)",
    script: "tools/coverage/reserved-id-mirror.mjs",
    what: "policy/reserved-ids.json and AstraPlugins' spec/reserved-ids.yaml name the same set, in both directions — `pending` until AP-7 writes that file",
    network: true,
  },
  {
    name: "examples-staging-id",
    owner: "M-T2.1 (MOD-16, TRUST-26)",
    script: "tools/coverage/examples-staging-id.mjs",
    what: "no AstraPlugins examples/*/plugin.toml declares, or is named for, policy/reserved-ids.json's staging_listing_id",
    network: true,
  },
  {
    name: "repo-settings",
    owner: "RC-R0-4 (ROLL-7, ROLL-8) for the settings it holds; ops dev/couplings.md gap 22 for the check",
    script: "tools/coverage/settings.mjs",
    what:
      "every environment and ruleset GitHub serves for astra-registry and AstraPlugins is the one " +
      "policy/settings-expected.json records, in both directions, and every environment a workflow job names is " +
      "live with a custom branch policy, or pending creation and named only by jobs a literal `if: false` holds",
    network: true,
  },
  // ── the seam. Each line below is one other task's, and lands with it. ─────
  //
  // Written here as a comment rather than as a disabled entry, because an
  // entry with no script is a rule that reports nothing, and a rule that
  // reports nothing is red on every run from the day this lands until the day
  // that task does — which for M-T6.2 is R6. An alarm that fires for six
  // milestones is an alarm somebody switches off in month one (TRUST-45).
  //
  //   { name: "roll47-promises",     owner: "M-T4.2, M-T4.3, M-T6.2",  … }          R4a
  //   { name: "no-issue-channel",    owner: "M-T6.2 (DEC-12)",         … }          R6
  //
  // M-T5.8's badge-withdrawal trailer is NOT a line here: the plan puts it
  // inside `tools/moderation-coverage.mjs`'s walk, beside the rules it is one
  // of, and that file carries the seam for it instead.
];

/**
 * Owner acts this job cannot perform, printed on every run.
 *
 * "Pending" is deliberately not "red". A red canary means somebody has to go
 * and look now; a pending act means the owner has to do something before a
 * milestone. Rendering the second as the first is how the first stops being
 * believed. But leaving it out entirely is how a step that was never performed
 * becomes a step nobody remembers was owed — which is exactly what happened to
 * the live half of this canary, planned in one line of one document and
 * findable nowhere else. So it is on the run page of every scheduled run, and
 * `bot/tests/moderation-coverage.test.mjs` fails if this list is emptied while
 * the record it names is still absent.
 */
export const PENDING_OWNER_ACTS = [
  {
    id: "live-once",
    task: "M-T1.5",
    record: "state/coverage-live-run.json",
    act:
      "OWNER APPROVAL: a fixture repository for the live run — a new one, or the reuse of BOT-88's test " +
      "repository (registry plan §2.13, ext.6). The run is: this workflow, in that repository, with a " +
      "workflow there pushing an uncovered `yanked` commit under GITHUB_TOKEN; the scheduled run finds it " +
      "within 15 minutes, the alarm arrives, and a `Moderation-Exempt: <sha>: …` commit clears it. Until it " +
      "is done, the one thing this canary has never been watched doing is finding a real uncovered commit " +
      "that a real token push put on a real branch — which is the only part of it that GITHUB_TOKEN's " +
      "no-recursion rule can break without any fixture noticing. Record it in " +
      "`state/coverage-live-run.json` (`{run, at, fixture_repo, alarm_delivered_at}`) and under ROLL-1.",
  },
  {
    id: "ingest-schedule-receiver",
    task: "M-T1.5 for the rule, BOT-85 for the receiver",
    record: "state/ingest-schedule-watch.json",
    act:
      "OWNER: `drain-age` turns this canary red when ingest.yml's schedule stops, which is a red X in the " +
      "Actions tab and an alarm on whatever environment `alerts` carries. It does NOT page, and the reason is " +
      "structural rather than unfinished: the rule runs inside moderation-coverage.yml, which is itself a " +
      "schedule in this repository, so the one case it cannot report is the case where Actions is disabled and " +
      "BOTH schedules stop together — a liveness check that dies with what it watches has the ambiguity it was " +
      "built to remove. The half that closes it is BOT-85's `coverage-canary` receiver, which pages on this " +
      "workflow's silence from OFF this box; `bot/lib/alert-checks.mjs` declares it at 900 s and nothing in " +
      "this repository can prove the receiver exists. Stand it up, post one heartbeat, watch it page after " +
      "the silence bound `boundMinutes()` gives it (a day, the floor for a poster GitHub schedules), and " +
      "record it in `state/ingest-schedule-watch.json` " +
      "(`{at, receiver, check, silence_paged_at}`). Until then the inner guard is the whole guard, and it is " +
      "deliberately not waiting: `ingest.yml` carried a written claim that the plugins service's BOT-47 " +
      "watched this schedule, and a claim of coverage is what stops anybody looking.",
  },
];

/**
 * The acts above whose record is still absent.
 *
 * Derived rather than hand-maintained, so the line retires itself on the day
 * the act is performed. A pending notice that has to be DELETED by hand is a
 * pending notice that is still being printed a year later, and the third time
 * a reader sees a stale one they stop reading the others.
 *
 * @param {string} repo repository root
 */
export function outstandingActs(repo, acts = PENDING_OWNER_ACTS) {
  return acts.filter((a) => !fs.existsSync(path.join(repo, a.record)));
}

/** @returns {string[]} the names in `RULES`, in order */
export const ruleNames = () => RULES.map((r) => r.name);

/** @returns {object|undefined} */
export const findRule = (name) => RULES.find((r) => r.name === name);

/** A rule's verdict word. `pending` never turns the canary red. */
export const STATUSES = ["green", "red", "pending"];

/**
 * Append one rule's finding to the findings file.
 *
 * Append, not write: the rules are separate processes in separate steps and
 * one of them truncating the file would delete the findings of every rule that
 * ran before it — and would do it silently, because the composer would then
 * report those rules as never having run, which reads as a workflow defect
 * rather than as this one.
 *
 * @param {string} name            the rule's name in `RULES`
 * @param {object} finding
 * @param {"green"|"red"|"pending"} finding.status
 * @param {string[]} [finding.codes]  fixed codes, `^[A-Z][A-Z0-9_]{0,47}$`
 * @param {string[]} [finding.ids]    plugin ids
 * @param {string[]} [finding.hexes]  16-, 40- or 64-character lowercase hex
 * @param {string[]} [finding.detail] sentences for the run log; never sent
 * @param {string} [file]          defaults to $ASTRA_COVERAGE_FINDINGS
 */
export function report(name, finding, file = process.env.ASTRA_COVERAGE_FINDINGS) {
  const line = {
    rule: name,
    status: finding.status,
    codes: [...new Set(finding.codes ?? [])],
    ids: [...new Set(finding.ids ?? [])],
    hexes: [...new Set(finding.hexes ?? [])],
    detail: finding.detail ?? [],
  };
  if (!STATUSES.includes(line.status)) {
    throw new Error(`rule ${name} reported status ${JSON.stringify(line.status)}, which is not one of ${STATUSES.join(", ")}`);
  }
  // Printed whether or not a findings file was asked for, so that running a
  // rule by hand — which is what an operator clearing a red canary does — says
  // the same thing the job saw.
  const mark = { green: "ok   ", red: "RED  ", pending: "pend " }[line.status];
  console.log(`${mark} ${name}: ${line.status}${line.codes.length ? ` [${line.codes.join(" ")}]` : ""}`);
  for (const d of line.detail) console.log(`      ${d}`);
  if (!file) return line;
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.appendFileSync(file, `${JSON.stringify(line)}\n`);
  return line;
}

/**
 * Read a findings file back.
 *
 * An unparseable line is not skipped. A rule that wrote half a line — killed
 * mid-append, or two rules interleaving on a filesystem that does not make an
 * append atomic — is a rule whose finding is lost, and a composer that skipped
 * it would report that rule as never having run. Naming the line is the one
 * message that leads to the truth.
 */
export function readFindings(file) {
  if (!fs.existsSync(file)) return { lines: [], bad: [`${file} does not exist: no rule in this job reported anything`] };
  const bad = [];
  const lines = [];
  fs.readFileSync(file, "utf8").split("\n").forEach((raw, i) => {
    if (raw.trim() === "") return;
    try {
      lines.push(JSON.parse(raw));
    } catch {
      bad.push(`${file}:${i + 1} is not a finding this composer can read: ${JSON.stringify(raw.slice(0, 120))}`);
    }
  });
  return { lines, bad };
}
