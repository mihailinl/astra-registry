#!/usr/bin/env node
// One verdict out of every rule the `check` job ran — and out of every rule it
// was supposed to run and did not.
//
//     node tools/coverage-verdict.mjs --findings <file> --out verdict.json
//
// ── THE FAILURE THIS FILE EXISTS FOR ────────────────────────────────────────
//
// Eight rules, eight steps, each `if: always()`. Composing the verdict out of
// their exit codes would be the obvious thing and it is wrong in one specific
// way: a step that never ran contributes no failure. A typo in a path, a
// `continue-on-error` left over from an afternoon's debugging, a step lost in
// a merge, a script that threw in its import — every one of those produces a
// green verdict and a silent alarm about a rule nobody can tell was skipped.
// That is the same shape as the release workflow whose comment described a
// checkout step that was never written, and it is the shape M-T1.5 exists to
// prevent one level up.
//
// So the signal is not the exit code. Each rule APPENDS a line naming itself,
// and this composer compares the reporters against `tools/coverage/rules.mjs`.
// Listed and silent is red. Reporting and unlisted is red. Reporting twice is
// red, because two lines from one rule means one of the two came from
// somewhere nobody meant.
//
// ── WHAT REACHES TELEGRAM ───────────────────────────────────────────────────
//
// The verdict, and only the verdict: `bot/lib/alert-verdict.mjs`'s grammar of
// fixed codes, plugin ids, hex digests and one github.com run URL. Everything
// the rules found in prose goes to the run log and the job summary, behind a
// login. That split is why a moderation reason — 300 characters a stranger
// may have written — cannot be used to push the codes out of a 4096-byte
// Telegram message.
//
// This composer VALIDATES its own output with that grammar before writing it,
// and if it cannot produce a sendable verdict it writes a minimal red one
// saying so. An alarm channel that goes quiet because the alarm was malformed
// is the worst of the available outcomes: the run is red, the estate is
// broken, and the message that would have said so was the thing that failed.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { RULES, outstandingActs, readFindings } from "./coverage/rules.mjs";
import { VERDICT_SCHEMA, runUrl, verdictProblems } from "../bot/lib/alert-verdict.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..");

/** The receiver check this workflow posts to (`bot/lib/alert-checks.mjs`). */
export const CHECK = "coverage-canary";

/** `bot/lib/alert-verdict.mjs`'s cap. Past it the channel refuses the whole message. */
const MAX_ELEMENTS = 40;

/**
 * @param {{lines: object[], bad: string[]}} findings
 * @returns {{verdict: object, summary: string[], status: "red"|"green"}}
 */
export function compose(findings, { rules = RULES, pending = [], run = null } = {}) {
  const codes = [];
  const ids = [];
  const hexes = [];
  const summary = [];

  for (const why of findings.bad) {
    codes.push("E_FINDINGS_UNREADABLE");
    summary.push(`unreadable: ${why}`);
  }

  const byRule = new Map();
  for (const line of findings.lines) {
    if (!byRule.has(line.rule)) byRule.set(line.rule, []);
    byRule.get(line.rule).push(line);
  }

  for (const rule of rules) {
    const reported = byRule.get(rule.name) ?? [];
    if (reported.length === 0) {
      codes.push("E_RULE_DID_NOT_REPORT");
      summary.push(
        `MISSING  ${rule.name} (${rule.owner}) — declared in tools/coverage/rules.mjs and wrote no finding. ` +
        `Its step runs \`node ${rule.script} --report "$ASTRA_COVERAGE_FINDINGS"\`; either that step is not ` +
        "in the job, or it did not reach the line that reports.",
      );
      continue;
    }
    if (reported.length > 1) {
      codes.push("E_RULE_REPORTED_TWICE");
      summary.push(`DOUBLE   ${rule.name} wrote ${reported.length} findings; one of them came from a step nobody meant`);
    }
    for (const line of reported) {
      const mark = { green: "ok      ", red: "RED     ", pending: "pending " }[line.status] ?? "?       ";
      summary.push(`${mark} ${rule.name}: ${line.status}`);
      for (const d of line.detail ?? []) summary.push(`         ${d}`);
      if (line.status !== "red") continue;
      codes.push(...(line.codes ?? []));
      ids.push(...(line.ids ?? []));
      hexes.push(...(line.hexes ?? []));
    }
  }

  const declared = new Set(rules.map((r) => r.name));
  for (const name of byRule.keys()) {
    if (declared.has(name)) continue;
    codes.push("E_RULE_UNDECLARED");
    summary.push(
      `UNKNOWN  ${name} reported and is not in tools/coverage/rules.mjs; a rule the register does not know ` +
      "about is a rule whose silence nothing would notice",
    );
  }

  for (const act of pending) {
    summary.push(`PENDING  ${act.task} ${act.id}: ${act.act}`);
  }

  // Deduplicate before capping: one code repeated forty times is one thing
  // wrong, and it must not push the other things out of the message.
  const uniq = (a) => [...new Set(a)];
  let verdict = {
    schema: VERDICT_SCHEMA,
    check: CHECK,
    status: codes.length ? "red" : "green",
    codes: uniq(codes).slice(0, MAX_ELEMENTS),
    ids: uniq(ids).slice(0, MAX_ELEMENTS),
    hexes: uniq(hexes).slice(0, MAX_ELEMENTS),
  };
  const url = run ?? runUrl();
  if (url) verdict.run = url;
  for (const key of ["codes", "ids", "hexes"]) if (verdict[key].length === 0) delete verdict[key];

  const problems = verdictProblems(verdict);
  if (problems.length) {
    // Never silence. A verdict this channel will not carry becomes a verdict
    // it will, saying exactly that, so the run still pages somebody.
    summary.push(...problems.map((p) => `UNSENDABLE  ${p}`));
    verdict = {
      schema: VERDICT_SCHEMA,
      check: CHECK,
      status: "red",
      codes: ["E_VERDICT_UNSENDABLE"],
      ...(url ? { run: url } : {}),
    };
  }
  return { verdict, summary, status: verdict.status };
}

function main(argv) {
  const args = {
    findings: process.env.ASTRA_COVERAGE_FINDINGS,
    out: "verdict.json",
    repo: DEFAULT_REPO,
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--findings") args.findings = argv[++i];
    else if (argv[i] === "--out") args.out = argv[++i];
    else { console.error(`FAIL  unknown argument ${JSON.stringify(argv[i])}`); return 2; }
  }
  if (!args.findings) {
    console.error("FAIL  --findings <file> is required (or $ASTRA_COVERAGE_FINDINGS)");
    return 2;
  }

  const { verdict, summary, status } = compose(readFindings(args.findings), {
    pending: outstandingActs(args.repo),
  });
  const json = JSON.stringify(verdict);
  fs.writeFileSync(args.out, `${json}\n`);

  console.log(`\n── ${CHECK} ${"─".repeat(56)}`);
  for (const line of summary) console.log(line);
  console.log(`\n${status === "red" ? "RED " : "ok  "} verdict: ${json}`);

  // The run page, not only the log. A pending owner act printed 400 lines into
  // a step's output is a pending owner act nobody has read; the summary is on
  // the run's front page and survives log retention.
  if (process.env.GITHUB_STEP_SUMMARY) {
    const md = [
      `### Coverage canary — **${status}**`,
      "",
      "```",
      ...summary,
      "```",
    ].join("\n");
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`);
  }
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `verdict=${json}\nstatus=${status}\n`);
  }

  // Exit 0 even when red. The job's own red X is one step further on, so that
  // "the check job failed" and "the canary is red" stay two different facts:
  // the alert job treats a failed job with no verdict as its own alarm, and a
  // composer that exited non-zero here would never have written the output
  // that tells it which.
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
