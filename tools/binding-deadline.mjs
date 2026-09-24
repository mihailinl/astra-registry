#!/usr/bin/env node
// Write the binding deadline and its POLICY.md line, together (registry plan
// M-T5.2; contract MIG-2, MIG-3, MIG-29).
//
//     node tools/binding-deadline.mjs --cutover-estimate 2026-09-27T00:00:00Z \
//          [--round2-estimate <time>] [--root <tree>] [--write]
//
// Without `--write` it prints the plan and writes nothing. With it, it writes
// `policy/binding-deadline.json` and replaces the one `**Binding deadline:**`
// line in root `POLICY.md`, and nothing else — the commit that carries the two
// is the owner's (MIG-2), made by a person, because the date is his.
//
// It refuses, and writes nothing, when the floors do not hold: the deadline is
// the cutover estimate plus 60 days, at least 60 days after the round-2
// estimate, and never earlier than a deadline already committed. The rules are
// `tools/lib/binding-deadline.mjs`'s; this file only reads and writes.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { deadlineText, planDeadline, withPolicyLine } from "./lib/binding-deadline.mjs";
import { DEADLINE_FILE, readMarkers } from "../bot/lib/listing-state.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const args = { root: REPO, write: false, cutoverEstimate: null, round2Estimate: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--cutover-estimate") args.cutoverEstimate = argv[++i];
    else if (a === "--round2-estimate") args.round2Estimate = argv[++i];
    else if (a === "--root") args.root = path.resolve(argv[++i]);
    else if (a === "--write") args.write = true;
    else throw new Error(`unknown argument ${JSON.stringify(a)}`);
  }
  if (args.cutoverEstimate === null) throw new Error("--cutover-estimate <§0.7 time> is required (MIG-2 computes from it)");
  return args;
}

export function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    return 2;
  }
  // The committed deadline is read the way the bot reads it, so a malformed
  // file on the tree stops this rather than being overwritten unseen.
  let committed;
  try {
    committed = readMarkers(args.root).deadline;
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    return 1;
  }
  const plan = planDeadline({ cutoverEstimate: args.cutoverEstimate, round2Estimate: args.round2Estimate, committed });
  for (const n of plan.notes) console.log(`note  ${n}`);
  if (plan.problems.length) {
    for (const p of plan.problems) console.error(`FAIL  ${p}`);
    return 1;
  }
  if (plan.change === "same") return 0;

  const policyFile = path.join(args.root, "POLICY.md");
  const policy = withPolicyLine(fs.readFileSync(policyFile, "utf8"), plan.deadline);
  if (!args.write) {
    console.log(`plan  ${DEADLINE_FILE} ← ${plan.deadline}; POLICY.md's deadline line states it. Re-run with --write.`);
    return 0;
  }
  const deadlineFile = path.join(args.root, DEADLINE_FILE);
  fs.writeFileSync(deadlineFile, deadlineText(plan.deadline));
  fs.writeFileSync(policyFile, policy);
  // Read back through the bot's own reader: a write the bot cannot read is not
  // a deadline.
  const back = readMarkers(args.root).deadline;
  if (back !== plan.deadline) {
    console.error(`FAIL  wrote ${plan.deadline} and the bot's reader reads ${JSON.stringify(back)}`);
    return 1;
  }
  console.log(`wrote ${DEADLINE_FILE} (${plan.deadline}) and POLICY.md's deadline line. Commit BOTH in one commit ` +
    "(MIG-3), then send the re-send to every MIG-13 recipient if a deadline was already committed (MIG-29).");
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
