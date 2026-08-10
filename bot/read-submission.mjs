#!/usr/bin/env node
// Turn an issue body into the two facts, for a workflow to consume.
//
//   node bot/read-submission.mjs --body-file "$GITHUB_EVENT_PATH_BODY"
//
// Writes `repo=…` and `tag=…` to `$GITHUB_OUTPUT` when it can, and exits 2 with
// a sentence when it cannot. Separate from `bot/ingest.mjs` on purpose: parsing
// a stranger's markdown and downloading a stranger's archive are different
// jobs, and the workflow gives them different permissions.
//
// The body arrives via a FILE, never an argument or an environment
// interpolation. `${{ github.event.issue.body }}` pasted into a `run:` block is
// the standard GitHub Actions script-injection hole — the body is attacker
// text, and the runner would be substituting it into a shell before bash ever
// sees a quote.

import fs from "node:fs";

import { parseIssueForm } from "./lib/issue.mjs";

function parseArgs(argv) {
  const opts = { bodyFile: null, output: process.env.GITHUB_OUTPUT ?? null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--body-file") opts.bodyFile = argv[++i];
    else if (argv[i] === "--output") opts.output = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (!opts.bodyFile) throw new Error("--body-file <path> is required");
  return opts;
}

function main(argv) {
  const opts = parseArgs(argv);
  const parsed = parseIssueForm(fs.readFileSync(opts.bodyFile, "utf8"));

  if (!parsed.repo || !parsed.tag) {
    console.error(
      "This submission does not carry the two facts the bot needs.\n" +
      `  Source repository: ${parsed.repo ?? "(missing)"}\n` +
      `  Release tag:       ${parsed.tag ?? "(missing)"}\n` +
      "Open a new issue with the listing template rather than editing this one, so the form's " +
      "field labels are present.",
    );
    return 2;
  }

  const unchecked = parsed.confirmations.filter((c) => !c.checked);
  if (parsed.confirmations.length && unchecked.length) {
    console.error(
      `Not every confirmation is ticked: ${unchecked.map((c) => `"${c.label}"`).join(", ")}.\n` +
      "They are not evidence — the bot proves ownership against GitHub either way — but they are " +
      "the difference between a mistake and a statement, and the template requires them.",
    );
    return 2;
  }

  console.log(`repo=${parsed.repo}`);
  console.log(`tag=${parsed.tag}`);
  if (opts.output) fs.appendFileSync(opts.output, `repo=${parsed.repo}\ntag=${parsed.tag}\n`);
  return 0;
}

try {
  process.exit(main(process.argv.slice(2)));
} catch (e) {
  console.error(`bot: ${e.message}`);
  process.exit(2);
}
